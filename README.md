# ClrOxide (fork)

Fork de [clroxide](https://github.com/b4rtik/clroxide), une bibliothèque Rust permettant d'héberger le CLR .NET et d'exécuter dynamiquement des assemblies .NET en mémoire.

---

## Fonctionnalités ajoutées — Bypass AMSI via `IHostAssemblyStore`

Cette implémentation du bypass AMSI est basée sur la technique décrite dans [Being a Good CLR Host](https://github.com/xforcered/Being-A-Good-CLR-Host).

### Principe

AMSI instrumente `AppDomain.Load(byte[])` (`Load_3` dans la vtable de `_AppDomain`), qui est la méthode standard pour charger un assembly en mémoire depuis des octets bruts. Tout appel à cette méthode déclenche un scan AMSI.

La technique consiste à utiliser `AppDomain.Load(string)` (`Load_2`) à la place — cette variante prend une **identity string** (nom de l'assembly + version + culture + token de clé publique) et n'est **pas instrumentée par AMSI**.

Pour que `Load_2` puisse trouver les bytes de l'assembly sans passer par le disque, on enregistre une implémentation personnalisée de `IHostAssemblyStore` auprès du CLR **avant** le démarrage du runtime. Le CLR appellera notre `ProvideAssembly` pour obtenir les bytes de l'assembly sous forme d'`IStream`.

### Flux d'exécution

```
1. ICLRRuntimeHost::SetHostControl(notre IHostControl)
         ↓
2. CLR → IHostControl::GetHostManager(IID_IHostAssemblyManager)
         ↓
3. CLR → IHostAssemblyManager::GetAssemblyStore()
         ↓
4. AppDomain.Load_2("Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null")
         ↓
5. CLR → IHostAssemblyStore::ProvideAssembly(identity)
         ↓
6. On retourne un IStream contenant les bytes de l'assembly
         ↓
   AMSI ne voit jamais les bytes — Load_2 n'est pas instrumenté !
```

### Extraction automatique de l'identity

L'identity string doit correspondre exactement aux métadonnées de l'assembly (nom, version, culture, PublicKeyToken). Elle est extraite directement depuis les bytes PE via un **parser de métadonnées .NET pur Rust** (`src/primitives/pe_identity.rs`) :

- Parsing du PE header (DOS → COFF → optional header → data directories)
- Localisation du CLI header (data directory [14])
- Parsing du header de métadonnées BSJB
- Navigation dans les streams `#~` (tables), `#Strings` (heap de chaînes), `#Blob`
- Lecture de la table `AssemblyDef` (table 0x20) avec calcul dynamique des tailles de colonnes (coded indexes ECMA-335)
- Calcul du `PublicKeyToken` : SHA-1 de la clé publique, 8 derniers octets inversés, encodé en hex

### Robustesse — normalisation de l'identity par le CLR

Le CLR **normalise** l'identity string avant de la passer à `ProvideAssembly`. Par exemple, l'identity enregistrée :

```
Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
```

peut arriver dans `ProvideAssembly` sous la forme :

```
Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null, processorArchitecture=MSIL
```

Un lookup exact échouerait systématiquement → le CLR retomberait sur une résolution disque → `HRESULT(0x8007000B)` `ERROR_BAD_FORMAT`.

**Fix** : `AssemblyStorage::find_by_simple_name()` effectue une recherche par nom simple (tout ce qui précède la première virgule, case-insensitive) en fallback après le lookup exact.

### Réutilisation du CLR dans le même processus

`SetHostControl` doit être appelé **avant** `ICLRRuntimeHost::Start()`. Si le CLR est déjà démarré dans le processus (second `execute-assembly`), un appel à `SetHostControl` retourne `HRESULT(0x80070005)` `E_ACCESSDENIED`.

**Fix** dans `get_context_with_amsi_bypass()` : le statut `has_started()` est vérifié avant de tenter `SetHostControl`. Si le runtime est déjà actif, le HostControl est ignoré et on récupère l'AppDomain existant directement.

> **Note OPSEC** : si le CLR est déjà démarré, l'assembly est chargé sur l'AppDomain existant sans le bypass `IHostAssemblyStore`. Pour un bypass garantit à chaque exécution, utiliser un nouveau processus CLR par run (via injection ou spawn).

---

## Utilisation

```rust
use clroxide::{Clr, primitives::AmsiBypassLoader};

let bytes = std::fs::read("Rubeus.exe")?;
let args = vec!["kerberoast".to_string()];

let mut clr = Clr::new(bytes, args)?;
let mut bypass = AmsiBypassLoader::new();

// Extraction automatique de l'identity + exécution via Load_2 (bypass AMSI)
let output = clr.run_with_amsi_bypass_auto(&mut bypass)?;
println!("{}", output);
```

### API disponible

| Méthode | Description |
|---|---|
| `run_with_amsi_bypass_auto` | Identity extraite automatiquement + output redirigé |
| `run_with_amsi_bypass_auto_no_redirect` | Identity automatique, output sur stdout |
| `run_with_amsi_bypass` | Identity manuelle + output redirigé |
| `run_with_amsi_bypass_no_redirect` | Identity manuelle, output sur stdout |
| `get_assembly_identity` | Extrait l'identity string depuis les bytes PE |

---

## Références

- [Being a Good CLR Host — xforcered](https://github.com/xforcered/Being-A-Good-CLR-Host)
- [ECMA-335 — Common Language Infrastructure (CLI)](https://ecma-international.org/publications-and-standards/standards/ecma-335/)
- [clroxide (upstream)](https://github.com/b4rtik/clroxide)
