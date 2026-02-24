//! Pure Rust PE metadata parser to extract .NET assembly identity
//!
//! This replaces the broken ICLRAssemblyIdentityManager approach which fails with
//! HRESULT(0x80040154) REGDB_E_CLASSNOTREG because:
//!   1. CLSID_CLRAssemblyIdentityManager was incorrect
//!   2. ICLRRuntimeInfo::GetInterface does NOT support ICLRAssemblyIdentityManager
//!
//! This parser reads the CLI header and metadata tables directly from the PE bytes
//! to produce: "AssemblyName, Version=w.x.y.z, Culture=neutral, PublicKeyToken=null"

use std::convert::TryInto;

// Helper to read a little-endian u16 from a byte slice at a given offset
fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}

// Helper to read a little-endian u32 from a byte slice at a given offset
fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

// Read a null-terminated UTF-8 string from the strings heap at `offset`
fn read_string(strings_heap: &[u8], offset: usize) -> String {
    let start = offset;
    let end = strings_heap[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strings_heap.len());
    String::from_utf8_lossy(&strings_heap[start..end]).to_string()
}

/// Extract a .NET assembly identity string from raw PE bytes.
///
/// Returns a string like:
/// `MyAssembly, Version=1.2.3.4, Culture=neutral, PublicKeyToken=null`
pub fn get_assembly_identity_from_bytes(data: &[u8]) -> Result<String, String> {
    // --- Step 1: DOS header → PE offset ---
    if data.len() < 64 {
        return Err("PE too small for DOS header".into());
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ signature)".into());
    }
    let pe_offset = read_u32(data, 0x3C).ok_or("Cannot read e_lfanew")? as usize;

    // --- Step 2: PE signature ---
    if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return Err("Invalid PE signature".into());
    }

    // --- Step 3: Optional Header ---
    let coff_offset = pe_offset + 4;
    let machine = read_u16(data, coff_offset).ok_or("Cannot read Machine")?;
    let num_sections = read_u16(data, coff_offset + 2).ok_or("Cannot read NumSections")? as usize;
    let opt_header_size =
        read_u16(data, coff_offset + 16).ok_or("Cannot read OptHeaderSize")? as usize;
    let opt_offset = coff_offset + 20;

    // Magic: 0x10B = PE32, 0x20B = PE32+
    let magic = read_u16(data, opt_offset).ok_or("Cannot read optional header magic")?;
    let is_pe32_plus = magic == 0x20B;

    // Data directories start offset within optional header
    let data_dir_offset = opt_offset + if is_pe32_plus { 112 } else { 96 };

    // Data directory [14] = CLI header (COM descriptor)
    let clr_dir_offset = data_dir_offset + 14 * 8;
    let clr_rva = read_u32(data, clr_dir_offset).ok_or("Cannot read CLR RVA")?;
    let clr_size = read_u32(data, clr_dir_offset + 4).ok_or("Cannot read CLR size")?;

    if clr_rva == 0 || clr_size == 0 {
        return Err("Not a .NET assembly (no CLR data directory)".into());
    }

    // --- Step 4: Section headers to convert RVA → file offset ---
    let sections_offset = opt_offset + opt_header_size;

    let rva_to_offset = |rva: u32| -> Option<usize> {
        for i in 0..num_sections {
            let sec = sections_offset + i * 40;
            let virt_addr = read_u32(data, sec + 12)?;
            let virt_size = read_u32(data, sec + 16)?;
            let raw_offset = read_u32(data, sec + 20)?;
            if rva >= virt_addr && rva < virt_addr + virt_size {
                return Some((rva - virt_addr + raw_offset) as usize);
            }
        }
        None
    };

    // --- Step 5: CLI header ---
    let clr_offset = rva_to_offset(clr_rva).ok_or("Cannot resolve CLR header RVA")?;
    // CLI header layout: cb(4), MajorRuntime(2), MinorRuntime(2), Metadata RVA(4), Metadata Size(4), ...
    let metadata_rva = read_u32(data, clr_offset + 8).ok_or("Cannot read Metadata RVA")?;
    let _metadata_size = read_u32(data, clr_offset + 12).ok_or("Cannot read Metadata size")?;

    // --- Step 6: Metadata header ---
    let meta_offset = rva_to_offset(metadata_rva).ok_or("Cannot resolve Metadata RVA")?;

    // Metadata signature: 0x424A5342 ("BSJB")
    let sig = read_u32(data, meta_offset).ok_or("Cannot read metadata signature")?;
    if sig != 0x424A5342 {
        return Err(format!("Invalid metadata signature: 0x{:08X}", sig));
    }

    // Version string length at offset 12 (padded to 4 bytes)
    let ver_len = read_u32(data, meta_offset + 12).ok_or("Cannot read version length")? as usize;
    let ver_len_padded = (ver_len + 3) & !3;

    // Streams count at offset 16 + ver_len_padded + 2 (flags)
    let flags_offset = meta_offset + 16 + ver_len_padded;
    // flags (2 bytes) then num streams (2 bytes)
    let num_streams = read_u16(data, flags_offset + 2).ok_or("Cannot read stream count")? as usize;

    // --- Step 7: Locate streams (#~, #Strings, #Blob, #US) ---
    let mut stream_header_offset = flags_offset + 4;
    let mut tables_rva: Option<u32> = None;
    let mut tables_stream_offset: Option<usize> = None;
    let mut strings_heap: Option<&[u8]> = None;
    let mut blob_heap: Option<&[u8]> = None;

    for _ in 0..num_streams {
        let stream_offset =
            read_u32(data, stream_header_offset).ok_or("Cannot read stream offset")? as usize;
        let stream_size =
            read_u32(data, stream_header_offset + 4).ok_or("Cannot read stream size")? as usize;

        // Stream name is a null-terminated string at stream_header_offset + 8, padded to 4 bytes
        let name_start = stream_header_offset + 8;
        let name_end = data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(name_start + 32);
        let name = std::str::from_utf8(&data[name_start..name_end]).unwrap_or("");
        let name_padded = ((name_end - name_start + 1) + 3) & !3;

        let abs_offset = meta_offset + stream_offset;

        match name {
            "#~" | "#-" => {
                tables_stream_offset = Some(abs_offset);
                let _ = tables_rva;
            },
            "#Strings" => {
                strings_heap = data.get(abs_offset..abs_offset + stream_size);
            },
            "#Blob" => {
                blob_heap = data.get(abs_offset..abs_offset + stream_size);
            },
            _ => {},
        }

        stream_header_offset = name_start + name_padded;
    }

    let tables_off = tables_stream_offset.ok_or("No #~ stream found")?;
    let strings = strings_heap.ok_or("No #Strings heap found")?;
    let blob = blob_heap.unwrap_or(&[]);

    // --- Step 8: Parse #~ stream header ---
    // Offset 0: Reserved (4)
    // Offset 4: MajorVersion (1)
    // Offset 5: MinorVersion (1)
    // Offset 6: HeapSizes (1) — bit 0 = StringsHeap wide (4 bytes), bit 1 = GUIDheap wide, bit 2 = BlobHeap wide
    // Offset 7: Reserved (1)
    // Offset 8: Valid (8) — bitmask of present tables
    // Offset 16: Sorted (8)
    // Offset 24: row counts (4 bytes each for each present table)

    let heap_sizes = data
        .get(tables_off + 6)
        .copied()
        .ok_or("Cannot read HeapSizes")?;
    let string_index_wide = (heap_sizes & 0x01) != 0; // 4-byte string index if set
    let guid_index_wide = (heap_sizes & 0x02) != 0;
    let blob_index_wide = (heap_sizes & 0x04) != 0;

    let string_idx_size: usize = if string_index_wide { 4 } else { 2 };
    let guid_idx_size: usize = if guid_index_wide { 4 } else { 2 };
    let blob_idx_size: usize = if blob_index_wide { 4 } else { 2 };

    let valid_mask = {
        let b = data
            .get(tables_off + 8..tables_off + 16)
            .ok_or("Cannot read Valid mask")?;
        u64::from_le_bytes(b.try_into().unwrap())
    };

    // Row counts start at offset 24
    let mut row_counts: [u32; 64] = [0; 64];
    let mut rc_offset = tables_off + 24;
    for bit in 0..64u64 {
        if valid_mask & (1 << bit) != 0 {
            let count = read_u32(data, rc_offset).ok_or("Cannot read row count")?;
            row_counts[bit as usize] = count;
            rc_offset += 4;
        }
    }

    // --- Step 9: Calculate table row sizes and find AssemblyDef (table 0x20 = 32) ---
    // Table 0x20 = Assembly
    // Row layout:
    //   HashAlgId (4)
    //   MajorVersion (2), MinorVersion (2), BuildNumber (2), RevisionNumber (2)
    //   Flags (4)
    //   PublicKey (blob index)
    //   Name (string index)
    //   Culture (string index)
    const ASSEMBLY_TABLE: usize = 0x20;

    if row_counts[ASSEMBLY_TABLE] == 0 {
        return Err("No AssemblyDef table (not an assembly?)".into());
    }

    // We need to skip all tables before 0x20 to find the row data offset.
    // First, calculate the size of each table's rows.
    let table_row_size = |table: usize| -> Result<usize, String> {
        // This is complex in general; we implement only what we need.
        // Use a simpler approach: we count only known fixed tables we need to skip.
        // A full implementation would need all 45+ table schemas.
        // For our purposes we implement just enough to reach AssemblyDef.
        Ok(match table {
            0x00 => 2 + guid_idx_size,                   // Module
            0x01 => string_idx_size + blob_idx_size + 2, // TypeRef (ResolutionScope coded + Name + Namespace)
            // TypeRef ResolutionScope is a coded index (2 or 4 bytes)
            // Let's use coded index size = 2 for now
            _ => return Err(format!("Unknown table 0x{:02X} row size needed", table)),
        })
    };

    // We'll use a simpler approach: since AssemblyDef is usually near the start,
    // we calculate total bytes to skip for tables 0..0x1F
    //
    // The table data starts after the row counts in the stream header.
    // We implement table schemas for all tables 0x00-0x1F that can be present.
    //
    // Coded index sizes depend on row counts of referenced tables.
    // We implement a simplified but accurate version.

    // Helper: coded index size (2 if max referenced table has <= 2^(16-tag_bits) rows, else 4)
    let coded_idx_size = |tables: &[usize], tag_bits: u32| -> usize {
        let threshold = (1u32 << (16 - tag_bits)) as u32;
        let needs_4 = tables.iter().any(|&t| row_counts[t] >= threshold);
        if needs_4 {
            4
        } else {
            2
        }
    };

    // Simple table index size
    let tbl_idx = |t: usize| -> usize {
        if row_counts[t] >= 65536 {
            4
        } else {
            2
        }
    };

    // Coded index types (II.24.2.6 of ECMA-335)
    let ci_type_def_or_ref = coded_idx_size(&[0x00, 0x01, 0x1B], 2); // TypeDefOrRef
    let ci_has_constant = coded_idx_size(&[0x04, 0x08, 0x17], 2); // HasConstant
    let ci_has_cattr = coded_idx_size(
        &[
            0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x0E, 0x11, 0x14, 0x17,
            0x19, 0x1A, 0x1B, 0x1C,
        ],
        5,
    ); // HasCustomAttribute
    let ci_has_field_marshal = coded_idx_size(&[0x04, 0x08], 1);
    let ci_has_decl_security = coded_idx_size(&[0x02, 0x06, 0x20], 2);
    let ci_member_ref_parent = coded_idx_size(&[0x00, 0x01, 0x1A, 0x06, 0x1B], 3);
    let ci_has_semantics = coded_idx_size(&[0x14, 0x17], 1);
    let ci_method_def_or_ref = coded_idx_size(&[0x06, 0x0A], 1);
    let ci_member_forwarded = coded_idx_size(&[0x04, 0x06], 1);
    let ci_implementation = coded_idx_size(&[0x26, 0x23, 0x27], 2);
    let ci_cattr_type = coded_idx_size(
        &[
            0x00, /*unused*/
            0x00, /*unused*/
            0x06, 0x0A, 0x00, /*unused*/
        ],
        3,
    );
    let ci_resolution_scope = coded_idx_size(&[0x00, 0x1A, 0x23, 0x01], 2);
    let ci_type_or_method_def = coded_idx_size(&[0x02, 0x06], 1);

    // Row sizes for tables 0x00 through 0x1F
    let row_size: [usize; 0x20] = [
        /* 0x00 Module            */
        2 + string_idx_size + guid_idx_size + guid_idx_size + guid_idx_size,
        /* 0x01 TypeRef           */ ci_resolution_scope + string_idx_size + string_idx_size,
        /* 0x02 TypeDef           */
        4 + string_idx_size + string_idx_size + ci_type_def_or_ref + tbl_idx(0x04) + tbl_idx(0x06),
        /* 0x03 FieldPtr          */ tbl_idx(0x04),
        /* 0x04 Field             */ 2 + string_idx_size + blob_idx_size,
        /* 0x05 MethodPtr         */ tbl_idx(0x06),
        /* 0x06 Method            */
        4 + 2 + 2 + string_idx_size + blob_idx_size + tbl_idx(0x08),
        /* 0x07 ParamPtr          */ tbl_idx(0x08),
        /* 0x08 Param             */ 2 + 2 + string_idx_size,
        /* 0x09 InterfaceImpl     */ tbl_idx(0x02) + ci_type_def_or_ref,
        /* 0x0A MemberRef         */ ci_member_ref_parent + string_idx_size + blob_idx_size,
        /* 0x0B Constant          */ 2 + 2 + ci_has_constant + blob_idx_size,
        /* 0x0C CustomAttribute   */ ci_has_cattr + ci_cattr_type + blob_idx_size,
        /* 0x0D FieldMarshal      */ ci_has_field_marshal + blob_idx_size,
        /* 0x0E DeclSecurity      */ 2 + ci_has_decl_security + blob_idx_size,
        /* 0x0F ClassLayout       */ 2 + 4 + tbl_idx(0x02),
        /* 0x10 FieldLayout       */ 4 + tbl_idx(0x04),
        /* 0x11 StandAloneSig     */ blob_idx_size,
        /* 0x12 EventMap          */ tbl_idx(0x02) + tbl_idx(0x14),
        /* 0x13 EventPtr          */ tbl_idx(0x14),
        /* 0x14 Event             */ 2 + string_idx_size + ci_type_def_or_ref,
        /* 0x15 PropertyMap       */ tbl_idx(0x02) + tbl_idx(0x17),
        /* 0x16 PropertyPtr       */ tbl_idx(0x17),
        /* 0x17 Property          */ 2 + string_idx_size + blob_idx_size,
        /* 0x18 MethodSemantics   */ 2 + tbl_idx(0x06) + ci_has_semantics,
        /* 0x19 MethodImpl        */
        tbl_idx(0x02) + ci_method_def_or_ref + ci_method_def_or_ref,
        /* 0x1A ModuleRef         */ string_idx_size,
        /* 0x1B TypeSpec          */ blob_idx_size,
        /* 0x1C ImplMap           */
        2 + ci_member_forwarded + string_idx_size + tbl_idx(0x1A),
        /* 0x1D FieldRVA          */ 4 + tbl_idx(0x04),
        /* 0x1E ENCLog            */ 4 + 4,
        /* 0x1F ENCMap            */ 4,
    ];

    // Skip tables 0..0x1F
    let mut data_off = rc_offset; // after all row counts
    for t in 0..ASSEMBLY_TABLE {
        if valid_mask & (1 << t) != 0 {
            let rows = row_counts[t] as usize;
            let size = row_size[t];
            data_off += rows * size;
        }
    }

    // --- Step 10: Read AssemblyDef row (first and only row) ---
    // Assembly table row layout (ECMA-335 II.22.2):
    //   HashAlgId : 4
    //   MajorVersion : 2
    //   MinorVersion : 2
    //   BuildNumber : 2
    //   RevisionNumber : 2
    //   Flags : 4
    //   PublicKey : BlobIndex
    //   Name : StringIndex
    //   Culture : StringIndex

    let row_off = data_off;
    let hash_alg_id = read_u32(data, row_off).ok_or("Cannot read HashAlgId")?;
    let _ = hash_alg_id;

    let major = read_u16(data, row_off + 4).ok_or("Cannot read MajorVersion")?;
    let minor = read_u16(data, row_off + 6).ok_or("Cannot read MinorVersion")?;
    let build = read_u16(data, row_off + 8).ok_or("Cannot read BuildNumber")?;
    let revision = read_u16(data, row_off + 10).ok_or("Cannot read RevisionNumber")?;
    // Flags (4 bytes)
    let _flags = read_u32(data, row_off + 12).ok_or("Cannot read Flags")?;

    let pk_offset = row_off + 16;
    let pk_blob_idx = if blob_index_wide {
        read_u32(data, pk_offset).ok_or("Cannot read PublicKey blob index")? as usize
    } else {
        read_u16(data, pk_offset).ok_or("Cannot read PublicKey blob index")? as usize
    };

    let name_offset = pk_offset + blob_idx_size;
    let name_str_idx = if string_index_wide {
        read_u32(data, name_offset).ok_or("Cannot read Name string index")? as usize
    } else {
        read_u16(data, name_offset).ok_or("Cannot read Name string index")? as usize
    };

    let culture_offset = name_offset + string_idx_size;
    let culture_str_idx = if string_index_wide {
        read_u32(data, culture_offset).ok_or("Cannot read Culture string index")? as usize
    } else {
        read_u16(data, culture_offset).ok_or("Cannot read Culture string index")? as usize
    };

    // --- Step 11: Resolve name and culture strings ---
    let name = read_string(strings, name_str_idx);
    let culture_raw = read_string(strings, culture_str_idx);
    let culture = if culture_raw.is_empty() {
        "neutral".to_string()
    } else {
        culture_raw
    };

    // --- Step 12: Resolve public key token ---
    // If PublicKey blob is empty (index points to 0-size blob) → "null"
    // Otherwise compute SHA1 of key, take last 8 bytes reversed → hex token
    let public_key_token = get_public_key_token(blob, pk_blob_idx);

    let identity = format!(
        "{}, Version={}.{}.{}.{}, Culture={}, PublicKeyToken={}",
        name, major, minor, build, revision, culture, public_key_token
    );

    Ok(identity)
}

/// Get the public key token from the blob heap.
/// The token is the last 8 bytes of SHA-1(PublicKey), reversed, encoded as lowercase hex.
/// If the blob is empty (index 0 or size 0), returns "null".
fn get_public_key_token(blob: &[u8], blob_idx: usize) -> String {
    if blob.is_empty() || blob_idx == 0 {
        return "null".to_string();
    }

    // Blob heap: each entry is prefixed by a compressed size (1, 2, or 4 bytes)
    if blob_idx >= blob.len() {
        return "null".to_string();
    }

    let (size, data_start) = read_compressed_uint(blob, blob_idx);

    if size == 0 {
        return "null".to_string();
    }

    let key_bytes = match blob.get(data_start..data_start + size) {
        Some(b) => b,
        None => return "null".to_string(),
    };

    // Compute SHA-1 and take last 8 bytes reversed
    let sha1 = sha1_bytes(key_bytes);
    let token = &sha1[sha1.len() - 8..];
    let reversed: Vec<u8> = token.iter().rev().cloned().collect();
    reversed
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Read a compressed unsigned integer from a blob according to ECMA-335 II.23.2
fn read_compressed_uint(buf: &[u8], offset: usize) -> (usize, usize) {
    let b0 = buf[offset] as usize;
    if b0 & 0x80 == 0 {
        (b0, offset + 1)
    } else if b0 & 0xC0 == 0x80 {
        let b1 = buf.get(offset + 1).copied().unwrap_or(0) as usize;
        (((b0 & 0x3F) << 8) | b1, offset + 2)
    } else {
        let b1 = buf.get(offset + 1).copied().unwrap_or(0) as usize;
        let b2 = buf.get(offset + 2).copied().unwrap_or(0) as usize;
        let b3 = buf.get(offset + 3).copied().unwrap_or(0) as usize;
        (
            ((b0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3,
            offset + 4,
        )
    }
}

/// Minimal SHA-1 implementation (no external crate)
fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Pre-processing: padding
    let orig_len = data.len();
    let bit_len = (orig_len as u64) * 8;

    let padded_len = ((orig_len + 9 + 63) / 64) * 64;
    let mut msg = vec![0u8; padded_len];
    msg[..orig_len].copy_from_slice(data);
    msg[orig_len] = 0x80;
    msg[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());

    // Process in 512-bit (64-byte) chunks
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);

        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | (!b & d), 0x5A827999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62C1D6u32)
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut result = [0u8; 20];
    for i in 0..5 {
        result[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}
