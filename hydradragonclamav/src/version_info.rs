//! PE version-information (`VS_VERSION_INFO`) offset extraction — a faithful port
//! of ClamAV's `findres(0x10, ...)` and the `VS_VERSION_INFO` walk in `pe.c`
//! (`cli_peheader` under `CLI_PEHEADER_OPT_EXTRACT_VINFO`).
//!
//! It produces the set of file offsets where version-info string entries begin —
//! ClamAV's `peinfo->vinfo` hashset, each entry `vptr - baseptr + 6`. A `VI`
//! (`CLI_OFF_VERSION`) anchored signature matches only when its match offset is
//! one of these (matcher-ac.c:1902: `cli_hashset_contains(mdata->vinfo, realoff)`).

use crate::pe::Section;

// UTF-16LE keys, exactly as compared by ClamAV (`memcmp`).
const KEY_VS_VERSION_INFO: &[u8] = b"V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0"; // 0x20
const KEY_VAR_FILE_INFO: &[u8] = b"V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0"; // 0x18
const KEY_STRING_FILE_INFO: &[u8] = b"S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0"; // 0x1e

#[inline]
fn ru16(data: &[u8], off: u32) -> Option<u16> {
    let o = off as usize;
    data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn ru32(data: &[u8], off: u32) -> Option<u32> {
    let o = off as usize;
    data.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// ClamAV `cli_rawaddr`: map an RVA to a file offset. `hdr_size` is the PE
/// `SizeOfHeaders`; an RVA below it maps 1:1 (header region).
fn cli_rawaddr(rva: u32, sections: &[Section], hdr_size: u32, fsize: usize) -> Option<u32> {
    if rva < hdr_size {
        if (rva as usize) >= fsize {
            return None;
        }
        return Some(rva);
    }
    // ClamAV scans sections from last to first.
    for s in sections.iter().rev() {
        let rsz = s.raw_size as u32;
        if rsz != 0 && s.virtual_address <= rva && rsz > (rva - s.virtual_address) {
            return Some((rva - s.virtual_address).wrapping_add(s.raw_start as u32));
        }
    }
    None
}

/// Port of `findres(0x10, 0xffffffff, ...)`: walk the resource directory for the
/// `RT_VERSION` (type `0x10`) entries, returning each leaf's data-entry RVA
/// (`res_rva + lang_offs`), capped at 16 like ClamAV's `versioninfo_cb`.
fn find_version_resources(
    data: &[u8],
    res_rva: u32,
    sections: &[Section],
    hdr_size: u32,
) -> Vec<u32> {
    let fsize = data.len();
    let mut leaves: Vec<u32> = Vec::new();
    const BY_TYPE: u32 = 0x10;

    let Some(resdir) = cli_rawaddr(res_rva, sections, hdr_size, fsize) else {
        return leaves;
    };
    if data.get(resdir as usize..resdir as usize + 16).is_none() {
        return leaves;
    }
    // by_type high bit is not set → skip the named entries, iterate id entries.
    let mut type_entry = resdir + 16 + (ru16(data, resdir + 12).unwrap_or(0) as u32) * 8;
    let mut type_cnt = ru16(data, resdir + 14).unwrap_or(0);

    while type_cnt > 0 {
        type_cnt -= 1;
        let (Some(typ), Some(type_offs)) = (ru32(data, type_entry), ru32(data, type_entry + 4))
        else {
            return leaves;
        };
        if typ == BY_TYPE && (type_offs >> 31) != 0 {
            let Some(resdir2) =
                cli_rawaddr(res_rva + (type_offs & 0x7fff_ffff), sections, hdr_size, fsize)
            else {
                return leaves;
            };
            if data.get(resdir2 as usize..resdir2 as usize + 16).is_none() {
                return leaves;
            }
            // by_name == 0xffffffff → both named and id name entries.
            let mut name_cnt = ru16(data, resdir2 + 12).unwrap_or(0) as u32
                + ru16(data, resdir2 + 14).unwrap_or(0) as u32;
            let mut name_entry = resdir2 + 16;
            while name_cnt > 0 {
                name_cnt -= 1;
                let Some(name_offs) = ru32(data, name_entry + 4) else {
                    return leaves;
                };
                if (name_offs >> 31) != 0 {
                    let Some(resdir3) = cli_rawaddr(
                        res_rva + (name_offs & 0x7fff_ffff),
                        sections,
                        hdr_size,
                        fsize,
                    ) else {
                        return leaves;
                    };
                    if data.get(resdir3 as usize..resdir3 as usize + 16).is_none() {
                        return leaves;
                    }
                    let mut lang_cnt = ru16(data, resdir3 + 12).unwrap_or(0) as u32
                        + ru16(data, resdir3 + 14).unwrap_or(0) as u32;
                    let mut lang_entry = resdir3 + 16;
                    while lang_cnt > 0 {
                        lang_cnt -= 1;
                        let Some(lang_offs) = ru32(data, lang_entry + 4) else {
                            return leaves;
                        };
                        if (lang_offs >> 31) == 0 {
                            leaves.push(res_rva + lang_offs);
                            if leaves.len() == 16 {
                                return leaves;
                            }
                        }
                        lang_entry += 8;
                    }
                }
                name_entry += 8;
            }
            return leaves; // ClamAV stops after the first matching type
        }
        type_entry += 8;
    }
    leaves
}

/// Parse one `VS_VERSION_INFO` resource (given its data-entry RVA) and push the
/// file offset of every string entry's key into `out` (ClamAV: `vptr-baseptr+6`).
fn parse_version_resource(
    data: &[u8],
    leaf_rva: u32,
    sections: &[Section],
    hdr_size: u32,
    out: &mut Vec<u32>,
) {
    let fsize = data.len();
    // IMAGE_RESOURCE_DATA_ENTRY → data RVA + size.
    let Some(de_off) = cli_rawaddr(leaf_rva, sections, hdr_size, fsize) else {
        return;
    };
    let (Some(data_rva), Some(res_sz)) = (ru32(data, de_off), ru32(data, de_off + 4)) else {
        return;
    };
    let Some(vi_off) = cli_rawaddr(data_rva, sections, hdr_size, fsize) else {
        return;
    };
    // Clamp the resource to what's actually present in the buffer.
    let start = vi_off as usize;
    let avail = data.len().saturating_sub(start);
    let res_sz = (res_sz as usize).min(avail) as u32;
    // `pos` tracks the absolute file offset (ClamAV's `vptr - baseptr`).
    let mut pos = vi_off;

    // --- look for VS_VERSION_INFO (exactly one) ---
    if res_sz <= 4 {
        return;
    }
    let Some(vinfo_field) = ru32(data, pos) else {
        return;
    };
    let mut vinfo_sz = vinfo_field & 0xffff;
    let vinfo_val_sz = vinfo_field >> 16;
    if vinfo_sz > res_sz {
        return;
    }
    let header = 6 + 0x20 + 2 + 0x34;
    if vinfo_sz <= header
        || vinfo_val_sz != 0x34
        || data.get(pos as usize + 6..pos as usize + 6 + 0x20) != Some(KEY_VS_VERSION_INFO)
        || ru32(data, pos + 0x28) != Some(0xfeef_04bd)
    {
        return;
    }
    pos += header;
    vinfo_sz -= header;

    // --- look for StringFileInfo (skip a leading VarFileInfo) ---
    let mut got_varfileinfo = false;
    while vinfo_sz > 6 {
        let Some(sfi_sz_raw) = ru32(data, pos) else {
            return;
        };
        let mut sfi_sz = sfi_sz_raw & 0xffff;
        if sfi_sz > vinfo_sz {
            return;
        }
        if !got_varfileinfo
            && sfi_sz > 6 + 0x18
            && data.get(pos as usize + 6..pos as usize + 6 + 0x18) == Some(KEY_VAR_FILE_INFO)
        {
            pos += sfi_sz;
            vinfo_sz -= sfi_sz;
            got_varfileinfo = true;
            continue;
        }
        if sfi_sz <= 6 + 0x1e
            || data.get(pos as usize + 6..pos as usize + 6 + 0x1e) != Some(KEY_STRING_FILE_INFO)
        {
            return;
        }
        pos += 6 + 0x1e;
        sfi_sz -= 6 + 0x1e;

        // --- enum all string tables ---
        while sfi_sz > 6 {
            let Some(st_sz_raw) = ru32(data, pos) else {
                return;
            };
            let mut st_sz = st_sz_raw & 0xffff;
            let next_pos = pos.wrapping_add(st_sz);
            let next_sfi_sz = sfi_sz.wrapping_sub(st_sz);
            if st_sz > sfi_sz || st_sz <= 24 {
                return;
            }
            pos += 24;
            st_sz -= 24;

            // --- enum all strings ---
            while st_sz > 6 {
                let Some(s_field) = ru32(data, pos) else {
                    return;
                };
                let mut s_sz = (s_field & 0xffff) + 3;
                s_sz &= !3;
                if s_sz > st_sz || s_sz <= 6 + 2 + 8 {
                    // force a hard fail (ClamAV zeroes st_sz and sfi_sz)
                    sfi_sz = 0;
                    break;
                }
                // ~wcstrlen(key)
                let mut s_key_sz = 6u32;
                while s_key_sz + 1 < s_sz {
                    let (Some(a), Some(b)) = (
                        data.get((pos + s_key_sz) as usize).copied(),
                        data.get((pos + s_key_sz + 1) as usize).copied(),
                    ) else {
                        return;
                    };
                    if a != 0 || b != 0 {
                        s_key_sz += 2;
                        continue;
                    }
                    s_key_sz += 2;
                    break;
                }
                s_key_sz = (s_key_sz + 3) & !3;
                if s_key_sz >= s_sz {
                    pos += s_sz;
                    st_sz -= s_sz;
                    continue;
                }
                let s_val_sz = s_sz - s_key_sz;
                if s_val_sz <= 2 {
                    pos += s_sz;
                    st_sz -= s_sz;
                    continue;
                }
                // The version-info string entry: its key begins at pos + 6.
                out.push(pos + 6);
                pos += s_sz;
                st_sz -= s_sz;
            }

            pos = next_pos;
            sfi_sz = if sfi_sz != 0 { next_sfi_sz } else { 0 };
        }
        break;
    }
}

/// Compute ClamAV's `vinfo` set: the sorted file offsets where version-info
/// string entries begin. Empty when the PE has no parseable version resource.
/// `res_rva` is the resource data-directory RVA (`dirs[2].VirtualAddress`).
pub fn version_info_offsets(
    data: &[u8],
    res_rva: u32,
    sections: &[Section],
    hdr_size: u32,
) -> Vec<u32> {
    if res_rva == 0 {
        return Vec::new();
    }
    let leaves = find_version_resources(data, res_rva, sections, hdr_size);
    let mut out = Vec::new();
    for rva in leaves {
        parse_version_resource(data, rva, sections, hdr_size, &mut out);
    }
    out.sort_unstable();
    out.dedup();
    out
}
