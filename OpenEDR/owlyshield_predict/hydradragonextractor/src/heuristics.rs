use std::io::Cursor;

const RLO: char = '\u{202e}';
const MAX_SPACES: usize = 10;
const SIZE_BOMB_ARCHIVE: u64 = 20 * 1024 * 1024;
const SIZE_BOMB_MEMBER: u64 = 650 * 1024 * 1024;
const ZIP_ENCRYPT_FLAG: u16 = 0x0001;
const ZIP_AES_METHOD: u16 = 99;
const AES256_SHA256: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

const KNOWN_EXTS: &[&str] = &[
    ".7z", ".apk", ".application", ".appx", ".bat", ".bin", ".cab", ".chm",
    ".cmd", ".com", ".cpl", ".dll", ".doc", ".docm", ".docx", ".drv", ".elf",
    ".exe", ".gadget", ".hta", ".img", ".inf", ".iso", ".jar", ".js", ".jse",
    ".lnk", ".msi", ".msp", ".mst", ".ocx", ".pdf", ".pif", ".ppt", ".pptm",
    ".pptx", ".ps1", ".psd1", ".psm1", ".py", ".pyd", ".rar", ".reg", ".rtf",
    ".scf", ".scr", ".sct", ".shb", ".shs", ".so", ".sys", ".url", ".vbe",
    ".vbs", ".vhd", ".vhdx", ".wll", ".wsf", ".wsh", ".xll", ".xls", ".xlsm",
    ".xlsx", ".zip",
];

#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveHeuristic {
    pub name: &'static str,
    pub score: f32,
    pub details: String,
    pub entry_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FilenameObfuscation {
    pub rlo_attack: bool,
    pub excessive_spaces: bool,
    pub multiple_extensions: bool,
    pub details: Vec<String>,
}

impl FilenameObfuscation {
    pub fn suspicious(&self) -> bool {
        self.rlo_attack || self.excessive_spaces || self.multiple_extensions
    }

    pub fn attack_label(&self) -> String {
        let mut parts = Vec::new();
        if self.rlo_attack {
            parts.push("RLO");
        }
        if self.excessive_spaces {
            parts.push("Spaces");
        }
        if self.multiple_extensions {
            parts.push("MultiExt");
        }
        if parts.is_empty() {
            "Generic".to_string()
        } else {
            parts.join("+")
        }
    }
}

pub fn is_known_extension(ext: &str) -> bool {
    let lower = ext.to_ascii_lowercase();
    KNOWN_EXTS.binary_search(&lower.as_str()).is_ok()
}

fn leaf_name(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

fn extension_of(name: &str) -> &str {
    let leaf = leaf_name(name);
    match leaf.rfind('.') {
        Some(i) => &leaf[i..],
        None => "",
    }
}

pub fn detect_suspicious_filename(filename: &str) -> FilenameObfuscation {
    let mut out = FilenameObfuscation::default();
    let leaf = leaf_name(filename);

    if leaf.contains(RLO) && leaf.contains('.') {
        let ext = extension_of(leaf).to_ascii_lowercase();
        if is_known_extension(&ext) || leaf.contains(&format!(".{RLO}")) {
            out.rlo_attack = true;
            out.details
                .push(format!("RLO character in '{leaf}' with extension '{ext}'"));
        }
    }

    if leaf.contains("  ") {
        let mut run = 0usize;
        let mut max_run = 0usize;
        for ch in leaf.chars() {
            if ch == ' ' {
                run += 1;
                max_run = max_run.max(run);
            } else {
                run = 0;
            }
        }
        if max_run > MAX_SPACES {
            out.excessive_spaces = true;
            out.details
                .push(format!("Excessive spaces: {max_run} consecutive"));
            let trimmed = leaf.trim_end();
            if trimmed != leaf {
                let hidden = extension_of(trimmed).to_ascii_lowercase();
                if is_known_extension(&hidden) {
                    out.details
                        .push(format!("Potential hidden extension: '{hidden}'"));
                }
            }
        }
    }

    let parts: Vec<&str> = leaf.split('.').collect();
    if parts.len() > 5 {
        let known: Vec<String> = parts[1..]
            .iter()
            .map(|p| format!(".{}", p.to_ascii_lowercase()))
            .filter(|e| is_known_extension(e))
            .collect();
        if !known.is_empty() {
            out.multiple_extensions = true;
            out.details.push(format!(
                "Excessive extensions ({}): {known:?}",
                parts.len() - 1
            ));
        }
    }

    out
}

struct ZipCdEntry {
    name: String,
    encrypted: bool,
    uncompressed_size: u64,
    is_dir: bool,
    local_header_offset: u64,
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let min = data.len().saturating_sub(65_557);
    (min..=data.len() - 22)
        .rev()
        .find(|&i| data.get(i..i + 4) == Some(&b"PK\x05\x06"[..]))
}

fn parse_zip_cd(data: &[u8]) -> Option<Vec<ZipCdEntry>> {
    let eocd = find_eocd(data)?;
    let total = read_u16(data, eocd + 10)? as usize;
    let cd_off = read_u32(data, eocd + 16)? as usize;
    if total == 0 || cd_off >= data.len() {
        return None;
    }
    let mut cursor = cd_off;
    let mut out = Vec::new();
    let limit = total.min(crate::MAX_ARCHIVE_ENTRIES).max(1);
    for _ in 0..limit {
        if data.get(cursor..cursor + 4) != Some(&b"PK\x01\x02"[..]) {
            break;
        }
        let flags = read_u16(data, cursor + 8)?;
        let method = read_u16(data, cursor + 10)?;
        let compressed = read_u32(data, cursor + 20)? as u64;
        let uncompressed = read_u32(data, cursor + 24)? as u64;
        let name_len = read_u16(data, cursor + 28)? as usize;
        let extra_len = read_u16(data, cursor + 30)? as usize;
        let comment_len = read_u16(data, cursor + 32)? as usize;
        let local_off = read_u32(data, cursor + 42)? as u64;
        let name_start = cursor + 46;
        let name_end = name_start.saturating_add(name_len);
        let name_bytes = data.get(name_start..name_end)?;
        let name = String::from_utf8_lossy(name_bytes).replace('\\', "/");
        let is_dir = name.ends_with('/');
        let encrypted = (flags & ZIP_ENCRYPT_FLAG) != 0 || method == ZIP_AES_METHOD;
        let _ = compressed;
        out.push(ZipCdEntry {
            name,
            encrypted,
            uncompressed_size: uncompressed,
            is_dir,
            local_header_offset: local_off,
        });
        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
        if cursor >= data.len() {
            break;
        }
    }
    Some(out)
}

fn zip_member_prefix(data: &[u8], entry: &ZipCdEntry, max: usize) -> Option<Vec<u8>> {
    if entry.encrypted {
        return None;
    }
    crate::zip_extract_entry(data, &entry.name)
        .ok()
        .map(|buf| buf.into_iter().take(max).collect())
}

fn emit_filename_hits(
    format: &str,
    name: &str,
    encrypted: bool,
    out: &mut Vec<ArchiveHeuristic>,
) {
    let det = detect_suspicious_filename(name);
    if !det.suspicious() {
        return;
    }
    let label = det.attack_label();
    let heur_name: &'static str = match (label.as_str(), encrypted, format) {
        ("RLO", true, "zip") => "HEUR:RLO.Susp.Name.Encrypted.ZIP.gen",
        ("RLO", false, "zip") => "HEUR:RLO.Susp.Name.ZIP.gen",
        ("Spaces", true, "zip") => "HEUR:Spaces.Susp.Name.Encrypted.ZIP.gen",
        ("Spaces", false, "zip") => "HEUR:Spaces.Susp.Name.ZIP.gen",
        ("MultiExt", true, "zip") => "HEUR:MultiExt.Susp.Name.Encrypted.ZIP.gen",
        ("MultiExt", false, "zip") => "HEUR:MultiExt.Susp.Name.ZIP.gen",
        ("RLO", true, "7z") => "HEUR:RLO.Susp.Name.Encrypted.7z.gen",
        ("RLO", false, "7z") => "HEUR:RLO.Susp.Name.7z.gen",
        ("RLO", _, "tar") => "HEUR:RLO.Susp.Name.TAR.gen",
        ("RLO", true, "rar") => "HEUR:RLO.Susp.Name.Encrypted.RAR.gen",
        ("RLO", false, "rar") => "HEUR:RLO.Susp.Name.RAR.gen",
        _ => "HEUR:Susp.Name.Archive.gen",
    };
    out.push(ArchiveHeuristic {
        name: heur_name,
        score: if det.rlo_attack { 0.95 } else { 0.85 },
        details: format!("{}: {}", label, det.details.join("; ")),
        entry_name: Some(name.to_string()),
    });
}

fn inspect_zip(data: &[u8]) -> Vec<ArchiveHeuristic> {
    let Some(entries) = parse_zip_cd(data) else {
        return Vec::new();
    };
    let files: Vec<&ZipCdEntry> = entries.iter().filter(|e| !e.is_dir).collect();
    let mut out = Vec::new();
    let archive_len = data.len() as u64;
    let mut enc = 0usize;
    let mut plain = 0usize;

    for e in &files {
        if e.encrypted {
            enc += 1;
        } else {
            plain += 1;
        }
        emit_filename_hits("zip", &e.name, e.encrypted, &mut out);
        if archive_len < SIZE_BOMB_ARCHIVE && e.uncompressed_size > SIZE_BOMB_MEMBER {
            out.push(ArchiveHeuristic {
                name: if e.encrypted {
                    "HEUR:Win32.Susp.Size.Encrypted.ZIP"
                } else {
                    "HEUR:Win32.Susp.Size.ZIP"
                },
                score: 0.90,
                details: format!(
                    "archive {} bytes, member '{}' claims {} bytes",
                    archive_len, e.name, e.uncompressed_size
                ),
                entry_name: Some(e.name.clone()),
            });
        }
        if !e.encrypted {
            if let Some(trick) = inspect_stored_pe_rva(data, e) {
                out.push(trick);
            }
        }
    }

    if files.len() == 1 && enc == 1 {
        out.push(ArchiveHeuristic {
            name: "HEUR:Win32.Susp.Encrypted.Zip.SingleFile",
            score: 0.75,
            details: format!(
                "password-protected ZIP with a single file '{}'",
                files[0].name
            ),
            entry_name: Some(files[0].name.clone()),
        });
    }

    if enc >= 1 && plain >= 1 {
        let bait: Vec<&str> = files
            .iter()
            .filter(|e| !e.encrypted)
            .map(|e| e.name.as_str())
            .collect();
        out.push(ArchiveHeuristic {
            name: "HEUR:Win32.Susp.Encrypted.Zip.PlaintextBait",
            score: 0.92,
            details: format!(
                "encrypted ZIP ({enc} encrypted, {plain} plaintext) hides payload behind unencrypted bait {bait:?}"
            ),
            entry_name: bait.first().map(|s| s.to_string()),
        });
    }

    if files.len() == 1 && plain == 1 {
        if let Some(prefix) = zip_member_prefix(data, files[0], 4096) {
            if let Ok(text) = std::str::from_utf8(&prefix) {
                if text.to_ascii_lowercase().contains("pass") {
                    out.push(ArchiveHeuristic {
                        name: "HEUR:Win32.Susp.Encrypted.Zip.SingleEntry",
                        score: 0.85,
                        details: format!(
                            "single unencrypted ZIP member '{}' contains password lure",
                            files[0].name
                        ),
                        entry_name: Some(files[0].name.clone()),
                    });
                }
            }
        }
    }

    out
}

fn inspect_stored_pe_rva(data: &[u8], entry: &ZipCdEntry) -> Option<ArchiveHeuristic> {
    let local = entry.local_header_offset as usize;
    if data.get(local..local + 4) != Some(&b"PK\x03\x04"[..]) {
        return None;
    }
    let flags = read_u16(data, local + 6)?;
    if flags & ZIP_ENCRYPT_FLAG != 0 {
        return None;
    }
    let method = read_u16(data, local + 8)?;
    if method != 0 {
        return None;
    }
    let name_len = read_u16(data, local + 26)? as usize;
    let extra_len = read_u16(data, local + 28)? as usize;
    let start = local.saturating_add(30).saturating_add(name_len).saturating_add(extra_len);
    let slice = data.get(start..)?;
    let pe = if slice.len() > 2 * 1024 * 1024 {
        &slice[..2 * 1024 * 1024]
    } else {
        slice
    };
    let detail = inspect_pe_rva_trick(pe)?;
    Some(ArchiveHeuristic {
        name: "HEUR:Win32.Susp.PE.RVATrick",
        score: 0.90,
        details: format!("{} in ZIP member '{}'", detail, entry.name),
        entry_name: Some(entry.name.clone()),
    })
}

pub fn inspect_pe_rva_trick(data: &[u8]) -> Option<String> {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let e_lfanew = read_u32(data, 0x3c)? as usize;
    if e_lfanew < 0x40 || e_lfanew.saturating_add(24) > data.len() {
        return None;
    }
    if data.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return None;
    }
    let num_sections = read_u16(data, e_lfanew + 6)? as usize;
    let size_of_optional = read_u16(data, e_lfanew + 20)? as usize;
    let opt = e_lfanew + 24;
    if opt + 18 > data.len() {
        return None;
    }
    let magic = read_u16(data, opt)?;
    if magic != 0x10b && magic != 0x20b {
        return None;
    }
    let ep_rva = read_u32(data, opt + 16)?;
    let size_of_image = if magic == 0x10b {
        read_u32(data, opt + 56)?
    } else {
        read_u32(data, opt + 56)?
    };
    let num_rva = if magic == 0x10b {
        read_u32(data, opt + 92).unwrap_or(16)
    } else {
        read_u32(data, opt + 108).unwrap_or(16)
    };
    if num_rva == 0 && ep_rva != 0 {
        return Some(format!(
            "NumberOfRvaAndSizes is 0 but AddressOfEntryPoint is 0x{ep_rva:x}"
        ));
    }
    if num_sections == 0 || num_sections > 96 {
        return Some(format!("implausible NumberOfSections={num_sections}"));
    }
    let sec_off = opt + size_of_optional;
    let mut in_virtual = false;
    let mut in_raw = false;
    let mut exec = false;
    for i in 0..num_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let vs = read_u32(data, s + 8)?;
        let va = read_u32(data, s + 12)?;
        let raw_size = read_u32(data, s + 16)?;
        let chars = read_u32(data, s + 36)?;
        let span = vs.max(raw_size);
        if ep_rva >= va && ep_rva < va.saturating_add(span) {
            in_virtual = true;
            let delta = ep_rva - va;
            if delta < raw_size {
                in_raw = true;
            }
            exec = chars & 0x2000_0000 != 0;
        }
    }
    if ep_rva != 0 && ep_rva >= size_of_image && size_of_image != 0 {
        return Some(format!(
            "AddressOfEntryPoint RVA 0x{ep_rva:x} is past SizeOfImage 0x{size_of_image:x} (overlay EP)"
        ));
    }
    if ep_rva != 0 && !in_virtual {
        return Some(format!(
            "AddressOfEntryPoint RVA 0x{ep_rva:x} is outside all sections"
        ));
    }
    if in_virtual && !in_raw {
        return Some(format!(
            "AddressOfEntryPoint RVA 0x{ep_rva:x} lands in virtual-only section padding"
        ));
    }
    if in_virtual && !exec {
        return Some(format!(
            "AddressOfEntryPoint RVA 0x{ep_rva:x} is in a non-executable section"
        ));
    }
    None
}

fn inspect_7z(data: &[u8]) -> Vec<ArchiveHeuristic> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(data);
    let Ok(mut reader) =
        sevenz_rust2::ArchiveReader::new(&mut cursor, sevenz_rust2::Password::from(""))
    else {
        return out;
    };
    let files: Vec<(String, bool, u64)> = {
        let archive = reader.archive();
        let enc_blocks: Vec<bool> = archive
            .blocks
            .iter()
            .map(|b| {
                b.coders
                    .iter()
                    .any(|c| c.encoder_method_id() == AES256_SHA256)
            })
            .collect();
        archive
            .files
            .iter()
            .enumerate()
            .filter(|(_, file)| !file.is_directory && file.has_stream)
            .map(|(i, file)| {
                let encrypted = archive
                    .stream_map
                    .file_block_index
                    .get(i)
                    .copied()
                    .flatten()
                    .and_then(|bi| enc_blocks.get(bi).copied())
                    .unwrap_or(false);
                (file.name.clone(), encrypted, file.size)
            })
            .collect()
    };
    let archive_len = data.len() as u64;
    let mut enc = 0usize;
    let mut plain = 0usize;
    for (name, encrypted, size) in &files {
        if *encrypted {
            enc += 1;
        } else {
            plain += 1;
        }
        emit_filename_hits("7z", name, *encrypted, &mut out);
        if archive_len < SIZE_BOMB_ARCHIVE && *size > SIZE_BOMB_MEMBER {
            out.push(ArchiveHeuristic {
                name: if *encrypted {
                    "HEUR:Win32.Susp.Size.Encrypted.7z"
                } else {
                    "HEUR:Win32.Susp.Size.7z"
                },
                score: 0.90,
                details: format!("archive {archive_len} bytes, member '{name}' claims {size} bytes"),
                entry_name: Some(name.clone()),
            });
        }
    }
    if files.len() == 1 && enc == 1 {
        out.push(ArchiveHeuristic {
            name: "HEUR:Win32.Susp.Encrypted.7z.SingleFile",
            score: 0.75,
            details: format!("password-protected 7z with a single file '{}'", files[0].0),
            entry_name: Some(files[0].0.clone()),
        });
    }
    if enc >= 1 && plain >= 1 {
        let bait: Vec<&str> = files
            .iter()
            .filter(|(_, e, _)| !*e)
            .map(|(n, _, _)| n.as_str())
            .collect();
        out.push(ArchiveHeuristic {
            name: "HEUR:Win32.Susp.Encrypted.7z.PlaintextBait",
            score: 0.92,
            details: format!(
                "encrypted 7z ({enc} encrypted, {plain} plaintext) with unencrypted bait {bait:?}"
            ),
            entry_name: bait.first().map(|s| s.to_string()),
        });
    }
    if files.len() == 1 && plain == 1 {
        if let Ok(buf) = reader.read_file(&files[0].0) {
            let prefix = &buf[..buf.len().min(4096)];
            if let Ok(text) = std::str::from_utf8(prefix) {
                if text.to_ascii_lowercase().contains("pass") {
                    out.push(ArchiveHeuristic {
                        name: "HEUR:Win32.Susp.Encrypted.7z.SingleEntry",
                        score: 0.85,
                        details: format!(
                            "single unencrypted 7z member '{}' contains password lure",
                            files[0].0
                        ),
                        entry_name: Some(files[0].0.clone()),
                    });
                }
            }
            if let Some(detail) = inspect_pe_rva_trick(&buf) {
                out.push(ArchiveHeuristic {
                    name: "HEUR:Win32.Susp.PE.RVATrick",
                    score: 0.90,
                    details: format!("{} in 7z member '{}'", detail, files[0].0),
                    entry_name: Some(files[0].0.clone()),
                });
            }
        }
    }
    out
}

fn inspect_tar(data: &[u8]) -> Vec<ArchiveHeuristic> {
    let mut out = Vec::new();
    let Ok(entries) = crate::tar_entries(data) else {
        return out;
    };
    let archive_len = data.len() as u64;
    for e in &entries {
        emit_filename_hits("tar", &e.name, false, &mut out);
        if archive_len < SIZE_BOMB_ARCHIVE && e.size_real > SIZE_BOMB_MEMBER {
            out.push(ArchiveHeuristic {
                name: "HEUR:Win32.Susp.Size.Encrypted.TAR",
                score: 0.90,
                details: format!(
                    "TAR {} bytes contains '{}' of {} bytes",
                    archive_len, e.name, e.size_real
                ),
                entry_name: Some(e.name.clone()),
            });
        }
        if let Some(detail) = inspect_pe_rva_trick(&e.data) {
            out.push(ArchiveHeuristic {
                name: "HEUR:Win32.Susp.PE.RVATrick",
                score: 0.90,
                details: format!("{} in TAR member '{}'", detail, e.name),
                entry_name: Some(e.name.clone()),
            });
        }
    }
    out
}

fn inspect_rar(data: &[u8]) -> Vec<ArchiveHeuristic> {
    crate::rar::inspect(data)
}

pub fn inspect_archive(data: &[u8]) -> Vec<ArchiveHeuristic> {
    if data.starts_with(&crate::ZIP_LOCAL_MAGIC) {
        inspect_zip(data)
    } else if data.starts_with(&crate::SEVENZ_MAGIC) {
        inspect_7z(data)
    } else if crate::is_rar(data) {
        inspect_rar(data)
    } else if crate::is_tar(data) {
        inspect_tar(data)
    } else if data.starts_with(&crate::GZIP_MAGIC) {
        crate::decompress_gzip(data)
            .ok()
            .filter(|d| crate::is_tar(d))
            .map(|d| inspect_tar(&d))
            .unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub(crate) fn rar_heuristics(
    members: &[(String, bool, u64)],
    archive_len: u64,
) -> Vec<ArchiveHeuristic> {
    let mut out = Vec::new();
    let files: Vec<&(String, bool, u64)> = members.iter().collect();
    let mut enc = 0usize;
    let mut plain = 0usize;
    for (name, encrypted, size) in &files {
        if *encrypted {
            enc += 1;
        } else {
            plain += 1;
        }
        emit_filename_hits("rar", name, *encrypted, &mut out);
        if archive_len < SIZE_BOMB_ARCHIVE && *size > SIZE_BOMB_MEMBER {
            out.push(ArchiveHeuristic {
                name: if *encrypted {
                    "HEUR:Win32.Susp.Size.Encrypted.RAR"
                } else {
                    "HEUR:Win32.Susp.Size.RAR"
                },
                score: 0.90,
                details: format!("archive {archive_len} bytes, member '{name}' claims {size} bytes"),
                entry_name: Some((*name).clone()),
            });
        }
    }
    if files.len() == 1 && enc == 1 {
        out.push(ArchiveHeuristic {
            name: "HEUR:Win32.Susp.Encrypted.RAR.SingleFile",
            score: 0.75,
            details: format!("password-protected RAR with a single file '{}'", files[0].0),
            entry_name: Some(files[0].0.clone()),
        });
    }
    if enc >= 1 && plain >= 1 {
        let bait: Vec<&str> = files
            .iter()
            .filter(|(_, e, _)| !*e)
            .map(|(n, _, _)| n.as_str())
            .collect();
        out.push(ArchiveHeuristic {
            name: "HEUR:Win32.Susp.Encrypted.RAR.PlaintextBait",
            score: 0.92,
            details: format!(
                "encrypted RAR ({enc} encrypted, {plain} plaintext) with unencrypted bait {bait:?}"
            ),
            entry_name: bait.first().map(|s| s.to_string()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zip_store(entries: &[(&str, bool, &[u8])]) -> Vec<u8> {
        let mut locals = Vec::new();
        let mut cd = Vec::new();
        for (name, encrypted, payload) in entries {
            let name_b = name.as_bytes();
            let flags: u16 = if *encrypted { 1 } else { 0 };
            let crc = 0u32;
            let size = payload.len() as u32;
            let local_off = locals.len() as u32;
            locals.extend_from_slice(&0x04034b50u32.to_le_bytes());
            locals.extend_from_slice(&20u16.to_le_bytes());
            locals.extend_from_slice(&flags.to_le_bytes());
            locals.extend_from_slice(&0u16.to_le_bytes());
            locals.extend_from_slice(&0u16.to_le_bytes());
            locals.extend_from_slice(&0u16.to_le_bytes());
            locals.extend_from_slice(&crc.to_le_bytes());
            locals.extend_from_slice(&size.to_le_bytes());
            locals.extend_from_slice(&size.to_le_bytes());
            locals.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            locals.extend_from_slice(&0u16.to_le_bytes());
            locals.extend_from_slice(name_b);
            locals.extend_from_slice(payload);
            cd.extend_from_slice(&0x02014b50u32.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&flags.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&size.to_le_bytes());
            cd.extend_from_slice(&size.to_le_bytes());
            cd.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u32.to_le_bytes());
            cd.extend_from_slice(&local_off.to_le_bytes());
            cd.extend_from_slice(name_b);
        }
        let cd_off = locals.len() as u32;
        let cd_size = cd.len() as u32;
        let count = entries.len() as u16;
        let mut out = locals;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&0x06054b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn rlo_after_dot_is_detected() {
        let name = format!("invoice.{RLO}fdp.exe");
        let det = detect_suspicious_filename(&name);
        assert!(det.rlo_attack, "{:?}", det.details);
        assert!(det.suspicious());
    }

    #[test]
    fn clean_name_is_not_suspicious() {
        let det = detect_suspicious_filename("readme.txt");
        assert!(!det.suspicious());
    }

    #[test]
    fn excessive_spaces_detected() {
        let name = format!("photo{}.exe", " ".repeat(12));
        let det = detect_suspicious_filename(&name);
        assert!(det.excessive_spaces);
    }

    #[test]
    fn single_encrypted_zip_matches_yara_shape() {
        let zip = zip_store(&[("payload.exe", true, b"MZ")]);
        let hits = inspect_zip(&zip);
        assert!(
            hits.iter()
                .any(|h| h.name == "HEUR:Win32.Susp.Encrypted.Zip.SingleFile"),
            "{hits:?}"
        );
    }

    #[test]
    fn mixed_encrypted_zip_flags_plaintext_bait() {
        let zip = zip_store(&[
            ("password.txt", false, b"Password: hunter2"),
            ("payload.exe", true, b"MZ"),
        ]);
        let hits = inspect_zip(&zip);
        assert!(
            hits.iter()
                .any(|h| h.name == "HEUR:Win32.Susp.Encrypted.Zip.PlaintextBait"),
            "{hits:?}"
        );
    }

    #[test]
    fn rlo_name_in_zip() {
        let name = format!("photo.{RLO}gpj.exe");
        let zip = zip_store(&[(&name, false, b"MZ")]);
        let hits = inspect_zip(&zip);
        assert!(
            hits.iter().any(|h| h.name.contains("RLO")),
            "{hits:?}"
        );
    }

    #[test]
    fn pe_ep_outside_sections_is_rva_trick() {
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86] = 1;
        pe[0x80 + 20] = 0xe0;
        pe[0x80 + 24] = 0x0b;
        pe[0x80 + 25] = 0x01;
        let ep = 0x00ff_0000u32;
        pe[0x80 + 24 + 16..0x80 + 24 + 20].copy_from_slice(&ep.to_le_bytes());
        pe[0x80 + 24 + 56..0x80 + 24 + 60].copy_from_slice(&0x1000u32.to_le_bytes());
        let sec = 0x80 + 24 + 0xe0;
        if sec + 40 <= pe.len() {
            pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            pe[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes());
            pe[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
            pe[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        }
        let hit = inspect_pe_rva_trick(&pe);
        assert!(hit.is_some(), "expected RVA trick, got {hit:?}");
    }
}
