//! VBA macro source extraction from compound-file Office documents.
//!
//! A VBA project is a storage (`Macros/VBA`, `_VBA_PROJECT_CUR/VBA`, `VBA`)
//! holding a `dir` stream and one stream per module. Both use the [MS-OVBA]
//! compression (2.4.1); the `dir` stream lists every module with its stream
//! name and the offset where the compressed source starts inside that stream
//! (2.3.4.2). When `dir` cannot be read, module streams are searched for the
//! compressed container that starts their `Attribute VB_Name` header.
//!
//! The recovered sources feed `report.decoded_strings` as `vba_source`, so the
//! existing `decoded` string conditions match macro code with no new condition.
//! All work is capped; malformed input yields fewer modules, never a panic.

use super::cfb::{read_streams, CfbStream};
use super::scripts::ScriptDecodeConfig;
use crate::models::DecodedString;
use crate::utils::text::truncate_middle;

/// Decompressed bytes produced from one compressed container.
pub const MAX_DECOMPRESSED: usize = 1024 * 1024;
const CHUNK_DATA: usize = 4096;
const MAX_MODULES: usize = 512;
/// Bytes read per stream of the document.
const MAX_STREAM_READ: usize = 8 * 1024 * 1024;
const MAX_TOTAL_READ: usize = 64 * 1024 * 1024;
/// Overlap between pieces of a line longer than `decoded_trunc`.
const LINE_OVERLAP: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VbaInfo {
    pub modules: usize,
    pub module_names: Vec<String>,
    /// Decompressed source of each module, same order as `module_names`.
    pub sources: Vec<String>,
}

/// [MS-OVBA] 2.4.1 decompression of a CompressedContainer. `None` when the
/// signature byte is not 0x01 or the first chunk is invalid; a later invalid
/// chunk ends the output there. At most [`MAX_DECOMPRESSED`] bytes.
pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.first() != Some(&0x01) {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 1usize;
    while pos + 2 <= data.len() && out.len() < MAX_DECOMPRESSED {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if (header >> 12) & 0b111 != 0b011 {
            break;
        }
        let chunk_end = (pos + (header & 0x0fff) as usize + 3).min(data.len());
        let compressed = header & 0x8000 != 0;
        pos += 2;
        let chunk_start = out.len();
        if !compressed {
            let end = (pos + CHUNK_DATA).min(data.len());
            out.extend_from_slice(&data[pos..end]);
            pos = end;
            continue;
        }
        'chunk: while pos < chunk_end {
            let flags = data[pos];
            pos += 1;
            for bit in 0..8 {
                if pos >= chunk_end || out.len() >= MAX_DECOMPRESSED {
                    break 'chunk;
                }
                if flags & (1 << bit) == 0 {
                    out.push(data[pos]);
                    pos += 1;
                    continue;
                }
                if pos + 2 > chunk_end {
                    break 'chunk;
                }
                let token = u16::from_le_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                let difference = out.len() - chunk_start;
                let bit_count = ceil_log2(difference).clamp(4, 12);
                let length_mask = 0xffffu16 >> bit_count;
                let length = (token & length_mask) as usize + 3;
                let offset = ((token & !length_mask) >> (16 - bit_count)) as usize + 1;
                if offset > difference {
                    return (!out.is_empty()).then_some(out);
                }
                let from = out.len() - offset;
                for i in 0..length.min(MAX_DECOMPRESSED - out.len()) {
                    out.push(out[from + i]);
                }
            }
        }
        pos = chunk_end;
    }
    (!out.is_empty()).then_some(out)
}

fn ceil_log2(n: usize) -> u32 {
    if n <= 1 { 0 } else { usize::BITS - (n - 1).leading_zeros() }
}

/// One module as listed by the `dir` stream.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ModuleRecord {
    name: String,
    stream: String,
    offset: usize,
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Module records of a decompressed `dir` stream ([MS-OVBA] 2.3.4.2): a run of
/// `id u16, size u32, data` records. PROJECTVERSION (0x0009) is the one record
/// whose size field does not count its data (4 + 6 bytes follow the id).
fn parse_dir(dir: &[u8]) -> Vec<ModuleRecord> {
    let mut modules = Vec::new();
    let mut current: Option<ModuleRecord> = None;
    let mut pos = 0usize;
    while pos + 6 <= dir.len() && modules.len() < MAX_MODULES {
        let id = u16::from_le_bytes([dir[pos], dir[pos + 1]]);
        let size = u32::from_le_bytes([dir[pos + 2], dir[pos + 3], dir[pos + 4], dir[pos + 5]]) as usize;
        if id == 0x0009 {
            pos += 2 + 4 + 6;
            continue;
        }
        let start = pos + 6;
        let Some(end) = start.checked_add(size).filter(|&e| e <= dir.len()) else { break };
        let data = &dir[start..end];
        match id {
            0x0019 => current = Some(ModuleRecord { name: String::from_utf8_lossy(data).into_owned(), ..Default::default() }),
            0x0047 => {
                if let Some(m) = current.as_mut() {
                    m.name = utf16le(data);
                }
            }
            0x001a => {
                if let Some(m) = current.as_mut() {
                    m.stream = String::from_utf8_lossy(data).into_owned();
                }
            }
            0x0032 => {
                if let Some(m) = current.as_mut() {
                    m.stream = utf16le(data);
                }
            }
            0x0031 if data.len() == 4 => {
                if let Some(m) = current.as_mut() {
                    m.offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                }
            }
            0x002b => {
                if let Some(m) = current.take() {
                    modules.push(m);
                }
            }
            0x0010 => break,
            _ => {}
        }
        pos = end;
    }
    modules
}

/// Offset of the compressed container holding a module's source when `dir` is
/// unusable: the container signature, a chunk header, a flag byte and the
/// literal `Attribut` that every exported module starts with.
fn find_source_container(stream: &[u8]) -> Option<usize> {
    memchr::memmem::find_iter(stream, b"\x00Attribut")
        .filter_map(|p| p.checked_sub(3))
        .find(|&start| stream[start] == 0x01 && (stream[start + 2] >> 4) & 0b0111 == 0b011)
}

fn module_source(stream: &[u8], offset: Option<usize>) -> Option<String> {
    let offset = offset.filter(|&o| stream.get(o) == Some(&0x01)).or_else(|| find_source_container(stream))?;
    let bytes = decompress(&stream[offset..])?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Storages named `VBA` (`Macros/VBA`, `_VBA_PROJECT_CUR/VBA`): the VBA projects.
fn project_roots(streams: &[CfbStream]) -> Vec<String> {
    let mut roots: Vec<String> = streams
        .iter()
        .filter_map(|s| {
            let (parent, _) = s.path.rsplit_once('/')?;
            parent.rsplit('/').next().is_some_and(|p| p.eq_ignore_ascii_case("vba")).then(|| parent.to_string())
        })
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// Streams of a VBA storage that are not project metadata (`dir`,
/// `_VBA_PROJECT`, `__SRP_n`, `PROJECT*`).
fn is_module_candidate(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !(lower == "dir" || lower == "_vba_project" || lower.starts_with("__srp_") || lower.starts_with("project"))
}

/// Modules and decompressed sources of every VBA project in a compound file.
/// `None` when `buf` is not a compound file or holds no module source.
pub fn extract(buf: &[u8]) -> Option<VbaInfo> {
    let streams = read_streams(buf, MAX_STREAM_READ, MAX_TOTAL_READ)?;
    let mut info = VbaInfo::default();
    for root in project_roots(&streams) {
        let in_root = |name: &str| {
            let path = format!("{root}/{name}");
            streams.iter().find(|s| s.path.eq_ignore_ascii_case(&path))
        };
        let records = in_root("dir").and_then(|d| decompress(&d.data)).map(|d| parse_dir(&d)).unwrap_or_default();
        let mut done: Vec<&str> = Vec::new();
        for record in &records {
            let Some(stream) = in_root(&record.stream) else { continue };
            if let Some(source) = module_source(&stream.data, Some(record.offset)) {
                info.module_names.push(if record.name.is_empty() { record.stream.clone() } else { record.name.clone() });
                info.sources.push(source);
                done.push(stream.path.as_str());
            }
        }
        // `dir` missing, damaged or listing fewer modules than are stored.
        let prefix = format!("{root}/");
        for stream in &streams {
            let Some(name) = stream.path.strip_prefix(&prefix) else { continue };
            if name.contains('/') || !is_module_candidate(name) || done.contains(&stream.path.as_str()) {
                continue;
            }
            if let Some(source) = module_source(&stream.data, None) {
                info.module_names.push(name.to_string());
                info.sources.push(source);
            }
        }
    }
    info.module_names.truncate(MAX_MODULES);
    info.sources.truncate(MAX_MODULES);
    info.modules = info.sources.len();
    (info.modules > 0).then_some(info)
}

/// One `vba_source` decoded string per non-blank source line (`source` is
/// `<module>:<line>`); lines longer than `decoded_trunc` are split into
/// overlapping pieces so no part of the code is dropped. At most
/// `output_limit` entries.
pub fn decoded_strings(info: &VbaInfo, cfg: &ScriptDecodeConfig) -> Vec<DecodedString> {
    let piece = cfg.decoded_trunc.max(LINE_OVERLAP * 2);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    'all: for (name, source) in info.module_names.iter().zip(&info.sources) {
        for (no, line) in source.lines().enumerate() {
            let line = line.trim();
            if line.chars().count() < cfg.decoded_min_len {
                continue;
            }
            let chars: Vec<char> = line.chars().collect();
            let mut start = 0usize;
            loop {
                let end = (start + piece).min(chars.len());
                let text: String = chars[start..end].iter().collect();
                if seen.insert(text.clone()) {
                    out.push(DecodedString {
                        method: "vba_source".to_string(),
                        source: truncate_middle(&format!("{name}:{}", no + 1), cfg.source_trunc),
                        decoded: text,
                    });
                    if out.len() >= cfg.output_limit {
                        break 'all;
                    }
                }
                if end == chars.len() {
                    break;
                }
                start = end - LINE_OVERLAP;
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// [MS-OVBA] compression (greedy longest match), for fixtures.
    pub(crate) fn compress(input: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01u8];
        for chunk in input.chunks(CHUNK_DATA) {
            let mut body = Vec::new();
            let mut pos = 0usize;
            while pos < chunk.len() {
                let flag_at = body.len();
                body.push(0u8);
                for bit in 0..8 {
                    if pos >= chunk.len() {
                        break;
                    }
                    let bit_count = ceil_log2(pos).clamp(4, 12);
                    let max_len = (0xffffusize >> bit_count) + 3;
                    let max_off = 1usize << bit_count;
                    let (mut best_len, mut best_off) = (0usize, 0usize);
                    for off in 1..=pos.min(max_off) {
                        let mut len = 0;
                        while len < max_len && pos + len < chunk.len() && chunk[pos + len] == chunk[pos - off + len] {
                            len += 1;
                        }
                        if len > best_len {
                            (best_len, best_off) = (len, off);
                            if len == max_len {
                                break;
                            }
                        }
                    }
                    if best_len >= 3 {
                        let token = (((best_off - 1) << (16 - bit_count)) | (best_len - 3)) as u16;
                        body.extend_from_slice(&token.to_le_bytes());
                        body[flag_at] |= 1 << bit;
                        pos += best_len;
                    } else {
                        body.push(chunk[pos]);
                        pos += 1;
                    }
                }
            }
            let header = 0xb000u16 | (body.len() + 2 - 3) as u16;
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    fn record(out: &mut Vec<u8>, id: u16, data: &[u8]) {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Decompressed `dir` stream listing `(module name, stream name, offset)`.
    pub(crate) fn dir_stream(modules: &[(&str, &str, u32)]) -> Vec<u8> {
        let mut d = Vec::new();
        record(&mut d, 0x0001, &1u32.to_le_bytes());
        record(&mut d, 0x0003, &1252u16.to_le_bytes());
        record(&mut d, 0x0004, b"VBAProject");
        d.extend_from_slice(&0x0009u16.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes());
        d.extend_from_slice(&[1, 0, 0, 0, 7, 0]);
        record(&mut d, 0x000f, &(modules.len() as u16).to_le_bytes());
        record(&mut d, 0x0013, &0xffffu16.to_le_bytes());
        for (name, stream, offset) in modules {
            record(&mut d, 0x0019, name.as_bytes());
            record(&mut d, 0x0047, &utf16(name));
            record(&mut d, 0x001a, stream.as_bytes());
            record(&mut d, 0x0032, &utf16(stream));
            record(&mut d, 0x0031, &offset.to_le_bytes());
            record(&mut d, 0x0021, &[]);
            record(&mut d, 0x002b, &[]);
        }
        record(&mut d, 0x0010, &[]);
        d
    }

    /// Module stream: `pcode_len` bytes of performance cache, then the compressed source.
    pub(crate) fn module_stream(pcode_len: usize, source: &str) -> Vec<u8> {
        let mut s = vec![0xccu8; pcode_len];
        s.extend(compress(source.as_bytes()));
        s
    }

    /// Word-style document whose `Macros/VBA` project holds `modules`
    /// (name, source); module streams carry 37 bytes of performance cache.
    pub(crate) fn macro_document(modules: &[(&str, &str)], with_dir: bool) -> Vec<u8> {
        let mut streams: Vec<(String, Vec<u8>)> = vec![("WordDocument".into(), vec![0u8; 64])];
        let listing: Vec<(&str, &str, u32)> = modules.iter().map(|(n, _)| (*n, *n, 37u32)).collect();
        if with_dir {
            streams.push(("Macros/VBA/dir".into(), compress(&dir_stream(&listing))));
        }
        streams.push(("Macros/VBA/_VBA_PROJECT".into(), vec![0xcc, 0x61, 0xff, 0xff]));
        for (name, source) in modules {
            streams.push((format!("Macros/VBA/{name}"), module_stream(37, source)));
        }
        let refs: Vec<(&str, &[u8])> = streams.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        super::super::cfb::tests::write_cfb(&refs)
    }

    const SOURCE: &str = "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n    Set sh = CreateObject(\"WScript.Shell\")\r\n    sh.Run \"calc.exe\"\r\nEnd Sub\r\n";

    #[test]
    fn decompress_round_trip_and_spec_example() {
        // [MS-OVBA] 3.2.3: "#aaabcdefaaaaghijaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..." style input.
        let text = "#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(decompress(&compress(text.as_bytes())).unwrap(), text.as_bytes());
        let long: String = (0..2000).map(|i| format!("Dim v{i} As Long\r\n")).collect();
        assert!(long.len() > CHUNK_DATA * 2, "multi-chunk input");
        assert_eq!(decompress(&compress(long.as_bytes())).unwrap(), long.as_bytes());
        // Spec example 3.2.1: no compression possible, single literal run.
        let spec = [0x01, 0x19, 0xb0, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x00, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x00, 0x71, 0x72, 0x2e];
        assert_eq!(decompress(&spec).unwrap(), b"abcdefghijklmnopqr.");
        // Spec example 3.2.2: "abcdefghijklmnopqr." repeated through a copy token.
        let spec2 = [0x01, 0x2f, 0xb0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00, 0x70, 0x61, 0x67, 0x68, 0x69, 0x6a, 0x01, 0x38, 0x08, 0x61, 0x6b, 0x6c, 0x00, 0x30, 0x6d, 0x6e, 0x6f, 0x70, 0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7a, 0x00, 0x3c];
        assert_eq!(
            String::from_utf8(decompress(&spec2).unwrap()).unwrap(),
            "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
        );
    }

    #[test]
    fn decompress_rejects_and_caps() {
        assert!(decompress(b"").is_none());
        assert!(decompress(b"\x00abc").is_none(), "no container signature");
        assert!(decompress(&[0x01, 0x00, 0x00]).is_none(), "bad chunk signature");
        // Copy token reaching before the chunk start: stop, keep nothing.
        assert!(decompress(&[0x01, 0x03, 0xb0, 0x01, 0x00, 0x10]).is_none());
        // 4 MiB of one byte compresses tiny but must stop at the cap.
        let flood = compress(&vec![b'A'; 4 * MAX_DECOMPRESSED]);
        assert_eq!(decompress(&flood).unwrap().len(), MAX_DECOMPRESSED);
        let ok = compress(SOURCE.as_bytes());
        for cut in 0..ok.len() {
            let _ = decompress(&ok[..cut]);
        }
    }

    #[test]
    fn dir_records_name_modules_and_offsets() {
        let modules = parse_dir(&dir_stream(&[("ThisDocument", "ThisDocument", 1200), ("Módulo1", "Module1", 37)]));
        assert_eq!(
            modules,
            vec![
                ModuleRecord { name: "ThisDocument".into(), stream: "ThisDocument".into(), offset: 1200 },
                ModuleRecord { name: "Módulo1".into(), stream: "Module1".into(), offset: 37 },
            ]
        );
        assert!(parse_dir(&[0x19, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x41]).is_empty(), "oversized record");
    }

    #[test]
    fn extracts_sources_through_dir_and_without_it() {
        for with_dir in [true, false] {
            let doc = macro_document(&[("Module1", SOURCE), ("Helper", "Attribute VB_Name = \"Helper\"\r\nFunction X()\r\nEnd Function\r\n")], with_dir);
            let info = extract(&doc).expect("vba project");
            assert_eq!(info.modules, 2, "with_dir={with_dir}");
            let mut names = info.module_names.clone();
            names.sort();
            assert_eq!(names, vec!["Helper", "Module1"]);
            let i = info.module_names.iter().position(|n| n == "Module1").unwrap();
            assert_eq!(info.sources[i], SOURCE);
        }
        assert!(extract(&super::super::cfb::tests::write_cfb(&[("WordDocument", b"no macros")])).is_none());
        assert!(extract(b"plain text").is_none());
    }

    #[test]
    fn decoded_strings_cover_every_line() {
        let body: String = (0..1500).map(|i| (b'a' + (i % 26) as u8) as char).collect();
        let long_line = format!("x = \"{body}\"");
        let source = format!("{SOURCE}{long_line}\r\n");
        let info = VbaInfo { modules: 1, module_names: vec!["Module1".into()], sources: vec![source] };
        let cfg = ScriptDecodeConfig::default();
        let out = decoded_strings(&info, &cfg);
        assert!(out.iter().all(|d| d.method == "vba_source" && d.decoded.chars().count() <= cfg.decoded_trunc));
        let shell = out.iter().find(|d| d.decoded.contains("CreateObject(\"WScript.Shell\")")).unwrap();
        assert_eq!(shell.source, "Module1:3");
        let pieces = out.iter().filter(|d| d.source == "Module1:6").count();
        assert_eq!(pieces, 4, "1506 chars in 512-char pieces with 64 overlap");
        assert!(out.iter().any(|d| d.source == "Module1:6" && d.decoded.ends_with('"')));
        let capped = decoded_strings(&info, &ScriptDecodeConfig { output_limit: 2, ..ScriptDecodeConfig::default() });
        assert_eq!(capped.len(), 2);
    }
}
