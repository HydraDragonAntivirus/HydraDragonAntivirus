//! Non-executing structural PDF scanner for the `pdf_*` conditions.
//!
//! The cross-reference table is not trusted: indirect objects (`N G obj`) are
//! found by scanning the file, so junk before `%PDF-` (within the first 1 KiB),
//! broken xrefs and appended revisions are all read. Names are unescaped
//! (`/#4A#61#76#61#53#63#72#69#70#74` is `/JavaScript`) before they are
//! counted. Streams are decoded through `/FlateDecode`, `/ASCIIHexDecode`,
//! `/ASCII85Decode` and `/RunLengthDecode` (and their abbreviations), and
//! `/ObjStm` object streams are opened, all under fixed budgets: 2 MiB per
//! decoded stream, 16 MiB per file, a filter chain of at most 4 and at most
//! 4096 objects. A stream past a budget is truncated, never fully inflated.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

pub const MAX_STREAM_OUTPUT: usize = 2 * 1024 * 1024;
pub const MAX_TOTAL_OUTPUT: usize = 16 * 1024 * 1024;
pub const MAX_FILTER_CHAIN: usize = 4;
pub const MAX_OBJECTS: usize = 4096;
/// Where `%PDF-` may start.
pub const HEADER_WINDOW: usize = 1024;
const MAX_STRINGS: usize = 1024;
const MAX_STRING_LEN: usize = 64 * 1024;
/// Text kept per payload list (`javascript`, `uris`, `launches`).
const MAX_LIST_BYTES: usize = 1024 * 1024;

/// Counts and extracted payloads of a PDF (decoded stream bytes are kept
/// apart, in [`PdfStreams`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PdfInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Offset of `%PDF-`.
    pub header_offset: usize,
    pub obj_count: usize,
    pub stream_count: usize,
    pub objstm_count: usize,
    /// Occurrences of each (unescaped) name, without the `/`.
    pub names: BTreeMap<String, usize>,
    /// Names that were written with `#XX` escapes.
    pub obfuscated_names: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub javascript: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub launches: Vec<String>,
    /// Some stream hit a decode budget.
    pub truncated: bool,
}

impl PdfInfo {
    pub fn name_count(&self, name: &str) -> usize {
        self.names.get(name.trim_start_matches('/')).copied().unwrap_or(0)
    }
}

/// One stream: its filter chain (unescaped, no `/`) and bytes.
#[derive(Debug, Clone, Default)]
pub struct PdfStream {
    pub object: u32,
    pub filters: Vec<String>,
    pub raw: std::ops::Range<usize>,
    /// Bytes after the supported filters (raw when it has none).
    pub decoded: Vec<u8>,
}

/// The decoded streams of a scan (not part of the report).
#[derive(Debug, Clone, Default)]
pub struct PdfStreams {
    pub streams: Vec<PdfStream>,
}

/// `%PDF-` within the first [`HEADER_WINDOW`] bytes.
pub fn header_offset(bytes: &[u8]) -> Option<usize> {
    memchr::memmem::find(&bytes[..bytes.len().min(HEADER_WINDOW + 5)], b"%PDF-")
}

fn is_delim(b: u8) -> bool {
    b.is_ascii_whitespace() || b == 0 || b"()<>[]{}/%".contains(&b)
}

/// A name starting after its `/` at `at`: (unescaped text, end, had escapes).
fn read_name(b: &[u8], mut at: usize) -> (String, usize, bool) {
    let mut out = Vec::new();
    let mut escaped = false;
    while at < b.len() && !is_delim(b[at]) {
        if b[at] == b'#' {
            let hex = b.get(at + 1..at + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(v) = hex {
                out.push(v);
                escaped = true;
                at += 3;
                continue;
            }
        }
        out.push(b[at]);
        at += 1;
    }
    (String::from_utf8_lossy(&out).into_owned(), at, escaped)
}

/// Every name of `b`: (unescaped, end offset, had escapes).
fn names(b: &[u8]) -> Vec<(String, usize, bool)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(rel) = memchr::memchr(b'/', &b[at..]) {
        let (name, end, esc) = read_name(b, at + rel + 1);
        if !name.is_empty() {
            out.push((name, end, esc));
        }
        at = end.max(at + rel + 1);
    }
    out
}

fn skip_ws(b: &[u8], mut at: usize) -> usize {
    while at < b.len() && (b[at].is_ascii_whitespace() || b[at] == 0) {
        at += 1;
    }
    at
}

/// A literal `( ... )` string starting at `(`: (bytes, end).
fn literal_string(b: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut at = start;
    while at < b.len() {
        let c = b[at];
        match c {
            b'(' => {
                depth += 1;
                if depth > 1 {
                    out.push(c);
                }
            }
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some((out, at + 1));
                }
                out.push(c);
            }
            b'\\' => {
                at += 1;
                let e = *b.get(at)?;
                match e {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'0'..=b'7' => {
                        let mut v = u32::from(e - b'0');
                        for _ in 0..2 {
                            match b.get(at + 1) {
                                Some(d @ b'0'..=b'7') => {
                                    v = v * 8 + u32::from(d - b'0');
                                    at += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push(v as u8);
                    }
                    b'\r' | b'\n' => {}
                    other => out.push(other),
                }
            }
            _ => out.push(c),
        }
        if out.len() > MAX_STRING_LEN {
            return Some((out, at));
        }
        at += 1;
    }
    Some((out, b.len()))
}

/// A hex `< ... >` string starting at `<`.
fn hex_string(b: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let end = start + 1 + memchr::memchr(b'>', b.get(start + 1..)?)?;
    let digits: Vec<u8> = b[start + 1..end].iter().copied().filter(u8::is_ascii_hexdigit).collect();
    let mut out = Vec::with_capacity(digits.len() / 2 + 1);
    for pair in digits.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = pair.get(1).and_then(|c| (*c as char).to_digit(16)).unwrap_or(0);
        out.push((hi * 16 + lo) as u8);
    }
    Some((out, end + 1))
}

/// Text of a PDF string (UTF-16BE with BOM, else Latin-1).
fn pdf_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xfe, 0xff]) {
        let units: Vec<u16> = bytes[2..].as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&units);
    }
    bytes.iter().map(|&c| c as char).collect()
}

/// The value after a name: a string, or an indirect reference `N G R`.
enum Value {
    Text(Vec<u8>),
    Ref(u32),
    None,
}

fn value_at(b: &[u8], at: usize) -> Value {
    let at = skip_ws(b, at);
    match b.get(at) {
        Some(b'(') => literal_string(b, at).map_or(Value::None, |(s, _)| Value::Text(s)),
        Some(b'<') if b.get(at + 1) != Some(&b'<') => hex_string(b, at).map_or(Value::None, |(s, _)| Value::Text(s)),
        Some(c) if c.is_ascii_digit() => {
            let rest = &b[at..b.len().min(at + 32)];
            let text = String::from_utf8_lossy(rest);
            let mut parts = text.split_ascii_whitespace();
            match (parts.next().and_then(|n| n.parse().ok()), parts.next(), parts.next()) {
                (Some(n), Some(_), Some(r)) if r.starts_with('R') => Value::Ref(n),
                _ => Value::None,
            }
        }
        _ => Value::None,
    }
}

/// Normalized filter name (abbreviations expanded).
fn filter_name(n: &str) -> String {
    match n {
        "Fl" => "FlateDecode",
        "AHx" => "ASCIIHexDecode",
        "A85" => "ASCII85Decode",
        "RL" => "RunLengthDecode",
        "LZW" => "LZWDecode",
        "DCT" => "DCTDecode",
        "CCF" => "CCITTFaxDecode",
        other => other,
    }
    .to_string()
}

/// `/Filter /X` or `/Filter [/X /Y]` of a dictionary.
fn filters_of(dict: &[u8]) -> Vec<String> {
    let all = names(dict);
    let Some(pos) = all.iter().position(|(n, _, _)| n == "Filter") else { return Vec::new() };
    let after = skip_ws(dict, all[pos].1);
    if dict.get(after) == Some(&b'[') {
        let close = memchr::memchr(b']', &dict[after..]).map_or(dict.len(), |c| after + c);
        names(&dict[after..close]).into_iter().map(|(n, _, _)| filter_name(&n)).take(8).collect()
    } else {
        all.get(pos + 1).filter(|(_, end, _)| *end <= after + 64).map(|(n, _, _)| vec![filter_name(n)]).unwrap_or_default()
    }
}

/// Integer value of `/Key` in a dictionary.
fn int_of(dict: &[u8], key: &str) -> Option<usize> {
    let (_, end, _) = names(dict).into_iter().find(|(n, _, _)| n == key)?;
    let at = skip_ws(dict, end);
    let digits: String = dict[at..].iter().take_while(|c| c.is_ascii_digit()).map(|&c| c as char).take(12).collect();
    digits.parse().ok()
}

/// Inflate (zlib, else raw deflate) up to `limit` bytes: (output, hit the limit).
fn inflate(data: &[u8], limit: usize) -> (Vec<u8>, bool) {
    let run = |r: &mut dyn Read| {
        let mut out = Vec::new();
        let _ = r.take(limit as u64 + 1).read_to_end(&mut out);
        out
    };
    let mut out = run(&mut flate2::read::ZlibDecoder::new(data));
    if out.is_empty() {
        out = run(&mut flate2::read::DeflateDecoder::new(data));
    }
    let over = out.len() > limit;
    out.truncate(limit);
    (out, over)
}

fn ascii_hex(data: &[u8], limit: usize) -> Vec<u8> {
    let end = memchr::memchr(b'>', data).unwrap_or(data.len());
    let digits: Vec<u8> = data[..end].iter().copied().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .take(limit)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap_or(0);
            let lo = p.get(1).and_then(|c| (*c as char).to_digit(16)).unwrap_or(0);
            (hi * 16 + lo) as u8
        })
        .collect()
}

fn ascii85(data: &[u8], limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut group = [0u32; 5];
    let mut n = 0;
    let body = data.strip_prefix(b"<~").unwrap_or(data);
    for &c in body {
        if out.len() >= limit {
            break;
        }
        match c {
            b'~' => break,
            b'z' if n == 0 => out.extend([0u8; 4]),
            b'!'..=b'u' => {
                group[n] = u32::from(c - b'!');
                n += 1;
                if n == 5 {
                    let v = group.iter().fold(0u64, |a, d| a * 85 + u64::from(*d)) as u32;
                    out.extend(v.to_be_bytes());
                    n = 0;
                }
            }
            _ => {}
        }
    }
    if n > 1 {
        for d in group.iter_mut().skip(n) {
            *d = 84;
        }
        let v = group.iter().fold(0u64, |a, d| a * 85 + u64::from(*d)) as u32;
        out.extend(&v.to_be_bytes()[..n - 1]);
    }
    out.truncate(limit);
    out
}

fn run_length(data: &[u8], limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() && out.len() < limit {
        let len = data[at];
        at += 1;
        match len {
            128 => break,
            0..=127 => {
                let end = (at + len as usize + 1).min(data.len());
                out.extend_from_slice(&data[at..end]);
                at = end;
            }
            _ => {
                let Some(&b) = data.get(at) else { break };
                out.extend(std::iter::repeat_n(b, 257 - len as usize));
                at += 1;
            }
        }
    }
    out.truncate(limit);
    out
}

/// Apply the supported filters in order; stops at the first unsupported one.
/// Returns (bytes, hit a budget).
fn decode(raw: &[u8], filters: &[String], budget: &mut usize) -> (Vec<u8>, bool) {
    let mut data = raw.to_vec();
    let mut truncated = false;
    for f in filters.iter().take(MAX_FILTER_CHAIN) {
        let limit = MAX_STREAM_OUTPUT.min(*budget);
        if limit == 0 {
            return (Vec::new(), true);
        }
        data = match f.as_str() {
            "FlateDecode" => {
                let (out, over) = inflate(&data, limit);
                truncated |= over;
                out
            }
            "ASCIIHexDecode" => ascii_hex(&data, limit),
            "ASCII85Decode" => ascii85(&data, limit),
            "RunLengthDecode" => run_length(&data, limit),
            _ => break,
        };
        truncated |= data.len() >= limit;
    }
    if filters.len() > MAX_FILTER_CHAIN {
        truncated = true;
    }
    data.truncate(MAX_STREAM_OUTPUT.min(*budget));
    *budget = budget.saturating_sub(data.len());
    (data, truncated)
}

/// An indirect object: number, dictionary part, stream bytes.
struct Object {
    num: u32,
    body: std::ops::Range<usize>,
    stream: Option<std::ops::Range<usize>>,
}

/// `N G obj` headers at line / token starts.
fn find_objects(b: &[u8], from: usize) -> Vec<(u32, usize)> {
    let mut out = Vec::new();
    let mut at = from;
    while out.len() < MAX_OBJECTS {
        let Some(rel) = memchr::memmem::find(&b[at..], b"obj") else { break };
        let kw = at + rel;
        at = kw + 3;
        if b.get(kw + 3).is_some_and(|c| !is_delim(*c)) {
            continue;
        }
        // Walk back over `G`, whitespace, `N`.
        let mut p = kw;
        let back = |p: &mut usize, digits: bool| -> usize {
            let end = *p;
            while *p > 0 && (if digits { b[*p - 1].is_ascii_digit() } else { b[*p - 1].is_ascii_whitespace() }) {
                *p -= 1;
            }
            end - *p
        };
        if back(&mut p, false) == 0 || back(&mut p, true) == 0 || back(&mut p, false) == 0 {
            continue;
        }
        let num_end = p;
        if back(&mut p, true) == 0 || (p > 0 && !is_delim(b[p - 1])) {
            continue;
        }
        let Some(num) = std::str::from_utf8(&b[p..num_end]).ok().and_then(|n| n.parse().ok()) else { continue };
        out.push((num, kw + 3));
    }
    out
}

fn split_object(b: &[u8], num: u32, start: usize, end: usize) -> Object {
    let region = &b[start..end];
    let body_end = memchr::memmem::find(region, b"endobj").map_or(end, |e| start + e);
    let body = &b[start..body_end];
    let mut stream = None;
    if let Some(s) = memchr::memmem::find(body, b"stream").filter(|s| !body[..*s].ends_with(b"end")) {
        let mut data = start + s + 6;
        if b.get(data) == Some(&b'\r') {
            data += 1;
        }
        if b.get(data) == Some(&b'\n') {
            data += 1;
        }
        let data = data.min(body_end);
        let stop = memchr::memmem::find(&b[data..body_end], b"endstream").map_or(body_end, |e| data + e);
        let mut stop = stop;
        while stop > data && matches!(b[stop - 1], b'\r' | b'\n') {
            stop -= 1;
        }
        stream = Some(data..stop);
        return Object { num, body: start..start + s, stream };
    }
    Object { num, body: start..body_end, stream }
}

/// Parse a PDF. `None` when there is no `%PDF-` header in the first KiB.
pub fn parse_pdf(bytes: &[u8]) -> Option<(PdfInfo, PdfStreams)> {
    let header = header_offset(bytes)?;
    let mut info = PdfInfo { header_offset: header, ..Default::default() };
    let vline = &bytes[header + 5..bytes.len().min(header + 16)];
    let version: String = vline.iter().take_while(|c| c.is_ascii_digit() || **c == b'.').map(|&c| c as char).collect();
    info.version = (!version.is_empty()).then_some(version);

    let heads = find_objects(bytes, header);
    let objects: Vec<Object> = heads
        .iter()
        .enumerate()
        .map(|(i, &(num, start))| {
            let end = heads.get(i + 1).map_or(bytes.len(), |n| n.1.saturating_sub(3)).max(start);
            split_object(bytes, num, start, end)
        })
        .collect();
    info.obj_count = objects.len();

    let mut budget = MAX_TOTAL_OUTPUT;
    let mut streams = PdfStreams::default();
    // Dictionaries / object texts whose names are counted.
    let mut texts: Vec<Vec<u8>> = Vec::new();
    for obj in &objects {
        let dict = &bytes[obj.body.clone()];
        texts.push(dict.to_vec());
        let Some(range) = obj.stream.clone() else { continue };
        info.stream_count += 1;
        let filters = filters_of(dict);
        let (decoded, truncated) = decode(&bytes[range.clone()], &filters, &mut budget);
        info.truncated |= truncated;
        let dict_names = names(dict);
        if dict_names.iter().any(|(n, _, _)| n == "Type") && dict_names.iter().any(|(n, _, _)| n == "ObjStm") {
            info.objstm_count += 1;
            // Objects inside an object stream follow `/First`; their text is counted like any other.
            let first = int_of(dict, "First").unwrap_or(0).min(decoded.len());
            let n = int_of(dict, "N").unwrap_or(0).min(MAX_OBJECTS);
            info.obj_count = (info.obj_count + n).min(MAX_OBJECTS);
            texts.push(decoded[first..].to_vec());
        }
        streams.streams.push(PdfStream { object: obj.num, filters, raw: range, decoded });
    }

    let stream_of = |num: u32| streams.streams.iter().find(|s| s.object == num).map(|s| s.decoded.as_slice());
    for text in &texts {
        let all = names(text);
        for (name, end, escaped) in &all {
            *info.names.entry(name.clone()).or_insert(0) += 1;
            if *escaped {
                info.obfuscated_names += 1;
            }
            let target = match name.as_str() {
                "JS" => Some(&mut info.javascript),
                "URI" => Some(&mut info.uris),
                "F" | "P" if all.iter().any(|(n, _, _)| n == "Launch") => Some(&mut info.launches),
                _ => None,
            };
            let Some(list) = target else { continue };
            if list.len() >= MAX_STRINGS || list.iter().map(String::len).sum::<usize>() >= MAX_LIST_BYTES {
                continue;
            }
            let payload: Option<std::borrow::Cow<[u8]>> = match value_at(text, *end) {
                Value::Text(t) => Some(t.into()),
                Value::Ref(n) => stream_of(n).map(Into::into),
                Value::None => None,
            };
            if let Some(p) = payload.filter(|p| !p.is_empty()) {
                let s = pdf_text(&p[..p.len().min(MAX_STRING_LEN)]);
                if !list.contains(&s) {
                    list.push(s);
                }
            }
        }
    }
    Some((info, streams))
}

/// Decoded strings of a PDF: `pdf_js`, `pdf_uri`, `pdf_launch`, and the text
/// of mostly printable decoded streams (`pdf_stream`, 64 KiB each, 1 MiB total).
pub fn decoded_strings(info: &PdfInfo, streams: &PdfStreams) -> Vec<crate::models::DecodedString> {
    let mut out = Vec::new();
    for (method, list) in [("pdf_js", &info.javascript), ("pdf_uri", &info.uris), ("pdf_launch", &info.launches)] {
        for s in list {
            out.push(crate::models::DecodedString { method: method.into(), source: "pdf".into(), decoded: s.clone() });
        }
    }
    let mut total = 0usize;
    for s in &streams.streams {
        if s.filters.is_empty() || s.decoded.is_empty() || total >= 1024 * 1024 {
            continue;
        }
        let part = &s.decoded[..s.decoded.len().min(64 * 1024)];
        let printable = part.iter().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).count();
        if printable * 10 >= part.len() * 9 {
            total += part.len();
            out.push(crate::models::DecodedString {
                method: "pdf_stream".into(),
                source: format!("obj {}", s.object),
                decoded: String::from_utf8_lossy(part).into_owned(),
            });
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Junk before the header, an `/OpenAction` with a hex-escaped
    /// `/JavaScript` name whose `/JS` points at a FlateDecode stream, a `/URI`,
    /// and a zip-bomb stream inflating far past the per-stream cap.
    pub fn build_pdf(js: &str, bomb_bytes: usize) -> Vec<u8> {
        let mut out = b"JUNKJUNK\r\n%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        out.extend(b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Names << /#45mbeddedFiles 5 0 R >> >>\nendobj\n");
        out.extend(b"2 0 obj\n<< /S /#4A#61#76#61#53#63#72#69#70#74 /JS 3 0 R >>\nendobj\n");
        let js_z = zlib(js.as_bytes());
        out.extend(format!("3 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n", js_z.len()).as_bytes());
        out.extend(&js_z);
        out.extend(b"\nendstream\nendobj\n");
        out.extend(b"4 0 obj\n<< /S /URI /URI (http://evil.example/\\(x\\)) >>\nendobj\n");
        let bomb = zlib(&vec![b'A'; bomb_bytes]);
        out.extend(format!("5 0 obj\n<< /Length {} /Filter [/Fl] >>\nstream\r\n", bomb.len()).as_bytes());
        out.extend(&bomb);
        out.extend(b"\r\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
        out
    }

    #[test]
    fn parses_obfuscated_names_streams_and_actions() {
        let js = "app.alert('x'); var s = unescape('%u9090%u9090');";
        let pdf = build_pdf(js, 64 * 1024);
        let (info, streams) = parse_pdf(&pdf).unwrap();
        assert_eq!(info.header_offset, 10);
        assert_eq!(info.version.as_deref(), Some("1.7"));
        assert_eq!(info.obj_count, 5);
        assert_eq!(info.stream_count, 2);
        assert_eq!(info.name_count("JavaScript"), 1);
        assert_eq!(info.name_count("/OpenAction"), 1);
        assert_eq!(info.name_count("EmbeddedFiles"), 1);
        assert_eq!(info.obfuscated_names, 2);
        assert_eq!(info.javascript, vec![js]);
        assert_eq!(info.uris, vec!["http://evil.example/(x)"]);
        assert!(!info.truncated);
        assert_eq!(streams.streams[0].decoded, js.as_bytes());
        let dec = decoded_strings(&info, &streams);
        assert!(dec.iter().any(|d| d.method == "pdf_js" && d.decoded == js));
        assert!(dec.iter().any(|d| d.method == "pdf_uri"));
    }

    #[test]
    fn zip_bomb_is_truncated_at_the_cap() {
        let pdf = build_pdf("x", 40 * 1024 * 1024);
        assert!(pdf.len() < 200 * 1024, "the bomb is small on disk");
        let (info, streams) = parse_pdf(&pdf).unwrap();
        assert!(info.truncated);
        assert_eq!(streams.streams[1].decoded.len(), MAX_STREAM_OUTPUT);
        let total: usize = streams.streams.iter().map(|s| s.decoded.len()).sum();
        assert!(total <= MAX_TOTAL_OUTPUT);
    }

    #[test]
    fn object_streams_and_filters() {
        let inner = b"10 0 20 30 << /JS (app.launchURL\\(1\\)) /S /JavaScript >> << /AA << >> >>";
        let z = zlib(inner);
        let mut pdf = b"%PDF-1.5\n".to_vec();
        pdf.extend(format!("7 0 obj\n<< /Type /ObjStm /N 2 /First 11 /Filter /FlateDecode /Length {} >>\nstream\n", z.len()).as_bytes());
        pdf.extend(&z);
        pdf.extend(b"\nendstream\nendobj\n");
        let (info, _) = parse_pdf(&pdf).unwrap();
        assert_eq!(info.objstm_count, 1);
        assert_eq!(info.obj_count, 3);
        assert_eq!(info.javascript, vec!["app.launchURL(1)"]);
        assert_eq!(info.name_count("AA"), 1);

        assert_eq!(ascii_hex(b"48 65 6c6c 6f>", 99), b"Hello");
        assert_eq!(ascii85(b"<~87cURD]i,\"Ebo80~>", 99), b"Hello World!");
        assert_eq!(run_length(&[2, b'a', b'b', b'c', 254, b'x', 128], 99), b"abcxxx");
        let mut budget = 10;
        let (out, truncated) = decode(&zlib(&[7u8; 100]), &["FlateDecode".into()], &mut budget);
        assert_eq!((out.len(), truncated, budget), (10, true, 0));
    }

    #[test]
    fn hostile_input_does_not_panic() {
        assert!(parse_pdf(b"no header").is_none());
        let mut junk = vec![b' '; 2000];
        junk.extend(b"%PDF-1.4");
        assert!(parse_pdf(&junk).is_none(), "header past the first KiB");
        let pdf = build_pdf("abc", 1000);
        for cut in [9, 30, 100, pdf.len() / 2, pdf.len() - 1] {
            let _ = parse_pdf(&pdf[..cut]);
        }
        let _ = parse_pdf(b"%PDF-1.1\n1 0 obj (unterminated \\");
        let _ = parse_pdf(b"%PDF-1.1\n1 0 obj << /JS <4142 >> stream\n");
        let many: Vec<u8> = (0..10_000).flat_map(|i| format!("{i} 0 obj\n").into_bytes()).collect();
        let (info, _) = parse_pdf(&[b"%PDF-1.0\n".as_slice(), &many].concat()).unwrap();
        assert_eq!(info.obj_count, MAX_OBJECTS);
    }
}
