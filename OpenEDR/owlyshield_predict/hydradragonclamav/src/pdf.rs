//! PDF layer, after libclamav `pdf.c` / `pdfdecode.c`.
//!
//! A PDF keeps its active content - JavaScript, embedded files, page text - in
//! filtered (usually Flate-compressed) streams, so a scan of the raw file bytes
//! never sees it. Like ClamAV's `cli_pdf`, this finds every `N G obj`, reads
//! its dictionary names (with `#xx` escapes), decodes its stream through the
//! filter chain (Flate, LZW, ASCIIHex, ASCII85, RunLength, PNG predictors),
//! expands object streams (`/ObjStm`), pulls `/JS` code out of literal and hex
//! strings and indirect references, and hands the decoded pieces back to the
//! scanner as child objects.
//!
//! Heuristics are ClamAV's own and nothing more:
//! * `Heuristics.PDF.ObfuscatedNameObject` - a common PDF name written with
//!   `#xx` escapes (`/Fl#61teDecode`, `/Java#53cript`): no producer does that,
//!   only obfuscation does.
//! * `Heuristics.Encrypted.PDF` - an encrypted document that cannot be opened
//!   without a password; off by default, as in ClamAV
//!   (`ScanOptions::heuristic_encrypted_pdf`).
//!
//! Encrypted PDFs: like ClamAV (`check_user_password` / `check_owner_password`,
//! `decrypt_any`) only the EMPTY password is tried - no guessing, no emulation.
//! That opens the common "permissions only" documents (Standard handler R2-R6:
//! RC4 40-128, AES-128, AES-256); the key is derived once per file and each
//! stream / string is decrypted with its object key before the filters.

use std::collections::HashMap;
use std::io::Read;

/// Most objects read from one PDF (ClamAV stops at the same order of magnitude).
const MAX_OBJECTS: usize = 200_000;
/// Most bytes one stream may decode to.
const MAX_STREAM_OUT: usize = 64 * 1024 * 1024;
/// Most filters applied to one stream (ClamAV `PDF_FILTERLIST_MAX`).
const MAX_FILTERS: usize = 64;
/// How deep object streams may nest (ClamAV `PDF_OBJECT_RECURSION_LIMIT`).
const MAX_DEPTH: usize = 25;

/// Names whose escaped spelling is flagged (ClamAV `pdfname_actions` with
/// `NAMEFLAG_HEURISTIC`).
const COMMON_NAMES: &[&str] = &[
    "ASCIIHexDecode", "ASCII85Decode", "A85", "AHx", "EmbeddedFile", "FlateDecode", "Fl", "LZWDecode", "LZW",
    "RunLengthDecode", "RL", "CCITTFaxDecode", "CCF", "JBIG2Decode", "DCTDecode", "DCT", "JPXDecode", "Crypt",
    "Standard", "Sig", "V", "R", "Linearized", "Filter", "JavaScript", "Length", "S", "Type", "OpenAction",
    "Launch", "Page", "Contents",
];

/// A decoded piece of the PDF for the signature scan.
#[derive(Debug, Clone)]
pub struct PdfChild {
    /// `obj 12 0`, `obj 12 0 js`, ...
    pub name: String,
    pub data: Vec<u8>,
}

/// What the PDF layer found (ClamAV `pdf_struct` flags and stats, the ones
/// used here).
#[derive(Debug, Clone, Default)]
pub struct PdfAnalysis {
    pub children: Vec<PdfChild>,
    pub objects: usize,
    /// A heuristic-flagged name written with `#xx` escapes (ESCAPED_COMMON_PDFNAME).
    pub escaped_common_name: bool,
    /// `/Encrypt` in the trailer (ENCRYPTED_PDF).
    pub encrypted: bool,
    /// Encrypted, and the empty password opens it (DECRYPTABLE_PDF).
    pub decryptable: bool,
    /// JavaScript stored as a hex string (HEX_JAVASCRIPT).
    pub hex_javascript: bool,
    pub javascript: usize,
    pub open_action: usize,
    pub launch: usize,
    pub embedded_files: usize,
    /// A filter this layer cannot decode (UNKNOWN_FILTER).
    pub unknown_filter: bool,
    /// The same filter twice on one stream (BAD_STREAM_FILTERS).
    pub bad_stream_filters: bool,
    /// Header not at offset 0 (BAD_PDF_HEADERPOS).
    pub bad_header_pos: bool,
    /// No `%%EOF` / `startxref` near the end (BAD_PDF_TRAILER).
    pub bad_trailer: bool,
}

/// Offset of the `%PDF-` header when `data` is a PDF (ClamAV looks within the
/// first 1032 bytes).
pub fn header_offset(data: &[u8]) -> Option<usize> {
    memchr::memmem::find(&data[..data.len().min(1032)], b"%PDF-")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    Flate,
    Lzw,
    AsciiHex,
    Ascii85,
    RunLength,
    /// Image codecs and crypt: the data is passed on as it is.
    Passthrough,
    Unknown,
}

fn filter_of(name: &str) -> Filter {
    match name {
        "FlateDecode" | "Fl" => Filter::Flate,
        "LZWDecode" | "LZW" => Filter::Lzw,
        "ASCIIHexDecode" | "AHx" => Filter::AsciiHex,
        "ASCII85Decode" | "A85" => Filter::Ascii85,
        "RunLengthDecode" | "RL" => Filter::RunLength,
        "DCTDecode" | "DCT" | "JPXDecode" | "JBIG2Decode" | "CCITTFaxDecode" | "CCF" | "Crypt" => Filter::Passthrough,
        _ => Filter::Unknown,
    }
}

/// One `N G obj ... endobj`.
#[derive(Debug, Clone)]
struct RawObj<'a> {
    id: u32,
    generation: u32,
    /// Dictionary part (up to `stream`, or the whole body).
    dict: &'a [u8],
    /// Stream payload, when the object has one.
    stream: Option<&'a [u8]>,
}

/// Names of a dictionary in order, `#xx` decoded, with whether any was escaped.
/// Literal `( )` and hex `< >` strings are skipped, so a `/Name` inside text is
/// not a name.
fn names(dict: &[u8]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < dict.len() {
        match dict[i] {
            b'(' => i = skip_literal(dict, i),
            b'<' if dict.get(i + 1) != Some(&b'<') => {
                i = memchr::memchr(b'>', &dict[i..]).map_or(dict.len(), |p| i + p + 1);
            }
            b'<' => i += 2,
            b'/' => {
                let start = i + 1;
                let mut j = start;
                while j < dict.len() && !is_delim(dict[j]) && !dict[j].is_ascii_whitespace() {
                    j += 1;
                }
                let raw = &dict[start..j];
                let escaped = raw.contains(&b'#');
                out.push((unescape_name(raw), escaped));
                i = j.max(i + 1);
            }
            _ => i += 1,
        }
    }
    out
}

fn is_delim(b: u8) -> bool {
    matches!(b, b'/' | b'[' | b']' | b'<' | b'>' | b'(' | b')' | b'{' | b'}' | b'%')
}

fn unescape_name(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (raw.get(i + 1).and_then(|c| hex_val(*c)), raw.get(i + 2).and_then(|c| hex_val(*c))) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Index just past the literal string starting at `data[start] == '('`
/// (balanced parentheses, backslash escapes).
fn skip_literal(data: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < data.len() {
        match data[i] {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    data.len()
}

/// Bytes of the literal string at `data[start] == '('` (escapes resolved).
fn read_literal(data: &[u8], start: usize) -> Vec<u8> {
    let end = skip_literal(data, start);
    let body = &data[start + 1..end.saturating_sub(1).max(start + 1)];
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&e) = body.get(i) else { break };
        match e {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'\r' => {
                // Line continuation.
                if body.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => {}
            b'0'..=b'7' => {
                let mut v = 0u32;
                let mut k = 0;
                while k < 3 && i < body.len() && (b'0'..=b'7').contains(&body[i]) {
                    v = v * 8 + (body[i] - b'0') as u32;
                    i += 1;
                    k += 1;
                }
                out.push(v as u8);
                continue;
            }
            other => out.push(other),
        }
        i += 1;
    }
    out
}

/// Bytes of the hex string at `data[start] == '<'`.
fn read_hex_string(data: &[u8], start: usize) -> Vec<u8> {
    let end = memchr::memchr(b'>', &data[start..]).map_or(data.len(), |p| start + p);
    decode_ascii_hex(&data[start + 1..end])
}

/// Every object of `data` (ClamAV `pdf_findobj`): `<id> <generation> obj` up to
/// `endobj` or the next object.
fn find_objects(data: &[u8]) -> Vec<RawObj<'_>> {
    let mut starts: Vec<(u32, u32, usize, usize)> = Vec::new(); // id, generation, header start, body start
    for pos in memchr::memmem::find_iter(data, b"obj") {
        if starts.len() >= MAX_OBJECTS {
            break;
        }
        // Not `endobj`, not a longer word.
        if data.get(pos + 3).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let Some((id, generation, hstart)) = parse_obj_header(data, pos) else { continue };
        starts.push((id, generation, hstart, pos + 3));
    }
    let mut out = Vec::with_capacity(starts.len());
    for (k, &(id, generation, _, body)) in starts.iter().enumerate() {
        let limit = starts.get(k + 1).map_or(data.len(), |n| n.2);
        let region = &data[body..limit.max(body)];
        let end = memchr::memmem::find(region, b"endobj").unwrap_or(region.len());
        out.push(split_object(id, generation, &region[..end]));
    }
    out
}

/// `<digits> <ws> <digits> <ws> obj` ending at `obj_pos`.
fn parse_obj_header(data: &[u8], obj_pos: usize) -> Option<(u32, u32, usize)> {
    let mut i = obj_pos;
    let ws = |c: u8| c.is_ascii_whitespace() || c == 0;
    let skip_ws = |i: &mut usize| -> bool {
        let s = *i;
        while *i > 0 && ws(data[*i - 1]) {
            *i -= 1;
        }
        *i < s
    };
    let read_num = |i: &mut usize| -> Option<u32> {
        let e = *i;
        while *i > 0 && data[*i - 1].is_ascii_digit() && e - *i < 10 {
            *i -= 1;
        }
        if *i == e {
            return None;
        }
        std::str::from_utf8(&data[*i..e]).ok()?.parse().ok()
    };
    if !skip_ws(&mut i) {
        return None;
    }
    let generation = read_num(&mut i)?;
    if !skip_ws(&mut i) {
        return None;
    }
    let id = read_num(&mut i)?;
    if i > 0 && data[i - 1].is_ascii_alphanumeric() {
        return None;
    }
    Some((id, generation, i))
}

/// Splits an object body into its dictionary and stream payload.
fn split_object(id: u32, generation: u32, body: &[u8]) -> RawObj<'_> {
    // `stream` keyword after the dictionary (`>>` then optional whitespace), not
    // the word inside `endstream` or document text.
    let mut search = 0;
    while let Some(p) = memchr::memmem::find(&body[search..], b"stream").map(|p| p + search) {
        search = p + 6;
        if p >= 3 && &body[p - 3..p] == b"end" {
            continue;
        }
        let mut k = p;
        while k > 0 && body[k - 1].is_ascii_whitespace() {
            k -= 1;
        }
        if k < 2 || &body[k - 2..k] != b">>" {
            continue;
        }
        let mut s = p + 6;
        if body.get(s) == Some(&b'\r') {
            s += 1;
        }
        if body.get(s) == Some(&b'\n') {
            s += 1;
        }
        let rest = &body[s.min(body.len())..];
        let mut e = memchr::memmem::rfind(rest, b"endstream").unwrap_or(rest.len());
        // Trim the EOL before `endstream`.
        if e > 0 && rest[e - 1] == b'\n' {
            e -= 1;
        }
        if e > 0 && rest[e - 1] == b'\r' {
            e -= 1;
        }
        return RawObj { id, generation, dict: &body[..p], stream: Some(&rest[..e]) };
    }
    RawObj { id, generation, dict: body, stream: None }
}

/// Integer after `/key` in a dictionary, if it is a direct number.
fn dict_int(dict: &[u8], key: &[u8]) -> Option<i64> {
    let mut from = 0;
    while let Some(p) = memchr::memmem::find(&dict[from..], key).map(|p| p + from) {
        from = p + key.len();
        // Whole name only (`/Length` is not `/Length1`).
        if dict.get(from).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let mut i = from;
        while i < dict.len() && dict[i].is_ascii_whitespace() {
            i += 1;
        }
        let s = i;
        if i < dict.len() && dict[i] == b'-' {
            i += 1;
        }
        while i < dict.len() && dict[i].is_ascii_digit() {
            i += 1;
        }
        // An indirect reference (`12 0 R`) is not a direct number.
        let mut j = i;
        while j < dict.len() && dict[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < dict.len() && dict[j].is_ascii_digit() {
            return None;
        }
        return std::str::from_utf8(&dict[s..i]).ok()?.parse().ok();
    }
    None
}

/// Filters of a stream dictionary, in order: `/Filter /X` or `/Filter [/X /Y]`
/// (names `#xx` decoded, so an escaped filter still decodes).
fn filters(dict: &[u8]) -> Vec<String> {
    let mut i = 0;
    while i < dict.len() {
        match dict[i] {
            b'(' => i = skip_literal(dict, i),
            b'<' if dict.get(i + 1) != Some(&b'<') => {
                i = memchr::memchr(b'>', &dict[i..]).map_or(dict.len(), |p| i + p + 1);
            }
            b'<' => i += 2,
            b'/' => {
                let (name, end) = read_name(dict, i);
                i = end;
                if name != "Filter" {
                    continue;
                }
                while i < dict.len() && dict[i].is_ascii_whitespace() {
                    i += 1;
                }
                let mut out = Vec::new();
                match dict.get(i) {
                    Some(b'/') => out.push(read_name(dict, i).0),
                    Some(b'[') => {
                        i += 1;
                        while i < dict.len() && dict[i] != b']' && out.len() < MAX_FILTERS {
                            if dict[i] == b'/' {
                                let (n, e) = read_name(dict, i);
                                out.push(n);
                                i = e;
                            } else {
                                i += 1;
                            }
                        }
                    }
                    _ => {}
                }
                return out;
            }
            _ => i += 1,
        }
    }
    Vec::new()
}

/// The name starting at `dict[start] == '/'` (decoded) and the index after it.
fn read_name(dict: &[u8], start: usize) -> (String, usize) {
    let mut j = start + 1;
    while j < dict.len() && !is_delim(dict[j]) && !dict[j].is_ascii_whitespace() {
        j += 1;
    }
    (unescape_name(&dict[start + 1..j]), j.max(start + 1))
}

/// Decodes a stream through `filters` (ClamAV `pdf_decodestream`). Returns the
/// bytes and whether every filter was understood.
fn decode(raw: &[u8], filters: &[String], dict: &[u8]) -> (Vec<u8>, bool) {
    let mut cur: Vec<u8> = raw.to_vec();
    let mut all_known = true;
    for f in filters {
        let next = match filter_of(f) {
            Filter::Flate => {
                let out = inflate(&cur);
                apply_predictor(out, dict)
            }
            Filter::Lzw => {
                let early = dict_int(dict, b"/EarlyChange").unwrap_or(1) != 0;
                apply_predictor(decode_lzw(&cur, early), dict)
            }
            Filter::AsciiHex => decode_ascii_hex(&cur),
            Filter::Ascii85 => decode_ascii85(&cur),
            Filter::RunLength => decode_run_length(&cur),
            Filter::Passthrough => break,
            Filter::Unknown => {
                all_known = false;
                break;
            }
        };
        cur = next;
        if cur.is_empty() {
            break;
        }
    }
    (cur, all_known)
}

/// zlib, else raw deflate; keeps what decoded before an error (truncated or
/// damaged streams are common in malicious PDFs).
fn inflate(data: &[u8]) -> Vec<u8> {
    let read_all = |r: &mut dyn Read| {
        let mut out = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.len() >= MAX_STREAM_OUT {
                        out.truncate(MAX_STREAM_OUT);
                        break;
                    }
                }
            }
        }
        out
    };
    let out = read_all(&mut flate2::read::ZlibDecoder::new(data));
    if !out.is_empty() {
        return out;
    }
    // Leading garbage before the zlib header (BAD_FLATESTART): ClamAV skips
    // whitespace; also try raw deflate.
    let trimmed = &data[data.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(data.len())..];
    let out = read_all(&mut flate2::read::ZlibDecoder::new(trimmed));
    if !out.is_empty() {
        return out;
    }
    read_all(&mut flate2::read::DeflateDecoder::new(trimmed))
}

/// PNG / TIFF predictors from `/DecodeParms` (`/Predictor`, `/Columns`, ...).
fn apply_predictor(data: Vec<u8>, dict: &[u8]) -> Vec<u8> {
    let predictor = dict_int(dict, b"/Predictor").unwrap_or(1);
    if predictor < 10 {
        // 1 = none; TIFF predictor 2 is rare and harmless to leave undecoded.
        return data;
    }
    let colors = dict_int(dict, b"/Colors").unwrap_or(1).clamp(1, 32) as usize;
    let bpc = dict_int(dict, b"/BitsPerComponent").unwrap_or(8).clamp(1, 16) as usize;
    let columns = dict_int(dict, b"/Columns").unwrap_or(1).clamp(1, 1 << 20) as usize;
    let bpp = (colors * bpc).div_ceil(8).max(1);
    let row = (colors * bpc * columns).div_ceil(8);
    if row == 0 {
        return data;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = vec![0u8; row];
    let mut i = 0;
    while i < data.len() {
        let kind = data[i];
        i += 1;
        let end = (i + row).min(data.len());
        let mut line = data[i..end].to_vec();
        line.resize(row, 0);
        i = end;
        for x in 0..row {
            let a = if x >= bpp { line[x - bpp] } else { 0 };
            let b = prev[x];
            let c = if x >= bpp { prev[x - bpp] } else { 0 };
            line[x] = match kind {
                1 => line[x].wrapping_add(a),
                2 => line[x].wrapping_add(b),
                3 => line[x].wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => {
                    let p = a as i16 + b as i16 - c as i16;
                    let (pa, pb, pc) = ((p - a as i16).abs(), (p - b as i16).abs(), (p - c as i16).abs());
                    let pred = if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c };
                    line[x].wrapping_add(pred)
                }
                _ => line[x],
            };
        }
        out.extend_from_slice(&line);
        prev = line;
    }
    out
}

fn decode_ascii_hex(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2);
    let mut hi: Option<u8> = None;
    for &c in data {
        if c == b'>' {
            break;
        }
        let Some(v) = hex_val(c) else { continue };
        match hi.take() {
            None => hi = Some(v),
            Some(h) => out.push(h << 4 | v),
        }
    }
    if let Some(h) = hi {
        out.push(h << 4);
    }
    out
}

fn decode_ascii85(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 4 / 5);
    let mut group = [0u8; 5];
    let mut n = 0;
    let body = data.strip_prefix(b"<~").unwrap_or(data);
    for &c in body {
        match c {
            b'~' => break,
            b'z' if n == 0 => out.extend_from_slice(&[0, 0, 0, 0]),
            b'!'..=b'u' => {
                group[n] = c - b'!';
                n += 1;
                if n == 5 {
                    let v = group.iter().fold(0u64, |acc, &d| acc * 85 + d as u64);
                    out.extend_from_slice(&(v as u32).to_be_bytes());
                    n = 0;
                }
            }
            _ => {}
        }
    }
    if n > 1 {
        for g in group.iter_mut().skip(n) {
            *g = 84;
        }
        let v = group.iter().fold(0u64, |acc, &d| acc * 85 + d as u64);
        out.extend_from_slice(&(v as u32).to_be_bytes()[..n - 1]);
    }
    out
}

fn decode_run_length(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let len = data[i];
        i += 1;
        match len {
            128 => break,
            0..=127 => {
                let n = len as usize + 1;
                out.extend_from_slice(&data[i..(i + n).min(data.len())]);
                i += n;
            }
            _ => {
                if let Some(&b) = data.get(i) {
                    out.extend(std::iter::repeat_n(b, 257 - len as usize));
                }
                i += 1;
            }
        }
        if out.len() >= MAX_STREAM_OUT {
            break;
        }
    }
    out
}

/// PDF LZW: 9-12 bit codes, 256 = clear, 257 = end; `early` = EarlyChange 1.
fn decode_lzw(data: &[u8], early: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut table: Vec<Vec<u8>> = (0..=255u16).map(|b| vec![b as u8]).collect();
    table.push(Vec::new());
    table.push(Vec::new());
    let mut width = 9u32;
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut prev: Option<Vec<u8>> = None;
    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= width {
            let code = ((acc >> (bits - width)) & ((1 << width) - 1)) as usize;
            bits -= width;
            match code {
                256 => {
                    table.truncate(258);
                    width = 9;
                    prev = None;
                    continue;
                }
                257 => return out,
                _ => {}
            }
            let entry = if code < table.len() {
                table[code].clone()
            } else if let Some(p) = &prev {
                let mut e = p.clone();
                e.push(p[0]);
                e
            } else {
                return out;
            };
            out.extend_from_slice(&entry);
            if out.len() >= MAX_STREAM_OUT {
                return out;
            }
            if let Some(p) = prev.take() {
                if table.len() < 4096 {
                    let mut e = p;
                    e.push(entry[0]);
                    table.push(e);
                }
            }
            prev = Some(entry);
            let next = table.len() + usize::from(early);
            width = if next >= 2048 { 12 } else if next >= 1024 { 11 } else if next >= 512 { 10 } else { 9 };
        }
    }
    out
}

/// What one object (top-level or from an object stream) contributes.
struct ObjInfo {
    names: Vec<(String, bool)>,
}

impl ObjInfo {
    fn has(&self, n: &str) -> bool {
        self.names.iter().any(|(x, _)| x == n)
    }
}

/// `/JS` value of a dictionary: (code, was hex, referenced object).
fn javascript_of(dict: &[u8]) -> Option<(Vec<u8>, bool, Option<u32>)> {
    let mut from = 0;
    while let Some(p) = memchr::memmem::find(&dict[from..], b"/JS").map(|p| p + from) {
        from = p + 3;
        if dict.get(from).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let mut i = from;
        while i < dict.len() && dict[i].is_ascii_whitespace() {
            i += 1;
        }
        match dict.get(i) {
            Some(b'(') => return Some((read_literal(dict, i), false, None)),
            Some(b'<') if dict.get(i + 1) != Some(&b'<') => return Some((read_hex_string(dict, i), true, None)),
            Some(c) if c.is_ascii_digit() => {
                // `12 0 R`
                let s = i;
                while i < dict.len() && dict[i].is_ascii_digit() {
                    i += 1;
                }
                let id: u32 = std::str::from_utf8(&dict[s..i]).ok()?.parse().ok()?;
                return Some((Vec::new(), false, Some(id)));
            }
            _ => {}
        }
    }
    None
}

/// Runs the PDF layer over `data` (which starts with or contains `%PDF-` in its
/// first 1032 bytes). `budget` caps the total decoded bytes handed back.
pub fn analyze(data: &[u8], budget: usize) -> PdfAnalysis {
    let mut a = PdfAnalysis::default();
    let Some(hdr) = header_offset(data) else { return a };
    a.bad_header_pos = hdr != 0;
    let tail = &data[data.len().saturating_sub(2048)..];
    a.bad_trailer = memchr::memmem::rfind(tail, b"%%EOF").is_none() || memchr::memmem::rfind(tail, b"startxref").is_none();
    a.encrypted = memchr::memmem::find(data, b"/Encrypt").is_some_and(|p| {
        // The trailer key, not a word in text (`/EncryptMetadata` is a different key).
        !data.get(p + 8).is_some_and(|c| c.is_ascii_alphanumeric())
    });

    let objs = find_objects(&data[hdr..]);
    a.objects = objs.len();
    let mut used = 0usize;
    // Decoded streams by object id, for `/JS 12 0 R`.
    let mut streams: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut js_refs: Vec<(u32, u32, u32)> = Vec::new(); // (referenced id, from id, from generation)
    let mut pending: Vec<(Vec<u8>, usize)> = Vec::new(); // object-stream bodies to expand, depth

    let crypt = if a.encrypted { crypt::empty_password(&data[hdr..], &objs) } else { None };
    a.decryptable = crypt.is_some();

    for o in &objs {
        let info = ObjInfo { names: names(o.dict) };
        note_names(&mut a, &info);
        if let Some((code, hex, r)) = javascript_of(o.dict) {
            // Strings of an encrypted file are encrypted with the object key.
            let code = match &crypt {
                Some(c) if !code.is_empty() => c.decrypt(c.string, o.id, o.generation, &code).unwrap_or(code),
                // Encrypted and no key: the string is ciphertext.
                None if a.encrypted => Vec::new(),
                _ => code,
            };
            a.javascript += 1;
            a.hex_javascript |= hex;
            match r {
                Some(id) => js_refs.push((id, o.id, o.generation)),
                None if !code.is_empty() => push_child(&mut a, &mut used, budget, format!("obj {} {} js", o.id, o.generation), code),
                None => {}
            }
        }
        let Some(raw) = o.stream else { continue };
        if raw.is_empty() {
            continue;
        }
        let fl = filters(o.dict);
        for (k, f) in fl.iter().enumerate() {
            if fl[..k].contains(f) {
                a.bad_stream_filters = true;
            }
        }
        // Encrypted streams cannot be decoded without the key.
        // Encrypted streams: decrypted with the empty-password key; without it
        // they cannot be decoded. XRef streams are never encrypted, and Metadata
        // only when /EncryptMetadata is true.
        let plain: std::borrow::Cow<[u8]> = match &crypt {
            Some(c) if Some(o.id) != c.encrypt_obj
                && !info.has("XRef")
                && !(info.has("Metadata") && !c.encrypt_metadata) =>
            {
                let method = if info.has("EmbeddedFile") { c.embedded } else { c.stream };
                match c.decrypt(method, o.id, o.generation, raw) {
                    Some(d) => std::borrow::Cow::Owned(d),
                    None => continue,
                }
            }
            None if a.encrypted && !info.has("XRef") && !info.has("Metadata") => continue,
            _ => std::borrow::Cow::Borrowed(raw),
        };
        let raw: &[u8] = &plain;
        let (decoded, known) = decode(raw, &fl, o.dict);
        a.unknown_filter |= !known;
        if info.has("XRef") {
            continue; // binary offset table
        }
        let is_objstm = info.has("ObjStm");
        if is_objstm {
            pending.push((decoded.clone(), 1));
        }
        // Raw streams were already scanned with the file; non-JPEG images carry
        // no code (ClamAV dumps the same set).
        let filtered = !fl.is_empty() && decoded.as_slice() != raw;
        let flagged = info.has("JavaScript") || info.has("JS") || info.has("EmbeddedFile") || info.has("OpenAction") || info.has("Launch");
        let image = info.has("Image") && !fl.iter().any(|f| matches!(f.as_str(), "DCTDecode" | "DCT"));
        if (filtered || flagged || is_objstm) && !image && !decoded.is_empty() {
            streams.insert(o.id, decoded.clone());
            push_child(&mut a, &mut used, budget, format!("obj {} {}", o.id, o.generation), decoded);
        } else if !decoded.is_empty() {
            streams.insert(o.id, decoded);
        }
    }

    // Object streams: `N` pairs of `<id> <offset>`, then the objects from `/First`.
    let mut objstm_objs: HashMap<u32, Vec<u8>> = HashMap::new();
    while let Some((body, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        for (id, text) in objstm_members(&body) {
            let info = ObjInfo { names: names(&text) };
            note_names(&mut a, &info);
            if let Some((code, hex, r)) = javascript_of(&text) {
                a.javascript += 1;
                a.hex_javascript |= hex;
                match r {
                    Some(rid) => js_refs.push((rid, id, 0)),
                    None if !code.is_empty() => push_child(&mut a, &mut used, budget, format!("objstm {id} js"), code),
                    None => {}
                }
            }
            objstm_objs.insert(id, text);
        }
    }

    // `/JS 12 0 R`: the referenced stream is JavaScript (already scanned as a
    // child when filtered); a referenced string object is read here.
    for (rid, from, generation) in js_refs {
        if streams.contains_key(&rid) {
            continue;
        }
        // Top-level objects carry their own encryption; object-stream members are
        // already plain (the object stream was decrypted).
        let top = objs.iter().find(|o| o.id == rid);
        let text = top.map(|o| o.dict.to_vec()).or_else(|| objstm_objs.get(&rid).cloned());
        let Some(text) = text else { continue };
        let i = text.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(text.len());
        let code = match text.get(i) {
            Some(b'(') => read_literal(&text, i),
            Some(b'<') if text.get(i + 1) != Some(&b'<') => {
                a.hex_javascript = true;
                read_hex_string(&text, i)
            }
            _ => continue,
        };
        let code = match (&crypt, top) {
            (Some(c), Some(o)) if !code.is_empty() => c.decrypt(c.string, o.id, o.generation, &code).unwrap_or(code),
            _ => code,
        };
        if !code.is_empty() {
            push_child(&mut a, &mut used, budget, format!("obj {from} {generation} js -> {rid}"), code);
        }
    }
    a
}

fn note_names(a: &mut PdfAnalysis, info: &ObjInfo) {
    for (n, escaped) in &info.names {
        if *escaped && COMMON_NAMES.contains(&n.as_str()) {
            a.escaped_common_name = true;
        }
        match n.as_str() {
            "OpenAction" => a.open_action += 1,
            "Launch" => a.launch += 1,
            "EmbeddedFile" => a.embedded_files += 1,
            _ => {}
        }
    }
}

fn push_child(a: &mut PdfAnalysis, used: &mut usize, budget: usize, name: String, data: Vec<u8>) {
    if *used >= budget {
        return;
    }
    let take = data.len().min(budget - *used);
    *used += take;
    let mut data = data;
    data.truncate(take);
    a.children.push(PdfChild { name, data });
}

/// Members of a decoded object stream: (object id, object text).
fn objstm_members(body: &[u8]) -> Vec<(u32, Vec<u8>)> {
    // The header is `id off id off ...` up to the first object; its end is
    // the first non-number token.
    let mut nums: Vec<usize> = Vec::new();
    let mut i = 0;
    let mut header_end = 0;
    while i < body.len() {
        while i < body.len() && body[i].is_ascii_whitespace() {
            i += 1;
        }
        let s = i;
        while i < body.len() && body[i].is_ascii_digit() {
            i += 1;
        }
        if s == i {
            header_end = s;
            break;
        }
        let Some(v) = std::str::from_utf8(&body[s..i]).ok().and_then(|t| t.parse().ok()) else { break };
        nums.push(v);
        if nums.len() > 2 * MAX_OBJECTS {
            break;
        }
    }
    if header_end == 0 || nums.len() < 2 {
        return Vec::new();
    }
    let pairs: Vec<(u32, usize)> = nums.chunks_exact(2).map(|p| (p[0] as u32, p[1])).collect();
    let mut out = Vec::with_capacity(pairs.len());
    for (k, &(id, off)) in pairs.iter().enumerate() {
        let start = header_end + off;
        let end = pairs.get(k + 1).map_or(body.len(), |n| header_end + n.1);
        if start < end && end <= body.len() {
            out.push((id, body[start..end].to_vec()));
        }
    }
    out
}

/// Standard security handler with the empty password (libclamav
/// `pdf_handle_enc`, `check_user_password`, `check_owner_password`,
/// `compute_hash_r6`, `decrypt_any`).
mod crypt {
    use super::{dict_int, read_hex_string, read_literal, RawObj};
    use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
    use md5::{Digest as _, Md5};
    use sha2::{Sha256, Sha384, Sha512};

    /// PDF password padding (7.6.3.3, Algorithm 2).
    const PAD: [u8; 32] = [
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00,
        0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
    ];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Method {
        /// `/Identity` or `/None`: stored in the clear.
        Identity,
        Rc4,
        AesV2,
        AesV3,
        Unknown,
    }

    #[derive(Debug)]
    pub struct Crypt {
        key: Vec<u8>,
        pub stream: Method,
        pub string: Method,
        pub embedded: Method,
        pub encrypt_metadata: bool,
        /// The encryption dictionary's own object (never encrypted).
        pub encrypt_obj: Option<u32>,
    }

    impl Crypt {
        /// `decrypt_any`: the object key is MD5(file key, object number (3 bytes
        /// LE), generation (2 bytes LE)[, "sAlT"]) for RC4 / AES-128; AES-256
        /// uses the file key itself. None for an unknown method.
        pub fn decrypt(&self, method: Method, id: u32, generation: u32, data: &[u8]) -> Option<Vec<u8>> {
            match method {
                Method::Identity => Some(data.to_vec()),
                Method::Unknown => None,
                Method::AesV3 => aes_cbc_decrypt(&self.key, data),
                Method::Rc4 | Method::AesV2 => {
                    let mut k = self.key.clone();
                    k.extend_from_slice(&id.to_le_bytes()[..3]);
                    k.extend_from_slice(&generation.to_le_bytes()[..2]);
                    if method == Method::AesV2 {
                        k.extend_from_slice(b"sAlT");
                    }
                    let h = Md5::digest(&k);
                    let n = (self.key.len() + 5).min(16);
                    if method == Method::Rc4 {
                        let mut out = data.to_vec();
                        rc4(&h[..n], &mut out);
                        Some(out)
                    } else {
                        aes_cbc_decrypt(&h[..16], data)
                    }
                }
            }
        }
    }

    fn rc4(key: &[u8], data: &mut [u8]) {
        let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        let (mut i, mut j) = (0u8, 0u8);
        for b in data.iter_mut() {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            *b ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        }
    }

    /// AES-CBC with the IV in the first 16 bytes and PKCS#7 padding (kept when
    /// the padding is invalid: damaged data is still worth scanning).
    fn aes_cbc_decrypt(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 32 {
            return if data.len() == 16 { Some(Vec::new()) } else { None };
        }
        let (iv, body) = data.split_at(16);
        let mut buf = body[..body.len() / 16 * 16].to_vec();
        let n = buf.len();
        let res = match key.len() {
            16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .ok()?
                .decrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf)
                .map(|_| ()),
            32 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                .ok()?
                .decrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf)
                .map(|_| ()),
            _ => return None,
        };
        res.ok()?;
        if let Some(&p) = buf.last() {
            let p = p as usize;
            if (1..=16).contains(&p) && p <= n && buf[n - p..].iter().all(|&b| b as usize == p) {
                buf.truncate(n - p);
            }
        }
        Some(buf)
    }

    /// AES-256 key from /UE or /OE: CBC, zero IV, no padding.
    fn aes256_unwrap(key: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
        if wrapped.len() != 32 {
            return None;
        }
        let mut buf = wrapped.to_vec();
        cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &[0u8; 16])
            .ok()?
            .decrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf)
            .ok()?;
        Some(buf)
    }

    /// ISO 32000-2 Algorithm 2.B (R6), with the empty password.
    fn hash_r6(salt: &[u8], u: Option<&[u8]>) -> [u8; 32] {
        let mut first = Sha256::new();
        first.update(salt);
        if let Some(u) = u {
            first.update(u);
        }
        let mut k: Vec<u8> = first.finalize().to_vec();
        let mut round = 0usize;
        loop {
            let mut k1 = Vec::with_capacity((k.len() + 48) * 64);
            for _ in 0..64 {
                k1.extend_from_slice(&k);
                if let Some(u) = u {
                    k1.extend_from_slice(u);
                }
            }
            let mut e = k1;
            let n = e.len();
            let Ok(enc) = cbc::Encryptor::<aes::Aes128>::new_from_slices(&k[..16], &k[16..32]) else { break };
            if enc.encrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut e, n).is_err() {
                break;
            }
            let sum: u32 = e[..16].iter().map(|&b| b as u32).sum();
            k = match sum % 3 {
                0 => Sha256::digest(&e).to_vec(),
                1 => Sha384::digest(&e).to_vec(),
                _ => Sha512::digest(&e).to_vec(),
            };
            round += 1;
            let last = *e.last().unwrap_or(&0) as usize;
            if round >= 64 && last + 32 <= round {
                break;
            }
            if round > 64 + 256 {
                break;
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&k[..32]);
        out
    }

    /// String value of `/key` in a dictionary (literal or hex).
    fn string(dict: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let mut from = 0;
        while let Some(p) = memchr::memmem::find(&dict[from..], key).map(|p| p + from) {
            from = p + key.len();
            if dict.get(from).is_some_and(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            let mut i = from;
            while i < dict.len() && dict[i].is_ascii_whitespace() {
                i += 1;
            }
            return match dict.get(i) {
                Some(b'(') => Some(read_literal(dict, i)),
                Some(b'<') if dict.get(i + 1) != Some(&b'<') => Some(read_hex_string(dict, i)),
                _ => None,
            };
        }
        None
    }

    /// Name value of `/key` (`/StmF /StdCF` -> "StdCF").
    fn name(dict: &[u8], key: &[u8]) -> Option<String> {
        let p = memchr::memmem::find(dict, key)?;
        let rest = &dict[p + key.len()..];
        let i = rest.iter().position(|c| !c.is_ascii_whitespace())?;
        if rest[i] != b'/' {
            return None;
        }
        let end = rest[i + 1..].iter().position(|c| !c.is_ascii_alphanumeric()).map_or(rest.len(), |e| i + 1 + e);
        Some(String::from_utf8_lossy(&rest[i + 1..end]).into_owned())
    }

    /// `parse_enc_method`: the /CFM of crypt filter `filter` in /CF.
    fn method(dict: &[u8], filter: Option<String>, default: Method) -> Method {
        let Some(filter) = filter else { return default };
        if filter == "Identity" {
            return Method::Identity;
        }
        let Some(cf) = memchr::memmem::find(dict, b"/CF").map(|p| &dict[p..]) else { return default };
        let key = format!("/{filter}");
        let Some(p) = memchr::memmem::find(cf, key.as_bytes()) else { return default };
        match name(&cf[p..], b"/CFM").as_deref() {
            Some("V2") => Method::Rc4,
            Some("AESV2") => Method::AesV2,
            Some("AESV3") => Method::AesV3,
            Some("None") => Method::Identity,
            _ => Method::Unknown,
        }
    }

    /// First string of the trailer `/ID [<...> <...>]` (the last one in the file).
    fn file_id(data: &[u8]) -> Option<Vec<u8>> {
        let mut end = data.len();
        while let Some(p) = memchr::memmem::rfind(&data[..end], b"/ID") {
            end = p;
            let rest = &data[p + 3..];
            if rest.first().is_some_and(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            let i = rest.iter().position(|c| !c.is_ascii_whitespace())?;
            if rest[i] != b'[' {
                continue;
            }
            let j = i + 1 + rest[i + 1..].iter().position(|c| !c.is_ascii_whitespace())?;
            return match rest.get(j) {
                Some(b'<') => Some(read_hex_string(rest, j)),
                Some(b'(') => Some(read_literal(rest, j)),
                _ => None,
            };
        }
        None
    }

    /// The trailer's encryption dictionary: an inline `<< >>` or `N G R`.
    fn encrypt_dict<'a>(data: &'a [u8], objs: &'a [RawObj<'a>]) -> Option<(&'a [u8], Option<u32>)> {
        let mut end = data.len();
        while let Some(p) = memchr::memmem::rfind(&data[..end], b"/Encrypt") {
            end = p;
            let rest = &data[p + 8..];
            if rest.first().is_some_and(|c| c.is_ascii_alphanumeric()) {
                continue; // /EncryptMetadata
            }
            let i = rest.iter().position(|c| !c.is_ascii_whitespace())?;
            if rest[i..].starts_with(b"<<") {
                let close = memchr::memmem::find(&rest[i..], b">>").map_or(rest.len(), |c| i + c + 2);
                return Some((&rest[i..close], None));
            }
            let digits = rest[i..].iter().take_while(|c| c.is_ascii_digit()).count();
            let id: u32 = std::str::from_utf8(&rest[i..i + digits]).ok()?.parse().ok()?;
            return objs.iter().rev().find(|o| o.id == id).map(|o| (o.dict, Some(id)));
        }
        None
    }

    /// The decryption key when the empty password opens the document (user or
    /// owner password), else None.
    pub fn empty_password(data: &[u8], objs: &[RawObj<'_>]) -> Option<Crypt> {
        let (dict, encrypt_obj) = encrypt_dict(data, objs)?;
        memchr::memmem::find(dict, b"/Standard")?;
        let r = dict_int(dict, b"/R")?;
        if !(2..=6).contains(&r) {
            return None;
        }
        let o = string(dict, b"/O")?;
        let u = string(dict, b"/U")?;
        let oulen = if r < 5 { 32 } else { 48 };
        if o.len() < oulen || u.len() < oulen {
            return None;
        }
        let encrypt_metadata = !memchr::memmem::find(dict, b"/EncryptMetadata")
            .is_some_and(|p| dict[p + 16..].iter().skip_while(|c| c.is_ascii_whitespace()).take(5).eq(b"false".iter()));
        let (stream, string_m, embedded) = if r <= 3 {
            (Method::Rc4, Method::Rc4, Method::Rc4)
        } else {
            let stm = method(dict, name(dict, b"/StmF"), Method::Identity);
            let st = method(dict, name(dict, b"/StrF"), Method::Identity);
            let ef = method(dict, name(dict, b"/EFF"), stm);
            (stm, st, ef)
        };
        let key = match r {
            2..=4 => {
                let id = file_id(data)?;
                let p = dict_int(dict, b"/P")? as i32;
                let bits = if r == 4 { 128 } else { dict_int(dict, b"/Length").unwrap_or(40).clamp(40, 128) as usize };
                // Algorithm 2: key from the padded empty password.
                let mut h = Md5::new();
                h.update(PAD);
                h.update(&o[..32]);
                h.update(p.to_le_bytes());
                h.update(&id);
                if r >= 4 && !encrypt_metadata {
                    h.update([0xFF; 4]);
                }
                let mut key = h.finalize().to_vec();
                let n = if r == 2 { 5 } else { bits / 8 };
                if r >= 3 {
                    for _ in 0..50 {
                        key = Md5::digest(&key[..n]).to_vec();
                    }
                }
                key.truncate(n);
                // Algorithms 4 / 5: the key must reproduce /U.
                let ok = if r == 2 {
                    let mut t = PAD;
                    rc4(&key, &mut t);
                    t[..] == u[..32]
                } else {
                    let mut h = Md5::new();
                    h.update(PAD);
                    h.update(&id);
                    let mut t = h.finalize().to_vec();
                    for i in 0..=19u8 {
                        let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
                        rc4(&k, &mut t);
                    }
                    t[..16] == u[..16]
                };
                ok.then_some(key)?
            }
            5 | 6 => {
                let hash = |salt: &[u8], with_u: Option<&[u8]>| -> [u8; 32] {
                    if r == 6 {
                        hash_r6(salt, with_u)
                    } else {
                        let mut h = Sha256::new();
                        h.update(salt);
                        if let Some(u) = with_u {
                            h.update(u);
                        }
                        h.finalize().into()
                    }
                };
                // User password: hash(salt) == U[0..32], key = AES-256(UE).
                if hash(&u[32..40], None)[..] == u[..32] {
                    aes256_unwrap(&hash(&u[40..48], None), &string(dict, b"/UE")?)?
                } else if hash(&o[32..40], Some(&u[..48]))[..] == o[..32] {
                    // Owner password (with the 48-byte U).
                    aes256_unwrap(&hash(&o[40..48], Some(&u[..48])), &string(dict, b"/OE")?)?
                } else {
                    return None;
                }
            }
            _ => return None,
        };
        Some(Crypt { key, stream, string: string_m, embedded, encrypt_metadata, encrypt_obj })
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn pdf(objects: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n".to_vec();
        for o in objects {
            out.extend_from_slice(o);
            out.push(b'\n');
        }
        out.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
        out
    }

    fn stream_obj(id: u32, dict: &str, payload: &[u8]) -> Vec<u8> {
        let mut o = format!("{id} 0 obj\n<< {dict} /Length {} >>\nstream\n", payload.len()).into_bytes();
        o.extend_from_slice(payload);
        o.extend_from_slice(b"\nendstream\nendobj");
        o
    }

    #[test]
    fn flate_stream_is_decoded_for_the_scan() {
        let body = b"var x = unescape('%u9090%u9090'); app.alert(x);";
        let data = pdf(&[stream_obj(4, "/Filter /FlateDecode", &deflate(body))]);
        let a = analyze(&data, 1 << 20);
        assert_eq!(a.objects, 1);
        assert!(a.children.iter().any(|c| c.data == body), "{:?}", a.children);
        assert!(!a.escaped_common_name);
    }

    #[test]
    fn filter_chain_hex_then_flate() {
        let body = b"hello from a chained stream";
        let hex: String = deflate(body).iter().map(|b| format!("{b:02x}")).collect();
        let data = pdf(&[stream_obj(5, "/Filter [/ASCIIHexDecode /FlateDecode]", format!("{hex}>").as_bytes())]);
        let a = analyze(&data, 1 << 20);
        assert!(a.children.iter().any(|c| c.data == body));
    }

    #[test]
    fn escaped_name_is_flagged_and_still_decoded() {
        let body = b"payload";
        let data = pdf(&[stream_obj(6, "/Filter /Fl#61te#44ecode", &deflate(body))]);
        let a = analyze(&data, 1 << 20);
        assert!(a.escaped_common_name);
        assert!(a.children.iter().any(|c| c.data == body), "the unescaped filter is used");
    }

    #[test]
    fn name_inside_a_string_is_not_a_name() {
        let data = pdf(&[b"1 0 obj\n<< /Title (see /Fl#61teDecode here) >>\nendobj".to_vec()]);
        assert!(!analyze(&data, 1 << 20).escaped_common_name);
    }

    #[test]
    fn javascript_literal_hex_and_reference() {
        let lit = b"2 0 obj\n<< /S /JavaScript /JS (app.alert\\(1\\);\\nvar a=1;) >>\nendobj".to_vec();
        let hex = b"3 0 obj\n<< /S /JavaScript /JS <6170702e616c657274283229> >>\nendobj".to_vec();
        let reff = b"4 0 obj\n<< /S /JavaScript /JS 9 0 R >>\nendobj".to_vec();
        let target = stream_obj(9, "/Filter /FlateDecode", &deflate(b"eval('x')"));
        let a = analyze(&pdf(&[lit, hex, reff, target]), 1 << 20);
        assert_eq!(a.javascript, 3);
        assert!(a.hex_javascript);
        let has = |d: &[u8]| a.children.iter().any(|c| c.data == d);
        assert!(has(b"app.alert(1);\nvar a=1;"));
        assert!(has(b"app.alert(2)"));
        assert!(has(b"eval('x')"));
    }

    #[test]
    fn object_stream_members_are_read() {
        let inner = b"<< /S /JavaScript /JS (this.exportDataObject\\(\\)) >> << /Type /Page >>";
        let header = b"11 0 12 52 ";
        let mut body = header.to_vec();
        body.extend_from_slice(inner);
        let data = pdf(&[stream_obj(10, &format!("/Type /ObjStm /N 2 /First {} /Filter /FlateDecode", header.len()), &deflate(&body))]);
        let a = analyze(&data, 1 << 20);
        assert!(a.children.iter().any(|c| c.data == b"this.exportDataObject()"), "{:?}", a.children.iter().map(|c| &c.name).collect::<Vec<_>>());
    }

    #[test]
    fn png_predictor_up() {
        // Two rows of 3 bytes, filter 2 (Up).
        let rows = [2u8, 1, 2, 3, 2, 1, 1, 1];
        let data = pdf(&[stream_obj(7, "/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 3 >>", &deflate(&rows))]);
        let a = analyze(&data, 1 << 20);
        assert!(a.children.iter().any(|c| c.data == [1, 2, 3, 2, 3, 4]), "{:?}", a.children);
    }

    #[test]
    fn lzw_ascii85_runlength() {
        // "-----A---B" in LZW (from the PDF reference, EarlyChange 1).
        let lzw = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        assert_eq!(decode_lzw(&lzw, true), b"-----A---B");
        assert_eq!(decode_ascii85(b"<~87cURD]i,\"Ebo80~>"), b"Hello World!");
        assert_eq!(decode_run_length(&[2, b'a', b'b', b'c', 254, b'x', 128]), b"abcxxx");
    }

    #[test]
    fn raw_unfiltered_streams_are_not_children_and_trailer_checks() {
        let data = pdf(&[stream_obj(8, "", b"plain text already in the file")]);
        let a = analyze(&data, 1 << 20);
        assert!(a.children.is_empty());
        assert!(!a.bad_trailer && !a.bad_header_pos);
        let mut shifted = b"junk\n".to_vec();
        shifted.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n");
        let b = analyze(&shifted, 1 << 20);
        assert!(b.bad_header_pos && b.bad_trailer);
    }

    #[test]
    fn encrypted_flag() {
        let mut data = pdf(&[b"1 0 obj\n<< >>\nendobj".to_vec()]);
        data.extend_from_slice(b"trailer << /Encrypt 5 0 R >>");
        assert!(analyze(&data, 1 << 20).encrypted);
        let plain = pdf(&[b"1 0 obj\n<< /EncryptMetadata false >>\nendobj".to_vec()]);
        assert!(!analyze(&plain, 1 << 20).encrypted);
    }

    #[test]
    fn budget_caps_children() {
        let big = vec![b'A'; 10_000];
        let data = pdf(&[stream_obj(1, "/Filter /FlateDecode", &deflate(&big)), stream_obj(2, "/Filter /FlateDecode", &deflate(&big))]);
        let a = analyze(&data, 12_000);
        assert_eq!(a.children.iter().map(|c| c.data.len()).sum::<usize>(), 12_000);
    }
}
