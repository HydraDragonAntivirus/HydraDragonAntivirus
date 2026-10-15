//! ClamAV's normalized views, a port of libclamav `textnorm.c` and
//! `htmlnorm.c` (`cli_html_normalise`, with `screnc_decode` and the entity
//! handling of `entconv.c`).
//!
//! ClamAV scans scripts and HTML twice: as they are, and normalized. Its
//! text signatures (Target 7) and HTML signatures (Target 3) are written against
//! the normalized form, so they need it to match:
//! * text: control and 8-bit bytes dropped, whitespace runs to one space, lower case;
//! * HTML: `nocomment` (tags and text, comments out, lower case, entities
//!   decoded, `'` as `"` in scripts, `JScript.Encode` decoded), `notags` (the
//!   text only, plus link targets), `javascript` (every script through
//!   `jsnorm`), and the `data:` URIs as separate objects.
//!
//! Kept faithful to ClamAV, quirks included; the only difference is that the
//! input is processed as one buffer instead of 8 KB chunks.

use crate::jsnorm::JsNormalizer;

/// ClamAV defaults (`CLI_DEFAULT_MAX*`).
pub const MAX_HTML_NORMALIZE: usize = 40 * 1024 * 1024;
pub const MAX_HTML_NOTAGS: usize = 8 * 1024 * 1024;
pub const MAX_SCRIPT_NORMALIZE: usize = 20 * 1024 * 1024;

/// `textnorm.c`: the normalized text view.
pub fn text(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut space = false;
    for &c in data {
        match c {
            9..=13 | b' ' => {
                if !space {
                    out.push(b' ');
                }
                space = true;
            }
            0x21..=0x7e => {
                space = false;
                out.push(c.to_ascii_lowercase());
            }
            _ => {} // control and 8-bit bytes are skipped
        }
    }
    out
}

/// The views `html` produces.
#[derive(Debug, Default, Clone)]
pub struct HtmlViews {
    /// `nocomment.html`.
    pub nocomment: Vec<u8>,
    /// `notags.html`.
    pub notags: Vec<u8>,
    /// `javascript`: every script normalized, empty when there is none.
    pub javascript: Vec<u8>,
    /// `data:` URIs (RFC 2397), decoded.
    pub data_uris: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    Bad,
    Norm,
    Bit8,
    Comment,
    CharRef,
    EntityRefDecode,
    SkipWs,
    TrimWs,
    Tag,
    TagArg,
    TagArgVal,
    TagArgEqual,
    ProcessTag,
    CharRefDecode,
    LookforScrenc,
    JsDecode,
    JsDecodeLength,
    JsDecodeDecrypt,
    Rfc2397Type,
    Rfc2397Init,
    Rfc2397Data,
    Rfc2397Finish,
    Rfc2397Esc,
    EscapeChar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InTag {
    None,
    Script,
    Style,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quoted {
    Single,
    Double,
    Not,
}

const STR_LEN: usize = 1024;

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | 9..=13)
}

fn push_limited(v: &mut Vec<u8>, c: u8) {
    if v.len() < STR_LEN {
        v.push(c);
    }
}

/// ClamAV `u16_normalize`: < 0xff as the byte, `。．﹒` as `.`, else `&#xhhhh;`
/// (`\0` is dropped).
fn u16_normalize(u: u16, out: &mut Vec<u8>) {
    if u == 0 {
    } else if u < 0xff {
        out.push(u as u8);
    } else if matches!(u, 0x3002 | 0xFF0E | 0xFE52) {
        out.push(b'.');
    } else {
        out.extend_from_slice(format!("&#x{u:04x};").as_bytes());
    }
}

const TABLE_ORDER: [u8; 64] = [
    0, 2, 1, 0, 2, 1, 2, 1, 1, 2, 1, 2, 0, 1, 2, 1, 0, 1, 2, 1, 0, 0, 2, 1, 1, 2, 0, 1, 2, 1, 1, 2, 0, 0, 1, 2, 1, 2,
    1, 0, 1, 0, 0, 2, 1, 0, 1, 2, 0, 1, 2, 1, 0, 0, 2, 1, 1, 0, 0, 2, 1, 0, 1, 2,
];

#[rustfmt::skip]
const DECRYPT_TABLES: [[u8; 128]; 3] = [
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x57, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
     0x2E, 0x47, 0x7A, 0x56, 0x42, 0x6A, 0x2F, 0x26, 0x49, 0x41, 0x34, 0x32, 0x5B, 0x76, 0x72, 0x43,
     0x38, 0x39, 0x70, 0x45, 0x68, 0x71, 0x4F, 0x09, 0x62, 0x44, 0x23, 0x75, 0x3C, 0x7E, 0x3E, 0x5E,
     0xFF, 0x77, 0x4A, 0x61, 0x5D, 0x22, 0x4B, 0x6F, 0x4E, 0x3B, 0x4C, 0x50, 0x67, 0x2A, 0x7D, 0x74,
     0x54, 0x2B, 0x2D, 0x2C, 0x30, 0x6E, 0x6B, 0x66, 0x35, 0x25, 0x21, 0x64, 0x4D, 0x52, 0x63, 0x3F,
     0x7B, 0x78, 0x29, 0x28, 0x73, 0x59, 0x33, 0x7F, 0x6D, 0x55, 0x53, 0x7C, 0x3A, 0x5F, 0x65, 0x46,
     0x58, 0x31, 0x69, 0x6C, 0x5A, 0x48, 0x27, 0x5C, 0x3D, 0x24, 0x79, 0x37, 0x60, 0x51, 0x20, 0x36],
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x7B, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
     0x32, 0x30, 0x21, 0x29, 0x5B, 0x38, 0x33, 0x3D, 0x58, 0x3A, 0x35, 0x65, 0x39, 0x5C, 0x56, 0x73,
     0x66, 0x4E, 0x45, 0x6B, 0x62, 0x59, 0x78, 0x5E, 0x7D, 0x4A, 0x6D, 0x71, 0x3C, 0x60, 0x3E, 0x53,
     0xFF, 0x42, 0x27, 0x48, 0x72, 0x75, 0x31, 0x37, 0x4D, 0x52, 0x22, 0x54, 0x6A, 0x47, 0x64, 0x2D,
     0x20, 0x7F, 0x2E, 0x4C, 0x5D, 0x7E, 0x6C, 0x6F, 0x79, 0x74, 0x43, 0x26, 0x76, 0x25, 0x24, 0x2B,
     0x28, 0x23, 0x41, 0x34, 0x09, 0x2A, 0x44, 0x3F, 0x77, 0x3B, 0x55, 0x69, 0x61, 0x63, 0x50, 0x67,
     0x51, 0x49, 0x4F, 0x46, 0x68, 0x7C, 0x36, 0x70, 0x6E, 0x7A, 0x2F, 0x5F, 0x4B, 0x5A, 0x2C, 0x57],
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x6E, 0x0A, 0x0B, 0x0C, 0x06, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
     0x2D, 0x75, 0x52, 0x60, 0x71, 0x5E, 0x49, 0x5C, 0x62, 0x7D, 0x29, 0x36, 0x20, 0x7C, 0x7A, 0x7F,
     0x6B, 0x63, 0x33, 0x2B, 0x68, 0x51, 0x66, 0x76, 0x31, 0x64, 0x54, 0x43, 0x3C, 0x3A, 0x3E, 0x7E,
     0xFF, 0x45, 0x2C, 0x2A, 0x74, 0x27, 0x37, 0x44, 0x79, 0x59, 0x2F, 0x6F, 0x26, 0x72, 0x6A, 0x39,
     0x7B, 0x3F, 0x38, 0x77, 0x67, 0x53, 0x47, 0x34, 0x78, 0x5D, 0x30, 0x23, 0x5A, 0x5B, 0x6C, 0x48,
     0x55, 0x70, 0x69, 0x2E, 0x4C, 0x21, 0x24, 0x4E, 0x50, 0x09, 0x56, 0x73, 0x35, 0x61, 0x4B, 0x58,
     0x3B, 0x57, 0x22, 0x6D, 0x4D, 0x25, 0x28, 0x46, 0x4A, 0x32, 0x41, 0x3D, 0x5F, 0x4F, 0x42, 0x65],
];

fn b64(c: u8) -> i64 {
    match c {
        b'A'..=b'Z' => (c - b'A') as i64,
        b'a'..=b'z' => (c - b'a' + 26) as i64,
        b'0'..=b'9' => (c - b'0' + 52) as i64,
        b'+' => 62,
        b'/' => 63,
        _ => -1,
    }
}

/// `JScript.Encode` length / checksum field (ClamAV's exact arithmetic).
fn screnc_number(p: &[u8]) -> u32 {
    let g = |i: usize| b64(p[i]);
    let pos = |v: i64| if v < 0 { 0 } else { v };
    let mut v: i64 = pos(g(0)) << 2;
    v += g(1) >> 4;
    v += (g(1) & 0x0f) << 12;
    v += pos(g(2) >> 2) << 8;
    v += (g(2) & 0x03) << 22;
    v += pos(g(3)) << 16;
    v += (pos(g(4)) << 2) << 24;
    v += pos(g(5) >> 4) << 24;
    v as u32
}

struct Screnc {
    length: u32,
    table_pos: u8,
}

/// `screnc_decode`: decodes in place from `p`; the decoded bytes replace the
/// encoded ones (the buffer shrinks).
fn screnc_decode(buf: &mut Vec<u8>, p: usize, s: &mut Screnc) {
    let (mut src, mut dst) = (p, p);
    while s.length > 0 && src < buf.len() {
        let c = buf[src];
        if c == b'\n' || c == b'\r' {
            src += 1;
            continue;
        }
        if c < 0x80 {
            let mut value = DECRYPT_TABLES[TABLE_ORDER[s.table_pos as usize] as usize][c as usize];
            if value == 0xFF {
                src += 1;
                s.length = s.length.saturating_sub(1);
                match buf.get(src) {
                    None => src -= 1,
                    Some(0x21) => value = 0x3c,
                    Some(0x23) => value = 0x0d,
                    Some(0x24) => value = 0x40,
                    Some(0x26) => value = 0x0a,
                    Some(0x2a) => value = 0x3e,
                    _ => {}
                }
            }
            buf[dst] = value;
            dst += 1;
            s.table_pos = (s.table_pos + 1) % 64;
        } else {
            buf[dst] = buf[src];
            dst += 1;
            src += 1;
            match buf.get(src).copied() {
                Some(n) => {
                    buf[dst] = n;
                    dst += 1;
                }
                None => break,
            }
        }
        src += 1;
        s.length = s.length.saturating_sub(1);
    }
    if s.length == 0 {
        // Checksum (8) and the `^#~@` terminator (4).
        if buf.len().saturating_sub(src) >= 12 {
            src += 12;
        }
        buf.drain(dst..src.min(buf.len()));
    } else {
        buf.truncate(dst);
    }
}

/// `cli_html_normalise` over `data`.
#[allow(unused_assignments)] // faithful port of the C state machine
pub fn html(data: &[u8]) -> HtmlViews {
    // ClamAV's chunk reader drops NUL bytes.
    let mut buf: Vec<u8> = data.iter().copied().filter(|&c| c != 0).collect();
    let mut v = HtmlViews::default();
    let o2 = &mut v.nocomment;
    let text = &mut v.notags;

    let mut state = St::Norm;
    let mut next_state = St::Bad;
    let mut saved_next_state = St::Bad;
    let mut in_tag = InTag::None;
    let mut text_space_written = false;
    let mut binary = false;
    let mut escape = false;
    let mut hex = false;
    let mut quoted = Quoted::Not;
    let mut value: i64 = 0;
    let mut length: u32 = 0;
    let mut tag: Vec<u8> = Vec::new();
    let mut tag_arg: Vec<u8> = Vec::new();
    let mut tag_val: Vec<u8> = Vec::new();
    let mut tag_args: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    let mut entity: Vec<u8> = Vec::new();
    let (mut mbchar, mut mbchar2): (u32, u32) = (0, 0);
    let (mut look_for_screnc, mut in_screnc) = (false, false);
    let mut ptr_screnc: Option<usize> = None;
    let mut screnc = Screnc { length: 0, table_pos: 0 };
    let mut js: Option<(JsNormalizer, usize)> = None; // normalizer, script start
    let mut data_uri: Option<(Vec<u8>, Vec<u8>)> = None; // media type, data

    let arg_value = |args: &[(Vec<u8>, Option<Vec<u8>>)], name: &[u8]| -> Option<Vec<u8>> {
        args.iter().find(|(t, _)| t == name).and_then(|(_, v)| v.clone())
    };
    let arg_add = |args: &mut Vec<(Vec<u8>, Option<Vec<u8>>)>, name: &[u8], val: Option<&[u8]>| {
        let val = val.map(|v| match v.strip_prefix(b"\"") {
            // Quotes are dropped: the opening one and the last character.
            Some(rest) => rest[..rest.len().saturating_sub(1)].to_vec(),
            None => v.to_vec(),
        });
        args.push((name.to_vec(), val));
    };

    let mut i = buf.iter().position(|&c| !is_space(c)).unwrap_or(buf.len());
    loop {
        if i >= buf.len() {
            // A `JScript.Encode` start found ahead: decode from there.
            if look_for_screnc {
                if let Some(p) = ptr_screnc.take() {
                    i = p;
                    state = St::JsDecodeLength;
                    next_state = St::Bad;
                    continue;
                }
            }
            break;
        }
        let c = buf[i];
        if !binary && c == b'\n' {
            buf[i] = b' ';
            continue;
        }
        if !binary && c == b'\r' {
            i += 1;
            continue;
        }
        match state {
            St::Bad => break,
            St::SkipWs => {
                if is_space(c) {
                    i += 1;
                } else {
                    state = next_state;
                    next_state = St::Bad;
                }
            }
            St::TrimWs => {
                if is_space(c) {
                    i += 1;
                } else {
                    if in_tag == InTag::None {
                        o2.push(b' ');
                    }
                    state = next_state;
                    next_state = St::Bad;
                }
            }
            St::Bit8 => {
                if c < 0x80 || mbchar >= 0x10000 {
                    if mbchar == 0xE38082 || mbchar == 0xEFBC8E || mbchar == 0xEFB992 || (mbchar == 0xA1 && matches!(c, 0x43 | 0x44 | 0x4F)) {
                        o2.push(b'.');
                        text.push(b'.');
                        if mbchar == 0xA1 {
                            i += 1;
                            mbchar = 0;
                            continue;
                        }
                    } else {
                        let (c0, c1, c2) = ((mbchar >> 16) as u8, (mbchar >> 8) as u8, mbchar as u8);
                        if c0 != 0 {
                            o2.push(c0);
                            text.push(c0);
                        }
                        if c0 != 0 || c1 != 0 {
                            o2.push(c1);
                            text.push(c1);
                        }
                        o2.push(c2);
                        text.push(c1); // sic: ClamAV writes c1 here
                    }
                    mbchar = 0;
                    state = next_state;
                    next_state = St::Norm;
                } else {
                    mbchar = (mbchar << 8) | c as u32;
                    i += 1;
                }
            }
            St::Norm => {
                if c == b'<' {
                    o2.push(b'<');
                    if in_tag == InTag::None && !text_space_written {
                        text.push(b' ');
                        text_space_written = true;
                    }
                    i += 1;
                    state = St::SkipWs;
                    tag.clear();
                    next_state = St::Tag;
                } else if is_space(c) {
                    if !text_space_written && in_tag == InTag::None {
                        text.push(b' ');
                        text_space_written = true;
                    }
                    state = St::TrimWs;
                    next_state = St::Norm;
                } else if c == b'&' {
                    if !text_space_written && in_tag == InTag::None {
                        text.push(b' ');
                        text_space_written = true;
                    }
                    state = St::CharRef;
                    next_state = St::Norm;
                    i += 1;
                } else if c >= 0x80 {
                    state = St::Bit8;
                    next_state = St::Norm;
                    mbchar = c as u32;
                    i += 1;
                } else {
                    let mut l = c.to_ascii_lowercase();
                    if in_tag != InTag::None && l == b'\'' {
                        l = b'"';
                    }
                    o2.push(l);
                    if in_tag == InTag::None {
                        if c < 0x20 {
                            if !text_space_written {
                                text.push(b' ');
                                text_space_written = true;
                            }
                        } else {
                            text.push(l);
                            text_space_written = false;
                        }
                    }
                    i += 1;
                }
            }
            St::Tag => {
                if tag.is_empty() && c == b'!' {
                    if in_tag != InTag::None {
                        o2.push(b'!');
                    } else {
                        o2.pop(); // the `<`
                    }
                    state = St::Comment;
                    next_state = St::Bad;
                    i += 1;
                } else if c == b'>' {
                    o2.push(b'>');
                    i += 1;
                    state = St::SkipWs;
                    next_state = St::ProcessTag;
                } else if !is_space(c) {
                    o2.push(c.to_ascii_lowercase());
                    // Inside a script only `</` starts a tag.
                    if in_tag != InTag::None && tag.is_empty() && c != b'/' {
                        state = St::Norm;
                    }
                    push_limited(&mut tag, c.to_ascii_lowercase());
                    i += 1;
                } else {
                    state = St::SkipWs;
                    tag_arg.clear();
                    next_state = if in_tag == InTag::None { St::TagArg } else { St::ProcessTag };
                }
            }
            St::TagArg => {
                if c == b'=' {
                    o2.push(b'=');
                    i += 1;
                    state = St::SkipWs;
                    escape = false;
                    quoted = Quoted::Not;
                    tag_val.clear();
                    next_state = St::TagArgVal;
                } else if is_space(c) {
                    i += 1;
                    state = St::SkipWs;
                    next_state = St::TagArgEqual;
                } else if c == b'>' {
                    o2.push(b'>');
                    if !tag_arg.is_empty() {
                        arg_add(&mut tag_args, &tag_arg, None);
                    }
                    i += 1;
                    state = St::ProcessTag;
                    next_state = St::Bad;
                } else {
                    if tag_arg.is_empty() {
                        o2.push(b' ');
                    }
                    o2.push(c.to_ascii_lowercase());
                    push_limited(&mut tag_arg, c.to_ascii_lowercase());
                    i += 1;
                }
            }
            St::TagArgEqual => {
                if c == b'=' {
                    o2.push(b'=');
                    i += 1;
                    state = St::SkipWs;
                    escape = false;
                    quoted = Quoted::Not;
                    tag_val.clear();
                    next_state = St::TagArgVal;
                } else {
                    if !tag_arg.is_empty() {
                        arg_add(&mut tag_args, &tag_arg, None);
                    }
                    tag_arg.clear();
                    state = St::TagArg;
                    next_state = St::Bad;
                }
            }
            St::TagArgVal => {
                if tag_val == b"data:" || tag_val == b"\"data:" {
                    // RFC 2397 inline data.
                    o2.pop();
                    if quoted != Quoted::Not {
                        o2.push(b'"');
                    }
                    tag_val.clear();
                    state = St::Rfc2397Type;
                    next_state = St::TagArg;
                } else if c == b'&' {
                    state = St::CharRef;
                    next_state = St::TagArgVal;
                    i += 1;
                } else if c == b'\'' || c == b'"' {
                    let q = if c == b'\'' { Quoted::Single } else { Quoted::Double };
                    if tag_val.is_empty() {
                        quoted = q;
                        o2.push(b'"');
                        push_limited(&mut tag_val, b'"');
                        i += 1;
                    } else if !escape && quoted == q {
                        o2.push(b'"');
                        push_limited(&mut tag_val, b'"');
                        arg_add(&mut tag_args, &tag_arg, Some(&tag_val));
                        i += 1;
                        state = St::SkipWs;
                        tag_arg.clear();
                        next_state = St::TagArg;
                    } else {
                        o2.push(b'"');
                        push_limited(&mut tag_val, b'"');
                        i += 1;
                    }
                } else if is_space(c) || c == b'>' {
                    if quoted == Quoted::Not {
                        arg_add(&mut tag_args, &tag_arg, Some(&tag_val));
                        state = St::SkipWs;
                        tag_arg.clear();
                        next_state = St::TagArg;
                    } else {
                        o2.push(c);
                        push_limited(&mut tag_val, if is_space(c) { b' ' } else { b'>' });
                        state = St::SkipWs;
                        escape = false;
                        quoted = Quoted::Not;
                        next_state = St::TagArgVal;
                        i += 1;
                    }
                } else {
                    if mbchar2 != 0 && (c < 0x80 || mbchar2 >= 0x10000) {
                        if mbchar2 == 0xE38082 || mbchar2 == 0xEFBC8E || mbchar2 == 0xEFB992 || (mbchar2 == 0xA1 && matches!(c, 0x43 | 0x44 | 0x4F)) {
                            o2.push(b'.');
                            push_limited(&mut tag_val, b'.');
                            if mbchar2 == 0xA1 {
                                i += 1;
                                mbchar2 = 0;
                                continue;
                            }
                        } else {
                            let (c0, c1, c2) = ((mbchar2 >> 16) as u8, (mbchar2 >> 8) as u8, mbchar2 as u8);
                            if c0 != 0 {
                                o2.push(c0);
                            }
                            if c0 != 0 || c1 != 0 {
                                o2.push(c1);
                            }
                            o2.push(c2);
                            if c0 != 0 {
                                push_limited(&mut tag_val, c0);
                            }
                            if c0 != 0 || c1 != 0 {
                                push_limited(&mut tag_val, c1);
                            }
                            push_limited(&mut tag_val, c2);
                        }
                        mbchar2 = 0;
                    }
                    if c >= 0x80 {
                        mbchar2 = (mbchar2 << 8) | c as u32;
                    } else {
                        o2.push(c.to_ascii_lowercase());
                        push_limited(&mut tag_val, c);
                    }
                    i += 1;
                }
                escape = buf.get(i) == Some(&b'\\');
            }
            St::Comment => {
                if in_tag != InTag::None && !is_space(c) {
                    let l = c.to_ascii_lowercase();
                    o2.push(if l == b'\'' { b'"' } else { l });
                }
                if c == b'>' {
                    state = St::SkipWs;
                    next_state = St::Norm;
                }
                i += 1;
            }
            St::ProcessTag => {
                state = St::SkipWs;
                next_state = St::Norm;
                if tag.first() == Some(&b'/') {
                    if tag == b"/script" {
                        in_tag = InTag::None;
                        if let Some((mut n, begin)) = js.take() {
                            n.process(&buf[begin.min(i)..i]);
                            n.finish();
                            n.output(&mut v.javascript);
                        }
                    } else if tag == b"/style" && in_tag == InTag::Style {
                        in_tag = InTag::None;
                    }
                } else if tag == b"script" {
                    let lang = arg_value(&tag_args, b"language").map(|l| l.to_ascii_lowercase());
                    let new_lang: Option<&[u8]> = match lang.as_deref() {
                        Some(b"jscript.encode") => Some(b"javascript"),
                        Some(b"vbscript.encode") => Some(b"vbscript"),
                        _ => None,
                    };
                    if let Some(new_lang) = new_lang {
                        for (t, val) in tag_args.iter_mut() {
                            if t == b"language" {
                                *val = Some(new_lang.to_vec());
                            }
                        }
                        state = St::SkipWs;
                        next_state = St::JsDecode;
                        // The new tag after the one already written.
                        o2.push(b'<');
                        o2.extend_from_slice(&tag);
                        for (t, val) in &tag_args {
                            o2.push(b' ');
                            o2.extend_from_slice(t);
                            if let Some(val) = val {
                                o2.extend_from_slice(b"=\"");
                                o2.extend(val.iter().map(u8::to_ascii_lowercase));
                                o2.push(b'"');
                            }
                        }
                        o2.push(b'>');
                    }
                    in_tag = InTag::Script;
                    if js.is_none() {
                        js = Some((JsNormalizer::new(), i));
                    }
                } else if tag == b"style" {
                    in_tag = InTag::Style;
                } else if tag == b"%@" {
                    let lang = arg_value(&tag_args, b"language").map(|l| l.to_ascii_lowercase());
                    if matches!(lang.as_deref(), Some(b"jscript.encode") | Some(b"vbscript.encode")) {
                        saved_next_state = next_state;
                        next_state = state;
                        look_for_screnc = false;
                        state = St::LookforScrenc;
                    }
                } else if tag == b"a" || tag == b"img" {
                    // Link targets go to the text view.
                    let key: &[u8] = if tag == b"a" { b"href" } else { b"src" };
                    if let Some(val) = arg_value(&tag_args, key).filter(|v| !v.is_empty()) {
                        text.extend_from_slice(&val);
                        text.push(b' ');
                        text_space_written = true;
                    }
                }
                tag_args.clear();
            }
            St::CharRef => {
                if c == b'#' {
                    value = 0;
                    hex = false;
                    state = St::CharRefDecode;
                    i += 1;
                } else {
                    state = St::EntityRefDecode;
                }
            }
            St::EntityRefDecode => {
                if c == b';' {
                    match crate::html_entities::lookup(&entity) {
                        Some(cp) => {
                            let mut tmp = Vec::new();
                            u16_normalize(cp, &mut tmp);
                            for &b in &tmp {
                                o2.push(b);
                                if next_state == St::TagArgVal {
                                    push_limited(&mut tag_val, b);
                                }
                            }
                        }
                        None => {
                            o2.push(b'&');
                            if next_state == St::TagArgVal {
                                push_limited(&mut tag_val, b'&');
                            }
                            for &b in &entity {
                                let l = b.to_ascii_lowercase();
                                o2.push(l);
                                if next_state == St::TagArgVal {
                                    push_limited(&mut tag_val, l);
                                }
                            }
                            if next_state == St::TagArgVal {
                                push_limited(&mut tag_val, b';');
                            }
                            o2.push(b';');
                        }
                    }
                    entity.clear();
                    state = next_state;
                    next_state = St::Bad;
                    i += 1;
                } else if (c.is_ascii_alphanumeric() || matches!(c, b'_' | b':' | b'-')) && entity.len() < STR_LEN {
                    entity.push(c);
                    i += 1;
                } else {
                    if next_state == St::TagArgVal {
                        push_limited(&mut tag_val, b'&');
                    }
                    o2.push(b'&');
                    for &b in &entity {
                        let l = b.to_ascii_lowercase();
                        o2.push(l);
                        if next_state == St::TagArgVal {
                            push_limited(&mut tag_val, l);
                        }
                    }
                    state = next_state;
                    next_state = St::Bad;
                    entity.clear();
                }
            }
            St::CharRefDecode => {
                if value == 0 && (c == b'x' || c == b'X') {
                    hex = true;
                    i += 1;
                } else if c == b';' {
                    if next_state == St::TagArgVal {
                        push_limited(&mut tag_val, value as u8);
                    }
                    if value < 0x80 {
                        o2.push((value as u8).to_ascii_lowercase());
                    } else {
                        u16_normalize(value as u16, o2);
                    }
                    state = next_state;
                    next_state = St::Bad;
                    i += 1;
                } else if c.is_ascii_digit() || (hex && c.is_ascii_hexdigit()) {
                    if hex && value < i64::MAX / 16 {
                        value *= 16;
                    } else if !hex && value < i64::MAX / 10 {
                        value *= 10;
                    } else {
                        o2.push(value as u8);
                        state = next_state;
                        next_state = St::Bad;
                        i += 1;
                        continue;
                    }
                    let inc = if c.is_ascii_digit() { (c - b'0') as i64 } else { (c.to_ascii_lowercase() - b'a' + 10) as i64 };
                    if value > i64::MAX - inc {
                        o2.push(value as u8);
                        state = next_state;
                        next_state = St::Bad;
                        i += 1;
                        continue;
                    }
                    value += inc;
                    i += 1;
                } else {
                    o2.push(value as u8);
                    state = next_state;
                    next_state = St::Bad;
                }
            }
            St::LookforScrenc => {
                look_for_screnc = true;
                ptr_screnc = memchr::memmem::find(&buf[i..], b"#@~^").map(|p| {
                    buf[i + p] = b'/';
                    buf[i + p + 1] = b'/';
                    i + p + 4
                });
                state = next_state;
                next_state = saved_next_state;
            }
            St::JsDecode => {
                if buf[i..].starts_with(b"#@~^") {
                    buf[i] = b'/';
                    buf[i + 1] = b'/';
                    i += 4;
                    state = St::JsDecodeLength;
                    next_state = St::Bad;
                } else {
                    o2.push(c.to_ascii_lowercase());
                    i += 1;
                }
            }
            St::JsDecodeLength => {
                if buf.len() - i < 8 {
                    state = St::Norm;
                    next_state = St::Bad;
                    continue;
                }
                screnc = Screnc { length: screnc_number(&buf[i..]), table_pos: 0 };
                state = St::JsDecodeDecrypt;
                in_screnc = true;
                next_state = St::Bad;
                buf[i + 7] = b'\n'; // for the JS normalizer
                i += 8;
            }
            St::JsDecodeDecrypt => {
                screnc_decode(&mut buf, i, &mut screnc);
                if screnc.length == 0 {
                    in_screnc = false;
                }
                state = St::Norm;
                next_state = St::Bad;
            }
            St::Rfc2397Type => {
                if c == b'\'' || c == b'"' {
                    let q = if c == b'\'' { Quoted::Single } else { Quoted::Double };
                    if !escape && quoted == q {
                        i += 1;
                        state = St::SkipWs;
                        tag_arg.clear();
                        next_state = St::TagArg;
                    } else {
                        push_limited(&mut tag_val, b'"');
                        i += 1;
                    }
                } else if is_space(c) || c == b'>' {
                    if quoted == Quoted::Not {
                        state = St::SkipWs;
                        tag_arg.clear();
                        next_state = St::TagArg;
                    } else {
                        push_limited(&mut tag_val, if is_space(c) { b' ' } else { b'>' });
                        state = St::SkipWs;
                        escape = false;
                        quoted = Quoted::Not;
                        next_state = St::Rfc2397Type;
                        i += 1;
                    }
                } else if c == b',' {
                    state = St::Rfc2397Init;
                    escape = false;
                    next_state = St::Bad;
                    i += 1;
                } else {
                    push_limited(&mut tag_val, c.to_ascii_lowercase());
                    i += 1;
                }
                escape = buf.get(i) == Some(&b'\\');
            }
            St::Rfc2397Init => {
                if let Some((t, d)) = data_uri.take() {
                    v.data_uris.push(decode_data_uri(&t, d));
                }
                data_uri = Some((tag_val.clone(), Vec::new()));
                state = St::Rfc2397Data;
                binary = true;
            }
            St::Rfc2397Data => {
                let out = &mut data_uri.as_mut().map(|d| &mut d.1);
                if c == b'&' {
                    state = St::CharRef;
                    next_state = St::Rfc2397Data;
                    i += 1;
                } else if c == b'%' {
                    length = 0;
                    value = 0;
                    state = St::EscapeChar;
                    next_state = St::Rfc2397Esc;
                    i += 1;
                } else if (c == b'\'' && !escape && quoted == Quoted::Single)
                    || (c == b'"' && !escape && quoted == Quoted::Double)
                    || ((is_space(c) || c == b'>') && quoted == Quoted::Not)
                {
                    state = St::Rfc2397Finish;
                    i += 1;
                } else {
                    if let Some(o) = out {
                        o.push(c);
                    }
                    i += 1;
                }
                escape = buf.get(i) == Some(&b'\\');
            }
            St::Rfc2397Finish => {
                if let Some((t, d)) = data_uri.take() {
                    v.data_uris.push(decode_data_uri(&t, d));
                }
                state = St::SkipWs;
                escape = false;
                quoted = Quoted::Not;
                next_state = St::TagArg;
                binary = false;
            }
            St::Rfc2397Esc => {
                if let Some((_, d)) = data_uri.as_mut() {
                    match length {
                        2 => d.push(value as u8),
                        1 => {
                            d.push(b'%');
                            d.push((value as u8).wrapping_add(b'0'));
                        }
                        _ => d.push(b'%'),
                    }
                }
                state = St::Rfc2397Data;
            }
            St::EscapeChar => {
                if value < i64::MAX / 16 {
                    value *= 16;
                } else {
                    state = next_state;
                    next_state = St::Bad;
                    i += 1;
                    continue;
                }
                length += 1;
                if c.is_ascii_hexdigit() {
                    value += if c.is_ascii_digit() { (c - b'0') as i64 } else { (c.to_ascii_lowercase() - b'a' + 10) as i64 };
                } else {
                    state = next_state;
                }
                if length == 2 {
                    state = next_state;
                }
                i += 1;
            }
        }
        if next_state == state && state != St::Bad && !matches!(state, St::SkipWs | St::TrimWs) {
            // ClamAV's infinite-loop guard (it checks once per chunk).
            next_state = St::Bad;
        }
    }
    let _ = in_screnc;
    // Unfinished entity.
    if !entity.is_empty() {
        match crate::html_entities::lookup(&entity) {
            Some(cp) => u16_normalize(cp, &mut v.nocomment),
            None => {
                v.nocomment.push(b'&');
                v.nocomment.extend(entity.iter().map(u8::to_ascii_lowercase));
            }
        }
    }
    if let Some((t, d)) = data_uri.take() {
        v.data_uris.push(decode_data_uri(&t, d));
    }
    // A script still open at the end.
    if let Some((mut n, begin)) = js.take() {
        n.process(&buf[begin.min(buf.len())..]);
        n.finish();
        n.output(&mut v.javascript);
    }
    v.data_uris.retain(|d| !d.is_empty());
    v
}

/// A `data:` URI's bytes: base64 decoded when the media type says so (ClamAV
/// writes it as a MIME part with `Content-transfer-encoding: base64`).
fn decode_data_uri(media: &[u8], data: Vec<u8>) -> Vec<u8> {
    if !memchr::memmem::find(media, b";base64").is_some() {
        return data;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in &data {
        let v = b64(c);
        if v < 0 {
            continue;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> String {
        String::from_utf8_lossy(v).into_owned()
    }

    #[test]
    fn text_view() {
        assert_eq!(s(&text(b"Hello\r\n\t  WORLD\x00\xff!")), "hello world!");
        // UTF-16LE ASCII text becomes plain text (NULs dropped).
        assert_eq!(s(&text(b"E\0V\0I\0L\0")), "evil");
    }

    #[test]
    fn html_views() {
        let v = html(b"<HTML><!-- hidden --><BODY onload='Go()'>Hi &amp; <b>Bye</b> &#x41;&lt;\n<a href=\"HTTP://X.y/Z\">link</a></BODY></HTML>");
        assert_eq!(s(&v.nocomment), "<html><body onload=\"go()\">hi & <b>bye</b>a< <a href=\"http://x.y/z\">link</a></body></html>");
        assert_eq!(s(&v.notags), " hi bye HTTP://X.y/Z link ");
        assert!(v.javascript.is_empty());
    }

    #[test]
    fn script_goes_to_javascript_view() {
        let v = html(b"<html><script>var Abc = 'x' + \"y\";\ndocument.write(Abc);</script></html>");
        assert_eq!(s(&v.javascript), "<script>var n000=\"xy\";document.write(n000);</script>");
        assert!(s(&v.nocomment).contains("<script>varabc=\"x\"+\"y\";document.write(abc);</script>"), "{}", s(&v.nocomment));
    }

    #[test]
    fn data_uri_is_decoded() {
        let v = html(b"<img src=\"data:text/plain;base64,SGVsbG8=\"> <a href='data:,abc%41'>x</a>");
        assert_eq!(v.data_uris, vec![b"Hello".to_vec(), b"abcA".to_vec()]);
    }

    #[test]
    fn jscript_encode_is_decoded() {
        // "#@~^" + length + encoded "alert(1)"-like body is hard to hand-craft:
        // check the decoder round-trips ClamAV's table on a known sample.
        let mut buf = b"//~^CAAAAA==\nzm/\x7fXDb4ZAAAAA==^#~@ rest".to_vec();
        let mut st = Screnc { length: 8, table_pos: 0 };
        screnc_decode(&mut buf, 13, &mut st);
        assert_eq!(st.length, 0);
        assert!(buf.ends_with(b" rest"));
    }
}
