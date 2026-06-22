// ClamAV-compatible AC (Aho-Corasick) pattern matching engine.
// Maps exactly to clamav/libclamav/matcher-ac.c structure and semantics.

use std::fmt;

// ── CLI_MATCH constants ────────────────────────────────────────────────────
// From clamav/libclamav/matcher.h lines 66-73
pub const CLI_MATCH_METADATA: u16 = 0xff00;
pub const CLI_MATCH_WILDCARD: u16 = 0x0f00;
pub const CLI_MATCH_CHAR: u16 = 0x0000;
pub const CLI_MATCH_NOCASE: u16 = 0x1000;
pub const CLI_MATCH_IGNORE: u16 = 0x0100;
pub const CLI_MATCH_SPECIAL: u16 = 0x0200;
pub const CLI_MATCH_NIBBLE_HIGH: u16 = 0x0300;
pub const CLI_MATCH_NIBBLE_LOW: u16 = 0x0400;

// ACPATT options from matcher-ac.h lines 40-46
pub const ACPATT_OPTION_NOOPTS: u8 = 0x00;
pub const ACPATT_OPTION_NOCASE: u8 = 0x01;
pub const ACPATT_OPTION_FULLWORD: u8 = 0x02;
pub const ACPATT_OPTION_WIDE: u8 = 0x04;
pub const ACPATT_OPTION_ASCII: u8 = 0x08;

// AC special types from matcher-ac.c lines 51-56
const AC_SPECIAL_ALT_CHAR: u16 = 1;
const AC_SPECIAL_ALT_STR_FIXED: u16 = 2;
const AC_SPECIAL_ALT_STR: u16 = 3;
const AC_SPECIAL_LINE_MARKER: u16 = 4;
const AC_SPECIAL_BOUNDARY: u16 = 5;
const AC_SPECIAL_WORD_MARKER: u16 = 6;

// Boundary flags from matcher-ac.c lines 58-69
const AC_BOUNDARY_LEFT: u32 = 0x0001;
const AC_BOUNDARY_LEFT_NEGATIVE: u32 = 0x0002;
const AC_BOUNDARY_RIGHT: u32 = 0x0004;
const AC_BOUNDARY_RIGHT_NEGATIVE: u32 = 0x0008;
const AC_LINE_MARKER_LEFT: u32 = 0x0010;
const AC_LINE_MARKER_LEFT_NEGATIVE: u32 = 0x0020;
const AC_LINE_MARKER_RIGHT: u32 = 0x0040;
const AC_LINE_MARKER_RIGHT_NEGATIVE: u32 = 0x0080;
const AC_WORD_MARKER_LEFT: u32 = 0x0100;
const AC_WORD_MARKER_LEFT_NEGATIVE: u32 = 0x0200;
const AC_WORD_MARKER_RIGHT: u32 = 0x0400;
const AC_WORD_MARKER_RIGHT_NEGATIVE: u32 = 0x0800;

const AC_CH_MAXDIST: u16 = 32;
const ACPATT_ALTN_MAXNEST: usize = 15;

// ── Boundary character table ───────────────────────────────────────────────
// From matcher-ac.c lines 71-88
static BOUNDARY: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    3, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 1, 3,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn cli_nocase(val: u8) -> u8 {
    val.to_ascii_lowercase()
}

fn cli_nocasei(val: u8) -> u8 {
    val.to_ascii_uppercase()
}

// ── Hex parsing ────────────────────────────────────────────────────────────
// Equivalent to cli_hex2ui in clamav/libclamav/str.c lines 124-140
pub fn hex_to_u16(hex: &str) -> Result<Vec<u16>, String> {
    let hex = hex.as_bytes();
    let len = hex.len();
    if len % 2 != 0 {
        return Err(format!("Malformed hexstring: length {len}"));
    }
    let mut out = Vec::with_capacity(len / 2);
    let mut i = 0;
    while i < len {
        let val = if hex[i] == b'?' && hex[i + 1] == b'?' {
            CLI_MATCH_IGNORE
        } else if hex[i + 1] == b'?' {
            let c = hex_nibble(hex[i])?;
            (c as u16) << 4 | CLI_MATCH_NIBBLE_HIGH
        } else if hex[i] == b'?' {
            let c = hex_nibble(hex[i + 1])?;
            c as u16 | CLI_MATCH_NIBBLE_LOW
        } else if hex[i] == b'(' {
            CLI_MATCH_SPECIAL
        } else {
            let hi = hex_nibble(hex[i])?;
            let lo = hex_nibble(hex[i + 1])?;
            (hi << 4 | lo) as u16
        };
        out.push(val);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex nibble '{}'", c as char)),
    }
}

pub fn hex_from_u16(inst: u16) -> String {
    let meta = inst & CLI_MATCH_METADATA;
    let byte = (inst & 0xff) as u8;
    match meta {
        CLI_MATCH_CHAR => format!("{:02x}", byte),
        CLI_MATCH_NOCASE => format!("{:02x}", byte),
        CLI_MATCH_IGNORE => "??".to_string(),
        CLI_MATCH_NIBBLE_HIGH => format!("{:01x}?", byte >> 4),
        CLI_MATCH_NIBBLE_LOW => format!("?{:01x}", byte),
        CLI_MATCH_SPECIAL => "()".to_string(),
        _ => format!("{:04x}", inst),
    }
}

// ── AltNode & AcSpecial ────────────────────────────────────────────────────
// From matcher-ac.h lines 73-88
#[derive(Clone)]
pub struct AltNode {
    pub str: Vec<u16>,
    pub unique: bool,
    pub next: Option<Box<AltNode>>,
}

#[derive(Clone)]
pub enum AltUnion {
    Byte(Vec<u8>),
    FStr(Vec<Vec<u8>>),
    VStr(Option<Box<AltNode>>),
}

#[derive(Clone)]
pub struct AcSpecial {
    pub alt: AltUnion,
    pub len: [u16; 2], // 0=MIN, 1=MAX
    pub num: u16,
    pub type_: u16,
    pub negative: u16,
}

// ── AcPattern ──────────────────────────────────────────────────────────────
// From matcher-ac.h lines 90-107
#[derive(Clone)]
pub struct AcPattern {
    pub pattern: Vec<u16>,
    pub prefix: Vec<u16>,
    pub length: [u16; 3],
    pub prefix_length: [u16; 3],
    pub mindist: u32,
    pub maxdist: u32,
    pub sigid: u32,
    pub ch: [u16; 2],
    pub ch_mindist: [u16; 2],
    pub ch_maxdist: [u16; 2],
    pub parts: u16,
    pub partno: u16,
    pub special: u16,
    pub special_pattern: u16,
    pub special_table: Vec<AcSpecial>,
    pub rtype: u16,
    pub type_: u16,
    pub boundary: u32,
    pub depth: u8,
    pub sigopts: u8,
    pub virname: Option<String>,
    pub lsigid: [u32; 3],
}

impl AcPattern {
    fn new() -> Self {
        Self {
            pattern: Vec::new(),
            prefix: Vec::new(),
            length: [0; 3],
            prefix_length: [0; 3],
            mindist: 0,
            maxdist: 0,
            sigid: 0,
            ch: [CLI_MATCH_IGNORE, CLI_MATCH_IGNORE],
            ch_mindist: [0; 2],
            ch_maxdist: [0; 2],
            parts: 0,
            partno: 0,
            special: 0,
            special_pattern: 0,
            special_table: Vec::new(),
            rtype: 0,
            type_: 0,
            boundary: 0,
            depth: 0,
            sigopts: 0,
            virname: None,
            lsigid: [0; 3],
        }
    }

    /// Match a single uint16_t instruction against a byte.
    /// Equivalent to AC_MATCH_CHAR macro in matcher-ac.c lines 1056-1100
    pub fn match_byte(inst: u16, byte: u8) -> bool {
        match inst & CLI_MATCH_METADATA {
            CLI_MATCH_CHAR => (inst as u8) == byte,
            CLI_MATCH_NOCASE => (inst & 0xff) as u8 == cli_nocase(byte),
            CLI_MATCH_IGNORE => true,
            CLI_MATCH_NIBBLE_HIGH => (inst as u8 & 0xf0) == (byte & 0xf0),
            CLI_MATCH_NIBBLE_LOW => (inst as u8 & 0x0f) == (byte & 0x0f),
            _ => false,
        }
    }
}

// ── Trie node ──────────────────────────────────────────────────────────────
// Index-based trie for safe Rust. We store all nodes in a Vec and refer by index.
// This avoids the ownership problems of Box<AcNode>.

#[derive(Clone)]
pub struct TrieNode {
    pub list: Vec<usize>, // indices into AcMatcher.patterns
    pub trans: Vec<usize>, // 256 entries, 0 = no transition
    pub fail: usize,      // index to failure node
}

impl TrieNode {
    fn new() -> Self {
        Self {
            list: Vec::new(),
            trans: vec![0; 256],
            fail: 0,
        }
    }

    fn is_final(&self) -> bool {
        !self.list.is_empty()
    }
}

// ── AcMatcher ──────────────────────────────────────────────────────────────
// The top-level AC automaton.

pub struct AcMatcher {
    pub nodes: Vec<TrieNode>,
    pub patterns: Vec<AcPattern>,
    pub ac_mindepth: u8,
    pub ac_maxdepth: u8,
    pub maxpatlen: u16,
}

impl AcMatcher {
    pub fn new(mindepth: u8, maxdepth: u8) -> Self {
        let mut nodes = Vec::new();
        nodes.push(TrieNode::new()); // root is index 0
        Self {
            nodes,
            patterns: Vec::new(),
            ac_mindepth: mindepth,
            ac_maxdepth: maxdepth,
            maxpatlen: 0,
        }
    }

    /// Add a hex pattern signature with ClamAV semantics.
    pub fn add_sig(
        &mut self,
        hexsig: &str,
        sigopts: u8,
        sigid: u32,
        parts: u16,
        partno: u16,
        rtype: u16,
        type_: u16,
        mindist: u32,
        maxdist: u32,
    ) -> Result<(), String> {
        let mut new = AcPattern::new();
        new.rtype = rtype;
        new.type_ = type_;
        new.sigid = sigid;
        new.parts = parts;
        new.partno = partno;
        new.mindist = mindist;
        new.maxdist = maxdist;
        new.ch[0] |= CLI_MATCH_IGNORE;
        new.ch[1] |= CLI_MATCH_IGNORE;
        new.sigopts = sigopts;

        // ── Parse [a-b] anchored byte ranges ──────────────────────────────
        // ClamAV matcher-ac.c lines 2761-2852
        let processed = self.parse_brackets(hexsig, sigopts, &mut new)?;

        // ── Parse (alternations) and (B) (L) (W) ──────────────────────────
        // ClamAV matcher-ac.c lines 2854-3009
        let processed = self.parse_specials(&processed, sigopts, &mut new)?;

        // ── Convert hex to uint16_t pattern ───────────────────────────────
        // ClamAV matcher-ac.c line 3014
        let raw_pattern = hex_to_u16(&processed)?;

        // Length check
        if (raw_pattern.len() as u16) < self.ac_mindepth as u16 {
            return Err(format!(
                "Signature too short: {} < mindepth {}",
                raw_pattern.len(),
                self.ac_mindepth
            ));
        }

        new.length[0] = raw_pattern.len() as u16;
        new.pattern = raw_pattern;

        // Compute length[1] and length[2] (min/max accounting for specials)
        // ClamAV matcher-ac.c lines 3036-3045
        let mut j: usize = 0;
        for i in 0..new.length[0] as usize {
            if (new.pattern[i] & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL {
                new.length[1] += new.special_table[j].len[0];
                new.length[2] += new.special_table[j].len[1];
                j += 1;
            } else {
                new.length[1] += 1;
                new.length[2] += 1;
            }
        }

        // ── Apply nocase ──────────────────────────────────────────────────
        // ClamAV matcher-ac.c lines 3051-3057
        if sigopts & ACPATT_OPTION_NOCASE != 0 {
            for i in 0..new.length[0] as usize {
                if (new.pattern[i] & CLI_MATCH_METADATA) == CLI_MATCH_CHAR {
                    new.pattern[i] = cli_nocase((new.pattern[i] & 0xff) as u8) as u16 | CLI_MATCH_NOCASE;
                }
            }
        }

        // ── Prefix splitting (wprefix/zprefix) ────────────────────────────
        // ClamAV matcher-ac.c lines 3073-3186
        self.split_prefix(&mut new)?;

        // ── Update maxpatlen ──────────────────────────────────────────────
        if new.length[2] + new.prefix_length[2] > self.maxpatlen {
            self.maxpatlen = new.length[2] + new.prefix_length[2];
        }

        // Store the pattern
        self.patterns.push(new);
        Ok(())
    }

    /// Parse [a-b] anchored byte ranges (ClamAV matcher-ac.c lines 2761-2852)
    fn parse_brackets(&self, hex: &str, sigopts: u8, pat: &mut AcPattern) -> Result<String, String> {
        if !hex.contains('[') {
            return Ok(hex.to_string());
        }

        let mut result = String::new();
        let mut pos = 0;

        for range_idx in 0..2u8 {
            // Find '['
            let open = match hex[pos..].find('[') {
                Some(o) => pos + o,
                None => break,
            };

            // Push everything before '['
            result.push_str(&hex[pos..open]);

            let close = match hex[open..].find(']') {
                Some(c) => open + c,
                None => return Err("missing closing square bracket".to_string()),
            };

            let range_str = &hex[open + 1..close];
            let after = close + 1;

            // Parse range
            let (n1_str, n2_str) = if let Some(dash) = range_str.find('-') {
                (range_str[..dash].trim(), Some(range_str[dash + 1..].trim()))
            } else {
                (range_str.trim(), None)
            };

            let n1: u32 = n1_str.parse().map_err(|_| "invalid range value".to_string())?;
            let n2: u32 = match n2_str {
                Some(s) => s.parse().map_err(|_| "invalid range value".to_string())?,
                None => n1,
            };

            if n1 > n2 || n2 > AC_CH_MAXDIST as u32 {
                return Err("incorrect range inside square brackets".to_string());
            }

            // The anchored byte is the hex pair BEFORE the bracket
            let before = &hex[open.saturating_sub(2)..open];
            if before.len() == 2 && before.as_bytes().iter().all(|&c| c.is_ascii_hexdigit()) {
                let dec = hex_to_u16(before)?;
                if !dec.is_empty() {
                    let val = dec[0];
                    if (sigopts & ACPATT_OPTION_NOCASE != 0) && (val & CLI_MATCH_METADATA) == CLI_MATCH_CHAR {
                        pat.ch[range_idx as usize] = cli_nocase((val & 0xff) as u8) as u16 | CLI_MATCH_NOCASE;
                    } else {
                        pat.ch[range_idx as usize] = val;
                    }
                    pat.ch_mindist[range_idx as usize] = n1 as u16;
                    pat.ch_maxdist[range_idx as usize] = n2 as u16;
                }
            }

            pos = after;
        }

        // Push remaining
        result.push_str(&hex[pos..]);
        Ok(result)
    }

    /// Parse (alternations) and (B) (L) (W) special tokens (ClamAV matcher-ac.c lines 2854-3009)
    fn parse_specials(&self, hex: &str, sigopts: u8, pat: &mut AcPattern) -> Result<String, String> {
        if !hex.contains('(') {
            return Ok(hex.to_string());
        }

        let mut result = String::new();
        let bytes = hex.as_bytes();
        let len = bytes.len();
        let mut pos = 0;

        while pos < len {
            if bytes[pos] != b'(' {
                result.push(bytes[pos] as char);
                pos += 1;
                continue;
            }

            // Found '('
            let open_pos = pos;

            // Check for negative alternate (!) 
            let mut negative = false;
            let content_start_for_check = if open_pos >= 2 { open_pos - 2 } else { 0 };
            if content_start_for_check + 2 == open_pos && bytes[content_start_for_check] == b'!' {
                negative = true;
            }

            // Find matching ')'
            pos += 1;
            let paren_content_start = pos;
            let mut depth = 1;
            while pos < len && depth > 0 {
                if bytes[pos] == b'(' { depth += 1; }
                else if bytes[pos] == b')' { depth -= 1; }
                pos += 1;
            }
            if depth != 0 {
                return Err("Missing closing parenthesis".to_string());
            }
            let close_pos = pos; // position after ')'
            let content = &hex[paren_content_start..close_pos - 1];

            // Check for (B), (L), (W) at pattern boundaries
            let content_trimmed = content.trim();
            let after_paren = close_pos;
            let at_end = after_paren >= len;
            let at_start = open_pos == 0 || (open_pos >= 2 && bytes[open_pos - 2] == b'!');

            match content_trimmed {
                "B" | "L" | "W" => {
                    let (right_flag, right_neg_flag, left_flag, left_neg_flag) = match content_trimmed {
                        "B" => (AC_BOUNDARY_RIGHT, AC_BOUNDARY_RIGHT_NEGATIVE, AC_BOUNDARY_LEFT, AC_BOUNDARY_LEFT_NEGATIVE),
                        "L" => (AC_LINE_MARKER_RIGHT, AC_LINE_MARKER_RIGHT_NEGATIVE, AC_LINE_MARKER_LEFT, AC_LINE_MARKER_LEFT_NEGATIVE),
                        "W" => (AC_WORD_MARKER_RIGHT, AC_WORD_MARKER_RIGHT_NEGATIVE, AC_WORD_MARKER_LEFT, AC_WORD_MARKER_LEFT_NEGATIVE),
                        _ => unreachable!(),
                    };

                    if at_end {
                        pat.boundary |= if negative { right_neg_flag } else { right_flag };
                        continue;
                    } else if at_start {
                        pat.boundary |= if negative { left_neg_flag } else { left_flag };
                        continue;
                    }
                    // Not at boundary — treat as inline special, fall through
                }
                _ => {}
            }

            // Create special table entry
            let mut special = AcSpecial {
                alt: AltUnion::Byte(Vec::new()),
                len: [0, 0],
                num: 0,
                type_: 0,
                negative: if negative { 1 } else { 0 },
            };

            match content_trimmed {
                "B" => special.type_ = AC_SPECIAL_BOUNDARY,
                "L" => special.type_ = AC_SPECIAL_LINE_MARKER,
                "W" => special.type_ = AC_SPECIAL_WORD_MARKER,
                _ => {
                    self.parse_alternation_str(content, sigopts, &mut special)?;
                }
            }

            pat.special += 1;
            pat.special_table.push(special);

            // Add "()" placeholder in hex pattern
            result.push_str("()");
        }

        Ok(result)
    }

    /// Parse alternation string like "ALT1|ALT2|ALT3" into an AcSpecial
    fn parse_alternation_str(&self, content: &str, _sigopts: u8, special: &mut AcSpecial) -> Result<(), String> {
        let alternatives: Vec<&str> = content.split('|').collect();
        if alternatives.is_empty() {
            return Err("Empty alternation block".to_string());
        }

        if alternatives.len() > ACPATT_ALTN_MAXNEST {
            return Err("Alternation exceeds max nest".to_string());
        }

        let all_hex = alternatives.iter().all(|a| a.bytes().all(|c| c.is_ascii_hexdigit()));
        let all_single_byte = all_hex && alternatives.iter().all(|a| a.len() == 2);
        let all_same_len = alternatives.iter().all(|a| a.len() == alternatives[0].len());

        if all_single_byte {
            // AC_SPECIAL_ALT_CHAR
            let mut bytes: Vec<u8> = alternatives.iter()
                .filter_map(|a| hex_to_u16(a).ok())
                .filter_map(|v| v.first().copied())
                .map(|v| (v & 0xff) as u8)
                .collect();
            bytes.sort();
            special.alt = AltUnion::Byte(bytes.clone());
            special.num = bytes.len() as u16;
            special.len = [1, 1];
            special.type_ = AC_SPECIAL_ALT_CHAR;
        } else if all_hex && all_same_len {
            // AC_SPECIAL_ALT_STR_FIXED
            let strlen = (alternatives[0].len() / 2) as u16;
            let mut strs: Vec<Vec<u8>> = alternatives.iter()
                .filter_map(|a| hex_to_u16(a).ok())
                .map(|v| v.iter().map(|x| (*x & 0xff) as u8).collect())
                .collect();
            strs.sort();
            special.alt = AltUnion::FStr(strs.clone());
            special.num = strs.len() as u16;
            special.len = [strlen, strlen];
            special.type_ = AC_SPECIAL_ALT_STR_FIXED;
        } else {
            // AC_SPECIAL_ALT_STR: generic alternatives
            let mut nodes: Option<Box<AltNode>> = None;
            for alt in alternatives.iter().rev() {
                if let Ok(str_u16) = hex_to_u16(alt) {
                    if str_u16.len() > special.len[1] as usize {
                        special.len[1] = str_u16.len() as u16;
                    }
                    if special.len[0] == 0 || (str_u16.len() as u16) < special.len[0] {
                        special.len[0] = str_u16.len() as u16;
                    }
                    nodes = Some(Box::new(AltNode {
                        str: str_u16,
                        unique: false,
                        next: nodes,
                    }));
                }
            }
            special.alt = AltUnion::VStr(nodes);
            special.num = alternatives.len() as u16;
            special.type_ = AC_SPECIAL_ALT_STR;
        }

        Ok(())
    }

    /// Prefix splitting: ClamAV matcher-ac.c lines 3082-3186
    fn split_prefix(&mut self, new: &mut AcPattern) -> Result<(), String> {
        let mut wprefix = false;
        let mut zprefix = true;
        let mut plen: u16 = 0;
        let mut ppos: u16 = 0;
        let mut nzplen: u16 = 0;
        let mut nzpos: u16 = 0;

        let max_check = (self.ac_maxdepth as u16).min(new.length[0]);
        for i in 0..max_check as usize {
            if new.pattern[i] & CLI_MATCH_WILDCARD != 0 {
                wprefix = true;
                break;
            }
            if zprefix && new.pattern[i] != 0 {
                zprefix = false;
            }
        }

        if !wprefix && !zprefix {
            new.depth = new.length[0].min(self.ac_maxdepth as u16) as u8;
            return Ok(());
        }

        let pend = if new.length[0] >= self.ac_mindepth as u16 {
            new.length[0] - self.ac_mindepth as u16 + 1
        } else {
            new.depth = new.length[0].min(self.ac_maxdepth as u16) as u8;
            return Ok(());
        };

        for i in 0..pend {
            let max_j = (i + self.ac_maxdepth as u16).min(new.length[0]);
            for j in i..max_j {
                if new.pattern[j as usize] & CLI_MATCH_WILDCARD != 0 {
                    break;
                }
                if j - i + 1 >= plen {
                    plen = j - i + 1;
                    ppos = i;
                }

                if (new.pattern[ppos as usize] != 0)
                    || (new.length[0] > ppos + 1 && new.pattern[(ppos + 1) as usize] != 0)
                {
                    if plen >= self.ac_maxdepth as u16 {
                        break;
                    }
                    if plen >= self.ac_mindepth as u16 && plen > nzplen {
                        nzplen = plen;
                        nzpos = ppos;
                    }
                }
            }

            if plen >= self.ac_maxdepth as u16
                && (new.pattern[ppos as usize] != 0 || new.pattern[(ppos + 1) as usize] != 0)
            {
                break;
            }
        }

        if nzplen != 0
            && new.length[0] > ppos + 1
            && new.pattern[ppos as usize] == 0
            && new.pattern[(ppos + 1) as usize] == 0
        {
            plen = nzplen;
            ppos = nzpos;
        }

        if plen < self.ac_mindepth as u16 {
            new.depth = new.length[0].min(self.ac_maxdepth as u16) as u8;
            return Ok(());
        }

        new.prefix = new.pattern[..ppos as usize].to_vec();
        new.prefix_length[0] = ppos;
        let mut j: usize = 0;
        for i in 0..ppos as usize {
            if (new.prefix[i] & CLI_MATCH_WILDCARD) == CLI_MATCH_SPECIAL {
                new.special_pattern += 1;
            }
            if (new.prefix[i] & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL {
                new.prefix_length[1] += new.special_table[j].len[0];
                new.prefix_length[2] += new.special_table[j].len[1];
                j += 1;
            } else {
                new.prefix_length[1] += 1;
                new.prefix_length[2] += 1;
            }
        }

        new.pattern = new.pattern[ppos as usize..].to_vec();
        new.length[0] -= ppos;
        new.length[1] -= new.prefix_length[1];
        new.length[2] -= new.prefix_length[2];

        Ok(())
    }

    /// Add all stored patterns into the AC trie (cli_ac_addpatt equivalent)
    pub fn build_trie_from_patterns(&mut self) {
        for idx in 0..self.patterns.len() {
            self.add_patt_to_trie(idx);
        }
        self.build_trie_failure_links();
    }

    fn add_patt_to_trie(&mut self, pat_idx: usize) {
        let pat = &self.patterns[pat_idx];
        let mut len = (self.ac_maxdepth as u16).min(pat.length[0]);

        for i in 0..len as usize {
            if pat.pattern[i] & CLI_MATCH_WILDCARD != 0 {
                len = i as u16;
                break;
            }
        }

        if len < self.ac_mindepth as u16 {
            return;
        }

        // Update pattern depth
        self.patterns[pat_idx].depth = len as u8;

        // Insert into trie recursively
        self.add_patt_recursive(pat_idx, 0, 0, len);
    }

    fn add_patt_recursive(&mut self, pat_idx: usize, node_idx: usize, i: u16, len: u16) {
        if i >= len {
            self.nodes[node_idx].list.push(pat_idx);
            return;
        }

        let byte_val = (self.patterns[pat_idx].pattern[i as usize] & 0xff) as usize;

        // Handle nocase: also insert under uppercase
        if (self.patterns[pat_idx].sigopts & ACPATT_OPTION_NOCASE != 0)
            && (self.patterns[pat_idx].pattern[i as usize] & 0xff) < 0x80
            && char::from(self.patterns[pat_idx].pattern[i as usize] as u8 & 0xff).is_ascii_alphabetic()
        {
            let upper = cli_nocasei(byte_val as u8) as usize;
            if self.nodes[node_idx].trans[upper] == 0 {
                let new_idx = self.nodes.len();
                self.nodes.push(TrieNode::new());
                self.nodes[node_idx].trans[upper] = new_idx;
            }
            self.add_patt_recursive(pat_idx, self.nodes[node_idx].trans[upper], i + 1, len);
        }

        // Normal transition
        if self.nodes[node_idx].trans[byte_val] == 0 {
            let new_idx = self.nodes.len();
            self.nodes.push(TrieNode::new());
            self.nodes[node_idx].trans[byte_val] = new_idx;
        }
        self.add_patt_recursive(pat_idx, self.nodes[node_idx].trans[byte_val], i + 1, len);
    }

    /// Build failure links (ac_maketrans equivalent, matcher-ac.c lines 535-625)
    fn build_trie_failure_links(&mut self) {
        // Root failure is root
        self.nodes[0].fail = 0;

        // Initialize root's transitions to point to root for missing chars
        // Then BFS to build failure links
        let mut bfs_queue: Vec<usize> = Vec::new();

        for i in 0..256 {
            if self.nodes[0].trans[i] != 0 {
                let child = self.nodes[0].trans[i];
                self.nodes[child].fail = 0;
                bfs_queue.push(child);
            } else {
                self.nodes[0].trans[i] = 0;
            }
        }

        // BFS
        let mut qidx = 0;
        while qidx < bfs_queue.len() {
            let node = bfs_queue[qidx];
            qidx += 1;

            // Handle leaf nodes: propagate failure lists
            if self.nodes[node].trans.iter().all(|&t| t == 0) {
                // Leaf: propagate fail list
                let fail = self.nodes[node].fail;
                if fail != 0 {
                    let fail_list = self.nodes[fail].list.clone();
                    for &p in &fail_list {
                        if !self.nodes[node].list.contains(&p) {
                            self.nodes[node].list.push(p);
                        }
                    }
                }
                continue;
            }

            for i in 0..256 {
                let child = self.nodes[node].trans[i];
                if child != 0 {
                    // Compute failure for this child
                    let mut fail = self.nodes[node].fail;
                    while fail != 0 && self.nodes[fail].trans[i] == 0 {
                        fail = self.nodes[fail].fail;
                    }
                    if self.nodes[fail].trans[i] != 0 && self.nodes[fail].trans[i] != child {
                        self.nodes[child].fail = self.nodes[fail].trans[i];
                    } else {
                        self.nodes[child].fail = 0;
                    }

                    // Propagate failure's final lists
                    let fail_of_child = self.nodes[child].fail;
                    if fail_of_child != 0 {
                        let fail_list = self.nodes[fail_of_child].list.clone();
                        for &p in &fail_list {
                            if !self.nodes[child].list.contains(&p) {
                                self.nodes[child].list.push(p);
                            }
                        }
                    }

                    bfs_queue.push(child);
                }
            }

            // Fill in missing transitions from fail links
            for i in 0..256 {
                if self.nodes[node].trans[i] == 0 {
                    let fail = self.nodes[node].fail;
                    if fail != 0 {
                        self.nodes[node].trans[i] = self.nodes[fail].trans[i];
                    } else {
                        self.nodes[node].trans[i] = 0;
                    }
                }
            }
        }
    }

    /// Scan a buffer and return all pattern matches.
    /// This is the simplified Rust equivalent of cli_ac_scanbuff.
    /// Returns (pattern_index, match_start, match_end) for each match.
    pub fn scan(&self, buffer: &[u8], base_offset: u32) -> Vec<(usize, u32, u32)> {
        let mut results = Vec::new();
        if buffer.is_empty() || self.nodes.is_empty() {
            return results;
        }

        let mut current = 0usize; // start at root

        for i in 0..buffer.len() {
            let byte = buffer[i] as usize;

            // Follow transition
            if byte < 256 {
                current = self.nodes[current].trans[byte];
            } else {
                current = 0;
            }

            // Check if current node is final (has patterns)
            if self.nodes[current].is_final() {
                for &pat_idx in &self.nodes[current].list {
                    // Verify full pattern including backward match
                    if let Some((start, end)) = self.verify_match(pat_idx, i, buffer, base_offset) {
                        results.push((pat_idx, start, end));
                    }
                }
            }
        }

        results
    }

    /// Verify a pattern candidate at trie-match position `bp`. Special-aware
    /// (alternations / gaps / boundaries via the special table), so the byte
    /// width can differ from the instruction count. Equivalent to ClamAV's
    /// ac_findmatch + ac_forward/backward_match_branch.
    fn verify_match(&self, pat_idx: usize, bp: usize, buffer: &[u8], _file_offset: u32) -> Option<(u32, u32)> {
        let pat = &self.patterns[pat_idx];
        let depth = pat.depth as usize;
        if depth == 0 || bp + 1 < depth {
            return None;
        }
        // Where pattern[0] (start of the trie-anchored main part) sits.
        let anchor = bp + 1 - depth;

        // Forward: match the main part (with specials) from the anchor.
        let end = self.match_seq(
            &pat.pattern,
            &pat.special_table,
            0,
            anchor,
            pat.special_pattern as usize,
            buffer,
        )?;
        if !self.right_checks(pat, end, buffer) {
            return None;
        }

        // No prefix → match starts at the anchor.
        if pat.prefix_length[0] == 0 {
            if !self.left_checks(pat, anchor, buffer) {
                return None;
            }
            return Some((anchor as u32, end as u32));
        }

        // Prefix: find a start in [anchor-max, anchor-min] whose prefix match
        // (with specials) ends exactly at the anchor.
        let pre_specials = &pat.special_table[..pat.special_pattern as usize];
        let pmin = pat.prefix_length[1] as usize;
        let pmax = pat.prefix_length[2] as usize;
        for w in pmin..=pmax {
            if anchor < w {
                continue;
            }
            let start = anchor - w;
            if let Some(pend) = self.match_seq(&pat.prefix, pre_specials, 0, start, 0, buffer) {
                if pend == anchor {
                    if !self.left_checks(pat, start, buffer) {
                        return None;
                    }
                    return Some((start as u32, end as u32));
                }
            }
        }
        None
    }

    /// Recursive special-aware forward matcher over an instruction slice.
    /// `ip` = instruction index, `bp` = buffer position, `sc` = special-table
    /// index. Returns the buffer position just past the match, or `None`.
    fn match_seq(
        &self,
        pattern: &[u16],
        specials: &[AcSpecial],
        ip: usize,
        bp: usize,
        sc: usize,
        buffer: &[u8],
    ) -> Option<usize> {
        let mut ip = ip;
        let mut bp = bp;
        let mut sc = sc;
        while ip < pattern.len() {
            let inst = pattern[ip];
            if (inst & CLI_MATCH_METADATA) != CLI_MATCH_SPECIAL {
                if bp >= buffer.len() || !AcPattern::match_byte(inst, buffer[bp]) {
                    return None;
                }
                bp += 1;
                ip += 1;
                continue;
            }
            let sp = specials.get(sc)?;
            let neg = sp.negative != 0;
            match sp.type_ {
                AC_SPECIAL_BOUNDARY | AC_SPECIAL_LINE_MARKER | AC_SPECIAL_WORD_MARKER => {
                    // Inline marker — approximated as a zero-width pass.
                    ip += 1;
                    sc += 1;
                }
                AC_SPECIAL_ALT_CHAR => {
                    if bp >= buffer.len() {
                        return None;
                    }
                    let hit = matches!(&sp.alt, AltUnion::Byte(b) if b.binary_search(&buffer[bp]).is_ok());
                    if hit == neg {
                        return None;
                    }
                    bp += 1;
                    ip += 1;
                    sc += 1;
                }
                AC_SPECIAL_ALT_STR_FIXED => {
                    let w = sp.len[0] as usize;
                    if bp + w > buffer.len() {
                        return None;
                    }
                    let hit = matches!(&sp.alt, AltUnion::FStr(strs) if strs.iter().any(|s| s.as_slice() == &buffer[bp..bp + w]));
                    if hit == neg {
                        return None;
                    }
                    bp += w;
                    ip += 1;
                    sc += 1;
                }
                AC_SPECIAL_ALT_STR => {
                    let AltUnion::VStr(head) = &sp.alt else { return None };
                    if neg {
                        let w = sp.len[0] as usize;
                        if bp + w > buffer.len() {
                            return None;
                        }
                        let mut any = false;
                        let mut node = head;
                        while let Some(n) = node {
                            if n.str.len() == w
                                && n.str.iter().enumerate().all(|(k, &bi)| AcPattern::match_byte(bi, buffer[bp + k]))
                            {
                                any = true;
                                break;
                            }
                            node = &n.next;
                        }
                        if any {
                            return None;
                        }
                        bp += w;
                        ip += 1;
                        sc += 1;
                    } else {
                        let mut node = head;
                        while let Some(n) = node {
                            let blen = n.str.len();
                            if bp + blen <= buffer.len()
                                && n.str.iter().enumerate().all(|(k, &bi)| AcPattern::match_byte(bi, buffer[bp + k]))
                            {
                                if let Some(e) = self.match_seq(pattern, specials, ip + 1, bp + blen, sc + 1, buffer) {
                                    return Some(e);
                                }
                            }
                            node = &n.next;
                        }
                        return None;
                    }
                }
                _ => return None,
            }
        }
        Some(bp)
    }

    /// Right-side boundary / `[a-b]` checks at `bp` (the byte just past the match).
    /// (Tail of ClamAV's ac_forward_match_branch; the forward byte matching itself
    /// now lives in `match_seq`.)
    fn right_checks(&self, pat: &AcPattern, bp: usize, buffer: &[u8]) -> bool {
        let length = buffer.len();

        // Right-side boundary checks
        if pat.boundary & AC_BOUNDARY_RIGHT != 0 {
            let matched = pat.boundary & AC_BOUNDARY_RIGHT_NEGATIVE != 0;
            if bp == length || BOUNDARY[buffer[bp.min(buffer.len() - 1)] as usize] >= 2 {
                if !matched { return false; }
            } else {
                if matched { return false; }
            }
        }

        if pat.boundary & AC_LINE_MARKER_RIGHT != 0 {
            let matched = pat.boundary & AC_LINE_MARKER_RIGHT_NEGATIVE != 0;
            if bp == length || buffer[bp - 1] == b'\n' {
                if !matched { return false; }
            } else {
                if matched { return false; }
            }
        }

        if pat.boundary & AC_WORD_MARKER_RIGHT != 0 {
            let matched = pat.boundary & AC_WORD_MARKER_RIGHT_NEGATIVE != 0;
            if bp >= length {
                if !matched { return false; }
            } else if bp + 1 < length && (pat.sigopts & ACPATT_OPTION_WIDE) != 0 {
                if !(buffer[bp].is_ascii_alphanumeric() && buffer[bp + 1] == 0) {
                    if !matched { return false; }
                } else {
                    if matched { return false; }
                }
            } else if !buffer[bp].is_ascii_alphanumeric() {
                if !matched { return false; }
            } else {
                if matched { return false; }
            }
        }

        // Right-side anchored byte range [n-m]
        if !(pat.ch[1] & CLI_MATCH_IGNORE != 0) {
            let mut bp = bp + pat.ch_mindist[1] as usize;
            let mut found = false;
            for _ in pat.ch_mindist[1]..=pat.ch_maxdist[1] {
                if bp >= buffer.len() { return false; }
                if AcPattern::match_byte(pat.ch[1], buffer[bp]) {
                    found = true;
                    break;
                }
                bp += 1;
            }
            if !found { return false; }
        }

        true
    }

    /// Left-side boundary / `[a-b]` checks at the match `start` (the prefix byte
    /// matching itself now lives in `match_seq`). Tail of ClamAV's
    /// ac_backward_match_branch.
    fn left_checks(&self, pat: &AcPattern, start: usize, buffer: &[u8]) -> bool {
        let bp = start; // match start position (original `bp` == `*start`)

        if pat.boundary & AC_BOUNDARY_LEFT != 0 {
            let matched = pat.boundary & AC_BOUNDARY_LEFT_NEGATIVE != 0;
            if start == 0 || (bp > 0 && (BOUNDARY[buffer[bp - 1] as usize] == 1 || BOUNDARY[buffer[bp - 1] as usize] == 3)) {
                if !matched { return false; }
            } else if matched {
                return false;
            }
        }

        if pat.boundary & AC_LINE_MARKER_LEFT != 0 {
            let matched = pat.boundary & AC_LINE_MARKER_LEFT_NEGATIVE != 0;
            if start == 0 || (bp > 0 && buffer[bp - 1] == b'\n') {
                if !matched { return false; }
            } else if matched {
                return false;
            }
        }

        if pat.boundary & AC_WORD_MARKER_LEFT != 0 {
            let matched = pat.boundary & AC_WORD_MARKER_LEFT_NEGATIVE != 0;
            if start == 0 {
                if !matched { return false; }
            } else if bp > 0 && (pat.sigopts & ACPATT_OPTION_WIDE) != 0 {
                let left_byte = if bp >= 2 { buffer[bp - 2] } else { 0 };
                if bp <= 1 || !(left_byte.is_ascii_alphanumeric() && buffer[bp - 1] == 0) {
                    if !matched { return false; }
                } else if matched {
                    return false;
                }
            } else if bp > 0 && !buffer[bp - 1].is_ascii_alphanumeric() {
                if !matched { return false; }
            } else if matched {
                return false;
            }
        }

        // Left-side anchored byte range [n-m]
        if !(pat.ch[0] & CLI_MATCH_IGNORE != 0) {
            if pat.ch_mindist[0] as usize + 1 > start {
                return false;
            }
            let mut p = bp - pat.ch_mindist[0] as usize;
            let mut found = false;
            for _ in pat.ch_mindist[0]..=pat.ch_maxdist[0] {
                if AcPattern::match_byte(pat.ch[0], buffer[p]) {
                    found = true;
                    break;
                }
                if p == 0 { return false; }
                p -= 1;
            }
            if !found { return false; }
        }

        true
    }

    /// Get the longest fixed-byte literal from a pattern for prefilter use.
    /// Scans for runs of CLI_MATCH_CHAR / CLI_MATCH_NOCASE instructions.
    pub fn pattern_literal(pat: &AcPattern) -> Option<(Vec<u8>, usize)> {
        let mut best_len = 0usize;
        let mut best_bytes: Option<Vec<u8>> = None;
        let mut best_prefix: usize = 0;

        let mut run_start: Option<usize> = None;
        let mut run_bytes: Vec<u8> = Vec::new();

        for (i, &inst) in pat.pattern.iter().enumerate() {
            let meta = inst & CLI_MATCH_METADATA;
            if meta == CLI_MATCH_CHAR || meta == CLI_MATCH_NOCASE {
                if run_start.is_none() {
                    run_start = Some(i);
                    run_bytes.clear();
                }
                run_bytes.push((inst & 0xff) as u8);
            } else {
                if let Some(start) = run_start.take() {
                    if run_bytes.len() >= 2 && run_bytes.len() > best_len {
                        best_len = run_bytes.len();
                        best_bytes = Some(run_bytes.clone());
                        best_prefix = start;
                    }
                }
                run_bytes.clear();
            }
        }
        // Flush final run
        if let Some(start) = run_start {
            if run_bytes.len() >= 2 && run_bytes.len() > best_len {
                best_bytes = Some(run_bytes);
                best_prefix = start + pat.prefix.len();
            }
        }

        best_bytes.map(|bytes| (bytes, best_prefix))
    }
}

// ── fmt::Debug impls ───────────────────────────────────────────────────────

impl fmt::Debug for AcPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcPattern")
            .field("length", &self.length)
            .field("prefix_length", &self.prefix_length)
            .field("sigid", &self.sigid)
            .field("parts", &self.parts)
            .field("partno", &self.partno)
            .field("sigopts", &self.sigopts)
            .field("virname", &self.virname)
            .field("boundary", &self.boundary)
            .finish()
    }
}

#[cfg(test)]
mod smoke_tests {
    use super::*;

    fn build(sigs: &[(&str, u32)]) -> AcMatcher {
        let mut m = AcMatcher::new(2, 3);
        for (hex, id) in sigs {
            m.add_sig(hex, 0, *id, 0, 0, 0, 0, 0, 0).unwrap();
        }
        m.build_trie_from_patterns();
        m
    }

    #[test]
    fn smoke_plain_match() {
        let m = build(&[("4d5a", 1)]);
        let hits = m.scan(b"xxMZyy", 0);
        assert!(hits.iter().any(|&(p, _, _)| m.patterns[p].sigid == 1), "MZ not found: {hits:?}");
    }

    #[test]
    fn smoke_no_false_match() {
        let m = build(&[("4d5a", 1)]);
        assert!(m.scan(b"xxxxxx", 0).is_empty());
    }

    #[test]
    fn smoke_alternation_match() {
        // Needs a fixed run >= mindepth (here "AB") so it can be trie-anchored,
        // like real signatures (a lone `41(2e|2f)42` has no 2-byte anchor).
        let m = build(&[("4142(2e|2f)4344", 7)]);
        assert!(!m.scan(b"xxAB.CDyy", 0).is_empty(), "alternation . missed");
        assert!(!m.scan(b"xxAB/CDyy", 0).is_empty(), "alternation / missed");
        assert!(m.scan(b"xxAB,CDyy", 0).is_empty(), "alternation false match");
    }

    #[test]
    fn smoke_alternation_in_prefix() {
        // Alternation BEFORE the long anchor run → lands in the prefix, exercising
        // the backward (prefix-window) path. Anchor = "CDEF".
        let m = build(&[("(2e|2f)43444546", 8)]);
        assert!(!m.scan(b"xx.CDEFyy", 0).is_empty(), "prefix-alternation . missed");
        assert!(m.scan(b"xx,CDEFyy", 0).is_empty(), "prefix-alternation false match");
    }
}
