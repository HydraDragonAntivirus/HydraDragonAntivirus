//! JavaScript normalizer, a port of libclamav `jsparse/js-norm.c` (plus the
//! `cli_unescape` / `cli_textbuffer_append_normalize` helpers of `str.c`).
//!
//! ClamAV's HTML/JS signatures are written against this output, not the raw
//! script: tokens joined with the minimum of spaces, everything lower case,
//! string escapes (`\x41`, `A`) resolved, `"a" + "b"` folded,
//! `unescape("%u..")` evaluated, `eval("...")`, Dean Edwards' packer and the
//! scriptasylum `dF()` encoder unpacked, and declared identifiers renamed to
//! `n000`, `n001`, ... Behaviour (including ClamAV's quirks) is kept as is, so
//! the same signatures match.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    FutureReserved,
    Ident,
    True,
    False,
    Null,
    BracketOpen,
    BracketClose,
    Comma,
    CurlyOpen,
    CurlyClose,
    ParOpen,
    ParClose,
    Dot,
    Semicolon,
    NumInt,
    NumFloat,
    Str,
    /// Keywords and operators with no role in the parser (output by name).
    Other,
    Plus,
    Var,
    Function,
    /// Member name after `.`: never renamed.
    Unnorm,
}

#[derive(Debug, Clone)]
enum Val {
    None,
    /// Identifier names, keywords, operators.
    CStr(Vec<u8>),
    /// String literals and member names (owned "string" in ClamAV).
    Str(Vec<u8>),
    /// FUNCTION token: the scope it opens, or None for the dummy end marker.
    Scope(Option<usize>),
    Int(i64),
    Float(f64),
}

#[derive(Debug, Clone)]
struct Token {
    kind: Tok,
    val: Val,
}

impl Token {
    fn cstring(&self) -> Option<&[u8]> {
        match &self.val {
            Val::CStr(s) | Val::Str(s) => Some(s),
            _ => None,
        }
    }
    fn string(&self) -> Option<&[u8]> {
        match &self.val {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
    fn ival(&self) -> i64 {
        match self.val {
            Val::Int(v) => v,
            _ => -1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fsm {
    Base,
    InsideVar,
    InsideInitializer,
    WaitFunctionName,
    WaitParameterList,
    InsideFunctionDecl,
}

#[derive(Debug)]
struct Scope {
    /// Identifier -> unique id (-1: used, not declared here).
    ids: HashMap<Vec<u8>, i64>,
    parent: Option<usize>,
    fsm: Fsm,
    last_token: Option<Tok>,
    brackets: u32,
    blocks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexState {
    Initial,
    MultilineComment,
    SinglelineComment,
    Number,
    DoubleQString,
    SingleQString,
    Identifier,
}

#[derive(Debug)]
struct Lexer {
    buf: Vec<u8>,
    state: LexState,
    pos: usize,
    lastpos: usize,
    last_state: Option<LexState>,
}

/// One script being normalized (ClamAV `parser_state`).
pub struct JsNormalizer {
    var_uniq: i64,
    scopes: Vec<Scope>,
    current: usize,
    lexer: Lexer,
    tokens: Vec<Token>,
    rec: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Ws,
    Slash,
    Op,
    Dq,
    Sq,
    Digit,
    Id,
    Special(Tok, u8),
    Nop,
}

fn ctype(c: u8) -> Class {
    match c {
        9..=11 | 13 | b' ' => Class::Ws,
        b'/' => Class::Slash,
        b'"' => Class::Dq,
        b'\'' => Class::Sq,
        b'0'..=b'9' => Class::Digit,
        b'$' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'\\' => Class::Id,
        b'[' => Class::Special(Tok::BracketOpen, b'['),
        b']' => Class::Special(Tok::BracketClose, b']'),
        b',' => Class::Special(Tok::Comma, b','),
        b'{' => Class::Special(Tok::CurlyOpen, b'{'),
        b'}' => Class::Special(Tok::CurlyClose, b'}'),
        b'(' => Class::Special(Tok::ParOpen, b'('),
        b')' => Class::Special(Tok::ParClose, b')'),
        b'.' => Class::Special(Tok::Dot, b'.'),
        b';' => Class::Special(Tok::Semicolon, b';'),
        b'!' | b'%' | b'&' | b'*' | b'+' | b'-' | b':' | b'<' | b'=' | b'>' | b'?' | b'^' | b'|' | b'~' => Class::Op,
        _ => Class::Nop,
    }
}

/// `id_ctype`: identifier characters after the first (`\` is "operator").
fn id_class(c: u8) -> Class {
    match c {
        b'$' | b'0'..=b'9' | b'A'..=b'Z' | b'_' | b'a'..=b'z' => Class::Id,
        b'\\' => Class::Op,
        _ => Class::Nop,
    }
}

fn keyword(word: &[u8]) -> Option<Tok> {
    Some(match word {
        b"var" => Tok::Var,
        b"function" => Tok::Function,
        b"true" => Tok::True,
        b"false" => Tok::False,
        b"null" => Tok::Null,
        b"break" | b"case" | b"catch" | b"continue" | b"default" | b"delete" | b"do" | b"else" | b"finally"
        | b"for" | b"if" | b"in" | b"instanceof" | b"new" | b"return" | b"switch" | b"this" | b"throw" | b"try"
        | b"typeof" | b"void" | b"while" | b"with" => Tok::Other,
        b"abstract" | b"boolean" | b"byte" | b"char" | b"class" | b"const" | b"debugger" | b"double" | b"enum"
        | b"export" | b"extends" | b"final" | b"float" | b"goto" | b"implements" | b"import" | b"int"
        | b"interface" | b"long" | b"native" | b"package" | b"private" | b"protected" | b"public" | b"short"
        | b"static" | b"super" | b"synchronized" | b"throws" | b"transient" | b"volatile" => Tok::FutureReserved,
        _ => return None,
    })
}

/// `operators.gperf`, longest match first.
const OPERATORS: &[&[u8]] = &[
    b">>>=", b"===", b">>>", b"!==", b"<<=", b">>=", b"<<", b"<=", b"==", b">=", b">>", b"||", b"--", b"!=", b"&&",
    b"++", b"*=", b"/=", b"%=", b"+=", b"-=", b"&=", b"^=", b"|=", b"=", b"+", b"&", b":", b"/", b"!", b">", b"<",
    b"-", b"*", b"|", b"%", b"?", b"~", b"^",
];

fn hex2int(c: u8) -> i32 {
    match c {
        b'0'..=b'9' => (c - b'0') as i32,
        b'a'..=b'f' => (c - b'a' + 10) as i32,
        b'A'..=b'F' => (c - b'A' + 10) as i32,
        _ => -1,
    }
}

/// ClamAV `output_utf8`: UTF-16 unit as UTF-8, `\0` written as `\1`.
fn output_utf8(u: u16, out: &mut Vec<u8>) {
    if u == 0 {
        out.push(1);
    } else if u < 0x80 {
        out.push(u as u8);
    } else if u < 0x800 {
        out.push(0xc0 | (u >> 6) as u8);
        out.push(0x80 | (u & 0x3f) as u8);
    } else {
        out.push(0xe0 | (u >> 12) as u8);
        out.push(0x80 | ((u >> 6) & 0x3f) as u8);
        out.push(0x80 | (u & 0x3f) as u8);
    }
}

fn hex_pair(a: u8, b: u8) -> u8 {
    ((hex2int(a).max(0) << 4) | hex2int(b)) as u8
}

fn hex_quad(s: &[u8]) -> u16 {
    ((hex2int(s[0]).max(0) << 12) | (hex2int(s[1]).max(0) << 8) | (hex2int(s[2]).max(0) << 4) | hex2int(s[3])) as u16
}

/// ClamAV `cli_unescape`: JavaScript `unescape()` (`%uXXXX`, `%XX`).
pub fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let len = s.len();
    let mut k = 0;
    while k < len {
        let mut c = s[k];
        if s[k] == b'%' {
            let is_u = k + 5 < len
                && s[k + 1] == b'u'
                && s[k + 2].is_ascii_hexdigit()
                && s[k + 3].is_ascii_hexdigit()
                && s[k + 4].is_ascii_hexdigit()
                && s[k + 5].is_ascii_hexdigit();
            if is_u {
                output_utf8(hex_quad(&s[k + 2..k + 6]), &mut out);
                k += 6;
                continue;
            }
            if k + 2 < len && s[k + 1].is_ascii_hexdigit() && s[k + 2].is_ascii_hexdigit() {
                c = hex_pair(s[k + 1], s[k + 2]);
                k += 2;
            }
        }
        out.push(if c == 0 { 1 } else { c });
        k += 1;
    }
    out
}

/// ClamAV `cli_textbuffer_append_normalize`: string escapes inside a literal.
fn append_normalize(buf: &mut Vec<u8>, s: &[u8]) {
    let len = s.len();
    let mut i = 0;
    while i < len {
        let mut c = s[i];
        if c == b'\\' && i + 1 < len {
            i += 1;
            match s[i] {
                b'0' => c = 0,
                b'b' => c = 8,
                b't' => c = 9,
                b'n' => c = 10,
                b'v' => c = 11,
                b'f' => c = 12,
                b'r' => c = 13,
                b'x' => {
                    if i + 2 < len {
                        c = hex_pair(s[i + 1], s[i + 2]);
                    }
                    i += 2;
                }
                b'u' => {
                    if i + 4 < len {
                        output_utf8(hex_quad(&s[i + 1..i + 5]), buf);
                        i += 5;
                        continue;
                    }
                }
                other => c = other,
            }
        }
        buf.push(if c == 0 { 1 } else { c });
        i += 1;
    }
}

/// C `%g`.
fn fmt_g(v: f64) -> String {
    if v == 0.0 {
        return if v.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    if !v.is_finite() {
        return if v.is_nan() { "nan".into() } else if v > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let exp = v.abs().log10().floor() as i32;
    let trim = |s: String| -> String {
        if s.contains('.') { s.trim_end_matches('0').trim_end_matches('.').to_string() } else { s }
    };
    // %e precision 5 rounds; re-derive the exponent from it.
    let e_form = format!("{:.5e}", v);
    let (mant, e) = e_form.split_once('e').unwrap_or((&e_form, "0"));
    let e: i32 = e.parse().unwrap_or(exp);
    if e < -4 || e >= 6 {
        let mant = trim(mant.to_string());
        format!("{mant}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs())
    } else {
        let prec = (5 - e).max(0) as usize;
        trim(format!("{:.*}", prec, v))
    }
}

/// C `atoi`: strtol clamped to `long`, then cut to `int`.
fn atoi(s: &[u8]) -> i64 {
    let digits = std::str::from_utf8(s).unwrap_or("0");
    let v: i128 = digits.parse().unwrap_or(i128::MAX);
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64 as i32 as i64
}

impl Default for JsNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl JsNormalizer {
    pub fn new() -> Self {
        JsNormalizer {
            var_uniq: 0,
            scopes: vec![Scope { ids: HashMap::new(), parent: None, fsm: Fsm::Base, last_token: None, brackets: 0, blocks: 0 }],
            current: 0,
            lexer: Lexer { buf: Vec::new(), state: LexState::Initial, pos: 0, lastpos: usize::MAX, last_state: None },
            tokens: Vec::new(),
            rec: 0,
        }
    }

    fn scope_new(&mut self) -> usize {
        self.scopes.push(Scope {
            ids: HashMap::new(),
            parent: Some(self.current),
            fsm: Fsm::Base,
            last_token: None,
            brackets: 0,
            blocks: 0,
        });
        self.current = self.scopes.len() - 1;
        self.current
    }

    fn scope_lookup(&self, mut s: usize, name: &[u8]) -> Option<i64> {
        loop {
            if let Some(&id) = self.scopes[s].ids.get(name) {
                if id != -1 {
                    return Some(id);
                }
            }
            s = self.scopes[s].parent?;
        }
    }

    /// Feeds script text (ClamAV `cli_js_process_buffer`).
    pub fn process(&mut self, input: &[u8]) {
        let mut current = self.current;
        self.lexer.pos = 0;
        self.lexer.lastpos = usize::MAX;
        self.lexer.last_state = None;
        while let Some((kind, mut val)) = self.lex(input) {
            let mut kind = kind;
            match kind {
                Tok::Var => self.scopes[current].fsm = Fsm::InsideVar,
                Tok::Ident => {
                    let text = match &val {
                        Val::CStr(t) => t.clone(),
                        _ => Vec::new(),
                    };
                    if self.scopes[current].last_token == Some(Tok::Dot) {
                        val = Val::Str(text);
                        kind = Tok::Unnorm;
                    } else {
                        match self.scopes[current].fsm {
                            Fsm::WaitParameterList | Fsm::Base | Fsm::InsideInitializer => {
                                self.scopes[current].ids.entry(text.clone()).or_insert(-1);
                            }
                            Fsm::InsideVar | Fsm::InsideFunctionDecl => {
                                let id = self.var_uniq;
                                self.var_uniq += 1;
                                self.scopes[current].ids.insert(text.clone(), id);
                                self.scopes[current].fsm = Fsm::InsideInitializer;
                                self.scopes[current].brackets = 0;
                            }
                            Fsm::WaitFunctionName => {
                                let id = self.var_uniq;
                                self.var_uniq += 1;
                                self.scopes[current].ids.insert(text.clone(), id);
                                self.scopes[current].fsm = Fsm::WaitParameterList;
                            }
                        }
                        val = Val::CStr(text);
                    }
                }
                Tok::ParOpen => {
                    if matches!(self.scopes[current].fsm, Fsm::WaitFunctionName | Fsm::WaitParameterList) {
                        self.scopes[current].fsm = Fsm::InsideFunctionDecl;
                    }
                }
                Tok::ParClose => {
                    if self.scopes[current].fsm == Fsm::WaitParameterList {
                        self.scopes[current].fsm = Fsm::Base;
                    }
                }
                Tok::CurlyOpen => {
                    if matches!(self.scopes[current].fsm, Fsm::WaitFunctionName | Fsm::WaitParameterList | Fsm::InsideFunctionDecl) {
                        self.scopes[current].fsm = Fsm::Base;
                    }
                    self.scopes[current].blocks += 1;
                }
                Tok::CurlyClose => {
                    let s = &mut self.scopes[current];
                    if s.blocks > 0 {
                        s.blocks -= 1;
                    }
                    if s.blocks == 0 {
                        if let Some(parent) = s.parent {
                            // `}` then a dummy FUNCTION token marking the function end.
                            self.tokens.push(Token { kind: Tok::CurlyClose, val: Val::CStr(b"}".to_vec()) });
                            kind = Tok::Function;
                            val = Val::Scope(None);
                            self.current = parent;
                            current = parent;
                        }
                    }
                }
                Tok::BracketOpen => self.scopes[current].brackets += 1,
                Tok::BracketClose => {
                    let s = &mut self.scopes[current];
                    s.brackets = s.brackets.saturating_sub(1);
                }
                Tok::Comma => {
                    let s = &mut self.scopes[current];
                    if s.fsm == Fsm::InsideInitializer && s.brackets == 0 && s.blocks == 0 {
                        s.fsm = Fsm::InsideVar;
                    }
                }
                Tok::Semicolon => {
                    let s = &mut self.scopes[current];
                    if s.brackets == 0 && s.blocks == 0 {
                        s.fsm = Fsm::Base;
                    }
                }
                Tok::Function => {
                    current = self.scope_new();
                    self.scopes[current].fsm = Fsm::WaitFunctionName;
                    val = Val::Scope(Some(current));
                }
                Tok::Str => {
                    // Fold "a" + "b".
                    let n = self.tokens.len();
                    if n > 1 && self.tokens[n - 1].kind == Tok::Plus && self.tokens[n - 2].kind == Tok::Str {
                        self.tokens.pop();
                        let add = match &val {
                            Val::Str(s) => s.clone(),
                            _ => Vec::new(),
                        };
                        if let Val::Str(prev) = &mut self.tokens[n - 2].val {
                            prev.extend_from_slice(&add);
                        }
                        continue;
                    }
                }
                _ => {}
            }
            self.tokens.push(Token { kind, val });
            // ClamAV records the token type read, before any rewrite.
            let read = if kind == Tok::Function && matches!(self.tokens.last().map(|t| &t.val), Some(Val::Scope(None))) {
                Tok::CurlyClose
            } else if kind == Tok::Unnorm {
                Tok::Ident
            } else {
                kind
            };
            self.scopes[current].last_token = Some(read);
        }
    }

    /// One token from `input` (continuing an unfinished one), or None at the end
    /// of the input (ClamAV `yylex`).
    fn lex(&mut self, input: &[u8]) -> Option<(Tok, Val)> {
        let lx = &mut self.lexer;
        if lx.pos == lx.lastpos && lx.last_state == Some(lx.state) {
            lx.pos += 1; // infloop guard
        }
        lx.lastpos = lx.pos;
        lx.last_state = Some(lx.state);
        while lx.pos < input.len() {
            match lx.state {
                LexState::Initial => {
                    lx.buf.clear();
                    let c = input[lx.pos];
                    lx.pos += 1;
                    match ctype(c) {
                        Class::Ws | Class::Nop => continue,
                        Class::Slash => {
                            match input.get(lx.pos) {
                                Some(b'*') => {
                                    lx.state = LexState::MultilineComment;
                                    lx.pos += 1;
                                    continue;
                                }
                                Some(b'/') => {
                                    lx.state = LexState::SinglelineComment;
                                    lx.pos += 1;
                                    continue;
                                }
                                _ => {}
                            }
                            lx.pos -= 1;
                            return Some(Self::operator(lx, input));
                        }
                        Class::Op => {
                            lx.pos -= 1;
                            return Some(Self::operator(lx, input));
                        }
                        Class::Dq => {
                            if let Some(t) = Self::string(lx, input, b'"', LexState::DoubleQString) {
                                return Some(t);
                            }
                        }
                        Class::Sq => {
                            if let Some(t) = Self::string(lx, input, b'\'', LexState::SingleQString) {
                                return Some(t);
                            }
                        }
                        Class::Digit => {
                            lx.pos -= 1;
                            if let Some(t) = Self::number(lx, input) {
                                return Some(t);
                            }
                        }
                        Class::Id => {
                            lx.pos -= 1;
                            if let Some(t) = Self::ident(lx, input) {
                                return Some(t);
                            }
                        }
                        Class::Special(t, ch) => return Some((t, Val::CStr(vec![ch]))),
                    }
                }
                LexState::DoubleQString => {
                    if let Some(t) = Self::string(lx, input, b'"', LexState::DoubleQString) {
                        return Some(t);
                    }
                }
                LexState::SingleQString => {
                    if let Some(t) = Self::string(lx, input, b'\'', LexState::SingleQString) {
                        return Some(t);
                    }
                }
                LexState::Identifier => {
                    if let Some(t) = Self::ident(lx, input) {
                        return Some(t);
                    }
                }
                LexState::Number => {
                    if let Some(t) = Self::number(lx, input) {
                        return Some(t);
                    }
                }
                LexState::MultilineComment => {
                    while lx.pos + 1 < input.len() {
                        if input[lx.pos] == b'*' && input[lx.pos + 1] == b'/' {
                            lx.state = LexState::Initial;
                            lx.pos += 1;
                            break;
                        }
                        lx.pos += 1;
                    }
                    lx.pos += 1;
                }
                LexState::SinglelineComment => {
                    // htmlnorm turns newlines into spaces: a space ends it too.
                    while lx.pos < input.len() && input[lx.pos] != b'\n' && input[lx.pos] != b' ' {
                        lx.pos += 1;
                    }
                    lx.state = LexState::Initial;
                }
            }
        }
        None
    }

    fn operator(lx: &mut Lexer, input: &[u8]) -> (Tok, Val) {
        let rest = &input[lx.pos..];
        for op in OPERATORS {
            if rest.starts_with(op) {
                lx.pos += op.len();
                let kind = if *op == b"+" { Tok::Plus } else { Tok::Other };
                return (kind, Val::CStr(op.to_vec()));
            }
        }
        lx.pos += 1;
        (Tok::Other, Val::None)
    }

    fn string(lx: &mut Lexer, input: &[u8], q: u8, unfinished: LexState) -> Option<(Tok, Val)> {
        let start = lx.pos;
        let mut from = start;
        let end = loop {
            match input[from..].iter().position(|&c| c == q).map(|p| p + from) {
                Some(e) if e > start && input[e - 1] == b'\\' => from = e + 1,
                other => break other,
            }
        };
        let len = end.map_or(input.len() - start, |e| e - start);
        append_normalize(&mut lx.buf, &input[start..start + len]);
        if end.is_some() {
            lx.pos += len + 1;
            lx.state = LexState::Initial;
            Some((Tok::Str, Val::Str(std::mem::take(&mut lx.buf))))
        } else {
            lx.pos += len;
            lx.state = unfinished;
            None
        }
    }

    fn number(lx: &mut Lexer, input: &[u8]) -> Option<(Tok, Val)> {
        let mut is_float = lx.buf.contains(&b'.');
        while lx.pos < input.len() {
            let c = input[lx.pos];
            lx.pos += 1;
            if c.is_ascii_digit() {
                lx.buf.push(c);
                continue;
            }
            if c == b'.' && !is_float {
                is_float = true;
                lx.buf.push(b'.');
                continue;
            }
            if (c == b'e' || c == b'E') && is_float {
                lx.buf.push(c);
                if lx.pos < input.len() {
                    let d = input[lx.pos];
                    lx.pos += 1;
                    if d == b'+' || d == b'-' || d.is_ascii_digit() {
                        lx.buf.push(d);
                        continue;
                    }
                }
            }
            lx.pos -= 1;
            lx.state = LexState::Initial;
            let text = std::mem::take(&mut lx.buf);
            return Some(if is_float {
                // atof: the longest valid prefix.
                let s = String::from_utf8_lossy(&text).into_owned();
                let v = (1..=s.len()).rev().find_map(|n| s[..n].parse::<f64>().ok()).unwrap_or(0.0);
                (Tok::NumFloat, Val::Float(v))
            } else {
                (Tok::NumInt, Val::Int(atoi(&text)))
            });
        }
        lx.state = LexState::Number;
        None
    }

    fn ident(lx: &mut Lexer, input: &[u8]) -> Option<(Tok, Val)> {
        lx.state = LexState::Initial;
        while lx.pos < input.len() {
            let c = input[lx.pos];
            lx.pos += 1;
            match id_class(c) {
                Class::Id => lx.buf.push(c),
                Class::Op if lx.pos < input.len() && {
                    let next = input[lx.pos];
                    lx.pos += 1;
                    next == b'u'
                } =>
                {
                    lx.buf.push(c);
                }
                class => {
                    if class == Class::Op && lx.pos == input.len() {
                        lx.pos += 1;
                    }
                    lx.pos -= 1;
                    let word = std::mem::take(&mut lx.buf);
                    if let Some(kw) = keyword(&word) {
                        return Some((kw, Val::CStr(word)));
                    }
                    return Some((Tok::Ident, Val::CStr(word)));
                }
            }
        }
        lx.state = LexState::Identifier;
        None
    }

    /// End of the script (ClamAV `cli_js_parse_done`): closes an unfinished
    /// string and parentheses, then runs the folders and decoders.
    pub fn finish(&mut self) {
        let end = match self.lexer.state {
            LexState::DoubleQString => Some(b'"'),
            LexState::SingleQString => Some(b'\''),
            _ => None,
        };
        if let Some(q) = end {
            self.process(&[q]);
        }
        let mut balance = 0usize;
        for t in &self.tokens {
            match t.kind {
                Tok::ParOpen => balance += 1,
                Tok::ParClose if balance > 0 => balance -= 1,
                _ => {}
            }
        }
        for _ in 0..balance {
            self.tokens.push(Token { kind: Tok::ParClose, val: Val::CStr(b")".to_vec()) });
        }
        self.run_folders();
        self.run_decoders();
    }

    /// `unescape("...")` -> the unescaped string.
    fn run_folders(&mut self) {
        let mut i = 0;
        while i < self.tokens.len() {
            let t = &self.tokens[i];
            if i + 2 < self.tokens.len()
                && t.kind == Tok::Ident
                && t.cstring() == Some(b"unescape")
                && self.tokens[i + 1].kind == Tok::ParOpen
                && self.tokens[i + 2].kind == Tok::Str
                && i + 4 <= self.tokens.len()
            {
                let s = unescape(self.tokens[i + 2].cstring().unwrap_or_default());
                self.tokens.splice(i..i + 4, [Token { kind: Tok::Str, val: Val::Str(s) }]);
            }
            i += 1;
        }
    }

    fn update_scope(&mut self, i: usize) -> bool {
        if let Some(Token { kind: Tok::Function, val: Val::Scope(s) }) = self.tokens.get(i) {
            match s {
                Some(s) => self.current = *s,
                None => {
                    if let Some(p) = self.scopes[self.current].parent {
                        self.current = p;
                    }
                    return false;
                }
            }
        }
        true
    }

    /// Packer, `dF()` and `eval("...")`: the decoded code replaces the call.
    fn run_decoders(&mut self) {
        let mut i = 0;
        while i < self.tokens.len() {
            let cnt = self.tokens.len();
            let mut res: Option<(Vec<u8>, usize, usize, bool)> = None; // text, begin, end, append
            if self.tokens[i].kind == Tok::Function && i + 13 < cnt {
                let mut name: Option<Vec<u8>> = None;
                i += 1;
                if self.tokens[i].kind == Tok::Ident {
                    name = self.tokens[i].cstring().map(<[u8]>::to_vec);
                    i += 1;
                }
                if match_parameters(&self.tokens[i..], &[b"p", b"a", b"c", b"k", b"e", b"r"])
                    || match_parameters(&self.tokens[i..], &[b"p", b"a", b"c", b"k", b"e", b"d"])
                {
                    res = handle_de(&self.tokens, i, name.as_deref());
                }
            } else if i + 2 < cnt && self.tokens[i].kind == Tok::Ident && self.tokens[i + 1].kind == Tok::ParOpen {
                match self.tokens[i].cstring() {
                    Some(b"dF") => res = handle_df(&self.tokens, i + 2),
                    Some(b"eval") => {
                        let start = i + 2;
                        if start + 1 < cnt && self.tokens[start].string().is_some() && self.tokens[start + 1].kind == Tok::ParClose {
                            if let Val::Str(s) = std::mem::replace(&mut self.tokens[start].val, Val::None) {
                                res = Some((s, start - 2, start + 2, false));
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some((text, begin, mut end, append)) = res.filter(|r| r.2 > r.1) {
                if end < self.tokens.len() && self.tokens[end].kind == Tok::Semicolon {
                    end += 1;
                }
                let end = end.min(self.tokens.len());
                let parent = std::mem::take(&mut self.tokens);
                self.rec += 1;
                if self.rec <= 16 {
                    self.process(&text);
                }
                self.rec -= 1;
                let nested = std::mem::replace(&mut self.tokens, parent);
                if begin < end {
                    if append {
                        self.tokens.drain(begin..end);
                        self.tokens.extend(nested);
                    } else {
                        self.tokens.splice(begin..end, nested);
                    }
                }
            }
            if i < self.tokens.len() {
                self.update_scope(i);
            }
            i += 1;
        }
    }

    /// The normalized script: `<script>...</script>`, lower case (ClamAV
    /// `cli_js_output`).
    pub fn output(&mut self, out: &mut Vec<u8>) {
        if !out.is_empty() {
            out.push(b'\n');
        }
        let start = out.len();
        outs(out, b"<script>");
        self.current = 0;
        let mut last: u8 = 0;
        for i in 0..self.tokens.len() {
            if self.update_scope(i) {
                last = self.output_token(i, out, last);
            }
        }
        if !out[start..].ends_with(b"</script>") {
            outs(out, b"</script>");
        }
    }

    fn output_token(&self, i: usize, out: &mut Vec<u8>, last: u8) -> u8 {
        let t = &self.tokens[i];
        let space = |out: &mut Vec<u8>, cur: u8| {
            if last.is_ascii_alphanumeric() && cur.is_ascii_alphanumeric() {
                out.push(b' ');
            }
        };
        match t.kind {
            Tok::Str => {
                space(out, b'"');
                out.push(b'"');
                if let Some(s) = t.cstring() {
                    outs(out, s);
                }
                out.push(b'"');
                b'"'
            }
            Tok::NumInt => {
                space(out, b'0');
                outs(out, t.ival().to_string().as_bytes());
                b'0'
            }
            Tok::NumFloat => {
                space(out, b'0');
                if let Val::Float(v) = t.val {
                    outs(out, fmt_g(v).as_bytes());
                }
                b'0'
            }
            Tok::Ident => {
                space(out, b'a');
                if let Some(s) = t.cstring() {
                    match self.scope_lookup(self.current, s) {
                        Some(id) => outs(out, format!("n{id:03}").as_bytes()),
                        None => outs(out, s),
                    }
                }
                b'a'
            }
            Tok::Function => {
                space(out, b'a');
                outs(out, b"function");
                b'a'
            }
            _ => match t.cstring() {
                Some(s) if !s.is_empty() => {
                    space(out, s[0]);
                    outs(out, s);
                    s[s.len() - 1]
                }
                _ => 0,
            },
        }
    }
}

/// ClamAV `buf_outs`: lower case, whitespace as a space.
fn outs(out: &mut Vec<u8>, s: &[u8]) {
    out.extend(s.iter().map(|&c| if matches!(c, b' ' | 9..=13) { b' ' } else { c.to_ascii_lowercase() }));
}

/// ClamAV `match_parameters`, including its loop that checks only the first
/// half of the names (`(p,a,c,` for the packer).
fn match_parameters(tokens: &[Token], names: &[&[u8]]) -> bool {
    if tokens.first().map(|t| t.kind) != Some(Tok::ParOpen) {
        return false;
    }
    let (mut ti, mut ni, mut remaining) = (1usize, 0usize, names.len());
    while ni < remaining {
        remaining -= 1;
        let Some(t) = tokens.get(ti) else { return false };
        if t.kind != Tok::Ident || t.cstring() != Some(names[ni]) {
            return false;
        }
        ti += 1;
        ni += 1;
        let Some(next) = tokens.get(ti) else { return false };
        if (remaining > 0 && next.kind != Tok::Comma) || (remaining == 0 && next.kind != Tok::ParClose) {
            return false;
        }
        ti += 1;
    }
    true
}

/// Dean Edwards' packer (`eval(function(p,a,c,k,e,r){...}('...',62,..,'a|b'.split('|'),0,{}))`).
fn handle_de(tokens: &[Token], start: usize, name: Option<&[u8]>) -> Option<(Vec<u8>, usize, usize, bool)> {
    let cnt = tokens.len();
    let mut nesting = 1i64;
    let mut i = start;
    while i < cnt {
        if let Token { kind: Tok::Function, val: Val::Scope(s) } = &tokens[i] {
            if s.is_some() {
                nesting += 1;
            } else {
                nesting -= 1;
            }
            if nesting == 0 {
                break;
            }
        }
        i += 1;
    }
    if nesting != 0 {
        return None;
    }
    let mut text = Vec::new();
    let (mut first, mut last) = (None, None);
    let mut collect = |i: &mut usize, text: &mut Vec<u8>| {
        let mut params: Vec<usize> = Vec::with_capacity(6);
        for j in 0..6 {
            if *i >= cnt {
                break;
            }
            params.push(*i);
            *i += 1;
            let stop = if j != 5 { Tok::Comma } else { Tok::ParClose };
            while *i < cnt && tokens[*i].kind != stop {
                *i += 1;
            }
            *i += 1;
        }
        if params.len() == 6 {
            first.get_or_insert(params[0]);
            last = Some(params[5]);
            decode_de(tokens, &params, text);
        }
    };
    match name {
        Some(name) => {
            while i + 2 < cnt {
                if tokens[i].kind == Tok::Ident && tokens[i].cstring() == Some(name) && tokens[i + 1].kind == Tok::ParOpen {
                    i += 2;
                    collect(&mut i, &mut text);
                }
                i += 1;
            }
        }
        None => {
            while i < cnt && tokens[i].kind != Tok::ParOpen {
                i += 1;
            }
            i += 1;
            if i >= cnt {
                return None;
            }
            collect(&mut i, &mut text);
        }
    }
    let (first, last) = (first?, last?);
    let mut end = last + 1;
    if end + 2 < cnt
        && tokens[end].kind == Tok::BracketOpen
        && tokens[end + 1].kind == Tok::BracketClose
        && tokens[end + 2].kind == Tok::ParClose
    {
        end += 3;
    } else if end < cnt {
        end += 1;
    }
    Some((text, first, end, false))
}

/// ClamAV `decode_de`: replaces each base-`a` word of `p` with its entry in `k`.
fn decode_de(tokens: &[Token], params: &[usize], out: &mut Vec<u8>) {
    let (Some(p), Some(k)) = (tokens[params[0]].cstring(), tokens[params[3]].string()) else { return };
    let a = tokens[params[1]].ival();
    let words: Vec<&[u8]> = k.split(|&c| c == b'|').collect();
    let mut i = 0;
    loop {
        while i < p.len() && !p[i].is_ascii_alphanumeric() {
            if p[i] == b'\\' && matches!(p.get(i + 1), Some(b'\'') | Some(b'"')) {
                i += 1;
            } else {
                out.push(p[i]);
                i += 1;
            }
        }
        if i >= p.len() {
            break;
        }
        let o = i;
        let mut val: u64 = 0;
        while i < p.len() && p[i].is_ascii_alphanumeric() {
            let v = p[i];
            i += 1;
            let x = if v >= b'a' {
                10 + (v - b'a') as u64
            } else if v >= b'A' {
                36 + (v - b'A') as u64
            } else {
                (v - b'0') as u64
            };
            val = (val.wrapping_mul(a as u64).wrapping_add(x)) & 0xffff_ffff;
        }
        match words.get(val as usize) {
            Some(w) if !w.is_empty() => out.extend_from_slice(w),
            _ => out.extend_from_slice(&p[o..i]),
        }
        if i >= p.len() {
            break;
        }
    }
}

/// scriptasylum's `dF("...N")` encoder.
fn handle_df(tokens: &[Token], start: usize) -> Option<(Vec<u8>, usize, usize, bool)> {
    let t = tokens.get(start)?;
    if t.kind != Tok::Str {
        return None;
    }
    let s = t.string()?;
    let (&last, body) = s.split_last()?;
    let clast = last.wrapping_sub(b'0');
    let s1: Vec<u8> = unescape(body).into_iter().map(|c| c.wrapping_sub(clast)).collect();
    Some((unescape(&s1), start - 2, start + 2, true))
}

/// Normalizes one script.
pub fn normalize(code: &[u8]) -> Vec<u8> {
    let mut n = JsNormalizer::new();
    n.process(code);
    n.finish();
    let mut out = Vec::new();
    n.output(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> String {
        String::from_utf8_lossy(&normalize(s.as_bytes())).into_owned()
    }

    #[test]
    fn identifiers_renamed_strings_folded_lowercase() {
        assert_eq!(norm("var Foo = 'A' + \"b\"; Foo.Bar(Foo);"), "<script>var n000=\"ab\";n000.bar(n000);</script>");
        assert_eq!(norm("function F(x){ return x+1 }"), "<script>function n000(n001){return n001+1}</script>");
        assert_eq!(norm("document.write(unknown)"), "<script>document.write(unknown)</script>");
    }

    #[test]
    fn escapes_and_unescape() {
        assert_eq!(norm(r#"x = "\x41B\n";"#), "<script>x=\"ab \";</script>");
        assert_eq!(norm("unescape('%u4141%41%42')"), "<script>\"\u{4141}ab\"</script>".to_lowercase());
    }

    #[test]
    fn eval_string_is_unpacked() {
        assert_eq!(norm("eval('var A=1;');"), "<script>var n000=1;</script>");
    }

    #[test]
    fn comments_numbers_unfinished() {
        // ClamAV quirks: htmlnorm turns newlines into spaces, so `//` ends at a
        // space; an identifier still open at the end of the input is dropped
        // (inside HTML the script always ends with `</script>`).
        assert_eq!(norm("/* c */ a = 1.50; // x\n b"), "<script>a=1.5;x</script>");
        assert_eq!(norm("/* c */ a = 1.50; // x\n b;"), "<script>a=1.5;x b;</script>");
        assert_eq!(norm("a=1;//comment\nb"), "<script>a=1;</script>");
        assert_eq!(norm("f(\"abc"), "<script>f(\"abc\")</script>");
        assert_eq!(fmt_g(1e21), "1e+21");
        assert_eq!(fmt_g(0.0001), "0.0001");
        assert_eq!(fmt_g(123456.0), "123456");
        assert_eq!(fmt_g(1234567.0), "1.23457e+06");
    }

    #[test]
    fn packer() {
        let packed = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('0(\\'1\\')',2,2,'alert|hello'.split('|'),0,{}))";
        let out = norm(packed);
        assert!(out.contains("alert(\"hello\")"), "{out}");
    }
}
