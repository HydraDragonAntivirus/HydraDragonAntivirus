//! Level-5 `native_signature` expressions: a parsed, typed expression tree
//! for what the rewrite-based evaluator in `engine` cannot express.
//!
//! An expression the original evaluator fully understands keeps using it, so
//! existing rules evaluate exactly as before; any other expression is parsed
//! here. On top of the original constructs (`$a`, `N of (...)`, `them`,
//! `$a at N`, `$a in (lo..hi)`, `$a at $b + N`, `@a[n] op @b[m]`, `filesize`,
//! file type words) it adds:
//!
//! * `#a` (match count), `#a in (lo..hi)` (count with start offset in the
//!   inclusive range), `!a` / `!a[i]` (length of the first / i-th match),
//!   `@a` (first offset), `@a#i` (offset of the i-th match, 1-based);
//!   `@a[n]` keeps meaning "offset + n";
//! * integer readers `uint8/16/32`, `uint16be/32be`, `int8/16/32`,
//!   `int16be/32be`, `entrypoint` (raw file offset);
//! * `+ - * / % & | ^ << >> ~` on 64-bit integers, comparisons `== != < <= > >=`;
//! * `for Q of (set) : ( body )` (bare `$ # @ !` in the body name the current
//!   atom) and `for Q i in (lo..hi) : ( body )`, `Q` = `any`, `all`, `none`,
//!   `N` or `N%`, at most [`MAX_FOR_ITERATIONS`] iterations.
//!
//! A value can be undefined (an atom that did not match, a read past the end of
//! the file, division by zero, overflow, no entry point): a comparison with it
//! is false, as in YARA. Comparisons written exactly as the original
//! evaluator's offset forms (`@a[n] op @b[m]`, `@a[n] op N`) keep its meaning:
//! they hold when any pair of occurrences satisfies them.

use std::collections::HashMap;

/// Most iterations of one `for` loop.
pub const MAX_FOR_ITERATIONS: i64 = 4096;
/// Nodes one evaluation may visit (bounds nested loops).
const MAX_EVAL_STEPS: usize = 2_000_000;
/// Parser recursion depth.
const MAX_DEPTH: usize = 64;

/// Occurrences of one atom: start offset and length (when known), sorted.
#[derive(Debug, Clone, Default)]
pub struct AtomHits {
    pub matched: bool,
    pub occurrences: Vec<(u64, Option<u64>)>,
}

impl AtomHits {
    /// Raw occurrences, but at least 1 for an atom matched outside the raw
    /// bytes (decoded strings).
    fn count(&self) -> i64 {
        if !self.matched {
            return 0;
        }
        (self.occurrences.len() as i64).max(1)
    }
}

/// What an expression is evaluated against.
pub struct Context<'a> {
    pub hits: &'a HashMap<String, AtomHits>,
    pub bytes: &'a [u8],
    pub filesize: u64,
    pub entrypoint: Option<u64>,
    /// Value of a file type word (`PE`, `ELF`, `DotNet`, ...), None when unknown.
    pub type_word: &'a dyn Fn(&str) -> Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    U8,
    U16,
    U32,
    U16Be,
    U32Be,
    I8,
    I16,
    I32,
    I16Be,
    I32Be,
}

impl Reader {
    fn from_name(n: &str) -> Option<Self> {
        Some(match n {
            "uint8" => Self::U8,
            "uint16" => Self::U16,
            "uint32" => Self::U32,
            "uint16be" => Self::U16Be,
            "uint32be" => Self::U32Be,
            "int8" => Self::I8,
            "int16" => Self::I16,
            "int32" => Self::I32,
            "int16be" => Self::I16Be,
            "int32be" => Self::I32Be,
            _ => return None,
        })
    }

    fn read(self, bytes: &[u8], off: i64) -> Option<i64> {
        let off = usize::try_from(off).ok()?;
        let take = |n: usize| bytes.get(off..off.checked_add(n)?);
        Some(match self {
            Self::U8 => i64::from(*bytes.get(off)?),
            Self::I8 => i64::from(*bytes.get(off)? as i8),
            Self::U16 => i64::from(u16::from_le_bytes(take(2)?.try_into().ok()?)),
            Self::U16Be => i64::from(u16::from_be_bytes(take(2)?.try_into().ok()?)),
            Self::I16 => i64::from(i16::from_le_bytes(take(2)?.try_into().ok()?)),
            Self::I16Be => i64::from(i16::from_be_bytes(take(2)?.try_into().ok()?)),
            Self::U32 => i64::from(u32::from_le_bytes(take(4)?.try_into().ok()?)),
            Self::U32Be => i64::from(u32::from_be_bytes(take(4)?.try_into().ok()?)),
            Self::I32 => i64::from(i32::from_le_bytes(take(4)?.try_into().ok()?)),
            Self::I32Be => i64::from(i32::from_be_bytes(take(4)?.try_into().ok()?)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quant {
    Any,
    All,
    None,
    Count(i64),
    Percent(i64),
}

impl Quant {
    fn holds(self, hits: i64, total: i64) -> bool {
        match self {
            Self::Any => hits >= 1,
            Self::All => total > 0 && hits == total,
            Self::None => hits == 0,
            Self::Count(n) => hits >= n,
            Self::Percent(p) => total > 0 && hits * 100 >= p * total,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn holds(self, l: i64, r: i64) -> bool {
        match self {
            Self::Eq => l == r,
            Self::Ne => l != r,
            Self::Lt => l < r,
            Self::Le => l <= r,
            Self::Gt => l > r,
            Self::Ge => l >= r,
        }
    }
}

/// An atom named in the expression, or the atom a `for .. of` loop is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomRef {
    Id(String),
    Current,
}

#[derive(Debug, Clone)]
pub enum Node {
    Bool(bool),
    Int(i64),
    Filesize,
    Entrypoint,
    Var(String),
    TypeWord(String),
    Read(Reader, Box<Node>),
    Matched(AtomRef),
    Count(AtomRef, Option<(Box<Node>, Box<Node>)>),
    /// `@a` / `@a[n]`: first offset + n (any occurrence in a legacy comparison).
    Offset(AtomRef, i64),
    /// `@a#i`.
    OffsetAt(AtomRef, Box<Node>),
    /// `!a` / `!a[i]`.
    Length(AtomRef, Option<Box<Node>>),
    At(AtomRef, Box<Node>),
    /// `$a at $b + n`: some occurrence of `a` is `n` bytes after one of `b`.
    AtAtom(AtomRef, AtomRef, i64),
    In(AtomRef, Box<Node>, Box<Node>),
    Of(Quant, Vec<String>),
    ForOf(Quant, Vec<String>, Box<Node>),
    ForIn(Quant, String, Box<Node>, Box<Node>, Box<Node>),
    Neg(Box<Node>),
    BitNot(Box<Node>),
    Bin(BinOp, Box<Node>, Box<Node>),
    Cmp(CmpOp, Box<Node>, Box<Node>),
    Not(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Int(i64),
    Ident(String),
    /// `$`, `#`, `@`, `!` with an optional id and `*`.
    Sigil(char, String, bool),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Colon,
    DotDot,
    Op(&'static str),
}

fn lex(input: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let id_char = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        let two: String = c[i..c.len().min(i + 2)].iter().collect();
        if let Some(op) = ["==", "!=", "<=", ">=", "<<", ">>"].into_iter().find(|o| *o == two) {
            out.push(Tok::Op(op));
            i += 2;
            continue;
        }
        if two == ".." {
            out.push(Tok::DotDot);
            i += 2;
            continue;
        }
        match ch {
            '(' => out.push(Tok::LParen),
            ')' => out.push(Tok::RParen),
            '[' => out.push(Tok::LBracket),
            ']' => out.push(Tok::RBracket),
            ',' => out.push(Tok::Comma),
            ':' => out.push(Tok::Colon),
            '+' => out.push(Tok::Op("+")),
            '-' => out.push(Tok::Op("-")),
            '*' => out.push(Tok::Op("*")),
            '/' => out.push(Tok::Op("/")),
            '%' => out.push(Tok::Op("%")),
            '&' => out.push(Tok::Op("&")),
            '|' => out.push(Tok::Op("|")),
            '^' => out.push(Tok::Op("^")),
            '~' => out.push(Tok::Op("~")),
            '<' => out.push(Tok::Op("<")),
            '>' => out.push(Tok::Op(">")),
            '$' | '#' | '@' | '!' => {
                let mut j = i + 1;
                while j < c.len() && id_char(c[j]) {
                    j += 1;
                }
                let id: String = c[i + 1..j].iter().collect();
                let star = c.get(j) == Some(&'*') && ch == '$';
                out.push(Tok::Sigil(ch, id, star));
                i = j + usize::from(star);
                continue;
            }
            d if d.is_ascii_digit() => {
                let mut j = i;
                while j < c.len() && id_char(c[j]) {
                    j += 1;
                }
                let text: String = c[i..j].iter().collect();
                let lower = text.to_ascii_lowercase();
                let (digits, mult) = match lower.strip_suffix("kb").map(|d| (d, 1024)).or_else(|| lower.strip_suffix("mb").map(|d| (d, 1 << 20))).or_else(|| lower.strip_suffix("gb").map(|d| (d, 1 << 30))) {
                    Some((d, m)) if !d.starts_with("0x") => (d.to_string(), m),
                    _ => (lower.clone(), 1i64),
                };
                let value = match digits.strip_prefix("0x") {
                    Some(h) => i64::from_str_radix(h, 16),
                    None => digits.parse::<i64>(),
                }
                .map_err(|_| format!("invalid number `{text}`"))?;
                out.push(Tok::Int(value.checked_mul(mult).ok_or_else(|| format!("number `{text}` is too large"))?));
                i = j;
                continue;
            }
            a if a.is_ascii_alphabetic() || a == '_' => {
                let mut j = i;
                while j < c.len() && id_char(c[j]) {
                    j += 1;
                }
                out.push(Tok::Ident(c[i..j].iter().collect()));
                i = j;
                continue;
            }
            other => return Err(format!("unsupported character `{other}`")),
        }
        i += 1;
    }
    Ok(out)
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    atom_ids: &'a [String],
    vars: Vec<String>,
    in_for_of: usize,
    depth: usize,
}

fn kw(t: Option<&Tok>, word: &str) -> bool {
    matches!(t, Some(Tok::Ident(w)) if w.eq_ignore_ascii_case(word))
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_at(&self, n: usize) -> Option<&Tok> {
        self.toks.get(self.pos + n)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_kw(&mut self, word: &str) -> bool {
        if kw(self.peek(), word) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Tok, what: &str) -> Result<(), String> {
        if self.eat(t) { Ok(()) } else { Err(format!("expected {what}")) }
    }

    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH { Err(format!("expression nested deeper than {MAX_DEPTH}")) } else { Ok(()) }
    }

    fn atom_ref(&self, id: &str, sigil: char) -> Result<AtomRef, String> {
        if id.is_empty() {
            if self.in_for_of == 0 {
                return Err(format!("bare `{sigil}` outside `for .. of`"));
            }
            return Ok(AtomRef::Current);
        }
        if !self.atom_ids.iter().any(|a| a == id) {
            return Err(format!("`{sigil}{id}` names no atom"));
        }
        Ok(AtomRef::Id(id.to_string()))
    }

    fn or(&mut self) -> Result<Node, String> {
        self.enter()?;
        let mut l = self.and()?;
        while self.eat_kw("or") {
            l = Node::Or(Box::new(l), Box::new(self.and()?));
        }
        self.depth -= 1;
        Ok(l)
    }

    fn and(&mut self) -> Result<Node, String> {
        let mut l = self.not()?;
        while self.eat_kw("and") {
            l = Node::And(Box::new(l), Box::new(self.not()?));
        }
        Ok(l)
    }

    fn not(&mut self) -> Result<Node, String> {
        if self.eat_kw("not") {
            self.enter()?;
            let n = Node::Not(Box::new(self.not()?));
            self.depth -= 1;
            return Ok(n);
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Node, String> {
        let l = self.bin(0)?;
        let op = match self.peek() {
            Some(Tok::Op("==")) => CmpOp::Eq,
            Some(Tok::Op("!=")) => CmpOp::Ne,
            Some(Tok::Op("<")) => CmpOp::Lt,
            Some(Tok::Op("<=")) => CmpOp::Le,
            Some(Tok::Op(">")) => CmpOp::Gt,
            Some(Tok::Op(">=")) => CmpOp::Ge,
            _ => return Ok(l),
        };
        self.pos += 1;
        let r = self.bin(0)?;
        Ok(Node::Cmp(op, Box::new(l), Box::new(r)))
    }

    /// Binary integer operators by precedence level: `|`, `^`, `&`, shifts, `+ -`, `* / %`.
    fn bin(&mut self, level: usize) -> Result<Node, String> {
        const LEVELS: [&[(&str, BinOp)]; 6] = [
            &[("|", BinOp::Or)],
            &[("^", BinOp::Xor)],
            &[("&", BinOp::And)],
            &[("<<", BinOp::Shl), (">>", BinOp::Shr)],
            &[("+", BinOp::Add), ("-", BinOp::Sub)],
            &[("*", BinOp::Mul), ("/", BinOp::Div), ("%", BinOp::Mod)],
        ];
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut l = self.bin(level + 1)?;
        loop {
            let op = match self.peek() {
                Some(Tok::Op(o)) => LEVELS[level].iter().find(|(s, _)| s == o).map(|(_, b)| *b),
                _ => None,
            };
            let Some(op) = op else { break };
            self.pos += 1;
            l = Node::Bin(op, Box::new(l), Box::new(self.bin(level + 1)?));
        }
        Ok(l)
    }

    fn unary(&mut self) -> Result<Node, String> {
        if self.eat(&Tok::Op("-")) {
            self.enter()?;
            let n = Node::Neg(Box::new(self.unary()?));
            self.depth -= 1;
            return Ok(n);
        }
        if self.eat(&Tok::Op("~")) {
            self.enter()?;
            let n = Node::BitNot(Box::new(self.unary()?));
            self.depth -= 1;
            return Ok(n);
        }
        self.primary()
    }

    fn range(&mut self) -> Result<(Box<Node>, Box<Node>), String> {
        self.expect(&Tok::LParen, "`(` before a range")?;
        let lo = self.bin(0)?;
        self.expect(&Tok::DotDot, "`..` in a range")?;
        let hi = self.bin(0)?;
        self.expect(&Tok::RParen, "`)` after a range")?;
        Ok((Box::new(lo), Box::new(hi)))
    }

    /// `them` or `( $a, $b*, ... )`: atom ids in order.
    fn atom_set(&mut self) -> Result<Vec<String>, String> {
        if self.eat_kw("them") {
            if self.atom_ids.is_empty() {
                return Err("`them` with no atoms".into());
            }
            return Ok(self.atom_ids.to_vec());
        }
        self.expect(&Tok::LParen, "`them` or `(` after `of`")?;
        let mut ids = Vec::new();
        loop {
            match self.next() {
                Some(Tok::Sigil('$', id, star)) => {
                    if star {
                        let before = ids.len();
                        ids.extend(self.atom_ids.iter().filter(|a| a.starts_with(id.as_str())).cloned());
                        if ids.len() == before {
                            return Err(format!("`${id}*` matches no atom"));
                        }
                    } else if self.atom_ids.contains(&id) {
                        ids.push(id);
                    } else {
                        return Err(format!("`${id}` names no atom"));
                    }
                }
                _ => return Err("expected `$id` in an atom list".into()),
            }
            if self.eat(&Tok::RParen) {
                break;
            }
            self.expect(&Tok::Comma, "`,` or `)` in an atom list")?;
        }
        Ok(ids)
    }

    /// `any`, `all`, `none`, `N`, `N%`.
    fn quant(&mut self) -> Option<Quant> {
        let q = match self.peek()? {
            Tok::Ident(w) if w.eq_ignore_ascii_case("any") => Quant::Any,
            Tok::Ident(w) if w.eq_ignore_ascii_case("all") => Quant::All,
            Tok::Ident(w) if w.eq_ignore_ascii_case("none") => Quant::None,
            Tok::Int(n) => {
                let n = *n;
                if self.peek_at(1) == Some(&Tok::Op("%")) {
                    self.pos += 2;
                    return Some(Quant::Percent(n));
                }
                Quant::Count(n)
            }
            _ => return None,
        };
        self.pos += 1;
        Some(q)
    }

    fn body(&mut self) -> Result<Box<Node>, String> {
        self.expect(&Tok::Colon, "`:` before a loop body")?;
        self.expect(&Tok::LParen, "`(` around a loop body")?;
        let b = self.or()?;
        self.expect(&Tok::RParen, "`)` after a loop body")?;
        Ok(Box::new(b))
    }

    fn primary(&mut self) -> Result<Node, String> {
        self.enter()?;
        let n = self.primary_inner();
        self.depth -= 1;
        n
    }

    fn primary_inner(&mut self) -> Result<Node, String> {
        // `N of ...` / `N% of ...` before a plain number.
        let save = self.pos;
        if let Some(q) = self.quant() {
            if self.eat_kw("of") {
                return Ok(Node::Of(q, self.atom_set()?));
            }
            self.pos = save;
        }
        match self.next() {
            None => Err("expression ends early".into()),
            Some(Tok::Int(n)) => Ok(Node::Int(n)),
            Some(Tok::LParen) => {
                let e = self.or()?;
                self.expect(&Tok::RParen, "`)`")?;
                Ok(e)
            }
            Some(Tok::Sigil(s, id, star)) => {
                if star {
                    return Err(format!("`${id}*` is only valid in an atom list"));
                }
                let atom = self.atom_ref(&id, s)?;
                match s {
                    '$' => {
                        if self.eat_kw("at") {
                            if let Some(Tok::Sigil('$', other, false)) = self.peek().cloned() {
                                self.pos += 1;
                                let other = self.atom_ref(&other, '$')?;
                                let sign = match self.next() {
                                    Some(Tok::Op("+")) => 1,
                                    Some(Tok::Op("-")) => -1,
                                    _ => return Err("expected `+ N` or `- N` after `at $id`".into()),
                                };
                                let Some(Tok::Int(n)) = self.next() else { return Err("expected a number after `at $id +`".into()) };
                                return Ok(Node::AtAtom(atom, other, sign * n));
                            }
                            return Ok(Node::At(atom, Box::new(self.bin(0)?)));
                        }
                        if self.eat_kw("in") {
                            let (lo, hi) = self.range()?;
                            return Ok(Node::In(atom, lo, hi));
                        }
                        Ok(Node::Matched(atom))
                    }
                    '#' => {
                        if self.eat_kw("in") {
                            let (lo, hi) = self.range()?;
                            return Ok(Node::Count(atom, Some((lo, hi))));
                        }
                        Ok(Node::Count(atom, None))
                    }
                    '@' => {
                        if self.eat(&Tok::LBracket) {
                            let sign = if self.eat(&Tok::Op("-")) { -1 } else { self.eat(&Tok::Op("+")); 1 };
                            let n = match self.next() {
                                Some(Tok::Int(n)) => n,
                                Some(Tok::RBracket) => {
                                    return Ok(Node::Offset(atom, 0));
                                }
                                _ => return Err("expected a number in `@id[n]`".into()),
                            };
                            self.expect(&Tok::RBracket, "`]`")?;
                            return Ok(Node::Offset(atom, sign * n));
                        }
                        if let Some(Tok::Sigil('#', idx, false)) = self.peek().cloned() {
                            // `@a#2` lexes as `@a` then `#2`.
                            if let Ok(n) = idx.parse::<i64>() {
                                self.pos += 1;
                                return Ok(Node::OffsetAt(atom, Box::new(Node::Int(n))));
                            }
                            if idx.is_empty() && self.peek_at(1) == Some(&Tok::LParen) {
                                self.pos += 2;
                                let e = self.or()?;
                                self.expect(&Tok::RParen, "`)`")?;
                                return Ok(Node::OffsetAt(atom, Box::new(e)));
                            }
                            if self.vars.contains(&idx) {
                                self.pos += 1;
                                return Ok(Node::OffsetAt(atom, Box::new(Node::Var(idx))));
                            }
                        }
                        Ok(Node::Offset(atom, 0))
                    }
                    _ => {
                        if self.eat(&Tok::LBracket) {
                            let e = self.bin(0)?;
                            self.expect(&Tok::RBracket, "`]`")?;
                            return Ok(Node::Length(atom, Some(Box::new(e))));
                        }
                        Ok(Node::Length(atom, None))
                    }
                }
            }
            Some(Tok::Ident(w)) => self.word(w),
            Some(other) => Err(format!("unexpected {other:?}")),
        }
    }

    fn word(&mut self, w: String) -> Result<Node, String> {
        let lower = w.to_ascii_lowercase();
        if self.vars.contains(&w) {
            return Ok(Node::Var(w));
        }
        match lower.as_str() {
            "true" => return Ok(Node::Bool(true)),
            "false" => return Ok(Node::Bool(false)),
            "filesize" => return Ok(Node::Filesize),
            "entrypoint" => return Ok(Node::Entrypoint),
            "for" => return self.for_loop(),
            _ => {}
        }
        if let Some(r) = Reader::from_name(&lower) {
            self.expect(&Tok::LParen, "`(` after an integer reader")?;
            let e = self.bin(0)?;
            self.expect(&Tok::RParen, "`)`")?;
            return Ok(Node::Read(r, Box::new(e)));
        }
        if super::engine::EXPRESSION_TYPE_WORDS.iter().any(|t| t.eq_ignore_ascii_case(&w)) {
            return Ok(Node::TypeWord(w));
        }
        Err(format!("unsupported word `{w}`"))
    }

    fn for_loop(&mut self) -> Result<Node, String> {
        let q = self.quant().ok_or("expected `any`, `all`, `none`, N or N% after `for`")?;
        if self.eat_kw("of") {
            let set = self.atom_set()?;
            self.in_for_of += 1;
            let body = self.body();
            self.in_for_of -= 1;
            return Ok(Node::ForOf(q, set, body?));
        }
        let Some(Tok::Ident(var)) = self.next() else { return Err("expected `of` or a variable after `for` and the quantifier".into()) };
        if !self.eat_kw("in") {
            return Err(format!("expected `in` after `for .. {var}`"));
        }
        let (lo, hi) = self.range()?;
        if let (Node::Int(a), Node::Int(b)) = (&*lo, &*hi) {
            let n = b.saturating_sub(*a).saturating_add(1);
            if n > MAX_FOR_ITERATIONS {
                return Err(format!("`for` over {n} values: at most {MAX_FOR_ITERATIONS}"));
            }
        }
        self.vars.push(var.clone());
        let body = self.body();
        self.vars.pop();
        Ok(Node::ForIn(q, var, lo, hi, body?))
    }
}

/// Parse an expression against the atom ids of its condition.
pub fn parse(expression: &str, atom_ids: &[String]) -> Result<Node, String> {
    if expression.trim().is_empty() {
        return Err("empty expression".into());
    }
    let toks = lex(expression)?;
    let mut p = Parser { toks, pos: 0, atom_ids, vars: Vec::new(), in_for_of: 0, depth: 0 };
    let node = p.or()?;
    if let Some(t) = p.peek() {
        return Err(format!("unexpected {t:?} after the expression"));
    }
    check_types(&node, true)?;
    Ok(node)
}

fn is_bool(n: &Node) -> bool {
    matches!(
        n,
        Node::Bool(_)
            | Node::TypeWord(_)
            | Node::Matched(_)
            | Node::At(..)
            | Node::AtAtom(..)
            | Node::In(..)
            | Node::Of(..)
            | Node::ForOf(..)
            | Node::ForIn(..)
            | Node::Cmp(..)
            | Node::Not(_)
            | Node::And(..)
            | Node::Or(..)
    )
}

/// Booleans where conditions go, integers where numbers go.
fn check_types(n: &Node, want_bool: bool) -> Result<(), String> {
    if want_bool && !is_bool(n) {
        return Err("a number is used as a condition (compare it, e.g. `#a > 0`)".into());
    }
    if !want_bool && is_bool(n) {
        return Err("a condition is used as a number".into());
    }
    let int = |x: &Node| check_types(x, false);
    let boolean = |x: &Node| check_types(x, true);
    match n {
        Node::Read(_, x) | Node::Neg(x) | Node::BitNot(x) | Node::OffsetAt(_, x) | Node::At(_, x) => int(x),
        Node::Length(_, Some(x)) => int(x),
        Node::Count(_, Some((a, b))) | Node::In(_, a, b) | Node::Bin(_, a, b) | Node::Cmp(_, a, b) => {
            int(a)?;
            int(b)
        }
        Node::ForOf(q, _, body) => {
            check_quant(*q)?;
            boolean(body)
        }
        Node::ForIn(q, _, a, b, body) => {
            check_quant(*q)?;
            int(a)?;
            int(b)?;
            boolean(body)
        }
        Node::Of(q, _) => check_quant(*q),
        Node::Not(x) => boolean(x),
        Node::And(a, b) | Node::Or(a, b) => {
            boolean(a)?;
            boolean(b)
        }
        _ => Ok(()),
    }
}

fn check_quant(q: Quant) -> Result<(), String> {
    match q {
        Quant::Count(n) if n < 0 => Err("negative quantifier".into()),
        Quant::Percent(p) if !(0..=100).contains(&p) => Err(format!("{p}% is outside 0..100")),
        _ => Ok(()),
    }
}

/// A value: an integer, a boolean, or undefined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    Int(i64),
    Bool(bool),
    Undef,
}

impl Val {
    fn int(self) -> Option<i64> {
        match self {
            Val::Int(v) => Some(v),
            _ => None,
        }
    }

    fn truth(self) -> Option<bool> {
        match self {
            Val::Bool(b) => Some(b),
            Val::Int(v) => Some(v != 0),
            Val::Undef => None,
        }
    }
}

struct Eval<'a, 'c> {
    ctx: &'a Context<'c>,
    vars: Vec<(String, i64)>,
    current: Vec<String>,
    steps: usize,
    /// A loop was cut at `MAX_FOR_ITERATIONS` or the step budget ran out.
    pub aborted: Option<String>,
}

fn bool_val(b: bool) -> Val {
    Val::Bool(b)
}

impl Eval<'_, '_> {
    fn hits(&self, a: &AtomRef) -> Option<&AtomHits> {
        let id = match a {
            AtomRef::Id(id) => id.as_str(),
            AtomRef::Current => self.current.last()?.as_str(),
        };
        self.ctx.hits.get(id)
    }

    /// Occurrence `i` (1-based) of an atom.
    fn occurrence(&self, a: &AtomRef, i: i64) -> Option<(u64, Option<u64>)> {
        let h = self.hits(a)?;
        if !h.matched || i < 1 {
            return None;
        }
        h.occurrences.get(usize::try_from(i - 1).ok()?).copied()
    }

    /// Offsets usable by a legacy `@a[n]` comparison.
    fn legacy_offsets(&self, n: &Node) -> Option<Vec<i64>> {
        match n {
            Node::Offset(a, delta) => {
                let h = self.hits(a)?;
                Some(h.occurrences.iter().filter_map(|(o, _)| i64::try_from(*o).ok()?.checked_add(*delta)).filter(|v| *v >= 0).collect())
            }
            Node::Int(v) if *v >= 0 => Some(vec![*v]),
            _ => None,
        }
    }

    fn eval(&mut self, n: &Node) -> Val {
        self.steps += 1;
        if self.steps > MAX_EVAL_STEPS {
            self.aborted.get_or_insert_with(|| format!("evaluation stopped after {MAX_EVAL_STEPS} steps"));
            return Val::Undef;
        }
        match n {
            Node::Bool(b) => Val::Bool(*b),
            Node::Int(v) => Val::Int(*v),
            Node::Filesize => i64::try_from(self.ctx.filesize).map_or(Val::Undef, Val::Int),
            Node::Entrypoint => self.ctx.entrypoint.and_then(|e| i64::try_from(e).ok()).map_or(Val::Undef, Val::Int),
            Node::Var(name) => self.vars.iter().rev().find(|(v, _)| v == name).map_or(Val::Undef, |(_, x)| Val::Int(*x)),
            Node::TypeWord(w) => (self.ctx.type_word)(w).map_or(Val::Bool(false), Val::Bool),
            Node::Read(r, x) => match self.eval(x).int() {
                Some(off) => r.read(self.ctx.bytes, off).map_or(Val::Undef, Val::Int),
                None => Val::Undef,
            },
            Node::Matched(a) => bool_val(self.hits(a).is_some_and(|h| h.matched)),
            Node::Count(a, None) => Val::Int(self.hits(a).map_or(0, AtomHits::count)),
            Node::Count(a, Some((lo, hi))) => {
                let (Some(lo), Some(hi)) = (self.eval(lo).int(), self.eval(hi).int()) else { return Val::Undef };
                let n = self.hits(a).filter(|h| h.matched).map_or(0, |h| {
                    h.occurrences.iter().filter(|(o, _)| i64::try_from(*o).is_ok_and(|o| o >= lo && o <= hi)).count()
                });
                Val::Int(n as i64)
            }
            Node::Offset(a, delta) => match self.occurrence(a, 1) {
                Some((o, _)) => i64::try_from(o).ok().and_then(|o| o.checked_add(*delta)).map_or(Val::Undef, Val::Int),
                None => Val::Undef,
            },
            Node::OffsetAt(a, i) => match self.eval(i).int().and_then(|i| self.occurrence(a, i)) {
                Some((o, _)) => i64::try_from(o).map_or(Val::Undef, Val::Int),
                None => Val::Undef,
            },
            Node::Length(a, i) => {
                let i = match i {
                    Some(x) => match self.eval(x).int() {
                        Some(v) => v,
                        None => return Val::Undef,
                    },
                    None => 1,
                };
                match self.occurrence(a, i) {
                    Some((_, Some(len))) => i64::try_from(len).map_or(Val::Undef, Val::Int),
                    _ => Val::Undef,
                }
            }
            Node::At(a, pos) => {
                let Some(pos) = self.eval(pos).int() else { return Val::Bool(false) };
                bool_val(self.hits(a).is_some_and(|h| h.matched && h.occurrences.iter().any(|(o, _)| i64::try_from(*o) == Ok(pos))))
            }
            Node::AtAtom(a, b, delta) => {
                let (Some(ha), Some(hb)) = (self.hits(a), self.hits(b)) else { return Val::Bool(false) };
                bool_val(ha.occurrences.iter().any(|(oa, _)| {
                    hb.occurrences.iter().any(|(ob, _)| i64::try_from(*ob).ok().and_then(|ob| ob.checked_add(*delta)).is_some_and(|t| t >= 0 && i64::try_from(*oa) == Ok(t)))
                }))
            }
            Node::In(a, lo, hi) => {
                let (Some(lo), Some(hi)) = (self.eval(lo).int(), self.eval(hi).int()) else { return Val::Bool(false) };
                bool_val(self.hits(a).is_some_and(|h| h.matched && h.occurrences.iter().any(|(o, _)| i64::try_from(*o).is_ok_and(|o| o >= lo && o <= hi))))
            }
            Node::Of(q, ids) => {
                let hits = ids.iter().filter(|id| self.ctx.hits.get(*id).is_some_and(|h| h.matched)).count() as i64;
                bool_val(q.holds(hits, ids.len() as i64))
            }
            Node::ForOf(q, ids, body) => {
                let mut hits = 0;
                for id in ids {
                    self.current.push(id.clone());
                    let v = self.eval(body).truth() == Some(true);
                    self.current.pop();
                    hits += i64::from(v);
                }
                bool_val(q.holds(hits, ids.len() as i64))
            }
            Node::ForIn(q, var, lo, hi, body) => {
                let (Some(lo), Some(hi)) = (self.eval(lo).int(), self.eval(hi).int()) else { return Val::Bool(false) };
                let total = if hi < lo { 0 } else { hi.saturating_sub(lo).saturating_add(1) };
                if total > MAX_FOR_ITERATIONS {
                    self.aborted.get_or_insert_with(|| format!("`for {var} in ({lo}..{hi})` has {total} iterations, more than {MAX_FOR_ITERATIONS}"));
                    return Val::Bool(false);
                }
                let mut hits = 0;
                for i in 0..total {
                    self.vars.push((var.clone(), lo + i));
                    let v = self.eval(body).truth() == Some(true);
                    self.vars.pop();
                    hits += i64::from(v);
                    if self.aborted.is_some() {
                        return Val::Bool(false);
                    }
                }
                bool_val(q.holds(hits, total))
            }
            Node::Neg(x) => self.eval(x).int().and_then(i64::checked_neg).map_or(Val::Undef, Val::Int),
            Node::BitNot(x) => self.eval(x).int().map_or(Val::Undef, |v| Val::Int(!v)),
            Node::Bin(op, a, b) => {
                let (Some(a), Some(b)) = (self.eval(a).int(), self.eval(b).int()) else { return Val::Undef };
                let r = match op {
                    BinOp::Add => a.checked_add(b),
                    BinOp::Sub => a.checked_sub(b),
                    BinOp::Mul => a.checked_mul(b),
                    BinOp::Div => a.checked_div(b),
                    BinOp::Mod => a.checked_rem(b),
                    BinOp::And => Some(a & b),
                    BinOp::Or => Some(a | b),
                    BinOp::Xor => Some(a ^ b),
                    BinOp::Shl => u32::try_from(b).ok().filter(|s| *s < 64).map(|s| a.wrapping_shl(s)),
                    BinOp::Shr => u32::try_from(b).ok().filter(|s| *s < 64).map(|s| a.wrapping_shr(s)),
                };
                r.map_or(Val::Undef, Val::Int)
            }
            Node::Cmp(op, a, b) => {
                // The original evaluator's offset comparisons: any occurrence pair.
                if matches!(**a, Node::Offset(..))
                    && let (Some(l), Some(r)) = (self.legacy_offsets(a), self.legacy_offsets(b))
                {
                    return bool_val(l.iter().any(|x| r.iter().any(|y| op.holds(*x, *y))));
                }
                match (self.eval(a).int(), self.eval(b).int()) {
                    (Some(x), Some(y)) => bool_val(op.holds(x, y)),
                    _ => Val::Bool(false),
                }
            }
            Node::Not(x) => match self.eval(x).truth() {
                Some(b) => Val::Bool(!b),
                None => Val::Undef,
            },
            Node::And(a, b) => match self.eval(a).truth() {
                Some(false) => Val::Bool(false),
                l => match (l, self.eval(b).truth()) {
                    (_, Some(false)) => Val::Bool(false),
                    (Some(true), Some(true)) => Val::Bool(true),
                    _ => Val::Undef,
                },
            },
            Node::Or(a, b) => match self.eval(a).truth() {
                Some(true) => Val::Bool(true),
                l => match (l, self.eval(b).truth()) {
                    (_, Some(true)) => Val::Bool(true),
                    (Some(false), Some(false)) => Val::Bool(false),
                    _ => Val::Undef,
                },
            },
        }
    }
}

/// Evaluate a parsed expression: (holds, why a loop or the budget cut it short).
pub fn evaluate(node: &Node, ctx: &Context) -> (bool, Option<String>) {
    let mut e = Eval { ctx, vars: Vec::new(), current: Vec::new(), steps: 0, aborted: None };
    let v = e.eval(node).truth() == Some(true);
    (v, e.aborted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_eval(expr: &str, atoms: &[(&str, &[(u64, u64)])], bytes: &[u8], entry: Option<u64>) -> Result<bool, String> {
        let ids: Vec<String> = atoms.iter().map(|(id, _)| id.to_string()).collect();
        let hits: HashMap<String, AtomHits> = atoms
            .iter()
            .map(|(id, occ)| {
                (id.to_string(), AtomHits { matched: !occ.is_empty(), occurrences: occ.iter().map(|(o, l)| (*o, Some(*l))).collect() })
            })
            .collect();
        let node = parse(expr, &ids)?;
        let words = |w: &str| Some(w.eq_ignore_ascii_case("PE"));
        let ctx = Context { hits: &hits, bytes, filesize: bytes.len() as u64, entrypoint: entry, type_word: &words };
        Ok(evaluate(&node, &ctx).0)
    }

    const A: (&str, &[(u64, u64)]) = ("a", &[(16, 12), (200, 4), (900, 4)]);
    const B: (&str, &[(u64, u64)]) = ("b", &[(24, 3)]);
    const NONE: (&str, &[(u64, u64)]) = ("c", &[]);

    fn ok(expr: &str) -> bool {
        let bytes: Vec<u8> = [0xCA, 0xFE, 0xBA, 0xBE].into_iter().chain((4..1024).map(|i| i as u8)).collect();
        ctx_eval(expr, &[A, B, NONE], &bytes, Some(100)).unwrap()
    }

    #[test]
    fn counts_lengths_and_offsets() {
        assert!(ok("#a >= 3"));
        assert!(!ok("#a >= 4"));
        assert!(ok("#a in (0..512) == 2"));
        assert!(ok("#a in (16..16) == 1 and #a in (17..199) == 0"));
        assert!(ok("!a > 10"));
        assert!(ok("!a[2] == 4"));
        assert!(!ok("!c > 0"), "length of a missing atom is undefined");
        assert!(!ok("!a[9] >= 0"), "no ninth match");
        assert!(ok("@a#2 > @a#1"));
        assert!(ok("@a#3 == 900 and @a == 16"));
        assert!(ok("@a[8] == @b"), "legacy +n offset");
        assert!(ok("@a[1] == 201"), "legacy any-occurrence comparison");
        assert!(ok("@a + 8 == @b"), "arithmetic uses the first match");
        assert!(ok("$a at $b - 8 and $a in (100..300)"));
        assert!(ok("#c == 0 and not $c"));
    }

    #[test]
    fn readers_arithmetic_and_undefined() {
        assert!(ok("uint32be(0) == 0xCAFEBABE"));
        assert!(ok("uint32(0) == 0xBEBAFECA"));
        assert!(ok("uint16be(0) == 0xcafe and uint8(4) == 4 and int8(0) == -54"));
        assert!(ok("int16be(0) == -13570 and int32(0) < 0 and int32be(0) < 0 and int16(0) < 0"));
        assert!(!ok("uint32(1022) == 0"), "read past the end");
        assert!(!ok("uint32(1022) != 0"), "undefined compares false either way");
        assert!(!ok("filesize / 0 == 0") && !ok("filesize % 0 != 1"), "division by zero");
        assert!(ok("filesize == 1KB and (filesize >> 2) == 256 and (1 << 4 | 1) == 17 and (0xff & ~0xf) == 0xf0 and (6 ^ 3) == 5"));
        assert!(ok("entrypoint == 100 and @a < entrypoint"));
        assert!(!ok("0x7fffffffffffffff + 1 > 0"), "overflow is undefined");
        assert!(ok("-(3) * 2 == -6 and 7 % 4 == 3"));
        assert!(ok("PE and not (filesize < 10)"));
    }

    #[test]
    fn bounded_loops() {
        assert!(ok("for any i in (0..8) : ( uint8(i) == 0xBA )"));
        assert!(!ok("for all i in (0..8) : ( uint8(i) == 0xBA )"));
        assert!(ok("for 2 i in (1..3) : ( @a#i > 100 )"));
        assert!(ok("for all i in (1..#a) : ( !a[i] >= 4 )"));
        assert!(!ok("for any of ($a, $b) : ( @ >= entrypoint and ! < 16 )"));
        assert!(ok("for any of ($a*, $b) : ( # >= 3 and ! > 10 )"));
        assert!(ok("for all of them : ( $ or # == 0 )"));
        assert!(ok("for none of ($c) : ( $ )"));
        assert!(ok("for 50% of them : ( $ )") && !ok("for 100% of them : ( $ )"));
        assert!(ok("2 of ($a, $b, $c) and not all of them and 60% of them"));
        // Dynamic bounds above the cap stop the loop as false.
        assert!(!ok("for any i in (0..filesize * 8) : ( i == 1 )"));
        let ids = ["a".to_string()];
        let err = parse("for any i in (0..4096) : ( uint8(i) == 0 )", &ids).unwrap_err();
        assert!(err.contains("4096"), "{err}");
        assert!(parse("for any i in (0..4095) : ( uint8(i) == 0 )", &ids).is_ok());
    }

    #[test]
    fn parse_errors() {
        let ids = ["a".to_string(), "b".to_string()];
        for bad in [
            "#z > 1",
            "$a +",
            "#a",
            "uint32(0)",
            "$a > 1",
            "@ > 0",
            "for any i in (0..9) : ( j == 1 )",
            "for 150% of them : ( $ )",
            "(((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((#a > 1)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))",
            "uint33(0) == 1",
            "$a and",
            "99999999999999999999 > 1",
        ] {
            assert!(parse(bad, &ids).is_err(), "{bad}");
        }
    }
}
