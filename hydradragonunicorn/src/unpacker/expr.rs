// unpacker/expr.rs — integer expressions of unpacker recipes (`pos + 4`,
// `n & 0x7fffffff`, `len(stream) - pos >= 4`, `rva2off(entry_rva)`). C operators
// and precedence; comparisons and `&&` / `||` / `!` give 1 or 0. Evaluated in
// i128, so no u32 / u64 field read from a file overflows an addition.

use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Num(i128),
    Var(String),
    /// `len(buffer)`: the length of a buffer (its name, not a value).
    Len(String),
    /// `name(a, b, ...)`: a function of integers the environment provides.
    Call(String, Vec<Expr>),
    Unary(char, Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
}

/// What an expression can read.
pub trait Env {
    fn var(&self, name: &str) -> Option<i128>;
    fn buf_len(&self, name: &str) -> Option<usize>;
    fn call(&self, name: &str, args: &[i128]) -> Result<i128, String>;
}

/// Binary operators, lowest precedence first.
const LEVELS: &[&[&str]] = &[
    &["||"],
    &["&&"],
    &["|"],
    &["^"],
    &["&"],
    &["==", "!="],
    &["<=", ">=", "<", ">"],
    &["<<", ">>"],
    &["+", "-"],
    &["*", "/", "%"],
];

impl Expr {
    pub fn parse(s: &str) -> Result<Expr, String> {
        let tokens = tokenize(s)?;
        let mut p = Parser { tokens: &tokens, i: 0 };
        let e = p.binary(0)?;
        if p.i != tokens.len() {
            return Err(format!("unexpected `{}` in `{s}`", tokens[p.i]));
        }
        Ok(e)
    }

    pub fn eval(&self, env: &dyn Env) -> Result<i128, String> {
        Ok(match self {
            Expr::Num(n) => *n,
            Expr::Var(v) => env.var(v).ok_or_else(|| format!("variable `{v}` is not set"))?,
            Expr::Len(b) => env.buf_len(b).ok_or_else(|| format!("buffer `{b}` is not set"))? as i128,
            Expr::Call(f, args) => {
                let args = args.iter().map(|a| a.eval(env)).collect::<Result<Vec<_>, _>>()?;
                env.call(f, &args)?
            }
            Expr::Unary(op, e) => {
                let v = e.eval(env)?;
                match op {
                    '!' => (v == 0) as i128,
                    '~' => !v,
                    _ => v.checked_neg().ok_or("overflow")?,
                }
            }
            Expr::Binary(op, a, b) => {
                let a = a.eval(env)?;
                // `&&` / `||` do not evaluate the right side when the left decides.
                match *op {
                    "&&" if a == 0 => return Ok(0),
                    "||" if a != 0 => return Ok(1),
                    _ => {}
                }
                let b = b.eval(env)?;
                let shift = || u32::try_from(b).ok().filter(|&s| s < 127).ok_or_else(|| format!("bad shift {b}"));
                match *op {
                    "||" | "&&" => (b != 0) as i128,
                    "|" => a | b,
                    "^" => a ^ b,
                    "&" => a & b,
                    "==" => (a == b) as i128,
                    "!=" => (a != b) as i128,
                    "<=" => (a <= b) as i128,
                    ">=" => (a >= b) as i128,
                    "<" => (a < b) as i128,
                    ">" => (a > b) as i128,
                    "<<" => a.checked_shl(shift()?).ok_or("overflow")?,
                    ">>" => a >> shift()?,
                    "+" => a.checked_add(b).ok_or("overflow")?,
                    "-" => a.checked_sub(b).ok_or("overflow")?,
                    "*" => a.checked_mul(b).ok_or("overflow")?,
                    "/" => a.checked_div(b).ok_or("division by zero")?,
                    _ => a.checked_rem(b).ok_or("division by zero")?,
                }
            }
        })
    }
}

/// A YAML integer or an expression string.
impl<'de> Deserialize<'de> for Expr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(i64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(n) => Ok(Expr::Num(n as i128)),
            Raw::Text(s) => Expr::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            let start = i;
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(c[start..i].iter().collect());
        } else {
            let two: String = c[i..(i + 2).min(c.len())].iter().collect();
            if ["||", "&&", "==", "!=", "<=", ">=", "<<", ">>"].contains(&two.as_str()) {
                out.push(two);
                i += 2;
            } else if "|^&<>+-*/%!~(),".contains(ch) {
                out.push(ch.to_string());
                i += 1;
            } else {
                return Err(format!("unexpected `{ch}` in `{s}`"));
            }
        }
    }
    Ok(out)
}

struct Parser<'a> {
    tokens: &'a [String],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.i).map(String::as_str)
    }

    fn expect(&mut self, t: &str) -> Result<(), String> {
        if self.peek() == Some(t) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected `{t}`"))
        }
    }

    fn binary(&mut self, level: usize) -> Result<Expr, String> {
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        while let Some(op) = self.peek().and_then(|t| LEVELS[level].iter().find(|o| **o == t)) {
            self.i += 1;
            let right = self.binary(level + 1)?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(op @ ("!" | "~" | "-")) => {
                let op = op.chars().next().unwrap_or('-');
                self.i += 1;
                Ok(Expr::Unary(op, Box::new(self.unary()?)))
            }
            Some("(") => {
                self.i += 1;
                let e = self.binary(0)?;
                self.expect(")")?;
                Ok(e)
            }
            Some(t) if t.starts_with(|c: char| c.is_ascii_digit()) => {
                let t = t.to_string();
                self.i += 1;
                let n = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(h) => i128::from_str_radix(h, 16),
                    None => t.parse(),
                };
                n.map(Expr::Num).map_err(|_| format!("bad number `{t}`"))
            }
            Some(t) if t.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') => {
                let name = t.to_string();
                self.i += 1;
                if self.peek() != Some("(") {
                    return Ok(Expr::Var(name));
                }
                self.i += 1;
                let mut args = Vec::new();
                if self.peek() != Some(")") {
                    loop {
                        args.push(self.binary(0)?);
                        if self.peek() == Some(",") {
                            self.i += 1;
                        } else {
                            break;
                        }
                    }
                }
                self.expect(")")?;
                if name == "len" {
                    return match args.as_slice() {
                        [Expr::Var(b)] => Ok(Expr::Len(b.clone())),
                        _ => Err("len(buffer) takes one buffer name".into()),
                    };
                }
                Ok(Expr::Call(name, args))
            }
            Some(t) => Err(format!("unexpected `{t}`")),
            None => Err("expression ends early".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestEnv(HashMap<String, i128>);

    impl Env for TestEnv {
        fn var(&self, name: &str) -> Option<i128> {
            self.0.get(name).copied()
        }
        fn buf_len(&self, name: &str) -> Option<usize> {
            (name == "buf").then_some(10)
        }
        fn call(&self, name: &str, args: &[i128]) -> Result<i128, String> {
            match (name, args) {
                ("twice", [a]) => Ok(a * 2),
                _ => Err(format!("unknown function {name}")),
            }
        }
    }

    fn eval(s: &str, vars: &[(&str, i128)]) -> i128 {
        let env = TestEnv(vars.iter().map(|(k, v)| (k.to_string(), *v)).collect());
        Expr::parse(s).unwrap().eval(&env).unwrap()
    }

    #[test]
    fn c_precedence_and_values() {
        assert_eq!(eval("1 + 2 * 3", &[]), 7);
        assert_eq!(eval("(1 + 2) * 3", &[]), 9);
        assert_eq!(eval("n & 0x7fffffff", &[("n", 0x8000_0010)]), 0x10);
        assert_eq!(eval("n & 0x80000000 != 0", &[("n", 0x8000_0010)]), 0); // `!=` binds tighter, as in C
        assert_eq!(eval("(n & 0x80000000) != 0", &[("n", 0x8000_0010)]), 1);
        assert_eq!(eval("pos + 4 <= len(buf)", &[("pos", 6)]), 1);
        assert_eq!(eval("pos + 4 <= len(buf)", &[("pos", 7)]), 0);
        assert_eq!(eval("!x || 1 / x", &[("x", 0)]), 1);
        assert_eq!(eval("-3 + 1 << 2", &[]), -8);
        assert_eq!(eval("0xFFFFFFFF + 0xFFFFFFFF", &[]), 0x1_FFFF_FFFE);
        assert_eq!(eval("twice(x + 1) - 1", &[("x", 4)]), 9);
    }

    #[test]
    fn errors() {
        let env = TestEnv(HashMap::new());
        assert!(Expr::parse("1 +").is_err());
        assert!(Expr::parse("(1").is_err());
        assert!(Expr::parse("a $ b").is_err());
        assert!(Expr::parse("len(1)").is_err());
        assert!(Expr::parse("x").unwrap().eval(&env).is_err());
        assert!(Expr::parse("1 / 0").unwrap().eval(&env).is_err());
        assert!(Expr::parse("nope(1)").unwrap().eval(&env).is_err());
    }
}
