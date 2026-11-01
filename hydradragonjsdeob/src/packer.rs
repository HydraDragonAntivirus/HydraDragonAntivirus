//! Dean Edwards' P.A.C.K.E.R., unpacked as text without running anything.
//!
//! ```javascript
//! eval(function(p,a,c,k,e,d){ ... return p}('0 1=2;',3,3,'var|x|5'.split('|'),0,{}))
//! ```
//!
//! `p` is the code with every word replaced by its index in base `a` (digits, then
//! `a-z`, then `A-Z`, as the packer's own `e` function writes it); `k` is the word list.
//! The packer's unpacker replaces each `\b<code>\b` with `k[index]` when that entry is
//! not empty and evals the result. Here the replacement is done on the text and the
//! result takes the place of the whole `eval(...)` call. Packed code can be packed again,
//! so it is applied until nothing is left (at most `MAX_LAYERS`).

const MAX_LAYERS: usize = 8;

/// The source with every P.A.C.K.E.R. call unpacked, or `None` when there is none.
pub fn unpack_all(source: &str) -> Option<String> {
    let mut cur = unpack_once(source)?;
    for _ in 1..MAX_LAYERS {
        match unpack_once(&cur) {
            Some(next) => cur = next,
            None => break,
        }
    }
    Some(cur)
}

/// Unpacks the first P.A.C.K.E.R. call of `source`.
pub fn unpack_once(source: &str) -> Option<String> {
    let start = find_packer(source)?;
    let s = &source[start..];
    // The arguments follow the function body: `...return p}('payload',a,c,'k'.split('|')...`
    let body_end = s.find("}(")? + 2;
    let mut cur = Cursor { s, i: body_end };
    let payload = cur.string()?;
    cur.expect(',')?;
    let radix = cur.int()?;
    cur.expect(',')?;
    let count = cur.int()?;
    cur.expect(',')?;
    let words = cur.string()?;
    cur.skip_ws();
    let rest = s.get(cur.i..)?;
    let split = [".split('|')", ".split(\"|\")"].into_iter().find(|p| rest.starts_with(p))?;
    cur.i += split.len();
    // The rest of the inner call (`,0,{}`) and the closing `)` of it and of `eval(`.
    let end = cur.close_calls(2)?;
    if !(2..=62).contains(&radix) {
        return None;
    }
    let dict: Vec<&str> = words.split('|').collect();
    let code = substitute(&payload, radix, count.min(dict.len()), &dict);
    let mut out = String::with_capacity(source.len() - end + code.len());
    out.push_str(&source[..start]);
    out.push_str(&code);
    out.push_str(&source[start + end..]);
    Some(out)
}

/// Start of `eval(function(p,a,c,k,e,` (any spacing, any last parameter name).
fn find_packer(source: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(off) = source[from..].find("eval(") {
        let at = from + off;
        let rest: String = source[at + 5..].chars().take(64).filter(|c| !c.is_whitespace()).collect();
        if rest.starts_with("function(p,a,c,k,e,") {
            return Some(at);
        }
        from = at + 5;
    }
    None
}

/// Every word of `payload` that is a code below `count` with a non-empty dictionary
/// entry becomes that entry (`\b\w+\b` in JavaScript: `[A-Za-z0-9_]` runs).
fn substitute(payload: &str, radix: usize, count: usize, dict: &[&str]) -> String {
    let b = payload.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = String::with_capacity(payload.len() * 2);
    let mut i = 0;
    while i < b.len() {
        if !is_word(b[i]) {
            let ch_len = payload[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&payload[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        let j = (i..b.len()).find(|&j| !is_word(b[j])).unwrap_or(b.len());
        let word = &payload[i..j];
        match decode(word, radix).filter(|&n| n < count).and_then(|n| dict.get(n)).filter(|w| !w.is_empty()) {
            Some(w) => out.push_str(w),
            None => out.push_str(word),
        }
        i = j;
    }
    out
}

/// The packer's `e(c)` read back: base `radix` with digits `0-9`, `a-z`, `A-Z`.
fn decode(word: &str, radix: usize) -> Option<usize> {
    let mut n: usize = 0;
    for c in word.bytes() {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as usize,
            b'a'..=b'z' => (c - b'a') as usize + 10,
            b'A'..=b'Z' => (c - b'A') as usize + 36,
            _ => return None,
        };
        if d >= radix {
            return None;
        }
        n = n.checked_mul(radix)?.checked_add(d)?;
    }
    Some(n)
}

struct Cursor<'s> {
    s: &'s str,
    i: usize,
}

impl Cursor<'_> {
    fn skip_ws(&mut self) {
        while self.s.as_bytes().get(self.i).is_some_and(|c| c.is_ascii_whitespace()) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: char) -> Option<()> {
        self.skip_ws();
        (self.s.as_bytes().get(self.i) == Some(&(c as u8))).then(|| self.i += 1)
    }

    fn int(&mut self) -> Option<usize> {
        self.skip_ws();
        let start = self.i;
        while self.s.as_bytes().get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        self.s[start..self.i].parse().ok()
    }

    /// A JavaScript string literal (`'...'` or `"..."`), unescaped.
    fn string(&mut self) -> Option<String> {
        self.skip_ws();
        let quote = *self.s.as_bytes().get(self.i)?;
        if quote != b'\'' && quote != b'"' {
            return None;
        }
        self.i += 1;
        let mut out = String::new();
        let mut chars = self.s[self.i..].char_indices();
        while let Some((off, c)) = chars.next() {
            match c {
                c if c as u32 == quote as u32 => {
                    self.i += off + 1;
                    return Some(out);
                }
                '\\' => {
                    let (_, e) = chars.next()?;
                    match e {
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'v' => out.push('\u{b}'),
                        '0' => out.push('\0'),
                        'x' => {
                            let h: String = (0..2).filter_map(|_| chars.next().map(|(_, c)| c)).collect();
                            out.push(char::from_u32(u32::from_str_radix(&h, 16).ok()?)?);
                        }
                        'u' => {
                            let h: String = (0..4).filter_map(|_| chars.next().map(|(_, c)| c)).collect();
                            out.push(char::from_u32(u32::from_str_radix(&h, 16).ok()?).unwrap_or('\u{fffd}'));
                        }
                        '\n' => {}
                        other => out.push(other),
                    }
                }
                c => out.push(c),
            }
        }
        None
    }

    /// Skips to just after the `n`-th `)` that closes an open call, skipping strings
    /// and nested brackets. Returns that offset.
    fn close_calls(&mut self, n: usize) -> Option<usize> {
        let b = self.s.as_bytes();
        let (mut depth, mut closed) = (0i32, 0usize);
        while self.i < b.len() {
            match b[self.i] {
                b'\'' | b'"' => {
                    self.string()?;
                    continue;
                }
                b'(' | b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                b')' if depth > 0 => depth -= 1,
                b')' => {
                    closed += 1;
                    if closed == n {
                        return Some(self.i + 1);
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNPACKER: &str = "function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}";

    #[test]
    fn unpacks_a_simple_call_in_place() {
        let src = format!("a();eval({UNPACKER}('0 1=2;',3,3,'var|x|5'.split('|'),0,{{}}));b();");
        assert_eq!(unpack_all(&src).unwrap(), "a();var x=5;;b();");
    }

    #[test]
    fn empty_entries_keep_the_code_and_words_outside_the_count_stay() {
        // `1` has an empty entry; `z` is past the count.
        let src = format!("eval({UNPACKER}('0 1 z',36,2,'hello|'.split('|'),0,{{}}))");
        assert_eq!(unpack_all(&src).unwrap(), "hello 1 z");
    }

    #[test]
    fn upper_case_digits_past_base_36_and_escapes() {
        // 36 is `A` in base 62.
        let mut words = vec![""; 37];
        words[36] = "done";
        // The JS literal of the text A('it\'s').
        let payload = r"A(\'it\\\'s\')";
        let src = format!("eval({UNPACKER}('{payload}',62,37,'{}'.split('|'),0,{{}}))", words.join("|"));
        assert_eq!(unpack_all(&src).unwrap(), "done('it\\'s')");
    }

    #[test]
    fn nested_layers_and_plain_code() {
        let inner = format!("eval({UNPACKER}('0',2,1,'ok'.split('|'),0,{{}}))").replace('\\', "\\\\").replace('\'', "\\'");
        let outer = format!("eval({UNPACKER}('{inner}',2,0,''.split('|'),0,{{}}))");
        assert_eq!(unpack_all(&outer).unwrap(), "ok");
        assert_eq!(unpack_all("var a = eval('1');"), None);
    }
}
