//! Wildcard glob matching shared by path patterns, version fields, resource
//! types, certificate subjects and remediation targets.
//!
//! Supported wildcards:
//! * `*` matches any run of characters (no leading-dot exceptions).
//! * `**` also matches path separators, so `**\loader.tlb` matches at any depth.
//! * `?` matches exactly one character.
//! * `#` matches exactly one alphanumeric character (digit or letter, either
//!   case), useful as a stricter single-character wildcard.
//! Backslashes and slashes in both pattern and text are treated the same.
//! Matching is always case-insensitive.

/// True when `text` matches the glob `pattern`. Unknown `{}` are literal.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(pattern.chars().collect(), text.chars().collect())
}

/// True when any pattern of a list matches.
pub fn glob_match_list(patterns: &[&str], text: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, text))
}

fn glob_match_inner(pat: Vec<char>, txt: Vec<char>) -> bool {
    let p = &pat[..];
    let t = &txt[..];
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            while pi < p.len() && p[pi] == '*' {
                pi += 1;
            }
            star_pi = Some(pi);
            star_ti = ti;
        } else if pi < p.len() && char_matches(p[pi], t[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = sp;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn char_matches(pc: char, tc: char) -> bool {
    match pc {
        '?' => true,
        '#' => tc.is_ascii_alphanumeric(),
        '/' | '\\' => tc == '/' || tc == '\\',
        _ => pc.eq_ignore_ascii_case(&tc),
    }
}

/// True when `text` contains glob wildcards (`*`, `?`, `#`).
pub fn has_glob_wildcards(text: &str) -> bool {
    text.chars().any(|c| c == '*' || c == '?' || c == '#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_globs() {
        assert!(glob_match("%SYSDIR%\\c_#####.nls", "%SysDir%\\c_01k46.nls"));
        assert!(!glob_match("%SYSDIR%\\c_#####.nls", "%SYSDIR%\\c_01k4a6.nls"));
        assert!(glob_match("local##spl.dll", "localaSspl.dll"));
        assert!(!glob_match("local##spl.dll", "localspl.dll"));
        assert!(glob_match(".tex#t", ".tex5t"));
        assert!(glob_match("**\\Local Settings\\**\\U\\loader.tlb", "c:\\x\\Local Settings\\a\\b\\U\\loader.tlb"));
        assert!(glob_match(".pdata*", ".pdataa"));
        assert!(glob_match(".pdata*", ".pdata")); // `*` may be empty
    }
}