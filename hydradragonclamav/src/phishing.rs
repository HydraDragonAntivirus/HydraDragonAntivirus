//! ClamAV phishing engine (`.pdb` / `.gdb` protected domains, `.wdb` allow list)
//! and the spoofed-domain heuristic, ported from `clamav/libclamav/phishcheck.c`,
//! `regex_list.c`, and `phish_domaincheck_db.c` / `phish_allow_list.c`.
//!
//! ClamAV checks `<a href="REAL">DISPLAY</a>` link pairs harvested from HTML/email.
//! A link whose DISPLAY host belongs to a *protected* domain (`.pdb`/`.gdb`) but
//! whose REAL host resolves to a different registrable domain — and which no
//! `.wdb` allow-list entry pardons — is reported as a phishing heuristic.
//!
//! Faithful to ClamAV's non-hash phishing matching. The Google-Safe-Browsing
//! `S:`/`S2:` SHA-256 entries that can appear in `.gdb` are hash-based and out of
//! scope here (this crate is the non-hash engine); they are skipped on load.

use crate::database::SourceLocation;
use regex::Regex;
use std::collections::HashMap;

mod tld;

/// One detection produced by the phishing heuristic: a `Heuristics.Phishing.*`
/// name plus the protected-domain database line that armed the check.
#[derive(Clone, Debug)]
pub struct PhishMatch {
    pub name: &'static str,
    pub source: SourceLocation,
}

/// `.pdb` / `.gdb` protected-domain matcher (`cli_loadpdb` →
/// `phish_protected_domain_matcher`). A display host matching one of these is
/// subjected to the spoof heuristic.
#[derive(Debug, Default)]
pub struct ProtectedDomainMatcher {
    /// `H:` — protected display-host literals (subdomain-aware suffix match),
    /// mapped to the database line that defined them for citation.
    host_literals: HashMap<String, SourceLocation>,
    /// `R:` — `(real_regex, display_regex)` URL pairs, with source line.
    regex_pairs: Vec<(Regex, Regex, SourceLocation)>,
}

/// `.wdb` allow-list matcher (`cli_loadwdb` → `phish_allow_list_matcher`). A link
/// pair pardoned here is never reported, suppressing known cross-domain links.
#[derive(Debug, Default)]
pub struct AllowListMatcher {
    /// `M:` — literal `(real_host, display_host)` pairs (suffix match each side).
    host_pairs: Vec<(String, String)>,
    /// `X:` — `(real_regex, display_regex)` URL pairs.
    regex_pairs: Vec<(Regex, Regex)>,
    /// `Y:` — real-host-only allow regexes.
    host_regexes: Vec<Regex>,
}

impl ProtectedDomainMatcher {
    pub fn is_empty(&self) -> bool {
        self.host_literals.is_empty() && self.regex_pairs.is_empty()
    }

    /// Parse one `.pdb`/`.gdb` line. Returns `Ok(true)` if an entry was added,
    /// `Ok(false)` if the line was intentionally skipped (e.g. `S:` hash), or
    /// `Err` on a malformed entry.
    pub fn add_line(&mut self, line: &str, source: SourceLocation) -> Result<bool, String> {
        let tokens: Vec<&str> = line.split(':').collect();
        match flag_of(line) {
            // `H:host` — protected display host literal.
            b'H' => {
                let host = tokens.get(1).map(|s| s.trim()).unwrap_or("");
                if host.is_empty() {
                    return Err("empty H: host in protected-domain entry".to_string());
                }
                self.host_literals.insert(host.to_ascii_lowercase(), source);
                Ok(true)
            }
            // `R:realRegex:displayRegex` — protected regex pair.
            b'R' => {
                let (real, display) = (tokens.get(1), tokens.get(2));
                match (real, display) {
                    (Some(r), Some(d)) => {
                        let rr = compile(r)?;
                        let dr = compile(d)?;
                        self.regex_pairs.push((rr, dr, source));
                        Ok(true)
                    }
                    _ => Err("R: entry needs real and display regex".to_string()),
                }
            }
            // `S:`/`S2:` Google-Safe-Browsing SHA-256 — hash-based, out of scope.
            b'S' => Ok(false),
            other => Err(format!("unknown .pdb/.gdb prefix '{}'", other as char)),
        }
    }
}

impl AllowListMatcher {
    pub fn is_empty(&self) -> bool {
        self.host_pairs.is_empty() && self.regex_pairs.is_empty() && self.host_regexes.is_empty()
    }

    /// Parse one `.wdb` line. `Ok(true)` if added, `Ok(false)` if skipped.
    pub fn add_line(&mut self, line: &str) -> Result<bool, String> {
        let tokens: Vec<&str> = line.split(':').collect();
        match flag_of(line) {
            // `M:realHost:displayHost` — literal allow pair.
            b'M' => match (tokens.get(1), tokens.get(2)) {
                (Some(r), Some(d)) => {
                    self.host_pairs
                        .push((r.trim().to_ascii_lowercase(), d.trim().to_ascii_lowercase()));
                    Ok(true)
                }
                _ => Err("M: entry needs real and display host".to_string()),
            },
            // `X:realRegex:displayRegex` — regex allow pair.
            b'X' => match (tokens.get(1), tokens.get(2)) {
                (Some(r), Some(d)) => {
                    self.regex_pairs.push((compile(r)?, compile(d)?));
                    Ok(true)
                }
                _ => Err("X: entry needs real and display regex".to_string()),
            },
            // `Y:realHostRegex` — real-host-only allow regex.
            b'Y' => match tokens.get(1) {
                Some(r) => {
                    self.host_regexes.push(compile(r)?);
                    Ok(true)
                }
                None => Err("Y: entry needs a host regex".to_string()),
            },
            other => Err(format!("unknown .wdb prefix '{}'", other as char)),
        }
    }

    /// True if `(real_url, display_url)` (and their hosts) are pardoned.
    fn allows(&self, real_url: &str, display_url: &str, real_host: &str, display_host: &str) -> bool {
        // X: full-URL regex pair.
        if self
            .regex_pairs
            .iter()
            .any(|(rr, dr)| rr.is_match(real_url) && dr.is_match(display_url))
        {
            return true;
        }
        // Y: real-host-only regex.
        if self.host_regexes.iter().any(|re| re.is_match(real_host)) {
            return true;
        }
        // M: literal host pair (subdomain-aware on each side).
        self.host_pairs
            .iter()
            .any(|(r, d)| host_suffix_match(real_host, r) && host_suffix_match(display_host, d))
    }
}

/// Combined protected + allow-list databases, owned by the `Database`.
#[derive(Debug, Default)]
pub struct PhishingDb {
    pub protected: ProtectedDomainMatcher,
    pub allow: AllowListMatcher,
}

impl PhishingDb {
    pub fn is_empty(&self) -> bool {
        self.protected.is_empty() && self.allow.is_empty()
    }

    /// Run the phishing heuristic over every `<a>`/`<area>` link pair in `html`,
    /// returning each detection. Mirrors `phishingScan` → `phishingCheck`.
    pub fn scan_html(&self, html: &[u8]) -> Vec<PhishMatch> {
        let mut out = Vec::new();
        if self.protected.is_empty() {
            return out; // nothing to protect → nothing to flag (ClamAV gate)
        }
        for (real, display) in extract_anchor_pairs(html) {
            if let Some(hit) = self.check_pair(&real, &display) {
                out.push(hit);
            }
        }
        out
    }

    /// The ordered `phishingCheck` decision procedure for one link pair
    /// (`phishcheck.c:1450-1648`). Returns `Some` only on a phishing verdict.
    fn check_pair(&self, real_raw: &str, display_raw: &str) -> Option<PhishMatch> {
        // 1. Empty real link → clean.
        if real_raw.trim().is_empty() {
            return None;
        }
        // 2. Real link must look like a URL.
        if !is_url(real_raw) {
            return None;
        }
        // 3. Identical raw links → clean.
        if real_raw == display_raw {
            return None;
        }
        // 4. Empty displayed link → clean.
        if display_raw.trim().is_empty() {
            return None;
        }
        // 5. Cleanup (lowercase host, strip spaces, decode %xx). Equal → clean.
        let real = cleanup_url(real_raw);
        let display = cleanup_url(display_raw);
        if real == display {
            return None;
        }
        // 6. Displayed link must look like a URL (else it's just link text).
        if !is_url(&display) {
            return None;
        }

        let real_host = get_host(&real);
        let display_host = get_host(&display);

        // 7-8. Allow list (X/Y/M) pardons the pair → clean.
        if self.allow.allows(&real, &display, &real_host, &display_host) {
            return None;
        }

        // 9. Protected R: regex pair arms the spoof gate.
        let mut domain_listed: Option<SourceLocation> = None;
        for (rr, dr, src) in &self.protected.regex_pairs {
            if rr.is_match(&real) && dr.is_match(&display) {
                domain_listed = Some(src.clone());
                break;
            }
        }

        // 10-11. Need both hosts; identical hosts → clean.
        if real_host.is_empty() || display_host.is_empty() {
            return None;
        }
        if real_host == display_host {
            return None;
        }

        // 13. Protected H: the *display* host belongs to a protected domain.
        if domain_listed.is_none() {
            if let Some(src) = self.protected.match_host_literal(&display_host) {
                domain_listed = Some(src);
            }
        }

        // 14. Null-byte cloak in the real link.
        let listed = domain_listed?; // 19. gate: only protected domains proceed
        if real_raw.bytes().any(|b| b == 0x00 || b == 0x01) || real_raw.contains("%00") {
            return Some(PhishMatch {
                name: "Heuristics.Phishing.Email.Cloaked.Null",
                source: listed,
            });
        }
        // 15. SSL spoof: display is https, real is not.
        if is_ssl(&display) && !is_ssl(&real) {
            return Some(PhishMatch {
                name: "Heuristics.Phishing.Email.SSL-Spoof",
                source: listed,
            });
        }
        // 20. Same registrable domain → clean.
        if get_domain(&real_host) == get_domain(&display_host) {
            return None;
        }
        // 21. Spoof verdict, specialised by cloak type (phishy_map).
        let name = if has_userinfo(&real) {
            "Heuristics.Phishing.Email.Cloaked.Username"
        } else if is_numeric(&real_host) {
            "Heuristics.Phishing.Email.Cloaked.NumericIP"
        } else {
            "Heuristics.Phishing.Email.SpoofedDomain"
        };
        Some(PhishMatch {
            name,
            source: listed,
        })
    }
}

impl ProtectedDomainMatcher {
    /// Return the defining source if `host` is, or is a subdomain of, a protected
    /// `H:` domain (`validate_subdomain` boundary semantics).
    fn match_host_literal(&self, host: &str) -> Option<SourceLocation> {
        if let Some(src) = self.host_literals.get(host) {
            return Some(src.clone());
        }
        // Subdomain: a protected `paypal.com` matches `www.paypal.com`.
        let mut idx = 0;
        while let Some(dot) = host[idx..].find('.') {
            let pos = idx + dot + 1;
            if let Some(src) = self.host_literals.get(&host[pos..]) {
                return Some(src.clone());
            }
            idx = pos;
        }
        None
    }
}

// ── URL / host / domain helpers (phishcheck.c) ─────────────────────────────

/// The flag letter of a regex-list line (`buffer[0]`).
fn flag_of(line: &str) -> u8 {
    line.bytes().next().unwrap_or(0).to_ascii_uppercase()
}

/// Compile a ClamAV phishing regex. The trailing `([/?].*)?` path-optional suffix
/// ClamAV strips for suffix indexing is harmless to keep when matching whole URLs.
fn compile(pattern: &str) -> Result<Regex, String> {
    let p = pattern.trim();
    Regex::new(p).map_err(|e| format!("invalid phishing regex '{p}': {e}"))
}

/// `cleanupURL`: lowercase, drop spaces/control bytes, decode `%xx` escapes.
fn cleanup_url(url: &str) -> String {
    let decoded = percent_decode(url.trim());
    let mut out = String::with_capacity(decoded.len());
    for ch in decoded.chars() {
        if ch.is_whitespace() || ch.is_control() {
            continue;
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// Decode `%xx` hex escapes; leave malformed escapes verbatim.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `isURL`: looks like a link — has a scheme, `//` authority, or a dotted host.
fn is_url(s: &str) -> bool {
    let s = s.trim();
    if s.contains("://") || s.starts_with("//") {
        return true;
    }
    if let Some(scheme_end) = s.find(':') {
        let scheme = &s[..scheme_end];
        if !scheme.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphabetic()) {
            return true; // mailto:, etc.
        }
    }
    // Bare `host.tld[/path]` — the displayed-text-as-URL case.
    let host = get_host(s);
    host.contains('.') && host.split('.').next_back().is_some_and(|t| t.len() >= 2)
}

/// `get_host`: the hostname of a URL — scheme and userinfo stripped, terminated
/// by the first `/?#:`. Lowercased.
fn get_host(url: &str) -> String {
    let mut s = url.trim();
    // Strip scheme.
    if let Some(pos) = s.find("://") {
        s = &s[pos + 3..];
    } else if let Some(stripped) = s.strip_prefix("//") {
        s = stripped;
    } else if let Some(pos) = s.find(':') {
        // `scheme:rest` with an alphabetic scheme (e.g. mailto:).
        let scheme = &s[..pos];
        if !scheme.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphabetic()) {
            s = &s[pos + 1..];
        }
    }
    // Authority ends at the first path/query/fragment delimiter.
    let auth_end = s
        .find(['/', '?', '#'])
        .unwrap_or(s.len());
    let mut auth = &s[..auth_end];
    // Strip userinfo (`user:pass@host`).
    if let Some(at) = auth.rfind('@') {
        auth = &auth[at + 1..];
    }
    // Strip port.
    let host = auth.split(':').next().unwrap_or(auth);
    host.trim_matches('.').to_ascii_lowercase()
}

/// True if the URL carries `user@` userinfo before the host (cloaking vector).
fn has_userinfo(url: &str) -> bool {
    let mut s = url.trim();
    if let Some(pos) = s.find("://") {
        s = &s[pos + 3..];
    }
    let auth_end = s
        .find(['/', '?', '#'])
        .unwrap_or(s.len());
    s[..auth_end].contains('@')
}

/// `get_domain`: the registrable domain of a host, TLD/ccTLD aware
/// (`phishcheck.c:422`). E.g. `www.paypal.com` → `paypal.com`,
/// `a.b.example.co.uk` → `example.co.uk`.
pub fn get_domain(host: &str) -> String {
    let host = host.trim_matches('.');
    let Some(tld_dot) = host.rfind('.') else {
        return host.to_string();
    };
    let tld = &host[tld_dot + 1..];
    let mut cut = tld_dot; // index of the dot before the registrable label

    if tld::is_cctld(tld) {
        // Country-code TLD: inspect the label left of it.
        let Some(second_dot) = host[..tld_dot].rfind('.') else {
            return host.to_string(); // only two levels, e.g. `domain.uk`
        };
        let second = &host[second_dot + 1..tld_dot];
        if !tld::is_tld(second) {
            // `subdomain.domain.uk` → `domain.uk`.
            return host[second_dot + 1..].to_string();
        }
        // `something.co.uk` — strip one more level below `co.uk`.
        cut = second_dot;
    }

    match host[..cut].rfind('.') {
        Some(dot) => host[dot + 1..].to_string(),
        None => host.to_string(),
    }
}

/// True if `host` equals `domain` or is a boundary subdomain of it.
fn host_suffix_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// `isNumeric`: a dotted IPv4 literal (`1.2.3.4`).
fn is_numeric(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets
            .iter()
            .all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()) && o.parse::<u32>().map(|n| n <= 256).unwrap_or(false))
}

/// `isSSL`: an https link.
fn is_ssl(url: &str) -> bool {
    url.trim_start().to_ascii_lowercase().starts_with("https:")
}

// ── HTML anchor extraction (htmlnorm.c link harvesting) ────────────────────

/// Upper bound on link pairs harvested from one document (pathological-input guard).
const MAX_ANCHORS: usize = 8192;

/// Extract `(real_url, displayed_text)` pairs from `<a href=…>…</a>` and
/// `<area href=…>` elements — the inputs ClamAV's phishing engine checks.
pub fn extract_anchor_pairs(html: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(html);
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut search = 0;

    while out.len() < MAX_ANCHORS {
        // Find the next `<a` or `<area` tag start.
        let Some(rel) = lower[search..].find("<a") else {
            break;
        };
        let tag_start = search + rel;
        // Must be `<a ` / `<a>` / `<area` — a real anchor, not `<abbr` etc.
        let after = lower.as_bytes().get(tag_start + 2).copied().unwrap_or(b' ');
        let is_area = lower[tag_start..].starts_with("<area");
        if !is_area && !matches!(after, b' ' | b'>' | b'\t' | b'\n' | b'\r' | b'/') {
            search = tag_start + 2;
            continue;
        }
        // End of the opening tag.
        let Some(rel_gt) = lower[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + rel_gt;
        let tag = &text[tag_start..tag_end];
        let href = extract_attr(tag, "href").unwrap_or_default();

        if is_area {
            // Void element — no inner text; displayed link is the href itself,
            // which ClamAV treats as no spoof. Skip pairing.
            search = tag_end + 1;
            if !href.is_empty() {
                out.push((href.clone(), href));
            }
            continue;
        }

        // Displayed text runs until the matching `</a>`.
        let content_start = tag_end + 1;
        let close = lower[content_start..]
            .find("</a")
            .map(|x| content_start + x)
            .unwrap_or(bytes.len());
        let display = strip_tags(&text[content_start..close]);
        if !href.is_empty() {
            out.push((href, display));
        }
        search = close + 3;
    }
    out
}

/// Read an HTML attribute value (quoted or bare) from an opening tag's text.
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find(attr) {
        let pos = from + rel;
        // Boundary before the attribute name (avoid matching inside another word).
        let before_ok = pos == 0
            || matches!(lower.as_bytes()[pos - 1], b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'/');
        let mut i = pos + attr.len();
        // Skip whitespace then require `=`.
        while i < lower.len() && lower.as_bytes()[i].is_ascii_whitespace() {
            i += 1;
        }
        if before_ok && i < lower.len() && lower.as_bytes()[i] == b'=' {
            i += 1;
            while i < lower.len() && lower.as_bytes()[i].is_ascii_whitespace() {
                i += 1;
            }
            let value = &tag[i..];
            let v = match value.as_bytes().first() {
                Some(b'"') => value[1..].split('"').next().unwrap_or(""),
                Some(b'\'') => value[1..].split('\'').next().unwrap_or(""),
                _ => value
                    .split(|c: char| c.is_whitespace() || c == '>')
                    .next()
                    .unwrap_or(""),
            };
            return Some(v.trim().to_string());
        }
        from = pos + attr.len();
    }
    None
}

/// Strip nested tags from anchor inner HTML, leaving the displayed text.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn src() -> SourceLocation {
        SourceLocation {
            path: Arc::from(PathBuf::from("daily.pdb").as_path()),
            line: 1,
        }
    }

    fn db_with(protected: &[&str], allow: &[&str]) -> PhishingDb {
        let mut db = PhishingDb::default();
        for p in protected {
            db.protected.add_line(p, src()).unwrap();
        }
        for a in allow {
            db.allow.add_line(a).unwrap();
        }
        db
    }

    #[test]
    fn get_host_strips_scheme_userinfo_port_path() {
        assert_eq!(get_host("http://www.evil.com/a/b?x=1"), "www.evil.com");
        assert_eq!(get_host("https://user:pass@evil.com:8443/x"), "evil.com");
        assert_eq!(get_host("paypal.com/login"), "paypal.com");
    }

    #[test]
    fn get_domain_is_tld_aware() {
        assert_eq!(get_domain("www.paypal.com"), "paypal.com");
        assert_eq!(get_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(get_domain("login.sub.sears.com"), "sears.com");
        assert_eq!(get_domain("domain.uk"), "domain.uk");
    }

    #[test]
    fn flags_spoofed_protected_domain() {
        // paypal.com is protected; a link DISPLAYING paypal.com but pointing at
        // evil.com is a spoof.
        let db = db_with(&["H:paypal.com"], &[]);
        let html = br#"<a href="http://evil.com/login">www.paypal.com</a>"#;
        let hits = db.scan_html(html);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Heuristics.Phishing.Email.SpoofedDomain");
    }

    #[test]
    fn same_domain_link_is_clean() {
        let db = db_with(&["H:paypal.com"], &[]);
        let html = br#"<a href="http://www.paypal.com/login">paypal.com</a>"#;
        assert!(db.scan_html(html).is_empty());
    }

    #[test]
    fn unprotected_domain_is_not_flagged() {
        // Gate: only protected display domains are subject to the spoof check.
        let db = db_with(&["H:paypal.com"], &[]);
        let html = br#"<a href="http://evil.com">www.chase.com</a>"#;
        assert!(db.scan_html(html).is_empty());
    }

    #[test]
    fn allow_list_pardons_known_pair() {
        // M: real:display literal allow pair suppresses the spoof.
        let db = db_with(
            &["H:apple.com"],
            &["M:news.apple.co.jp:images.apple.com"],
        );
        let html = br#"<a href="http://news.apple.co.jp/x">images.apple.com</a>"#;
        assert!(db.scan_html(html).is_empty());
    }

    #[test]
    fn allow_list_regex_pardons_pair() {
        let db = db_with(
            &["H:commerzbank.de"],
            &[r"X:.+\.commerzbank\.com([/?].*)?:.+\.commerzbank\.de"],
        );
        let html =
            br#"<a href="http://secure.commerzbank.com/x">login.commerzbank.de</a>"#;
        assert!(db.scan_html(html).is_empty());
    }

    #[test]
    fn numeric_ip_real_link_is_cloaked_numericip() {
        let db = db_with(&["H:paypal.com"], &[]);
        let html = br#"<a href="http://192.168.0.5/login">paypal.com</a>"#;
        let hits = db.scan_html(html);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Heuristics.Phishing.Email.Cloaked.NumericIP");
    }

    #[test]
    fn ssl_spoof_detected() {
        let db = db_with(&["H:bank.com"], &[]);
        let html = br#"<a href="http://bank.com.evil.org">https://bank.com</a>"#;
        let hits = db.scan_html(html);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Heuristics.Phishing.Email.SSL-Spoof");
    }

    #[test]
    fn skips_safebrowsing_hash_entries() {
        let mut m = ProtectedDomainMatcher::default();
        assert_eq!(m.add_line("S:P:0123abcd", src()).unwrap(), false);
        assert!(m.is_empty());
    }
}
