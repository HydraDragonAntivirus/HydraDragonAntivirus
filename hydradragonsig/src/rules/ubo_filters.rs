//! uBlock Origin / Adblock Plus static network filter lists for
//! `domain_blocklist` (syntax reference: uBlockOrigin/uAssets `filters/`).
//!
//! A static scanner has no page, request type or party, so only the part of a
//! filter that names a host or a URL is kept: `||host^` hostname filters, plain
//! hostname and hosts-file lines, `||host/path` / `|https://...` / `*`
//! wildcard URL patterns, `/regex/` filters and `@@` exceptions. Cosmetic
//! filters, comments, headers and filters whose effect is not "block this
//! request" are recognized and skipped. List files are untrusted: every limit
//! below is enforced and nothing here panics on hostile input.

// Byte regexes without Unicode: JavaScript regexes without the `u` flag (the
// uBO filter syntax) have ASCII `\w`, `\d`, `\s` and case folding.
use regex::bytes::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Category given to uBO entries when neither the load spec (`CATEGORY=PATH`)
/// nor a `! Category:` header names one.
pub(crate) const DEFAULT_CATEGORY: &str = "UNWANTED";
/// Largest list file that is read (includes count separately).
pub(crate) const MAX_LIST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LINE_LEN: usize = 8 * 1024;
const MAX_LINES: usize = 8_000_000;
const MAX_FILTERS: usize = 4_000_000;
const MAX_REGEX_FILTERS: usize = 8 * 1024;
const MAX_REGEX_SIZE: usize = 1 << 20;
/// Backtracking steps per URL for lookaround / backreference regexes.
const MAX_BACKTRACK_STEPS: usize = 100_000;
const MAX_IF_DEPTH: usize = 32;
const MAX_INCLUDE_DEPTH: usize = 2;
const MAX_CATEGORY_LEN: usize = 32;
const MAX_REJECTED_SAMPLES: usize = 16;
/// Unanchored URL patterns with fewer literal bytes match too much to be useful.
const MIN_GENERIC_LITERALS: usize = 4;
/// URLs are truncated to this many bytes before matching.
pub(crate) const MAX_URL_LEN: usize = 4096;

/// Options that turn a filter into something other than "block this request"
/// (parameter stripping, header/CSP injection, cosmetic or partial exceptions,
/// response-dependent conditions). Such filters never name a blocked host.
const NON_BLOCKING_OPTIONS: &[&str] = &[
    "removeparam", "queryprune", "csp", "header", "replace", "permissions",
    "redirect-rule", "urlskip", "uritransform", "urltransform", "cname",
    "generichide", "ghide", "elemhide", "ehide", "specifichide", "shide",
    "genericblock", "inline-script", "inline-font", "content",
    "jsinject", "extension", "stealth", "cookie", "hls", "jsonprune",
    "xmlprune", "referrerpolicy", "urlblock", "network",
];

/// Very common URL tokens: a pattern indexed by one of them would be checked
/// against almost every URL, so a rarer token of the same pattern is preferred.
const BAD_TOKENS: &[&str] = &["http", "https", "www", "com", "net", "org", "html", "php", "js"];

/// What a load did with the lines of uBO-syntax lists.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ListStats {
    /// Blocking filters kept (hostname, URL pattern and regex).
    pub blocks: usize,
    /// `@@` exception filters kept.
    pub exceptions: usize,
    /// Comments, headers, directives, cosmetic and non-blocking filters.
    pub ignored: usize,
    /// Malformed, unsupported or over-limit lines.
    pub rejected: usize,
    /// `!#include` files that were read.
    pub includes: usize,
}

#[derive(Debug, Clone, Copy)]
struct HostRule {
    category: u16,
    important: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Lit(u8),
    /// `^`: one separator byte, or the end of the URL.
    Sep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    None,
    /// `|...`: the URL starts with the pattern.
    Start,
    /// `||...`: the pattern starts at the hostname or one of its label boundaries.
    Host,
}

/// A wildcard URL pattern: `segments` are the `*`-separated parts.
#[derive(Debug)]
struct UrlFilter {
    anchor: Anchor,
    first_anchored: bool,
    end_anchored: bool,
    segments: Vec<Vec<Unit>>,
    exception: bool,
    important: bool,
    category: u16,
    /// Normalized filter text, for `$badfilter`.
    key: String,
}

/// `regex` runs every filter it can (linear time); lookaround and
/// backreferences fall back to `fancy-regex` with a bounded backtrack budget.
#[derive(Debug)]
enum UrlRegex {
    Linear(Regex),
    Backtracking(fancy_regex::Regex),
}

impl UrlRegex {
    fn is_match(&self, url: &str) -> bool {
        match self {
            UrlRegex::Linear(re) => re.is_match(url.as_bytes()),
            // A backtrack-limit error counts as no match.
            UrlRegex::Backtracking(re) => re.is_match(url).unwrap_or(false),
        }
    }
}

#[derive(Debug)]
struct RegexFilter {
    re: UrlRegex,
    /// The pattern of a `regex` (linear) filter, for the combined set.
    source: Option<String>,
    exception: bool,
    important: bool,
    category: u16,
    key: String,
}

/// A blocking verdict for one host or URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Block<'a> {
    pub category: &'a str,
    pub important: bool,
    /// The match came from a URL pattern / regex (report the URL, not the host).
    pub by_url: bool,
}

/// Parsed uBO network filters of every list loaded into one DB.
#[derive(Debug, Default)]
pub(crate) struct UboFilters {
    categories: Vec<String>,
    hosts: HashMap<String, HostRule>,
    host_exceptions: HashSet<String>,
    url_filters: Vec<UrlFilter>,
    token_index: HashMap<Vec<u8>, Vec<u32>>,
    untokenized: Vec<u32>,
    regexes: Vec<RegexFilter>,
    /// Every linear regex filter in one set (built by [`UboFilters::finish`]): a URL
    /// is matched against all of them in one pass instead of one regex at a time.
    regex_set: Option<regex::bytes::RegexSet>,
    /// Per filter of `regexes`: its index in `regex_set` (None: checked alone).
    regex_set_pos: Vec<Option<usize>>,
    /// Filters disabled by `$badfilter`, applied by [`UboFilters::finish`].
    badfilters: Vec<String>,
    lines: usize,
    pub stats: ListStats,
    /// First rejected lines (truncated), for load diagnostics.
    pub rejected_samples: Vec<String>,
}

enum Parsed {
    Host { host: String, exception: bool, important: bool },
    Url(UrlFilter),
    Regex(RegexFilter),
    BadFilter(String),
    Ignored,
    Rejected,
}

/// Splits `CATEGORY=PATH` into its parts. A spec that is an existing path, or
/// whose prefix is not a plain category name, is all path.
pub(crate) fn split_spec(spec: &str) -> (Option<String>, &str) {
    let spec = spec.trim();
    if let Some((cat, path)) = spec.split_once('=')
        && let Some(cat) = sanitize_category(cat)
        && !path.trim().is_empty() && !Path::new(spec).exists()
    {
        return (Some(cat), path.trim());
    }
    (None, spec)
}

fn sanitize_category(raw: &str) -> Option<String> {
    let cat = raw.trim();
    let ok = !cat.is_empty()
        && cat.len() <= MAX_CATEGORY_LEN
        && cat.as_bytes()[0].is_ascii_alphabetic()
        && cat.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok.then(|| cat.to_ascii_uppercase())
}

/// Reads a list file, refusing oversized ones; invalid UTF-8 is replaced.
pub(crate) fn read_list(path: &Path) -> std::io::Result<String> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_LIST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("list file is larger than {MAX_LIST_BYTES} bytes"),
        ));
    }
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_string())
}

/// `domain:CATEGORY` (or several joined with `|`): the original DB syntax.
pub(crate) fn is_legacy_line(line: &str) -> bool {
    if line.starts_with('|') || line.starts_with("@@") {
        return false;
    }
    let mut any = false;
    for piece in line.split('|') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let Some((domain, category)) = piece.rsplit_once(':') else {
            return false;
        };
        let domain = domain.trim();
        if domain.is_empty()
            || domain.contains(|c: char| {
                c.is_whitespace() || matches!(c, '/' | '^' | '$' | '*' | '@' | '[' | ']' | ':')
            })
            || sanitize_category(category).is_none()
        {
            return false;
        }
        any = true;
    }
    any
}

/// Element hiding, scriptlet, HTML and CSS filters of uBO, ABP and AdGuard:
/// `##`, `#@#`, `#?#`, `#@?#`, `#$#`, `#@$#`, `#%#`, `#$?#`, `$$`, `$@$`.
pub(crate) fn is_cosmetic(line: &str) -> bool {
    let b = line.as_bytes();
    for (i, _) in line.match_indices('#') {
        let mut j = i + 1;
        if b.get(j) == Some(&b'@') {
            j += 1;
        }
        if matches!(b.get(j), Some(b'?' | b'$' | b'%')) {
            j += 1;
        }
        if b.get(j) == Some(&b'?') {
            j += 1;
        }
        if b.get(j) == Some(&b'#') {
            return true;
        }
    }
    line.contains("$$") || line.contains("$@$")
}

fn is_sep(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'%'))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host.bytes().any(|b| b.is_ascii_alphanumeric())
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') || b >= 0x80)
}

/// Names the hosts files map to their own address; never blocked hosts.
fn is_hosts_file_self_name(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "localhost.localdomain" | "local" | "broadcasthost" | "0.0.0.0"
    ) || host.starts_with("ip6-")
}

/// `!#if` expressions: `||` of `&&` of optionally `!`-negated tokens.
/// Tokens uBO does not set on a desktop browser (and unknown ones) are false.
fn eval_if(expr: &str) -> bool {
    if expr.contains('(') || expr.contains(')') {
        return false;
    }
    expr.split("||").any(|conj| {
        conj.split("&&").all(|term| {
            let mut term = term.trim();
            let mut negate = false;
            while let Some(rest) = term.strip_prefix('!') {
                negate = !negate;
                term = rest.trim_start();
            }
            let value = matches!(
                term,
                "true"
                    | "ext_ublock"
                    | "env_chromium"
                    | "env_firefox"
                    | "env_edge"
                    | "cap_html_filtering"
                    | "cap_user_stylesheet"
            );
            value != negate
        })
    })
}

impl UboFilters {
    pub(crate) fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.host_exceptions.is_empty()
            && self.url_filters.is_empty()
            && self.regexes.is_empty()
    }

    /// Hostname entries (blocks and exceptions).
    pub(crate) fn host_entries(&self) -> usize {
        self.hosts.len() + self.host_exceptions.len()
    }

    /// True when URL patterns or regexes exist, i.e. URLs need a full check.
    pub(crate) fn has_url_filters(&self) -> bool {
        !self.url_filters.is_empty() || !self.regexes.is_empty()
    }

    fn category_id(&mut self, name: &str) -> u16 {
        if let Some(i) = self.categories.iter().position(|c| c == name) {
            return i as u16;
        }
        if self.categories.len() >= u16::MAX as usize {
            return 0;
        }
        self.categories.push(name.to_string());
        (self.categories.len() - 1) as u16
    }

    fn category_name(&self, id: u16) -> &str {
        self.categories
            .get(id as usize)
            .map(String::as_str)
            .unwrap_or(DEFAULT_CATEGORY)
    }

    fn filter_count(&self) -> usize {
        self.stats.blocks + self.stats.exceptions
    }

    /// Parses one list text. Lines in the original `domain:CATEGORY` syntax
    /// go to `legacy`; `base_dir` enables `!#include` of sibling files.
    pub(crate) fn parse_list(
        &mut self,
        text: &str,
        base_dir: Option<&Path>,
        default_category: &str,
        depth: usize,
        legacy: &mut dyn FnMut(&str),
    ) {
        let mut category = self.category_id(default_category);
        // Active state of every open `!#if` (beyond MAX_IF_DEPTH only counted).
        let mut if_stack: Vec<(bool, bool)> = Vec::new(); // (parent active, condition)
        let mut overflow_ifs = 0usize;
        let mut active = true;
        for raw in text.split(['\n', '\r']) {
            if self.lines >= MAX_LINES {
                self.stats.rejected += 1;
                break;
            }
            self.lines += 1;
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_LINE_LEN {
                self.reject(line);
                continue;
            }
            if let Some(directive) = line.strip_prefix("!#") {
                let (name, arg) = directive
                    .split_once(char::is_whitespace)
                    .map(|(n, a)| (n, a.trim()))
                    .unwrap_or((directive, ""));
                match name {
                    "if" => {
                        if if_stack.len() >= MAX_IF_DEPTH {
                            overflow_ifs += 1;
                            active = false;
                        } else {
                            let cond = eval_if(arg);
                            if_stack.push((active, cond));
                            active = active && cond;
                        }
                    }
                    "else" if overflow_ifs == 0 => {
                        if let Some(top) = if_stack.last_mut() {
                            top.1 = !top.1;
                            active = top.0 && top.1;
                        }
                    }
                    "endif" => {
                        if overflow_ifs > 0 {
                            overflow_ifs -= 1;
                        } else {
                            if_stack.pop();
                        }
                        active = overflow_ifs == 0
                            && if_stack.last().is_none_or(|&(parent, cond)| parent && cond);
                    }
                    "include" if active => {
                        let name = self.category_name(category).to_string();
                        self.include(arg, base_dir, &name, depth, legacy);
                    }
                    _ => {}
                }
                self.stats.ignored += 1;
                continue;
            }
            if !active {
                self.stats.ignored += 1;
                continue;
            }
            if let Some(comment) = line.strip_prefix('!') {
                if let Some((key, value)) = comment.trim().split_once(':')
                    && key.trim().eq_ignore_ascii_case("category")
                    && let Some(name) = sanitize_category(value)
                {
                    category = self.category_id(&name);
                }
                self.stats.ignored += 1;
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                self.stats.ignored += 1;
                continue;
            }
            if is_cosmetic(line) {
                self.stats.ignored += 1;
                continue;
            }
            if line.starts_with('#') || is_legacy_line(line) {
                legacy(line);
                continue;
            }
            if self.parse_hosts_line(line, category) {
                continue;
            }
            if self.filter_count() >= MAX_FILTERS {
                self.stats.rejected += 1;
                continue;
            }
            match parse_network(line, category) {
                Parsed::Host { host, exception, important } => {
                    if exception {
                        self.host_exceptions.insert(host);
                        self.stats.exceptions += 1;
                    } else {
                        let rule = HostRule { category, important };
                        self.hosts
                            .entry(host)
                            .and_modify(|r| r.important |= important)
                            .or_insert(rule);
                        self.stats.blocks += 1;
                    }
                }
                Parsed::Url(filter) => self.push_url_filter(filter),
                Parsed::Regex(filter) => {
                    if self.regexes.len() >= MAX_REGEX_FILTERS {
                        self.reject(line);
                    } else {
                        self.count(filter.exception);
                        self.regexes.push(filter);
                    }
                }
                Parsed::BadFilter(key) => {
                    self.badfilters.push(key);
                    self.stats.ignored += 1;
                }
                Parsed::Ignored => self.stats.ignored += 1,
                Parsed::Rejected => self.reject(line),
            }
        }
    }

    fn reject(&mut self, line: &str) {
        self.stats.rejected += 1;
        if self.rejected_samples.len() < MAX_REJECTED_SAMPLES {
            let mut end = line.len().min(160);
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            self.rejected_samples.push(line[..end].to_string());
        }
    }

    fn count(&mut self, exception: bool) {
        if exception {
            self.stats.exceptions += 1;
        } else {
            self.stats.blocks += 1;
        }
    }

    /// `!#include NAME`: a file next to the including list (no absolute paths,
    /// no `..`, no URLs), nested at most [`MAX_INCLUDE_DEPTH`] levels.
    fn include(
        &mut self,
        name: &str,
        base_dir: Option<&Path>,
        category: &str,
        depth: usize,
        legacy: &mut dyn FnMut(&str),
    ) {
        let Some(base) = base_dir else {
            self.stats.rejected += 1;
            return;
        };
        let rel = Path::new(name);
        let safe = !name.is_empty()
            && !name.contains(':')
            && !name.starts_with(['/', '\\'])
            && !rel.is_absolute()
            && rel
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
        if !safe || depth >= MAX_INCLUDE_DEPTH {
            self.stats.rejected += 1;
            return;
        }
        let path = base.join(rel);
        match read_list(&path) {
            Ok(text) => {
                self.stats.includes += 1;
                let dir = path.parent().map(Path::to_path_buf);
                self.parse_list(&text, dir.as_deref(), category, depth + 1, legacy);
            }
            Err(_) => self.stats.rejected += 1,
        }
    }

    /// `0.0.0.0 host [host...] [# comment]` (any IPv4/IPv6 address first).
    fn parse_hosts_line(&mut self, line: &str, category: u16) -> bool {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let Some(addr) = fields.next() else { return false };
        // A lone address is a hostname filter for that IP, not a hosts line.
        if addr.parse::<std::net::IpAddr>().is_err() || line.trim() == addr {
            return false;
        }
        let mut any = false;
        for host in fields {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            if is_hosts_file_self_name(&host) || host.parse::<std::net::IpAddr>().is_ok() {
                self.stats.ignored += 1;
                continue;
            }
            if !valid_host(&host) || self.filter_count() >= MAX_FILTERS {
                self.stats.rejected += 1;
                continue;
            }
            self.hosts
                .entry(host)
                .or_insert(HostRule { category, important: false });
            self.stats.blocks += 1;
            any = true;
        }
        if !any {
            self.stats.ignored += 1;
        }
        true
    }

    fn push_url_filter(&mut self, filter: UrlFilter) {
        self.count(filter.exception);
        self.index_url_filter(filter);
    }

    fn index_url_filter(&mut self, filter: UrlFilter) {
        let idx = self.url_filters.len() as u32;
        match best_token(&filter) {
            Some(token) => self.token_index.entry(token).or_default().push(idx),
            None => self.untokenized.push(idx),
        }
        self.url_filters.push(filter);
    }

    /// Applies `$badfilter` lines collected from every loaded list.
    pub(crate) fn finish(&mut self) {
        self.apply_badfilters();
        self.build_regex_set();
    }

    /// The linear regex filters as one [`regex::bytes::RegexSet`], same options as
    /// each filter (case-insensitive, no Unicode). Left out when it does not build:
    /// the filters are then checked one by one as before.
    fn build_regex_set(&mut self) {
        self.regex_set = None;
        self.regex_set_pos = vec![None; self.regexes.len()];
        let mut patterns = Vec::new();
        for (i, f) in self.regexes.iter().enumerate() {
            if let (UrlRegex::Linear(_), Some(src)) = (&f.re, &f.source) {
                self.regex_set_pos[i] = Some(patterns.len());
                patterns.push(src.as_str());
            }
        }
        if patterns.len() < 2 {
            self.regex_set_pos = vec![None; self.regexes.len()];
            return;
        }
        let set = regex::bytes::RegexSetBuilder::new(&patterns)
            .unicode(false)
            .case_insensitive(true)
            .size_limit(MAX_REGEX_SIZE * 64)
            .dfa_size_limit(MAX_REGEX_SIZE * 64)
            .build();
        match set {
            Ok(set) => self.regex_set = Some(set),
            Err(_) => self.regex_set_pos = vec![None; self.regexes.len()],
        }
    }

    fn apply_badfilters(&mut self) {
        if self.badfilters.is_empty() {
            return;
        }
        let bad: HashSet<String> = std::mem::take(&mut self.badfilters).into_iter().collect();
        for key in &bad {
            // A hostname filter is removed by any badfilter naming the same host.
            if let Parsed::Host { host, exception, .. } = parse_network(key, 0) {
                let removed = if exception {
                    self.host_exceptions.remove(&host)
                } else {
                    self.hosts.remove(&host).is_some()
                };
                if removed {
                    self.uncount(exception);
                }
            }
        }
        for filter in std::mem::take(&mut self.regexes) {
            if bad.contains(&filter.key) {
                self.uncount(filter.exception);
            } else {
                self.regexes.push(filter);
            }
        }
        if self.url_filters.iter().any(|f| bad.contains(&f.key)) {
            let filters = std::mem::take(&mut self.url_filters);
            self.token_index.clear();
            self.untokenized.clear();
            for filter in filters {
                if bad.contains(&filter.key) {
                    self.uncount(filter.exception);
                } else {
                    self.index_url_filter(filter);
                }
            }
        }
    }

    fn uncount(&mut self, exception: bool) {
        if exception {
            self.stats.exceptions = self.stats.exceptions.saturating_sub(1);
        } else {
            self.stats.blocks = self.stats.blocks.saturating_sub(1);
        }
    }

    /// Most specific hostname filter covering `host` (or a parent domain).
    pub(crate) fn host_block(&self, host: &str) -> Option<Block<'_>> {
        suffixes(host).find_map(|h| {
            self.hosts.get(h).map(|r| Block {
                category: self.category_name(r.category),
                important: r.important,
                by_url: false,
            })
        })
    }

    /// `@@||host^` covering `host` or a parent domain.
    pub(crate) fn host_excepted(&self, host: &str) -> bool {
        !self.host_exceptions.is_empty() && suffixes(host).any(|h| self.host_exceptions.contains(h))
    }

    fn candidates(&self, url: &[u8]) -> Vec<u32> {
        let mut out: Vec<u32> = self.untokenized.clone();
        if self.token_index.is_empty() {
            return out;
        }
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for token in url
            .split(|b| !b.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
        {
            if seen.insert(token) && let Some(list) = self.token_index.get(token) {
                out.extend_from_slice(list);
            }
        }
        out
    }

    /// First URL pattern / regex filter of the wanted kind matching `url`
    /// (lowercase, host at `host`).
    fn url_match(
        &self,
        url: &str,
        host: std::ops::Range<usize>,
        exception: bool,
        important_only: bool,
    ) -> Option<Block<'_>> {
        let bytes = url.as_bytes();
        let wanted = |e: bool, i: bool| e == exception && (!important_only || i);
        for idx in self.candidates(bytes) {
            let Some(f) = self.url_filters.get(idx as usize) else { continue };
            if wanted(f.exception, f.important) && filter_matches(f, bytes, &host) {
                return Some(Block {
                    category: self.category_name(f.category),
                    important: f.important,
                    by_url: true,
                });
            }
        }
        // First wanted filter in list order, as before; the set answers for every
        // linear filter at once.
        let set_hits = match &self.regex_set {
            Some(set) if self.regexes.iter().any(|f| wanted(f.exception, f.important)) => Some(set.matches(bytes)),
            _ => None,
        };
        self.regexes
            .iter()
            .enumerate()
            .find(|(i, f)| {
                wanted(f.exception, f.important)
                    && match (&set_hits, self.regex_set_pos.get(*i).copied().flatten()) {
                        (Some(hits), Some(pos)) => hits.matched(pos),
                        _ => f.re.is_match(url),
                    }
            })
            .map(|(_, f)| f)
            .map(|f| Block {
                category: self.category_name(f.category),
                important: f.important,
                by_url: true,
            })
    }

    pub(crate) fn url_block(
        &self,
        url: &str,
        host: std::ops::Range<usize>,
        important_only: bool,
    ) -> Option<Block<'_>> {
        self.url_match(url, host, false, important_only)
    }

    pub(crate) fn url_excepted(&self, url: &str, host: std::ops::Range<usize>) -> bool {
        self.url_match(url, host, true, false).is_some()
    }
}

/// `a.b.example.com`, `b.example.com`, `example.com`, `com`.
fn suffixes(host: &str) -> impl Iterator<Item = &str> {
    let host = host.trim_matches('.');
    std::iter::once(host).chain(
        host.match_indices('.')
            .map(move |(i, _)| &host[i + 1..])
            .filter(|h| !h.is_empty()),
    )
}

/// Byte range of the hostname in a `scheme://[user@]host[:port]/...` URL.
pub(crate) fn url_host_range(url: &str) -> Option<std::ops::Range<usize>> {
    let start = url.find("://")? + 3;
    let rest = &url[start..];
    let auth_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let auth = &rest[..auth_end];
    let host_start = auth.rfind('@').map(|i| i + 1).unwrap_or(0);
    let host = &auth[host_start..];
    let (h0, h1) = if let Some(inner) = host.strip_prefix('[') {
        (1, 1 + inner.find(']')?)
    } else {
        (0, host.find(':').unwrap_or(host.len()))
    };
    let host_str = &host[h0..h1];
    let trimmed = host_str.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let s = start + host_start + h0;
    Some(s..s + trimmed.len())
}

fn parse_network(line: &str, category: u16) -> Parsed {
    let (exception, body) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    // Regex filter: `/.../` optionally followed by `$options`.
    let regex_end = if body.len() >= 3 && body.starts_with('/') {
        if body.ends_with('/') {
            Some(body.len())
        } else {
            body.rfind("/$").filter(|&i| i > 0).map(|i| i + 1)
        }
    } else {
        None
    };
    let (pattern, options) = match regex_end {
        Some(end) => (&body[..end], body[end..].strip_prefix('$').unwrap_or("")),
        None => match body.rfind('$') {
            Some(i) => (&body[..i], &body[i + 1..]),
            None => (body, ""),
        },
    };

    let mut important = false;
    let mut badfilter = false;
    let mut ip_target: Option<String> = None;
    let mut kept_options: Vec<String> = Vec::new();
    for opt in options.split(',') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        let (name, value) = opt.split_once('=').unwrap_or((opt, ""));
        let name = name.trim().trim_start_matches('~').to_ascii_lowercase();
        match name.as_str() {
            "important" => important = true,
            "badfilter" => {
                badfilter = true;
                continue;
            }
            // Applies only on the listed pages: no page context in a file.
            "domain" | "from"
                if value
                    .split('|')
                    .map(str::trim)
                    .any(|v| !v.is_empty() && !v.starts_with('~')) =>
            {
                if !badfilter_pending(options) {
                    return Parsed::Ignored;
                }
            }
            // `$ipaddress=IP`: requests served from that address. A literal
            // IP is a host the file can reference; `lan`, ranges and regexes
            // depend on DNS resolution and are skipped.
            "ipaddress" => match value.trim().parse::<std::net::IpAddr>() {
                Ok(ip) => ip_target = Some(ip.to_string()),
                Err(_) if !badfilter_pending(options) => return Parsed::Ignored,
                Err(_) => {}
            },
            n if NON_BLOCKING_OPTIONS.contains(&n)
                && !badfilter_pending(options) => {
                    return Parsed::Ignored;
                }
            _ => {}
        }
        kept_options.push(opt.to_ascii_lowercase());
    }
    let key = filter_key(exception, pattern, &mut kept_options);
    if badfilter {
        return Parsed::BadFilter(key);
    }
    if let Some(ip) = ip_target {
        // Only "anything served from IP" filters reduce to a host; a URL
        // pattern combined with an address condition cannot be evaluated.
        return if matches!(pattern, "" | "*" | "|" | "||" | "||*") {
            Parsed::Host { host: ip, exception, important }
        } else {
            Parsed::Ignored
        };
    }
    if pattern.is_empty() {
        return Parsed::Rejected;
    }

    if let Some(end) = regex_end {
        let source = &pattern[1..end - 1];
        let linear = RegexBuilder::new(source)
            .unicode(false)
            .case_insensitive(true)
            .size_limit(MAX_REGEX_SIZE)
            .dfa_size_limit(MAX_REGEX_SIZE)
            .build()
            .map(UrlRegex::Linear);
        let set_source = linear.is_ok().then(|| source.to_string());
        let re = linear.or_else(|_| {
            fancy_regex::RegexBuilder::new(source)
                .case_insensitive(true)
                .backtrack_limit(MAX_BACKTRACK_STEPS)
                .delegate_size_limit(MAX_REGEX_SIZE)
                .delegate_dfa_size_limit(MAX_REGEX_SIZE)
                .build()
                .map(UrlRegex::Backtracking)
        });
        return match re {
            Ok(re) => Parsed::Regex(RegexFilter { re, source: set_source, exception, important, category, key }),
            Err(_) => Parsed::Rejected,
        };
    }

    let lower = pattern.to_ascii_lowercase();
    let (anchor, rest) = if let Some(r) = lower.strip_prefix("||") {
        (Anchor::Host, r)
    } else if let Some(r) = lower.strip_prefix('|') {
        (Anchor::Start, r)
    } else {
        (Anchor::None, lower.as_str())
    };
    let (rest, end_anchored) = match rest.strip_suffix('|') {
        Some(r) if !r.is_empty() => (r, true),
        _ => (rest, false),
    };

    // Hostname filter: `||host^`, `||host^|`, `||host`, or a plain hostname.
    let host_part = rest.strip_suffix('^').unwrap_or(rest).trim_end_matches('.');
    let is_host = match anchor {
        Anchor::Host => valid_host(host_part),
        Anchor::None => !end_anchored && host_part == rest && host_part.contains('.') && valid_host(host_part),
        Anchor::Start => false,
    };
    if is_host {
        return Parsed::Host { host: host_part.to_string(), exception, important };
    }

    let mut segments: Vec<Vec<Unit>> = Vec::new();
    let mut literals = 0usize;
    let mut has_alnum = false;
    for part in rest.split('*') {
        let units: Vec<Unit> = part
            .bytes()
            .map(|b| if b == b'^' { Unit::Sep } else { Unit::Lit(b) })
            .collect();
        for u in &units {
            if let Unit::Lit(b) = u {
                literals += 1;
                has_alnum |= b.is_ascii_alphanumeric();
            }
        }
        segments.push(units);
    }
    let first_anchored = anchor != Anchor::None && segments.first().is_some_and(|s| !s.is_empty());
    let end_anchored = end_anchored && segments.last().is_some_and(|s| !s.is_empty());
    segments.retain(|s| !s.is_empty());
    if segments.is_empty() || !has_alnum || (anchor == Anchor::None && literals < MIN_GENERIC_LITERALS) {
        return Parsed::Rejected;
    }
    Parsed::Url(UrlFilter {
        anchor,
        first_anchored,
        end_anchored,
        segments,
        exception,
        important,
        category,
        key,
    })
}

/// A non-blocking option inside a `$badfilter` line still names a filter to
/// disable, so it must not short-circuit the parse.
fn badfilter_pending(options: &str) -> bool {
    options
        .split(',')
        .any(|o| o.trim().eq_ignore_ascii_case("badfilter"))
}

fn filter_key(exception: bool, pattern: &str, options: &mut [String]) -> String {
    options.sort();
    let mut key = String::with_capacity(pattern.len() + 16);
    if exception {
        key.push_str("@@");
    }
    key.push_str(&pattern.to_ascii_lowercase());
    if !options.is_empty() {
        key.push('$');
        key.push_str(&options.join(","));
    }
    key
}

/// Longest alphanumeric literal run of the pattern that is a whole URL token
/// (bounded by separators or anchors, never by `*` or an open pattern end).
fn best_token(f: &UrlFilter) -> Option<Vec<u8>> {
    let mut best: Option<(bool, Vec<u8>)> = None; // (is bad token, token)
    let last_seg = f.segments.len().saturating_sub(1);
    for (si, seg) in f.segments.iter().enumerate() {
        let mut i = 0;
        while i < seg.len() {
            if !matches!(seg[i], Unit::Lit(b) if b.is_ascii_alphanumeric()) {
                i += 1;
                continue;
            }
            let start = i;
            while i < seg.len() && matches!(seg[i], Unit::Lit(b) if b.is_ascii_alphanumeric()) {
                i += 1;
            }
            let left_ok = if start == 0 {
                si == 0 && f.first_anchored
            } else {
                true // previous unit is a separator or a non-alphanumeric literal
            };
            let right_ok = if i == seg.len() {
                si == last_seg && f.end_anchored
            } else {
                true
            };
            if !(left_ok && right_ok) {
                continue;
            }
            let token: Vec<u8> = seg[start..i]
                .iter()
                .filter_map(|u| match u {
                    Unit::Lit(b) => Some(*b),
                    Unit::Sep => None,
                })
                .collect();
            let bad = BAD_TOKENS.iter().any(|t| t.as_bytes() == token.as_slice());
            let better = match &best {
                None => true,
                Some((best_bad, best_tok)) => {
                    (*best_bad && !bad) || (*best_bad == bad && token.len() > best_tok.len())
                }
            };
            if better {
                best = Some((bad, token));
            }
        }
    }
    best.map(|(_, t)| t)
}

/// Matches `seg` at `p`; returns the end offset.
fn seg_match_at(seg: &[Unit], text: &[u8], p: usize) -> Option<usize> {
    let mut i = p;
    for unit in seg {
        match *unit {
            Unit::Lit(b) => {
                if text.get(i) != Some(&b) {
                    return None;
                }
                i += 1;
            }
            Unit::Sep => {
                if i < text.len() {
                    if !is_sep(text[i]) {
                        return None;
                    }
                    i += 1;
                }
            }
        }
    }
    Some(i)
}

/// Leftmost match of `seg` at or after `from`; returns the end offset.
fn seg_find(seg: &[Unit], text: &[u8], from: usize) -> Option<usize> {
    if let Some(Unit::Lit(first)) = seg.first() {
        let mut p = from;
        while p < text.len() {
            let off = memchr::memchr(*first, &text[p..])?;
            if let Some(end) = seg_match_at(seg, text, p + off) {
                return Some(end);
            }
            p += off + 1;
        }
        return None;
    }
    (from..=text.len()).find_map(|p| seg_match_at(seg, text, p))
}

fn match_from(f: &UrlFilter, text: &[u8], start: usize, first_anchored: bool) -> bool {
    let n = f.segments.len();
    let mut pos = start;
    for (i, seg) in f.segments.iter().enumerate() {
        let last = i + 1 == n;
        if i == 0 && first_anchored {
            let Some(end) = seg_match_at(seg, text, pos) else { return false };
            if last && f.end_anchored && end != text.len() {
                return false;
            }
            pos = end;
            continue;
        }
        if last && f.end_anchored {
            let lo = text.len().saturating_sub(seg.len()).max(pos);
            return (lo..=text.len()).any(|p| seg_match_at(seg, text, p) == Some(text.len()));
        }
        let Some(end) = seg_find(seg, text, pos) else { return false };
        pos = end;
    }
    true
}

fn filter_matches(f: &UrlFilter, url: &[u8], host: &std::ops::Range<usize>) -> bool {
    match f.anchor {
        Anchor::None => match_from(f, url, 0, false),
        Anchor::Start => match_from(f, url, 0, f.first_anchored),
        Anchor::Host => {
            if !f.first_anchored {
                return match_from(f, url, host.start, false);
            }
            let end = host.end.min(url.len());
            if host.start >= end {
                return false;
            }
            std::iter::once(host.start)
                .chain((host.start + 1..end).filter(|&i| url[i - 1] == b'.'))
                .any(|s| match_from(f, url, s, true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::DomainCategoryDb;

    fn parse(text: &str) -> UboFilters {
        parse_with(text, DEFAULT_CATEGORY)
    }

    fn parse_with(text: &str, category: &str) -> UboFilters {
        let mut filters = UboFilters::default();
        let mut legacy = Vec::new();
        filters.parse_list(text, None, category, 0, &mut |l| legacy.push(l.to_string()));
        filters.finish();
        assert!(legacy.is_empty(), "unexpected legacy lines {legacy:?}");
        filters
    }

    /// Category of a URL block, `None` when unlisted or excepted.
    fn url_cat<'a>(f: &'a UboFilters, url: &str) -> Option<&'a str> {
        let host = url_host_range(url).expect("url with host");
        let host_str = &url[host.clone()];
        let block = f.host_block(host_str).or_else(|| f.url_block(url, host.clone(), false))?;
        if !f.host_excepted(host_str) && !f.url_excepted(url, host.clone()) {
            return Some(block.category);
        }
        f.host_block(host_str)
            .filter(|b| b.important)
            .or_else(|| f.url_block(url, host, true))
            .map(|b| b.category)
    }

    #[test]
    fn hostname_filters_cover_subdomains() {
        let f = parse("||evil.example^\n||other.example^$doc,3p\n||plain.example\n");
        assert_eq!(f.stats.blocks, 3);
        assert_eq!(f.host_block("evil.example").unwrap().category, "UNWANTED");
        assert!(f.host_block("a.b.evil.example").is_some());
        assert!(f.host_block("notevil.example").is_none());
        assert!(f.host_block("other.example").is_some());
        assert!(f.host_block("plain.example").is_some());
    }

    #[test]
    fn options_are_ignored_or_skip_non_blocking_filters() {
        let f = parse(
            "||a.example^$all\n||b.example^$important\n||c.example^$3p,popup\n\
             ||d.example^$removeparam=utm_source\n||e.example^$domain=site.example\n\
             ||f.example^$from=~site.example\n||g.example^$csp=script-src 'none'\n",
        );
        assert!(f.host_block("a.example").is_some());
        assert!(f.host_block("b.example").unwrap().important);
        assert!(f.host_block("c.example").is_some());
        assert!(f.host_block("d.example").is_none(), "removeparam does not block");
        assert!(f.host_block("e.example").is_none(), "page-restricted filter");
        assert!(f.host_block("f.example").is_some(), "negated-only domain= applies everywhere");
        assert!(f.host_block("g.example").is_none(), "csp does not block");
        assert_eq!(f.stats.blocks, 4);
        assert_eq!(f.stats.ignored, 3);
    }

    #[test]
    fn exceptions_override_blocks_unless_important() {
        let f = parse(
            "||evil.example^\n@@||good.evil.example^\n||hard.example^$important\n\
             @@||hard.example^\n@@||cdn.example^$ghide\n||cdn.example^\n",
        );
        assert_eq!(url_cat(&f, "https://x.evil.example/a"), Some("UNWANTED"));
        assert_eq!(url_cat(&f, "https://good.evil.example/a"), None);
        assert_eq!(url_cat(&f, "https://sub.good.evil.example/a"), None);
        assert_eq!(url_cat(&f, "https://hard.example/"), Some("UNWANTED"));
        assert_eq!(url_cat(&f, "https://cdn.example/"), Some("UNWANTED"), "$ghide is not a whitelist");
        assert_eq!(f.stats.exceptions, 2);
    }

    #[test]
    fn plain_hostnames_and_hosts_file_lines() {
        let f = parse(
            "plain.example\n0.0.0.0 ads.example tracker.example # comment\n\
             127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n:: v6.example\n",
        );
        for host in ["plain.example", "ads.example", "tracker.example", "v6.example", "x.ads.example"] {
            assert!(f.host_block(host).is_some(), "{host}");
        }
        assert!(f.host_block("localhost").is_none());
        assert_eq!(f.stats.blocks, 4);

        // `*$doc,ipaddress=IP` (badware list) blocks that IP; other address
        // conditions need DNS and are skipped.
        let f = parse("*$doc,ipaddress=185.100.85.248
$doc,ipaddress=10.0.0.1
*$doc,ipaddress=lan
||x.example^$ipaddress=1.2.3.4
");
        assert!(f.host_block("185.100.85.248").is_some());
        assert!(f.host_block("10.0.0.1").is_some());
        assert!(f.host_block("x.example").is_none());
        assert_eq!((f.stats.blocks, f.stats.ignored), (2, 2));

        // A lone IP line (URLhaus lists) is a hostname filter for that IP.
        let f = parse("1.94.221.183\n");
        assert_eq!(url_cat(&f, "http://1.94.221.183/bins/x.sh"), Some("UNWANTED"));
    }

    #[test]
    fn comments_headers_and_cosmetic_filters_are_skipped() {
        let f = parse(
            "[Adblock Plus 2.0]\n! Title: test\n! comment ||not.example^\n\
             example.com##.ad-banner\nexample.com#@#.ad\n##.generic\n\
             example.com#?#div:has(> a)\nexample.com##+js(nowoif)\n\
             example.com#$#body { color: red }\nexample.com#%#//scriptlet('x')\n\
             example.com$$script[src]\nexample.com#@?#.x\n||real.example^\n",
        );
        assert_eq!(f.stats.blocks, 1);
        assert!(f.host_block("real.example").is_some());
        assert!(f.host_block("example.com").is_none());
        assert!(f.host_block("not.example").is_none());
        assert_eq!(f.stats.rejected, 0);
    }

    #[test]
    fn malformed_lines_are_rejected_without_panicking() {
        let long = format!("||{}.example^", "a".repeat(MAX_LINE_LEN));
        let f = parse(&format!(
            "||^\n||\n|\n@@\n$important\n*$image\n/[unclosed/\n/(?<=x)y/\n\
             ||a..b^\nab\n||*^\n{long}\n||\u{00e9}\u{0301}^$\n||ok.example^\n"
        ));
        assert!(f.host_block("ok.example").is_some());
        assert!(f.stats.rejected >= 9, "{:?}", f.stats);
        assert_eq!(f.stats.exceptions, 0);
    }

    #[test]
    fn url_patterns_and_wildcards() {
        let f = parse_with(
            "||files.example/payload/*.exe\n|https://drop.example/gate.php|\n\
             /malicious-path/\n||cdn.example^*/stage2^\n||*.zz/x\n",
            "MALWARE",
        );
        assert_eq!(url_cat(&f, "https://files.example/payload/a/b.exe"), Some("MALWARE"));
        assert_eq!(url_cat(&f, "http://eu.files.example/payload/b.exe"), Some("MALWARE"));
        assert_eq!(url_cat(&f, "https://files.example/other/b.exe"), None);
        assert_eq!(url_cat(&f, "https://notfiles.example/payload/b.exe"), None);
        assert_eq!(url_cat(&f, "https://drop.example/gate.php"), Some("MALWARE"));
        assert_eq!(url_cat(&f, "https://drop.example/gate.php?x=1"), None, "end anchor");
        assert_eq!(url_cat(&f, "http://drop.example/gate.php"), None, "start anchor");
        assert_eq!(url_cat(&f, "http://any.example/x/malicious-path/y"), Some("MALWARE"));
        assert_eq!(url_cat(&f, "http://cdn.example/a/stage2"), Some("MALWARE"));
        assert_eq!(url_cat(&f, "http://cdn.example/a/stage2x"), None, "^ separator");
        assert!(f.host_block("files.example").is_none(), "path filters do not list the host");
    }

    #[test]
    fn url_exceptions_override_url_and_host_blocks() {
        let f = parse("||evil.example^\n@@||evil.example/safe/*\n/tracker-js/\n@@/tracker-js/ok^\n");
        assert_eq!(url_cat(&f, "https://evil.example/bad"), Some("UNWANTED"));
        assert_eq!(url_cat(&f, "https://evil.example/safe/x"), None);
        assert_eq!(url_cat(&f, "https://h.example/tracker-js/a"), Some("UNWANTED"));
        assert_eq!(url_cat(&f, "https://h.example/tracker-js/ok/a"), None);
    }

    #[test]
    fn regex_filters() {
        let f = parse("/^https?:\\/\\/[a-z]{8}\\.top\\/[0-9]+$/$doc\n@@/allowed\\d/\n/[unclosed/\n");
        assert_eq!(f.regexes.len(), 2, "invalid regex is rejected");
        // Unicode `\w{40,}` would exceed the size limit; JS `\w` is ASCII.
        let g = parse("/[0-9a-z]{3,}\\.top\\/\\?utm_campaign=\\w{40,}/$doc\n");
        assert_eq!(g.regexes.len(), 1, "{:?}", g.rejected_samples);
        assert_eq!(url_cat(&f, "https://abcdefgh.top/123"), Some("UNWANTED"));
        assert_eq!(url_cat(&f, "https://abc.top/123"), None);
        assert_eq!(url_cat(&f, "https://abcdefgh.top/allowed1"), None);

        // Lookahead and backreferences (badware list) run on fancy-regex.
        let h = parse(
            "/\\.cloudfront\\.net\\/(?=[a-z]{0,6}\\d)[a-f0-9]{7}\\.js$/$script,3p\n\
             /^https:\\/\\/[0-9a-z]{7}\\.([0-9a-z]{7})\\.top\\/[0-9a-z]{7}\\?t=\\1&cid=[0-9a-z]+/$doc\n",
        );
        assert_eq!(h.regexes.len(), 2, "{:?}", h.rejected_samples);
        assert_eq!(url_cat(&h, "https://d1.cloudfront.net/abc1def.js"), Some("UNWANTED"));
        assert_eq!(url_cat(&h, "https://d1.cloudfront.net/abcdeff.js"), None, "lookahead needs a digit");
        assert_eq!(url_cat(&h, "https://aaaaaaa.bbbbbbb.top/ccccccc?t=bbbbbbb&cid=1"), Some("UNWANTED"));
        assert_eq!(url_cat(&h, "https://aaaaaaa.bbbbbbb.top/ccccccc?t=xxxxxxx&cid=1"), None, "backreference");

        // Catastrophic backtracking hits the step limit and counts as no match.
        let slow = parse("/^(?=x)(a+)+\\1$/\n");
        let url = format!("http://h.example/{}b", "a".repeat(64));
        assert_eq!(url_cat(&slow, &url), None);
    }

    #[test]
    fn preprocessor_directives() {
        let f = parse(
            "!#if false\n||skip1.example^\n!#else\n||keep1.example^\n!#endif\n\
             !#if env_mobile\n||skip2.example^\n!#endif\n\
             !#if !env_mobile && ext_ublock\n||keep2.example^\n\
             !#if adguard\n||skip3.example^\n!#endif\n!#endif\n\
             !#if (env_firefox)\n||skip4.example^\n!#endif\n\
             !#endif\n!#endif\n||keep3.example^\n!#include other.txt\n",
        );
        for host in ["keep1.example", "keep2.example", "keep3.example"] {
            assert!(f.host_block(host).is_some(), "{host}");
        }
        for host in ["skip1.example", "skip2.example", "skip3.example", "skip4.example"] {
            assert!(f.host_block(host).is_none(), "{host}");
        }
        assert_eq!(f.stats.rejected, 1, "include without a list directory");
    }

    #[test]
    fn deep_if_nesting_is_bounded() {
        let mut text = String::new();
        for _ in 0..(MAX_IF_DEPTH * 3) {
            text.push_str("!#if true\n");
        }
        text.push_str("||deep.example^\n");
        for _ in 0..(MAX_IF_DEPTH * 3) {
            text.push_str("!#endif\n");
        }
        text.push_str("||after.example^\n");
        let f = parse(&text);
        assert!(f.host_block("deep.example").is_none());
        assert!(f.host_block("after.example").is_some());
    }

    #[test]
    fn badfilter_disables_filters() {
        let f = parse(
            "||evil.example^\n||evil.example^$badfilter\n||path.example/x/*\n\
             ||path.example/x/*$badfilter\n/re[0-9]/\n/re[0-9]/$badfilter\n||kept.example^\n",
        );
        assert!(f.host_block("evil.example").is_none());
        assert_eq!(url_cat(&f, "https://path.example/x/y"), None);
        assert_eq!(url_cat(&f, "https://h.example/re1"), None);
        assert!(f.host_block("kept.example").is_some());
        assert_eq!(f.stats.blocks, 1);
    }

    #[test]
    fn category_header_and_spec() {
        let f = parse_with(
            "||a.example^\n! Category: Phishing\n||b.example^\n! Category: bad name!\n||c.example^\n",
            "MALWARE",
        );
        assert_eq!(f.host_block("a.example").unwrap().category, "MALWARE");
        assert_eq!(f.host_block("b.example").unwrap().category, "PHISHING");
        assert_eq!(f.host_block("c.example").unwrap().category, "PHISHING");

        assert_eq!(split_spec("malware=lists/x.txt"), (Some("MALWARE".to_string()), "lists/x.txt"));
        assert_eq!(split_spec(r"C:\lists\x.txt"), (None, r"C:\lists\x.txt"));
        assert_eq!(split_spec("lists/a=b.txt"), (None, "lists/a=b.txt"));
    }

    #[test]
    fn legacy_lines_are_recognized() {
        assert!(is_legacy_line("evil.example:MALWARE"));
        assert!(is_legacy_line("a.example:MALWARE|b.example: UNWANTED "));
        assert!(!is_legacy_line("||evil.example^"));
        assert!(!is_legacy_line("evil.example"));
        assert!(!is_legacy_line(":: evil.example"));
        assert!(!is_legacy_line("evil.example:8080"));
        assert!(!is_legacy_line("|https://evil.example:443/x"));
    }

    #[test]
    fn mixed_db_keeps_legacy_entries_and_applies_exceptions() {
        let db = DomainCategoryDb::from_text_with_category(
            "# legacy\nlegacy.example:MALWARE|other.example:PHISHING\n\
             ||ubo.example^\n0.0.0.0 hosts.example\n@@||legacy.example^\n",
            "MALWARE",
        );
        assert_eq!(db.entries, 5);
        assert_eq!(db.category("other.example"), Some("PHISHING"));
        assert_eq!(db.category("www.other.example"), Some("PHISHING"));
        assert_eq!(db.category("sub.other.example"), None, "legacy entries stay exact");
        assert_eq!(db.category("legacy.example"), None, "@@ exception wins");
        assert_eq!(db.category("x.ubo.example"), Some("MALWARE"));
        assert_eq!(db.category("hosts.example"), Some("MALWARE"));
    }

    #[test]
    fn include_reads_sibling_files_only() {
        let dir = std::env::temp_dir()
            .join(format!("hydradragonsig_ubo_include_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("main.txt"),
            "||main.example^\n!#include sub.txt\n!#include ../escape.txt\n!#include C:/abs.txt\n",
        )
        .unwrap();
        std::fs::write(dir.join("sub.txt"), "||sub.example^\n!#include sub.txt\n").unwrap();
        let spec = format!("PHISHING={}", dir.join("main.txt").display());
        let db = DomainCategoryDb::load_spec(&spec).unwrap();
        assert_eq!(db.category("main.example"), Some("PHISHING"));
        assert_eq!(db.category("sub.example"), Some("PHISHING"));
        let stats = db.list_stats();
        assert_eq!(stats.includes, 2, "self-include stops at the depth limit");
        assert_eq!(stats.rejected, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_range_parsing() {
        let url = "https://user:pw@sub.evil.example:8443/a?b";
        assert_eq!(&url[url_host_range(url).unwrap()], "sub.evil.example");
        let url = "http://[::1]:80/";
        assert_eq!(&url[url_host_range(url).unwrap()], "::1");
        assert!(url_host_range("http:///x").is_none());
        assert!(url_host_range("no scheme").is_none());
    }
}
