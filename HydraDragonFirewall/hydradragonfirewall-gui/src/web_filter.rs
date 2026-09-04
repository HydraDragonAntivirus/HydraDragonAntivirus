use glob::glob;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, RwLock};

// Use lazy_static to compile regex patterns lazily (on first use, not on startup)
// This prevents stack overflow during initialization
// Hardcoded regexes removed in favor of SDK signatures

#[derive(Clone, Debug, Default)]
struct CidrIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrIndex {
    fn add(&mut self, cidr: &str) -> bool {
        let trimmed = cidr.trim();
        if trimmed == "0.0.0.0/0"
            || trimmed == "0.0.0.0"
            || trimmed == "::/0"
            || trimmed == "::"
            || trimmed.ends_with("/0")
        {
            return false;
        }
        match Self::parse_interval(cidr) {
            Some(CidrInterval::V4(start, end)) => {
                self.v4.push((start, end));
                true
            }
            Some(CidrInterval::V6(start, end)) => {
                self.v6.push((start, end));
                true
            }
            None => false,
        }
    }

    fn normalize(&mut self) {
        Self::merge_intervals_u32(&mut self.v4);
        Self::merge_intervals_u128(&mut self.v6);
    }

    fn contains(&self, ip: IpAddr) -> bool {
        if ip.is_unspecified() || ip.is_loopback() {
            return false;
        }
        match ip {
            IpAddr::V4(ipv4) => Self::contains_value(&self.v4, u32::from(ipv4)),
            IpAddr::V6(ipv6) => Self::contains_value(&self.v6, u128::from(ipv6)),
        }
    }

    fn parse_interval(cidr: &str) -> Option<CidrInterval> {
        let cidr = cidr.trim();
        if let Some((network, prefix)) = cidr.split_once('/') {
            let prefix_len = prefix.parse::<u32>().ok()?;

            if let Ok(ipv4) = network.parse::<Ipv4Addr>() {
                // 0.0.0.0/0 protection: prefix_len == 0 or unspecified IP matches entire IPv4 space
                if prefix_len == 0 || prefix_len > 32 || ipv4.is_unspecified() {
                    return None;
                }
                let mask = !0u32 << (32 - prefix_len);
                let start = u32::from(ipv4) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V4(start, end));
            }

            if let Ok(ipv6) = network.parse::<Ipv6Addr>() {
                // ::/0 protection: prefix_len == 0 or unspecified IP matches entire IPv6 space
                if prefix_len == 0 || prefix_len > 128 || ipv6.is_unspecified() {
                    return None;
                }
                let mask = !0u128 << (128 - prefix_len);
                let start = u128::from(ipv6) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V6(start, end));
            }

            return None;
        }

        match cidr.parse::<IpAddr>().ok()? {
            IpAddr::V4(ipv4) => {
                if ipv4.is_unspecified() || ipv4.is_broadcast() {
                    return None;
                }
                let value = u32::from(ipv4);
                Some(CidrInterval::V4(value, value))
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unspecified() {
                    return None;
                }
                let value = u128::from(ipv6);
                Some(CidrInterval::V6(value, value))
            }
        }
    }

    fn merge_intervals_u32(intervals: &mut Vec<(u32, u32)>) {
        intervals.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(intervals.len());

        for &(start, end) in intervals.iter() {
            let Some(last) = merged.last_mut() else {
                merged.push((start, end));
                continue;
            };

            if start > last.1.saturating_add(1) {
                merged.push((start, end));
            } else if end > last.1 {
                last.1 = end;
            }
        }

        *intervals = merged;
    }

    fn merge_intervals_u128(intervals: &mut Vec<(u128, u128)>) {
        intervals.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(intervals.len());

        for &(start, end) in intervals.iter() {
            let Some(last) = merged.last_mut() else {
                merged.push((start, end));
                continue;
            };

            if start > last.1.saturating_add(1) {
                merged.push((start, end));
            } else if end > last.1 {
                last.1 = end;
            }
        }

        *intervals = merged;
    }

    fn contains_value<T>(intervals: &[(T, T)], value: T) -> bool
    where
        T: Copy + Ord,
    {
        let index = intervals.partition_point(|&(start, _)| start <= value);
        index > 0 && intervals[index - 1].1 >= value
    }
}

enum CidrInterval {
    V4(u32, u32),
    V6(u128, u128),
}

#[derive(Clone)]
pub struct WebFilter {
    ipv4_blocklist: Arc<RwLock<HashSet<Ipv4Addr>>>,
    ipv6_blocklist: Arc<RwLock<HashSet<Ipv6Addr>>>,
    cidr_blocklist: Arc<RwLock<CidrIndex>>,
    domain_blocklist: Arc<RwLock<HashSet<String>>>,

    // Whitelists to override blocklists
    ipv4_whitelist: Arc<RwLock<HashSet<Ipv4Addr>>>,
    ipv6_whitelist: Arc<RwLock<HashSet<Ipv6Addr>>>,
    cidr_whitelist: Arc<RwLock<CidrIndex>>,
    domain_whitelist: Arc<RwLock<HashSet<String>>>,
    popular_domain_whitelist: Arc<RwLock<HashSet<String>>>,

    /// Blocked hostname patterns (supports wildcards like *.facebook.com)
    blocked_hostnames: Arc<RwLock<Vec<String>>>,
    /// Blocked URL patterns (supports wildcards)
    blocked_url_patterns: Arc<RwLock<Vec<String>>>,
    /// Exact malicious URLs loaded from feeds such as phishing_links.txt.
    exact_url_blocklist: Arc<RwLock<HashSet<String>>>,

    // --- New Advanced Filtering Fields ---
    email_blocklist: Arc<RwLock<HashSet<String>>>,
    urlhaus_urls: Arc<RwLock<HashSet<String>>>,
    _urlhaus_domains: Arc<RwLock<HashSet<String>>>,
    reference_map: Arc<RwLock<HashMap<u32, String>>>,
}

fn new_bloom() -> Arc<RwLock<HashSet<String>>> {
    Arc::new(RwLock::new(HashSet::new()))
}

impl WebFilter {
    pub fn new() -> Self {
        // HashSet-backed blocklists/whitelists guarded by RwLock.
        let filter = Self {
            ipv4_blocklist: Arc::new(RwLock::new(HashSet::new())),
            ipv6_blocklist: Arc::new(RwLock::new(HashSet::new())),
            cidr_blocklist: Arc::new(RwLock::new(CidrIndex::default())),
            domain_blocklist: new_bloom(),

            ipv4_whitelist: Arc::new(RwLock::new(HashSet::new())),
            ipv6_whitelist: Arc::new(RwLock::new(HashSet::new())),
            cidr_whitelist: Arc::new(RwLock::new(CidrIndex::default())),
            domain_whitelist: new_bloom(),
            popular_domain_whitelist: new_bloom(),

            blocked_hostnames: Arc::new(RwLock::new(Vec::new())),
            blocked_url_patterns: Arc::new(RwLock::new(Vec::new())),
            exact_url_blocklist: new_bloom(),

            email_blocklist: new_bloom(),
            urlhaus_urls: new_bloom(),
            _urlhaus_domains: new_bloom(),
            reference_map: Arc::new(RwLock::new(HashMap::new())),
        };

        for d in [
            "discord.com",
            "discordapp.com",
            "gateway.discord.gg",
            "cdn.discordapp.com",
        ] {
            filter
                .domain_whitelist
                .write()
                .unwrap()
                .insert(d.to_string());
        }

        filter
    }

    /// Add a hostname pattern to block (e.g., "*.facebook.com")
    pub fn add_blocked_hostname(&self, pattern: String) {
        self.blocked_hostnames.write().unwrap().push(pattern);
    }

    /// Add a URL pattern to block (e.g., "*malware*")
    pub fn add_blocked_url_pattern(&self, pattern: String) {
        self.blocked_url_patterns.write().unwrap().push(pattern);
    }

    /// Check if a hostname matches any blocked patterns
    pub fn check_hostname(&self, hostname: &str) -> Option<String> {
        let hostname_lower = hostname.to_lowercase();

        // 0. Check whitelist (whitelist prevents hostname/domain blocking, but individual URLs can still be blocked)
        if self
            .domain_whitelist
            .read()
            .unwrap()
            .contains(hostname_lower.as_str())
        {
            return None;
        }

        if self.is_popularity_whitelisted(&hostname_lower) {
            return None;
        }

        // 1. Check domain blocklist (exact match)
        if self
            .domain_blocklist
            .read()
            .unwrap()
            .contains(hostname_lower.as_str())
        {
            return Some(format!("Blocked Domain: {}", hostname));
        }

        // Check hostname patterns (wildcard match)
        for pattern in self.blocked_hostnames.read().unwrap().iter() {
            if Self::wildcard_match(pattern, &hostname_lower) {
                return Some(format!("Blocked Hostname Pattern: {}", pattern));
            }
        }

        None
    }

    fn is_popularity_whitelisted(&self, hostname: &str) -> bool {
        let mut candidate = hostname;

        loop {
            if self
                .popular_domain_whitelist
                .read()
                .unwrap()
                .contains(candidate)
            {
                return true;
            }

            let Some(dot_pos) = candidate.find('.') else {
                break;
            };
            candidate = &candidate[dot_pos + 1..];
        }

        false
    }

    /// Check if a URL matches any blocked patterns
    pub fn check_url(&self, url: &str) -> Option<String> {
        let url_lower = Self::normalize_url(url);
        if url_lower.is_empty() {
            return None;
        }

        if self
            .exact_url_blocklist
            .read()
            .unwrap()
            .contains(url_lower.as_str())
        {
            return Some(format!("Blocked URL: {}", url));
        }

        let url_without_scheme = Self::strip_url_scheme(&url_lower);
        if self
            .exact_url_blocklist
            .read()
            .unwrap()
            .contains(url_without_scheme)
        {
            return Some(format!("Blocked URL: {}", url));
        }

        if self
            .urlhaus_urls
            .read()
            .unwrap()
            .contains(url_lower.as_str())
            || self
                .urlhaus_urls
                .read()
                .unwrap()
                .contains(url_without_scheme)
        {
            return Some(format!("Blocked URL: {}", url));
        }

        for pattern in self.blocked_url_patterns.read().unwrap().iter() {
            if Self::wildcard_match(pattern, &url_lower) {
                return Some(format!("Blocked URL Pattern: {}", pattern));
            }
        }

        None
    }

    fn normalize_url(url: &str) -> String {
        url.trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim_end_matches('/')
            .to_lowercase()
    }

    fn strip_url_scheme(url: &str) -> &str {
        url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .or_else(|| url.strip_prefix("ftp://"))
            .unwrap_or(url)
    }

    /// Simple wildcard matching (supports * for any characters)
    fn wildcard_match(pattern: &str, text: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();

        if pattern_lower == "*" || pattern_lower == "any" {
            return true;
        }

        // Handle *.example.com pattern
        if pattern_lower.starts_with("*.") {
            let suffix = &pattern_lower[1..];
            return text.ends_with(suffix) || text == &pattern_lower[2..];
        }

        // Handle *keyword* pattern
        if pattern_lower.starts_with('*') && pattern_lower.ends_with('*') && pattern_lower.len() > 2
        {
            let keyword = &pattern_lower[1..pattern_lower.len() - 1];
            return text.contains(keyword);
        }

        // Handle keyword* pattern
        if pattern_lower.ends_with('*') {
            let prefix = &pattern_lower[..pattern_lower.len() - 1];
            return text.starts_with(prefix);
        }

        // Handle *keyword pattern
        if pattern_lower.starts_with('*') {
            let suffix = &pattern_lower[1..];
            return text.ends_with(suffix);
        }

        // Exact match
        text == pattern_lower
    }

    fn is_header_value(value: &str) -> bool {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "entry" | "ip" | "address" | "domain" | "subdomain" | "url" | "host"
        )
    }

    fn cidr_family_matches(cidr: &str, is_ipv4_file: bool, is_ipv6_file: bool) -> bool {
        let Some((network, prefix)) = cidr.split_once('/') else {
            return false;
        };
        let Ok(prefix_len) = prefix.parse::<u32>() else {
            return false;
        };

        if let Ok(_) = network.parse::<Ipv4Addr>() {
            return prefix_len <= 32 && !is_ipv6_file;
        }
        if let Ok(_) = network.parse::<Ipv6Addr>() {
            return prefix_len <= 128 && !is_ipv4_file;
        }
        false
    }

    pub fn load_references(&self, path: &str) -> std::io::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;
        let mut map = self.reference_map.write().unwrap();

        for line in content.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                if let Ok(id) = parts[0].trim().parse::<u32>() {
                    let name = parts[1].trim().to_string();
                    map.insert(id, name);
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    pub fn load_emails(&self, path: &str) -> std::io::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;

        for line in content.lines() {
            let email = line.trim().to_lowercase();
            if !email.is_empty() && !email.starts_with('#') {
                self.email_blocklist.write().unwrap().insert(email);
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn load_urlhaus(&self, path: &str) -> std::io::Result<usize> {
        // Simple line-based loader for now, assuming URL per line or CSV
        // If CSV, we might need robust parsing.
        // Based on user "urlhaus.txt", let's assume one URL per line or CSV.
        // If it's the standard export: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        // Basic check if it looks like CSV
        // We'll iterate lines manually to avoid strict CSV errors
        use std::io::BufRead;

        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with('#') {
                    continue;
                }

                // Try to extract URL column (index 2 usually)
                let parts: Vec<&str> = l.split(',').collect();
                if parts.len() > 3 {
                    let url = Self::normalize_url(&parts[2].trim().replace("\"", "")); // Simple unquote
                    if !url.is_empty() {
                        self.urlhaus_urls.write().unwrap().insert(url.clone());
                        self.exact_url_blocklist.write().unwrap().insert(url);
                        // Parse domain from URL for domain blocking?
                        // Left as future optimization to avoid over-blocking
                    }
                } else if !l.is_empty() {
                    // Fallback: Treat whole line as URL
                    let url = Self::normalize_url(l.trim());
                    if !url.is_empty() {
                        self.urlhaus_urls.write().unwrap().insert(url.clone());
                        self.exact_url_blocklist.write().unwrap().insert(url);
                    }
                }
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn load_plain_url_list(&self, path: &str) -> std::io::Result<usize> {
        use std::io::BufRead;

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0usize;

        for line in reader.lines() {
            let line = line?;
            let url = Self::normalize_url(&line);
            if url.is_empty() || url.starts_with('#') {
                continue;
            }
            self.exact_url_blocklist.write().unwrap().insert(url);
            count += 1;
        }

        Ok(count)
    }

    pub fn load_json_url_list(&self, path: &str) -> std::io::Result<usize> {
        #[derive(Deserialize)]
        struct JsonUrlFeed {
            #[serde(default)]
            data: Vec<String>,
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let feed: JsonUrlFeed = serde_json::from_reader(reader)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;

        let mut count = 0usize;
        for url in feed.data {
            let normalized = Self::normalize_url(&url);
            if normalized.is_empty() {
                continue;
            }
            self.exact_url_blocklist.write().unwrap().insert(normalized);
            count += 1;
        }

        Ok(count)
    }

    pub fn find_match(
        &self,
        remote_ip: IpAddr,
        hostname: Option<&str>,
        full_url: Option<&str>,
        payload_urls: &[String],
        payload_domains: &[String],
    ) -> Option<WebThreatMatch> {
        if let Some(url) = full_url {
            if let Some(reason) = self.check_url(url) {
                return Some(WebThreatMatch::url(url.to_string(), reason));
            }
        }

        for url in payload_urls {
            if let Some(reason) = self.check_url(url) {
                return Some(WebThreatMatch::url(url.clone(), reason));
            }
        }

        if let Some(host) = hostname {
            if let Some(reason) = self.check_hostname(host) {
                return Some(WebThreatMatch::hostname(host.to_string(), reason));
            }
        }

        for domain in payload_domains {
            if let Some(reason) = self.check_hostname(domain) {
                return Some(WebThreatMatch::hostname(domain.clone(), reason));
            }
        }

        if self.is_blocked_ip(remote_ip) {
            return Some(WebThreatMatch::ip(
                remote_ip.to_string(),
                format!("Blocked IP: {}", remote_ip),
            ));
        }

        None
    }

    pub fn load_from_website_folder(&self, base_path: &str) -> std::io::Result<usize> {
        let mut count = 0;

        // 1. Load References
        let ref_path = format!("{}\\references.txt", base_path);
        if Path::new(&ref_path).exists() {
            if let Ok(c) = self.load_references(&ref_path) {
                println!("Loaded {} references.", c);
            }
        }

        // 2. Load Email Blacklist
        let email_path = format!("{}\\listed_email_365.txt", base_path);
        if Path::new(&email_path).exists() {
            if let Ok(c) = self.load_emails(&email_path) {
                println!("Loaded {} malicious emails.", c);
            }
        }

        // 3. Load URLHaus
        let urlhaus_path = format!("{}\\urlhaus.txt", base_path);
        if Path::new(&urlhaus_path).exists() {
            if let Ok(c) = self.load_urlhaus(&urlhaus_path) {
                count += c;
                println!("Loaded {} URLHaus entries.", c);
            }
        }

        // `phishing_links.txt` is expected to contain the JSON feed format used by
        // the Exerra blacklist project: https://github.com/Exerra/blacklist
        let phishing_links_path = format!("{}\\phishing_links.txt", base_path);
        if Path::new(&phishing_links_path).exists() {
            if let Ok(c) = self.load_json_url_list(&phishing_links_path) {
                count += c;
                println!("Loaded {} phishing JSON URLs from Exerra/blacklist.", c);
            }
        }

        for filename in ["MaliciousLinks.txt", "Links.txt"] {
            let path = format!("{}\\{}", base_path, filename);
            if Path::new(&path).exists() {
                if let Ok(c) = self.load_plain_url_list(&path) {
                    count += c;
                    println!("Loaded {} plain malicious URLs from {}.", c, filename);
                }
            }
        }

        for filename in [
            "CIDRWhiteListIPv4.csv",
            "CIDRWhiteListIPv6.csv",
            "CIDRBlackListIPv4.csv",
            "CIDRBlackListIPv6.csv",
        ] {
            let path = Path::new(base_path).join(filename);
            if path.exists() {
                if let Ok(c) = self.load_csv(&path) {
                    count += c;
                    println!("Loaded {} CIDR entries from {}.", c, filename);
                }
            }
        }

        // 4. Load Optimized CSVs
        // glob pattern requires forward slashes even on Windows to avoid escaping issues
        let base_path_slash = base_path.replace("\\", "/");
        let pattern = format!("{}/{}", base_path_slash, "*.optimized.csv");

        for entry in glob(&pattern)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        {
            match entry {
                Ok(path) => {
                    let filename = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if let Ok(c) = self.load_csv(&path) {
                        count += c;
                        println!("Loaded {} entries from {}", c, filename);
                    } else {
                        eprintln!("Failed to load CSV: {}", filename);
                    }
                }
                Err(e) => eprintln!("Error reading glob entry: {:?}", e),
            }
        }
        Ok(count)
    }

    fn load_csv(&self, path: &Path) -> std::io::Result<usize> {
        let file = File::open(path)?;
        // CRITICAL UPDATE: The optimized CSVs (like WhiteListDomains.optimized.csv)
        // observed in `everything/website` DO NOT have headers (line 1 is data: "zzzzzzzzz.info,1").
        // We must set has_headers(false) to read the first line as data.
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false) // Optimized CSVs are headerless
            .from_reader(BufReader::new(file));

        let mut count = 0;
        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let filename_lower = filename.to_ascii_lowercase();
        let is_ipv4 = filename_lower.contains("ipv4") || filename_lower.contains("cidr4");
        let is_ipv6 = filename_lower.contains("ipv6") || filename_lower.contains("cidr6");
        let is_cidr_file = filename_lower.contains("cidrwhitelist")
            || filename_lower.contains("cidrblacklist")
            || filename_lower.starts_with("allow_cidr")
            || filename_lower.starts_with("block_cidr");
        let is_domain = filename_lower.contains("domain") || filename_lower.contains("subdomain");
        let is_popularity_subdomain_whitelist =
            filename_lower.contains("subdomainspopularitywhitelist");
        let is_popularity_domain_whitelist = filename_lower.contains("domainspopularitywhitelist")
            && !is_popularity_subdomain_whitelist;
        // Temporary vectors to hold data before locking
        let mut ips_v4 = Vec::new();
        let mut ips_v6 = Vec::new();
        let mut cidr_ranges = Vec::new();
        let mut domains = Vec::new();
        let mut popular_domains = Vec::new();

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            if is_popularity_domain_whitelist {
                if let Some(domain_str) = record.get(0) {
                    let domain = domain_str.trim().to_lowercase();
                    if !domain.is_empty() {
                        popular_domains.push(domain);
                        count += 1;
                    }
                }
                continue;
            }

            if is_popularity_subdomain_whitelist {
                if let Some(subdomain_str) = record.get(0) {
                    let subdomain = subdomain_str.trim().to_lowercase();
                    if !subdomain.is_empty() {
                        domains.push(subdomain);
                        count += 1;
                    }
                }
                continue;
            }

            // In headerless "optimized" CSVs:
            // Column 0 = Address/Domain
            // Column 1 = Reference ID
            if let Some(addr_str) = record.get(0) {
                let addr_str = addr_str.trim();
                if addr_str.is_empty() || Self::is_header_value(addr_str) {
                    continue;
                }

                if is_cidr_file || addr_str.contains('/') {
                    if Self::cidr_family_matches(addr_str, is_ipv4, is_ipv6) {
                        cidr_ranges.push(addr_str.to_string());
                        count += 1;
                    }
                    continue;
                }

                if is_ipv4 {
                    if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                        ips_v4.push(ip);
                        count += 1;
                    }
                } else if is_ipv6 {
                    if let Ok(ip) = addr_str.parse::<Ipv6Addr>() {
                        ips_v6.push(ip);
                        count += 1;
                    }
                } else {
                    // Assume domain if not specifically IP file, or auto-detect?
                    // Relying on filename heuristic for now as it's cleaner.
                    if is_domain {
                        domains.push(addr_str.to_lowercase());
                        count += 1;
                    } else {
                        // Fallback auto-detect
                        if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                            ips_v4.push(ip);
                            count += 1;
                        } else if let Ok(ip) = addr_str.parse::<Ipv6Addr>() {
                            ips_v6.push(ip);
                            count += 1;
                        } else {
                            domains.push(addr_str.to_lowercase());
                            count += 1;
                        }
                    }
                }
            }
        }

        let is_whitelist =
            filename_lower.contains("whitelist") || filename_lower.contains("allowlist");

        // Insert everything into appropriate lists
        if is_whitelist {
            {
                let mut wl4 = self.ipv4_whitelist.write().unwrap();
                for ip in &ips_v4 {
                    wl4.insert(*ip);
                }
            }
            {
                let mut wl6 = self.ipv6_whitelist.write().unwrap();
                for ip in &ips_v6 {
                    wl6.insert(*ip);
                }
            }
            if !cidr_ranges.is_empty() {
                let mut cidr_whitelist = self.cidr_whitelist.write().unwrap();
                for cidr in cidr_ranges {
                    cidr_whitelist.add(&cidr);
                }
                cidr_whitelist.normalize();
            }
            {
                let mut dwl = self.domain_whitelist.write().unwrap();
                for d in &domains {
                    dwl.insert(d.clone());
                }
            }
            {
                let mut pdwl = self.popular_domain_whitelist.write().unwrap();
                for d in &popular_domains {
                    pdwl.insert(d.clone());
                }
            }
        } else {
            {
                let mut bl4 = self.ipv4_blocklist.write().unwrap();
                for ip in &ips_v4 {
                    bl4.insert(*ip);
                }
            }
            {
                let mut bl6 = self.ipv6_blocklist.write().unwrap();
                for ip in &ips_v6 {
                    bl6.insert(*ip);
                }
            }
            if !cidr_ranges.is_empty() {
                let mut cidr_blocklist = self.cidr_blocklist.write().unwrap();
                for cidr in cidr_ranges {
                    cidr_blocklist.add(&cidr);
                }
                cidr_blocklist.normalize();
            }
            {
                let mut dbl = self.domain_blocklist.write().unwrap();
                for d in &domains {
                    dbl.insert(d.clone());
                }
            }
        }

        Ok(count)
    }

    pub fn is_blocked_ip(&self, ip: IpAddr) -> bool {
        if self.cidr_whitelist.read().unwrap().contains(ip) {
            return false;
        }

        let exact_blocked = match ip {
            IpAddr::V4(ipv4) => {
                // Check whitelist first
                if self.ipv4_whitelist.read().unwrap().contains(&ipv4) {
                    return false;
                }
                self.ipv4_blocklist.read().unwrap().contains(&ipv4)
            }
            IpAddr::V6(ipv6) => {
                // Check whitelist first
                if self.ipv6_whitelist.read().unwrap().contains(&ipv6) {
                    return false;
                }
                self.ipv6_blocklist.read().unwrap().contains(&ipv6)
            }
        };

        exact_blocked || self.cidr_blocklist.read().unwrap().contains(ip)
    }
}

#[derive(Clone, Debug)]
pub enum WebThreatTargetKind {
    Url,
    Hostname,
    Ip,
}

#[derive(Clone, Debug)]
pub struct WebThreatMatch {
    pub kind: WebThreatTargetKind,
    pub target: String,
    pub reason: String,
}

impl WebThreatMatch {
    pub fn url(target: String, reason: String) -> Self {
        Self {
            kind: WebThreatTargetKind::Url,
            target,
            reason,
        }
    }

    pub fn hostname(target: String, reason: String) -> Self {
        Self {
            kind: WebThreatTargetKind::Hostname,
            target,
            reason,
        }
    }

    pub fn ip(target: String, reason: String) -> Self {
        Self {
            kind: WebThreatTargetKind::Ip,
            target,
            reason,
        }
    }

    pub fn decision_key(&self) -> String {
        match self.kind {
            WebThreatTargetKind::Url => {
                format!("website:url:{}", WebFilter::normalize_url(&self.target))
            }
            WebThreatTargetKind::Hostname => {
                format!("website:host:{}", self.target.trim().to_lowercase())
            }
            WebThreatTargetKind::Ip => format!("website:ip:{}", self.target.trim().to_lowercase()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_whitelist_csv_is_treated_as_whitelist() {
        let filter = WebFilter::new();

        let tmp_base = std::env::temp_dir().join(format!(
            "hdf_wf_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        fs::create_dir_all(&tmp_base).unwrap();

        let whitelist_path = tmp_base.join("WhiteListDomains.optimized.csv");
        let malware_path = tmp_base.join("MalwareDomains.optimized.csv");

        fs::write(&whitelist_path, b"trusted.example,1\n").unwrap();
        fs::write(&malware_path, b"blocked.example,1\n").unwrap();

        let _ = filter
            .load_csv(&whitelist_path)
            .expect("Failed to load whitelist");
        let _ = filter
            .load_csv(&malware_path)
            .expect("Failed to load malware blocklist");

        // Whitelist should NOT block
        let blocked = filter.check_hostname("trusted.example");
        assert!(blocked.is_none(), "Whitelist entries must NOT block");

        // Malware should stay blocked
        let malware_block = filter
            .check_hostname("blocked.example")
            .expect("Malware domains should stay blocked");
        assert!(malware_block.contains("blocked.example"));

        // Clean up the temporary folder; ignore errors
        let _ = fs::remove_file(&whitelist_path);
        let _ = fs::remove_file(&malware_path);
        let _ = fs::remove_dir(&tmp_base);
    }

    #[test]
    fn test_popularity_whitelist_covers_subdomains() {
        let filter = WebFilter::new();

        let tmp_base = std::env::temp_dir().join(format!(
            "hdf_wf_popularity_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        fs::create_dir_all(&tmp_base).unwrap();

        let popularity_domain_path = tmp_base.join("DomainsPopularityWhiteList.optimized.csv");
        let popularity_subdomain_path =
            tmp_base.join("SubDomainsPopularityWhiteList.optimized.csv");
        let malware_path = tmp_base.join("MalwareDomains.optimized.csv");

        fs::write(&popularity_domain_path, b"trusted.example,1,42\n").unwrap();
        fs::write(&popularity_subdomain_path, b"login.trusted.example,2,42\n").unwrap();
        fs::write(&malware_path, b"foo.trusted.example,1\nblocked.example,1\n").unwrap();

        let _ = filter
            .load_csv(&popularity_domain_path)
            .expect("Failed to load popularity domain whitelist");
        let _ = filter
            .load_csv(&popularity_subdomain_path)
            .expect("Failed to load popularity subdomain whitelist");
        let _ = filter
            .load_csv(&malware_path)
            .expect("Failed to load malware blocklist");

        assert!(
            filter.check_hostname("foo.trusted.example").is_none(),
            "Popularity whitelist domains must cover subdomains"
        );
        assert!(
            filter.check_hostname("login.trusted.example").is_none(),
            "Specific popularity subdomains must be whitelisted"
        );

        let malware_block = filter
            .check_hostname("blocked.example")
            .expect("Unrelated malware domains should stay blocked");
        assert!(malware_block.contains("blocked.example"));

        let _ = fs::remove_file(&popularity_domain_path);
        let _ = fs::remove_file(&popularity_subdomain_path);
        let _ = fs::remove_file(&malware_path);
        let _ = fs::remove_dir(&tmp_base);
    }

    #[test]
    fn test_cidr_csvs_are_loaded_as_network_rules() {
        let filter = WebFilter::new();

        let tmp_base = std::env::temp_dir().join(format!(
            "hdf_wf_cidr_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        fs::create_dir_all(&tmp_base).unwrap();

        let whitelist_path = tmp_base.join("CIDRWhiteListIPv4.csv");
        let blacklist_path = tmp_base.join("CIDRBlackListIPv4.csv");

        fs::write(&whitelist_path, b"entry,reference\n10.0.0.0/8,trusted\n").unwrap();
        fs::write(
            &blacklist_path,
            b"entry,reference\n10.1.2.0/24,bad\n203.0.113.0/24,bad\n",
        )
        .unwrap();

        let _ = filter
            .load_csv(&whitelist_path)
            .expect("Failed to load CIDR whitelist");
        let _ = filter
            .load_csv(&blacklist_path)
            .expect("Failed to load CIDR blacklist");

        assert!(
            !filter.is_blocked_ip("10.1.2.3".parse().unwrap()),
            "CIDR whitelist must override overlapping CIDR blacklist"
        );
        assert!(
            filter.is_blocked_ip("203.0.113.7".parse().unwrap()),
            "CIDR blacklist must block IPs inside the network"
        );

        let _ = fs::remove_file(&whitelist_path);
        let _ = fs::remove_file(&blacklist_path);
        let _ = fs::remove_dir(&tmp_base);
    }
}
