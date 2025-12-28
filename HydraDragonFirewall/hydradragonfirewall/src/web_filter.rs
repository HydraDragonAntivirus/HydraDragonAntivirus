use glob::glob;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, RwLock};

// Use lazy_static to compile regex patterns lazily (on first use, not on startup)
// This prevents stack overflow during initialization
lazy_static! {
    static ref DISCORD_WEBHOOK_REGEX: Regex =
        Regex::new(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+").unwrap();
    static ref DISCORD_ATTACHMENT_REGEX: Regex =
        Regex::new(r"https://cdn\.discordapp\.com/attachments/\d+/\d+/[A-Za-z0-9._-]+").unwrap();
    static ref TELEGRAM_TOKEN_REGEX: Regex =
        Regex::new(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}").unwrap();

    // Ported from antivirus.py
    static ref EMAIL_REGEX: Regex =
        Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    static ref UBLOCK_REGEX: Regex =
         Regex::new(r"^https?://[a-z0-9-]+\.com/ad_pattern").unwrap(); // Placeholder for actual pattern
}

#[derive(Clone)]
pub struct WebFilter {
    ipv4_blocklist: Arc<RwLock<HashSet<Ipv4Addr>>>,
    ipv6_blocklist: Arc<RwLock<HashSet<Ipv6Addr>>>,
    domain_blocklist: Arc<RwLock<HashSet<String>>>,
    /// Blocked hostname patterns (supports wildcards like *.facebook.com)
    blocked_hostnames: Arc<RwLock<Vec<String>>>,
    /// Blocked URL patterns (supports wildcards)
    /// Blocked URL patterns (supports wildcards)
    blocked_url_patterns: Arc<RwLock<Vec<String>>>,

    // --- New Advanced Filtering Fields ---
    email_blocklist: Arc<RwLock<HashSet<String>>>,
    urlhaus_urls: Arc<RwLock<HashSet<String>>>,
    _urlhaus_domains: Arc<RwLock<HashSet<String>>>,
    reference_map: Arc<RwLock<HashMap<u32, String>>>,
}

impl WebFilter {
    pub fn new() -> Self {
        // No regex compilation here - patterns are lazily compiled on first use
        Self {
            ipv4_blocklist: Arc::new(RwLock::new(HashSet::new())),
            ipv6_blocklist: Arc::new(RwLock::new(HashSet::new())),
            domain_blocklist: Arc::new(RwLock::new(HashSet::new())),
            blocked_hostnames: Arc::new(RwLock::new(Vec::new())),
            blocked_url_patterns: Arc::new(RwLock::new(Vec::new())),

            email_blocklist: Arc::new(RwLock::new(HashSet::new())),
            urlhaus_urls: Arc::new(RwLock::new(HashSet::new())),
            _urlhaus_domains: Arc::new(RwLock::new(HashSet::new())),
            reference_map: Arc::new(RwLock::new(HashMap::new())),
        }
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

        // 1. Check domain blocklist (exact match)
        if self
            .domain_blocklist
            .read()
            .unwrap()
            .contains(&hostname_lower)
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

    /// Check if a URL matches any blocked patterns
    pub fn check_url(&self, url: &str) -> Option<String> {
        let url_lower = url.to_lowercase();

        for pattern in self.blocked_url_patterns.read().unwrap().iter() {
            if Self::wildcard_match(pattern, &url_lower) {
                return Some(format!("Blocked URL Pattern: {}", pattern));
            }
        }

        None
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
        let mut emails = self.email_blocklist.write().unwrap();

        for line in content.lines() {
            let email = line.trim().to_lowercase();
            if !email.is_empty() && !email.starts_with('#') {
                emails.insert(email);
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
        let mut urls = self.urlhaus_urls.write().unwrap();

        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with('#') {
                    continue;
                }

                // Try to extract URL column (index 2 usually)
                let parts: Vec<&str> = l.split(',').collect();
                if parts.len() > 3 {
                    let url = parts[2].trim().replace("\"", ""); // Simple unquote
                    if !url.is_empty() {
                        urls.insert(url.to_lowercase());
                        // Parse domain from URL for domain blocking?
                        // Left as future optimization to avoid over-blocking
                    }
                } else if !l.is_empty() {
                    // Fallback: Treat whole line as URL
                    urls.insert(l.trim().to_lowercase());
                }
                count += 1;
            }
        }
        Ok(count)
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
                println!("Loaded {} URLHaus entries.", c);
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

        let is_ipv4 = filename.contains("IPv4");
        let is_ipv6 = filename.contains("IPv6");
        let is_domain = filename.contains("Domain") || filename.contains("SubDomain");
        // Temporary vectors to hold data before locking
        let mut ips_v4 = Vec::new();
        let mut ips_v6 = Vec::new();
        let mut domains = Vec::new();

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            // In headerless "optimized" CSVs:
            // Column 0 = Address/Domain
            // Column 1 = Reference ID
            if let Some(addr_str) = record.get(0) {
                let addr_str = addr_str.trim();
                if addr_str.is_empty() {
                    continue;
                }

                if is_ipv4 {
                    if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                        ips_v4.push(ip);
                    }
                } else if is_ipv6 {
                    if let Ok(ip) = addr_str.parse::<Ipv6Addr>() {
                        ips_v6.push(ip);
                    }
                } else {
                    // Assume domain if not explicitly IP file, or auto-detect?
                    // Relying on filename heuristic for now as it's cleaner.
                    if is_domain {
                        domains.push(addr_str.to_lowercase());
                    } else {
                        // Fallback auto-detect
                        if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                            ips_v4.push(ip);
                        } else if let Ok(ip) = addr_str.parse::<Ipv6Addr>() {
                            ips_v6.push(ip);
                        } else {
                            domains.push(addr_str.to_lowercase());
                        }
                    }
                }
                count += 1;
            }
        }

        // Insert everything into blocklists; whitelist files are treated as signatures too
        if !ips_v4.is_empty() {
            self.ipv4_blocklist.write().unwrap().extend(ips_v4);
        }
        if !ips_v6.is_empty() {
            self.ipv6_blocklist.write().unwrap().extend(ips_v6);
        }
        if !domains.is_empty() {
            self.domain_blocklist.write().unwrap().extend(domains);
        }

        Ok(count)
    }

    pub fn is_blocked_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.ipv4_blocklist.read().unwrap().contains(&ipv4),
            IpAddr::V6(ipv6) => self.ipv6_blocklist.read().unwrap().contains(&ipv6),
        }
    }

    pub fn check_payload(
        &self,
        payload: &[u8],
        settings: &crate::engine::FirewallSettings,
    ) -> Option<String> {
        // 1. Convert to string (lossy) to check regex
        // We only check the first 2KB for efficiency
        let scan_len = std::cmp::min(payload.len(), 4096); // Increased default scan
        if scan_len == 0 {
            return None;
        }

        let text = String::from_utf8_lossy(&payload[..scan_len]);
        let text_lower = text.to_lowercase();

        // Dynamic Keyword Scan from Settings
        for keyword in &settings.blocked_keywords {
            if text_lower.contains(&keyword.to_lowercase()) {
                return Some(format!("Blocked Keyword: {}", keyword));
            }
        }

        // Check regexes using lazy_static patterns (compiled on first use)
        // These can be toggled in future updates via settings if needed
        if DISCORD_WEBHOOK_REGEX.is_match(&text) {
            return Some(format!("Regex Match: Discord Webhook"));
        }
        if DISCORD_ATTACHMENT_REGEX.is_match(&text) {
            return Some(format!("Regex Match: Discord Attachment"));
        }
        if TELEGRAM_TOKEN_REGEX.is_match(&text) {
            return Some(format!("Regex Match: Telegram Token"));
        }

        // --- Email Scanning ---
        for cap in EMAIL_REGEX.captures_iter(&text) {
            if let Some(email_match) = cap.get(0) {
                let email = email_match.as_str().to_lowercase();
                if self.email_blocklist.read().unwrap().contains(&email) {
                    return Some(format!("Blocked Malicious Email: {}", email));
                }
            }
        }

        // --- URLHaus Check in Payload (e.g. GET requests) ---
        // Basic heuristic: check if any part of the text matches a known bad URL
        // (Optimized: Checking substring for every URL is slow, so we check ONLY if "http" is present)
        if text_lower.contains("http") {
            for url in self.urlhaus_urls.read().unwrap().iter() {
                if text_lower.contains(url) {
                    return Some(format!("Blocked URLHaus: {}", url));
                }
            }
        }

        // 2. Check for Host header (HTTP)
        // Find "Host: "
        if let Some(host_idx) = text_lower.find("host: ") {
            let start = host_idx + 6;
            if let Some(end) = text[start..].find("\r\n") {
                let host = text[start..start + end].trim().to_lowercase();
                // Remove port if present
                let host_name = host.split(':').next().unwrap_or(&host);

                if self.domain_blocklist.read().unwrap().contains(host_name) {
                    return Some(format!("Blocked Domain: {}", host_name));
                }

                // Also check dynamic keywords in Host header specifically
                for keyword in &settings.blocked_keywords {
                    if host_name.contains(&keyword.to_lowercase()) {
                        return Some(format!("Blocked Host Keyword: {}", keyword));
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_whitelist_csv_is_treated_as_blocklist() {
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
            .expect("Failed to load whitelist as blocklist");
        let _ = filter
            .load_csv(&malware_path)
            .expect("Failed to load malware blocklist");

        let blocked = filter
            .check_hostname("trusted.example")
            .expect("Whitelist entries must now block");
        assert!(blocked.contains("trusted.example"));

        let malware_block = filter
            .check_hostname("blocked.example")
            .expect("Malware domains should stay blocked");
        assert!(malware_block.contains("blocked.example"));

        // Clean up the temporary folder; ignore errors
        let _ = fs::remove_file(&whitelist_path);
        let _ = fs::remove_file(&malware_path);
        let _ = fs::remove_dir(&tmp_base);
    }
}
