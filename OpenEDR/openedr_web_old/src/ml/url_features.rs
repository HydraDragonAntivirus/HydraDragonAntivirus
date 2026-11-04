//! High-performance URL & Query Feature Extractor matching train_url_lgbm.py (32 features)

use super::features::UrlFeatureVector;

const SUSPICIOUS_TLDS: &[&str] = &[
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "buzz", "rest", "fit", "casa", "surf", "icu", "bar", "live", "vip",
];

const HACK_KEYWORDS: &[&str] = &[
    "login", "signin", "verify", "account", "banking", "secure", "update",
    "confirm", "wallet", "admin", "wp-content", "cmd", "shell", "exec",
    "eval", "select", "union", "insert", "drop", "etc/passwd", "windows/system32",
];

#[inline]
fn ln1p(x: f32) -> f32 {
    if x <= 0.0 || x.is_nan() {
        0.0
    } else {
        (x + 1.0).ln()
    }
}

pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let total = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for &c in &freq {
        if c > 0 {
            let p = (c as f32) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Extract 32 features matching the HydraDragon URL training pipeline
pub fn extract_url_features(raw_url: &str) -> UrlFeatureVector {
    let url_to_parse = if !raw_url.starts_with("http://") && !raw_url.starts_with("https://") {
        format!("http://{}", raw_url)
    } else {
        raw_url.to_string()
    };

    let parsed = url::Url::parse(&url_to_parse).ok();

    let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("");
    let path = parsed.as_ref().map(|u| u.path()).unwrap_or("");
    let query = parsed.as_ref().and_then(|u| u.query()).unwrap_or("");

    let url_len = raw_url.len() as f32;
    let domain_len = host.len() as f32;
    let path_len = path.len() as f32;
    let query_len = query.len() as f32;

    let path_depth = path.split('/').filter(|p| !p.is_empty()).count() as f32;
    let subdomain_count = if !host.is_empty() {
        let parts = host.split('.').count();
        parts.saturating_sub(2) as f32
    } else {
        0.0
    };

    let query_param_count = parsed
        .as_ref()
        .map(|u| u.query_pairs().count() as f32)
        .unwrap_or(0.0);

    let is_ip_host = if host.parse::<std::net::IpAddr>().is_ok() {
        1.0
    } else {
        0.0
    };
    let has_port = if parsed.as_ref().and_then(|u| u.port()).is_some() {
        1.0
    } else {
        0.0
    };
    let is_https = if raw_url.to_ascii_lowercase().starts_with("https://") {
        1.0
    } else {
        0.0
    };

    let mut digit_count = 0f32;
    let mut letter_count = 0f32;
    let mut count_at = 0f32;
    let mut count_question = 0f32;
    let mut count_hyphen = 0f32;
    let mut count_equal = 0f32;
    let mut count_dot = 0f32;
    let mut count_percent = 0f32;
    let mut count_slash = 0f32;
    let mut count_semicolon = 0f32;
    let mut count_ampersand = 0f32;

    for &b in raw_url.as_bytes() {
        if b.is_ascii_digit() {
            digit_count += 1.0;
        } else if b.is_ascii_alphabetic() {
            letter_count += 1.0;
        }
        match b {
            b'@' => count_at += 1.0,
            b'?' => count_question += 1.0,
            b'-' => count_hyphen += 1.0,
            b'=' => count_equal += 1.0,
            b'.' => count_dot += 1.0,
            b'%' => count_percent += 1.0,
            b'/' => count_slash += 1.0,
            b';' => count_semicolon += 1.0,
            b'&' => count_ampersand += 1.0,
            _ => {}
        }
    }

    let special_count = (url_len - digit_count - letter_count).max(0.0);
    let max_len = url_len.max(1.0);
    let digit_ratio = digit_count / max_len;
    let letter_ratio = letter_count / max_len;
    let special_ratio = special_count / max_len;

    // Tokens split on [/._?=&-]
    let mut token_count = 0f32;
    let mut max_token_len = 0f32;
    let mut total_token_len = 0f32;

    for tok in raw_url.split(|c| matches!(c, '/' | '.' | '_' | '?' | '=' | '&' | '-')) {
        if !tok.is_empty() {
            token_count += 1.0;
            let l = tok.len() as f32;
            if l > max_token_len {
                max_token_len = l;
            }
            total_token_len += l;
        }
    }

    let avg_token_len = if token_count > 0.0 {
        total_token_len / token_count
    } else {
        0.0
    };

    let url_entropy = shannon_entropy(raw_url);
    let host_entropy = shannon_entropy(host);

    let tld = host.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let has_suspicious_tld = if SUSPICIOUS_TLDS.iter().any(|&s| s == tld) {
        1.0
    } else {
        0.0
    };

    let raw_lower = raw_url.to_ascii_lowercase();
    let has_hacked_keywords = if HACK_KEYWORDS.iter().any(|&k| raw_lower.contains(k)) {
        1.0
    } else {
        0.0
    };

    UrlFeatureVector {
        url_len: ln1p(url_len),
        domain_len: ln1p(domain_len),
        path_len: ln1p(path_len),
        query_len: ln1p(query_len),
        path_depth,
        subdomain_count,
        query_param_count,
        is_ip_host,
        has_port,
        is_https,
        digit_count: ln1p(digit_count),
        letter_count: ln1p(letter_count),
        special_count: ln1p(special_count),
        digit_ratio,
        letter_ratio,
        special_ratio,
        token_count: ln1p(token_count),
        max_token_len: ln1p(max_token_len),
        avg_token_len,
        url_entropy,
        host_entropy,
        count_at,
        count_question,
        count_hyphen: ln1p(count_hyphen),
        count_equal: ln1p(count_equal),
        count_dot: ln1p(count_dot),
        count_percent: ln1p(count_percent),
        count_slash: ln1p(count_slash),
        count_semicolon,
        count_ampersand: ln1p(count_ampersand),
        has_suspicious_tld,
        has_hacked_keywords,
    }
}
