//! High-performance URL & Query Feature Extractor and LightGBM Tree Model Evaluator
//!
//! Mirrors `train_url_lgbm.py` exactly (32 features) and runs in-memory fast inference
//! without external C runtime dependencies using precompiled `url_model.bin`.

use super::features::UrlFeatureVector;
use std::collections::HashMap;
use std::sync::OnceLock;

const SUSPICIOUS_TLDS: &[&str] = &[
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "buzz", "rest", "fit", "casa", "surf", "icu", "bar", "live", "vip"
];

const HACK_KEYWORDS: &[&str] = &[
    "login", "signin", "verify", "account", "banking", "secure", "update",
    "confirm", "wallet", "admin", "wp-content", "cmd", "shell", "exec",
    "eval", "select", "union", "insert", "drop", "etc/passwd", "windows/system32"
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

    let query_param_count = parsed.as_ref()
        .map(|u| u.query_pairs().count() as f32)
        .unwrap_or(0.0);

    let is_ip_host = if host.parse::<std::net::IpAddr>().is_ok() { 1.0 } else { 0.0 };
    let has_port = if parsed.as_ref().and_then(|u| u.port()).is_some() { 1.0 } else { 0.0 };
    let is_https = if raw_url.to_ascii_lowercase().starts_with("https://") { 1.0 } else { 0.0 };

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

    let avg_token_len = if token_count > 0.0 { total_token_len / token_count } else { 0.0 };

    let url_entropy = shannon_entropy(raw_url);
    let host_entropy = shannon_entropy(host);

    let tld = host.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let has_suspicious_tld = if SUSPICIOUS_TLDS.iter().any(|&s| s == tld) { 1.0 } else { 0.0 };

    let raw_lower = raw_url.to_ascii_lowercase();
    let has_hacked_keywords = if HACK_KEYWORDS.iter().any(|&k| raw_lower.contains(k)) { 1.0 } else { 0.0 };

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

/// Binary Tree representation
#[derive(Clone, Debug)]
pub struct UrlTreeNode {
    pub is_leaf: bool,
    pub feat: usize,
    pub val_or_thresh: f32,
    pub left: usize,
    pub right: usize,
}

#[derive(Clone, Debug)]
pub struct UrlTreeModel {
    pub n_features: usize,
    pub trees: Vec<Vec<UrlTreeNode>>,
}

impl UrlTreeModel {
    pub fn load_from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 || &data[0..4] != b"HDTR" {
            return None;
        }

        let n_features = u16::from_le_bytes(data[4..6].try_into().ok()?) as usize;
        let n_trees = u16::from_le_bytes(data[6..8].try_into().ok()?) as usize;

        let mut offset = 8;
        let mut trees = Vec::with_capacity(n_trees);

        for _ in 0..n_trees {
            if offset + 4 > data.len() {
                return None;
            }
            let n_nodes = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;

            let mut nodes = Vec::with_capacity(n_nodes);
            for _ in 0..n_nodes {
                if offset + 16 > data.len() {
                    return None;
                }
                let is_leaf = data[offset] == 1;
                // byte 1 is padding
                let feat = u16::from_le_bytes(data[offset + 2..offset + 4].try_into().ok()?) as usize;
                let val_or_thresh = f32::from_le_bytes(data[offset + 4..offset + 8].try_into().ok()?);
                let left = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().ok()?) as usize;
                let right = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().ok()?) as usize;
                offset += 16;

                nodes.push(UrlTreeNode {
                    is_leaf,
                    feat,
                    val_or_thresh,
                    left,
                    right,
                });
            }
            trees.push(nodes);
        }

        Some(Self { n_features, trees })
    }

    #[inline]
    pub fn predict_features(&self, feats: &[f32; 32]) -> f32 {
        let mut raw = 0.0f32;
        for tree in &self.trees {
            let mut curr = 0;
            loop {
                let node = &tree[curr];
                if node.is_leaf {
                    raw += node.val_or_thresh;
                    break;
                }
                if feats[node.feat] <= node.val_or_thresh {
                    curr = node.left;
                } else {
                    curr = node.right;
                }
            }
        }
        1.0 / (1.0 + (-raw).exp())
    }

    pub fn predict_url(&self, raw_url: &str) -> (f32, UrlFeatureVector) {
        let fv = extract_url_features(raw_url);
        let arr = fv.to_array();
        let prob = self.predict_features(&arr);
        (prob, fv)
    }
}

static URL_MODEL: OnceLock<Option<UrlTreeModel>> = OnceLock::new();

/// Resolve an ML model file across all runtime contexts:
/// 1. Registry HKLM\SOFTWARE\Owlyshield\SDK (DATABASE_PATH/MODELS_PATH)
/// 2. Loaded module directory (owlyshield_ransom.dll or companion DLL)
/// 3. current_exe directory
/// 4. Default installation directories (Program Files)
/// 5. CWD-relative models/ (dev / tests)
/// (Moved from the removed fast_detect.rs; URL model is the only file-ML
/// artifact left in owlyshield — PE/JS static ML lives in openedr_static.)
pub(crate) fn model_path(file: &str) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        for flags in [KEY_READ | KEY_WOW64_64KEY, KEY_READ] {
            if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SOFTWARE\Owlyshield\SDK", flags) {
                if let Ok(p) = key.get_value::<String, _>("MODELS_PATH") {
                    let cand = std::path::PathBuf::from(&p).join(file);
                    if cand.is_file() {
                        return Some(cand);
                    }
                }
                if let Ok(p) = key.get_value::<String, _>("DATABASE_PATH") {
                    let pb = std::path::PathBuf::from(&p);
                    if let Some(parent) = pb.parent() {
                        let cand = parent.join("models").join(file);
                        if cand.is_file() {
                            return Some(cand);
                        }
                    }
                }
            }
        }
    }

    if let Some(dll_dir) = crate::utils::current_module_dir() {
        let cand = dll_dir.join("models").join(file);
        if cand.is_file() {
            return Some(cand);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("models").join(file);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }

    for install_base in [
        r"C:\Program Files\HydraDragonAntivirus\OpenEDR\models",
        r"C:\Program Files (x86)\HydraDragonAntivirus\OpenEDR\models",
    ] {
        let cand = std::path::PathBuf::from(install_base).join(file);
        if cand.is_file() {
            return Some(cand);
        }
    }

    let cand = std::path::Path::new("models").join(file);
    if cand.is_file() {
        return Some(cand);
    }
    None
}

pub fn get_url_model() -> Option<&'static UrlTreeModel> {
    URL_MODEL.get_or_init(|| {
        let cand_paths = [
            model_path("url_model.bin"),
            Some(std::path::PathBuf::from("models/url_model.bin")),
            Some(std::path::PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\models\url_model.bin")),
        ];

        for opt_p in cand_paths {
            if let Some(p) = opt_p {
                if p.is_file() {
                    if let Ok(bytes) = std::fs::read(&p) {
                        if let Some(m) = UrlTreeModel::load_from_bytes(&bytes) {
                            crate::Logging::info(&format!("[URL ML] Loaded model from {}", p.display()));
                            return Some(m);
                        }
                    }
                }
            }
        }

        crate::Logging::warning("[URL ML] url_model.bin not found in standard paths");
        None
    }).as_ref()
}

pub const URL_ML_DETECTION_THRESHOLD: f32 = 0.90;

pub fn scan_url(raw_url: &str) -> Option<(f32, HashMap<String, f32>)> {
    let model = get_url_model()?;
    let (prob, fv) = model.predict_url(raw_url);
    if prob >= URL_ML_DETECTION_THRESHOLD {
        Some((prob, fv.to_map()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_and_predict() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let bin_path = manifest_dir.join("models").join("url_model.bin");
        let bytes = std::fs::read(&bin_path).expect("models/url_model.bin must exist");
        let model = UrlTreeModel::load_from_bytes(&bytes).expect("model parse failed");

        let (prob_google, _) = model.predict_url("http://google.com");
        println!("google.com prob: {}", prob_google);
        assert!(prob_google < 0.20, "google.com should have low prob");

        let (prob_bad, _) = model.predict_url("http://paypal-verification-security-login.xyz/account/verify.php?cmd=eval");
        println!("phishing prob: {}", prob_bad);
        assert!(prob_bad > 0.85, "phishing url should have high prob");
    }
}
