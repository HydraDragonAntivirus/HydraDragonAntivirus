//! Killchain centroid anomaly scorer (unsupervised burn port).
//!
//! Model file `kc_model.json`: `{kind, n_features, vocab, mu, sd,
//! meta.threshold}`. Score for an event feature vector x is
//! `sum(|x - mu| / sd)` on the burn NdArray backend; anomalous when
//! `score >= threshold`. No malware names, paths, or hashes anywhere:
//! labels (eval only) come from engine verdict fields, features are
//! behavior-only (identities, oracles, hashes, exact free text excluded).
//! Feature extraction mirrors the Python trainer exactly.

use burn::backend::ndarray::NdArrayDevice;
use burn::backend::NdArray;
use burn::tensor::Tensor;
use serde_json::Value;
use std::collections::HashMap;

pub type InferBackend = NdArray<f32>;

const IDENTITY_KEYS: &[&str] = &[
    "imagefile",
    "imagepath",
    "cmdline",
    "commandline",
    "exepath",
    "appname",
];

const EXCLUDE_SUB: &[&str] = &[
    "verdict",
    "threat",
    "hash",
    "ticktime",
    "creationtime",
    "accesstime",
    "$$",
];
const EXCLUDE_EQ: &[&str] = &["id", "pid", "gid", "sid", "time"];
const EXCLUDE_END: &[&str] = &["_id", ".id"];

// Free-text payload keys: presence + length only, never exact values.
const DATA_KEYS: &[&str] = &["data", "content", "blob", "script", "scripttext", "value"];

fn key_excluded(kl: &str) -> bool {
    if EXCLUDE_EQ.contains(&kl) {
        return true;
    }
    if EXCLUDE_END.iter().any(|s| kl.ends_with(s)) {
        return true;
    }
    EXCLUDE_SUB.iter().any(|s| kl.contains(s))
}

fn dirclass(p: &str) -> &'static str {
    let l = p.to_lowercase().replace('/', "\\");
    if l.is_empty() {
        return "none";
    }
    if l.contains("startup") {
        return "startup";
    }
    if l.contains("\\system32") || l.contains("\\syswow64") || l.starts_with("%systemroot%") {
        return "system32";
    }
    if l.contains("programdata") {
        return "programdata";
    }
    if l.contains("\\temp\\") || l.contains("\\tmp\\") {
        return "temp";
    }
    if l.contains("appdata") {
        return "appdata";
    }
    if l.starts_with("\\\\.\\pipe\\") {
        return "pipe";
    }
    if l.contains("harddisk") {
        return "device";
    }
    if l.contains("\\windows\\") || l.starts_with("%systemroot%") {
        return "windows_other";
    }
    if l.contains("program files") {
        return "progfiles";
    }
    if l.contains("\\users\\") {
        return "user";
    }
    "other"
}

fn ext_of(p: &str) -> String {
    let l = p.to_lowercase();
    match l.rfind('.') {
        Some(pos) => {
            let tail = &l[pos + 1..];
            if (1..=5).contains(&tail.len())
                && tail.chars().all(|c| c.is_ascii_alphanumeric())
            {
                tail.to_string()
            } else {
                "none".to_string()
            }
        }
        None => "none".to_string(),
    }
}

fn is_pathy(s: &str) -> bool {
    (s.contains('\\') || s.contains('/') || s.starts_with('%')) && s.chars().count() > 3
}

fn logbucket(x: f64) -> String {
    if !x.is_finite() || x <= 0.0 {
        return "0".to_string();
    }
    // int(math.log10(x + 1)); truncation == floor for positives.
    ((x + 1.0).log10().floor() as i64).to_string()
}

fn trim_prefix(prefix: &str) -> &str {
    prefix.strip_suffix('.').unwrap_or(prefix)
}

fn flatten(prefix: &str, val: &Value, f: &mut HashMap<String, f32>, depth: usize) {
    if depth > 4 || f.len() > 2000 {
        return;
    }
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let kl = k.to_lowercase();
                if key_excluded(&kl) {
                    continue;
                }
                if kl.contains("kernelstack") {
                    continue; // handled explicitly (modules + frame count, no offsets)
                }
                if DATA_KEYS.contains(&kl.as_str()) {
                    f.insert(format!("{prefix}{kl}_present"), 1.0);
                    let len = match v {
                        Value::String(s) => s.chars().count(),
                        _ => v.to_string().len(),
                    };
                    f.insert(
                        format!("{prefix}{kl}_len~{}", logbucket(len as f64)),
                        1.0,
                    );
                    continue;
                }
                if IDENTITY_KEYS.iter().any(|idk| kl.contains(idk)) {
                    f.insert(format!("has_{prefix}{kl}"), 1.0);
                    continue;
                }
                let child = format!("{prefix}{kl}.");
                flatten(&child, v, f, depth + 1);
            }
        }
        Value::Array(arr) => {
            // DictVectorizer one-hots string values: effective feature is
            // `len_<path>=<bucket>` (e.g. len_raw.processes=2).
            f.insert(
                format!("len_{}={}", trim_prefix(prefix), logbucket(arr.len() as f64)),
                1.0,
            );
            for v in arr.iter().take(5) {
                flatten(prefix, v, f, depth + 1);
            }
        }
        Value::Bool(b) => {
            f.insert(format!("{}={}", trim_prefix(prefix), i32::from(*b)), 1.0);
        }
        Value::Number(n) => {
            let x = n.as_f64().unwrap_or(f64::NAN);
            f.insert(format!("{}~{}", trim_prefix(prefix), logbucket(x)), 1.0);
        }
        Value::String(s) => {
            if s.is_empty() || s == "<undefined>" || s == "null" {
                return;
            }
            if is_pathy(s) {
                f.insert(format!("{prefix}dir={}", dirclass(s)), 1.0);
                f.insert(format!("{prefix}ext={}", ext_of(s)), 1.0);
                f.insert(
                    format!("{prefix}len~{}", logbucket(s.chars().count() as f64)),
                    1.0,
                );
            } else if s.chars().count() > 80 {
                f.insert(
                    format!("{prefix}longlen~{}", logbucket(s.chars().count() as f64)),
                    1.0,
                );
            } else {
                f.insert(format!("{}={}", trim_prefix(prefix), s.to_lowercase()), 1.0);
            }
        }
        Value::Null => {}
    }
}

fn is_ipv4_port(t: &str) -> bool {
    let (host, port) = match t.rfind(':') {
        Some(i) => (&t[..i], Some(&t[i + 1..])),
        None => (t, None),
    };
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    if !parts
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    if let Some(port) = port {
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// "mod+off;mod+off" / "addr,addr" -> module names + frame count only.
/// Raw offsets/addresses are per-boot fingerprints, never features.
fn kstack_features(raw: &Value, f: &mut HashMap<String, f32>) {
    for key in ["kernelStackSymbols", "kernelstacksymbols", "kernelStack", "kernelstack"] {
        let Some(s) = raw.get(key).and_then(|v| v.as_str()) else {
            continue;
        };
        if s.is_empty() {
            continue;
        }
        let mut mods: Vec<String> = Vec::new();
        let mut nframes = 0usize;
        for p in s.split([';', ',']) {
            let p = p.trim().to_lowercase();
            if p.is_empty() || p.chars().all(|c| c == '0') {
                continue;
            }
            nframes += 1;
            let first = p.split(['+', '!']).next().unwrap_or("");
            let base = first.rsplit(['\\', '/']).next().unwrap_or("");
            if !base.is_empty() && base.len() < 64 && !mods.contains(&base.to_string()) {
                mods.push(base.to_string());
            }
        }
        mods.sort();
        for m in mods {
            f.insert(format!("kstack_mod={m}"), 1.0);
        }
        f.insert(format!("kstack_frames~{}", logbucket(nframes as f64)), 1.0);
        break;
    }
}

pub fn extract_features(
    event: &str,
    details: &str,
    raw: &Value,
    dt_prev: Option<i64>,
) -> HashMap<String, f32> {
    let mut f: HashMap<String, f32> = HashMap::new();
    f.insert(format!("event={event}"), 1.0);

    for (tag, name) in [
        ("[File:", "File"),
        ("[Reg:", "Reg"),
        ("[API:", "API"),
        ("[Net:", "Net"),
    ] {
        if details.starts_with(&format!(" {tag}")) || details.starts_with(tag) {
            f.insert(format!("det={name}"), 1.0);
        }
    }
    // First [File|Reg|API|Net: ...] capture (leftmost wins).
    let mut best: Option<(usize, &str)> = None;
    for tag in ["[File:", "[Reg:", "[API:", "[Net:"] {
        if let Some(pos) = details.find(tag) {
            if best.map(|(p, _)| pos < p).unwrap_or(true) {
                best = Some((pos, tag));
            }
        }
    }
    if let Some((pos, _tag)) = best {
        let after = &details[pos..];
        if let Some(colon) = after.find(':') {
            let mut val = after[colon + 1..].trim_start().to_string();
            if let Some(end) = val.find(']') {
                val.truncate(end);
                if is_pathy(&val) {
                    f.insert(format!("detdir={}", dirclass(&val)), 1.0);
                    f.insert(format!("detext={}", ext_of(&val)), 1.0);
                } else if val.contains('!') {
                    let mut parts = val.splitn(2, '!');
                    let m = parts.next().unwrap_or("").to_lowercase();
                    let fn_ = parts.next().unwrap_or("").to_lowercase();
                    f.insert(format!("detmod={m}"), 1.0);
                    f.insert(format!("detfn={fn_}"), 1.0);
                } else if is_ipv4_port(&val) {
                    f.insert("detnet_ip=1".to_string(), 1.0);
                    f.insert(
                        format!("detnet_len~{}", logbucket(val.chars().count() as f64)),
                        1.0,
                    );
                } else if !val.is_empty() {
                    // Free text / hostname: never exact, presence + length only.
                    f.insert("dettxt_present=1".to_string(), 1.0);
                    f.insert(
                        format!("dettxt_len~{}", logbucket(val.chars().count() as f64)),
                        1.0,
                    );
                }
            }
        }
    }

    flatten("raw.", raw, &mut f, 0);
    kstack_features(raw, &mut f);

    let dt_key = match dt_prev {
        Some(dt) if dt >= 0 => format!("dt_prev~{}", logbucket(dt as f64)),
        _ => "dt_prev~none".to_string(),
    };
    f.insert(dt_key, 1.0);

    f.insert(
        "has_net".to_string(),
        if details.contains("[Net:") { 1.0 } else { 0.0 },
    );
    f.insert(
        "has_target".to_string(),
        if raw.get("target").map(|v| v.is_object()).unwrap_or(false) {
            1.0
        } else {
            0.0
        },
    );
    f.insert(
        "has_thread".to_string(),
        if raw.get("thread").map(|v| v.is_object()).unwrap_or(false) {
            1.0
        } else {
            0.0
        },
    );
    f.insert(
        "has_stack".to_string(),
        if raw.get("kernelStackSymbols").is_some() {
            1.0
        } else {
            0.0
        },
    );
    match raw.get("accessMask") {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                f.insert(format!("access={i}"), 1.0);
            } else if let Some(u) = n.as_u64() {
                f.insert(format!("access={u}"), 1.0);
            } else if let Some(fl) = n.as_f64() {
                f.insert(format!("access={fl}"), 1.0);
            }
        }
        _ => {
            f.insert("access=None".to_string(), 1.0);
        }
    }
    f
}

/// Eval-only label from ENGINE verdict fields. No names, no paths.
pub fn label_event(_exe: &str, raw: &Value) -> u8 {
    if let Some(Value::String(t)) = raw.get("threatName") {
        if !t.is_empty() {
            return 1;
        }
    }
    if let Some(v) = raw.get("flsVerdict") {
        let hit = v.as_i64().map(|i| i == 2 || i == 3).unwrap_or(false)
            || v.as_u64().map(|u| u == 2 || u == 3).unwrap_or(false)
            || v.as_f64().map(|x| x == 2.0 || x == 3.0).unwrap_or(false);
        if hit {
            return 1;
        }
    }
    0
}



/// Tri-state verdict from the hybrid killchain engine
#[derive(Debug, Clone, PartialEq)]
pub enum KcVerdict {
    /// Recognized benign behavior profile (White list)
    Benign { distance: f32 },
    /// Recognized malware killchain profile (Black list) -> Kill and Quarantine
    Malicious { distance: f32, confidence: f32 },
    /// Unknown anomaly -> Forward to Firewall / HIPS engine
    UnknownToHips {
        benign_dist: f32,
        malware_dist: f32,
        reason: String,
    },
}

/// Dual-centroid hybrid classifier & anomaly scorer.
/// Distinguishes known clean, known malware, and routes unknown behavior to HIPS.
pub struct KcHybridModel {
    index: HashMap<String, usize>,
    mu_benign: Vec<f32>,
    sd_benign: Vec<f32>,
    mu_malware: Vec<f32>,
    sd_malware: Vec<f32>,
    benign_threshold: f32,
    malware_threshold: f32,
}

impl KcHybridModel {
    pub fn load_json(path: &str) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        let v: Value =
            serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
        if v.get("kind").and_then(|k| k.as_str()) != Some("hybrid_centroid") {
            return Err("kc_hybrid_model.json: unexpected kind (want hybrid_centroid)".to_string());
        }
        let vocab: Vec<String> = v
            .get("vocab")
            .and_then(|x| x.as_array())
            .ok_or("kc_hybrid_model.json: missing vocab")?
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect();
        let mu_benign: Vec<f32> = v
            .get("mu_benign")
            .and_then(|x| x.as_array())
            .ok_or("kc_hybrid_model.json: missing mu_benign")?
            .iter()
            .map(|x| x.as_f64().unwrap_or(0.0) as f32)
            .collect();
        let sd_benign: Vec<f32> = v
            .get("sd_benign")
            .and_then(|x| x.as_array())
            .ok_or("kc_hybrid_model.json: missing sd_benign")?
            .iter()
            .map(|x| x.as_f64().unwrap_or(1.0) as f32)
            .collect();
        let mu_malware: Vec<f32> = v
            .get("mu_malware")
            .and_then(|x| x.as_array())
            .ok_or("kc_hybrid_model.json: missing mu_malware")?
            .iter()
            .map(|x| x.as_f64().unwrap_or(0.0) as f32)
            .collect();
        let sd_malware: Vec<f32> = v
            .get("sd_malware")
            .and_then(|x| x.as_array())
            .ok_or("kc_hybrid_model.json: missing sd_malware")?
            .iter()
            .map(|x| x.as_f64().unwrap_or(1.0) as f32)
            .collect();
        let benign_threshold = v
            .get("meta")
            .and_then(|m| m.get("benign_threshold"))
            .and_then(|t| t.as_f64())
            .unwrap_or(275.0) as f32;
        let malware_threshold = v
            .get("meta")
            .and_then(|m| m.get("malware_threshold"))
            .and_then(|t| t.as_f64())
            .unwrap_or(130.0) as f32;

        let mut index = HashMap::with_capacity(vocab.len());
        for (i, k) in vocab.iter().enumerate() {
            index.insert(k.clone(), i);
        }
        Ok(Self {
            index,
            mu_benign,
            sd_benign,
            mu_malware,
            sd_malware,
            benign_threshold,
            malware_threshold,
        })
    }

    /// Evaluates event features into a Tri-State KcVerdict
    pub fn evaluate(&self, feats: &HashMap<String, f32>) -> KcVerdict {
        let n = self.index.len();
        let mut x = vec![0f32; n];
        for (k, v) in feats {
            if let Some(&i) = self.index.get(k) {
                x[i] += v;
            }
        }
        let device = NdArrayDevice::default();
        let xv = Tensor::<InferBackend, 1>::from_floats(x.as_slice(), &device).reshape([n, 1]);

        let mu_b = Tensor::<InferBackend, 1>::from_floats(self.mu_benign.as_slice(), &device).reshape([n, 1]);
        let sd_b = Tensor::<InferBackend, 1>::from_floats(self.sd_benign.as_slice(), &device).reshape([n, 1]);
        let dist_b: f32 = ((xv.clone() - mu_b) / sd_b).abs().sum().into_scalar();

        let mu_m = Tensor::<InferBackend, 1>::from_floats(self.mu_malware.as_slice(), &device).reshape([n, 1]);
        let sd_m = Tensor::<InferBackend, 1>::from_floats(self.sd_malware.as_slice(), &device).reshape([n, 1]);
        let dist_m: f32 = ((xv - mu_m) / sd_m).abs().sum().into_scalar();

        if dist_m <= self.malware_threshold && dist_m < dist_b {
            let conf = 1.0 - (dist_m / self.malware_threshold).clamp(0.0, 1.0);
            KcVerdict::Malicious {
                distance: dist_m,
                confidence: 0.5 + 0.5 * conf,
            }
        } else if dist_b <= self.benign_threshold && dist_b < dist_m {
            KcVerdict::Benign { distance: dist_b }
        } else {
            KcVerdict::UnknownToHips {
                benign_dist: dist_b,
                malware_dist: dist_m,
                reason: format!(
                    "Anomaly: dist_b={:.1} (thresh={:.1}), dist_m={:.1} (thresh={:.1})",
                    dist_b, self.benign_threshold, dist_m, self.malware_threshold
                ),
            }
        }
    }
}

