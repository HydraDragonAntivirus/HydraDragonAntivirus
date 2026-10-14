//! ML training datasets filled from the cloud.
//!
//! `dataset_paths.json` next to the server (see `yarGen/TRAINING_GUIDE.md`) names the
//! same folders the ML and HydraDragonSig training uses:
//!
//! ```json
//! {
//!   "windows_malware":    "C:\\...\\usbdosyalar\\datamaliciousorder",
//!   "windows_clean":      "C:\\...\\usbdosyalar\\data2",
//!   "android_malware":    "C:\\...\\HydraDragonAV-Mobile\\dataset\\malicious",
//!   "android_clean":      "C:\\...\\HydraDragonAV-Mobile\\dataset\\benign",
//!   "javascript_malware": "C:\\...\\usbdosyalar\\javascript\\malicious",
//!   "javascript_clean":   "C:\\...\\usbdosyalar\\javascript\\data2"
//! }
//! ```
//!
//! A file is copied as `<SHA256>.<ext>` into the folder of its platform (APK -> android,
//! PE -> windows, JavaScript -> javascript) and label, ONLY when the label comes from a
//! reliable source, so the models never learn the engine's own mistakes:
//!
//! * an analyst verdict (human review) - malicious or clean; a later verdict that flips
//!   the label moves the copy to the other folder;
//! * analyst signatures / the analyst company allow-list;
//! * an exact SHA-256 match in the verified benign reference corpus;
//! * a valid, trusted Authenticode signature with a clean verdict.
//!
//! XOR-filter hash verdicts, ML / heuristic verdicts, TLSH look-alikes
//! (`possible_clean`) and `suspicious` are never copied. Missing keys or an absent file
//! turn that folder (or the whole feature) off.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::engine_adapter::ResultMessage;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DatasetPaths {
    #[serde(default)]
    pub windows_malware: Option<PathBuf>,
    #[serde(default)]
    pub windows_clean: Option<PathBuf>,
    #[serde(default)]
    pub android_malware: Option<PathBuf>,
    #[serde(default)]
    pub android_clean: Option<PathBuf>,
    #[serde(default)]
    pub javascript_malware: Option<PathBuf>,
    #[serde(default)]
    pub javascript_clean: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Android,
    JavaScript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Malware,
    Clean,
}

pub fn config_path() -> PathBuf {
    crate::config::app_dir().join("dataset_paths.json")
}

impl DatasetPaths {
    /// `dataset_paths.json` next to the server; None when absent or empty.
    pub fn load() -> Option<Self> {
        // The archive server is read-only: it never writes datasets.
        if crate::config::is_archive() {
            return None;
        }
        let path = config_path();
        let text = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<DatasetPaths>(&text) {
            Ok(p) if p.any() => {
                eprintln!("[dataset] ML dataset folders from {}", path.display());
                Some(p)
            }
            Ok(_) => None,
            Err(e) => {
                eprintln!("[dataset] {} ignored: {e}", path.display());
                None
            }
        }
    }

    fn any(&self) -> bool {
        [
            &self.windows_malware,
            &self.windows_clean,
            &self.android_malware,
            &self.android_clean,
            &self.javascript_malware,
            &self.javascript_clean,
        ]
        .iter()
        .any(|p| p.as_ref().is_some_and(|p| !p.as_os_str().is_empty()))
    }

    pub fn dir(&self, platform: Platform, label: Label) -> Option<&Path> {
        let p = match (platform, label) {
            (Platform::Windows, Label::Malware) => &self.windows_malware,
            (Platform::Windows, Label::Clean) => &self.windows_clean,
            (Platform::Android, Label::Malware) => &self.android_malware,
            (Platform::Android, Label::Clean) => &self.android_clean,
            (Platform::JavaScript, Label::Malware) => &self.javascript_malware,
            (Platform::JavaScript, Label::Clean) => &self.javascript_clean,
        };
        p.as_deref().filter(|p| !p.as_os_str().is_empty())
    }

    /// Copies `data` as `<SHA256>.<ext>` into the folder for its platform and label and
    /// removes a copy this server put under the other label. Returns the path written.
    pub fn export(&self, sha256: &str, data: &[u8], name: &str, label: Label) -> Option<PathBuf> {
        let platform = platform_of(data, name)?;
        let dir = self.dir(platform, label)?;
        let file = format!("{}.{}", sha256.to_ascii_uppercase(), extension(platform, name));
        let other = match label {
            Label::Malware => Label::Clean,
            Label::Clean => Label::Malware,
        };
        if let Some(o) = self.dir(platform, other) {
            let stale = o.join(&file);
            if stale.exists() {
                let _ = std::fs::remove_file(&stale);
            }
        }
        let target = dir.join(&file);
        if target.exists() {
            return None;
        }
        std::fs::create_dir_all(dir).ok()?;
        let tmp = dir.join(format!("{file}.part"));
        std::fs::write(&tmp, data).ok()?;
        if std::fs::rename(&tmp, &target).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return None;
        }
        Some(target)
    }
}

/// Label of an engine result when (and only when) it comes from a reliable source.
pub fn reliable_label(res: &ResultMessage) -> Option<(Label, &'static str)> {
    if crate::engine_adapter::is_xorfilter_result(res) {
        return None;
    }
    let ruleset = res.rule.as_ref().and_then(|r| r["ruleset"].as_str()).unwrap_or("");
    match res.verdict.as_str() {
        "malicious" if ruleset.starts_with("analyst/") => Some((Label::Malware, "analyst signature")),
        "clean" if ruleset == "analyst/company_allowlist" => Some((Label::Clean, "analyst company allow-list")),
        "clean" if ruleset == "benign_corpus/sha256" => Some((Label::Clean, "benign reference corpus")),
        "clean" if res.signer.as_ref().is_some_and(|s| s.signed && s.trusted) => Some((Label::Clean, "trusted signature")),
        _ => None,
    }
}

/// Label from an analyst verdict (`suspicious` and the rest are not labels).
pub fn human_label(verdict: &str) -> Option<Label> {
    match verdict {
        "malicious" => Some(Label::Malware),
        "clean" => Some(Label::Clean),
        _ => None,
    }
}

pub fn platform_of(data: &[u8], name: &str) -> Option<Platform> {
    let lower = name.to_ascii_lowercase();
    if data.starts_with(b"PK\x03\x04") {
        let head = &data[..data.len().min(8 * 1024 * 1024)];
        if lower.ends_with(".apk") || (contains(head, b"AndroidManifest.xml") && contains(head, b"classes")) {
            return Some(Platform::Android);
        }
        return None;
    }
    if is_pe(data) {
        return Some(Platform::Windows);
    }
    let js_ext = [".js", ".mjs", ".cjs", ".jse"].iter().any(|e| lower.ends_with(e));
    if js_ext && !data.is_empty() && !data[..data.len().min(4096)].contains(&0) {
        return Some(Platform::JavaScript);
    }
    None
}

fn is_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }
    let off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data.get(off..off.saturating_add(4)) == Some(b"PE\0\0".as_slice())
}

fn extension(platform: Platform, name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    match platform {
        Platform::Android => "apk",
        Platform::JavaScript => "js",
        Platform::Windows => {
            for ext in ["dll", "sys", "scr", "ocx", "cpl", "drv", "efi"] {
                if lower.ends_with(&format!(".{ext}")) {
                    return ext;
                }
            }
            "exe"
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe() -> Vec<u8> {
        let mut d = vec![0u8; 0x100];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c] = 0x80;
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d
    }

    #[test]
    fn platforms() {
        assert_eq!(platform_of(&pe(), "a.dll"), Some(Platform::Windows));
        assert_eq!(platform_of(b"PK\x03\x04...AndroidManifest.xml...classes.dex", "x.zip"), Some(Platform::Android));
        assert_eq!(platform_of(b"PK\x03\x04 plain zip", "x.zip"), None);
        assert_eq!(platform_of(b"var a = 1;", "a.js"), Some(Platform::JavaScript));
        assert_eq!(platform_of(b"var a = 1;", "a.txt"), None);
        assert_eq!(platform_of(b"MZ not a pe", "a.exe"), None);
    }

    #[test]
    fn export_moves_between_labels() {
        let root = std::env::temp_dir().join(format!("multron_dataset_test_{}", std::process::id()));
        let paths = DatasetPaths {
            windows_malware: Some(root.join("mal")),
            windows_clean: Some(root.join("clean")),
            ..Default::default()
        };
        let sha = "ab".repeat(32);
        let p = paths.export(&sha, &pe(), "x.dll", Label::Clean).unwrap();
        assert!(p.ends_with(format!("{}.dll", sha.to_ascii_uppercase())));
        assert!(paths.export(&sha, &pe(), "x.dll", Label::Clean).is_none(), "already there");
        paths.export(&sha, &pe(), "x.dll", Label::Malware).unwrap();
        assert!(!p.exists(), "flipped label removes the old copy");
        assert!(paths.export(&sha, b"var a;", "a.js", Label::Clean).is_none(), "no javascript folder set");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn labels_need_a_reliable_source() {
        let mut r: ResultMessage = serde_json::from_value(serde_json::json!({ "type": "result", "id": 0 })).unwrap();
        r.verdict = "malicious".into();
        assert_eq!(reliable_label(&r), None, "plain engine verdict");
        r.rule = Some(serde_json::json!({ "ruleset": "analyst/clamav" }));
        assert_eq!(reliable_label(&r).map(|x| x.0), Some(Label::Malware));
        r.rule = Some(serde_json::json!({ "ruleset": "xorfilter/malicious_sha256" }));
        assert_eq!(reliable_label(&r), None, "xor filter is not reliable");
        r.verdict = "clean".into();
        r.rule = Some(serde_json::json!({ "ruleset": "benign_corpus/sha256" }));
        assert_eq!(reliable_label(&r).map(|x| x.0), Some(Label::Clean));
        assert_eq!(human_label("suspicious"), None);
    }
}
