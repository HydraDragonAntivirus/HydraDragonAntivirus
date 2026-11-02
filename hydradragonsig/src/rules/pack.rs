//! Signature pack manifest (`rule_pack.yml`): a version number plus the
//! SHA-256 and size of every rule file of the pack, so a scanner loads a pack
//! only when every file is exactly the one that was released.
//!
//! ```yaml
//! version: 2
//! generated_at: "2026-11-02T12:00:00Z"
//! notes: "generic pack"
//! files:
//!   - path: rules/base.yaml
//!     sha256: 0f343b0931126a20f133d67c2b018a3b...
//!     size: 12345
//! ```
//!
//! File paths are relative to the manifest's directory, `/`-separated, and
//! must stay inside it: absolute paths, `..` components and symbolic links are
//! refused. Hashes cover the exact bytes, so a line-ending conversion of a rule
//! file (CRLF/LF) is a mismatch like any other edit.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    /// Pack version, a positive integer.
    pub version: u32,
    /// Creation time (informational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub files: Vec<PackFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackFile {
    /// Path relative to the manifest directory, `/`-separated.
    pub path: String,
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
}

/// The relative path as written in a manifest, or why it is refused.
fn checked_relative(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    if path.trim().is_empty() {
        bail!("empty path");
    }
    if p.is_absolute() || path.starts_with(['/', '\\']) {
        bail!("`{path}` is absolute; paths are relative to the manifest");
    }
    for c in p.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => bail!("`{path}` leaves the manifest directory"),
        }
    }
    Ok(p.to_path_buf())
}

impl RulePack {
    /// Parse a manifest and check its shape (no file access).
    pub fn parse(text: &str) -> Result<Self> {
        let pack: RulePack = yaml_serde::from_str(text).context("invalid rule pack manifest")?;
        if pack.version == 0 {
            bail!("rule pack `version` must be a positive integer");
        }
        if pack.files.is_empty() {
            bail!("rule pack lists no files");
        }
        let mut seen = std::collections::HashSet::new();
        for f in &pack.files {
            checked_relative(&f.path)?;
            if !(f.sha256.len() == 64 && f.sha256.chars().all(|c| c.is_ascii_hexdigit())) {
                bail!("`{}`: sha256 must be 64 hex characters", f.path);
            }
            if !seen.insert(f.path.replace('\\', "/").to_ascii_lowercase()) {
                bail!("`{}` is listed twice", f.path);
            }
        }
        Ok(pack)
    }

    pub fn to_yaml(&self) -> Result<String> {
        let body = yaml_serde::to_string(self).context("failed to write rule pack manifest")?;
        Ok(format!("# HydraDragonSig rule pack manifest: every file must match its sha256 and size.\n{body}"))
    }

    /// Full paths of the listed files, in manifest order (rule load order).
    pub fn load_paths(&self, base_dir: &Path) -> Vec<PathBuf> {
        self.files.iter().map(|f| base_dir.join(&f.path)).collect()
    }

    /// Check every listed file under `base_dir`. The error names each file
    /// that is missing, a symbolic link, or differs in size or SHA-256.
    pub fn verify(&self, base_dir: &Path) -> Result<()> {
        let mut problems = Vec::new();
        for f in &self.files {
            let full = base_dir.join(checked_relative(&f.path)?);
            let meta = match std::fs::symlink_metadata(&full) {
                Ok(m) => m,
                Err(e) => {
                    problems.push(format!("{}: missing ({e})", f.path));
                    continue;
                }
            };
            if meta.file_type().is_symlink() {
                problems.push(format!("{}: is a symbolic link", f.path));
                continue;
            }
            if !meta.is_file() {
                problems.push(format!("{}: not a regular file", f.path));
                continue;
            }
            if meta.len() != f.size {
                problems.push(format!("{}: size {} != manifest {}", f.path, meta.len(), f.size));
                continue;
            }
            let bytes = std::fs::read(&full).with_context(|| format!("failed to read {}", full.display()))?;
            let actual = crate::utils::hash::sha256_hex(&bytes);
            if !actual.eq_ignore_ascii_case(&f.sha256) {
                problems.push(format!("{}: sha256 {} != manifest {}", f.path, actual, f.sha256.to_ascii_lowercase()));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            bail!(
                "rule pack v{}: {} of {} file(s) do not match:\n  {}",
                self.version,
                problems.len(),
                self.files.len(),
                problems.join("\n  ")
            )
        }
    }
}

/// Parse a manifest and verify its files against `base_dir`.
pub fn verify_yaml(text: &str, base_dir: &Path) -> Result<RulePack> {
    let pack = RulePack::parse(text)?;
    pack.verify(base_dir)?;
    Ok(pack)
}

/// Read, parse and verify a manifest; files resolve against its directory.
pub fn load_manifest(path: &Path) -> Result<RulePack> {
    let text = std::fs::read_to_string(path).with_context(|| format!("failed to read rule pack {}", path.display()))?;
    verify_yaml(&text, manifest_dir(path)).with_context(|| path.display().to_string())
}

/// Directory the paths of the manifest at `path` are relative to.
pub fn manifest_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Build a manifest for `paths` (which must lie under `base_dir`, the directory
/// the manifest will be written to).
pub fn write_manifest(paths: &[PathBuf], base_dir: &Path, version: u32, notes: Option<String>) -> Result<RulePack> {
    if version == 0 {
        bail!("rule pack version must be a positive integer");
    }
    if paths.is_empty() {
        bail!("no rule files to put in the pack");
    }
    let base = base_dir
        .canonicalize()
        .with_context(|| format!("rule pack directory {} does not exist", base_dir.display()))?;
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        if std::fs::symlink_metadata(path).with_context(|| format!("failed to read {}", path.display()))?.file_type().is_symlink() {
            bail!("{} is a symbolic link; packs hold regular files only", path.display());
        }
        let full = path.canonicalize().with_context(|| format!("failed to resolve {}", path.display()))?;
        let rel = full
            .strip_prefix(&base)
            .with_context(|| format!("{} is outside the pack directory {}", path.display(), base.display()))?;
        let rel = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
        let bytes = std::fs::read(&full).with_context(|| format!("failed to read {}", full.display()))?;
        files.push(PackFile { path: rel, sha256: crate::utils::hash::sha256_hex(&bytes), size: bytes.len() as u64 });
    }
    let pack = RulePack {
        version,
        generated_at: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        notes,
        files,
    };
    RulePack::parse(&pack.to_yaml()?)?;
    Ok(pack)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hydradragonsig-pack-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        dir
    }

    #[test]
    fn write_read_verify_round_trip() {
        let dir = temp_dir("roundtrip");
        std::fs::write(dir.join("rules/a.yaml"), "rules: []\n").unwrap();
        std::fs::write(dir.join("b.yaml"), "rules: []\r\n").unwrap();
        let pack = write_manifest(&[dir.join("rules/a.yaml"), dir.join("b.yaml")], &dir, 2, Some("generic pack".into())).unwrap();
        assert_eq!(pack.files[0].path, "rules/a.yaml");
        assert_eq!(pack.files[0].size, 10);
        assert_eq!(pack.files[0].sha256, crate::utils::hash::sha256_hex(b"rules: []\n"));
        let manifest = dir.join("rule_pack.yml");
        std::fs::write(&manifest, pack.to_yaml().unwrap()).unwrap();
        let loaded = load_manifest(&manifest).unwrap();
        assert_eq!(loaded, pack);
        assert_eq!(loaded.load_paths(&dir), vec![dir.join("rules/a.yaml"), dir.join("b.yaml")]);

        // Same size, one byte different.
        std::fs::write(dir.join("rules/a.yaml"), "rules: {}\n").unwrap();
        let err = format!("{:#}", load_manifest(&manifest).unwrap_err());
        assert!(err.contains("rules/a.yaml: sha256"), "{err}");
        assert!(!err.contains("b.yaml"), "only the changed file is reported: {err}");

        // Line-ending conversion changes size and hash.
        std::fs::write(dir.join("rules/a.yaml"), "rules: []\n").unwrap();
        std::fs::write(dir.join("b.yaml"), "rules: []\n").unwrap();
        let err = format!("{:#}", load_manifest(&manifest).unwrap_err());
        assert!(err.contains("b.yaml: size 10 != manifest 11"), "{err}");

        std::fs::remove_file(dir.join("b.yaml")).unwrap();
        assert!(format!("{:#}", load_manifest(&manifest).unwrap_err()).contains("b.yaml: missing"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_shape_checks() {
        let hash = "a".repeat(64);
        let ok = format!("version: 1\nfiles:\n  - path: r.yaml\n    sha256: {hash}\n    size: 1\n");
        assert!(RulePack::parse(&ok).is_ok());
        for (bad, why) in [
            (ok.replace("version: 1", "version: 0"), "positive"),
            (format!("version: 1\nfiles: []\n"), "no files"),
            (ok.replace("r.yaml", "../r.yaml"), "leaves"),
            (ok.replace("r.yaml", "/etc/r.yaml"), "absolute"),
            (ok.replace(&hash, "abc"), "64 hex"),
            (format!("{ok}  - path: R.yaml\n    sha256: {hash}\n    size: 1\n"), "twice"),
            (ok.replace("size: 1", "size: 1\n    extra: 1"), "invalid rule pack"),
            (ok.replace("    size: 1\n", ""), "invalid rule pack"),
        ] {
            let err = format!("{:#}", RulePack::parse(&bad).unwrap_err());
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    #[test]
    fn files_outside_the_pack_directory_are_refused() {
        let dir = temp_dir("outside");
        let outside = dir.join("outside.yaml");
        std::fs::write(&outside, "rules: []\n").unwrap();
        let err = format!("{:#}", write_manifest(&[outside], &dir.join("rules"), 1, None).unwrap_err());
        assert!(err.contains("outside the pack directory"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
