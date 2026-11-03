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
//!
//! A pack may also carry an Ed25519 signature over its canonical transcript
//! ([`RulePack::transcript`]), which binds the version, time, notes and every
//! `path`/`size`/`sha256` independent of the YAML formatting:
//!
//! ```yaml
//! signature:
//!   algorithm: ed25519
//!   key_id: "hds-prod-2026-01"
//!   value: "<128 hex>"
//! ```
//!
//! [`load_manifest_with_policy`] checks, in this order and failing closed:
//! manifest shape, `version >= min_version` (anti-rollback), the signature
//! against the trusted keys (before any rule file is opened), then the files.

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Domain separator and transcript version of the signed payload.
const TRANSCRIPT_MAGIC: &str = "HDS-PACK-V1\n";

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
    /// Ed25519 signature over [`RulePack::transcript`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PackSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSignature {
    /// Always `ed25519`.
    pub algorithm: String,
    /// Names the trusted public key the pack was signed with.
    pub key_id: String,
    /// 128 hex characters (64-byte Ed25519 signature).
    pub value: String,
}

/// A public key a signed pack may be verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    /// `None` for a bare key, which is tried for any `key_id`.
    pub key_id: Option<String>,
    pub key: VerifyingKey,
}

/// How [`load_manifest_with_policy`] judges a pack.
#[derive(Debug, Clone, Default)]
pub struct PackVerifyPolicy {
    /// Keys a signature may verify against. Non-empty means the pack must be
    /// signed by one of them.
    pub trusted_keys: Vec<TrustedKey>,
    /// Refuse unsigned packs (needs `trusted_keys`).
    pub require_signature: bool,
    /// Refuse packs older than this version (anti-rollback).
    pub min_version: Option<u32>,
}

impl PackVerifyPolicy {
    /// The signature is checked: keys were given or a signature is required.
    pub fn checks_signature(&self) -> bool {
        self.require_signature || !self.trusted_keys.is_empty()
    }
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
    // Tabs and newlines separate the fields of the signed transcript.
    if path.chars().any(char::is_control) {
        bail!("`{}` holds a control character", path.escape_debug());
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
        if let Some(sig) = &pack.signature {
            if sig.algorithm != "ed25519" {
                bail!("rule pack signature algorithm `{}` is not supported (ed25519)", sig.algorithm);
            }
            if sig.key_id.trim().is_empty() || sig.key_id.chars().any(char::is_control) {
                bail!("rule pack signature needs a `key_id` without control characters");
            }
            if !(sig.value.len() == 128 && sig.value.chars().all(|c| c.is_ascii_hexdigit())) {
                bail!("rule pack signature value must be 128 hex characters");
            }
        }
        Ok(pack)
    }

    /// The signed bytes: a fixed header, the version, the length-prefixed
    /// `generated_at`, `notes` and signing `key_id` (`-` when absent), then one
    /// `path\tsize\tsha256` line per file sorted by path. YAML layout, comments,
    /// key order and the order of `files` do not change it.
    pub fn transcript(&self, key_id: &str) -> Vec<u8> {
        fn field(out: &mut String, v: Option<&str>) {
            match v {
                Some(v) => out.push_str(&format!("{}:{v}\n", v.len())),
                None => out.push_str("-\n"),
            }
        }
        let mut out = String::from(TRANSCRIPT_MAGIC);
        out.push_str(&format!("{}\n", self.version));
        field(&mut out, self.generated_at.as_deref());
        field(&mut out, self.notes.as_deref());
        field(&mut out, Some(key_id));
        let mut lines: Vec<String> = self
            .files
            .iter()
            .map(|f| format!("{}\t{}\t{}\n", f.path, f.size, f.sha256.to_ascii_lowercase()))
            .collect();
        lines.sort();
        out.push_str(&format!("{}\n", lines.len()));
        for l in lines {
            out.push_str(&l);
        }
        out.into_bytes()
    }

    /// Sign the pack with `key` under `key_id` (replaces any signature).
    pub fn sign(&mut self, key: &SigningKey, key_id: &str) -> Result<()> {
        if key_id.trim().is_empty() || key_id.chars().any(char::is_control) {
            bail!("signing key id must be non-empty without control characters");
        }
        let sig = key.sign(&self.transcript(key_id));
        self.signature = Some(PackSignature {
            algorithm: "ed25519".into(),
            key_id: key_id.to_string(),
            value: hex::encode(sig.to_bytes()),
        });
        Ok(())
    }

    /// Check the signature against `keys`: keys named by the signature's
    /// `key_id` when any are, else the bare keys.
    pub fn verify_signature(&self, keys: &[TrustedKey]) -> Result<()> {
        let Some(sig) = &self.signature else {
            bail!("rule pack v{} is not signed", self.version);
        };
        if keys.is_empty() {
            bail!("no trusted public key to verify the rule pack signature with");
        }
        let mut raw = [0u8; 64];
        hex::decode_to_slice(&sig.value, &mut raw).context("rule pack signature value is not hex")?;
        let signature = Signature::from_bytes(&raw);
        let named: Vec<&TrustedKey> = keys.iter().filter(|k| k.key_id.as_deref() == Some(sig.key_id.as_str())).collect();
        let candidates: Vec<&TrustedKey> = if named.is_empty() {
            keys.iter().filter(|k| k.key_id.is_none()).collect()
        } else {
            named
        };
        if candidates.is_empty() {
            bail!("rule pack is signed with key `{}`, which is not trusted", sig.key_id);
        }
        let message = self.transcript(&sig.key_id);
        if candidates.iter().any(|k| k.key.verify_strict(&message, &signature).is_ok()) {
            Ok(())
        } else {
            bail!("rule pack signature (key `{}`) does not verify: the manifest was modified or signed with another key", sig.key_id)
        }
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

/// [`verify_yaml`] under `policy`: shape, then `min_version`, then the
/// signature (before any listed file is read), then the files.
pub fn verify_yaml_with_policy(text: &str, base_dir: &Path, policy: &PackVerifyPolicy) -> Result<RulePack> {
    let pack = RulePack::parse(text)?;
    if let Some(min) = policy.min_version
        && pack.version < min
    {
        bail!("rule pack v{} is older than the minimum version {min} (rollback refused)", pack.version);
    }
    if policy.checks_signature() {
        pack.verify_signature(&policy.trusted_keys)?;
    }
    pack.verify(base_dir)?;
    Ok(pack)
}

/// [`load_manifest`] under `policy`.
pub fn load_manifest_with_policy(path: &Path, policy: &PackVerifyPolicy) -> Result<RulePack> {
    let text = std::fs::read_to_string(path).with_context(|| format!("failed to read rule pack {}", path.display()))?;
    verify_yaml_with_policy(&text, manifest_dir(path), policy).with_context(|| path.display().to_string())
}

/// Parse public keys: one per line, `key_id:<64 hex>` or a bare `<64 hex>`;
/// blank lines and `#` comments are skipped.
pub fn parse_public_keys(text: &str) -> Result<Vec<TrustedKey>> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key_id, hex_key) = match line.rsplit_once(':') {
            Some((id, k)) if !id.trim().is_empty() => (Some(id.trim().to_string()), k.trim()),
            Some(_) => bail!("public key line {}: empty key id", n + 1),
            None => (None, line),
        };
        let mut raw = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut raw)
            .map_err(|_| anyhow::anyhow!("public key line {}: expected 64 hex characters", n + 1))?;
        let key = VerifyingKey::from_bytes(&raw).map_err(|e| anyhow::anyhow!("public key line {}: {e}", n + 1))?;
        keys.push(TrustedKey { key_id, key });
    }
    if keys.is_empty() {
        bail!("no public key found");
    }
    Ok(keys)
}

/// Read a key file written by [`write_keypair`] (64 hex characters, the seed).
pub fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("failed to read signing key {}", path.display()))?;
    let mut seed = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut seed)
        .map_err(|_| anyhow::anyhow!("{}: expected a 64 hex character Ed25519 seed", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// A new random signing key.
pub fn generate_signing_key() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("no system randomness: {e}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Write `<prefix>.key` (hex seed, owner-only on Unix) and `<prefix>.pub`
/// (`key_id:<hex public key>`); refuses to overwrite either.
pub fn write_keypair(prefix: &Path, key_id: &str) -> Result<(PathBuf, PathBuf)> {
    if key_id.trim().is_empty() || key_id.contains(':') || key_id.chars().any(char::is_control) {
        bail!("key id must be non-empty without `:` or control characters");
    }
    let key = generate_signing_key()?;
    let mut key_path = prefix.as_os_str().to_owned();
    key_path.push(".key");
    let mut pub_path = prefix.as_os_str().to_owned();
    pub_path.push(".pub");
    let (key_path, pub_path) = (PathBuf::from(key_path), PathBuf::from(pub_path));
    for p in [&key_path, &pub_path] {
        if p.exists() {
            bail!("{} already exists", p.display());
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&key_path).with_context(|| format!("failed to create {}", key_path.display()))?;
    std::io::Write::write_all(&mut f, format!("{}\n", hex::encode(key.to_bytes())).as_bytes())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    std::fs::write(&pub_path, format!("{key_id}:{}\n", hex::encode(key.verifying_key().to_bytes())))
        .with_context(|| format!("failed to write {}", pub_path.display()))?;
    Ok((key_path, pub_path))
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
        signature: None,
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
            ("version: 1\nfiles: []\n".to_string(), "no files"),
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

    fn signed_pack(dir: &Path, key: &SigningKey) -> (PathBuf, RulePack) {
        std::fs::write(dir.join("rules/a.yaml"), "rules: []\n").unwrap();
        let mut pack = write_manifest(&[dir.join("rules/a.yaml")], dir, 5, Some("signed".into())).unwrap();
        pack.sign(key, "hds-test").unwrap();
        let manifest = dir.join("rule_pack.yml");
        std::fs::write(&manifest, pack.to_yaml().unwrap()).unwrap();
        (manifest, pack)
    }

    fn policy(key: &SigningKey, key_id: Option<&str>) -> PackVerifyPolicy {
        PackVerifyPolicy {
            trusted_keys: vec![TrustedKey { key_id: key_id.map(str::to_string), key: key.verifying_key() }],
            require_signature: true,
            min_version: None,
        }
    }

    #[test]
    fn signed_pack_verifies_and_fails_closed() {
        let dir = temp_dir("signed");
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (manifest, pack) = signed_pack(&dir, &key);
        let ok = policy(&key, Some("hds-test"));
        assert_eq!(load_manifest_with_policy(&manifest, &ok).unwrap(), pack);
        // A bare key verifies any key id.
        assert!(load_manifest_with_policy(&manifest, &policy(&key, None)).is_ok());
        // The unsigned loader still accepts it (signature shape only).
        assert!(load_manifest(&manifest).is_ok());

        let text = std::fs::read_to_string(&manifest).unwrap();
        let err = |t: &str, p: &PackVerifyPolicy| format!("{:#}", verify_yaml_with_policy(t, &dir, p).unwrap_err());
        // Reformatting (comments, file order) keeps the signature valid.
        assert!(verify_yaml_with_policy(&format!("# reformatted\n{text}\n"), &dir, &ok).is_ok());
        assert!(err(&text.replace("notes: signed", "notes: signeD"), &ok).contains("does not verify"));
        assert!(err(&text.replace("version: 5", "version: 6"), &ok).contains("does not verify"));
        assert!(err(&text, &policy(&key, Some("other-id"))).contains("not trusted"));
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(err(&text, &policy(&other, Some("hds-test"))).contains("does not verify"));
        let rollback = PackVerifyPolicy { min_version: Some(6), ..ok.clone() };
        assert!(err(&text, &rollback).contains("rollback"));

        // The signature is checked before the files are read.
        std::fs::write(dir.join("rules/a.yaml"), "rules: {}\n").unwrap();
        assert!(err(&text, &ok).contains("rules/a.yaml: sha256"));
        assert!(err(&text.replace("notes: signed", "notes: x"), &ok).contains("does not verify"));

        let unsigned = text.split("signature:").next().unwrap().to_string();
        assert!(err(&unsigned, &ok).contains("not signed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_round_trip() {
        let dir = temp_dir("keys");
        let prefix = dir.join("hds");
        let (key_path, pub_path) = write_keypair(&prefix, "hds-prod-2026-01").unwrap();
        assert!(write_keypair(&prefix, "again").is_err(), "never overwrites a key");
        let key = read_signing_key(&key_path).unwrap();
        let keys = parse_public_keys(&std::fs::read_to_string(&pub_path).unwrap()).unwrap();
        assert_eq!(keys, vec![TrustedKey { key_id: Some("hds-prod-2026-01".into()), key: key.verifying_key() }]);
        let bare = hex::encode(key.verifying_key().to_bytes());
        assert_eq!(parse_public_keys(&format!("# ring\n\n{bare}\n")).unwrap()[0].key_id, None);
        assert!(parse_public_keys("id:abcd").is_err());
        assert!(parse_public_keys("# nothing").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signature_block_shape_checks() {
        let hash = "a".repeat(64);
        let base = format!("version: 1\nfiles:\n  - path: r.yaml\n    sha256: {hash}\n    size: 1\n");
        let sig = |alg: &str, id: &str, v: &str| format!("{base}signature:\n  algorithm: {alg}\n  key_id: \"{id}\"\n  value: \"{v}\"\n");
        let v = "b".repeat(128);
        assert!(RulePack::parse(&sig("ed25519", "k", &v)).is_ok());
        assert!(RulePack::parse(&sig("rsa", "k", &v)).is_err());
        assert!(RulePack::parse(&sig("ed25519", "", &v)).is_err());
        assert!(RulePack::parse(&sig("ed25519", "k", "abc")).is_err());
        assert!(RulePack::parse(&format!("{}  extra: 1\n", sig("ed25519", "k", &v))).is_err());
        assert!(RulePack::parse(&base.replace("r.yaml", "\"r\\tx.yaml\"")).is_err());
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
