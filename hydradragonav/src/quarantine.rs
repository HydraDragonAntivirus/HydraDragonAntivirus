//! XOR-encoded file quarantine with a manager (list / restore / delete).
//!
//! Like Owlyshield, quarantined files are XOR-neutralized on disk so the stored
//! bytes are not a runnable or signature-identical copy of the malware, yet the
//! original is fully recoverable. Each item is a `<id>.quar` (XOR'd bytes) plus
//! a `<id>.json` metadata record under `<quarantine>/store/`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Single-byte XOR key used to neutralize quarantined content. This is
/// obfuscation/neutralization (not encryption) — enough that the stored bytes
/// are not an executable, signature-identical copy of the malware.
const XOR_KEY: u8 = 0x6A;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub detection: String,
    pub quarantined_at: u64,
    pub size: u64,
    pub sha256: String,
    pub xor_key: u8,
}

pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    fn store_dir(&self) -> PathBuf {
        self.dir.join("store")
    }
    fn data_path(&self, id: &str) -> PathBuf {
        self.store_dir().join(format!("{id}.quar"))
    }
    fn meta_path(&self, id: &str) -> PathBuf {
        self.store_dir().join(format!("{id}.json"))
    }

    /// XOR-encode `path` into the quarantine store and record metadata WITHOUT
    /// removing the original. Used when a file is locked and will be deleted later
    /// (e.g. at restart), so a recoverable copy already shows in the Quarantine tab.
    pub fn backup(&self, path: &Path, detection: &str) -> io::Result<QuarantineEntry> {
        let data = fs::read(path)?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = hex::encode(hasher.finalize());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let short = &sha256[..8.min(sha256.len())];
        fs::create_dir_all(self.store_dir())?;
        let id = unique_id(&self.store_dir(), &format!("{stem}_{short}"));

        let encoded: Vec<u8> = data.iter().map(|b| b ^ XOR_KEY).collect();
        fs::write(self.data_path(&id), &encoded)?;

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_path_buf(),
            detection: detection.to_string(),
            quarantined_at: now,
            size: data.len() as u64,
            sha256,
            xor_key: XOR_KEY,
        };
        fs::write(
            self.meta_path(&id),
            serde_json::to_vec_pretty(&entry).unwrap_or_default(),
        )?;
        Ok(entry)
    }

    /// XOR-encode `path` into the quarantine store, record metadata, and remove
    /// the original file. Returns the stored entry.
    pub fn quarantine(&self, path: &Path, detection: &str) -> io::Result<QuarantineEntry> {
        let entry = self.backup(path, detection)?;
        // Only after the encoded copy + metadata are safely written do we remove
        // the original; on failure, roll back so we don't leave orphans.
        if let Err(e) = fs::remove_file(path) {
            let _ = fs::remove_file(self.data_path(&entry.id));
            let _ = fs::remove_file(self.meta_path(&entry.id));
            return Err(e);
        }
        Ok(entry)
    }

    /// The on-disk `.quar` path for an entry (for callers that want it).
    pub fn data_file(&self, id: &str) -> PathBuf {
        self.data_path(id)
    }

    pub fn list(&self) -> Vec<QuarantineEntry> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(self.store_dir()) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("json") {
                    if let Ok(bytes) = fs::read(&p) {
                        if let Ok(meta) = serde_json::from_slice::<QuarantineEntry>(&bytes) {
                            out.push(meta);
                        }
                    }
                }
            }
        }
        out.sort_by_key(|e| e.quarantined_at);
        out
    }

    fn load(&self, id: &str) -> io::Result<QuarantineEntry> {
        let bytes = fs::read(self.meta_path(id))?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Decode a quarantined item back to its original path and drop it from the
    /// store. Returns the restored path.
    pub fn restore(&self, id: &str) -> io::Result<PathBuf> {
        let meta = self.load(id)?;
        let encoded = fs::read(self.data_path(id))?;
        let decoded: Vec<u8> = encoded.iter().map(|b| b ^ meta.xor_key).collect();
        if let Some(parent) = meta.original_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&meta.original_path, &decoded)?;
        let _ = fs::remove_file(self.data_path(id));
        let _ = fs::remove_file(self.meta_path(id));
        Ok(meta.original_path)
    }

    /// Permanently delete a quarantined item.
    pub fn delete(&self, id: &str) -> io::Result<()> {
        let _ = fs::remove_file(self.data_path(id));
        fs::remove_file(self.meta_path(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_quarantine_round_trip() {
        let tmp = std::env::temp_dir().join(format!("hdq_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let src = tmp.join("evil.bin");
        let content: &[u8] = b"MZ\x90\x00 malware bytes \xff\x00\x6a";
        fs::write(&src, content).unwrap();

        let q = Quarantine::new(tmp.join("quar"));
        let entry = q.quarantine(&src, "test.detection").unwrap();

        // Original is gone; stored copy is XOR-encoded (not identical to source).
        assert!(!src.exists());
        let stored = fs::read(q.data_file(&entry.id)).unwrap();
        assert_eq!(stored, content.iter().map(|b| b ^ XOR_KEY).collect::<Vec<_>>());
        assert_ne!(stored, content);
        assert_eq!(q.list().len(), 1);

        // Restore decodes back to the exact original bytes at the original path.
        let restored = q.restore(&entry.id).unwrap();
        assert_eq!(restored, src);
        assert_eq!(fs::read(&src).unwrap(), content);
        assert!(q.list().is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }
}

fn unique_id(store: &Path, base: &str) -> String {
    let base: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut id = base.clone();
    let mut i = 1u32;
    while store.join(format!("{id}.json")).exists() {
        id = format!("{base}_{i}");
        i += 1;
    }
    id
}
