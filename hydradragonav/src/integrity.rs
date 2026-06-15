use sha2::{Digest, Sha256};
use std::path::Path;

/// Embedded hash manifest produced by build.rs.
static MANIFEST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sig_hashes.bin"));

/// Verify all signature files relative to `base_dir` against the embedded manifest.
/// Returns a list of filenames that are missing or have a different hash.
pub fn verify(base_dir: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    let mut pos = 0usize;

    let count = u32::from_le_bytes(MANIFEST[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    for _ in 0..count {
        let key_len = u16::from_le_bytes(MANIFEST[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let key = std::str::from_utf8(&MANIFEST[pos..pos + key_len]).unwrap_or("?");
        pos += key_len;
        let expected = &MANIFEST[pos..pos + 32];
        pos += 32;

        let file_path = base_dir.join(key.replace('/', std::path::MAIN_SEPARATOR_STR));
        match std::fs::read(&file_path) {
            Ok(bytes) => {
                let actual = Sha256::digest(&bytes);
                if actual.as_slice() != expected {
                    failures.push(key.to_string());
                }
            }
            Err(_) => {
                failures.push(key.to_string());
            }
        }
    }

    failures
}
