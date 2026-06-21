#![cfg(windows)]

use std::fs;
use std::io::{BufReader, Seek, SeekFrom};
use std::path::Path;

use flate2::read::GzDecoder;

use crate::error::Error;

const CVD_HEADER_SIZE: u64 = 512;

pub struct FilterConfig {
    pub include_platforms: Vec<String>,
    pub exclude_platforms: Vec<String>,
    pub exclude_types: Vec<String>,
    pub ndb_types: Option<Vec<String>>,
    /// Signature-name prefixes to drop (e.g. ClamAV `ExcludePUA` categories).
    pub exclude_pua: Vec<String>,
}

impl FilterConfig {
    /// Keep all non-hash signatures across every platform (no Windows-only
    /// restriction). Hash signatures (.hdb/.hsb/.mdb/.msb and their update
    /// variants) are dropped — exact-hash detection is handled by the bloom
    /// filters, and the engine skips hash signature files anyway.
    pub fn no_hash_all_platforms() -> Self {
        Self {
            // Empty include/exclude => keep every platform (Win, Unix, etc.).
            include_platforms: vec![],
            exclude_platforms: vec![],
            exclude_types: vec![
                "hdb".into(),
                "hdu".into(),
                "hsb".into(),
                "hsu".into(),
                "mdb".into(),
                "mdu".into(),
                "msb".into(),
                "msu".into(),
            ],
            ndb_types: None,
            // Only these PUA (packer) categories are dropped; all other PUA and
            // every non-hash signature are kept.
            exclude_pua: vec![
                "PUA.Win.Packer".into(),
                "PUA.Win.Trojan.Packed".into(),
                "PUA.Win.Trojan.Molebox".into(),
                "PUA.Win.Packer.Upx".into(),
                "PUA.Doc.Packed".into(),
            ],
        }
    }
}

#[derive(Default, Debug)]
pub struct FilterStats {
    pub ndb_original: usize,
    pub ndb_kept: usize,
    pub ldb_original: usize,
    pub ldb_kept: usize,
    pub hdb_excluded: bool,
    pub mdb_excluded: bool,
    pub hsb_excluded: bool,
}

fn should_keep(name: &str, cfg: &FilterConfig) -> bool {
    let lc = name.to_lowercase();
    if lc.contains("eicar") {
        return true;
    }
    // Drop the configured PUA categories (prefix match on the signature name),
    // e.g. "PUA.Win.Packer" also covers "PUA.Win.Packer.Upx-6".
    if cfg
        .exclude_pua
        .iter()
        .any(|p| name.starts_with(p.as_str()))
    {
        return false;
    }
    let prefix = name.split('.').next().unwrap_or("");
    if !cfg.include_platforms.is_empty() {
        return cfg.include_platforms.iter().any(|p| p == prefix);
    }
    if !cfg.exclude_platforms.is_empty() {
        return !cfg.exclude_platforms.iter().any(|p| p == prefix);
    }
    true
}

fn filter_ndb(content: &str, cfg: &FilterConfig, stats: &mut FilterStats) -> String {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push(line);
            continue;
        }
        stats.ndb_original += 1;
        let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
        if parts.len() >= 4 {
            let keep_name = should_keep(parts[0], cfg);
            let keep_type = cfg
                .ndb_types
                .as_ref()
                .map(|ts| ts.iter().any(|t| t == parts[1]))
                .unwrap_or(true);
            if keep_name && keep_type {
                stats.ndb_kept += 1;
                out.push(line);
            }
        } else {
            stats.ndb_kept += 1;
            out.push(line);
        }
    }
    out.join("\n")
}

fn filter_by_name_col2(
    content: &str,
    cfg: &FilterConfig,
    orig: &mut usize,
    kept: &mut usize,
) -> String {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push(line);
            continue;
        }
        *orig += 1;
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() >= 3 {
            if should_keep(parts[2], cfg) {
                *kept += 1;
                out.push(line);
            }
        } else {
            *kept += 1;
            out.push(line);
        }
    }
    out.join("\n")
}

fn filter_ldb(content: &str, cfg: &FilterConfig, stats: &mut FilterStats) -> String {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push(line);
            continue;
        }
        stats.ldb_original += 1;
        let name = trimmed.split(';').next().unwrap_or(trimmed);
        if should_keep(name, cfg) {
            stats.ldb_kept += 1;
            out.push(line);
        }
    }
    out.join("\n")
}

fn unpack_cvd(cvd_path: &Path, output_dir: &Path) -> Result<(), Error> {
    let file = fs::File::open(cvd_path).map_err(|e| Error::Other(e.to_string()))?;
    let mut reader = BufReader::new(file);
    reader
        .seek(SeekFrom::Start(CVD_HEADER_SIZE))
        .map_err(|e| Error::Other(e.to_string()))?;

    let gz = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(output_dir)
        .map_err(|e| Error::Other(format!("CVD unpack failed: {e}")))?;
    Ok(())
}

pub fn filter_cvd(
    cvd_path: &Path,
    output_dir: &Path,
    cfg: &FilterConfig,
    delete_source: bool,
) -> Result<FilterStats, Error> {
    let mut stats = FilterStats::default();

    let temp_dir = tempfile::tempdir().map_err(|e| Error::Other(e.to_string()))?;
    unpack_cvd(cvd_path, temp_dir.path())?;

    fs::create_dir_all(output_dir).map_err(|e| Error::Other(e.to_string()))?;

    for entry in fs::read_dir(temp_dir.path()).map_err(|e| Error::Other(e.to_string()))? {
        let entry = entry.map_err(|e| Error::Other(e.to_string()))?;
        let src = entry.path();
        let ext = src
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let filename = match src.file_name() {
            Some(n) => n.to_owned(),
            None => continue,
        };
        let dest = output_dir.join(&filename);

        let excluded = cfg.exclude_types.iter().any(|t| t == &ext);

        // Drop excluded signature types (hash signatures) entirely, whatever the
        // extension — write a stub comment so the file is present but inert.
        if excluded {
            match ext.as_str() {
                "hdb" | "hdu" => stats.hdb_excluded = true,
                "mdb" | "mdu" => stats.mdb_excluded = true,
                "hsb" | "hsu" | "msb" | "msu" => stats.hsb_excluded = true,
                _ => {}
            }
            fs::write(&dest, format!("# {ext} excluded (hash signature)\n"))
                .map_err(|e| Error::Other(e.to_string()))?;
            continue;
        }

        match ext.as_str() {
            "ndb" => {
                let content = fs::read_to_string(&src).map_err(|e| Error::Other(e.to_string()))?;
                let filtered = filter_ndb(&content, cfg, &mut stats);
                fs::write(&dest, filtered).map_err(|e| Error::Other(e.to_string()))?;
            }
            "ldb" => {
                if excluded {
                    fs::write(&dest, "# ldb excluded\n")
                        .map_err(|e| Error::Other(e.to_string()))?;
                } else {
                    let content =
                        fs::read_to_string(&src).map_err(|e| Error::Other(e.to_string()))?;
                    let filtered = filter_ldb(&content, cfg, &mut stats);
                    fs::write(&dest, filtered).map_err(|e| Error::Other(e.to_string()))?;
                }
            }
            "hdb" => {
                if excluded {
                    stats.hdb_excluded = true;
                    fs::write(&dest, "# hdb excluded\n")
                        .map_err(|e| Error::Other(e.to_string()))?;
                } else {
                    let content =
                        fs::read_to_string(&src).map_err(|e| Error::Other(e.to_string()))?;
                    let mut orig = 0;
                    let mut kept = 0;
                    let filtered = filter_by_name_col2(&content, cfg, &mut orig, &mut kept);
                    fs::write(&dest, filtered).map_err(|e| Error::Other(e.to_string()))?;
                }
            }
            "fp" | "sfp" => {
                // Don't deploy .fp/.sfp files as signatures — extract the hash
                // (first colon-delimited field) and merge into whitelist.db.
                // Format: HashString:FileSize:MalwareName
                let content = fs::read_to_string(&src).map_err(|e| Error::Other(e.to_string()))?;
                let db_path = output_dir.join("whitelist.db");
                let mut out = String::new();
                if db_path.exists() {
                    out = fs::read_to_string(&db_path).map_err(|e| Error::Other(e.to_string()))?;
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let hash = trimmed.split(':').next().unwrap_or("").trim();
                    let valid = match hash.len() {
                        32 | 40 | 64 | 128 => hash.chars().all(|c| c.is_ascii_hexdigit()),
                        _ => false,
                    };
                    if valid {
                        out.push_str(hash);
                        out.push('\n');
                    }
                }
                fs::write(&db_path, out).map_err(|e| Error::Other(e.to_string()))?;
            }
            "mdb" | "hsb" => {
                if excluded {
                    if ext == "mdb" {
                        stats.mdb_excluded = true;
                    } else {
                        stats.hsb_excluded = true;
                    }
                    fs::write(&dest, format!("# {ext} excluded\n"))
                        .map_err(|e| Error::Other(e.to_string()))?;
                } else {
                    let content =
                        fs::read_to_string(&src).map_err(|e| Error::Other(e.to_string()))?;
                    let mut orig = 0;
                    let mut kept = 0;
                    let filtered = filter_by_name_col2(&content, cfg, &mut orig, &mut kept);
                    fs::write(&dest, filtered).map_err(|e| Error::Other(e.to_string()))?;
                }
            }
            _ => {
                // .cfg, .info, .cbc, .idb etc — copy as-is
                fs::copy(&src, &dest).map_err(|e| Error::Other(e.to_string()))?;
            }
        }
    }

    if delete_source {
        let _ = fs::remove_file(cvd_path);
    }

    Ok(stats)
}

pub fn run_juice(db_dir: &Path, delete_source: bool) {
    let cfg = FilterConfig::no_hash_all_platforms();

    for cvd in ["main.cvd", "daily.cvd", "main.cld", "daily.cld"] {
        let cvd_path = db_dir.join(cvd);
        if !cvd_path.exists() {
            continue;
        }
        eprintln!("[ClamJuice] Filtering {}...", cvd);
        match filter_cvd(&cvd_path, db_dir, &cfg, delete_source) {
            Ok(stats) => {
                eprintln!(
                    "[ClamJuice] {} done — ndb kept {}/{}, ldb kept {}/{}, hdb_excl={}, mdb_excl={}, hsb_excl={}",
                    cvd,
                    stats.ndb_kept,
                    stats.ndb_original,
                    stats.ldb_kept,
                    stats.ldb_original,
                    stats.hdb_excluded,
                    stats.mdb_excluded,
                    stats.hsb_excluded,
                );
            }
            Err(e) => eprintln!("[ClamJuice] Failed to filter {cvd}: {e}"),
        }
    }
}
