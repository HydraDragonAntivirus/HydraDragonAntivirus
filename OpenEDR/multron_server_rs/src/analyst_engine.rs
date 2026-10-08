//! Analyst signatures in engine formats, kept apart from the shipped databases:
//!
//! * `analyst_signatures/clamav/*.ndb|*.ldb` — ClamAV body / logical signatures,
//!   compiled by `hydradragonclamav` into a small engine of their own.
//! * `analyst_signatures/hydradragonsig/*.yaml` — HydraDragonSig rules (strings,
//!   imports, native expressions...), evaluated by `hydradragonsig` itself.
//!
//! The shipped engine is never touched: these run after the main scan and can only
//! raise a verdict (unknown/clean -> suspicious/malicious), never lower one. Both sets
//! are rebuilt from disk on every save or delete, so edits and deletions apply at once
//! (unlike YARA sources, which can only be appended to the live engine).
//!
//! Every signature name / rule family must follow `naming.rs`
//! (`Category.Platform.Family[.Variant]`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use hydradragonclamav::scanner::{Engine as ClamEngine, ScanOptions as ClamScanOptions};
use hydradragonsig::models::{MemoryScanContext, Verdict as SigVerdict};
use hydradragonsig::rules::RuleSet;

use crate::naming::normalize_threat_name;

/// What a signature room entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigKind {
    Yara,
    HydraSig,
    ClamNdb,
    ClamLdb,
}

impl SigKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "yara" => Some(Self::Yara),
            "hydradragonsig" | "sig" => Some(Self::HydraSig),
            "clamav_ndb" | "ndb" => Some(Self::ClamNdb),
            "clamav_ldb" | "ldb" => Some(Self::ClamLdb),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Yara => "yara",
            Self::HydraSig => "hydradragonsig",
            Self::ClamNdb => "clamav_ndb",
            Self::ClamLdb => "clamav_ldb",
        }
    }
    pub fn folder(self) -> &'static str {
        match self {
            Self::Yara => "yara",
            Self::HydraSig => "hydradragonsig",
            Self::ClamNdb | Self::ClamLdb => "clamav",
        }
    }
    pub fn ext(self) -> &'static str {
        match self {
            Self::Yara => "yar",
            Self::HydraSig => "yaml",
            Self::ClamNdb => "ndb",
            Self::ClamLdb => "ldb",
        }
    }
    pub const ALL: [SigKind; 4] = [Self::Yara, Self::HydraSig, Self::ClamNdb, Self::ClamLdb];

    pub fn path(self, name: &str) -> PathBuf {
        let dir = crate::human_review::analyst_dir().join(self.folder());
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{name}.{}", self.ext()))
    }
}

/// A match from an analyst signature.
#[derive(Debug, Clone)]
pub struct AnalystHit {
    pub engine: &'static str,
    pub name: String,
    pub verdict: &'static str,
}

#[derive(Default)]
pub struct AnalystEngine {
    clam: RwLock<Option<ClamEngine>>,
    sig: RwLock<Option<RuleSet>>,
    companies: RwLock<CompanyLists>,
}

/// Analyst company (Authenticode signer) lists: `analyst_signatures/companies_allow.txt`
/// and `companies_block.txt`, one signer name per line, matched case-insensitively.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CompanyLists {
    pub allow: Vec<String>,
    pub block: Vec<String>,
}

/// Decision from the company lists for one file.
pub enum CompanyDecision {
    /// Signer is allow-listed and the signature is valid and trusted.
    Allow(String),
    /// Signer is block-listed (valid signature or not).
    Block(String),
}

fn read_list(file: &str) -> Vec<String> {
    std::fs::read_to_string(crate::human_review::analyst_dir().join(file))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

pub fn save_company_lists(allow: &[String], block: &[String]) -> std::io::Result<()> {
    let clean = |v: &[String]| {
        let mut out: Vec<String> = v.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && s.len() <= 200).collect();
        out.sort_by_key(|s| s.to_lowercase());
        out.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        out.join("\n") + "\n"
    };
    let dir = crate::human_review::analyst_dir();
    std::fs::write(dir.join("companies_allow.txt"), clean(allow))?;
    std::fs::write(dir.join("companies_block.txt"), clean(block))
}

// ------------------------------------------------------------------ validation

/// Names inside one ClamAV `.ndb` / `.ldb` document (first field of every line).
fn clam_names(kind: SigKind, src: &str) -> Vec<String> {
    let sep = if kind == SigKind::ClamLdb { ';' } else { ':' };
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(sep).next().unwrap_or("").to_string())
        .collect()
}

/// Checks a ClamAV document: every signature name follows the naming convention and
/// the whole file parses with hydradragonclamav. Returns the number of signatures.
pub fn validate_clamav(kind: SigKind, src: &str) -> Result<usize, String> {
    let names = clam_names(kind, src);
    if names.is_empty() {
        return Err("no signature lines".into());
    }
    for n in &names {
        let canon = normalize_threat_name(n).map_err(|e| format!("signature name \"{n}\": {e}"))?;
        if &canon != n {
            return Err(format!("write the signature name in canonical form: {canon}"));
        }
    }
    let mut files = HashMap::new();
    files.insert(format!("check.{}", kind.ext()), src.as_bytes().to_vec());
    let (_engine, report) = ClamEngine::from_bytes_map(&files);
    if let Some(e) = report.errors.first() {
        return Err(format!("line {}: {}", e.source.line, e.message));
    }
    let loaded = report.extended_loaded + report.logical_loaded + report.db_loaded;
    if loaded == 0 {
        return Err("hydradragonclamav loaded no signature from this file".into());
    }
    if loaded < names.len() {
        return Err(format!("only {loaded} of {} signatures were accepted", names.len()));
    }
    Ok(loaded)
}

/// Checks a HydraDragonSig YAML document: it parses, every rule has a `family` in the
/// naming convention and a malware/pua/suspicious verdict. Returns the rule count.
pub fn validate_hydrasig(src: &str) -> Result<usize, String> {
    let rs = RuleSet::from_yaml_str(src).map_err(|e| format!("{e:#}"))?;
    if rs.rules().is_empty() {
        return Err("no rules in the document".into());
    }
    for r in rs.rules() {
        let fam = r.family.as_deref().unwrap_or("");
        if fam.is_empty() {
            return Err(format!("rule {} needs a family, e.g. family: \"Trojan.Win32.Remcos.A\"", r.id));
        }
        let canon = normalize_threat_name(fam).map_err(|e| format!("rule {} family: {e}", r.id))?;
        if canon != fam {
            return Err(format!("rule {}: write the family in canonical form: {canon}", r.id));
        }
    }
    Ok(rs.rules().len())
}

// ------------------------------------------------------------------ runtime

impl AnalystEngine {
    fn read_dir(kind_folder: &str, exts: &[&str]) -> Vec<(String, Vec<u8>)> {
        let dir = crate::human_review::analyst_dir().join(kind_folder);
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                let ok = p.extension().and_then(|x| x.to_str()).is_some_and(|x| exts.contains(&x));
                if !ok {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&p) {
                    out.push((p.file_name().unwrap_or_default().to_string_lossy().into_owned(), bytes));
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Rebuilds both analyst engines from disk. Returns a one-line summary.
    pub fn reload(&self) -> String {
        // ClamAV: one in-memory database from every analyst .ndb/.ldb file.
        let clam_files: HashMap<String, Vec<u8>> = Self::read_dir("clamav", &["ndb", "ldb"]).into_iter().collect();
        let clam_count = clam_files.len();
        let (clam, clam_loaded, clam_errors) = if clam_files.is_empty() {
            (None, 0, 0)
        } else {
            let (engine, report) = ClamEngine::from_bytes_map(&clam_files);
            let loaded = report.extended_loaded + report.logical_loaded + report.db_loaded;
            (if loaded > 0 { Some(engine) } else { None }, loaded, report.errors.len())
        };
        *self.clam.write().unwrap() = clam;

        // HydraDragonSig: every analyst YAML document merged into one rule set.
        let mut set: Option<RuleSet> = None;
        let mut sig_failed = Vec::new();
        for (name, bytes) in Self::read_dir("hydradragonsig", &["yaml", "yml"]) {
            match std::str::from_utf8(&bytes).ok().and_then(|s| RuleSet::from_yaml_str(s).ok()) {
                Some(rs) => match set.as_mut() {
                    Some(cur) => cur.extend(rs),
                    None => set = Some(rs),
                },
                None => sig_failed.push(name),
            }
        }
        let sig_rules = set.as_ref().map(|s| s.rules().len()).unwrap_or(0);
        *self.sig.write().unwrap() = set.filter(|s| !s.rules().is_empty());

        let companies = CompanyLists { allow: read_list("companies_allow.txt"), block: read_list("companies_block.txt") };
        let (n_allow, n_block) = (companies.allow.len(), companies.block.len());
        *self.companies.write().unwrap() = companies;

        let msg = format!(
            "companies {n_allow} allowed / {n_block} blocked, analyst signatures: clamav {clam_loaded} sigs from {clam_count} files ({clam_errors} errors), hydradragonsig {sig_rules} rules ({} files failed)",
            sig_failed.len()
        );
        eprintln!("[engine] {msg}");
        msg
    }

    pub fn company_lists(&self) -> CompanyLists {
        self.companies.read().unwrap().clone()
    }

    /// Block wins over allow. Allow needs a valid, trusted signature: a name alone (or
    /// a broken signature) never makes a file clean.
    pub fn company_decision(&self, signer: Option<&str>, trusted: bool) -> Option<CompanyDecision> {
        let signer = signer?.trim();
        if signer.is_empty() {
            return None;
        }
        let lists = self.companies.read().unwrap();
        if lists.block.iter().any(|c| c.eq_ignore_ascii_case(signer)) {
            return Some(CompanyDecision::Block(signer.to_string()));
        }
        if trusted && lists.allow.iter().any(|c| c.eq_ignore_ascii_case(signer)) {
            return Some(CompanyDecision::Allow(signer.to_string()));
        }
        None
    }

    /// Runs the analyst signatures over a file. Cheap when no analyst signatures exist.
    pub fn scan(&self, data: &[u8], name: &str) -> Vec<AnalystHit> {
        let mut hits = Vec::new();
        if let Some(clam) = self.clam.read().unwrap().as_ref() {
            for m in clam.scan_bytes_named(data, if name.is_empty() { "file" } else { name }, ClamScanOptions::default(), &[]) {
                hits.push(AnalystHit { engine: "clamav", name: m.name, verdict: "malicious" });
            }
        }
        if let Some(rules) = self.sig.read().unwrap().as_ref() {
            let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: name.to_string(), base_address: None };
            if let Ok(report) = hydradragonsig::scan_memory_owned(ctx, rules, &hydradragonsig::ScanOptions::default()) {
                let verdict = match report.verdict {
                    SigVerdict::Malware => Some("malicious"),
                    SigVerdict::Pua | SigVerdict::Suspicious => Some("suspicious"),
                    _ => None,
                };
                if let Some(v) = verdict {
                    let name = report.threat_name.clone().unwrap_or_else(|| "Generic.Multi.AnalystRule".into());
                    hits.push(AnalystHit { engine: "hydradragonsig", name, verdict: v });
                }
            }
        }
        hits
    }
}
