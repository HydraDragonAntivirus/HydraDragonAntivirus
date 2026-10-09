use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use openedr_static::engine::StaticEngine;
use openedr_static::report::{ExtractedObject, StaticScanReport};
use openedr_static::signers::BinaryFuse16Filter;
use serde::{Deserialize, Serialize};

use crate::cache::Sha;

pub const ENGINE_NAME: &str = "VirusKov";

const EICAR_SHA256: &str = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

/// Pure Elasticsearch ECS (8.11+) result message for VirusKov.
/// Serializes only standard Elastic Common Schema fields over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMessage {
    pub r#type: String, // "result"
    pub id: i64,
    #[serde(rename = "@timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecs: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub antivirus: Option<serde_json::Value>,
    #[serde(rename = "threat", skip_serializing_if = "Option::is_none")]
    pub threat_indicator: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<serde_json::Value>,

    // Internal engine state fields (not serialized or deserialized - no legacy wire fields)
    #[serde(default, skip)]
    pub verdict: String,
    #[serde(default, skip)]
    pub threat: Option<String>,
    #[serde(default, skip)]
    pub detail: Option<String>,
    #[serde(default, skip)]
    pub score: f64,
    #[serde(default, skip)]
    pub sha256: String,
    #[serde(default, skip)]
    pub scan_ms: i64,
    #[serde(default, skip)]
    pub source: String,
    #[serde(default, skip)]
    pub extracted_objects: Vec<ExtractedObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub status: String, // "loading" | "ready" | "error"
    pub error: String,
    pub load_ms: i64,
    pub name: String,
    /// True while a hot reload is building the new engine in the background.
    #[serde(default)]
    pub reloading: bool,
    /// Result of the last hot reload ("" if none yet).
    #[serde(default)]
    pub reload_msg: String,
}

pub struct EngineAdapter {
    engine: OnceLock<Arc<RwLock<StaticEngine>>>,
    error_msg: RwLock<String>,
    load_ms: AtomicI64,
    work_dir: Option<PathBuf>,
    file_seq: AtomicI64,
    malicious_xf: RwLock<Option<BinaryFuse16Filter>>,
    whitelist_enabled: bool,
    keep_unknown: bool,
    pub keep_threats: bool,
    /// Keep clean PE / APK files (dashboard toggle, saved; `--keep-clean` turns it on).
    /// They have their own disk quota so they never crowd out unknown and threat files.
    pub keep_clean: AtomicBool,
    /// Keep files the TLSH smart whitelist called `possible_clean` (default on; dashboard
    /// toggle, saved in multron_server.json, `--no-keep-possible-clean`).
    pub keep_possible_clean: AtomicBool,
    pub compress_low_disk: bool,
    pub low_disk_threshold_bytes: u64,
    keep_limit_bytes: u64,
    kept_bytes: AtomicU64,
    pub keep_clean_limit_bytes: u64,
    pub kept_clean_bytes: AtomicU64,
    pub kept_files: AtomicI64,
    /// Analyst ClamAV / HydraDragonSig signatures (analyst_signatures/), run after the main scan.
    pub analyst: crate::analyst_engine::AnalystEngine,
    /// Rules folder the engine was loaded from; reused by `reload_all`.
    rules_dir: RwLock<Option<PathBuf>>,
    reloading: AtomicBool,
    reload_msg: RwLock<String>,
}

impl EngineAdapter {
    pub fn new(
        work_dir: Option<PathBuf>,
        whitelist_enabled: bool,
        keep_unknown: bool,
        keep_unknown_gb: u64,
        keep_threats: bool,
        keep_clean: bool,
        keep_clean_gb: u64,
        compress_low_disk: bool,
        low_disk_gb: u64,
    ) -> Arc<Self> {
        let mut kept = (0u64, 0i64, 0u64);
        if let Some(ref dir) = work_dir {
            let _ = std::fs::create_dir_all(dir);
            kept = remove_leftover_uploads(dir);
        }

        Arc::new(Self {
            engine: OnceLock::new(),
            error_msg: RwLock::new(String::new()),
            load_ms: AtomicI64::new(0),
            work_dir,
            file_seq: AtomicI64::new(0),
            malicious_xf: RwLock::new(None),
            whitelist_enabled,
            keep_unknown,
            keep_threats,
            keep_clean: AtomicBool::new(keep_clean),
            keep_possible_clean: AtomicBool::new(true),
            compress_low_disk,
            low_disk_threshold_bytes: low_disk_gb * 1024 * 1024 * 1024,
            keep_limit_bytes: keep_unknown_gb * 1024 * 1024 * 1024,
            kept_bytes: AtomicU64::new(kept.0),
            keep_clean_limit_bytes: keep_clean_gb * 1024 * 1024 * 1024,
            kept_clean_bytes: AtomicU64::new(kept.2),
            rules_dir: RwLock::new(None),
            reloading: AtomicBool::new(false),
            reload_msg: RwLock::new(String::new()),
            kept_files: AtomicI64::new(kept.1),
            analyst: Default::default(),
        })
    }

    pub fn start_loading(self: &Arc<Self>, custom_rules_dir: Option<PathBuf>) {
        let adapter = Arc::clone(self);
        std::thread::Builder::new()
            .name("engine-load".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let started = Instant::now();
                let rules_dir = resolve_rules_dir(custom_rules_dir);
                eprintln!("[engine] loading from: {}", rules_dir.display());
                *adapter.rules_dir.write().unwrap() = Some(rules_dir.clone());

                *adapter.malicious_xf.write().unwrap() = load_malicious_xf(&rules_dir);

                match std::panic::catch_unwind(|| StaticEngine::init(&rules_dir)) {
                    Ok(engine) => {
                        let elapsed = started.elapsed().as_millis() as i64;
                        adapter.load_ms.store(elapsed, Ordering::Relaxed);
                        if adapter.whitelist_enabled && !engine.benign_whitelist_loaded() {
                            eprintln!("[engine] benign_sha256.xf not found in xorfilter_rules, hash whitelist is off");
                        }
                        let _ = adapter.engine.set(Arc::new(RwLock::new(engine)));
                        adapter.load_analyst_yara();
                        adapter.analyst.reload();
                        eprintln!("[engine] ready in {} ms", elapsed);
                    }
                    Err(_) => {
                        *adapter.error_msg.write().unwrap() = "engine failed to load (panic in init)".into();
                        eprintln!("[engine] failed to load");
                    }
                }
            })
            .expect("cannot start engine loader");
    }

    pub fn ready(&self) -> bool {
        self.engine.get().is_some()
    }

    /// Every kept upload: `<work>/<category>/<SHA256>_<name>[.xz]`, plus old-style
    /// `<prefix><SHA256>_<name>` files left in the work folder itself.
    pub fn list_kept(&self) -> Vec<KeptFile> {
        let Some(dir) = self.work_dir.as_ref() else { return Vec::new() };
        let mut out = Vec::new();
        for cat in KeptFile::CATEGORIES {
            if let Ok(rd) = std::fs::read_dir(dir.join(cat)) {
                out.extend(rd.flatten().filter_map(|e| KeptFile::parse(e.path(), Some(cat))));
            }
        }
        // `threat/` from an earlier build that did not split malicious and suspicious
        // (sorted by `sort_legacy_kept`, malicious until then).
        if let Ok(rd) = std::fs::read_dir(dir.join(KeptFile::LEGACY_THREAT_DIR)) {
            out.extend(rd.flatten().filter_map(|e| KeptFile::parse(e.path(), Some("malicious"))));
        }
        if let Ok(rd) = std::fs::read_dir(dir) {
            out.extend(rd.flatten().filter(|e| e.path().is_file()).filter_map(|e| KeptFile::parse(e.path(), None)));
        }
        out
    }

    pub fn find_kept(&self, sha_upper: &str) -> Option<KeptFile> {
        self.list_kept().into_iter().find(|k| k.sha256.eq_ignore_ascii_case(sha_upper))
    }

    /// Bytes of a kept upload (any category, plain or `.xz`).
    pub fn read_kept_sample(&self, sha_upper: &str) -> Option<Vec<u8>> {
        self.find_kept(sha_upper)?.read()
    }

    /// Moves a kept upload to the folder of its new verdict (after a rescan).
    pub fn relabel_kept(&self, sha_upper: &str, verdict: &str) {
        if let Some(k) = self.find_kept(sha_upper) {
            self.move_kept(&k, KeptFile::category_for(verdict));
        }
    }

    /// `relabel_kept` for many files with one walk of the folders (human verdicts:
    /// bulk whitelists, startup). `items` are (SHA-256, verdict). Returns files moved.
    pub fn relabel_many(&self, items: &[(String, String)]) -> usize {
        if items.is_empty() || self.work_dir.is_none() {
            return 0;
        }
        let kept: std::collections::HashMap<String, KeptFile> =
            self.list_kept().into_iter().map(|k| (k.sha256.clone(), k)).collect();
        items
            .iter()
            .filter_map(|(sha, verdict)| kept.get(&sha.to_ascii_uppercase()).map(|k| (k, verdict)))
            .filter(|(k, verdict)| self.move_kept(k, KeptFile::category_for(verdict)))
            .count()
    }

    /// Moves a kept file into the folder of `cat`, moving its bytes between the clean
    /// quota and the shared one when needed. True when it moved.
    fn move_kept(&self, k: &KeptFile, cat: &'static str) -> bool {
        let Some(dir) = self.work_dir.as_ref() else { return false };
        if k.category == cat && !k.legacy {
            return false;
        }
        let target = dir.join(cat).join(k.file_name());
        let _ = std::fs::create_dir_all(dir.join(cat));
        if target.exists() || std::fs::rename(&k.path, &target).is_err() {
            return false;
        }
        if (k.category == "clean") != (cat == "clean") {
            let len = std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
            let (from, to) = if cat == "clean" { (&self.kept_bytes, &self.kept_clean_bytes) } else { (&self.kept_clean_bytes, &self.kept_bytes) };
            let _ = from.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(len)));
            to.fetch_add(len, Ordering::Relaxed);
        }
        true
    }

    /// Kept files on disk per category: (category, files, bytes). Walks the folders,
    /// so callers cache it.
    pub fn kept_counts(&self) -> Vec<(&'static str, u64, u64)> {
        let mut out: Vec<(&'static str, u64, u64)> = KeptFile::CATEGORIES.iter().map(|c| (*c, 0, 0)).collect();
        for k in self.list_kept() {
            if let Some(e) = out.iter_mut().find(|e| e.0 == k.category) {
                e.1 += 1;
                e.2 += std::fs::metadata(&k.path).map(|m| m.len()).unwrap_or(0);
            }
        }
        out
    }

    pub fn work_dir(&self) -> Option<&Path> {
        self.work_dir.as_deref()
    }

    /// Deletes a kept file (it was moved elsewhere) and frees its quota. Returns the bytes freed.
    pub fn forget_kept(&self, k: &KeptFile) -> Option<u64> {
        let len = std::fs::metadata(&k.path).map(|m| m.len()).unwrap_or(0);
        std::fs::remove_file(&k.path).ok()?;
        let used = if k.category == "clean" { &self.kept_clean_bytes } else { &self.kept_bytes };
        let _ = used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(len)));
        let _ = self.kept_files.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some((v - 1).max(0)));
        Some(len)
    }

    /// What is short of room: (clean quota, shared quota, disk). A quota counts when it is
    /// at least 80 % full and the disk when free space is under the low-disk threshold;
    /// with `until_relieved` the marks are 60 % and the threshold + 25 %, so an automatic
    /// move does not stop right at the edge.
    pub fn storage_pressure(&self, until_relieved: bool) -> Pressure {
        let Some(dir) = self.work_dir.as_ref() else { return Pressure::default() };
        let (num, den) = if until_relieved { (6, 10) } else { (8, 10) };
        let over = |used: &AtomicU64, limit: u64| limit > 0 && used.load(Ordering::Relaxed) >= limit * num / den;
        let threshold = if until_relieved { self.low_disk_threshold_bytes + self.low_disk_threshold_bytes / 4 } else { self.low_disk_threshold_bytes };
        Pressure {
            clean: over(&self.kept_clean_bytes, self.keep_clean_limit_bytes),
            shared: over(&self.kept_bytes, self.keep_limit_bytes),
            disk: get_available_disk_space_bytes(dir).is_some_and(|free| free <= threshold),
        }
    }

    /// Moves old-style `<prefix><SHA256>_<name>` files from the work folder root into the
    /// category folders. `verdict_of` gives the recorded engine verdict, which splits the
    /// old `threat_` files into malicious and suspicious. Run once at startup.
    pub fn sort_legacy_kept(&self, verdict_of: impl Fn(&str) -> Option<String>) {
        let Some(dir) = self.work_dir.as_ref() else { return };
        let (mut moved, mut left) = (0usize, 0usize);
        for k in self.list_kept().into_iter().filter(|k| k.legacy) {
            let cat = match (k.category, verdict_of(&k.sha256).as_deref()) {
                ("malicious", Some("suspicious")) => "suspicious",
                (c, _) => c,
            };
            let target = dir.join(cat).join(k.file_name());
            if !target.exists() && std::fs::rename(&k.path, &target).is_ok() {
                moved += 1;
            } else {
                left += 1;
            }
        }
        if moved + left > 0 {
            eprintln!("[engine] kept files sorted into category folders: {moved} moved, {left} left in place");
        }
        // Remove the old threat/ folder once it is empty.
        let _ = std::fs::remove_dir(dir.join(KeptFile::LEGACY_THREAT_DIR));
    }

    /// Adds the analyst-written YARA rules (`analyst_signatures/yara/*.yar`, kept apart
    /// from the shipped rule folders) to the live engine. Returns (loaded, failed files).
    pub fn load_analyst_yara(&self) -> (usize, Vec<String>) {
        let mut failed = Vec::new();
        let Some(engine) = self.engine.get() else { return (0, failed) };
        let dir = crate::human_review::analyst_dir().join("yara");
        let Ok(rd) = std::fs::read_dir(&dir) else { return (0, failed) };
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "yar" || e == "yara"))
            .collect();
        files.sort();
        let Ok(mut g) = engine.write() else { return (0, failed) };
        let mut ok = 0;
        for p in files {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            match std::fs::read_to_string(&p) {
                Ok(src) if g.add_yara_source(&src) => ok += 1,
                _ => failed.push(name),
            }
        }
        if ok > 0 || !failed.is_empty() {
            eprintln!("[engine] analyst YARA rules: {ok} loaded, {} failed {:?}", failed.len(), failed);
        }
        (ok, failed)
    }

    /// Hot reload of the whole engine (compiled `.yrc`, ML models, XOR filters, YAML
    /// rules) from the rules folder, without restarting the process or the listener.
    ///
    /// The new engine is built on a background thread while the old one keeps scanning;
    /// only the final swap takes the write lock (waits for scans in progress, then
    /// is instant). If loading fails or panics, the old engine stays in place.
    /// Peak memory is roughly two engines while the new one loads.
    pub fn reload_all<F>(self: &Arc<Self>, on_done: F) -> Result<(), String>
    where
        F: FnOnce(Result<i64, String>) + Send + 'static,
    {
        if !self.ready() {
            return Err("engine is still loading".into());
        }
        let Some(rules_dir) = self.rules_dir.read().unwrap().clone() else {
            return Err("rules folder unknown".into());
        };
        if self.reloading.swap(true, Ordering::SeqCst) {
            return Err("a reload is already running".into());
        }
        *self.reload_msg.write().unwrap() = "reloading…".into();

        let adapter = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("engine-reload".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let started = Instant::now();
                eprintln!("[engine] hot reload from: {}", rules_dir.display());
                let new_xf = load_malicious_xf(&rules_dir);
                let result = match std::panic::catch_unwind(|| StaticEngine::init(&rules_dir)) {
                    Ok(new_engine) => match adapter.engine.get() {
                        Some(slot) => match slot.write() {
                            Ok(mut guard) => {
                                let old = std::mem::replace(&mut *guard, new_engine);
                                drop(guard);
                                *adapter.malicious_xf.write().unwrap() = new_xf;
                                drop(old); // free the old engine outside the lock
                                adapter.load_analyst_yara();
                                adapter.analyst.reload();
                                let ms = started.elapsed().as_millis() as i64;
                                adapter.load_ms.store(ms, Ordering::Relaxed);
                                Ok(ms)
                            }
                            Err(_) => Err("engine lock poisoned".to_string()),
                        },
                        None => Err("engine not ready".to_string()),
                    },
                    Err(_) => Err("panic while loading the new engine".to_string()),
                };
                let msg = match &result {
                    Ok(ms) => format!("reloaded in {ms} ms"),
                    Err(e) => format!("reload failed, old engine kept: {e}"),
                };
                eprintln!("[engine] {msg}");
                *adapter.reload_msg.write().unwrap() = msg;
                adapter.reloading.store(false, Ordering::SeqCst);
                on_done(result);
            });
        if let Err(e) = spawned {
            self.reloading.store(false, Ordering::SeqCst);
            *self.reload_msg.write().unwrap() = String::new();
            return Err(format!("cannot start reload thread: {e}"));
        }
        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        self.ready()
    }

    pub async fn get_status(&self) -> EngineStatus {
        let error = self.error_msg.read().unwrap().clone();
        let status = if self.ready() {
            "ready"
        } else if !error.is_empty() {
            "error"
        } else {
            "loading"
        };
        EngineStatus {
            status: status.to_string(),
            error,
            load_ms: self.load_ms.load(Ordering::Relaxed),
            name: ENGINE_NAME.to_string(),
            reloading: self.reloading.load(Ordering::Relaxed),
            reload_msg: self.reload_msg.read().unwrap().clone(),
        }
    }

    pub fn malicious_hash_count(&self) -> usize {
        self.malicious_xf
            .read()
            .unwrap()
            .as_ref()
            .map(|f| f.len())
            .unwrap_or(0)
    }

    pub fn whitelist_active(&self) -> bool {
        self.whitelist_enabled
            && self
                .engine
                .get()
                .is_some_and(|e| e.read().map(|g| g.benign_whitelist_loaded()).unwrap_or(false))
    }

    /// Full URL Threat Inspection through OpenEDR Static Engine.
    pub fn inspect_url(
        &self,
        raw_url: &str,
        liveness_code: i32,
        page_content: Option<&str>,
    ) -> Result<openedr_static::url_rules::UrlThreatReport, String> {
        let engine = self
            .engine
            .get()
            .ok_or_else(|| "Engine not ready".to_string())?;
        let guard = engine.read().map_err(|_| "engine lock poisoned".to_string())?;
        Ok(guard.inspect_url_with_content(raw_url, liveness_code, page_content))
    }

    /// Difference-scan judgment: evaluates only YAML rules carrying a
    /// `content_difference` condition. Severity/score/whitelist handling come
    /// from the rules; each hit is paired with its flags for the caller.
    pub fn match_difference_rules(
        &self,
        raw_url: &str,
        difference_percent: u8,
        client_status: Option<u16>,
        server_status: Option<u16>,
        liveness_code: i32,
    ) -> Result<Vec<(openedr_static::url_rules::UrlRuleHit, bool, bool)>, String> {
        let engine = self
            .engine
            .get()
            .ok_or_else(|| "Engine not ready".to_string())?;
        let guard = engine.read().map_err(|_| "engine lock poisoned".to_string())?;
        Ok(guard.url_engine.match_difference_rules(raw_url, difference_percent, client_status, server_status, liveness_code))
    }

    /// General runtime rule reload without restart. Kinds:
    /// - `url`: URL threat rules YAML (replaces the whole document)
    /// - `strings`: HydraDragonSig string-rule YAML (replaces)
    /// - `registry`: PUA registry YAML (replaces; shares the string-rule store)
    /// - `yara_src`: one YARA source document (appended to the YARA set)
    /// Binary bundles (ML models, compiled `.yrc`) stay restart-only.
    pub fn reload_rules(&self, kind: &str, content: &str) -> Result<String, String> {
        let engine = self
            .engine
            .get()
            .ok_or_else(|| "Engine not ready".to_string())?;
        let mut guard = engine.write().map_err(|_| "engine lock poisoned".to_string())?;
        match kind.to_ascii_lowercase().as_str() {
            "url" => guard
                .load_url_rules(content)
                .map(|n| format!("url rules loaded: {n} rules")),
            "strings" => {
                let n = guard.set_string_rules(content);
                if n >= 0 {
                    Ok(format!("string rules loaded: {n} rules"))
                } else {
                    Err("string rules rejected (parse error)".to_string())
                }
            }
            "registry" => {
                let n = guard.set_registry_rules(content);
                if n >= 0 {
                    Ok(format!("registry rules loaded: {n} rules"))
                } else {
                    Err("registry rules rejected (parse error)".to_string())
                }
            }
            "yara_src" => {
                if guard.add_yara_source(content) {
                    Ok("yara source compiled and added".to_string())
                } else {
                    Err("yara source rejected (compile error)".to_string())
                }
            }
            _ => Err("unknown rule kind (url|strings|registry|yara_src)".to_string()),
        }
    }

    /// Verdict from the SHA-256 alone, without the file: hash signatures first (a
    /// malicious hit must win), then the engine's benign whitelist. None = upload needed.
    pub fn hash_lookup(&self, _sha: &Sha, sha_hex: &str) -> Option<ResultMessage> {
        if sha_hex == EICAR_SHA256 {
            return Some(hash_result("malicious", Some("EICAR-Test-File"), "EICAR standard antivirus test file (hash)", 1.0, sha_hex, "hash"));
        }
        if let Some(ref filter) = *self.malicious_xf.read().unwrap() {
            if filter.contains(sha_hex) {
                return Some(hash_result("malicious", Some("Malware.Hash.XorFilter"), "Matched malicious SHA-256 (XOR Filter)", 1.0, sha_hex, "hash"));
            }
        }
        if self.whitelist_enabled {
            if let Some(engine) = self.engine.get() {
                if let Ok(guard) = engine.read() {
                    if guard.is_benign(sha_hex) {
                        return Some(hash_result("clean", None, "Known benign file (whitelist)", 0.0, sha_hex, "whitelist"));
                    }
                }
            }
        }
        None
    }

    /// Runs on an engine thread. The file is written to the work folder first so the
    /// engine can check its Authenticode signature; it falls back to an in-memory scan.
    #[allow(dead_code)]
    pub fn scan_blocking(&self, data: &[u8], name: &str, sha: &str) -> Result<ResultMessage, String> {
        self.scan_blocking_with(data, name, sha, |_| {})
    }

    /// Like `scan_blocking`, with `refine` run on the result before the file is kept or
    /// removed (the TLSH smart whitelist uses it, so `possible_clean` files are kept
    /// under their own prefix).
    pub fn scan_blocking_with(
        &self,
        data: &[u8],
        name: &str,
        sha: &str,
        refine: impl FnOnce(&mut ResultMessage),
    ) -> Result<ResultMessage, String> {
        self.scan_blocking_opts(data, name, sha, true, refine)
    }

    /// `keep = false` (rescans of an already kept file): the temporary copy is always
    /// removed and nothing new is kept.
    pub fn scan_blocking_opts(
        &self,
        data: &[u8],
        name: &str,
        sha: &str,
        keep: bool,
        refine: impl FnOnce(&mut ResultMessage),
    ) -> Result<ResultMessage, String> {
        let engine = self.engine.get().ok_or_else(|| "engine not ready".to_string())?;
        let engine = engine.read().map_err(|_| "engine lock poisoned".to_string())?;

        let started = Instant::now();
        if data.is_empty() {
            let res = ResultMessage {
                r#type: "result".to_string(),
                id: 0,
                timestamp: Some(chrono::Utc::now().to_rfc3339()),
                ecs: Some(serde_json::json!({ "version": "9.5.4" })),
                event: Some(serde_json::json!({ "action": "scan_skipped", "kind": "event", "category": ["malware", "file"] })),
                file: Some(serde_json::json!({ "name": name, "size": 0, "hash": { "sha256": sha } })),
                antivirus: Some(serde_json::json!({ "engine": ENGINE_NAME, "verdict": "skipped" })),
                threat_indicator: None,
                rule: None,
                verdict: "skipped".to_string(),
                threat: None,
                detail: Some("0 KB / empty file skipped".to_string()),
                score: 0.0,
                sha256: sha.to_string(),
                scan_ms: started.elapsed().as_millis() as i64,
                source: "scan".to_string(),
                extracted_objects: Vec::new(),
            };
            return Ok(res);
        }

        let safe_filename = file_system_name(name);
        let mut temp_path: Option<PathBuf> = None;

        let report = if let Some(ref dir) = self.work_dir {
            let seq = self.file_seq.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("{:08}_{}", seq % 100_000_000, temp_name(&safe_filename, data)));
            let rep = if std::fs::write(&path, data).is_ok() {
                temp_path = Some(path.clone());
                Some(engine.scan_file(&path))
            } else {
                None
            };
            match rep {
                Some(r) if !r.verdict.eq_ignore_ascii_case("Error") => r,
                _ => engine.scan_bytes(data, name),
            }
        } else {
            engine.scan_bytes(data, name)
        };

        if report.verdict.eq_ignore_ascii_case("Error") {
            if let Some(p) = temp_path {
                let _ = std::fs::remove_file(p);
            }
            let err_msg = report
                .detections
                .first()
                .map(|d| d.name.clone())
                .unwrap_or_else(|| "unknown engine error".to_string());
            return Err(err_msg);
        }

        let mut res = build_result(&report, sha);
        // Analyst company lists (Authenticode signer): allow -> clean, block -> malicious.
        let signer = report.signer_info.as_ref();
        match self.analyst.company_decision(
            signer.and_then(|s| s.signer_name.as_deref()),
            signer.is_some_and(|s| s.is_signed && s.is_trusted),
        ) {
            Some(crate::analyst_engine::CompanyDecision::Block(company)) => apply_analyst_hit(
                &mut res,
                &crate::analyst_engine::AnalystHit {
                    engine: "company_blocklist",
                    name: format!("Riskware.Multi.BlockedSigner ({company})"),
                    verdict: "malicious",
                },
            ),
            Some(crate::analyst_engine::CompanyDecision::Allow(company)) => apply_company_allow(&mut res, &company),
            None => {}
        }
        // Analyst ClamAV / HydraDragonSig signatures can only raise the verdict.
        for hit in self.analyst.scan(data, name) {
            apply_analyst_hit(&mut res, &hit);
        }
        refine(&mut res);
        res.scan_ms = started.elapsed().as_millis() as i64;

        if keep {
            self.keep_or_remove(temp_path.as_deref(), data, &res, sha, &safe_filename);
        } else if let Some(p) = temp_path {
            let _ = std::fs::remove_file(p);
        }
        Ok(res)
    }

    /// Unknown, possible-clean (TLSH smart whitelist), suspicious and malicious (for
    /// false positive inspection) and, if enabled, clean PE / APK files are kept in the
    /// work folder (multron_incoming) by category: `unknown/`, `possible_clean/`,
    /// `suspicious/`, `malicious/`, `clean/`, each as `<SHA256>_<name>`. Clean files use
    /// their own quota (`--keep-clean-gb`), the rest share `--keep-unknown-gb`.
    /// When disk space is low, incoming files are automatically compressed using LZMA2 maximum preset (.xz).
    fn keep_or_remove(&self, temp: Option<&Path>, data: &[u8], res: &ResultMessage, sha: &str, name: &str) {
        let size = data.len() as u64;
        let is_threat = res.verdict == "malicious" || res.verdict == "suspicious";
        let is_unknown = res.verdict == "unknown";
        let is_clean = res.verdict == "clean";
        let is_possible_clean = res.verdict == "possible_clean";

        let (used, limit) = if is_clean {
            (&self.kept_clean_bytes, self.keep_clean_limit_bytes)
        } else {
            (&self.kept_bytes, self.keep_limit_bytes)
        };
        let should_keep = !data.is_empty()
            && ((self.keep_threats && is_threat)
                || (self.keep_unknown && is_unknown)
                || (is_clean && self.keep_clean.load(Ordering::Relaxed) && is_pe_or_apk(data, name))
                || (self.keep_possible_clean.load(Ordering::Relaxed) && is_possible_clean))
            && used.load(Ordering::Relaxed) + size <= limit;

        if should_keep {
            if let Some(dir) = &self.work_dir {
                let name = if name.is_empty() { "file" } else { name };
                let cat_dir = dir.join(KeptFile::category_for(&res.verdict));
                let _ = std::fs::create_dir_all(&cat_dir);
                let low_disk = self.compress_low_disk
                    && is_disk_space_low(
                        dir,
                        used.load(Ordering::Relaxed),
                        limit,
                        self.low_disk_threshold_bytes,
                    );

                if low_disk {
                    // PC has low disk space: compress with LZMA2 Max (Preset 9) into .xz
                    let target_xz = cat_dir.join(format!("{}_{}.xz", sha, name));
                    if !target_xz.exists() {
                        let comp_res = if let Some(p) = temp {
                            compress_file_lzma2_max(p, &target_xz)
                        } else {
                            compress_bytes_lzma2_max(data, &target_xz)
                        };
                        if let Ok(compressed_len) = comp_res {
                            used.fetch_add(compressed_len, Ordering::Relaxed);
                            self.kept_files.fetch_add(1, Ordering::Relaxed);
                            if let Some(p) = temp {
                                let _ = std::fs::remove_file(p);
                            }
                            return;
                        }
                    }
                } else {
                    let target = cat_dir.join(format!("{}_{}", sha, name));
                    let stored = if target.exists() {
                        false
                    } else if let Some(p) = temp {
                        std::fs::rename(p, &target).is_ok()
                    } else {
                        std::fs::write(&target, data).is_ok()
                    };
                    if stored {
                        used.fetch_add(size, Ordering::Relaxed);
                        self.kept_files.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
        if let Some(p) = temp {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// See `EngineAdapter::storage_pressure`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pressure {
    /// Clean quota (`--keep-clean-gb`).
    pub clean: bool,
    /// Shared quota of the other categories (`--keep-unknown-gb`).
    pub shared: bool,
    /// Free disk space.
    pub disk: bool,
}

impl Pressure {
    pub fn any(&self) -> bool {
        self.clean || self.shared || self.disk
    }

    /// Whether moving a file of `category` helps.
    pub fn helped_by(&self, category: &str) -> bool {
        self.disk || if category == "clean" { self.clean } else { self.shared }
    }

    /// Still short of room in any of the resources that were short at the start.
    pub fn still(&self, start: &Pressure) -> bool {
        (start.clean && self.clean) || (start.shared && self.shared) || (start.disk && self.disk)
    }
}

/// A file kept in the work folder: `<category>/<SHA256>_<name>[.xz]` (older servers
/// wrote `<prefix><SHA256>_<name>[.xz]` into the work folder itself).
#[derive(Debug, Clone)]
pub struct KeptFile {
    pub path: PathBuf,
    /// "unknown", "possible_clean", "suspicious", "malicious" or "clean".
    pub category: &'static str,
    pub sha256: String,
    pub name: String,
    pub xz: bool,
    /// Old prefixed file still in the work folder root.
    pub legacy: bool,
}

impl KeptFile {
    pub const CATEGORIES: [&'static str; 5] = ["unknown", "possible_clean", "suspicious", "malicious", "clean"];
    /// Folder of an earlier build for malicious + suspicious together.
    pub const LEGACY_THREAT_DIR: &'static str = "threat";
    /// Old file name prefixes. `threat_` did not tell malicious from suspicious: such files
    /// are sorted by their recorded verdict (`sort_legacy_kept`), malicious by default.
    const LEGACY_PREFIXES: [(&'static str, &'static str); 3] =
        [("threat_", "malicious"), ("possible_clean_", "possible_clean"), ("clean_", "clean")];

    /// `category` is the folder the file is in; `None` for the work folder root, where
    /// the category comes from the old file name prefix.
    fn parse(path: PathBuf, category: Option<&'static str>) -> Option<Self> {
        let file = path.file_name()?.to_string_lossy().into_owned();
        let (category, rest) = match category {
            Some(c) => (c, file.as_str()),
            None => Self::LEGACY_PREFIXES
                .iter()
                .find_map(|(p, c)| file.strip_prefix(p).map(|r| (*c, r)))
                .unwrap_or(("unknown", file.as_str())),
        };
        let sha = rest.get(..64)?;
        if !sha.chars().all(|c| c.is_ascii_hexdigit()) || rest.as_bytes().get(64) != Some(&b'_') {
            return None;
        }
        let tail = &rest[65..];
        let (name, xz) = match tail.strip_suffix(".xz") {
            Some(n) => (n, true),
            None => (tail, false),
        };
        Some(KeptFile {
            category,
            sha256: sha.to_ascii_uppercase(),
            name: name.to_string(),
            xz,
            legacy: category_dir_of(&path).is_none(),
            path,
        })
    }

    pub fn category_for(verdict: &str) -> &'static str {
        match verdict {
            "malicious" => "malicious",
            "suspicious" => "suspicious",
            "possible_clean" => "possible_clean",
            "clean" => "clean",
            _ => "unknown",
        }
    }

    /// File name inside a category folder.
    pub fn file_name(&self) -> String {
        format!("{}_{}{}", self.sha256, self.name, if self.xz { ".xz" } else { "" })
    }

    pub fn read(&self) -> Option<Vec<u8>> {
        if self.xz {
            use std::io::Read;
            let f = std::fs::File::open(&self.path).ok()?;
            let mut out = Vec::new();
            lzma_rust2::XzReader::new(std::io::BufReader::new(f), false).read_to_end(&mut out).ok()?;
            return Some(out);
        }
        std::fs::read(&self.path).ok()
    }
}

/// TLSH smart whitelist: not proven clean, only very close to a verified clean file
/// with no sign of injection. Clients show it apart from `clean`; it never feeds the
/// hash whitelist and an analyst verdict or signature still overrides it.
pub fn mark_possible_clean(res: &mut ResultMessage, detail: String, ruleset: &str) {
    res.verdict = "possible_clean".into();
    res.threat = None;
    res.score = 0.0;
    res.detail = Some(detail.clone());
    res.threat_indicator = None;
    res.rule = Some(serde_json::json!({ "name": "", "verdict": "possible_clean", "ruleset": ruleset }));
    let av = res.antivirus.get_or_insert_with(|| serde_json::json!({ "engine": ENGINE_NAME }));
    if let Some(o) = av.as_object_mut() {
        o.insert("verdict".into(), serde_json::json!("possible_clean"));
        o.insert("score".into(), serde_json::json!(0.0));
        o.insert("detail".into(), serde_json::json!(detail));
    }
    if let Some(ev) = res.event.as_mut().and_then(|e| e.as_object_mut()) {
        ev.insert("kind".into(), serde_json::json!("event"));
    }
}

fn hash_result(verdict: &str, threat: Option<&str>, detail: &str, score: f64, sha: &str, source: &str) -> ResultMessage {
    let is_threat = verdict == "malicious" || verdict == "suspicious";
    let ecs = serde_json::json!({
        "@timestamp": chrono::Utc::now().to_rfc3339(),
        "ecs": { "version": "9.5.4" },
        "event": {
            "kind": if is_threat { "alert" } else { "event" },
            "category": ["malware", "file"],
            "type": if is_threat { vec!["info", "indicator"] } else { vec!["info"] },
            "action": format!("hash_lookup_{}", source),
            "outcome": "success",
            "duration": 0,
        },
        "file": {
            "hash": {
                "sha256": sha,
            }
        },
        "antivirus": {
            "engine": ENGINE_NAME,
            "verdict": verdict,
            "score": score,
            "source": source,
            "detail": detail,
        },
        "rule": {
            "name": threat.unwrap_or(detail),
            "verdict": verdict,
        }
    });

    let threat_indicator = if is_threat {
        Some(serde_json::json!({
            "indicator": {
                "type": "file",
                "name": threat.unwrap_or(detail),
                "confidence": score,
                "file": {
                    "hash": {
                        "sha256": sha,
                    }
                }
            }
        }))
    } else {
        None
    };

    ResultMessage {
        r#type: "result".to_string(),
        id: 0,
        timestamp: ecs.get("@timestamp").and_then(|t| t.as_str()).map(|s| s.to_string()),
        ecs: Some(serde_json::json!({ "version": "9.5.4" })),
        event: ecs.get("event").cloned(),
        file: ecs.get("file").cloned(),
        antivirus: ecs.get("antivirus").cloned(),
        threat_indicator,
        rule: ecs.get("rule").cloned(),
        verdict: verdict.to_string(),
        threat: threat.map(|t| t.to_string()),
        detail: Some(detail.to_string()),
        score,
        sha256: sha.to_string(),
        scan_ms: 0,
        source: source.to_string(),
        extracted_objects: Vec::new(),
    }
}

fn verdict_rank(v: &str) -> u8 {
    match v {
        "malicious" => 3,
        "suspicious" => 2,
        "clean" => 1,
        _ => 0, // unknown, possible_clean
    }
}

/// Raises a result to an analyst signature's verdict (never lowers it) and keeps the
/// ECS fields the clients read (`antivirus`, `rule`, `threat`, `event.kind`) in sync.
fn apply_analyst_hit(res: &mut ResultMessage, hit: &crate::analyst_engine::AnalystHit) {
    if verdict_rank(hit.verdict) <= verdict_rank(&res.verdict) {
        return;
    }
    let detail = format!("Analyst signature ({}): {}", hit.engine, hit.name);
    let score = if hit.verdict == "malicious" { 100.0 } else { 60.0 };
    res.verdict = hit.verdict.to_string();
    res.threat = Some(hit.name.clone());
    res.detail = Some(match res.detail.take() {
        Some(d) if !d.is_empty() => format!("{detail} — {d}"),
        _ => detail.clone(),
    });
    res.score = res.score.max(score);
    let av = res.antivirus.get_or_insert_with(|| serde_json::json!({ "engine": ENGINE_NAME }));
    if let Some(o) = av.as_object_mut() {
        o.insert("verdict".into(), serde_json::json!(hit.verdict));
        o.insert("score".into(), serde_json::json!(res.score));
        o.insert("detail".into(), serde_json::json!(res.detail));
    }
    res.rule = Some(serde_json::json!({
        "name": hit.name,
        "verdict": hit.verdict,
        "ruleset": format!("analyst/{}", hit.engine),
    }));
    res.threat_indicator = Some(serde_json::json!({
        "indicator": {
            "type": "file",
            "name": hit.name,
            "confidence": res.score,
            "file": { "hash": { "sha256": res.sha256 } }
        }
    }));
    if let Some(ev) = res.event.as_mut().and_then(|e| e.as_object_mut()) {
        ev.insert("kind".into(), serde_json::json!("alert"));
    }
}

/// Allow-listed, validly signed company: the engine verdict becomes clean. Analyst
/// ClamAV/HydraDragonSig hits are applied afterwards and can still raise it again.
fn apply_company_allow(res: &mut ResultMessage, company: &str) {
    if res.verdict == "clean" {
        return;
    }
    let detail = format!("Trusted company (analyst allow-list): {company}; engine said {}", res.verdict);
    mark_clean(res, detail, "analyst/company_allowlist");
}

/// Rewrites a result as clean (keeps the ECS fields the clients read in sync).
pub fn mark_clean(res: &mut ResultMessage, detail: String, ruleset: &str) {
    res.verdict = "clean".into();
    res.threat = None;
    res.score = 0.0;
    res.detail = Some(detail.clone());
    res.threat_indicator = None;
    res.rule = Some(serde_json::json!({ "name": "", "verdict": "clean", "ruleset": ruleset }));
    let av = res.antivirus.get_or_insert_with(|| serde_json::json!({ "engine": ENGINE_NAME }));
    if let Some(o) = av.as_object_mut() {
        o.insert("verdict".into(), serde_json::json!("clean"));
        o.insert("score".into(), serde_json::json!(0.0));
        o.insert("detail".into(), serde_json::json!(detail));
    }
    if let Some(ev) = res.event.as_mut().and_then(|e| e.as_object_mut()) {
        ev.insert("kind".into(), serde_json::json!("event"));
    }
}

fn build_result(report: &StaticScanReport, sha: &str) -> ResultMessage {
    let raw_verdict = report.verdict.to_lowercase();
    let verdict = match raw_verdict.as_str() {
        "clean" | "malicious" | "suspicious" | "unknown" | "skipped" => raw_verdict,
        _ => "unknown".to_string(),
    };

    let mut res = ResultMessage {
        r#type: "result".to_string(),
        id: 0,
        timestamp: None,
        ecs: Some(serde_json::json!({ "version": "9.5.4" })),
        event: None,
        file: None,
        antivirus: None,
        threat_indicator: None,
        rule: None,
        verdict,
        threat: None,
        detail: None,
        score: report.max_threat_score as f64,
        sha256: sha.to_string(),
        scan_ms: report.scan_time_ms as i64,
        source: "scan".to_string(),
        extracted_objects: report.extracted_objects.clone(),
    };

    let mut detail_parts = Vec::new();

    if !report.detections.is_empty() {
        res.threat = Some(report.detections[0].name.clone());
        let details: Vec<String> = report
            .detections
            .iter()
            .take(8)
            .map(|d| format!("{} ({})", d.name, d.layer))
            .collect();
        detail_parts.push(details.join(", "));
    } else if let Some(ref signer) = report.signer_info {
        if signer.is_trusted {
            if let Some(ref name) = signer.signer_name {
                detail_parts.push(format!("Signed by {}", name));
            }
        }
    }

    // Explicitly summarize extracted objects (Unicorn unpacked, archives, overlays)
    if !report.extracted_objects.is_empty() {
        let unpacked_count = report.extracted_objects.iter().filter(|o| o.origin_type == "UnpackedPE").count();
        let archive_count = report.extracted_objects.iter().filter(|o| o.origin_type == "ArchiveMember").count();
        let overlay_count = report.extracted_objects.iter().filter(|o| o.origin_type == "Overlay").count();

        let mut summary_tags = Vec::new();
        if unpacked_count > 0 {
            let total_unpacked_bytes: u64 = report.extracted_objects.iter().filter(|o| o.origin_type == "UnpackedPE").map(|o| o.size).sum();
            summary_tags.push(format!("Unicorn Unpacked: {} PE ({} KB)", unpacked_count, (total_unpacked_bytes + 1023) / 1024));
        }
        if archive_count > 0 {
            summary_tags.push(format!("Archive: {} items", archive_count));
        }
        if overlay_count > 0 {
            summary_tags.push(format!("Overlay: {} items", overlay_count));
        }

        if !summary_tags.is_empty() {
            detail_parts.push(format!("[{}]", summary_tags.join(" | ")));
        }
    }

    if !detail_parts.is_empty() {
        res.detail = Some(detail_parts.join(" — "));
    }

    let mut ecs_val = report.to_ecs_value();
    if let Some(file_obj) = ecs_val.get_mut("file").and_then(|f| f.as_object_mut()) {
        file_obj.insert("hash".to_string(), serde_json::json!({ "sha256": sha }));
    }
    res.timestamp = ecs_val.get("@timestamp").and_then(|t| t.as_str()).map(|s| s.to_string());
    res.ecs = ecs_val.get("ecs").cloned().or_else(|| Some(serde_json::json!({ "version": "9.5.4" })));
    res.event = ecs_val.get("event").cloned();
    res.file = ecs_val.get("file").cloned();
    res.antivirus = ecs_val.get("antivirus").cloned();
    res.threat_indicator = ecs_val.get("threat").cloned();
    res.rule = ecs_val.get("rule").cloned();

    res
}

/// Malicious SHA-256 XOR filter from `xorfilter_rules` (no .txt hash files).
fn load_malicious_xf(rules_dir: &Path) -> Option<BinaryFuse16Filter> {
    let xf_dir = rules_dir.join("xorfilter_rules");
    for cand in &["malicious_sha256.xf", "malware.xf"] {
        let p = xf_dir.join(cand);
        if p.is_file() {
            if let Ok(bytes) = std::fs::read(&p) {
                if let Some(f) = BinaryFuse16Filter::from_bytes(&bytes) {
                    eprintln!("[engine] {} malicious SHA-256 signatures loaded from XOR filter {}", f.len(), p.display());
                    return Some(f);
                }
            }
        }
    }
    None
}

fn resolve_rules_dir(custom: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = custom {
        if dir.is_dir() {
            return dir;
        }
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.to_path_buf());
            candidates.push(parent.join("rules"));
            candidates.push(parent.join("OpenMalwareScannerPortable"));
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join("OpenMalwareScannerPortable"));
                if let Some(ggparent) = grandparent.parent() {
                    candidates.push(ggparent.join("OpenMalwareScannerPortable"));
                }
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.clone());
        candidates.push(cwd.join("OpenMalwareScannerPortable"));
        candidates.push(cwd.join("OpenEDR"));
    }

    for c in &candidates {
        if c.join("database").is_dir()
            || c.join("yara_rules").is_dir()
            || c.join("models").is_dir()
            || c.join("xorfilter_rules").is_dir()
        {
            return c.clone();
        }
    }

    PathBuf::from(".")
}

/// Deletes temp files left by a previous run; returns (bytes, count) of kept unknown files.
/// Only PE files and Android packages are worth keeping when clean: they feed rescans
/// after engine updates and the TLSH / ML benign corpus.
fn is_pe_or_apk(data: &[u8], name: &str) -> bool {
    if data.starts_with(b"MZ") {
        return true;
    }
    if !data.starts_with(b"PK\x03\x04") {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".apk") || lower.ends_with(".xapk") || data.windows(11).any(|w| w == b"classes.dex")
}

/// Category folder (`unknown`, `malicious`, ...) a kept file is in, if any.
fn category_dir_of(path: &Path) -> Option<&'static str> {
    let parent = path.parent()?.file_name()?.to_str()?;
    KeptFile::CATEGORIES.iter().copied().find(|c| *c == parent)
}

/// At startup: deletes temp files of interrupted scans, creates the category folders
/// and counts what is kept (bytes outside clean/, files, bytes in clean/).
fn remove_leftover_uploads(dir: &Path) -> (u64, i64, u64) {
    for cat in KeptFile::CATEGORIES {
        let _ = std::fs::create_dir_all(dir.join(cat));
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let b = name.as_bytes();
            if path.is_file() && b.len() >= 9 && b[..8].iter().all(|c| c.is_ascii_digit()) && b[8] == b'_' {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    let mut kept = (0u64, 0i64, 0u64);
    let mut count = |rd: std::fs::ReadDir, cat: Option<&'static str>| {
        for e in rd.flatten() {
            if let Some(k) = KeptFile::parse(e.path(), cat) {
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                if k.category == "clean" {
                    kept.2 += len;
                } else {
                    kept.0 += len;
                }
                kept.1 += 1;
            }
        }
    };
    for cat in KeptFile::CATEGORIES {
        if let Ok(rd) = std::fs::read_dir(dir.join(cat)) {
            count(rd, Some(cat));
        }
    }
    if let Ok(rd) = std::fs::read_dir(dir.join(KeptFile::LEGACY_THREAT_DIR)) {
        count(rd, Some("malicious"));
    }
    // Old-style files still in the root (sorted later by `sort_legacy_kept`).
    if let Ok(rd) = std::fs::read_dir(dir) {
        count(rd, None);
    }
    kept
}

fn compress_bytes_lzma2_max(data: &[u8], target_path: &Path) -> std::io::Result<u64> {
    use std::io::Write;
    let file = std::fs::File::create(target_path)?;
    let mut enc = lzma_rust2::XzWriter::new(file, lzma_rust2::XzOptions::with_preset(9))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    enc.write_all(data)?;
    let finished_file = enc.finish()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    finished_file.metadata().map(|m| m.len())
}

fn compress_file_lzma2_max(src_path: &Path, target_path: &Path) -> std::io::Result<u64> {
    use std::io::{Read, Write};
    let mut src = std::fs::File::open(src_path)?;
    let file = std::fs::File::create(target_path)?;
    let mut enc = lzma_rust2::XzWriter::new(file, lzma_rust2::XzOptions::with_preset(9))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        enc.write_all(&buffer[..n])?;
    }
    let finished_file = enc.finish()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    finished_file.metadata().map(|m| m.len())
}

#[cfg(windows)]
fn get_available_disk_space_bytes(dir: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    wide.push(0);

    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }

    let mut free_bytes_available: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free_bytes: u64 = 0;

    let ret = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes_available,
            &mut total_bytes,
            &mut total_free_bytes,
        )
    };

    if ret != 0 {
        Some(free_bytes_available)
    } else {
        None
    }
}

#[cfg(not(windows))]
fn get_available_disk_space_bytes(_dir: &Path) -> Option<u64> {
    None
}

fn is_disk_space_low(dir: &Path, kept_bytes: u64, keep_limit_bytes: u64, low_disk_threshold_bytes: u64) -> bool {
    if keep_limit_bytes > 0 && kept_bytes >= (keep_limit_bytes * 8) / 10 {
        return true;
    }
    if let Some(free_bytes) = get_available_disk_space_bytes(dir) {
        if free_bytes <= low_disk_threshold_bytes {
            return true;
        }
    }
    false
}

/// Name used for the temp file. Executables uploaded with a sample extension such as
/// `.vir` get `.exe` so the engine treats them as PE files.
fn temp_name(safe: &str, data: &[u8]) -> String {
    let mut name: String = safe.chars().take(80).collect();
    if name.is_empty() {
        name = "file".into();
    }
    if data.starts_with(b"MZ") {
        let lower = name.to_ascii_lowercase();
        let is_pe_ext = [".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi", ".drv", ".com"]
            .iter()
            .any(|e| lower.ends_with(e));
        if !is_pe_ext {
            name.push_str(".exe");
        }
    }
    name
}

pub fn file_system_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            _ => c,
        })
        .collect::<String>()
        .trim_matches(['.', ' '])
        .to_string()
}

#[cfg(test)]
mod pc_test {
    #[test]
    fn possible_clean_wire() {
        let mut r = super::hash_result("unknown", None, "x", 0.0, "AB", "scan");
        super::mark_possible_clean(&mut r, "Smart whitelist: test".into(), "smart_whitelist/tlsh");
        println!("WIRE {}", serde_json::to_string(&r).unwrap());
    }
}

#[cfg(test)]
mod kept_tests {
    use super::*;

    #[test]
    fn categories_and_legacy() {
        let dir = std::env::temp_dir().join(format!("kept_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sha = |c: char| c.to_string().repeat(64);
        std::fs::write(dir.join(format!("threat_{}_a.exe", sha('A'))), b"x").unwrap();
        std::fs::write(dir.join(format!("threat_{}_b.exe", sha('B'))), b"x").unwrap();
        std::fs::write(dir.join(format!("possible_clean_{}_c.dll", sha('C'))), b"x").unwrap();
        std::fs::write(dir.join(format!("{}_d.js", sha('D'))), b"x").unwrap();
        std::fs::write(dir.join("00000012_tmp.exe"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("threat")).unwrap();
        std::fs::write(dir.join("threat").join(format!("{}_e.exe", sha('E'))), b"x").unwrap();
        let (_, n, _) = remove_leftover_uploads(&dir);
        assert_eq!(n, 5);
        assert!(!dir.join("00000012_tmp.exe").exists());
        let ad = EngineAdapter::new(Some(dir.clone()), false, true, 1, true, false, 1, false, 1);
        ad.sort_legacy_kept(|s| (s == sha('B')).then(|| "suspicious".to_string()));
        assert!(dir.join("malicious").join(format!("{}_a.exe", sha('A'))).exists());
        assert!(dir.join("suspicious").join(format!("{}_b.exe", sha('B'))).exists());
        assert!(dir.join("possible_clean").join(format!("{}_c.dll", sha('C'))).exists());
        assert!(dir.join("unknown").join(format!("{}_d.js", sha('D'))).exists());
        assert!(dir.join("malicious").join(format!("{}_e.exe", sha('E'))).exists());
        assert!(!dir.join("threat").exists());
        ad.relabel_kept(&sha('D'), "clean");
        let k = ad.find_kept(&sha('D')).unwrap();
        assert_eq!(k.category, "clean");
        assert!(!k.legacy);
        assert_eq!(ad.list_kept().len(), 5);
        let moved = ad.relabel_many(&[(sha('a'), "clean".into()), (sha('C'), "possible_clean".into()), ("F".repeat(64), "clean".into())]);
        assert_eq!(moved, 1);
        assert!(dir.join("clean").join(format!("{}_a.exe", sha('A'))).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
