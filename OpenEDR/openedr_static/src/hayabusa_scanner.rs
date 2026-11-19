use std::collections::HashSet;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use evtx::{EvtxParser, ParserSettings, RecordAllocation};
use nested::Nested;
use hayabusa::detections::configs::{
    Action, Config, DetectCommonOption, DfirTimelineOption, InputOption, OutputOption, StoredStatic,
};
use hayabusa::options::htmlreport::HtmlReporter;
use hayabusa::detections::detection::{Detection, EvtxRecordInfo};
use hayabusa::detections::message::DetectInfo;
use hayabusa::detections::rule;
use hayabusa::detections::utils;
use hayabusa::filter;
use serde_json::Value;
use tokio::runtime::Runtime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HayabusaEventMatch {
    pub title: String,
    pub level: String,
    pub severity: u32,
    pub computer: Option<String>,
    pub channel: Option<String>,
    pub event_id: Option<u32>,
    pub timestamp: Option<String>,
    pub details: Option<String>,
}

pub struct HayabusaScanner {
    rules_dir: PathBuf,
    /// Additional rule directories (analyst Sigma rules). Parsed with the same
    /// `StoredStatic` - hence the same `rules_dir/config`, level floor and
    /// status filter - as `rules_dir`, so they behave exactly like shipped rules.
    extra_dirs: Vec<PathBuf>,
    stored_static: Option<StoredStatic>,
    rule_keys: Nested<String>,
    is_valid: bool,
}

impl HayabusaScanner {
    pub fn new(rules_dir: &Path) -> Self {
        Self::new_with_extra(rules_dir, &[])
    }

    /// `new`, plus the `.yml` rules under each of `extra_dirs`. Missing extra
    /// directories are skipped. Correlation rules only link to rules parsed
    /// from the same directory (Hayabusa resolves them per parse).
    pub fn new_with_extra(rules_dir: &Path, extra_dirs: &[PathBuf]) -> Self {
        let extra_dirs: Vec<PathBuf> = extra_dirs.iter().filter(|d| d.is_dir()).cloned().collect();
        let invalid = |extra_dirs: Vec<PathBuf>| Self {
            rules_dir: rules_dir.to_path_buf(),
            extra_dirs,
            stored_static: None,
            rule_keys: Nested::new(),
            is_valid: false,
        };
        if !rules_dir.is_dir() && extra_dirs.is_empty() {
            return invalid(extra_dirs);
        }

        let stored_static = match create_minimal_stored_static(rules_dir) {
            Some(s) => s,
            None => return invalid(extra_dirs),
        };

        let rule_nodes = parse_all_rule_dirs(rules_dir, &extra_dirs, &stored_static);

        let mut key_set: HashSet<String> = HashSet::new();
        for r in &rule_nodes {
            let keys = rule::get_detection_keys(r);
            key_set.extend(keys.iter().map(|x| x.to_string()));
        }
        let rule_keys: Nested<String> = key_set.into_iter().collect();
        let is_valid = !rule_nodes.is_empty();

        Self {
            rules_dir: rules_dir.to_path_buf(),
            extra_dirs,
            stored_static: Some(stored_static),
            rule_keys,
            is_valid,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.is_valid
    }

    pub fn scan_evtx_file(&self, path: &Path) -> Vec<HayabusaEventMatch> {
        let stored_static = match self.stored_static.as_ref() {
            Some(s) if self.is_valid => s,
            _ => return Vec::new(),
        };

        let rt = match Runtime::new() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let rule_nodes = parse_all_rule_dirs(&self.rules_dir, &self.extra_dirs, stored_static);
        if rule_nodes.is_empty() {
            return Vec::new();
        }

        let mut detection = Detection::new(rule_nodes);
        let detect_infos = scan_single_evtx(path, stored_static, &self.rule_keys, &mut detection, &rt);

        let mut all_matches = Vec::new();
        let mut seen = HashSet::new();
        for di in detect_infos {
            add_if_new(&mut all_matches, &mut seen, &di);
        }
        all_matches
    }

    pub fn scan_system_events(&self) -> Vec<HayabusaEventMatch> {
        let evtx_dir = get_evtx_dir();
        if !evtx_dir.exists() {
            return Vec::new();
        }

        let stored_static = match self.stored_static.as_ref() {
            Some(s) if self.is_valid => s,
            _ => return Vec::new(),
        };

        let rt = match Runtime::new() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let rule_nodes = parse_all_rule_dirs(&self.rules_dir, &self.extra_dirs, stored_static);
        if rule_nodes.is_empty() {
            return Vec::new();
        }

        let mut detection = Detection::new(rule_nodes);
        let mut all_matches = Vec::new();
        let mut seen = HashSet::new();

        if let Ok(entries) = std::fs::read_dir(&evtx_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("evtx") {
                    continue;
                }
                let detect_infos = scan_single_evtx(&path, stored_static, &self.rule_keys, &mut detection, &rt);
                for di in detect_infos {
                    add_if_new(&mut all_matches, &mut seen, &di);
                }
            }
        }

        all_matches
    }
}

/// Parse the main rule directory and every extra one with one `StoredStatic`
/// (same config, `informational` floor, status filter). A missing main
/// directory contributes nothing rather than failing the extra ones.
fn parse_all_rule_dirs(
    rules_dir: &Path,
    extra_dirs: &[PathBuf],
    stored_static: &StoredStatic,
) -> Vec<rule::RuleNode> {
    let exclude_ids = filter::RuleExclude::new();
    let mut nodes = Vec::new();
    for dir in std::iter::once(rules_dir).chain(extra_dirs.iter().map(PathBuf::as_path)) {
        if !dir.is_dir() {
            continue;
        }
        nodes.extend(Detection::parse_rule_files(
            "informational",
            "",
            dir,
            &exclude_ids,
            stored_static,
            &mut HtmlReporter::default(),
        ));
    }
    nodes
}

const SIGMA_LEVELS: &[&str] = &["informational", "low", "medium", "high", "critical"];

/// Validate one analyst Sigma/Hayabusa rule document. Returns its `title`.
///
/// Structural checks first (precise messages for the common mistakes):
/// `title`, `id`, `level` in informational|low|medium|high|critical, a
/// `logsource` mapping and a `detection` mapping with a `condition`. Then the
/// rule goes through Hayabusa's own loader and `RuleNode::init` - the exact
/// path a shipped rule takes - so a condition that references a missing
/// selection, a bad modifier, an invalid regex, or a field Hayabusa's format
/// demands (it requires `author` and `date`) is rejected here rather than
/// silently dropped when the scheduled scan builds the scanner.
pub fn validate_sigma_yaml(src: &str) -> Result<String, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(src).map_err(|e| format!("YAML parse error: {e}"))?;
    let map = doc.as_mapping().ok_or("rule must be a YAML mapping")?;
    let get = |k: &str| map.get(serde_yaml::Value::String(k.to_string()));
    let non_empty_str = |k: &str| -> Result<String, String> {
        match get(k) {
            Some(serde_yaml::Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
            Some(_) => Err(format!("`{k}` must be a non-empty string")),
            None => Err(format!("missing `{k}`")),
        }
    };
    let title = non_empty_str("title")?;
    non_empty_str("id")?;
    let level = non_empty_str("level")?.to_ascii_lowercase();
    if !SIGMA_LEVELS.contains(&level.as_str()) {
        return Err(format!("`level` must be one of {}, got {level:?}", SIGMA_LEVELS.join("|")));
    }
    if !get("logsource").is_some_and(|v| v.is_mapping()) {
        return Err("`logsource` must be a mapping".to_string());
    }
    let detection = get("detection")
        .and_then(|v| v.as_mapping())
        .ok_or("`detection` must be a mapping")?;
    if !detection.contains_key(serde_yaml::Value::String("condition".to_string())) {
        return Err("`detection` has no `condition`".to_string());
    }
    hayabusa_rule_check(src)?;
    Ok(title)
}

/// Run `src` through Hayabusa's rule loader and `RuleNode::init`.
///
/// The loader only reads rule files, so the document goes through a private
/// temp file. One `StoredStatic` (embedded default config) is built once and
/// reused; the mutex serializes checks so the shared error log can be read
/// back per call.
fn hayabusa_rule_check(src: &str) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    static CHECKER: OnceLock<Mutex<StoredStatic>> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let checker = CHECKER.get_or_init(|| {
        // The shipped Hayabusa rule tree next to the executable when there is
        // one (its `config/` is what the scanner itself will use); otherwise a
        // directory that does not exist, so config lookups fall back to
        // Hayabusa's defaults. Rule *validity* does not depend on that config.
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        let rules_dir = exe_dir
            .iter()
            .flat_map(|d| [d.join("hayabusa_rules"), d.join("rules").join("hayabusa")])
            .find(|d| d.join("config").is_dir())
            .unwrap_or_else(|| std::env::temp_dir().join("openedr_sigma_check"));
        let ss = create_minimal_stored_static(&rules_dir)
            .expect("create_minimal_stored_static always returns Some");
        Mutex::new(ss)
    });
    let ss = checker.lock().unwrap_or_else(|p| p.into_inner());

    let path = std::env::temp_dir().join(format!(
        "openedr_sigma_check_{}_{}.yml",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, src).map_err(|e| format!("cannot stage rule for validation: {e}"))?;
    let path_str = path.display().to_string();
    let scrub = |m: &str| m.replace(&path_str, "<rule>");

    let log_before = ss.error_log_stack.lock().map(|l| l.len()).unwrap_or(0);
    let mut loader = hayabusa::yaml::ParseYaml::new(&ss);
    let read = loader.read_dir(&path, "informational", "", &filter::RuleExclude::new(), &ss);
    let _ = std::fs::remove_file(&path);
    read.map_err(|e| format!("Hayabusa could not read the rule: {e}"))?;

    if loader.error_rule_count > 0 {
        let msgs: Vec<String> = ss
            .error_log_stack
            .lock()
            .map(|l| l.iter().skip(log_before).map(|m| scrub(m)).collect())
            .unwrap_or_default();
        return Err(if msgs.is_empty() {
            "Hayabusa rejected the rule format".to_string()
        } else {
            msgs.join("; ")
        });
    }
    if loader.files.is_empty() {
        return Err("Hayabusa would not load this rule (deprecated/unsupported `status`, or filtered out)".to_string());
    }
    for (rule_path, yaml) in loader.files {
        let mut node = rule::create_rule(rule_path, yaml);
        node.init(&ss).map_err(|errs| errs.iter().map(|m| scrub(m)).collect::<Vec<_>>().join("; "))?;
    }
    Ok(())
}

fn get_evtx_dir() -> PathBuf {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    PathBuf::from(system_root)
        .join("System32")
        .join("winevt")
        .join("Logs")
}

fn create_minimal_stored_static(rules_dir: &Path) -> Option<StoredStatic> {
    let config = Config {
        action: Some(Action::DfirTimeline(DfirTimelineOption {
            output_options: OutputOption {
                input_args: InputOption {
                    live_analysis: true,
                    ..Default::default()
                },
                min_level: "informational".to_string(),
                include_status: Some(vec!["*".to_string()]),
                no_wizard: true,
                detect_common_options: DetectCommonOption {
                    config: rules_dir.join("config"),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })),
        debug: false,
    };
    Some(StoredStatic::create_static_data(config))
}

fn scan_single_evtx(
    path: &Path,
    stored_static: &StoredStatic,
    rule_keys: &Nested<String>,
    detection: &mut Detection,
    rt: &Runtime,
) -> Vec<DetectInfo> {
    let mut d = std::mem::replace(detection, Detection::new(vec![]));
    let parser = match EvtxParser::from_path(path) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let parse_config = ParserSettings::default()
        .separate_json_attributes(true)
        .num_threads(stored_static.thread_number.unwrap_or(0));
    let mut parser = parser.with_configuration(parse_config);
    let mut evtx_iter = parser.records_json_value();

    let mut all_detect_infos: Vec<DetectInfo> = Vec::new();
    let path_str = path.to_string_lossy().to_string();
    let no_pwsh = stored_static.no_pwsh_field_extraction;

    loop {
        let mut batch: Vec<(Value, bool)> = Vec::new();
        while batch.len() < 1000 {
            match evtx_iter.next() {
                None => break,
                Some(Err(_)) => continue,
                Some(Ok(rec)) => {
                    let recovered = rec.allocation == RecordAllocation::EmptyPage;
                    batch.push((rec.data, recovered));
                }
            }
        }
        if batch.is_empty() {
            break;
        }

        let records: Vec<EvtxRecordInfo> = batch
            .into_iter()
            .map(|(data, recovered)| {
                utils::create_rec_info(
                    data,
                    path_str.clone(),
                    rule_keys,
                    &recovered,
                    &no_pwsh,
                    &stored_static.eventkey_alias,
                )
            })
            .collect();

        let (d_next, detect_infos) = d.start(rt, records, Arc::new(stored_static.clone()));
        all_detect_infos.extend(detect_infos);
        d = d_next;
    }

    *detection = d;
    all_detect_infos
}

fn add_if_new(
    all_matches: &mut Vec<HayabusaEventMatch>,
    seen: &mut HashSet<String>,
    di: &DetectInfo,
) {
    let title = di.ruletitle.to_string();
    if title.is_empty() || !seen.insert(format!("{}_{}", title, di.rec_id)) {
        return;
    }
    let level_str = di.level.to_full().to_string();
    let severity = match level_str.as_str() {
        "critical" => 100,
        "high" => 85,
        "medium" => 65,
        "low" => 45,
        "informational" => 20,
        _ => 50,
    };
    all_matches.push(HayabusaEventMatch {
        title,
        level: level_str,
        severity,
        computer: if di.computername.is_empty() { None } else { Some(di.computername.to_string()) },
        channel: None,
        event_id: di.eventid.parse().ok(),
        timestamp: Some(di.detected_time.to_rfc3339()),
        details: if di.detail.is_empty() { None } else { Some(di.detail.to_string()) },
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
title: Analyst test rule
id: 6f1b8c2e-0000-4000-8000-000000000001
author: analyst
date: 2026/11/19
level: high
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
    condition: selection
"#;

    #[test]
    fn validate_sigma_accepts_valid_rule() {
        assert_eq!(validate_sigma_yaml(VALID), Ok("Analyst test rule".to_string()));
    }

    #[test]
    fn validate_sigma_rejects_bad_rules() {
        assert!(validate_sigma_yaml(&VALID.replace("level: high", "level: severe"))
            .unwrap_err()
            .contains("level"));
        assert!(validate_sigma_yaml(&VALID.replace("    condition: selection\n", ""))
            .unwrap_err()
            .contains("condition"));
        assert!(validate_sigma_yaml("title: x\n").is_err());
        // Structurally fine, but the condition names a selection that does not
        // exist: only Hayabusa's own init catches this.
        let err = validate_sigma_yaml(&VALID.replace("condition: selection", "condition: missing_sel"))
            .unwrap_err();
        assert!(!err.is_empty());
    }
}
