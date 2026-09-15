use std::collections::HashSet;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use evtx::{EvtxParser, ParserSettings, RecordAllocation};
use nested::Nested;
use hayabusa::detections::configs::{
    Action, Config, CsvOutputOption, DetectCommonOption, InputOption, OutputOption, StoredStatic,
    STORED_EKEY_ALIAS, STORED_STATIC,
};
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
    stored_static: Option<StoredStatic>,
    rule_keys: Nested<String>,
    is_valid: bool,
}

impl HayabusaScanner {
    pub fn new(rules_dir: &Path) -> Self {
        if !rules_dir.is_dir() {
            return Self {
                rules_dir: rules_dir.to_path_buf(),
                stored_static: None,
                rule_keys: Nested::new(),
                is_valid: false,
            };
        }

        let stored_static = match create_minimal_stored_static(rules_dir) {
            Some(s) => s,
            None => {
                return Self {
                    rules_dir: rules_dir.to_path_buf(),
                    stored_static: None,
                    rule_keys: Nested::new(),
                    is_valid: false,
                };
            }
        };

        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());

        let exclude_ids = filter::RuleExclude::new();
        let rule_nodes = Detection::parse_rule_files(
            "informational",
            "",
            rules_dir,
            &exclude_ids,
            &stored_static,
        );

        let mut key_set: HashSet<String> = HashSet::new();
        for r in &rule_nodes {
            let keys = rule::get_detection_keys(r);
            key_set.extend(keys.iter().map(|x| x.to_string()));
        }
        let rule_keys: Nested<String> = key_set.into_iter().collect();
        let is_valid = !rule_nodes.is_empty();

        Self {
            rules_dir: rules_dir.to_path_buf(),
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

        let exclude_ids = filter::RuleExclude::new();
        let rule_nodes = Detection::parse_rule_files(
            "informational",
            "",
            &self.rules_dir,
            &exclude_ids,
            stored_static,
        );
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

        let exclude_ids = filter::RuleExclude::new();
        let rule_nodes = Detection::parse_rule_files(
            "informational",
            "",
            &self.rules_dir,
            &exclude_ids,
            stored_static,
        );
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

fn get_evtx_dir() -> PathBuf {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    PathBuf::from(system_root)
        .join("System32")
        .join("winevt")
        .join("Logs")
}

fn create_minimal_stored_static(rules_dir: &Path) -> Option<StoredStatic> {
    let config = Config {
        action: Some(Action::CsvTimeline(CsvOutputOption {
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
    Some(StoredStatic::create_static_data(Some(config)))
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
                utils::create_rec_info(data, path_str.clone(), rule_keys, &recovered, &no_pwsh)
            })
            .collect();

        let (d_next, detect_infos) = d.start(rt, records);
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
