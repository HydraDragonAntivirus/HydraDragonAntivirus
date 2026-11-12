#![cfg(windows)]

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;
use serde::Serialize;

use crate::registry_scanner::RegistryEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePumDetection {
    pub check: String,
    pub min_lines: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePumRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub verdict: String,
    pub confidence: u8,
    pub family: Option<String>,
    pub score: u32,
    pub file_path: String,
    pub detection: FilePumDetection,
    #[serde(default)]
    pub expected_reverted_value: Option<String>,
    pub tags: Vec<String>,
    pub mitre: Vec<FilePumMitre>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePumMitre {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FilePumRulesFile {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    pub rules: Vec<FilePumRule>,
}

/// Resolve environment-variable placeholders like `%SystemRoot%` in file paths.
fn resolve_path(template: &str) -> String {
    let mut result = template.to_string();
    while let Some(start) = result.find('%') {
        let end = result[start + 1..].find('%').map(|p| start + 1 + p + 1);
        let Some(end) = end else { break };
        let var = &result[start + 1..end - 1];
        if let Ok(val) = std::env::var(var) {
            result.replace_range(start..end, &val);
        } else {
            break;
        }
    }
    result
}

/// Load file PUM rules from a YAML file.
pub fn load_rules(path: &Path) -> Result<Vec<FilePumRule>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path:?}: {e}"))?;
    let file: FilePumRulesFile =
        yaml_serde::from_str(&content).map_err(|e| format!("YAML parse error: {e}"))?;
    Ok(file.rules)
}

/// Scan all configured files for PUM modifications based on YAML rules.
/// Returns registry-like entries (hive="FILE") for each triggered rule.
pub fn scan_file_pums(
    rules: &[FilePumRule],
    seen: &mut HashSet<String>,
) -> Vec<RegistryEntry> {
    let mut entries = Vec::new();

    for rule in rules {
        let file_path = resolve_path(&rule.file_path);
        let dedup_key = format!("FILE|{}", rule.id);
        if !seen.insert(dedup_key) {
            continue;
        }

        let content = match std::fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let hit = match rule.detection.check.as_str() {
            "non_comment_lines" => {
                let threshold = rule.detection.min_lines.unwrap_or(1);
                let non_comment: Vec<&str> = content
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                if non_comment.len() >= threshold {
                    Some(non_comment.into_iter().map(|s| s.to_string()).collect::<Vec<_>>())
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(lines) = hit {
            let detail = format!(
                "{}: {} non-comment entries: {}",
                rule.title,
                lines.len(),
                lines.join(" | ")
            );
            entries.push(RegistryEntry {
                hive: "FILE".into(),
                path: file_path,
                value_name: format!("{}_content", rule.id),
                value_data: lines.join("; "),
                pua_match: false,
                static_match: true,
                pum: true,
                expected_reverted_value: rule.expected_reverted_value.clone(),
                threat_name: rule.family.clone().or(Some(format!("PUM.{}", rule.id))),
                detail,
            });
        }
    }

    entries
}
