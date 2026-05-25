//! Processes.rs contains all functions associated with the process page UI in Tauri.
//! This module will handle state, requests, async, and events.

use serde_json::{json, Value};
use shared_no_std::ipc::CommandResponse;
use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::ipc::IpcClient;

const MAX_OVERVIEW_TIMELINES: usize = 80;

#[tauri::command]
pub async fn process_query_pid(pid: String) -> Result<String, ()> {
    let requested_pid = sanitize_pid(pid.trim());

    if requested_pid.is_empty() {
        return Ok(build_mitre_attack_overview_response().to_string());
    }

    let cache = load_owlyshield_timeline_cache(&requested_pid, 1);
    if let Some(timeline) = cache.html.clone() {
        return Ok(timeline_cache_response(
            "success",
            "owlyshield_cache",
            "Loaded persistent Owlyshield attack timeline",
            timeline,
            &cache,
        )
        .to_string());
    }

    match IpcClient::send_ipc::<CommandResponse, String>(
        "process_query_pid",
        Some(requested_pid.clone()),
    )
    .await
    {
        Ok(response) => {
            let mut value = serde_json::to_value(&response).unwrap_or_else(|_| {
                json!({
                    "status": "error",
                    "message": "Failed to serialize process query response"
                })
            });

            if value.get("timeline").is_none() {
                let cache = load_owlyshield_timeline_cache(&requested_pid, 1);
                if let Some(timeline) = cache.html.clone() {
                    value["timeline"] = json!(timeline);
                    value["source"] = json!("owlyshield_cache");
                    append_archive_metadata(&mut value, &cache);
                }
            }

            Ok(value.to_string())
        }
        Err(e) => {
            eprintln!("[-] Error with IPC: {e}");
            let cache = load_owlyshield_timeline_cache(&requested_pid, 1);
            let fallback = cache.html.clone().unwrap_or_else(|| {
                format!(
                    "<pre>IPC error: {}\nNo Owlyshield attack timeline cache was found.</pre>",
                    html_escape(&e.to_string())
                )
            });
            Ok(timeline_cache_response(
                "error",
                "owlyshield_cache",
                &format!("IPC error: {e}"),
                fallback,
                &cache,
            )
            .to_string())
        }
    }
}

#[tauri::command]
pub async fn mitre_attack_overview() -> Result<String, ()> {
    Ok(build_mitre_attack_overview_response().to_string())
}

fn build_mitre_attack_overview_response() -> Value {
    let cache = load_owlyshield_timeline_cache("", MAX_OVERVIEW_TIMELINES);
    let timeline = cache
        .html
        .clone()
        .unwrap_or_else(|| empty_mitre_overview_html(&cache));

    timeline_cache_response(
        "success",
        "programdata_mitre_archive",
        "Loaded persistent MITRE ATT&CK timeline archive",
        timeline,
        &cache,
    )
}

fn timeline_cache_response(
    status: &str,
    source: &str,
    message: &str,
    timeline: String,
    cache: &TimelineCacheLoad,
) -> Value {
    let mut value = json!({
        "status": status,
        "source": source,
        "message": message,
        "timeline": timeline,
    });
    append_archive_metadata(&mut value, cache);
    value
}

fn append_archive_metadata(value: &mut Value, cache: &TimelineCacheLoad) {
    value["archive_dir"] = json!(cache.archive_dir.display().to_string());
    value["timeline_count"] = json!(cache.found);
    value["archived_files"] = json!(cache.copied);
    value["archive_errors"] = json!(&cache.errors);
}

fn load_owlyshield_timeline_cache(pid: &str, limit: usize) -> TimelineCacheLoad {
    let pid = sanitize_pid(pid);
    let mut candidates = Vec::new();
    let archive_dir = mitre_archive_dir();

    for dir in owlyshield_report_dirs() {
        if !dir.is_dir() {
            continue;
        }

        collect_timeline_files(&dir, &pid, &mut candidates);
    }

    candidates.sort_by_key(|candidate| Reverse(candidate.modified));
    dedup_timeline_candidates(&mut candidates);

    let (copied, errors) = archive_timeline_candidates(&candidates, &archive_dir);
    let mut result = TimelineCacheLoad {
        html: None,
        found: candidates.len(),
        copied,
        archive_dir,
        errors,
    };

    if pid.is_empty() {
        let mut fragments = Vec::new();
        for candidate in candidates.into_iter().take(limit) {
            if let Ok(html) = fs::read_to_string(&candidate.path) {
                fragments.push(format!(
                    "<section class=\"owlyshield-cache-entry\"><div class=\"cache-source\">{}</div>{}</section>",
                    html_escape(&candidate.path.display().to_string()),
                    html
                ));
            }
        }
        if fragments.is_empty() {
            result
        } else {
            result.html = Some(fragments.join("<hr class=\"cache-separator\"/>"));
            result
        }
    } else {
        result.html = candidates
            .into_iter()
            .find_map(|candidate| fs::read_to_string(candidate.path).ok());
        result
    }
}

fn dedup_timeline_candidates(candidates: &mut Vec<TimelineCacheFile>) {
    let mut seen = HashSet::new();
    candidates.retain(|candidate| {
        let key = candidate
            .path
            .file_name()
            .map(|value| value.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|| candidate.path.display().to_string().to_ascii_lowercase());
        seen.insert(key)
    });
}

fn archive_timeline_candidates(
    candidates: &[TimelineCacheFile],
    archive_dir: &Path,
) -> (usize, Vec<String>) {
    let mut copied = 0;
    let mut errors = Vec::new();

    if let Err(err) = fs::create_dir_all(archive_dir) {
        errors.push(format!(
            "Unable to create MITRE archive at {}: {}",
            archive_dir.display(),
            err
        ));
        return (copied, errors);
    }

    for candidate in candidates {
        copied += copy_timeline_artifact(&candidate.path, archive_dir, &mut errors);

        let json_path = candidate.path.with_extension("json");
        if json_path.is_file() {
            copied += copy_timeline_artifact(&json_path, archive_dir, &mut errors);
        }
    }

    if let Err(err) = write_timeline_index(candidates, archive_dir) {
        errors.push(format!("Unable to write MITRE archive index: {err}"));
    }

    (copied, errors)
}

fn copy_timeline_artifact(source: &Path, archive_dir: &Path, errors: &mut Vec<String>) -> usize {
    let Some(file_name) = source.file_name() else {
        return 0;
    };
    let target = archive_dir.join(file_name);

    if same_path(source, &target) {
        return 0;
    }

    match fs::copy(source, &target) {
        Ok(_) => 1,
        Err(err) => {
            errors.push(format!(
                "Unable to archive {} to {}: {}",
                source.display(),
                target.display(),
                err
            ));
            0
        }
    }
}

fn write_timeline_index(
    candidates: &[TimelineCacheFile],
    archive_dir: &Path,
) -> Result<(), String> {
    let entries = candidates
        .iter()
        .take(MAX_OVERVIEW_TIMELINES)
        .map(|candidate| {
            json!({
                "file": candidate
                    .path
                    .file_name()
                    .map(|value| value.to_string_lossy().to_string())
                    .unwrap_or_default(),
                "source_path": candidate.path.display().to_string(),
                "modified_unix_ms": system_time_unix_ms(candidate.modified),
            })
        })
        .collect::<Vec<_>>();

    let index = json!({
        "archive_dir": archive_dir.display().to_string(),
        "updated_unix_ms": system_time_unix_ms(SystemTime::now()),
        "timelines": entries,
    });
    let rendered = serde_json::to_string_pretty(&index).map_err(|err| err.to_string())?;
    fs::write(archive_dir.join("timeline_index.json"), rendered).map_err(|err| err.to_string())
}

fn same_path(left: &Path, right: &Path) -> bool {
    normalize_path_for_compare(left) == normalize_path_for_compare(right)
}

fn normalize_path_for_compare(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn system_time_unix_ms(value: SystemTime) -> u128 {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn collect_timeline_files(dir: &Path, pid: &str, out: &mut Vec<TimelineCacheFile>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("html") {
            continue;
        }

        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };

        let matches = if pid.is_empty() {
            name.starts_with("latest_timeline_pid_")
                || name.starts_with("latest_timeline_gid_")
                || name.starts_with("attack_timeline_pid_")
        } else {
            name == format!("latest_timeline_pid_{}.html", pid)
                || name.starts_with(&format!("attack_timeline_pid_{}_", pid))
        };

        if !matches {
            continue;
        }

        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        out.push(TimelineCacheFile { path, modified });
    }
}

fn owlyshield_report_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
        dirs.push(
            PathBuf::from(program_data)
                .join("HydraDragonAntivirus")
                .join("Owlyshield")
                .join("threats"),
        );
    }

    if let Some(all_users) = std::env::var_os("ALLUSERSPROFILE") {
        dirs.push(
            PathBuf::from(all_users)
                .join("HydraDragonAntivirus")
                .join("Owlyshield")
                .join("threats"),
        );
    }

    dirs.push(PathBuf::from(
        r"C:\ProgramData\HydraDragonAntivirus\Owlyshield\threats",
    ));
    dirs.push(mitre_archive_dir());
    dirs.push(PathBuf::from("reports"));

    dirs.sort();
    dirs.dedup();
    dirs
}

fn mitre_archive_dir() -> PathBuf {
    let program_data = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));

    program_data
        .join("HydraDragonAntivirus")
        .join("Sanctum")
        .join("mitre_attack")
}

fn sanitize_pid(pid: &str) -> String {
    pid.chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<String>()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn empty_mitre_overview_html(cache: &TimelineCacheLoad) -> String {
    format!(
        r#"<section class="mitre-empty-state">
<h2>No MITRE ATT&amp;CK timelines archived yet</h2>
<p>Sanctum will persist Owlyshield attack timelines here when detections arrive:</p>
<code>{}</code>
</section>"#,
        html_escape(&cache.archive_dir.display().to_string())
    )
}

struct TimelineCacheLoad {
    html: Option<String>,
    found: usize,
    copied: usize,
    archive_dir: PathBuf,
    errors: Vec<String>,
}

struct TimelineCacheFile {
    path: PathBuf,
    modified: SystemTime,
}
