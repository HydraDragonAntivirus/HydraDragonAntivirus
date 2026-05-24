//! Processes.rs contains all functions associated with the process page UI in Tauri.
//! This module will handle state, requests, async, and events.

use serde_json::json;
use shared_no_std::ipc::CommandResponse;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::ipc::IpcClient;

#[tauri::command]
pub async fn process_query_pid(pid: String) -> Result<String, ()> {
    let pid = pid.trim().to_string();
    let requested_pid = pid.clone();

    if let Some(timeline) = load_owlyshield_timeline_cache(&pid) {
        return Ok(json!({
            "status": "success",
            "source": "owlyshield_cache",
            "message": if pid.is_empty() {
                "Loaded latest Owlyshield attack timelines"
            } else {
                "Loaded latest Owlyshield attack timeline"
            },
            "timeline": timeline,
        })
        .to_string());
    }

    match IpcClient::send_ipc::<CommandResponse, String>("process_query_pid", Some(pid)).await {
        Ok(response) => {
            let mut value = serde_json::to_value(&response).unwrap_or_else(|_| {
                json!({
                    "status": "error",
                    "message": "Failed to serialize process query response"
                })
            });

            if value.get("timeline").is_none() {
                if let Some(timeline) = load_owlyshield_timeline_cache(&requested_pid) {
                    value["timeline"] = json!(timeline);
                    value["source"] = json!("owlyshield_cache");
                }
            }

            Ok(value.to_string())
        }
        Err(e) => {
            eprintln!("[-] Error with IPC: {e}");
            let fallback = load_owlyshield_timeline_cache(&requested_pid).unwrap_or_else(|| {
                format!(
                    "<pre>IPC error: {}\nNo Owlyshield attack timeline cache was found.</pre>",
                    html_escape(&e.to_string())
                )
            });
            Ok(json!({
                "status": "error",
                "source": "owlyshield_cache",
                "message": format!("IPC error: {e}"),
                "timeline": fallback,
            })
            .to_string())
        }
    }
}

fn load_owlyshield_timeline_cache(pid: &str) -> Option<String> {
    let pid = sanitize_pid(pid);
    let mut candidates = Vec::new();

    for dir in owlyshield_report_dirs() {
        if !dir.is_dir() {
            continue;
        }

        collect_timeline_files(&dir, &pid, &mut candidates);
    }

    candidates.sort_by(|a, b| b.modified.cmp(&a.modified));

    if pid.is_empty() {
        let mut fragments = Vec::new();
        for candidate in candidates.into_iter().take(20) {
            if let Ok(html) = fs::read_to_string(&candidate.path) {
                fragments.push(format!(
                    "<section class=\"owlyshield-cache-entry\"><div class=\"cache-source\">{}</div>{}</section>",
                    html_escape(&candidate.path.display().to_string()),
                    html
                ));
            }
        }
        if fragments.is_empty() {
            None
        } else {
            Some(fragments.join("<hr class=\"cache-separator\"/>"))
        }
    } else {
        candidates
            .into_iter()
            .find_map(|candidate| fs::read_to_string(candidate.path).ok())
    }
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
    dirs.push(PathBuf::from("reports"));

    dirs.sort();
    dirs.dedup();
    dirs
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

struct TimelineCacheFile {
    path: PathBuf,
    modified: SystemTime,
}
