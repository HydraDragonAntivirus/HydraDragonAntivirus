//! Post-detection remediation actions for file deletion, text patching,
//! registry cleanup and external command execution.
//!
//! By default (`apply: false`) remediation runs in dry-run mode and only reports
//! what would be modified. Destructive actions require `apply: true` (`--remediate --yes`),
//! and arbitrary shell/process execution (`command`) additionally requires
//! `allow_commands: true` (`--remediate-allow-commands`).

use crate::rules::glob::{glob_match, has_glob_wildcards};
use crate::rules::system_windows::expand_windows_vars;
use crate::rules::types::Rule;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One declarative remediation step attached to a [`Rule`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Remediation {
    /// Delete a file (or directory). When `path` is omitted, deletes the
    /// scanned file that triggered the rule.
    FileDelete {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// Remove every line matching `pattern` (case-insensitive substring or
    /// glob) from `path`.
    TextDeleteLine {
        path: String,
        pattern: String,
    },
    /// Replace `pattern` (substring or line glob) with `replacement` in `path`.
    TextReplace {
        path: String,
        pattern: String,
        #[serde(default)]
        replacement: String,
    },
    /// Strip every occurrence of `pattern` from `path`.
    TextDeleteString {
        path: String,
        pattern: String,
    },
    /// Delete a single registry value under `key` (`reg.exe DELETE <key> /v <value> /f`).
    RegistryDeleteValue {
        key: String,
        value: String,
    },
    /// Delete an entire registry key (`reg.exe DELETE <key> /f`).
    RegistryDeleteKey {
        key: String,
    },
    /// Execute an external remediation command.
    /// Gated behind `--remediate-allow-commands`.
    Command {
        program: String,
        #[serde(default)]
        args: Vec<String>,
    },
}

/// Execution switches controlled by CLI flags (`--remediate`, `--yes`, `--remediate-allow-commands`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemediationOptions {
    /// When false, log/report planned actions without modifying the system.
    pub apply: bool,
    /// Permit `type: command` steps when `apply` is also true.
    pub allow_commands: bool,
}

/// Result of one remediation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationOutcome {
    pub rule_id: String,
    pub action: String,
    pub applied: bool,
    pub success: bool,
    pub detail: String,
}

/// Pure text helper for `text_delete_line`: removes lines matching `pattern`
/// (case-insensitive substring or glob). Preserves LF / CRLF line endings.
pub fn delete_lines_matching(text: &str, pattern: &str) -> (String, usize) {
    if pattern.is_empty() {
        return (text.to_string(), 0);
    }
    let crlf = text.contains("\r\n");
    let sep = if crlf { "\r\n" } else { "\n" };
    let trailing_newline = text.ends_with('\n');
    let pat_lower = pattern.to_ascii_lowercase();
    let is_glob = has_glob_wildcards(pattern);

    let mut kept = Vec::new();
    let mut removed = 0usize;
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        let hit = if is_glob {
            glob_match(pattern, line) || glob_match(&format!("*{pattern}*"), line)
        } else {
            line.to_ascii_lowercase().contains(&pat_lower)
        };
        if hit {
            removed += 1;
        } else {
            kept.push(line);
        }
    }
    if removed == 0 {
        return (text.to_string(), 0);
    }
    let mut out = kept.join(sep);
    if trailing_newline && !out.is_empty() {
        out.push_str(sep);
    }
    (out, removed)
}

/// Pure text helper for `text_replace`: replaces substring occurrences of
/// `pattern` (or whole lines matching `pattern` when `pattern` uses glob
/// wildcards) with `replacement`.
pub fn replace_in_text(text: &str, pattern: &str, replacement: &str) -> (String, usize) {
    if pattern.is_empty() {
        return (text.to_string(), 0);
    }
    if has_glob_wildcards(pattern) {
        let crlf = text.contains("\r\n");
        let sep = if crlf { "\r\n" } else { "\n" };
        let trailing_newline = text.ends_with('\n');
        let mut count = 0usize;
        let mut lines = Vec::new();
        for raw_line in text.lines() {
            let line = raw_line.trim_end_matches('\r');
            if glob_match(pattern, line) || glob_match(&format!("*{pattern}*"), line) {
                count += 1;
                lines.push(replacement.to_string());
            } else {
                lines.push(line.to_string());
            }
        }
        if count == 0 {
            return (text.to_string(), 0);
        }
        let mut out = lines.join(sep);
        if trailing_newline && !out.is_empty() {
            out.push_str(sep);
        }
        return (out, count);
    }
    let count = text.matches(pattern).count();
    if count > 0 {
        return (text.replace(pattern, replacement), count);
    }
    // Case-insensitive fallback if exact case wasn't found.
    let lower_text = text.to_ascii_lowercase();
    let lower_pat = pattern.to_ascii_lowercase();
    if lower_text.len() == text.len() && lower_text.contains(&lower_pat) {
        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        let mut hits = 0usize;
        for (idx, _) in lower_text.match_indices(&lower_pat) {
            out.push_str(&text[last..idx]);
            out.push_str(replacement);
            last = idx + pattern.len();
            hits += 1;
        }
        out.push_str(&text[last..]);
        return (out, hits);
    }
    (text.to_string(), 0)
}

/// Pure text helper for `text_delete_string`.
pub fn delete_string_in_text(text: &str, pattern: &str) -> (String, usize) {
    replace_in_text(text, pattern, "")
}

/// Expand `%VAR%` and resolve any glob components to concrete existing paths.
/// When no glob wildcards are present, returns the single expanded path.
pub fn resolve_target_paths(spec: &str) -> Vec<PathBuf> {
    let expanded = expand_windows_vars(spec);
    if !has_glob_wildcards(&expanded) {
        return vec![PathBuf::from(expanded)];
    }
    let normalized = expanded.replace('/', "\\");
    let mut parts = normalized.split('\\').peekable();
    let mut frontier: Vec<PathBuf> = Vec::new();
    if let Some(first) = parts.peek() {
        if first.ends_with(':') {
            let drive = format!("{}\\", parts.next().unwrap());
            frontier.push(PathBuf::from(drive));
        } else if first.is_empty() {
            frontier.push(PathBuf::from("\\"));
            parts.next();
        } else {
            frontier.push(PathBuf::from("."));
        }
    }
    for comp in parts {
        if comp.is_empty() {
            continue;
        }
        let mut next = Vec::new();
        if has_glob_wildcards(comp) {
            for base in &frontier {
                let Ok(entries) = std::fs::read_dir(base) else { continue };
                for entry in entries.flatten().take(256) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if glob_match(comp, &name) {
                        next.push(entry.path());
                    }
                }
            }
        } else {
            for base in &frontier {
                let candidate = base.join(comp);
                if candidate.exists() {
                    next.push(candidate);
                }
            }
        }
        frontier = next;
        if frontier.len() > 64 {
            frontier.truncate(64);
        }
        if frontier.is_empty() {
            break;
        }
    }
    frontier
}

/// Execute all remediation steps of `rule`.
pub fn run_rule_remediations(
    rule: &Rule,
    scanned_path: Option<&Path>,
    opts: RemediationOptions,
) -> Vec<RemediationOutcome> {
    rule.remediation
        .iter()
        .map(|step| run_remediation(&rule.id, step, scanned_path, opts))
        .collect()
}

/// Execute a single remediation step.
pub fn run_remediation(
    rule_id: &str,
    step: &Remediation,
    scanned_path: Option<&Path>,
    opts: RemediationOptions,
) -> RemediationOutcome {
    match step {
        Remediation::FileDelete { path } => {
            let targets: Vec<PathBuf> = match path.as_deref().filter(|s| !s.trim().is_empty()) {
                Some(spec) => resolve_target_paths(spec),
                None => scanned_path.map(|p| vec![p.to_path_buf()]).unwrap_or_default(),
            };
            if targets.is_empty() {
                return RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: "file_delete".into(),
                    applied: false,
                    success: false,
                    detail: "no target path resolved for file_delete".into(),
                };
            }
            if !opts.apply {
                let list: Vec<String> = targets.iter().map(|p| p.display().to_string()).collect();
                return RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: "file_delete".into(),
                    applied: false,
                    success: true,
                    detail: format!("dry-run: would delete {}", list.join(", ")),
                };
            }
            let mut deleted = Vec::new();
            let mut errors = Vec::new();
            for target in &targets {
                let res = if target.is_dir() {
                    std::fs::remove_dir_all(target)
                } else {
                    std::fs::remove_file(target)
                };
                match res {
                    Ok(()) => deleted.push(target.display().to_string()),
                    Err(e) => errors.push(format!("{}: {e}", target.display())),
                }
            }
            let success = errors.is_empty() && !deleted.is_empty();
            let detail = if errors.is_empty() {
                format!("deleted {}", deleted.join(", "))
            } else {
                format!("deleted [{}]; errors: {}", deleted.join(", "), errors.join("; "))
            };
            RemediationOutcome {
                rule_id: rule_id.to_string(),
                action: "file_delete".into(),
                applied: !deleted.is_empty(),
                success,
                detail,
            }
        }
        Remediation::TextDeleteLine { path, pattern } => {
            apply_text_op(rule_id, "text_delete_line", path, opts, |text| {
                delete_lines_matching(text, pattern)
            })
        }
        Remediation::TextReplace {
            path,
            pattern,
            replacement,
        } => apply_text_op(rule_id, "text_replace", path, opts, |text| {
            replace_in_text(text, pattern, replacement)
        }),
        Remediation::TextDeleteString { path, pattern } => {
            apply_text_op(rule_id, "text_delete_string", path, opts, |text| {
                delete_string_in_text(text, pattern)
            })
        }
        Remediation::RegistryDeleteValue { key, value } => {
            let expanded_key = expand_windows_vars(key);
            if !opts.apply {
                return RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: "registry_delete_value".into(),
                    applied: false,
                    success: true,
                    detail: format!("dry-run: would delete registry value `{expanded_key}` `{value}`"),
                };
            }
            run_reg_delete(rule_id, "registry_delete_value", &expanded_key, Some(value))
        }
        Remediation::RegistryDeleteKey { key } => {
            let expanded_key = expand_windows_vars(key);
            if !opts.apply {
                return RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: "registry_delete_key".into(),
                    applied: false,
                    success: true,
                    detail: format!("dry-run: would delete registry key `{expanded_key}`"),
                };
            }
            run_reg_delete(rule_id, "registry_delete_key", &expanded_key, None)
        }
        Remediation::Command { program, args } => {
            let prog = expand_windows_vars(program);
            let expanded_args: Vec<String> = args.iter().map(|a| expand_windows_vars(a)).collect();
            if !opts.apply {
                return RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: "command".into(),
                    applied: false,
                    success: true,
                    detail: format!("dry-run: would run `{prog} {}`", expanded_args.join(" ")),
                };
            }
            if !opts.allow_commands {
                return RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: "command".into(),
                    applied: false,
                    success: false,
                    detail: format!(
                        "skipped command `{prog} {}` (pass --remediate-allow-commands to enable)",
                        expanded_args.join(" ")
                    ),
                };
            }
            match std::process::Command::new(&prog).args(&expanded_args).output() {
                Ok(out) => {
                    let ok = out.status.success();
                    RemediationOutcome {
                        rule_id: rule_id.to_string(),
                        action: "command".into(),
                        applied: true,
                        success: ok,
                        detail: format!("ran `{prog} {}` (status: {})", expanded_args.join(" "), out.status),
                    }
                }
                Err(e) => RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: "command".into(),
                    applied: false,
                    success: false,
                    detail: format!("failed to spawn `{prog}`: {e}"),
                },
            }
        }
    }
}

fn apply_text_op(
    rule_id: &str,
    action: &str,
    path_spec: &str,
    opts: RemediationOptions,
    transform: impl Fn(&str) -> (String, usize),
) -> RemediationOutcome {
    let targets = resolve_target_paths(path_spec);
    if !opts.apply {
        let names: Vec<String> = targets.iter().map(|p| p.display().to_string()).collect();
        return RemediationOutcome {
            rule_id: rule_id.to_string(),
            action: action.into(),
            applied: false,
            success: true,
            detail: format!("dry-run: would run {action} on {}", names.join(", ")),
        };
    }
    let mut total_hits = 0usize;
    let mut modified_files = Vec::new();
    let mut errors = Vec::new();
    for target in &targets {
        let content = match std::fs::read_to_string(target) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: {e}", target.display()));
                continue;
            }
        };
        let (updated, hits) = transform(&content);
        if hits > 0 {
            match std::fs::write(target, updated) {
                Ok(()) => {
                    total_hits += hits;
                    modified_files.push(format!("{} ({hits} change(s))", target.display()));
                }
                Err(e) => errors.push(format!("{}: {e}", target.display())),
            }
        }
    }
    let success = errors.is_empty();
    let detail = if !errors.is_empty() {
        format!(
            "{action}: modified [{}]; errors: {}",
            modified_files.join(", "),
            errors.join("; ")
        )
    } else if modified_files.is_empty() {
        format!("{action}: no matching text in {}", path_spec)
    } else {
        format!("{action}: updated {}", modified_files.join(", "))
    };
    RemediationOutcome {
        rule_id: rule_id.to_string(),
        action: action.into(),
        applied: total_hits > 0,
        success,
        detail,
    }
}

fn run_reg_delete(
    rule_id: &str,
    action: &str,
    key: &str,
    value: Option<&str>,
) -> RemediationOutcome {
    #[cfg(not(windows))]
    {
        let _ = (key, value);
        RemediationOutcome {
            rule_id: rule_id.to_string(),
            action: action.into(),
            applied: false,
            success: false,
            detail: format!("{action} is only supported on Windows"),
        }
    }
    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("reg.exe");
        cmd.arg("DELETE").arg(key);
        if let Some(val) = value {
            if val.is_empty() {
                cmd.arg("/ve");
            } else {
                cmd.arg("/v").arg(val);
            }
        }
        cmd.arg("/f");
        match cmd.output() {
            Ok(out) => {
                let ok = out.status.success();
                RemediationOutcome {
                    rule_id: rule_id.to_string(),
                    action: action.into(),
                    applied: ok,
                    success: ok,
                    detail: match value {
                        Some(v) => format!("reg.exe DELETE `{key}` /v `{v}` /f -> {}", out.status),
                        None => format!("reg.exe DELETE `{key}` /f -> {}", out.status),
                    },
                }
            }
            Err(e) => RemediationOutcome {
                rule_id: rule_id.to_string(),
                action: action.into(),
                applied: false,
                success: false,
                detail: format!("failed to run reg.exe: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_delete_line_removes_matching_lines() {
        let input = "127.0.0.1 localhost\n123.123.123.123 google.ge\n::1 localhost\n";
        let (out, removed) = delete_lines_matching(input, "123.123.123.123 google.ge");
        assert_eq!(removed, 1);
        assert_eq!(out, "127.0.0.1 localhost\n::1 localhost\n");
    }

    #[test]
    fn text_replace_and_delete_string() {
        let input = "user_pref(\"browser.startup.homepage\", \"http://evil.example/start\");\n";
        let (replaced, count) = replace_in_text(
            input,
            "http://evil.example/start",
            "https://example.org/restore",
        );
        assert_eq!(count, 1);
        assert!(replaced.contains("https://example.org/restore"));

        let (stripped, del_count) = delete_string_in_text(input, "http://evil.example/start");
        assert_eq!(del_count, 1);
        assert!(!stripped.contains("evil.example"));
    }
}
