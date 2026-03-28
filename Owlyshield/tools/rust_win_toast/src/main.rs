use std::{
    cmp::Ordering,
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration as SleepDuration,
};

use winrt_notification::{Duration, IconCrop, Sound, Toast};

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(target_os = "windows")]
fn has_brand_shortcut() -> bool {
    fn walk(dir: &Path) -> bool {
        let Ok(entries) = fs::read_dir(dir) else {
            return false;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if walk(&path) {
                    return true;
                }
                continue;
            }

            let is_shortcut = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("lnk"))
                .unwrap_or(false);
            if !is_shortcut {
                continue;
            }

            let lower_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if lower_name.contains("owlyshield") || lower_name.contains("hydradragon") {
                return true;
            }
        }

        false
    }

    let mut roots = Vec::<PathBuf>::new();
    if let Ok(program_data) = env::var("ProgramData") {
        roots.push(PathBuf::from(program_data).join("Microsoft\\Windows\\Start Menu\\Programs"));
    }
    if let Ok(app_data) = env::var("APPDATA") {
        roots.push(PathBuf::from(app_data).join("Microsoft\\Windows\\Start Menu\\Programs"));
    }

    roots.iter().any(|root| root.exists() && walk(root))
}

#[cfg(not(target_os = "windows"))]
fn has_brand_shortcut() -> bool {
    false
}

fn resolve_toast_app_id(requested: &str) -> &str {
    let trimmed = requested.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case(Toast::POWERSHELL_APP_ID) {
        return Toast::POWERSHELL_APP_ID;
    }

    if has_brand_shortcut() {
        trimmed
    } else {
        Toast::POWERSHELL_APP_ID
    }
}

fn show_toast(app_id: &str, title: &str, text: &str, logo: Option<&str>) {
    let resolved_app_id = resolve_toast_app_id(app_id);
    let mut toast = Toast::new(resolved_app_id)
        .title(title)
        .text1(text)
        .sound(Some(Sound::SMS))
        .duration(Duration::Short);

    if let Some(logo_path) = logo.filter(|value| !value.trim().is_empty()) {
        let logo_path = Path::new(logo_path);
        if logo_path.exists() {
            toast = toast.icon(logo_path, IconCrop::Square, "");
        }
    }

    toast.show().expect("unable to toast");

    // Give Windows a brief moment to commit the toast before this helper exits.
    thread::sleep(SleepDuration::from_millis(750));
}

fn maybe_open_report_async(path: &str) {
    let lower = path.to_ascii_lowercase();
    if !(lower.ends_with(".html") || lower.ends_with(".txt") || lower.ends_with(".log")) {
        return;
    }

    if path.trim().is_empty() || !Path::new(path).exists() {
        return;
    }

    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("cmd")
            .args(["/C", "start", "", path])
            .spawn();
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("xdg-open").arg(path).spawn();
    }
}

fn main() {
    let arguments: Vec<String> = env::args().map(|s| unquote(&s)).collect();
    match arguments.len().cmp(&3) {
        Ordering::Equal => {
            show_toast(Toast::POWERSHELL_APP_ID, &arguments[1], &arguments[2], None);
        }
        Ordering::Greater => {
            let title = &arguments[1];
            let text = &arguments[2];
            let logo = if arguments.len() > 3 && !arguments[3].is_empty() {
                Some(arguments[3].as_str())
            } else {
                None
            };
            let app = if arguments.len() > 4 && !arguments[4].is_empty() {
                arguments[4].as_str()
            } else {
                Toast::POWERSHELL_APP_ID
            };
            let log = &arguments[arguments.len() - 1];

            show_toast(app, title, text, logo);
            maybe_open_report_async(log);
        }
        Ordering::Less => {
            eprintln!("bad number of args");
        }
    }
}
