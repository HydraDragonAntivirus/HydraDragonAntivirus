use std::{
    cmp::Ordering, env, path::Path, process::Command, thread, time::Duration as SleepDuration,
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

fn resolve_toast_app_id(requested: &str) -> &str {
    let trimmed = requested.trim();
    if trimmed.is_empty() {
        Toast::POWERSHELL_APP_ID
    } else {
        trimmed
    }
}

fn show_toast(app_id: &str, title: &str, text: &str, logo: Option<&str>) {
    let requested_app_id = resolve_toast_app_id(app_id).to_string();
    let logo_path = logo
        .filter(|value| !value.trim().is_empty())
        .map(Path::new)
        .filter(|path| path.exists());

    let show_with = |active_app_id: &str| {
        let mut toast = Toast::new(active_app_id)
            .title(title)
            .text1(text)
            .sound(Some(Sound::SMS))
            .duration(Duration::Short);

        if let Some(path) = logo_path {
            toast = toast.icon(path, IconCrop::Square, "");
        }

        toast.show()
    };

    if let Err(err) = show_with(&requested_app_id) {
        if !requested_app_id.eq_ignore_ascii_case(Toast::POWERSHELL_APP_ID) {
            eprintln!(
                "failed to show branded toast with app id '{}': {}. falling back to powershell app id",
                requested_app_id,
                err
            );
            if let Err(fallback_err) = show_with(Toast::POWERSHELL_APP_ID) {
                eprintln!(
                    "failed to show fallback toast with powershell app id: {}",
                    fallback_err
                );
            }
        } else {
            eprintln!("unable to toast: {}", err);
        }
    }

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
        let _ = Command::new("cmd").args(["/C", "start", "", path]).spawn();
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
