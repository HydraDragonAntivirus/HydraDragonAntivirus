use std::{env, path::Path, process::Command};

use win_toast_notify::{Audio, CropCircle, Duration, Loop, WinToastNotify};

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
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

    // Contract (from notifications.rs):
    //   argv[1] = title
    //   argv[2] = message
    //   argv[3] = logo path (optional, may be empty)
    //   argv[4] = app id (optional, may be empty)
    //   argv[5] = report path (optional, may be empty)
    if arguments.len() < 3 {
        eprintln!("bad number of args");
        std::process::exit(1);
    }

    let title = &arguments[1];
    let text = &arguments[2];
    let logo = arguments
        .get(3)
        .filter(|value| !value.trim().is_empty())
        .map(String::as_str)
        .filter(|path| Path::new(path).exists());
    let app_id = arguments
        .get(4)
        .filter(|value| !value.trim().is_empty())
        .map(String::as_str);
    let report = arguments
        .get(5)
        .filter(|value| !value.trim().is_empty())
        .map(String::as_str)
        .filter(|path| Path::new(path).exists());

    let mut toast = WinToastNotify::new()
        .set_title(title)
        .set_messages(vec![text])
        .set_duration(Duration::Long)
        .set_audio(Audio::WinSMS, Loop::False);

    if let Some(app) = app_id {
        toast = toast.set_app_id(app);
    }

    if let Some(logo_path) = logo {
        toast = toast.set_logo(logo_path, CropCircle::False);
    }

    if let Some(report_path) = report {
        toast = toast.set_open(report_path);
    }

    match toast.show() {
        Ok(()) => {}
        Err(err) => eprintln!("unable to toast: {}", err),
    }

    // Give Windows a brief moment to commit the toast before this helper exits.
    std::thread::sleep(std::time::Duration::from_millis(750));

    if let Some(report_path) = report {
        maybe_open_report_async(report_path);
    }
}
