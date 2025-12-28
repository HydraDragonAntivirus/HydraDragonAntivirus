use std::{cmp::Ordering, env, path::Path, process::Command};

use winrt_notification::{Duration, IconCrop, Sound, Toast};

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn main() {
    // debug: print args
    for (i, a) in env::args().enumerate() {
        println!("arg[{}] = {}", i, a);
    }

    let arguments: Vec<String> = env::args().map(|s| unquote(&s)).collect();
    match arguments.len().cmp(&3) {
        Ordering::Equal => {
            // exe, title, text
            let title = &arguments[1];
            let text = &arguments[2];
            Toast::new(Toast::POWERSHELL_APP_ID)
                .title(title)
                .text1(text)
                .sound(Some(Sound::SMS))
                .duration(Duration::Short)
                .show()
                .expect("unable to toast");
        }
        Ordering::Greater => {
            // exe title text [logo?] [app_id?] log
            let title = &arguments[1];
            let text = &arguments[2];

            // logo is at arguments[3] if present
            let logo = if arguments.len() > 3 && !arguments[3].is_empty() {
                &arguments[3]
            } else {
                ""
            };

            // app id is at arguments[4] if present
            let app = if arguments.len() > 4 && !arguments[4].is_empty() {
                &arguments[4]
            } else {
                Toast::POWERSHELL_APP_ID
            };

            // last argument is expected to be the log/open target
            let log = &arguments[arguments.len() - 1];

            let mut t = Toast::new(app).title(title).text1(text).sound(Some(Sound::SMS)).duration(Duration::Short);

            if !logo.is_empty() {
                let logo_path = Path::new(logo);
                if logo_path.exists() {
                    t = t.icon(logo_path, IconCrop::Square, "");
                } else {
                    eprintln!("logo path does not exist: {}", logo);
                }
            }

            t.show().expect("unable to toast");

            // Open the log if it's a known file type (spawn and don't block)
            if log.ends_with(".html") || log.ends_with(".txt") || log.ends_with(".log") {
                if cfg!(target_os = "windows") {
                    // spawn via cmd /C to let Windows choose associated app
                    if let Err(e) = Command::new("cmd").arg("/C").arg(log).spawn() {
                        eprintln!("failed to open log via cmd: {}", e);
                    }
                } else {
                    if let Err(e) = Command::new("sh").arg("-c").arg(log).spawn() {
                        eprintln!("failed to open log via sh: {}", e);
                    }
                }
            }
        }
        Ordering::Less => {
            eprintln!("bad number of args");
        }
    }
}
