use std::ffi::c_char;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const CREATE_NO_WINDOW: u32 = 0x08000000;

static FIREWALL_CHILD: OnceLock<Mutex<Option<Child>>> = OnceLock::new();
static LAST_ERROR: OnceLock<Mutex<String>> = OnceLock::new();

fn firewall_child() -> &'static Mutex<Option<Child>> {
    FIREWALL_CHILD.get_or_init(|| Mutex::new(None))
}

fn last_error() -> &'static Mutex<String> {
    LAST_ERROR.get_or_init(|| Mutex::new(String::new()))
}

fn set_last_error(message: impl Into<String>) {
    *last_error().lock().unwrap() = message.into();
}

fn clear_last_error() {
    last_error().lock().unwrap().clear();
}

fn candidate_executable_paths() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(explicit_path) = std::env::var("HYDRADRAGON_FIREWALL_EXE") {
        candidates.push(PathBuf::from(explicit_path));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            candidates.push(exe_dir.join("hydradragonfirewall.exe"));

            let relative_candidates = [
                PathBuf::from(r"HydraDragonFirewall\hydradragonfirewall\target\release\hydradragonfirewall.exe"),
                PathBuf::from(r"HydraDragonFirewall\hydradragonfirewall\target\debug\hydradragonfirewall.exe"),
            ];

            for ancestor in exe_dir.ancestors() {
                for relative_path in &relative_candidates {
                    candidates.push(ancestor.join(relative_path));
                }
            }
        }
    }

    candidates.push(PathBuf::from("hydradragonfirewall.exe"));

    candidates
}

fn resolve_executable_path() -> Option<PathBuf> {
    candidate_executable_paths()
        .into_iter()
        .find(|path| path.is_file())
}

fn child_is_running(child: &mut Child) -> bool {
    matches!(child.try_wait(), Ok(None))
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_IsRunning() -> i32 {
    let mut slot = firewall_child().lock().unwrap();
    if let Some(child) = slot.as_mut() {
        if child_is_running(child) {
            return 1;
        }
    }

    *slot = None;
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_Start() -> i32 {
    {
        let mut slot = firewall_child().lock().unwrap();
        if let Some(child) = slot.as_mut() {
            if child_is_running(child) {
                clear_last_error();
                return 1;
            }
        }
        *slot = None;
    }

    let Some(executable_path) = resolve_executable_path() else {
        set_last_error("Unable to locate hydradragonfirewall.exe");
        return 0;
    };

    let working_directory = executable_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut command = Command::new(&executable_path);
    command
        .arg("--headless")
        .arg("--no-alert")
        .current_dir(&working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);

    match command.spawn() {
        Ok(mut child) => {
            std::thread::sleep(Duration::from_millis(500));
            match child.try_wait() {
                Ok(Some(status)) => {
                    set_last_error(format!(
                        "hydradragonfirewall.exe exited early with status {}",
                        status
                    ));
                    0
                }
                Ok(None) => {
                    *firewall_child().lock().unwrap() = Some(child);
                    clear_last_error();
                    1
                }
                Err(error) => {
                    set_last_error(format!(
                        "Failed to query hydradragonfirewall.exe status: {}",
                        error
                    ));
                    0
                }
            }
        }
        Err(error) => {
            set_last_error(format!(
                "Failed to start hydradragonfirewall.exe from {}: {}",
                executable_path.display(),
                error
            ));
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_Stop() -> i32 {
    let mut slot = firewall_child().lock().unwrap();
    let Some(mut child) = slot.take() else {
        clear_last_error();
        return 1;
    };

    match child.try_wait() {
        Ok(Some(_)) => {
            clear_last_error();
            1
        }
        Ok(None) => match child.kill() {
            Ok(()) => {
                let _ = child.wait();
                clear_last_error();
                1
            }
            Err(error) => {
                set_last_error(format!("Failed to stop hydradragonfirewall.exe: {}", error));
                0
            }
        },
        Err(error) => {
            set_last_error(format!(
                "Failed to query hydradragonfirewall.exe state during shutdown: {}",
                error
            ));
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_GetLastErrorMessage(
    buffer: *mut c_char,
    buffer_len: usize,
) -> usize {
    let message = last_error().lock().unwrap().clone();
    let bytes = message.as_bytes();

    if buffer.is_null() || buffer_len == 0 {
        return bytes.len();
    }

    let copy_len = bytes.len().min(buffer_len.saturating_sub(1));
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), copy_len);
        *buffer.add(copy_len) = 0;
    }

    copy_len
}
