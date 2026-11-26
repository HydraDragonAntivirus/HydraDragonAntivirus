//! Inter-process communication module for the PPL Service to talk to the engine.

use std::{
    fs::OpenOptions,
    io::Write,
    sync::{
        OnceLock,
        mpsc::{SyncSender, sync_channel},
    },
    time::Duration,
};

use serde_json::to_vec;
use shared_no_std::ghost_hunting::Syscall;
use shared_std::constants::{PIPE_FOR_ETW, PIPE_SANCTUM_TELEMETRY};

static TELEMETRY_PIPE_TX: OnceLock<SyncSender<String>> = OnceLock::new();

fn telemetry_pipe_sender() -> &'static SyncSender<String> {
    TELEMETRY_PIPE_TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<String>(8192);
        let _ = std::thread::Builder::new()
            .name("sanctum-ppl-telemetry-ipc".into())
            .spawn(move || {
                while let Ok(mut line) = rx.recv() {
                    if !line.ends_with('\n') {
                        line.push('\n');
                    }
                    let mut sent = false;
                    while !sent {
                        match OpenOptions::new().write(true).open(PIPE_SANCTUM_TELEMETRY) {
                            Ok(mut client) => {
                                if client.write_all(line.as_bytes()).is_err() {
                                    std::thread::sleep(Duration::from_millis(250));
                                    continue;
                                }
                                sent = true;
                                while let Ok(mut next) = rx.try_recv() {
                                    if !next.ends_with('\n') {
                                        next.push('\n');
                                    }
                                    if client.write_all(next.as_bytes()).is_err() {
                                        line = next;
                                        sent = false;
                                        std::thread::sleep(Duration::from_millis(250));
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                std::thread::sleep(Duration::from_millis(500));
                                // Drop oldest queued item rather than blocking forever if pipe is absent
                                break;
                            }
                        }
                    }
                }
            });
        tx
    })
}

/// Queue a JSON telemetry line to OpenEDR (`\\.\pipe\SanctumTelemetry`) without blocking ETW callbacks.
pub fn send_telemetry_json_ipc(json_line: String) {
    let _ = telemetry_pipe_sender().try_send(json_line);
}

pub fn send_etw_info_ipc(data: Syscall) {
    // send information to the engine via IPC; do not use Tokio as we don't want the async runtime in our processes..
    // and it would not be FFI safe, so we will use the standard library to achieve this
    let mut client = match OpenOptions::new().read(true).write(true).open(PIPE_FOR_ETW) {
        Ok(client) => client,
        Err(_) => return, // Engine is likely not running or pipe is unavailable, just drop the event
    };

    if let Ok(message_data) = to_vec(&data) {
        let _ = client.write_all(&message_data); // ignore write errors instead of panicking
    }
}

/// Report an ETW blinding attempt to the GUI without attributing it to a specific PID.
/// This avoids false positives caused by guessing the wrong process from a recent-PID ring buffer.
/// The watchdog loop will automatically restart the trace session.
pub fn report_etw_blinding_attempt() {
    let payload = serde_json::json!({
        "sanctumEventType": "SANCTUM_ETW_BLINDING",
        "type": "SANCTUM_ETW_BLINDING",
        "pid": std::process::id(),
        "details": "ETW:TI trace session was interrupted and auto-revived by watchdog",
        "source": "sanctum_ppl_watchdog",
        "process": {
            "pid": std::process::id(),
            "imageFile": {
                "rawPath": "sanctum_ppl_runner.exe",
                "abstractPath": "sanctum_ppl_runner.exe"
            }
        }
    });
    if let Ok(line) = serde_json::to_string(&payload) {
        send_telemetry_json_ipc(line);
    }

    if let Ok(mut pipe) = OpenOptions::new()
        .write(true)
        .open(r"\\.\pipe\HydraHipEvent")
    {
        let msg = "THREAT_ALERT:ETW_Blinding_Attempt|ETW:TI trace session was interrupted and auto-revived by watchdog\n";
        let _ = pipe.write_all(msg.as_bytes());
        let _ = pipe.flush();
    }
}
