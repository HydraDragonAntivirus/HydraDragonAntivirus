//! Inter-process communication module for the PPL Service to talk to the engine.

use std::{fs::OpenOptions, io::Write};

use serde_json::to_vec;
use shared_no_std::ghost_hunting::Syscall;
use shared_std::constants::PIPE_FOR_ETW;

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

/// Report ETW tamper / blinding attempt directly to OpenEDR's Ring-0 driver controller and GUI
pub fn report_tamper_attempt(pid: u32, exe_path: &str) {
    if pid == 0 || pid == 4 || pid == std::process::id() {
        return;
    }

    // 1. Send Ring-0 immediate kernel driver kill order to libsysmon (edrdrv.sys)
    if let Ok(mut pipe) = OpenOptions::new()
        .write(true)
        .open(r"\\.\pipe\HydraHipDecision")
    {
        let msg = format!("HIPS_KILL:{}|block|{}\n", pid, exe_path);
        let _ = pipe.write_all(msg.as_bytes());
        let _ = pipe.flush();
    }

    // 2. Broadcast Threat Alert to Pascal GUI (edrgui.exe)
    if let Ok(mut pipe) = OpenOptions::new()
        .write(true)
        .open(r"\\.\pipe\HydraHipEvent")
    {
        let msg = format!("THREAT_ALERT:ETW_Blinding_Defense (Killed)|{}\n", exe_path);
        let _ = pipe.write_all(msg.as_bytes());
        let _ = pipe.flush();
    }
}
