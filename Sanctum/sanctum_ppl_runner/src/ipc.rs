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


/// Report an ETW blinding attempt to the GUI without attributing it to a specific PID.
/// This avoids false positives caused by guessing the wrong process from a recent-PID ring buffer.
/// The watchdog loop will automatically restart the trace session.
pub fn report_etw_blinding_attempt() {
    if let Ok(mut pipe) = OpenOptions::new()
        .write(true)
        .open(r"\\.\pipe\HydraHipEvent")
    {
        let msg = "THREAT_ALERT:ETW_Blinding_Attempt|ETW:TI trace session was interrupted and auto-revived by watchdog\n";
        let _ = pipe.write_all(msg.as_bytes());
        let _ = pipe.flush();
    }
}
