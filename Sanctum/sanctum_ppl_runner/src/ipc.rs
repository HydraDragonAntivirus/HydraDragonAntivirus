//! Inter-process communication module for the PPL Service to talk to the engine.

use std::{fs::OpenOptions, io::Write, thread::sleep, time::Duration};

use serde_json::to_vec;
use shared_no_std::ghost_hunting::Syscall;
use shared_std::constants::PIPE_FOR_ETW;
use windows::Win32::Foundation::ERROR_PIPE_BUSY;

pub fn send_etw_info_ipc(data: Syscall) {
    // send information to the engine via IPC; do not use Tokio as we don't want the async runtime in our processes..
    // and it would not be FFI safe, so we will use the standard library to achieve this
    let mut client = loop {
        match OpenOptions::new().read(true).write(true).open(PIPE_FOR_ETW) {
            Ok(client) => break client,
            // If the pipe is busy, try again after a wait
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as _) => (),
            Err(e) => panic!("An error occurred talking to the engine, {e}"), // todo is this acceptable?
        }

        sleep(Duration::from_millis(50));
    };

    let message_data = to_vec(&data).unwrap();
    if let Err(e) = client.write_all(&message_data) {
        panic!("Error writing to named pipe to UM Engine. {e}");
    };
}
