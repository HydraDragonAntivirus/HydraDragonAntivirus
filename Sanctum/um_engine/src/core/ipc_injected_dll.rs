//! The Sanctum EDR DLL which is injected into processes needs a way to communicate
//! with the engine, and this module provides the functionality for this.

use serde_json::from_slice;
use shared_no_std::ghost_hunting::{DLLMessage, Syscall};
use shared_std::{constants::PIPE_FOR_INJECTED_DLL, security::create_security_attributes};
use std::{
    os::windows::io::{AsHandle, AsRawHandle},
    sync::Arc,
};
use tokio::{
    io::AsyncReadExt,
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    sync::mpsc::Sender,
};
use windows::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeClientProcessId};

use crate::{
    driver_manager::SanctumDriverManager,
    utils::log::{Log, LogLevel},
};
use anyhow::{Result, bail};

/// Starts the IPC server for the DLL injected into processes to communicate with
pub async fn run_ipc_for_injected_dll(tx: Sender<Syscall>) {
    // Store the pointer in the atomic so we can safely access it across
    let mut sec_attr = create_security_attributes();

    // SAFETY: Null pointer checked at start of function
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(
                PIPE_FOR_INJECTED_DLL,
                &mut sec_attr as *mut _ as *mut _,
            )
            .expect("[-] Unable to create named pipe server for injected DLL")
    };

    let tx_arc = Arc::new(tx);

    let _ = tokio::spawn(async move {
        loop {
            let logger = Log::new();
            // wait for a connection
            server
                .connect()
                .await
                .expect("Could not get a client connection for injected DLL ipc");
            let mut connected_client = server;

            // Construct the next server before sending the one we have onto a task, which ensures
            // the server isn't closed
            let mut sec_attr = create_security_attributes();
            // SAFETY: null pointer checked above
            server = unsafe {
                ServerOptions::new()
                    .create_with_security_attributes_raw(
                        PIPE_FOR_INJECTED_DLL,
                        &mut sec_attr as *mut _ as *mut _,
                    )
                    .expect("Unable to create new version of IPC for injected DLL")
            };
            let tx_cl: Arc<Sender<Syscall>> = Arc::clone(&tx_arc);

            //
            // Read the IPC request, ensure we can actually read bytes from it (and that it casts as a Syscall type) - if so,
            // transmit the data via the mpsc to the core loop.
            //
            let _ = tokio::spawn(async move {
                let mut buffer = vec![0; 1024];
                match connected_client.read(&mut buffer).await {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            logger.log(LogLevel::Info, "IPC client disconnected");
                            return;
                        }

                        let s = String::from_utf8_lossy(&buffer);

                        // deserialise the request
                        match from_slice::<DLLMessage>(&buffer[..bytes_read]) {
                            Ok(message) => {
                                match message {
                                    DLLMessage::SyscallWrapper(syscall) => {
                                        if let Err(e) = get_pipe_pid(syscall.pid, &connected_client)
                                        {
                                            println!("{e}");
                                            return;
                                        }

                                        if let Err(e) = tx_cl.send(syscall).await {
                                            logger.log(LogLevel::Error, &format!("Error sending message from IPC msg from DLL. {e}"));
                                        }
                                    }
                                    DLLMessage::NtdllOverwrite => {
                                        // todo this needs handling
                                        println!("[i] NTDLL manipulation detected!");
                                    }
                                    DLLMessage::ProcessReadyForGhostHunting => {
                                        let mut m = SanctumDriverManager::new();
                                        let pid = get_pid_from_pipe(&connected_client)
                                            .expect("could not get pid");
                                        if let Err(e) = m.ioctl_notify_process_ready_for_gh(pid) {
                                            println!("Error notifying process for GH: {e}");
                                        }
                                    }
                                }
                            }
                            Err(e) => logger.log(
                                LogLevel::Error,
                                &format!("Error converting data to Syscall. {e}. Got: {s}"),
                            ),
                        }
                    }
                    Err(e) => {
                        logger.log(LogLevel::Error, &format!("Error reading IPC buffer. {e}"));
                    }
                }
            });
        }
    });
}

fn get_pipe_pid(syscall_pid: u32, connected_client: &NamedPipeServer) -> Result<u32> {
    //
    // As part of the Ghost Hunting technique, one way I have thought up to bypass this would be to spoof an
    // IPC from the malware saying you are performing an operation via a hooked syscall; when in actuality you are
    // using direct syscalls to evade detection etc.
    //
    // Therefore, in order to combat this we can enforce IPC messages to contain the HasPid trait, so that all inbound
    // IPC messages contain a pid. We can then compare the pid offered by the message, with the PID the pipe actually came
    // from to verify the message authenticity.
    //
    let pipe_pid = match get_pid_from_pipe(connected_client) {
        Some(p) => p,
        None => {
            // todo this is bad and should do something
            eprintln!("!!!!!!!!!!!!! GOT NO PID");
            todo!()
        }
    };
    if pipe_pid != syscall_pid {
        // todo this is bad and should do something
        bail!("!!!!!!!!!!! PIDS DONT MATCH!");
    }

    Ok(pipe_pid)
}

/// Gets the PID that sent the named pipe, to ensure the pid we receive the message from is the same as the
/// pid wrapped inside the message - prevents false messages being sent to the server where an attacker may wish
/// to use a raw syscall and spoof the pipe message.
///
/// # Returns
/// - The PID as a u32 if success
/// - Otherwise, None
fn get_pid_from_pipe(connected_client: &NamedPipeServer) -> Option<u32> {
    let handle = connected_client.as_handle().as_raw_handle();
    let mut pid: u32 = 0;

    if unsafe { GetNamedPipeClientProcessId(HANDLE(handle), &mut pid) }.is_err() {
        return None;
    }

    Some(pid)
}
