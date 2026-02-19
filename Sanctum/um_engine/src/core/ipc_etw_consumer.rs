//! Consume IPC messages from the Events Tracing for Windows consumer.

use crate::{
    engine::PPL_SERVICE_PID,
    utils::log::{Log, LogLevel},
};
use serde_json::from_slice;
use shared_no_std::ghost_hunting::Syscall;
use shared_std::{constants::PIPE_FOR_ETW, security::create_security_attributes};
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

/// Starts the IPC server for the ETW running from PPL
pub async fn run_ipc_for_etw(tx: Sender<Syscall>) {
    // Store the pointer in the atomic so we can safely access it across
    let mut sec_attr = create_security_attributes();

    // SAFETY: Null pointer checked at start of function
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(PIPE_FOR_ETW, &mut sec_attr as *mut _ as *mut _)
            .expect("[-] Unable to create named pipe server for ETW receiver")
    };

    let tx_arc = Arc::new(tx);

    let _ = tokio::spawn(async move {
        loop {
            let logger = Log::new();
            // wait for a connection
            server
                .connect()
                .await
                .expect("Could not get a client connection for ETW ipc");
            let mut connected_client = server;

            let mut sec_attr = create_security_attributes();

            // SAFETY: null pointer checked above
            server = unsafe {
                ServerOptions::new()
                    .create_with_security_attributes_raw(
                        PIPE_FOR_ETW,
                        &mut sec_attr as *mut _ as *mut _,
                    )
                    .expect("Unable to create new version of IPC for ETW pipe listener")
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

                        // deserialise the request
                        match from_slice::<Syscall>(&buffer[..bytes_read]) {
                            Ok(etw_msg) => {
                                // check the PID of the transmission is our PPL service so we can detect tempering
                                let pipe_pid = match get_pid_from_pipe(&connected_client) {
                                    Some(p) => p,
                                    None => {
                                        // todo this is bad and should do something
                                        eprintln!("!!!!!!!!!!!!! GOT NO PID");
                                        todo!()
                                    }
                                };
                                // SAFETY: The PPL_SERVICE_PID is only initialised once mutably, so is safe to read.
                                if pipe_pid != unsafe { PPL_SERVICE_PID } {
                                    // todo this is bad and should do something
                                    eprintln!("!!!!!!!!!!! PIDS DONT MATCH!");
                                }

                                //
                                // Send the data via the channel to the engine
                                //
                                if let Err(e) = tx_cl.send(etw_msg).await {
                                    logger.log(
                                        LogLevel::Error,
                                        &format!(
                                            "Error sending message from IPC msg from ETW. {e}"
                                        ),
                                    );
                                }
                            }
                            Err(e) => logger.log(
                                LogLevel::Error,
                                &format!("Error converting data to Syscall. {e}"),
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
