use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};
use serde_json::{from_slice, to_value, to_vec};
use shared_no_std::{constants::PIPE_NAME, ghost_hunting::Syscall, ipc::CommandRequest};
use shared_std::{constants::PIPE_FOR_GUI, security::create_security_attributes};
use tauri_winrt_notification::{Duration, Sound, Toast};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, ServerOptions},
};

pub struct IpcClient;

impl IpcClient {
    /// Main mechanism for sending IPC requests to the usermode engine for the EDR. This function
    /// requires a turbofish generic which will be whatever the function on the other side of the IPC
    /// (aka the usermode EDR engine) returns.
    ///
    /// This contains the command in question as a String, and 'args' which is a generic JSON serialised "Value"
    /// from Serde which allows the struct to contain any number of arguments, serialised to / from a struct that
    /// is appropriate for the calling / receiving functions.
    ///
    /// # Sending function
    ///
    /// The first parameter in the turbofish is the return type.
    ///
    /// The sending function must encode data like so:
    ///
    /// ## No data to send:
    ///
    /// ```
    /// // where IPC is of type IpcClient as implemented in the GUI.
    /// IpcClient::send_ipc::<(), Option<Value>>("scanner_cancel_scan", None).await
    /// ```
    ///
    /// ## Data of type A to send:
    ///
    /// ```
    /// let path = to_value(vec![PathBuf::from(file_path)]).unwrap();
    /// IpcClient::send_ipc::<FileScannerState, _>("scanner_start_folder_scan", Some(path)).await
    /// ```
    ///
    /// # Returns
    ///
    /// This function will return:
    ///
    /// - Ok T: where T is the return type of the function run by the usermode engine.
    /// - Err: where the error relates to the reading / writing of the IPC, and NOT the function run
    ///   by the IPC server.
    pub async fn send_ipc<T, A>(command: &str, args: Option<A>) -> io::Result<T>
    where
        T: DeserializeOwned + Debug,
        A: Serialize,
    {
        let mut client = ClientOptions::new().open(PIPE_NAME)?;

        // where there are args, serialise, otherwise, set to none
        let args = args.map(|a| to_value(a).unwrap());

        let message = CommandRequest {
            command: command.to_string(),
            args,
        };

        let message_data = to_vec(&message)?;
        client.write_all(&message_data).await?;

        // read the response until EOF (when the server closes the pipe)
        let mut received_data = Vec::new();
        client.read_to_end(&mut received_data).await?;

        // Deserialize the received JSON data into a Message struct
        let response_message: T = serde_json::from_slice(&received_data)?;

        Ok(response_message)
    }
}

/// An IPC server for inbound notifications from the EDR where we aren't sending outbound polls.
pub async fn global_inbound_ipc() {
    let mut sec_attr = create_security_attributes();

    // SAFETY: Security attributes are properly initialized above
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(PIPE_FOR_GUI, &mut sec_attr as *mut _ as *mut _)
            .expect("[-] Unable to create named pipe server for GUI IPC receiver")
    };

    tokio::spawn(async move {
        loop {
            // wait for a connection
            match server.connect().await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[-] Failed to accept client connection for GUI IPC: {}", e);
                    continue;
                }
            }

            let mut connected_client = server;

            let mut sec_attr = create_security_attributes();

            // SAFETY: Security attributes are properly initialized above
            server = unsafe {
                ServerOptions::new()
                    .create_with_security_attributes_raw(
                        PIPE_FOR_GUI,
                        &mut sec_attr as *mut _ as *mut _,
                    )
                    .expect("[-] Unable to create new instance of IPC for GUI pipe listener")
            };

            // Process the inbound message in a separate task
            tokio::spawn(async move {
                let mut buffer = vec![0; 4096];
                match connected_client.read(&mut buffer).await {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            return;
                        }

                        // Deserialize the syscall event
                        match from_slice::<Syscall>(&buffer[..bytes_read]) {
                            Ok(syscall) => {
                                // Handle the syscall event - show notification to user
                                handle_syscall_notification(syscall);
                            }
                            Err(e) => {
                                eprintln!("[-] Failed to deserialize syscall event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] Failed to read from IPC pipe: {}", e);
                    }
                }
            });
        }
    });
}

/// Handle incoming syscall events by showing Windows notifications
fn handle_syscall_notification(syscall: Syscall) {
    let title = format!("Security Event Detected (PID: {})", syscall.pid);
    let message = format!("Event: {:?}", syscall.data);

    // Show Windows toast notification
    if let Err(e) = Toast::new(Toast::POWERSHELL_APP_ID)
        .title(&title)
        .text1(&message)
        .sound(Some(Sound::Default))
        .duration(Duration::Short)
        .show()
    {
        eprintln!("[-] Failed to show notification: {}", e);
    }
}
