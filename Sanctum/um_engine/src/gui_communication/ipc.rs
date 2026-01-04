//! The inter-process communication module responsible for sending and receiving IPC requests from:
//! * Driver
//! * GUI
//! * DLLs
//!
//! This does not handle IOCTL's, that can be found in the driver_manager module.
//!
//! This IPC module is the main event loop for the application.

use std::{path::PathBuf, sync::Arc};

use crate::{
    core::core::Core,
    driver_manager::SanctumDriverManager,
    filescanner::FileScanner,
    settings::get_setting_paths,
    utils::{
        env::get_logged_in_username,
        log::{Log, LogLevel},
    },
};
use serde_json::{Value, from_slice, to_value, to_vec};
use shared_no_std::{
    constants::PIPE_NAME,
    ipc::{CommandRequest, CommandResponse},
};
use shared_std::settings::SanctumSettings;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::ServerOptions,
    sync::Mutex,
};

/// An interface for the usermode IPC server
pub struct UmIpc {}

impl UmIpc {
    pub async fn listen(
        settings: Arc<Mutex<SanctumSettings>>,
        core: Arc<Core>,
        file_scanner: Arc<FileScanner>,
        driver_manager: Arc<Mutex<SanctumDriverManager>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = Log::new();
        logger.log(
            LogLevel::Info,
            &format!("Trying to start IPC server at {}...", PIPE_NAME),
        );

        // set up IPC
        // todo default server type to Bytes and see if it causes an issue, if not - delete the commented out pipe_mode.
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            // .pipe_mode(PipeMode::Message)
            .create(PIPE_NAME)?;

        logger.log(
            LogLevel::Success,
            &format!("Named pipe listening on {}", PIPE_NAME),
        );

        loop {
            // create the next server instance before accepting the client connection, without this
            // there is a fraction of time where there will be no server listening
            let next_server = ServerOptions::new().create(PIPE_NAME)?;

            server.connect().await?;

            // move the current server instance to a client handler
            let mut client = server;
            server = next_server;

            let settings_clone = Arc::clone(&settings);
            let core_clone = Arc::clone(&core);
            let scanner_clone = Arc::clone(&file_scanner);
            let drv_mgr_clone = Arc::clone(&driver_manager);

            tokio::spawn(async move {
                let mut buffer = vec![0; 1024];
                let logger = Log::new();

                // read the request
                match client.read(&mut buffer).await {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            logger.log(LogLevel::Info, "IPC client disconnected");
                            return;
                        }

                        // deserialise the request
                        match from_slice::<CommandRequest>(&buffer[..bytes_read]) {
                            Ok(request) => {
                                //
                                // Handle the incoming IPC request here
                                //
                                if let Some(response) = handle_ipc(
                                    request,
                                    settings_clone,
                                    core_clone,
                                    scanner_clone,
                                    drv_mgr_clone,
                                )
                                .await
                                {
                                    //
                                    // Serialise and send the response back to the client
                                    //
                                    match to_vec(&response) {
                                        Ok(response_bytes) => {
                                            if let Err(e) = client.write_all(&response_bytes).await
                                            {
                                                logger.log(LogLevel::Error, &format!("[-] Failed to send response to client via pipe: {}", e));
                                            }
                                        }
                                        // err serialising to vec
                                        Err(e) => logger.log(
                                            LogLevel::Error,
                                            &format!("[-] Failed to serialise response: {}", e),
                                        ),
                                    };
                                };
                            }
                            // err serialising into CommandRequest
                            Err(e) => logger.log(
                                LogLevel::Error,
                                &format!(
                                    "Failed to deserialise request: {:?}. Err: {}. Bytes read: {}",
                                    &buffer[..bytes_read],
                                    e,
                                    bytes_read
                                ),
                            ),
                        }
                    }
                    // err reading IPC
                    Err(e) => logger.log(
                        LogLevel::Error,
                        &format!("Failed to read from client: {}", e),
                    ),
                }
            });
        }
    }
}

/// IPC logic handler, this function accepts a request and an Arc of UmEngine which matches on a
/// string based command to decide on what to do, this is considered the heart of the tasking of the
/// engine where its come from the GUI, or even other sources which may feed in via IPC (such as injected
/// DLL's)
///
/// # Args
///
/// * 'request' - The CommandRequest type which will be matched on and logic will be executed accordingly.
/// * 'engine_clone' - An Arc of the UmEngine
///
/// # Returns
///
/// None if there is to be no response to the IPC - will usually be the case in respect of the driver sending a message.
/// As the IPC channel is a 'one shot' from the driver implemented natively, the pipe will be closed on receipt in this function.
/// In the case of a Tokio IPC pipe, a response can be sent, in which case, it will be serialised to a Value and sent wrapped in a Some.
pub async fn handle_ipc(
    request: CommandRequest,
    settings: Arc<Mutex<SanctumSettings>>,
    core: Arc<Core>,
    file_scanner: Arc<FileScanner>,
    driver_manager: Arc<Mutex<SanctumDriverManager>>,
) -> Option<Value> {
    let response: Value = match request.command.as_str() {
        //
        // Scanner IPC requests
        //
        "scanner_check_page_state" => to_value(file_scanner.get_state()).unwrap(),
        "scanner_get_scan_stats" => to_value(file_scanner.scanner_get_scan_data()).unwrap(),
        "scanner_cancel_scan" => {
            file_scanner.cancel_scan();
            to_value("").unwrap()
        }
        "scanner_start_folder_scan" => {
            if let Some(args) = request.args {
                let target: Vec<PathBuf> = serde_json::from_value(args).unwrap();
                to_value(file_scanner.start_scan(target)).unwrap()
            } else {
                to_value(CommandResponse {
                    status: "error".to_string(),
                    message: "No path passed to scanner".to_string(),
                })
                .unwrap()
            }
        }
        "settings_get_common_scan_areas" => to_value({
            let lock = settings.lock().await;
            lock.common_scan_areas.clone()
        })
        .unwrap(),

        //
        // Settings control page
        //
        "settings_load_page_state" => {
            let res = settings.lock().await.clone();
            to_value(res).unwrap()
        }
        "settings_update_settings" => {
            if let Some(args) = request.args {
                let settings_local: SanctumSettings = serde_json::from_value(args).unwrap();

                {
                    // change the live state
                    let mut lock = settings.lock().await;
                    *lock = settings_local.clone();
                }

                // write the new file
                let settings_str = serde_json::to_string(&settings_local).unwrap();
                let path = get_setting_paths(&get_logged_in_username().unwrap()).1;
                let res = fs::write(path, settings_str).await;
                match res {
                    Ok(_) => to_value("").unwrap(),
                    Err(e) => to_value(CommandResponse {
                        status: "error".to_string(),
                        message: format!("Error saving settings. {}", e),
                    })
                    .unwrap(),
                }
            } else {
                to_value(CommandResponse {
                    status: "error".to_string(),
                    message: "No path passed to scanner".to_string(),
                })
                .unwrap()
            }
        }

        //
        // Driver control from GUI
        //
        "driver_install_driver" => to_value({
            let mut lock = driver_manager.lock().await;
            lock.install_driver();
            lock.get_state()
        })
        .unwrap(),
        "driver_uninstall_driver" => to_value({
            let mut lock = driver_manager.lock().await;
            lock.uninstall_driver();
            lock.get_state()
        })
        .unwrap(),
        "driver_start_driver" => to_value({
            let mut lock = driver_manager.lock().await;
            lock.start_driver();
            lock.get_state()
        })
        .unwrap(),
        "driver_stop_driver" => to_value({
            let mut lock = driver_manager.lock().await;
            lock.stop_driver();
            lock.get_state()
        })
        .unwrap(),
        "driver_get_state" => to_value({
            let lock = driver_manager.lock().await;
            lock.get_state()
        })
        .unwrap(),

        //
        // Processes page in driver
        //
        "process_query_pid" => {
            return Some(
                to_value(CommandResponse {
                    status: "error".to_string(),
                    message: "Invalid PID received".to_string(),
                })
                .unwrap(),
            );

            // if let Some(args) = request.args {
            //     let pid: String = serde_json::from_value(args).unwrap();
            //     let pid = pid.parse::<u64>();

            //     // if the pid is a valid u64 proceed to query the pid
            //     if let Ok(pid) = pid {
            //         let res = core.query_process_by_pid(pid).await;
            //         if res.is_none() {
            //             to_value(CommandResponse {
            //                 status: "error".to_string(),
            //                 message: format!("Could not find process from pid: {pid}."),
            //             })
            //             .unwrap()
            //         } else {
            //             to_value(CommandResponse {
            //                 status: "success".to_string(),
            //                 message: format!("{:?}", res.unwrap()),
            //             })
            //             .unwrap()
            //         }

            //     // if pid was NaN
            //     } else {
            //         to_value(CommandResponse {
            //             status: "error".to_string(),
            //             message: "Invalid PID received".to_string(),
            //         })
            //         .unwrap()
            //     }
            // } else {
            //     to_value(CommandResponse {
            //         status: "error".to_string(),
            //         message: "No pid received".to_string(),
            //     })
            //     .unwrap()
            // }
        }

        //
        // IOCTL / IPC from driver
        // **NOTE** Do NOT use this for future work; any driver comms should take place in the core module. This is here
        // as a demonstration incase I want to do it again in the future for some weird edge case.
        //
        "ioctl_ping_driver" => to_value({
            let mut lock = driver_manager.lock().await;
            lock.ioctl_ping_driver()
        })
        .unwrap(),
        "driver_collect_knl_dbg_msg" => {
            to_value({ core.get_cached_driver_messages().await }).unwrap()
        }

        //
        // Unhandled requests
        //
        _ => to_value(CommandResponse {
            status: "error".to_string(),
            message: "Unknown command".to_string(),
        })
        .unwrap(),
    };

    Some(response)
}
