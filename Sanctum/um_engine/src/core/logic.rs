use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use crate::{
    core::process_monitor::inject_edr_dll,
    driver_manager::manager::SanctumDriverManager,
    utils::log::{Log, LogLevel},
};

use super::ipc_etw_consumer::run_ipc_for_etw;
use super::ipc_injected_dll::run_ipc_for_injected_dll;
use serde_json::to_vec;
use shared_no_std::ghost_hunting::NtFunction;
use shared_std::constants::PIPE_SANCTUM_TELEMETRY;
use tokio::net::windows::named_pipe::ServerOptions;

/// Forward a Syscall event to the OpenEDR behavior engine.
fn forward_to_owlyshield(syscall: &shared_no_std::ghost_hunting::Syscall, pipe_tx: &tokio::sync::mpsc::Sender<String>) {
    if let Ok(json) = serde_json::to_string(syscall) {
        let _ = pipe_tx.try_send(json + "\n");
    }
}

/// Forward an AMSI bypass attempt.
fn forward_amsi_bypass_to_owlyshield(attempt: &shared_no_std::driver_ipc::AmsiBypassAttempt, pipe_tx: &tokio::sync::mpsc::Sender<String>) {
    if let Ok(json) = serde_json::to_string(attempt) {
        let _ = pipe_tx.try_send(json + "\n");
    }
}

/// Forward a Ghost Hunting detection (direct/indirect syscall abuse).
fn forward_ghost_hunt_to_owlyshield(hunt: &shared_no_std::driver_ipc::GhostHunt, pipe_tx: &tokio::sync::mpsc::Sender<String>) {
    if let Ok(json) = serde_json::to_string(hunt) {
        let _ = pipe_tx.try_send(json + "\n");
    }
}

fn source_name(source: shared_no_std::ghost_hunting::SyscallEventSource) -> &'static str {
    match source {
        shared_no_std::ghost_hunting::SyscallEventSource::EventSourceKernel => "kernel",
        shared_no_std::ghost_hunting::SyscallEventSource::EventSourceSyscallHook => "syscall_hook",
    }
}

/// The core struct contains information on the core of the usermode engine where decisions are being made, and directly communicates
/// with the kernel.
///
/// Note, this module no longer does `Ghost Hunting`, this is done by the driver.
///
/// # Components
///
/// - `driver_poll_rate`: the poll rate in milliseconds that the kernel will be (approximately) queried. The
///   approximation is because the polling / decision making loop is not asynchronous and other decision making
///   takes place prior to the poll rate sleep time.
/// - `driver_dbg_message_cache`: a temporary cache of messages which are returned from the kernel which the
///   GUI can request.
#[derive(Debug, Default)]
pub struct Core {
    _driver_poll_rate: u64,
    driver_dbg_message_cache: Mutex<Vec<String>>,
    // process_monitor: RwLock<ProcessMonitor>,
}

impl Core {
    /// Initialises a new Core instance from a poll rate in **milliseconds**.
    pub fn from(poll_rate: u64) -> Self {
        Core {
            _driver_poll_rate: poll_rate,
            ..Default::default()
        }
    }

    /// Starts the core of the usermode engine; kicking off the frequent polling of the driver, and conducts relevant decision making
    pub async fn start_core(&self, driver_manager: Arc<Mutex<SanctumDriverManager>>) -> ! {
        let logger = Log::new();

        //
        // To start with, we will snapshot all running processes and then add them to the active processes.
        // there is possible a short time window where processes are created / terminated, which may cause
        // a zone of 'invisibility' at this point in time, but this should be fixed in the future when
        // we receive handles / changes to processes, if they don't exist, they should be created then.
        // todo - marker for info re above.
        //
        // let snapshot_processes = snapshot_all_processes().await;

        // extend the newly created local processes type from the results of the snapshot
        // self.process_monitor
        //     .write()
        //     .await
        //     .extend_processes(snapshot_processes);

        let (pipe_tx, mut pipe_rx) = mpsc::channel::<String>(5000);
        tokio::spawn(async move {
            use tokio::net::windows::named_pipe::ClientOptions;
            use tokio::io::AsyncWriteExt;
            loop {
                match ClientOptions::new().open(PIPE_SANCTUM_TELEMETRY) {
                    Ok(mut client) => {
                        while let Some(msg) = pipe_rx.recv().await {
                            if client.write_all(msg.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
        });

        let (tx, mut rx) = mpsc::channel(1000);

        // Start the IPC server for the injected DLL to communicate with the core
        tokio::spawn(async {
            run_ipc_for_injected_dll(tx).await;
        });

        let (etw_tx, mut etw_rx) = mpsc::channel(1000);
        tokio::spawn(async {
            run_ipc_for_etw(etw_tx).await;
        });

        //
        // Enter the polling & decision making loop, this here is the core / engine of the usermode engine.
        // todo: we need to actually inspect what these params are doing and if they are malicious.
        //
        loop {
            if let Ok(syscall) = etw_rx.try_recv() {
                forward_to_owlyshield(&syscall, &pipe_tx);

                if let NtFunction::NetworkActivity(_) = &syscall.data {
                }

                if matches!(&syscall.data, NtFunction::EtwThreatIntelligence(_)) {
                    continue;
                }

                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_syscall_event(syscall);
            }

            // See if there is a message from the injected DLL
            if let Ok(syscall) = rx.try_recv() {
                // Forward to Owlyshield behavior engine before local processing.
                forward_to_owlyshield(&syscall, &pipe_tx);
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_syscall_event(syscall);
            }

            // contact the driver and get any messages from the kernel
            // todo needing to unlock the driver manager is an unnecessary bottleneck
            let driver_response = {
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_get_driver_messages()
            };

            let image_loads = {
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_get_image_loads_for_injecting_sanc_dll()
            };

            // If we have new message(s) / emissions from the driver or injected DLL, process them as appropriate
            if let Some(mut driver_messages) = driver_response {
                // cache messages
                {
                    let mut message_cache = self.driver_dbg_message_cache.lock().await;
                    if !driver_messages.messages.is_empty() {
                        message_cache.append(&mut driver_messages.messages);
                    }
                }

                // Forward AMSI bypass attempts to Owlyshield
                for attempt in &driver_messages.amsi_bypass_attempts {
                    forward_amsi_bypass_to_owlyshield(attempt, &pipe_tx);
                }

                // Forward Ghost Hunting (direct syscall) detections to Owlyshield
                for hunt in &driver_messages.ghost_hunts {
                    forward_ghost_hunt_to_owlyshield(hunt, &pipe_tx);
                }
            }

            if let Some(image_loads) = image_loads {
                for pid in image_loads {
                    // println!("[i] Target process detected, injecting EDR DLL into PID: {pid}...");
                    if let Err(e) = inject_edr_dll(pid as _) {
                        println!("[-] Error injecting Sanctum DLL: {e:?}");
                        logger.log(
                            LogLevel::Error,
                            &format!("Error injecting Sanctum DLL: {e:?}"),
                        );
                    }

                    // Also inject CAPEMON.DLL for Cuckoo behavioral tracing
                    if let Err(e) = crate::core::process_monitor::inject_capemon_dll(pid as _) {
                        println!("[-] Error injecting Capemon DLL: {e:?}");
                        logger.log(
                            LogLevel::Error,
                            &format!("Error injecting Capemon DLL: {e:?}"),
                        );

                        // Let the driver know we failed to inject
                        let mut mtx = driver_manager.lock().await;
                        mtx.ioctl_dll_inject_failed(pid as u32);
                    }

                    // Check if it's PowerShell to inject Exorcism
                    if let Some(path_str) = crate::utils::env::resolve_process_path(pid as u32) {
                        if let Some(file_name) = std::path::Path::new(&path_str).file_name() {
                            let file_name_lower = file_name.to_string_lossy().to_lowercase();
                            if file_name_lower == "powershell.exe" || file_name_lower == "pwsh.exe"
                            {
                                if let Err(e) =
                                    crate::core::process_monitor::inject_exorcism_dll(pid as _)
                                {
                                    logger.log(
                                        LogLevel::Error,
                                        &format!("Error injecting Exorcism DLL: {e:?}"),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Gets the cached driver messages for use in the GUI
    ///
    /// # Returns
    ///
    /// If there are no messages cached, None will be returned. Otherwise, a vector of the messages
    /// will be returned to the caller.
    pub async fn get_cached_driver_messages(&self) -> Option<Vec<String>> {
        let mut msg_lock = self.driver_dbg_message_cache.lock().await;

        if msg_lock.is_empty() {
            return None;
        }

        let tmp = msg_lock.clone();
        msg_lock.clear();

        Some(tmp)
    }

    // Query a given process by its Pid, returning information about the process
    // pub async fn query_process_by_pid(&self, pid: u64) -> Option<Process> {
    //     self.process_monitor.read().await.query_process_by_pid(pid)
    // }
}
