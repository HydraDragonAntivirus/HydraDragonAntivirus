use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use crate::{
    core::process_monitor::inject_edr_dll,
    driver_manager::SanctumDriverManager,
    utils::log::{Log, LogLevel},
};

use super::ipc_injected_dll::run_ipc_for_injected_dll;

/// The core struct contains information on the core of the usermode engine where decisions are being made, and directly communicates
/// with the kernel.
///
/// Note, this module no longer does `Ghost Hunting`, this is done by the driver.
///
/// # Components
///
/// - `driver_poll_rate`: the poll rate in milliseconds that the kernel will be (approximately) queried. The
/// approximation is because the polling / decision making loop is not asynchronous and other decision making
/// takes place prior to the poll rate sleep time.
/// - `driver_dbg_message_cache`: a temporary cache of messages which are returned from the kernel which the
/// GUI can request.
#[derive(Debug, Default)]
pub struct Core {
    driver_poll_rate: u64,
    driver_dbg_message_cache: Mutex<Vec<String>>,
    // process_monitor: RwLock<ProcessMonitor>,
}

impl Core {
    /// Initialises a new Core instance from a poll rate in **milliseconds**.
    pub fn from(poll_rate: u64) -> Self {
        let mut core = Core::default();

        core.driver_poll_rate = poll_rate;

        core
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

        let (tx, mut rx) = mpsc::channel(1000);

        // Start the IPC server for the injected DLL to communicate with the core
        tokio::spawn(async {
            run_ipc_for_injected_dll(tx).await;
        });

        //
        // Enter the polling & decision making loop, this here is the core / engine of the usermode engine.
        // todo: we need to actually inspect what these params are doing and if they are malicious.
        //
        loop {
            // See if there is a message from the injected DLL
            if let Ok(rx) = rx.try_recv() {
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_syscall_event(rx);
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
            if driver_response.is_some() {
                // first deal with process terminations to prevent trying to add to an old process id if there is a duplicate
                let mut driver_messages = driver_response.unwrap();

                // cache messages
                {
                    let mut message_cache = self.driver_dbg_message_cache.lock().await;
                    if !driver_messages.messages.is_empty() {
                        message_cache.append(&mut driver_messages.messages);
                    }
                }
            }

            if let Some(image_loads) = image_loads {
                for pid in image_loads {
                    // println!("[i] Target process detected, injecting EDR DLL into PID: {pid}...");
                    if let Err(e) = inject_edr_dll(pid as _) {
                        println!("[-] Error injecting DLL: {e:?}");
                        logger.log(LogLevel::Error, &format!("Error injecting DLL: {e:?}"));

                        //
                        // We do get the occasional error here; most likely something we simply cannot inject into,
                        // such as PPL / AppContainers, etc.
                        // In the cases the injection failed, this is mostly OK. The DLL is at this point (thanks to
                        // alt syscalls) detecting the abuse of direct / indirect syscalls.
                        // Any process we cannot touch, the adversary will also have a hard time touching; thus we
                        // aren't too bothered. As the Alt Syscalls can do everything the EDR's DLL was, then, we can
                        // just keep the logic there.
                        //
                        // We do however want to send down an IOCTL to tell the driver we failed to inject, as to not
                        // ghost hunt that process.
                        //
                        let mut mtx = driver_manager.lock().await;
                        mtx.ioctl_dll_inject_failed(pid as u32);
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
