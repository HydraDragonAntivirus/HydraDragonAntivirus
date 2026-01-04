use std::{ffi::CStr, sync::Arc};

use shared_std::settings::SanctumSettings;
use tokio::sync::Mutex;
use windows::Win32::{
    Foundation::GetLastError,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPALL,
    },
};

use crate::{
    core::core::Core,
    driver_manager::SanctumDriverManager,
    filescanner::FileScanner,
    gui_communication::ipc::UmIpc,
    settings::SanctumSettingsImpl,
    utils::log::{Log, LogLevel},
};

/// The Process ID of the Sanctum PPL service.
pub static mut PPL_SERVICE_PID: u32 = 0;

/// Engine is the central driver and control point for the Sanctum EDR. It is responsible for
/// managing the core features of the EDR, including:
///
/// - Communication with the driver
/// - Communication with the GUI
/// - Decision making
/// - Scanning
/// - Process monitoring
/// - File monitoring
/// - Driver management
pub struct Engine;

impl Engine {
    /// Start the engine
    pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize PPL Service PID for ETW verification
        if let Ok(pid) = get_ppl_svc_pid() {
            unsafe { PPL_SERVICE_PID = pid };
            println!("[Sanctum] Trusted PPL Service PID: {}", pid);
        } else {
            eprintln!(
                "[Sanctum] WARNING: Could not find sanctum_ppl_runner. ETW telemetry may be rejected."
            );
        }

        //
        // Start by instantiating the elements we will be using in the engine.
        // Once created; clone them as Arcs to share across the threads
        //

        // core
        let core = Arc::new(Core::from(20));
        let core_umipc = Arc::clone(&core);

        // file scanner
        let scanner = FileScanner::new().await;
        if let Err(e) = scanner {
            panic!("[-] Failed to initialise scanner: {e}.");
        }
        let file_scanner = Arc::new(scanner.unwrap());
        let file_scanner_clone = Arc::clone(&file_scanner);

        // driver manager
        // Happy the driver manager being wrapped in a mutex now; it isn't a high performance module and I
        // don't need necessarily to spend time refactoring that at the moment. The only place the mutex may
        // cause a bottleneck is when making IOCTL calls via SanctumDriverManager.
        // todo review - issue #50
        let driver_manager = Arc::new(Mutex::new(SanctumDriverManager::new()));
        let drv_mgr_for_umipc = Arc::clone(&driver_manager);
        let drv_mgr_for_core = Arc::clone(&driver_manager);

        // settings - happy to leave as mutex for now, may refactor later to move the mutex deeper into the
        // call flow
        let sanctum_settings = Arc::new(Mutex::new(SanctumSettings::load()));
        let settings_clone = Arc::clone(&sanctum_settings);

        //
        // Spawn the core of the engine which will constantly talk to the driver and process any IO
        // from / to the driver and other working parts of the EDR, except for the GUI which will
        // be handled below.
        //
        // The `core` is passed into the start method as an Arc<Mutex<>> so we can share its data with
        // other threads from the engine / usermode IPC loops.
        //
        let core_handle = tokio::spawn(async move {
            core.start_core(drv_mgr_for_core).await;
        });

        // blocks indefinitely unless some error gets thrown up
        // todo review this; can this state ever crash the app?
        let gui_ipc_handle = tokio::spawn(async move {
            let error = UmIpc::listen(
                settings_clone,
                core_umipc,
                file_scanner_clone,
                drv_mgr_for_umipc,
            )
            .await;

            let logger = Log::new();
            logger.log(crate::utils::log::LogLevel::NearFatal, &format!("A near fatal error occurred in Engine::start() causing the application to crash. {:?}", error));
        });

        // If one thread returns out an error of the runtime; we want to return out of the engine and
        // halt
        tokio::try_join!(core_handle, gui_ipc_handle)?;

        Ok(())
    }
}

/// Gets the PID of the Protected Process Light service which should be running to catch ETW events.
///
/// # Returns
/// - Ok: If the service was found, the PID will be returned
/// - Err: If the service was not found a unit Error will be returned
///
/// # PAnics
/// The function will panic if it encounters an error snapshotting the processes.
fn get_ppl_svc_pid() -> Result<u32, ()> {
    let logger = Log::new();

    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0) } {
        Ok(s) => {
            if s.is_invalid() {
                logger.panic(&format!(
                    "Unable to create snapshot of all processes. GLE: {}",
                    unsafe { GetLastError().0 }
                ));
            } else {
                s
            }
        }
        Err(_) => {
            // not really bothered about the error at this stage
            logger.panic(&format!(
                "Unable to create snapshot of all processes. GLE: {}",
                unsafe { GetLastError().0 }
            ));
        }
    };

    let mut process_entry = PROCESSENTRY32::default();
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot, &mut process_entry) }.is_ok() {
        loop {
            //
            // Get the process name; helpful mostly for debug messages
            //
            let current_process_name_ptr = process_entry.szExeFile.as_ptr() as *const _;
            let current_process_name =
                match unsafe { CStr::from_ptr(current_process_name_ptr) }.to_str() {
                    Ok(process) => process.to_string(),
                    Err(e) => {
                        logger.log(
                            LogLevel::Error,
                            &format!("Error converting process name. {e}"),
                        );
                        if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                            break;
                        }
                        continue;
                    }
                };

            // look for our service
            if current_process_name.contains("sanctum_ppl_runner") {
                return Ok(process_entry.th32ProcessID);
            }

            // continue enumerating
            if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                break;
            }
        }
    }

    Err(())
}
