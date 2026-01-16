//! Owlyshield is an open-source AI-driven behavior based antiransomware engine designed to run
//!

// #![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]
extern crate num;
#[macro_use]
extern crate num_derive;

#[cfg(feature = "service")]
use std::ffi::OsString; //win
#[cfg(feature = "service")]
use std::sync::mpsc;
#[cfg(feature = "service")]
use std::thread;
//win
#[cfg(feature = "service")]
use std::time::Duration;
#[cfg(feature = "service")]
use crate::mpsc::channel;

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::service_control_handler::ServiceControlHandlerResult;
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::{define_windows_service, service_control_handler, service_dispatcher};

use crate::connectors::register::Connectors;
#[cfg(target_os = "windows")]
use crate::driver_com::Driver;
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use std::{env, path::Path, sync::OnceLock};

// Conditionally compile AVIntegration `use` statement
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
#[path = "windows/av_integration.rs"]
pub mod av_integration;

// ============================================================================
// HYDRADRAGON INTEGRATION - CORRECTED APPROACH
// ============================================================================

/// Check if HydraDragon antivirus is installed
/// This is safe to use as a static because it only stores a bool
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub static HYDRA_DRAGON_ENABLED: OnceLock<bool> = OnceLock::new();

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub fn is_hydra_dragon_enabled() -> bool {
    *HYDRA_DRAGON_ENABLED.get_or_init(|| {
        env::var("ProgramFiles")
            .map(|pf| Path::new(&pf).join("HydraDragonAntivirus").exists())
            .unwrap_or(false)
    })
}

/// Initialize AVIntegration for the current thread.
/// 
/// CRITICAL: This function MUST be called on the thread that will use the AVIntegration.
/// The TensorFlow Lite models contain raw pointers (NonNull) that are NOT Send/Sync,
/// so AVIntegration CANNOT be stored in a static or shared across threads via Mutex/Arc.
/// 
/// # Arguments
/// * `config` - Reference to the Config instance for this thread
/// 
/// # Returns
/// * `Some(AVIntegration)` if HydraDragon is available
/// * `None` if HydraDragon is not installed
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub fn init_hydra_dragon(config: &crate::config::Config) -> Option<av_integration::AVIntegration> {
    if is_hydra_dragon_enabled() {
        use crate::worker::predictor::PredictorMalware;
        
        // Create predictor on this thread
        let predictor_malware = PredictorMalware::new(config);
        
        // Create AVIntegration on this thread
        // This is safe because we're not trying to share it across threads
        Some(av_integration::AVIntegration::new(config, predictor_malware))
    } else {
        None
    }
}

/*
*/

#[cfg(target_os = "windows")]
use crate::driver_com::CDriverMsgs;
#[cfg(target_os = "linux")]
use crate::driver_com::LDriverMsg;
use crate::shared_def::IOMessage;
use crate::logging::Logging;
use crate::worker::process_record_handling::{ExepathLive, ProcessRecordHandlerLive, ProcessRecordHandlerNovelty};
use crate::worker::worker_instance::{IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter, Worker};

mod actions_on_kill;
mod config;
mod app_settings;
mod connectors;
mod csvwriter;
#[cfg(target_os = "windows")]
#[path = "windows/driver_com.rs"]
pub(crate) mod driver_com;
#[cfg(target_os = "linux")]
#[path = "linux/driver_com.rs"]
pub(crate) mod driver_com;
mod extensions;
mod jsonrpc;
mod logging;
#[cfg(target_os = "windows")]
#[path = "windows/notifications.rs"]
pub(crate) mod notifications;
#[cfg(target_os = "linux")]
#[path = "linux/notifications.rs"]
pub(crate) mod notifications;
mod predictions;
mod process;
#[cfg(target_os = "windows")]
#[path = "windows/run.rs"]
mod run;
#[cfg(target_os = "windows")]
#[path = "windows/signature_verification.rs"]
pub mod signature_verification;
#[cfg(all(target_os = "linux", feature = "linux-ebpf"))]
#[path = "linux/run.rs"]
mod run;

#[cfg(all(target_os = "linux", not(feature = "linux-ebpf")))]
mod run {
    pub fn run() {
        // Linux runtime is disabled unless the `linux-ebpf` feature is enabled.
        // This keeps default builds working even when BPF artifacts are not present.
        log::info!("Linux runtime skipped (enable `linux-ebpf` to run eBPF monitor)");
    }
}
pub(crate) mod shared_def;
mod utils;
mod watchlist;
mod whitelist;
pub(crate) mod worker;
mod novelty;
#[cfg(target_os = "windows")]
pub mod services;
#[cfg(feature = "realtime_learning")]
pub mod realtime_learning;  // OwlyShield realtime-learning module
#[cfg(target_os = "windows")]
#[path = "windows/threathandling.rs"]
pub(crate) mod threathandling;
#[cfg(target_os = "linux")]
#[path = "linux/threathandling.rs"]
pub(crate) mod threathandling;

#[cfg(feature = "service")]
const SERVICE_NAME: &str = "Owlyshield Service";
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
define_windows_service!(ffi_service_main, service_main);

// examples at https://github.com/mullvad/windows-service-rs/tree/master/examples
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn service_main(arguments: Vec<OsString>) {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        // error!("Critical error: {}", pi);
        println!("{pi}");
        Logging::error(format!("Critical error: {pi}").as_str());
    }));
    // let log_source = "Owlyshield Ransom Rust 2";
    // winlog::register(log_source);
    // winlog::init(log_source).unwrap_or(());
    // info!("Program started.");
    Logging::start();


    if let Err(_e) = run_service(arguments) {
        // error!("Error in run_service.");
        Logging::error("Error in run_service.");
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn run_service(_arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
    let (shutdown_tx, shutdown_rx) = channel();
    let shutdown_tx1 = shutdown_tx.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Interrogate => {
                shutdown_tx.send(()).unwrap();
                // info!("Stop event received");
                Logging::stop();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let next_status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    // Tell the system that the service is running now
    status_handle.set_service_status(next_status)?;

    thread::spawn(move || {
        let t = thread::spawn(move || {
            run::run();
        })
        .join();
        if t.is_err() {
            shutdown_tx1.send(()).unwrap();
        }
    });

    loop {
        // Poll shutdown event.
        match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
            // Break the loop either upon stop or channel disconnect
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,

            // Continue work if no events were received within the timeout
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        };
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn main() -> Result<(), windows_service::Error> {
    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(feature = "service"))]
fn main() {
    //https://patorjk.com/software/taag/#p=display&f=Bloody&t=Owlyshield
    let banner = r#"

 ▒█████   █     █░ ██▓   ▓██   ██▓  ██████  ██░ ██  ██▓▓█████  ██▓    ▓█████▄
▒██▒  ██▒▓█░ █ ░█░▓██▒    ▒██  ██▒▒██    ▒ ▓██░ ██▒▓██▒▓█   ▀ ▓██▒    ▒██▀ ██▌
▒██░  ██▒▒█░ █ ░█ ▒██░     ▒██ ██░░ ▓██▄   ▒██▀▀██░▒██▒▒███   ▒██░    ░██   █▌
▒██   ██░░█░ █ ░█ ▒██░     ░ ▐██▓░  ▒   ██▒░▓█ ░██ ░██░▒▓█  ▄ ▒██░    ░▓█▄   ▌
░ ████▓▒░░░██▒██▓ ░██████▒ ░ ██▒▓░▒██████▒▒░▓█▒░██▓░██░░▒████▒░██████▒░▒████▓
░ ▒░▒░▒░ ░ ▓░▒ ▒  ░ ▒░▓  ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓  ░░ ▒░ ░░ ▒░▓  ░ ▒▒▓  ▒
  ░ ▒ ▒░   ▒ ░ ░  ░ ░ ▒  ░▓██ ░▒░ ░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░ ░  ░░ ░ ▒  ░ ░ ▒  ▒
░ ░ ░ ▒    ░   ░    ░ ░   ▒ ▒ ░░  ░  ░  ░   ░  ░░ ░ ▒ ░   ░     ░ ░    ░ ░  ░
    ░ ░      ░        ░  ░░ ░           ░   ░  ░  ░ ░     ░  ░    ░  ░   ░
                          ░ ░                                          ░

                                                                By SitinCloud
    "#;
    println!("{banner}");

    run::run();
}
