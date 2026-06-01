//! Owlyshield is an open-source AI-driven behavior based antiransomware engine designed to run
//!

// #![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]
extern crate num;
extern crate num_derive;

#[cfg(feature = "service")]
use std::ffi::OsString; //win
#[cfg(feature = "service")]
use std::sync::mpsc;
#[cfg(feature = "service")]
use std::thread;
//win
#[cfg(feature = "service")]
use crate::mpsc::channel;
#[cfg(feature = "service")]
use std::time::Duration;

#[cfg(all(target_os = "windows", feature = "service"))]
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(all(target_os = "windows", feature = "service"))]
use windows_service::service_control_handler::ServiceControlHandlerResult;
#[cfg(all(target_os = "windows", feature = "service"))]
use windows_service::{define_windows_service, service_control_handler, service_dispatcher};

#[cfg(target_os = "windows")]
use crate::driver_com::Driver;
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use std::{env, path::Path, sync::OnceLock};

// Conditionally compile AVIntegration `use` statement
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub mod hydradragon;
// Conditionally compile AVIntegration `use` statement
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
mod behavioral;

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
/// * `Some(AVIntegration)` when the HydraDragon feature is compiled in
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub fn init_hydra_dragon(
    config: &crate::config::Config,
) -> Option<hydradragon::av_integration::AVIntegration<'_>> {
    if !is_hydra_dragon_enabled() {
        crate::logging::Logging::warning(
            "HydraDragon install path was not found; starting pipe integration anyway",
        );
    }

    use crate::worker::predictor::PredictorMalware;

    // Create predictor on this thread
    let predictor_malware = PredictorMalware::new(config);

    // Create AVIntegration on this thread
    // This is safe because we're not trying to share it across threads
    Some(hydradragon::av_integration::AVIntegration::new(
        config,
        predictor_malware,
    ))
}

/*
*/

use crate::logging::Logging;
use crate::shared_def::IOMessage;
use crate::worker::process_record_handling::ExepathLive;

mod actions_on_kill;
mod config;
// mod app_settings; // removed, now in behavioral
mod connectors;
#[cfg(feature = "realtime_learning")]
mod correlation;
mod csvwriter;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(crate) use windows::driver_com;
#[cfg(target_os = "linux")]
#[path = "linux/driver_com.rs"]
pub(crate) mod driver_com;
#[cfg(feature = "realtime_learning")]
mod explainability;
mod extensions;
mod jsonrpc;
mod logging;
#[cfg(feature = "realtime_learning")]
mod mitre_attack;
#[cfg(target_os = "windows")]
pub(crate) use windows::notifications;
#[cfg(target_os = "linux")]
#[path = "linux/notifications.rs"]
pub(crate) mod notifications;
mod predictions;
mod process;
#[cfg(target_os = "windows")]
pub(crate) use windows::quarantine;
#[cfg(target_os = "windows")]
pub(crate) use windows::run;
#[cfg(all(target_os = "linux", feature = "linux-ebpf"))]
#[path = "linux/run.rs"]
mod run;
#[cfg(target_os = "windows")]
pub use windows::signature_verification;

#[cfg(all(target_os = "linux", not(feature = "linux-ebpf")))]
mod run {
    pub fn run() {
        // Linux runtime is disabled unless the `linux-ebpf` feature is enabled.
        // This keeps default builds working even when BPF artifacts are not present.
        log::info!("Linux runtime skipped (enable `linux-ebpf` to run eBPF monitor)");
    }
}
mod globals;
mod novelty;
#[cfg(all(target_os = "windows", feature = "realtime_learning"))]
pub mod realtime_learning; // Owlyshield realtime-learning module
mod report;
#[cfg(target_os = "windows")]
pub mod services;
#[cfg(target_os = "windows")]
pub(crate) use windows::shadow_copy;
pub(crate) mod shared_def;
mod threat_handler;
#[cfg(target_os = "windows")]
pub(crate) use windows::threathandling;
#[cfg(target_os = "linux")]
#[path = "linux/threathandling.rs"]
pub(crate) mod threathandling;
mod utils;
mod watchlist;
pub(crate) mod worker;

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
    Logging::stop();
}
