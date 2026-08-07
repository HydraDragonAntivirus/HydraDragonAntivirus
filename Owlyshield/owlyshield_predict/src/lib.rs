//! Library entry point for the Owlyshield ransomware protection SDK.
//! Re-exports and module structure aligned with main.rs and existing submodule requirements.

extern crate num;
extern crate num_derive;

// --- Windows-Only Feature Enforcement ---
#[cfg(all(feature = "firewall", not(target_os = "windows")))]
compile_error!("The 'firewall' feature is only supported on Windows.");
#[cfg(all(feature = "behavior_engine", not(target_os = "windows")))]
compile_error!("The 'behavior_engine' feature is only supported on Windows.");

// --- Module Definitions ---

pub mod actions_on_kill;
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub mod behavioral;
pub mod config;
pub mod connectors;
pub mod csvwriter;
pub mod extensions;
pub mod globals;
pub mod jsonrpc;
pub mod logging;
pub mod predictions;
pub mod process;
pub mod report;
pub mod shared_def;
pub mod signature_verification;
pub mod threat_handler;
pub mod utils;
pub mod watchlist;
pub mod whitelist_loader;
pub mod worker;

// Platform-Specific Modules via sub-mod files
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

// Support for service and other features
#[cfg(target_os = "windows")]
pub mod services;

// --- Bridge Module Exports (Alignment with main.rs root namespace) ---
// This resolves `crate::Symbol` and `crate::module::Symbol` imports in submodules.

pub use crate::connectors::register::Connectors;
pub use crate::logging::Logging;
pub use crate::shared_def::IOMessage;
pub use crate::threat_handler::ThreatHandler;
pub use crate::utils::is_process_alive;
pub use crate::watchlist::WatchList;
pub use crate::worker::process_record_handling::{
    ExepathLive, ProcessRecordHandlerLive,
};
pub use crate::worker::worker_instance::{
    IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter, Worker,
};

#[cfg(target_os = "windows")]
pub use crate::windows::edrsvc_client::Driver;
#[cfg(target_os = "windows")]
pub use crate::windows::notifications;
#[cfg(target_os = "windows")]
pub use crate::windows::quarantine;
#[cfg(target_os = "windows")]
pub use crate::windows::run;
#[cfg(target_os = "windows")]
pub use crate::windows::shadow_copy;
#[cfg(target_os = "windows")]
pub use crate::windows::threathandling;

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub use behavioral::behavior_engine::BehaviorEngine;

#[cfg(target_os = "linux")]
pub use crate::linux::driver_com;
#[cfg(target_os = "linux")]
pub use crate::linux::driver_com::LDriverMsg;
#[cfg(target_os = "linux")]
pub use crate::linux::notifications;
#[cfg(target_os = "linux")]
pub use crate::linux::run;
#[cfg(target_os = "linux")]
pub use crate::linux::threathandling;

/// SDK-facing exports used by examples and integrations.
pub mod sdk {
    pub use crate::process;
    pub use crate::shared_def;
}
