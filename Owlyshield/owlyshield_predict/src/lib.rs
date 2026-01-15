//! Library entry point for the OwlyShield ransomware protection SDK.
//! Re-exports and module structure aligned with main.rs and existing submodule requirements.

extern crate num;
#[macro_use]
extern crate num_derive;

// --- Module Definitions ---

pub mod actions_on_kill;
pub mod config;
pub mod app_settings;
pub mod connectors;
pub mod csvwriter;
pub mod extensions;
pub mod jsonrpc;
pub mod logging;
pub mod novelty;
pub mod predictions;
pub mod process;
pub mod shared_def;
pub mod utils;
pub mod watchlist;
pub mod whitelist;
pub mod worker;
pub mod behavior_engine;

#[cfg(feature = "realtime_learning")]
pub mod realtime_learning;

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

pub use crate::logging::Logging;
pub use crate::shared_def::IOMessage;
pub use crate::worker::worker_instance::{Worker, IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter};
pub use crate::worker::process_record_handling::{ExepathLive, ProcessRecordHandlerLive, ProcessRecordHandlerNovelty};
pub use crate::connectors::register::Connectors;
pub use crate::watchlist::WatchList;
pub use crate::utils::is_process_alive;

#[cfg(target_os = "windows")]
pub use crate::windows::driver_com;
#[cfg(target_os = "windows")]
pub use crate::windows::driver_com::{Driver, CDriverMsgs};
#[cfg(target_os = "windows")]
pub use crate::windows::run;
#[cfg(target_os = "windows")]
pub use crate::windows::notifications;
#[cfg(target_os = "windows")]
pub use crate::windows::signature_verification;
#[cfg(target_os = "windows")]
pub use crate::windows::threathandling;

#[cfg(target_os = "linux")]
pub use crate::linux::driver_com;
#[cfg(target_os = "linux")]
pub use crate::linux::driver_com::LDriverMsg;
#[cfg(target_os = "linux")]
pub use crate::linux::run;
#[cfg(target_os = "linux")]
pub use crate::linux::notifications;
#[cfg(target_os = "linux")]
pub use crate::linux::threathandling;

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
#[path = "windows/av_integration.rs"]
pub mod av_integration;

/// SDK-facing exports used by examples and integrations.
pub mod sdk {
    #[cfg(feature = "realtime_learning")]
    pub use crate::realtime_learning::behavioral_signature;
    #[cfg(feature = "realtime_learning")]
    pub use crate::realtime_learning::ml_collector::CollectionMode;
    #[cfg(feature = "realtime_learning")]
    pub use crate::realtime_learning::{OwlyShieldSDK, PatternType};
    pub use crate::process;
    pub use crate::shared_def;
}

