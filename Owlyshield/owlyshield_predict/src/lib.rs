//! Library entry point for the OwlyShield ransomware protection SDK.
//! Re-exports and module structure aligned with main.rs and existing submodule requirements.

extern crate num;
#[macro_use]
extern crate num_derive;

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use std::{env, path::Path, sync::OnceLock};

// --- Module Definitions ---

pub mod actions_on_kill;
pub mod config;
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub mod behavioral;
pub mod connectors;
pub mod csvwriter;
pub mod extensions;
pub mod jsonrpc;
pub mod logging;
pub mod novelty;
pub mod predictions;
pub mod process;
pub mod shared_def;
pub mod threat_handler;
pub mod utils;
pub mod watchlist;
pub mod whitelist;
pub mod whitelist_loader;
pub mod worker;

#[cfg(feature = "realtime_learning")]
pub mod realtime_learning;

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
#[path = "windows/av_integration.rs"]
pub mod av_integration;

// Platform-Specific Modules via sub-mod files
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

// Support for service and other features
#[cfg(target_os = "windows")]
pub mod services;

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

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub fn init_hydra_dragon(
    config: &crate::config::Config,
) -> Option<av_integration::AVIntegration> {
    if is_hydra_dragon_enabled() {
        use crate::worker::predictor::PredictorMalware;
        let predictor_malware = PredictorMalware::new(config);
        Some(av_integration::AVIntegration::new(config, predictor_malware))
    } else {
        None
    }
}

// --- Bridge Module Exports (Alignment with main.rs root namespace) ---
// This resolves `crate::Symbol` and `crate::module::Symbol` imports in submodules.

pub use crate::logging::Logging;
pub use crate::shared_def::IOMessage;
pub use crate::worker::worker_instance::{Worker, IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter};
pub use crate::worker::process_record_handling::{ExepathLive, ProcessRecordHandlerLive, ProcessRecordHandlerNovelty};
pub use crate::connectors::register::Connectors;
pub use crate::watchlist::WatchList;
pub use crate::utils::is_process_alive;
pub use crate::threat_handler::ThreatHandler;

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

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub use behavioral::behavior_engine::BehaviorEngine;

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

