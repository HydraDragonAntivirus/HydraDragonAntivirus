//! Library entry point for the Owlyshield ransomware protection SDK.
//! Re-exports and module structure aligned with main.rs and existing submodule requirements.

extern crate num;
extern crate num_derive;

// --- Windows-Only Feature Enforcement ---
#[cfg(all(feature = "firewall", not(target_os = "windows")))]
compile_error!("The 'firewall' feature is only supported on Windows.");
#[cfg(all(feature = "sanctum", not(target_os = "windows")))]
compile_error!("The 'sanctum' feature is only supported on Windows.");
#[cfg(all(feature = "hydradragon", not(target_os = "windows")))]
compile_error!("The 'hydradragon' feature is only supported on Windows.");
#[cfg(all(feature = "behavior_engine", not(target_os = "windows")))]
compile_error!("The 'behavior_engine' feature is only supported on Windows.");

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use std::{env, path::Path, sync::OnceLock};

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
pub mod novelty;
pub mod predictions;
pub mod process;
pub mod report;
pub mod shared_def;
pub mod threat_handler;
pub mod utils;
pub mod watchlist;
pub mod whitelist_loader;
pub mod worker;

#[cfg(feature = "realtime_learning")]
pub mod realtime_learning;

#[cfg(feature = "realtime_learning")]
pub mod correlation;
#[cfg(feature = "realtime_learning")]
pub mod explainability;
#[cfg(feature = "realtime_learning")]
pub mod mitre_attack;

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub mod hydradragon;

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
    driver: crate::windows::edrsvc_client::Driver,
) -> Option<hydradragon::av_integration::AVIntegration<'_>> {
    if !is_hydra_dragon_enabled() {
        crate::logging::Logging::warning(
            "HydraDragon install path was not found; starting pipe integration anyway",
        );
    }

    use crate::worker::predictor::PredictorMalware;
    let predictor_malware = PredictorMalware::new(config);
    Some(hydradragon::av_integration::AVIntegration::new(
        config,
        predictor_malware,
        driver,
    ))
}

// --- Bridge Module Exports (Alignment with main.rs root namespace) ---
// This resolves `crate::Symbol` and `crate::module::Symbol` imports in submodules.

pub use crate::connectors::register::Connectors;
pub use crate::logging::Logging;
pub use crate::shared_def::IOMessage;
pub use crate::threat_handler::ThreatHandler;
pub use crate::utils::is_process_alive;
pub use crate::watchlist::WatchList;
pub use crate::worker::process_record_handling::{
    ExepathLive, ProcessRecordHandlerLive, ProcessRecordHandlerNovelty,
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
pub use crate::linux::notifications;
#[cfg(target_os = "linux")]
pub use crate::linux::run;
#[cfg(target_os = "linux")]
pub use crate::linux::threathandling;

/// SDK-facing exports used by examples and integrations.
pub mod sdk {
    pub use crate::process;
    #[cfg(feature = "realtime_learning")]
    pub use crate::realtime_learning::behavioral_signature;
    #[cfg(feature = "realtime_learning")]
    pub use crate::realtime_learning::ml_collector::CollectionMode;
    #[cfg(feature = "realtime_learning")]
    pub use crate::realtime_learning::{OwlyshieldSDK, PatternType};
    pub use crate::shared_def;
}
