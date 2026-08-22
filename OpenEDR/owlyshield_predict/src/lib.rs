//! Library entry point for the Owlyshield ransomware protection SDK.

extern crate num;
extern crate num_derive;

pub mod actions_on_kill;
pub mod config;
pub mod connectors;
pub mod extensions;
pub mod ffi;
pub mod firewall;
pub mod globals;
pub mod logging;
pub mod ml;
pub mod notifications;
pub mod predictions;
pub mod process;
pub mod report;
pub mod shared_def;
pub mod signature_verification;
pub mod threat_handler;
pub mod utils;
pub mod watchlist;
pub mod whitelist_loader;
pub mod windows;
pub mod worker;

// --- Re-exports ---

pub use crate::connectors::register::Connectors;
pub use crate::logging::Logging;
pub use crate::shared_def::IOMessage;
pub use crate::threat_handler::ThreatHandler;
pub use crate::utils::is_process_alive;
pub use crate::watchlist::WatchList;
pub use crate::windows::edrsvc_client::Driver;

pub use crate::windows::quarantine;
pub use crate::windows::run;
pub use crate::windows::shadow_copy;
pub use crate::windows::threathandling;
pub use crate::worker::process_record_handling::{ExepathLive, ProcessRecordHandlerLive};
pub use crate::worker::worker_instance::{IOMsgPostProcessorWriter, Worker};

pub mod sdk {
    pub use crate::process;
    pub use crate::shared_def;
}
