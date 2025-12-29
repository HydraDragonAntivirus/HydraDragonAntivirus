//! Library entry point for the OwlyShield ransomware protection SDK.
//! This exposes the runtime learning engine and shared data structures
//! so that examples and external tools can link against the crate.

#[macro_use]
extern crate num_derive;
extern crate num;

pub mod extensions;
pub mod novelty;
pub mod process;
pub mod realtime_learning;
pub mod shared_def;

/// SDK-facing exports used by examples and integrations.
pub mod sdk {
    pub use crate::realtime_learning::behavioral_signature;
    pub use crate::realtime_learning::ml_collector::CollectionMode;
    pub use crate::realtime_learning::{OwlyShieldSDK, PatternType};
    pub use crate::process;
    pub use crate::shared_def;
}
