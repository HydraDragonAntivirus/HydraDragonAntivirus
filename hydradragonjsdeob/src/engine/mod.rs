//! Layer 7: Orchestration — Module trait, convergence loop, public API.
//!
//! module.rs and error.rs are leaf types with no upward dependencies.
//! Lower layers (fold/, transform/, etc.) import them freely.

pub mod error;
pub mod module;
pub mod config;
pub mod pipeline;
pub mod api;
