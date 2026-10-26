//! Layer 2: Symbol resolution and reference tracking.
//!
//! Wraps OXC `Scoping` with safe, never-panicking accessors.
//! Depends on: OXC Scoping.

pub mod resolve;
pub mod query;
pub mod safety;
