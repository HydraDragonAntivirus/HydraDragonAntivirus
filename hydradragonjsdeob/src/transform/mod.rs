//! Layer 5: Semantic transforms.
//!
//! Two-pass modules that use scope analysis to propagate, inline, and eliminate.
//! Each is a Module implementation. Depends on scope/, fold/, ast/.

pub mod constant;
pub mod alias;
pub mod proxy;
pub mod object;
pub mod dead;
pub mod member;
pub mod global;
