//! Layer 1: OXC AST helpers.
//!
//! Reads from and writes to the arena. Zero-copy extraction where possible.
//! Depends on: value (JsValue), OXC (allocator, ast, span).

pub mod extract;
pub mod create;
pub mod query;
pub mod codegen;
