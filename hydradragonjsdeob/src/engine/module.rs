//! Module trait — the contract every transformation pass implements.
//!
//! Leaf type — depends only on OXC types.

use oxc::allocator::Allocator;
use oxc::ast::ast::Program;
use oxc::semantic::Scoping;

use super::error::Result;

/// Result of a single module's transformation pass.
pub struct TransformResult {
    /// Number of AST modifications made.
    pub modifications: usize,
    /// Scoping state after transformation (may be shared or rebuilt).
    pub scoping: Scoping,
}

/// A deobfuscation transformation module.
///
/// Each module is a self-contained transformation pass. Modules run in a
/// fixed order within the convergence loop. The engine chains scoping
/// between modules and rebuilds it when `changes_symbols` returns true.
pub trait Module: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &'static str;

    /// Whether this module adds/removes declarations or renames bindings.
    ///
    /// If true and modifications > 0, the engine rebuilds scoping after
    /// this module runs.
    fn changes_symbols(&self) -> bool {
        false
    }

    /// Run the transformation.
    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult>;
}
