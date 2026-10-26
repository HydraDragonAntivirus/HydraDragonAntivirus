//! Two-phase convergence loop.
//!
//! Phase 1 (Common): Run modules in order, repeat until 0 modifications.
//! Phase 2 (Locked): Run once after common stabilizes. If changes, restart Phase 1.
//! Outer loop: Repeat until locked makes 0 changes, or max iterations reached.

use std::time::{Duration, Instant};

use oxc::allocator::Allocator;
use oxc::ast::ast::Program;
use oxc::semantic::{SemanticBuilder, Scoping};

use tracing::{debug, info};

use super::error::Result;
use super::module::Module;

/// Statistics from an engine run.
#[derive(Debug)]
pub struct EngineResult {
    /// Number of convergence iterations executed.
    pub iterations: usize,
    /// Total modifications across all iterations.
    pub total_modifications: usize,
    /// Whether the engine reached a fixed point (0 changes).
    pub converged: bool,
    /// Wall-clock time for the entire run.
    pub elapsed: Duration,
}

/// The convergence engine.
pub struct Engine {
    /// Common modules — converge to 0 changes before locked modules run.
    common: Vec<Box<dyn Module>>,
    /// Locked modules — run once after common stabilizes.
    locked: Vec<Box<dyn Module>>,
    max_iterations: usize,
}

impl Engine {
    pub fn new(
        common: Vec<Box<dyn Module>>,
        locked: Vec<Box<dyn Module>>,
        max_iterations: usize,
    ) -> Self {
        Self { common, locked, max_iterations }
    }

    /// Run the two-phase convergence loop.
    pub fn run<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
    ) -> Result<EngineResult> {
        let start = Instant::now();
        let mut scoping = build_scoping(program);
        let mut total_modifications = 0;
        let mut iterations = 0;
        let mut converged = false;

        for _outer in 0..self.max_iterations {
            // Phase 1: Common convergence
            for _inner in 0..self.max_iterations {
                let mut iteration_mods = 0;

                for module in &mut self.common {
                    let result = module.transform(allocator, program, scoping)?;
                    iteration_mods += result.modifications;
                    scoping = result.scoping;

                    if module.changes_symbols() && result.modifications > 0 {
                        scoping = build_scoping(program);
                    }
                }

                total_modifications += iteration_mods;
                iterations += 1;

                debug!(iteration = iterations, mods = iteration_mods, "common iteration");

                if iteration_mods == 0 {
                    break;
                }
            }

            // Phase 2: Locked modules (run once)
            let mut locked_mods = 0;
            for module in &mut self.locked {
                let result = module.transform(allocator, program, scoping)?;
                locked_mods += result.modifications;
                scoping = result.scoping;

                if module.changes_symbols() && result.modifications > 0 {
                    scoping = build_scoping(program);
                }
            }

            total_modifications += locked_mods;
            if locked_mods > 0 {
                iterations += 1;
                debug!(locked_mods, "locked modules changed, restarting common");
            }

            if locked_mods == 0 {
                converged = true;
                break;
            }
        }

        info!(
            iterations,
            total_modifications,
            converged,
            elapsed_ms = start.elapsed().as_millis(),
            "engine run complete"
        );

        Ok(EngineResult {
            iterations,
            total_modifications,
            converged,
            elapsed: start.elapsed(),
        })
    }
}

fn build_scoping(program: &Program) -> Scoping {
    SemanticBuilder::new().build(program).semantic.into_scoping()
}
