//! Engine configuration.

use std::collections::HashMap;

/// Configuration for the deobfuscator engine.
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum convergence iterations before stopping.
    pub max_iterations: usize,

    /// Enable static expression folding (fold/ layer).
    pub static_eval: bool,

    /// Enable semantic transforms (transform/ layer).
    pub transforms: bool,

    /// Global values for resolving external references.
    ///
    /// Example: `{"window": {"secret": "abc123"}}` lets the deobfuscator
    /// resolve `window.secret` → `"abc123"`.
    pub globals: HashMap<String, serde_json::Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_iterations: 50,
            static_eval: true,
            transforms: true,
            globals: HashMap::new(),
        }
    }
}
