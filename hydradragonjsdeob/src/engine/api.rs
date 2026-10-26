//! Public API — JSDeobfuscator builder.

use oxc::allocator::Allocator;
use oxc::codegen::Codegen;
use oxc::parser::Parser;
use oxc::span::SourceType;

use super::config::Config;
use super::error::{DeobError, Result};
use super::module::Module;
use super::pipeline::{Engine, EngineResult};

/// Result of a deobfuscation run.
pub struct DeobfuscateResult {
    /// The deobfuscated source code.
    pub code: String,
    /// Number of convergence iterations.
    pub iterations: usize,
    /// Total AST modifications made.
    pub modifications: usize,
    /// Whether the engine reached a fixed point.
    pub converged: bool,
}

/// High-level deobfuscator with builder API.
///
/// ```ignore
/// use js_deobfuscator::JSDeobfuscator;
///
/// let result = JSDeobfuscator::new()
///     .deobfuscate("var a = 1 + 2;")?;
/// assert!(result.code.contains("var a = 3"));
/// ```
pub struct JSDeobfuscator {
    config: Config,
    custom_common: Vec<Box<dyn Module>>,
    custom_locked: Vec<Box<dyn Module>>,
}

impl Default for JSDeobfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl JSDeobfuscator {
    /// Create a deobfuscator with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            custom_common: Vec::new(),
            custom_locked: Vec::new(),
        }
    }

    /// Create a deobfuscator with the given configuration.
    #[must_use]
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            custom_common: Vec::new(),
            custom_locked: Vec::new(),
        }
    }

    /// Set maximum convergence iterations.
    #[must_use]
    pub fn max_iterations(mut self, n: usize) -> Self {
        self.config.max_iterations = n;
        self
    }

    /// Enable or disable static folding.
    #[must_use]
    pub fn static_eval(mut self, enabled: bool) -> Self {
        self.config.static_eval = enabled;
        self
    }

    /// Enable or disable semantic transforms.
    #[must_use]
    pub fn transforms(mut self, enabled: bool) -> Self {
        self.config.transforms = enabled;
        self
    }

    /// Add a global context value.
    #[must_use]
    pub fn global(mut self, name: &str, value: serde_json::Value) -> Self {
        self.config.globals.insert(name.to_string(), value);
        self
    }

    /// Add a custom common module (runs in convergence loop).
    #[must_use]
    pub fn add_common(mut self, module: Box<dyn Module>) -> Self {
        self.custom_common.push(module);
        self
    }

    /// Add a custom locked module (runs once after common stabilizes).
    #[must_use]
    pub fn add_locked(mut self, module: Box<dyn Module>) -> Self {
        self.custom_locked.push(module);
        self
    }

    /// Deobfuscate JavaScript source code.
    pub fn deobfuscate(self, source: &str) -> Result<DeobfuscateResult> {
        // P.A.C.K.E.R. layers are text: unpacked before parsing.
        let unpacked = crate::packer::unpack_all(source);
        let source = unpacked.as_deref().unwrap_or(source);
        let allocator = Allocator::default();
        let ret = Parser::new(&allocator, source, SourceType::mjs()).parse();

        if ret.diagnostics.has_errors() {
            let msg = ret.diagnostics.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DeobError::Parse(msg));
        }

        let mut program = ret.program;

        // Build module lists
        let mut common: Vec<Box<dyn Module>> = Vec::new();
        let mut locked: Vec<Box<dyn Module>> = Vec::new();

        // Built-in modules — order matters (see ARCHITECTURE.md)
        // inject → resolve → propagate → inline → fold → simplify → eliminate
        if self.config.transforms {
            if !self.config.globals.is_empty() {
                common.push(Box::new(crate::transform::global::GlobalResolver::new(
                    self.config.globals.clone(),
                )));
            }
            common.push(Box::new(crate::transform::object::ObjectPropResolver));
            common.push(Box::new(crate::transform::constant::ConstantPropagator));
            common.push(Box::new(crate::transform::alias::AliasInliner));
            common.push(Box::new(crate::transform::proxy::ProxyInliner));
        }
        if self.config.static_eval {
            common.push(Box::new(crate::fold::StaticFolder));
        }
        if self.config.transforms {
            common.push(Box::new(crate::transform::member::MemberSimplifier));
            common.push(Box::new(crate::transform::dead::DeadCodeEliminator));
        }

        // Custom modules
        common.extend(self.custom_common);
        locked.extend(self.custom_locked);

        // Run engine
        let mut engine = Engine::new(common, locked, self.config.max_iterations);
        let EngineResult {
            iterations,
            total_modifications,
            converged,
            ..
        } = engine.run(&allocator, &mut program)?;

        // Codegen
        let code = Codegen::new().build(&program).code;

        Ok(DeobfuscateResult {
            code,
            iterations,
            modifications: total_modifications,
            converged,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_fold() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(1 + 2);")
            .unwrap();
        assert!(result.code.contains("console.log(3)"), "got: {}", result.code);
        assert!(result.converged);
    }

    #[test]
    fn test_string_concat() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(\"hello\" + \" world\");")
            .unwrap();
        assert!(result.code.contains("\"hello world\""), "got: {}", result.code);
    }

    #[test]
    fn test_math_fold() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(Math.floor(1.7));")
            .unwrap();
        assert!(result.code.contains("console.log(1)"), "got: {}", result.code);
    }

    #[test]
    fn test_atob_fold() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(atob(\"SGVsbG8=\"));")
            .unwrap();
        assert!(result.code.contains("\"Hello\""), "got: {}", result.code);
    }

    #[test]
    fn test_ternary_fold() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(true ? 42 : 0);")
            .unwrap();
        assert!(result.code.contains("console.log(42)"), "got: {}", result.code);
    }

    #[test]
    fn test_dead_code_removal() {
        let result = JSDeobfuscator::new()
            .deobfuscate("if (false) { var dead = 1; } console.log(2);")
            .unwrap();
        assert!(!result.code.contains("dead"), "got: {}", result.code);
        assert!(result.code.contains("console.log(2)"), "got: {}", result.code);
    }

    #[test]
    fn test_chained_fold() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(String(1 + 2));")
            .unwrap();
        assert!(result.code.contains("\"3\""), "got: {}", result.code);
    }

    #[test]
    fn test_complex_chain() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(atob(\"dGVzdA==\").toUpperCase());")
            .unwrap();
        assert!(result.code.contains("\"TEST\""), "got: {}", result.code);
    }

    #[test]
    fn test_convergence_with_nested() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(parseInt(\"0xff\") + 1);")
            .unwrap();
        assert!(result.code.contains("256"), "got: {}", result.code);
    }

    #[test]
    fn test_parse_error() {
        let result = JSDeobfuscator::new()
            .deobfuscate("var x = ;");
        assert!(result.is_err());
    }

    #[test]
    fn test_no_modifications_converges() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(y);")
            .unwrap();
        assert!(result.converged);
    }

    #[test]
    fn test_disabled_static_eval() {
        let result = JSDeobfuscator::new()
            .static_eval(false)
            .transforms(false)
            .deobfuscate("var x = 1 + 2;")
            .unwrap();
        assert!(result.code.contains("1 + 2"), "got: {}", result.code);
    }

    #[test]
    fn test_constant_propagation() {
        let result = JSDeobfuscator::new()
            .deobfuscate("var key = 42; console.log(key);")
            .unwrap();
        // constant propagation inlines key → 42
        assert!(result.code.contains("console.log(42)"), "got: {}", result.code);
    }

    #[test]
    fn test_dead_var_removed_function_scope() {
        // DCE only operates at function scope or smaller — module-scope vars
        // are preserved for safety (see transform/dead.rs module docs).
        let result = JSDeobfuscator::new()
            .deobfuscate("function f() { var unused = 1; console.log(2); } f();")
            .unwrap();
        assert!(!result.code.contains("unused"), "got: {}", result.code);
        assert!(result.code.contains("console.log(2)"), "got: {}", result.code);
    }

    #[test]
    fn test_module_scope_var_preserved() {
        // Safety: module-scope `var` must NOT be removed even if statically
        // unread. It may be observable via host hooks, eval, or reflection.
        let result = JSDeobfuscator::new()
            .deobfuscate("var unused = 1; console.log(2);")
            .unwrap();
        assert!(result.code.contains("unused"), "module-scope var must be preserved: {}", result.code);
    }

    #[test]
    fn test_member_simplification() {
        let result = JSDeobfuscator::new()
            .deobfuscate("console.log(obj[\"property\"]);")
            .unwrap();
        assert!(result.code.contains("obj.property"), "got: {}", result.code);
    }

    #[test]
    fn test_full_pipeline() {
        // Simulates obfuscated pattern: const + fold + dead code.
        // Wrapped in a function so DCE is allowed to prune _unused
        // (module-scope vars are preserved for safety — see dead.rs).
        let result = JSDeobfuscator::new()
            .deobfuscate(r#"
                function main() {
                    var _0x1 = "Hello";
                    var _0x2 = " ";
                    var _0x3 = "World";
                    var _unused = 999;
                    console.log(_0x1 + _0x2 + _0x3);
                }
                main();
            "#)
            .unwrap();
        assert!(result.code.contains("\"Hello World\""), "got: {}", result.code);
        assert!(!result.code.contains("_unused"), "got: {}", result.code);
        assert!(!result.code.contains("999"), "got: {}", result.code);
    }

    #[test]
    fn test_alias_inlining() {
        let result = JSDeobfuscator::new()
            .deobfuscate("var e = Yp; console.log(e(445));")
            .unwrap();
        assert!(result.code.contains("Yp(445)"), "alias not inlined: {}", result.code);
    }

    #[test]
    fn test_object_prop_resolution() {
        let result = JSDeobfuscator::new()
            .deobfuscate("var t = {F: 445, H: 417}; console.log(t.F + t.H);")
            .unwrap();
        assert!(result.code.contains("862"), "got: {}", result.code);
    }

    #[test]
    fn test_global_injection() {
        let result = JSDeobfuscator::new()
            .global("window", serde_json::json!({"secret": "abc123"}))
            .deobfuscate("console.log(window.secret);")
            .unwrap();
        assert!(result.code.contains("\"abc123\""), "got: {}", result.code);
    }

    #[test]
    fn test_obfuscated_pattern_full() {
        // Realistic obfuscation: lookup table + alias + bracket notation + dead code.
        // Wrapped in a function so DCE is allowed to prune _unused
        // (module-scope vars are preserved for safety — see dead.rs).
        let result = JSDeobfuscator::new()
            .deobfuscate(r#"
                function main() {
                    var _0x4e = {a: "log", b: "Hello"};
                    var _0xc = console;
                    var _unused = 42;
                    _0xc[_0x4e["a"]](_0x4e["b"]);
                }
                main();
            "#)
            .unwrap();
        // After all transforms: console.log("Hello")
        assert!(result.code.contains("\"Hello\""), "got: {}", result.code);
        assert!(!result.code.contains("_unused"), "dead code not removed: {}", result.code);
    }

    #[test]
    fn packer_is_unpacked_then_folded() {
        // The P.A.C.K.E.R. pre-pass runs before parsing; the result is then folded.
        let packed = "eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};return p}('0 1=2+3;4.5(1)',6,6,'var|x|1|2|console|log'.split('|'),0,{}))";
        let result = JSDeobfuscator::new().deobfuscate(packed).unwrap();
        assert!(result.code.contains("console.log(3)"), "got: {}", result.code);
        assert!(!result.code.contains("eval"), "got: {}", result.code);
    }
}
