//! Constant propagation: inline literal values into their usage sites.
//!
//! `var x = 5; return x;` → `var x = 5; return 5;`
//!
//! Two-pass:
//!   Pass 1 (Collect): Find var/let/const with literal init and 0 writes.
//!   Pass 2 (Inline): Replace all read references with the literal.

use rustc_hash::FxHashMap;

use oxc::allocator::Allocator;
use oxc::ast::ast::{Expression, Program};
use oxc::semantic::{Scoping, SymbolId};

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::ast::extract;
use crate::ast::create;
use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};
use crate::scope::{query, resolve};
use crate::value::JsValue;

/// Constant propagation module.
pub struct ConstantPropagator;

impl Module for ConstantPropagator {
    fn name(&self) -> &'static str {
        "ConstantPropagator"
    }

    fn changes_symbols(&self) -> bool {
        // Replaces identifier references with literals — need scoping rebuild
        true
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        // Pass 1: Collect
        let mut collector = Collector::default();
        let scoping = traverse_mut(&mut collector, allocator, program, scoping, ());

        if collector.constants.is_empty() {
            return Ok(TransformResult { modifications: 0, scoping });
        }

        // Pass 2: Inline
        let mut inliner = Inliner { constants: collector.constants, modifications: 0 };
        let scoping = traverse_mut(&mut inliner, allocator, program, scoping, ());

        Ok(TransformResult { modifications: inliner.modifications, scoping })
    }
}

// ============================================================================
// Collector
// ============================================================================

#[derive(Default)]
struct Collector {
    constants: FxHashMap<SymbolId, JsValue>,
}

impl<'a> Traverse<'a, ()> for Collector {
    fn enter_variable_declarator(
        &mut self,
        node: &mut oxc::ast::ast::VariableDeclarator<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        let Some(init) = &node.init else { return };
        let Some(symbol_id) = resolve::get_declarator_symbol(node) else { return };
        let Some(value) = extract::js_value(init) else { return };

        // Must have no write references
        if query::has_writes(ctx.scoping(), symbol_id) {
            return;
        }

        self.constants.insert(symbol_id, value);
    }
}

// ============================================================================
// Inliner
// ============================================================================

struct Inliner {
    constants: FxHashMap<SymbolId, JsValue>,
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for Inliner {
    fn exit_expression(
        &mut self,
        expr: &mut Expression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        let Expression::Identifier(ident) = &*expr else { return };
        let Some(symbol_id) = resolve::get_reference_symbol(ctx.scoping(), ident) else { return };
        let Some(value) = self.constants.get(&symbol_id) else { return };

        *expr = create::from_js_value(value, &ctx.ast);
        self.modifications += 1;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn propagate(source: &str) -> (String, usize) {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs())
            .parse()
            .program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();

        let mut module = ConstantPropagator;
        let result = module.transform(&allocator, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    #[test]
    fn test_number() {
        let (code, mods) = propagate("var x = 42; console.log(x);");
        assert!(mods > 0);
        assert!(code.contains("console.log(42)"), "got: {code}");
    }

    #[test]
    fn test_string() {
        let (code, mods) = propagate("var msg = \"hello\"; alert(msg);");
        assert!(mods > 0);
        assert!(code.contains("alert(\"hello\")"), "got: {code}");
    }

    #[test]
    fn test_boolean() {
        let (code, mods) = propagate("const flag = true; if (flag) {}");
        assert!(mods > 0);
        assert!(code.contains("if (true)"), "got: {code}");
    }

    #[test]
    fn test_no_propagate_with_writes() {
        let (_, mods) = propagate("var x = 1; x = 2; console.log(x);");
        assert_eq!(mods, 0, "should not propagate reassigned var");
    }

    #[test]
    fn test_no_propagate_non_literal() {
        let (_, mods) = propagate("var x = foo(); console.log(x);");
        assert_eq!(mods, 0, "should not propagate call result");
    }

    #[test]
    fn test_multiple_refs() {
        let (code, mods) = propagate("var x = 5; f(x); g(x);");
        assert_eq!(mods, 2, "should inline both references");
        assert!(code.contains("f(5)"), "got: {code}");
        assert!(code.contains("g(5)"), "got: {code}");
    }
}
