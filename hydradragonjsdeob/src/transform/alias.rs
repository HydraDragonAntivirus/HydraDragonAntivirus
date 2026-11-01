//! Alias inlining: `var e = Yp; e(445)` → `Yp(445)`.
//!
//! Two-pass: collect identifier-to-identifier aliases with 0 writes,
//! then replace all reads of the alias with the target identifier.
//! Transitive chains resolve through convergence loop iterations.

use oxc::ast::ast::*;
use oxc::allocator::GetAllocator;

use rustc_hash::FxHashMap;

use oxc::allocator::Allocator;
use oxc::ast::ast::{Expression, Program};
use oxc::semantic::{Scoping, SymbolId};
use oxc::span::SPAN;

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};
use crate::scope::{query, resolve};

/// Alias inlining module.
pub struct AliasInliner;

impl Module for AliasInliner {
    fn name(&self) -> &'static str {
        "AliasInliner"
    }

    fn changes_symbols(&self) -> bool {
        // Creates new IdentifierReferences that need scoping rebuild
        true
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        let mut collector = AliasCollector::default();
        let scoping = traverse_mut(&mut collector, allocator, program, scoping, ());

        if collector.aliases.is_empty() {
            return Ok(TransformResult { modifications: 0, scoping });
        }

        let mut inliner = Inliner { aliases: collector.aliases, modifications: 0 };
        let scoping = traverse_mut(&mut inliner, allocator, program, scoping, ());

        Ok(TransformResult { modifications: inliner.modifications, scoping })
    }
}

#[derive(Default)]
struct AliasCollector {
    aliases: FxHashMap<SymbolId, String>,
}

impl<'a> Traverse<'a, ()> for AliasCollector {
    fn enter_variable_declarator(
        &mut self,
        node: &mut oxc::ast::ast::VariableDeclarator<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        let Some(Expression::Identifier(target)) = &node.init else { return };

        // Skip well-known globals that aren't aliases
        if matches!(target.name.as_str(), "undefined" | "NaN" | "Infinity") {
            return;
        }

        let target_name = target.name.to_string();
        let Some(symbol_id) = resolve::get_declarator_symbol(node) else { return };

        if query::has_writes(ctx.scoping(), symbol_id) {
            return;
        }

        self.aliases.insert(symbol_id, target_name);
    }
}

struct Inliner {
    aliases: FxHashMap<SymbolId, String>,
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
        let Some(target_name) = self.aliases.get(&symbol_id) else { return };

        let arena_name = ctx.ast.allocator().alloc_str(target_name);
        let new_ident = IdentifierReference::boxed(SPAN, arena_name, &ctx.ast);
        *expr = Expression::Identifier(new_ident);
        self.modifications += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn inline(source: &str) -> (String, usize) {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs())
            .parse().program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
        let mut module = AliasInliner;
        let result = module.transform(&allocator, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    #[test]
    fn test_simple_alias() {
        let (code, mods) = inline("var e = Yp; console.log(e(445));");
        assert!(mods > 0);
        assert!(code.contains("Yp(445)"), "e → Yp: {code}");
    }

    #[test]
    fn test_no_inline_with_writes() {
        let (_, mods) = inline("var e = Yp; e = other; console.log(e(445));");
        assert_eq!(mods, 0);
    }

    #[test]
    fn test_no_inline_literal() {
        let (_, mods) = inline("var e = 42; console.log(e);");
        assert_eq!(mods, 0, "literal not an alias");
    }

    #[test]
    fn test_multiple() {
        let (code, mods) = inline("var a = X; var b = Y; console.log(a(1), b(2));");
        assert!(mods >= 2);
        assert!(code.contains("X(1)"), "got: {code}");
        assert!(code.contains("Y(2)"), "got: {code}");
    }

    #[test]
    fn test_skip_undefined() {
        let (_, mods) = inline("var x = undefined; console.log(x);");
        assert_eq!(mods, 0, "undefined is not an alias");
    }
}
