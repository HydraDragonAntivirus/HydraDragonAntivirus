//! Dead code elimination: remove provably-unused declarations.
//!
//! `function f() { var x = 1; var y = 2; return y; }` → `function f() { var y = 2; return y; }`
//!
//! ## Safety contract
//!
//! A universal deobfuscator must produce code that is **still runnable** like the
//! original. The original may invoke a binding via mechanisms invisible to static
//! analysis: `eval`, `new Function`, `with`, computed property access on the global
//! object, runtime dispatch tables (`__dispatch__[idx]`), reflection, etc. We can
//! never *prove* a binding is unreachable.
//!
//! Therefore this pass is intentionally conservative:
//!
//! 1. **Function declarations are NEVER removed.** A 0-reference function may still
//!    be called via dispatch table or computed lookup. Removing one whole-program
//!    function can drop entire subtrees of nested helpers — this exact bug was
//!    observed wiping 7700 lines from kasada decompiled output.
//! 2. **Module/program-scope `var/let/const` are NEVER removed**, because:
//!    - `var` at module scope can still be observable via host hooks or stale
//!      tooling that opts out of strict module semantics;
//!    - the cost of being wrong (broken script) outweighs the benefit (slightly
//!      shorter file).
//! 3. **Function-/block-scope variable declarations** with 0 read references and a
//!    side-effect-free initializer ARE removed — within a function body the
//!    surface area is bounded by the parent function and OXC's symbol table is
//!    authoritative there.
//! 4. **Empty statements** are always removed.
//!
//! Vendor-specific aggressive DCE belongs in a target/locked module, not here.

use oxc::allocator::GetAllocator;
use oxc::allocator::Allocator;
use oxc::ast::ast::{Program, Statement};
use oxc::semantic::{Scoping, SymbolId};

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::ast::query;
use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};
use crate::scope::{query as scope_query, resolve};

/// Dead code elimination module. See module docs for the safety contract.
pub struct DeadCodeEliminator;

impl Module for DeadCodeEliminator {
    fn name(&self) -> &'static str {
        "DeadCodeEliminator"
    }

    fn changes_symbols(&self) -> bool {
        true
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        let mut visitor = DeadCodeVisitor { modifications: 0 };
        let scoping = traverse_mut(&mut visitor, allocator, program, scoping, ());
        Ok(TransformResult { modifications: visitor.modifications, scoping })
    }
}

struct DeadCodeVisitor {
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for DeadCodeVisitor {
    fn exit_statements(
        &mut self,
        stmts: &mut oxc::allocator::Vec<'a, Statement<'a>>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        let allocator = &ctx.ast.allocator();
        let mut new_stmts = oxc::allocator::Vec::new_in(&ctx.ast);
        let mut removed = 0;

        for stmt in stmts.drain(..) {
            if should_remove(&stmt, ctx.scoping()) {
                removed += 1;
                continue;
            }
            new_stmts.push(stmt);
        }

        *stmts = new_stmts;
        let _ = allocator;
        self.modifications += removed;
    }
}

/// True if the symbol is declared at the program (root) scope.
#[inline]
fn is_module_scope(scoping: &Scoping, symbol_id: SymbolId) -> bool {
    scoping.symbol_scope_id(symbol_id) == scoping.root_scope_id()
}

/// Check if a statement should be removed.
///
/// See the module docs for the safety contract this enforces.
fn should_remove(stmt: &Statement, scoping: &Scoping) -> bool {
    match stmt {
        Statement::VariableDeclaration(decl) => {
            // All declarators must be eligible: declared at non-root scope,
            // 0 read references, side-effect-free init.
            decl.declarations.iter().all(|d| {
                let Some(symbol_id) = resolve::get_declarator_symbol(d) else {
                    return false;
                };
                // Safety: never remove module/program-scope declarations.
                if is_module_scope(scoping, symbol_id) {
                    return false;
                }
                if scope_query::has_reads(scoping, symbol_id) {
                    return false;
                }
                d.init.as_ref().is_none_or(|init| query::is_side_effect_free(init))
            })
        }
        // Function declarations are intentionally NEVER removed — see module docs.
        // The 0-reference check is unsound in the presence of dispatch tables,
        // eval, computed lookups, reflection, etc. Universal deobfuscation must
        // preserve callable definitions; vendor-specific pruning belongs in a
        // locked module.
        Statement::FunctionDeclaration(_) => false,
        Statement::EmptyStatement(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn eliminate(source: &str) -> (String, usize) {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs())
            .parse()
            .program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();

        let mut module = DeadCodeEliminator;
        let result = module.transform(&allocator, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    // ── Module-scope safety: nothing at the program root must be removed ──

    #[test]
    fn test_keep_module_scope_unused_var() {
        // Module-scope `var` is never removed even when statically unread —
        // it may be observable via host hooks or runtime reflection.
        let (code, mods) = eliminate("var x = 1; var y = 2; console.log(y);");
        assert_eq!(mods, 0, "module-scope vars must be preserved");
        assert!(code.contains("var x"), "should keep module-scope x: {code}");
        assert!(code.contains("var y"), "should keep module-scope y: {code}");
    }

    #[test]
    fn test_keep_unused_function_declaration() {
        // The kasada bug: 552 dispatch-called functions had 0 static refs.
        // Removing them dropped 7700 lines of executable code. Never again.
        let (code, mods) = eliminate("function unused() {} console.log(1);");
        assert_eq!(mods, 0, "function declarations must never be removed");
        assert!(code.contains("function unused"), "must preserve unused: {code}");
    }

    #[test]
    fn test_keep_used_function() {
        let (code, _) = eliminate("function used() {} used();");
        assert!(code.contains("function used"), "should keep used function: {code}");
    }

    #[test]
    fn test_keep_side_effectful_module_var() {
        let (code, mods) = eliminate("var x = foo(); console.log(1);");
        assert_eq!(mods, 0, "should not remove side-effectful init");
        assert!(code.contains("foo()"), "got: {code}");
    }

    // ── Function-scope DCE: bounded surface, safe to prune ──

    #[test]
    fn test_remove_function_scope_unused_var() {
        let (code, mods) = eliminate(
            "function f() { var x = 1; var y = 2; return y; }"
        );
        assert!(mods > 0, "function-scope unused var should be removed");
        assert!(!code.contains("var x"), "should remove function-scope x: {code}");
        assert!(code.contains("var y"), "should keep used y: {code}");
    }

    #[test]
    fn test_keep_function_scope_side_effect_var() {
        let (code, mods) = eliminate(
            "function f() { var x = foo(); return 1; }"
        );
        assert_eq!(mods, 0, "side-effectful init must be preserved");
        assert!(code.contains("foo()"), "got: {code}");
    }

    #[test]
    fn test_keep_nested_function_declaration() {
        // Even nested, function declarations are preserved — they may be
        // referenced through dispatch.
        let (code, mods) = eliminate(
            "function outer() { function helper() {} return 1; }"
        );
        assert_eq!(mods, 0, "nested function declarations must be preserved");
        assert!(code.contains("function helper"), "got: {code}");
    }

    #[test]
    fn test_remove_empty_statement() {
        let (code, mods) = eliminate("function f() { ;;; return 1; }");
        assert!(mods > 0, "empty statements always removable");
        assert!(!code.contains(";;"), "got: {code}");
    }
}
