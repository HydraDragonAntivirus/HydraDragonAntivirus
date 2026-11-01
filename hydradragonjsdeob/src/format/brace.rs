//! Brace wrapping: ensure if/else/for/while bodies have `{}` blocks.
//!
//! `if (x) return 1;` → `if (x) { return 1; }`

use oxc::allocator::Allocator;
use oxc::ast::ast::{Program, Statement};
use oxc::semantic::Scoping;
use oxc::span::SPAN;

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};

/// Brace wrapping module.
pub struct BraceWrapper;

impl Module for BraceWrapper {
    fn name(&self) -> &'static str {
        "BraceWrapper"
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        let mut visitor = BraceVisitor { modifications: 0 };
        let scoping = traverse_mut(&mut visitor, allocator, program, scoping, ());
        Ok(TransformResult { modifications: visitor.modifications, scoping })
    }
}

struct BraceVisitor {
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for BraceVisitor {
    fn exit_statement(
        &mut self,
        stmt: &mut Statement<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        match stmt {
            Statement::IfStatement(if_stmt) => {
                if wrap_if_needed(&mut if_stmt.consequent, ctx) {
                    self.modifications += 1;
                }
                if let Some(alt) = &mut if_stmt.alternate {
                    // Don't wrap `else if`
                    if !matches!(alt, Statement::IfStatement(_)) && wrap_if_needed(alt, ctx) {
                        self.modifications += 1;
                    }
                }
            }
            Statement::WhileStatement(w) => {
                if wrap_if_needed(&mut w.body, ctx) {
                    self.modifications += 1;
                }
            }
            Statement::ForStatement(f) => {
                if wrap_if_needed(&mut f.body, ctx) {
                    self.modifications += 1;
                }
            }
            Statement::ForInStatement(f) => {
                if wrap_if_needed(&mut f.body, ctx) {
                    self.modifications += 1;
                }
            }
            Statement::ForOfStatement(f) => {
                if wrap_if_needed(&mut f.body, ctx) {
                    self.modifications += 1;
                }
            }
            _ => {}
        }
    }
}

/// Wrap a statement in a block if it isn't one already. Returns true if wrapped.
fn wrap_if_needed<'a>(stmt: &mut Statement<'a>, ctx: &mut TraverseCtx<'a, ()>) -> bool {
    if matches!(stmt, Statement::BlockStatement(_)) {
        return false;
    }

    let inner = std::mem::replace(stmt, Statement::new_empty_statement(SPAN, &ctx.ast));
    let mut stmts = oxc::allocator::Vec::new_in(&ctx.ast);
    stmts.push(inner);
    *stmt = Statement::new_block_statement(SPAN, stmts, &ctx.ast);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn wrap(source: &str) -> String {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs()).parse().program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
        let mut module = BraceWrapper;
        module.transform(&allocator, &mut program, scoping).unwrap();
        Codegen::new().build(&program).code
    }

    #[test]
    fn test_if_body() {
        let code = wrap("if (x) return 1;");
        assert!(code.contains("{"), "should add braces: {code}");
    }

    #[test]
    fn test_already_braced() {
        let code = wrap("if (x) { return 1; }");
        assert!(code.contains("{"), "should keep braces: {code}");
    }

    #[test]
    fn test_while_body() {
        let code = wrap("while (x) x--;");
        assert!(code.contains("{"), "should wrap while body: {code}");
    }

    #[test]
    fn test_else_if_not_wrapped() {
        let code = wrap("if (a) {} else if (b) {}");
        // else if should not become else { if }
        assert!(!code.contains("else {\n\tif") && !code.contains("else {\n  if"), "got: {code}");
    }
}
