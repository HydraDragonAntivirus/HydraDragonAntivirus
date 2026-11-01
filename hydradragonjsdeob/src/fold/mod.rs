//! Layer 3: Static expression folding.
//!
//! One file per AST Expression/Statement variant. Pure Rust evaluation —
//! no scope analysis, no Node.js. Depends on value/ + ast/.
//!
//! The visitor dispatches by Expression variant to sub-modules.
//! Each sub-module's `try_fold` returns `Option<usize>`:
//!   - `None` — can't fold this expression
//!   - `Some(n)` — folded, n modifications made (usually 1)

pub mod binary;
pub mod unary;
pub mod logical;
pub mod conditional;
pub mod call;
pub mod sequence;
pub mod statement;
pub mod template;

// ============================================================================
// Imports
// ============================================================================

use oxc::allocator::Allocator;
use oxc::ast::ast::{Expression, Statement};
use oxc::semantic::Scoping;

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};

// ============================================================================
// Module implementation
// ============================================================================

/// Layer 3 module: folds all statically-known expressions in pure Rust.
pub struct StaticFolder;

impl Module for StaticFolder {
    fn name(&self) -> &'static str {
        "StaticFolder"
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut oxc::ast::ast::Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        let mut visitor = FoldVisitor::default();
        let scoping = traverse_mut(&mut visitor, allocator, program, scoping, ());
        Ok(TransformResult {
            modifications: visitor.modifications,
            scoping,
        })
    }
}

// ============================================================================
// Visitor
// ============================================================================

#[derive(Default)]
struct FoldVisitor {
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for FoldVisitor {
    fn exit_expression(
        &mut self,
        expr: &mut Expression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        // Skip leaf literals — already fully reduced.
        if is_leaf_literal(expr) {
            return;
        }

        // Dispatch to appropriate folder based on expression type.
        // Each folder returns Some(n) if it made n modifications.
        // We dispatch by type first to avoid unnecessary work.
        let folded = match expr {
            Expression::BinaryExpression(_) => binary::try_fold(expr, ctx),
            Expression::UnaryExpression(_) => unary::try_fold(expr, ctx),
            Expression::LogicalExpression(_) => logical::try_fold(expr, ctx),
            Expression::ConditionalExpression(_) => conditional::try_fold(expr, ctx),
            Expression::CallExpression(_) => call::try_fold(expr, ctx),
            Expression::SequenceExpression(_) => sequence::try_fold(expr, ctx),
            Expression::TemplateLiteral(_) => template::try_fold(expr, ctx),
            _ => None,
        };

        if let Some(n) = folded {
            self.modifications += n;
        }
    }

    fn exit_statement(
        &mut self,
        stmt: &mut Statement<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        self.modifications += statement::try_fold(stmt, ctx);
    }

    fn exit_statements(
        &mut self,
        stmts: &mut oxc::allocator::Vec<'a, Statement<'a>>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        self.modifications += statement::clean(stmts, ctx);
    }
}

/// Check if an expression is a leaf literal that needs no folding.
fn is_leaf_literal(expr: &Expression) -> bool {
    match expr {
        Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "undefined" | "Infinity" | "NaN")
        }
        _ => false,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
pub(crate) mod test_utils {
    use oxc::allocator::Allocator;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    /// Parse → fold → codegen. Returns the output source.
    pub fn fold(source: &str) -> String {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs())
            .parse()
            .program;
        let scoping = SemanticBuilder::new()
            .build(&program)
            .semantic
            .into_scoping();

        let mut folder = super::FoldVisitor::default();
        oxc_traverse::traverse_mut(&mut folder, &allocator, &mut program, scoping, ());

        Codegen::new().build(&program).code
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::fold;

    #[test]
    fn test_leaf_literals_unchanged() {
        assert_eq!(fold("42;\n").trim(), "42;");
        assert_eq!(fold("\"hello\";\n").trim(), "\"hello\";");
        assert_eq!(fold("true;\n").trim(), "true;");
    }
}
