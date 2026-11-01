//! AST-to-text conversion. Thin wrapper around OXC Codegen.
//!
//! Used for eval caching keys and debug output.

use oxc::ast::ast::{Expression, Function, Statement};
use oxc::codegen::{Codegen, Context, Gen, GenExpr};
use oxc::syntax::precedence::Precedence;

/// Generate JavaScript source from a statement.
pub fn stmt_to_code(stmt: &Statement) -> String {
    let mut cg = Codegen::new();
    stmt.print(&mut cg, Context::empty());
    cg.into_source_text()
}

/// Generate JavaScript source from an expression.
pub fn expr_to_code(expr: &Expression) -> String {
    let mut cg = Codegen::new();
    expr.print_expr(&mut cg, Precedence::Lowest, Context::empty());
    cg.into_source_text()
}

/// Generate JavaScript source from a function.
pub fn function_to_code(func: &Function) -> String {
    let mut cg = Codegen::new();
    func.print(&mut cg, Context::empty());
    cg.into_source_text()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::allocator::Allocator;
    use oxc::parser::Parser;
    use oxc::span::SourceType;

    #[test]
    fn test_expr_to_code() {
        let a = Allocator::default();
        let expr = Parser::new(&a, "1 + 2", SourceType::mjs())
            .parse_expression()
            .unwrap();
        let code = expr_to_code(&expr);
        assert_eq!(code, "1 + 2");
    }

    #[test]
    fn test_stmt_to_code() {
        let a = Allocator::default();
        let program = Parser::new(&a, "var x = 42;", SourceType::mjs()).parse().program;
        let stmt = &program.body[0];
        let code = stmt_to_code(stmt);
        assert!(code.contains("var x = 42"), "got: {code}");
    }
}
