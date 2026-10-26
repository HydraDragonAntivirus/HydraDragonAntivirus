//! Safety predicates for inlining and transformation decisions.

use oxc::ast::ast::IdentifierReference;
use oxc::semantic::{Scoping, SymbolId};

use super::query;
use super::resolve;

/// Check if a symbol is safe to inline.
///
/// A symbol is safe to inline if it is `const` or has no write references.
/// This is the minimum check — callers should also verify the initializer
/// is a suitable value (literal, side-effect-free, etc).
#[inline]
pub fn is_safe_to_inline(scoping: &Scoping, symbol_id: SymbolId) -> bool {
    query::is_const(scoping, symbol_id) || !query::has_writes(scoping, symbol_id)
}

/// Check if an identifier reference is a global (not declared in any scope).
///
/// Globals: `console`, `Math`, `window`, `atob`, etc.
#[inline]
pub fn is_global(scoping: &Scoping, ident: &IdentifierReference) -> bool {
    resolve::get_reference_symbol(scoping, ident).is_none()
}

/// Check if a symbol is unused (zero read references).
#[inline]
pub fn is_unused(scoping: &Scoping, symbol_id: SymbolId) -> bool {
    !query::has_reads(scoping, symbol_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::allocator::Allocator;
    use oxc::ast::ast::{Expression, Statement};
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    #[test]
    fn test_const_is_safe() {
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, "const x = 1; x;", SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        if let Statement::ExpressionStatement(stmt) = &ret.program.body[1] {
            if let Expression::Identifier(ident) = &stmt.expression {
                let sym = resolve::get_reference_symbol(&scoping, ident).unwrap();
                assert!(is_safe_to_inline(&scoping, sym));
            }
        }
    }

    #[test]
    fn test_written_is_not_safe() {
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, "let x = 1; x = 2; x;", SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        if let Statement::ExpressionStatement(stmt) = &ret.program.body[2] {
            if let Expression::Identifier(ident) = &stmt.expression {
                let sym = resolve::get_reference_symbol(&scoping, ident).unwrap();
                assert!(!is_safe_to_inline(&scoping, sym));
            }
        }
    }

    #[test]
    fn test_global_detection() {
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, "console; Math;", SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        if let Statement::ExpressionStatement(stmt) = &ret.program.body[0] {
            if let Expression::Identifier(ident) = &stmt.expression {
                assert!(is_global(&scoping, ident), "console should be global");
            }
        }
    }

    #[test]
    fn test_declared_is_not_global() {
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, "const x = 1; x;", SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        if let Statement::ExpressionStatement(stmt) = &ret.program.body[1] {
            if let Expression::Identifier(ident) = &stmt.expression {
                assert!(!is_global(&scoping, ident), "x is declared, not global");
            }
        }
    }

    #[test]
    fn test_unused_symbol() {
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, "const x = 1; const y = 2; y;", SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        // x is declared but never read
        if let Statement::VariableDeclaration(decl) = &ret.program.body[0] {
            let sym = resolve::get_binding_symbol(
                decl.declarations[0].id.get_binding_identifier().unwrap()
            ).unwrap();
            assert!(is_unused(&scoping, sym), "x should be unused");
        }

        // y is read once
        if let Statement::VariableDeclaration(decl) = &ret.program.body[1] {
            let sym = resolve::get_binding_symbol(
                decl.declarations[0].id.get_binding_identifier().unwrap()
            ).unwrap();
            assert!(!is_unused(&scoping, sym), "y should not be unused");
        }
    }
}
