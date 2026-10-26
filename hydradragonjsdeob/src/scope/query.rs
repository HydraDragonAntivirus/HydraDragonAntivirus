//! Reference counting and symbol queries.

use oxc::semantic::{Scoping, SymbolId};

/// Check if a symbol has any write references.
#[inline]
pub fn has_writes(scoping: &Scoping, symbol_id: SymbolId) -> bool {
    scoping
        .get_resolved_references(symbol_id)
        .any(|r| r.flags().is_write())
}

/// Check if a symbol has any read references.
#[inline]
pub fn has_reads(scoping: &Scoping, symbol_id: SymbolId) -> bool {
    scoping
        .get_resolved_references(symbol_id)
        .any(|r| r.flags().is_read())
}

/// Count read references to a symbol.
pub fn count_reads(scoping: &Scoping, symbol_id: SymbolId) -> usize {
    scoping
        .get_resolved_references(symbol_id)
        .filter(|r| r.flags().is_read())
        .count()
}

/// Count write references to a symbol.
pub fn count_writes(scoping: &Scoping, symbol_id: SymbolId) -> usize {
    scoping
        .get_resolved_references(symbol_id)
        .filter(|r| r.flags().is_write())
        .count()
}

/// Check if a symbol is declared with `const`.
#[inline]
pub fn is_const(scoping: &Scoping, symbol_id: SymbolId) -> bool {
    scoping.symbol_flags(symbol_id).is_const_variable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::resolve;
    use oxc::allocator::Allocator;
    use oxc::ast::ast::{Expression, Statement};
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    #[test]
    fn test_const_no_writes() {
        let source = "const x = 42; x; x;";
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, source, SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        // Find symbol for x
        if let Statement::ExpressionStatement(stmt) = &ret.program.body[1] {
            if let Expression::Identifier(ident) = &stmt.expression {
                let sym = resolve::get_reference_symbol(&scoping, ident).unwrap();
                assert!(is_const(&scoping, sym));
                assert!(!has_writes(&scoping, sym));
                assert!(has_reads(&scoping, sym));
                assert_eq!(count_reads(&scoping, sym), 2);
                assert_eq!(count_writes(&scoping, sym), 0);
            }
        }
    }

    #[test]
    fn test_let_with_writes() {
        let source = "let y = 1; y = 2; y;";
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, source, SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        // Find symbol via the last expression statement (read of y)
        if let Statement::ExpressionStatement(stmt) = &ret.program.body[2] {
            if let Expression::Identifier(ident) = &stmt.expression {
                let sym = resolve::get_reference_symbol(&scoping, ident).unwrap();
                assert!(!is_const(&scoping, sym));
                assert!(has_writes(&scoping, sym));
                assert!(has_reads(&scoping, sym));
                assert_eq!(count_writes(&scoping, sym), 1);
            }
        }
    }
}
