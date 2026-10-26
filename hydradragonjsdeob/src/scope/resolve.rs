//! Symbol resolution — safe ID extraction from AST nodes.
//!
//! Every function uses `.get()` on `Cell<Option<_>>`. Never panics.

use oxc::ast::ast::{
    BindingIdentifier, Function, IdentifierReference, VariableDeclarator,
};
use oxc::semantic::{Scoping, SymbolId};

/// Resolve an identifier reference to its declared symbol.
///
/// Returns `None` for global/unresolved references.
#[inline]
pub fn get_reference_symbol(scoping: &Scoping, ident: &IdentifierReference) -> Option<SymbolId> {
    let ref_id = ident.reference_id.get()?;
    scoping.get_reference(ref_id).symbol_id()
}

/// Get symbol ID from a binding identifier (declaration site).
#[inline]
pub fn get_binding_symbol(binding: &BindingIdentifier) -> Option<SymbolId> {
    binding.symbol_id.get()
}

/// Get symbol ID from a variable declarator.
///
/// Traverses: declarator → binding pattern → binding identifier → symbol ID.
#[inline]
pub fn get_declarator_symbol(decl: &VariableDeclarator) -> Option<SymbolId> {
    decl.id.get_binding_identifier().and_then(|b| b.symbol_id.get())
}

/// Get symbol ID from a named function.
#[inline]
pub fn get_function_symbol(func: &Function) -> Option<SymbolId> {
    func.id.as_ref().and_then(|id| id.symbol_id.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::allocator::Allocator;
    use oxc::ast::ast::Statement;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    #[test]
    fn test_resolve_const() {
        let source = "const x = 42; x;";
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, source, SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        // The second statement is an expression statement with identifier "x"
        if let Statement::ExpressionStatement(stmt) = &ret.program.body[1] {
            if let oxc::ast::ast::Expression::Identifier(ident) = &stmt.expression {
                let sym = get_reference_symbol(&scoping, ident);
                assert!(sym.is_some(), "should resolve const x");
            }
        }
    }

    #[test]
    fn test_global_is_none() {
        let source = "console.log(1);";
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, source, SourceType::mjs()).parse();
        let scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        if let Statement::ExpressionStatement(stmt) = &ret.program.body[0] {
            if let oxc::ast::ast::Expression::CallExpression(call) = &stmt.expression {
                if let oxc::ast::ast::Expression::StaticMemberExpression(member) = &call.callee {
                    if let oxc::ast::ast::Expression::Identifier(ident) = &member.object {
                        let sym = get_reference_symbol(&scoping, ident);
                        assert!(sym.is_none(), "console should be unresolved (global)");
                    }
                }
            }
        }
    }

    #[test]
    fn test_get_declarator_symbol() {
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, "const x = 1;", SourceType::mjs()).parse();
        let _scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        if let Statement::VariableDeclaration(decl) = &ret.program.body[0] {
            let sym = get_declarator_symbol(&decl.declarations[0]);
            assert!(sym.is_some(), "declarator should have symbol ID");
        }
    }

    #[test]
    fn test_get_function_symbol() {
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, "function foo() {}", SourceType::mjs()).parse();
        let _scoping = SemanticBuilder::new().build(&ret.program).semantic.into_scoping();

        if let Statement::FunctionDeclaration(func) = &ret.program.body[0] {
            let sym = get_function_symbol(func);
            assert!(sym.is_some(), "named function should have symbol ID");
        }
    }
}
