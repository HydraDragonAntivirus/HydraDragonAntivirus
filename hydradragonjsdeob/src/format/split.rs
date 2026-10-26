//! Statement splitting: `var a = 1, b = 2` → `var a = 1; var b = 2;`

use oxc::ast::ast::VariableDeclaration;

use oxc::allocator::Allocator;
use oxc::ast::ast::{Program, Statement};
use oxc::semantic::Scoping;
use oxc::span::SPAN;

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};

/// Statement splitting module.
pub struct StatementSplitter;

impl Module for StatementSplitter {
    fn name(&self) -> &'static str {
        "StatementSplitter"
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
        let mut visitor = SplitVisitor { modifications: 0 };
        let scoping = traverse_mut(&mut visitor, allocator, program, scoping, ());
        Ok(TransformResult { modifications: visitor.modifications, scoping })
    }
}

struct SplitVisitor {
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for SplitVisitor {
    fn exit_statements(
        &mut self,
        stmts: &mut oxc::allocator::Vec<'a, Statement<'a>>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        let mut new_stmts = oxc::allocator::Vec::new_in(&ctx.ast);
        let mut split_count = 0;

        for stmt in stmts.drain(..) {
            match &stmt {
                Statement::VariableDeclaration(decl) if decl.declarations.len() > 1 => {
                    // Split into individual declarations
                    let Statement::VariableDeclaration(decl) = stmt else { unreachable!() };
                    let kind = decl.kind;
                    for declarator in decl.unbox().declarations.into_iter() {
                        let mut decls = oxc::allocator::Vec::new_in(&ctx.ast);
                        decls.push(declarator);
                        new_stmts.push(Statement::VariableDeclaration(
                            VariableDeclaration::boxed(SPAN, kind, decls, false, &ctx.ast),
                        ));
                    }
                    split_count += 1;
                }
                _ => new_stmts.push(stmt),
            }
        }

        *stmts = new_stmts;
        self.modifications += split_count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn split(source: &str) -> (String, usize) {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs()).parse().program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
        let mut module = StatementSplitter;
        let result = module.transform(&allocator, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    #[test]
    fn test_split_var() {
        let (code, mods) = split("var a = 1, b = 2;");
        assert!(mods > 0);
        assert!(code.contains("var a = 1;"), "got: {code}");
        assert!(code.contains("var b = 2;"), "got: {code}");
    }

    #[test]
    fn test_split_const() {
        let (code, mods) = split("const x = 1, y = 2;");
        assert!(mods > 0);
        assert!(code.contains("const x = 1;"), "got: {code}");
        assert!(code.contains("const y = 2;"), "got: {code}");
    }

    #[test]
    fn test_single_not_split() {
        let (_, mods) = split("var a = 1;");
        assert_eq!(mods, 0);
    }
}
