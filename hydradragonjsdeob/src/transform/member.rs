//! Member simplification: `obj["property"]` → `obj.property`.
//!
//! Converts computed member access with string literal keys to static
//! member access when the key is a valid JavaScript identifier.

use oxc::ast::ast::*;
use oxc::allocator::GetAllocator;

use oxc::allocator::Allocator;
use oxc::ast::ast::{Expression, Program};
use oxc::semantic::Scoping;
use oxc::span::SPAN;

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::ast::extract;
use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};

/// Member simplification module.
pub struct MemberSimplifier;

impl Module for MemberSimplifier {
    fn name(&self) -> &'static str {
        "MemberSimplifier"
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        let mut visitor = MemberVisitor { modifications: 0 };
        let scoping = traverse_mut(&mut visitor, allocator, program, scoping, ());
        Ok(TransformResult { modifications: visitor.modifications, scoping })
    }
}

struct MemberVisitor {
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for MemberVisitor {
    fn exit_expression(
        &mut self,
        expr: &mut Expression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        // Check eligibility immutably first
        let key_str = {
            let Expression::ComputedMemberExpression(computed) = &*expr else { return };
            let Some(key) = extract::string(&computed.expression) else { return };
            if !is_valid_identifier(key) { return; }
            key.to_string() // own the string before we mutate
        };

        // Allocate the key in the arena so it has lifetime 'a
        let arena_key = ctx.ast.allocator().alloc_str(&key_str);

        // Now mutate
        let Expression::ComputedMemberExpression(computed) = expr else { return };
        let object = std::mem::replace(
            &mut computed.object,
            Expression::new_null_literal(SPAN, &ctx.ast),
        );

        let property = IdentifierName::new(SPAN, arena_key, &ctx.ast);
        let member = StaticMemberExpression::boxed(SPAN, object, property, false, &ctx.ast);
        *expr = Expression::StaticMemberExpression(member);
        self.modifications += 1;
    }
}

/// Check if a string is a valid JavaScript identifier.
fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() { return false; }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' && first != '$' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn simplify(source: &str) -> (String, usize) {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs())
            .parse()
            .program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();

        let mut module = MemberSimplifier;
        let result = module.transform(&allocator, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    #[test]
    fn test_bracket_to_dot() {
        let (code, mods) = simplify("obj[\"property\"];");
        assert!(mods > 0);
        assert!(code.contains("obj.property"), "got: {code}");
        assert!(!code.contains("[\"property\"]"), "got: {code}");
    }

    #[test]
    fn test_keep_numeric_key() {
        let (code, mods) = simplify("arr[0];");
        assert_eq!(mods, 0, "should not convert numeric key");
        assert!(code.contains("[0]"), "got: {code}");
    }

    #[test]
    fn test_keep_invalid_identifier() {
        let (code, mods) = simplify("obj[\"has-dash\"];");
        assert_eq!(mods, 0);
        assert!(code.contains("[\"has-dash\"]"), "got: {code}");
    }

    #[test]
    fn test_keep_keyword_like() {
        let (code, mods) = simplify("obj[\"valid_key\"];");
        assert!(mods > 0);
        assert!(code.contains("obj.valid_key"), "got: {code}");
    }
}
