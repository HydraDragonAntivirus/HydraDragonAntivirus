//! Global value injection.
//!
//! Resolves global references from user-provided config.
//! `window.secret` → `"abc123"` when globals has `{"window": {"secret": "abc123"}}`.

use oxc::allocator::Allocator;
use oxc::ast::ast::{Expression, Program};
use oxc::semantic::Scoping;

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::ast::{create, extract};
use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};
use crate::scope::safety;
use crate::value::JsValue;

/// Global resolver module.
pub struct GlobalResolver {
    globals: std::collections::HashMap<String, serde_json::Value>,
}

impl GlobalResolver {
    pub fn new(globals: std::collections::HashMap<String, serde_json::Value>) -> Self {
        Self { globals }
    }
}

impl Module for GlobalResolver {
    fn name(&self) -> &'static str {
        "GlobalResolver"
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        if self.globals.is_empty() {
            return Ok(TransformResult { modifications: 0, scoping });
        }
        let mut visitor = GlobalVisitor { globals: &self.globals, modifications: 0 };
        let scoping = traverse_mut(&mut visitor, allocator, program, scoping, ());
        Ok(TransformResult { modifications: visitor.modifications, scoping })
    }
}

struct GlobalVisitor<'g> {
    globals: &'g std::collections::HashMap<String, serde_json::Value>,
    modifications: usize,
}

impl<'a, 'g> Traverse<'a, ()> for GlobalVisitor<'g> {
    fn exit_expression(
        &mut self,
        expr: &mut Expression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        // Resolve: global_name → value
        if let Expression::Identifier(ident) = &*expr {
            if !safety::is_global(ctx.scoping(), ident) { return; }
            let name = ident.name.as_str();
            if let Some(val) = self.globals.get(name) {
                if let Some(js_val) = json_to_jsvalue(val) {
                    *expr = create::from_js_value(&js_val, &ctx.ast);
                    self.modifications += 1;
                    return;
                }
            }
        }

        // Resolve: global_name.property → value (walk property chain)
        if let Expression::StaticMemberExpression(_) = &*expr {
            if let Some(val) = resolve_member_chain(expr, ctx.scoping(), self.globals) {
                *expr = create::from_js_value(&val, &ctx.ast);
                self.modifications += 1;
            }
        }
    }
}

/// Walk a member expression chain: `window.config.key` → lookup in globals.
fn resolve_member_chain(
    expr: &Expression,
    scoping: &Scoping,
    globals: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<JsValue> {
    // Collect the property chain
    let mut chain = Vec::new();
    let mut current = expr;

    loop {
        match current {
            Expression::StaticMemberExpression(m) => {
                chain.push(m.property.name.as_str());
                current = &m.object;
            }
            Expression::ComputedMemberExpression(m) => {
                let key = extract::string(&m.expression)?;
                chain.push(key);
                current = &m.object;
            }
            Expression::Identifier(ident) => {
                if !safety::is_global(scoping, ident) { return None; }
                chain.push(ident.name.as_str());
                break;
            }
            _ => return None,
        }
    }

    // Reverse to get root → leaf order
    chain.reverse();

    // Walk the JSON value
    let root_name = chain.first()?;
    let mut val = globals.get(*root_name)?;

    for key in &chain[1..] {
        val = val.get(key)?;
    }

    json_to_jsvalue(val)
}

fn json_to_jsvalue(val: &serde_json::Value) -> Option<JsValue> {
    match val {
        serde_json::Value::Number(n) => n.as_f64().map(JsValue::Number),
        serde_json::Value::String(s) => Some(JsValue::String(s.clone())),
        serde_json::Value::Bool(b) => Some(JsValue::Boolean(*b)),
        serde_json::Value::Null => Some(JsValue::Null),
        _ => None, // Objects/arrays can't be represented as JsValue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn resolve_globals(source: &str, globals: serde_json::Value) -> (String, usize) {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs()).parse().program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();

        let map: std::collections::HashMap<String, serde_json::Value> = globals
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut module = GlobalResolver::new(map);
        let result = module.transform(&allocator, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    #[test]
    fn test_simple_global() {
        let (code, mods) = resolve_globals(
            "console.log(SECRET);",
            serde_json::json!({"SECRET": "abc123"}),
        );
        assert!(mods > 0);
        assert!(code.contains("\"abc123\""), "got: {code}");
    }

    #[test]
    fn test_nested_property() {
        let (code, mods) = resolve_globals(
            "console.log(window.config.key);",
            serde_json::json!({"window": {"config": {"key": "value123"}}}),
        );
        assert!(mods > 0);
        assert!(code.contains("\"value123\""), "got: {code}");
    }

    #[test]
    fn test_no_resolve_declared() {
        // x is declared locally, not a global
        let (_, mods) = resolve_globals(
            "var x = 1; console.log(x);",
            serde_json::json!({"x": 999}),
        );
        assert_eq!(mods, 0, "should not resolve locally declared var");
    }

    #[test]
    fn test_number_global() {
        let (code, mods) = resolve_globals(
            "console.log(TIMEOUT);",
            serde_json::json!({"TIMEOUT": 5000}),
        );
        assert!(mods > 0);
        assert!(code.contains("5e3") || code.contains("5000"), "got: {code}");
    }
}
