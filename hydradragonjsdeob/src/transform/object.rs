//! Object/array property resolution.
//!
//! `var t = {F: 445}; t.F` → `445`
//! `var a = [10, 20]; a[1]` → `20`
//!
//! Two-pass: collect constant objects/arrays, resolve property access.

use rustc_hash::{FxHashMap, FxHashSet};

use oxc::allocator::Allocator;
use oxc::ast::ast::{Expression, ObjectPropertyKind, Program, PropertyKey};
use oxc::semantic::{Scoping, SymbolId};

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::ast::{create, extract};
use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};
use crate::scope::{query, resolve};
use crate::value::JsValue;
use crate::value::coerce::number_to_string;

/// Object property resolution module.
pub struct ObjectPropResolver;

impl Module for ObjectPropResolver {
    fn name(&self) -> &'static str {
        "ObjectPropResolver"
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        let mut collector = Collector::default();
        let scoping = traverse_mut(&mut collector, allocator, program, scoping, ());

        // Remove mutated symbols
        for sym in &collector.mutated {
            collector.objects.remove(sym);
            collector.arrays.remove(sym);
        }

        if collector.objects.is_empty() && collector.arrays.is_empty() {
            return Ok(TransformResult { modifications: 0, scoping });
        }

        let mut resolver = Resolver {
            objects: collector.objects,
            arrays: collector.arrays,
            modifications: 0,
        };
        let scoping = traverse_mut(&mut resolver, allocator, program, scoping, ());

        Ok(TransformResult { modifications: resolver.modifications, scoping })
    }
}

#[derive(Default)]
struct Collector {
    objects: FxHashMap<SymbolId, FxHashMap<String, JsValue>>,
    arrays: FxHashMap<SymbolId, Vec<JsValue>>,
    mutated: FxHashSet<SymbolId>,
}

impl<'a> Traverse<'a, ()> for Collector {
    fn enter_assignment_expression(
        &mut self,
        node: &mut oxc::ast::ast::AssignmentExpression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        let target_obj = match &node.left {
            oxc::ast::ast::AssignmentTarget::StaticMemberExpression(m) => Some(&m.object),
            oxc::ast::ast::AssignmentTarget::ComputedMemberExpression(m) => Some(&m.object),
            _ => None,
        };
        if let Some(Expression::Identifier(id)) = target_obj {
            if let Some(sym) = resolve::get_reference_symbol(ctx.scoping(), id) {
                self.mutated.insert(sym);
            }
        }
    }

    fn enter_update_expression(
        &mut self,
        node: &mut oxc::ast::ast::UpdateExpression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        // Catch ++obj.x, obj.x--, etc.
        let target_obj = match &node.argument {
            oxc::ast::ast::SimpleAssignmentTarget::StaticMemberExpression(m) => Some(&m.object),
            oxc::ast::ast::SimpleAssignmentTarget::ComputedMemberExpression(m) => Some(&m.object),
            _ => None,
        };
        if let Some(Expression::Identifier(id)) = target_obj {
            if let Some(sym) = resolve::get_reference_symbol(ctx.scoping(), id) {
                self.mutated.insert(sym);
            }
        }
    }

    fn enter_unary_expression(
        &mut self,
        node: &mut oxc::ast::ast::UnaryExpression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        // Catch delete obj.x
        if node.operator != oxc::ast::ast::UnaryOperator::Delete {
            return;
        }
        let target_obj = match &node.argument {
            Expression::StaticMemberExpression(m) => Some(&m.object),
            Expression::ComputedMemberExpression(m) => Some(&m.object),
            _ => None,
        };
        if let Some(Expression::Identifier(id)) = target_obj {
            if let Some(sym) = resolve::get_reference_symbol(ctx.scoping(), id) {
                self.mutated.insert(sym);
            }
        }
    }

    fn enter_call_expression(
        &mut self,
        node: &mut oxc::ast::ast::CallExpression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        // Catch mutating method calls: arr.push(), arr.splice(), obj.assign(), etc.
        const MUTATING_METHODS: &[&str] = &[
            "push", "pop", "shift", "unshift", "splice", "sort", "reverse", "fill", "copyWithin",
        ];
        if let Expression::StaticMemberExpression(m) = &node.callee {
            if MUTATING_METHODS.contains(&m.property.name.as_str()) {
                if let Expression::Identifier(id) = &m.object {
                    if let Some(sym) = resolve::get_reference_symbol(ctx.scoping(), id) {
                        self.mutated.insert(sym);
                    }
                }
            }
        }
    }

    fn enter_variable_declarator(
        &mut self,
        node: &mut oxc::ast::ast::VariableDeclarator<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        let Some(init) = &node.init else { return };
        let Some(symbol_id) = resolve::get_declarator_symbol(node) else { return };

        if query::has_writes(ctx.scoping(), symbol_id) {
            return;
        }

        match init {
            Expression::ObjectExpression(obj) => {
                let mut props = FxHashMap::default();
                for prop in &obj.properties {
                    let ObjectPropertyKind::ObjectProperty(p) = prop else { return; };
                    let Some(key) = get_key_str(&p.key) else { return; };
                    let Some(val) = extract::js_value(&p.value) else { return; };
                    props.insert(key, val);
                }
                if !props.is_empty() {
                    self.objects.insert(symbol_id, props);
                }
            }
            Expression::ArrayExpression(arr) => {
                let elements: Option<Vec<JsValue>> = arr.elements.iter()
                    .map(|el| el.as_expression().and_then(extract::js_value))
                    .collect();
                if let Some(elems) = elements {
                    if !elems.is_empty() {
                        self.arrays.insert(symbol_id, elems);
                    }
                }
            }
            _ => {}
        }
    }
}

struct Resolver {
    objects: FxHashMap<SymbolId, FxHashMap<String, JsValue>>,
    arrays: FxHashMap<SymbolId, Vec<JsValue>>,
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for Resolver {
    fn exit_expression(
        &mut self,
        expr: &mut Expression<'a>,
        ctx: &mut TraverseCtx<'a, ()>,
    ) {
        match &*expr {
            Expression::StaticMemberExpression(_) => self.try_resolve_static(expr, ctx),
            Expression::ComputedMemberExpression(_) => self.try_resolve_computed(expr, ctx),
            _ => {}
        }
    }
}

impl Resolver {
    fn try_resolve_static<'a>(&mut self, expr: &mut Expression<'a>, ctx: &mut TraverseCtx<'a, ()>) {
        let val = {
            let Expression::StaticMemberExpression(m) = &*expr else { return; };
            let Expression::Identifier(id) = &m.object else { return; };
            let Some(sym) = resolve::get_reference_symbol(ctx.scoping(), id) else { return; };
            let prop = m.property.name.as_str();

            if let Some(props) = self.objects.get(&sym) {
                props.get(prop).cloned()
            } else if let Some(elems) = self.arrays.get(&sym) {
                if prop == "length" { Some(JsValue::Number(elems.len() as f64)) } else { None }
            } else {
                None
            }
        };
        if let Some(val) = val {
            *expr = create::from_js_value(&val, &ctx.ast);
            self.modifications += 1;
        }
    }

    fn try_resolve_computed<'a>(&mut self, expr: &mut Expression<'a>, ctx: &mut TraverseCtx<'a, ()>) {
        let val = {
            let Expression::ComputedMemberExpression(m) = &*expr else { return; };
            let Expression::Identifier(id) = &m.object else { return; };
            let Some(sym) = resolve::get_reference_symbol(ctx.scoping(), id) else { return; };

            if let Some(props) = self.objects.get(&sym) {
                extract::string(&m.expression).and_then(|k| props.get(k).cloned())
            } else if let Some(elems) = self.arrays.get(&sym) {
                extract::number(&m.expression).and_then(|idx| elems.get(idx as usize).cloned())
            } else {
                None
            }
        };
        if let Some(val) = val {
            *expr = create::from_js_value(&val, &ctx.ast);
            self.modifications += 1;
        }
    }
}

fn get_key_str(key: &PropertyKey) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => Some(s.value.to_string()),
        PropertyKey::NumericLiteral(n) => Some(number_to_string(n.value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn resolve_obj(source: &str) -> (String, usize) {
        let allocator = Allocator::default();
        let mut program = Parser::new(&allocator, source, SourceType::mjs()).parse().program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
        let mut module = ObjectPropResolver;
        let result = module.transform(&allocator, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    #[test]
    fn test_object_static() {
        let (code, mods) = resolve_obj("var t = {F: 445, H: 417}; console.log(t.F);");
        assert!(mods > 0);
        assert!(code.contains("445"), "t.F → 445: {code}");
    }

    #[test]
    fn test_object_computed() {
        let (code, mods) = resolve_obj("var t = {F: 445}; console.log(t[\"F\"]);");
        assert!(mods > 0);
        assert!(code.contains("445"), "got: {code}");
    }

    #[test]
    fn test_array_index() {
        let (code, mods) = resolve_obj("var a = [10, 20, 30]; console.log(a[1]);");
        assert!(mods > 0);
        assert!(code.contains("20"), "a[1] → 20: {code}");
    }

    #[test]
    fn test_array_length() {
        let (code, mods) = resolve_obj("var a = [1, 2, 3]; console.log(a.length);");
        assert!(mods > 0);
        assert!(code.contains("3"), "got: {code}");
    }

    #[test]
    fn test_no_resolve_mutated() {
        let (code, mods) = resolve_obj("var t = {x: 1}; t.x = 2; console.log(t.x);");
        assert_eq!(mods, 0);
        assert!(code.contains("t.x"), "got: {code}");
    }
}
