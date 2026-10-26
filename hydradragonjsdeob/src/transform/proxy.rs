//! Proxy function inlining.
//!
//! `function c(r, v) { return Hs(v - -966, r); }`
//! `c(-679, -602)` → `Hs(-602 - -966, -679)`
//!
//! Two-pass: collect single-return-call functions, inline call sites.
//! Uses proper AST-based parameter substitution to avoid corrupting strings.

use oxc::allocator::GetAllocator;
use rustc_hash::FxHashMap;

use oxc::allocator::{Allocator, CloneIn};
use oxc::ast::ast::*;
use oxc::ast::builder::AstBuilder;
use oxc::ast_visit::VisitMut;
use oxc::semantic::{Scoping, SymbolId};
use oxc::span::SPAN;

use oxc_traverse::{Traverse, TraverseCtx, traverse_mut};

use crate::ast::codegen;
use crate::engine::error::Result;
use crate::engine::module::{Module, TransformResult};
use crate::scope::{query, resolve};

/// Proxy function inliner module.
pub struct ProxyInliner;

impl Module for ProxyInliner {
    fn name(&self) -> &'static str { "ProxyInliner" }

    fn changes_symbols(&self) -> bool {
        // Creates new identifier references
        true
    }

    fn transform<'a>(
        &mut self,
        allocator: &'a Allocator,
        program: &mut Program<'a>,
        scoping: Scoping,
    ) -> Result<TransformResult> {
        let mut collector = Collector::default();
        let scoping = traverse_mut(&mut collector, allocator, program, scoping, ());
        if collector.proxies.is_empty() {
            return Ok(TransformResult { modifications: 0, scoping });
        }
        let mut inliner = Inliner { proxies: collector.proxies, modifications: 0 };
        let scoping = traverse_mut(&mut inliner, allocator, program, scoping, ());
        Ok(TransformResult { modifications: inliner.modifications, scoping })
    }
}

/// Information about a proxy function (stored as source code to avoid lifetime issues).
struct ProxyInfo {
    /// Parameter names in order
    params: Vec<String>,
    /// The return expression as source code
    return_source: String,
}

#[derive(Default)]
struct Collector {
    proxies: FxHashMap<SymbolId, ProxyInfo>,
}

impl<'a> Traverse<'a, ()> for Collector {
    fn enter_statement(&mut self, stmt: &mut Statement<'a>, ctx: &mut TraverseCtx<'a, ()>) {
        let Statement::FunctionDeclaration(func) = stmt else { return; };
        let Some(id) = &func.id else { return; };
        let Some(sym) = id.symbol_id.get() else { return; };
        if query::has_writes(ctx.scoping(), sym) { return; }

        // Must have exactly one statement: return <expression>
        let Some(body) = &func.body else { return; };
        if body.statements.len() != 1 { return; }
        let Statement::ReturnStatement(ret) = &body.statements[0] else { return; };
        let Some(ret_expr) = &ret.argument else { return; };

        // Return value must be a simple expression (call, binary, etc.)
        if !is_simple_expression(ret_expr) { return; }

        // All params must be simple identifiers
        let params: Vec<String> = func.params.items.iter()
            .filter_map(|p| p.pattern.get_binding_identifier())
            .map(|b| b.name.to_string())
            .collect();
        if params.len() != func.params.items.len() { return; }

        // Store source code to avoid lifetime issues
        let return_source = codegen::expr_to_code(ret_expr);

        self.proxies.insert(sym, ProxyInfo {
            params,
            return_source,
        });
    }
}

/// Maximum AST depth allowed for an expression to qualify as a proxy template.
///
/// Caps the recursion budget for both the collector (`is_simple_expression`)
/// and the inliner's `ParamSubstitutor`. Real proxy functions are shallow
/// (`return f(b - a, r)` is depth ~3); legitimate inlining never needs more.
/// Pathological obfuscator chains (`a + b + c + ... + z` with thousands of
/// terms) used to overflow Rust's default 8 MB main stack via the recursive
/// walker — capping depth here makes the pass safe by construction.
const MAX_TEMPLATE_DEPTH: usize = 32;

/// Check if an expression is simple enough to inline safely.
///
/// Bounded by [`MAX_TEMPLATE_DEPTH`] — deeper expressions are conservatively
/// rejected so the inliner's substitutor never walks an unbounded tree.
fn is_simple_expression(expr: &Expression) -> bool {
    is_simple_expression_inner(expr, 0)
}

fn is_simple_expression_inner(expr: &Expression, depth: usize) -> bool {
    if depth >= MAX_TEMPLATE_DEPTH {
        return false;
    }
    let next = depth + 1;
    match expr {
        Expression::CallExpression(c) => {
            is_simple_expression_inner(&c.callee, next) &&
            c.arguments.iter().all(|a| {
                a.as_expression().is_some_and(|e| is_simple_expression_inner(e, next))
            })
        }
        Expression::BinaryExpression(b) => {
            is_simple_expression_inner(&b.left, next)
                && is_simple_expression_inner(&b.right, next)
        }
        Expression::UnaryExpression(u) => is_simple_expression_inner(&u.argument, next),
        Expression::LogicalExpression(l) => {
            is_simple_expression_inner(&l.left, next)
                && is_simple_expression_inner(&l.right, next)
        }
        Expression::ConditionalExpression(c) => {
            is_simple_expression_inner(&c.test, next)
                && is_simple_expression_inner(&c.consequent, next)
                && is_simple_expression_inner(&c.alternate, next)
        }
        Expression::Identifier(_) |
        Expression::NumericLiteral(_) |
        Expression::StringLiteral(_) |
        Expression::BooleanLiteral(_) |
        Expression::NullLiteral(_) => true,
        Expression::StaticMemberExpression(m) => is_simple_expression_inner(&m.object, next),
        Expression::ComputedMemberExpression(m) => {
            is_simple_expression_inner(&m.object, next)
                && is_simple_expression_inner(&m.expression, next)
        }
        Expression::ParenthesizedExpression(p) => {
            is_simple_expression_inner(&p.expression, next)
        }
        _ => false,
    }
}

struct Inliner {
    proxies: FxHashMap<SymbolId, ProxyInfo>,
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for Inliner {
    fn exit_expression(&mut self, expr: &mut Expression<'a>, ctx: &mut TraverseCtx<'a, ()>) {
        // Match: proxy_func(args...)
        let sym = {
            let Expression::CallExpression(call) = &*expr else { return; };
            let Expression::Identifier(id) = &call.callee else { return; };
            resolve::get_reference_symbol(ctx.scoping(), id)
        };
        let Some(sym) = sym else { return; };
        let Some(proxy) = self.proxies.get(&sym) else { return; };

        // Must have exact argument count
        let Expression::CallExpression(call) = &*expr else { return; };
        if call.arguments.len() != proxy.params.len() { return; }

        // Collect argument source codes
        let arg_sources: Vec<String> = call.arguments.iter()
            .filter_map(|a| a.as_expression())
            .map(codegen::expr_to_code)
            .collect();
        if arg_sources.len() != proxy.params.len() { return; }

        // Parse the return expression template
        let allocator = &ctx.ast.allocator();
        let parsed = oxc::parser::Parser::new(
            allocator, &proxy.return_source, oxc::span::SourceType::mjs(),
        ).parse();

        if parsed.diagnostics.has_errors() || parsed.program.body.is_empty() { return; }
        let Statement::ExpressionStatement(es) = &parsed.program.body[0] else { return; };

        // Clone into our arena
        let mut cloned = es.expression.clone_in(allocator);

        // Build parameter → argument source mapping
        let mut substitutions: FxHashMap<&str, &str> = FxHashMap::default();
        for (i, param) in proxy.params.iter().enumerate() {
            substitutions.insert(param.as_str(), arg_sources[i].as_str());
        }

        // Substitute all parameter references with argument expressions
        let mut substitutor = ParamSubstitutor {
            substitutions: &substitutions,
            allocator,
            ast: &ctx.ast,
        };
        substitutor.visit_expression(&mut cloned);

        *expr = cloned;
        self.modifications += 1;
    }
}

/// AST visitor that substitutes parameter identifiers with argument expressions.
struct ParamSubstitutor<'a, 's> {
    substitutions: &'s FxHashMap<&'s str, &'s str>,
    allocator: &'a Allocator,
    ast: &'s AstBuilder<'a>,
}

impl<'a, 's> VisitMut<'a> for ParamSubstitutor<'a, 's> {
    fn visit_expression(&mut self, expr: &mut Expression<'a>) {
        // Check if this is an identifier that should be substituted
        if let Expression::Identifier(ident) = expr {
            let name = ident.name.as_str();
            if let Some(&replacement_src) = self.substitutions.get(name) {
                // Parse the replacement expression
                let parsed = oxc::parser::Parser::new(
                    self.allocator, replacement_src, oxc::span::SourceType::mjs(),
                ).parse();

                if parsed.diagnostics.has_errors() || parsed.program.body.is_empty() {
                    return;
                }
                let Statement::ExpressionStatement(es) = &parsed.program.body[0] else {
                    return;
                };

                // Clone and wrap in parens if needed
                let mut cloned = es.expression.clone_in(self.allocator);

                // Wrap complex expressions in parentheses for safety
                if needs_parens(&cloned) {
                    cloned = Expression::new_parenthesized_expression(SPAN, cloned, self.ast);
                }

                *expr = cloned;
                return; // Don't recurse into the replacement
            }
        }

        // Recurse into children
        match expr {
            Expression::BinaryExpression(b) => {
                self.visit_expression(&mut b.left);
                self.visit_expression(&mut b.right);
            }
            Expression::UnaryExpression(u) => {
                self.visit_expression(&mut u.argument);
            }
            Expression::LogicalExpression(l) => {
                self.visit_expression(&mut l.left);
                self.visit_expression(&mut l.right);
            }
            Expression::ConditionalExpression(c) => {
                self.visit_expression(&mut c.test);
                self.visit_expression(&mut c.consequent);
                self.visit_expression(&mut c.alternate);
            }
            Expression::CallExpression(c) => {
                self.visit_expression(&mut c.callee);
                for arg in &mut c.arguments {
                    if let Some(e) = arg.as_expression_mut() {
                        self.visit_expression(e);
                    }
                }
            }
            Expression::StaticMemberExpression(m) => {
                self.visit_expression(&mut m.object);
            }
            Expression::ComputedMemberExpression(m) => {
                self.visit_expression(&mut m.object);
                self.visit_expression(&mut m.expression);
            }
            Expression::ParenthesizedExpression(p) => {
                self.visit_expression(&mut p.expression);
            }
            Expression::SequenceExpression(s) => {
                for e in &mut s.expressions {
                    self.visit_expression(e);
                }
            }
            _ => {}
        }
    }
}

/// Check if an expression needs parentheses when used as a replacement.
fn needs_parens(e: &Expression) -> bool {
    matches!(e,
        Expression::BinaryExpression(_)
        | Expression::ConditionalExpression(_)
        | Expression::AssignmentExpression(_)
        | Expression::SequenceExpression(_)
        | Expression::LogicalExpression(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::codegen::Codegen;
    use oxc::parser::Parser;
    use oxc::semantic::SemanticBuilder;
    use oxc::span::SourceType;

    fn deob(source: &str) -> (String, usize) {
        let alloc = Allocator::default();
        let mut program = Parser::new(&alloc, source, SourceType::mjs()).parse().program;
        let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
        let mut module = ProxyInliner;
        let result = module.transform(&alloc, &mut program, scoping).unwrap();
        (Codegen::new().build(&program).code, result.modifications)
    }

    #[test]
    fn test_simple_proxy() {
        let (code, mods) = deob("function f(a, b) { return g(b, a); } f(1, 2);");
        assert!(mods > 0);
        assert!(code.contains("g(2, 1)"), "got: {code}");
    }

    #[test]
    fn test_arithmetic_proxy() {
        let (code, mods) = deob("function c(r, v) { return Hs(v - -966, r); } c(-679, -602);");
        assert!(mods > 0);
        assert!(code.contains("Hs("), "should contain inlined call: {code}");
    }

    #[test]
    fn test_no_inline_multi_statement() {
        let (_, mods) = deob("function f(a) { var x = 1; return g(a); } f(1);");
        assert_eq!(mods, 0, "multi-statement body should not be inlined");
    }

    #[test]
    fn test_binary_expression() {
        let (code, mods) = deob("function f(a) { return a + 1; } f(5);");
        assert!(mods > 0, "should inline simple binary expression");
        assert!(code.contains("5") && code.contains("+ 1"), "got: {code}");
    }

    #[test]
    fn test_wrong_arg_count() {
        let (_, mods) = deob("function f(a, b) { return g(a, b); } f(1);");
        assert_eq!(mods, 0, "wrong arg count should not inline");
    }

    #[test]
    fn test_string_literal_not_corrupted() {
        // This was the critical bug - make sure strings aren't modified
        let (code, mods) = deob("function f(a) { return g(\"hello a world\"); } f(1);");
        assert!(mods > 0);
        assert!(code.contains("\"hello a world\""), "string should not be corrupted: {code}");
    }

    #[test]
    fn test_nested_calls() {
        let (code, mods) = deob("function f(a, b) { return outer(inner(a), b); } f(1, 2);");
        assert!(mods > 0);
        assert!(code.contains("outer(inner(1), 2)") || code.contains("outer(inner((1)), (2))"), "got: {code}");
    }
}
