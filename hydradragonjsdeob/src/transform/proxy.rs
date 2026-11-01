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
use oxc::ast_visit::{Visit, VisitMut};
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
        let mut inliner = Inliner { proxies: collector.proxies, templates: FxHashMap::default(), modifications: 0 };
        let scoping = traverse_mut(&mut inliner, allocator, program, scoping, ());
        Ok(TransformResult { modifications: inliner.modifications, scoping })
    }
}

/// Information about a proxy function (stored as source code to avoid lifetime issues).
struct ProxyInfo {
    /// Parameter names in order
    params: Vec<String>,
    /// How many times each parameter appears in the return expression.
    uses: Vec<usize>,
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

        let mut counter = UseCounter { params: &params, uses: vec![0; params.len()] };
        counter.visit_expression(ret_expr);
        let uses = counter.uses;

        // Store source code to avoid lifetime issues
        let return_source = codegen::expr_to_code(ret_expr);
        if return_source.len() > MAX_TEMPLATE_BYTES { return; }

        self.proxies.insert(sym, ProxyInfo {
            params,
            uses,
            return_source,
        });
    }
}

/// Counts the references to each parameter in a return expression.
struct UseCounter<'p> {
    params: &'p [String],
    uses: Vec<usize>,
}

impl<'a> Visit<'a> for UseCounter<'_> {
    fn visit_identifier_reference(&mut self, id: &IdentifierReference<'a>) {
        if let Some(i) = self.params.iter().position(|p| p == id.name.as_str()) {
            self.uses[i] += 1;
        }
    }
}

/// An argument that may be copied to every use of its parameter, or dropped when the
/// parameter is unused: no side effects and small. Anything else is substituted only
/// for a parameter used exactly once. Copying a call or assignment would run it again
/// (`ff(d, g, ...)` of MD5 uses `g` three times, and its argument is itself a nested
/// `ff(...)` call: copying it at every level is exponential, a 4 KB file asked for
/// 49 GB).
fn is_copyable_argument(e: &Expression) -> bool {
    match e {
        Expression::Identifier(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::StringLiteral(s) => s.value.len() <= 256,
        Expression::UnaryExpression(u) => {
            matches!(u.operator, UnaryOperator::UnaryNegation | UnaryOperator::UnaryPlus)
                && matches!(u.argument, Expression::NumericLiteral(_))
        }
        _ => false,
    }
}

/// Longest return expression (as code) a proxy may have. Obfuscator proxies are one
/// call or operation (`return Hs(v - -966, r)`); a function returning a whole decision
/// tree (Bing's WSB model: 450 functions of a few KB each) is not one, and copying its
/// body to every call site doubled the code and filled the arena (139 MB for 717 KB).
const MAX_TEMPLATE_BYTES: usize = 256;

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

struct Inliner<'a> {
    proxies: FxHashMap<SymbolId, ProxyInfo>,
    /// Each proxy's return expression, parsed once into the arena and cloned per call
    /// site: parsing it again at every one of tens of thousands of call sites filled
    /// the arena (which frees nothing until the run ends) with copies.
    templates: FxHashMap<SymbolId, Option<Expression<'a>>>,
    modifications: usize,
}

impl<'a> Traverse<'a, ()> for Inliner<'a> {
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
        let copies_safely = call.arguments.iter().zip(&proxy.uses).all(|(a, &uses)| {
            uses == 1 || a.as_expression().is_some_and(is_copyable_argument)
        });
        if !copies_safely { return; }

        let allocator = ctx.ast.allocator();
        let template = self.templates.entry(sym).or_insert_with(|| {
            // Parse the return expression template
            let parsed = oxc::parser::Parser::new(
                allocator, allocator.alloc_str(&proxy.return_source), oxc::span::SourceType::mjs(),
            ).parse();
            if parsed.diagnostics.has_errors() || parsed.program.body.is_empty() { return None; }
            let Statement::ExpressionStatement(es) = &parsed.program.body[0] else { return None; };
            Some(es.expression.clone_in(allocator))
        });
        let Some(template) = template else { return; };
        let mut cloned = template.clone_in(allocator);

        // Build parameter → argument mapping (the call's own argument nodes, copied
        // where the parameter is used)
        let Expression::CallExpression(call) = &*expr else { return; };
        let mut substitutions: FxHashMap<&str, &Expression<'a>> = FxHashMap::default();
        for (param, arg) in proxy.params.iter().zip(&call.arguments) {
            let Some(arg) = arg.as_expression() else { return; };
            substitutions.insert(param.as_str(), arg);
        }

        // Substitute all parameter references with argument expressions
        let mut substitutor = ParamSubstitutor {
            substitutions: &substitutions,
            allocator,
            ast: &ctx.ast,
        };
        substitutor.visit_expression(&mut cloned);
        drop(substitutor);
        drop(substitutions);

        *expr = cloned;
        self.modifications += 1;
    }
}

/// AST visitor that substitutes parameter identifiers with argument expressions.
struct ParamSubstitutor<'a, 's> {
    substitutions: &'s FxHashMap<&'s str, &'s Expression<'a>>,
    allocator: &'a Allocator,
    ast: &'s AstBuilder<'a>,
}

impl<'a, 's> VisitMut<'a> for ParamSubstitutor<'a, 's> {
    fn visit_expression(&mut self, expr: &mut Expression<'a>) {
        // Check if this is an identifier that should be substituted
        if let Expression::Identifier(ident) = expr {
            let name = ident.name.as_str();
            if let Some(&replacement) = self.substitutions.get(name) {
                // Clone and wrap in parens if needed
                let mut cloned = replacement.clone_in(self.allocator);

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
    fn test_argument_used_twice_is_copied_only_when_simple() {
        let (code, mods) = deob("function f(a) { return a * a; } f(3); f(g());");
        assert_eq!(mods, 1, "got: {code}");
        assert!(code.contains("f(g())"), "a call must not run twice: {code}");
    }

    #[test]
    fn test_nested_multi_use_proxies_stay_small() {
        // The MD5 shape: each level uses its parameter three times.
        let mut src = String::from("function ff(d, g) { return h(g & d | ~g & d, g); } let f = 1;");
        let mut e = String::from("f");
        for _ in 0..64 {
            e = format!("ff(f = {e}, 2)");
        }
        src.push_str(&e);
        src.push(';');
        let (code, _) = deob(&src);
        assert!(code.len() < src.len() * 4, "{} -> {} bytes", src.len(), code.len());
    }

    #[test]
    fn test_large_function_is_not_a_proxy() {
        let tree = (0..40).map(|i| format!("a > {i} ? {i} : ")).collect::<String>() + "0";
        let (_, mods) = deob(&format!("function f(a) {{ return {tree}; }} f(x);"));
        assert_eq!(mods, 0);
    }

    #[test]
    fn test_nested_calls() {
        let (code, mods) = deob("function f(a, b) { return outer(inner(a), b); } f(1, 2);");
        assert!(mods > 0);
        assert!(code.contains("outer(inner(1), 2)") || code.contains("outer(inner((1)), (2))"), "got: {code}");
    }
}
