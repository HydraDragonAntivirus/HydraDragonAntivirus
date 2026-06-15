use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::features::JsFeatureVector;

fn shannon_entropy_str(data: &str) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let len = data.len() as f32;
    let mut counts: HashMap<char, u64> = HashMap::new();
    for c in data.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let mut entropy = 0.0f32;
    for &c in counts.values() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

struct AstWalkerCounts {
    function_count: u32,
    variable_declarations: u32,
    call_expressions: u32,
    member_expressions: u32,
    binary_expressions: u32,
    conditional_statements: u32,
    loop_statements: u32,
    try_catch_blocks: u32,
    array_literals: u32,
    object_literals: u32,
    max_nesting_depth: u32,
    eval_usage: u32,
    suspicious_calls: Vec<String>,
    current_depth: u32,
}

impl AstWalkerCounts {
    fn new() -> Self {
        Self {
            function_count: 0,
            variable_declarations: 0,
            call_expressions: 0,
            member_expressions: 0,
            binary_expressions: 0,
            conditional_statements: 0,
            loop_statements: 0,
            try_catch_blocks: 0,
            array_literals: 0,
            object_literals: 0,
            max_nesting_depth: 0,
            eval_usage: 0,
            suspicious_calls: Vec::new(),
            current_depth: 0,
        }
    }

    fn walk_statements(&mut self, stmts: &[Statement]) {
        for stmt in stmts {
            self.walk_statement(stmt);
        }
    }

    fn walk_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::BlockStatement(s) => {
                self.current_depth += 1;
                self.max_nesting_depth = self.max_nesting_depth.max(self.current_depth);
                self.walk_statements(&s.body);
                self.current_depth -= 1;
            }
            Statement::ExpressionStatement(s) => {
                self.walk_expression(&s.expression);
            }
            Statement::IfStatement(s) => {
                self.conditional_statements += 1;
                self.walk_expression(&s.test);
                self.walk_statement(&s.consequent);
                if let Some(alt) = &s.alternate {
                    self.walk_statement(alt);
                }
            }
            Statement::SwitchStatement(s) => {
                self.conditional_statements += 1;
                self.walk_expression(&s.discriminant);
                for case in &s.cases {
                    for c in &case.consequent {
                        self.walk_statement(c);
                    }
                }
            }
            Statement::ForStatement(s) => {
                self.loop_statements += 1;
                if let Some(init) = &s.init {
                    match init {
                        ForStatementInit::VariableDeclaration(var_decl) => {
                            self.variable_declarations += 1;
                        }
                        ForStatementInit::Expression(expr) => {
                            self.walk_expression(expr);
                        }
                    }
                }
                if let Some(test) = &s.test {
                    self.walk_expression(test);
                }
                if let Some(update) = &s.update {
                    self.walk_expression(update);
                }
                self.walk_statement(&s.body);
            }
            Statement::ForInStatement(s) => {
                self.loop_statements += 1;
                self.walk_expression(&s.right);
                self.walk_statement(&s.body);
            }
            Statement::ForOfStatement(s) => {
                self.loop_statements += 1;
                self.walk_expression(&s.right);
                self.walk_statement(&s.body);
            }
            Statement::WhileStatement(s) => {
                self.loop_statements += 1;
                self.walk_expression(&s.test);
                self.walk_statement(&s.body);
            }
            Statement::DoWhileStatement(s) => {
                self.loop_statements += 1;
                self.walk_expression(&s.test);
                self.walk_statement(&s.body);
            }
            Statement::TryStatement(s) => {
                self.try_catch_blocks += 1;
                self.walk_statements(&s.block.body);
                if let Some(handler) = &s.handler {
                    self.walk_statements(&handler.body.body);
                }
                if let Some(finalizer) = &s.finalizer {
                    self.walk_statements(&finalizer.body);
                }
            }
            Statement::ReturnStatement(s) => {
                if let Some(arg) = &s.argument {
                    self.walk_expression(arg);
                }
            }
            Statement::ThrowStatement(s) => {
                self.walk_expression(&s.argument);
            }
            Statement::LabeledStatement(s) => {
                self.walk_statement(&s.body);
            }
            Statement::WithStatement(s) => {
                self.walk_expression(&s.object);
                self.walk_statement(&s.body);
            }
            Statement::BreakStatement(_) | Statement::ContinueStatement(_) | Statement::EmptyStatement(_) | Statement::DebuggerStatement(_) => {}
            Statement::VariableDeclaration(_) => {
                self.variable_declarations += 1;
            }
            Statement::FunctionDeclaration(f) => {
                self.function_count += 1;
                if let Some(body) = &f.body {
                    self.current_depth += 1;
                    self.max_nesting_depth = self.max_nesting_depth.max(self.current_depth);
                    self.walk_statements(&body.body);
                    self.current_depth -= 1;
                }
            }
            Statement::ExportNamedDeclaration(decl) => {
                if let Some(d) = &decl.declaration {
                    self.walk_statement(d);
                }
            }
            Statement::ExportDefaultDeclaration(decl) => {
                match &decl.declaration {
                    ExportDefaultDeclarationKind::Expression(expr) => self.walk_expression(expr),
                    ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                        self.function_count += 1;
                        if let Some(body) = &f.body {
                            self.current_depth += 1;
                            self.max_nesting_depth = self.max_nesting_depth.max(self.current_depth);
                            self.walk_statements(&body.body);
                            self.current_depth -= 1;
                        }
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                        if let Some(body) = &c.body {
                            for def in &body.body {
                                if let ClassElement::MethodDefinition(m) = def {
                                    self.function_count += 1;
                                }
                            }
                        }
                    }
                }
            }
            Statement::ExportAllDeclaration(_) | Statement::ImportDeclaration(_) => {}
        }
    }

    fn walk_expression(&mut self, expr: &Expression) {
        match expr {
            Expression::CallExpression(call) => {
                self.call_expressions += 1;
                self.walk_call_callee(&call.callee);
                for arg in &call.arguments {
                    match arg {
                        Argument::Expression(e) => self.walk_expression(e),
                        Argument::SpreadElement(e) => self.walk_expression(&e.argument),
                    }
                }
            }
            Expression::NewExpression(new_expr) => {
                self.call_expressions += 1;
                self.walk_expression(&new_expr.callee);
                for arg in &new_expr.arguments {
                    match arg {
                        Argument::Expression(e) => self.walk_expression(e),
                        Argument::SpreadElement(e) => self.walk_expression(&e.argument),
                    }
                }
            }
            Expression::StaticMemberExpression(member) => {
                self.member_expressions += 1;
                self.walk_expression(&member.object);
            }
            Expression::ComputedMemberExpression(member) => {
                self.member_expressions += 1;
                self.walk_expression(&member.object);
                self.walk_expression(&member.expression);
            }
            Expression::PrivateFieldExpression(member) => {
                self.member_expressions += 1;
                self.walk_expression(&member.object);
            }
            Expression::BinaryExpression(bin) => {
                self.binary_expressions += 1;
                self.walk_expression(&bin.left);
                self.walk_expression(&bin.right);
            }
            Expression::LogicalExpression(log) => {
                self.binary_expressions += 1;
                self.walk_expression(&log.left);
                self.walk_expression(&log.right);
            }
            Expression::UnaryExpression(un) => {
                self.walk_expression(&un.argument);
            }
            Expression::UpdateExpression(up) => {
                self.walk_expression(&up.argument);
            }
            Expression::ConditionalExpression(cond) => {
                self.conditional_statements += 1;
                self.walk_expression(&cond.test);
                self.walk_expression(&cond.consequent);
                self.walk_expression(&cond.alternate);
            }
            Expression::AssignmentExpression(assign) => {
                self.walk_expression(&assign.right);
            }
            Expression::SequenceExpression(seq) => {
                for e in &seq.expressions {
                    self.walk_expression(e);
                }
            }
            Expression::TemplateLiteral(tpl) => {
                for expr in &tpl.expressions {
                    self.walk_expression(expr);
                }
            }
            Expression::TaggedTemplateExpression(tag) => {
                self.walk_expression(&tag.tag);
                for expr in &tag.quasi.expressions {
                    self.walk_expression(expr);
                }
            }
            Expression::ArrayExpression(arr) => {
                self.array_literals += 1;
                for elem in &arr.elements {
                    if let ArrayExpressionElement::Expression(e) = elem {
                        self.walk_expression(e);
                    }
                }
            }
            Expression::ObjectExpression(obj) => {
                self.object_literals += 1;
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            self.walk_expression(&p.key);
                            self.walk_expression(&p.value);
                        }
                        _ => {}
                    }
                }
            }
            Expression::ArrowFunctionExpression(func) => {
                self.function_count += 1;
                if let Some(body) = &func.body {
                    self.current_depth += 1;
                    self.max_nesting_depth = self.max_nesting_depth.max(self.current_depth);
                    for stmt in &body.body {
                        self.walk_statement(stmt);
                    }
                    self.current_depth -= 1;
                }
            }
            Expression::FunctionExpression(func) => {
                self.function_count += 1;
                if let Some(body) = &func.body {
                    self.current_depth += 1;
                    self.max_nesting_depth = self.max_nesting_depth.max(self.current_depth);
                    for stmt in &body.body {
                        self.walk_statement(stmt);
                    }
                    self.current_depth -= 1;
                }
            }
            Expression::ParenthesizedExpression(p) => self.walk_expression(&p.expression),
            Expression::ChainExpression(chain) => self.walk_expression(&chain.expression),
            Expression::AwaitExpression(a) => self.walk_expression(&a.argument),
            Expression::YieldExpression(y) => {
                if let Some(arg) = &y.argument {
                    self.walk_expression(arg);
                }
            }
            Expression::Identifier(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::ThisExpression(_)
            | Expression::Super(_)
            | Expression::MetaProperty(_)
            | Expression::ImportExpression(_)
            | Expression::V8IntrinsicExpression(_) => {}
            _ => {}
        }
    }

    fn walk_call_callee(&mut self, callee: &Expression) {
        let suspicious_apis = [
            "eval", "Function", "setTimeout", "setInterval",
            "ActiveXObject", "WScript", "XMLHttpRequest", "fetch",
            "WebSocket",
        ];

        match callee {
            Expression::Identifier(ident) => {
                let name = ident.name.as_str();
                if suspicious_apis.contains(&name) {
                    self.suspicious_calls.push(name.to_string());
                }
                if name == "eval" {
                    self.eval_usage += 1;
                }
            }
            Expression::StaticMemberExpression(member) => {
                let name = member.property.name.as_str();
                if suspicious_apis.contains(&name) {
                    self.suspicious_calls.push(name.to_string());
                }
                if name == "eval" {
                    self.eval_usage += 1;
                }
                self.walk_expression(&member.object);
            }
            _ => {
                self.walk_expression(callee);
            }
        }
    }
}

pub fn extract_js_features(source: &str) -> Option<JsFeatureVector> {
    let allocator = Allocator::default();
    let source_type = SourceType::mjs();
    let ret = Parser::new(&allocator, source, source_type).parse();
    let program = ret.program;

    let parse_success = if ret.errors.is_empty() { 1.0 } else { 0.0 };

    let mut walker = AstWalkerCounts::new();
    walker.walk_statements(&program.body);

    let hex_encoded = count_regex(source, r"\\x[0-9a-fA-F]{2}");
    let unicode_encoded = count_regex(source, r"\\u[0-9a-fA-F]{4}");
    let char_code = count_regex(source, r"String\.fromCharCode");
    let base64 = count_regex(source, r"atob|btoa");
    let escape = count_regex(source, r"unescape|escape");
    let bracket_notation = count_regex(source, r"\[['\"].*?['\"]\]\s*\(");

    let obfuscation_score = hex_encoded + unicode_encoded + char_code + base64 + escape + bracket_notation;
    let is_obfuscated = if obfuscation_score > 10.0 { 1.0 } else { 0.0 };

    let crypto_refs = count_regex(source, r"crypto|CryptoJS|aes|des|rsa|md5|sha1|sha256|sha512|encrypt|decrypt|cipher");
    let network_ops = count_regex(source, r"http[s]?://|ws[s]?://|fetch\s*\(|XMLHttpRequest|\.send\s*\(|\.open\s*\(|WebSocket");
    let file_ops = count_regex(source, r"FileSystemObject|readFile|writeFile|OpenTextFile|DeleteFile|CopyFile");
    let registry_ops = count_regex(source, r"RegRead|RegWrite|RegDelete|HKEY_|HKLM|HKCU");
    let process_ops = count_regex(source, r"Run\s*\(|Exec\s*\(|ShellExecute|CreateObject\s*\(");

    let suspicious_apis = [
        "eval", "Function", "setTimeout", "setInterval",
        "ActiveXObject", "WScript", "XMLHttpRequest", "fetch",
        "WebSocket",
    ];
    let suspicious_api_calls_f32 = suspicious_apis.iter().map(|api| count_regex(source, api) as i32).sum::<i32>() as f32;

    let suspicious_score = crypto_refs * 2.0 + network_ops * 3.0 + file_ops * 4.0
        + registry_ops * 5.0 + process_ops * 5.0 + suspicious_api_calls_f32 * 2.0;

    let (total_strings, avg_string_len, max_string_len, long_strings, base64_strings, url_strings, hex_strings_val) = extract_string_features(source);
    let (total_lines, code_lines, comment_lines, blank_lines, avg_line_len, max_line_len, cyclomatic) = analyze_complexity(source);
    let (total_idents, short_idents, long_idents, avg_ident_len, suspicious_naming, random_idents) = analyze_identifiers(source);

    Some(JsFeatureVector {
        file_size: source.len() as f32,
        entropy: shannon_entropy_str(source),
        parse_success,
        function_count: walker.function_count as f32,
        variable_declarations: walker.variable_declarations as f32,
        call_expressions: walker.call_expressions as f32,
        member_expressions: walker.member_expressions as f32,
        binary_expressions: walker.binary_expressions as f32,
        conditional_statements: walker.conditional_statements as f32,
        loop_statements: walker.loop_statements as f32,
        try_catch_blocks: walker.try_catch_blocks as f32,
        array_literals: walker.array_literals as f32,
        object_literals: walker.object_literals as f32,
        max_nesting_depth: walker.max_nesting_depth as f32,
        eval_usage: walker.eval_usage as f32,
        suspicious_call_count: walker.suspicious_calls.len() as f32,
        hex_encoded_strings: hex_encoded as f32,
        unicode_encoded_strings: unicode_encoded as f32,
        char_code_usage: char_code as f32,
        base64_usage: base64 as f32,
        escape_usage: escape as f32,
        bracket_notation_calls: bracket_notation as f32,
        obfuscation_score: obfuscation_score as f32,
        is_obfuscated,
        crypto_references: crypto_refs,
        network_operations: network_ops,
        file_system_operations: file_ops,
        registry_operations: registry_ops,
        process_operations: process_ops,
        suspicious_api_calls: suspicious_api_calls_f32,
        suspicious_score,
        total_strings,
        avg_string_length: avg_string_len,
        max_string_length: max_string_len,
        long_strings_count: long_strings,
        base64_like_strings: base64_strings,
        url_strings,
        hex_strings: hex_strings_val,
        total_lines,
        code_lines,
        comment_lines,
        blank_lines,
        avg_line_length: avg_line_len,
        max_line_length: max_line_len,
        cyclomatic_complexity: cyclomatic,
        total_identifiers: total_idents,
        short_identifiers: short_idents,
        long_identifiers: long_idents,
        avg_identifier_length: avg_ident_len,
        suspicious_naming,
        random_like_identifiers: random_idents,
    })
}

fn count_regex(text: &str, pattern: &str) -> f32 {
    if let Ok(re) = regex::Regex::new(pattern) {
        re.find_iter(text).count() as f32
    } else {
        0.0
    }
}

fn extract_string_features(source: &str) -> (f32, f32, f32, f32, f32, f32, f32) {
    let re = regex::Regex::new(r#"["']([^"']*)["']"#).unwrap();
    let strings: Vec<&str> = re.find_iter(source)
        .filter_map(|m| {
            let s = m.as_str();
            Some(&s[1..s.len()-1])
        })
        .collect();

    if strings.is_empty() {
        return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }

    let total = strings.len() as f32;
    let lengths: Vec<f32> = strings.iter().map(|s| s.len() as f32).collect();
    let avg = lengths.iter().sum::<f32>() / total;
    let max = lengths.iter().cloned().fold(0.0f32, f32::max);
    let long = strings.iter().filter(|s| s.len() > 100).count() as f32;

    let b64 = strings.iter()
        .filter(|s| s.len() > 20)
        .count() as f32;

    let url_re = regex::Regex::new(r"https?://|ftp://|ws[s]?://").unwrap();
    let urls = strings.iter().filter(|s| url_re.is_match(s)).count() as f32;

    let hex_re = regex::Regex::new(r"^[0-9a-fA-F]+$").unwrap();
    let hex = strings.iter().filter(|s| s.len() > 10 && hex_re.is_match(s)).count() as f32;

    (total, avg, max, long, b64, urls, hex)
}

fn analyze_complexity(source: &str) -> (f32, f32, f32, f32, f32, f32, f32) {
    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len() as f32;

    let mut code_lines = 0u32;
    let mut comment_lines = 0u32;
    let mut blank_lines = 0u32;
    let mut in_multiline = false;
    let mut code_line_lengths: Vec<f32> = Vec::new();

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            blank_lines += 1;
            continue;
        }
        if trimmed.starts_with("/*") {
            in_multiline = true;
        }
        if in_multiline {
            comment_lines += 1;
            if trimmed.contains("*/") {
                in_multiline = false;
            }
            continue;
        }
        if trimmed.starts_with("//") {
            comment_lines += 1;
            continue;
        }
        code_lines += 1;
        code_line_lengths.push(line.len() as f32);
    }

    let avg_line = if code_lines > 0 {
        code_line_lengths.iter().sum::<f32>() / code_lines as f32
    } else {
        0.0
    };
    let max_line = code_line_lengths.iter().cloned().fold(0.0f32, f32::max);

    let decision_keywords = ["if", "else", "for", "while", "case", "catch", "&&", "||", "?"];
    let cyclomatic: u32 = decision_keywords.iter()
        .map(|kw| count_substring(source, kw))
        .sum();

    (
        total_lines,
        code_lines as f32,
        comment_lines as f32,
        blank_lines as f32,
        avg_line,
        max_line,
        cyclomatic as f32,
    )
}

fn analyze_identifiers(source: &str) -> (f32, f32, f32, f32, f32, f32) {
    let js_keywords = [
        "var","let","const","function","return","if","else","for","while","do",
        "switch","case","break","continue","try","catch","finally","throw","new",
        "this","typeof","instanceof","in","of","delete","void","null","undefined",
        "true","false","class","extends","super","static","import","export","from",
        "default","async","await",
    ];

    let ident_re = regex::Regex::new(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b").unwrap();
    let all: Vec<&str> = ident_re.find_iter(source).map(|m| m.as_str()).collect();
    let identifiers: Vec<&str> = all.iter().filter(|id| !js_keywords.contains(id)).copied().collect();

    if identifiers.is_empty() {
        return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }

    let total = identifiers.len() as f32;
    let lengths: Vec<f32> = identifiers.iter().map(|id| id.len() as f32).collect();
    let avg = lengths.iter().sum::<f32>() / total;
    let short = identifiers.iter().filter(|id| id.len() <= 2).count() as f32;
    let long = identifiers.iter().filter(|id| id.len() > 20).count() as f32;

    let random = identifiers.iter()
        .filter(|id| id.len() > 5 && shannon_entropy_str(id) > 3.5)
        .count() as f32;

    let short_ratio = if total > 0.0 { short / total } else { 0.0 };
    let random_ratio = if total > 0.0 { random / total } else { 0.0 };
    let suspicious = if short_ratio > 0.5 || random_ratio > 0.3 { 1.0 } else { 0.0 };

    (total, short, long, avg, suspicious, random)
}

fn count_substring(text: &str, sub: &str) -> u32 {
    text.matches(sub).count() as u32
}
