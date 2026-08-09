use std::collections::HashMap;
use std::sync::LazyLock;

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::features::JsFeatureVector;

static RE_HEX_ENCODED: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap());
static RE_UNICODE_ENCODED: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap());
static RE_CHAR_CODE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"String\.fromCharCode").unwrap());
static RE_BASE64: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\batob\b|\bbtoa\b").unwrap());
static RE_ESCAPE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\bunescape\b|\bescape\b").unwrap());
static RE_BRACKET_NOTATION: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"\[['"].*?['"]\]\s*\("#).unwrap());
static RE_CRYPTO: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"crypto|CryptoJS|aes|des|rsa|md5|sha1|sha256|sha512|encrypt|decrypt|cipher")
        .unwrap()
});
static RE_NETWORK: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"http[s]?://|ws[s]?://|fetch\s*\(|XMLHttpRequest|\.send\s*\(|\.open\s*\(|WebSocket",
    )
    .unwrap()
});
static RE_FILE_OPS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"FileSystemObject|readFile|writeFile|OpenTextFile|DeleteFile|CopyFile")
        .unwrap()
});
static RE_REGISTRY: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"RegRead|RegWrite|RegDelete|HKEY_|HKLM|HKCU").unwrap());
static RE_PROCESS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"Run\s*\(|Exec\s*\(|ShellExecute|CreateObject\s*\(").unwrap()
});
static RE_SUSPICIOUS_APIS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\beval\b|\bFunction\b|\bsetTimeout\b|\bsetInterval\b|\bActiveXObject\b|\bWScript\b|\bXMLHttpRequest\b|\bfetch\b|\bWebSocket\b").unwrap()
});
static RE_STRINGS: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"["']([^"']*)["']"#).unwrap());
static RE_BASE64_STR: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap());
static RE_URL_STR: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"https?://|ftp://|ws[s]?://").unwrap());
static RE_HEX_STR: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[0-9a-fA-F]+$").unwrap());
static RE_IDENTIFIERS: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b").unwrap());

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

#[inline]
fn ln1p(x: f32) -> f32 {
    (x + 1.0).ln()
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

    fn walk_function_body(&mut self, body: &FunctionBody) {
        self.current_depth += 1;
        self.max_nesting_depth = self.max_nesting_depth.max(self.current_depth);
        self.walk_statements(&body.statements);
        self.current_depth -= 1;
    }

    fn walk_function(&mut self, func: &Function) {
        self.function_count += 1;
        if let Some(body) = &func.body {
            self.walk_function_body(body);
        }
    }

    fn walk_class(&mut self, class: &Class) {
        for def in &class.body.body {
            if let ClassElement::MethodDefinition(_) = def {
                self.function_count += 1;
            }
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
                    if let Some(test) = &case.test {
                        self.walk_expression(test);
                    }
                    for c in &case.consequent {
                        self.walk_statement(c);
                    }
                }
            }
            Statement::ForStatement(s) => {
                self.loop_statements += 1;
                if let Some(init) = &s.init {
                    self.walk_for_init(init);
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
            Statement::VariableDeclaration(decl) => {
                self.walk_variable_declaration(decl);
            }
            Statement::FunctionDeclaration(f) => {
                self.walk_function(f);
            }
            Statement::ClassDeclaration(c) => {
                self.walk_class(c);
            }
            Statement::ExportNamedDeclaration(decl) => {
                if let Some(d) = &decl.declaration {
                    self.walk_declaration(d);
                }
            }
            Statement::ExportDefaultDeclaration(decl) => {
                self.walk_export_default_kind(&decl.declaration);
            }
            _ => {}
        }
    }

    fn walk_declaration(&mut self, decl: &Declaration) {
        match decl {
            Declaration::VariableDeclaration(v) => self.walk_variable_declaration(v),
            Declaration::FunctionDeclaration(f) => self.walk_function(f),
            Declaration::ClassDeclaration(c) => self.walk_class(c),
            _ => {}
        }
    }

    fn walk_variable_declaration(&mut self, decl: &VariableDeclaration) {
        self.variable_declarations += 1;
        for declarator in &decl.declarations {
            if let Some(init) = &declarator.init {
                self.walk_expression(init);
            }
        }
    }

    fn walk_export_default_kind(&mut self, decl: &ExportDefaultDeclarationKind) {
        match decl {
            ExportDefaultDeclarationKind::FunctionDeclaration(f) => self.walk_function(f),
            ExportDefaultDeclarationKind::ClassDeclaration(c) => self.walk_class(c),
            _ => {
                if let Some(expr) = decl.as_expression() {
                    self.walk_expression(expr);
                }
            }
        }
    }

    fn walk_for_init(&mut self, init: &ForStatementInit) {
        match init {
            ForStatementInit::VariableDeclaration(v) => self.walk_variable_declaration(v),
            _ => {
                if let Some(expr) = init.as_expression() {
                    self.walk_expression(expr);
                }
            }
        }
    }

    fn walk_argument(&mut self, arg: &Argument) {
        match arg {
            Argument::SpreadElement(s) => self.walk_expression(&s.argument),
            _ => {
                if let Some(expr) = arg.as_expression() {
                    self.walk_expression(expr);
                }
            }
        }
    }

    fn walk_array_element(&mut self, elem: &ArrayExpressionElement) {
        match elem {
            ArrayExpressionElement::SpreadElement(s) => self.walk_expression(&s.argument),
            ArrayExpressionElement::Elision(_) => {}
            _ => {
                if let Some(expr) = elem.as_expression() {
                    self.walk_expression(expr);
                }
            }
        }
    }

    fn walk_property_key(&mut self, key: &PropertyKey) {
        match key {
            PropertyKey::StaticIdentifier(_) | PropertyKey::PrivateIdentifier(_) => {}
            _ => {
                if let Some(expr) = key.as_expression() {
                    self.walk_expression(expr);
                }
            }
        }
    }

    fn walk_expression(&mut self, expr: &Expression) {
        match expr {
            Expression::CallExpression(call) => {
                self.call_expressions += 1;
                self.walk_call_callee(&call.callee);
                for arg in &call.arguments {
                    self.walk_argument(arg);
                }
            }
            Expression::NewExpression(new_expr) => {
                self.call_expressions += 1;
                self.walk_expression(&new_expr.callee);
                for arg in &new_expr.arguments {
                    self.walk_argument(arg);
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
                self.walk_simple_assignment_target(&up.argument);
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
                    self.walk_array_element(elem);
                }
            }
            Expression::ObjectExpression(obj) => {
                self.object_literals += 1;
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            self.walk_property_key(&p.key);
                            self.walk_expression(&p.value);
                        }
                        ObjectPropertyKind::SpreadProperty(s) => {
                            self.walk_expression(&s.argument);
                        }
                    }
                }
            }
            Expression::ArrowFunctionExpression(func) => {
                self.function_count += 1;
                self.walk_function_body(&func.body);
            }
            Expression::FunctionExpression(func) => {
                self.walk_function(func);
            }
            Expression::ClassExpression(c) => {
                self.walk_class(c);
            }
            Expression::ParenthesizedExpression(p) => self.walk_expression(&p.expression),
            Expression::ChainExpression(chain) => self.walk_chain_element(&chain.expression),
            Expression::AwaitExpression(a) => self.walk_expression(&a.argument),
            Expression::YieldExpression(y) => {
                if let Some(arg) = &y.argument {
                    self.walk_expression(arg);
                }
            }
            _ => {}
        }
    }

    fn walk_simple_assignment_target(&mut self, target: &SimpleAssignmentTarget) {
        match target {
            SimpleAssignmentTarget::ComputedMemberExpression(e) => {
                self.member_expressions += 1;
                self.walk_expression(&e.object);
                self.walk_expression(&e.expression);
            }
            SimpleAssignmentTarget::StaticMemberExpression(e) => {
                self.member_expressions += 1;
                self.walk_expression(&e.object);
            }
            SimpleAssignmentTarget::PrivateFieldExpression(e) => {
                self.member_expressions += 1;
                self.walk_expression(&e.object);
            }
            _ => {}
        }
    }

    fn walk_chain_element(&mut self, elem: &ChainElement) {
        match elem {
            ChainElement::CallExpression(call) => {
                self.call_expressions += 1;
                self.walk_call_callee(&call.callee);
                for arg in &call.arguments {
                    self.walk_argument(arg);
                }
            }
            ChainElement::StaticMemberExpression(member) => {
                self.member_expressions += 1;
                self.walk_expression(&member.object);
            }
            ChainElement::ComputedMemberExpression(member) => {
                self.member_expressions += 1;
                self.walk_expression(&member.object);
                self.walk_expression(&member.expression);
            }
            ChainElement::PrivateFieldExpression(member) => {
                self.member_expressions += 1;
                self.walk_expression(&member.object);
            }
            _ => {}
        }
    }

    fn walk_call_callee(&mut self, callee: &Expression) {
        let suspicious_apis = [
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "ActiveXObject",
            "WScript",
            "XMLHttpRequest",
            "fetch",
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

    // Mirror extract_pe_features (which returns None for non-PE): only score input
    // that is actually valid JavaScript. Previously this returned Some() even when
    // the parse failed, so during TRAINING any non-JS / unparseable file in the
    // malicious folder was learned as "malware", and at INFERENCE any benign JS the
    // parser choked on (modern syntax, edge cases) looked like that class → false
    // positives. Rejecting unparseable input removes that asymmetry with the PE
    // model, which is exactly why PE rarely false-positives and JS did.
    if !ret.errors.is_empty() {
        return None;
    }

    let parse_errors = ret.errors.len();
    let parse_success = if parse_errors == 0 { 1.0 } else { 0.0 };

    let mut walker = AstWalkerCounts::new();
    walker.walk_statements(&program.body);

    if parse_errors > 0
        && walker.function_count == 0
        && walker.call_expressions == 0
        && walker.variable_declarations == 0
    {
        return None;
    }

    let hex_encoded = RE_HEX_ENCODED.find_iter(source).count() as f32;
    let unicode_encoded = RE_UNICODE_ENCODED.find_iter(source).count() as f32;
    let char_code = RE_CHAR_CODE.find_iter(source).count() as f32;
    let base64 = RE_BASE64.find_iter(source).count() as f32;
    let escape = RE_ESCAPE.find_iter(source).count() as f32;
    let bracket_notation = RE_BRACKET_NOTATION.find_iter(source).count() as f32;

    let obfuscation_score =
        hex_encoded + unicode_encoded + char_code + base64 + escape + bracket_notation;
    let is_obfuscated = if obfuscation_score > 10.0 { 1.0 } else { 0.0 };

    let crypto_refs = RE_CRYPTO.find_iter(source).count() as f32;
    let network_ops = RE_NETWORK.find_iter(source).count() as f32;
    let file_ops = RE_FILE_OPS.find_iter(source).count() as f32;
    let registry_ops = RE_REGISTRY.find_iter(source).count() as f32;
    let process_ops = RE_PROCESS.find_iter(source).count() as f32;

    // AST walker gives the suspicious_call_count; regex gives a raw text count
    // from a different angle (catches string-wrapped names the AST misses).
    let suspicious_api_calls_regex = RE_SUSPICIOUS_APIS.find_iter(source).count() as f32;

    let suspicious_score = crypto_refs * 2.0
        + network_ops * 3.0
        + file_ops * 4.0
        + registry_ops * 5.0
        + process_ops * 5.0;

    let (
        total_strings,
        avg_string_len,
        max_string_len,
        long_strings,
        base64_strings,
        url_strings,
        hex_strings_val,
    ) = extract_string_features(source);

    let (total_lines, code_lines, comment_lines, blank_lines, avg_line_len, max_line_len) =
        analyze_lines(source);

    // Cyclomatic complexity derived from AST decision points, not raw text.
    // Raw substring counting matched keywords inside strings/comments/identifiers.
    let cyclomatic =
        (walker.conditional_statements + walker.loop_statements + walker.try_catch_blocks + 1)
            as f32;

    let (total_idents, short_idents, long_idents, avg_ident_len, suspicious_naming, random_idents) =
        analyze_identifiers(source);

    Some(JsFeatureVector {
        file_size: ln1p(source.len() as f32),
        entropy: shannon_entropy_str(source),
        parse_success,
        function_count: ln1p(walker.function_count as f32),
        variable_declarations: ln1p(walker.variable_declarations as f32),
        call_expressions: ln1p(walker.call_expressions as f32),
        member_expressions: ln1p(walker.member_expressions as f32),
        binary_expressions: ln1p(walker.binary_expressions as f32),
        conditional_statements: ln1p(walker.conditional_statements as f32),
        loop_statements: ln1p(walker.loop_statements as f32),
        try_catch_blocks: walker.try_catch_blocks as f32,
        array_literals: ln1p(walker.array_literals as f32),
        object_literals: ln1p(walker.object_literals as f32),
        max_nesting_depth: walker.max_nesting_depth as f32,
        eval_usage: walker.eval_usage as f32,
        suspicious_call_count: walker.suspicious_calls.len() as f32,
        hex_encoded_strings: ln1p(hex_encoded),
        unicode_encoded_strings: ln1p(unicode_encoded),
        char_code_usage: char_code as f32,
        base64_usage: base64 as f32,
        escape_usage: escape as f32,
        bracket_notation_calls: bracket_notation as f32,
        obfuscation_score: ln1p(obfuscation_score),
        is_obfuscated,
        crypto_references: ln1p(crypto_refs),
        network_operations: ln1p(network_ops),
        file_system_operations: file_ops as f32,
        registry_operations: registry_ops as f32,
        process_operations: process_ops as f32,
        suspicious_api_calls: ln1p(suspicious_api_calls_regex),
        suspicious_score: ln1p(suspicious_score),
        total_strings: ln1p(total_strings),
        avg_string_length: avg_string_len,
        max_string_length: ln1p(max_string_len),
        long_strings_count: ln1p(long_strings),
        base64_like_strings: ln1p(base64_strings),
        url_strings: ln1p(url_strings),
        hex_strings: ln1p(hex_strings_val),
        total_lines: ln1p(total_lines),
        code_lines: ln1p(code_lines),
        comment_lines: ln1p(comment_lines),
        blank_lines: ln1p(blank_lines),
        avg_line_length: avg_line_len,
        max_line_length: ln1p(max_line_len),
        cyclomatic_complexity: ln1p(cyclomatic),
        total_identifiers: ln1p(total_idents),
        short_identifiers: ln1p(short_idents),
        long_identifiers: ln1p(long_idents),
        avg_identifier_length: avg_ident_len,
        suspicious_naming,
        random_like_identifiers: ln1p(random_idents),
    })
}

fn extract_string_features(source: &str) -> (f32, f32, f32, f32, f32, f32, f32) {
    let strings: Vec<&str> = RE_STRINGS
        .find_iter(source)
        .filter_map(|m| {
            let s = m.as_str();
            Some(&s[1..s.len() - 1])
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
    let b64 = strings.iter().filter(|s| RE_BASE64_STR.is_match(s)).count() as f32;
    let urls = strings.iter().filter(|s| RE_URL_STR.is_match(s)).count() as f32;
    let hex = strings
        .iter()
        .filter(|s| s.len() > 10 && RE_HEX_STR.is_match(s))
        .count() as f32;

    (total, avg, max, long, b64, urls, hex)
}

fn analyze_lines(source: &str) -> (f32, f32, f32, f32, f32, f32) {
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

    (
        total_lines,
        code_lines as f32,
        comment_lines as f32,
        blank_lines as f32,
        avg_line,
        max_line,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_text_returns_none() {
        let text = "The quick brown fox jumps over the lazy dog.";
        assert!(extract_js_features(text).is_none());
    }

    #[test]
    fn test_html_returns_none() {
        let html = r#"<html><body><h1>Hello</h1><p>This is not JavaScript.</p></body></html>"#;
        assert!(extract_js_features(html).is_none());
    }

    #[test]
    fn test_xml_returns_none() {
        let xml = r#"<?xml version="1.0"?><root><item id="1">value</item></root>"#;
        assert!(extract_js_features(xml).is_none());
    }

    #[test]
    fn test_json_returns_none() {
        let json = r#"{"name": "test", "version": 1, "enabled": true}"#;
        assert!(extract_js_features(json).is_none());
    }

    #[test]
    fn test_valid_js_returns_some() {
        let js = r#"
function greet(name) {
    console.log("Hello, " + name);
}
greet("world");
"#;
        let features = extract_js_features(js);
        assert!(features.is_some());
        let f = features.unwrap();
        assert!(f.function_count > 0.0);
        assert!(f.call_expressions > 0.0);
    }

    #[test]
    fn test_obfuscated_js_returns_some() {
        let js = r#"
var _0x1234 = "\\x48\\x65\\x6c\\x6c\\x6f";
eval(_0x1234);
"#;
        let features = extract_js_features(js);
        assert!(features.is_some());
        let f = features.unwrap();
        assert!(f.eval_usage > 0.0);
        assert!(f.hex_encoded_strings > 0.0);
    }

    #[test]
    fn test_empty_string_returns_some() {
        // Empty string: parser succeeds, all counts are 0, should return Some
        let features = extract_js_features("");
        assert!(features.is_some());
    }

    #[test]
    fn test_minimal_js_variable_returns_some() {
        let js = "let x = 1;";
        let features = extract_js_features(js);
        assert!(features.is_some());
        let f = features.unwrap();
        assert!(f.variable_declarations > 0.0);
    }

    #[test]
    fn test_binary_gibberish_returns_none() {
        let gibberish = "\\x00\\x01\\x02\\xff\\xfe Hello World \\x00\\x00";
        assert!(extract_js_features(gibberish).is_none());
    }

    #[test]
    fn test_css_returns_none() {
        let css = r#"
body {
    background-color: #fff;
    color: #000;
    font-family: Arial, sans-serif;
}
.container {
    margin: 0 auto;
    max-width: 1200px;
}
"#;
        assert!(extract_js_features(css).is_none());
    }

    #[test]
    fn test_csv_returns_none() {
        let csv = "name,age,city\nJohn,30,New York\nJane,25,London";
        assert!(extract_js_features(csv).is_none());
    }
}

fn analyze_identifiers(source: &str) -> (f32, f32, f32, f32, f32, f32) {
    let js_keywords = [
        "var",
        "let",
        "const",
        "function",
        "return",
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "break",
        "continue",
        "try",
        "catch",
        "finally",
        "throw",
        "new",
        "this",
        "typeof",
        "instanceof",
        "in",
        "of",
        "delete",
        "void",
        "null",
        "undefined",
        "true",
        "false",
        "class",
        "extends",
        "super",
        "static",
        "import",
        "export",
        "from",
        "default",
        "async",
        "await",
    ];

    let all: Vec<&str> = RE_IDENTIFIERS
        .find_iter(source)
        .map(|m| m.as_str())
        .collect();
    let identifiers: Vec<&str> = all
        .iter()
        .filter(|id| !js_keywords.contains(id))
        .copied()
        .collect();

    if identifiers.is_empty() {
        return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }

    let total = identifiers.len() as f32;
    let lengths: Vec<f32> = identifiers.iter().map(|id| id.len() as f32).collect();
    let avg = lengths.iter().sum::<f32>() / total;
    let short = identifiers.iter().filter(|id| id.len() <= 2).count() as f32;
    let long = identifiers.iter().filter(|id| id.len() > 20).count() as f32;

    let random = identifiers
        .iter()
        .filter(|id| id.len() > 5 && shannon_entropy_str(id) > 3.5)
        .count() as f32;

    let short_ratio = if total > 0.0 { short / total } else { 0.0 };
    let random_ratio = if total > 0.0 { random / total } else { 0.0 };
    let suspicious = if short_ratio > 0.5 || random_ratio > 0.3 {
        1.0
    } else {
        0.0
    };

    (total, short, long, avg, suspicious, random)
}
