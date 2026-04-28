import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import esprima
import numpy as np

from .hydra_logger import logger


FEATURE_VECTOR_SIZE = 51


JAVASCRIPT_AST_NODE_TYPES = frozenset(
    {
        "ArrowFunctionExpression",
        "AssignmentExpression",
        "AwaitExpression",
        "CallExpression",
        "ClassDeclaration",
        "DoWhileStatement",
        "ExportAllDeclaration",
        "ExportDefaultDeclaration",
        "ExportNamedDeclaration",
        "ForInStatement",
        "ForOfStatement",
        "ForStatement",
        "FunctionDeclaration",
        "FunctionExpression",
        "IfStatement",
        "ImportDeclaration",
        "NewExpression",
        "ReturnStatement",
        "SwitchStatement",
        "TaggedTemplateExpression",
        "ThrowStatement",
        "TryStatement",
        "UpdateExpression",
        "VariableDeclaration",
        "WhileStatement",
    }
)


class JSFeatureExtractor:
    def __init__(self):
        self.features_cache = {}

        # Suspicious patterns for malware detection
        self.suspicious_apis = [
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "ActiveXObject",
            "WScript.Shell",
            "WScript.Network",
            "Scripting.FileSystemObject",
            "Shell.Application",
            "XMLHttpRequest",
            "fetch",
            "WebSocket",
            "document.write",
            "innerHTML",
            "outerHTML",
            "execCommand",
            "createTextRange",
        ]

        self.obfuscation_patterns = [
            r"\\x[0-9a-fA-F]{2}",
            r"\\u[0-9a-fA-F]{4}",
            r"String\.fromCharCode",
            r"atob|btoa",
            r"unescape|escape",
            r"charCodeAt",
            r"\[[\"\'].*?[\"]\]\s*\(",
        ]

        self.crypto_patterns = [
            r"crypto",
            r"CryptoJS",
            r"aes",
            r"des",
            r"rsa",
            r"md5",
            r"sha1",
            r"sha256",
            r"sha512",
            r"encrypt",
            r"decrypt",
            r"cipher",
        ]

        self.network_patterns = [
            r"http[s]?://",
            r"ws[s]?://",
            r"ftp://",
            r"fetch\s*\(",
            r"XMLHttpRequest",
            r"\.send\s*\(",
            r"\.open\s*\(",
            r"WebSocket",
            r"EventSource",
        ]

        self.file_system_patterns = [
            r"FileSystemObject",
            r"readFile",
            r"writeFile",
            r"createTextFile",
            r"OpenTextFile",
            r"DeleteFile",
            r"CopyFile",
            r"MoveFile",
        ]

        self.registry_patterns = [
            r"RegRead",
            r"RegWrite",
            r"RegDelete",
            r"HKEY_",
            r"HKLM",
            r"HKCU",
            r"HKCR",
        ]

        self.process_patterns = [
            r"Run\s*\(",
            r"Exec\s*\(",
            r"ShellExecute",
            r"CreateObject\s*\(",
            r"GetObject\s*\(",
            r"\.Run\s*\(",
            r"\.Exec\s*\(",
        ]

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string data."""
        if not data:
            return 0.0

        char_counts = Counter(data)
        total_chars = len(data)
        probs = np.array([count / total_chars for count in char_counts.values()])
        entropy = -np.sum(probs * np.log2(probs))
        return float(entropy)

    def _iter_ast_nodes(self, node):
        """Yield an Esprima AST depth-first."""
        if node is None or not hasattr(node, "type"):
            return

        yield node

        for value in getattr(node, "__dict__", {}).values():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, "type"):
                        yield from self._iter_ast_nodes(item)
            elif hasattr(value, "type"):
                yield from self._iter_ast_nodes(value)

    def _parse_javascript_tree(self, code: str):
        """Try both classic script and ES module parsing modes."""
        parse_options = {"tolerant": True, "loc": True, "jsx": True}

        for parser in (esprima.parseScript, esprima.parseModule):
            try:
                tree = parser(code, parse_options)
                if getattr(tree, "body", None) is not None:
                    return tree
            except Exception:
                continue

        return None

    def is_javascript_source(self, code: str) -> bool:
        """Return True only for text Esprima recognizes as real JavaScript."""
        if not code:
            return False

        stripped = code.lstrip("\ufeff \t\r\n")
        if not stripped or "\x00" in code:
            return False

        tree = self._parse_javascript_tree(code)
        if tree is None:
            return False

        for node in self._iter_ast_nodes(tree):
            if getattr(node, "type", "") in JAVASCRIPT_AST_NODE_TYPES:
                return True

        return False

    def is_javascript_file(self, file_path: str | Path) -> bool:
        """Detect JavaScript by AST instead of by filename extension."""
        try:
            with open(file_path, "rb") as handle:
                raw = handle.read()

            if not raw or b"\x00" in raw:
                return False

            return self.is_javascript_source(raw.decode("utf-8", errors="ignore"))
        except Exception:
            return False

    def extract_ast_features(self, code: str) -> Dict[str, Any]:
        """Extract features from JavaScript AST using esprima."""
        ast_features = {
            "parse_success": False,
            "node_counts": {},
            "function_count": 0,
            "variable_declarations": 0,
            "call_expressions": 0,
            "member_expressions": 0,
            "binary_expressions": 0,
            "conditional_statements": 0,
            "loop_statements": 0,
            "try_catch_blocks": 0,
            "array_literals": 0,
            "object_literals": 0,
            "max_nesting_depth": 0,
            "suspicious_function_calls": [],
            "eval_usage": 0,
            "program_structure_nodes": 0,
            "error": None,
        }

        try:
            tree = self._parse_javascript_tree(code)
            if tree is None:
                raise ValueError("Esprima could not parse the source as script or module")
            ast_features["parse_success"] = True

            def traverse(node, depth=0):
                if node is None or not isinstance(node, esprima.nodes.Node):
                    return depth

                node_type = node.type
                ast_features["node_counts"][node_type] = ast_features["node_counts"].get(node_type, 0) + 1

                max_depth = depth

                if node_type in JAVASCRIPT_AST_NODE_TYPES:
                    ast_features["program_structure_nodes"] += 1

                if node_type in ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"]:
                    ast_features["function_count"] += 1
                elif node_type == "VariableDeclaration":
                    ast_features["variable_declarations"] += 1
                elif node_type == "CallExpression":
                    ast_features["call_expressions"] += 1
                    if hasattr(node, "callee"):
                        callee_name = self._get_callee_name(node.callee)
                        if callee_name in self.suspicious_apis:
                            ast_features["suspicious_function_calls"].append(callee_name)
                        if callee_name == "eval":
                            ast_features["eval_usage"] += 1
                elif node_type == "MemberExpression":
                    ast_features["member_expressions"] += 1
                elif node_type == "BinaryExpression":
                    ast_features["binary_expressions"] += 1
                elif node_type in ["IfStatement", "ConditionalExpression", "SwitchStatement"]:
                    ast_features["conditional_statements"] += 1
                elif node_type in ["ForStatement", "WhileStatement", "DoWhileStatement", "ForInStatement", "ForOfStatement"]:
                    ast_features["loop_statements"] += 1
                elif node_type == "TryStatement":
                    ast_features["try_catch_blocks"] += 1
                elif node_type == "ArrayExpression":
                    ast_features["array_literals"] += 1
                elif node_type == "ObjectExpression":
                    ast_features["object_literals"] += 1

                for key, value in node.__dict__.items():
                    if isinstance(value, esprima.nodes.Node):
                        child_depth = traverse(value, depth + 1)
                        max_depth = max(max_depth, child_depth)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, esprima.nodes.Node):
                                child_depth = traverse(item, depth + 1)
                                max_depth = max(max_depth, child_depth)

                return max_depth

            ast_features["max_nesting_depth"] = traverse(tree)

        except Exception as e:
            logger.error(f"AST parsing failed: {e}")
            ast_features["error"] = str(e)

        return ast_features

    def _get_callee_name(self, callee) -> str:
        """Extract function name from callee node."""
        if hasattr(callee, "name"):
            return callee.name
        if hasattr(callee, "property") and hasattr(callee.property, "name"):
            return callee.property.name
        if hasattr(callee, "object") and hasattr(callee.object, "name"):
            obj_name = callee.object.name
            prop_name = getattr(callee.property, "name", "")
            return f"{obj_name}.{prop_name}" if prop_name else obj_name
        return ""

    def analyze_obfuscation(self, code: str) -> Dict[str, Any]:
        """Analyze code for obfuscation techniques."""
        obfuscation = {
            "hex_encoded_strings": 0,
            "unicode_encoded_strings": 0,
            "char_code_usage": 0,
            "base64_usage": 0,
            "escape_usage": 0,
            "bracket_notation_calls": 0,
            "total_obfuscation_score": 0,
            "is_likely_obfuscated": False,
        }

        for pattern_name, pattern in [
            ("hex_encoded_strings", self.obfuscation_patterns[0]),
            ("unicode_encoded_strings", self.obfuscation_patterns[1]),
            ("char_code_usage", self.obfuscation_patterns[2]),
            ("base64_usage", self.obfuscation_patterns[3]),
            ("escape_usage", self.obfuscation_patterns[4]),
            ("bracket_notation_calls", self.obfuscation_patterns[6]),
        ]:
            matches = re.findall(pattern, code, re.IGNORECASE)
            count = len(matches)
            obfuscation[pattern_name] = count
            obfuscation["total_obfuscation_score"] += count

        obfuscation["is_likely_obfuscated"] = obfuscation["total_obfuscation_score"] > 10
        return obfuscation

    def analyze_suspicious_patterns(self, code: str) -> Dict[str, Any]:
        """Analyze code for suspicious patterns indicating malware."""
        patterns = {
            "crypto_references": 0,
            "network_operations": 0,
            "file_system_operations": 0,
            "registry_operations": 0,
            "process_operations": 0,
            "suspicious_api_calls": 0,
            "suspicious_score": 0,
            "detected_patterns": [],
        }

        for pattern in self.crypto_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns["crypto_references"] += len(matches)
                patterns["detected_patterns"].append(f"crypto:{pattern}")

        for pattern in self.network_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns["network_operations"] += len(matches)
                patterns["detected_patterns"].append(f"network:{pattern}")

        for pattern in self.file_system_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns["file_system_operations"] += len(matches)
                patterns["detected_patterns"].append(f"filesystem:{pattern}")

        for pattern in self.registry_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns["registry_operations"] += len(matches)
                patterns["detected_patterns"].append(f"registry:{pattern}")

        for pattern in self.process_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns["process_operations"] += len(matches)
                patterns["detected_patterns"].append(f"process:{pattern}")

        for api in self.suspicious_apis:
            if api in code:
                patterns["suspicious_api_calls"] += code.count(api)

        patterns["suspicious_score"] = (
            patterns["crypto_references"] * 2 + patterns["network_operations"] * 3 + patterns["file_system_operations"] * 4 + patterns["registry_operations"] * 5 + patterns["process_operations"] * 5 + patterns["suspicious_api_calls"] * 2
        )

        return patterns

    def analyze_string_features(self, code: str) -> Dict[str, Any]:
        """Analyze string-related features."""
        strings = {
            "total_strings": 0,
            "avg_string_length": 0.0,
            "max_string_length": 0,
            "suspicious_strings": [],
            "long_strings_count": 0,
            "base64_like_strings": 0,
            "url_strings": 0,
            "hex_strings": 0,
        }

        string_pattern = r'["\']([^"\']*)["\']'
        found_strings = re.findall(string_pattern, code)

        if found_strings:
            strings["total_strings"] = len(found_strings)
            string_lengths = [len(s) for s in found_strings]
            strings["avg_string_length"] = float(np.mean(string_lengths))
            strings["max_string_length"] = max(string_lengths)
            strings["long_strings_count"] = sum(1 for s in found_strings if len(s) > 100)

            base64_pattern = r"^[A-Za-z0-9+/]+=*$"
            strings["base64_like_strings"] = sum(1 for s in found_strings if len(s) > 20 and re.match(base64_pattern, s))

            url_pattern = r"https?://|ftp://|ws[s]?://"
            strings["url_strings"] = sum(1 for s in found_strings if re.search(url_pattern, s, re.IGNORECASE))

            hex_pattern = r"^[0-9a-fA-F]+$"
            strings["hex_strings"] = sum(1 for s in found_strings if len(s) > 10 and re.match(hex_pattern, s))

            for s in found_strings:
                if len(s) > 100 or re.match(base64_pattern, s) or re.search(url_pattern, s, re.IGNORECASE):
                    strings["suspicious_strings"].append(s[:100])

        return strings

    def analyze_code_complexity(self, code: str) -> Dict[str, Any]:
        """Analyze code complexity metrics."""
        complexity = {
            "total_lines": 0,
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
            "avg_line_length": 0.0,
            "max_line_length": 0,
            "cyclomatic_complexity_estimate": 0,
        }

        lines = code.split("\n")
        complexity["total_lines"] = len(lines)

        code_lines = []
        comment_lines = 0
        blank_lines = 0
        in_multiline_comment = False

        for line in lines:
            stripped = line.strip()

            if "/*" in stripped:
                in_multiline_comment = True
            if "*/" in stripped:
                in_multiline_comment = False
                comment_lines += 1
                continue

            if in_multiline_comment:
                comment_lines += 1
                continue

            if stripped.startswith("//"):
                comment_lines += 1
            elif not stripped:
                blank_lines += 1
            else:
                code_lines.append(line)

        complexity["code_lines"] = len(code_lines)
        complexity["comment_lines"] = comment_lines
        complexity["blank_lines"] = blank_lines

        if code_lines:
            line_lengths = [len(line) for line in code_lines]
            complexity["avg_line_length"] = float(np.mean(line_lengths))
            complexity["max_line_length"] = max(line_lengths)

        decision_keywords = ["if", "else", "for", "while", "case", "catch", "&&", "||", "?"]
        for keyword in decision_keywords:
            complexity["cyclomatic_complexity_estimate"] += code.count(keyword)

        return complexity

    def analyze_identifiers(self, code: str) -> Dict[str, Any]:
        """Analyze identifier naming patterns."""
        identifiers = {
            "total_identifiers": 0,
            "short_identifiers": 0,
            "long_identifiers": 0,
            "avg_identifier_length": 0.0,
            "suspicious_naming": False,
            "random_like_identifiers": 0,
        }

        identifier_pattern = r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b"
        found_identifiers = re.findall(identifier_pattern, code)

        js_keywords = {
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
        }

        valid_identifiers = [identifier for identifier in found_identifiers if identifier not in js_keywords]

        if valid_identifiers:
            identifiers["total_identifiers"] = len(valid_identifiers)
            id_lengths = [len(identifier) for identifier in valid_identifiers]
            identifiers["avg_identifier_length"] = float(np.mean(id_lengths))
            identifiers["short_identifiers"] = sum(1 for identifier in valid_identifiers if len(identifier) <= 2)
            identifiers["long_identifiers"] = sum(1 for identifier in valid_identifiers if len(identifier) > 20)

            for identifier in valid_identifiers:
                if len(identifier) > 5 and self._calculate_entropy(identifier) > 3.5:
                    identifiers["random_like_identifiers"] += 1

            short_ratio = identifiers["short_identifiers"] / identifiers["total_identifiers"]
            random_ratio = identifiers["random_like_identifiers"] / identifiers["total_identifiers"]
            identifiers["suspicious_naming"] = short_ratio > 0.5 or random_ratio > 0.3

        return identifiers

    def extract_features_from_code(self, code: str, file_path: Optional[str] = None, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Extract all supported features from JavaScript source code."""
        if not code or not code.strip():
            logger.warning(f"{file_path or '<memory>'} is empty")
            return None

        ast_features = self.extract_ast_features(code)
        if not ast_features.get("parse_success") or ast_features.get("program_structure_nodes", 0) <= 0:
            logger.warning(f"{file_path or '<memory>'} is not recognized as JavaScript by Esprima")
            return None

        features = {
            "file_size": len(code),
            "entropy": self._calculate_entropy(code),
            "ast_features": ast_features,
            "obfuscation": self.analyze_obfuscation(code),
            "suspicious_patterns": self.analyze_suspicious_patterns(code),
            "string_features": self.analyze_string_features(code),
            "complexity": self.analyze_code_complexity(code),
            "identifiers": self.analyze_identifiers(code),
        }

        if file_path:
            features["file_info"] = {
                "filename": os.path.basename(file_path),
                "path": file_path,
                "size": len(code),
            }

        if rank is not None:
            features["numeric_tag"] = rank

        return features

    def extract_all_features(self, file_path: str, problematic_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Extract all features from a JavaScript file. Moves to problematic_path if it fails."""

        def _move_failed():
            if problematic_path:
                try:
                    dest = Path(problematic_path)
                    dest.mkdir(parents=True, exist_ok=True)
                    import shutil

                    shutil.move(file_path, str(dest / Path(file_path).name))
                except Exception:
                    pass

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                code = handle.read()

            features = self.extract_features_from_code(code, file_path=file_path)
            if features:
                return features

            _move_failed()
            return None

        except Exception as e:
            logger.error(f"Error extracting features from {file_path}: {e}", exc_info=True)
            _move_failed()
            return None

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Compatibility wrapper matching the PE extractor naming convention.
        Returns a structured feature dictionary, not a flattened vector.
        """
        features = self.extract_all_features(file_path)
        if features and rank is not None:
            features["numeric_tag"] = rank
        return features

    def extract_numeric_vector(self, file_path: str, rank: Optional[int] = None) -> Optional[List[float]]:
        """Extract a flattened numeric vector for similarity comparison."""
        features = self.extract_numeric_features(file_path, rank=rank)
        if not features:
            return None
        return features_to_numeric(features)


def features_to_numeric(entry: dict) -> List[float]:
    """Convert a JS feature dictionary to a numeric vector."""

    def to_float(value, default=0.0):
        try:
            if value is None:
                return float(default)
            return float(value)
        except Exception:
            return float(default)

    def safe_len(value):
        try:
            return len(value) if value is not None else 0
        except Exception:
            return 0

    if not isinstance(entry, dict):
        entry = {}

    file_size = to_float(entry.get("file_size", 0))
    entropy = to_float(entry.get("entropy", 0))

    ast_feats = entry.get("ast_features", {}) or {}
    parse_success = float(ast_feats.get("parse_success", False))
    function_count = to_float(ast_feats.get("function_count", 0))
    var_declarations = to_float(ast_feats.get("variable_declarations", 0))
    call_expressions = to_float(ast_feats.get("call_expressions", 0))
    member_expressions = to_float(ast_feats.get("member_expressions", 0))
    binary_expressions = to_float(ast_feats.get("binary_expressions", 0))
    conditional_statements = to_float(ast_feats.get("conditional_statements", 0))
    loop_statements = to_float(ast_feats.get("loop_statements", 0))
    try_catch_blocks = to_float(ast_feats.get("try_catch_blocks", 0))
    array_literals = to_float(ast_feats.get("array_literals", 0))
    object_literals = to_float(ast_feats.get("object_literals", 0))
    max_nesting_depth = to_float(ast_feats.get("max_nesting_depth", 0))
    eval_usage = to_float(ast_feats.get("eval_usage", 0))
    suspicious_calls_count = safe_len(ast_feats.get("suspicious_function_calls", []))

    obf = entry.get("obfuscation", {}) or {}
    hex_encoded = to_float(obf.get("hex_encoded_strings", 0))
    unicode_encoded = to_float(obf.get("unicode_encoded_strings", 0))
    char_code_usage = to_float(obf.get("char_code_usage", 0))
    base64_usage = to_float(obf.get("base64_usage", 0))
    escape_usage = to_float(obf.get("escape_usage", 0))
    bracket_notation = to_float(obf.get("bracket_notation_calls", 0))
    obfuscation_score = to_float(obf.get("total_obfuscation_score", 0))
    is_obfuscated = float(obf.get("is_likely_obfuscated", False))

    susp = entry.get("suspicious_patterns", {}) or {}
    crypto_refs = to_float(susp.get("crypto_references", 0))
    network_ops = to_float(susp.get("network_operations", 0))
    file_ops = to_float(susp.get("file_system_operations", 0))
    registry_ops = to_float(susp.get("registry_operations", 0))
    process_ops = to_float(susp.get("process_operations", 0))
    suspicious_api = to_float(susp.get("suspicious_api_calls", 0))
    suspicious_score = to_float(susp.get("suspicious_score", 0))

    strings = entry.get("string_features", {}) or {}
    total_strings = to_float(strings.get("total_strings", 0))
    avg_string_len = to_float(strings.get("avg_string_length", 0))
    max_string_len = to_float(strings.get("max_string_length", 0))
    long_strings = to_float(strings.get("long_strings_count", 0))
    base64_strings = to_float(strings.get("base64_like_strings", 0))
    url_strings = to_float(strings.get("url_strings", 0))
    hex_strings = to_float(strings.get("hex_strings", 0))

    complexity = entry.get("complexity", {}) or {}
    total_lines = to_float(complexity.get("total_lines", 0))
    code_lines = to_float(complexity.get("code_lines", 0))
    comment_lines = to_float(complexity.get("comment_lines", 0))
    blank_lines = to_float(complexity.get("blank_lines", 0))
    avg_line_len = to_float(complexity.get("avg_line_length", 0))
    max_line_len = to_float(complexity.get("max_line_length", 0))
    cyclomatic = to_float(complexity.get("cyclomatic_complexity_estimate", 0))

    idents = entry.get("identifiers", {}) or {}
    total_idents = to_float(idents.get("total_identifiers", 0))
    short_idents = to_float(idents.get("short_identifiers", 0))
    long_idents = to_float(idents.get("long_identifiers", 0))
    avg_ident_len = to_float(idents.get("avg_identifier_length", 0))
    suspicious_naming = float(idents.get("suspicious_naming", False))
    random_idents = to_float(idents.get("random_like_identifiers", 0))

    return [
        file_size,
        entropy,
        parse_success,
        function_count,
        var_declarations,
        call_expressions,
        member_expressions,
        binary_expressions,
        conditional_statements,
        loop_statements,
        try_catch_blocks,
        array_literals,
        object_literals,
        max_nesting_depth,
        eval_usage,
        float(suspicious_calls_count),
        hex_encoded,
        unicode_encoded,
        char_code_usage,
        base64_usage,
        escape_usage,
        bracket_notation,
        obfuscation_score,
        is_obfuscated,
        crypto_refs,
        network_ops,
        file_ops,
        registry_ops,
        process_ops,
        suspicious_api,
        suspicious_score,
        total_strings,
        avg_string_len,
        max_string_len,
        long_strings,
        base64_strings,
        url_strings,
        hex_strings,
        total_lines,
        code_lines,
        comment_lines,
        blank_lines,
        avg_line_len,
        max_line_len,
        cyclomatic,
        total_idents,
        short_idents,
        long_idents,
        avg_ident_len,
        suspicious_naming,
        random_idents,
    ]


def entry_to_numeric(entry: dict) -> Tuple[List[float], str]:
    """Flatten an extracted feature entry and return its filename metadata."""
    numeric = features_to_numeric(entry)
    filename = (entry.get("file_info", {}) or {}).get("filename", "unknown")
    return numeric, filename


def calculate_vector_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculate cosine similarity scaled into the [0, 1] range."""
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0

    arr1 = np.array(vec1, dtype=np.float64)
    arr2 = np.array(vec2, dtype=np.float64)

    dot_product = np.dot(arr1, arr2)
    norm_vec1 = np.linalg.norm(arr1)
    norm_vec2 = np.linalg.norm(arr2)

    if norm_vec1 == 0 or norm_vec2 == 0:
        return 1.0 if norm_vec1 == norm_vec2 else 0.0

    cosine_similarity = dot_product / (norm_vec1 * norm_vec2)
    return float((cosine_similarity + 1) / 2)


js_extractor = JSFeatureExtractor()
