import hashlib
import json
import pickle
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import numpy as np
import argparse
from tqdm import tqdm
import time
from collections import Counter
import ast as python_ast
import esprima  # JavaScript AST parser
from hydra_logger import logger

class JSFeatureExtractor:
    def __init__(self):
        self.features_cache = {}
        
        # Suspicious patterns for malware detection
        self.suspicious_apis = [
            'eval', 'Function', 'setTimeout', 'setInterval',
            'ActiveXObject', 'WScript.Shell', 'WScript.Network',
            'Scripting.FileSystemObject', 'Shell.Application',
            'XMLHttpRequest', 'fetch', 'WebSocket',
            'document.write', 'innerHTML', 'outerHTML',
            'execCommand', 'createTextRange'
        ]
        
        self.obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            r'String\.fromCharCode',  # Character code obfuscation
            r'atob|btoa',  # Base64 encoding/decoding
            r'unescape|escape',  # URL encoding
            r'charCodeAt',  # Character code extraction
            r'\[[\"\'].*?[\"]\]\s*\(',  # Bracket notation calls
        ]
        
        self.crypto_patterns = [
            r'crypto', r'CryptoJS', r'aes', r'des', r'rsa',
            r'md5', r'sha1', r'sha256', r'sha512',
            r'encrypt', r'decrypt', r'cipher'
        ]
        
        self.network_patterns = [
            r'http[s]?://', r'ws[s]?://', r'ftp://',
            r'fetch\s*\(', r'XMLHttpRequest',
            r'\.send\s*\(', r'\.open\s*\(',
            r'WebSocket', r'EventSource'
        ]
        
        self.file_system_patterns = [
            r'FileSystemObject', r'readFile', r'writeFile',
            r'createTextFile', r'OpenTextFile',
            r'DeleteFile', r'CopyFile', r'MoveFile'
        ]
        
        self.registry_patterns = [
            r'RegRead', r'RegWrite', r'RegDelete',
            r'HKEY_', r'HKLM', r'HKCU', r'HKCR'
        ]
        
        self.process_patterns = [
            r'Run\s*\(', r'Exec\s*\(', r'ShellExecute',
            r'CreateObject\s*\(', r'GetObject\s*\(',
            r'\.Run\s*\(', r'\.Exec\s*\('
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

    def extract_ast_features(self, code: str) -> Dict[str, Any]:
        """Extract features from JavaScript AST using esprima."""
        ast_features = {
            'parse_success': False,
            'node_counts': {},
            'function_count': 0,
            'variable_declarations': 0,
            'call_expressions': 0,
            'member_expressions': 0,
            'binary_expressions': 0,
            'conditional_statements': 0,
            'loop_statements': 0,
            'try_catch_blocks': 0,
            'array_literals': 0,
            'object_literals': 0,
            'max_nesting_depth': 0,
            'suspicious_function_calls': [],
            'eval_usage': 0,
            'error': None
        }
        
        try:
            # Parse JavaScript code
            tree = esprima.parseScript(code, {'tolerant': True, 'loc': True})
            ast_features['parse_success'] = True
            
            # Traverse AST and collect features
            def traverse(node, depth=0):
                if node is None or not isinstance(node, esprima.nodes.Node):
                    return depth
                
                node_type = node.type
                ast_features['node_counts'][node_type] = ast_features['node_counts'].get(node_type, 0) + 1
                
                max_depth = depth
                
                # Count specific node types
                if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                    ast_features['function_count'] += 1
                elif node_type == 'VariableDeclaration':
                    ast_features['variable_declarations'] += 1
                elif node_type == 'CallExpression':
                    ast_features['call_expressions'] += 1
                    # Check for suspicious function calls
                    if hasattr(node, 'callee'):
                        callee_name = self._get_callee_name(node.callee)
                        if callee_name in self.suspicious_apis:
                            ast_features['suspicious_function_calls'].append(callee_name)
                        if callee_name == 'eval':
                            ast_features['eval_usage'] += 1
                elif node_type == 'MemberExpression':
                    ast_features['member_expressions'] += 1
                elif node_type == 'BinaryExpression':
                    ast_features['binary_expressions'] += 1
                elif node_type in ['IfStatement', 'ConditionalExpression', 'SwitchStatement']:
                    ast_features['conditional_statements'] += 1
                elif node_type in ['ForStatement', 'WhileStatement', 'DoWhileStatement', 'ForInStatement', 'ForOfStatement']:
                    ast_features['loop_statements'] += 1
                elif node_type == 'TryStatement':
                    ast_features['try_catch_blocks'] += 1
                elif node_type == 'ArrayExpression':
                    ast_features['array_literals'] += 1
                elif node_type == 'ObjectExpression':
                    ast_features['object_literals'] += 1
                
                # Recursively traverse child nodes
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
            
            ast_features['max_nesting_depth'] = traverse(tree)
            
        except Exception as e:
            logger.error(f"AST parsing failed: {e}")
            ast_features['error'] = str(e)
        
        return ast_features

    def _get_callee_name(self, callee) -> str:
        """Extract function name from callee node."""
        if hasattr(callee, 'name'):
            return callee.name
        elif hasattr(callee, 'property') and hasattr(callee.property, 'name'):
            return callee.property.name
        elif hasattr(callee, 'object') and hasattr(callee.object, 'name'):
            obj_name = callee.object.name
            prop_name = getattr(callee.property, 'name', '')
            return f"{obj_name}.{prop_name}" if prop_name else obj_name
        return ''

    def analyze_obfuscation(self, code: str) -> Dict[str, Any]:
        """Analyze code for obfuscation techniques."""
        obfuscation = {
            'hex_encoded_strings': 0,
            'unicode_encoded_strings': 0,
            'char_code_usage': 0,
            'base64_usage': 0,
            'escape_usage': 0,
            'bracket_notation_calls': 0,
            'total_obfuscation_score': 0,
            'is_likely_obfuscated': False
        }
        
        for pattern_name, pattern in [
            ('hex_encoded_strings', self.obfuscation_patterns[0]),
            ('unicode_encoded_strings', self.obfuscation_patterns[1]),
            ('char_code_usage', self.obfuscation_patterns[2]),
            ('base64_usage', self.obfuscation_patterns[3]),
            ('escape_usage', self.obfuscation_patterns[4]),
            ('bracket_notation_calls', self.obfuscation_patterns[6])
        ]:
            matches = re.findall(pattern, code, re.IGNORECASE)
            count = len(matches)
            obfuscation[pattern_name] = count
            obfuscation['total_obfuscation_score'] += count
        
        # Heuristic: if obfuscation score is high, likely obfuscated
        obfuscation['is_likely_obfuscated'] = obfuscation['total_obfuscation_score'] > 10
        
        return obfuscation

    def analyze_suspicious_patterns(self, code: str) -> Dict[str, Any]:
        """Analyze code for suspicious patterns indicating malware."""
        patterns = {
            'crypto_references': 0,
            'network_operations': 0,
            'file_system_operations': 0,
            'registry_operations': 0,
            'process_operations': 0,
            'suspicious_api_calls': 0,
            'suspicious_score': 0,
            'detected_patterns': []
        }
        
        # Check crypto patterns
        for pattern in self.crypto_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns['crypto_references'] += len(matches)
                patterns['detected_patterns'].append(f"crypto:{pattern}")
        
        # Check network patterns
        for pattern in self.network_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns['network_operations'] += len(matches)
                patterns['detected_patterns'].append(f"network:{pattern}")
        
        # Check file system patterns
        for pattern in self.file_system_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns['file_system_operations'] += len(matches)
                patterns['detected_patterns'].append(f"filesystem:{pattern}")
        
        # Check registry patterns
        for pattern in self.registry_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns['registry_operations'] += len(matches)
                patterns['detected_patterns'].append(f"registry:{pattern}")
        
        # Check process patterns
        for pattern in self.process_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                patterns['process_operations'] += len(matches)
                patterns['detected_patterns'].append(f"process:{pattern}")
        
        # Count suspicious API calls
        for api in self.suspicious_apis:
            if api in code:
                patterns['suspicious_api_calls'] += code.count(api)
        
        # Calculate overall suspicious score
        patterns['suspicious_score'] = (
            patterns['crypto_references'] * 2 +
            patterns['network_operations'] * 3 +
            patterns['file_system_operations'] * 4 +
            patterns['registry_operations'] * 5 +
            patterns['process_operations'] * 5 +
            patterns['suspicious_api_calls'] * 2
        )
        
        return patterns

    def analyze_string_features(self, code: str) -> Dict[str, Any]:
        """Analyze string-related features."""
        strings = {
            'total_strings': 0,
            'avg_string_length': 0.0,
            'max_string_length': 0,
            'suspicious_strings': [],
            'long_strings_count': 0,  # Strings longer than 100 chars
            'base64_like_strings': 0,
            'url_strings': 0,
            'hex_strings': 0
        }
        
        # Extract strings (both single and double quoted)
        string_pattern = r'["\']([^"\']*)["\']'
        found_strings = re.findall(string_pattern, code)
        
        if found_strings:
            strings['total_strings'] = len(found_strings)
            string_lengths = [len(s) for s in found_strings]
            strings['avg_string_length'] = float(np.mean(string_lengths))
            strings['max_string_length'] = max(string_lengths)
            strings['long_strings_count'] = sum(1 for s in found_strings if len(s) > 100)
            
            # Check for base64-like strings (alphanumeric + / + =)
            base64_pattern = r'^[A-Za-z0-9+/]+=*$'
            strings['base64_like_strings'] = sum(1 for s in found_strings if len(s) > 20 and re.match(base64_pattern, s))
            
            # Check for URLs
            url_pattern = r'https?://|ftp://|ws[s]?://'
            strings['url_strings'] = sum(1 for s in found_strings if re.search(url_pattern, s, re.IGNORECASE))
            
            # Check for hex strings
            hex_pattern = r'^[0-9a-fA-F]+$'
            strings['hex_strings'] = sum(1 for s in found_strings if len(s) > 10 and re.match(hex_pattern, s))
            
            # Collect suspicious strings
            for s in found_strings:
                if len(s) > 100 or re.match(base64_pattern, s) or re.search(url_pattern, s, re.IGNORECASE):
                    strings['suspicious_strings'].append(s[:100])  # Truncate for storage
        
        return strings

    def analyze_code_complexity(self, code: str) -> Dict[str, Any]:
        """Analyze code complexity metrics."""
        complexity = {
            'total_lines': 0,
            'code_lines': 0,
            'comment_lines': 0,
            'blank_lines': 0,
            'avg_line_length': 0.0,
            'max_line_length': 0,
            'cyclomatic_complexity_estimate': 0
        }
        
        lines = code.split('\n')
        complexity['total_lines'] = len(lines)
        
        code_lines = []
        comment_lines = 0
        blank_lines = 0
        
        in_multiline_comment = False
        
        for line in lines:
            stripped = line.strip()
            
            # Handle multi-line comments
            if '/*' in stripped:
                in_multiline_comment = True
            if '*/' in stripped:
                in_multiline_comment = False
                comment_lines += 1
                continue
            
            if in_multiline_comment:
                comment_lines += 1
                continue
            
            # Check for single-line comments
            if stripped.startswith('//'):
                comment_lines += 1
            elif not stripped:
                blank_lines += 1
            else:
                code_lines.append(line)
        
        complexity['code_lines'] = len(code_lines)
        complexity['comment_lines'] = comment_lines
        complexity['blank_lines'] = blank_lines
        
        if code_lines:
            line_lengths = [len(line) for line in code_lines]
            complexity['avg_line_length'] = float(np.mean(line_lengths))
            complexity['max_line_length'] = max(line_lengths)
        
        # Estimate cyclomatic complexity (count decision points)
        decision_keywords = ['if', 'else', 'for', 'while', 'case', 'catch', '&&', '||', '?']
        for keyword in decision_keywords:
            complexity['cyclomatic_complexity_estimate'] += code.count(keyword)
        
        return complexity

    def analyze_identifiers(self, code: str) -> Dict[str, Any]:
        """Analyze identifier naming patterns."""
        identifiers = {
            'total_identifiers': 0,
            'short_identifiers': 0,  # 1-2 chars
            'long_identifiers': 0,   # > 20 chars
            'avg_identifier_length': 0.0,
            'suspicious_naming': False,
            'random_like_identifiers': 0
        }
        
        # Extract identifiers (variable names, function names)
        identifier_pattern = r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b'
        found_identifiers = re.findall(identifier_pattern, code)
        
        # Filter out JavaScript keywords
        js_keywords = {'var', 'let', 'const', 'function', 'return', 'if', 'else', 
                       'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
                       'try', 'catch', 'finally', 'throw', 'new', 'this', 'typeof',
                       'instanceof', 'in', 'of', 'delete', 'void', 'null', 'undefined',
                       'true', 'false', 'class', 'extends', 'super', 'static',
                       'import', 'export', 'from', 'default', 'async', 'await'}
        
        valid_identifiers = [i for i in found_identifiers if i not in js_keywords]
        
        if valid_identifiers:
            identifiers['total_identifiers'] = len(valid_identifiers)
            
            id_lengths = [len(i) for i in valid_identifiers]
            identifiers['avg_identifier_length'] = float(np.mean(id_lengths))
            identifiers['short_identifiers'] = sum(1 for i in valid_identifiers if len(i) <= 2)
            identifiers['long_identifiers'] = sum(1 for i in valid_identifiers if len(i) > 20)
            
            # Check for random-like identifiers (high entropy, alphanumeric mix)
            for identifier in valid_identifiers:
                if len(identifier) > 5 and self._calculate_entropy(identifier) > 3.5:
                    identifiers['random_like_identifiers'] += 1
            
            # Suspicious if lots of short or random identifiers
            short_ratio = identifiers['short_identifiers'] / identifiers['total_identifiers']
            random_ratio = identifiers['random_like_identifiers'] / identifiers['total_identifiers']
            identifiers['suspicious_naming'] = short_ratio > 0.5 or random_ratio > 0.3
        
        return identifiers

    def extract_all_features(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract all features from a JavaScript file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            if not code.strip():
                logger.warning(f"{file_path} is empty")
                return None
            
            features = {
                # Basic file info
                'file_size': len(code),
                'entropy': self._calculate_entropy(code),
                
                # AST-based features
                'ast_features': self.extract_ast_features(code),
                
                # Obfuscation analysis
                'obfuscation': self.analyze_obfuscation(code),
                
                # Suspicious patterns
                'suspicious_patterns': self.analyze_suspicious_patterns(code),
                
                # String analysis
                'string_features': self.analyze_string_features(code),
                
                # Code complexity
                'complexity': self.analyze_code_complexity(code),
                
                # Identifier analysis
                'identifiers': self.analyze_identifiers(code)
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from {file_path}: {e}", exc_info=True)
            return None

class DataProcessor:
    def __init__(self,
                 malicious_dir: str = 'datamaliciousorder',
                 benign_dir: str = 'data2',
                 out_dir_prefix: str = 'js_features',
                 bin_path: str = 'ml_vectors_js.bin',
                 index_path: str = 'ml_index_js.jsonl',
                 malicious_pickle_path: str = 'ml_definitions_malicious_js.pkl',
                 benign_pickle_path: str = 'ml_definitions_benign_js.pkl',
                 reset: bool = False):
        self.malicious_dir = malicious_dir
        self.benign_dir = benign_dir
        self.js_extractor = JSFeatureExtractor()
        self.problematic_dir = Path('problematic_files_js')
        self.duplicates_dir = Path('duplicate_files_js')
        self.output_dir = Path(f"{out_dir_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.bin_path = Path(bin_path)
        self.index_path = Path(index_path)
        self.malicious_pickle_path = Path(malicious_pickle_path)
        self.benign_pickle_path = Path(benign_pickle_path)
        self.reset = reset

        if self.reset:
            logger.info("Reset flag is True. Deleting existing files.")
            for p in [self.bin_path, self.index_path, self.malicious_pickle_path, self.benign_pickle_path]:
                if p.exists():
                    try:
                        p.unlink()
                        logger.info(f"Deleted: {p}")
                    except OSError as e:
                        logger.error(f"Error deleting {p}: {e}")

        for directory in [self.problematic_dir, self.duplicates_dir, self.output_dir]:
            directory.mkdir(exist_ok=True, parents=True)

        self._init_store()
        self.seen = self._load_seen_md5s()

    def _init_store(self):
        if not self.bin_path.exists():
            self.bin_path.parent.mkdir(parents=True, exist_ok=True)
            self.bin_path.write_bytes(b'')
        if not self.index_path.exists():
            self.index_path.parent.mkdir(parents=True, exist_ok=True)
            self.index_path.write_text('', encoding='utf-8')
        for p in [self.malicious_pickle_path, self.benign_pickle_path]:
            if not p.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'')

    def _load_seen_md5s(self) -> set:
        seen = set()
        try:
            with open(self.index_path, 'r', encoding='utf-8') as idxf:
                for line in idxf:
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                        md5 = obj.get('md5')
                        if md5:
                            seen.add(md5)
                    except Exception:
                        continue
        except FileNotFoundError:
            pass
        logger.info(f"Resuming: {len(seen)} md5s preloaded from index.")
        return seen

    def features_to_numeric(self, entry: dict) -> np.ndarray:
        """Convert features dict to numpy float32 vector."""
        def to_float(x, default=0.0):
            try:
                if x is None:
                    return float(default)
                return float(x)
            except Exception:
                return float(default)

        def safe_len(x):
            try:
                return len(x) if x is not None else 0
            except Exception:
                return 0

        if not isinstance(entry, dict):
            entry = {}

        file_size = to_float(entry.get('file_size', 0))
        entropy = to_float(entry.get('entropy', 0))

        # AST features
        ast_feats = entry.get('ast_features', {}) or {}
        parse_success = float(ast_feats.get('parse_success', False))
        function_count = to_float(ast_feats.get('function_count', 0))
        var_declarations = to_float(ast_feats.get('variable_declarations', 0))
        call_expressions = to_float(ast_feats.get('call_expressions', 0))
        member_expressions = to_float(ast_feats.get('member_expressions', 0))
        binary_expressions = to_float(ast_feats.get('binary_expressions', 0))
        conditional_statements = to_float(ast_feats.get('conditional_statements', 0))
        loop_statements = to_float(ast_feats.get('loop_statements', 0))
        try_catch_blocks = to_float(ast_feats.get('try_catch_blocks', 0))
        array_literals = to_float(ast_feats.get('array_literals', 0))
        object_literals = to_float(ast_feats.get('object_literals', 0))
        max_nesting_depth = to_float(ast_feats.get('max_nesting_depth', 0))
        eval_usage = to_float(ast_feats.get('eval_usage', 0))
        suspicious_calls_count = safe_len(ast_feats.get('suspicious_function_calls', []))

        # Obfuscation features
        obf = entry.get('obfuscation', {}) or {}
        hex_encoded = to_float(obf.get('hex_encoded_strings', 0))
        unicode_encoded = to_float(obf.get('unicode_encoded_strings', 0))
        char_code_usage = to_float(obf.get('char_code_usage', 0))
        base64_usage = to_float(obf.get('base64_usage', 0))
        escape_usage = to_float(obf.get('escape_usage', 0))
        bracket_notation = to_float(obf.get('bracket_notation_calls', 0))
        obfuscation_score = to_float(obf.get('total_obfuscation_score', 0))
        is_obfuscated = float(obf.get('is_likely_obfuscated', False))

        # Suspicious patterns
        susp = entry.get('suspicious_patterns', {}) or {}
        crypto_refs = to_float(susp.get('crypto_references', 0))
        network_ops = to_float(susp.get('network_operations', 0))
        file_ops = to_float(susp.get('file_system_operations', 0))
        registry_ops = to_float(susp.get('registry_operations', 0))
        process_ops = to_float(susp.get('process_operations', 0))
        suspicious_api = to_float(susp.get('suspicious_api_calls', 0))
        suspicious_score = to_float(susp.get('suspicious_score', 0))

        # String features
        strings = entry.get('string_features', {}) or {}
        total_strings = to_float(strings.get('total_strings', 0))
        avg_string_len = to_float(strings.get('avg_string_length', 0))
        max_string_len = to_float(strings.get('max_string_length', 0))
        long_strings = to_float(strings.get('long_strings_count', 0))
        base64_strings = to_float(strings.get('base64_like_strings', 0))
        url_strings = to_float(strings.get('url_strings', 0))
        hex_strings = to_float(strings.get('hex_strings', 0))

        # Complexity features
        complexity = entry.get('complexity', {}) or {}
        total_lines = to_float(complexity.get('total_lines', 0))
        code_lines = to_float(complexity.get('code_lines', 0))
        comment_lines = to_float(complexity.get('comment_lines', 0))
        blank_lines = to_float(complexity.get('blank_lines', 0))
        avg_line_len = to_float(complexity.get('avg_line_length', 0))
        max_line_len = to_float(complexity.get('max_line_length', 0))
        cyclomatic = to_float(complexity.get('cyclomatic_complexity_estimate', 0))

        # Identifier features
        idents = entry.get('identifiers', {}) or {}
        total_idents = to_float(idents.get('total_identifiers', 0))
        short_idents = to_float(idents.get('short_identifiers', 0))
        long_idents = to_float(idents.get('long_identifiers', 0))
        avg_ident_len = to_float(idents.get('avg_identifier_length', 0))
        suspicious_naming = float(idents.get('suspicious_naming', False))
        random_idents = to_float(idents.get('random_like_identifiers', 0))

        numeric = [
            file_size, entropy,
            parse_success, function_count, var_declarations,
            call_expressions, member_expressions, binary_expressions,
            conditional_statements, loop_statements, try_catch_blocks,
            array_literals, object_literals, max_nesting_depth,
            eval_usage, float(suspicious_calls_count),
            hex_encoded, unicode_encoded, char_code_usage,
            base64_usage, escape_usage, bracket_notation,
            obfuscation_score, is_obfuscated,
            crypto_refs, network_ops, file_ops,
            registry_ops, process_ops, suspicious_api, suspicious_score,
            total_strings, avg_string_len, max_string_len,
            long_strings, base64_strings, url_strings, hex_strings,
            total_lines, code_lines, comment_lines, blank_lines,
            avg_line_len, max_line_len, cyclomatic,
            total_idents, short_idents, long_idents,
            avg_ident_len, suspicious_naming, random_idents
        ]
        
        return np.asarray(numeric, dtype=np.float32)

    def _process_one(self, args: Tuple) -> Optional[Dict[str, Any]]:
        """Worker function to process a single JavaScript file."""
        file_path, rank, is_malicious = args
        
        try:
            # Read file and calculate MD5
            with open(file_path, 'rb') as f:
                content = f.read()
                md5 = hashlib.md5(content).hexdigest()
            
            # Extract features
            features = self.js_extractor.extract_all_features(str(file_path))
            if features:
                features['file_info'] = {
                    'filename': Path(file_path).name,
                    'path': str(file_path),
                    'md5': md5,
                    'size': len(content),
                    'is_malicious': bool(is_malicious),
                    'rank': rank
                }
                return features
            
            return None
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}", exc_info=True)
            try:
                self._move(Path(file_path), self.problematic_dir)
            except Exception as ex_move:
                logger.error(f"Error moving problematic file {file_path}: {ex_move}", exc_info=True)
            return None

    def _move(self, file_path: Path, dest_root: Path) -> None:
        """Move a file to destination directory."""
        dest_root = Path(dest_root)
        dest_root.mkdir(parents=True, exist_ok=True)
        dest = dest_root / file_path.name

        try:
            import shutil
            shutil.move(str(file_path), str(dest))
            logger.info(f"Moved {file_path} -> {dest}")
            return
        except FileNotFoundError:
            logger.warning(f"File not found for move: {file_path}")
            return
        except PermissionError:
            # Try copy + delete with retries
            max_retries = 6
            for attempt in range(1, max_retries + 1):
                try:
                    import shutil
                    shutil.copy2(str(file_path), str(dest))
                    os.remove(str(file_path))
                    logger.info(f"Copied and removed locked file {file_path} -> {dest}")
                    return
                except FileNotFoundError:
                    logger.warning(f"File disappeared during move: {file_path}")
                    return
                except PermissionError:
                    logger.warning(f"PermissionError moving {file_path}, attempt {attempt}/{max_retries}")
                    time.sleep(0.5 * attempt)
                    continue
                except Exception as e:
                    logger.error(f"Error moving {file_path} on attempt {attempt}: {e}", exc_info=True)
                    break
            
            logger.error(f"Failed to move {file_path} after {max_retries} retries")
            return
        except Exception as ex:
            logger.error(f"Error moving {file_path} -> {dest}: {ex}", exc_info=True)
            return

    def _append_vector_and_index(self, features: dict) -> dict:
        """Append numeric vector to bin file and index entry to JSONL."""
        fi = features.get('file_info', {})
        md5 = fi.get('md5')
        filename = fi.get('filename')
        path = fi.get('path')
        size = fi.get('size')
        is_malicious = fi.get('is_malicious')
        label = "malicious" if is_malicious else "benign"

        vec = self.features_to_numeric(features)
        vec_bytes = vec.tobytes()
        vec_bytes_len = len(vec_bytes)
        dtype_name = str(vec.dtype)

        # Append to binary file
        with open(self.bin_path, 'ab') as bf:
            offset = bf.tell()
            bf.write(vec_bytes)

        index_entry = {
            'md5': md5,
            'label': label,
            'filename': filename,
            'path': path,
            'size': size,
            'offset': offset,
            'vec_bytes_len': vec_bytes_len,
            'dtype': dtype_name,
            'vec_len': int(vec.size),
            'timestamp': datetime.now().isoformat()
        }

        # Append index line
        with open(self.index_path, 'a', encoding='utf-8') as idxf:
            idxf.write(json.dumps(index_entry, ensure_ascii=False) + '\n')

        # Append full features to pickle
        pickle_path = self.malicious_pickle_path if is_malicious else self.benign_pickle_path
        try:
            with open(pickle_path, 'ab') as pf:
                pickle.dump(features, pf, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            logger.exception(f"Failed to append pickled features for {path}: {e}")

        return index_entry

    def process_dir(self, directory: Path, is_malicious: bool):
        """Process all JavaScript files in a directory."""
        # Collect all .js files
        files = [f for f in directory.rglob('*.js') if f.is_file()]
        
        if not files:
            logger.warning(f"No .js files found in {directory}")
            return 0
        
        tasks = [(f, i, is_malicious) for i, f in enumerate(files, 1)]

        inserted = 0
        with ProcessPoolExecutor() as exe:
            for feats in tqdm(exe.map(self._process_one, tasks), total=len(tasks),
                              desc=f"Processing {'malicious' if is_malicious else 'benign'} JS files"):
                if not feats:
                    continue

                md5 = feats['file_info']['md5']
                if md5 in self.seen:
                    try:
                        self._move(Path(feats['file_info']['path']), self.duplicates_dir)
                    except Exception as e:
                        logger.error(f"Error moving duplicate: {e}", exc_info=True)
                    continue

                self.seen.add(md5)

                try:
                    self._append_vector_and_index(feats)
                    inserted += 1
                except Exception as e:
                    logger.exception(f"Failed to append vector for {feats['file_info'].get('path')}: {e}")
                    try:
                        self._move(Path(feats['file_info']['path']), self.problematic_dir)
                    except Exception:
                        pass

        logger.info(f"Finished processing {directory}: inserted {inserted} unique records")
        return inserted

    def process_dataset(self):
        """Process both malicious and benign datasets."""
        logger.info("Processing malicious JavaScript files...")
        malicious_count = self.process_dir(Path(self.malicious_dir), True)

        logger.info("Processing benign JavaScript files...")
        benign_count = self.process_dir(Path(self.benign_dir), False)

        summary = {
            'timestamp': datetime.now().isoformat(),
            'malicious_count': malicious_count,
            'benign_count': benign_count,
            'bin_path': str(self.bin_path),
            'index_path': str(self.index_path),
            'malicious_pickle_path': str(self.malicious_pickle_path),
            'benign_pickle_path': str(self.benign_pickle_path),
            'feature_vector_size': 52  # Update this if you change features
        }

        output_file = self.output_dir / 'summary.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved summary to {output_file}")
        logger.info(f"Binary store: {self.bin_path}")
        logger.info(f"Index: {self.index_path}")
        logger.info(f"Malicious pickle: {self.malicious_pickle_path}")
        logger.info(f"Benign pickle: {self.benign_pickle_path}")

def main():
    parser = argparse.ArgumentParser(description='JavaScript Malware Feature Extractor')
    parser.add_argument('--malicious-dir', default='datamaliciousorder', 
                        help='Directory containing malicious JS files')
    parser.add_argument('--benign-dir', default='data2', 
                        help='Directory containing benign JS files')
    parser.add_argument('--reset', action='store_true', 
                        help='Reset the binary store and index files before processing')
    args = parser.parse_args()

    processor = DataProcessor(args.malicious_dir, args.benign_dir, reset=args.reset)
    processor.process_dataset()

if __name__ == "__main__":
    main()
