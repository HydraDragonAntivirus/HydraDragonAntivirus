#!/usr/bin/env python3
"""
HydraDragon ML Model Trainer - JavaScript Edition
Extracts identical 51-dimensional AST and lexical features from JavaScript files,
matching hydradragon/old_machine_learning and OpenEDR/owlyshield_predict/src/ml/js_features.rs.
Trains a high-precision LightGBM classifier and exports to ONNX.
"""

import os
import sys
import re
import math
import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, List

import numpy as np
import esprima
import lightgbm as lgb
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

JS_FEATURE_NAMES = [
    "file_size",
    "entropy",
    "parse_success",
    "function_count",
    "variable_declarations",
    "call_expressions",
    "member_expressions",
    "binary_expressions",
    "conditional_statements",
    "loop_statements",
    "try_catch_blocks",
    "array_literals",
    "object_literals",
    "max_nesting_depth",
    "eval_usage",
    "suspicious_call_count",
    "hex_encoded_strings",
    "unicode_encoded_strings",
    "char_code_usage",
    "base64_usage",
    "escape_usage",
    "bracket_notation_calls",
    "obfuscation_score",
    "is_obfuscated",
    "crypto_references",
    "network_operations",
    "file_system_operations",
    "registry_operations",
    "process_operations",
    "suspicious_api_calls",
    "suspicious_score",
    "total_strings",
    "avg_string_length",
    "max_string_length",
    "long_strings_count",
    "base64_like_strings",
    "url_strings",
    "hex_strings",
    "total_lines",
    "code_lines",
    "comment_lines",
    "blank_lines",
    "avg_line_length",
    "max_line_length",
    "cyclomatic_complexity",
    "total_identifiers",
    "short_identifiers",
    "long_identifiers",
    "avg_identifier_length",
    "suspicious_naming",
    "random_like_identifiers",
]

JAVASCRIPT_AST_NODE_TYPES = frozenset({
    "ArrowFunctionExpression", "AssignmentExpression", "AwaitExpression", "CallExpression",
    "ClassDeclaration", "DoWhileStatement", "ExportAllDeclaration", "ExportDefaultDeclaration",
    "ExportNamedDeclaration", "ForInStatement", "ForOfStatement", "ForStatement",
    "FunctionDeclaration", "FunctionExpression", "IfStatement", "ImportDeclaration",
    "NewExpression", "ReturnStatement", "SwitchStatement", "TaggedTemplateExpression",
    "ThrowStatement", "TryStatement", "UpdateExpression", "VariableDeclaration", "WhileStatement"
})

SUSPICIOUS_APIS = frozenset([
    "eval", "Function", "setTimeout", "setInterval", "ActiveXObject",
    "WScript.Shell", "WScript.Network", "Scripting.FileSystemObject",
    "Shell.Application", "XMLHttpRequest", "fetch", "WebSocket",
    "document.write", "innerHTML", "outerHTML", "execCommand", "createTextRange"
])

RE_HEX = re.compile(r"\\x[0-9a-fA-F]{2}")
RE_UNICODE = re.compile(r"\\u[0-9a-fA-F]{4}")
RE_CHAR_CODE = re.compile(r"String\.fromCharCode")
RE_BASE64 = re.compile(r"\batob\b|\bbtoa\b")
RE_ESCAPE = re.compile(r"\bunescape\b|\bescape\b")
RE_BRACKET = re.compile(r"\[[\"\'].*?[\"]\]\s*\(")
RE_CRYPTO = re.compile(r"crypto|CryptoJS|aes|des|rsa|md5|sha1|sha256|sha512|encrypt|decrypt|cipher", re.I)
RE_NETWORK = re.compile(r"http[s]?://|ws[s]?://|ftp://|fetch\s*\(|XMLHttpRequest|\.send\s*\(|\.open\s*\(|WebSocket", re.I)
RE_FILE = re.compile(r"FileSystemObject|readFile|writeFile|createTextFile|OpenTextFile|DeleteFile|CopyFile|MoveFile", re.I)
RE_REGISTRY = re.compile(r"RegRead|RegWrite|RegDelete|HKEY_|HKLM|HKCU|HKCR", re.I)
RE_PROCESS = re.compile(r"Run\s*\(|Exec\s*\(|ShellExecute|CreateObject\s*\(|GetObject\s*\(|\.Run\s*\(|\.Exec\s*\(", re.I)
RE_SUSP_API = re.compile(r"\beval\b|\bFunction\b|\bsetTimeout\b|\bsetInterval\b|\bActiveXObject\b|\bWScript\b|\bXMLHttpRequest\b|\bfetch\b|\bWebSocket\b")
RE_STRINGS = re.compile(r'["\']([^"\']*)["\']')
RE_BASE64_STR = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
RE_URL_STR = re.compile(r"https?://|ftp://|ws[s]?://", re.I)
RE_HEX_STR = re.compile(r"^[0-9a-fA-F]+$")
RE_IDENTIFIERS = re.compile(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b")

JS_KEYWORDS = frozenset([
    "var", "let", "const", "function", "return", "if", "else", "for", "while",
    "do", "switch", "case", "default", "break", "continue", "try", "catch",
    "finally", "throw", "new", "this", "typeof", "instanceof", "in", "of",
    "null", "undefined", "true", "false", "class", "extends", "super", "static",
    "import", "export", "from", "async", "await"
])

def ln1p(x: float) -> float:
    if x is None or math.isnan(x) or x <= 0:
        return 0.0
    return float(math.log1p(x))

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c, count in counts.items():
        p = count / total
        ent -= p * math.log2(p)
    return float(ent)

def get_callee_name(callee) -> str:
    if hasattr(callee, "name"):
        return callee.name
    elif hasattr(callee, "property") and hasattr(callee.property, "name"):
        return callee.property.name
    elif hasattr(callee, "object") and hasattr(callee.object, "name"):
        obj_name = callee.object.name
        prop_name = getattr(callee.property, "name", "")
        return f"{obj_name}.{prop_name}" if prop_name else obj_name
    return ""

def extract_js_features_from_source(code: str) -> Optional[List[float]]:
    if not code or len(code.strip()) < 5:
        return None

    if "\x00" in code:
        return None

    tree = None
    parse_options = {"tolerant": True, "loc": True, "jsx": True}
    for parser in (esprima.parseScript, esprima.parseModule):
        try:
            tree = parser(code, parse_options)
            if getattr(tree, "body", None) is not None:
                break
        except Exception:
            continue

    if tree is None or getattr(tree, "body", None) is None:
        return None

    ast_features = {
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
        "eval_usage": 0,
        "suspicious_calls": 0,
        "structure_nodes": 0,
    }

    def traverse(node, depth=0):
        if node is None or not isinstance(node, esprima.nodes.Node):
            return depth

        node_type = node.type
        if node_type in JAVASCRIPT_AST_NODE_TYPES:
            ast_features["structure_nodes"] += 1

        if node_type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            ast_features["function_count"] += 1
        elif node_type == "VariableDeclaration":
            ast_features["variable_declarations"] += 1
        elif node_type == "CallExpression":
            ast_features["call_expressions"] += 1
            if hasattr(node, "callee"):
                callee_name = get_callee_name(node.callee)
                if callee_name in SUSPICIOUS_APIS:
                    ast_features["suspicious_calls"] += 1
                if callee_name == "eval":
                    ast_features["eval_usage"] += 1
        elif node_type == "MemberExpression":
            ast_features["member_expressions"] += 1
        elif node_type == "BinaryExpression":
            ast_features["binary_expressions"] += 1
        elif node_type in ("IfStatement", "ConditionalExpression", "SwitchStatement"):
            ast_features["conditional_statements"] += 1
        elif node_type in ("ForStatement", "WhileStatement", "DoWhileStatement", "ForInStatement", "ForOfStatement"):
            ast_features["loop_statements"] += 1
        elif node_type == "TryStatement":
            ast_features["try_catch_blocks"] += 1
        elif node_type == "ArrayExpression":
            ast_features["array_literals"] += 1
        elif node_type == "ObjectExpression":
            ast_features["object_literals"] += 1

        max_depth = depth
        for key, value in node.__dict__.items():
            if isinstance(value, esprima.nodes.Node):
                d = traverse(value, depth + 1)
                max_depth = max(max_depth, d)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, esprima.nodes.Node):
                        d = traverse(item, depth + 1)
                        max_depth = max(max_depth, d)
        return max_depth

    ast_features["max_nesting_depth"] = traverse(tree)

    if ast_features["structure_nodes"] == 0 and ast_features["function_count"] == 0 and ast_features["call_expressions"] == 0:
        return None

    hex_encoded = float(len(RE_HEX.findall(code)))
    unicode_encoded = float(len(RE_UNICODE.findall(code)))
    char_code = float(len(RE_CHAR_CODE.findall(code)))
    base64 = float(len(RE_BASE64.findall(code)))
    escape = float(len(RE_ESCAPE.findall(code)))
    bracket = float(len(RE_BRACKET.findall(code)))
    obf_score = hex_encoded + unicode_encoded + char_code + base64 + escape + bracket
    is_obf = 1.0 if obf_score > 10.0 else 0.0

    crypto_refs = float(len(RE_CRYPTO.findall(code)))
    network_ops = float(len(RE_NETWORK.findall(code)))
    file_ops = float(len(RE_FILE.findall(code)))
    reg_ops = float(len(RE_REGISTRY.findall(code)))
    proc_ops = float(len(RE_PROCESS.findall(code)))
    susp_apis = float(len(RE_SUSP_API.findall(code)))

    susp_score = (
        crypto_refs * 2.0 +
        network_ops * 3.0 +
        file_ops * 4.0 +
        reg_ops * 5.0 +
        proc_ops * 5.0 +
        susp_apis * 2.0
    )

    raw_strings = RE_STRINGS.findall(code)
    total_strings = float(len(raw_strings))
    if raw_strings:
        lens = [len(s) for s in raw_strings]
        avg_str_len = float(np.mean(lens))
        max_str_len = float(max(lens))
        long_strings = float(sum(1 for s in raw_strings if len(s) > 100))
        b64_strings = float(sum(1 for s in raw_strings if len(s) > 20 and RE_BASE64_STR.match(s)))
        url_strings = float(sum(1 for s in raw_strings if RE_URL_STR.search(s)))
        hex_strings = float(sum(1 for s in raw_strings if len(s) > 10 and RE_HEX_STR.match(s)))
    else:
        avg_str_len = max_str_len = long_strings = b64_strings = url_strings = hex_strings = 0.0

    lines = code.split("\n")
    total_lines = float(len(lines))
    code_lines = 0
    comment_lines = 0
    blank_lines = 0
    in_multi = False
    code_line_lens = []

    for l in lines:
        st = l.strip()
        if "/*" in st:
            in_multi = True
        if "*/" in st:
            in_multi = False
            comment_lines += 1
            continue
        if in_multi:
            comment_lines += 1
            continue
        if st.startswith("//"):
            comment_lines += 1
        elif not st:
            blank_lines += 1
        else:
            code_lines += 1
            code_line_lens.append(len(l))

    avg_line_len = float(np.mean(code_line_lens)) if code_line_lens else 0.0
    max_line_len = float(max(code_line_lens)) if code_line_lens else 0.0
    cyclomatic = float(ast_features["conditional_statements"] + ast_features["loop_statements"] + ast_features["try_catch_blocks"] + 1)

    all_idents = RE_IDENTIFIERS.findall(code)
    valid_idents = [i for i in all_idents if i not in JS_KEYWORDS]
    total_idents = float(len(valid_idents))
    if valid_idents:
        id_lens = [len(i) for i in valid_idents]
        avg_id_len = float(np.mean(id_lens))
        short_idents = float(sum(1 for i in valid_idents if len(i) <= 2))
        long_idents = float(sum(1 for i in valid_idents if len(i) > 20))
        random_idents = float(sum(1 for i in valid_idents if len(i) > 5 and shannon_entropy(i) > 3.5))
        short_ratio = short_idents / total_idents
        rand_ratio = random_idents / total_idents
        susp_naming = 1.0 if (short_ratio > 0.5 or rand_ratio > 0.3) else 0.0
    else:
        avg_id_len = short_idents = long_idents = random_idents = susp_naming = 0.0

    return [
        ln1p(len(code)),
        shannon_entropy(code),
        1.0,
        ln1p(ast_features["function_count"]),
        ln1p(ast_features["variable_declarations"]),
        ln1p(ast_features["call_expressions"]),
        ln1p(ast_features["member_expressions"]),
        ln1p(ast_features["binary_expressions"]),
        ln1p(ast_features["conditional_statements"]),
        ln1p(ast_features["loop_statements"]),
        float(ast_features["try_catch_blocks"]),
        ln1p(ast_features["array_literals"]),
        ln1p(ast_features["object_literals"]),
        float(ast_features["max_nesting_depth"]),
        float(ast_features["eval_usage"]),
        float(ast_features["suspicious_calls"]),
        ln1p(hex_encoded),
        ln1p(unicode_encoded),
        char_code,
        base64,
        escape,
        bracket,
        ln1p(obf_score),
        is_obf,
        ln1p(crypto_refs),
        ln1p(network_ops),
        file_ops,
        reg_ops,
        proc_ops,
        ln1p(susp_apis),
        ln1p(susp_score),
        ln1p(total_strings),
        avg_str_len,
        ln1p(max_str_len),
        ln1p(long_strings),
        ln1p(b64_strings),
        ln1p(url_strings),
        ln1p(hex_strings),
        ln1p(total_lines),
        ln1p(code_lines),
        ln1p(comment_lines),
        ln1p(blank_lines),
        avg_line_len,
        ln1p(max_line_len),
        ln1p(cyclomatic),
        ln1p(total_idents),
        ln1p(short_idents),
        ln1p(long_idents),
        avg_id_len,
        susp_naming,
        ln1p(random_idents)
    ]

def extract_js_features_from_file(filepath: str) -> Optional[List[float]]:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        return extract_js_features_from_source(code)
    except Exception:
        return None

def find_js_files(dir_path: str, max_files: int = 100000):
    files = []
    for root, _, filenames in os.walk(dir_path):
        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            if ext in (".js", ".jse", ".vbs", ".html", ".htm", ".txt", ""):
                files.append(os.path.join(root, f))
                if len(files) >= max_files:
                    return files
    return files

def collect_js_features(file_list: List[str], workers: int, label_name: str):
    print(f"[*] Extracting JS features from {len(file_list)} {label_name} files with {workers} workers...")
    features = []
    processed = 0
    total = len(file_list)
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(extract_js_features_from_file, p): p for p in file_list}
        for future in as_completed(futures):
            processed += 1
            if processed % 5000 == 0 or processed == total:
                print(f"  -> Progress [{label_name}]: {processed}/{total} ({(processed/total)*100:.1f}%) | Valid JS so far: {len(features)}")
            res = future.result()
            if res is not None:
                features.append(res)
    print(f"[+] Valid {label_name} JS samples extracted: {len(features)} / {len(file_list)}")
    return features

def parse_args():
    parser = argparse.ArgumentParser(description="Train LightGBM JS Model and Export to ONNX")
    parser.add_argument("--malicious", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\malicious", help="Directory of malicious JS files")
    parser.add_argument("--benign", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\benign", help="Directory of benign JS files")
    parser.add_argument("--js-dir", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript", help="Root JS directory if organized by folders")
    parser.add_argument("--output-onnx", type=str, default="js_model.onnx", help="Output ONNX model path")
    parser.add_argument("--max-samples-per-class", type=int, default=50000, help="Max samples to scan from each class")
    parser.add_argument("--cache-file", type=str, default=None, help="Legacy single-file cache (joblib)")
    parser.add_argument("--chunk-dir", type=str, default="cache_chunks_js", help="Directory to store JS feature chunks")
    parser.add_argument("--chunk-size", type=int, default=3000, help="Number of files per disk chunk to avoid RAM blowup")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 6, help="Feature extraction threads")
    parser.add_argument("--extract-only", action="store_true", help="Only extract chunks to disk, do not train")
    parser.add_argument("--train-only", action="store_true", help="Only train from existing chunk directory")
    return parser.parse_args()

def collect_js_batch(file_batch: List[str], workers: int):
    features = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(extract_js_features_from_file, p): p for p in file_batch}
        for future in as_completed(futures):
            res = future.result()
            if res is not None:
                features.append(res)
    return features

def extract_js_chunks_to_disk(file_list: List[str], workers: int, label_name: str, label_val: int, chunk_dir: str, chunk_size: int):
    os.makedirs(chunk_dir, exist_ok=True)
    total_files = len(file_list)
    print(f"[*] Extracting {label_name} JS ({total_files} files) into chunks of {chunk_size} to {chunk_dir}...")
    
    chunk_idx = 0
    total_valid = 0
    
    for i in range(0, total_files, chunk_size):
        chunk_files = file_list[i : i + chunk_size]
        chunk_path = os.path.join(chunk_dir, f"chunk_js_{label_name.lower()}_{chunk_idx:04d}.joblib")
        
        if os.path.exists(chunk_path):
            print(f"  [>] Chunk {chunk_idx:04d} already exists on disk, skipping.")
            chunk_idx += 1
            continue
            
        feats = collect_js_batch(chunk_files, workers)
        if feats:
            X_chunk = np.array(feats, dtype=np.float32)
            y_chunk = np.full(len(feats), label_val, dtype=np.int32)
            joblib.dump({"X": X_chunk, "y": y_chunk}, chunk_path, compress=3)
            total_valid += len(feats)
            print(f"  [+] Saved {chunk_path}: {len(feats)} valid samples (Processed {min(i + chunk_size, total_files)}/{total_files})")
        else:
            print(f"  [-] Chunk {chunk_idx:04d} had 0 valid JS samples.")
            
        del feats
        import gc
        gc.collect()
        chunk_idx += 1
        
    print(f"[+] Total {label_name} JS samples extracted: {total_valid}")
    return total_valid

def load_js_chunks_balanced(chunk_dir: str):
    import glob
    chunk_files = glob.glob(os.path.join(chunk_dir, "chunk_js_*.joblib"))
    if not chunk_files:
        raise RuntimeError(f"No JS chunk files found in {chunk_dir}")
        
    print(f"[*] Found {len(chunk_files)} chunk files in {chunk_dir}. Loading and balancing 50/50...")
    X_mal_list, X_ben_list = [], []
    
    for cf in chunk_files:
        data = joblib.load(cf)
        X_sub = data["X"]
        y_sub = data["y"]
        if y_sub[0] == 1:
            X_mal_list.append(X_sub)
        else:
            X_ben_list.append(X_sub)
            
    if not X_mal_list or not X_ben_list:
        raise RuntimeError(f"Need both Malicious and Benign chunks in {chunk_dir} to train!")
        
    X_mal = np.vstack(X_mal_list)
    X_ben = np.vstack(X_ben_list)
    
    n_mal = len(X_mal)
    n_ben = len(X_ben)
    target_each = min(n_mal, n_ben)
    print(f"[*] Raw counts: {n_mal} Malicious, {n_ben} Benign -> Balancing to {target_each} each (50/50)")
    
    np.random.seed(42)
    idx_mal = np.random.choice(n_mal, target_each, replace=False)
    idx_ben = np.random.choice(n_ben, target_each, replace=False)
    
    X = np.vstack([X_mal[idx_mal], X_ben[idx_ben]])
    y = np.array([1] * target_each + [0] * target_each, dtype=np.int32)
    
    del X_mal, X_ben, X_mal_list, X_ben_list
    import gc
    gc.collect()
    
    print(f"[+] Loaded perfectly balanced JS dataset: {len(X)} samples ({target_each} Malicious, {target_each} Benign)")
    return X, y

def main():
    args = parse_args()
    print("=" * 65)
    print(" HydraDragon Antivirus - High Precision JS LightGBM Trainer ")
    print(" (Out-of-Core Low RAM Chunked Engine) ")
    print("=" * 65)

    if not args.train_only:
        mal_files, ben_files = [], []
        if os.path.exists(args.malicious) and os.path.exists(args.benign):
            mal_files = find_js_files(args.malicious, args.max_samples_per_class)
            ben_files = find_js_files(args.benign, args.max_samples_per_class)
        elif os.path.exists(args.js_dir):
            for root, _, filenames in os.walk(args.js_dir):
                r_low = root.lower()
                is_mal = "malware" in r_low or "malicious" in r_low or "virus" in r_low or "obfuscated" in r_low
                for f in filenames:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in (".js", ".jse", ".vbs", ".html", ".htm", ".txt", ""):
                        full_p = os.path.join(root, f)
                        if is_mal and len(mal_files) < args.max_samples_per_class:
                            mal_files.append(full_p)
                        elif not is_mal and len(ben_files) < args.max_samples_per_class:
                            ben_files.append(full_p)
                            
        print(f"[+] Discovered {len(mal_files)} malicious JS and {len(ben_files)} benign JS files.")
        extract_js_chunks_to_disk(mal_files, args.workers, "MALICIOUS", 1, args.chunk_dir, args.chunk_size)
        extract_js_chunks_to_disk(ben_files, args.workers, "BENIGN", 0, args.chunk_dir, args.chunk_size)

    if args.extract_only:
        print("[+] Feature extraction finished. Exiting as --extract-only was specified.")
        return

    X, y = load_js_chunks_balanced(args.chunk_dir)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train)} | Test set: {len(X_test)}")

    print("[*] Training LightGBM Classifier (Balanced 50/50, zero false-positive tuning)...")
    clf = lgb.LGBMClassifier(
        n_estimators=400,
        learning_rate=0.03,
        num_leaves=63,
        max_depth=8,
        min_child_samples=30,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.0,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"], digits=4))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) * 100.0 if (tp + fn) > 0 else 0.0
    print(f"Confusion Matrix: TP={tp}, FN={fn}, TN={tn}, FP={fp}")
    print(f"JS Malware Recall (Detection Rate): {recall:.2f}%")
    print(f"False Positive Rate (FPR):          {fpr:.2f}%")
    print("=" * 79)

    print(f"[*] Converting LightGBM JS model to ONNX: {args.output_onnx}...")
    initial_type = [("float_input", FloatTensorType([None, len(JS_FEATURE_NAMES)]))]
    onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
    with open(args.output_onnx, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"[+] JS ONNX model successfully saved to {args.output_onnx}!")

if __name__ == "__main__":
    main()
