#!/usr/bin/env python
import argparse
import os
import re
import json
import sys
from engine import process_file, PEFeatureExtractor  # Import functions from engine.py

SIGNATURES_FILE = "signatures.json"

def load_signatures(signatures_file=SIGNATURES_FILE):
    """Loads human-defined signatures from a JSON file."""
    if not os.path.exists(signatures_file):
        print(f"Signatures file {signatures_file} not found.", file=sys.stderr)
        return []
    with open(signatures_file, "r") as f:
        try:
            return json.load(f)
        except Exception as e:
            print(f"Error loading signatures: {e}", file=sys.stderr)
            return []

def dynamic_scan(file_path):
    """
    Runs dynamic analysis on an executable using process_file from engine.py.
    Returns a token string if a dynamic signature is extracted.
    """
    # process_file returns a tuple: (dynamic_signature, original_filename)
    try:
        result = process_file(file_path)
    except Exception as e:
        print(f"Dynamic analysis error: {e}", file=sys.stderr)
        return ""
    
    if result:
        dynamic_signature, fname = result
        # Only add token if dynamic_signature is non-zero
        if dynamic_signature != "0":
            return f"MEMDUMP:{dynamic_signature}"
    return ""

def static_scan(file_path):
    """
    Runs static analysis using the PEFeatureExtractor from engine.py.
    Constructs tokens based on various PE features.
    """
    extractor = PEFeatureExtractor()
    try:
        numeric_features = extractor.extract_numeric_features(file_path)
    except Exception as e:
        print(f"Static analysis failed: {e}", file=sys.stderr)
        return ""
    
    tokens = []
    # DOS Stub: if the analysis shows the DOS stub exists (indicating potential modification)
    dos_stub = numeric_features.get("dos_stub", {})
    if dos_stub and dos_stub.get("exists"):
        tokens.append("DOSSTUB:exists")
    
    # TLS Callbacks: if present, add token using the first callback address
    tls = numeric_features.get("tls_callbacks", {})
    callbacks = tls.get("callbacks", [])
    if callbacks:
        # Format first callback as hexadecimal
        tokens.append("TLS:" + hex(callbacks[0]))
    
    # Overlay: if an overlay exists and its entropy is above a threshold
    overlay = numeric_features.get("overlay", {})
    if overlay.get("exists") and overlay.get("entropy", 0) > 7.5:
        tokens.append("OVERLAY:Entropy>7.5")
    
    # Certificate: if no certificate information is found, mark as invalid
    cert = numeric_features.get("certificates", {})
    if not cert:
        tokens.append("CERT:Invalid")
    
    # Delay Imports: if no delay-load imports are found, mark as missing
    delay_imports = numeric_features.get("delay_imports", [])
    if not delay_imports:
        tokens.append("DELAYIMPORTS:Missing")
    
    # Load Config: as a simple heuristic, if the load configuration size is very small, mark as anomaly
    load_config = numeric_features.get("load_config", {})
    if load_config and load_config.get("size", 0) < 100:
        tokens.append("LOADCONFIG:Anomaly")
    
    # Bound Imports: if no bound imports are found, mark as unverified
    bound_imports = numeric_features.get("bound_imports", [])
    if not bound_imports:
        tokens.append("BOUNDIMPORTS:Unverified")
    
    # Section Characteristics: add a token if sections are present (simulate unusual flags)
    sections = numeric_features.get("sections", [])
    if sections:
        tokens.append("SECTION:Unusual")
    
    # Extended Headers: if no extended header data is found, assume corruption
    ext_headers = numeric_features.get("extended_headers", {})
    if not ext_headers:
        tokens.append("EXTHEADER:Corrupt")
    
    # Rich Header: if rich header values are missing or inconsistent
    rich_header = numeric_features.get("rich_header", {})
    if not rich_header or not rich_header.get("values"):
        tokens.append("RICHHEADER:Inconsistent")
    
    return " ".join(tokens)

def scan_file(file_path):
    """Scans the provided file using both dynamic and static methods, then applies signatures."""
    print(f"Scanning file: {file_path}")
    report_tokens = []

    # Run dynamic analysis only for executables
    if file_path.lower().endswith(".exe"):
        dynamic_result = dynamic_scan(file_path)
        if dynamic_result:
            report_tokens.append(dynamic_result)
    
    # Run static analysis for PE files (executables or similar)
    static_result = static_scan(file_path)
    if static_result:
        report_tokens.append(static_result)
    
    # Combine tokens into one scan report string
    scan_report = " ".join(report_tokens)
    print("Scan Report:", scan_report)
    
    # Load human-defined signatures and test against the scan report
    signatures = load_signatures()
    matched_signatures = []
    for sig in signatures:
        pattern = sig.get("pattern", "")
        try:
            if re.search(pattern, scan_report):
                matched_signatures.append(sig.get("name"))
        except re.error as re_err:
            print(f"Regex error in signature '{sig.get('name', '')}': {re_err}", file=sys.stderr)
    
    if matched_signatures:
        print("Matched Signatures:")
        for ms in matched_signatures:
            print(" -", ms)
    else:
        print("No signatures matched.")

def main():
    parser = argparse.ArgumentParser(description="Scanner for OpenHydra Antivirus Engine")
    parser.add_argument("file", help="Path to the file to scan")
    args = parser.parse_args()
    
    if not os.path.isfile(args.file):
        print("Error: File does not exist.", file=sys.stderr)
        return
    
    scan_file(args.file)

if __name__ == "__main__":
    main()