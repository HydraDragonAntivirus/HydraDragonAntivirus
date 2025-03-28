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
    Always returns a detailed MEMDUMP token.
    """
    try:
        result = process_file(file_path)
    except Exception as e:
        print(f"Dynamic analysis error: {e}", file=sys.stderr)
        return "MEMDUMP:0"
    
    if result:
        dynamic_signature, fname = result
        if dynamic_signature != "0":
            return f"MEMDUMP:{dynamic_signature}"
    return "MEMDUMP:0"

def detailed_static_scan(file_path):
    """
    Runs static analysis using PEFeatureExtractor from engine.py.
    Constructs detailed tokens for every feature extracted.
    """
    extractor = PEFeatureExtractor()
    try:
        nf = extractor.extract_numeric_features(file_path)
    except Exception as e:
        print(f"Static analysis failed: {e}", file=sys.stderr)
        nf = {}

    tokens = []

    # Optional Header Fields
    tokens.append(f"OPTIONALHEADER:SizeOfOptionalHeader={nf.get('SizeOfOptionalHeader','NA')}")
    tokens.append(f"LINKERVERSION:{nf.get('MajorLinkerVersion','NA')}.{nf.get('MinorLinkerVersion','NA')}")
    tokens.append(f"SizeOfCode={nf.get('SizeOfCode','NA')}")
    tokens.append(f"SizeOfInitializedData={nf.get('SizeOfInitializedData','NA')}")
    tokens.append(f"SizeOfUninitializedData={nf.get('SizeOfUninitializedData','NA')}")
    tokens.append(f"AddressOfEntryPoint={hex(nf.get('AddressOfEntryPoint',0))}")
    tokens.append(f"BaseOfCode={hex(nf.get('BaseOfCode',0))}")
    tokens.append(f"BaseOfData={hex(nf.get('BaseOfData',0))}")
    tokens.append(f"ImageBase={hex(nf.get('ImageBase',0))}")
    tokens.append(f"SectionAlignment={nf.get('SectionAlignment','NA')}")
    tokens.append(f"FileAlignment={nf.get('FileAlignment','NA')}")
    tokens.append(f"OSVersion:{nf.get('MajorOperatingSystemVersion','NA')}.{nf.get('MinorOperatingSystemVersion','NA')}")
    tokens.append(f"ImageVersion:{nf.get('MajorImageVersion','NA')}.{nf.get('MinorImageVersion','NA')}")
    tokens.append(f"SubsystemVersion:{nf.get('MajorSubsystemVersion','NA')}.{nf.get('MinorSubsystemVersion','NA')}")
    tokens.append(f"SizeOfImage={nf.get('SizeOfImage','NA')}")
    tokens.append(f"SizeOfHeaders={nf.get('SizeOfHeaders','NA')}")
    tokens.append(f"CheckSum={nf.get('CheckSum','NA')}")
    tokens.append(f"Subsystem={nf.get('Subsystem','NA')}")
    tokens.append(f"DllCharacteristics={nf.get('DllCharacteristics','NA')}")
    tokens.append(f"SizeOfStackReserve={nf.get('SizeOfStackReserve','NA')}")
    tokens.append(f"SizeOfStackCommit={nf.get('SizeOfStackCommit','NA')}")
    tokens.append(f"SizeOfHeapReserve={nf.get('SizeOfHeapReserve','NA')}")
    tokens.append(f"SizeOfHeapCommit={nf.get('SizeOfHeapCommit','NA')}")
    tokens.append(f"LoaderFlags={nf.get('LoaderFlags','NA')}")
    tokens.append(f"NumberOfRvaAndSizes={nf.get('NumberOfRvaAndSizes','NA')}")
    
    # Sections (list each section)
    sections = nf.get("sections", [])
    tokens.append(f"SECTIONS:count={len(sections)}")
    for sec in sections:
        tokens.append(f"SECTION:{sec.get('name','NA')},virtSize={sec.get('virtual_size','NA')},rawSize={sec.get('size_of_raw_data','NA')},entropy={sec.get('entropy','NA')}")
    
    # Imports and Exports
    imports = nf.get("imports", [])
    tokens.append(f"IMPORTS:count={len(imports)}")
    exports = nf.get("exports", [])
    tokens.append(f"EXPORTS:count={len(exports)}")
    
    # Resources
    resources = nf.get("resources", [])
    tokens.append(f"RESOURCES:count={len(resources)}")
    
    # Debug
    debug = nf.get("debug", [])
    tokens.append(f"DEBUG:count={len(debug)}")
    
    # Certificates
    cert = nf.get("certificates", {})
    if cert:
        tokens.append(f"CERTIFICATES:present,size={cert.get('size','NA')}")
    else:
        tokens.append("CERTIFICATES:absent")
    
    # DOS Stub
    dos_stub = nf.get("dos_stub", {})
    if dos_stub.get("exists"):
        tokens.append(f"DOSSTUB:exists,size={dos_stub.get('size','NA')},entropy={dos_stub.get('entropy','NA')}")
    else:
        tokens.append("DOSSTUB:absent")
    
    # TLS Callbacks
    tls = nf.get("tls_callbacks", {})
    callbacks = tls.get("callbacks", [])
    if callbacks:
        tokens.append("TLS:callbacks=[" + ",".join(hex(cb) for cb in callbacks) + "]")
    else:
        tokens.append("TLS:absent")
    
    # Delay Imports
    delay_imports = nf.get("delay_imports", [])
    tokens.append(f"DELAYIMPORTS:count={len(delay_imports)}")
    
    # Load Config
    load_config = nf.get("load_config", {})
    if load_config:
        tokens.append(f"LOADCONFIG:size={load_config.get('size','NA')},timestamp={load_config.get('timestamp','NA')}")
    else:
        tokens.append("LOADCONFIG:absent")
    
    # Bound Imports
    bound_imports = nf.get("bound_imports", [])
    tokens.append(f"BOUNDIMPORTS:count={len(bound_imports)}")
    
    # Section Characteristics (detailed)
    section_chars = nf.get("section_characteristics", {})
    tokens.append(f"SECTIONCHAR:count={len(section_chars)}")
    for sec_name, details in section_chars.items():
        tokens.append(f"SECTIONCHAR:{sec_name},entropy={details.get('entropy','NA')},flags={details.get('flags','NA')}")
    
    # Extended Headers
    ext_headers = nf.get("extended_headers", {})
    if ext_headers:
        tokens.append("EXTHEADER:present")
    else:
        tokens.append("EXTHEADER:absent")
    
    # Rich Header
    rich_header = nf.get("rich_header", {})
    if rich_header and rich_header.get("values"):
        tokens.append(f"RICHHEADER:present,count={len(rich_header.get('values'))}")
    else:
        tokens.append("RICHHEADER:absent")
    
    # Overlay
    overlay = nf.get("overlay", {})
    if overlay.get("exists"):
        tokens.append(f"OVERLAY:exists,offset={overlay.get('offset','NA')},size={overlay.get('size','NA')},entropy={overlay.get('entropy','NA')}")
    else:
        tokens.append("OVERLAY:absent")
    
    return " ".join(tokens)

def scan_file(file_path):
    """Scans the provided file using both dynamic and detailed static analysis, then applies signatures."""
    print(f"Scanning file: {file_path}")
    report_tokens = []
    
    # Dynamic analysis: always output the MEMDUMP token.
    if file_path.lower().endswith(".exe"):
        report_tokens.append(dynamic_scan(file_path))
    else:
        report_tokens.append("MEMDUMP:0")
    
    # Detailed static analysis using all features.
    report_tokens.append(detailed_static_scan(file_path))
    
    scan_report = " ".join(report_tokens)
    print("Scan Report:", scan_report)
    
    # Load human-defined signatures and match using regex.
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
    parser = argparse.ArgumentParser(description="Comprehensive Scanner for Hydra Dragon Antivirus Engine using all features")
    parser.add_argument("file", help="Path to the file to scan")
    args = parser.parse_args()
    
    if not os.path.isfile(args.file):
        print("Error: File does not exist.", file=sys.stderr)
        return
    
    scan_file(args.file)

if __name__ == "__main__":
    main()
