"""
auto_blob_orchestrator.py

AUTOMATED NUITKA DECOMPILATION ORCHESTRATOR
This handles end-to-end automation of the Nuitka reverse engineering pipeline.
1. Automatically discovers valid `.bin` RCDATA payloads in the directory.
2. Ingests and profiles the binary layout (finding main loop, GUI, hooks).
3. Invokes the OMNI Unified Framework to synthesize Python + C-API layers.
4. Generates a summary log of automated intel recovered.

Author: Emirhan Ucan
"""
import os, sys, glob, json, re
from pathlib import Path

def setup_environment():
    try:
        import nuitka_deobfuscate
        return nuitka_deobfuscate
    except ImportError:
        print("[!] FATAL: 'nuitka_deobfuscate' extension missing or incompatible architecture.")
        sys.exit(1)

def discover_blobs():
    """Finds all potential Nuitka constant blobs in the current directory."""
    blobs = []
    # Identify typical RCDATA dumps or explicitly named bin files
    for ext in ('*.bin', '*.blob', '*.dat'):
        for file in glob.glob(ext):
            path = Path(file)
            if path.stat().st_size > 1024:  # Must be substantial
                blobs.append(path)
    return blobs

def b2s_safe(val):
    if val is None: return "None"
    if isinstance(val, str): return val
    if isinstance(val, (int, float, bool)): return str(val)
    if isinstance(val, (tuple, list, dict, set, frozenset)): return str(val)
    if hasattr(val, 'decode'):
        try: return val.decode('utf-8')
        except: return val.decode('latin-1', errors='replace')
    return repr(val)

def automate_blob_recovery(blob_path, deobfuscator, out_base):
    print(f"[*] Automating recovery for: {blob_path.name} ({blob_path.stat().st_size / 1024 / 1024:.2f} MB)")
    
    data = blob_path.read_bytes()
    print(f"    [*] Extracted payload buffer, passing to Nuitka Native Decoder...")
    
    try:
        sections = deobfuscator.decode_blob(data)
    except Exception as e:
        print(f"    [!] Decoder crashed on {blob_path.name}: {e}")
        return False
        
    print(f"    [*] Decoded {len(sections)} internal sections.")
    
    try:
        from omni_nuitka_framework import OmniDecompiler, generate_omni_source
    except ImportError:
        print("    [!] 'omni_nuitka_framework.py' is missing. Please ensure the Omni Engine is in the same directory.")
        return False

    out_dir = out_base / f"automated_{blob_path.stem}"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    meta_log = {
        "blob_name": blob_path.name,
        "total_sections": len(sections),
        "recovered_modules": 0,
        "api_endpoints_detected": [],
        "ui_elements_detected": []
    }
    
    sc = 0
    for section_name, items in sections.items():
        if not items or len(items) < 5: continue
        
        has_structure = any(
            (isinstance(i, str) and '.' in i) or
            isinstance(i, dict) or
            (isinstance(i, (bytes, bytearray)) and b'\x00' in i and len(i) > 4)
            for i in items[:300]
        )
        if not has_structure: continue
        
        try:
            omp = OmniDecompiler()
            omp.run_pass_1_structural_mapping(items)
            omp.run_pass_2_ast_synthesis()
            
            source = generate_omni_source(omp, section_name)
            
            if 'class ' in source and 'def ' in source:
                safe_name = re.sub(r'[<>:"/\\|?*\x00]', '_', section_name)[:80]
                out_file = out_dir / f'{safe_name}.py'
                out_file.write_text(source, encoding='utf-8')
                sc += 1
                
                # Meta Logging
                for ep in omp.api_endpoints:
                    if ep not in meta_log["api_endpoints_detected"]:
                        meta_log["api_endpoints_detected"].append(ep)
        except Exception as e:
            continue
            
    meta_log["recovered_modules"] = sc
    meta_file = out_dir / "automation_report.json"
    meta_file.write_text(json.dumps(meta_log, indent=4), encoding='utf-8')
    
    print(f"    [+] Successfully recovered {sc} critical modules.")
    print(f"    [+] Output and automation report saved to: {out_dir}")
    return True

def main():
    print("="*60)
    print(" V12 OMNI AUTOMATION ORCHESTRATOR ")
    print("="*60)
    
    deobfuscator = setup_environment()
    blobs = discover_blobs()
    
    if not blobs:
        print("[-] No valid .bin blobs found in current directory to automate.")
        sys.exit(0)
        
    out_root = Path('restore_deep_ultra')
    
    successes = 0
    for blob in blobs:
        if automate_blob_recovery(blob, deobfuscator, out_root):
            successes += 1
            
    print("="*60)
    print(f"[*] AUTOMATION COMPLETE. Processed {successes}/{len(blobs)} blobs.")

if __name__ == '__main__':
    main()
