import os
import sys
from pathlib import Path
from setuptools import setup, Extension

def update_protection_rules():
    """Detect local Nuitka bytecode path and update all default_rules.txt files."""
    current_dir = Path(__file__).resolve().parent
    bytecode_dir = current_dir / "build" / "bytecode"
    
    if not bytecode_dir.exists():
        bytecode_dir.mkdir(parents=True, exist_ok=True)

    rule_path_str = str(bytecode_dir).lower()
    print(f"[*] Synchronizing protection rules for: {rule_path_str}")

    # Rules are in: .../hydradragon/HydraDragon_Protection_Rules/
    project_root = current_dir.parent.parent.parent.parent
    rules_base = project_root / "HydraDragon_Protection_Rules"
    
    rule_files = [
        rules_base / "PYAS" / "File" / "default_rules.txt",
        rules_base / "Owlyshield" / "DynamicHook" / "default_rules.txt",
        rules_base / "Owlyshield" / "FSFilter" / "default_rules.txt",
        rules_base / "Owlyshield" / "ProcessProtection" / "default_rules.txt"
    ]

    for rule_file in rule_files:
        if not rule_file.exists():
            continue

        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            cleaned_lines = [l for l in lines if "nuitka_deobfuscate\\build\\bytecode" not in l.lower()]

            with open(rule_file, 'w', encoding='utf-8') as f:
                f.writelines(cleaned_lines)
                if cleaned_lines and not cleaned_lines[-1].endswith('\n'):
                    f.write('\n')
                f.write("# --- Dynamic Nuitka Bytecode Protection (.pyc only) ---\n")
                f.write(f"{rule_path_str}\\\n")
            
            print(f"[+] Updated: {rule_file.name}")
        except Exception as e:
            print(f"[ERROR] Failed to update {rule_file}: {e}")

ext = Extension(
    name="nuitka_deobfuscate",
    sources=["nuitka_deobfuscate.c"],
)

setup(
    name="nuitka_deobfuscate",
    version="1.0.0",
    ext_modules=[ext],
)

# Run rule synchronization after successful build call
if "build_ext" in sys.argv or "install" in sys.argv or "--inplace" in sys.argv:
    update_protection_rules()
