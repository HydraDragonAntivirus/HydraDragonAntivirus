"""Analyze what hints the OMNI framework collects but doesn't use."""
import sys
sys.path.insert(0, '.')
import nuitka_deobfuscate
from omni_nuitka_framework import OmniDecompiler, generate_omni_source
from pathlib import Path

raw = Path('rcdata_10_3.bin').read_bytes()
sections = nuitka_deobfuscate.decode_blob(raw)

# Analyze multiple sections
checked = 0
total_methods = 0
methods_with_hints = 0
hint_types = {'string_hints': 0, 'messages': 0, 'dict_hints': 0, 'tuples': 0, 'literals': 0}

for name, items in sections.items():
    if not items or len(items) < 20:
        continue
    
    omp = OmniDecompiler()
    omp.run_pass_1_structural_mapping(items)
    
    for cls_name, cls in omp.classes.items():
        for mname, func in cls.methods.items():
            total_methods += 1
            has_hints = False
            for htype in hint_types:
                val = getattr(func, htype)
                if val:
                    hint_types[htype] += 1
                    has_hints = True
            if has_hints:
                methods_with_hints += 1
    
    checked += 1

print(f"Sections checked: {checked}")
print(f"Total methods: {total_methods}")
print(f"Methods with ANY hint data: {methods_with_hints} ({100*methods_with_hints/max(1,total_methods):.1f}%)")
print(f"Hint breakdown:")
for htype, count in hint_types.items():
    print(f"  {htype}: {count} methods have this")

# Now show detailed examples of methods with rich hints
print("\n=== SAMPLE METHODS WITH RICH HINTS ===")
sample_count = 0
for name, items in sections.items():
    if not items or len(items) < 20 or sample_count >= 20:
        continue
    
    omp = OmniDecompiler()
    omp.run_pass_1_structural_mapping(items)
    
    for cls_name, cls in omp.classes.items():
        for mname, func in cls.methods.items():
            if sample_count >= 20:
                break
            # Only show methods with multiple hint types
            hint_count = sum(1 for h in ['string_hints', 'messages', 'dict_hints', 'tuples', 'literals'] if getattr(func, h))
            if hint_count >= 2:
                args_str = ', '.join(func.args)
                print(f"\n  {cls_name}.{mname}({args_str}):")
                if func.string_hints:
                    print(f"    string_hints = {func.string_hints[:8]}")
                if func.messages:
                    print(f"    messages = {func.messages[:4]}")
                if func.dict_hints:
                    print(f"    dict_hints = {func.dict_hints[:2]}")
                if func.tuples:
                    print(f"    tuples = {func.tuples[:4]}")
                if func.literals:
                    print(f"    literals = {func.literals[:8]}")
                if func.docstring:
                    print(f"    docstring = {func.docstring[:80]}")
                sample_count += 1
