#!/usr/bin/env python3
"""
Reconstruct module-like Python source files from a Nuitka integrated source blob.

This reuses the same core module extraction logic already present in
`test_py_source_hook_with_gui.py`:
- replace standalone `u` tokens with newlines
- treat `<name> a__module__` as module boundaries
- decode standalone `a <name>` into `def <name>`
- normalise a-prefixed module markers back to readable names
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def split_source_by_u_delimiter(source: str) -> str:
    source = re.sub(r'(?<![.\w])u(?![.\w])', '\n', source)
    source = re.sub(r'(\.?[\w\d\._]+\s+a__module__)', r'\n\1', source)
    source = re.sub(r'^([ \t]*)\ba\b(\s+)(?=[a-zA-Z_]\w*)', r'\1def\2', source, flags=re.MULTILINE)
    return source


def decode_a_module_names(source: str) -> str:
    source = re.sub(r'\b([\w\d\_]+)_a__module__\b', r'\1_def', source)
    source = re.sub(r'\.?([\w\d\_]+(?:\.[\w\d\_]+)*)\s+a__module__', r'\1_def', source)
    return source


def decode_alias_assignments(source: str) -> str:
    for builtin in ["open", "print", "exec", "eval", "getattr", "setattr"]:
        pat = r'^([ \t]*)([a-zA-Z0-9_]+)\s*=\s*' + re.escape(builtin) + r'\b'
        source = re.sub(pat, r'\1' + builtin + ' = ' + builtin, source, flags=re.MULTILINE)
    return source


def extract_modules(static_src: str):
    static_src = re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', ' ', static_src)
    marker_re = re.compile(r'\b([a-zA-Z0-9_\.]+)[ \t\n]+a__module__\b')
    matches = list(marker_re.finditer(static_src))

    if not matches:
        content = split_source_by_u_delimiter(static_src)
        content = decode_a_module_names(content)
        content = decode_alias_assignments(content)
        return {"__main__": content}

    modules = {}
    for i, m in enumerate(matches):
        name = re.sub(r'[^\w\.]', '_', m.group(1))
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(static_src)
        content = static_src[start:end].strip()
        if not content:
            continue
        content = split_source_by_u_delimiter(content)
        content = decode_a_module_names(content)
        content = decode_alias_assignments(content)
        modules[name] = content
    return modules


def main() -> int:
    ap = argparse.ArgumentParser(description='Reconstruct module files from a source-like Nuitka blob dump')
    ap.add_argument('blob_text', help='Path to full_source_blob.txt')
    ap.add_argument('out_dir', help='Directory to write reconstructed .py files')
    args = ap.parse_args()

    text = Path(args.blob_text).read_text(encoding='utf-8', errors='ignore')
    modules = extract_modules(text)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, content in modules.items():
        safe = re.sub(r'[^\w\.-]', '_', name).strip('._') or '__main__'
        path = out_dir / f'{safe}.py'
        path.write_text(content.rstrip() + '\n', encoding='utf-8')
        print(f'[reconstruct] wrote {path}')

    print(f'[reconstruct] wrote {len(modules)} module file(s) to {out_dir}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
