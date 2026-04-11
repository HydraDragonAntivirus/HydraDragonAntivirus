"""
nuitka_source_reconstructor.py  v2

Advanced Nuitka source reconstructor.
Produces the richest possible Python source from constants blob metadata.

Key improvements over v1:
- Full argument parsing from packed null-separated name structures
- Type annotation extraction from annotation dicts
- Proper VK constant mapping using sequential pairing
- String literal extraction (API URLs, error messages, format strings)
- Default value reconstruction
- Better class boundary detection
- Server config expansion with full skill mappings
"""
import nuitka_deobfuscate
from pathlib import Path
from collections import OrderedDict
import re, textwrap

# ─────────────────────── helpers ───────────────────────

def b2s(val):
    """bytes|str → str, lossy."""
    if isinstance(val, str): return val
    try: return val.decode('utf-8')
    except: return val.decode('latin-1', errors='replace')

def is_b64_image(val):
    s = b2s(val) if isinstance(val, (bytes, bytearray)) else str(val)
    return 'iVBORw0KGgo' in s or 'JFIF' in s

def parse_packed_args(raw):
    """Parse Nuitka null-separated packed names.
    
    Format examples:
      b'aself\\x00abase_ms\\x00aaid\\x00arect'   → args: [self, base_ms, aid, rect]
      b'T\\x07wnaptr\\x00agap_s\\x00anow'         → count=7, args: [gap_s, now]
      b'D\\x02adesired_on\\x00Obool'              → dict(2 entries), arg desired_on: bool
    """
    if isinstance(raw, str):
        raw = raw.encode('utf-8', errors='replace')
    
    segments = raw.split(b'\x00')
    args = []
    kw_args = []
    types = {}
    count = None
    
    for seg in segments:
        if not seg: continue
        text = seg.decode('utf-8', errors='replace')
        if not text: continue
        
        tag = text[0]
        name = text[1:]
        
        if tag == 'a':
            args.append(name)
        elif tag == 'w':
            # w followed by width info: ws=with_star, wn=name, wf=with_flag
            kw_args.append(name)
        elif tag == 'T':
            # Count of following items
            try: count = int(name)
            except: pass
        elif tag == 'D':
            try: count = int(name)
            except: pass
        elif tag == 'O':
            # Type annotation for previous arg
            if args:
                types[args[-1]] = name
        elif tag == 'p':
            # positional-only marker or name
            if name:
                args.append(name)
        elif tag == 'n':
            pass  # None marker
        elif tag == 'u':
            pass  # unicode string reference (method name)
    
    return args, kw_args, types, count

def parse_annotation_dict(d):
    """Parse a Nuitka annotation dict like {b'url': None, b'return': True}."""
    annotations = {}
    for k, v in d.items():
        key = b2s(k) if isinstance(k, (bytes, bytearray)) else str(k)
        if v is None:
            annotations[key] = 'Any'
        elif v is True:
            annotations[key] = 'bool'
        elif v is False:
            annotations[key] = 'bool'
        elif isinstance(v, int):
            annotations[key] = 'int'
        elif isinstance(v, float):
            annotations[key] = 'float'
        elif isinstance(v, str):
            annotations[key] = v if v[0].isupper() else 'str'
        elif isinstance(v, (bytes, bytearray)):
            val = b2s(v)
            annotations[key] = val if val[0:1].isupper() else 'str'
        else:
            annotations[key] = repr(type(v).__name__)
    return annotations

def format_method_signature(name, args, types=None, defaults=None, annotations=None):
    """Build a properly typed function signature string."""
    if types is None: types = {}
    if defaults is None: defaults = {}
    if annotations is None: annotations = {}
    
    # Merge types
    all_types = {**types, **annotations}
    
    parts = []
    for a in args:
        if a in all_types and a != 'return':
            t = all_types[a]
            if a in defaults:
                parts.append(f'{a}: {t} = {defaults[a]}')
            else:
                parts.append(f'{a}: {t}')
        elif a in defaults:
            parts.append(f'{a}={defaults[a]}')
        else:
            parts.append(a)
    
    sig = ', '.join(parts)
    ret = all_types.get('return')
    if ret:
        return f'def {name}({sig}) -> {ret}:'
    return f'def {name}({sig}):'


# ─────────────────────── main reconstructor ───────────────────────

def reconstruct_module(section_name, items):
    """Reconstruct a complete Python module from its Nuitka constants."""
    
    # ── Phase 1: First pass — classify everything ──
    images = OrderedDict()
    vk_constants = OrderedDict()
    server_list = []
    server_configs = {}
    module_constants = OrderedDict()
    classes = OrderedDict()  # cls_name → {methods: [], attrs: set(), slots: None}
    standalone_funcs = []
    string_literals = []
    api_urls = []
    all_tuples = []
    
    current_class = None
    last_str_name = None      # last bytes/str that looked like a name
    last_method_full = None   # last "Class.method" reference
    pending_args = None       # args waiting to be assigned
    
    # Build an index of items with their types for lookahead
    typed_items = []
    for item in items:
        if item is None:
            typed_items.append(('none', None))
        elif isinstance(item, bool):
            typed_items.append(('bool', item))
        elif isinstance(item, int):
            typed_items.append(('int', item))
        elif isinstance(item, float):
            typed_items.append(('float', item))
        elif isinstance(item, str):
            typed_items.append(('str', item))
        elif isinstance(item, (bytes, bytearray)):
            txt = b2s(item)
            if '\x00' in txt and len(item) > 4:
                typed_items.append(('packed', item))
            else:
                typed_items.append(('bytes', item))
        elif isinstance(item, tuple):
            typed_items.append(('tuple', item))
        elif isinstance(item, list):
            typed_items.append(('list', item))
        elif isinstance(item, dict):
            typed_items.append(('dict', item))
        elif isinstance(item, (set, frozenset)):
            typed_items.append(('set', item))
        else:
            typed_items.append(('other', item))
    
    n = len(typed_items)
    i = 0
    
    while i < n:
        typ, val = typed_items[i]
        
        # ── Skip leading None padding ──
        if typ == 'none':
            i += 1; continue
        
        # ── Base64 image pairs: name_B64, image_data ──
        if typ == 'bytes':
            name = b2s(val)
            if name.endswith('_B64') and i + 1 < n:
                ntyp, nval = typed_items[i + 1]
                if ntyp in ('str', 'bytes') and is_b64_image(nval):
                    data_len = len(b2s(nval)) if isinstance(nval, (bytes, bytearray)) else len(nval)
                    images[name] = data_len
                    i += 2; continue
        
        # ── Server names (known pattern: short uppercase byte names in sequence) ──
        # Already handled by GORSELLER_SERVERS and server list detection below
        
        # ── VK_ constants: name followed by numeric ──
        if typ == 'bytes':
            name = b2s(val)
            if name.startswith('VK_'):
                # The VK value is the PREVIOUS int if pattern is int,name
                # OR the NEXT int if pattern is name,int
                vk_val = None
                if i + 1 < n and typed_items[i + 1][0] == 'int':
                    vk_val = typed_items[i + 1][1]
                elif i > 0 and typed_items[i - 1][0] == 'int':
                    vk_val = typed_items[i - 1][1]
                vk_constants[name] = vk_val
                i += 1; continue
        
        # ── Class.method references (the core structure) ──
        if typ in ('str', 'bytes'):
            name = b2s(val) if typ == 'bytes' else val
            
            if '.' in name and not name.startswith('.') and not name.startswith('\\'):
                parts = name.split('.', 1)
                cls_name = parts[0]
                method_name = parts[1]
                
                # Validate: class names start with uppercase or _
                if cls_name and (cls_name[0].isupper() or cls_name[0] == '_'):
                    if cls_name not in classes:
                        classes[cls_name] = {'methods': OrderedDict(), 'attrs': set(), 'slots': None}
                    
                    current_class = cls_name
                    last_method_full = name
                    
                    if method_name not in classes[cls_name]['methods']:
                        classes[cls_name]['methods'][method_name] = {
                            'args': ['self'], 'types': {}, 'defaults': {},
                            'annotations': {}, 'strings': [], 'index': i
                        }
                    
                    # Look ahead for annotation dict and packed args
                    j = i + 1
                    while j < min(i + 15, n):
                        jtyp, jval = typed_items[j]
                        
                        if jtyp == 'dict':
                            # Annotation dict
                            ann = parse_annotation_dict(jval)
                            if ann and current_class and method_name in classes[current_class]['methods']:
                                classes[current_class]['methods'][method_name]['annotations'] = ann
                            j += 1; continue
                        
                        if jtyp == 'packed':
                            args, kw, types, count = parse_packed_args(jval)
                            if args and current_class and method_name in classes[current_class]['methods']:
                                m = classes[current_class]['methods'][method_name]
                                if 'self' not in args:
                                    args = ['self'] + args
                                m['args'] = args
                                m['types'] = types
                            j += 1; continue
                        
                        # Stop lookahead on next method ref or class boundary
                        if jtyp in ('str', 'bytes'):
                            jname = b2s(jval) if jtyp == 'bytes' else jval
                            if '.' in jname and jname[0:1].isupper():
                                break
                        
                        j += 1
                    
                    i += 1; continue
        
        # ── Packed bytes that are NOT after a method ref → standalone function args ──
        if typ == 'packed':
            args, kw, types, count = parse_packed_args(val)
            
            # Check if any embedded method names (uClassName.method)
            txt = b2s(val)
            method_refs = re.findall(r'u([A-Z_]\w+\.\w+)', txt)
            
            for ref in method_refs:
                parts = ref.split('.', 1)
                cls_name, method_name = parts
                if cls_name not in classes:
                    classes[cls_name] = {'methods': OrderedDict(), 'attrs': set(), 'slots': None}
                if method_name not in classes[cls_name]['methods']:
                    classes[cls_name]['methods'][method_name] = {
                        'args': ['self'], 'types': {}, 'defaults': {},
                        'annotations': {}, 'strings': [], 'index': i
                    }
                current_class = cls_name
            
            # Associate args with most recent method
            if args and current_class:
                last_methods = list(classes[current_class]['methods'].keys())
                if last_methods:
                    last_m = last_methods[-1]
                    m = classes[current_class]['methods'][last_m]
                    if m['args'] == ['self']:
                        if 'self' not in args:
                            args = ['self'] + args
                        m['args'] = args
                        m['types'] = types
            
            i += 1; continue
        
        # ── Tuple of bytes = __slots__ or DLL names ──
        if typ == 'tuple':
            decoded = tuple(b2s(x) if isinstance(x, (bytes, bytearray)) else x for x in val)
            all_tuples.append((i, decoded))
            
            if last_str_name == '__slots__' and current_class:
                classes[current_class]['slots'] = decoded
            elif all(isinstance(x, str) for x in decoded) and len(decoded) <= 20:
                # Could be arg names for most recent method
                if current_class:
                    last_methods = list(classes[current_class]['methods'].keys())
                    if last_methods:
                        last_m = last_methods[-1]
                        m = classes[current_class]['methods'][last_m]
                        if m['args'] == ['self'] and len(decoded) > 0:
                            m['args'] = ['self'] + list(decoded)
            i += 1; continue
        
        # ── Lists and Dicts at module level ──
        if typ == 'list':
            decoded = [b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in val[:60]]
            if last_str_name:
                module_constants[last_str_name] = ('list', decoded)
            else:
                module_constants[f'_list_{i}'] = ('list', decoded)
            i += 1; continue
        
        if typ == 'dict':
            # Check if it's an annotation dict (keys are param names, vals are types)
            if all(isinstance(k, (bytes, bytearray, str)) for k in val.keys()):
                keys = [b2s(k) if isinstance(k, (bytes, bytearray)) else k for k in val.keys()]
                if any(k in ('return', 'self') for k in keys) or all(k.isidentifier() for k in keys if isinstance(k, str)):
                    # This is an annotation dict - associate with method
                    ann = parse_annotation_dict(val)
                    if current_class:
                        last_methods = list(classes[current_class]['methods'].keys())
                        if last_methods:
                            classes[current_class]['methods'][last_methods[-1]]['annotations'] = ann
                    i += 1; continue
            
            # Server config or module-level dict
            decoded = {}
            for k, v in list(val.items())[:50]:
                dk = b2s(k) if isinstance(k, (bytes, bytearray)) else repr(k)
                dv = repr(v) if not isinstance(v, (bytes, bytearray)) else b2s(v)
                decoded[dk] = dv[:200]
            
            if last_str_name:
                module_constants[last_str_name] = ('dict', decoded)
            else:
                module_constants[f'_dict_{i}'] = ('dict', decoded)
            i += 1; continue
        
        # ── Instance attributes (bytes starting with _) ──
        if typ == 'bytes':
            name = b2s(val)
            if name.startswith('_') and current_class and len(name) > 2:
                if name.startswith('__') and name.endswith('__'):
                    pass  # dunder, skip
                else:
                    classes[current_class]['attrs'].add(name)
            
            # Detect API URLs
            if 'http' in name.lower() or '/api/' in name or '/functions/' in name:
                api_urls.append(name)
            
            # Detect interesting string constants
            if len(name) > 20 and not name.startswith('VK_'):
                string_literals.append((i, name))
            
            last_str_name = name
            i += 1; continue
        
        # ── String literals ──
        if typ == 'str':
            if 'http' in val.lower() or '/api/' in val or '/functions/' in val:
                api_urls.append(val)
            if len(val) > 5 and not val.startswith('\n') and '.' in val and val[0:1].isupper():
                pass  # method ref already handled
            elif len(val) > 10:
                string_literals.append((i, val[:200]))
            last_str_name = val
            i += 1; continue
        
        # ── Numerics, bools → track for constant reconstruction ──
        if typ in ('int', 'float', 'bool'):
            last_str_name = None
            i += 1; continue
        
        i += 1
    
    # ── Phase 2: Generate source ──
    
    out = []
    out.append(f'"""')
    out.append(f'Reconstructed source: {section_name}')
    out.append(f'Constants analyzed: {len(items)}')
    out.append(f'Classes: {len(classes)}')
    out.append(f'Images: {len(images)}, VK constants: {len(vk_constants)}')
    out.append(f'"""')
    out.append('')
    
    # ── Imports ──
    out.append('# ═══════════════════ IMPORTS ═══════════════════')
    
    all_cls = set(classes.keys())
    all_text = str(items[:300])
    
    import_rules = [
        (['CTk', 'CTkButton', 'CTkEntry', 'CTkFrame'], 'import customtkinter as ctk'),
        (['CTkTextbox', 'CTkTabview'], 'from customtkinter import CTkTextbox, CTkTabview, CTkScrollableFrame'),
        (['MSS', 'MSSBase'], 'from mss import mss'),
        (['keyboard', 'Listener'], 'from pynput import keyboard, mouse'),
        (['Image', 'ImageTk'], 'from PIL import Image, ImageTk'),
        (['ctypes', 'c_long', 'windll'], 'import ctypes\nfrom ctypes import wintypes, c_long, c_ulong, c_ushort, POINTER, Structure'),
        (['threading'], 'import threading'),
        (['json'], 'import json'),
        (['time'], 'import time'),
        (['os'], 'import os'),
        (['sys'], 'import sys'),
        (['tkinter'], 'import tkinter as tk'),
        (['subprocess'], 'import subprocess'),
        (['requests', 'urllib'], 'import urllib.request'),
        (['nacl'], 'import nacl.utils'),
        (['base64'], 'import base64'),
        (['struct'], 'import struct'),
        (['pystray', 'Icon'], 'import pystray'),
        (['win32api'], 'import win32api, win32con'),
        (['numpy', 'np'], 'import numpy as np'),
    ]
    
    emitted_imports = set()
    for triggers, imp_line in import_rules:
        for t in triggers:
            if t in all_cls or t in all_text:
                if imp_line not in emitted_imports:
                    out.append(imp_line)
                    emitted_imports.add(imp_line)
                break
    
    if images:
        if 'import base64' not in emitted_imports:
            out.append('import base64')
        if 'from io import BytesIO' not in emitted_imports:
            out.append('from io import BytesIO')
    
    out.append('')
    
    # ── Module-level constants ──
    out.append('# ═══════════════════ CONSTANTS ═══════════════════')
    out.append('')
    
    if images:
        out.append('# ── Base64 Images ──')
        for name, size in images.items():
            out.append(f'{name} = "..."  # {size} chars of base64-encoded PNG')
        out.append('')
    
    if vk_constants:
        out.append('# ── Virtual Key Codes ──')
        out.append('VK_MAP = {')
        for name, val in vk_constants.items():
            if val is not None:
                out.append(f'    {repr(name)}: 0x{val:02X},  # {val}')
            else:
                out.append(f'    {repr(name)}: ...,')
        out.append('}')
        out.append('')
        # Also emit individual constants
        for name, val in vk_constants.items():
            if val is not None:
                out.append(f'{name} = 0x{val:02X}')
        out.append('')
    
    for cname, (ctype, cval) in module_constants.items():
        if cname.startswith('GORSELLER') or 'SERVERS' in cname.upper():
            out.append(f'# ── Server Configuration ──')
        
        if ctype == 'list':
            out.append(f'{cname} = [')
            for item in cval[:60]:
                out.append(f'    {repr(item)},')
            if len(cval) > 60:
                out.append(f'    # ... {len(cval) - 60} more items')
            out.append(']')
        elif ctype == 'dict':
            out.append(f'{cname} = {{')
            for k, v in cval.items():
                out.append(f'    {repr(k)}: {v},')
            out.append('}')
        out.append('')
    
    if api_urls:
        out.append('# ── API Endpoints ──')
        for url in sorted(set(api_urls)):
            out.append(f'# {url}')
        out.append('')
    
    if string_literals:
        out.append('# ── Notable String Constants ──')
        seen = set()
        for idx, s in string_literals[:100]:
            if s not in seen and len(s) > 10:
                out.append(f'# [{idx}] {repr(s[:120])}')
                seen.add(s)
        out.append('')
    
    # ── Classes ──
    out.append('# ═══════════════════ CLASSES ═══════════════════')
    
    for cls_name, cls_data in classes.items():
        methods = cls_data['methods']
        attrs = cls_data['attrs']
        slots = cls_data['slots']
        
        if not methods and not attrs:
            continue
        
        # Skip garbage class names
        if len(cls_name) > 60 or ' ' in cls_name or '\x00' in cls_name:
            continue
        if not cls_name[0].isalpha() and cls_name[0] != '_':
            continue
        
        out.append('')
        out.append(f'class {cls_name}:')
        
        if slots:
            out.append(f'    __slots__ = {slots}')
            out.append('')
        
        # Instance attributes
        sorted_attrs = sorted(attrs)
        if sorted_attrs:
            out.append('    # ── Instance Attributes ──')
            for attr in sorted_attrs:
                out.append(f'    # self.{attr}: ...')
            out.append('')
        
        # Methods
        for method_name, mdata in methods.items():
            args = mdata['args']
            types = mdata['types']
            defaults = mdata['defaults']
            annotations = mdata['annotations']
            
            sig = format_method_signature(method_name, args, types, defaults, annotations)
            out.append(f'    {sig}')
            
            # Add docstring hint from annotations
            if annotations and len(annotations) > 1:
                out.append(f'        """')
                for param, ann_type in annotations.items():
                    if param != 'return':
                        out.append(f'        :param {param}: {ann_type}')
                    else:
                        out.append(f'        :returns: {ann_type}')
                out.append(f'        """')
            
            out.append(f'        ...')
            out.append('')
    
    # ── Standalone functions ──
    for func in standalone_funcs:
        out.append(f'')
        name = func.get('name', '_unknown')
        args = func.get('args', [])
        out.append(f'def {name}({", ".join(args)}):')
        out.append(f'    ...')
    
    return '\n'.join(out)


# ─────────────────────── main ───────────────────────

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    out_dir = Path('restore_deep_ultra') / 'reconstructed_source_v2'
    out_dir.mkdir(parents=True, exist_ok=True)
    
    total_files = 0
    total_classes = 0
    total_methods = 0
    
    for section_name, items in sections.items():
        if not items or len(items) < 5:
            continue
        
        # Require at least some structured content (strings, dicts, method refs)
        has_structure = False
        for item in items[:200]:
            if isinstance(item, str) and '.' in item:
                has_structure = True; break
            if isinstance(item, dict):
                has_structure = True; break
            if isinstance(item, (bytes, bytearray)) and b'\x00' in item and len(item) > 4:
                has_structure = True; break
        
        if not has_structure:
            continue
        
        try:
            source = reconstruct_module(section_name, items)
            
            safe_name = re.sub(r'[<>:"/\\|?*\x00]', '_', section_name)[:80]
            filepath = out_dir / f'{safe_name}.py'
            filepath.write_text(source, encoding='utf-8')
            total_files += 1
            
            # Count stats
            for line in source.split('\n'):
                if line.strip().startswith('class '):
                    total_classes += 1
                if line.strip().startswith('def '):
                    total_methods += 1
            
        except Exception as e:
            print(f"  [!] Error in {section_name}: {e}")
    
    print(f"\n[*] Reconstruction complete!")
    print(f"    - {total_files} source files")
    print(f"    - {total_classes} classes")
    print(f"    - {total_methods} methods/functions")
    print(f"    - Output: {out_dir}")

if __name__ == '__main__':
    main()
