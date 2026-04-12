"""
nuitka_source_reconstructor.py  v4

Major improvements over v3:
- Fully recovers function/method internal constants
- Populates the function bodies with the exact constants (strings, ints, tuples, bounds)
  used by that specific function. Since the control flow is native C, this is the
  maximum amount of logic recovery possible purely from the blob.
- Maps internal dicts and tuples directly into the method's local scope.
"""
import nuitka_deobfuscate
from pathlib import Path
from collections import OrderedDict
import re

# ─────────────────────── helpers ───────────────────────

def b2s(val):
    if isinstance(val, str): return val
    try: return val.decode('utf-8')
    except: return val.decode('latin-1', errors='replace')

def is_b64_image(val):
    s = b2s(val) if isinstance(val, (bytes, bytearray)) else str(val)
    return 'iVBORw0KGgo' in s or 'JFIF' in s

def is_annotation_dict(d):
    """Check if a dict is a Nuitka function annotation dict."""
    if not d or len(d) > 15: return False
    for k in d.keys():
        key = b2s(k) if isinstance(k, (bytes, bytearray)) else str(k)
        if not key.isidentifier() and key != 'return':
            return False
    return True

def parse_annotation_dict(d):
    """Parse annotation dict → {param: type_str}."""
    ann = {}
    for k, v in d.items():
        key = b2s(k) if isinstance(k, (bytes, bytearray)) else str(k)
        if v is None: ann[key] = 'Any'
        elif v is True: ann[key] = 'bool'
        elif v is False: ann[key] = 'bool'
        elif isinstance(v, int): ann[key] = 'int'
        elif isinstance(v, float): ann[key] = 'float'
        elif isinstance(v, str): ann[key] = v if v[0:1].isupper() else 'str'
        elif isinstance(v, (bytes, bytearray)):
            s = b2s(v)
            ann[key] = s if s[0:1].isupper() else 'str'
        else: ann[key] = type(v).__name__
    return ann

def parse_packed_full(raw):
    """Parse packed bytes → (method_refs[], arg_names[], {arg: type}, count)"""
    if isinstance(raw, str):
        raw = raw.encode('utf-8', errors='replace')
    
    segments = raw.split(b'\x00')
    method_refs = []
    args = []
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
        elif tag == 'u':
            if '.' in name and name[0:1].isupper():
                method_refs.append(name)
        elif tag == 'O':
            if args:
                types[args[-1]] = name
        elif tag == 'D' or tag == 'T':
            try: count = int(name)
            except: pass
        elif tag == 'p':
            if name and '.' in name and name.split('.')[0][0:1].isupper():
                method_refs.append(name)
    
    return method_refs, args, types, count

def format_signature(name, args, types=None, ann=None, defaults=None):
    if types is None: types = {}
    if ann is None: ann = {}
    if defaults is None: defaults = {}
    all_t = {**types, **ann}
    
    parts = []
    for a in args:
        if a == 'return': continue
        base = a
        if a in all_t:
            base = f'{a}: {all_t[a]}'
        if a in defaults:
            base += f' = {defaults[a]}'
        parts.append(base)
    
    sig = ', '.join(parts)
    ret = all_t.get('return')
    if ret:
        return f'def {name}({sig}) -> {ret}:'
    return f'def {name}({sig}):'

# ─────────────────────── reconstructor ───────────────────────

def reconstruct_module(section_name, items):
    n = len(items)
    
    images = OrderedDict()
    vk_constants = OrderedDict()
    module_consts = OrderedDict()
    classes = OrderedDict()
    string_consts = []
    api_urls = []
    
    current_class = None
    last_name = None
    last_method_cls = None
    last_method_name = None
    
    def item_type(item):
        if item is None: return 'none'
        if isinstance(item, bool): return 'bool'
        if isinstance(item, int): return 'int'
        if isinstance(item, float): return 'float'
        if isinstance(item, str): return 'str'
        if isinstance(item, (bytes, bytearray)):
            if b'\x00' in item and len(item) > 4: return 'packed'
            return 'bytes'
        if isinstance(item, tuple): return 'tuple'
        if isinstance(item, list): return 'list'
        if isinstance(item, dict): return 'dict'
        if isinstance(item, (set, frozenset)): return 'set'
        return 'other'
    
    types = [item_type(x) for x in items]
    
    def ensure_class(name):
        if name not in classes:
            classes[name] = {'methods': OrderedDict(), 'attrs': set(), 'slots': None}
    
    def add_method(cls, method, args=None, ann=None, types_=None):
        ensure_class(cls)
        if method not in classes[cls]['methods']:
            classes[cls]['methods'][method] = {
                'args': args or ['self'], 'types': types_ or {},
                'annotations': ann or {}, 'defaults': {},
                'locals': [], 'internal_constants': []
            }
        elif args and args != ['self']:
            m = classes[cls]['methods'][method]
            if m['args'] == ['self']:
                m['args'] = args
            if types_: m['types'].update(types_)
            if ann: m['annotations'].update(ann)
    
    # ── PASS 1: Identify all method boundaries and module constants ──
    i = 0
    while i < n:
        t = types[i]
        v = items[i]
        
        if t == 'none':
            i += 1; continue
        
        # Base64 image pairs
        if t == 'bytes':
            name = b2s(v)
            if name.endswith('_B64') and i + 1 < n and types[i+1] in ('str', 'bytes'):
                if is_b64_image(items[i+1]):
                    images[name] = len(b2s(items[i+1])) if isinstance(items[i+1], (bytes, bytearray)) else len(items[i+1])
                    i += 2; continue
        
        # VK_ constants
        if t == 'bytes':
            name = b2s(v)
            if name.startswith('VK_'):
                vk_val = None
                if i + 1 < n and types[i+1] == 'int':
                    vk_val = items[i+1][1] if isinstance(items[i+1], tuple) else items[i+1]
                elif i > 0 and types[i-1] == 'int':
                    vk_val = items[i-1]
                vk_constants[name] = vk_val
                i += 1; continue
        
        # Method ref: "ClassName.method_name"
        is_method_ref = False
        if t in ('str', 'bytes'):
            name = b2s(v) if t == 'bytes' else v
            if '.' in name and not name.startswith('.') and not name.startswith('\\'):
                parts = name.split('.', 1)
                cls, method = parts[0], parts[1]
                if cls and (cls[0].isupper() or cls[0] == '_') and method.isidentifier():
                    add_method(cls, method)
                    current_class = cls
                    last_method_cls = cls
                    last_method_name = method
                    is_method_ref = True
                    
                    # Look ahead for ANNOTATION DICT
                    if i + 1 < n and types[i+1] == 'dict':
                        d = items[i+1]
                        if is_annotation_dict(d):
                            ann = parse_annotation_dict(d)
                            classes[cls]['methods'][method]['annotations'] = ann
                            arg_names = [k for k in ann.keys() if k != 'return']
                            if arg_names:
                                add_method(cls, method, args=['self'] + arg_names, ann=ann)
        
        # Packed bytes
        if t == 'packed':
            method_refs, args, ptypes, count = parse_packed_full(v)
            for ref in method_refs:
                parts = ref.split('.', 1)
                if len(parts) == 2:
                    cls, method = parts
                    if cls[0:1].isupper() or cls[0:1] == '_':
                        add_method(cls, method)
                        current_class = cls
                        last_method_cls = cls
                        last_method_name = method
            
            if args and method_refs:
                last_ref = method_refs[-1]
                parts = last_ref.split('.', 1)
                if len(parts) == 2:
                    cls, method = parts
                    if 'self' not in args: args = ['self'] + args
                    add_method(cls, method, args=args, types_=ptypes)
            elif args and last_method_cls and last_method_name:
                if 'self' not in args: args = ['self'] + args
                add_method(last_method_cls, last_method_name, args=args, types_=ptypes)
            i += 1; continue
        
        # Body Constants Mapping
        # If we are INSIDE a method (we saw a method ref recently, and haven't hit a new one)
        # Any items like dicts, tuples, non-VK strings, ints, etc. are Internal Constants!
        if last_method_cls and last_method_name:
            m = classes[last_method_cls]['methods'][last_method_name]
            
            if t == 'dict':
                if is_annotation_dict(v):
                    pass # Already handled
                else:
                    decoded = {}
                    for k, val in list(v.items())[:20]:
                        dk = b2s(k) if isinstance(k, (bytes, bytearray)) else repr(k)
                        dv = repr(val)[:100] if not isinstance(val, (bytes, bytearray)) else b2s(val)[:100]
                        decoded[dk] = dv
                    m['internal_constants'].append(('dict', decoded))
            
            elif t == 'list':
                decoded = [b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in v[:40]]
                m['internal_constants'].append(('list', decoded))
                
            elif t == 'tuple':
                decoded = tuple(b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in v)
                if last_name == '__slots__' and current_class:
                    classes[current_class]['slots'] = decoded
                elif all(isinstance(x, str) for x in decoded) and len(decoded) >= 2:
                    m['locals'].append(decoded)
                else:
                    m['internal_constants'].append(('tuple', decoded))
                    
            elif t in ('int', 'float', 'bool'):
                m['internal_constants'].append(('literal', v))
                
            elif t == 'str':
                if 'http' in v.lower() or '/functions/' in v:
                    api_urls.append(v)
                if len(v) > 2 and not is_method_ref:
                    m['internal_constants'].append(('str', v[:100]))
                    
            elif t == 'bytes':
                name = b2s(v)
                if name.startswith('_') and current_class and len(name) > 2 and not name.startswith('__'):
                    classes[current_class]['attrs'].add(name)
                elif 'http' in name.lower() or '/functions/' in name:
                    api_urls.append(name)
                elif len(name) > 2 and not name.startswith('VK_') and not is_method_ref:
                    m['internal_constants'].append(('str', name[:100]))
        
        # Track last name
        if t in ('str', 'bytes'):
            last_name = b2s(v) if t == 'bytes' else v
        else:
            last_name = None
            
        i += 1
    
    # ═══ PASS 2: Generate source ═══
    out = []
    out.append(f'"""')
    out.append(f'Reconstructed source: {section_name}')
    out.append(f'Constants: {n} | Classes: {len(classes)} | Images: {len(images)}')
    out.append(f'"""')
    out.append('')
    
    # Imports
    out.append('# ═══ IMPORTS ═══')
    all_text = str(list(classes.keys())) + str(items[:300])
    imp_map = [
        (['CTk', 'CTkButton'], 'import customtkinter as ctk'),
        (['CTkTextbox'], 'from customtkinter import CTkTextbox, CTkTabview, CTkScrollableFrame'),
        (['MSS', 'MSSBase'], 'from mss import mss'),
        (['keyboard', 'Listener'], 'from pynput import keyboard, mouse'),
        (['Image', 'ImageTk'], 'from PIL import Image, ImageTk'),
        (['ctypes', 'MOUSEINPUT'], 'import ctypes\nfrom ctypes import wintypes, c_long, c_ulong, POINTER, Structure'),
        (['threading'], 'import threading'), (['json'], 'import json'),
        (['time'], 'import time'), (['os'], 'import os'), (['sys'], 'import sys'),
        (['base64'], 'import base64'), (['numpy', 'np'], 'import numpy as np'),
        (['requests', 'urllib'], 'import urllib.request'),
    ]
    seen_imp = set()
    for triggers, imp in imp_map:
        for t in triggers:
            if t in all_text and imp not in seen_imp:
                out.append(imp); seen_imp.add(imp); break
    if images and 'import base64' not in seen_imp:
        out.append('import base64\nfrom io import BytesIO')
    out.append('')
    
    # VK & APIs
    out.append('# ═══ CONSTANTS ═══')
    if api_urls:
        out.append('# ── API Endpoints & URLs ──')
        for url in sorted(set(api_urls)):
            out.append(f'API_URL_{abs(hash(url)) % 1000} = {repr(url)}')
        out.append('')
        
    if vk_constants:
        out.append('# ── Virtual Key Codes ──')
        for name, val in vk_constants.items():
            if val is not None:
                out.append(f'{name} = 0x{val:02X}')
        out.append('')
    
    # Classes
    out.append('# ═══ CLASSES & FUNCTIONS ═══')
    for cls_name, cls_data in classes.items():
        if len(cls_name) > 60 or ' ' in cls_name or '\x00' in cls_name: continue
        if not cls_name[0:1].isalpha() and cls_name[0:1] != '_': continue
        
        methods = cls_data['methods']
        attrs = cls_data['attrs']
        
        if not methods and not attrs: continue
        
        out.append('')
        out.append(f'class {cls_name}:')
        if cls_data['slots']:
            out.append(f'    __slots__ = {cls_data["slots"]}')
            out.append('')
        
        # Instance attributes
        if attrs:
            out.append('    # Attributes used in this class:')
            for attr in sorted(attrs):
                out.append(f'    # self.{attr}')
            out.append('')
        
        # Methods
        for method_name, mdata in methods.items():
            if not method_name.isidentifier(): continue
            
            sig = format_signature(method_name, mdata['args'], mdata.get('types'), mdata.get('annotations'))
            out.append(f'    {sig}')
            
            # Formulate the Function Body from internal constants!
            internals = mdata.get('internal_constants', [])
            locals_ = mdata.get('locals', [])
            
            body = []
            
            # 1. Local variable hints
            if locals_:
                for local_tuple in locals_[:2]:
                    local_strs = [str(x) for x in local_tuple[:5]]
                    body.append(f'# locals: {", ".join(local_strs)}')
            
            # 2. Internal Constants Map
            if internals:
                dedup = []
                for typ, val in internals:
                    if typ == 'str' and (val.startswith('iVBORw0KG') or len(val) < 3): continue
                    if (typ, val) not in dedup:
                        dedup.append((typ, val))
                
                if dedup:
                    body.append(f'# --- internal function logic constants ---')
                    for i, (typ, val) in enumerate(dedup[:25]): # cap to 25 to avoid bloat
                        if typ == 'literal':
                            body.append(f'_const_{i} = {val}')
                        elif typ == 'str':
                            body.append(f'_str_{i} = {repr(val)}')
                        elif typ == 'tuple':
                            body.append(f'_tuple_{i} = {val}')
                        elif typ == 'dict':
                            body.append(f'_dict_{i} = {val}')
                        elif typ == 'list':
                            body.append(f'_list_{i} = {val}')
            
            if not body:
                out.append(f'        pass\n')
            else:
                for line in body:
                    out.append(f'        {line}')
                out.append(f'        ...\n')
    
    return '\n'.join(out)

# ─────────────────────── main ───────────────────────

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    out_dir = Path('restore_deep_ultra') / 'reconstructed_source_v4'
    out_dir.mkdir(parents=True, exist_ok=True)
    
    total_files = total_classes = total_methods = 0
    
    for section_name, items in sections.items():
        if not items or len(items) < 5: continue
        
        has_structure = False
        for item in items[:200]:
            if isinstance(item, str) and '.' in item: has_structure = True; break
            if isinstance(item, dict): has_structure = True; break
            if isinstance(item, (bytes, bytearray)) and b'\x00' in item and len(item) > 4: has_structure = True; break
        if not has_structure: continue
        
        try:
            source = reconstruct_module(section_name, items)
            safe_name = re.sub(r'[<>:"/\\|?*\x00]', '_', section_name)[:80]
            (out_dir / f'{safe_name}.py').write_text(source, encoding='utf-8')
            total_files += 1
            for line in source.split('\n'):
                s = line.strip()
                if s.startswith('class '): total_classes += 1
                if s.startswith('def '): total_methods += 1
        except Exception as e:
            print(f"  [!] {section_name}: {e}")
    
    print(f"\n[*] v4 Reconstruction complete!")
    print(f"    - {total_files} source files")
    print(f"    - {total_classes} classes")
    print(f"    - {total_methods} methods/functions")
    print(f"    - Output: {out_dir}")

if __name__ == '__main__':
    main()
