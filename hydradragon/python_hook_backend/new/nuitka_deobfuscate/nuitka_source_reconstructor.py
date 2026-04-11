"""
nuitka_source_reconstructor.py  v3

Major fixes over v2:
- Annotation dicts correctly map to IMMEDIATELY PRECEDING method ref
- Packed items properly decomposed: method refs (u-prefix) vs args (a-prefix)
- Proper arg names extracted from packed structures with D/T count prefixes
- ScreenSelector, DropdownManager, WideOption classes correctly extracted
- API URLs extracted from embedded frozensets
- Server-specific skill bar configs fully expanded
- Clean SinqleBoYApp: no garbage class bleeding, proper method boundaries
- Instance attrs extracted from tuple items (e.g., __slots__ tuples)
- Local variable tuples mapped to their owning methods
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
    """Parse packed bytes → (method_refs[], arg_names[], {arg: type}, count)
    
    Null-separated segments with prefix tags:
      a = argument name
      u = unicode string (often 'ClassName.method' ref)
      D = dict count prefix
      T = tuple count prefix
      O = type annotation for previous arg
      w = keyword width
      p = positional / misc string
      n = None marker
    """
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
            # method reference like 'SinqleBoYApp._build_ui'
            if '.' in name and name[0:1].isupper():
                method_refs.append(name)
        elif tag == 'O':
            if args:
                types[args[-1]] = name
        elif tag == 'D':
            try: count = int(name)
            except: pass
        elif tag == 'T':
            try: count = int(name)
            except: pass
        elif tag == 'p':
            # Often a partial string from truncation, or a positional arg
            if name and '.' in name and name.split('.')[0][0:1].isupper():
                method_refs.append(name)
        elif tag == 'w':
            pass  # keyword info
        elif tag == 'n':
            pass  # None
    
    return method_refs, args, types, count

def format_signature(name, args, types=None, ann=None, defaults=None):
    """Build def name(args): with types and annotations."""
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
    last_name = None  # last bytes/str name for association
    
    # Pre-classify all items
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
            classes[name] = {'methods': OrderedDict(), 'attrs': set(), 'slots': None, 'locals': {}}
    
    def add_method(cls, method, args=None, ann=None, types_=None):
        ensure_class(cls)
        if method not in classes[cls]['methods']:
            classes[cls]['methods'][method] = {
                'args': args or ['self'], 'types': types_ or {},
                'annotations': ann or {}, 'defaults': {},
                'locals': [], 'strings': []
            }
        elif args and args != ['self']:
            m = classes[cls]['methods'][method]
            if m['args'] == ['self']:
                m['args'] = args
            if types_:
                m['types'].update(types_)
            if ann:
                m['annotations'].update(ann)
    
    # ═══ PASS 1: Sequential scan ═══
    i = 0
    last_method_cls = None
    last_method_name = None
    
    while i < n:
        t = types[i]
        v = items[i]
        
        if t == 'none':
            i += 1; continue
        
        # ── Base64 image pairs ──
        if t == 'bytes':
            name = b2s(v)
            if name.endswith('_B64') and i + 1 < n and types[i+1] in ('str', 'bytes'):
                if is_b64_image(items[i+1]):
                    data_len = len(b2s(items[i+1])) if isinstance(items[i+1], (bytes, bytearray)) else len(items[i+1])
                    images[name] = data_len
                    i += 2; continue
        
        # ── VK_ constants ──
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
        
        # ── Method ref: "ClassName.method_name" ──
        if t in ('str', 'bytes'):
            name = b2s(v) if t == 'bytes' else v
            
            if '.' in name and not name.startswith('.') and not name.startswith('\\'):
                parts = name.split('.', 1)
                cls, method = parts[0], parts[1]
                
                if cls and (cls[0].isupper() or cls[0] == '_') and method.isidentifier():
                    # This IS a method reference
                    add_method(cls, method)
                    current_class = cls
                    last_method_cls = cls
                    last_method_name = method
                    
                    # Look ahead for ANNOTATION DICT (immediately following)
                    if i + 1 < n and types[i+1] == 'dict':
                        d = items[i+1]
                        if is_annotation_dict(d):
                            ann = parse_annotation_dict(d)
                            classes[cls]['methods'][method]['annotations'] = ann
                            # The annotation keys (minus 'return') are the arg names
                            arg_names = [k for k in ann.keys() if k != 'return']
                            if arg_names:
                                add_method(cls, method, args=['self'] + arg_names, ann=ann)
                    
                    i += 1; continue
        
        # ── Packed bytes: extract method refs AND function args ──
        if t == 'packed':
            method_refs, args, ptypes, count = parse_packed_full(v)
            
            # Register discovered method refs
            for ref in method_refs:
                parts = ref.split('.', 1)
                if len(parts) == 2:
                    cls, method = parts
                    if cls[0:1].isupper() or cls[0:1] == '_':
                        add_method(cls, method)
                        current_class = cls
                        last_method_cls = cls
                        last_method_name = method
            
            # If we have args, associate with the LAST method ref in this packed item
            # (or the most recently declared method)
            if args and method_refs:
                last_ref = method_refs[-1]
                parts = last_ref.split('.', 1)
                if len(parts) == 2:
                    cls, method = parts
                    if 'self' not in args:
                        args = ['self'] + args
                    add_method(cls, method, args=args, types_=ptypes)
            elif args and last_method_cls and last_method_name:
                if 'self' not in args:
                    args = ['self'] + args
                add_method(last_method_cls, last_method_name, args=args, types_=ptypes)
            
            i += 1; continue
        
        # ── Annotation dict NOT after a method ref → associate with previous method ──
        if t == 'dict':
            d = v
            if is_annotation_dict(d):
                ann = parse_annotation_dict(d)
                # Check if prev item was a method ref (already handled above)
                if i > 0 and types[i-1] in ('str', 'bytes'):
                    prev_name = b2s(items[i-1]) if types[i-1] == 'bytes' else items[i-1]
                    if '.' in prev_name and prev_name.split('.', 1)[0][0:1].isupper():
                        pass  # Already handled in the method ref lookahead
                    elif last_method_cls and last_method_name:
                        m = classes.get(last_method_cls, {}).get('methods', {}).get(last_method_name)
                        if m and not m.get('annotations'):
                            m['annotations'] = ann
                            arg_names = [k for k in ann.keys() if k != 'return']
                            if arg_names and m['args'] == ['self']:
                                m['args'] = ['self'] + arg_names
                elif last_method_cls and last_method_name:
                    m = classes.get(last_method_cls, {}).get('methods', {}).get(last_method_name)
                    if m and not m.get('annotations'):
                        m['annotations'] = ann
                        arg_names = [k for k in ann.keys() if k != 'return']
                        if arg_names and m['args'] == ['self']:
                            m['args'] = ['self'] + arg_names
                i += 1; continue
            
            # Non-annotation dict → module constant
            decoded = {}
            for k, val in list(d.items())[:50]:
                dk = b2s(k) if isinstance(k, (bytes, bytearray)) else repr(k)
                dv = repr(val)[:200] if not isinstance(val, (bytes, bytearray)) else b2s(val)[:200]
                decoded[dk] = dv
            cname = last_name or f'_config_{i}'
            module_consts[cname] = ('dict', decoded)
            i += 1; continue
        
        # ── List → module constant ──
        if t == 'list':
            decoded = [b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in v[:80]]
            cname = last_name or f'_list_{i}'
            module_consts[cname] = ('list', decoded)
            i += 1; continue
        
        # ── Tuple → local vars or __slots__ ──
        if t == 'tuple':
            decoded = tuple(b2s(x) if isinstance(x, (bytes, bytearray)) else x for x in v)
            if last_name == '__slots__' and current_class:
                classes[current_class]['slots'] = decoded
            elif all(isinstance(x, str) for x in decoded) and 2 <= len(decoded) <= 30:
                if last_method_cls and last_method_name:
                    m = classes.get(last_method_cls, {}).get('methods', {}).get(last_method_name)
                    if m:
                        m['locals'].append(decoded)
            i += 1; continue
        
        # ── Sets/frozensets → extract API URLs ──
        if t == 'set':
            for item in v:
                s = b2s(item) if isinstance(item, (bytes, bytearray)) else str(item)
                if 'http' in s.lower() or '/functions/' in s or 'supabase' in s.lower():
                    api_urls.append(s)
                if '.' in s and s[0:1].isupper() and s.split('.')[0].isidentifier():
                    # Possible class.method ref
                    parts = s.split('.', 1)
                    if len(parts) == 2 and parts[1].isidentifier():
                        add_method(parts[0], parts[1])
            i += 1; continue
        
        # ── Bytes: instance attrs, string constants ──
        if t == 'bytes':
            name = b2s(v)
            if name.startswith('_') and current_class and len(name) > 2:
                if not (name.startswith('__') and name.endswith('__')):
                    classes[current_class]['attrs'].add(name)
            if 'http' in name.lower() or '/functions/' in name:
                api_urls.append(name)
            if len(name) > 10 and not name.startswith('VK_'):
                string_consts.append((i, name))
            last_name = name
            i += 1; continue
        
        if t == 'str':
            if 'http' in v.lower() or '/functions/' in v:
                api_urls.append(v)
            if len(v) > 10:
                string_consts.append((i, v[:200]))
            last_name = v
            i += 1; continue
        
        last_name = None
        i += 1
    
    # ═══ PASS 2: Generate source ═══
    out = []
    out.append(f'"""')
    out.append(f'Reconstructed source: {section_name}')
    out.append(f'Constants: {n} | Classes: {len(classes)} | Images: {len(images)} | VK: {len(vk_constants)}')
    out.append(f'"""')
    out.append('')
    
    # Imports
    out.append('# ═══ IMPORTS ═══')
    all_text = str(list(classes.keys())) + str(items[:300])
    imp_map = [
        (['CTk', 'CTkButton', 'CTkEntry'], 'import customtkinter as ctk'),
        (['CTkTextbox', 'CTkTabview'], 'from customtkinter import CTkTextbox, CTkTabview, CTkScrollableFrame'),
        (['MSS', 'MSSBase'], 'from mss import mss'),
        (['keyboard', 'Listener'], 'from pynput import keyboard, mouse'),
        (['Image', 'ImageTk'], 'from PIL import Image, ImageTk'),
        (['ctypes', 'c_long', 'windll', 'MOUSEINPUT'], 'import ctypes\nfrom ctypes import wintypes, c_long, c_ulong, c_ushort, POINTER, Structure'),
        (['threading'], 'import threading'), (['json'], 'import json'),
        (['time'], 'import time'), (['os'], 'import os'), (['sys'], 'import sys'),
        (['tkinter'], 'import tkinter as tk'), (['subprocess'], 'import subprocess'),
        (['requests', 'urllib'], 'import urllib.request'),
        (['nacl', 'SigningKey', 'VerifyKey'], 'import nacl.signing, nacl.utils'),
        (['base64'], 'import base64'), (['struct'], 'import struct'),
        (['pystray', 'Icon'], 'import pystray'), (['numpy', 'np'], 'import numpy as np'),
    ]
    seen_imp = set()
    for triggers, imp in imp_map:
        for t in triggers:
            if t in all_text:
                if imp not in seen_imp: out.append(imp); seen_imp.add(imp)
                break
    if images and 'import base64' not in seen_imp:
        out.append('import base64\nfrom io import BytesIO')
    out.append('')
    
    # Constants
    out.append('# ═══ CONSTANTS ═══')
    out.append('')
    
    if images:
        out.append('# ── Base64 Images ──')
        for name, sz in images.items():
            out.append(f'{name} = "..."  # {sz} chars base64 PNG')
        out.append('')
    
    if vk_constants:
        out.append('# ── Virtual Key Codes ──')
        for name, val in vk_constants.items():
            if val is not None:
                out.append(f'{name} = 0x{val:02X}  # {val}')
            else:
                out.append(f'{name} = ...  # value not paired')
        out.append('')
    
    for cname, (ctype, cval) in module_consts.items():
        if ctype == 'list':
            out.append(f'{cname} = [')
            for item in cval[:80]:
                out.append(f'    {repr(item)},')
            out.append(']')
        elif ctype == 'dict':
            out.append(f'{cname} = {{')
            for k, v in list(cval.items())[:50]:
                out.append(f'    {repr(k)}: {v},')
            if len(cval) > 50:
                out.append(f'    # ... {len(cval)-50} more entries')
            out.append('}')
        out.append('')
    
    if api_urls:
        out.append('# ── API Endpoints & URLs ──')
        for url in sorted(set(api_urls)):
            out.append(f'# URL: {url}')
        out.append('')
    
    if string_consts:
        out.append('# ── Notable Strings ──')
        seen = set()
        for idx, s in string_consts:
            if s not in seen and len(s) > 10 and not s.startswith('iVBOR'):
                out.append(f'# [{idx}] {repr(s[:120])}')
                seen.add(s)
                if len(seen) > 120: break
        out.append('')
    
    # Classes
    out.append('# ═══ CLASSES ═══')
    
    for cls_name, cls_data in classes.items():
        # Skip garbage
        if len(cls_name) > 60 or ' ' in cls_name or '\x00' in cls_name:
            continue
        if not cls_name[0:1].isalpha() and cls_name[0:1] != '_':
            continue
        
        methods = cls_data['methods']
        attrs = cls_data['attrs']
        slots = cls_data['slots']
        
        if not methods and not attrs:
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
                out.append(f'    # self.{attr}')
            out.append('')
        
        # Methods
        for method_name, mdata in methods.items():
            if not method_name.isidentifier():
                continue
            
            args = mdata['args']
            types_ = mdata.get('types', {})
            ann = mdata.get('annotations', {})
            defaults = mdata.get('defaults', {})
            locals_ = mdata.get('locals', [])
            
            sig = format_signature(method_name, args, types_, ann, defaults)
            out.append(f'    {sig}')
            
            # Docstring with annotations
            if ann and len(ann) > 0:
                out.append(f'        """')
                for param, atype in ann.items():
                    if param != 'return':
                        out.append(f'        :param {param}: {atype}')
                    else:
                        out.append(f'        :returns: {atype}')
                out.append(f'        """')
            
            # Local variables hint
            if locals_:
                for local_tuple in locals_[:3]:
                    local_strs = [str(x) for x in local_tuple[:8]]
                    out.append(f'        # locals: {", ".join(local_strs)}')
            
            out.append(f'        ...')
            out.append('')
    
    return '\n'.join(out)


# ─────────────────────── main ───────────────────────

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    out_dir = Path('restore_deep_ultra') / 'reconstructed_source_v3'
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
    
    print(f"\n[*] v3 Reconstruction complete!")
    print(f"    - {total_files} source files")
    print(f"    - {total_classes} classes")
    print(f"    - {total_methods} methods/functions")
    print(f"    - Output: {out_dir}")

if __name__ == '__main__':
    main()
