"""
nuitka_source_reconstructor_v5.py

THE MAXIMUM PSEUDO-DECOMPILER
Uses advanced heuristics on the sequence and shape of constant tables to infer 
pseudo-code logic, yielding a "best guess" structural recovery.
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
    if not d or len(d) > 15: return False
    for k in d.keys():
        key = b2s(k) if isinstance(k, (bytes, bytearray)) else str(k)
        if not key.isidentifier() and key != 'return':
            return False
    return True

def parse_annotation_dict(d):
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
    if isinstance(raw, str):
        raw = raw.encode('utf-8', errors='replace')
    segments = raw.split(b'\x00')
    method_refs, args, types = [], [], {}
    for seg in segments:
        if not seg: continue
        text = seg.decode('utf-8', errors='replace')
        if not text: continue
        tag, name = text[0], text[1:]
        if tag == 'a': args.append(name)
        elif tag in ('u', 'p'):
            if '.' in name and name.split('.')[0][0:1].isupper():
                method_refs.append(name)
        elif tag == 'O' and args: types[args[-1]] = name
    return method_refs, args, types, None

def format_signature(name, args, types=None, ann=None, defaults=None):
    all_t = {**(types or {}), **(ann or {})}
    parts = []
    for a in args:
        if a == 'return': continue
        base = a
        if a in all_t: base = f'{a}: {all_t[a]}'
        if a in (defaults or {}): base += f' = {defaults[a]}'
        parts.append(base)
    sig = ', '.join(parts)
    ret = all_t.get('return')
    return f'def {name}({sig}) -> {ret}:' if ret else f'def {name}({sig}):'


# ─────────────────────── heuristic pseudo-decompiler ───────────────────────

def generate_pseudo_code(internals, locals_hints, class_methods, class_attrs):
    """
    Analyzes the exact sequence of constants to build pseudo-code statements.
    """
    body = []
    
    # Add local variable setup
    local_vars_declared = set()
    if locals_hints:
        body.append("# --- Setup Locals ---")
        for hint_tuple in locals_hints[:3]:
             for var in hint_tuple:
                 if var not in local_vars_declared and str(var).isidentifier():
                     body.append(f"{var} = None")
                     local_vars_declared.add(var)
                     
    if not internals:
        if not body: return ["    pass"]
        else: return ["    " + b for b in body]
        
    body.append("\n# --- Inferred Logic (Heuristic Reconstruction) ---")
    
    i = 0
    n = len(internals)
    
    while i < n:
        typ, val = internals[i]
        
        # Heuristic 1: Tuple of length 1 containing a string that is a method -> call
        if typ == 'tuple' and len(val) == 1 and isinstance(val[0], str):
            method_candidate = val[0]
            if method_candidate in class_methods:
                body.append(f"self.{method_candidate}()  # Inferred call")
                i += 1; continue
        
        # Heuristic 2: String that is a method of this class
        if typ == 'str' and val in class_methods:
            # Maybe passing method as callback? Or direct call?
            body.append(f"callback = self.{val}")
            i += 1; continue
            
        # Heuristic 3: String that is an attribute of this class
        if typ == 'str' and val in class_attrs:
            # Probably self getattr or setattr
            if i + 1 < n and internals[i+1][0] in ('int', 'float', 'bool', 'str', 'tuple', 'list'):
                next_val = internals[i+1][1]
                body.append(f"self.{val} = {repr(next_val)}  # Assignment")
                i += 2; continue
            else:
                body.append(f"var = getattr(self, {repr(val)})")
                i += 1; continue
                
        # Heuristic 4: Tuple ending in kwargs/flags (often UI elements like CTkButton)
        if typ == 'tuple' and len(val) > 1 and any(isinstance(x, str) and (x.endswith('_color') or x == 'command') for x in val):
            body.append(f"ui_element = apply_kwargs(**{repr(val)})")
            i += 1; continue

        # Heuristic 5: HTTP/API Request
        if typ == 'str' and ('http' in val.lower() or '/functions/' in val):
            body.append(f"api_response = requests.request(url={repr(val)})")
            i += 1; continue

        # Heuristic 6: Print/Log
        if typ == 'str' and ('error' in val.lower() or 'success' in val.lower() or 'warning' in val.lower()):
            body.append(f"log({repr(val)})")
            i += 1; continue
            
        # Heuristic 7: Timeouts and Limits (Numbers)
        if typ == 'literal':
            if isinstance(val, int) and val > 10 and val < 10000:
                body.append(f"time.sleep({val} / 1000.0)  # Or timeout limitation")
            elif isinstance(val, float):
                body.append(f"threshold = {val}")
            else:
                body.append(f"flag = {val}")
            i += 1; continue
            
        # Heuristic 8: Dictionary mappings (Configs)
        if typ == 'dict':
            body.append(f"config_map = {val}")
            i += 1; continue
            
        # Heuristic 9: State/UI tuple configs
        if typ == 'list':
            body.append(f"ui_states = {val}")
            i += 1; continue
            
        # Fallback
        if typ == 'str' and len(val) > 3 and not val.startswith('iVBORw') and not val.startswith('JFIF'):
            body.append(f"string_const = {repr(val)}")
        elif typ == 'tuple':
            body.append(f"state_tuple = {repr(val)}")

        i += 1

    # Clean up output
    dedup = []
    for line in body:
        if line not in dedup or "time.sleep" in line or "Inferred" in line or "callback =" in line:
            dedup.append(line)
            
    return ["    " + line for line in dedup]

# ─────────────────────── reconstructor ───────────────────────

def reconstruct_module(section_name, items):
    n = len(items)
    
    images = OrderedDict()
    vk_constants = OrderedDict()
    module_consts = OrderedDict()
    classes = OrderedDict()
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
            if m['args'] == ['self']: m['args'] = args
            if types_: m['types'].update(types_)
            if ann: m['annotations'].update(ann)
    
    # PASS 1: Identify bounds
    i = 0
    while i < n:
        t = types[i]
        v = items[i]
        
        if t == 'none':
            i += 1; continue
        
        if t == 'bytes':
            name = b2s(v)
            if name.endswith('_B64') and i + 1 < n and types[i+1] in ('str', 'bytes'):
                if is_b64_image(items[i+1]):
                    images[name] = len(b2s(items[i+1])) if isinstance(items[i+1], (bytes, bytearray)) else len(items[i+1])
                    i += 2; continue
            if name.startswith('VK_'):
                vk_val = None
                if i + 1 < n and types[i+1] == 'int':
                    vk_val = items[i+1][1] if isinstance(items[i+1], tuple) else items[i+1]
                elif i > 0 and types[i-1] == 'int': vk_val = items[i-1]
                vk_constants[name] = vk_val
                i += 1; continue
        
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
                    
                    if i + 1 < n and types[i+1] == 'dict':
                        if is_annotation_dict(items[i+1]):
                            ann = parse_annotation_dict(items[i+1])
                            classes[cls]['methods'][method]['annotations'] = ann
                            arg_names = [k for k in ann.keys() if k != 'return']
                            if arg_names: add_method(cls, method, args=['self'] + arg_names, ann=ann)
        
        if t == 'packed':
            method_refs, args, ptypes, _ = parse_packed_full(v)
            for ref in method_refs:
                parts = ref.split('.', 1)
                if len(parts) == 2 and (parts[0][0:1].isupper() or parts[0][0:1] == '_'):
                    add_method(parts[0], parts[1])
                    current_class, last_method_cls, last_method_name = parts[0], parts[0], parts[1]
            
            if args and method_refs:
                last_ref = method_refs[-1]
                parts = last_ref.split('.', 1)
                if len(parts) == 2:
                    if 'self' not in args: args = ['self'] + args
                    add_method(parts[0], parts[1], args=args, types_=ptypes)
            elif args and last_method_cls and last_method_name:
                if 'self' not in args: args = ['self'] + args
                add_method(last_method_cls, last_method_name, args=args, types_=ptypes)
            i += 1; continue
        
        # Capturing the body constants sequentially
        if last_method_cls and last_method_name:
            m = classes[last_method_cls]['methods'][last_method_name]
            
            if t == 'dict':
                if not is_annotation_dict(v):
                    decoded = {b2s(k) if isinstance(k, (bytes, bytearray)) else repr(k): repr(val)[:100] if not isinstance(val, (bytes, bytearray)) else b2s(val)[:100] for k, val in list(v.items())[:20]}
                    m['internal_constants'].append(('dict', decoded))
            elif t == 'list':
                m['internal_constants'].append(('list', [b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in v[:40]]))
            elif t == 'tuple':
                decoded = tuple(b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in v)
                if last_name == '__slots__' and current_class: classes[current_class]['slots'] = decoded
                elif all(isinstance(x, str) for x in decoded) and len(decoded) >= 2: m['locals'].append(decoded)
                else: m['internal_constants'].append(('tuple', decoded))
            elif t in ('int', 'float', 'bool'):
                m['internal_constants'].append(('literal', v))
            elif t == 'str':
                if 'http' in v.lower() or '/functions/' in v: api_urls.append(v)
                if len(v) > 2 and not is_method_ref: m['internal_constants'].append(('str', v[:100]))
            elif t == 'bytes':
                name = b2s(v)
                if name.startswith('_') and current_class and len(name) > 2 and not name.startswith('__'):
                    classes[current_class]['attrs'].add(name)
                elif 'http' in name.lower() or '/functions/' in name: api_urls.append(name)
                elif len(name) > 2 and not name.startswith('VK_') and not is_method_ref:
                    m['internal_constants'].append(('str', name[:100]))
        
        last_name = b2s(v) if t == 'bytes' else v if t == 'str' else None
        i += 1
    
    # PASS 2: Generation
    out = []
    out.append(f'"""')
    out.append(f'MAXIMUM LONG PSEUDO-DECOMPILED SOURCE: {section_name}')
    out.append(f'"""\n')
    
    out.append('# ═══ IMPORTS ═══')
    out.append('import customtkinter as ctk\nfrom mss import mss\nimport ctypes\nimport json, os, sys, time\nimport numpy as np\nimport base64\nfrom io import BytesIO')
    out.append('from pynput import keyboard, mouse\nfrom PIL import Image, ImageTk\nimport urllib.request\n')
    
    out.append('# ═══ CONSTANTS ═══')
    if api_urls:
        for url in sorted(set(api_urls)): out.append(f'API_URL_{abs(hash(url)) % 1000} = {repr(url)}')
    
    for cls_name, cls_data in classes.items():
        if len(cls_name) > 60 or ' ' in cls_name or '\x00' in cls_name: continue
        if not cls_name[0:1].isalpha() and cls_name[0:1] != '_': continue
        
        methods = cls_data['methods']
        attrs = cls_data['attrs']
        if not methods and not attrs: continue
        
        out.append(f'\nclass {cls_name}:')
        if cls_data['slots']: out.append(f'    __slots__ = {cls_data["slots"]}\n')
        
        if attrs:
            for attr in sorted(attrs): out.append(f'    # self.{attr}')
            out.append('')
        
        class_methods = list(methods.keys())
        class_attrs   = list(attrs)
        
        for method_name, mdata in methods.items():
            if not method_name.isidentifier(): continue
            
            sig = format_signature(method_name, mdata['args'], mdata.get('types'), mdata.get('annotations'))
            out.append(f'    {sig}')
            
            pseudo_lines = generate_pseudo_code(
                mdata.get('internal_constants', []),
                mdata.get('locals', []),
                class_methods,
                class_attrs
            )
            for line in pseudo_lines:
                out.append(line)
            out.append('')
            
    return '\n'.join(out)

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    out_dir = Path('restore_deep_ultra') / 'reconstructed_source_v5'
    out_dir.mkdir(parents=True, exist_ok=True)
    
    for section_name, items in sections.items():
        if not items or len(items) < 5: continue
        try:
            source = reconstruct_module(section_name, items)
            if 'class ' in source and 'def ' in source:
                safe_name = re.sub(r'[<>:"/\\|?*\x00]', '_', section_name)[:80]
                (out_dir / f'{safe_name}.py').write_text(source, encoding='utf-8')
        except Exception as e:
            pass
            
    print("[*] V5 Maximum Pseudo-Decompilation Complete! Stored in restore_deep_ultra/reconstructed_source_v5/")

if __name__ == '__main__':
    main()
