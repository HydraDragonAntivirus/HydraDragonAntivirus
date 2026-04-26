#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import threading
import time

# Get the directory where this script is located
current_dir = os.path.dirname(os.path.abspath(__file__))

# Add it to sys.path so 'import other_script' works
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# NOTE: do NOT print here — stdout may be the host app's pipe/GUI.
# All output goes to the log file opened inside _hook_worker().

import importlib.util
import inspect
import dis
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================
# Do NOT call sys.setrecursionlimit at module level — it would permanently
# alter the host process's recursion limit on the main thread before our
# worker even starts.  It is set inside _hook_worker() instead.
MAX_WORKER_THREADS = 64

# =============================================================================
# BYTECODE DECOMPILER
# =============================================================================

class BytecodeDecompiler:
    """Reconstructs Python Source from Raw Bytecode Instructions"""
    
    @staticmethod
    def decompile_code(code_obj):
        if not code_obj:
            return "    pass  # No bytecode found"

        # Use dis.get_instructions() as the sole probe — co_code was removed
        # as a public attribute in Python 3.12 and must not be accessed directly.
        lines = []
        try:
            instructions = list(dis.get_instructions(code_obj))

            # If very few instructions, it's likely compiled/empty
            if len(instructions) < 3:
                return BytecodeDecompiler.extract_compiled_metadata(code_obj)
            
            stack = []
            
            for instr in instructions:
                op = instr.opname
                arg = instr.argval
                
                if op == 'LOAD_CONST':
                    stack.append(repr(arg))
                elif op in ('LOAD_FAST', 'LOAD_GLOBAL', 'LOAD_NAME'):
                    stack.append(str(arg))
                elif op == 'LOAD_ATTR':
                    if stack:
                        obj = stack.pop()
                        stack.append(f"{obj}.{arg}")
                elif 'CALL' in op:
                    args_count = instr.arg
                    args = []
                    for _ in range(args_count):
                        if stack: args.insert(0, stack.pop())
                    if stack:
                        func = stack.pop()
                        call_str = f"{func}({', '.join(args)})"
                        lines.append(f"    {call_str}")
                        stack.append(call_str)
                elif op == 'STORE_FAST' or op == 'STORE_NAME':
                    if stack:
                        val = stack.pop()
                        lines.append(f"    {arg} = {val}")
                elif op == 'RETURN_VALUE':
                    if stack:
                        val = stack.pop()
                        if val != 'None':
                            lines.append(f"    return {val}")
            
            if not lines:
                return "    # Complex logic detected.\n    pass"
                
            return "\n".join(lines)
        except Exception as e:
            return BytecodeDecompiler.extract_compiled_metadata(code_obj)
    
    @staticmethod
    def extract_compiled_metadata(code_obj):
        """Extract metadata from compiled/Nuitka code objects"""
        lines = ["    # COMPILED CODE - Metadata extraction:"]
        
        try:
            # Extract constants
            if hasattr(code_obj, 'co_consts') and code_obj.co_consts:
                consts = [c for c in code_obj.co_consts if c is not None and not callable(c)]
                if consts:
                    lines.append("    # Constants found:")
                    for const in consts:
                        lines.append(f"    #   {repr(const)}")
            
            # Extract variable names
            if hasattr(code_obj, 'co_names') and code_obj.co_names:
                lines.append("    # Names referenced:")
                for name in code_obj.co_names:
                    lines.append(f"    #   {name}")
            
            # Extract local variables
            if hasattr(code_obj, 'co_varnames') and code_obj.co_varnames:
                lines.append("    # Local variables:")
                for var in code_obj.co_varnames:
                    lines.append(f"    #   {var}")
            
            # Extract free variables (closures)
            if hasattr(code_obj, 'co_freevars') and code_obj.co_freevars:
                lines.append("    # Free variables (closures):")
                for fv in code_obj.co_freevars:
                    lines.append(f"    #   {fv}")
            
            # Extract cell variables
            if hasattr(code_obj, 'co_cellvars') and code_obj.co_cellvars:
                lines.append("    # Cell variables:")
                for cv in code_obj.co_cellvars:
                    lines.append(f"    #   {cv}")
            
            # Code object info
            if hasattr(code_obj, 'co_argcount'):
                lines.append(f"    # Argument count: {code_obj.co_argcount}")
            if hasattr(code_obj, 'co_kwonlyargcount'):
                lines.append(f"    # Keyword-only args: {code_obj.co_kwonlyargcount}")
            if hasattr(code_obj, 'co_nlocals'):
                lines.append(f"    # Local variables count: {code_obj.co_nlocals}")
            
            lines.append("    pass  # AG: STUB_IDENTIFIED - Compiled code - no Python bytecode available")
        except Exception as e:
            lines.append(f"    # Metadata extraction error: {str(e)}")
            lines.append("    pass  # AG: STUB_IDENTIFIED")
        
        return "\n".join(lines)

# =============================================================================
# ENHANCED SIGNATURE & DOCSTRING EXTRACTOR
# =============================================================================

class SignatureExtractor:
    """Extracts function signatures and documentation safely"""
    
    @staticmethod
    def get_signature(func):
        """Extract function signature using inspect.signature()"""
        try:
            sig = inspect.signature(func)
            return str(sig)
        except (ValueError, TypeError):
            # Fallback for built-in/compiled functions
            try:
                # Try to get parameter names from code object
                if hasattr(func, '__code__'):
                    code = func.__code__
                    argcount = code.co_argcount
                    kwonlyargcount = getattr(code, 'co_kwonlyargcount', 0)
                    varnames = code.co_varnames
                    
                    # Build signature from code object
                    params = []
                    
                    # Regular arguments
                    for i in range(argcount):
                        params.append(varnames[i])
                    
                    # *args if present
                    if code.co_flags & 0x04:  # CO_VARARGS
                        params.append(f"*{varnames[argcount + kwonlyargcount]}")
                    
                    # Keyword-only arguments
                    for i in range(argcount, argcount + kwonlyargcount):
                        params.append(varnames[i])
                    
                    # **kwargs if present
                    if code.co_flags & 0x08:  # CO_VARKEYWORDS
                        kwarg_index = argcount + kwonlyargcount
                        if code.co_flags & 0x04:
                            kwarg_index += 1
                        params.append(f"**{varnames[kwarg_index]}")
                    
                    return f"({', '.join(params)})"
            except:
                pass
            return "(*args, **kwargs)"
    
    @staticmethod
    def get_docstring(obj):
        """Extract docstring safely"""
        try:
            doc = inspect.getdoc(obj)
            if doc:
                # Format as multiline docstring
                lines = doc.split('\n')
                if len(lines) == 1:
                    return f'    """{doc}"""'
                else:
                    formatted = ['    """']
                    formatted.extend([f"    {line}" for line in lines])
                    formatted.append('    """')
                    return '\n'.join(formatted)
        except:
            pass
        return None
    
    @staticmethod
    def get_source_info(obj):
        """Try to get source file and line number"""
        try:
            file = inspect.getfile(obj)
            lines = inspect.getsourcelines(obj)
            return f"    # Source: {file}:{lines[1]}"
        except:
            return None

# =============================================================================
# MODULE RECONSTRUCTOR
# =============================================================================

class ModuleReconstructor:
    def __init__(self, backup_dir):
        self.backup_dir = backup_dir
        self.decompiler = BytecodeDecompiler()
        self.sig_extractor = SignatureExtractor()
        self.compiled_modules = []  # Track compiled modules

    def process_module(self, name, mod, is_potential_main=False):
        safe_name = name.replace('.', '_')
        output_path = self.backup_dir / "RECONSTRUCTED_SOURCE" / f"{safe_name}.py"
        
        content = [f'"""\nModule: {name}\nType: {type(mod)}\n']
        
        if is_potential_main:
            if name == '__main__':
                content.append("=" * 70 + "\n")
                content.append("*** APPLICATION ENTRY POINT (__main__) ***\n")
                content.append("=" * 70 + "\n")
            else:
                content.append("*** POTENTIAL APPLICATION MODULE ***\n")
        
        if hasattr(mod, '__file__'):
            content.append(f"File: {mod.__file__}\n")
        
        content.append('"""\n')
        
        # Add module docstring if exists
        mod_doc = self.sig_extractor.get_docstring(mod)
        if mod_doc:
            content.append(mod_doc)
            content.append("")
        
        # Check for Nuitka-specific attributes
        nuitka_info = []
        try:
            if hasattr(mod, '__compiled__'):
                nuitka_info.append("# NUITKA COMPILED MODULE")
            if hasattr(mod, '__nuitka_version__'):
                nuitka_info.append(f"# Nuitka version: {mod.__nuitka_version__}")
            if hasattr(mod, '__package__'):
                nuitka_info.append(f"# Package: {mod.__package__}")
            if hasattr(mod, '__spec__') and mod.__spec__:
                nuitka_info.append(f"# Spec: {mod.__spec__}")
        except:
            pass
        
        if nuitka_info:
            content.extend(nuitka_info)
            content.append("")
        
        # Try to capture module-level code (especially important for __main__)
        try:
            module_code = None
            
            # Method 1: Try __loader__.get_code()
            if hasattr(mod, '__loader__') and hasattr(mod.__loader__, 'get_code'):
                try:
                    module_code = mod.__loader__.get_code(name)
                except:
                    pass
            
            # Method 2: Search for code object in module's compiled file
            if not module_code and hasattr(mod, '__file__'):
                try:
                    spec = importlib.util.find_spec(name) if name != '__main__' else None
                    if spec and hasattr(spec, 'loader'):
                        module_code = spec.loader.get_code(name)
                except:
                    pass
            
            # If we got module-level code, decompile it
            if module_code:
                content.append("\n# ===== MODULE-LEVEL CODE =====")
                content.append(self.decompiler.decompile_code(module_code))
                content.append("# ===== END MODULE-LEVEL CODE =====\n")
        except:
            pass
        
        # For __main__, try to extract ANY additional runtime info
        if name == '__main__':
            extra_info = []
            try:
                # Check for __dict__ items we might have missed
                if hasattr(mod, '__dict__'):
                    hidden_items = []
                    for key, val in mod.__dict__.items():
                        # Look for non-standard attributes
                        if not key.startswith('_') and key not in dir(mod):
                            hidden_items.append(f"# Hidden: {key} = {repr(val)}")
                    if hidden_items:
                        extra_info.append("\n# ===== ADDITIONAL MODULE ATTRIBUTES =====")
                        extra_info.extend(hidden_items)
                        extra_info.append("# ===== END ADDITIONAL ATTRIBUTES =====\n")
            except:
                pass
            
            if extra_info:
                content.extend(extra_info)
        
        # Hook-injected infrastructure variable names — these are leaked into __main__'s
        # namespace by the injection mechanism and must never appear in the output.
        _HOOK_INJECTED_VARS = frozenset({
            'hook_globals', 'env_hook', 'exe_dir', 'dlls_dir',
            'lib_dir', 'pythonhome', 'site_packages', 'path',
        })

        # Hunt for every callable in the module
        for attr_name in sorted(dir(mod)):
            if attr_name.startswith('__') and attr_name != '__init__':
                continue

            # Strip hook-injected runtime vars from __main__ — they are not part
            # of the original application source and would corrupt the merged output.
            if name == '__main__' and attr_name in _HOOK_INJECTED_VARS:
                continue
            
            try:
                attr = getattr(mod, attr_name)
            except Exception as e:
                content.append(f"# Error accessing {attr_name}: {str(e)}")
                continue
            
            try:
                
                # If it's a Class
                if inspect.isclass(attr):
                    content.append(f"\nclass {attr_name}:")
                    
                    # Add class docstring
                    class_doc = self.sig_extractor.get_docstring(attr)
                    if class_doc:
                        content.append(class_doc)
                    else:
                        content.append('    """Class"""')
                    
                    # Add source info
                    source_info = self.sig_extractor.get_source_info(attr)
                    if source_info:
                        content.append(source_info)
                    
                    content.append("")
                    
                    # Process class methods
                    for m_name in sorted(dir(attr)):
                        if m_name.startswith('__') and m_name not in ['__init__', '__call__']:
                            continue
                        try:
                            m_attr = getattr(attr, m_name)
                            
                            # Only process if it's callable
                            if not callable(m_attr):
                                continue
                                
                            # Get signature
                            sig = self.sig_extractor.get_signature(m_attr)
                            content.append(f"    def {m_name}{sig}:")
                            
                            # Get docstring
                            m_doc = self.sig_extractor.get_docstring(m_attr)
                            if m_doc:
                                content.append(m_doc)
                            
                            # Try to get code object safely
                            code_obj = None
                            decompiled = None
                            try:
                                # Force attempt to access __code__, don't rely on hasattr
                                code_obj = m_attr.__code__
                            except (RuntimeError, AttributeError, Exception) as e:
                                # Compiled code or built-in - __code__ access failed
                                code_obj = None
                            
                            # Add decompiled code or metadata
                            if code_obj:
                                try:
                                    decompiled = self.decompiler.decompile_code(code_obj)
                                    if not m_doc or "pass" not in decompiled:
                                        content.append(decompiled)
                                    
                                    # Track if compiled
                                    if "COMPILED CODE" in decompiled or "Nuitka compiled" in decompiled:
                                        self.compiled_modules.append((name, attr_name, m_name))
                                except Exception as e:
                                    content.append(f"        # Decompile error: {e}")
                                    content.append("        pass")
                            
                            # If no code_obj, do metadata extraction (fallback for compiled/builtin)
                            if not code_obj:
                                # Extract what we can without code object
                                content.append("        # Compiled/protected code - attempting metadata extraction")
                                
                                # Try multiple methods to get info
                                metadata = []
                                
                                # Method 0: Show docstring again in metadata comments if available
                                if m_doc:
                                    doc_preview = m_doc.replace('\n', ' ').replace('    """', '').replace('"""', '').strip()
                                    metadata.append(f"        # Docstring: {doc_preview}")
                                
                                # Method 1: Try inspect.signature
                                try:
                                    sig = inspect.signature(m_attr)
                                    metadata.append(f"        # Signature: {sig}")
                                except:
                                    pass
                                
                                # Method 2: Check for __annotations__
                                try:
                                    if hasattr(m_attr, '__annotations__') and m_attr.__annotations__:
                                        metadata.append(f"        # Annotations: {m_attr.__annotations__}")
                                except:
                                    pass
                                
                                # Method 3: Check for __defaults__
                                try:
                                    if hasattr(m_attr, '__defaults__') and m_attr.__defaults__:
                                        metadata.append(f"        # Defaults: {m_attr.__defaults__}")
                                except:
                                    pass
                                
                                # Method 4: Check for __kwdefaults__
                                try:
                                    if hasattr(m_attr, '__kwdefaults__') and m_attr.__kwdefaults__:
                                        metadata.append(f"        # Keyword defaults: {m_attr.__kwdefaults__}")
                                except:
                                    pass
                                
                                # Method 5: Try __wrapped__ (for decorated functions)
                                try:
                                    if hasattr(m_attr, '__wrapped__'):
                                        metadata.append(f"        # Has __wrapped__ attribute")
                                except:
                                    pass
                                
                                # Method 6: Try __doc__ directly as backup
                                try:
                                    if hasattr(m_attr, '__doc__') and m_attr.__doc__ and not m_doc:
                                        doc_raw = str(m_attr.__doc__).strip()
                                        metadata.append(f"        # Raw __doc__: {doc_raw}")
                                except:
                                    pass
                                
                                if metadata:
                                    content.extend(metadata)
                                
                                content.append("        pass  # AG: STUB_IDENTIFIED - No bytecode accessible")
                                self.compiled_modules.append((name, attr_name, m_name))
                            
                            content.append("")
                        except:
                            continue
                
                # If it's a Function
                elif callable(attr):
                    # Get signature
                    sig = self.sig_extractor.get_signature(attr)
                    content.append(f"\ndef {attr_name}{sig}:")
                    
                    # Add docstring
                    func_doc = self.sig_extractor.get_docstring(attr)
                    if func_doc:
                        content.append(func_doc)
                    
                    # Add source info
                    source_info = self.sig_extractor.get_source_info(attr)
                    if source_info:
                        content.append(source_info)
                    
                    # Try to get code object safely
                    code_obj = None
                    decompiled = None
                    try:
                        # Force attempt to access __code__, don't rely on hasattr
                        code_obj = attr.__code__
                    except (RuntimeError, AttributeError, Exception):
                        # Compiled code or built-in - __code__ access failed
                        code_obj = None
                    
                    # Add decompiled code or metadata
                    if code_obj:
                        try:
                            decompiled = self.decompiler.decompile_code(code_obj)
                            content.append(decompiled)
                            
                            # Track if compiled
                            if "COMPILED CODE" in decompiled or "Nuitka compiled" in decompiled:
                                self.compiled_modules.append((name, attr_name, None))
                        except Exception as e:
                            content.append(f"    # Decompile error: {e}")
                            content.append("    pass")
                    
                    # If no code_obj, do metadata extraction (fallback for compiled/builtin)
                    if not code_obj:
                        # Extract what we can without code object
                        content.append("    # Compiled/protected code - attempting metadata extraction")
                        
                        # Try multiple methods to get info
                        metadata = []
                        
                        # Method 0: Show docstring again in metadata comments if available
                        if func_doc:
                            doc_preview = func_doc.replace('\n', ' ').replace('    """', '').replace('"""', '').strip()
                            metadata.append(f"    # Docstring: {doc_preview}")
                        
                        # Method 1: Try inspect.signature
                        try:
                            sig = inspect.signature(attr)
                            metadata.append(f"    # Signature: {sig}")
                        except:
                            pass
                        
                        # Method 2: Check for __annotations__
                        try:
                            if hasattr(attr, '__annotations__') and attr.__annotations__:
                                metadata.append(f"    # Annotations: {attr.__annotations__}")
                        except:
                            pass
                        
                        # Method 3: Check for __defaults__
                        try:
                            if hasattr(attr, '__defaults__') and attr.__defaults__:
                                metadata.append(f"    # Defaults: {attr.__defaults__}")
                        except:
                            pass
                        
                        # Method 4: Check for __kwdefaults__
                        try:
                            if hasattr(attr, '__kwdefaults__') and attr.__kwdefaults__:
                                metadata.append(f"    # Keyword defaults: {attr.__kwdefaults__}")
                        except:
                            pass
                        
                        # Method 5: Try __wrapped__ (for decorated functions)
                        try:
                            if hasattr(attr, '__wrapped__'):
                                metadata.append(f"    # Has __wrapped__ attribute")
                        except:
                            pass
                        
                        # Method 6: Try __doc__ directly as backup
                        try:
                            if hasattr(attr, '__doc__') and attr.__doc__ and not func_doc:
                                doc_raw = str(attr.__doc__).strip()
                                metadata.append(f"    # Raw __doc__: {doc_raw}")
                        except:
                            pass
                        
                        if metadata:
                            content.extend(metadata)
                        
                        content.append("    pass  # AG: STUB_IDENTIFIED - No bytecode accessible")
                        self.compiled_modules.append((name, attr_name, None))
                    content.append("")
                
                # If it's a variable/constant
                elif not callable(attr):
                    if isinstance(attr, (str, int, float, bool, type(None))):
                        content.append(f"{attr_name} = {repr(attr)}")
                    elif isinstance(attr, (dict, list, tuple, set)):
                        repr_str = repr(attr)
                        content.append(f"{attr_name} = {repr_str}")
                    
            except Exception as e:
                content.append(f"# Error processing {attr_name}: {str(e)}")
                continue
        
        output_path.write_text("\n".join(content), encoding='utf-8', errors='ignore')



# =============================================================================
# FROZEN MODULE DUMPER
# =============================================================================
def dump_frozen_modules(recon, source_dir, hook_log):
    """Dump code objects from CPython's frozen-module table without importing them.

    This is intentionally not an import hook and not a source-file copier.  It
    only uses _imp's frozen-module table that already exists in the current
    interpreter.  If a protected/embedded module is present there, it can be
    dumped even when it is not visible as a normal .py source file.
    """
    try:
        import _imp
        import types
        import dis as _dis
        import io as _io
    except Exception as e:
        try: hook_log(f"[FROZEN] unavailable: {e}\n")
        except Exception: pass
        return 0

    def safe_name(name):
        return name.replace('.', '_').replace('<', '_').replace('>', '_').replace(':', '_').replace('\\', '_').replace('/', '_')

    def disassemble(code_obj):
        try:
            buf = _io.StringIO()
            _dis.dis(code_obj, file=buf)
            return buf.getvalue()
        except Exception as e:
            return f"<disassembly failed: {e}>\n"

    def emit_code_metadata(code_obj, prefix="# "):
        lines = []
        try:
            lines.append(f"{prefix}co_name={code_obj.co_name!r}")
            lines.append(f"{prefix}co_qualname={getattr(code_obj, 'co_qualname', code_obj.co_name)!r}")
            lines.append(f"{prefix}co_filename={code_obj.co_filename!r}")
            lines.append(f"{prefix}co_firstlineno={code_obj.co_firstlineno!r}")
            lines.append(f"{prefix}co_argcount={getattr(code_obj, 'co_argcount', None)!r}")
            lines.append(f"{prefix}co_kwonlyargcount={getattr(code_obj, 'co_kwonlyargcount', None)!r}")
            lines.append(f"{prefix}co_nlocals={getattr(code_obj, 'co_nlocals', None)!r}")
            lines.append(f"{prefix}co_varnames={getattr(code_obj, 'co_varnames', ())!r}")
            lines.append(f"{prefix}co_names={getattr(code_obj, 'co_names', ())!r}")
            const_preview = []
            for c in getattr(code_obj, 'co_consts', ()): 
                if isinstance(c, types.CodeType):
                    const_preview.append(f"<code {c.co_name}>")
                else:
                    r = repr(c)
                    if len(r) > 300:
                        r = r[:300] + '...'
                    const_preview.append(r)
            lines.append(f"{prefix}co_consts={const_preview!r}")
        except Exception as e:
            lines.append(f"{prefix}metadata failed: {e}")
        return "\n".join(lines)

    def nested_code_objects(code_obj, seen=None):
        if seen is None:
            seen = set()
        out = []
        ident = id(code_obj)
        if ident in seen:
            return out
        seen.add(ident)
        for c in getattr(code_obj, 'co_consts', ()): 
            if isinstance(c, types.CodeType):
                out.append(c)
                out.extend(nested_code_objects(c, seen))
        return out

    names = []
    try:
        getter = getattr(_imp, '_frozen_module_names', None)
        if getter:
            names = list(getter())
    except Exception as e:
        try: hook_log(f"[FROZEN] _frozen_module_names failed: {e}\n")
        except Exception: pass
        names = []

    # Also include frozen modules already visible in sys.modules. This does not
    # import anything; it only adds names that are already loaded.
    try:
        for name, mod in list(sys.modules.items()):
            try:
                spec = getattr(mod, '__spec__', None)
                origin = getattr(spec, 'origin', None) if spec else None
                loader = getattr(spec, 'loader', None) if spec else None
                loader_name = type(loader).__name__ if loader is not None else ''
                if origin == 'frozen' or loader_name == 'FrozenImporter' or _imp.is_frozen(name):
                    names.append(name)
            except Exception:
                pass
    except Exception:
        pass

    names = sorted(set(n for n in names if isinstance(n, str) and n))
    try:
        hook_log(f"[FROZEN] candidate names: {len(names)}\n")
        like = [n for n in names if 'crack' in n.lower() or 'v5' in n.lower()]
        hook_log(f"[FROZEN] crack/v5-like candidate names: {like}\n")
    except Exception:
        pass

    frozen_dir = source_dir / "FROZEN_MODULES"
    try:
        frozen_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    dumped = 0
    for name in names:
        if name == '__hook__' or name.startswith('__hook__.'):
            continue
        try:
            if not _imp.is_frozen(name):
                continue
        except Exception:
            pass
        try:
            code_obj = _imp.get_frozen_object(name)
        except Exception as e:
            try: hook_log(f"[FROZEN ERR] get_frozen_object({name!r}): {e}\n")
            except Exception: pass
            continue
        if not isinstance(code_obj, types.CodeType):
            try: hook_log(f"[FROZEN SKIP] {name}: object is {type(code_obj)}\n")
            except Exception: pass
            continue

        safe = safe_name(name)
        content = []
        content.append('\"\"\"')
        content.append(f"Frozen module: {name}")
        content.append("Source type: _imp frozen code object")
        content.append("Note: no original .py source is available through normal inspect/getsource.")
        content.append('\"\"\"')
        content.append("")
        content.append("# ===== FROZEN MODULE CODE OBJECT METADATA =====")
        content.append(emit_code_metadata(code_obj))
        content.append("")
        content.append("# ===== BEST-EFFORT PSEUDO SOURCE =====")
        try:
            content.append(recon.decompiler.decompile_code(code_obj))
        except Exception as e:
            content.append(f"# decompile failed: {e}")
            content.append("pass")
        content.append("")
        content.append("FROZEN_DISASSEMBLY = " + repr(disassemble(code_obj)))

        nested = nested_code_objects(code_obj)
        if nested:
            content.append("")
            content.append("# ===== NESTED CODE OBJECTS =====")
            for idx, nested_code in enumerate(nested, 1):
                content.append(f"\n# --- nested code object {idx}: {nested_code.co_name} ---")
                content.append(emit_code_metadata(nested_code))
                content.append("NESTED_DISASSEMBLY_%d = " % idx + repr(disassemble(nested_code)))

        data = "\n".join(content)
        try:
            (frozen_dir / f"{safe}.py").write_text(data, encoding='utf-8', errors='replace')
            # Also create the normal top-level reconstructed file only if the
            # regular sys.modules pass did not already create one.
            top = source_dir / f"{safe}.py"
            if not top.exists():
                top.write_text(data, encoding='utf-8', errors='replace')
            dumped += 1
            try: hook_log(f"[FROZEN OK] Dumped frozen module: {name}\n")
            except Exception: pass
        except Exception as e:
            try: hook_log(f"[FROZEN ERR] write {name}: {e}\n")
            except Exception: pass

    try: hook_log(f"[FROZEN] dumped={dumped}\n")
    except Exception: pass
    return dumped


# =============================================================================
# HELPER: GET NEXT INCREMENTAL PATH
# =============================================================================

def get_next_dump_path(base_dir):
    """Get next available dump path (dump_1, dump_2, etc.)"""
    base_path = Path(base_dir)
    
    if not base_path.exists():
        base_path.mkdir(parents=True, exist_ok=True)
        return base_path / "dump_1"
    
    # Always pick Max + 1 so we never fill old gaps and confuse the GUI
    max_num = 0
    try:
        for d in base_path.iterdir():
            if d.is_dir() and d.name.startswith("dump_"):
                try:
                    num = int(d.name.split("_", 1)[1])
                    if num > max_num:
                        max_num = num
                except ValueError:
                    pass
    except Exception:
        pass
        
    return base_path / f"dump_{max_num + 1}"

# =============================================================================
# MAIN EXECUTION
# =============================================================================
def run_decompiler():
    # Set recursion limit only for this worker thread — does not affect the
    # host process's main thread.
    sys.setrecursionlimit(15000)

    dump_root = Path(r"C:\ProgramData\HydraDragonAntivirus\python_dumps")
    backup_dir = get_next_dump_path(str(dump_root))
    source_dir = backup_dir / "RECONSTRUCTED_SOURCE"
    started_path = backup_dir / "started.txt"
    progress_path = backup_dir / "progress.txt"
    finished_path = backup_dir / "finished.txt"
    error_path = backup_dir / "error.txt"
    status_path = source_dir / "__dump_status__.txt"

    def write_marker(path: Path, text: str):
        try:
            path.write_text(text, encoding='utf-8', errors='replace')
        except Exception:
            pass

    # Create output directories immediately so the injector can see progress
    # even if logging fails later.
    source_dir.mkdir(parents=True, exist_ok=True)
    write_marker(
        started_path,
        "pid={pid}\nstarted_unix={ts:.3f}\nstarted_local={local}\n".format(
            pid=os.getpid(),
            ts=time.time(),
            local=time.strftime('%Y-%m-%d %H:%M:%S'),
        ),
    )
    write_marker(progress_path, "phase=bootstrap\n")
    write_marker(status_path, "status=started\n")

    # Keep the debug log beside the dump so the user can always find it.
    log_path = str(backup_dir / "decompiler_debug.txt")

    try:
        with open(log_path, "w", encoding='utf-8', errors='replace') as f:
            f.write("")
    except Exception:
        pass

    def hook_log(msg):
        # Open, Write, and Close instantly to prevent Windows file locking
        try:
            with open(log_path, "a", encoding='utf-8', errors='replace') as log_f:
                log_f.write(msg)
        except Exception:
            pass

    try:
        hook_log(f"Starting decompilation\nTarget Dir: {backup_dir}\n")
        hook_log(f"Created: {source_dir}\n")
        write_marker(progress_path, "phase=initializing\n")

        recon = ModuleReconstructor(backup_dir)
        # Snapshot sys.modules immediately — the set changes as imports happen.
        targets = list(sys.modules.items())
        total_targets = len(targets)
        hook_log(f"Found {total_targets} modules\n")
        write_marker(
            progress_path,
            "phase=scanning\ncurrent=0/{total}\nprocessed=0\nerrors=0\n".format(
                total=total_targets
            ),
        )

        # Identify the application entry point(s) for the report header —
        # __main__ that isn't the hook itself, or any non-hook module.
        potential_mains = []
        for name, mod in targets:
            if not mod or not hasattr(mod, '__file__') or not mod.__file__:
                continue
            file_path = mod.__file__
            if '__hook__' in file_path or 'hook_backend' in file_path:
                continue
            potential_mains.append((name, file_path))

        if potential_mains:
            hook_log(f"\n[INFO] Modules found in process:\n")
            for name, path in potential_mains:
                hook_log(f"  - {name}: {path}\n")
            hook_log("\n")

        processed_count = 0
        error_count = 0

        for idx, (name, mod) in enumerate(targets, 1):
            if idx == 1 or idx % 25 == 0 or idx == total_targets:
                progress_text = (
                    "phase=processing\n"
                    "current={idx}/{total}\n"
                    "module={name}\n"
                    "processed={processed}\n"
                    "errors={errors}\n"
                ).format(
                    idx=idx,
                    total=total_targets,
                    name=name,
                    processed=processed_count,
                    errors=error_count,
                )
                write_marker(progress_path, progress_text)
                write_marker(status_path, "status=" + progress_text)

            # Skip null entries
            if not mod:
                continue

            # Only skip __hook__ itself — decompile everything else including stdlib
            if name == '__hook__':
                continue

            # Skip __main__ only if it literally IS the hook script
            if name == '__main__':
                try:
                    if hasattr(mod, '__file__') and mod.__file__:
                        if '__hook__' in mod.__file__ or 'hook_backend' in mod.__file__:
                            hook_log(f"[SKIP] __main__ is the hook script: {mod.__file__}\n")
                            continue
                except Exception:
                    pass

            # is_potential_main: mark __main__ and any non-hook module that has a file
            is_potential_main = False
            if hasattr(mod, '__file__') and mod.__file__:
                file_path = mod.__file__
                if '__hook__' not in file_path and 'hook_backend' not in file_path:
                    is_potential_main = (name == '__main__')

            try:
                recon.process_module(name, mod, is_potential_main)
                processed_count += 1
                hook_log(f"[OK] Processed: {name}\n")
            except Exception as e:
                error_count += 1
                hook_log(f"[ERR] Error processing {name}: {str(e)}\n")

        frozen_dumped = 0
        try:
            write_marker(progress_path, "phase=frozen_scan\nprocessed={processed}\nerrors={errors}\n".format(processed=processed_count, errors=error_count))
            frozen_dumped = dump_frozen_modules(recon, source_dir, hook_log)
        except Exception as e:
            error_count += 1
            hook_log(f"[FROZEN ERR] frozen scan crashed: {e}\n")

        # Final diagnostics only.  Do NOT wait here and do NOT force-import
        # anything.  _module_locks can prove a name was requested by importlib,
        # but the lock does not contain module source or a module object.
        try:
            crack_like_modules = sorted(
                name for name in sys.modules
                if 'crack' in str(name).lower() or 'v5' in str(name).lower()
            )
            hook_log(f"[FINAL CHECK] crack/v5-like sys.modules: {crack_like_modules}\n")
        except Exception as e:
            try: hook_log(f"[FINAL CHECK] sys.modules diagnostic failed: {e}\n")
            except Exception: pass

        try:
            import importlib._bootstrap as _bootstrap
            locks = getattr(_bootstrap, '_module_locks', {})
            lock_names = sorted(str(name) for name in getattr(locks, 'keys', lambda: [])())
            crack_like_locks = [
                name for name in lock_names
                if 'crack' in name.lower() or 'v5' in name.lower()
            ]
            hook_log(f"[FINAL CHECK] crack/v5-like module_locks: {crack_like_locks}\n")
        except Exception as e:
            try: hook_log(f"[FINAL CHECK] module_locks diagnostic failed: {e}\n")
            except Exception: pass

        try:
            import _imp
            names_to_check = set()
            try:
                names_to_check.update(crack_like_modules)
            except Exception:
                pass
            try:
                names_to_check.update(crack_like_locks)
            except Exception:
                pass
            for n in sorted(names_to_check):
                try:
                    hook_log(f"[FINAL CHECK] _imp.is_frozen({n!r})={_imp.is_frozen(n)}\n")
                except Exception as e:
                    hook_log(f"[FINAL CHECK] _imp.is_frozen({n!r}) failed: {e}\n")
        except Exception as e:
            try: hook_log(f"[FINAL CHECK] _imp diagnostic failed: {e}\n")
            except Exception: pass

        hook_log("\n" + "=" * 60 + "\n--- FINISHED ---\n")
        hook_log(f"Output location: {backup_dir}\n")
        hook_log(f"Processed: {processed_count} modules\nErrors: {error_count}\n")
        hook_log(f"Compiled code blocks: {len(recon.compiled_modules)}\n")
        hook_log(f"Frozen modules dumped: {frozen_dumped}\n")
        write_marker(
            progress_path,
            "phase=finished\nprocessed={processed}\nerrors={errors}\ncompiled={compiled}\n".format(
                processed=processed_count,
                errors=error_count,
                compiled=len(recon.compiled_modules),
            ),
        )
        write_marker(
            status_path,
            "status=finished\nprocessed={processed}\nerrors={errors}\ncompiled={compiled}\n".format(
                processed=processed_count,
                errors=error_count,
                compiled=len(recon.compiled_modules),
            ),
        )
        write_marker(finished_path, "DONE\n")
    except Exception:
        try:
            import traceback
            tb = traceback.format_exc()
            hook_log(tb)
            write_marker(error_path, tb)
            write_marker(progress_path, "phase=crashed\n")
            write_marker(status_path, "status=crashed\n")
        except Exception:
            pass
        raise


# =============================================================================
# ENTRY POINT — runs in a daemon background thread so:
#   1. The GIL is released immediately after import returns to the host process.
#   2. The host process's main thread, watchdog, and GUI are never blocked.
#   3. If the host exits normally the thread dies with it (daemon=True).
# =============================================================================
def _hook_worker():
    # Make absolutely sure old crashes don't pollute new runs
    crash_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), "hook_crash.txt")
    if os.path.exists(crash_path):
        try: os.remove(crash_path)
        except: pass

    try:
        run_decompiler()
    except Exception:
        # Last-resort: write to a separate crash log so we never raise into
        # the host process's thread.
        try:
            import traceback
            with open(crash_path, "w", encoding='utf-8', errors='replace') as f:
                traceback.print_exc(file=f)
        except Exception:
            pass


threading.Thread(target=_hook_worker, daemon=True, name="HydraDragonHook").start()
