#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import threading

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
                    for const in consts[:10]:  # Limit to first 10
                        lines.append(f"    #   {repr(const)}")
            
            # Extract variable names
            if hasattr(code_obj, 'co_names') and code_obj.co_names:
                lines.append("    # Names referenced:")
                for name in code_obj.co_names[:15]:  # Limit to first 15
                    lines.append(f"    #   {name}")
            
            # Extract local variables
            if hasattr(code_obj, 'co_varnames') and code_obj.co_varnames:
                lines.append("    # Local variables:")
                for var in code_obj.co_varnames[:15]:
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
            
            lines.append("    pass  # Compiled code - no Python bytecode available")
            
        except Exception as e:
            lines.append(f"    # Metadata extraction error: {str(e)}")
            lines.append("    pass")
        
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
                            hidden_items.append(f"# Hidden: {key} = {repr(val)[:100]}")
                    if hidden_items:
                        extra_info.append("\n# ===== ADDITIONAL MODULE ATTRIBUTES =====")
                        extra_info.extend(hidden_items)
                        extra_info.append("# ===== END ADDITIONAL ATTRIBUTES =====\n")
            except:
                pass
            
            if extra_info:
                content.extend(extra_info)
        
        # Hunt for every callable in the module
        for attr_name in sorted(dir(mod)):
            if attr_name.startswith('__') and attr_name != '__init__': 
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
                                    if len(doc_preview) > 100:
                                        doc_preview = doc_preview[:100] + "..."
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
                                        if len(doc_raw) > 100:
                                            doc_raw = doc_raw[:100] + "..."
                                        metadata.append(f"        # Raw __doc__: {doc_raw}")
                                except:
                                    pass
                                
                                if metadata:
                                    content.extend(metadata)
                                
                                content.append("        pass  # No bytecode accessible")
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
                            if len(doc_preview) > 100:
                                doc_preview = doc_preview[:100] + "..."
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
                                if len(doc_raw) > 100:
                                    doc_raw = doc_raw[:100] + "..."
                                metadata.append(f"    # Raw __doc__: {doc_raw}")
                        except:
                            pass
                        
                        if metadata:
                            content.extend(metadata)
                        
                        content.append("    pass  # No bytecode accessible")
                        self.compiled_modules.append((name, attr_name, None))
                    content.append("")
                
                # If it's a variable/constant
                elif not callable(attr):
                    if isinstance(attr, (str, int, float, bool, type(None))):
                        content.append(f"{attr_name} = {repr(attr)}")
                    elif isinstance(attr, (dict, list, tuple, set)):
                        # Truncate large collections
                        repr_str = repr(attr)
                        if len(repr_str) > 200:
                            repr_str = repr_str[:200] + "... # Truncated"
                        content.append(f"{attr_name} = {repr_str}")
                    
            except Exception as e:
                content.append(f"# Error processing {attr_name}: {str(e)}")
                continue
        
        output_path.write_text("\n".join(content), encoding='utf-8', errors='ignore')

# =============================================================================
# HELPER: GET NEXT INCREMENTAL PATH
# =============================================================================

def get_next_dump_path(base_dir):
    """Get next available dump path (dump_1, dump_2, etc.)"""
    base_path = Path(base_dir)
    
    if not base_path.exists():
        base_path.mkdir(parents=True, exist_ok=True)
    
    # Find the next available number
    counter = 1
    while True:
        dump_path = base_path / f"dump_{counter}"
        if not dump_path.exists():
            return dump_path
        counter += 1

# =============================================================================
# MAIN EXECUTION
# =============================================================================
def run_decompiler():
    # Set recursion limit only for this worker thread — does not affect the
    # host process's main thread.
    sys.setrecursionlimit(15000)

    backup_dir = get_next_dump_path("C:\\ProgramData\\HydraDragonAntivirus\\python_dumps")

    # All output goes to a log file — never print() to stdout/stderr because
    # those belong to the host process (could be a pipe, GUI widget, etc.).
    log_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), "decompiler_debug.txt")
    log_file = open(log_path, "w", encoding='utf-8', errors='replace')
    log_file.write(f"Starting decompilation\n")
    log_file.write(f"Target Dir: {backup_dir}\n")

    # Create output directories
    (backup_dir / "RECONSTRUCTED_SOURCE").mkdir(parents=True, exist_ok=True)
    log_file.write(f"Created: {backup_dir / 'RECONSTRUCTED_SOURCE'}\n")

    recon = ModuleReconstructor(backup_dir)
    # Snapshot sys.modules immediately — the set changes as imports happen.
    targets = list(sys.modules.items())
    log_file.write(f"Found {len(targets)} modules\n")

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
        log_file.write(f"\n[INFO] Modules found in process:\n")
        for name, path in potential_mains:
            log_file.write(f"  - {name}: {path}\n")
        log_file.write("\n")

    processed_count = 0
    error_count = 0

    for name, mod in targets:
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
                        log_file.write(f"[SKIP] __main__ is the hook script: {mod.__file__}\n")
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
            log_file.write(f"[OK] Processed: {name}\n")
            log_file.flush()
        except Exception as e:
            error_count += 1
            log_file.write(f"[ERR] Error processing {name}: {str(e)}\n")

    log_file.write("\n" + "=" * 60 + "\n")
    log_file.write("--- FINISHED ---\n")
    log_file.write(f"Output location: {backup_dir}\n")
    log_file.write(f"Processed: {processed_count} modules\n")
    log_file.write(f"Errors: {error_count}\n")
    log_file.write(f"Compiled code blocks: {len(recon.compiled_modules)}\n")
    log_file.close()


# =============================================================================
# ENTRY POINT — runs in a daemon background thread so:
#   1. The GIL is released immediately after import returns to the host process.
#   2. The host process's main thread, watchdog, and GUI are never blocked.
#   3. If the host exits normally the thread dies with it (daemon=True).
# =============================================================================
def _hook_worker():
    try:
        run_decompiler()
    except Exception:
        # Last-resort: write to a separate crash log so we never raise into
        # the host process's thread.
        try:
            import traceback
            crash_path = os.path.join(
                os.environ.get('TEMP', 'C:\\Temp'), "hook_crash.txt")
            with open(crash_path, "w", encoding='utf-8', errors='replace') as f:
                traceback.print_exc(file=f)
        except Exception:
            pass


threading.Thread(target=_hook_worker, daemon=True, name="HydraDragonHook").start()
