#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os

# Get the directory where this script is located
current_dir = os.path.dirname(os.path.abspath(__file__))

# Add it to sys.path so 'import other_script' works
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

print(f"[HOOK] Bootstrap complete. Path added: {current_dir}")

import importlib.util
import inspect
import dis
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================
sys.setrecursionlimit(15000)
MAX_WORKER_THREADS = 64

# =============================================================================
# BYTECODE DECOMPILER
# =============================================================================

class BytecodeDecompiler:
    """Reconstructs Python Source from Raw Bytecode Instructions"""
    
    @staticmethod
    def decompile_code(code_obj):
        if not code_obj or not hasattr(code_obj, 'co_code'):
            return "    pass  # No bytecode found"
        
        # Check if this is compiled/Nuitka code (empty or minimal bytecode)
        if len(code_obj.co_code) < 4:
            return BytecodeDecompiler.extract_compiled_metadata(code_obj)
        
        lines = []
        try:
            instructions = list(dis.get_instructions(code_obj))
            
            # If very few instructions, it's likely compiled
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

    def generate_compiled_report(self):
        """Generate a report of all compiled modules found"""
        if not self.compiled_modules:
            return
        
        report_path = self.backup_dir / "COMPILED_MODULES_REPORT.txt"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("COMPILED MODULES DETECTED (Nuitka/PyInstaller/etc.)\n")
            f.write("=" * 80 + "\n\n")
            f.write("These modules contain compiled code with no Python bytecode.\n")
            f.write("Metadata has been extracted where possible.\n\n")
            f.write(f"Total compiled functions/methods: {len(self.compiled_modules)}\n\n")
            
            # Group by module
            by_module = {}
            for mod_name, func_name, method_name in self.compiled_modules:
                if mod_name not in by_module:
                    by_module[mod_name] = []
                if method_name:
                    by_module[mod_name].append(f"  - {func_name}.{method_name}")
                else:
                    by_module[mod_name].append(f"  - {func_name}")
            
            f.write("-" * 80 + "\n")
            for mod_name, items in sorted(by_module.items()):
                f.write(f"\nModule: {mod_name}\n")
                for item in items:
                    f.write(item + "\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("NOTE: Check RECONSTRUCTED_SOURCE files for extracted metadata\n")
            f.write("      (constants, variable names, argument counts, etc.)\n")
            f.write("=" * 80 + "\n")
            
            # Add special note about __main__
            if '__main__' in by_module:
                f.write("\n" + "=" * 80 + "\n")
                f.write("IMPORTANT: __main__.py Analysis\n")
                f.write("=" * 80 + "\n\n")
                f.write("__main__.py is your Nuitka-compiled application.\n")
                f.write("Nuitka compiled the Python source code to C, then to machine code.\n\n")
                f.write("WHAT WE RECOVERED:\n")
                f.write("  ✓ Class names and structure\n")
                f.write("  ✓ Function/method names\n")
                f.write("  ✓ Parameter signatures (names, counts)\n")
                f.write("  ✓ Module-level variables and constants\n")
                f.write("  ✓ Docstrings (if any)\n\n")
                f.write("WHAT IS LOST (compiled to C):\n")
                f.write("  ✗ Function logic/implementation\n")
                f.write("  ✗ Control flow (if/else/loops)\n")
                f.write("  ✗ Calculations and algorithms\n")
                f.write("  ✗ Internal function calls\n\n")
                f.write("To recover the actual logic, you would need to:\n")
                f.write("  - Reverse engineer the compiled C code\n")
                f.write("  - Use a C/assembly decompiler like Ghidra or IDA Pro\n")
                f.write("  - Analyze the machine code in the .exe file\n")
                f.write("=" * 80 + "\n")

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
    # Use incremental path instead of timestamp
    backup_dir = get_next_dump_path("C:\\ProgramData\\HydraDragonAntivirus\\pythondumps")
    
    # Debug log file with UTF-8 encoding
    log_file = open(os.path.join(os.environ.get('TEMP', '/tmp'), "decompiler_debug.txt"), "w", encoding='utf-8', errors='replace')
    log_file.write(f"Starting decompilation\n")
    log_file.write(f"Target Dir: {backup_dir}\n")

    # Create directories
    for d in ["RECONSTRUCTED_SOURCE"]:
        p = backup_dir / d
        p.mkdir(parents=True, exist_ok=True)
        log_file.write(f"Created: {p}\n")
    
    recon = ModuleReconstructor(backup_dir)
    targets = list(sys.modules.items())
    log_file.write(f"Found {len(targets)} modules\n")
    
    # Try to identify the real application entry point
    potential_mains = []
    stdlib_names = {
        'inspect', 'os', 'sys', 'io', 're', 'collections', 'itertools', 'functools',
        'types', 'typing', 'pathlib', 'json', 'pickle', 'struct', 'enum', 'abc',
        'contextlib', 'warnings', 'weakref', 'copy', 'math', 'random', 'time',
        'datetime', 'hashlib', 'hmac', 'secrets', 'uuid', 'base64', 'binascii',
        'codecs', 'locale', 'gettext', 'string', 'textwrap', 'unicodedata',
        'stringprep', 'difflib', 'pprint', 'reprlib', 'traceback', 'gc', 'sysconfig'
    }
    
    for name, mod in targets:
        if not mod or not hasattr(mod, '__file__') or not mod.__file__:
            continue
        file_path = mod.__file__
        
        # __main__ is the primary entry point (if it's not the hook)
        if name == '__main__':
            if '__hook__' not in file_path and 'hook_backend' not in file_path:
                potential_mains.append((name, file_path))
        # Skip known stdlib modules even if bundled by Nuitka
        elif name in stdlib_names or name.split('.')[0] in stdlib_names:
            continue
        # Look for other non-stdlib, non-site-packages modules
        elif ('site-packages' not in file_path and 
              'lib\\python' not in file_path and 
              'lib/python' not in file_path and
              '__hook__' not in file_path and
              file_path.endswith('.py')):
            potential_mains.append((name, file_path))
    
    if potential_mains:
        log_file.write(f"\n[INFO] Potential application modules found:\n")
        for name, path in potential_mains:
            log_file.write(f"  - {name}: {path}\n")
        log_file.write("\n")

    processed_count = 0
    error_count = 0
    compiled_count = 0
    
    for name, mod in targets:
        if not mod or name in sys.builtin_module_names: 
            continue
        if name == '__hook__': 
            continue
        
        # Skip __main__ if it's the hook script itself
        if name == '__main__':
            try:
                if hasattr(mod, '__file__') and mod.__file__:
                    # Check if __main__ is this hook script
                    if '__hook__' in mod.__file__ or 'hook_backend' in mod.__file__:
                        log_file.write(f"[SKIP] Skipping __main__ (is hook script): {mod.__file__}\n")
                        continue
            except:
                pass
        
        try:
            # Check if this is a potential main application module
            is_potential_main = False
            if hasattr(mod, '__file__') and mod.__file__:
                file_path = mod.__file__
                
                # Known stdlib modules list
                stdlib_names = {
                    'inspect', 'os', 'sys', 'io', 're', 'collections', 'itertools', 'functools',
                    'types', 'typing', 'pathlib', 'json', 'pickle', 'struct', 'enum', 'abc',
                    'contextlib', 'warnings', 'weakref', 'copy', 'math', 'random', 'time',
                    'datetime', 'hashlib', 'hmac', 'secrets', 'uuid', 'base64', 'binascii',
                    'codecs', 'locale', 'gettext', 'string', 'textwrap', 'unicodedata',
                    'stringprep', 'difflib', 'pprint', 'reprlib', 'traceback', 'gc', 'sysconfig'
                }
                
                # __main__ is the entry point (unless it's the hook script)
                if name == '__main__':
                    if '__hook__' not in file_path and 'hook_backend' not in file_path:
                        is_potential_main = True
                # Skip stdlib even if bundled by Nuitka
                elif name in stdlib_names or name.split('.')[0] in stdlib_names:
                    is_potential_main = False
                # Also mark non-stdlib user modules
                elif ('site-packages' not in file_path and 
                      'lib\\python' not in file_path and 
                      'lib/python' not in file_path and
                      '__hook__' not in file_path and
                      file_path.endswith('.py')):
                    is_potential_main = True
            
            recon.process_module(name, mod, is_potential_main)
            processed_count += 1
            
            # Track if this module had compiled code
            if name == '__main__' or is_potential_main:
                print(f"[INFO] Processed entry point: {name}")
            
            log_file.write(f"[OK] Processed: {name}\n")
            log_file.flush()
        except Exception as e:
            error_count += 1
            log_file.write(f"[ERR] Error processing {name}: {str(e)}\n")

    # Generate compiled modules report
    recon.generate_compiled_report()

    log_file.write("\n" + "="*60 + "\n")
    log_file.write("--- FINISHED ---\n")
    log_file.write(f"Output location: {backup_dir}\n")
    log_file.write(f"Processed: {processed_count} modules\n")
    log_file.write(f"Errors: {error_count}\n")
    log_file.write(f"Compiled code blocks: {len(recon.compiled_modules)}\n")
    log_file.close()
    
    print(f"[SUCCESS] Decompilation complete: {backup_dir}")
    print(f"[STATS] Processed: {processed_count} | Errors: {error_count} | Compiled: {len(recon.compiled_modules)}")
        
run_decompiler()
