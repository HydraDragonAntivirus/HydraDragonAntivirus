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

import time
import marshal
import struct
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
        
        lines = []
        try:
            instructions = list(dis.get_instructions(code_obj))
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
                return "    # Complex logic detected. See .pyc for raw bytecode.\n    pass"
                
            return "\n".join(lines)
        except Exception as e:
            return f"    # Decompilation Error: {str(e)}\n    pass"

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
                    args = code.co_varnames[:code.co_argcount]
                    return f"({', '.join(args)})"
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

    def process_module(self, name, mod):
        safe_name = name.replace('.', '_')
        output_path = self.backup_dir / "RECONSTRUCTED_SOURCE" / f"{safe_name}.py"
        
        content = [f'"""\nModule: {name}\nType: {type(mod)}\n"""\n']
        
        # Add module docstring if exists
        mod_doc = self.sig_extractor.get_docstring(mod)
        if mod_doc:
            content.append(mod_doc)
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
                    import importlib.util
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
        
        # Hunt for every callable in the module
        for attr_name in sorted(dir(mod)):
            if attr_name.startswith('__') and attr_name != '__init__': 
                continue
            try:
                attr = getattr(mod, attr_name)
                
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
                            if hasattr(m_attr, '__code__') or callable(m_attr):
                                # Get signature
                                sig = self.sig_extractor.get_signature(m_attr)
                                content.append(f"    def {m_name}{sig}:")
                                
                                # Get docstring
                                m_doc = self.sig_extractor.get_docstring(m_attr)
                                if m_doc:
                                    content.append(m_doc)
                                
                                # Add decompiled code
                                if hasattr(m_attr, '__code__'):
                                    decompiled = self.decompiler.decompile_code(m_attr.__code__)
                                    if not m_doc or "pass" not in decompiled:
                                        content.append(decompiled)
                                else:
                                    content.append("        pass  # Compiled/builtin method")
                                content.append("")
                        except:
                            continue
                
                # If it's a Function
                elif hasattr(attr, '__code__') or callable(attr):
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
                    
                    # Add decompiled code
                    if hasattr(attr, '__code__'):
                        decompiled = self.decompiler.decompile_code(attr.__code__)
                        content.append(decompiled)
                    else:
                        content.append("    pass  # Compiled/builtin function")
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

        # Also save the PYC (Standard Bytecode)
        self.save_pyc(name, mod)

    def save_pyc(self, name, mod):
        try:
            pyc_path = self.backup_dir / "RAW_BYTECODE" / f"{name.replace('.', '_')}.pyc"
            code = None
            
            # Priority 1: Try to get module-level code from loader
            if hasattr(mod, '__loader__') and hasattr(mod.__loader__, 'get_code'):
                try:
                    code = mod.__loader__.get_code(name)
                except:
                    pass
            
            # Priority 2: Check if module itself has __code__
            if not code and hasattr(mod, '__code__'): 
                code = mod.__code__
            
            # Priority 3: Find any code object in the module
            if not code:
                for n in list(dir(mod)):
                    a = getattr(mod, n, None)
                    if hasattr(a, '__code__'):
                        code = a.__code__
                        break
            
            if code:
                with open(pyc_path, 'wb') as f:
                    f.write(importlib.util.MAGIC_NUMBER)
                    f.write(struct.pack('<I', int(time.time())))
                    if sys.version_info >= (3, 7): 
                        f.write(struct.pack('<I', 0))
                    f.write(marshal.dumps(code))
        except: 
            pass

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
    backup_dir = get_next_dump_path(r"C:\pythondumps")
    
    # Debug log file with UTF-8 encoding
    log_file = open(os.path.join(os.environ.get('TEMP', '/tmp'), "decompiler_debug.txt"), "w", encoding='utf-8', errors='replace')
    log_file.write(f"Starting decompilation\n")
    log_file.write(f"Target Dir: {backup_dir}\n")

    # Create directories
    for d in ["RECONSTRUCTED_SOURCE", "RAW_BYTECODE", "STRUCTURE"]:
        p = backup_dir / d
        p.mkdir(parents=True, exist_ok=True)
        log_file.write(f"Created: {p}\n")
    
    recon = ModuleReconstructor(backup_dir)
    targets = list(sys.modules.items())
    log_file.write(f"Found {len(targets)} modules\n")

    processed_count = 0
    error_count = 0
    
    for name, mod in targets:
        if not mod or name in sys.builtin_module_names: 
            continue
        if name == '__hook__': 
            continue 
        
        try:
            recon.process_module(name, mod)
            processed_count += 1
            log_file.write(f"[OK] Processed: {name}\n")
            log_file.flush()
        except Exception as e:
            error_count += 1
            log_file.write(f"[ERR] Error processing {name}: {str(e)}\n")

    log_file.write("\n" + "="*60 + "\n")
    log_file.write("--- FINISHED ---\n")
    log_file.write(f"Output location: {backup_dir}\n")
    log_file.write(f"Processed: {processed_count} modules\n")
    log_file.write(f"Errors: {error_count}\n")
    log_file.close()
    
    print(f"[SUCCESS] Decompilation complete: {backup_dir}")
    print(f"[STATS] Processed: {processed_count} | Errors: {error_count}")
        
run_decompiler()
