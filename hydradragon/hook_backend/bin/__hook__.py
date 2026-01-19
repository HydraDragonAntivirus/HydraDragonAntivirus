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
import gc
import types
import threading
import struct
import importlib.util
import inspect
import dis
from queue import Queue
from pathlib import Path

# =============================================================================
# GOD MODE CONFIG
# =============================================================================
sys.setrecursionlimit(15000)
MAX_WORKER_THREADS = 64

# =============================================================================
# ENGINE: THE PSEUDO-DECOMPILER (Instruction-to-Source)
# =============================================================================

class GodModeDecompiler:
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
                        # If the next op is POP_TOP, it's a statement
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
                return "    # [Decompiler] Complex logic detected. See .pyc for raw analysis.\n    pass"
                
            return "\n".join(lines)
        except Exception as e:
            return f"    # Decompilation Error: {str(e)}\n    pass"

# =============================================================================
# ENGINE: MODULE RECONSTRUCTOR
# =============================================================================

class ModuleReconstructor:
    def __init__(self, backup_dir):
        self.backup_dir = backup_dir
        self.decompiler = GodModeDecompiler()

    def process_module(self, name, mod):
        safe_name = name.replace('.', '_')
        output_path = self.backup_dir / "RECONSTRUCTED_SOURCE" / f"{safe_name}.py"
        
        content = [f'"""\nGOD MODE RECONSTRUCTION: {name}\nType: {type(mod)}\n"""\n']
        
        # 1. Hunt for every callable in the module
        for attr_name in list(dir(mod)):
            if attr_name.startswith('__') and attr_name != '__init__': continue
            try:
                attr = getattr(mod, attr_name)
                
                # If it's a Class
                if inspect.isclass(attr):
                    content.append(f"\nclass {attr_name}:")
                    for m_name in list(dir(attr)):
                        m_attr = getattr(attr, m_name)
                        if hasattr(m_attr, '__code__'):
                            content.append(f"  def {m_name}(self, *args, **kwargs):")
                            content.append(self.decompiler.decompile_code(m_attr.__code__))
                
                # If it's a Function
                elif hasattr(attr, '__code__'):
                    content.append(f"\ndef {attr_name}(*args, **kwargs):")
                    content.append(self.decompiler.decompile_code(attr.__code__))
                
                # If it's a variable/constant
                elif not callable(attr):
                    if isinstance(attr, (str, int, float, dict, list)):
                        content.append(f"{attr_name} = {repr(attr)}")
            except:
                continue
        
        output_path.write_text("\n".join(content), encoding='utf-8', errors='ignore')

        # 2. Also save the PYC (Standard Bytecode)
        self.save_pyc(name, mod)

    def save_pyc(self, name, mod):
        try:
            pyc_path = self.backup_dir / "RAW_BYTECODE" / f"{name.replace('.', '_')}.pyc"
            code = None
            if hasattr(mod, '__code__'): code = mod.__code__
            else:
                # Try to find the module's main code object
                for n in list(dir(mod)):
                    a = getattr(mod, n, None)
                    if hasattr(a, '__code__'):
                        code = a.__code__; break
            
            if code:
                with open(pyc_path, 'wb') as f:
                    f.write(importlib.util.MAGIC_NUMBER)
                    f.write(struct.pack('<I', int(time.time())))
                    if sys.version_info >= (3, 7): f.write(struct.pack('<I', 0))
                    f.write(marshal.dumps(code))
        except: pass

# =============================================================================
# MAIN EXECUTION
# =============================================================================
def god_mode_run():
    import ctypes
    import datetime
    import os
    
    # --- DEBUG: POPUP TO PROVE IT STARTED ---
    ctypes.windll.user32.MessageBoxW(0, "Python Hook actually started!", "Hydra God Mode", 0x40)
    
    try:
        ts = datetime.datetime.now().strftime("%H%M%S")
        backup_dir = Path(r"C:\pythondumps") / f"GOD_MODE_{ts}"
        
        # --- DEBUG: LOG FILE ---
        # We write to a file because we can't see 'print'
        log_file = open(os.path.join(os.environ['TEMP'], "hydra_debug.txt"), "w")
        log_file.write(f"Starting dump at {ts}\n")
        log_file.write(f"Target Dir: {backup_dir}\n")

        # Create directories
        for d in ["RECONSTRUCTED_SOURCE", "RAW_BYTECODE", "STRUCTURE"]:
            p = backup_dir / d
            p.mkdir(parents=True, exist_ok=True)
            log_file.write(f"Created: {p}\n")
        
        recon = ModuleReconstructor(backup_dir)
        targets = list(sys.modules.items())
        log_file.write(f"Found {len(targets)} modules\n")

        for name, mod in targets:
            if not mod or name in sys.builtin_module_names: continue
            if name == '__hook__': continue 
            
            try:
                recon.process_module(name, mod)
                # Periodically flush log so we see progress
                log_file.write(f"Processed: {name}\n")
                log_file.flush()
            except Exception as e:
                log_file.write(f"Error processing {name}: {str(e)}\n")

        log_file.write("--- FINISHED ---\n")
        log_file.close()
        
        ctypes.windll.user32.MessageBoxW(0, f"Dumping Finished!\nSaved to: {backup_dir}", "Hydra Success", 0x40)

    except Exception as e:
        # If the whole thing crashes, show us why!
        ctypes.windll.user32.MessageBoxW(0, f"CRITICAL ERROR:\n{str(e)}", "Hydra Failure", 0x10)

god_mode_run()