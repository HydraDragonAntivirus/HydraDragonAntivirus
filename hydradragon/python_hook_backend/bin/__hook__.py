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
HYDRADRAGON_DUMPER_PIPE = r"\\.\pipe\HydraDragonDumper"
PYTHON_DUMPS_DIR = r"C:\ProgramData\HydraDragonAntivirus\hydradragon\python_dumps"


def notify_hydradragon_dump_receiver_async(source_paths):
    """Best-effort notification to Owlyshield; never block the hooked process."""
    paths = [str(path) for path in source_paths]
    if not paths:
        return 0

    def _worker():
        for source_path in paths:
            try:
                with open(HYDRADRAGON_DUMPER_PIPE, "w", encoding="utf-8", errors="ignore") as pipe:
                    pipe.write(f"PYTHON_HOOK|{source_path}")
            except Exception:
                pass
            time.sleep(0.05)

    try:
        threading.Thread(
            target=_worker,
            daemon=True,
            name="HydraDragonDumpNotify",
        ).start()
    except Exception:
        return 0

    return len(paths)

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

                if op == "LOAD_CONST":
                    stack.append(repr(arg))
                elif op in ("LOAD_FAST", "LOAD_GLOBAL", "LOAD_NAME"):
                    stack.append(str(arg))
                elif op == "LOAD_ATTR":
                    if stack:
                        obj = stack.pop()
                        stack.append(f"{obj}.{arg}")
                elif "CALL" in op:
                    args_count = instr.arg
                    args = []
                    for _ in range(args_count):
                        if stack:
                            args.insert(0, stack.pop())
                    if stack:
                        func = stack.pop()
                        call_str = f"{func}({', '.join(args)})"
                        lines.append(f"    {call_str}")
                        stack.append(call_str)
                elif op == "STORE_FAST" or op == "STORE_NAME":
                    if stack:
                        val = stack.pop()
                        lines.append(f"    {arg} = {val}")
                elif op == "RETURN_VALUE":
                    if stack:
                        val = stack.pop()
                        if val != "None":
                            lines.append(f"    return {val}")

            if not lines:
                return "    # Complex logic detected.\n    pass"

            return "\n".join(lines)
        except Exception:
            return BytecodeDecompiler.extract_compiled_metadata(code_obj)

    @staticmethod
    def extract_compiled_metadata(code_obj):
        """Extract metadata from compiled/Nuitka code objects"""
        lines = ["    # COMPILED CODE - Metadata extraction:"]

        try:
            # Extract constants
            if hasattr(code_obj, "co_consts") and code_obj.co_consts:
                consts = [c for c in code_obj.co_consts if c is not None and not callable(c)]
                if consts:
                    lines.append("    # Constants found:")
                    for const in consts:
                        lines.append(f"    #   {repr(const)}")

            # Extract variable names
            if hasattr(code_obj, "co_names") and code_obj.co_names:
                lines.append("    # Names referenced:")
                for name in code_obj.co_names:
                    lines.append(f"    #   {name}")

            # Extract local variables
            if hasattr(code_obj, "co_varnames") and code_obj.co_varnames:
                lines.append("    # Local variables:")
                for var in code_obj.co_varnames:
                    lines.append(f"    #   {var}")

            # Extract free variables (closures)
            if hasattr(code_obj, "co_freevars") and code_obj.co_freevars:
                lines.append("    # Free variables (closures):")
                for fv in code_obj.co_freevars:
                    lines.append(f"    #   {fv}")

            # Extract cell variables
            if hasattr(code_obj, "co_cellvars") and code_obj.co_cellvars:
                lines.append("    # Cell variables:")
                for cv in code_obj.co_cellvars:
                    lines.append(f"    #   {cv}")

            # Code object info
            if hasattr(code_obj, "co_argcount"):
                lines.append(f"    # Argument count: {code_obj.co_argcount}")
            if hasattr(code_obj, "co_kwonlyargcount"):
                lines.append(f"    # Keyword-only args: {code_obj.co_kwonlyargcount}")
            if hasattr(code_obj, "co_nlocals"):
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
                if hasattr(func, "__code__"):
                    code = func.__code__
                    argcount = code.co_argcount
                    kwonlyargcount = getattr(code, "co_kwonlyargcount", 0)
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
                lines = doc.split("\n")
                if len(lines) == 1:
                    return f'    """{doc}"""'
                else:
                    formatted = ['    """']
                    formatted.extend([f"    {line}" for line in lines])
                    formatted.append('    """')
                    return "\n".join(formatted)
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
        safe_name = name.replace(".", "_")
        output_path = self.backup_dir / "RECONSTRUCTED_SOURCE" / f"{safe_name}.py"

        content = [f'"""\nModule: {name}\nType: {type(mod)}\n']

        if is_potential_main:
            if name == "__main__":
                content.append("=" * 70 + "\n")
                content.append("*** APPLICATION ENTRY POINT (__main__) ***\n")
                content.append("=" * 70 + "\n")
            else:
                content.append("*** POTENTIAL APPLICATION MODULE ***\n")

        if hasattr(mod, "__file__"):
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
            if hasattr(mod, "__compiled__"):
                nuitka_info.append("# NUITKA COMPILED MODULE")
            if hasattr(mod, "__nuitka_version__"):
                nuitka_info.append(f"# Nuitka version: {mod.__nuitka_version__}")
            if hasattr(mod, "__package__"):
                nuitka_info.append(f"# Package: {mod.__package__}")
            if hasattr(mod, "__spec__") and mod.__spec__:
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
            if hasattr(mod, "__loader__") and hasattr(mod.__loader__, "get_code"):
                try:
                    module_code = mod.__loader__.get_code(name)
                except:
                    pass

            # Method 2: Search for code object in module's compiled file
            if not module_code and hasattr(mod, "__file__"):
                try:
                    spec = importlib.util.find_spec(name) if name != "__main__" else None
                    if spec and hasattr(spec, "loader"):
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
        if name == "__main__":
            extra_info = []
            try:
                # Check for __dict__ items we might have missed
                if hasattr(mod, "__dict__"):
                    hidden_items = []
                    for key, val in mod.__dict__.items():
                        # Look for non-standard attributes
                        if not key.startswith("_") and key not in dir(mod):
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
        _HOOK_INJECTED_VARS = frozenset(
            {
                "hook_globals",
                "env_hook",
                "exe_dir",
                "dlls_dir",
                "lib_dir",
                "pythonhome",
                "site_packages",
                "path",
            }
        )

        # Hunt for every callable in the module
        for attr_name in sorted(dir(mod)):
            if attr_name.startswith("__") and attr_name != "__init__":
                continue

            # Strip hook-injected runtime vars from __main__ — they are not part
            # of the original application source and would corrupt the merged output.
            if name == "__main__" and attr_name in _HOOK_INJECTED_VARS:
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
                        if m_name.startswith("__") and m_name not in ["__init__", "__call__"]:
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
                            except (RuntimeError, AttributeError, Exception):
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
                                    doc_preview = m_doc.replace("\n", " ").replace('    """', "").replace('"""', "").strip()
                                    metadata.append(f"        # Docstring: {doc_preview}")

                                # Method 1: Try inspect.signature
                                try:
                                    sig = inspect.signature(m_attr)
                                    metadata.append(f"        # Signature: {sig}")
                                except:
                                    pass

                                # Method 2: Check for __annotations__
                                try:
                                    if hasattr(m_attr, "__annotations__") and m_attr.__annotations__:
                                        metadata.append(f"        # Annotations: {m_attr.__annotations__}")
                                except:
                                    pass

                                # Method 3: Check for __defaults__
                                try:
                                    if hasattr(m_attr, "__defaults__") and m_attr.__defaults__:
                                        metadata.append(f"        # Defaults: {m_attr.__defaults__}")
                                except:
                                    pass

                                # Method 4: Check for __kwdefaults__
                                try:
                                    if hasattr(m_attr, "__kwdefaults__") and m_attr.__kwdefaults__:
                                        metadata.append(f"        # Keyword defaults: {m_attr.__kwdefaults__}")
                                except:
                                    pass

                                # Method 5: Try __wrapped__ (for decorated functions)
                                try:
                                    if hasattr(m_attr, "__wrapped__"):
                                        metadata.append("        # Has __wrapped__ attribute")
                                except:
                                    pass

                                # Method 6: Try __doc__ directly as backup
                                try:
                                    if hasattr(m_attr, "__doc__") and m_attr.__doc__ and not m_doc:
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
                            doc_preview = func_doc.replace("\n", " ").replace('    """', "").replace('"""', "").strip()
                            metadata.append(f"    # Docstring: {doc_preview}")

                        # Method 1: Try inspect.signature
                        try:
                            sig = inspect.signature(attr)
                            metadata.append(f"    # Signature: {sig}")
                        except:
                            pass

                        # Method 2: Check for __annotations__
                        try:
                            if hasattr(attr, "__annotations__") and attr.__annotations__:
                                metadata.append(f"    # Annotations: {attr.__annotations__}")
                        except:
                            pass

                        # Method 3: Check for __defaults__
                        try:
                            if hasattr(attr, "__defaults__") and attr.__defaults__:
                                metadata.append(f"    # Defaults: {attr.__defaults__}")
                        except:
                            pass

                        # Method 4: Check for __kwdefaults__
                        try:
                            if hasattr(attr, "__kwdefaults__") and attr.__kwdefaults__:
                                metadata.append(f"    # Keyword defaults: {attr.__kwdefaults__}")
                        except:
                            pass

                        # Method 5: Try __wrapped__ (for decorated functions)
                        try:
                            if hasattr(attr, "__wrapped__"):
                                metadata.append("    # Has __wrapped__ attribute")
                        except:
                            pass

                        # Method 6: Try __doc__ directly as backup
                        try:
                            if hasattr(attr, "__doc__") and attr.__doc__ and not func_doc:
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

        output_path.write_text("\n".join(content), encoding="utf-8", errors="ignore")


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
        try:
            hook_log(f"[FROZEN] unavailable: {e}\n")
        except Exception:
            pass
        return 0

    def safe_name(name):
        return name.replace(".", "_").replace("<", "_").replace(">", "_").replace(":", "_").replace("\\", "_").replace("/", "_")

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
            for c in getattr(code_obj, "co_consts", ()):
                if isinstance(c, types.CodeType):
                    const_preview.append(f"<code {c.co_name}>")
                else:
                    r = repr(c)
                    if len(r) > 300:
                        r = r[:300] + "..."
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
        for c in getattr(code_obj, "co_consts", ()):
            if isinstance(c, types.CodeType):
                out.append(c)
                out.extend(nested_code_objects(c, seen))
        return out

    names = []
    try:
        getter = getattr(_imp, "_frozen_module_names", None)
        if getter:
            names = list(getter())
    except Exception as e:
        try:
            hook_log(f"[FROZEN] _frozen_module_names failed: {e}\n")
        except Exception:
            pass
        names = []

    # Also include frozen modules already visible in sys.modules. This does not
    # import anything; it only adds names that are already loaded.
    try:
        for name, mod in list(sys.modules.items()):
            try:
                spec = getattr(mod, "__spec__", None)
                origin = getattr(spec, "origin", None) if spec else None
                loader = getattr(spec, "loader", None) if spec else None
                loader_name = type(loader).__name__ if loader is not None else ""
                if origin == "frozen" or loader_name == "FrozenImporter" or _imp.is_frozen(name):
                    names.append(name)
            except Exception:
                pass
    except Exception:
        pass

    names = sorted(set(n for n in names if isinstance(n, str) and n))
    try:
        hook_log(f"[FROZEN] candidate names: {len(names)}\n")
        hook_log(f"[FROZEN] candidate names list: {names!r}\n")
    except Exception:
        pass

    frozen_dir = source_dir / "FROZEN_MODULES"
    try:
        frozen_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    dumped = 0
    for name in names:
        if name == "__hook__" or name.startswith("__hook__."):
            continue
        try:
            if not _imp.is_frozen(name):
                continue
        except Exception:
            pass
        try:
            code_obj = _imp.get_frozen_object(name)
        except Exception as e:
            try:
                hook_log(f"[FROZEN ERR] get_frozen_object({name!r}): {e}\n")
            except Exception:
                pass
            continue
        if not isinstance(code_obj, types.CodeType):
            try:
                hook_log(f"[FROZEN SKIP] {name}: object is {type(code_obj)}\n")
            except Exception:
                pass
            continue

        safe = safe_name(name)
        content = []
        content.append('"""')
        content.append(f"Frozen module: {name}")
        content.append("Source type: _imp frozen code object")
        content.append("Note: no original .py source is available through normal inspect/getsource.")
        content.append('"""')
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
            (frozen_dir / f"{safe}.py").write_text(data, encoding="utf-8", errors="replace")
            # Also create the normal top-level reconstructed file only if the
            # regular sys.modules pass did not already create one.
            top = source_dir / f"{safe}.py"
            if not top.exists():
                top.write_text(data, encoding="utf-8", errors="replace")
            dumped += 1
            try:
                hook_log(f"[FROZEN OK] Dumped frozen module: {name}\n")
            except Exception:
                pass
        except Exception as e:
            try:
                hook_log(f"[FROZEN ERR] write {name}: {e}\n")
            except Exception:
                pass

    try:
        hook_log(f"[FROZEN] dumped={dumped}\n")
    except Exception:
        pass
    return dumped


# =============================================================================
# LOCKED MODULE SPEC PROBE (NO IMPORT / NO TARGET NAMES)
# =============================================================================
def probe_locked_module_specs(module_names, recon, source_dir, hook_log):
    """Probe finder/spec/loader data for locked module names without importing.

    This is generic: it uses every current sys.meta_path finder and only calls
    find_spec/find_module plus optional loader get_source/get_code. It does not
    execute the module, does not force import it, does not parse __main__, and
    does not filter by target-name substrings. This is the useful layer when an
    import lock exists but sys.modules has no module object.
    """
    try:
        import types
        import dis as _dis
        import io as _io
    except Exception as e:
        try:
            hook_log(f"[SPEC_PROBE] unavailable: {e}\n")
        except Exception:
            pass
        return 0

    def safe_filename(name):
        return str(name).replace(".", "_").replace("<", "_").replace(">", "_").replace(":", "_").replace("\\", "_").replace("/", "_")

    def disassemble(code_obj):
        try:
            buf = _io.StringIO()
            _dis.dis(code_obj, file=buf)
            return buf.getvalue()
        except Exception as e:
            return f"<disassembly failed: {e}>\n"

    def code_metadata(code_obj, prefix="# "):
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
            for c in getattr(code_obj, "co_consts", ()):
                if isinstance(c, types.CodeType):
                    const_preview.append(f"<code {c.co_name}>")
                else:
                    r = repr(c)
                    if len(r) > 300:
                        r = r[:300] + "..."
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
        for c in getattr(code_obj, "co_consts", ()):
            if isinstance(c, types.CodeType):
                out.append(c)
                out.extend(nested_code_objects(c, seen))
        return out

    names = sorted(set(str(n) for n in (module_names or []) if isinstance(n, str) and n and n != "__hook__" and not n.startswith("__hook__.")))
    try:
        hook_log(f"[SPEC_PROBE] names={names!r}\n")
    except Exception:
        pass
    if not names:
        return 0

    spec_dir = source_dir / "LOCKED_MODULE_SPECS"
    try:
        spec_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    dumped = 0
    meta_path = []
    try:
        meta_path = list(sys.meta_path)
    except Exception:
        meta_path = []

    for name in names:
        if name in sys.modules and sys.modules.get(name) is not None:
            try:
                hook_log(f"[SPEC_PROBE SKIP] {name!r}: already in sys.modules\n")
            except Exception:
                pass
            continue

        finder_reports = []
        found_any = False
        wrote_any = False

        for idx, finder in enumerate(meta_path):
            finder_type = type(finder).__module__ + "." + type(finder).__name__
            spec = None
            err = None
            try:
                if hasattr(finder, "find_spec"):
                    spec = finder.find_spec(name, None, None)
                elif hasattr(finder, "find_module"):
                    loader = finder.find_module(name, None)
                    if loader is not None:
                        spec = type("LegacySpecRecord", (), {})()
                        spec.name = name
                        spec.loader = loader
                        spec.origin = getattr(loader, "path", None)
                        spec.has_location = bool(getattr(loader, "path", None))
                        spec.submodule_search_locations = None
            except BaseException as e:
                err = repr(e)

            loader = getattr(spec, "loader", None) if spec is not None else None
            origin = getattr(spec, "origin", None) if spec is not None else None
            has_location = getattr(spec, "has_location", None) if spec is not None else None
            subloc = getattr(spec, "submodule_search_locations", None) if spec is not None else None
            loader_type = (type(loader).__module__ + "." + type(loader).__name__) if loader is not None else None
            finder_reports.append(
                {
                    "index": idx,
                    "finder_type": finder_type,
                    "error": err,
                    "spec_found": spec is not None,
                    "origin": origin,
                    "has_location": has_location,
                    "submodule_search_locations": repr(subloc),
                    "loader_type": loader_type,
                    "loader_repr": repr(loader)[:500],
                }
            )

            try:
                hook_log(f"[SPEC_PROBE FINDER] name={name!r} idx={idx} finder={finder_type!r} found={spec is not None} origin={origin!r} loader={loader_type!r} err={err}\n")
            except Exception:
                pass

            if spec is None or loader is None:
                continue

            found_any = True
            source_text = None
            code_obj = None
            source_error = None
            code_error = None

            # get_source is passive for normal loaders. If the loader refuses,
            # keep the error in metadata.
            try:
                if hasattr(loader, "get_source"):
                    source_text = loader.get_source(name)
            except BaseException as e:
                source_error = repr(e)

            # get_code returns the code object without exec_module for normal
            # Python loaders, frozen loaders, and many custom importers.
            try:
                if hasattr(loader, "get_code"):
                    code_obj = loader.get_code(name)
            except BaseException as e:
                code_error = repr(e)

            content = []
            content.append('"""')
            content.append(f"Locked module spec probe: {name}")
            content.append("Source type: finder/spec/loader probe, no import execution")
            content.append(f"Finder: {finder_type}")
            content.append(f"Loader: {loader_type}")
            content.append(f"Origin: {origin!r}")
            content.append(f"Has location: {has_location!r}")
            content.append(f"Submodule search locations: {subloc!r}")
            content.append(f"get_source_error: {source_error!r}")
            content.append(f"get_code_error: {code_error!r}")
            content.append('"""')
            content.append("")

            if isinstance(source_text, str):
                content.append("# ===== LOADER GET_SOURCE RESULT =====")
                content.append(source_text)
                content.append("")
                wrote_any = True

            if isinstance(code_obj, types.CodeType):
                content.append("# ===== LOADER GET_CODE METADATA =====")
                content.append(code_metadata(code_obj))
                content.append("")
                content.append("# ===== BEST-EFFORT PSEUDO SOURCE =====")
                try:
                    content.append(recon.decompiler.decompile_code(code_obj))
                except Exception as e:
                    content.append(f"# decompile failed: {e}")
                    content.append("pass")
                content.append("")
                content.append("LOCKED_SPEC_DISASSEMBLY = " + repr(disassemble(code_obj)))
                nested = nested_code_objects(code_obj)
                if nested:
                    content.append("")
                    content.append("# ===== NESTED CODE OBJECTS =====")
                    for nidx, nested_code in enumerate(nested, 1):
                        content.append(f"\n# --- nested code object {nidx}: {nested_code.co_name} ---")
                        content.append(code_metadata(nested_code))
                        content.append("NESTED_DISASSEMBLY_%d = " % nidx + repr(disassemble(nested_code)))
                wrote_any = True

            if not wrote_any:
                content.append("# No source/code was returned by this loader.")
                content.append(f"SPEC_OBJECT_REPR = {repr(spec)!r}")
                content.append(f"LOADER_OBJECT_REPR = {repr(loader)!r}")
                # Pull non-callable/simple loader attributes for diagnostics.
                attrs = []
                try:
                    for attr_name in sorted(set(dir(loader))):
                        if attr_name.startswith("__"):
                            continue
                        try:
                            val = getattr(loader, attr_name)
                        except Exception as e:
                            attrs.append((attr_name, f"<error: {e}>"))
                            continue
                        if callable(val):
                            continue
                        r = repr(val)
                        if len(r) > 1000:
                            r = r[:1000] + "..."
                        attrs.append((attr_name, r))
                except Exception as e:
                    attrs.append(("<loader-dir-error>", repr(e)))
                content.append("LOADER_NONCALLABLE_ATTRS = " + repr(attrs))

            data = "\n".join(content)
            safe = safe_filename(name)
            out_path = spec_dir / f"{safe}.py"
            try:
                out_path.write_text(data, encoding="utf-8", errors="replace")
                top_path = source_dir / f"{safe}.py"
                if not top_path.exists() and wrote_any:
                    top_path.write_text(data, encoding="utf-8", errors="replace")
                dumped += 1
                try:
                    hook_log(f"[SPEC_PROBE OK] name={name!r} finder={finder_type!r} wrote={out_path} has_source={isinstance(source_text, str)} has_code={isinstance(code_obj, types.CodeType)}\n")
                except Exception:
                    pass
            except Exception as e:
                try:
                    hook_log(f"[SPEC_PROBE ERR] name={name!r} write failed: {e}\n")
                except Exception:
                    pass

            # One successful spec file is enough for this name. If it had no
            # code/source, continue to other finders in case a later finder can
            # provide more.
            if wrote_any:
                break

        if not found_any:
            # Write a report even when no finder knows this locked name.
            safe = safe_filename(name)
            try:
                report = []
                report.append('"""')
                report.append(f"Locked module spec probe: {name}")
                report.append("No sys.meta_path finder returned a spec.")
                report.append('"""')
                report.append("")
                report.append("FINDER_REPORTS = " + repr(finder_reports))
                (spec_dir / f"{safe}__NO_SPEC.txt").write_text("\n".join(report), encoding="utf-8", errors="replace")
                try:
                    hook_log(f"[SPEC_PROBE NO_SPEC] name={name!r}\n")
                except Exception:
                    pass
            except Exception as e:
                try:
                    hook_log(f"[SPEC_PROBE NO_SPEC_ERR] name={name!r}: {e}\n")
                except Exception:
                    pass

    try:
        hook_log(f"[SPEC_PROBE] dumped={dumped}\n")
    except Exception:
        pass
    return dumped


# =============================================================================
# IMPORT LOCK DIAGNOSTICS / FORCE UNLOCK
# =============================================================================
def _iter_import_module_locks():
    """Return [(name, lock_obj, weakref_or_obj)] for importlib's private module locks."""
    try:
        import importlib._bootstrap as _bootstrap

        locks = getattr(_bootstrap, "_module_locks", {})
        items = list(locks.items()) if hasattr(locks, "items") else []
    except Exception:
        return []

    out = []
    for name, ref in items:
        try:
            lock = ref() if callable(ref) else ref
        except Exception:
            lock = None
        out.append((str(name), lock, ref))
    return out


def log_import_module_locks(hook_log, label):
    """Generic module-lock report. No target-name matching and no waiting."""
    entries = _iter_import_module_locks()
    try:
        hook_log(f"[MODULE_LOCKS {label}] count={len(entries)}\n")
    except Exception:
        pass

    names = []
    for name, lock, ref in entries:
        names.append(name)
        try:
            in_sys = name in sys.modules
            mod = sys.modules.get(name)
            hook_log(
                f"[MODULE_LOCK {label}] name={name!r} "
                f"alive={lock is not None} "
                f"in_sys_modules={in_sys} "
                f"module_is_none={mod is None} "
                f"lock_type={type(lock).__name__ if lock is not None else None!r} "
                f"owner={getattr(lock, 'owner', None)!r} "
                f"count={getattr(lock, 'count', None)!r} "
                f"waiters={getattr(lock, 'waiters', None)!r}\n"
            )
        except Exception as e:
            try:
                hook_log(f"[MODULE_LOCK {label}] name={name!r} diagnostic failed: {e}\n")
            except Exception:
                pass
    return names


def force_unlock_import_module_locks(hook_log):
    """Force-clear importlib private module locks once, generically.

    This does not import any module and does not synthesize source. It only
    clears importlib._bootstrap._module_locks entries that exist at dump time.
    It is intentionally aggressive because the caller requested force unlock.
    """
    try:
        import importlib._bootstrap as _bootstrap
        import _thread

        locks = getattr(_bootstrap, "_module_locks", {})
        current_tid = _thread.get_ident()
    except Exception as e:
        try:
            hook_log(f"[MODULE_LOCK_FORCE] unavailable: {e}\n")
        except Exception:
            pass
        return 0

    if not hasattr(locks, "items"):
        try:
            hook_log("[MODULE_LOCK_FORCE] _module_locks is not dict-like\n")
        except Exception:
            pass
        return 0

    forced = 0
    for name, ref in list(locks.items()):
        name_s = str(name)
        if name_s == "__hook__" or name_s.startswith("__hook__."):
            continue

        try:
            lock = ref() if callable(ref) else ref
        except Exception:
            lock = None

        before_owner = getattr(lock, "owner", None) if lock is not None else None
        before_count = getattr(lock, "count", None) if lock is not None else None
        before_waiters = getattr(lock, "waiters", None) if lock is not None else None
        in_sys = name_s in sys.modules
        module_is_none = sys.modules.get(name_s) is None

        api_released = 0
        api_error = None
        direct_error = None
        wake_error = None
        pop_error = None

        # If this worker owns the lock, use the normal release path first.
        # Releasing a lock owned by a different thread normally raises, so the
        # requested force path below directly clears private fields too.
        try:
            if lock is not None and before_owner == current_tid:
                limit = int(before_count or 1) + 1
                for _ in range(max(1, min(limit, 100))):
                    try:
                        lock.release()
                        api_released += 1
                    except Exception as e:
                        api_error = repr(e)
                        break
        except Exception as e:
            api_error = repr(e)

        # Aggressive private-field clear. This is what actually breaks a stale
        # or foreign-thread lock; use only because this hook runs inside a dump.
        try:
            if lock is not None:
                try:
                    setattr(lock, "owner", None)
                except Exception:
                    pass
                try:
                    setattr(lock, "count", 0)
                except Exception:
                    pass
                try:
                    setattr(lock, "waiters", 0)
                except Exception:
                    pass
        except Exception as e:
            direct_error = repr(e)

        # Wake any waiters if the wakeup lock is currently locked.
        try:
            wakeup = getattr(lock, "wakeup", None) if lock is not None else None
            if wakeup is not None and hasattr(wakeup, "locked") and wakeup.locked():
                try:
                    wakeup.release()
                except Exception as e:
                    wake_error = repr(e)
        except Exception as e:
            wake_error = repr(e)

        try:
            try:
                locks.pop(name, None)
            except AttributeError:
                del locks[name]
            popped = True
        except Exception as e:
            popped = False
            pop_error = repr(e)

        forced += 1
        try:
            hook_log(
                f"[MODULE_LOCK_FORCE] name={name_s!r} "
                f"in_sys_modules={in_sys} module_is_none={module_is_none} "
                f"owner_before={before_owner!r} count_before={before_count!r} waiters_before={before_waiters!r} "
                f"api_released={api_released} popped={popped} "
                f"api_error={api_error} direct_error={direct_error} wake_error={wake_error} pop_error={pop_error}\n"
            )
        except Exception:
            pass

    try:
        hook_log(f"[MODULE_LOCK_FORCE] forced={forced}\n")
    except Exception:
        pass
    return forced


def process_new_sys_modules_once(recon, processed_names, hook_log):
    """One immediate rescan after lock clearing. No waiting and no imports."""
    processed = 0
    errors = 0
    for name, mod in list(sys.modules.items()):
        if name in processed_names:
            continue
        if not mod:
            continue
        if name == "__hook__" or str(name).startswith("__hook__."):
            continue
        if name == "__main__":
            try:
                if hasattr(mod, "__file__") and mod.__file__:
                    if "__hook__" in mod.__file__ or "hook_backend" in mod.__file__:
                        continue
            except Exception:
                pass
        is_potential_main = False
        try:
            if hasattr(mod, "__file__") and mod.__file__:
                file_path = mod.__file__
                if "__hook__" not in file_path and "hook_backend" not in file_path:
                    is_potential_main = name == "__main__"
        except Exception:
            pass
        try:
            recon.process_module(name, mod, is_potential_main)
            processed_names.add(name)
            processed += 1
            hook_log(f"[OK] Processed after unlock: {name}\n")
        except Exception as e:
            errors += 1
            try:
                hook_log(f"[ERR] Error processing after unlock {name}: {e}\n")
            except Exception:
                pass
    try:
        hook_log(f"[MODULE_RESCAN_AFTER_UNLOCK] processed={processed} errors={errors}\n")
    except Exception:
        pass
    return processed, errors


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

    dump_root = Path(PYTHON_DUMPS_DIR)
    backup_dir = get_next_dump_path(str(dump_root))
    source_dir = backup_dir / "RECONSTRUCTED_SOURCE"
    started_path = backup_dir / "started.txt"
    progress_path = backup_dir / "progress.txt"
    finished_path = backup_dir / "finished.txt"
    error_path = backup_dir / "error.txt"
    status_path = source_dir / "__dump_status__.txt"

    def write_marker(path: Path, text: str):
        try:
            path.write_text(text, encoding="utf-8", errors="replace")
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
            local=time.strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    write_marker(progress_path, "phase=bootstrap\n")
    write_marker(status_path, "status=started\n")

    # Keep the debug log beside the dump so the user can always find it.
    log_path = str(backup_dir / "decompiler_debug.txt")

    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as f:
            f.write("")
    except Exception:
        pass

    def hook_log(msg):
        # Open, Write, and Close instantly to prevent Windows file locking
        try:
            with open(log_path, "a", encoding="utf-8", errors="replace") as log_f:
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
            "phase=scanning\ncurrent=0/{total}\nprocessed=0\nerrors=0\n".format(total=total_targets),
        )

        # Identify the application entry point(s) for the report header —
        # __main__ that isn't the hook itself, or any non-hook module.
        potential_mains = []
        for name, mod in targets:
            if not mod or not hasattr(mod, "__file__") or not mod.__file__:
                continue
            file_path = mod.__file__
            if "__hook__" in file_path or "hook_backend" in file_path:
                continue
            potential_mains.append((name, file_path))

        if potential_mains:
            hook_log("\n[INFO] Modules found in process:\n")
            for name, path in potential_mains:
                hook_log(f"  - {name}: {path}\n")
            hook_log("\n")

        processed_count = 0
        error_count = 0
        processed_names = set()

        for idx, (name, mod) in enumerate(targets, 1):
            if idx == 1 or idx % 25 == 0 or idx == total_targets:
                progress_text = ("phase=processing\ncurrent={idx}/{total}\nmodule={name}\nprocessed={processed}\nerrors={errors}\n").format(
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
            if name == "__hook__":
                continue

            # Skip __main__ only if it literally IS the hook script
            if name == "__main__":
                try:
                    if hasattr(mod, "__file__") and mod.__file__:
                        if "__hook__" in mod.__file__ or "hook_backend" in mod.__file__:
                            hook_log(f"[SKIP] __main__ is the hook script: {mod.__file__}\n")
                            continue
                except Exception:
                    pass

            # is_potential_main: mark __main__ and any non-hook module that has a file
            is_potential_main = False
            if hasattr(mod, "__file__") and mod.__file__:
                file_path = mod.__file__
                if "__hook__" not in file_path and "hook_backend" not in file_path:
                    is_potential_main = name == "__main__"

            try:
                recon.process_module(name, mod, is_potential_main)
                processed_names.add(name)
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

        # Generic import-lock diagnostics and requested force-unlock pass.
        # No target-name matching, no waiting, no forced imports.
        locked_names_before_force = []
        spec_probe_dumped = 0
        try:
            locked_names_before_force = log_import_module_locks(hook_log, "BEFORE_FORCE")
        except Exception as e:
            try:
                hook_log(f"[MODULE_LOCKS BEFORE_FORCE] diagnostic failed: {e}\n")
            except Exception:
                pass

        try:
            spec_probe_dumped = probe_locked_module_specs(locked_names_before_force, recon, source_dir, hook_log)
        except Exception as e:
            error_count += 1
            try:
                hook_log(f"[SPEC_PROBE] crashed: {e}\n")
            except Exception:
                pass

        forced_locks = 0
        try:
            forced_locks = force_unlock_import_module_locks(hook_log)
        except Exception as e:
            error_count += 1
            try:
                hook_log(f"[MODULE_LOCK_FORCE] crashed: {e}\n")
            except Exception:
                pass

        try:
            log_import_module_locks(hook_log, "AFTER_FORCE")
        except Exception as e:
            try:
                hook_log(f"[MODULE_LOCKS AFTER_FORCE] diagnostic failed: {e}\n")
            except Exception:
                pass

        try:
            extra_processed, extra_errors = process_new_sys_modules_once(recon, processed_names, hook_log)
            processed_count += extra_processed
            error_count += extra_errors
        except Exception as e:
            error_count += 1
            try:
                hook_log(f"[MODULE_RESCAN_AFTER_UNLOCK] crashed: {e}\n")
            except Exception:
                pass

        # Generic final snapshots.  These intentionally report all names, not
        # a hard-coded target substring.
        try:
            module_names = sorted(str(name) for name in sys.modules.keys())
            hook_log(f"[FINAL CHECK] sys.modules count={len(module_names)}\n")
            hook_log(f"[FINAL CHECK] sys.modules names={module_names!r}\n")
        except Exception as e:
            try:
                hook_log(f"[FINAL CHECK] sys.modules diagnostic failed: {e}\n")
            except Exception:
                pass

        try:
            lock_names = log_import_module_locks(hook_log, "FINAL")
        except Exception as e:
            lock_names = []
            try:
                hook_log(f"[FINAL CHECK] final module-lock diagnostic failed: {e}\n")
            except Exception:
                pass

        try:
            import _imp

            for n in sorted(set(lock_names)):
                try:
                    hook_log(f"[FINAL CHECK] _imp.is_frozen({n!r})={_imp.is_frozen(n)}\n")
                except Exception as e:
                    hook_log(f"[FINAL CHECK] _imp.is_frozen({n!r}) failed: {e}\n")
        except Exception as e:
            try:
                hook_log(f"[FINAL CHECK] _imp diagnostic failed: {e}\n")
            except Exception:
                pass

        hook_log("\n" + "=" * 60 + "\n--- FINISHED ---\n")
        hook_log(f"Output location: {backup_dir}\n")
        hook_log(f"Processed: {processed_count} modules\nErrors: {error_count}\n")
        hook_log(f"Compiled code blocks: {len(recon.compiled_modules)}\n")
        hook_log(f"Frozen modules dumped: {frozen_dumped}\n")
        try:
            hook_log(f"Locked spec probes dumped: {spec_probe_dumped}\n")
        except Exception:
            pass
        try:
            hook_log(f"Import locks force-cleared: {forced_locks}\n")
        except Exception:
            pass
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
        try:
            source_paths = sorted(source_dir.rglob("*.py"))
            notified_count = notify_hydradragon_dump_receiver_async(source_paths)
            hook_log(f"Queued {notified_count} Python source dump notifications\n")
        except Exception as e:
            try:
                hook_log(f"[DUMP_NOTIFY] failed: {e}\n")
            except Exception:
                pass
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
    crash_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "hook_crash.txt")
    if os.path.exists(crash_path):
        try:
            os.remove(crash_path)
        except:
            pass

    try:
        run_decompiler()
    except Exception:
        # Last-resort: write to a separate crash log so we never raise into
        # the host process's thread.
        try:
            import traceback

            with open(crash_path, "w", encoding="utf-8", errors="replace") as f:
                traceback.print_exc(file=f)
        except Exception:
            pass


threading.Thread(target=_hook_worker, daemon=True, name="HydraDragonHook").start()
