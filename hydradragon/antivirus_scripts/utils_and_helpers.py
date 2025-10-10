import hashlib
import os
import string
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------
# Helper function to generate platform-specific signatures
def get_signature(base_signature, **flags):
    """Generate platform-specific signature based on flags."""
    platform_map = {
        'dotnet_flag': 'DotNET',
        'fernflower_flag': 'Java',
        'jsc_flag': 'JavaScript.ByteCode.v8',
        'javascript_deobfuscated_flag': 'JavaScript',
        'nuitka_flag': 'Nuitka',
        'ole2_flag': 'OLE2',
        'inno_setup_flag': 'Inno Setup',
        'autohotkey_flag': 'AutoHotkey',
        'nsis_flag': 'NSIS',
        'pyc_flag': 'PYC.Python',
        'androguard_flag': 'Android',
        'asar_flag': 'Electron',
        'registry_flag': 'Registry',
        'nexe_flag' : 'nexe'
    }

    for flag, platform in platform_map.items():
        if flags.get(flag):
            return f"HEUR:Win32.{platform}.{base_signature}"

    return f"HEUR:Win32.{base_signature}"

def compute_md5_via_text(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def compute_md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

num_cores = os.cpu_count()  # returns the number of logical CPUs
max_workers=num_cores * 2
executor = ThreadPoolExecutor(max_workers=max_workers)

def run_in_thread(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        return executor.submit(fn, *args, **kwargs)
    return wrapper

def _enumerate_drive_roots():
    """Return drive roots like 'C:\\', 'D:\\' for existing drive letters (Windows)."""
    roots = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:/"
        if os.path.exists(root):
            roots.append(root)
    return roots

def _is_relative_path(p: str) -> bool:
    # Consider relative if not absolute and not starting with drive letter like 'C:\'
    if os.path.isabs(p):
        return False
    # treat paths that start with a backslash but missing drive as relative for our purposes
    return True

def _norm(p: str) -> str:
    return os.path.normpath(p).replace("\\", "/").lower()
