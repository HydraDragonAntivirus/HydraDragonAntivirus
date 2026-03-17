#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------
# Helper function to generate platform-specific signatures
async def get_signature(base_signature, **flags):
    """Generate platform-specific signature based on flags."""
    platform_map = {
        'dotnet_flag': 'DotNET',
        'vineflower_flag': 'Java',
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

def _norm(p: str) -> str:
    return os.path.normpath(p).replace("\\", "/").lower()

def validate_pipe_peer(handle, expected_path: str, is_server: bool = True, logger=None) -> bool:
    """
    Validate the peer of a named pipe handle.
    If is_server is True, it validates the CLIENT (server-side check).
    If is_server is False, it validates the SERVER (client-side check).
    """
    try:
        import win32pipe
        import win32process
        import win32api
        
        # Standard access right for querying process info
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        
        if is_server:
            peer_pid = win32pipe.GetNamedPipeClientProcessId(handle)
        else:
            peer_pid = win32pipe.GetNamedPipeServerProcessId(handle)
            
        if peer_pid == 0:
            return False
            
        # Handle kernel (PID 4) if needed (usually for drivers, here we assume user-mode exes)
        if peer_pid == 4:
            return False

        try:
            h_proc = win32api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, peer_pid)
        except Exception:
            # Fallback if limited info is not enough
            try:
                h_proc = win32api.OpenProcess(0x0400, False, peer_pid) # PROCESS_QUERY_INFORMATION
            except Exception:
                return False

        try:
            path = win32process.GetModuleFileNameEx(h_proc, 0)
            is_valid = path.lower() == expected_path.lower()
            if not is_valid and logger:
                logger.warning(f"Pipe peer validation failed. Expected: {expected_path}, Got: {path}")
            return is_valid
        finally:
            win32api.CloseHandle(h_proc)
    except Exception as e:
        if logger:
            logger.error(f"Error validating pipe peer: {e}")
        return False
