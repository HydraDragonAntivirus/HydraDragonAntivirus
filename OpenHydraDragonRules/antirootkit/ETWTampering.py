#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect ETW-disable patching in ntdll.dll by comparing the in-memory bytes of NtTraceEvent
against the on-disk bytes.
"""
import os
import ctypes
from ctypes import wintypes
from pathlib import Path
import pefile
import logging

def detect_etw_tampering() -> dict:
    """
    Checks whether NtTraceEvent in ntdll.dll has been tampered (e.g., patched to just 'ret').
    Returns a dict with:
      - 'patched': bool (True if in-memory bytes differ from on-disk bytes)
      - if patched: 'orig_bytes' and 'mem_bytes' (hex of first few bytes)
      - on error or export not found: 'error'
    """
    try:
        # Locate ntdll.dll on disk (System32). Adjust if running under Wow64 and need SysWOW64 path.
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        ntdll_path = Path(system_root) / "System32" / "ntdll.dll"
        if not ntdll_path.exists():
            return {"error": f"ntdll.dll not found at {ntdll_path}"}
        
        # Parse PE to find the RVA of NtTraceEvent
        pe = pefile.PE(str(ntdll_path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        nttrace_rva = None
        for exp in getattr(pe, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
            if exp.name and exp.name.decode(errors='ignore') == "NtTraceEvent":
                nttrace_rva = exp.address
                break
        if nttrace_rva is None:
            return {"error": "Export NtTraceEvent not found in ntdll.dll"}
        
        # Compute file offset and read original bytes
        try:
            file_offset = pe.get_offset_from_rva(nttrace_rva)
        except Exception as e:
            return {"error": f"Cannot compute file offset for NtTraceEvent RVA: {e}"}
        
        length = 16  # number of bytes to compare; enough to catch a small patch like a series of 0xC3.
        with open(ntdll_path, "rb") as f:
            f.seek(file_offset)
            orig_bytes = f.read(length)
            if len(orig_bytes) < length:
                return {"error": f"Could not read {length} bytes from disk image"}
        
        # Get in-memory base address of ntdll.dll in current process
        kernel32 = ctypes.windll.kernel32
        GetModuleHandleW = kernel32.GetModuleHandleW
        GetModuleHandleW.restype = wintypes.HMODULE
        GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        hModule = GetModuleHandleW("ntdll.dll")
        if not hModule:
            return {"error": "GetModuleHandleW failed for ntdll.dll"}
        
        # Compute the in-memory address of NtTraceEvent
        addr = hModule + nttrace_rva
        # Read from our own process memory
        try:
            mem_bytes = ctypes.string_at(addr, length)
        except (ValueError, OSError) as e:
            return {"error": f"Cannot read memory at address {hex(addr)}: {e}"}
        
        # Compare
        if mem_bytes != orig_bytes:
            return {
                "patched": True,
                "orig_bytes": orig_bytes[:8].hex(),
                "mem_bytes": mem_bytes[:8].hex(),
                "note": "In-memory bytes differ from on-disk bytes - possible ETW patch"
            }
        else: 
             return {}
    except Exception as ex:
        logging.error(f"[ETW Detection] Error: {ex}")
        return {"error": str(ex)}
