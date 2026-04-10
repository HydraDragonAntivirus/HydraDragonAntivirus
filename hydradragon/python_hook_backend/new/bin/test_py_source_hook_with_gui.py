#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import threading
import time
import io
import struct
import re
import platform
import ctypes
from typing import Any
from typing import List
from typing import Dict
from typing import Set
from typing import Tuple
from collections import deque
import pefile
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from ctypes import wintypes


# -- Constants & Win32 APIs --
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE  = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
INJECT_ACCESS = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
INVALID_HANDLE_VALUE = -1
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

# Standard WinAPI Loading
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

def _def(f, r, *a): 
    f.restype, f.argtypes = r, a

# Define API functions with correct signatures
_def(k32.OpenProcess, wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_def(k32.VirtualAllocEx, wintypes.LPVOID, wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)
_def(k32.WriteProcessMemory, wintypes.BOOL, wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
_def(k32.CreateRemoteThread, wintypes.HANDLE, wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
_def(k32.GetModuleHandleW, wintypes.HMODULE, wintypes.LPCWSTR)
_def(k32.GetProcAddress, wintypes.LPVOID, wintypes.HMODULE, wintypes.LPCSTR)
_def(k32.CloseHandle, wintypes.BOOL, wintypes.HANDLE)
_def(k32.IsWow64Process, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
_def(k32.WaitForSingleObject, wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD)
_def(k32.GetExitCodeThread, wintypes.BOOL, wintypes.HANDLE, wintypes.LPDWORD)
_def(k32.LoadLibraryW, wintypes.HMODULE, wintypes.LPCWSTR)
_def(k32.FreeLibrary, wintypes.BOOL, wintypes.HMODULE)
_def(ntdll.NtCreateThreadEx, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.LPVOID, wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, wintypes.LPVOID)
_def(psapi.EnumProcessModulesEx, wintypes.BOOL, wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD, wintypes.DWORD)
_def(psapi.GetModuleFileNameExW, wintypes.DWORD, wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD)
_def(k32.LoadLibraryExW, wintypes.HMODULE, wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD)
_def(k32.FindResourceW, wintypes.HANDLE, wintypes.HMODULE, wintypes.LPCWSTR, wintypes.LPCWSTR)
_def(k32.LoadResource, wintypes.HANDLE, wintypes.HMODULE, wintypes.HANDLE)
_def(k32.LockResource, wintypes.LPVOID, wintypes.HANDLE)
_def(k32.SizeofResource, wintypes.DWORD, wintypes.HMODULE, wintypes.HANDLE)
_def(k32.CreateToolhelp32Snapshot, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD)
_def(k32.QueryFullProcessImageNameW, wintypes.BOOL, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE), ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260)
    ]

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)
    ]
_def(k32.Process32FirstW, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
_def(k32.Process32NextW, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))

def enable_debug_privilege():
    h_token = wintypes.HANDLE()
    if not k32.OpenProcessToken(k32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(h_token)):
        return False
    try:
        luid = wintypes.LARGE_INTEGER()
        # LookupPrivilageValueW is in advapi32
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", (wintypes.DWORD*3)*1)]
        tp = TOKEN_PRIVILEGES(1, ((luid.LowPart, luid.HighPart, 0x00000002),))
        advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)
    finally:
        k32.CloseHandle(h_token)
    return True

def _normalize_func_name(name: str) -> str:
    # Nuitka "a" prefix normalization (aparseConfig → parseConfig)
    if name.startswith('a') and len(name) > 1 and name[1].islower():
        return name[1:]
    return name

def _sanitize_identifier(name: str) -> str:
    # Remove ALL non-printable / non-ascii chars
    name = re.sub(r'[^\x20-\x7E]', '', name)

    # Remove leading garbage before valid identifier
    m = re.search(r'[a-zA-Z_]\w*', name)
    if m:
        name = name[m.start():]
    else:
        return ""

    return name

# -- Nuitka Extraction Logic --
class ResourceScanner:
    UPYTHON_MARKER = b"upython.exe"
    
    def __init__(self, filepath, logger=None):
        self.filepath = filepath
        self.logger = logger or print

    def _read_resource_id27(self) -> bytes:
        """Read the Nuitka blob from RT_RCDATA (type=10), ID=3, language=0 — i.e. 10_3_0.bin."""
        LOAD_LIBRARY_AS_DATAFILE = 0x00000002
        try:
            h_mod = k32.LoadLibraryExW(self.filepath, None, LOAD_LIBRARY_AS_DATAFILE)
            if not h_mod:
                self.logger(f"[!] LoadLibraryExW failed for {self.filepath}"); return b""
            try:
                res_type = ctypes.cast(10, wintypes.LPCWSTR)  # RT_RCDATA
                res_id   = ctypes.cast(3,  wintypes.LPCWSTR)  # ID 3
                h_res = k32.FindResourceW(h_mod, res_id, res_type)
                if not h_res:
                    self.logger(f"[!] FindResourceW: RCDATA ID 3 not found in {self.filepath}"); return b""
                h_glob = k32.LoadResource(h_mod, h_res)
                if not h_glob:
                    self.logger(f"[!] LoadResource failed"); return b""
                size = k32.SizeofResource(h_mod, h_res)
                ptr  = k32.LockResource(h_glob)
                if not ptr:
                    self.logger(f"[!] LockResource failed"); return b""
                data = ctypes.string_at(ptr, size)
                self.logger(f"[*] Found Nuitka blob (RCDATA ID 3): {size} bytes. First 4: {data[:4].hex()}")
                return data
            finally:
                k32.FreeLibrary(h_mod)
        except Exception as e:
            self.logger(f"[!] WinAPI resource error: {e}"); return b""

    def _parse_stream(self, raw: bytes) -> Dict[str, bytes]:
        stream, files = io.BytesIO(raw), {}
        last_pos = -1
        try:
            while True:
                curr_pos = stream.tell()
                if curr_pos == last_pos: break
                last_pos = curr_pos
                # Skip leading nulls/whitespace (Padding)
                while True:
                    curr = stream.read(1)
                    if not curr: return files
                    if curr != b'\x00' and not curr.isspace():
                        stream.seek(-1, io.SEEK_CUR); break
                
                # Filename: Standard null-terminated or basic ASCII
                name_buf = bytearray()
                while True:
                    ch = stream.read(1)
                    if not ch or ch == b'\x00': break
                    name_buf.append(ch[0])
                if not name_buf: break
                
                try: filename = name_buf.decode('utf-8', errors='ignore').strip()
                except: filename = f"file_{len(files)}"
                
                size_bytes = stream.read(8)
                if len(size_bytes) < 8: break
                file_size = struct.unpack('<Q', size_bytes)[0]
                
                # Safety checks for corrupted headers
                if file_size > len(raw) or file_size < 0: break
                files[filename] = stream.read(file_size)
        except Exception: pass
        return files

    @staticmethod
    def detect_python_marker(text: str, filename: str = "") -> str | None:
        markers = ("python3", "python3.dll", "python", "upython", ".py", ".pyc")
        n, t = filename.lower(), text.lower()
        for m in markers:
            if m in n or m in t: return m
        return None

    def extract(self) -> Dict[str, bytes]:
            raw = self._read_resource_id27()
            if not raw: return {}

            # NORMALIZATION: Replace nulls with newlines immediately.
            # This allows the worker to receive a LIST of lines, which is much faster.
            normalized = raw.replace(b'\x00', b'\n')
            
            # We search for the Nuitka marker to slice the noise.
            slice_pos = -1
            for marker in (b'upython.exe', b'\\python.exe', b'python'):
                idx = normalized.find(marker)
                if idx != -1 and (slice_pos == -1 or idx < slice_pos):
                    slice_pos = idx
            
            if slice_pos != -1:
                nl = normalized.find(b'\n', slice_pos)
                if nl != -1: slice_pos = nl + 1
            
            final_blob = normalized[slice_pos:] if slice_pos != -1 else normalized
            
            # Return as a dict so the worker knows it's the integrated source.
            return {"integrated_blob.py": final_blob}

class StaticSourceMerger:
    @staticmethod
    def split_source_by_u_delimiter(source: str) -> str:
        # Nuitka blob encoding rules:
        #   u              = next line (newline delimiter between tokens)
        #   a <n>       = def <n>  (function definition marker)
        #   <x> a__module__ = module boundary sentinel
        #                    also dot-prefixed: .vxauth_module a__module__

        # Step 1: u = next line — replace standalone 'u' tokens with newlines
        # Must run BEFORE a→def so we don't break identifiers containing 'u'
        source = re.sub(r'(?<![.\w])u(?![.\w])', '\n', source)

        # Step 2: Ensure every module boundary (including dot-prefixed .name a__module__)
        # gets its own line so extract_modules can index them cleanly
        source = re.sub(r'(\.?[\w\d\._]+\s+a__module__)', r'\n\1', source)

        # Step 3: Standalone 'a' before an identifier = def
        source = re.sub(r'^([ \t]*)\ba\b(\s+)(?=[a-zA-Z_]\w*)', r'\1def\2', source, flags=re.MULTILINE)

        return source

    @staticmethod
    def extract_modules(static_src: str) -> Tuple[Dict[str, str], Set[str]]:
        # --- sanitize blob ---
        static_src = re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', ' ', static_src)

        try:
            imports = set(re.findall(
                r'(?:import\s+[\w\d\._]+|from\s+[\w\d\._]+\s+import\s+[\w\d\._, ]+)',
                static_src
            ))
        except:
            imports = set()

        modules: Dict[str, str] = {}

        marker_re = re.compile(r'\b([a-zA-Z0-9_\.]+)[ \t\n]+a__module__\b')
        matches = list(marker_re.finditer(static_src))

        if not matches:
            content = StaticSourceMerger.split_source_by_u_delimiter(static_src)
            content = StaticSourceMerger.decode_a_module_names(content)
            content = StaticSourceMerger.decode_alias_assignments(content)
            return {"__main__": content}, imports

        def _sanitize(name: str) -> str:
            return re.sub(r'[^\w\.]', '_', name)

        # CRITICAL: iterate markers as START points
        for i, m in enumerate(matches):
            name = _sanitize(m.group(1))

            start = m.end()  # AFTER marker
            end = matches[i + 1].start() if i + 1 < len(matches) else len(static_src)

            content = static_src[start:end].strip()

            if not content:
                continue

            content = StaticSourceMerger.split_source_by_u_delimiter(content)
            content = StaticSourceMerger.decode_a_module_names(content)
            content = StaticSourceMerger.decode_alias_assignments(content)

            modules[name] = content

        return modules, imports

    @staticmethod
    def decode_a_module_names(source: str) -> str:
        # <n>_a__module__ → <n>_def
        source = re.sub(r'\b([\w\d\_]+)_a__module__\b', r'\1_def', source)
        # .vxauth_module a__module__ or plain name a__module__ → name_def
        # The leading dot (from dot-prefixed blob tokens like .vxauth) must be stripped
        source = re.sub(r'\.?([\w\d\_]+(?:\.[\w\d\_]+)*)\s+a__module__', r'\1_def', source)
        return source

    @staticmethod
    def decode_alias_assignments(source: str) -> str:
        for builtin in ["open", "print", "exec", "eval", "getattr", "setattr"]:
            pat = r'^([ \t]*)([a-zA-Z0-9_]+)\s*=\s*' + re.escape(builtin) + r'\b'
            source = re.sub(pat, r'\1' + builtin + ' = ' + builtin, source, flags=re.MULTILINE)
        return source

    @staticmethod
    def find_incomplete_functions(source: str) -> List[str]:
        # Fast line-based stub identification (O(N) vs greedy regex)
        # Lookback is 30 lines — stubs can have 10-20 metadata comment lines
        # between the def signature and the pass # AG: STUB_IDENTIFIED line.
        stubs = []
        lines = source.splitlines()
        for i, line in enumerate(lines):
            if "# AG: STUB_IDENTIFIED" in line:
                for j in range(i-1, max(-1, i-30), -1):
                    m = re.search(r'def\s+([a-zA-Z_]\w*)\s*\(', lines[j])
                    if m: stubs.append(m.group(1)); break
        return stubs

    @staticmethod
    def _extract_func_from_src(src: str, name: str) -> str | None:
        """Extract a named function's full body from a raw source string.
        Returns None if the extracted body is itself a stub — replacing a dynamic
        stub with a static stub gains nothing."""
        pat = re.compile(
            r'^([ \t]*)def\s+' + re.escape(name) + r'\s*\([^)]*\)'
            r'(?:\s*->\s*[^\n:]+?)?\s*:[ \t]*\n'
            r'(?:(?:\1[ \t]+[^\n]*|\s*)\n)*',
            re.MULTILINE
        )
        m = pat.search(src)
        if not m:
            return None
        body = m.group(0).rstrip()
        # Reject stubs — only return real implementations
        if 'AG: STUB_IDENTIFIED' in body:
            return None
        return body

    @staticmethod
    def merge_dynamic_static(dynamic_src, static_src, stubs, global_cache=None, mod_key=None):
        """
        Merge dynamic source code with static implementations.

        Parameters:
        - dynamic_src: str, the dynamically generated source code.
        - static_src: str | dict[str, str], raw module source string or mapping of
          stub names to bodies. When global_cache is empty, raw string is searched
          directly via _extract_func_from_src.
        - stubs: list[str], names of stub functions to replace.
        - global_cache: dict[str, str], optional, pre-indexed function bodies from blob.
        - mod_key: str, optional, module key for scoped cache lookup.

        Returns:
        - merged_src: str, dynamic source with stubs replaced.
        """
        if not stubs:
            return dynamic_src

        global_cache = global_cache or {}

        # static_src may arrive as a raw string (module source) or a dict {name: body}.
        # Normalise both cases so the rest of the logic is uniform.
        static_src_dict = static_src if isinstance(static_src, dict) else {}
        static_src_str  = static_src if isinstance(static_src, str)  else ""

        merged_src = dynamic_src

        for name in stubs:
            scoped_key = f"{mod_key}.{name}" if mod_key else None

            res = (
                (scoped_key and global_cache.get(scoped_key))
                or global_cache.get(name)
                or static_src_dict.get(name)
                or (static_src_str and StaticSourceMerger._extract_func_from_src(static_src_str, name))
            )

            if res is None:
                continue

            pat = re.compile(
                r'([ \t]*)def\s+' + re.escape(name) + r'\s*\([^)]*\)'
                r'(?:\s*->\s*[^\n:]+?)?'
                r'\s*:.*?'
                r'[ \t]*pass[^\n]*# AG: STUB_IDENTIFIED[^\n]*',
                re.DOTALL
            )

            def _replace(m, body=res):
                indent = m.group(1)
                lines = body.splitlines()
                if not lines:
                    return m.group(0)
                base = len(lines[0]) - len(lines[0].lstrip())
                reindented = []
                for line in lines:
                    stripped = line[base:] if line.startswith(' ' * base) else line.lstrip()
                    reindented.append(indent + stripped if stripped else '')
                return '\n'.join(reindented)

            merged_src = pat.sub(_replace, merged_src, count=1)

        return merged_src

def _blob_analysis_worker(
    blob_text: str,
    dynamic_sources: Dict[str, str],
    shared_logs: list = None,
    ui_log=None,
) -> Tuple[Dict[str, str], int, int, int, List[str], List[str], List[str]]:

    # ------------------------------------------------------------------
    # Constants & Dictionaries
    # ------------------------------------------------------------------
    _REAL_A_MODS = frozenset({
        'abc','ast','asyncio','asynchat','asyncore','atexit','audioop',
        'array','argparse','annotated_types','aiohttp','attrs','attr',
    })
    _PY_KEYWORDS = frozenset({
        'and','as','assert','async','await','break','class','continue',
        'def','del','elif','else','except','finally','for','from',
        'global','if','import','in','is','lambda','nonlocal','not',
        'or','pass','raise','return','try','while','with','yield',
    })
    _STDLIB = frozenset({
        'os','sys','re','io','math','time','json','functools','operator',
        'itertools','collections','pathlib','random','socket','struct',
        'threading','dataclasses','warnings',
    })

    def _norm(name: str) -> str:
        if name.startswith('a') and len(name) > 1 and name[1].islower():
            if name not in _REAL_A_MODS:
                return name[1:]
        return name

    def _is_valid_import(imp: str) -> bool:
        imp = ' '.join(imp.split())
        if not imp or len(imp) < 5: return False
        try:
            mod_part = imp.split(' import ')[0][5:].strip() if imp.startswith('from ') else imp[7:].strip()
            for component in mod_part.replace('.', ' ').split():
                if len(component) < 1: return False
                cl = component.lower()
                if cl in _PY_KEYWORDS: return False
                if not re.match(r'^[a-zA-Z_]\w*$', component): return False
            return True
        except: return False

    def _is_real_body(body: str) -> bool:
        code_lines = []
        for line in body.splitlines():
            s = line.strip()
            if not s or s.startswith(('#', '"""', "'''")): continue
            if re.match(r'(async\s+)?def\s+\w+', s) and not code_lines: continue
            code_lines.append(s)
        if not code_lines: return False
        if len(code_lines) == 1 and 'pass' in code_lines[0] and 'STUB' in code_lines[0]: return False
        return True

    def _cache_put(cache: Dict[str, str], mod_key: str, f_name: str, body: str) -> None:
        norm_name = _norm(f_name)
        # We map BOTH names. If stub asks for getLatestProgramVersion, 
        # it finds what was stored as agetLatestProgramVersion.
        for key in (norm_name, f"{mod_key}.{norm_name}", f_name, f"{mod_key}.{f_name}"):
            if not cache.get(key) or len(body) > len(cache[key]):
                cache[key] = body

    _def_pat = re.compile(
        r'^[ \t]*(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*(?:->.*?)?\s*:',
        re.MULTILINE
    )

    # Inline the three StaticSourceMerger helpers the worker needs.
    # These are pure-Python / re-only so they are safe in a spawned subprocess
    # (no tkinter, no Win32 — the original from __main__ import caused the hang
    # because reimporting __main__ initialises tkinter in the child process).
    def _split_source_by_u_delimiter(source: str) -> str:
        source = re.sub(r'(?<![.\w])u(?![.\w])', '\n', source)
        source = re.sub(r'(\.?[\w\d\._]+\s+a__module__)', r'\n\1', source)
        source = re.sub(r'^([ \t]*)\ba\b(\s+)(?=[a-zA-Z_]\w*)', r'\1def\2', source, flags=re.MULTILINE)
        return source

    def _decode_a_module_names(source: str) -> str:
        source = re.sub(r'\b([\w\d\_]+)_a__module__\b', r'\1_def', source)
        source = re.sub(r'\.?([\w\d\_]+(?:\.[\w\d\_]+)*)\s+a__module__', r'\1_def', source)
        return source

    def _decode_alias_assignments(source: str) -> str:
        for builtin in ["open", "print", "exec", "eval", "getattr", "setattr"]:
            pat = r'^([ \t]*)([a-zA-Z0-9_]+)\s*=\s*' + re.escape(builtin) + r'\b'
            source = re.sub(pat, r'\1' + builtin + ' = ' + builtin, source, flags=re.MULTILINE)
        return source

    def _merge_dynamic_static(dynamic_src, static_src_str, stubs, global_cache, mod_key, token_map=None):
        if not stubs:
            return dynamic_src
        merged_src = dynamic_src
        for name in stubs:
            scoped_key = f"{mod_key}.{name}" if mod_key else None
            nuitka_name = f"a{name}" if not name.startswith('a') else name
            keys_to_check = [scoped_key, name, nuitka_name,
                             f"{mod_key}.{nuitka_name}" if mod_key else None]
            res = None
            for k in keys_to_check:
                if k and global_cache.get(k):
                    res = global_cache[k]; break
            if res is None and static_src_str:
                pat = re.compile(
                    r'^([ \t]*)def\s+' + re.escape(name) + r'\s*\([^)]*\)'
                    r'(?:\s*->\s*[^\n:]+?)?\s*:[ \t]*\n'
                    r'(?:(?:\1[ \t]+[^\n]*|\s*)\n)*',
                    re.MULTILINE)
                m = pat.search(static_src_str)
                if m and 'AG: STUB_IDENTIFIED' not in m.group(0):
                    res = m.group(0).rstrip()

            if res is None and token_map:
                # token_map[mod] = list of tokens, token_map[bare_name] = mod string
                def _get_tokens(key):
                    v = token_map.get(key)
                    if isinstance(v, str): v = token_map.get(v)  # resolve mod pointer
                    return v if isinstance(v, list) else None

                tokens = (_get_tokens(f"{mod_key}.{name}")
                          or _get_tokens(name)
                          or _get_tokens(f"{mod_key}.{nuitka_name}")
                          or _get_tokens(nuitka_name)
                          or _get_tokens(mod_key))
                # Last resort: search all module chunks for this function name
                if not tokens:
                    for k, v in token_map.items():
                        if isinstance(v, list) and any(name in t or nuitka_name in t for t in v[:50]):
                            tokens = v
                            break
                if tokens:
                    res = tokens

            if res is None:
                continue

            if isinstance(res, list):
                # No Python source — only replace the pass line with token comments
                stub_line_pat = re.compile(
                    r'^([ \t]*)pass[^\n]*# AG: STUB_IDENTIFIED[^\n]*',
                    re.MULTILINE)
                def _replace_stub_line(m, toks=res):
                    indent = m.group(1)
                    return '\n'.join(f"{indent}# {t}" for t in toks)
                def _replace_for_func(src, func_name, replacer):
                    lines = src.split('\n')
                    for i, line in enumerate(lines):
                        if re.search(r'\bdef\s+' + re.escape(func_name) + r'\s*\(', line):
                            end = min(i + 50, len(lines))
                            chunk = '\n'.join(lines[i:end])
                            new_chunk, n = stub_line_pat.subn(replacer, chunk, count=1)
                            if n:
                                lines[i:end] = new_chunk.split('\n')
                                return '\n'.join(lines)
                            break
                    return src
                merged_src = _replace_for_func(merged_src, name, _replace_stub_line)
            else:
                # Full Python source body — replace entire stub function
                stub_pat = re.compile(
                    r'([ \t]*)def\s+' + re.escape(name) + r'\s*\([^)]*\)'
                    r'(?:\s*->\s*[^\n:]+?)?'
                    r'\s*:.*?'
                    r'[ \t]*pass[^\n]*# AG: STUB_IDENTIFIED[^\n]*',
                    re.DOTALL)
                def _replace(m, body=res):
                    indent = m.group(1)
                    lines = body.splitlines()
                    if not lines: return m.group(0)
                    base = len(lines[0]) - len(lines[0].lstrip())
                    reindented = []
                    for line in lines:
                        stripped = line[base:] if line.startswith(' ' * base) else line.lstrip()
                        reindented.append(indent + stripped if stripped else '')
                    return '\n'.join(reindented)
                merged_src = stub_pat.sub(_replace, merged_src, count=1)
        return merged_src

    def _find_incomplete_functions(source: str):
        stubs = []
        lines = source.splitlines()
        for i, line in enumerate(lines):
            if "# AG: STUB_IDENTIFIED" in line:
                for j in range(i-1, max(-1, i-30), -1):
                    m = re.search(r'def\s+([a-zA-Z_]\w*)\s*\(', lines[j])
                    if m: stubs.append(m.group(1)); break
        return stubs

    _REAL_A_MODS_SET = frozenset({
        'abc','ast','asyncio','asynchat','asyncore','atexit','audioop',
        'array','argparse','annotated_types','aiohttp','attrs','attr',
        'all','any','abs','ascii','aiter','anext',
    })

    # Build a one-pass a-prefix decode table for all tokens in the blob.
    # Using re.sub with a Python callable per chunk is O(matches * chunks) — too slow.
    # Instead: scan the whole blob once to collect every distinct 'a'-prefixed token,
    # build a static replacement dict, then do a single re.sub with a dict lookup.
    def _build_aprefix_table(text: str) -> dict:
        table = {}
        for line in text.split('\n'):
            token = line.strip()
            if token and token not in table and token not in _REAL_A_MODS_SET:
                if len(token) > 1 and token[0] == 'a' and token[1].islower():
                    table[token] = token[1:]
        return table

    def _apply_aprefix_table(text: str, table: dict) -> str:
        if not table:
            return text
        # Each token is on its own line — no regex needed, just replace whole lines
        lines = text.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped in table:
                lines[i] = line.replace(stripped, table[stripped], 1)
        return '\n'.join(lines)

    scan_logs, global_cache, static_modules = [], {}, {}
    token_map: Dict[str, list] = {}

    def _log(msg):
        scan_logs.append(msg)
        if shared_logs is not None:
            shared_logs.append(msg)
        if ui_log is not None:
            try: ui_log(f"[SCANNER] {msg}")
            except: pass

    try:
        import time as _time

        if blob_text:
            _log(f"[*] Worker: {len(blob_text)} char blob")
            _t = _time.time()

            # Split once, reuse the list for both passes
            blob_lines = blob_text.split('\n')

            # Build a-prefix table
            aprefix_table = {}
            for line in blob_lines:
                t = line.strip()
                if t and t not in aprefix_table and t not in _REAL_A_MODS_SET:
                    if len(t) > 1 and t[0] == 'a' and t[1].islower():
                        aprefix_table[t] = t[1:]

            # Single pass: decode + module split
            current_mod = "__main__"
            mod_chunks = {current_mod: []}
            prev_token = ""
            prev_was_a = False

            for line in blob_lines:
                stripped = line.strip()
                if not stripped or stripped == 'u':
                    prev_was_a = False
                    continue

                decoded = aprefix_table.get(stripped, stripped)

                if decoded == 'a__module__' or stripped == 'a__module__':
                    mod_name = ''.join(c if (c.isalnum() or c == '_') else '_' for c in prev_token.strip('.'))
                    if mod_name:
                        current_mod = mod_name
                    if current_mod not in mod_chunks:
                        mod_chunks[current_mod] = []
                    prev_token = ""
                    prev_was_a = False
                    continue

                if prev_was_a and decoded and decoded[0].isalpha():
                    decoded = 'def ' + decoded
                    if mod_chunks[current_mod] and mod_chunks[current_mod][-1] == 'a':
                        mod_chunks[current_mod].pop()

                prev_was_a = (decoded == 'a')

                if prev_token:
                    mod_chunks[current_mod].append(prev_token)
                prev_token = decoded

            if prev_token:
                mod_chunks[current_mod].append(prev_token)

            _log(f"[*] T1 single-pass: {_time.time()-_t:.2f}s, {len(mod_chunks)} modules")

            # Detect the real entry-point module name.
            # Nuitka stores the actual main script as "__parents_main__" in the blob.
            # The token just before its a__module__ marker is the real filename/module name
            # e.g. "main.py" → real_main_name = "main"
            real_main_name: str = "__main__"
            if '__parents_main__' in mod_chunks:
                # The chunk for __parents_main__ contains the actual script tokens
                real_main_name = '__parents_main__'
            # Also check if a module whose name matches a .py file in dynamic_sources
            # is called something other than __main__
            for mod in mod_chunks:
                if mod not in ('__main__', '__parents_main__') and mod.replace('_', '') == 'main':
                    real_main_name = mod
                    break

            _log(f"[*] Worker: real main module detected as '{real_main_name}'")

            # Collect ALL imports from __main__ and __parents_main__ tokens.
            # These are added only to the __main__ dynamic source output.
            main_imports: set = set()
            _imp_scan = re.compile(r'(?:import\s+[\w\d\._]+|from\s+[\w\d\._]+\s+import\s+[\w\d\._, ]+)')
            for main_mod in ('__main__', '__parents_main__', real_main_name):
                if main_mod in mod_chunks:
                    main_text = '\n'.join(mod_chunks[main_mod])
                    for imp in _imp_scan.findall(main_text):
                        imp_clean = ' '.join(imp.split())
                        if _is_valid_import(imp_clean):
                            main_imports.add(imp_clean)

            # --- PHASE 2: Per-module def extraction (no heavy regex here) ---
            _t = _time.time()
            for mod, chunk_lines in mod_chunks.items():
                if not chunk_lines:
                    continue

                if mod == '__main__':
                    continue

                # Fast check without joining: does any token look like 'def ...'
                if not any(t.startswith('def ') for t in chunk_lines):
                    # Still need token_map even for non-def modules
                    token_map[mod] = chunk_lines
                    for tok in chunk_lines[:200]:
                        if tok.isidentifier() and tok not in token_map:
                            token_map[tok] = mod
                    continue

                chunk_src = '\n'.join(chunk_lines)

                # Store entire module chunk once. Build lightweight func->mod index.
                token_map[mod] = chunk_lines
                for tok in chunk_lines[:200]:
                    if tok.isidentifier() and tok not in token_map:
                        token_map[tok] = mod

                # Only run fixups on chunks that actually have Python source defs
                chunk_src = re.sub(r'\b([\w\d\_]+)_a__module__\b', r'\1_def', chunk_src)
                chunk_src = re.sub(r'\.?([\w\d\_]+(?:\.[\w\d\_]+)*)\s+a__module__', r'\1_def', chunk_src)

                static_modules[mod] = chunk_src
                def_matches = list(_def_pat.finditer(chunk_src))

                if not def_matches:
                    continue

                for i, m in enumerate(def_matches):
                    f_name = m.group(1)
                    start_pos = m.start()
                    max_end = def_matches[i+1].start() if i+1 < len(def_matches) else len(chunk_src)
                    raw_chunk = chunk_src[start_pos:max_end]

                    body_lines = raw_chunk.splitlines()
                    if not body_lines:
                        continue
                    valid_lines = [body_lines[0]]
                    for bl in body_lines[1:]:
                        if bl.strip() and not bl.startswith((' ', '\t')):
                            break
                        valid_lines.append(bl)

                    body = '\n'.join(valid_lines).strip()
                    if len(body) > 10 and _is_real_body(body):
                        _cache_put(global_cache, mod, f_name, body)
            _log(f"[*] T5 phase2 total: {_time.time()-_t:.2f}s, cache={len(global_cache)}, token_map={len(token_map)}")

    except Exception as e:
        import traceback as _tb
        _log(f"[!] Worker Error: {e}")
        _log(_tb.format_exc())

    # ------------------------------------------------------------------
    # PHASE 2 — Import Separation (Internal Modules vs External)
    # ------------------------------------------------------------------
    _t2 = time.time()
    dynamic_mod_keys = {f.replace('.py', '') for f in dynamic_sources.keys()}
    extracted_module_names = set(static_modules.keys())
    
    _imp_pat = re.compile(r'(?:import\s+[\w\d\._]+|from\s+[\w\d\._]+\s+import\s+[\w\d\._, ]+)')

    all_blob_imports = set()
    for src in static_modules.values():
        for imp in _imp_pat.findall(src):
            imp_clean = ' '.join(imp.split())
            if _is_valid_import(imp_clean):
                all_blob_imports.add(imp_clean)
    _log(f"[*] T6 import scan: {time.time()-_t2:.2f}s")
    # ------------------------------------------------------------------
    # PHASE 3 — Smart Reconstruction
    # ------------------------------------------------------------------
    _t3 = time.time()
    merged_outputs = {}
    stub_hits, stub_misses = [], []
    
    for f_name, d_src in dynamic_sources.items():
        mod_key = f_name.replace('.py', '')
        s_content = static_modules.get(mod_key, '')
        stubs = _find_incomplete_functions(d_src)

        for sn in stubs:
            nuitka_name = f"a{sn}" if not sn.startswith('a') else sn
            keys_to_check = [f"{mod_key}.{sn}", sn, nuitka_name, f"{mod_key}.{nuitka_name}"]
            
            if any(global_cache.get(k) for k in keys_to_check):
                stub_hits.append(f"{mod_key}.{sn}")
            else:
                stub_misses.append(f"{mod_key}.{sn}")

        _log(f"[*] T7 merging {mod_key} ({len(stubs)} stubs)...")
        merged_src = _merge_dynamic_static(d_src, s_content, stubs, global_cache, mod_key, token_map)
        _log(f"[*] T7 merged {mod_key}: {time.time()-_t3:.2f}s")

        # Header logic to separate reconstructed code from original stubs
        existing_imps = set(_imp_pat.findall(merged_src))

        if mod_key == '__main__':
            # Only __main__ gets the collected entry-point imports injected
            new_imps = {i for i in all_blob_imports | main_imports if i not in existing_imps
                        and not any(m in i for m in extracted_module_names)}
            real_main_note = (f'\n# NOTE: Real entry-point module detected as: {real_main_name}\n'
                              if real_main_name not in ('__main__', '') else '')
            header = ('\n'.join(sorted(new_imps)) + '\n\n' if new_imps else '') + \
                     '#'*15 + ' NUITKA MAIN RECONSTRUCTION ' + '#'*15 + real_main_note + '\n\n'
        else:
            new_imps = {i for i in all_blob_imports if i not in existing_imps
                        and not any(m in i for m in extracted_module_names)}
            header = ('\n'.join(sorted(new_imps)) + '\n\n' if new_imps else '') + \
                     '#'*15 + f' MODULE: {mod_key} ' + '#'*15 + '\n\n'

        merged_outputs[f_name] = header + merged_src

    return merged_outputs, len(global_cache), len(static_modules), len(static_modules), stub_hits, stub_misses, scan_logs

class DynamicDumpReader:
    DEFAULT_BASE = r"C:\ProgramData\HydraDragonAntivirus\python_dumps"
    @staticmethod
    def get_latest_dump_dir(base: str | None = None) -> tuple[str | None, int]:
        base = base or DynamicDumpReader.DEFAULT_BASE
        if not os.path.isdir(base): return None, -1
        candidates = []
        for d in os.listdir(base):
            if d.startswith("dump_"):
                try: candidates.append((int(d.split("_", 1)[1]), os.path.join(base, d)))
                except ValueError: pass
        if not candidates: return None, -1
        best = max(candidates, key=lambda x: x[0]); return best[1], best[0]
    @staticmethod
    def wait_for_dump(timeout, baseline_idx, log_cb=None):
        start = time.time()
        seen_dir = None
        announced_start = False
        while time.time() - start < timeout:
            d, idx = DynamicDumpReader.get_latest_dump_dir()
            if d and idx > baseline_idx:
                if d != seen_dir:
                    seen_dir = d
                    if log_cb:
                        try: log_cb(f"[ANALYSIS] Detected new dump directory: {d}")
                        except: pass
                started_path = os.path.join(d, "started.txt")
                progress_path = os.path.join(d, "progress.txt")
                error_path = os.path.join(d, "error.txt")
                finished_path = os.path.join(d, "finished.txt")
                if os.path.exists(finished_path):
                    return ("finished", d)
                if os.path.exists(error_path):
                    return ("error", d)
                if os.path.exists(started_path) and not announced_start:
                    announced_start = True
                    if log_cb:
                        try: log_cb(f"[ANALYSIS] Hook worker started in {d}; waiting for finished.txt...")
                        except: pass
                if os.path.exists(progress_path) and log_cb and announced_start:
                    try:
                        with open(progress_path, "r", encoding='utf-8', errors='replace') as f:
                            progress = f.read().strip()
                        if progress:
                            try: log_cb(f"[ANALYSIS] Progress:\n{progress}")
                            except: pass
                            announced_start = False  # throttle repeated progress spam
                    except Exception:
                        pass
            time.sleep(1)
        latest_dir, latest_idx = DynamicDumpReader.get_latest_dump_dir()
        if latest_dir and latest_idx > baseline_idx:
            return ("pending", latest_dir)
        return ("missing", None)

class LiteInjector:
    btn_ninja: tk.Button
    tree: ttk.Treeview
    search: tk.Entry
    log_box: scrolledtext.ScrolledText
    search_timer: Any = ""
    scan_lock: threading.Lock
    last_tree_data: List = []
    log_queue: deque = deque(maxlen=500)
    _hb_count: int = 0
    _log_pending: bool = False

    def __init__(self, root: tk.Tk):
        self.root = root; self.root.geometry("750x650")
        enable_debug_privilege(); self.ninja_on, self.processed = False, set()
        self.scan_lock = threading.Lock(); self.search_timer = ""; self.last_tree_data = []
        self.inject_lock = threading.Lock(); self.active_injections = set()
        self.log_queue = deque(maxlen=500); self._hb_count = 0
        self.hook_var = tk.StringVar(value=self._path("__hook__.py"))
        d_dir = os.path.dirname(os.path.abspath(__file__))
        self.dll_var = tk.StringVar(value=os.path.join(d_dir, "hook64.dll" if platform.machine().endswith("64") else "hook32.dll"))
        self.hide_std = tk.BooleanVar(value=True); self._build_ui(); self.refresh(); self._heartbeat()
    def _heartbeat(self):
        self._hb_count += 1; self.root.title(f"Hydra Injector [HB:{self._hb_count}] [NINJA:{'ON' if self.ninja_on else 'OFF'}]")
        self.root.after(250, self._heartbeat)
    def _path(self, n): p = os.path.join(os.path.dirname(os.path.abspath(__file__)), n); return p if os.path.exists(p) else n
    def log(self, msg):
        t_msg = f"[{time.strftime('%H:%M:%S')}] {msg}"
        self.log_queue.append(t_msg)
        # Throttled UI dispatch to prevent event flooding (Critical for stability)
        if not self._log_pending:
            self._log_pending = True; self.root.after(150, self._flush_logs)
        # Asynchronous disk logging (Prevents main thread I/O block)
        def _bg_log(m):
            try:
                p = r"C:\ProgramData\HydraDragonAntivirus\injector_debug.txt"; os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "a", encoding='utf-8') as f: f.write(m + "\n")
            except: pass
        threading.Thread(target=_bg_log, args=(t_msg,)).start()
    def _flush_logs(self):
        self._log_pending = False
        if not self.log_queue: return
        self.log_box.config(state='normal')
        self.log_box.insert(tk.END, "\n".join(self.log_queue) + "\n")
        self.log_box.see(tk.END); self.log_box.config(state='disabled')
        self.log_queue.clear()
    def _build_ui(self):
        top = tk.Frame(self.root, pady=5); top.pack(fill=tk.X, padx=10)
        tk.Button(top, text="Refresh List", command=self.refresh).pack(side=tk.LEFT)
        self.search = tk.Entry(top); self.search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10); self.search.bind("<KeyRelease>", self._trigger_refresh)
        tk.Checkbutton(self.root, text="Hide System Pythons", variable=self.hide_std, command=self.refresh).pack(anchor='w', padx=10)
        cols = ("PID", "Name", "Arch", "Path"); self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=12)
        for c, w in zip(cols, (70, 150, 70, 450)): self.tree.heading(c, text=c); self.tree.column(c, width=w)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10); self.tree.bind("<Double-1>", lambda e: self.run_inject())
        cfg = tk.LabelFrame(self.root, text="Settings", padx=10, pady=5); cfg.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(cfg, text="Hook Script:").pack(anchor='w'); tk.Entry(cfg, textvariable=self.hook_var).pack(fill=tk.X, pady=2)
        tk.Label(cfg, text="DLL Path:").pack(anchor='w'); tk.Entry(cfg, textvariable=self.dll_var).pack(fill=tk.X, pady=2)
        btns = tk.Frame(self.root, pady=5); btns.pack(fill=tk.X, padx=10)
        self.btn_ninja = tk.Button(btns, text="Ninja Mode: OFF", command=self.toggle_ninja, width=15); self.btn_ninja.pack(side=tk.LEFT)
        tk.Button(btns, text="INJECT NOW", bg="#d32f2f", fg="white", font=("Arial", 9, "bold"), command=self.run_inject).pack(side=tk.RIGHT)
        self.log_box = scrolledtext.ScrolledText(self.root, height=10, state='disabled', bg="#1e1e1e", fg="#00ff00", font=("Consolas", 8)); self.log_box.pack(fill=tk.X, padx=10, pady=5)

    def post_injection_analysis(self, file_path, baseline_idx=-1):
        try:
            self.log(f"[ANALYSIS] Waiting for dynamic hook dump after baseline index {baseline_idx}...")
            status, dump_dir = DynamicDumpReader.wait_for_dump(180, baseline_idx, self.log)
            if status == "error":
                self.log(f"[ANALYSIS] ERROR: Hook worker crashed in: {dump_dir}")
                error_path = os.path.join(dump_dir, "error.txt")
                try:
                    with open(error_path, "r", encoding='utf-8', errors='replace') as f:
                        err_text = f.read().strip()
                    if err_text:
                        self.log(err_text)
                except Exception as e:
                    self.log(f"[ANALYSIS] Could not read worker error log: {e}")
                return
            if status == "pending":
                self.log(f"[ANALYSIS] ERROR: Dump directory created but not finished: {dump_dir}")
                progress_path = os.path.join(dump_dir, "progress.txt")
                if os.path.exists(progress_path):
                    try:
                        with open(progress_path, "r", encoding='utf-8', errors='replace') as f:
                            progress = f.read().strip()
                        if progress:
                            self.log(f"[ANALYSIS] Last progress:\n{progress}")
                    except Exception as e:
                        self.log(f"[ANALYSIS] Could not read progress file: {e}")
                return
            if status != "finished" or not dump_dir:
                self.log("[ANALYSIS] ERROR: No new dump directory was created."); return
            self.log(f"[ANALYSIS] Dynamic dump ready at: {dump_dir}"); src_dir = os.path.join(dump_dir, "RECONSTRUCTED_SOURCE")
            dynamic_sources: Dict[str, str] = {}
            if os.path.isdir(src_dir):
                for f in os.listdir(src_dir):
                    if f.endswith(".py") and f != "__hook__.py":
                        with open(os.path.join(src_dir, f), "r", encoding='utf-8', errors='replace') as fh:
                            content: str = fh.read()
                            dynamic_sources[f] = content
            self.log(f"[*] Scanning blob from {file_path}...")
            try:
                scanner = ResourceScanner(file_path, self.log)
                files_dict = scanner.extract()
                blob_text = files_dict.get("integrated_blob.py", b"").decode('utf-8', errors='replace')
            except Exception as e:
                self.log(f"[ANALYSIS] ERROR: Blob extraction failed: {e}"); return
            if not blob_text:
                self.log("[ANALYSIS] ERROR: Empty blob — nothing to reconstruct."); return
            self.log(f"[*] Blob extracted ({len(blob_text)} chars). Running analysis...")
            _shared_logs: list = []
            try:
                merged_outputs, cache_size, matched, total, stub_hits, stub_misses, scan_logs = \
                    _blob_analysis_worker(blob_text, dynamic_sources, _shared_logs, self.log)
            except Exception as ex:
                import traceback
                self.log(f"[ANALYSIS] ERROR: Worker raised: {ex}")
                self.log(traceback.format_exc())
                for msg in _shared_logs:
                    self.log(f"[SCANNER] {msg}")
                return

            for msg in scan_logs:
                self.log(f"[SCANNER] {msg}")

            self.log(f"[*] global_cache: {cache_size} bodies | matched: {matched}/{total}")
            if not cache_size:
                self.log("[!] global_cache is EMPTY — blob produced no recoverable bodies. Falling back to static string extraction only.")
            if stub_hits: self.log(f"[*] Stubs merged: {', '.join(stub_hits)}")
            if stub_misses: self.log(f"[!] Stubs NOT in cache (blob missing bodies): {', '.join(stub_misses)}")
            merged_count = 0
            for f_name, content in merged_outputs.items():
                try:
                    p = os.path.join(src_dir, f_name)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "w", encoding='utf-8') as fh: fh.write(content)
                    merged_count += 1
                except Exception as e: self.log(f"[!] Write failed for {f_name}: {e}")
            self.log(f"[ANALYSIS] Nuitka Global Union complete. Restored {merged_count} module(s).")
        except Exception as e: self.log(f"[ANALYSIS] CRITICAL ERROR: {e}"); import traceback; self.log(traceback.format_exc())

    def update_view(self, s_term, hide):
        if not self.scan_lock.acquire(blocking=False): return
        try:
            results = []
            h_snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)
            if h_snap == -1: return
            try:
                pe = PROCESSENTRY32W(); pe.dwSize = ctypes.sizeof(pe)
                own_pid = os.getpid()
                if k32.Process32FirstW(h_snap, ctypes.byref(pe)):
                    while True:
                        pid, name = pe.th32ProcessID, pe.szExeFile
                        # Never show our own process — injecting into self causes
                        # loader lock deadlock → LoadLibraryW remote thread exits with code 1
                        if pid == own_pid:
                            if not k32.Process32NextW(h_snap, ctypes.byref(pe)): break
                            continue
                        match = (not s_term) or (s_term in name.lower())
                        exe = self._get_proc_path(pid) if (match or "python" in name.lower()) else ""
                        if (match or (exe and "python" in exe.lower())):
                            if hide and exe and any(x in exe.lower() for x in ["program files", "windows", "appdata\\local\\programs\\python"]): pass
                            else:
                                arch = "x64" if self.get_target_arch_64(pid) else "x86"
                                results.append((pid, name, arch, exe))
                        if not k32.Process32NextW(h_snap, ctypes.byref(pe)): break
            finally: k32.CloseHandle(h_snap)
            self.root.after(0, self._render_tree, results)
        finally: self.scan_lock.release()
    def _get_proc_path(self, pid):
        h = k32.OpenProcess(0x1000, False, pid)
        if not h: return ""
        try:
            buf = (wintypes.WCHAR * 1024)(); sz = wintypes.DWORD(1024)
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)): return buf.value
        finally: k32.CloseHandle(h)
        return ""
    def _render_tree(self, data):
        # Fingerprint check to avoid redundant UI mutations (O(N) vs O(N) UI ops)
        if self.last_tree_data == data: return
        self.last_tree_data = data
        self.tree.delete(*self.tree.get_children())
        for row in data: self.tree.insert("", tk.END, values=row)
    def _trigger_refresh(self, event=None):
        if self.search_timer:
            try: self.root.after_cancel(self.search_timer)
            except: pass
        # Standardize typing for the timer ID
        self.search_timer = str(self.root.after(450, self.refresh))
    def refresh(self):
        try:
            s_term = self.search.get().lower(); hide = self.hide_std.get()
            threading.Thread(target=self.update_view, args=(s_term, hide)).start()
        except: pass
    def toggle_ninja(self):
        self.ninja_on = not self.ninja_on
        self.btn_ninja.config(text="Ninja Mode: ON" if self.ninja_on else "Ninja Mode: OFF", bg="#4caf50" if self.ninja_on else "grey")
        # Recursively schedule instead of while-looping (Event-Driven)
        if self.ninja_on: self.root.after(100, self.ninja_loop)
    def ninja_loop(self):
        if not self.ninja_on: return
        threading.Thread(target=self._ninja_scan_worker).start()
        self.root.after(5000, self.ninja_loop)
    def _ninja_scan_worker(self):
        self.processed = {p for p in self.processed if self._pid_exists_native(p)}
        h_snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)
        if h_snap != -1:
            try:
                pe = PROCESSENTRY32W(); pe.dwSize = ctypes.sizeof(pe)
                if k32.Process32FirstW(h_snap, ctypes.byref(pe)):
                    while True:
                        pid, name = pe.th32ProcessID, pe.szExeFile
                        if pid not in self.processed and pid != os.getpid():
                            exe = self._get_proc_path(pid)
                            if self.is_target_native(pid, name, exe):
                                self.processed.add(pid); threading.Thread(target=self.inject, args=(pid, name, exe)).start()
                                self.root.after(0, self.refresh)
                        if not k32.Process32NextW(h_snap, ctypes.byref(pe)): break
            finally: k32.CloseHandle(h_snap)
    def _find_python_dll_loaded(self, pid: int) -> str | None:
        """Return the full path of python3.dll or python3XX.dll loaded in the target process,
        or None if Python is not actually loaded. This is the only reliable check —
        file-on-disk checks are meaningless, only what's in the live module list matters."""
        h_proc = k32.OpenProcess(0x0410, False, pid)
        if not h_proc: return None
        try:
            h_mods = (wintypes.HMODULE * 2048)(); cb = wintypes.DWORD()
            if not psapi.EnumProcessModulesEx(h_proc, ctypes.byref(h_mods), ctypes.sizeof(h_mods), ctypes.byref(cb), 0x03):
                return None
            count = cb.value // ctypes.sizeof(wintypes.HMODULE)
            pat = re.compile(r'python3\d*\.dll', re.IGNORECASE)
            for i in range(count):
                m_path = (wintypes.WCHAR * 1024)()
                if psapi.GetModuleFileNameExW(h_proc, h_mods[i], m_path, 1024):
                    basename = os.path.basename(m_path.value)
                    if pat.match(basename):
                        return m_path.value
        except: pass
        finally: k32.CloseHandle(h_proc)
        return None

    def is_target_native(self, pid, name, exe):
        n = name.lower(); e = exe.lower()
        if any(x in n for x in ["csrss", "lsass", "services", "wininit", "winlogon", "smss", "fontdrvhost", "svchost", "explorer", "taskhost"]): return False
        if self.hide_std.get() and any(x in e for x in ["program files", "windows", "appdata\\local\\programs\\python"]): return False
        # Only inject if Python is actually loaded in the process — not just if the
        # exe name contains "python" or python3.dll sits on disk next to it.
        return self._find_python_dll_loaded(pid) is not None
    def get_target_arch_64(self, pid):
        try:
            h = k32.OpenProcess(0x0400, False, pid)
            if h:
                is_wow64 = wintypes.BOOL(); k32.IsWow64Process(h, ctypes.byref(is_wow64)); k32.CloseHandle(h)
                is_os_64 = platform.machine().endswith("64"); return (not is_wow64.value) if is_os_64 else False
        except: pass
        return True
    def _create_remote_thread(self, h_proc, start, param, pid, label):
        tid = wintypes.DWORD(0); h = k32.CreateRemoteThread(h_proc, None, 0, start, param, 0, ctypes.byref(tid))
        if h: return h
        h_nt = wintypes.HANDLE(); status = ntdll.NtCreateThreadEx(ctypes.byref(h_nt), 0x1FFFFF, None, h_proc, start, param, 0, 0, 0, 0, None)
        return h_nt.value if (status & 0xFFFFFFFF) == 0 else None
    def _wait_thread_exit(self, h, timeout, label):
        if k32.WaitForSingleObject(h, timeout) == 0:
            ec = wintypes.DWORD(); k32.GetExitCodeThread(h, ctypes.byref(ec)); return True, ec.value
        return False, None
    def _find_remote_module_base(self, pid: int, name: str) -> int | None:
        if not psapi: return None
        name = name.lower()
        for i in range(25):
            h_proc = k32.OpenProcess(0x0410, False, pid)
            if h_proc:
                try:
                    h_mods = (wintypes.HMODULE * 1024)(); cb = wintypes.DWORD()
                    if psapi.EnumProcessModulesEx(h_proc, ctypes.byref(h_mods), ctypes.sizeof(h_mods), ctypes.byref(cb), 0x03):
                        for j in range(cb.value // ctypes.sizeof(wintypes.HMODULE)):
                            m_path = (wintypes.WCHAR * 1024)()
                            if psapi.GetModuleFileNameExW(h_proc, h_mods[j], m_path, 1024):
                                if os.path.basename(m_path.value).lower() == name:
                                    base = h_mods[j]; k32.CloseHandle(h_proc); return base
                finally: k32.CloseHandle(h_proc)
            time.sleep(0.5)
        return None

    def run_inject(self):
        sel = self.tree.selection()
        if not sel: return
        pid, name, arch, exe = self.tree.item(sel[0], "values")
        self.log(f"[*] Starting injection into {name} (PID: {pid})..."); threading.Thread(target=self.inject, args=(int(pid), name, exe)).start()

    def inject(self, pid, name, exe):
        with self.inject_lock:
            if pid in self.active_injections:
                self.log(f"[*] Injection already running for PID {pid}; skipping duplicate request.")
                return
            self.active_injections.add(pid)
        try:
            # Hard guard — injecting into our own process causes loader lock deadlock:
            # LoadLibraryW remote thread exits with code 1, HydraStartHook never runs.
            if pid == os.getpid():
                self.log(f"ERROR: Refusing to inject into own process (PID {pid})."); return

            # Select DLL based on TARGET process bitness, not host OS arch.
            # Loading hook64.dll into a 32-bit target (or vice-versa) makes
            # LoadLibraryW succeed but all Python C API calls inside HydraStartHook
            # will fault → thread exits with code 1.
            target_is_64 = self.get_target_arch_64(pid)
            d_dir = os.path.dirname(os.path.abspath(__file__))

            # Verify Python is actually loaded in the target before touching it.
            py_dll = self._find_python_dll_loaded(pid)
            if not py_dll:
                self.log(f"ERROR: No python3.dll / python3XX.dll loaded in PID {pid} ({name}). Not a Python process."); return
            self.log(f"[*] Found Python in target: {py_dll}")
            dll_path = os.path.join(d_dir, "hook64.dll" if target_is_64 else "hook32.dll")
            # Allow manual override from the UI field only if the user explicitly changed it
            ui_dll = self.dll_var.get()
            if ui_dll and os.path.exists(ui_dll) and ui_dll != os.path.join(d_dir, "hook64.dll") and ui_dll != os.path.join(d_dir, "hook32.dll"):
                dll_path = ui_dll
            self.log(f"[*] Target arch: {'x64' if target_is_64 else 'x86'} → using {os.path.basename(dll_path)}")

            hook_path = self.hook_var.get()
            if not os.path.exists(dll_path): self.log(f"ERROR: DLL not found: {dll_path}"); return
            if not os.path.exists(hook_path): self.log(f"ERROR: Hook script not found: {hook_path}"); return
            try:
                config_dir = r"C:\ProgramData\HydraDragonAntivirus\python_dumps"
                os.makedirs(config_dir, exist_ok=True)
                with open(os.path.join(config_dir, "hook_config.ini"), "w", encoding='utf-8') as f: 
                    f.write(f"HookPath={os.path.abspath(hook_path)}\n")
            except Exception as e: self.log(f"ERROR: FAILED TO WRITE CONFIG: {e}"); return
            # Check if our hook DLL is already loaded in the target — error 183
            # (ERROR_ALREADY_EXISTS) means a previous inject is still running.
            if self._find_remote_module_base(pid, os.path.basename(dll_path)):
                self.log(f"[*] {os.path.basename(dll_path)} already loaded in PID {pid} — skipping re-inject."); return

            h_proc = k32.OpenProcess(INJECT_ACCESS, False, pid)
            if not h_proc:
                err = k32.GetLastError()
                self.log(f"ERROR: OpenProcess FAILED: {err} (pid={pid}, access=0x{INJECT_ACCESS:X})")
                if err == 87:
                    self.log("ERROR: Windows rejected the requested process-open parameters. This is separate from Python hook initialization.")
                return
            try:
                p_bytes = (dll_path + "\0").encode('utf-16le'); mem = k32.VirtualAllocEx(h_proc, 0, len(p_bytes), 0x3000, 0x40)
                if not mem: self.log(f"ERROR: VirtualAllocEx FAILED: {k32.GetLastError()}"); return
                k32.WriteProcessMemory(h_proc, mem, p_bytes, len(p_bytes), None)
                lload = k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
                h_load = self._create_remote_thread(h_proc, lload, mem, pid, "Load")
                ok, l_res = self._wait_thread_exit(h_load, 5000, "Load"); k32.CloseHandle(h_load)
                if not ok or not l_res: self.log(f"ERROR: LoadLibraryW FAILED. Res: {l_res}, Error: {k32.GetLastError()}"); return
                rem_mod = self._find_remote_module_base(pid, os.path.basename(dll_path))
                if not rem_mod:
                    if l_res and l_res != 0: rem_mod = l_res; self.log(f"[*] Module base from thread code: 0x{rem_mod:X}")
                    else: self.log(f"ERROR: Module not found in remote process: {os.path.basename(dll_path)}"); return
                try:
                    if not pefile: self.log("ERROR: pefile MISSING. Using fallback export."); fn_rva = 0x1000
                    else:
                        pe = pefile.PE(dll_path); fn_rva = None
                        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            if export.name == b"HydraStartHook": fn_rva = export.address; break
                        if not fn_rva: self.log("ERROR: HydraStartHook EXPORT NOT FOUND."); return
                except Exception as pe_err: self.log(f"ERROR: pefile failed: {pe_err}"); return
                _, baseline_dump_idx = DynamicDumpReader.get_latest_dump_dir()
                self.log(f"[*] Baseline dump index before hook start: {baseline_dump_idx}")
                rem_fn = int(rem_mod) + fn_rva; h_st = self._create_remote_thread(h_proc, rem_fn, None, pid, "Start")
                if not h_st: self.log("ERROR: CreateRemoteThread Start FAILED."); return
                ok, exit_code = self._wait_thread_exit(h_st, 5000, "Start"); k32.CloseHandle(h_st)
                if ok and exit_code == 0:
                    self.log(f"SUCCESS: {name} hooked and running.")
                    if exe: threading.Thread(target=self.post_injection_analysis, args=(exe, baseline_dump_idx), daemon=True).start()
                elif not ok:
                    self.log(f"ERROR: HydraStartHook thread timed out (possible deadlock in target).")
                else:
                    self.log(f"ERROR: HydraStartHook returned {exit_code} — hook init failed inside target.")
                    self.log("ERROR: Exit code 1 is generic here; check C:\\ProgramData\\HydraDragonAntivirus\\python_dumps\\hook_dll.log for the real reason.")
            finally: k32.CloseHandle(h_proc)
        except Exception as e: self.log(f"EXC: {e}")
        finally:
            with self.inject_lock:
                self.active_injections.discard(pid)
    def _pid_exists_native(self, pid):
        # O(1) existence check (Process Query rights)
        h = k32.OpenProcess(0x1000, False, pid)
        if h: k32.CloseHandle(h); return True
        return False

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()  # required for ProcessPoolExecutor on Windows frozen/spawned processes
    try:
        shell32 = ctypes.WinDLL('shell32')
        if not shell32.IsUserAnAdmin():
            shell32.ShellExecuteW(None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1); sys.exit()
        root = tk.Tk(); app = LiteInjector(root); root.mainloop()
    except Exception as e:
        import tkinter.messagebox as mbox
        try: mbox.showerror("Fatal Error", f"Failed to launch: {e}")
        except: print(f"CRITICAL ERROR: {e}"); sys.exit(1)
