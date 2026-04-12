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
