#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import asyncio
import ctypes
import platform
import time
import threading
import psutil
from ctypes import wintypes

from .hydra_logger import logger
from .path_and_variables import (
    hook_dll_32_path,
    hook_dll_64_path,
    hook_py_path,
    hydra_dragon_antivirus_dir,
    python_dumps_dir,
)

# ---------------------------------------------------------------------------
# Derived paths
# ---------------------------------------------------------------------------
# Processes whose exe lives under the antivirus install dir are never hooked
_EXCLUDED_DIR_NORM = os.path.normcase(os.path.normpath(hydra_dragon_antivirus_dir))

# Per-session set of PIDs we already successfully injected
_hooked_pids: set[int] = set()
_hooked_pids_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Windows API definitions
# ---------------------------------------------------------------------------
k32   = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll',    use_last_error=True)


def _def(f, r, *a):
    f.restype, f.argtypes = r, list(a)


_def(k32.OpenProcess,              wintypes.HANDLE,  wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_def(k32.VirtualAllocEx,           wintypes.LPVOID,  wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)
_def(k32.WriteProcessMemory,       wintypes.BOOL,    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
_def(k32.CreateRemoteThread,       wintypes.HANDLE,  wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
_def(k32.GetModuleHandleW,         wintypes.HMODULE, wintypes.LPCWSTR)
_def(k32.GetProcAddress,           wintypes.LPVOID,  wintypes.HMODULE, wintypes.LPCSTR)
_def(k32.CloseHandle,              wintypes.BOOL,    wintypes.HANDLE)
_def(k32.IsWow64Process,           wintypes.BOOL,    wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
_def(k32.WaitForSingleObject,      wintypes.DWORD,   wintypes.HANDLE, wintypes.DWORD)
_def(k32.GetExitCodeThread,        wintypes.BOOL,    wintypes.HANDLE, wintypes.LPDWORD)
_def(k32.LoadLibraryW,             wintypes.HMODULE, wintypes.LPCWSTR)
_def(k32.FreeLibrary,              wintypes.BOOL,    wintypes.HMODULE)
_def(k32.CreateToolhelp32Snapshot, wintypes.HANDLE,  wintypes.DWORD, wintypes.DWORD)

MAX_MODULE_NAME32    = 255
TH32CS_SNAPMODULE    = 0x00000008
TH32CS_SNAPMODULE32  = 0x00000010
WAIT_OBJECT_0        = 0x00000000
WAIT_TIMEOUT_CODE    = 0x00000102
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",        wintypes.DWORD),
        ("th32ModuleID",  wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage",  wintypes.DWORD),
        ("ProccntUsage",  wintypes.DWORD),
        ("modBaseAddr",   ctypes.c_void_p),
        ("modBaseSize",   wintypes.DWORD),
        ("hModule",       wintypes.HMODULE),
        ("szModule",      wintypes.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     wintypes.WCHAR * wintypes.MAX_PATH),
    ]


_def(k32.Module32FirstW, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W))
_def(k32.Module32NextW,  wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W))

_def(ntdll.NtCreateThreadEx, ctypes.c_long,
     ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.LPVOID,
     wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.ULONG,
     ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, wintypes.LPVOID)

# ---------------------------------------------------------------------------
# Privilege
# ---------------------------------------------------------------------------

def enable_debug_privilege():
    """Enable SeDebugPrivilege once at startup so OpenProcess reaches any target."""
    try:
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges",     LUID_AND_ATTRIBUTES * 1)]

        h_token = wintypes.HANDLE()
        advapi32.OpenProcessToken(k32.GetCurrentProcess(),
                                  0x0020 | 0x0008, ctypes.byref(h_token))
        luid = LUID()
        advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount           = 1
        tp.Privileges[0].Luid       = luid
        tp.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp),
                                       ctypes.sizeof(tp), None, None)
        k32.CloseHandle(h_token)
        logger.debug("[Hook] SeDebugPrivilege enabled")
    except Exception:
        logger.warning("[Hook] Could not enable SeDebugPrivilege", exc_info=True)

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _get_target_arch_64(pid: int) -> bool:
    try:
        h = k32.OpenProcess(0x1000, False, pid)
        if h:
            is_wow64 = wintypes.BOOL()
            k32.IsWow64Process(h, ctypes.byref(is_wow64))
            k32.CloseHandle(h)
            return (not is_wow64.value) if platform.machine().endswith("64") else False
    except Exception:
        pass
    return True


def _create_remote_thread(h_proc, start_addr, param, pid: int, label: str):
    thread_id = wintypes.DWORD(0)
    h_thread  = k32.CreateRemoteThread(h_proc, None, 0, start_addr,
                                        param, 0, ctypes.byref(thread_id))
    if h_thread:
        logger.debug(f"[Hook] {label}: remote thread TID {thread_id.value}")
        return h_thread

    if not psutil.pid_exists(pid):
        logger.debug(f"[Hook] SKIP: PID {pid} terminated before {label}")
        return None

    logger.debug(f"[Hook] {label}: CreateRemoteThread failed, trying NtCreateThreadEx")
    h_nt     = wintypes.HANDLE()
    status   = ntdll.NtCreateThreadEx(ctypes.byref(h_nt), 0x1FFFFF, None,
                                       h_proc, start_addr, param, 0, 0, 0, 0, None)
    status_u = status & 0xFFFFFFFF
    if status_u == 0:
        get_tid          = ctypes.windll.kernel32.GetThreadId
        get_tid.restype  = wintypes.DWORD
        get_tid.argtypes = [wintypes.HANDLE]
        thread_id.value  = get_tid(h_nt.value)
        logger.debug(f"[Hook] {label}: NtCreateThreadEx TID {thread_id.value}")
        return h_nt.value
    if status_u == 0xC000010A:
        logger.debug(f"[Hook] SKIP: PID {pid} already terminating during {label}")
        return None

    logger.error(f"[Hook] {label}: thread creation failed NTSTATUS 0x{status_u:08X}")
    return None


def _wait_thread_exit(h_thread, timeout_ms: int, label: str):
    result = k32.WaitForSingleObject(h_thread, timeout_ms)
    if result == WAIT_OBJECT_0:
        exit_code = wintypes.DWORD()
        if k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code)):
            return True, exit_code.value
        logger.warning(f"[Hook] {label}: GetExitCodeThread failed "
                       f"({ctypes.get_last_error()})")
        return True, None
    if result == WAIT_TIMEOUT_CODE:
        logger.error(f"[Hook] {label}: timed out after {timeout_ms} ms")
        return False, None
    logger.error(f"[Hook] {label}: wait failed 0x{result:X}")
    return False, None


def _find_remote_module_base(pid: int, module_name: str,
                              retries: int = 20, delay: float = 0.1):
    target = module_name.lower()
    for _ in range(retries):
        snap = k32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap and snap != INVALID_HANDLE_VALUE:
            try:
                entry        = MODULEENTRY32W()
                entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
                ok = k32.Module32FirstW(snap, ctypes.byref(entry))
                while ok:
                    if (entry.szModule.lower() == target or
                            os.path.basename(entry.szExePath).lower() == target):
                        return int(entry.modBaseAddr or entry.hModule or 0)
                    ok = k32.Module32NextW(snap, ctypes.byref(entry))
            finally:
                k32.CloseHandle(snap)
        time.sleep(delay)
    return None

# ---------------------------------------------------------------------------
# Core injection (sync – run via asyncio.to_thread from scan_and_warn)
# ---------------------------------------------------------------------------

def inject(pid: int, name: str) -> bool:
    """
    Inject hook{32|64}.dll into *pid* and call HydraStartHook.
    Synchronous; called via asyncio.to_thread() from hook_python_process.
    Returns True on full success.
    """
    try:
        is_64      = _get_target_arch_64(pid)
        target_dll = hook_dll_64_path if is_64 else hook_dll_32_path
        dll_name   = os.path.basename(target_dll)

        if not os.path.exists(target_dll):
            logger.error(f"[Hook] DLL not found: {target_dll}")
            return False
        if not os.path.exists(hook_py_path):
            logger.error(f"[Hook] Hook script not found: {hook_py_path}")
            return False

        logger.info(f"[Hook] Injecting into {name} "
                    f"(PID: {pid}, {'x64' if is_64 else 'x86'})")

        os.makedirs(python_dumps_dir, exist_ok=True)
        config_path = os.path.join(python_dumps_dir, "hook_config.ini")
        with open(config_path, "w") as fh:
            fh.write(f"[General]\nHookPath={os.path.dirname(hook_py_path)}\n")
        logger.debug(f"[Hook] Config written: {config_path}")

        h_proc = k32.OpenProcess(0x1F0FFF, False, pid)
        if not h_proc:
            logger.error(f"[Hook] OpenProcess failed PID {pid} "
                         f"(error {ctypes.get_last_error()})")
            return False

        try:
            path_bytes = os.path.abspath(target_dll).encode("utf-16le") + b"\0\0"
            mem        = k32.VirtualAllocEx(h_proc, None, len(path_bytes), 0x3000, 0x04)
            if not mem:
                logger.error(f"[Hook] VirtualAllocEx failed PID {pid} "
                             f"(error {ctypes.get_last_error()})")
                return False

            written = ctypes.c_size_t(0)
            if not k32.WriteProcessMemory(h_proc, mem, path_bytes,
                                          len(path_bytes), ctypes.byref(written)):
                logger.error(f"[Hook] WriteProcessMemory failed PID {pid} "
                             f"(error {ctypes.get_last_error()})")
                return False

            load_lib = k32.GetProcAddress(
                k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
            if not load_lib:
                logger.error("[Hook] Could not resolve LoadLibraryW")
                return False

            h_load = _create_remote_thread(h_proc, load_lib, mem, pid, "LoadLibraryW")
            if not h_load:
                return False
            try:
                load_ok, load_exit = _wait_thread_exit(h_load, 5000, "LoadLibraryW")
            finally:
                k32.CloseHandle(h_load)

            if not load_ok or load_exit == 0:
                logger.error(f"[Hook] LoadLibraryW failed or returned NULL for PID {pid}")
                return False

            remote_mod = _find_remote_module_base(pid, dll_name)
            if not remote_mod:
                logger.error(f"[Hook] Cannot locate {dll_name} in PID {pid} after inject")
                return False

            logger.debug(f"[Hook] {dll_name} @ 0x{remote_mod:X} in PID {pid}")

            local_mod = k32.LoadLibraryW(target_dll)
            if not local_mod:
                logger.error(f"[Hook] Cannot load {dll_name} locally to resolve RVA")
                return False

            try:
                local_fn = k32.GetProcAddress(local_mod, b"HydraStartHook")
                if not local_fn:
                    logger.error(f"[Hook] HydraStartHook export not found in {dll_name}")
                    return False

                remote_fn = remote_mod + (local_fn - local_mod)
                h_start   = _create_remote_thread(h_proc, remote_fn, None,
                                                   pid, "HydraStartHook")
                if not h_start:
                    return False
                try:
                    start_ok, start_exit = _wait_thread_exit(h_start, 5000,
                                                             "HydraStartHook")
                finally:
                    k32.CloseHandle(h_start)

                if not start_ok:
                    return False

                if start_exit and start_exit != 0:
                    logger.warning(f"[Hook] HydraStartHook returned error {start_exit} "
                                   f"for {name} PID {pid}")
                else:
                    logger.info(f"[Hook] Hook active in {name} (PID: {pid})")
                return True
            finally:
                k32.FreeLibrary(local_mod)
        finally:
            k32.CloseHandle(h_proc)

    except Exception:
        logger.exception(f"[Hook] Unhandled exception injecting into {name} PID {pid}")
        return False

# ---------------------------------------------------------------------------
# Public async API – called from scan_and_warn
# ---------------------------------------------------------------------------

def _find_pids_for_exe(exe_path: str) -> list[tuple[int, str]]:
    """
    Return [(pid, name), ...] for every running process whose executable
    matches *exe_path*.  Skips our own PID and anything under the antivirus
    installation directory.
    """
    target  = os.path.normcase(os.path.normpath(exe_path))
    results = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.pid == os.getpid():
                continue
            proc_exe = proc.info.get('exe') or ""
            if not proc_exe:
                continue
            if os.path.normcase(os.path.normpath(proc_exe)).startswith(
                    _EXCLUDED_DIR_NORM):
                continue
            if os.path.normcase(os.path.normpath(proc_exe)) == target:
                results.append((proc.info['pid'],
                                proc.info['name'] or f"pid_{proc.pid}"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return results


async def hook_python_process(file_path: str) -> None:
    """
    Entry point called by scan_and_warn when it identifies a Python-based
    executable (PyInstaller, cx_Freeze, Nuitka, plain python.exe, etc.).

    Resolves the live PID(s) for *file_path*, skips already-hooked processes,
    and delegates to inject() via asyncio.to_thread so the event loop is
    never blocked.

    Usage in scan_and_warn (inside the relevant detection block):
        from .py_source_hook import hook_python_process
        asyncio.create_task(hook_python_process(norm_path))
    """
    try:
        norm_path  = os.path.normpath(os.path.abspath(file_path))
        candidates = await asyncio.to_thread(_find_pids_for_exe, norm_path)

        if not candidates:
            logger.debug(f"[Hook] No running process found for {norm_path}")
            return

        for pid, name in candidates:
            with _hooked_pids_lock:
                if pid in _hooked_pids:
                    logger.debug(f"[Hook] PID {pid} ({name}) already hooked, skipping")
                    continue
                # Reserve slot before awaiting to prevent duplicate injection
                _hooked_pids.add(pid)

            success = await asyncio.to_thread(inject, pid, name)
            if not success:
                # Allow retry on the next scan_and_warn invocation
                with _hooked_pids_lock:
                    _hooked_pids.discard(pid)
                logger.warning(f"[Hook] Injection failed for {name} (PID: {pid})")

    except Exception:
        logger.exception(f"[Hook] hook_python_process failed for {file_path}")
