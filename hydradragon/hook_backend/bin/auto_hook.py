#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ctypes, os, sys, time, threading, psutil, platform
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from ctypes import wintypes

# --- Windows API Setup ---
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

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
_def(k32.CreateToolhelp32Snapshot, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD)

MAX_MODULE_NAME32 = 255
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wintypes.WCHAR * wintypes.MAX_PATH),
    ]

_def(k32.Module32FirstW, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W))
_def(k32.Module32NextW, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W))

# NtCreateThreadEx for fallback
class CLIENT_ID(ctypes.Structure):
    _fields_ = [("UniqueProcess", wintypes.HANDLE), ("UniqueThread", wintypes.HANDLE)]

_def(ntdll.NtCreateThreadEx, ctypes.c_long,
     ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.LPVOID,
     wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.ULONG,
     ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, wintypes.LPVOID)

def enable_debug_privilege():
    """Enable SeDebugPrivilege so OpenProcess works on protected targets."""
    try:
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY             = 0x0008
        SE_PRIVILEGE_ENABLED    = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        h_token = wintypes.HANDLE()
        advapi32.OpenProcessToken(
            k32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token)
        )
        luid = LUID()
        advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
        k32.CloseHandle(h_token)
    except Exception as e:
        print(f"[WARN] Could not enable SeDebugPrivilege: {e}")

class LiteInjector:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Arch-Aware Injector - FIXED")
        self.root.geometry("750x650")
        
        enable_debug_privilege()
        self.ninja_on, self.processed = False, set()
        self.hook_var = tk.StringVar(value=self._path("__hook__.py"))
        
        is_os_64 = platform.machine().endswith("64")
        # Store the BASE path (directory containing both DLLs)
        dll_dir = os.path.dirname(os.path.abspath(__file__))
        default_dll = os.path.join(dll_dir, "hook64.dll" if is_os_64 else "hook32.dll")
        self.dll_var = tk.StringVar(value=default_dll)
        self.hide_std = tk.BooleanVar(value=True)

        self._build_ui()
        self.refresh()

    def _path(self, name):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        return p if os.path.exists(p) else name

    def _build_ui(self):
        # 1. Filters
        top = tk.Frame(self.root, pady=5)
        top.pack(fill=tk.X, padx=10)
        self.btn_refresh = tk.Button(top, text="Refresh List", command=self.refresh)
        self.btn_refresh.pack(side=tk.LEFT)
        self.search = tk.Entry(top)
        self.search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.search.bind("<KeyRelease>", lambda e: self.update_view())
        tk.Checkbutton(top, text="Hide System Pythons", variable=self.hide_std, command=self.update_view).pack(side=tk.RIGHT)

        # 2. Process Tree
        cols = ("PID", "Name", "Arch", "Path")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=12)
        for c, w in zip(cols, (70, 150, 70, 450)): 
            self.tree.heading(c, text=c); self.tree.column(c, width=w)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10)
        self.tree.bind("<Double-1>", lambda e: self.run_inject())

        # 3. Settings
        cfg = tk.LabelFrame(self.root, text="Injection Settings", padx=10, pady=5)
        cfg.pack(fill=tk.X, padx=10, pady=10)
        
        h_row = tk.Frame(cfg); h_row.pack(fill=tk.X, pady=2)
        tk.Label(h_row, text="Hook Script:").pack(side=tk.LEFT)
        tk.Entry(h_row, textvariable=self.hook_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        tk.Button(h_row, text="Browse", command=lambda: self.hook_var.set(filedialog.askopenfilename() or self.hook_var.get())).pack(side=tk.RIGHT)

        d_row = tk.Frame(cfg); d_row.pack(fill=tk.X, pady=2)
        tk.Label(d_row, text="DLL Path (auto-swaps 32/64):").pack(side=tk.LEFT)
        self.dll_ent = tk.Entry(d_row, textvariable=self.dll_var)
        self.dll_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        tk.Button(d_row, text="Browse", command=self._browse_dll).pack(side=tk.RIGHT)

        btns = tk.Frame(self.root, pady=5); btns.pack(fill=tk.X, padx=10)
        self.btn_ninja = tk.Button(btns, text="Ninja Mode: OFF", command=self.toggle_ninja, width=15)
        self.btn_ninja.pack(side=tk.LEFT)
        tk.Button(btns, text="INJECT NOW", bg="#d32f2f", fg="white", font=("Arial", 9, "bold"), command=self.run_inject).pack(side=tk.RIGHT)

        self.log_box = scrolledtext.ScrolledText(self.root, height=6, state='disabled', bg="#1e1e1e", fg="#00ff00", font=("Consolas", 8))
        self.log_box.pack(fill=tk.X, padx=10, pady=5)

    def _browse_dll(self):
        f = filedialog.askopenfilename(filetypes=[("DLL Files", "*.dll"), ("All Files", "*.*")])
        if f:
            self.dll_var.set(f)

    def log(self, m):
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self.log, m)
            return
        self.log_box.config(state='normal')
        self.log_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {m}\n")
        self.log_box.see(tk.END)
        self.log_box.config(state='disabled')

    def is_target(self, p):
        try:
            exe = (p.info['exe'] or "").lower()
            if self.hide_std.get() and any(x in exe for x in ["program files", "windows", "appdata\\local\\programs\\python"]):
                return False
            # Check for python3.dll in modules
            try:
                for m in p.memory_maps():
                    if "python3" in os.path.basename(m.path).lower():
                        return True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except:
            pass
        return False

    def _log_threadsafe(self, m):
        """Schedule a log write on the main thread; safe to call from any thread."""
        self.root.after(0, self.log, m)

    def _create_remote_thread(self, h_proc, start_addr, param, pid, label):
        thread_id = wintypes.DWORD(0)
        h_thread = k32.CreateRemoteThread(
            h_proc,
            None,
            0,
            start_addr,
            param,
            0,
            ctypes.byref(thread_id),
        )
        if h_thread:
            self.log(f"{label}: remote thread created (TID: {thread_id.value})")
            return h_thread

        if not psutil.pid_exists(pid):
            self.log(f"SKIP: PID {pid} terminated before {label.lower()} thread creation")
            return None

        self.log(f"{label}: CreateRemoteThread failed, trying NtCreateThreadEx...")
        h_thread_nt = wintypes.HANDLE()
        status = ntdll.NtCreateThreadEx(
            ctypes.byref(h_thread_nt),
            0x1FFFFF,
            None,
            h_proc,
            start_addr,
            param,
            0,
            0,
            0,
            0,
            None,
        )
        status_u = status & 0xFFFFFFFF
        if status_u == 0:
            h_thread = h_thread_nt.value
            get_thread_id = ctypes.windll.kernel32.GetThreadId
            get_thread_id.restype = wintypes.DWORD
            get_thread_id.argtypes = [wintypes.HANDLE]
            thread_id.value = get_thread_id(h_thread)
            self.log(f"{label}: NtCreateThreadEx succeeded (TID: {thread_id.value})")
            return h_thread
        if status_u == 0xC000010A:
            self.log(f"SKIP: PID {pid} is already terminating during {label.lower()}")
            return None

        self.log(f"ERROR: {label} thread creation failed (NTSTATUS: 0x{status_u:08X})")
        return None

    def _wait_thread_exit(self, h_thread, timeout_ms, label):
        wait_result = k32.WaitForSingleObject(h_thread, timeout_ms)
        if wait_result == WAIT_OBJECT_0:
            exit_code = wintypes.DWORD()
            if k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code)):
                return True, exit_code.value
            self.log(f"WARNING: {label} completed but GetExitCodeThread failed ({ctypes.get_last_error()})")
            return True, None
        if wait_result == WAIT_TIMEOUT:
            self.log(f"ERROR: {label} timed out after {timeout_ms}ms")
            return False, None

        self.log(f"ERROR: {label} wait failed: 0x{wait_result:X}")
        return False, None

    def _find_remote_module_base(self, pid, module_name, retries=20, delay=0.1):
        target_name = module_name.lower()
        for _ in range(retries):
            snapshot = k32.CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pid,
            )
            if snapshot and snapshot != INVALID_HANDLE_VALUE:
                try:
                    entry = MODULEENTRY32W()
                    entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
                    ok = k32.Module32FirstW(snapshot, ctypes.byref(entry))
                    while ok:
                        module_basename = entry.szModule.lower()
                        exe_basename = os.path.basename(entry.szExePath).lower()
                        if module_basename == target_name or exe_basename == target_name:
                            return int(entry.modBaseAddr or entry.hModule or 0)
                        ok = k32.Module32NextW(snapshot, ctypes.byref(entry))
                finally:
                    k32.CloseHandle(snapshot)
            time.sleep(delay)
        return None

    def get_target_arch_64(self, pid):
        # Called from background refresh thread AND main thread during inject.
        # Must NEVER call self.log() directly; Tkinter is not thread-safe.
        try:
            h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_INFORMATION
            if h:
                is_wow64 = wintypes.BOOL()
                k32.IsWow64Process(h, ctypes.byref(is_wow64))
                k32.CloseHandle(h)
                is_os_64 = platform.machine().endswith("64")
                # Not WoW64 on a 64-bit OS -> native 64-bit process
                return (not is_wow64.value) if is_os_64 else False
        except Exception:
            pass
        return True  # Default to 64-bit

    def refresh(self):
        """Scan processes in a background thread so the UI never freezes."""
        self._set_refresh_btn('disabled')
        threading.Thread(target=self._refresh_worker, daemon=True).start()

    def _set_refresh_btn(self, state):
        try:
            self.btn_refresh.config(state=state)
        except Exception:
            pass

    def _refresh_worker(self):
        rows = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if self.is_target(p):
                        pid  = p.info['pid']
                        name = p.info['name'] or ""
                        exe  = p.info['exe']  or ""
                        arch = "x64" if self.get_target_arch_64(pid) else "x86"
                        rows.append((pid, name, arch, exe))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        self.root.after(0, self._refresh_done, rows)

    def _refresh_done(self, rows):
        self._proc_rows = rows
        self.update_view()
        self._set_refresh_btn('normal')

    def update_view(self):
        self.tree.delete(*self.tree.get_children())
        q = self.search.get().lower()
        for (pid, name, arch, exe) in getattr(self, '_proc_rows', []):
            if q in name.lower() or q in str(pid):
                self.tree.insert("", tk.END, values=(pid, name, arch, exe))

    def run_inject(self):
        sel = self.tree.selection()
        if sel:
            pid, name = self.tree.item(sel[0])['values'][:2]
            threading.Thread(target=self.inject, args=(int(pid), name), daemon=True).start()

    def inject(self, pid, name):
        try:
            is_target_64 = self.get_target_arch_64(pid)

            dll_path = self.dll_var.get()
            dll_dir = os.path.dirname(os.path.abspath(dll_path))
            target_dll_name = "hook64.dll" if is_target_64 else "hook32.dll"
            target_dll_path = os.path.join(dll_dir, target_dll_name)

            if not os.path.exists(target_dll_path):
                self.log(f"ERROR: {target_dll_name} not found at {dll_dir}")
                return

            hook_path = os.path.abspath(self.hook_var.get())
            if not os.path.exists(hook_path):
                self.log(f"ERROR: Hook script not found: {hook_path}")
                return

            self.log(f"Target: {name} (PID: {pid}, Arch: {'x64' if is_target_64 else 'x86'})")
            self.log(f"Using DLL: {target_dll_path}")

            config_dir = "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps"
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "hook_config.ini")
            hook_dir = os.path.dirname(hook_path)
            with open(config_path, "w") as f:
                f.write(f"[General]\nHookPath={hook_dir}\n")

            self.log(f"Config written to: {config_path}")

            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_proc = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_proc:
                error = ctypes.get_last_error()
                self.log(f"ERROR: OpenProcess failed (error {error}). Try running as admin!")
                return

            try:
                path_bytes = os.path.abspath(target_dll_path).encode("utf-16le") + b"\0\0"
                path_size = len(path_bytes)
                mem = k32.VirtualAllocEx(h_proc, None, path_size, 0x3000, 0x04)
                if not mem:
                    error = ctypes.get_last_error()
                    self.log(f"ERROR: VirtualAllocEx failed (error {error})")
                    return

                self.log(f"Allocated {path_size} bytes at 0x{mem:X}")

                bytes_written = ctypes.c_size_t(0)
                if not k32.WriteProcessMemory(h_proc, mem, path_bytes, path_size, ctypes.byref(bytes_written)):
                    error = ctypes.get_last_error()
                    self.log(f"ERROR: WriteProcessMemory failed (error {error})")
                    return

                self.log(f"Wrote {bytes_written.value} bytes to target process")

                k32_mod = k32.GetModuleHandleW("kernel32.dll")
                load_lib = k32.GetProcAddress(k32_mod, b"LoadLibraryW")
                if not load_lib:
                    self.log("ERROR: Could not find LoadLibraryW")
                    return

                self.log(f"LoadLibraryW at 0x{load_lib:X}")

                h_load_thread = self._create_remote_thread(h_proc, load_lib, mem, pid, "LoadLibraryW")
                if not h_load_thread:
                    return

                try:
                    load_ok, load_exit = self._wait_thread_exit(h_load_thread, 5000, "LoadLibraryW")
                finally:
                    k32.CloseHandle(h_load_thread)

                if not load_ok:
                    return
                if load_exit == 0:
                    self.log("ERROR: LoadLibraryW returned NULL; DLL load failed")
                    return

                remote_mod = self._find_remote_module_base(pid, target_dll_name)
                if not remote_mod:
                    self.log(f"ERROR: Could not locate {target_dll_name} in target process after injection")
                    return

                self.log(f"SUCCESS: {target_dll_name} injected into {name} (module @ 0x{remote_mod:X})")

                local_mod = k32.LoadLibraryW(target_dll_path)
                if not local_mod:
                    self.log("ERROR: Could not load DLL locally to resolve HydraStartHook RVA")
                    return

                try:
                    local_fn = k32.GetProcAddress(local_mod, b"HydraStartHook")
                    if not local_fn:
                        self.log("ERROR: Export HydraStartHook not found in DLL")
                        return

                    rva = local_fn - local_mod
                    remote_fn = remote_mod + rva
                    self.log(f"HydraStartHook RVA: 0x{rva:X}")
                    self.log(f"Remote HydraStartHook: 0x{remote_fn:X}")

                    h_start_thread = self._create_remote_thread(
                        h_proc,
                        remote_fn,
                        None,
                        pid,
                        "HydraStartHook",
                    )
                    if not h_start_thread:
                        return

                    try:
                        start_ok, start_exit = self._wait_thread_exit(h_start_thread, 5000, "HydraStartHook")
                    finally:
                        k32.CloseHandle(h_start_thread)

                    if not start_ok:
                        return

                    if start_exit is None:
                        self.log("SUCCESS: HydraStartHook completed")
                    elif start_exit == 0:
                        self.log("SUCCESS: DLL loaded and hook started")
                    else:
                        self.log(f"WARNING: HydraStartHook returned error {start_exit}")
                finally:
                    k32.FreeLibrary(local_mod)
            finally:
                k32.CloseHandle(h_proc)
        except Exception as e:
            self.log(f"EXCEPTION: {type(e).__name__}: {e}")
            import traceback
            self.log(traceback.format_exc())

    def toggle_ninja(self):
        self.ninja_on = not self.ninja_on
        self.btn_ninja.config(
            text="Ninja: ON" if self.ninja_on else "Ninja: OFF",
            bg="#4caf50" if self.ninja_on else "SystemButtonFace"
        )
        if self.ninja_on:
            threading.Thread(target=self.ninja_loop, daemon=True).start()

    def ninja_loop(self):
        while self.ninja_on:
            try:
                # Prune stale PIDs so recycled PIDs are not permanently skipped
                self.processed = {pid for pid in self.processed if psutil.pid_exists(pid)}
                for p in psutil.process_iter(['pid', 'name', 'exe']):
                    if p.pid not in self.processed and p.pid != os.getpid() and self.is_target(p):
                        self.processed.add(p.pid)
                        threading.Thread(target=self.inject, args=(p.pid, p.name()), daemon=True).start()
            except Exception as e:
                self._log_threadsafe(f"Ninja error: {e}")

if __name__ == "__main__":
    # Check admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        exe_path = sys.executable
        params = "" if getattr(sys, 'frozen', False) else f'"{os.path.abspath(__file__)}"'
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe_path,
            params, None, 1
        )
        sys.exit()

    root = tk.Tk()
    LiteInjector(root)
    root.mainloop()
