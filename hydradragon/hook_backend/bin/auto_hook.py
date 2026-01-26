import ctypes, os, sys, time, threading, psutil, platform
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
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

# NtCreateThreadEx for fallback
class CLIENT_ID(ctypes.Structure):
    _fields_ = [("UniqueProcess", wintypes.HANDLE), ("UniqueThread", wintypes.HANDLE)]

_def(ntdll.NtCreateThreadEx, ctypes.c_long,
     ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.LPVOID,
     wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.ULONG,
     ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, wintypes.LPVOID)

class LiteInjector:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Arch-Aware Injector - FIXED")
        self.root.geometry("750x650")
        
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
        tk.Button(top, text="Refresh List", command=self.refresh).pack(side=tk.LEFT)
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

    def get_target_arch_64(self, pid):
        try:
            h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_INFORMATION
            if h:
                is_wow64 = wintypes.BOOL()
                k32.IsWow64Process(h, ctypes.byref(is_wow64))
                k32.CloseHandle(h)
                is_os_64 = platform.machine().endswith("64")
                # If OS is 64-bit and process is NOT WoW64, it's 64-bit
                # If OS is 64-bit and process IS WoW64, it's 32-bit
                return (not is_wow64.value) if is_os_64 else False
        except Exception as e:
            self.log(f"Arch detection error: {e}")
        return True  # Default to 64-bit

    def refresh(self):
        self.procs = [p for p in psutil.process_iter(['pid', 'name', 'exe'])]
        self.update_view()

    def update_view(self):
        self.tree.delete(*self.tree.get_children())
        q = self.search.get().lower()
        for p in self.procs:
            if self.is_target(p):
                pid, name, exe = p.info['pid'], p.info['name'], p.info['exe'] or ""
                if q in name.lower() or q in str(pid):
                    arch = "x64" if self.get_target_arch_64(pid) else "x86"
                    self.tree.insert("", tk.END, values=(pid, name, arch, exe))

    def run_inject(self):
        sel = self.tree.selection()
        if sel:
            pid, name = self.tree.item(sel[0])['values'][:2]
            threading.Thread(target=self.inject, args=(int(pid), name), daemon=True).start()

    def inject(self, pid, name):
        try:
            # Determine target architecture
            is_target_64 = self.get_target_arch_64(pid)
            
            # Get DLL directory and determine correct DLL
            dll_path = self.dll_var.get()
            dll_dir = os.path.dirname(os.path.abspath(dll_path))
            target_dll_name = "hook64.dll" if is_target_64 else "hook32.dll"
            target_dll_path = os.path.join(dll_dir, target_dll_name)
            
            # Verify DLL exists
            if not os.path.exists(target_dll_path):
                self.log(f"ERROR: {target_dll_name} not found at {dll_dir}")
                return

            self.log(f"Target: {name} (PID: {pid}, Arch: {'x64' if is_target_64 else 'x86'})")
            self.log(f"Using DLL: {target_dll_path}")
            
            # Create config file - CRITICAL FIX: Use correct path
            config_dir = "C:\\pythondumps"
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "hook_config.ini")
            
            hook_dir = os.path.dirname(os.path.abspath(self.hook_var.get()))
            with open(config_path, "w") as f:
                f.write(f"[General]\nHookPath={hook_dir}\n")
            
            self.log(f"Config written to: {config_path}")

            # Open target process with full access
            PROCESS_ALL_ACCESS = 0x1F0FFF
            h_proc = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_proc:
                error = ctypes.get_last_error()
                self.log(f"ERROR: OpenProcess failed (error {error}). Try running as admin!")
                return

            try:
                # Allocate memory in target process
                path_bytes = os.path.abspath(target_dll_path).encode('utf-16le') + b'\0\0'
                path_size = len(path_bytes)
                
                mem = k32.VirtualAllocEx(h_proc, None, path_size, 0x3000, 0x04)  # MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
                if not mem:
                    error = ctypes.get_last_error()
                    self.log(f"ERROR: VirtualAllocEx failed (error {error})")
                    return
                
                self.log(f"Allocated {path_size} bytes at 0x{mem:X}")
                
                # Write DLL path to target process - CRITICAL FIX
                bytes_written = ctypes.c_size_t(0)
                if not k32.WriteProcessMemory(h_proc, mem, path_bytes, path_size, ctypes.byref(bytes_written)):
                    error = ctypes.get_last_error()
                    self.log(f"ERROR: WriteProcessMemory failed (error {error})")
                    return
                
                self.log(f"Wrote {bytes_written.value} bytes to target process")
                
                # Get LoadLibraryW address
                k32_mod = k32.GetModuleHandleW("kernel32.dll")
                load_lib = k32.GetProcAddress(k32_mod, b"LoadLibraryW")
                
                if not load_lib:
                    self.log("ERROR: Could not find LoadLibraryW")
                    return
                
                self.log(f"LoadLibraryW at 0x{load_lib:X}")
                
                # Create remote thread - CRITICAL FIX
                thread_id = wintypes.DWORD(0)
                h_thread = k32.CreateRemoteThread(
                    h_proc,           # hProcess
                    None,             # lpThreadAttributes
                    0,                # dwStackSize
                    load_lib,         # lpStartAddress
                    mem,              # lpParameter
                    0,                # dwCreationFlags
                    ctypes.byref(thread_id)  # lpThreadId - proper pointer
                )
                
                if not h_thread:
                    # Try NtCreateThreadEx fallback
                    self.log("CreateRemoteThread failed, trying NtCreateThreadEx...")
                    h_thread_nt = wintypes.HANDLE()
                    status = ntdll.NtCreateThreadEx(
                        ctypes.byref(h_thread_nt),
                        0x1FFFFF,  # THREAD_ALL_ACCESS
                        None,
                        h_proc,
                        load_lib,
                        mem,
                        0,  # Not suspended
                        0, 0, 0, 0,
                        None
                    )
                    
                    if status == 0:  # STATUS_SUCCESS
                        h_thread = h_thread_nt.value
                        self.log(f"NtCreateThreadEx succeeded (TID: {thread_id.value})")
                    else:
                        self.log(f"ERROR: Both CreateRemoteThread and NtCreateThreadEx failed (NTSTATUS: 0x{status:X})")
                        return

                if h_thread:
                    self.log(f"Remote thread created (TID: {thread_id.value})")
                    
                    # Wait for thread to complete (with timeout)
                    wait_result = k32.WaitForSingleObject(h_thread, 5000)  # 5 second timeout
                    
                    if wait_result == 0:  # WAIT_OBJECT_0
                        exit_code = wintypes.DWORD()
                        if k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code)):
                            if exit_code.value == 0:
                                self.log(f"SUCCESS: {target_dll_name} injected into {name}!")
                            else:
                                self.log(f"WARNING: Thread exited with code {exit_code.value}")
                        else:
                            self.log("SUCCESS: Injection completed (could not get exit code)")
                    elif wait_result == 0x102:  # WAIT_TIMEOUT
                        self.log("Thread still running after 5 seconds (may be OK)")
                    else:
                        self.log(f"Wait returned: 0x{wait_result:X}")
                    
                    k32.CloseHandle(h_thread)
                
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
                for p in psutil.process_iter(['pid', 'name', 'exe']):
                    if p.pid not in self.processed and p.pid != os.getpid() and self.is_target(p):
                        self.processed.add(p.pid)
                        self.inject(p.pid, p.name())
            except Exception as e:
                self.log(f"Ninja error: {e}")
            time.sleep(1.5)

if __name__ == "__main__":
    # Check admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        self_path = sys.executable if getattr(sys, 'frozen', False) else __file__
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, 
            f'"{self_path}"', None, 1
        )
        sys.exit()
    
    root = tk.Tk()
    LiteInjector(root)
    root.mainloop()
