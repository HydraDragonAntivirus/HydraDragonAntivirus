/**
 * hook_dll.cpp
 * Toolchain: MSVC / VS 2022  (x64)
 *
 * Build:
 *   build_dll.bat   (see companion file)
 *
 * DESIGN RULE: No char[] local stack buffers for path construction anywhere.
 * All path ops use std::string to prevent /GS cookie overflows (0xc0000409).
 * Only char[MAX_PATH] used where a Win32 API requires an output buffer of
 * that exact size — those APIs guarantee they write at most MAX_PATH chars.
 */

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <string>
#include <vector>
#include <algorithm>
#include <stdint.h>

#ifndef strcasecmp
#  define strcasecmp _stricmp
#endif

// ─── Globals ──────────────────────────────────────────────────────────────────
static std::string       g_pythonHomePath;
#define PYMODULE_NAME    "__hook__"

static HINSTANCE         g_hInstance        = nullptr;
static FILE             *g_logFile          = nullptr;
static CRITICAL_SECTION  g_logCS;
static volatile LONG     g_logCSState       = 0; // 0=uninitialized, 1=ready, 2=destroying
static HANDLE            g_workerThread     = nullptr;
static DWORD             g_workerThreadId   = 0;
static HANDLE            g_shutdownEvent    = nullptr;
static volatile LONG     g_started          = 0;
static volatile LONG     g_stopRequested    = 0;
static volatile LONG     g_unloading        = 0;

// ─── Thread-safe debug print ──────────────────────────────────────────────────
static void dbgPrintf(const char *fmt, ...) {
    char    buf[2048];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(buf, sizeof(buf) - 1u, fmt, ap);
    buf[sizeof(buf) - 1] = '\0';
    va_end(ap);

    OutputDebugStringA(buf);

    if (InterlockedCompareExchange(&g_unloading, 0, 0) != 0)
        return;

    if (InterlockedCompareExchange(&g_logCSState, 0, 0) == 1) {
        __try {
            EnterCriticalSection(&g_logCS);
            if (g_logFile) {
                fprintf(g_logFile, "%s", buf);
                fflush(g_logFile);
            }
            LeaveCriticalSection(&g_logCS);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Never crash the host process from logging.
        }
    }
}

// ─── Anti-tamper / debugger check ─────────────────────────────────────────────
static void CheckForProtection() {
    if (IsDebuggerPresent())
        dbgPrintf("[HOOK] WARNING: Debugger detected!\n");

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (hK32) {
        const BYTE *p = reinterpret_cast<const BYTE *>(
            GetProcAddress(hK32, "LoadLibraryW"));
        if (p && (*p == 0xE9 || *p == 0xEB))
            dbgPrintf("[HOOK] WARNING: LoadLibraryW appears to be hooked!\n");
    }
}

// ─── Config reader ────────────────────────────────────────────────────────────
static std::string GetHookFilePathFromConfig() {
    const char *cfgPath =
        "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps\\hook_config.ini";

    FILE *f = nullptr;
    if (fopen_s(&f, cfgPath, "r") != 0 || !f) return {};

    char line[4096];
    std::string result;
    while (fgets(line, static_cast<int>(sizeof(line)), f)) {
        if (strncmp(line, "HookPath=", 9) == 0) {
            char *path = line + 9;
            char *nl   = strpbrk(path, "\r\n");
            if (nl) *nl = '\0';
            if (path[0] != '\0') {
                result = std::string(path) + "\\" + PYMODULE_NAME + ".py";
                break;
            }
        }
    }
    fclose(f);
    return result;
}

// ─── Find python.exe in running processes ─────────────────────────────────────
static std::string FindPythonExePath() {
    UINT prev = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    SetErrorMode(prev);
    if (hSnap == INVALID_HANDLE_VALUE) return {};

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    std::string result;
    if (Process32First(hSnap, &pe32)) {
        do {
            if (strcasecmp(pe32.szExeFile, "python.exe")  == 0 ||
                strcasecmp(pe32.szExeFile, "pythonw.exe") == 0) {
                HANDLE hProc = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    FALSE, pe32.th32ProcessID);
                if (hProc) {
                    char buf[MAX_PATH];
                    if (GetModuleFileNameExA(hProc, nullptr, buf, MAX_PATH))
                        result = buf;
                    CloseHandle(hProc);
                    if (!result.empty()) break;
                }
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return result;
}

// ─── Validate Python home: does dir\Lib exist? ────────────────────────────────
static bool IsValidPythonHome(const std::string &dir) {
    std::string libPath = dir + "\\Lib";
    DWORD attr = GetFileAttributesA(libPath.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

// ─── Scan a base path for Python3x subdirs ────────────────────────────────────
static std::string ScanBasePathForPython(const std::string &basePath) {
    std::string pat = basePath + "\\Python3*";

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pat.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return {};

    std::vector<std::string> found;
    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            strcmp(fd.cFileName, ".")  != 0 &&
            strcmp(fd.cFileName, "..") != 0) {
            std::string candidate = basePath + "\\" + fd.cFileName;
            if (IsValidPythonHome(candidate))
                found.push_back(fd.cFileName);
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (found.empty()) return {};
    std::sort(found.rbegin(), found.rend());
    return basePath + "\\" + found[0];
}

// ─── Enumerate well-known Python install locations ────────────────────────────
static std::string FindPythonInstallation() {
    {
        std::string r = ScanBasePathForPython("C:");
        if (!r.empty()) return r;
    }

    char base[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, base))) {
        std::string r = ScanBasePathForPython(base);
        if (!r.empty()) return r;
    }
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROGRAM_FILESX86, nullptr, 0, base))) {
        std::string r = ScanBasePathForPython(base);
        if (!r.empty()) return r;
    }
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, base))) {
        std::string b(base);
        std::string r = ScanBasePathForPython(b + "\\Programs\\Python");
        if (!r.empty()) return r;
        r = ScanBasePathForPython(b + "\\Programs");
        if (!r.empty()) return r;
    }
    return {};
}

// ─── Auto-detect and set PYTHONHOME/PYTHONPATH ────────────────────────────────
static void AutoSetPythonHome() {
    {
        char existing[MAX_PATH];
        if (GetEnvironmentVariableA("PYTHONHOME", existing, MAX_PATH) > 0) {
            dbgPrintf("[HOOK] PYTHONHOME already set: %s\n", existing);
            g_pythonHomePath = existing;
            return;
        }
    }

    std::string pythonHome;

    // Method 0: current process is python.exe
    {
        char exeBuf[MAX_PATH];
        if (GetModuleFileNameA(nullptr, exeBuf, MAX_PATH)) {
            const char *fn = strrchr(exeBuf, '\\');
            fn = fn ? fn + 1 : exeBuf;
            if (strcasecmp(fn, "python.exe")  == 0 ||
                strcasecmp(fn, "pythonw.exe") == 0) {
                std::string dir(exeBuf);
                size_t sl = dir.rfind('\\');
                if (sl != std::string::npos) dir.resize(sl);
                if (IsValidPythonHome(dir)) {
                    pythonHome = dir;
                    dbgPrintf("[HOOK] Method 0: %s\n", pythonHome.c_str());
                }
            }
        }
    }

    // Method 1: find python.exe in running processes
    if (pythonHome.empty()) {
        std::string pyExe = FindPythonExePath();
        if (!pyExe.empty()) {
            size_t sl = pyExe.rfind('\\');
            std::string dir = (sl != std::string::npos) ? pyExe.substr(0, sl) : pyExe;
            if (IsValidPythonHome(dir)) {
                pythonHome = dir;
                dbgPrintf("[HOOK] Method 1: %s\n", pythonHome.c_str());
            }
        }
    }

    // Method 2: common install paths
    if (pythonHome.empty()) {
        pythonHome = FindPythonInstallation();
        if (!pythonHome.empty())
            dbgPrintf("[HOOK] Method 2: %s\n", pythonHome.c_str());
    }

    // Method 3: walk PATH
    if (pythonHome.empty()) {
        char *pathEnv = static_cast<char *>(malloc(32768));
        if (pathEnv) {
            DWORD len = GetEnvironmentVariableA("PATH", pathEnv, 32768);
            if (len > 0 && len < 32768) {
                char *ctx = nullptr;
                char *tok = strtok_s(pathEnv, ";", &ctx);
                while (tok) {
                    std::string dir(tok);
                    std::string testExe = dir + "\\python.exe";
                    DWORD attr = GetFileAttributesA(testExe.c_str());
                    if (attr != INVALID_FILE_ATTRIBUTES &&
                        !(attr & FILE_ATTRIBUTE_DIRECTORY) &&
                        IsValidPythonHome(dir)) {
                        pythonHome = dir;
                        dbgPrintf("[HOOK] Method 3: %s\n", pythonHome.c_str());
                        break;
                    }
                    tok = strtok_s(nullptr, ";", &ctx);
                }
            }
            free(pathEnv);
        }
    }

    if (!pythonHome.empty()) {
        g_pythonHomePath = pythonHome;
        SetEnvironmentVariableA("PYTHONHOME", pythonHome.c_str());
        std::string pyPath =
            pythonHome + "\\Lib;" + pythonHome + "\\Lib\\site-packages";
        SetEnvironmentVariableA("PYTHONPATH", pyPath.c_str());
        dbgPrintf("[HOOK] PYTHONHOME=%s\n", pythonHome.c_str());
        dbgPrintf("[HOOK] PYTHONPATH=%s\n", pyPath.c_str());
    } else {
        dbgPrintf("[HOOK] Could not auto-detect PYTHONHOME\n");
    }
}

// ─── Open log file ────────────────────────────────────────────────────────────
static std::string SetupLog() {
    const char *logDir =
        "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps";
    CreateDirectoryA(logDir, nullptr);

    if (InterlockedCompareExchange(&g_logCSState, 1, 0) == 0) {
        InitializeCriticalSection(&g_logCS);
    }

    std::string logPath = std::string(logDir) + "\\hook_dll.log";
    FILE *f = nullptr;
    fopen_s(&f, logPath.c_str(), "a");
    if (f) {
        setvbuf(f, nullptr, _IOLBF, 0);
        g_logFile = f;
    }
    dbgPrintf("[HOOK] Log: %s\n", logPath.c_str());
    return logPath;
}

// ─── Replace backslashes with forward slashes ─────────────────────────────────
static std::string ToFwdSlash(std::string s) {
    for (char &c : s) if (c == '\\') c = '/';
    return s;
}

// ─── Python C-API typedefs ────────────────────────────────────────────────────
using PyGILState_STATE     = int;
using PyImportModuleFunc   = void *(*)(const char *);
using Py_DecRefFunc        = void  (*)(void *);
using PyGILState_EnsureT   = PyGILState_STATE (*)();
using PyGILState_ReleaseT  = void  (*)(PyGILState_STATE);
using PyErr_PrintFunc      = void  (*)();
using PyRun_SimpleStrFunc  = int   (*)(const char *);
using Py_IsInitializedFunc = int   (*)();

static bool StopRequested() {
    return InterlockedCompareExchange(&g_stopRequested, 0, 0) != 0 ||
           (g_shutdownEvent && WaitForSingleObject(g_shutdownEvent, 0) == WAIT_OBJECT_0);
}

// ─── Main hook thread ─────────────────────────────────────────────────────────
static DWORD WINAPI hookImpl([[maybe_unused]] LPVOID) {
    AutoSetPythonHome();
    if (StopRequested()) { dbgPrintf("[HOOK] Stop requested before init\n"); return 1; }
    CheckForProtection();
    std::string logPath = SetupLog();
    if (StopRequested()) { dbgPrintf("[HOOK] Stop requested after log setup\n"); return 1; }

    // ── Locate python3x.dll ───────────────────────────────────────────────────
    std::string dllName;
    HMODULE hPyDll = GetModuleHandleA("python3.dll");
    if (hPyDll) {
        dllName = "python3.dll";
        dbgPrintf("[HOOK] Found python3.dll\n");
    } else {
        char buf[32];
        for (int i = 99; i >= 0; --i) {
            snprintf(buf, sizeof(buf), "python3%d.dll", i);
            hPyDll = GetModuleHandleA(buf);
            if (hPyDll) {
                dllName = buf;
                dbgPrintf("[HOOK] Found %s\n", buf);
                break;
            }
        }
    }
    if (!hPyDll) { dbgPrintf("[HOOK] ERROR: No python3x.dll\n"); return 1; }
    if (StopRequested()) { dbgPrintf("[HOOK] Stop requested before C-API resolve\n"); return 1; }

    // ── Resolve Python C-API ──────────────────────────────────────────────────
    auto PyImport_ImportModule =
        reinterpret_cast<PyImportModuleFunc> (GetProcAddress(hPyDll, "PyImport_ImportModule"));
    auto Py_DecRef =
        reinterpret_cast<Py_DecRefFunc>      (GetProcAddress(hPyDll, "Py_DecRef"));
    auto PyGILState_Ensure =
        reinterpret_cast<PyGILState_EnsureT> (GetProcAddress(hPyDll, "PyGILState_Ensure"));
    auto PyGILState_Release =
        reinterpret_cast<PyGILState_ReleaseT>(GetProcAddress(hPyDll, "PyGILState_Release"));
    auto PyErr_Print =
        reinterpret_cast<PyErr_PrintFunc>    (GetProcAddress(hPyDll, "PyErr_Print"));
    auto PyRun_SimpleString =
        reinterpret_cast<PyRun_SimpleStrFunc>(GetProcAddress(hPyDll, "PyRun_SimpleString"));
    auto Py_IsInitialized =
        reinterpret_cast<Py_IsInitializedFunc>(GetProcAddress(hPyDll, "Py_IsInitialized"));

    if (!PyImport_ImportModule || !PyGILState_Ensure || !PyGILState_Release) {
        dbgPrintf("[HOOK] ERROR: missing C-API symbols\n"); return 1;
    }

    // ── Wait for Python to initialize ─────────────────────────────────────────
    if (Py_IsInitialized) {
        int waited = 0;
        while (!Py_IsInitialized() && waited < 10000) { Sleep(50); waited += 50; }
        if (!Py_IsInitialized()) {
            dbgPrintf("[HOOK] ERROR: Python not initialized after 10s\n"); return 1;
        }
        dbgPrintf("[HOOK] Python ready (waited %dms)\n", waited);
    }

    if (StopRequested()) { dbgPrintf("[HOOK] Stop requested before GIL\n"); return 1; }
    PyGILState_STATE gil = PyGILState_Ensure();

    // ── Python setup: fix sys.path, redirect I/O ──────────────────────────────
    if (PyRun_SimpleString) {
        std::string pyLog  = ToFwdSlash(logPath);
        std::string pyHome = ToFwdSlash(g_pythonHomePath);

        std::string cmd =
            "import sys, os\n"
            "try:\n"
            "    f = open(r'" + pyLog + "', 'a', buffering=1, encoding='utf-8')\n"
            "    _orig_stdout, _orig_stderr = sys.stdout, sys.stderr\n"
            "    sys.stdout = sys.stderr = f\n"
            "    print('Python stdout/stderr redirected')\n"
            "    print('sys.executable:', sys.executable)\n"
            "    pythonhome = r'" + pyHome + "'\n"
            "    if pythonhome and os.path.isdir(pythonhome):\n"
            "        for sub in ('DLLs', 'Lib', os.path.join('Lib','site-packages')):\n"
            "            d = os.path.join(pythonhome, sub)\n"
            "            if os.path.isdir(d) and d not in sys.path:\n"
            "                sys.path.insert(0, d)\n"
            "                print('Added:', d)\n"
            "                if 'DLLs' in d and d not in os.environ.get('PATH',''):\n"
            "                    os.environ['PATH'] = d + os.pathsep + os.environ.get('PATH','')\n"
            "    for d in (os.getcwd(), os.path.dirname(sys.executable)):\n"
            "        if d and d not in sys.path: sys.path.insert(0, d); print('Added:', d)\n"
            "    env_hook = os.environ.get('HYDRA_HOOK_PATH')\n"
            "    if env_hook and os.path.exists(env_hook) and env_hook not in sys.path:\n"
            "        sys.path.insert(0, env_hook); print('Added env hook:', env_hook)\n"
            "    for mod in ('_ctypes', 'concurrent.futures'):\n"
            "        try: __import__(mod); print('OK:', mod)\n"
            "        except ImportError as e: print('WARN:', mod, e)\n"
            "    print('sys.path[:5]:', sys.path[:5])\n"
            "    sys.stdout, sys.stderr = _orig_stdout, _orig_stderr\n"
            "    f.close()\n"
            "except Exception as e:\n"
            "    import traceback; traceback.print_exc()\n";

        int res = PyRun_SimpleString(cmd.c_str());
        dbgPrintf("[HOOK] Setup: %d\n", res);
        if (res != 0 && PyErr_Print) PyErr_Print();
    }

    // ── Standard import ───────────────────────────────────────────────────────
    if (StopRequested()) { PyGILState_Release(gil); dbgPrintf("[HOOK] Stop requested before import\n"); return 1; }
    void *hMod = PyImport_ImportModule(PYMODULE_NAME);
    if (hMod) {
        Py_DecRef(hMod);
        PyGILState_Release(gil);
        dbgPrintf("[HOOK] SUCCESS: imported %s\n", PYMODULE_NAME);
        return 0;
    }

    // ── Fallback: explicit path from config ───────────────────────────────────
    dbgPrintf("[HOOK] Standard import failed, trying config path\n");
    std::string hookFilePath = GetHookFilePathFromConfig();

    if (!hookFilePath.empty() && PyRun_SimpleString) {
        dbgPrintf("[HOOK] Config path: %s\n", hookFilePath.c_str());

        std::string hookDir = hookFilePath;
        size_t sl = hookDir.rfind('\\');
        if (sl != std::string::npos) hookDir.resize(sl);

        std::string pyDir  = ToFwdSlash(hookDir);
        std::string pyFile = ToFwdSlash(hookFilePath);

        // Add directory to sys.path
        std::string addCmd =
            "import sys, os\n"
            "try:\n"
            "    d = os.path.abspath(r'" + pyDir + "')\n"
            "    if d not in sys.path: sys.path.insert(0, d); print('Added:', d)\n"
            "    hf = os.path.join(d, '__hook__.py')\n"
            "    print('hook exists:', os.path.exists(hf))\n"
            "    if not os.path.exists(hf):\n"
            "        try:\n"
            "            for x in os.listdir(d): print(' -', x)\n"
            "        except: pass\n"
            "except Exception as e:\n"
            "    import traceback; traceback.print_exc()\n";

        PyRun_SimpleString(addCmd.c_str());

        void *hMod2 = PyImport_ImportModule(PYMODULE_NAME);
        if (hMod2) {
            Py_DecRef(hMod2);
            PyGILState_Release(gil);
            dbgPrintf("[HOOK] SUCCESS: imported after path add\n");
            return 0;
        }
        if (PyErr_Print) PyErr_Print();

        // Last resort: exec the file
        std::string execCmd =
            "import sys, os\n"
            "path = r'" + pyFile + "'\n"
            "print('Direct exec:', path, 'exists:', os.path.exists(path))\n"
            "if os.path.exists(path):\n"
            "    with open(path,'r',encoding='utf-8') as f: src=f.read()\n"
            "    exec(compile(src, path, 'exec'), {'__name__':'" + std::string(PYMODULE_NAME) + "',"
            "        '__file__':path,'__package__':None,'__builtins__':__builtins__})\n"
            "    print('Direct exec done')\n"
            "else:\n"
            "    raise FileNotFoundError('not found: '+path)\n";

        int r = PyRun_SimpleString(execCmd.c_str());
        dbgPrintf("[HOOK] Direct exec: %d\n", r);
        if (r == 0) {
            PyGILState_Release(gil);
            dbgPrintf("[HOOK] SUCCESS: hook ran via direct exec\n");
            return 0;
        }
        if (PyErr_Print) PyErr_Print();
    } else {
        dbgPrintf("[HOOK] No config path found\n");
    }

    if (PyErr_Print) PyErr_Print();
    PyGILState_Release(gil);
    dbgPrintf("[HOOK] ERROR: All import methods failed\n");
    return 1;
}

// ─── Worker lifecycle helpers ────────────────────────────────────────────────
static void CleanupResources() {
    FILE *f = g_logFile;
    g_logFile = nullptr;
    if (f) fclose(f);

    if (InterlockedCompareExchange(&g_logCSState, 2, 1) == 1) {
        DeleteCriticalSection(&g_logCS);
        InterlockedExchange(&g_logCSState, 0);
    }

    if (g_shutdownEvent) {
        CloseHandle(g_shutdownEvent);
        g_shutdownEvent = nullptr;
    }

    if (g_workerThread) {
        CloseHandle(g_workerThread);
        g_workerThread = nullptr;
    }

    g_workerThreadId = 0;
    InterlockedExchange(&g_started, 0);
    InterlockedExchange(&g_stopRequested, 0);
}

extern "C" __declspec(dllexport) DWORD WINAPI HydraStartHook() {
    if (InterlockedCompareExchange(&g_unloading, 0, 0) != 0)
        return ERROR_DLL_INIT_FAILED;

    if (InterlockedCompareExchange(&g_started, 1, 0) != 0)
        return ERROR_ALREADY_EXISTS;

    InterlockedExchange(&g_stopRequested, 0);

    if (!g_shutdownEvent) {
        g_shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_shutdownEvent) {
            InterlockedExchange(&g_started, 0);
            return GetLastError();
        }
    } else {
        ResetEvent(g_shutdownEvent);
    }

    HANDLE h = CreateThread(nullptr, 8u * 1024u * 1024u, hookImpl, nullptr, 0, &g_workerThreadId);
    if (!h) {
        DWORD err = GetLastError();
        CleanupResources();
        return err;
    }

    g_workerThread = h;
    return ERROR_SUCCESS;
}

extern "C" __declspec(dllexport) DWORD WINAPI HydraStopHook(DWORD timeoutMs) {
    InterlockedExchange(&g_stopRequested, 1);

    if (g_shutdownEvent)
        SetEvent(g_shutdownEvent);

    if (g_workerThread) {
        DWORD wr = WaitForSingleObject(g_workerThread, timeoutMs);
        if (wr == WAIT_TIMEOUT)
            return WAIT_TIMEOUT;
    }

    CleanupResources();
    return ERROR_SUCCESS;
}

// Optional helper for injectors/hosts that want one-call startup.
extern "C" __declspec(dllexport) DWORD WINAPI HydraInitialize() {
    return HydraStartHook();
}

// ─── DLL entry point ──────────────────────────────────────────────────────────
BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                    DWORD     fdwReason,
                    [[maybe_unused]] LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        InterlockedExchange(&g_unloading, 1);

        // Best-effort only. Do not create threads, wait indefinitely, or call
        // complex teardown here. The host should call HydraStopHook() before unload.
        if (g_shutdownEvent)
            SetEvent(g_shutdownEvent);
    }
    return TRUE;
}
