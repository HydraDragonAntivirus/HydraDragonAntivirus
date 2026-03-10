/**
 * hook_dll.cpp
 * Toolchain: MSVC / VS 2022  (x64)
 *
 * Build:
 *   build_dll.bat   (see companion file)
 *
 * Changes from original
 *   - All strncpy  -> strncpy_s  (safe, _TRUNCATE)
 *   - All fopen    -> fopen_s    (safe)
 *   - PROCESSENTRY32 / Process32First / Process32Next (no explicit A suffix)
 *   - All C-style GetProcAddress casts -> reinterpret_cast<>
 *   - PyGILState typed via int alias to match CPython ABI
 *   - NULL -> nullptr throughout
 *   - [[maybe_unused]] on unused params to silence C4100
 *   - #pragma comment(lib) for every Win32 import lib
 *   - ALL MessageBoxA calls removed — they block the host process message loop
 *     and cause watchdog-monitored processes (like WebRB.exe) to be killed
 *   - Py_IsInitialized() polled before PyGILState_Ensure() — calling GIL
 *     functions before Python is initialized is UB and crashes the host
 *   - SetErrorMode guard around CreateToolhelp32Snapshot to suppress popups
 */

// ─── Required Windows libraries ──────────────────────────────────────────────
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <direct.h>
#include <shlobj.h>
#include <vector>
#include <algorithm>
#include <string.h>
#include <stdarg.h>

#ifndef strcasecmp
#  define strcasecmp _stricmp
#endif

// ─── Global storage ──────────────────────────────────────────────────────────
static char g_pythonHomePath[MAX_PATH] = {0};
#define PYMODULE_NAME "__hook__"

static FILE             *g_logFile          = nullptr;
static CRITICAL_SECTION  g_logCS;
static bool              g_logCSInitialized = false;

// ─── Thread-safe debug print ─────────────────────────────────────────────────
static void dbgPrintf(const char *fmt, ...) {
    char    buf[2048];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(buf, sizeof(buf) - 1u, fmt, ap);
    buf[sizeof(buf) - 1] = '\0';
    va_end(ap);

    OutputDebugStringA(buf);

    if (g_logCSInitialized) {
        EnterCriticalSection(&g_logCS);
        if (g_logFile) {
            fprintf(g_logFile, "%s", buf);
            fflush(g_logFile);
        }
        LeaveCriticalSection(&g_logCS);
    }
}

// ─── Anti-tamper / debugger check ────────────────────────────────────────────
static void CheckForProtection() {
    if (IsDebuggerPresent()) {
        dbgPrintf("[HOOK] WARNING: Debugger detected!\n");
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        const BYTE *pLoadLib =
            reinterpret_cast<const BYTE *>(GetProcAddress(hKernel32, "LoadLibraryW"));
        if (pLoadLib && (*pLoadLib == 0xE9 || *pLoadLib == 0xEB)) {
            dbgPrintf("[HOOK] WARNING: LoadLibraryW appears to be hooked!\n");
        }
    }
}

// ─── Config reader ────────────────────────────────────────────────────────────
static bool GetHookFilePathFromConfig(char *outPath, size_t maxLen) {
    const char *configPath =
        "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps\\hook_config.ini";

    FILE *f = nullptr;
    if (fopen_s(&f, configPath, "r") != 0 || !f) return false;

    char line[MAX_PATH];
    bool found = false;
    while (fgets(line, static_cast<int>(sizeof(line)), f)) {
        if (strncmp(line, "HookPath=", 9) == 0) {
            char *path = line + 9;
            char *nl   = strpbrk(path, "\r\n");
            if (nl) *nl = '\0';

            if (path[0] != '\0') {
                snprintf(outPath, maxLen, "%s\\%s.py", path, PYMODULE_NAME);
                outPath[maxLen - 1] = '\0';
                found = true;
                break;
            }
        }
    }
    fclose(f);
    return found;
}

// ─── Find python.exe in running processes ────────────────────────────────────
static bool FindPythonExePath(char *outPath, size_t maxLen) {
    // Guard: CreateToolhelp32Snapshot holds a system lock.
    // Suppress any hard-error popup the OS might show if it fails.
    UINT prevErrMode = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    SetErrorMode(prevErrMode);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    // Use un-suffixed PROCESSENTRY32 / Process32First / Process32Next.
    // MSVC's tlhelp32.h does not expose explicit *A variants.
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcasecmp(pe32.szExeFile, "python.exe")  == 0 ||
                strcasecmp(pe32.szExeFile, "pythonw.exe") == 0) {

                HANDLE hProcess = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    char path[MAX_PATH];
                    if (GetModuleFileNameExA(hProcess, nullptr, path, MAX_PATH)) {
                        strncpy_s(outPath, maxLen, path, _TRUNCATE);
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return true;
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false;
}

// ─── Validate Python home directory ──────────────────────────────────────────
static bool IsValidPythonHome(const char *dir, char *outPath, size_t maxLen) {
    if (!dir || !outPath) return false;

    char libPath[MAX_PATH];
    snprintf(libPath, MAX_PATH, "%s\\Lib", dir);
    libPath[MAX_PATH - 1] = '\0';

    DWORD attrib = GetFileAttributesA(libPath);
    if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
        strncpy_s(outPath, maxLen, dir, _TRUNCATE);
        return true;
    }
    return false;
}

// ─── Scan a base path for Python3x installations ─────────────────────────────
static bool ScanBasePathForPython(const char *basePath, char *outPath, size_t maxLen) {
    if (!basePath || !outPath) return false;

    char searchPattern[MAX_PATH];
    snprintf(searchPattern, MAX_PATH, "%s\\Python3*", basePath);
    searchPattern[MAX_PATH - 1] = '\0';

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPattern, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    std::vector<std::string> foundHomes;

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            strcmp(findData.cFileName, ".")  != 0 &&
            strcmp(findData.cFileName, "..") != 0) {

            char testDir[MAX_PATH];
            snprintf(testDir, MAX_PATH, "%s\\%s", basePath, findData.cFileName);
            testDir[MAX_PATH - 1] = '\0';

            char tempPath[MAX_PATH];
            if (IsValidPythonHome(testDir, tempPath, MAX_PATH)) {
                foundHomes.emplace_back(findData.cFileName);
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    if (foundHomes.empty()) return false;

    std::sort(foundHomes.rbegin(), foundHomes.rend());
    snprintf(outPath, maxLen, "%s\\%s", basePath, foundHomes[0].c_str());
    outPath[maxLen - 1] = '\0';
    return true;
}

// ─── Enumerate well-known Python install locations ───────────────────────────
static bool FindPythonInstallation(char *outPath, size_t maxLen) {
    char basePath[MAX_PATH];

    if (ScanBasePathForPython("C:", outPath, maxLen)) return true;

    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, basePath)))
        if (ScanBasePathForPython(basePath, outPath, maxLen)) return true;

    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROGRAM_FILESX86, nullptr, 0, basePath)))
        if (ScanBasePathForPython(basePath, outPath, maxLen)) return true;

    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, basePath))) {
        char localPrograms[MAX_PATH];

        snprintf(localPrograms, MAX_PATH, "%s\\Programs\\Python", basePath);
        localPrograms[MAX_PATH - 1] = '\0';
        if (ScanBasePathForPython(localPrograms, outPath, maxLen)) return true;

        snprintf(localPrograms, MAX_PATH, "%s\\Programs", basePath);
        localPrograms[MAX_PATH - 1] = '\0';
        if (ScanBasePathForPython(localPrograms, outPath, maxLen)) return true;
    }

    return false;
}

// ─── Auto-detect and set PYTHONHOME ──────────────────────────────────────────
static void AutoSetPythonHome() {
    char existing[MAX_PATH];
    if (GetEnvironmentVariableA("PYTHONHOME", existing, MAX_PATH) > 0) {
        dbgPrintf("[HOOK] PYTHONHOME already set to: %s\n", existing);
        strncpy_s(g_pythonHomePath, MAX_PATH, existing, _TRUNCATE);
        return;
    }

    char pythonHome[MAX_PATH] = {0};
    bool found = false;

    // Method 0: Current process is python.exe
    char currentExe[MAX_PATH];
    if (GetModuleFileNameA(nullptr, currentExe, MAX_PATH)) {
        const char *filename = strrchr(currentExe, '\\');
        filename = filename ? filename + 1 : currentExe;

        if (strcasecmp(filename, "python.exe")  == 0 ||
            strcasecmp(filename, "pythonw.exe") == 0) {
            strncpy_s(pythonHome, MAX_PATH, currentExe, _TRUNCATE);
            PathRemoveFileSpecA(pythonHome);
            found = true;
            dbgPrintf("[HOOK] Using current python.exe dir: %s\n", pythonHome);
        }
    }

    // Method 1: Find python.exe in running processes
    if (!found) {
        char pythonExe[MAX_PATH];
        if (FindPythonExePath(pythonExe, MAX_PATH)) {
            strncpy_s(pythonHome, MAX_PATH, pythonExe, _TRUNCATE);
            PathRemoveFileSpecA(pythonHome);
            if (IsValidPythonHome(pythonHome, pythonHome, MAX_PATH))
                found = true;
        }
    }

    // Method 2: Common install paths
    if (!found) found = FindPythonInstallation(pythonHome, MAX_PATH);

    // Method 3: Walk PATH
    if (!found) {
        char *pathEnv = static_cast<char *>(malloc(32768));
        if (pathEnv) {
            DWORD pathLen = GetEnvironmentVariableA("PATH", pathEnv, 32768);
            if (pathLen > 0 && pathLen < 32768) {
                char *context = nullptr;
                char *token   = strtok_s(pathEnv, ";", &context);
                while (token) {
                    char testExe[MAX_PATH];
                    snprintf(testExe, MAX_PATH, "%s\\python.exe", token);
                    testExe[MAX_PATH - 1] = '\0';

                    DWORD attrib = GetFileAttributesA(testExe);
                    if (attrib != INVALID_FILE_ATTRIBUTES &&
                        !(attrib & FILE_ATTRIBUTE_DIRECTORY)) {
                        if (IsValidPythonHome(token, pythonHome, MAX_PATH)) {
                            found = true;
                            break;
                        }
                    }
                    token = strtok_s(nullptr, ";", &context);
                }
            }
            free(pathEnv);
        }
    }

    if (found) {
        SetEnvironmentVariableA("PYTHONHOME", pythonHome);
        strncpy_s(g_pythonHomePath, MAX_PATH, pythonHome, _TRUNCATE);
        dbgPrintf("[HOOK] Set PYTHONHOME=%s\n", pythonHome);

        // Buffer must hold: pythonHome + "\Lib;" + pythonHome + "\Lib\site-packages" + NUL
        // Worst case: (MAX_PATH-1)*2 + 24 = 542 bytes.
        // MAX_PATH*2 (520) was too small — overflowed the stack cookie (0xc0000409 / BEX64).
        char pythonPath[MAX_PATH * 3];
        snprintf(pythonPath, sizeof(pythonPath),
                 "%s\\Lib;%s\\Lib\\site-packages", pythonHome, pythonHome);
        pythonPath[sizeof(pythonPath) - 1] = '\0';
        SetEnvironmentVariableA("PYTHONPATH", pythonPath);
        dbgPrintf("[HOOK] Set PYTHONPATH=%s\n", pythonPath);
    } else {
        dbgPrintf("[HOOK] Could not auto-detect PYTHONHOME\n");
    }
}

// ─── Open log file ────────────────────────────────────────────────────────────
static bool SetupStdoutStderrToLog(char *outLogPath) {
    const char logDir[] =
        "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps";
    CreateDirectoryA(logDir, nullptr);

    char logPath[MAX_PATH];
    snprintf(logPath, MAX_PATH, "%s\\hook_dll.log", logDir);
    logPath[MAX_PATH - 1] = '\0';

    fopen_s(&g_logFile, logPath, "a");
    if (g_logFile)
        setvbuf(g_logFile, nullptr, _IOLBF, 0);

    if (outLogPath)
        strncpy_s(outLogPath, MAX_PATH, logPath, _TRUNCATE);

    dbgPrintf("[HOOK] Log file: %s\n", logPath);
    return true;
}

// ─── Python C-API typedefs ────────────────────────────────────────────────────
using PyGILState_STATE    = int;   // ABI matches CPython int enum
using PyImportModuleFunc  = void *(*)(const char *);
using Py_DecRefFunc       = void  (*)(void *);
using PyGILState_EnsureT  = PyGILState_STATE (*)();
using PyGILState_ReleaseT = void  (*)(PyGILState_STATE);
using PyErr_PrintFunc     = void  (*)();
using PyRun_SimpleStrFunc = int   (*)(const char *);

// ─── Main hook thread ─────────────────────────────────────────────────────────
static DWORD WINAPI hookImpl([[maybe_unused]] LPVOID lpParam) {
    if (!g_logCSInitialized) {
        InitializeCriticalSection(&g_logCS);
        g_logCSInitialized = true;
    }

    AutoSetPythonHome();
    CheckForProtection();

    char logPathBuf[MAX_PATH] = {0};
    SetupStdoutStderrToLog(logPathBuf);

    // ── Locate python3x.dll ──────────────────────────────────────────────────
    char    dllName[64] = {0};
    HMODULE hPyDll      = nullptr;

    hPyDll = GetModuleHandleA("python3.dll");
    if (hPyDll) {
        strncpy_s(dllName, sizeof(dllName), "python3.dll", _TRUNCATE);
        dbgPrintf("[HOOK] Found python3.dll\n");
    } else {
        for (int i = 99; i >= 0; --i) {
            snprintf(dllName, sizeof(dllName), "python3%d.dll", i);
            hPyDll = GetModuleHandleA(dllName);
            if (hPyDll) {
                dbgPrintf("[HOOK] Found %s\n", dllName);
                break;
            }
        }
    }

    if (!hPyDll) {
        dbgPrintf("[HOOK] ERROR: No python3x.dll found\n");
        return 1;
    }

    // ── Resolve Python C-API symbols ─────────────────────────────────────────
    auto PyImport_ImportModule =
        reinterpret_cast<PyImportModuleFunc>(GetProcAddress(hPyDll, "PyImport_ImportModule"));
    auto Py_DecRef =
        reinterpret_cast<Py_DecRefFunc>(GetProcAddress(hPyDll, "Py_DecRef"));
    auto PyGILState_Ensure =
        reinterpret_cast<PyGILState_EnsureT>(GetProcAddress(hPyDll, "PyGILState_Ensure"));
    auto PyGILState_Release =
        reinterpret_cast<PyGILState_ReleaseT>(GetProcAddress(hPyDll, "PyGILState_Release"));
    auto PyErr_Print =
        reinterpret_cast<PyErr_PrintFunc>(GetProcAddress(hPyDll, "PyErr_Print"));
    auto PyRun_SimpleString =
        reinterpret_cast<PyRun_SimpleStrFunc>(GetProcAddress(hPyDll, "PyRun_SimpleString"));

    if (!PyImport_ImportModule || !PyGILState_Ensure || !PyGILState_Release) {
        dbgPrintf("[HOOK] ERROR: Cannot load Python C-API functions\n");
        return 1;
    }

    // ── Wait for Python runtime to be fully initialized ───────────────────────
    // Calling PyGILState_Ensure before Py_Initialize completes is UB and will
    // crash the host process. Poll Py_IsInitialized() with a timeout instead.
    using Py_IsInitializedFunc = int (*)();
    auto Py_IsInitialized =
        reinterpret_cast<Py_IsInitializedFunc>(GetProcAddress(hPyDll, "Py_IsInitialized"));

    if (Py_IsInitialized) {
        int waited_ms = 0;
        while (!Py_IsInitialized() && waited_ms < 10000) {
            Sleep(50);
            waited_ms += 50;
        }
        if (!Py_IsInitialized()) {
            dbgPrintf("[HOOK] ERROR: Python runtime not initialized after 10s — aborting\n");
            return 1;
        }
        dbgPrintf("[HOOK] Python is initialized (waited %dms)\n", waited_ms);
    }

    PyGILState_STATE gilState = PyGILState_Ensure();

    // ── Python setup command ──────────────────────────────────────────────────
    char *pycmd = static_cast<char *>(malloc(16384));
    if (!pycmd) {
        dbgPrintf("[HOOK] ERROR: Memory allocation failed\n");
        PyGILState_Release(gilState);
        return 1;
    }

    if (PyRun_SimpleString) {
        char pyLogPath[MAX_PATH];
        strncpy_s(pyLogPath, sizeof(pyLogPath), logPathBuf, _TRUNCATE);
        for (char *p = pyLogPath; *p; ++p)
            if (*p == '\\') *p = '/';

        char pyHomePath[MAX_PATH];
        strncpy_s(pyHomePath, sizeof(pyHomePath), g_pythonHomePath, _TRUNCATE);
        for (char *p = pyHomePath; *p; ++p)
            if (*p == '\\') *p = '/';

        int written = snprintf(
            pycmd, 16384,
            "import sys, os\n"
            "try:\n"
            "    f = open(r'%s', 'a', buffering=1, encoding='utf-8')\n"
            "    _orig_stdout = sys.stdout\n"
            "    _orig_stderr = sys.stderr\n"
            "    sys.stdout = f\n"
            "    sys.stderr = f\n"
            "    print('Python stdout/stderr redirected')\n"
            "    print('sys.executable:', sys.executable)\n"
            "    print('sys.prefix:', sys.prefix)\n"
            "    pythonhome = r'%s'\n"
            "    print('Detected PYTHONHOME:', pythonhome)\n"
            "    if pythonhome and os.path.isdir(pythonhome):\n"
            "        dlls_dir      = os.path.join(pythonhome, 'DLLs')\n"
            "        lib_dir       = os.path.join(pythonhome, 'Lib')\n"
            "        site_packages = os.path.join(lib_dir, 'site-packages')\n"
            "        if os.path.isdir(dlls_dir) and dlls_dir not in sys.path:\n"
            "            sys.path.insert(0, dlls_dir)\n"
            "            print('Added DLLs directory:', dlls_dir)\n"
            "            if dlls_dir not in os.environ.get('PATH', ''):\n"
            "                os.environ['PATH'] = dlls_dir + os.pathsep + os.environ.get('PATH', '')\n"
            "                print('Added DLLs to PATH')\n"
            "        if os.path.isdir(lib_dir) and lib_dir not in sys.path:\n"
            "            sys.path.insert(0, lib_dir)\n"
            "            print('Added Lib directory:', lib_dir)\n"
            "        if os.path.isdir(site_packages) and site_packages not in sys.path:\n"
            "            sys.path.insert(0, site_packages)\n"
            "            print('Added site-packages:', site_packages)\n"
            "    cwd     = os.getcwd()\n"
            "    exe_dir = os.path.dirname(sys.executable)\n"
            "    if cwd     not in sys.path: sys.path.insert(0, cwd);     print('Added CWD:', cwd)\n"
            "    if exe_dir not in sys.path: sys.path.insert(0, exe_dir); print('Added exe dir:', exe_dir)\n"
            "    env_hook = os.environ.get('HYDRA_HOOK_PATH')\n"
            "    if env_hook and os.path.exists(env_hook) and env_hook not in sys.path:\n"
            "        sys.path.insert(0, env_hook)\n"
            "        print('Added env hook path:', env_hook)\n"
            "    try:\n"
            "        import _ctypes\n"
            "        print('SUCCESS: _ctypes is available')\n"
            "    except ImportError as e:\n"
            "        print('WARNING: _ctypes still not available:', e)\n"
            "    try:\n"
            "        import concurrent.futures\n"
            "        print('SUCCESS: concurrent.futures available')\n"
            "    except ImportError as e:\n"
            "        print('ERROR: concurrent.futures not available:', e)\n"
            "    print('Final sys.path:', sys.path[:5], '...')\n"
            "    sys.stdout = _orig_stdout\n"
            "    sys.stderr = _orig_stderr\n"
            "    f.close()\n"
            "except Exception as e:\n"
            "    print('Setup error:', e)\n"
            "    import traceback\n"
            "    traceback.print_exc()\n",
            pyLogPath, pyHomePath);

        if (written >= 16384)
            dbgPrintf("[HOOK] WARNING: Python setup command truncated!\n");

        int res = PyRun_SimpleString(pycmd);
        dbgPrintf("[HOOK] Setup returned: %d\n", res);
        if (res != 0 && PyErr_Print) PyErr_Print();
    }

    free(pycmd);

    // ── Try importing the hook module ────────────────────────────────────────
    void *hook_module = PyImport_ImportModule(PYMODULE_NAME);

    if (hook_module) {
        Py_DecRef(hook_module);
        PyGILState_Release(gilState);
        dbgPrintf("[HOOK] Successfully imported %s\n", PYMODULE_NAME);
        dbgPrintf("[HOOK] SUCCESS: Hook injection successful!\n");
        return 0;
    }

    // ── Fallback: explicit file execution ────────────────────────────────────
    dbgPrintf("[HOOK] Standard import failed, trying explicit execution\n");

    char hookFilePath[MAX_PATH];
    if (GetHookFilePathFromConfig(hookFilePath, MAX_PATH)) {
        dbgPrintf("[HOOK] Explicit hook path: %s\n", hookFilePath);

        char hookDir[MAX_PATH];
        strncpy_s(hookDir, MAX_PATH, hookFilePath, _TRUNCATE);
        PathRemoveFileSpecA(hookDir);

        char pyHookPath[MAX_PATH];
        strncpy_s(pyHookPath, MAX_PATH, hookFilePath, _TRUNCATE);
        for (char *p = pyHookPath; *p; ++p)
            if (*p == '\\') *p = '/';

        char pyHookDir[MAX_PATH];
        strncpy_s(pyHookDir, MAX_PATH, hookDir, _TRUNCATE);
        for (char *p = pyHookDir; *p; ++p)
            if (*p == '\\') *p = '/';

        // Add hook directory to sys.path, then retry import
        char *addPathCmd = static_cast<char *>(malloc(8192));
        if (addPathCmd) {
            snprintf(addPathCmd, 8192,
                     "import sys, os\n"
                     "try:\n"
                     "    hook_dir = r'%s'\n"
                     "    print('Target hook directory:', hook_dir)\n"
                     "    print('Directory exists:', os.path.exists(hook_dir))\n"
                     "    hook_dir = os.path.abspath(hook_dir)\n"
                     "    print('Normalized hook directory:', hook_dir)\n"
                     "    if hook_dir not in sys.path:\n"
                     "        sys.path.insert(0, hook_dir)\n"
                     "        print('Added to sys.path')\n"
                     "    else:\n"
                     "        print('Already in sys.path')\n"
                     "    print('Current sys.path:', sys.path)\n"
                     "    hook_file = os.path.join(hook_dir, '__hook__.py')\n"
                     "    print('Looking for:', hook_file)\n"
                     "    print('Hook file exists:', os.path.exists(hook_file))\n"
                     "    if not os.path.exists(hook_file):\n"
                     "        print('ERROR: Hook file not found')\n"
                     "        try:\n"
                     "            for item in os.listdir(hook_dir): print('  -', item)\n"
                     "        except Exception as e:\n"
                     "            print('Cannot list directory:', e)\n"
                     "except Exception as e:\n"
                     "    print('ERROR in path addition:', type(e).__name__, str(e))\n"
                     "    import traceback; traceback.print_exc()\n",
                     pyHookDir);

            int pathRes = PyRun_SimpleString(addPathCmd);
            dbgPrintf("[HOOK] Added hook dir to sys.path, result: %d\n", pathRes);
            free(addPathCmd);

            if (pathRes == 0) {
                void *hook_module_retry = PyImport_ImportModule(PYMODULE_NAME);
                if (hook_module_retry) {
                    Py_DecRef(hook_module_retry);
                    PyGILState_Release(gilState);
                    dbgPrintf("[HOOK] Successfully imported %s after adding path\n",
                              PYMODULE_NAME);
                    dbgPrintf("[HOOK] SUCCESS: Hook injection successful!\n");
                    return 0;
                } else {
                    dbgPrintf("[HOOK] Import still failed after adding path\n");
                    if (PyErr_Print) PyErr_Print();
                }
            } else {
                dbgPrintf("[HOOK] Path addition returned error code\n");
                if (PyErr_Print) PyErr_Print();
            }
        }

        // Last resort: direct exec of the .py file
        char *execCmd = static_cast<char *>(malloc(16384));
        if (execCmd) {
            int written = snprintf(
                execCmd, 16384,
                "import sys, os\n"
                "print('\\n=== Direct Execution of Hook File ===')\n"
                "path = r'%s'\n"
                "print('Target:', path)\n"
                "print('Path exists:', os.path.exists(path))\n"
                "print('CWD:', os.getcwd())\n"
                "if os.path.exists(path):\n"
                "    try:\n"
                "        with open(path, 'r', encoding='utf-8') as f:\n"
                "            code_str = f.read()\n"
                "        print('Read', len(code_str), 'bytes')\n"
                "        hook_globals = {\n"
                "            '__name__': '%s',\n"
                "            '__file__': path,\n"
                "            '__package__': None,\n"
                "            '__builtins__': __builtins__,\n"
                "        }\n"
                "        exec(compile(code_str, path, 'exec'), hook_globals)\n"
                "        print('=== Hook Execution Completed ===')\n"
                "    except SyntaxError as e:\n"
                "        print('SYNTAX ERROR line', e.lineno, ':', e.msg)\n"
                "        import traceback; traceback.print_exc(); raise\n"
                "    except Exception as e:\n"
                "        print('ERROR:', type(e).__name__, str(e))\n"
                "        import traceback; traceback.print_exc(); raise\n"
                "else:\n"
                "    hook_dir  = os.path.dirname(path)\n"
                "    hook_name = os.path.basename(path)\n"
                "    print('Hook directory:', hook_dir)\n"
                "    print('Hook filename:', hook_name)\n"
                "    if os.path.exists(hook_dir):\n"
                "        try:\n"
                "            for item in os.listdir(hook_dir): print('  -', item)\n"
                "        except Exception as e:\n"
                "            print('Cannot list directory:', e)\n"
                "    else:\n"
                "        print('ERROR: Directory does not exist!')\n"
                "    raise FileNotFoundError(f'Hook file not found: {path}')\n",
                pyHookPath, PYMODULE_NAME);

            if (written < 16384) {
                dbgPrintf("[HOOK] Executing hook file directly...\n");
                int execRes = PyRun_SimpleString(execCmd);
                dbgPrintf("[HOOK] Direct execution returned: %d\n", execRes);

                if (execRes == 0) {
                    free(execCmd);
                    PyGILState_Release(gilState);
                    dbgPrintf("[HOOK] Hook executed successfully via direct exec\n");
                    dbgPrintf("[HOOK] SUCCESS: Hook successful (direct exec)!\n");
                    return 0;
                } else {
                    dbgPrintf("[HOOK] Direct execution failed with code: %d\n", execRes);
                    if (PyErr_Print) PyErr_Print();
                }
            } else {
                dbgPrintf("[HOOK] ERROR: execCmd buffer too small (written=%d)\n", written);
            }
            free(execCmd);
        }
    } else {
        dbgPrintf("[HOOK] No hook path found in config\n");
    }

    if (PyErr_Print) PyErr_Print();
    PyGILState_Release(gilState);

    dbgPrintf("[HOOK] Failed to import %s\n", PYMODULE_NAME);
    dbgPrintf("[HOOK] ERROR: Failed to import hook. Check logs.\n");
    return 1;
}

// ─── DLL entry point ──────────────────────────────────────────────────────────
BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                    DWORD     fdwReason,
                    [[maybe_unused]] LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE hThread = CreateThread(nullptr, 0, hookImpl, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);

    } else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_logCSInitialized) {
            DeleteCriticalSection(&g_logCS);
            g_logCSInitialized = false;
        }
        if (g_logFile) {
            fclose(g_logFile);
            g_logFile = nullptr;
        }
    }
    return TRUE;
}
