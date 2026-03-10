/**
 * hook_dll.cpp - FIXED VERSION
 * Critical fixes for access violations:
 * 1. Increased buffer sizes to prevent overflow
 * 2. Fixed strtok use-after-free with PATH parsing
 * 3. Added null pointer checks
 * 4. Thread-safe logging
 */

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <direct.h>
#include <shlobj.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <process.h>
#include <errno.h>
#include <exception>
#include <new>

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

// Global storage
static char g_pythonHomePath[MAX_PATH] = {0};
#define PYMODULE_NAME "__hook__"

static FILE *g_logFile = NULL;
static CRITICAL_SECTION g_logCS; // Thread-safe logging
static bool g_logCSInitialized = false;
static HINSTANCE g_hInstance = NULL;

static void __cdecl HydraInvalidParameterHandler(
    const wchar_t *expression,
    const wchar_t *function,
    const wchar_t *file,
    unsigned int line,
    uintptr_t reserved) {
  UNREFERENCED_PARAMETER(expression);
  UNREFERENCED_PARAMETER(function);
  UNREFERENCED_PARAMETER(file);
  UNREFERENCED_PARAMETER(line);
  UNREFERENCED_PARAMETER(reserved);
  OutputDebugStringA("[HOOK] ERROR: MSVC invalid parameter detected\n");
}
static HANDLE g_workerThread = NULL;
static DWORD g_workerThreadId = 0;
static volatile LONG g_started = 0;
static volatile LONG g_unloading = 0;

// Thread-safe debug print
static void dbgPrintf(const char *fmt, ...) {
  char buf[2048]; // Increased size
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
  buf[sizeof(buf) - 1] = '\0';
  va_end(ap);
  OutputDebugStringA(buf);

  if (InterlockedCompareExchange(&g_unloading, 0, 0) != 0)
    return;
  
  if (g_logCSInitialized) {
    EnterCriticalSection(&g_logCS);
    if (g_logFile) {
      fprintf(g_logFile, "%s", buf);
      fflush(g_logFile);
    }
    LeaveCriticalSection(&g_logCS);
  }
}

static void CheckForProtection() {
  if (IsDebuggerPresent()) {
    dbgPrintf("[HOOK] WARNING: Debugger detected!\n");
  }

  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  if (hKernel32) {
    BYTE *pLoadLib = (BYTE *)GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLib && (*pLoadLib == 0xE9 || *pLoadLib == 0xEB)) {
      dbgPrintf("[HOOK] WARNING: LoadLibraryW appears to be hooked!\n");
    }
  }
}

static bool GetHookFilePathFromConfig(char *outPath, size_t maxLen) {
  const char *configPath = "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps\\hook_config.ini";
  FILE *f = NULL;
  if (fopen_s(&f, configPath, "r") != 0 || !f) return false;

  char line[MAX_PATH];
  bool found = false;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "HookPath=", 9) == 0) {
      char *path = line + 9;
      char *nl = strpbrk(path, "\r\n");
      if (nl) *nl = '\0';

      if (path[0] != '\0') {
        _snprintf_s(outPath, maxLen, _TRUNCATE, "%s\\%s.py", path, PYMODULE_NAME);
        outPath[maxLen - 1] = '\0';
        found = true;
        break;
      }
    }
  }
  fclose(f);
  return found;
}

static bool FindPythonExePath(char *outPath, size_t maxLen) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (Process32First(hSnapshot, &pe32)) {
    do {
      if (strcasecmp(pe32.szExeFile, "python.exe") == 0 ||
          strcasecmp(pe32.szExeFile, "pythonw.exe") == 0) {

        HANDLE hProcess =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                        pe32.th32ProcessID);
        if (hProcess) {
          char path[MAX_PATH];
          DWORD pathLen = GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH);
          if (pathLen > 0 && pathLen < MAX_PATH) {
            strncpy_s(outPath, maxLen, path, _TRUNCATE);
            outPath[maxLen - 1] = '\0';
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

static bool IsValidPythonHome(const char *dir, char *outPath, size_t maxLen) {
  if (!dir)
    return false;

  char libPath[MAX_PATH];
  _snprintf_s(libPath, MAX_PATH, _TRUNCATE, "%s\\Lib", dir);
  libPath[MAX_PATH - 1] = '\0';

  DWORD attrib = GetFileAttributesA(libPath);
  if (attrib != INVALID_FILE_ATTRIBUTES &&
      (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
    if (outPath && maxLen > 0 && outPath != dir) {
      strncpy_s(outPath, maxLen, dir, _TRUNCATE);
      outPath[maxLen - 1] = '\0';
    }
    return true;
  }
  return false;
}

static long GetPythonVersionRank(const char *folderName) {
  if (!folderName || _strnicmp(folderName, "Python", 6) != 0)
    return -1;

  const char *suffix = folderName + 6;
  if (*suffix == '\0')
    return -1;

  char *endPtr = NULL;
  long rank = strtol(suffix, &endPtr, 10);
  if (endPtr == suffix)
    return -1;

  return rank;
}

static bool ScanBasePathForPython(const char *basePath, char *outPath,
                                  size_t maxLen) {
  if (!basePath || !outPath)
    return false;

  char searchPattern[MAX_PATH];
  _snprintf_s(searchPattern, MAX_PATH, _TRUNCATE, "%s\\Python3*", basePath);
  searchPattern[MAX_PATH - 1] = '\0';

  WIN32_FIND_DATAA findData;
  HANDLE hFind = FindFirstFileA(searchPattern, &findData);
  if (hFind == INVALID_HANDLE_VALUE)
    return false;

  char bestPath[MAX_PATH] = {0};
  char bestFolder[MAX_PATH] = {0};
  long bestRank = -1;
  bool found = false;

  do {
    if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        strcmp(findData.cFileName, ".") != 0 &&
        strcmp(findData.cFileName, "..") != 0) {
      char testDir[MAX_PATH];
      _snprintf_s(testDir, MAX_PATH, _TRUNCATE, "%s\\%s", basePath,
                  findData.cFileName);
      testDir[MAX_PATH - 1] = '\0';

      char tempPath[MAX_PATH];
      if (IsValidPythonHome(testDir, tempPath, MAX_PATH)) {
        long rank = GetPythonVersionRank(findData.cFileName);
        if (!found || rank > bestRank ||
            (rank == bestRank && _stricmp(findData.cFileName, bestFolder) > 0)) {
          strncpy_s(bestPath, MAX_PATH, tempPath, _TRUNCATE);
          bestPath[MAX_PATH - 1] = '\0';
          strncpy_s(bestFolder, MAX_PATH, findData.cFileName, _TRUNCATE);
          bestFolder[MAX_PATH - 1] = '\0';
          bestRank = rank;
          found = true;
        }
      }
    }
  } while (FindNextFileA(hFind, &findData));

  FindClose(hFind);

  if (!found)
    return false;

  strncpy_s(outPath, maxLen, bestPath, _TRUNCATE);
  outPath[maxLen - 1] = '\0';
  return true;
}

static bool FindPythonInstallation(char *outPath, size_t maxLen) {
  char basePath[MAX_PATH];

  if (ScanBasePathForPython("C:", outPath, maxLen))
    return true;

  if (SUCCEEDED(
          SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, basePath))) {
    if (ScanBasePathForPython(basePath, outPath, maxLen))
      return true;
  }

  if (SUCCEEDED(
          SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, basePath))) {
    if (ScanBasePathForPython(basePath, outPath, maxLen))
      return true;
  }

  if (SUCCEEDED(
          SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, basePath))) {
    char localPrograms[MAX_PATH];

    _snprintf_s(localPrograms, MAX_PATH, _TRUNCATE, "%s\\Programs\\Python", basePath);
    localPrograms[MAX_PATH - 1] = '\0';
    if (ScanBasePathForPython(localPrograms, outPath, maxLen))
      return true;

    _snprintf_s(localPrograms, MAX_PATH, _TRUNCATE, "%s\\Programs", basePath);
    localPrograms[MAX_PATH - 1] = '\0';
    if (ScanBasePathForPython(localPrograms, outPath, maxLen))
      return true;
  }

  return false;
}

static bool EnsureDirectoryExists(const char *path) {
  DWORD attrs = GetFileAttributesA(path);
  if (attrs != INVALID_FILE_ATTRIBUTES)
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;

  if (CreateDirectoryA(path, NULL))
    return true;

  return GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool FindPreferredPython312Home(char *outPath, size_t maxLen) {
  if (!outPath || maxLen == 0)
    return false;

  char candidate[MAX_PATH] = {0};
  char localAppData[MAX_PATH] = {0};

  if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
    _snprintf_s(candidate, MAX_PATH, _TRUNCATE,
                "%s\\Programs\\Python\\Python312", localAppData);
    candidate[MAX_PATH - 1] = '\0';
    if (IsValidPythonHome(candidate, outPath, maxLen)) {
      dbgPrintf("[HOOK] Using preferred Python312 home: %s\n", outPath);
      return true;
    }
  }

  const char *fallbackCandidates[] = {
      "C:\\Python312",
      "C:\\Program Files\\Python312",
      "C:\\Program Files (x86)\\Python312",
  };

  for (size_t i = 0; i < sizeof(fallbackCandidates) / sizeof(fallbackCandidates[0]); ++i) {
    if (IsValidPythonHome(fallbackCandidates[i], outPath, maxLen)) {
      dbgPrintf("[HOOK] Using preferred Python312 home: %s\n", outPath);
      return true;
    }
  }

  return false;
}

static bool FindLoadedPythonHome(char *outPath, size_t maxLen) {
  if (!outPath || maxLen == 0)
    return false;

  const char *dllCandidates[] = {
      "python313.dll", "python312.dll", "python311.dll", "python310.dll",
      "python39.dll",  "python38.dll",  "python37.dll",  "python36.dll",
      "python3.dll",
  };

  char modulePath[MAX_PATH] = {0};
  char homePath[MAX_PATH] = {0};
  char parentPath[MAX_PATH] = {0};

  for (size_t i = 0; i < sizeof(dllCandidates) / sizeof(dllCandidates[0]); ++i) {
    HMODULE hPy = GetModuleHandleA(dllCandidates[i]);
    if (!hPy)
      continue;

    DWORD moduleLen = GetModuleFileNameA(hPy, modulePath, MAX_PATH);
    if (moduleLen == 0 || moduleLen >= MAX_PATH)
      continue;

    strncpy_s(homePath, MAX_PATH, modulePath, _TRUNCATE);
    homePath[MAX_PATH - 1] = '\0';
    PathRemoveFileSpecA(homePath);

    if (IsValidPythonHome(homePath, outPath, maxLen)) {
      dbgPrintf("[HOOK] Using loaded %s dir: %s\n", dllCandidates[i], outPath);
      return true;
    }

    strncpy_s(parentPath, MAX_PATH, homePath, _TRUNCATE);
    parentPath[MAX_PATH - 1] = '\0';
    if (PathRemoveFileSpecA(parentPath) &&
        IsValidPythonHome(parentPath, outPath, maxLen)) {
      dbgPrintf("[HOOK] Using parent of loaded %s dir: %s\n", dllCandidates[i],
                outPath);
      return true;
    }
  }

  return false;
}

static void AutoSetPythonHome() {
  char pythonHome[MAX_PATH] = {0};
  bool found = false;

  // Method 0: Prefer HydraDragonAntivirus's Python 3.12 install.
  if (FindPreferredPython312Home(pythonHome, MAX_PATH))
    found = true;

  // Method 1: Use the current executable's Python home when available.
  if (!found) {
    char currentExe[MAX_PATH] = {0};
    DWORD currentExeLen = GetModuleFileNameA(NULL, currentExe, MAX_PATH);
    if (currentExeLen > 0 && currentExeLen < MAX_PATH) {
      const char *filename = strrchr(currentExe, '\\');
      if (filename)
        filename++;
      else
        filename = currentExe;

      if (strcasecmp(filename, "python.exe") == 0 ||
          strcasecmp(filename, "pythonw.exe") == 0) {
        strncpy_s(pythonHome, MAX_PATH, currentExe, _TRUNCATE);
        pythonHome[MAX_PATH - 1] = '\0';
        PathRemoveFileSpecA(pythonHome);
        if (IsValidPythonHome(pythonHome, NULL, 0)) {
          found = true;
          dbgPrintf("[HOOK] Using current python.exe dir: %s\n", pythonHome);
        }
      }
    }
  }

  // Method 2: Prefer the Python runtime already loaded in this process.
  if (!found && FindLoadedPythonHome(pythonHome, MAX_PATH))
    found = true;

  // Method 3: Use PYTHONHOME only when it still points to a valid install.
  if (!found) {
    char existing[MAX_PATH] = {0};
    DWORD existingLen = GetEnvironmentVariableA("PYTHONHOME", existing, MAX_PATH);
    if (existingLen > 0 && existingLen < MAX_PATH) {
      if (IsValidPythonHome(existing, NULL, 0)) {
        dbgPrintf("[HOOK] PYTHONHOME already set to: %s\n", existing);
        strncpy_s(pythonHome, MAX_PATH, existing, _TRUNCATE);
        pythonHome[MAX_PATH - 1] = '\0';
        found = true;
      } else {
        dbgPrintf("[HOOK] Ignoring invalid PYTHONHOME: %s\n", existing);
      }
    } else if (existingLen >= MAX_PATH) {
      dbgPrintf("[HOOK] Ignoring PYTHONHOME because it exceeds MAX_PATH\n");
    }
  }

  // Method 4: Find python.exe in other processes.
  if (!found) {
    char pythonExe[MAX_PATH] = {0};
    if (FindPythonExePath(pythonExe, MAX_PATH)) {
      strncpy_s(pythonHome, MAX_PATH, pythonExe, _TRUNCATE);
      pythonHome[MAX_PATH - 1] = '\0';
      PathRemoveFileSpecA(pythonHome);
      if (IsValidPythonHome(pythonHome, NULL, 0))
        found = true;
    }
  }

  // Method 5: Check common installation paths.
  if (!found)
    found = FindPythonInstallation(pythonHome, MAX_PATH);

  // Method 6: Check PATH environment.
  if (!found) {
    char *pathEnv = (char *)malloc(32768);
    if (pathEnv) {
      DWORD pathLen = GetEnvironmentVariableA("PATH", pathEnv, 32768);
      if (pathLen > 0 && pathLen < 32768) {
        char *context = NULL;
        char *token = strtok_s(pathEnv, ";", &context);
        while (token != NULL) {
          char testExe[MAX_PATH];
          _snprintf_s(testExe, MAX_PATH, _TRUNCATE, "%s\\python.exe", token);
          testExe[MAX_PATH - 1] = '\0';

          DWORD attrib = GetFileAttributesA(testExe);
          if (attrib != INVALID_FILE_ATTRIBUTES &&
              !(attrib & FILE_ATTRIBUTE_DIRECTORY)) {
            if (IsValidPythonHome(token, pythonHome, MAX_PATH)) {
              found = true;
              break;
            }
          }
          token = strtok_s(NULL, ";", &context);
        }
      }
      free(pathEnv);
    }
  }

  if (found) {
    SetEnvironmentVariableA("PYTHONHOME", pythonHome);
    strncpy_s(g_pythonHomePath, MAX_PATH, pythonHome, _TRUNCATE);
    g_pythonHomePath[MAX_PATH - 1] = '\0';

    dbgPrintf("[HOOK] Set PYTHONHOME=%s\n", pythonHome);

    char pythonPath[MAX_PATH * 2];
    _snprintf_s(pythonPath, sizeof(pythonPath), _TRUNCATE,
                "%s\\Lib;%s\\Lib\\site-packages", pythonHome, pythonHome);
    pythonPath[sizeof(pythonPath) - 1] = '\0';
    SetEnvironmentVariableA("PYTHONPATH", pythonPath);
    dbgPrintf("[HOOK] Set PYTHONPATH=%s\n", pythonPath);
  } else {
    dbgPrintf("[HOOK] Could not auto-detect PYTHONHOME\n");
  }
}

static bool SetupStdoutStderrToLog(char *outLogPath) {
  const char *baseDir = "C:\\ProgramData\\HydraDragonAntivirus";
  const char *logDir = "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps";
  char logPath[MAX_PATH];

  EnsureDirectoryExists(baseDir);
  EnsureDirectoryExists(logDir);

  _snprintf_s(logPath, MAX_PATH, _TRUNCATE, "%s\\hook_dll.log", logDir);
  logPath[MAX_PATH - 1] = '\0';

  if (g_logFile) {
    fclose(g_logFile);
    g_logFile = NULL;
  }

  errno_t openErr = fopen_s(&g_logFile, logPath, "a");
  if (openErr != 0 || !g_logFile) {
    dbgPrintf("[HOOK] ERROR: fopen_s failed for %s (errno=%d)\n", logPath,
              (int)openErr);
    return false;
  }

  // Avoid setvbuf here. In MSVC, invalid parameters can fail-fast the target
  // process, and dbgPrintf already flushes the log file after each write.

  // Don't redirect stdout/stderr via freopen - can cause crashes
  // Let Python handle its own redirection

  if (outLogPath) {
    strncpy_s(outLogPath, MAX_PATH, logPath, _TRUNCATE);
    outLogPath[MAX_PATH - 1] = '\0';
  }

  dbgPrintf("[HOOK] Log file: %s\n", logPath);
  return true;
}

static unsigned __stdcall hookImpl(void *lpParam) {
  UNREFERENCED_PARAMETER(lpParam);

  _set_invalid_parameter_handler(HydraInvalidParameterHandler);

  // Initialize logging critical section
  if (!g_logCSInitialized) {
    InitializeCriticalSection(&g_logCS);
    g_logCSInitialized = true;
  }

  char logPathBuf[MAX_PATH] = {0};
  SetupStdoutStderrToLog(logPathBuf);

  try {
    CheckForProtection();
    AutoSetPythonHome();

    char dllName[64];
  HMODULE hPyDll = nullptr;

  hPyDll = GetModuleHandleA("python3.dll");
  if (hPyDll) {
    strncpy_s(dllName, sizeof(dllName), "python3.dll", _TRUNCATE);
    dbgPrintf("[HOOK] Found python3.dll\n");
  } else {
    for (int i = 13; i >= 6; i--) {
      _snprintf_s(dllName, sizeof(dllName), _TRUNCATE, "python3%d.dll", i);
      dllName[sizeof(dllName) - 1] = '\0';
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

  typedef void *(*PyImportModuleFunc)(const char *);
  typedef void (*Py_DecRefFunc)(void *);
  typedef int (*PyGILState_EnsureFunc)();
  typedef void (*PyGILState_ReleaseFunc)(int);
  typedef void (*PyErr_PrintFunc)();
  typedef int (*PyRun_SimpleStringFunc)(const char *);

  auto PyImport_ImportModule =
      (PyImportModuleFunc)GetProcAddress(hPyDll, "PyImport_ImportModule");
  auto Py_DecRef = (Py_DecRefFunc)GetProcAddress(hPyDll, "Py_DecRef");
  auto PyGILState_Ensure =
      (PyGILState_EnsureFunc)GetProcAddress(hPyDll, "PyGILState_Ensure");
  auto PyGILState_Release =
      (PyGILState_ReleaseFunc)GetProcAddress(hPyDll, "PyGILState_Release");
  auto PyErr_Print = (PyErr_PrintFunc)GetProcAddress(hPyDll, "PyErr_Print");
  auto PyRun_SimpleString =
      (PyRun_SimpleStringFunc)GetProcAddress(hPyDll, "PyRun_SimpleString");

  if (!PyImport_ImportModule || !PyGILState_Ensure || !PyGILState_Release) {
    dbgPrintf("[HOOK] ERROR: Cannot load Python C-API functions\n");
    return 1;
  }

  int gilState = PyGILState_Ensure();

  // CRITICAL FIX: Allocate larger buffer for Python setup code
  char *pycmd = (char *)malloc(16384);
  if (!pycmd) {
    dbgPrintf("[HOOK] ERROR: Memory allocation failed for Python setup command\n");
    PyGILState_Release(gilState);
    return 1;
  }

  if (PyRun_SimpleString) {
    char pyLogPath[MAX_PATH];
    strncpy_s(pyLogPath, sizeof(pyLogPath), logPathBuf, _TRUNCATE);
    pyLogPath[sizeof(pyLogPath) - 1] = '\0';

    for (char *p = pyLogPath; *p; ++p) {
      if (*p == '\\') *p = '/';
    }

    char pyHomePath[MAX_PATH];
    strncpy_s(pyHomePath, sizeof(pyHomePath), g_pythonHomePath, _TRUNCATE);
    pyHomePath[sizeof(pyHomePath) - 1] = '\0';
    for (char *p = pyHomePath; *p; ++p) {
      if (*p == '\\') *p = '/';
    }

    // Safely build Python setup command
    int written = _snprintf_s(
        pycmd, 16384,
        _TRUNCATE,
        "import sys, os\n"
        "try:\n"
        "    f = open(r'%s', 'a', buffering=1, encoding='utf-8')\n"
        "    sys.stdout = f\n"
        "    sys.stderr = f\n"
        "    print('Python stdout/stderr redirected')\n"
        "    print('sys.executable:', sys.executable)\n"
        "    print('sys.prefix:', sys.prefix)\n"
        "    pythonhome = r'%s'\n"
        "    print('Detected PYTHONHOME:', pythonhome)\n"
        "    \n"
        "    # CRITICAL: Add DLLs directory for compiled extensions like _ctypes\n"
        "    if pythonhome and os.path.isdir(pythonhome):\n"
        "        dlls_dir = os.path.join(pythonhome, 'DLLs')\n"
        "        lib_dir = os.path.join(pythonhome, 'Lib')\n"
        "        site_packages = os.path.join(lib_dir, 'site-packages')\n"
        "        \n"
        "        # Add DLLs first (contains _ctypes.pyd, etc.)\n"
        "        if os.path.isdir(dlls_dir) and dlls_dir not in sys.path:\n"
        "            sys.path.insert(0, dlls_dir)\n"
        "            print('Added DLLs directory:', dlls_dir)\n"
        "            # Also add to PATH for DLL loading\n"
        "            if dlls_dir not in os.environ.get('PATH', ''):\n"
        "                os.environ['PATH'] = dlls_dir + os.pathsep + os.environ.get('PATH', '')\n"
        "                print('Added DLLs to PATH')\n"
        "        \n"
        "        if os.path.isdir(lib_dir) and lib_dir not in sys.path:\n"
        "            sys.path.insert(0, lib_dir)\n"
        "            print('Added Lib directory:', lib_dir)\n"
        "        \n"
        "        if os.path.isdir(site_packages) and site_packages not in sys.path:\n"
        "            sys.path.insert(0, site_packages)\n"
        "            print('Added site-packages:', site_packages)\n"
        "    \n"
        "    # Add current working directory and executable directory\n"
        "    cwd = os.getcwd()\n"
        "    exe_dir = os.path.dirname(sys.executable)\n"
        "    if cwd not in sys.path: \n"
        "        sys.path.insert(0, cwd)\n"
        "        print('Added CWD:', cwd)\n"
        "    if exe_dir not in sys.path: \n"
        "        sys.path.insert(0, exe_dir)\n"
        "        print('Added exe dir:', exe_dir)\n"
        "    \n"
        "    # Add global hook path from environment\n"
        "    env_hook = os.environ.get('HYDRA_HOOK_PATH')\n"
        "    if env_hook and os.path.exists(env_hook) and env_hook not in sys.path:\n"
        "        sys.path.insert(0, env_hook)\n"
        "        print('Added env hook path:', env_hook)\n"
        "    \n"
        "    # Test if _ctypes is now available\n"
        "    try:\n"
        "        import _ctypes\n"
        "        print('SUCCESS: _ctypes is available')\n"
        "    except ImportError as e:\n"
        "        print('WARNING: _ctypes still not available:', e)\n"
        "        print('This will cause ctypes imports to fail')\n"
        "    \n"
        "    # Test concurrent.futures\n"
        "    try:\n"
        "        import concurrent.futures\n"
        "        print('SUCCESS: concurrent.futures available')\n"
        "    except ImportError as e:\n"
        "        print('ERROR: concurrent.futures not available:', e)\n"
        "    \n"
        "    print('Final sys.path:', sys.path[:5], '...')\n"
        "except Exception as e:\n"
        "    print('Setup error:', e)\n"
        "    import traceback\n"
        "    traceback.print_exc()\n",
        pyLogPath, pyHomePath);

    if (written < 0) {
      dbgPrintf("[HOOK] WARNING: Python setup command truncated!\n");
    }

    int res = PyRun_SimpleString(pycmd);
    dbgPrintf("[HOOK] Setup returned: %d\n", res);
    
    if (res != 0 && PyErr_Print) {
      PyErr_Print();
    }
  }

  free(pycmd);

  // Try importing hook module
  void *hook_module = PyImport_ImportModule(PYMODULE_NAME);

  if (hook_module) {
    Py_DecRef(hook_module);
    PyGILState_Release(gilState);
    dbgPrintf("[HOOK] Successfully imported %s\n", PYMODULE_NAME);
    return 0;
  }

  // Fallback: explicit file execution
  dbgPrintf("[HOOK] Standard import failed, trying explicit execution\n");

  char hookFilePath[MAX_PATH];
  if (GetHookFilePathFromConfig(hookFilePath, MAX_PATH)) {
    dbgPrintf("[HOOK] Explicit hook path: %s\n", hookFilePath);

    // Extract directory from hook file path and add to sys.path
    char hookDir[MAX_PATH];
    strncpy_s(hookDir, MAX_PATH, hookFilePath, _TRUNCATE);
    hookDir[MAX_PATH - 1] = '\0';
    PathRemoveFileSpecA(hookDir); // Get directory only

    // Convert backslashes for Python
    char pyHookPath[MAX_PATH];
    strncpy_s(pyHookPath, MAX_PATH, hookFilePath, _TRUNCATE);
    pyHookPath[MAX_PATH - 1] = '\0';
    for (char *p = pyHookPath; *p; ++p) 
      if (*p == '\\') *p = '/';

    char pyHookDir[MAX_PATH];
    strncpy_s(pyHookDir, MAX_PATH, hookDir, _TRUNCATE);
    pyHookDir[MAX_PATH - 1] = '\0';
    for (char *p = pyHookDir; *p; ++p) 
      if (*p == '\\') *p = '/';

    // CRITICAL FIX: Add hook directory to sys.path BEFORE importing
    char *addPathCmd = (char *)malloc(8192);
    if (addPathCmd) {
      _snprintf_s(addPathCmd, 8192, _TRUNCATE,
               "import sys, os\n"
               "try:\n"
               "    hook_dir = r'%s'\n"
               "    print('Target hook directory:', hook_dir)\n"
               "    print('Directory exists:', os.path.exists(hook_dir))\n"
               "    \n"
               "    # Normalize path\n"
               "    hook_dir = os.path.abspath(hook_dir)\n"
               "    print('Normalized hook directory:', hook_dir)\n"
               "    \n"
               "    if hook_dir not in sys.path:\n"
               "        sys.path.insert(0, hook_dir)\n"
               "        print('Added to sys.path')\n"
               "    else:\n"
               "        print('Already in sys.path')\n"
               "    \n"
               "    print('Current sys.path:', sys.path)\n"
               "    \n"
               "    # Verify hook file exists\n"
               "    hook_file = os.path.join(hook_dir, '__hook__.py')\n"
               "    print('Looking for:', hook_file)\n"
               "    print('Hook file exists:', os.path.exists(hook_file))\n"
               "    \n"
               "    if os.path.exists(hook_file):\n"
               "        print('Hook file found and accessible')\n"
               "    else:\n"
               "        print('ERROR: Hook file not found at expected location')\n"
               "        print('Contents of hook dir:')\n"
               "        try:\n"
               "            for item in os.listdir(hook_dir):\n"
               "                print('  -', item)\n"
               "        except Exception as e:\n"
               "            print('Cannot list directory:', e)\n"
               "except Exception as e:\n"
               "    print('ERROR in path addition:', type(e).__name__, str(e))\n"
               "    import traceback\n"
               "    traceback.print_exc()\n",
               pyHookDir);
      
      int pathRes = PyRun_SimpleString(addPathCmd);
      dbgPrintf("[HOOK] Added hook dir to sys.path, result: %d\n", pathRes);
      free(addPathCmd);
      
      // Now try importing again
      if (pathRes == 0) {
        void *hook_module_retry = PyImport_ImportModule(PYMODULE_NAME);
        if (hook_module_retry) {
          Py_DecRef(hook_module_retry);
          PyGILState_Release(gilState);
          dbgPrintf("[HOOK] Successfully imported %s after adding path\n", PYMODULE_NAME);
          return 0;
        } else {
          dbgPrintf("[HOOK] Import still failed after adding path, checking error...\n");
          if (PyErr_Print) PyErr_Print();
        }
      } else {
        dbgPrintf("[HOOK] Path addition returned error code, checking Python error...\n");
        if (PyErr_Print) PyErr_Print();
      }
    }

    // If import still fails, try direct execution with proper globals
    char *execCmd = (char *)malloc(16384);
    if (execCmd) {
      int written = _snprintf_s(execCmd, 16384, _TRUNCATE,
               "import sys, os\n"
               "print('\\n=== Direct Execution of Hook File ===')\n"
               "path = r'%s'\n"
               "print('Target:', path)\n"
               "print('Path exists:', os.path.exists(path))\n"
               "print('Path is absolute:', os.path.isabs(path))\n"
               "print('Current working directory:', os.getcwd())\n"
               "\n"
               "if os.path.exists(path):\n"
               "    try:\n"
               "        # Set up proper module context\n"
               "        hook_globals = {\n"
               "            '__name__': '%s',\n"
               "            '__file__': path,\n"
               "            '__package__': None,\n"
               "            '__builtins__': __builtins__,\n"
               "        }\n"
               "        \n"
               "        # Compile and execute directly from the file handle\n"
               "        with open(path, 'r', encoding='utf-8') as f:\n"
               "            print('Hook file opened successfully')\n"
               "            exec(compile(f.read(), path, 'exec'), hook_globals)\n"
               "        print('=== Hook Execution Completed Successfully ===')\n"
               "    except SyntaxError as e:\n"
               "        print('\\n=== SYNTAX ERROR IN HOOK FILE ===')\n"
               "        print('Line', e.lineno, ':', e.msg)\n"
               "        print('Text:', e.text)\n"
               "        import traceback\n"
               "        traceback.print_exc()\n"
               "        raise\n"
               "    except Exception as e:\n"
               "        print('\\n=== HOOK EXECUTION ERROR ===')\n"
               "        print('Error type:', type(e).__name__)\n"
               "        print('Error message:', str(e))\n"
               "        import traceback\n"
               "        traceback.print_exc()\n"
               "        print('=== END ERROR ===')\n"
               "        raise\n"
               "else:\n"
               "    print('\\n=== ERROR: HOOK FILE NOT FOUND ===')\n"
               "    print('Searched for:', path)\n"
               "    \n"
               "    # Try to find it\n"
               "    hook_dir = os.path.dirname(path)\n"
               "    hook_name = os.path.basename(path)\n"
               "    print('Hook directory:', hook_dir)\n"
               "    print('Hook filename:', hook_name)\n"
               "    \n"
               "    if os.path.exists(hook_dir):\n"
               "        print('Directory exists. Contents:')\n"
               "        try:\n"
               "            for item in os.listdir(hook_dir):\n"
               "                print('  -', item)\n"
               "        except Exception as e:\n"
               "            print('Cannot list directory:', e)\n"
               "    else:\n"
               "        print('ERROR: Directory does not exist!')\n"
               "    \n"
               "    print('sys.path entries:')\n"
               "    for p in sys.path:\n"
               "        print('  -', p)\n"
               "    \n"
               "    raise FileNotFoundError(f'Hook file not found: {path}')\n", 
               pyHookPath, PYMODULE_NAME);

      if (written >= 0) {
        dbgPrintf("[HOOK] Executing hook file directly...\n");
        int execRes = PyRun_SimpleString(execCmd);
        dbgPrintf("[HOOK] Direct execution returned: %d\n", execRes);
        
        if (execRes == 0) {
          free(execCmd);
          PyGILState_Release(gilState);
          dbgPrintf("[HOOK] Hook executed successfully via direct exec\n");
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
  return 1;
  } catch (const std::bad_alloc &) {
    dbgPrintf("[HOOK] ERROR: C++ exception: bad_alloc during hook startup\n");
  } catch (const std::exception &ex) {
    dbgPrintf("[HOOK] ERROR: C++ exception during hook startup: %s\n", ex.what());
  } catch (...) {
    dbgPrintf("[HOOK] ERROR: Unknown C++ exception during hook startup\n");
  }

  return ERROR_DLL_INIT_FAILED;
}

static void ReleaseWorkerThreadHandle() {
  if (g_workerThread) {
    CloseHandle(g_workerThread);
    g_workerThread = NULL;
  }
  g_workerThreadId = 0;
}

static void CleanupResources() {
  ReleaseWorkerThreadHandle();
  InterlockedExchange(&g_started, 0);

  if (g_logCSInitialized) {
    DeleteCriticalSection(&g_logCS);
    g_logCSInitialized = false;
  }
  if (g_logFile) {
    fclose(g_logFile);
    g_logFile = NULL;
  }
}

extern "C" __declspec(dllexport) DWORD WINAPI HydraStartHook() {
  if (InterlockedCompareExchange(&g_unloading, 0, 0) != 0)
    return ERROR_DLL_INIT_FAILED;

  if (InterlockedCompareExchange(&g_started, 1, 0) != 0)
    return ERROR_ALREADY_EXISTS;

  unsigned threadId = 0;
  uintptr_t workerHandle = _beginthreadex(nullptr, 0, hookImpl, nullptr, 0, &threadId);
  if (!workerHandle) {
    InterlockedExchange(&g_started, 0);
    return ERROR_DLL_INIT_FAILED;
  }

  g_workerThread = reinterpret_cast<HANDLE>(workerHandle);
  g_workerThreadId = static_cast<DWORD>(threadId);

  DWORD waitResult = WaitForSingleObject(g_workerThread, INFINITE);
  if (waitResult != WAIT_OBJECT_0) {
    DWORD err = GetLastError();
    CleanupResources();
    return err ? err : ERROR_DLL_INIT_FAILED;
  }

  DWORD exitCode = ERROR_DLL_INIT_FAILED;
  if (!GetExitCodeThread(g_workerThread, &exitCode))
    exitCode = ERROR_DLL_INIT_FAILED;

  ReleaseWorkerThreadHandle();

  if (exitCode != ERROR_SUCCESS)
    InterlockedExchange(&g_started, 0);

  return exitCode;
}

extern "C" __declspec(dllexport) DWORD WINAPI HydraStopHook(DWORD timeoutMs) {
  if (g_workerThread) {
    DWORD wr = WaitForSingleObject(g_workerThread, timeoutMs);
    if (wr == WAIT_TIMEOUT)
      return WAIT_TIMEOUT;
  }

  CleanupResources();
  return ERROR_SUCCESS;
}

extern "C" __declspec(dllexport) DWORD WINAPI HydraInitialize() {
  return HydraStartHook();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  UNREFERENCED_PARAMETER(lpvReserved);

  if (fdwReason == DLL_PROCESS_ATTACH) {
    g_hInstance = hinstDLL;
    DisableThreadLibraryCalls(hinstDLL);
  } else if (fdwReason == DLL_PROCESS_DETACH) {
    InterlockedExchange(&g_unloading, 1);
  }
  return TRUE;
}









