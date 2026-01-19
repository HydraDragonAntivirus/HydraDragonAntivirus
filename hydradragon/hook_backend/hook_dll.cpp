/**
 * hook_dll.cpp - FIXED VERSION
 * Critical fixes for access violations:
 * 1. Increased buffer sizes to prevent overflow
 * 2. Fixed strtok use-after-free with PATH parsing
 * 3. Added null pointer checks
 * 4. Thread-safe logging
 */

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

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

// Global storage
static char g_pythonHomePath[MAX_PATH] = {0};
#define PYMODULE_NAME "__hook__"

static FILE *g_logFile = NULL;
static CRITICAL_SECTION g_logCS; // Thread-safe logging
static bool g_logCSInitialized = false;

// Thread-safe debug print
static void dbgPrintf(const char *fmt, ...) {
  char buf[2048]; // Increased size
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
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
  const char *configPath = "C:\\pythondumps\\hook_config.ini";
  FILE *f = fopen(configPath, "r");
  if (!f) return false;

  char line[MAX_PATH];
  bool found = false;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "HookPath=", 9) == 0) {
      char *path = line + 9;
      char *nl = strpbrk(path, "\r\n");
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
          if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
            strncpy(outPath, path, maxLen - 1);
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
  if (!dir || !outPath) return false;
  
  char libPath[MAX_PATH];
  snprintf(libPath, MAX_PATH, "%s\\Lib", dir);
  libPath[MAX_PATH - 1] = '\0';

  DWORD attrib = GetFileAttributesA(libPath);
  if (attrib != INVALID_FILE_ATTRIBUTES &&
      (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
    strncpy(outPath, dir, maxLen - 1);
    outPath[maxLen - 1] = '\0';
    return true;
  }
  return false;
}

static bool ScanBasePathForPython(const char *basePath, char *outPath,
                                  size_t maxLen) {
  if (!basePath || !outPath) return false;
  
  char searchPattern[MAX_PATH];
  snprintf(searchPattern, MAX_PATH, "%s\\Python3*", basePath);
  searchPattern[MAX_PATH - 1] = '\0';

  WIN32_FIND_DATAA findData;
  HANDLE hFind = FindFirstFileA(searchPattern, &findData);

  if (hFind == INVALID_HANDLE_VALUE) {
    return false;
  }

  std::vector<std::string> foundHomes;

  do {
    if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        strcmp(findData.cFileName, ".") != 0 &&
        strcmp(findData.cFileName, "..") != 0) {

      char testDir[MAX_PATH];
      snprintf(testDir, MAX_PATH, "%s\\%s", basePath, findData.cFileName);
      testDir[MAX_PATH - 1] = '\0';

      char tempPath[MAX_PATH];
      if (IsValidPythonHome(testDir, tempPath, MAX_PATH)) {
        foundHomes.push_back(findData.cFileName);
      }
    }
  } while (FindNextFileA(hFind, &findData));

  FindClose(hFind);

  if (foundHomes.empty()) {
    return false;
  }

  std::sort(foundHomes.rbegin(), foundHomes.rend());

  snprintf(outPath, maxLen, "%s\\%s", basePath, foundHomes[0].c_str());
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

    snprintf(localPrograms, MAX_PATH, "%s\\Programs\\Python", basePath);
    localPrograms[MAX_PATH - 1] = '\0';
    if (ScanBasePathForPython(localPrograms, outPath, maxLen))
      return true;

    snprintf(localPrograms, MAX_PATH, "%s\\Programs", basePath);
    localPrograms[MAX_PATH - 1] = '\0';
    if (ScanBasePathForPython(localPrograms, outPath, maxLen))
      return true;
  }

  return false;
}

static void AutoSetPythonHome() {
  char existing[MAX_PATH];
  if (GetEnvironmentVariableA("PYTHONHOME", existing, MAX_PATH) > 0) {
    dbgPrintf("[HOOK] PYTHONHOME already set to: %s\n", existing);
    strncpy(g_pythonHomePath, existing, MAX_PATH - 1);
    g_pythonHomePath[MAX_PATH - 1] = '\0';
    return;
  }

  char pythonHome[MAX_PATH];
  bool found = false;

  // Method 0: Check current process
  char currentExe[MAX_PATH];
  if (GetModuleFileNameA(NULL, currentExe, MAX_PATH)) {
    const char *filename = strrchr(currentExe, '\\');
    if (filename)
      filename++;
    else
      filename = currentExe;

    if (strcasecmp(filename, "python.exe") == 0 ||
        strcasecmp(filename, "pythonw.exe") == 0) {
      strncpy(pythonHome, currentExe, MAX_PATH - 1);
      pythonHome[MAX_PATH - 1] = '\0';
      PathRemoveFileSpecA(pythonHome);
      found = true;
      dbgPrintf("[HOOK] Using current python.exe dir: %s\n", pythonHome);
    }
  }

  // Method 1: Find python.exe in processes
  if (!found) {
    char pythonExe[MAX_PATH];
    if (FindPythonExePath(pythonExe, MAX_PATH)) {
      strncpy(pythonHome, pythonExe, MAX_PATH - 1);
      pythonHome[MAX_PATH - 1] = '\0';
      PathRemoveFileSpecA(pythonHome);
      if (IsValidPythonHome(pythonHome, pythonHome, MAX_PATH))
        found = true;
    }
  }

  // Method 2: Check common paths
  if (!found)
    found = FindPythonInstallation(pythonHome, MAX_PATH);
  
  // Method 3: Check PATH environment - FIXED strtok issue
  if (!found) {
    char *pathEnv = (char *)malloc(32768);
    if (pathEnv) {
      DWORD pathLen = GetEnvironmentVariableA("PATH", pathEnv, 32768);
      if (pathLen > 0 && pathLen < 32768) {
        char *context = NULL;
        char *token = strtok_s(pathEnv, ";", &context); // Use strtok_s for safety
        while (token != NULL) {
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
          token = strtok_s(NULL, ";", &context);
        }
      }
      free(pathEnv);
    }
  }

  if (found) {
    SetEnvironmentVariableA("PYTHONHOME", pythonHome);
    strncpy(g_pythonHomePath, pythonHome, MAX_PATH - 1);
    g_pythonHomePath[MAX_PATH - 1] = '\0';

    dbgPrintf("[HOOK] Set PYTHONHOME=%s\n", pythonHome);

    char pythonPath[MAX_PATH * 2];
    snprintf(pythonPath, sizeof(pythonPath), "%s\\Lib;%s\\Lib\\site-packages",
             pythonHome, pythonHome);
    pythonPath[sizeof(pythonPath) - 1] = '\0';
    SetEnvironmentVariableA("PYTHONPATH", pythonPath);
    dbgPrintf("[HOOK] Set PYTHONPATH=%s\n", pythonPath);
  } else {
    dbgPrintf("[HOOK] Could not auto-detect PYTHONHOME\n");
  }
}

static bool SetupStdoutStderrToLog(char *outLogPath) {
  char logDir[] = "C:\\pythondumps";
  CreateDirectoryA(logDir, NULL);

  char logPath[MAX_PATH];
  snprintf(logPath, MAX_PATH, "%s\\hook_dll.log", logDir);
  logPath[MAX_PATH - 1] = '\0';

  g_logFile = fopen(logPath, "a");
  if (!g_logFile) {
    char publicLogDir[] = "C:\\Users\\Public\\pythondumps";
    CreateDirectoryA(publicLogDir, NULL);
    snprintf(logPath, MAX_PATH, "%s\\hook_dll.log", publicLogDir);
    logPath[MAX_PATH - 1] = '\0';
    g_logFile = fopen(logPath, "a");
  }

  if (!g_logFile)
    return false;

  setvbuf(g_logFile, NULL, _IOLBF, 0);
  
  // Don't redirect stdout/stderr via freopen - can cause crashes
  // Let Python handle its own redirection
  
  if (outLogPath) {
    strncpy(outLogPath, logPath, MAX_PATH - 1);
    outLogPath[MAX_PATH - 1] = '\0';
  }

  dbgPrintf("[HOOK] Log file: %s\n", logPath);
  return true;
}

DWORD WINAPI hookImpl(LPVOID lpParam) {
  // Initialize logging critical section
  if (!g_logCSInitialized) {
    InitializeCriticalSection(&g_logCS);
    g_logCSInitialized = true;
  }

  AutoSetPythonHome();
  CheckForProtection();

  char logPathBuf[MAX_PATH] = {0};
  SetupStdoutStderrToLog(logPathBuf);

  char dllName[64];
  HMODULE hPyDll = nullptr;

  hPyDll = GetModuleHandleA("python3.dll");
  if (hPyDll) {
    strncpy(dllName, "python3.dll", sizeof(dllName) - 1);
    dbgPrintf("[HOOK] Found python3.dll\n");
  } else {
    for (int i = 13; i >= 6; i--) {
      snprintf(dllName, sizeof(dllName), "python3%d.dll", i);
      dllName[sizeof(dllName) - 1] = '\0';
      hPyDll = GetModuleHandleA(dllName);
      if (hPyDll) {
        dbgPrintf("[HOOK] Found %s\n", dllName);
        break;
      }
    }
  }

  if (!hPyDll) {
    MessageBoxA(NULL, "No python3x.dll found", "Hook Error", MB_ICONEXCLAMATION);
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
    MessageBoxA(NULL, "Cannot load Python C-API functions", "Hook Error",
                MB_ICONEXCLAMATION);
    return 1;
  }

  int gilState = PyGILState_Ensure();

  // CRITICAL FIX: Allocate larger buffer for Python setup code
  char *pycmd = (char *)malloc(16384);
  if (!pycmd) {
    MessageBoxA(NULL, "Memory allocation failed", "Hook Error", MB_ICONEXCLAMATION);
    PyGILState_Release(gilState);
    return 1;
  }

  if (PyRun_SimpleString) {
    char pyLogPath[MAX_PATH];
    strncpy(pyLogPath, logPathBuf, sizeof(pyLogPath) - 1);
    pyLogPath[sizeof(pyLogPath) - 1] = '\0';

    for (char *p = pyLogPath; *p; ++p) {
      if (*p == '\\') *p = '/';
    }

    char pyHomePath[MAX_PATH];
    strncpy(pyHomePath, g_pythonHomePath, sizeof(pyHomePath) - 1);
    pyHomePath[sizeof(pyHomePath) - 1] = '\0';
    for (char *p = pyHomePath; *p; ++p) {
      if (*p == '\\') *p = '/';
    }

    // Safely build Python setup command
    int written = snprintf(
        pycmd, 16384,
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

    if (written >= 16384) {
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
    MessageBoxA(NULL, "Hook injection successful!", "Success", MB_OK);
    return 0;
  }

  // Fallback: explicit file execution
  dbgPrintf("[HOOK] Standard import failed, trying explicit execution\n");

  char hookFilePath[MAX_PATH];
  if (GetHookFilePathFromConfig(hookFilePath, MAX_PATH)) {
    dbgPrintf("[HOOK] Explicit hook path: %s\n", hookFilePath);

    // Extract directory from hook file path and add to sys.path
    char hookDir[MAX_PATH];
    strncpy(hookDir, hookFilePath, MAX_PATH - 1);
    hookDir[MAX_PATH - 1] = '\0';
    PathRemoveFileSpecA(hookDir); // Get directory only

    // Convert backslashes for Python
    char pyHookPath[MAX_PATH];
    strncpy(pyHookPath, hookFilePath, MAX_PATH - 1);
    pyHookPath[MAX_PATH - 1] = '\0';
    for (char *p = pyHookPath; *p; ++p) 
      if (*p == '\\') *p = '/';

    char pyHookDir[MAX_PATH];
    strncpy(pyHookDir, hookDir, MAX_PATH - 1);
    pyHookDir[MAX_PATH - 1] = '\0';
    for (char *p = pyHookDir; *p; ++p) 
      if (*p == '\\') *p = '/';

    // CRITICAL FIX: Add hook directory to sys.path BEFORE importing
    char *addPathCmd = (char *)malloc(8192);
    if (addPathCmd) {
      snprintf(addPathCmd, 8192,
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
          MessageBoxA(NULL, "Hook injection successful!", "Success", MB_OK);
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
      int written = snprintf(execCmd, 16384, 
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
               "        # Verify file is readable\n"
               "        with open(path, 'r', encoding='utf-8') as f:\n"
               "            code_str = f.read()\n"
               "        print('Successfully read', len(code_str), 'bytes from hook file')\n"
               "        \n"
               "        # Set up proper module context\n"
               "        hook_globals = {\n"
               "            '__name__': '%s',\n"
               "            '__file__': path,\n"
               "            '__package__': None,\n"
               "            '__builtins__': __builtins__,\n"
               "        }\n"
               "        \n"
               "        # Compile and execute\n"
               "        code_obj = compile(code_str, path, 'exec')\n"
               "        exec(code_obj, hook_globals)\n"
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

      if (written < 16384) {
        dbgPrintf("[HOOK] Executing hook file directly...\n");
        int execRes = PyRun_SimpleString(execCmd);
        dbgPrintf("[HOOK] Direct execution returned: %d\n", execRes);
        
        if (execRes == 0) {
          free(execCmd);
          PyGILState_Release(gilState);
          dbgPrintf("[HOOK] Hook executed successfully via direct exec\n");
          MessageBoxA(NULL, "Hook successful (direct exec)!", "Success", MB_OK);
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
  MessageBoxA(NULL, "Failed to import hook\nCheck logs", "Hook Error", MB_ICONEXCLAMATION);
  return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hinstDLL); // Reduce overhead
    HANDLE hThread = CreateThread(nullptr, 0, hookImpl, nullptr, 0, nullptr);
    if (hThread)
      CloseHandle(hThread);
  } else if (fdwReason == DLL_PROCESS_DETACH) {
    if (g_logCSInitialized) {
      DeleteCriticalSection(&g_logCS);
      g_logCSInitialized = false;
    }
    if (g_logFile) {
      fclose(g_logFile);
      g_logFile = NULL;
    }
  }
  return TRUE;
}
