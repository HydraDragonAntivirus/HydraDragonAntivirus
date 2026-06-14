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
// Windows header must be included first
#include <psapi.h>

#include <direct.h>
#include <exception>
#include <new>
#include <process.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <share.h>


#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

// Global storage
static char g_pythonHomePath[MAX_PATH] = {0};
#define PYMODULE_NAME "__hook__"
#define PYTHON_DUMPS_DIR "C:\\ProgramData\\HydraDragonAntivirus\\hydradragon\\python_dumps"

static FILE *g_logFile = NULL;
static CRITICAL_SECTION g_logCS; // Thread-safe logging
static bool g_logCSInitialized = false;
static HINSTANCE g_hInstance = NULL;

static void __cdecl HydraInvalidParameterHandler(const wchar_t *expression,
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
  const char *configPath =
      "C:\\ProgramData\\HydraDragonAntivirus\\hydradragon\\python_dumps\\hook_config.ini";
  FILE *f = NULL;
  if (fopen_s(&f, configPath, "r") != 0 || !f)
    return false;

  char line[MAX_PATH];
  bool found = false;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "HookPath=", 9) == 0) {
      char *path = line + 9;
      char *nl = strpbrk(path, "\r\n");
      if (nl)
        *nl = '\0';

      if (path[0] != '\0') {
        // Check if path already ends with .py
        size_t len = strlen(path);
        if (len > 3 && _stricmp(path + len - 3, ".py") == 0) {
          strncpy_s(outPath, maxLen, path, _TRUNCATE);
        } else {
          _snprintf_s(outPath, maxLen, _TRUNCATE, "%s\\%s.py", path,
                      PYMODULE_NAME);
        }
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
            (rank == bestRank &&
             _stricmp(findData.cFileName, bestFolder) > 0)) {
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

    _snprintf_s(localPrograms, MAX_PATH, _TRUNCATE, "%s\\Programs\\Python",
                basePath);
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

  if (SUCCEEDED(
          SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
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

  for (size_t i = 0;
       i < sizeof(fallbackCandidates) / sizeof(fallbackCandidates[0]); ++i) {
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
      "python313.dll", "python312.dll", "python311.dll",
      "python310.dll", "python39.dll",  "python38.dll",
      "python37.dll",  "python36.dll",  "python3.dll",
  };

  char modulePath[MAX_PATH] = {0};
  char homePath[MAX_PATH] = {0};
  char parentPath[MAX_PATH] = {0};

  for (size_t i = 0; i < sizeof(dllCandidates) / sizeof(dllCandidates[0]);
       ++i) {
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

// Returns the raw directory containing the loaded pythonXY.dll — no Lib/
// check. This is the Nuitka temp extraction dir when running a OneFile build,
// and it contains the bundled _ctypes.pyd / other extension modules.
static bool GetLoadedPythonDllDir(char *outPath, size_t maxLen) {
  if (!outPath || maxLen == 0)
    return false;

  for (int i = 15; i >= 6; i--) {
    char dllName[32];
    _snprintf_s(dllName, sizeof(dllName), _TRUNCATE, "python3%d.dll", i);
    dllName[sizeof(dllName) - 1] = '\0';
    HMODULE hPy = GetModuleHandleA(dllName);
    if (!hPy)
      continue;

    DWORD len = GetModuleFileNameA(hPy, outPath, (DWORD)maxLen);
    if (len > 0 && len < maxLen) {
      outPath[maxLen - 1] = '\0';
      PathRemoveFileSpecA(outPath);
      dbgPrintf("[HOOK] Loaded DLL dir (Nuitka temp): %s\n", outPath);
      return true;
    }
    break;
  }
  return false;
}

static int GetLoadedPythonRuntimeTag() {
  for (int i = 15; i >= 6; --i) {
    char dllName[32];
    _snprintf_s(dllName, sizeof(dllName), _TRUNCATE, "python3%d.dll", i);
    dllName[sizeof(dllName) - 1] = '\0';
    if (GetModuleHandleA(dllName))
      return i;
  }
  return 0;
}

static bool PythonHomeMatchesLoadedRuntime(const char *pythonHome,
                                           int loadedRuntimeTag) {
  if (!pythonHome || pythonHome[0] == '\0' || loadedRuntimeTag == 0)
    return true;

  char marker[32];
  _snprintf_s(marker, sizeof(marker), _TRUNCATE, "Python3%d", loadedRuntimeTag);
  marker[sizeof(marker) - 1] = '\0';
  if (StrStrIA(pythonHome, marker) != NULL)
    return true;

  char dllPath[MAX_PATH];
  _snprintf_s(dllPath, MAX_PATH, _TRUNCATE, "%s\\python3%d.dll", pythonHome,
              loadedRuntimeTag);
  dllPath[MAX_PATH - 1] = '\0';
  DWORD attrib = GetFileAttributesA(dllPath);
  if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY))
    return true;

  _snprintf_s(dllPath, MAX_PATH, _TRUNCATE, "%s\\DLLs\\python3%d.dll",
              pythonHome, loadedRuntimeTag);
  dllPath[MAX_PATH - 1] = '\0';
  attrib = GetFileAttributesA(dllPath);
  if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY))
    return true;

  return false;
}

// Find the installed Python home that matches the pythonXY.dll actually
// loaded in this process. This avoids version mismatches where (e.g.)
// python311.dll is loaded but PYTHONHOME points at Python312.
static bool FindPythonHomeForLoadedDll(char *outPath, size_t maxLen) {
  if (!outPath || maxLen == 0)
    return false;

  char localAppData[MAX_PATH] = {0};
  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);

  // Walk from newest to oldest to match FindLoadedPythonHome search order.
  for (int i = 15; i >= 6; i--) {
    char dllName[32];
    _snprintf_s(dllName, sizeof(dllName), _TRUNCATE, "python3%d.dll", i);
    dllName[sizeof(dllName) - 1] = '\0';
    if (!GetModuleHandleA(dllName))
      continue;

    dbgPrintf("[HOOK] Detected loaded runtime: python3%d.dll — searching for "
              "matching install\n", i);

    char candidate[MAX_PATH];

    // %LOCALAPPDATA%\Programs\Python\Python3X
    if (localAppData[0]) {
      _snprintf_s(candidate, MAX_PATH, _TRUNCATE,
                  "%s\\Programs\\Python\\Python3%d", localAppData, i);
      candidate[MAX_PATH - 1] = '\0';
      if (IsValidPythonHome(candidate, outPath, maxLen)) {
        dbgPrintf("[HOOK] Matched loaded DLL to install: %s\n", outPath);
        return true;
      }
    }

    // C:\Python3X
    _snprintf_s(candidate, MAX_PATH, _TRUNCATE, "C:\\Python3%d", i);
    candidate[MAX_PATH - 1] = '\0';
    if (IsValidPythonHome(candidate, outPath, maxLen)) {
      dbgPrintf("[HOOK] Matched loaded DLL to install: %s\n", outPath);
      return true;
    }

    // C:\Program Files\Python3X
    _snprintf_s(candidate, MAX_PATH, _TRUNCATE,
                "C:\\Program Files\\Python3%d", i);
    candidate[MAX_PATH - 1] = '\0';
    if (IsValidPythonHome(candidate, outPath, maxLen)) {
      dbgPrintf("[HOOK] Matched loaded DLL to install: %s\n", outPath);
      return true;
    }

    // C:\Program Files (x86)\Python3X
    _snprintf_s(candidate, MAX_PATH, _TRUNCATE,
                "C:\\Program Files (x86)\\Python3%d", i);
    candidate[MAX_PATH - 1] = '\0';
    if (IsValidPythonHome(candidate, outPath, maxLen)) {
      dbgPrintf("[HOOK] Matched loaded DLL to install: %s\n", outPath);
      return true;
    }

    // Found the loaded DLL but no matching install — stop searching.
    dbgPrintf("[HOOK] WARNING: python3%d.dll loaded but no matching install "
              "found\n", i);
    break;
  }
  return false;
}

static void AutoSetPythonHome() {
  char pythonHome[MAX_PATH] = {0};
  bool found = false;
  const int loadedRuntimeTag = GetLoadedPythonRuntimeTag();

  // PRIORITY 1: Find the installed home that matches the loaded pythonXY.dll.
  // This must come first so DLLs/Lib always match the actual runtime version.
  if (FindPythonHomeForLoadedDll(pythonHome, MAX_PATH))
    found = true;

  // PRIORITY 2: Fallback — use the directory of the loaded DLL itself
  // (handles in-place / embedded installs without a standard layout).
  if (!found && FindLoadedPythonHome(pythonHome, MAX_PATH))
    found = true;

  // PRIORITY 3: Use the current executable's Python home when available.
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
          if (PythonHomeMatchesLoadedRuntime(pythonHome, loadedRuntimeTag)) {
            found = true;
            dbgPrintf("[HOOK] Using current python.exe dir: %s\n", pythonHome);
          } else {
            dbgPrintf("[HOOK] Skipping current python.exe dir because it does "
                      "not match loaded runtime python3%d.dll\n",
                      loadedRuntimeTag);
          }
        }
      }
    }
  }

  // PRIORITY 4: Use existing PYTHONHOME only when it still points to a valid
  // install.
  if (!found) {
    char existing[MAX_PATH] = {0};
    DWORD existingLen =
        GetEnvironmentVariableA("PYTHONHOME", existing, MAX_PATH);
    if (existingLen > 0 && existingLen < MAX_PATH) {
      if (IsValidPythonHome(existing, NULL, 0)) {
        if (PythonHomeMatchesLoadedRuntime(existing, loadedRuntimeTag)) {
          dbgPrintf("[HOOK] PYTHONHOME already set to: %s\n", existing);
          strncpy_s(pythonHome, MAX_PATH, existing, _TRUNCATE);
          pythonHome[MAX_PATH - 1] = '\0';
          found = true;
        } else {
          dbgPrintf("[HOOK] Ignoring PYTHONHOME because it does not match "
                    "loaded runtime python3%d.dll: %s\n",
                    loadedRuntimeTag, existing);
        }
      } else {
        dbgPrintf("[HOOK] Ignoring invalid PYTHONHOME: %s\n", existing);
      }
    } else if (existingLen >= MAX_PATH) {
      dbgPrintf("[HOOK] Ignoring PYTHONHOME because it exceeds MAX_PATH\n");
    }
  }

  // If a version-specific runtime is already loaded and no matching install was
  // found, do NOT fall back to an arbitrary different Python version.
  if (!found && loadedRuntimeTag != 0) {
    dbgPrintf("[HOOK] Loaded runtime python3%d.dll has no matching install. "
              "Skipping cross-version PYTHONHOME fallback.\n",
              loadedRuntimeTag);
  }

  // Generic fallback logic is only safe when there is no version-specific
  // python3X.dll already loaded in this process.
  if (!found && loadedRuntimeTag == 0) {
    // PRIORITY 5: Prefer HydraDragonAntivirus's Python 3.12 install.
    if (FindPreferredPython312Home(pythonHome, MAX_PATH))
      found = true;

    // PRIORITY 6: Find python.exe in other processes.
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

    // PRIORITY 7: Check common installation paths.
    if (!found)
      found = FindPythonInstallation(pythonHome, MAX_PATH);

    // PRIORITY 8: Check PATH environment.
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
    g_pythonHomePath[0] = '\0';
    SetEnvironmentVariableA("PYTHONHOME", NULL);
    SetEnvironmentVariableA("PYTHONPATH", NULL);
    dbgPrintf("[HOOK] Could not auto-detect a SAFE PYTHONHOME; leaving "
              "PYTHONHOME/PYTHONPATH unset\n");
  }
}

static bool SetupStdoutStderrToLog(char *outLogPath) {
  const char *baseDir = "C:\\ProgramData\\HydraDragonAntivirus\\hydradragon";
  const char *logDir =
      "C:\\ProgramData\\HydraDragonAntivirus\\hydradragon\\python_dumps";
  char logPath[MAX_PATH];

  EnsureDirectoryExists(baseDir);
  EnsureDirectoryExists(logDir);

  _snprintf_s(logPath, MAX_PATH, _TRUNCATE, "%s\\hook_dll.log", logDir);
  logPath[MAX_PATH - 1] = '\0';

  if (g_logFile) {
    fclose(g_logFile);
    g_logFile = NULL;
  }

  // Use _fsopen with _SH_DENYNO to prevent file locking, allowing other processes to read/move the log.
  g_logFile = _fsopen(logPath, "a", _SH_DENYNO);
  if (!g_logFile) {
    dbgPrintf("[HOOK] ERROR: _fsopen failed for %s (errno=%d)\n", logPath, errno);
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

// --- Safe SEH wrappers for Python C-API ---
typedef void *(*PyImportModuleFunc)(const char *);
typedef void (*Py_DecRefFunc)(void *);
typedef int (*PyGILState_EnsureFunc)();
typedef void (*PyGILState_ReleaseFunc)(int);
typedef void (*PyErr_PrintFunc)();
typedef int (*PyRun_SimpleStringFunc)(const char *);

static __declspec(noinline) int SafePyGILState_Ensure(
    PyGILState_EnsureFunc func, bool *success) {
  int res = 0;
  *success = false;
  __try {
    res = func();
    *success = true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    *success = false;
  }
  return res;
}

static __declspec(noinline) void SafePyGILState_Release(
    PyGILState_ReleaseFunc func, int state) {
  __try {
    func(state);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
}

static __declspec(noinline) int SafePyRun_SimpleString(
    PyRun_SimpleStringFunc func, const char *str) {
  __try {
    return func(str);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return -1;
  }
}

static __declspec(noinline) void *SafePyImport_ImportModule(
    PyImportModuleFunc func, const char *name) {
  __try {
    return func(name);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return nullptr;
  }
}

static __declspec(noinline) void SafePy_DecRef(Py_DecRefFunc func, void *obj) {
  __try {
    func(obj);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
}

static __declspec(noinline) void SafePyErr_Print(PyErr_PrintFunc func) {
  __try {
    func();
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
}

static void RestorePythonStdStreams(PyRun_SimpleStringFunc func) {
  if (!func)
    return;

  static const char *restoreCmd =
      "import sys, builtins\n"
      "try:\n"
      "    _saved_out = getattr(builtins, '__hydra_saved_stdout__', None)\n"
      "    _saved_err = getattr(builtins, '__hydra_saved_stderr__', None)\n"
      "    _log_file = getattr(builtins, '__hydra_log_stream__', None)\n"
      "    if _saved_out is not None:\n"
      "        sys.stdout = _saved_out\n"
      "    if _saved_err is not None:\n"
      "        sys.stderr = _saved_err\n"
      "    if _log_file is not None:\n"
      "        try:\n"
      "            _log_file.flush()\n"
      "        except Exception:\n"
      "            pass\n"
      "    for _name in ('__hydra_saved_stdout__', '__hydra_saved_stderr__',\n"
      "                  '__hydra_log_stream__'):\n"
      "        if hasattr(builtins, _name):\n"
      "            delattr(builtins, _name)\n"
      "except Exception:\n"
      "    pass\n";

  int restoreRes = SafePyRun_SimpleString(func, restoreCmd);
  dbgPrintf("[HOOK] Restore Python stdio returned: %d\n", restoreRes);
}

static void LogImportedHookModulePath(PyRun_SimpleStringFunc func,
                                    const char *moduleName) {
  if (!func || !moduleName || !moduleName[0])
    return;

  char cmd[1024];
  int written = _snprintf_s(
      cmd, sizeof(cmd), _TRUNCATE,
      "import sys\n"
      "try:\n"
      "    _m = sys.modules.get(r'%s')\n"
      "    print('Imported module __file__:', getattr(_m, '__file__', '<none>'))\n"
      "except Exception as _e:\n"
      "    print('Imported module path logging failed:', type(_e).__name__, str(_e))\n",
      moduleName);
  if (written >= 0)
    SafePyRun_SimpleString(func, cmd);
}

// --- PyMarshal_ReadObjectFromString hook ---
// Intercepts C-level marshal deserialization (used by Nuitka, Cython, etc.)
// and forwards captured byte data to the Python-level _write_marshal_pyc.

// Forward-declare Python C API function pointers (loaded at runtime)
// Py_ssize_t == ptrdiff_t on all platforms Python supports.
typedef void* (*PyMarshal_ReadObjectFromStringFunc)(const char*, ptrdiff_t);
typedef void* (*PyBytes_FromStringAndSizeFunc)(const char*, ptrdiff_t);
typedef void* (*PyObject_CallFunctionObjArgsFunc)(void*, ...);
typedef void* (*PyObject_GetAttrStringFunc)(void*, const char*);

// Globals — loaded in SetupMarshalHook / CacheMarshalWriteFunc
static PyMarshal_ReadObjectFromStringFunc g_original_PyMarshal_ReadObjectFromString = nullptr;
static void* g_marshal_hook_fn = nullptr;
static void* g_marshal_target = nullptr;
static unsigned char g_marshal_original_bytes[16];
static void* g_py_write_marshal_pyc = nullptr;
static char g_marshal_dump_dir[MAX_PATH] = {0};
static unsigned long long g_marshal_seq = 0;
static unsigned char g_marshal_magic[4] = {0};
static int g_marshal_magic_len = 0;

// PyMarshal_ReadObjectFromFile globals
typedef void* (*PyMarshal_ReadObjectFromFileFunc)(void*);
typedef void* (*PyMarshal_WriteObjectToStringFunc)(void*, int);
static PyMarshal_ReadObjectFromFileFunc g_original_PyMarshal_ReadObjectFromFile = nullptr;
static PyMarshal_WriteObjectToStringFunc g_PyMarshal_WriteObjectToString_local = nullptr;
static void* g_marshal_file_hook_fn = nullptr;
static void* g_marshal_file_target = nullptr;
static unsigned char g_marshal_original_file_bytes[16];
static void* g_py_marshal_dumps = nullptr;

// PyEval_EvalCode globals
typedef void* (*PyEvalEvalCodeFunc)(void*, void*, void*);
static PyEvalEvalCodeFunc g_original_PyEval_EvalCode = nullptr;
static void* g_eval_code_hook_fn = nullptr;
static void* g_eval_code_target = nullptr;
static unsigned char g_eval_code_original_bytes[16];

// Cached Python C API function pointers
static PyGILState_EnsureFunc g_PyGILState_Ensure = nullptr;
static PyGILState_ReleaseFunc g_PyGILState_Release = nullptr;
static PyObject_CallFunctionObjArgsFunc g_PyObject_CallFunctionObjArgs = nullptr;
static PyBytes_FromStringAndSizeFunc g_PyBytes_FromStringAndSize = nullptr;
typedef int (*PyBytesAsStringAndSizeFunc)(void*, const char**, ptrdiff_t*);
static PyBytesAsStringAndSizeFunc g_PyBytes_AsStringAndSize = nullptr;
static PyObject_GetAttrStringFunc g_PyObject_GetAttrString = nullptr;
static Py_DecRefFunc g_Py_DecRef = nullptr;
static PyImportModuleFunc g_PyImport_ImportModule = nullptr;
static HMODULE g_hPyDll = nullptr;

// The PyMarshal_ReadObjectFromString prologue in CPython 3.8+ is exactly
// 16 bytes (mov r11,rsp; push rbx; sub rsp,0x60; lea rax,[rcx+rdx];
// mov [r11-0x30],rcx).  Must save/restore a full 16-byte instruction
// boundary — using only 14 bytes splits the last instruction and crashes
// with STATUS_STACK_BUFFER_OVERRUN (BEX64).
#define MARSHAL_PROLOGUE_SIZE 16
// FF 25 [rip+0] + 8-byte addr = 14 bytes (full 64-bit, used in detour)
#define MARSHAL_DETOUR_SIZE 14

// Full Nuitka decrypted blob detection globals
static void*  g_blob_start = nullptr;
static size_t g_blob_size  = 0;
static LONG   g_blob_found = 0;
static LONG   g_blob_attempts = 0;

static bool IsValidMarshalTag(unsigned char tag) {
    switch (tag) {
        case 'i': case 'I': case 'f': case 'g': case 'x': case 'y':
        case 'l': case 's': case 't': case 'r': case '(': case '[':
        case '{': case 'c': case 'u': case '?': case '<': case '>':
        case 'N': case 'F': case 'T': case 'S': case '.': case 'a':
        case 'A': case ')': case 'z': case 'Z':
            return true;
        default:
            return false;
    }
}

// Returns layout type: 0 for invalid, 1 for size_only, 2 for size_count.
static int ChooseSectionLayout(const unsigned char* end, const unsigned char* name_end, unsigned int* out_size, unsigned int* out_data_offset) {
    if (name_end + 5 > end) return 0;

    unsigned int section_size;
    memcpy(&section_size, name_end + 1, 4);

    auto is_valid_next = [&](const unsigned char* next_ptr) -> bool {
        while (next_ptr < end && *next_ptr == 0) {
            next_ptr++;
        }
        if (next_ptr == end) return true;
        if (next_ptr < end) {
            // Structurally check if next_ptr points to a valid null-terminated module name of reasonable length
            const unsigned char* n_end = (const unsigned char*)memchr(next_ptr, 0, (size_t)(end - next_ptr));
            if (n_end && n_end - next_ptr >= 1 && n_end - next_ptr <= 250) {
                return true;
            }
        }
        return false;
    };

    // Pass 1: Strict check with marshal tag signature to accurately resolve layout
    if (name_end + 7 <= end) {
        unsigned short item_count;
        memcpy(&item_count, name_end + 5, 2);
        const unsigned char* data_start = name_end + 7;
        if (section_size > 0 && section_size <= 128 * 1024 * 1024 &&
            data_start + section_size <= end &&
            item_count > 0 && item_count < 65000 && section_size >= item_count) {
            if (IsValidMarshalTag(*data_start) && is_valid_next(data_start + section_size)) {
                *out_size = section_size;
                *out_data_offset = 7;
                return 2; // size_count
            }
        }
    }

    const unsigned char* data_start = name_end + 5;
    if (section_size > 0 && section_size <= 128 * 1024 * 1024 &&
        data_start + section_size <= end) {
        if (IsValidMarshalTag(*data_start) && is_valid_next(data_start + section_size)) {
            *out_size = section_size;
            *out_data_offset = 5;
            return 1; // size_only
        }
    }

    // Pass 2: Fallback to structural check only (in case of new/custom marshal tags)
    if (name_end + 7 <= end) {
        unsigned short item_count;
        memcpy(&item_count, name_end + 5, 2);
        const unsigned char* data_start = name_end + 7;
        if (section_size > 0 && section_size <= 128 * 1024 * 1024 &&
            data_start + section_size <= end &&
            item_count > 0 && item_count < 65000 && section_size >= item_count) {
            if (is_valid_next(data_start + section_size)) {
                *out_size = section_size;
                *out_data_offset = 7;
                return 2; // size_count
            }
        }
    }

    if (section_size > 0 && section_size <= 128 * 1024 * 1024 &&
        data_start + section_size <= end) {
        if (is_valid_next(data_start + section_size)) {
            *out_size = section_size;
            *out_data_offset = 5;
            return 1; // size_only
        }
    }

    return 0;
}

static bool ValidateBlobHeader(const unsigned char* hdr, const unsigned char* data_limit) {
    __try {
        // First 4 bytes: magic/version (anything non-zero)
        uint32_t magic;
        memcpy(&magic, hdr, 4);
        if (magic == 0) return false;

        uint32_t tsz;
        memcpy(&tsz, hdr + 4, 4);
        if (tsz < 64 || tsz > 256 * 1024 * 1024) return false;

        const unsigned char* data_section = hdr + 8;
        const unsigned char* end = data_section + tsz;
        if (end > data_limit) return false;

        // Walk entries — require at least 3 valid ones (lenient: stop on error, don't fail)
        const unsigned char* ptr = data_section;
        int entry_count = 0;

        while (ptr < end && entry_count < 4096) {
            while (ptr < end && *ptr == 0) {
                ptr++;
            }
            if (ptr >= end - 5) break;
            const unsigned char* name_end = (const unsigned char*)memchr(ptr, 0, (size_t)(end - ptr));
            if (!name_end || name_end >= end - 4) break;
            ptrdiff_t name_len = name_end - ptr;
            if (name_len < 1 || name_len > 250) break;

            unsigned int section_size = 0;
            unsigned int data_offset = 0;
            int layout = ChooseSectionLayout(end, name_end, &section_size, &data_offset);
            if (layout == 0) break;

            entry_count++;
            ptr = name_end + data_offset + section_size;
        }

        return (entry_count >= 3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// --- Blob entry storage for module name lookup ---
#define MAX_BLOB_ENTRIES 2048
struct BlobEntry {
    const unsigned char* chunk_start;  // pointer to chunk data in memory
    unsigned int chunk_size;
    char name[256];  // module name
};
static BlobEntry g_blob_entries[MAX_BLOB_ENTRIES];
static int g_blob_entry_count = 0;

// Parse blob entries from the detected blob and store them for name lookup.
static void ParseBlobEntries() {
    if (!g_blob_start) return;
    const unsigned char* data_section = (const unsigned char*)g_blob_start + 8;
    unsigned int total_sz;
    memcpy(&total_sz, (const char*)g_blob_start + 4, 4);
    const unsigned char* end = data_section + total_sz;
    const unsigned char* ptr = data_section;
    g_blob_entry_count = 0;

    while (ptr < end && g_blob_entry_count < MAX_BLOB_ENTRIES) {
        while (ptr < end && *ptr == 0) {
            ptr++;
        }
        if (ptr >= end - 5) break;
        const unsigned char* name_end = (const unsigned char*)
            memchr(ptr, 0, (size_t)(end - ptr));
        if (!name_end || name_end >= end - 4) break;
        ptrdiff_t name_len = name_end - ptr;
        if (name_len < 1 || name_len > 250) break;

        unsigned int section_size = 0;
        unsigned int data_offset = 0;
        int layout = ChooseSectionLayout(end, name_end, &section_size, &data_offset);
        if (layout == 0) break;

        BlobEntry* e = &g_blob_entries[g_blob_entry_count];
        memcpy(e->name, ptr, name_len);
        e->name[name_len] = '\0';

        e->chunk_start = name_end + data_offset;
        e->chunk_size = section_size;

        g_blob_entry_count++;
        ptr = e->chunk_start + section_size;
    }
}

// Look up module name by marshal data pointer.
static const char* LookupModuleName(const unsigned char* data) {
    if (InterlockedCompareExchange(&g_blob_found, 1, 1) != 1) return NULL;
    for (int i = 0; i < g_blob_entry_count; i++) {
        const BlobEntry* e = &g_blob_entries[i];
        if (data >= e->chunk_start &&
            data < e->chunk_start + e->chunk_size) {
            return e->name;
        }
    }
    return NULL;
}


static void DumpNuitkaBlob();

static void DetectNuitkaBlob(const char* data, ptrdiff_t len) {
    if (InterlockedCompareExchange(&g_blob_found, 1, 1) == 1 || !data || len < 1) {
        return;
    }

    if (g_marshal_dump_dir[0] == '\0') return;

    if (InterlockedIncrement(&g_blob_attempts) > 20) {
        InterlockedExchange(&g_blob_found, 1);
        return;
    }

    const unsigned char* udata = (const unsigned char*)data;

    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(udata, &mbi, sizeof(mbi))) return;
        if (mbi.State != MEM_COMMIT) return;

        const unsigned char* region_base = (const unsigned char*)mbi.BaseAddress;
        const unsigned char* region_end = region_base + mbi.RegionSize;

        // Try AllocationBase directly first (most common for VirtualAlloc/large heap)
        const unsigned char* candidate = (const unsigned char*)mbi.AllocationBase;
        if (candidate != nullptr) {
            uint32_t candidate_sz = 0;
            __try {
                memcpy(&candidate_sz, candidate + 4, 4);
                if (candidate_sz >= 1024 && candidate_sz <= 256 * 1024 * 1024) {
                    if (ValidateBlobHeader(candidate, region_end)) {
                        g_blob_start = (void*)candidate;
                        g_blob_size  = (size_t)(region_end - candidate);
                        InterlockedExchange(&g_blob_found, 1);
                        dbgPrintf("[BLOB] Detected Nuitka blob @ 0x%p, size=%zu (via AllocationBase)\n",
                                  g_blob_start, g_blob_size);
                        ParseBlobEntries();
                        DumpNuitkaBlob();
                        return;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // Try BaseAddress (in case it differs)
        candidate = (const unsigned char*)mbi.BaseAddress;
        if (candidate != nullptr) {
            uint32_t candidate_sz = 0;
            __try {
                memcpy(&candidate_sz, candidate + 4, 4);
                if (candidate_sz >= 1024 && candidate_sz <= 256 * 1024 * 1024) {
                    if (ValidateBlobHeader(candidate, region_end)) {
                        g_blob_start = (void*)candidate;
                        g_blob_size  = (size_t)(region_end - candidate);
                        InterlockedExchange(&g_blob_found, 1);
                        dbgPrintf("[BLOB] Detected Nuitka blob @ 0x%p, size=%zu (via BaseAddress)\n",
                                  g_blob_start, g_blob_size);
                        ParseBlobEntries();
                        DumpNuitkaBlob();
                        return;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // Fallback: fast page-aligned scan backwards within same allocation base
        const unsigned char* scan_start = (const unsigned char*)mbi.AllocationBase;
        if (!scan_start) {
            scan_start = (uintptr_t)udata > 256 * 1024 * 1024 ? udata - 256 * 1024 * 1024 : nullptr;
        }
        const unsigned char* scan_end = udata;

        for (const unsigned char* hdr = (const unsigned char*)((uintptr_t)scan_end & ~0xFFF); hdr >= scan_start; hdr -= 4096) {
            uint32_t candidate_sz = 0;
            __try {
                memcpy(&candidate_sz, hdr + 4, 4);
                if (candidate_sz < 1024 || candidate_sz > 256 * 1024 * 1024) continue;

                if (ValidateBlobHeader(hdr, region_end)) {
                    g_blob_start = (void*)hdr;
                    g_blob_size  = (size_t)(region_end - hdr);
                    InterlockedExchange(&g_blob_found, 1);
                    dbgPrintf("[BLOB] Detected Nuitka blob @ 0x%p, size=%zu (via PageScan)\n",
                              g_blob_start, g_blob_size);
                    ParseBlobEntries();
                    DumpNuitkaBlob();
                    return;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dbgPrintf("[BLOB] SEH exception in DetectNuitkaBlob\n");
    }
}

static void DumpNuitkaBlob() {
    if (InterlockedCompareExchange(&g_blob_found, 1, 1) != 1 || !g_blob_start || g_blob_size == 0) return;

    // Derive dump_N from g_marshal_dump_dir which is:
    //   dump_N\RECONSTRUCTED_SOURCE\PYC_DUMPS
    // Walk up two backslash-separated components to reach dump_N, then
    // append \DYNAMIC_BLOB so the blob lands next to RECONSTRUCTED_SOURCE.
    // Fall back to PYTHON_DUMPS_DIR\DYNAMIC_BLOB if the dir isn't set yet.
    char dir[MAX_PATH];
    if (g_marshal_dump_dir[0] != '\0') {
        // Copy and strip the last path component (PYC_DUMPS) to get to RECONSTRUCTED_SOURCE
        char tmp[MAX_PATH];
        strncpy_s(tmp, MAX_PATH, g_marshal_dump_dir, _TRUNCATE);
        char* last_slash = strrchr(tmp, '/');
        char* last_backslash = strrchr(tmp, '\\');
        char* last = (last_slash > last_backslash) ? last_slash : last_backslash;
        if (last) *last = '\0';
        
        _snprintf_s(dir, MAX_PATH, _TRUNCATE, "%s\\DYNAMIC_BLOB", tmp);
    } else {
        // Fallback: marshal dir not yet resolved, use root dumps directory
        _snprintf_s(dir, MAX_PATH, _TRUNCATE, "%s\\RECONSTRUCTED_SOURCE\\DYNAMIC_BLOB", PYTHON_DUMPS_DIR);
    }
    CreateDirectoryA(dir, NULL);

    char path[MAX_PATH];
    _snprintf_s(path, MAX_PATH, _TRUNCATE, "%s\\nuitka_blob.bin", dir);
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        dbgPrintf("[BLOB] ERROR: CreateFileA failed for %s (err=%lu)\n", path, err);
        return;
    }

    DWORD written;
    WriteFile(hFile, g_blob_start, (DWORD)g_blob_size, &written, NULL);
    CloseHandle(hFile);

    dbgPrintf("[BLOB] Dumped Nuitka blob: %s (%zu bytes)\n", path, g_blob_size);
}

// The hook — called instead of PyMarshal_ReadObjectFromString.
// Uses restore-call-rehook: temporarily restore original bytes, call the
// real function directly, then re-install the FF 25 detour.
// No trampoline = no copied-prologue bugs (RIP-relative, boundary splits).
static __declspec(noinline) void* HookPyMarshal_ReadObjectFromString(const char* data, ptrdiff_t len) {
    __try {
        dbgPrintf("[HOOK_MARSHAL] HookPyMarshal_ReadObjectFromString(len=%lld, data[0..4]=0x%02x%02x%02x%02x%02x)\n",
                  len,
                  len>0 ? (unsigned char)data[0] : 0,
                  len>1 ? (unsigned char)data[1] : 0,
                  len>2 ? (unsigned char)data[2] : 0,
                  len>3 ? (unsigned char)data[3] : 0,
                  len>4 ? (unsigned char)data[4] : 0);

        // Skip file I/O during shutdown
        if (g_marshal_dump_dir[0] != '\0' && data != nullptr && len > 16 &&
            InterlockedCompareExchange(&g_unloading, 0, 0) == 0) {
            
            DetectNuitkaBlob(data, len);
            const char* name_from_blob = LookupModuleName((const unsigned char*)data);

            char mod_name[128] = "unknown";
            if (name_from_blob) {
                _snprintf_s(mod_name, _TRUNCATE, "%s", name_from_blob);
            } else {
                // Scan raw data for first null-terminated module name (fallback Nuitka format)
                for (ptrdiff_t i = 5; i < len - 2 && i < 512; i++) {
                    if (data[i] == '\0' && i + 1 < len) {
                        ptrdiff_t name_start = i + 1;
                        ptrdiff_t name_end = name_start;
                        while (name_end < len && name_end - name_start < 120 &&
                               data[name_end] >= 32 && data[name_end] < 127)
                            name_end++;
                        if (name_end - name_start >= 4 &&
                            name_end - name_start < 120 &&
                            memchr(data + name_start, '.', name_end - name_start)) {
                            char tmp[128];
                            ptrdiff_t copy_sz = (name_end - name_start < 120) ? (name_end - name_start) : 119;
                            memcpy(tmp, data + name_start, copy_sz);
                            tmp[copy_sz] = '\0';
                            int valid = 1;
                            if (!((tmp[0] >= 'a' && tmp[0] <= 'z') ||
                                  (tmp[0] >= 'A' && tmp[0] <= 'Z') ||
                                  tmp[0] == '_'))
                                valid = 0;
                            if (valid && (tmp[copy_sz - 1] == '.'))
                                valid = 0;
                            if (valid) {
                                int prev_dot = 0;
                                for (int c = 0; tmp[c] && valid; c++) {
                                    if (tmp[c] == '.') {
                                        if (prev_dot) { valid = 0; break; }
                                        prev_dot = 1;
                                    } else {
                                        prev_dot = 0;
                                        if (!((tmp[c] >= 'a' && tmp[c] <= 'z') ||
                                              (tmp[c] >= 'A' && tmp[c] <= 'Z') ||
                                              (tmp[c] >= '0' && tmp[c] <= '9') ||
                                              tmp[c] == '_'))
                                            { valid = 0; break; }
                                    }
                                }
                            }
                            if (valid) {
                                _snprintf_s(mod_name, _TRUNCATE, "%s", tmp);
                                break;
                            }
                        }
                    }
                }
            }

            char path[MAX_PATH];
            unsigned long long seq = InterlockedIncrement64((volatile LONG64*)&g_marshal_seq);
            _snprintf_s(path, MAX_PATH, _TRUNCATE, "%s\\%s_%llu.bin",
                        g_marshal_dump_dir, mod_name, seq);
            char pyc_path[MAX_PATH];
            _snprintf_s(pyc_path, MAX_PATH, _TRUNCATE, "%s\\%s_%llu.pyc",
                        g_marshal_dump_dir, mod_name, seq);

            HANDLE hRaw = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL, NULL);
            if (hRaw != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hRaw, data, (DWORD)len, &written, NULL);
                CloseHandle(hRaw);
            }
            if (g_marshal_magic_len > 0) {
                HANDLE hPyc = CreateFileA(pyc_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                          FILE_ATTRIBUTE_NORMAL, NULL);
                if (hPyc != INVALID_HANDLE_VALUE) {
                    DWORD written;
                    WriteFile(hPyc, g_marshal_magic, 4, &written, NULL);
                    unsigned char pyc_header[12] = {0};
                    WriteFile(hPyc, pyc_header, 12, &written, NULL);
                    WriteFile(hPyc, data, (DWORD)len, &written, NULL);
                    CloseHandle(hPyc);
                }
            }
            dbgPrintf("[HOOK_MARSHAL] Wrote marshal_%llu (%lld bytes)\n", seq, (long long)len);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dbgPrintf("[HOOK_MARSHAL] SEH exception in HookPyMarshal_ReadObjectFromString\n");
    }

    // Restore-call-rehook: remove detour, call original, re-install
    if (g_marshal_target && g_original_PyMarshal_ReadObjectFromString) {
        DWORD old;
        VirtualProtect(g_marshal_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        memcpy(g_marshal_target, g_marshal_original_bytes, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_marshal_target, MARSHAL_DETOUR_SIZE, old, &old);
        FlushInstructionCache(GetCurrentProcess(), g_marshal_target, MARSHAL_DETOUR_SIZE);

        void* result = g_original_PyMarshal_ReadObjectFromString(data, len);

        // Re-install FF 25 detour
        VirtualProtect(g_marshal_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        uintptr_t hookFn = (uintptr_t)g_marshal_hook_fn;
        InterlockedExchange64((volatile LONG64*)((unsigned char*)g_marshal_target + 6),
                              *(LONG64*)&hookFn);
        MemoryBarrier();
        unsigned char header[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        memcpy(g_marshal_target, header, 6);
        FlushInstructionCache(GetCurrentProcess(), g_marshal_target, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_marshal_target, MARSHAL_DETOUR_SIZE, old, &old);

        return result;
    }

    dbgPrintf("[HOOK_MARSHAL] ERROR: g_original_PyMarshal_ReadObjectFromString is null!\n");
    return nullptr;
}

// Forward declarations for hooks defined later
static __declspec(noinline) void* HookPyMarshal_ReadObjectFromFile(void* fp);
static __declspec(noinline) void* HookPyEval_EvalCode(void* code, void* globals, void* locals);

// Restore-call-rehook architecture:
// 1. Save original prologue bytes and function pointer
// 2. Write FF 25 detour at the target
// 3. On hook fire: restore bytes, call real function directly, re-install
// No trampoline = no copied-prologue bugs (RIP-relative, boundary splits).
static bool SetupMarshalHook(HMODULE hPyDll) {
    // Guard: already installed — never patch twice.
    if (g_marshal_target != nullptr) {
        dbgPrintf("[HOOK] Marshal hook already installed, skipping\n");
        return true;
    }

    // Load Python C API function pointers needed by the hook
    g_PyGILState_Ensure = (PyGILState_EnsureFunc)GetProcAddress(hPyDll, "PyGILState_Ensure");
    g_PyGILState_Release = (PyGILState_ReleaseFunc)GetProcAddress(hPyDll, "PyGILState_Release");
    g_PyBytes_FromStringAndSize = (PyBytes_FromStringAndSizeFunc)GetProcAddress(hPyDll, "PyBytes_FromStringAndSize");
    g_PyBytes_AsStringAndSize = (PyBytesAsStringAndSizeFunc)GetProcAddress(hPyDll, "PyBytes_AsStringAndSize");
    g_PyObject_CallFunctionObjArgs = (PyObject_CallFunctionObjArgsFunc)GetProcAddress(hPyDll, "PyObject_CallFunctionObjArgs");
    g_PyObject_GetAttrString = (PyObject_GetAttrStringFunc)GetProcAddress(hPyDll, "PyObject_GetAttrString");
    g_Py_DecRef = (Py_DecRefFunc)GetProcAddress(hPyDll, "Py_DecRef");
    g_PyImport_ImportModule = (PyImportModuleFunc)GetProcAddress(hPyDll, "PyImport_ImportModule");

    if (!g_PyGILState_Ensure || !g_PyBytes_FromStringAndSize || !g_PyBytes_AsStringAndSize ||
        !g_PyObject_CallFunctionObjArgs || !g_PyObject_GetAttrString ||
        !g_Py_DecRef || !g_PyImport_ImportModule) {
        dbgPrintf("[HOOK] ERROR: Cannot load Python C API functions for marshal hook\n");
        return false;
    }

    void* target = (void*)GetProcAddress(hPyDll, "PyMarshal_ReadObjectFromString");
    if (!target) {
        dbgPrintf("[HOOK] ERROR: PyMarshal_ReadObjectFromString not exported\n");
        return false;
    }
    dbgPrintf("[HOOK] PyMarshal_ReadObjectFromString @ 0x%p\n", target);

    // Save original prologue (full 16-byte instruction boundary)
    DWORD oldProtect;
    if (!VirtualProtect(target, MARSHAL_PROLOGUE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        dbgPrintf("[HOOK] ERROR: VirtualProtect(save) failed\n");
        return false;
    }
    memcpy(g_marshal_original_bytes, target, MARSHAL_PROLOGUE_SIZE);
    {   // Dump prologue via OutputDebugStringA (no fprintf dependency)
        char _pb[256];
        _snprintf_s(_pb, _TRUNCATE,
            "[HOOK] Orig prologue: %02x %02x %02x %02x %02x %02x %02x %02x "
            "%02x %02x %02x %02x %02x %02x %02x %02x\n",
            g_marshal_original_bytes[0],  g_marshal_original_bytes[1],
            g_marshal_original_bytes[2],  g_marshal_original_bytes[3],
            g_marshal_original_bytes[4],  g_marshal_original_bytes[5],
            g_marshal_original_bytes[6],  g_marshal_original_bytes[7],
            g_marshal_original_bytes[8],  g_marshal_original_bytes[9],
            g_marshal_original_bytes[10], g_marshal_original_bytes[11],
            g_marshal_original_bytes[12], g_marshal_original_bytes[13],
            g_marshal_original_bytes[14], g_marshal_original_bytes[15]);
        OutputDebugStringA(_pb);
    }
    VirtualProtect(target, MARSHAL_PROLOGUE_SIZE, oldProtect, &oldProtect);

    // Save direct pointer to original function (we'll restore bytes on each call)
    g_original_PyMarshal_ReadObjectFromString = (PyMarshal_ReadObjectFromStringFunc)target;
    g_marshal_hook_fn = (void*)&HookPyMarshal_ReadObjectFromString;
    g_marshal_target = target;
    g_hPyDll = hPyDll;

    // Write FF 25 [rip+0] + 8-byte absolute address detour at target
    // (14 bytes total). Write address first (atomic 64-bit at offset 6),
    // then the 6-byte header, so any thread seeing FF 25 sees a valid target.
    uintptr_t hookFn = (uintptr_t)&HookPyMarshal_ReadObjectFromString;

    DWORD old2;
    if (!VirtualProtect(target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old2)) {
        dbgPrintf("[HOOK] ERROR: VirtualProtect(detour) failed\n");
        g_marshal_target = nullptr;
        return false;
    }
    InterlockedExchange64((volatile LONG64*)((unsigned char*)target + 6), *(LONG64*)&hookFn);
    MemoryBarrier();
    unsigned char header[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    memcpy(target, header, 6);
    FlushInstructionCache(GetCurrentProcess(), target, MARSHAL_DETOUR_SIZE);
    VirtualProtect(target, MARSHAL_DETOUR_SIZE, old2, &old2);
    dbgPrintf("[HOOK] PyMarshal_ReadObjectFromString detour installed (FF 25)\n");

    // ── PyMarshal_ReadObjectFromFile hook ─────────────────────────────
    g_PyMarshal_WriteObjectToString_local = (PyMarshal_WriteObjectToStringFunc)
        GetProcAddress(hPyDll, "PyMarshal_WriteObjectToString");
    if (!g_PyMarshal_WriteObjectToString_local) {
        dbgPrintf("[HOOK] WARNING: PyMarshal_WriteObjectToString not exported, FromFile hook disabled\n");
    }

    void* target_file = (void*)GetProcAddress(hPyDll, "PyMarshal_ReadObjectFromFile");
    if (!target_file) {
        dbgPrintf("[HOOK] WARNING: PyMarshal_ReadObjectFromFile not exported, skipping\n");
        return true;
    }
    dbgPrintf("[HOOK] PyMarshal_ReadObjectFromFile @ 0x%p\n", target_file);

    // Save original prologue
    DWORD oldProtect2;
    if (!VirtualProtect(target_file, MARSHAL_PROLOGUE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect2)) {
        dbgPrintf("[HOOK] WARNING: VirtualProtect(save) for FromFile failed\n");
        return true;
    }
    memcpy(g_marshal_original_file_bytes, target_file, MARSHAL_PROLOGUE_SIZE);
    VirtualProtect(target_file, MARSHAL_PROLOGUE_SIZE, oldProtect2, &oldProtect2);

    g_original_PyMarshal_ReadObjectFromFile = (PyMarshal_ReadObjectFromFileFunc)target_file;
    g_marshal_file_hook_fn = (void*)&HookPyMarshal_ReadObjectFromFile;
    g_marshal_file_target = target_file;

    uintptr_t hookFnFile = (uintptr_t)&HookPyMarshal_ReadObjectFromFile;
    DWORD old3;
    if (!VirtualProtect(target_file, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old3)) {
        dbgPrintf("[HOOK] WARNING: VirtualProtect(detour) for FromFile failed\n");
        g_marshal_file_target = nullptr;
        return true;
    }
    InterlockedExchange64((volatile LONG64*)((unsigned char*)target_file + 6), *(LONG64*)&hookFnFile);
    MemoryBarrier();
    unsigned char header_file[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    memcpy(target_file, header_file, 6);
    FlushInstructionCache(GetCurrentProcess(), target_file, MARSHAL_DETOUR_SIZE);
    VirtualProtect(target_file, MARSHAL_DETOUR_SIZE, old3, &old3);
    dbgPrintf("[HOOK] PyMarshal_ReadObjectFromFile detour installed (FF 25)\n");

    // ── PyEval_EvalCode hook ─────────────────────────────────────────
    void* target_eval = (void*)GetProcAddress(hPyDll, "PyEval_EvalCode");
    if (!target_eval) {
        target_eval = (void*)GetProcAddress(hPyDll, "PyEval_EvalCodeEx");
    }
    if (target_eval) {
        dbgPrintf("[HOOK] PyEval_EvalCode @ 0x%p\n", target_eval);

        DWORD oldP;
        if (VirtualProtect(target_eval, MARSHAL_PROLOGUE_SIZE, PAGE_EXECUTE_READWRITE, &oldP)) {
            memcpy(g_eval_code_original_bytes, target_eval, MARSHAL_PROLOGUE_SIZE);
            VirtualProtect(target_eval, MARSHAL_PROLOGUE_SIZE, oldP, &oldP);

            g_original_PyEval_EvalCode = (PyEvalEvalCodeFunc)target_eval;
            g_eval_code_hook_fn = (void*)&HookPyEval_EvalCode;
            g_eval_code_target = target_eval;

            uintptr_t hookFnEval = (uintptr_t)&HookPyEval_EvalCode;
            DWORD old2;
            if (VirtualProtect(target_eval, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old2)) {
                InterlockedExchange64((volatile LONG64*)((unsigned char*)target_eval + 6), *(LONG64*)&hookFnEval);
                MemoryBarrier();
                unsigned char hdr[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                memcpy(target_eval, hdr, 6);
                FlushInstructionCache(GetCurrentProcess(), target_eval, MARSHAL_DETOUR_SIZE);
                VirtualProtect(target_eval, MARSHAL_DETOUR_SIZE, old2, &old2);
                dbgPrintf("[HOOK] PyEval_EvalCode detour installed (FF 25)\n");
            } else {
                dbgPrintf("[HOOK] WARNING: VirtualProtect(detour) for PyEval_EvalCode failed\n");
                g_eval_code_target = nullptr;
            }
        } else {
            dbgPrintf("[HOOK] WARNING: VirtualProtect(save) for PyEval_EvalCode failed\n");
        }
    } else {
        dbgPrintf("[HOOK] WARNING: PyEval_EvalCode/PyEval_EvalCodeEx not exported, skipping\n");
    }

    return true;
}

// --- PyMarshal_ReadObjectFromFile hook ---
// Intercepts C-level file-based marshal deserialization.
// Since we can't intercept raw bytes from a FILE*, we call the original,
// re-serialize the result with PyMarshal_WriteObjectToString, and dump as .pyc.
static __declspec(noinline) void* HookPyMarshal_ReadObjectFromFile(void* fp) {
    __try {
        dbgPrintf("[HOOK_MARSHAL_FILE] HookPyMarshal_ReadObjectFromFile(fp=%p)\n", fp);

        if (g_marshal_file_target && g_original_PyMarshal_ReadObjectFromFile && fp &&
            InterlockedCompareExchange(&g_unloading, 0, 0) == 0) {

            // Restore original bytes
            DWORD old;
            VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
            memcpy(g_marshal_file_target, g_marshal_original_file_bytes, MARSHAL_DETOUR_SIZE);
            VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, old, &old);
            FlushInstructionCache(GetCurrentProcess(), g_marshal_file_target, MARSHAL_DETOUR_SIZE);

            void* result = g_original_PyMarshal_ReadObjectFromFile(fp);

            // Re-install FF 25 detour
            VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
            uintptr_t hookFn = (uintptr_t)g_marshal_file_hook_fn;
            InterlockedExchange64((volatile LONG64*)((unsigned char*)g_marshal_file_target + 6),
                                  *(LONG64*)&hookFn);
            MemoryBarrier();
            unsigned char header[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
            memcpy(g_marshal_file_target, header, 6);
            FlushInstructionCache(GetCurrentProcess(), g_marshal_file_target, MARSHAL_DETOUR_SIZE);
            VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, old, &old);

            // Re-serialize the result and dump as .pyc
            if (result && g_marshal_dump_dir[0] != '\0' && g_PyMarshal_WriteObjectToString_local) {
                void* bytes_obj = g_PyMarshal_WriteObjectToString_local(result, 0);
                if (bytes_obj) {
                    const char* buf = NULL;
                    ptrdiff_t buf_len = 0;
                    if (g_PyBytes_AsStringAndSize &&
                        g_PyBytes_AsStringAndSize(bytes_obj, &buf, &buf_len) == 0 && buf && buf_len > 0) {

                        unsigned long long seq = InterlockedIncrement64((volatile LONG64*)&g_marshal_seq);
                        char pyc_path[MAX_PATH];
                        _snprintf_s(pyc_path, MAX_PATH, _TRUNCATE, "%s\\fromfile_%llu.pyc",
                                    g_marshal_dump_dir, seq);
                        HANDLE hPyc = CreateFileA(pyc_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                                  FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hPyc != INVALID_HANDLE_VALUE) {
                            DWORD written;
                            if (g_marshal_magic_len > 0) {
                                WriteFile(hPyc, g_marshal_magic, 4, &written, NULL);
                                unsigned char pyc_header[12] = {0};
                                WriteFile(hPyc, pyc_header, 12, &written, NULL);
                            }
                            WriteFile(hPyc, buf, (DWORD)buf_len, &written, NULL);
                            CloseHandle(hPyc);
                            dbgPrintf("[HOOK_MARSHAL_FILE] Wrote %s (%lld bytes)\n", pyc_path, (long long)buf_len);
                        }
                    }
                    g_Py_DecRef(bytes_obj);
                }
            }

            return result;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dbgPrintf("[HOOK_MARSHAL_FILE] SEH exception in HookPyMarshal_ReadObjectFromFile\n");
    }

    // Fallback: try calling original via pointer
    if (g_original_PyMarshal_ReadObjectFromFile && g_marshal_file_target && fp) {
        DWORD old;
        VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        memcpy(g_marshal_file_target, g_marshal_original_file_bytes, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, old, &old);
        FlushInstructionCache(GetCurrentProcess(), g_marshal_file_target, MARSHAL_DETOUR_SIZE);
        void* result = g_original_PyMarshal_ReadObjectFromFile(fp);
        VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        uintptr_t hookFn = (uintptr_t)g_marshal_file_hook_fn;
        InterlockedExchange64((volatile LONG64*)((unsigned char*)g_marshal_file_target + 6),
                              *(LONG64*)&hookFn);
        MemoryBarrier();
        unsigned char header[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        memcpy(g_marshal_file_target, header, 6);
        FlushInstructionCache(GetCurrentProcess(), g_marshal_file_target, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, old, &old);
        return result;
    }
    return nullptr;
}

// --- PyEval_EvalCode hook ---
// Intercepts C-level code execution (exec(code_obj, globals, locals),
// PyEval_EvalCodeEx, etc.) to capture dynamically executed code objects.
// We call the original first, then dump the code object via Python-level
// marshal.dumps so Python-side decompiler can process it.
static __declspec(noinline) void* HookPyEval_EvalCode(void* code, void* globals, void* locals) {
    __try {
        if (code && g_marshal_dump_dir[0] != '\0' &&
            InterlockedCompareExchange(&g_unloading, 0, 0) == 0) {

            // Call original first, then dump via Python marshal.dumps
            // The dump must happen outside the restore-call-rehook window
            // because it uses Python C API.
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dbgPrintf("[HOOK_EVAL] SEH exception in HookPyEval_EvalCode\n");
    }

    // Restore-call-rehook
    if (g_eval_code_target && g_original_PyEval_EvalCode) {
        DWORD old;
        VirtualProtect(g_eval_code_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        memcpy(g_eval_code_target, g_eval_code_original_bytes, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_eval_code_target, MARSHAL_DETOUR_SIZE, old, &old);
        FlushInstructionCache(GetCurrentProcess(), g_eval_code_target, MARSHAL_DETOUR_SIZE);

        void* result = g_original_PyEval_EvalCode(code, globals, locals);

        // Re-install FF 25 detour
        VirtualProtect(g_eval_code_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        uintptr_t hookFn = (uintptr_t)g_eval_code_hook_fn;
        InterlockedExchange64((volatile LONG64*)((unsigned char*)g_eval_code_target + 6),
                              *(LONG64*)&hookFn);
        MemoryBarrier();
        unsigned char header[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        memcpy(g_eval_code_target, header, 6);
        FlushInstructionCache(GetCurrentProcess(), g_eval_code_target, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_eval_code_target, MARSHAL_DETOUR_SIZE, old, &old);

        // Dump the code object via Python marshal.dumps
        if (code && result && g_PyMarshal_WriteObjectToString_local) {
            int gilState = g_PyGILState_Ensure();
            void* bytes_obj = g_PyMarshal_WriteObjectToString_local(code, 2);
            if (bytes_obj) {
                const char* buf = NULL;
                ptrdiff_t buf_len = 0;
                if (g_PyBytes_AsStringAndSize &&
                    g_PyBytes_AsStringAndSize(bytes_obj, &buf, &buf_len) == 0 && buf && buf_len > 4) {
                    unsigned long long seq = InterlockedIncrement64((volatile LONG64*)&g_marshal_seq);
                    char pyc_path[MAX_PATH];
                    _snprintf_s(pyc_path, MAX_PATH, _TRUNCATE, "%s\\evalcode_%llu.pyc",
                                g_marshal_dump_dir, seq);
                    HANDLE hPyc = CreateFileA(pyc_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                              FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hPyc != INVALID_HANDLE_VALUE) {
                        DWORD written;
                        if (g_marshal_magic_len > 0) {
                            WriteFile(hPyc, g_marshal_magic, 4, &written, NULL);
                            unsigned char pyc_header[12] = {0};
                            WriteFile(hPyc, pyc_header, 12, &written, NULL);
                        }
                        WriteFile(hPyc, buf, (DWORD)buf_len, &written, NULL);
                        CloseHandle(hPyc);
                        dbgPrintf("[HOOK_EVAL] Wrote %s (%lld bytes)\n", pyc_path, (long long)buf_len);
                    }
                }
                g_Py_DecRef(bytes_obj);
            }
            g_PyGILState_Release(gilState);
        }

        return result;
    }

    return nullptr;
}

// Compute marshal dump dir and cache Python magic number.
// First tries sys.__marshal_target_dir__ (set by Python setup code), falls
// back to computing the path via Windows API if PyUnicode_AsUTF8 is missing.
static bool CacheMarshalWriteFunc() {
    if (g_py_write_marshal_pyc != nullptr || g_marshal_dump_dir[0] != '\0') {
        return true;
    }

    // Load PyBytes_AsStringAndSize for reading magic number bytes
    typedef int (*PyBytesAsStringAndSizeFunc)(void*, const char**, ptrdiff_t*);
    auto PyBytes_AsStringAndSize = (PyBytesAsStringAndSizeFunc)GetProcAddress(g_hPyDll, "PyBytes_AsStringAndSize");

    // Load PyUnicode_AsUTF8 for reading Python strings
    typedef const char* (*PyUnicodeAsUTF8Func)(void*);
    auto PyUnicode_AsUTF8 = (PyUnicodeAsUTF8Func)GetProcAddress(g_hPyDll, "PyUnicode_AsUTF8");

    // Try Python's sys.__marshal_target_dir__ first
    bool got_dir = false;
    if (PyUnicode_AsUTF8) {
        void* sys_mod = g_PyImport_ImportModule("sys");
        if (sys_mod) {
            void* target_dir_obj = g_PyObject_GetAttrString(sys_mod, "__marshal_target_dir__");
            if (target_dir_obj) {
                const char* utf8 = PyUnicode_AsUTF8(target_dir_obj);
                if (utf8 && utf8[0] != '\0') {
                    strncpy_s(g_marshal_dump_dir, MAX_PATH, utf8, _TRUNCATE);
                    got_dir = true;
                }
            }
            if (target_dir_obj) g_Py_DecRef(target_dir_obj);
            g_Py_DecRef(sys_mod);
        }
    }

    // Fallback: compute path via Windows API
    if (!got_dir) {
        const char* base = PYTHON_DUMPS_DIR;
        WIN32_FIND_DATAA ffd;
        char search[MAX_PATH];
        _snprintf_s(search, MAX_PATH, _TRUNCATE, "%s\\dump_*", base);
        HANDLE hFind = FindFirstFileA(search, &ffd);
        int max_n = 0;
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    int n = 0;
                    if (sscanf_s(ffd.cFileName, "dump_%d", &n) == 1 && n > max_n)
                        max_n = n;
                }
            } while (FindNextFileA(hFind, &ffd));
            FindClose(hFind);
        }
        _snprintf_s(g_marshal_dump_dir, MAX_PATH, _TRUNCATE,
                    "%s\\dump_%d\\RECONSTRUCTED_SOURCE\\PYC_DUMPS",
                    base, max_n + 1);
        CreateDirectoryA(g_marshal_dump_dir, NULL);
    }
    dbgPrintf("[HOOK] Marshal dump dir: %s\n", g_marshal_dump_dir);

    // Extract magic number: import importlib.util; MAGIC_NUMBER
    void* importlib_util = g_PyImport_ImportModule("importlib.util");
    if (importlib_util) {
        void* magic_obj = g_PyObject_GetAttrString(importlib_util, "MAGIC_NUMBER");
        if (magic_obj && PyBytes_AsStringAndSize) {
            const char* magic_buf = NULL;
            ptrdiff_t magic_sz = 0;
            if (PyBytes_AsStringAndSize(magic_obj, &magic_buf, &magic_sz) == 0 && magic_sz > 0) {
                int copy_sz = magic_sz > 4 ? 4 : (int)magic_sz;
                memcpy(g_marshal_magic, magic_buf, copy_sz);
                g_marshal_magic_len = copy_sz;
            }
        }
        if (magic_obj) g_Py_DecRef(magic_obj);
        g_Py_DecRef(importlib_util);
    }

    // Also cache the Python _write_marshal_pyc for backward compat / Python-level use
    if (!g_PyImport_ImportModule || !g_PyObject_GetAttrString || !g_Py_DecRef) {
        dbgPrintf("[HOOK] WARNING: Python API pointers not loaded for CacheMarshalWriteFunc\n");
        return false;
    }
    void* marshal_mod = g_PyImport_ImportModule("marshal");
    if (marshal_mod) {
        g_py_write_marshal_pyc = g_PyObject_GetAttrString(marshal_mod, "_write_marshal_pyc");
        g_Py_DecRef(marshal_mod);
    }
    dbgPrintf("[HOOK] Cached marshal._write_marshal_pyc OK\n");
    return true;
}

// Restore the original prologue (call on cleanup).
// Safe for DLL_PROCESS_DETACH: uses only kernel32 API (no Python API, no
// C runtime heap operations) because python312.dll and/or the CRT may
// already be unloaded at that point.
static void RemoveMarshalHook() {
    if (g_marshal_target) {
        DWORD old;
        VirtualProtect(g_marshal_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        memcpy(g_marshal_target, g_marshal_original_bytes, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_marshal_target, MARSHAL_DETOUR_SIZE, old, &old);
        g_marshal_target = nullptr;
    }

    if (g_marshal_file_target) {
        DWORD old;
        VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        memcpy(g_marshal_file_target, g_marshal_original_file_bytes, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_marshal_file_target, MARSHAL_DETOUR_SIZE, old, &old);
        g_marshal_file_target = nullptr;
    }

    if (g_eval_code_target) {
        DWORD old;
        VirtualProtect(g_eval_code_target, MARSHAL_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &old);
        memcpy(g_eval_code_target, g_eval_code_original_bytes, MARSHAL_DETOUR_SIZE);
        VirtualProtect(g_eval_code_target, MARSHAL_DETOUR_SIZE, old, &old);
        g_eval_code_target = nullptr;
    }

    // Do NOT call g_Py_DecRef here: during DLL_PROCESS_DETACH the Python
    // DLL may already be unloaded. The reference will be cleaned up by
    // process exit.  Use OutputDebugStringA directly (safe from kernel32)
    // instead of dbgPrintf (which calls fprintf into the C runtime).
    g_py_write_marshal_pyc = nullptr;
    g_py_marshal_dumps = nullptr;
    OutputDebugStringA("[HOOK] PyMarshal_ReadObjectFromString/FromFile/EvalCode hooks removed\n");
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

    hPyDll = nullptr;

    // Try version-specific DLL first because python3.dll (Stable ABI) does NOT export PyRun_SimpleString
    for (int i = 15; i >= 6; i--) {
      _snprintf_s(dllName, sizeof(dllName), _TRUNCATE, "python3%d.dll", i);
      dllName[sizeof(dllName) - 1] = '\0';
      hPyDll = GetModuleHandleA(dllName);
      if (hPyDll) {
        dbgPrintf("[HOOK] Found %s\n", dllName);
        break;
      }
    }

    if (!hPyDll) {
      hPyDll = GetModuleHandleA("python3.dll");
      if (hPyDll) {
        strncpy_s(dllName, sizeof(dllName), "python3.dll", _TRUNCATE);
        dbgPrintf("[HOOK] Found python3.dll (WARNING: PyRun_SimpleString may be missing)\n");
      }
    }

    if (!hPyDll) {
      dbgPrintf("[HOOK] ERROR: No python3x.dll found\n");
      return 1;
    }

    typedef int (*Py_IsInitializedFunc)();

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
    auto Py_IsInitialized =
        (Py_IsInitializedFunc)GetProcAddress(hPyDll, "Py_IsInitialized");

    if (!PyImport_ImportModule || !PyGILState_Ensure || !PyGILState_Release) {
      dbgPrintf("[HOOK] ERROR: Cannot load Python C-API functions\n");
      return 1;
    }

    // CRITICAL: Check if Python interpreter is actually initialized
    // Nuitka OneFile may load python3XX.dll but not have called Py_Initialize
    // yet. Calling PyGILState_Ensure on uninitialized Python causes
    // ACCESS_VIOLATION.
    if (Py_IsInitialized && !Py_IsInitialized()) {
      dbgPrintf("[HOOK] ERROR: Python is NOT initialized in this process. "
                "Cannot acquire GIL. The target may be a Nuitka OneFile "
                "that hasn't started Python yet.\n");
      return 2;
    }

    bool gilSuccess = false;
    int gilState = SafePyGILState_Ensure(PyGILState_Ensure, &gilSuccess);
    if (!gilSuccess) {
      dbgPrintf("[HOOK] SEH EXCEPTION: SafePyGILState_Ensure crashed! "
                "Python runtime is hopelessly corrupted or uninitialized.\n");
      return 2;
    }

    // CRITICAL FIX: Allocate larger buffer for Python setup code
    char *pycmd = (char *)malloc(24576);
    if (!pycmd) {
      dbgPrintf(
          "[HOOK] ERROR: Memory allocation failed for Python setup command\n");
      PyGILState_Release(gilState);
      return 1;
    }

    char hookFilePath[MAX_PATH] = {0};
    char hookDir[MAX_PATH] = {0};
    char pyHookPath[MAX_PATH] = {0};
    char pyHookDir[MAX_PATH] = {0};
    bool haveConfiguredHook = false;

    if (PyRun_SimpleString) {
      char pyLogPath[MAX_PATH];
      strncpy_s(pyLogPath, sizeof(pyLogPath), logPathBuf, _TRUNCATE);
      pyLogPath[sizeof(pyLogPath) - 1] = '\0';

      for (char *p = pyLogPath; *p; ++p) {
        if (*p == '\\')
          *p = '/';
      }

      char pyHomePath[MAX_PATH];
      strncpy_s(pyHomePath, sizeof(pyHomePath), g_pythonHomePath, _TRUNCATE);
      pyHomePath[sizeof(pyHomePath) - 1] = '\0';
      for (char *p = pyHomePath; *p; ++p) {
        if (*p == '\\')
          *p = '/';
      }

      if (GetHookFilePathFromConfig(hookFilePath, MAX_PATH) &&
          hookFilePath[0] != '\0') {
        strncpy_s(hookDir, MAX_PATH, hookFilePath, _TRUNCATE);
        hookDir[MAX_PATH - 1] = '\0';
        PathRemoveFileSpecA(hookDir);
        strncpy_s(pyHookPath, MAX_PATH, hookFilePath, _TRUNCATE);
        pyHookPath[MAX_PATH - 1] = '\0';
        strncpy_s(pyHookDir, MAX_PATH, hookDir, _TRUNCATE);
        pyHookDir[MAX_PATH - 1] = '\0';
        for (char *p = pyHookPath; *p; ++p)
          if (*p == '\\')
            *p = '/';
        for (char *p = pyHookDir; *p; ++p)
          if (*p == '\\')
            *p = '/';
        haveConfiguredHook = true;
        dbgPrintf("[HOOK] Configured hook file: %s\n", hookFilePath);
        dbgPrintf("[HOOK] Configured hook dir: %s\n", hookDir);
      }

      // Get the raw dir of the loaded pythonXY.dll (Nuitka temp extraction
      // dir). This is where the bundled _ctypes.pyd lives when no matching
      // system-wide Python install exists for the loaded DLL version.
      char pyDllDir[MAX_PATH] = {0};
      {
        char rawDllDir[MAX_PATH] = {0};
        if (GetLoadedPythonDllDir(rawDllDir, MAX_PATH)) {
          strncpy_s(pyDllDir, MAX_PATH, rawDllDir, _TRUNCATE);
          pyDllDir[MAX_PATH - 1] = '\0';
          for (char *p = pyDllDir; *p; ++p)
            if (*p == '\\') *p = '/';
        }
      }

      // Safely build Python setup command
      int written = _snprintf_s(
          pycmd, 24576, _TRUNCATE,
          "import sys, os\n"
          "try:\n"
          "    import builtins as _hydra_builtins\n"
          "    _log_path = r'%s'\n"
          "    _hydra_builtins.__hydra_saved_stdout__ = sys.stdout\n"
          "    _hydra_builtins.__hydra_saved_stderr__ = sys.stderr\n"
          "    if _log_path:\n"
          "        try:\n"
          "            f = open(_log_path, 'a', buffering=1, encoding='utf-8')\n"
          "            _hydra_builtins.__hydra_log_stream__ = f\n"
          "            sys.stdout = f\n"
          "            sys.stderr = f\n"
          "            print('Python stdout/stderr temporarily redirected')\n"
          "        except Exception as _le:\n"
          "            print('WARNING: Could not open log file:', _le)\n"
          "    else:\n"
          "        print('WARNING: Log path is empty, skipping file redirect')\n"
          "    print('sys.executable:', sys.executable)\n"
          "    print('sys.prefix:', sys.prefix)\n"
          "    pythonhome = r'%s'\n"
          "    print('Detected PYTHONHOME:', pythonhome)\n"
          "    \n"
          "    # PRIORITY 0: Add the raw loaded pythonXY.dll directory first.\n"
          "    # For Nuitka OneFile builds this is the temp extraction dir and\n"
          "    # contains the bundled _ctypes.pyd / other extension modules.\n"
          "    _dll_dir = r'%s'\n"
          "    if _dll_dir and os.path.isdir(_dll_dir):\n"
          "        if _dll_dir not in sys.path:\n"
          "            sys.path.insert(0, _dll_dir)\n"
          "            print('Added Nuitka DLL dir:', _dll_dir)\n"
          "        if _dll_dir not in os.environ.get('PATH', ''):\n"
          "            os.environ['PATH'] = _dll_dir + os.pathsep + os.environ.get('PATH', '')\n"
          "            print('Added Nuitka DLL dir to PATH')\n"
          "    \n"
          "    # CRITICAL: Add DLLs directory for compiled extensions like "
          "_ctypes\n"
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
          "                os.environ['PATH'] = dlls_dir + os.pathsep + "
          "os.environ.get('PATH', '')\n"
          "                print('Added DLLs to PATH')\n"
          "        \n"
          "        if os.path.isdir(lib_dir) and lib_dir not in sys.path:\n"
          "            sys.path.insert(0, lib_dir)\n"
          "            print('Added Lib directory:', lib_dir)\n"
          "        \n"
          "        if os.path.isdir(site_packages) and site_packages not in "
          "sys.path:\n"
          "            sys.path.insert(0, site_packages)\n"
          "            print('Added site-packages:', site_packages)\n"
          "    \n"
          "    # Force the configured hook directory to win before any plain import.\n"
          "    configured_hook_file = r'%s'\n"
          "    configured_hook_dir = r'%s'\n"
          "    if configured_hook_dir:\n"
          "        try:\n"
          "            if '__hook__' in sys.modules:\n"
          "                del sys.modules['__hook__']\n"
          "                print('Removed stale __hook__ from sys.modules')\n"
          "        except Exception as _se:\n"
          "            print('Could not clear stale __hook__:', type(_se).__name__, str(_se))\n"
          "        if os.path.isdir(configured_hook_dir):\n"
          "            while configured_hook_dir in sys.path:\n"
          "                sys.path.remove(configured_hook_dir)\n"
          "            sys.path.insert(0, configured_hook_dir)\n"
          "            os.environ['HYDRA_HOOK_PATH'] = configured_hook_dir\n"
          "            print('Pinned configured hook dir:', configured_hook_dir)\n"
          "            print('Configured hook file exists:', os.path.exists(configured_hook_file))\n"
          "        else:\n"
          "            print('WARNING: Configured hook dir is missing:', configured_hook_dir)\n"
          "    else:\n"
          "        print('WARNING: No configured hook path available before import')\n"
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
          "    if env_hook and os.path.exists(env_hook) and env_hook not in "
          "sys.path:\n"
          "        sys.path.insert(0, env_hook)\n"
          "        print('Added env hook path:', env_hook)\n"
          "    \n"
           "    print('Final sys.path:', sys.path[:5], '...')\n"
           "    _marshal_base = r'" PYTHON_DUMPS_DIR "'\n"
           "    try:\n"
           "        import os as _mo\n"
           "        _mo.makedirs(_marshal_base, exist_ok=True)\n"
           "        _max_n = 0\n"
           "        for _d in _mo.listdir(_marshal_base):\n"
           "            if _d.startswith('dump_'):\n"
           "                try:\n"
           "                    _n = int(_d.split('_', 1)[1])\n"
           "                    if _n > _max_n: _max_n = _n\n"
           "                except: pass\n"
           "        _target = _mo.path.join(_marshal_base, f'dump_{_max_n + 1}', 'RECONSTRUCTED_SOURCE', 'PYC_DUMPS')\n"
            "        _mo.makedirs(_target, exist_ok=True)\n"
            "        sys.__marshal_target_dir__ = _target.replace('\\\\', '/')\n"
            "        print('Marshal target dir:', sys.__marshal_target_dir__)\n"
           "    except Exception as _me:\n"
           "        print('Marshal target dir setup failed:', _me)\n"
           "except Exception as e:\n"
          "    print('Setup error:', type(e).__name__, str(e))\n"
          "    import sys as _sys\n"
          "    _ei = _sys.exc_info()\n"
          "    print('  Type :', _ei[0].__name__ if _ei[0] else '?')\n"
          "    print('  Value:', str(_ei[1]))\n"
          "    try:\n"
          "        import traceback as _tb; _tb.print_exc()\n"
          "    except Exception: pass\n",
          pyLogPath, pyHomePath, pyDllDir, pyHookPath, pyHookDir);

      if (written < 0) {
        dbgPrintf("[HOOK] WARNING: Python setup command truncated!\n");
      }

      int res = SafePyRun_SimpleString(PyRun_SimpleString, pycmd);
      dbgPrintf("[HOOK] Setup returned: %d\n", res);

      if (res != 0 && PyErr_Print) {
        SafePyErr_Print(PyErr_Print);
      }
    }

    free(pycmd);

    // Try importing hook module
    void *hook_module =
        SafePyImport_ImportModule(PyImport_ImportModule, PYMODULE_NAME);

    if (hook_module) {
      LogImportedHookModulePath(PyRun_SimpleString, PYMODULE_NAME);
      SafePy_DecRef(Py_DecRef, hook_module);

      // Install C-level detour (loads API function pointers), then cache
      // the Python _write_marshal_pyc for the hook callback.
      SetupMarshalHook(hPyDll);
      CacheMarshalWriteFunc();

      RestorePythonStdStreams(PyRun_SimpleString);
      SafePyGILState_Release(PyGILState_Release, gilState);
      dbgPrintf("[HOOK] Successfully imported %s\n", PYMODULE_NAME);
      return 0;
    }

    // Fallback: explicit file execution
    dbgPrintf("[HOOK] Standard import failed, trying explicit execution\n");

    if ((hookFilePath[0] != '\0') || GetHookFilePathFromConfig(hookFilePath, MAX_PATH)) {
      // Guard: path must be non-empty before passing into Python
      if (hookFilePath[0] == '\0') {
        dbgPrintf("[HOOK] ERROR: HookPath resolved to empty string. "
                  "Check hook_config.ini has a valid HookPath= entry.\n");
        RestorePythonStdStreams(PyRun_SimpleString);
        SafePyGILState_Release(PyGILState_Release, gilState);
        return 1;
      }
      dbgPrintf("[HOOK] Explicit hook path: %s\n", hookFilePath);

      // Extract directory from hook file path and add to sys.path
      strncpy_s(hookDir, MAX_PATH, hookFilePath, _TRUNCATE);
      hookDir[MAX_PATH - 1] = '\0';
      PathRemoveFileSpecA(hookDir); // Get directory only

      // Convert backslashes for Python
      strncpy_s(pyHookPath, MAX_PATH, hookFilePath, _TRUNCATE);
      pyHookPath[MAX_PATH - 1] = '\0';
      for (char *p = pyHookPath; *p; ++p)
        if (*p == '\\')
          *p = '/';

      strncpy_s(pyHookDir, MAX_PATH, hookDir, _TRUNCATE);
      pyHookDir[MAX_PATH - 1] = '\0';
      for (char *p = pyHookDir; *p; ++p)
        if (*p == '\\')
          *p = '/';

      // CRITICAL FIX: Add hook directory to sys.path BEFORE importing
      char *addPathCmd = (char *)malloc(8192);
      if (addPathCmd) {
        _snprintf_s(
            addPathCmd, 8192, _TRUNCATE,
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
            "    import sys as _sys\n"
            "    _ei = _sys.exc_info()\n"
            "    print('  Type :', _ei[0].__name__ if _ei[0] else '?')\n"
            "    print('  Value:', str(_ei[1]))\n"
            "    try:\n"
            "        import traceback as _tb; _tb.print_exc()\n"
            "    except Exception: pass\n",
            pyHookDir);

        int pathRes = SafePyRun_SimpleString(PyRun_SimpleString, addPathCmd);
        dbgPrintf("[HOOK] Added hook dir to sys.path, result: %d\n", pathRes);
        free(addPathCmd);

        // Now try importing again
        if (pathRes == 0) {
          void *hook_module_retry =
              SafePyImport_ImportModule(PyImport_ImportModule, PYMODULE_NAME);
          if (hook_module_retry) {
            LogImportedHookModulePath(PyRun_SimpleString, PYMODULE_NAME);
            SafePy_DecRef(Py_DecRef, hook_module_retry);
            SetupMarshalHook(hPyDll);
            CacheMarshalWriteFunc();
            RestorePythonStdStreams(PyRun_SimpleString);
            SafePyGILState_Release(PyGILState_Release, gilState);
            dbgPrintf("[HOOK] Successfully imported %s after adding path\n",
                      PYMODULE_NAME);
            return 0;
          } else {
            dbgPrintf("[HOOK] Import still failed. This is EXPECTED for Nuitka "
                      "One-File programs.\n");
            dbgPrintf("[HOOK] Nuitka disables dynamic imports. You will see an "
                      "error below, but do not worry.\n");
            if (PyErr_Print)
              SafePyErr_Print(PyErr_Print);
          }
        } else {
          dbgPrintf("[HOOK] Path addition returned error code. This is normal "
                    "for Nuitka. Checking Python error...\n");
          if (PyErr_Print)
            SafePyErr_Print(PyErr_Print);
        }
      }

      // If import still fails, try direct execution with proper globals
      char *execCmd = (char *)malloc(16384);
      if (execCmd) {
        int written = _snprintf_s(
            execCmd, 16384, _TRUNCATE,
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
            "        try:\n"
            "            import traceback as _tb; _tb.print_exc()\n"
            "        except Exception: pass\n"
            "        raise\n"
            "    except Exception as e:\n"
            "        print('\\n=== HOOK EXECUTION ERROR ===')\n"
            "        print('Error type:', type(e).__name__)\n"
            "        print('Error message:', str(e))\n"
            "        try:\n"
            "            import traceback as _tb; _tb.print_exc()\n"
            "        except Exception: pass\n"
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
          int execRes = SafePyRun_SimpleString(PyRun_SimpleString, execCmd);
          dbgPrintf("[HOOK] Direct execution returned: %d\n", execRes);

          if (execRes == 0) {
            free(execCmd);
            SetupMarshalHook(hPyDll);
            CacheMarshalWriteFunc();
            RestorePythonStdStreams(PyRun_SimpleString);
            SafePyGILState_Release(PyGILState_Release, gilState);
            dbgPrintf("[HOOK] Hook executed successfully via direct exec\n");
            return 0;
          } else {
            dbgPrintf("[HOOK] Direct execution failed with code: %d\n",
                      execRes);
            if (PyErr_Print)
              PyErr_Print();
          }
        } else {
          dbgPrintf("[HOOK] ERROR: execCmd buffer too small (written=%d)\n",
                    written);
        }
        free(execCmd);
      }
    } else {
      dbgPrintf("[HOOK] No hook path found in config\n");
    }

    if (PyErr_Print)
      PyErr_Print();
    RestorePythonStdStreams(PyRun_SimpleString);
    SafePyGILState_Release(PyGILState_Release, gilState);

    dbgPrintf("[HOOK] Failed to import %s\n", PYMODULE_NAME);
    return 1;
  } catch (const std::bad_alloc &) {
    dbgPrintf("[HOOK] ERROR: C++ exception: bad_alloc during hook startup\n");
  } catch (const std::exception &ex) {
    dbgPrintf("[HOOK] ERROR: C++ exception during hook startup: %s\n",
              ex.what());
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

  // Reset blob detection for this injection session.
  // Without this, g_blob_found stays 1 from a previous DLL load and
  // DetectNuitkaBlob immediately returns "skipped, already found".
  InterlockedExchange(&g_blob_found, 0);
  InterlockedExchange(&g_blob_attempts, 0);
  g_blob_start = nullptr;
  g_blob_size  = 0;
  g_blob_entry_count = 0;
  g_marshal_dump_dir[0] = '\0';

  unsigned threadId = 0;
  uintptr_t workerHandle =
      _beginthreadex(nullptr, 0, hookImpl, nullptr, 0, &threadId);
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
    RemoveMarshalHook();
  }
  return TRUE;
}
