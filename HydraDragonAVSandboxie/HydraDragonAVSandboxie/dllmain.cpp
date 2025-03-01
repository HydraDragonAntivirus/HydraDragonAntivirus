// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <detours/detours.h>
#include <shellapi.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <shlwapi.h>
#include <process.h>
#include <stdlib.h>
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "detours.lib")

// -----------------------------------------------------------------
// Global Paths and Variables
// -----------------------------------------------------------------
const WCHAR LOG_FOLDER[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs";
const WCHAR SIGMA_LOG_FILE[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\DONTREMOVEsigma_log.txt";
const WCHAR ERROR_LOG_FILE[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\DONTREMOVEerror_log.txt";
const WCHAR DETECT_JSON_FILE[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\DONTREMOVEdetectiteasy.json";
const WCHAR KNOWN_EXTENSIONS_FILE[] = L"C:\\Program Files\\HydraDragonAntivirus\\knownextensions\\extensions.txt";

// -----------------------------------------------------------------
// Thread-local flag to prevent recursive logging.
// -----------------------------------------------------------------
__declspec(thread) bool g_bInLogging = false;

// -----------------------------------------------------------------
// Asynchronous Logging for Regular Logs
// -----------------------------------------------------------------
CRITICAL_SECTION g_logLock;
std::vector<std::wstring> g_logQueue;
HANDLE g_hLogThread = NULL;
volatile bool g_bLogThreadRunning = true;

void EnsureLogDirectory()
{
    CreateDirectory(LOG_FOLDER, NULL);
}

DWORD WINAPI LoggerThreadProc(LPVOID lpParameter)
{
    while (g_bLogThreadRunning)
    {
        std::vector<std::wstring> localQueue;
        EnterCriticalSection(&g_logLock);
        if (!g_logQueue.empty())
            localQueue.swap(g_logQueue);
        LeaveCriticalSection(&g_logLock);
        if (!localQueue.empty())
        {
            EnsureLogDirectory();
            FILE* f = nullptr;
            if (_wfopen_s(&f, SIGMA_LOG_FILE, L"a+") == 0 && f)
            {
                for (const auto& msg : localQueue)
                    fwprintf(f, L"%s\n", msg.c_str());
                fclose(f);
            }
        }
        Sleep(100);
    }
    return 0;
}

void QueueLogMessage(const std::wstring& message)
{
    EnterCriticalSection(&g_logLock);
    g_logQueue.push_back(message);
    LeaveCriticalSection(&g_logLock);
}

void WriteSigmaLog(const WCHAR* eventType, const WCHAR* details)
{
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    WCHAR timeBuffer[64];
    wcsftime(timeBuffer, 64, L"%Y-%m-%dT%H:%M:%SZ", &tm_now);
    WCHAR logEntry[2048];
    _snwprintf_s(logEntry, 2048, _TRUNCATE,
        L"{\"timestamp\":\"%s\", \"event\":\"%s\", \"details\":\"%s\"}",
        timeBuffer, eventType, details);
    QueueLogMessage(logEntry);
}

// Safe logging wrapper to prevent recursion.
void SafeWriteSigmaLog(const WCHAR* eventType, const WCHAR* details)
{
    if (g_bInLogging)
        return;
    g_bInLogging = true;
    WriteSigmaLog(eventType, details);
    g_bInLogging = false;
}

// -----------------------------------------------------------------
// Asynchronous Logging for Error Logs
// -----------------------------------------------------------------
CRITICAL_SECTION g_errorLogLock;
std::vector<std::wstring> g_errorLogQueue;
HANDLE g_hErrorLogThread = NULL;
volatile bool g_bErrorLogThreadRunning = true;

DWORD WINAPI ErrorLoggerThreadProc(LPVOID lpParameter)
{
    while (g_bErrorLogThreadRunning)
    {
        std::vector<std::wstring> localQueue;
        EnterCriticalSection(&g_errorLogLock);
        if (!g_errorLogQueue.empty())
            localQueue.swap(g_errorLogQueue);
        LeaveCriticalSection(&g_errorLogLock);
        if (!localQueue.empty())
        {
            EnsureLogDirectory();
            FILE* f = nullptr;
            if (_wfopen_s(&f, ERROR_LOG_FILE, L"a+") == 0 && f)
            {
                for (const auto& msg : localQueue)
                    fwprintf(f, L"%s\n", msg.c_str());
                fclose(f);
            }
        }
        Sleep(100);
    }
    return 0;
}

void QueueErrorLogMessage(const std::wstring& message)
{
    EnterCriticalSection(&g_errorLogLock);
    g_errorLogQueue.push_back(message);
    LeaveCriticalSection(&g_errorLogLock);
}

void WriteErrorLog(const WCHAR* eventType, const WCHAR* details)
{
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    WCHAR timeBuffer[64];
    wcsftime(timeBuffer, 64, L"%Y-%m-%dT%H:%M:%SZ", &tm_now);
    WCHAR logEntry[2048];
    _snwprintf_s(logEntry, 2048, _TRUNCATE,
        L"{\"timestamp\":\"%s\", \"event\":\"%s\", \"details\":\"%s\"}",
        timeBuffer, eventType, details);
    QueueErrorLogMessage(logEntry);
}

// -----------------------------------------------------------------
// NormalizePath and IsOurLogFile Helper Functions
// -----------------------------------------------------------------
bool NormalizePath(std::wstring& path)
{
    const std::wstring prefix = L"\\\\?\\";
    if (path.compare(0, prefix.length(), prefix) == 0)
    {
        path = path.substr(prefix.length());
        return true;
    }
    return false;
}

bool IsOurLogFile(LPCWSTR filePath)
{
    if (!filePath)
        return false;
    std::wstring path(filePath);
    NormalizePath(path);
    std::transform(path.begin(), path.end(), path.begin(), towlower);
    // Check against our log file names.
    if (path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremovesigma_log.txt") != std::wstring::npos ||
        path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremoveerror_log.txt") != std::wstring::npos ||
        path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremovedetectiteasy.json") != std::wstring::npos)
    {
        return true;
    }
    return false;
}

// -----------------------------------------------------------------
// Load Known Extensions from File
// -----------------------------------------------------------------
std::vector<std::wstring> g_knownExtensions;

void LoadKnownExtensions()
{
    g_knownExtensions.clear();
    FILE* f = nullptr;
    if (_wfopen_s(&f, KNOWN_EXTENSIONS_FILE, L"r") == 0 && f)
    {
        wchar_t line[256];
        while (fgetws(line, 256, f))
        {
            size_t len = wcslen(line);
            while (len > 0 && (line[len - 1] == L'\n' || line[len - 1] == L'\r'))
            {
                line[len - 1] = L'\0';
                len--;
            }
            if (len > 0)
                g_knownExtensions.push_back(line);
        }
        fclose(f);
        SafeWriteSigmaLog(L"LoadKnownExtensions", L"Known extensions loaded successfully.");
    }
    else
    {
        WriteErrorLog(L"LoadKnownExtensions", L"Failed to open known extensions file.");
    }
}

// -----------------------------------------------------------------
// Notification Infrastructure via Shell_NotifyIcon
// -----------------------------------------------------------------
HWND g_hNotificationWnd = NULL;

HWND CreateNotificationWindow()
{
    const wchar_t* className = L"HydraDragonNotificationWindowClass";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = DefWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);
    HWND hWnd = CreateWindow(className, L"", WS_OVERLAPPED, CW_USEDEFAULT, CW_USEDEFAULT, 100, 100, NULL, NULL, wc.hInstance, NULL);
    return hWnd;
}

void ShowNotification_Internal(const WCHAR* title, const WCHAR* msg)
{
    if (!g_hNotificationWnd)
        return;

    NOTIFYICONDATA nid = { 0 };
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hNotificationWnd;
    nid.uID = 1001;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_USER + 1;
    nid.hIcon = LoadIcon(NULL, IDI_WARNING);
    wcscpy_s(nid.szTip, title);
    Shell_NotifyIcon(NIM_ADD, &nid);

    nid.uFlags = NIF_INFO;
    wcscpy_s(nid.szInfo, msg);
    wcscpy_s(nid.szInfoTitle, title);
    nid.dwInfoFlags = NIIF_WARNING;
    Shell_NotifyIcon(NIM_MODIFY, &nid);

    Sleep(3000);
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

DWORD WINAPI NotificationThreadProc(LPVOID param)
{
    auto* pData = (std::pair<std::wstring, std::wstring>*)param;
    ShowNotification_Internal(pData->first.c_str(), pData->second.c_str());
    delete pData;
    return 0;
}

void TriggerNotification(const WCHAR* title, const WCHAR* msg)
{
    auto* pData = new std::pair<std::wstring, std::wstring>(title, msg);
    HANDLE hThread = CreateThread(NULL, 0, NotificationThreadProc, pData, 0, NULL);
    if (hThread)
        CloseHandle(hThread);
}

// -----------------------------------------------------------------
// Ransomware Heuristic Functions
// -----------------------------------------------------------------
bool RunDetectItEasy(LPCWSTR filePath)
{
    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &saAttr, 0))
    {
        WriteErrorLog(L"RunDetectItEasy", L"Failed to create pipe.");
        return false;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    std::wstring command = L"\"C:\\Program Files\\HydraDragonAntivirus\\detectiteasy\\diec.exe\" \"";
    command += filePath;
    command += L"\"";

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcess(NULL, &command[0], NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        WriteErrorLog(L"RunDetectItEasy", L"Failed to create process for diec.exe.");
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return false;
    }
    CloseHandle(hWrite);

    char buffer[4096];
    DWORD bytesRead = 0;
    std::string output;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Save Detect It Easy results to JSON file.
    EnsureLogDirectory();
    FILE* f = nullptr;
    if (_wfopen_s(&f, DETECT_JSON_FILE, L"a+") == 0 && f)
    {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, NULL, 0);
        std::wstring wdieOutput(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, output.c_str(), -1, &wdieOutput[0], size_needed);
        if (!wdieOutput.empty() && wdieOutput.back() == L'\0')
            wdieOutput.pop_back();
        fwprintf(f, L"{\"file\":\"%s\", \"die_output\":\"%s\"}\n", filePath, wdieOutput.c_str());
        fclose(f);
    }

    if (output.find("Binary") != std::string::npos &&
        output.find("Unknown: Unknown") != std::string::npos)
        return true;
    return false;
}

bool IsRansomware(LPCWSTR filePath)
{
    if (!filePath)
        return false;
    std::wstring fullPath(filePath);
    std::wstring filename = PathFindFileNameW(fullPath.c_str());
    std::vector<std::wstring> parts;
    size_t start = 0;
    size_t pos = filename.find(L'.');
    while (pos != std::wstring::npos)
    {
        parts.push_back(filename.substr(start, pos - start));
        start = pos;
        pos = filename.find(L'.', start + 1);
    }
    if (start < filename.size())
        parts.push_back(filename.substr(start));
    if (parts.size() < 3)
        return false;

    std::wstring previousExt = parts[parts.size() - 2];
    if (previousExt[0] != L'.')
        previousExt = L"." + previousExt;
    if (std::find(g_knownExtensions.begin(), g_knownExtensions.end(), previousExt) == g_knownExtensions.end())
        return false;

    std::wstring finalExt = parts.back();
    if (finalExt[0] != L'.')
        finalExt = L"." + finalExt;
    if (std::find(g_knownExtensions.begin(), g_knownExtensions.end(), finalExt) != g_knownExtensions.end())
        return false;

    return RunDetectItEasy(filePath);
}

// -----------------------------------------------------------------
// Windows API Hooking (Registry & File System)
// -----------------------------------------------------------------
typedef LSTATUS(WINAPI* RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
static RegSetValueExW_t TrueRegSetValueExW = RegSetValueExW;

LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType,
    const BYTE* lpData, DWORD cbData)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegSetValueExW called: ValueName = %s, Type = %u, DataSize = %u",
        lpValueName ? lpValueName : L"(null)", dwType, cbData);
    SafeWriteSigmaLog(L"RegSetValueExW", buffer);
    return TrueRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

typedef LSTATUS(WINAPI* RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
    const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static RegCreateKeyExW_t TrueRegCreateKeyExW = RegCreateKeyExW;

LSTATUS WINAPI HookedRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult, LPDWORD lpdwDisposition)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegCreateKeyExW called: SubKey = %s",
        lpSubKey ? lpSubKey : L"(null)");
    SafeWriteSigmaLog(L"RegCreateKeyExW", buffer);
    return TrueRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
        lpSecurityAttributes, phkResult, lpdwDisposition);
}

typedef BOOL(WINAPI* DeleteFileW_t)(LPCWSTR);
static DeleteFileW_t TrueDeleteFileW = DeleteFileW;

BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName)
{
    if (lpFileName)
    {
        std::wstring file(lpFileName);
        std::wstring basename = file;
        size_t pos = file.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            basename = file.substr(pos + 1);

        if (_wcsicmp(basename.c_str(), L"log.txt") == 0)
        {
            SafeWriteSigmaLog(L"DeleteFileW", L"HEUR:Win32.Generic.Trojan.Wiper.Log - log.txt deletion detected");
            TriggerNotification(L"Alert", L"Warning: log.txt was deleted (Wiper behavior detected)");
        }
        else if (IsRansomware(lpFileName))
        {
            SafeWriteSigmaLog(L"DeleteFileW", L"HEUR:Win32.Generic.Ransom.Log - suspicious file deletion detected");
            TriggerNotification(L"Alert", L"Warning: Suspicious file deletion (potential ransomware)");
        }
        else
        {
            WCHAR buffer[1024];
            _snwprintf_s(buffer, 1024, _TRUNCATE,
                L"DeleteFileW called: FileName = %s", lpFileName);
            SafeWriteSigmaLog(L"DeleteFileW", buffer);
        }
    }
    else
    {
        SafeWriteSigmaLog(L"DeleteFileW", L"DeleteFileW called: FileName = (null)");
    }
    return TrueDeleteFileW(lpFileName);
}

typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileW_t TrueCreateFileW = CreateFileW;

HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    if (!IsOurLogFile(lpFileName))
    {
        WCHAR buffer[1024];
        _snwprintf_s(buffer, 1024, _TRUNCATE,
            L"CreateFileW called: FileName = %s, Access = 0x%X, Disposition = %u",
            lpFileName ? lpFileName : L"(null)", dwDesiredAccess, dwCreationDisposition);
        SafeWriteSigmaLog(L"CreateFileW", buffer);
    }
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static WriteFile_t TrueWriteFile = WriteFile;

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    WCHAR filePath[512] = L"(unknown)";
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD ret = GetFinalPathNameByHandleW(hFile, filePath, 512, FILE_NAME_NORMALIZED);
        if (ret == 0)
            wcscpy_s(filePath, 512, L"(unknown)");
    }
    if (!IsOurLogFile(filePath))
    {
        WCHAR buffer[1024];
        _snwprintf_s(buffer, 1024, _TRUNCATE,
            L"WriteFile called: File = %s, BytesToWrite = %u", filePath, nNumberOfBytesToWrite);
        SafeWriteSigmaLog(L"WriteFile", buffer);
    }
    return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

typedef BOOL(WINAPI* MoveFileW_t)(LPCWSTR, LPCWSTR);
static MoveFileW_t TrueMoveFileW = MoveFileW;

BOOL WINAPI HookedMoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"MoveFileW called: From = %s To = %s",
        lpExistingFileName ? lpExistingFileName : L"(null)",
        lpNewFileName ? lpNewFileName : L"(null)");
    SafeWriteSigmaLog(L"MoveFileW", buffer);
    return TrueMoveFileW(lpExistingFileName, lpNewFileName);
}

// -----------------------------------------------------------------
// Sandboxie SBIE API Hooking
// -----------------------------------------------------------------
typedef void* (__stdcall* P_SbieDll_Hook)(const char*, void*, void*);
typedef LONG(WINAPI* P_SbieDll_UpdateConf)(WCHAR, const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*);
static P_SbieDll_UpdateConf TrueSbieDll_UpdateConf = NULL;

LONG WINAPI HookedSbieDll_UpdateConf(WCHAR operation_code, const WCHAR* password,
    const WCHAR* section_name, const WCHAR* setting_name, const WCHAR* value)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"SbieDll_UpdateConf called: op=%c, section=%s, setting=%s, value=%s",
        operation_code, section_name ? section_name : L"(null)",
        setting_name ? setting_name : L"(null)",
        value ? value : L"(null)");
    SafeWriteSigmaLog(L"SbieDll_UpdateConf", buffer);
    return TrueSbieDll_UpdateConf(operation_code, password, section_name, setting_name, value);
}

typedef BOOLEAN(__stdcall* P_SbieDll_RegisterDllCallback)(void(__stdcall*)(const WCHAR*, HMODULE));
void __stdcall MyDllCallback(const WCHAR* ImageName, HMODULE ImageBase)
{
    WCHAR details[512];
    _snwprintf_s(details, 512, _TRUNCATE,
        L"ImageName: %s, ModuleBase: 0x%p", ImageName, ImageBase);
    SafeWriteSigmaLog(L"DLL_Event", details);
}

static HMODULE g_hSbieDll = NULL;
extern "C" __declspec(dllexport) void __stdcall InjectDllMain(HINSTANCE hSbieDll, ULONG_PTR UnusedParameter)
{
    g_hSbieDll = hSbieDll;
    WCHAR buffer[256];
    _snwprintf_s(buffer, 256, _TRUNCATE, L"InjectDllMain called. SbieDll handle: 0x%p", hSbieDll);
    SafeWriteSigmaLog(L"InjectDllMain", buffer);

    // Load known extensions from file.
    LoadKnownExtensions();

    P_SbieDll_RegisterDllCallback p_RegisterDllCallback =
        (P_SbieDll_RegisterDllCallback)GetProcAddress(hSbieDll, "SbieDll_RegisterDllCallback");
    if (p_RegisterDllCallback)
    {
        BOOLEAN result = p_RegisterDllCallback(MyDllCallback);
        if (result)
            SafeWriteSigmaLog(L"RegisterDllCallback", L"Callback registered successfully.");
        else
            SafeWriteSigmaLog(L"RegisterDllCallback", L"Callback registration failed.");
    }
    else
    {
        SafeWriteSigmaLog(L"RegisterDllCallback", L"Failed to retrieve SbieDll_RegisterDllCallback address.");
    }

    P_SbieDll_Hook p_SbieDll_Hook = (P_SbieDll_Hook)GetProcAddress(hSbieDll, "SbieDll_Hook");
    if (p_SbieDll_Hook)
    {
        TrueSbieDll_UpdateConf = (P_SbieDll_UpdateConf)
            p_SbieDll_Hook("SbieDll_UpdateConf", GetProcAddress(hSbieDll, "SbieDll_UpdateConf"), HookedSbieDll_UpdateConf);
        if (TrueSbieDll_UpdateConf)
            SafeWriteSigmaLog(L"SbieDll_UpdateConf", L"Hooked successfully.");
        else
            SafeWriteSigmaLog(L"SbieDll_UpdateConf", L"Failed to hook.");
    }
    else
    {
        SafeWriteSigmaLog(L"SbieDll_Hook", L"Failed to retrieve SbieDll_Hook address.");
    }

    // Create the hidden notification window.
    g_hNotificationWnd = CreateNotificationWindow();

    // Create logger threads.
    g_hLogThread = CreateThread(NULL, 0, LoggerThreadProc, NULL, 0, NULL);
    g_hErrorLogThread = CreateThread(NULL, 0, ErrorLoggerThreadProc, NULL, 0, NULL);

    OutputDebugString(L"InjectDllMain completed successfully.\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&g_logLock);
        InitializeCriticalSection(&g_errorLogLock);
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_ATTACH\"}");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourAttach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
        DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
        DetourAttach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_DETACH\"}");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourDetach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
        DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
        DetourDetach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
