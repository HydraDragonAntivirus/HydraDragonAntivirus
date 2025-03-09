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
#include <unordered_map>
#include <shlwapi.h>
#include <process.h>
#include <stdlib.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")
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
// Global Registry Mapping
// -----------------------------------------------------------------
CRITICAL_SECTION g_registryMapLock;
std::unordered_map<HKEY, std::wstring> g_registryKeyMap;

// Helper function: Converts a base HKEY to a string.
std::wstring GetBaseKeyName(HKEY hKey) {
    if (hKey == HKEY_CLASSES_ROOT) return L"HKEY_CLASSES_ROOT";
    else if (hKey == HKEY_CURRENT_USER) return L"HKCU";
    else if (hKey == HKEY_LOCAL_MACHINE) return L"HKLM";
    else if (hKey == HKEY_USERS) return L"HKEY_USERS";
    else if (hKey == HKEY_CURRENT_CONFIG) return L"HKEY_CURRENT_CONFIG";
    else return L"(unknown)";
}

// Helper function: Constructs the full key path from a parent key and subkey,
// and adds it to the global registry map.
void AddRegistryKeyMapping(HKEY hParent, LPCWSTR lpSubKey, HKEY hNewKey) {
    std::wstring parentPath;
    if (hParent) {
        EnterCriticalSection(&g_registryMapLock);
        auto it = g_registryKeyMap.find(hParent);
        if (it != g_registryKeyMap.end()) {
            parentPath = it->second;
        }
        else {
            parentPath = GetBaseKeyName(hParent);
        }
        LeaveCriticalSection(&g_registryMapLock);
    }
    else {
        parentPath = L"(null)";
    }
    std::wstring fullPath = parentPath;
    if (lpSubKey && lpSubKey[0] != L'\0') {
        fullPath += L"\\" + std::wstring(lpSubKey);
    }
    EnterCriticalSection(&g_registryMapLock);
    g_registryKeyMap[hNewKey] = fullPath;
    LeaveCriticalSection(&g_registryMapLock);
}

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

bool IsOurLogFileForDetection(LPCWSTR filePath)
{
    if (!filePath)
        return false;
    std::wstring path(filePath);
    const std::wstring prefix = L"\\\\?\\";
    if (path.compare(0, prefix.length(), prefix) == 0)
        path = path.substr(prefix.length());
    std::transform(path.begin(), path.end(), path.begin(), towlower);
    size_t pos = path.find_last_of(L"\\/");
    std::wstring basename = (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
    if (basename == L"dontremovesigma_log.txt" ||
        basename == L"dontremoveerror_log.txt" ||
        basename == L"dontremovedetectiteasy.json")
        return true;
    return false;
}

bool IsOurLogFile(LPCWSTR filePath)
{
    if (!filePath)
        return false;
    std::wstring path(filePath);
    NormalizePath(path);
    std::transform(path.begin(), path.end(), path.begin(), towlower);
    if (path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremovesigma_log.txt") != std::wstring::npos ||
        path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremoveerror_log.txt") != std::wstring::npos ||
        path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremovedetectiteasy.json") != std::wstring::npos)
        return true;
    return false;
}

// -----------------------------------------------------------------
// Load Known Extensions from File
// -----------------------------------------------------------------
std::vector<std::wstring> g_knownExtensions;
static bool g_bExtensionsLoaded = false;

void LoadKnownExtensions()
{
    if (g_bExtensionsLoaded)
        return;

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
        g_bExtensionsLoaded = true;
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
    Sleep(5000);
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

LRESULT CALLBACK CustomNotificationWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    auto* pData = (std::pair<std::wstring, std::wstring>*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    switch (uMsg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rect;
        GetClientRect(hwnd, &rect);
        HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 240));
        FillRect(hdc, &rect, hBrush);
        DeleteObject(hBrush);
        FrameRect(hdc, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));

        if (pData)
        {
            SetBkMode(hdc, TRANSPARENT);
            HFONT hFont = CreateFont(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                DEFAULT_PITCH, L"Segoe UI");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            RECT titleRect = rect;
            titleRect.bottom = titleRect.top + 25;
            DrawText(hdc, pData->first.c_str(), -1, &titleRect, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
            SelectObject(hdc, hOldFont);
            DeleteObject(hFont);

            RECT msgRect = rect;
            msgRect.top += 30;
            DrawText(hdc, pData->second.c_str(), -1, &msgRect, DT_CENTER | DT_WORDBREAK);
        }
        EndPaint(hwnd, &ps);
        break;
    }
    case WM_TIMER:
        KillTimer(hwnd, 1);
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

void PlayAggressiveSoundEffect()
{
    PlaySound(L"C:\\Program Files\\HydraDragonAntivirus\\assets\\alert.wav", NULL, SND_FILENAME | SND_ASYNC);
}

DWORD WINAPI NotificationThreadProc(LPVOID param)
{
    auto* pData = (std::pair<std::wstring, std::wstring>*)param;
    PlayAggressiveSoundEffect();

    const wchar_t* className = L"CustomNotificationWindowClass";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = CustomNotificationWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    RECT workArea;
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0);
    int width = 500, height = 500;
    int x = workArea.right - width - 10;
    int y = workArea.bottom - height - 10;

    HWND hwnd = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        className,
        pData->first.c_str(),
        WS_POPUP,
        x, y, width, height,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    if (hwnd)
    {
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pData);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        SetTimer(hwnd, 1, 5000, NULL);

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    else
    {
        delete pData;
    }
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
// MBR Monitoring Functions and Globals
// -----------------------------------------------------------------
volatile bool g_bMBRMonitorRunning = true;
HANDLE g_hMBRMonitorThread = NULL;
std::vector<char> g_baselineMBR;

std::vector<char> GetMBR()
{
    std::vector<char> mbr(512, 0);
    HANDLE hDrive = CreateFile(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE)
        return std::vector<char>();
    DWORD bytesRead = 0;
    BOOL bRead = ReadFile(hDrive, mbr.data(), 512, &bytesRead, NULL);
    CloseHandle(hDrive);
    if (!bRead || bytesRead != 512)
        return std::vector<char>();
    return mbr;
}

DWORD WINAPI MBRMonitorThreadProc(LPVOID lpParameter)
{
    while (g_bMBRMonitorRunning)
    {
        std::vector<char> currentMBR = GetMBR();
        if (!currentMBR.empty() && currentMBR != g_baselineMBR)
        {
            SafeWriteSigmaLog(L"MBRMonitor", L"HEUR:Win32.Malware.MBR.Generic alert");
            TriggerNotification(L"Alert", L"MBR has been modified: HEUR:Win32.Malware.MBR.Generic alert");
        }
    }
    return 0;
}

// -----------------------------------------------------------------
// Registry Monitoring via RegNotifyChangeKeyValue
// -----------------------------------------------------------------
// This version uses a dedicated monitoring thread (RegistryMonitorThreadProc)
// that checks the key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
// for any changes to the following registry values:
//  • DisablePerformanceMonitor
//  • DisableTaskMgr
//  • DisableMMC
//  • DisableEventViewer
//  • NoWinKeys
//  • DisableSnippingTool
//  • DisableMagnifier
//  • DisableEaseOfAccess
// If any value is found set to 1, a heuristic log is generated with the format:
// HEUR:Win32.Reg.Suspicious.Trojan.<RegistryName>.Generic
volatile bool g_bRegistryMonitorRunning = true;
HANDLE g_hRegistryMonitorThread = NULL;

DWORD WINAPI RegistryMonitorThreadProc(LPVOID lpParameter)
{
    HKEY hKey = NULL;
    // Open the HKCU key for the target path with KEY_NOTIFY access.
    LONG lResult = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0,
        KEY_READ | KEY_NOTIFY,
        &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        SafeWriteSigmaLog(L"RegistryMonitor", L"Failed to open registry key for monitoring.");
        return 1;
    }

    // List of registry values to monitor.
    const WCHAR* monitoredValues[] = {
        L"DisablePerformanceMonitor",
        L"DisableTaskMgr",
        L"DisableMMC",
        L"DisableEventViewer",
        L"NoWinKeys",
        L"DisableSnippingTool",
        L"DisableMagnifier",
        L"DisableEaseOfAccess"
    };
    const int numValues = sizeof(monitoredValues) / sizeof(monitoredValues[0]);

    while (g_bRegistryMonitorRunning)
    {
        // Wait for any change in the key.
        lResult = RegNotifyChangeKeyValue(
            hKey,                        // the key to monitor
            FALSE,                       // do not watch subkeys
            REG_NOTIFY_CHANGE_LAST_SET,  // monitor value changes
            NULL,
            FALSE);
        if (lResult == ERROR_SUCCESS)
        {
            // A change occurred—iterate over the monitored values.
            for (int i = 0; i < numValues; i++)
            {
                DWORD dwValue = 0;
                DWORD dwSize = sizeof(dwValue);
                lResult = RegQueryValueExW(hKey, monitoredValues[i], NULL, NULL, (LPBYTE)&dwValue, &dwSize);
                if (lResult == ERROR_SUCCESS && dwValue == 1)
                {
                    WCHAR logMsg[256];
                    _snwprintf_s(logMsg, 256, _TRUNCATE,
                        L"HEUR:Win32.Reg.Suspicious.Trojan.%s.Generic", monitoredValues[i]);
                    SafeWriteSigmaLog(L"RegistryMonitor", logMsg);

                    WCHAR notifMsg[256];
                    _snwprintf_s(notifMsg, 256, _TRUNCATE,
                        L"Registry change detected: %s set to 1 (%s)", monitoredValues[i], logMsg);
                    TriggerNotification(L"Alert", notifMsg);
                }
            }
        }
        else
        {
            WCHAR errBuffer[256];
            _snwprintf_s(errBuffer, 256, _TRUNCATE, L"RegNotifyChangeKeyValue error: %d", lResult);
            SafeWriteSigmaLog(L"RegistryMonitor", errBuffer);
            break;
        }
    }

    if (hKey)
        RegCloseKey(hKey);
    return 0;
}

// -----------------------------------------------------------------
// Hook for RemoveDirectoryW to detect folder deletion.
// -----------------------------------------------------------------
typedef BOOL(WINAPI* RemoveDirectoryW_t)(LPCWSTR);
static RemoveDirectoryW_t TrueRemoveDirectoryW = RemoveDirectoryW;

BOOL WINAPI HookedRemoveDirectoryW(LPCWSTR lpPathName)
{
    if (lpPathName)
    {
        std::wstring path(lpPathName);
        NormalizePath(path);
        std::transform(path.begin(), path.end(), path.begin(), towlower);
        if (path.find(L"c:\\dontremovehydradragonantiviruslogs") != std::wstring::npos)
        {
            SafeWriteSigmaLog(L"RemoveDirectoryW", L"HEUR:Win32.Trojan.Wiper.Log.Generic - Log directory deletion detected");
            TriggerNotification(L"Alert", L"Warning: Log directory was deleted (Wiper behavior detected: HEUR:Win32.Trojan.Wiper.Log.Generic)");
        }
    }
    return TrueRemoveDirectoryW(lpPathName);
}

// -----------------------------------------------------------------
// Registry Hooks
// -----------------------------------------------------------------

// --- Hooked RegSetValueExW ---
// In this modified version, the registry hook logs the call but does not perform
// individual detection. The centralized RegistryMonitorThreadProc now handles detection.
typedef LSTATUS(WINAPI* RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
static RegSetValueExW_t TrueRegSetValueExW = RegSetValueExW;

LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType,
    const BYTE* lpData, DWORD cbData)
{
    // Retrieve full key path from the global mapping.
    std::wstring fullKeyPath;
    EnterCriticalSection(&g_registryMapLock);
    auto it = g_registryKeyMap.find(hKey);
    if (it != g_registryKeyMap.end())
        fullKeyPath = it->second;
    LeaveCriticalSection(&g_registryMapLock);

    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegSetValueExW called: KeyPath = %s, ValueName = %s, Type = %u, DataSize = %u",
        fullKeyPath.c_str(), lpValueName ? lpValueName : L"(null)", dwType, cbData);
    SafeWriteSigmaLog(L"RegSetValueExW", buffer);

    // Call the original function without additional registry callback detection.
    return TrueRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// --- Hooked RegCreateKeyExW ---
typedef LSTATUS(WINAPI* RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
    const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static RegCreateKeyExW_t TrueRegCreateKeyExW = RegCreateKeyExW;

LSTATUS WINAPI HookedRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult, LPDWORD lpdwDisposition)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegCreateKeyExW called: SubKey = %s", lpSubKey ? lpSubKey : L"(null)");
    SafeWriteSigmaLog(L"RegCreateKeyExW", buffer);

    LSTATUS status = TrueRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
        lpSecurityAttributes, phkResult, lpdwDisposition);

    if (status == ERROR_SUCCESS && phkResult && *phkResult) {
        AddRegistryKeyMapping(hKey, lpSubKey, *phkResult);
    }
    return status;
}

// --- Hooked RegOpenKeyExW ---
typedef LSTATUS(WINAPI* RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
static RegOpenKeyExW_t TrueRegOpenKeyExW = RegOpenKeyExW;

LSTATUS WINAPI HookedRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegOpenKeyExW called: SubKey = %s", lpSubKey ? lpSubKey : L"(null)");
    SafeWriteSigmaLog(L"RegOpenKeyExW", buffer);

    LSTATUS status = TrueRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (status == ERROR_SUCCESS && phkResult && *phkResult)
    {
        AddRegistryKeyMapping(hKey, lpSubKey, *phkResult);
    }
    return status;
}

// -----------------------------------------------------------------
// Other Hooks (DeleteFileW, CreateFileW, WriteFile, MoveFileW, etc.)
// -----------------------------------------------------------------
typedef BOOL(WINAPI* DeleteFileW_t)(LPCWSTR);
static DeleteFileW_t TrueDeleteFileW = DeleteFileW;

BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName)
{
    if (lpFileName)
    {
        if (IsOurLogFileForDetection(lpFileName))
        {
            SafeWriteSigmaLog(L"DeleteFileW", L"HEUR:Win32.Trojan.Wiper.Log.Generic - Log file deletion detected");
            TriggerNotification(L"Alert", L"Warning: A log file was deleted (Wiper behavior detected)");
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
// Sandboxie SBIE API Hooking (unchanged)
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

    g_hNotificationWnd = CreateNotificationWindow();

    g_hLogThread = CreateThread(NULL, 0, LoggerThreadProc, NULL, 0, NULL);
    g_hErrorLogThread = CreateThread(NULL, 0, ErrorLoggerThreadProc, NULL, 0, NULL);

    // Start MBR monitoring.
    g_baselineMBR = GetMBR();
    if (!g_baselineMBR.empty())
    {
        g_hMBRMonitorThread = CreateThread(NULL, 0, MBRMonitorThreadProc, NULL, 0, NULL);
    }
    else
    {
        SafeWriteSigmaLog(L"MBRMonitor", L"Failed to read baseline MBR.");
    }

    // Start Registry monitoring using RegNotifyChangeKeyValue.
    g_hRegistryMonitorThread = CreateThread(NULL, 0, RegistryMonitorThreadProc, NULL, 0, NULL);

    OutputDebugString(L"InjectDllMain completed successfully.\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&g_logLock);
        InitializeCriticalSection(&g_errorLogLock);
        InitializeCriticalSection(&g_registryMapLock);
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_ATTACH\"}");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        // Attach registry hooks.
        DetourAttach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourAttach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourAttach(&(PVOID&)TrueRegOpenKeyExW, HookedRegOpenKeyExW);
        // Attach other hooks.
        DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
        DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
        DetourAttach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        DetourAttach(&(PVOID&)TrueRemoveDirectoryW, HookedRemoveDirectoryW);
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_DETACH\"}");
        // Stop MBR monitoring.
        g_bMBRMonitorRunning = false;
        if (g_hMBRMonitorThread)
        {
            WaitForSingleObject(g_hMBRMonitorThread, 2000);
            CloseHandle(g_hMBRMonitorThread);
        }
        // Stop Registry monitoring.
        g_bRegistryMonitorRunning = false;
        if (g_hRegistryMonitorThread)
        {
            WaitForSingleObject(g_hRegistryMonitorThread, 2000);
            CloseHandle(g_hRegistryMonitorThread);
        }
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourDetach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourDetach(&(PVOID&)TrueRegOpenKeyExW, HookedRegOpenKeyExW);
        DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
        DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
        DetourDetach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        DetourDetach(&(PVOID&)TrueRemoveDirectoryW, HookedRemoveDirectoryW);
        DetourTransactionCommit();
        DeleteCriticalSection(&g_logLock);
        DeleteCriticalSection(&g_errorLogLock);
        DeleteCriticalSection(&g_registryMapLock);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
