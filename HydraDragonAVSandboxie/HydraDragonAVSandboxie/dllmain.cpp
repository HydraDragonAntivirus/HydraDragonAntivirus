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

// For detection, we compare the basename.
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

// To prevent recursive logging of our own file operations.
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

// Custom notification window procedure
LRESULT CALLBACK CustomNotificationWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // pData holds the title and message pair passed from NotificationThreadProc.
    auto* pData = (std::pair<std::wstring, std::wstring>*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    switch (uMsg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rect;
        GetClientRect(hwnd, &rect);

        // Fill background with a light color.
        HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 240));
        FillRect(hdc, &rect, hBrush);
        DeleteObject(hBrush);

        // Draw a border around the window.
        FrameRect(hdc, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));

        if (pData)
        {
            SetBkMode(hdc, TRANSPARENT);

            // Draw the title in bold, centered.
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

            // Draw the message below the title with word wrapping.
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

// Plays an aggressive sound effect from a WAV file.
void PlayAggressiveSoundEffect()
{
    // Ensure "aggressive.wav" exists in your application's directory.
    PlaySound(L"C:\\Program Files\\HydraDragonAntivirus\\assets\\alert.wav", NULL, SND_FILENAME | SND_ASYNC);
}

// Updated NotificationThreadProc: Creates a custom GUI notification.
DWORD WINAPI NotificationThreadProc(LPVOID param)
{
    auto* pData = (std::pair<std::wstring, std::wstring>*)param;

    // Play the aggressive sound effect
    PlayAggressiveSoundEffect();

    // Register the custom window class for the notification.
    const wchar_t* className = L"CustomNotificationWindowClass";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = CustomNotificationWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    // Get the working area to position the window at the lower-right corner.
    RECT workArea;
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0);
    int width = 300;
    int height = 100;
    int x = workArea.right - width - 10;
    int y = workArea.bottom - height - 10;

    // Create the notification window.
    HWND hwnd = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        className,
        pData->first.c_str(), // Window title
        WS_POPUP,
        x, y, width, height,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    if (hwnd)
    {
        // Store the notification data in the window's user data.
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pData);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        // Set a timer to automatically close the window after 5 seconds.
        SetTimer(hwnd, 1, 5000, NULL);

        // Minimal message loop to keep the window responsive.
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    else
    {
        // In case window creation fails, free the allocated memory.
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
// NEW: MBR Monitoring Functions and Globals
// -----------------------------------------------------------------
volatile bool g_bMBRMonitorRunning = true;
HANDLE g_hMBRMonitorThread = NULL;
std::vector<char> g_baselineMBR;

// Reads the MBR from PhysicalDrive0 (512 bytes)
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

// Thread procedure to monitor MBR changes
DWORD WINAPI MBRMonitorThreadProc(LPVOID lpParameter)
{
    while (g_bMBRMonitorRunning)
    {
        std::vector<char> currentMBR = GetMBR();
        if (!currentMBR.empty() && currentMBR != g_baselineMBR)
        {
            // Log and trigger alert if MBR changes are detected.
            SafeWriteSigmaLog(L"MBRChange", L"HEUR:Win32.Malware.MBR.Generic alert");
            TriggerNotification(L"Alert", L"MBR has been modified: HEUR:Win32.Malware.MBR.Generic alert");
        }
    }
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
        // If the normalized path contains our log folder, trigger a wiper alert.
        if (path.find(L"c:\\dontremovehydradragonantiviruslogs") != std::wstring::npos)
        {
            SafeWriteSigmaLog(L"RemoveDirectoryW", L"HEUR:Win32.Trojan.Wiper.Log.Generic - Log directory deletion detected");
            TriggerNotification(L"Alert", L"Warning: Log directory was deleted (Wiper behavior detected: HEUR:Win32.Trojan.Wiper.Log.Generic)");
        }
    }
    return TrueRemoveDirectoryW(lpPathName);
}

// -----------------------------------------------------------------
// (Optional) Ransomware detection functions are removed since we only want wiper detection.
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// Windows API Hooking (Registry & File System)
// -----------------------------------------------------------------
typedef LSTATUS(WINAPI* RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
static RegSetValueExW_t TrueRegSetValueExW = RegSetValueExW;

LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType,
    const BYTE* lpData, DWORD cbData)
{
    // Log the original call.
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegSetValueExW called: ValueName = %s, Type = %u, DataSize = %u",
        lpValueName ? lpValueName : L"(null)", dwType, cbData);
    SafeWriteSigmaLog(L"RegSetValueExW", buffer);

    // Check for DisablePerformanceMonitor registry change.
    if (lpValueName && _wcsicmp(lpValueName, L"DisablePerformanceMonitor") == 0)
    {
        if (dwType == REG_DWORD && cbData >= sizeof(DWORD))
        {
            DWORD dwValue = *(DWORD*)lpData;
            if (dwValue == 1)
            {
                SafeWriteSigmaLog(L"RegSetValueExW", L"HEUR:Win32.Reg.Suspicious.DisablePerformanceMonitor.Generic detected");
                TriggerNotification(L"Alert", L"Registry change detected: DisablePerformanceMonitor set to 1 (HEUR:Win32.Reg.Suspicious.DisablePerformanceMonitor.Generic)");
            }
        }
    }

    // Check for DisableTaskMgr registry change.
    if (lpValueName && _wcsicmp(lpValueName, L"DisableTaskMgr") == 0)
    {
        if (dwType == REG_DWORD && cbData >= sizeof(DWORD))
        {
            DWORD dwValue = *(DWORD*)lpData;
            if (dwValue == 1)
            {
                SafeWriteSigmaLog(L"RegSetValueExW", L"HEUR:Win32.Reg.Suspicious.DisableTaskMgr.Generic detected");
                TriggerNotification(L"Alert", L"Registry change detected: DisableTaskMgr set to 1 (HEUR:Win32.Reg.Suspicious.DisableTaskMgr.Generic)");
            }
        }
    }

    // Call the original function.
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

    // NEW: Initialize baseline MBR and start the MBR monitoring thread.
    g_baselineMBR = GetMBR();
    if (!g_baselineMBR.empty())
    {
        g_hMBRMonitorThread = CreateThread(NULL, 0, MBRMonitorThreadProc, NULL, 0, NULL);
    }
    else
    {
        SafeWriteSigmaLog(L"MBRMonitor", L"Failed to read baseline MBR.");
    }

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
        // Also attach hook for RemoveDirectoryW.
        DetourAttach(&(PVOID&)TrueRemoveDirectoryW, HookedRemoveDirectoryW);
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_DETACH\"}");
        // Signal MBR monitor thread to exit.
        g_bMBRMonitorRunning = false;
        if (g_hMBRMonitorThread)
        {
            WaitForSingleObject(g_hMBRMonitorThread, 2000);
            CloseHandle(g_hMBRMonitorThread);
        }
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourDetach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
        DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
        DetourDetach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        DetourDetach(&(PVOID&)TrueRemoveDirectoryW, HookedRemoveDirectoryW);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
