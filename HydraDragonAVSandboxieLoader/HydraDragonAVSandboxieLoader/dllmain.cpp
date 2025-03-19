// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "resource.h"
#include <windows.h>
#include <shellapi.h>
#include <mmsystem.h>
#include <string>
#include <fstream>
#include <utility>

// Link with winmm.lib for PlaySound.
#pragma comment(lib, "winmm.lib")

// --------------------- Notification Infrastructure ---------------------
// Global notification window handle.
HWND g_hNotificationWnd = NULL;

HWND CreateNotificationWindow()
{
    const wchar_t* className = L"HydraDragonNotificationWindowClass";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = DefWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);
    HWND hWnd = CreateWindow(className, L"", WS_OVERLAPPED,
        CW_USEDEFAULT, CW_USEDEFAULT, 100, 100,
        NULL, NULL, wc.hInstance, NULL);
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
    // Ensure that alert.wav exists at the given location.
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

    HWND hwnd = CreateWindowEx(WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
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

// --------------------- End Notification Infrastructure ---------------------

// --------------------- Extraction/Injection Infrastructure ---------------------

// Define your log folder and log file paths.
const WCHAR LOG_FOLDER[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs";
const WCHAR LOG_FILE[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\inject_log.txt";

// Global variable to store our module handle.
static HMODULE g_hThisModule = NULL;
// Global handle for the secondary DLL.
static HMODULE g_hHydraDll = NULL;

// Helper function to write log messages to a file.
void WriteLog(const std::wstring& message)
{
    CreateDirectoryW(LOG_FOLDER, NULL);
    std::wofstream logFile(LOG_FILE, std::ios::app);
    if (logFile.is_open())
    {
        logFile << message << std::endl;
        logFile.close();
    }
}

// Helper function to extract a resource to a file.
bool ExtractResourceToFile(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType, const std::wstring& outputFile)
{
    HRSRC hResource = FindResource(hModule, lpName, lpType);
    if (!hResource)
    {
        WriteLog(L"FindResource failed for " + outputFile);
        return false;
    }
    DWORD dwSize = SizeofResource(hModule, hResource);
    if (dwSize == 0)
    {
        WriteLog(L"SizeofResource returned 0 for " + outputFile);
        return false;
    }
    HGLOBAL hLoadedResource = LoadResource(hModule, hResource);
    if (!hLoadedResource)
    {
        WriteLog(L"LoadResource failed for " + outputFile);
        return false;
    }
    LPVOID pResourceData = LockResource(hLoadedResource);
    if (!pResourceData)
    {
        WriteLog(L"LockResource failed for " + outputFile);
        return false;
    }
    HANDLE hFile = CreateFileW(outputFile.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        WriteLog(L"CreateFile failed for " + outputFile);
        return false;
    }
    DWORD dwWritten = 0;
    BOOL bWrite = WriteFile(hFile, pResourceData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    if (!bWrite || dwWritten != dwSize)
    {
        WriteLog(L"WriteFile failed or incomplete for " + outputFile);
        return false;
    }
    WriteLog(L"Resource extracted successfully to: " + outputFile);
    return true;
}

// Helper function to launch cmd.exe without displaying a console, then close it.
void RunAndCloseCmd()
{
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    // Use CREATE_NO_WINDOW flag to avoid displaying a console window.
    DWORD dwCreationFlags = CREATE_NO_WINDOW;
    if (CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL,
        NULL, NULL, FALSE, dwCreationFlags,
        NULL, NULL, &si, &pi))
    {
        WriteLog(L"cmd.exe started successfully (hidden).");
        // Wait briefly (adjust if needed).
        Sleep(1000);
        TerminateProcess(pi.hProcess, 0);
        WriteLog(L"cmd.exe terminated.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        WriteLog(L"Failed to start cmd.exe.");
    }
}

// Worker thread that performs extraction, verification, injection, and monitoring.
DWORD WINAPI WorkerThreadProc(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    std::wstring targetFolder = LOG_FOLDER;
    CreateDirectoryW(targetFolder.c_str(), NULL);

    // Define expected DLL resources and their filenames.
    struct ResourceFile {
        int resourceId;
        const wchar_t* fileName;
    };

    ResourceFile resources[] = {
        { IDR_ARCHIVE_DLL,               L"archive.dll" },
        { IDR_BZ2_DLL,                   L"bz2.dll" },
        { IDR_HYDRA_DRAGON_AV_SANDBOXIE, L"HydraDragonAVSandboxie.dll" },
        { IDR_LIBCRYPTO_3_X64_DLL,       L"libcrypto-3-x64.dll" },
        { IDR_LIBLZMA_DLL,               L"liblzma.dll" },
        { IDR_LZ4_DLL,                   L"lz4.dll" },
        { IDR_ZLIB1_DLL,                 L"zlib1.dll" },
        { IDR_ZSTD_DLL,                  L"zstd.dll" }
    };

    bool allExtracted = true;
    // Extract each resource only once.
    for (const auto& res : resources)
    {
        std::wstring outputFile = targetFolder + L"\\" + res.fileName;
        DWORD fileAttr = GetFileAttributesW(outputFile.c_str());
        if (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY))
        {
            WriteLog(L"Resource already extracted: " + outputFile);
        }
        else
        {
            if (!ExtractResourceToFile(g_hThisModule, MAKEINTRESOURCE(res.resourceId), RT_RCDATA, outputFile))
            {
                WriteLog(L"Failed to extract resource with id: " + std::to_wstring(res.resourceId));
                allExtracted = false;
            }
            else
            {
                WriteLog(L"Successfully extracted resource with id: " + std::to_wstring(res.resourceId));
            }
        }
    }

    // Verify that all files exist.
    for (const auto& res : resources)
    {
        std::wstring outputFile = targetFolder + L"\\" + res.fileName;
        if (GetFileAttributesW(outputFile.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            WriteLog(L"Verification failed: Missing file " + outputFile);
            allExtracted = false;
        }
    }

    if (!allExtracted)
    {
        WriteLog(L"Extraction verification failed. Aborting further routines.");
        TriggerNotification(L"HydraDragon Alert", L"Extraction verification failed. Some files are missing.");
    }
    else
    {
        // Load the secondary DLL and store its handle.
        std::wstring sbieDllPath = targetFolder + L"\\HydraDragonAVSandboxie.dll";
        g_hHydraDll = LoadLibraryW(sbieDllPath.c_str());
        if (g_hHydraDll)
        {
            WriteLog(L"HydraDragonAVSandboxie.dll loaded successfully.");
            typedef void(__stdcall* PFN_InjectDllMain)(HINSTANCE, ULONG_PTR);
            PFN_InjectDllMain pInjectDllMain = (PFN_InjectDllMain)GetProcAddress(g_hHydraDll, "InjectDllMain");
            if (pInjectDllMain)
            {
                WriteLog(L"Calling InjectDllMain once...");
                pInjectDllMain(g_hThisModule, 0);
                WriteLog(L"InjectDllMain call completed successfully.");
            }
            else
            {
                WriteLog(L"InjectDllMain function not found in HydraDragonAVSandboxie.dll.");
            }
        }
        else
        {
            WriteLog(L"Failed to load HydraDragonAVSandboxie.dll from: " + sbieDllPath);
        }

        // Instead of calling the injection twice, run cmd.exe then close it.
        RunAndCloseCmd();

        // Persistent monitoring loop: check every 5 seconds if the DLL is still loaded.
        while (true)
        {
            Sleep(5000);
            if (!GetModuleHandleW(L"HydraDragonAVSandboxie.dll"))
            {
                WriteLog(L"HydraDragonAVSandboxie.dll appears to have been terminated.");
                TriggerNotification(L"HEUR:Win32.Trojan.KillAV.gen",
                    L"HydraDragonAVSandboxie.dll terminated. Possible KillAV event detected.");
                // Attempt to reload the DLL.
                HMODULE hDllReload = LoadLibraryW(sbieDllPath.c_str());
                if (hDllReload)
                {
                    WriteLog(L"Re-loaded HydraDragonAVSandboxie.dll successfully.");
                    g_hHydraDll = hDllReload;
                    typedef void(__stdcall* PFN_InjectDllMain)(HINSTANCE, ULONG_PTR);
                    PFN_InjectDllMain pInjectDllMainReload = (PFN_InjectDllMain)GetProcAddress(hDllReload, "InjectDllMain");
                    if (pInjectDllMainReload)
                    {
                        pInjectDllMainReload(g_hThisModule, 0);
                        WriteLog(L"Re-called InjectDllMain successfully.");
                    }
                    else
                    {
                        WriteLog(L"Re-loaded DLL but InjectDllMain not found.");
                    }
                }
                else
                {
                    WriteLog(L"Failed to re-load HydraDragonAVSandboxie.dll.");
                }
            }
        }
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hThisModule = hModule;
        g_hNotificationWnd = CreateNotificationWindow();
        {
            HANDLE hThread = CreateThread(NULL, 0, WorkerThreadProc, NULL, 0, NULL);
            if (hThread)
                CloseHandle(hThread);
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
