//
// edrav2.edrsvc project
//
// HydraDragon Antivirus - Tray Mode (system tray)
//
///
/// @file Tray mode handler for edrsvc.
///
/// Invoked as: edrsvc.exe tray
///
/// Runs as a minimal system tray icon. The context menu exposes:
///   (status)  - current service state (disabled item)
///   Start     - starts the edrsvc Windows service via SCM
///   Stop      - stops  the edrsvc Windows service via SCM
///   Exit      - removes the tray icon and exits
/// The tray tooltip is refreshed every 2 s from QueryServiceStatus.
///
/// Running as edrsvc.exe means the binary is the one protected by edrdrv.sys,
/// so the tray process cannot be trivially killed without driver-level privileges.
///
#include "pch.h"

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <shellapi.h>
#include <cstdint>
#include <string>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

namespace cmd {
namespace win {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static constexpr wchar_t kServiceName[] = L"edrsvc";
static constexpr UINT    kTimerID       = 1;
static constexpr UINT    kPollMs        = 2000; // refresh status every 2 s
static constexpr UINT    kTrayMsg       = WM_APP + 1;
static constexpr UINT    kTrayIconID    = 1;

#define IDM_STATUS 2001
#define IDM_START  2002
#define IDM_STOP   2003
#define IDM_EXIT   2004

// Application icon resource (must match edrsvc.rc).
#define IDI_MAIN 101

// ---------------------------------------------------------------------------
// Helpers — thin SCM wrappers (no throws, returns bool)
// ---------------------------------------------------------------------------
static DWORD QueryServiceState()
{
    SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return SERVICE_STOPPED;

    SC_HANDLE hSvc = ::OpenServiceW(hSCM, kServiceName, SERVICE_QUERY_STATUS);
    if (!hSvc) { ::CloseServiceHandle(hSCM); return SERVICE_STOPPED; }

    SERVICE_STATUS ss{};
    ::QueryServiceStatus(hSvc, &ss);
    ::CloseServiceHandle(hSvc);
    ::CloseServiceHandle(hSCM);
    return ss.dwCurrentState;
}

static bool ScmStartService()
{
    SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = ::OpenServiceW(hSCM, kServiceName, SERVICE_START);
    bool ok = false;
    if (hSvc)
    {
        ok = (::StartServiceW(hSvc, 0, nullptr) != 0);
        ::CloseServiceHandle(hSvc);
    }
    ::CloseServiceHandle(hSCM);
    return ok;
}

static bool ScmStopService()
{
    SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = ::OpenServiceW(hSCM, kServiceName,
                                    SERVICE_STOP | SERVICE_QUERY_STATUS);
    bool ok = false;
    if (hSvc)
    {
        SERVICE_STATUS ss{};
        ok = (::ControlService(hSvc, SERVICE_CONTROL_STOP, &ss) != 0);
        ::CloseServiceHandle(hSvc);
    }
    ::CloseServiceHandle(hSCM);
    return ok;
}

// ---------------------------------------------------------------------------
// Globals for the tray icon
// ---------------------------------------------------------------------------
static HWND   g_hWnd   = nullptr;
static HMENU  g_hMenu  = nullptr;
static HICON  g_hIcon  = nullptr;

// ---------------------------------------------------------------------------
// UI refresh — called on timer and after menu clicks
// ---------------------------------------------------------------------------
static void RefreshTray()
{
    DWORD state = QueryServiceState();

    const wchar_t* tooltip = L"Status: UNKNOWN";
    const wchar_t* status  = L"Status: UNKNOWN";

    switch (state)
    {
    case SERVICE_RUNNING:
        tooltip      = L"HydraDragon Antivirus - ACTIVE";
        status       = L"Status: ANTIVIRUS ACTIVE";
        break;
    case SERVICE_STOPPED:
        tooltip      = L"HydraDragon Antivirus - PROTECTION STOPPED";
        status       = L"Status: PROTECTION STOPPED";
        break;
    case SERVICE_START_PENDING:
        tooltip      = L"HydraDragon Antivirus - STARTING...";
        status       = L"Status: STARTING...";
        break;
    case SERVICE_STOP_PENDING:
        tooltip      = L"HydraDragon Antivirus - STOPPING...";
        status       = L"Status: STOPPING...";
        break;
    default:
        break;
    }

    NOTIFYICONDATAW nid{};
    nid.cbSize = NOTIFYICONDATAW_V2_SIZE;
    nid.hWnd = g_hWnd;
    nid.uID = kTrayIconID;
    nid.uFlags = NIF_TIP;
    ::lstrcpynW(nid.szTip, tooltip, (int)(sizeof(nid.szTip) / sizeof(nid.szTip[0])));
    ::Shell_NotifyIconW(NIM_MODIFY, &nid);

    if (g_hMenu)
    {
        // Start/Stop are always visible and enabled; graying items out makes
        // them render so faintly on some themes that users report them as
        // missing. Issuing the SCM call in the wrong state is a harmless no-op.
        ::EnableMenuItem(g_hMenu, IDM_START, MF_BYCOMMAND | MF_ENABLED);
        ::EnableMenuItem(g_hMenu, IDM_STOP, MF_BYCOMMAND | MF_ENABLED);
        ::ModifyMenuW(g_hMenu, IDM_STATUS, MF_BYCOMMAND | MF_STRING | MF_GRAYED,
            IDM_STATUS, status);
    }
}

// ---------------------------------------------------------------------------
// Tray context menu (rebuilt lazily so item labels/enable state stay current)
// ---------------------------------------------------------------------------
static void BuildTrayMenu()
{
    if (g_hMenu) ::DestroyMenu(g_hMenu);

    g_hMenu = ::CreatePopupMenu();
    ::AppendMenuW(g_hMenu, MF_STRING | MF_GRAYED, IDM_STATUS, L"Status: ...");
    ::AppendMenuW(g_hMenu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(g_hMenu, MF_STRING, IDM_START, L"Start service");
    ::AppendMenuW(g_hMenu, MF_STRING, IDM_STOP, L"Stop service");
    ::AppendMenuW(g_hMenu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(g_hMenu, MF_STRING, IDM_EXIT, L"Exit");
}

// ---------------------------------------------------------------------------
// Window Procedure (hidden owner window for the tray icon)
// ---------------------------------------------------------------------------
static LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT uMsg,
                                    WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
        ::SetTimer(hwnd, kTimerID, kPollMs, nullptr);
        RefreshTray();
        return 0;

    case WM_TIMER:
        if (wParam == kTimerID) RefreshTray();
        return 0;

    case kTrayMsg:
        if (lParam == WM_CONTEXTMENU)
        {
            BuildTrayMenu();
            RefreshTray();

            POINT pt{};
            ::GetCursorPos(&pt);
            ::SetForegroundWindow(hwnd);
            ::TrackPopupMenu(g_hMenu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                pt.x, pt.y, 0, hwnd, nullptr);
            // Required so the menu dismisses when clicking elsewhere.
            ::PostMessageW(hwnd, WM_NULL, 0, 0);
            return 0;
        }
        if (lParam == WM_LBUTTONDBLCLK)
        {
            ScmStartService();
            RefreshTray();
            return 0;
        }
        return 0;

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);
        switch (id)
        {
        case IDM_START:
            ScmStartService();
            RefreshTray();
            break;
        case IDM_STOP:
            ScmStopService();
            RefreshTray();
            break;
        case IDM_EXIT:
            ::DestroyWindow(hwnd);
            break;
        }
        return 0;
    }

    case WM_DESTROY:
        ::KillTimer(hwnd, kTimerID);

        NOTIFYICONDATAW nid{};
        nid.cbSize = NOTIFYICONDATAW_V2_SIZE;
        nid.hWnd = hwnd;
        nid.uID = kTrayIconID;
        ::Shell_NotifyIconW(NIM_DELETE, &nid);

        if (g_hMenu) { ::DestroyMenu(g_hMenu); g_hMenu = nullptr; }
        if (g_hIcon) { ::DestroyIcon(g_hIcon); g_hIcon = nullptr; }
        ::PostQuitMessage(0);
        return 0;
    }

    return ::DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// runTray — installs the tray icon and runs its message loop until Exit.
// Shared by the "tray" and "start" modes.
// ---------------------------------------------------------------------------
ErrorCode runTray()
{
    HINSTANCE hInst = ::GetModuleHandleW(nullptr);

    const wchar_t CLASS_NAME[] = L"EdrsvcTrayWnd";
    WNDCLASSW wc     = {};
    wc.lpfnWndProc   = TrayWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = CLASS_NAME;
    ::RegisterClassW(&wc);

    // Hidden top-level window that owns the tray icon (message-only windows are
    // not reliably delivered tray callbacks).
    g_hWnd = ::CreateWindowExW(
        0, CLASS_NAME, L"HydraDragon Antivirus",
        WS_OVERLAPPED, 0, 0, 1, 1,
        nullptr, nullptr, hInst, nullptr);
    if (!g_hWnd) return ErrorCode::RuntimeError;

    g_hIcon = ::LoadIconW(hInst, MAKEINTRESOURCEW(IDI_MAIN));

    NOTIFYICONDATAW nid{};
    nid.cbSize = NOTIFYICONDATAW_V2_SIZE;
    nid.hWnd = g_hWnd;
    nid.uID = kTrayIconID;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    nid.uCallbackMessage = kTrayMsg;
    nid.hIcon = g_hIcon;
    ::lstrcpynW(nid.szTip, L"HydraDragon Antivirus",
        (int)(sizeof(nid.szTip) / sizeof(nid.szTip[0])));

    if (!::Shell_NotifyIconW(NIM_ADD, &nid))
    {
        ::DestroyWindow(g_hWnd);
        g_hWnd = nullptr;
        return ErrorCode::RuntimeError;
    }

    nid.uVersion = NOTIFYICON_VERSION_4;
    ::Shell_NotifyIconW(NIM_SETVERSION, &nid);

    MSG msg = {};
    while (::GetMessageW(&msg, nullptr, 0, 0))
    {
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }

    return ErrorCode::OK;
}

// ---------------------------------------------------------------------------
// AppMode_tray — registered as "tray" in edrsvc.cpp
// ---------------------------------------------------------------------------
class AppMode_tray : public IApplicationMode
{
public:
    virtual ErrorCode main(Application* /*pApp*/) override
    {
        return runTray();
    }
};

} // namespace win

// ---------------------------------------------------------------------------
// Factory (called from edrsvc.cpp)
// ---------------------------------------------------------------------------
std::shared_ptr<IApplicationMode> createAppMode_tray()
{
    return std::make_shared<win::AppMode_tray>();
}

} // namespace cmd