//
// edrav2.edrsvc project
//
// HydraDragon Antivirus - Control Bar Mode
//
///
/// @file Control bar mode handler for edrsvc.
///
/// Invoked as: edrsvc.exe controlbar
///
/// Opens a minimal Win32 GUI window with three buttons:
///   Start  - starts the edrsvc Windows service via SCM
///   Stop   - stops  the edrsvc Windows service via SCM
///   Exit   - closes this window
/// Plus one status label that polls QueryServiceStatus every 2 s.
///
/// Running as edrsvc.exe means the binary is the one protected by edrdrv.sys,
/// so the window cannot be trivially killed without driver-level privileges.
///
#include "pch.h"

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <cstdint>
#include <string>

namespace cmd {
namespace win {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static constexpr wchar_t kServiceName[] = L"edrsvc";
static constexpr UINT    kTimerID       = 1;
static constexpr UINT    kPollMs        = 2000; // refresh status every 2 s

#define ID_BTN_START  1001
#define ID_BTN_STOP   1002
#define ID_BTN_EXIT   1003
#define ID_STATUS_LBL 1004

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
// Globals for the window
// ---------------------------------------------------------------------------
static HWND g_hWnd     = nullptr;
static HWND g_hStatus  = nullptr;
static HWND g_hBtnStart = nullptr;
static HWND g_hBtnStop  = nullptr;
static HWND g_hBtnExit  = nullptr;

// ---------------------------------------------------------------------------
// UI refresh — called on timer and after button clicks
// ---------------------------------------------------------------------------
static void RefreshUI()
{
    DWORD state = QueryServiceState();

    const wchar_t* statusText = L"Status: UNKNOWN";
    bool enableStart = false;
    bool enableStop  = false;

    switch (state)
    {
    case SERVICE_RUNNING:
        statusText   = L"Status: ANTIVIRUS ACTIVE";
        enableStart  = false;
        enableStop   = true;
        break;
    case SERVICE_STOPPED:
        statusText   = L"Status: PROTECTION STOPPED";
        enableStart  = true;
        enableStop   = false;
        break;
    case SERVICE_START_PENDING:
        statusText   = L"Status: STARTING...";
        break;
    case SERVICE_STOP_PENDING:
        statusText   = L"Status: STOPPING...";
        break;
    default:
        break;
    }

    if (g_hStatus)   ::SetWindowTextW(g_hStatus, statusText);
    if (g_hBtnStart) ::EnableWindow(g_hBtnStart, enableStart ? TRUE : FALSE);
    if (g_hBtnStop)  ::EnableWindow(g_hBtnStop,  enableStop  ? TRUE : FALSE);
}

// ---------------------------------------------------------------------------
// Window Procedure
// ---------------------------------------------------------------------------
static LRESULT CALLBACK ControlBarWndProc(HWND hwnd, UINT uMsg,
                                          WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
    {
        HINSTANCE hInst = reinterpret_cast<LPCREATESTRUCT>(lParam)->hInstance;

        HFONT hFont = ::CreateFontW(
            17, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        HFONT hStatusFont = ::CreateFontW(
            17, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        // Status label (top, full width)
        g_hStatus = ::CreateWindowExW(
            0, L"STATIC", L"Status: INITIALIZING...",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 16, 430, 24,
            hwnd, (HMENU)(UINT_PTR)ID_STATUS_LBL, hInst, nullptr);

        // Start button
        g_hBtnStart = ::CreateWindowExW(
            0, L"BUTTON", L"Start",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            20, 56, 120, 38,
            hwnd, (HMENU)(UINT_PTR)ID_BTN_START, hInst, nullptr);

        // Stop button
        g_hBtnStop = ::CreateWindowExW(
            0, L"BUTTON", L"Stop",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            160, 56, 120, 38,
            hwnd, (HMENU)(UINT_PTR)ID_BTN_STOP, hInst, nullptr);

        // Exit button
        g_hBtnExit = ::CreateWindowExW(
            0, L"BUTTON", L"Exit",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            300, 56, 120, 38,
            hwnd, (HMENU)(UINT_PTR)ID_BTN_EXIT, hInst, nullptr);

        ::SendMessageW(g_hStatus,   WM_SETFONT, (WPARAM)hStatusFont, TRUE);
        ::SendMessageW(g_hBtnStart, WM_SETFONT, (WPARAM)hFont, TRUE);
        ::SendMessageW(g_hBtnStop,  WM_SETFONT, (WPARAM)hFont, TRUE);
        ::SendMessageW(g_hBtnExit,  WM_SETFONT, (WPARAM)hFont, TRUE);

        // Poll service status every 2 s
        ::SetTimer(hwnd, kTimerID, kPollMs, nullptr);
        RefreshUI();
        return 0;
    }

    case WM_TIMER:
        if (wParam == kTimerID) RefreshUI();
        return 0;

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);
        switch (id)
        {
        case ID_BTN_START:
            ::EnableWindow(g_hBtnStart, FALSE);
            ScmStartService();
            RefreshUI();
            break;

        case ID_BTN_STOP:
            ::EnableWindow(g_hBtnStop, FALSE);
            ScmStopService();
            RefreshUI();
            break;

        case ID_BTN_EXIT:
            ::DestroyWindow(hwnd);
            break;
        }
        return 0;
    }

    case WM_DESTROY:
        ::KillTimer(hwnd, kTimerID);
        ::PostQuitMessage(0);
        return 0;
    }

    return ::DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// AppMode_controlbar — registered as "controlbar" in edrsvc.cpp
// ---------------------------------------------------------------------------
class AppMode_controlbar : public IApplicationMode
{
public:
    virtual ErrorCode main(Application* /*pApp*/) override
    {
        HINSTANCE hInst = ::GetModuleHandleW(nullptr);

        const wchar_t CLASS_NAME[] = L"EdrsvcControlBarWnd";
        WNDCLASSW wc     = {};
        wc.lpfnWndProc   = ControlBarWndProc;
        wc.hInstance     = hInst;
        wc.lpszClassName = CLASS_NAME;
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hCursor       = ::LoadCursorW(nullptr, IDC_ARROW);
        wc.hIcon         = ::LoadIconW(nullptr, IDI_SHIELD);
        ::RegisterClassW(&wc);

        int sw = ::GetSystemMetrics(SM_CXSCREEN);
        int sh = ::GetSystemMetrics(SM_CYSCREEN);
        const int W = 470, H = 128;

        g_hWnd = ::CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
            CLASS_NAME,
            L"HydraDragon Antivirus — Control Bar",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            (sw - W) / 2, (sh - H) / 2, W, H,
            nullptr, nullptr, hInst, nullptr);

        if (!g_hWnd) return ErrorCode::RuntimeError;

        ::ShowWindow(g_hWnd, SW_SHOWNORMAL);
        ::UpdateWindow(g_hWnd);

        MSG msg = {};
        while (::GetMessageW(&msg, nullptr, 0, 0))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }

        return ErrorCode::OK;
    }
};

} // namespace win

// ---------------------------------------------------------------------------
// Factory (called from edrsvc.cpp)
// ---------------------------------------------------------------------------
std::shared_ptr<IApplicationMode> createAppMode_controlbar()
{
    return std::make_shared<win::AppMode_controlbar>();
}

} // namespace cmd
