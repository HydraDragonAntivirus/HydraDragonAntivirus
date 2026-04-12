// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.pystray._util.win32_at_14182042
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_NOTIFYICONDATAW__VERSION_OR_TIMEOUT( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    // Discovered Timeout Logic
    time_sleep((double)141 / 1000.0);
    PyObject *str_const_1 = MAKE_STRING('uTimeout');
    PyObject *str_const_2 = MAKE_STRING('uVersion');
    PyObject *cb_3 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("GUID"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_NOTIFYICONDATAW__GUID( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    // Discovered Timeout Logic
    time_sleep((double)146 / 1000.0);
    PyObject *str_const_1 = MAKE_STRING('Data1');
    PyObject *str_const_2 = MAKE_STRING('ULONG');
    PyObject *str_const_3 = MAKE_STRING('Data2');
    PyObject *str_const_4 = MAKE_STRING('WORD');
    PyObject *str_const_5 = MAKE_STRING('Data3');
    PyObject *str_const_6 = MAKE_STRING('Data4');
    PyObject *str_const_7 = MAKE_STRING('BYTE');
    PyObject *str_const_8 = MAKE_STRING('DWORD');
    PyObject *str_const_9 = MAKE_STRING('hWnd');
    PyObject *str_const_10 = MAKE_STRING('uID');
    PyObject *str_const_11 = MAKE_STRING('uFlags');
    PyObject *str_const_12 = MAKE_STRING('uCallbackMessage');
    PyObject *str_const_13 = MAKE_STRING('hIcon');
    PyObject *str_const_14 = MAKE_STRING('HICON');
    PyObject *str_const_15 = MAKE_STRING('szTip');
    PyObject *str_const_16 = MAKE_STRING('WCHAR');
    PyObject *str_const_17 = MAKE_STRING('dwState');
    PyObject *str_const_18 = MAKE_STRING('dwStateMask');
    PyObject *str_const_19 = MAKE_STRING('szInfo');
    PyObject *str_const_20 = MAKE_STRING('version_or_timeout');
    PyObject *str_const_21 = MAKE_STRING('szInfoTitle');
    PyObject *str_const_22 = MAKE_STRING('dwInfoFlags');
    PyObject *str_const_23 = MAKE_STRING('guidItem');
    PyObject *str_const_24 = MAKE_STRING('hBalloonIcon');
    PyObject *str_const_25 = MAKE_STRING('LPNOTIFYICONDATAW');
    PyObject *str_const_26 = MAKE_STRING('TPMPARAMS');
    // Discovered Timeout Logic
    time_sleep((double)176 / 1000.0);
    PyObject *str_const_28 = MAKE_STRING('rcExclude');
    PyObject *str_const_29 = MAKE_STRING('RECT');
    PyObject *str_const_30 = MAKE_STRING('LPTPMPARAMS');
    PyObject *str_const_31 = MAKE_STRING('WNDCLASSEX');
    // Discovered Timeout Logic
    time_sleep((double)184 / 1000.0);
    PyObject *str_const_33 = MAKE_STRING('style');
    PyObject *str_const_34 = MAKE_STRING('lpfnWndProc');
    PyObject *str_const_35 = MAKE_STRING('cbClsExtra');
    PyObject *str_const_36 = MAKE_STRING('INT');
    PyObject *str_const_37 = MAKE_STRING('cbWndExtra');
    PyObject *str_const_38 = MAKE_STRING('hInstance');
    PyObject *str_const_39 = MAKE_STRING('HANDLE');
    PyObject *str_const_40 = MAKE_STRING('hCursor');
    PyObject *str_const_41 = MAKE_STRING('hbrBackground');
    PyObject *str_const_42 = MAKE_STRING('HBRUSH');
    PyObject *str_const_43 = MAKE_STRING('lpszMenuName');
    PyObject *str_const_44 = MAKE_STRING('lpszClassName');
    PyObject *str_const_45 = MAKE_STRING('hIconSm');
    PyObject *str_const_46 = MAKE_STRING('LPWNDCLASSEX');
    PyObject *str_const_47 = MAKE_STRING('user32');
    PyObject *str_const_48 = MAKE_STRING('CreatePopupMenu');
    PyObject *str_const_49 = MAKE_STRING('argtypes');
    PyObject *str_const_50 = MAKE_STRING('restype');
    PyObject *str_const_51 = MAKE_STRING('errcheck');
    PyObject *str_const_52 = MAKE_STRING('CreateWindowExW');
    PyObject *str_const_53 = MAKE_STRING('CreateWindowEx');
    PyObject *str_const_54 = MAKE_STRING('ATOM');
    PyObject *str_const_55 = MAKE_STRING('HINSTANCE');
    PyObject *str_const_56 = MAKE_STRING('DefWindowProcW');
    PyObject *str_const_57 = MAKE_STRING('DefWindowProc');
    PyObject *str_const_58 = MAKE_STRING('DestroyIcon');
    PyObject *str_const_59 = MAKE_STRING('BOOL');
    PyObject *str_const_60 = MAKE_STRING('DestroyMenu');
    PyObject *str_const_61 = MAKE_STRING('DestroyWindow');
    PyObject *str_const_62 = MAKE_STRING('DispatchMessageW');
    PyObject *str_const_63 = MAKE_STRING('DispatchMessage');
    PyObject *str_const_64 = MAKE_STRING('GetCursorPos');
    PyObject *str_const_65 = MAKE_STRING('GetMessageW');
    PyObject *str_const_66 = MAKE_STRING('GetMessage');
    PyObject *str_const_67 = MAKE_STRING('kernel32');
    PyObject *str_const_68 = MAKE_STRING('GetModuleHandleW');
    PyObject *str_const_69 = MAKE_STRING('GetModuleHandle');
    PyObject *str_const_70 = MAKE_STRING('HMODULE');
    PyObject *str_const_71 = MAKE_STRING('InsertMenuItemW');
    PyObject *str_const_72 = MAKE_STRING('InsertMenuItem');
    PyObject *str_const_73 = MAKE_STRING('LoadImageW');
    PyObject *str_const_74 = MAKE_STRING('LoadImage');
    PyObject *str_const_75 = MAKE_STRING('PeekMessageW');
    PyObject *str_const_76 = MAKE_STRING('PeekMessage');
    PyObject *str_const_77 = MAKE_STRING('PostMessageW');
    PyObject *str_const_78 = MAKE_STRING('PostMessage');
    PyObject *str_const_79 = MAKE_STRING('PostQuitMessage');
    PyObject *str_const_80 = MAKE_STRING('RegisterClassExW');
    PyObject *str_const_81 = MAKE_STRING('RegisterClassEx');
    PyObject *str_const_82 = MAKE_STRING('SetForegroundWindow');
    PyObject *str_const_83 = MAKE_STRING('shell32');
    PyObject *str_const_84 = MAKE_STRING('Shell_NotifyIconW');
    PyObject *str_const_85 = MAKE_STRING('Shell_NotifyIcon');
    PyObject *str_const_86 = MAKE_STRING('TranslateMessage');
    PyObject *str_const_87 = MAKE_STRING('TrackPopupMenuEx');
    PyObject *str_const_88 = MAKE_STRING('UnregisterClassW');
    PyObject *str_const_89 = MAKE_STRING('UnregisterClass');
    PyObject *str_const_90 = MAKE_STRING('RegisterWindowMessageW');
    PyObject *str_const_91 = MAKE_STRING('RegisterWindowMessage');
    PyObject *tuple_92 = MAKE_TUPLE("('TaskbarCreated',)");
    PyObject *str_const_93 = MAKE_STRING('WM_TASKBARCREATED');
    PyObject *str_const_94 = MAKE_STRING('ChangeWindowMessageFilterEx');
    PyObject *str_const_95 = MAKE_STRING('A dummy implementation of ``ChangeWindowMessageFilterEx`` always\n        returning ``TRUE``.\n\n      ');
    PyObject *str_const_96 = MAKE_STRING('pystray\\_util\\win32.py');
    PyObject *str_const_97 = MAKE_STRING('<module pystray._util.win32>');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
