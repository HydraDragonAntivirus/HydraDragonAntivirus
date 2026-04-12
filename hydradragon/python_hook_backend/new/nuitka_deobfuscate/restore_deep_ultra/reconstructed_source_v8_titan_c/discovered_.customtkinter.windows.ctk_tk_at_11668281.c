// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.customtkinter.windows.ctk_tk_at_11668281
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_CustomTkinter_icon_Windows__ico( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_pop_from_dict_by_set = NULL;
    PyObject *var_check_kwargs_empty = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('state');
    PyObject *str_const_1 = MAKE_STRING('iconic');
    PyObject *str_const_2 = MAKE_STRING('withdrawn');
    PyObject *str_const_3 = MAKE_STRING('focus_get');
    PyObject *str_const_4 = MAKE_STRING('dark');
    PyObject *str_const_5 = MAKE_STRING('light');
    PyObject *str_const_6 = MAKE_STRING('windll');
    PyObject *str_const_7 = MAKE_STRING('user32');
    PyObject *str_const_8 = MAKE_STRING('GetParent');
    PyObject *str_const_9 = MAKE_STRING('winfo_id');
    PyObject *str_const_10 = MAKE_STRING('dwmapi');
    PyObject *str_const_11 = MAKE_STRING('DwmSetWindowAttribute');
    // Discovered Timeout Logic
    time_sleep((double)20 / 1000.0);
    PyObject *str_const_13 = MAKE_STRING('byref');
    PyObject *str_const_14 = MAKE_STRING('c_int');
    PyObject *str_const_15 = MAKE_STRING('sizeof');
    // Discovered Timeout Logic
    time_sleep((double)19 / 1000.0);
    PyObject *str_const_17 = MAKE_STRING('normal');
    PyObject *str_const_18 = MAKE_STRING('zoomed');
    PyObject *tuple_19 = MAKE_TUPLE("('zoomed',)");
    PyObject *str_const_20 = MAKE_STRING('focus');
    // API Request Hook
    PyObject *url_21 = MAKE_STRING('Set the titlebar color of the window to light or dark theme on Microsoft Windows.\n\n        Credits for this function:\n        https://stackoverflow.com/questions/23836000/can-i-change-the-title-bar-in-tkinter/70724666#70724666\n\n        MORE INFO:\n        https://docs.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute\n        ');
    PyObject *api_res_21 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, module_requests, url_21);
    PyObject *str_const_22 = MAKE_STRING('origin');
    PyObject *str_const_23 = MAKE_STRING('has_location');
    PyObject *str_const_24 = MAKE_STRING('sys');
    PyObject *str_const_25 = MAKE_STRING('platform');
    PyObject *str_const_26 = MAKE_STRING('ctypes');
    PyObject *str_const_27 = MAKE_STRING('Union');
    PyObject *str_const_28 = MAKE_STRING('Tuple');
    PyObject *str_const_29 = MAKE_STRING('Optional');
    PyObject *str_const_30 = MAKE_STRING('packaging');
    PyObject *tuple_31 = MAKE_TUPLE("('version',)");
    PyObject *str_const_32 = MAKE_STRING('version');
    PyObject *str_const_33 = MAKE_STRING('widgets.theme');
    PyObject *tuple_34 = MAKE_TUPLE("('ThemeManager',)");
    PyObject *str_const_35 = MAKE_STRING('widgets.scaling');
    PyObject *tuple_36 = MAKE_TUPLE("('CTkScalingBaseClass',)");
    PyObject *str_const_37 = MAKE_STRING('widgets.appearance_mode');
    PyObject *tuple_38 = MAKE_TUPLE("('CTkAppearanceModeBaseClass',)");
    PyObject *str_const_39 = MAKE_STRING('customtkinter.windows.widgets.utility.utility_functions');
    PyObject *str_const_40 = MAKE_STRING('__prepare__');
    PyObject *str_const_41 = MAKE_STRING('__getitem__');
    PyObject *str_const_42 = MAKE_STRING('%s.__prepare__() must return a mapping, not %s');
    PyObject *str_const_43 = MAKE_STRING('<metaclass>');
    PyObject *str_const_44 = MAKE_STRING('customtkinter.windows.ctk_tk');
    PyObject *str_const_45 = MAKE_STRING('Main app window with dark titlebar on Windows and macOS.\n    For detailed information check out the ');
    PyObject *str_const_46 = MAKE_STRING('__qualname__');
    // Discovered Timeout Logic
    time_sleep((double)18 / 1000.0);
    PyObject *str_const_48 = MAKE_STRING('__firstlineno__');
    PyObject *str_const_49 = MAKE_STRING('set');
    PyObject *str_const_50 = MAKE_STRING('bool');
    PyObject *tuple_51 = MAKE_TUPLE("('None',)");
    PyObject *str_const_52 = MAKE_STRING('str');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTk____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__destroy( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk___focus_in_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk___update_dimensions_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk___set_scaling( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("block_update_dimensions_event"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTk__block_update_dimensions_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("unblock_update_dimensions_event"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTk__unblock_update_dimensions_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk___set_scaled_min_max( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__withdraw( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__iconify( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__update( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__mainloop( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;

    // Empty block
}

static PyObject *impl_CTk__resizable( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__minsize( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__maxsize( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('geometry_string');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTk__geometry( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__configure( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('attribute_name');
    PyObject *str_const_1 = MAKE_STRING('return');
    PyObject *str_const_2 = MAKE_STRING('any');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTk__cget( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__wm_iconbitmap( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk__iconbitmap( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk___windows_set_titlebar_icon( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk___enable_macos_dark_title_bar( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTk___disable_macos_dark_title_bar( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('color_mode');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTk___windows_set_titlebar_color( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('mode_string');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTk___set_appearance_mode( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var__current_width = NULL;
    PyObject *var__current_height = NULL;
    PyObject *var__min_width = NULL;
    PyObject *var__min_height = NULL;
    PyObject *var__max_width = NULL;
    PyObject *var__max_height = NULL;
    PyObject *var__last_resizable_args = NULL;
    PyObject *var__fg_color = NULL;
    PyObject *var__iconbitmap_method_called = NULL;
    PyObject *var__state_before_windows_set_titlebar_color = NULL;
    PyObject *var__window_exists = NULL;
    PyObject *var__withdraw_called_before_window_exists = NULL;
    PyObject *var__iconify_called_before_window_exists = NULL;
    PyObject *var__block_update_dimensions_event = NULL;
    PyObject *var_focused_widget_before_widthdraw = NULL;
    PyObject *var_self = NULL;
    PyObject *var_fg_color = NULL;
    PyObject *var_kwargs = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_event = NULL;
    PyObject *var_self = NULL;
    PyObject *var_mode_string = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_new_widget_scaling = NULL;
    PyObject *var_new_window_scaling = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_event = NULL;
    PyObject *var_detected_width = NULL;
    PyObject *var_detected_height = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_color_mode = NULL;
    PyObject *var_value = NULL;
    PyObject *var_hwnd = NULL;
    PyObject *var_DWMWA_USE_IMMERSIVE_DARK_MODE = NULL;
    PyObject *var_DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = NULL;
    PyObject *var_err = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_customtkinter_directory = NULL;
    PyObject *var_self = NULL;
    PyObject *var_attribute_name = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_kwargs = NULL;
    PyObject *var_child = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_geometry_string = NULL;
    PyObject *var_width = NULL;
    PyObject *var_height = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_self = NULL;
    PyObject *var_bitmap = NULL;
    PyObject *var_default = NULL;
    PyObject *var___class__ = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_1 = MAKE_STRING('__orig_bases__');
    PyObject *str_const_2 = MAKE_STRING('customtkinter\\windows\\ctk_tk.py');
    PyObject *str_const_3 = MAKE_STRING('<module customtkinter.windows.ctk_tk>');
    PyObject *tuple_4 = MAKE_TUPLE("('__class__',)");
    PyObject *tuple_5 = MAKE_TUPLE("('cls',)");
    PyObject *tuple_6 = MAKE_TUPLE("('self',)");
    PyObject *str_const_7 = MAKE_STRING('__class__');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
