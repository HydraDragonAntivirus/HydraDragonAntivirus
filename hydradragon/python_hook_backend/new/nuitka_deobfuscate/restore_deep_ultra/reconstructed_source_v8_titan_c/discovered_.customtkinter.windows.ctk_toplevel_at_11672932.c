// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.customtkinter.windows.ctk_toplevel_at_11672932
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
    PyObject *str_const_0 = MAKE_STRING('tkinter');
    PyObject *str_const_1 = MAKE_STRING('Toplevel');
    PyObject *str_const_2 = MAKE_STRING('destroy');
    PyObject *str_const_3 = MAKE_STRING('winfo_width');
    PyObject *str_const_4 = MAKE_STRING('winfo_height');
    PyObject *str_const_5 = MAKE_STRING('minsize');
    PyObject *str_const_6 = MAKE_STRING('maxsize');
    PyObject *str_const_7 = MAKE_STRING('geometry');
    // Discovered Timeout Logic
    time_sleep((double)1000 / 1000.0);
    PyObject *str_const_9 = MAKE_STRING('max');
    PyObject *str_const_10 = MAKE_STRING('min');
    PyObject *str_const_11 = MAKE_STRING('withdraw');
    PyObject *str_const_12 = MAKE_STRING('iconify');
    PyObject *str_const_13 = MAKE_STRING('resizable');
    PyObject *str_const_14 = MAKE_STRING('width');
    PyObject *str_const_15 = MAKE_STRING('height');
    PyObject *val_16 = MAKE_INT(10);
    PyObject *str_const_17 = MAKE_STRING('CTkToplevel.resizable.<locals>.<lambda>');
    PyObject *str_const_18 = MAKE_STRING('winfo_children');
    PyObject *tuple_19 = MAKE_TUPLE("('bg_color',)");
    PyObject *str_const_20 = MAKE_STRING('cget');
    PyObject *str_const_21 = MAKE_STRING('wm_iconbitmap');
    PyObject *str_const_22 = MAKE_STRING('state');
    PyObject *str_const_23 = MAKE_STRING('focus_get');
    PyObject *str_const_24 = MAKE_STRING('update');
    PyObject *str_const_25 = MAKE_STRING('dark');
    PyObject *str_const_26 = MAKE_STRING('light');
    PyObject *str_const_27 = MAKE_STRING('windll');
    PyObject *str_const_28 = MAKE_STRING('user32');
    PyObject *str_const_29 = MAKE_STRING('GetParent');
    PyObject *str_const_30 = MAKE_STRING('winfo_id');
    PyObject *str_const_31 = MAKE_STRING('dwmapi');
    PyObject *str_const_32 = MAKE_STRING('DwmSetWindowAttribute');
    // Discovered Timeout Logic
    time_sleep((double)20 / 1000.0);
    PyObject *str_const_34 = MAKE_STRING('byref');
    PyObject *str_const_35 = MAKE_STRING('c_int');
    PyObject *str_const_36 = MAKE_STRING('sizeof');
    // Discovered Timeout Logic
    time_sleep((double)19 / 1000.0);
    PyObject *val_38 = MAKE_INT(5);
    PyObject *str_const_39 = MAKE_STRING('focus');
    // API Request Hook
    PyObject *url_40 = MAKE_STRING('Set the titlebar color of the window to light or dark theme on Microsoft Windows.\n\n        Credits for this function:\n        https://stackoverflow.com/questions/23836000/can-i-change-the-title-bar-in-tkinter/70724666#70724666\n\n        MORE INFO:\n        https://docs.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute\n        ');
    PyObject *api_res_40 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, module_requests, url_40);
    PyObject *str_const_41 = MAKE_STRING('normal');
    PyObject *str_const_42 = MAKE_STRING('deiconify');
    PyObject *str_const_43 = MAKE_STRING('iconic');
    PyObject *str_const_44 = MAKE_STRING('zoomed');
    PyObject *tuple_45 = MAKE_TUPLE("('zoomed',)");
    PyObject *str_const_46 = MAKE_STRING('if in a short time (5ms) after ');
    PyObject *str_const_47 = MAKE_STRING('origin');
    PyObject *str_const_48 = MAKE_STRING('has_location');
    PyObject *str_const_49 = MAKE_STRING('packaging');
    PyObject *tuple_50 = MAKE_TUPLE("('version',)");
    PyObject *str_const_51 = MAKE_STRING('version');
    PyObject *str_const_52 = MAKE_STRING('sys');
    PyObject *str_const_53 = MAKE_STRING('platform');
    PyObject *str_const_54 = MAKE_STRING('ctypes');
    PyObject *str_const_55 = MAKE_STRING('Union');
    PyObject *str_const_56 = MAKE_STRING('Tuple');
    PyObject *str_const_57 = MAKE_STRING('Optional');
    PyObject *str_const_58 = MAKE_STRING('widgets.theme');
    PyObject *tuple_59 = MAKE_TUPLE("('ThemeManager',)");
    PyObject *str_const_60 = MAKE_STRING('widgets.scaling');
    PyObject *tuple_61 = MAKE_TUPLE("('CTkScalingBaseClass',)");
    PyObject *str_const_62 = MAKE_STRING('widgets.appearance_mode');
    PyObject *tuple_63 = MAKE_TUPLE("('CTkAppearanceModeBaseClass',)");
    PyObject *str_const_64 = MAKE_STRING('customtkinter.windows.widgets.utility.utility_functions');
    PyObject *str_const_65 = MAKE_STRING('__prepare__');
    PyObject *str_const_66 = MAKE_STRING('__getitem__');
    PyObject *str_const_67 = MAKE_STRING('%s.__prepare__() must return a mapping, not %s');
    PyObject *str_const_68 = MAKE_STRING('<metaclass>');
    PyObject *str_const_69 = MAKE_STRING('customtkinter.windows.ctk_toplevel');
    PyObject *str_const_70 = MAKE_STRING('Toplevel window with dark titlebar on Windows and macOS.\n    For detailed information check out the ');
    PyObject *str_const_71 = MAKE_STRING('__qualname__');
    // Discovered Timeout Logic
    time_sleep((double)16 / 1000.0);
    PyObject *str_const_73 = MAKE_STRING('__firstlineno__');
    PyObject *str_const_74 = MAKE_STRING('set');
    PyObject *str_const_75 = MAKE_STRING('bool');
    PyObject *str_const_76 = MAKE_STRING('str');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTkToplevel____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel__destroy( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___focus_in_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('None',)");

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_CTkToplevel___update_dimensions_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___set_scaling( PyObject *par_self ) {
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

static PyObject *impl_CTkToplevel__block_update_dimensions_event( PyObject *par_self ) {
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

static PyObject *impl_CTkToplevel__unblock_update_dimensions_event( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___set_scaled_min_max( PyObject *par_self ) {
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

static PyObject *impl_CTkToplevel__geometry( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel__withdraw( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel__iconify( PyObject *par_self ) {
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

static PyObject *impl_CTkToplevel__resizable( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel__minsize( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel__maxsize( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel__configure( PyObject *par_self ) {
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

static PyObject *impl_CTkToplevel__cget( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel__wm_iconbitmap( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___windows_set_titlebar_icon( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___enable_macos_dark_title_bar( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___disable_macos_dark_title_bar( PyObject *par_self ) {
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

static PyObject *impl_CTkToplevel___windows_set_titlebar_color( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___revert_withdraw_after_windows_set_titlebar_color( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_CTkToplevel___set_appearance_mode( PyObject *par_self ) {
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
    PyObject *var__windows_set_titlebar_color_called = NULL;
    PyObject *var__withdraw_called_after_windows_set_titlebar_color = NULL;
    PyObject *var__iconify_called_after_windows_set_titlebar_color = NULL;
    PyObject *var__block_update_dimensions_event = NULL;
    PyObject *var_focused_widget_before_widthdraw = NULL;
    PyObject *var_self = NULL;
    PyObject *var_customtkinter_directory = NULL;
    PyObject *var_customtkinter_directory = NULL;
    PyObject *var_self = NULL;
    PyObject *var_self = NULL;
    PyObject *var_fg_color = NULL;
    PyObject *var_args = NULL;
    PyObject *var_kwargs = NULL;
    PyObject *var_customtkinter_directory = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_event = NULL;
    PyObject *var_self = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_mode_string = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_new_widget_scaling = NULL;
    PyObject *var_new_window_scaling = NULL;
    PyObject *var___class__ = NULL;
    PyObject *var_self = NULL;
    PyObject *var_event = NULL;
    PyObject *var_detected_width = NULL;
    PyObject *var_detected_height = NULL;
    PyObject *var_self = NULL;
    PyObject *var_color_mode = NULL;
    PyObject *var_value = NULL;
    PyObject *var_hwnd = NULL;
    PyObject *var_DWMWA_USE_IMMERSIVE_DARK_MODE = NULL;
    PyObject *var_DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = NULL;
    PyObject *var_err = NULL;
    PyObject *var___class__ = NULL;
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

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_1 = MAKE_STRING('__orig_bases__');
    PyObject *str_const_2 = MAKE_STRING('customtkinter\\windows\\ctk_toplevel.py');
    PyObject *tuple_3 = MAKE_TUPLE("('self',)");
    PyObject *str_const_4 = MAKE_STRING('<module customtkinter.windows.ctk_toplevel>');
    PyObject *tuple_5 = MAKE_TUPLE("('__class__',)");
    PyObject *tuple_6 = MAKE_TUPLE("('cls',)");
    PyObject *str_const_7 = MAKE_STRING('__class__');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
