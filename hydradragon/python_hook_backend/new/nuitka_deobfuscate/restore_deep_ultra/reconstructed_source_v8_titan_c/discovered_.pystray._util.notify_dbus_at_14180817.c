// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.pystray._util.notify_dbus_at_14180817
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_Notifier____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("notify"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Notifier__notify( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("hide"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Notifier__hide( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var__connection = NULL;
    PyObject *var__notify = NULL;
    PyObject *var__nid = NULL;
    PyObject *var__icon = NULL;
    PyObject *var_self = NULL;
    PyObject *var_icon_path = NULL;
    PyObject *var_cleanup = NULL;
    PyObject *var_self = NULL;
    PyObject *var_title = NULL;
    PyObject *var_message = NULL;
    PyObject *var_icon = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_1 = MAKE_STRING('__orig_bases__');
    PyObject *str_const_2 = MAKE_STRING('pystray\\_util\\notify_dbus.py');
    PyObject *str_const_3 = MAKE_STRING('<module pystray._util.notify_dbus>');
    PyObject *tuple_4 = MAKE_TUPLE("('__class__',)");
    PyObject *tuple_5 = MAKE_TUPLE("('icon_path',)");
    PyObject *tuple_6 = MAKE_TUPLE("('self',)");

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
