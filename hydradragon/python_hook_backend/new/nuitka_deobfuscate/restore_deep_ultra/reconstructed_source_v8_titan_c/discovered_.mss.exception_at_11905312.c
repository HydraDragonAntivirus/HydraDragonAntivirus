// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.mss.exception_at_11905312
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_ScreenShotError____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('details',)");
    PyObject *str_const_1 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_2 = MAKE_STRING('__orig_bases__');
    PyObject *str_const_3 = MAKE_STRING('mss\\exception.py');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
