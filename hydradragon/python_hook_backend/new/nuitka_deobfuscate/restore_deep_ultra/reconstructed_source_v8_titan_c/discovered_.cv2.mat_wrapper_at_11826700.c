// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.cv2.mat_wrapper_at_11826700
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_Mat____new__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_Mat____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__array_finalize__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Mat____array_finalize__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_self = NULL;
    PyObject *var_obj = NULL;
    PyObject *var_self = NULL;
    PyObject *var_arr = NULL;
    PyObject *var_kwargs = NULL;
    PyObject *var_cls = NULL;
    PyObject *var_arr = NULL;
    PyObject *var_kwargs = NULL;
    PyObject *var_obj = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('wrap_channels',)");
    PyObject *str_const_1 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_2 = MAKE_STRING('__orig_bases__');
    PyObject *str_const_3 = MAKE_STRING('cv2\\mat_wrapper\\__init__.py');
    PyObject *str_const_4 = MAKE_STRING('<module cv2.mat_wrapper>');
    PyObject *tuple_5 = MAKE_TUPLE("('__class__',)");

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
