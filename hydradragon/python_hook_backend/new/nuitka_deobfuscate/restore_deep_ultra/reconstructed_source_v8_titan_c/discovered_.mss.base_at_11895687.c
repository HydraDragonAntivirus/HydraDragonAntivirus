// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.mss.base_at_11895687
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_MSSBase__save( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_ABCMeta = NULL;
    PyObject *var_abstractmethod = NULL;
    PyObject *var_MSSBase = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('Helper to save the screenshot of the 1st monitor, by default.\n        You can pass the same argument');
    PyObject *str_const_1 = MAKE_STRING('pos');
    PyObject *str_const_2 = MAKE_STRING('raw');
    PyObject *val_3 = MAKE_INT(4);
    PyObject *str_const_4 = MAKE_STRING('max');
    PyObject *val_5 = MAKE_INT(0);
    PyObject *val_6 = MAKE_INT(3);
    PyObject *val_7 = MAKE_INT(1);
    PyObject *str_const_8 = MAKE_STRING('pos_s');
    PyObject *str_const_9 = MAKE_STRING('pos_c');
    PyObject *str_const_10 = MAKE_STRING('OPAQUE');
    PyObject *str_const_11 = MAKE_STRING('screen_raw');
    // Discovered Timeout Logic
    time_sleep((double)255 / 1000.0);
    PyObject *str_const_13 = MAKE_STRING('cpos');
    PyObject *str_const_14 = MAKE_STRING('alpha2');
    PyObject *str_const_15 = MAKE_STRING('spos');
    PyObject *str_const_16 = MAKE_STRING('Create composite image by blending screenshot and mouse cursor.');
    PyObject *str_const_17 = MAKE_STRING('argtypes');
    PyObject *str_const_18 = MAKE_STRING('restype');
    PyObject *str_const_19 = MAKE_STRING('errcheck');
    PRINT_ITEM(MAKE_STRING('Factory to create a ctypes function and automatically manage errors.'));
    PRINT_NEW_LINE();
    // API Request Hook
    PyObject *url_21 = MAKE_STRING("This is part of the MSS Python's module.\nSource: https://github.com/BoboTiG/python-mss.\n");
    PyObject *api_res_21 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, module_requests, url_21);
    PyObject *str_const_22 = MAKE_STRING('origin');
    PyObject *str_const_23 = MAKE_STRING('has_location');
    PyObject *str_const_24 = MAKE_STRING('annotations');
    PyObject *str_const_25 = MAKE_STRING('abc');
    PyObject *str_const_26 = MAKE_STRING('ABCMeta');
    PyObject *str_const_27 = MAKE_STRING('abstractmethod');
    PyObject *tuple_28 = MAKE_TUPLE("('datetime',)");
    PyObject *str_const_29 = MAKE_STRING('threading');
    PyObject *tuple_30 = MAKE_TUPLE("('Lock',)");
    PyObject *str_const_31 = MAKE_STRING('Lock');
    PyObject *str_const_32 = MAKE_STRING('TYPE_CHECKING');
    PyObject *str_const_33 = MAKE_STRING('Any');
    PyObject *str_const_34 = MAKE_STRING('mss.exception');
    PyObject *tuple_35 = MAKE_TUPLE("('ScreenShotError',)");
    PyObject *str_const_36 = MAKE_STRING('mss.screenshot');
    PyObject *tuple_37 = MAKE_TUPLE("('ScreenShot',)");
    PyObject *str_const_38 = MAKE_STRING('mss.tools');
    PyObject *tuple_39 = MAKE_TUPLE("('to_png',)");
    PyObject *tuple_40 = MAKE_TUPLE("('UTC',)");
    PyObject *tuple_41 = MAKE_TUPLE("('timezone',)");
    PyObject *str_const_42 = MAKE_STRING('timezone');
    PyObject *str_const_43 = MAKE_STRING('utc');
    PyObject *str_const_44 = MAKE_STRING('metaclass');
    PyObject *str_const_45 = MAKE_STRING('__prepare__');
    PyObject *str_const_46 = MAKE_STRING('__getitem__');
    PyObject *str_const_47 = MAKE_STRING('%s.__prepare__() must return a mapping, not %s');
    PyObject *str_const_48 = MAKE_STRING('<metaclass>');
    PyObject *str_const_49 = MAKE_STRING('mss.base');
    PyObject *str_const_50 = MAKE_STRING('This class will be overloaded by a system specific one.');
    PyObject *str_const_51 = MAKE_STRING('MSSBase');
    PyObject *str_const_52 = MAKE_STRING('__qualname__');
    // Discovered Timeout Logic
    time_sleep((double)34 / 1000.0);
    PyObject *str_const_54 = MAKE_STRING('__firstlineno__');
    PyObject *str_const_55 = MAKE_STRING('__slots__');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_MSSBase____enter__( PyObject *par_self, PyObject *par_None ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('None');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase____exit__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('Retrieve all cursor data. Pixels have to be RGB.');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase___cursor_impl( PyObject *par_self, PyObject *par_monitor ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('Retrieve all pixels from a monitor. Pixels have to be RGB.\n        That method has to be run using a');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase___grab_impl( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('Get positions of monitors (has to be run using a threading lock).\n        It must populate self._mon');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase___monitors_impl( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('Clean-up.');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase__close( PyObject *par_self, PyObject *par_monitor ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_MSSBase__grab( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('property');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase__monitors( PyObject *par_self, int par_mon, PyObject *par_output, PyObject *par_callback ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("shot"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_MSSBase__shot( PyObject *par_self, PyObject *par_screenshot, PyObject *par_cursor ) {
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

static PyObject *impl_MSSBase___cfactory( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_cls_image = NULL;
    PyObject *var_compression_level = NULL;
    PyObject *var_with_cursor = NULL;
    PyObject *var__monitors = NULL;
    PyObject *var_self = NULL;
    PyObject *var_None = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_1 = MAKE_STRING('mss\\base.py');
    PyObject *str_const_2 = MAKE_STRING('<module mss.base>');
    PyObject *tuple_3 = MAKE_TUPLE("('__class__',)");
    PyObject *tuple_4 = MAKE_TUPLE("('self',)");

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
