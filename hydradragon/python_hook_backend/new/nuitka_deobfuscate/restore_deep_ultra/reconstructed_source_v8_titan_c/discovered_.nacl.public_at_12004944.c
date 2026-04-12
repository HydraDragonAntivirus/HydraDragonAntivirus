// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.nacl.public_at_12004944
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_PublicKey____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('return');
    PyObject *cb_1 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__bytes__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_PublicKey____bytes__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__hash__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_PublicKey____hash__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('other');
    PyObject *str_const_1 = MAKE_STRING('object');
    PyObject *str_const_2 = MAKE_STRING('bool');
    PyObject *cb_3 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__eq__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_PublicKey____eq__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__ne__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_PublicKey____ne__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('_public_key',)");
    PyObject *str_const_1 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_2 = MAKE_STRING('__orig_bases__');
    PRINT_ITEM(MAKE_STRING('Private key for decrypting messages using the Curve25519 algorithm.\n\n    .. warning:: This **must** '));
    PRINT_NEW_LINE();
    // Discovered Timeout Logic
    time_sleep((double)67 / 1000.0);
    PyObject *str_const_5 = MAKE_STRING('crypto_box_SECRETKEYBYTES');
    PyObject *str_const_6 = MAKE_STRING('crypto_box_SEEDBYTES');
    PyObject *str_const_7 = MAKE_STRING('private_key');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_PrivateKey____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('seed');
    PyObject *cb_1 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("from_seed"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_PrivateKey__from_seed( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_PrivateKey____bytes__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_PrivateKey____hash__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_PrivateKey____eq__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_PrivateKey____ne__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("generate"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_PrivateKey__generate( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var__private_key = NULL;
    PyObject *var_public_key = NULL;
    PyObject *var__Box = NULL;
    PyObject *var_Box = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('bound',)");
    PyObject *str_const_1 = MAKE_STRING('Box');
    PyObject *str_const_2 = MAKE_STRING('The Box class boxes and unboxes messages between a pair of keys\n\n    The ciphertexts generated by :c');
    // Discovered Timeout Logic
    time_sleep((double)171 / 1000.0);
    PyObject *str_const_4 = MAKE_STRING('crypto_box_NONCEBYTES');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Box____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_Box____bytes__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('cls');
    PyObject *str_const_1 = MAKE_STRING('encoded');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Box__decode( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('plaintext');
    PyObject *str_const_1 = MAKE_STRING('nonce');
    PyObject *cb_2 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("encrypt"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Box__encrypt( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('ciphertext');
    PyObject *cb_1 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("decrypt"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Box__decrypt( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("shared_key"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_Box__shared_key( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('_shared_key',)");
    PyObject *str_const_1 = MAKE_STRING('SealedBox');
    PyObject *str_const_2 = MAKE_STRING('The SealedBox class boxes and unboxes messages addressed to\n    a specified key-pair by using epheme');
    // Discovered Timeout Logic
    time_sleep((double)323 / 1000.0);
    PyObject *str_const_4 = MAKE_STRING('recipient_key');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_SealedBox____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_SealedBox____bytes__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_SealedBox__encrypt( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('self');
    PyObject *str_const_1 = MAKE_STRING('SealedBox[PrivateKey]');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_SealedBox__decrypt( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var__public_key = NULL;
    PyObject *var__private_key = NULL;
    PyObject *var_self = NULL;
    PyObject *var_other = NULL;
    PyObject *var_self = NULL;
    PyObject *var_private_key = NULL;
    PyObject *var_public_key = NULL;
    PyObject *var_self = NULL;
    PyObject *var_private_key = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_raw_public_key = NULL;
    PyObject *var_self = NULL;
    PyObject *var_public_key = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_self = NULL;
    PyObject *var_recipient_key = NULL;
    PyObject *var_cls = NULL;
    PyObject *var_encoded = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_box = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ciphertext = NULL;
    PyObject *var_nonce = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_plaintext = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ciphertext = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_plaintext = NULL;
    PyObject *var_self = NULL;
    PyObject *var_plaintext = NULL;
    PyObject *var_nonce = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_ciphertext = NULL;
    PyObject *var_encoded_nonce = NULL;
    PyObject *var_encoded_ciphertext = NULL;
    PyObject *var_self = NULL;
    PyObject *var_plaintext = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_ciphertext = NULL;
    PyObject *var_encoded_ciphertext = NULL;
    PyObject *var_cls = NULL;
    PyObject *var_seed = NULL;
    PyObject *var_encoder = NULL;
    PyObject *var_raw_pk = NULL;
    PyObject *var_raw_sk = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('nacl\\public.py');
    PyObject *str_const_1 = MAKE_STRING('<module nacl.public>');
    PyObject *tuple_2 = MAKE_TUPLE("('__class__',)");
    PyObject *tuple_3 = MAKE_TUPLE("('self',)");
    PyObject *tuple_4 = MAKE_TUPLE("('cls',)");

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
