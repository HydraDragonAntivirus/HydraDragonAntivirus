/*
 * nuitka_shim.h
 *
 * Drop-in replacement for "nuitka/prelude.h" so that the vendored
 * Nuitka HelpersConstantsBlob.c (here: blob_decode.c) compiles and
 * runs unmodified against vanilla CPython 3.12.
 *
 * Force-included via -include in setup.py BEFORE blob_decode.c is
 * processed. blob_decode.c only #includes "nuitka/prelude.h" inside
 * `#ifdef __IDE_ONLY__` (which we never define), so the real Nuitka
 * prelude is never pulled in.
 */

#ifndef NUITKA_BLOB_LOADER_SHIM_H
#define NUITKA_BLOB_LOADER_SHIM_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/*  Target CPython version. Override with -DPYTHON_VERSION=0xNNN.     */
/*  0x3c0 = CPython 3.12.                                             */
/* ------------------------------------------------------------------ */
#ifndef PYTHON_VERSION
#  define PYTHON_VERSION 0x3c0
#endif

#ifndef _NUITKA_EXE_MODE
#  define _NUITKA_EXE_MODE 0
#endif

/* We do NOT define any of:
 *   _NUITKA_CONSTANTS_FROM_LINKER
 *   _NUITKA_CONSTANTS_FROM_COFF_OBJ
 *   _NUITKA_CONSTANTS_FROM_INCBIN
 *   _NUITKA_CONSTANTS_FROM_RESOURCE
 *   _NUITKA_CONSTANTS_FROM_MACOS_SECTION
 *   _NUITKA_CONSTANTS_FROM_CODE
 *
 * That puts blob_decode.c in the "fall-through" branch where
 * `unsigned char const *constant_bin = NULL;` is declared with
 * external linkage, and loadConstantsBlob() simply uses whatever
 * value `constant_bin` already holds. The Python extension code
 * (module.c) sets that pointer before calling loadConstantsBlob().
 */

/* ------------------------------------------------------------------ */
/*  Branch hints                                                      */
/* ------------------------------------------------------------------ */
#ifndef likely
#  if defined(__GNUC__) || defined(__clang__)
#    define likely(x)   __builtin_expect(!!(x), 1)
#    define unlikely(x) __builtin_expect(!!(x), 0)
#  else
#    define likely(x)   (x)
#    define unlikely(x) (x)
#  endif
#endif

/* ------------------------------------------------------------------ */
/*  Misc Nuitka attribute / array helpers                             */
/* ------------------------------------------------------------------ */
#define NUITKA_MAY_BE_UNUSED                  /* nothing */
#ifdef _MSC_VER
#  include <malloc.h>
#  define NUITKA_DYNAMIC_ARRAY_DECL(name, type, size) type *name = (type *)_alloca((size) * sizeof(type))
#else
#  define NUITKA_DYNAMIC_ARRAY_DECL(name, type, size) type name[size]
#endif

#define NUITKA_PRINT_TIMING(msg)              ((void)0)

#define NUITKA_CANNOT_GET_HERE(msg)                                       \
    do {                                                                  \
        fprintf(stderr,                                                   \
                "[nuitka_blob_loader] CANNOT_GET_HERE at %s:%d: %s\n",    \
                __FILE__, __LINE__, (msg));                               \
        abort();                                                          \
    } while (0)

#define PRINT_STRING(s)        fputs((s), stderr)
#define PRINT_FORMAT(fmt, ...) fprintf(stderr, (fmt), __VA_ARGS__)

/* CHECK_OBJECT is a Nuitka debug-build sanity check. No-op here. */
#define CHECK_OBJECT(x) ((void)(x))

/* Nuitka treats constants as immortal. CPython 3.12 has real
   immortal objects but no public macro to mark one. We just take
   normal refs / no-op the SET_REFCNT, which is safe (the objects
   simply behave as ordinary refcounted objects in our process). */
#ifndef Py_INCREF_IMMORTAL
#  define Py_INCREF_IMMORTAL(op) Py_INCREF(op)
#endif
#ifndef Py_SET_REFCNT_IMMORTAL
#  define Py_SET_REFCNT_IMMORTAL(op) ((void)(op))
#endif

/* ------------------------------------------------------------------ */
/*  Nuitka long / bytes / unicode helpers -> plain CPython API        */
/* ------------------------------------------------------------------ */
#define Nuitka_LongFromCLong(v)               PyLong_FromLong((long)(v))
#define Nuitka_PyLong_FromLong(v)             PyLong_FromLong((long)(v))
#define Nuitka_Bytes_FromStringAndSize(s, n)  PyBytes_FromStringAndSize((s), (n))

/* CPython small-int singleton range. Used by blob_decode.c only as a
   gate to skip the long_cache for values that are already singletons. */
#ifndef NUITKA_STATIC_SMALLINT_VALUE_MIN
#  define NUITKA_STATIC_SMALLINT_VALUE_MIN (-5)
#endif
#ifndef NUITKA_STATIC_SMALLINT_VALUE_MAX
#  define NUITKA_STATIC_SMALLINT_VALUE_MAX (257)
#endif
#ifndef NUITKA_TO_SMALL_VALUE_OFFSET
#  define NUITKA_TO_SMALL_VALUE_OFFSET(i) ((i) - NUITKA_STATIC_SMALLINT_VALUE_MIN)
#endif

/* Nuitka helpers that don't exist in vanilla CPython. We map each to
   its plain-CPython equivalent. The `tstate` argument is ignored. */
static inline PyObject *_nbl_call_single(PyThreadState *tstate,
                                         PyObject *callable, PyObject *arg) {
    (void)tstate;
    PyObject *args = PyTuple_Pack(1, arg);
    if (!args) return NULL;
    PyObject *r = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);
    return r;
}
#define CALL_FUNCTION_WITH_SINGLE_ARG(tstate, callable, arg) \
    _nbl_call_single((tstate), (callable), (arg))

static inline PyObject *_nbl_complex2(PyThreadState *tstate,
                                      PyObject *re, PyObject *im) {
    (void)tstate;
    double r = PyFloat_AsDouble(re); if (r == -1.0 && PyErr_Occurred()) return NULL;
    double i = PyFloat_AsDouble(im); if (i == -1.0 && PyErr_Occurred()) return NULL;
    return PyComplex_FromDoubles(r, i);
}
#define BUILTIN_COMPLEX2(tstate, re, im) _nbl_complex2((tstate), (re), (im))

static inline PyObject *_nbl_slice3(PyThreadState *tstate,
                                    PyObject *a, PyObject *b, PyObject *c) {
    (void)tstate;
    return PySlice_New(a, b, c);
}
#define MAKE_SLICE_OBJECT3(tstate, a, b, c) _nbl_slice3((tstate), (a), (b), (c))

static inline PyObject *_nbl_range3(PyThreadState *tstate,
                                    PyObject *a, PyObject *b, PyObject *c) {
    (void)tstate;
    PyObject *builtins = PyEval_GetBuiltins();  /* borrowed dict */
    if (!builtins) return NULL;
    PyObject *range_cls = PyDict_GetItemString(builtins, "range"); /* borrowed */
    if (!range_cls) return NULL;
    PyObject *args = PyTuple_Pack(3, a, b, c);
    if (!args) return NULL;
    PyObject *r = PyObject_Call(range_cls, args, NULL);
    Py_DECREF(args);
    return r;
}
#define BUILTIN_XRANGE3(tstate, a, b, c) _nbl_range3((tstate), (a), (b), (c))

/* Nuitka uses PyFloat_SET_DOUBLE to mutate the double value of an
   existing PyFloat in place (for the special-float singletons that
   need a sign flip via copysign). CPython exposes the struct layout
   in cpython/floatobject.h, so we can do the same thing inline. */
#ifndef PyFloat_SET_DOUBLE
#  define PyFloat_SET_DOUBLE(op, v) (((PyFloatObject *)(op))->ob_fval = (v))
#endif

/* Flip the sign of a PyLong in-place. CPython has no public API for
   this, so we do (result = -result) by replacing the pointer. The
   call sites in blob_decode.c follow the pattern:
       PyObject *result = ... build positive bigint ...;
       Nuitka_LongSetSignNegative(result);
   We can't truly mutate, so we substitute with PyNumber_Negative
   and Py_SETREF the local. Achieving that needs a wrapping macro
   that takes the lvalue. The single call site is line 724 where
   `result` is a local PyObject*. */
#define Nuitka_LongSetSignNegative(result_lv)                             \
    do {                                                                  \
        PyObject *_neg = PyNumber_Negative(result_lv);                    \
        Py_DECREF(result_lv);                                             \
        (result_lv) = _neg;                                               \
    } while (0)

/* Nuitka_PyUnicode_CheckConsistency is only used inside an assert()
   block guarded on PYTHON_VERSION < 0x3e0 && >= 0x3c0. For 3.12 it
   IS reached. CPython has _PyUnicode_CheckConsistency in the private
   header. We provide a stub that always returns 1. */
static inline int Nuitka_PyUnicode_CheckConsistency(PyObject *op, int check_content) {
    (void)op;
    (void)check_content;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Dict iteration                                                    */
/* ------------------------------------------------------------------ */
static inline int Nuitka_DictNext(PyObject *dict, Py_ssize_t *pos,
                                  PyObject **key, PyObject **value) {
    return PyDict_Next(dict, pos, key, value);
}

/* ------------------------------------------------------------------ */
/*  Globals blob_decode.c references                                   */
/*                                                                    */
/*    builtin_module        - the __builtin__ / builtins module       */
/*    Py_SysVersionInfo     - sys.version_info                        */
/*    Nuitka_PyUnion_Type   - typing-style Union type (3.10+)         */
/*                                                                    */
/*  We declare them extern here and define+initialize them in         */
/*  module.c before any constant unpacking happens.                   */
/* ------------------------------------------------------------------ */
extern PyObject *builtin_module;
extern PyObject *Py_SysVersionInfo;

#if PYTHON_VERSION >= 0x3a0
extern PyTypeObject *Nuitka_PyUnion_Type;
#endif

/* ------------------------------------------------------------------ */
/*  MAKE_UNION_TYPE                                                   */
/*                                                                    */
/*  Nuitka builds a `int | str` UnionType from a tuple of args.       */
/*  CPython exposes _PyUnion_FromArgs(args) only as a private symbol  */
/*  in 3.10+. Public route: types.UnionType(*args) -- but that does   */
/*  not exist as a constructor. The simplest portable thing is to    */
/*  build it via __or__: reduce(operator.or_, args).                  */
/* ------------------------------------------------------------------ */
#if PYTHON_VERSION >= 0x3a0
static inline PyObject *MAKE_UNION_TYPE(PyObject *args_tuple) {
    Py_ssize_t n = PyTuple_GET_SIZE(args_tuple);
    if (n == 0) {
        PyErr_SetString(PyExc_ValueError, "empty union args");
        return NULL;
    }
    PyObject *acc = PyTuple_GET_ITEM(args_tuple, 0);
    Py_INCREF(acc);
    for (Py_ssize_t i = 1; i < n; i++) {
        PyObject *next = PyTuple_GET_ITEM(args_tuple, i);
        PyObject *combined = PyNumber_Or(acc, next);
        Py_DECREF(acc);
        if (combined == NULL) {
            return NULL;
        }
        acc = combined;
    }
    return acc;
}
#endif

/* ------------------------------------------------------------------ */
/*  MAKE_CODE_OBJECT                                                  */
/*                                                                    */
/*  Nuitka rebuilds a stub code object that holds *no actual          */
/*  bytecode* (the bytecode lives elsewhere -- here, in 'X' blobs).   */
/*  Its only purpose in the constants table is to provide function    */
/*  metadata: name, qualname, argument names, free vars, flags.       */
/*                                                                    */
/*  CPython 3.12: PyCode_NewWithPosOnlyArgs() exists and is the       */
/*  blessed constructor. We feed it almost-empty bytecode (a single   */
/*  RESUME / RETURN_CONST None pair) just so the validator is happy. */
/*                                                                    */
/*  Signature in blob_decode.c (line ~1290):                           */
/*    MAKE_CODE_OBJECT(filename=Py_None,                              */
/*                     line_number,                                   */
/*                     co_flags,                                      */
/*                     function_name,                                 */
/*                     function_qualname,                             */
/*                     arg_names,           // tuple of str           */
/*                     free_vars,           // tuple or NULL          */
/*                     arg_count,                                     */
/*                     kw_only_count,                                 */
/*                     pos_only_count)                                */
/* ------------------------------------------------------------------ */
PyObject *nuitka_blob_loader_make_code_object(PyObject *filename,
                                              int line_number,
                                              int co_flags,
                                              PyObject *function_name,
                                              PyObject *function_qualname,
                                              PyObject *arg_names,
                                              PyObject *free_vars,
                                              int arg_count,
                                              int kw_only_count,
                                              int pos_only_count);

#define MAKE_CODE_OBJECT(filename, lineno, flags, name, qualname,         \
                         argnames, freevars, argc, kwonly, posonly)       \
    nuitka_blob_loader_make_code_object((filename), (lineno), (flags),    \
                                        (name), (qualname), (argnames),   \
                                        (freevars), (argc), (kwonly),     \
                                        (posonly))

/* ------------------------------------------------------------------ */
/*  X-blob recording hook (the only patch in blob_decode.c)            */
/*                                                                    */
/*  Each time the parser hits a 'X' tag (raw marshal blob), it calls  */
/*  NUITKA_BLOB_LOADER_RECORD_X(ptr, size). We push (ptr, size) onto  */
/*  a global growable array. module.c reads it after the unpack.     */
/* ------------------------------------------------------------------ */
typedef struct {
    const unsigned char *data;
    size_t               size;
} NuitkaXBlob;

void nuitka_blob_loader_x_reset(void);
void nuitka_blob_loader_x_record(const unsigned char *data, size_t size);
const NuitkaXBlob *nuitka_blob_loader_x_items(size_t *out_count);

#define NUITKA_BLOB_LOADER_RECORD_X(ptr, size) \
    nuitka_blob_loader_x_record((const unsigned char *)(ptr), (size_t)(size))

/* ------------------------------------------------------------------ */
/*  CRC32 / DECODE                                                    */
/*                                                                    */
/*  loadConstantsBlob() calls:                                        */
/*    DECODE(constant_bin)         - decrypt in-place (or no-op)      */
/*    calcCRC32(payload, size)     - verify checksum                  */
/*                                                                    */
/*  We provide both as plain extern functions, defined in helpers.c.  */
/*  DECODE defaults to a no-op; can be replaced with an XOR/S-box     */
/*  step from Python via nuitka_blob_loader.set_sbox(...).            */
/* ------------------------------------------------------------------ */
void     nuitka_blob_loader_decode(unsigned char *blob);
uint32_t calcCRC32(unsigned char const *data, uint32_t size);

#define DECODE(blob) nuitka_blob_loader_decode((unsigned char *)(blob))

#endif /* NUITKA_BLOB_LOADER_SHIM_H */
