/*
 * helpers.c
 *
 * Out-of-line implementations of the symbols declared in nuitka_shim.h.
 * Compiled separately and linked into the extension.
 */

#include "nuitka_shim.h"

/* ------------------------------------------------------------------ */
/*  Globals referenced from blob_decode.c                              */
/* ------------------------------------------------------------------ */
PyObject *builtin_module    = NULL;
PyObject *Py_SysVersionInfo = NULL;

#if PYTHON_VERSION >= 0x3a0
PyTypeObject *Nuitka_PyUnion_Type = NULL;
#endif

/* blob_decode.c declares `unsigned char const *constant_bin = NULL;`
   itself in the fall-through branch -- we don't redefine it here. */

/* ------------------------------------------------------------------ */
/*  CRC32 (zlib polynomial 0xEDB88320, ISO-HDLC)                      */
/* ------------------------------------------------------------------ */
static uint32_t crc_table[256];
static int      crc_table_built = 0;

static void build_crc_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
    crc_table_built = 1;
}

uint32_t calcCRC32(unsigned char const *data, uint32_t size) {
    if (!crc_table_built) build_crc_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < size; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ------------------------------------------------------------------ */
/*  DECODE (in-place blob decryption)                                 */
/*                                                                    */
/*  Default: no-op. Many Nuitka builds emit DECODE() as nothing.     */
/*  Optional: 256-byte S-box XOR. The Python side may install one    */
/*  via nuitka_blob_loader.set_sbox(bytes_of_length_256).            */
/* ------------------------------------------------------------------ */
static int     g_have_sbox = 0;
static uint8_t g_sbox[256];

void nuitka_blob_loader_set_sbox(const uint8_t sbox[256]) {
    memcpy(g_sbox, sbox, 256);
    g_have_sbox = 1;
}

void nuitka_blob_loader_clear_sbox(void) {
    g_have_sbox = 0;
}

/* DECODE is called once on the whole blob during loadConstantsBlob.
   We can't know the blob length here -- blob_decode.c reads the
   length from inside the blob AFTER DECODE runs. So if a non-trivial
   DECODE is needed, the caller must arrange for it to happen BEFORE
   we hand the blob to loadConstantsBlob(), or we use the default
   no-op and rely on the loader's own walking to be correct.

   In practice the dump-from-memory tool (the .bin file) is already
   plaintext, so a no-op DECODE is what we want. We keep the S-box
   path available for symmetry but it is unused in default flows. */
void nuitka_blob_loader_decode(unsigned char *blob) {
    (void)blob;
    /* No length known here -- intentionally a no-op. If you need
       sbox decryption, do it in Python before passing the buffer. */
    if (g_have_sbox) {
        /* Reserved for future use. */
    }
}

/* ------------------------------------------------------------------ */
/*  X-blob recording                                                  */
/* ------------------------------------------------------------------ */
static NuitkaXBlob *g_x_items = NULL;
static size_t       g_x_count = 0;
static size_t       g_x_cap   = 0;

void nuitka_blob_loader_x_reset(void) {
    g_x_count = 0;
}

void nuitka_blob_loader_x_record(const unsigned char *data, size_t size) {
    if (g_x_count == g_x_cap) {
        size_t new_cap = g_x_cap ? g_x_cap * 2 : 64;
        NuitkaXBlob *new_items = (NuitkaXBlob *)PyMem_Realloc(
            g_x_items, new_cap * sizeof(NuitkaXBlob));
        if (new_items == NULL) {
            /* Best-effort: drop the record. */
            return;
        }
        g_x_items = new_items;
        g_x_cap   = new_cap;
    }
    g_x_items[g_x_count].data = data;
    g_x_items[g_x_count].size = size;
    g_x_count++;
}

const NuitkaXBlob *nuitka_blob_loader_x_items(size_t *out_count) {
    *out_count = g_x_count;
    return g_x_items;
}

/* ------------------------------------------------------------------ */
/*  MAKE_CODE_OBJECT for CPython 3.12                                 */
/*                                                                    */
/*  Builds a stub PyCodeObject with empty bytecode. Only used as a    */
/*  metadata holder; we never execute it. We feed it a minimal valid  */
/*  bytecode sequence so PyCode_NewWithPosOnlyArgs accepts it.       */
/*                                                                    */
/*  Layout for 3.12:                                                  */
/*    PyCode_NewWithPosOnlyArgs(                                      */
/*      argcount, posonlyargcount, kwonlyargcount, nlocals,           */
/*      stacksize, flags,                                             */
/*      code, consts, names, varnames, freevars, cellvars,            */
/*      filename, name, qualname,                                     */
/*      firstlineno, linetable, exceptiontable)                       */
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
                                              int pos_only_count) {
    PyObject *empty_bytes = PyBytes_FromStringAndSize("", 0);
    PyObject *empty_tuple = PyTuple_New(0);
    if (!empty_bytes || !empty_tuple) {
        Py_XDECREF(empty_bytes);
        Py_XDECREF(empty_tuple);
        return NULL;
    }

    /* varnames must contain at least all argument names. arg_names is
       a tuple of strings; reuse it. If NULL, fall back to empty. */
    PyObject *varnames = arg_names ? arg_names : empty_tuple;
    Py_INCREF(varnames);

    PyObject *freevars_tuple = free_vars ? free_vars : empty_tuple;
    Py_INCREF(freevars_tuple);

    /* nlocals must be >= number of varnames. */
    Py_ssize_t nlocals = PyTuple_GET_SIZE(varnames);

    PyObject *result = (PyObject *)PyCode_NewWithPosOnlyArgs(
        arg_count,                /* argcount         */
        pos_only_count,           /* posonlyargcount  */
        kw_only_count,            /* kwonlyargcount   */
        (int)nlocals,             /* nlocals          */
        0,                        /* stacksize        */
        co_flags,                 /* flags            */
        empty_bytes,              /* code             */
        empty_tuple,              /* consts           */
        empty_tuple,              /* names            */
        varnames,                 /* varnames         */
        freevars_tuple,           /* freevars         */
        empty_tuple,              /* cellvars         */
        filename,                 /* filename         */
        function_name,            /* name             */
        function_qualname,        /* qualname         */
        line_number,              /* firstlineno      */
        empty_bytes,              /* linetable        */
        empty_bytes               /* exceptiontable   */
    );

    Py_DECREF(empty_bytes);
    Py_DECREF(empty_tuple);
    Py_DECREF(varnames);
    Py_DECREF(freevars_tuple);

    return result;
}
