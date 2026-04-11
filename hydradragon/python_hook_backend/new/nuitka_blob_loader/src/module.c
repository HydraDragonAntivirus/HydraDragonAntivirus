/*
 * module.c
 *
 * Python extension entry point for `nuitka_blob_loader._core`.
 *
 * Public API:
 *
 *   _core.load(blob_path: str | bytes,
 *              section: str = ".bytecode") -> dict[str, bytes]
 *
 *       Loads a Nuitka constants blob from disk, drives blob_decode.c
 *       to unpack the requested section, and returns a dict mapping
 *       module name (string constant immediately preceding each X
 *       blob) -> raw marshal bytes for that module.
 *
 *   _core.set_sbox(sbox: bytes | None) -> None
 *       Install or clear an optional 256-byte S-box for DECODE().
 *
 *   _core.PYTHON_VERSION_HEX -> int
 *       The PYTHON_VERSION the extension was compiled for (e.g. 0x3c0).
 */

#include "nuitka_shim.h"

/* blob_decode.c declares these in its fall-through branch:
       unsigned char const *constant_bin = NULL;
   and provides the entry point:
       void loadConstantsBlob(PyThreadState *tstate,
                              PyObject **output, char const *name);
*/
extern unsigned char const *constant_bin;
extern void loadConstantsBlob(PyThreadState *tstate,
                              PyObject **output, char const *name);

/* ------------------------------------------------------------------ */
/*  TOC scanning                                                      */
/*                                                                    */
/*  Blob layout (after the 8-byte CRC+size header):                   */
/*    repeated:                                                       */
/*      [ NUL-terminated section name ]                               */
/*      [ uint32_t  payload_size      ]                               */
/*      [ payload_size bytes          ]                               */
/*    end-of-toc when name is empty.                                  */
/* ------------------------------------------------------------------ */
typedef struct {
    char    *name;        /* malloc'd, NUL-terminated */
    uint32_t size;        /* payload size */
} TocEntry;

static int scan_toc(const unsigned char *blob_start, size_t blob_total,
                    TocEntry **out_entries, size_t *out_count) {
    if (blob_total < 8) return -1;

    const unsigned char *p   = blob_start + 8;       /* skip CRC + size */
    const unsigned char *end = blob_start + blob_total;

    TocEntry *entries = NULL;
    size_t    count   = 0;
    size_t    cap     = 0;

    while (p < end) {
        const unsigned char *name_start = p;
        while (p < end && *p != 0) p++;
        if (p >= end) break;

        size_t name_len = (size_t)(p - name_start);
        p++; /* skip NUL */

        if (name_len == 0) break;  /* end-of-TOC marker */

        if (p + 4 > end) break;
        uint32_t payload_size;
        memcpy(&payload_size, p, 4);
        p += 4;

        if (p + payload_size > end) break;

        if (count == cap) {
            size_t new_cap = cap ? cap * 2 : 16;
            TocEntry *na = (TocEntry *)PyMem_Realloc(
                entries, new_cap * sizeof(TocEntry));
            if (!na) {
                for (size_t i = 0; i < count; i++) PyMem_Free(entries[i].name);
                PyMem_Free(entries);
                return -1;
            }
            entries = na;
            cap = new_cap;
        }

        entries[count].name = (char *)PyMem_Malloc(name_len + 1);
        if (!entries[count].name) {
            for (size_t i = 0; i < count; i++) PyMem_Free(entries[i].name);
            PyMem_Free(entries);
            return -1;
        }
        memcpy(entries[count].name, name_start, name_len);
        entries[count].name[name_len] = '\0';
        entries[count].size = payload_size;
        count++;

        p += payload_size;
    }

    *out_entries = entries;
    *out_count   = count;
    return 0;
}

static void free_toc(TocEntry *entries, size_t count) {
    for (size_t i = 0; i < count; i++) PyMem_Free(entries[i].name);
    PyMem_Free(entries);
}

/* ------------------------------------------------------------------ */
/*  Determine the top-level constant count for a section              */
/*                                                                    */
/*  loadConstantsBlob calls unpackBlobConstants which reads a uint16  */
/*  count from the start of the section payload. We need that count  */
/*  externally so we can size the output[] array we hand it.          */
/* ------------------------------------------------------------------ */
static int section_top_count(const unsigned char *blob_start,
                              size_t blob_total,
                              const char *section_name,
                              uint16_t *out_count) {
    if (blob_total < 8) return -1;
    const unsigned char *p   = blob_start + 8;
    const unsigned char *end = blob_start + blob_total;

    while (p < end) {
        const unsigned char *name_start = p;
        while (p < end && *p != 0) p++;
        if (p >= end) return -1;
        size_t name_len = (size_t)(p - name_start);
        p++;
        if (name_len == 0) return -1;

        if (p + 4 > end) return -1;
        uint32_t payload_size;
        memcpy(&payload_size, p, 4);
        p += 4;
        if (p + payload_size > end) return -1;

        if (strcmp((const char *)name_start, section_name) == 0) {
            if (payload_size < 2) return -1;
            uint16_t c;
            memcpy(&c, p, 2);
            *out_count = c;
            return 0;
        }
        p += payload_size;
    }
    return -1;  /* not found */
}

/* ------------------------------------------------------------------ */
/*  Build a Python dict { module_name: marshal_bytes } by walking    */
/*  the parsed output[] array and the recorded X-blob list together. */
/*                                                                    */
/*  Pairing rule: every X blob is preceded by its module-name string */
/*  in the output array. The output entries that correspond to X     */
/*  slots hold raw byte pointers (NOT real PyObjects), so we must    */
/*  identify them positionally. We do this by remembering, in        */
/*  call order, the indices in the output array where the parser    */
/*  consumed an 'X'. To get those indices we scan the section       */
/*  payload tags ourselves -- a tiny tag walker just for finding    */
/*  X positions, NOT for decoding values.                            */
/* ------------------------------------------------------------------ */

/* Skip exactly one constant in `*p` and advance the cursor.
   Returns 0 on success, -1 on unknown tag / truncation. We only
   need enough tag knowledge to step over them; we don't decode. */
static uint64_t skip_varint(const unsigned char **p, const unsigned char *end) {
    uint64_t result = 0;
    uint64_t factor = 1;
    while (*p < end) {
        unsigned char v = **p;
        (*p)++;
        result += (v & 127u) * factor;
        if (v < 128u) return result;
        factor <<= 7;
    }
    return result;  /* truncated; caller will likely fail later */
}

static int skip_constant(const unsigned char **p, const unsigned char *end);

static int skip_n_constants(const unsigned char **p, const unsigned char *end,
                            uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        if (skip_constant(p, end) != 0) return -1;
    }
    return 0;
}

static int skip_constant(const unsigned char **p, const unsigned char *end) {
    if (*p >= end) return -1;
    char tag = (char)**p;
    (*p)++;

    switch (tag) {
    /* zero-payload */
    case 'n': case 't': case 'F': case 's': case 'p':
        return 0;

    /* single byte index */
    case 'M': case 'Q': case 'Z': case 'd': case 'w':
        if (*p >= end) return -1;
        (*p)++;
        return 0;

    /* varint scalar */
    case 'l': case 'q':
        skip_varint(p, end);
        return 0;

    /* varint count + count varints */
    case 'G': case 'g': {
        uint64_t cnt = skip_varint(p, end);
        for (uint64_t i = 0; i < cnt; i++) skip_varint(p, end);
        return 0;
    }

    /* 8-byte float */
    case 'f':
        if (*p + 8 > end) return -1;
        *p += 8;
        return 0;

    /* two 8-byte doubles */
    case 'j':
        if (*p + 16 > end) return -1;
        *p += 16;
        return 0;

    /* NUL-terminated string */
    case 'c': case 'u': case 'a': case 'O': case 'E': {
        while (*p < end && **p != 0) (*p)++;
        if (*p >= end) return -1;
        (*p)++;
        return 0;
    }

    /* varint length + raw bytes */
    case 'b': case 'B': case 'v': case 'X': {
        uint64_t len = skip_varint(p, end);
        if (*p + len > end) return -1;
        *p += len;
        return 0;
    }

    /* container: varint count + count children */
    case 'T': case 'L': case 'S': case 'P': {
        uint64_t cnt = skip_varint(p, end);
        return skip_n_constants(p, end, cnt);
    }

    /* dict: varint count + count keys + count values */
    case 'D': {
        uint64_t cnt = skip_varint(p, end);
        if (skip_n_constants(p, end, cnt) != 0) return -1;
        return skip_n_constants(p, end, cnt);
    }

    /* slice / range: 3 children */
    case ':': case ';':
        return skip_n_constants(p, end, 3);

    /* GenericAlias: 2 children */
    case 'A':
        return skip_n_constants(p, end, 2);

    /* Union: 1 child (a tuple) */
    case 'H':
        return skip_n_constants(p, end, 1);

    /* Code object: this one is messy. We don't need to handle it for
       the .bytecode section (which only contains string + X pairs),
       and conservatively bail if we see it. */
    case 'C':
        return -1;

    case '.':
    default:
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/*  load(path, section=".bytecode") -> dict[str, bytes]               */
/* ------------------------------------------------------------------ */

static unsigned char *g_blob_buf  = NULL;
static size_t         g_blob_size = 0;

static int load_blob_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); PyErr_SetString(PyExc_OSError, "seek"); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); PyErr_SetString(PyExc_OSError, "tell"); return -1; }
    rewind(f);

    unsigned char *buf = (unsigned char *)PyMem_Malloc((size_t)sz);
    if (!buf) { fclose(f); PyErr_NoMemory(); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        PyMem_Free(buf); fclose(f);
        PyErr_SetString(PyExc_OSError, "short read");
        return -1;
    }
    fclose(f);

    if (g_blob_buf) PyMem_Free(g_blob_buf);
    g_blob_buf  = buf;
    g_blob_size = (size_t)sz;
    constant_bin = g_blob_buf;
    return 0;
}

static PyObject *py_load(PyObject *self, PyObject *args, PyObject *kwargs) {
    static char *kw[] = {"path", "section", NULL};
    const char *path     = NULL;
    const char *section  = ".bytecode";
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|s", kw,
                                     &path, &section)) {
        return NULL;
    }

    if (load_blob_file(path) != 0) return NULL;

    /* Verify CRC32 over the post-header payload. The blob layout
       starts with [crc:u32][size:u32][payload...] -- this matches
       what loadConstantsBlob() asserts internally. */
    if (g_blob_size < 8) {
        PyErr_SetString(PyExc_ValueError, "blob smaller than header");
        return NULL;
    }
    uint32_t want_crc, claimed_size;
    memcpy(&want_crc, g_blob_buf, 4);
    memcpy(&claimed_size, g_blob_buf + 4, 4);
    if (8 + (size_t)claimed_size > g_blob_size) {
        PyErr_SetString(PyExc_ValueError, "blob size header inconsistent");
        return NULL;
    }
    uint32_t got_crc = calcCRC32(g_blob_buf + 8, claimed_size);
    if (got_crc != want_crc) {
        PyErr_Format(PyExc_ValueError,
                     "CRC32 mismatch: header=0x%08x computed=0x%08x",
                     want_crc, got_crc);
        return NULL;
    }

    /* Find the requested section's payload pointer + size, and the
       top-level constant count at its head. */
    uint16_t top_count = 0;
    if (section_top_count(g_blob_buf, g_blob_size, section, &top_count) != 0) {
        PyErr_Format(PyExc_KeyError, "section not found: %s", section);
        return NULL;
    }
    if (top_count == 0) {
        return PyDict_New();
    }

    /* Allocate output array of PyObject* slots for the parser. */
    PyObject **slots = (PyObject **)PyMem_Calloc(top_count, sizeof(PyObject *));
    if (!slots) return PyErr_NoMemory();

    /* Reset X-blob recorder, then drive the unmodified parser. */
    nuitka_blob_loader_x_reset();

    PyThreadState *tstate = PyThreadState_Get();
    loadConstantsBlob(tstate, slots, section);

    if (PyErr_Occurred()) {
        PyMem_Free(slots);
        return NULL;
    }

    /* Pull the recorded X blobs (in payload order). */
    size_t x_count = 0;
    const NuitkaXBlob *x_items = nuitka_blob_loader_x_items(&x_count);

    /* Build the result dict. We expect the .bytecode section to be a
       flat sequence of (name, X) pairs. The parser stored each name
       at slot[2*i] and each X raw pointer at slot[2*i+1] -- but the
       X slot is NOT a real PyObject and we must not touch it. We
       only need the names. */
    PyObject *result = PyDict_New();
    if (!result) { PyMem_Free(slots); return NULL; }

    /* If top_count is exactly 2*x_count, the flat layout holds. */
    int flat_layout = ((size_t)top_count == 2 * x_count);

    if (flat_layout) {
        for (size_t i = 0; i < x_count; i++) {
            PyObject *name = slots[2 * i];
            if (!name || !PyUnicode_Check(name)) {
                /* Bail with a placeholder name. */
                PyObject *fallback = PyUnicode_FromFormat(".bytecode_%zu", i);
                PyObject *blob = PyBytes_FromStringAndSize(
                    (const char *)x_items[i].data, (Py_ssize_t)x_items[i].size);
                PyDict_SetItem(result, fallback, blob);
                Py_DECREF(fallback);
                Py_DECREF(blob);
                continue;
            }
            PyObject *blob = PyBytes_FromStringAndSize(
                (const char *)x_items[i].data, (Py_ssize_t)x_items[i].size);
            if (!blob) { Py_DECREF(result); PyMem_Free(slots); return NULL; }
            PyDict_SetItem(result, name, blob);
            Py_DECREF(blob);
        }
    } else {
        /* Fallback: just emit blobs with synthetic names. */
        for (size_t i = 0; i < x_count; i++) {
            PyObject *name = PyUnicode_FromFormat(".bytecode_%zu", i);
            PyObject *blob = PyBytes_FromStringAndSize(
                (const char *)x_items[i].data, (Py_ssize_t)x_items[i].size);
            PyDict_SetItem(result, name, blob);
            Py_DECREF(name);
            Py_DECREF(blob);
        }
    }

    PyMem_Free(slots);
    return result;
}

/* ------------------------------------------------------------------ */
/*  set_sbox(bytes | None)                                            */
/* ------------------------------------------------------------------ */
extern void nuitka_blob_loader_set_sbox(const uint8_t sbox[256]);
extern void nuitka_blob_loader_clear_sbox(void);

static PyObject *py_set_sbox(PyObject *self, PyObject *arg) {
    if (arg == Py_None) {
        nuitka_blob_loader_clear_sbox();
        Py_RETURN_NONE;
    }
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) != 0) return NULL;
    if (buf.len != 256) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "sbox must be exactly 256 bytes");
        return NULL;
    }
    nuitka_blob_loader_set_sbox((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------ */
/*  Method table + module init                                        */
/* ------------------------------------------------------------------ */
static PyMethodDef Methods[] = {
    {"load",     (PyCFunction)py_load, METH_VARARGS | METH_KEYWORDS,
     "load(path, section='.bytecode') -> dict[str, bytes]"},
    {"set_sbox", py_set_sbox,          METH_O,
     "set_sbox(bytes | None) -> None"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef ModuleDef = {
    PyModuleDef_HEAD_INIT, "_core", NULL, -1, Methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__core(void) {
    PyObject *m = PyModule_Create(&ModuleDef);
    if (!m) return NULL;

    /* Initialize the globals blob_decode.c expects. */
    builtin_module = PyImport_ImportModule("builtins");
    if (!builtin_module) { Py_DECREF(m); return NULL; }

    PyObject *sys_mod = PyImport_ImportModule("sys");
    if (!sys_mod) { Py_DECREF(m); return NULL; }
    Py_SysVersionInfo = PyObject_GetAttrString(sys_mod, "version_info");
    Py_DECREF(sys_mod);
    if (!Py_SysVersionInfo) { Py_DECREF(m); return NULL; }

#if PYTHON_VERSION >= 0x3a0
    PyObject *types_mod = PyImport_ImportModule("types");
    if (!types_mod) { Py_DECREF(m); return NULL; }
    PyObject *ut = PyObject_GetAttrString(types_mod, "UnionType");
    Py_DECREF(types_mod);
    if (!ut) { Py_DECREF(m); return NULL; }
    Nuitka_PyUnion_Type = (PyTypeObject *)ut;
#endif

    PyModule_AddIntConstant(m, "PYTHON_VERSION_HEX", PYTHON_VERSION);
    return m;
}
