#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// HARDENING: Use heap allocation instead of stack (_alloca) to prevent c0000409
#define NUITKA_DYNAMIC_ARRAY_DECL(name, type, size)                            \
  type *name = (type *)PyMem_Calloc((size), sizeof(type))
#define NUITKA_DYNAMIC_ARRAY_FREE(name) PyMem_Free(name)

#define PYTHON_VERSION 0x030c00
#ifndef Py_SET_REFCNT_IMMORTAL
#define Py_SET_REFCNT_IMMORTAL(x)
#endif

#define DEOC_CHECK_LEN(len)                                                    \
  if (*data + (len) > end) {                                                   \
    *output = Py_None;                                                         \
    Py_INCREF(Py_None);                                                        \
    return;                                                                    \
  }

static PyObject *builtin_module = NULL;
static PyObject *Py_SysVersionInfo = NULL;

static PyObject *long_cache = NULL;
static PyObject *float_cache = NULL;
static PyObject *bytes_cache = NULL;
static PyObject *tuple_cache = NULL;
static PyObject *list_cache = NULL;
static PyObject *dict_cache = NULL;
static PyObject *set_cache = NULL;
static PyObject *frozenset_cache = NULL;

static void initCaches(void) {
  if (long_cache)
    return;
  long_cache = PyDict_New();
  float_cache = PyDict_New();
  bytes_cache = PyDict_New();
  tuple_cache = PyDict_New();
  list_cache = PyDict_New();
  dict_cache = PyDict_New();
  set_cache = PyDict_New();
  frozenset_cache = PyDict_New();
}

static void insertToDictCache(PyObject *dict, PyObject **value) {
  if (!*value)
    return;
  // Hardening: ONLY cache hashable immutable types to avoid noise and
  // TypeErrors
  if (!PyUnicode_Check(*value) && !PyBytes_Check(*value) &&
      !PyLong_Check(*value) && !PyFloat_Check(*value)) {
    return;
  }
  // Double check hashability just in case
  if (PyObject_Hash(*value) == -1 && PyErr_Occurred()) {
    PyErr_Clear();
    return;
  }
  PyObject *item = PyDict_GetItem(dict, *value);
  if (item != NULL) {
    Py_DECREF(*value);
    *value = item;
    Py_INCREF(*value);
  } else {
    PyErr_Clear();
    if (PyDict_SetItem(dict, *value, *value) < 0)
      PyErr_Clear();
  }
}

// Dummy hashes for cache
static Py_hash_t dummy_hash(PyObject *o) { return 0; }
static PyObject *dummy_richcompare(PyObject *a, PyObject *b, int op) {
  Py_INCREF(Py_NotImplemented);
  return Py_NotImplemented;
}

static void insertToDictCacheForced(PyObject *dict, PyObject **value) {
  insertToDictCache(dict, value);
}

static uint64_t _unpackVariableLength(unsigned char const **data,
                                      unsigned char const *end) {
  uint64_t result = 0;
  uint64_t factor = 1;
  while (*data < end) {
    unsigned char value = **data;
    *data += 1;
    result += (uint64_t)(value & 127) * factor;
    if (value < 128)
      break;
    factor <<= 7;
  }
  return result;
}

static PyObject *_unpackAnonValue(unsigned char anon_index) {
  switch (anon_index) {
  case 0:
    return (PyObject *)Py_TYPE(Py_None);
  case 1:
    return (PyObject *)&PyEllipsis_Type;
  case 2:
    return (PyObject *)Py_TYPE(Py_NotImplemented);
  case 3:
    return (PyObject *)&PyFunction_Type;
#if PYTHON_VERSION < 0x030000
  case 4:
    return (PyObject *)&PyGen_Type;
#endif
  case 5:
    return (PyObject *)&PyCFunction_Type;
  case 6:
    return (PyObject *)&PyCode_Type;
  case 7:
    return (PyObject *)&PyModule_Type;
  default:
    Py_INCREF(Py_None);
    return Py_None;
  }
}

static PyObject *_unpackSpecialValue(unsigned char special_index) {
  switch (special_index) {
  case 0:
    return PyObject_GetAttrString(builtin_module, "Ellipsis");
  case 1:
    return PyObject_GetAttrString(builtin_module, "NotImplemented");
  case 2:
    if (Py_SysVersionInfo) {
      Py_INCREF(Py_SysVersionInfo);
      return Py_SysVersionInfo;
    }
  default:
    Py_INCREF(Py_None);
    return Py_None;
  }
}

static void _unpackBlobConstant(PyThreadState *tstate, PyObject **output,
                                unsigned char const **data,
                                unsigned char const *end, int depth);

static void _unpackBlobConstants(PyThreadState *tstate, PyObject **output,
                                 unsigned char const **data,
                                 unsigned char const *end, int count,
                                 int depth) {
  for (int i = 0; i < count; i++) {
    _unpackBlobConstant(tstate, &output[i], data, end, depth);
  }
}

static bool is_valid_tag(unsigned char c) {
  const char *valid = "TLDCXbvactF:;MQOEZSPilqgGfjJBwu.AHc";
  while (*valid) {
    if (*valid == c)
      return true;
    valid++;
  }
  return false;
}

static void _unpackBlobConstant(PyThreadState *tstate, PyObject **output,
                                unsigned char const **data,
                                unsigned char const *end, int depth) {
  if (depth > 500 || *data >= end) {
    *output = Py_None;
    Py_INCREF(Py_None);
    if (*data < end)
      (*data)++;
    return;
  }
  *output = NULL;
  bool is_object = false;
  unsigned char c = *(*data)++;

  switch (c) {
  case 'p': {
    (void)_unpackVariableLength(data, end);
    *output = Py_None;
    Py_INCREF(Py_None);
    is_object = true;
    break;
  }
  case 'T':
  case 'L': {
    uint32_t size = (uint32_t)_unpackVariableLength(data, end);
    if (size > (uint32_t)(end - *data)) {
      *output = (c == 'T') ? PyTuple_New(0) : PyList_New(0);
      is_object = true;
      return;
    }
    PyObject *coll = (c == 'T') ? PyTuple_New(size) : PyList_New(size);
    if (size > 0 && *data < end) {
      PyObject **elements = (PyObject **)PyMem_Calloc(size, sizeof(PyObject *));
      if (!elements) {
        *output = coll;
        is_object = true;
        return;
      }
      _unpackBlobConstants(tstate, elements, data, end, size, depth + 1);
      for (uint32_t i = 0; i < size; i++) {
        PyObject *val =
            elements[i] ? elements[i] : (Py_INCREF(Py_None), Py_None);
        if (c == 'T')
          PyTuple_SET_ITEM(coll, i, val);
        else
          PyList_SET_ITEM(coll, i, val);
      }
      PyMem_Free(elements);
    }
    insertToDictCacheForced((c == 'T') ? tuple_cache : list_cache, &coll);
    *output = coll;
    is_object = true;
    break;
  }
  case 'D': {
    uint32_t size = (uint32_t)_unpackVariableLength(data, end);
    if (size > (uint32_t)(end - *data)) {
      *output = PyDict_New();
      is_object = true;
      return;
    }
    PyObject *d = _PyDict_NewPresized(size);
    if (size > 0 && *data < end) {
      PyObject **keys = (PyObject **)PyMem_Calloc(size, sizeof(PyObject *));
      PyObject **values = (PyObject **)PyMem_Calloc(size, sizeof(PyObject *));
      if (!keys || !values) {
        Py_XDECREF(d);
        PyMem_Free(keys);
        PyMem_Free(values);
        *output = PyDict_New();
        is_object = true;
        return;
      }
      _unpackBlobConstants(tstate, keys, data, end, size, depth + 1);
      _unpackBlobConstants(tstate, values, data, end, size, depth + 1);
      for (uint32_t i = 0; i < size; i++) {
        if (keys[i] && values[i]) {
          PyDict_SetItem(d, keys[i], values[i]);
          if (PyErr_Occurred())
            PyErr_Clear();
        }
        Py_XDECREF(keys[i]);
        Py_XDECREF(values[i]);
      }
      PyMem_Free(keys);
      PyMem_Free(values);
    }
    insertToDictCacheForced(dict_cache, &d);
    *output = d;
    is_object = true;
    break;
  }
  case 'P':
  case 'S': {
    uint32_t size = (uint32_t)_unpackVariableLength(data, end);
    if (size > (uint32_t)(end - *data)) {
      *output = (c == 'S') ? PySet_New(NULL) : PyFrozenSet_New(NULL);
      is_object = true;
      return;
    }
    PyObject *s = (c == 'S') ? PySet_New(NULL) : PyFrozenSet_New(NULL);
    if (size > 0 && *data < end) {
      PyObject **elements = (PyObject **)PyMem_Calloc(size, sizeof(PyObject *));
      if (!elements) {
        *output = s;
        is_object = true;
        return;
      }
      _unpackBlobConstants(tstate, elements, data, end, size, depth + 1);
      for (uint32_t i = 0; i < size; i++) {
        if (elements[i]) {
          if (PySet_Add(s, elements[i]) < 0)
            PyErr_Clear();
        }
        Py_XDECREF(elements[i]);
      }
      PyMem_Free(elements);
    }
    insertToDictCacheForced((c == 'S') ? set_cache : frozenset_cache, &s);
    *output = s;
    is_object = true;
    break;
  }
  case 'i':
  case 'l':
  case 'q': {
    uint64_t val = _unpackVariableLength(data, end);
    *output =
        PyLong_FromLongLong((c == 'q') ? -(long long)val : (long long)val);
    is_object = true;
    break;
  }
  case 'f': {
    DEOC_CHECK_LEN(sizeof(double));
    double fval;
    memcpy(&fval, *data, sizeof(double));
    *data += sizeof(double);
    *output = PyFloat_FromDouble(fval);
    insertToDictCacheForced(float_cache, output);
    is_object = true;
    break;
  }
  case 'c':
  case 'a':
  case 'u': {
    const char *start = (const char *)*data;
    while (*data < end && **data != '\0')
      (*data)++;
    Py_ssize_t len = (Py_ssize_t)((const char *)*data - start);
    if (*data < end)
      (*data)++; // skip null
    if (c == 'c' || c == 'a') {
      *output = PyBytes_FromStringAndSize(start, len);
    } else {
      *output = PyUnicode_DecodeUTF8(start, len, "replace");
      if (!*output) {
        PyErr_Clear();
        *output = PyBytes_FromStringAndSize(start, len);
      }
    }
    is_object = true;
    break;
  }
  case 'b':
  case 'A':
  case 'v': {
    uint32_t size = (uint32_t)_unpackVariableLength(data, end);
    DEOC_CHECK_LEN(size);
    if (c == 'b' || c == 'A') {
      *output = PyBytes_FromStringAndSize((const char *)*data, size);
    } else {
      *output = PyUnicode_DecodeUTF8((const char *)*data, size, "replace");
      if (!*output) {
        PyErr_Clear();
        *output = PyBytes_FromStringAndSize((const char *)*data, size);
      }
    }
    *data += size;
    is_object = true;
    break;
  }
  case 'n': {
    *output = Py_None;
    Py_INCREF(Py_None);
    is_object = true;
    break;
  }
  case 't': {
    *output = Py_True;
    Py_INCREF(Py_True);
    is_object = true;
    break;
  }
  case 'F': {
    *output = Py_False;
    Py_INCREF(Py_False);
    is_object = true;
    break;
  }
  case 'X': {
    uint64_t size = _unpackVariableLength(data, end);
    if (*data + size > end) {
      *output = Py_None;
      Py_INCREF(Py_None);
      break;
    }
    *output = PyBytes_FromStringAndSize((const char *)*data, (Py_ssize_t)size);
    *data += (size_t)size;
    is_object = true;
    break;
  }
  case 'K': {
    _unpackBlobConstant(tstate, output, data, end, depth + 1);
    is_object = true;
    break;
  }
  case 'Q': {
    uint64_t size = _unpackVariableLength(data, end);
    if (*data + size > end) {
      *output = Py_None;
      Py_INCREF(Py_None);
      break;
    }
    *output = PyBytes_FromStringAndSize((const char *)*data, (Py_ssize_t)size);
    *data += (size_t)size;
    is_object = true;
    break;
  }
  case 'C': {
    (void)_unpackVariableLength(data, end); // flags
    PyObject *fn, *arg_names, *qualname = NULL, *free_vars = NULL;
    _unpackBlobConstant(tstate, &fn, data, end, depth + 1);
    (void)_unpackVariableLength(data, end); // line
    _unpackBlobConstant(tstate, &arg_names, data, end, depth + 1);
    (void)_unpackVariableLength(data, end); // arg_count
    // Simply returned values in a tuple to avoid CodeObject complexity
    PyObject *res = PyTuple_New(2);
    PyTuple_SET_ITEM(res, 0, fn ? fn : (Py_INCREF(Py_None), Py_None));
    PyTuple_SET_ITEM(res, 1,
                     arg_names ? arg_names : (Py_INCREF(Py_None), Py_None));
    *output = res;
    is_object = true;
    break;
  }
  default: {
    *output = Py_None;
    Py_INCREF(Py_None);
    is_object = true;
    break;
  }
  }

  if (is_object && *output) {
    Py_INCREF(*output);
  }
}

static PyObject *make_safe_unicode(const char *name) {
  PyObject *u = PyUnicode_DecodeUTF8(name, strlen(name), "replace");
  if (!u) {
    PyErr_Clear();
    u = PyUnicode_FromString("mangled_name");
  }
  return u;
}

static void add_section_to_dict(PyObject *dict, const char *name,
                                PyObject *tuple) {
  PyObject *key = make_safe_unicode(name);
  if (PyDict_GetItem(dict, key) != NULL) {
    // Handle duplicate names by appending a counter
    char alt_name[256];
    static int collision_idx = 0;
    const char *base_name = PyUnicode_AsUTF8(key);
    snprintf(alt_name, sizeof(alt_name), "%s_dup_%d",
             base_name ? base_name : "unknown", collision_idx++);
    PyObject *alt_key = make_safe_unicode(alt_name);
    PyDict_SetItem(dict, alt_key, tuple);
    Py_XDECREF(alt_key);
  } else {
    PyDict_SetItem(dict, key, tuple);
  }
  Py_XDECREF(key);
}

static PyObject *decode_nuitka_blob(PyObject *self, PyObject *args) {
  const unsigned char *blob_data;
  Py_ssize_t blob_size;
  if (!PyArg_ParseTuple(args, "y#", &blob_data, &blob_size))
    return NULL;

  unsigned char const *end = blob_data + blob_size;
  PyThreadState *tstate = PyThreadState_Get();
  if (!builtin_module)
    builtin_module = PyImport_ImportModule("builtins");
  initCaches();

  PyObject *result_dict = PyDict_New();

  // --- SCAN 1: Linear Chain ---
  const unsigned char *w = blob_data + 8; // skip hash/size
  while (w + 6 < end) {
    while (w < end && *w == '\0')
      w++;
    if (w + 6 >= end)
      break;

    const char *name_ptr = (const char *)w;
    const unsigned char *p = w;
    while (p < end && *p != '\0')
      p++;

    if (p + 6 < end) {
      uint32_t s_size;
      uint16_t s_count;
      memcpy(&s_size, p + 1, sizeof(uint32_t));
      memcpy(&s_count, p + 5, sizeof(uint16_t));

      if (s_size > 0 && s_size < (unsigned int)(end - p - 7) && s_count > 0 &&
          s_count < 65000) {
        const unsigned char *data_ptr = p + 7;
        const unsigned char *sec_end = data_ptr + s_size;

        PyObject **out_array =
            (PyObject **)PyMem_Calloc(s_count, sizeof(PyObject *));
        if (out_array) {
          const unsigned char *work_ptr = data_ptr;
          _unpackBlobConstants(tstate, out_array, &work_ptr, sec_end, s_count,
                               0);
          PyObject *out_tuple = PyTuple_New(s_count);
          for (uint16_t i = 0; i < s_count; i++) {
            PyObject *val =
                out_array[i] ? out_array[i] : (Py_INCREF(Py_None), Py_None);
            PyTuple_SET_ITEM(out_tuple, i, val);
          }
          PyMem_Free(out_array);
          add_section_to_dict(result_dict, name_ptr, out_tuple);
          Py_DECREF(out_tuple);
        }
        w = sec_end;
        continue;
      }
    }
    w = p + 1;
  }

  // --- SCAN 2: Aggressive Signature Scan ---
  for (const unsigned char *scan_p = blob_data + 8; scan_p + 7 < end;
       scan_p++) {
    uint32_t s_size;
    uint16_t s_count;
    memcpy(&s_size, scan_p, sizeof(uint32_t));
    memcpy(&s_count, scan_p + 4, sizeof(uint16_t));
    unsigned char next_tag = *(scan_p + 6);

    // PHYSICAL SANITY CHECK: Every Nuitka constant takes at least 1 byte (the
    // tag). If the claimed size is smaller than the claimed count, it's
    // mathematically impossible to be a valid section.
    if (s_size > 0 && s_size < (unsigned int)(end - scan_p - 6) &&
        s_count > 0 && s_count < 65000 && (s_size >= (uint32_t)s_count) &&
        is_valid_tag(next_tag)) {

      const char *discovered_name = "hidden_segment";
      char name_buf[512];
      const unsigned char *name_scan = scan_p - 1;
      if (name_scan >= blob_data && *name_scan == '\0') {
        name_scan--;
        while (name_scan >= blob_data && *name_scan != '\0' &&
               *name_scan >= 32 && *name_scan < 127)
          name_scan--;
        if (name_scan < blob_data || *name_scan == '\0') {
          discovered_name = (const char *)(name_scan + 1);
        }
      }

      snprintf(name_buf, sizeof(name_buf), "discovered_%s_at_%lld",
               discovered_name, (long long)(scan_p - blob_data));

      const unsigned char *work_ptr = scan_p + 6;
      PyObject *test_obj = NULL;
      _unpackBlobConstant(tstate, &test_obj, &work_ptr, scan_p + 6 + s_size, 0);
      if (test_obj) {
        PyObject **out_array =
            (PyObject **)PyMem_Calloc(s_count, sizeof(PyObject *));
        if (out_array) {
          work_ptr = scan_p + 6;
          _unpackBlobConstants(tstate, out_array, &work_ptr,
                               scan_p + 6 + s_size, s_count, 0);
          PyObject *out_tuple = PyTuple_New(s_count);
          for (uint16_t i = 0; i < s_count; i++) {
            PyObject *val =
                out_array[i] ? out_array[i] : (Py_INCREF(Py_None), Py_None);
            PyTuple_SET_ITEM(out_tuple, i, val);
          }
          PyMem_Free(out_array);
          add_section_to_dict(result_dict, name_buf, out_tuple);
          Py_DECREF(out_tuple);
        }
        Py_XDECREF(test_obj);
        scan_p += 6 + s_size - 1;
      }
    }
  }

  if (PyErr_Occurred()) {
    Py_XDECREF(result_dict);
    return NULL;
  }
  return result_dict;
}

static PyObject *decode_at_offset(PyObject *self, PyObject *args) {
  const unsigned char *blob_data;
  Py_ssize_t blob_size;
  long long offset;
  if (!PyArg_ParseTuple(args, "y#L", &blob_data, &blob_size, &offset))
    return NULL;

  if (offset < 0 || offset >= blob_size) {
    PyErr_SetString(PyExc_ValueError, "Offset out of bounds");
    return NULL;
  }

  unsigned char const *end = blob_data + blob_size;
  unsigned char const *w = blob_data + offset;
  PyThreadState *tstate = PyThreadState_Get();
  if (!builtin_module)
    builtin_module = PyImport_ImportModule("builtins");
  initCaches();

  PyObject *res = NULL;
  _unpackBlobConstant(tstate, &res, &w, end, 0);

  if (PyErr_Occurred())
    PyErr_Clear();
  return res ? res : (Py_INCREF(Py_None), Py_None);
}

static PyMethodDef BlobLoaderMethods[] = {
    {"decode_blob", decode_nuitka_blob, METH_VARARGS,
     "Decodes a Nuitka constant blob."},
    {"decode_at_offset", decode_at_offset, METH_VARARGS,
     "Decode constant at offset"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef blobxdis_module = {
    PyModuleDef_HEAD_INIT, "nuitka_deobfuscate", NULL, -1, BlobLoaderMethods};

PyMODINIT_FUNC PyInit_nuitka_deobfuscate(void) {
  return PyModule_Create(&blobxdis_module);
}
