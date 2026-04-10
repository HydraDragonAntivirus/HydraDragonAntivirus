/*
 * blob_export.c
 *
 * Purpose:
 *   Walk every TOC section, find every 'X' blob, deserialize the raw
 *   marshal payload in memory through the embedded Python runtime,
 *   then write a valid .pyc file to disk.
 *
 * Flow:
 *   raw 'X' blob
 *     -> PyMarshal_ReadObjectFromString()   (memory only decode)
 *     -> PyMarshal_WriteObjectToString()    (memory only remarshal)
 *     -> write_pyc()                        (save valid .pyc to disk)
 *
 * Notes:
 *   - .pyc output is still written to disk.
 *   - The marshal decode/remarshal step happens only in memory.
 *   - Python 3.12 is the intended target. If py_version == 0 we default
 *     to Python 3.12 magic.
 */

#include "blob_loader.h"
#include <Python.h>
#include <marshal.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#  include <direct.h>
#  define MKDIR(p) _mkdir(p)
#  define PATH_SEP '\\'
#else
#  include <unistd.h>
#  define MKDIR(p) mkdir((p), 0755)
#  define PATH_SEP '/'
#endif

/* ------------------------------------------------------------------ */
/*  Tiny blob primitives                                               */
/* ------------------------------------------------------------------ */
static uint16_t ex_read_u16(const uint8_t **p) {
    uint16_t v;
    memcpy(&v, *p, 2);
    *p += 2;
    return v;
}

static uint32_t ex_read_u32(const uint8_t **p) {
    uint32_t v;
    memcpy(&v, *p, 4);
    *p += 4;
    return v;
}

static uint64_t ex_varint(const uint8_t **p) {
    uint64_t r = 0, f = 1;
    for (;;) {
        uint8_t b = **p;
        (*p)++;
        r += (uint64_t)(b & 0x7F) * f;
        if (b < 0x80) break;
        f <<= 7;
    }
    return r;
}

static const uint8_t *ex_skip_cstr(const uint8_t *p) {
    while (*p) p++;
    return p + 1;
}

/* ------------------------------------------------------------------ */
/*  Hex dump                                                          */
/* ------------------------------------------------------------------ */
void blob_hexdump(FILE *fp, const char *label,
                  const uint8_t *data, size_t len) {
    if (label) fprintf(fp, "=== %s  (%zu bytes) ===\n", label, len);
    for (size_t off = 0; off < len; off += 16) {
        fprintf(fp, "%08zX  ", off);
        for (size_t i = 0; i < 16; i++) {
            if (off + i < len)
                fprintf(fp, "%02X ", data[off + i]);
            else
                fprintf(fp, "   ");
            if (i == 7) fputc(' ', fp);
        }
        fprintf(fp, " |");
        for (size_t i = 0; i < 16 && off + i < len; i++) {
            uint8_t c = data[off + i];
            fputc((c >= 0x20 && c < 0x7F) ? c : '.', fp);
        }
        fprintf(fp, "|\n");
    }
    if (label) fprintf(fp, "=== end ===\n\n");
}

/* ------------------------------------------------------------------ */
/*  Python magic numbers                                              */
/* ------------------------------------------------------------------ */
static uint32_t pyc_magic(unsigned int py_ver) {
    switch (py_ver & 0xFF0) {
    case 0x380: return 0x0D0D550A; /* 3.8  */
    case 0x390: return 0x0D0D610A; /* 3.9  */
    case 0x3a0: return 0x0D0D6F0A; /* 3.10 */
    case 0x3b0: return 0x0D0DA70A; /* 3.11 */
    case 0x3c0: return 0x0D0DCB0A; /* 3.12 */
    case 0x3d0: return 0x0D0DF50A; /* 3.13 */
    default:    return 0x0D0DCB0A; /* default: 3.12 */
    }
}

/* ------------------------------------------------------------------ */
/*  Recursive mkdir -p                                                */
/* ------------------------------------------------------------------ */
static int mkdirs(const char *path) {
    char tmp[4096];
    size_t len = strlen(path);

    if (len == 0 || len >= sizeof(tmp))
        return -1;

    memcpy(tmp, path, len + 1);

    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\' || tmp[i] == '\0') {
            char saved = tmp[i];
            tmp[i] = '\0';

            if (MKDIR(tmp) != 0 && errno != EEXIST) {
                if (errno != ENOENT) {
                    fprintf(stderr, "[export] mkdir '%s': %s\n",
                            tmp, strerror(errno));
                }
            }

            tmp[i] = saved;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Build output path                                                 */
/* ------------------------------------------------------------------ */
static void build_pyc_path(char *out, size_t cap,
                           const char *base_dir,
                           const char *module_name,
                           const char *file_suffix) {
    char modpath[1024];
    size_t ml = strlen(module_name);
    size_t start = 0;

    if (ml >= sizeof(modpath))
        ml = sizeof(modpath) - 1;

    if (module_name[0] == '.') {
        modpath[0] = '_';
        start = 1;
    }

    for (size_t i = start; i < ml; i++) {
        modpath[i] = (module_name[i] == '.') ? PATH_SEP : module_name[i];
    }
    modpath[ml] = '\0';

    snprintf(out, cap, "%s%c%s%s",
             base_dir, PATH_SEP, modpath, file_suffix);
}

/* ------------------------------------------------------------------ */
/*  Write one .pyc                                                    */
/* ------------------------------------------------------------------ */
static int write_pyc(const char *pyc_path,
                     const uint8_t *marshal_data, size_t marshal_len,
                     uint32_t magic) {
    char dir[4096];
    FILE *f;
    uint32_t flags    = 0;
    uint32_t mtime    = 0;
    uint32_t src_size = 0;

    snprintf(dir, sizeof(dir), "%s", pyc_path);
    {
        char *last = strrchr(dir, PATH_SEP);
        if (last) {
            *last = '\0';
            mkdirs(dir);
        }
    }

    f = fopen(pyc_path, "wb");
    if (!f) {
        fprintf(stderr, "[export] Cannot write '%s': %s\n",
                pyc_path, strerror(errno));
        return -1;
    }

    fwrite(&magic,    4, 1, f);
    fwrite(&flags,    4, 1, f);
    fwrite(&mtime,    4, 1, f);
    fwrite(&src_size, 4, 1, f);
    fwrite(marshal_data, 1, marshal_len, f);
    fclose(f);

    printf("[export] %-60s (%zu bytes marshal)\n", pyc_path, marshal_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Raw constant scanner                                              */
/* ------------------------------------------------------------------ */
static const uint8_t *skip_one(const uint8_t *p, const uint8_t *end);

static const uint8_t *skip_n(const uint8_t *p, const uint8_t *end, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        p = skip_one(p, end);
        if (!p) return NULL;
    }
    return p;
}

static const uint8_t *skip_one(const uint8_t *p, const uint8_t *end) {
    if (p >= end) return NULL;
    char tag = (char)*p++;

    switch (tag) {
    case 'n': case 't': case 'F': case 's': case 'p':
        return p;

    case 'l': case 'q':
        ex_varint(&p);
        return p;

    case 'G': case 'g': {
        uint64_t nc = ex_varint(&p);
        for (uint64_t i = 0; i < nc; i++) ex_varint(&p);
        return p;
    }

    case 'f':
        return (p + 8 <= end) ? p + 8 : NULL;

    case 'Z':
        return (p + 1 <= end) ? p + 1 : NULL;

    case 'j':
        return (p + 16 <= end) ? p + 16 : NULL;

    case 'J':
        return skip_n(p, end, 2);

    case 'c': case 'u': case 'a':
        while (p < end && *p) p++;
        return (p < end) ? p + 1 : NULL;

    case 'd': case 'w':
        return (p + 1 <= end) ? p + 1 : NULL;

    case 'b': case 'B': case 'v': {
        uint64_t l = ex_varint(&p);
        return (p + l <= end) ? p + l : NULL;
    }

    case 'T': case 'L': case 'S': case 'P':
        return skip_n(p, end, ex_varint(&p));

    case ':': case ';':
        return skip_n(p, end, 3);

    case 'D': {
        uint64_t n = ex_varint(&p);
        const uint8_t *mid = skip_n(p, end, n);
        return mid ? skip_n(mid, end, n) : NULL;
    }

    case 'A':
        return skip_n(p, end, 2);

    case 'H':
        return skip_n(p, end, 1);

    case 'M': case 'Q':
        return (p + 1 <= end) ? p + 1 : NULL;

    case 'O': case 'E':
        while (p < end && *p) p++;
        return (p < end) ? p + 1 : NULL;

    case 'X': {
        uint64_t l = ex_varint(&p);
        return (p + l <= end) ? p + l : NULL;
    }

    case 'C': {
        uint64_t flags = ex_varint(&p);
        uint64_t fb = 1;

        p = skip_one(p, end);
        if (!p) return NULL;
        ex_varint(&p);

        p = skip_one(p, end);
        if (!p) return NULL;
        ex_varint(&p);

        if (flags & fb) {
            p = skip_one(p, end);
            if (!p) return NULL;
        }
        fb <<= 1;

        if (flags & fb) {
            p = skip_one(p, end);
            if (!p) return NULL;
        }
        fb <<= 1;

        if (flags & fb) ex_varint(&p);
        fb <<= 1;
        if (flags & fb) ex_varint(&p);

        return p;
    }

    default:
        return NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  String helpers                                                    */
/* ------------------------------------------------------------------ */
static bool get_str_val(const uint8_t *tag_ptr, const uint8_t *end,
                        char *buf, size_t cap) {
    if (!tag_ptr || tag_ptr >= end || !buf || cap == 0) return false;

    {
        char tag = (char)*tag_ptr++;
        if (tag == 'u' || tag == 'a' || tag == 'c') {
            size_t i = 0;
            while (tag_ptr < end && *tag_ptr && i + 1 < cap)
                buf[i++] = (char)*tag_ptr++;
            buf[i] = '\0';
            return i > 0;
        }
        if (tag == 'v') {
            uint64_t l = ex_varint(&tag_ptr);
            size_t cp = (l < cap - 1) ? (size_t)l : cap - 1;
            memcpy(buf, tag_ptr, cp);
            buf[cp] = '\0';
            return cp > 0;
        }
        if (tag == 'w' || tag == 'd') {
            buf[0] = (char)*tag_ptr;
            buf[1] = '\0';
            return true;
        }
    }

    return false;
}

static bool normalize_module_name(const char *src, char *out, size_t cap) {
    char work[1024];
    char *tokens[64];
    size_t token_count = 0;
    size_t i, n, start, end, keep_from;
    bool saw_sep = false;

    if (!src || !*src || !out || cap == 0) return false;

    while (*src == ' ' || *src == '\t' || *src == '\r' || *src == '\n')
        src++;

    n = strlen(src);
    while (n > 0 &&
           (src[n - 1] == ' ' || src[n - 1] == '\t' ||
            src[n - 1] == '\r' || src[n - 1] == '\n'))
        n--;

    if (n == 0 || n >= sizeof(work)) return false;

    memcpy(work, src, n);
    work[n] = '\0';

    if (n > 4 && strcmp(work + n - 4, ".pyc") == 0) {
        work[n - 4] = '\0';
        n -= 4;
    } else if (n > 3 && strcmp(work + n - 3, ".py") == 0) {
        work[n - 3] = '\0';
        n -= 3;
    }

    start = 0;
    for (i = 0; i <= n; i++) {
        char c = work[i];
        if (c == '/' || c == '\\' || c == '.' || c == '\0') {
            if (c == '/' || c == '\\')
                saw_sep = true;
            end = i;
            if (end > start) {
                char *tok = work + start;
                size_t j;
                int valid = 1;

                if (!(isalpha((unsigned char)tok[0]) || tok[0] == '_'))
                    valid = 0;

                for (j = 1; j < end - start && valid; j++) {
                    unsigned char ch = (unsigned char)tok[j];
                    if (!(isalnum(ch) || ch == '_'))
                        valid = 0;
                }

                if (valid && token_count < 64) {
                    work[end] = '\0';
                    tokens[token_count++] = tok;
                }
            }
            start = i + 1;
        }
    }

    if (token_count == 0) return false;

    keep_from = (saw_sep && token_count > 4) ? (token_count - 4) : 0;

    out[0] = '\0';
    for (i = keep_from; i < token_count; i++) {
        size_t cur = strlen(out);
        size_t add = strlen(tokens[i]);

        if (cur + (cur ? 1 : 0) + add + 1 >= cap)
            return cur > 0;

        if (cur) out[cur++] = '.';
        memcpy(out + cur, tokens[i], add + 1);
    }

    return out[0] != '\0';
}

static bool extract_module_name_from_blob(const uint8_t *data, size_t len,
                                          char *out, size_t cap) {
    char best[512];
    int best_score = -1;
    size_t i = 0;

    if (!data || !len || !out || cap == 0) return false;

    best[0] = '\0';

    while (i < len) {
        size_t j = i;
        while (j < len && data[j] >= 0x20 && data[j] <= 0x7e)
            j++;

        if (j > i + 3) {
            size_t slen = j - i;
            if (slen < 1024) {
                char s[1024];
                char norm[512];
                int score = 0;

                memcpy(s, data + i, slen);
                s[slen] = '\0';

                if (normalize_module_name(s, norm, sizeof(norm))) {
                    if (strstr(s, ".pyc")) score += 200;
                    else if (strstr(s, ".py")) score += 180;
                    if (strchr(s, '/') || strchr(s, '\\')) score += 80;
                    if (strchr(s, '.')) score += 40;
                    score += (int)strlen(norm);

                    if (score > best_score) {
                        best_score = score;
                        strncpy(best, norm, sizeof(best) - 1);
                        best[sizeof(best) - 1] = '\0';
                    }
                }
            }
        }

        i = (j == i) ? (i + 1) : (j + 1);
    }

    if (best_score < 0) return false;

    strncpy(out, best, cap - 1);
    out[cap - 1] = '\0';
    return true;
}

/* ------------------------------------------------------------------ */
/*  Embedded Python / remarshal                                       */
/* ------------------------------------------------------------------ */
typedef struct {
    bool initialized_here;
} MarshalRuntime;

static int marshal_runtime_init(MarshalRuntime *rt) {
    if (!rt) return -1;
    memset(rt, 0, sizeof(*rt));

    if (!Py_IsInitialized()) {
        Py_Initialize();
        if (!Py_IsInitialized()) {
            fprintf(stderr, "[marshal] Py_Initialize() failed\n");
            return -1;
        }
        rt->initialized_here = true;
    }

    return 0;
}

static void marshal_runtime_fini(MarshalRuntime *rt) {
    if (!rt) return;
    if (rt->initialized_here) {
        Py_Finalize();
        rt->initialized_here = false;
    }
}

static void py_print_utf8_attr(PyObject *obj, const char *attr_name,
                               const char *label) {
    PyObject *attr = PyObject_GetAttrString(obj, attr_name);
    if (!attr) {
        PyErr_Clear();
        return;
    }

    if (PyUnicode_Check(attr)) {
        const char *s = PyUnicode_AsUTF8(attr);
        if (s && *s)
            fprintf(stdout, " %s=%s", label, s);
        else
            PyErr_Clear();
    }

    Py_DECREF(attr);
}

static void report_marshaled_object(const char *name, PyObject *obj,
                                    size_t blob_len) {
    fprintf(stdout, "[marshal] %-36s len=%zu type=%s",
            name ? name : "<blob>", blob_len,
            obj ? Py_TYPE(obj)->tp_name : "<null>");

    if (obj && PyCode_Check(obj)) {
        py_print_utf8_attr(obj, "co_name", "co_name");
        py_print_utf8_attr(obj, "co_filename", "co_filename");
    }

    fputc('\n', stdout);
}

static int marshal_remarshal_blob(MarshalRuntime *rt,
                                  const uint8_t *blob_data,
                                  size_t blob_len,
                                  const char *blob_name,
                                  uint8_t **out_data,
                                  size_t *out_len) {
    PyObject *loaded = NULL;
    PyObject *bytes_obj = NULL;
    char *buf = NULL;
    Py_ssize_t n = 0;

    (void)rt;

    if (!blob_data || !out_data || !out_len)
        return -1;

    *out_data = NULL;
    *out_len = 0;

    loaded = PyMarshal_ReadObjectFromString((const char *)blob_data,
                                            (Py_ssize_t)blob_len);
    if (!loaded) {
        fprintf(stderr, "[marshal] PyMarshal_ReadObjectFromString failed for %s\n",
                blob_name ? blob_name : "<blob>");
        PyErr_Print();
        return -1;
    }

    report_marshaled_object(blob_name, loaded, blob_len);

    bytes_obj = PyMarshal_WriteObjectToString(loaded, Py_MARSHAL_VERSION);
    Py_DECREF(loaded);

    if (!bytes_obj) {
        fprintf(stderr, "[marshal] PyMarshal_WriteObjectToString failed for %s\n",
                blob_name ? blob_name : "<blob>");
        PyErr_Print();
        return -1;
    }

    if (!PyBytes_Check(bytes_obj)) {
        fprintf(stderr, "[marshal] remarshal result is not bytes for %s\n",
                blob_name ? blob_name : "<blob>");
        Py_DECREF(bytes_obj);
        return -1;
    }

    if (PyBytes_AsStringAndSize(bytes_obj, &buf, &n) != 0) {
        fprintf(stderr, "[marshal] PyBytes_AsStringAndSize failed for %s\n",
                blob_name ? blob_name : "<blob>");
        PyErr_Print();
        Py_DECREF(bytes_obj);
        return -1;
    }

    *out_data = (uint8_t *)malloc((size_t)n);
    if (!*out_data) {
        Py_DECREF(bytes_obj);
        return -1;
    }

    memcpy(*out_data, buf, (size_t)n);
    *out_len = (size_t)n;

    Py_DECREF(bytes_obj);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  BlobCtx view                                                      */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  *raw;
    size_t    raw_len;
    uint8_t  *decrypted;
    const uint8_t *payload;
    size_t    payload_len;
    const uint8_t *section_ptr;
    uint32_t  section_size;
} BlobCtxView;

/* ------------------------------------------------------------------ */
/*  Main walk                                                         */
/* ------------------------------------------------------------------ */
int blob_export_all_pyc(BlobCtx *ctx_opaque,
                        const char *output_dir,
                        unsigned int py_version) {
    BlobCtxView *ctx = (BlobCtxView *)ctx_opaque;
    MarshalRuntime rt;
    const uint8_t *toc_p;
    const uint8_t *toc_end;
    int total_written = 0;
    int section_idx = 0;
    unsigned int actual_pyver;
    uint32_t magic;

    if (!ctx || !ctx->payload) {
        fprintf(stderr, "[export] Call blob_verify() first.\n");
        return -1;
    }

    if (!output_dir || !*output_dir)
        output_dir = "output";

    mkdirs(output_dir);

    actual_pyver = py_version ? py_version : 0x3c0; /* default Python 3.12 */
    magic = pyc_magic(actual_pyver);

    if (marshal_runtime_init(&rt) != 0)
        return -1;

    toc_p = ctx->payload;
    toc_end = ctx->payload + ctx->payload_len;

    printf("\n[export] Scanning all sections for 'X' blobs...\n");

    while (toc_p < toc_end && *toc_p != 0) {
        const char *section_name = (const char *)toc_p;
        const uint8_t *sec_start;
        const uint8_t *sec_end;
        const uint8_t *p;
        char last_str[1024] = {0};
        uint16_t count;
        uint32_t section_bytes;
        int x_count = 0;
        bool is_bytecode_section;

        toc_p = ex_skip_cstr(toc_p);
        if (toc_p + 4 > toc_end) break;

        section_bytes = ex_read_u32(&toc_p);
        sec_start = toc_p;
        sec_end = toc_p + section_bytes;
        toc_p += section_bytes;

        if (sec_end > toc_end) {
            fprintf(stderr, "[export] section '%s' overruns payload\n", section_name);
            break;
        }
        if (sec_start + 2 > sec_end) {
            section_idx++;
            continue;
        }

        count = ex_read_u16(&sec_start);
        p = sec_start;
        is_bytecode_section = (strcmp(section_name, ".bytecode") == 0);

        printf("[export] Section [%2d] %-35s %u consts %u bytes\n",
               section_idx, section_name, count, section_bytes);

        for (uint16_t ci = 0; ci < count && p < sec_end; ci++) {
            const uint8_t *const_start = p;
            char tag;

            if (p >= sec_end) break;
            tag = (char)*p;

            if (tag == 'X') {
                uint64_t blob_len;
                const uint8_t *blob_data;
                char blob_name[512] = {0};
                char pyc_path[4096];
                uint8_t *remarshal_data = NULL;
                size_t remarshal_len = 0;

                p++;
                blob_len = ex_varint(&p);
                if (p + blob_len > sec_end) {
                    fprintf(stderr, "[export] 'X' blob overruns section '%s'\n",
                            section_name);
                    break;
                }

                blob_data = p;
                p += blob_len;

                if (is_bytecode_section) {
                    if (!(last_str[0] &&
                          normalize_module_name(last_str, blob_name, sizeof(blob_name))) &&
                        !extract_module_name_from_blob(blob_data, (size_t)blob_len,
                                                       blob_name, sizeof(blob_name))) {
                        snprintf(blob_name, sizeof(blob_name),
                                 "_bytecode_%d_%d", section_idx, x_count);
                    }
                    build_pyc_path(pyc_path, sizeof(pyc_path),
                                   output_dir, blob_name, ".pyc");
                } else {
                    if (x_count == 0) {
                        build_pyc_path(pyc_path, sizeof(pyc_path),
                                       output_dir, section_name, ".pyc");
                        snprintf(blob_name, sizeof(blob_name), "%s", section_name);
                    } else {
                        char suffix[32];
                        snprintf(suffix, sizeof(suffix), ".%d.pyc", x_count);
                        build_pyc_path(pyc_path, sizeof(pyc_path),
                                       output_dir, section_name, suffix);
                        snprintf(blob_name, sizeof(blob_name), "%s#%d",
                                 section_name, x_count);
                    }
                }

                if (marshal_remarshal_blob(&rt, blob_data, (size_t)blob_len,
                                           blob_name,
                                           &remarshal_data, &remarshal_len) == 0) {
                    if (write_pyc(pyc_path, remarshal_data, remarshal_len, magic) == 0) {
                        total_written++;
                    }
                }

                free(remarshal_data);
                x_count++;
                last_str[0] = '\0';
            } else {
                const uint8_t *next;
                get_str_val(const_start, sec_end, last_str, sizeof(last_str));
                next = skip_one(const_start, sec_end);
                if (!next) {
                    fprintf(stderr,
                            "[export] skip_one failed at section '%s' const #%u tag=0x%02X\n",
                            section_name, ci, (unsigned int)(uint8_t)tag);
                    break;
                }
                p = next;
            }
        }

        section_idx++;
    }

    printf("\n[export] Done. %d .pyc file(s) written to '%s'\n\n",
           total_written, output_dir);

    marshal_runtime_fini(&rt);
    return total_written;
}

/* Optional alias */
int blob_load_all_marshal(BlobCtx *ctx_opaque) {
    return blob_export_all_pyc(ctx_opaque, "output", 0x3c0);
}
