/*
 * blob_export.c
 *
 * Two features:
 *
 * 1. blob_hexdump()         – classic hex+ascii dump, usable anywhere.
 *
 * 2. blob_export_all_pyc()  – walks every TOC section, finds every 'X'
 * (raw marshal) blob, and assembles a proper .pyc file in memory
 * (Disk writing disabled as requested).
 *
 * .pyc file layout (Python 3.8+):
 * offset 0  uint32  magic number   (version-specific, see table below)
 * offset 4  uint32  flags          0 = timestamp-based validation
 * offset 8  uint32  source mtime   0 (unknown)
 * offset 12 uint32  source size    0 (unknown)
 * offset 16 bytes   raw marshal data from the 'X' blob
 *
 * Python magic numbers:
 * 3.8  → 0x0D0D550A   (3413 + CRLF)
 * 3.9  → 0x0D0D610A   (3425 + CRLF)
 * 3.10 → 0x0D0D6F0A   (3439 + CRLF)
 * 3.11 → 0x0D0DA70A   (3495 + CRLF)
 * 3.12 → 0x0D0DCB0A   (3531 + CRLF)
 * 3.13 → 0x0D0DF50A   (3557 + CRLF)
 *
 * Auto-detection heuristic (when py_version == 0):
 * We scan the marshal bytes for a TYPE_CODE (0x63) or TYPE_CODE|FLAG_REF
 * (0xE3) marker and look at the co_flags / nlocals fields to guess version.
 * If detection fails we default to 3.11 magic (most common Nuitka target).
 *
 * Section name → file path mapping:
 * "pkg.subpkg.mod"  → output_dir/pkg/subpkg/mod.pyc
 * ".bytecode"       → output_dir/.bytecode/<filename_or_index>.pyc
 * "__main__"        → output_dir/__main__.pyc
 *
 * For .bytecode section: the constant immediately before each 'X' that is
 * a string (tag 'u','a','v','c','w') is used as the file path.  If no string
 * precedes an 'X', we fall back to ".bytecode_<N>.pyc".
 */

#include "blob_loader.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

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
/* Forward-declare what we need from blob_loader.c internals           */
/* ------------------------------------------------------------------ */
/* We expose the internal blob format via a thin shim — the raw payload
   pointer and length are accessible through the opaque BlobCtx only via
   blob_verify/blob_find_section. We replicate the tiny primitives here. */

static uint16_t ex_read_u16(const uint8_t **p) {
    uint16_t v; memcpy(&v,*p,2); *p+=2; return v;
}
static uint32_t ex_read_u32(const uint8_t **p) {
    uint32_t v; memcpy(&v,*p,4); *p+=4; return v;
}
static uint64_t ex_varint(const uint8_t **p) {
    uint64_t r=0, f=1;
    for(;;){ uint8_t b=**p; (*p)++; r+=(b&0x7F)*f; if(b<0x80) break; f<<=7; }
    return r;
}
static const uint8_t *ex_skip_cstr(const uint8_t *p){ while(*p) p++; return p+1; }

/* ------------------------------------------------------------------ */
/* Hex dump                                                             */
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
/* Python magic number table                                            */
/* ------------------------------------------------------------------ */
static uint32_t pyc_magic(unsigned int py_ver) {
    /* Format: little-endian uint32
       Each value = (minor_magic << 16) | 0x00000D0A  ... no, actually:
       cpython encodes as: magic_int.to_bytes(2,'little') + b'\r\n'
       So uint32LE = magic_int | (0x0D0A << 16)                         */
    switch (py_ver & 0xFF0) {
    case 0x380: return 0x0D0D550A; /* 3413 */
    case 0x390: return 0x0D0D610A; /* 3425 */
    case 0x3a0: return 0x0D0D6F0A; /* 3439 */
    case 0x3b0: return 0x0D0DA70A; /* 3495 */
    case 0x3c0: return 0x0D0DCB0A; /* 3531 */
    case 0x3d0: return 0x0D0DF50A; /* 3557 */
    default:    return 0x0D0DA70A; /* default: 3.11 */
    }
}

/* ------------------------------------------------------------------ */
/* Auto-detect Python version from marshal stream                      */
/* */
/* The marshal format changed significantly between versions.           */
/* We use a heuristic: look at the second 4-byte field of a code       */
/* object (nlocals in 3.8-3.10, argcount+kwonlycount in 3.11+).        */
/* In practice, for most compiled outputs, defaulting to 3.11 is safe. */
/* ------------------------------------------------------------------ */
static unsigned int autodetect_pyver(const uint8_t *data, size_t len) {
    if (len < 4) return 0x3b0;
    /* First byte of a marshal code object */
    uint8_t first = data[0];
    if (first != 0x63 && first != 0xE3) {
        /* Not a code object at top level — can't detect */
        return 0x3b0;
    }
    /* In Python 3.11+ the code object layout changed radically.
       If byte 1..4 look like a valid small integer for argcount we assume >=3.11.
       This is a rough heuristic; override with --pyver if wrong. */
    uint32_t field1;
    memcpy(&field1, data + 1, 4);
    if (field1 > 0xFFFF) {
        /* Implausibly large argcount → probably 3.8-3.10 nlocals field */
        return 0x3a0;
    }
    return 0x3b0; /* default 3.11 */
}

/* ------------------------------------------------------------------ */
/* Directory creation (recursive mkdir -p)                             */
/* (Retained for completeness, unused in in-memory mode)               */
/* ------------------------------------------------------------------ */
static int mkdirs(const char *path) {
    char tmp[4096];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);

    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\' || tmp[i] == '\0') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (MKDIR(tmp) != 0 && errno != EEXIST) {
                /* Ignore ENOENT on root slash */
                if (errno != ENOENT) {
                    fprintf(stderr, "[export] mkdir '%s': %s\n", tmp, strerror(errno));
                    /* don't fatal — might already exist */
                }
            }
            tmp[i] = saved;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Build output path from module name                                   */
/* */
/* "pkg.sub.mod"  → output_dir/pkg/sub/mod.pyc                        */
/* ".bytecode"    → output_dir/_bytecode/  (prefix dot → underscore)  */
/* "__main__"     → output_dir/__main__.pyc                            */
/* ------------------------------------------------------------------ */
static void build_pyc_path(char *out, size_t cap,
                           const char *base_dir,
                           const char *module_name,
                           const char *file_suffix) {
    /* Replace dots with path separators in module name,
       but NOT the leading dot in ".bytecode" */
    char modpath[1024];
    size_t ml = strlen(module_name);
    if (ml >= sizeof(modpath)) ml = sizeof(modpath) - 1;

    size_t start = 0;
    /* If name starts with '.', replace with '_' to avoid hidden dirs */
    if (module_name[0] == '.') {
        modpath[0] = '_';
        start = 1;
    }
    for (size_t i = start; i < ml; i++) {
        modpath[i] = (module_name[i] == '.') ? PATH_SEP : module_name[i];
    }
    modpath[ml] = '\0';

    snprintf(out, cap, "%s%c%s%s", base_dir, PATH_SEP, modpath, file_suffix);
}

/* ------------------------------------------------------------------ */
/* Process one .pyc in memory (No disk write)                          */
/* ------------------------------------------------------------------ */
static int process_pyc_in_memory(const char *pyc_path,
                     const uint8_t *marshal_data, size_t marshal_len,
                     uint32_t magic) {
    /* .pyc header */
    uint32_t flags    = 0;   /* timestamp-based validation */
    uint32_t mtime    = 0;
    uint32_t src_size = 0;

    size_t pyc_size = 16 + marshal_len;
    uint8_t *pyc_buf = (uint8_t *)malloc(pyc_size);
    if (!pyc_buf) {
        fprintf(stderr, "[export] Allocation failed for '%s'\n", pyc_path);
        return -1;
    }

    /* Assemble PYC file structure in memory */
    memcpy(pyc_buf, &magic, 4);
    memcpy(pyc_buf + 4, &flags, 4);
    memcpy(pyc_buf + 8, &mtime, 4);
    memcpy(pyc_buf + 12, &src_size, 4);
    memcpy(pyc_buf + 16, marshal_data, marshal_len);

    /* We skip creating the hex side-car as well to completely avoid disk IO */
    printf("[export] IN-MEMORY ASSEMBLED: %-60s  (%zu bytes marshal, %zu bytes total)\n", 
           pyc_path, marshal_len, pyc_size);

    /* Free the buffer. If you need to interface with this buffer later, 
       you could return pyc_buf instead of freeing it. */
    free(pyc_buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Section-level raw constant scanner                                   */
/* */
/* We need to find 'X' blobs inside a section WITHOUT fully decoding   */
/* nested constants (to avoid needing the full recursive decoder here). */
/* Instead we do a linear scan tracking only:                           */
/* • the immediately-preceding string value (for naming)             */
/* • the 'X' blob start + size                                        */
/* */
/* This is done with a minimal tag-skip routine that understands all    */
/* tag widths — it doesn't build a BlobVal tree, just skips.           */
/* ------------------------------------------------------------------ */

/* Returns pointer just past the consumed constant, or NULL on error. */
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
    /* zero-width singletons */
    case 'n': case 't': case 'F': case 's': case 'p':
        return p;
    /* varint */
    case 'l': case 'q': ex_varint(&p); return p;
    /* bigint: varint count, then count varints */
    case 'G': case 'g': { uint64_t nc=ex_varint(&p); for(uint64_t i=0;i<nc;i++) ex_varint(&p); return p; }
    /* 8-byte float */
    case 'f': return (p+8<=end) ? p+8 : NULL;
    /* 1-byte sub-tag float */
    case 'Z': return (p+1<=end) ? p+1 : NULL;
    /* two 8-byte floats */
    case 'j': return (p+16<=end) ? p+16 : NULL;
    /* complex via 2 children */
    case 'J': return skip_n(p, end, 2);
    /* zero-terminated strings */
    case 'c': case 'u': case 'a':
        while (p < end && *p) p++; 
        return (p<end) ? p+1 : NULL;
    /* 1-byte */
    case 'd': case 'w': return (p+1<=end) ? p+1 : NULL;
    /* length-prefixed */
    case 'b': case 'B': case 'v': { uint64_t l=ex_varint(&p); return (p+l<=end)?p+l:NULL; }
    /* containers */
    case 'T': case 'L': case 'S': case 'P': return skip_n(p, end, ex_varint(&p));
    case ':': case ';': return skip_n(p, end, 3);
    case 'D': { uint64_t n=ex_varint(&p); return skip_n(skip_n(p,end,n), end, n); }
    case 'A': return skip_n(p, end, 2);
    case 'H': return skip_n(p, end, 1);
    /* builtins by index */
    case 'M': case 'Q': return (p+1<=end) ? p+1 : NULL;
    /* builtins by name */
    case 'O': case 'E':
        while (p<end && *p) p++;
        return (p<end)?p+1:NULL;
    /* 'X' raw blob — caller handles; we skip here */
    case 'X': { uint64_t l=ex_varint(&p); return (p+l<=end)?p+l:NULL; }
    /* 'C' code object — skip all fields manually */
    case 'C': {
        uint64_t flags = ex_varint(&p);
        p = skip_one(p, end);   /* function_name */
        if (!p) return NULL;
        ex_varint(&p);          /* line_number */
        p = skip_one(p, end);   /* arg_names */
        if (!p) return NULL;
        ex_varint(&p);          /* arg_count */
        uint64_t fb = 1;
        if (flags & fb) { p = skip_one(p, end); if(!p) return NULL; } fb <<= 1; /* qualname */
        if (flags & fb) { p = skip_one(p, end); if(!p) return NULL; } fb <<= 1; /* free_vars */
        if (flags & fb) { ex_varint(&p); } fb <<= 1; /* kw_only */
        if (flags & fb) { ex_varint(&p); }            /* pos_only */
        return p;
    }
    default: return NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Get the string value of a zero-terminated str tag ('u','a','c')     */
/* ------------------------------------------------------------------ */
static bool get_str_val(const uint8_t *tag_ptr, const uint8_t *end,
                        char *buf, size_t cap) {
    if (tag_ptr >= end) return false;
    char tag = (char)*tag_ptr++;
    if (tag == 'u' || tag == 'a' || tag == 'c') {
        size_t i = 0;
        while (tag_ptr < end && *tag_ptr && i + 1 < cap)
            buf[i++] = (char)*tag_ptr++;
        buf[i] = '\0';
        return i > 0;
    }
    if (tag == 'v') {   /* length-prefixed */
        uint64_t l = ex_varint(&tag_ptr);
        size_t cp = (l < cap - 1) ? (size_t)l : cap - 1;
        memcpy(buf, tag_ptr, cp); buf[cp] = '\0';
        return cp > 0;
    }
    if (tag == 'w' || tag == 'd') {   /* 1-char */
        buf[0] = (char)*tag_ptr; buf[1] = '\0';
        return true;
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
    while (n > 0 && (src[n - 1] == ' ' || src[n - 1] == '\t' || src[n - 1] == '\r' || src[n - 1] == '\n'))
        n--;

    if (n == 0 || n >= sizeof(work))
        return false;

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

    if (token_count == 0)
        return false;

    if (saw_sep && token_count > 4)
        keep_from = token_count - 4;
    else
        keep_from = 0;

    out[0] = '\0';
    for (i = keep_from; i < token_count; i++) {
        size_t cur = strlen(out);
        size_t add = strlen(tokens[i]);
        if (cur + (cur ? 1 : 0) + add + 1 >= cap)
            return cur > 0;
        if (cur)
            out[cur++] = '.';
        memcpy(out + cur, tokens[i], add + 1);
    }

    return out[0] != '\0';
}

static bool extract_module_name_from_blob(const uint8_t *data, size_t len,
                                          char *out, size_t cap) {
    char best[512];
    int best_score = -1;
    size_t i = 0;

    if (!data || !len || !out || cap == 0)
        return false;

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

    if (best_score < 0)
        return false;

    strncpy(out, best, cap - 1);
    out[cap - 1] = '\0';
    return true;
}

/* ------------------------------------------------------------------ */
/* Main export function                                                 */
/* ------------------------------------------------------------------ */

/* We expose the payload pointer through a private accessor.
   Since blob_loader.c and blob_export.c share the same BlobCtx struct
   definition (via blob_loader.h), we can just cast — but BlobCtx is
   opaque in the header.  We duplicate the minimal fields we need via
   a local view struct. */

/* This MUST match the struct in blob_loader.c exactly. */
typedef struct {
    uint8_t  *raw;
    size_t    raw_len;
    uint8_t  *decrypted;
    const uint8_t *payload;
    size_t    payload_len;
    const uint8_t *section_ptr;
    uint32_t  section_size;
} BlobCtxView;

int blob_export_all_pyc(BlobCtx *ctx_opaque,
                        const char *output_dir,
                        unsigned int py_version) {
    BlobCtxView *ctx = (BlobCtxView *)ctx_opaque;

    if (!ctx->payload) {
        fprintf(stderr, "[export] Call blob_verify() first.\n");
        return -1;
    }

    /* Create output root is skipped since we aren't writing to disk anymore */
    /* mkdirs(output_dir); */

    /* Auto-detect Python version if not specified */
    unsigned int actual_pyver = py_version;

    const uint8_t *toc_p   = ctx->payload;
    const uint8_t *toc_end = ctx->payload + ctx->payload_len;

    int total_written = 0;
    int section_idx   = 0;

    printf("\n[export] Scanning all sections for 'X' blobs (In-Memory Processing)...\n");

    /* ---- Walk TOC ---- */
    while (toc_p < toc_end && *toc_p != 0) {
        const char *section_name = (const char *)toc_p;
        toc_p = ex_skip_cstr(toc_p);
        if (toc_p + 4 > toc_end) break;

        uint32_t section_bytes = ex_read_u32(&toc_p);
        const uint8_t *sec_start = toc_p;
        const uint8_t *sec_end   = toc_p + section_bytes;
        toc_p += section_bytes;  /* advance TOC cursor regardless */

        if (sec_start + 2 > sec_end) { section_idx++; continue; }

        uint16_t count = ex_read_u16(&sec_start);
        /* sec_start now points to first constant in this section */

        printf("[export] Section [%2d] %-35s  %u consts  %u bytes\n",
               section_idx, section_name, count, section_bytes);

        bool is_bytecode_section = (strcmp(section_name, ".bytecode") == 0);

        /* Scan constants linearly, tracking last seen string */
        const uint8_t *p          = sec_start;
        char           last_str[1024] = {0};
        int            x_count    = 0;

        for (uint16_t ci = 0; ci < count && p < sec_end; ci++) {
            const uint8_t *const_start = p;
            if (p >= sec_end) break;
            char tag = (char)*p;

            if (tag == 'X') {
                /* ---- Found a bytecode blob ---- */
                p++;  /* consume tag */
                uint64_t blob_len = ex_varint(&p);
                if (p + blob_len > sec_end) {
                    fprintf(stderr, "[export] 'X' blob overruns section in '%s'\n", section_name);
                    break;
                }
                const uint8_t *blob_data = p;
                p += blob_len;

                /* Auto-detect Python version from first X blob seen */
                if (actual_pyver == 0 && blob_len > 0) {
                    actual_pyver = autodetect_pyver(blob_data, (size_t)blob_len);
                    printf("[export] Auto-detected Python version: 0x%03X\n", actual_pyver);
                }
                uint32_t magic = pyc_magic(actual_pyver ? actual_pyver : 0x3b0);

                /* Build output path */
                char pyc_path[4096];

                if (is_bytecode_section) {
                    char modname[512] = {0};
                    char suffix[32];

                    if (!(last_str[0] && normalize_module_name(last_str, modname, sizeof(modname))) &&
                        !extract_module_name_from_blob(blob_data, (size_t)blob_len, modname, sizeof(modname))) {
                        snprintf(modname, sizeof(modname),
                                 "_bytecode_%d_%d", section_idx, x_count);
                    }

                    if (x_count == 0) {
                        strcpy(suffix, ".pyc");
                    } else {
                        snprintf(suffix, sizeof(suffix), "__%d.pyc", x_count);
                    }

                    build_pyc_path(pyc_path, sizeof(pyc_path),
                                   output_dir, modname, suffix);
                } else {
                    /* One 'X' per non-.bytecode section = the module bytecode */
                    build_pyc_path(pyc_path, sizeof(pyc_path),
                                   output_dir, section_name,
                                   (x_count == 0) ? ".pyc"
                                   : (char[32]){[0]='.', [1]='0'+x_count, [2]='\0'});
                }

                if (process_pyc_in_memory(pyc_path, blob_data, (size_t)blob_len, magic) == 0) {
                    total_written++;
                    x_count++;
                }

                /* Reset last_str so it's not reused */
                last_str[0] = '\0';

            } else {
                /* Try to extract a string value for naming purposes */
                get_str_val(const_start, sec_end, last_str, sizeof(last_str));

                /* Skip this constant so cursor advances correctly */
                const uint8_t *next = skip_one(const_start, sec_end);
                if (!next) {
                    fprintf(stderr,
                        "[export] skip_one failed at section '%s' const #%u "
                        "tag=0x%02X\n",
                        section_name, ci, (uint8_t)tag);
                    break;
                }
                p = next;
            }
        }

        section_idx++;
    }

    printf("\n[export] Done. %d .pyc file(s) processed in-memory for '%s'\n\n",
           total_written, output_dir);
    return total_written;
}
