#include "blob_loader.h"
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
#  include <io.h>
#  include <process.h>
#  include <windows.h>
#  define MKDIR(p) _mkdir(p)
#  define PATH_SEP '\\'
#else
#  include <unistd.h>
#  include <sys/wait.h>
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
    char work[4096];
    char *tokens[256];
    size_t token_count = 0;
    size_t i, n, start, end;

    if (!src || !*src || !out || cap == 0) return false;

    /* strip leading/trailing whitespace */
    while (*src == ' ' || *src == '\t' || *src == '\r' || *src == '\n')
        src++;

    n = strlen(src);
    while (n > 0 &&
           (src[n-1] == ' ' || src[n-1] == '\t' ||
            src[n-1] == '\r' || src[n-1] == '\n'))
        n--;

    if (n == 0 || n >= sizeof(work)) return false;

    memcpy(work, src, n);
    work[n] = '\0';

    /* strip .pyc / .py extension */
    if (n > 4 && strcmp(work + n - 4, ".pyc") == 0) {
        work[n - 4] = '\0'; n -= 4;
    } else if (n > 3 && strcmp(work + n - 3, ".py") == 0) {
        work[n - 3] = '\0'; n -= 3;
    }

    /* split on / \\ . and validate every token individually.
       If ANY token is invalid the whole name is rejected --
       no silent dropping of components. */
    start = 0;
    for (i = 0; i <= n; i++) {
        char c = work[i];
        if (c == '/' || c == '\\' || c == '.' || c == '\0') {
            end = i;
            if (end > start) {
                char *tok = work + start;
                size_t tlen = end - start;
                size_t j;

                /* first char: letter or underscore */
                if (!(isalpha((unsigned char)tok[0]) || tok[0] == '_'))
                    return false;

                /* remaining: alnum or underscore */
                for (j = 1; j < tlen; j++) {
                    unsigned char ch = (unsigned char)tok[j];
                    if (!(isalnum(ch) || ch == '_'))
                        return false;
                }

                if (token_count >= 256) return false;
                work[end] = '\0';
                tokens[token_count++] = tok;
            }
            start = i + 1;
        }
    }

    if (token_count == 0) return false;

    /* join all tokens with '.' -- no truncation, full path preserved */
    out[0] = '\0';
    for (i = 0; i < token_count; i++) {
        size_t cur = strlen(out);
        size_t add = strlen(tokens[i]);

        if (cur + (cur ? 1 : 0) + add + 1 >= cap)
            return false;   /* buffer too small: reject cleanly */

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
/*  Filesystem helpers                                                */
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

static int ensure_parent_dir(const char *path) {
    char dir[4096];
    char *last;

    snprintf(dir, sizeof(dir), "%s", path);
    last = strrchr(dir, PATH_SEP);
    if (!last) return 0;

    *last = '\0';
    return mkdirs(dir);
}

static int write_binary_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f;
    if (ensure_parent_dir(path) != 0) {
        fprintf(stderr, "[export] failed to create parent dir for '%s'\n", path);
        return -1;
    }

    f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[export] Cannot write '%s': %s\n", path, strerror(errno));
        return -1;
    }

    if (len && fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "[export] short write to '%s'\n", path);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Helper invocation                                                 */
/* ------------------------------------------------------------------ */
static int file_exists(const char *path) {
#ifdef _WIN32
    return _access(path, 0) == 0;
#else
    return access(path, F_OK) == 0;
#endif
}

static void path_dirname_inplace(char *s) {
    size_t n = strlen(s);
    while (n > 0) {
        if (s[n - 1] == '/' || s[n - 1] == '\\') {
            s[n - 1] = '\0';
            return;
        }
        n--;
    }
    s[0] = '\0';
}

static void join_path(char *out, size_t cap, const char *a, const char *b) {
    if (!a || !*a) {
        snprintf(out, cap, "%s", b ? b : "");
        return;
    }
    snprintf(out, cap, "%s%c%s", a, PATH_SEP, b ? b : "");
}

static int get_exe_dir(char *out, size_t cap) {
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    if (n == 0 || n >= cap) return -1;
    out[n] = '\0';
    path_dirname_inplace(out);
    return 0;
#else
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0 || (size_t)n >= cap) return -1;
    out[n] = '\0';
    path_dirname_inplace(out);
    return 0;
#endif
}

static int locate_helper(char *helper_path, size_t cap) {
    char exe_dir[4096];

    if (get_exe_dir(exe_dir, sizeof(exe_dir)) == 0) {
        join_path(helper_path, cap, exe_dir, "pyc_helper.py");
        if (file_exists(helper_path))
            return 0;
    }

    snprintf(helper_path, cap, "pyc_helper.py");
    if (file_exists(helper_path))
        return 0;

    return -1;
}

static int run_helper_dir(const char *helper_path,
                          const char *stage_dir,
                          const char *output_dir) {
#ifdef _WIN32
    intptr_t rc = _spawnlp(_P_WAIT,
                           "py",
                           "py",
                           "-3.12",
                           helper_path,
                           stage_dir,
                           output_dir,
                           NULL);
    if (rc == -1) {
        fprintf(stderr, "[export] failed to run folder helper: py -3.12 %s\n", helper_path);
        return -1;
    }
    return (int)rc;
#else
    pid_t pid = fork();
    int status = 0;
    if (pid < 0) return -1;
    if (pid == 0) {
        execlp("python3.12", "python3.12", helper_path, stage_dir, output_dir, (char *)NULL);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
#endif
}

static int stage_blob_for_helper(const char *stage_raw_path,
                                 const uint8_t *marshal_data,
                                 size_t marshal_len) {
    if (write_binary_file(stage_raw_path, marshal_data, marshal_len) != 0)
        return -1;

    printf("[stage]  %-60s (%zu bytes marshal)\n", stage_raw_path, marshal_len);
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
    const uint8_t *toc_p;
    const uint8_t *toc_end;
    int total_staged = 0;
    int total_written = 0;
    int section_idx = 0;
    int helper_rc;
    char helper_path[4096];
    char stage_dir[4096];

    (void)py_version;

    if (!ctx || !ctx->payload) {
        fprintf(stderr, "[export] Call blob_verify() first.\n");
        return -1;
    }

    if (!output_dir || !*output_dir)
        output_dir = "output";

    mkdirs(output_dir);

    if (locate_helper(helper_path, sizeof(helper_path)) != 0) {
        fprintf(stderr, "[export] pyc_helper.py not found next to exe or in cwd\n");
        return -1;
    }

    snprintf(stage_dir, sizeof(stage_dir), "%s.rawstage", output_dir);
    mkdirs(stage_dir);

    toc_p = ctx->payload;
    toc_end = ctx->payload + ctx->payload_len;

    printf("\n[export] Using helper: %s\n", helper_path);
    printf("[export] Staging raw marshal blobs into: %s\n", stage_dir);
    printf("[export] Scanning all sections for 'X' blobs...\n");

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
                char stage_raw_path[4096];

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

                    build_pyc_path(stage_raw_path, sizeof(stage_raw_path),
                                   stage_dir, blob_name, ".pyc.rawmarshal");
                } else {
                    if (x_count == 0) {
                        snprintf(blob_name, sizeof(blob_name), "%s", section_name);
                        build_pyc_path(stage_raw_path, sizeof(stage_raw_path),
                                       stage_dir, section_name, ".pyc.rawmarshal");
                    } else {
                        char suffix[64];
                        snprintf(blob_name, sizeof(blob_name), "%s#%d",
                                 section_name, x_count);
                        snprintf(suffix, sizeof(suffix), ".%d.pyc.rawmarshal", x_count);
                        build_pyc_path(stage_raw_path, sizeof(stage_raw_path),
                                       stage_dir, section_name, suffix);
                    }
                }

                if (stage_blob_for_helper(stage_raw_path,
                                          blob_data,
                                          (size_t)blob_len) == 0) {
                    total_staged++;
                }

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

    helper_rc = run_helper_dir(helper_path, stage_dir, output_dir);
    if (helper_rc != 0) {
        fprintf(stderr,
                "\n[export] folder helper failed for '%s' -> '%s' (exit=%d)\n\n",
                stage_dir, output_dir, helper_rc);
        return -1;
    }

    total_written = total_staged;

    printf("\n[export] Done. %d staged blob(s) processed from '%s' into '%s'\n\n",
           total_written, stage_dir, output_dir);

    return total_written;
}

int blob_load_all_marshal(BlobCtx *ctx_opaque) {
    return blob_export_all_pyc(ctx_opaque, "output", 0);
}
