/*
 * main.c  --  Nuitka loader entry point with source + PyLingual bundle mode.
 *
 * Default behavior:
 *   1. Verify the RCDATA blob and dump the section TOC.
 *   2. Reconstruct the integrated source-like text into ./full_source.
 *   3. Parse .bytecode and export every recoverable marshal/code blob into ./pylingual_bundle as:
 *        - .marshal blobs
 *        - .pyc files
 *        - pyc_list.txt / manifest.tsv
 *
 * Exported .marshal files always preserve the original extracted bytes.
 * Derived .pyc files keep the original header when one is already present;
 * otherwise a synthetic header is added for raw marshal/code blobs.
 *
 * Default synthetic .pyc header magic is Python 3.13.3 (F3 0D 0D 0A),
 * matching the earlier target runtime in this project. Use --py-version or
 * --magic-hex when you need another CPython version such as 3.13.3
 * (F3 0D 0D 0A).
 */

#include "blob_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *DEFAULT_PATHS[] = {
    "rcdata_10_3.bin",
    "bin/rcdata_10_3.bin",
    "../rcdata_10_3.bin",
    NULL
};


static const char *find_default_bin(void) {
    int i;
    for (i = 0; DEFAULT_PATHS[i]; i++) {
        FILE *f = fopen(DEFAULT_PATHS[i], "rb");
        if (f) {
            fclose(f);
            return DEFAULT_PATHS[i];
        }
    }
    return NULL;
}

static int hex_nibble(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    ch = tolower((unsigned char)ch);
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    return -1;
}

static int parse_magic_hex(const char *text, uint8_t out[4]) {
    char clean[9];
    int n = 0;
    int i;
    if (!text || !out) return 0;
    for (; *text; text++) {
        if (*text == 'x' || *text == 'X') continue;
        if (*text == '0' && n == 0) continue;
        if (isxdigit((unsigned char)*text)) {
            if (n >= 8) return 0;
            clean[n++] = *text;
        }
    }
    if (n != 8) return 0;
    for (i = 0; i < 4; i++) {
        int hi = hex_nibble(clean[i * 2]);
        int lo = hex_nibble(clean[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

int main(int argc, char *argv[]) {
    const char *bin_path = NULL;
    const char *source_dir = "full_source";
    const char *bundle_dir = "pylingual_bundle";
    int want_source = 1;
    int want_bundle = 1;
    uint8_t pyc_magic[4] = {0xF3, 0x0D, 0x0D, 0x0A};
    BlobCtx *ctx = NULL;
    BlobError err;
    size_t module_count = 0;
    BlobVal *vals = NULL;
    uint32_t count = 0;
    uint32_t section_size = 0;
    uint32_t written = 0;
    int i;

    printf("=======================================================\n");
    printf("  Nuitka loader  (full source + PyLingual bundle mode)\n");
    printf("=======================================================\n\n");

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-source") == 0) {
            want_source = 0;
        } else if (strcmp(argv[i], "--no-pyc") == 0) {
            want_bundle = 0;
        } else if (strcmp(argv[i], "--source-dir") == 0 && i + 1 < argc) {
            source_dir = argv[++i];
        } else if (strcmp(argv[i], "--bundle-dir") == 0 && i + 1 < argc) {
            bundle_dir = argv[++i];
        } else if (strcmp(argv[i], "--magic-hex") == 0 && i + 1 < argc) {
            if (!parse_magic_hex(argv[++i], pyc_magic)) {
                fprintf(stderr, "[main] ERROR: --magic-hex must be 8 hex chars, e.g. f30d0d0a\n");
                return 1;
            }
        } else if (!bin_path) {
            bin_path = argv[i];
        } else {
            fprintf(stderr, "[main] ERROR: unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!bin_path) {
        bin_path = find_default_bin();
        if (!bin_path) {
            fprintf(stderr,
                    "[main] ERROR: rcdata_10_3.bin not found.\n"
                    "  Usage: ./blob_loader [path/to/rcdata_10_3.bin] [--py-version 3.13.3]\n"
                    "                      [--magic-hex f30d0d0a] [--source-dir full_source]\n"
                    "                      [--bundle-dir pylingual_bundle]\n"
                    "                      [--no-source] [--no-pyc]\n");
            return 1;
        }
        printf("[main] Auto-detected: %s\n\n", bin_path);
    } else {
        printf("[main] Using path from argument: %s\n\n", bin_path);
    }

    err = blob_load_file(bin_path, &ctx);
    if (err != BLOB_OK) {
        fprintf(stderr, "[main] blob_load_file: %s\n", blob_error_str(err));
        return 1;
    }

    err = blob_verify(ctx);
    if (err != BLOB_OK) {
        fprintf(stderr, "[main] blob_verify: %s\n", blob_error_str(err));
        blob_free(ctx);
        return 1;
    }

    blob_dump_toc(ctx);

    if (want_source) {
        err = blob_dump_full_source(ctx, source_dir, &module_count);
        if (err != BLOB_OK) {
            fprintf(stderr, "[main] blob_dump_full_source: %s\n", blob_error_str(err));
            blob_free(ctx);
            return 1;
        }
        printf("[main] Reconstructed %zu module file(s) into ./%s\n", module_count, source_dir);
        printf("[main] Combined output: ./%s/combined_source.py\n", source_dir);
        printf("[main] Raw normalized dump: ./%s/raw_source_dump.txt\n\n", source_dir);
    }

    if (want_bundle) {
        err = blob_find_section(ctx, ".bytecode", &section_size);
        if (err != BLOB_OK) {
            fprintf(stderr, "[main] blob_find_section(.bytecode): %s\n", blob_error_str(err));
            blob_free(ctx);
            return 1;
        }
        printf("[main] .bytecode section: %u bytes\n\n", section_size);

        err = blob_parse_constants(ctx, &vals, &count);
        if (err != BLOB_OK) {
            fprintf(stderr, "[main] blob_parse_constants: %s\n", blob_error_str(err));
            blob_free(ctx);
            return 1;
        }

        err = blob_export_pylingual_bundle(vals, count, bundle_dir, want_source ? source_dir : NULL, pyc_magic, &written);
        if (err != BLOB_OK) {
            fprintf(stderr, "[main] blob_export_pylingual_bundle: %s\n", blob_error_str(err));
            blob_free_values(vals, count);
            blob_free(ctx);
            return 1;
        }

        printf("[main] Exported %u bytecode blob(s) into ./%s\n", written, bundle_dir);
        printf("[main] Names keep original top-level constant indexes when available.\n");
        printf("[main] Pyc list: ./%s/pyc_list.txt\n", bundle_dir);
        printf("[main] Manifest: ./%s/manifest.tsv\n", bundle_dir);
        printf("[main] Helper:   ./%s/make_pyc_list.py\n\n", bundle_dir);
        printf("[main] PyLingual example:\n");
        printf("        pylingual -v 3.13 -o out %s/bytecode_*.pyc\n", bundle_dir);
        printf("        pylingual -v 3.13 -o out %s/bytecode_*.pyc\n\n", bundle_dir);

        blob_free_values(vals, count);
    }

    blob_free(ctx);
    return 0;
}
