/*
 * main.c  --  Nuitka blob loader + pyc exporter
 *
 * Usage:
 *   ./blob_loader [options] <rcdata_10_3.bin>
 *
 * Options:
 *   --section <name>    Section to decode and print  (default: .bytecode)
 *   --save-pyc <dir>    Export ALL sections' 'X' blobs as .pyc + .hex files
 *   --pyver <hex>       Python version for .pyc magic  (e.g. 0x3b0 = 3.11)
 *   --sbox <file>       Load 256-byte S-box from binary file (for decryption)
 *   --toc               Only print the section table-of-contents and exit
 *   --no-print          Skip printing decoded constants to stdout
 *
 * Examples:
 *   ./blob_loader rcdata_10_3.bin
 *   ./blob_loader rcdata_10_3.bin --save-pyc ./output --pyver 0x3b0
 *   ./blob_loader rcdata_10_3.bin --save-pyc ./output --sbox sbox.bin
 *   ./blob_loader rcdata_10_3.bin --section __main__ --no-print --save-pyc out
 *   ./blob_loader rcdata_10_3.bin --toc
 */

#include "blob_loader.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *DEFAULT_PATHS[] = {
    "rcdata_10_3.bin", "bin/rcdata_10_3.bin", "../rcdata_10_3.bin", NULL
};
static const char *find_default_bin(void) {
    for (int i = 0; DEFAULT_PATHS[i]; i++) {
        FILE *f = fopen(DEFAULT_PATHS[i], "rb");
        if (f) { fclose(f); return DEFAULT_PATHS[i]; }
    }
    return NULL;
}

static void usage(const char *prog) {
    printf("Usage: %s [options] [path_to_rcdata_10_3.bin]\n\n", prog);
    printf("Options:\n");
    printf("  --section <name>   Section to decode and print (default: .bytecode)\n");
    printf("  --save-pyc <dir>   Export all 'X' blobs as .pyc + .hex files\n");
    printf("  --pyver <hex>      Python version for .pyc magic (e.g. 0x3b0)\n");
    printf("                     Supported: 0x380 0x390 0x3a0 0x3b0 0x3c0 0x3d0\n");
    printf("  --sbox <file>      256-byte S-box binary for decryption\n");
    printf("  --toc              Print section table-of-contents and exit\n");
    printf("  --no-print         Skip printing decoded constants to stdout\n");
    printf("  --help             This message\n\n");
    printf("  When --save-pyc is given:\n");
    printf("    • Every section is scanned for 'X' (raw marshal) blobs\n");
    printf("    • Each is saved as <dir>/<module_path>.pyc\n");
    printf("    • A <dir>/<module_path>.hex hex dump is also written\n");
    printf("    • The .pyc header is: [magic][flags=0][mtime=0][srcsize=0]\n");
    printf("    • Use 'python -m dis file.pyc' to disassemble output\n\n");
}

int main(int argc, char *argv[]) {
    printf("=======================================================\n");
    printf("  Nuitka constants blob loader + pyc exporter\n");
    printf("=======================================================\n\n");

    /* --- parse args --- */
    const char *bin_path    = NULL;
    const char *section     = ".bytecode";
    const char *save_dir    = NULL;
    const char *sbox_path   = NULL;
    unsigned int py_version = 0;
    bool toc_only           = false;
    bool do_print           = true;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]); return 0;
        } else if (!strcmp(argv[i], "--section") && i+1 < argc) {
            section = argv[++i];
        } else if (!strcmp(argv[i], "--save-pyc") && i+1 < argc) {
            save_dir = argv[++i];
        } else if (!strcmp(argv[i], "--pyver") && i+1 < argc) {
            py_version = (unsigned int)strtol(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--sbox") && i+1 < argc) {
            sbox_path = argv[++i];
        } else if (!strcmp(argv[i], "--toc")) {
            toc_only = true;
        } else if (!strcmp(argv[i], "--no-print")) {
            do_print = false;
        } else if (argv[i][0] != '-') {
            bin_path = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (!bin_path) {
        bin_path = find_default_bin();
        if (!bin_path) {
            fprintf(stderr,
                "[main] rcdata_10_3.bin not found.\n"
                "  Pass path explicitly, or see README for extraction instructions.\n");
            return 1;
        }
        printf("[main] Auto-detected: %s\n\n", bin_path);
    }

    /* ---- load S-box if provided ---- */
    if (sbox_path) {
        FILE *sf = fopen(sbox_path, "rb");
        if (!sf) { fprintf(stderr, "[main] Cannot open sbox: %s\n", sbox_path); return 1; }
        uint8_t sbox[256];
        if (fread(sbox, 1, 256, sf) != 256) {
            fprintf(stderr, "[main] S-box file must be exactly 256 bytes\n");
            fclose(sf); return 1;
        }
        fclose(sf);
        blob_set_sbox(sbox);
    }

    /* ---- Step 1: load ---- */
    BlobCtx *ctx = NULL;
    BlobError err = blob_load_file(bin_path, &ctx);
    if (err != BLOB_OK) { fprintf(stderr, "[main] load: %s\n", blob_error_str(err)); return 1; }

    /* ---- Step 2: verify ---- */
    err = blob_verify(ctx);
    if (err != BLOB_OK) { fprintf(stderr, "[main] verify: %s\n", blob_error_str(err)); blob_free(ctx); return 1; }

    /* ---- Step 3: TOC ---- */
    blob_dump_toc(ctx);
    if (toc_only) { blob_free(ctx); return 0; }

    /* ---- Step 4a: export .pyc files ---- */
    if (save_dir) {
        int n = blob_export_all_pyc(ctx, save_dir, py_version);
        if (n < 0) {
            fprintf(stderr, "[main] export failed\n");
            blob_free(ctx); return 1;
        }
        printf("[main] Exported %d .pyc file(s)  →  %s/\n\n", n, save_dir);
    }

    /* ---- Step 4b: decode + print one section ---- */
    if (do_print) {
        printf("[main] Decoding section '%s'...\n", section);
        err = blob_find_section(ctx, section, NULL);
        if (err != BLOB_OK) {
            fprintf(stderr, "[main] find_section: %s\n", blob_error_str(err));
            blob_free(ctx); return 1;
        }

        BlobVal *vals  = NULL;
        uint32_t count = 0;
        err = blob_parse_constants(ctx, &vals, &count);
        if (err != BLOB_OK) {
            fprintf(stderr, "[main] parse: %s\n", blob_error_str(err));
            blob_free(ctx); return 1;
        }

        printf("\n=== Section '%s' — %u constants ===\n\n", section, count);
        for (uint32_t i = 0; i < count; i++) {
            printf("[%4u] ", i);
            blob_print_val(&vals[i], 0);
        }
        printf("\n=== Done. ===\n");

        blob_free_values(vals, count);
    }

    blob_free(ctx);
    return 0;
}
