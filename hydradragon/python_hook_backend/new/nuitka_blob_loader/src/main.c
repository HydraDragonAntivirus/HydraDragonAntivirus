/*
 * main.c  --  Nuitka .bytecode blob loader entry point.
 *
 * Usage:
 *   ./blob_loader [path_to_bin]
 *
 * Defaults to looking for "rcdata_10_3.bin" in the current directory
 * or the "bin/" sub-directory.
 *
 * What it does:
 *   1. Reads the raw RCDATA binary (rcdata_10_3.bin from a Nuitka binary).
 *   2. Verifies the CRC32 header.
 *   3. Dumps the full section table-of-contents.
 *   4. Locates the ".bytecode" section.
 *   5. Decodes every constant in that section.
 *   6. Pretty-prints the decoded constant tree.
 */

#include "blob_loader.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Try several default search paths for the bin file.                  */
/* ------------------------------------------------------------------ */
static const char *DEFAULT_PATHS[] = {
    "rcdata_10_3.bin",
    "bin/rcdata_10_3.bin",
    "../rcdata_10_3.bin",
    NULL
};

static const char *find_default_bin(void) {
    for (int i = 0; DEFAULT_PATHS[i]; i++) {
        FILE *f = fopen(DEFAULT_PATHS[i], "rb");
        if (f) { fclose(f); return DEFAULT_PATHS[i]; }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  main                                                                 */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    const char *bundle_dir = "pylingual_bundle";
    uint32_t written = 0;
    printf("=======================================================\n");
    printf("  Nuitka constants blob loader  (.bytecode section)\n");
    printf("=======================================================\n\n");

    /* --- resolve path --- */
    const char *bin_path = NULL;
    if (argc >= 2) {
        bin_path = argv[1];
        printf("[main] Using path from argument: %s\n", bin_path);
    } else {
        bin_path = find_default_bin();
        if (!bin_path) {
            fprintf(stderr,
                "[main] ERROR: rcdata_10_3.bin not found.\n"
                "  Place the file next to the executable, or pass its path as:\n"
                "    ./blob_loader <path/to/rcdata_10_3.bin>\n\n"
                "  To extract this file from a Nuitka Windows binary:\n"
                "    ResourceHacker.exe -open program.exe -save rcdata_10_3.bin"
                " -action extract -mask RCDATA,3\n");
            return 1;
        }
        printf("[main] Auto-detected: %s\n\n", bin_path);
    }

    /* ---- Step 1: load file ---- */
    BlobCtx *ctx = NULL;
    BlobError err = blob_load_file(bin_path, &ctx);
    if (err != BLOB_OK) {
        fprintf(stderr, "[main] blob_load_file: %s\n", blob_error_str(err));
        return 1;
    }

    /* ---- Step 2: verify CRC32 ---- */
    err = blob_verify(ctx);
    if (err != BLOB_OK) {
        fprintf(stderr, "[main] blob_verify: %s\n", blob_error_str(err));
        blob_free(ctx);
        return 1;
    }

    /* ---- Step 3: dump section TOC ---- */
    blob_dump_toc(ctx);

    /* ---- Step 4: find .bytecode section ---- */
    uint32_t section_size = 0;
    err = blob_find_section(ctx, ".bytecode", &section_size);
    if (err != BLOB_OK) {
        fprintf(stderr, "[main] blob_find_section: %s\n", blob_error_str(err));
        blob_free(ctx);
        return 1;
    }
    printf("[main] .bytecode section: %u bytes\n\n", section_size);

    /* ---- Step 5: decode constants ---- */
    BlobVal *vals  = NULL;
    uint32_t count = 0;

    err = blob_parse_constants(ctx, &vals, &count);
    if (err != BLOB_OK) {
        fprintf(stderr, "[main] blob_parse_constants: %s\n", blob_error_str(err));
        blob_free(ctx);
        return 1;
    }

    /* ---- Step 6: export named bytecode files ---- */
    err = blob_export_named_bytecode_files(vals, count, bundle_dir, &written);
    if (err != BLOB_OK) {
        fprintf(stderr, "[main] blob_export_named_bytecode_files: %s\n", blob_error_str(err));
        blob_free_values(vals, count);
        blob_free(ctx);
        return 1;
    }
    printf("[main] Exported %u detected bytecode file(s) into ./%s\n\n", written, bundle_dir);

    /* ---- Step 7: print ---- */
    printf("\n=== Decoded .bytecode constants (%u total) ===\n\n", count);
    for (uint32_t i = 0; i < count; i++) {
        printf("[%4u] ", i);
        blob_print_val(&vals[i], 0);
    }
    printf("\n=== Done. ===\n");

    /* ---- cleanup ---- */
    blob_free_values(vals, count);
    blob_free(ctx);

    return 0;
}
