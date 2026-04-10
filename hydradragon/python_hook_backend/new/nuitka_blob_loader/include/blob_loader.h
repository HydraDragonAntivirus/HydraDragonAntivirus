#ifndef BLOB_LOADER_H
#define BLOB_LOADER_H

/*
 * blob_loader.h
 *
 * Standalone loader for Nuitka compiled constants blobs.
 * Reads rcdata_10_3.bin, verifies CRC32, finds the named section,
 * and decodes all constants in it.
 *
 * Blob wire format (after optional DECODE/XOR step):
 *
 *   [ uint32_t crc32  ]  -- CRC32 of everything after this header
 *   [ uint32_t size   ]  -- byte count covered by crc32
 *   Repeated sections:
 *     [ char[] name \0 ]  -- null-terminated module name, e.g. ".bytecode"
 *     [ uint32_t len  ]   -- byte length of the section payload
 *     [ payload bytes ]   -- packed constants for that module
 *
 * Section payload (constants):
 *   [ uint16_t count ]    -- how many top-level constants follow
 *   count x encoded constant:
 *     [ char type_tag ]   -- single byte: 'n','t','F','l','q','f','u',...
 *     [ payload ... ]     -- type-specific bytes (see CONSTANT TYPE TAGS below)
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ---------- result codes ---------- */
typedef enum {
    BLOB_OK            = 0,
    BLOB_ERR_IO        = 1,
    BLOB_ERR_ALLOC     = 2,
    BLOB_ERR_CRC       = 3,
    BLOB_ERR_NOT_FOUND = 4,
    BLOB_ERR_CORRUPT   = 5,
} BlobError;

const char *blob_error_str(BlobError err);

/* ---------- opaque blob context ---------- */
typedef struct BlobCtx BlobCtx;

/* ---------- constant value (tagged union for display) ---------- */
typedef enum {
    BVAL_NONE,
    BVAL_TRUE,
    BVAL_FALSE,
    BVAL_INT,
    BVAL_FLOAT,
    BVAL_COMPLEX,
    BVAL_BYTES,
    BVAL_STR,
    BVAL_TUPLE,
    BVAL_LIST,
    BVAL_DICT,
    BVAL_SET,
    BVAL_FROZENSET,
    BVAL_SLICE,
    BVAL_RANGE,
    BVAL_BIGINT,
    BVAL_BUILTIN,
    BVAL_CODE,
    BVAL_BACKREF,
    BVAL_UNKNOWN,
} BlobValKind;

typedef struct BlobVal BlobVal;
struct BlobVal {
    BlobValKind kind;
    union {
        int64_t ival;
        double fval;
        struct {
            double real;
            double imag;
        } cval;
        struct {
            uint8_t *data;
            size_t len;
        } buf;
        struct {
            BlobVal *items;
            size_t count;
        } seq;
        struct {
            BlobVal *keys;
            BlobVal *vals;
            size_t count;
        } dval;
        struct {
            BlobVal *items;
        } code;
        int backref_offset;
    };
    char tag;
};

/* ---------- public API ---------- */

BlobError blob_load_file(const char *path, BlobCtx **out_ctx);
BlobError blob_verify(BlobCtx *ctx);
BlobError blob_find_section(BlobCtx *ctx, const char *name,
                            uint32_t *out_section_size);
BlobError blob_parse_constants(BlobCtx *ctx,
                               BlobVal **out_values,
                               uint32_t *out_count);
void blob_print_val(const BlobVal *val, int indent);
void blob_free_values(BlobVal *vals, uint32_t count);
void blob_free(BlobCtx *ctx);
BlobError blob_dump_toc(BlobCtx *ctx);
void blob_set_sbox(const uint8_t sbox[256]);

/*
 * Best-effort full-source reconstruction from the integrated Nuitka blob.
 *
 * This does NOT decompile .bytecode 'X' blobs. Instead, it reconstructs the
 * textual source/token stream embedded in the raw RCDATA blob, which is the
 * right thing to do when you want readable source instead of the current
 * bytecode[len](E3 00 ...) output.
 *
 * Files created under out_dir:
 *   raw_source_dump.txt      - normalized full blob text after marker slicing
 *   combined_source.py       - all recovered modules in one file
 *   module_index.tsv         - module name to emitted file mapping
 *   __main__.py / module_XXXX_<name>.py
 *                            - one file per reconstructed module when writable
 */
BlobError blob_dump_full_source(BlobCtx *ctx,
                                const char *out_dir,
                                size_t *out_module_count);


/*
 * Export every raw marshalled bytecode/blob entry ('X' tags) found in the
 * decoded constants tree into a PyLingual-friendly bundle.
 *
 * Files created under out_dir:
 *   manifest.tsv        - index, size, marshal path, pyc path
 *   marshal_list.txt    - one raw marshal blob path per line
 *   pyc_list.txt        - one generated .pyc path per line
 *   bytecode_XXXX.marshal
 *   bytecode_XXXX.pyc
 *   make_pyc_list.py    - helper to rebuild .pyc headers with a different magic
 *
 * pyc_magic is the 4-byte CPython MAGIC_NUMBER to use for emitted .pyc files.
 * For Python 3.11 final that value is A7 0D 0D 0A.
 */
BlobError blob_export_pylingual_bundle(const BlobVal *vals,
                                       uint32_t count,
                                       const char *out_dir,
                                       const uint8_t pyc_magic[4],
                                       uint32_t *out_written);

/* Write the helper script used by blob_export_pylingual_bundle(). */
BlobError blob_write_pylingual_helper(const char *out_dir,
                                      const uint8_t default_magic[4]);

#endif /* BLOB_LOADER_H */
