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
 *   count × encoded constant:
 *     [ char type_tag ]   -- single byte: 'n','t','F','l','q','f','u',...
 *     [ payload ... ]     -- type-specific bytes (see CONSTANT TYPE TAGS below)
 *
 * CONSTANT TYPE TAGS (from HelpersConstantsBlob.c):
 *   'n'  None               (no payload)
 *   't'  True               (no payload)
 *   'F'  False              (no payload)
 *   's'  empty str/bytes    (no payload)
 *   'p'  back-ref prev obj  (no payload)
 *   'l'  +long < 2^31       varint
 *   'q'  -long < 2^31       varint
 *   'G'  +bigint            varint count, then count×31-bit varints
 *   'g'  -bigint            varint count, then count×31-bit varints
 *   'f'  float              8-byte IEEE 754 double
 *   'j'  complex            two 8-byte doubles (real, imag)
 *   'Z'  special float      1-byte sub-tag (0=+0.0,1=-0.0,2=+nan,3=-nan,4=+inf,5=-inf)
 *   'c'  bytes (py3)/str(py2) zero-terminated
 *   'd'  1-byte bytes/str   1 raw byte
 *   'b'  bytes len-prefixed varint length + raw bytes
 *   'B'  bytearray          varint length + raw bytes
 *   'w'  1-char unicode     1 raw byte (UTF-8)
 *   'u'  unicode/str        zero-terminated UTF-8
 *   'a'  interned unicode   zero-terminated UTF-8 (attribute)
 *   'v'  unicode len-prefix varint length + UTF-8 bytes
 *   'T'  tuple              varint count + count×child
 *   'L'  list               varint count + count×child
 *   'D'  dict               varint count + count×key + count×value
 *   'S'  set                varint count + count×child
 *   'P'  frozenset          varint count + count×child
 *   ':'  slice              3 children (start, stop, step)
 *   ';'  range              3 children (start, stop, step)
 *   'M'  anon builtin       1-byte index into builtin table
 *   'Q'  special singleton  1-byte index (0=Ellipsis,1=NotImplemented,2=sys.version_info)
 *   'O'  builtin by name    zero-terminated name string
 *   'E'  exception by name  zero-terminated name string
 *   'C'  code object        fully serialized fields
 *   '.'  sentinel/corrupt
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

/* ---------- result codes ---------- */
typedef enum {
    BLOB_OK              = 0,
    BLOB_ERR_IO          = 1,   /* file read error           */
    BLOB_ERR_ALLOC       = 2,   /* malloc failed             */
    BLOB_ERR_CRC         = 3,   /* CRC32 mismatch            */
    BLOB_ERR_NOT_FOUND   = 4,   /* section name not in blob  */
    BLOB_ERR_CORRUPT     = 5,   /* unexpected tag / truncate */
} BlobError;

const char *blob_error_str(BlobError err);

/* ---------- opaque blob context ---------- */
typedef struct BlobCtx BlobCtx;

/* ---------- constant value (tagged union for display) ---------- */
typedef enum {
    BVAL_NONE, BVAL_TRUE, BVAL_FALSE,
    BVAL_INT,       /* int64_t  */
    BVAL_FLOAT,     /* double   */
    BVAL_COMPLEX,   /* two doubles */
    BVAL_BYTES,     /* raw byte buffer */
    BVAL_STR,       /* UTF-8 string    */
    BVAL_TUPLE, BVAL_LIST, BVAL_DICT, BVAL_SET, BVAL_FROZENSET,
    BVAL_SLICE, BVAL_RANGE,
    BVAL_BIGINT,    /* printed as hex string */
    BVAL_BUILTIN,   /* name string */
    BVAL_CODE,      /* code object summary */
    BVAL_BACKREF,   /* reference to previous constant */
    BVAL_UNKNOWN,
} BlobValKind;

typedef struct BlobVal BlobVal;
struct BlobVal {
    BlobValKind kind;
    union {
        int64_t  ival;
        double   fval;
        struct { double real; double imag; } cval;
        struct { uint8_t *data; size_t len; } buf;   /* bytes / str / bigint */
        struct { BlobVal *items; size_t count; }  seq; /* tuple/list/set */
        struct { BlobVal *keys; BlobVal *vals; size_t count; } dval;
        struct { BlobVal *items; } code; /* code object fields as sequence */
        int backref_offset;
    };
    char tag;   /* original type tag byte, always set */
};

/* ---------- public API ---------- */

/* Load raw file into a new BlobCtx. Call blob_free() when done. */
BlobError blob_load_file(const char *path, BlobCtx **out_ctx);

/* Verify CRC32 header; must be called before blob_find_section. */
BlobError blob_verify(BlobCtx *ctx);

/* Locate a named section (e.g. ".bytecode") inside the blob.
   Sets internal cursor; must call blob_parse_constants after this. */
BlobError blob_find_section(BlobCtx *ctx, const char *name,
                            uint32_t *out_section_size);

/* Parse all constants from the current section.
   *out_values is malloc-allocated; caller owns it.
   *out_count receives number of top-level constants. */
BlobError blob_parse_constants(BlobCtx *ctx,
                               BlobVal **out_values,
                               uint32_t *out_count);

/* Print a BlobVal tree to stdout at the given indent level. */
void blob_print_val(const BlobVal *val, int indent);

/* Free everything. */
void blob_free_values(BlobVal *vals, uint32_t count);
void blob_free(BlobCtx *ctx);

/* Dump full blob section map (names + sizes) without parsing contents. */
BlobError blob_dump_toc(BlobCtx *ctx);

/*
 * Install the 256-byte S-box extracted from the compiled binary.
 * Must be called BEFORE blob_verify() to enable decryption.
 * If not called, raw bytes are used as-is (works when DECODE is a no-op).
 */
void blob_set_sbox(const uint8_t sbox[256]);

#endif /* BLOB_LOADER_H */
