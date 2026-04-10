/*
 * blob_loader.c  --  Nuitka constants blob loader (v2, fixed)
 *
 * BUGS FIXED vs v1:
 *
 *  1. 'X' tag (0x58) was missing — caused "Unexpected tag" crash.
 *     Source (line 1098): raw blob data, varint size + raw bytes.
 *     Used to store compiled bytecode in the .bytecode section.
 *
 *  2. 'C' (code object) had the entirely wrong wire format.
 *     Actual order (source lines 1139-1307):
 *       varint  flags            (packed bits for optional fields)
 *       CONST   function_name    <- recursive _unpackBlobConstant!
 *       varint  line_number + 1
 *       CONST   arg_names        <- recursive (usually tuple of str)
 *       varint  arg_count
 *       [CONST  qualname         if flags & bit0  (Python >= 3.11)]
 *       [CONST  free_vars        if flags & bit1]
 *       [varint kw_only+1        if flags & bit2]
 *       [varint pos_only+1       if flags & bit3]
 *       remaining bits -> CO_GENERATOR/CO_OPTIMIZED/...
 *
 *  3. Added 'A' (GenericAlias, Python >= 3.9): 2 child constants.
 *     Added 'H' (UnionType,    Python >= 3.10): 1 child constant.
 *
 *  4. Added stream-cipher decryption matching the IDA pseudocode.
 *     Call blob_set_sbox(sbox) before blob_verify() to enable.
 *     (See extract_sbox.py to dump the S-box from the .exe.)
 *
 *  5. Fixed corrupt-tag error to print payload-relative offset.
 */

#include "blob_loader.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

extern uint32_t calc_crc32(const uint8_t *data, size_t size);

/* ------------------------------------------------------------------ */
struct BlobCtx {
    uint8_t  *raw;
    size_t    raw_len;
    uint8_t  *decrypted;       /* malloc'd decrypted copy, or NULL */
    const uint8_t *payload;    /* past 8-byte CRC/size header      */
    size_t    payload_len;
    const uint8_t *section_ptr;
    uint32_t  section_size;
};

static uint8_t g_sbox[256];
static bool    g_sbox_ready = false;

void blob_set_sbox(const uint8_t sbox[256]) {
    memcpy(g_sbox, sbox, 256);
    g_sbox_ready = true;
    printf("[blob] S-box installed — decryption enabled.\n");
}

const char *blob_error_str(BlobError err) {
    switch (err) {
    case BLOB_OK:           return "OK";
    case BLOB_ERR_IO:       return "I/O error";
    case BLOB_ERR_ALLOC:    return "allocation failure";
    case BLOB_ERR_CRC:      return "CRC32 mismatch";
    case BLOB_ERR_NOT_FOUND:return "section not found";
    case BLOB_ERR_CORRUPT:  return "corrupt/truncated data";
    default:                return "unknown error";
    }
}

/* ------------------------------------------------------------------ */
/*  File loading                                                        */
/* ------------------------------------------------------------------ */
BlobError blob_load_file(const char *path, BlobCtx **out_ctx) {
    *out_ctx = NULL;
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[blob] Cannot open '%s'\n", path); return BLOB_ERR_IO; }
    fseek(f, 0, SEEK_END); long fs = ftell(f); rewind(f);
    if (fs <= 0) { fclose(f); return BLOB_ERR_IO; }
    uint8_t *buf = (uint8_t *)malloc((size_t)fs);
    if (!buf) { fclose(f); return BLOB_ERR_ALLOC; }
    if (fread(buf, 1, (size_t)fs, f) != (size_t)fs) { free(buf); fclose(f); return BLOB_ERR_IO; }
    fclose(f);
    BlobCtx *ctx = (BlobCtx *)calloc(1, sizeof(BlobCtx));
    if (!ctx) { free(buf); return BLOB_ERR_ALLOC; }
    ctx->raw = buf; ctx->raw_len = (size_t)fs;
    printf("[blob] Loaded '%s': %zu bytes\n", path, ctx->raw_len);
    *out_ctx = ctx;
    return BLOB_OK;
}

/* ------------------------------------------------------------------ */
/*  Primitive readers                                                   */
/* ------------------------------------------------------------------ */
static uint16_t read_u16(const uint8_t **p) { uint16_t v; memcpy(&v,*p,2); *p+=2; return v; }
static uint32_t read_u32(const uint8_t **p) { uint32_t v; memcpy(&v,*p,4); *p+=4; return v; }
static double   read_f64(const uint8_t **p) { double   v; memcpy(&v,*p,8); *p+=8; return v; }

static uint64_t read_varint(const uint8_t **p) {
    uint64_t r=0, f=1;
    for(;;){ uint8_t b=**p; (*p)++; r+=(b&0x7F)*f; if(b<0x80) break; f<<=7; }
    return r;
}
static const uint8_t *skip_cstr(const uint8_t *p) { while(*p) p++; return p+1; }

/* ------------------------------------------------------------------ */
/*  Stream-cipher decryption (IDA pseudocode, exact port)              */
/*                                                                       */
/*  Resource layout:                                                     */
/*    bytes  0-3  : stored CRC32 of decrypted data (plaintext)          */
/*    bytes  4-7  : size covered by CRC32 (plaintext)                   */
/*    bytes  8-23 : cipher initialisation input (not decrypted)         */
/*    bytes 24+   : encrypted payload                                    */
/*                                                                       */
/*  Decryption: for each source byte at position i (i >= 24):           */
/*    v14 = S[ ct[i] ^ (state + i - 8) ]                               */
/*    out[i - 16] = v14                                                  */
/*    state updated per (i & 7) with fixed offsets from IDA             */
/*                                                                       */
/*  The first 8 bytes of the output (CRC header) are copied unchanged.  */
/* ------------------------------------------------------------------ */

static uint8_t cipher_init_state(const uint8_t *raw) {
    /* Chain of S-box lookups over bytes 8..23; constants from IDA subtract chain */
    const uint8_t *S = g_sbox;
    uint8_t acc;
    acc = (uint8_t)(S[raw[ 8]]           - 115);
    acc = (uint8_t)(S[(uint8_t)(raw[ 9] ^ acc)] + 34);
    acc = (uint8_t)(S[(uint8_t)(raw[10] ^ acc)] - 74);
    acc = (uint8_t)(S[(uint8_t)(raw[11] ^ acc)] - 95);
    acc = (uint8_t)(S[(uint8_t)(raw[12] ^ acc)] + 59);
    acc = (uint8_t)(S[(uint8_t)(raw[13] ^ acc)] - 12);
    acc = (uint8_t)(S[(uint8_t)(raw[14] ^ acc)] - 44);
    acc = (uint8_t)(S[(uint8_t)(raw[15] ^ acc)] - 111);
    acc = (uint8_t)(S[(uint8_t)(raw[16] ^ acc)] - 107);
    acc = (uint8_t)(S[(uint8_t)(raw[17] ^ acc)] + 42);
    acc = (uint8_t)(S[(uint8_t)(raw[18] ^ acc)] - 66);
    acc = (uint8_t)(S[(uint8_t)(raw[19] ^ acc)] - 87);
    acc = (uint8_t)(S[(uint8_t)(raw[20] ^ acc)] + 67);
    acc = (uint8_t)(S[(uint8_t)(raw[21] ^ acc)] - 4);
    acc = (uint8_t)(S[(uint8_t)(raw[22] ^ acc)] - 36);
    acc = (uint8_t)(S[(uint8_t)(raw[23] ^ acc)] - 119);
    return acc;
}

static uint8_t *decrypt_blob(const uint8_t *raw, size_t raw_len) {
    uint8_t *out = (uint8_t *)malloc(raw_len);
    if (!out) return NULL;
    memcpy(out, raw, raw_len < 8 ? raw_len : 8);
    if (raw_len > 8) memcpy(out + 8, raw + 8, raw_len - 8);

    const uint8_t *S   = g_sbox;
    uint8_t        v13 = cipher_init_state(raw);

    for (size_t i = 24; i < raw_len; i++) {
        uint8_t v14 = S[(uint8_t)(raw[i] ^ (uint8_t)(v13 + (uint8_t)i - 8))];
        out[i - 16] = v14;
        switch (i & 7) {
        case 0: v13=(uint8_t)(v14-116); break; case 1: v13=(uint8_t)(v14+ 32); break;
        case 2: v13=(uint8_t)(v14- 77); break; case 3: v13=(uint8_t)(v14- 99); break;
        case 4: v13=(uint8_t)(v14+ 54); break; case 5: v13=(uint8_t)(v14- 18); break;
        case 6: v13=(uint8_t)(v14- 51); break; case 7: v13=(uint8_t)(v14-119); break;
        }
    }
    return out;
}

/* ------------------------------------------------------------------ */
/*  CRC verification                                                    */
/*  IDA check: stored == ~CRC32(decrypted_payload)                     */
/*  Also accepts stored == CRC32(payload) for unencrypted builds.      */
/* ------------------------------------------------------------------ */
BlobError blob_verify(BlobCtx *ctx) {
    if (ctx->raw_len < 8) return BLOB_ERR_CORRUPT;

    const uint8_t *working = ctx->raw;
    if (g_sbox_ready) {
        printf("[blob] Decrypting with S-box...\n");
        uint8_t *dec = decrypt_blob(ctx->raw, ctx->raw_len);
        if (!dec) return BLOB_ERR_ALLOC;
        ctx->decrypted = dec;
        working = dec;
        printf("[blob] Decryption done.\n");
    }

    const uint8_t *p     = working;
    uint32_t stored_crc  = read_u32(&p);
    uint32_t covered_len = read_u32(&p);

    printf("[blob] Header: stored_crc=0x%08X  covered=%u bytes\n", stored_crc, covered_len);
    if ((size_t)covered_len + 8 > ctx->raw_len) {
        fprintf(stderr, "[blob] size field (%u) exceeds file (%zu)\n", covered_len, ctx->raw_len);
        return BLOB_ERR_CORRUPT;
    }

    uint32_t computed = calc_crc32(p, covered_len);
    bool ok = (computed == stored_crc) || (computed == ~stored_crc);
    printf("[blob] Computed CRC32=0x%08X  -> %s\n", computed, ok ? "OK" : "MISMATCH");
    if (!ok) return BLOB_ERR_CRC;

    ctx->payload     = p;
    ctx->payload_len = covered_len;
    return BLOB_OK;
}

/* ------------------------------------------------------------------ */
/*  TOC dump / section finder                                           */
/* ------------------------------------------------------------------ */
BlobError blob_dump_toc(BlobCtx *ctx) {
    if (!ctx->payload) { fprintf(stderr, "[blob] Call blob_verify() first.\n"); return BLOB_ERR_CORRUPT; }
    const uint8_t *p = ctx->payload, *end = p + ctx->payload_len;
    int idx = 0;
    printf("\n[blob] === Section TOC ===\n");
    while (p < end && *p) {
        const char *name = (const char *)p; p = skip_cstr(p);
        if (p + 4 > end) break;
        uint32_t sz = read_u32(&p);
        printf("  [%2d] %-40s  %u bytes\n", idx++, name, sz);
        p += sz;
    }
    printf("[blob] ===  End TOC  ===\n\n");
    return BLOB_OK;
}

BlobError blob_find_section(BlobCtx *ctx, const char *name, uint32_t *out_size) {
    if (!ctx->payload) { fprintf(stderr, "[blob] Call blob_verify() first.\n"); return BLOB_ERR_CORRUPT; }
    const uint8_t *p = ctx->payload, *end = p + ctx->payload_len;
    while (p < end && *p) {
        const char *sn = (const char *)p; p = skip_cstr(p);
        if (p + 4 > end) return BLOB_ERR_CORRUPT;
        uint32_t sz = read_u32(&p);
        if (!strcmp(sn, name)) {
            printf("[blob] Found '%s': %u bytes\n", name, sz);
            ctx->section_ptr = p; ctx->section_size = sz;
            if (out_size) *out_size = sz;
            return BLOB_OK;
        }
        p += sz;
    }
    fprintf(stderr, "[blob] Section '%s' not found.\n", name);
    return BLOB_ERR_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/*  Recursive constant decoder                                          */
/* ------------------------------------------------------------------ */
static BlobVal *alloc_vals(size_t n) { return (BlobVal *)calloc(n ? n : 1, sizeof(BlobVal)); }

/* Used only to track position for back-refs and error messages */
static const uint8_t *g_payload_base = NULL;

static BlobError unpack_one(const uint8_t **p, const uint8_t *end, BlobVal *out);

static BlobError unpack_n(const uint8_t **p, const uint8_t *end, BlobVal *arr, size_t n) {
    for (size_t i = 0; i < n; i++) {
        BlobError e = unpack_one(p, end, &arr[i]);
        if (e != BLOB_OK) return e;
    }
    return BLOB_OK;
}

static BlobError unpack_one(const uint8_t **p, const uint8_t *end, BlobVal *out) {
    if (*p >= end) return BLOB_ERR_CORRUPT;
    char tag = (char)(**p); (*p)++;
    out->tag = tag; out->kind = BVAL_UNKNOWN;

#define SEQ(KIND, N) do { \
    size_t _n=(size_t)(N); BlobVal *_it=alloc_vals(_n); \
    if(!_it&&_n) return BLOB_ERR_ALLOC; \
    BlobError _e=unpack_n(p,end,_it,_n); \
    if(_e!=BLOB_OK){free(_it);return _e;} \
    out->kind=(KIND); out->seq.items=_it; out->seq.count=_n; \
} while(0)

    switch (tag) {
    /* singletons */
    case 'n': out->kind=BVAL_NONE; break;
    case 't': out->kind=BVAL_TRUE; break;
    case 'F': out->kind=BVAL_FALSE; break;
    case 's': out->kind=BVAL_STR; out->buf.data=(uint8_t*)""; out->buf.len=0; break;
    case 'p': out->kind=BVAL_BACKREF; out->backref_offset=-1; break;

    /* integers */
    case 'l': { uint64_t v=read_varint(p); out->kind=BVAL_INT; out->ival= (int64_t)v; break; }
    case 'q': { uint64_t v=read_varint(p); out->kind=BVAL_INT; out->ival=-(int64_t)v; break; }
    case 'G': case 'g': {
        int nc=(int)read_varint(p);
        size_t cap=(size_t)nc*12+4;
        uint8_t *hbuf=(uint8_t*)malloc(cap);
        if(!hbuf) return BLOB_ERR_ALLOC;
        uint64_t *limbs=(uint64_t*)malloc((size_t)nc*8);
        if(!limbs){free(hbuf);return BLOB_ERR_ALLOC;}
        for(int i=0;i<nc;i++) limbs[i]=read_varint(p);
        int hl=0;
        if(tag=='G') hl+=snprintf((char*)hbuf+hl,cap-hl,"-");
        hl+=snprintf((char*)hbuf+hl,cap-hl,"0x");
        for(int i=nc-1;i>=0;i--)
            hl+=snprintf((char*)hbuf+hl,cap-hl,"%016llX",(unsigned long long)limbs[i]);
        free(limbs);
        out->kind=BVAL_BIGINT; out->buf.data=hbuf; out->buf.len=(size_t)hl;
        break;
    }

    /* floats */
    case 'f': out->kind=BVAL_FLOAT; out->fval=read_f64(p); break;
    case 'Z': {
        uint8_t sub=**p; (*p)++;
        static const double sp[]={0.0,-0.0,NAN,-NAN,INFINITY,-INFINITY};
        out->kind=BVAL_FLOAT; out->fval=(sub<6)?sp[sub]:0.0; break;
    }
    case 'j': out->kind=BVAL_COMPLEX; out->cval.real=read_f64(p); out->cval.imag=read_f64(p); break;
    case 'J': {
        BlobVal parts[2];
        BlobError e=unpack_n(p,end,parts,2); if(e!=BLOB_OK) return e;
        out->kind=BVAL_COMPLEX;
        out->cval.real=(parts[0].kind==BVAL_FLOAT)?parts[0].fval:(double)parts[0].ival;
        out->cval.imag=(parts[1].kind==BVAL_FLOAT)?parts[1].fval:(double)parts[1].ival;
        break;
    }

    /* bytes / strings */
    case 'c': {
        size_t sl=strlen((const char*)*p);
        uint8_t *b=(uint8_t*)malloc(sl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,*p,sl+1); *p+=sl+1;
        out->kind=BVAL_BYTES; out->buf.data=b; out->buf.len=sl; break;
    }
    case 'd': {
        uint8_t *b=(uint8_t*)malloc(1); if(!b) return BLOB_ERR_ALLOC;
        b[0]=**p; (*p)++;
        out->kind=BVAL_BYTES; out->buf.data=b; out->buf.len=1; break;
    }
    case 'b': case 'B': {
        uint64_t sl=read_varint(p);
        uint8_t *b=(uint8_t*)malloc(sl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,*p,sl); b[sl]=0; *p+=sl;
        out->kind=BVAL_BYTES; out->buf.data=b; out->buf.len=(size_t)sl; break;
    }
    case 'w': {
        uint8_t *b=(uint8_t*)malloc(2); if(!b) return BLOB_ERR_ALLOC;
        b[0]=**p; (*p)++; b[1]=0;
        out->kind=BVAL_STR; out->buf.data=b; out->buf.len=1; break;
    }
    case 'u': case 'a': {
        size_t sl=strlen((const char*)*p);
        uint8_t *b=(uint8_t*)malloc(sl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,*p,sl+1); *p+=sl+1;
        out->kind=BVAL_STR; out->buf.data=b; out->buf.len=sl; break;
    }
    case 'v': {
        uint64_t sl=read_varint(p);
        uint8_t *b=(uint8_t*)malloc(sl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,*p,sl); b[sl]=0; *p+=sl;
        out->kind=BVAL_STR; out->buf.data=b; out->buf.len=(size_t)sl; break;
    }

    /* containers */
    case 'T': { SEQ(BVAL_TUPLE,    read_varint(p)); break; }
    case 'L': { SEQ(BVAL_LIST,     read_varint(p)); break; }
    case 'S': { SEQ(BVAL_SET,      read_varint(p)); break; }
    case 'P': { SEQ(BVAL_FROZENSET,read_varint(p)); break; }
    case ':': { SEQ(BVAL_SLICE,    3);               break; }
    case ';': { SEQ(BVAL_RANGE,    3);               break; }
    case 'D': {
        uint64_t n=read_varint(p);
        BlobVal *ks=alloc_vals(n), *vs=alloc_vals(n);
        if((!ks||!vs)&&n){free(ks);free(vs);return BLOB_ERR_ALLOC;}
        BlobError e=unpack_n(p,end,ks,n); if(e!=BLOB_OK){free(ks);free(vs);return e;}
        e=unpack_n(p,end,vs,n);           if(e!=BLOB_OK){free(ks);free(vs);return e;}
        out->kind=BVAL_DICT; out->dval.keys=ks; out->dval.vals=vs; out->dval.count=(size_t)n;
        break;
    }
    case 'A': { SEQ(BVAL_TUPLE, 2); break; }  /* GenericAlias (py3.9+) */
    case 'H': { SEQ(BVAL_TUPLE, 1); break; }  /* UnionType    (py3.10+) */

    /* builtins */
    case 'M': {
        static const char *anon[]={"NoneType","EllipsisType","NotImplementedType",
            "function","generator","builtin_function","code","module"};
        uint8_t idx=**p; (*p)++;
        const char *nm=(idx<8)?anon[idx]:"<anon?>";
        size_t nl=strlen(nm); uint8_t *b=(uint8_t*)malloc(nl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,nm,nl+1); out->kind=BVAL_BUILTIN; out->buf.data=b; out->buf.len=nl; break;
    }
    case 'Q': {
        static const char *sp[]={"Ellipsis","NotImplemented","sys.version_info"};
        uint8_t idx=**p; (*p)++;
        const char *nm=(idx<3)?sp[idx]:"<special?>";
        size_t nl=strlen(nm); uint8_t *b=(uint8_t*)malloc(nl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,nm,nl+1); out->kind=BVAL_BUILTIN; out->buf.data=b; out->buf.len=nl; break;
    }
    case 'O': case 'E': {
        size_t nl=strlen((const char*)*p);
        uint8_t *b=(uint8_t*)malloc(nl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,*p,nl+1); *p+=nl+1;
        out->kind=BVAL_BUILTIN; out->buf.data=b; out->buf.len=nl; break;
    }

    /* ---------------------------------------------------------------
     * 'X'  Raw blob data  (NEW — was causing the crash)
     *
     * Source line 1098:
     *   uint64_t size = _unpackVariableLength(&data);
     *   *output = (PyObject *)data;   // raw pointer into blob
     *   is_object = false;
     *   data += size;
     *
     * Stores compiled Python bytecode (.pyc content) inline.
     * --------------------------------------------------------------- */
    case 'X': {
        uint64_t sl=read_varint(p);
        if(*p+(size_t)sl>end) return BLOB_ERR_CORRUPT;
        uint8_t *b=(uint8_t*)malloc(sl+1); if(!b&&sl) return BLOB_ERR_ALLOC;
        if(b){ memcpy(b,*p,sl); b[sl]=0; }
        *p+=sl;
        out->kind=BVAL_BYTES; out->buf.data=b; out->buf.len=(size_t)sl;
        break;
    }

    /* ---------------------------------------------------------------
     * 'C'  Code object  (REWRITTEN — completely wrong in v1)
     *
     * v1 mistake: treated function_name/arg_names as plain cstrings.
     * Reality:    they are RECURSIVE _unpackBlobConstant() calls,
     *             meaning they have a type-tag byte first ('u','a','T'…).
     *
     * Correct wire format (source lines 1139-1307):
     *
     *   varint   flags           bit0=qualname, bit1=free_vars,
     *                            bit2=kw_only,  bit3=pos_only,
     *                            bit4-5=gen/coro/async, bit6+=CO_*
     *   CONST    function_name   (recursive call — has its own tag byte)
     *   varint   line_number+1
     *   CONST    arg_names       (recursive — usually 'T' tuple of str)
     *   varint   arg_count
     *   CONST?   qualname        (only if flags & bit0, Python >= 3.11)
     *   CONST?   free_vars       (only if flags & bit1)
     *   varint?  kw_only_count+1 (only if flags & bit2)
     *   varint?  pos_only_count+1(only if flags & bit3)
     *   ← remaining flag bits are CO_GENERATOR/CO_OPTIMIZED/etc.
     * --------------------------------------------------------------- */
    case 'C': {
        uint64_t flags = read_varint(p);

        /* function_name: recursive constant (tag + data) */
        BlobVal fn; memset(&fn,0,sizeof(fn));
        BlobError e = unpack_one(p, end, &fn);
        if (e != BLOB_OK) return e;

        uint64_t line_number = read_varint(p) + 1;

        /* arg_names: recursive constant (usually a tuple of unicode) */
        BlobVal an; memset(&an,0,sizeof(an));
        e = unpack_one(p, end, &an);
        if (e != BLOB_OK) return e;

        uint64_t arg_count = read_varint(p);

        uint64_t flag_base = 1;

        /* bit0: qualname (Python >= 3.11) */
        BlobVal qn; memset(&qn,0,sizeof(qn));
        bool has_qn = (flags & flag_base) != 0; flag_base <<= 1;
        if (has_qn) { e = unpack_one(p, end, &qn); if (e != BLOB_OK) return e; }

        /* bit1: free_vars */
        BlobVal fv; memset(&fv,0,sizeof(fv));
        bool has_fv = (flags & flag_base) != 0; flag_base <<= 1;
        if (has_fv) { e = unpack_one(p, end, &fv); if (e != BLOB_OK) return e; }

        /* bit2: kw_only_count */
        uint64_t kw = 0;
        if (flags & flag_base) kw = read_varint(p) + 1;
        flag_base <<= 1;

        /* bit3: pos_only_count */
        uint64_t po = 0;
        if (flags & flag_base) po = read_varint(p) + 1;
        /* remaining bits are CO_* flags already read in the flags varint */

        const char *fn_str = (fn.kind==BVAL_STR||fn.kind==BVAL_BYTES)
                             ? (const char*)fn.buf.data : "?";
        const char *qn_str = has_qn
                             ? ((qn.kind==BVAL_STR)?(const char*)qn.buf.data:"?")
                             : fn_str;
        char summary[512];
        int sl = snprintf(summary, sizeof(summary),
            "<code '%s' qualname='%s' line=%llu args=%llu kw=%llu "
            "pos_only=%llu free=%s flags=0x%llX>",
            fn_str, qn_str,
            (unsigned long long)line_number, (unsigned long long)arg_count,
            (unsigned long long)kw, (unsigned long long)po,
            has_fv?"yes":"no", (unsigned long long)flags);
        uint8_t *b=(uint8_t*)malloc((size_t)sl+1); if(!b) return BLOB_ERR_ALLOC;
        memcpy(b,summary,(size_t)sl+1);
        out->kind=BVAL_CODE; out->buf.data=b; out->buf.len=(size_t)sl;
        break;
    }

    case '.':
    default: {
        ptrdiff_t off = g_payload_base ? ((*p-1) - g_payload_base) : -1;
        fprintf(stderr,"[blob] Unknown tag 0x%02X ('%c') at payload+%td\n",
                (uint8_t)tag,(tag>=32&&tag<127)?tag:'?', off);
        return BLOB_ERR_CORRUPT;
    }
    }

#undef SEQ
    return BLOB_OK;
}

/* ------------------------------------------------------------------ */
/*  Public: parse constants                                             */
/* ------------------------------------------------------------------ */
BlobError blob_parse_constants(BlobCtx *ctx, BlobVal **out, uint32_t *cnt) {
    *out = NULL; *cnt = 0;
    if (!ctx->section_ptr) { fprintf(stderr,"[blob] Call blob_find_section() first.\n"); return BLOB_ERR_CORRUPT; }

    g_payload_base = ctx->payload;

    const uint8_t *p   = ctx->section_ptr;
    const uint8_t *end = p + ctx->section_size;
    if (p + 2 > end) return BLOB_ERR_CORRUPT;

    uint16_t count = read_u16(&p);
    printf("[blob] Section has %u top-level constants\n", count);

    BlobVal *vals = alloc_vals(count);
    if (!vals && count) return BLOB_ERR_ALLOC;

    for (uint32_t i = 0; i < count; i++) {
        BlobError e = unpack_one(&p, end, &vals[i]);
        if (e != BLOB_OK) {
            fprintf(stderr, "[blob] Failed on constant #%u\n", i);
            free(vals);
            return e;
        }
    }
    *out = vals; *cnt = count;
    return BLOB_OK;
}

/* ------------------------------------------------------------------ */
/*  Pretty-printer                                                      */
/* ------------------------------------------------------------------ */
static void pi(int n){ for(int i=0;i<n*2;i++) putchar(' '); }

void blob_print_val(const BlobVal *v, int indent) {
    pi(indent);
    switch(v->kind){
    case BVAL_NONE:    printf("None\n"); break;
    case BVAL_TRUE:    printf("True\n"); break;
    case BVAL_FALSE:   printf("False\n"); break;
    case BVAL_INT:     printf("int(%lld)\n",(long long)v->ival); break;
    case BVAL_BIGINT:  printf("bigint(%.*s)\n",(int)v->buf.len,v->buf.data); break;
    case BVAL_FLOAT:   printf("float(%g)\n",v->fval); break;
    case BVAL_COMPLEX: printf("complex(%g+%gj)\n",v->cval.real,v->cval.imag); break;
    case BVAL_STR:
        printf("str[%zu](%.*s)\n",v->buf.len,(int)(v->buf.len>80?80:v->buf.len),v->buf.data); break;
    case BVAL_BYTES:
        if(v->tag=='X'){
            printf("bytecode[%zu](",v->buf.len);
            for(size_t i=0;i<v->buf.len&&i<16;i++) printf("%02X ",v->buf.data[i]);
            if(v->buf.len>16) printf("...");
            printf(")\n");
        } else {
            printf("bytes[%zu](",v->buf.len);
            for(size_t i=0;i<v->buf.len&&i<20;i++) printf("%02X ",v->buf.data[i]);
            if(v->buf.len>20) printf("...");
            printf(")\n");
        }
        break;
    case BVAL_TUPLE: case BVAL_LIST: case BVAL_SET: case BVAL_FROZENSET:{
        const char *nm=v->kind==BVAL_TUPLE?"tuple":v->kind==BVAL_LIST?"list":
                       v->kind==BVAL_SET?"set":"frozenset";
        printf("%s[%zu]\n",nm,v->seq.count);
        for(size_t i=0;i<v->seq.count&&i<8;i++) blob_print_val(&v->seq.items[i],indent+1);
        if(v->seq.count>8){pi(indent+1);printf("...(%zu more)\n",v->seq.count-8);}
        break;}
    case BVAL_DICT:
        printf("dict[%zu]\n",v->dval.count);
        for(size_t i=0;i<v->dval.count&&i<4;i++){
            pi(indent+1);printf("key:");blob_print_val(&v->dval.keys[i],0);
            pi(indent+1);printf("val:");blob_print_val(&v->dval.vals[i],0);}
        if(v->dval.count>4){pi(indent+1);printf("...(%zu more)\n",v->dval.count-4);}
        break;
    case BVAL_SLICE: printf("slice\n"); for(int i=0;i<3;i++) blob_print_val(&v->seq.items[i],indent+1); break;
    case BVAL_RANGE: printf("range\n"); for(int i=0;i<3;i++) blob_print_val(&v->seq.items[i],indent+1); break;
    case BVAL_BUILTIN: printf("builtin(%s)\n",v->buf.data); break;
    case BVAL_CODE:    printf("%s\n",v->buf.data); break;
    case BVAL_BACKREF: printf("<backref #%d>\n",v->backref_offset); break;
    default:           printf("<unknown tag='%c'(0x%02X)>\n",v->tag,(uint8_t)v->tag); break;
    }
}

/* ------------------------------------------------------------------ */
/*  Free                                                                */
/* ------------------------------------------------------------------ */
static void fv(BlobVal *v) {
    switch (v->kind) {
    case BVAL_STR: case BVAL_BYTES: case BVAL_BIGINT:
    case BVAL_BUILTIN: case BVAL_CODE:
        if (v->buf.data && v->buf.data != (uint8_t *)"") { free(v->buf.data); }
        break;
    case BVAL_TUPLE: case BVAL_LIST: case BVAL_SET:
    case BVAL_FROZENSET: case BVAL_SLICE: case BVAL_RANGE:
        if (v->seq.items) {
            for (size_t i = 0; i < v->seq.count; i++) { fv(&v->seq.items[i]); }
            free(v->seq.items);
        }
        break;
    case BVAL_DICT:
        if (v->dval.keys) {
            for (size_t i = 0; i < v->dval.count; i++) {
                fv(&v->dval.keys[i]); fv(&v->dval.vals[i]);
            }
            free(v->dval.keys); free(v->dval.vals);
        }
        break;
    default: break;
    }
}
void blob_free_values(BlobVal *vals, uint32_t count) {
    if (!vals) { return; }
    for (uint32_t i = 0; i < count; i++) { fv(&vals[i]); }
    free(vals);
}
void blob_free(BlobCtx *ctx) {
    if (!ctx) { return; }
    free(ctx->raw); free(ctx->decrypted); free(ctx);
}


/* ------------------------------------------------------------------ */
/*  Best-effort full source reconstruction                             */
/* ------------------------------------------------------------------ */

#if defined(_WIN32)
#include <direct.h>
#define BLOB_MKDIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define BLOB_MKDIR(path) mkdir((path), 0755)
#endif
#include <ctype.h>
#include <errno.h>

typedef struct {
    char *name;
    char **lines;
    size_t count;
    size_t cap;
} SourceModule;

static const char *g_real_a_mods[] = {
    "abc", "ast", "asyncio", "asynchat", "asyncore", "atexit", "audioop",
    "array", "argparse", "annotated_types", "aiohttp", "attrs", "attr",
    "all", "any", "abs", "ascii", "aiter", "anext", NULL
};

static char *blob_strdup(const char *s) {
    size_t n;
    char *d;
    if (!s) {
        return NULL;
    }
    n = strlen(s);
    d = (char *)malloc(n + 1);
    if (!d) {
        return NULL;
    }
    memcpy(d, s, n + 1);
    return d;
}

static int path_is_dir(const char *path) {
    FILE *probe;
    if (!path || !*path) {
        return 0;
    }
    probe = fopen(path, "rb");
    if (probe) {
        fclose(probe);
        return 0;
    }
    if (errno == EISDIR) {
        return 1;
    }
#if defined(_WIN32)
    return errno == EACCES;
#else
    return 0;
#endif
}

static int ensure_dir_exists(const char *path) {
    char tmp[4096];
    size_t i;
    size_t n;

    if (!path || !*path) {
        return 0;
    }
    n = strlen(path);
    if (n >= sizeof(tmp)) {
        return 0;
    }
    memcpy(tmp, path, n + 1);

    for (i = 1; i < n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (tmp[0] != '\0' && BLOB_MKDIR(tmp) != 0) {
#if defined(_WIN32)
                if (errno != EEXIST && !path_is_dir(tmp)) {
                    tmp[i] = saved;
                    return 0;
                }
#else
                if (errno != EEXIST) {
                    tmp[i] = saved;
                    return 0;
                }
#endif
            }
            tmp[i] = saved;
        }
    }

    if (BLOB_MKDIR(tmp) != 0) {
#if defined(_WIN32)
        if (errno != EEXIST && !path_is_dir(tmp)) {
            return 0;
        }
#else
        if (errno != EEXIST) {
            return 0;
        }
#endif
    }
    return 1;
}

static void rstrip_in_place(char *s) {
    size_t n;
    if (!s) {
        return;
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) {
        s[--n] = '\0';
    }
}

static char *trim_in_place(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        s++;
    }
    rstrip_in_place(s);
    return s;
}

static int is_real_a_module(const char *token) {
    int i;
    for (i = 0; g_real_a_mods[i] != NULL; i++) {
        if (strcmp(token, g_real_a_mods[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static char *decode_a_prefix_token(const char *token) {
    if (token && token[0] == 'a' && token[1] != '\0' && islower((unsigned char)token[1]) && !is_real_a_module(token)) {
        return blob_strdup(token + 1);
    }
    return blob_strdup(token ? token : "");
}

static int is_windows_reserved_basename(const char *name) {
    static const char *reserved[] = {
        "con", "prn", "aux", "nul",
        "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
        NULL
    };
    char lower[64];
    size_t i;
    size_t n;
    if (!name || !*name) {
        return 0;
    }
    n = strlen(name);
    if (n >= sizeof(lower)) {
        n = sizeof(lower) - 1;
    }
    for (i = 0; i < n; i++) {
        lower[i] = (char)tolower((unsigned char)name[i]);
    }
    lower[n] = '\0';
    for (i = 0; reserved[i] != NULL; i++) {
        if (strcmp(lower, reserved[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static char *sanitize_module_name_for_path(const char *name) {
    size_t i;
    size_t n;
    size_t o = 0;
    char *out;
    const char *src = name ? name : "__main__";

    while (*src == "."[0]) {
        src++;
    }
    if (*src == '\0') {
        src = "__main__";
    }

    n = strlen(src);
    out = (char *)malloc(192);
    if (!out) {
        return NULL;
    }
    for (i = 0; i < n && o < 80; i++) {
        unsigned char ch = (unsigned char)src[i];
        if (isalnum(ch) || ch == "_"[0]) {
            out[o++] = (char)ch;
        } else if (o == 0 || out[o - 1] != "_"[0]) {
            out[o++] = "_"[0];
        }
    }
    while (o > 0 && out[o - 1] == "_"[0]) {
        o--;
    }
    out[o] = '\0';
    if (out[0] == '\0') {
        strcpy(out, "__main__");
    }
    if (is_windows_reserved_basename(out)) {
        size_t len = strlen(out);
        memmove(out + 4, out, len + 1);
        memcpy(out, "mod_", 4);
    }
    return out;
}

static int module_append_line(SourceModule *mod, const char *line) {
    char **new_lines;
    char *dup;
    size_t new_cap;

    if (!mod || !line) {
        return 0;
    }
    if (mod->count == mod->cap) {
        new_cap = (mod->cap == 0) ? 64 : (mod->cap * 2);
        new_lines = (char **)realloc(mod->lines, new_cap * sizeof(char *));
        if (!new_lines) {
            return 0;
        }
        mod->lines = new_lines;
        mod->cap = new_cap;
    }
    dup = blob_strdup(line);
    if (!dup) {
        return 0;
    }
    mod->lines[mod->count++] = dup;
    return 1;
}

static SourceModule *module_get_or_add(SourceModule **mods, size_t *count, size_t *cap, const char *name) {
    size_t i;
    SourceModule *new_mods;
    size_t new_cap;

    for (i = 0; i < *count; i++) {
        if (strcmp((*mods)[i].name, name) == 0) {
            return &(*mods)[i];
        }
    }
    if (*count == *cap) {
        new_cap = (*cap == 0) ? 16 : (*cap * 2);
        new_mods = (SourceModule *)realloc(*mods, new_cap * sizeof(SourceModule));
        if (!new_mods) {
            return NULL;
        }
        *mods = new_mods;
        *cap = new_cap;
    }
    memset(&(*mods)[*count], 0, sizeof(SourceModule));
    (*mods)[*count].name = blob_strdup(name);
    if (!(*mods)[*count].name) {
        return NULL;
    }
    (*count)++;
    return &(*mods)[(*count) - 1];
}

static void free_modules(SourceModule *mods, size_t count) {
    size_t i;
    size_t j;
    if (!mods) {
        return;
    }
    for (i = 0; i < count; i++) {
        free(mods[i].name);
        for (j = 0; j < mods[i].count; j++) {
            free(mods[i].lines[j]);
        }
        free(mods[i].lines);
    }
    free(mods);
}

static void normalize_blob_text(const uint8_t *src, size_t len, char *dst) {
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned char c = src[i];
        if (c == 0) {
            dst[i] = '\n';
        } else if (c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c <= 0x7e)) {
            dst[i] = (char)c;
        } else {
            dst[i] = ' ';
        }
    }
    dst[len] = '\0';
}

static char *slice_after_marker(char *text) {
    const char *markers[] = {"upython.exe", "\\python.exe", "python", NULL};
    char *best = NULL;
    int i;

    for (i = 0; markers[i] != NULL; i++) {
        char *p = strstr(text, markers[i]);
        if (p && (!best || p < best)) {
            best = p;
        }
    }
    if (best) {
        char *nl = strchr(best, '\n');
        if (nl && nl[1] != '\0') {
            return nl + 1;
        }
    }
    return text;
}

static int write_text_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        return 0;
    }
    if (text) {
        fwrite(text, 1, strlen(text), f);
    }
    fclose(f);
    return 1;
}

static int write_module_file(const char *out_dir,
                             const SourceModule *mod,
                             size_t module_index,
                             FILE *combined,
                             FILE *index_file,
                             int *out_opened_file) {
    char *safe_name;
    char file_name[512];
    char path[4096];
    FILE *f = NULL;
    size_t i;

    if (out_opened_file) {
        *out_opened_file = 0;
    }

    safe_name = sanitize_module_name_for_path(mod->name);
    if (!safe_name) {
        return 0;
    }

    if (strcmp(safe_name, "__main__") == 0) {
        snprintf(file_name, sizeof(file_name), "__main__.py");
    } else {
        snprintf(file_name, sizeof(file_name), "module_%04zu_%s.py", module_index, safe_name);
    }
    free(safe_name);

    snprintf(path, sizeof(path), "%s/%s", out_dir, file_name);
    f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr,
                "[blob] WARNING: could not open module file '%s' for module '%s' (errno=%d). Keeping output in combined_source.py only.\n",
                path,
                mod->name,
                errno);
    } else if (out_opened_file) {
        *out_opened_file = 1;
    }

    if (index_file) {
        fprintf(index_file,
                "%zu\t%s\t%s\t%s\n",
                module_index,
                mod->name,
                file_name,
                f ? "ok" : "combined_only");
    }

    if (f) {
        fprintf(f, "# Reconstructed from integrated Nuitka blob\n");
        fprintf(f, "# Module: %s\n\n", mod->name);
    }

    if (combined) {
        fprintf(combined, "# ==================================================\n");
        fprintf(combined, "# Module: %s\n", mod->name);
        fprintf(combined, "# ==================================================\n\n");
    }

    for (i = 0; i < mod->count; i++) {
        const char *line = mod->lines[i] ? mod->lines[i] : "";
        if (f) {
            fprintf(f, "%s\n", line);
        }
        if (combined) {
            fprintf(combined, "%s\n", line);
        }
    }
    if (combined) {
        fprintf(combined, "\n\n");
    }
    if (f) {
        fclose(f);
    }
    return 1;
}

BlobError blob_dump_full_source(BlobCtx *ctx, const char *out_dir, size_t *out_module_count) {
    const uint8_t *src;
    size_t src_len;
    char *normalized;
    char *scan;
    char *line;
    SourceModule *mods = NULL;
    size_t mod_count = 0;
    size_t mod_cap = 0;
    SourceModule *current_mod;
    char *prev_token = NULL;
    int prev_was_a = 0;
    char combined_path[4096];
    char raw_path[4096];
    FILE *combined = NULL;
    FILE *index_file = NULL;
    char index_path[4096];
    size_t i;

    if (out_module_count) {
        *out_module_count = 0;
    }
    if (!ctx || !out_dir) {
        return BLOB_ERR_CORRUPT;
    }

    src = ctx->decrypted ? ctx->decrypted : ctx->raw;
    src_len = ctx->raw_len;
    if (!src || src_len == 0) {
        return BLOB_ERR_CORRUPT;
    }

    if (!ensure_dir_exists(out_dir)) {
        fprintf(stderr, "[blob] Cannot create source output dir '%s' (errno=%d)\n", out_dir, errno);
        return BLOB_ERR_IO;
    }

    normalized = (char *)malloc(src_len + 1);
    if (!normalized) {
        return BLOB_ERR_ALLOC;
    }
    normalize_blob_text(src, src_len, normalized);
    scan = slice_after_marker(normalized);

    snprintf(raw_path, sizeof(raw_path), "%s/raw_source_dump.txt", out_dir);
    if (!write_text_file(raw_path, scan)) {
        fprintf(stderr,
                "[blob] WARNING: could not write raw source dump '%s' (errno=%d). Continuing.\n",
                raw_path,
                errno);
    }

    current_mod = module_get_or_add(&mods, &mod_count, &mod_cap, "__main__");
    if (!current_mod) {
        free(normalized);
        return BLOB_ERR_ALLOC;
    }

    for (line = strtok(scan, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        char *trimmed = trim_in_place(line);
        char *decoded = NULL;
        char *marker = NULL;
        char *module_name = NULL;

        if (*trimmed == '\0') {
            prev_was_a = 0;
            continue;
        }

        if (strcmp(trimmed, "u") == 0) {
            if (prev_token) {
                if (!module_append_line(current_mod, prev_token)) {
                    free(prev_token);
                    free_modules(mods, mod_count);
                    free(normalized);
                    return BLOB_ERR_ALLOC;
                }
                free(prev_token);
                prev_token = NULL;
            }
            if (!module_append_line(current_mod, "")) {
                free_modules(mods, mod_count);
                free(normalized);
                return BLOB_ERR_ALLOC;
            }
            prev_was_a = 0;
            continue;
        }

        decoded = decode_a_prefix_token(trimmed);
        if (!decoded) {
            free_modules(mods, mod_count);
            free(normalized);
            return BLOB_ERR_ALLOC;
        }

        marker = strstr(decoded, "a__module__");
        if (marker) {
            if (strcmp(decoded, "a__module__") == 0) {
                module_name = prev_token ? trim_in_place(prev_token) : NULL;
            } else {
                *marker = '\0';
                module_name = trim_in_place(decoded);
            }

            if (module_name && *module_name) {
                current_mod = module_get_or_add(&mods, &mod_count, &mod_cap, module_name);
                if (!current_mod) {
                    free(decoded);
                    free(prev_token);
                    free_modules(mods, mod_count);
                    free(normalized);
                    return BLOB_ERR_ALLOC;
                }
            }

            free(prev_token);
            prev_token = NULL;
            prev_was_a = 0;
            free(decoded);
            continue;
        }

        if (prev_was_a && decoded[0] != '\0' && isalpha((unsigned char)decoded[0])) {
            size_t n = strlen(decoded);
            char *with_def = (char *)malloc(n + 5);
            if (!with_def) {
                free(decoded);
                free(prev_token);
                free_modules(mods, mod_count);
                free(normalized);
                return BLOB_ERR_ALLOC;
            }
            strcpy(with_def, "def ");
            strcat(with_def, decoded);
            free(decoded);
            decoded = with_def;
        }

        if (prev_token) {
            if (!module_append_line(current_mod, prev_token)) {
                free(decoded);
                free(prev_token);
                free_modules(mods, mod_count);
                free(normalized);
                return BLOB_ERR_ALLOC;
            }
            free(prev_token);
        }
        prev_token = decoded;
        prev_was_a = (strcmp(decoded, "a") == 0);
    }

    if (prev_token) {
        if (!module_append_line(current_mod, prev_token)) {
            free(prev_token);
            free_modules(mods, mod_count);
            free(normalized);
            return BLOB_ERR_ALLOC;
        }
        free(prev_token);
        prev_token = NULL;
    }

    snprintf(combined_path, sizeof(combined_path), "%s/combined_source.py", out_dir);
    combined = fopen(combined_path, "wb");
    if (!combined) {
        free_modules(mods, mod_count);
        free(normalized);
        return BLOB_ERR_IO;
    }
    fprintf(combined, "# Best-effort integrated source reconstruction\n");
    fprintf(combined, "# Generated from raw Nuitka RCDATA blob\n\n");

    snprintf(index_path, sizeof(index_path), "%s/module_index.tsv", out_dir);
    index_file = fopen(index_path, "wb");
    if (index_file) {
        fprintf(index_file, "index\tmodule_name\tfile_name\tstatus\n");
    } else {
        fprintf(stderr,
                "[blob] WARNING: could not write module index '%s' (errno=%d). Continuing.\n",
                index_path,
                errno);
    }

    for (i = 0; i < mod_count; i++) {
        int opened_file = 0;
        if (!write_module_file(out_dir, &mods[i], i, combined, index_file, &opened_file)) {
            if (index_file) {
                fclose(index_file);
            }
            fclose(combined);
            free_modules(mods, mod_count);
            free(normalized);
            return BLOB_ERR_IO;
        }
    }

    if (index_file) {
        fclose(index_file);
    }
    fclose(combined);
    if (out_module_count) {
        *out_module_count = mod_count;
    }
    free_modules(mods, mod_count);
    free(normalized);
    return BLOB_OK;
}


/* ------------------------------------------------------------------ */
/*  PyLingual bundle export                                            */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  PyLingual bundle export                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char **names;
    size_t count;
    size_t cap;
} ModuleHintSet;

typedef struct {
    const char *out_dir;
    const uint8_t *pyc_magic;
    FILE *manifest;
    FILE *pyc_list;
    FILE *marshal_list;
    uint32_t next_ordinal;
    uint32_t written;
    uint32_t current_top_index;
    uint32_t current_sub_index;
    char *current_top_hint;
    ModuleHintSet source_hints;
} PyLingualExportCtx;

static int ensure_dir_exists_ok(const char *path) {
    if (!path || !*path) {
        return 0;
    }
    if (BLOB_MKDIR(path) == 0) {
        return 1;
    }
#if defined(_WIN32)
    return errno == EEXIST || errno == EACCES;
#else
    return errno == EEXIST;
#endif
}

static void bytes_to_hex(const uint8_t *src, size_t len, char *dst, size_t dst_len) {
    static const char hexdig[] = "0123456789ABCDEF";
    size_t i;
    size_t p = 0;
    if (!dst || dst_len == 0) {
        return;
    }
    for (i = 0; i < len && p + 2 < dst_len; i++) {
        dst[p++] = hexdig[(src[i] >> 4) & 0xF];
        dst[p++] = hexdig[src[i] & 0xF];
    }
    dst[p] = '\0';
}

static int write_u32_le(FILE *f, uint32_t value) {
    uint8_t b[4];
    b[0] = (uint8_t)(value & 0xFF);
    b[1] = (uint8_t)((value >> 8) & 0xFF);
    b[2] = (uint8_t)((value >> 16) & 0xFF);
    b[3] = (uint8_t)((value >> 24) & 0xFF);
    return fwrite(b, 1, 4, f) == 4;
}

static int looks_like_marshaled_code_blob(const uint8_t *data, size_t len) {
    if (!data || len < 8) {
        return 0;
    }
    /* CPython marshal TYPE_CODE is 'c' (0x63); with FLAG_REF it becomes 0xE3. */
    return data[0] == 0x63 || data[0] == 0xE3;
}

static void module_hintset_free(ModuleHintSet *set) {
    size_t i;
    if (!set) {
        return;
    }
    for (i = 0; i < set->count; i++) {
        free(set->names[i]);
    }
    free(set->names);
    set->names = NULL;
    set->count = 0;
    set->cap = 0;
}

static int is_plausible_module_hint(const char *s) {
    size_t i;
    size_t n;
    if (!s || !*s) {
        return 0;
    }
    if (strcmp(s, "<module>") == 0 || strcmp(s, "<lambda>") == 0 || strcmp(s, "<listcomp>") == 0 ||
        strcmp(s, "<dictcomp>") == 0 || strcmp(s, "<setcomp>") == 0 || strcmp(s, "<genexpr>") == 0) {
        return 0;
    }
    n = strlen(s);
    if (n == 0 || n > 180) {
        return 0;
    }
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_')) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (!(isalnum(ch) || ch == '_' || ch == '.')) {
            return 0;
        }
    }
    return 1;
}

static const char *module_hintset_find_exact(const ModuleHintSet *set, const char *name) {
    size_t i;
    if (!set || !name || !*name) {
        return NULL;
    }
    for (i = 0; i < set->count; i++) {
        if (strcmp(set->names[i], name) == 0) {
            return set->names[i];
        }
    }
    return NULL;
}

static const char *module_hintset_resolve_basename(const ModuleHintSet *set, const char *base) {
    size_t i;
    const char *match = NULL;
    if (!set || !base || !*base) {
        return NULL;
    }
    for (i = 0; i < set->count; i++) {
        const char *full = set->names[i];
        const char *tail = strrchr(full, '.');
        tail = tail ? tail + 1 : full;
        if (strcmp(tail, base) == 0) {
            if (match && strcmp(match, full) != 0) {
                return NULL;
            }
            match = full;
        }
    }
    return match;
}

static int module_hintset_add(ModuleHintSet *set, const char *name) {
    char *dup;
    char **new_names;
    size_t new_cap;

    if (!set || !name || !*name || !is_plausible_module_hint(name)) {
        return 1;
    }
    if (module_hintset_find_exact(set, name)) {
        return 1;
    }
    if (set->count == set->cap) {
        new_cap = (set->cap == 0) ? 64 : (set->cap * 2);
        new_names = (char **)realloc(set->names, new_cap * sizeof(char *));
        if (!new_names) {
            return 0;
        }
        set->names = new_names;
        set->cap = new_cap;
    }
    dup = blob_strdup(name);
    if (!dup) {
        return 0;
    }
    set->names[set->count++] = dup;
    return 1;
}

static char *module_hint_from_output_file(const char *file_name) {
    const char *base;
    const char *dot;
    char temp[256];
    size_t n;
    if (!file_name || !*file_name) {
        return NULL;
    }
    base = file_name;
    if (strcmp(base, "__main__.py") == 0) {
        return blob_strdup("__main__");
    }
    if (strncmp(base, "module_", 7) == 0) {
        const char *p = base + 7;
        while (*p && isdigit((unsigned char)*p)) {
            p++;
        }
        if (*p == '_') {
            base = p + 1;
        }
    }
    dot = strrchr(base, '.');
    n = dot ? (size_t)(dot - base) : strlen(base);
    if (n == 0 || n >= sizeof(temp)) {
        return NULL;
    }
    memcpy(temp, base, n);
    temp[n] = '\0';
    return blob_strdup(temp);
}

static int load_source_hints_from_dir(const char *source_dir, ModuleHintSet *set) {
    char index_path[4096];
    FILE *f;
    char line[4096];
    if (!source_dir || !set) {
        return 1;
    }
    snprintf(index_path, sizeof(index_path), "%s/module_index.tsv", source_dir);
    f = fopen(index_path, "rb");
    if (!f) {
        return 1;
    }
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *c1;
        char *c2;
        char *c3;
        char *module_name;
        char *file_name;
        char *derived;
        if (strncmp(p, "index\t", 6) == 0) {
            continue;
        }
        c1 = strchr(p, '\t');
        if (!c1) {
            continue;
        }
        c2 = strchr(c1 + 1, '\t');
        if (!c2) {
            continue;
        }
        c3 = strchr(c2 + 1, '\t');
        if (!c3) {
            continue;
        }
        *c1 = '\0';
        *c2 = '\0';
        *c3 = '\0';
        module_name = trim_in_place(c1 + 1);
        file_name = trim_in_place(c2 + 1);
        module_hintset_add(set, module_name);
        derived = module_hint_from_output_file(file_name);
        if (derived) {
            module_hintset_add(set, derived);
            free(derived);
        }
    }
    fclose(f);
    return 1;
}

static char *normalize_module_hint_candidate(const char *raw,
                                             const ModuleHintSet *known,
                                             int require_path_or_known,
                                             int *score_out) {
    char temp[512];
    size_t n;
    char *s;
    char *candidate;
    char *slash;
    char *py;
    int path_like = 0;
    const char *exact;
    const char *resolved;
    int score = -1;

    if (score_out) {
        *score_out = -1;
    }
    if (!raw || !*raw) {
        return NULL;
    }

    n = strlen(raw);
    if (n >= sizeof(temp)) {
        n = sizeof(temp) - 1;
    }
    memcpy(temp, raw, n);
    temp[n] = '\0';
    s = trim_in_place(temp);

    while (*s == '\'' || *s == '"' || *s == '<' || *s == '(' || *s == '[' || *s == '{') {
        s++;
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\'' || s[n - 1] == '"' || s[n - 1] == '>' ||
                     s[n - 1] == ')' || s[n - 1] == ']' || s[n - 1] == '}' ||
                     s[n - 1] == ':' || s[n - 1] == ',' || s[n - 1] == ';')) {
        s[--n] = '\0';
    }
    if (*s == '\0') {
        return NULL;
    }

    for (candidate = s; *candidate; candidate++) {
        if (*candidate == '\\') {
            *candidate = '/';
        }
    }

    candidate = s;
    if (strchr(candidate, '/')) {
        path_like = 1;
    }
    py = strstr(candidate, ".py");
    if (py) {
        char *last_slash = py;
        path_like = 1;
        while (last_slash > candidate && last_slash[-1] != '/') {
            last_slash--;
        }
        *py = '\0';
        candidate = last_slash;
        if (strcmp(candidate, "__init__") == 0 && last_slash > s) {
            char *prev = last_slash - 1;
            *py = '\0';
            while (prev > s && prev[-1] != '/') {
                prev--;
            }
            if (*prev) {
                candidate = prev;
            }
        }
    } else {
        slash = strrchr(candidate, '/');
        if (slash && slash[1] != '\0') {
            candidate = slash + 1;
            path_like = 1;
        }
    }

    while (*candidate == '.') {
        candidate++;
    }
    if (!*candidate) {
        return NULL;
    }

    exact = module_hintset_find_exact(known, candidate);
    if (exact) {
        if (score_out) {
            *score_out = 1000;
        }
        return blob_strdup(exact);
    }

    resolved = module_hintset_resolve_basename(known, candidate);
    if (resolved) {
        if (score_out) {
            *score_out = 900;
        }
        return blob_strdup(resolved);
    }

    if (!is_plausible_module_hint(candidate)) {
        return NULL;
    }

    if (require_path_or_known && !path_like) {
        return NULL;
    }

    score = path_like ? 700 : 500;
    if (strcmp(candidate, "__main__") == 0) {
        score += 50;
    }
    if (score_out) {
        *score_out = score;
    }
    return blob_strdup(candidate);
}

static char *guess_module_hint_from_bytes(const uint8_t *data, size_t len, const ModuleHintSet *known) {
    size_t i = 0;
    char *best = NULL;
    int best_score = -1;

    if (!data || len < 3) {
        return NULL;
    }

    while (i < len) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            size_t start = i;
            char run[256];
            size_t run_len;
            int score = -1;
            char *cand;
            while (i < len && data[i] >= 0x20 && data[i] <= 0x7E) {
                i++;
            }
            run_len = i - start;
            if (run_len < 3) {
                continue;
            }
            if (run_len >= sizeof(run)) {
                run_len = sizeof(run) - 1;
            }
            memcpy(run, data + start, run_len);
            run[run_len] = '\0';
            cand = normalize_module_hint_candidate(run, known, 1, &score);
            if (cand) {
                if (score > best_score) {
                    free(best);
                    best = cand;
                    best_score = score;
                } else {
                    free(cand);
                }
            }
        } else {
            i++;
        }
    }

    return best;
}

static char *guess_module_hint_from_blobval(const BlobVal *v, const ModuleHintSet *known) {
    int score = -1;
    if (!v) {
        return NULL;
    }
    switch (v->kind) {
    case BVAL_BYTES:
        return guess_module_hint_from_bytes(v->buf.data, v->buf.len, known);
    case BVAL_STR:
    case BVAL_BUILTIN:
        return normalize_module_hint_candidate((const char *)v->buf.data, known, 1, &score);
    default:
        return NULL;
    }
}

static char *guess_top_level_hint(const BlobVal *vals,
                                  uint32_t count,
                                  uint32_t top_index,
                                  const ModuleHintSet *known) {
    static const int offsets[] = {0, -1, 1, -2, 2, -3, 3};
    size_t j;
    for (j = 0; j < sizeof(offsets) / sizeof(offsets[0]); j++) {
        int idx = (int)top_index + offsets[j];
        char *hint;
        if (idx < 0 || (uint32_t)idx >= count) {
            continue;
        }
        hint = guess_module_hint_from_blobval(&vals[idx], known);
        if (hint) {
            return hint;
        }
    }
    return NULL;
}

static BlobError write_single_pylingual_blob(PyLingualExportCtx *ctx, const BlobVal *v) {
    char marshal_path[4096];
    char pyc_path[4096];
    char magic_hex[16];
    char head_hex[34];
    char *raw_hint = NULL;
    char *safe_hint = NULL;
    const char *hint_source = "none";
    FILE *fm = NULL;
    FILE *fp = NULL;
    size_t preview_len;
    uint32_t sub_index = ctx->current_sub_index;

    raw_hint = guess_module_hint_from_bytes(v->buf.data, v->buf.len, &ctx->source_hints);
    if (raw_hint) {
        hint_source = "marshal";
    } else if (ctx->current_top_hint) {
        raw_hint = blob_strdup(ctx->current_top_hint);
        hint_source = "top_hint";
    }

    if (raw_hint) {
        safe_hint = sanitize_module_name_for_path(raw_hint);
    }

    if (safe_hint && *safe_hint) {
        if (sub_index == 0) {
            snprintf(marshal_path, sizeof(marshal_path), "%s/bytecode_top%04u__%s.marshal",
                     ctx->out_dir, ctx->current_top_index, safe_hint);
            snprintf(pyc_path, sizeof(pyc_path), "%s/bytecode_top%04u__%s.pyc",
                     ctx->out_dir, ctx->current_top_index, safe_hint);
        } else {
            snprintf(marshal_path, sizeof(marshal_path), "%s/bytecode_top%04u_sub%03u__%s.marshal",
                     ctx->out_dir, ctx->current_top_index, sub_index, safe_hint);
            snprintf(pyc_path, sizeof(pyc_path), "%s/bytecode_top%04u_sub%03u__%s.pyc",
                     ctx->out_dir, ctx->current_top_index, sub_index, safe_hint);
        }
    } else {
        if (sub_index == 0) {
            snprintf(marshal_path, sizeof(marshal_path), "%s/bytecode_top%04u.marshal",
                     ctx->out_dir, ctx->current_top_index);
            snprintf(pyc_path, sizeof(pyc_path), "%s/bytecode_top%04u.pyc",
                     ctx->out_dir, ctx->current_top_index);
        } else {
            snprintf(marshal_path, sizeof(marshal_path), "%s/bytecode_top%04u_sub%03u.marshal",
                     ctx->out_dir, ctx->current_top_index, sub_index);
            snprintf(pyc_path, sizeof(pyc_path), "%s/bytecode_top%04u_sub%03u.pyc",
                     ctx->out_dir, ctx->current_top_index, sub_index);
        }
    }

    fm = fopen(marshal_path, "wb");
    if (!fm) {
        free(raw_hint);
        free(safe_hint);
        return BLOB_ERR_IO;
    }
    if (v->buf.len && fwrite(v->buf.data, 1, v->buf.len, fm) != v->buf.len) {
        fclose(fm);
        free(raw_hint);
        free(safe_hint);
        return BLOB_ERR_IO;
    }
    fclose(fm);

    fp = fopen(pyc_path, "wb");
    if (!fp) {
        free(raw_hint);
        free(safe_hint);
        return BLOB_ERR_IO;
    }
    if (fwrite(ctx->pyc_magic, 1, 4, fp) != 4 ||
        !write_u32_le(fp, 0) ||
        !write_u32_le(fp, 0) ||
        !write_u32_le(fp, 0) ||
        (v->buf.len && fwrite(v->buf.data, 1, v->buf.len, fp) != v->buf.len)) {
        fclose(fp);
        free(raw_hint);
        free(safe_hint);
        return BLOB_ERR_IO;
    }
    fclose(fp);

    if (ctx->marshal_list) {
        fprintf(ctx->marshal_list, "%s\n", marshal_path);
    }
    if (ctx->pyc_list) {
        fprintf(ctx->pyc_list, "%s\n", pyc_path);
    }
    if (ctx->manifest) {
        bytes_to_hex(ctx->pyc_magic, 4, magic_hex, sizeof(magic_hex));
        preview_len = v->buf.len < 16 ? v->buf.len : 16;
        bytes_to_hex(v->buf.data, preview_len, head_hex, sizeof(head_hex));
        fprintf(ctx->manifest,
                "%u\t%u\t%u\t%c\t%s\t%s\t%zu\t%s\t%s\t%s\t%s\n",
                ctx->next_ordinal,
                ctx->current_top_index,
                sub_index,
                v->tag ? v->tag : '?',
                raw_hint ? raw_hint : "",
                hint_source,
                v->buf.len,
                marshal_path,
                pyc_path,
                magic_hex,
                head_hex);
    }

    ctx->current_sub_index++;
    ctx->next_ordinal++;
    ctx->written++;
    free(raw_hint);
    free(safe_hint);
    return BLOB_OK;
}

static BlobError export_value_pylingual(PyLingualExportCtx *ctx, const BlobVal *v) {
    size_t i;
    BlobError e;
    if (!v) {
        return BLOB_OK;
    }
    switch (v->kind) {
    case BVAL_BYTES:
        if (v->tag == 'X' || looks_like_marshaled_code_blob(v->buf.data, v->buf.len)) {
            return write_single_pylingual_blob(ctx, v);
        }
        return BLOB_OK;
    case BVAL_TUPLE:
    case BVAL_LIST:
    case BVAL_SET:
    case BVAL_FROZENSET:
    case BVAL_SLICE:
    case BVAL_RANGE:
        for (i = 0; i < v->seq.count; i++) {
            e = export_value_pylingual(ctx, &v->seq.items[i]);
            if (e != BLOB_OK) {
                return e;
            }
        }
        return BLOB_OK;
    case BVAL_DICT:
        for (i = 0; i < v->dval.count; i++) {
            e = export_value_pylingual(ctx, &v->dval.keys[i]);
            if (e != BLOB_OK) {
                return e;
            }
            e = export_value_pylingual(ctx, &v->dval.vals[i]);
            if (e != BLOB_OK) {
                return e;
            }
        }
        return BLOB_OK;
    default:
        return BLOB_OK;
    }
}

BlobError blob_write_pylingual_helper(const char *out_dir, const uint8_t default_magic[4]) {
    static const char *helper_script =
        "#!/usr/bin/env python3\n"
        "from __future__ import annotations\n"
        "import argparse\n"
        "import importlib.util\n"
        "from pathlib import Path\n"
        "\n"
        "def parse_magic(value: str | None) -> bytes:\n"
        "    if not value:\n"
        "        return importlib.util.MAGIC_NUMBER\n"
        "    value = value.strip().lower().replace('0x', '').replace(' ', '')\n"
        "    if len(value) != 8:\n"
        "        raise SystemExit('magic must be exactly 8 hex characters, e.g. a70d0d0a')\n"
        "    return bytes.fromhex(value)\n"
        "\n"
        "def build_pyc(marshal_bytes: bytes, magic: bytes) -> bytes:\n"
        "    return magic + (0).to_bytes(4, 'little') + (0).to_bytes(4, 'little') + (0).to_bytes(4, 'little') + marshal_bytes\n"
        "\n"
        "def main() -> int:\n"
        "    ap = argparse.ArgumentParser(description='Rebuild .pyc files from exported Nuitka marshal blobs')\n"
        "    ap.add_argument('bundle_dir', nargs='?', default='.', help='Directory containing bytecode_*.marshal')\n"
        "    ap.add_argument('--magic-hex', help='Override 4-byte MAGIC_NUMBER as 8 hex chars (e.g. a70d0d0a for Python 3.11)')\n"
        "    args = ap.parse_args()\n"
        "\n"
        "    bundle_dir = Path(args.bundle_dir)\n"
        "    magic = parse_magic(args.magic_hex)\n"
        "    pyc_list = []\n"
        "    for path in sorted(bundle_dir.glob('bytecode_*.marshal')):\n"
        "        pyc_path = path.with_suffix('.pyc')\n"
        "        pyc_path.write_bytes(build_pyc(path.read_bytes(), magic))\n"
        "        pyc_list.append(str(pyc_path))\n"
        "        print(f'[make_pyc_list] wrote {pyc_path}')\n"
        "    (bundle_dir / 'pyc_list.txt').write_text('\\n'.join(pyc_list) + ('\\n' if pyc_list else ''), encoding='utf-8')\n"
        "    print(f'[make_pyc_list] wrote {len(pyc_list)} pyc path(s) to {bundle_dir / \"pyc_list.txt\"}')\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    raise SystemExit(main())\n";
    char helper_path[4096];
    char readme_path[4096];
    char magic_hex[16];
    FILE *f;

    if (!out_dir || !default_magic) {
        return BLOB_ERR_CORRUPT;
    }
    if (!ensure_dir_exists_ok(out_dir)) {
        return BLOB_ERR_IO;
    }

    snprintf(helper_path, sizeof(helper_path), "%s/make_pyc_list.py", out_dir);
    f = fopen(helper_path, "wb");
    if (!f) {
        return BLOB_ERR_IO;
    }
    fwrite(helper_script, 1, strlen(helper_script), f);
    fclose(f);

    bytes_to_hex(default_magic, 4, magic_hex, sizeof(magic_hex));
    snprintf(readme_path, sizeof(readme_path), "%s/README.txt", out_dir);
    f = fopen(readme_path, "wb");
    if (!f) {
        return BLOB_ERR_IO;
    }
    fprintf(f,
            "PyLingual bundle generated from Nuitka marshal/code blobs.\n\n"
            "Files:\n"
            "  - bytecode_topXXXX*.marshal : raw marshal/code-object blob\n"
            "  - bytecode_topXXXX*.pyc     : .pyc rebuilt with the selected magic\n"
            "  - pyc_list.txt              : one .pyc path per line\n"
            "  - marshal_list.txt          : one raw marshal path per line\n"
            "  - manifest.tsv              : export manifest with top-level indexes\n\n"
            "Default MAGIC_NUMBER used here: %s\n"
            "For Python 3.11 final that value is A70D0D0A.\n"
            "If you need a different header, run:\n"
            "  python make_pyc_list.py --magic-hex <8hex> .\n\n"
            "PyLingual usage example:\n"
            "  pylingual -v 3.11 -o out bytecode_*.pyc\n",
            magic_hex);
    fclose(f);
    return BLOB_OK;
}

BlobError blob_export_pylingual_bundle(const BlobVal *vals,
                                       uint32_t count,
                                       const char *out_dir,
                                       const char *source_dir,
                                       const uint8_t pyc_magic[4],
                                       uint32_t *out_written) {
    PyLingualExportCtx ctx;
    char manifest_path[4096];
    char pyc_list_path[4096];
    char marshal_list_path[4096];
    BlobError e;
    uint32_t i;

    if (out_written) {
        *out_written = 0;
    }
    if (!vals || !out_dir || !pyc_magic) {
        return BLOB_ERR_CORRUPT;
    }
    if (!ensure_dir_exists_ok(out_dir)) {
        fprintf(stderr, "[blob] Cannot create export dir '%s' (errno=%d)\n", out_dir, errno);
        return BLOB_ERR_IO;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.out_dir = out_dir;
    ctx.pyc_magic = pyc_magic;
    load_source_hints_from_dir(source_dir, &ctx.source_hints);

    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.tsv", out_dir);
    snprintf(pyc_list_path, sizeof(pyc_list_path), "%s/pyc_list.txt", out_dir);
    snprintf(marshal_list_path, sizeof(marshal_list_path), "%s/marshal_list.txt", out_dir);

    ctx.manifest = fopen(manifest_path, "wb");
    ctx.pyc_list = fopen(pyc_list_path, "wb");
    ctx.marshal_list = fopen(marshal_list_path, "wb");
    if (!ctx.manifest || !ctx.pyc_list || !ctx.marshal_list) {
        if (ctx.manifest) fclose(ctx.manifest);
        if (ctx.pyc_list) fclose(ctx.pyc_list);
        if (ctx.marshal_list) fclose(ctx.marshal_list);
        module_hintset_free(&ctx.source_hints);
        return BLOB_ERR_IO;
    }

    fprintf(ctx.manifest,
            "ordinal\ttop_index\tsub_index\torigin_tag\tmodule_hint\thint_source\tsize\tmarshal_path\tpyc_path\tpyc_magic\tfirst16_hex\n");

    e = blob_write_pylingual_helper(out_dir, pyc_magic);
    if (e != BLOB_OK) {
        fclose(ctx.manifest);
        fclose(ctx.pyc_list);
        fclose(ctx.marshal_list);
        module_hintset_free(&ctx.source_hints);
        return e;
    }

    for (i = 0; i < count; i++) {
        ctx.current_top_index = i;
        ctx.current_sub_index = 0;
        free(ctx.current_top_hint);
        ctx.current_top_hint = guess_top_level_hint(vals, count, i, &ctx.source_hints);
        e = export_value_pylingual(&ctx, &vals[i]);
        if (e != BLOB_OK) {
            fclose(ctx.manifest);
            fclose(ctx.pyc_list);
            fclose(ctx.marshal_list);
            free(ctx.current_top_hint);
            module_hintset_free(&ctx.source_hints);
            return e;
        }
    }

    fclose(ctx.manifest);
    fclose(ctx.pyc_list);
    fclose(ctx.marshal_list);
    free(ctx.current_top_hint);
    module_hintset_free(&ctx.source_hints);

    if (out_written) {
        *out_written = ctx.written;
    }
    return BLOB_OK;
}
