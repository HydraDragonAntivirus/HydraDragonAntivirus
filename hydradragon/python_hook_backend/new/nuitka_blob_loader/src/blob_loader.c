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
