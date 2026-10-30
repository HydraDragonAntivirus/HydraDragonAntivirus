# Unpacker signatures

An unpacker signature says how to unpack one packer. It has two parts:

- **conditions**: hydradragonsig conditions that recognise the packer (the same
  `pe_section`, `pe_anchor_pattern`, `unpacker_any`, `byte_pattern`, ... as a
  detection rule, with `logic` / `threshold`). See hydradragonsig `FORMAT.md`.
- **unpack**: the recipe, a small program that turns the file into its payload(s).

The header only picks the recipe. A step that cannot do what it says (a pattern
that is not there, a read past the end, a stream that does not decompress, an
emulated condition that never happens) fails the recipe, and the caller falls back
to its generic emulation. A fake header over other code, or a variant the recipe
does not know, therefore never yields a wrong payload.

Rules are tried in file order; the first one whose conditions match runs. The
engine ships no built-in rules (`UnpackRules::builtin()` is empty).
`UnpackRules::builtin_with_file` / `from_file` load a rule file; a rule with an
existing `id` replaces it, new ids are tried first. Rules are checked when they are
loaded: unknown keys, bad patterns / keys / expressions, emulation inside `try` /
`repeat`, and recipes that never give a payload are errors.

```yaml
version: 1
rules:
  - id: example_container
    description: payload blocks after a "PKD!" header, XOR 0x5A, some zlib
    conditions:
      - {type: byte_pattern, pattern: "{ 50 4B 44 21 }"}
    unpack:
      - find: {pattern: "50 4B 44 21", align: 16, as: hdr}
      - read: {at: hdr + 4, type: u32, as: count}
      - set: {pos: hdr + 8, i: 0}
      - repeat:
          while: i < count
          steps:
            - read: {at: pos, type: u32, as: n}
            - take: {at: pos + 4, len: n & 0x7fffffff, as: block}
            - xor: {in: block, key: "5A"}
            - if:
                cond: (n & 0x80000000) != 0
                then: [{decompress: {in: block, method: zlib}}]
            - emit: block
            - set: {pos: pos + 4 + (n & 0x7fffffff), i: i + 1}

  - id: example_self_decrypting_stub
    conditions:
      - {type: pe_section, name: .data}
    unpack:
      - section: {name: .data, as: d}
      - run_until: {write_execute: true, outside: [.text]}
      - check: ip == image_base + d_rva
      - set_oep: ip
      - dump
```

## State

- **Variables**: integers (`set`, `read`, `find`, ...). Predefined: `file_size`;
  for a PE also `entry_rva`, `image_base`, `size_of_image`, `overlay` (offset where
  the overlay starts, `file_size` without one), `is_64`, `sections`.
- **Buffers**: named byte strings. `file` is the input (read-only). Steps that
  write a buffer take `as`; transforms without `as` change their input in place.
- **Payloads**: what `emit` and `dump` give. A recipe that ends without one fails.

## Expressions

Any integer field is an expression: a YAML number or a string with C operators and
precedence (`|| && | ^ & == != < <= > >= << >> + - * / %`, unary `! ~ -`,
parentheses). Comparisons and logic give 1 / 0. Note that, as in C, `==` binds
tighter than `&`: write `(n & 0x80000000) != 0`. Functions: `len(buffer)`,
`rva2off(rva)`, `off2rva(offset)`, `min(a, b)`, `max(a, b)`. Values are 128-bit:
no u32 / u64 field overflows an addition; overflow and division by zero fail.

## Steps

### Data

| step | does |
|---|---|
| `find: {in, pattern, from, align, offset, as}` | Offset of a hex pattern (`??` = any byte, first byte fixed) in `in` (default `file`), searched from `from`. With `align`, only a match whose `match + offset` is a multiple of it counts. The variable gets `match + offset`. |
| `read: {in, at, type, big_endian, as}` | An integer: `type` is `u8 u16 u32 u64 i8 i16 i32 i64`. |
| `take: {in, at, len, as}` | `len` bytes at `at` (default: to the end) as a buffer. |
| `set: {var: expr, ...}` | Assign variables, in order. |
| `check: expr` | Fail unless the expression is not 0. |
| `section: {name or index, as}` | Raw data of a PE section as a buffer; variables `<as>_off _size _rva _vsize _flags`. |
| `resource: {type, name, nth, as}` | Data of a PE resource. `type` / `name`: a number (`10` = RT_RCDATA) or a name; omitted = any. `nth`: of the matches in directory order. |

### Transforms

| step | does |
|---|---|
| `decompress: {in, method, size, method_as, as}` | `method` is one codec or a list tried in order: `deflate`, `zlib`, `gzip`, `lzma` (5 props + raw stream, as in 7-Zip and NSIS), `lzma_alone`, `bzip2`, `nsis_bzip2` (no `BZh` header; NSIS 2.x+ and 1.x block layouts), `aplib`, `lznt1`. `size`: exact output size when the format does not store it. `method_as`: variable that gets the index of the codec that worked. |
| `xor` / `add` / `sub: {in, key or key_buf, from, as}` | Byte-wise with a repeating key: `key: "6B 65 79"` (hex) or `key_buf: buffer`. Bytes before `from` stay as they are. |
| `rc4: {in, key or key_buf, from, as}` | RC4. |
| `rol` / `ror: {in, bits, as}` | Rotate every byte. |
| `base64: {in, as}` | Base64 decode (whitespace ignored, URL-safe letters accepted). |
| `reverse: {in, as}` | Reverse the bytes. |
| `join: {parts: [a, b], as}` | Concatenate buffers. |

### Flow and output

| step | does |
|---|---|
| `if: {cond, then: [...], else: [...]}` | Branch. |
| `try: [[...], [...]]` | Alternatives: the first that does not fail is kept; a failed one leaves no variables, buffers or payloads behind. All failing fails the step. |
| `repeat: {while, max, steps: [...]}` | Loop while `while` is not 0. Over `max` iterations (default 100000) fails. |
| `emit: buffer` | The buffer is a payload. |

### Emulation

The file is loaded into the emulator at its entry point the first time one of
these runs. They cannot be inside `try` or `repeat`.

| step | does |
|---|---|
| `run_until: {...}` | Emulate from the current instruction until one of the conditions holds; the run stops **before** that instruction. Sets `ip`; when it stops at an API, also `arg0`..`arg7` (the call's arguments, x86 stack or x64 RCX/RDX/R8/R9/stack). Ending first (budget, exit, fault, an API it cannot return from) fails. |
| `mem: {at, len, as}` | Emulated memory at a virtual address as a buffer (e.g. `mem: {at: arg0, len: arg1, as: blob}` after stopping at `VirtualProtect`). |
| `set_oep: ip` / `{rva: expr}` / `{va: expr}` | Set the instruction pointer: the entry point of the next `dump`. |
| `dump` | The memory image is a payload: entry point = instruction pointer, imports rebuilt from the API stubs. |
| `dump_alloc` | The allocated memory region the code runs in is a payload (the instruction pointer's region when it is outside the image, else the first write-execute outside it): a PE mapped there (found at a page boundary) is dumped like the image with that entry point, anything else is the raw region. |

`write_execute` covers allocated memory too: writes into the VirtualAlloc / heap
area are tracked like writes into the image, so a stub that decrypts its payload
into allocated memory and jumps there stops `run_until: {write_execute: true}`.

`run_until` keys (at least one condition):

| key | stops when |
|---|---|
| `write_execute: true` | Code runs from a page this run wrote. |
| `api: [VirtualProtect]` | One of these APIs is called. Names match without leading `_`, `@n` or DLL prefix, case-insensitive. |
| `section: [.text]` | Execution enters one of these sections. |
| `ip_pattern: ["61 E9"]` | A basic block starts with one of these hex patterns. |
| `outside: [UPX1]` | No condition stops inside these sections (the stub's own). |
| `max_instructions`, `timeout_ms` | Budget of this step (default: the caller's). |

## Limits

A buffer holds at most 256 MB, all payloads of one run 512 MB together, and a run
executes at most 2,000,000 steps (loop iterations included). Every decoder is
bounded by the buffer limit.
