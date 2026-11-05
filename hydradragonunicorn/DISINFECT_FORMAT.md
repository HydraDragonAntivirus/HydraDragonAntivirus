# HydraDragon disinfection definitions

`disinfect_rules/default.yaml` is compiled into hydradragonunicorn
(`DisinfectRules::builtin()`). Extra files load with
`DisinfectRules::builtin_with_file(path)` (a definition with the same name
replaces the built-in one) and run with `disinfect_bytes_with(data, &rules)`.

A file is repaired **only when a definition recognises the virus by its
signature**. Unknown infections are never "repaired".

## How a definition runs

1. The file is mapped with Unicorn in the unpacker's Windows environment
   (sections at their RVAs, headers, TEB/PEB/LDR, IAT hooks).
2. The virus is located according to `locate`:
   - `section_scan` / `last_section`: signatures are scanned directly across
     mapped executable sections (or the last section) **before** entry-point
     execution, catching EPO (Entry Point Obscuring) and API-blocked infectors.
   - `emulate` / `entry_point`: the file runs from its entry point (stopping at
     an imported API call, an invalid access, `max_blocks` or 30 s) and every
     signature part is checked at each basic-block start (or only at the entry
     point), catching self-decrypting stubs after they decrypt.
3. `recover` finds the original entry point (OEP, or keeps the existing entry
   point for EPO infectors) and original host code — by reading stored bytes,
   calling the virus's own decryptor/restore routine (`call_function`), or
   emulating back into the host (`emulate_to_host`).
4. The original code is written back, the entry point is updated, the
   `cleanup` actions cut the virus out, SizeOfImage is recomputed and the
   checksum too when the file had one (system files, drivers).
5. The repaired file is checked again; if the definition still recognises
   it the result is `NotRepairable`.

## Fields

```yaml
version: 1
viruses:
  - name: W32.Example.A          # reported threat name (required)
    description: "..."
    arch: x86                    # any (default) | x86 | x64
    locate: emulate              # emulate (default) | entry_point | section_scan | last_section
    max_blocks: 5000000          # basic blocks before giving up (0 = default)
    body_size: 0x1800            # virus size from its start; default: to the end of its section
    signatures:                  # all must match; >= 16 fixed bytes in total
      - {offset: 0x0,  hex: "E8 00 00 00 00 5D ?? ?? 81 ED"}   # ?? = any byte
      - {offset: 0x23, hex: "..."}
    recover: ...                 # see below
    cleanup: [...]               # see below (required unless recover is none)
    fix_checksum: true           # default true (only when the file had a checksum)
```

### Addresses (`AddrExpr`)

`value` = `size` bytes (1/2/4/8, little endian) read at `virus_start + offset`,
XORed with `xor`.

| `mode` | result |
|---|---|
| `virus_offset` | `virus_start + add` (nothing read) |
| `absolute` | `value + add` |
| `rva` | `image_base + value + add` |
| `relative` | `virus_start + add + value` (value sign-extended) |
| `relative_back` | `virus_start + add - value` |
| `return_va` | `call_ret + add` (`call_function` only: EAX/RAX return value as VA) |
| `return_rva` | `image_base + call_ret + add` (`call_function` only: EAX/RAX as RVA) |

### `recover`

```yaml
recover: {method: none}           # detection only, always NotRepairable

recover:
  method: stored                  # the body keeps OEP and/or stolen bytes
  oep: {mode: relative_back, offset: 0x1F, size: 4, add: 5}   # omit to keep existing EP (EPO)
  restore:                        # optional, any number of blocks
    - data_offset: 0x1778         # where the bytes are (from virus start)
      size: {offset: 0x1774, size: 4}     # or {value: 32}
      present_flag: {offset: 0x1773, size: 1}   # optional, 0 = patient zero
      min_size: 2                 # smaller = patient zero (default 1)
      max_size: 0x1000            # refuse larger (default 0x1000)
      xor_key: "5A"               # optional repeating XOR key
      to: {mode: rva, offset: 0x40}       # optional, default: the OEP

recover:
  method: emulate_to_host         # let the virus restore the host itself
  max_restore_bytes: 0x4000       # refuse when it changed more host code

recover:
  method: call_function           # call a virus decryptor/restore routine via Unicorn
  func: {mode: virus_offset, add: 0x40}
  args:                           # optional (up to 8; x86 stack, x64 RCX/RDX/R8/R9 + stack)
    - {scratch: 0x200}            # zeroed RW buffer mapped in Unicorn, passes its VA
    - {addr: {mode: virus_offset, add: 0x120}}
    - {value: {offset: 0x118, size: 4}}
  max_instructions: 500000        # default 500000 (1..=50000000)
  timeout_ms: 2000                # default 2000 (1..=30000)
  oep: {mode: return_rva}         # optional (evaluated AFTER func returns; omit for EPO)
  restore:                        # optional (read AFTER func returns)
    - scratch_index: 0            # optional: read from args[0] scratch instead of virus_start
      data_offset: 0x0
      size: {offset: 0x118, size: 4}
      to: {mode: rva, offset: 0x110}
  diff_host: false                # optional: also capture bytes func wrote into host code sections
  max_restore_bytes: 0x4000
```

`emulate_to_host` keeps emulating after the match until a block starts in the
image outside the virus body: that address is the OEP. Every byte the virus
changed in the host's executable sections (outside its body) is written back.

### `cleanup` (applied in order)

```yaml
cleanup:
  - action: truncate_at           # cut the file at the file offset of this VA
    at: {mode: virus_offset, add: -0x1116}
  - action: remove_virus_section  # the virus start's section (must be the last)
  - action: zero_body             # zero body_size bytes (cavity infectors)
```

`truncate_at` keeps the section that contains the cut (raw size re-aligned,
virtual size never grown) and removes sections that start after it; a cut that
would remove a section in the middle of the file or the headers is refused. A
security directory pointing past the new end is cleared (the signature was
already broken by the infection).

## Limits

- Section characteristics changed by the virus (e.g. made writable) are not
  restored; a definition cannot know the original values.
- Emulation stops at the first imported API call, so a virus that needs API
  results before reaching its body is not matched by `locate: emulate`.
- A repaired program is not the vendor's file: outside system files the
  server still recommends a clean copy or reinstall.
