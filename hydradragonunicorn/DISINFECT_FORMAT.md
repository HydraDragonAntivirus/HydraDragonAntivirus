# HydraDragon disinfection definitions

`disinfect_rules/default.yaml` is compiled into hydradragonunicorn
(`DisinfectRules::builtin()`). Extra files load with
`DisinfectRules::builtin_with_file(path)` (a definition with the same name
replaces the built-in one) and run with `disinfect_bytes_with(data, &rules)`.

A file is repaired **only when a definition recognises the virus by its
signature**. Unknown infections are never "repaired".

## How a definition runs

1. The file is emulated with Unicorn in the unpacker's Windows environment
   (sections at their RVAs, headers, TEB/PEB/LDR, IAT hooks). Emulation stops
   at an imported API call, an invalid access, `max_blocks` or 30 s.
2. At every basic-block start (`locate: emulate`) or only at the entry point
   (`locate: entry_point`) every signature part is compared with emulated
   memory. A self-decrypting virus is therefore matched after it decrypted.
3. `recover` finds the original entry point (OEP) and original code.
4. The original code is written back, the entry point is set to the OEP, the
   `cleanup` actions cut the virus out, SizeOfImage is recomputed and the
   checksum too when the file had one (system files, drivers).
5. The repaired file is emulated again; if the definition still recognises
   it the result is `NotRepairable`.

## Fields

```yaml
version: 1
viruses:
  - name: W32.Example.A          # reported threat name (required)
    description: "..."
    arch: x86                    # any (default) | x86 | x64
    locate: emulate              # emulate (default) | entry_point
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

### `recover`

```yaml
recover: {method: none}           # detection only, always NotRepairable

recover:
  method: stored                  # the body keeps OEP and stolen bytes
  oep: {mode: relative_back, offset: 0x1F, size: 4, add: 5}
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
