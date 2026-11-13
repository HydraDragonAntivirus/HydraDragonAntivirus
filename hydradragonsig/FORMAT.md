# HydraDragonSig rule format

HydraDragonSig rules are YAML documents. Each rule lists conditions over the
scanned file (strings, imports, byte patterns, sections, icons, ...). This file
is the reference for what every key does. The code is in `src/rules/types.rs`
(format), `src/rules/engine.rs` (matching) and `src/rules/validate.rs` (load
checks).

Check a rule file without scanning anything:

```bash
hydradragonsig --rules my_rules.yaml --check-rules
```

It prints every load warning and exits with code 1 when there is any.

## 1. File layout

```yaml
name: My rules          # optional
version: "1.0"          # optional
rules:
  - id: TROJAN-EXAMPLE-001
    title: "Example"
    severity: high
    verdict: malware
    family: "Trojan.Win32.Example.A"
    conditions:
      - type: string_set
        values: ["first unique string", "second unique string"]
```

`!include other.yaml` lines (optionally written `- !include other.yaml`) load
another file first, relative to the including file. Included rules come before
the rules of the including file. Includes may nest up to 20 levels; a missing or
broken include prints a warning and loading goes on.

Keys are case-sensitive and must be spelled exactly. Enum values (`severity`,
`verdict`, `logic`, atom `kind`) also accept `Critical` / `CRITICAL` style.

## 2. Rule fields

| Key | Required | Default | Meaning |
|---|---|---|---|
| `id` | yes | | Unique rule id. Used by `rule_match` and as the threat name when `family` is missing. |
| `title` | yes | | Short title (output only). |
| `description` | no | `""` | Output only. |
| `severity` | yes | | `info`, `low`, `medium`, `high`, `critical`. Output only: it does not change the verdict. |
| `verdict` | no | `suspicious` | `malware`, `pua`, `suspicious`, `clean`, `trusted`. See section 4. |
| `confidence` | no | `60` | 0-100, output only. |
| `score` | no | `10` | Added to the file score (capped at 100). The highest-scoring finding names the threat. |
| `family` | no | | Threat name reported for the file, e.g. `Trojan.Win32.Remcos.A`. |
| `tags` | no | `[]` | Output only. |
| `mitre` | no | `[]` | List of `{id, name, tactic}` (all three required), copied to the report. |
| `references` | no | `[]` | Where the rule comes from: report URLs, sample hashes, notes. Copied to every finding of the rule (`references` in the JSON output). `reference: "..."` takes one. |
| `private` | no | `false` | The rule is evaluated but produces no finding. Use it as a building block for `rule_match`. |
| `logic` | no | `any` | How conditions combine: `any`, `all`, `threshold`. |
| `threshold` | with `logic: threshold` | | How many conditions must match. |
| `conditions` | yes | | List of conditions (section 5). A rule without conditions never matches. |
| `file_path` | no | | Only evaluate the rule for this exact path, e.g. `%SystemRoot%\System32\drivers\etc\hosts`. `%VAR%` is expanded from the scanning machine's environment; the comparison is a full-path, case-insensitive match (no wildcards). |
| `remediation` | no | `[]` | Declarative remediation actions run when `--remediate` is passed (section 5.9). |
| `assign_types` | no | `[]` | File type tags added to the file when the rule matches (section 5.11). Alias: `assign_file_type`. |

## 3. Logic

- `any`: the first matching condition matches the rule (its evidence is reported).
- `all`: every condition must match, checked in order; the first failure stops.
- `threshold`: at least `threshold` conditions must match. Every condition counts,
  including cheap ones such as `file_type` or `file_size_lte`. With
  `threshold: 3`, a `file_type: pe` and a `file_size_lte` condition that almost
  every PE meets leave only one real signal to find: put such gates in a
  separate `private` rule and combine with `rule_match`, or use `logic: all`.

File-type gating: when a rule has PE conditions (`import_*`, `export_*`, `dll_*`,
`suspicious_import_count`, `section_*`, `packed_pe`) or `file_type` conditions,
the rule is skipped for files that are not of those types, whatever `logic` says.

## 4. Verdict, score and threat name of a file

- Verdict: any `trusted` finding makes the file trusted; otherwise any `malware`
  finding makes it malware, then `pua`, then `suspicious`; with no finding the
  file is clean. One matching `verdict: malware` rule is enough.
- Score: sum of the `score` of the findings, capped at 100.
- Threat name: `family` of the finding with the highest score (ties: smallest
  `id`), or its `id` when it has no `family`.

With stop-on-detection (the library default; the CLI flag
`--stop-on-detection`), evaluation stops at the first non-private matching rule,
in load order.

## 5. Conditions

Every condition has a `type` and the keys listed for it. Unknown keys are
reported at load time (they used to be ignored silently).

### 5.1 Strings

Where strings are matched:

- **Raw bytes**: the whole file, in the encoding the flags select. This is how
  `string_contains` and `string_set` (without `regex`) are matched, through one
  Aho-Corasick pass over the file for all rules.
- **Extracted strings**: printable ASCII (`0x20-0x7E`, tab, CR, LF) and UTF-16LE
  runs of at least 5 characters (`--min-string-len`), extracted the first time a
  rule needs them. `string_regex`, `string_set` with `regex: true` and
  `native_signature` regex atoms run on these.
- **Decoded strings** (`decoded: true`): extracted strings that look like base64
  or hex are decoded and kept when the result is readable text (ASCII/UTF-8 or
  UTF-16LE), plus the script/IL decoders of section 5.12 whose decoded outputs
  carry `method` tags (`ps_encodedcommand`, `ps_frombase64string`, `js_atob`,
  `vbs_chr_chain`). Off when the scan disables decoding (`--no-decode`).

Encoding flags: `ascii` (default on) and `utf8` search the value's UTF-8 bytes,
`wide` its UTF-16LE form, `utf16` its UTF-16BE form. `nocase` folds ASCII letters
only.

| Type | Keys | Matches when |
|---|---|---|
| `string_contains` | `value`, `nocase`, `ascii` (true), `wide`, `utf8`, `utf16`, `decoded` | The value occurs in the file in one of the selected encodings, or in a decoded string. |
| `string_set` | `values`, `min`, `nocase`, `ascii` (true), `wide`, `utf8`, `utf16`, `decoded`, `regex` | At least `min` different values occur. **`min` defaults to all values.** With `regex: true` each value is a regex matched against the extracted (and, with `decoded`, decoded) strings. |
| `string_regex` | `pattern`, `decoded` | The regex matches an extracted (or decoded) string. |
| `env_reference` | `min` (default 1) | At least `min` extracted strings reference environment variables (`%APPDATA%`, `$env:`, `getenv(...)`, `GetEnvironmentVariable*`, `USERPROFILE`, `TEMP`, ...). Only the file is looked at. |

Regexes use the Rust `regex` crate: unanchored, case-sensitive unless the
pattern starts with `(?i)`, no back-references or look-around.

### 5.2 PE (Windows executables)

PE data is parsed the first time a rule needs it. A file that is not a valid PE
never matches these conditions.

Imports are stored as `dll!function` (or `dll!ord<N>` for imports by ordinal).

| Type | Keys | Matches when |
|---|---|---|
| `import_any` | `names` | One name matches an import. |
| `import_all` | `names` | Every name matches an import. |
| `import_set` | `names`, `min` (default **1**) | At least `min` names match imports. |
| `import_regex` | `pattern` | The regex matches a `dll!function` string (original case). |
| `export_any` / `export_all` / `export_set` | `names` (`min`, default 1) | Same, against exported names: exact match, case-insensitive. |
| `dll_any` | `names` | An imported DLL has this name (exact, case-insensitive, with extension: `ws2_32.dll`). |
| `dll_regex` | `pattern` | The regex matches an imported DLL name (case-insensitive). |
| `suspicious_import_count` | `min` | At least `min` imports are in the suspicious API list (`SUSPICIOUS_APIS` in `src/scanner/pe.rs`: injection, hooks, credential, anti-debug, service/driver and download APIs). |
| `section_entropy` | `min` | Some section's raw data has entropy ≥ `min` (0-8 bits per byte). |
| `section_name_regex` | `pattern` | The regex matches a section name. |
| `packed_pe` | | Two or more suspicious sections (entropy ≥ 7.2, `UPX*` / `.packed*` / empty name), a `UPX*` section, or at most 3 sections with one at entropy ≥ 7.4. |
| `pe_section` | `select`, `index`, `name`, `name_regex`, `flags_all`, `flags_none`, `characteristics`, `entropy_min`, `entropy_max`, `raw_size`, `raw_size_min`, `raw_size_max`, `raw_offset`, `virtual_address`, `virtual_size`, `virtual_size_min`, `virtual_size_max`, `md5`, `sha1`, `sha256`, `crc32`, `code_xrefs_min`, `cfg_xrefs`, `has_entry`, `directories_any`, `directories_none`, `directory_share_max` | The chosen section passes every key that is given (see below). |
| `pe_sections_summary` | `total_raw_size`, `total_raw_size_min`, `total_raw_size_max`, `md5`, `sha1`, `sha256`, `crc32`, `count`, `count_min`, `count_max` | Aggregate across all PE sections in table order: sum of `SizeOfRawData`, section count, and hashes of the concatenated raw section bytes (`md5[sections]`, `crc32[sections]`). |
| `export_hash_any` | `values` | The PE's export table MD5 (`md5[exports]`, 32 hex) is in `values`. |
| `pe_timestamp` | `value`, `hex`, `min`, `max` | `IMAGE_FILE_HEADER.TimeDateStamp` matches the exact integer, 32-bit hex string or range bounds. |
| `pe_anchor_pattern` | `anchor`, `section`, `offset`, `range`, `count`, `patterns`, `min`, `negate`, `excludes` | Hex pattern(s) (`??`, `!!` non-zero, `4?` nibble) match at `anchor` (`absolute`, `entry`, `section`, `overlay`, `eof`) + signed `offset` (or within `range` bytes, `count` times). `negate: true` inverts the match. |
| `byte_repeat` | `anchor`, `section`, `offset`, `length`, `min` (default 1) | The first `length` bytes at `anchor` + `offset` repeat at least `min` time(s) elsewhere in the file. |
| `authenticode` | `signed`, `subject_glob`, `cert_tbs_any`, `publisher`, `oem_id` | Checks whether the PE carries an Authenticode `WIN_CERTIFICATE` (`signed: true|false`) and/or matches a certificate subject CN / O / OU against `subject_glob`. The signer keys are the Windows Code Integrity (WDAC) signer fields and must all hold on one signature (the primary one or a nested one): `cert_tbs_any` = hash of the DER `tbsCertificate` of a certificate on the chain from the signing certificate up, as far as the embedded certificates reach (40 / 64 / 96 hex = SHA-1 / SHA-256 / SHA-384; WDAC `CertRoot Type="TBS"`), `publisher` = CN of the signing certificate (`CertPublisher`), `oem_id` = `SpcSpOpusInfo` program name (`CertOemID`, the OEM name in Microsoft WHCP signatures); both compared case-insensitively. |
| `authentihash_any` | `values`, `pages` | The Authenticode image digest (SHA-1 or SHA-256 of the file without the checksum, the security directory entry and the attribute certificate table; WDAC "Hash Sha1/Sha256") is in `values`, or the digest of the first 4 KiB page (headers with the same two fields left out, zero-padded to 4096; WDAC "Hash Page Sha1/Sha256") is in `pages`. Computed once per scan. |
| `pe_subsystem` | `values` | `IMAGE_OPTIONAL_HEADER.Subsystem` is one of `values`: `native` (kernel drivers), `windows_gui`, `windows_cui`, `native_windows`, `efi_application`, `efi_boot_service_driver`, `efi_runtime_driver`, `efi_rom`, `windows_boot_application`, ... or a number. A cheap first condition in `logic: all` rules that only concern drivers. |
| `version_info` | `fields`, `absent`, `file_version_min`, `file_version_max`, `product_version_min`, `product_version_max` | `absent: true` matches when no `RT_VERSION` resource exists; `fields` maps `VS_VERSIONINFO` string keys (`CompanyName`, `FileDescription`, `ProductName`, ... or numeric slot indices `0`..`11`) to glob patterns (`%NULL%` matches an empty/missing field; leading `!` negates). The `*_version_min` / `*_version_max` bounds are inclusive, written `a[.b[.c[.d]]]` (missing parts are 0), and compare the four numbers, so `1.10` is above `1.9`: the version comes from `VS_FIXEDFILEINFO`, else from the leading numbers of the `FileVersion` / `ProductVersion` string; a file without that version never matches a bound. All given keys must hold. |
| `resource_match` | `type_glob`, `size_min`, `size_max`, `data_patterns`, `min` (default 1) | At least `min` PE resources match the given type/language glob (`RT_RCDATA`, `BINARY`, `0003:0419`, ...), byte size bounds and hex `data_patterns`. |
| `resource_hash_any` | `values` | Any PE resource's MD5 (32 hex) or SHA-256 (64 hex) is in `values`. |
| `resources_absent` | | The PE has no resource directory or zero resource data entries. |

#### `pe_section`

Describes one section, so file infectors, packers and protectors can be written
as rules instead of code. `index` picks a specific 0-based section index
(`sectionindex=0..N`); otherwise `select` picks the section: `any` (default: one
section must pass), `last` (last in the section table) or `entry` (the one with
the entry point). Every other key is optional; all given keys must hold.

| Key | Meaning |
|---|---|
| `index` | 0-based section table index (`0` = first section). |
| `name` / `name_regex` | Exact section name (`.text`, `/4`, `/19`) or regex on the section name (the name ends at the first NUL). |
| `flags_all` / `flags_none` | Characteristics that must all be set / must all be clear: `code`, `initialized_data`, `uninitialized_data`, `discardable`, `not_cached`, `not_paged`, `shared`, `execute`, `read`, `write`. |
| `characteristics` | Exact 32-bit `Characteristics` field (e.g. `0x60000020`). |
| `entropy_min` / `entropy_max` | Entropy of the section's raw data (0-8). |
| `raw_size` / `raw_size_min` / `raw_size_max` | Exact or bounded `SizeOfRawData` in bytes (`size[section]` / `physicalsize[section]`). |
| `raw_offset` | Exact `PointerToRawData` in bytes (`physicaladdress[section]`). |
| `virtual_address` | Exact `VirtualAddress` RVA (`virtualaddress[section]`). |
| `virtual_size` / `virtual_size_min` / `virtual_size_max` | Exact or bounded `VirtualSize` (`virtualsize[section]`). |
| `md5` / `sha1` / `sha256` / `crc32` | Hash of the section's raw byte slice (`md5[section]`, `md5[sectionindex]`). |
| `has_entry` | `true`: the entry point is inside it; `false`: it is not. |
| `directories_any` | One of these data directories points inside it: `export`, `import`, `resource`, `exception`, `security`, `basereloc`, `debug`, `architecture`, `globalptr`, `tls`, `load_config`, `bound_import`, `iat`, `delay_import`, `clr`. |
| `directories_none` | None of these data directories points inside it. |
| `directory_share_max` | With `directories_any`: those directories cover at most this share (0-1) of the section. An infector that appends its body to the section holding a small table (relocations, exception data) leaves a share near 0. |
| `code_xrefs_min` | At least this many direct near `call` / `jmp` / `jcc` from the other executable sections land inside it (iced-x86 linear sweep, so code reached only through data or after misaligned bytes is not counted). |
| `cfg_xrefs` | With `code_xrefs_min`: count the branches found by walking the code from the entry point along direct jumps, branches and calls (2048 blocks, 65536 instructions) instead of the linear sweep, so bytes after a `ret` / `jmp` / `int3` are not read as code. x86 / x64 only. |

Example, an appender that keeps the relocation table in its own writable,
executable, encrypted last section:

```yaml
- type: pe_section
  select: last
  flags_all: [write, execute]
  entropy_min: 7.8
  raw_size_min: 32768
  directories_any: [basereloc]
```

Import name matching is a case-insensitive **suffix** match on `dll!function`:
`VirtualAlloc` matches `kernel32.dll!VirtualAlloc` (and not `VirtualAllocEx`),
but a short name such as `Alloc` would match it too. Write `!VirtualAlloc` to
require the whole function name, or `kernel32.dll!VirtualAlloc` to pin the DLL.

### 5.3 File properties

| Type | Keys | Matches when |
|---|---|---|
| `file_type` | `values` | The file has one of these types (section 8). |
| `file_size_gte` / `file_size_lte` | `bytes` | Size ≥ / ≤ `bytes`. |
| `file_entropy` | `min` | Whole-file entropy ≥ `min`. |
| `hash_sha256` / `hash_md5` / `hash_sha1` / `hash_crc32` | `value` | The file hash equals `value` (case-insensitive; `hash_crc32` is 8 hex digits). |
| `imphash_any` | `values` | The PE's import hash is one of `values` (32 hex characters, case-insensitive). Same imphash as pefile / Mandiant and the Multron server's imphash signatures. Every program built the same way shares an imphash, and every .NET program has the same one: combine it with other conditions or check it on clean files first. |
| `path_regex` | `pattern` | The regex matches the scanned path (as given; memory scans use `memory://<id>`, archive members `archive://<parent>!<member>`). |
| `path_glob` | `pattern` | The wildcard glob (`*`, `**`, `?`, `#` alphanumeric) with `%VAR%` and `<$VAR>` (`<$PROFILE>`, `<$WINDIR>`, `<$SYSDIR>`, ...) expansion matches the scanned path. |
| `file_timestamp` | `equals`, `after`, `before`, `raw_hex`, `age_days_min`, `age_days_max` | Matches the file's modification timestamp (`YYYY-MM-DD HH:MM:SS`), raw DOS/Unix 32-bit hex (`timestampraw[file]`) or age in days (`age[file]`). |
| `file_attributes` | `spec`, `required`, `forbidden` | Matches Windows file attributes via compact spec (`A+D-H-L-R-S-`) or `required` / `forbidden` flag lists (`archive`, `directory`, `hidden`, `reparse`, `readonly`, `system`). |
| `not_mz` | | The file does not begin with the `MZ` DOS header signature. |
| `feature_gte` | `name`, `value` | A numeric feature is ≥ `value` (section 9). |
| `feature_lte` | `name`, `value` | A numeric feature is ≤ `value` (section 9), e.g. `pe_import_count` ≤ 10 for a thin stub. |
| `feature_bounds` | `bounds: [{feature, min, max}]`, `min` (default all) | At least `min` numeric feature range checks (`min`..=`max`) hold. |

### 5.4 Bytes

| Type | Keys | Matches when |
|---|---|---|
| `byte_pattern` | `pattern`, `scope`, `excludes` | The pattern occurs inside `scope` and none of `excludes` occurs anywhere in the file. |
| `byte_set` | `patterns`, `min`, `scope`, `excludes` | At least `min` patterns occur. **`min` defaults to all patterns.** |
| `unpacker_any` | `signatures: [{name, pattern}]` | One of the packer signatures occurs (the first one found is reported). |

`scope: {start, end}` limits the search to `[start, end)`. Negative values count
from the end of the file: `{start: -4096}` is the last 4 KiB. Both are optional.

`excludes` lists known-benign byte patterns: if any of them occurs, the condition
does not match.

Byte pattern syntax (braces optional, case-insensitive hex):

| Syntax | Meaning |
|---|---|
| `4D 5A` or `4D5A` | Exact bytes. |
| `??` | Any byte. |
| `4?` / `?A` | Nibble wildcard. |
| `~00`, `~4?` | Any byte except this one. |
| `[4]` | Exactly 4 bytes of anything. |
| `[2-8]` | Between 2 and 8 bytes. |
| `[4-]`, `[-]` | 4 or more / any number of bytes (up to 4096). |
| `( 90 \| E8 ?? \| EB [1-2] 00 )` | Alternatives (may contain any of the above). |

Example: `{ 4D 5A [2-4] ( 90 | 91 ) ~00 }`.

#### `opcode_pattern` (x86 / x64 and AArch64 instructions)

Matches instructions, not bytes: the region is disassembled (iced-x86, linear
sweep) and the pattern is compared with what the bytes decode to. Every encoding
of an instruction matches the same step (`89 D8` and `8B C3` are both
`mov eax,ebx`), and operand globs cover register and constant changes.

| Key | Default | Meaning |
|---|---|---|
| `pattern` / `patterns` | | One pattern, or a list of them. |
| `min` | `1` | How many of the patterns must match. |
| `region` | `entry` | `entry` (from the entry point), `code` (every executable section), `exports` (every exported function of a PE; forwarders left out), `tls_callbacks` (every PE TLS callback), `section_N` / `%PEN%` (section N, 1-based), `overlay`, `file` (the whole file as code, for shellcode and decrypted bodies that are not a PE). `exports` / `tls_callbacks` take at most 256 functions, 4096 bytes each by default. |
| `max_bytes` | 4096 for `entry`, 4 MiB otherwise | Bytes decoded from the start of the region (per section for `code`; at most 16 MiB). |
| `bitness` | `32` | `16`, `32` or `64` for `file` / `overlay` code that is not a PE. A PE always uses its own. |
| `skip` | `[]` | Mnemonics left out before matching (junk filler), e.g. `[nop, fnop]`; globs allowed. |
| `arch` | | `auto`, `x86`, `x64` or `arm64`. Without it, only the PE regions exist and a PE decodes as x86 of its own bitness. `auto` takes the PE `Machine` (`0xAA64` = arm64), ELF `e_machine` or Mach-O CPU type, and also gives ELF / Mach-O files `entry` and `code` regions; `file` / `overlay` keep `bitness` unless `arch` names an instruction set. |
| `mode` | `linear` | `linear`, or `cfg`: decode along the control flow from the region start (below). |
| `max_blocks` | `256` | `mode: cfg`: blocks walked (at most 2048). |
| `max_insns` | `8192` | `mode: cfg`: instructions decoded (at most 65536). |
| `follow_calls` | `false` | `mode: cfg`: also walk into the targets of direct calls. |
| `follow_jumps` | `true` | `mode: cfg`: continue at the target of an unconditional direct jump as if the code were contiguous. |

A pattern is a list of steps separated by `;` or new lines:

| Step | Meaning |
|---|---|
| `inc eax` | The mnemonic with these operands. |
| `loop` | The mnemonic with any operands. |
| `mov\|lea reg, mem` | Alternatives (`\|`) for the mnemonic. |
| `j* *` | Mnemonic glob (`*`, `?`): every jump with one operand. |
| `* reg` | Any instruction with one register operand. |
| `[2]`, `[1-3]`, `[2-]`, `[-]` | 2 / 1 to 3 / 2 or more / any number of other instructions in between (at most 64). |

Operands are separated by `,`; with operands the count must be the same. An
operand is `reg`, `mem`, `imm`, `*`, or a glob (alternatives with `|`, e.g.
`eax|ecx`) over the operand as the Intel formatter writes it: lower case, spaces ignored, numbers in hex with `0x`
(`0x5a`, never decimal), memory with its size (`byte ptr [eax+0x4]`; the size may be
left out: `[e?x+*]`). Branch targets are absolute addresses (image base + RVA for
a PE, 0-based for `file` / `overlay`), so write `*` for them.

```yaml
  - type: opcode_pattern
    region: entry
    skip: [nop]
    pattern: "pushad; call *; pop reg; [0-4]; xor byte ptr [*], imm; inc reg; loop *"
```

The finding names the file offset and the instructions that matched. A region is
decoded once per scan and shared by every `opcode_pattern` of that scan (per
region, instruction set and mode).

**`mode: cfg`.** Conditional branches (and with `follow_calls` direct calls)
start new blocks; an unconditional direct `jmp` / `b` is left out and decoding
continues at its target; a run stops at a return, an indirect branch, an
invalid instruction or code already decoded. Each run is matched on its own, so
code split into islands by jumps over junk bytes matches like straight-line
code, without emulating anything:

```yaml
  - type: opcode_pattern
    region: entry
    mode: cfg
    pattern: "push ebp; mov ebp, esp; [0-6]; xor byte ptr [*], imm; inc reg; loop *"
```

**AArch64** (`arch: arm64`, or `auto` on an AArch64 file). Decoded instructions:
branches, hints and system, data processing (immediate and register) and
integer loads / stores, with the usual aliases (`mov`, `cmp`, `cmn`, `tst`,
`mvn`, `neg`, `mul`, `lsl`, `lsr`, `asr`, `ror`, `cset`); anything else
(SIMD / FP, atomics) is `unknown`. Operands are written lower case without
spaces or `#`: `x0`, `w1`, `sp`, `xzr`, immediates in hex (`0x10`, `-0x10`),
memory `[x0]`, `[x0,0x10]`, `[sp,-0x10]!` (a post-index offset is a separate
operand: `[x0],0x1`), branch targets as absolute hex. `#` and spaces in a
pattern are ignored, so the assembler form can be pasted; commas inside `[...]`
do not split operands.

```yaml
  - type: opcode_pattern
    arch: auto
    skip: [nop, hint]
    pattern: "stp x29, x30, [sp, #-0x10]!; [0-4]; eor w*, w*, w*; [0-2]; b.ne *"
```

#### `bytecode` (ClamAV bytecode programs)

Runs a ClamAV bytecode program (`.cbc`) over the file in hydradragonclamav's VM,
for what the declarative conditions cannot say: decryption loops with a variable
key, walking data structures, checksums. Needs the `bytecode` build feature (on
by default); without it the condition never matches and `--check-rules` says so.

| Key | Default | Meaning |
|---|---|---|
| `program` | required | The `.cbc` file, relative to the rule file. |
| `entry_func` | `0` | Function the run starts in. |
| `params` | `[]` | Arguments of the entry function (in order, sized by its argument types); also what `hds_param(i)` returns. |
| `max_ops` | `100000` | Instruction budget, at most 12 000 000. A run that reaches it stops, is logged, and does not match. |
| `expect_return` | | Match when the entry function returns this value. Without it: a non-zero return value or a virus name set by the program (`setvirusname`). |
| `virname_glob` | | Also require a virus name matching this glob. |
| `apis` | `{}` | New APIs for the program (below). |

**New APIs.** A program calls an API by the name its `E` line declares. When
`apis` has that name, the rule answers the call, before ClamAV's own API table:
an id past ClamAV's 107 is a new API, a ClamAV name is answered the rule's way.
Each entry gives exactly one source:

| Source | Returns |
|---|---|
| `value: N` | the constant `N` |
| `param: i` | `params[i]` |
| `param_arg: true` | `params[arg0]` (the call's first argument) |
| `table: [a, b, …]` | `table[arg0]`, 0 past its end |
| `fact: NAME` | a fact about the file: `file.size`, `file.entropy_x1000`, `file.is_pe`, `pe.sections`, `pe.imports`, `pe.exports`, `pe.dlls`, `pe.suspicious_imports`, `pe.entry` (RVA), `pe.image_base`, `pe.timestamp`, `pe.is_64`, `pe.packed`, `strings.count` |
| `condition: {…}` | 1 when that condition (any condition type, `rule_match` included) matches the file, else 0 |

`hds_param(i)` is always there. The program reads the file through the usual
ClamAV APIs (`read`, `seek`, `file_byteat`, `file_find`, …), with the PE section
table and entry point filled in for `pe_rawaddr` and `get_pe_section`. A program
that fails to load is logged once and never matches.

```yaml
  - type: bytecode
    program: bytecode/poly_decryptor.cbc
    max_ops: 50000
    params: [16]
    expect_return: 1
    apis:
      hds_sections: { fact: pe.sections }
      hds_key_table: { table: [0x37, 0x5a, 0x13] }
      hds_is_upx: { condition: { type: pe_section, name: "UPX*" } }
```

### 5.5 Combining rules

| Type | Keys | Matches when |
|---|---|---|
| `rule_match` | `ids`, `min` (default **all**) | At least `min` of the listed rules matched earlier in this scan. |

Rules run in load order, so a referenced rule must come before the rule that
uses it (same file, an earlier include, or an earlier file). `private: true`
rules are the usual building blocks:

```yaml
rules:
  - id: HELPER-INJECT
    title: "Helper: injection imports"
    severity: info
    private: true
    conditions:
      - type: import_all
        names: ["!VirtualAllocEx", "!WriteProcessMemory", "!CreateRemoteThread"]

  - id: TROJAN-INJECTOR-001
    title: "Small PE with injection imports"
    severity: high
    verdict: malware
    family: "Trojan.Win32.Injector.A"
    logic: all
    conditions:
      - type: file_size_lte
        bytes: 307200
      - type: rule_match
        ids: [HELPER-INJECT]
```

### 5.6 Parent comparison (unpacked dumps, extracted payloads)

A scan can carry a summary of the file the buffer came from: the packed
original of a Unicorn dump, the dropper of an extracted payload, the archive of
a zip member. The conditions below compare the scanned file with it. Without a
parent they never match, so ordinary scans are unaffected.

Where the parent comes from:

- library: `ScanOptions { parent: Some(ParentInfo::from_bytes(name, &bytes)), .. }`
  (or `ParentInfo::from_report(&report)` when the parent was scanned already);
- HydraDragonAV: the disinfector passes the packed original to the scan of the
  Unicorn dump, and the dump to the scan of every file extracted from it
  (`Pipeline::scan_bytes_with_parent`);
- CLI: `hydradragonsig --rules r.yaml --parent packed.exe dump.exe`;
- zip members get their archive as parent automatically.

| Type | Keys | Matches when |
|---|---|---|
| `has_parent` | | The scan has a parent. |
| `parent_feature_gte` / `parent_feature_lte` | `name`, `value` | A parent feature is ≥ / ≤ `value`. Parent features: `file_entropy_bits_per_byte`, `pe_import_count`, `pe_export_count`, `pe_section_count`, `pe_suspicious_import_count` (PE ones only when the parent is a PE), `elf_import_count`, `elf_export_count`, `elf_section_count`, `elf_rwx_segment_count` (when it is an ELF). |
| `feature_delta_gte` | `name`, `value` | This file's feature minus the parent's is ≥ `value`, e.g. `pe_suspicious_import_count` grew by 5 after unpacking. Both sides must have the feature. |
| `new_import_set` | `names`, `min` (default **1**) | At least `min` names match an import of this file that the parent does **not** import (same suffix matching as `import_set`). PE condition. |
| `new_elf_import_set` | `names`, `min` (default **1**) | At least `min` names are imported symbols of this ELF that the parent ELF does **not** import (exact names). ELF condition. |

Example: a packed shell with a handful of imports whose dump imports
process-hollowing APIs.

```yaml
- id: CRYPTER-BY-DIFF
  title: "Unpacked payload reveals hidden injection"
  severity: high
  verdict: malware
  family: "Trojan.Win32.Crypter.B"
  logic: all
  conditions:
    - type: has_parent
    - type: parent_feature_lte
      name: pe_import_count
      value: 30
    - type: new_import_set
      min: 3
      names: ["!VirtualAllocEx", "!WriteProcessMemory", "!SetThreadContext", "!NtUnmapViewOfSection"]
```

A clean packed program (a UPX-packed tool) also gains imports when unpacked:
combine the diff with a malicious capability before giving `verdict: malware`.

### 5.7 Icons and images

| Type | Keys | Matches when |
|---|---|---|
| `pe_icon_any` | `dhash`, `dhash_max_distance` (0), `phash`, `phash_max_distance` (0), `idb`, `idb_groups` | An icon of the PE matches one fingerprint: 64-bit dHash or pHash (16 hex, optionally `dhash#` / `fuzzy_img#`) within the distance in bits, or a ClamAV `.idb` line (`Name:Group1:Group2:<124 hex>`, icon sizes 16/24/32). `idb_groups` limits the `.idb` groups accepted. |
| `image_fuzzy_hash_any` | `hashes`, `max_distance` (0) | The file is an image (PNG, JPEG, GIF, BMP, WebP, ...) whose pHash is within `max_distance` bits of one hash. |

Icons are shared by many unrelated files (stolen icons, installers): use them as
one signal next to others, not alone.

### 5.8 System, registry and raw-sector conditions (Windows)

On non-Windows hosts these conditions log a one-time warning and never match.

| Type | Keys | Matches when |
|---|---|---|
| `registry_key` | `key`, `recursive` (false), `value_pattern` | The registry key path (with optional glob segments) exists, and when `value_pattern` is set, a value name matching that regex exists in the key (or subtree if `recursive: true`). |
| `registry_value` | `key`, `recursive` (false), `value_regex`, `data_regex`, `data_not_regex`, `data_hex`, `md5`, `sha256`, `min` (default 1) | At least `min` registry values under `key` pass all supplied filters. `data_not_regex` keeps only values whose text data does NOT match (a value other than its safe/stock form). When the caller supplies one registry write (`ScanReport::registry_event`, e.g. an EDR event), that write is judged instead of the live registry; `data_hex` / `md5` / `sha256` never match a write. |
| `clsid` | `guids`, `inproc_regex` | Any listed COM `CLSID` is registered under `HKCR\CLSID` or `HKLM\SOFTWARE\Classes\CLSID` (and its `InprocServer32` default value matches `inproc_regex` when set). |
| `hosts_entry` | `ip`, `host` | A non-comment line in `%SystemRoot%\System32\drivers\etc\hosts` matches the `ip` glob and/or `host` regex. Inline `#` comments and the stock localhost mapping (`127.x` / `0.0.0.0` / `::1` -> `localhost`, `localhost.localdomain`) are not entries. |
| `sector_pattern` | `device`, `lba` (0), `count` (1, max 64), `patterns`, `min` (default 1), `excludes` | Raw 512-byte sectors read from `device` (`physical0`, `volume:C`, `\\.\PhysicalDrive0`) at `lba` match at least `min` hex patterns and no `excludes`. |

### 5.9 Remediation (`remediation`)

Rules may attach declarative remediation steps executed by the CLI when
`--remediate` is passed (dry-run by default; pass `--yes` to apply, and
`--remediate-allow-commands` to permit `command` steps):

| Type | Keys | Action |
|---|---|---|
| `file_delete` | `path` (optional) | Delete `path` (with `%VAR%` and glob expansion), or the detected file itself when `path` is omitted. |
| `text_delete_line` | `path`, `pattern` | Remove lines matching `pattern` (substring or glob) from `path`. |
| `text_replace` | `path`, `pattern`, `replacement` | Replace `pattern` (substring or line glob) with `replacement` in `path`. |
| `text_delete_string` | `path`, `pattern` | Remove occurrences of `pattern` from `path`. |
| `registry_delete_value` | `key`, `value` | Delete registry value `value` under `key` via `reg.exe DELETE`. |
| `registry_delete_key` | `key` | Delete registry key `key` via `reg.exe DELETE`. |
| `command` | `program`, `args` | Run an external command (requires `--remediate-allow-commands`). |

### 5.10 Host blocklist and scan whitelist

#### `domain_blocklist`

Cross-references hostnames, domains and URLs found in the scanned file (ASCII
and UTF-16LE strings, optionally the decoded base64/hex strings) with an
external categorized blocklist DB and reports at least `min` (default 1)
distinct listed domains of an accepted category:

| Key | Default | Meaning |
|---|---|---|
| `db` | global CLI DB | Optional path to a `domain:CATEGORY` text file for this rule. None set = DB loaded once with the CLI flag below; a path set here is loaded and cached on first use. |
| `categories` | `[]` (any) | Uppercase categories to report; `*` or an empty list accepts every category. |
| `decoded` | `false` | Also search the decoded (base64/hex) strings. |
| `min` | 1 | Minimum distinct listed domains that must be referenced. |

The rule carries only category names, never the blocked domains themselves.
Without any DB (`--domain-db` not passed and no `db` field) the condition logs
a one-time warning and never matches.

Example:

```yaml
conditions:
  - type: domain_blocklist
    categories: [MALWARE, PHISHING]
    min: 1
```

DB file syntax (one entry per line, `|`-separated entries in one line also
work, `#` comments, leading `www.` is tolerated on both sides):

```
# domain:category
sub.example-cdn.internal:MALWARE
tracked-ads.example:UNWANTED
```

Load it with `hydradragonsig --domain-db blocklist.txt ...`; an entry count is
printed to stderr on load. `tools/decode_containers.py` converts captured
container databases into this text format.

#### uBlock Origin / Adblock Plus filter lists and hosts files

A DB file may also be (or contain) a uBlock Origin / Adblock Plus filter list
(syntax of `uBlockOrigin/uAssets` `filters/`) or a hosts file. Lines are
classified one by one, so `domain:CATEGORY` lines keep working unchanged and
may be mixed with filter lines in one file.

**Category.** Filter-list and hosts entries have no category of their own; they
take the category of their list. Give it in the DB spec as `CATEGORY=PATH`
(both `--domain-db` and the rule's `db` field accept it), for example
`--domain-db MALWARE=badware.txt --domain-db PHISHING=phish.txt`.
`--domain-db` is repeatable; all lists are merged into one DB, and `@@`
exceptions of any list apply to all of them. Without a spec category the
entries are `UNWANTED`. A `! Category: NAME` comment line inside a list
changes the category of the entries that follow it. Use broad category names
(`MALWARE`, `PHISHING`, `UNWANTED`, ...).

Accepted lines:

| Line | Meaning |
|---|---|
| `\|\|host^`, `\|\|host^\|`, `\|\|host` | Hostname filter: `host` and all its subdomains. |
| `host.tld` (plain hostname, at least one dot) | Same as `\|\|host.tld^`. |
| `0.0.0.0 host [host...]`, `127.0.0.1 host`, `:: host` | Hosts-file entry (any IP first; `localhost`, `broadcasthost`, `ip6-*` are skipped; `#` ends the line). |
| `\|\|host/path*.exe`, `\|\|host^*/x^` | URL pattern anchored at the hostname or one of its parent-domain label boundaries. |
| `\|https://host/x\|` | URL pattern anchored at the URL start (`\|` at the end anchors the URL end). |
| `/path-part/`-style patterns without an anchor | URL substring pattern (at least 4 literal characters). |
| `/regex/` | Regular expression on the URL (case-insensitive, ASCII `\w`/`\d`/`\s` as in JavaScript). Lookaround and backreferences run on a backtracking engine limited to 100k steps per URL; hitting the limit counts as no match. |
| `*$doc,ipaddress=IP` (pattern empty or `*`) | Blocks the literal IP address as a host. `ipaddress=` with `lan`, ranges or a URL pattern needs DNS and is skipped. |
| `@@` + any of the above | Exception: wins over every block except `$important` ones. |

In patterns, `*` matches any run of characters and `^` matches one separator
(any character except a letter, digit, `_`, `-`, `.`, `%`) or the URL end.
Hostname filters match every hostname found in the file (as before); URL
patterns and regexes match the URLs found in the file (`http(s)://`, `ftp(s)://`,
`ws(s)://`, and scheme-less `host/path` / `host:port/...` references, which are
treated as `http://` URLs). A URL-pattern hit is reported with the URL instead
of the hostname.

Options (`$...`):

- `$important` makes the block win over `@@` exceptions.
- `$badfilter` disables the identical filter (a hostname filter is disabled
  for its host regardless of its other options).
- `$domain=` / `$from=` with at least one non-negated entry restrict the filter
  to pages the scanner does not have, so the filter is skipped; only negated
  entries (`~site`) are ignored.
- Filters whose effect is not blocking are skipped: `removeparam`, `csp`,
  `header`, `replace`, `permissions`, `redirect-rule`, `urlskip`,
  `uritransform`, `cname`, and the cosmetic/partial exception
  options (`generichide`/`ghide`, `elemhide`/`ehide`, `specifichide`/`shide`,
  `genericblock`, `inline-script`, `inline-font`, ...). `@@||site^$ghide` is
  therefore not a whitelist.
- Every other option (`$doc`, `$all`, `$3p`, `$1p`, `$script`, `$popup`,
  `$redirect=`, `$denyallow=`, `$to=`, `$match-case`, ...) is ignored.

Skipped lines: `!` comments, `[Adblock Plus ...]` headers, cosmetic, scriptlet
and HTML filters (`##`, `#@#`, `#?#`, `#@?#`, `#$#`, `#%#`, `##+js(...)`,
`$$`, `$@$`), and patterns that would match almost anything (no literal letter
or digit, e.g. `*$image`, or fewer than 4 literal characters without an anchor).

Preprocessor directives: `!#if` / `!#else` / `!#endif` are evaluated with uBO's
desktop tokens true (`ext_ublock`, `env_chromium`, `env_firefox`, `env_edge`,
`cap_html_filtering`, `cap_user_stylesheet`) and every other token false
(`env_mobile`, `env_safari`, `adguard`, `false`, ...); `!`, `&&` and `||` are
supported, a parenthesized condition is false. `!#include NAME` reads a file
next to the including list (no absolute paths, `..` or URLs, at most 2
levels). Unknown `!#` directives are ignored.

List files are untrusted: files over 256 MiB are refused, and lines over 8 KiB,
lines past 8 million, filters past 4 million and regex filters past 8192 are
rejected instead of loaded. Malformed lines are rejected one by one, never the
whole list. The CLI prints the block / exception / ignored / rejected / include
counts on load, followed by the first 16 rejected lines.

`OpenMalwareScannerPortable/hydradragonsig_rules/domain_lists/` holds verbatim
copies of uBlock Origin's malware protection lists (badware, URLhaus,
phishing) with their sources and licenses; see its README. Its
`domain_lists.txt` manifest (one `[CATEGORY=]FILE` per line, relative to the
manifest) is loaded into the global DB by the scan engine
(`set_global_domain_db_manifest`), where `domain_blocklist_rules.yaml` uses it.

```
[Adblock Plus 2.0]
! Title: local badware list
! Category: MALWARE
||evil-cdn.example^$doc
||drop.example/payload/*.exe
@@||drop.example/payload/signed/*
/^https?:\/\/[a-z]{8}\.top\/[0-9]+$/
example.com##.ad-banner
0.0.0.0 tracker.example
```

#### `--smart-whitelist` (scan-level depth whitelist)

The CLI accepts `--smart-whitelist FILE` with one `path:MAX_DEPTH` entry per
line (blank lines and `#` comments ignored, `%VAR%` placeholders like
`%CHROMEPROFILE%` expand). While walking the scan roots, every candidate file
is measured against its nearest (longest) matching whitelist prefix: when the
file lies deeper than `MAX_DEPTH` directory levels below the prefix it is
skipped.

```
# path:MAX_DEPTH
%CHROMEPROFILE%:0
%CHROMEPROFILE%\Extensions:3
%COMMONDOWNLOADS%:32767
%APPDATA%:2
```

`0` skips all files inside the prefix (but not files directly in it, which are
level 0); a large number effectively never skips; the longest prefix wins, so
a deeper entry can re-enable scanning under a blocked path. A summary of
skipped paths is printed to stderr.

### 5.11 File type magic DB and rule-assigned types

#### `--ftm` (file type magic signatures)

`--ftm FILE` loads a file type magic DB consulted during classification for
every scanned file. Line format (one entry per line, `#` comments):

```
Name:Type:Offset:Magic[:MIN_FLC[:MAX_FLC[:ALIAS[:MAGIC_VERSION]]]]
```

| Field | Meaning |
|---|---|
| `Name` | Type name; its normalized form becomes a `file_type.tags` entry and known names (`msexe`, `elf`, `mach-o`, `zip`, `rar`, `mscab`, `gzip`, `tar`, `7z`, `jar`, `pdf`, `msole2`, `dex`, script/mail names, ...) raise the dedicated format flags. |
| `Type` | Numeric type code, informational. |
| `Offset` | 0-based byte offset of the magic; **negative** counts from EOF (`-7` = magic ends 7 bytes before end). |
| `Magic` | Comma-separated hex bytes (`4D,5A`); **empty** matches any content at the offset (combine with `MIN_FLC`). |
| `MIN_FLC` / `MAX_FLC` | File length bounds, `0` = unbounded. |
| `ALIAS` | Report the entry as this type name instead of `Name`. |

An unresolved `primary` (the built-in classifier found nothing) adopts the
first matching type name. The matched entries appear in the report's
`file_type.tags`, so extractors, emulators and external engines route on the
same classification; an unknown name never blocks `--include-type`-style use
beyond that tag. `--include-type` / `--exclude-type` accept both builtin types
(filter at walk time, before scanning) and the rule-assigned tags of the next
paragraph plus these ftm names (decided after the rules ran, because that is
when the tags exist).

#### `assign_types` (rules that classify)

A rule may add tags to the file type when it fires:

```yaml
- id: COMPONENT-VERIFIER
  title: recognizable update utility layout
  severity: low
  private: true
  conditions:
    - type: string_contains
      value: "VerifyUpdateSignature"
      nocase: true
  assign_types: [update_verifier]
```

Every matched rule's `assign_types` tag is appended to `file_type.tags`
(alias `assign_file_type`), freeing later rules to gate on it with a normal
`file_type` condition (`- type: file_type / values: [update_verifier]`),
routing tools to see it in the JSON report and external components to receive
the classification. Tag names are free-form; they are treated exactly like
`ftm` tags (normalized letters/digits/`_`).

#### Magic DB names in `file_type` and the type filters

`file_type` values and `--include-type` / `--exclude-type` accept the `Name`
and the `ALIAS` of a loaded `--ftm` entry exactly as written in the DB; no
renaming is needed:

```yaml
- type: file_type
  values: [MY_TYPE_ZIP, MY_TYPE_PDF, myalias]
```

```
--ftm types.ftm --include-type MY_TYPE_ZIP --exclude-type myalias
```

Both sides go through the same normalizer (ASCII letters and digits
lowercased, every other run of characters becomes one `_`, outer `_`
trimmed), so `MY_TYPE_ZIP`, `my-type-zip` and `my_type_zip` are the same
type. A matching entry contributes both its normalized `Name` and its
normalized `ALIAS` as `file_type.tags`, so a rule may name the entry either
way. Load checks (`--check-rules` included, section 7) accept these names
when `--ftm` is given; a name that is neither builtin, nor assigned by a
rule, nor in the loaded DB is still reported as `unknown file type`. The
filters decide magic DB names at walk time, like builtin types, since the
classification already holds their tags before the rules run.

A namespaced name of the form `<prefix>_TYPE_<format>` raises the same
dedicated flags as the bare `<format>`, so builtin `file_type` values keep
working on files the DB classifies:

| `<format>` | Flags |
|---|---|
| `zip`, `rar` / `rar5`, `7z`, `gzip`, `tar`, `jar` | the matching `is_*` flag and `is_archive` |
| `msexe` | `is_pe`, `is_binary` |
| `pdf` | `is_pdf`, `is_binary` |
| `msole2` | `is_office`, `is_microsoft_compound` |
| `java_class` | `is_java_class` |
| `dex` | `is_dex` |

For example a file tagged `my_type_zip` also matches `file_type: [archive]`
and `[zip]`, and one tagged `my_type_msexe` matches `[pe]`.

### 5.12 Script/IL preprocessing

Before the generic base64/hex pass, extracted strings run through focused
script decoders that turn obfuscated script payloads into readable decoded
strings. They feed the same `report.decoded_strings` list, so every `decoded`
consumer sees them: `string_contains`, `string_set`, `string_regex`, the
`decoded_string_count` feature and `env_reference` hits.

| `method` | Source pattern in the file | Decoded result |
|---|---|---|
| `ps_encodedcommand` | `powershell` style `-EncodedCommand` / `-enc` / `-e <base64-token>` | The payload text (UTF-16LE first, then UTF-8). |
| `ps_frombase64string` | `[Convert]::FromBase64String("...")` (single quotes allowed) | The payload text. |
| `js_atob` | `atob("...")` | The payload text. |
| `vbs_chr_chain` | `Chr(104)&Chr(97)...` chains of 3+ members (`ChrW` included) | The joined characters. |

Rules expect readable decoding results (8+ characters count); short or binary
decodes are dropped. `--no-decode` disables the whole decoded layer.

### 5.13 DEX conditions (Android payloads)

Dalvik executable (`classes.dex`) structure is parsed lazily: header counts, string table, defined classes and method references. Non-DEX files never match these conditions. DEX yapısı parse ediliyor (veri tablosu + class + method tabloları).

| Type | Keys | Matches when |
|---|---|---|
| `dex_string_regex` | `pattern` | Regex matches any entry in the DEX string table. |
| `dex_class_regex` | `pattern`, `min` (default 1) | Dotted class name (`com.foo.Bar`) matches regex at least `min` times. |
| `dex_method_regex` | `pattern`, `min` (default 1) | Method reference (`com.foo.Bar->name`) matches regex at least `min` times. |
| `dex_class_count` | `min` (default 1) | Number of class definitions (`classes`) is at least `min`. |
| `dex_method_count` | `min` (default 1) | Number of method references (`methods`) is at least `min`. |

Example:

```yaml
rules:
  - id: TEST-DEX-DROPPER
    title: dex dropper class and method counts
    severity: high
    conditions:
      - type: dex_class_regex
        pattern: "(net\\.alchemy|lepplix).*dropper"
        min: 1
      - type: dex_method_count
        min: 200
```

### 5.14 Android packages and compound files

**APK profile.** An Android package (`file_type: apk`) gets `report.apk`: a
58-value structural profile (package layout, manifest summary and capability
permissions, DEX counts, native library architectures and symbols, Dalvik API
references, packaging anomalies, string statistics). Every value is also a
feature named `apk_<name>`, so `feature_gte`, `feature_lte` and
`feature_bounds` read it:

```yaml
- id: TEST-APK-SMS-TRIO
  title: premium sms permission trio
  severity: high
  logic: all
  conditions:
    - type: feature_gte
      name: apk_sms_trio
      value: 1
    - type: feature_gte
      name: apk_api_sms_send_calls
      value: 0.5
```

`*_log` sizes, the `so_*` symbol counts, every `api_*` count,
`assets_entry_count` and the `*_hits` counts are stored as `ln(1 + n)`
(`apk_api_sms_send_calls >= 0.5` means at least one reference); the other
counts (`dex_*`, `perm_total`, `dangerous_perm_count`, ...) are raw, and flags
are 0 or 1. The string statistics
(`mal_str_hits` ... `total_unique_strings_log`) need a string model supplied by
the embedding engine; without one every string counts as unknown. The members
of the APK (`classes.dex`, libraries) are still scanned one by one, so DEX
conditions (5.13) apply to each `classes*.dex`.

**Compound files (OLE2 / CFB).** Legacy Office documents, MSI and other
structured storage files are opened like archives: every stream is scanned as a
member named by its storage path (`Macros/VBA/Module1`; control characters
written as `\x01`). An OLE packager stream (`\x01Ole10Native`) also yields the
file it embeds as `<stream>/<embedded name>`, so `path_regex` /
`path_glob` rules can target dropped payloads. Stream and total sizes follow
the archive limits.

### 5.15 Office macro preprocessing (VBA)

Compound-file Office documents (`.doc`, `.xls`, `.ppt` and other OLE2
containers) are searched for VBA projects: every storage named `VBA`
(`Macros/VBA`, `_VBA_PROJECT_CUR/VBA`, ...). Module sources are stored
compressed ([MS-OVBA] 2.4.1), so the raw bytes never hold readable macro code.
The engine reads the project's `dir` stream for the module names and the
offset of each compressed source, decompresses every module and adds each
non-blank source line to `report.decoded_strings`:

| Field | Value |
|---|---|
| `method` | `vba_source` |
| `source` | `<module>:<line>` (e.g. `AutoMod:3`) |
| `decoded` | The source line; lines longer than 512 characters become overlapping pieces, so no part is dropped. |

When `dir` is missing or damaged, module streams are searched for the
compressed `Attribute VB_Name` header instead. There is no new condition: every
`decoded` consumer sees macro code (`string_contains` / `string_set` /
`string_regex` with `decoded: true`, `native_signature` atoms with
`decoded: true`, the `decoded_string_count` feature).

```yaml
- id: TEST-VBAMACRO-SHELL
  title: macro starts a shell object
  severity: high
  verdict: malware
  logic: all
  conditions:
    - type: string_contains
      value: "CreateObject(\"WScript.Shell\")"
      nocase: true
      decoded: true
    - type: string_regex
      pattern: "(?i)sub\\s+(auto_?open|document_open|workbook_open)"
      decoded: true
```

Limits: 1 MiB per decompressed module, 512 modules, 2000 `vba_source`
entries per file. `--no-decode` turns macro extraction off with the rest of the
decoded layer.

### 5.16 Signature pack manifest (`--rules-pack`)

A pack manifest pins the exact rule files of a release, so a scanner never runs
a partially updated or modified pack:

```yaml
# HydraDragonSig rule pack manifest: every file must match its sha256 and size.
version: 2                              # positive integer
generated_at: "2026-11-02T12:00:00Z"    # informational
notes: "generic pack"                   # optional
files:
  - path: base.yaml                     # relative to the manifest's directory
    sha256: 6b4d624d9c1bf029f04b7a20352d943c987764ae331827ee7278eac2e1031a23
    size: 153
  - path: rules/macro.yaml
    sha256: b2a19582c57585354e0f1abf5d62889dc568074936bfd7819246b2effd22b3ec
    size: 251
```

| Key | Required | Meaning |
|---|---|---|
| `version` | yes | Pack version, at least 1. |
| `generated_at` | no | Creation time, not checked. |
| `notes` | no | Free text. |
| `files[].path` | yes | Rule file, `/`-separated, relative to the manifest; absolute paths and `..` are refused. Listed once each. |
| `files[].sha256` | yes | SHA-256 of the file bytes (64 hex). |
| `files[].size` | yes | File size in bytes. |

Unknown keys are an error. Hashes cover the exact bytes: converting a rule
file's line endings (CRLF/LF, e.g. by a git checkout setting) is a mismatch,
so ship packs with their line endings fixed.

Flow:

1. `hydradragonsig --create-rules-pack <files or dirs> --out pack/rule_pack.yml
   [--pack-version N] [--pack-notes TEXT]` hashes the `.yaml`/`.yml` files
   (directories are walked) and writes the manifest. Every file must lie under
   the manifest's directory.
2. `hydradragonsig --rules-pack pack/rule_pack.yml <paths>` checks every file
   (present, regular file, not a symbolic link, size, then SHA-256) before
   anything is loaded. On any mismatch it prints each failing file and exits
   with code 2; otherwise the files are loaded in manifest order, replacing
   `--rules` (the two flags cannot be combined).
3. `--rules-pack ... --check-rules` verifies the pack, then runs the usual
   load checks (section 7). The verification is the dry run: no separate
   verify-only flag is needed.

**Signed packs.** A manifest may carry an Ed25519 signature:

```yaml
signature:
  algorithm: ed25519
  key_id: "hds-prod-2026-01"
  value: "<128 hex characters>"
```

The signature covers a fixed transcript, not the YAML text: `HDS-PACK-V1`, the
version, the length-prefixed `generated_at`, `notes` and `key_id` (`-` when
absent), then one `path<TAB>size<TAB>sha256` line per file sorted by path.
Reformatting, comments, key order and the order of `files` leave it valid; any
change to a listed value breaks it. Paths may not hold control characters.

| Flag | Meaning |
|---|---|
| `--pack-keygen PREFIX [--pack-key-id ID]` | Writes `PREFIX.key` (64 hex seed; owner-only on Unix) and `PREFIX.pub` (`ID:<64 hex public key>`); never overwrites. |
| `--create-rules-pack ... --pack-sign-key FILE [--pack-key-id ID]` | Signs the written manifest. The key file is the 64 hex seed `--pack-keygen` writes, or an unencrypted PKCS#8 Ed25519 key (`-----BEGIN PRIVATE KEY-----` PEM from `openssl genpkey -algorithm ed25519`, or the DER). |
| `--pack-pubkey KEY` | Trusted key(s): a `.pub` / keyring file (`id:<hex>` or bare `<hex>` per line, `#` comments) or one key inline; repeatable. The pack must be signed by a key with the signature's `key_id` (a bare key accepts any id). |
| `--require-signed-pack` | Refuse unsigned packs (needs `--pack-pubkey`). |
| `--min-pack-version N` | Refuse a pack whose `version` is below N (rollback). |

Checks run in this order and the first failure exits with code 2: manifest
shape and unknown keys, `version >= N`, the signature (before any rule file is
opened), then every file's type, size and SHA-256. Without `--pack-pubkey` /
`--require-signed-pack` a signature is only checked for its shape. Library:
`rules::pack::load_manifest_with_policy(path, &PackVerifyPolicy { trusted_keys,
require_signature, min_version })`, keys from `rules::pack::parse_public_keys`.

### 5.17 .NET metadata

CLR metadata of a PE is read when a rule needs it: the CLI header, the `BSJB`
root, the streams and the TypeRef, TypeDef, MethodDef, MemberRef, ModuleRef,
ImplMap, Assembly and CustomAttribute tables. A PE with that metadata gets the
file type `dotnet`; other files never match these conditions.

| Type | Keys | Matches when |
|---|---|---|
| `dotnet_guid_any` | `values` | The module MVID or the assembly's `GuidAttribute` (type library id) is one of `values` (case, `{}` and `-` ignored). |
| `dotnet_type_regex` | `pattern`, `min` (default 1) | At least `min` defined or referenced types (`Namespace.Type`) match. |
| `dotnet_method_regex` | `pattern`, `min` (default 1) | At least `min` defined methods or member references (`Namespace.Type::Method`) match. |
| `dotnet_pinvoke_any` | `names` | A P/Invoke import (`module.dll!function`; a module without extension gets `.dll`) ends with one of `names`, case-insensitive (as `import_any`). |
| `dotnet_pinvoke_set` | `names`, `min` (default 1) | At least `min` names match P/Invoke imports. |
| `dotnet_stream_any` | `names` | A metadata stream has one of these names (`#Confuser`, `#SuppressIldasm`, ...; case-insensitive). |
| `dotnet_user_string_regex` | `pattern`, `min` (default 1) | At least `min` `#US` strings match. |

`#US` strings of 8 or more characters (4096 at most, 1 MiB) are decoded strings
with method `dotnet_us`, so `decoded: true` conditions see them.

### 5.18 ELF

32/64-bit ELF of either byte order: header, sections, program headers, dynamic
tags, `.dynsym` (or `.symtab`) symbols and the `NT_GNU_BUILD_ID` note. Other
files never match.

| Type | Keys | Matches when |
|---|---|---|
| `elf_import_any` / `elf_import_set` | `names` (`min`, default 1) | Undefined (imported) symbols, exact names. |
| `elf_import_regex` | `pattern`, `min` (default 1) | At least `min` imported symbols match. |
| `elf_export_any` / `elf_export_set` | `names` (`min`, default 1) | Defined global / weak function and object symbols. |
| `elf_needed_any` | `names`, `nocase` | A `DT_NEEDED` library is one of `names`. |
| `elf_section` | `select` (`any`, `last`, `entry`), `index`, `name`, `name_regex`, `flags_all`, `flags_none` (`alloc`, `write`, `exec`), `entropy_min`, `entropy_max`, `size_min`, `size_max`, `md5`, `sha256` | The chosen section passes every given key (as `pe_section`). |
| `elf_segment` | `seg_type` (`load`, `dynamic`, `interp`, `note`, `phdr`, `tls`, `gnu_stack`, `gnu_relro`, `gnu_eh_frame`, ... or a number), `flags_all`, `flags_none` (`r`, `w`, `x`), `memsz_minus_filesz_min`, `entropy_min` | A program header passes every given key: an RWX `load`, an executable `gnu_stack`, a large in-memory gap. |
| `elf_build_id_any` | `values` | The GNU build id (hex) is one of `values`. |
| `new_elf_import_set` | `names`, `min` | See 5.6. |

### 5.19 Mach-O

Thin 32/64-bit Mach-O and Universal (fat) binaries; every architecture slice is
read and a condition holds when one slice satisfies it.

| Type | Keys | Matches when |
|---|---|---|
| `macho_dylib_any` | `names` | A loaded dylib (`LC_LOAD_DYLIB`, weak, re-export, lazy, upward) path ends with one of `names`, case-insensitive. |
| `macho_sym_any` | `names`, `min` (default 1) | External symbols (`_ptrace` also matches `ptrace`). |
| `macho_sym_regex` | `pattern`, `min` (default 1) | At least `min` external symbols match. |
| `macho_segment` | `name`, `flags_all`, `flags_none` (`r`, `w`, `x` of the initial protection), `entropy_min`, `entropy_max` | A segment passes every given key. |
| `macho_uuid_any` | `values` | `LC_UUID` is one of `values` (case and `-` ignored). |
| `macho_signed` | `signed`, `adhoc`, `identifier_glob`, `team_id` | `LC_CODE_SIGNATURE` has (`signed: true`) or lacks a code directory; ad-hoc (`CS_ADHOC` or no CMS signature), signing identifier glob, team id. |
| `macho_entitlement_any` | `keys` | The embedded entitlements hold one of these keys (e.g. `com.apple.security.cs.disable-library-validation`). |

The entitlements XML is a decoded string with method `macho_entitlements`.

### 5.20 PDF

The PDF is scanned without its cross-reference table: `%PDF-` within the first
KiB, every `N G obj` block, names unescaped (`/#4A#61#76#61#53#63#72#69#70#74`
is `/JavaScript`), streams decoded through `FlateDecode`, `ASCIIHexDecode`,
`ASCII85Decode`, `RunLengthDecode` (and `Fl`, `AHx`, `A85`, `RL`) and `/ObjStm`
object streams opened. Budgets: 2 MiB per decoded stream, 16 MiB per file, 4
filters per chain, 4096 objects; past a budget a stream is cut, never fully
inflated. Nothing is executed.

| Type | Keys | Matches when |
|---|---|---|
| `pdf_keyword` | `names`, `min` (default 1) | At least `min` of these names occur (`JavaScript`, `JS`, `OpenAction`, `AA`, `Launch`, `EmbeddedFiles`, `RichMedia`, `XFA`, `AcroForm`, `JBIG2Decode`, ...; with or without `/`). |
| `pdf_stream_match` | `patterns`, `min` (default 1), `filter_any`, `decoded` (default true) | At least `min` patterns (text, or a `{ hex }` byte pattern) occur in a stream, decoded unless `decoded: false`, only in streams whose filter chain has one of `filter_any` when given. |

`/JS` payloads (inline or in a referenced stream), `/URI` targets, `/Launch`
`/F` / `/P` values and mostly printable decoded streams are decoded strings
with methods `pdf_js`, `pdf_uri`, `pdf_launch` and `pdf_stream`.

## 6. native_signature

YARA-like atoms plus a boolean expression:

```yaml
- type: native_signature
  expression: "$cmd and (2 of ($url*) or $key at 0x40)"
  atoms:
    - id: cmd
      value: "powershell -enc"
      nocase: true
      ascii: true
      wide: true
    - id: url1
      value: "/gate.php"
    - id: url2
      kind: regex
      value: "https?://[0-9]{1,3}(\\.[0-9]{1,3}){3}/"
    - id: key
      kind: bytes
      value: "{ 6A 40 68 00 30 00 00 }"
```

Atom keys:

| Key | Default | Meaning |
|---|---|---|
| `id` | required | Letters, digits, `_`. Unique in the condition. |
| `kind` | `text` | `text`, `regex` or `bytes`. |
| `value` | required | Text, regex, or byte pattern (section 5.4 syntax). |
| `ascii` / `wide` | ascii on unless only `wide` is set | Encodings searched (text). |
| `nocase` | false | ASCII case folding (text, regex). |
| `fullword` | false | The match must not touch letters, digits or `_` on either side (text). |
| `xor` | false | Also search the value XORed with every key from `xor_min` (1) to `xor_max` (255). As in YARA, `xor` alone (= `xor(0-255)`) also matches the plain value; an explicit `xor_min: 1` or more (= `xor(1-255)`) searches **only** XORed forms, e.g. a hidden DOS stub without hitting the file's own header. Fixed-width byte patterns only for `bytes`. |
| `base64` / `base64wide` | false | Search the base64 form of the value (ASCII / UTF-16LE), at any of the three alignments, **instead of** the plain value (as YARA). |
| `decoded` | false | Also search decoded strings. |

`text` and `bytes` atoms are searched in the raw file; `regex` atoms in the
extracted strings.

Expression grammar (case-insensitive keywords):

| Form | Meaning |
|---|---|
| `$a` | Atom `a` matched. |
| `any of them`, `all of them`, `2 of them` | Over all atoms. |
| `any of ($a, $b*)`, `3 of ($s*)`, `all of ($*)` | Over a list; `$x*` selects every atom whose id starts with `x`. |
| `$a at 0x40`, `$a in (0..1024)` | An occurrence at / inside this offset range (decimal or `0x` hex). |
| `$a at $b + 16`, `$a at $b - 4` | An occurrence of `a` exactly that far from one of `b`. |
| `@a < @b`, `@a[8] == @b`, `@a >= 0x100` | Compare occurrence offsets (`== != < <= > >=`): holds when any pair of occurrences does. `[n]` **adds n bytes** to the offset (it is not YARA's occurrence index). |
| `filesize < 500KB` | Size comparison; `KB`, `MB`, `GB` are powers of 1024. |
| `uint16(0) == 0x5A4D`, `uint32(0x3c) == 0x4550`, `uint32(uint32(0x3c)) == 0x4550` | Little-endian values at an offset. |
| `#a`, `#a in (0..512)` | Number of occurrences (in the inclusive start-offset range). |
| `!a`, `!a[2]` | Length of the first / 2nd occurrence (text and byte atoms). |
| `@a#2` | Offset of the 2nd occurrence (1-based; `@a#i`, `@a#(expr)`). `@a` in arithmetic is the first. |
| `uint8`, `uint16`, `uint32`, `uint16be`, `uint32be`, `int8`, `int16`, `int32`, `int16be`, `int32be` | Integer at an offset (little endian unless `be`; `int*` signed). |
| `entrypoint` | Raw file offset of the PE / ELF / Mach-O entry point. |
| `+ - * / % & \| ^ << >> ~`, `== != < <= > >=` | 64-bit integer arithmetic and comparisons on any integer expression. |
| `for any of ($s*) : ( @ >= entrypoint and ! > 16 )` | `any`, `all`, `none`, `N` or `N%` of the atoms satisfy the body; in it a bare `$`, `#`, `@`, `!` (`@#i`, `![i]`) mean the current atom. |
| `for all i in (0..15) : ( uint8(i) != 0 )` | `any`, `all`, `none`, `N` of the integers satisfy the body (at most 4096 values). |
| `PE`, `PE32`, `PE64`, `DotNet`, `ELF`, `ELF32`, `ELF64`, `MachO`, `MachO64`, `ARM64`, `APK`, `ZIP`, `JAR`, `DEX`, `PDF`, `OLE`, `Office`, `Archive`, `Text`, `PlainText`, `Script` | File type tests. |
| `and`, `or`, `not`, `( )` | Precedence: `not` > `and` > `or` > comparisons > `\|` > `^` > `&` > shifts > `+ -` > `* / %` > unary `- ~`. |

A value can be undefined: an atom that did not match (`!a`, `@a#3`), a read past
the end of the file, division or modulo by zero, overflow, `entrypoint` of a
file that has none. A comparison with an undefined value is false. Integers
are not conditions: `#a > 0`, not `#a`.

A `for .. in` loop over more than 4096 values is refused at load time when its
bounds are numbers, and evaluates to false when they are computed; nested loops
share a budget of 2,000,000 steps. Expressions written only with the original
forms (atoms, `of`, `at`, `in`, `@a[n]` comparisons, `filesize`, `uint16` /
`uint32 ==`, type words) are evaluated exactly as before.

Not supported (refused at load time): modules (`pe.`, `math.`), `uint64`,
string comparisons, `for .. in` over lists.

## 7. Load checks

`RuleSet::from_yaml_str` / `from_yaml_file` keep the rules and list problems in
`RuleSet::warnings()`; `from_yaml_file` and `--check-rules` print them.
`RuleSet::from_yaml_str_strict` refuses a document with any problem (the Multron
signature room uses it). Problems reported:

- unknown keys anywhere (rule, condition, atom, `scope`, `mitre`, ...);
- invalid regexes, byte patterns and native expressions; atom ids that do not exist;
- conditions that can never match (empty lists, `min` larger than the list,
  `threshold` larger than the condition count, all encodings off, no conditions);
- unknown `file_type` values, `feature_gte` / `feature_lte` / `feature_delta_gte`
  and `parent_feature_*` names, malformed hashes and icon
  fingerprints;
- duplicate rule ids; `rule_match` ids not defined earlier.

YAML errors (bad indentation, an unquoted `: ` inside a value, an unknown
`severity` / `verdict` / `type`) stop the whole file from loading. Quote values
that contain `: `, `#` or start with a special character; in single quotes a `'`
is written `''`.

## 8. File types

`file_type` values (also used for rule gating): `pe` (also `exe`, `dll`, `sys`),
`pe32`, `pe64`, `elf`, `elf32`, `elf64`, `macho`, `apk`, `zip`, `archive`, `7z`,
`rar`, `gzip`, `tar`, `jar`, `dex`, `java_class`, `asar`, `pdf`, `office`,
`openxml`, `ole`, `text`, `script`, `powershell`, `batch`, `javascript`, `vbs`,
`python`, `shell`, `binary`, `unknown`, `broken`, `broken_executable`,
`broken_pe`, `broken_elf`, `broken_macho`, `broken_apk`, `dotnet` (a PE with CLR
metadata).

`broken_*`: the file starts with the format's magic but its header does not
parse (for example `MZ` without a valid PE header).

## 9. Features (`feature_gte`, `feature_lte`, `feature_delta_gte`)

`string_count`, `decoded_string_count`, `env_hit_count`,
`file_entropy_bits_per_byte`, `pe_import_count`, `pe_export_count`,
`pe_section_count`, `pe_suspicious_import_count`.

Structural features, present only for files of that format: `dotnet_type_count`,
`dotnet_method_count`, `dotnet_pinvoke_count`, `dotnet_user_string_count`,
`dotnet_stream_count`; `elf_import_count`, `elf_export_count`,
`elf_section_count`, `elf_rwx_segment_count`; `macho_dylib_count`,
`macho_section_count`, `macho_rwx_segment_count`; `pdf_obj_count`,
`pdf_stream_count`, `pdf_objstm_count`, `pdf_js_count`, `pdf_openaction_count`,
`pdf_embedded_file_count`, `pdf_uri_count`.

Android packages add `apk_<name>` for each APK profile value (section 5.14):
`apk_dex_classes`, `apk_dex_strings`, `apk_dex_methods`, `apk_dex_files`,
`apk_elf_so_count`, `apk_perm_total`, `apk_activities`, `apk_services`,
`apk_receivers`, `apk_min_sdk`, `apk_target_sdk`, `apk_entropy`,
`apk_entry_count`, `apk_file_size_log`, `apk_manifest_size_log`,
`apk_dex_size_log`, `apk_so_size_log`, `apk_dangerous_perm_count`,
`apk_sms_trio`, `apk_has_manifest`, `apk_multidex`, `apk_compression_ratio`,
`apk_avg_entry_size_log`, `apk_native_with_perms`, `apk_has_arm64`,
`apk_has_arm32`, `apk_has_x86`, `apk_has_x86_64`, `apk_so_exported_jni_count`,
`apk_so_imported_symbols_count`, `apk_so_suspicious_imports_count`,
`apk_perm_boot_completed`, `apk_perm_accessibility_service`,
`apk_perm_device_admin`, `apk_perm_system_alert_window`,
`apk_perm_install_packages`, `apk_perm_read_phone_state`,
`apk_perm_external_storage_write`, `apk_api_reflection_calls`,
`apk_api_dynamic_dex_loading`, `apk_api_crypto_cipher_calls`,
`apk_api_process_exec_calls`, `apk_api_sms_send_calls`,
`apk_api_device_id_calls`, `apk_api_network_http_calls`,
`apk_api_package_manager_queries`, `apk_api_anti_debug_root_calls`,
`apk_assets_entry_count`, `apk_assets_size_log`,
`apk_has_hidden_payload_in_assets`, `apk_is_protector_packed`,
`apk_has_non_standard_dex`, `apk_mal_str_hits`, `apk_ben_str_hits`,
`apk_mal_ben_str_ratio`, `apk_mal_str_density`, `apk_unknown_str_ratio`,
`apk_total_unique_strings_log`.

## 10. Writing good signatures

- Prefer several specific signals over one: `string_set` with `min: 2` or more of
  strings unique to the family, plus an import or byte condition, with `logic: all`.
- Avoid strings that come from compilers, runtimes, installers or common
  libraries (`Rich`, `.text`, `kernel32.dll`, `This program cannot be run in DOS
  mode`, `Microsoft Corporation`): they are in clean files too.
- Do not let cheap conditions (`file_type`, `file_size_lte`, common imports such
  as `VirtualAlloc`) reach a `threshold` on their own.
- Use `excludes` for benign blobs that contain your pattern, and `scope` when the
  pattern only makes sense in one place (header, overlay).
- Test before shipping: `--check-rules`, then scan clean software (system files,
  common installers) and a few samples of the family. In Multron the signature
  room runs a retrohunt over all stored files after every save: check that it
  matches no clean file.

## 11. Multron signature room

Analyst rules saved from the Multron dashboard follow these extra rules:

- every rule needs `family` in the naming convention
  `Category.Platform.Family[.Variant]`, written in its canonical form;
- `verdict` must be `malware`, `pua` or `suspicious`;
- the document is loaded strictly (section 7);
- `malware` makes the file malicious, `pua` and `suspicious` make it suspicious.
