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
| `private` | no | `false` | The rule is evaluated but produces no finding. Use it as a building block for `rule_match`. |
| `logic` | no | `any` | How conditions combine: `any`, `all`, `threshold`. |
| `threshold` | with `logic: threshold` | | How many conditions must match. |
| `conditions` | yes | | List of conditions (section 5). A rule without conditions never matches. |
| `file_path` | no | | Only evaluate the rule for this exact path, e.g. `%SystemRoot%\System32\drivers\etc\hosts`. `%VAR%` is expanded from the scanning machine's environment; the comparison is a full-path, case-insensitive match (no wildcards). |

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
  UTF-16LE). Off when the scan disables decoding (`--no-decode`).

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
| `hash_sha256` / `hash_md5` | `value` | The file hash equals `value` (case-insensitive). |
| `path_regex` | `pattern` | The regex matches the scanned path (as given; memory scans use `memory://<id>`, archive members `archive://<parent>!<member>`). |
| `feature_gte` | `name`, `value` | A numeric feature is ≥ `value` (section 9). |
| `feature_lte` | `name`, `value` | A numeric feature is ≤ `value` (section 9), e.g. `pe_import_count` ≤ 10 for a thin stub. |

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
| `parent_feature_gte` / `parent_feature_lte` | `name`, `value` | A parent feature is ≥ / ≤ `value`. Parent features: `file_entropy_bits_per_byte`, `pe_import_count`, `pe_export_count`, `pe_section_count`, `pe_suspicious_import_count` (PE ones only when the parent is a PE). |
| `feature_delta_gte` | `name`, `value` | This file's feature minus the parent's is ≥ `value`, e.g. `pe_suspicious_import_count` grew by 5 after unpacking. Both sides must have the feature. |
| `new_import_set` | `names`, `min` (default **1**) | At least `min` names match an import of this file that the parent does **not** import (same suffix matching as `import_set`). PE condition. |

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
| `@a < @b`, `@a[8] == @b`, `@a >= 0x100` | Compare occurrence offsets (`== != < <= > >=`). `[n]` **adds n bytes** to the offset (it is not YARA's occurrence index). |
| `filesize < 500KB` | Size comparison; `KB`, `MB`, `GB` are powers of 1024. |
| `uint16(0) == 0x5A4D`, `uint32(0x3c) == 0x4550`, `uint32(uint32(0x3c)) == 0x4550` | Little-endian values at an offset (only `==`). |
| `PE`, `PE32`, `PE64`, `DotNet`, `ELF`, `ELF32`, `ELF64`, `MachO`, `APK`, `ZIP`, `JAR`, `DEX`, `Archive`, `Text`, `PlainText`, `Script` | File type tests. |
| `and`, `or`, `not`, `( )` | Precedence: `not` > `and` > `or`. |

Not supported (refused at load time): `#a` counts, `!a` lengths, `for` loops,
`uint8`, arithmetic, modules (`pe.`, `math.`).

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
`broken_pe`, `broken_elf`, `broken_macho`, `broken_apk`.

`broken_*`: the file starts with the format's magic but its header does not
parse (for example `MZ` without a valid PE header).

## 9. Features (`feature_gte`, `feature_lte`, `feature_delta_gte`)

`string_count`, `decoded_string_count`, `env_hit_count`,
`file_entropy_bits_per_byte`, `pe_import_count`, `pe_export_count`,
`pe_section_count`, `pe_suspicious_import_count`.

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
