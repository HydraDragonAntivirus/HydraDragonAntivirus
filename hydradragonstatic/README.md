# HydraDragonStatic

HydraDragonStatic is a standalone Rust static analysis scanner for Windows PE files, extracted strings, decoded/obfuscated strings, registry indicators, environment references, entropy, and deterministic external Yamdle/YAML antivirus signatures.

## No built-in rules

This build intentionally ships with **no built-in production signatures** and the binary does **not** embed any rule pack.

- No `include_str!` rule embedding
- No default static signature list
- No bundled production malware database
- No machine learning, training, cloud scoring, or auto-learning
- The scanner only detects what your explicitly supplied Yamdle/YAML rules match

At least one external rule file or rule directory must be passed with `--rules`.

## Detection philosophy

HydraDragonStatic is deterministic and signature-engine style:

- `verdict: malware` means one matched rule is enough for the final file verdict to become `MALWARE`.
- `verdict: suspicious` means the rule is evidence only and does not become Malware by itself.
- `verdict: clean` can be used for informational checks that should not affect the final verdict.
- Aggressiveness is controlled by rule design.
- Rules can have multiple internal conditions with `logic: all`, `logic: any`, or `logic: threshold`.

## Features

- Windows PE import detection through `goblin`
- Suspicious API/import clustering
- DLL and section analysis
- File and section Shannon entropy in bits/byte (0.0-8.0)
- ASCII and UTF-16LE string extraction
- Decoding for base64, hex, reverse strings, ROT13, and simple XOR indicators
- Registry persistence and reconnaissance indicators
- Environment/sandbox/anti-analysis string indicators
- Deterministic external Yamdle/YAML signature rules
- Recursive multi-root and alternate sub-path scanning
- Path-list input for bulk target lists
- Include/exclude glob filters for controlled recursive scans
- Signature-style hex byte patterns with `??` wildcards and nibble wildcards
- JSON, JSONL, and readable terminal output

## Build

```bash
cargo build --release
```

## Run

Single file with one external rule pack:

```bash
cargo run --release -- path/to/sample.exe --rules rules/my_pack.yaml
```

Multiple external rule packs:

```bash
cargo run --release -- path/to/sample.exe --rules rules/base.yaml --rules rules/malware_families.yaml
```

Load every `.yaml` / `.yml` file in a rules directory:

```bash
cargo run --release -- ./samples --recursive --rules rules/
```

Multiple scan roots / alternate sub-paths:

```bash
cargo run --release -- ./samples ./dropzone --scan-path ./quarantine --recursive --rules rules/
```

Read extra scan roots from a path list file:

```bash
cargo run --release -- ./samples --path-list targets.txt --recursive --rules rules/
```

Controlled recursive scan with depth and path filters:

```bash
cargo run --release -- C:/Users --recursive --max-depth 4 --rules rules/ \
  --include "*.exe" --include "*.dll" --exclude "*/AppData/Local/Temp/*"
```

JSONL output:

```bash
cargo run --release -- ./samples --recursive --rules rules/ --output jsonl
```

## Rule format

```yaml
rules:
  - id: CUSTOM-SIG-001
    title: Custom strong signature
    severity: Critical
    verdict: malware
    confidence: 95
    family: custom.family
    score: 40
    tags: [custom, yamdle]
    logic: any
    conditions:
      - type: string_set
        values: [very_unique_malware_mutex, very_unique_c2_gate]
        min: 1
        nocase: true
        decoded: true
      - type: byte_pattern
        pattern: "{ DE AD BE EF ?? 90 }"
```

This rule marks the final file as Malware if either condition matches because the rule has `verdict: malware` and `logic: any`.

## Native Yamdle signature condition

```yaml
conditions:
  - type: native_signature
    expression: "2 of ($a*) and any of ($b*)"
    atoms:
      - id: a1
        kind: text
        value: suspicious marker
        nocase: true
        decoded: true
      - id: b1
        kind: bytes
        value: "{ 4D 5A ?? ?? }"
```

Supported native expression subset:

- `any of them`, `all of them`, `N of them`
- `any/all/N of ($prefix*)`
- `$id`, `$id at 0`, `$id in (0..512)`
- `and`, `or`, `not`, parentheses
- `filesize < 500KB`, `filesize >= 1MB`
- PE/Mach-O/ELF/.NET magic words and common `uint16/uint32` magic checks

## Supported condition types

- `native_signature`
- `string_contains`
- `string_regex`
- `string_set`
- `byte_pattern`
- `byte_set`
- `import_any`
- `import_all`
- `import_set`
- `import_regex`
- `dll_any`
- `dll_regex`
- `suspicious_import_count`
- `file_entropy`
- `file_size_gte`
- `file_size_lte`
- `section_entropy`
- `section_name_regex`
- `packed_pe`
- `env_reference`
- `registry_pattern`
- `registry_hit_count`
- `path_regex`
- `hash_sha256`
- `hash_md5`
- `feature_gte`

## Entropy scale

HydraDragonStatic entropy values are **Shannon bits per byte** and use the standard byte entropy range:

- `0.0`: no randomness / every byte identical
- `8.0`: theoretical maximum for uniformly random byte distribution
- Practical packed/encrypted thresholds usually live around `7.0`-`7.8`, not `0.7`-`0.98`

So Yamdle rules should be written like this:

```yaml
conditions:
  - type: file_entropy
    min: 7.2
  - type: section_entropy
    min: 7.4
```

Do **not** use normalized `0.0`-`1.0` entropy thresholds.


## Recursive alternate path scanning

HydraDragonStatic can now scan more than one root in the same run. This is useful when a static AV workflow has several sample locations, quarantine folders, extracted archives, or manually selected subdirectories.

Supported target inputs:

```bash
# Multiple positional roots
cargo run --release -- ./samples ./unpacked ./quarantine --recursive --rules rules/

# Extra repeatable roots
cargo run --release -- ./samples --scan-path ./alt1 --scan-path ./alt2 --recursive --rules rules/

# Same as --scan-path, friendlier name for scripts
cargo run --release -- ./samples --include-path ./alt-path --recursive --rules rules/

# Path-list file, one path per line, # comments allowed
cargo run --release -- ./samples --path-list targets.txt --recursive --rules rules/
```

Depth and symlink controls:

```bash
# Unlimited recursive walk
--recursive

# Files directly under root plus 2 nested directory levels
--recursive --max-depth 2

# Follow symlinks only when explicitly requested
--follow-links
```

Path filters are case-insensitive and use simple glob-like matching. Backslashes are normalized to `/`, so the same filters work on Windows-style and Unix-style paths.

```bash
# Only executable-like files
--include "*.exe" --include "*.dll" --include "*.sys"

# Skip noisy folders
--exclude "*/node_modules/*" --exclude "*/target/*" --exclude "*.tmp"
```

The scanner deduplicates targets after collecting all roots, so the same file is not scanned twice when paths overlap.

## Parallel rule scanning and stop modes

By default HydraDragonStatic parallelizes across files and evaluates rules sequentially inside each file. For large rule packs and single-file scans, enable rule-level parallelism:

```bash
cargo run --release -- sample.exe --rules rules/ --parallel-rules
```

Useful combinations:

```bash
# Use rule-level parallelism and avoid nested file-level parallelism
cargo run --release -- ./samples --recursive --rules rules/ --parallel-rules --no-parallel-files

# Cap Rayon workers used by file/rule parallel execution
cargo run --release -- sample.exe --rules rules/ --parallel-rules --rule-threads 8
```

Stop modes:

```bash
# Stop evaluating more rules for each file after the first matched rule
cargo run --release -- sample.exe --rules rules/ --stop-on-detection

# Parallel rule evaluation plus deterministic first-match behavior by rule-file order
cargo run --release -- sample.exe --rules rules/ --parallel-rules --stop-on-detection

# Directory scan: stop the whole scan after the first detected file
cargo run --release -- ./samples --recursive --rules rules/ --stop-scan-on-detection
```

Notes:

- `--parallel-rules` uses Rayon to evaluate rules concurrently. Matched findings are sorted after scan, so output stays stable.
- `--stop-on-detection` is per-file and returns only the first matched rule for that file.
- With `--parallel-rules --stop-on-detection`, the engine keeps the earliest matching rule in the external rule-file order.
- `--stop-scan-on-detection` forces sequential file scanning so the first detected file is deterministic.
- If rule profiling is enabled together with stop mode, profiling data is intentionally partial because later rules are skipped.


## False-positive rule removal mode

HydraDragonStatic can scan a known-clean false-positive sample and remove the matching external rule definitions from the Yamdle/YAML files you passed with `--rules`. This never touches built-in rules because this build has no built-in rules.

Dry run first:

```bash
cargo run --release -- clean_fp_sample.exe --rules rules/ --fp-remove --fp-remove-levels suspicious,malware --fp-remove-dry-run
```

Actually remove matching rules and create `.bak` backups next to each edited rule file:

```bash
cargo run --release -- clean_fp_sample.exe --rules rules/ --fp-remove --fp-remove-levels suspicious,malware
```

Choose exactly what gets removed with `--fp-remove-levels`:

- Severity levels: `info`, `low`, `medium`, `high`, `critical`
- Verdict levels: `clean`, `suspicious`, `malware`
- Shortcut: `all`

Examples:

```bash
# Remove only suspicious verdict rules that matched this clean file
cargo run --release -- clean.exe --rules rules/ --fp-remove --fp-remove-levels suspicious

# Remove only low/medium severity rules that matched this clean file
cargo run --release -- clean.exe --rules rules/ --fp-remove --fp-remove-levels low,medium

# Remove malware-verdict rules too, if the clean file triggered strong signatures
cargo run --release -- clean.exe --rules rules/ --fp-remove --fp-remove-levels malware
```

By default the tool writes `filename.yaml.bak` before modifying a rule file. Use `--fp-remove-no-backup` only if you are already version-controlling your rules. False-positive removal rewrites YAML through the serializer, so comments and original formatting may not be preserved.

## Exit codes

- `0`: no malware/suspicious verdict
- `2`: suspicious detection
- `3`: malware detection

## Notes

HydraDragonStatic is a defensive static analysis project. It does not execute samples, unpack malware, inject into processes, download payloads, or perform live remediation.


## Slow rule detection / rule profiler

HydraDragonStatic can profile every external Yamdle rule and report slow signatures without adding any built-in rules or runtime YARA dependency.

```bash
cargo run --release -- sample.exe --rules rules/ --profile-rules
```

Alias:

```bash
cargo run --release -- sample.exe --rules rules/ --slow-rules
```

Useful options:

```bash
# Show only rules whose slowest evaluation is >= 1 ms
--profile-rules --slow-rule-threshold-ms 1

# Show top 50 slow rules
--profile-rules --slow-rule-top 50

# Show all profiled rules, including fast ones
--profile-rules --slow-rule-threshold-ms 0 --slow-rule-top 0
```

Pretty output prints an aggregate summary with max/average runtime, evaluation count, match count, condition count, atom count, and the file where the rule was slowest. JSON and JSONL output include per-file `rule_performance` records when profiling is enabled.

## Slow rule removal mode

HydraDragonStatic can remove external Yamdle/YAML rules that are too slow after profiling. This is useful when a rule pack contains expensive regexes, huge atom groups, or broad byte patterns that make scanning slow.

Slow-rule removal automatically enables rule profiling; you do not need to pass `--profile-rules` separately.

Dry run first:

```bash
cargo run --release -- ./samples --recursive --rules rules/ \
  --remove-slow-rules \
  --slow-rule-threshold-ms 10 \
  --remove-slow-rules-dry-run
```

Actually remove rules whose slowest single evaluation is at least 10 ms:

```bash
cargo run --release -- ./samples --recursive --rules rules/ \
  --remove-slow-rules \
  --slow-rule-threshold-ms 10
```

By default slow-rule removal uses the `max` metric, meaning one very slow evaluation is enough to select the rule. You can switch to average runtime:

```bash
cargo run --release -- ./samples --recursive --rules rules/ \
  --remove-slow-rules \
  --slow-rule-threshold-ms 5 \
  --remove-slow-rule-metric avg
```

Limit removal to certain severities or verdicts:

```bash
# Remove only slow suspicious rules, keep malware verdict rules even if slow
cargo run --release -- ./samples --recursive --rules rules/ \
  --remove-slow-rules \
  --slow-rule-threshold-ms 10 \
  --remove-slow-rule-levels suspicious

# Remove only slow low/medium severity rules
cargo run --release -- ./samples --recursive --rules rules/ \
  --remove-slow-rules \
  --slow-rule-threshold-ms 10 \
  --remove-slow-rule-levels low,medium
```

Options:

- `--remove-slow-rules`: enable slow-rule deletion mode
- `--slow-rule-threshold-ms N`: select rules at or above this runtime threshold
- `--remove-slow-rule-metric max|avg`: choose slowest single evaluation or average runtime
- `--remove-slow-rule-levels ...`: filter by severity/verdict; default is `all`
- `--remove-slow-rules-dry-run`: preview removals without writing files
- `--remove-slow-rules-no-backup`: skip `.bak` backup creation

Like false-positive removal, slow-rule removal rewrites only the external Yamdle/YAML files passed with `--rules`. It never touches built-in rules because this build has no built-in rules.


## Optimization pass in 0.1.4

This build removes several hot-path costs from the scanner:

- Rule regexes are cached/warmed when YAML packs are loaded instead of recompiling during every file scan.
- Hex byte patterns are cached/warmed once and reused across files.
- Case-insensitive string/import/DLL matching uses one per-file lowercase index instead of lowercasing every string for every rule.
- Rule logic now short-circuits: `any` stops on the first matching condition, `all` stops on the first failed condition, and `threshold` stops as soon as the threshold can/cannot be reached.
- Byte-pattern scanning uses an exact-byte anchor when available instead of checking every full window first.
- The raw file buffer is moved into the rule engine without cloning the whole file.
- XOR decoded-string extraction reuses one buffer across keys instead of allocating 255 buffers per candidate string.

Fast raw-signature scan example:

```bash
hydradragonstatic sample.exe --rules rules/ --no-decode --min-string-len 8 --stop-on-detection
```

Large rule pack against one file:

```bash
hydradragonstatic sample.exe --rules rules/ --parallel-rules --rule-threads 8 --no-decode
```

Large sample directory:

```bash
hydradragonstatic ./samples --recursive --rules rules/ --no-parallel-files --parallel-rules --rule-threads 8
```

## Native Yamdle God Mode / registry sabotage packs

This version includes optional example signature packs under `examples/signatures/`. They are not built in and are not auto-loaded.

```bash
cargo run --release -- suspicious.bat \
  --rules examples/signatures/god_mode_iddqd_yamdle.yaml \
  --rules examples/signatures/windows_registry_sabotage_yamdle.yaml
```

New `native_signature` atom modifiers:

- `xor: true`, `xor_min`, `xor_max`
- `base64: true`
- `base64wide: true`
- raw `ascii` / `wide` matching
- byte pattern XOR matching for `kind: bytes`

The registry sabotage pack detects strings/templates related to:

- Windows Defender/AV disable and tamper-protection changes
- third-party AV self-protection disable values
- IFEO `Debugger` hijack with `taskkill`/`systray` payloads
- Task Manager/CMD/Regedit/MMC/Event Viewer/MSCONFIG lockdown
- SafeBoot/recovery/crash-dump sabotage
- Run/RunServices/RunOnceEx persistence
- raw disk access such as `\\.\PhysicalDrive0` / `PhysicalDrive` / `DeviceIoControl`

Reminder: there are still no built-in rules. Pass the pack explicitly with `--rules`.

## File-type filtering and native classification

This build adds native file-type classification and pre-scan filtering:

```bash
hydradragonstatic ./samples --recursive --rules rules/ --include-type pe,elf,macho
hydradragonstatic ./samples --recursive --rules rules/ --include-type apk,jar,zip --exclude-type text
hydradragonstatic ./samples --recursive --rules rules/ --include-type text,script,powershell,batch
```

The classifier identifies PE/PE32/PE64, ELF/ELF32/ELF64, Mach-O, APK, ZIP/archive, 7z, RAR, gzip, tar, JAR, DEX, Java class, PDF, Office/OLE compound files, plain text and script-like files. It also reports broken executable magic such as broken PE/ELF/Mach-O/APK. JSON output now includes `file_type` plus feature fields like `file_type_primary`, `file_type_tags`, `is_pe`, `is_apk`, `is_plain_text`, `is_archive`, and `is_broken_executable`.

Yamdle rules can also scope conditions by type:

```yaml
conditions:
  - type: file_type
    values: [pe, elf, macho]
```

No built-in rules are loaded; file-type rules only run when supplied through `--rules`.
