# Unpacker signatures (`unpack_rules/*.yaml`)

An unpacker signature says how to unpack one packer. It has two parts:

- **conditions**: hydradragonsig conditions that recognise the packer (the same
  `pe_section`, `pe_anchor_pattern`, `unpacker_any`, `byte_pattern`, ... as a
  detection rule, with `logic` / `threshold`). See hydradragonsig `FORMAT.md`.
- **unpack**: the steps that unpack it, run in order on the emulated program.

The header only picks the recipe. Every `run_until` must really happen in the
emulation. If it doesn't (the budget runs out, the program exits or faults, or
an API stops it first), the recipe fails and the caller falls back to its generic
emulation. A fake .NET header over native code, or a packer variant the recipe
does not know, therefore never gets a wrong result.

Rules are tried in file order; the first one whose conditions match runs. The
built-in rules (`unpack_rules/default.yaml`) are compiled in.
`UnpackRules::builtin_with_file` adds a file on top: a rule with an existing `id`
replaces it, and new ids are tried before the built-in ones.

```yaml
version: 1
rules:
  - id: upx
    description: UPX, tail jump into the decompressed UPX0
    logic: any
    conditions:
      - {type: pe_section, name: UPX0}
      - {type: pe_section, name: UPX1}
    unpack:
      - run_until: {write_execute: true, outside: [UPX1], max_instructions: 100000000}
      - set_oep: ip
      - dump
```

## Steps

| step | meaning |
|---|---|
| `run_until: {...}` | Emulate from the current instruction until one of the conditions holds. The run stops **before** that instruction. |
| `set_oep: ip` / `set_oep: {rva: 0x1234}` | Set the instruction pointer: the entry point the dump gets. `ip` keeps where the last `run_until` stopped. |
| `dump` | Dump the memory image: entry point = instruction pointer, imports rebuilt from the API stubs. |
| `decompile` | Managed (.NET IL) or script code: static analysis of the file (hydradragondecompiler). |
| `extract` | A container hydradragonextractor opens. When it extracts nothing, the caller emulates instead. |

A recipe ends with exactly one of `dump`, `decompile` or `extract`, as its last step.

### `run_until` keys

At least one condition is required. Any condition that holds stops the run.

| key | stops when |
|---|---|
| `write_execute: true` | Code runs from a page this run wrote (the decompressed / decrypted payload). |
| `api: [_CorExeMain]` | One of these APIs is called (stop at its stub, before the call). Names are matched without leading `_`, `@n` or DLL prefix, case-insensitive. |
| `section: [.text]` | Execution enters one of these sections. |
| `ip_pattern: ["61 E9"]` | A basic block starts with one of these hex patterns (`??` = any byte). |

Other keys:

| key | meaning |
|---|---|
| `outside: [UPX1]` | No condition stops inside these sections (the stub's own, which often writes and runs its own code first). |
| `max_instructions` | Instruction budget of this step (default: the caller's, 20M in the scanner). |
| `timeout_ms` | Time limit of this step (default: the caller's, 20 s in the scanner). |
