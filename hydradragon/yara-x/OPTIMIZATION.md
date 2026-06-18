# YARA Performance Optimization

This document covers the `--perf` and `--fix-perf` features of
`YARA_Util_metadata_updater.py`: what they detect, what gets auto-fixed,
what doesn't, and why.

## Quick start

```bash
# Report-only: list perf anti-patterns, change nothing
python YARA_Util_metadata_updater.py -d ./rules --perf

# Auto-fix the safe issues, write <file>.fixed.yar next to each original
# (originals are never touched)
python YARA_Util_metadata_updater.py -d ./rules --fix-perf

# Auto-fix in place, with a .bak backup written first
python YARA_Util_metadata_updater.py -d ./rules --fix-perf --in-place
```

`--fix-perf` implies `--perf`, so you always get the full warning list
printed, regardless of which mode you use.

## Design principle: detect everything, auto-fix almost nothing

Auto-fixing a performance anti-pattern is only safe when the fix is a pure,
**semantics-preserving substitution** — something that produces an
identical match result, just faster. The moment a "fix" requires a
judgment call (how long should this regex bound be? is `nocase` actually
needed here? which alternation branch matters more?), an automated tool
can't make that call correctly. Getting it wrong means a rule silently
stops matching what it used to match, which is worse than just being slow.

So the tool is split into two tiers:

| Tier | Behavior |
|---|---|
| **Auto-fixable** | Mechanically rewritten in `--fix-perf` mode. Currently just one pattern (see below). |
| **Report-only** | Always flagged with a line number and explanation. Never rewritten — left for a human to decide on. |

## What gets auto-fixed

| Pattern | Fix | Why it's safe |
|---|---|---|
| `pe.is_pe` / `pe.is_pe()` | `uint16(0) == 0x5A4D` | Identical result for any valid PE file. `pe.is_pe` just checks the MZ magic bytes at offset 0 — that's exactly what `uint16(0) == 0x5A4D` does, except without forcing YARA to parse the entire PE structure first. There is no rule where this substitution changes behavior. |

That's the entire list today. Adding more auto-fixes to this tier should be
rare and deliberate — only patterns with the same "no possible behavior
change" property qualify.

## What's report-only (and why)

These are flagged with a line number, but never rewritten automatically:

| Pattern | Why it's flagged | Why it's not auto-fixed |
|---|---|---|
| `import "magic"` | Slow; module unavailable on Windows | Replacing it requires writing format-specific magic-byte conditions (e.g. GIF/PNG/ZIP signatures) — that's new logic, not a substitution. |
| `import "pe"` (beyond `is_pe`) | Forces a full PE parse even if you only need the MZ check | Many rules legitimately use `pe.sections`, `pe.imports()`, etc. The tool can't tell whether the import is load-bearing elsewhere in the rule. |
| `nocase` on string literals | Generates atoms for every case permutation of the matched bytes (exponential blowup on longer strings) | Whether case-insensitivity is actually required depends on what the rule targets (e.g. case-insensitive shells vs. case-sensitive binaries). Swapping to `/[Aa]ssert/`-style regex changes which bytes match — a judgment call. |
| `math.entropy(...)` | CPU-expensive; should run last in the condition, after cheap checks short-circuit | Reordering condition clauses can change which clause is "first" for short-circuit purposes in ways that depend on the rest of the rule — not a local, line-level fix. |
| `for all i in (1..filesize)` / `for any i in (1..filesize)` | Can iterate up to `filesize` times with no bound | The right guard (`filesize < 100KB`? `< 1MB`?) depends on what file types the rule targets. |
| `{00 00 00 00}` (and similar all-zero/uniform atoms) | Too common — triggers "too many matches" | There's no automatic replacement; the rule author needs to pick a more distinctive byte sequence from the actual sample. |
| `.*` / `.+` in regex strings | Greedy, unbounded — slow and prone to over-matching | The correct bound (`.{1,30}`? `.{1,3000}`?) depends on the expected distance between anchors in real samples. |
| Hex alternation, e.g. `(31 \| 33)` | Generates short atoms, slows scanning | Splitting into separate strings is mechanical *once you decide it's worth the rule-count tradeoff*, but the tool doesn't currently do this — flagged for now, may become auto-fixable later (see Roadmap). |
| Large `meta:` blocks (>20 lines) | Metadata is loaded into RAM for every scan | Stripping it is a real option (`--strip-meta` / `-O`), but it's destructive to information you may want — left as an explicit opt-in, not bundled into perf fixing. |

## Output modes

### Non-destructive (default)

```bash
python YARA_Util_metadata_updater.py -d ./rules --fix-perf
```

For every file where a safe fix was applied, writes `original.yar.fixed.yar`
next to it. The original file is **never modified**. Nothing is fixed in
files where no safe-fixable pattern was found (no `.fixed.yar` is created).

### In-place

```bash
python YARA_Util_metadata_updater.py -d ./rules --fix-perf --in-place
```

Overwrites the original file, but only after writing `original.yar.bak`
with the pre-fix content. If something looks wrong after an in-place run,
restore from the `.bak` file.

> **Note:** `--in-place` only affects files where a fix was actually
> applied. Files with zero auto-fixable issues are left untouched either
> way.

## Interaction with other flags

`--fix-perf` only touches the specific substring matched by the safe-fix
pattern (e.g. `pe.is_pe` → `uint16(0) == 0x5A4D`). It does not strip
metadata, comments, or blank lines. Combine with `--strip-meta`,
`--strip-comments`, `--strip-blank`, or `-O`/`--optimize` if you want both
perf fixes and size reduction — these operate independently and can be
used together in the same invocation.

## Example

Input:

```yara
import "pe"
rule example
{
    meta:
        description = "test"
    condition:
        pe.is_pe and
        filesize < 1000
}
```

Running `--perf`:

```
[PERF] rules/example.yar
  L1: import "pe"  → use uint16(0) == 0x5A4D for PE detection unless you need sections/directories
  L7: pe.is_pe  → use uint16(0) == 0x5A4D instead (avoids full PE parse)
```

Running `--fix-perf`:

```
[PERF] rules/example.yar
  L1: import "pe"  → use uint16(0) == 0x5A4D for PE detection unless you need sections/directories
  L7: pe.is_pe  → [FIXED] replaced with uint16(0) == 0x5A4D
  -> auto-fixed 1 safe issue(s); remaining warnings above need manual review
  -> wrote fixed copy to rules/example.yar.fixed.yar (original untouched)
```

`rules/example.yar.fixed.yar`:

```yara
import "pe"
rule example
{
    meta:
        description = "test"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1000
}
```

Note `import "pe"` is still flagged but left alone — the tool can't confirm
nothing else in the rule depends on the `pe` module.

## Roadmap (not yet implemented)

Possible future safe-fix candidates, in rough order of how mechanical they'd be:

- **Hex alternation splitting** — `{C7 C3 00 (31 | 33)}` → two separate
  strings `{C7 C3 00 31}` / `{C7 C3 00 33}` joined by `or` in the
  condition. This is mechanical for simple single-byte alternations, but
  requires rewriting both the `strings:` and `condition:` sections
  consistently, so it's a bigger change than a one-line substitution.
- **Unused-import removal** — if `import "pe"` exists but no `pe.` usage
  remains after a `pe.is_pe` fix, the import could be dropped. Requires a
  whole-rule usage scan, not just line-level matching.

Anything added here will follow the same rule as the existing fix: it only
qualifies if it cannot change what the rule matches.

## References

- [YARA-Performance-Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines) — the source guide this checker's anti-pattern list is based on (atoms, string selection, condition short-circuiting, regex quantifier bounds, module usage caveats, etc.).

