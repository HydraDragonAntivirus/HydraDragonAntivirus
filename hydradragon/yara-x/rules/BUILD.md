# YARA-X Rules Build

## Pipeline

```
original-*.yar  ──►  *.yar  ──►  yr fmt  ──►  yr compile  ──►  .yrc
                    ▲              ▲
                    copy      .yara-x.toml
```

## Steps

1. **Copy to fmt/** – `copy *.yar fmt\`

2. **Format** – `yr fmt fmt\*.yar` (uses `.yara-x.toml` in CWD)

3. **Compile** – `yr compile fmt\*.yar --output compiled\`
Note: Or use my own compiler if yr.exe not compatiable with antivirus.

## Config (`.yara-x.toml`)

- `rule.indent_section_headers = true`
- `rule.indent_section_contents = true`
- `rule.indent_spaces = 2`
- `meta.align_values = false`
- `patterns.align_values = false`
