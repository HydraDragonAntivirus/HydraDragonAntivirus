# !include Feature for HydraDragonSig

## Overview

The `!include` feature allows you to organize your detection rules across multiple YAML files. This is particularly useful for:

- **Separating private and public rules**: Keep private detection logic separate from open-source rules
- **Conditional rule loading**: Choose which rule sets to include based on your deployment scenario
- **Modular organization**: Group rules by category, threat type, or severity
- **Easier maintenance**: Update specific rule sets without modifying the main file
- **Reusability**: Share common rule sets across different configurations

## Usage

### Basic Syntax

In your main YAML rule file, use the `!include` directive to reference other rule files:

```yaml
# Main rule file
- !include private_rules.yaml
- !include open_rules.yaml
- !include malware_signatures.yaml
```

### Relative Paths

Include paths are resolved relative to the directory containing the file with the `!include` directive:

```yaml
# Include from subdirectory
- !include rules/private/custom_detections.yaml

# Include from parent directory
- !include ../shared_rules.yaml
```

### Mixed Content

You can combine `!include` directives with direct rule definitions in the same file:

```yaml
# Include external rules
- !include private_rules.yaml

# Define rules directly
rules:
  - name: "DirectRule"
    description: "A rule defined in this file"
    level: "high"
    signature:
      - kind: "native"
        expression: "pe.is_pe and filesize > 1MB"
```

## Private vs Open Rules Use Case

A common use case is to maintain separate rule files for private and open (public) rules:

### Open Rules Only (Default)

**main_rules_open_only.yaml:**
```yaml
# Only include public/open-source rules
- !include open_rules.yaml
```

Use this for:
- Public releases
- Community distributions
- Open-source deployments

```bash
cargo run --release -- sample.exe --rules main_rules_open_only.yaml
```

### With Private Rules (Full Detection)

**main_rules_with_private.yaml:**
```yaml
# Include both private and open rules
- !include private_rules.yaml
- !include open_rules.yaml
```

Use this for:
- Internal/enterprise deployments
- Full detection capability with private signatures
- Commercial products

```bash
cargo run --release -- sample.exe --rules main_rules_with_private.yaml
```

### Direct Private Rules (No Main File)

You can also load private rules directly without a main file:

```bash
# Only private rules
cargo run --release -- sample.exe --rules private_rules.yaml

# Multiple rule files
cargo run --release -- sample.exe --rules private_rules.yaml --rules open_rules.yaml
```

## Example Structure

```
rules/
├── main_rules_open_only.yaml      # Public deployment (no private rules)
├── main_rules_with_private.yaml   # Full deployment (with private rules)
├── private_rules.yaml             # Private detection rules (not included by default)
├── open_rules.yaml                # Public/open-source rules
└── categories/
    ├── ransomware.yaml
    ├── trojans.yaml
    └── packers.yaml
```

**Workflow:**
1. Develop and test with `main_rules_with_private.yaml` (full detection)
2. Deploy to public/community with `main_rules_open_only.yaml` (no private rules)
3. Keep `private_rules.yaml` in a separate repository or secure location

## Features

### Recursive Loading
The `!include` feature supports nested includes. An included file can itself include other files:

**main.yaml:**
```yaml
- !include all_categories.yaml
```

**all_categories.yaml:**
```yaml
- !include categories/ransomware.yaml
- !include categories/trojans.yaml
- !include categories/packers.yaml
```

### Circular Include Protection
The implementation includes protection against circular includes with a maximum recursion depth of 20 levels.

### Error Handling
- If an included file doesn't exist, a warning is printed and loading continues
- If an included file has syntax errors, the error is reported and loading continues
- The main rule loading process won't fail due to a single bad include

## Loading Rules with Includes

When using the Rust API:

```rust
use hydradragonsig::rules::RuleSet;
use std::path::Path;

// Load rules with automatic include processing
let rules = RuleSet::from_yaml_file(Path::new("main_rules_with_includes.yaml"))?;

// All included rules are merged into a single RuleSet
println!("Loaded {} rules total", rules.rules().len());
```

## Best Practices

1. **Separate private from public**: Keep private rules in separate files that are not included by default
2. **Use descriptive names**: Name include files clearly (e.g., `private_apt_signatures.yaml`, `open_generic_malware.yaml`)
3. **Document includes**: Add comments explaining what each include provides
4. **Version control separately**: Consider keeping private rules in a separate repository
5. **Avoid deep nesting**: Keep include hierarchies shallow for maintainability
6. **Test both configurations**: Verify both open-only and with-private configurations work correctly

## Example Files

This directory contains example files demonstrating the `!include` feature:

- **main_rules_open_only.yaml**: Main file with only open/public rules (no private rules)
- **main_rules_with_private.yaml**: Main file with both private and open rules
- **private_rules.yaml**: Example private rules (not included by default)
- **open_rules.yaml**: Example public/open-source rules

### Try the Examples

**Open rules only (no private detections):**
```bash
cargo run --release -- sample.exe --rules examples/main_rules_open_only.yaml
```

**Full detection with private rules:**
```bash
cargo run --release -- sample.exe --rules examples/main_rules_with_private.yaml
```

**Direct private rules:**
```bash
cargo run --release -- sample.exe --rules examples/private_rules.yaml
```

## Compatibility

The `!include` feature is compatible with the behavior engine's include syntax, allowing consistent rule organization across both static and behavioral detection engines.

## Security Considerations

When deploying with private rules:

1. **Access Control**: Ensure private rule files have appropriate file permissions
2. **Distribution**: Don't include private rules in public releases or repositories
3. **Backup**: Keep secure backups of private rule files
4. **Version Control**: Use separate repositories for private and open rules
5. **Documentation**: Document which rules are private vs open for your team
