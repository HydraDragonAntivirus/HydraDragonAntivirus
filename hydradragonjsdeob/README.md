# JS-Deobfuscator

Universal JavaScript deobfuscator built on [OXC](https://oxc.rs). Handles string encoding, control flow flattening, constant obfuscation, proxy functions, and string array rotation — layer by layer.

## Install

```bash
cargo install --path .
```

## CLI Usage

```bash
# File input
deob input.js -o output.js --stats

# Stdin
cat input.js | deob > output.js

# With global context
deob input.js --globals '{"window":{"secret":"abc123"}}'

# Disable transforms
deob input.js --no-fold        # skip static folding
deob input.js --no-transforms  # skip semantic transforms
```

## Library Usage

```rust
use js_deobfuscator::engine::api::JSDeobfuscator;

let result = JSDeobfuscator::new()
    .deobfuscate("var x = 1 + 2; console.log(x);")?;

assert!(result.code.contains("console.log(3)"));
assert!(result.converged);
```

### With options

```rust
let result = JSDeobfuscator::new()
    .max_iterations(100)
    .global("window", serde_json::json!({"key": "value"}))
    .deobfuscate(&source)?;
```

### Custom modules

```rust
use js_deobfuscator::engine::module::Module;

struct MyTransform;
impl Module for MyTransform { /* ... */ }

let result = JSDeobfuscator::new()
    .add_common(Box::new(MyTransform))  // runs in convergence loop
    .add_locked(Box::new(MyLockedPass)) // runs once after convergence
    .deobfuscate(&source)?;
```

## What It Does

| Transform | Example |
|-----------|---------|
| Constant folding | `1 + 2` → `3` |
| String concat | `"hello" + " world"` → `"hello world"` |
| Built-in methods | `Math.floor(1.7)` → `1`, `atob("SGVsbG8=")` → `"Hello"` |
| Typeof/void/not | `typeof "x"` → `"string"`, `!0` → `true` |
| Ternary | `true ? a : b` → `a` |
| Logical short-circuit | `false \|\| x` → `x` |
| Constant propagation | `var x = 5; f(x)` → `f(5)` |
| Alias inlining | `var e = Yp; e(1)` → `Yp(1)` |
| Proxy inlining | `function f(a,b){return g(b,a)} f(1,2)` → `g(2,1)` |
| Object resolution | `var t={F:445}; t.F` → `445` |
| Member simplification | `obj["key"]` → `obj.key` |
| Dead code elimination | `if(false){...}` → removed |
| Global injection | `window.secret` → `"abc123"` (user-provided) |
| String array decoding | obfuscator.io rotation pattern → decoded strings |
| Statement splitting | `var a=1, b=2` → `var a=1; var b=2;` |
| Brace wrapping | `if(x) return 1` → `if(x) { return 1; }` |

## Architecture

Layer-by-layer, each depends only on layers below:

```
value/      ← Pure JS computation (no OXC)
ast/        ← OXC AST helpers (zero-copy extraction)
scope/      ← Symbol resolution (wraps OXC Scoping)
fold/       ← Static expression folding (operators, builtins, methods)
eval/       ← Dynamic evaluation (Node.js subprocess, optional)
transform/  ← Semantic transforms (propagation, inlining, dead code)
engine/     ← Convergence loop + public API
format/     ← Output normalization
```

Two-phase convergence: common modules loop until stable, locked modules run once and restart if they make changes.

## Dependencies

- **OXC v0.124.0** — parser, AST, semantic analysis, codegen
- **No embedded V8** — Node.js subprocess for dynamic eval (optional)
- **230 tests**, clippy clean

## License

Apache-2.0
