//! Times each pass of `extract_strings` on the files given (to see which one costs).
use hydradragondecompiler::{extract_strings, ExtractOptions};
use std::time::Instant;

fn main() {
    for f in std::env::args().skip(1) {
        let d = std::fs::read(&f).unwrap();
        let base = ExtractOptions { min_len: 4, ascii: false, wide: false, code_refs: false, stack_strings: false, opcode_patterns: false, max_strings: 10_000 };
        let mut line = format!("{} ({} B):", &f[f.len().saturating_sub(20)..], d.len());
        for (name, o) in [
            ("none", base.clone()),
            ("code_refs", ExtractOptions { code_refs: true, ..base.clone() }),
            ("stack", ExtractOptions { stack_strings: true, ..base.clone() }),
            ("opcodes", ExtractOptions { opcode_patterns: true, ..base.clone() }),
            ("all", ExtractOptions { code_refs: true, stack_strings: true, opcode_patterns: true, ..base.clone() }),
        ] {
            let t = Instant::now();
            let n = extract_strings(&d, &o).len();
            line.push_str(&format!(" {name}={}ms/{n}", t.elapsed().as_millis()));
        }
        println!("{line}");
    }
}
