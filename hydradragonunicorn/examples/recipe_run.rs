//! Runs the unpacker signatures of a rule file on one file and prints what came out:
//! the rule that matched, the payloads or why the recipe failed, and the values its
//! `iocs` steps extracted (C2 hosts, URLs, paths).
//!
//! `recipe_run <unpack_rules.yaml> <file>`

use hydradragonunicorn::unpacker::plan::{Budget, Outcome, UnpackRules};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: recipe_run <unpack_rules.yaml> <file>");
        std::process::exit(2);
    }
    // An unpacker signature file, else a hydradragonsig rule file (its `unpack:` keys).
    let rules = UnpackRules::from_file(std::path::Path::new(&args[1]))
        .or_else(|e| {
            let text = std::fs::read_to_string(&args[1]).map_err(|_| e.clone())?;
            match UnpackRules::from_sig_yaml_str(&text) {
                Ok(r) if !r.is_empty() => Ok(r),
                Ok(_) => Err(e),
                Err(e2) => Err(format!("{e}\nas a hydradragonsig file: {e2}")),
            }
        })
        .unwrap_or_else(|e| {
            eprintln!("{}: {e}", args[1]);
            std::process::exit(2);
        });
    let data = std::fs::read(&args[2]).unwrap_or_else(|e| {
        eprintln!("{}: {e}", args[2]);
        std::process::exit(2);
    });
    let budget = Budget { max_instructions: 20_000_000, timeout_us: 20_000_000 };
    let Some(run) = rules.unpack(&data, budget) else {
        println!("no rule matches");
        return;
    };
    println!("rule: {}", run.rule);
    match &run.outcome {
        Outcome::Unpacked(p) => println!("payloads: {} ({} bytes)", p.len(), p.iter().map(Vec::len).sum::<usize>()),
        Outcome::Failed(e) => println!("failed: {e}"),
    }
    for v in &run.trace.extracted {
        println!("extracted: {v}");
    }
}
