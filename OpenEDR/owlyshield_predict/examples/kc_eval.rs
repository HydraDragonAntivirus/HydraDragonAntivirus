//! Killchain centroid parity eval: same clean jsonl through the Rust feature
//! pipeline, scores compared one-to-one with the Python trainer.
//!
//! Run: cargo run --release --example kc_eval -- <jsonl> <models_dir>

use owlyshield_ransom::ml::kc_predict::{extract_features, label_event, KcModel};
use std::collections::HashMap;

fn num_i64(v: &serde_json::Value) -> Option<i64> {
    if let Some(i) = v.as_i64() {
        return Some(i);
    }
    if let Some(u) = v.as_u64() {
        return i64::try_from(u).ok();
    }
    if let Some(x) = v.as_f64() {
        if x.fract() == 0.0 && x >= i64::MIN as f64 && x <= i64::MAX as f64 {
            return Some(x as i64);
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: kc_eval <killchain.clean.jsonl> <models_dir>");
        eprintln!("example: kc_eval unknown_killchain_20260912.clean.jsonl models");
        std::process::exit(2);
    }
    let jsonl = args[1].clone();
    let models = args[2].clone();

    let model =
        KcModel::load_json(&format!("{models}/kc_model.json")).expect("cannot load kc_model.json");
    println!(
        "[+] model: {} features, threshold={}",
        model.n_features(),
        model.threshold()
    );

    let py_scores: Vec<f64> = {
        let t = std::fs::read_to_string(format!("{models}/scores_py.json"))
            .expect("scores_py.json missing (run the trainer export)");
        serde_json::from_str(&t).expect("scores_py.json corrupt")
    };

    let text = std::fs::read_to_string(&jsonl).expect("cannot read jsonl");
    let mut last_tick: HashMap<String, i64> = HashMap::new();
    let (mut tp, mut tn, mut fp, mut fny) = (0u64, 0u64, 0u64, 0u64);
    let mut max_diff = 0f64;
    let mut n = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let o: serde_json::Value = serde_json::from_str(line).expect("corrupt line");
        let raw = o.get("raw").cloned().unwrap_or(serde_json::Value::Null);
        let event = o.get("event").and_then(|v| v.as_str()).unwrap_or("?");
        let details = o.get("details").and_then(|v| v.as_str()).unwrap_or("");
        let exe = o.get("exe").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let dt: Option<i64> = num_i64(raw.get("tickTime").unwrap_or(&serde_json::Value::Null))
            .and_then(|t| {
                let prev = last_tick.insert(exe.clone(), t);
                prev.map(|p| t - p)
            });

        let feats = extract_features(event, details, &raw, dt);
        let s = model.score(&feats) as f64;
        let y = label_event(&exe, &raw);
        let pred = model.predict(&feats);
        match (y, pred) {
            (1, 1) => tp += 1,
            (0, 0) => tn += 1,
            (0, 1) => fp += 1,
            _ => fny += 1,
        }
        if n < py_scores.len() {
            let d = (s - py_scores[n]).abs();
            if d > max_diff {
                max_diff = d;
            }
        }
        n += 1;
    }

    let acc = (tp + tn) as f64 / n as f64;
    println!("[+] events: {n}  TP={tp} TN={tn} FP={fp} FN={fny}  acc={acc:.4}");
    // f32 vs f64 accumulation over ~765 dims: allow small relative tolerance.
    let rel = if max_diff > 0.0 { max_diff } else { 0.0 };
    println!("[+] parity max|score_rust - score_py| = {rel:.2e}");
    if rel < 5e-2 {
        println!("[+] PARITY OK: burn output matches the trainer");
    } else {
        println!("[!] PARITY BROKEN: feature extraction differs, check the port");
    }
}
