use owlyshield_ransom::ml::kc_predict::{extract_features, label_event, KcHybridModel, KcVerdict};
use std::collections::HashMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let jsonl = if args.len() > 1 {
        args[1].clone()
    } else {
        r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\data\unknown_killchain_20260912.jsonl".to_string()
    };
    let model_path = if args.len() > 2 {
        args[2].clone()
    } else {
        r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenEDR\owlyshield_predict\models\kc_hybrid_model.json".to_string()
    };

    println!("[*] Loading hybrid model from: {}", model_path);
    let model = KcHybridModel::load_json(&model_path).expect("cannot load kc_hybrid_model.json");
    println!("[+] Hybrid model loaded successfully!");

    println!("[*] Evaluating telemetry events from: {}", jsonl);
    let text = std::fs::read_to_string(&jsonl).expect("cannot read jsonl");

    let mut count_benign = 0usize;
    let mut count_malicious = 0usize;
    let mut count_hips = 0usize;
    let mut total = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let o: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let raw = o.get("raw").cloned().unwrap_or(serde_json::Value::Null);
        let event = o.get("event").and_then(|v| v.as_str()).unwrap_or("?");
        let details = o.get("details").and_then(|v| v.as_str()).unwrap_or("");

        let feats = extract_features(event, details, &raw, None);
        let verdict = model.evaluate(&feats);

        match verdict {
            KcVerdict::Benign { .. } => count_benign += 1,
            KcVerdict::Malicious { .. } => count_malicious += 1,
            KcVerdict::UnknownToHips { .. } => count_hips += 1,
        }
        total += 1;
    }

    println!("\n=== Rust In-Process Hybrid Killchain Evaluation ===");
    println!("Total Evaluated Events: {}", total);
    println!("  -> Clean / White List: {} ({:.1}%)", count_benign, (count_benign as f64 / total as f64) * 100.0);
    println!("  -> Malware / Quarantine: {} ({:.1}%)", count_malicious, (count_malicious as f64 / total as f64) * 100.0);
    println!("  -> Unknown / Forward to HIPS: {} ({:.1}%)", count_hips, (count_hips as f64 / total as f64) * 100.0);
    println!("[+] Tri-State Killchain Engine is fully operational!");
}
