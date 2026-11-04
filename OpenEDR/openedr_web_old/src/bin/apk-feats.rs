//! `apk-feats` — print the 24 tree-model features for one APK as JSON.
//!
//! Parity companion to `tools/apk_train.py --parity`: both must print
//! identical vectors for the same file. Compares like:
//!
//! ```sh
//! cargo run -p openedr_web --bin apk-feats -- suspicious.apk
//! python tools/apk_train.py --parity suspicious.apk
//! ```

use openedr_web::apk::{APK_TREE_FEATURE_NAMES, apk_tree_features};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: apk-feats <file.apk>");
            std::process::exit(2);
        });
    let data = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {path}: {e}");
        std::process::exit(1);
    });
    match apk_tree_features(&data) {
        Some(f) => {
            let vals: Vec<String> = f.iter().map(|v| format!("{v:.9}").trim_end_matches('0').trim_end_matches('.').to_string()).collect();
            let names: Vec<String> = APK_TREE_FEATURE_NAMES.iter().map(|s| format!("\"{s}\"")).collect();
            println!(
                "{{\"features\": [{}], \"names\": [{}]}}",
                vals.join(", "),
                names.join(", ")
            );
        }
        None => {
            println!("{{\"features\": null, \"names\": []}}");
            std::process::exit(3);
        }
    }
}
