//! Read-only measurement of `threat_insights.jsonl`: how much of the append-only file is
//! stale (an older copy of a hash that has a newer line). Never writes or deletes.
//!
//! Usage: `ti_stats <path\to\threat_insights.jsonl>`

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

const KEY: &[u8] = b"\"sha256\":\"";

fn sha_of(line: &[u8]) -> Option<[u8; 64]> {
    let head = &line[..line.len().min(512)];
    let at = head.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let s = line.get(at..at + 64)?;
    s.iter().all(u8::is_ascii_hexdigit).then(|| {
        let mut out = [0u8; 64];
        out.iter_mut().zip(s).for_each(|(o, b)| *o = b.to_ascii_lowercase());
        out
    })
}

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: ti_stats <threat_insights.jsonl>");
        std::process::exit(2);
    };
    let file = File::open(&path).unwrap_or_else(|e| {
        eprintln!("cannot open {path}: {e}");
        std::process::exit(1);
    });
    let total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(1 << 20, file);

    // sha -> bytes of its newest line; every replaced line is counted as stale.
    let mut newest: HashMap<[u8; 64], u64> = HashMap::new();
    let (mut lines, mut bad, mut stale_bytes) = (0u64, 0u64, 0u64);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                lines += 1;
                match sha_of(&buf) {
                    Some(sha) => {
                        if let Some(old) = newest.insert(sha, n as u64) {
                            stale_bytes += old;
                        }
                    }
                    None => bad += 1,
                }
            }
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }
    let live_bytes: u64 = newest.values().sum();
    let gb = |b: u64| b as f64 / (1u64 << 30) as f64;
    println!("file size       : {:.2} GB", gb(total_bytes));
    println!("lines           : {lines} ({bad} without a readable sha256)");
    println!("unique hashes   : {}", newest.len());
    println!("live lines      : {:.2} GB", gb(live_bytes));
    println!("stale lines     : {:.2} GB ({:.1} % of the file)", gb(stale_bytes), 100.0 * stale_bytes as f64 / total_bytes.max(1) as f64);
    println!("avg live record : {} B", live_bytes / newest.len().max(1) as u64);
    println!("estimated SQLite size (one row per hash, ~live bytes + index): {:.2} GB", gb(live_bytes + newest.len() as u64 * 100));
}
