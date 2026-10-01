//! High-Performance yarGen String Signature Engine powered by daachorse 5.0.0
//!
//! Loads `malicious_strings.txt` and `benign_strings.txt` from the `yargen_strings/` folder.
//! Uses DoubleArrayAhoCorasick for microsecond-level linear buffer scanning.
//! Applies "Goodware Wins" collision logic: benign hits suppress false positives.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use daachorse::DoubleArrayAhoCorasick;

pub struct YarGenMatcher {
    mal_automaton: Option<DoubleArrayAhoCorasick<u32>>,
    ben_automaton: Option<DoubleArrayAhoCorasick<u32>>,
    mal_count: usize,
    ben_count: usize,
}

impl YarGenMatcher {
    pub fn empty() -> Self {
        Self {
            mal_automaton: None,
            ben_automaton: None,
            mal_count: 0,
            ben_count: 0,
        }
    }

    pub fn from_dir(dir: &Path) -> Self {
        if !dir.is_dir() {
            return Self::empty();
        }

        let mal_path = dir.join("malicious_strings.txt");
        let ben_path = dir.join("benign_strings.txt");

        let load_lines = |path: &Path| -> Vec<String> {
            let mut out = Vec::new();
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if trimmed.len() >= 6 {
                        out.push(trimmed.to_ascii_lowercase());
                    }
                }
            }
            out
        };

        let mal_patterns = load_lines(&mal_path);
        let ben_patterns = load_lines(&ben_path);

        let mal_count = mal_patterns.len();
        let ben_count = ben_patterns.len();

        let mal_automaton = if !mal_patterns.is_empty() {
            DoubleArrayAhoCorasick::new(&mal_patterns).ok()
        } else {
            None
        };

        let ben_automaton = if !ben_patterns.is_empty() {
            DoubleArrayAhoCorasick::new(&ben_patterns).ok()
        } else {
            None
        };

        Self {
            mal_automaton,
            ben_automaton,
            mal_count,
            ben_count,
        }
    }

    #[inline]
    pub fn is_loaded(&self) -> bool {
        self.mal_automaton.is_some()
    }

    #[inline]
    pub fn signature_counts(&self) -> (usize, usize) {
        (self.mal_count, self.ben_count)
    }

    /// Evaluates raw buffer against both malicious and benign automata.
    /// Returns (mal_hits, ben_hits, sample_mal_evidence).
    pub fn scan_buffer(&self, data: &[u8]) -> (usize, usize, Vec<String>) {
        if data.is_empty() || self.mal_automaton.is_none() {
            return (0, 0, Vec::new());
        }

        // Fast ascii lowercase view (bounded to first 4MB for instant scanning)
        let scan_len = data.len().min(4 * 1024 * 1024);
        let mut lower_buf = Vec::with_capacity(scan_len);
        for &b in &data[..scan_len] {
            lower_buf.push(if b.is_ascii_uppercase() { b + 32 } else { b });
        }

        let mut ben_hits = 0usize;
        if let Some(ref ben_ac) = self.ben_automaton {
            ben_hits = ben_ac.find_overlapping_iter(&lower_buf).count();
        }

        let mut mal_hits = 0usize;
        let mut evidence = Vec::new();
        if let Some(ref mal_ac) = self.mal_automaton {
            for m in mal_ac.find_overlapping_iter(&lower_buf) {
                mal_hits += 1;
                if evidence.len() < 3 {
                    if let Ok(matched_str) = std::str::from_utf8(&lower_buf[m.start()..m.end()]) {
                        if !evidence.contains(&matched_str.to_string()) {
                            evidence.push(matched_str.to_string());
                        }
                    }
                }
            }
        }

        (mal_hits, ben_hits, evidence)
    }
}
