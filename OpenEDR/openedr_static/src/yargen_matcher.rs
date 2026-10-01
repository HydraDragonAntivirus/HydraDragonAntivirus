//! High-Performance YarGen String Signature Engine powered by daachorse 5.0.0 & BinaryFuse16 XOR Filter
//!
//! - Malicious Patterns: daachorse DoubleArrayAhoCorasick (linear single-pass substring search)
//! - Benign Patterns: BinaryFuse16 XOR Filter (`benign_strings.xf`, 4.9MB for 2.18M keys, O(1) lookup)
//! - "Goodware Wins" logic: any match found in the benign XOR filter is dropped immediately.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use daachorse::DoubleArrayAhoCorasick;
use crate::signers::BinaryFuse16Filter;

pub struct YarGenMatcher {
    mal_automaton: Option<DoubleArrayAhoCorasick<u32>>,
    ben_filter: Option<BinaryFuse16Filter>,
    mal_count: usize,
    ben_count: usize,
}

impl YarGenMatcher {
    pub fn empty() -> Self {
        Self {
            mal_automaton: None,
            ben_filter: None,
            mal_count: 0,
            ben_count: 0,
        }
    }

    pub fn from_dir(dir: &Path) -> Self {
        if !dir.is_dir() {
            return Self::empty();
        }

        let mal_path = dir.join("malicious_strings.txt");
        let ben_xf_path = dir.join("benign_strings.xf");

        // 1. Load Malicious strings into daachorse
        let mut mal_patterns = Vec::new();
        if let Ok(file) = File::open(&mal_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.len() >= 6 {
                    mal_patterns.push(trimmed.to_ascii_lowercase());
                }
            }
        }

        let mal_count = mal_patterns.len();
        let mal_automaton = if !mal_patterns.is_empty() {
            DoubleArrayAhoCorasick::new(&mal_patterns).ok()
        } else {
            None
        };

        // 2. Load Benign strings from BinaryFuse16 XOR filter (.xf)
        let ben_filter = if let Ok(bytes) = std::fs::read(&ben_xf_path) {
            BinaryFuse16Filter::from_bytes(&bytes)
        } else {
            None
        };
        let ben_count = ben_filter.as_ref().map(|f| f.len()).unwrap_or(0);

        Self {
            mal_automaton,
            ben_filter,
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

    /// Evaluates raw buffer against malicious daachorse automaton and suppresses hits using benign XOR filter.
    /// Returns (clean_mal_hits, suppressed_hits, sample_evidence).
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

        let mut clean_mal_hits = 0usize;
        let mut suppressed_hits = 0usize;
        let mut evidence = Vec::new();

        if let Some(ref mal_ac) = self.mal_automaton {
            for m in mal_ac.find_overlapping_iter(&lower_buf) {
                if let Ok(matched_str) = std::str::from_utf8(&lower_buf[m.start()..m.end()]) {
                    // Check against benign BinaryFuse16 XOR filter
                    if let Some(ref ben_xf) = self.ben_filter {
                        if ben_xf.contains(matched_str) {
                            suppressed_hits += 1;
                            continue; // Whitelist wins!
                        }
                    }

                    clean_mal_hits += 1;
                    if evidence.len() < 3 && !evidence.contains(&matched_str.to_string()) {
                        evidence.push(matched_str.to_string());
                    }
                }
            }
        }

        (clean_mal_hits, suppressed_hits, evidence)
    }
}
