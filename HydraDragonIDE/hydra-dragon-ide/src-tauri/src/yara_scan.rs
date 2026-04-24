// src-tauri/src/yara_scan.rs
// YARA-X rule compilation and scanning.
// Returns per-byte annotations so the hex view can colour matches.

use yara_x;
use crate::state::YaraHit;

/// Compile `rules_source` and scan `data`.
/// Returns a flat list of all pattern match ranges.
pub fn scan(data: &[u8], rules_source: &str) -> Result<Vec<YaraHit>, String> {
    // ── Compile ──────────────────────────────────────────────────────────────
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(rules_source)
        .map_err(|e| format!("YARA compile error: {e}"))?;

    let rules = compiler.build();

    // ── Scan ─────────────────────────────────────────────────────────────────
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .map_err(|e| format!("YARA scan error: {e}"))?;

    let mut hits = Vec::new();

    for matching_rule in results.matching_rules() {
        let rule_name = matching_rule.identifier().to_string();
        let namespace  = matching_rule.namespace().to_string();

        for pattern in matching_rule.patterns() {
            let pattern_name = pattern.identifier().to_string();

            for m in pattern.matches() {
                let range = m.range();
                hits.push(YaraHit {
                    rule_name:    rule_name.clone(),
                    namespace:    namespace.clone(),
                    pattern_name: pattern_name.clone(),
                    offset: range.start,
                    length: range.end - range.start,
                });
            }
        }
    }

    Ok(hits)
}

/// Build a per-byte lookup: `byte_index → Option<rule_name>`.
/// For a slice `data[offset .. offset+len]`.
pub fn hit_mask_for_slice(
    hits: &[YaraHit],
    slice_offset: usize,
    slice_len: usize,
) -> Vec<Option<String>> {
    let mut mask: Vec<Option<String>> = vec![None; slice_len];

    for hit in hits {
        let hit_end = hit.offset + hit.length;
        // Intersect [hit.offset, hit_end) with [slice_offset, slice_offset+slice_len)
        let start = hit.offset.max(slice_offset);
        let end   = hit_end.min(slice_offset + slice_len);

        if start < end {
            for i in start..end {
                let rel = i - slice_offset;
                if mask[rel].is_none() {
                    mask[rel] = Some(hit.rule_name.clone());
                }
            }
        }
    }

    mask
}
