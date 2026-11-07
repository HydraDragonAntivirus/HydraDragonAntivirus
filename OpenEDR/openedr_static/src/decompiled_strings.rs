//! The decompiler's strings of a buffer, for both of its consumers at once.
//!
//! HydraSig (`pe_strings::extract_strings`) and the PE string ML
//! (`pe_string_ml::collect_all_inner_strings`) both run `hydradragondecompiler` on the
//! same bytes (the file, or its unpacked image) with different options. Disassembling
//! the code is most of that cost, so the first of them runs one disassembly for both
//! option sets (`extract_strings_multi`, each result exactly what a separate call
//! gives) and the other takes its result from here. Keyed by the bytes' content
//! (length and a 64-bit hash), not their address: the two calls often see different
//! copies of the same data.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hydradragondecompiler::{extract_strings_multi, ExtractOptions, ExtractedString};

/// Results of both option sets for one buffer.
pub struct Decompiled {
    /// `pe_strings::extract_strings`: every pass, min length 4, at most 50 000.
    pub hydrasig: Vec<ExtractedString>,
    /// `pe_string_ml`: code refs, stack strings and opcode patterns only, min length
    /// 6, at most 10 000.
    pub string_ml: Vec<ExtractedString>,
}

pub fn hydrasig_options() -> ExtractOptions {
    ExtractOptions {
        min_len: crate::pe_strings::MIN_LEN,
        ascii: true,
        wide: true,
        code_refs: true,
        stack_strings: true,
        opcode_patterns: true,
        max_strings: 50_000,
    }
}

pub fn string_ml_options() -> ExtractOptions {
    ExtractOptions {
        min_len: crate::ml::pe_string_ml::MIN_LEN,
        ascii: false, // the string ML extracts plain strings itself, with its own alignment
        wide: false,
        code_refs: true,
        stack_strings: true,
        opcode_patterns: true,
        max_strings: 10_000,
    }
}

/// Buffers kept: a scan asks for the file and then its unpacked image.
const KEEP: usize = 4;

type Key = (usize, u64);

static CACHE: Mutex<VecDeque<(Key, Arc<Decompiled>)>> = Mutex::new(VecDeque::new());

/// A fast 64-bit hash of the whole buffer (8 bytes at a time).
fn content_hash(data: &[u8]) -> u64 {
    const K: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut h = (data.len() as u64).wrapping_mul(K);
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let w = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        h = (h ^ w).wrapping_mul(K).rotate_left(29);
    }
    for &b in chunks.remainder() {
        h = (h ^ b as u64).wrapping_mul(K).rotate_left(29);
    }
    h ^ (h >> 32)
}

/// HydraSig's strings of `data`. A PE (the PE string ML reads the same bytes
/// too) gets both option sets from one disassembly; anything else only its own, as
/// the string ML never asks for it.
pub fn hydrasig(data: &[u8]) -> Vec<String> {
    let key = (data.len(), content_hash(data));
    if let Some(hit) = cached(key) {
        return hit.hydrasig.iter().map(|s| s.text.clone()).collect();
    }
    if !looks_like_pe(data) {
        return hydradragondecompiler::extract_strings(data, &hydrasig_options()).into_iter().map(|s| s.text).collect();
    }
    both(data, key).hydrasig.iter().map(|s| s.text.clone()).collect()
}

/// The PE string ML's decompiler strings of `data` (both option sets are computed:
/// HydraSig scans the same bytes, an unpacked image after the file's features).
pub fn string_ml(data: &[u8]) -> Arc<Decompiled> {
    let key = (data.len(), content_hash(data));
    cached(key).unwrap_or_else(|| both(data, key))
}

/// `MZ` with a `PE\0\0` header where `e_lfanew` says.
fn looks_like_pe(data: &[u8]) -> bool {
    let Some(lfanew) = data.get(0x3c..0x40) else { return false };
    let at = u32::from_le_bytes([lfanew[0], lfanew[1], lfanew[2], lfanew[3]]) as usize;
    data.starts_with(b"MZ") && data.get(at..at + 4) == Some(b"PE\0\0".as_slice())
}

fn cached(key: Key) -> Option<Arc<Decompiled>> {
    let cache = CACHE.lock().ok()?;
    cache.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
}

/// Both option sets' strings of `data`, computed once per content.
pub fn of(data: &[u8]) -> Arc<Decompiled> {
    let key = (data.len(), content_hash(data));
    cached(key).unwrap_or_else(|| both(data, key))
}

fn both(data: &[u8], key: Key) -> Arc<Decompiled> {
    let mut both = extract_strings_multi(data, &[hydrasig_options(), string_ml_options()]).into_iter();
    let value = Arc::new(Decompiled { hydrasig: both.next().unwrap_or_default(), string_ml: both.next().unwrap_or_default() });
    if let Ok(mut cache) = CACHE.lock() {
        if !cache.iter().any(|(k, _)| *k == key) {
            if cache.len() >= KEEP {
                cache.pop_front();
            }
            cache.push_back((key, value.clone()));
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cached results are what the two separate calls give.
    #[test]
    fn same_as_separate_calls() {
        let path = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
        let Ok(d) = std::fs::read(path) else { return };
        let both = of(&d);
        assert_eq!(both.hydrasig, hydradragondecompiler::extract_strings(&d, &hydrasig_options()));
        assert_eq!(both.string_ml, hydradragondecompiler::extract_strings(&d, &string_ml_options()));
        // A copy of the same bytes is the same entry.
        let copy = d.clone();
        assert!(Arc::ptr_eq(&both, &of(&copy)));
    }
}
