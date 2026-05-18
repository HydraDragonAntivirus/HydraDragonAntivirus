/// Shannon entropy in bits per byte.
///
/// Returned range is 0.0..=8.0 for byte buffers:
/// - 0.0 means every byte is identical
/// - 8.0 is the theoretical maximum for uniformly random bytes
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in counts.into_iter().filter(|c| *c > 0) {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Alias used by the scanner/rules. This intentionally returns bits/byte,
/// not a normalized 0.0..1.0 score.
pub fn byte_entropy(bytes: &[u8]) -> f64 {
    shannon_entropy(bytes)
}
