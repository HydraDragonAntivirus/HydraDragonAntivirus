use hydradragonclamav::{Engine, ScanOptions};

/// Extended bodies whose selective literal follows a bounded gap (the Virut
/// shape) are verified from that literal's occurrences. Every occurrence must
/// count, overlapping ones included: here `8a8a` matches only at the second of
/// the overlapping `8a8a8a` positions.
#[test]
fn post_gap_literal_uses_overlapping_occurrences() {
    let mut files = std::collections::HashMap::new();
    files.insert(
        "t.ndb".to_string(),
        b"Virut.Like:0:*:e8??000000{-50}8a8a(90|91){-15}ffe2\n".to_vec(),
    );
    let e = Engine::from_bytes_map(&files).0;
    let names = |d: &[u8]| e.scan_bytes(d, ScanOptions::default()).into_iter().map(|m| m.name).collect::<Vec<_>>();

    let mut hit = vec![0x41u8; 64];
    hit.extend_from_slice(&[0xe8, 0x11, 0, 0, 0, 0x55, 0x8a, 0x8a, 0x8a, 0x90, 0x33, 0xff, 0xe2]);
    hit.extend_from_slice(&[0x41; 64]);
    assert_eq!(names(&hit), ["Virut.Like"]);

    // Literal present but the gap bound exceeded: no match.
    let mut far = vec![0xe8, 0x11, 0, 0, 0];
    far.extend_from_slice(&[0x55; 60]);
    far.extend_from_slice(&[0x8a, 0x8a, 0x90, 0xff, 0xe2]);
    assert!(names(&far).is_empty());
}
