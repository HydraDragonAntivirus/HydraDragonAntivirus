use hydradragonclamav::{Engine, ScanOptions};

/// ClamAV runs every Target:0 signature on data of a type it cannot name
/// (CL_TYPE_BINARY_DATA); type-specific ones stay off it. OLE2 / Mach-O / Java
/// files are typed so their own targets apply. Compiled rule files are not
/// scanned raw (they contain every string the signatures look for).
fn engine() -> Engine {
    let mut files = std::collections::HashMap::new();
    files.insert(
        "t.ndb".to_string(),
        b"Any.T0:0:*:4142434445464748494a\nOle.T2:2:*:4142434445464748494a\nPe.T1:1:*:4142434445464748494a\nMacho.T9:9:*:4142434445464748494a\nJava.T12:12:*:4142434445464748494a\n".to_vec(),
    );
    Engine::from_bytes_map(&files).0
}

fn names(e: &Engine, data: &[u8]) -> Vec<String> {
    let mut n: Vec<String> = e.scan_bytes(data, ScanOptions::default()).into_iter().map(|m| m.name).collect();
    n.sort();
    n
}

fn with(header: &[u8]) -> Vec<u8> {
    let mut d = header.to_vec();
    d.extend_from_slice(b" ABCDEFGHIJ ");
    d
}

#[test]
fn unknown_binary_gets_target_zero_only() {
    let e = engine();
    assert_eq!(names(&e, &with(b"xx\xde\xad\xbe\xef")), ["Any.T0"]);
}

#[test]
fn ole2_macho_java_are_typed() {
    let e = engine();
    assert_eq!(names(&e, &with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])), ["Any.T0", "Ole.T2"]);
    assert_eq!(names(&e, &with(&[0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1])), ["Any.T0", "Macho.T9"]);
    assert_eq!(names(&e, &with(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52])), ["Any.T0", "Java.T12"]);
    // CAFEBABE with a small arch count is a Mach-O universal binary: a container, untyped.
    assert_eq!(names(&e, &with(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2])), ["Any.T0"]);
}

#[test]
fn compiled_rules_are_not_scanned_raw() {
    let e = engine();
    assert!(names(&e, &with(b"YARA-X\0\0\x07\0\0\0")).is_empty());
    assert!(names(&e, &with(b"ClamAV-VDB:03 Nov 2026")).is_empty());
}
