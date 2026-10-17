//! End-to-end checks of rule conditions through the public scan API.

use hydradragonsig::models::{MemoryScanContext, Verdict};
use hydradragonsig::rules::RuleSet;
use hydradragonsig::{scan_memory_owned, ScanOptions};

fn rules(body: &str) -> RuleSet {
    let set = RuleSet::from_yaml_str(&format!("rules:\n{body}")).expect("rules parse");
    assert!(set.warnings().is_empty(), "unexpected warnings: {:?}", set.warnings());
    set
}

fn scan(set: &RuleSet, data: &[u8]) -> Vec<String> {
    scan_with(set, data, ScanOptions::default())
}

fn scan_with(set: &RuleSet, data: &[u8], options: ScanOptions) -> Vec<String> {
    let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: "t".into(), base_address: None };
    let report = scan_memory_owned(ctx, set, &options).expect("scan");
    report.findings.iter().map(|f| f.rule_id.clone()).collect()
}

fn one(cond: &str) -> RuleSet {
    rules(&format!("  - id: R\n    title: t\n    severity: high\n    verdict: malware\n    conditions:\n{cond}"))
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

#[test]
fn string_regex_matches_extracted_strings() {
    let set = one("      - type: string_regex\n        pattern: 'https?://[a-z]+\\.evil/[a-z]+'\n");
    assert_eq!(scan(&set, b"\x00\x01GET http://www.evil/payload HTTP\x00"), vec!["R"]);
    assert!(scan(&set, b"\x00nothing to see\x00").is_empty());
    // UTF-16LE strings are extracted too.
    let mut data = b"\x00\x00".to_vec();
    data.extend(wide("http://abc.evil/xyz"));
    assert_eq!(scan(&set, &data), vec!["R"]);
}

#[test]
fn string_contains_default_flags_match() {
    let set = one("      - type: string_contains\n        value: 'Mimikatz'\n        nocase: true\n");
    assert_eq!(scan(&set, b"\x00\x02 by mimikatz author \x00"), vec!["R"]);
    assert!(scan(&set, b"\x00nothing\x00").is_empty());
}

#[test]
fn decoded_base64_and_hex_strings() {
    let set = one("      - type: string_contains\n        value: 'http://c2.example/gate'\n        decoded: true\n");
    // base64("download http://c2.example/gate now")
    assert_eq!(scan(&set, b"\x00ZG93bmxvYWQgaHR0cDovL2MyLmV4YW1wbGUvZ2F0ZSBub3c=\x00"), vec!["R"]);
    // hex("http://c2.example/gate")
    assert_eq!(scan(&set, b"\x00687474703a2f2f63322e6578616d706c652f67617465\x00"), vec!["R"]);
    // decoding switched off
    let options = ScanOptions { decode_obfuscated_strings: false, ..ScanOptions::default() };
    assert!(scan_with(&set, b"\x00ZG93bmxvYWQgaHR0cDovL2MyLmV4YW1wbGUvZ2F0ZSBub3c=\x00", options).is_empty());
}

#[test]
fn string_set_without_min_needs_every_value() {
    let set = one("      - type: string_set\n        values: ['alpha', 'beta']\n");
    assert!(scan(&set, b"alpha only").is_empty());
    assert_eq!(scan(&set, b"alpha and beta"), vec!["R"]);
    let set = one("      - type: string_set\n        min: 1\n        values: ['alpha', 'beta']\n");
    assert_eq!(scan(&set, b"alpha only"), vec!["R"]);
}

#[test]
fn byte_set_counts_wildcard_patterns() {
    let set = one("      - type: byte_set\n        min: 2\n        patterns: ['4D 5A', 'E8 ?? ?? ?? ?? C3']\n");
    assert_eq!(scan(&set, b"MZ\x00\xE8\x01\x02\x03\x04\xC3"), vec!["R"]);
    assert!(scan(&set, b"MZ\x00\xE8\x01\x02\xC3").is_empty());
}

#[test]
fn byte_pattern_scope_applies_to_exact_patterns() {
    let set = one("      - type: byte_pattern\n        pattern: '50 41 59'\n        scope: {start: 0, end: 8}\n");
    assert_eq!(scan(&set, b"xxPAYxxxxxxxxxxxx"), vec!["R"]);
    assert!(scan(&set, b"xxxxxxxxxxxxPAY").is_empty());
    let set = one("      - type: byte_pattern\n        pattern: '50 41 59'\n        excludes: ['42 45 4E 49 47 4E']\n");
    assert!(scan(&set, b"PAY BENIGN").is_empty());
    assert_eq!(scan(&set, b"PAY"), vec!["R"]);
}

#[test]
fn byte_pattern_jumps_alternations_negation() {
    let set = one("      - type: byte_pattern\n        pattern: '{ 4D 5A [2-4] ( 90 | 91 ) ~00 }'\n");
    assert_eq!(scan(&set, b"MZab\x90\x01"), vec!["R"]);
    assert_eq!(scan(&set, b"MZabcd\x91\x02"), vec!["R"]);
    assert!(scan(&set, b"MZa\x90\x01").is_empty(), "jump too short");
    assert!(scan(&set, b"MZab\x92\x01").is_empty(), "no alternative");
    assert!(scan(&set, b"MZab\x90\x00").is_empty(), "negated byte");
}

#[test]
fn rule_match_with_private_helpers() {
    let set = rules(
        "  - id: H1\n    title: h\n    severity: info\n    private: true\n    conditions:\n      - type: string_contains\n        value: 'alpha'\n\
         \x20 - id: H2\n    title: h\n    severity: info\n    private: true\n    conditions:\n      - type: string_contains\n        value: 'beta'\n\
         \x20 - id: R\n    title: r\n    severity: high\n    verdict: malware\n    conditions:\n      - type: rule_match\n        ids: [H1, H2]\n",
    );
    // stop_on_detection (the library default) must not stop at a private match.
    assert_eq!(scan(&set, b"alpha beta"), vec!["R"]);
    assert!(scan(&set, b"alpha only").is_empty());
}

#[test]
fn env_reference_and_features() {
    let set = one("      - type: env_reference\n        min: 1\n");
    assert_eq!(scan(&set, b"\x00copy to %APPDATA%\\run.exe\x00"), vec!["R"]);
    assert!(scan(&set, b"\x00plain text here\x00").is_empty());
    let set = one("      - type: feature_gte\n        name: string_count\n        value: 3\n");
    assert_eq!(scan(&set, b"first\x00second\x00third\x00"), vec!["R"]);
    assert!(scan(&set, b"first\x00second\x00").is_empty());
}

#[test]
fn native_offsets_see_every_occurrence() {
    let set = one("      - type: native_signature\n        expression: '$a at 16'\n        atoms:\n          - id: a\n            value: 'MARK'\n");
    let mut data = b"MARK".to_vec();
    data.resize(16, b'.');
    data.extend_from_slice(b"MARK");
    assert_eq!(scan(&set, &data), vec!["R"]);
}

#[test]
fn native_base64_any_alignment() {
    let set = one("      - type: native_signature\n        expression: 'any of them'\n        atoms:\n          - id: a\n            value: 'AmsiScanBuffer'\n            base64: true\n");
    use base64::Engine as _;
    for prefix in ["", "x", "xy"] {
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{prefix}AmsiScanBuffer!"));
        assert_eq!(scan(&set, enc.as_bytes()), vec!["R"], "prefix {prefix:?}");
    }
}

#[test]
fn verdict_and_case_insensitive_enums() {
    let set = RuleSet::from_yaml_str(
        "rules:\n  - id: R\n    title: t\n    severity: Critical\n    verdict: Malware\n    logic: ALL\n    conditions:\n      - type: string_contains\n        value: 'zzzz'\n",
    )
    .unwrap();
    let ctx = MemoryScanContext { buffer: b"aa zzzz".to_vec(), identifier: "t".into(), base_address: None };
    let report = scan_memory_owned(ctx, &set, &ScanOptions::default()).unwrap();
    assert_eq!(report.verdict, Verdict::Malware);
}

#[test]
fn load_warnings_and_strict_mode() {
    let doc = "rules:\n  - id: R\n    title: t\n    severity: low\n    sevrity: high\n    conditions:\n      - type: byte_pattern\n        pattern: '4D 5A'\n        scope: {offset: 0}\n      - type: string_regex\n        pattern: '(unclosed'\n      - type: native_signature\n        expression: '#a > 2 and pe.is_pe'\n        atoms:\n          - id: a\n            value: x\n";
    let set = RuleSet::from_yaml_str(doc).unwrap();
    let w = set.warnings().join("\n");
    assert!(w.contains("unknown key `sevrity`"), "{w}");
    assert!(w.contains("unknown key `offset`"), "{w}");
    assert!(w.contains("invalid regex"), "{w}");
    assert!(w.contains("#a"), "{w}");
    assert!(RuleSet::from_yaml_str_strict(doc).is_err());
}

#[test]
fn expression_validation() {
    let bad = [
        ("$a $b", "two operands"),
        ("$a and pe.is_pe", "unsupported"),
        ("$missing", "names no atom"),
        ("($a or $b", "unbalanced"),
        ("uint8(0) == 0x4D", "unsupported"),
    ];
    for (expr, needle) in bad {
        let doc = format!("rules:\n  - id: R\n    title: t\n    severity: low\n    conditions:\n      - type: native_signature\n        expression: '{expr}'\n        atoms:\n          - id: a\n            value: x\n          - id: b\n            value: y\n");
        let set = RuleSet::from_yaml_str(&doc).unwrap();
        assert!(set.warnings().iter().any(|w| w.contains(needle)), "{expr}: {:?}", set.warnings());
    }
    let good = ["2 of ($a, $b)", "$a and not $b", "@a < @b and filesize < 1MB", "uint16(0) == 0x5A4D or $a at 0", "any of them and PE"];
    for expr in good {
        let doc = format!("rules:\n  - id: R\n    title: t\n    severity: low\n    conditions:\n      - type: native_signature\n        expression: '{expr}'\n        atoms:\n          - id: a\n            value: x\n          - id: b\n            value: y\n");
        let set = RuleSet::from_yaml_str(&doc).unwrap();
        assert!(set.warnings().is_empty(), "{expr}: {:?}", set.warnings());
    }
}

#[test]
fn macho_with_valid_header_is_not_broken() {
    let set = one("      - type: file_type\n        values: [broken_executable]\n");
    // 64-bit little-endian Mach-O: magic, cputype x86_64, subtype, filetype, ncmds=1, sizeofcmds=16
    let mut data = vec![0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0, 0, 0, 0x02, 0, 0, 0, 0x01, 0, 0, 0, 0x10, 0, 0, 0];
    data.resize(64, 0);
    assert!(scan(&set, &data).is_empty());
    let truncated = data[..24].to_vec();
    assert_eq!(scan(&set, &truncated), vec!["R"]);
}

#[test]
fn remove_ids_drops_rules() {
    let mut set = rules("  - id: A\n    title: t\n    severity: low\n    conditions:\n      - type: string_contains\n        value: 'aaaa'\n  - id: B\n    title: t\n    severity: low\n    conditions:\n      - type: string_contains\n        value: 'bbbb'\n");
    let all = || ScanOptions { stop_on_detection: false, ..ScanOptions::default() };
    assert_eq!(scan_with(&set, b"aaaa bbbb", all()).len(), 2);
    let ids: std::collections::HashSet<String> = ["A".to_string()].into_iter().collect();
    assert_eq!(set.remove_ids(&ids), 1);
    assert_eq!(scan_with(&set, b"aaaa bbbb", all()), vec!["B"]);
}

fn with_parent(features: &[(&str, f64)], imports: &[&str]) -> ScanOptions {
    let parent = hydradragonsig::models::ParentInfo {
        identifier: "packed.exe".into(),
        file_size: 1000,
        is_pe: true,
        imports: imports.iter().map(|s| s.to_ascii_lowercase()).collect(),
        features: features.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
    };
    ScanOptions { parent: Some(parent), ..ScanOptions::default() }
}

#[test]
fn feature_lte_matches_at_or_below() {
    let set = one("      - type: feature_lte\n        name: string_count\n        value: 1\n");
    assert_eq!(scan(&set, b"only-one-string"), vec!["R"]);
    assert!(scan(&set, b"first-string\x00second-string\x00third-string").is_empty());
}

#[test]
fn parent_conditions_need_a_parent() {
    let set = one("      - type: has_parent\n");
    assert!(scan(&set, b"payload").is_empty(), "no parent given");
    assert_eq!(scan_with(&set, b"payload", with_parent(&[], &[])), vec!["R"]);

    let set = one("      - type: parent_feature_lte\n        name: pe_import_count\n        value: 10\n");
    assert!(scan(&set, b"payload").is_empty());
    assert_eq!(scan_with(&set, b"payload", with_parent(&[("pe_import_count", 4.0)], &[])), vec!["R"]);
    assert!(scan_with(&set, b"payload", with_parent(&[("pe_import_count", 40.0)], &[])).is_empty());

    let set = one("      - type: parent_feature_gte\n        name: file_entropy_bits_per_byte\n        value: 7.5\n");
    assert_eq!(scan_with(&set, b"x", with_parent(&[("file_entropy_bits_per_byte", 7.9)], &[])), vec!["R"]);
}

#[test]
fn feature_delta_compares_child_with_parent() {
    // string_count of the child (3) minus the parent's (1) = +2.
    let set = one("      - type: feature_delta_gte\n        name: string_count\n        value: 2\n");
    let data = b"first-string\x00second-string\x00third-string";
    assert_eq!(scan_with(&set, data, with_parent(&[("string_count", 1.0)], &[])), vec!["R"]);
    assert!(scan_with(&set, data, with_parent(&[("string_count", 2.0)], &[])).is_empty());
    assert!(scan(&set, data).is_empty(), "no parent, no delta");
}

#[test]
fn new_import_set_is_pe_only_and_validated() {
    let set = one("      - type: new_import_set\n        min: 1\n        names: ['!WriteProcessMemory']\n");
    // Not a PE: the rule is gated out even with a parent.
    assert!(scan_with(&set, b"WriteProcessMemory", with_parent(&[], &[])).is_empty());
    let bad = RuleSet::from_yaml_str(
        "rules:\n  - id: R\n    title: t\n    severity: low\n    conditions:\n      - type: new_import_set\n        min: 3\n        names: [a, b]\n",
    )
    .unwrap();
    assert!(!bad.warnings().is_empty(), "min larger than list must warn");
    let bad = RuleSet::from_yaml_str(
        "rules:\n  - id: R\n    title: t\n    severity: low\n    conditions:\n      - type: parent_feature_lte\n        name: string_count\n        value: 1\n",
    )
    .unwrap();
    assert!(bad.warnings().iter().any(|w| w.contains("parent feature")), "{:?}", bad.warnings());
}

#[test]
fn xor_and_base64_atoms_skip_the_plain_text() {
    let stub = "This program cannot be run in DOS mode";
    let xor = one(&format!(
        "      - type: native_signature\n        expression: '$a'\n        atoms:\n          - id: a\n            value: '{stub}'\n            xor: true\n"
    ));
    // `xor` alone is YARA xor(0-255): the plain text matches too.
    assert_eq!(scan(&xor, stub.as_bytes()), vec!["R"]);
    let xor = one(&format!(
        "      - type: native_signature\n        expression: '$a'\n        atoms:\n          - id: a\n            value: '{stub}'\n            xor: true\n            xor_min: 1\n"
    ));
    // With xor_min: 1 (YARA xor(1-255)) the plain stub of a PE header must not match.
    assert!(scan(&xor, format!("MZ....{stub}....").as_bytes()).is_empty());
    let encoded: Vec<u8> = stub.bytes().map(|b| b ^ 0x37).collect();
    assert_eq!(scan(&xor, &[b"MZ....".as_slice(), &encoded].concat()), vec!["R"]);
    // xor_min: 0 is the explicit form of the default.
    let xor0 = one(&format!(
        "      - type: native_signature\n        expression: '$a'\n        atoms:\n          - id: a\n            value: '{stub}'\n            xor: true\n            xor_min: 0\n"
    ));
    assert_eq!(scan(&xor0, stub.as_bytes()), vec!["R"]);

    let b64 = one(&format!(
        "      - type: native_signature\n        expression: '$a'\n        atoms:\n          - id: a\n            value: '{stub}'\n            base64: true\n"
    ));
    assert!(scan(&b64, stub.as_bytes()).is_empty(), "base64 atom must not match plain text");
    assert_eq!(scan(&b64, b"VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU="), vec!["R"]);
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

/// Zip of (name, compression method, bytes); method 0 stores `bytes`, others are
/// written as they are (a member the reader cannot open).
fn zip(members: &[(&str, u16, &[u8])]) -> Vec<u8> {
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for (name, method, data) in members {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let header = |sig: &[u8], central: bool| {
            let mut h = sig.to_vec();
            if central {
                h.extend(20u16.to_le_bytes());
            }
            h.extend(20u16.to_le_bytes());
            h.extend(0u16.to_le_bytes());
            h.extend(method.to_le_bytes());
            h.extend([0u8; 4]);
            h.extend(crc.to_le_bytes());
            h.extend((data.len() as u32).to_le_bytes());
            h.extend((data.len() as u32).to_le_bytes());
            h.extend((name.len() as u16).to_le_bytes());
            h.extend(0u16.to_le_bytes());
            if central {
                h.extend([0u8; 6]); // comment length, disk, internal attributes
                h.extend(0u32.to_le_bytes()); // external attributes
                h.extend(offset.to_le_bytes());
            }
            h.extend(name.as_bytes());
            h
        };
        out.extend(header(b"PK\x03\x04", false));
        out.extend(*data);
        central.extend(header(b"PK\x01\x02", true));
    }
    let cd_offset = out.len() as u32;
    let n = members.len() as u16;
    out.extend(&central);
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    out.extend(n.to_le_bytes());
    out.extend(n.to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

#[test]
fn unreadable_archive_member_does_not_stop_the_scan() {
    // The size limit keeps the rule off the zip itself: only the member can match.
    let set = rules("  - id: R\n    title: t\n    severity: high\n    verdict: malware\n    logic: all\n    conditions:\n      - type: string_contains\n        value: 'ARCHIVE-MEMBER-MARK'\n      - type: file_size_lte\n        bytes: 100\n");
    let good: &[u8] = b"\x00\x01 ARCHIVE-MEMBER-MARK payload \x00";
    // Method 12 (bzip2) is not built in: the reader cannot open that member, like an
    // encrypted one.
    let data = zip(&[("locked.bin", 12, b"0123456789abcdef"), ("payload.bin", 0, good)]);
    let ctx = MemoryScanContext { buffer: data, identifier: "t.zip".into(), base_address: None };
    let report = scan_memory_owned(ctx, &set, &ScanOptions::default()).expect("the scan goes on");
    use hydradragonsig::models::ScanResultCode;
    let member = |n: &str| report.archive_members.iter().find(|m| m.name == n).map(|m| m.result_code);
    assert_eq!(member("locked.bin"), Some(ScanResultCode::OpenError), "{:?}", report.archive_members);
    assert!(member("payload.bin").is_some_and(|c| c.is_infected()), "the member after it is still scanned: {:?}", report.archive_members);
    assert!(report.findings.iter().any(|f| f.rule_id == "R"));
}

