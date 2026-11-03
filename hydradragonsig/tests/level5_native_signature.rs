//! Level-5 `native_signature` expressions through the public API: match
//! counts, lengths, occurrence offsets, integer readers, `entrypoint`,
//! checked arithmetic and bounded `for` loops.

use hydradragonsig::models::{MemoryScanContext, ScanReport};
use hydradragonsig::rules::RuleSet;
use hydradragonsig::{ScanOptions, scan_memory};

/// Little-endian ELF64 with one `PT_LOAD` mapping the file at 0x400000 and the
/// entry point at file offset 0x100; `EVILMARK` at 0x110, 0x180, 0x280 (inside
/// `EVILMARK_PAYLOAD_TAG`) and 0x300, `<TAIL>` at 0x118.
fn elf_sample() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    let ph = 64;
    b[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    b[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    b[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    b[ph + 32..ph + 40].copy_from_slice(&0x400u64.to_le_bytes());
    b[ph + 40..ph + 48].copy_from_slice(&0x400u64.to_le_bytes());
    for (at, text) in [(0x110, "EVILMARK"), (0x118, "<TAIL>"), (0x180, "EVILMARK"), (0x280, "EVILMARK_PAYLOAD_TAG"), (0x300, "EVILMARK")] {
        b[at..at + text.len()].copy_from_slice(text.as_bytes());
    }
    b
}

const ATOMS: &str = "        atoms:\n          - {id: a, value: EVILMARK}\n          - {id: b, value: '<TAIL>'}\n          - {id: c, value: EVILMARK_PAYLOAD_TAG}\n          - {id: d, kind: bytes, value: '{ 45 56 49 4C [2-16] 54 41 47 }'}\n";

fn ruleset(exprs: &[(&str, &str)]) -> RuleSet {
    let mut y = String::from("rules:\n");
    for (id, expr) in exprs {
        y.push_str(&format!(
            "  - id: {id}\n    title: {id}\n    severity: low\n    conditions:\n      - type: native_signature\n        expression: \"{expr}\"\n{ATOMS}"
        ));
    }
    RuleSet::from_yaml_str_strict(&y).unwrap_or_else(|e| panic!("{e:#}"))
}

fn matched(rules: &RuleSet, bytes: Vec<u8>) -> Vec<String> {
    let ctx = MemoryScanContext { buffer: bytes, identifier: "sample".into(), base_address: None };
    let options = ScanOptions { stop_on_detection: false, ..ScanOptions::default() };
    let report: ScanReport = scan_memory(&ctx, rules, &options).expect("scan");
    let mut ids: Vec<String> = report.findings.into_iter().map(|f| f.rule_id).collect();
    ids.sort();
    ids
}

#[test]
fn counts_lengths_offsets_readers_and_loops() {
    let rules = ruleset(&[
        ("COUNT", "#a >= 4"),
        ("COUNT_TOO_MANY", "#a >= 5"),
        ("COUNT_IN", "#a in (0..512) == 2"),
        ("LENGTH", "!c > 10 and !a == 8 and !a[3] == 8"),
        ("LENGTH_VARIABLE", "!d == 20"),
        ("LEGACY_OFFSET_ADD", "@a[8] == @b"),
        ("OCCURRENCE", "@a#2 > @a#1 and @a#4 == 0x300 and @a == 0x110"),
        ("NO_FIFTH", "@a#5 > 0"),
        ("ENTRY", "entrypoint == 0x100 and $a in (entrypoint..entrypoint + 0x20)"),
        ("FOR_OF", "for any of ($a, $c) : ( @ >= entrypoint and ! > 16 )"),
        ("FOR_OF_ALL", "for all of ($a*, $b) : ( @ >= entrypoint and ! > 16 )"),
        ("DIV_ZERO", "filesize / 0 == 0 or filesize % 0 != 1"),
        ("DIV_ZERO_NOT", "not (filesize / 0 == 0) and ELF"),
        ("FOR_IN", "for any i in (0..8) : ( uint8(i) == 0x45 )"),
        ("FOR_IN_ALL", "for all i in (1..#a) : ( @a#i > 0x100 )"),
        ("FOR_DYNAMIC_CAP", "for any i in (0..filesize * 100) : ( i == 3 )"),
        ("MAGIC_BE", "uint32be(0) == 0xCAFEBABE"),
        ("ARITH", "(uint16(18) << 4 | 0xF) == 0x3EF and uint32(0) & 0xFF == 0x7F and ~0 == -1"),
    ]);
    let got = matched(&rules, elf_sample());
    assert_eq!(
        got,
        [
            "ARITH", "COUNT", "COUNT_IN", "DIV_ZERO_NOT", "ENTRY", "FOR_IN", "FOR_IN_ALL", "FOR_OF", "LEGACY_OFFSET_ADD", "LENGTH",
            "LENGTH_VARIABLE", "OCCURRENCE",
        ]
    );

    let mut java = b"\xca\xfe\xba\xbe\x00\x00\x00\x34".to_vec();
    java.resize(64, 0);
    assert_eq!(matched(&rules, java), ["MAGIC_BE"]);
}

#[test]
fn loop_caps_and_malformed_expressions_are_rejected() {
    let doc = |expr: &str| {
        format!("rules:\n  - id: R\n    title: t\n    severity: low\n    conditions:\n      - type: native_signature\n        expression: \"{expr}\"\n{ATOMS}")
    };
    for (expr, why) in [
        ("for any i in (0..4096) : ( uint8(i) == 0 )", "at most 4096"),
        ("for any i in (0..9) : ( uint8(j) == 0 )", "unsupported word `j`"),
        ("#z > 1", "names no atom"),
        ("#a", "a number is used as a condition"),
        ("$a + 1 > 2", "a condition is used as a number"),
        ("@ > 1", "outside `for .. of`"),
        ("for any of ($a) : ( ! > 1 ) and ! > 1", "outside `for .. of`"),
        ("uint64(0) == 1", "unsupported word"),
        ("for 101% of them : ( $ )", "outside 0..100"),
        ("#a in (0..) == 1", "expected"),
        ("!a[1 > 2", "expected `]`"),
    ] {
        let err = match RuleSet::from_yaml_str_strict(&doc(expr)) {
            Ok(_) => panic!("accepted: {expr}"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains(why), "{expr}: {err}");
    }
    assert!(RuleSet::from_yaml_str_strict(&doc("for any i in (0..4095) : ( uint8(i) == 0 )")).is_ok());
    assert!(RuleSet::from_yaml_str_strict(&doc("for 50% of them : ( # > 0 ) and PDF == false or ARM64 or MachO64 or OLE or Office or DotNet")).is_err());
    assert!(RuleSet::from_yaml_str_strict(&doc("for 50% of them : ( # > 0 ) and not (PDF or ARM64 or MachO64 or OLE or Office or DotNet)")).is_ok());
}
