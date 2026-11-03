//! `opcode_pattern` `mode: cfg` and `arch: arm64` through the public API.

use hydradragonsig::models::MemoryScanContext;
use hydradragonsig::rules::RuleSet;
use hydradragonsig::{ScanOptions, scan_memory};

fn matched(yaml: &str, bytes: Vec<u8>) -> Vec<String> {
    let rules = RuleSet::from_yaml_str_strict(yaml).unwrap_or_else(|e| panic!("{e:#}"));
    let ctx = MemoryScanContext { buffer: bytes, identifier: "sample".into(), base_address: None };
    let options = ScanOptions { stop_on_detection: false, ..ScanOptions::default() };
    let mut ids: Vec<String> = scan_memory(&ctx, &rules, &options).expect("scan").findings.into_iter().map(|f| f.rule_id).collect();
    ids.sort();
    ids
}

fn rule(id: &str, keys: &str) -> String {
    let mut y = format!("  - id: {id}\n    title: {id}\n    severity: low\n    conditions:\n      - type: opcode_pattern\n");
    for line in keys.lines() {
        y.push_str(&format!("        {line}\n"));
    }
    y
}

/// `push ebp; jmp L1; FF FF FF; L1: mov ebp,esp; jmp L2; FF FF; L2: xor byte ptr
/// [eax],0x5a; inc eax; loop L2; ret`, behind 16 bytes of padding.
fn jump_islands() -> Vec<u8> {
    let mut c = vec![0xC3u8; 16];
    c.extend([0x55, 0xEB, 0x03, 0xFF, 0xFF, 0xFF]);
    c.extend([0x89, 0xE5, 0xEB, 0x02, 0xFF, 0xFF]);
    c.extend([0x80, 0x30, 0x5A, 0x40, 0xE2, 0xFA, 0xC3]);
    c
}

#[test]
fn cfg_mode_defeats_jump_islands() {
    let pattern = "pattern: 'push ebp; mov ebp, esp; xor byte ptr [eax], 0x5a; inc eax; loop *'";
    let yaml = format!(
        "rules:\n{}{}{}",
        rule("LINEAR", &format!("{pattern}\nregion: file\nbitness: 32")),
        rule("CFG", &format!("{pattern}\nregion: file\nbitness: 32\nmode: cfg")),
        rule("CFG_NO_FOLLOW", &format!("{pattern}\nregion: file\nbitness: 32\nmode: cfg\nfollow_jumps: false")),
    );
    // The walk starts at the region start: the padding `ret` ends it at once.
    assert!(matched(&yaml, jump_islands()).is_empty());
    let code = jump_islands()[16..].to_vec();
    assert_eq!(matched(&yaml, code), ["CFG"]);
}

/// AArch64 ELF64: one `PT_LOAD` mapping the file at 0x400000, entry at file
/// offset 0x78: prologue and an XOR decryptor loop.
fn arm64_elf() -> Vec<u8> {
    let mut b = vec![0u8; 0x78];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&183u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    let code: [u32; 9] = [0xa9bf7bfd, 0x910003fd, 0x39400008, 0x4a010108, 0x38001408, 0xf1000442, 0x54ffff81, 0xa8c17bfd, 0xd65f03c0];
    for w in code {
        b.extend(w.to_le_bytes());
    }
    let len = b.len() as u64;
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    b[96..104].copy_from_slice(&len.to_le_bytes());
    b[104..112].copy_from_slice(&len.to_le_bytes());
    b
}

#[test]
fn arm64_decryptor_on_an_elf_entry_point() {
    let decryptor = "pattern: 'stp x29, x30, [sp, #-0x10]!; [0-4]; eor w*, w*, w*; [0-2]; b.ne *'";
    let yaml = format!(
        "rules:\n{}{}{}{}",
        rule("AUTO_ENTRY", &format!("{decryptor}\narch: auto")),
        rule("AUTO_CFG", &format!("{decryptor}\narch: auto\nmode: cfg\nmax_blocks: 8\nmax_insns: 64")),
        rule("X86_ON_ARM", "pattern: 'push ebp; mov ebp, esp'\narch: auto"),
        // Without `arch` only PE regions exist, as before.
        rule("NO_ARCH", "pattern: '*'"),
    );
    assert_eq!(matched(&yaml, arm64_elf()), ["AUTO_CFG", "AUTO_ENTRY"]);
}

#[test]
fn opcode_keys_are_validated() {
    for (keys, why) in [
        ("pattern: nop\nmode: graph", "invalid mode"),
        ("pattern: nop\narch: mips", "invalid arch"),
        ("pattern: nop\nmax_blocks: 10", "need `mode: cfg`"),
        ("pattern: nop\nmode: cfg\nmax_blocks: 4096", "max_blocks must be"),
        ("pattern: nop\nmode: cfg\nmax_insns: 0", "max_insns must be"),
        ("pattern: 'stp x29, x30, [sp]'", "unknown mnemonic `stp`"),
        ("pattern: 'push ebp'\narch: arm64", "unknown arm64 mnemonic `push`"),
        ("pattern: 'frobnicate x0'\narch: auto", "fits neither"),
        ("pattern: nop\narch: arm64\nskip: [hlt2]", "skip `hlt2`"),
    ] {
        let yaml = format!("rules:\n{}", rule("BAD", keys));
        let err = match RuleSet::from_yaml_str_strict(&yaml) {
            Ok(_) => panic!("accepted: {keys}"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains(why), "{keys}: {err}");
    }
    let ok = format!("rules:\n{}", rule("OK", "pattern: 'b* *'\narch: arm64\nmode: cfg\nfollow_calls: true\nskip: [nop, hint]"));
    assert!(RuleSet::from_yaml_str_strict(&ok).is_ok());
}
