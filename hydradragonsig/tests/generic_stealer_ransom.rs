//! The shipped generic stealer / ransomware rules (src/rules/*.yaml) on small
//! hand-made buffers: every step alone must stay quiet, the chain must match.

use hydradragonsig::models::{ApiCall, BehaviorTrace, MemoryScanContext};
use hydradragonsig::rules::RuleSet;
use hydradragonsig::{scan_memory_owned, ScanOptions};
use std::path::Path;

fn shipped() -> RuleSet {
    let set = RuleSet::from_yaml_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rules/file_rules.yaml")).unwrap();
    assert!(set.warnings().is_empty(), "{:?}", set.warnings());
    set
}

/// A minimal PE32 (headers + one data section holding `body`): the rules' import /
/// PE conditions gate them to PE files, and string-only fallbacks still need a PE.
fn tiny_pe(body: &[u8]) -> Vec<u8> {
    let raw = body.len().div_ceil(0x200).max(1) * 0x200;
    let mut pe = vec![0u8; 0x200 + raw];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    pe[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes()); // i386
    pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // sections
    pe[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes()); // optional header size
    pe[coff + 18..coff + 20].copy_from_slice(&0x102u16.to_le_bytes()); // executable, 32-bit
    let opt = coff + 20;
    pe[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    pe[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
    pe[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // image base
    pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    pe[opt + 40..opt + 42].copy_from_slice(&6u16.to_le_bytes()); // OS version
    pe[opt + 48..opt + 50].copy_from_slice(&6u16.to_le_bytes()); // subsystem version
    let image = 0x1000 + raw.div_ceil(0x1000) * 0x1000;
    pe[opt + 56..opt + 60].copy_from_slice(&(image as u32).to_le_bytes());
    pe[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // headers
    pe[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // GUI
    pe[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // data directories
    let sec = opt + 0xe0;
    pe[sec..sec + 5].copy_from_slice(b".data");
    pe[sec + 8..sec + 12].copy_from_slice(&(raw as u32).to_le_bytes());
    pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[sec + 16..sec + 20].copy_from_slice(&(raw as u32).to_le_bytes());
    pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec + 36..sec + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes()); // RW initialized data
    pe[0x200..0x200 + body.len()].copy_from_slice(body);
    pe
}

fn findings(parts: &[&str], behavior: Option<BehaviorTrace>) -> Vec<String> {
    let mut body = b"\x00\x00".to_vec();
    for p in parts {
        body.extend_from_slice(p.as_bytes());
        body.extend_from_slice(b"\x00\x00");
    }
    let data = tiny_pe(&body);
    let options = ScanOptions { stop_on_detection: false, behavior, ..ScanOptions::default() };
    let ctx = MemoryScanContext { buffer: data, identifier: "t".into(), base_address: None };
    let report = scan_memory_owned(ctx, &shipped(), &options).unwrap();
    report.findings.iter().map(|f| f.rule_id.clone()).collect()
}

const BROWSER: &[&str] = &["\\Google\\Chrome\\User Data", "\\Microsoft\\Edge\\User Data", "Login Data", "logins.json"];
const WALLET: &[&str] = &["\\Exodus\\exodus.wallet", "\\Electrum\\wallets", "wallet.dat"];
const DECRYPT: &str = "CryptUnprotectData";
const EXFIL: &str = "https://api.telegram.org/bot123:abc/sendDocument";

#[test]
fn stealer_needs_two_stores_decryption_and_exfiltration() {
    let full: Vec<&str> = BROWSER.iter().chain(WALLET).copied().chain([DECRYPT, EXFIL]).collect();
    assert!(findings(&full, None).contains(&"HDS-GEN-STEALER-001".to_string()));

    // One kind of store only (a browser, a password manager importer).
    let one_kind: Vec<&str> = BROWSER.iter().copied().chain([DECRYPT, EXFIL]).collect();
    assert!(!findings(&one_kind, None).contains(&"HDS-GEN-STEALER-001".to_string()));
    // Paths only.
    let paths: Vec<&str> = BROWSER.iter().chain(WALLET).copied().collect();
    assert!(findings(&paths, None).is_empty());
    // No way out.
    let no_exfil: Vec<&str> = BROWSER.iter().chain(WALLET).copied().chain([DECRYPT]).collect();
    assert!(!findings(&no_exfil, None).contains(&"HDS-GEN-STEALER-001".to_string()));
}

const WALK: &[&str] = &["FindFirstFileW", "FindNextFileW", "GetLogicalDrives"];
const CHACHA: &str = "expand 32-byte k";
const NOTE: &[&str] = &["All your files have been encrypted", "To decrypt your files visit", "http://abcdefghijklmnop.onion/pay"];

#[test]
fn ransomware_chain_and_recovery_inhibition() {
    let chain: Vec<&str> = WALK.iter().copied().chain([CHACHA]).chain(NOTE.iter().copied()).collect();
    assert!(findings(&chain, None).contains(&"RANSOM_0001".to_string()));

    // Crypto + walk without a note: archivers, backup and disk-encryption tools.
    let no_note: Vec<&str> = WALK.iter().copied().chain([CHACHA]).collect();
    assert!(findings(&no_note, None).is_empty());
    // A note alone (a security tool's help text).
    assert!(findings(NOTE, None).is_empty());

    // Recovery inhibition alone is suspicious, not malware.
    let inhibit = ["cmd.exe /c vssadmin delete shadows /all /quiet"];
    assert_eq!(findings(&inhibit, None), vec!["RANSOM_0002".to_string()]);
    // With two more steps it is ransomware.
    let inhibit_plus: Vec<&str> = inhibit.iter().copied().chain(WALK.iter().copied()).chain([CHACHA]).collect();
    assert!(findings(&inhibit_plus, None).contains(&"RANSOM_0001".to_string()));
}

fn trace(calls: &[(&str, &[&str])]) -> Option<BehaviorTrace> {
    Some(BehaviorTrace {
        calls: calls
            .iter()
            .map(|(api, args)| ApiCall { api: api.to_string(), args: args.iter().map(|a| a.to_string()).collect(), ret: 0 })
            .collect(),
        ..Default::default()
    })
}

#[test]
fn emulation_evidence_is_suspicious_only() {
    let t = trace(&[
        ("CreateFileW", &["C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"]),
        ("ReadFile", &["0x100"]),
        ("WinHttpSendRequest", &["0x200"]),
    ]);
    assert_eq!(findings(&["nothing"], t), vec!["HDS-GEN-STEALER-EMU-001".to_string()]);

    let t = trace(&[
        ("FindFirstFileW", &["C:\\*"]),
        ("CryptEncrypt", &["0x1"]),
        ("MoveFileExW", &["C:\\a.doc", "C:\\a.doc.locked"]),
    ]);
    assert_eq!(findings(&["nothing"], t), vec!["RANSOM_0003".to_string()]);

    let t = trace(&[("CreateProcessW", &["0x0", "vssadmin.exe delete shadows /all /quiet"])]);
    assert_eq!(findings(&["nothing"], t), vec!["RANSOM_0003".to_string()]);
}
