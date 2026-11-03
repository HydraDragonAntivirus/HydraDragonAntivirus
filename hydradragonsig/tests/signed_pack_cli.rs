//! `--rules-pack` signing from the command line: keygen, signed creation, and
//! fail-closed loading (exit code 2) on tampering, untrusted keys, unsigned
//! packs and rollback.
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::Command;

const RULES: &str = "rules:\n  - id: SIGNED_PACK_TEST\n    title: signed pack test\n    severity: low\n    conditions:\n      - type: string_contains\n        value: hydradragon-signed-pack\n";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hydradragonsig"))
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hydradragonsig-signed-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rules")).unwrap();
    dir
}

fn run(args: &[&str]) -> (i32, String) {
    let out = bin().args(args).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Key pair plus a signed v3 pack over one rule file; returns (dir, manifest, pubkey file).
fn setup(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = temp_dir(tag);
    std::fs::write(dir.join("rules/base.yaml"), RULES).unwrap();
    let prefix = dir.join("signer");
    let (code, out) = run(&["--pack-keygen", s(&prefix), "--pack-key-id", "hds-test-2026"]);
    assert_eq!(code, 0, "{out}");
    let manifest = dir.join("rule_pack.yml");
    let (code, out) = run(&[
        "--create-rules-pack",
        s(&dir.join("rules")),
        "--out",
        s(&manifest),
        "--pack-version",
        "3",
        "--pack-notes",
        "release",
        "--pack-sign-key",
        s(&dir.join("signer.key")),
        "--pack-key-id",
        "hds-test-2026",
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(std::fs::read_to_string(&manifest).unwrap().contains("algorithm: ed25519"));
    let public = dir.join("signer.pub");
    (dir, manifest, public)
}

fn load(manifest: &Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["--rules-pack", s(manifest), "--check-rules"];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn signed_pack_loads_and_tampering_fails_closed() {
    let (dir, manifest, public) = setup("main");
    let trusted = ["--pack-pubkey", s(&public), "--require-signed-pack"];

    let (code, out) = load(&manifest, &trusted);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("signature of `hds-test-2026` verified"), "{out}");
    let (code, out) = load(&manifest, &["--pack-pubkey", s(&public), "--min-pack-version", "3"]);
    assert_eq!(code, 0, "{out}");

    // Rollback.
    let (code, out) = load(&manifest, &["--pack-pubkey", s(&public), "--min-pack-version", "4"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("rollback"), "{out}");

    // Modified notes.
    let original = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, original.replace("notes: release", "notes: releasE")).unwrap();
    let (code, out) = load(&manifest, &trusted);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("does not verify"), "{out}");

    // Wrong key id: the trusted key is named differently.
    std::fs::write(&manifest, &original).unwrap();
    let key_hex = std::fs::read_to_string(&public).unwrap().trim().rsplit_once(':').unwrap().1.to_string();
    let renamed = format!("other-key:{key_hex}");
    let (code, out) = load(&manifest, &["--pack-pubkey", &renamed]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("not trusted"), "{out}");

    // One flipped bit in a rule file (same size).
    let rule = dir.join("rules/base.yaml");
    let mut bytes = std::fs::read(&rule).unwrap();
    let last = bytes.len() - 2;
    bytes[last] ^= 0x01;
    std::fs::write(&rule, &bytes).unwrap();
    let (code, out) = load(&manifest, &trusted);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("rules/base.yaml: sha256"), "{out}");
    std::fs::write(&rule, RULES).unwrap();

    // Unsigned pack under --require-signed-pack.
    let unsigned = original.split("signature:").next().unwrap().to_string();
    std::fs::write(&manifest, unsigned).unwrap();
    let (code, out) = load(&manifest, &trusted);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("not signed"), "{out}");
    // Without a policy the unsigned pack still loads (hash checks only).
    let (code, out) = load(&manifest, &[]);
    assert_eq!(code, 0, "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn require_signed_pack_needs_a_key() {
    let (dir, manifest, _) = setup("nokey");
    let (code, out) = load(&manifest, &["--require-signed-pack"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("needs --pack-pubkey"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}
