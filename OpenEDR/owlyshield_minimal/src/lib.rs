//! Minimal firewall-only build for bisection debugging (no edrsvc).
//!
//! Keeps `firewall` plus the two small helpers it directly depends on:
//! `signature_verification` (authenticode checks) and `signer_rules`
//! (trusted-signer patterns). Everything else (ML, telemetry, kernel
//! driver client, logging, ransomware worker) is stubbed out at the
//! call sites inside `firewall/`.

pub mod firewall;
pub mod signature_verification;
pub mod signer_rules;
