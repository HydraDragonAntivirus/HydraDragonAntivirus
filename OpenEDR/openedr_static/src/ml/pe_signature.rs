//! `shell_signature_tampered`: the file carries an intact Authenticode signature whose
//! digest does not match its bytes, i.e. it was changed after it was signed (a patched,
//! cracked or trojanized copy of a signed program keeps the original publisher's
//! certificate). The same files WinVerifyTrust reports as `TRUST_E_BAD_DIGEST`, worked
//! out from the bytes alone so scanning and training (`pe_feature_dump`) need no file
//! on disk.
//!
//! Deliberately 0 (not tampered) for everything that is not that exact case:
//! - unsigned, or a certificate table that is not a PKCS#7 Authenticode signature
//!   (junk / forged bytes: Windows calls those unsigned);
//! - a certificate table outside the file;
//! - any data after the certificate table. Windows reports such files as unsigned, not
//!   as a bad digest, and legitimate SFX / installer payloads and tagged installers are
//!   appended there.
//!
//! Who signed it (self-signed, untrusted chain, expired) plays no part: an intact
//! self-signed file is 0.
//!
//! Measured on the training sets (2026-11-13, with Windows' own verdicts): every benign
//! file Windows calls HashMismatch (26 of 236k, mostly patched commercial tools) has no
//! data after its certificate table and a digest that is not in its signature, and every
//! benign file this check would otherwise call tampered had appended data.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Names (without the `shell_` prefix) in `to_array` order.
pub const NAMES: [&str; 1] = ["signature_tampered"];
pub const LEN: usize = NAMES.len();

/// OID 1.2.840.113549.1.7.2 (PKCS#7 signedData), DER-encoded with its tag and length.
const OID_SIGNED_DATA: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
/// OID 1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA: holds the image digest).
const OID_SPC_INDIRECT_DATA: &[u8] = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04";

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// The feature block: `[1.0]` when the signature is intact and the content changed.
pub fn to_array(data: &[u8]) -> [f32; LEN] {
    [signature_tampered(data) as u8 as f32]
}

/// True for an intact embedded Authenticode signature whose image digest is not the
/// digest of `data` (see the module docs for what counts).
pub fn signature_tampered(data: &[u8]) -> bool {
    let Some(pe) = u32_at(data, 0x3C).map(|v| v as usize) else { return false };
    if data.get(0..2) != Some(b"MZ") || data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return false;
    }
    let opt = pe + 24;
    let dirs = match u16_at(data, opt) {
        Some(0x10B) => opt + 96,
        Some(0x20B) => opt + 112,
        _ => return false,
    };
    // Number of data directories (the u32 before them): the certificate table is #4.
    if u32_at(data, dirs - 4).is_none_or(|n| n < 5) {
        return false;
    }
    let checksum = opt + 64;
    let cert_entry = dirs + 4 * 8;
    let (Some(cert_off), Some(cert_size)) = (u32_at(data, cert_entry), u32_at(data, cert_entry + 4)) else {
        return false;
    };
    let (cert_off, cert_size) = (cert_off as usize, cert_size as usize);
    if cert_off == 0 || cert_size < 8 || cert_off < cert_entry + 8 {
        return false;
    }
    let Some(cert_end) = cert_off.checked_add(cert_size) else { return false };
    // Outside the file, or data after it (appended payloads: not a bad digest).
    if cert_end != data.len() {
        return false;
    }
    let blob = &data[cert_off..cert_end];
    // WIN_CERTIFICATE: revision 0x0200, type PKCS_SIGNED_DATA, then signedData that
    // carries SpcIndirectDataContent.
    if u16_at(blob, 4) != Some(0x0200) || u16_at(blob, 6) != Some(0x0002) || blob.get(8) != Some(&0x30) {
        return false;
    }
    let head = &blob[8..];
    if !contains(&head[..head.len().min(64)], OID_SIGNED_DATA)
        || !contains(&head[..head.len().min(2048)], OID_SPC_INDIRECT_DATA)
    {
        return false;
    }
    // Image digest: the file up to the certificate table, minus the checksum field and
    // the certificate directory entry. The algorithm is whichever the signer used, so
    // look for each one's digest in the signature.
    let pieces = [&data[..checksum], &data[checksum + 4..cert_entry], &data[cert_entry + 8..cert_off]];
    fn digest_of<D: Digest>(pieces: &[&[u8]]) -> Vec<u8> {
        let mut h = D::new();
        for p in pieces {
            h.update(p);
        }
        h.finalize().to_vec()
    }
    let found = [
        digest_of::<Sha256>(&pieces),
        digest_of::<Sha1>(&pieces),
        digest_of::<Md5>(&pieces),
        digest_of::<Sha384>(&pieces),
        digest_of::<Sha512>(&pieces),
    ]
    .iter()
    .any(|d| contains(blob, d));
    !found
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel32() -> Option<Vec<u8>> {
        std::fs::read("C:\\Windows\\System32\\kernel32.dll").ok()
    }

    #[test]
    fn intact_signed_binary_is_not_tampered() {
        let Some(k) = kernel32() else { return };
        assert!(!signature_tampered(&k));
    }

    #[test]
    fn a_byte_changed_after_signing_is_tampered() {
        let Some(mut k) = kernel32() else { return };
        let at = 0x1000.min(k.len() / 2);
        k[at] ^= 0xFF;
        assert!(signature_tampered(&k));
        assert_eq!(to_array(&k), [1.0]);
    }

    #[test]
    fn appended_data_is_not_tampered() {
        let Some(mut k) = kernel32() else { return };
        let at = 0x1000.min(k.len() / 2);
        k[at] ^= 0xFF; // even when also changed: Windows says unsigned
        k.extend_from_slice(&[0x41; 4096]);
        assert!(!signature_tampered(&k));
    }

    #[test]
    fn unsigned_junk_and_truncated_are_not_tampered() {
        assert!(!signature_tampered(b""));
        assert!(!signature_tampered(b"MZ"));
        let Some(k) = kernel32() else { return };
        // Certificate table cut off: points outside the file.
        assert!(!signature_tampered(&k[..k.len() - 16]));
        // Same layout but the signature bytes replaced by junk.
        let mut junk = k.clone();
        let pe = u32_at(&k, 0x3C).unwrap() as usize;
        let dirs = pe + 24 + if u16_at(&k, pe + 24) == Some(0x20B) { 112 } else { 96 };
        let off = u32_at(&k, dirs + 32).unwrap() as usize;
        for b in &mut junk[off + 8..] {
            *b = 0x5A;
        }
        assert!(!signature_tampered(&junk));
    }
}
