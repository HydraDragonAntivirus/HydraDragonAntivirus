//! Authenticode timestamp extraction.
//!
//! Reads the embedded PKCS#7 out of a PE's certificate table and reports the
//! countersignature, in both shapes Windows emits:
//!
//! - RFC 3161 token, OID 1.3.6.1.4.1.311.3.3.1 - a nested `SignedData` whose
//!   eContent is a TSTInfo, with the TSA's certificate in its own certs set.
//! - Legacy PKCS#9 countersignature, OID 1.2.840.113549.1.9.6 - a bare
//!   `SignerInfo` addressed by issuer and serial against the outer certs set.
//!
//! Self-contained DER walking on purpose: no new dependency, and the same code
//! serves the on-disk and the in-memory scan paths. Catalog-signed files carry
//! no embedded PKCS#7, so they correctly report "no timestamp" - the catalog
//! carries the signature, not the file.
//!
//! What is read is a *fact about the signature*, not a trust decision: WinTrust
//! has already decided whether the signature is valid by the time this runs.

/// OID 1.3.6.1.4.1.311.3.3.1 - RFC 3161 countersignature (Microsoft).
const OID_RFC3161_COUNTERSIGN: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01,
];
/// OID 1.2.840.113549.1.9.6 - legacy PKCS#9 countersignature.
const OID_PKCS9_COUNTERSIGN: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06,
];
/// OID 1.2.840.113549.1.9.16.1.4 - id-smime-ct-TSTInfo, the RFC 3161 payload.
const OID_TST_INFO: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
];
/// OID 2.5.4.3 - commonName.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// How the timestamp was carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampKind {
    /// RFC 3161 token in the signer's unauthenticated attributes.
    Rfc3161,
    /// Legacy PKCS#9 countersignature.
    Pkcs9,
}

#[derive(Debug, Clone)]
pub struct TimestampInfo {
    pub kind: TimestampKind,
    /// Common name of the TSA / countersigner.
    pub signer: Option<String>,
    /// `genTime` of the TSTInfo, Unix seconds. `None` for a PKCS#9
    /// countersignature, which carries no timestamp value at all.
    pub time: Option<i64>,
}

// --------------------------------------------------------------------------- //
//  Minimal DER reader
// --------------------------------------------------------------------------- //
/// One TLV: `tag`, `content` slice, `total` bytes consumed (header + content).
#[derive(Clone, Copy)]
#[derive(Debug)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    total: usize,
}

impl<'a> Tlv<'a> {
    /// SEQUENCE / SET bodies: iterate their children.
    fn children(&self) -> Vec<Tlv<'a>> {
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            match Tlv::read(rest) {
                Some(t) => {
                    rest = &rest[t.total..];
                    out.push(t);
                }
                None => break,
            }
        }
        out
    }

    fn is_ctx(&self, n: u8) -> bool {
        self.tag & 0xC0 == 0x80 && self.tag & 0x1F == n
    }

    fn is_seq(&self) -> bool {
        self.tag == 0x30
    }

    fn is_set(&self) -> bool {
        self.tag == 0x31
    }
}

impl<'a> Tlv<'a> {
    fn read(mut b: &'a [u8]) -> Option<Self> {
        if b.len() < 2 {
            return None;
        }
        let tag = b[0];
        if tag & 0x1F == 0x1F {
            return None; // high tag-number form: not used anywhere below
        }
        b = &b[1..];
        let first = b[0];
        b = &b[1..];
        let (len, hdr) = if first & 0x80 == 0 {
            (first as usize, 0usize)
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 4 || b.len() < n {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | b[i] as usize;
            }
            b = &b[n..];
            (len, n)
        };
        if b.len() < len {
            return None;
        }
        Some(Tlv { tag, content: &b[..len], total: 1 + hdr + len + 1 })
    }
}

/// Days from 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`), days-from-civil transposed.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYMMDDHHMMSSZ` (UTCTime) or `YYYYMMDDHHMMSSZ` (GeneralizedTime) to Unix seconds.
fn asn1_time_to_unix(b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let s = s.trim_end_matches('Z');
    let digits: Vec<u32> = s.bytes().filter(|c| c.is_ascii_digit()).map(|c| (c - b'0') as u32).collect();
    let (y, off) = if digits.len() >= 14 {
        // GeneralizedTime: 4-digit year.
        (digits[0] as i64 * 1000 + digits[1] as i64 * 100 + digits[2] as i64 * 10 + digits[3] as i64, 4)
    } else if digits.len() >= 12 {
        // UTCTime: 2-digit year, RFC 5280 sliding window [1950, 2049].
        let yy = digits[0] as i64 * 10 + digits[1] as i64;
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
    } else {
        return None;
    };
    let g = |i: usize| -> i64 {
        if i < digits.len() {
            digits[i] as i64 * 10 + digits[i + 1] as i64
        } else {
            0
        }
    };
    let (mo, d, h, mi, sec) = (g(off), g(off + 2), g(off + 4), g(off + 6), g(off + 8));
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

/// First `commonName` attribute value inside an X.501 Name (RDNSequence).
fn common_name(name: Tlv<'_>) -> Option<String> {
    for rdn in name.children() {
        if !rdn.is_set() {
            continue;
        }
        for atv in rdn.children() {
            if !atv.is_seq() {
                continue;
            }
            let k = atv.children();
            if k.len() < 2 {
                continue;
            }
            if k[0].content == OID_COMMON_NAME {
                // BMPString / UTF8String / PrintableString: for CN the useful
                // case is BMPString (UTF-16BE) and PrintableString.
                let raw = k[1].content;
                let text = match k[1].tag {
                    0x1E => String::from_utf16_lossy(
                        &raw.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<u16>>(),
                    ),
                    _ => String::from_utf8_lossy(raw).into_owned(),
                };
                let cleaned: String = text.chars().filter(|c| *c != '\0').collect();
                if !cleaned.is_empty() {
                    return Some(cleaned);
                }
            }
        }
    }
    None
}

/// `subject` of an X.509 `Certificate`.
///
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`
/// `TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
///                                 issuer, validity, subject, ... }`
fn cert_subject(cert: Tlv<'_>) -> Option<String> {
    let tbs = cert.children().into_iter().next()?;
    let mut k = tbs.children().into_iter();
    if k.next()?.is_ctx(0) {
        k.next()?; // serialNumber
    }
    k.next()?; // signature
    k.next()?; // issuer
    k.next()?; // validity
    common_name(k.next()?)
}

/// `issuer` of an X.509 `Certificate`, for matching a PKCS#9 countersignature
/// by issuerAndSerialNumber.
fn cert_issuer(cert: Tlv<'_>) -> Option<&[u8]> {
    let tbs = cert.children().into_iter().next()?;
    let mut k = tbs.children().into_iter();
    if k.next()?.is_ctx(0) {
        k.next()?;
    }
    k.next()?; // serialNumber
    k.next()?; // signature
    Some(k.next()?.content)
}

fn cert_serial(cert: Tlv<'_>) -> Option<&[u8]> {
    let tbs = cert.children().into_iter().next()?;
    let mut k = tbs.children().into_iter();
    if k.next()?.is_ctx(0) {
        k.next()?;
    }
    Some(k.next()?.content)
}

/// Certificate list of a `SignedData`, as `(issuer, serial, subject)` triples.
fn signed_data_certs(sd: Tlv<'_>) -> Vec<(Vec<u8>, Vec<u8>, Option<String>)> {
    let mut out = Vec::new();
    for k in sd.children() {
        if k.is_ctx(0) {
            for c in k.children().into_iter().filter(|c| c.is_seq()) {
                let issuer = cert_issuer(c).map(|x| x.to_vec()).unwrap_or_default();
                let serial = cert_serial(c).map(|x| x.to_vec()).unwrap_or_default();
                out.push((issuer, serial, cert_subject(c)));
            }
        }
    }
    out
}

/// The nested `SignedData` inside a ContentInfo (`SEQUENCE { OID, [0] ... }`).
fn content_info_signed_data(ci: Tlv<'_>) -> Option<Tlv<'_>> {
    for k in ci.children() {
        if k.is_ctx(0) {
            let sd = k.children().into_iter().find(|c| c.is_seq());
            if sd.is_some() {
                return sd;
            }
        }
    }
    None
}

/// eContent of a `ContentInfo` whose inner type really is a TSTInfo, as DER.
///
/// The content type is checked rather than assumed: the token's SignedData
/// could in principle wrap something else, and reading a `genTime` out of an
/// arbitrary structure would report a timestamp that does not exist. Note that
/// the TSTInfo type sits in the *encapsulated* ContentInfo, one level below
/// the `ContentInfo` that wraps the token's SignedData.
fn tst_info(content: Tlv<'_>) -> Option<&[u8]> {
    if !content.is_seq() {
        return None;
    }
    let sd = content_info_signed_data(content)?;
    // SignedData: version, digestAlgorithms, contentInfo, [0] certs, [1] crls, signerInfos
    let ci = sd.children().into_iter().find(|k| k.is_seq() && !k.is_set())?;
    let kids = ci.children();
    // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, [0] eContent }
    if kids.first().map(|c| c.content) != Some(OID_TST_INFO) {
        return None;
    }
    for k in kids {
        if k.is_ctx(0) {
            for inner in k.children() {
                if inner.tag == 0x04 {
                    return Some(inner.content);
                }
            }
        }
    }
    None
}

// --------------------------------------------------------------------------- //
//  PKCS#7 entry points
// --------------------------------------------------------------------------- //
/// `ContentInfo` of an Authenticode signature.
fn signed_data_of(pkcs7: &[u8]) -> Option<Tlv<'_>> {
    let ci = Tlv::read(pkcs7)?;
    if !ci.is_seq() {
        return None;
    }
    let inner = ci.children().into_iter().find(|k| k.is_ctx(0))?;
    inner.children().into_iter().find(|k| k.is_seq())
}

/// Report the countersignature carried by an Authenticode PKCS#7.
///
/// RFC 3161 is preferred when both are present: it is the one with a timestamp
/// value, and on any current Windows build it is what gets written.
pub fn parse_authenticode_timestamp(pkcs7: &[u8]) -> Option<TimestampInfo> {
    let sd = signed_data_of(pkcs7)?;
    let certs = signed_data_certs(sd);
    let signer_infos = sd.children().into_iter().filter(|k| k.is_set());

    let mut legacy: Option<TimestampInfo> = None;

    for si in signer_infos {
        for sk in si.children() {
            // SignerInfo: version, issuerAndSerial, digestAlgorithm,
            //              [0] authenticatedAttributes, digestAlgorithm,
            //              encryptedDigest, [1] unauthenticatedAttributes
            let k = sk.children();
            let Some(unauth) = k.iter().find(|x| x.is_ctx(1)) else {
                continue;
            };
            for attr in unauth.children().into_iter().filter(|a| a.is_seq()) {
                let ak = attr.children();
                if ak.len() < 2 {
                    continue;
                }
                let oid = ak[0].content;
                let values = ak[1].children();

                if oid == OID_RFC3161_COUNTERSIGN {
                    for v in values {
                        // `v` is the ContentInfo carrying the token: a
                        // complete TLV, not the body of one.
                        let Some(inner_sd) = content_info_signed_data(v) else {
                            continue;
                        };
                        let signer = signed_data_certs(inner_sd)
                            .into_iter()
                            .find_map(|(_, _, s)| s);
                        let time = tst_info(v).and_then(|der| {
                            let ti = Tlv::read(der)?;
                            // TSTInfo: version, policy, messageImprint,
                            //          serialNumber, genTime, ...
                            let mut f = ti.children().into_iter();
                            f.next()?; // version
                            f.next()?; // policy
                            f.next()?; // messageImprint
                            f.next()?; // serialNumber
                            let gen_time = f.next()?;
                            if gen_time.tag == 0x17 || gen_time.tag == 0x18 {
                                asn1_time_to_unix(gen_time.content)
                            } else {
                                None
                            }
                        });
                        return Some(TimestampInfo {
                            kind: TimestampKind::Rfc3161,
                            signer,
                            time,
                        });
                    }
                } else if oid == OID_PKCS9_COUNTERSIGN && legacy.is_none() {
                    for v in values {
                        // Countersignature ::= SignerInfo, again already a TLV.
                        if !v.is_seq() {
                            continue;
                        }
                        let ck = v.children();
                        if ck.len() < 2 {
                            continue;
                        }
                        let ias = ck[1].children();
                        if ias.len() < 2 {
                            continue;
                        }
                        let issuer = ias[0].content.to_vec();
                        let serial = ias[1].content.to_vec();
                        let signer = certs
                            .iter()
                            .find(|(i, s, _)| *i == issuer && *s == serial)
                            .and_then(|(_, _, s)| s.clone());
                        legacy = Some(TimestampInfo {
                            kind: TimestampKind::Pkcs9,
                            signer,
                            // A PKCS#9 countersignature has no timestamp value; the
                            // signing time lives in its own unauthenticated attrs,
                            // which this pass deliberately does not chase.
                            time: None,
                        });
                        break;
                    }
                }
            }
        }
    }

    legacy
}

/// Little-endian `u16` at `off`, or `None` when the slice is too short.
fn le_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

/// Little-endian `u32` at `off`, or `None` when the slice is too short.
fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// The embedded PKCS#7 of a PE, from `IMAGE_DIRECTORY_ENTRY_SECURITY`.
///
/// Returns `None` for anything that is not a PE carrying a PKCS#7-signed-data
/// certificate entry - which includes every catalog-signed file, correctly.
pub fn embedded_pkcs7(pe: &[u8]) -> Option<&[u8]> {
    if pe.len() < 0x40 || &pe[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = le_u32(pe, 0x3C)? as usize;
    if pe.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let opt = coff + 20;
    let magic = le_u16(pe, opt)?;
    // PE32: data directories at opt+96; PE32+: opt+112. Entry 4 is the
    // certificate table, and its "RVA" is a plain file offset.
    let dd = match magic {
        0x10B => opt + 96 + 4 * 8,
        0x20B => opt + 112 + 4 * 8,
        _ => return None,
    };
    let off = le_u32(pe, dd)? as usize;
    let size = le_u32(pe, dd + 4)? as usize;
    if off == 0 || size < 8 || off + size > pe.len() {
        return None;
    }
    // WIN_CERTIFICATE: dwLength, wRevision, wCertificateType, bCertificate[]
    let len = le_u32(pe, off)? as usize;
    let ctype = le_u16(pe, off + 6)?;
    if ctype != 0x0002 || len < 8 || off + len > pe.len() {
        return None; // 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    }
    Some(&pe[off + 8..off + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_epoch_is_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        // 51 years plus the 13 leap days of 1972..2020, then 59 days into 2021.
        assert_eq!(days_from_civil(2021, 3, 1), 18_687);
    }

    #[test]
    fn utctime_and_generalizedtime_agree() {
        // 2011-04-14T15:22:53Z, the sliding-window UTCTime encoding of a
        // GeneralizedTime for the same instant.
        let utc = b"110414152253Z";
        let generalized = b"20110414152253Z";
        assert_eq!(asn1_time_to_unix(utc), asn1_time_to_unix(generalized));
        assert_eq!(asn1_time_to_unix(generalized), Some(1_302_794_573));
        // The 2050 boundary is what makes the two-digit year meaningful:
        // 49 is 2049, 50 is 1950.
        assert_eq!(asn1_time_to_unix(b"490101000000Z"), Some(2_493_072_000));
        assert_eq!(asn1_time_to_unix(b"500101000000Z"), Some(-631_152_000));
    }

    #[test]
    fn junk_time_is_rejected() {
        assert!(asn1_time_to_unix(b"").is_none());
        assert!(asn1_time_to_unix(b"Z").is_none());
        assert!(asn1_time_to_unix(b"2114").is_none());
    }

    #[test]
    fn non_pe_yields_no_pkcs7() {
        assert!(embedded_pkcs7(b"").is_none());
        assert!(embedded_pkcs7(b"not a pe at all").is_none());
        assert!(embedded_pkcs7(&[b'M'; 256]).is_none());
        // MZ header without a PE header.
        let mut fake = vec![0u8; 0x100];
        fake[..2].copy_from_slice(b"MZ");
        fake[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(embedded_pkcs7(&fake).is_none());
    }

    #[test]
    fn a_real_signed_binary_reports_its_timestamp() {
        let Ok(meta) = std::fs::metadata("C:\\Windows\\System32\\kernel32.dll") else {
            eprintln!("kernel32.dll not reachable, skipping");
            return;
        };
        assert!(meta.is_file());
        let bytes = std::fs::read("C:\\Windows\\System32\\kernel32.dll").expect("read");

        let pkcs7 = embedded_pkcs7(&bytes).expect("kernel32.dll carries an embedded signature");
        let ts = parse_authenticode_timestamp(pkcs7).expect("a shipping binary is timestamped");

        assert_eq!(ts.kind, TimestampKind::Rfc3161);
        let t = ts.time.expect("RFC 3161 token carries a genTime");
        // 2011-2025: the certificate and its countersignature predate today.
        assert!(t > 1_300_000_000, "sane genTime, got {t}");
        assert!(t < 1_800_000_000, "not in the future, got {t}");
        assert!(ts.signer.is_some(), "TSA common name");
    }
}