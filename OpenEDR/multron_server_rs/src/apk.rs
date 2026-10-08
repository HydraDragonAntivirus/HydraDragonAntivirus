//! Minimal APK reader for the smart whitelist and VirusKovAlyzer reports.
//!
//! * ZIP central directory -> entries (stored / deflate), with size caps.
//! * `classes*.dex` concatenated in order (the code; its TLSH is what we compare).
//! * Binary AndroidManifest.xml (AXML): package, permissions, components.
//! * Signing certificates: APK Signature Scheme v3/v2 block, else v1 (META-INF/*.RSA|DSA|EC).
//!
//! Everything is best effort and bounds-checked: a malformed or obfuscated APK simply
//! yields `None`, and without an `ApkInfo` the smart whitelist never applies.

use std::collections::BTreeSet;
use std::io::Read;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_DEX_TOTAL: usize = 128 * 1024 * 1024;
const MAX_ENTRY: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ApkInfo {
    pub package: String,
    /// SHA-256 of each signer's certificate (DER), sorted.
    pub signers: Vec<String>,
    /// "v3", "v2" or "v1".
    pub signature_scheme: String,
    /// Android debug key or AOSP test key: anyone can sign with these.
    pub test_key: bool,
    pub permissions: BTreeSet<String>,
    pub activities: u32,
    pub services: BTreeSet<String>,
    pub receivers: BTreeSet<String>,
    pub providers: BTreeSet<String>,
    pub dex_count: u32,
    pub native_libs: BTreeSet<String>,
}

// ------------------------------------------------------------------ ZIP

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    method: u16,
    csize: usize,
    usize_: usize,
    local: usize,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    let b = d.get(o..o.checked_add(8)?)?;
    Some(u64::from_le_bytes(b.try_into().ok()?))
}

/// (end-of-central-directory offset, central directory offset, entry count)
fn eocd(data: &[u8]) -> Option<(usize, usize, usize)> {
    if data.len() < 22 {
        return None;
    }
    let from = data.len().saturating_sub(65_557);
    let e = (from..=data.len() - 22).rev().find(|&i| data[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])?;
    Some((e, u32_at(data, e + 16)? as usize, u16_at(data, e + 10)? as usize))
}

pub fn entries(data: &[u8]) -> Option<Vec<Entry>> {
    if !data.starts_with(b"PK\x03\x04") {
        return None;
    }
    let (_, mut off, count) = eocd(data)?;
    let mut out = Vec::new();
    for _ in 0..count.min(200_000) {
        if u32_at(data, off)? != 0x0201_4b50 {
            break;
        }
        let nlen = u16_at(data, off + 28)? as usize;
        out.push(Entry {
            name: String::from_utf8_lossy(data.get(off + 46..off + 46 + nlen)?).into_owned(),
            method: u16_at(data, off + 10)?,
            csize: u32_at(data, off + 20)? as usize,
            usize_: u32_at(data, off + 24)? as usize,
            local: u32_at(data, off + 42)? as usize,
        });
        off += 46 + nlen + u16_at(data, off + 30)? as usize + u16_at(data, off + 32)? as usize;
    }
    (!out.is_empty()).then_some(out)
}

pub fn read_entry(data: &[u8], e: &Entry, cap: usize) -> Option<Vec<u8>> {
    if u32_at(data, e.local)? != 0x0403_4b50 {
        return None;
    }
    let start = e.local + 30 + u16_at(data, e.local + 26)? as usize + u16_at(data, e.local + 28)? as usize;
    let comp = data.get(start..start.checked_add(e.csize)?)?;
    match e.method {
        0 => Some(comp[..comp.len().min(cap)].to_vec()),
        8 => {
            let mut buf = Vec::with_capacity(e.usize_.min(cap));
            flate2::read::DeflateDecoder::new(comp).take(cap as u64).read_to_end(&mut buf).ok()?;
            Some(buf)
        }
        _ => None,
    }
}

fn dex_order(name: &str) -> Option<u32> {
    let mid = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    if mid.is_empty() { Some(1) } else { mid.parse().ok() }
}

/// `classes.dex`, `classes2.dex`, ... concatenated in order.
pub fn dex_code(data: &[u8]) -> Option<Vec<u8>> {
    let mut dex: Vec<(u32, Entry)> = entries(data)?.into_iter().filter_map(|e| dex_order(&e.name).map(|o| (o, e))).collect();
    dex.sort_by_key(|x| x.0);
    let mut out = Vec::new();
    for (_, e) in dex {
        let room = MAX_DEX_TOTAL.saturating_sub(out.len());
        if room == 0 {
            break;
        }
        if let Some(b) = read_entry(data, &e, room) {
            out.extend_from_slice(&b);
        }
    }
    (!out.is_empty()).then_some(out)
}

// ------------------------------------------------------------------ AXML

const RES_STRING_POOL: u16 = 0x0001;
const RES_XML_RESOURCE_MAP: u16 = 0x0180;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const ATTR_NAME_ID: u32 = 0x0101_0003; // android:name

fn string_pool(d: &[u8], c: usize) -> Option<Vec<String>> {
    let hsize = u16_at(d, c + 2)? as usize;
    let count = (u32_at(d, c + 8)? as usize).min(500_000);
    let utf8 = u32_at(d, c + 16)? & 0x100 != 0;
    let strings_start = c + u32_at(d, c + 20)? as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let Some(o) = u32_at(d, c + hsize + i * 4) else { break };
        let p = strings_start + o as usize;
        let s = if utf8 {
            let mut q = p;
            let b = *d.get(q)?;
            q += if b & 0x80 != 0 { 2 } else { 1 }; // UTF-16 length, skipped
            let b0 = *d.get(q)? as usize;
            let (len, skip) = if b0 & 0x80 != 0 { (((b0 & 0x7f) << 8) | *d.get(q + 1)? as usize, 2) } else { (b0, 1) };
            String::from_utf8_lossy(d.get(q + skip..q + skip + len).unwrap_or(&[])).into_owned()
        } else {
            let l0 = u16_at(d, p)? as usize;
            let (len, skip) = if l0 & 0x8000 != 0 { ((((l0 & 0x7fff) << 16) | u16_at(d, p + 2)? as usize), 4) } else { (l0, 2) };
            let raw = d.get(p + skip..p + skip + len.min(65_536) * 2).unwrap_or(&[]);
            String::from_utf16_lossy(&raw.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect::<Vec<_>>())
        };
        out.push(s);
    }
    Some(out)
}

struct Manifest {
    package: String,
    permissions: BTreeSet<String>,
    activities: u32,
    services: BTreeSet<String>,
    receivers: BTreeSet<String>,
    providers: BTreeSet<String>,
}

fn parse_axml(d: &[u8]) -> Option<Manifest> {
    if u16_at(d, 0)? != 0x0003 {
        return None;
    }
    let total = (u32_at(d, 4)? as usize).min(d.len());
    let mut strings: Vec<String> = Vec::new();
    let mut resmap: Vec<u32> = Vec::new();
    let mut m = Manifest {
        package: String::new(),
        permissions: BTreeSet::new(),
        activities: 0,
        services: BTreeSet::new(),
        receivers: BTreeSet::new(),
        providers: BTreeSet::new(),
    };
    let str_at = |strings: &Vec<String>, i: u32| strings.get(i as usize).cloned().unwrap_or_default();
    let mut c = u16_at(d, 2)? as usize;
    while c + 8 <= total {
        let ty = u16_at(d, c)?;
        let hsize = u16_at(d, c + 2)? as usize;
        let size = u32_at(d, c + 4)? as usize;
        if size < 8 || c + size > total {
            break;
        }
        match ty {
            RES_STRING_POOL if strings.is_empty() => strings = string_pool(d, c)?,
            RES_XML_RESOURCE_MAP => {
                resmap = (c + hsize..c + size).step_by(4).filter_map(|o| u32_at(d, o)).collect();
            }
            RES_XML_START_ELEMENT => {
                let ext = c + hsize;
                let tag = str_at(&strings, u32_at(d, ext + 4)?);
                let attr_start = u16_at(d, ext + 8)? as usize;
                let attr_size = (u16_at(d, ext + 10)? as usize).max(20);
                let attr_count = (u16_at(d, ext + 12)? as usize).min(1000);
                let mut name_val = String::new();
                for i in 0..attr_count {
                    let a = ext + attr_start + i * attr_size;
                    let Some(an) = u32_at(d, a + 4) else { break };
                    let raw = u32_at(d, a + 8)?;
                    let dtype = *d.get(a + 15)?;
                    let data = u32_at(d, a + 16)?;
                    let val = if raw != u32::MAX {
                        str_at(&strings, raw)
                    } else if dtype == 0x03 {
                        str_at(&strings, data)
                    } else {
                        continue;
                    };
                    let aname = str_at(&strings, an);
                    let is_name = resmap.get(an as usize).copied() == Some(ATTR_NAME_ID)
                        || (resmap.get(an as usize).is_none() && aname == "name");
                    if tag == "manifest" && aname == "package" && resmap.get(an as usize).is_none() {
                        m.package = val.clone();
                    }
                    if is_name {
                        name_val = val;
                    }
                }
                let full = |n: &str, pkg: &str| if n.starts_with('.') { format!("{pkg}{n}") } else { n.to_string() };
                match tag.as_str() {
                    "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" if !name_val.is_empty() => {
                        m.permissions.insert(name_val);
                    }
                    "activity" | "activity-alias" => m.activities += 1,
                    "service" if !name_val.is_empty() => {
                        m.services.insert(full(&name_val, &m.package));
                    }
                    "receiver" if !name_val.is_empty() => {
                        m.receivers.insert(full(&name_val, &m.package));
                    }
                    "provider" if !name_val.is_empty() => {
                        m.providers.insert(full(&name_val, &m.package));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        c += size;
    }
    (!m.package.is_empty()).then_some(m)
}

// ------------------------------------------------------------------ signatures

/// (tag, content start, content end, element end)
fn der_tlv(d: &[u8], o: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *d.get(o)?;
    let l0 = *d.get(o + 1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *d.get(o + 2 + i)? as usize;
        }
        (l, 2 + n)
    };
    let start = o + hdr;
    let end = start.checked_add(len)?;
    (end <= d.len()).then_some((tag, start, end, end))
}

/// First certificate of a PKCS#7 SignedData (v1 META-INF/*.RSA|DSA|EC).
fn pkcs7_first_cert(d: &[u8]) -> Option<Vec<u8>> {
    let (_, s, _, _) = der_tlv(d, 0)?; // ContentInfo SEQUENCE
    let (_, _, _, oid_end) = der_tlv(d, s)?; // contentType OID
    let (t, s0, _, _) = der_tlv(d, oid_end)?; // [0] EXPLICIT
    if t != 0xa0 {
        return None;
    }
    let (_, sd, sd_end, _) = der_tlv(d, s0)?; // SignedData SEQUENCE
    let mut o = sd;
    for _ in 0..3 {
        o = der_tlv(d, o)?.3; // version, digestAlgorithms, contentInfo
    }
    while o < sd_end {
        let (t, cs, _, end) = der_tlv(d, o)?;
        if t == 0xa0 {
            let (_, _, _, cert_end) = der_tlv(d, cs)?;
            return Some(d[cs..cert_end].to_vec());
        }
        o = end;
    }
    None
}

/// Length-prefixed (u32) items of a v2/v3 sequence.
fn lp_items(d: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    let mut o = 0usize;
    while let Some(l) = u32_at(d, o) {
        let s = o + 4;
        let Some(item) = d.get(s..s + l as usize) else { break };
        v.push(item);
        o = s + l as usize;
        if v.len() > 64 {
            break;
        }
    }
    v
}

fn lp_first(d: &[u8]) -> Option<&[u8]> {
    let l = u32_at(d, 0)? as usize;
    d.get(4..4 + l)
}

/// First certificate of every signer in an APK Signature Scheme v2/v3 block value.
fn v2_certs(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some(signers) = lp_first(value) else { return out };
    for signer in lp_items(signers) {
        let Some(signed_data) = lp_first(signer) else { continue };
        let Some(digests_len) = u32_at(signed_data, 0) else { continue };
        let Some(rest) = signed_data.get(4 + digests_len as usize..) else { continue };
        let Some(certs) = lp_first(rest) else { continue };
        if let Some(c) = lp_items(certs).first() {
            out.push(c.to_vec());
        }
    }
    out
}

/// (scheme, certificate DERs)
fn signing_certs(data: &[u8], entries: &[Entry]) -> Option<(String, Vec<Vec<u8>>)> {
    let (_, cd, _) = eocd(data)?;
    if cd >= 32 && data.get(cd - 16..cd) == Some(b"APK Sig Block 42") {
        let size = u64_at(data, cd - 24)? as usize;
        if let Some(start) = cd.checked_sub(size + 8) {
            let (mut v3, mut v2) = (Vec::new(), Vec::new());
            let mut o = start + 8;
            while o + 12 <= cd - 24 {
                let len = u64_at(data, o)? as usize;
                let id = u32_at(data, o + 8)?;
                let Some(val) = data.get(o + 12..(o + 8).checked_add(len)?) else { break };
                match id {
                    0xf053_68c0 | 0x1b93_ad61 => v3 = v2_certs(val),
                    0x7109_871a => v2 = v2_certs(val),
                    _ => {}
                }
                o = o + 8 + len;
            }
            if !v3.is_empty() {
                return Some(("v3".into(), v3));
            }
            if !v2.is_empty() {
                return Some(("v2".into(), v2));
            }
        }
    }
    let mut v1 = Vec::new();
    for e in entries {
        let n = e.name.to_ascii_uppercase();
        if n.starts_with("META-INF/") && (n.ends_with(".RSA") || n.ends_with(".DSA") || n.ends_with(".EC")) {
            if let Some(cert) = read_entry(data, e, MAX_ENTRY).as_deref().and_then(pkcs7_first_cert) {
                v1.push(cert);
            }
        }
    }
    (!v1.is_empty()).then(|| ("v1".into(), v1))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------------ entry point

pub fn parse(data: &[u8]) -> Option<ApkInfo> {
    let entries = entries(data)?;
    let manifest = entries.iter().find(|e| e.name == "AndroidManifest.xml")?;
    let m = parse_axml(&read_entry(data, manifest, MAX_ENTRY)?)?;
    let (scheme, certs) = signing_certs(data, &entries).unwrap_or_default();
    let mut signers: Vec<String> = certs.iter().map(|c| hex::encode(Sha256::digest(c))).collect();
    signers.sort();
    signers.dedup();
    let test_key = certs.iter().any(|c| contains(c, b"Android Debug") || contains(c, b"android@android.com"));
    Some(ApkInfo {
        package: m.package,
        signers,
        signature_scheme: scheme,
        test_key,
        permissions: m.permissions,
        activities: m.activities,
        services: m.services,
        receivers: m.receivers,
        providers: m.providers,
        dex_count: entries.iter().filter(|e| dex_order(&e.name).is_some()).count() as u32,
        native_libs: entries.iter().filter(|e| e.name.starts_with("lib/") && e.name.ends_with(".so")).map(|e| e.name.clone()).collect(),
    })
}
