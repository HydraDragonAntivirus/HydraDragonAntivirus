//! Extended PE inspection helpers that `PeInfo` does not carry:
//! the resource tree (`resource_match`, `resource_hash_any`, `resources_absent`),
//! the version-info resource (`version_info`) and the Authenticode signing
//! table (`authenticode`). All deterministic byte parsing, no OS calls.

use crate::models::PeInfo;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// One RT_* resource data blob, reached as `type / name / lang` in the tree.
#[derive(Debug, Clone)]
pub struct ResourceBlob {
    /// Numeric type id when the entry used one; from custom-type names this is
    /// the raw low-31-bit id field (the name is the identity instead).
    pub type_id: u32,
    /// `RT_ICON` / `RT_VERSION` style label, or the custom type name, used in
    /// evidence and type globs.
    pub type_label: String,
    /// Resource name when the entry resolved to a string, else the numeric id.
    pub name: String,
    pub lang_id: u32,
    /// File offset and size of the data-entry blob.
    pub data_offset: u64,
    pub data_size: u64,
}

impl ResourceBlob {
    pub fn data<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let start = self.data_offset.min(bytes.len() as u64) as usize;
        let end = self
            .data_offset
            .saturating_add(self.data_size)
            .min(bytes.len() as u64) as usize;
        &bytes[start..end]
    }
}

const RT_NAMES: &[(u32, &str)] = &[
    (1, "RT_CURSOR"),
    (2, "RT_BITMAP"),
    (3, "RT_ICON"),
    (4, "RT_MENU"),
    (5, "RT_DIALOG"),
    (6, "RT_STRING"),
    (7, "RT_FONTDIR"),
    (8, "RT_FONT"),
    (9, "RT_ACCELERATOR"),
    (10, "RT_RCDATA"),
    (11, "RT_MESSAGETABLE"),
    (12, "RT_GROUP_CURSOR"),
    (13, "RT_GROUP_ICON"),
    (14, "RT_VERSION"),
    (15, "RT_DLGINCLUDE"),
    (16, "RT_PLUGPLAY"),
    (17, "RT_VXD"),
    (18, "RT_ANICURSOR"),
    (19, "RT_ANIICON"),
    (20, "RT_HTML"),
    (21, "RT_MANIFEST"),
    (23, "RT_DLGINIT"),
    (24, "RT_TOOLBAR"),
];

fn type_label(id: u32, custom: Option<&str>) -> String {
    if let Some(name) = custom {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    RT_NAMES
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, label)| (*label).to_string())
        .unwrap_or_else(|| format!("#{id}"))
}

/// Map an RVA through the section table to a raw file offset.
pub fn rva_file_offset(pe: &PeInfo, bytes: &[u8], rva: u64) -> Option<usize> {
    if rva == 0 || bytes.is_empty() {
        return None;
    }
    for s in &pe.sections {
        let vs = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(vs) {
            let raw = s
                .raw_offset
                .saturating_add(rva - s.virtual_address);
            if raw < bytes.len() as u64 {
                return Some(raw as usize);
            }
        }
    }
    None
}

/// Walk the resource tree and flatten every data entry. Depth- and
/// entry-capped so corrupt trees cannot spin.
pub fn resource_blobs(
    pe: &PeInfo,
    bytes: &[u8],
    dir: &pefile_rs::ResourceDirectory,
) -> Vec<ResourceBlob> {
    let mut out = Vec::new();
    for (type_id, type_name, child) in dir.entries.iter().take(256) {
        match child {
            pefile_rs::ResourceEntry::Directory(names) => {
                for (name_id, name, child) in names.entries.iter().take(256) {
                    match child {
                        pefile_rs::ResourceEntry::Directory(langs) => {
                            for (lang_id, _, child) in langs.entries.iter().take(64) {
                                if let pefile_rs::ResourceEntry::Data(data) = child {
                                    if let Some(blob) = blob_from(pe, bytes, data, *type_id, type_name.as_deref(), *name_id, name.as_deref(), *lang_id) {
                                        out.push(blob);
                                    }
                                }
                            }
                        }
                        pefile_rs::ResourceEntry::Data(data) => {
                            // Language level moved into the name level
                            // (degenerate trees exist in the wild).
                            if let Some(blob) = blob_from(pe, bytes, data, *type_id, type_name.as_deref(), *name_id, name.as_deref(), 0) {
                                out.push(blob);
                            }
                        }
                    }
                    if out.len() >= 4096 {
                        return out;
                    }
                }
            }
            pefile_rs::ResourceEntry::Data(data) => {
                // Degenerate tree with no type level at all.
                if let Some(blob) = blob_from(pe, bytes, data, *type_id, type_name.as_deref(), 0, None, 0) {
                    out.push(blob);
                }
            }
        }
        if out.len() >= 4096 {
            break;
        }
    }
    out
}

/// `data.offset_to_data` is an RVA into the image; remap it through the section
/// table to a raw file offset for the blob span.
fn blob_from(
    pe: &PeInfo,
    bytes: &[u8],
    data: &pefile_rs::ResourceDataEntry,
    type_id: u32,
    type_name: Option<&str>,
    name_id: u32,
    name: Option<&str>,
    lang_id: u32,
) -> Option<ResourceBlob> {
    if data.size == 0 {
        return None;
    }
    let file_offset = rva_file_offset(pe, bytes, data.offset_to_data as u64)? as u64;
    if file_offset >= bytes.len() as u64 {
        return None;
    }
    Some(ResourceBlob {
        type_id,
        type_label: type_label(type_id & 0x7fff_ffff, type_name),
        name: match name {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => format!("{name_id}"),
        },
        lang_id,
        data_offset: file_offset,
        data_size: (data.size as u64).min(bytes.len() as u64 - file_offset),
    })
}

// ---------------------------------------------------------------------------
// VERSIONINFO resource (version_info conditions)
// ---------------------------------------------------------------------------

/// Parsed VS_VERSIONINFO contents.
#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    /// String-table fields, lower-cased names (`fileversion`, `description`).
    pub fields: BTreeMap<String, String>,
    pub file_version: Option<(u16, u16, u16, u16)>,
    pub product_version: Option<(u16, u16, u16, u16)>,
    /// A version-info resource existed (even when empty); `absent` rules flip
    /// on this being false.
    pub present: bool,
}

/// Parse the first `RT_VERSION` resource (VS_VERSIONINFO blob).
pub fn version_info(
    pe: &PeInfo,
    bytes: &[u8],
    dir: &pefile_rs::ResourceDirectory,
) -> Option<VersionInfo> {
    let blobs = resource_blobs(pe, bytes, dir);
    let version_blob = blobs.iter().find(|b| {
        b.type_id & 0x7fff_ffff == 14 || b.type_label.eq_ignore_ascii_case("RT_VERSION")
    })?;
    let data = version_blob.data(bytes);
    let mut info = parse_version_blob(data);
    info.present = true;
    Some(info)
}

/// Parse a VS_VERSIONINFO data blob. Structured per the SDK layout:
/// header `{wLength wValueLength wType key "VS_VERSION_INFO" pad`,
/// 52-byte `VS_FIXEDFILEINFO` value, then StringFileInfo / VarFileInfo
/// children, all 4-byte aligned. Block lengths cover children, value lengths
/// are raw bytes for the root and 16-bit units for string values.
pub fn parse_version_blob(data: &[u8]) -> VersionInfo {
    let mut info = VersionInfo::default();
    let mut r = Reader { data, pos: 0 };
    let Some(root) = r.header() else {
        return info;
    };
    // Root's fixed info: search for the 0xFEEF04BD signature in the value area.
    // For the root VS_VERSION_INFO block, wValueLength is in bytes (not 16-bit words).
    let value_start = r.pos;
    let value_end = (value_start + root.value_len as usize).min(data.len());
    read_fixed_info(&mut info, &data[value_start..value_end]);
    let root_end = (root.header_pos + root.block_len as usize).min(data.len());
    r.pos = value_end;
    r.align();
    // Children of the root: StringFileInfo / VarFileInfo blocks.
    while r.pos + 6 <= root_end {
        let Some(child) = r.header() else {
            break;
        };
        if child.block_len == 0 || child.header_pos + child.block_len as usize > root_end {
            break;
        }
        r.align();
        if child.key.eq_ignore_ascii_case("StringFileInfo") {
            let child_end = child.header_pos + child.block_len as usize;
            while r.pos + 6 <= child_end {
                let Some(lang_block) = r.header() else {
                    break;
                };
                if lang_block.block_len == 0
                    || lang_block.header_pos + lang_block.block_len as usize > child_end
                {
                    break;
                }
                r.align();
                let lang_end = lang_block.header_pos + lang_block.block_len as usize;
                while r.pos + 6 <= lang_end {
                    let Some(field) = r.header() else {
                        break;
                    };
                    if field.block_len == 0
                        || field.header_pos + field.block_len as usize > lang_end
                    {
                        break;
                    }
                    // Value: UTF-16 until the NUL or the field's end, aligned.
                    let value = r.read_utf16z_bounded(
                        field.value_len,
                        lang_end.saturating_sub(r.pos),
                    );
                    r.align();
                    let field = field.key.to_ascii_lowercase();
                    if !field.is_empty()
                        && !info.fields.contains_key(&field)
                        && !field.chars().all(|c| c.is_ascii_punctuation() || c.is_whitespace())
                    {
                        info.fields.insert(field, value);
                    }
                }
                r.pos = lang_end;
            }
        }
        r.pos = child.header_pos + child.block_len as usize;
        r.align();
    }
    info
}

/// Locate VS_FIXEDFILEINFO in the root value bytes and pull both version
/// quadruples: MS word = major.minor (at +8) and LS word = build.revision.
fn read_fixed_info(info: &mut VersionInfo, bytes: &[u8]) {
    // The signature sits first in a conforming file, but also tolerate writers
    // that shrank the header (skip-probe a little).
    let where_sig = bytes.windows(4).take(128).position(|w| w == [0xBD, 0x04, 0xEF, 0xFE]);
    let Some(at) = where_sig else { return };
    let rest = &bytes[at..];
    if rest.len() < 24 {
        return;
    }
    let quad = |lo: usize| -> (u16, u16, u16, u16) {
        let ms = u32::from_le_bytes(rest[lo..lo + 4].try_into().unwrap());
        let ls = u32::from_le_bytes(rest[lo + 4..lo + 8].try_into().unwrap());
        ((ms >> 16) as u16, (ms & 0xFFFF) as u16, (ls >> 16) as u16, (ls & 0xFFFF) as u16)
    };
    info.file_version = Some(quad(8));
    info.product_version = Some(quad(16));
}

/// One `{wLength wValueLength wType key}` header.
struct BlockHeader {
    header_pos: usize,
    block_len: u16,
    value_len: u16,
    /// wType: 1 = text value, 0 = binary (VarFileInfo); consumed implicitly by
    /// how the value area is decoded downstream.
    #[allow(dead_code)]
    kind: u16,
    key: String,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u16(&mut self) -> u16 {
        let v = self
            .data
            .get(self.pos..self.pos + 2)
            .map(|s| u16::from_le_bytes([s[0], s[1]]))
            .unwrap_or(0);
        self.pos += 2;
        v
    }

    fn align(&mut self) {
        self.pos = self.pos.div_ceil(4) * 4;
    }

    /// Read one "}": header+key block. Length counts from header_pos.
    fn header(&mut self) -> Option<BlockHeader> {
        let header_pos = self.pos;
        if header_pos + 6 > self.data.len() {
            return None;
        }
        let block_len = self.u16();
        let value_len = self.u16();
        let kind = self.u16();
        let mut units = Vec::new();
        while self.pos + 2 <= self.data.len() {
            let w = self.u16();
            if w == 0 {
                break;
            }
            units.push(w);
            if units.len() > 256 {
                break;
            }
        }
        self.align();
        Some(BlockHeader {
            header_pos,
            block_len,
            value_len,
            kind,
            key: String::from_utf16_lossy(&units),
        })
    }

    /// Value of a string block: up to `bytes_avail` bytes / `value_len` u16
    /// units ending at the UTF-16 NUL. Handles both writers that store the
    /// length in words and ones that store bytes (padding NUL ignored either
    /// way).
    fn read_utf16z_bounded(&mut self, value_len: u16, bytes_avail: usize) -> String {
        let limit = (value_len as usize).saturating_mul(2).min(bytes_avail.min(4096));
        let mut units = Vec::new();
        while units.len() * 2 + 2 <= limit {
            let w = self.u16();
            if w == 0 {
                break;
            }
            units.push(w);
        }
        String::from_utf16_lossy(&units)
    }
}

// ---------------------------------------------------------------------------
// Authenticode signing block (authenticode conditions)
// ---------------------------------------------------------------------------

/// What could be read from the security directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authenticode {
    /// A WIN_CERTIFICATE blob of type PKCS_SIGNED_DATA existed: the PE claims
    /// a code-signing signature. `SIGNED=FALSE` / `DIGISIG=FALSE` rules match
    /// when this is false.
    pub has_certificate: bool,
    /// Subject / organization strings seen in the signing certificates.
    pub subjects: Vec<String>,
}

/// IMAGE_DIRECTORY_ENTRY_SECURITY = 4. Its "RVA" is conventionally a file
/// offset, unlike all other directories.
const SECURITY_DIRECTORY: usize = 4;

/// Read the security directory. `None` for a non-PE input; `has_certificate:
/// false` for an unsigned PE (the `DIGISIG=FALSE` case).
pub fn authenticode(bytes: &[u8], pe: &PeInfo) -> Option<Authenticode> {
    let mut out = Authenticode::default();
    let (rva, size) = pe.data_directories.get(SECURITY_DIRECTORY).copied()?;
    if size == 0 || bytes.is_empty() {
        return Some(out);
    }
    let mut off = rva as usize; // file offset, by WIN_CERTIFICATE convention
    if off >= bytes.len() {
        return Some(out);
    }
    let end = (off + size as usize).min(bytes.len());
    // The region holds one or more chained WIN_CERTIFICATEs.
    let mut guard = 0;
    while off + 8 <= end && guard < 64 {
        guard += 1;
        let total_len = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?) as usize;
        let w_revision = u16::from_le_bytes(bytes[off + 4..off + 6].try_into().ok()?);
        let w_certificate_type = u16::from_le_bytes(bytes[off + 6..off + 8].try_into().ok()?);
        let _ = w_revision;
        if total_len < 8 {
            break;
        }
        if w_certificate_type == 2 && off + total_len <= end {
            let blob = &bytes[off + 8..off + total_len];
            out.has_certificate = true;
            out.subjects = pkcs7_subjects(blob);
            // First PKCS blob wins; ignore later re-signings.
            break;
        }
        // Chain to the next certificate, aligned to 8 as required.
        off += total_len.div_ceil(8) * 8;
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Extract the subject CN / O / OU strings out of a SignedData DER blob.
/// Just enough of an ASN.1 reader to reach X.509 names, nothing more.
pub fn pkcs7_subjects(blob: &[u8]) -> Vec<String> {
    let mut subjects = Vec::new();
    let mut walk = Der { data: blob, pos: 0 };
    let Some((0x30, ci_span)) = walk.tlv() else {
        return subjects;
    };
    let ci_bytes = &blob[ci_span.start..ci_span.end];
    let mut ci = Der { data: ci_bytes, pos: 0 };
    // ContentInfo: OID + [0] explicit content.
    let Some((_, _oid)) = ci.tlv() else {
        return subjects;
    };
    let Some((tag, inner)) = ci.tlv() else {
        return subjects;
    };
    if tag != 0xA0 {
        return subjects;
    }
    let content = &ci_bytes[inner.start..inner.end];
    let mut signed_data_outer = Der { data: content, pos: 0 };
    let Some((0x30, sd_span)) = signed_data_outer.tlv() else {
        return subjects;
    };
    let sd_bytes = &content[sd_span.start..sd_span.end];
    let mut signed_data = Der { data: sd_bytes, pos: 0 };
    // SignedData: version INTEGER, digestAlgs SET, contentInfo SEQ,
    // [0] certificates, [1] crls, signerInfos SET.
    let _ = signed_data.tlv(); // version
    let _ = signed_data.tlv(); // digestAlgs
    let _ = signed_data.tlv(); // contentInfo
    let mut guard = 0;
    while let Some((tag, inner)) = signed_data.tlv() {
        guard += 1;
        if guard > 4 {
            break;
        }
        match tag {
            0xA0 => {
                let certs = &sd_bytes[inner.start..inner.end];
                let mut list = Der { data: certs, pos: 0 };
                let mut cap = 0;
                while let Some((_, cert)) = list.tlv() {
                    cap += 1;
                    if cap > 32 {
                        break;
                    }
                    let cert_inner = &certs[cert.start..cert.end];
                    subjects.extend(collect_name_strings_inner(cert_inner));
                }
                break;
            }
            0x31 => {
                // signerInfos came before certificates or afterwards: stop.
                break;
            }
            _ => continue,
        }
    }
    subjects.sort();
    subjects.dedup();
    subjects
}

/// A minimal DER TLV reader over a borrowed slice.
struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    /// Read one TLV; returns `(tag, span of content)`.
    fn tlv(&mut self) -> Option<(u8, Span)> {
        let mut at = self.pos;
        let tag = *self.data.get(at)?;
        at += 1;
        if tag & 0x1F == 0x1F {
            return None; // multi-byte tags: not seen inside PKCS7 structures
        }
        let len = read_length(self.data, &mut at)?;
        let content_start = at;
        let content_end = content_start.checked_add(len)?;
        if content_end > self.data.len() {
            return None;
        }
        self.pos = content_end;
        Some((tag, Span { start: content_start, end: content_end }))
    }
}

fn read_length(data: &[u8], at: &mut usize) -> Option<usize> {
    let first = *data.get(*at)?;
    *at += 1;
    if first < 0x80 {
        return Some(first as usize);
    }
    let count = (first & 0x7F) as usize;
    if count == 0 || count > 4 {
        return None;
    }
    let mut len = 0usize;
    for _ in 0..count {
        let b = *data.get(*at)?;
        *at += 1;
        len = (len << 8) | b as usize;
    }
    Some(len)
}

/// Pull CN / O / OU attribute strings out of the body of an X.509 Certificate
/// SEQUENCE (`tbsCertificate, signatureAlgorithm, signatureValue`).
fn collect_name_strings_inner(cert_body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut walk = Der { data: cert_body, pos: 0 };
    // Certificate body starts with tbsCertificate SEQUENCE (0x30)
    let Some((tag, tbs_span)) = walk.tlv() else { return out };
    if tag != 0x30 {
        return out;
    }
    let tbs = &cert_body[tbs_span.start..tbs_span.end];
    let mut tbs_walk = Der { data: tbs, pos: 0 };
    let mut names: Vec<Span> = Vec::new();
    let mut guard = 0;
    while guard < 16 {
        guard += 1;
        let Some((tag, span)) = tbs_walk.tlv() else { break };
        match tag {
            0x30 => names.push(span), // Name issuer/validity/spki; validity is a SEQ of two times
            0xA0 => continue,         // version
            _ => {}
        }
        if names.len() >= 2 {
            // The first two SEQs after serial+sig are issuer then validity.
            // We keep scanning because the exact ordering varies; below we
            // filter by which spans hold SEQ-of-SEQ attribute pairs.
        }
        if names.len() > 4 {
            break;
        }
    }
    for span in names {
        let name = &tbs[span.start..span.end];
        if let Some(values) = x509_name_values(name) {
            out.extend(values);
        }
    }
    out
}

/// X.509 DistinguishedName := SEQ of SET of SEQ { OID, any-typed value }.
/// Returns the CN / O / OU values, else `None` when the span is something else
/// (validity SEQ of UTCTime pairs, for instance).
fn x509_name_values(name: &[u8]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut rdn_seq = Der { data: name, pos: 0 };
    let mut saw_attr = false;
    while let Some((_, rdn)) = rdn_seq.tlv() {
        let attrs = &name[rdn.start..rdn.end];
        let mut attr_set = Der { data: attrs, pos: 0 };
        while let Some((_, attr)) = attr_set.tlv() {
            let attr = &attrs[attr.start..attr.end];
            let mut pair = Der { data: attr, pos: 0 };
            let Some((_, oid)) = pair.tlv() else { continue };
            if !is_name_oid(&attr[oid.start..oid.end]) {
                continue;
            }
            saw_attr = true;
            if let Some((value_tag, value_span)) = pair.tlv() {
                let raw = &attr[value_span.start..value_span.end];
                let text: Option<String> = match value_tag {
                    0x13 => Some(String::from_utf8_lossy(raw).to_string()),
                    0x0C => Some(String::from_utf8_lossy(raw).to_string()),
                    0x1E => Some(String::from_utf16_lossy(
                        &raw.chunks_exact(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    )),
                    _ => None,
                };
                if let Some(t) = text {
                    let t = t.trim().to_string();
                    if !t.is_empty() {
                        out.push(t);
                    }
                }
            }
        }
    }
    saw_attr.then_some(out)
}

fn is_name_oid(oid: &[u8]) -> bool {
    // DER-encoded 2.5.4.3 = 55 04 03 (CN), 2.5.4.10 = 55 04 0A (O),
    // 2.5.4.11 = 55 04 0B (OU).
    matches!(oid, [0x55, 0x04, 0x03] | [0x55, 0x04, 0x0A] | [0x55, 0x04, 0x0B])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_type_labels() {
        assert_eq!(type_label(14, None), "RT_VERSION");
        assert_eq!(type_label(10, None), "RT_RCDATA");
        assert_eq!(type_label(99, None), "#99");
        assert_eq!(type_label(1033, Some("BINARY")), "BINARY");
    }

    #[test]
    fn name_oid_matches() {
        assert!(is_name_oid(&[0x55, 0x04, 0x03]));
        assert!(!is_name_oid(&[0x55, 0x04, 0x04]));
    }

    #[test]
    fn version_blob_empty_is_absent() {
        assert_eq!(parse_version_blob(&[0, 0, 0]).fields.len(), 0);
    }
}
