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

/// winuser.h `RT_*` ids (`RT_GROUP_x` = `RT_x` + 11, hence the gaps at 13 and 15);
/// `RT_DLGINIT` / `RT_TOOLBAR` are the MFC ones.
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
    (14, "RT_GROUP_ICON"),
    (16, "RT_VERSION"),
    (17, "RT_DLGINCLUDE"),
    (19, "RT_PLUGPLAY"),
    (20, "RT_VXD"),
    (21, "RT_ANICURSOR"),
    (22, "RT_ANIICON"),
    (23, "RT_HTML"),
    (24, "RT_MANIFEST"),
    (240, "RT_DLGINIT"),
    (241, "RT_TOOLBAR"),
];

fn type_label(id: u32, custom: Option<&str>) -> String {
    if let Some(name) = custom && !name.is_empty() {
        return name.to_string();
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
                                if let pefile_rs::ResourceEntry::Data(data) = child
                                    && let Some(blob) = blob_from(pe, bytes, data, *type_id, type_name.as_deref(), *name_id, name.as_deref(), *lang_id)
                                {
                                    out.push(blob);
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
#[allow(clippy::too_many_arguments)]
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

pub type Version4 = (u16, u16, u16, u16);

/// A version bound written in a rule: `a[.b[.c[.d]]]`, digits only, missing parts 0.
pub fn parse_version_bound(s: &str) -> Option<Version4> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut v = [0u16; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v[i] = p.parse().ok()?;
    }
    Some((v[0], v[1], v[2], v[3]))
}

/// The version a file states in its string table (`"10.0.19041.1 (WinBuild…)"`,
/// `"1, 2, 3, 4"`): the leading numbers, separated by dots or commas.
pub fn version_from_text(s: &str) -> Option<Version4> {
    let mut v = [0u16; 4];
    let mut n = 0;
    for part in s.trim().split(['.', ',']).map(str::trim) {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() || n == 4 {
            break;
        }
        v[n] = digits.parse().ok()?;
        n += 1;
        if digits.len() != part.len() {
            break;
        }
    }
    (n > 0).then_some((v[0], v[1], v[2], v[3]))
}

impl VersionInfo {
    /// File version: the numeric `VS_FIXEDFILEINFO` one, else the string table's.
    pub fn file_version4(&self) -> Option<Version4> {
        self.file_version.or_else(|| self.fields.get("fileversion").and_then(|s| version_from_text(s)))
    }

    /// Product version, same sources as `file_version4`.
    pub fn product_version4(&self) -> Option<Version4> {
        self.product_version.or_else(|| self.fields.get("productversion").and_then(|s| version_from_text(s)))
    }
}

/// Parse the first `RT_VERSION` resource (VS_VERSIONINFO blob).
pub fn version_info(
    pe: &PeInfo,
    bytes: &[u8],
    dir: &pefile_rs::ResourceDirectory,
) -> Option<VersionInfo> {
    let blobs = resource_blobs(pe, bytes, dir);
    let version_blob = blobs.iter().find(|b| {
        b.type_id & 0x7fff_ffff == 16 || b.type_label.eq_ignore_ascii_case("RT_VERSION")
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
                        &raw.as_chunks::<2>().0.iter()
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

// ---------------------------------------------------------------------------
// Code Integrity identity (authentihash_any, page_hash_any, pe_subsystem and
// the authenticode cert_tbs_any / publisher / oem_id keys)
//
// These are the values Windows Code Integrity (WDAC / App Control for
// Business) keys its rules on, so the Microsoft vulnerable driver blocklist
// and any other CI policy can be expressed as rules:
// * `<Deny Hash=...>` "Hash Sha1/Sha256": the Authenticode image digest.
// * `<Deny Hash=...>` "Hash Page Sha1/Sha256": the digest of the first 4 KiB
//   page (headers only), as the first entry of `SpcPageHashes`.
// * `<Signer>` `<CertRoot Type="TBS">`: digest of a chain certificate's
//   DER `tbsCertificate`, with the algorithm of that certificate's signature
//   (40 / 64 / 96 hex = SHA-1 / SHA-256 / SHA-384).
// * `<CertPublisher>`: CN of the leaf (signing) certificate.
// * `<CertOemID>`: `SpcSpOpusInfo.programName` of the signer (the OEM name
//   Microsoft puts into WHCP / attestation signatures).
// All four were checked byte for byte against `New-CIPolicy -Level Hash`,
// `FilePublisher` and `WHQLPublisher` output.
// ---------------------------------------------------------------------------

/// Offsets the Authenticode digests are built from.
struct PeDigestLayout {
    checksum: usize,
    /// IMAGE_DIRECTORY_ENTRY_SECURITY entry; `None` with fewer than 5 directories.
    security_entry: Option<usize>,
    size_of_headers: usize,
    /// End of the image bytes covered by the digest (the attribute certificate
    /// table and anything after it are left out).
    image_end: usize,
    subsystem: u16,
}

fn rd_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn rd_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn pe_digest_layout(bytes: &[u8]) -> Option<PeDigestLayout> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew = rd_u32(bytes, 0x3C)? as usize;
    if bytes.get(e_lfanew..e_lfanew.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let oh = e_lfanew + 24;
    let dir_start = match rd_u16(bytes, oh)? {
        0x10B => oh + 96,
        0x20B => oh + 112,
        _ => return None,
    };
    let checksum = oh + 64;
    let subsystem = rd_u16(bytes, oh + 68)?;
    let size_of_headers = rd_u32(bytes, oh + 60)? as usize;
    let dir_count = rd_u32(bytes, dir_start - 4)?;
    let security_entry = (dir_count > 4 && dir_start + 40 <= bytes.len()).then_some(dir_start + 32);
    let mut image_end = bytes.len();
    if let Some(se) = security_entry {
        let cert_off = rd_u32(bytes, se)? as usize;
        let cert_size = rd_u32(bytes, se + 4)?;
        if cert_size != 0 && cert_off >= se + 8 && cert_off <= bytes.len() {
            image_end = cert_off;
        }
    }
    if checksum + 4 > image_end || security_entry.is_some_and(|se| se + 8 > image_end) {
        return None;
    }
    Some(PeDigestLayout { checksum, security_entry, size_of_headers, image_end, subsystem })
}

/// Feed `bytes[..end]` without the checksum and the security directory entry.
fn feed_digest_ranges(bytes: &[u8], l: &PeDigestLayout, end: usize, mut feed: impl FnMut(&[u8])) {
    feed(&bytes[..l.checksum]);
    match l.security_entry {
        Some(se) => {
            feed(&bytes[l.checksum + 4..se]);
            feed(&bytes[se + 8..end]);
        }
        None => feed(&bytes[l.checksum + 4..end]),
    }
}

/// `IMAGE_OPTIONAL_HEADER.Subsystem` (1 = native, the subsystem of kernel drivers).
pub fn pe_subsystem(bytes: &[u8]) -> Option<u16> {
    pe_digest_layout(bytes).map(|l| l.subsystem)
}

/// Authenticode image digests and first-page digests, lowercase hex.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CiImageHashes {
    pub authentihash_sha1: String,
    pub authentihash_sha256: String,
    /// `None` when the headers do not fit in the first page.
    pub page_sha1: Option<String>,
    pub page_sha256: Option<String>,
}

const CI_PAGE_SIZE: usize = 4096;

pub fn ci_image_hashes(bytes: &[u8]) -> Option<CiImageHashes> {
    use sha2::{Digest, Sha256};
    let l = pe_digest_layout(bytes)?;
    let mut s1 = crate::utils::hash::Sha1::new();
    let mut s256 = Sha256::new();
    feed_digest_ranges(bytes, &l, l.image_end, |part| {
        s1.update(part);
        s256.update(part);
    });
    let mut out = CiImageHashes {
        authentihash_sha1: hex::encode(s1.finalize()),
        authentihash_sha256: hex::encode(s256.finalize()),
        ..Default::default()
    };
    let soh = l.size_of_headers;
    let headers_fit = soh <= CI_PAGE_SIZE
        && soh <= l.image_end
        && soh >= l.security_entry.map_or(l.checksum + 4, |se| se + 8);
    if headers_fit {
        let mut p1 = crate::utils::hash::Sha1::new();
        let mut p256 = Sha256::new();
        let zeros = [0u8; CI_PAGE_SIZE];
        feed_digest_ranges(bytes, &l, soh, |part| {
            p1.update(part);
            p256.update(part);
        });
        p1.update(&zeros[..CI_PAGE_SIZE - soh]);
        p256.update(&zeros[..CI_PAGE_SIZE - soh]);
        out.page_sha1 = Some(hex::encode(p1.finalize()));
        out.page_sha256 = Some(hex::encode(p256.finalize()));
    }
    Some(out)
}

/// One Authenticode signature (the primary one or a nested one).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CiSignature {
    /// CN of the signing certificate (WDAC `CertPublisher`).
    pub publisher: Option<String>,
    /// `SpcSpOpusInfo.programName` (WDAC `CertOemID`).
    pub oem_id: Option<String>,
    /// SHA-1, SHA-256 and SHA-384 of the `tbsCertificate` of every certificate
    /// from the leaf up the chain, as far as the embedded certificates reach
    /// (lowercase hex). Every embedded certificate when the leaf is not found.
    pub chain_tbs: Vec<String>,
}

struct CertView<'a> {
    tbs: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
}

/// DER-encoded OIDs (content bytes).
const OID_SPC_SP_OPUS_INFO: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0C];
const OID_SPC_NESTED_SIGNATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01];

impl<'a> Der<'a> {
    /// Like [`Der::tlv`], also returning the whole element (header included).
    fn tlv_full(&mut self) -> Option<(u8, &'a [u8], &'a [u8])> {
        let start = self.pos;
        let (tag, span) = self.tlv()?;
        Some((tag, &self.data[start..span.end], &self.data[span.start..span.end]))
    }
}

fn der_children(content: &[u8]) -> Vec<(u8, &[u8], &[u8])> {
    let mut walk = Der { data: content, pos: 0 };
    let mut out = Vec::new();
    while out.len() < 256 {
        let Some(item) = walk.tlv_full() else { break };
        out.push(item);
    }
    out
}

fn parse_cert(cert_content: &[u8]) -> Option<CertView<'_>> {
    let (tag, tbs_full, tbs) = *der_children(cert_content).first()?;
    if tag != 0x30 {
        return None;
    }
    let fields = der_children(tbs);
    let skip = usize::from(fields.first()?.0 == 0xA0); // [0] version
    // serialNumber, signature, issuer, validity, subject
    let serial = fields.get(skip)?;
    let issuer = fields.get(skip + 2)?;
    let subject = fields.get(skip + 4)?;
    (serial.0 == 0x02 && issuer.0 == 0x30 && subject.0 == 0x30).then_some(CertView {
        tbs: tbs_full,
        serial: serial.2,
        issuer: issuer.1,
        subject: subject.1,
    })
}

fn decode_der_string(tag: u8, raw: &[u8]) -> Option<String> {
    let text = match tag {
        // UTF8String, PrintableString, IA5String, T61String (Latin-1 in practice)
        0x0C | 0x13 | 0x16 => String::from_utf8_lossy(raw).into_owned(),
        0x14 => raw.iter().map(|&b| b as char).collect(),
        // BMPString
        0x1E => String::from_utf16_lossy(
            &raw.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect::<Vec<_>>(),
        ),
        _ => return None,
    };
    let text = text.trim_end_matches('\0').trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// The commonName of an X.509 Name (whole TLV).
fn name_common_name(name_full: &[u8]) -> Option<String> {
    let (_, _, rdns) = *der_children(name_full).first()?;
    for (_, _, rdn) in der_children(rdns) {
        for (_, _, attr) in der_children(rdn) {
            let parts = der_children(attr);
            if let [(0x06, _, oid), (tag, _, value), ..] = parts[..]
                && oid == [0x55, 0x04, 0x03]
            {
                return decode_der_string(tag, value);
            }
        }
    }
    None
}

/// `SpcSpOpusInfo ::= SEQUENCE { programName [0] EXPLICIT SpcString OPTIONAL, ... }`,
/// `SpcString ::= CHOICE { unicode [0] IMPLICIT BMPString, ascii [1] IMPLICIT IA5String }`.
fn opus_program_name(attr_values: &[u8]) -> Option<String> {
    let (_, _, opus) = *der_children(attr_values).first()?;
    let (tag, _, program) = *der_children(opus).first()?;
    if tag != 0xA0 {
        return None;
    }
    let (choice, _, raw) = *der_children(program).first()?;
    match choice {
        0x80 => decode_der_string(0x1E, raw),
        0x81 => decode_der_string(0x16, raw),
        _ => None,
    }
}

/// Signatures of one `ContentInfo { signedData }`, nested signatures included.
fn collect_ci_signatures(content_info: &[u8], depth: usize, out: &mut Vec<CiSignature>) {
    use sha2::{Digest, Sha256, Sha384};
    if depth > 3 || out.len() >= 16 {
        return;
    }
    let Some(&(0x30, _, ci)) = der_children(content_info).first() else { return };
    let ci = der_children(ci);
    let Some(&(0xA0, _, explicit)) = ci.get(1) else { return };
    let Some(&(0x30, _, signed_data)) = der_children(explicit).first() else { return };
    let mut certs = Vec::new();
    let mut signer_infos: &[u8] = &[];
    for (tag, _, content) in der_children(signed_data) {
        match tag {
            0xA0 => {
                for (ctag, _, cert) in der_children(content).into_iter().take(64) {
                    if ctag == 0x30
                        && let Some(view) = parse_cert(cert)
                    {
                        certs.push(view);
                    }
                }
            }
            0x31 => signer_infos = content,
            _ => {}
        }
    }
    let tbs_hashes = |c: &CertView<'_>, into: &mut Vec<String>| {
        into.push(hex::encode(crate::utils::hash::sha1(c.tbs)));
        into.push(hex::encode(Sha256::digest(c.tbs)));
        into.push(hex::encode(Sha384::digest(c.tbs)));
    };
    for (stag, _, signer) in der_children(signer_infos).into_iter().take(8) {
        if stag != 0x30 {
            continue;
        }
        let fields = der_children(signer);
        let mut sig = CiSignature::default();
        // sid: issuerAndSerialNumber (a subjectKeyIdentifier sid is not matched).
        let leaf = fields.get(1).filter(|f| f.0 == 0x30).and_then(|sid| {
            let parts = der_children(sid.2);
            let (issuer, serial) = (parts.first()?, parts.get(1)?);
            certs.iter().position(|c| c.issuer == issuer.1 && c.serial == serial.2)
        });
        match leaf {
            Some(mut at) => {
                sig.publisher = name_common_name(certs[at].subject);
                let mut seen = vec![at];
                tbs_hashes(&certs[at], &mut sig.chain_tbs);
                while seen.len() < 10 {
                    let cur = &certs[at];
                    if cur.issuer == cur.subject {
                        break; // self-signed root
                    }
                    let Some(next) = certs
                        .iter()
                        .enumerate()
                        .position(|(i, c)| c.subject == cur.issuer && !seen.contains(&i))
                    else {
                        break;
                    };
                    at = next;
                    seen.push(at);
                    tbs_hashes(&certs[at], &mut sig.chain_tbs);
                }
            }
            None => certs.iter().for_each(|c| tbs_hashes(c, &mut sig.chain_tbs)),
        }
        for (ftag, _, content) in &fields {
            if *ftag != 0xA0 && *ftag != 0xA1 {
                continue;
            }
            for (_, _, attr) in der_children(content) {
                let parts = der_children(attr);
                let [(0x06, _, oid), (0x31, _, values), ..] = parts[..] else { continue };
                if *ftag == 0xA0 && oid == OID_SPC_SP_OPUS_INFO {
                    sig.oem_id = opus_program_name(values);
                } else if *ftag == 0xA1 && oid == OID_SPC_NESTED_SIGNATURE {
                    for (_, nested_full, _) in der_children(values).into_iter().take(8) {
                        collect_ci_signatures(nested_full, depth + 1, out);
                    }
                }
            }
        }
        out.push(sig);
    }
}

/// Every Authenticode signature of the PE (the first PKCS#7 attribute
/// certificate and the signatures nested in it). Empty for an unsigned PE,
/// `None` for a non-PE.
pub fn ci_signatures(bytes: &[u8]) -> Option<Vec<CiSignature>> {
    let l = pe_digest_layout(bytes)?;
    let mut out = Vec::new();
    let Some(se) = l.security_entry else { return Some(out) };
    let (off, size) = (rd_u32(bytes, se)? as usize, rd_u32(bytes, se + 4)? as usize);
    if size == 0 || off >= bytes.len() {
        return Some(out);
    }
    let end = off.saturating_add(size).min(bytes.len());
    let mut at = off;
    for _ in 0..64 {
        if at + 8 > end {
            break;
        }
        let total = rd_u32(bytes, at)? as usize;
        let cert_type = rd_u16(bytes, at + 6)?;
        if total < 8 || at + total > end {
            break;
        }
        if cert_type == 2 {
            collect_ci_signatures(&bytes[at + 8..at + total], 0, &mut out);
            break;
        }
        at += total.div_ceil(8) * 8;
    }
    Some(out)
}

/// Parse Authenticode signer subjects, `VS_VERSIONINFO`, and resource blobs in a
/// single pass for static analysis reports (such as VirusKovAlyzer).
pub fn inspect_pe_extras(
    bytes: &[u8],
) -> Option<(Authenticode, Option<VersionInfo>, Vec<ResourceBlob>)> {
    let parsed = pefile_rs::PE::parse(bytes).ok()?;
    let pe = PeInfo {
        arch: String::new(),
        is_64: parsed.is_64bit,
        entry: parsed.optional_header.address_of_entry_point as u64,
        image_base: parsed.optional_header.image_base,
        imports: Vec::new(),
        exports: Vec::new(),
        dlls: Vec::new(),
        suspicious_imports: Vec::new(),
        sections: parsed
            .sections
            .iter()
            .map(|s| crate::models::PeSectionInfo {
                name: s.name.split('\0').next().unwrap_or("").to_string(),
                virtual_size: s.virtual_size as u64,
                raw_size: s.size_of_raw_data as u64,
                entropy: 0.0,
                characteristics: s.characteristics,
                virtual_address: s.virtual_address as u64,
                raw_offset: s.pointer_to_raw_data as u64,
            })
            .collect(),
        suspicious_sections: Vec::new(),
        likely_packed: false,
        time_date_stamp: parsed.file_header.time_date_stamp,
        imphash: None,
        data_directories: parsed
            .optional_header
            .data_directories
            .iter()
            .map(|d| (d.virtual_address, d.size))
            .collect(),
    };
    let auth = authenticode(bytes, &pe).unwrap_or_default();
    let (ver, blobs) = match parsed.resources.as_ref() {
        Some(dir) => {
            let blobs = resource_blobs(&pe, bytes, dir);
            let ver = blobs
                .iter()
                .find(|b| {
                    b.type_id & 0x7fff_ffff == 14
                        || b.type_label.eq_ignore_ascii_case("RT_VERSION")
                })
                .map(|b| {
                    let mut info = parse_version_blob(b.data(bytes));
                    info.present = true;
                    info
                });
            (ver, blobs)
        }
        None => (None, Vec::new()),
    };
    Some((auth, ver, blobs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_type_labels() {
        assert_eq!(type_label(16, None), "RT_VERSION");
        assert_eq!(type_label(14, None), "RT_GROUP_ICON");
        assert_eq!(type_label(24, None), "RT_MANIFEST");
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
    fn version_bounds_and_text() {
        assert_eq!(parse_version_bound("1.10"), Some((1, 10, 0, 0)));
        assert_eq!(parse_version_bound("10.0.19041.1"), Some((10, 0, 19041, 1)));
        assert_eq!(parse_version_bound("1.2.x"), None);
        assert_eq!(parse_version_bound("1.2.3.4.5"), None);
        assert_eq!(parse_version_bound("70000"), None);
        assert_eq!(version_from_text("10.0.19041.1 (WinBuild.160101.0800)"), Some((10, 0, 19041, 1)));
        assert_eq!(version_from_text("1, 2, 3, 4"), Some((1, 2, 3, 4)));
        assert_eq!(version_from_text("2.5beta"), Some((2, 5, 0, 0)));
        assert_eq!(version_from_text("beta"), None);
        assert!((1, 10, 0, 0) > (1, 9, 0, 0));
    }

    #[test]
    fn version_blob_empty_is_absent() {
        assert_eq!(parse_version_blob(&[0, 0, 0]).fields.len(), 0);
    }

    /// PE32+ image of `len` bytes: e_lfanew 0x80, SizeOfHeaders 0x400,
    /// native subsystem, and an attribute certificate table at `cert`.
    fn tiny_pe64(len: usize, cert: Option<(u32, u32)>) -> Vec<u8> {
        let mut b: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let oh = 0x80 + 24;
        b[oh..oh + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        b[oh + 60..oh + 64].copy_from_slice(&0x400u32.to_le_bytes());
        b[oh + 68..oh + 70].copy_from_slice(&1u16.to_le_bytes());
        b[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes());
        let (off, size) = cert.unwrap_or((0, 0));
        b[oh + 144..oh + 148].copy_from_slice(&off.to_le_bytes());
        b[oh + 148..oh + 152].copy_from_slice(&size.to_le_bytes());
        b
    }

    #[test]
    fn ci_digests_skip_checksum_security_entry_and_cert_table() {
        use sha2::{Digest, Sha256};
        let pe = tiny_pe64(0x1800, Some((0x1600, 0x200)));
        let (checksum, sec) = (0x80 + 24 + 64, 0x80 + 24 + 144);
        let image: Vec<u8> = [&pe[..checksum], &pe[checksum + 4..sec], &pe[sec + 8..0x1600]].concat();
        let h = ci_image_hashes(&pe).expect("pe");
        assert_eq!(h.authentihash_sha256, hex::encode(Sha256::digest(&image)));
        assert_eq!(h.authentihash_sha1, hex::encode(crate::utils::hash::sha1(&image)));
        let mut page: Vec<u8> = [&pe[..checksum], &pe[checksum + 4..sec], &pe[sec + 8..0x400]].concat();
        page.resize(4096 - 12, 0);
        assert_eq!(h.page_sha256.as_deref(), Some(hex::encode(Sha256::digest(&page)).as_str()));
        // The checksum and the certificate table do not change the digests.
        let mut resigned = pe.clone();
        resigned[checksum] ^= 0xFF;
        resigned[0x1700] ^= 0xFF;
        assert_eq!(ci_image_hashes(&resigned), Some(h));
        assert_eq!(pe_subsystem(&pe), Some(1));
        // Unsigned: everything up to the end of the file.
        let unsigned = tiny_pe64(0x1234, None);
        let image: Vec<u8> = [&unsigned[..checksum], &unsigned[checksum + 4..sec], &unsigned[sec + 8..]].concat();
        assert_eq!(ci_image_hashes(&unsigned).unwrap().authentihash_sha256, hex::encode(Sha256::digest(&image)));
        assert_eq!(ci_signatures(&unsigned), Some(Vec::new()));
        assert!(ci_image_hashes(b"MZ not a pe").is_none());
    }
}
