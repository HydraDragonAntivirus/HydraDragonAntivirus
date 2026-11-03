//! Structural Mach-O parser (32/64-bit, either byte order) including Universal
//! (`FAT_MAGIC` / `FAT_MAGIC_64`, both byte orders) binaries, for the
//! `macho_*` conditions: load commands, dylibs, segments and sections,
//! external symbols, `LC_UUID`, the entry point and the `LC_CODE_SIGNATURE`
//! SuperBlob (code directory, identifier, team id, entitlements).
//!
//! Every count is capped and every read is bounds-checked; a truncated or
//! hostile file yields what could be read, never a panic.

use super::bin::{Reader, fixed_name};
use serde::{Deserialize, Serialize};

const MAX_SLICES: usize = 16;
const MAX_LOAD_COMMANDS: usize = 4096;
const MAX_SECTIONS: usize = 4096;
const MAX_SYMBOLS: usize = 65_536;
const MAX_NAME: usize = 4096;
/// Report cap of the name lists.
pub const MAX_NAMES: usize = 32_768;
/// Largest entitlements blob kept.
const MAX_ENTITLEMENTS: usize = 256 * 1024;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_RPATH: u32 = 0x8000_001c;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_MAIN: u32 = 0x8000_0028;

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
const CS_ADHOC: u32 = 0x2;

pub const VM_PROT_READ: u64 = 0x1;
pub const VM_PROT_WRITE: u64 = 0x2;
pub const VM_PROT_EXECUTE: u64 = 0x4;
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// Segment protection names of `macho_segment` (`flags_all` / `flags_none`).
pub fn prot_flag(name: &str) -> Option<u64> {
    match name.trim().to_ascii_lowercase().as_str() {
        "r" | "read" => Some(VM_PROT_READ),
        "w" | "write" => Some(VM_PROT_WRITE),
        "x" | "exec" | "execute" => Some(VM_PROT_EXECUTE),
        _ => None,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MachoSegment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MachoSection {
    pub segment: String,
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MachoSignature {
    /// A code directory was found.
    pub signed: bool,
    /// The code directory carries `CS_ADHOC`, or no CMS signature backs it.
    pub adhoc: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Entitlement keys (XML `<key>` names, or reverse-DNS strings of DER entitlements).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entitlement_keys: Vec<String>,
    /// Entitlements XML text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlements_xml: Option<String>,
}

/// One architecture of a (possibly Universal) Mach-O.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MachoSlice {
    /// `x86`, `x86_64`, `arm`, `arm64`, `arm64_32`, `ppc`, `ppc64` or the number.
    pub arch: String,
    pub cputype: u32,
    /// `execute`, `dylib`, `bundle`, ... or the number.
    pub filetype: String,
    pub flags: u32,
    pub is_64: bool,
    /// File offset of the slice in the file.
    pub offset: u64,
    pub dylibs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpaths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// File offset (in the whole file) of the entry point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_offset: Option<u64>,
    pub segments: Vec<MachoSegment>,
    pub sections: Vec<MachoSection>,
    /// External symbols, defined and undefined.
    pub symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<MachoSignature>,
}

/// Mach-O structure read by the `macho_*` conditions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MachoInfo {
    pub universal: bool,
    pub slices: Vec<MachoSlice>,
}

impl MachoInfo {
    pub fn dylib_count(&self) -> usize {
        let mut all: Vec<&String> = self.slices.iter().flat_map(|s| &s.dylibs).collect();
        all.sort();
        all.dedup();
        all.len()
    }

    pub fn section_count(&self) -> usize {
        self.slices.iter().map(|s| s.sections.len()).sum()
    }

    /// Segments whose initial protection is both writable and executable.
    pub fn rwx_segment_count(&self) -> usize {
        let wx = (VM_PROT_WRITE | VM_PROT_EXECUTE) as u32;
        self.slices.iter().flat_map(|s| &s.segments).filter(|g| g.initprot & wx == wx).count()
    }
}

pub fn is_macho(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some([0xfe, 0xed, 0xfa, 0xce | 0xcf]) | Some([0xce | 0xcf, 0xfa, 0xed, 0xfe])
    ) || fat_header(bytes).is_some()
}

/// A Universal binary whose first slice starts with a Mach-O header.
pub fn is_universal(bytes: &[u8]) -> bool {
    let Some((little, wide)) = fat_header(bytes) else { return false };
    let r = Reader::new(bytes, little);
    let off = if wide { r.u64(16) } else { r.u32(16).map(u64::from) };
    off.and_then(|o| r.slice(o, 4)).is_some_and(|m| {
        matches!(m, [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe])
    })
}

fn arch_name(cputype: u32) -> String {
    match cputype {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "arm",
        CPU_TYPE_ARM64 => "arm64",
        0x0200_000c => "arm64_32",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        _ => return format!("{cputype}"),
    }
    .to_string()
}

fn filetype_name(t: u32) -> String {
    match t {
        1 => "object",
        2 => "execute",
        3 => "fvmlib",
        4 => "core",
        5 => "preload",
        6 => "dylib",
        7 => "dylinker",
        8 => "bundle",
        9 => "dylib_stub",
        10 => "dsym",
        11 => "kext_bundle",
        _ => return format!("{t}"),
    }
    .to_string()
}

/// `(little_endian, wide)` of a Universal header, or None. `0xcafebabe` is
/// also the Java class magic: a fat header has a small slice count, a class
/// file a major version of 45 or more there.
fn fat_header(bytes: &[u8]) -> Option<(bool, bool)> {
    let magic = bytes.get(0..4)?;
    let (little, wide) = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => (false, false),
        [0xbe, 0xba, 0xfe, 0xca] => (true, false),
        [0xca, 0xfe, 0xba, 0xbf] => (false, true),
        [0xbf, 0xba, 0xfe, 0xca] => (true, true),
        _ => return None,
    };
    let n = Reader::new(bytes, little).u32(4)?;
    (n >= 1 && n as usize <= MAX_SLICES).then_some((little, wide))
}

fn push_capped(list: &mut Vec<String>, value: String) {
    if list.len() < MAX_NAMES && !value.is_empty() && !list.contains(&value) {
        list.push(value);
    }
}

/// Parse a thin or Universal Mach-O. `None` when no slice header is readable.
pub fn parse_macho(bytes: &[u8]) -> Option<MachoInfo> {
    let mut info = MachoInfo::default();
    if let Some((little, wide)) = fat_header(bytes) {
        info.universal = true;
        let r = Reader::new(bytes, little);
        let n = r.u32(4)? as u64;
        let ent = if wide { 32 } else { 20 };
        for i in 0..n {
            let at = 8 + i * ent;
            let (off, size) = if wide { (r.u64(at + 8), r.u64(at + 16)) } else { (r.u32(at + 8).map(u64::from), r.u32(at + 12).map(u64::from)) };
            let (Some(off), Some(size)) = (off, size) else { break };
            let Some(end) = off.checked_add(size) else { continue };
            let end = end.min(bytes.len() as u64);
            if off >= end {
                continue;
            }
            if let Some(slice) = parse_thin(&bytes[off as usize..end as usize], off) {
                info.slices.push(slice);
            }
        }
    } else if let Some(slice) = parse_thin(bytes, 0) {
        info.slices.push(slice);
    }
    (!info.slices.is_empty()).then_some(info)
}

/// One thin Mach-O starting at `base` in the file (`bytes` is the slice).
fn parse_thin(bytes: &[u8], base: u64) -> Option<MachoSlice> {
    let (little, is_64) = match bytes.get(0..4)? {
        [0xfe, 0xed, 0xfa, 0xce] => (false, false),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, true),
        [0xce, 0xfa, 0xed, 0xfe] => (true, false),
        [0xcf, 0xfa, 0xed, 0xfe] => (true, true),
        _ => return None,
    };
    let r = Reader::new(bytes, little);
    let cputype = r.u32(4)?;
    let filetype = r.u32(12)?;
    let ncmds = r.u32(16)? as usize;
    let sizeofcmds = u64::from(r.u32(20)?);
    let flags = r.u32(24)?;
    let mut slice = MachoSlice {
        arch: arch_name(cputype),
        cputype,
        filetype: filetype_name(filetype),
        flags,
        is_64,
        offset: base,
        ..Default::default()
    };
    let header = if is_64 { 32u64 } else { 28u64 };
    let cmds_end = header.saturating_add(sizeofcmds).min(bytes.len() as u64);
    let mut at = header;
    let mut entry_vmaddr = None;
    let mut entry_fileoff = None;
    let mut symtab = None;
    let mut codesig = None;
    for _ in 0..ncmds.min(MAX_LOAD_COMMANDS) {
        if at.saturating_add(8) > cmds_end {
            break;
        }
        let (Some(cmd), Some(cmdsize)) = (r.u32(at), r.u32(at + 4)) else { break };
        let cmdsize = u64::from(cmdsize);
        if cmdsize < 8 || at.saturating_add(cmdsize) > cmds_end {
            break;
        }
        let lc_str = |field: u64| -> String {
            let Some(off) = r.u32(at + field) else { return String::new() };
            let off = u64::from(off);
            if off >= cmdsize {
                return String::new();
            }
            r.cstr(at + off, (cmdsize - off).min(MAX_NAME as u64) as usize).unwrap_or_default()
        };
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => read_segment(&r, at, cmd == LC_SEGMENT_64, &mut slice),
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                push_capped(&mut slice.dylibs, lc_str(8))
            }
            LC_RPATH => push_capped(&mut slice.rpaths, lc_str(8)),
            LC_UUID => {
                if let Some(u) = r.slice(at + 8, 16) {
                    slice.uuid = Some(format_uuid(u));
                }
            }
            LC_MAIN => entry_fileoff = r.u64(at + 8),
            LC_UNIXTHREAD => {
                // flavor, count, then the thread state; the pc slot depends on the CPU.
                let state = at + 16;
                entry_vmaddr = match cputype {
                    0x0100_0007 => r.u64(state + 16 * 8),
                    CPU_TYPE_ARM64 => r.u64(state + 32 * 8),
                    7 => r.u32(state + 10 * 4).map(u64::from),
                    12 => r.u32(state + 15 * 4).map(u64::from),
                    _ => None,
                };
            }
            LC_SYMTAB => symtab = Some((r.u32(at + 8)?, r.u32(at + 12)?, r.u32(at + 16)?, r.u32(at + 20)?)),
            LC_CODE_SIGNATURE => codesig = Some((u64::from(r.u32(at + 8)?), u64::from(r.u32(at + 12)?))),
            _ => {}
        }
        at += cmdsize;
    }
    let to_file = |vmaddr: u64| {
        slice.segments.iter().find_map(|s| {
            let rel = vmaddr.checked_sub(s.vmaddr)?;
            (rel < s.filesize).then(|| s.fileoff.checked_add(rel)).flatten()
        })
    };
    slice.entry_offset = entry_fileoff.or_else(|| entry_vmaddr.and_then(to_file)).and_then(|o| o.checked_add(base));
    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        read_symbols(&r, is_64, u64::from(symoff), nsyms as usize, u64::from(stroff), u64::from(strsize), &mut slice.symbols);
    }
    if let Some((off, size)) = codesig {
        slice.signature = r.slice(off, size).map(parse_code_signature);
    }
    Some(slice)
}

fn format_uuid(u: &[u8]) -> String {
    let h = hex::encode(u);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn read_segment(r: &Reader, at: u64, wide: bool, slice: &mut MachoSlice) {
    let name = r.slice(at + 8, 16).map(fixed_name).unwrap_or_default();
    let (seg, nsects, sect_at, sect_len) = if wide {
        let seg = MachoSegment {
            name,
            vmaddr: r.u64(at + 24).unwrap_or(0),
            vmsize: r.u64(at + 32).unwrap_or(0),
            fileoff: r.u64(at + 40).unwrap_or(0),
            filesize: r.u64(at + 48).unwrap_or(0),
            maxprot: r.u32(at + 56).unwrap_or(0),
            initprot: r.u32(at + 60).unwrap_or(0),
        };
        (seg, r.u32(at + 64).unwrap_or(0), at + 72, 80u64)
    } else {
        let seg = MachoSegment {
            name,
            vmaddr: u64::from(r.u32(at + 24).unwrap_or(0)),
            vmsize: u64::from(r.u32(at + 28).unwrap_or(0)),
            fileoff: u64::from(r.u32(at + 32).unwrap_or(0)),
            filesize: u64::from(r.u32(at + 36).unwrap_or(0)),
            maxprot: r.u32(at + 40).unwrap_or(0),
            initprot: r.u32(at + 44).unwrap_or(0),
        };
        (seg, r.u32(at + 48).unwrap_or(0), at + 56, 68u64)
    };
    for i in 0..u64::from(nsects) {
        if slice.sections.len() >= MAX_SECTIONS {
            break;
        }
        let s = sect_at + i * sect_len;
        let Some(sname) = r.slice(s, 16).map(fixed_name) else { break };
        let segment = r.slice(s + 16, 16).map(fixed_name).unwrap_or_default();
        let (size, offset, flags) = if wide {
            (r.u64(s + 40), r.u32(s + 48), r.u32(s + 64))
        } else {
            (r.u32(s + 36).map(u64::from), r.u32(s + 40), r.u32(s + 56))
        };
        slice.sections.push(MachoSection {
            segment,
            name: sname,
            offset: u64::from(offset.unwrap_or(0)),
            size: size.unwrap_or(0),
            flags: flags.unwrap_or(0),
        });
    }
    slice.segments.push(seg);
}

#[allow(clippy::too_many_arguments)]
fn read_symbols(r: &Reader, wide: bool, symoff: u64, nsyms: usize, stroff: u64, strsize: u64, out: &mut Vec<String>) {
    let ent = if wide { 16 } else { 12 };
    for i in 0..nsyms.min(MAX_SYMBOLS) as u64 {
        let at = symoff.saturating_add(i * ent);
        let (Some(strx), Some(n_type)) = (r.u32(at), r.u8(at + 4)) else { break };
        let strx = u64::from(strx);
        // External (N_EXT) symbols that are not debug (N_STAB) entries.
        if n_type & 0xe0 != 0 || n_type & 0x01 == 0 || strx == 0 || strx >= strsize {
            continue;
        }
        if let Some(name) = r.cstr(stroff.saturating_add(strx), MAX_NAME) {
            push_capped(out, name);
        }
    }
}

/// The embedded signature SuperBlob (big-endian).
fn parse_code_signature(blob: &[u8]) -> MachoSignature {
    let mut sig = MachoSignature::default();
    let r = Reader::new(blob, false);
    if r.u32(0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
        return sig;
    }
    let count = r.u32(8).unwrap_or(0).min(64) as u64;
    let mut cms_len = None;
    for i in 0..count {
        let (Some(_slot), Some(off)) = (r.u32(12 + i * 8), r.u32(16 + i * 8)) else { break };
        let off = u64::from(off);
        let (Some(magic), Some(len)) = (r.u32(off), r.u32(off + 4)) else { continue };
        let Some(data) = r.slice(off, u64::from(len)) else { continue };
        match magic {
            CSMAGIC_CODEDIRECTORY => {
                sig.signed = true;
                let cd = Reader::new(data, false);
                let version = cd.u32(8).unwrap_or(0);
                if cd.u32(12).unwrap_or(0) & CS_ADHOC != 0 {
                    sig.adhoc = true;
                }
                if let Some(ident) = cd.u32(20) {
                    sig.identifier = cd.cstr(u64::from(ident), MAX_NAME).filter(|s| !s.is_empty());
                }
                if version >= 0x20200 {
                    if let Some(team) = cd.u32(48).filter(|t| *t != 0) {
                        sig.team_id = cd.cstr(u64::from(team), MAX_NAME).filter(|s| !s.is_empty());
                    }
                }
            }
            CSMAGIC_EMBEDDED_ENTITLEMENTS => {
                let body = &data[8.min(data.len())..];
                let xml = String::from_utf8_lossy(&body[..body.len().min(MAX_ENTITLEMENTS)]).into_owned();
                for key in xml.split("<key>").skip(1).filter_map(|k| k.split("</key>").next()) {
                    push_capped(&mut sig.entitlement_keys, key.trim().to_string());
                }
                sig.entitlements_xml = Some(xml);
            }
            CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => {
                // DER UTF8String keys: printable reverse-DNS runs.
                let body = &data[8.min(data.len())..];
                for run in body.split(|b| !(b.is_ascii_graphic())) {
                    if run.len() >= 8 && run.contains(&b'.') && run.iter().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b)) {
                        push_capped(&mut sig.entitlement_keys, String::from_utf8_lossy(run).into_owned());
                    }
                }
            }
            CSMAGIC_BLOBWRAPPER => cms_len = Some(len),
            _ => {}
        }
    }
    // No CMS blob (or an empty wrapper) behind the code directory: ad-hoc.
    if sig.signed && cms_len.is_none_or(|l| l <= 8) {
        sig.adhoc = true;
    }
    sig
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// Big-endian SuperBlob: an ad-hoc code directory (identifier, team id) and
    /// an entitlements plist.
    pub fn code_signature(entitlements: &[&str]) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend(be32(CSMAGIC_CODEDIRECTORY));
        cd.extend(be32(0)); // length, patched
        cd.extend(be32(0x20200)); // version
        cd.extend(be32(CS_ADHOC));
        cd.extend([0u8; 4]); // hashOffset
        cd.extend(be32(64)); // identOffset
        cd.extend([0u8; 24]); // nSpecialSlots .. spare2, scatterOffset
        cd.extend(be32(64 + 16)); // teamOffset (at 48)
        cd.resize(64, 0);
        cd.extend(b"com.evil.loader\0");
        cd.extend(b"TEAM123456\0");
        let len = cd.len() as u32;
        cd[4..8].copy_from_slice(&be32(len));
        let mut plist = String::from("<?xml version=\"1.0\"?><plist><dict>");
        for k in entitlements {
            plist.push_str(&format!("<key>{k}</key><true/>"));
        }
        plist.push_str("</dict></plist>");
        let mut ent = Vec::new();
        ent.extend(be32(CSMAGIC_EMBEDDED_ENTITLEMENTS));
        ent.extend(be32(8 + plist.len() as u32));
        ent.extend(plist.as_bytes());
        let mut sb = Vec::new();
        sb.extend(be32(CSMAGIC_EMBEDDED_SIGNATURE));
        sb.extend(be32(0));
        sb.extend(be32(2));
        let cd_off = 12 + 16;
        sb.extend(be32(0));
        sb.extend(be32(cd_off));
        sb.extend(be32(5));
        sb.extend(be32(cd_off + cd.len() as u32));
        sb.extend(&cd);
        sb.extend(&ent);
        let total = sb.len() as u32;
        sb[4..8].copy_from_slice(&be32(total));
        sb
    }

    /// Little-endian 64-bit Mach-O executable for `cputype`: `__TEXT` (r-x)
    /// with `__text`, an RWX `__DATA`, `LC_LOAD_DYLIB`, `LC_UUID`, `LC_MAIN`,
    /// an `LC_SYMTAB` with `_main` and `_ptrace`, and an embedded signature.
    pub fn build_macho64(cputype: u32, entitlements: &[&str]) -> Vec<u8> {
        let mut cmds: Vec<Vec<u8>> = Vec::new();
        let le32 = |v: u32| v.to_le_bytes();
        let le64 = |v: u64| v.to_le_bytes();
        let segment = |name: &str, fileoff: u64, filesize: u64, prot: u32, sects: &[(&str, u64, u64)]| {
            let mut c = Vec::new();
            c.extend(le32(LC_SEGMENT_64));
            c.extend(le32(72 + 80 * sects.len() as u32));
            let mut n = [0u8; 16];
            n[..name.len()].copy_from_slice(name.as_bytes());
            c.extend(n);
            c.extend(le64(0x1_0000_0000 + fileoff));
            c.extend(le64(filesize));
            c.extend(le64(fileoff));
            c.extend(le64(filesize));
            c.extend(le32(prot));
            c.extend(le32(prot));
            c.extend(le32(sects.len() as u32));
            c.extend(le32(0));
            for (sname, off, size) in sects {
                let mut s = vec![0u8; 80];
                s[..sname.len()].copy_from_slice(sname.as_bytes());
                s[16..16 + name.len()].copy_from_slice(name.as_bytes());
                s[40..48].copy_from_slice(&le64(*size));
                s[48..52].copy_from_slice(&le32(*off as u32));
                c.extend(s);
            }
            c
        };
        let data_off = 0x1000u64;
        cmds.push(segment("__TEXT", 0, data_off, 5, &[("__text", 0x800, 0x40)]));
        cmds.push(segment("__DATA", data_off, 0x100, 7, &[("__data", data_off, 0x100)]));
        let mut dylib = Vec::new();
        let name = b"/usr/lib/libSystem.B.dylib\0\0\0\0\0";
        dylib.extend(le32(LC_LOAD_DYLIB));
        dylib.extend(le32(24 + name.len() as u32));
        dylib.extend(le32(24));
        dylib.extend([0u8; 12]);
        dylib.extend(name);
        cmds.push(dylib);
        let mut uuid = Vec::new();
        uuid.extend(le32(LC_UUID));
        uuid.extend(le32(24));
        uuid.extend((0u8..16).collect::<Vec<_>>());
        cmds.push(uuid);
        let mut main = Vec::new();
        main.extend(le32(LC_MAIN));
        main.extend(le32(24));
        main.extend(le64(0x800));
        main.extend(le64(0));
        cmds.push(main);
        let sym_off = data_off as u32 + 0x100;
        let strtab = b"\0_main\0_ptrace\0";
        let str_off = sym_off + 32;
        let mut symtab = Vec::new();
        symtab.extend(le32(LC_SYMTAB));
        symtab.extend(le32(24));
        symtab.extend(le32(sym_off));
        symtab.extend(le32(2));
        symtab.extend(le32(str_off));
        symtab.extend(le32(strtab.len() as u32));
        cmds.push(symtab);
        let sig = code_signature(entitlements);
        let sig_off = str_off + strtab.len() as u32;
        let mut cs = Vec::new();
        cs.extend(le32(LC_CODE_SIGNATURE));
        cs.extend(le32(16));
        cs.extend(le32(sig_off));
        cs.extend(le32(sig.len() as u32));
        cmds.push(cs);

        let sizeofcmds: usize = cmds.iter().map(Vec::len).sum();
        let mut out = Vec::new();
        out.extend(le32(0xfeed_facf));
        out.extend(le32(cputype));
        out.extend(le32(3));
        out.extend(le32(2));
        out.extend(le32(cmds.len() as u32));
        out.extend(le32(sizeofcmds as u32));
        out.extend(le32(0x0020_0085));
        out.extend(le32(0));
        for c in cmds {
            out.extend(c);
        }
        out.resize(sym_off as usize, 0);
        for (strx, n_type, sect) in [(1u32, 0x0fu8, 1u8), (7, 0x01, 0)] {
            out.extend(le32(strx));
            out.push(n_type);
            out.push(sect);
            out.extend([0u8; 10]);
        }
        out.extend(strtab);
        out.extend(sig);
        out
    }

    /// Big-endian Universal header around two slices.
    pub fn build_fat(slices: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(be32(0xcafe_babe));
        out.extend(be32(slices.len() as u32));
        let mut off = 0x1000u32;
        let mut bodies = Vec::new();
        for (cpu, body) in slices {
            out.extend(be32(*cpu));
            out.extend(be32(0));
            out.extend(be32(off));
            out.extend(be32(body.len() as u32));
            out.extend(be32(12));
            bodies.push((off, body));
            off += (body.len() as u32).next_multiple_of(0x1000);
        }
        for (at, body) in bodies {
            out.resize(at as usize, 0);
            out.extend(body);
        }
        out
    }

    #[test]
    fn parses_thin_and_fat_binaries() {
        let ents = ["com.apple.security.cs.disable-library-validation"];
        let thin = build_macho64(CPU_TYPE_ARM64, &ents);
        let m = parse_macho(&thin).unwrap();
        assert!(!m.universal);
        let s = &m.slices[0];
        assert_eq!((s.arch.as_str(), s.filetype.as_str()), ("arm64", "execute"));
        assert_eq!(s.dylibs, vec!["/usr/lib/libSystem.B.dylib"]);
        assert_eq!(s.uuid.as_deref(), Some("00010203-0405-0607-0809-0a0b0c0d0e0f"));
        assert_eq!(s.entry_offset, Some(0x800));
        assert_eq!(s.symbols, vec!["_main", "_ptrace"]);
        assert_eq!(m.section_count(), 2);
        assert_eq!(m.rwx_segment_count(), 1);
        let sig = s.signature.as_ref().unwrap();
        assert!(sig.signed && sig.adhoc);
        assert_eq!(sig.identifier.as_deref(), Some("com.evil.loader"));
        assert_eq!(sig.team_id.as_deref(), Some("TEAM123456"));
        assert_eq!(sig.entitlement_keys, ents);
        assert!(sig.entitlements_xml.as_deref().unwrap().contains("disable-library-validation"));

        let fat = build_fat(&[(0x0100_0007, build_macho64(0x0100_0007, &[])), (CPU_TYPE_ARM64, thin.clone())]);
        let m = parse_macho(&fat).unwrap();
        assert!(m.universal);
        assert_eq!(m.slices.iter().map(|s| s.arch.as_str()).collect::<Vec<_>>(), ["x86_64", "arm64"]);
        assert_eq!(m.slices[1].entry_offset, Some(m.slices[1].offset + 0x800));
        assert!(m.slices[1].offset > 0x1000);
        assert_eq!(m.dylib_count(), 1);
    }

    #[test]
    fn hostile_input_does_not_panic() {
        let thin = build_macho64(CPU_TYPE_ARM64, &["a.b.c.d"]);
        for cut in [0, 4, 31, 32, 100, thin.len() / 2, thin.len() - 1] {
            let _ = parse_macho(&thin[..cut]);
        }
        let mut fat = build_fat(&[(CPU_TYPE_ARM64, thin)]);
        fat[16..20].copy_from_slice(&be32(u32::MAX));
        let _ = parse_macho(&fat);
        let mut noisy = build_macho64(7, &[]);
        for b in noisy.iter_mut().skip(32).step_by(5) {
            *b = 0xff;
        }
        let _ = parse_macho(&noisy);
        // Java class files share 0xcafebabe.
        assert!(parse_macho(b"\xca\xfe\xba\xbe\x00\x00\x00\x34rest").is_none());
    }
}
