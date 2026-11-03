//! .NET / CLR metadata parser for the `dotnet_*` conditions: the CLI header
//! (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`), the `BSJB` metadata root, its
//! streams (`#~` / `#-`, `#Strings`, `#US`, `#GUID`, `#Blob`) and the tables
//! that name things: Module (MVID), TypeRef, TypeDef, MethodDef, MemberRef,
//! ModuleRef, ImplMap (P/Invoke), Assembly and the `GuidAttribute` custom
//! attribute (type library GUID). Table layouts follow ECMA-335 II.22-24.
//!
//! Every count is capped and every read is bounds-checked; a truncated or
//! hostile file yields what could be read, never a panic.

use super::bin::Reader;
use serde::{Deserialize, Serialize};

/// Report cap of each name list.
pub const MAX_NAMES: usize = 32_768;
/// `#US` entries kept.
pub const MAX_USER_STRINGS: usize = 16_384;
const MAX_STREAMS: usize = 64;
const MAX_ROWS: u32 = 1 << 24;
const MAX_NAME: usize = 1024;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: u64 = 14;

/// CLR metadata of a .NET PE.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DotNetInfo {
    /// Metadata version string, e.g. `v4.0.30319`.
    pub version: String,
    /// Stream names and sizes in header order.
    pub streams: Vec<(String, u32)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assembly_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mvid: Option<String>,
    /// `GuidAttribute` of the assembly (type library id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typelib: Option<String>,
    /// Defined types, `Namespace.Type`.
    pub types: Vec<String>,
    /// Referenced types, `Namespace.Type`.
    pub type_refs: Vec<String>,
    /// Defined methods, `Namespace.Type::Method`.
    pub methods: Vec<String>,
    /// Member references, `Namespace.Type::Member`.
    pub member_refs: Vec<String>,
    /// P/Invoke imports, `module.dll!function`.
    pub pinvokes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_strings: Vec<String>,
}

/// Section table and data directories of a PE, enough to map RVAs.
struct PeLayout {
    sections: Vec<(u64, u64, u64, u64)>, // va, vsize, raw offset, raw size
    dirs_at: u64,
    dir_count: u64,
}

fn pe_layout(r: &Reader) -> Option<PeLayout> {
    if r.slice(0, 2)? != b"MZ" {
        return None;
    }
    let pe = u64::from(r.u32(0x3c)?);
    if r.slice(pe, 4)? != b"PE\0\0" {
        return None;
    }
    let nsect = u64::from(r.u16(pe + 6)?).min(96);
    let opt_size = u64::from(r.u16(pe + 20)?);
    let opt = pe + 24;
    let (dirs_at, count_at) = match r.u16(opt)? {
        0x10b => (opt + 96, opt + 92),
        0x20b => (opt + 112, opt + 108),
        _ => return None,
    };
    let dir_count = u64::from(r.u32(count_at)?).min(16);
    let mut sections = Vec::new();
    let table = opt + opt_size;
    for i in 0..nsect {
        let s = table + i * 40;
        let (Some(vsize), Some(va), Some(rsize), Some(roff)) = (r.u32(s + 8), r.u32(s + 12), r.u32(s + 16), r.u32(s + 20)) else {
            break;
        };
        sections.push((u64::from(va), u64::from(vsize.max(rsize)), u64::from(roff), u64::from(rsize)));
    }
    Some(PeLayout { sections, dirs_at, dir_count })
}

impl PeLayout {
    fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        self.sections.iter().find_map(|&(va, vsize, roff, rsize)| {
            let rel = rva.checked_sub(va)?;
            (rel < vsize && rel < rsize).then(|| roff.checked_add(rel)).flatten()
        })
    }

    fn directory(&self, r: &Reader, index: u64) -> Option<(u64, u64)> {
        if index >= self.dir_count {
            return None;
        }
        let at = self.dirs_at + index * 8;
        let (rva, size) = (u64::from(r.u32(at)?), u64::from(r.u32(at + 4)?));
        (rva != 0 && size != 0).then_some((rva, size))
    }
}

/// File offset and size of the metadata root (`BSJB`), when the PE has CLR metadata.
fn metadata_root(bytes: &[u8]) -> Option<(u64, u64)> {
    let r = Reader::new(bytes, true);
    let layout = pe_layout(&r)?;
    let (cli_rva, _) = layout.directory(&r, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?;
    let cli = layout.rva_to_offset(cli_rva)?;
    let md_rva = u64::from(r.u32(cli + 8)?);
    let md_size = u64::from(r.u32(cli + 12)?);
    let md = layout.rva_to_offset(md_rva)?;
    (r.slice(md, 4)? == b"BSJB").then_some((md, md_size))
}

/// The PE has a CLR directory pointing at a `BSJB` metadata root (cheap check).
pub fn has_clr_metadata(bytes: &[u8]) -> bool {
    metadata_root(bytes).is_some()
}

/// ECMA-335 II.24.2.4 compressed unsigned integer: (value, bytes used).
fn compressed_u32(b: &[u8]) -> Option<(u32, usize)> {
    let first = *b.first()?;
    if first & 0x80 == 0 {
        Some((u32::from(first), 1))
    } else if first & 0xc0 == 0x80 {
        Some(((u32::from(first & 0x3f) << 8) | u32::from(*b.get(1)?), 2))
    } else if first & 0xe0 == 0xc0 {
        let v = (u32::from(first & 0x1f) << 24) | (u32::from(*b.get(1)?) << 16) | (u32::from(*b.get(2)?) << 8) | u32::from(*b.get(3)?);
        Some((v, 4))
    } else {
        None
    }
}

fn format_guid(g: &[u8]) -> Option<String> {
    let g: [u8; 16] = g.try_into().ok()?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        hex::encode(&g[8..10]),
        hex::encode(&g[10..16])
    ))
}

/// Lowercase hex digits only: `{A-B}` and `a-b` compare equal.
pub fn normalize_guid(g: &str) -> String {
    g.chars().filter(char::is_ascii_hexdigit).map(|c| c.to_ascii_lowercase()).collect()
}

// Column kinds of the metadata tables.
#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    /// Simple index into a table.
    T(usize),
    /// Coded index: tag bits and the tables it can name.
    C(u32, &'static [usize]),
}

const TYPE_DEF_OR_REF: Col = Col::C(2, &[0x02, 0x01, 0x1b]);
const HAS_CONSTANT: Col = Col::C(2, &[0x04, 0x08, 0x17]);
const HAS_CUSTOM_ATTRIBUTE: Col = Col::C(
    5,
    &[0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b],
);
const HAS_FIELD_MARSHAL: Col = Col::C(1, &[0x04, 0x08]);
const HAS_DECL_SECURITY: Col = Col::C(2, &[0x02, 0x06, 0x20]);
const MEMBER_REF_PARENT: Col = Col::C(3, &[0x02, 0x01, 0x1a, 0x06, 0x1b]);
const HAS_SEMANTICS: Col = Col::C(1, &[0x14, 0x17]);
const METHOD_DEF_OR_REF: Col = Col::C(1, &[0x06, 0x0a]);
const MEMBER_FORWARDED: Col = Col::C(1, &[0x04, 0x06]);
const IMPLEMENTATION: Col = Col::C(2, &[0x26, 0x23, 0x27]);
const CUSTOM_ATTRIBUTE_TYPE: Col = Col::C(3, &[0x3f, 0x3f, 0x06, 0x0a, 0x3f]);
const RESOLUTION_SCOPE: Col = Col::C(2, &[0x00, 0x1a, 0x23, 0x01]);
const TYPE_OR_METHOD_DEF: Col = Col::C(1, &[0x02, 0x06]);

use Col::*;

/// Columns of tables 0x00..=0x2c (ECMA-335 II.22).
const SCHEMA: [&[Col]; 0x2d] = [
    &[U16, Str, Guid, Guid, Guid],                    // 0x00 Module
    &[RESOLUTION_SCOPE, Str, Str],                    // 0x01 TypeRef
    &[U32, Str, Str, TYPE_DEF_OR_REF, T(0x04), T(0x06)], // 0x02 TypeDef
    &[T(0x04)],                                       // 0x03 FieldPtr
    &[U16, Str, Blob],                                // 0x04 Field
    &[T(0x06)],                                       // 0x05 MethodPtr
    &[U32, U16, U16, Str, Blob, T(0x08)],             // 0x06 MethodDef
    &[T(0x08)],                                       // 0x07 ParamPtr
    &[U16, U16, Str],                                 // 0x08 Param
    &[T(0x02), TYPE_DEF_OR_REF],                      // 0x09 InterfaceImpl
    &[MEMBER_REF_PARENT, Str, Blob],                  // 0x0a MemberRef
    &[U16, HAS_CONSTANT, Blob],                       // 0x0b Constant
    &[HAS_CUSTOM_ATTRIBUTE, CUSTOM_ATTRIBUTE_TYPE, Blob], // 0x0c CustomAttribute
    &[HAS_FIELD_MARSHAL, Blob],                       // 0x0d FieldMarshal
    &[U16, HAS_DECL_SECURITY, Blob],                  // 0x0e DeclSecurity
    &[U16, U32, T(0x02)],                             // 0x0f ClassLayout
    &[U32, T(0x04)],                                  // 0x10 FieldLayout
    &[Blob],                                          // 0x11 StandAloneSig
    &[T(0x02), T(0x14)],                              // 0x12 EventMap
    &[T(0x14)],                                       // 0x13 EventPtr
    &[U16, Str, TYPE_DEF_OR_REF],                     // 0x14 Event
    &[T(0x02), T(0x17)],                              // 0x15 PropertyMap
    &[T(0x17)],                                       // 0x16 PropertyPtr
    &[U16, Str, Blob],                                // 0x17 Property
    &[U16, T(0x06), HAS_SEMANTICS],                   // 0x18 MethodSemantics
    &[T(0x02), METHOD_DEF_OR_REF, METHOD_DEF_OR_REF], // 0x19 MethodImpl
    &[Str],                                           // 0x1a ModuleRef
    &[Blob],                                          // 0x1b TypeSpec
    &[U16, MEMBER_FORWARDED, Str, T(0x1a)],           // 0x1c ImplMap
    &[U32, T(0x04)],                                  // 0x1d FieldRVA
    &[U32, U32],                                      // 0x1e EncLog
    &[U32],                                           // 0x1f EncMap
    &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],  // 0x20 Assembly
    &[U32],                                           // 0x21 AssemblyProcessor
    &[U32, U32, U32],                                 // 0x22 AssemblyOS
    &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob], // 0x23 AssemblyRef
    &[U32, T(0x23)],                                  // 0x24 AssemblyRefProcessor
    &[U32, U32, U32, T(0x23)],                        // 0x25 AssemblyRefOS
    &[U32, Str, Blob],                                // 0x26 File
    &[U32, U32, Str, Str, IMPLEMENTATION],            // 0x27 ExportedType
    &[U32, U32, Str, IMPLEMENTATION],                 // 0x28 ManifestResource
    &[T(0x02), T(0x02)],                              // 0x29 NestedClass
    &[U16, U16, TYPE_OR_METHOD_DEF, Str],             // 0x2a GenericParam
    &[METHOD_DEF_OR_REF, Blob],                       // 0x2b MethodSpec
    &[T(0x2a), TYPE_DEF_OR_REF],                      // 0x2c GenericParamConstraint
];

/// Table layout of a `#~` stream: row counts, widths, start of each table.
struct Tables<'a> {
    r: Reader<'a>,
    rows: [u32; 64],
    str_wide: bool,
    guid_wide: bool,
    blob_wide: bool,
    /// (offset of the table, row size) per table; None past an unknown table.
    at: [Option<(u64, u64)>; 0x2d],
}

impl<'a> Tables<'a> {
    fn col_width(&self, c: Col) -> u64 {
        match c {
            U16 => 2,
            U32 => 4,
            Str => if self.str_wide { 4 } else { 2 },
            Guid => if self.guid_wide { 4 } else { 2 },
            Blob => if self.blob_wide { 4 } else { 2 },
            T(t) => if self.rows[t] > 0xffff { 4 } else { 2 },
            C(bits, tables) => {
                let max = tables.iter().map(|&t| if t < 64 { self.rows[t] } else { 0 }).max().unwrap_or(0);
                if max >= (1u32 << (16 - bits)) { 4 } else { 2 }
            }
        }
    }

    fn parse(stream: &'a [u8]) -> Option<Self> {
        let r = Reader::new(stream, true);
        let heap_sizes = r.u8(6)?;
        let valid = r.u64(8)?;
        let mut rows = [0u32; 64];
        let mut at = 24u64;
        for (t, row) in rows.iter_mut().enumerate() {
            if valid & (1u64 << t) != 0 {
                *row = r.u32(at)?.min(MAX_ROWS);
                at += 4;
            }
        }
        // `#-` streams may carry 4 extra bytes after the row counts.
        if heap_sizes & 0x40 != 0 {
            at += 4;
        }
        let mut tables = Tables { r, rows, str_wide: heap_sizes & 1 != 0, guid_wide: heap_sizes & 2 != 0, blob_wide: heap_sizes & 4 != 0, at: [None; 0x2d] };
        for (t, cols) in SCHEMA.iter().enumerate() {
            let size: u64 = cols.iter().map(|c| tables.col_width(*c)).sum();
            tables.at[t] = Some((at, size));
            at = at.saturating_add(size.saturating_mul(u64::from(tables.rows[t])));
        }
        Some(tables)
    }

    /// Column `col` of 1-based row `row` of table `t`.
    fn get(&self, t: usize, row: u32, col: usize) -> Option<u32> {
        if row == 0 || row > self.rows[t] {
            return None;
        }
        let (base, size) = self.at[t]?;
        let mut off = base.checked_add(u64::from(row - 1).checked_mul(size)?)?;
        for c in &SCHEMA[t][..col] {
            off += self.col_width(*c);
        }
        match self.col_width(*SCHEMA[t].get(col)?) {
            2 => self.r.u16(off).map(u32::from),
            _ => self.r.u32(off),
        }
    }
}

/// Decoded coded index: (table, 1-based row).
fn decode_coded(c: Col, v: u32) -> Option<(usize, u32)> {
    let C(bits, tables) = c else { return None };
    let tag = (v & ((1 << bits) - 1)) as usize;
    let t = *tables.get(tag)?;
    (t < 0x2d).then_some((t, v >> bits))
}

struct Heaps<'a> {
    strings: &'a [u8],
    guid: &'a [u8],
    blob: &'a [u8],
}

impl Heaps<'_> {
    fn string(&self, idx: u32) -> String {
        let Some(rest) = self.strings.get(idx as usize..) else { return String::new() };
        let rest = &rest[..rest.len().min(MAX_NAME)];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        String::from_utf8_lossy(&rest[..end]).into_owned()
    }

    fn guid(&self, idx: u32) -> Option<String> {
        let start = (idx.checked_sub(1)? as usize).checked_mul(16)?;
        format_guid(self.guid.get(start..start.checked_add(16)?)?)
    }

    fn blob(&self, idx: u32) -> Option<&[u8]> {
        let rest = self.blob.get(idx as usize..)?;
        let (len, used) = compressed_u32(rest)?;
        rest.get(used..used.checked_add(len as usize)?)
    }
}

fn push_capped(list: &mut Vec<String>, value: String) {
    if list.len() < MAX_NAMES && !value.is_empty() {
        list.push(value);
    }
}

fn full_name(ns: String, name: String) -> String {
    if ns.is_empty() { name } else { format!("{ns}.{name}") }
}

/// P/Invoke module as Windows resolves it: no extension means `.dll`.
fn module_name(m: &str) -> String {
    if m.contains('.') { m.to_string() } else { format!("{m}.dll") }
}

/// Parse the CLR metadata of a .NET PE. `None` when there is none.
pub fn parse_dotnet(bytes: &[u8]) -> Option<DotNetInfo> {
    let (md, md_size) = metadata_root(bytes)?;
    let r = Reader::new(bytes, true);
    let md_end = md.saturating_add(md_size).min(bytes.len() as u64);
    let md_bytes = r.slice(md, md_end.checked_sub(md)?)?;
    let m = Reader::new(md_bytes, true);
    let ver_len = u64::from(m.u32(12)?).min(255);
    let mut info = DotNetInfo { version: m.cstr(16, ver_len as usize).unwrap_or_default(), ..Default::default() };
    let hdr = 16 + ver_len.next_multiple_of(4);
    let nstreams = usize::from(m.u16(hdr + 2)?).min(MAX_STREAMS);
    let mut at = hdr + 4;
    let mut streams: Vec<(String, &[u8])> = Vec::new();
    for _ in 0..nstreams {
        let (Some(off), Some(size)) = (m.u32(at), m.u32(at + 4)) else { break };
        let Some(name) = m.cstr(at + 8, 32) else { break };
        at += 8 + (name.len() as u64 + 1).next_multiple_of(4);
        info.streams.push((name.clone(), size));
        let data = m.slice(u64::from(off), u64::from(size)).unwrap_or(&[]);
        streams.push((name, data));
    }
    let stream = |n: &str| streams.iter().find(|(name, _)| name == n).map(|(_, d)| *d).unwrap_or(&[]);
    let heaps = Heaps { strings: stream("#Strings"), guid: stream("#GUID"), blob: stream("#Blob") };
    read_user_strings(stream("#US"), &mut info.user_strings);

    let table_stream = streams.iter().find(|(n, _)| n == "#~" || n == "#-").map(|(_, d)| *d);
    let Some(tables) = table_stream.and_then(Tables::parse) else { return Some(info) };

    info.mvid = tables.get(0x00, 1, 2).and_then(|g| heaps.guid(g));
    info.assembly_name = tables.get(0x20, 1, 7).map(|s| heaps.string(s)).filter(|s| !s.is_empty());

    let type_ref = |row: u32| full_name(heaps.string(tables.get(0x01, row, 2).unwrap_or(0)), heaps.string(tables.get(0x01, row, 1).unwrap_or(0)));
    let type_def = |row: u32| full_name(heaps.string(tables.get(0x02, row, 2).unwrap_or(0)), heaps.string(tables.get(0x02, row, 1).unwrap_or(0)));
    for row in 1..=tables.rows[0x01].min(MAX_NAMES as u32) {
        push_capped(&mut info.type_refs, type_ref(row));
    }
    let ntypes = tables.rows[0x02].min(MAX_NAMES as u32);
    let nmethods = tables.rows[0x06];
    // Type i owns methods MethodList(i) .. MethodList(i + 1) - 1.
    let mut owner = vec![0u32; nmethods.min(MAX_NAMES as u32) as usize + 1];
    for row in 1..=ntypes {
        push_capped(&mut info.types, type_def(row));
        let first = tables.get(0x02, row, 5).unwrap_or(0);
        let next = if row < tables.rows[0x02] { tables.get(0x02, row + 1, 5).unwrap_or(0) } else { nmethods + 1 };
        for m in first..next.min(owner.len() as u32) {
            owner[m as usize] = row;
        }
    }
    let method_name = |row: u32| -> String {
        let name = heaps.string(tables.get(0x06, row, 3).unwrap_or(0));
        match owner.get(row as usize).copied().filter(|o| *o != 0) {
            Some(t) => format!("{}::{name}", type_def(t)),
            None => name,
        }
    };
    for row in 1..=nmethods.min(MAX_NAMES as u32) {
        push_capped(&mut info.methods, method_name(row));
    }
    let class_name = |coded: u32| -> String {
        match decode_coded(MEMBER_REF_PARENT, coded) {
            Some((0x01, row)) => type_ref(row),
            Some((0x02, row)) => type_def(row),
            Some((0x1a, row)) => heaps.string(tables.get(0x1a, row, 0).unwrap_or(0)),
            _ => String::new(),
        }
    };
    for row in 1..=tables.rows[0x0a].min(MAX_NAMES as u32) {
        let class = class_name(tables.get(0x0a, row, 0).unwrap_or(0));
        let name = heaps.string(tables.get(0x0a, row, 1).unwrap_or(0));
        push_capped(&mut info.member_refs, if class.is_empty() { name } else { format!("{class}::{name}") });
    }
    for row in 1..=tables.rows[0x1c].min(MAX_NAMES as u32) {
        let func = heaps.string(tables.get(0x1c, row, 2).unwrap_or(0));
        let module = tables.get(0x1c, row, 3).and_then(|m| tables.get(0x1a, m, 0)).map(|s| heaps.string(s)).unwrap_or_default();
        if !func.is_empty() {
            push_capped(&mut info.pinvokes, if module.is_empty() { func } else { format!("{}!{func}", module_name(&module)) });
        }
    }
    info.typelib = find_guid_attribute(&tables, &heaps, &class_name);
    Some(info)
}

/// `[assembly: Guid("...")]`: a CustomAttribute on the Assembly whose
/// constructor's class is `System.Runtime.InteropServices.GuidAttribute`.
fn find_guid_attribute(tables: &Tables, heaps: &Heaps, class_name: &dyn Fn(u32) -> String) -> Option<String> {
    for row in 1..=tables.rows[0x0c].min(MAX_NAMES as u32) {
        let Some((0x20, _)) = tables.get(0x0c, row, 0).and_then(|p| decode_coded(HAS_CUSTOM_ATTRIBUTE, p)) else { continue };
        let Some((0x0a, ctor)) = tables.get(0x0c, row, 1).and_then(|t| decode_coded(CUSTOM_ATTRIBUTE_TYPE, t)) else { continue };
        if class_name(tables.get(0x0a, ctor, 0).unwrap_or(0)) != "System.Runtime.InteropServices.GuidAttribute" {
            continue;
        }
        // Prolog 0x0001, then a SerString.
        let value = heaps.blob(tables.get(0x0c, row, 2)?)?;
        if value.get(0..2)? != [1, 0] {
            continue;
        }
        let (len, used) = compressed_u32(value.get(2..)?)?;
        let text = value.get(2 + used..2 + used + len as usize)?;
        return Some(String::from_utf8_lossy(text).to_ascii_lowercase());
    }
    None
}

/// `#US`: length-prefixed UTF-16LE strings with a trailing flag byte.
fn read_user_strings(heap: &[u8], out: &mut Vec<String>) {
    let mut at = 1usize;
    while at < heap.len() && out.len() < MAX_USER_STRINGS {
        let Some((len, used)) = compressed_u32(&heap[at..]) else { break };
        let start = at + used;
        let Some(end) = start.checked_add(len as usize).filter(|e| *e <= heap.len()) else { break };
        let body = &heap[start..end.saturating_sub(1).max(start)];
        let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let s = String::from_utf16_lossy(&units);
        if !s.is_empty() {
            out.push(s);
        }
        at = end.max(at + 1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn heap_add(heap: &mut Vec<u8>, s: &str) -> u16 {
        let at = heap.len() as u16;
        heap.extend(s.as_bytes());
        heap.push(0);
        at
    }

    fn table(rows: &[Vec<u16>]) -> Vec<u8> {
        rows.iter().flatten().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// A minimal PE32 with a CLR directory and metadata: Module (MVID),
    /// TypeRef `System.Runtime.InteropServices.GuidAttribute`, TypeDefs
    /// `<Module>` and `Evil.Loader` with method `Run`, a MemberRef `.ctor` on
    /// the GuidAttribute, ModuleRef `kernel32`, ImplMap `VirtualAlloc`,
    /// Assembly `EvilAsm` with `[assembly: Guid(typelib)]`, and `#US` strings.
    pub fn build_dotnet_pe(user_strings: &[&str], typelib: &str) -> Vec<u8> {
        let mut strings = vec![0u8];
        let s_module = heap_add(&mut strings, "evil.exe");
        let s_guid_attr = heap_add(&mut strings, "GuidAttribute");
        let s_interop = heap_add(&mut strings, "System.Runtime.InteropServices");
        let s_mod_type = heap_add(&mut strings, "<Module>");
        let s_loader = heap_add(&mut strings, "Loader");
        let s_evil = heap_add(&mut strings, "Evil");
        let s_run = heap_add(&mut strings, "Run");
        let s_valloc = heap_add(&mut strings, "VirtualAlloc");
        let s_ctor = heap_add(&mut strings, ".ctor");
        let s_k32 = heap_add(&mut strings, "kernel32");
        let s_asm = heap_add(&mut strings, "EvilAsm");
        while strings.len() % 4 != 0 {
            strings.push(0);
        }
        let mut us = vec![0u8];
        for s in user_strings {
            let utf16: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            us.push((utf16.len() + 1) as u8);
            us.extend(utf16);
            us.push(0);
        }
        while us.len() % 4 != 0 {
            us.push(0);
        }
        let guid: Vec<u8> = (1u8..=16).collect();
        let mut blob = vec![0u8];
        let sig_at = blob.len() as u16;
        blob.extend([3, 0x20, 0, 1]);
        let attr_at = blob.len() as u16;
        let mut attr = vec![1u8, 0, typelib.len() as u8];
        attr.extend(typelib.as_bytes());
        attr.extend([0, 0]);
        blob.push(attr.len() as u8);
        blob.extend(attr);
        while blob.len() % 4 != 0 {
            blob.push(0);
        }

        // Tables: Module, TypeRef, TypeDef, MethodDef, MemberRef, CustomAttribute, ModuleRef, ImplMap, Assembly.
        let present = [0x00usize, 0x01, 0x02, 0x06, 0x0a, 0x0c, 0x1a, 0x1c, 0x20];
        let valid: u64 = present.iter().map(|t| 1u64 << t).sum();
        let mut ts = Vec::new();
        ts.extend([0u8; 4]);
        ts.extend([2, 0, 0, 1]);
        ts.extend(valid.to_le_bytes());
        ts.extend(0u64.to_le_bytes());
        let rows = [1u32, 1, 2, 1, 1, 1, 1, 1, 1];
        for n in rows {
            ts.extend(n.to_le_bytes());
        }
        // Module: Generation, Name, Mvid, EncId, EncBaseId
        ts.extend(table(&[vec![0, s_module, 1, 0, 0]]));
        // TypeRef: ResolutionScope, Name, Namespace
        ts.extend(table(&[vec![0, s_guid_attr, s_interop]]));
        // TypeDef: Flags(u32), Name, Namespace, Extends, FieldList, MethodList
        for (name, ns, methods) in [(s_mod_type, 0u16, 1u16), (s_loader, s_evil, 1)] {
            ts.extend(0u32.to_le_bytes());
            ts.extend(table(&[vec![name, ns, 0, 1, methods]]));
        }
        // MethodDef: RVA(u32), ImplFlags, Flags, Name, Signature, ParamList
        ts.extend(0u32.to_le_bytes());
        ts.extend(table(&[vec![0, 0x2096, s_run, sig_at, 1]]));
        // MemberRef: Class (MemberRefParent: TypeRef row 1 = 1<<3 | 1), Name, Signature
        ts.extend(table(&[vec![(1 << 3) | 1, s_ctor, sig_at]]));
        // CustomAttribute: Parent (Assembly row 1: 1<<5 | 14), Type (MemberRef row 1: 1<<3 | 3), Value
        ts.extend(table(&[vec![(1 << 5) | 14, (1 << 3) | 3, attr_at]]));
        // ModuleRef: Name
        ts.extend(table(&[vec![s_k32]]));
        // ImplMap: Flags, MemberForwarded (MethodDef row 1: 1<<1 | 1), ImportName, ImportScope
        ts.extend(table(&[vec![0x0100, (1 << 1) | 1, s_valloc, 1]]));
        // Assembly: HashAlgId(u32), 4 x u16, Flags(u32), PublicKey, Name, Culture
        ts.extend(0x8004u32.to_le_bytes());
        ts.extend(table(&[vec![1, 0, 0, 0]]));
        ts.extend(0u32.to_le_bytes());
        ts.extend(table(&[vec![0, s_asm, 0]]));
        while ts.len() % 4 != 0 {
            ts.push(0);
        }

        let version = b"v4.0.30319\0\0";
        let streams: [(&str, &Vec<u8>); 5] = [("#~", &ts), ("#Strings", &strings), ("#US", &us), ("#GUID", &guid), ("#Blob", &blob)];
        let mut md = Vec::new();
        md.extend(b"BSJB");
        md.extend([1, 0, 1, 0, 0, 0, 0, 0]);
        md.extend((version.len() as u32).to_le_bytes());
        md.extend(version);
        md.extend([0, 0]);
        md.extend((streams.len() as u16).to_le_bytes());
        let hdr_len: usize = md.len() + streams.iter().map(|(n, _)| 8 + (n.len() + 1).next_multiple_of(4)).sum::<usize>();
        let mut off = hdr_len;
        for (name, data) in &streams {
            md.extend((off as u32).to_le_bytes());
            md.extend((data.len() as u32).to_le_bytes());
            let mut n = name.as_bytes().to_vec();
            n.push(0);
            while n.len() % 4 != 0 {
                n.push(0);
            }
            md.extend(n);
            off += data.len();
        }
        for (_, data) in &streams {
            md.extend(data.iter());
        }

        // PE32: headers in the first 0x200 bytes, one section `.text` at RVA 0x2000 / raw 0x200.
        let mut pe = vec![0u8; 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        pe[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes());
        let opt = 0x98;
        pe[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        pe[opt + 16..opt + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes());
        pe[opt + 32..opt + 36].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        pe[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        let cli_rva = 0x2000u32;
        let dir14 = opt + 96 + 14 * 8;
        pe[dir14..dir14 + 4].copy_from_slice(&cli_rva.to_le_bytes());
        pe[dir14 + 4..dir14 + 8].copy_from_slice(&72u32.to_le_bytes());
        let mut text = vec![0u8; 72];
        text[0..4].copy_from_slice(&72u32.to_le_bytes());
        text[8..12].copy_from_slice(&(cli_rva + 72).to_le_bytes());
        text[12..16].copy_from_slice(&(md.len() as u32).to_le_bytes());
        text.extend(&md);
        let raw = (text.len() as u32).next_multiple_of(0x200);
        let sec = opt + 0xe0;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        pe[sec + 12..sec + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[sec + 16..sec + 20].copy_from_slice(&raw.to_le_bytes());
        pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        pe.extend(text);
        pe.resize(0x200 + raw as usize, 0);
        pe
    }

    #[test]
    fn parses_the_synthetic_assembly() {
        let typelib = "d1e2f3a4-0000-4000-8000-123456789abc";
        let pe = build_dotnet_pe(&["http://evil.example/payload", "short"], typelib);
        assert!(has_clr_metadata(&pe));
        let info = parse_dotnet(&pe).unwrap();
        assert_eq!(info.version, "v4.0.30319");
        assert_eq!(info.streams.iter().map(|s| s.0.as_str()).collect::<Vec<_>>(), ["#~", "#Strings", "#US", "#GUID", "#Blob"]);
        assert_eq!(info.mvid.as_deref(), Some("04030201-0605-0807-090a-0b0c0d0e0f10"));
        assert_eq!(info.typelib.as_deref(), Some(typelib));
        assert_eq!(info.assembly_name.as_deref(), Some("EvilAsm"));
        assert_eq!(info.types, vec!["<Module>", "Evil.Loader"]);
        assert_eq!(info.type_refs, vec!["System.Runtime.InteropServices.GuidAttribute"]);
        assert_eq!(info.methods, vec!["Evil.Loader::Run"]);
        assert_eq!(info.member_refs, vec!["System.Runtime.InteropServices.GuidAttribute::.ctor"]);
        assert_eq!(info.pinvokes, vec!["kernel32.dll!VirtualAlloc"]);
        assert_eq!(info.user_strings, vec!["http://evil.example/payload", "short"]);
        assert_eq!(normalize_guid("{D1E2F3A4-0000-4000-8000-123456789ABC}"), normalize_guid(typelib));
    }

    #[test]
    fn hostile_metadata_does_not_panic() {
        let pe = build_dotnet_pe(&["abcdefgh"], "x");
        for cut in [0, 0x80, 0x200, 0x248, pe.len() / 2, pe.len() - 1] {
            let _ = parse_dotnet(&pe[..cut]);
        }
        let mut noisy = pe.clone();
        for b in noisy.iter_mut().skip(0x248).step_by(3) {
            *b = 0xff;
        }
        let _ = parse_dotnet(&noisy);
        assert!(!has_clr_metadata(b"MZ"));
    }
}
