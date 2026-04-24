// src-tauri/src/pe_info.rs
// Parse PE32/PE64 and ELF headers via goblin.
// Returns a structured description for the frontend tree-view.

use goblin::Object;
use serde::{Deserialize, Serialize};

// ─── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderField {
    pub name:  String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name:       String,
    pub virt_addr:  String,
    pub virt_size:  String,
    pub raw_offset: String,
    pub raw_size:   String,
    pub entropy:    f32,
    pub flags:      String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub dll:      String,
    pub function: String,
    pub ordinal:  Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name:    Option<String>,
    pub offset:  String,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedHeaders {
    pub format:   String,   // "PE32", "PE64", "ELF32", "ELF64", "Unknown"
    pub fields:   Vec<HeaderField>,
    pub sections: Vec<SectionInfo>,
    pub imports:  Vec<ImportEntry>,
    pub exports:  Vec<ExportEntry>,
}

// ─── Main entry point ─────────────────────────────────────────────────────────

pub fn parse(data: &[u8]) -> Result<ParsedHeaders, String> {
    match Object::parse(data).map_err(|e| e.to_string())? {
        Object::PE(pe)  => parse_pe(data, pe),
        Object::Elf(elf) => parse_elf(data, elf),
        _               => Ok(ParsedHeaders {
            format:   "Unknown / Unsupported".into(),
            fields:   vec![HeaderField { name: "Note".into(), value: "Not a PE or ELF binary".into() }],
            sections: Vec::new(),
            imports:  Vec::new(),
            exports:  Vec::new(),
        }),
    }
}

// ─── PE ───────────────────────────────────────────────────────────────────────

fn parse_pe(data: &[u8], pe: goblin::pe::PE) -> Result<ParsedHeaders, String> {
    use crate::entropy::shannon;

    let format = if pe.is_64 { "PE64" } else { "PE32" }.to_string();

    // ── Header fields ──────────────────────────────────────────────────────
    let mut fields = Vec::new();

    // Optional header basics
    if let Some(opt) = &pe.header.optional_header {
        fields.push(field("Entry Point",
            format!("0x{:08X}", opt.standard_fields.address_of_entry_point)));
        fields.push(field("Image Base",
            format!("0x{:016X}", opt.windows_fields.image_base)));
        fields.push(field("Size of Image",
            format!("0x{:X} ({} KiB)",
                opt.windows_fields.size_of_image,
                opt.windows_fields.size_of_image / 1024)));
        fields.push(field("Subsystem",
            subsystem_name(opt.windows_fields.subsystem)));
        fields.push(field("DLL Characteristics",
            format!("0x{:04X}", opt.windows_fields.dll_characteristics)));
    }

    // COFF header
    let coff = &pe.header.coff_header;
    fields.push(field("Machine",     machine_name(coff.machine)));
    fields.push(field("Sections",    coff.number_of_sections.to_string()));
    fields.push(field("Timestamp",   format!("0x{:08X}", coff.time_date_stamp)));
    fields.push(field("Characteristics", format!("0x{:04X}", coff.characteristics)));
    fields.push(field("Is DLL",      pe.is_lib.to_string()));
    fields.push(field("Is 64-bit",   pe.is_64.to_string()));

    // ── Sections ───────────────────────────────────────────────────────────
    let sections: Vec<SectionInfo> = pe.sections.iter().map(|s| {
        let raw_start = s.pointer_to_raw_data as usize;
        let raw_end   = (raw_start + s.size_of_raw_data as usize).min(data.len());
        let ent = if raw_end > raw_start { shannon(&data[raw_start..raw_end]) } else { 0.0 };

        let name = String::from_utf8_lossy(&s.name)
            .trim_matches('\0').to_string();

        SectionInfo {
            name,
            virt_addr:  format!("0x{:08X}", s.virtual_address),
            virt_size:  format!("0x{:X}",   s.virtual_size),
            raw_offset: format!("0x{:08X}", s.pointer_to_raw_data),
            raw_size:   format!("0x{:X}",   s.size_of_raw_data),
            entropy:    (ent * 100.0).round() / 100.0,
            flags:      format!("0x{:08X}", s.characteristics),
        }
    }).collect();

    // ── Imports ────────────────────────────────────────────────────────────
    let mut imports = Vec::new();
    for imp in &pe.imports {
        imports.push(ImportEntry {
            dll:      imp.dll.to_string(),
            function: imp.name.to_string(),
            ordinal:  Some(imp.ordinal as u32),
        });
    }

    // ── Exports ────────────────────────────────────────────────────────────
    let export_ordinal_base = pe.export_data
        .as_ref()
        .map(|data| data.export_directory_table.ordinal_base)
        .unwrap_or(0);

    let mut exports = Vec::new();
    for (index, exp) in pe.exports.iter().enumerate() {
        let ordinal = pe.export_data
            .as_ref()
            .and_then(|data| data.export_ordinal_table.get(index))
            .map(|ordinal| export_ordinal_base + u32::from(*ordinal))
            .unwrap_or(export_ordinal_base + index as u32);

        exports.push(ExportEntry {
            name:    exp.name.map(|n| n.to_string()),
            offset:  exp.offset.map(|o| format!("0x{:X}", o)).unwrap_or_default(),
            ordinal,
        });
    }

    Ok(ParsedHeaders { format, fields, sections, imports, exports })
}

// ─── ELF ──────────────────────────────────────────────────────────────────────

fn parse_elf(data: &[u8], elf: goblin::elf::Elf) -> Result<ParsedHeaders, String> {
    use crate::entropy::shannon;

    let bits   = if elf.is_64 { "64" } else { "32" };
    let format = format!("ELF{bits}");

    let mut fields = Vec::new();
    fields.push(field("Type",          elf_type_name(elf.header.e_type)));
    fields.push(field("Machine",       format!("0x{:04X}", elf.header.e_machine)));
    fields.push(field("Entry Point",   format!("0x{:X}",   elf.header.e_entry)));
    fields.push(field("Endianness",    if elf.little_endian { "Little" } else { "Big" }.to_string()));
    fields.push(field("Is 64-bit",     elf.is_64.to_string()));
    fields.push(field("Interpreter",   elf.interpreter.unwrap_or("(none)").to_string()));

    let sections: Vec<SectionInfo> = elf.section_headers.iter().map(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?").to_string();
        let off  = sh.sh_offset as usize;
        let sz   = sh.sh_size   as usize;
        let end  = (off + sz).min(data.len());
        let ent  = if end > off { shannon(&data[off..end]) } else { 0.0 };

        SectionInfo {
            name,
            virt_addr:  format!("0x{:X}",  sh.sh_addr),
            virt_size:  format!("0x{:X}",  sh.sh_size),
            raw_offset: format!("0x{:X}",  sh.sh_offset),
            raw_size:   format!("0x{:X}",  sh.sh_size),
            entropy:    (ent * 100.0).round() / 100.0,
            flags:      format!("0x{:X}",  sh.sh_flags),
        }
    }).collect();

    let imports: Vec<ImportEntry> = elf.dynsyms.iter()
        .filter(|s| s.is_import())
        .map(|s| ImportEntry {
            dll:      "(dynamic)".into(),
            function: elf.dynstrtab.get_at(s.st_name).unwrap_or("?").to_string(),
            ordinal:  None,
        })
        .collect();

    let exports: Vec<ExportEntry> = elf.dynsyms.iter()
        .filter(|s| !s.is_import() && s.st_value != 0)
        .enumerate()
        .map(|(i, s)| ExportEntry {
            name:    Some(elf.dynstrtab.get_at(s.st_name).unwrap_or("?").to_string()),
            offset:  format!("0x{:X}", s.st_value),
            ordinal: i as u32,
        })
        .collect();

    Ok(ParsedHeaders { format, fields, sections, imports, exports })
}

// ─── Small helpers ────────────────────────────────────────────────────────────

fn field(name: &str, value: String) -> HeaderField {
    HeaderField { name: name.to_string(), value }
}

fn machine_name(m: u16) -> String {
    match m {
        0x014C => "x86 (i386)".into(),
        0x8664 => "x86-64 (AMD64)".into(),
        0x01C4 => "ARM (Thumb-2)".into(),
        0xAA64 => "ARM64 (AArch64)".into(),
        0x0200 => "IA-64 (Itanium)".into(),
        _      => format!("0x{m:04X}"),
    }
}

fn subsystem_name(s: u16) -> String {
    match s {
        1 => "Native".into(),
        2 => "Windows GUI".into(),
        3 => "Windows Console (CUI)".into(),
        9 => "Windows CE".into(),
        _ => format!("0x{s:04X}"),
    }
}

fn elf_type_name(t: u16) -> String {
    match t {
        1 => "ET_REL (Relocatable)".into(),
        2 => "ET_EXEC (Executable)".into(),
        3 => "ET_DYN (Shared object)".into(),
        4 => "ET_CORE (Core dump)".into(),
        _ => format!("0x{t:04X}"),
    }
}
