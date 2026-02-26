use std::{
    collections::HashMap,
    error::Error,
    ffi::OsStr,
    fmt::{Debug, Formatter},
    path::Path,
    {fmt, fs},
};

use object::{
    read::pe::{ImageNtHeaders, PeFile, PeFile32, PeFile64},
    {AddressSize, Object},
};

use serde::Serialize;

use crate::PeParsingError::{ArchNotImplementedError, UnknownAddrSizeError};

#[derive(Serialize)]
pub struct StaticFeatures {
    pub appname: String,
    pub data_len: usize,
    pub section_table_len: usize,
    pub imports: Vec<LibImport>,
    pub has_dbg_symbols: bool,
}

#[derive(Serialize)]
pub struct LibImport {
    pub lib: String,
    pub import: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtSyscallEntry {
    pub id: u32,
    pub api: String,
}

impl StaticFeatures {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}

pub enum PeParsingError {
    ArchNotImplementedError,
    UnknownAddrSizeError,
}

impl fmt::Display for PeParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Arch not implemented")
    }
}

impl Debug for PeParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Arch not implemented")
    }
}

impl Error for PeParsingError {}

pub fn inspect_pe(path: &Path) -> Result<StaticFeatures, Box<dyn Error>> {
    let bin_data = fs::read(path)?;
    let obj_data = object::File::parse(&*bin_data)?;
    let arch = obj_data.architecture();
    if let Some(addr_size) = arch.address_size() {
        match addr_size {
            AddressSize::U32 => {
                let obj_pe: PeFile32 = PeFile::parse(&*bin_data)?;
                inspect_pe_aux(path, &bin_data, &obj_pe)
            }
            AddressSize::U64 => {
                let obj_pe: PeFile64 = PeFile::parse(&*bin_data)?;
                inspect_pe_aux(path, &bin_data, &obj_pe)
            }
            _ => Err(Box::new(ArchNotImplementedError)),
        }
    } else {
        Err(Box::new(UnknownAddrSizeError))
    }
}

fn inspect_pe_aux<Pe: ImageNtHeaders>(
    path: &Path,
    bin_data: &Vec<u8>,
    obj_pe: &PeFile<Pe>,
) -> Result<StaticFeatures, Box<dyn Error>> {
    let pe_imports = obj_pe.imports()?;
    let mut lib_imports: Vec<LibImport> = vec![];
    for import in pe_imports {
        lib_imports.push(LibImport {
            lib: String::from_utf8(Vec::from(import.library())).unwrap(),
            import: String::from_utf8(Vec::from(import.name())).unwrap(),
        });
    }

    Ok(StaticFeatures {
        appname: path
            .file_name()
            .unwrap_or(OsStr::new("UNKNOWN.exe"))
            .to_os_string()
            .into_string()
            .unwrap_or(String::from("UNKNOWN.exe")),
        data_len: bin_data.len(),
        section_table_len: obj_pe.section_table().len(),
        imports: lib_imports,
        has_dbg_symbols: obj_pe.has_debug_symbols(),
    })
}

pub fn inspect_ntdll_syscalls(path: &Path) -> Result<Vec<NtSyscallEntry>, Box<dyn Error>> {
    let bin_data = fs::read(path)?;
    let obj_data = object::File::parse(&*bin_data)?;
    let arch = obj_data.architecture();
    if let Some(addr_size) = arch.address_size() {
        match addr_size {
            AddressSize::U32 => {
                let obj_pe: PeFile32 = PeFile::parse(&*bin_data)?;
                inspect_ntdll_syscalls_aux(&bin_data, &obj_pe)
            }
            AddressSize::U64 => {
                let obj_pe: PeFile64 = PeFile::parse(&*bin_data)?;
                inspect_ntdll_syscalls_aux(&bin_data, &obj_pe)
            }
            _ => Err(Box::new(ArchNotImplementedError)),
        }
    } else {
        Err(Box::new(UnknownAddrSizeError))
    }
}

fn inspect_ntdll_syscalls_aux<Pe: ImageNtHeaders>(
    bin_data: &Vec<u8>,
    obj_pe: &PeFile<Pe>,
) -> Result<Vec<NtSyscallEntry>, Box<dyn Error>> {
    let image_base = obj_pe.relative_address_base();
    let mut map: HashMap<u32, String> = HashMap::new();

    for export in obj_pe.exports()? {
        let name_bytes = export.name();
        if !name_bytes.starts_with(b"Nt") {
            continue;
        }

        let export_name = match std::str::from_utf8(name_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let abs_address = export.address();
        if abs_address < image_base {
            continue;
        }

        let rva_u64 = abs_address - image_base;
        if rva_u64 > u32::MAX as u64 {
            continue;
        }

        let code = match obj_pe.section_table().pe_data_at(&**bin_data, rva_u64 as u32) {
            Some(v) => v,
            None => continue,
        };

        if let Some(syscall_id) = extract_syscall_id(code) {
            map.entry(syscall_id).or_insert_with(|| export_name.to_string());
        }
    }

    let mut entries: Vec<NtSyscallEntry> = map
        .into_iter()
        .map(|(id, api)| NtSyscallEntry { id, api })
        .collect();
    entries.sort_by_key(|e| e.id);
    Ok(entries)
}

fn extract_syscall_id(code: &[u8]) -> Option<u32> {
    if code.len() < 8 {
        return None;
    }

    let scan_len = code.len().min(40);
    for i in 0..scan_len.saturating_sub(7) {
        if code[i] != 0xB8 {
            continue;
        }

        let imm = u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);

        let tail_max = (i + 16).min(scan_len.saturating_sub(1));
        for j in (i + 5)..tail_max {
            if code[j] == 0x0F && code[j + 1] == 0x05 {
                return Some(imm);
            }
        }
    }

    None
}
