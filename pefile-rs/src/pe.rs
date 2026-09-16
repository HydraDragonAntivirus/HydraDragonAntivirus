use std::path::Path;
use crate::error::PeError;
use crate::headers::{
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    DIRECTORY_ENTRY_EXPORT, DIRECTORY_ENTRY_IMPORT, DIRECTORY_ENTRY_DEBUG,
    DIRECTORY_ENTRY_TLS,
};
use crate::sections::Section;
use crate::directories::{
    ImportDirectory, ImportSymbol, ExportDirectory, ExportSymbol,
    ResourceDirectory,
    DebugEntry, TlsDirectory, LoadConfigDirectory, RelocationBlock,
};
use crate::utils::calculate_entropy;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PE {
    pub raw_data: Vec<u8>,
    pub dos_header: DosHeader,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<Section>,
    pub is_64bit: bool,

    pub imports: Vec<ImportDirectory>,
    pub exports: Option<ExportDirectory>,
    pub resources: Option<ResourceDirectory>,
    pub debug_entries: Vec<DebugEntry>,
    pub tls: Option<TlsDirectory>,
    pub load_config: Option<LoadConfigDirectory>,
    pub relocations: Vec<RelocationBlock>,
}

impl PE {
    /// Parse PE from memory byte slice (matching Python pefile.PE(data=...))
    pub fn parse(data: &[u8]) -> Result<Self, PeError> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err(PeError::InvalidDosSignature);
        }

        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
        if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(PeError::InvalidPeSignature);
        }

        let dos_header = DosHeader {
            e_magic: u16::from_le_bytes(data[0..2].try_into().unwrap()),
            e_cblp: u16::from_le_bytes(data[2..4].try_into().unwrap_or([0; 2])),
            e_cp: u16::from_le_bytes(data[4..6].try_into().unwrap_or([0; 2])),
            e_crlc: u16::from_le_bytes(data[6..8].try_into().unwrap_or([0; 2])),
            e_cparhdr: u16::from_le_bytes(data[8..10].try_into().unwrap_or([0; 2])),
            e_minalloc: u16::from_le_bytes(data[10..12].try_into().unwrap_or([0; 2])),
            e_maxalloc: u16::from_le_bytes(data[12..14].try_into().unwrap_or([0; 2])),
            e_ss: u16::from_le_bytes(data[14..16].try_into().unwrap_or([0; 2])),
            e_sp: u16::from_le_bytes(data[16..18].try_into().unwrap_or([0; 2])),
            e_csum: u16::from_le_bytes(data[18..20].try_into().unwrap_or([0; 2])),
            e_ip: u16::from_le_bytes(data[20..22].try_into().unwrap_or([0; 2])),
            e_cs: u16::from_le_bytes(data[22..24].try_into().unwrap_or([0; 2])),
            e_lfarlc: u16::from_le_bytes(data[24..26].try_into().unwrap_or([0; 2])),
            e_ovno: u16::from_le_bytes(data[26..28].try_into().unwrap_or([0; 2])),
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: e_lfanew as u32,
        };

        let coff_off = e_lfanew + 4;
        let machine = u16::from_le_bytes(data[coff_off..coff_off + 2].try_into().unwrap());
        let number_of_sections = u16::from_le_bytes(data[coff_off + 2..coff_off + 4].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(data[coff_off + 4..coff_off + 8].try_into().unwrap());
        let pointer_to_symbol_table = u32::from_le_bytes(data[coff_off + 8..coff_off + 12].try_into().unwrap());
        let number_of_symbols = u32::from_le_bytes(data[coff_off + 12..coff_off + 16].try_into().unwrap());
        let size_of_optional_header = u16::from_le_bytes(data[coff_off + 16..coff_off + 18].try_into().unwrap()) as usize;
        let characteristics = u16::from_le_bytes(data[coff_off + 18..coff_off + 20].try_into().unwrap());

        let file_header = FileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header: size_of_optional_header as u16,
            characteristics,
        };

        let opt_off = coff_off + 20;
        let magic = if opt_off + 2 <= data.len() {
            u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().unwrap())
        } else {
            0
        };

        let is_64bit = magic == 0x20b;

        let optional_header = if size_of_optional_header >= 28 && opt_off + 28 <= data.len() {
            let major_linker_version = data[opt_off + 2];
            let minor_linker_version = data[opt_off + 3];
            let size_of_code = u32::from_le_bytes(data[opt_off + 4..opt_off + 8].try_into().unwrap());
            let size_of_initialized_data = u32::from_le_bytes(data[opt_off + 8..opt_off + 12].try_into().unwrap());
            let size_of_uninitialized_data = u32::from_le_bytes(data[opt_off + 12..opt_off + 16].try_into().unwrap());
            let address_of_entry_point = u32::from_le_bytes(data[opt_off + 16..opt_off + 20].try_into().unwrap());
            let base_of_code = u32::from_le_bytes(data[opt_off + 20..opt_off + 24].try_into().unwrap());
            let base_of_data = if !is_64bit && opt_off + 28 <= data.len() {
                u32::from_le_bytes(data[opt_off + 24..opt_off + 28].try_into().unwrap())
            } else {
                0
            };

            let (image_base, win_fields_off) = if is_64bit {
                (u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().unwrap_or([0; 8])), opt_off + 32)
            } else {
                (u32::from_le_bytes(data[opt_off + 28..opt_off + 32].try_into().unwrap_or([0; 4])) as u64, opt_off + 32)
            };

            let section_alignment = if win_fields_off + 4 <= data.len() { u32::from_le_bytes(data[win_fields_off..win_fields_off + 4].try_into().unwrap()) } else { 0x1000 };
            let file_alignment = if win_fields_off + 8 <= data.len() { u32::from_le_bytes(data[win_fields_off + 4..win_fields_off + 8].try_into().unwrap()) } else { 0x200 };
            let major_operating_system_version = if win_fields_off + 10 <= data.len() { u16::from_le_bytes(data[win_fields_off + 8..win_fields_off + 10].try_into().unwrap()) } else { 0 };
            let minor_operating_system_version = if win_fields_off + 12 <= data.len() { u16::from_le_bytes(data[win_fields_off + 10..win_fields_off + 12].try_into().unwrap()) } else { 0 };
            let major_image_version = if win_fields_off + 14 <= data.len() { u16::from_le_bytes(data[win_fields_off + 12..win_fields_off + 14].try_into().unwrap()) } else { 0 };
            let minor_image_version = if win_fields_off + 16 <= data.len() { u16::from_le_bytes(data[win_fields_off + 14..win_fields_off + 16].try_into().unwrap()) } else { 0 };
            let major_subsystem_version = if win_fields_off + 18 <= data.len() { u16::from_le_bytes(data[win_fields_off + 16..win_fields_off + 18].try_into().unwrap()) } else { 0 };
            let minor_subsystem_version = if win_fields_off + 20 <= data.len() { u16::from_le_bytes(data[win_fields_off + 18..win_fields_off + 20].try_into().unwrap()) } else { 0 };
            let win32_version_value = if win_fields_off + 24 <= data.len() { u32::from_le_bytes(data[win_fields_off + 20..win_fields_off + 24].try_into().unwrap()) } else { 0 };
            let size_of_image = if win_fields_off + 28 <= data.len() { u32::from_le_bytes(data[win_fields_off + 24..win_fields_off + 28].try_into().unwrap()) } else { 0 };
            let size_of_headers = if win_fields_off + 32 <= data.len() { u32::from_le_bytes(data[win_fields_off + 28..win_fields_off + 32].try_into().unwrap()) } else { 0 };
            let check_sum = if win_fields_off + 36 <= data.len() { u32::from_le_bytes(data[win_fields_off + 32..win_fields_off + 36].try_into().unwrap()) } else { 0 };
            let subsystem = if win_fields_off + 38 <= data.len() { u16::from_le_bytes(data[win_fields_off + 36..win_fields_off + 38].try_into().unwrap()) } else { 0 };
            let dll_characteristics = if win_fields_off + 40 <= data.len() { u16::from_le_bytes(data[win_fields_off + 38..win_fields_off + 40].try_into().unwrap()) } else { 0 };

            let (size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit, loader_flags, num_rva, dd_start) = if is_64bit {
                let s_res = if win_fields_off + 48 <= data.len() { u64::from_le_bytes(data[win_fields_off + 40..win_fields_off + 48].try_into().unwrap()) } else { 0 };
                let s_com = if win_fields_off + 56 <= data.len() { u64::from_le_bytes(data[win_fields_off + 48..win_fields_off + 56].try_into().unwrap()) } else { 0 };
                let h_res = if win_fields_off + 64 <= data.len() { u64::from_le_bytes(data[win_fields_off + 56..win_fields_off + 64].try_into().unwrap()) } else { 0 };
                let h_com = if win_fields_off + 72 <= data.len() { u64::from_le_bytes(data[win_fields_off + 64..win_fields_off + 72].try_into().unwrap()) } else { 0 };
                let l_flags = if win_fields_off + 76 <= data.len() { u32::from_le_bytes(data[win_fields_off + 72..win_fields_off + 76].try_into().unwrap()) } else { 0 };
                let n_rva = if win_fields_off + 80 <= data.len() { u32::from_le_bytes(data[win_fields_off + 76..win_fields_off + 80].try_into().unwrap()) } else { 0 };
                (s_res, s_com, h_res, h_com, l_flags, n_rva, win_fields_off + 80)
            } else {
                let s_res = if win_fields_off + 44 <= data.len() { u32::from_le_bytes(data[win_fields_off + 40..win_fields_off + 44].try_into().unwrap()) as u64 } else { 0 };
                let s_com = if win_fields_off + 48 <= data.len() { u32::from_le_bytes(data[win_fields_off + 44..win_fields_off + 48].try_into().unwrap()) as u64 } else { 0 };
                let h_res = if win_fields_off + 52 <= data.len() { u32::from_le_bytes(data[win_fields_off + 48..win_fields_off + 52].try_into().unwrap()) as u64 } else { 0 };
                let h_com = if win_fields_off + 56 <= data.len() { u32::from_le_bytes(data[win_fields_off + 52..win_fields_off + 56].try_into().unwrap()) as u64 } else { 0 };
                let l_flags = if win_fields_off + 60 <= data.len() { u32::from_le_bytes(data[win_fields_off + 56..win_fields_off + 60].try_into().unwrap()) } else { 0 };
                let n_rva = if win_fields_off + 64 <= data.len() { u32::from_le_bytes(data[win_fields_off + 60..win_fields_off + 64].try_into().unwrap()) } else { 0 };
                (s_res, s_com, h_res, h_com, l_flags, n_rva, win_fields_off + 64)
            };

            let mut data_directories = Vec::new();
            for i in 0..num_rva.min(16) as usize {
                let entry_off = dd_start + i * 8;
                if entry_off + 8 <= data.len() {
                    let virtual_address = u32::from_le_bytes(data[entry_off..entry_off + 4].try_into().unwrap());
                    let size = u32::from_le_bytes(data[entry_off + 4..entry_off + 8].try_into().unwrap());
                    data_directories.push(DataDirectory { virtual_address, size });
                }
            }

            OptionalHeader {
                magic,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                address_of_entry_point,
                base_of_code,
                base_of_data,
                image_base,
                section_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_subsystem_version,
                minor_subsystem_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                check_sum,
                subsystem,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                number_of_rva_and_sizes: num_rva,
                data_directories,
            }
        } else {
            OptionalHeader::default()
        };

        let sec_start = opt_off + size_of_optional_header;
        let mut sections = Vec::new();
        for i in 0..number_of_sections as usize {
            let off = sec_start + i * 40;
            if off + 40 <= data.len() {
                let name_raw = &data[off..off + 8];
                let name = String::from_utf8_lossy(name_raw).trim_end_matches('\0').to_string();
                let virtual_size = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
                let virtual_address = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
                let size_of_raw_data = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
                let pointer_to_raw_data = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap());
                let pointer_to_relocations = u32::from_le_bytes(data[off + 24..off + 28].try_into().unwrap());
                let pointer_to_linenumbers = u32::from_le_bytes(data[off + 28..off + 32].try_into().unwrap());
                let number_of_relocations = u16::from_le_bytes(data[off + 32..off + 34].try_into().unwrap());
                let number_of_linenumbers = u16::from_le_bytes(data[off + 34..off + 36].try_into().unwrap());
                let characteristics = u32::from_le_bytes(data[off + 36..off + 40].try_into().unwrap());

                sections.push(Section {
                    name,
                    virtual_size,
                    virtual_address,
                    size_of_raw_data,
                    pointer_to_raw_data,
                    pointer_to_relocations,
                    pointer_to_linenumbers,
                    number_of_relocations,
                    number_of_linenumbers,
                    characteristics,
                });
            }
        }

        let mut pe = PE {
            raw_data: data.to_vec(),
            dos_header,
            file_header,
            optional_header,
            sections,
            is_64bit,
            imports: Vec::new(),
            exports: None,
            resources: None,
            debug_entries: Vec::new(),
            tls: None,
            load_config: None,
            relocations: Vec::new(),
        };

        pe.parse_imports();
        pe.parse_exports();
        pe.parse_debug();
        pe.parse_tls();

        Ok(pe)
    }

    pub fn from_file(path: &Path) -> Result<Self, PeError> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
    }

    pub fn get_offset_from_rva(&self, rva: u32) -> Result<usize, PeError> {
        for s in &self.sections {
            let limit = s.virtual_size.max(s.size_of_raw_data);
            if rva >= s.virtual_address && rva < s.virtual_address + limit {
                return Ok((rva - s.virtual_address + s.pointer_to_raw_data) as usize);
            }
        }
        Err(PeError::RvaNotMapped(rva))
    }

    pub fn get_rva_from_offset(&self, offset: usize) -> Result<u32, PeError> {
        let off = offset as u32;
        for s in &self.sections {
            if off >= s.pointer_to_raw_data && off < s.pointer_to_raw_data + s.size_of_raw_data {
                return Ok(off - s.pointer_to_raw_data + s.virtual_address);
            }
        }
        Err(PeError::OffsetNotMapped(off))
    }

    pub fn get_string_at_rva(&self, rva: u32, max_len: usize) -> Option<String> {
        let off = self.get_offset_from_rva(rva).ok()?;
        if off >= self.raw_data.len() {
            return None;
        }
        let mut end = off;
        while end < self.raw_data.len() && self.raw_data[end] != 0 && end - off < max_len {
            end += 1;
        }
        String::from_utf8(self.raw_data[off..end].to_vec()).ok()
    }

    pub fn get_data(&self, rva: u32, length: usize) -> Option<&[u8]> {
        let off = self.get_offset_from_rva(rva).ok()?;
        if off + length <= self.raw_data.len() {
            Some(&self.raw_data[off..off + length])
        } else {
            None
        }
    }

    pub fn get_entropy(&self) -> f64 {
        calculate_entropy(&self.raw_data)
    }

    pub fn is_dll(&self) -> bool {
        (self.file_header.characteristics & 0x2000) != 0
    }

    pub fn is_exe(&self) -> bool {
        (self.file_header.characteristics & 0x0002) != 0 && !self.is_dll()
    }

    pub fn is_driver(&self) -> bool {
        self.optional_header.subsystem == 1
    }

    fn parse_imports(&mut self) {
        if self.optional_header.data_directories.len() <= DIRECTORY_ENTRY_IMPORT {
            return;
        }
        let imp_dir = &self.optional_header.data_directories[DIRECTORY_ENTRY_IMPORT];
        if imp_dir.virtual_address == 0 || imp_dir.size == 0 {
            return;
        }

        let mut desc_off = match self.get_offset_from_rva(imp_dir.virtual_address) {
            Ok(o) => o,
            Err(_) => return,
        };

        let raw = &self.raw_data;
        let mut imports = Vec::new();

        while desc_off + 20 <= raw.len() {
            let orig_first_thunk = u32::from_le_bytes(raw[desc_off..desc_off + 4].try_into().unwrap());
            let time_date_stamp = u32::from_le_bytes(raw[desc_off + 4..desc_off + 8].try_into().unwrap());
            let forwarder_chain = u32::from_le_bytes(raw[desc_off + 8..desc_off + 12].try_into().unwrap());
            let name_rva = u32::from_le_bytes(raw[desc_off + 12..desc_off + 16].try_into().unwrap());
            let first_thunk = u32::from_le_bytes(raw[desc_off + 16..desc_off + 20].try_into().unwrap());

            if orig_first_thunk == 0 && first_thunk == 0 && name_rva == 0 {
                break;
            }

            let dll_name = self.get_string_at_rva(name_rva, 256).unwrap_or_default();
            let mut entries = Vec::new();
            let thunk_rva_base = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk };
            let mut thunk_idx = 0;

            if self.is_64bit {
                while let Ok(t_off) = self.get_offset_from_rva(thunk_rva_base + thunk_idx * 8) {
                    if t_off + 8 > raw.len() { break; }
                    let thunk_val = u64::from_le_bytes(raw[t_off..t_off + 8].try_into().unwrap());
                    if thunk_val == 0 { break; }

                    if (thunk_val & 0x8000_0000_0000_0000) != 0 {
                        entries.push(ImportSymbol {
                            name: None,
                            ordinal: Some((thunk_val & 0xFFFF) as u16),
                            address: thunk_val,
                            hint: None,
                        });
                    } else {
                        let name_rva = (thunk_val & 0xFFFF_FFFF) as u32;
                        if let Ok(ibn_off) = self.get_offset_from_rva(name_rva) {
                            if ibn_off + 2 <= raw.len() {
                                let hint = u16::from_le_bytes(raw[ibn_off..ibn_off + 2].try_into().unwrap());
                                let name = self.get_string_at_rva(name_rva + 2, 256);
                                entries.push(ImportSymbol {
                                    name,
                                    ordinal: None,
                                    address: thunk_val,
                                    hint: Some(hint),
                                });
                            }
                        }
                    }
                    thunk_idx += 1;
                }
            } else {
                while let Ok(t_off) = self.get_offset_from_rva(thunk_rva_base + thunk_idx * 4) {
                    if t_off + 4 > raw.len() { break; }
                    let thunk_val = u32::from_le_bytes(raw[t_off..t_off + 4].try_into().unwrap());
                    if thunk_val == 0 { break; }

                    if (thunk_val & 0x8000_0000) != 0 {
                        entries.push(ImportSymbol {
                            name: None,
                            ordinal: Some((thunk_val & 0xFFFF) as u16),
                            address: thunk_val as u64,
                            hint: None,
                        });
                    } else {
                        if let Ok(ibn_off) = self.get_offset_from_rva(thunk_val) {
                            if ibn_off + 2 <= raw.len() {
                                let hint = u16::from_le_bytes(raw[ibn_off..ibn_off + 2].try_into().unwrap());
                                let name = self.get_string_at_rva(thunk_val + 2, 256);
                                entries.push(ImportSymbol {
                                    name,
                                    ordinal: None,
                                    address: thunk_val as u64,
                                    hint: Some(hint),
                                });
                            }
                        }
                    }
                    thunk_idx += 1;
                }
            }

            imports.push(ImportDirectory {
                dll: dll_name,
                original_first_thunk: orig_first_thunk,
                time_date_stamp,
                forwarder_chain,
                name_rva,
                first_thunk,
                entries,
            });

            desc_off += 20;
        }

        self.imports = imports;
    }

    fn parse_exports(&mut self) {
        if self.optional_header.data_directories.len() <= DIRECTORY_ENTRY_EXPORT {
            return;
        }
        let exp_dir = &self.optional_header.data_directories[DIRECTORY_ENTRY_EXPORT];
        if exp_dir.virtual_address == 0 || exp_dir.size == 0 {
            return;
        }

        let off = match self.get_offset_from_rva(exp_dir.virtual_address) {
            Ok(o) => o,
            Err(_) => return,
        };

        let raw = &self.raw_data;
        if off + 40 > raw.len() {
            return;
        }

        let characteristics = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap());
        let major_version = u16::from_le_bytes(raw[off + 8..off + 10].try_into().unwrap());
        let minor_version = u16::from_le_bytes(raw[off + 10..off + 12].try_into().unwrap());
        let name_rva = u32::from_le_bytes(raw[off + 12..off + 16].try_into().unwrap());
        let base = u32::from_le_bytes(raw[off + 16..off + 20].try_into().unwrap());
        let number_of_functions = u32::from_le_bytes(raw[off + 20..off + 24].try_into().unwrap());
        let number_of_names = u32::from_le_bytes(raw[off + 24..off + 28].try_into().unwrap());
        let address_of_functions = u32::from_le_bytes(raw[off + 28..off + 32].try_into().unwrap());
        let address_of_names = u32::from_le_bytes(raw[off + 32..off + 36].try_into().unwrap());
        let address_of_name_ordinals = u32::from_le_bytes(raw[off + 36..off + 40].try_into().unwrap());

        let name = self.get_string_at_rva(name_rva, 256);
        let mut symbols = Vec::new();

        if let Ok(funcs_off) = self.get_offset_from_rva(address_of_functions) {
            for i in 0..number_of_functions.min(4096) as usize {
                if funcs_off + (i + 1) * 4 <= raw.len() {
                    let addr = u32::from_le_bytes(raw[funcs_off + i * 4..funcs_off + (i + 1) * 4].try_into().unwrap());
                    if addr != 0 {
                        symbols.push(ExportSymbol {
                            name: None,
                            ordinal: (base as u16).wrapping_add(i as u16),
                            address: addr,
                            forwarder: None,
                        });
                    }
                }
            }
        }

        if let (Ok(names_off), Ok(ord_off)) = (self.get_offset_from_rva(address_of_names), self.get_offset_from_rva(address_of_name_ordinals)) {
            for i in 0..number_of_names.min(4096) as usize {
                if names_off + (i + 1) * 4 <= raw.len() && ord_off + (i + 1) * 2 <= raw.len() {
                    let n_rva = u32::from_le_bytes(raw[names_off + i * 4..names_off + (i + 1) * 4].try_into().unwrap());
                    let ord = u16::from_le_bytes(raw[ord_off + i * 2..ord_off + (i + 1) * 2].try_into().unwrap());
                    let sym_name = self.get_string_at_rva(n_rva, 256);

                    if (ord as usize) < symbols.len() {
                        symbols[ord as usize].name = sym_name;
                    }
                }
            }
        }

        self.exports = Some(ExportDirectory {
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            name,
            base,
            number_of_functions,
            number_of_names,
            address_of_functions,
            address_of_names,
            address_of_name_ordinals,
            symbols,
        });
    }

    fn parse_debug(&mut self) {
        if self.optional_header.data_directories.len() <= DIRECTORY_ENTRY_DEBUG {
            return;
        }
        let dbg_dir = &self.optional_header.data_directories[DIRECTORY_ENTRY_DEBUG];
        if dbg_dir.virtual_address == 0 || dbg_dir.size == 0 {
            return;
        }

        let off = match self.get_offset_from_rva(dbg_dir.virtual_address) {
            Ok(o) => o,
            Err(_) => return,
        };

        let raw = &self.raw_data;
        let count = dbg_dir.size as usize / 28;
        let mut entries = Vec::new();

        for i in 0..count.min(32) {
            let e_off = off + i * 28;
            if e_off + 28 <= raw.len() {
                let characteristics = u32::from_le_bytes(raw[e_off..e_off + 4].try_into().unwrap());
                let time_date_stamp = u32::from_le_bytes(raw[e_off + 4..e_off + 8].try_into().unwrap());
                let major_version = u16::from_le_bytes(raw[e_off + 8..e_off + 10].try_into().unwrap());
                let minor_version = u16::from_le_bytes(raw[e_off + 10..e_off + 12].try_into().unwrap());
                let debug_type = u32::from_le_bytes(raw[e_off + 12..e_off + 16].try_into().unwrap());
                let size_of_data = u32::from_le_bytes(raw[e_off + 16..e_off + 20].try_into().unwrap());
                let address_of_raw_data = u32::from_le_bytes(raw[e_off + 20..e_off + 24].try_into().unwrap());
                let pointer_to_raw_data = u32::from_le_bytes(raw[e_off + 24..e_off + 28].try_into().unwrap());

                let mut guid_pdb_path = None;
                if debug_type == 2 && (pointer_to_raw_data as usize) + (size_of_data as usize) <= raw.len() {
                    let p_off = pointer_to_raw_data as usize;
                    if size_of_data >= 24 && &raw[p_off..p_off + 4] == b"RSDS" {
                        let pdb_bytes = &raw[p_off + 24..p_off + size_of_data as usize];
                        guid_pdb_path = String::from_utf8(pdb_bytes.iter().copied().take_while(|&b| b != 0).collect()).ok();
                    }
                }

                entries.push(DebugEntry {
                    characteristics,
                    time_date_stamp,
                    major_version,
                    minor_version,
                    debug_type,
                    size_of_data,
                    address_of_raw_data,
                    pointer_to_raw_data,
                    guid_pdb_path,
                });
            }
        }

        self.debug_entries = entries;
    }

    fn parse_tls(&mut self) {
        if self.optional_header.data_directories.len() <= DIRECTORY_ENTRY_TLS {
            return;
        }
        let tls_dir = &self.optional_header.data_directories[DIRECTORY_ENTRY_TLS];
        if tls_dir.virtual_address == 0 || tls_dir.size == 0 {
            return;
        }

        let off = match self.get_offset_from_rva(tls_dir.virtual_address) {
            Ok(o) => o,
            Err(_) => return,
        };

        let raw = &self.raw_data;
        if self.is_64bit && off + 40 <= raw.len() {
            let start_address_of_raw_data = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
            let end_address_of_raw_data = u64::from_le_bytes(raw[off + 8..off + 16].try_into().unwrap());
            let address_of_index = u64::from_le_bytes(raw[off + 16..off + 24].try_into().unwrap());
            let address_of_callbacks = u64::from_le_bytes(raw[off + 24..off + 32].try_into().unwrap());
            let size_of_zero_fill = u32::from_le_bytes(raw[off + 32..off + 36].try_into().unwrap());
            let characteristics = u32::from_le_bytes(raw[off + 36..off + 40].try_into().unwrap());

            self.tls = Some(TlsDirectory {
                start_address_of_raw_data,
                end_address_of_raw_data,
                address_of_index,
                address_of_callbacks,
                size_of_zero_fill,
                characteristics,
                callbacks: Vec::new(),
            });
        } else if !self.is_64bit && off + 24 <= raw.len() {
            let start_address_of_raw_data = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap()) as u64;
            let end_address_of_raw_data = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap()) as u64;
            let address_of_index = u32::from_le_bytes(raw[off + 8..off + 12].try_into().unwrap()) as u64;
            let address_of_callbacks = u32::from_le_bytes(raw[off + 12..off + 16].try_into().unwrap()) as u64;
            let size_of_zero_fill = u32::from_le_bytes(raw[off + 16..off + 20].try_into().unwrap());
            let characteristics = u32::from_le_bytes(raw[off + 20..off + 24].try_into().unwrap());

            self.tls = Some(TlsDirectory {
                start_address_of_raw_data,
                end_address_of_raw_data,
                address_of_index,
                address_of_callbacks,
                size_of_zero_fill,
                characteristics,
                callbacks: Vec::new(),
            });
        }
    }
}
