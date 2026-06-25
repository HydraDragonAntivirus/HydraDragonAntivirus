use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::Instant;

use goblin::pe::PE;
use goblin::Object;
use unicorn_engine::unicorn_const::{
    uc_error, Arch, HookType as UcHookType, MemType, Mode, Prot, SECOND_SCALE,
};
use unicorn_engine::{RegisterX86, UcHookId, Unicorn};

use crate::unpacker::error::{UnpackerError, UnpackerResult};
use crate::unpacker::kernel_structs::{Peb, PebLdrData, Teb};
use crate::unpacker::packers::{self, UnpackerConfig};
use vmpunpacker;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PAGE_SIZE: u64 = 0x1000;
const STACK_ADDR: u64 = 0x0;
const STACK_SIZE: u64 = 1024 * 1024;
const TEB_ADDR: u64 = 0x200000;
const PEB_ADDR: u64 = 0x201000;
const LDR_ADDR: u64 = 0x202000;
const HOOK_ADDR: u64 = 0x7F000000;
const LDR_ENTRY_SIZE: u64 = 0x60;

// ---------------------------------------------------------------------------
// PE header structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

#[derive(Debug, Clone)]
pub struct PeHeader {
    pub signature: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub magic: u16,
    pub address_of_entry_point: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub data_directory: Vec<DataDirectory>,
}

#[derive(Debug, Clone)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub first_thunk: u32,
    pub dll_name: String,
    pub imports: Vec<String>,
}

// ---------------------------------------------------------------------------
// Sample
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Sample {
    pub path: String,
    pub yara_path: String,
    pub imports: Vec<String>,
    pub dllname_to_functionlist: HashMap<String, Vec<(String, u64)>>,
    pub original_imports: Vec<ImportDescriptor>,
    pub atn: HashMap<(u64, u64), String>,
    pub ntp: HashMap<String, (bool, bool, bool)>,
    pub allocated_chunks: Vec<(u64, u64)>,
    pub base_addr: u64,
    pub virtualmemorysize: u64,
    /// Raw PE bytes (possibly VMProtect-unpacked). Used by `init_uc` and
    /// `patch_imports` instead of re-reading from disk.
    pub raw_bytes: Vec<u8>,
    pub loaded_image: Vec<u8>,
    pub sections: Vec<Section>,
    pub unpacker: UnpackerConfig,
    pub yara_matches: Vec<String>,
    pub dos_header: DosHeader,
    pub pe_header: PeHeader,
    pub opt_header: OptionalHeader,
}

impl Sample {
    pub fn new(path: &str, yara_path: &str) -> UnpackerResult<Self> {
        let raw = std::fs::read(path)?;

        // Detect and statically unpack VMProtect sections in memory.
        let raw_bytes = if !raw.is_empty() && vmpunpacker::detect(&raw) {
            log::info!("VMProtect detected in {}, unpacking in memory…", path);
            let unpacked = vmpunpacker::unpack(&raw)
                .map_err(|e| UnpackerError::General(format!("VMProtect LZMA unpack failed: {e}")))?;
            log::info!("VMProtect unpacked: {} -> {} bytes", path, unpacked.len());
            unpacked
        } else {
            raw
        };

        let (dos_header, pe_header, opt_header, sections) = parse_pe_bytes(&raw_bytes)?;

        let base_addr = opt_header.image_base as u64;
        let virtualmemorysize = get_virtual_memory_size(&sections);
        let ep = entrypoint(&opt_header);

        let sec_headers: Vec<crate::filetype::pe_file::SectionHeader> = sections
            .iter()
            .map(|s| crate::filetype::pe_file::SectionHeader {
                name: s.name.clone(),
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_offset: s.pointer_to_raw_data,
                raw_size: s.size_of_raw_data,
                characteristics: s.characteristics,
            })
            .collect();

        let unpacker = packers::create_default_unpacker(&sec_headers, base_addr, ep);

        Ok(Self {
            path: path.to_string(),
            yara_path: yara_path.to_string(),
            imports: Vec::new(),
            dllname_to_functionlist: HashMap::new(),
            original_imports: Vec::new(),
            atn: HashMap::new(),
            ntp: HashMap::new(),
            allocated_chunks: Vec::new(),
            base_addr,
            virtualmemorysize,
            raw_bytes,
            loaded_image: Vec::new(),
            sections,
            unpacker,
            yara_matches: Vec::new(),
            dos_header,
            pe_header,
            opt_header,
        })
    }
}

// ---------------------------------------------------------------------------
// Hook state shared with Unicorn callbacks
// ---------------------------------------------------------------------------

struct HookState {
    breakpoints: Vec<u64>,
    mem_breakpoints: Vec<(u64, u64)>,
    sections_read: HashMap<String, u64>,
    sections_written: HashMap<String, u64>,
    sections_executed: HashMap<String, u64>,
    write_targets: Vec<(u64, u64)>,
    apicall_counter: HashMap<String, u64>,
    hook_addr: u64,
    start_time: Instant,
    sample_sections: Vec<Section>,
    unpacker: UnpackerConfig,
    log_instr: bool,
    log_mem_read: bool,
    log_mem_write: bool,
    log_apicalls: bool,
}

// ---------------------------------------------------------------------------
// UnpackerEngine
// ---------------------------------------------------------------------------

pub struct UnpackerEngine {
    pub sample: Sample,
    pub unpack_path: String,
    pub breakpoints: Vec<u64>,
    pub mem_breakpoints: Vec<(u64, u64)>,
    pub sections_read: HashMap<String, u64>,
    pub sections_written: HashMap<String, u64>,
    pub sections_executed: HashMap<String, u64>,
    pub write_targets: Vec<(u64, u64)>,
    pub apicall_counter: HashMap<String, u64>,
    pub hook_addr: u64,
    pub stack_addr: u64,
    pub stack_size: u64,
    pub peb_base: u64,
    pub teb_base: u64,
    pub start_time: Instant,
    pub log_instr: bool,
    pub log_mem_read: bool,
    pub log_mem_write: bool,
    pub log_apicalls: bool,

    uc: Option<Unicorn<'static, ()>>,
    hook_ids: Vec<UcHookId>,
    hook_state: Rc<RefCell<HookState>>,
}

impl UnpackerEngine {
    pub fn new(sample: Sample, unpack_path: &str) -> Self {
        let peb_base = PEB_ADDR;
        let teb_base = TEB_ADDR;
        let sections = sample.sections.clone();
        let unpacker = sample.unpacker.clone();

        Self {
            sample,
            unpack_path: unpack_path.to_string(),
            breakpoints: Vec::new(),
            mem_breakpoints: Vec::new(),
            sections_read: HashMap::new(),
            sections_written: HashMap::new(),
            sections_executed: HashMap::new(),
            write_targets: Vec::new(),
            apicall_counter: HashMap::new(),
            hook_addr: HOOK_ADDR,
            stack_addr: STACK_ADDR,
            stack_size: STACK_SIZE,
            peb_base,
            teb_base,
            start_time: Instant::now(),
            log_instr: false,
            log_mem_read: false,
            log_mem_write: false,
            log_apicalls: false,
            uc: None,
            hook_ids: Vec::new(),
            hook_state: Rc::new(RefCell::new(HookState {
                breakpoints: Vec::new(),
                mem_breakpoints: Vec::new(),
                sections_read: HashMap::new(),
                sections_written: HashMap::new(),
                sections_executed: HashMap::new(),
                write_targets: Vec::new(),
                apicall_counter: HashMap::new(),
                hook_addr: HOOK_ADDR,
                start_time: Instant::now(),
                sample_sections: sections,
                unpacker,
                log_instr: false,
                log_mem_read: false,
                log_mem_write: false,
                log_apicalls: false,
            })),
        }
    }

    // ------------------------------------------------------------------
    // init_uc — set up Unicorn, map PE, load DLLs, hook imports
    // ------------------------------------------------------------------

    pub fn init_uc(&mut self) -> UnpackerResult<()> {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32)
            .map_err(|e| UnpackerError::EmulatorError(format!("uc_open: {:?}", e)))?;

        let pe_data = self.sample.raw_bytes.clone();
        let pe = match goblin::Object::parse(&pe_data) {
            Ok(Object::PE(pe)) => {
                if pe.is_64 {
                    return Err(UnpackerError::InvalidPeFile("64-bit not supported".into()));
                }
                pe
            }
            Ok(_) => {
                return Err(UnpackerError::InvalidPeFile("Not a PE file".into()));
            }
            Err(e) => {
                return Err(UnpackerError::InvalidPeFile(e.to_string()));
            }
        };

        let image_base = self.sample.base_addr;
        let virtual_size = page_align(self.sample.virtualmemorysize);

        // --- Map PE image ---
        uc.mem_map(image_base, virtual_size, Prot::ALL)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map PE: {:?}", e)))?;

        let mmap_image = get_memory_mapped_image(&pe_data, &pe, virtual_size);
        uc.mem_write(image_base, &mmap_image)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_write PE: {:?}", e)))?;

        self.sample.loaded_image = mmap_image;

        // --- Map TEB ---
        let teb_size = page_align(0x1000);
        uc.mem_map(TEB_ADDR, teb_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map TEB: {:?}", e)))?;

        let teb = Teb::new(
            (STACK_ADDR + STACK_SIZE) as u32,
            STACK_ADDR as u32,
            TEB_ADDR as u32,
            0x1000,
            0x1001,
            PEB_ADDR as u32,
        );
        uc.mem_write(TEB_ADDR, &teb.to_bytes())
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_write TEB: {:?}", e)))?;

        // --- Map PEB ---
        let peb_size = page_align(0x1000);
        uc.mem_map(PEB_ADDR, peb_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map PEB: {:?}", e)))?;

        let peb = Peb::new(image_base as u32, LDR_ADDR as u32);
        uc.mem_write(PEB_ADDR, &peb.to_bytes())
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_write PEB: {:?}", e)))?;

        // --- Map LDR ---
        let ldr_size = page_align(0x2000);
        uc.mem_map(LDR_ADDR, ldr_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map LDR: {:?}", e)))?;

        let peb_ldr = PebLdrData::new((LDR_ADDR + 0x30) as u32);
        uc.mem_write(LDR_ADDR, &peb_ldr.to_bytes())
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR: {:?}", e)))?;

        // --- Map stack at 0x0 ---
        let stack_size = page_align(STACK_SIZE);
        uc.mem_map(STACK_ADDR, stack_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map stack: {:?}", e)))?;

        // --- Map hook memory ---
        let hook_mem_size = page_align(0x100000);
        uc.mem_map(HOOK_ADDR, hook_mem_size, Prot::ALL)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map hook: {:?}", e)))?;

        // --- Load system DLLs ---
        let dll_dir = {
            let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
            crate_root.join("DLLs")
        };

        let dll_names = ["kernel32.dll", "ntdll.dll", "KernelBase.dll"];
        let mut dll_bases: Vec<(String, u64, u32)> = Vec::new();

        for dll_name in &dll_names {
            let dll_path = dll_dir.join(dll_name);
            if dll_path.exists() {
                match load_dll_into_emu(&mut uc, dll_path.to_str().unwrap()) {
                    Ok((base, size)) => {
                        dll_bases.push((dll_name.to_string(), base, size as u32));
                    }
                    Err(e) => {
                        log::warn!("Failed to load {}: {}", dll_name, e);
                    }
                }
            } else {
                log::warn!("DLL not found: {:?}", dll_path);
            }
        }

        // --- Set up LDR entries for loaded DLLs ---
        let ldr_entries_base = LDR_ADDR + 0x30;
        setup_ldr_entries(&mut uc, ldr_entries_base, &dll_bases)?;

        // --- Initialize registers ---
        let esp_val = STACK_ADDR + STACK_SIZE / 2;
        uc.reg_write(RegisterX86::ESP as i32, esp_val)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write ESP: {:?}", e)))?;
        uc.reg_write(RegisterX86::EBP as i32, esp_val)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write EBP: {:?}", e)))?;

        let start_addr = entrypoint(&self.sample.opt_header);
        uc.reg_write(RegisterX86::EAX as i32, start_addr)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write EAX: {:?}", e)))?;
        uc.reg_write(RegisterX86::EBX as i32, start_addr)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write EBX: {:?}", e)))?;
        uc.reg_write(RegisterX86::ECX as i32, start_addr)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write ECX: {:?}", e)))?;
        uc.reg_write(RegisterX86::EDX as i32, start_addr)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write EDX: {:?}", e)))?;
        uc.reg_write(RegisterX86::ESI as i32, start_addr)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write ESI: {:?}", e)))?;
        uc.reg_write(RegisterX86::EDI as i32, start_addr)
            .map_err(|e| UnpackerError::EmulatorError(format!("reg_write EDI: {:?}", e)))?;

        // --- Store imported function info ---
        self.store_imports(&pe);

        // --- Patch IAT with hook addresses ---
        self.patch_imports(&mut uc, image_base)?;

        // --- Register hooks ---
        let hook_state = Rc::clone(&self.hook_state);
        let hook_state2 = Rc::clone(&self.hook_state);
        // Code hook
        let code_hook = uc
            .add_code_hook(0, u64::MAX, move |uc, addr, _size| {
                let state = hook_state.borrow();
                // Check breakpoints
                if state.breakpoints.contains(&addr) {
                    let _ = uc.emu_stop();
                    return;
                }

                // Check end address
                let end_addr = state.unpacker.endaddr;
                if addr >= end_addr {
                    let _ = uc.emu_stop();
                    return;
                }

                // Drop state before potentially recursive calls
                drop(state);

                // Store the hook addresses we need to check
                let hook_addr_val: u64;
                let do_section_hopping: bool;
                let do_write_execute: bool;
                let allowed_sections: Vec<String>;
                let allowed_ranges: Vec<(u64, u64)>;
                let secs: Vec<Section>;
                let apicall_counter: HashMap<String, u64>;

                {
                    let s = hook_state.borrow();
                    hook_addr_val = s.hook_addr;
                    do_section_hopping = s.unpacker.section_hopping_control;
                    do_write_execute = s.unpacker.write_execute_control;
                    allowed_sections = s.unpacker.allowed_sections.clone();
                    allowed_ranges = s.unpacker.allowed_addr_ranges.clone();
                    secs = s.sample_sections.clone();
                    apicall_counter = s.apicall_counter.clone();
                }

                // Detect API calls via hook address
                if addr >= hook_addr_val && addr < hook_addr_val + 0x100000 {
                    if let Some(api_name) = resolve_hook_name(&apicall_counter, addr) {
                        log::info!("API call: {}", api_name);
                    }
                    let _ = uc.emu_stop();
                    return;
                }

                // Track section execution
                let sec_name = get_section_name(&secs, addr);
                if !sec_name.is_empty() {
                    let mut s = hook_state.borrow_mut();
                    *s.sections_executed.entry(sec_name.clone()).or_insert(0) += 1;
                }

                // Write-execute detection
                if do_write_execute {
                    let s = hook_state.borrow();
                    for &(w_start, w_end) in &s.write_targets {
                        if addr >= w_start && addr < w_end {
                            log::warn!(
                                "Write-execute at {:#x} in range {:#x}-{:#x}",
                                addr,
                                w_start,
                                w_end
                            );
                            drop(s);
                            let _ = uc.emu_stop();
                            return;
                        }
                    }
                }

                // Section hopping detection
                if do_section_hopping {
                    let in_allowed_section = allowed_sections.iter().any(|name| {
                        get_section_name(&secs, addr) == *name
                    });
                    let in_allowed_range = allowed_ranges
                        .iter()
                        .any(|&(lo, hi)| addr >= lo && addr < hi);

                    if !in_allowed_section && !in_allowed_range {
                        log::warn!(
                            "Section hopping detected at {:#x}, stopping",
                            addr
                        );
                        let _ = uc.emu_stop();
                        return;
                    }
                }
            })
            .map_err(|e| UnpackerError::EmulatorError(format!("add_code_hook: {:?}", e)))?;

        self.hook_ids.push(code_hook);

        // Memory access hook (read / write tracking)
        let mem_access_hook = uc
            .add_mem_hook(
                UcHookType::MEM_READ | UcHookType::MEM_WRITE,
                0,
                u64::MAX,
                move |_uc, mem_type, addr, size, _value| {
                    let sec_name = get_section_name_from_state(&hook_state2, addr);
                    if sec_name.is_empty() {
                        return true;
                    }

                    let mut state = hook_state2.borrow_mut();
                    match mem_type {
                        MemType::READ => {
                            *state.sections_read.entry(sec_name).or_insert(0) += size as u64;
                        }
                        MemType::WRITE => {
                            *state.sections_written.entry(sec_name).or_insert(0) += size as u64;
                            state.write_targets.push((addr, addr + size as u64));
                        }
                        _ => {}
                    }

                    // Check memory breakpoints
                    for &(bp_start, bp_end) in &state.mem_breakpoints {
                        if addr >= bp_start && addr < bp_end {
                            return false; // stop emulation
                        }
                    }

                    true
                },
            )
            .map_err(|e| UnpackerError::EmulatorError(format!("add_mem_access_hook: {:?}", e)))?;

        self.hook_ids.push(mem_access_hook);

        // Invalid memory hook
        let invalid_mem_hook = uc
            .add_mem_hook(
                UcHookType::MEM_READ_UNMAPPED
                    | UcHookType::MEM_WRITE_UNMAPPED
                    | UcHookType::MEM_FETCH_UNMAPPED,
                0,
                u64::MAX,
                move |_uc, _mem_type, addr, _size, _value| {
                    log::error!("Invalid memory access at {:#x}", addr);
                    false
                },
            )
            .map_err(|e| UnpackerError::EmulatorError(format!("add_mem_invalid_hook: {:?}", e)))?;

        self.hook_ids.push(invalid_mem_hook);

        self.uc = Some(uc);
        Ok(())
    }

    // ------------------------------------------------------------------
    // emu — start the emulator
    // ------------------------------------------------------------------

    pub fn emu(&mut self) -> UnpackerResult<()> {
        let uc = self
            .uc
            .as_mut()
            .ok_or_else(|| UnpackerError::EmulatorError("engine not initialized".into()))?;

        let ep = entrypoint(&self.sample.opt_header);
        let end_addr = self.sample.base_addr + self.sample.virtualmemorysize;

        // Sync hook state from engine fields
        {
            let mut hs = self.hook_state.borrow_mut();
            hs.breakpoints = self.breakpoints.clone();
            hs.mem_breakpoints = self.mem_breakpoints.clone();
            hs.log_instr = self.log_instr;
            hs.log_mem_read = self.log_mem_read;
            hs.log_mem_write = self.log_mem_write;
            hs.log_apicalls = self.log_apicalls;
            hs.start_time = self.start_time;
        }

        let result = uc.emu_start(ep, end_addr, 30 * SECOND_SCALE, 0);

        // Sync back results
        {
            let hs = self.hook_state.borrow();
            self.sections_read = hs.sections_read.clone();
            self.sections_written = hs.sections_written.clone();
            self.sections_executed = hs.sections_executed.clone();
            self.write_targets = hs.write_targets.clone();
            self.apicall_counter = hs.apicall_counter.clone();
        }

        match result {
            Ok(_) => Ok(()),
            Err(uc_error::OK) => Ok(()),
            Err(e) => Err(UnpackerError::EmulatorError(format!("emu_start: {:?}", e))),
        }
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn store_imports(&mut self, pe: &PE<'_>) {
        let mut dllname_to_functionlist: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        let mut all_imports: Vec<String> = Vec::new();
        let mut import_descriptors: HashMap<String, ImportDescriptor> = HashMap::new();
        let mut hook_addr = self.hook_addr;

        // goblin 0.10 provides a flat list of imports, each with .dll and .name
        for imp in &pe.imports {
            let dll_name = imp.dll.to_lowercase();
            let func_name = imp.name.to_string();
            let name_lower = func_name.to_lowercase();

            dllname_to_functionlist
                .entry(dll_name.clone())
                .or_default()
                .push((name_lower.clone(), hook_addr));

            import_descriptors
                .entry(dll_name.clone())
                .or_insert_with(|| ImportDescriptor {
                    characteristics: 0,
                    time_date_stamp: 0,
                    forwarder_chain: 0,
                    name_rva: 0,
                    first_thunk: 0,
                    dll_name: dll_name.clone(),
                    imports: Vec::new(),
                })
                .imports
                .push(name_lower.clone());

            all_imports.push(format!("{}.{}", dll_name, func_name));
            hook_addr += 4;
        }

        self.sample.imports = all_imports;
        self.sample.dllname_to_functionlist = dllname_to_functionlist;
        self.sample.original_imports = import_descriptors.into_values().collect();
        self.hook_addr = hook_addr;
    }

    fn patch_imports(&mut self, uc: &mut Unicorn<'static, ()>, image_base: u64) -> UnpackerResult<()> {
        let pe = match goblin::Object::parse(&self.sample.raw_bytes) {
            Ok(Object::PE(pe)) => pe,
            _ => return Ok(()),
        };

        let mut hook_addr = self.hook_addr;

        // In goblin 0.10, each Import has an .offset field which is the file
        // offset of the IAT entry. The thunk RVA can be derived by finding
        // which section contains that file offset.
        for imp in &pe.imports {
            let thunk_rva = offset_to_rva(&pe, imp.offset);
            let thunk_addr = image_base + thunk_rva as u64;
            let hook_bytes = (hook_addr as u32).to_le_bytes();
            let _ = uc.mem_write(thunk_addr, &hook_bytes);
            hook_addr += 4;
        }

        self.hook_addr = hook_addr;
        Ok(())
    }

    /// Dump the emulated PE image to a file.
    pub fn dump(&self, file_path: &str) -> UnpackerResult<()> {
        let uc = self
            .uc
            .as_ref()
            .ok_or_else(|| UnpackerError::EmulatorError("engine not initialized".into()))?;
        let ctx = crate::unpacker::imagedump::DumpContext {
            virtualmemorysize: self.sample.virtualmemorysize,
            hook_addr: self.hook_addr,
            ntp: HashMap::new(),
            dllname_to_functionlist: self.sample.dllname_to_functionlist.clone(),
            allocated_chunks: self.sample.allocated_chunks.clone(),
            original_imports: self.sample.original_imports.iter().map(|id| {
                crate::unpacker::imagedump::ImportDescriptor {
                    characteristics: id.characteristics,
                    time_date_stamp: id.time_date_stamp,
                    forwarder_chain: id.forwarder_chain,
                    name: id.name_rva,
                    first_thunk: id.first_thunk,
                    dll_name: id.dll_name.clone(),
                    imports: id.imports.clone(),
                }
            }).collect(),
            sections: self.sample.sections.iter().map(|s| {
                crate::unpacker::imagedump::Section {
                    name: s.name.clone(),
                    virtual_size: s.virtual_size,
                    virtual_address: s.virtual_address,
                    size_of_raw_data: s.size_of_raw_data,
                    pointer_to_raw_data: s.pointer_to_raw_data,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: s.characteristics,
                }
            }).collect(),
        };
        crate::unpacker::imagedump::dump_image(uc, self.sample.base_addr, self.sample.virtualmemorysize, &ctx, file_path)
    }

    /// Dump the emulated PE image to a byte vector (no file I/O).
    pub fn dump_bytes(&self) -> UnpackerResult<Vec<u8>> {
        let uc = self
            .uc
            .as_ref()
            .ok_or_else(|| UnpackerError::EmulatorError("engine not initialized".into()))?;
        let ctx = crate::unpacker::imagedump::DumpContext {
            virtualmemorysize: self.sample.virtualmemorysize,
            hook_addr: self.hook_addr,
            ntp: HashMap::new(),
            dllname_to_functionlist: self.sample.dllname_to_functionlist.clone(),
            allocated_chunks: self.sample.allocated_chunks.clone(),
            original_imports: self.sample.original_imports.iter().map(|id| {
                crate::unpacker::imagedump::ImportDescriptor {
                    characteristics: id.characteristics,
                    time_date_stamp: id.time_date_stamp,
                    forwarder_chain: id.forwarder_chain,
                    name: id.name_rva,
                    first_thunk: id.first_thunk,
                    dll_name: id.dll_name.clone(),
                    imports: id.imports.clone(),
                }
            }).collect(),
            sections: self.sample.sections.iter().map(|s| {
                crate::unpacker::imagedump::Section {
                    name: s.name.clone(),
                    virtual_size: s.virtual_size,
                    virtual_address: s.virtual_address,
                    size_of_raw_data: s.size_of_raw_data,
                    pointer_to_raw_data: s.pointer_to_raw_data,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: s.characteristics,
                }
            }).collect(),
        };
        crate::unpacker::imagedump::dump_image_to_bytes(uc, self.sample.base_addr, self.sample.virtualmemorysize, &ctx)
    }
}

impl Drop for UnpackerEngine {
    fn drop(&mut self) {
        // Hooks are removed when Unicorn is dropped
    }
}

// ---------------------------------------------------------------------------
// PE header parsing from disk
// ---------------------------------------------------------------------------

pub fn read_pe_headers_from_disk(
    path: &str,
) -> UnpackerResult<(DosHeader, PeHeader, OptionalHeader, Vec<Section>)> {
    let data = std::fs::read(path)?;
    parse_pe_bytes(&data)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

pub fn page_align(value: u64) -> u64 {
    (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub fn align(value: u64, page_size: u64) -> u64 {
    (value + page_size - 1) & !(page_size - 1)
}

pub fn entrypoint(opt_header: &OptionalHeader) -> u64 {
    opt_header.image_base as u64 + opt_header.address_of_entry_point as u64
}

pub fn get_virtual_memory_size(sections: &[Section]) -> u64 {
    let mut max_end = 0u64;
    for s in sections {
        let end = s.virtual_address as u64 + s.virtual_size as u64;
        if end > max_end {
            max_end = end;
        }
    }
    page_align(max_end)
}

pub fn merge_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut sorted: Vec<(u64, u64)> = ranges.to_vec();
    sorted.sort_by_key(|&(start, _)| start);

    let mut merged: Vec<(u64, u64)> = Vec::new();
    merged.push(sorted[0]);

    for &(start, end) in &sorted[1..] {
        let last = merged.last_mut().unwrap();
        if start <= last.1 {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }

    merged
}

pub fn read_cstring(uc: &Unicorn<'_, ()>, addr: u64) -> String {
    let mut buf = Vec::new();
    let mut offset = 0u64;

    loop {
        match uc.mem_read_as_vec(addr + offset, 1) {
            Ok(bytes) => {
                if bytes.is_empty() || bytes[0] == 0 {
                    break;
                }
                buf.push(bytes[0]);
                offset += 1;
            }
            Err(_) => break,
        }

        if offset > 4096 {
            break;
        }
    }

    String::from_utf8_lossy(&buf).to_string()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn get_memory_mapped_image(data: &[u8], pe: &PE<'_>, virtual_size: u64) -> Vec<u8> {
    let mut image = vec![0u8; virtual_size as usize];
    for section in &pe.sections {
        let dest_start = section.virtual_address as usize;
        let src_start = section.pointer_to_raw_data as usize;
        let copy_size = section.size_of_raw_data.min(section.virtual_size) as usize;
        if src_start + copy_size <= data.len() && dest_start + copy_size <= image.len() {
            image[dest_start..dest_start + copy_size]
                .copy_from_slice(&data[src_start..src_start + copy_size]);
        }
    }
    image
}

fn load_dll_into_emu(
    uc: &mut Unicorn<'static, ()>,
    dll_path: &str,
) -> UnpackerResult<(u64, u64)> {
    let data = std::fs::read(dll_path)?;
    let pe = match goblin::Object::parse(&data) {
        Ok(Object::PE(pe)) => pe,
        Ok(_) => return Err(UnpackerError::InvalidPeFile("Not a PE file".into())),
        Err(e) => return Err(UnpackerError::InvalidPeFile(e.to_string())),
    };

    let image_base = pe.image_base;
    let virtual_size = {
        let mut max_end = 0u64;
        for s in &pe.sections {
            let end = s.virtual_address as u64 + s.virtual_size as u64;
            if end > max_end {
                max_end = end;
            }
        }
        page_align(max_end)
    };

    let mmap = get_memory_mapped_image(&data, &pe, virtual_size);

    uc.mem_map(image_base, virtual_size, Prot::ALL)
        .map_err(|e| UnpackerError::EmulatorError(format!("mem_map DLL: {:?}", e)))?;

    uc.mem_write(image_base, &mmap)
        .map_err(|e| UnpackerError::EmulatorError(format!("mem_write DLL: {:?}", e)))?;

    Ok((image_base, virtual_size))
}

fn setup_ldr_entries(
    uc: &mut Unicorn<'static, ()>,
    base: u64,
    dlls: &[(String, u64, u32)],
) -> UnpackerResult<()> {
    let mut prev_entry = base;

    for (i, (name, dll_base, size)) in dlls.iter().enumerate() {
        let entry_addr = base + (i as u64) * LDR_ENTRY_SIZE;
        let next_addr = base + ((i + 1) as u64) * LDR_ENTRY_SIZE;
        let prev_link = if i == 0 {
            entry_addr + LDR_ENTRY_SIZE * (dlls.len() as u64)
        } else {
            prev_entry
        };

        // Build minimal LDR_DATA_TABLE_ENTRY (32-bit):
        // +0x00: InLoadOrderLinks (LIST_ENTRY: Flink, Blink)
        // +0x08: InMemoryOrderLinks (LIST_ENTRY)
        // +0x10: InInitializationOrderLinks (LIST_ENTRY)
        // +0x18: DllBase
        // +0x1C: EntryPoint
        // +0x20: SizeOfImage
        // +0x24: FullDllName (UNICODE_STRING: Length, MaxLength, Buffer)
        // +0x2C: BaseDllName (UNICODE_STRING)
        // +0x34: Flags
        let mut entry = vec![0u8; LDR_ENTRY_SIZE as usize];

        // InLoadOrderLinks
        let flink = if i + 1 < dlls.len() {
            next_addr as u32
        } else {
            base as u32 // loop back to LDR
        };
        let blink = if i > 0 {
            prev_link as u32
        } else {
            base as u32
        };
        entry[0..4].copy_from_slice(&flink.to_le_bytes());
        entry[4..8].copy_from_slice(&blink.to_le_bytes());

        // InMemoryOrderLinks
        entry[8..12].copy_from_slice(&flink.to_le_bytes());
        entry[12..16].copy_from_slice(&blink.to_le_bytes());

        // InInitializationOrderLinks
        entry[16..20].copy_from_slice(&flink.to_le_bytes());
        entry[20..24].copy_from_slice(&blink.to_le_bytes());

        // DllBase
        entry[24..28].copy_from_slice(&(*dll_base as u32).to_le_bytes());

        // EntryPoint (0 = no entry point needed for emulation)
        entry[28..32].copy_from_slice(&0u32.to_le_bytes());

        // SizeOfImage
        entry[32..36].copy_from_slice(&size.to_le_bytes());

        // FullDllName (UNICODE_STRING: just store Length next to entry)
        let name_len = (name.len() * 2) as u16;
        entry[36..38].copy_from_slice(&name_len.to_le_bytes()); // Length
        entry[38..40].copy_from_slice(&name_len.to_le_bytes()); // MaxLength
        entry[40..44].copy_from_slice(&0u32.to_le_bytes()); // Buffer (null for simplicity)

        // BaseDllName
        entry[44..46].copy_from_slice(&name_len.to_le_bytes());
        entry[46..48].copy_from_slice(&name_len.to_le_bytes());
        entry[48..52].copy_from_slice(&0u32.to_le_bytes());

        // Flags: 0x1000 (LDRP_ENTRY_PROCESSED)
        entry[52..56].copy_from_slice(&0x1000u32.to_le_bytes());

        uc.mem_write(entry_addr, &entry)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR entry: {:?}", e)))?;

        prev_entry = entry_addr;
    }

    Ok(())
}

fn get_section_name(sections: &[Section], addr: u64) -> String {
    for s in sections {
        let sec_end =
            s.virtual_address as u64 + s.virtual_size.max(s.size_of_raw_data) as u64;
        if addr >= s.virtual_address as u64 && addr < sec_end {
            return s.name.clone();
        }
    }
    String::new()
}

fn get_section_name_from_state(hook_state: &Rc<RefCell<HookState>>, addr: u64) -> String {
    let state = hook_state.borrow();
    for s in &state.sample_sections {
        let sec_end =
            s.virtual_address as u64 + s.virtual_size.max(s.size_of_raw_data) as u64;
        if addr >= s.virtual_address as u64 && addr < sec_end {
            return s.name.clone();
        }
    }
    String::new()
}

fn resolve_hook_name(
    apicall_counter: &HashMap<String, u64>,
    addr: u64,
) -> Option<String> {
    // This will be populated by WinApiCalls in the future.
    // For now, return None to indicate unknown hook address.
    let _ = (apicall_counter, addr);
    None
}

fn offset_to_rva(pe: &PE<'_>, file_offset: usize) -> u32 {
    for section in &pe.sections {
        let raw_start = section.pointer_to_raw_data as usize;
        let raw_end = raw_start + section.size_of_raw_data as usize;
        if file_offset >= raw_start && file_offset < raw_end {
            return section.virtual_address + (file_offset - raw_start) as u32;
        }
    }
    0
}

/// Parse PE headers from an in-memory byte slice (no disk I/O).
pub fn parse_pe_bytes(
    data: &[u8],
) -> UnpackerResult<(DosHeader, PeHeader, OptionalHeader, Vec<Section>)> {
    let pe = match goblin::Object::parse(data) {
        Ok(Object::PE(pe)) => {
            if pe.is_64 {
                return Err(UnpackerError::InvalidPeFile("64-bit not supported".into()));
            }
            pe
        }
        Ok(_) => return Err(UnpackerError::InvalidPeFile("Not a PE file".into())),
        Err(e) => return Err(UnpackerError::InvalidPeFile(e.to_string())),
    };

    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4]));
    let e_magic = u16::from_le_bytes(data[0..2].try_into().unwrap_or([0; 2]));

    let dos_header = DosHeader { e_magic, e_lfanew };

    let pe_header = PeHeader {
        signature: pe.header.coff_header.machine as u32,
        machine: pe.header.coff_header.machine,
        number_of_sections: pe.header.coff_header.number_of_sections,
        characteristics: pe.header.coff_header.characteristics,
    };

    let opt = pe
        .header
        .optional_header
        .as_ref()
        .ok_or_else(|| UnpackerError::InvalidPeFile("missing optional header".into()))?;

    let opt_header = OptionalHeader {
        magic: opt.standard_fields.magic,
        address_of_entry_point: opt.standard_fields.address_of_entry_point,
        image_base: pe.image_base as u32,
        section_alignment: opt.windows_fields.section_alignment,
        file_alignment: opt.windows_fields.file_alignment,
        size_of_image: opt.windows_fields.size_of_image,
        size_of_headers: opt.windows_fields.size_of_headers,
        check_sum: opt.windows_fields.check_sum,
        subsystem: opt.windows_fields.subsystem,
        dll_characteristics: opt.windows_fields.dll_characteristics,
        data_directory: opt
            .data_directories
            .data_directories
            .iter()
            .filter_map(|entry| entry.as_ref().map(|(_, dd)| DataDirectory {
                virtual_address: dd.virtual_address,
                size: dd.size,
            }))
            .collect(),
    };

    let sections: Vec<Section> = pe
        .sections
        .iter()
        .map(|s| Section {
            name: String::from_utf8_lossy(&s.name)
                .trim_end_matches('\0')
                .to_string(),
            virtual_size: s.virtual_size,
            virtual_address: s.virtual_address,
            size_of_raw_data: s.size_of_raw_data,
            pointer_to_raw_data: s.pointer_to_raw_data,
            characteristics: s.characteristics,
        })
        .collect();

    Ok((dos_header, pe_header, opt_header, sections))
}
