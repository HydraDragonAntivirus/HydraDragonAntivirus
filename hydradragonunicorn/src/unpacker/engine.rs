use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::Instant;

use unicorn_engine::unicorn_const::{
    uc_error, Arch, HookType as UcHookType, MemType, Mode, Prot, SECOND_SCALE,
};
use unicorn_engine::{RegisterARM, RegisterARM64, RegisterX86, UcHookId, Unicorn, X86Insn};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

use crate::unpacker::apicalls::{self, ApiState};
use crate::unpacker::error::{UnpackerError, UnpackerResult};
use crate::unpacker::kernel_structs::{Peb, Peb64, PebLdrData, PebLdrData64, Teb, Teb64};
use crate::unpacker::packers::{self, UnpackerConfig};
use hydradragonsig::models::{ApiCall, BehaviorTrace};
use vmpunpacker;

// ---------------------------------------------------------------------------
// Architecture enumeration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArch {
    X86,
    X64,
    Arm32,
    Arm64,
}

impl PeArch {
    pub fn from_pe(machine: u16, magic: u16) -> Self {
        match machine {
            0xaa64 | 0xa641 | 0xa64e => PeArch::Arm64,
            0x1c0 | 0x1c2 | 0x1c4 => PeArch::Arm32,
            0x8664 => PeArch::X64,
            0x14c => PeArch::X86,
            _ => {
                if magic == 0x20b {
                    PeArch::X64
                } else {
                    PeArch::X86
                }
            }
        }
    }

    pub fn is_64(&self) -> bool {
        matches!(self, PeArch::X64 | PeArch::Arm64)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PAGE_SIZE: u64 = 0x1000;
// Keep the low 64 KiB unmapped, as on Windows. Besides matching the process
// address space this is required for null dereferences to raise an exception.
// The stack fills the space up to the TEB (~1.8 MB): with 512 KB below the start,
// stubs that probe a large frame (`sub esp, n` / __chkstk) or recurse ran off its
// bottom (16 of the faults in the 2026-10-30 profile wrote to 0xffffc).
pub(crate) const STACK_ADDR: u64 = 0x0003_0000;
pub(crate) const STACK_SIZE: u64 = 0x0020_0000 - STACK_ADDR;
/// Where ESP starts: near the top, as in a Windows thread, with room above for
/// the entry point's return address and frames that read their caller's.
const STACK_START: u64 = STACK_ADDR + STACK_SIZE - 0x4000;
const TEB_ADDR: u64 = 0x200000;
const PEB_ADDR: u64 = 0x201000;
const LDR_ADDR: u64 = 0x202000;
const GDT_ADDR: u64 = 0x205000;
/// Static TLS: the pointer array, then block 0 (up to the next mapping, far above).
const TLS_ADDR: u64 = 0x206000;
/// Synthetic Windows kernel driver structures (DRIVER_OBJECT, KLDR_DATA_TABLE_ENTRY, RegistryPath).
const KDRV_ADDR: u64 = 0x0028_0000;
const KDRV_SIZE: u64 = 0x10000;
const HOOK_ADDR: u64 = 0x7F000000;
// Keep the synthetic RET target away from the mapped region's trailing page;
// Unicorn may fetch a small instruction window past a basic block boundary.
pub(crate) const SEH_RETURN_ADDR: u64 = HOOK_ADDR + 0x0F0000;
/// Return address of the entry point: an EXE's start routine or a DLL's DllMain that
/// returns lands here and the run ends cleanly (it used to return to address 0 and end
/// as a FETCH_UNMAPPED fault).
pub const ENTRY_RETURN_ADDR: u64 = HOOK_ADDR + 0x0F2000;

/// How an emulation run ended (`UnpackerEngine::end`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EmuEnd {
    /// Ran until the instruction budget or the time limit (or a configured stop).
    #[default]
    Finished,
    /// The program ended itself (ExitProcess / ExitThread / TerminateProcess on itself).
    Exited,
    /// The entry point (start routine, DllMain) returned.
    EntryReturned,
    /// An API call the emulator could not return from.
    Stopped,
    /// A memory or CPU fault no handler took.
    Fault,
}

impl EmuEnd {
    /// The program ran as far as it wanted to (as opposed to the emulator failing it).
    pub fn is_clean(self) -> bool {
        matches!(self, EmuEnd::Finished | EmuEnd::Exited | EmuEnd::EntryReturned)
    }
}

/// Where the run stopped on one of the conditions set with `set_stops`. The
/// address is the instruction the run stopped before (not executed yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopHit {
    /// Executing a page this run had written.
    WriteExecute(u64),
    /// Calling this API (name as imported); the stop is at its stub, before the call.
    Api(String, u64),
    /// Entering this section.
    Section(String, u64),
    /// A basic block starting with one of the patterns.
    Pattern(u64),
}

impl StopHit {
    pub fn address(&self) -> u64 {
        match self {
            StopHit::WriteExecute(a) | StopHit::Pattern(a) | StopHit::Api(_, a) | StopHit::Section(_, a) => *a,
        }
    }
}

/// An invalid memory access: the address, the instruction that made it, and the
/// access (0 read, 1 write, 8 execute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemFault {
    pub address: u64,
    pub instruction: u64,
    pub access: u32,
}

/// Conditions a run stops on (any of them), on top of the budget and time limit.
#[derive(Debug, Clone, Default)]
pub struct Stops {
    pub write_execute: bool,
    /// API names, normalized (`apicalls::normalize_api_name`).
    pub apis: Vec<String>,
    pub sections: Vec<String>,
    /// Hex byte patterns (`??` = any byte) matched at the start of a basic block.
    pub patterns: Vec<Vec<crate::disinfect::rules::HexByte>>,
    /// No condition stops inside these sections (the packer stub's own).
    pub outside: Vec<String>,
}
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
    pub image_base: u64,
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
        // A static unpack that fails leaves the file as it is: the emulator runs the
        // packer's own code instead.
        let raw_bytes = if !raw.is_empty() && vmpunpacker::detect(&raw) {
            log::info!("VMProtect detected in {}, unpacking in memory…", path);
            match vmpunpacker::unpack(&raw) {
                Ok(unpacked) => {
                    log::info!("VMProtect unpacked: {} -> {} bytes", path, unpacked.len());
                    unpacked
                }
                Err(e) => {
                    log::warn!("VMProtect LZMA unpack failed for {path}, emulating the packed file: {e}");
                    raw
                }
            }
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

    pub fn from_bytes(raw: &[u8]) -> UnpackerResult<Self> {
        let raw_bytes = if !raw.is_empty() && vmpunpacker::detect(raw) {
            vmpunpacker::unpack(raw).unwrap_or_else(|e| {
                log::warn!("VMProtect LZMA unpack failed, emulating the packed file: {e}");
                raw.to_vec()
            })
        } else {
            raw.to_vec()
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
            path: String::new(),
            yara_path: String::new(),
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
    /// Syscall number -> `Nt` function, from the `Zw` exports of the ntdll the emulator
    /// loaded sorted by address (their order is the number order).
    syscall_names: HashMap<u32, String>,
    breakpoints: Vec<u64>,
    mem_breakpoints: Vec<(u64, u64)>,
    /// Bytes written / executed per section, by index into `sample_sections` (the
    /// hooks only add to a slot; the name maps are built once after the run).
    section_write_bytes: Vec<u64>,
    section_exec_bytes: Vec<u64>,
    /// Pages (address >> 12) written inside the image. A set stays bounded however
    /// long a decryption loop runs; the old Vec of every single write grew by 16 bytes
    /// per write (millions per second) until the scanner ran out of memory.
    written_pages: HashSet<u64>,
    /// First address executed from a page this run had written (write-execute):
    /// self-decrypting / self-modifying code.
    wx_hit: Option<u64>,
    /// The same outside the image: code decrypted into allocated memory.
    wx_alloc_hit: Option<u64>,
    /// `insn_count` at the last write into an executable section or allocated
    /// memory in this run (0: none): a stub still unpacking writes until the end.
    last_code_write: u64,
    /// The last invalid memory access of this run.
    last_fault: Option<MemFault>,
    /// Set where the API hook ends the run (exit, or no way to return).
    api_end: Option<EmuEnd>,
    /// The API the run could not return from (`EmuEnd::Stopped`).
    stop_api: Option<String>,
    /// `set_stops` conditions (section names resolved to indices) and the one hit.
    stops: Stops,
    stop_sections: Vec<usize>,
    stop_outside: Vec<usize>,
    stop_hit: Option<StopHit>,
    /// Map a zeroed page on an unmapped read/write/fetch and continue instead of
    /// stopping (infector scan: polymorphic junk code dereferences registers that
    /// pointed at host data in the real process). Bounded by `faults`.
    map_on_fault: bool,
    faults: u32,
    /// Pending x86 access violation captured by Unicorn's invalid-memory hook.
    seh_fault: Option<SehFault>,
    /// Active frame while an x86 SEH handler runs.
    seh_active: Option<SehDispatch>,
    seh_count: u32,
    /// x64 VEH entries in Windows first/last registration order.
    veh_handlers: Vec<(u64, u64)>,
    next_veh_handle: u64,
    exception_rva: u32,
    exception_size: u32,
    seh64_active: Option<Seh64Dispatch>,
    /// Section addresses are RVAs; hook addresses are absolute.
    image_base: u64,
    image_size: u64,
    apicall_counter: HashMap<String, u64>,
    hook_addr: u64,
    start_time: Instant,
    /// End of the run's time limit (all SEH re-runs of one `emu_from` together),
    /// checked in the block hook instead of Unicorn's own timer (see `emu_from`).
    deadline: Option<Instant>,
    /// Instruction budget of the run (0 = none) and instructions run so far, counted
    /// per block in the block hook instead of Unicorn's `count`, which adds a code hook
    /// on every instruction and halved the emulation speed.
    insn_budget: u64,
    insn_count: u64,
    /// `(insn_count, ends_with_indirect_branch)` of each (block address, size), decoded once.
    block_insns: HashMap<(u64, u32), (u32, bool)>,
    blocks_seen: u32,
    total_blocks: u64,
    vm_indirect_blocks: u64,
    sample_sections: Vec<Section>,
    unpacker: UnpackerConfig,
    log_instr: bool,
    log_mem_read: bool,
    log_mem_write: bool,
    log_apicalls: bool,
    trace_mode: bool,
    is_64: bool,
    dllname_to_functionlist: HashMap<String, Vec<(String, u64)>>,
    api_state: ApiState,
    behavior_trace: BehaviorTrace,
    trace_bytes: usize,
}

#[derive(Clone, Copy)]
struct SehFault {
    code: u32,
    address: u64,
    access: u32,
    instruction: u64,
}

#[derive(Clone)]
struct SehDispatch {
    context: Vec<u8>,
    exception_record: u32,
    context_record: u32,
    dispatcher_context: u32,
    exception_pointers: u32,
    veh_handlers: Vec<u32>,
    veh_index: usize,
    next: u32,
    initial_esp: u32,
}

#[derive(Clone)]
struct Seh64Dispatch {
    context_ptr: u64,
    exception_record: u64,
    exception_pointers: u64,
    dispatcher_context: u64,
    prior_rsp: u64,
    image_base: u64,
    handlers: Vec<Seh64Handler>,
    next_handler: usize,
}

#[derive(Clone)]
struct Seh64Handler {
    address: u64,
    table: bool,
    context: Vec<u8>,
    control_pc: u64,
    establisher_frame: u64,
    function_entry: u64,
    handler_data: u64,
}

#[derive(Clone, Copy)]
struct RuntimeFunction64 { begin: u32, end: u32, unwind: u32, entry: u64 }

pub(crate) const SEH64_RETURN_ADDR: u64 = HOOK_ADDR + 0x0f1000;

fn write_u64(uc: &mut Unicorn<'static, ()>, addr: u64, value: u64) -> bool {
    uc.mem_write(addr, &value.to_le_bytes()).is_ok()
}

fn read_u32(uc: &Unicorn<'static, ()>, addr: u64) -> Option<u32> {
    Some(u32::from_le_bytes(uc.mem_read_as_vec(addr, 4).ok()?.try_into().ok()?))
}

/// Locate a language handler for the faulting instruction in the PE x64
/// RUNTIME_FUNCTION/.pdata table. Handles UNW_FLAG_EHANDLER and UHANDLER.
fn x64_runtime_function(uc: &Unicorn<'static, ()>, base: u64, image_size: u64, rva: u32, size: u32, ip: u64) -> Option<RuntimeFunction64> {
    if rva == 0 || size < 12 || rva as u64 >= image_size || size as u64 > image_size - rva as u64 { return None; }
    let count = (size / 12).min(((image_size - rva as u64) / 12) as u32).min(1_000_000);
    for i in 0..count {
        let entry = base.checked_add(rva as u64 + i as u64 * 12)?;
        let begin = read_u32(uc, entry)?;
        let end = read_u32(uc, entry + 4)?;
        let unwind = read_u32(uc, entry + 8)?;
        if begin >= end || end as u64 > image_size || (unwind & !3) as u64 >= image_size { continue; }
        if ip < base + begin as u64 || ip >= base + end as u64 { continue; }
        return Some(RuntimeFunction64 { begin, end, unwind, entry });
    }
    None
}

fn context_reg_offset(reg: u8) -> Option<usize> {
    match reg { 0 => Some(0x78), 1 => Some(0x80), 2 => Some(0x88), 3 => Some(0x90), 4 => Some(0x98),
        5 => Some(0xa0), 6 => Some(0xa8), 7 => Some(0xb0), 8..=15 => Some(0xb8 + (reg as usize - 8) * 8), _ => None }
}

fn context_read(c: &[u8], reg: u8) -> Option<u64> {
    let off = context_reg_offset(reg)?;
    Some(u64::from_le_bytes(c.get(off..off + 8)?.try_into().ok()?))
}

fn context_write(c: &mut [u8], reg: u8, value: u64) -> Option<()> {
    let off = context_reg_offset(reg)?;
    c.get_mut(off..off + 8)?.copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn stack_read_u64(uc: &Unicorn<'static, ()>, address: u64) -> Option<u64> {
    if address < STACK_ADDR || address.checked_add(8)? > STACK_ADDR + STACK_SIZE { return None; }
    Some(u64::from_le_bytes(uc.mem_read_as_vec(address, 8).ok()?.try_into().ok()?))
}

/// Apply one Windows x64 UNWIND_INFO to a CONTEXT and return the caller's
/// control PC and stack pointer. Also collects a language handler at this frame.
fn x64_unwind_one(
    uc: &Unicorn<'static, ()>, base: u64, image_size: u64, rf: RuntimeFunction64,
    control_pc: u64, context: &mut [u8], chain_depth: u8,
) -> Option<(u64, u64, Option<Seh64Handler>)> {
    let info = base.checked_add((rf.unwind & !3) as u64)?;
    let header = uc.mem_read_as_vec(info, 4).ok()?;
    let version = header[0] & 7;
    let flags = header[0] >> 3;
    let unwind_rva = (rf.unwind & !3) as u64;
    if !(1..=2).contains(&version) || flags & !7 != 0 || flags == 3 || flags & 4 != 0 && flags & 3 != 0 { return None; }
    let prolog_size = header[1] as u64;
    let count_codes = header[2] as usize;
    if count_codes > 128 { return None; }
    let trailer_rva = unwind_rva.checked_add(4 + (((count_codes + 1) & !1) * 2) as u64)?;
    let trailer_size = if flags & 3 != 0 { 4 } else if flags & 4 != 0 { 12 } else { 0 };
    if trailer_rva.checked_add(trailer_size)? > image_size { return None; }
    let frame_reg = header[3] & 0x0f;
    let frame_off = (header[3] >> 4) as u64 * 16;
    let code_addr = info.checked_add(4)?;
    let mut slots = Vec::with_capacity(count_codes);
    for i in 0..count_codes {
        let bytes = uc.mem_read_as_vec(code_addr + (i * 2) as u64, 2).ok()?;
        slots.push((bytes[0], bytes[1] & 0x0f, bytes[1] >> 4, u16::from_le_bytes([bytes[0], bytes[1]])));
    }
    let code_offset = control_pc.saturating_sub(base + rf.begin as u64);
    let in_prolog = code_offset < prolog_size;
    let mut rsp = context_read(context, 4)?;
    let mut machine_frame = None;
    let mut i = 0usize;
    while i < count_codes {
        let (offset, op, opinfo, _) = slots[i];
        i += 1;
        let extra_slots = match op { 1 if opinfo == 0 => 1, 1 if opinfo == 1 => 2,
            4 | 8 => 1, 5 | 9 => 2, _ => 0 };
        if i + extra_slots > count_codes { return None; }
        if in_prolog && offset as u64 > code_offset { i += extra_slots; continue; }
        match op {
            0 => { // UWOP_PUSH_NONVOL
                let value = stack_read_u64(uc, rsp)?;
                context_write(context, opinfo, value)?;
                rsp = rsp.checked_add(8)?;
            }
            1 => { // UWOP_ALLOC_LARGE
                let alloc = match opinfo {
                    0 => (slots.get(i)?.3 as u64) * 8,
                    1 => { let lo = slots.get(i)?.3 as u32; let hi = slots.get(i+1)?.3 as u32; (lo | hi << 16) as u64 }
                    _ => return None,
                };
                rsp = rsp.checked_add(alloc)?;
            }
            2 => rsp = rsp.checked_add(opinfo as u64 * 8 + 8)?, // UWOP_ALLOC_SMALL
            3 => { // UWOP_SET_FPREG
                if frame_reg == 0 || opinfo != 0 { return None; }
                rsp = context_read(context, frame_reg)?.checked_sub(frame_off)?;
            }
            4 | 5 => { // UWOP_SAVE_NONVOL(_FAR)
                let off = if op == 4 { slots.get(i)?.3 as u64 * 8 }
                    else { let lo = slots.get(i)?.3 as u32; let hi = slots.get(i+1)?.3 as u32; (lo | hi << 16) as u64 };
                context_write(context, opinfo, stack_read_u64(uc, rsp.checked_add(off)?)?)?;
            }
            6 => { // Version 2 epilog marker.
                if version != 2 { return None; }
            }
            7 => return None, // Reserved opcode.
            8 | 9 => { // UWOP_SAVE_XMM128(_FAR)
                let offset = if op == 8 { slots.get(i)?.3 as u64 * 16 }
                    else { let lo = slots.get(i)?.3 as u32; let hi = slots.get(i+1)?.3 as u32; (lo | hi << 16) as u64 };
                if !(6..=15).contains(&opinfo) { return None; }
                let address = rsp.checked_add(offset)?;
                if address < STACK_ADDR || address.checked_add(16)? > STACK_ADDR + STACK_SIZE { return None; }
                let xmm = uc.mem_read_as_vec(address, 16).ok()?;
                let xmm_offset = 0x1a0 + (opinfo as usize - 6) * 16;
                context.get_mut(xmm_offset..xmm_offset + 16)?.copy_from_slice(&xmm);
            }
            10 => { // UWOP_PUSH_MACHFRAME
                if opinfo > 1 { return None; }
                let has_error = opinfo == 1;
                let rip_offset = if has_error { 8 } else { 0 };
                let cs_offset = rip_offset + 8;
                let flags_offset = cs_offset + 8;
                let saved_rsp_offset = flags_offset + 8;
                let ss_offset = saved_rsp_offset + 8;
                let rip = stack_read_u64(uc, rsp + rip_offset)?;
                let cs = stack_read_u64(uc, rsp + cs_offset)? as u16;
                let flags = stack_read_u64(uc, rsp + flags_offset)? as u32;
                let restored_rsp = stack_read_u64(uc, rsp + saved_rsp_offset)?;
                let ss = stack_read_u64(uc, rsp + ss_offset)? as u16;
                context[0xf8..0x100].copy_from_slice(&rip.to_le_bytes());
                context[0x98..0xa0].copy_from_slice(&restored_rsp.to_le_bytes());
                context[0x38..0x3a].copy_from_slice(&cs.to_le_bytes());
                context[0x42..0x44].copy_from_slice(&ss.to_le_bytes());
                context[0x44..0x48].copy_from_slice(&flags.to_le_bytes());
                rsp = restored_rsp;
                machine_frame = Some((rip, restored_rsp));
                break;
            }
            _ => return None,
        }
        i += extra_slots;
        if i > count_codes { return None; }
    }
    let establisher = if frame_reg != 0 { context_read(context, frame_reg)?.checked_sub(frame_off)? } else { rsp };
    let handler = if flags & 3 != 0 {
        let aligned_slots = (count_codes + 1) & !1;
        let handler_slot = code_addr.checked_add((aligned_slots * 2) as u64)?;
        let handler_rva = read_u32(uc, handler_slot)?;
        let handler_addr = base.checked_add(handler_rva as u64)?;
        if handler_rva == 0 || handler_addr >= base.saturating_add(image_size) { return None; }
        Some(Seh64Handler { address: handler_addr, table: true, context: context.to_vec(), control_pc,
            establisher_frame: establisher, function_entry: rf.entry, handler_data: handler_slot + 4 })
    } else { None };
    if flags & 4 != 0 { // UNW_FLAG_CHAININFO; nested RUNTIME_FUNCTION follows aligned codes.
        if chain_depth >= 8 { return None; }
        let chain_addr = code_addr.checked_add((((count_codes + 1) & !1) * 2) as u64)?;
        let chained_begin = read_u32(uc, chain_addr)?;
        let chained_end = read_u32(uc, chain_addr + 4)?;
        let chained_unwind = read_u32(uc, chain_addr + 8)?;
        if chained_begin >= chained_end || chained_end as u64 > image_size || (chained_unwind & !3) as u64 >= image_size { return None; }
        let chained = RuntimeFunction64 { begin: chained_begin, end: chained_end, unwind: chained_unwind, entry: chain_addr };
        let chained_pc = base + chained.end as u64;
        let (caller_pc, caller_rsp, chained_handler) = x64_unwind_one(uc, base, image_size, chained, chained_pc, context, chain_depth + 1)?;
        return Some((caller_pc, caller_rsp, handler.or(chained_handler)));
    }
    if let Some((machine_pc, machine_rsp)) = machine_frame {
        return Some((machine_pc, machine_rsp, handler));
    }
    let return_pc = stack_read_u64(uc, rsp)?;
    let caller_rsp = rsp.checked_add(8)?;
    context[0xf8..0x100].copy_from_slice(&return_pc.to_le_bytes());
    context[0x98..0xa0].copy_from_slice(&caller_rsp.to_le_bytes());
    Some((return_pc, caller_rsp, handler))
}

fn x64_unwind_register(reg: Register) -> Option<u8> {
    Some(match reg {
        Register::RAX => 0, Register::RCX => 1, Register::RDX => 2, Register::RBX => 3,
        Register::RSP => 4, Register::RBP => 5, Register::RSI => 6, Register::RDI => 7,
        Register::R8 => 8, Register::R9 => 9, Register::R10 => 10, Register::R11 => 11,
        Register::R12 => 12, Register::R13 => 13, Register::R14 => 14, Register::R15 => 15,
        _ => return None,
    })
}

fn x64_unwind_iced_register(reg: u8) -> Option<Register> {
    Some(match reg {
        0 => Register::RAX, 1 => Register::RCX, 2 => Register::RDX, 3 => Register::RBX,
        4 => Register::RSP, 5 => Register::RBP, 6 => Register::RSI, 7 => Register::RDI,
        8 => Register::R8, 9 => Register::R9, 10 => Register::R10, 11 => Register::R11,
        12 => Register::R12, 13 => Register::R13, 14 => Register::R14, 15 => Register::R15,
        _ => return None,
    })
}

fn x64_iced_memory_address(ins: &iced_x86::Instruction, context: &[u8]) -> Option<u64> {
    let base = match ins.memory_base() {
        Register::None => 0,
        Register::RIP => ins.next_ip(),
        reg => context_read(context, x64_unwind_register(reg)?)?,
    };
    let index = match ins.memory_index() {
        Register::None => 0,
        reg => context_read(context, x64_unwind_register(reg)?)?.checked_mul(ins.memory_index_scale() as u64)?,
    };
    let displacement = ins.memory_displacement64() as i64;
    let address = base.checked_add(index)?;
    if displacement < 0 { address.checked_sub(displacement.unsigned_abs()) }
    else { address.checked_add(displacement as u64) }
}

/// If RIP is in an x64 epilog, execute its remaining stack/register effects on
/// the saved CONTEXT. Returns the next caller PC and RSP; `None` means the code
/// at RIP is not a recognized Windows epilog and normal UNWIND_INFO applies.
fn x64_unwind_epilog(
    uc: &Unicorn<'static, ()>, base: u64, rf: RuntimeFunction64, context: &mut [u8],
) -> Option<(u64, u64)> {
    let control_pc = u64::from_le_bytes(context[0xf8..0x100].try_into().ok()?);
    if control_pc < base + rf.begin as u64 || control_pc >= base + rf.end as u64 { return None; }
    let info = base.checked_add((rf.unwind & !3) as u64)?;
    let frame_reg = uc.mem_read_as_vec(info + 3, 1).ok()?[0] & 0x0f;
    let max_len = (base + rf.end as u64 - control_pc).min(96) as usize;
    let bytes = uc.mem_read_as_vec(control_pc, max_len).ok()?;
    let mut decoder = Decoder::with_ip(64, &bytes, control_pc, DecoderOptions::NONE);
    let mut rsp = context_read(context, 4)?;
    let mut adjusted_rsp = false;
    let mut popped = false;
    let mut recognized = false;

    for _ in 0..24 {
        if !decoder.can_decode() { return None; }
        let ins = decoder.decode();
        if ins.is_invalid() { return None; }
        match ins.mnemonic() {
            Mnemonic::Add if ins.op0_register() == Register::RSP
                && matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64) && !adjusted_rsp && !popped => {
                let amount = match ins.op1_kind() {
                    OpKind::Immediate8to64 => ins.immediate8to64() as i64,
                    _ => ins.immediate32to64(),
                };
                if amount < 0 { return None; }
                rsp = rsp.checked_add(amount as u64)?;
                adjusted_rsp = true;
                recognized = true;
            }
            Mnemonic::Lea if frame_reg != 0 && ins.op0_register() == Register::RSP && !adjusted_rsp && !popped
                && ins.memory_base() == x64_unwind_iced_register(frame_reg)?
                && ins.memory_index() == Register::None && ins.memory_index_scale() == 1 => {
                let base_value = context_read(context, frame_reg)?;
                let displacement = ins.memory_displacement64() as i64;
                let value = if displacement < 0 { base_value.checked_sub(displacement.unsigned_abs())? }
                    else { base_value.checked_add(displacement as u64)? };
                rsp = value;
                adjusted_rsp = true;
                recognized = true;
            }
            Mnemonic::Pop => {
                let reg = x64_unwind_register(ins.op0_register())?;
                if !matches!(reg, 3 | 5 | 6 | 7 | 12..=15) { return None; }
                let value = stack_read_u64(uc, rsp)?;
                context_write(context, reg, value)?;
                rsp = rsp.checked_add(8)?;
                popped = true;
                recognized = true;
            }
            Mnemonic::Ret => {
                let target = stack_read_u64(uc, rsp)?;
                let cleanup = if ins.op_count() == 1 && ins.op0_kind() == OpKind::Immediate16 { ins.immediate16() as u64 } else { 0 };
                rsp = rsp.checked_add(8)?.checked_add(cleanup)?;
                context[0xf8..0x100].copy_from_slice(&target.to_le_bytes());
                context[0x98..0xa0].copy_from_slice(&rsp.to_le_bytes());
                return Some((target, rsp));
            }
            _ if matches!(ins.flow_control(), FlowControl::UnconditionalBranch | FlowControl::IndirectBranch) => {
                context[0x98..0xa0].copy_from_slice(&rsp.to_le_bytes());
                let target = match ins.flow_control() {
                    FlowControl::UnconditionalBranch => ins.near_branch_target(),
                    FlowControl::IndirectBranch if recognized && ins.op0_kind() == OpKind::Register => {
                        context_read(context, x64_unwind_register(ins.op0_register())?)?
                    }
                    FlowControl::IndirectBranch if recognized && ins.op0_kind() == OpKind::Memory => {
                        let address = x64_iced_memory_address(&ins, context)?;
                        u64::from_le_bytes(uc.mem_read_as_vec(address, 8).ok()?.try_into().ok()?)
                    }
                    _ => return None,
                };
                if !recognized && ins.flow_control() != FlowControl::UnconditionalBranch { return None; }
                if target >= base + rf.begin as u64 && target < base + rf.end as u64 { return None; }
                context[0xf8..0x100].copy_from_slice(&target.to_le_bytes());
                context[0x98..0xa0].copy_from_slice(&rsp.to_le_bytes());
                return Some((target, rsp));
            }
            _ => return None,
        }
    }
    None
}

fn x64_unwind_chain(uc: &Unicorn<'static, ()>, base: u64, image_size: u64, rva: u32, size: u32, initial: &[u8]) -> Vec<Seh64Handler> {
    let mut handlers = Vec::new();
    let mut context = initial.to_vec();
    let mut control_pc = u64::from_le_bytes(context[0xf8..0x100].try_into().unwrap_or([0; 8]));
    let mut rsp = u64::from_le_bytes(context[0x98..0xa0].try_into().unwrap_or([0; 8]));
    let mut seen = HashSet::new();
    for _ in 0..64 {
        if control_pc == 0 || rsp < STACK_ADDR || rsp.checked_add(8).map_or(true, |x| x > STACK_ADDR + STACK_SIZE) { break; }
        if !seen.insert((control_pc, rsp)) { break; }
        if let Some(rf) = x64_runtime_function(uc, base, image_size, rva, size, control_pc) {
            if let Some((pc, new_rsp)) = x64_unwind_epilog(uc, base, rf, &mut context) {
                control_pc = pc; rsp = new_rsp;
                continue;
            }
            match x64_unwind_one(uc, base, image_size, rf, control_pc, &mut context, 0) {
                Some((pc, new_rsp, handler)) => {
                    if let Some(h) = handler { handlers.push(h); }
                    if new_rsp < rsp { break; }
                    control_pc = pc; rsp = new_rsp;
                }
                None => break,
            }
        } else {
            let Some(pc) = stack_read_u64(uc, rsp) else { break; };
            let Some(new_rsp) = rsp.checked_add(8) else { break; };
            if new_rsp <= rsp { break; }
            context[0xf8..0x100].copy_from_slice(&pc.to_le_bytes());
            context[0x98..0xa0].copy_from_slice(&new_rsp.to_le_bytes());
            control_pc = pc; rsp = new_rsp;
        }
    }
    handlers
}

fn x64_context(uc: &Unicorn<'static, ()>) -> Option<Vec<u8>> {
    let mut c = vec![0u8; 0x4d0];
    let put = |buf: &mut [u8], off: usize, val: u64| { buf[off..off+8].copy_from_slice(&val.to_le_bytes()); };
    c[0x30..0x34].copy_from_slice(&0x0010_000bu32.to_le_bytes());
    for (off, reg) in [(0x78,RegisterX86::RAX),(0x80,RegisterX86::RCX),(0x88,RegisterX86::RDX),(0x90,RegisterX86::RBX),
        (0x98,RegisterX86::RSP),(0xa0,RegisterX86::RBP),(0xa8,RegisterX86::RSI),(0xb0,RegisterX86::RDI),
        (0xb8,RegisterX86::R8),(0xc0,RegisterX86::R9),(0xc8,RegisterX86::R10),(0xd0,RegisterX86::R11),
        (0xd8,RegisterX86::R12),(0xe0,RegisterX86::R13),(0xe8,RegisterX86::R14),(0xf0,RegisterX86::R15),
        (0xf8,RegisterX86::RIP)] { put(&mut c, off, uc.reg_read(reg as i32).ok()?); }
    let flags = uc.reg_read(RegisterX86::EFLAGS as i32).ok()? as u32;
    c[0x44..0x48].copy_from_slice(&flags.to_le_bytes());
    Some(c)
}

fn restore_x64_context(uc: &mut Unicorn<'static, ()>, c: &[u8]) -> Option<u64> {
    for (off, reg) in [(0x78,RegisterX86::RAX),(0x80,RegisterX86::RCX),(0x88,RegisterX86::RDX),(0x90,RegisterX86::RBX),
        (0x98,RegisterX86::RSP),(0xa0,RegisterX86::RBP),(0xa8,RegisterX86::RSI),(0xb0,RegisterX86::RDI),
        (0xb8,RegisterX86::R8),(0xc0,RegisterX86::R9),(0xc8,RegisterX86::R10),(0xd0,RegisterX86::R11),
        (0xd8,RegisterX86::R12),(0xe0,RegisterX86::R13),(0xe8,RegisterX86::R14),(0xf0,RegisterX86::R15),
        (0xf8,RegisterX86::RIP)] {
        uc.reg_write(reg as i32, u64::from_le_bytes(c[off..off+8].try_into().ok()?)).ok()?;
    }
    let ip = u64::from_le_bytes(c[0xf8..0x100].try_into().ok()?);
    uc.reg_write(RegisterX86::EFLAGS as i32, u32::from_le_bytes(c[0x44..0x48].try_into().ok()?) as u64).ok()?;
    Some(ip)
}

fn setup_x64_handler(uc: &mut Unicorn<'static, ()>, active: &Seh64Dispatch) -> Option<u64> {
    let handler = active.handlers.get(active.next_handler)?;
    uc.mem_write(active.context_ptr, &handler.context).ok()?;
    let mut disp = [0u8; 0x50];
    for (off, value) in [(0x00, handler.control_pc), (0x08, active.image_base),
        (0x10, handler.function_entry), (0x18, handler.establisher_frame),
        (0x28, active.context_ptr), (0x30, handler.address), (0x38, handler.handler_data)] {
        disp[off..off+8].copy_from_slice(&value.to_le_bytes());
    }
    uc.mem_write(active.dispatcher_context, &disp).ok()?;
    let call_rsp = (active.prior_rsp.checked_sub(0x80)? & !0xf) - 8;
    write_u64(uc, call_rsp, SEH64_RETURN_ADDR).then_some(())?;
    if handler.table {
        uc.reg_write(RegisterX86::RCX as i32, active.exception_record).ok()?;
        uc.reg_write(RegisterX86::RDX as i32, handler.establisher_frame).ok()?;
        uc.reg_write(RegisterX86::R8 as i32, active.context_ptr).ok()?;
        uc.reg_write(RegisterX86::R9 as i32, active.dispatcher_context).ok()?;
    } else {
        uc.reg_write(RegisterX86::RCX as i32, active.exception_pointers).ok()?;
    }
    uc.reg_write(RegisterX86::RSP as i32, call_rsp).ok()?;
    uc.reg_write(RegisterX86::RIP as i32, handler.address).ok()?;
    Some(handler.address)
}

fn begin_x64_seh(uc: &mut Unicorn<'static, ()>, shared: &Rc<RefCell<HookState>>, fault: SehFault) -> Option<u64> {
    let (base, image_size, rva, size, veh_handlers) = {
        let mut s = shared.borrow_mut();
        if !s.is_64 || s.seh_count >= 128 { return None; }
        s.seh_count += 1;
        (s.image_base, s.image_size, s.exception_rva, s.exception_size,
         s.veh_handlers.iter().map(|(_, h)| *h).collect::<Vec<_>>())
    };
    let ip = fault.instruction;
    let ctx = x64_context(uc)?;
    let mut handlers: Vec<Seh64Handler> = veh_handlers.into_iter().map(|address| Seh64Handler {
        address, table: false, context: ctx.clone(), control_pc: ip,
        establisher_frame: u64::from_le_bytes(ctx[0x98..0xa0].try_into().unwrap_or([0; 8])),
        function_entry: 0, handler_data: 0,
    }).collect();
    handlers.extend(x64_unwind_chain(uc, base, image_size, rva, size, &ctx));
    if handlers.is_empty() { return None; }
    let rsp = uc.reg_read(RegisterX86::RSP as i32).ok()?;
    let reserve = 0x800u64;
    let record = (rsp.checked_sub(reserve)? & !0xf) + 0x100;
    let ctx_ptr = record + 0x100;
    let ptrs = ctx_ptr + 0x4d0;
    let dispatcher = ptrs + 0x10;
    let mut er = vec![0u8; 0x98];
    er[0..4].copy_from_slice(&fault.code.to_le_bytes());
    er[0x10..0x18].copy_from_slice(&fault.instruction.to_le_bytes());
    let n = if fault.code == 0xc0000005 { 2u32 } else { 0 };
    er[0x18..0x1c].copy_from_slice(&n.to_le_bytes());
    if n == 2 { er[0x20..0x28].copy_from_slice(&(fault.access as u64).to_le_bytes()); er[0x28..0x30].copy_from_slice(&fault.address.to_le_bytes()); }
    uc.mem_write(record, &er).ok()?;
    uc.mem_write(ctx_ptr, &ctx).ok()?;
    uc.mem_write(ptrs, &record.to_le_bytes()).ok()?;
    uc.mem_write(ptrs+8, &ctx_ptr.to_le_bytes()).ok()?;
    let active = Seh64Dispatch { context_ptr: ctx_ptr, exception_record: record, exception_pointers: ptrs,
        dispatcher_context: dispatcher, prior_rsp: rsp, image_base: base, handlers, next_handler: 0 };
    let handler = setup_x64_handler(uc, &active)?;
    shared.borrow_mut().seh64_active = Some(active);
    Some(handler)
}

fn finish_x64_seh(uc: &mut Unicorn<'static, ()>, shared: &Rc<RefCell<HookState>>) -> Option<u64> {
    let mut active = shared.borrow_mut().seh64_active.take()?;
    let ret = uc.reg_read(RegisterX86::RAX as i32).ok()? as u32;
    let is_table = active.handlers.get(active.next_handler).is_some_and(|h| h.table);
    let continue_exec = if is_table { ret == 0 } else { ret == u32::MAX };
    let continue_search = if is_table { ret == 1 } else { ret == 0 };
    if continue_exec {
        let context = uc.mem_read_as_vec(active.context_ptr, 0x4d0).ok()?;
        return restore_x64_context(uc, &context);
    }
    if !continue_search { return None; }
    active.next_handler += 1;
    let _ = active.handlers.get(active.next_handler)?;
    let next = setup_x64_handler(uc, &active)?;
    shared.borrow_mut().seh64_active = Some(active);
    Some(next)
}

fn x86_segment_descriptor(base: u32, limit: u32, access: u8, flags: u8) -> [u8; 8] {
    [
        limit as u8,
        (limit >> 8) as u8,
        base as u8,
        (base >> 8) as u8,
        (base >> 16) as u8,
        access,
        ((limit >> 16) as u8 & 0x0f) | (flags & 0xf0),
        (base >> 24) as u8,
    ]
}

fn dispatch_next_x86_seh_frame(
    uc: &mut Unicorn<'static, ()>,
    image_base: u64,
    image_size: u64,
    start_frame: u32,
    record: u32,
    ctx_ptr: u32,
    disp_ptr: u32,
    esp_base: u32,
) -> Option<(u32, u32, u32)> {
    let mut frame = start_frame;
    loop {
        if frame < STACK_ADDR as u32 || frame as u64 + 8 > STACK_ADDR + STACK_SIZE {
            return None;
        }
        let words = uc.mem_read_as_vec(frame as u64, 8).ok()?;
        let next = u32::from_le_bytes(words[0..4].try_into().ok()?);
        let handler = u32::from_le_bytes(words[4..8].try_into().ok()?);
        if handler == 0 {
            return None;
        }
        if valid_seh_handler(image_base, image_size, handler) {
            let mut sp = esp_base;
            let args = [SEH_RETURN_ADDR as u32, record, frame, ctx_ptr, disp_ptr];
            for value in args.iter().rev() {
                sp = sp.checked_sub(4)?;
                uc.mem_write(sp as u64, &value.to_le_bytes()).ok()?;
            }
            uc.reg_write(RegisterX86::ESP as i32, sp as u64).ok()?;
            uc.reg_write(RegisterX86::EIP as i32, handler as u64).ok()?;
            return Some((handler, next, sp));
        }
        if next <= frame || next == u32::MAX {
            return None;
        }
        frame = next;
    }
}

fn restore_x86_seh_context(uc: &mut Unicorn<'static, ()>, ctx: &[u8]) -> Option<u64> {
    for (off, reg) in [
        (0x9c, RegisterX86::EDI),
        (0xa0, RegisterX86::ESI),
        (0xa4, RegisterX86::EBX),
        (0xa8, RegisterX86::EDX),
        (0xac, RegisterX86::ECX),
        (0xb0, RegisterX86::EAX),
        (0xb4, RegisterX86::EBP),
        (0xc0, RegisterX86::EFLAGS),
        (0xc4, RegisterX86::ESP),
    ] {
        uc.reg_write(reg as i32, u32::from_le_bytes(ctx[off..off + 4].try_into().ok()?) as u64).ok()?;
    }
    let ip = u32::from_le_bytes(ctx[0xb8..0xbc].try_into().ok()?);
    uc.reg_write(RegisterX86::EIP as i32, ip as u64).ok()?;
    Some(ip as u64)
}

fn begin_x86_seh(
    uc: &mut Unicorn<'static, ()>,
    shared: &Rc<RefCell<HookState>>,
    fault: SehFault,
) -> Option<u64> {
    let (is_64, seh_count, image_base, image_size, veh_handlers) = {
        let state = shared.borrow();
        let vehs = state
            .veh_handlers
            .iter()
            .filter_map(|(_, h)| u32::try_from(*h).ok().filter(|&a| valid_seh_handler(state.image_base, state.image_size, a)))
            .collect::<Vec<_>>();
        (state.is_64, state.seh_count, state.image_base, state.image_size, vehs)
    };
    if is_64 || seh_count >= 128 { return None; }
    shared.borrow_mut().seh_count = seh_count + 1;
    let head = u32::from_le_bytes(uc.mem_read_as_vec(TEB_ADDR, 4).ok()?.try_into().ok()?);
    if veh_handlers.is_empty() && (head == u32::MAX || head == 0) { return None; }
    let esp = uc.reg_read(RegisterX86::ESP as i32).ok()? as u32;
    let mut context = vec![0u8; 0x2cc];
    let put = |buf: &mut [u8], off: usize, value: u32| { buf[off..off + 4].copy_from_slice(&value.to_le_bytes()); };
    put(&mut context, 0x00, 0x0001_0007); // CONTEXT_FULL | CONTEXT_i386
    for (off, reg) in [(0x9c, RegisterX86::EDI),(0xa0,RegisterX86::ESI),(0xa4,RegisterX86::EBX),
        (0xa8,RegisterX86::EDX),(0xac,RegisterX86::ECX),(0xb0,RegisterX86::EAX),
        (0xb4,RegisterX86::EBP),(0xb8,RegisterX86::EIP),(0xc0,RegisterX86::EFLAGS),
        (0xc4,RegisterX86::ESP)] {
        put(&mut context, off, uc.reg_read(reg as i32).ok()? as u32);
    }
    for (off, reg) in [(0x8c,RegisterX86::GS),(0x90,RegisterX86::FS),(0x94,RegisterX86::ES),
        (0x98,RegisterX86::DS),(0xbc,RegisterX86::CS),(0xc8,RegisterX86::SS)] {
        put(&mut context, off, uc.reg_read(reg as i32).unwrap_or(0) as u32);
    }
    let record = esp.checked_sub(0x500)?;
    let ctx_ptr = record.checked_add(0x80)?;
    let disp_ptr = ctx_ptr.checked_add(0x2cc)?;
    let ptrs = disp_ptr.checked_add(0x20)?;
    uc.mem_write(ctx_ptr as u64, &context).ok()?;
    let mut er = vec![0u8; 80];
    er[0..4].copy_from_slice(&fault.code.to_le_bytes());
    er[12..16].copy_from_slice(&(fault.instruction as u32).to_le_bytes());
    let parameter_count = if fault.code == 0xc0000005 { 2u32 } else { 0u32 };
    er[16..20].copy_from_slice(&parameter_count.to_le_bytes());
    if parameter_count == 2 {
        er[20..24].copy_from_slice(&fault.access.to_le_bytes());
        er[24..28].copy_from_slice(&(fault.address as u32).to_le_bytes());
    }
    uc.mem_write(record as u64, &er).ok()?;
    uc.mem_write(disp_ptr as u64, &[0u8; 32]).ok()?;
    uc.mem_write(ptrs as u64, &record.to_le_bytes()).ok()?;
    uc.mem_write(ptrs as u64 + 4, &ctx_ptr.to_le_bytes()).ok()?;

    if let Some(&handler) = veh_handlers.first() {
        let mut sp = record;
        for value in [ptrs, SEH_RETURN_ADDR as u32] {
            sp = sp.checked_sub(4)?;
            uc.mem_write(sp as u64, &value.to_le_bytes()).ok()?;
        }
        uc.reg_write(RegisterX86::ESP as i32, sp as u64).ok()?;
        uc.reg_write(RegisterX86::EIP as i32, handler as u64).ok()?;
        shared.borrow_mut().seh_active = Some(SehDispatch {
            context,
            exception_record: record,
            context_record: ctx_ptr,
            dispatcher_context: disp_ptr,
            exception_pointers: ptrs,
            veh_handlers,
            veh_index: 0,
            next: head,
            initial_esp: record,
        });
        return Some(handler as u64);
    }

    let (handler, next, sp) = dispatch_next_x86_seh_frame(uc, image_base, image_size, head, record, ctx_ptr, disp_ptr, record)?;
    shared.borrow_mut().seh_active = Some(SehDispatch {
        context,
        exception_record: record,
        context_record: ctx_ptr,
        dispatcher_context: disp_ptr,
        exception_pointers: ptrs,
        veh_handlers: Vec::new(),
        veh_index: 0,
        next,
        initial_esp: sp,
    });
    Some(handler as u64)
}

fn finish_x86_seh(uc: &mut Unicorn<'static, ()>, shared: &Rc<RefCell<HookState>>) -> Option<u64> {
    let (mut active, seh_count, image_base, image_size) = {
        let mut state = shared.borrow_mut();
        (state.seh_active.take()?, state.seh_count, state.image_base, state.image_size)
    };
    active.context = uc.mem_read_as_vec(active.context_record as u64, 0x2cc).ok()?;
    let eax = uc.reg_read(RegisterX86::EAX as i32).ok()? as u32;

    // Active x86 VEH pass before FS:[0] frame handlers
    if active.veh_index < active.veh_handlers.len() {
        if eax == u32::MAX {
            return restore_x86_seh_context(uc, &active.context);
        }
        if eax != 0 {
            return None;
        }
        active.veh_index += 1;
        if let Some(&next_veh) = active.veh_handlers.get(active.veh_index) {
            if seh_count >= 128 { return None; }
            let mut sp = active.exception_record;
            for value in [active.exception_pointers, SEH_RETURN_ADDR as u32] {
                sp = sp.checked_sub(4)?;
                uc.mem_write(sp as u64, &value.to_le_bytes()).ok()?;
            }
            uc.reg_write(RegisterX86::ESP as i32, sp as u64).ok()?;
            uc.reg_write(RegisterX86::EIP as i32, next_veh as u64).ok()?;
            let mut state = shared.borrow_mut();
            state.seh_count = seh_count + 1;
            state.seh_active = Some(active);
            return Some(next_veh as u64);
        }
        if active.next == 0 || active.next == u32::MAX || seh_count >= 128 {
            return None;
        }
        let (handler, next, sp) = dispatch_next_x86_seh_frame(
            uc, image_base, image_size, active.next, active.exception_record,
            active.context_record, active.dispatcher_context, active.exception_record,
        )?;
        let mut state = shared.borrow_mut();
        state.seh_count = seh_count + 1;
        state.seh_active = Some(SehDispatch { next, initial_esp: sp, ..active });
        return Some(handler as u64);
    }

    match eax {
        0 => restore_x86_seh_context(uc, &active.context),
        1 => {
            if active.next == u32::MAX || seh_count >= 128 { return None; }
            let (handler, next, sp) = dispatch_next_x86_seh_frame(
                uc, image_base, image_size, active.next, active.exception_record,
                active.context_record, active.dispatcher_context, active.initial_esp,
            )?;
            let mut state = shared.borrow_mut();
            state.seh_count = seh_count + 1;
            state.seh_active = Some(SehDispatch { next, initial_esp: sp, ..active });
            Some(handler as u64)
        }
        _ => None,
    }
}

fn valid_handler_addr(image_base: u64, image_size: u64, handler: u64) -> bool {
    let in_image = handler >= image_base && handler < image_base.saturating_add(image_size);
    let in_alloc = handler >= apicalls::ALLOC_BASE && handler < apicalls::ALLOC_END;
    in_image || in_alloc
}

fn valid_seh_handler(image_base: u64, image_size: u64, handler: u32) -> bool {
    valid_handler_addr(image_base, image_size, handler as u64)
}

fn apply_veh_call(st: &mut HookState, is_add: bool, arg0: u64, arg1: u64) -> u64 {
    if is_add {
        if !valid_handler_addr(st.image_base, st.image_size, arg1) {
            return 0;
        }
        let handle = st.next_veh_handle;
        st.next_veh_handle = st.next_veh_handle.wrapping_add(1).max(1);
        if arg0 != 0 {
            st.veh_handlers.insert(0, (handle, arg1));
        } else {
            st.veh_handlers.push((handle, arg1));
        }
        handle
    } else {
        let before = st.veh_handlers.len();
        st.veh_handlers.retain(|(handle, _)| *handle != arg0);
        (before != st.veh_handlers.len()) as u64
    }
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
    /// First address executed from a page written during this run, if any.
    pub wx_hit: Option<u64>,
    /// First such address outside the image (allocated memory); `alloc_payload`.
    pub wx_alloc_hit: Option<u64>,
    /// The last invalid memory access of the last run (an unhandled one ends it
    /// as `EmuEnd::Fault`).
    pub last_fault: Option<MemFault>,
    /// How the last run ended.
    pub end: EmuEnd,
    /// The API the run could not return from, when it ended `Stopped`.
    pub stop_api: Option<String>,
    /// The `set_stops` condition the last run stopped on.
    pub stop_hit: Option<StopHit>,
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
    pub trace_mode: bool,
    pub behavior_trace: BehaviorTrace,
    pub unique_blocks: usize,
    pub total_blocks: u64,
    pub vm_indirect_blocks: u64,
    pub seh_dispatches: u32,
    pub insn_count: u64,

    pub(crate) uc: Option<Unicorn<'static, ()>>,
    hook_ids: Vec<UcHookId>,
    hook_state: Rc<RefCell<HookState>>,
}

impl UnpackerEngine {
    pub fn new(sample: Sample, unpack_path: &str) -> Self {
        let peb_base = PEB_ADDR;
        let teb_base = TEB_ADDR;
        let sections = sample.sections.clone();
        let unpacker = sample.unpacker.clone();
        let image_base = sample.base_addr;
        let image_size = sample.virtualmemorysize;
        let (exception_rva, exception_size) = sample.opt_header.data_directory.get(3)
            .map(|d| (d.virtual_address, d.size)).unwrap_or((0, 0));
        let trace_mode = unpacker.trace_mode;
        let is_64 = PeArch::from_pe(sample.pe_header.machine, sample.opt_header.magic).is_64();
        let dllname_to_functionlist = sample.dllname_to_functionlist.clone();

        Self {
            sample,
            unpack_path: unpack_path.to_string(),
            breakpoints: Vec::new(),
            mem_breakpoints: Vec::new(),
            sections_read: HashMap::new(),
            sections_written: HashMap::new(),
            sections_executed: HashMap::new(),
            write_targets: Vec::new(),
            wx_hit: None,
            wx_alloc_hit: None,
            last_fault: None,
            end: EmuEnd::Finished,
            stop_api: None,
            stop_hit: None,
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
            trace_mode,
            behavior_trace: BehaviorTrace::default(),
            unique_blocks: 0,
            total_blocks: 0,
            vm_indirect_blocks: 0,
            seh_dispatches: 0,
            insn_count: 0,
            uc: None,
            hook_ids: Vec::new(),
            hook_state: Rc::new(RefCell::new(HookState {
                syscall_names: HashMap::new(),
                breakpoints: Vec::new(),
                mem_breakpoints: Vec::new(),
                section_write_bytes: vec![0; sections.len()],
                section_exec_bytes: vec![0; sections.len()],
                written_pages: HashSet::new(),
                wx_hit: None,
                wx_alloc_hit: None,
                last_code_write: 0,
                last_fault: None,
                api_end: None,
                stop_api: None,
                stops: Stops::default(),
                stop_sections: Vec::new(),
                stop_outside: Vec::new(),
                stop_hit: None,
                map_on_fault: false,
                faults: 0,
                seh_fault: None,
                seh_active: None,
                seh_count: 0,
                veh_handlers: Vec::new(),
                next_veh_handle: 1,
                exception_rva,
                exception_size,
                seh64_active: None,
                image_base,
                image_size,
                apicall_counter: HashMap::new(),
                hook_addr: HOOK_ADDR,
                start_time: Instant::now(),
                deadline: None,
                insn_budget: 0,
                insn_count: 0,
                block_insns: HashMap::new(),
                blocks_seen: 0,
                total_blocks: 0,
                vm_indirect_blocks: 0,
                sample_sections: sections,
                unpacker,
                log_instr: false,
                log_mem_read: false,
                log_mem_write: false,
                log_apicalls: false,
                trace_mode,
                is_64,
                dllname_to_functionlist,
                api_state: ApiState {
                    image_base,
                    is_64,
                    ..ApiState::default()
                },
                behavior_trace: BehaviorTrace::default(),
                trace_bytes: 0,
            })),
        }
    }

    pub fn with_trace_mode(mut self, trace_mode: bool) -> Self {
        self.trace_mode = trace_mode;
        self.hook_state.borrow_mut().trace_mode = trace_mode;
        self
    }

    pub fn behavior_trace(&self) -> &BehaviorTrace {
        &self.behavior_trace
    }

    pub fn api_trace(&self) -> &[ApiCall] {
        &self.behavior_trace.calls
    }

    pub fn unique_blocks(&self) -> usize {
        self.unique_blocks
    }

    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    pub fn vm_indirect_blocks(&self) -> u64 {
        self.vm_indirect_blocks
    }

    pub fn seh_dispatches(&self) -> u32 {
        self.seh_dispatches
    }

    pub fn insn_count(&self) -> u64 {
        self.insn_count
    }

    // ------------------------------------------------------------------
    // PE Loader Fidelity Helpers (LOAD_CONFIG cookie & Kernel Driver Env)
    // ------------------------------------------------------------------

    /// Initializes an uninitialized MSVC `LOAD_CONFIG.SecurityCookie` slot (and its
    /// complement) so `GsDriverEntry` / `__security_init_cookie` does not fail with `int 29h`.
    fn init_security_cookie(
        &self,
        uc: &mut Unicorn<'static, ()>,
        image_base: u64,
        virtual_size: u64,
        is_64: bool,
    ) {
        let Some(lc_dir) = self
            .sample
            .opt_header
            .data_directory
            .get(10)
            .filter(|d| d.virtual_address != 0)
        else {
            return;
        };
        let dir_va = image_base.saturating_add(lc_dir.virtual_address as u64);
        let img_end = image_base.saturating_add(virtual_size);
        let read_u32_mem = |uc: &Unicorn<'static, ()>, va: u64| -> Option<u32> {
            let b = uc.mem_read_as_vec(va, 4).ok()?;
            <[u8; 4]>::try_from(b).ok().map(u32::from_le_bytes)
        };
        let read_u64_mem = |uc: &Unicorn<'static, ()>, va: u64| -> Option<u64> {
            let b = uc.mem_read_as_vec(va, 8).ok()?;
            <[u8; 8]>::try_from(b).ok().map(u64::from_le_bytes)
        };

        let Some(lc_size) = read_u32_mem(uc, dir_va) else {
            return;
        };

        if is_64 {
            const DEFAULT_COOKIE_64: u64 = 0x0000_2B99_2DDF_A232;
            const INIT_COOKIE_64: u64 = 0x0000_7A53_9C1E_4B2F;
            if lc_size < 0x60 {
                return;
            }
            let Some(cookie_va) = read_u64_mem(uc, dir_va + 0x58) else {
                return;
            };
            if cookie_va >= image_base && cookie_va.saturating_add(8) <= img_end {
                if let Some(cur) = read_u64_mem(uc, cookie_va) {
                    if cur == 0 || cur == DEFAULT_COOKIE_64 {
                        let _ = uc.mem_write(cookie_va, &INIT_COOKIE_64.to_le_bytes());
                        if cookie_va.saturating_add(16) <= img_end {
                            if let Some(comp) = read_u64_mem(uc, cookie_va + 8) {
                                if comp == 0 || comp == !DEFAULT_COOKIE_64 {
                                    let _ = uc.mem_write(
                                        cookie_va + 8,
                                        &(!INIT_COOKIE_64).to_le_bytes(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        } else {
            const DEFAULT_COOKIE_32: u32 = 0xBB40_E64E;
            const INIT_COOKIE_32: u32 = 0x5A3C_91E7;
            if lc_size < 0x40 {
                return;
            }
            let Some(cookie_va32) = read_u32_mem(uc, dir_va + 0x3C) else {
                return;
            };
            let cookie_va = cookie_va32 as u64;
            if cookie_va >= image_base && cookie_va.saturating_add(4) <= img_end {
                if let Some(cur) = read_u32_mem(uc, cookie_va) {
                    if cur == 0 || cur == DEFAULT_COOKIE_32 {
                        let _ = uc.mem_write(cookie_va, &INIT_COOKIE_32.to_le_bytes());
                        if cookie_va.saturating_add(8) <= img_end {
                            if let Some(comp) = read_u32_mem(uc, cookie_va + 4) {
                                if comp == 0 || comp == !DEFAULT_COOKIE_32 {
                                    let _ = uc.mem_write(
                                        cookie_va + 4,
                                        &(!INIT_COOKIE_32).to_le_bytes(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Sets up minimal Windows kernel driver structures (`DRIVER_OBJECT`, `KLDR_DATA_TABLE_ENTRY`,
    /// and `RegistryPath` `UNICODE_STRING`) when `Subsystem == 1` (NATIVE) on x86/x64.
    fn init_kernel_driver_env(
        &self,
        uc: &mut Unicorn<'static, ()>,
        arch: PeArch,
        image_base: u64,
        virtual_size: u64,
        start_addr: u64,
        esp_val: u64,
    ) {
        if self.sample.opt_header.subsystem != 1 || !matches!(arch, PeArch::X86 | PeArch::X64) {
            return;
        }
        let img_end = image_base.saturating_add(virtual_size);
        let kdrv_end = KDRV_ADDR + KDRV_SIZE;
        if KDRV_ADDR < img_end && kdrv_end > image_base {
            return;
        }
        if uc
            .mem_map(KDRV_ADDR, KDRV_SIZE, Prot::READ | Prot::WRITE)
            .is_err()
        {
            return;
        }

        let is_64 = arch.is_64();
        let ldr_entry = KDRV_ADDR + 0x1000;
        let reg_path = KDRV_ADDR + 0x2000;
        let reg_buf = KDRV_ADDR + 0x2100;

        let mut region = vec![0u8; KDRV_SIZE as usize];
        // DRIVER_OBJECT at +0x0000
        region[0x00..0x02].copy_from_slice(&4u16.to_le_bytes());
        let drv_size: u16 = if is_64 { 0x150 } else { 0xA8 };
        region[0x02..0x04].copy_from_slice(&drv_size.to_le_bytes());
        if is_64 {
            region[0x18..0x20].copy_from_slice(&image_base.to_le_bytes());
            region[0x20..0x24].copy_from_slice(&(virtual_size as u32).to_le_bytes());
            region[0x28..0x30].copy_from_slice(&ldr_entry.to_le_bytes());
        } else {
            region[0x0C..0x10].copy_from_slice(&(image_base as u32).to_le_bytes());
            region[0x10..0x14].copy_from_slice(&(virtual_size as u32).to_le_bytes());
            region[0x14..0x18].copy_from_slice(&(ldr_entry as u32).to_le_bytes());
        }

        // KLDR_DATA_TABLE_ENTRY at +0x1000
        let l = 0x1000usize;
        if is_64 {
            region[l..l + 8].copy_from_slice(&ldr_entry.to_le_bytes());
            region[l + 8..l + 16].copy_from_slice(&ldr_entry.to_le_bytes());
            region[l + 0x30..l + 0x38].copy_from_slice(&image_base.to_le_bytes());
            region[l + 0x38..l + 0x40].copy_from_slice(&start_addr.to_le_bytes());
            region[l + 0x40..l + 0x44].copy_from_slice(&(virtual_size as u32).to_le_bytes());
        } else {
            region[l..l + 4].copy_from_slice(&(ldr_entry as u32).to_le_bytes());
            region[l + 4..l + 8].copy_from_slice(&(ldr_entry as u32).to_le_bytes());
            region[l + 0x18..l + 0x1C].copy_from_slice(&(image_base as u32).to_le_bytes());
            region[l + 0x1C..l + 0x20].copy_from_slice(&(start_addr as u32).to_le_bytes());
            region[l + 0x20..l + 0x24].copy_from_slice(&(virtual_size as u32).to_le_bytes());
        }

        // UNICODE_STRING RegistryPath at +0x2000 + UTF-16 string at +0x2100
        let svc_path: Vec<u8> = r"\Registry\Machine\System\CurrentControlSet\Services\Sample"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let u = 0x2000usize;
        let len_bytes = svc_path.len() as u16;
        region[u..u + 2].copy_from_slice(&len_bytes.to_le_bytes());
        region[u + 2..u + 4].copy_from_slice(&(len_bytes + 2).to_le_bytes());
        if is_64 {
            region[u + 8..u + 16].copy_from_slice(&reg_buf.to_le_bytes());
        } else {
            region[u + 4..u + 8].copy_from_slice(&(reg_buf as u32).to_le_bytes());
        }
        region[0x2100..0x2100 + svc_path.len()].copy_from_slice(&svc_path);

        if uc.mem_write(KDRV_ADDR, &region).is_err() {
            return;
        }

        match arch {
            PeArch::X64 => {
                let _ = uc.reg_write(RegisterX86::RCX as i32, KDRV_ADDR);
                let _ = uc.reg_write(RegisterX86::RDX as i32, reg_path);
            }
            PeArch::X86 => {
                let _ = uc.mem_write(esp_val + 4, &(KDRV_ADDR as u32).to_le_bytes());
                let _ = uc.mem_write(esp_val + 8, &(reg_path as u32).to_le_bytes());
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // init_uc — set up Unicorn, map PE, load DLLs, hook imports
    // ------------------------------------------------------------------

    pub fn init_uc(&mut self) -> UnpackerResult<()> {
        let arch = PeArch::from_pe(self.sample.pe_header.machine, self.sample.opt_header.magic);
        let is_64 = arch.is_64();
        let mut uc = match arch {
            PeArch::X86 => Unicorn::new(Arch::X86, Mode::MODE_32),
            PeArch::X64 => Unicorn::new(Arch::X86, Mode::MODE_64),
            PeArch::Arm32 => Unicorn::new(Arch::ARM, Mode::THUMB),
            PeArch::Arm64 => Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN),
        }.map_err(|e| UnpackerError::EmulatorError(format!("uc_open: {:?}", e)))?;

        let pe_data = self.sample.raw_bytes.clone();
        let image_base = self.sample.base_addr;
        let virtual_size = page_align(self.sample.virtualmemorysize);

        // --- Map PE image ---
        uc.mem_map(image_base, virtual_size, Prot::ALL)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map PE: {:?}", e)))?;

        let mmap_image = get_memory_mapped_image(&pe_data, &self.sample.sections, virtual_size, self.sample.opt_header.size_of_headers);
        uc.mem_write(image_base, &mmap_image)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_write PE: {:?}", e)))?;

        self.sample.loaded_image = mmap_image;
        self.init_security_cookie(&mut uc, image_base, virtual_size as u64, is_64);

        // --- Map TEB ---
        let teb_size = page_align(0x1000);
        uc.mem_map(TEB_ADDR, teb_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map TEB: {:?}", e)))?;

        if is_64 {
            let teb = Teb64::new(
                STACK_ADDR + STACK_SIZE,
                STACK_ADDR,
                TEB_ADDR,
                0x1000,
                0x1001,
                PEB_ADDR,
            );
            uc.mem_write(TEB_ADDR, &teb.to_bytes())
                .map_err(|e| UnpackerError::EmulatorError(format!("mem_write TEB: {:?}", e)))?;
            if arch == PeArch::X64 {
                let _ = uc.reg_write(RegisterX86::GS_BASE as i32, TEB_ADDR);
            } else if arch == PeArch::Arm64 {
                // Windows on ARM64 platform register X18 points to TEB
                let _ = uc.reg_write(RegisterARM64::X18 as i32, TEB_ADDR);
            }
        } else {
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
        }

        // --- Static TLS, as the loader sets it up ---
        // TEB.ThreadLocalStoragePointer (+0x58 x64, +0x2C x86) -> array of blocks;
        // block 0 = the image's TLS template (StartAddressOfRawData..End) plus
        // SizeOfZeroFill zeros; *AddressOfIndex = 0. `thread_local` variables read
        // gs:[0x58][_tls_index]; without it they read through a null pointer.
        if matches!(arch, PeArch::X86 | PeArch::X64) {
            if let Some(tls) = self.sample.opt_header.data_directory.get(9).filter(|d| d.virtual_address != 0) {
                let w = if is_64 { 8usize } else { 4 };
                let rd = |uc: &Unicorn<'static, ()>, at: u64, n: usize| -> u64 {
                    let mut b = [0u8; 8];
                    let _ = uc.mem_read(at, &mut b[..n]);
                    u64::from_le_bytes(b)
                };
                let dir = image_base + tls.virtual_address as u64;
                let (start, end, index_at) = (rd(&uc, dir, w), rd(&uc, dir + w as u64, w), rd(&uc, dir + 2 * w as u64, w));
                let zero_fill = rd(&uc, dir + 4 * w as u64, 4);
                let template_len = end.saturating_sub(start).min(16 << 20);
                let block_len = template_len + zero_fill.min(16 << 20);
                let region = page_align(0x10 + block_len.max(1));
                if uc.mem_map(TLS_ADDR, region, Prot::READ | Prot::WRITE).is_ok() {
                    let block = TLS_ADDR + 0x10;
                    let _ = uc.mem_write(TLS_ADDR, &block.to_le_bytes()[..w]);
                    if let Ok(template) = uc.mem_read_as_vec(start, template_len as usize) {
                        let _ = uc.mem_write(block, &template);
                    }
                    let slot = TEB_ADDR + if is_64 { 0x58 } else { 0x2C };
                    let _ = uc.mem_write(slot, &TLS_ADDR.to_le_bytes()[..w]);
                    if index_at >= image_base {
                        let _ = uc.mem_write(index_at, &0u32.to_le_bytes());
                    }
                }
            }
        }

        // --- Map PEB ---
        let peb_size = page_align(0x1000);
        uc.mem_map(PEB_ADDR, peb_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map PEB: {:?}", e)))?;

        if is_64 {
            let peb = Peb64::new(image_base, LDR_ADDR);
            uc.mem_write(PEB_ADDR, &peb.to_bytes())
                .map_err(|e| UnpackerError::EmulatorError(format!("mem_write PEB: {:?}", e)))?;
        } else {
            let peb = Peb::new(image_base as u32, LDR_ADDR as u32);
            uc.mem_write(PEB_ADDR, &peb.to_bytes())
                .map_err(|e| UnpackerError::EmulatorError(format!("mem_write PEB: {:?}", e)))?;
        }

        // --- Map LDR ---
        // Up to the GDT page: PEB_LDR_DATA, one entry per module and their names.
        let ldr_size = GDT_ADDR - LDR_ADDR;
        uc.mem_map(LDR_ADDR, ldr_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map LDR: {:?}", e)))?;

        if is_64 {
            let peb_ldr = PebLdrData64::new(LDR_ADDR + 0x58);
            uc.mem_write(LDR_ADDR, &peb_ldr.to_bytes())
                .map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR: {:?}", e)))?;
        } else {
            let peb_ldr = PebLdrData::new((LDR_ADDR + 0x30) as u32);
            uc.mem_write(LDR_ADDR, &peb_ldr.to_bytes())
                .map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR: {:?}", e)))?;
        }

        // In 32-bit mode Unicorn ignores FS_BASE writes. Install a real FS
        // segment descriptor so fs:[0] addresses the TEB's ExceptionList.
        // Explicit flat 32-bit CS/SS/data descriptors also keep stack pushes
        // from wrapping through a default 16-bit SS cache.
        if arch == PeArch::X86 {
            uc.mem_map(GDT_ADDR, PAGE_SIZE, Prot::READ | Prot::WRITE)
                .map_err(|e| UnpackerError::EmulatorError(format!("mem_map GDT: {:?}", e)))?;
            let mut gdt = [0u8; 32];
            gdt[8..16].copy_from_slice(&x86_segment_descriptor(0, 0x000f_ffff, 0xfa, 0xc0));
            gdt[16..24].copy_from_slice(&x86_segment_descriptor(0, 0x000f_ffff, 0x92, 0xc0));
            gdt[24..32].copy_from_slice(&x86_segment_descriptor(TEB_ADDR as u32, 0x0fff, 0x92, 0x40));
            uc.mem_write(GDT_ADDR, &gdt)
                .map_err(|e| UnpackerError::EmulatorError(format!("mem_write GDT: {:?}", e)))?;
            let gdtr = unicorn_engine::unicorn_const::uc_x86_mmr {
                selector: 0,
                base: GDT_ADDR,
                limit: 31,
                flags: 0,
            };
            let gdtr_bytes = unsafe {
                std::slice::from_raw_parts(
                    (&gdtr as *const unicorn_engine::unicorn_const::uc_x86_mmr).cast::<u8>(),
                    std::mem::size_of_val(&gdtr),
                )
            };
            uc.reg_write_long(RegisterX86::GDTR, gdtr_bytes)
                .map_err(|e| UnpackerError::EmulatorError(format!("set GDTR: {:?}", e)))?;
            let cr0 = uc.reg_read(RegisterX86::CR0 as i32).unwrap_or(0);
            uc.reg_write(RegisterX86::CR0 as i32, cr0 | 1)
                .map_err(|e| UnpackerError::EmulatorError(format!("enable protected mode: {:?}", e)))?;
            for reg in [RegisterX86::SS, RegisterX86::DS, RegisterX86::ES, RegisterX86::GS] {
                uc.reg_write(reg as i32, 0x10)
                    .map_err(|e| UnpackerError::EmulatorError(format!("set data selector: {:?}", e)))?;
            }
            uc.reg_write(RegisterX86::FS as i32, 0x18)
                .map_err(|e| UnpackerError::EmulatorError(format!("set FS selector: {:?}", e)))?;
        }

        // --- Map stack above the reserved null page ---
        let stack_size = page_align(STACK_SIZE);
        uc.mem_map(STACK_ADDR, stack_size, Prot::READ | Prot::WRITE)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map stack: {:?}", e)))?;

        // --- KUSER_SHARED_DATA (0x7FFE0000 in every process, read-only) ---
        // ntdll's syscall stubs test SystemCall (+0x308; 0 = the `syscall` instruction)
        // and code reads the Windows version from here instead of calling an API.
        if uc.mem_map(0x7FFE_0000, 0x1000, Prot::READ).is_ok() {
            let mut shared = vec![0u8; 0x1000];
            shared[0x260..0x264].copy_from_slice(&19045u32.to_le_bytes()); // NtBuildNumber
            shared[0x26C..0x270].copy_from_slice(&10u32.to_le_bytes()); // NtMajorVersion
            // NtSystemRoot (WCHAR[260] at +0x30)
            let root: Vec<u8> = r"C:\Windows".encode_utf16().flat_map(u16::to_le_bytes).collect();
            shared[0x30..0x30 + root.len()].copy_from_slice(&root);
            let _ = uc.mem_write(0x7FFE_0000, &shared);
        }

        // --- Map hook memory ---
        let hook_mem_size = page_align(0x100000);
        uc.mem_map(HOOK_ADDR, hook_mem_size, Prot::ALL)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map hook: {:?}", e)))?;

        // --- Load system DLLs ---
        let dll_dir = system_dll_dir_for(is_64);

        let dll_names = ["kernel32.dll", "ntdll.dll", "KernelBase.dll"];
        let mut dll_bases: Vec<(String, u64, u32)> = Vec::new();

        for dll_name in &dll_names {
            let dll_path = dll_dir.join(dll_name);
            if dll_path.exists() {
                match load_dll_into_emu(&mut uc, dll_path.to_str().unwrap(), is_64) {
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

        // --- Syscall numbers of this ntdll (the `syscall` hook) ---
        if is_64 {
            self.hook_state.borrow_mut().syscall_names = syscall_table(&dll_dir.join("ntdll.dll"));
        }

        // --- Set up LDR entries: the image first, then ntdll, kernel32, KernelBase ---
        let ldr_entries_base = if is_64 { LDR_ADDR + 0x58 } else { LDR_ADDR + 0x30 };
        let mut modules = vec![("sample.exe".to_string(), image_base, self.sample.virtualmemorysize as u32)];
        for want in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
            modules.extend(dll_bases.iter().filter(|(n, _, _)| n.eq_ignore_ascii_case(want)).cloned());
        }
        let rest: Vec<_> = dll_bases.iter().filter(|(n, _, _)| !modules.iter().any(|(m, _, _)| m.eq_ignore_ascii_case(n))).cloned().collect();
        modules.extend(rest);
        setup_ldr_entries(&mut uc, LDR_ADDR, ldr_entries_base, GDT_ADDR, &modules, is_64)?;

        // --- Initialize registers ---
        let esp_val = STACK_START;
        let start_addr = entrypoint(&self.sample.opt_header);
        let entry_return = match arch {
            PeArch::X86 => Some((ENTRY_RETURN_ADDR as u32).to_le_bytes().to_vec()),
            PeArch::X64 => Some(ENTRY_RETURN_ADDR.to_le_bytes().to_vec()),
            _ => None,
        };
        if let Some(ret) = entry_return {
            uc.mem_write(esp_val, &ret)
                .map_err(|e| UnpackerError::EmulatorError(format!("write entry return address: {:?}", e)))?;
        }
        match arch {
            PeArch::X86 => {
                uc.reg_write(RegisterX86::ESP as i32, esp_val)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write ESP: {:?}", e)))?;
                uc.reg_write(RegisterX86::EBP as i32, esp_val)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write EBP: {:?}", e)))?;
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
            }
            PeArch::X64 => {
                uc.reg_write(RegisterX86::RSP as i32, esp_val)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RSP: {:?}", e)))?;
                uc.reg_write(RegisterX86::RBP as i32, esp_val)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RBP: {:?}", e)))?;
                uc.reg_write(RegisterX86::RAX as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RAX: {:?}", e)))?;
                uc.reg_write(RegisterX86::RBX as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RBX: {:?}", e)))?;
                uc.reg_write(RegisterX86::RCX as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RCX: {:?}", e)))?;
                uc.reg_write(RegisterX86::RDX as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RDX: {:?}", e)))?;
                uc.reg_write(RegisterX86::RSI as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RSI: {:?}", e)))?;
                uc.reg_write(RegisterX86::RDI as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RDI: {:?}", e)))?;
                uc.reg_write(RegisterX86::RIP as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write RIP: {:?}", e)))?;
            }
            PeArch::Arm32 => {
                uc.reg_write(RegisterARM::SP as i32, esp_val)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write SP: {:?}", e)))?;
                uc.reg_write(RegisterARM::PC as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write PC: {:?}", e)))?;
                uc.reg_write(RegisterARM::R0 as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write R0: {:?}", e)))?;
                uc.reg_write(RegisterARM::R1 as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write R1: {:?}", e)))?;
            }
            PeArch::Arm64 => {
                uc.reg_write(RegisterARM64::SP as i32, esp_val)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write SP: {:?}", e)))?;
                uc.reg_write(RegisterARM64::PC as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write PC: {:?}", e)))?;
                uc.reg_write(RegisterARM64::X0 as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write X0: {:?}", e)))?;
                uc.reg_write(RegisterARM64::X1 as i32, start_addr)
                    .map_err(|e| UnpackerError::EmulatorError(format!("reg_write X1: {:?}", e)))?;
            }
        }

        self.init_kernel_driver_env(&mut uc, arch, image_base, virtual_size as u64, start_addr, esp_val);

        // --- Store imported function info & patch IAT with hook addresses ---
        self.parse_and_patch_imports(&mut uc, image_base)?;
        if is_64 {
            self.redirect_dll_exports(&mut uc, &dll_dir, &dll_bases);
        }
        {
            let mut hs = self.hook_state.borrow_mut();
            hs.dllname_to_functionlist = self.sample.dllname_to_functionlist.clone();
            hs.is_64 = is_64;
            hs.api_state.is_64 = is_64;
            for (name, base, _) in &dll_bases {
                hs.api_state.dll_bases.insert(name.clone(), *base);
            }
        }

        // --- Register hooks ---
        let hook_state = Rc::clone(&self.hook_state);
        let hook_state2 = Rc::clone(&self.hook_state);
        let hook_state3 = Rc::clone(&self.hook_state);
        let hook_state4 = Rc::clone(&self.hook_state);
        let (api_lo, image_lo, image_hi) = {
            let hs = self.hook_state.borrow();
            (hs.hook_addr, hs.image_base, hs.image_base.saturating_add(hs.image_size.max(1)) - 1)
        };
        // API hook: a code hook over the patched-IAT stub region only. A code hook over
        // all memory ran this closure for every emulated instruction, most of the cost
        // of an emulation; the per-block work is in the block hook below.
        let code_hook = uc
            .add_code_hook(api_lo, api_lo + 0x100000 - 1, move |uc, addr, _size| {
                if addr == SEH_RETURN_ADDR || addr == SEH64_RETURN_ADDR || addr == ENTRY_RETURN_ADDR {
                    let _ = uc.emu_stop();
                    return;
                }
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

                drop(state);

                // Runs for every emulated instruction: one borrow, no clones.
                let stop = {
                    let mut guard = hook_state.borrow_mut();
                    let st = &mut *guard;
                    if addr >= st.hook_addr && addr < st.hook_addr + 0x100000 {
                        // API call via a patched IAT entry.
                        let (api_name_opt, dll_name_opt) = apicalls::resolve_api_and_dll(
                            addr,
                            &st.dllname_to_functionlist,
                        );
                        let api_name = api_name_opt.unwrap_or_else(|| format!("UnknownHook_{:#x}", addr));
                        let norm = apicalls::normalize_api_name(&api_name);

                        match st.apicall_counter.get_mut(&api_name) {
                            Some(c) => *c += 1,
                            None => {
                                st.apicall_counter.insert(api_name.clone(), 1);
                            }
                        }

                        if st.stops.apis.iter().any(|a| *a == norm) {
                            st.stop_hit = Some(StopHit::Api(api_name.clone(), addr));
                            true
                        } else if !st.trace_mode {
                            log::info!("API call: {}", api_name);
                            let is_add_veh = norm == "addvectoredexceptionhandler" || norm == "rtladdvectoredexceptionhandler";
                            let is_remove_veh = norm == "removevectoredexceptionhandler" || norm == "rtlremovevectoredexceptionhandler";
                            if is_add_veh || is_remove_veh {
                                if st.is_64 {
                                    if let Ok(rsp) = uc.reg_read(RegisterX86::RSP as i32) {
                                        let ret_addr = uc.mem_read_as_vec(rsp, 8)
                                            .ok().and_then(|b| <[u8; 8]>::try_from(b).ok())
                                            .map(u64::from_le_bytes).unwrap_or(0);
                                        let arg0 = uc.reg_read(RegisterX86::RCX as i32).unwrap_or(0);
                                        let arg1 = uc.reg_read(RegisterX86::RDX as i32).unwrap_or(0);
                                        let ret = apply_veh_call(st, is_add_veh, arg0, arg1);
                                        if ret_addr != 0 && !(ret_addr >= st.hook_addr && ret_addr < st.hook_addr + 0x100000) {
                                            let _ = uc.reg_write(RegisterX86::RAX as i32, ret);
                                            let _ = uc.reg_write(RegisterX86::RSP as i32, rsp + 8);
                                            let _ = uc.reg_write(RegisterX86::RIP as i32, ret_addr);
                                            false
                                        } else { true }
                                    } else { true }
                                } else if let Ok(esp) = uc.reg_read(RegisterX86::ESP as i32) {
                                    let rd32 = |a: u64| uc.mem_read_as_vec(a, 4).ok()
                                        .and_then(|b| <[u8; 4]>::try_from(b).ok())
                                        .map(u32::from_le_bytes).unwrap_or(0) as u64;
                                    let ret_addr = rd32(esp);
                                    let arg0 = rd32(esp + 4);
                                    let arg1 = if is_add_veh { rd32(esp + 8) } else { 0 };
                                    let pop = if is_add_veh { 12 } else { 8 };
                                    let ret = apply_veh_call(st, is_add_veh, arg0, arg1);
                                    if ret_addr != 0 && !(ret_addr >= st.hook_addr && ret_addr < st.hook_addr + 0x100000) {
                                        let _ = uc.reg_write(RegisterX86::EAX as i32, ret & 0xFFFF_FFFF);
                                        let _ = uc.reg_write(RegisterX86::ESP as i32, esp + pop);
                                        let _ = uc.reg_write(RegisterX86::EIP as i32, ret_addr);
                                        false
                                    } else { true }
                                } else { true }
                            } else { true }
                        } else {
                            let spec = apicalls::get_api_spec(&api_name).or_else(|| apicalls::get_ordinal_spec(&api_name, dll_name_opt.as_deref()));
                                let is_64 = st.is_64;
                                let hook_addr_base = st.hook_addr;

                                let (ret_addr, raw_args, pop_size, can_continue) = if !is_64 {
                                    // x86 calling convention
                                    if let Ok(esp) = uc.reg_read(RegisterX86::ESP as i32) {
                                        let mut ret_buf = [0u8; 4];
                                        let ret = if uc.mem_read(esp, &mut ret_buf).is_ok() {
                                            u32::from_le_bytes(ret_buf) as u64
                                        } else {
                                            0
                                        };

                                        let (arg_count, can_pop) = match spec {
                                            Some(s) => (s.arg_count, true),
                                            None => {
                                                // Unknown API: attempt call-site disassembly to count pushed arguments
                                                if let Some(count) = apicalls::estimate_x86_stdcall_arg_count(uc, ret) {
                                                    (count, true)
                                                } else if apicalls::is_cdecl_api(&api_name, dll_name_opt.as_deref()) {
                                                    // The caller cleans the stack: only the return address is popped.
                                                    (0, true)
                                                } else {
                                                    // Indeterminate push count: safe stop to prevent stack corruption
                                                    log::warn!("Indeterminate argument count for x86 API {}; stopping emulation safely", api_name);
                                                    (0, false)
                                                }
                                            }
                                        };

                                        if !can_pop {
                                            (ret, Vec::new(), 0, false)
                                        } else {
                                            let mut args = Vec::with_capacity(arg_count);
                                            for i in 0..arg_count {
                                                let arg_addr = esp + 4 * (i as u64 + 1);
                                                let mut arg_buf = [0u8; 4];
                                                let val = if uc.mem_read(arg_addr, &mut arg_buf).is_ok() {
                                                    u32::from_le_bytes(arg_buf) as u64
                                                } else {
                                                    0
                                                };
                                                args.push(val);
                                            }
                                            // Handle __cdecl (caller cleans stack, only pop return address) vs __stdcall
                                            let is_cdecl = apicalls::is_cdecl_api(&api_name, dll_name_opt.as_deref());
                                            let pop = if is_cdecl { 4 } else { 4 + (arg_count as u64) * 4 };
                                            (ret, args, pop, true)
                                        }
                                    } else {
                                        (0, Vec::new(), 0, false)
                                    }
                                } else {
                                    // x64 MS ABI (caller cleans stack)
                                    if let Ok(rsp) = uc.reg_read(RegisterX86::RSP as i32) {
                                        let mut ret_buf = [0u8; 8];
                                        let ret = if uc.mem_read(rsp, &mut ret_buf).is_ok() {
                                            u64::from_le_bytes(ret_buf)
                                        } else {
                                            0
                                        };
                                        let arg_count = spec.map(|s| s.arg_count).unwrap_or(4);
                                        let mut args = Vec::with_capacity(arg_count);
                                        for i in 0..arg_count {
                                            let val = match i {
                                                0 => uc.reg_read(RegisterX86::RCX as i32).unwrap_or(0),
                                                1 => uc.reg_read(RegisterX86::RDX as i32).unwrap_or(0),
                                                2 => uc.reg_read(RegisterX86::R8 as i32).unwrap_or(0),
                                                3 => uc.reg_read(RegisterX86::R9 as i32).unwrap_or(0),
                                                _ => {
                                                    let arg_addr = rsp + 0x28 + (i as u64 - 4) * 8;
                                                    let mut arg_buf = [0u8; 8];
                                                    if uc.mem_read(arg_addr, &mut arg_buf).is_ok() {
                                                        u64::from_le_bytes(arg_buf)
                                                    } else {
                                                        0
                                                    }
                                                }
                                            };
                                            args.push(val);
                                        }
                                        (ret, args, 8, true)
                                    } else {
                                        (0, Vec::new(), 0, false)
                                    }
                                };

                                let string_specs = spec.map(|s| s.string_args).unwrap_or(&[]);
                                let is_wide_hint = api_name.ends_with('w') || api_name.ends_with('W');
                                let mut formatted_args = Vec::with_capacity(raw_args.len());
                                let mut detected_strings = Vec::new();

                                for (idx, &arg_val) in raw_args.iter().enumerate() {
                                    let str_val = if let Some(&(_, str_type)) = string_specs.iter().find(|(i, _)| *i == idx) {
                                        match str_type {
                                            apicalls::StringType::Ansi => apicalls::read_ansi_string(uc, arg_val, 512),
                                            apicalls::StringType::Wide => apicalls::read_wide_string(uc, arg_val, 512),
                                        }
                                    } else if norm == "readfile" || norm == "writefile" || norm == "send" || norm == "recv" {
                                        // Do NOT probe string on raw file/network data buffers
                                        None
                                    } else {
                                        apicalls::probe_string_arg(uc, arg_val, is_wide_hint)
                                    };

                                    if let Some(ref s) = str_val {
                                        detected_strings.push(s.clone());
                                        // Bound argument string length in trace (512 characters)
                                        if s.len() > 512 {
                                            let mut tr: String = s.chars().take(509).collect();
                                            tr.push_str("...");
                                            formatted_args.push(tr);
                                        } else {
                                            formatted_args.push(s.clone());
                                        }
                                    } else {
                                        formatted_args.push(format!("{:#x}", arg_val));
                                    }
                                }

                                // Check process termination APIs:
                                // Only halt emulation if terminating the current process ((target_h & 0xFFFFFFFF) == 0xFFFFFFFF || target_h == u64::MAX).
                                // In Windows, NULL handle (0) is invalid (ERROR_INVALID_HANDLE) and cannot terminate the process; emulation continues.
                                let is_terminate = norm == "terminateprocess";
                                let target_h = raw_args.first().copied().unwrap_or(0);
                                let is_self_termination = !is_terminate || (target_h & 0xFFFFFFFF) == 0xFFFFFFFF || target_h == u64::MAX;

                                if norm == "exitprocess" || norm == "corlexitprocess" || norm == "exitthread" || norm == "exit" || norm == "quick_exit" || norm == "abort" || (is_terminate && is_self_termination) {
                                    st.behavior_trace.calls.push(ApiCall {
                                        api: api_name.clone(),
                                        args: formatted_args.clone(),
                                        ret: 0,
                                    });
                                    log::info!("API [trace]: {} called -> terminating emulation cleanly", api_name);
                                    st.api_end = Some(EmuEnd::Exited);
                                    true
                                } else if !can_continue
                                    || ret_addr == 0
                                    || (ret_addr >= hook_addr_base
                                        && ret_addr < hook_addr_base + 0x100000
                                        // A CRT frame handler (`_except_handler3`) called by the
                                        // SEH dispatch returns to its sentinel, which ends the dispatch.
                                        && ret_addr != SEH_RETURN_ADDR
                                        && ret_addr != SEH64_RETURN_ADDR)
                                {
                                    log::warn!("Cannot continue from return address {:#x} for API {}, stopping emulation", ret_addr, api_name);
                                    st.api_end = Some(EmuEnd::Stopped);
                                    let why = if !can_continue {
                                        "stack unreadable"
                                    } else if ret_addr == 0 {
                                        "returns to 0"
                                    } else {
                                        "returns into an API stub"
                                    };
                                    st.stop_api = Some(format!("{api_name} ({why})"));
                                    true
                                } else {
                                    // Execute stub logic with dllname_to_functionlist
                                    let mut ret_val = apicalls::handle_api_call(
                                        uc,
                                        &api_name,
                                        &raw_args,
                                        &mut st.api_state,
                                        &mut st.dllname_to_functionlist,
                                    );

                                    // Model Windows VEH registration in-process (both x86 and x64, including
                                    // handlers inside VirtualAlloc'd regions).
                                    if norm == "addvectoredexceptionhandler" || norm == "rtladdvectoredexceptionhandler" {
                                        let arg0 = raw_args.first().copied().unwrap_or(0);
                                        let arg1 = raw_args.get(1).copied().unwrap_or(0);
                                        ret_val = apply_veh_call(st, true, arg0, arg1);
                                    } else if norm == "removevectoredexceptionhandler" || norm == "rtlremovevectoredexceptionhandler" {
                                        let handle = raw_args.first().copied().unwrap_or(0);
                                        ret_val = apply_veh_call(st, false, handle, 0);
                                    }

                                    // Categorize behavior trace with deduplication
                                    const MAX_CATEGORY_ITEMS: usize = 5000;
                                    if norm.starts_with("createfile") {
                                        if let Some((p, is_write)) = st.api_state.file_handles.get(&ret_val) {
                                            if *is_write {
                                                if !st.behavior_trace.files_written.contains(p) && st.behavior_trace.files_written.len() < MAX_CATEGORY_ITEMS {
                                                    st.behavior_trace.files_written.push(p.clone());
                                                }
                                            } else {
                                                if !st.behavior_trace.files_read.contains(p) && st.behavior_trace.files_read.len() < MAX_CATEGORY_ITEMS {
                                                    st.behavior_trace.files_read.push(p.clone());
                                                }
                                            }
                                        }
                                    } else if norm == "readfile" {
                                        let h = raw_args.first().copied().unwrap_or(0);
                                        if let Some((p, _)) = st.api_state.file_handles.get(&h) {
                                            if !st.behavior_trace.files_read.contains(p) && st.behavior_trace.files_read.len() < MAX_CATEGORY_ITEMS {
                                                st.behavior_trace.files_read.push(p.clone());
                                            }
                                        }
                                    } else if norm == "writefile" {
                                        let h = raw_args.first().copied().unwrap_or(0);
                                        if let Some((p, _)) = st.api_state.file_handles.get(&h) {
                                            if !st.behavior_trace.files_written.contains(p) && st.behavior_trace.files_written.len() < MAX_CATEGORY_ITEMS {
                                                st.behavior_trace.files_written.push(p.clone());
                                            }
                                        }
                                    } else if norm == "connect" || norm == "wsaconnect" {
                                        let sockaddr_ptr = raw_args.get(1).copied().unwrap_or(0);
                                        let namelen = raw_args.get(2).copied().unwrap_or(16) as usize;
                                        if let Some((ip, port)) = apicalls::parse_sockaddr(uc, sockaddr_ptr, namelen) {
                                            let endpoint = apicalls::format_endpoint(&st.api_state, ip, port);
                                            if !st.behavior_trace.network_targets.contains(&endpoint) && st.behavior_trace.network_targets.len() < MAX_CATEGORY_ITEMS {
                                                st.behavior_trace.network_targets.push(endpoint.clone());
                                            }
                                            if formatted_args.len() > 1 {
                                                formatted_args[1] = format!("{:#x} ({})", sockaddr_ptr, endpoint);
                                            }
                                        }
                                    } else if norm.starts_with("getaddrinfo") {
                                        // Only add the resolved hostname (node name) to network_targets, NOT the service/port string
                                        let node_ptr = raw_args.get(0).copied().unwrap_or(0);
                                        let node_name = if norm.ends_with('w') {
                                            apicalls::read_wide_string(uc, node_ptr, 512)
                                        } else {
                                            apicalls::read_ansi_string(uc, node_ptr, 512)
                                        };
                                        if let Some(node) = node_name {
                                            if !st.behavior_trace.network_targets.contains(&node) && st.behavior_trace.network_targets.len() < MAX_CATEGORY_ITEMS {
                                                st.behavior_trace.network_targets.push(node);
                                            }
                                        }
                                    } else {
                                        for s in &detected_strings {
                                            if norm.starts_with("findfirstfile") {
                                                if !st.behavior_trace.files_read.contains(s) && st.behavior_trace.files_read.len() < MAX_CATEGORY_ITEMS {
                                                    st.behavior_trace.files_read.push(s.clone());
                                                }
                                            } else if norm.starts_with("deletefile")
                                                || norm.starts_with("movefile")
                                                || norm.starts_with("copyfile")
                                            {
                                                if !st.behavior_trace.files_written.contains(s) && st.behavior_trace.files_written.len() < MAX_CATEGORY_ITEMS {
                                                    st.behavior_trace.files_written.push(s.clone());
                                                }
                                            } else if norm.starts_with("reg") {
                                                if !st.behavior_trace.registry.contains(s) && st.behavior_trace.registry.len() < MAX_CATEGORY_ITEMS {
                                                    st.behavior_trace.registry.push(s.clone());
                                                }
                                            } else if norm.starts_with("createprocess")
                                                || norm.starts_with("shellexecute")
                                                || norm.starts_with("winexec")
                                            {
                                                if !st.behavior_trace.processes.contains(s) && st.behavior_trace.processes.len() < MAX_CATEGORY_ITEMS {
                                                    st.behavior_trace.processes.push(s.clone());
                                                }
                                            } else if norm.starts_with("winhttp")
                                                || norm.starts_with("internet")
                                                || norm.starts_with("urldownload")
                                                || norm.starts_with("gethostbyname")
                                            {
                                                if !st.behavior_trace.network_targets.contains(s) && st.behavior_trace.network_targets.len() < MAX_CATEGORY_ITEMS {
                                                    st.behavior_trace.network_targets.push(s.clone());
                                                }
                                            }
                                        }
                                    }

                                    // Record trace entry (bounded by call count and total payload budget)
                                    const MAX_TRACE_CALLS: usize = 20_000;
                                    const MAX_TRACE_BYTES: usize = 2 * 1024 * 1024; // 2 MB budget
                                    let call_size = api_name.len() + formatted_args.iter().map(|s| s.len()).sum::<usize>() + 16;
                                    if st.behavior_trace.calls.len() >= MAX_TRACE_CALLS || st.trace_bytes + call_size > MAX_TRACE_BYTES {
                                        st.behavior_trace.truncated = true;
                                    } else {
                                        st.trace_bytes += call_size;
                                        st.behavior_trace.calls.push(ApiCall {
                                            api: api_name.clone(),
                                            args: formatted_args.clone(),
                                            ret: ret_val,
                                        });
                                    }

                                    log::info!(
                                        "API [trace]: {}({}) -> {:#x}",
                                        api_name,
                                        formatted_args.join(", "),
                                        ret_val
                                    );

                                    // Fix stack and set instruction pointer to return address
                                    if !is_64 {
                                        let _ = uc.reg_write(RegisterX86::EAX as i32, ret_val & 0xFFFFFFFF);
                                        if let Ok(esp) = uc.reg_read(RegisterX86::ESP as i32) {
                                            let _ = uc.reg_write(RegisterX86::ESP as i32, esp + pop_size);
                                        }
                                        let _ = uc.reg_write(RegisterX86::EIP as i32, ret_addr);
                                    } else {
                                        let _ = uc.reg_write(RegisterX86::RAX as i32, ret_val);
                                        if let Ok(rsp) = uc.reg_read(RegisterX86::RSP as i32) {
                                            let _ = uc.reg_write(RegisterX86::RSP as i32, rsp + pop_size);
                                        }
                                        let _ = uc.reg_write(RegisterX86::RIP as i32, ret_addr);
                                    }

                                    false // Continue emulation from return address!
                                }
                            }
                    } else {
                        false
                    }
                };
                if stop {
                    let _ = uc.emu_stop();
                }
            })
            .map_err(|e| UnpackerError::EmulatorError(format!("add_code_hook: {:?}", e)))?;

        self.hook_ids.push(code_hook);

        // Block hook: once per basic block instead of once per instruction. Stops,
        // per-section execution (bytes) and write-execute: a block that runs code from
        // a page this run wrote is unpacked / self-modifying code.
        let block_hook = uc
            .add_block_hook(1, 0, move |uc, addr, size| {
                if addr == SEH_RETURN_ADDR || addr == SEH64_RETURN_ADDR || addr == ENTRY_RETURN_ADDR {
                    let _ = uc.emu_stop();
                    return;
                }
                let stop = {
                    let mut guard = hook_state4.borrow_mut();
                    let st = &mut *guard;
                    let end = addr + (size as u64).max(1);
                    st.blocks_seen = st.blocks_seen.wrapping_add(1);
                    st.total_blocks = st.total_blocks.wrapping_add(1);
                    let out_of_time = st.blocks_seen & 255 == 0 && st.deadline.is_some_and(|d| Instant::now() >= d);
                    let (n, indirect) = match st.block_insns.get(&(addr, size)) {
                        Some(&entry) => entry,
                        None => {
                            let entry = analyze_block_insns(uc, addr, size, st.is_64);
                            st.block_insns.insert((addr, size), entry);
                            entry
                        }
                    };
                    if indirect {
                        st.vm_indirect_blocks = st.vm_indirect_blocks.wrapping_add(1);
                    }
                    let out_of_budget = st.insn_budget > 0 && st.insn_count >= st.insn_budget;
                    st.insn_count += n as u64;
                    if out_of_time || out_of_budget || addr >= st.unpacker.endaddr || st.breakpoints.iter().any(|&b| b >= addr && b < end) {
                        true
                    } else if addr >= st.hook_addr && addr < st.hook_addr + 0x100000 {
                        false // API stubs: the code hook handles them
                    } else {
                        let idx = section_index(&st.sample_sections, st.image_base, addr);
                        if let Some(i) = idx {
                            st.section_exec_bytes[i] += size as u64;
                        }
                        let wx_page = if st.written_pages.is_empty() {
                            None
                        } else {
                            ((addr >> 12)..=((end - 1) >> 12)).find(|p| st.written_pages.contains(p))
                        };
                        if let Some(page) = wx_page {
                            if st.wx_hit.is_none() {
                                st.wx_hit = Some(addr.max(page << 12));
                            }
                            let in_image = addr >= st.image_base && addr < st.image_base.saturating_add(st.image_size);
                            if !in_image && st.wx_alloc_hit.is_none() {
                                st.wx_alloc_hit = Some(addr.max(page << 12));
                            }
                        }
                        let hit = if idx.is_some_and(|i| st.stop_outside.contains(&i)) {
                            None
                        } else if st.stops.write_execute && wx_page.is_some() {
                            Some(StopHit::WriteExecute(addr))
                        } else if let Some(i) = idx.filter(|i| st.stop_sections.contains(i)) {
                            Some(StopHit::Section(st.sample_sections[i].name.clone(), addr))
                        } else if !st.stops.patterns.is_empty() {
                            let longest = st.stops.patterns.iter().map(Vec::len).max().unwrap_or(0);
                            let head = uc.mem_read_as_vec(addr, longest).unwrap_or_default();
                            st.stops
                                .patterns
                                .iter()
                                .any(|p| head.len() >= p.len() && p.iter().zip(&head).all(|(b, h)| b.matches(*h)))
                                .then_some(StopHit::Pattern(addr))
                        } else {
                            None
                        };
                        if hit.is_some() {
                            st.stop_hit = hit;
                            true
                        } else if st.unpacker.write_execute_control && wx_page.is_some() {
                            log::warn!("Write-execute at {:#x}", addr);
                            true
                        } else if st.unpacker.section_hopping_control
                            && !idx.is_some_and(|i| st.unpacker.allowed_sections.iter().any(|n| *n == st.sample_sections[i].name))
                            && !st.unpacker.allowed_addr_ranges.iter().any(|&(lo, hi)| addr >= lo && addr < hi)
                        {
                            log::warn!("Section hopping detected at {:#x}, stopping", addr);
                            true
                        } else {
                            false
                        }
                    }
                };
                if stop {
                    let _ = uc.emu_stop();
                }
            })
            .map_err(|e| UnpackerError::EmulatorError(format!("add_block_hook: {:?}", e)))?;

        self.hook_ids.push(block_hook);

        // Memory hook: writes inside the image only. Reads were hooked too, over all
        // memory (stack, DLLs), for counters nothing used; every emulated load paid
        // for a callback.
        let mem_access_hook = uc
            .add_mem_hook(
                UcHookType::MEM_WRITE,
                image_lo,
                image_hi,
                move |_uc, mem_type, addr, size, _value| {
                    let mut guard = hook_state2.borrow_mut();
                    let st = &mut *guard;
                    let Some(i) = section_index(&st.sample_sections, st.image_base, addr) else {
                        return true;
                    };
                    let is_write = matches!(mem_type, MemType::WRITE);
                    if is_write {
                        st.section_write_bytes[i] += size as u64;
                        if st.sample_sections[i].characteristics & 0x2000_0000 != 0 {
                            st.last_code_write = st.insn_count.max(1);
                        }
                        let first = addr >> 12;
                        let last = (addr + (size as u64).max(1) - 1) >> 12;
                        for page in first..=last {
                            st.written_pages.insert(page);
                        }
                    }

                    // Check memory breakpoints
                    for &(bp_start, bp_end) in &st.mem_breakpoints {
                        if addr >= bp_start && addr < bp_end {
                            return false; // stop emulation
                        }
                    }

                    true
                },
            )
            .map_err(|e| UnpackerError::EmulatorError(format!("add_mem_access_hook: {:?}", e)))?;

        self.hook_ids.push(mem_access_hook);

        // Writes into the VirtualAlloc / heap area: a crypter that decrypts its
        // payload into allocated memory and jumps there is a write-execute too.
        let hook_state_alloc = Rc::clone(&self.hook_state);
        let alloc_write_hook = uc
            .add_mem_hook(UcHookType::MEM_WRITE, apicalls::ALLOC_BASE, apicalls::ALLOC_END - 1, move |_uc, _mem_type, addr, size, _value| {
                let mut st = hook_state_alloc.borrow_mut();
                for page in addr >> 12..=(addr + (size as u64).max(1) - 1) >> 12 {
                    st.written_pages.insert(page);
                }
                st.last_code_write = st.insn_count.max(1);
                true
            })
            .map_err(|e| UnpackerError::EmulatorError(format!("add_mem_hook (allocations): {:?}", e)))?;
        self.hook_ids.push(alloc_write_hook);

        // Invalid memory hook
        let invalid_mem_hook = uc
            .add_mem_hook(
                UcHookType::MEM_READ_UNMAPPED
                    | UcHookType::MEM_WRITE_UNMAPPED
                    | UcHookType::MEM_FETCH_UNMAPPED
                    | UcHookType::MEM_READ_PROT
                    | UcHookType::MEM_WRITE_PROT
                    | UcHookType::MEM_FETCH_PROT,
                0,
                u64::MAX,
                move |uc, mem_type, addr, _size, _value| {
                    {
                        let mut st = hook_state3.borrow_mut();
                        if st.map_on_fault && st.faults < 512 {
                            st.faults += 1;
                            drop(st);
                            let page = addr & !0xfff;
                            if uc.mem_map(page, 0x1000, Prot::ALL).is_ok() {
                                return true;
                            }
                        }
                    }
                    if let Ok(mut st) = hook_state3.try_borrow_mut() {
                        {
                            let access = match mem_type {
                                MemType::WRITE_UNMAPPED | MemType::WRITE_PROT => 1,
                                MemType::FETCH_UNMAPPED | MemType::FETCH_PROT => 8,
                                _ => 0,
                            };
                            let instruction = if st.is_64 { uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0) } else { uc.reg_read(RegisterX86::EIP as i32).unwrap_or(0) };
                            st.seh_fault = Some(SehFault { code: 0xc0000005, address: addr, access, instruction });
                            st.last_fault = Some(MemFault { address: addr, instruction, access });
                        }
                    }
                    let eip = uc.reg_read(RegisterX86::EIP as i32).unwrap_or(0);
                    let esp = uc.reg_read(RegisterX86::ESP as i32).unwrap_or(0);
                    log::error!("Invalid memory access at {:#x} (EIP={:#x}, ESP={:#x})", addr, eip, esp);
                    false
                },
            )
            .map_err(|e| UnpackerError::EmulatorError(format!("add_mem_invalid_hook: {:?}", e)))?;

        self.hook_ids.push(invalid_mem_hook);

        {
            let intr_state = Rc::clone(&self.hook_state);
            let intr_hook = uc.add_intr_hook(move |uc, interrupt| {
                let (code, subtract_one, clear_tf) = match interrupt {
                    0 => (0xC000_0094u32, false, false), // EXCEPTION_INT_DIVIDE_BY_ZERO
                    1 => (0x8000_0004u32, false, true),  // EXCEPTION_SINGLE_STEP
                    3 => (0x8000_0003u32, true, false),  // EXCEPTION_BREAKPOINT
                    4 => (0xC000_0095u32, false, false), // EXCEPTION_INT_OVERFLOW
                    6 => (0xC000_001Du32, false, false), // EXCEPTION_ILLEGAL_INSTRUCTION
                    13 => (0xC000_0096u32, false, false), // EXCEPTION_PRIVILEGED_INSTRUCTION
                    _ => return,
                };
                if clear_tf {
                    if let Ok(eflags) = uc.reg_read(RegisterX86::EFLAGS as i32) {
                        let _ = uc.reg_write(RegisterX86::EFLAGS as i32, eflags & !0x100);
                    }
                }
                if let Ok(mut st) = intr_state.try_borrow_mut() {
                    let mut ip = if st.is_64 {
                        uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0)
                    } else {
                        uc.reg_read(RegisterX86::EIP as i32).unwrap_or(0)
                    };
                    if subtract_one {
                        ip = ip.saturating_sub(1);
                    }
                    st.seh_fault = Some(SehFault { code, address: ip, access: 0, instruction: ip });
                }
                let _ = uc.emu_stop();
            })
            .map_err(|e| UnpackerError::EmulatorError(format!("add_intr_hook: {:?}", e)))?;
            self.hook_ids.push(intr_hook);

            // Direct and indirect syscalls (a `syscall` in the sample, or the one in an
            // ntdll stub it jumps to): RAX is the number, the arguments are R10, RDX, R8,
            // R9 and the stack above the return address and shadow space. The `Nt`
            // function is answered like the API it stands for; NTSTATUS goes to RAX.
            if is_64 {
                let sys_state = Rc::clone(&self.hook_state);
                let sys_hook = uc
                    .add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, move |uc| {
                        let Ok(mut st) = sys_state.try_borrow_mut() else { return };
                        let reg = |uc: &Unicorn<'_, ()>, r: RegisterX86| uc.reg_read(r as i32).unwrap_or(0);
                        let ssn = reg(uc, RegisterX86::RAX) as u32;
                        let rsp = reg(uc, RegisterX86::RSP);
                        let mut args = vec![reg(uc, RegisterX86::R10), reg(uc, RegisterX86::RDX), reg(uc, RegisterX86::R8), reg(uc, RegisterX86::R9)];
                        for i in 0..8u64 {
                            let mut b = [0u8; 8];
                            let v = if uc.mem_read(rsp + 0x28 + i * 8, &mut b).is_ok() { u64::from_le_bytes(b) } else { 0 };
                            args.push(v);
                        }
                        let name = st.syscall_names.get(&ssn).cloned().unwrap_or_else(|| format!("syscall_{ssn:#x}"));
                        let st = &mut *st;
                        let ret = if name.starts_with("syscall_") {
                            0xC000_0002 // STATUS_NOT_IMPLEMENTED
                        } else {
                            apicalls::handle_api_call(uc, &name, &args, &mut st.api_state, &mut st.dllname_to_functionlist)
                        };
                        if st.behavior_trace.calls.len() < 100_000 {
                            st.behavior_trace.calls.push(ApiCall {
                                api: format!("{name} (syscall {ssn:#x})"),
                                args: args.iter().take(6).map(|a| format!("{a:#x}")).collect(),
                                ret,
                            });
                        }
                        let _ = uc.reg_write(RegisterX86::RAX as i32, ret);
                    })
                    .map_err(|e| UnpackerError::EmulatorError(format!("add_insn_sys_hook: {:?}", e)))?;
                self.hook_ids.push(sys_hook);
            }

            let invalid_state = Rc::clone(&self.hook_state);
            let invalid_instruction_hook = uc.add_insn_invalid_hook(move |uc| {
                if let Ok(mut st) = invalid_state.try_borrow_mut() {
                    let ip = if st.is_64 { uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0) } else { uc.reg_read(RegisterX86::EIP as i32).unwrap_or(0) };
                    st.seh_fault = Some(SehFault { code: 0xc000001d, address: 0, access: 0, instruction: ip });
                }
                false
            })
            .map_err(|e| UnpackerError::EmulatorError(format!("add_insn_invalid_hook: {:?}", e)))?;
            self.hook_ids.push(invalid_instruction_hook);
        }

        self.uc = Some(uc);
        Ok(())
    }

    /// The Unicorn instance after `init_uc`, for callers that add their own hooks
    /// (the disinfector) or read emulated memory after `emu`.
    pub fn unicorn_mut(&mut self) -> Option<&mut Unicorn<'static, ()>> {
        self.uc.as_mut()
    }

    // ------------------------------------------------------------------
    // emu — start the emulator
    // ------------------------------------------------------------------

    pub fn emu(&mut self) -> UnpackerResult<()> {
        let ep = entrypoint(&self.sample.opt_header);
        self.emu_from(ep, 30 * SECOND_SCALE, 0)
    }

    pub fn emu_for(&mut self, limit: std::time::Duration) -> UnpackerResult<()> {
        let ep = entrypoint(&self.sample.opt_header);
        let us = (limit.as_micros() as u64).clamp(1, 30 * SECOND_SCALE as u64);
        self.emu_from(ep, us, 0)
    }

    /// Stop on write-execute (self-modifying code) and/or on leaving the
    /// allowed sections. Call after `init_uc`, before `emu` / `emu_from`.
    pub fn set_controls(&mut self, write_execute: bool, section_hopping: bool) {
        let mut hs = self.hook_state.borrow_mut();
        hs.unpacker.write_execute_control = write_execute;
        hs.unpacker.section_hopping_control = section_hopping;
    }

    /// Stop once execution reaches `end` or beyond (the packer configs stop at
    /// image base + 0x10000; an appended virus body lies far past that).
    pub fn set_end_addr(&mut self, end: u64) {
        self.hook_state.borrow_mut().unpacker.endaddr = end;
    }

    pub(crate) fn swap_run_limits(&mut self, endaddr: u64, write_exec: bool, sec_hop: bool) -> (u64, bool, bool) {
        let mut hs = self.hook_state.borrow_mut();
        let prev = (
            hs.unpacker.endaddr,
            hs.unpacker.write_execute_control,
            hs.unpacker.section_hopping_control,
        );
        hs.unpacker.endaddr = endaddr;
        hs.unpacker.write_execute_control = write_exec;
        hs.unpacker.section_hopping_control = sec_hop;
        prev
    }

    /// Conditions the next runs stop on (`stop_hit` says which one); `Stops::default()`
    /// clears them. Section names not in the image are ignored.
    pub fn set_stops(&mut self, stops: Stops) {
        let mut hs = self.hook_state.borrow_mut();
        let indices = |names: &[String]| -> Vec<usize> {
            hs.sample_sections
                .iter()
                .enumerate()
                .filter(|(_, s)| names.iter().any(|n| n.eq_ignore_ascii_case(&s.name)))
                .map(|(i, _)| i)
                .collect()
        };
        let (sections, outside) = (indices(&stops.sections), indices(&stops.outside));
        hs.stop_sections = sections;
        hs.stop_outside = outside;
        hs.stops = Stops { apis: stops.apis.iter().map(|a| apicalls::normalize_api_name(a)).collect(), ..stops };
    }

    /// The instruction pointer (x86 / x64).
    pub fn ip(&self) -> Option<u64> {
        let reg = if self.hook_state.borrow().is_64 { RegisterX86::RIP } else { RegisterX86::EIP };
        self.uc.as_ref()?.reg_read(reg as i32).ok()
    }

    /// The first `n` arguments of a call stopped at its API stub (before the
    /// call ran): x86 stdcall / cdecl from the stack above the return address,
    /// x64 from RCX, RDX, R8, R9 and the stack. Unreadable ones are 0.
    pub fn api_args(&self, n: usize) -> Vec<u64> {
        let Some(uc) = self.uc.as_ref() else { return vec![0; n] };
        let is_64 = self.hook_state.borrow().is_64;
        let stack = |addr: u64, size: usize| -> u64 {
            let mut b = [0u8; 8];
            if uc.mem_read(addr, &mut b[..size]).is_ok() { u64::from_le_bytes(b) } else { 0 }
        };
        (0..n)
            .map(|i| {
                if is_64 {
                    match i {
                        0 => uc.reg_read(RegisterX86::RCX as i32).unwrap_or(0),
                        1 => uc.reg_read(RegisterX86::RDX as i32).unwrap_or(0),
                        2 => uc.reg_read(RegisterX86::R8 as i32).unwrap_or(0),
                        3 => uc.reg_read(RegisterX86::R9 as i32).unwrap_or(0),
                        _ => stack(uc.reg_read(RegisterX86::RSP as i32).unwrap_or(0) + 0x28 + (i as u64 - 4) * 8, 8),
                    }
                } else {
                    stack(uc.reg_read(RegisterX86::ESP as i32).unwrap_or(0) + 4 * (i as u64 + 1), 4)
                }
            })
            .collect()
    }

    /// `len` bytes of emulated memory at `addr`.
    pub fn read_mem(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        self.uc.as_ref()?.mem_read_as_vec(addr, len).ok()
    }

    pub fn is_64(&self) -> bool {
        self.hook_state.borrow().is_64
    }

    pub fn set_ip(&mut self, ip: u64) -> bool {
        let reg = if self.hook_state.borrow().is_64 { RegisterX86::RIP } else { RegisterX86::EIP };
        self.uc.as_mut().is_some_and(|uc| uc.reg_write(reg as i32, ip).is_ok())
    }

    /// Calls the function at `va` with `args` and emulates until it returns: x64 in
    /// RCX, RDX, R8, R9 and the stack above the shadow space, x86 on the stack. The
    /// frame is built below the current stack pointer, with the entry point's return
    /// address, so the return ends the run (`EmuEnd::EntryReturned`). Returns RAX / EAX,
    /// or why the function did not return.
    pub fn call_function(&mut self, va: u64, args: &[u64], timeout_us: u64, count: usize) -> Result<u64, String> {
        let is_64 = self.is_64();
        let uc = self.uc.as_mut().ok_or("engine not initialized")?;
        let (sp_reg, ax) = if is_64 { (RegisterX86::RSP, RegisterX86::RAX) } else { (RegisterX86::ESP, RegisterX86::EAX) };
        let sp = uc.reg_read(sp_reg as i32).map_err(|e| format!("{e:?}"))?;
        // Room for the frames the function builds above ours, aligned as at a call.
        let base = (sp.saturating_sub(0x1000)) & !0xF;
        let word = if is_64 { 8 } else { 4 };
        let put = |uc: &mut Unicorn<'static, ()>, at: u64, v: u64| uc.mem_write(at, &v.to_le_bytes()[..word as usize]).map_err(|e| format!("{e:?}"));
        if is_64 {
            for (i, &a) in args.iter().enumerate().skip(4) {
                put(uc, base + 0x20 + (i as u64 - 4) * 8, a)?;
            }
            for (i, reg) in [RegisterX86::RCX, RegisterX86::RDX, RegisterX86::R8, RegisterX86::R9].into_iter().enumerate() {
                uc.reg_write(reg as i32, args.get(i).copied().unwrap_or(0)).map_err(|e| format!("{e:?}"))?;
            }
        } else {
            for (i, &a) in args.iter().enumerate() {
                put(uc, base + i as u64 * 4, a)?;
            }
        }
        let entry_sp = base - word;
        put(uc, entry_sp, ENTRY_RETURN_ADDR)?;
        uc.reg_write(sp_reg as i32, entry_sp).map_err(|e| format!("{e:?}"))?;
        let run = self.emu_from(va, timeout_us, count);
        if self.end != EmuEnd::EntryReturned {
            let at = self.ip().unwrap_or(0);
            return Err(match run {
                Err(e) => format!("{e} at {at:#x}"),
                Ok(()) => format!("{:?} at {at:#x} before the function returned", self.end),
            });
        }
        let uc = self.uc.as_ref().ok_or("engine not initialized")?;
        uc.reg_read(ax as i32).map_err(|e| format!("{e:?}"))
    }

    /// Map zeroed pages on unmapped accesses instead of stopping (at most 512).
    pub fn set_map_on_fault(&mut self, on: bool) {
        self.hook_state.borrow_mut().map_on_fault = on;
    }

    /// Emulate from `start` (absolute address) for at most `timeout_us`
    /// microseconds and `count` instructions (0 = no limit).
    pub fn emu_from(&mut self, start: u64, timeout_us: u64, count: usize) -> UnpackerResult<()> {
        let uc = self
            .uc
            .as_mut()
            .ok_or_else(|| UnpackerError::EmulatorError("engine not initialized".into()))?;

        let ep = start;
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
            hs.trace_mode = self.trace_mode;
            hs.start_time = self.start_time;
            // Unicorn's own time limit starts a timer thread at every emu_start that
            // polls with usleep(2) and is joined at the end: on Windows each sleep is a
            // scheduler tick (~15 ms), so every run cost at least 15-30 ms and every
            // SEH re-run as much again (a 2 KB DLL with 32 exceptions took a second).
            // The limit is checked in the block hook instead, for the whole run.
            hs.deadline = (timeout_us > 0).then(|| Instant::now() + std::time::Duration::from_micros(timeout_us));
            hs.blocks_seen = 0;
            // The instruction budget, for the whole run like the time limit.
            hs.insn_budget = count as u64;
            hs.insn_count = 0;
            hs.last_code_write = 0;
            hs.last_fault = None;
            hs.api_end = None;
            hs.stop_api = None;
            hs.stop_hit = None;
        }

        let mut run_from = ep;
        let mut result: Result<(), uc_error> = Ok(());
        let mut first = true;
        loop {
            // An SEH re-run starts only while the run's time is not used up.
            if !std::mem::take(&mut first) && self.hook_state.borrow().deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
            result = uc.emu_start(run_from, end_addr, 0, 0);
            let x64 = self.hook_state.borrow().is_64;
            let sentinel = if x64 { uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0) == SEH64_RETURN_ADDR } else { uc.reg_read(RegisterX86::EIP as i32).unwrap_or(0) == SEH_RETURN_ADDR };
            if sentinel {
                let next = if x64 { finish_x64_seh(uc, &self.hook_state) } else { finish_x86_seh(uc, &self.hook_state) };
                match next {
                    Some(next_ip) => { run_from = next_ip; continue; }
                    None => break,
                }
            }
            let fault = self.hook_state.borrow_mut().seh_fault.take();
            if let Some(fault) = fault {
                let next = if x64 { begin_x64_seh(uc, &self.hook_state, fault) } else { begin_x86_seh(uc, &self.hook_state, fault) };
                match next {
                    Some(handler) => { run_from = handler; continue; }
                    None => break,
                }
            }
            break;
        }

        // Sync back results
        {
            let hs = self.hook_state.borrow();
            let by_name = |counts: &[u64]| -> HashMap<String, u64> {
                let mut m = HashMap::new();
                for (s, &n) in hs.sample_sections.iter().zip(counts) {
                    if n > 0 {
                        *m.entry(s.name.clone()).or_insert(0) += n;
                    }
                }
                m
            };
            self.sections_written = by_name(&hs.section_write_bytes);
            self.sections_executed = by_name(&hs.section_exec_bytes);
            // Written pages as merged [start, end) address ranges.
            let mut pages: Vec<u64> = hs.written_pages.iter().copied().collect();
            pages.sort_unstable();
            let mut ranges: Vec<(u64, u64)> = Vec::new();
            for p in pages {
                match ranges.last_mut() {
                    Some(r) if r.1 == p << 12 => r.1 = (p + 1) << 12,
                    _ => ranges.push((p << 12, (p + 1) << 12)),
                }
            }
            self.write_targets = ranges;
            self.wx_hit = hs.wx_hit;
            self.wx_alloc_hit = hs.wx_alloc_hit;
            self.last_fault = hs.last_fault;
            let x64 = hs.is_64;
            let pc = uc.reg_read(if x64 { RegisterX86::RIP } else { RegisterX86::EIP } as i32).unwrap_or(0);
            self.stop_api = hs.stop_api.clone();
            self.stop_hit = hs.stop_hit.clone();
            self.end = if !matches!(result, Ok(_) | Err(uc_error::OK)) {
                EmuEnd::Fault
            } else if pc == ENTRY_RETURN_ADDR {
                EmuEnd::EntryReturned
            } else {
                hs.api_end.unwrap_or(EmuEnd::Finished)
            };
            self.apicall_counter = hs.apicall_counter.clone();
            self.behavior_trace = hs.behavior_trace.clone();
            self.unique_blocks = hs.block_insns.len();
            self.total_blocks = hs.total_blocks;
            self.vm_indirect_blocks = hs.vm_indirect_blocks;
            self.seh_dispatches = hs.seh_count;
            self.insn_count = hs.insn_count;
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

    /// Code that finds an API in a system DLL's export table itself (walking the PEB
    /// and the exports, as shellcode and loaders do) calls into the DLL's real code,
    /// whose own imports are not bound here. Each exported function of the loaded DLLs
    /// starts with a jump to an API stub instead (`mov rax, stub; jmp rax`), so the call
    /// is answered like an imported one. ntdll's syscall stubs stay as they are: code
    /// reads their first bytes for the syscall number, and their `syscall` is hooked.
    fn redirect_dll_exports(&mut self, uc: &mut Unicorn<'static, ()>, dll_dir: &Path, dlls: &[(String, u64, u32)]) {
        let mut hook_addr = self.hook_addr;
        for (name, base, _) in dlls {
            for (rva, func) in dll_code_exports(&dll_dir.join(name)).iter() {
                let at = base + *rva as u64;
                let mut head = [0u8; 12];
                if uc.mem_read(at, &mut head).is_err() || head[..4] == [0x4C, 0x8B, 0xD1, 0xB8] {
                    continue;
                }
                if hook_addr + 8 > HOOK_ADDR + 0x100000 {
                    return;
                }
                let mut jump = vec![0x48, 0xB8];
                jump.extend_from_slice(&hook_addr.to_le_bytes());
                jump.extend_from_slice(&[0xFF, 0xE0]);
                if uc.mem_write(at, &jump).is_ok() {
                    self.sample.dllname_to_functionlist.entry(name.to_ascii_lowercase()).or_default().push((func.to_ascii_lowercase(), hook_addr));
                    hook_addr += 8;
                }
            }
        }
        self.hook_addr = hook_addr;
    }

    fn parse_and_patch_imports(&mut self, uc: &mut Unicorn<'static, ()>, image_base: u64) -> UnpackerResult<()> {
        let raw = &self.sample.raw_bytes;
        let opt = &self.sample.opt_header;
        let sections = &self.sample.sections;
        let is_64 = opt.magic == 0x20b;
        if opt.data_directory.len() <= 1 {
            return Ok(());
        }
        let imp_dir = &opt.data_directory[1];
        if imp_dir.virtual_address == 0 || imp_dir.size == 0 {
            return Ok(());
        }

        let rva_to_off = |rva: u32| -> Option<usize> {
            for s in sections {
                if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.size_of_raw_data) {
                    return Some((rva - s.virtual_address + s.pointer_to_raw_data) as usize);
                }
            }
            None
        };

        let read_cstring = |off: usize| -> Option<String> {
            if off >= raw.len() { return None; }
            let mut end = off;
            while end < raw.len() && raw[end] != 0 && end - off < 256 {
                end += 1;
            }
            String::from_utf8(raw[off..end].to_vec()).ok()
        };

        let mut desc_off = match rva_to_off(imp_dir.virtual_address) {
            Some(o) => o,
            None => return Ok(()),
        };

        let mut dllname_to_functionlist: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        let mut all_imports: Vec<String> = Vec::new();
        let mut import_descriptors: HashMap<String, ImportDescriptor> = HashMap::new();
        let mut hook_addr = self.hook_addr;
        let thunk_size: u32 = if is_64 { 8 } else { 4 };

        while desc_off + 20 <= raw.len() {
            let orig_first_thunk = u32::from_le_bytes(raw[desc_off..desc_off + 4].try_into().unwrap());
            let time_date_stamp = u32::from_le_bytes(raw[desc_off + 4..desc_off + 8].try_into().unwrap());
            let forwarder_chain = u32::from_le_bytes(raw[desc_off + 8..desc_off + 12].try_into().unwrap());
            let name_rva = u32::from_le_bytes(raw[desc_off + 12..desc_off + 16].try_into().unwrap());
            let first_thunk = u32::from_le_bytes(raw[desc_off + 16..desc_off + 20].try_into().unwrap());

            if orig_first_thunk == 0 && first_thunk == 0 && name_rva == 0 {
                break;
            }

            let dll_name = if let Some(off) = rva_to_off(name_rva) {
                read_cstring(off).unwrap_or_default().to_lowercase()
            } else {
                String::new()
            };

            let thunk_rva_base = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk };
            let mut thunk_idx = 0;

            loop {
                let thunk_rva = thunk_rva_base.wrapping_add(thunk_idx * thunk_size);
                let t_off = match rva_to_off(thunk_rva) {
                    Some(o) => o,
                    None => break,
                };
                if t_off + (thunk_size as usize) > raw.len() {
                    break;
                }

                let (is_ordinal, ordinal_val, hint_name_rva) = if is_64 {
                    let val = u64::from_le_bytes(raw[t_off..t_off + 8].try_into().unwrap());
                    if val == 0 { break; }
                    let ord = (val & 0x8000000000000000) != 0;
                    (ord, (val & 0xFFFF) as u32, (val & 0x7FFFFFFF) as u32)
                } else {
                    let val = u32::from_le_bytes(raw[t_off..t_off + 4].try_into().unwrap());
                    if val == 0 { break; }
                    let ord = (val & 0x80000000) != 0;
                    (ord, val & 0xFFFF, val & 0x7FFFFFFF)
                };

                let func_name = if is_ordinal {
                    format!("Ordinal{}", ordinal_val)
                } else if let Some(ibn_off) = rva_to_off(hint_name_rva) {
                    if ibn_off + 2 < raw.len() {
                        read_cstring(ibn_off + 2).unwrap_or_else(|| format!("Ordinal{}", ordinal_val))
                    } else {
                        format!("Ordinal{}", ordinal_val)
                    }
                } else {
                    format!("Ordinal{}", ordinal_val)
                };

                let name_lower = func_name.to_lowercase();
                if !dll_name.is_empty() {
                    dllname_to_functionlist
                        .entry(dll_name.clone())
                        .or_default()
                        .push((name_lower.clone(), hook_addr));

                    import_descriptors
                        .entry(dll_name.clone())
                        .or_insert_with(|| ImportDescriptor {
                            characteristics: orig_first_thunk,
                            time_date_stamp,
                            forwarder_chain,
                            name_rva,
                            first_thunk,
                            dll_name: dll_name.clone(),
                            imports: Vec::new(),
                        })
                        .imports
                        .push(name_lower.clone());

                    all_imports.push(format!("{}.{}", dll_name, func_name));

                    // Patch IAT in Unicorn memory
                    let iat_addr = image_base + (first_thunk.wrapping_add(thunk_idx * thunk_size)) as u64;
                    if is_64 {
                        let hook_bytes = hook_addr.to_le_bytes();
                        let _ = uc.mem_write(iat_addr, &hook_bytes);
                        hook_addr += 8;
                    } else {
                        let hook_bytes = (hook_addr as u32).to_le_bytes();
                        let _ = uc.mem_write(iat_addr, &hook_bytes);
                        hook_addr += 4;
                    }
                }

                thunk_idx += 1;
            }

            desc_off += 20;
        }

        // Import tables the program fills itself (a protector's or a custom loader's,
        // through LoadLibrary / GetProcAddress at start): still hint / name RVAs in the
        // file. Bound to stubs like the real ones, so code that runs without that start
        // (a single called function, an entry stub that skipped it) reaches the APIs.
        let real_iat: HashSet<u64> = dllname_to_functionlist.values().flatten().map(|(_, a)| *a).collect();
        let _ = real_iat;
        for (slot_rva, name) in hidden_iat_slots(raw, sections, opt.size_of_image, thunk_size, &rva_to_off) {
            let iat_addr = image_base + slot_rva as u64;
            let mut cur = [0u8; 8];
            // Real import slots are patched already (no longer an RVA in memory).
            if uc.mem_read(iat_addr, &mut cur[..thunk_size as usize]).is_err() || u64::from_le_bytes(cur) >= opt.size_of_image as u64 {
                continue;
            }
            let dll = "msvcrt.dll".to_string();
            dllname_to_functionlist.entry(dll.clone()).or_default().push((name.to_lowercase(), hook_addr));
            all_imports.push(format!("{dll}.{name}"));
            let bytes = hook_addr.to_le_bytes();
            let _ = uc.mem_write(iat_addr, &bytes[..thunk_size as usize]);
            hook_addr += thunk_size as u64;
        }

        self.sample.imports = all_imports;
        self.sample.dllname_to_functionlist = dllname_to_functionlist;
        self.sample.original_imports = import_descriptors.into_values().collect();
        self.hook_addr = hook_addr;
        Ok(())
    }

    /// Dump the emulated PE image to a file.
    pub fn dump(&self, file_path: &str) -> UnpackerResult<()> {
        let uc = self
            .uc
            .as_ref()
            .ok_or_else(|| UnpackerError::EmulatorError("engine not initialized".into()))?;
        crate::unpacker::imagedump::dump_image(uc, self.sample.base_addr, self.sample.virtualmemorysize, &self.dump_context(), file_path)
    }

    /// Dump the emulated PE image to a byte vector (no file I/O).
    pub fn dump_bytes(&self) -> UnpackerResult<Vec<u8>> {
        let uc = self
            .uc
            .as_ref()
            .ok_or_else(|| UnpackerError::EmulatorError("engine not initialized".into()))?;
        crate::unpacker::imagedump::dump_image_to_bytes(uc, self.sample.base_addr, self.sample.virtualmemorysize, &self.dump_context())
    }

    /// The run wrote into an executable section of the image (UPX0, a packer's
    /// target section) or into allocated memory: code is being unpacked, whether or
    /// not it has run yet. Ordinary programs write their data sections only.
    pub fn wrote_code(&self) -> bool {
        self.code_pages_written() > 0
    }

    /// Pages of executable sections and allocated memory written so far.
    fn code_pages_written(&self) -> usize {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        let hs = self.hook_state.borrow();
        let code: Vec<(u64, u64)> = hs
            .sample_sections
            .iter()
            .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            .map(|s| {
                let lo = hs.image_base + s.virtual_address as u64;
                (lo, lo + s.virtual_size.max(s.size_of_raw_data) as u64)
            })
            .collect();
        hs.written_pages
            .iter()
            .filter(|&&p| {
                let a = p << 12;
                (apicalls::ALLOC_BASE..apicalls::ALLOC_END).contains(&a) || code.iter().any(|&(lo, hi)| a + PAGE_SIZE > lo && a < hi)
            })
            .count()
    }

    /// The last run wrote into an executable section or allocated memory during
    /// its last quarter: whatever writes code was still at it when the run ended.
    fn writing_code_at_end(&self) -> bool {
        let hs = self.hook_state.borrow();
        hs.last_code_write > 0 && hs.insn_count.saturating_sub(hs.last_code_write) <= hs.insn_count / 4
    }

    fn alloc_pages_written(&self) -> usize {
        self.hook_state
            .borrow()
            .written_pages
            .iter()
            .filter(|&&p| {
                let a = p << 12;
                (apicalls::ALLOC_BASE..apicalls::ALLOC_END).contains(&a)
            })
            .count()
    }

    /// Continues a run that used up its budget while still unpacking or executing
    /// VM-protected code with observable progress (new code/alloc pages or API calls).
    pub fn continue_unpacking(&mut self, timeout_us: u64, count: usize) -> bool {
        const UNPACK_SLICE: usize = 10_000_000;
        let mut pages = self.code_pages_written();
        let mut alloc_pages = self.alloc_pages_written();
        let mut calls_seen = self.behavior_trace.calls.len();
        let can_resume = (pages > 0 && self.writing_code_at_end()) || self.vm_indirect_blocks > 0;
        if self.end != EmuEnd::Finished || self.wx_hit.is_some() || !can_resume {
            return false;
        }
        let deadline = Instant::now() + std::time::Duration::from_micros(timeout_us);
        let mut left = count;
        let mut ran = false;
        while left > 0 {
            let Some(ip) = self.ip() else { break };
            let time = deadline.saturating_duration_since(Instant::now()).as_micros() as u64;
            if time == 0 {
                break;
            }
            let slice = left.min(UNPACK_SLICE);
            let _ = self.emu_from(ip, time, slice);
            ran = true;
            left -= slice;
            let now = self.code_pages_written();
            let now_alloc = self.alloc_pages_written();
            let now_calls = self.behavior_trace.calls.len();
            let code_progressed = now > pages && self.writing_code_at_end();
            let vm_progressed = now_alloc > alloc_pages || now_calls > calls_seen;
            if self.wx_hit.is_some() || self.end != EmuEnd::Finished || !(code_progressed || vm_progressed) {
                break;
            }
            pages = now;
            alloc_pages = now_alloc;
            calls_seen = now_calls;
        }
        // The first run ended cleanly at its budget. An extension that faults or
        // stops at an API before anything written ran found nothing: the run counts
        // as it was (clean), not as an emulator failure.
        if ran && self.wx_hit.is_none() && self.end != EmuEnd::Finished {
            self.end = EmuEnd::Finished;
            self.stop_api = None;
        }
        ran
    }

    fn harvest_candidate_ranges(&self) -> Vec<(u64, u64, bool)> {
        let mut ranges: Vec<(u64, u64, bool)> = Vec::new();
        let img_lo = self.sample.base_addr;
        let img_hi = img_lo.saturating_add(self.sample.virtualmemorysize);

        for &(lo, hi) in &self.write_targets {
            let in_image = lo >= img_lo && lo < img_hi;
            ranges.push((lo, hi, in_image));
        }

        if let Some(uc) = self.uc.as_ref() {
            if let Ok(regions) = uc.mem_regions() {
                for r in regions {
                    let lo = r.begin;
                    let hi = r.end.saturating_add(1);
                    if lo >= apicalls::ALLOC_BASE && lo < apicalls::ALLOC_END {
                        let already = ranges.iter().any(|&(a, b, _)| lo >= a && hi <= b);
                        if !already {
                            ranges.push((lo, hi, false));
                        }
                    }
                }
            }
        }
        ranges
    }

    /// Scans memory written during emulation (`VirtualAlloc`/heap regions and modified
    /// image pages) and extracts embedded PE files or non-empty runtime payloads even when
    /// control never transferred to them (`wx_alloc_hit` not triggered).
    pub fn harvest_written_payloads(&mut self) -> Vec<HarvestedPayload> {
        const MAX_HARVEST_REGION: u64 = 16 << 20;
        const MAX_HARVEST_TOTAL: usize = 32 << 20;

        let ranges = self.harvest_candidate_ranges();
        if self.uc.is_none() {
            return Vec::new();
        }

        let mut payloads = Vec::new();
        let mut total_read = 0usize;

        for (lo, hi, in_image) in ranges {
            if total_read >= MAX_HARVEST_TOTAL || hi <= lo {
                break;
            }
            let len = (hi - lo).min(MAX_HARVEST_REGION).min((MAX_HARVEST_TOTAL - total_read) as u64) as usize;
            if len < 64 {
                continue;
            }
            let Some(buf) = self.read_mem(lo, len) else {
                continue;
            };
            total_read += buf.len();

            // 1. Look for embedded / mapped PE images inside the written memory
            let mut found_pe = false;
            let mut off = 0usize;
            while off + 0x80 <= buf.len() {
                if buf[off] == b'M' && buf[off + 1] == b'Z' {
                    if let Some((img_size, ep_rva)) = mapped_pe_size(&buf[off..]) {
                        let pe_base = lo + off as u64;
                        let ctx = self.dump_context();
                        let saved_ip = self.ip();
                        let _ = self.set_ip(pe_base + ep_rva as u64);
                        let dumped = self
                            .uc
                            .as_ref()
                            .and_then(|u| crate::unpacker::imagedump::dump_image_to_bytes(u, pe_base, img_size, &ctx).ok())
                            .filter(|d| !d.is_empty());
                        if let Some(ip) = saved_ip {
                            self.set_ip(ip);
                        }
                        let pe_bytes = dumped.unwrap_or_else(|| buf[off..off + img_size as usize].to_vec());
                        payloads.push(HarvestedPayload {
                            base: pe_base,
                            size: pe_bytes.len(),
                            in_image,
                            is_pe: true,
                            data: pe_bytes,
                        });
                        found_pe = true;
                        off += img_size as usize;
                        continue;
                    } else if let Some(raw_len) = raw_pe_end(&buf[off..]) {
                        let pe_bytes = buf[off..off + raw_len].to_vec();
                        payloads.push(HarvestedPayload {
                            base: lo + off as u64,
                            size: pe_bytes.len(),
                            in_image,
                            is_pe: true,
                            data: pe_bytes,
                        });
                        found_pe = true;
                        off += raw_len;
                        continue;
                    }
                }
                off += 16;
            }

            // 2. If no PE was extracted and this region lies outside the original image, keep non-zero payload bytes
            if !found_pe && !in_image {
                let Some(nz_end) = buf.iter().rposition(|&b| b != 0).map(|i| i + 1) else {
                    continue;
                };
                if nz_end >= 64 {
                    payloads.push(HarvestedPayload {
                        base: lo,
                        size: nz_end,
                        in_image: false,
                        is_pe: false,
                        data: buf[..nz_end].to_vec(),
                    });
                }
            }
        }

        payloads
    }

    /// Extracts printable ASCII and UTF-16LE strings from memory written during emulation,
    /// prioritizing URLs, file paths, registry keys, and command/module strings.
    pub fn extract_written_strings(&self) -> Vec<String> {
        const MAX_STR_SCAN: usize = 8 << 20;
        const MAX_STRINGS: usize = 512;

        let ranges = self.harvest_candidate_ranges();
        let Some(uc) = self.uc.as_ref() else {
            return Vec::new();
        };

        let mut seen = HashSet::new();
        let mut high_signal = Vec::new();
        let mut normal = Vec::new();
        let mut scanned = 0usize;

        for (lo, hi, _) in ranges {
            if scanned >= MAX_STR_SCAN || hi <= lo {
                break;
            }
            let len = (hi - lo).min((MAX_STR_SCAN - scanned) as u64) as usize;
            let Ok(buf) = uc.mem_read_as_vec(lo, len) else {
                continue;
            };
            scanned += buf.len();
            collect_strings_from_bytes(&buf, &mut seen, &mut high_signal, &mut normal);
        }

        high_signal.extend(normal);
        high_signal.truncate(MAX_STRINGS);
        high_signal
    }

    /// What the run executed from memory it wrote outside the image (a payload
    /// decrypted into VirtualAlloc'd memory): see `region_payload`.
    pub fn alloc_payload(&mut self) -> Option<AllocPayload> {
        let hit = self.wx_alloc_hit?;
        self.region_payload(hit)
    }

    /// The mapped region holding `addr`, as it is in memory, and a PE found in it
    /// at a page boundary (a loader that maps its payload image there) dumped like
    /// the image: entry point = `addr` when it lies in that PE, else its own.
    pub fn region_payload(&mut self, addr: u64) -> Option<AllocPayload> {
        let uc = self.uc.as_ref()?;
        let region = uc.mem_regions().ok()?.into_iter().find(|r| addr >= r.begin && addr <= r.end)?;
        let len = (region.end - region.begin + 1).min(MAX_REGION_DUMP);
        let memory = uc.mem_read_as_vec(region.begin, len as usize).ok()?;
        let pe_base = (0..memory.len())
            .step_by(PAGE_SIZE as usize)
            .find_map(|off| mapped_pe_size(&memory[off..]).map(|(size, ep)| (region.begin + off as u64, size, ep)));
        let pe = pe_base.and_then(|(base, size, ep)| {
            let entry = if addr >= base && addr < base + size { addr } else { base + ep as u64 };
            let saved = self.ip()?;
            self.set_ip(entry);
            let ctx = self.dump_context();
            let dumped = crate::unpacker::imagedump::dump_image_to_bytes(self.uc.as_ref()?, base, size, &ctx).ok();
            self.set_ip(saved);
            dumped.filter(|d| !d.is_empty())
        });
        Some(AllocPayload { base: region.begin, entry: addr, memory, pe })
    }

    fn dump_context(&self) -> crate::unpacker::imagedump::DumpContext {
        crate::unpacker::imagedump::DumpContext {
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
        }
    }
}

/// Code a run executed from memory it wrote outside the image.
#[derive(Debug, Clone)]
pub struct AllocPayload {
    /// Start of the mapped region holding it.
    pub base: u64,
    /// The instruction the payload was looked up from (the first one executed there).
    pub entry: u64,
    /// The region as it is in memory (at most `MAX_REGION_DUMP` bytes).
    pub memory: Vec<u8>,
    /// A PE mapped in the region, dumped like the image.
    pub pe: Option<Vec<u8>>,
}

/// Payload or embedded PE extracted from memory written during emulation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HarvestedPayload {
    pub base: u64,
    pub size: usize,
    pub in_image: bool,
    pub is_pe: bool,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
}

/// Bytes of one region `region_payload` reads.
const MAX_REGION_DUMP: u64 = 64 << 20;

/// A PE image mapped at the start of `mem` (as a loader maps it): its
/// SizeOfImage (page aligned, within `mem`) and entry point RVA.
fn mapped_pe_size(mem: &[u8]) -> Option<(u64, u32)> {
    let rd16 = |o: usize| mem.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let rd32 = |o: usize| mem.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if mem.get(..2)? != b"MZ" {
        return None;
    }
    let pe = rd32(0x3C)? as usize;
    if pe >= 0x1000 || mem.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = pe + 24;
    if !matches!(rd16(opt)?, 0x10B | 0x20B) {
        return None;
    }
    let ep = rd32(opt + 16)?;
    let size = page_align(rd32(opt + 56)? as u64);
    (size >= PAGE_SIZE && size <= mem.len() as u64).then_some((size, ep))
}

fn raw_pe_end(mem: &[u8]) -> Option<usize> {
    let rd16 = |o: usize| mem.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let rd32 = |o: usize| mem.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if mem.get(..2)? != b"MZ" {
        return None;
    }
    let pe = rd32(0x3C)? as usize;
    if pe >= 0x1000 || mem.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let nsec = rd16(coff + 2)? as usize;
    let opt_sz = rd16(coff + 16)? as usize;
    let opt = coff + 20;
    if !matches!(rd16(opt)?, 0x10B | 0x20B) {
        return None;
    }
    let sec_hdr = opt + opt_sz;
    if nsec == 0 || nsec > 96 || sec_hdr + nsec * 40 > mem.len() {
        return None;
    }
    let mut end = sec_hdr + nsec * 40;
    for i in 0..nsec {
        let off = sec_hdr + i * 40;
        let rsz = rd32(off + 16)? as usize;
        let rptr = rd32(off + 20)? as usize;
        end = end.max(rptr.saturating_add(rsz));
    }
    (end >= 0x200 && end <= mem.len()).then_some(end)
}

fn is_high_signal_str(s: &str) -> bool {
    let low = s.to_ascii_lowercase();
    low.contains("://")
        || low.contains("http")
        || low.contains('\\')
        || low.contains(".exe")
        || low.contains(".dll")
        || low.contains(".sys")
        || low.contains(".ps1")
        || low.contains(".bat")
        || low.contains("hkey_")
        || low.contains("software\\")
        || low.contains("cmd")
        || low.contains("powershell")
}

pub(crate) fn collect_strings_from_bytes(
    buf: &[u8],
    seen: &mut HashSet<String>,
    high_signal: &mut Vec<String>,
    normal: &mut Vec<String>,
) {
    let mut push_str = |s: String| {
        if s.len() < 6 || !seen.insert(s.clone()) {
            return;
        }
        if is_high_signal_str(&s) {
            if high_signal.len() < 512 {
                high_signal.push(s);
            }
        } else if normal.len() < 512 {
            normal.push(s);
        }
    };

    // ASCII runs
    let mut i = 0usize;
    while i < buf.len() {
        if (0x20..=0x7E).contains(&buf[i]) {
            let start = i;
            while i < buf.len() && (0x20..=0x7E).contains(&buf[i]) && i - start < 512 {
                i += 1;
            }
            if i - start >= 6 {
                push_str(String::from_utf8_lossy(&buf[start..i]).into_owned());
            }
        } else {
            i += 1;
        }
    }

    // UTF-16LE runs
    let mut j = 0usize;
    while j + 1 < buf.len() {
        if (0x20..=0x7E).contains(&buf[j]) && buf[j + 1] == 0 {
            let mut chars = String::new();
            while j + 1 < buf.len() && (0x20..=0x7E).contains(&buf[j]) && buf[j + 1] == 0 && chars.len() < 512 {
                chars.push(buf[j] as char);
                j += 2;
            }
            if chars.len() >= 6 {
                push_str(chars);
            }
        } else {
            j += 1;
        }
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

/// The image as the Windows loader maps it: the headers (`SizeOfHeaders` bytes) at the
/// image base, then every section at its RVA. Without the headers the image cannot be
/// dumped (`dump_bytes` parses them from emulated memory), and code that reads its own
/// headers (packers do) sees zeros.
pub(crate) fn get_memory_mapped_image(data: &[u8], sections: &[Section], virtual_size: u64, size_of_headers: u32) -> Vec<u8> {
    let mut image = vec![0u8; virtual_size as usize];
    let headers = (size_of_headers as usize).min(data.len()).min(image.len());
    image[..headers].copy_from_slice(&data[..headers]);
    for section in sections {
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

/// Folder of the system DLLs mapped into the emulator (kernel32, ntdll, KernelBase), the
/// first that exists of: `HYDRADRAGON_DLLS`, `DLLs` next to the running executable (a
/// deployed scanner or server), `DLLs` in this crate's source folder (development).
/// The same folder must be used for training (pe_feature_dump) and scanning, or the
/// emulated payloads differ.
pub fn system_dll_dir() -> std::path::PathBuf {
    system_dll_dir_for(false)
}

/// Where the system DLLs (ntdll, kernel32, KernelBase) of a 32-bit or 64-bit sample
/// come from: `HYDRADRAGON_DLLS` / `HYDRADRAGON_DLLS64`, then `DLLs` / `DLLs64` next
/// to the executable and in the crate, then this Windows itself (System32 for 64-bit,
/// SysWOW64 for 32-bit). The bundled `DLLs` are 32-bit: a 64-bit sample got none, so
/// everything that walks the loader list for ntdll or kernel32 failed.
pub fn system_dll_dir_for(is_64: bool) -> std::path::PathBuf {
    let has_dlls = |d: &Path| {
        let k = d.join("kernel32.dll");
        // The bitness must match: a DLL of the other one is refused when it is mapped.
        std::fs::read(&k).ok().and_then(|b| {
            let e = u32::from_le_bytes(b.get(0x3c..0x40)?.try_into().ok()?) as usize;
            Some(u16::from_le_bytes(b.get(e + 24..e + 26)?.try_into().ok()?) == if is_64 { 0x20b } else { 0x10b })
        }) == Some(true)
    };
    let (env, folder) = if is_64 { ("HYDRADRAGON_DLLS64", "DLLs64") } else { ("HYDRADRAGON_DLLS", "DLLs") };
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    candidates.extend(std::env::var_os(env).map(std::path::PathBuf::from));
    if !is_64 {
        candidates.extend(std::env::var_os("HYDRADRAGON_DLLS").map(std::path::PathBuf::from));
    }
    candidates.extend(std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join(folder))));
    candidates.push(Path::new(env!("CARGO_MANIFEST_DIR")).join(folder));
    let windows = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\Windows".into());
    candidates.push(windows.join(if is_64 { "System32" } else { "SysWOW64" }));
    candidates.push(windows.join("System32"));
    candidates.iter().find(|d| has_dlls(d)).cloned().unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(folder))
}

/// Maps a system DLL at its image base. A DLL of the other bitness (an x86 kernel32 for
/// an x64 sample) is refused: its exports and loader entries would be wrong there.
fn load_dll_into_emu(
    uc: &mut Unicorn<'static, ()>,
    dll_path: &str,
    is_64: bool,
) -> UnpackerResult<(u64, u64)> {
    let dll = mapped_dll(dll_path)?;
    let (dll_64, image_base, virtual_size, mmap) = (dll.0, dll.1, dll.2, &dll.3);
    if dll_64 != is_64 {
        return Err(UnpackerError::InvalidPeFile(format!(
            "{dll_path} is {}-bit, the sample is {}-bit",
            if dll_64 { 64 } else { 32 },
            if is_64 { 64 } else { 32 }
        )));
    }

    // 64-bit system DLLs all prefer 0x180000000 (ASLR places them apart): when the
    // preferred base is taken, the DLL goes where Windows puts system DLLs, without
    // relocating it (its code is RIP-relative; exports and stubs are read by RVA).
    let candidates = std::iter::once(image_base).chain((1..16u64).map(|i| if is_64 { 0x7FF8_0000_0000 + i * 0x1000_0000 } else { 0x7000_0000 + i * 0x0100_0000 }));
    let mut mapped = None;
    for base in candidates {
        if uc.mem_map(base, virtual_size, Prot::ALL).is_ok() {
            mapped = Some(base);
            break;
        }
    }
    let image_base = mapped.ok_or_else(|| UnpackerError::EmulatorError(format!("mem_map DLL {dll_path}: no free base")))?;

    uc.mem_write(image_base, mmap)
        .map_err(|e| UnpackerError::EmulatorError(format!("mem_write DLL: {:?}", e)))?;

    Ok((image_base, virtual_size))
}

/// A system DLL mapped as in memory: (64-bit, image base, virtual size, image). Read and
/// laid out once per process; every emulation used to read ~4 MB of DLLs from disk and
/// parse them again.
type MappedDll = std::sync::Arc<(bool, u64, u64, Vec<u8>)>;

fn mapped_dll(dll_path: &str) -> UnpackerResult<MappedDll> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, MappedDll>>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(d) = cache.lock().unwrap().get(dll_path) {
        return Ok(d.clone());
    }
    let data = std::fs::read(dll_path)?;
    let (_, _, opt_header, sections) = parse_pe_bytes(&data)?;
    let virtual_size = get_virtual_memory_size(&sections);
    let mmap = get_memory_mapped_image(&data, &sections, virtual_size, opt_header.size_of_headers);
    let d: MappedDll = std::sync::Arc::new((opt_header.magic == 0x20b, opt_header.image_base as u64, virtual_size, mmap));
    cache.lock().unwrap().insert(dll_path.to_string(), d.clone());
    Ok(d)
}

/// Slots (RVA, function name) of import tables still in their file form: runs of at
/// least two consecutive pointer-sized values that are RVAs of a hint / name entry (a
/// 16-bit hint, then a C identifier and a NUL), in any section.
fn hidden_iat_slots(
    raw: &[u8],
    sections: &[Section],
    size_of_image: u32,
    thunk_size: u32,
    rva_to_off: &dyn Fn(u32) -> Option<usize>,
) -> Vec<(u32, String)> {
    let name_at = |rva: u64| -> Option<String> {
        if rva == 0 || rva >= size_of_image as u64 {
            return None;
        }
        let off = rva_to_off(rva as u32)? + 2;
        let bytes = raw.get(off..off + 64.min(raw.len().saturating_sub(off)))?;
        let end = bytes.iter().position(|&b| b == 0)?;
        let name = &bytes[..end];
        let ok = (3..=60).contains(&name.len())
            && (name[0].is_ascii_alphabetic() || name[0] == b'_')
            && name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_');
        ok.then(|| String::from_utf8_lossy(name).into_owned())
    };
    let mut out = Vec::new();
    let step = thunk_size as usize;
    for sec in sections {
        let (start, len) = (sec.pointer_to_raw_data as usize, sec.size_of_raw_data as usize);
        let Some(data) = raw.get(start..start + len.min(raw.len().saturating_sub(start))) else { continue };
        let mut run: Vec<(u32, String)> = Vec::new();
        let mut flush = |run: &mut Vec<(u32, String)>| {
            if run.len() >= 2 {
                out.append(run);
            }
            run.clear();
        };
        for (i, chunk) in data.chunks_exact(step).enumerate() {
            let mut b = [0u8; 8];
            b[..step].copy_from_slice(chunk);
            match name_at(u64::from_le_bytes(b)) {
                Some(name) => run.push((sec.virtual_address + (i * step) as u32, name)),
                None => flush(&mut run),
            }
        }
        flush(&mut run);
    }
    out
}

/// (RVA, name) of a DLL's named exports that are code (in an executable section, not
/// forwarders), read once per process.
fn dll_code_exports(path: &Path) -> std::sync::Arc<Vec<(u32, String)>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<std::path::PathBuf, std::sync::Arc<Vec<(u32, String)>>>>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().unwrap().get(path) {
        return v.clone();
    }
    let mut out = Vec::new();
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(pe) = pefile_rs::PE::parse(&bytes) {
            let exec = |rva: u32| pe.sections.iter().any(|s| s.virtual_address <= rva && rva < s.virtual_address + s.virtual_size.max(s.size_of_raw_data) && s.characteristics & 0x2000_0000 != 0);
            for e in pe.exports.iter() {
                for sym in &e.symbols {
                    if let (Some(n), None) = (&sym.name, &sym.forwarder) {
                        if sym.address != 0 && exec(sym.address) {
                            out.push((sym.address, n.clone()));
                        }
                    }
                }
            }
        }
    }
    // One stub per address (aliases share code).
    out.sort();
    out.dedup_by_key(|(a, _)| *a);
    let v = std::sync::Arc::new(out);
    cache.lock().unwrap().insert(path.to_path_buf(), v.clone());
    v
}

/// Syscall number -> `Nt` name for one ntdll: its `Zw` exports sorted by address
/// (the stubs are laid out in number order). The same way samples that avoid the stub
/// bytes find the numbers, so both agree with the ntdll the emulator runs.
fn syscall_table(ntdll: &Path) -> HashMap<u32, String> {
    let Ok(bytes) = std::fs::read(ntdll) else { return HashMap::new() };
    let Ok(pe) = pefile_rs::PE::parse(&bytes) else { return HashMap::new() };
    let mut zw: Vec<(u32, String)> = pe
        .exports
        .iter()
        .flat_map(|e| e.symbols.iter())
        .filter_map(|s| s.name.as_ref().filter(|n| n.starts_with("Zw")).map(|n| (s.address, format!("Nt{}", &n[2..]))))
        .collect();
    zw.sort();
    zw.dedup_by_key(|(a, _)| *a);
    zw.into_iter().enumerate().map(|(i, (_, n))| (i as u32, n)).collect()
}

fn setup_ldr_entries(
    uc: &mut Unicorn<'static, ()>,
    ldr: u64,
    base: u64,
    region_end: u64,
    modules: &[(String, u64, u32)],
    is_64: bool,
) -> UnpackerResult<()> {
    // The three lists of PEB_LDR_DATA are circular through their heads, as in
    // Windows: a walker stops when it is back at the head. Each link points at the
    // same list's link of the next entry (InMemoryOrder at +0x10 / +0x08, ...).
    // The image is first in load and memory order and not in initialization order.
    // Every entry has its FullDllName and BaseDllName, for walkers that look modules
    // up by (hashed) name.
    let (ptr, entry_size) = if is_64 { (8u64, 0x80u64) } else { (4u64, LDR_ENTRY_SIZE) };
    let heads = if is_64 { [0x10u64, 0x20, 0x30] } else { [0x0Cu64, 0x14, 0x1C] };
    let link_off = [0u64, 2 * ptr, 4 * ptr];
    let n = modules.len() as u64;
    let entry = |i: u64| base + i * entry_size;
    let mut names_at = entry(n);
    let write = |uc: &mut Unicorn<'static, ()>, at: u64, v: u64| -> UnpackerResult<()> {
        let b = v.to_le_bytes();
        uc.mem_write(at, &b[..ptr as usize]).map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR: {e:?}")))
    };
    for (list, (&head_off, &off)) in heads.iter().zip(&link_off).enumerate() {
        let head = ldr + head_off;
        // Initialization order leaves the image (entry 0) out.
        let members: Vec<u64> = (0..n).filter(|&i| list != 2 || i != 0).map(|i| entry(i) + off).collect();
        if members.is_empty() {
            write(uc, head, head)?;
            write(uc, head + ptr, head)?;
            continue;
        }
        write(uc, head, members[0])?;
        write(uc, head + ptr, *members.last().expect("not empty"))?;
        for (k, &m) in members.iter().enumerate() {
            let next = members.get(k + 1).copied().unwrap_or(head);
            let prev = if k == 0 { head } else { members[k - 1] };
            write(uc, m, next)?;
            write(uc, m + ptr, prev)?;
        }
    }
    for (i, (name, dll_base, size)) in modules.iter().enumerate() {
        let e = entry(i as u64);
        let full = if i == 0 { format!("C:\\Users\\user\\Desktop\\{name}") } else { format!("C:\\Windows\\System32\\{name}") };
        let wide = |s: &str| s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        let (full_w, base_w) = (wide(&full), wide(name));
        let (full_at, base_at) = (names_at, names_at + full_w.len() as u64);
        let fits = base_at + base_w.len() as u64 <= region_end;
        if fits {
            uc.mem_write(full_at, &full_w).map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR name: {e:?}")))?;
            uc.mem_write(base_at, &base_w).map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR name: {e:?}")))?;
            names_at = (base_at + base_w.len() as u64 + 7) & !7;
        }
        // UNICODE_STRING: Length, MaximumLength (bytes, without / with the NUL), Buffer.
        let unicode = |len: usize, buf: u64| -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&((len - 2) as u16).to_le_bytes());
            v.extend_from_slice(&(len as u16).to_le_bytes());
            if is_64 {
                v.extend_from_slice(&[0; 4]);
                v.extend_from_slice(&buf.to_le_bytes());
            } else {
                v.extend_from_slice(&(buf as u32).to_le_bytes());
            }
            v
        };
        let (full_s, base_s) = if fits { (unicode(full_w.len(), full_at), unicode(base_w.len(), base_at)) } else { (unicode(2, 0), unicode(2, 0)) };
        // DllBase, EntryPoint (0), SizeOfImage, FullDllName, BaseDllName, Flags.
        let (dll, size_off, full_off, base_off, flags_off) = if is_64 { (0x30, 0x40, 0x48, 0x58, 0x68) } else { (0x18, 0x20, 0x24, 0x2C, 0x34) };
        write(uc, e + dll, *dll_base)?;
        let put = |uc: &mut Unicorn<'static, ()>, at: u64, b: &[u8]| uc.mem_write(at, b).map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR entry: {e:?}")));
        put(uc, e + size_off, &size.to_le_bytes())?;
        put(uc, e + full_off, &full_s)?;
        put(uc, e + base_off, &base_s)?;
        put(uc, e + flags_off, &0x1000u32.to_le_bytes())?;
    }
    Ok(())
}

/// Index of the section that holds `addr` (an absolute address in the emulated image).
/// Instructions in the basic block at `addr` (`size` bytes), decoded from the
/// emulator's memory. At least 1; x86 / x64 only (other code: one per 4 bytes).
fn analyze_block_insns(uc: &Unicorn<'_, ()>, addr: u64, size: u32, is_64: bool) -> (u32, bool) {
    let mut buf = vec![0u8; size as usize];
    if size == 0 || uc.mem_read(addr, &mut buf).is_err() {
        return ((size / 4).max(1), false);
    }
    let mut dec = iced_x86::Decoder::with_ip(if is_64 { 64 } else { 32 }, &buf, addr, iced_x86::DecoderOptions::NONE);
    let mut n = 0u32;
    let mut ends_indirect = false;
    while dec.can_decode() {
        let instr = dec.decode();
        n += 1;
        ends_indirect = matches!(
            instr.flow_control(),
            FlowControl::IndirectBranch | FlowControl::IndirectCall
        );
    }
    (n.max(1), ends_indirect)
}

fn section_index(sections: &[Section], image_base: u64, addr: u64) -> Option<usize> {
    let rva = addr.checked_sub(image_base)?;
    sections.iter().position(|s| {
        let start = s.virtual_address as u64;
        rva >= start && rva < start + s.virtual_size.max(s.size_of_raw_data) as u64
    })
}


/// Parse PE headers from an in-memory byte slice (no disk I/O, zero external dependencies).
pub fn parse_pe_bytes(
    data: &[u8],
) -> UnpackerResult<(DosHeader, PeHeader, OptionalHeader, Vec<Section>)> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(UnpackerError::InvalidPeFile("Not a PE file (missing MZ)".into()));
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(UnpackerError::InvalidPeFile("Not a PE file (missing PE header)".into()));
    }

    let coff_offset = e_lfanew + 4;
    let machine = u16::from_le_bytes(data[coff_offset..coff_offset + 2].try_into().unwrap());
    let number_of_sections = u16::from_le_bytes(data[coff_offset + 2..coff_offset + 4].try_into().unwrap());
    let size_of_optional_header = u16::from_le_bytes(data[coff_offset + 16..coff_offset + 18].try_into().unwrap()) as usize;
    let characteristics = u16::from_le_bytes(data[coff_offset + 18..coff_offset + 20].try_into().unwrap());

    let dos_header = DosHeader {
        e_magic: u16::from_le_bytes(data[0..2].try_into().unwrap()),
        e_lfanew: e_lfanew as u32,
    };

    let pe_header = PeHeader {
        signature: u32::from_le_bytes(data[e_lfanew..e_lfanew + 4].try_into().unwrap()),
        machine,
        number_of_sections,
        characteristics,
    };

    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() {
        return Err(UnpackerError::InvalidPeFile("missing optional header".into()));
    }

    let magic = u16::from_le_bytes(data[opt_offset..opt_offset + 2].try_into().unwrap());
    if magic != 0x10b && magic != 0x20b {
        return Err(UnpackerError::InvalidPeFile(format!("unknown magic 0x{:x}", magic)));
    }
    let is_pe64 = magic == 0x20b;

    let address_of_entry_point = if opt_offset + 20 <= data.len() {
        u32::from_le_bytes(data[opt_offset + 16..opt_offset + 20].try_into().unwrap())
    } else { 0 };

    let image_base: u64 = if is_pe64 {
        if opt_offset + 32 <= data.len() {
            u64::from_le_bytes(data[opt_offset + 24..opt_offset + 32].try_into().unwrap())
        } else {
            0x140000000
        }
    } else {
        if opt_offset + 32 <= data.len() {
            u32::from_le_bytes(data[opt_offset + 28..opt_offset + 32].try_into().unwrap()) as u64
        } else {
            0x400000
        }
    };

    let section_alignment = if opt_offset + 36 <= data.len() {
        u32::from_le_bytes(data[opt_offset + 32..opt_offset + 36].try_into().unwrap())
    } else { 0x1000 };

    let file_alignment = if opt_offset + 40 <= data.len() {
        u32::from_le_bytes(data[opt_offset + 36..opt_offset + 40].try_into().unwrap())
    } else { 0x200 };

    let size_of_image = if opt_offset + 60 <= data.len() {
        u32::from_le_bytes(data[opt_offset + 56..opt_offset + 60].try_into().unwrap())
    } else { 0 };

    let size_of_headers = if opt_offset + 64 <= data.len() {
        u32::from_le_bytes(data[opt_offset + 60..opt_offset + 64].try_into().unwrap())
    } else { 0 };

    let check_sum = if opt_offset + 68 <= data.len() {
        u32::from_le_bytes(data[opt_offset + 64..opt_offset + 68].try_into().unwrap())
    } else { 0 };

    let subsystem = if opt_offset + 70 <= data.len() {
        u16::from_le_bytes(data[opt_offset + 68..opt_offset + 70].try_into().unwrap())
    } else { 0 };

    let dll_characteristics = if opt_offset + 72 <= data.len() {
        u16::from_le_bytes(data[opt_offset + 70..opt_offset + 72].try_into().unwrap())
    } else { 0 };

    let (num_rva, dd_start) = if is_pe64 {
        let n = if opt_offset + 112 <= data.len() {
            u32::from_le_bytes(data[opt_offset + 108..opt_offset + 112].try_into().unwrap()) as usize
        } else {
            0
        };
        (n, opt_offset + 112)
    } else {
        let n = if opt_offset + 96 <= data.len() {
            u32::from_le_bytes(data[opt_offset + 92..opt_offset + 96].try_into().unwrap()) as usize
        } else {
            0
        };
        (n, opt_offset + 96)
    };

    let mut data_directories = Vec::new();
    for i in 0..num_rva.min(16) {
        let entry_off = dd_start + i * 8;
        if entry_off + 8 <= data.len() {
            let virtual_address = u32::from_le_bytes(data[entry_off..entry_off + 4].try_into().unwrap());
            let size = u32::from_le_bytes(data[entry_off + 4..entry_off + 8].try_into().unwrap());
            data_directories.push(DataDirectory { virtual_address, size });
        }
    }

    let opt_header = OptionalHeader {
        magic,
        address_of_entry_point,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        check_sum,
        subsystem,
        dll_characteristics,
        data_directory: data_directories,
    };

    let sec_start = opt_offset + size_of_optional_header;
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
            let characteristics = u32::from_le_bytes(data[off + 36..off + 40].try_into().unwrap());

            sections.push(Section {
                name,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                characteristics,
            });
        }
    }

    Ok((dos_header, pe_header, opt_header, sections))
}

#[cfg(test)]
mod x64_unwind_tests {
    use super::*;

    fn put32(uc: &mut Unicorn<'static, ()>, address: u64, value: u32) {
        uc.mem_write(address, &value.to_le_bytes()).unwrap();
    }

    fn runtime_function(uc: &mut Unicorn<'static, ()>, table: u64, begin: u32, end: u32, unwind: u32) {
        put32(uc, table, begin);
        put32(uc, table + 4, end);
        put32(uc, table + 8, unwind);
    }

    #[test]
    fn x64_unwind_walks_multiple_runtime_functions_and_calls_each_handler() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
        let base = 0x400000u64;
        uc.mem_map(base, 0x10000, Prot::ALL).unwrap();
        uc.mem_map(STACK_ADDR, STACK_SIZE, Prot::ALL).unwrap();

        let pdata = base + 0x5000;
        runtime_function(&mut uc, pdata, 0x200, 0x300, 0x1000);
        runtime_function(&mut uc, pdata + 12, 0x400, 0x500, 0x1100);
        // Child: an 8-byte allocation followed by an EHANDLER record.
        uc.mem_write(base + 0x1000, &[9, 4, 1, 0, 4, 2, 0, 0]).unwrap();
        put32(&mut uc, base + 0x1008, 0x600);
        // Caller: no unwind slots, but it also has an EHANDLER.
        uc.mem_write(base + 0x1100, &[9, 0, 0, 0]).unwrap();
        put32(&mut uc, base + 0x1104, 0x700);

        let rsp = STACK_ADDR + 0x1000;
        assert!(write_u64(&mut uc, rsp + 8, base + 0x410));
        assert!(write_u64(&mut uc, rsp + 16, base + 0x900));
        let mut context = vec![0; 0x4d0];
        context[0x98..0xa0].copy_from_slice(&rsp.to_le_bytes());
        context[0xf8..0x100].copy_from_slice(&(base + 0x210).to_le_bytes());

        let handlers = x64_unwind_chain(&uc, base, 0x10000, 0x5000, 24, &context);
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0].address, base + 0x600);
        assert_eq!(handlers[0].establisher_frame, rsp + 8);
        assert_eq!(handlers[1].address, base + 0x700);
        assert_eq!(handlers[1].establisher_frame, rsp + 16);
    }

    #[test]
    fn x64_epilog_executes_remaining_stack_adjust_pop_and_return() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
        let base = 0x400000u64;
        uc.mem_map(base, 0x10000, Prot::ALL).unwrap();
        uc.mem_map(STACK_ADDR, STACK_SIZE, Prot::ALL).unwrap();
        // Version 1 UNWIND_INFO, with stack allocation and saved RBP in the prolog.
        uc.mem_write(base + 0x1000, &[1, 12, 2, 0, 4, 0x32, 1, 0x50]).unwrap();
        let rf = RuntimeFunction64 { begin: 0x200, end: 0x300, unwind: 0x1000, entry: base + 0x5000 };
        let epilog = [0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3]; // add rsp,32; pop rbp; ret
        uc.mem_write(base + 0x250, &epilog).unwrap();
        let rsp = STACK_ADDR + 0x1000;
        assert!(write_u64(&mut uc, rsp + 0x20, 0x12345678));
        assert!(write_u64(&mut uc, rsp + 0x28, base + 0x410));
        let mut context = vec![0; 0x4d0];
        context[0x98..0xa0].copy_from_slice(&rsp.to_le_bytes());
        context[0xa0..0xa8].copy_from_slice(&0xdeadbeefu64.to_le_bytes());
        context[0xf8..0x100].copy_from_slice(&(base + 0x250).to_le_bytes());
        let (caller, caller_rsp) = x64_unwind_epilog(&uc, base, rf, &mut context).unwrap();
        assert_eq!(caller, base + 0x410);
        assert_eq!(caller_rsp, rsp + 0x30);
        assert_eq!(u64::from_le_bytes(context[0xa0..0xa8].try_into().unwrap()), 0x12345678);
        assert_eq!(u64::from_le_bytes(context[0x98..0xa0].try_into().unwrap()), caller_rsp);
    }

    pub(super) fn make_tiny_x64_pe(code: &[u8], ep_rva: u32) -> Vec<u8> {
        let mut pe = vec![0u8; 0x2000];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
        pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        pe[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        pe[opt + 16..opt + 20].copy_from_slice(&ep_rva.to_le_bytes());
        pe[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        pe[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        pe[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + 240;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sec + 16..sec + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        pe[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        let end = (0x400 + code.len()).min(pe.len());
        pe[0x400..end].copy_from_slice(&code[..end - 0x400]);
        pe
    }

    #[test]
    fn int0_and_int1_dispatch_to_veh_and_resume_cleanly() {
        // Code at VA 0x1_4000_1000 (EP = 0x1000):
        //   0x1000: pushfq; or qword ptr [rsp], 0x100; popfq; nop; xor eax, eax; div eax; mov rax, 0xCAFE; ret
        // VEH handler at VA 0x1_4000_1080:
        //   rcx = PEXCEPTION_POINTERS; [rcx] = PEXCEPTION_RECORD; [rcx+8] = PCONTEXT
        //   check exception code == 0xC0000094 (INT0) -> advance CONTEXT.Rip (+0xf8) by 2 (skip `div eax`)
        //   always return 0 (EXCEPTION_CONTINUE_EXECUTION inside finish_x64_seh)
        let mut code = vec![0x90u8; 0x200];
        let ep_stub: &[u8] = &[
            0x9C,                         // pushfq
            0x48, 0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, // or qword ptr [rsp], 0x100 (TF)
            0x9D,                         // popfq -> triggers single-step (#DB / INT 1)
            0x90,                         // nop (runs after INT 1 VEH resumes)
            0x31, 0xC0,                   // xor eax, eax
            0xF7, 0xF0,                   // div eax -> triggers #DE / INT 0 (2 bytes)
            0x48, 0xC7, 0xC0, 0xFE, 0xCA, 0x00, 0x00, // mov rax, 0xCAFE (0x... only signed i32 -> use 0x1337)
            0xC3,                         // ret
        ];
        code[..ep_stub.len()].copy_from_slice(ep_stub);
        // Patch 0xCAFE -> 0x00001337 (sign-extended safely)
        code[ep_stub.len() - 5..ep_stub.len() - 1].copy_from_slice(&0x1337u32.to_le_bytes());

        // VEH at offset 0x80:
        //   mov rdx, [rcx]          ; rdx = ExceptionRecord
        //   mov r8d, [rdx]          ; r8d = ExceptionCode
        //   cmp r8d, 0xC0000094
        //   jne done
        //   mov rax, [rcx+8]        ; rax = ContextRecord
        //   add qword ptr [rax+0xf8], 2 ; skip `f7 f0` (div eax)
        // done:
        //   mov eax, -1             ; EXCEPTION_CONTINUE_EXECUTION
        //   ret
        let veh: &[u8] = &[
            0x48, 0x8B, 0x11,             // mov rdx, [rcx]
            0x44, 0x8B, 0x02,             // mov r8d, [rdx]
            0x41, 0x81, 0xF8, 0x94, 0x00, 0x00, 0xC0, // cmp r8d, 0xC0000094
            0x75, 0x0C,                   // jne +12 -> done
            0x48, 0x8B, 0x41, 0x08,       // mov rax, [rcx+8]
            0x48, 0x83, 0x80, 0xF8, 0x00, 0x00, 0x00, 0x02, // add qword ptr [rax+0xf8], 2
            // done:
            0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, -1
            0xC3,                         // ret
        ];
        code[0x80..0x80 + veh.len()].copy_from_slice(veh);

        let pe = make_tiny_x64_pe(&code, 0x1000);
        let sample = Sample::from_bytes(&pe).unwrap();
        let mut eng = UnpackerEngine::new(sample, "mem");
        eng.init_uc().unwrap();
        let handler_va = eng.sample.base_addr + 0x1080;
        eng.hook_state.borrow_mut().veh_handlers.push((1, handler_va));
        let ret = eng.call_function(eng.sample.base_addr + 0x1000, &[], 5_000_000, 5_000).unwrap();
        assert_eq!(ret, 0x1337);
        assert!(eng.seh_dispatches() >= 2, "expected both INT 1 and INT 0 dispatches, got {}", eng.seh_dispatches());
    }

    #[test]
    fn harvest_written_payloads_and_strings_from_alloc() {
        let ep_stub: &[u8] = &[0x31, 0xC0, 0xC3]; // xor eax, eax; ret
        let pe = make_tiny_x64_pe(ep_stub, 0x1000);
        let sample = Sample::from_bytes(&pe).unwrap();
        let mut eng = UnpackerEngine::new(sample, "mem");
        eng.init_uc().unwrap();
        let _ = eng.emu();

        // Map a simulated VirtualAlloc buffer containing an embedded raw PE + decrypted URL
        let inner_pe = make_tiny_x64_pe(&[0xC3], 0x1000);
        let alloc_addr = apicalls::ALLOC_BASE + 0x10000;
        {
            let uc = eng.unicorn_mut().unwrap();
            uc.mem_map(alloc_addr, 0x4000, Prot::ALL).unwrap();
            uc.mem_write(alloc_addr, &inner_pe).unwrap();
            uc.mem_write(alloc_addr + 0x2800, b"https://c2.example.invalid/stage2.bin\0").unwrap();
        }

        let payloads = eng.harvest_written_payloads();
        assert!(payloads.iter().any(|p| p.is_pe && p.base == alloc_addr && p.size >= 0x1000));

        let strings = eng.extract_written_strings();
        assert!(strings.iter().any(|s| s.contains("https://c2.example.invalid/stage2.bin")));
    }

    #[test]
    fn load_config_security_cookie_and_native_driver_setup() {
        let mut sec0 = vec![0x90u8; 0x400];
        let stub: &[u8] = &[
            0x4C, 0x8B, 0x05, 0xF9, 0x01, 0x00, 0x00, // mov r8, [rip+0x1f9] -> [0x1200]
            0x4D, 0x85, 0xC0,                         // test r8, r8
            0x74, 0x1C,                               // jz fail (0x1028)
            0x49, 0xB9, 0x32, 0xA2, 0xDF, 0x2D, 0x99, 0x2B, 0x00, 0x00, // mov r9, 0x2b992ddfa232
            0x4D, 0x39, 0xC8,                         // cmp r8, r9
            0x74, 0x0D,                               // je fail (0x1028)
            0x0F, 0xB7, 0x01,                         // movzx eax, word ptr [rcx] (DRIVER_OBJECT.Type)
            0x0F, 0xB7, 0x0A,                         // movzx ecx, word ptr [rdx] (RegistryPath.Length)
            0xC1, 0xE0, 0x10,                         // shl eax, 16
            0x09, 0xC8,                               // or eax, ecx
            0xC3,                                     // ret
            0x90,                                     // nop
            0xCD, 0x29,                               // int 29h (fail)
            0xC3,                                     // ret
        ];
        sec0[..stub.len()].copy_from_slice(stub);

        // LOAD_CONFIG at RVA 0x1080 (offset 0x80 in sec0): size=0x140, SecurityCookie VA at +0x58 -> 0x140001200
        sec0[0x80..0x84].copy_from_slice(&0x140u32.to_le_bytes());
        sec0[0x80 + 0x58..0x80 + 0x60].copy_from_slice(&0x1_4000_1200u64.to_le_bytes());
        // Default uninitialized GS cookie + complement at RVA 0x1200 / 0x1208
        let def_cookie = 0x0000_2B99_2DDF_A232u64;
        sec0[0x200..0x208].copy_from_slice(&def_cookie.to_le_bytes());
        sec0[0x208..0x210].copy_from_slice(&(!def_cookie).to_le_bytes());

        let mut pe = make_tiny_x64_pe(&sec0, 0x1000);
        let opt = 0x84 + 20;
        // Subsystem = 1 (IMAGE_SUBSYSTEM_NATIVE)
        pe[opt + 68..opt + 70].copy_from_slice(&1u16.to_le_bytes());
        // DataDirectory[10] = LOAD_CONFIG (opt + 112 + 10*8)
        pe[opt + 192..opt + 196].copy_from_slice(&0x1080u32.to_le_bytes());
        pe[opt + 196..opt + 200].copy_from_slice(&0x140u32.to_le_bytes());

        let sample = Sample::from_bytes(&pe).unwrap();
        let mut eng = UnpackerEngine::new(sample, "mem");
        eng.init_uc().unwrap();
        eng.emu().unwrap();
        assert_eq!(eng.end, EmuEnd::EntryReturned);

        let uc = eng.unicorn_mut().unwrap();
        let rax = uc.reg_read(RegisterX86::RAX as i32).unwrap();
        let drv_type = (rax >> 16) as u16;
        let reg_len = (rax & 0xFFFF) as u16;
        assert_eq!(drv_type, 4);
        assert!(reg_len >= 20, "expected valid RegistryPath length, got {reg_len}");
    }
}
