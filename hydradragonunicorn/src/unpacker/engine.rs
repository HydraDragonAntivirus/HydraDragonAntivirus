use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::Instant;

use unicorn_engine::unicorn_const::{
    uc_error, Arch, HookType as UcHookType, MemType, Mode, Prot, SECOND_SCALE,
};
use unicorn_engine::{RegisterARM, RegisterARM64, RegisterX86, UcHookId, Unicorn};
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
const STACK_ADDR: u64 = 0x0010_0000;
const STACK_SIZE: u64 = 1024 * 1024;
const TEB_ADDR: u64 = 0x200000;
const PEB_ADDR: u64 = 0x201000;
const LDR_ADDR: u64 = 0x202000;
const GDT_ADDR: u64 = 0x205000;
const HOOK_ADDR: u64 = 0x7F000000;
// Keep the synthetic RET target away from the mapped region's trailing page;
// Unicorn may fetch a small instruction window past a basic block boundary.
const SEH_RETURN_ADDR: u64 = HOOK_ADDR + 0x0F0000;
/// Return address of the entry point: an EXE's start routine or a DLL's DllMain that
/// returns lands here and the run ends cleanly (it used to return to address 0 and end
/// as a FETCH_UNMAPPED fault).
const ENTRY_RETURN_ADDR: u64 = HOOK_ADDR + 0x0F2000;

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

/// Conditions a run stops on (any of them), on top of the budget and time limit.
#[derive(Debug, Clone, Default)]
pub struct Stops {
    pub write_execute: bool,
    /// API names, normalized (`apicalls::normalize_api_name`).
    pub apis: Vec<String>,
    pub sections: Vec<String>,
    /// Hex byte patterns (`??` = any byte) matched at the start of a basic block.
    pub patterns: Vec<Vec<Option<u8>>>,
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

    pub fn from_bytes(raw: &[u8]) -> UnpackerResult<Self> {
        let raw_bytes = if !raw.is_empty() && vmpunpacker::detect(raw) {
            let unpacked = vmpunpacker::unpack(raw)
                .map_err(|e| UnpackerError::General(format!("VMProtect LZMA unpack failed: {e}")))?;
            unpacked
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
    /// Instructions of each (block address, size), decoded once.
    block_insns: HashMap<(u64, u32), u32>,
    blocks_seen: u32,
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

const SEH64_RETURN_ADDR: u64 = HOOK_ADDR + 0x0f1000;

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
        if !s.is_64 || s.seh_count >= 32 { return None; }
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
    if ret == 0 {
        let context = uc.mem_read_as_vec(active.context_ptr, 0x4d0).ok()?;
        return restore_x64_context(uc, &context);
    }
    if ret != 1 { return None; }
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

fn begin_x86_seh(
    uc: &mut Unicorn<'static, ()>,
    shared: &Rc<RefCell<HookState>>,
    fault: SehFault,
) -> Option<u64> {
    let (is_64, seh_count, image_base, image_size) = {
        let state = shared.borrow();
        (state.is_64, state.seh_count, state.image_base, state.image_size)
    };
    if is_64 || seh_count >= 32 { return None; }
    shared.borrow_mut().seh_count = seh_count + 1;
    let head = u32::from_le_bytes(uc.mem_read_as_vec(TEB_ADDR, 4).ok()?.try_into().ok()?);
    if head == u32::MAX || head == 0 { return None; }
    let mut esp = uc.reg_read(RegisterX86::ESP as i32).ok()? as u32;
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
    let mut frame = head;
    loop {
        if frame < STACK_ADDR as u32 || frame as u64 + 8 > STACK_ADDR + STACK_SIZE { return None; }
        let words = uc.mem_read_as_vec(frame as u64, 8).ok()?;
        let next = u32::from_le_bytes(words[0..4].try_into().ok()?);
        let handler = u32::from_le_bytes(words[4..8].try_into().ok()?);
        if handler == 0 { return None; }
        if valid_seh_handler(image_base, image_size, handler) {
            let mut caller_sp = record;
            let args = [SEH_RETURN_ADDR as u32, record, frame, ctx_ptr, disp_ptr];
            for value in args.iter().rev() { caller_sp = caller_sp.checked_sub(4)?; uc.mem_write(caller_sp as u64, &value.to_le_bytes()).ok()?; }
            esp = caller_sp;
            uc.reg_write(RegisterX86::ESP as i32, esp as u64).ok()?;
            uc.reg_write(RegisterX86::EIP as i32, handler as u64).ok()?;
            shared.borrow_mut().seh_active = Some(SehDispatch { context, exception_record: record, context_record: ctx_ptr, dispatcher_context: disp_ptr, next, initial_esp: esp });
            return Some(handler as u64);
        }
        if next <= frame || next == u32::MAX { return None; }
        frame = next;
    }
}

fn finish_x86_seh(uc: &mut Unicorn<'static, ()>, shared: &Rc<RefCell<HookState>>) -> Option<u64> {
    let (mut active, seh_count, image_base, image_size) = {
        let mut state = shared.borrow_mut();
        (state.seh_active.take()?, state.seh_count, state.image_base, state.image_size)
    };
    active.context = uc.mem_read_as_vec(active.context_record as u64, 0x2cc).ok()?;
    match uc.reg_read(RegisterX86::EAX as i32).ok()? as u32 {
        0 => {
            for (off, reg) in [(0x9c,RegisterX86::EDI),(0xa0,RegisterX86::ESI),(0xa4,RegisterX86::EBX),(0xa8,RegisterX86::EDX),(0xac,RegisterX86::ECX),(0xb0,RegisterX86::EAX),(0xb4,RegisterX86::EBP),(0xc0,RegisterX86::EFLAGS),(0xc4,RegisterX86::ESP)] {
                uc.reg_write(reg as i32, u32::from_le_bytes(active.context[off..off+4].try_into().ok()?) as u64).ok()?;
            }
            let ip = u32::from_le_bytes(active.context[0xb8..0xbc].try_into().ok()?);
            uc.reg_write(RegisterX86::EIP as i32, ip as u64).ok()?;
            Some(ip as u64)
        }
        1 => {
            if active.next == u32::MAX || seh_count >= 32 { return None; }
            let words = uc.mem_read_as_vec(active.next as u64, 8).ok()?;
            let next = u32::from_le_bytes(words[0..4].try_into().ok()?);
            let handler = u32::from_le_bytes(words[4..8].try_into().ok()?);
            if !valid_seh_handler(image_base, image_size, handler) { return None; }
            let args = [SEH_RETURN_ADDR as u32, active.exception_record, active.next, active.context_record, active.dispatcher_context];
            let mut sp = active.initial_esp;
            for value in args.iter().rev() { sp = sp.checked_sub(4)?; uc.mem_write(sp as u64, &value.to_le_bytes()).ok()?; }
            uc.reg_write(RegisterX86::ESP as i32, sp as u64).ok()?;
            uc.reg_write(RegisterX86::EIP as i32, handler as u64).ok()?;
            let mut state = shared.borrow_mut();
            state.seh_count = seh_count + 1;
            state.seh_active = Some(SehDispatch { next, initial_esp: sp, ..active });
            Some(handler as u64)
        }
        _ => None,
    }
}

fn valid_seh_handler(image_base: u64, image_size: u64, handler: u32) -> bool {
    let address = handler as u64;
    address >= image_base && address < image_base.saturating_add(image_size)
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
            uc: None,
            hook_ids: Vec::new(),
            hook_state: Rc::new(RefCell::new(HookState {
                breakpoints: Vec::new(),
                mem_breakpoints: Vec::new(),
                section_write_bytes: vec![0; sections.len()],
                section_exec_bytes: vec![0; sections.len()],
                written_pages: HashSet::new(),
                wx_hit: None,
                wx_alloc_hit: None,
                last_code_write: 0,
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
        let ldr_size = page_align(0x2000);
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

        // --- Map hook memory ---
        let hook_mem_size = page_align(0x100000);
        uc.mem_map(HOOK_ADDR, hook_mem_size, Prot::ALL)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_map hook: {:?}", e)))?;

        // --- Load system DLLs ---
        let dll_dir = system_dll_dir();

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

        // --- Set up LDR entries for loaded DLLs ---
        let ldr_entries_base = if is_64 { LDR_ADDR + 0x58 } else { LDR_ADDR + 0x30 };
        setup_ldr_entries(&mut uc, ldr_entries_base, &dll_bases, is_64)?;

        // --- Initialize registers ---
        let esp_val = STACK_ADDR + STACK_SIZE / 2;
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

        // --- Store imported function info & patch IAT with hook addresses ---
        self.parse_and_patch_imports(&mut uc, image_base)?;
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
                            if st.is_64 && (is_add_veh || is_remove_veh) {
                                if let Ok(rsp) = uc.reg_read(RegisterX86::RSP as i32) {
                                    let ret_addr = uc.mem_read_as_vec(rsp, 8)
                                        .ok().and_then(|b| <[u8; 8]>::try_from(b).ok())
                                        .map(u64::from_le_bytes).unwrap_or(0);
                                    let arg0 = uc.reg_read(RegisterX86::RCX as i32).unwrap_or(0);
                                    let arg1 = uc.reg_read(RegisterX86::RDX as i32).unwrap_or(0);
                                    let ret = if is_add_veh {
                                        if arg1 < st.image_base || arg1 >= st.image_base.saturating_add(st.image_size) { 0 }
                                        else {
                                            let handle = st.next_veh_handle;
                                            st.next_veh_handle = st.next_veh_handle.wrapping_add(1).max(1);
                                            if arg0 != 0 { st.veh_handlers.insert(0, (handle, arg1)); }
                                            else { st.veh_handlers.push((handle, arg1)); }
                                            handle
                                        }
                                    } else {
                                        let before = st.veh_handlers.len();
                                        st.veh_handlers.retain(|(handle, _)| *handle != arg0);
                                        (before != st.veh_handlers.len()) as u64
                                    };
                                    if ret_addr != 0 && !(ret_addr >= st.hook_addr && ret_addr < st.hook_addr + 0x100000) {
                                        let _ = uc.reg_write(RegisterX86::RAX as i32, ret);
                                        let _ = uc.reg_write(RegisterX86::RSP as i32, rsp + 8);
                                        let _ = uc.reg_write(RegisterX86::RIP as i32, ret_addr);
                                        false
                                    } else { true }
                                } else { true }
                            } else { true }
                        } else {
                            let spec = apicalls::get_api_spec(&api_name);
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

                                if norm == "exitprocess" || norm == "corlexitprocess" || norm == "exitthread" || (is_terminate && is_self_termination) {
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

                                    // Model Windows VEH registration in-process. The returned
                                    // opaque handle is stable for RemoveVectoredExceptionHandler.
                                    if is_64 && (norm == "addvectoredexceptionhandler" || norm == "rtladdvectoredexceptionhandler") {
                                        let first = raw_args.first().copied().unwrap_or(0) != 0;
                                        let handler = raw_args.get(1).copied().unwrap_or(0);
                                        if handler >= st.image_base && handler < st.image_base.saturating_add(st.image_size) {
                                            let handle = st.next_veh_handle;
                                            st.next_veh_handle = st.next_veh_handle.wrapping_add(1).max(1);
                                            if first { st.veh_handlers.insert(0, (handle, handler)); }
                                            else { st.veh_handlers.push((handle, handler)); }
                                            ret_val = handle;
                                        } else { ret_val = 0; }
                                    } else if is_64 && (norm == "removevectoredexceptionhandler" || norm == "rtlremovevectoredexceptionhandler") {
                                        let handle = raw_args.first().copied().unwrap_or(0);
                                        let before = st.veh_handlers.len();
                                        st.veh_handlers.retain(|(h, _)| *h != handle);
                                        ret_val = (before != st.veh_handlers.len()) as u64;
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
                    let out_of_time = st.blocks_seen & 255 == 0 && st.deadline.is_some_and(|d| Instant::now() >= d);
                    let out_of_budget = st.insn_budget > 0 && {
                        let n = match st.block_insns.get(&(addr, size)) {
                            Some(&n) => n,
                            None => {
                                let n = count_block_insns(uc, addr, size, st.is_64);
                                st.block_insns.insert((addr, size), n);
                                n
                            }
                        };
                        let spent = st.insn_count >= st.insn_budget;
                        st.insn_count += n as u64;
                        spent
                    };
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
                                .any(|p| head.len() >= p.len() && p.iter().zip(&head).all(|(b, h)| b.is_none_or(|b| b == *h)))
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
                if interrupt == 3 {
                    if let Ok(mut st) = intr_state.try_borrow_mut() {
                        let ip = if st.is_64 { uc.reg_read(RegisterX86::RIP as i32).unwrap_or(1).saturating_sub(1) } else { uc.reg_read(RegisterX86::EIP as i32).unwrap_or(1).saturating_sub(1) };
                        st.seh_fault = Some(SehFault { code: 0x80000003, address: 0, access: 0, instruction: ip });
                    }
                    let _ = uc.emu_stop();
                }
            })
            .map_err(|e| UnpackerError::EmulatorError(format!("add_intr_hook: {:?}", e)))?;
            self.hook_ids.push(intr_hook);

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

    /// Continues a run that used up its budget while still unpacking, from where
    /// it stopped, for up to `timeout_us` / `count` more. A stub decompressing a
    /// large payload (UPX on a big program) needs more than the usual budget. The
    /// extra budget is given in slices of `UNPACK_SLICE` instructions, each only
    /// while nothing written has run yet and the previous run was still writing
    /// code (executable sections or allocated memory) in its last quarter, into
    /// new pages: a decompressor fills new pages until it is done, a program that
    /// loops, or wrote a code page once at start-up, does not. True when it ran again.
    pub fn continue_unpacking(&mut self, timeout_us: u64, count: usize) -> bool {
        const UNPACK_SLICE: usize = 10_000_000;
        let mut pages = self.code_pages_written();
        if self.end != EmuEnd::Finished || self.wx_hit.is_some() || pages == 0 || !self.writing_code_at_end() {
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
            if self.wx_hit.is_some() || self.end != EmuEnd::Finished || now == pages || !self.writing_code_at_end() {
                break;
            }
            pages = now;
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
fn get_memory_mapped_image(data: &[u8], sections: &[Section], virtual_size: u64, size_of_headers: u32) -> Vec<u8> {
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
    let has_dlls = |d: &Path| d.join("kernel32.dll").is_file();
    if let Some(d) = std::env::var_os("HYDRADRAGON_DLLS").map(std::path::PathBuf::from) {
        if has_dlls(&d) {
            return d;
        }
    }
    if let Some(d) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("DLLs"))) {
        if has_dlls(&d) {
            return d;
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("DLLs")
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

    uc.mem_map(image_base, virtual_size, Prot::ALL)
        .map_err(|e| UnpackerError::EmulatorError(format!("mem_map DLL: {:?}", e)))?;

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

fn setup_ldr_entries(
    uc: &mut Unicorn<'static, ()>,
    base: u64,
    dlls: &[(String, u64, u32)],
    is_64: bool,
) -> UnpackerResult<()> {
    let entry_size = if is_64 { 0x80u64 } else { LDR_ENTRY_SIZE };
    let mut prev_entry = base;

    for (i, (name, dll_base, size)) in dlls.iter().enumerate() {
        let entry_addr = base + (i as u64) * entry_size;
        let next_addr = base + ((i + 1) as u64) * entry_size;
        let prev_link = if i == 0 {
            entry_addr + entry_size * (dlls.len() as u64)
        } else {
            prev_entry
        };

        let mut entry = vec![0u8; entry_size as usize];

        if is_64 {
            let flink = if i + 1 < dlls.len() { next_addr } else { base };
            let blink = if i > 0 { prev_link } else { base };

            // InLoadOrderLinks (0..16)
            entry[0..8].copy_from_slice(&flink.to_le_bytes());
            entry[8..16].copy_from_slice(&blink.to_le_bytes());

            // InMemoryOrderLinks (16..32)
            entry[16..24].copy_from_slice(&flink.to_le_bytes());
            entry[24..32].copy_from_slice(&blink.to_le_bytes());

            // InInitializationOrderLinks (32..48)
            entry[32..40].copy_from_slice(&flink.to_le_bytes());
            entry[40..48].copy_from_slice(&blink.to_le_bytes());

            // DllBase (48..56)
            entry[48..56].copy_from_slice(&dll_base.to_le_bytes());

            // EntryPoint (56..64) = 0
            entry[56..64].copy_from_slice(&0u64.to_le_bytes());

            // SizeOfImage (64..68)
            entry[64..68].copy_from_slice(&size.to_le_bytes());

            // Flags (104..108)
            if entry.len() >= 108 {
                entry[104..108].copy_from_slice(&0x1000u32.to_le_bytes());
            }
        } else {
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
        }

        uc.mem_write(entry_addr, &entry)
            .map_err(|e| UnpackerError::EmulatorError(format!("mem_write LDR entry: {:?}", e)))?;

        prev_entry = entry_addr;
    }

    Ok(())
}

/// Index of the section that holds `addr` (an absolute address in the emulated image).
/// Instructions in the basic block at `addr` (`size` bytes), decoded from the
/// emulator's memory. At least 1; x86 / x64 only (other code: one per 4 bytes).
fn count_block_insns(uc: &Unicorn<'_, ()>, addr: u64, size: u32, is_64: bool) -> u32 {
    let mut buf = vec![0u8; size as usize];
    if size == 0 || uc.mem_read(addr, &mut buf).is_err() {
        return (size / 4).max(1);
    }
    let mut dec = iced_x86::Decoder::with_ip(if is_64 { 64 } else { 32 }, &buf, addr, iced_x86::DecoderOptions::NONE);
    let mut n = 0u32;
    while dec.can_decode() {
        let _ = dec.decode();
        n += 1;
    }
    n.max(1)
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
}
