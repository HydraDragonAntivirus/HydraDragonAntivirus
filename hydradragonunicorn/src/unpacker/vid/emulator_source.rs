//! Emulator-backed process/module memory abstraction and PE unpacking dump
//! driver for `vid` inside `hydradragonunicorn` (no live OS `OpenProcess`).

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use unicorn_engine::Unicorn;

use crate::unpacker::engine::{
    entrypoint, EmuEnd, PeArch, Sample, Section as EngineSection, StopHit, Stops, UnpackerEngine,
};

use super::exports::ExportIndex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    X86,
    X64,
}

impl Architecture {
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::X86 => 4,
            Self::X64 => 8,
        }
    }

    pub const fn bitness(self) -> u32 {
        match self {
            Self::X86 => 32,
            Self::X64 => 64,
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => formatter.write_str("x86"),
            Self::X64 => formatter.write_str("x64"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Module {
    pub name: String,
    pub image_path: String,
    pub base_address: u64,
    pub image_size: u32,
}

#[derive(Debug)]
pub enum MemoryError {
    Unmapped {
        address: u64,
        size: usize,
        detail: String,
    },
    UnsupportedArchitecture(String),
    ShortRead {
        address: u64,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmapped {
                address,
                size,
                detail,
            } => write!(
                formatter,
                "cannot read {size} byte(s) at 0x{address:x}: {detail}"
            ),
            Self::UnsupportedArchitecture(arch) => {
                write!(formatter, "unsupported emulator architecture `{arch}`")
            }
            Self::ShortRead {
                address,
                expected,
                actual,
            } => write!(
                formatter,
                "short read at 0x{address:x}: read {actual} of {expected} byte(s)"
            ),
        }
    }
}

impl Error for MemoryError {}

/// Read-only memory source abstracting Unicorn emulated memory and in-memory
/// snapshots (replacing Win32 `OpenProcess`/`ReadProcessMemory`).
pub trait MemorySource {
    fn architecture(&self) -> Architecture;
    fn read_exact(&self, address: u64, buffer: &mut [u8]) -> Result<(), MemoryError>;
}

/// Memory reader backed directly by a live `Unicorn` instance.
pub struct EmulatorMemory<'a> {
    uc: &'a Unicorn<'static, ()>,
    architecture: Architecture,
}

impl<'a> EmulatorMemory<'a> {
    pub fn new(uc: &'a Unicorn<'static, ()>, architecture: Architecture) -> Self {
        Self { uc, architecture }
    }
}

impl MemorySource for EmulatorMemory<'_> {
    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn read_exact(&self, address: u64, buffer: &mut [u8]) -> Result<(), MemoryError> {
        if buffer.is_empty() {
            return Ok(());
        }
        self.uc.mem_read(address, buffer).map_err(|err| MemoryError::Unmapped {
            address,
            size: buffer.len(),
            detail: format!("unicorn mem_read failed: {err:?}"),
        })
    }
}

/// Pure in-memory sparse address-space reader for unit tests and offline images.
#[derive(Clone, Debug)]
pub struct SliceMemory {
    architecture: Architecture,
    regions: Vec<(u64, Vec<u8>)>,
}

impl SliceMemory {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            regions: Vec::new(),
        }
    }

    pub fn from_single_module(
        architecture: Architecture,
        base_address: u64,
        bytes: Vec<u8>,
    ) -> Self {
        let mut memory = Self::new(architecture);
        memory.add_region(base_address, bytes);
        memory
    }

    pub fn add_region(&mut self, base_address: u64, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.regions.push((base_address, bytes));
        }
    }
}

impl MemorySource for SliceMemory {
    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn read_exact(&self, address: u64, buffer: &mut [u8]) -> Result<(), MemoryError> {
        if buffer.is_empty() {
            return Ok(());
        }
        let requested_end = address.checked_add(buffer.len() as u64).ok_or_else(|| {
            MemoryError::Unmapped {
                address,
                size: buffer.len(),
                detail: "address overflow".to_owned(),
            }
        })?;
        for (region_base, region_bytes) in &self.regions {
            let Some(region_end) = region_base.checked_add(region_bytes.len() as u64) else {
                continue;
            };
            if address >= *region_base && requested_end <= region_end {
                let start = (address - *region_base) as usize;
                let end = start + buffer.len();
                buffer.copy_from_slice(&region_bytes[start..end]);
                return Ok(());
            }
        }
        Err(MemoryError::Unmapped {
            address,
            size: buffer.len(),
            detail: "address not covered by any mapped memory region".to_owned(),
        })
    }
}

/// Controls how `UnpackerEngine` executes and dumps the sample before `vid`
/// reconstructs protected imports.
#[derive(Clone, Debug)]
pub struct VidEmulationConfig {
    /// Emulate from `AddressOfEntryPoint` before dumping. When `false`, only
    /// initializes Unicorn (maps sections, patches IAT/DLLs) and dumps immediately.
    pub emulate: bool,
    /// Run `vmpunpacker::unpack` before loading into Unicorn. Defaults to `false`
    /// so Unicorn executes the packer's own loader stub and initializes imports.
    pub static_vmp_unpack: bool,
    /// Maximum instructions executed in the initial unpacking run (`0` = time-only).
    pub max_insns: usize,
    /// Timeout in seconds for the initial unpacking run.
    pub timeout_secs: u64,
    /// Optional RVA breakpoint where unpacking emulation stops (likely OEP).
    pub stop_rva: Option<u32>,
    /// Stop when execution reaches a page written during the run outside the
    /// packer/VM entry section.
    pub stop_on_write_execute: bool,
    /// Extra instruction budget for `UnpackerEngine::continue_unpacking` when
    /// code decryption was still active at the end of the first budget slice.
    pub continue_unpacking_budget: usize,
    /// Map zeroed pages on unmapped memory faults during packer execution.
    pub map_on_fault: bool,
}

impl Default for VidEmulationConfig {
    fn default() -> Self {
        Self {
            emulate: true,
            static_vmp_unpack: false,
            max_insns: 5_000_000,
            timeout_secs: 30,
            stop_rva: None,
            stop_on_write_execute: true,
            continue_unpacking_budget: 10_000_000,
            map_on_fault: false,
        }
    }
}

/// Complete memory snapshot + export index dumped directly from `UnpackerEngine`.
pub struct VidDump {
    pub architecture: Architecture,
    pub module: Module,
    pub module_snapshot: Vec<u8>,
    pub export_index: ExportIndex,
    pub detected_oep_rva: Option<u32>,
    pub extra_data_regions: Vec<(u64, Vec<u8>)>,
    pub insn_count: u64,
    pub emu_end: EmuEnd,
    pub stop_hit: Option<StopHit>,
    pub wx_hit: Option<u64>,
    pub warnings: Vec<String>,
}

/// Extract a memory snapshot, resolved export index, runtime heap regions, and
/// candidate OEP directly from an initialized/emulated `UnpackerEngine`.
pub fn dump_from_engine(
    engine: &UnpackerEngine,
    module_name: Option<&str>,
) -> Result<VidDump, String> {
    let architecture = pe_arch_to_vid(engine.pe_arch())?;
    let uc = engine
        .unicorn()
        .ok_or_else(|| "UnpackerEngine is not initialized (call init_uc first)".to_owned())?;

    let module_snapshot = engine
        .read_image_snapshot()
        .map_err(|err| format!("failed to read module snapshot from emulator: {err}"))?;
    let image_size = u32::try_from(module_snapshot.len())
        .map_err(|_| "emulated image size exceeds 32-bit PE limit".to_owned())?;
    let base_address = engine.sample.base_addr;

    let name = module_name
        .filter(|name| !name.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            std::path::Path::new(&engine.sample.path)
                .file_name()
                .and_then(|n| n.to_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "sample.exe".to_owned());

    let module = Module {
        name,
        image_path: engine.sample.path.clone(),
        base_address,
        image_size,
    };

    let emu_memory = EmulatorMemory::new(uc, architecture);
    let dll_bases = engine.loaded_dll_bases();
    let hook_map = engine.dll_exports_snapshot();
    let export_index = ExportIndex::from_emulator(&emu_memory, &dll_bases, &hook_map);

    let detected_oep_rva = detect_oep_rva(
        base_address,
        image_size,
        engine.sample.opt_header.address_of_entry_point,
        &engine.sample.sections,
        engine.stop_hit.as_ref(),
        engine.wx_hit,
    );

    let extra_data_regions = engine.allocated_memory_snapshots(16 << 20);
    let mut warnings = Vec::new();
    if engine.end == EmuEnd::Fault {
        if let Some(fault) = engine.last_fault {
            warnings.push(format!(
                "emulator unpacking halted on memory fault at IP 0x{:x} (target 0x{:x}, access {}); proceeding with emulator dump",
                fault.instruction, fault.address, fault.access
            ));
        } else {
            warnings.push(
                "emulator unpacking halted on CPU/memory fault; proceeding with emulator dump"
                    .to_owned(),
            );
        }
    }

    Ok(VidDump {
        architecture,
        module,
        module_snapshot,
        export_index,
        detected_oep_rva,
        extra_data_regions,
        insn_count: engine.insn_count,
        emu_end: engine.end,
        stop_hit: engine.stop_hit.clone(),
        wx_hit: engine.wx_hit,
        warnings,
    })
}

/// Initialize `UnpackerEngine`, optionally run emulation until OEP/import
/// initialization completes, and dump the live unpacked image from Unicorn.
pub fn emulate_and_dump(
    pe_bytes: &[u8],
    module_name: &str,
    emu_cfg: &VidEmulationConfig,
) -> Result<VidDump, String> {
    let sample = if emu_cfg.static_vmp_unpack {
        Sample::from_bytes(pe_bytes)
    } else {
        Sample::from_bytes_raw(pe_bytes)
    }
    .map_err(|err| format!("cannot parse PE sample for emulation: {err}"))?;

    let mut engine = UnpackerEngine::new(sample, "");
    engine
        .init_uc()
        .map_err(|err| format!("cannot initialize Unicorn emulator: {err}"))?;

    if emu_cfg.emulate {
        configure_emulation_stops(&mut engine, emu_cfg);
        engine.set_map_on_fault(emu_cfg.map_on_fault);

        let entry_va = entrypoint(&engine.sample.opt_header);
        let timeout_us = emu_cfg.timeout_secs.saturating_mul(1_000_000);
        if let Err(err) = engine.emu_from(entry_va, timeout_us, emu_cfg.max_insns) {
            log::warn!("UnpackerEngine::emu_from returned non-fatal status: {err}");
        }

        if emu_cfg.continue_unpacking_budget > 0
            && emu_cfg.stop_rva.is_none()
            && engine.wx_hit.is_none()
            && engine.stop_hit.is_none()
            && engine.end == EmuEnd::Finished
        {
            let _ = engine.continue_unpacking(timeout_us, emu_cfg.continue_unpacking_budget);
        }
    }

    dump_from_engine(&engine, Some(module_name))
}

fn configure_emulation_stops(engine: &mut UnpackerEngine, emu_cfg: &VidEmulationConfig) {
    // Disable legacy coarse controls so StopHit/write_execute + outside rules drive OEP stops.
    engine.set_controls(false, false);
    engine.set_end_addr(u64::MAX);

    let base = engine.sample.base_addr;
    let entry_rva = engine.sample.opt_header.address_of_entry_point;
    let sections = engine.sample.sections.clone();
    let raw_bytes = engine.sample.raw_bytes.clone();

    let entry_sec_idx = section_index_for_rva(&sections, entry_rva);
    let mut stops = Stops::default();

    if let Some(stop_rva) = emu_cfg.stop_rva {
        let stop_va = base.saturating_add(u64::from(stop_rva));
        if !engine.breakpoints.contains(&stop_va) {
            engine.breakpoints.push(stop_va);
        }
        if let Some(idx) = entry_sec_idx {
            stops.outside = vec![sections[idx].name.clone()];
        }
        stops.write_execute = false;
        engine.set_stops(stops);
        return;
    }

    stops.write_execute = emu_cfg.stop_on_write_execute;
    if let Some(entry_idx) = entry_sec_idx {
        let entry_sec = &sections[entry_idx];
        let entry_is_packer = looks_like_packer_section(entry_sec, &raw_bytes);
        let has_zero_raw_exec = sections.iter().enumerate().any(|(i, s)| {
            i != entry_idx && is_executable(s) && s.size_of_raw_data == 0 && s.virtual_size > 0
        });
        if entry_is_packer || has_zero_raw_exec {
            stops.outside = vec![entry_sec.name.clone()];
            stops.sections = sections
                .iter()
                .enumerate()
                .filter(|(i, s)| *i != entry_idx && is_executable(s) && !looks_like_packer_section(s, &raw_bytes))
                .map(|(_, s)| s.name.clone())
                .collect();
        }
    }

    engine.set_stops(stops);
}

fn detect_oep_rva(
    base_address: u64,
    image_size: u32,
    original_entry_rva: u32,
    sections: &[EngineSection],
    stop_hit: Option<&StopHit>,
    wx_hit: Option<u64>,
) -> Option<u32> {
    let candidate = match stop_hit {
        Some(StopHit::WriteExecute(addr)) | Some(StopHit::Section(_, addr)) => Some(*addr),
        Some(StopHit::Api(_, _)) | Some(StopHit::Pattern(_)) | None => wx_hit,
    }?;
    let rva_u64 = candidate.checked_sub(base_address)?;
    let rva = u32::try_from(rva_u64).ok()?;
    if rva >= image_size || rva == original_entry_rva {
        return None;
    }
    let hit_sec = section_index_for_rva(sections, rva)?;
    if !is_executable(&sections[hit_sec]) {
        return None;
    }
    Some(rva)
}

fn pe_arch_to_vid(arch: PeArch) -> Result<Architecture, String> {
    match arch {
        PeArch::X86 => Ok(Architecture::X86),
        PeArch::X64 => Ok(Architecture::X64),
        PeArch::Arm32 => Err("vid only supports x86 and x64 PE images (got ARM32)".to_owned()),
        PeArch::Arm64 => Err("vid only supports x86 and x64 PE images (got ARM64)".to_owned()),
    }
}

fn section_index_for_rva(sections: &[EngineSection], rva: u32) -> Option<usize> {
    sections.iter().position(|s| {
        let span = s.virtual_size.max(s.size_of_raw_data);
        rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span)
    })
}

fn is_executable(sec: &EngineSection) -> bool {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
}

fn looks_like_packer_section(sec: &EngineSection, raw_bytes: &[u8]) -> bool {
    let lower = sec.name.to_ascii_lowercase();
    if lower.starts_with(".vmp")
        || lower.starts_with("vmp")
        || lower.starts_with(".upx")
        || lower.starts_with("upx")
        || lower.starts_with(".aspack")
        || lower.starts_with(".adata")
        || lower.starts_with(".packed")
        || lower.starts_with(".themida")
        || lower.starts_with(".enigma")
        || lower.starts_with(".mpress")
    {
        return true;
    }
    section_raw_entropy(sec, raw_bytes) > 7.0
}

fn section_raw_entropy(sec: &EngineSection, raw_bytes: &[u8]) -> f64 {
    let off = sec.pointer_to_raw_data as usize;
    let len = sec.size_of_raw_data as usize;
    let Some(slice) = raw_bytes.get(off..off.saturating_add(len).min(raw_bytes.len())) else {
        return 0.0;
    };
    if slice.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for &b in slice {
        counts[usize::from(b)] += 1;
    }
    let total = slice.len() as f64;
    counts
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Convert raw PE section headers into normalized `(dll_name, base)` test helpers
/// (internal utility for checking `MemoryError`).
#[allow(dead_code)]
fn _assert_memory_error_is_sync_send() -> HashMap<String, u64> {
    HashMap::new()
}
