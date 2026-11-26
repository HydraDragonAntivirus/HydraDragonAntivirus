//! Port of `vid` (<https://github.com/colby57/vid>, MIT License, Copyright (c) 2026 vid contributors)
//! into `hydradragonunicorn` using `UnpackerEngine` (Unicorn emulator) for live unpacking,
//! memory dumping, and export resolution rather than attaching to a live Windows process.

pub mod emulator_source;
pub mod exports;
pub mod import_layout;
pub mod imports;
pub mod patches;
pub mod pe;
pub mod stub_emulator;
pub mod transfers;

use std::{
    collections::HashSet,
    error::Error,
    fmt,
    num::NonZeroUsize,
    ops::Range,
    str::FromStr,
};

use serde::Serialize;

use crate::unpacker::engine::UnpackerEngine;

pub use emulator_source::{
    dump_from_engine, emulate_and_dump, Architecture, EmulatorMemory, MemoryError, MemorySource,
    Module, SliceMemory, VidDump, VidEmulationConfig,
};
pub use exports::{ExportError, ExportIndex, ExportSymbol};
pub use import_layout::{ImportLayoutError, ImportSectionLayout, RebuiltImportPointer};
pub use imports::{
    ImportPointerReference, ImportRecoveryError, ImportScanError, ImportSymbol, PointerOperand,
    RecoveredImport, ResolvedImportPointer,
};
pub use patches::{
    AppliedPointerPatch, AppliedVmPatch, PatchError, VmImportRewrite, VmImportSemantics,
};
pub use pe::{BaseRelocationDirectory, PeError, PeFileMetadata, PeOutputError, Section};
pub use stub_emulator::{
    EmulationError, EmulationStop, GeneralRegister, MemoryAccess, RegisterReading, StubEmulator,
};
pub use transfers::{TransferError, TransferOpcode, VmTransfer};

const MAX_SECTION_NAME_BYTES: usize = 8;
const DEFAULT_STUB_INSTRUCTION_LIMIT: usize = 100_000;
const DEFAULT_VM_ENTROPY_THRESHOLD: f64 = 7.0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SectionSelector {
    Ordinal(NonZeroUsize),
    Name(String),
}

impl fmt::Display for SectionSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ordinal(ordinal) => ordinal.fmt(formatter),
            Self::Name(name) => name.fmt(formatter),
        }
    }
}

impl FromStr for SectionSelector {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
            return trimmed
                .parse::<NonZeroUsize>()
                .map(Self::Ordinal)
                .map_err(|_| "section numbers start at 1".to_owned());
        }

        validate_section_name(trimmed)?;
        Ok(Self::Name(trimmed.to_owned()))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SectionSummary {
    pub ordinal: usize,
    pub name: String,
    pub virtual_address: u32,
    pub mapped_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub permissions: String,
    pub entropy: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct VidConfig {
    /// Select 1..=3 VM sections by 1-based ordinal or case-insensitive name.
    /// When empty, auto-selects 1..=3 executable sections above `entropy_threshold`.
    pub vm_sections: Vec<SectionSelector>,
    /// Allow rebuilding conventional resolved import pointers even when no VM
    /// sections are selected/detected.
    pub allow_no_vm_sections: bool,
    /// Shannon entropy cutoff (bits/byte) for automatic VM section selection.
    pub entropy_threshold: f64,
    /// Name of the appended PE section holding the rebuilt imports (max 8 ASCII bytes).
    pub section_name: String,
    /// Explicit override for `AddressOfEntryPoint` in the output PE (otherwise uses
    /// `dump.detected_oep_rva` when unpacking detected an OEP transition).
    pub new_entry_rva: Option<u32>,
    /// Instruction limit per VM import stub emulation.
    pub stub_instruction_limit: usize,
    /// Initial Unicorn unpacking + dump configuration.
    pub emulation: VidEmulationConfig,
}

impl Default for VidConfig {
    fn default() -> Self {
        Self {
            vm_sections: Vec::new(),
            allow_no_vm_sections: false,
            entropy_threshold: DEFAULT_VM_ENTROPY_THRESHOLD,
            section_name: ".vid".to_owned(),
            new_entry_rva: None,
            stub_instruction_limit: DEFAULT_STUB_INSTRUCTION_LIMIT,
            emulation: VidEmulationConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VidReport {
    pub architecture: String,
    pub module_base: u64,
    pub image_size: u32,
    pub insn_count: u64,
    pub detected_oep_rva: Option<u32>,
    pub applied_entry_rva: Option<u32>,
    pub sections: Vec<SectionSummary>,
    pub selected_vm_sections: Vec<String>,
    pub export_addresses_indexed: usize,
    pub code_roots: usize,
    pub vm_transfers_found: usize,
    pub vm_transfers_rewritten: usize,
    pub vm_transfers_unresolved: usize,
    pub conventional_pointers_found: usize,
    pub pointer_references_found: usize,
    pub pointer_patches_applied: usize,
    pub recovered_imports: usize,
    pub recovered_modules: usize,
    pub new_section_name: String,
    pub new_section_rva: u32,
    pub new_section_size: usize,
    pub import_directory_rva: u32,
    pub import_directory_size: u32,
    pub iat_rva: u32,
    pub iat_size: u32,
    pub base_relocation_fixups: usize,
    pub output_size: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum VidError {
    InvalidConfig(String),
    Emulation(String),
    Pe(PeError),
    PeOutput(PeOutputError),
    Export(ExportError),
    Transfer(TransferError),
    ImportScan(ImportScanError),
    ImportRecovery(ImportRecoveryError),
    StubEmulation(EmulationError),
    ImportLayout(ImportLayoutError),
    Patch(PatchError),
    Selection(String),
}

impl fmt::Display for VidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(formatter, "invalid vid configuration: {msg}"),
            Self::Emulation(msg) => write!(formatter, "emulator dump failed: {msg}"),
            Self::Pe(err) => err.fmt(formatter),
            Self::PeOutput(err) => err.fmt(formatter),
            Self::Export(err) => err.fmt(formatter),
            Self::Transfer(err) => err.fmt(formatter),
            Self::ImportScan(err) => err.fmt(formatter),
            Self::ImportRecovery(err) => err.fmt(formatter),
            Self::StubEmulation(err) => err.fmt(formatter),
            Self::ImportLayout(err) => err.fmt(formatter),
            Self::Patch(err) => err.fmt(formatter),
            Self::Selection(msg) => msg.fmt(formatter),
        }
    }
}

impl Error for VidError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pe(err) => Some(err),
            Self::PeOutput(err) => Some(err),
            Self::Export(err) => Some(err),
            Self::Transfer(err) => Some(err),
            Self::ImportScan(err) => Some(err),
            Self::ImportRecovery(err) => Some(err),
            Self::StubEmulation(err) => Some(err),
            Self::ImportLayout(err) => Some(err),
            Self::Patch(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PeError> for VidError {
    fn from(value: PeError) -> Self {
        Self::Pe(value)
    }
}
impl From<PeOutputError> for VidError {
    fn from(value: PeOutputError) -> Self {
        Self::PeOutput(value)
    }
}
impl From<ExportError> for VidError {
    fn from(value: ExportError) -> Self {
        Self::Export(value)
    }
}
impl From<TransferError> for VidError {
    fn from(value: TransferError) -> Self {
        Self::Transfer(value)
    }
}
impl From<ImportScanError> for VidError {
    fn from(value: ImportScanError) -> Self {
        Self::ImportScan(value)
    }
}
impl From<ImportRecoveryError> for VidError {
    fn from(value: ImportRecoveryError) -> Self {
        Self::ImportRecovery(value)
    }
}
impl From<EmulationError> for VidError {
    fn from(value: EmulationError) -> Self {
        Self::StubEmulation(value)
    }
}
impl From<ImportLayoutError> for VidError {
    fn from(value: ImportLayoutError) -> Self {
        Self::ImportLayout(value)
    }
}
impl From<PatchError> for VidError {
    fn from(value: PatchError) -> Self {
        Self::Patch(value)
    }
}

pub fn validate_section_name(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("a PE section name cannot be empty".to_owned());
    }
    if !raw.is_ascii() || raw.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("a PE section name must contain only printable ASCII characters".to_owned());
    }
    if raw.len() > MAX_SECTION_NAME_BYTES {
        return Err(format!(
            "a PE section name cannot exceed {MAX_SECTION_NAME_BYTES} bytes"
        ));
    }
    Ok(raw.to_owned())
}

pub fn parse_rva(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    let parsed_rva =
        if let Some(hex_digits) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
        {
            u32::from_str_radix(hex_digits, 16)
        } else {
            trimmed.parse()
        };
    parsed_rva.map_err(|_| format!("`{raw}` is not a 32-bit RVA"))
}

pub fn validate_config(config: &VidConfig) -> Result<(), VidError> {
    validate_section_name(&config.section_name).map_err(VidError::InvalidConfig)?;
    if config.vm_sections.len() > 3 {
        return Err(VidError::InvalidConfig(
            "vm_sections accepts at most three sections".to_owned(),
        ));
    }
    let uses_ordinals = config
        .vm_sections
        .iter()
        .any(|s| matches!(s, SectionSelector::Ordinal(_)));
    let uses_names = config
        .vm_sections
        .iter()
        .any(|s| matches!(s, SectionSelector::Name(_)));
    if uses_ordinals && uses_names {
        return Err(VidError::InvalidConfig(
            "vm_sections must contain either numbers or names, not both".to_owned(),
        ));
    }
    if config.stub_instruction_limit == 0 {
        return Err(VidError::InvalidConfig(
            "stub_instruction_limit must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

/// Emulate/initialize the PE in `UnpackerEngine`, dump the live image from
/// Unicorn memory, and inspect all sections and their Shannon entropies.
pub fn inspect_pe_sections(
    pe_bytes: &[u8],
    module_name: &str,
    emu_cfg: &VidEmulationConfig,
) -> Result<(VidDump, Vec<SectionSummary>), VidError> {
    let dump = emulate_and_dump(pe_bytes, module_name, emu_cfg).map_err(VidError::Emulation)?;
    let summaries = summarize_dump_sections(&dump)?;
    Ok((dump, summaries))
}

/// Inspect sections directly from an initialized/emulated `UnpackerEngine`.
pub fn list_sections_from_engine(engine: &UnpackerEngine) -> Result<Vec<SectionSummary>, VidError> {
    let dump = dump_from_engine(engine, None).map_err(VidError::Emulation)?;
    summarize_dump_sections(&dump)
}

fn summarize_dump_sections(dump: &VidDump) -> Result<Vec<SectionSummary>, VidError> {
    let snapshot_mem = SliceMemory::from_single_module(
        dump.architecture,
        dump.module.base_address,
        dump.module_snapshot.clone(),
    );
    let sections = pe::read_sections(&snapshot_mem, &dump.module)?;
    Ok(sections
        .iter()
        .enumerate()
        .map(|(ordinal, section)| {
            let entropy = pe::section_entropy_from_snapshot(&dump.module_snapshot, section);
            SectionSummary {
                ordinal: ordinal + 1,
                name: section.name.clone(),
                virtual_address: section.virtual_address,
                mapped_size: section.mapped_size(),
                raw_size: section.raw_size,
                characteristics: section.characteristics,
                permissions: section_permissions(section),
                entropy,
            }
        })
        .collect())
}

/// Run the full `vid` workflow on a PE binary using `UnpackerEngine` to emulate,
/// unpack, resolve exports, dump live memory, and reconstruct imports.
pub fn emulate_dump_and_rebuild_imports(
    pe_bytes: &[u8],
    module_name: &str,
    config: &VidConfig,
) -> Result<(Vec<u8>, VidReport), VidError> {
    validate_config(config)?;
    let dump =
        emulate_and_dump(pe_bytes, module_name, &config.emulation).map_err(VidError::Emulation)?;
    rebuild_imports_from_dump(&dump, config)
}

/// Dump live memory & exports from an already-emulated `UnpackerEngine` and run
/// the `vid` protected-import reconstructor.
pub fn rebuild_imports_from_engine(
    engine: &UnpackerEngine,
    config: &VidConfig,
) -> Result<(Vec<u8>, VidReport), VidError> {
    validate_config(config)?;
    let dump = dump_from_engine(engine, None).map_err(VidError::Emulation)?;
    rebuild_imports_from_dump(&dump, config)
}

/// Reconstruct protected + conventional imports and emit a runnable PE from a `VidDump`.
pub fn rebuild_imports_from_dump(
    dump: &VidDump,
    config: &VidConfig,
) -> Result<(Vec<u8>, VidReport), VidError> {
    validate_config(config)?;

    let architecture = dump.architecture;
    let module = &dump.module;
    let mut module_snapshot = dump.module_snapshot.clone();
    let mut warnings = dump.warnings.clone();

    let snapshot_mem = SliceMemory::from_single_module(
        architecture,
        module.base_address,
        module_snapshot.clone(),
    );
    let sections = pe::read_sections(&snapshot_mem, module)?;
    let entropies = sections
        .iter()
        .map(|section| pe::section_entropy_from_snapshot(&module_snapshot, section))
        .collect::<Vec<_>>();
    let section_summaries = sections
        .iter()
        .zip(&entropies)
        .enumerate()
        .map(|(ordinal, (section, entropy))| SectionSummary {
            ordinal: ordinal + 1,
            name: section.name.clone(),
            virtual_address: section.virtual_address,
            mapped_size: section.mapped_size(),
            raw_size: section.raw_size,
            characteristics: section.characteristics,
            permissions: section_permissions(section),
            entropy: *entropy,
        })
        .collect::<Vec<_>>();

    let selected_ordinals = select_vm_sections(
        &config.vm_sections,
        config.entropy_threshold,
        config.allow_no_vm_sections,
        &sections,
        &entropies,
    )?;
    let selected_vm_sections = selected_ordinals
        .iter()
        .map(|&idx| sections[idx].name.clone())
        .collect::<Vec<_>>();

    for &ordinal in &selected_ordinals {
        let section = &sections[ordinal];
        let entropy_str = entropies[ordinal]
            .map(|e| format!("{e:.4}"))
            .unwrap_or_else(|| "unavailable".to_owned());
        log::info!(
            "VM section #{} {} | RVA 0x{:08x} | entropy {}",
            ordinal + 1,
            section.name,
            section.virtual_address,
            entropy_str
        );
    }

    let pe_file_metadata = pe::PeFileMetadata::parse(architecture, &module_snapshot)?;
    let effective_entry_rva = config.new_entry_rva.or(dump.detected_oep_rva);
    let extra_roots: Vec<u32> = effective_entry_rva.into_iter().collect();
    let code_root_rvas =
        pe_file_metadata.code_roots_with_extra(&module_snapshot, module.base_address, &extra_roots)?;

    let vm_transfers = transfers::find(
        architecture,
        module.base_address,
        &module_snapshot,
        &sections,
        &selected_ordinals,
        &code_root_rvas,
    )?;
    log::info!(
        "Discovered {} transfer(s) into selected VM sections",
        vm_transfers.len()
    );

    let export_index = &dump.export_index;
    let resolved_import_pointers = imports::find_resolved_pointers(
        architecture,
        &module_snapshot,
        &sections,
        export_index,
    )?;
    let pointer_references = imports::find_pointer_references(
        architecture,
        module.base_address,
        &module_snapshot,
        &sections,
        &selected_ordinals,
        &resolved_import_pointers,
        &code_root_rvas,
    )?;

    let mut recovered_imports = pointer_references
        .iter()
        .map(|pointer_reference| pointer_reference.destination_address)
        .collect::<HashSet<_>>()
        .into_iter()
        .filter_map(|destination_address| {
            imports::recover_import(destination_address, export_index.at(destination_address))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let emulator = StubEmulator::new(architecture, module.base_address, module_snapshot.clone())?
        .with_extra_data_regions(dump.extra_data_regions.clone());
    let instruction_limit = NonZeroUsize::new(config.stub_instruction_limit)
        .expect("validated non-zero stub instruction limit");

    let mut vm_rewrites = Vec::new();
    let mut unresolved_vm_transfers = Vec::new();

    for vm_transfer in &vm_transfers {
        let stub_address = absolute_address(module.base_address, vm_transfer.stub_rva)?;
        let return_address = vm_transfer
            .return_rva
            .map(|return_rva| absolute_address(module.base_address, return_rva))
            .transpose()?;

        match emulator.emulate_stub(stub_address, return_address, instruction_limit) {
            Ok(stop_reason) => {
                if let VmRecoveryOutcome::Unresolved {
                    destination_address,
                } = record_emulated_imports(
                    architecture,
                    *vm_transfer,
                    stop_reason,
                    export_index,
                    module,
                    &mut recovered_imports,
                    &mut vm_rewrites,
                    &mut warnings,
                )? {
                    unresolved_vm_transfers
                        .push((vm_transfer.instruction_rva, destination_address));
                }
            }
            Err(failure) => {
                warnings.push(format!(
                    "Cannot emulate VM transfer 0x{:08x}: {failure}",
                    vm_transfer.instruction_rva
                ));
                unresolved_vm_transfers.push((vm_transfer.instruction_rva, None));
            }
        }
    }

    if !unresolved_vm_transfers.is_empty() {
        let unique_destination_count = unresolved_vm_transfers
            .iter()
            .filter_map(|(_, destination_address)| *destination_address)
            .collect::<HashSet<_>>()
            .len();
        warnings.push(format!(
            "Partial VM recovery: rewritten {} of {} ({} unresolved transfer(s), {} unique destination(s))",
            vm_rewrites.len(),
            vm_transfers.len(),
            unresolved_vm_transfers.len(),
            unique_destination_count
        ));
    }

    let normalized_imports = imports::normalize_recovered_imports(recovered_imports.clone());
    validate_rebuild_readiness(normalized_imports.len(), unresolved_vm_transfers.len())?;
    let recovered_module_count = normalized_imports
        .iter()
        .map(|item| item.module_name.to_ascii_lowercase())
        .collect::<HashSet<_>>()
        .len();

    // Pass all raw recovered imports so ImportSectionLayout indexes every alias address
    // in pointer_rva_by_address onto its single deduplicated rebuilt IAT slot.
    let mut import_layout = import_layout::build(
        architecture,
        pe_file_metadata.new_section_rva(),
        &recovered_imports,
    )?;

    let vm_patches = patches::rewrite_vm_transfers(
        architecture,
        module.base_address,
        &mut module_snapshot,
        &mut import_layout,
        &vm_rewrites,
    )?;
    let unchanged_direct_rewrite_count = vm_rewrites.len().saturating_sub(vm_patches.len());
    if unchanged_direct_rewrite_count != 0 {
        warnings.push(format!(
            "Direct VM rewrites: applied {} of {} ({} left unchanged due to patch space/stack constraints)",
            vm_patches.len(),
            vm_rewrites.len(),
            unchanged_direct_rewrite_count
        ));
    }

    let pointer_references_to_rewrite =
        patches::pointer_references_outside_vm_patches(&pointer_references, &vm_patches);
    let pointer_patches = patches::rewrite_pointer_operands(
        architecture,
        module.base_address,
        &mut module_snapshot,
        &pointer_references_to_rewrite,
        &import_layout,
    )?;

    patches::verify_applied_patches(
        architecture,
        module.base_address,
        &module_snapshot,
        &pointer_patches,
        &vm_patches,
        &import_layout,
    )?;

    let base_relocation_directory =
        pe_file_metadata.append_base_relocations(&module_snapshot, &mut import_layout)?;
    let base_relocation_fixups = import_layout.base_relocation_rvas.len();

    let applied_entry_rva = effective_entry_rva;
    let output_bytes = pe_file_metadata.build_file(
        &module_snapshot,
        module.base_address,
        &config.section_name,
        applied_entry_rva,
        &import_layout,
        base_relocation_directory,
    )?;

    let report = VidReport {
        architecture: architecture.to_string(),
        module_base: module.base_address,
        image_size: module.image_size,
        insn_count: dump.insn_count,
        detected_oep_rva: dump.detected_oep_rva,
        applied_entry_rva,
        sections: section_summaries,
        selected_vm_sections,
        export_addresses_indexed: export_index.len(),
        code_roots: code_root_rvas.len(),
        vm_transfers_found: vm_transfers.len(),
        vm_transfers_rewritten: vm_patches.len(),
        vm_transfers_unresolved: unresolved_vm_transfers.len(),
        conventional_pointers_found: resolved_import_pointers.len(),
        pointer_references_found: pointer_references.len(),
        pointer_patches_applied: pointer_patches.len(),
        recovered_imports: import_layout.rebuilt_pointers.len(),
        recovered_modules: recovered_module_count,
        new_section_name: config.section_name.clone(),
        new_section_rva: pe_file_metadata.new_section_rva(),
        new_section_size: import_layout.bytes.len(),
        import_directory_rva: import_layout.import_directory_rva,
        import_directory_size: import_layout.import_directory_size,
        iat_rva: import_layout.import_address_table_rva,
        iat_size: import_layout.import_address_table_size,
        base_relocation_fixups,
        output_size: output_bytes.len(),
        warnings,
    };

    Ok((output_bytes, report))
}

#[allow(dead_code)]
fn module_snapshot_ranges(
    image_size: u32,
    sections: &[Section],
) -> Result<Vec<Range<usize>>, VidError> {
    let first_section_rva = sections
        .iter()
        .map(|section| section.virtual_address)
        .min()
        .ok_or_else(|| VidError::Selection("the selected module has no sections".to_owned()))?;
    let mut ranges = Vec::with_capacity(sections.len() + 1);
    ranges.push(0..first_section_rva as usize);

    for section in sections {
        let begin = section.virtual_address as usize;
        let end = begin
            .checked_add(section.mapped_size() as usize)
            .filter(|end| *end <= image_size as usize)
            .ok_or_else(|| {
                VidError::Selection(format!(
                    "section `{}` exceeds the module image",
                    section.name
                ))
            })?;
        if begin != end {
            ranges.push(begin..end);
        }
    }

    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged_ranges: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged_ranges.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
        } else if !range.is_empty() {
            merged_ranges.push(range);
        }
    }
    Ok(merged_ranges)
}

fn absolute_address(module_base: u64, rva: u32) -> Result<u64, VidError> {
    module_base
        .checked_add(u64::from(rva))
        .ok_or_else(|| VidError::Selection(format!("RVA 0x{rva:08x} overflows the module address")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VmRecoveryOutcome {
    Rewritten,
    Unresolved { destination_address: Option<u64> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalContinuation {
    Resume(u32),
    TailTransfer,
    Unproven,
}

#[allow(clippy::too_many_arguments)]
fn record_emulated_imports(
    architecture: Architecture,
    vm_transfer: VmTransfer,
    stop_reason: EmulationStop,
    export_index: &ExportIndex,
    module: &Module,
    recovered_imports: &mut Vec<RecoveredImport>,
    vm_rewrites: &mut Vec<VmImportRewrite>,
    warnings: &mut Vec<String>,
) -> Result<VmRecoveryOutcome, VidError> {
    let instruction_rva = vm_transfer.instruction_rva;
    match stop_reason {
        EmulationStop::ExternalTransfer {
            destination_address,
            stack_pointer_delta,
            external_return_address,
        } => {
            let export_symbols = export_index.at(destination_address);
            if export_symbols.is_empty() {
                log::debug!(
                    "VM 0x{:08x} reached unresolved address 0x{:x}",
                    instruction_rva,
                    destination_address
                );
                return Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: Some(destination_address),
                });
            }

            let resume_rva = match classify_external_continuation(
                architecture,
                vm_transfer,
                stack_pointer_delta,
                external_return_address,
                module.base_address,
                module.image_size,
            ) {
                ExternalContinuation::Resume(resume_rva) => Some(resume_rva),
                ExternalContinuation::TailTransfer => None,
                ExternalContinuation::Unproven => {
                    warnings.push(format!(
                        "VM 0x{instruction_rva:08x} has no proven continuation after reaching 0x{destination_address:x}"
                    ));
                    return Ok(VmRecoveryOutcome::Unresolved {
                        destination_address: Some(destination_address),
                    });
                }
            };
            if let Some(recovered_import) =
                imports::recover_import(destination_address, export_symbols)?
            {
                recovered_imports.push(recovered_import);
                vm_rewrites.push(VmImportRewrite {
                    transfer: vm_transfer,
                    semantics: VmImportSemantics::ExternalTransfer {
                        destination_address,
                        stack_pointer_delta,
                        resume_rva,
                    },
                });
                Ok(VmRecoveryOutcome::Rewritten)
            } else {
                Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: Some(destination_address),
                })
            }
        }
        EmulationStop::UnmappedMemory {
            access,
            address,
            byte_count,
        } => {
            warnings.push(format!(
                "VM 0x{instruction_rva:08x} stopped on unmapped {access:?} at 0x{address:x} ({byte_count} byte(s))"
            ));
            Ok(VmRecoveryOutcome::Unresolved {
                destination_address: None,
            })
        }
        EmulationStop::ReturnedToCaller {
            return_address,
            register_readings,
        } => {
            let mut resolved_registers = Vec::new();
            for register_reading in register_readings {
                let export_symbols = export_index.at(register_reading.bits);
                if export_symbols.is_empty() {
                    continue;
                }
                if let Some(recovered_import) =
                    imports::recover_import(register_reading.bits, export_symbols)?
                {
                    resolved_registers.push((register_reading, recovered_import));
                }
            }

            if resolved_registers.is_empty() {
                warnings.push(format!(
                    "VM 0x{instruction_rva:08x} returned to 0x{return_address:x} without an import in a GPR"
                ));
                Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: None,
                })
            } else if resolved_registers.len() == 1 {
                let (register_reading, recovered_import) = resolved_registers
                    .pop()
                    .expect("one resolved register was verified");
                let Some(continuation_rva) = vm_transfer.return_rva else {
                    warnings.push(format!(
                        "VM 0x{instruction_rva:08x} returned an import without a call continuation"
                    ));
                    return Ok(VmRecoveryOutcome::Unresolved {
                        destination_address: Some(register_reading.bits),
                    });
                };
                recovered_imports.push(recovered_import);
                vm_rewrites.push(VmImportRewrite {
                    transfer: vm_transfer,
                    semantics: VmImportSemantics::RegisterLoad {
                        register: register_reading.register,
                        destination_address: register_reading.bits,
                        continuation_rva,
                    },
                });
                Ok(VmRecoveryOutcome::Rewritten)
            } else {
                warnings.push(format!(
                    "VM 0x{instruction_rva:08x} returned {} resolved registers (ambiguous rewrite)",
                    resolved_registers.len()
                ));
                Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: None,
                })
            }
        }
        EmulationStop::InstructionLimit {
            instruction_address,
        } => {
            warnings.push(format!(
                "VM 0x{instruction_rva:08x} reached instruction limit at 0x{instruction_address:x}"
            ));
            Ok(VmRecoveryOutcome::Unresolved {
                destination_address: None,
            })
        }
    }
}

fn classify_external_continuation(
    architecture: Architecture,
    vm_transfer: VmTransfer,
    stack_pointer_delta: i64,
    external_return_address: u64,
    module_base: u64,
    module_size: u32,
) -> ExternalContinuation {
    if let Some(resume_rva) = external_return_address
        .checked_sub(module_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .filter(|rva| *rva < module_size)
    {
        return ExternalContinuation::Resume(resume_rva);
    }

    let pointer_size = architecture.pointer_size();
    let Ok(stack_pointer_delta) = usize::try_from(stack_pointer_delta) else {
        return ExternalContinuation::Unproven;
    };
    if !stack_pointer_delta.is_multiple_of(pointer_size) {
        return ExternalContinuation::Unproven;
    }

    match vm_transfer.opcode {
        TransferOpcode::Call if stack_pointer_delta >= pointer_size => {
            ExternalContinuation::TailTransfer
        }
        TransferOpcode::Jump => ExternalContinuation::TailTransfer,
        TransferOpcode::Call => ExternalContinuation::Unproven,
    }
}

fn validate_rebuild_readiness(
    recovered_import_count: usize,
    unresolved_transfer_count: usize,
) -> Result<(), VidError> {
    if recovered_import_count != 0 {
        return Ok(());
    }
    Err(VidError::Selection(format!(
        "no recovered imports are available | unresolved VM transfers {unresolved_transfer_count}"
    )))
}

fn section_permissions(section: &Section) -> String {
    [
        if section.is_readable() { 'R' } else { '-' },
        if section.is_writable() { 'W' } else { '-' },
        if section.is_executable() { 'X' } else { '-' },
    ]
    .into_iter()
    .collect()
}

fn select_vm_sections(
    selectors: &[SectionSelector],
    entropy_threshold: f64,
    allow_no_vm_sections: bool,
    sections: &[Section],
    entropies: &[Option<f64>],
) -> Result<Vec<usize>, VidError> {
    if selectors.is_empty() {
        let candidates = sections
            .iter()
            .zip(entropies)
            .enumerate()
            .filter_map(|(ordinal, (section, entropy))| {
                (section.is_executable()
                    && entropy
                        .is_some_and(|section_entropy| section_entropy > entropy_threshold))
                .then_some(ordinal)
            })
            .collect::<Vec<_>>();

        return match candidates.len() {
            0 if allow_no_vm_sections => Ok(Vec::new()),
            0 => Err(VidError::Selection(format!(
                "no executable section has entropy above {entropy_threshold:.1}; pass --list-sections and --vm-sections (or --allow-no-vm-sections)"
            ))),
            1..=3 => Ok(candidates),
            _ => Err(VidError::Selection(format!(
                "found {} executable sections above entropy {entropy_threshold:.1}; choose one to three with --vm-sections",
                candidates.len()
            ))),
        };
    }

    let mut selected_ordinals = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let ordinal = match selector {
            SectionSelector::Ordinal(ordinal) => ordinal
                .get()
                .checked_sub(1)
                .filter(|ordinal| *ordinal < sections.len()),
            SectionSelector::Name(name) => sections
                .iter()
                .position(|section| section.name.eq_ignore_ascii_case(name)),
        }
        .ok_or_else(|| VidError::Selection(format!("section `{selector}` does not exist")))?;

        if selected_ordinals.contains(&ordinal) {
            return Err(VidError::Selection(format!(
                "section `{selector}` was selected more than once"
            )));
        }
        if !sections[ordinal].is_executable() {
            return Err(VidError::Selection(format!(
                "section `{selector}` is not executable and cannot contain VM code"
            )));
        }
        selected_ordinals.push(ordinal);
    }

    Ok(selected_ordinals)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use iced_x86::{Decoder, DecoderOptions, Mnemonic};

    use crate::unpacker::engine::parse_pe_bytes;

    use super::*;

    #[test]
    fn validates_output_section_names_and_rva_parsing() {
        assert_eq!(validate_section_name(".vid1234").as_deref(), Ok(".vid1234"));
        assert!(validate_section_name("").is_err());
        assert!(validate_section_name(".imports2").is_err());
        assert!(validate_section_name(".bad\n").is_err());
        assert_eq!(parse_rva("4096"), Ok(0x1000));
        assert_eq!(parse_rva("0X1000"), Ok(0x1000));
        assert_eq!(parse_rva("4294967295"), Ok(u32::MAX));
        assert!(parse_rva("-1").is_err());
        assert!(parse_rva("0x100000000").is_err());
    }

    #[test]
    fn rejects_non_executable_and_mixed_vm_section_selections() {
        let sections = [
            sample_section(".text", true),
            sample_section(".vmp0", true),
            sample_section(".vmp1", true),
            sample_section(".vmp2", true),
            sample_section(".data", false),
        ];
        let entropies = [Some(5.0), Some(7.1), Some(7.2), Some(7.3), Some(8.0)];

        assert_eq!(
            select_vm_sections(&[], 7.0, false, &sections, &entropies).expect("three candidates"),
            [1, 2, 3]
        );
        assert!(
            select_vm_sections(
                &[SectionSelector::Name(".data".to_owned())],
                7.0,
                false,
                &sections,
                &entropies,
            )
            .expect_err("data is non-exec")
            .to_string()
            .contains("not executable")
        );
        assert!(
            select_vm_sections(
                &[
                    SectionSelector::Name(".VMP0".to_owned()),
                    SectionSelector::Name(".vmp0".to_owned()),
                ],
                7.0,
                false,
                &sections,
                &entropies,
            )
            .is_err()
        );
        let mixed_cfg = VidConfig {
            vm_sections: vec![
                SectionSelector::Ordinal(NonZeroUsize::new(2).unwrap()),
                SectionSelector::Name(".vmp0".to_owned()),
            ],
            ..Default::default()
        };
        assert!(validate_config(&mixed_cfg).is_err());
    }

    #[test]
    fn rejects_register_result_without_call_continuation() {
        const IMPORT_ADDRESS: u64 = 0x7654_3210;
        let export_index = sample_export_index(IMPORT_ADDRESS);
        let module = sample_module("sample.exe");
        let mut recovered_imports = Vec::new();
        let mut rewrites = Vec::new();
        let mut warnings = Vec::new();

        let outcome = record_emulated_imports(
            Architecture::X86,
            VmTransfer {
                opcode: TransferOpcode::Jump,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: None,
            },
            EmulationStop::ReturnedToCaller {
                return_address: 0x0040_1005,
                register_readings: vec![RegisterReading {
                    register: GeneralRegister::Eax,
                    bits: IMPORT_ADDRESS,
                }],
            },
            &export_index,
            &module,
            &mut recovered_imports,
            &mut rewrites,
            &mut warnings,
        )
        .expect("valid import lookup");

        assert_eq!(
            outcome,
            VmRecoveryOutcome::Unresolved {
                destination_address: Some(IMPORT_ADDRESS)
            }
        );
        assert!(recovered_imports.is_empty());
        assert!(rewrites.is_empty());
    }

    #[test]
    fn requires_stack_proof_for_external_tail_transfer() {
        let transfer = VmTransfer {
            opcode: TransferOpcode::Call,
            instruction_rva: 0x1000,
            instruction_size: 5,
            stub_rva: 0x2000,
            return_rva: Some(0x1005),
        };

        assert_eq!(
            classify_external_continuation(
                Architecture::X64,
                transfer,
                0,
                0,
                0x0000_7ff6_0000_0000,
                0x3000,
            ),
            ExternalContinuation::Unproven
        );
        assert_eq!(
            classify_external_continuation(
                Architecture::X64,
                transfer,
                8,
                0,
                0x0000_7ff6_0000_0000,
                0x3000,
            ),
            ExternalContinuation::TailTransfer
        );
    }

    #[test]
    fn snapshot_ranges_skip_unmapped_image_gaps() {
        let sections = [
            Section {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                characteristics: 0x6000_0020,
            },
            Section {
                name: ".data".to_owned(),
                virtual_address: 0x3000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                characteristics: 0xc000_0040,
            },
        ];

        assert_eq!(
            module_snapshot_ranges(0x4000, &sections).expect("valid image ranges"),
            [0..0x2000, 0x3000..0x4000]
        );
    }

    // -----------------------------------------------------------------------
    // End-to-end emulator-dump tests (UnpackerEngine executes + dumps PE)
    // -----------------------------------------------------------------------

    #[test]
    fn e2e_x64_emulator_dump_recovers_vm_and_conventional_imports() {
        let image_base = 0x14000_0000_u64;
        // .text (0x1000), .rdata (0x2000), .vmp0 (0x3000)
        // Build PE64 with original IAT for ExitProcess (0x2100) and GetCurrentProcessId (0x2108)
        let mut text = vec![0x90_u8; 0x100];
        // 0x1000: call [GetCurrentProcessId] -> FF 15 <disp32 to 0x2108> (6 bytes)
        let disp_iat1 = (0x2108_i32) - (0x1006_i32);
        text[0..2].copy_from_slice(&[0xff, 0x15]);
        text[2..6].copy_from_slice(&disp_iat1.to_le_bytes());
        // 0x1006: CS-prefixed call stub_getpid (0x3000): 2E E8 <rel32> (6 bytes -> fits call [IAT]!)
        let rel_vm1 = (0x3000_i32) - (0x100c_i32);
        text[6..8].copy_from_slice(&[0x2e, 0xe8]);
        text[8..12].copy_from_slice(&rel_vm1.to_le_bytes());
        // 0x100c: push r8 (41 50) + call stub_regload (0x3020) -> patched to mov rax, [IAT] (7 bytes? no: pop rax = 58 + call = 6 bytes? Wait: push r8 (41 50) + E8 = 7 bytes for mov r8, [IAT]!)
        // Even better: pop r8 (41 58 = 2B) + E8 rel32 (5B) = 7B -> mov r8, qword ptr [rip + disp32] (7B)!
        text[12..14].copy_from_slice(&[0x41, 0x58]); // pop r8 (register setup pattern recognized by vid)
        let rel_vm2 = (0x3020_i32) - (0x1013_i32);
        text[14] = 0xe8;
        text[15..19].copy_from_slice(&rel_vm2.to_le_bytes());
        // 0x1013: call r8 (ff d0? no r8 is 41 ff d0), then jmp stub_exit (0x3040): 6 bytes push rax + jmp? Or xor ecx, ecx; ret
        text[19] = 0xc3; // ret -> EntryReturned

        let mut vmp = vec![0xCC_u8; 0x100];
        // Stub 1 at 0x3000: jmp qword ptr [rip + (0x2108 - 0x3006)] (GetCurrentProcessId)
        vmp[0..2].copy_from_slice(&[0xff, 0x25]);
        vmp[2..6].copy_from_slice(&(0x2108_i32 - 0x3006_i32).to_le_bytes());
        // Stub 2 at 0x3020: mov r8, qword ptr [rip + (0x2100 - 0x3027)]; ret (ExitProcess)
        vmp[0x20..0x23].copy_from_slice(&[0x4c, 0x8b, 0x05]);
        vmp[0x23..0x27].copy_from_slice(&(0x2100_i32 - 0x3027_i32).to_le_bytes());
        vmp[0x27] = 0xc3;

        let pe_bytes = build_synthetic_pe64(
            image_base,
            0x1000,
            &[
                (".text", 0x1000, 0x6000_0020, &text),
                (".vmp0", 0x3000, 0x6000_0020, &vmp),
            ],
            "KERNEL32.dll",
            &["ExitProcess", "GetCurrentProcessId"],
            0x2100,
        );

        let cfg = VidConfig {
            vm_sections: vec![SectionSelector::Name(".vmp0".to_owned())],
            ..Default::default()
        };
        let (rebuilt_pe, report) =
            emulate_dump_and_rebuild_imports(&pe_bytes, "sample64.exe", &cfg)
                .expect("x64 emulator dump & vid rebuild should succeed");

        assert_eq!(report.architecture, "x64");
        assert!(report.insn_count > 0);
        assert_eq!(report.vm_transfers_found, 2);
        assert_eq!(report.vm_transfers_rewritten, 2);
        assert_eq!(report.pointer_patches_applied, 1);
        assert_eq!(report.recovered_imports, 2);

        let (_, _, opt, secs) = parse_pe_bytes(&rebuilt_pe).expect("valid rebuilt PE64");
        assert!(secs.iter().any(|s| s.name == ".vid"));
        assert_eq!(opt.data_directory[1].virtual_address, report.import_directory_rva);

        // Verify .text bytes on disk decoded cleanly
        let text_raw = secs[0].pointer_to_raw_data as usize;
        let mut decoder = Decoder::with_ip(
            64,
            &rebuilt_pe[text_raw..text_raw + 0x20],
            image_base + 0x1000,
            DecoderOptions::NONE,
        );
        let i0 = decoder.decode();
        let i1 = decoder.decode();
        let i2 = decoder.decode();
        assert_eq!(i0.mnemonic(), Mnemonic::Call);
        assert_eq!(i1.mnemonic(), Mnemonic::Call);
        assert_eq!(i2.mnemonic(), Mnemonic::Mov);
        assert!(i2.ip_rel_memory_address() >= image_base + report.iat_rva as u64);
    }

    #[test]
    fn e2e_x86_emulator_dump_recovers_imports_and_base_relocations() {
        let image_base = 0x0040_0000_u32;
        let iat0_va = image_base + 0x2100;

        let mut text = vec![0x90_u8; 0x80];
        // 0x1000: call dword ptr [iat0_va] (6 bytes) -> conventional ref
        text[0..2].copy_from_slice(&[0xff, 0x15]);
        text[2..6].copy_from_slice(&iat0_va.to_le_bytes());
        // 0x1006: CS-prefixed call stub (0x3000): 2E E8 <rel32> (6 bytes)
        let rel_vm = (0x3000_i32) - (0x100c_i32);
        text[6..8].copy_from_slice(&[0x2e, 0xe8]);
        text[8..12].copy_from_slice(&rel_vm.to_le_bytes());
        // 0x100c: ret
        text[12] = 0xc3;

        let mut vmp = vec![0xCC_u8; 0x80];
        // Stub at 0x3000: jmp dword ptr [iat0_va]
        vmp[0..2].copy_from_slice(&[0xff, 0x25]);
        vmp[2..6].copy_from_slice(&iat0_va.to_le_bytes());

        let pe_bytes = build_synthetic_pe32(
            image_base,
            0x1000,
            &[
                (".text", 0x1000, 0x6000_0020, &text),
                (".vmp0", 0x3000, 0x6000_0020, &vmp),
            ],
            "KERNEL32.dll",
            &["GetCurrentProcessId"],
            0x2100,
        );

        let cfg = VidConfig {
            vm_sections: vec![SectionSelector::Name(".vmp0".to_owned())],
            ..Default::default()
        };
        let (rebuilt_pe, report) =
            emulate_dump_and_rebuild_imports(&pe_bytes, "sample32.exe", &cfg)
                .expect("x86 emulator dump & vid rebuild should succeed");

        assert_eq!(report.architecture, "x86");
        assert_eq!(report.vm_transfers_rewritten, 1);
        assert_eq!(report.pointer_patches_applied, 1);
        assert!(report.base_relocation_fixups >= 1);

        let (_, _, opt, secs) = parse_pe_bytes(&rebuilt_pe).expect("valid rebuilt PE32");
        assert!(secs.iter().any(|s| s.name == ".vid"));
        // Base relocation directory (index 5) must be populated for x86 generated direct call
        assert_ne!(opt.data_directory[5].virtual_address, 0);
        assert_ne!(opt.data_directory[5].size, 0);
    }

    #[test]
    fn e2e_dynamic_getprocaddress_collapses_aliases_without_missing_pointer() {
        // Test via SliceMemory + ExportIndex::from_emulator simulating UnpackerEngine having
        // both initial IAT hook (0x7F00_0000) and dynamic GetProcAddress hook (0x7F08_0000)
        // for the same Windows API, verifying alias collapse onto 1 rebuilt IAT slot.
        let image_base = 0x14000_0000_u64;
        let mut snapshot = build_minimal_rva_snapshot64(image_base, 0x1000);
        // Conventional pointer at 0x2000 holds 0x7F00_0000
        snapshot[0x2000..0x2008].copy_from_slice(&0x7F00_0000_u64.to_le_bytes());
        // .text at 0x1000: call [rip + disp(0x2000)] (6B) + CS-prefixed call stub 0x3000 (6B) + ret
        snapshot[0x1000..0x1002].copy_from_slice(&[0xff, 0x15]);
        snapshot[0x1002..0x1006].copy_from_slice(&(0x2000_i32 - 0x1006_i32).to_le_bytes());
        snapshot[0x1006..0x1008].copy_from_slice(&[0x2e, 0xe8]);
        snapshot[0x1008..0x100c].copy_from_slice(&(0x3000_i32 - 0x100c_i32).to_le_bytes());
        snapshot[0x100c] = 0xc3;
        // .vmp0 stub at 0x3000 loads dynamic GetProcAddress address 0x7F08_0000:
        // mov rax, 0x7F08_0000; jmp rax
        snapshot[0x3000..0x3002].copy_from_slice(&[0x48, 0xb8]);
        snapshot[0x3002..0x300a].copy_from_slice(&0x7F08_0000_u64.to_le_bytes());
        snapshot[0x300a..0x300c].copy_from_slice(&[0xff, 0xe0]);

        let mem = SliceMemory::from_single_module(Architecture::X64, image_base, snapshot.clone());
        let mut hook_map = std::collections::HashMap::new();
        hook_map.insert(
            "kernel32.dll".to_owned(),
            vec![
                ("VirtualAlloc".to_owned(), 0x7F00_0000),
                ("virtualalloc".to_owned(), 0x7F08_0000),
            ],
        );
        let export_index = ExportIndex::from_emulator(&mem, &[], &hook_map);
        let dump = VidDump {
            architecture: Architecture::X64,
            module: Module {
                name: "dyn.exe".to_owned(),
                image_path: String::new(),
                base_address: image_base,
                image_size: snapshot.len() as u32,
            },
            module_snapshot: snapshot,
            export_index,
            detected_oep_rva: None,
            extra_data_regions: Vec::new(),
            insn_count: 10,
            emu_end: crate::unpacker::engine::EmuEnd::EntryReturned,
            stop_hit: None,
            wx_hit: None,
            warnings: Vec::new(),
        };

        let cfg = VidConfig {
            vm_sections: vec![SectionSelector::Name(".vmp0".to_owned())],
            ..Default::default()
        };
        let (rebuilt_pe, report) =
            rebuild_imports_from_dump(&dump, &cfg).expect("multi-address alias rebuild");
        assert_eq!(report.recovered_imports, 1);
        assert_eq!(report.vm_transfers_rewritten, 1);
        assert_eq!(report.pointer_patches_applied, 1);
        assert!(!rebuilt_pe.is_empty());
    }

    #[test]
    fn e2e_unpacked_zero_raw_size_section_detects_oep_and_expands_raw_bytes() {
        let image_base = 0x14000_0000_u64;
        // Build a packer PE64 where:
        // - Section 0 (".text", RVA 0x1000, VirtualSize 0x1000, SizeOfRawData = 0 on disk!)
        // - Section 1 (".rdata", RVA 0x2000, IAT at 0x2100 = ExitProcess)
        // - Section 2 (".packer", RVA 0x3000, AddressOfEntryPoint = 0x3000)
        // At runtime, .packer writes `FF 15 <disp32 to 0x2100>; C3` to RVA 0x1000 and jumps to 0x1000!
        // Because stops.outside = [".packer"] and stops.write_execute = true, Unicorn stops at 0x1000,
        // dumps unpacked .text + ExitProcess IAT, sets detected_oep_rva = Some(0x1000), repacks .text's
        // SizeOfRawData > 0 on disk, rewrites the conventional IAT reference at 0x1000, and sets EntryPoint = 0x1000!
        let disp_iat = (0x2100_i32) - (0x1006_i32);
        let disp_bytes = disp_iat.to_le_bytes();
        let unpacked_payload: [u8; 7] = [
            0xff, 0x15, disp_bytes[0], disp_bytes[1], disp_bytes[2], disp_bytes[3], 0xc3,
        ];
        let payload_qword = u64::from_le_bytes([
            unpacked_payload[0],
            unpacked_payload[1],
            unpacked_payload[2],
            unpacked_payload[3],
            unpacked_payload[4],
            unpacked_payload[5],
            unpacked_payload[6],
            0x90,
        ]);

        let mut packer = vec![0x90_u8; 0x80];
        // lea rdi, [rip + disp_to_0x1000] -> at 0x3000, len 7 -> next_ip = 0x3007 -> disp = 0x1000 - 0x3007
        let mut p = 0usize;
        packer[p..p + 3].copy_from_slice(&[0x48, 0x8d, 0x3d]);
        packer[p + 3..p + 7].copy_from_slice(&(0x1000_i32 - 0x3007_i32).to_le_bytes());
        p += 7;
        // mov rax, payload_qword
        packer[p..p + 2].copy_from_slice(&[0x48, 0xb8]);
        packer[p + 2..p + 10].copy_from_slice(&payload_qword.to_le_bytes());
        p += 10;
        // mov [rdi], rax
        packer[p..p + 3].copy_from_slice(&[0x48, 0x89, 0x07]);
        p += 3;
        // jmp rdi
        packer[p..p + 2].copy_from_slice(&[0xff, 0xe7]);

        let pe_bytes = build_synthetic_pe64_with_zero_raw_text(
            image_base,
            0x3000,
            &packer,
            "KERNEL32.dll",
            "ExitProcess",
            0x2100,
        );

        let cfg = VidConfig {
            vm_sections: vec![SectionSelector::Name(".packer".to_owned())],
            allow_no_vm_sections: true,
            ..Default::default()
        };
        let (rebuilt_pe, report) =
            emulate_dump_and_rebuild_imports(&pe_bytes, "packed64.exe", &cfg)
                .expect("packer emulation -> OEP dump -> import rebuild should succeed");

        assert_eq!(report.detected_oep_rva, Some(0x1000));
        assert_eq!(report.applied_entry_rva, Some(0x1000));
        assert_eq!(report.pointer_patches_applied, 1);

        let (_, _, opt, secs) = parse_pe_bytes(&rebuilt_pe).expect("valid unpacked PE64");
        assert_eq!(opt.address_of_entry_point, 0x1000);
        assert!(secs[0].size_of_raw_data >= 0x200);
        let raw_text_off = secs[0].pointer_to_raw_data as usize;
        assert_ne!(raw_text_off, 0);
        // .text at file offset raw_text_off must hold the unpacked & patched `call [IAT]; ret`
        assert_eq!(rebuilt_pe[raw_text_off..raw_text_off + 2], [0xff, 0x15]);
        assert_eq!(rebuilt_pe[raw_text_off + 6], 0xc3);
    }

    // -----------------------------------------------------------------------
    // Synthetic PE builders for unit tests
    // -----------------------------------------------------------------------

    fn build_minimal_rva_snapshot64(image_base: u64, entry_rva: u32) -> Vec<u8> {
        let mut buf = vec![0_u8; 0x4000];
        let nt_off = 0x80usize;
        let opt_off = nt_off + 24;
        buf[..2].copy_from_slice(b"MZ");
        buf[0x3c..0x40].copy_from_slice(&(nt_off as u32).to_le_bytes());
        buf[nt_off..nt_off + 4].copy_from_slice(b"PE\0\0");
        buf[nt_off + 4..nt_off + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
        buf[nt_off + 6..nt_off + 8].copy_from_slice(&3_u16.to_le_bytes());
        buf[nt_off + 20..nt_off + 22].copy_from_slice(&0xf0_u16.to_le_bytes());
        buf[opt_off..opt_off + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
        buf[opt_off + 24..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x4000_u32.to_le_bytes());
        buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x400_u32.to_le_bytes());
        buf[opt_off + 108..opt_off + 112].copy_from_slice(&16_u32.to_le_bytes());

        let secs_off = opt_off + 0xf0;
        write_sec_hdr(&mut buf, secs_off, ".text", 0x1000, 0x1000, 0x200, 0x400, 0x6000_0020);
        write_sec_hdr(&mut buf, secs_off + 40, ".rdata", 0x1000, 0x2000, 0x200, 0x600, 0x4000_0040);
        write_sec_hdr(&mut buf, secs_off + 80, ".vmp0", 0x1000, 0x3000, 0x200, 0x800, 0x6000_0020);
        buf
    }

    fn write_sec_hdr(
        buf: &mut [u8],
        off: usize,
        name: &str,
        vsize: u32,
        va: u32,
        rsize: u32,
        roff: u32,
        chars: u32,
    ) {
        buf[off..off + 40].fill(0);
        let n = name.as_bytes();
        buf[off..off + n.len().min(8)].copy_from_slice(&n[..n.len().min(8)]);
        buf[off + 8..off + 12].copy_from_slice(&vsize.to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
        buf[off + 16..off + 20].copy_from_slice(&rsize.to_le_bytes());
        buf[off + 20..off + 24].copy_from_slice(&roff.to_le_bytes());
        buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
    }

    fn build_rdata_imports(
        is_64: bool,
        rdata_rva: u32,
        iat_rva: u32,
        dll_name: &str,
        funcs: &[&str],
    ) -> (Vec<u8>, u32, u32) {
        let mut rdata = vec![0_u8; 0x200];
        let ptr_size = if is_64 { 8usize } else { 4usize };
        let desc_off = 0usize;
        let ilt_off = 0x40usize;
        let iat_off = (iat_rva - rdata_rva) as usize;
        let dll_off = 0x80usize;
        let mut hint_off = 0xa0usize;

        rdata[dll_off..dll_off + dll_name.len()].copy_from_slice(dll_name.as_bytes());
        // Import descriptor
        rdata[desc_off..desc_off + 4].copy_from_slice(&(rdata_rva + ilt_off as u32).to_le_bytes());
        rdata[desc_off + 12..desc_off + 16].copy_from_slice(&(rdata_rva + dll_off as u32).to_le_bytes());
        rdata[desc_off + 16..desc_off + 20].copy_from_slice(&iat_rva.to_le_bytes());

        for (i, func) in funcs.iter().enumerate() {
            let entry_rva = rdata_rva + hint_off as u32;
            rdata[hint_off + 2..hint_off + 2 + func.len()].copy_from_slice(func.as_bytes());
            hint_off = (hint_off + 2 + func.len() + 2) & !1;
            if is_64 {
                let v = (entry_rva as u64).to_le_bytes();
                rdata[ilt_off + i * ptr_size..ilt_off + (i + 1) * ptr_size].copy_from_slice(&v);
                rdata[iat_off + i * ptr_size..iat_off + (i + 1) * ptr_size].copy_from_slice(&v);
            } else {
                let v = entry_rva.to_le_bytes();
                rdata[ilt_off + i * ptr_size..ilt_off + (i + 1) * ptr_size].copy_from_slice(&v);
                rdata[iat_off + i * ptr_size..iat_off + (i + 1) * ptr_size].copy_from_slice(&v);
            }
        }
        (rdata, rdata_rva, 40)
    }

    fn build_synthetic_pe64(
        image_base: u64,
        entry_rva: u32,
        exec_sections: &[(&str, u32, u32, &[u8])],
        dll_name: &str,
        funcs: &[&str],
        iat_rva: u32,
    ) -> Vec<u8> {
        let (rdata, imp_rva, imp_size) = build_rdata_imports(true, 0x2000, iat_rva, dll_name, funcs);
        let mut secs: Vec<(&str, u32, u32, Vec<u8>)> = vec![(
            exec_sections[0].0,
            exec_sections[0].1,
            exec_sections[0].2,
            exec_sections[0].3.to_vec(),
        )];
        secs.push((".rdata", 0x2000, 0x4000_0040, rdata));
        for &(n, va, ch, b) in &exec_sections[1..] {
            secs.push((n, va, ch, b.to_vec()));
        }

        let header_size = 0x400usize;
        let sec_raw_size = 0x200usize;
        let total = header_size + secs.len() * sec_raw_size;
        let mut pe = vec![0_u8; total];
        let nt_off = 0x80usize;
        let opt_off = nt_off + 24;
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(nt_off as u32).to_le_bytes());
        pe[nt_off..nt_off + 4].copy_from_slice(b"PE\0\0");
        pe[nt_off + 4..nt_off + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
        pe[nt_off + 6..nt_off + 8].copy_from_slice(&(secs.len() as u16).to_le_bytes());
        pe[nt_off + 20..nt_off + 22].copy_from_slice(&0xf0_u16.to_le_bytes());
        pe[nt_off + 22..nt_off + 24].copy_from_slice(&0x0022_u16.to_le_bytes());

        pe[opt_off..opt_off + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        pe[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
        pe[opt_off + 24..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
        pe[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[opt_off + 36..opt_off + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        let max_va = secs.iter().map(|s| s.1 + 0x1000).max().unwrap_or(0x2000);
        pe[opt_off + 56..opt_off + 60].copy_from_slice(&max_va.to_le_bytes());
        pe[opt_off + 60..opt_off + 64].copy_from_slice(&(header_size as u32).to_le_bytes());
        pe[opt_off + 68..opt_off + 70].copy_from_slice(&3_u16.to_le_bytes()); // CONSOLE
        pe[opt_off + 108..opt_off + 112].copy_from_slice(&16_u32.to_le_bytes());
        let dd_off = opt_off + 112;
        pe[dd_off + 8..dd_off + 12].copy_from_slice(&imp_rva.to_le_bytes());
        pe[dd_off + 12..dd_off + 16].copy_from_slice(&imp_size.to_le_bytes());

        let secs_hdr = opt_off + 0xf0;
        for (i, (name, va, ch, bytes)) in secs.iter().enumerate() {
            let roff = (header_size + i * sec_raw_size) as u32;
            write_sec_hdr(&mut pe, secs_hdr + i * 40, name, 0x1000, *va, sec_raw_size as u32, roff, *ch);
            let copy_len = bytes.len().min(sec_raw_size);
            pe[roff as usize..roff as usize + copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        pe
    }

    fn build_synthetic_pe32(
        image_base: u32,
        entry_rva: u32,
        exec_sections: &[(&str, u32, u32, &[u8])],
        dll_name: &str,
        funcs: &[&str],
        iat_rva: u32,
    ) -> Vec<u8> {
        let (rdata, imp_rva, imp_size) = build_rdata_imports(false, 0x2000, iat_rva, dll_name, funcs);
        let mut secs: Vec<(&str, u32, u32, Vec<u8>)> = vec![(
            exec_sections[0].0,
            exec_sections[0].1,
            exec_sections[0].2,
            exec_sections[0].3.to_vec(),
        )];
        secs.push((".rdata", 0x2000, 0x4000_0040, rdata));
        for &(n, va, ch, b) in &exec_sections[1..] {
            secs.push((n, va, ch, b.to_vec()));
        }

        let header_size = 0x400usize;
        let sec_raw_size = 0x200usize;
        let total = header_size + secs.len() * sec_raw_size;
        let mut pe = vec![0_u8; total];
        let nt_off = 0x80usize;
        let opt_off = nt_off + 24;
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(nt_off as u32).to_le_bytes());
        pe[nt_off..nt_off + 4].copy_from_slice(b"PE\0\0");
        pe[nt_off + 4..nt_off + 6].copy_from_slice(&0x014c_u16.to_le_bytes());
        pe[nt_off + 6..nt_off + 8].copy_from_slice(&(secs.len() as u16).to_le_bytes());
        pe[nt_off + 20..nt_off + 22].copy_from_slice(&0xe0_u16.to_le_bytes());
        pe[nt_off + 22..nt_off + 24].copy_from_slice(&0x0102_u16.to_le_bytes());

        pe[opt_off..opt_off + 2].copy_from_slice(&0x10b_u16.to_le_bytes());
        pe[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
        pe[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
        pe[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[opt_off + 36..opt_off + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        let max_va = secs.iter().map(|s| s.1 + 0x1000).max().unwrap_or(0x2000);
        pe[opt_off + 56..opt_off + 60].copy_from_slice(&max_va.to_le_bytes());
        pe[opt_off + 60..opt_off + 64].copy_from_slice(&(header_size as u32).to_le_bytes());
        pe[opt_off + 68..opt_off + 70].copy_from_slice(&3_u16.to_le_bytes());
        pe[opt_off + 92..opt_off + 96].copy_from_slice(&16_u32.to_le_bytes());
        let dd_off = opt_off + 96;
        pe[dd_off + 8..dd_off + 12].copy_from_slice(&imp_rva.to_le_bytes());
        pe[dd_off + 12..dd_off + 16].copy_from_slice(&imp_size.to_le_bytes());

        let secs_hdr = opt_off + 0xe0;
        for (i, (name, va, ch, bytes)) in secs.iter().enumerate() {
            let roff = (header_size + i * sec_raw_size) as u32;
            write_sec_hdr(&mut pe, secs_hdr + i * 40, name, 0x1000, *va, sec_raw_size as u32, roff, *ch);
            let copy_len = bytes.len().min(sec_raw_size);
            pe[roff as usize..roff as usize + copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        pe
    }

    fn build_synthetic_pe64_with_zero_raw_text(
        image_base: u64,
        entry_rva: u32,
        packer_code: &[u8],
        dll_name: &str,
        func_name: &str,
        iat_rva: u32,
    ) -> Vec<u8> {
        let (rdata, imp_rva, imp_size) = build_rdata_imports(true, 0x2000, iat_rva, dll_name, &[func_name]);
        let header_size = 0x400usize;
        let sec_raw_size = 0x200usize;
        // .text has SizeOfRawData = 0; .rdata at 0x400; .packer at 0x600
        let mut pe = vec![0_u8; header_size + 2 * sec_raw_size];
        let nt_off = 0x80usize;
        let opt_off = nt_off + 24;
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(nt_off as u32).to_le_bytes());
        pe[nt_off..nt_off + 4].copy_from_slice(b"PE\0\0");
        pe[nt_off + 4..nt_off + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
        pe[nt_off + 6..nt_off + 8].copy_from_slice(&3_u16.to_le_bytes());
        pe[nt_off + 20..nt_off + 22].copy_from_slice(&0xf0_u16.to_le_bytes());
        pe[nt_off + 22..nt_off + 24].copy_from_slice(&0x0022_u16.to_le_bytes());

        pe[opt_off..opt_off + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        pe[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
        pe[opt_off + 24..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
        pe[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[opt_off + 36..opt_off + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[opt_off + 56..opt_off + 60].copy_from_slice(&0x4000_u32.to_le_bytes());
        pe[opt_off + 60..opt_off + 64].copy_from_slice(&(header_size as u32).to_le_bytes());
        pe[opt_off + 68..opt_off + 70].copy_from_slice(&3_u16.to_le_bytes());
        pe[opt_off + 108..opt_off + 112].copy_from_slice(&16_u32.to_le_bytes());
        let dd_off = opt_off + 112;
        pe[dd_off + 8..dd_off + 12].copy_from_slice(&imp_rva.to_le_bytes());
        pe[dd_off + 12..dd_off + 16].copy_from_slice(&imp_size.to_le_bytes());

        let secs_hdr = opt_off + 0xf0;
        write_sec_hdr(&mut pe, secs_hdr, ".text", 0x1000, 0x1000, 0, 0, 0xE000_0020);
        write_sec_hdr(&mut pe, secs_hdr + 40, ".rdata", 0x1000, 0x2000, sec_raw_size as u32, 0x400, 0x4000_0040);
        write_sec_hdr(&mut pe, secs_hdr + 80, ".packer", 0x1000, 0x3000, sec_raw_size as u32, 0x600, 0x6000_0020);
        pe[0x400..0x400 + rdata.len().min(sec_raw_size)].copy_from_slice(&rdata[..rdata.len().min(sec_raw_size)]);
        pe[0x600..0x600 + packer_code.len().min(sec_raw_size)]
            .copy_from_slice(&packer_code[..packer_code.len().min(sec_raw_size)]);
        pe
    }

    fn sample_export_index(address: u64) -> ExportIndex {
        let mut export_index = ExportIndex::default();
        export_index.insert(
            address,
            ExportSymbol {
                module_name: "KERNEL32.dll".to_owned(),
                name: Some("GetVersion".to_owned()),
                ordinal: 1,
                forwarded: false,
            },
        );
        export_index
    }

    fn sample_module(name: &str) -> Module {
        Module {
            name: name.to_owned(),
            image_path: name.to_owned(),
            base_address: 0x0040_0000,
            image_size: 0x5000,
        }
    }

    fn sample_section(name: &str, executable: bool) -> Section {
        Section {
            name: name.to_owned(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_size: 0x1000,
            characteristics: if executable { 0x6000_0020 } else { 0x4000_0040 },
        }
    }
}
