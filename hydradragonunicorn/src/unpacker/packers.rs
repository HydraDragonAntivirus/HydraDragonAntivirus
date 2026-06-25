// hydradragonheur/src/unpacker/packers.rs
// Port of Python Unipacker's unpackers.py — packer identification and unpacker configuration.

use crate::filetype::pe_file::SectionHeader;
use crate::unpacker::error::{UnpackerError, UnpackerResult};
use yara_x::{Rules, Scanner};

/// Default path to the compiled YARA rules file.
pub const DEFAULT_YARA_PATH: &str = "packer_signatures.yrc";

// ---------------------------------------------------------------------------
// Section — our own section descriptor with u64-sized address fields
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub size_of_raw_data: u64,
    pub pointer_to_raw_data: u64,
    pub characteristics: u32,
}

impl From<&SectionHeader> for Section {
    fn from(s: &SectionHeader) -> Self {
        Section {
            name: s.name.clone(),
            virtual_address: s.virtual_address as u64,
            virtual_size: s.virtual_size as u64,
            size_of_raw_data: s.raw_size as u64,
            pointer_to_raw_data: s.raw_offset as u64,
            characteristics: s.characteristics,
        }
    }
}

// ---------------------------------------------------------------------------
// DumperType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumperType {
    Default,
    ImportRebuilder,
    PEtite,
    MEW,
    YZPack,
}

// ---------------------------------------------------------------------------
// UnpackerConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UnpackerConfig {
    pub name: String,
    pub base_addr: u64,
    pub ep: u64,
    pub startaddr: Option<u64>,
    pub endaddr: u64,
    pub allowed_sections: Vec<String>,
    pub allowed_addr_ranges: Vec<(u64, u64)>,
    pub section_hopping_control: bool,
    pub write_execute_control: bool,
    pub virtualmemorysize: Option<u64>,
    pub secs: Vec<Section>,
    pub dumper_type: DumperType,
    pub allocated_chunks: Vec<(u64, u64)>,
}

// Type aliases matching the re-exports in mod.rs
pub type Unpacker = UnpackerConfig;
pub type DefaultUnpacker = UnpackerConfig;

// ---------------------------------------------------------------------------
// Helpers to convert SectionHeader slices
// ---------------------------------------------------------------------------

fn to_sections(secs: &[SectionHeader]) -> Vec<Section> {
    secs.iter().map(Section::from).collect()
}

fn section_names(secs: &[SectionHeader]) -> Vec<String> {
    secs.iter().map(|s| s.name.clone()).collect()
}

// ---------------------------------------------------------------------------
// Packer factory functions
// ---------------------------------------------------------------------------

/// Generic unpacker — minimal restrictions; can execute anywhere.
pub fn create_default_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "default".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: true,
        write_execute_control: true,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// Automatic default — same as default with a slightly larger end address.
pub fn create_automatic_default_unpacker(
    secs: &[SectionHeader],
    base_addr: u64,
    ep: u64,
) -> UnpackerConfig {
    UnpackerConfig {
        name: "automatic_default".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x2_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: true,
        write_execute_control: true,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// UPX packer — allows all sections, disables section hopping and write-execute control.
pub fn create_upx_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "upx".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// PEtite packer — uses the PEtite dumper.
pub fn create_petite_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "petite".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::PEtite,
        allocated_chunks: vec![],
    }
}

/// ASPack packer.
pub fn create_aspack_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "aspack".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// FSG packer.
pub fn create_fsg_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "fsg".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// YZPack packer — uses the YZPack dumper.
pub fn create_yzpack_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "yzpack".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::YZPack,
        allocated_chunks: vec![],
    }
}

/// MEW packer — uses the MEW dumper.
pub fn create_mew_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "mew".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::MEW,
        allocated_chunks: vec![],
    }
}

/// VMProtect packer — LZMA-static unpacked, just needs relaxed emulation.
pub fn create_vmprotect_unpacker(
    secs: &[SectionHeader],
    base_addr: u64,
    ep: u64,
) -> UnpackerConfig {
    UnpackerConfig {
        name: "vmprotect".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x2_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// MPRESS packer.
pub fn create_mpress_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "mpress".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// PECOMPACT packer.
pub fn create_pecompact_unpacker(
    secs: &[SectionHeader],
    base_addr: u64,
    ep: u64,
) -> UnpackerConfig {
    UnpackerConfig {
        name: "pecompact".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

/// UPack packer.
pub fn create_upack_unpacker(secs: &[SectionHeader], base_addr: u64, ep: u64) -> UnpackerConfig {
    UnpackerConfig {
        name: "upack".into(),
        base_addr,
        ep,
        startaddr: None,
        endaddr: base_addr + 0x1_0000,
        allowed_sections: section_names(secs),
        allowed_addr_ranges: vec![],
        section_hopping_control: false,
        write_execute_control: false,
        virtualmemorysize: None,
        secs: to_sections(secs),
        dumper_type: DumperType::Default,
        allocated_chunks: vec![],
    }
}

// ---------------------------------------------------------------------------
// Address / section helper functions
// ---------------------------------------------------------------------------

/// Check whether `address` is allowed by `cfg` (inside an allowed section or
/// address range).
pub fn is_allowed(cfg: &UnpackerConfig, address: u64) -> bool {
    for &(lo, hi) in &cfg.allowed_addr_ranges {
        if address >= lo && address < hi {
            return true;
        }
    }
    let sec_name = get_section(cfg, address);
    cfg.allowed_sections.contains(&sec_name)
}

/// Return the name of the section containing `address`, or an empty string.
pub fn get_section(cfg: &UnpackerConfig, address: u64) -> String {
    for s in &cfg.secs {
        if address >= s.virtual_address
            && address < s.virtual_address + s.virtual_size.max(s.size_of_raw_data)
        {
            return s.name.clone();
        }
    }
    String::new()
}

/// Return the VA range `(start, end)` for the section named `name`, or
/// `None` if no such section exists.
pub fn get_section_range(cfg: &UnpackerConfig, name: &str) -> Option<(u64, u64)> {
    for s in &cfg.secs {
        if s.name == name {
            let end = s.virtual_address + s.virtual_size.max(s.size_of_raw_data);
            return Some((s.virtual_address, end));
        }
    }
    None
}

/// Return all address ranges from `cfg` that are allowed for execution.
pub fn get_allowed_addr_ranges(cfg: &UnpackerConfig) -> Vec<(u64, u64)> {
    cfg.allowed_addr_ranges.clone()
}

// ---------------------------------------------------------------------------
// YARA-based packer identification
// ---------------------------------------------------------------------------

/// Known packer names we look for in YARA rule identifiers.
const PACKER_NAMES: &[&str] = &[
    "upx", "petite", "mew", "mpress", "aspack", "fsg", "pecompact", "upack", "yzpack", "vmprotect",
];

/// Identify the packer used by a PE file by scanning it with YARA rules.
///
/// Returns a tuple `(packer_name, matched_rule_names)` where `packer_name` is
/// one of `"default"`, `"upx"`, `"petite"`, `"mew"`, `"mpress"`, `"aspack"`,
/// `"fsg"`, `"pecompact"`, `"upack"`, or `"yzpack"`.
fn scan_with_rules(file_data: &[u8], rules: &Rules) -> UnpackerResult<(String, Vec<String>)> {
    let mut scanner = Scanner::new(rules);
    let results = scanner
        .scan(file_data)
        .map_err(|e| UnpackerError::YaraError(e.to_string()))?;

    let mut matches: Vec<String> = Vec::new();
    let mut packer_name = String::from("default");
    let mut is_pe32 = false;

    for rule in results.matching_rules() {
        let rule_name = rule.identifier();
        matches.push(rule_name.to_string());

        let lower = rule_name.to_lowercase();

        if lower.contains("pe32") {
            is_pe32 = true;
        }

        for &pname in PACKER_NAMES {
            if lower.contains(pname) {
                packer_name = pname.to_string();
                break;
            }
        }
    }

    if !is_pe32 {
        return Err(UnpackerError::InvalidPeFile(
            "no PE32 YARA rule matched — not a PE32 file".into(),
        ));
    }

    Ok((packer_name, matches))
}

/// Identify packer from a file path + compiled .yrc file.
pub fn identify_packer(file_path: &str, yara_path: &str) -> UnpackerResult<(String, Vec<String>)> {
    let yrc_bytes = std::fs::read(yara_path)?;
    let file_data = std::fs::read(file_path)?;
    let rules = Rules::deserialize(&yrc_bytes)
        .map_err(|e| UnpackerError::YaraError(e.to_string()))?;
    scan_with_rules(&file_data, &rules)
}

/// Identify packer from raw file bytes + compiled .yrc bytes.
/// Useful when the .yrc is embedded in the binary via include_bytes!.
pub fn identify_packer_from_bytes(
    file_data: &[u8],
    yrc_bytes: &[u8],
) -> UnpackerResult<(String, Vec<String>)> {
    let rules = Rules::deserialize(yrc_bytes)
        .map_err(|e| UnpackerError::YaraError(e.to_string()))?;
    scan_with_rules(file_data, &rules)
}
