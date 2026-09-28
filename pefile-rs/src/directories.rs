#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ImportSymbol {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub address: u64,
    pub hint: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ImportDirectory {
    pub dll: String,
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub first_thunk: u32,
    pub entries: Vec<ImportSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExportSymbol {
    pub name: Option<String>,
    pub ordinal: u16,
    pub address: u32,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: Option<String>,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
    pub symbols: Vec<ExportSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceDataEntry {
    pub offset_to_data: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

/// Read an `IMAGE_RESOURCE_DATA_ENTRY` at `off`. `offset_to_data` is an RVA;
/// it is stored verbatim, like Python `pefile` does.
pub(crate) fn read_resource_data_entry(raw: &[u8], off: usize) -> Option<ResourceDataEntry> {
    let s = raw.get(off..off + 16)?;
    Some(ResourceDataEntry {
        offset_to_data: u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        size: u32::from_le_bytes([s[4], s[5], s[6], s[7]]),
        code_page: u32::from_le_bytes([s[8], s[9], s[10], s[11]]),
        reserved: u32::from_le_bytes([s[12], s[13], s[14], s[15]]),
    })
}

/// Read an `IMAGE_RESOURCE_DIR_STRING_U`: a 16-bit character count followed by
/// that many UTF-16LE code units. `offset` is relative to `base`.
pub(crate) fn read_resource_dir_string(
    raw: &[u8],
    base: usize,
    offset: u32,
) -> Option<String> {
    let file_off = (offset as usize).checked_add(base)?;
    let len_bytes = raw.get(file_off..file_off + 2)?;
    let chars = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    // Bound the string so a corrupt length cannot allocate or read unbounded.
    let chars = chars.min(4096);
    let start = file_off + 2;
    let s = raw.get(start..start + chars * 2)?;
    Some(String::from_utf16_lossy(
        &s.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<u16>>(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResourceEntry {
    Directory(Box<ResourceDirectory>),
    Data(ResourceDataEntry),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub id: u32,
    pub name: Option<String>,
    pub entries: Vec<(u32, Option<String>, ResourceEntry)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub guid_pdb_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub callbacks: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoadConfigDirectory {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RelocationBlock {
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: Vec<(u16, u16)>, // (type, offset)
}
