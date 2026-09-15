use crate::utils::calculate_entropy;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl Section {
    /// Calculate Shannon entropy for this section's raw data
    pub fn get_entropy(&self, raw_data: &[u8]) -> f64 {
        let start = self.pointer_to_raw_data as usize;
        let end = start + self.size_of_raw_data as usize;
        if start < raw_data.len() {
            let slice = &raw_data[start..end.min(raw_data.len())];
            calculate_entropy(slice)
        } else {
            0.0
        }
    }

    /// Extract raw slice of this section
    pub fn get_data<'a>(&self, raw_data: &'a [u8]) -> &'a [u8] {
        let start = self.pointer_to_raw_data as usize;
        let end = start + self.size_of_raw_data as usize;
        if start < raw_data.len() {
            &raw_data[start..end.min(raw_data.len())]
        } else {
            &[]
        }
    }

    /// Check if section is executable (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
    pub fn is_executable(&self) -> bool {
        (self.characteristics & 0x2000_0000) != 0
    }

    /// Check if section is readable (IMAGE_SCN_MEM_READ = 0x40000000)
    pub fn is_readable(&self) -> bool {
        (self.characteristics & 0x4000_0000) != 0
    }

    /// Check if section is writable (IMAGE_SCN_MEM_WRITE = 0x80000000)
    pub fn is_writable(&self) -> bool {
        (self.characteristics & 0x8000_0000) != 0
    }
}
