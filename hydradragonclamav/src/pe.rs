#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeInfo {
    pub entry_point_offset: Option<usize>,
    pub sections: Vec<Section>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    pub raw_start: usize,
    pub raw_size: usize,
    pub virtual_address: u32,
    pub virtual_size: u32,
}

pub fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }

    let pe_offset = read_u32(data, 0x3c)? as usize;
    if pe_offset.checked_add(24)? > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let coff = pe_offset + 4;
    let number_of_sections = read_u16(data, coff + 2)? as usize;
    let optional_header_size = read_u16(data, coff + 16)? as usize;
    let optional = coff + 20;
    if optional.checked_add(optional_header_size)? > data.len() {
        return None;
    }

    let magic = read_u16(data, optional)?;
    if magic != 0x10b && magic != 0x20b {
        return None;
    }
    let entry_point_rva = read_u32(data, optional + 16)?;

    let section_table = optional + optional_header_size;
    let mut sections = Vec::new();
    for index in 0..number_of_sections {
        let start = section_table + index * 40;
        if start.checked_add(40)? > data.len() {
            break;
        }
        let virtual_size = read_u32(data, start + 8)?;
        let virtual_address = read_u32(data, start + 12)?;
        let raw_size = read_u32(data, start + 16)? as usize;
        let raw_start = read_u32(data, start + 20)? as usize;
        sections.push(Section {
            raw_start,
            raw_size,
            virtual_address,
            virtual_size,
        });
    }

    let entry_point_offset = rva_to_offset(entry_point_rva, &sections);
    Some(PeInfo {
        entry_point_offset,
        sections,
    })
}

pub fn rva_to_offset(rva: u32, sections: &[Section]) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size as u32);
        if rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span) {
            let delta = rva - section.virtual_address;
            return Some(section.raw_start.saturating_add(delta as usize));
        }
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
