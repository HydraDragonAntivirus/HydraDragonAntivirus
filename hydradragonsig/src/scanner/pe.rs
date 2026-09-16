use crate::models::{PeInfo, PeSectionInfo};
use crate::utils::entropy::byte_entropy;
use std::collections::HashSet;

pub fn scan_pe(bytes: &[u8]) -> Option<PeInfo> {
    let pe = pefile_rs::PE::parse(bytes).ok()?;

    let mut imports: Vec<String> = Vec::new();
    for dir in &pe.imports {
        for sym in &dir.entries {
            let name = sym.name.clone().unwrap_or_else(|| {
                sym.ordinal.map(|o| format!("ord{o}")).unwrap_or_default()
            });
            if name.is_empty() {
                continue;
            }
            imports.push(format!("{}!{}", dir.dll, name));
        }
    }

    let dlls: Vec<String> = imports
        .iter()
        .filter_map(|s| s.split_once('!').map(|(dll, _)| dll.to_ascii_lowercase()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let suspicious_imports: Vec<String> = Vec::new();

    let mut sections = Vec::new();
    let mut suspicious_sections = Vec::new();
    for section in &pe.sections {
        let name = section.name.trim_matches('\0').to_string();
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let entropy = if start < bytes.len() {
            let end = start.saturating_add(size).min(bytes.len());
            byte_entropy(&bytes[start..end])
        } else {
            0.0
        };
        if entropy >= 7.20
            || name.starts_with("UPX")
            || name.starts_with(".packed")
            || name.is_empty()
        {
            suspicious_sections.push(format!(
                "{} entropy={:.3}",
                if name.is_empty() { "<empty>" } else { &name },
                entropy
            ));
        }
        sections.push(PeSectionInfo {
            name,
            virtual_size: section.virtual_size as u64,
            raw_size: section.size_of_raw_data as u64,
            entropy,
            characteristics: section.characteristics,
        });
    }

    let likely_packed = suspicious_sections.len() >= 2
        || sections.iter().any(|s| s.name.starts_with("UPX"))
        || (sections.len() <= 3 && sections.iter().any(|s| s.entropy >= 7.40));

    let time_date_stamp = pe.file_header.time_date_stamp;

    let exports: Vec<String> = pe
        .exports
        .iter()
        .flat_map(|exp| exp.symbols.iter())
        .filter_map(|sym| sym.name.clone())
        .collect();

    Some(PeInfo {
        arch: if pe.is_64bit { "x64".into() } else { "x86".into() },
        is_64: pe.is_64bit,
        entry: pe.optional_header.address_of_entry_point as u64,
        image_base: pe.optional_header.image_base,
        imports,
        exports,
        dlls,
        suspicious_imports,
        sections,
        suspicious_sections,
        likely_packed,
        time_date_stamp,
    })
}
