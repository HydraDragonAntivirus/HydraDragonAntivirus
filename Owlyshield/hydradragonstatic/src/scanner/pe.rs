use crate::models::{PeInfo, PeSectionInfo};
use crate::utils::entropy::byte_entropy;
use goblin::Object;
use std::collections::HashSet;

pub fn scan_pe(bytes: &[u8]) -> Option<PeInfo> {
    let obj = Object::parse(bytes).ok()?;
    let pe = match obj {
        Object::PE(pe) => pe,
        _ => return None,
    };

    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|imp| format!("{}!{}", imp.dll, imp.name))
        .collect();

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
        let name = section.name().unwrap_or("").trim_matches('\0').to_string();
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

    let time_date_stamp = pe.header.coff_header.time_date_stamp;

    let exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|exp| exp.name.map(|n| n.to_string()))
        .collect();

    Some(PeInfo {
        arch: if pe.is_64 { "x64".into() } else { "x86".into() },
        is_64: pe.is_64,
        entry: pe.entry as u64,
        image_base: pe.image_base as u64,
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
