//! `.NET`, ELF, Mach-O and PDF conditions over the structures of
//! `scanner::{dotnet, elf, macho, pdf}`. Each structure is parsed once per
//! scan, the first time a condition (or a feature / decoded-string read)
//! needs it, and only for files of that format.

use super::engine::cached_regex;
use super::types::{PeSectionSelect, RuleCondition};
use crate::models::ScanReport;
use crate::scanner::{dotnet, elf, macho, pdf};

/// Which structures this scan already tried to parse, and the decoded PDF
/// streams (kept out of the report).
#[derive(Debug, Default)]
pub struct FormatCache {
    dotnet: bool,
    elf: bool,
    macho: bool,
    pdf: bool,
    pub pdf_streams: pdf::PdfStreams,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    DotNet,
    Elf,
    Macho,
    Pdf,
}

/// The structure a condition reads.
pub fn condition_format(cond: &RuleCondition) -> Option<Format> {
    use RuleCondition::*;
    Some(match cond {
        DotnetGuidAny { .. } | DotnetTypeRegex { .. } | DotnetMethodRegex { .. } | DotnetPinvokeAny { .. } | DotnetPinvokeSet { .. }
        | DotnetStreamAny { .. } | DotnetUserStringRegex { .. } => Format::DotNet,
        ElfImportAny { .. } | ElfImportSet { .. } | ElfImportRegex { .. } | ElfExportAny { .. } | ElfExportSet { .. }
        | ElfNeededAny { .. } | ElfSection { .. } | ElfSegment { .. } | ElfBuildIdAny { .. } | NewElfImportSet { .. } => Format::Elf,
        MachoDylibAny { .. } | MachoSymAny { .. } | MachoSymRegex { .. } | MachoSegment { .. } | MachoUuidAny { .. }
        | MachoSigned { .. } | MachoEntitlementAny { .. } => Format::Macho,
        PdfKeyword { .. } | PdfStreamMatch { .. } => Format::Pdf,
        _ => return None,
    })
}

impl FormatCache {
    /// Parse `format` into the report if the file is of that format (once per scan).
    pub fn ensure(&mut self, format: Format, report: &mut ScanReport, bytes: &[u8]) {
        match format {
            Format::DotNet if !self.dotnet => {
                self.dotnet = true;
                if report.dotnet.is_none() {
                    report.dotnet = dotnet::parse_dotnet(bytes);
                }
            }
            Format::Elf if !self.elf => {
                self.elf = true;
                if report.elf.is_none() && elf::is_elf(bytes) {
                    report.elf = elf::parse_elf(bytes);
                }
            }
            Format::Macho if !self.macho => {
                self.macho = true;
                if report.macho.is_none() && macho::is_macho(bytes) {
                    report.macho = macho::parse_macho(bytes);
                }
            }
            Format::Pdf if !self.pdf => {
                self.pdf = true;
                if report.pdf.is_none() && let Some((info, streams)) = pdf::parse_pdf(bytes) {
                    report.pdf = Some(info);
                    self.pdf_streams = streams;
                }
            }
            _ => {}
        }
    }

    /// Every structure of the file's format (features, decoded strings, `entrypoint`).
    pub fn ensure_all(&mut self, report: &mut ScanReport, bytes: &[u8]) {
        if dotnet::has_clr_metadata(bytes) {
            self.ensure(Format::DotNet, report, bytes);
        }
        if elf::is_elf(bytes) {
            self.ensure(Format::Elf, report, bytes);
        }
        if macho::is_macho(bytes) {
            self.ensure(Format::Macho, report, bytes);
        }
        if pdf::header_offset(bytes).is_some() {
            self.ensure(Format::Pdf, report, bytes);
        }
    }
}

/// Decoded strings the structures contribute: `#US` strings (`dotnet_us`, 8+
/// characters, 4096 entries / 1 MiB at most), Mach-O entitlements
/// (`macho_entitlements`) and PDF payloads (`pdf_js`, `pdf_uri`, `pdf_launch`,
/// `pdf_stream`).
pub fn decoded_strings(report: &ScanReport, cache: &FormatCache) -> Vec<crate::models::DecodedString> {
    let mut out = Vec::new();
    if let Some(d) = &report.dotnet {
        let mut total = 0usize;
        for s in d.user_strings.iter().filter(|s| s.chars().count() >= 8) {
            if out.len() >= 4096 || total + s.len() > 1024 * 1024 {
                break;
            }
            total += s.len();
            out.push(crate::models::DecodedString { method: "dotnet_us".into(), source: "#US".into(), decoded: s.clone() });
        }
    }
    if let Some(m) = &report.macho {
        for xml in m.slices.iter().filter_map(|s| s.signature.as_ref()?.entitlements_xml.as_ref()) {
            out.push(crate::models::DecodedString { method: "macho_entitlements".into(), source: "LC_CODE_SIGNATURE".into(), decoded: xml.clone() });
        }
    }
    if let Some(p) = &report.pdf {
        out.extend(pdf::decoded_strings(p, &cache.pdf_streams));
    }
    out
}

fn needed(min: Option<usize>) -> usize {
    min.unwrap_or(1).max(1)
}

/// `names` found in `list` by `matches(entry, name)`: the entries that matched.
fn set_hits<'a>(list: &'a [String], names: &[String], matches: impl Fn(&str, &str) -> bool) -> Vec<&'a str> {
    names.iter().filter_map(|n| list.iter().find(|e| matches(e, n)).map(String::as_str)).collect()
}

fn suffix_nocase(entry: &str, name: &str) -> bool {
    entry.to_ascii_lowercase().ends_with(&name.to_ascii_lowercase())
}

fn regex_hits<'a>(lists: &[&'a [String]], pattern: &str) -> Option<Vec<&'a str>> {
    let re = cached_regex(pattern)?;
    Some(lists.iter().flat_map(|l| l.iter()).filter(|s| re.is_match(s)).map(String::as_str).collect())
}

fn sample(hits: &[&str]) -> String {
    hits.iter().take(3).copied().collect::<Vec<_>>().join(", ")
}

fn range_entropy(bytes: &[u8], off: u64, size: u64) -> Option<f64> {
    let start = usize::try_from(off).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?.min(bytes.len());
    (start < end).then(|| crate::utils::entropy::byte_entropy(&bytes[start..end]))
}

pub fn evaluate(cond: &RuleCondition, report: &ScanReport, cache: &FormatCache, bytes: &[u8]) -> Option<String> {
    use RuleCondition::*;
    match cond {
        DotnetGuidAny { values } => {
            let d = report.dotnet.as_ref()?;
            [("mvid", &d.mvid), ("typelib", &d.typelib)].into_iter().find_map(|(what, g)| {
                let g = g.as_deref()?;
                let norm = dotnet::normalize_guid(g);
                values.iter().any(|v| dotnet::normalize_guid(v) == norm).then(|| format!("dotnet_guid_any {what} {g}"))
            })
        }
        DotnetTypeRegex { pattern, min } => {
            let d = report.dotnet.as_ref()?;
            let hits = regex_hits(&[&d.types, &d.type_refs], pattern)?;
            (hits.len() >= needed(*min)).then(|| format!("dotnet_type_regex `{pattern}` matched {}: {}", hits.len(), sample(&hits)))
        }
        DotnetMethodRegex { pattern, min } => {
            let d = report.dotnet.as_ref()?;
            let hits = regex_hits(&[&d.methods, &d.member_refs], pattern)?;
            (hits.len() >= needed(*min)).then(|| format!("dotnet_method_regex `{pattern}` matched {}: {}", hits.len(), sample(&hits)))
        }
        DotnetPinvokeAny { names } => {
            let d = report.dotnet.as_ref()?;
            let hits = set_hits(&d.pinvokes, names, suffix_nocase);
            hits.first().map(|h| format!("dotnet_pinvoke_any matched {h}"))
        }
        DotnetPinvokeSet { names, min } => {
            let d = report.dotnet.as_ref()?;
            let hits = set_hits(&d.pinvokes, names, suffix_nocase);
            (hits.len() >= needed(*min)).then(|| format!("dotnet_pinvoke_set matched {}/{}: {}", hits.len(), needed(*min), hits.join(", ")))
        }
        DotnetStreamAny { names } => {
            let d = report.dotnet.as_ref()?;
            d.streams
                .iter()
                .find(|(s, _)| names.iter().any(|n| n.eq_ignore_ascii_case(s)))
                .map(|(s, size)| format!("dotnet_stream_any {s} ({size} bytes)"))
        }
        DotnetUserStringRegex { pattern, min } => {
            let d = report.dotnet.as_ref()?;
            let hits = regex_hits(&[&d.user_strings], pattern)?;
            (hits.len() >= needed(*min)).then(|| format!("dotnet_user_string_regex `{pattern}` matched {}: {}", hits.len(), sample(&hits)))
        }
        ElfImportAny { names } => {
            let e = report.elf.as_ref()?;
            set_hits(&e.imports, names, |a, b| a == b).first().map(|h| format!("elf_import_any matched {h}"))
        }
        ElfImportSet { names, min } | ElfExportSet { names, min } => {
            let e = report.elf.as_ref()?;
            let (what, list) = if matches!(cond, ElfImportSet { .. }) { ("elf_import_set", &e.imports) } else { ("elf_export_set", &e.exports) };
            let hits = set_hits(list, names, |a, b| a == b);
            (hits.len() >= needed(*min)).then(|| format!("{what} matched {}/{}: {}", hits.len(), needed(*min), hits.join(", ")))
        }
        ElfImportRegex { pattern, min } => {
            let e = report.elf.as_ref()?;
            let hits = regex_hits(&[&e.imports], pattern)?;
            (hits.len() >= needed(*min)).then(|| format!("elf_import_regex `{pattern}` matched {}: {}", hits.len(), sample(&hits)))
        }
        ElfExportAny { names } => {
            let e = report.elf.as_ref()?;
            set_hits(&e.exports, names, |a, b| a == b).first().map(|h| format!("elf_export_any matched {h}"))
        }
        ElfNeededAny { names, nocase } => {
            let e = report.elf.as_ref()?;
            let hit = set_hits(&e.needed, names, |a, b| if *nocase { a.eq_ignore_ascii_case(b) } else { a == b });
            hit.first().map(|h| format!("elf_needed_any matched {h}"))
        }
        ElfBuildIdAny { values } => {
            let e = report.elf.as_ref()?;
            let id = e.build_id.as_deref()?;
            values.iter().any(|v| v.trim().eq_ignore_ascii_case(id)).then(|| format!("elf_build_id_any {id}"))
        }
        NewElfImportSet { names, min } => {
            let parent = report.parent.as_ref()?;
            let e = report.elf.as_ref()?;
            let hits: Vec<&str> = set_hits(&e.imports, names, |a, b| a == b).into_iter().filter(|h| !parent.elf_imports.iter().any(|p| p == h)).collect();
            (hits.len() >= needed(*min)).then(|| format!("new_elf_import_set {}/{} not in parent: {}", hits.len(), needed(*min), hits.join(", ")))
        }
        ElfSection { .. } => elf_section(cond, report.elf.as_ref()?, bytes),
        ElfSegment { seg_type, flags_all, flags_none, memsz_minus_filesz_min, entropy_min } => {
            let e = report.elf.as_ref()?;
            let want_type = match seg_type {
                Some(t) => Some(elf::segment_type(t)?),
                None => None,
            };
            e.segments.iter().enumerate().find_map(|(i, s)| {
                let gap = s.memsz.saturating_sub(s.filesz);
                let ok = want_type.is_none_or(|t| t == s.p_type)
                    && crate::scanner::bin::flags_hold(u64::from(s.flags), flags_all, flags_none, elf::segment_flag)
                    && memsz_minus_filesz_min.is_none_or(|m| gap >= m)
                    && entropy_min.is_none_or(|m| range_entropy(bytes, s.offset, s.filesz).is_some_and(|h| h >= m));
                ok.then(|| format!("elf_segment #{i} type 0x{:x} flags 0x{:x} filesz {} memsz {}", s.p_type, s.flags, s.filesz, s.memsz))
            })
        }
        MachoDylibAny { names } => {
            let m = report.macho.as_ref()?;
            m.slices.iter().find_map(|s| set_hits(&s.dylibs, names, suffix_nocase).first().map(|h| format!("macho_dylib_any matched {h} ({})", s.arch)))
        }
        MachoSymAny { names, min } => {
            let m = report.macho.as_ref()?;
            m.slices.iter().find_map(|s| {
                let hits = set_hits(&s.symbols, names, |a, b| a == b || a.strip_prefix('_') == Some(b));
                (hits.len() >= needed(*min)).then(|| format!("macho_sym_any matched {}/{} ({}): {}", hits.len(), needed(*min), s.arch, hits.join(", ")))
            })
        }
        MachoSymRegex { pattern, min } => {
            let m = report.macho.as_ref()?;
            m.slices.iter().find_map(|s| {
                let hits = regex_hits(&[&s.symbols], pattern)?;
                (hits.len() >= needed(*min)).then(|| format!("macho_sym_regex `{pattern}` matched {} ({}): {}", hits.len(), s.arch, sample(&hits)))
            })
        }
        MachoSegment { name, flags_all, flags_none, entropy_min, entropy_max } => {
            let m = report.macho.as_ref()?;
            m.slices.iter().find_map(|sl| {
                sl.segments.iter().find_map(|g| {
                    let entropy = || range_entropy(bytes, sl.offset.saturating_add(g.fileoff), g.filesize);
                    let ok = name.as_ref().is_none_or(|n| n == &g.name)
                        && crate::scanner::bin::flags_hold(u64::from(g.initprot), flags_all, flags_none, macho::prot_flag)
                        && entropy_min.is_none_or(|m| entropy().is_some_and(|h| h >= m))
                        && entropy_max.is_none_or(|m| entropy().is_some_and(|h| h <= m));
                    ok.then(|| format!("macho_segment {} ({}) initprot {} maxprot {}", g.name, sl.arch, g.initprot, g.maxprot))
                })
            })
        }
        MachoUuidAny { values } => {
            let m = report.macho.as_ref()?;
            m.slices.iter().filter_map(|s| s.uuid.as_deref()).find_map(|u| {
                let norm = dotnet::normalize_guid(u);
                values.iter().any(|v| dotnet::normalize_guid(v) == norm).then(|| format!("macho_uuid_any {u}"))
            })
        }
        MachoSigned { signed, adhoc, identifier_glob, team_id } => {
            let m = report.macho.as_ref()?;
            m.slices.iter().find_map(|s| {
                let sig = s.signature.as_ref().filter(|g| g.signed);
                if sig.is_some() != *signed {
                    return None;
                }
                if let Some(sig) = sig {
                    if adhoc.is_some_and(|a| a != sig.adhoc)
                        || identifier_glob.as_ref().is_some_and(|g| !sig.identifier.as_deref().is_some_and(|i| super::glob::glob_match(g, i)))
                        || team_id.as_ref().is_some_and(|t| sig.team_id.as_deref() != Some(t.as_str()))
                    {
                        return None;
                    }
                    return Some(format!(
                        "macho_signed ({}): {} identifier {} team {}",
                        s.arch,
                        if sig.adhoc { "ad-hoc" } else { "authority" },
                        sig.identifier.as_deref().unwrap_or("-"),
                        sig.team_id.as_deref().unwrap_or("-")
                    ));
                }
                (adhoc.is_none() && identifier_glob.is_none() && team_id.is_none()).then(|| format!("macho_signed ({}): unsigned", s.arch))
            })
        }
        MachoEntitlementAny { keys } => {
            let m = report.macho.as_ref()?;
            m.slices.iter().filter_map(|s| s.signature.as_ref()).find_map(|sig| {
                set_hits(&sig.entitlement_keys, keys, |a, b| a == b).first().map(|k| format!("macho_entitlement_any {k}"))
            })
        }
        PdfKeyword { names, min } => {
            let p = report.pdf.as_ref()?;
            let hits: Vec<String> = names
                .iter()
                .filter_map(|n| {
                    let c = p.name_count(n);
                    (c > 0).then(|| format!("/{}x{c}", n.trim_start_matches('/')))
                })
                .collect();
            (hits.len() >= needed(*min)).then(|| format!("pdf_keyword matched {}/{}: {}", hits.len(), needed(*min), hits.join(", ")))
        }
        PdfStreamMatch { filter_any, patterns, decoded, min } => {
            report.pdf.as_ref()?;
            let compiled: Vec<(&String, Option<std::sync::Arc<super::engine::CompiledBytePattern>>)> = patterns
                .iter()
                .map(|p| (p, if p.trim_start().starts_with('{') { super::engine::cached_byte_pattern(p) } else { None }))
                .collect();
            let streams: Vec<&pdf::PdfStream> = cache
                .pdf_streams
                .streams
                .iter()
                .filter(|s| {
                    filter_any.as_ref().is_none_or(|want| want.iter().any(|w| s.filters.iter().any(|f| f.eq_ignore_ascii_case(w.trim_start_matches('/')))))
                })
                .collect();
            let mut hits = Vec::new();
            for (p, byte_pattern) in &compiled {
                let found = streams.iter().find_map(|s| {
                    let hay: &[u8] = if *decoded { &s.decoded } else { bytes.get(s.raw.clone()).unwrap_or(&[]) };
                    let at = match byte_pattern {
                        Some(bp) => super::engine::find_byte_pattern(hay, bp),
                        None if p.trim_start().starts_with('{') => None,
                        None => memchr::memmem::find(hay, p.as_bytes()),
                    };
                    at.map(|o| format!("`{p}` in obj {} at +0x{o:x}", s.object))
                });
                hits.extend(found);
            }
            (hits.len() >= needed(*min)).then(|| format!("pdf_stream_match {}/{}: {}", hits.len(), needed(*min), hits.join(", ")))
        }
        _ => None,
    }
}

fn elf_section(cond: &RuleCondition, e: &elf::ElfInfo, bytes: &[u8]) -> Option<String> {
    let RuleCondition::ElfSection { select, index, name, name_regex, flags_all, flags_none, entropy_min, entropy_max, size_min, size_max, md5, sha256 } =
        cond
    else {
        return None;
    };
    let re = match name_regex {
        Some(p) => Some(cached_regex(p)?),
        None => None,
    };
    let candidates: Vec<usize> = match select {
        PeSectionSelect::Any => (0..e.sections.len()).collect(),
        PeSectionSelect::Last => e.sections.len().checked_sub(1).into_iter().collect(),
        PeSectionSelect::Entry => e.entry_section().into_iter().collect(),
    };
    candidates.into_iter().filter(|i| index.is_none_or(|x| x == *i)).find_map(|i| {
        let s = &e.sections[i];
        // SHT_NOBITS (.bss) has no file bytes.
        let raw = || {
            if s.sh_type == 8 {
                return Some(&bytes[0..0]);
            }
            let start = usize::try_from(s.offset).ok()?;
            bytes.get(start..start.checked_add(usize::try_from(s.size).ok()?)?)
        };
        let ok = name.as_ref().is_none_or(|n| n == &s.name)
            && re.as_ref().is_none_or(|r| r.is_match(&s.name))
            && crate::scanner::bin::flags_hold(s.flags, flags_all, flags_none, elf::section_flag)
            && size_min.is_none_or(|m| s.size >= m)
            && size_max.is_none_or(|m| s.size <= m)
            && entropy_min.is_none_or(|m| raw().is_some_and(|r| crate::utils::entropy::byte_entropy(r) >= m))
            && entropy_max.is_none_or(|m| raw().is_some_and(|r| crate::utils::entropy::byte_entropy(r) <= m))
            && md5.as_ref().is_none_or(|h| raw().is_some_and(|r| crate::utils::hash::md5_hex(r).eq_ignore_ascii_case(h.trim())))
            && sha256.as_ref().is_none_or(|h| raw().is_some_and(|r| crate::utils::hash::sha256_hex(r).eq_ignore_ascii_case(h.trim())));
        ok.then(|| format!("elf_section #{i} {} flags 0x{:x} size {}", s.name, s.flags, s.size))
    })
}

#[cfg(test)]
mod tests {
    use crate::ScanOptions;
    use crate::models::{MemoryScanContext, ParentInfo, ScanReport};
    use crate::rules::RuleSet;
    use crate::scanner::{dotnet, elf, macho, pdf};

    fn scan_with(bytes: Vec<u8>, yaml: &str, parent: Option<ParentInfo>) -> ScanReport {
        let rules = RuleSet::from_yaml_str_strict(yaml).expect("rules");
        let ctx = MemoryScanContext { buffer: bytes, identifier: "sample".into(), base_address: None };
        let options = ScanOptions { stop_on_detection: false, parent, ..ScanOptions::default() };
        crate::scan_memory(&ctx, &rules, &options).expect("scan")
    }

    /// Matched rule ids, sorted.
    fn matched(report: &ScanReport) -> Vec<&str> {
        let mut ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        ids.sort_unstable();
        ids
    }

    fn sorted<'a>(ids: &[&'a str]) -> Vec<&'a str> {
        let mut v = ids.to_vec();
        v.sort_unstable();
        v
    }

    /// One rule per condition, so each can be checked on its own.
    fn rules(conds: &[(&str, &str)]) -> String {
        let mut y = String::from("rules:\n");
        for (id, cond) in conds {
            y.push_str(&format!("  - id: {id}\n    title: {id}\n    severity: low\n    conditions:\n"));
            for line in cond.lines() {
                y.push_str(&format!("      {line}\n"));
            }
        }
        y
    }

    #[test]
    fn dotnet_conditions_features_and_us_strings() {
        let typelib = "d1e2f3a4-0000-4000-8000-123456789abc";
        let pe = dotnet::tests::build_dotnet_pe(&["http://evil.example/payload", "short"], typelib);
        let yaml = rules(&[
            ("GUID", "- type: dotnet_guid_any\n  values: [\"{D1E2F3A4-0000-4000-8000-123456789ABC}\"]"),
            ("MVID", "- type: dotnet_guid_any\n  values: [04030201-0605-0807-090a-0b0c0d0e0f10]"),
            ("NO_GUID", "- type: dotnet_guid_any\n  values: [00000000-0000-0000-0000-000000000000]"),
            ("TYPE", "- type: dotnet_type_regex\n  pattern: '^Evil\\.'"),
            ("TYPEREF", "- type: dotnet_type_regex\n  pattern: 'InteropServices\\.GuidAttribute$'"),
            ("TYPE_MIN", "- type: dotnet_type_regex\n  pattern: '.'\n  min: 4"),
            ("METHOD", "- type: dotnet_method_regex\n  pattern: 'Loader::Run$'"),
            ("PINVOKE", "- type: dotnet_pinvoke_any\n  names: [VirtualAlloc]"),
            ("PINVOKE_SET", "- type: dotnet_pinvoke_set\n  names: [kernel32.dll!VirtualAlloc, WriteProcessMemory]\n  min: 1"),
            ("PINVOKE_SET2", "- type: dotnet_pinvoke_set\n  names: [kernel32.dll!VirtualAlloc, WriteProcessMemory]\n  min: 2"),
            ("STREAM", "- type: dotnet_stream_any\n  names: ['#GUID']"),
            ("CONFUSER", "- type: dotnet_stream_any\n  names: ['#Confuser']"),
            ("US", "- type: dotnet_user_string_regex\n  pattern: 'evil\\.example/'"),
            (
                "FEATURES",
                "- type: feature_bounds\n  bounds:\n    - {feature: dotnet_pinvoke_count, min: 1}\n    - {feature: dotnet_type_count, min: 2}\n    - {feature: dotnet_stream_count, min: 5, max: 5}",
            ),
            ("TYPE_TAG", "- type: file_type\n  values: [dotnet]"),
            ("DECODED", "- type: string_regex\n  pattern: '^http://evil\\.example/payload$'\n  decoded: true"),
        ]);
        let report = scan_with(pe, &yaml, None);
        assert_eq!(matched(&report), sorted(&["GUID", "MVID", "TYPE", "TYPEREF", "METHOD", "PINVOKE", "PINVOKE_SET", "STREAM", "US", "FEATURES", "TYPE_TAG", "DECODED"])
        );
        assert!(report.file_type.tags.iter().any(|t| t == "dotnet"));
        let us: Vec<&str> = report.decoded_strings.iter().filter(|d| d.method == "dotnet_us").map(|d| d.decoded.as_str()).collect();
        assert_eq!(us, ["http://evil.example/payload"], "8+ characters only");
        assert_eq!(report.features["dotnet_method_count"], serde_json::json!(1));
        // A file that is not .NET skips the rules.
        let report = scan_with(b"MZ not a dotnet file".to_vec(), &yaml, None);
        assert!(matched(&report).is_empty());
    }

    #[test]
    fn elf_conditions_and_parent_import_diff() {
        let child = elf::tests::build_elf64(&["mprotect", "dlopen"]);
        let yaml = rules(&[
            ("IMPORTS", "- type: elf_import_set\n  names: [mprotect, dlopen]\n  min: 2"),
            ("IMPORT_ANY", "- type: elf_import_any\n  names: [ptrace, dlopen]"),
            ("IMPORT_RE", "- type: elf_import_regex\n  pattern: '^mpro'"),
            ("EXPORT", "- type: elf_export_any\n  names: [run_payload]"),
            ("EXPORT_SET", "- type: elf_export_set\n  names: [run_payload, other]\n  min: 2"),
            ("NEEDED", "- type: elf_needed_any\n  names: [LIBDL.SO.2]\n  nocase: true"),
            ("NEEDED_CASE", "- type: elf_needed_any\n  names: [LIBDL.SO.2]"),
            ("RWX_LOAD", "- type: elf_segment\n  seg_type: load\n  flags_all: [w, x]\n  memsz_minus_filesz_min: 4096"),
            ("EXEC_STACK", "- type: elf_segment\n  seg_type: gnu_stack\n  flags_all: [x]"),
            ("BUILD_ID", "- type: elf_build_id_any\n  values: [DEADBEEF01020304]"),
            ("ENTRY_TEXT", "- type: elf_section\n  select: entry\n  name: .text\n  flags_all: [exec, alloc]\n  flags_none: [write]"),
            ("SECTION_HASH", "- type: elf_section\n  name: .text\n  md5: e5d0af9f935e480b3ec82ca05c126f46"),
            ("FEATURES", "- type: feature_bounds\n  bounds:\n    - {feature: elf_rwx_segment_count, min: 1}\n    - {feature: elf_import_count, min: 2}"),
            ("NEW_IMPORT", "- type: new_elf_import_set\n  names: [dlopen, mprotect]"),
            ("NEW_IMPORT2", "- type: new_elf_import_set\n  names: [dlopen, mprotect]\n  min: 2"),
        ]);
        let parent = ParentInfo::from_bytes("packed", &elf::tests::build_elf64(&["mprotect"]));
        assert_eq!(parent.elf_imports, ["mprotect"]);
        let report = scan_with(child.clone(), &yaml, Some(parent));
        assert_eq!(matched(&report), sorted(&[
                "IMPORTS", "IMPORT_ANY", "IMPORT_RE", "EXPORT", "NEEDED", "RWX_LOAD", "EXEC_STACK", "BUILD_ID", "ENTRY_TEXT", "SECTION_HASH",
                "FEATURES", "NEW_IMPORT"
            ])
        );
        // Without a parent the diff condition does not match.
        let report = scan_with(child, &yaml, None);
        assert!(!matched(&report).contains(&"NEW_IMPORT"));
    }

    #[test]
    fn macho_thin_and_fat_with_entitlements() {
        let ents = ["com.apple.security.cs.disable-library-validation", "com.apple.security.get-task-allow"];
        let thin = macho::tests::build_macho64(macho::CPU_TYPE_ARM64, &ents);
        let x64 = macho::tests::build_macho64(0x0100_0007, &[]);
        let fat = macho::tests::build_fat(&[(0x0100_0007, x64), (macho::CPU_TYPE_ARM64, thin.clone())]);
        let yaml = rules(&[
            ("DYLIB", "- type: macho_dylib_any\n  names: [libsystem.b.dylib]"),
            ("UUID", "- type: macho_uuid_any\n  values: [000102030405060708090A0B0C0D0E0F]"),
            ("ENT", "- type: macho_entitlement_any\n  keys: [com.apple.security.cs.disable-library-validation]"),
            ("SIGNED", "- type: macho_signed\n  signed: true\n  adhoc: true\n  identifier_glob: 'com.evil.*'\n  team_id: TEAM123456"),
            ("NOT_AUTHORITY", "- type: macho_signed\n  signed: true\n  adhoc: false"),
            ("RWX", "- type: macho_segment\n  flags_all: [w, x]"),
            ("TEXT_RX", "- type: macho_segment\n  name: __TEXT\n  flags_all: [r, x]\n  flags_none: [w]"),
            ("SYM", "- type: macho_sym_any\n  names: [ptrace, main]\n  min: 2"),
            ("SYM_RE", "- type: macho_sym_regex\n  pattern: '^_pt'"),
            ("FEATURES", "- type: feature_bounds\n  bounds:\n    - {feature: macho_rwx_segment_count, min: 1}\n    - {feature: macho_dylib_count, min: 1}"),
            ("DECODED", "- type: string_regex\n  pattern: '<key>com\\.apple\\.security\\.get-task-allow</key>'\n  decoded: true"),
        ]);
        for (what, bytes) in [("thin", thin), ("fat", fat)] {
            let report = scan_with(bytes, &yaml, None);
            assert!(report.file_type.is_macho, "{what}");
            assert_eq!(matched(&report), sorted(&["DYLIB", "UUID", "ENT", "SIGNED", "RWX", "TEXT_RX", "SYM", "SYM_RE", "FEATURES", "DECODED"]), "{what}");
            assert!(
                report.decoded_strings.iter().any(|d| d.method == "macho_entitlements" && d.decoded.contains("get-task-allow")),
                "{what}"
            );
        }
    }

    #[test]
    fn pdf_obfuscated_keywords_streams_and_bomb() {
        let js = "this.exportDataObject({cName: 'x', nLaunch: 2}); eval(unescape('%u4141'));";
        let bytes = pdf::tests::build_pdf(js, 40 * 1024 * 1024);
        let yaml = rules(&[
            ("KEYWORDS", "- type: pdf_keyword\n  names: [JavaScript, JS, OpenAction]\n  min: 3"),
            ("EMBEDDED", "- type: pdf_keyword\n  names: [/EmbeddedFiles]"),
            ("LAUNCH", "- type: pdf_keyword\n  names: [Launch, XFA]"),
            ("STREAM_JS", "- type: pdf_stream_match\n  filter_any: [FlateDecode]\n  patterns: [exportDataObject, '{ 75 6E 65 73 63 61 70 65 }']\n  min: 2"),
            ("STREAM_RAW", "- type: pdf_stream_match\n  patterns: [exportDataObject]\n  decoded: false"),
            ("STREAM_FILTER", "- type: pdf_stream_match\n  filter_any: [ASCIIHexDecode]\n  patterns: [exportDataObject]"),
            (
                "FEATURES",
                "- type: feature_bounds\n  bounds:\n    - {feature: pdf_js_count, min: 1}\n    - {feature: pdf_openaction_count, min: 1}\n    - {feature: pdf_stream_count, min: 2}\n    - {feature: pdf_uri_count, min: 1}",
            ),
            ("DECODED_JS", "- type: string_regex\n  pattern: 'exportDataObject'\n  decoded: true"),
        ]);
        let report = scan_with(bytes, &yaml, None);
        assert!(report.file_type.is_pdf, "junk before the header");
        assert_eq!(matched(&report), sorted(&["KEYWORDS", "EMBEDDED", "STREAM_JS", "FEATURES", "DECODED_JS"]));
        assert!(report.pdf.as_ref().unwrap().truncated, "the bomb stream stops at the cap");
        assert!(report.decoded_strings.iter().any(|d| d.method == "pdf_js" && d.decoded == js));
        assert!(report.decoded_strings.iter().any(|d| d.method == "pdf_uri"));
    }

    #[test]
    fn strict_validation_of_format_conditions() {
        for (cond, why) in [
            ("- type: dotnet_guid_any\n  values: [not-a-guid]", "not a GUID"),
            ("- type: dotnet_type_regex\n  pattern: '[a-'", "invalid regex"),
            ("- type: dotnet_method_regex\n  pattern: x\n  min: 0", "at least 1"),
            ("- type: dotnet_pinvoke_set\n  names: [a]\n  min: 2", "larger than"),
            ("- type: dotnet_stream_any\n  names: [Confuser]", "start with `#`"),
            ("- type: dotnet_user_string_regex\n  pattern: x\n  extra: 1", "unknown key `extra`"),
            ("- type: elf_import_set\n  names: []", "empty `names`"),
            ("- type: elf_section\n  flags_all: [rwx]", "unknown ELF section flag"),
            ("- type: elf_section\n  entropy_min: 7\n  entropy_max: 2", "never matches"),
            ("- type: elf_section\n  size_min: 9\n  size_max: 1", "never matches"),
            ("- type: elf_section\n  md5: abc", "32 hex"),
            ("- type: elf_section\n  select: last", "matches every ELF"),
            ("- type: elf_segment\n  seg_type: bogus", "unknown segment type"),
            ("- type: elf_segment\n  flags_all: [q]", "unknown ELF segment flag"),
            ("- type: elf_build_id_any\n  values: [abc]", "even number"),
            ("- type: new_elf_import_set\n  names: [a]\n  min: 0", "min: 0"),
            ("- type: macho_segment\n  entropy_min: 9", "outside 0..8"),
            ("- type: macho_segment\n  flags_none: [rw]", "unknown segment protection"),
            ("- type: macho_signed\n  signed: false\n  adhoc: true", "never matches"),
            ("- type: macho_uuid_any\n  values: ['1234']", "not a GUID"),
            ("- type: macho_sym_regex\n  pattern: '('", "invalid regex"),
            ("- type: macho_entitlement_any\n  keys: []", "empty `keys`"),
            ("- type: pdf_keyword\n  names: [JS]\n  min: 3", "larger than"),
            ("- type: pdf_stream_match\n  patterns: ['{ 4G }']", "invalid byte pattern"),
            ("- type: pdf_stream_match\n  patterns: [x]\n  filter_any: [Fl]", "unknown PDF filter"),
            ("- type: feature_gte\n  name: pdf_bogus_count\n  value: 1", "unknown feature"),
            ("- type: parent_feature_gte\n  name: macho_dylib_count\n  value: 1", "unknown parent feature"),
        ] {
            let yaml = rules(&[("BAD", cond)]);
            let err = match RuleSet::from_yaml_str_strict(&yaml) {
                Ok(_) => panic!("accepted: {cond}"),
                Err(e) => format!("{e:#}"),
            };
            assert!(err.contains(why), "{cond}: {err}");
        }
        assert!(RuleSet::from_yaml_str_strict(&rules(&[("OK", "- type: elf_segment\n  seg_type: '0x6474e551'\n  flags_all: [exec]")])).is_ok());
    }
}
