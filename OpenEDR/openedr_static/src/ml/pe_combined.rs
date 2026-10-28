//! PE ML feature vector v2: the file as it is (shell), what is inside it (inner), and
//! both together (combined).
//!
//! The v1 vector only describes the shell. A packed or wrapped program then looks like
//! every other packer: few imports, no IAT directory, one high-entropy section. The
//! model cannot see whether the payload is a clean tool or malware, so it learns the
//! compiler instead of the behaviour. v2 adds what is inside, kept apart from the shell
//! (a modified NSIS stub or a packer stub can be the malicious part):
//!
//! * shell  - `PeFeatureVector` of the file, plus ASCII / UTF-16LE string counts;
//! * inner  - the same for the content: the members `hydradragonextractor` pulls out of
//!   an archive or installer (NSIS, SFX, ...), else the image `hydradragonunicorn`
//!   unpacks from a packed PE; zeros when there is none;
//! * meta   - where the inner part came from (or that unpacking was tried and gave
//!   nothing usable) and how much of it there is;
//! * combined - string counts over shell and inner together (the real totals), and
//!   their ASCII / Unicode ratio.
//!
//! The trainer (`hydradragon_ml_models/pe_feature_dump`) and the engine call the same
//! `extract_pe_features_v2`, so training and scanning see the same numbers. Emulation is
//! bounded by an instruction count, not by time, so a file gives the same vector on
//! every machine.

use super::features::PeFeatureVector;
use super::pe_features::{extract_pe_features, extract_pe_mimicry, PeMimicryMetrics};
use super::pe_string_ml::{extract_inner_pe_string_ml_with_overlay, PeStringMlMetrics};

/// Strings shorter than this are not counted (`pe_strings::MIN_LEN`).
const MIN_STRING: usize = crate::pe_strings::MIN_LEN;
/// Instructions the unpacker may run on one file (deterministic bound).
pub const UNPACK_MAX_INSTRUCTIONS: usize = 20_000_000;
/// Safety stop for a file that runs very slowly per instruction (microseconds).
const UNPACK_TIMEOUT_US: u64 = 20_000_000;
/// Inner bytes looked at (all extracted members together).
const INNER_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Where the inner part came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerSource {
    None = 0,
    Unpacked = 1,
    Extracted = 2,
    /// The emulator failed the run (fault, or an API it could not return from) before
    /// the program ran code it had written: packed or not is unknown.
    UnpackFailed = 3,
    /// Not packed: the run ended cleanly and never ran code it had written, so the
    /// program is its own content. Its memory image after the run is the inner part,
    /// dumped the same way as an unpacked image, so the content model sees unpacked
    /// and not packed programs alike (not "dump = packed").
    Image = 4,
}

impl InnerSource {
    /// The inner part is the program's code as it runs (unpacked, not packed, or the
    /// program an installer / archive holds): the content model judges it.
    pub fn is_content(v: f32) -> bool {
        v == InnerSource::Unpacked as u8 as f32
            || v == InnerSource::Image as u8 as f32
            || v == InnerSource::Extracted as u8 as f32
    }
}

/// Printable ASCII runs and UTF-16LE runs of at least `MIN_STRING` characters.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringCounts {
    pub ascii: u64,
    pub utf16: u64,
}

impl StringCounts {
    pub fn of(data: &[u8]) -> Self {
        StringCounts { ascii: ascii_runs(data), utf16: utf16le_runs(data) }
    }

    fn add(self, o: StringCounts) -> Self {
        StringCounts { ascii: self.ascii + o.ascii, utf16: self.utf16 + o.utf16 }
    }

    /// `ln(1 + ascii)`, `ln(1 + utf16)`, ASCII share of all strings (0 without strings).
    fn features(self) -> [f32; 3] {
        let total = self.ascii + self.utf16;
        let ratio = if total == 0 { 0.0 } else { self.ascii as f32 / total as f32 };
        [(self.ascii as f32).ln_1p(), (self.utf16 as f32).ln_1p(), ratio]
    }
}

fn is_print(b: u8) -> bool {
    crate::pe_strings::is_print(b)
}

fn ascii_runs(data: &[u8]) -> u64 {
    let (mut n, mut run) = (0u64, 0usize);
    for &b in data {
        if is_print(b) {
            run += 1;
        } else {
            n += (run >= MIN_STRING) as u64;
            run = 0;
        }
    }
    n + (run >= MIN_STRING) as u64
}

fn utf16le_runs(data: &[u8]) -> u64 {
    // Same rule as `pe_strings::extract_utf16le`: a printable byte followed by 0x00.
    let (mut n, mut run, mut i) = (0u64, 0usize, 0usize);
    while i + 1 < data.len() {
        if data[i + 1] == 0 && data[i] != 0 && is_print(data[i]) {
            run += 1;
            i += 2;
        } else {
            n += (run >= MIN_STRING) as u64;
            run = 0;
            i += 1;
        }
    }
    n + (run >= MIN_STRING) as u64
}

/// The inner part of a PE and what is known about it.
#[derive(Debug, Clone)]
pub struct Inner {
    pub source: InnerSource,
    /// Extracted members (0 when unpacked or none).
    pub members: usize,
    /// The PE the inner features describe, as a memory image after emulation: of the
    /// largest extracted PE member, or of the file itself (unpacked or not packed).
    pub pe: Option<Vec<u8>>,
    /// Unicorn emulation behavior trace for the inner PE, when emulated.
    pub trace: Option<hydradragonsig::models::BehaviorTrace>,
    /// Strings of every extracted member (or of the unpacked image).
    pub strings: StringCounts,
    /// Inner bytes looked at.
    pub bytes: usize,
}

impl Inner {
    fn none() -> Self {
        Inner { source: InnerSource::None, members: 0, pe: None, trace: None, strings: StringCounts::default(), bytes: 0 }
    }
}

/// The PE has code: an entry point, or at least one executable section. A PE with
/// neither (`.mui` and other resource-only DLLs) does nothing; the PE model is neither
/// trained on it nor asked about it (`extract_pe_features_v2` gives `None`), as it would
/// only learn "no code = clean". A DLL without DllMain that runs from its exports has
/// executable sections and stays in. Signatures, YARA and ClamAV still scan it all.
pub fn has_code(data: &[u8]) -> bool {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    let Ok(pe) = pefile_rs::PE::parse(data) else { return false };
    pe.optional_header.address_of_entry_point != 0 || pe.sections.iter().any(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
}

/// Every PE big enough to have a packer stub is emulated: whether it was packed is
/// decided by what the code did (`unpack`), not guessed from section names or entropy,
/// which missed packers they did not list (PECompact, MPRESS, Enigma, ...) and took
/// compressed resources for packing.
pub fn should_unpack(data: &[u8]) -> bool {
    // Entry point 0: a resource-only DLL (`.mui` and the like). There is no code; the
    // emulator would run the MZ header as instructions.
    data.len() >= 0x1000 && pefile_rs::PE::parse(data).is_ok_and(|pe| pe.optional_header.address_of_entry_point != 0)
}

/// What is inside `data`: extracted members of an archive / installer first, else the
/// unpacked image of a packed PE.
pub fn inner_of(data: &[u8]) -> Inner {
    if hydradragonextractor::detect_format(data).is_some() {
        if let Ok(entries) = hydradragonextractor::extract_archive_from_bytes(data, false) {
            if !entries.is_empty() {
                let mut inner = Inner { source: InnerSource::Extracted, members: entries.len(), ..Inner::none() };
                let mut best: Option<&[u8]> = None;
                for e in &entries {
                    if inner.bytes >= INNER_MAX_BYTES {
                        break;
                    }
                    let d = &e.data[..e.data.len().min(INNER_MAX_BYTES - inner.bytes)];
                    inner.bytes += d.len();
                    inner.strings = inner.strings.add(StringCounts::of(d));
                    if e.data.starts_with(b"MZ") && best.is_none_or(|b| e.data.len() > b.len()) && extract_pe_features(&e.data).is_some() {
                        best = Some(&e.data);
                    }
                }
                // The largest PE member is the program the installer / archive holds:
                // content, like an unpacked payload. Taken as its memory image after
                // emulation, the same way as every other content image, so the content
                // model never sees "raw file vs dump" as a difference between sources.
                if let Some(emu) = best.filter(|b| should_unpack(b)).and_then(emulate) {
                    inner.pe = emu.dump.clone();
                    inner.trace = Some(emu.trace.clone());
                }
                return inner;
            }
        }
    }
    if should_unpack(data) {
        // Unpacked (ran code it had written), not packed (ran cleanly without: its own
        // image) or failed (the emulator stopped it first: unknown).
        let Some(emu) = emulate(data) else {
            return Inner::none();
        };
        let Some(image) = emu.dump.clone() else {
            return if emu.failed { Inner { source: InnerSource::UnpackFailed, ..Inner::none() } } else { Inner::none() };
        };
        let d = &image[..image.len().min(INNER_MAX_BYTES)];
        return Inner {
            source: if emu.unpacked { InnerSource::Unpacked } else { InnerSource::Image },
            members: 0,
            strings: StringCounts::of(d),
            bytes: d.len(),
            pe: extract_pe_features(&image).is_some().then_some(image),
            trace: Some(emu.trace.clone()),
        };
    }
    Inner::none()
}

/// The image `hydradragonunicorn` dumps after emulating from the entry point (`dump`). The stub
/// runs through every stage: API calls are answered by the trace-mode stubs instead of
/// ending the run (a packer allocates memory before it unpacks), there is no stop on
/// the first write-execute or at the packer configs' end address, so the run ends at
/// the instruction budget, an exit or a fault. Only when the program unpacked itself: it
/// executed code from a page of its image that it had written in this run (the
/// definition of a packer or crypter stub). A program that only writes data never does,
/// and a stub that crashes before reaching its payload has not run it either.
///
/// One emulation of a PE: that image (`dump`), the API calls it made and whether the
/// emulator failed the run.
#[derive(Debug)]
pub struct Emulation {
    /// The memory image after the run: unpacked, or the program itself when it is not
    /// packed. `None` when the emulator failed the run.
    pub dump: Option<Vec<u8>>,
    /// The program ran code it had written (`dump` is an unpacked payload).
    pub unpacked: bool,
    pub trace: hydradragonsig::models::BehaviorTrace,
    /// The emulator failed the run (fault, or an API it could not return from) before
    /// the program unpacked anything: packed or not is unknown.
    pub failed: bool,
}

thread_local! {
    /// The last emulation on this thread with its input: the ML features and the
    /// engine's unpack step look at the same file one after the other, so it is
    /// emulated once, not twice.
    /// Every caller that emulates without the unpack step right after must call
    /// `forget_emulation`: the entry holds a copy of the file, its dump and trace, and
    /// a thread that keeps one per worker held gigabytes.
    static LAST_EMULATION: std::cell::RefCell<Option<(Vec<u8>, std::rc::Rc<Emulation>)>> = const { std::cell::RefCell::new(None) };
}

/// Emulates `data` from its entry point once per file (see `LAST_EMULATION`). `None`
/// when it is not a PE the emulator can load.
pub fn emulate(data: &[u8]) -> Option<std::rc::Rc<Emulation>> {
    if let Some(hit) = LAST_EMULATION.with(|c| c.borrow().as_ref().filter(|(d, _)| d.as_slice() == data).map(|(_, e)| e.clone())) {
        return Some(hit);
    }
    let e = std::rc::Rc::new(run_emulation(data)?);
    LAST_EMULATION.with(|c| *c.borrow_mut() = Some((data.to_vec(), e.clone())));
    Some(e)
}

/// Drops the cached emulation (the engine calls it when a file is done).
pub fn forget_emulation() {
    LAST_EMULATION.with(|c| *c.borrow_mut() = None);
}

fn run_emulation(data: &[u8]) -> Option<Emulation> {
    use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
    use hydradragonunicorn::unpacker::plan::{Budget, UnpackRules};
    if !should_unpack(data) {
        return None;
    }
    // The recipe of the unpacker signature that recognises the file; a failed step
    // means the recipe does not fit this file: the generic run below.
    let budget = Budget { max_instructions: UNPACK_MAX_INSTRUCTIONS, timeout_us: UNPACK_TIMEOUT_US };
    if let Some(run) = UnpackRules::builtin().unpack(data, budget) {
        if let Some(payload) = run.main_payload() {
            return Some(Emulation { dump: Some(payload.to_vec()), unpacked: true, trace: run.trace.clone(), failed: false });
        }
    }
    let sample = Sample::from_bytes(data).ok()?;
    let ep = entrypoint(&sample.opt_header);
    let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
    eng.init_uc().ok()?;
    eng.set_controls(false, false);
    eng.set_end_addr(u64::MAX);
    let _ = eng.emu_from(ep, UNPACK_TIMEOUT_US, UNPACK_MAX_INSTRUCTIONS);
    let trace = eng.behavior_trace().clone();
    let unpacked = eng.wx_hit.is_some();
    let failed = !unpacked && !eng.end.is_clean();
    let dump = if failed { None } else { dump_image(&mut eng, ep) };
    Some(Emulation { dump, unpacked, trace, failed })
}

/// The image after the run, when the program ran code it had written.
fn dump_image(eng: &mut hydradragonunicorn::unpacker::engine::UnpackerEngine, ep: u64) -> Option<Vec<u8>> {
    // The dump's entry point is the instruction pointer at the end of the run. A run that
    // ended by jumping to 0 (a stubbed API returned a null pointer) would write 0 minus
    // the image base there; keep the file's own entry point instead.
    let (base, size) = (eng.sample.base_addr, eng.sample.virtualmemorysize);
    let is_64 = eng.sample.opt_header.magic == 0x20b;
    if let Some(uc) = eng.unicorn_mut() {
        use hydradragonunicorn::unicorn_engine::RegisterX86;
        let pc = if is_64 { RegisterX86::RIP } else { RegisterX86::EIP };
        let ip = uc.reg_read(pc as i32).unwrap_or(0);
        if ip < base || ip >= base + size {
            let _ = uc.reg_write(pc as i32, ep);
        }
    }
    let dumped = eng.dump_bytes().ok()?;
    (!dumped.is_empty()).then_some(dumped)
}

/// What kind of .NET image a PE is, from its CLR header (data directory 14) and the
/// metadata it points to: 0 = not .NET, or a CLR header whose metadata is not there
/// (no `BSJB` root: not a real managed image); 1 = IL only (`COMIMAGE_FLAGS_ILONLY`);
/// 2 = mixed mode (C++/CLI: managed metadata plus native code).
pub fn dotnet_kind(data: &[u8]) -> u8 {
    let rd16 = |o: usize| data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize);
    let rd32 = |o: usize| data.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let kind = || -> Option<u8> {
        if data.get(..2)? != b"MZ" {
            return None;
        }
        let pe = rd32(0x3c)?;
        if data.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let sections = rd16(pe + 6)?;
        let opt = pe + 24;
        let opt_size = rd16(pe + 20)?;
        let dirs = match rd16(opt)? {
            0x10b => opt + 96,
            0x20b => opt + 112,
            _ => return None,
        };
        let count = rd32(dirs - 4)?;
        if count <= 14 {
            return None;
        }
        let (clr_rva, clr_size) = (rd32(dirs + 14 * 8)?, rd32(dirs + 14 * 8 + 4)?);
        if clr_rva == 0 || clr_size < 0x48 {
            return None;
        }
        let table = opt + opt_size;
        let to_off = |rva: usize| -> Option<usize> {
            (0..sections).find_map(|i| {
                let s = table + i * 40;
                let (vsize, va, raw_size, raw) = (rd32(s + 8)?, rd32(s + 12)?, rd32(s + 16)?, rd32(s + 20)?);
                (rva >= va && rva < va + vsize.max(raw_size)).then(|| raw + (rva - va))
            })
        };
        let cor = to_off(clr_rva)?;
        let (md_rva, flags) = (rd32(cor + 8)?, rd32(cor + 16)?);
        let md = to_off(md_rva)?;
        if data.get(md..md + 4)? != b"BSJB" {
            return None;
        }
        Some(if flags & 0x1 != 0 { 1 } else { 2 })
    };
    kind().unwrap_or(0)
}

/// Shell 65 + shell strings 3 + inner 65 + inner strings 3 + meta 4 + combined strings 3
/// + shell / inner `dotnet_kind` + shell / inner `PeMimicryMetrics` + inner `PeStringMlMetrics`
/// (last, so the earlier positions stay where they were; string ML is ONLY on inner content,
/// NEVER on the outer shell model).
pub const PE_V2_FEATURE_COUNT: usize = 65 + 3 + 65 + 3 + 4 + 3 + 2 + 2 * PeMimicryMetrics::LEN + PeStringMlMetrics::LEN;
pub const PE_INNER_FEATURE_COUNT: usize = 65 + 3 + 1 + PeMimicryMetrics::LEN + PeStringMlMetrics::LEN;
pub const PE_SHELL_FEATURE_COUNT: usize = 65 + 3 + 1 + PeMimicryMetrics::LEN;
/// Where the shell / inner `PeMimicryMetrics` and inner `PeStringMlMetrics` start in the v2 vector.
const SHELL_MIMICRY: usize = 145;
const INNER_MIMICRY: usize = SHELL_MIMICRY + PeMimicryMetrics::LEN;

/// Shell-only feature set for files whose content was not successfully unpacked.
/// Does NOT include `PeStringMlMetrics` (unpacked/failed outer shells are evaluated
/// purely on structural and mimicry features).
pub fn pe_v2_shell_model_features(v: &[f32; PE_V2_FEATURE_COUNT]) -> [f32; PE_SHELL_FEATURE_COUNT] {
    let mut out = [0.0; PE_SHELL_FEATURE_COUNT];
    out[..68].copy_from_slice(&v[..68]);
    out[68] = v[143];
    out[69..].copy_from_slice(&v[SHELL_MIMICRY..INNER_MIMICRY]);
    out
}

/// Features for the dedicated successfully-unpacked PE model. Includes the inner
/// `PeStringMlMetrics` (Multron dynamic string whitelist + yarGen 2.5M benign / 2.6M
/// malicious + Unicorn trace + Disassembler strings).
pub fn extract_unpacked_inner_features(data: &[u8]) -> Option<[f32; PE_INNER_FEATURE_COUNT]> {
    let v = extract_pe_features_v2(data)?;
    (InnerSource::is_content(v[136]) && v[137] == 1.0)
        .then(|| extract_unpacked_inner_features_from_v2(&v))
}

pub fn extract_unpacked_inner_features_from_v2(v: &[f32; PE_V2_FEATURE_COUNT]) -> [f32; PE_INNER_FEATURE_COUNT] {
    let mut out = [0.0; PE_INNER_FEATURE_COUNT];
    out[..65].copy_from_slice(&v[68..133]);
    out[65..68].copy_from_slice(&v[133..136]);
    out[68] = v[144];
    out[69..].copy_from_slice(&v[INNER_MIMICRY..]);
    out
}

pub fn pe_inner_feature_names_static() -> &'static [&'static str] {
    static NAMES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        let mut names: Vec<String> = PeFeatureVector::NAMES.iter().map(|s| format!("inner_{s}")).collect();
        names.extend(["inner_ascii_strings", "inner_utf16_strings", "inner_ascii_unicode_ratio", "inner_is_dotnet"].map(String::from));
        names.extend(PeMimicryMetrics::NAMES.iter().map(|s| format!("inner_{s}")));
        names.extend(PeStringMlMetrics::NAMES.iter().map(|s| format!("inner_{s}")));
        names.into_iter().map(|s| &*Box::leak(s.into_boxed_str())).collect()
    })
}

pub fn pe_shell_feature_names_static() -> &'static [&'static str] {
    static NAMES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        let mut names: Vec<String> = PeFeatureVector::NAMES.iter().map(|s| format!("shell_{s}")).collect();
        names.extend(["shell_ascii_strings", "shell_utf16_strings", "shell_ascii_unicode_ratio", "shell_is_dotnet"].map(String::from));
        names.extend(PeMimicryMetrics::NAMES.iter().map(|s| format!("shell_{s}")));
        names.into_iter().map(|s| &*Box::leak(s.into_boxed_str())).collect()
    })
}

/// Remove outer-file influence from ML scoring when the inner PE was unpacked.
/// The raw feature extractor remains unchanged for diagnostics and training data.
/// The v2 vector of `data`; None when the file is not a PE the v1 extractor reads or a
/// PE without code (`has_code`).
pub fn extract_pe_features_v2(data: &[u8]) -> Option<[f32; PE_V2_FEATURE_COUNT]> {
    if !has_code(data) {
        return None;
    }
    let shell = extract_pe_features(data)?.to_array();
    let shell_strings = StringCounts::of(data);
    let inner = inner_of(data);
    let inner_pe = inner.pe.as_deref().and_then(extract_pe_features).map(|f| f.to_array()).unwrap_or([0.0; 65]);

    let mut v = [0f32; PE_V2_FEATURE_COUNT];
    let mut i = 0;
    let mut put = |xs: &[f32]| {
        v[i..i + xs.len()].copy_from_slice(xs);
        i += xs.len();
    };
    put(&shell);
    put(&shell_strings.features());
    put(&inner_pe);
    put(&inner.strings.features());
    put(&[
        inner.source as u8 as f32,
        inner.pe.is_some() as u8 as f32,
        (inner.members as f32).ln_1p(),
        // Inner bytes per shell byte (> 1: the content is larger than the file).
        if data.is_empty() { 0.0 } else { (inner.bytes as f32 / data.len() as f32).ln_1p() },
    ]);
    put(&shell_strings.add(inner.strings).features());
    put(&[dotnet_kind(data) as f32, inner.pe.as_deref().map_or(0.0, |p| dotnet_kind(p) as f32)]);
    let mimicry = |d: &[u8]| extract_pe_mimicry(d).unwrap_or_default().to_array();
    put(&mimicry(data));
    put(&inner.pe.as_deref().map_or([0.0; PeMimicryMetrics::LEN], mimicry));
    let extra_raw = (inner.source == InnerSource::Image).then_some(data);
    let inner_str_ml = inner
        .pe
        .as_deref()
        .map_or([0.0; PeStringMlMetrics::LEN], |p| {
            extract_inner_pe_string_ml_with_overlay(p, extra_raw, inner.trace.as_ref()).to_array()
        });
    put(&inner_str_ml);
    Some(v)
}

/// The inner PE's strings split into malicious / benign / unknown, for the report.
/// Reuses the cached emulation of `extract_pe_features_v2`, so call it before
/// `forget_emulation`. `None` when there is no inner PE (the shell model never reads strings).
pub fn pe_inner_string_breakdown(data: &[u8]) -> Option<super::pe_string_ml::PeStringBreakdown> {
    let inner = inner_of(data);
    let pe = inner.pe.as_deref()?;
    let extra_raw = (inner.source == InnerSource::Image).then_some(data);
    Some(super::pe_string_ml::classify_inner_pe_strings(pe, extra_raw, inner.trace.as_ref()))
}

/// `pe_v2_feature_names`, built once (the ML explanation keeps `&'static str` names).
pub fn pe_v2_feature_names_static() -> &'static [&'static str] {
    static NAMES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| pe_v2_feature_names().into_iter().map(|s| &*Box::leak(s.into_boxed_str())).collect())
}

/// Names in `extract_pe_features_v2` order.
pub fn pe_v2_feature_names() -> Vec<String> {
    let strings = ["ascii_strings", "utf16_strings", "ascii_unicode_ratio"];
    let mut n: Vec<String> = Vec::with_capacity(PE_V2_FEATURE_COUNT);
    n.extend(PeFeatureVector::NAMES.iter().map(|s| format!("shell_{s}")));
    n.extend(strings.iter().map(|s| format!("shell_{s}")));
    n.extend(PeFeatureVector::NAMES.iter().map(|s| format!("inner_{s}")));
    n.extend(strings.iter().map(|s| format!("inner_{s}")));
    n.extend(["inner_source", "inner_is_pe", "inner_members", "inner_size_ratio"].map(String::from));
    n.extend(strings.iter().map(|s| format!("combined_{s}")));
    n.extend(["shell_is_dotnet", "inner_is_dotnet"].map(String::from));
    n.extend(PeMimicryMetrics::NAMES.iter().map(|s| format!("shell_{s}")));
    n.extend(PeMimicryMetrics::NAMES.iter().map(|s| format!("inner_{s}")));
    n.extend(PeStringMlMetrics::NAMES.iter().map(|s| format!("inner_{s}")));
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_runs_count_ascii_and_utf16_apart() {
        let mut d = b"\x00hello world\x00ab\x00".to_vec();
        for c in "Unicode text".encode_utf16() {
            d.extend_from_slice(&c.to_le_bytes());
        }
        d.extend_from_slice(&[0, 0]);
        let s = StringCounts::of(&d);
        assert_eq!(s.ascii, 1, "hello world (ab is too short; UTF-16 bytes are not ASCII runs)");
        assert_eq!(s.utf16, 1);
        let f = s.features();
        assert!((f[2] - 0.5).abs() < 1e-6);
        assert_eq!(StringCounts::default().features(), [0.0, 0.0, 0.0]);
    }

    #[test]
    fn dotnet_kind_needs_real_metadata() {
        assert_eq!(dotnet_kind(b"not a pe"), 0);
        // Minimal PE32: one section at RVA 0x1000 / file 0x200, CLR header there,
        // metadata root right after it.
        let mut d = vec![0u8; 0x400];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        d[0x40..0x44].copy_from_slice(b"PE\0\0");
        d[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // sections
        d[0x54..0x56].copy_from_slice(&0xe0u16.to_le_bytes()); // optional header size
        let opt = 0x58;
        d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        let clr = opt + 96 + 14 * 8;
        d[clr..clr + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        d[clr + 4..clr + 8].copy_from_slice(&0x48u32.to_le_bytes());
        let sec = opt + 0xe0;
        d[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        d[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        d[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        d[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        d[0x208..0x20c].copy_from_slice(&0x1048u32.to_le_bytes()); // metadata RVA
        d[0x210..0x214].copy_from_slice(&1u32.to_le_bytes()); // ILONLY
        assert_eq!(dotnet_kind(&d), 0, "no BSJB root: not a managed image");
        d[0x248..0x24c].copy_from_slice(b"BSJB");
        assert_eq!(dotnet_kind(&d), 1);
        d[0x210..0x214].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(dotnet_kind(&d), 2, "metadata without ILONLY: mixed mode");
    }

    #[test]
    fn names_match_the_vector() {
        let names = pe_v2_feature_names();
        assert_eq!(names.len(), PE_V2_FEATURE_COUNT);
        assert_eq!(names[143], "shell_is_dotnet");
        assert_eq!(names[SHELL_MIMICRY], "shell_code_to_import_ratio");
        assert_eq!(names[INNER_MIMICRY], "inner_code_to_import_ratio");
        assert_eq!(pe_shell_feature_names_static().len(), PE_SHELL_FEATURE_COUNT);
        assert_eq!(pe_inner_feature_names_static().len(), PE_INNER_FEATURE_COUNT);
        assert!(extract_pe_features_v2(b"not a pe").is_none());
    }
}

/// Training only (`pe_feature_dump --harvest-strings`): keys of the inner PE's non-benign
/// strings, from the emulated / unpacked image. `None` when there is no inner PE.
pub fn pe_inner_harvest_keys(data: &[u8]) -> Option<Vec<u64>> {
    let inner = inner_of(data);
    let pe = inner.pe.as_deref()?;
    let extra_raw = (inner.source == InnerSource::Image).then_some(data);
    Some(super::pe_string_ml::harvest_inner_non_benign_keys(pe, extra_raw, inner.trace.as_ref()))
}
