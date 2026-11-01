//! Dynamic Multron Server String Whitelist + yarGen Benign / Malicious
//! String ML Feature Extractor for Unpacked / Content PE Models (`pe_model_inner`).
//!
//! IMPORTANT:
//! - The primary dynamic string whitelist is loaded from the hardcoded path
//!   `C:\Users\semae\OneDrive\Belgeler\stringwhitelist` which comes specially and
//!   dynamically from the **Multron Server** (`multron_server_rs/src/string_wl.rs`,
//!   `whitelist.json` + `strings-<generation>.u64` + `strings-<generation>.idx`).
//! - Whenever Multron Server promotes a new generation in `whitelist.json`, this reader
//!   dynamically reloads the active generation's index (`strings-<gen>.idx`, ~444 KB in
//!   RAM) and queries the sorted 64-bit SHA-256 keys (`strings-<gen>.u64`, 56.8M+ keys)
//!   via O(log N) block-indexed binary search without loading the 455 MB file into RAM.
//! - In addition, ALL yarGen benign databases (`good-strings-part1..9.db`,
//!   `good-strings-benign_data2.db`, `good-exports-*.db`, website whitelists ->
//!   `pe_strings_benign.xf`, BinaryFuse16) and yarGen/YARA-X/ClamAV malicious strings
//!   (`pe_strings_malicious.xf`, BinaryFuse32) are queried in O(1) time.
//! - Includes strings recovered from:
//!   1. The Unicorn-unpacked / memory-dumped inner PE (`inner.pe`)
//!   2. The Unicorn emulator behavior trace (`BehaviorTrace` API calls, args, files,
//!      registry keys, network targets, processes)
//!   3. The disassembler / decompiler-lite (`hydradragondecompiler`: CodeRef strings,
//!      StackStrings built via immediate-to-memory MOVs, and OpcodePatterns)
//! - These features are ONLY routed to the unpacked/content PE model (`pe_model_inner`),
//!   NEVER to the packed/unpacked-failed outer shell model (`pe_model_shell`).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use hydradragondecompiler::{extract_strings as decompile_strings, ExtractOptions, StringKind};
use hydradragonsig::models::BehaviorTrace;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::signers::{BinaryFuse16Filter, BinaryFuse32Filter};

/// Hardcoded path to the dynamic string whitelist directory maintained specially and
/// dynamically by the Multron Server (`multron_server_rs/src/string_wl.rs`).
/// IMPORTANT: Used ONLY during Machine Learning Training (`pe_feature_dump` &
/// `xorfilter_writer`). In real runtime (Viruskovalyzer / `openedr_static`), only
/// the `.xf` filters (`pe_strings_benign.xf` and `pe_strings_malicious.xf`) are used!
pub const MULTRON_DYNAMIC_STRING_WHITELIST_DIR: &str =
    r"C:\Users\semae\OneDrive\Belgeler\stringwhitelist";

static TRAINING_MULTRON_WHITELIST_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enables direct Multron Server `stringwhitelist` disk lookups for ML training (`pe_feature_dump`).
/// In real runtime (Viruskovalyzer), this remains `false` so only `.xf` files are used.
pub fn enable_multron_training_whitelist() {
    TRAINING_MULTRON_WHITELIST_ENABLED.store(true, Ordering::Relaxed);
}

/// Minimum string length matching Multron Server's `string_wl::MIN_LEN` and yarGen.
pub const MIN_LEN: usize = 6;
/// Format version matching `multron_server_rs::string_wl::FORMAT`.
const FORMAT: u32 = 2;
/// Keys per index block matching `multron_server_rs::string_wl::BLOCK`.
const BLOCK: usize = 1024;
/// Maximum strings inspected per inner PE image to bound worst-case latency.
const MAX_INSPECT_STRINGS: usize = 150_000;

#[derive(Deserialize)]
struct MultronManifest {
    #[serde(default)]
    format: u32,
    generation: u64,
    min_len: usize,
    keys: u64,
}

/// Reader for a single Multron Server dynamic string whitelist generation on disk.
struct MultronDiskGeneration {
    generation: u64,
    file: Mutex<File>,
    len: u64,
    index: Vec<u64>,
}

impl MultronDiskGeneration {
    fn open(dir: &Path, generation: u64, keys: u64) -> Option<Self> {
        let file = File::open(dir.join(format!("strings-{generation}.u64"))).ok()?;
        let len = file.metadata().ok()?.len() / 8;
        let mut raw = Vec::new();
        File::open(dir.join(format!("strings-{generation}.idx")))
            .ok()?
            .read_to_end(&mut raw)
            .ok()?;
        let index: Vec<u64> = raw
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        if len != keys || index.len() as u64 != len.div_ceil(BLOCK as u64) {
            return None;
        }
        Some(Self {
            generation,
            file: Mutex::new(file),
            len,
            index,
        })
    }

    /// Queries sorted unique `keys` against `strings-<generation>.u64` using the in-memory
    /// block index (`strings-<generation>.idx`), reading only matching 8 KB blocks.
    fn count_matches_sorted(&self, keys: &[u64], out: &mut [bool]) {
        let Ok(mut f) = self.file.lock() else { return };
        let mut cached: Option<(usize, Vec<u64>)> = None;
        for (k, hit) in keys.iter().zip(out.iter_mut()) {
            let b = self.index.partition_point(|&first| first <= *k);
            if b == 0 {
                continue;
            }
            let b = b - 1;
            if cached.as_ref().map(|(cb, _)| *cb) != Some(b) {
                let start = (b * BLOCK) as u64;
                let n = (self.len - start).min(BLOCK as u64) as usize;
                let mut buf = vec![0u8; n * 8];
                if f.seek(SeekFrom::Start(start * 8)).is_err() || f.read_exact(&mut buf).is_err() {
                    continue;
                }
                cached = Some((
                    b,
                    buf.chunks_exact(8)
                        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                        .collect(),
                ));
            }
            if let Some((_, ref block_keys)) = cached {
                *hit = block_keys.binary_search(k).is_ok();
            }
        }
    }
}

/// Computes the exact 64-bit key used by Multron Server (`string_wl::key("pe", s)`).
#[inline]
pub fn multron_pe_string_key(s: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(b"pe\0");
    h.update(s.as_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

/// Combined String ML Engine holding:
/// 1. Dynamic Multron Server String Whitelist (`C:\Users\semae\OneDrive\Belgeler\stringwhitelist`)
/// 2. Full yarGen Benign String Filter (`pe_strings_benign.xf`, BinaryFuse16)
/// 3. Full yarGen/YARA/ClamAV Malicious String Filter (`pe_strings_malicious.xf`, BinaryFuse32)
pub struct PeStringMlEngine {
    multron_dir: PathBuf,
    multron_gen: Mutex<Option<MultronDiskGeneration>>,
    yargen_benign: Option<BinaryFuse16Filter>,
    yargen_malicious: Option<BinaryFuse32Filter>,
}

impl PeStringMlEngine {
    fn load() -> Self {
        let multron_dir = PathBuf::from(MULTRON_DYNAMIC_STRING_WHITELIST_DIR);
        let multron_gen = if TRAINING_MULTRON_WHITELIST_ENABLED.load(Ordering::Relaxed) {
            Self::load_latest_multron_gen(&multron_dir)
        } else {
            None
        };
        let (yargen_benign, yargen_malicious) = Self::load_xf_filters();

        Self {
            multron_dir,
            multron_gen: Mutex::new(multron_gen),
            yargen_benign,
            yargen_malicious,
        }
    }

    fn load_latest_multron_gen(dir: &Path) -> Option<MultronDiskGeneration> {
        let bytes = std::fs::read(dir.join("whitelist.json")).ok()?;
        let man: MultronManifest = serde_json::from_slice(&bytes).ok()?;
        if man.format != FORMAT || man.min_len != MIN_LEN {
            return None;
        }
        MultronDiskGeneration::open(dir, man.generation, man.keys)
    }

    /// Dynamically checks if Multron Server wrote a newer `generation` in `whitelist.json`
    /// and hot-reloads the index if updated.
    fn with_multron_whitelist<F: FnOnce(&MultronDiskGeneration)>(&self, f: F) {
        let Ok(mut guard) = self.multron_gen.lock() else { return };
        if let Ok(bytes) = std::fs::read(self.multron_dir.join("whitelist.json")) {
            if let Ok(man) = serde_json::from_slice::<MultronManifest>(&bytes) {
                let needs_reload = guard
                    .as_ref()
                    .map_or(true, |g| g.generation != man.generation || g.len != man.keys);
                if needs_reload && man.format == FORMAT && man.min_len == MIN_LEN {
                    if let Some(new_gen) =
                        MultronDiskGeneration::open(&self.multron_dir, man.generation, man.keys)
                    {
                        *guard = Some(new_gen);
                    }
                }
            }
        }
        if let Some(ref gen_disk) = *guard {
            f(gen_disk);
        }
    }

    fn candidate_filter_dirs() -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(p) = exe.parent() {
                dirs.push(p.to_path_buf());
                dirs.push(p.join("models"));
                dirs.push(p.join("xorfilter_rules"));
                if let Some(root) = p.parent().and_then(|x| x.parent()).and_then(|x| x.parent()) {
                    dirs.push(root.to_path_buf());
                }
            }
        }
        dirs.push(PathBuf::from(
            r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models",
        ));
        dirs.push(PathBuf::from(
            r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenEDR\openedr_static\models",
        ));
        dirs.push(PathBuf::from(
            r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenMalwareScannerPortable\models",
        ));
        dirs
    }

    /// Loads both string filters and logs where each came from. A missing or unparseable
    /// filter is not an error, but it silently zeroes the inner string features, so it is
    /// reported as a disabled capability rather than passed over.
    fn load_xf_filters() -> (Option<BinaryFuse16Filter>, Option<BinaryFuse32Filter>) {
        let mut ben = None;
        let mut mal = None;
        let mut ben_status = "absent".to_string();
        let mut mal_status = "absent".to_string();
        for d in Self::candidate_filter_dirs() {
            if ben.is_none() {
                let p = d.join("pe_strings_benign.xf");
                if let Ok(b) = std::fs::read(&p) {
                    ben = BinaryFuse16Filter::from_bytes(&b);
                    ben_status = match &ben {
                        Some(f) => format!("loaded ({} keys) from {}", f.len(), p.display()),
                        None => format!("parse-failed {}", p.display()),
                    };
                }
            }
            if mal.is_none() {
                let p = d.join("pe_strings_malicious.xf");
                if let Ok(b) = std::fs::read(&p) {
                    mal = BinaryFuse32Filter::from_bytes(&b);
                    mal_status = match &mal {
                        Some(f) => format!("loaded ({} keys) from {}", f.len(), p.display()),
                        None => format!("parse-failed {}", p.display()),
                    };
                }
            }
            if ben.is_some() && mal.is_some() {
                break;
            }
        }
        crate::diagnostics::log(
            "init-step",
            &format!("pe_strings_benign={ben_status}; pe_strings_malicious={mal_status}"),
        );
        if ben.is_none() || mal.is_none() {
            crate::diagnostics::log(
                "capability-disabled",
                "PE string ML: pe_strings_benign.xf / pe_strings_malicious.xf missing or \
                 unparseable; inner string features (mal/ben_str_hits, ratio, density) read as 0",
            );
        }
        (ben, mal)
    }

    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<PeStringMlEngine> = OnceLock::new();
        INSTANCE.get_or_init(Self::load)
    }
}

/// 6 String + Disassembler + Unicorn ML features computed exclusively for the unpacked /
/// content PE (`inner`), NEVER for the outer shell (`pe_model_shell`):
/// 1. `mal_str_hits`: `ln(1 + unique_malicious_strings)` (not in Multron WL and not in yarGen Benign)
/// 2. `ben_str_hits`: `ln(1 + unique_benign_strings)` (in Multron Dynamic WL or yarGen Benign)
/// 3. `mal_ben_str_ratio`: `mal_unique / (ben_unique + 1.0)`
/// 4. `mal_str_density`: `mal_unique / (total_unique_strings + 1.0)`
/// 5. `decompiler_Auto_strings`: `ln(1 + stack_strings + code_ref_strings + opcode_patterns)`
/// 6. `unicorn_trace_strings`: `ln(1 + unique strings captured by Unicorn API/behavior trace)`
#[derive(Debug, Clone, Copy, Default)]
pub struct PeStringMlMetrics {
    pub mal_str_hits: f32,
    pub ben_str_hits: f32,
    pub mal_ben_str_ratio: f32,
    pub mal_str_density: f32,
    pub decompiler_strings: f32,
    pub unicorn_trace_strings: f32,
}

impl PeStringMlMetrics {
    pub const LEN: usize = 6;
    pub const NAMES: [&'static str; Self::LEN] = [
        "mal_str_hits",
        "ben_str_hits",
        "mal_ben_str_ratio",
        "mal_str_density",
        "decompiler_strings",
        "unicorn_trace_strings",
    ];

    pub fn to_array(&self) -> [f32; Self::LEN] {
        [
            self.mal_str_hits,
            self.ben_str_hits,
            self.mal_ben_str_ratio,
            self.mal_str_density,
            self.decompiler_strings,
            self.unicorn_trace_strings,
        ]
    }
}

#[inline]
fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

fn extract_ascii_and_utf16(bytes: &[u8], out: &mut Vec<String>) {
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        if printable(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            if i - s >= MIN_LEN {
                if let Ok(txt) = std::str::from_utf8(&bytes[s..i]) {
                    out.push(txt.to_string());
                    if out.len() >= MAX_INSPECT_STRINGS {
                        break;
                    }
                }
            }
        }
    }
    if out.len() < MAX_INSPECT_STRINGS {
        if let Some(s) = start {
            if bytes.len() - s >= MIN_LEN {
                if let Ok(txt) = std::str::from_utf8(&bytes[s..]) {
                    out.push(txt.to_string());
                }
            }
        }
    }

    // UTF-16LE (both even and odd alignments)
    for align in 0..2usize {
        if out.len() >= MAX_INSPECT_STRINGS {
            break;
        }
        let mut i = align;
        let mut run_start: Option<usize> = None;
        let mut buf = String::new();
        while i + 1 < bytes.len() {
            let (lo, hi) = (bytes[i], bytes[i + 1]);
            if hi == 0 && printable(lo) {
                run_start.get_or_insert(i);
                buf.push(lo as char);
            } else {
                if run_start.take().is_some() && buf.len() >= MIN_LEN {
                    out.push(std::mem::take(&mut buf));
                    if out.len() >= MAX_INSPECT_STRINGS {
                        break;
                    }
                }
                buf.clear();
            }
            i += 2;
        }
        if out.len() < MAX_INSPECT_STRINGS && run_start.is_some() && buf.len() >= MIN_LEN {
            out.push(buf);
        }
    }
}

/// Extracts:
/// 1. Standard ASCII & UTF-16LE strings (both alignments, matching Multron Server `each_string`)
/// 2. Disassembler / Decompiler-Lite strings (`hydradragondecompiler`: `CodeRef`, `StackString`, `OpcodePattern`)
/// 3. Unicorn Emulation `BehaviorTrace` strings (API names, string arguments, files, registry, network, processes)
fn collect_all_inner_strings(
    data: &[u8],
    extra_raw: Option<&[u8]>,
    trace: Option<&BehaviorTrace>,
) -> (Vec<String>, usize, usize) {
    let mut out = Vec::new();
    extract_ascii_and_utf16(data, &mut out);
    if let Some(raw) = extra_raw {
        if out.len() < MAX_INSPECT_STRINGS {
            extract_ascii_and_utf16(raw, &mut out);
        }
    }

    // Disassembler / Decompiler-Lite pass (CodeRef + StackStrings + OpcodePatterns)
    let mut decomp_count = 0usize;
    let opts = ExtractOptions {
        min_len: MIN_LEN,
        ascii: false, // already extracted above with exact Multron alignment
        wide: false,
        code_refs: true,
        stack_strings: true,
        opcode_patterns: true,
        max_strings: 10_000,
    };
    for s in decompile_strings(data, &opts) {
        if matches!(
            s.kind,
            StringKind::CodeRef | StringKind::StackString | StringKind::OpcodePattern
        ) && s.text.len() >= MIN_LEN
        {
            decomp_count += 1;
            if out.len() < MAX_INSPECT_STRINGS {
                out.push(s.text);
            }
        }
    }

    // Unicorn Emulation BehaviorTrace strings (APIs, decoded arguments, files, registry, network, processes)
    let mut trace_count = 0usize;
    if let Some(tr) = trace {
        let mut push_tr = |s: &str| {
            let t = s.trim();
            if t.len() >= MIN_LEN && !t.starts_with("0x") {
                trace_count += 1;
                if out.len() < MAX_INSPECT_STRINGS {
                    out.push(t.to_string());
                }
            }
        };
        for call in &tr.calls {
            push_tr(&call.api);
            for arg in &call.args {
                push_tr(arg);
            }
        }
        for f in &tr.files_read {
            push_tr(f);
        }
        for f in &tr.files_written {
            push_tr(f);
        }
        for net in &tr.network_targets {
            push_tr(net);
        }
        for proc_cmd in &tr.processes {
            push_tr(proc_cmd);
        }
        for reg in &tr.registry {
            push_tr(reg);
        }
    }

    (out, decomp_count, trace_count)
}

/// Evaluates `inner` PE bytes + Disassembler (`hydradragondecompiler`) + Unicorn `BehaviorTrace` against:
/// 1. Multron Server Dynamic String Whitelist (`C:\Users\semae\OneDrive\Belgeler\stringwhitelist`)
/// 2. yarGen Full Benign String Filter (`pe_strings_benign.xf`)
/// 3. yarGen/YARA/ClamAV Malicious String Filter (`pe_strings_malicious.xf`)
///
/// Whitelist priority rule (yarGen style): if a string is present in EITHER the Multron
/// dynamic whitelist OR the yarGen benign filter, it is counted as benign and NEVER as
/// malicious.
pub fn extract_inner_pe_string_ml(
    data: &[u8],
    trace: Option<&BehaviorTrace>,
) -> PeStringMlMetrics {
    extract_inner_pe_string_ml_with_overlay(data, None, trace)
}

/// Every unique inner string split by what the filters say about it. Shown in
/// VirusKovAlyzer next to the ML verdict: malicious = in `pe_strings_malicious.xf`
/// (and not benign), benign = in the benign whitelist (`pe_strings_benign.xf`, which
/// already holds the Multron Server keys), unknown = in neither.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PeStringBreakdown {
    pub malicious: Vec<String>,
    pub benign: Vec<String>,
    pub unknown: Vec<String>,
    pub total_unique: usize,
    pub decompiler_strings: usize,
    pub unicorn_trace_strings: usize,
}

impl PeStringBreakdown {
    fn metrics(&self) -> PeStringMlMetrics {
        let mal_f = self.malicious.len() as f32;
        let ben_f = self.benign.len() as f32;
        let tot_f = self.total_unique as f32;
        PeStringMlMetrics {
            mal_str_hits: mal_f.ln_1p(),
            ben_str_hits: ben_f.ln_1p(),
            mal_ben_str_ratio: mal_f / (ben_f + 1.0),
            mal_str_density: mal_f / (tot_f + 1.0),
            decompiler_strings: (self.decompiler_strings as f32).ln_1p(),
            unicorn_trace_strings: (self.unicorn_trace_strings as f32).ln_1p(),
        }
    }
}

/// Splits a string list into malicious / benign / unknown using the loaded `.xf` filters
/// (and Multron Server dynamic whitelist if in training mode). Whitelist always wins.
pub fn classify_string_list(mut strings: Vec<String>) -> PeStringBreakdown {
    let mut out = PeStringBreakdown::default();
    if strings.is_empty() {
        return out;
    }
    strings.sort_unstable();
    strings.dedup();
    out.total_unique = strings.len();
    let eng = PeStringMlEngine::global();

    // Only during ML training the Multron Server `stringwhitelist` on disk is queried;
    // at runtime (VirusKovAlyzer) only the `.xf` files answer.
    let mut is_whitelisted = vec![false; strings.len()];
    if TRAINING_MULTRON_WHITELIST_ENABLED.load(Ordering::Relaxed) {
        let mut keyed: Vec<(u64, usize)> = strings
            .iter()
            .enumerate()
            .map(|(idx, s)| (multron_pe_string_key(s), idx))
            .collect();
        keyed.sort_unstable_by_key(|&(k, _)| k);
        let sorted_keys: Vec<u64> = keyed.iter().map(|&(k, _)| k).collect();
        let mut multron_hits = vec![false; sorted_keys.len()];
        eng.with_multron_whitelist(|disk| {
            disk.count_matches_sorted(&sorted_keys, &mut multron_hits);
        });
        for ((_, orig_idx), hit) in keyed.into_iter().zip(multron_hits) {
            if hit {
                is_whitelisted[orig_idx] = true;
            }
        }
    }

    for (idx, s) in strings.into_iter().enumerate() {
        let norm = s.trim();
        let benign = is_whitelisted[idx]
            || (s.len() >= 4
                && eng.yargen_benign.as_ref().is_some_and(|b| {
                    b.contains(&s)
                        || (norm.len() >= 4 && b.contains(norm))
                        || (s.len() >= MIN_LEN && b.contains_key(multron_pe_string_key(&s)))
                }));
        if benign {
            out.benign.push(s);
            continue;
        }
        let malicious = s.len() >= MIN_LEN
            && eng
                .yargen_malicious
                .as_ref()
                .is_some_and(|m| m.contains(&s) || (norm.len() >= MIN_LEN && m.contains(norm)));
        if malicious {
            out.malicious.push(s);
        } else {
            out.unknown.push(s);
        }
    }
    out
}

/// Splits the inner PE's strings (image + overlay + decompiler + Unicorn trace) into
/// malicious / benign / unknown. Whitelist always wins over the malicious filter.
pub fn classify_inner_pe_strings(
    data: &[u8],
    extra_raw: Option<&[u8]>,
    trace: Option<&BehaviorTrace>,
) -> PeStringBreakdown {
    if data.len() < 64 {
        return PeStringBreakdown::default();
    }
    let (strings, decomp_count, trace_count) = collect_all_inner_strings(data, extra_raw, trace);
    let mut out = classify_string_list(strings);
    out.decompiler_strings = decomp_count;
    out.unicorn_trace_strings = trace_count;
    out
}

pub fn extract_inner_pe_string_ml_with_overlay(
    data: &[u8],
    extra_raw: Option<&[u8]>,
    trace: Option<&BehaviorTrace>,
) -> PeStringMlMetrics {
    classify_inner_pe_strings(data, extra_raw, trace).metrics()
}

/// FNV-1a-64 over the ASCII-lowercased bytes: the key `pe_strings_*.xf` are built with
/// (`hydradragonxorfilter::key`).
fn xf_key(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Training only: keys of every inner string that is NOT benign (malicious or unknown),
/// harvested from the unpacked / content image so `pe_strings_malicious.xf` is built
/// from what the engine really reads at scan time, not from packed bytes.
pub fn harvest_inner_non_benign_keys(
    data: &[u8],
    extra_raw: Option<&[u8]>,
    trace: Option<&BehaviorTrace>,
) -> Vec<u64> {
    let b = classify_inner_pe_strings(data, extra_raw, trace);
    b.malicious.iter().chain(b.unknown.iter()).map(|s| xf_key(s)).collect()
}
