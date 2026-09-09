use crate::scanner::ScanMatch;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// One cached `yara_x::Scanner` per `YaraEngine`, per thread. `Scanner::new`
    /// is not free (it allocates its own match-tracking state and instantiates
    /// a WASM runtime for the rules' compiled condition bytecode) — the scan
    /// path calls `YaraEngine::scan` once per (ruleset × extracted buffer ×
    /// normalized view), so building a brand-new `Scanner` on every single one
    /// of those calls was multiplying that non-trivial setup cost by a factor
    /// that scales with how many nested files an APK contains, on top of the
    /// actual scanning work — this is why the native engine measured
    /// (FILE_ENGINE_TIMING) as consistently and disproportionately slow.
    /// Reusing one `Scanner` per ruleset per thread amortizes that setup cost
    /// across every scan instead of paying it every time.
    static SCANNER_CACHE: RefCell<HashMap<u64, yara_x::Scanner<'static>>> =
        RefCell::new(HashMap::new());
}

/// Android-relevant ClamAV target types that get YARA scanning.
///
/// Includes HTML (3), Graphics (5), ELF (6), ASCII text (7), PDF (10),
/// DEX (16), ZIP/APK (17). Excludes PE (1), OLE2 (2), Mail (4), Mach-O (9),
/// SWF (11), Java (12) and other desktop-only formats never relevant on
/// Android. A file with no confident type match is skipped too — only
/// positively-identified supported types get scanned, same policy as the
/// ClamAV engine gate (`scanner::CLAMAV_ALLOWED_TARGETS`).
const ALLOWED_TARGETS: [u32; 7] = [3, 5, 6, 7, 10, 16, 17];

/// Returns `true` if files matching the given ClamAV target should be
/// scanned with YARA rules.
pub fn is_target_allowed(target: Option<u32>) -> bool {
    matches!(target, Some(t) if ALLOWED_TARGETS.contains(&t))
}

/// Ruleset names that depend on module metadata (hydradragon JSON report) built
/// only AFTER the streaming extract pass. These are skipped during streaming
/// (their module functions can't evaluate without metadata) and scanned exactly
/// once in the Phase 3 module-metadata rescan.
const MODULE_DEPENDENT_NAMES: [&str; 2] = ["hydradragon.yrc", "hips_rules_filtered_verified.yrc"];

/// A compiled YARA ruleset ready for scanning.
/// `rules` is boxed so its address is stable even when the containing `Vec<YaraEngine>`
/// is pushed to (which can reallocate and move elements). Thread-local `Scanner` caches
/// hold `&'static Rules` references — a `Box` guarantees those references stay valid.
#[derive(Debug)]
pub struct YaraEngine {
    id: u64,
    pub name: String,
    /// True if this ruleset references the hydradragon module and
    /// therefore only produces meaningful results once module metadata exists.
    pub module_dependent: bool,
    rules: Box<yara_x::Rules>,
}

impl YaraEngine {
    fn new(rules: yara_x::Rules, name: String) -> Self {
        let module_dependent = MODULE_DEPENDENT_NAMES.contains(&name.as_str());
        Self {
            id: NEXT_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
            name,
            module_dependent,
            rules: Box::new(rules),
        }
    }

    /// Compile a YARA source file and build the engine.
    ///
    /// Returns `None` if the file does not exist or compilation fails
    /// (the caller should degrade gracefully rather than abort the scan).
    pub fn from_source_file(path: impl AsRef<Path>) -> Option<Self> {
        let src = std::fs::read_to_string(path.as_ref()).ok()?;
        let name = path.as_ref().file_name()?.to_string_lossy().to_string();
        Self::from_source(&src, name)
    }

    /// Compile YARA source directly.
    pub fn from_source(source: &str, name: String) -> Option<Self> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).ok()?;
        Some(Self::new(compiler.build(), name))
    }

    /// Load a pre-compiled `.yrc` ruleset (produced by `Rules::serialize`).
    ///
    /// Far faster than compiling source on-device — the Android app bundles
    /// compiled `.yrc` assets and deserialises them at startup instead of
    /// compiling thousands of rules every launch.
    pub fn from_compiled(bytes: &[u8], name: String) -> Option<Self> {
        let rules = yara_x::Rules::deserialize(bytes).ok()?;
        Some(Self::new(rules, name))
    }

    /// Load a pre-compiled `.yrc` file from disk.
    pub fn from_compiled_file(path: impl AsRef<Path>) -> Option<Self> {
        let bytes = std::fs::read(path.as_ref()).ok()?;
        let name = path.as_ref().file_name()?.to_string_lossy().to_string();
        Self::from_compiled(&bytes, name)
    }

    /// Scan `data` with the compiled rules and return any matches.
    pub fn scan(
        &self,
        data: &[u8],
        object_path: &str,
        module_meta: &[(&str, &[u8])],
    ) -> Vec<ScanMatch> {
        SCANNER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            let scanner = cache.entry(self.id).or_insert_with(|| {
                // SAFETY: `self.rules` is a `Box<yara_x::Rules>`, so its heap
                // address is stable across `Vec::push` reallocations of the
                // containing vector. The `YaraEngine` itself is stored in
                // `static ENGINE: OnceLock<RwLock<Engine>>` (set exactly once
                // and never replaced), so the `Box` is never dropped for the
                // lifetime of the process. A `Scanner` that borrows the rules
                // at this address with a `'static` lifetime is therefore sound.
                let rules_ptr: *const yara_x::Rules = &*self.rules;
                let rules_static: &'static yara_x::Rules =
                    unsafe { &*rules_ptr };
                let mut scanner = yara_x::Scanner::new(rules_static);
                scanner.fast_scan(true);
                scanner
            });

            // Feed any per-module JSON report (hydradragon manifest/DEX/network
            // report) so its functions can query them.
            let results = if module_meta.is_empty() {
                match scanner.scan(data) {
                    Ok(r) => r,
                    Err(_) => return Vec::new(),
                }
            } else {
                let mut opts = yara_x::ScanOptions::new();
                for (name, meta) in module_meta {
                    opts = opts.set_module_metadata(name, meta);
                }
                match scanner.scan_with_options(data, opts) {
                    Ok(r) => r,
                    Err(_) => return Vec::new(),
                }
            };
            let mut matches = Vec::new();
            for rule in results.matching_rules() {
                matches.push(ScanMatch {
                    name: format!("YARA-X.{}", rule.identifier()),
                    kind: crate::scanner::SignatureKind::Yara,
                    source: crate::database::SourceLocation {
                        path: Arc::from(PathBuf::from("yara-x")),
                        line: 0,
                    },
                    object_path: object_path.to_string(),
                    view: crate::scanner::ScanView::Raw,
                });
            }
            matches
        })
    }
}
