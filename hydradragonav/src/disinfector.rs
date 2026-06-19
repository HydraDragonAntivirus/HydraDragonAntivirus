use std::path::{Path, PathBuf};

use hydradragonheur::extract::{extract_archive, detect_format};
use hydradragonheur::unpacker::engine::{Sample, UnpackerEngine};
use hydradragonheur::unpacker::packers::identify_packer_from_bytes;

use crate::pipeline::{Pipeline, PipelineConfig};
use crate::verdict::{EngineResult, ScanResult, Verdict};

/// Result of a disinfection attempt.
#[derive(Debug)]
pub struct DisinfectResult {
    /// Final verdict after unpacking + scanning all extracted files.
    pub verdict: Verdict,
    /// Details per engine.
    pub engines: Vec<EngineResult>,
    /// Paths to unpacked/extracted files that were scanned.
    pub extracted_files: Vec<PathBuf>,
    /// Whether the original file was disinfected (removed/cleaned).
    pub disinfected: bool,
}

/// The disinfector orchestrates: detect packer → Unicorn-unpack → dump PE →
/// extract embedded archives → scan extracted files → disinfect.
pub struct Disinfector {
    pipeline: Pipeline,
    yrc_bytes: &'static [u8],
}

impl Disinfector {
    pub fn new(config: PipelineConfig, yrc_bytes: &'static [u8]) -> Self {
        Self {
            pipeline: Pipeline::new(config),
            yrc_bytes,
        }
    }

    fn build_engine_result(engine: &'static str, verdict: Verdict, detail: String) -> EngineResult {
        EngineResult {
            engine,
            verdict,
            detail,
            elapsed_ms: None,
        }
    }

    /// Run the full unpack + scan + disinfect pipeline on a single file.
    pub fn disinfect(&self, file_path: &Path) -> DisinfectResult {
        let mut extracted_files: Vec<PathBuf> = Vec::new();
        let mut engines: Vec<EngineResult> = Vec::new();
        let file_path_str = file_path.to_string_lossy().to_string();

        // ---- Step 1: Read and detect packer ----
        let file_data = match std::fs::read(file_path) {
            Ok(d) => d,
            Err(e) => {
                return self.fail_result(
                    engines,
                    extracted_files,
                    format!("read error: {e}"),
                );
            }
        };

        let (packer_name, matches) = match identify_packer_from_bytes(&file_data, self.yrc_bytes) {
            Ok(r) => r,
            Err(_) => {
                return self.fail_result(
                    engines,
                    extracted_files,
                    "not a known packed PE".into(),
                );
            }
        };

        engines.push(Self::build_engine_result(
            "packer_detection",
            Verdict::Clean,
            format!("{packer_name} ({})", matches.join(", ")),
        ));

        // ---- Step 2: Create Sample and UnpackerEngine ----
        let sample = match Sample::new(&file_path_str, "") {
            Ok(s) => s,
            Err(e) => {
                return self.fail_result(engines, extracted_files, format!("Sample::new: {e}"));
            }
        };

        let mut engine = UnpackerEngine::new(sample, "");

        engines.push(Self::build_engine_result(
            "unpacker",
            Verdict::Clean,
            format!("emulating {packer_name} packed PE…"),
        ));

        // ---- Step 3: Init Unicorn and run emulation ----
        if let Err(e) = engine.init_uc() {
            return self.fail_result(engines, extracted_files, format!("init_uc: {e}"));
        }
        if let Err(e) = engine.emu() {
            return self.fail_result(engines, extracted_files, format!("emu: {e}"));
        }

        // ---- Step 4: Dump unpacked PE ----
        let work_dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                return self.fail_result(engines, extracted_files, format!("tempdir: {e}"));
            }
        };
        let dump_path = work_dir.path().join("unpacked.exe");
        let dump_path_str = dump_path.to_string_lossy().to_string();

        if let Err(e) = engine.dump(&dump_path_str) {
            return self.fail_result(engines, extracted_files, format!("dump: {e}"));
        }
        extracted_files.push(dump_path.clone());

        // ---- Step 5: Extract embedded archives ----
        if detect_format(&dump_path).is_some() {
            let extract_dir = work_dir.path().join("extracted");
            if let Ok(result) = extract_archive(&dump_path, &extract_dir) {
                for f in result.files {
                    extracted_files.push(f);
                }
            }
        }

        // ---- Step 6: Scan all extracted files with full pipeline ----
        for f in &extracted_files {
            let ScanResult { verdict, engines: pipe_engines, .. } = self.pipeline.scan_file(f);
            for e in &pipe_engines {
                engines.push(e.clone());
            }
            if verdict != Verdict::Clean && verdict != Verdict::Trusted {
                // ---- Step 7: Disinfect ----
                let disinfected = std::fs::remove_file(file_path).is_ok();
                return DisinfectResult {
                    verdict,
                    engines,
                    extracted_files,
                    disinfected,
                };
            }
        }

        DisinfectResult {
            verdict: Verdict::Clean,
            engines,
            extracted_files,
            disinfected: false,
        }
    }

    fn fail_result(
        &self,
        mut engines: Vec<EngineResult>,
        extracted_files: Vec<PathBuf>,
        detail: String,
    ) -> DisinfectResult {
        engines.push(Self::build_engine_result("disinfector", Verdict::Clean, detail));
        DisinfectResult {
            verdict: Verdict::Clean,
            engines,
            extracted_files,
            disinfected: false,
        }
    }
}
