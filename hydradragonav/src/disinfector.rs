use std::path::Path;
use std::time::Instant;

use hydradragonextractor::extract_archive_from_bytes;
use hydradragonunicorn::unpacker::engine::{Sample, UnpackerEngine};
use hydradragonunicorn::unpacker::packers::identify_packer_from_bytes;

use crate::pipeline::{Pipeline, PipelineConfig};
use crate::verdict::{EngineResult, ScanResult, Verdict};

/// Result of a disinfection attempt.
#[derive(Debug)]
pub struct DisinfectResult {
    pub verdict: Verdict,
    pub engines: Vec<EngineResult>,
    pub disinfected: bool,
}

/// The disinfector orchestrates: detect packer → Unicorn-unpack → dump PE →
/// extract embedded archives → scan extracted files → disinfect.
/// All intermediate steps operate on in-memory bytes — no temp files.
pub struct Disinfector {
    pipeline: Pipeline,
}

impl Disinfector {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            pipeline: Pipeline::new(config),
        }
    }

    fn engine_result(engine: &'static str, verdict: Verdict, detail: String, elapsed_ms: Option<u64>) -> EngineResult {
        EngineResult { engine, verdict, detail, elapsed_ms }
    }

    pub fn disinfect(&self, file_path: &Path) -> DisinfectResult {
        let mut engines: Vec<EngineResult> = Vec::new();
        let total_start = Instant::now();

        // ---- Step 1: Read file into memory ----
        let file_data = match std::fs::read(file_path) {
            Ok(d) => d,
            Err(e) => return self.fail_result(engines, format!("read error: {e}")),
        };

        // ---- Step 2: Packer detection (from bytes, lazily compiled rules) ----
        let t0 = Instant::now();
        let yrc_bytes = crate::build_data::packer_rules_bytes();
        let (packer_name, matches) = match identify_packer_from_bytes(&file_data, yrc_bytes) {
            Ok(r) => r,
            Err(_) => return self.fail_result(engines, "not a known packed PE".into()),
        };
        engines.push(Self::engine_result(
            "packer_detection",
            Verdict::Clean,
            format!("{packer_name} ({})", matches.join(", ")),
            Some(t0.elapsed().as_millis() as u64),
        ));

        // ---- Step 3: Create Sample (from path — Sample reads the file internally) ----
        let path_str = file_path.to_string_lossy();
        let sample = match Sample::new(&path_str, "") {
            Ok(s) => s,
            Err(e) => return self.fail_result(engines, format!("Sample::new: {e}")),
        };

        // ---- Step 4: Emulation (timed) ----
        let t0 = Instant::now();
        let mut engine = UnpackerEngine::new(sample, "");
        if let Err(e) = engine.init_uc() {
            return self.fail_result(engines, format!("init_uc: {e}"));
        }
        if let Err(e) = engine.emu() {
            return self.fail_result(engines, format!("emu: {e}"));
        }
        engines.push(Self::engine_result(
            "unpacker",
            Verdict::Clean,
            format!("emulated {packer_name} packed PE"),
            Some(t0.elapsed().as_millis() as u64),
        ));

        // ---- Step 5: Dump unpacked PE to memory (no file write) ----
        let t0 = Instant::now();
        let dumped_bytes: Vec<u8> = match engine.dump_bytes() {
            Ok(bytes) => bytes,
            Err(e) => return self.fail_result(engines, format!("dump_bytes: {e}")),
        };
        engines.push(Self::engine_result(
            "dump",
            Verdict::Clean,
            format!("unpacked {} bytes", dumped_bytes.len()),
            Some(t0.elapsed().as_millis() as u64),
        ));

        // ---- Step 6: Extract embedded archives from memory ----
        let t0 = Instant::now();
        let extracted_files = match extract_archive_from_bytes(&dumped_bytes) {
            Ok(files) => files,
            Err(_) => Vec::new(),
        };
        engines.push(Self::engine_result(
            "extractor",
            Verdict::Clean,
            if extracted_files.is_empty() {
                "no embedded archive".into()
            } else {
                format!("extracted {} file(s)", extracted_files.len())
            },
            Some(t0.elapsed().as_millis() as u64),
        ));

        // ---- Step 7: Scan dumped bytes with full pipeline ----
        let t0 = Instant::now();
        let ScanResult { verdict, engines: pipe_engines, .. } = self.pipeline.scan_bytes(&dumped_bytes);
        for e in &pipe_engines {
            engines.push(e.clone());
        }
        let scan_elapsed = t0.elapsed().as_millis() as u64;

        if verdict != Verdict::Clean && verdict != Verdict::Trusted {
            let disinfected = std::fs::remove_file(file_path).is_ok();
            engines.push(Self::engine_result(
                "disinfector",
                verdict,
                format!("disinfected={disinfected} (scan took {scan_elapsed}ms)"),
                None,
            ));
            return DisinfectResult { verdict, engines, disinfected };
        }

        // ---- Step 8: Scan each extracted file in memory too ----
        for bytes in &extracted_files {
            let ScanResult { verdict, engines: pipe_engines, .. } = self.pipeline.scan_bytes(bytes);
            for e in &pipe_engines {
                engines.push(e.clone());
            }
            if verdict != Verdict::Clean && verdict != Verdict::Trusted {
                let disinfected = std::fs::remove_file(file_path).is_ok();
                engines.push(Self::engine_result(
                    "disinfector",
                    verdict,
                    format!("extracted file disinfected={disinfected}"),
                    None,
                ));
                return DisinfectResult { verdict, engines, disinfected };
            }
        }

        engines.push(Self::engine_result(
            "disinfector",
            Verdict::Clean,
            format!("total {:.2}s", total_start.elapsed().as_secs_f64()),
            None,
        ));

        DisinfectResult { verdict: Verdict::Clean, engines, disinfected: false }
    }

    fn fail_result(&self, mut engines: Vec<EngineResult>, detail: String) -> DisinfectResult {
        engines.push(Self::engine_result("disinfector", Verdict::Clean, detail, None));
        DisinfectResult { verdict: Verdict::Clean, engines, disinfected: false }
    }
}
