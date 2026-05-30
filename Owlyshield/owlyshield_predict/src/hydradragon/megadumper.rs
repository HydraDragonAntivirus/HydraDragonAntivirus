use std::path::PathBuf;
use std::process::Command;
use crate::logging::Logging;

pub fn dump_process(pid: u32) -> bool {
    Logging::info(&format!("[MegaDumper] Attempting to dump PID: {}", pid));

    let mut candidates = Vec::new();
    if let Ok(pf) = std::env::var("ProgramFiles") {
        candidates.push(PathBuf::from(pf).join("HydraDragonAntivirus").join("hydradragon"));
    }
    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        candidates.push(PathBuf::from(pf86).join("HydraDragonAntivirus").join("hydradragon"));
    }
    candidates.push(PathBuf::from(r"C:\HydraDragonAntivirus\hydradragon"));

    let install_dir = candidates.into_iter().find(|p| p.exists()).unwrap_or_else(|| PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\hydradragon"));
    let dumper_path = install_dir.join("HydraDragonDumper").join("MegaDumper.exe");

    if !dumper_path.exists() {
        Logging::error(&format!("[MegaDumper] Executable not found at {:?}", dumper_path));
        return false;
    }

    let extracted_dir = PathBuf::from(r"C:\HydraDragon\MegaDumperExtracted");
    let output_dir = extracted_dir.join(format!("pid_{}", pid));
    let _ = std::fs::create_dir_all(&output_dir);

    Logging::info(&format!("[MegaDumper] Running dumper on PID: {} to output: {:?}", pid, output_dir));

    let output = Command::new(&dumper_path)
        .arg("--pid")
        .arg(pid.to_string())
        .arg("--output")
        .arg(&output_dir)
        .arg("--no-restore-filename")
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                Logging::info(&format!("[MegaDumper] Extraction complete for PID {}", pid));
                true
            } else {
                let err_str = String::from_utf8_lossy(&out.stderr);
                Logging::error(&format!("[MegaDumper] Extraction failed for PID {}: {}", pid, err_str));
                false
            }
        }
        Err(e) => {
            Logging::error(&format!("[MegaDumper] Failed to launch MegaDumper for PID {}: {}", pid, e));
            false
        }
    }
}
