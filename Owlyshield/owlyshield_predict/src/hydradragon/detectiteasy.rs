//! DetectItEasy integration for Owlyshield.
//!
//! Owlyshield runs DetectItEasy in Rust and sends the parsed JSON to Python so
//! HydraDragon can consume the detection data without spawning DIE itself.

use crate::logging::Logging;
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zip::ZipArchive;

const DIE_SCAN_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_DIE_SCAN_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Complete DetectItEasy scan result with all detections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectItEasyScanResult {
    pub scanner: String,
    pub file_path: String,
    pub scan_ok: bool,
    pub scan_error: Option<String>,
    pub die_output: String,

    // File types
    pub is_pe: bool,
    pub is_elf: bool,
    pub is_macho: bool,
    pub is_apk: bool,
    pub file_type: Option<String>,
    pub pe_result: Option<String>,
    pub elf_result: Option<String>,
    pub macho_result: Option<String>,
    pub apk_result: Option<String>,
    pub is_broken_executable: bool,
    pub broken_executable_type: Option<String>,

    // Protectors
    pub is_protected: bool,
    pub protector_name: Option<String>,
    pub is_themida: bool,
    pub themida_type: Option<String>,
    pub is_vmprotect: bool,

    // Packers
    pub is_packed: bool,
    pub packer_name: Option<String>,
    pub packer_type: Option<String>,
    pub is_upx: bool,
    pub is_pyinstaller: bool,
    pub is_nuitka: bool,
    pub nuitka_type: Option<String>,
    pub is_cx_freeze: bool,
    pub is_nexe: bool,
    pub is_npm: bool,
    pub is_python_process: bool,

    // Languages/Platforms
    pub is_dotnet: bool,
    pub dotnet_type: Option<String>,
    pub is_go_garble: bool,
    pub is_pyc: bool,
    pub is_pyarmor_archive: bool,
    pub is_jar: bool,
    pub is_java_class: bool,
    pub is_jsc: Option<String>,

    // Installers
    pub is_inno_setup: bool,
    pub is_nsis: bool,
    pub is_advanced_installer: bool,
    pub is_installshield: bool,
    pub is_clickteam: bool,
    pub is_autoit: bool,
    pub is_compiled_autohotkey: bool,

    // Archives
    pub is_archive: bool,
    pub is_7z: bool,
    pub is_asar: bool,
    pub is_microsoft_compound: bool,

    // Special
    pub is_unknown: bool,
    pub is_plain_text: bool,
    pub is_enigma_virtual_box: bool,
}

/// DetectItEasy scanner with complete Python detection logic
pub struct DetectItEasyScanner {
    diec_path: Option<PathBuf>,
}

fn run_diec_with_timeout(mut command: Command, timeout: Duration) -> Result<Output, String> {
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to run diec.exe: {}", e))?;
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("Failed to collect diec.exe output: {}", e));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("Failed to poll diec.exe: {}", e)),
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "diec.exe timed out after {} ms",
                timeout.as_millis()
            ));
        }

        thread::sleep(Duration::from_millis(25));
    }
}

impl DetectItEasyScanner {
    pub fn new() -> Self {
        DetectItEasyScanner {
            diec_path: Self::resolve_diec_path(),
        }
    }

    fn resolve_diec_path() -> Option<PathBuf> {
        let mut candidates = Vec::new();

        if let Ok(program_files) = std::env::var("ProgramFiles") {
            candidates.push(
                PathBuf::from(program_files)
                    .join("HydraDragonAntivirus")
                    .join("hydradragon")
                    .join("detectiteasy")
                    .join("diec.exe"),
            );
        }

        if let Ok(program_files) = std::env::var("ProgramW6432") {
            candidates.push(
                PathBuf::from(program_files)
                    .join("HydraDragonAntivirus")
                    .join("hydradragon")
                    .join("detectiteasy")
                    .join("diec.exe"),
            );
        }

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(hydradragon_dir) = exe_path
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
            {
                candidates.push(hydradragon_dir.join("detectiteasy").join("diec.exe"));
            }
        }

        candidates.push(PathBuf::from(
            r"C:\HydraDragonAntivirus\hydradragon\detectiteasy\diec.exe",
        ));

        candidates.into_iter().find(|candidate| candidate.is_file())
    }

    /// Scan file and return complete detection results
    pub fn scan_file(&self, file_path: &Path) -> Result<DetectItEasyScanResult, String> {
        Logging::info(&format!("[DetectItEasy] Scanning: {}", file_path.display()));

        if file_path
            .metadata()
            .map(|metadata| metadata.len() > MAX_DIE_SCAN_FILE_SIZE)
            .unwrap_or(false)
        {
            return Err(format!(
                "DIE scan skipped because file is over 2 GiB: {}",
                file_path.display()
            ));
        }

        if is_plain_text_file(file_path).unwrap_or(false) {
            Logging::debug(&format!(
                "[DetectItEasy] Plain-text gate matched before DIE: {}",
                file_path.display()
            ));
            return Ok(self.parse_all_detections(file_path, "Binary\n    Format: plain text"));
        }

        let diec_path = self
            .diec_path
            .as_ref()
            .ok_or_else(|| "diec.exe was not found in the HydraDragon install paths".to_string())?;

        let mut command = Command::new(diec_path);
        command
            .arg("-p")
            .arg(file_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(diec_dir) = diec_path.parent() {
            command.current_dir(diec_dir);
        }

        let output = run_diec_with_timeout(command, DIE_SCAN_TIMEOUT)?;

        let die_output = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            return Err(format!(
                "diec.exe failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        };

        let result = self.parse_all_detections(file_path, &die_output);

        Logging::debug(&format!(
            "[DetectItEasy] Complete scan: pe={}, dotnet={}, packed={}, protected={}, unknown={}",
            result.is_pe,
            result.is_dotnet,
            result.is_packed,
            result.is_protected,
            result.is_unknown
        ));

        Ok(result)
    }

    pub fn error_result(file_path: &Path, error: String) -> DetectItEasyScanResult {
        DetectItEasyScanResult {
            scanner: "detectiteasy".to_string(),
            file_path: file_path.to_string_lossy().to_string(),
            scan_ok: false,
            scan_error: Some(error),
            die_output: String::new(),
            is_pe: false,
            is_elf: false,
            is_macho: false,
            is_apk: false,
            file_type: None,
            pe_result: None,
            elf_result: None,
            macho_result: None,
            apk_result: None,
            is_broken_executable: false,
            broken_executable_type: None,
            is_protected: false,
            protector_name: None,
            is_themida: false,
            themida_type: None,
            is_vmprotect: false,
            is_packed: false,
            packer_name: None,
            packer_type: None,
            is_upx: false,
            is_pyinstaller: false,
            is_nuitka: false,
            nuitka_type: None,
            is_cx_freeze: false,
            is_nexe: false,
            is_npm: false,
            is_python_process: false,
            is_dotnet: false,
            dotnet_type: None,
            is_go_garble: false,
            is_pyc: false,
            is_pyarmor_archive: false,
            is_jar: false,
            is_java_class: false,
            is_jsc: None,
            is_inno_setup: false,
            is_nsis: false,
            is_advanced_installer: false,
            is_installshield: false,
            is_clickteam: false,
            is_autoit: false,
            is_compiled_autohotkey: false,
            is_archive: false,
            is_7z: false,
            is_asar: false,
            is_microsoft_compound: false,
            is_unknown: false,
            is_plain_text: is_plain_text_file(file_path).unwrap_or(false),
            is_enigma_virtual_box: false,
        }
    }

    /// Parse ALL detections from DIE output
    fn parse_all_detections(&self, file_path: &Path, die_output: &str) -> DetectItEasyScanResult {
        let protector_name = self.is_protector(die_output);
        let themida_type = self.is_themida(die_output);
        let packer_name = self.is_packed(die_output);
        let packer_type = self.packer_type(die_output);
        let nuitka_type = self.is_nuitka(die_output);
        let dotnet_type = self.is_dotnet(die_output);
        let format_validation = inspect_binary_formats(file_path);

        let is_pyinstaller = self.is_pyinstaller(die_output);
        let is_cx_freeze = self.is_cx_freeze(die_output);
        let is_nuitka_flag = nuitka_type.is_some();
        let path_lower = file_path.to_string_lossy().to_lowercase();
        let is_python_process = is_pyinstaller || is_cx_freeze || is_nuitka_flag 
            || path_lower.ends_with("python.exe") || path_lower.ends_with("pythonw.exe")
            || path_lower.ends_with("python3.dll") || path_lower.ends_with("python.dll");

        let detected_pe =
            self.is_pe_file(die_output) || format_validation.pe == FormatValidation::Valid;
        let detected_elf =
            self.is_elf_file(die_output) || format_validation.elf == FormatValidation::Valid;
        let detected_macho =
            self.is_macho_file(die_output) || format_validation.macho == FormatValidation::Valid;
        let detected_apk =
            self.is_apk_file(die_output) || format_validation.apk == FormatValidation::Valid;

        let pe_result = file_type_result(detected_pe, format_validation.pe, "Broken Executable");
        let elf_result = file_type_result(detected_elf, format_validation.elf, "Broken Executable");
        let macho_result =
            file_type_result(detected_macho, format_validation.macho, "Broken Executable");
        let apk_result = file_type_result(detected_apk, format_validation.apk, "Broken APK");
        let broken_executable_type = [
            ("PE", format_validation.pe, pe_result.as_deref()),
            ("ELF", format_validation.elf, elf_result.as_deref()),
            ("Mach-O", format_validation.macho, macho_result.as_deref()),
            ("APK", format_validation.apk, apk_result.as_deref()),
        ]
        .iter()
        .find_map(|(name, status, result)| {
            if *status == FormatValidation::Broken
                || matches!(*result, Some("Broken Executable") | Some("Broken APK"))
            {
                Some((*name).to_string())
            } else {
                None
            }
        });

        DetectItEasyScanResult {
            scanner: "detectiteasy".to_string(),
            file_path: file_path.to_string_lossy().to_string(),
            scan_ok: true,
            scan_error: None,
            die_output: die_output.to_string(),

            // File types
            is_pe: detected_pe,
            is_elf: detected_elf,
            is_macho: detected_macho,
            is_apk: detected_apk,
            file_type: format_validation
                .file_type
                .or_else(|| self.get_file_type(die_output)),
            pe_result,
            elf_result,
            macho_result,
            apk_result,
            is_broken_executable: broken_executable_type.is_some(),
            broken_executable_type,

            // Protectors
            is_protected: protector_name.is_some(),
            protector_name,
            is_themida: themida_type.is_some(),
            themida_type,
            is_vmprotect: self.is_vmprotect(die_output),

            // Packers
            is_packed: packer_name.is_some(),
            packer_name,
            packer_type,
            is_upx: self.is_upx(die_output),
            is_pyinstaller,
            is_nuitka: is_nuitka_flag,
            nuitka_type,
            is_cx_freeze,
            is_nexe: self.is_nexe(die_output),
            is_npm: self.is_npm(die_output),
            is_python_process,

            // Languages/Platforms
            is_dotnet: dotnet_type.is_some(),
            dotnet_type,
            is_go_garble: self.is_go_garble(die_output),
            is_pyc: self.is_pyc(die_output),
            is_pyarmor_archive: self.is_pyarmor_archive_file(file_path),
            is_jar: self.is_jar(die_output),
            is_java_class: self.is_java_class(die_output),
            is_jsc: self.is_jsc(die_output),

            // Installers
            is_inno_setup: self.is_inno_setup(die_output),
            is_nsis: self.is_nsis(die_output),
            is_advanced_installer: self.is_advanced_installer(die_output),
            is_installshield: self.is_installshield(die_output),
            is_clickteam: self.is_clickteam(die_output),
            is_autoit: self.is_autoit(die_output),
            is_compiled_autohotkey: self.is_compiled_autohotkey(die_output),

            // Archives
            is_archive: self.is_archive(die_output),
            is_7z: self.is_7z(die_output),
            is_asar: self.is_asar(die_output),
            is_microsoft_compound: self.is_microsoft_compound(die_output),

            // Special
            is_unknown: self.is_file_fully_unknown(die_output),
            is_plain_text: self.detects_plain_text_format(die_output)
                || is_plain_text_file(file_path).unwrap_or(false),
            is_enigma_virtual_box: self.is_enigma_virtual_box(die_output),
        }
    }

    pub fn is_protector(&self, die_output: &str) -> Option<String> {
        if let Some(line) = die_output.lines().find(|l| l.contains("Protector:")) {
            if let Some(protector) = line.split("Protector:").nth(1) {
                return Some(protector.trim().to_string());
            }
        }
        None
    }

    pub fn is_go_garble(&self, die_output: &str) -> bool {
        die_output.contains("Compiler: Go(unknown)")
    }

    pub fn is_nexe(&self, die_output: &str) -> bool {
        die_output.contains("Packer: nexe")
    }

    pub fn is_pyc(&self, die_output: &str) -> bool {
        die_output.contains("Python Compiled Module")
    }

    pub fn is_themida(&self, die_output: &str) -> Option<String> {
        if die_output.contains("Protector: Themida/Winlicense (2.XX)")
            || die_output.contains("Protector: Themida/Winlicense (3.XX)")
        {
            if die_output.contains("PE32") {
                return Some("PE32 Themida".to_string());
            }
            if die_output.contains("PE64") {
                return Some("PE64 Themida".to_string());
            }
        }
        None
    }

    pub fn is_vmprotect(&self, die_output: &str) -> bool {
        die_output.contains("Protector: VMProtect")
            && (die_output.contains("PE32") || die_output.contains("PE64"))
    }

    pub fn is_pe_file(&self, die_output: &str) -> bool {
        die_output.contains("PE32") || die_output.contains("PE64")
    }

    pub fn is_cx_freeze(&self, die_output: &str) -> bool {
        die_output.contains("Packer: cx_Freeze(5.x+)")
    }

    pub fn is_advanced_installer(&self, die_output: &str) -> bool {
        die_output.contains("Advanced Installer")
    }

    pub fn is_clickteam(&self, die_output: &str) -> bool {
        die_output.contains("ClickTeam")
    }

    pub fn is_autoit(&self, die_output: &str) -> bool {
        die_output.contains("AutoIt")
    }

    pub fn is_jsc(&self, die_output: &str) -> Option<String> {
        if !die_output.starts_with("Binary") {
            return None;
        }
        if !die_output.contains("Language: JavaScript") {
            return None;
        }
        if !die_output.contains("Format: JavaScript Compiled/Bytenode")
            && !die_output.contains(".JSC")
        {
            return None;
        }

        // Try to extract version
        if let Some(version_match) = die_output.split("v").nth(1) {
            if let Some(version) = version_match.split_whitespace().next() {
                return Some(format!("JSC v{}", version));
            }
        }

        Some("JSC (unknown version)".to_string())
    }

    pub fn is_npm(&self, die_output: &str) -> bool {
        die_output.contains("Packer: npm")
            && die_output.contains("Language: JavaScript")
            && (die_output.contains("PE32") || die_output.contains("PE64"))
    }

    pub fn is_archive(&self, die_output: &str) -> bool {
        die_output
            .lines()
            .any(|line| line.trim_start().starts_with("Archive:"))
    }

    pub fn is_asar(&self, die_output: &str) -> bool {
        let lines: Vec<&str> = die_output
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();
        lines.len() >= 2 && lines[0] == "Binary" && lines[1] == "Archive: Asar Archive (Electron)"
    }

    pub fn is_installshield(&self, die_output: &str) -> bool {
        die_output.contains("InstallShield")
    }

    pub fn is_nsis(&self, die_output: &str) -> bool {
        die_output.contains("Nullsoft Scriptable Install System")
            || die_output.contains("Data: NSIS data")
    }

    pub fn is_elf_file(&self, die_output: &str) -> bool {
        die_output.starts_with("ELF32") || die_output.starts_with("ELF64")
    }

    pub fn is_apk_file(&self, die_output: &str) -> bool {
        die_output.to_uppercase().contains("APK")
    }

    pub fn is_macho_file(&self, die_output: &str) -> bool {
        die_output.starts_with("Mach-O")
    }

    pub fn is_dotnet(&self, die_output: &str) -> Option<String> {
        if die_output.contains("C++") {
            return None;
        }
        if die_output.contains("Tool: de4dot[deobfuscated]") {
            return Some("Already Deobfuscated".to_string());
        }
        if die_output.contains("Protector: Obfuscar") {
            return Some("Protector: Obfuscar".to_string());
        }
        if die_output.contains("Protector: ConfuserEx") {
            return Some("Protector: ConfuserEx".to_string());
        }
        if die_output.contains("Protector: .NET Reactor") {
            return Some("Protector: .NET Reactor".to_string());
        }
        if die_output.contains(".NET") {
            return Some("Probably No Protector".to_string());
        }
        None
    }

    /// is_file_fully_unknown
    pub fn is_file_fully_unknown(&self, die_output: &str) -> bool {
        let lines: Vec<&str> = die_output
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();
        lines.len() >= 2 && lines[0] == "Binary" && lines[1] == "Unknown: Unknown"
    }

    pub fn is_packed(&self, die_output: &str) -> Option<String> {
        if die_output.contains("Packer:") {
            return Some("GENERIC".to_string());
        }

        let packers = vec![
            ("UPX", vec!["UPX", "UPX0", "UPX1", "UPX2", "UPX!", "upX"]),
            ("ASPACK", vec![".aspack", ".adata"]),
            ("FSG", vec!["FSG"]),
            ("PECOMPACT", vec!["PECompact", "PECompact2"]),
            ("UPACK", vec!["Upack"]),
            ("PETITE", vec![".petite", "petite"]),
            ("MEW", vec!["MEW"]),
            ("YZPACK", vec![".yzpack", ".yzpack2"]),
            ("MPRESS", vec![".MPRESS1", ".MPRESS2"]),
        ];

        for (name, signatures) in packers {
            for sig in signatures {
                if die_output.contains(sig) {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    pub fn packer_type(&self, die_output: &str) -> Option<String> {
        let detected_packer = self.is_packed(die_output)?;

        if die_output.contains("PE64") {
            return Some(format!("PE64 Packed ({detected_packer})"));
        }
        if die_output.contains("PE32") {
            return Some(format!("PE32 Packed ({detected_packer})"));
        }

        Some(format!("Packed ({detected_packer})"))
    }

    pub fn is_upx(&self, die_output: &str) -> bool {
        die_output.contains("Packer: UPX")
    }

    pub fn is_jar(&self, die_output: &str) -> bool {
        die_output.contains("Virtual machine: JVM")
    }

    pub fn is_java_class(&self, die_output: &str) -> bool {
        die_output.contains("Format: Java Class ")
    }

    pub fn detects_plain_text_format(&self, die_output: &str) -> bool {
        die_output.to_lowercase().contains("format: plain text")
    }

    pub fn is_7z(&self, die_output: &str) -> bool {
        die_output.contains("Archive: 7-Zip")
    }

    pub fn is_pyinstaller(&self, die_output: &str) -> bool {
        die_output.contains("Packer: PyInstaller")
    }

    pub fn is_microsoft_compound(&self, die_output: &str) -> bool {
        let indicators = [
            "Microsoft Compound File",
            "OLE",
            "MS Office",
            "Word",
            "Excel",
            "PowerPoint",
            ".doc",
            ".xls",
            ".ppt",
            "Composite Document File",
        ];
        indicators
            .iter()
            .any(|i| die_output.to_lowercase().contains(&i.to_lowercase()))
    }

    pub fn is_nuitka(&self, die_output: &str) -> Option<String> {
        if die_output.contains("Packer: Nuitka[OneFile]") {
            return Some("Nuitka OneFile".to_string());
        }
        if die_output.contains("Packer: Nuitka") {
            return Some("Nuitka".to_string());
        }
        None
    }

    pub fn is_compiled_autohotkey(&self, die_output: &str) -> bool {
        die_output.contains("Format: Compiled AutoHotKey")
    }

    pub fn is_inno_setup(&self, die_output: &str) -> bool {
        die_output.contains("Data: Inno Setup Installer data")
            && die_output.contains("Installer: Inno Setup Module")
    }

    pub fn is_pyarmor_archive_file(&self, file_path: &Path) -> bool {
        let Ok(data) = std::fs::read(file_path) else {
            return false;
        };

        data.starts_with(b"PY00")
            && data
                .windows(b"__pyarmor__".len())
                .any(|window| window == b"__pyarmor__")
    }

    pub fn is_enigma_virtual_box(&self, die_output: &str) -> bool {
        die_output.contains(".enigma1")
    }

    /// Get file type string
    fn get_file_type(&self, die_output: &str) -> Option<String> {
        if die_output.contains("PE64") {
            Some("PE64".to_string())
        } else if die_output.contains("PE32") {
            Some("PE32".to_string())
        } else if die_output.starts_with("ELF64") {
            Some("ELF64".to_string())
        } else if die_output.starts_with("ELF32") {
            Some("ELF32".to_string())
        } else if die_output.starts_with("Mach-O") {
            Some("Mach-O".to_string())
        } else if die_output.to_uppercase().contains("APK") {
            Some("APK".to_string())
        } else {
            None
        }
    }
}

/// Standalone functions (don't require DetectItEasy)

/// Calculate Shannon entropy
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let len = data.len() as f64;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if file is plain text (from Python: is_plain_text)
pub fn is_plain_text_file(file_path: &Path) -> Result<bool, String> {
    let mut file = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;

    let mut buffer = vec![0u8; 8192];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    if bytes_read == 0 {
        return Ok(true);
    }

    let data = &buffer[..bytes_read];

    // Check null bytes
    let null_ratio = data.iter().filter(|&&b| b == 0).count() as f64 / bytes_read as f64;
    if null_ratio > 0.01 {
        return Ok(false);
    }

    // Check control characters
    let control_count = data
        .iter()
        .filter(|&&b| {
            b < 32 && b != b'\n' && b != b'\r' && b != b'\t' && b != b'\x0C' && b != b'\x08'
        })
        .count();
    let control_ratio = control_count as f64 / bytes_read as f64;
    if control_ratio > 0.05 {
        return Ok(false);
    }

    // Check entropy
    if shannon_entropy(data) > 7.9 {
        return Ok(false);
    }

    Ok(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatValidation {
    NotDetected,
    Valid,
    Broken,
}

impl Default for FormatValidation {
    fn default() -> Self {
        Self::NotDetected
    }
}

fn file_type_result(
    detected_by_die: bool,
    validation: FormatValidation,
    broken_label: &str,
) -> Option<String> {
    if validation == FormatValidation::Valid {
        return Some("valid".to_string());
    }

    if detected_by_die || validation == FormatValidation::Broken {
        return Some(broken_label.to_string());
    }

    None
}

#[derive(Debug, Clone, Default)]
struct BinaryFormatValidation {
    pe: FormatValidation,
    elf: FormatValidation,
    macho: FormatValidation,
    apk: FormatValidation,
    file_type: Option<String>,
}

fn inspect_binary_formats(file_path: &Path) -> BinaryFormatValidation {
    let Ok(data) = std::fs::read(file_path) else {
        return BinaryFormatValidation::default();
    };

    let mut validation = BinaryFormatValidation::default();

    match Object::parse(&data) {
        Ok(Object::PE(_)) => {
            validation.pe = FormatValidation::Valid;
            validation.file_type = pe_file_type(&data).or_else(|| Some("PE".to_string()));
        }
        Ok(Object::Elf(_)) => {
            validation.elf = FormatValidation::Valid;
            validation.file_type = elf_file_type(&data).or_else(|| Some("ELF".to_string()));
        }
        Ok(Object::Mach(_)) => {
            validation.macho = FormatValidation::Valid;
            validation.file_type = Some("Mach-O".to_string());
        }
        Ok(Object::COFF(_)) | Ok(Object::Archive(_)) | Ok(Object::Unknown(_)) | Err(_) => {
            mark_broken_executable_magic(&data, &mut validation);
        }
        Ok(_) => {
            mark_broken_executable_magic(&data, &mut validation);
        }
    }

    validation.apk = inspect_apk_bytes(&data);
    if validation.file_type.is_none() && validation.apk == FormatValidation::Valid {
        validation.file_type = Some("APK".to_string());
    }

    validation
}

fn mark_broken_executable_magic(data: &[u8], validation: &mut BinaryFormatValidation) {
    if has_pe_magic(data) {
        validation.pe = FormatValidation::Broken;
        validation.file_type.get_or_insert_with(|| "PE".to_string());
    } else if has_elf_magic(data) {
        validation.elf = FormatValidation::Broken;
        validation
            .file_type
            .get_or_insert_with(|| "ELF".to_string());
    } else if has_macho_magic(data) {
        validation.macho = FormatValidation::Broken;
        validation
            .file_type
            .get_or_insert_with(|| "Mach-O".to_string());
    }
}

fn inspect_apk_bytes(data: &[u8]) -> FormatValidation {
    let has_zip_magic = looks_like_zip(data);
    let has_apk_marker = contains_bytes(data, b"AndroidManifest.xml")
        || contains_bytes(data, b"classes.dex")
        || contains_bytes(data, b"classes2.dex");

    if !has_zip_magic && !has_apk_marker {
        return FormatValidation::NotDetected;
    }

    let cursor = Cursor::new(data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return if has_apk_marker {
            FormatValidation::Broken
        } else {
            FormatValidation::NotDetected
        };
    };

    let mut has_android_manifest = false;
    let mut has_dex = false;

    for index in 0..archive.len() {
        let Ok(file) = archive.by_index(index) else {
            return FormatValidation::Broken;
        };

        let name = file.name();
        if name == "AndroidManifest.xml" {
            has_android_manifest = true;
        } else if name == "classes.dex" || (name.starts_with("classes") && name.ends_with(".dex")) {
            has_dex = true;
        }
    }

    if has_android_manifest {
        return FormatValidation::Valid;
    }

    if has_apk_marker || has_dex {
        return FormatValidation::Broken;
    }

    FormatValidation::NotDetected
}

fn pe_file_type(data: &[u8]) -> Option<String> {
    if !has_pe_magic(data) || data.len() < 0x40 {
        return None;
    }

    let pe_offset = read_u32_le(data, 0x3c)? as usize;
    let optional_header_offset = pe_offset.checked_add(24)?;
    let optional_magic = read_u16_le(data, optional_header_offset)?;

    match optional_magic {
        0x20b => Some("PE64".to_string()),
        0x10b | 0x107 => Some("PE32".to_string()),
        _ => Some("PE".to_string()),
    }
}

fn elf_file_type(data: &[u8]) -> Option<String> {
    if !has_elf_magic(data) || data.len() < 5 {
        return None;
    }

    match data[4] {
        1 => Some("ELF32".to_string()),
        2 => Some("ELF64".to_string()),
        _ => Some("ELF".to_string()),
    }
}

fn has_pe_magic(data: &[u8]) -> bool {
    data.len() >= 2 && &data[0..2] == b"MZ"
}

fn has_elf_magic(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"\x7fELF"
}

fn has_macho_magic(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    matches!(
        read_u32_be(data, 0).unwrap_or(0),
        0xfeedface
            | 0xcefaedfe
            | 0xfeedfacf
            | 0xcffaedfe
            | 0xcafebabe
            | 0xbebafeca
            | 0xcafebabf
            | 0xbfbafeca
    )
}

fn looks_like_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && (data.starts_with(b"PK\x03\x04")
            || data.starts_with(b"PK\x05\x06")
            || data.starts_with(b"PK\x07\x08")
            || contains_bytes(data, b"PK\x05\x06"))
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_detections() {
        let scanner = DetectItEasyScanner::new();

        // Test PE
        assert!(scanner.is_pe_file("PE32\nCompiler: MSVC"));
        assert!(scanner.is_pe_file("PE64\nCompiler: GCC"));

        // Test protectors
        assert!(scanner.is_vmprotect("PE32\nProtector: VMProtect"));
        assert!(
            scanner
                .is_themida("PE32\nProtector: Themida/Winlicense (2.XX)")
                .is_some()
        );

        // Test packers
        assert!(scanner.is_upx("PE32\nPacker: UPX(3.96)"));
        assert!(scanner.is_pyinstaller("PE32\nPacker: PyInstaller"));

        // Test installers
        assert!(scanner.is_nsis("Installer: Nullsoft Scriptable Install System"));
        assert!(
            scanner.is_inno_setup("Data: Inno Setup Installer data\nInstaller: Inno Setup Module")
        );

        // Test unknown
        assert!(scanner.is_file_fully_unknown("Binary\nUnknown: Unknown"));

        // Test generic archive detection
        assert!(scanner.is_archive("Binary\nArchive: Zip archive data"));
    }
}
