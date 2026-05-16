//! DetectItEasy integration for Owlyshield.
//!
//! Owlyshield runs DetectItEasy in Rust and sends the parsed JSON to Python so
//! HydraDragon can consume the detection data without spawning DIE itself.

use crate::logging::Logging;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

        let output = command
            .output()
            .map_err(|e| format!("Failed to run diec.exe: {}", e))?;

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
        let pe_status = inspect_pe_file(file_path);
        let elf_status = inspect_elf_file(file_path);
        let macho_status = inspect_macho_file(file_path);
        let apk_status = inspect_apk_file(file_path);
        let pe_result = file_type_result(
            self.is_pe_file(die_output),
            pe_status,
            "Broken Executable",
        );
        let elf_result = file_type_result(
            self.is_elf_file(die_output),
            elf_status,
            "Broken Executable",
        );
        let macho_result = file_type_result(
            self.is_macho_file(die_output),
            macho_status,
            "Broken Executable",
        );
        let apk_result = file_type_result(self.is_apk_file(die_output), apk_status, "Broken APK");
        let broken_executable_type = [
            ("PE", pe_status, pe_result.as_deref()),
            ("ELF", elf_status, elf_result.as_deref()),
            ("Mach-O", macho_status, macho_result.as_deref()),
            ("APK", apk_status, apk_result.as_deref()),
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
            is_pe: self.is_pe_file(die_output),
            is_elf: self.is_elf_file(die_output),
            is_macho: self.is_macho_file(die_output),
            is_apk: self.is_apk_file(die_output),
            file_type: self.get_file_type(die_output),
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
            is_pyinstaller: self.is_pyinstaller(die_output),
            is_nuitka: nuitka_type.is_some(),
            nuitka_type,
            is_cx_freeze: self.is_cx_freeze(die_output),
            is_nexe: self.is_nexe(die_output),
            is_npm: self.is_npm(die_output),

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

fn inspect_pe_file(file_path: &Path) -> FormatValidation {
    let Ok(data) = std::fs::read(file_path) else {
        return FormatValidation::NotDetected;
    };
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return FormatValidation::NotDetected;
    }

    let pe_offset = read_u32_le(&data, 0x3c).unwrap_or(0) as usize;
    if pe_offset < 0x40 || pe_offset.checked_add(24).map_or(true, |end| end > data.len()) {
        return FormatValidation::Broken;
    }
    if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0".as_slice()) {
        return FormatValidation::Broken;
    }

    let coff = pe_offset + 4;
    let machine = read_u16_le(&data, coff).unwrap_or(0);
    let sections = read_u16_le(&data, coff + 2).unwrap_or(0) as usize;
    let optional_size = read_u16_le(&data, coff + 16).unwrap_or(0) as usize;
    if machine == 0 || sections == 0 || sections > 96 || optional_size < 2 {
        return FormatValidation::Broken;
    }

    let optional_offset = coff + 20;
    let Some(section_table) = optional_offset.checked_add(optional_size) else {
        return FormatValidation::Broken;
    };
    if section_table > data.len() {
        return FormatValidation::Broken;
    }

    let optional_magic = read_u16_le(&data, optional_offset).unwrap_or(0);
    if !matches!(optional_magic, 0x10b | 0x20b | 0x107) {
        return FormatValidation::Broken;
    }

    let section_table_size = sections.saturating_mul(40);
    if section_table
        .checked_add(section_table_size)
        .map_or(true, |end| end > data.len())
    {
        return FormatValidation::Broken;
    }

    for index in 0..sections {
        let section = section_table + index * 40;
        let raw_size = read_u32_le(&data, section + 16).unwrap_or(0) as usize;
        let raw_ptr = read_u32_le(&data, section + 20).unwrap_or(0) as usize;
        if raw_size == 0 {
            continue;
        }
        if raw_ptr == 0
            || raw_ptr
                .checked_add(raw_size)
                .map_or(true, |end| end > data.len())
        {
            return FormatValidation::Broken;
        }
    }

    FormatValidation::Valid
}

fn inspect_elf_file(file_path: &Path) -> FormatValidation {
    let Ok(data) = std::fs::read(file_path) else {
        return FormatValidation::NotDetected;
    };
    if data.len() < 4 || &data[0..4] != b"\x7fELF" {
        return FormatValidation::NotDetected;
    }
    if data.len() < 16 {
        return FormatValidation::Broken;
    }

    let class = data[4];
    let endian = data[5];
    if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) {
        return FormatValidation::Broken;
    }

    let header_size = if class == 1 { 52usize } else { 64usize };
    if data.len() < header_size {
        return FormatValidation::Broken;
    }

    let read_u16 = |offset| read_u16_endian(&data, offset, endian);
    let read_u32 = |offset| read_u32_endian(&data, offset, endian);
    let read_u64 = |offset| read_u64_endian(&data, offset, endian);

    let (phoff, shoff, ehsize, phentsize, phnum, shentsize, shnum) = if class == 1 {
        (
            read_u32(28).unwrap_or(0) as u64,
            read_u32(32).unwrap_or(0) as u64,
            read_u16(40).unwrap_or(0),
            read_u16(42).unwrap_or(0),
            read_u16(44).unwrap_or(0),
            read_u16(46).unwrap_or(0),
            read_u16(48).unwrap_or(0),
        )
    } else {
        (
            read_u64(32).unwrap_or(0),
            read_u64(40).unwrap_or(0),
            read_u16(52).unwrap_or(0),
            read_u16(54).unwrap_or(0),
            read_u16(56).unwrap_or(0),
            read_u16(58).unwrap_or(0),
            read_u16(60).unwrap_or(0),
        )
    };

    if ehsize as usize != header_size {
        return FormatValidation::Broken;
    }
    if phnum > 0 && !table_fits(data.len(), phoff, phentsize, phnum) {
        return FormatValidation::Broken;
    }
    if shnum > 0 && !table_fits(data.len(), shoff, shentsize, shnum) {
        return FormatValidation::Broken;
    }

    FormatValidation::Valid
}

fn inspect_macho_file(file_path: &Path) -> FormatValidation {
    let Ok(data) = std::fs::read(file_path) else {
        return FormatValidation::NotDetected;
    };
    if data.len() < 4 {
        return FormatValidation::NotDetected;
    }

    let magic = read_u32_be(&data, 0).unwrap_or(0);
    let (is_64, little_endian) = match magic {
        0xfeedface => (false, false),
        0xcefaedfe => (false, true),
        0xfeedfacf => (true, false),
        0xcffaedfe => (true, true),
        0xcafebabe | 0xbebafeca => return inspect_fat_macho(&data, false),
        0xcafebabf | 0xbfbafeca => return inspect_fat_macho(&data, true),
        _ => return FormatValidation::NotDetected,
    };

    let header_size = if is_64 { 32usize } else { 28usize };
    if data.len() < header_size {
        return FormatValidation::Broken;
    }

    let ncmds = read_u32_macho(&data, 16, little_endian).unwrap_or(0) as usize;
    let sizeofcmds = read_u32_macho(&data, 20, little_endian).unwrap_or(0) as usize;
    if ncmds == 0
        || header_size
            .checked_add(sizeofcmds)
            .map_or(true, |end| end > data.len())
    {
        return FormatValidation::Broken;
    }

    let mut offset = header_size;
    for _ in 0..ncmds {
        if offset.checked_add(8).map_or(true, |end| end > data.len()) {
            return FormatValidation::Broken;
        }
        let cmdsize = read_u32_macho(&data, offset + 4, little_endian).unwrap_or(0) as usize;
        if cmdsize < 8 || offset.checked_add(cmdsize).map_or(true, |end| end > data.len()) {
            return FormatValidation::Broken;
        }
        offset += cmdsize;
    }

    FormatValidation::Valid
}

fn inspect_apk_file(file_path: &Path) -> FormatValidation {
    let Ok(data) = std::fs::read(file_path) else {
        return FormatValidation::NotDetected;
    };
    if data.len() < 4 || &data[0..2] != b"PK" {
        return FormatValidation::NotDetected;
    }
    if !contains_bytes(&data, b"AndroidManifest.xml") && !contains_bytes(&data, b"classes.dex") {
        return FormatValidation::NotDetected;
    }
    if !contains_bytes(&data, b"PK\x05\x06") {
        return FormatValidation::Broken;
    }

    FormatValidation::Valid
}

fn inspect_fat_macho(data: &[u8], is_64: bool) -> FormatValidation {
    if data.len() < 8 {
        return FormatValidation::Broken;
    }
    let nfat_arch = read_u32_be(data, 4).unwrap_or(0) as usize;
    let arch_size = if is_64 { 32usize } else { 20usize };
    if nfat_arch == 0
        || 8usize
            .checked_add(nfat_arch.saturating_mul(arch_size))
            .map_or(true, |end| end > data.len())
    {
        return FormatValidation::Broken;
    }
    FormatValidation::Valid
}

fn table_fits(file_len: usize, offset: u64, entry_size: u16, count: u16) -> bool {
    if offset == 0 || entry_size == 0 {
        return false;
    }
    let size = (entry_size as u64).saturating_mul(count as u64);
    offset
        .checked_add(size)
        .map_or(false, |end| end <= file_len as u64)
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u16_endian(data: &[u8], offset: usize, endian: u8) -> Option<u16> {
    if endian == 1 {
        read_u16_le(data, offset)
    } else {
        Some(u16::from_be_bytes(data.get(offset..offset + 2)?.try_into().ok()?))
    }
}

fn read_u32_endian(data: &[u8], offset: usize, endian: u8) -> Option<u32> {
    if endian == 1 {
        read_u32_le(data, offset)
    } else {
        read_u32_be(data, offset)
    }
}

fn read_u64_endian(data: &[u8], offset: usize, endian: u8) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(if endian == 1 {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn read_u32_macho(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    if little_endian {
        read_u32_le(data, offset)
    } else {
        read_u32_be(data, offset)
    }
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
    }
}
