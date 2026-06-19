// sality/mod.rs — W32.Sality.PE scan module.
//
// Ports TinyAntivirus's CKillVirus (SalityKiller/KillVirus.cpp).
//
// Algorithm (faithful port):
//   1. Check the file is a PE32.
//   2. Emulate from the entry point, hooking every instruction (UC_HOOK_CODE).
//   3. On each RETN (0xC3) instruction:
//      a. Read ESP → top-of-stack pointer = candidate Sality EP.
//      b. Read 0x100 bytes at that address.
//      c. Verify against two hard-coded Sality byte signatures.
//      d. If match → VirusDetected; recover OEP code and stop emulation.
//   4. If Disinfect mode:
//      a. Restore original code at OEP.
//      b. Fix the PE entry-point header.
//      c. Truncate Sality's code section.
//      d. Return rescan = true (mirrors C++ S_FALSE).
//
// Deletion is expressed via CleanVerdict::Deleted in the ScanResult;
// the ScanObserver (or caller) is responsible for acting on it.
// This mirrors how the C++ OnPostClean callback drives the cleanup decision.
//
// The two Sality byte signatures are lifted directly from KillVirus.cpp.

use crate::error::{AvError, AvResult};
use crate::filetype::Pe32File;
use crate::fs::{EnumContext, FsType, VirtualFs};
use crate::module::{Module, ModuleInfo, ModuleType};
use crate::scanner::{CleanVerdict, ScanModule, ScanObserver, ScanResult, ScanVerdict};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use unicorn_engine::{
    unicorn_const::{Arch, HookType as UcHookType, Mode, Prot, SECOND_SCALE},
    RegisterX86, Unicorn,
};

// ---------------------------------------------------------------------------
// Sality byte signatures (from KillVirus.cpp — VerifySignature)
// ---------------------------------------------------------------------------

const SALITY_SIG1: &[u8] = &[
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xC5, 0x81, 0xED, 0x05, 0x10, 0x40, 0x00, 0x8A, 0x9D,
    0x73, 0x27, 0x40, 0x00, 0x84, 0xDB, 0x74, 0x13, 0x81, 0xC4,
];

const SALITY_SIG2_OFFSET: usize = 0x23;
const SALITY_SIG2: &[u8] = &[
    0x89, 0x85, 0x54, 0x12, 0x40, 0x00, 0xEB, 0x19, 0xC7, 0x85, 0x4D, 0x14, 0x40, 0x00, 0x22, 0x22,
    0x22, 0x22, 0xC7, 0x85, 0x3A, 0x14, 0x40, 0x00, 0x33, 0x33, 0x33, 0x33, 0xE9, 0x82, 0x00, 0x00,
    0x00, 0x33, 0xDB, 0x64, 0x67, 0x8B, 0x1E, 0x30, 0x00, 0x85, 0xDB, 0x78, 0x0E, 0x8B, 0x5B, 0x0C,
];

const MAX_INS_COUNT: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Detection result
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct SalityDetection {
    detected: bool,
    sality_ep: u32,
    oep_addr: u32,
    oep_code: Vec<u8>,
    oep_code_size: u32,
}

// ---------------------------------------------------------------------------
// SalityModule
// ---------------------------------------------------------------------------

/// Scan module that detects and disinfects W32.Sality.PE (ports CKillVirus).
pub struct SalityModule;

impl SalityModule {
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Signature verification (ports CKillVirus::VerifySignature)
    // ------------------------------------------------------------------

    /// Verify the two hard-coded Sality signatures in a 0x100-byte buffer.
    pub fn verify_signature(buf: &[u8]) -> bool {
        if buf.len() < 0x100 {
            return false;
        }
        // Signature 1: at offset 0
        if buf[..SALITY_SIG1.len()] != *SALITY_SIG1 {
            return false;
        }
        // Signature 2: at offset 0x23
        let sig2_end = SALITY_SIG2_OFFSET + SALITY_SIG2.len();
        if buf.len() < sig2_end {
            return false;
        }
        buf[SALITY_SIG2_OFFSET..sig2_end] == *SALITY_SIG2
    }

    // ------------------------------------------------------------------
    // Emulation-based detection (ports CKillVirus::Scan core logic)
    // ------------------------------------------------------------------

    /// Run Unicorn x86-32 emulation over the PE's entry-point code and
    /// return detection state. Shared state is passed into the hook via Arc<Mutex<>>.
    fn run_sality_emulation(pe: &Pe32File) -> AvResult<SalityDetection> {
        let mut uc =
            Unicorn::new(Arch::X86, Mode::MODE_32).map_err(|e| AvError::EmulatorInternal {
                reason: format!("uc_open: {:?}", e),
            })?;

        let image_base = pe.image_base() as u64;
        let raw = pe.raw_data();
        let image_size = ((raw.len() as u64 + 0xFFF) & !0xFFF).max(0x1000);

        // Map PE image
        uc.mem_map(image_base, image_size, Prot::ALL)
            .map_err(|e| AvError::EmulatorInternal {
                reason: format!("mem_map: {:?}", e),
            })?;
        uc.mem_write(image_base, raw)
            .map_err(|e| AvError::EmulatorInternal {
                reason: format!("mem_write: {:?}", e),
            })?;

        // Map stack
        const STACK_BASE: u64 = 0x7F00_0000;
        const STACK_SIZE: u64 = 0x10_0000_u64;
        uc.mem_map(STACK_BASE, STACK_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|e| AvError::EmulatorInternal {
                reason: format!("stack map: {:?}", e),
            })?;
        let esp = STACK_BASE + STACK_SIZE / 2;
        uc.reg_write(RegisterX86::ESP as i32, esp).ok();
        uc.reg_write(RegisterX86::EBP as i32, esp).ok();

        // Shared detection state — written inside the hook, read after emulation ends
        let detected = Arc::new(Mutex::new(false));
        let sality_ep_out = Arc::new(Mutex::new(0u32));
        let oep_addr_out = Arc::new(Mutex::new(0u32));
        let oep_code_out = Arc::new(Mutex::new(Vec::<u8>::new()));
        let oep_sz_out = Arc::new(Mutex::new(0u32));
        let ins_count = Arc::new(Mutex::new(0u64));

        // Clone Arcs for the hook closure
        let det_c = Arc::clone(&detected);
        let sep_c = Arc::clone(&sality_ep_out);
        let oep_c = Arc::clone(&oep_addr_out);
        let code_c = Arc::clone(&oep_code_out);
        let sz_c = Arc::clone(&oep_sz_out);
        let ic_c = Arc::clone(&ins_count);

        // Code hook: fires on every instruction (ports CKillVirus::HookCode)
        uc.add_code_hook(0, u64::MAX, move |uc_ref, address, size| {
            // Instruction counter guard
            {
                let mut cnt = ic_c.lock().unwrap();
                *cnt += 1;
                if *cnt > MAX_INS_COUNT {
                    let _ = uc_ref.emu_stop();
                    return;
                }
            }

            // Only care about 1-byte opcodes (RETN = 0xC3)
            if size != 1 {
                return;
            }
            let opcode = match uc_ref.mem_read_as_vec(address, 1) {
                Ok(b) => b[0],
                Err(_) => return,
            };
            if opcode != 0xC3 {
                return;
            }

            // Read ESP → [ESP] = candidate Sality EP (return address on stack)
            let esp_val = match uc_ref.reg_read(RegisterX86::ESP as i32) {
                Ok(v) => v,
                Err(_) => return,
            };
            let ret_bytes = match uc_ref.mem_read_as_vec(esp_val, 4) {
                Ok(b) => b,
                Err(_) => return,
            };
            let candidate_ep =
                u32::from_le_bytes([ret_bytes[0], ret_bytes[1], ret_bytes[2], ret_bytes[3]]);

            // Read 0x100 bytes at candidate EP for signature check
            let sality_buf = match uc_ref.mem_read_as_vec(candidate_ep as u64, 0x100) {
                Ok(b) => b,
                Err(_) => return,
            };
            if !Self::verify_signature(&sality_buf) {
                return;
            }

            // === VIRUS DETECTED ===
            *det_c.lock().unwrap() = true;
            *sep_c.lock().unwrap() = candidate_ep;

            // Recover OEP — ports CKillVirus::OnHookCode OEP recovery block
            // offset 0x1F: DWORD relative offset → OEP VA = candidate_ep + 5 - rel
            if let Ok(rel_b) = uc_ref.mem_read_as_vec(candidate_ep as u64 + 0x1F, 4) {
                let rel = u32::from_le_bytes([rel_b[0], rel_b[1], rel_b[2], rel_b[3]]);
                let oep = candidate_ep.wrapping_add(5).wrapping_sub(rel);
                *oep_c.lock().unwrap() = oep;

                // offset 0x1773: restore flag byte
                if let Ok(flag) = uc_ref.mem_read_as_vec(candidate_ep as u64 + 0x1773, 1) {
                    if flag[0] != 0 {
                        // offset 0x1774: original code size (DWORD)
                        if let Ok(sz_b) = uc_ref.mem_read_as_vec(candidate_ep as u64 + 0x1774, 4) {
                            let oep_sz = u32::from_le_bytes([sz_b[0], sz_b[1], sz_b[2], sz_b[3]]);
                            *sz_c.lock().unwrap() = oep_sz;
                            // offset 0x1778: original code bytes
                            if oep_sz > 1 {
                                if let Ok(code) = uc_ref
                                    .mem_read_as_vec(candidate_ep as u64 + 0x1778, oep_sz as usize)
                                {
                                    *code_c.lock().unwrap() = code;
                                }
                            }
                        }
                    }
                }
            }

            let _ = uc_ref.emu_stop();
        })
        .map_err(|e| AvError::EmulatorInternal {
            reason: format!("add_code_hook: {:?}", e),
        })?;

        // Invalid memory hook — return false = stop emulation (ports HookMemInvalid)
        uc.add_mem_hook(
            UcHookType::MEM_READ_UNMAPPED | UcHookType::MEM_WRITE_UNMAPPED,
            0,
            u64::MAX,
            |_, _, _, _, _| false,
        )
        .map_err(|e| AvError::EmulatorInternal { reason: format!("add_mem_hook: {:?}", e) })?;

        // Start emulation from the PE entry point
        let ep_va = pe.entry_point_va() as u64;
        let end_addr = image_base + image_size;
        let _ = uc.emu_start(ep_va, end_addr, 10 * SECOND_SCALE, 0);

        // Extract values from Arc<Mutex<>> before constructing the result — the
        // MutexGuard temporaries must not be held across the struct literal boundary.
        let det  = *detected.lock().unwrap();
        let sep  = *sality_ep_out.lock().unwrap();
        let oep  = *oep_addr_out.lock().unwrap();
        let code = oep_code_out.lock().unwrap().clone();
        let sz   = *oep_sz_out.lock().unwrap();

        Ok(SalityDetection {
            detected:      det,
            sality_ep:     sep,
            oep_addr:      oep,
            oep_code:      code,
            oep_code_size: sz,
        })
    }

    // ------------------------------------------------------------------
    // Detect + optional disinfect (ports CKillVirus::Scan body)
    // ------------------------------------------------------------------

    fn detect_and_disinfect(
        &self,
        file: Arc<dyn VirtualFs>,
        context: &EnumContext,
        observer: &Arc<dyn ScanObserver>,
    ) -> AvResult<(ScanResult, bool)> {
        // --- Read raw bytes from the VFS stream ---
        let mut stream = file.open_stream()?;
        stream.seek(SeekFrom::Start(0))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        drop(stream);

        // --- Parse as PE32 ---
        let mut pe = match Pe32File::parse(raw) {
            Ok(p) => p,
            Err(_) => {
                // Not a PE — not applicable to this module
                return Ok((
                    ScanResult {
                        verdict: ScanVerdict::NotAVirus,
                        ..Default::default()
                    },
                    false,
                ));
            }
        };

        // --- Emulate and detect ---
        let detection = Self::run_sality_emulation(&pe)?;

        let mut result = ScanResult::default();

        if !detection.detected {
            result.verdict = ScanVerdict::Clean;
            return Ok((result, false));
        }

        // Virus found
        result.verdict = ScanVerdict::VirusDetected;
        result.malware_name = "W32.Sality.PE".into();

        // Detect-only mode — report but don't clean
        if !context.should_disinfect() {
            result.clean_verdict = CleanVerdict::CleanDenied;
            return Ok((result, false));
        }

        // Notify observer before cleaning
        observer.on_pre_clean(&file, context, &mut result)?;

        // Archive: cannot disinfect, caller should delete based on CleanVerdict
        if file.fs_type() == FsType::Archive {
            result.clean_verdict = CleanVerdict::Deleted;
            observer.on_post_clean(&file, context, &result)?;
            return Ok((result, false));
        }

        // Patient zero (no recoverable OEP code): cannot disinfect, caller should delete
        if detection.oep_code_size <= 1 {
            result.clean_verdict = CleanVerdict::Deleted;
            observer.on_post_clean(&file, context, &result)?;
            return Ok((result, false));
        }

        // --- Disinfect in-place ---
        if detection.oep_addr != 0 && !detection.oep_code.is_empty() {
            let file_offset = pe.va_to_file_offset(detection.oep_addr)?;

            let mut ws = file.open_stream()?;

            // Restore original entry-point code at file offset
            ws.seek(SeekFrom::Start(file_offset as u64))?;
            ws.write_all(&detection.oep_code)?;

            // Fix the PE entry-point field
            pe.set_va_to_entry_point(detection.oep_addr)?;

            // Truncate the Sality virus body
            // Original: m_parser->Truncate(m_salityEp - 0x1116)
            if detection.sality_ep != 0 {
                pe.truncate(detection.sality_ep.wrapping_sub(0x1116), false)
                    .ok();
            }

            result.clean_verdict = CleanVerdict::CleanSucceeded;
        } else {
            result.clean_verdict = CleanVerdict::CleanDenied;
        }

        observer.on_post_clean(&file, context, &result)?;

        // S_FALSE equivalent: rescan only when disinfection succeeded
        let rescan = result.clean_verdict == CleanVerdict::CleanSucceeded;
        Ok((result, rescan))
    }
}

impl Default for SalityModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for SalityModule {
    fn module_info(&self) -> ModuleInfo {
        ModuleInfo {
            module_type: ModuleType::ScanModule,
            name: "W32.Sality.PE".into(),
        }
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::ScanModule
    }

    fn name(&self) -> &str {
        "W32.Sality.PE"
    }
}

impl ScanModule for SalityModule {
    fn on_initialize(&mut self) -> AvResult<()> {
        // No persistent resources needed — Unicorn is created fresh per scan call
        Ok(())
    }

    fn scan(
        &mut self,
        file: Arc<dyn VirtualFs>,
        context: &EnumContext,
        observer: &Arc<dyn ScanObserver>,
    ) -> AvResult<bool> {
        observer.on_pre_scan(&file, context)?;
        let (_result, rescan) = self.detect_and_disinfect(file, context, observer)?;
        Ok(rescan)
    }

    fn on_shutdown(&mut self) -> AvResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_signature_detects_sality() {
        let mut buf = vec![0u8; 0x100];
        buf[..SALITY_SIG1.len()].copy_from_slice(SALITY_SIG1);
        let sig2_end = SALITY_SIG2_OFFSET + SALITY_SIG2.len();
        buf[SALITY_SIG2_OFFSET..sig2_end].copy_from_slice(SALITY_SIG2);
        assert!(SalityModule::verify_signature(&buf));
    }

    #[test]
    fn verify_signature_rejects_clean_buffer() {
        let buf = vec![0u8; 0x100];
        assert!(!SalityModule::verify_signature(&buf));
    }

    #[test]
    fn verify_signature_too_short() {
        let buf = vec![0u8; 10];
        assert!(!SalityModule::verify_signature(&buf));
    }

    #[test]
    fn verify_signature_wrong_sig1() {
        let mut buf = vec![0u8; 0x100];
        // plant sig2 but leave sig1 wrong
        let sig2_end = SALITY_SIG2_OFFSET + SALITY_SIG2.len();
        buf[SALITY_SIG2_OFFSET..sig2_end].copy_from_slice(SALITY_SIG2);
        assert!(!SalityModule::verify_signature(&buf));
    }

    #[test]
    fn module_name_and_type() {
        let m = SalityModule::new();
        assert_eq!(m.name(), "W32.Sality.PE");
        assert_eq!(m.module_type(), ModuleType::ScanModule);
    }

    #[test]
    fn module_info_round_trip() {
        let m = SalityModule::new();
        let info = m.module_info();
        assert_eq!(info.name, "W32.Sality.PE");
        assert_eq!(info.module_type, ModuleType::ScanModule);
    }
}
