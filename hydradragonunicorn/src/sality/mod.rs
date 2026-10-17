// sality/mod.rs — W32.Sality.PE scan module (VFS / ScanService front end).
//
// Ports TinyAntivirus's CKillVirus (SalityKiller/KillVirus.cpp). The detection
// and repair recipe (signatures, stored OEP at +0x1F, stolen code at +0x1773..,
// truncation at start - 0x1116) now lives in disinfect_rules/default.yaml and
// runs on the generic disinfector (crate::disinfect); this module only adapts it
// to the ScanModule / ScanObserver interface.
//
// Deletion is expressed via CleanVerdict::Deleted in the ScanResult; the
// ScanObserver (or caller) is responsible for acting on it.

use crate::disinfect::{DisinfectOutcome, DisinfectRules};
use crate::error::AvResult;
use crate::fs::{EnumContext, FsType, VirtualFs};
use crate::module::{Module, ModuleInfo, ModuleType};
use crate::scanner::{CleanVerdict, ScanModule, ScanObserver, ScanResult, ScanVerdict};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

const NAME: &str = "W32.Sality.PE";

/// Scan module that detects and disinfects W32.Sality.PE (ports CKillVirus).
pub struct SalityModule;

impl SalityModule {
    pub fn new() -> Self {
        Self
    }

    fn rules() -> DisinfectRules {
        DisinfectRules::builtin().only(NAME)
    }

    /// Detect and disinfect W32.Sality.PE in memory: nothing is written anywhere.
    pub fn disinfect_bytes(raw: &[u8]) -> AvResult<DisinfectOutcome> {
        Ok(crate::disinfect::disinfect_bytes_with(raw, &Self::rules()))
    }

    fn detect_and_disinfect(
        &self,
        file: Arc<dyn VirtualFs>,
        context: &EnumContext,
        observer: &Arc<dyn ScanObserver>,
    ) -> AvResult<(ScanResult, bool)> {
        let mut stream = file.open_stream()?;
        stream.seek(SeekFrom::Start(0))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        drop(stream);

        let rules = Self::rules();
        let mut result = ScanResult::default();
        if crate::disinfect::detect_bytes_with(&raw, &rules).is_none() {
            result.verdict = ScanVerdict::Clean;
            return Ok((result, false));
        }
        result.verdict = ScanVerdict::VirusDetected;
        result.malware_name = NAME.into();

        // Detect-only mode — report but don't clean
        if !context.should_disinfect() {
            result.clean_verdict = CleanVerdict::CleanDenied;
            return Ok((result, false));
        }

        observer.on_pre_clean(&file, context, &mut result)?;

        // Archive member: cannot be repaired in place, the caller deletes it.
        if file.fs_type() == FsType::Archive {
            result.clean_verdict = CleanVerdict::Deleted;
            observer.on_post_clean(&file, context, &result)?;
            return Ok((result, false));
        }

        match crate::disinfect::disinfect_bytes_with(&raw, &rules) {
            DisinfectOutcome::Disinfected { data, .. } => {
                let mut ws = file.open_stream()?;
                ws.seek(SeekFrom::Start(0))?;
                ws.write_all(&data)?;
                ws.shrink()?;
                result.clean_verdict = CleanVerdict::CleanSucceeded;
            }
            // Patient zero or an unsafe repair: only deletion is safe.
            DisinfectOutcome::NotRepairable { .. } => result.clean_verdict = CleanVerdict::Deleted,
            DisinfectOutcome::NotInfected => result.clean_verdict = CleanVerdict::CleanDenied,
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
        ModuleInfo { module_type: ModuleType::ScanModule, name: NAME.into() }
    }

    fn module_type(&self) -> ModuleType {
        ModuleType::ScanModule
    }

    fn name(&self) -> &str {
        NAME
    }
}

impl ScanModule for SalityModule {
    fn on_initialize(&mut self) -> AvResult<()> {
        // Unicorn is created fresh per scan call; the definition must load.
        if Self::rules().is_empty() {
            return Err(crate::error::AvError::InvalidArgument);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name_and_type() {
        let m = SalityModule::new();
        assert_eq!(m.name(), NAME);
        assert_eq!(m.module_type(), ModuleType::ScanModule);
        assert_eq!(m.module_info().name, NAME);
    }

    #[test]
    fn definition_is_built_in() {
        assert_eq!(SalityModule::rules().rules.len(), 1);
    }
}
