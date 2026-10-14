// disinfect.rs — Signature-based disinfection of in-memory files.
//
// A disinfector only acts when it RECOGNISES the infection by signature
// (today: W32.Sality.PE, emulation + byte signatures). It removes the virus
// and returns the repaired bytes; it never writes a file. Whether the caller
// should use the repaired file at all is a separate decision: a repaired
// program is not the original, so for anything but a system file deleting
// and reinstalling (or restoring a clean copy) is the safer advice.

/// Result of [`disinfect_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisinfectOutcome {
    /// No known (signature) infection was found.
    NotInfected,
    /// The infection was removed; `data` is the repaired file.
    Disinfected {
        malware_name: String,
        data: Vec<u8>,
        /// Bytes cut off (the virus body appended to the file).
        removed_bytes: usize,
    },
    /// The infection is known but cannot be removed safely (e.g. patient zero).
    NotRepairable { malware_name: String, reason: String },
}

/// Run every signature disinfector over `raw`, first match wins.
pub fn disinfect_bytes(raw: &[u8]) -> DisinfectOutcome {
    match crate::sality::SalityModule::disinfect_bytes(raw) {
        Ok(DisinfectOutcome::NotInfected) | Err(_) => DisinfectOutcome::NotInfected,
        Ok(found) => found,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pe_is_not_infected() {
        assert_eq!(disinfect_bytes(b"not a PE file at all"), DisinfectOutcome::NotInfected);
    }
}
