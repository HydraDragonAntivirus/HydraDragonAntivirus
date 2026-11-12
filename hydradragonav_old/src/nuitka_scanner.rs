//! Nuitka onefile executable detection and extraction.
//!
//! Nuitka compiles Python source into a native PE or ELF binary with an
//! embedded payload (RCDATA/27 on PE, appended on ELF) containing the
//! compressed Python modules.  This module detects such binaries and
//! exposes the extracted files for downstream scanning.

/// Quick magic check — `extract_from_bytes` already does this internally,
/// but having it up front avoids trying every non-Nuitka binary.
pub fn is_nuitka_executable(bytes: &[u8]) -> bool {
    // Must be PE (MZ) or ELF first.
    if bytes.len() < 4 {
        return false;
    }
    let is_pe = bytes[0] == 0x4D && bytes[1] == 0x5A;
    let is_elf = bytes[..4] == [0x7F, 0x45, 0x4C, 0x46];
    if !is_pe && !is_elf {
        return false;
    }

    // Probe for the Nuitka magic "KAX" or "KAY" near the end of the file.
    // On PE the payload lives in RCDATA/27; on ELF it's appended.
    // The size trailer is 8 bytes, and the 3 magic bytes precede the payload.
    // For a quick check we scan backwards from the end.
    if is_pe {
        // PE: payload is in resource section, not at end.
        // Just try a lightweight parse — use pelite to peek at RCDATA/27.
        // We do the full check inside `extract_from_bytes` anyway.
        // For the quick check, scan backwards up to 4KB from end for "KAX"/"KAY".
        let search_start = bytes.len().saturating_sub(4096);
        if bytes[search_start..]
            .windows(3)
            .any(|w| w == b"KAX" || w == b"KAY")
        {
            return true;
        }
        false
    } else {
        // ELF: payload is appended at the end.
        // The last 8 bytes are the size; before that is the magic.
        if bytes.len() < 11 {
            return false;
        }
        let payload_start = bytes.len() - 8;
        // The size tells us where the magic starts.
        if let Ok(size) = bytes[payload_start..].try_into().map(u64::from_le_bytes) {
            if size > 0 && (size as usize) < bytes.len().saturating_sub(8) {
                let magic_start = bytes.len() - 8 - size as usize;
                if bytes.get(magic_start..magic_start + 3) == Some(b"KAX")
                    || bytes.get(magic_start..magic_start + 3) == Some(b"KAY")
                {
                    return true;
                }
            }
        }
        false
    }
}

/// Try to extract Nuitka payload entries from a byte slice.
/// Returns `None` if the data is not a Nuitka executable.
pub fn extract_from_bytes(bytes: &[u8]) -> Option<Vec<nuitka_extractor::ExtractedEntry>> {
    nuitka_extractor::extract_from_bytes(bytes).ok()
}
