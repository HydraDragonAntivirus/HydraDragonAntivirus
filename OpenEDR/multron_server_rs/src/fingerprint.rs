//! Compact structural fingerprints (PE and APK), used by the smart whitelist's
//! injection guards. Built from a VirusKovAlyzer report, so the server and `tlsh_builder`
//! (which includes this file by path) always agree.
//!
//! It keeps only what the guard compares (a few hundred bytes per file), so large
//! reference corpora such as a 200,000-file benign set fit in memory.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Smart whitelist: maximum TLSH distance to a clean reference (DEX TLSH for APKs).
pub const SMART_WL_MAX_DIST: u32 = 20;
/// PE: stricter limit when the entry point address changed.
pub const SMART_WL_MAX_DIST_EP_MOVED: u32 = 10;

/// Imports whose appearance in a "new version" of a clean file is a red flag.
pub const DANGEROUS_IMPORTS: &[&str] = &[
    "virtualallocex", "virtualprotectex", "writeprocessmemory", "createremotethread", "createremotethreadex",
    "ntwritevirtualmemory", "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "ntqueueapcthread",
    "setthreadcontext", "ntunmapviewofsection", "zwunmapviewofsection", "ntmapviewofsection",
    "setwindowshookexa", "setwindowshookexw", "getasynckeystate", "urldownloadtofilea", "urldownloadtofilew",
    "internetopenurla", "internetopenurlw", "winhttpsendrequest", "cryptencrypt", "bcryptencrypt",
    "adjusttokenprivileges", "createservicea", "createservicew", "isdebuggerpresent", "loadlibrarya",
    "loadlibraryw", "getprocaddress", "winexec", "shellexecutea", "shellexecutew",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Section {
    pub name: String,
    pub perms: String,
    pub packed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fingerprint {
    pub size: u64,
    pub machine: String,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub subsystem: String,
    pub has_signature: bool,
    pub entry_point: String,
    pub entry_section: Option<String>,
    pub sections: Vec<Section>,
    pub import_count: u64,
    pub imphash: Option<String>,
    /// "dll!func" (lower case) of the DANGEROUS_IMPORTS present.
    pub dangerous_imports: BTreeSet<String>,
    pub overlay_size: u64,
    pub overlay_entropy: f64,
    /// Ids of medium / high static indicators.
    pub serious_indicators: BTreeSet<String>,
}

impl Fingerprint {
    /// From a VirusKovAlyzer report (as JSON). `None` for non-PE files.
    pub fn from_report(r: &Value) -> Option<Self> {
        let pe = &r["pe"];
        if pe.is_null() {
            return None;
        }
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let mut dangerous = BTreeSet::new();
        for imp in pe["imports"].as_array().into_iter().flatten() {
            let dll = imp["dll"].as_str().unwrap_or("").to_ascii_lowercase();
            for f in imp["functions"].as_array().into_iter().flatten() {
                let f = f.as_str().unwrap_or("").to_ascii_lowercase();
                if DANGEROUS_IMPORTS.contains(&f.as_str()) {
                    dangerous.insert(format!("{dll}!{f}"));
                }
            }
        }
        Some(Fingerprint {
            size: r["size"].as_u64().unwrap_or(0),
            machine: s(&pe["machine"]),
            is_64bit: pe["is_64bit"].as_bool().unwrap_or(false),
            is_dll: pe["is_dll"].as_bool().unwrap_or(false),
            is_dotnet: pe["is_dotnet"].as_bool().unwrap_or(false),
            subsystem: s(&pe["subsystem"]),
            has_signature: pe["has_signature"].as_bool().unwrap_or(false),
            entry_point: s(&pe["entry_point"]),
            entry_section: pe["entry_section"].as_str().map(str::to_string),
            sections: pe["sections"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|x| Section { name: s(&x["name"]), perms: s(&x["perms"]), packed: x["class"].as_str() == Some("packed") })
                .collect(),
            import_count: pe["import_count"].as_u64().unwrap_or(0),
            imphash: r["hashes"]["imphash"].as_str().map(str::to_string),
            dangerous_imports: dangerous,
            overlay_size: pe["overlay_size"].as_u64().unwrap_or(0),
            overlay_entropy: pe["overlay_entropy"].as_f64().unwrap_or(0.0),
            serious_indicators: r["indicators"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|i| matches!(i["severity"].as_str(), Some("medium" | "high")))
                .filter_map(|i| i["id"].as_str().map(str::to_string))
                .collect(),
        })
    }
}

/// `Ok(())` when `cand` looks like the same program as the clean `reference` with
/// nothing added; otherwise the first reason it does not.
pub fn injection_guard(cand: &Fingerprint, reference: &Fingerprint) -> Result<(), String> {
    if cand.machine != reference.machine
        || cand.is_64bit != reference.is_64bit
        || cand.is_dll != reference.is_dll
        || cand.is_dotnet != reference.is_dotnet
        || cand.subsystem != reference.subsystem
    {
        return Err("machine / subsystem / DLL / .NET differs".into());
    }
    if cand.has_signature != reference.has_signature {
        return Err("signature presence differs".into());
    }
    let ratio = cand.size as f64 / (reference.size.max(1)) as f64;
    if !(0.85..=1.15).contains(&ratio) {
        return Err(format!("size changed too much ({} vs {} bytes)", cand.size, reference.size));
    }
    // Script / installer stubs (AutoIt, NSIS, SFX...) keep their real content in a
    // compressed resource or overlay: the stub code dominates TLSH, so two very
    // different payloads look alike. Allow only near-identical sizes there.
    let opaque_payload = reference.sections.iter().any(|s| s.packed)
        || (reference.overlay_size > 1024 && reference.overlay_entropy >= 7.2);
    if opaque_payload && !(0.99..=1.01).contains(&ratio) {
        return Err(format!(
            "packed resource/overlay payload and size changed ({} vs {} bytes)",
            cand.size, reference.size
        ));
    }
    if cand.sections.len() != reference.sections.len() {
        return Err("section count differs".into());
    }
    for (c, r) in cand.sections.iter().zip(reference.sections.iter()) {
        if c.name != r.name || c.perms != r.perms {
            return Err(format!("section {} / {} differs (name or permissions)", c.name, r.name));
        }
        if c.packed && !r.packed {
            return Err(format!("section {} became packed/encrypted", c.name));
        }
    }
    if cand.entry_section != reference.entry_section {
        return Err("entry point moved to another section".into());
    }
    if let Some(bad) = cand.dangerous_imports.difference(&reference.dangerous_imports).next() {
        return Err(format!("new sensitive import {bad}"));
    }
    if cand.imphash != reference.imphash {
        let added = cand.import_count.saturating_sub(reference.import_count);
        if added > (reference.import_count / 10).max(5) {
            return Err(format!("{added} new imports"));
        }
    }
    let (co, ro) = (cand.overlay_size, reference.overlay_size);
    if co > ro + ro / 10 + 4096 {
        return Err(format!("overlay grew from {ro} to {co} bytes"));
    }
    if co > 1024 && ro == 0 {
        return Err("new overlay".into());
    }
    if co > 1024 && cand.overlay_entropy >= 7.2 && reference.overlay_entropy < 7.2 {
        return Err("overlay became encrypted / compressed".into());
    }
    let new_ind: Vec<&String> = cand.serious_indicators.difference(&reference.serious_indicators).collect();
    if !new_ind.is_empty() {
        return Err(format!(
            "new static indicators: {}",
            new_ind.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(())
}

/// `Some(how)` when `cand` is the clean program the malicious `infected` file was made
/// from by a file infector (a classic virus: Neshta, Virut, Sality...).
///
/// A virus adds itself to a clean program and the copy stays a few TLSH points from
/// the original, so a TLSH signature (or the ML models) made from the infected copy
/// also hits the clean original. Infectors only add: the clean host keeps every
/// section in the same order and is not larger. What was added, one of:
/// - prepender: the virus is a program of its own carrying the whole host in its
///   overlay (the overlay is the size of this file);
/// - appender / section adder: new sections, the entry point moved to another
///   section, a section given new permissions (made executable / writable) or
///   packed, a grown overlay, new sensitive imports or static indicators, or the
///   entry point changed in a file that grew.
///
/// `None` when the two are different programs or nothing was added (the same
/// structure: then `cand` is a copy of the infected file, not its host).
pub fn infector_host(cand: &Fingerprint, infected: &Fingerprint) -> Option<String> {
    let slack = cand.size / 20 + 4096;
    if infected.size > cand.size
        && infected.overlay_size + slack >= cand.size
        && infected.overlay_size <= cand.size + slack
    {
        return Some(format!(
            "prepender: the infected file ({} bytes) carries a {} byte overlay, the size of this file",
            infected.size, infected.overlay_size
        ));
    }
    if cand.machine != infected.machine
        || cand.is_64bit != infected.is_64bit
        || cand.is_dll != infected.is_dll
        || cand.is_dotnet != infected.is_dotnet
        || cand.subsystem != infected.subsystem
    {
        return None;
    }
    if cand.size > infected.size
        || cand.sections.len() > infected.sections.len()
        || cand.sections.iter().zip(&infected.sections).any(|(c, i)| c.name != i.name)
    {
        return None;
    }
    let mut added: Vec<String> = Vec::new();
    if infected.sections.len() > cand.sections.len() {
        let new: Vec<&str> = infected.sections[cand.sections.len()..].iter().map(|s| s.name.as_str()).collect();
        added.push(format!("new section {}", new.join(", ")));
    }
    if infected.entry_section != cand.entry_section {
        added.push("entry point moved to another section".into());
    }
    for (c, i) in cand.sections.iter().zip(&infected.sections) {
        if c.perms != i.perms {
            added.push(format!("section {} permissions {} -> {}", c.name, c.perms, i.perms));
        }
        if i.packed && !c.packed {
            added.push(format!("section {} packed / encrypted", c.name));
        }
    }
    if infected.overlay_size > cand.overlay_size + 4096 {
        added.push(format!("overlay grew from {} to {} bytes", cand.overlay_size, infected.overlay_size));
    }
    if let Some(imp) = infected.dangerous_imports.difference(&cand.dangerous_imports).next() {
        added.push(format!("new sensitive import {imp}"));
    }
    let ind: Vec<&str> = infected.serious_indicators.difference(&cand.serious_indicators).map(|s| s.as_str()).collect();
    if !ind.is_empty() {
        added.push(format!("new static indicators {}", ind.join(", ")));
    }
    if added.is_empty() && infected.entry_point != cand.entry_point && infected.size > cand.size + 512 {
        added.push(format!("entry point changed and the file grew by {} bytes", infected.size - cand.size));
    }
    (!added.is_empty()).then(|| format!("the infected file is this program with {}", added.join("; ")))
}

// ------------------------------------------------------------------ APK

/// APK structure for the guard: manifest + signers + layout, and the file size.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApkFp {
    pub size: u64,
    pub info: crate::apk::ApkInfo,
}

impl ApkFp {
    pub fn from_report(r: &Value) -> Option<Self> {
        let info: crate::apk::ApkInfo = serde_json::from_value(r["apk"].clone()).ok()?;
        Some(ApkFp { size: r["size"].as_u64().unwrap_or(0), info })
    }
}

/// `Ok(())` when the candidate APK is the same app from the same developer with nothing
/// added. The signing certificate is the core check: repackaged malware (the usual
/// Android trick: a real app plus a payload) cannot carry the original developer's
/// signature. Debug / AOSP test keys are public, so they never qualify.
pub fn apk_guard(cand: &ApkFp, reference: &ApkFp) -> Result<(), String> {
    let (c, r) = (&cand.info, &reference.info);
    if r.signers.is_empty() || c.signers.is_empty() {
        return Err("unsigned APK or signature not readable".into());
    }
    if r.test_key || c.test_key {
        return Err("signed with a public debug / test key".into());
    }
    if c.signers != r.signers {
        return Err("different signing certificate".into());
    }
    if c.package.is_empty() || c.package != r.package {
        return Err(format!("package differs ({} vs {})", c.package, r.package));
    }
    let ratio = cand.size as f64 / (reference.size.max(1)) as f64;
    if !(0.85..=1.15).contains(&ratio) {
        return Err(format!("size changed too much ({} vs {} bytes)", cand.size, reference.size));
    }
    if c.dex_count != r.dex_count {
        return Err("number of DEX files differs".into());
    }
    if let Some(p) = c.permissions.difference(&r.permissions).next() {
        return Err(format!("new permission {p}"));
    }
    for (kind, cs, rs) in [("service", &c.services, &r.services), ("receiver", &c.receivers, &r.receivers), ("provider", &c.providers, &r.providers)] {
        if let Some(n) = cs.difference(rs).next() {
            return Err(format!("new {kind} {n}"));
        }
    }
    if let Some(l) = c.native_libs.difference(&r.native_libs).next() {
        return Err(format!("new native library {l}"));
    }
    Ok(())
}

// ------------------------------------------------------------------ common

/// What the guard compares, by file kind.
#[derive(Debug, Clone)]
pub enum Structure {
    Pe(Fingerprint),
    Apk(ApkFp),
}

impl Structure {
    /// From a VirusKovAlyzer report; `None` for kinds the smart whitelist does not cover.
    pub fn from_report(r: &Value) -> Option<Self> {
        if let Some(fp) = Fingerprint::from_report(r) {
            return Some(Structure::Pe(fp));
        }
        ApkFp::from_report(r).map(Structure::Apk)
    }
}

/// Full smart-whitelist rule for one (candidate, clean reference) pair at TLSH
/// distance `d`. Shared by the server and `tlsh_builder tune`.
pub fn accept(d: u32, cand: &Structure, reference: &Structure) -> Result<(), String> {
    if d > SMART_WL_MAX_DIST {
        return Err(format!("distance {d} > {SMART_WL_MAX_DIST}"));
    }
    match (cand, reference) {
        (Structure::Pe(c), Structure::Pe(r)) => {
            // A moved entry point is how file infectors and code caves usually take
            // control; allow it only for an even closer match.
            if c.entry_point != r.entry_point && d > SMART_WL_MAX_DIST_EP_MOVED {
                return Err(format!("entry point moved and distance {d} > {SMART_WL_MAX_DIST_EP_MOVED}"));
            }
            injection_guard(c, r)
        }
        (Structure::Apk(c), Structure::Apk(r)) => apk_guard(c, r),
        _ => Err("different file kinds".into()),
    }
}

/// One line of a reference corpus file (`tlsh_whitelist_refs.jsonl`), as written by
/// `tlsh_builder refs` and read by the server. `tlsh` is the DEX TLSH for APKs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefLine {
    pub sha256: String,
    pub tlsh: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<Fingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apk: Option<ApkFp>,
    /// Path inside the corpus (for reports only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

impl RefLine {
    pub fn structure(&self) -> Option<Structure> {
        match (&self.fp, &self.apk) {
            (Some(fp), _) => Some(Structure::Pe(fp.clone())),
            (None, Some(a)) => Some(Structure::Apk(a.clone())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod infector_tests {
    use super::*;

    fn sec(name: &str, perms: &str) -> Section {
        Section { name: name.into(), perms: perms.into(), packed: false }
    }

    fn host() -> Fingerprint {
        Fingerprint {
            size: 500_000,
            machine: "AMD64".into(),
            is_64bit: true,
            is_dll: false,
            is_dotnet: false,
            subsystem: "GUI".into(),
            has_signature: false,
            entry_point: "0x1000".into(),
            entry_section: Some(".text".into()),
            sections: vec![sec(".text", "r-x"), sec(".rdata", "r--"), sec(".data", "rw-"), sec(".rsrc", "r--")],
            import_count: 120,
            imphash: Some("aa".into()),
            dangerous_imports: BTreeSet::new(),
            overlay_size: 0,
            overlay_entropy: 0.0,
            serious_indicators: BTreeSet::new(),
        }
    }

    #[test]
    fn section_adder_host_is_the_clean_original() {
        // Virut-like: a new last section holding the virus, entry point moved there.
        let mut infected = host();
        infected.size += 12_000;
        infected.sections.push(sec(".vir", "rwx"));
        infected.entry_section = Some(".vir".into());
        infected.entry_point = "0x80000".into();
        let how = infector_host(&host(), &infected).expect("host recognised");
        assert!(how.contains("new section .vir"), "{how}");
    }

    #[test]
    fn last_section_appender_host_is_the_clean_original() {
        // Sality-like: the virus appended to the last section, made executable.
        let mut infected = host();
        infected.size += 70_000;
        infected.sections[3].perms = "rwx".into();
        assert!(infector_host(&host(), &infected).is_some());
    }

    #[test]
    fn prepender_host_is_the_clean_original() {
        // Neshta-like: a small virus PE carrying the whole host in its overlay.
        let mut infected = host();
        infected.size = 41_472 + 500_000;
        infected.is_64bit = false;
        infected.machine = "I386".into();
        infected.sections = vec![sec("CODE", "r-x"), sec("DATA", "rw-")];
        infected.overlay_size = 500_000;
        assert!(infector_host(&host(), &infected).unwrap().starts_with("prepender"));
    }

    #[test]
    fn copy_of_the_infected_file_is_not_a_host() {
        // Same structure as the infected sample: another copy of it, still malicious.
        let mut infected = host();
        infected.size += 12_000;
        infected.sections.push(sec(".vir", "rwx"));
        infected.entry_section = Some(".vir".into());
        let mut other_copy = infected.clone();
        other_copy.size += 16;
        assert!(infector_host(&other_copy, &infected).is_none());
        assert!(infector_host(&infected, &infected).is_none());
    }

    #[test]
    fn different_program_is_not_a_host() {
        let mut infected = host();
        infected.sections.push(sec(".vir", "rwx"));
        let mut other = host();
        other.sections[1].name = ".idata".into();
        assert!(infector_host(&other, &infected).is_none());
        let mut bigger = host();
        bigger.size = infected.size + 1;
        assert!(infector_host(&bigger, &infected).is_none());
    }
}
