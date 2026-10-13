//! VirusKov threat naming convention: `Category.Platform.Family[.Variant]`
//! e.g. `Trojan.Win32.Remcos.A`, `Ransom.MSIL.Chaos`, `PUA.Win64.Bundler.B`,
//! `Vuln.WinDrv.RTCore64` (a legitimate but exploitable file, e.g. a vulnerable driver).
//!
//! Used by the signature room (analyst YARA rules) and by human verdicts, so every
//! name an analyst publishes has the same shape and can be grouped by family.

pub const CATEGORIES: &[&str] = &[
    "Trojan", "Backdoor", "RAT", "Ransom", "Wiper", "Worm", "Virus", "Rootkit", "Bootkit", "Exploit",
    "Downloader", "Dropper", "Loader", "Stealer", "Spyware", "Keylogger", "Banker", "Miner", "Botnet",
    "Phishing", "Adware", "PUA", "HackTool", "Riskware", "Vuln", "Packed", "Generic", "Test",
];

pub const PLATFORMS: &[&str] = &[
    "Win32", "Win64", "MSIL", "WinDrv", "Linux", "MacOS", "Android", "iOS", "Java", "JS", "VBS", "PowerShell",
    "Batch", "Python", "AutoIt", "Office", "PDF", "HTML", "LNK", "Script", "Multi",
];

fn canonical(list: &'static [&'static str], s: &str) -> Option<&'static str> {
    list.iter().find(|c| c.eq_ignore_ascii_case(s)).copied()
}

/// Validates and normalises a threat name. Returns the canonical form.
pub fn normalize_threat_name(input: &str) -> Result<String, String> {
    let parts: Vec<&str> = input.trim().split('.').collect();
    if !(3..=4).contains(&parts.len()) {
        return Err(format!(
            "name must be Category.Platform.Family[.Variant], e.g. Trojan.Win32.Remcos.A (got \"{}\")",
            input.trim()
        ));
    }
    let category = canonical(CATEGORIES, parts[0])
        .ok_or_else(|| format!("unknown category \"{}\"; use one of: {}", parts[0], CATEGORIES.join(", ")))?;
    let platform = canonical(PLATFORMS, parts[1])
        .ok_or_else(|| format!("unknown platform \"{}\"; use one of: {}", parts[1], PLATFORMS.join(", ")))?;
    let fam = parts[2];
    if !(2..=40).contains(&fam.len()) || !fam.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("family must be 2-40 characters: letters, digits, '_' or '-'".into());
    }
    if !fam.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return Err("family must start with a letter".into());
    }
    let mut family = String::with_capacity(fam.len());
    for (i, c) in fam.chars().enumerate() {
        family.push(if i == 0 { c.to_ascii_uppercase() } else { c });
    }
    let mut out = format!("{category}.{platform}.{family}");
    if let Some(v) = parts.get(3) {
        if !(1..=8).contains(&v.len()) || !v.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("variant must be 1-8 letters or digits (e.g. A, B, 2024)".into());
        }
        out.push('.');
        out.push_str(&v.to_ascii_uppercase());
    }
    Ok(out)
}

/// YARA rule identifier for a threat name: dots become underscores.
pub fn yara_identifier(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

/// Malware type of a detection, for grouping (dashboard, API, statistics).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Classification {
    /// One of `CATEGORIES`, or "Unclassified".
    pub category: &'static str,
    /// One of `PLATFORMS`, or "" when unknown.
    pub platform: &'static str,
    /// Family name, or "" when unknown.
    pub family: String,
    /// True when the name follows `Category.Platform.Family[.Variant]` (human verdicts,
    /// analyst signatures); false when it was guessed from an engine's own name.
    pub exact: bool,
}

/// Keywords (lower case) that give the category of an engine's detection name, most
/// specific first. Short ones must be a whole word, long ones may be part of one.
const CATEGORY_WORDS: &[(&str, &[&str])] = &[
    ("Test", &["eicar"]),
    ("Ransom", &["ransom", "ransomware", "filecoder", "cryptolocker", "lockbit", "ryuk", "wannacry", "encoder"]),
    ("Wiper", &["wiper", "killdisk"]),
    ("Bootkit", &["bootkit", "mbr"]),
    ("Rootkit", &["rootkit", "rtkit"]),
    ("Banker", &["banker", "banking"]),
    ("Keylogger", &["keylogger", "keylog"]),
    ("Stealer", &["stealer", "infostealer", "pws", "psw", "passwordstealer", "credstealer", "redline", "lumma", "vidar", "raccoon"]),
    ("Miner", &["miner", "coinminer", "cryptominer", "xmrig", "bitcoinminer"]),
    ("RAT", &["rat", "remoteadmin", "remcos", "njrat", "asyncrat", "darkcomet", "nanocore", "quasar"]),
    ("Backdoor", &["backdoor", "bkdr"]),
    ("Exploit", &["exploit", "exp", "cve"]),
    ("Downloader", &["downloader", "dldr", "dloader"]),
    ("Dropper", &["dropper", "drp"]),
    ("Loader", &["loader"]),
    ("Botnet", &["botnet", "bot"]),
    ("Worm", &["worm"]),
    ("Virus", &["virus", "infector", "virut", "sality", "ramnit"]),
    ("Spyware", &["spyware", "spy", "monitor"]),
    ("Phishing", &["phishing", "phish"]),
    ("Adware", &["adware", "adw"]),
    ("HackTool", &["hacktool", "hktl", "mimikatz", "cobaltstrike"]),
    ("Riskware", &["riskware", "risktool"]),
    ("PUA", &["pua", "pup", "unwanted", "bundler"]),
    ("Vuln", &["vulnerable", "vulndriver", "vuln"]),
    ("Packed", &["packed", "packer", "obfuscated", "obfuscator"]),
    ("Trojan", &["trojan", "troj", "trj"]),
    ("Generic", &["generic", "heur", "heuristic", "malware", "suspicious", "agent", "ml", "behavior", "behaviour"]),
];

const PLATFORM_WORDS: &[(&str, &[&str])] = &[
    ("WinDrv", &["windrv", "driver", "sys"]),
    ("Win64", &["win64", "w64", "x64"]),
    ("MSIL", &["msil", "dotnet", "net"]),
    ("Win32", &["win32", "w32", "win", "pe", "windows"]),
    ("Linux", &["linux", "elf", "unix"]),
    ("MacOS", &["macos", "osx", "mac", "macho"]),
    ("Android", &["android", "andr", "apk", "dex"]),
    ("iOS", &["ios"]),
    ("Java", &["java", "jar"]),
    ("PowerShell", &["powershell", "ps1", "pwsh"]),
    ("VBS", &["vbs", "vbscript"]),
    ("JS", &["js", "javascript", "jscript"]),
    ("Batch", &["batch", "bat", "cmd"]),
    ("Python", &["python", "py"]),
    ("AutoIt", &["autoit", "au3"]),
    ("Office", &["office", "doc", "xls", "ppt", "vba", "macro", "o97m", "w97m", "x97m"]),
    ("PDF", &["pdf"]),
    ("HTML", &["html", "htm"]),
    ("LNK", &["lnk"]),
];

/// Words of a detection name: split on anything but letters/digits and on lower-to-
/// upper case changes ("RansomChaos" -> ransom, chaos), lower case.
fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn find_word(words: &[String], joined: &str, table: &'static [(&'static str, &'static [&'static str])]) -> Option<&'static str> {
    table.iter().find_map(|(name, keys)| {
        keys.iter()
            .any(|k| words.iter().any(|w| w == k) || (k.len() >= 6 && joined.contains(k)))
            .then_some(*name)
    })
}

/// The detection name without the engine's prefixes and layer suffix:
/// "Memory: Unpacked: Win.Trojan.X-1 (ClamAV), ..." -> "Win.Trojan.X-1".
fn clean_detection(name: &str) -> &str {
    let mut s = name.split(", ").next().unwrap_or(name).trim();
    loop {
        let before = s;
        for p in ["Memory:", "Unpacked:", "Stripped:", "Overlay:"] {
            if let Some(r) = s.strip_prefix(p) {
                s = r.trim_start();
            }
        }
        if let Some(r) = s.strip_prefix("Archive:") {
            s = r.split_once(':').map(|(_, t)| t.trim_start()).unwrap_or(r);
        }
        if let Some((_, r)) = s.split_once("): ").filter(|(h, _)| h.starts_with("Analyst signature (")) {
            s = r.trim_start();
        }
        if s == before {
            break;
        }
    }
    if let Some(i) = s.rfind(" (") {
        if s.ends_with(')') {
            s = &s[..i];
        }
    }
    s.trim()
}

/// Category, platform and family of a detection name. Names in the VirusKov format
/// are exact; any other engine name is classified from its words.
pub fn classify(threat: &str) -> Classification {
    let name = clean_detection(threat);
    if let Ok(n) = normalize_threat_name(name) {
        let p: Vec<&str> = n.split('.').collect();
        return Classification {
            category: canonical(CATEGORIES, p[0]).unwrap_or("Unclassified"),
            platform: canonical(PLATFORMS, p[1]).unwrap_or(""),
            family: p[2].to_string(),
            exact: true,
        };
    }
    let w = words(name);
    let joined = w.concat();
    let category = find_word(&w, &joined, CATEGORY_WORDS).unwrap_or("Unclassified");
    let platform = find_word(&w, &joined, PLATFORM_WORDS).unwrap_or("");
    // ClamAV style "Platform.Category.Family-1234": the third part is the family.
    let parts: Vec<&str> = name.split('.').collect();
    let family = if parts.len() >= 3 {
        let f = parts[2].split(['-', ':']).next().unwrap_or("");
        let generic = ["agent", "generic", "gen", "heur", "malware", "variant", "trojan"];
        if f.len() >= 2 && f.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && !generic.contains(&f.to_ascii_lowercase().as_str()) {
            f.to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    Classification { category, platform, family, exact: false }
}

/// Threat name used when a TLSH blacklist name gives nothing better.
pub const BLACKLIST_DEFAULT_THREAT: &str = "Generic.Multi.TLSHBlacklist";

/// Threat name (Category.Platform.Family) from a blacklist name: a family
/// ("AgentTesla", "Smoke Loader") or a sample file name that carries a detection
/// ("HEUR-Backdoor.MSIL.Androm.gen-0136….vir", "Backdoor.MSIL.Remcos.gen.Trojan.Autorun_2.vir").
pub fn threat_from_name(name: &str) -> String {
    // Already a VirusKov name (with its variant): keep it.
    if let Ok(t) = normalize_threat_name(name.trim()) {
        return t;
    }
    let canon = |list: &[&'static str], s: &str| list.iter().find(|c| c.eq_ignore_ascii_case(s)).copied();
    let family_ok = |f: &str| (2..=40).contains(&f.len()) && f.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    // Category.Platform.Family somewhere in the dotted name ("HEUR-" / "Bazaar…__" prefixes
    // on the category, "-<hash>" suffixes on the family are cut off).
    let parts: Vec<&str> = name.split('.').collect();
    for w in parts.windows(3) {
        let cat = w[0].rsplit(['-', ':', '_', ' ']).next().unwrap_or(w[0]);
        let fam = w[2].split(['-', ':', ' ', '@', '!']).next().unwrap_or("");
        if let (Some(c), Some(p)) = (canon(CATEGORIES, cat), canon(PLATFORMS, w[1])) {
            if family_ok(fam) {
                if let Ok(t) = normalize_threat_name(&format!("{c}.{p}.{fam}")) {
                    return t;
                }
            }
        }
    }
    // A plain family name: category from its words, platform Multi.
    if !name.contains('.') {
        let fam: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if family_ok(&fam) {
            let c = classify(name);
            let cat = if c.category == "Unclassified" { "Generic" } else { c.category };
            let plat = if c.platform.is_empty() { "Multi" } else { c.platform };
            if let Ok(t) = normalize_threat_name(&format!("{cat}.{plat}.{fam}")) {
                return t;
            }
        }
    }
    // Some other name: at least the category when the words give one.
    let c = classify(name);
    if c.category != "Unclassified" {
        if let Ok(t) = normalize_threat_name(&format!("{}.{}.TLSHBlacklist", c.category, if c.platform.is_empty() { "Multi" } else { c.platform })) {
            return t;
        }
    }
    BLACKLIST_DEFAULT_THREAT.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_names() {
        let c = classify("Ransom.MSIL.Chaos");
        assert_eq!((c.category, c.platform, c.family.as_str(), c.exact), ("Ransom", "MSIL", "Chaos", true));
        let c = classify("Analyst signature (hydrasig): Stealer.Win32.Lumma.A");
        assert_eq!((c.category, c.family.as_str(), c.exact), ("Stealer", "Lumma", true));
        let c = classify("Memory: Unpacked: Win.Ransomware.Lockbit-9958 (ClamAV), Gen (ML)");
        assert_eq!((c.category, c.platform, c.family.as_str(), c.exact), ("Ransom", "Win32", "Lockbit", false));
        assert_eq!(classify("Win.Trojan.Agent-123").category, "Trojan");
        assert_eq!(classify("Win.Trojan.Agent-123").family, "");
        assert_eq!(classify("MLE_RANSOM_BEHAVIOR").category, "Ransom");
        assert_eq!(classify("HEUR:Trojan-PSW.Win32.Generic").category, "Stealer");
        assert_eq!(classify("XMRigCoinMiner").category, "Miner");
        assert_eq!(classify("Andr.Spyware.SmsSpy").platform, "Android");
        assert_eq!(classify("Eicar-Signature").category, "Test");
        assert_eq!(classify("CleverDeterminer").category, "Unclassified", "'miner' inside another word");
        assert_eq!(classify("something_odd").category, "Unclassified");
    }

    #[test]
    fn names() {
        assert_eq!(normalize_threat_name("trojan.win32.remcos.a").unwrap(), "Trojan.Win32.Remcos.A");
        assert_eq!(normalize_threat_name("RANSOM.msil.chaos").unwrap(), "Ransom.MSIL.Chaos");
        assert!(normalize_threat_name("Remcos").is_err());
        assert!(normalize_threat_name("Foo.Win32.Remcos").is_err());
        assert!(normalize_threat_name("Trojan.Win32.1abc").is_err());
        assert!(normalize_threat_name("Trojan.Win32.Remcos.TOOLONGVAR").is_err());
        assert_eq!(normalize_threat_name("vuln.windrv.RTCore64").unwrap(), "Vuln.WinDrv.RTCore64");
        assert_eq!(yara_identifier("Trojan.Win32.Remcos.A"), "Trojan_Win32_Remcos_A");
    }

    #[test]
    fn threat_from_names() {
        assert_eq!(threat_from_name("Bazaar.2023.01__HEUR-Backdoor.MSIL.Androm.gen-0136b412091dcc7ab89465b919f8b2efa89b23050345f6fefe6eedbf60d393c4.vir"), "Backdoor.MSIL.Androm");
        assert_eq!(threat_from_name("Backdoor.MSIL.Remcos.gen.Trojan.Autorun_2.vir"), "Backdoor.MSIL.Remcos");
        assert_eq!(threat_from_name("Adware.Gator.444.Trojan.Autorun_1.Worm.Win32.Convagent.gen.vir"), "Worm.Win32.Convagent");
        assert_eq!(threat_from_name("AgentTesla"), "Generic.Multi.AgentTesla");
        assert_eq!(threat_from_name("RedLineStealer"), "Stealer.Multi.RedLineStealer");
        assert_eq!(threat_from_name("Smoke Loader"), "Loader.Multi.SmokeLoader");
        assert_eq!(threat_from_name("Trojan.Win32.Remcos.A"), "Trojan.Win32.Remcos.A");
        assert_eq!(threat_from_name("invoice.exe"), BLACKLIST_DEFAULT_THREAT);
    }
}
