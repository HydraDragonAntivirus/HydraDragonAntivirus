//! VirusKov threat naming convention: `Category.Platform.Family[.Variant]`
//! e.g. `Trojan.Win32.Remcos.A`, `Ransom.MSIL.Chaos`, `PUA.Win64.Bundler.B`.
//!
//! Used by the signature room (analyst YARA rules) and by human verdicts, so every
//! name an analyst publishes has the same shape and can be grouped by family.

pub const CATEGORIES: &[&str] = &[
    "Trojan", "Backdoor", "RAT", "Ransom", "Wiper", "Worm", "Virus", "Rootkit", "Bootkit", "Exploit",
    "Downloader", "Dropper", "Loader", "Stealer", "Spyware", "Keylogger", "Banker", "Miner", "Botnet",
    "Phishing", "Adware", "PUA", "HackTool", "Riskware", "Packed", "Generic", "Test",
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names() {
        assert_eq!(normalize_threat_name("trojan.win32.remcos.a").unwrap(), "Trojan.Win32.Remcos.A");
        assert_eq!(normalize_threat_name("RANSOM.msil.chaos").unwrap(), "Ransom.MSIL.Chaos");
        assert!(normalize_threat_name("Remcos").is_err());
        assert!(normalize_threat_name("Foo.Win32.Remcos").is_err());
        assert!(normalize_threat_name("Trojan.Win32.1abc").is_err());
        assert!(normalize_threat_name("Trojan.Win32.Remcos.TOOLONGVAR").is_err());
        assert_eq!(yara_identifier("Trojan.Win32.Remcos.A"), "Trojan_Win32_Remcos_A");
    }
}
