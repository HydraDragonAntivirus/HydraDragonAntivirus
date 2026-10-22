use std::collections::HashMap;
use std::path::Path;
use std::sync::{OnceLock, RwLock};
use yara_x::{Compiler, MetaValue, Rules, Scanner};

/// Name parts that mark a rule as potentially unwanted rather than malware (dual-use
/// and grey tools: Process Hacker, adware bundles, vulnerable drivers, ...). A part is
/// a `_` / `.` / `-` separated segment, compared case-insensitively, anywhere in the name
/// (`SIGNATURE_BASE_PUA_VULN_Driver_…`, `ELASTIC_Windows_Hacktool_Processhacker_…`;
/// `HKTL` is signature-base's hacktool prefix).
const PUA_NAME_PARTS: [&str; 8] = ["pua", "pup", "hacktool", "hktl", "greyware", "grayware", "riskware", "adware"];

/// Phrases in a rule's metadata values that mark it as potentially unwanted
/// (`rule_category = "greyware_tool_keyword"`, `description = "Detects … Hacktool …"`).
const PUA_META_PHRASES: [&str; 8] = [
    "greyware", "grayware", "potentially unwanted", "hacktool", "hack tool", "riskware", "adware", "pua_",
];

/// Name parts of indicator / heuristic rules (`SUSP_…`, `INDICATOR_SUSPICIOUS_…`): they
/// describe something odd, not a malware family, and give Suspicious. By name only:
/// metadata saying "suspicious" also covers malware family rules whose description starts
/// "Detects suspicious …" (Andromeda, the Shamoon RawDisk agent, CrashOverride).
const SUSPICIOUS_NAME_PARTS: [&str; 2] = ["susp", "suspicious"];

/// Offensive tools used in real intrusions (credential theft, C2, lateral movement):
/// their rules stay Malicious even when filed as hacktool / greyware / suspicious.
/// Matched in the rule name and metadata values, lower case, with `_` `.` `-` and
/// spaces removed (`CobaltStrike`, `Cobalt_Strike`, `Cobalt Strike`).
const OFFENSIVE_TOOLS: [&str; 19] = [
    "mimikatz", "katz", "cobaltstrike", "lazagne", "rubeus", "kekeo", "sharphound", "bloodhound", "impacket",
    "metasploit", "meterpreter", "sliver", "bruteratel", "havoc", "nanodump", "lsassy", "powersploit", "potato",
    "printspoofer",
];

/// What a YARA rule's match means for the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleClass {
    Malware,
    Suspicious,
    Pua,
}

/// Class of every loaded rule that is marked PUA or suspicious (by name or metadata),
/// by identifier (filled as rule sets load). Rules not in it are judged by name alone.
fn decided() -> &'static RwLock<HashMap<String, RuleClass>> {
    static MAP: OnceLock<RwLock<HashMap<String, RuleClass>>> = OnceLock::new();
    MAP.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Named `PUA_*` / `PUA.*` by its author: always potentially unwanted.
fn explicit_pua(name: &str) -> bool {
    name.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("PUA_") || p.eq_ignore_ascii_case("PUA."))
}

fn has_name_part(name: &str, parts: &[&str]) -> bool {
    name.split(['_', '.', '-']).any(|p| parts.iter().any(|k| p.eq_ignore_ascii_case(k)))
}

/// The rule name marks it potentially unwanted (see `PUA_NAME_PARTS`).
pub fn is_pua_name(name: &str) -> bool {
    has_name_part(name, &PUA_NAME_PARTS)
}

/// `text` names an offensive tool (see `OFFENSIVE_TOOLS`).
fn names_offensive_tool(text: &str) -> bool {
    let t: String = text.chars().filter(|c| !matches!(c, '_' | '.' | '-' | ' ')).collect::<String>().to_ascii_lowercase();
    OFFENSIVE_TOOLS.iter().any(|k| t.contains(k))
}

/// The class from the marks found: named `PUA_*` → PUA; an offensive tool → Malware;
/// else a PUA mark → PUA, a suspicious mark → Suspicious, nothing → Malware.
fn classify(explicit: bool, pua: bool, suspicious: bool, offensive: bool) -> RuleClass {
    if explicit {
        RuleClass::Pua
    } else if offensive || !(pua || suspicious) {
        RuleClass::Malware
    } else if pua {
        RuleClass::Pua
    } else {
        RuleClass::Suspicious
    }
}

/// What a match of the rule `name` means (uses the metadata seen when it was loaded).
pub fn rule_class(name: &str) -> RuleClass {
    if let Some(c) = decided().read().ok().and_then(|m| m.get(name).copied()) {
        return c;
    }
    classify(explicit_pua(name), is_pua_name(name), has_name_part(name, &SUSPICIOUS_NAME_PARTS), names_offensive_tool(name))
}

/// The rule is potentially unwanted (PUA, not Malicious).
pub fn is_pua_rule(name: &str) -> bool {
    rule_class(name) == RuleClass::Pua
}

fn meta_strings<'a>(rule: &'a yara_x::Rule) -> impl Iterator<Item = (&'a str, String)> + 'a {
    rule.metadata().filter_map(|(key, value)| match value {
        MetaValue::String(v) => Some((key, v.to_ascii_lowercase())),
        _ => None,
    })
}

fn meta_says_pua(rule: &yara_x::Rule) -> bool {
    meta_strings(rule).any(|(key, v)| {
        PUA_META_PHRASES.iter().any(|p| v.contains(p))
            // A value or key that is just the word: `category = "PUA"`, `pup = "…"`.
            || v.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| t == "pua" || t == "pup")
            || key.eq_ignore_ascii_case("pua")
    })
}

/// Records the class of every rule in `rules` that has a PUA or suspicious mark.
fn note_rule_classes(rules: &Rules) {
    let mut found: Vec<(String, RuleClass)> = Vec::new();
    for rule in rules.iter() {
        let name = rule.identifier();
        let pua = is_pua_name(name) || meta_says_pua(&rule);
        let suspicious = has_name_part(name, &SUSPICIOUS_NAME_PARTS);
        if !(pua || suspicious) {
            continue;
        }
        let offensive = names_offensive_tool(name) || meta_strings(&rule).any(|(_, v)| names_offensive_tool(&v));
        found.push((name.to_string(), classify(explicit_pua(name), pua, suspicious, offensive)));
    }
    if !found.is_empty() {
        if let Ok(mut m) = decided().write() {
            m.extend(found);
        }
    }
}

pub struct YaraScanner {
    rules: Vec<Rules>,
    /// Rule names turned off by `*.ign2` / `*.ign` false-positive lists in the rules
    /// folder (ClamAV ignore-list format). Their matches are dropped.
    ignored: std::collections::HashSet<String>,
}

impl YaraScanner {
    pub fn new(rules_dir: &Path) -> Self {
        if !rules_dir.is_dir() {
            return Self { rules: Vec::new(), ignored: Default::default() };
        }

        let mut compiler = Compiler::new();
        let mut source_count = 0;
        let mut loaded_rules = Vec::new();

        if let Ok(entries) = std::fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    if ext.eq_ignore_ascii_case("yrc") {
                        // Compiled YARA-X rule file
                        if let Ok(bytes) = std::fs::read(&path) {
                            if let Ok(r) = Rules::deserialize(&bytes) {
                                loaded_rules.push(r);
                            }
                        }
                    } else if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                        if let Ok(src) = std::fs::read_to_string(&path) {
                            if compiler.add_source(src.as_str()).is_ok() {
                                source_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if source_count > 0 {
            let compiled = compiler.build();
            loaded_rules.push(compiled);
        }
        for r in &loaded_rules {
            note_rule_classes(r);
        }

        Self { rules: loaded_rules, ignored: crate::string_rules::read_ignore_lists(rules_dir) }
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        if self.rules.is_empty() || data.is_empty() {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for rules in &self.rules {
            let mut scanner = Scanner::new(rules);
            if let Ok(results) = scanner.scan(data) {
                for m in results.matching_rules() {
                    if !self.ignored.contains(m.identifier()) {
                        hits.push(m.identifier().to_string());
                    }
                }
            }
        }

        hits
    }

    /// Rule name and file byte range `[start, end)` of every pattern match (rules
    /// turned off by the `.ign2` lists are skipped), at most `limit`. For in-place
    /// disinfection; condition-only rules have no ranges.
    pub fn match_ranges(&self, data: &[u8], limit: usize) -> Vec<(String, usize, usize)> {
        let mut out = Vec::new();
        if data.is_empty() {
            return out;
        }
        for rules in &self.rules {
            let mut scanner = Scanner::new(rules);
            let Ok(results) = scanner.scan(data) else { continue };
            for rule in results.matching_rules() {
                if self.ignored.contains(rule.identifier()) {
                    continue;
                }
                for pattern in rule.patterns() {
                    for m in pattern.matches() {
                        if out.len() >= limit {
                            return out;
                        }
                        let r = m.range();
                        if r.start < r.end {
                            out.push((rule.identifier().to_string(), r.start, r.end));
                        }
                    }
                }
            }
        }
        out
    }

    /// Every matching rule (`.ign2`-ignored ones skipped) with the byte ranges of its
    /// pattern matches (at most `max_ranges` per rule; condition-only rules have none)
    /// and the matched pattern identifiers.
    pub fn explain(&self, data: &[u8], max_ranges: usize) -> Vec<(String, Vec<String>, Vec<(usize, usize)>)> {
        let mut out = Vec::new();
        if data.is_empty() {
            return out;
        }
        for rules in &self.rules {
            let mut scanner = Scanner::new(rules);
            let Ok(results) = scanner.scan(data) else { continue };
            for rule in results.matching_rules() {
                if self.ignored.contains(rule.identifier()) {
                    continue;
                }
                let mut ranges = Vec::new();
                let mut patterns = Vec::new();
                for pattern in rule.patterns() {
                    let mut any = false;
                    for m in pattern.matches() {
                        any = true;
                        let r = m.range();
                        if r.start < r.end && ranges.len() < max_ranges {
                            ranges.push((r.start, r.end));
                        }
                    }
                    if any {
                        patterns.push(pattern.identifier().to_string());
                    }
                }
                out.push((rule.identifier().to_string(), patterns, ranges));
            }
        }
        out
    }

    pub fn is_loaded(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Load one compiled `.yrc` bundle (web parity: same bytes as desktop).
    /// Returns false when bytes don't parse.
    pub fn load_yrc(&mut self, data: &[u8]) -> bool {
        match Rules::deserialize(data) {
            Ok(r) => {
                note_rule_classes(&r);
                self.rules.push(r);
                true
            }
            Err(_) => false,
        }
    }

    /// Compile one `.yar` source document and append it (web parity).
    /// Returns false on syntax error.
    pub fn add_source(&mut self, src: &str) -> bool {
        let mut compiler = Compiler::new();
        if compiler.add_source(src).is_err() {
            return false;
        }
        let r = compiler.build();
        note_rule_classes(&r);
        self.rules.push(r);
        true
    }

    /// How many rule names the `.ign2` lists turn off.
    pub fn ignored_count(&self) -> usize {
        self.ignored.len()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pua_by_name_part_anywhere() {
        assert!(is_pua_name("PUA_Win_Tool"));
        assert!(is_pua_name("SIGNATURE_BASE_PUA_VULN_Driver_Wj_Kprocesshacker_C725"));
        assert!(is_pua_name("ELASTIC_Windows_Hacktool_Processhacker_3D01069E"));
        assert!(is_pua_name("hacktool_win_processhacker"));
        assert!(!is_pua_name("Trojan_Win32_Remcos"));
        assert!(!is_pua_name("Puamba_Stealer"), "a part, not a substring");
    }

    #[test]
    fn offensive_tools_stay_malicious() {
        assert!(!is_pua_rule("ELASTIC_Windows_Hacktool_Mimikatz_1388212A"));
        assert!(!is_pua_rule("BINARYALERT_Hacktool_Windows_Cobaltstrike_Postexploitation"));
        assert!(is_pua_rule("ELASTIC_Windows_Hacktool_Processhacker_3D01069E"));
        assert!(is_pua_rule("PUA_Win_Mimikatz_Test"), "named PUA_ by its author");
        assert!(is_pua_rule("HKTL_ProcessHacker_Test"));
    }

    #[test]
    fn indicator_rules_are_suspicious() {
        assert_eq!(rule_class("INDICATOR_SUSPICIOUS_References_SecTools"), RuleClass::Suspicious);
        assert_eq!(rule_class("SUSP_Something_Odd"), RuleClass::Suspicious);
        assert_eq!(rule_class("SUSP_Mimikatz_Strings"), RuleClass::Malware, "offensive tool");
        assert_eq!(rule_class("Trojan_Win32_Remcos"), RuleClass::Malware);
    }

    #[test]
    fn pua_by_metadata_when_the_name_says_nothing() {
        let mut y = YaraScanner { rules: Vec::new(), ignored: Default::default() };
        assert!(y.add_source(
            r#"
            rule processhacker_kw_test {
              meta:
                tool          = "processhacker"
                rule_category = "greyware_tool_keyword"
              strings: $a = "kprocesshacker"
              condition: $a
            }
            rule greytool_c2_test {
              meta:
                description = "Detects the Cobalt Strike greyware loader"
              strings: $a = "beacon_c2_test"
              condition: $a
            }
            rule remcos_test {
              meta:
                description = "Detects Remcos RAT"
              strings: $a = "Remcos"
              condition: $a
            }"#
        ));
        assert!(is_pua_rule("processhacker_kw_test"));
        assert!(!is_pua_rule("remcos_test"));
        assert!(!is_pua_rule("greytool_c2_test"), "metadata names an offensive tool");
        assert_eq!(y.scan_bytes(b"..kprocesshacker.."), vec!["processhacker_kw_test".to_string()]);
    }
}
