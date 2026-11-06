// unpacker/plan.rs — unpacker signatures (format: UNPACK_FORMAT.md).
//
// One rule per packer: how to RECOGNISE it (hydradragonsig conditions, the same
// `pe_section`, `pe_anchor_pattern`, `unpacker_any`, ... a detection rule uses)
// and the recipe that UNPACKS it (`recipe.rs`). The header only picks the
// recipe; a step that does not happen fails it, and the caller falls back to
// its generic emulation.

pub use crate::unpacker::recipe::{Budget, Outcome};
use crate::unpacker::recipe::{self, Step};
use hydradragonsig::models::{BehaviorTrace, MemoryScanContext};
use hydradragonsig::rules::RuleSet;
use hydradragonsig::ScanOptions;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::OnceLock;

/// One recipe run.
#[derive(Debug, Clone)]
pub struct RecipeRun {
    pub rule: String,
    pub outcome: Outcome,
    /// API calls made by the emulated steps (empty when none emulated).
    pub trace: BehaviorTrace,
}

impl RecipeRun {
    /// The payload a scanner looks at first: the largest PE, else the largest one.
    pub fn main_payload(&self) -> Option<&[u8]> {
        let Outcome::Unpacked(p) = &self.outcome else { return None };
        p.iter()
            .filter(|d| d.starts_with(b"MZ"))
            .max_by_key(|d| d.len())
            .or_else(|| p.iter().max_by_key(|d| d.len()))
            .map(Vec::as_slice)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<u32>,
    #[serde(default)]
    rules: Vec<UnpackRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnpackRule {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    logic: Option<yaml_serde::Value>,
    #[serde(default)]
    threshold: Option<usize>,
    /// hydradragonsig conditions, passed through unchanged so its own loader
    /// checks them (unknown keys, bad patterns).
    conditions: Vec<yaml_serde::Value>,
    /// `- find: {...}` / `- dump`: enums as one-key maps, not YAML tags.
    #[serde(deserialize_with = "yaml_serde::with::singleton_map_recursive::deserialize")]
    unpack: Vec<Step>,
}

/// The recognition half as a hydradragonsig rule document.
#[derive(Serialize)]
struct SigFile<'a> {
    name: &'static str,
    rules: Vec<SigRule<'a>>,
}

#[derive(Serialize)]
struct SigRule<'a> {
    id: &'a str,
    title: &'a str,
    description: &'a str,
    severity: &'static str,
    verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    logic: Option<&'a yaml_serde::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<usize>,
    conditions: &'a [yaml_serde::Value],
}

/// A recipe carried by a hydradragonsig rule (its `unpack:` key): the rule itself
/// recognises the file, in the document it came from.
#[derive(Debug, Clone)]
struct SigUnpack {
    id: String,
    unpack: Vec<Step>,
}

/// A set of unpacker signatures, in the order they are tried.
#[derive(Debug, Clone, Default)]
pub struct UnpackRules {
    rules: Vec<UnpackRule>,
    set: RuleSet,
    /// Recipes from hydradragonsig rule files, tried after `rules`, in load order.
    sig: Vec<SigUnpack>,
    /// Those rule documents, whole (a recipe's rule may use `rule_match` on the
    /// others), with the recipe rules made public so their match is reported.
    sig_set: RuleSet,
}

static ACTIVE: std::sync::RwLock<Option<std::sync::Arc<UnpackRules>>> = std::sync::RwLock::new(None);

impl UnpackRules {
    /// The rules the engine ships with: none yet. With no rule every file takes
    /// the caller's generic path.
    pub fn builtin() -> &'static UnpackRules {
        static RULES: OnceLock<UnpackRules> = OnceLock::new();
        RULES.get_or_init(UnpackRules::default)
    }

    /// The rules the engine loaded ([`Self::install`]), else the built-in ones.
    pub fn active() -> std::sync::Arc<UnpackRules> {
        if let Some(r) = ACTIVE.read().ok().and_then(|g| g.clone()) {
            return r;
        }
        std::sync::Arc::new(Self::builtin().clone())
    }

    /// Makes `rules` the ones [`Self::active`] gives (replaces the previous load).
    pub fn install(rules: UnpackRules) {
        if let Ok(mut g) = ACTIVE.write() {
            *g = Some(std::sync::Arc::new(rules));
        }
    }

    /// The recipes in a hydradragonsig rule document: every rule with an `unpack:`
    /// key. The rule's own conditions (`rule_match` on the other rules of the
    /// document included) recognise the file; a private rule counts too. A document
    /// with no such rule gives an empty set.
    pub fn from_sig_yaml_str(yaml: &str) -> Result<Self, String> {
        let mut doc: yaml_serde::Value = yaml_serde::from_str(yaml).map_err(|e| format!("invalid YAML: {e}"))?;
        let mut sig = Vec::new();
        if let Some(rules) = doc.get_mut("rules").and_then(|r| r.as_sequence_mut()) {
            for r in rules.iter_mut() {
                let Some(map) = r.as_mapping_mut() else { continue };
                let Some(steps) = map.remove("unpack") else { continue };
                let id = map.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let unpack: Vec<Step> = yaml_serde::with::singleton_map_recursive::deserialize(steps)
                    .map_err(|e| format!("rule {id}: unpack: {e}"))?;
                if unpack.is_empty() {
                    return Err(format!("rule {id}: empty unpack"));
                }
                recipe::check(&unpack).map_err(|e| format!("rule {id}: {e}"))?;
                // A private rule gives no finding: here it must, to pick its recipe.
                map.insert("private".into(), false.into());
                sig.push(SigUnpack { id, unpack });
            }
        }
        if sig.is_empty() {
            return Ok(Self::default());
        }
        let yaml = yaml_serde::to_string(&doc).map_err(|e| format!("cannot serialize rules: {e}"))?;
        let sig_set = RuleSet::from_yaml_str(&yaml).map_err(|e| format!("{e:#}"))?;
        Ok(Self { sig, sig_set, ..Self::default() })
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self, String> {
        let file: RuleFile = yaml_serde::from_str(yaml).map_err(|e| format!("invalid YAML: {e}"))?;
        Self::build(file.rules)
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The built-in rules plus the ones in `path`: a rule with an existing id
    /// replaces it in place, new ids are tried before the built-in ones.
    pub fn builtin_with_file(path: &Path) -> Result<Self, String> {
        let mut out = Self::builtin().clone();
        out.extend(Self::from_file(path)?)?;
        Ok(out)
    }

    pub fn extend(&mut self, other: UnpackRules) -> Result<(), String> {
        let mut rules = self.rules.clone();
        let mut new = Vec::new();
        for r in other.rules {
            match rules.iter_mut().find(|x| x.id.eq_ignore_ascii_case(&r.id)) {
                Some(slot) => *slot = r,
                None => new.push(r),
            }
        }
        new.extend(rules);
        let (mut sig, mut sig_set) = (std::mem::take(&mut self.sig), std::mem::take(&mut self.sig_set));
        *self = Self::build(new)?;
        if !other.sig.is_empty() {
            sig.extend(other.sig);
            sig_set.extend(other.sig_set);
        }
        self.sig = sig;
        self.sig_set = sig_set;
        Ok(())
    }

    fn build(rules: Vec<UnpackRule>) -> Result<Self, String> {
        for (i, r) in rules.iter().enumerate() {
            if rules[..i].iter().any(|x| x.id.eq_ignore_ascii_case(&r.id)) {
                return Err(format!("duplicate rule id {}", r.id));
            }
            if r.conditions.is_empty() {
                return Err(format!("rule {}: no conditions", r.id));
            }
            recipe::check(&r.unpack).map_err(|e| format!("rule {}: {e}", r.id))?;
        }
        if rules.is_empty() {
            return Ok(Self::default());
        }
        let doc = SigFile {
            name: "unpack_rules",
            rules: rules
                .iter()
                .map(|r| SigRule {
                    id: &r.id,
                    title: &r.id,
                    description: &r.description,
                    severity: "info",
                    verdict: "clean",
                    logic: r.logic.as_ref(),
                    threshold: r.threshold,
                    conditions: &r.conditions,
                })
                .collect(),
        };
        let yaml = yaml_serde::to_string(&doc).map_err(|e| format!("cannot serialize rules: {e}"))?;
        let set = RuleSet::from_yaml_str_strict(&yaml).map_err(|e| format!("{e:#}"))?;
        Ok(Self { rules, set, ..Self::default() })
    }

    pub fn len(&self) -> usize {
        self.rules.len() + self.sig.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.sig.is_empty()
    }

    /// Id and recipe of the first rule (in file order) that recognises `data`:
    /// the unpacker signature files first, then the hydradragonsig rules' recipes.
    pub fn choose(&self, data: &[u8]) -> Option<(&str, &[Step])> {
        if self.is_empty() {
            return None;
        }
        let options = ScanOptions { stop_on_detection: false, decode_obfuscated_strings: false, ..ScanOptions::default() };
        if !self.rules.is_empty() {
            let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: "unpack_rules".into(), base_address: None };
            let report = hydradragonsig::scan_memory_owned(ctx, &self.set, &options).ok()?;
            if let Some(r) = self.rules.iter().find(|r| report.findings.iter().any(|f| f.rule_id == r.id)) {
                return Some((r.id.as_str(), r.unpack.as_slice()));
            }
        }
        if self.sig.is_empty() {
            return None;
        }
        let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: "unpack_rules".into(), base_address: None };
        let report = hydradragonsig::scan_memory_owned(ctx, &self.sig_set, &options).ok()?;
        self.sig
            .iter()
            .find(|r| report.findings.iter().any(|f| f.rule_id == r.id))
            .map(|r| (r.id.as_str(), r.unpack.as_slice()))
    }

    /// Unpacks `data` with the recipe of the first rule that recognises it.
    /// `None`: no rule does (the caller uses its generic way).
    pub fn unpack(&self, data: &[u8], budget: Budget) -> Option<RecipeRun> {
        let (rule, steps) = self.choose(data)?;
        let (outcome, trace) = recipe::run(data, steps, budget);
        Some(RecipeRun { rule: rule.to_string(), outcome, trace })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: Budget = Budget { max_instructions: 1000, timeout_us: 1_000_000 };

    fn rule(id: &str, steps: &str) -> String {
        format!("  - id: {id}\n    conditions: [{{type: not_mz}}]\n    unpack: {steps}\n")
    }

    #[test]
    fn no_builtin_rules_means_the_generic_path() {
        assert!(UnpackRules::builtin().is_empty());
        assert!(UnpackRules::builtin().unpack(b"anything", BUDGET).is_none());
    }

    #[test]
    fn the_format_document_example_loads() {
        let doc = include_str!("../../UNPACK_FORMAT.md");
        let yaml = doc.split("```yaml\n").nth(1).and_then(|s| s.split("```").next()).expect("yaml block in UNPACK_FORMAT.md");
        assert_eq!(UnpackRules::from_yaml_str(yaml).unwrap_or_else(|e| panic!("{e}")).len(), 2);
    }

    #[test]
    fn hydradragonsig_rules_carry_recipes() {
        // A private helper with the recipe, found through rule_match on another helper;
        // the detection rule without `unpack` is not a recipe.
        let doc = "name: t\nrules:\n  - id: H-A\n    title: a\n    severity: info\n    private: true\n    conditions: [{type: not_mz}]\n  - id: H-B\n    title: b\n    severity: info\n    private: true\n    conditions: [{type: rule_match, ids: [H-A]}]\n    unpack: [{take: {at: 0, len: 4, as: x}}, {emit: x}]\n  - id: DET\n    title: d\n    severity: high\n    verdict: malware\n    conditions: [{type: rule_match, ids: [H-B]}]\n";
        assert!(RuleSet::from_yaml_str_strict(doc).is_ok(), "the scanner accepts the unpack key");
        let mut rules = UnpackRules::from_sig_yaml_str(doc).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rules.len(), 1);
        let run = rules.unpack(b"abcdef", BUDGET).expect("H-B recognises it");
        assert_eq!(run.rule, "H-B");
        assert_eq!(run.main_payload(), Some(&b"abcd"[..]));
        // Merged after an unpacker signature file: still found.
        rules = { let mut r = UnpackRules::default(); r.extend(rules).unwrap(); r };
        assert_eq!(rules.unpack(b"abcdef", BUDGET).map(|r| r.rule), Some("H-B".into()));
        assert!(UnpackRules::from_sig_yaml_str("rules:\n  - id: X\n    title: x\n    severity: info\n    conditions: [{type: not_mz}]\n").unwrap().is_empty());
        assert!(UnpackRules::from_sig_yaml_str("rules:\n  - id: X\n    title: x\n    severity: info\n    conditions: [{type: not_mz}]\n    unpack: [{take: {as: x}}]\n").is_err());
    }

    #[test]
    fn bad_rules_are_rejected_at_load() {
        let bad_condition = "rules:\n  - id: bad\n    conditions:\n      - type: pe_section\n        nmae: UPX0\n    unpack: [{emit: file}]\n";
        assert!(UnpackRules::from_yaml_str(bad_condition).is_err());
        for steps in [
            "[]",
            "[{take: {as: x}}]",
            "[{run_until: {}}, dump]",
            "[{try: [[dump]]}]",
            "[{repeat: {while: 1, steps: [{run_until: {write_execute: true}}]}}, {emit: file}]",
            "[{xor: {in: file, as: x}}, {emit: x}]",
            "[{find: {pattern: \"?? 4D\", as: p}}, {emit: file}]",
            "[{set: {x: \"1 +\"}}, {emit: file}]",
            "[{nonsense: 1}, {emit: file}]",
        ] {
            let yaml = format!("rules:\n{}", rule("r", steps));
            assert!(UnpackRules::from_yaml_str(&yaml).is_err(), "{steps} must be rejected");
        }
    }

    #[test]
    fn first_matching_rule_wins_and_file_rules_go_first() {
        let base = UnpackRules::from_yaml_str(&format!("rules:\n{}{}", rule("a", "[{emit: file}]"), rule("b", "[{emit: file}]"))).unwrap();
        let data = b"just some text that is not a PE file at all".repeat(4);
        assert_eq!(base.choose(&data).unwrap().0, "a");

        let mut merged = base.clone();
        let file_rules = format!("rules:\n{}{}", rule("a", "[{take: {at: 0, len: 4, as: x}}, {emit: x}]"), rule("c", "[{take: {at: 5, len: 4, as: x}}, {emit: x}]"));
        merged.extend(UnpackRules::from_yaml_str(&file_rules).unwrap()).unwrap();
        assert_eq!(merged.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["c", "a", "b"]);
        let run = merged.unpack(&data, BUDGET).unwrap();
        assert_eq!((run.rule.as_str(), run.main_payload()), ("c", Some(&b"some"[..])));
    }
}
