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

/// A set of unpacker signatures, in the order they are tried.
#[derive(Debug, Clone, Default)]
pub struct UnpackRules {
    rules: Vec<UnpackRule>,
    set: RuleSet,
}

impl UnpackRules {
    /// The rules the engine ships with: none yet. With no rule every file takes
    /// the caller's generic path.
    pub fn builtin() -> &'static UnpackRules {
        static RULES: OnceLock<UnpackRules> = OnceLock::new();
        RULES.get_or_init(UnpackRules::default)
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
        *self = Self::build(new)?;
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
        Ok(Self { rules, set })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Id and recipe of the first rule (in file order) that recognises `data`.
    pub fn choose(&self, data: &[u8]) -> Option<(&str, &[Step])> {
        if self.rules.is_empty() {
            return None;
        }
        let options = ScanOptions { stop_on_detection: false, decode_obfuscated_strings: false, ..ScanOptions::default() };
        let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: "unpack_rules".into(), base_address: None };
        let report = hydradragonsig::scan_memory_owned(ctx, &self.set, &options).ok()?;
        self.rules
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
