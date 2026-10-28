// unpacker/plan.rs — unpacker signatures (format: UNPACK_FORMAT.md).
//
// One rule per packer: how to RECOGNISE it (hydradragonsig conditions, the same
// `pe_section`, `pe_anchor_pattern`, `unpacker_any`, ... a detection rule uses)
// and the steps that UNPACK it. The header only picks the recipe; every step is
// checked against what the emulated code really does. A `run_until` whose
// condition never happens (a fake .NET header over native code, a packer variant
// the recipe does not know) fails the recipe, and the caller falls back to its
// generic emulation.

use crate::unpacker::engine::{entrypoint, Sample, StopHit, Stops, UnpackerEngine};
use hydradragonsig::models::{BehaviorTrace, MemoryScanContext};
use hydradragonsig::rules::RuleSet;
use hydradragonsig::ScanOptions;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::OnceLock;

/// Rules shipped with the engine (compiled in).
const BUILTIN_YAML: &str = include_str!("../../unpack_rules/default.yaml");

/// One step of a recipe.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// Emulate from the current instruction until one of the conditions happens.
    /// The run stops BEFORE that instruction. Reaching the budget, an exit or a
    /// fault first fails the recipe.
    RunUntil(RunUntil),
    /// Set the instruction pointer: the entry point the dump gets.
    SetOep(Oep),
    /// Dump the memory image (entry point = instruction pointer, imports
    /// rebuilt from the API stubs). Ends the recipe.
    Dump,
    /// The code is managed (.NET IL) or a script: static analysis of the file
    /// (hydradragondecompiler). Ends the recipe.
    Decompile,
    /// The content is in a container hydradragonextractor opens. Ends the recipe.
    Extract,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunUntil {
    /// Executing a page this run has written (the packed code, decompressed).
    #[serde(default)]
    pub write_execute: bool,
    /// Calling one of these APIs (stop at its stub, before the call).
    #[serde(default)]
    pub api: Vec<String>,
    /// Entering one of these sections.
    #[serde(default)]
    pub section: Vec<String>,
    /// A basic block starting with one of these hex patterns (`??` = any byte).
    #[serde(default)]
    pub ip_pattern: Vec<String>,
    /// No condition stops inside these sections (the stub's own, which often
    /// writes and runs its own code before it reaches the payload).
    #[serde(default)]
    pub outside: Vec<String>,
    /// Instruction budget of this step (default: the caller's).
    #[serde(default)]
    pub max_instructions: Option<u64>,
    /// Time limit of this step in milliseconds (default: the caller's).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Oep {
    /// Where the last `run_until` stopped.
    Ip,
    /// An address relative to the image base.
    Rva(u64),
}

/// How a recipe ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The unpacked image.
    Dumped(Vec<u8>),
    /// Managed / script code: decompile the file.
    Decompile,
    /// A container: extract it.
    Extract,
    /// A step did not happen as the recipe says: fall back to the generic way.
    Failed { step: usize, reason: String },
}

/// One recipe run.
#[derive(Debug, Clone)]
pub struct RecipeRun {
    pub rule: String,
    pub outcome: Outcome,
    /// API calls made by the emulated steps (empty when none emulated).
    pub trace: BehaviorTrace,
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
    /// `- run_until: {...}` / `- dump`: enums as one-key maps, not YAML tags.
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

/// Budget a `run_until` gets when its rule does not give one.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_instructions: usize,
    pub timeout_us: u64,
}

/// A set of unpacker signatures, in the order they are tried.
#[derive(Debug, Clone, Default)]
pub struct UnpackRules {
    rules: Vec<UnpackRule>,
    set: RuleSet,
}

impl UnpackRules {
    pub fn builtin() -> &'static UnpackRules {
        static RULES: OnceLock<UnpackRules> = OnceLock::new();
        RULES.get_or_init(|| {
            UnpackRules::from_yaml_str(BUILTIN_YAML)
                .unwrap_or_else(|e| panic!("built-in unpack_rules/default.yaml is invalid: {e}"))
        })
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
            check_steps(&r.unpack).map_err(|e| format!("rule {}: {e}", r.id))?;
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

    /// Id and steps of the first rule (in file order) that recognises `data`.
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
        let (outcome, trace) = run_steps(data, steps, budget);
        Some(RecipeRun { rule: rule.to_string(), outcome, trace })
    }
}

/// Exactly one ending step (`dump`, `decompile`, `extract`), as the last one;
/// every `run_until` has a condition and valid patterns.
fn check_steps(steps: &[Step]) -> Result<(), String> {
    let ends = |s: &Step| matches!(s, Step::Dump | Step::Decompile | Step::Extract);
    match steps.iter().position(ends) {
        Some(i) if i + 1 == steps.len() => {}
        Some(_) => return Err("dump / decompile / extract must be the last step".into()),
        None => return Err("unpack must end with dump, decompile or extract".into()),
    }
    for (i, s) in steps.iter().enumerate() {
        if let Step::RunUntil(r) = s {
            if !r.write_execute && r.api.is_empty() && r.section.is_empty() && r.ip_pattern.is_empty() {
                return Err(format!("step {}: run_until without a condition", i + 1));
            }
            for p in &r.ip_pattern {
                let p = crate::disinfect::rules::parse_hex_pattern(p).map_err(|e| format!("step {}: {e}", i + 1))?;
                if p.is_empty() {
                    return Err(format!("step {}: empty ip_pattern", i + 1));
                }
            }
        }
    }
    Ok(())
}

fn run_steps(data: &[u8], steps: &[Step], budget: Budget) -> (Outcome, BehaviorTrace) {
    let mut eng: Option<UnpackerEngine> = None;
    let fail = |step: usize, reason: String| Outcome::Failed { step: step + 1, reason };
    for (i, step) in steps.iter().enumerate() {
        let trace = |eng: &Option<UnpackerEngine>| eng.as_ref().map(|e| e.behavior_trace().clone()).unwrap_or_default();
        if !matches!(step, Step::Decompile | Step::Extract) && eng.is_none() {
            match start(data) {
                Ok(e) => eng = Some(e),
                Err(e) => return (fail(i, e), BehaviorTrace::default()),
            }
        }
        match step {
            Step::RunUntil(r) => {
                let e = eng.as_mut().expect("started above");
                let patterns = r.ip_pattern.iter().filter_map(|p| crate::disinfect::rules::parse_hex_pattern(p).ok()).collect();
                e.set_stops(Stops {
                    write_execute: r.write_execute,
                    apis: r.api.clone(),
                    sections: r.section.clone(),
                    patterns,
                    outside: r.outside.clone(),
                });
                let from = e.ip().unwrap_or(0);
                let max = r.max_instructions.map_or(budget.max_instructions, |n| n as usize);
                let timeout = r.timeout_ms.map_or(budget.timeout_us, |ms| ms.saturating_mul(1000));
                let err = e.emu_from(from, timeout, max).err();
                e.set_stops(Stops::default());
                match e.stop_hit.clone() {
                    Some(hit) => {
                        e.set_ip(hit.address());
                    }
                    None => {
                        let why = match (&err, &e.stop_api) {
                            (_, Some(api)) => format!("stopped at {api}"),
                            (Some(err), _) => err.to_string(),
                            _ => format!("{:?} before the condition", e.end),
                        };
                        let t = trace(&eng);
                        return (fail(i, why), t);
                    }
                }
            }
            Step::SetOep(oep) => {
                let e = eng.as_mut().expect("started above");
                let ip = match oep {
                    Oep::Ip => e.ip().unwrap_or(0),
                    Oep::Rva(rva) => e.sample.base_addr.wrapping_add(*rva),
                };
                let (base, size) = (e.sample.base_addr, e.sample.virtualmemorysize);
                if ip < base || ip >= base + size {
                    let t = trace(&eng);
                    return (fail(i, format!("entry point {ip:#x} is outside the image")), t);
                }
                e.set_ip(ip);
            }
            Step::Dump => {
                let e = eng.as_ref().expect("started above");
                let t = trace(&eng);
                return match e.dump_bytes() {
                    Ok(image) if !image.is_empty() => (Outcome::Dumped(image), t),
                    Ok(_) => (fail(i, "empty dump".into()), t),
                    Err(err) => (fail(i, err.to_string()), t),
                };
            }
            Step::Decompile => return (Outcome::Decompile, trace(&eng)),
            Step::Extract => return (Outcome::Extract, trace(&eng)),
        }
    }
    unreachable!("check_steps: a recipe ends with dump, decompile or extract")
}

fn start(data: &[u8]) -> Result<UnpackerEngine, String> {
    let sample = Sample::from_bytes(data).map_err(|e| e.to_string())?;
    let ep = entrypoint(&sample.opt_header);
    let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
    eng.init_uc().map_err(|e| e.to_string())?;
    eng.set_controls(false, false);
    eng.set_end_addr(u64::MAX);
    eng.set_ip(ep);
    Ok(eng)
}

/// What the stop of a `run_until` was, for logs.
pub fn describe(hit: &StopHit) -> String {
    match hit {
        StopHit::WriteExecute(a) => format!("write-execute at {a:#x}"),
        StopHit::Api(n, _) => format!("call to {n}"),
        StopHit::Section(n, a) => format!("entered {n} at {a:#x}"),
        StopHit::Pattern(a) => format!("pattern at {a:#x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_load() {
        assert!(!UnpackRules::builtin().is_empty());
    }

    #[test]
    fn unknown_condition_key_is_an_error() {
        let yaml = r#"
rules:
  - id: bad
    conditions:
      - type: pe_section
        nmae: UPX0
    unpack: [dump]
"#;
        assert!(UnpackRules::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn recipe_must_end_with_one_ending_step() {
        for steps in ["[]", "[dump, dump]", "[decompile, {run_until: {write_execute: true}}]", "[{run_until: {}}, dump]"] {
            let yaml = format!("rules:\n  - id: r\n    conditions: [{{type: not_mz}}]\n    unpack: {steps}\n");
            assert!(UnpackRules::from_yaml_str(&yaml).is_err(), "{steps} must be rejected");
        }
        let ok = "rules:\n  - id: r\n    conditions: [{type: not_mz}]\n    unpack: [{run_until: {api: [_CorExeMain]}}, {set_oep: ip}, decompile]\n";
        assert!(UnpackRules::from_yaml_str(ok).is_ok());
    }

    #[test]
    fn first_matching_rule_wins_and_file_rules_go_first() {
        let base = UnpackRules::from_yaml_str(
            "rules:\n  - id: a\n    conditions: [{type: not_mz}]\n    unpack: [extract]\n  - id: b\n    conditions: [{type: not_mz}]\n    unpack: [decompile]\n",
        )
        .unwrap();
        let data = b"just some text that is not a PE file at all".repeat(4);
        assert_eq!(base.choose(&data).unwrap().0, "a");

        let mut merged = base.clone();
        merged
            .extend(UnpackRules::from_yaml_str(
                "rules:\n  - id: a\n    conditions: [{type: not_mz}]\n    unpack: [decompile]\n  - id: c\n    conditions: [{type: not_mz}]\n    unpack: [extract]\n",
            ).unwrap())
            .unwrap();
        assert_eq!(merged.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["c", "a", "b"]);
        assert_eq!(merged.rules[1].unpack, [Step::Decompile]);
        let budget = Budget { max_instructions: 1000, timeout_us: 1_000_000 };
        assert_eq!(merged.unpack(&data, budget).unwrap().outcome, Outcome::Extract);
    }

    #[test]
    fn emulating_a_non_pe_fails_the_recipe() {
        let rules = UnpackRules::from_yaml_str(
            "rules:\n  - id: r\n    conditions: [{type: not_mz}]\n    unpack: [{run_until: {write_execute: true}}, dump]\n",
        )
        .unwrap();
        let data = b"not a PE file, nothing to emulate here".repeat(4);
        let run = rules.unpack(&data, Budget { max_instructions: 1000, timeout_us: 1_000_000 }).unwrap();
        assert!(matches!(run.outcome, Outcome::Failed { step: 1, .. }), "{:?}", run.outcome);
    }
}
