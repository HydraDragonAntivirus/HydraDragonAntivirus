from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULE_TYPES = ROOT.parent / "Owlyshield" / "owlyshield_predict" / "src" / "behavioral" / "rule_types.rs"
DEFAULT_RULES = [
    ROOT / "hydradragon" / "Owlyshield" / "rules" / "sanctum_syscall_rules.yaml",
    ROOT / "hydradragon" / "Owlyshield" / "rules" / "amsi_detection_rules.yaml",
    ROOT / "hydradragon" / "Owlyshield" / "rules" / "zero_trust_behavior_rules.yaml",
]

CONDITION_FIELDS = {
    "File": {"op", "path_pattern"},
    "Registry": {"op", "key_pattern", "value_name", "expected_data"},
    "Process": {"op", "pattern"},
    "Service": {"op", "name_pattern"},
    "Network": {"op", "dest_pattern"},
    "NetworkCondition": set(),
    "Api": {"functions", "arguments", "module_pattern", "name_pattern"},
    "Heuristic": {"metric", "threshold"},
    "OperationCount": {"op_type", "operation", "path_pattern", "comparison", "threshold"},
    "ExtensionPattern": {"patterns", "match_mode", "op_type"},
    "ByteThreshold": {"direction", "comparison", "threshold"},
    "EntropyThreshold": {"metric", "comparison", "threshold"},
    "FileCount": {"category", "comparison", "threshold"},
    "Signature": {
        "is_trusted",
        "is_signed",
        "signer_pattern",
        "signer_patterns",
        "signature_status",
        "signature_statuses",
        "verification_failed",
        "no_signature",
        "signature_status_issues",
        "invalid_signature",
        "raw_hresult",
        "raw_hresults",
        "status_text_pattern",
    },
    "DirectorySpread": {"category", "comparison", "threshold"},
    "DriveActivity": {"drive_type", "op_type", "comparison", "threshold"},
    "ProcessAncestry": {"ancestor_pattern", "max_depth"},
    "ExtensionRatio": {"extensions", "comparison", "threshold"},
    "RateOfChange": {"metric", "comparison", "threshold"},
    "SelfModification": {"modification_type"},
    "CommandLineMatch": {"patterns", "match_mode"},
    "ProcessTree": {
        "parent_patterns",
        "child_patterns",
        "ancestor_patterns",
        "command_line_patterns",
        "max_depth",
        "require_current_process",
    },
    "MultiCondition": {
        "conditions",
        "operator",
        "op",
        "min_matches",
        "within_ms",
        "require_same_source_pid",
    },
    "SensitivePathAccess": {"patterns", "op_type", "min_unique_paths"},
    "ClusterPattern": {"min_clusters", "max_clusters"},
    "TempDirectoryWrite": {"min_bytes", "min_files"},
    "ArchiveCreation": {"extensions", "min_size", "in_temp"},
    "DataExfiltrationPattern": {"source_patterns", "min_source_reads", "detect_temp_staging", "detect_archive"},
    "MemoryScan": {"patterns", "detect_pe_headers", "private_only"},
    "Amsi": {"risk_at_least", "patterns", "cmdline_patterns", "source"},
    "SanctumGhost": {"functions", "caller_address_patterns", "hex_patterns", "min_matches"},
}

REQUIRED_FIELDS = {
    "File": {"op", "path_pattern"},
    "Registry": {"op", "key_pattern"},
    "Process": {"op", "pattern"},
    "Service": {"op", "name_pattern"},
    "Api": set(),
    "OperationCount": {"threshold"},
    "ByteThreshold": {"direction", "threshold"},
    "EntropyThreshold": {"metric", "threshold"},
    "CommandLineMatch": {"patterns"},
    "MultiCondition": {"conditions"},
}


def rule_condition_variants() -> set[str]:
    text = RULE_TYPES.read_text(encoding="utf-8")
    match = re.search(r"pub enum RuleCondition \{(?P<body>.*?)\n\}", text, re.S)
    if not match:
        raise RuntimeError(f"Could not locate RuleCondition enum in {RULE_TYPES}")
    body = match.group("body")
    variants = set(re.findall(r"^\s*([A-Z][A-Za-z0-9_]*)\s*(?:\{|,|\()", body, re.M))
    return variants


def load_rules(path: Path) -> list[dict[str, Any]]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return []
    if isinstance(loaded, dict):
        return [loaded]
    if isinstance(loaded, list):
        if not all(isinstance(item, dict) for item in loaded):
            raise ValueError(f"{path} must contain a rule object or a list of rule objects")
        return loaded
    raise ValueError(f"{path} has unsupported YAML root: {type(loaded).__name__}")


def iter_conditions(rule: dict[str, Any]):
    for stage in rule.get("stages", []) or []:
        for condition in stage.get("conditions", []) or []:
            yield condition, f"{rule.get('rule_id', rule.get('name', '<unnamed>'))}/{stage.get('name', '<stage>')}"


def validate_condition(condition: Any, context: str, variants: set[str], errors: list[str]) -> None:
    if not isinstance(condition, dict):
        errors.append(f"{context}: condition must be a mapping, got {type(condition).__name__}")
        return
    cond_type = condition.get("type")
    if not isinstance(cond_type, str):
        errors.append(f"{context}: condition is missing string field 'type'")
        return
    if cond_type not in variants:
        errors.append(f"{context}: condition type {cond_type!r} is not in RuleCondition enum")
        return
    allowed = CONDITION_FIELDS.get(cond_type)
    if allowed is not None and cond_type != "NetworkCondition":
        extra = set(condition) - allowed - {"type"}
        if extra:
            errors.append(f"{context}: {cond_type} has unknown fields {sorted(extra)}")
    missing = REQUIRED_FIELDS.get(cond_type, set()) - set(condition)
    if missing:
        errors.append(f"{context}: {cond_type} is missing required fields {sorted(missing)}")
    if cond_type == "MultiCondition":
        nested = condition.get("conditions", [])
        if not isinstance(nested, list) or not nested:
            errors.append(f"{context}: MultiCondition.conditions must be a non-empty list")
        for idx, subcondition in enumerate(nested):
            validate_condition(subcondition, f"{context}/MultiCondition[{idx}]", variants, errors)
    if cond_type == "SanctumGhost":
        for pattern in condition.get("hex_patterns", []) or []:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"{context}: invalid SanctumGhost regex {pattern!r}: {exc}")
    if cond_type == "Amsi":
        for pattern in condition.get("patterns", []) or []:
            if pattern.startswith("(?") or pattern.startswith("^") or pattern.endswith("$"):
                try:
                    re.compile(pattern)
                except re.error as exc:
                    errors.append(f"{context}: invalid AMSI regex {pattern!r}: {exc}")
    if cond_type in {"CommandLineMatch", "ProcessTree"}:
        key = "patterns" if cond_type == "CommandLineMatch" else "command_line_patterns"
        for entry in condition.get(key, []) or []:
            if isinstance(entry, dict) and entry.get("is_regex") and isinstance(entry.get("pattern"), str):
                try:
                    re.compile(entry["pattern"])
                except re.error as exc:
                    errors.append(f"{context}: invalid command-line regex {entry['pattern']!r}: {exc}")

    if cond_type == "OperationCount":
        if "op_type" not in condition and "operation" not in condition:
            errors.append(f"{context}: OperationCount must have 'op_type' or 'operation'")
    if cond_type == "ByteThreshold":
        if "direction" not in condition:
            errors.append(f"{context}: ByteThreshold must have 'direction'")
    if cond_type == "EntropyThreshold":
        if "metric" not in condition:
            errors.append(f"{context}: EntropyThreshold must have 'metric'")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate HydraDragon generated behavioral rules.")
    parser.add_argument("paths", nargs="*", type=Path, default=DEFAULT_RULES)
    args = parser.parse_args()

    variants = rule_condition_variants()
    missing_local_schema = set(CONDITION_FIELDS) - variants
    if missing_local_schema:
        print(f"RuleCondition enum missing expected variants: {sorted(missing_local_schema)}", file=sys.stderr)
        return 2

    errors: list[str] = []
    ids: dict[str, Path] = {}
    total_rules = 0
    condition_total = 0

    for path in args.paths:
        path = path if path.is_absolute() else ROOT / path
        rules = load_rules(path)
        total_rules += len(rules)
        for index, rule in enumerate(rules, 1):
            rid = rule.get("rule_id")
            if not isinstance(rid, str) or not rid.strip():
                errors.append(f"{path}:{index}: missing rule_id")
            elif rid in ids:
                errors.append(f"{path}:{index}: duplicate rule_id {rid!r} already used in {ids[rid]}")
            else:
                ids[rid] = path
            score = rule.get("severity_score") or rule.get("severity")
            if score is None:
                errors.append(f"{path}:{index}: missing severity/severity_score")
            elif not isinstance(score, int) or not (0 <= score <= 100):
                errors.append(f"{path}:{index}: severity must be an integer from 0 to 100")
            for condition, context in iter_conditions(rule):
                condition_total += 1
                validate_condition(condition, context, variants, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAILED: {len(errors)} issue(s), {total_rules} rule(s), {condition_total} top-level condition(s)", file=sys.stderr)
        return 1

    print(f"OK: {total_rules} rule(s), {len(ids)} unique rule_id value(s), {condition_total} top-level condition(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
