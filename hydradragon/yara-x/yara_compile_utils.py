import hashlib
import os
import re
import tempfile
import unicodedata
from pathlib import Path

import yara


RULE_DECL_RE = re.compile(r"^(\s*(?:private\s+)?rule\s+)(\S+)(.*)$")


def sanitize_rule_identifier(raw_name: str) -> str:
    normalized = unicodedata.normalize("NFKD", raw_name)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", ascii_only)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")

    if not cleaned:
        cleaned = "sig"

    if not re.match(r"^[A-Za-z_]", cleaned):
        cleaned = f"sig_{cleaned}"

    return cleaned


def uniquify_identifier(base_name: str, original_name: str, seen_identifiers: set[str]) -> str:
    if base_name not in seen_identifiers:
        seen_identifiers.add(base_name)
        return base_name

    digest = hashlib.sha1(original_name.encode("utf-8", "replace")).hexdigest()[:10]
    candidate = f"{base_name}_{digest}"
    suffix = 2
    while candidate in seen_identifiers:
        candidate = f"{base_name}_{digest}_{suffix}"
        suffix += 1

    seen_identifiers.add(candidate)
    return candidate


def create_sanitized_yara_copy(input_path: Path) -> tuple[Path, int]:
    seen_identifiers: set[str] = set()
    rewritten_rules = 0

    fd, temp_name = tempfile.mkstemp(
        prefix=f"{input_path.stem}_sanitized_",
        suffix=input_path.suffix,
        dir=input_path.parent,
        text=True,
    )
    os.close(fd)
    sanitized_path = Path(temp_name)

    with (
        input_path.open("r", encoding="utf-8", errors="replace") as source,
        sanitized_path.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as destination,
    ):
        for line in source:
            match = RULE_DECL_RE.match(line)
            if not match:
                destination.write(line)
                continue

            prefix, rule_name, suffix = match.groups()
            sanitized_name = sanitize_rule_identifier(rule_name)
            unique_name = uniquify_identifier(sanitized_name, rule_name, seen_identifiers)
            if unique_name != rule_name:
                rewritten_rules += 1
            destination.write(f"{prefix}{unique_name}{suffix}")

    return sanitized_path, rewritten_rules


def split_yara_header_and_rules(input_path: Path) -> tuple[str, list[tuple[str, str]]]:
    header_lines: list[str] = []
    rule_blocks: list[tuple[str, str]] = []
    current_rule_name: str | None = None
    current_rule_lines: list[str] = []

    with input_path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            match = RULE_DECL_RE.match(line)
            if match:
                if current_rule_name is not None:
                    rule_blocks.append((current_rule_name, "".join(current_rule_lines)))
                elif header_lines:
                    pass

                current_rule_name = match.group(2)
                current_rule_lines = [line]
                continue

            if current_rule_name is None:
                header_lines.append(line)
            else:
                current_rule_lines.append(line)

    if current_rule_name is not None:
        rule_blocks.append((current_rule_name, "".join(current_rule_lines)))

    return "".join(header_lines), rule_blocks


def create_filtered_yara_copy(input_path: Path, report_base_path: Path | None = None) -> tuple[Path, int, Path | None]:
    header_text, rule_blocks = split_yara_header_and_rules(input_path)
    kept_blocks: list[str] = []
    skipped_rules: list[tuple[str, str]] = []

    for rule_name, rule_text in rule_blocks:
        try:
            yara.compile(source=header_text + rule_text)
            kept_blocks.append(rule_text)
        except yara.Error as exc:
            skipped_rules.append((rule_name, str(exc)))

    if not skipped_rules:
        return input_path, 0, None

    fd, temp_name = tempfile.mkstemp(
        prefix=f"{input_path.stem}_filtered_",
        suffix=input_path.suffix,
        dir=input_path.parent,
        text=True,
    )
    os.close(fd)
    filtered_path = Path(temp_name)

    with filtered_path.open("w", encoding="utf-8", newline="") as destination:
        destination.write(header_text)
        for rule_text in kept_blocks:
            destination.write(rule_text)

    report_anchor = report_base_path or input_path
    skipped_report = report_anchor.with_name(f"{report_anchor.stem}_skipped_rules.txt")
    with skipped_report.open("w", encoding="utf-8", newline="\n") as report:
        for rule_name, error_text in skipped_rules:
            report.write(f"{rule_name}\t{error_text}\n")

    return filtered_path, len(skipped_rules), skipped_report


def compile_yara_rule_safely(input_file: str, output_file: str) -> tuple[int, int, Path | None]:
    input_path = Path(input_file)
    sanitized_path, rewritten_rules = create_sanitized_yara_copy(input_path)
    compile_input = sanitized_path
    skipped_rules = 0
    skipped_report: Path | None = None

    try:
        try:
            rules = yara.compile(filepath=str(compile_input))
        except yara.SyntaxError:
            filtered_path, skipped_rules, skipped_report = create_filtered_yara_copy(
                sanitized_path,
                report_base_path=input_path,
            )
            compile_input = filtered_path
            rules = yara.compile(filepath=str(compile_input))
        with open(output_file, "wb") as handle:
            rules.save(file=handle)
    finally:
        try:
            sanitized_path.unlink()
        except OSError:
            pass
        if compile_input != sanitized_path:
            try:
                compile_input.unlink()
            except OSError:
                pass

    return rewritten_rules, skipped_rules, skipped_report
