import hashlib
import os
import re
import unicodedata
import datetime
import logging
from pathlib import Path
from typing import List, Tuple, Set, Dict, Optional, Any

import yara
import yara_x

logger = logging.getLogger(__name__)

# Regex for YARA rule declarations
RULE_DECL_RE = re.compile(r"^(\s*(?:private\s+|global\s+)?rule\s+)(\S+)(.*)$")
# Regex for detecting 10k string limit (opcode10000)
OPCODE_LIMIT_RE = re.compile(r"\$opcode10000\s*=\s*string", re.IGNORECASE)


def sanitize_rule_identifier(raw_name: str) -> str:
    """Sanitizes a YARA rule identifier to be valid for both YARA and YARA-X."""
    normalized = unicodedata.normalize("NFKD", raw_name)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", ascii_only)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")

    if not cleaned:
        cleaned = "sig"

    if not re.match(r"^[A-Za-z_]", cleaned):
        cleaned = f"sig_{cleaned}"

    return cleaned


def uniquify_identifier(base_name: str, original_name: str, seen_identifiers: Set[str]) -> str:
    """Ensures a rule identifier is unique within the current context."""
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


def split_yara_rules(input_path: Path) -> Tuple[str, List[Tuple[str, str]]]:
    """Splits a YARA file into a header (imports/includes) and individual rule blocks."""
    header_lines: List[str] = []
    rule_blocks: List[Tuple[str, str]] = []
    current_rule_name: Optional[str] = None
    current_rule_lines: List[str] = []

    try:
        with input_path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                match = RULE_DECL_RE.match(line)
                if match:
                    if current_rule_name is not None:
                        rule_blocks.append((current_rule_name, "".join(current_rule_lines)))

                    current_rule_name = match.group(2)
                    # Strip trailing { if present in match
                    current_rule_name = current_rule_name.strip().rstrip("{").strip()
                    current_rule_lines = [line]
                    continue

                if current_rule_name is None:
                    header_lines.append(line)
                else:
                    current_rule_lines.append(line)

        if current_rule_name is not None:
            rule_blocks.append((current_rule_name, "".join(current_rule_lines)))
    except Exception as e:
        logger.error(f"Error reading {input_path}: {e}")

    return "".join(header_lines), rule_blocks


def validate_rule_block(header: str, rule_text: str, engine: str = "both") -> Tuple[bool, str]:
    """Validates a single rule block using YARA, YARA-X, or both."""
    full_source = header + "\n" + rule_text
    errors = []

    if engine in ("yara", "both"):
        try:
            yara.compile(source=full_source)
        except yara.Error as e:
            errors.append(f"YARA Error: {e}")

    if engine in ("yarax", "both"):
        try:
            # Use yara_x.compile as it's the simpler API
            yara_x.compile(full_source)
        except yara_x.CompileError as e:
            errors.append(f"YARA-X Error: {e}")
        except Exception as e:
            errors.append(f"YARA-X Generic Error: {e}")

    if errors:
        return False, "; ".join(errors)
    return True, ""


def clean_yara_file(input_file: str, broken_rules_file: Optional[str] = None, engine: str = "both", fix_limits: bool = False) -> Dict[str, Any]:
    """
    Cleans a YARA file by:
    1. Sanitizing rule identifiers.
    2. Removing rules with 10k string limit ($opcode10000).
    3. Removing duplicate rules (by name).
    4. Identifying broken rules and moving them to a quarantine file.
    5. Rewriting the original file with only valid, unique rules.
    """
    input_path = Path(input_file)
    if not input_path.exists():
        return {"error": "File not found"}

    if broken_rules_file is None:
        broken_rules_file = str(input_path.with_name(f"{input_path.stem}_broken.yar"))

    broken_path = Path(broken_rules_file)
    header, rule_blocks = split_yara_rules(input_path)

    valid_blocks: List[str] = []
    quarantined_blocks: List[Tuple[str, str, str]] = []  # name, text, reason
    seen_identifiers: Set[str] = set()

    stats = {"original_rules": len(rule_blocks), "valid_rules": 0, "broken_rules": 0, "limit_broken_rules": 0, "duplicate_rules": 0, "renamed_rules": 0}

    for rule_name, rule_text in rule_blocks:
        # 1. Detect limit-broken rules ($opcode10000)
        if fix_limits and OPCODE_LIMIT_RE.search(rule_text):
            quarantined_blocks.append((rule_name, rule_text, "10k String Limit Reached"))
            stats["limit_broken_rules"] += 1
            continue

        # 2. Sanitize name
        sanitized_name = sanitize_rule_identifier(rule_name)
        unique_name = uniquify_identifier(sanitized_name, rule_name, seen_identifiers)

        if unique_name != rule_name:
            # Rewrite rule text with new name
            rule_text = re.sub(r"\b" + re.escape(rule_name) + r"\b", unique_name, rule_text, count=1)
            if unique_name.startswith(sanitized_name) and "_" in unique_name:
                stats["duplicate_rules"] += 1
            else:
                stats["renamed_rules"] += 1
            rule_name = unique_name

        # 3. Validate
        is_valid, error_msg = validate_rule_block(header, rule_text, engine=engine)
        if is_valid:
            valid_blocks.append(rule_text)
            stats["valid_rules"] += 1
        else:
            quarantined_blocks.append((rule_name, rule_text, f"Compilation failed: {error_msg}"))
            stats["broken_rules"] += 1
            logger.warning(f"Rule '{rule_name}' in {input_file} is broken: {error_msg}")

    # 4. Rewrite original file if changes occurred
    if stats["broken_rules"] > 0 or stats["limit_broken_rules"] > 0 or stats["duplicate_rules"] > 0 or stats["renamed_rules"] > 0:
        with input_path.open("w", encoding="utf-8") as f:
            f.write(header)
            for block in valid_blocks:
                f.write(block)
                if not block.endswith("\n"):
                    f.write("\n")

    # 5. Write broken/quarantined rules to quarantine (append mode)
    if quarantined_blocks:
        with broken_path.open("a", encoding="utf-8") as f:
            f.write(f"\n// Rules quarantined on {datetime.datetime.now()} from {input_file}\n")
            for name, text, reason in quarantined_blocks:
                f.write(f"// Reason: {reason}\n")
                f.write(text)
                if not text.endswith("\n"):
                    f.write("\n")
                f.write("\n")

    return stats


def create_index_file(directory: str, index_file: str, recurse: bool = False):
    """Creates a YARA index file containing include statements for all .yar files in a directory."""
    dir_path = Path(directory)
    index_path = Path(index_file)

    with index_path.open("w", encoding="utf-8") as f:
        f.write("/*\n")
        f.write(" * YARA-X PRO CLI Generated Index File\n")
        f.write(f" * Date: {datetime.datetime.now()}\n")
        f.write(" */\n\n")

        pattern = "**/*.yar*" if recurse else "*.yar*"
        for file in dir_path.glob(pattern):
            if file.resolve() == index_path.resolve():
                continue

            # Use relative path if possible
            try:
                relative_path = os.path.relpath(file, index_path.parent)
            except ValueError:
                relative_path = str(file)

            # Ensure forward slashes for YARA includes
            relative_path = relative_path.replace("\\", "/")
            f.write(f'include "{relative_path}"\n')


def compile_yara_x(input_file: str, output_file: str) -> bool:
    """Compiles a YARA file using YARA-X and saves the serialized rules."""
    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            source_code = f.read()

        # Use yara_x.compile
        rules = yara_x.compile(source_code)

        # Use serialize_into
        with open(output_file, "wb") as f_out:
            rules.serialize_into(f_out)
        return True
    except yara_x.CompileError as e:
        logger.error(f"Error compiling YARA-X rules: {e}")
        return False
    except Exception as e:
        logger.error(f"Error saving YARA-X rules: {e}")
        return False


# CLI Support (compatible with YARA_Util.py patterns)
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="YARA-X PRO CLI: Unified Rule Maintenance Tool.")
    parser.add_argument("-d", "--directory", help="Directory containing YARA rules")
    parser.add_argument("-f", "--file", help="Specific YARA file to clean")
    parser.add_argument("-i", "--index", help="Path to create an index file")
    parser.add_argument("-r", "--recurse", action="store_true", help="Recurse subdirectories")
    parser.add_argument("-e", "--engine", choices=["yara", "yarax", "both"], default="both", help="Engine to use for validation")
    parser.add_argument("-b", "--broken", help="Path to broken rules quarantine file")
    parser.add_argument("--fix-limits", action="store_true", help="Remove rules with $opcode10000 (10k string limit)")

    args = parser.parse_args()

    if args.file:
        print(f"[*] Processing file: {args.file}")
        stats = clean_yara_file(args.file, broken_rules_file=args.broken, engine=args.engine, fix_limits=args.fix_limits)
        print(f"[+] Stats: {stats}")

    if args.directory:
        print(f"[*] Processing directory: {args.directory}")
        pattern = "**/*.yar*" if args.recurse else "*.yar*"
        total_stats = {"valid_rules": 0, "broken_rules": 0, "limit_broken_rules": 0, "duplicate_rules": 0, "renamed_rules": 0}

        for file in Path(args.directory).glob(pattern):
            if file.name.endswith("_broken.yar"):
                continue
            print(f"  [-] Processing {file}...")
            stats = clean_yara_file(str(file), engine=args.engine, fix_limits=args.fix_limits)
            if "error" not in stats:
                for k in total_stats:
                    if k in stats:
                        total_stats[k] += stats[k]

        print(f"[+] Total Stats: {total_stats}")

    if args.index and args.directory:
        print(f"[*] Creating index: {args.index}")
        create_index_file(args.directory, args.index, recurse=args.recurse)
