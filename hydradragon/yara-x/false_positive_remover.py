#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This script dynamically identifies and removes false positive YARA rules.
# It scans a directory of benign files in parallel and removes any rule that
# triggers a match from the source YARA file or directory.
#
# Copyright (c) 2020 Ryan Boyle randomrhythm@rhythmengineering.com.
# Modified in 2025 for simplicity, performance, and correctness.
# All rights reserved.
#
# This program is free software under the GNU General Public License v3.
# See <http://www.gnu.org/licenses/> for details.
#
# Dependencies: yara-python, tqdm
# Install with: pip install yara-python tqdm

import os
import sys
import re
import csv
import datetime
import tempfile
from optparse import OptionParser
from concurrent.futures import ProcessPoolExecutor, as_completed

# Attempt to import required libraries and provide helpful error messages.
try:
    import yara
except ImportError:
    print("Error: The 'yara-python' library is not installed.")
    print("Please install it by running: pip install yara-python")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: The 'tqdm' library is not installed.")
    print("Please install it by running: pip install tqdm")
    sys.exit(1)


LOG_FILE = "removal.log"
# Master exclusion list (one YARA rule name per line) kept in sync with every
# removal so the YARA-X engine can skip these rules without re-deriving them.
EXCLUDED_RULES_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "excluded_yara_x_rules_old.txt"
)


def build_cli_parser():
    """Builds the command-line interface for the script."""
    parser = OptionParser(usage="%prog -y <YARA_PATH> -f <BENIGN_FILES_DIR> [options]", description="Identifies false positive rules by scanning benign files, then removes those rules from the source.")
    parser.add_option("-y", "--yara-path", dest="yara_path", help="Required: Path to the YARA file or directory to scan and clean.")
    parser.add_option("-f", "--false-positives-dir", dest="fp_path", help="Required: Path to the directory of benign files to scan for false positives.")
    parser.add_option("-s", "--subdirectories", action="store_true", default=False, help="If --yara-path is a directory, recurse into its subdirectories.")
    parser.add_option("-w", "--workers", dest="workers", type="int", default=os.cpu_count(), help=f"Number of parallel processes to use for scanning. (Default: {os.cpu_count()})")
    parser.add_option("--from-log", action="store_true", dest="from_log", default=False, help="Skip scanning. Read already-identified FP rules from removal.log and remove them directly.")
    parser.add_option("--from-csv", dest="from_csv", default=None, metavar="CSV", help="Skip scanning. Read FP YARA rule names from a HydraDragon scan-results CSV (the yara_x: entries in the 'Threat' column) and remove them directly.")
    parser.add_option("--skip-yara-files", action="store_true", dest="skip_yara_files", default=False, help="Skip .yar, .yara, and .yrc files when scanning the benign files directory.")
    return parser


def log_message(message):
    """Logs a message to the console and the log file."""
    print(message)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now()}] {message}\n")
    except IOError as e:
        print(f"Error: Could not write to log file {LOG_FILE}: {e}")


def is_yara_artifact(filepath):
    """Return True when the path looks like a YARA source or compiled rule file."""
    return os.path.splitext(filepath)[1].lower() in (".yar", ".yara", ".yrc")


def get_scan_entrypoint(yara_path, recursive):
    """
    If the path is a directory, creates a temporary master YARA file that includes
    all .yar/.yara files. Returns the path to the file to be compiled.
    """
    if os.path.isfile(yara_path):
        return yara_path, None

    yara_files = []
    if recursive:
        for root, _, files in os.walk(yara_path):
            for filename in files:
                if filename.endswith((".yar", ".yara")):
                    yara_files.append(os.path.join(root, filename))
    else:
        for filename in os.listdir(yara_path):
            filepath = os.path.join(yara_path, filename)
            if os.path.isfile(filepath) and filename.endswith((".yar", ".yara")):
                yara_files.append(filepath)

    if not yara_files:
        return None, None

    temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar", encoding="utf-8")
    for yf in yara_files:
        temp_file.write(f'include "{yf}"\n')
    temp_file.close()
    return temp_file.name, temp_file


def scan_file(rules_path, file_to_scan):
    """
    Worker function: Compiles rules and scans a single file.
    Returns a set of rule names that matched.
    """
    matching_rules = set()
    try:
        rules = yara.compile(filepath=rules_path, includes=True)
        matches = rules.match(filepath=file_to_scan)
        for match in matches:
            matching_rules.add(match.rule)
    except (yara.Error, IOError):
        # Suppress errors for individual file scans (e.g., locked files)
        # These can be logged if more verbosity is needed.
        pass
    return matching_rules, file_to_scan


def generate_fp_rules_from_scan(scan_entrypoint_path, benign_files_dir, num_workers, skip_yara_files=False):
    """
    Scans a directory of benign files in parallel and returns the names of all matching rules.
    """
    fp_rule_names = set()

    # 1. Collect all benign files to be scanned
    benign_files = []
    skipped_yara_files = 0
    for root, _, files in os.walk(benign_files_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            if skip_yara_files and is_yara_artifact(filepath):
                skipped_yara_files += 1
                continue
            benign_files.append(filepath)

    if not benign_files:
        log_message("Warning: No files found in the benign files directory.")
        return fp_rule_names

    if skip_yara_files and skipped_yara_files:
        log_message(f"Skipped {skipped_yara_files} YARA file(s) in the benign files directory.")

    log_message(f"Scanning {len(benign_files)} benign files with {num_workers} workers...")

    # 2. Use ProcessPoolExecutor to scan files in parallel
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        # Submit all scan jobs
        futures = [executor.submit(scan_file, scan_entrypoint_path, bf) for bf in benign_files]

        # Process results as they complete with a progress bar
        for future in tqdm(as_completed(futures), total=len(benign_files), desc="Scanning Benign Files"):
            try:
                matching_rules, scanned_file = future.result()
                if matching_rules:
                    newly_identified = matching_rules - fp_rule_names
                    for rule_name in newly_identified:
                        log_message(f"  -> Identified FP: Rule '{rule_name}' matched on '{scanned_file}'")
                    fp_rule_names.update(matching_rules)
            except Exception as e:
                log_message(f"Error processing a file: {e}")

    return fp_rule_names


def find_rule_end_index(content, start_index):
    """Finds the matching closing brace for a rule block, ignoring braces in strings."""
    try:
        first_brace_index = content.index("{", start_index)
    except ValueError:
        return -1

    brace_level = 1
    in_string = False
    string_char = ""

    for i in range(first_brace_index + 1, len(content)):
        char = content[i]
        prev_char = content[i - 1]

        if in_string:
            if char == string_char and prev_char != "\\":
                in_string = False
        else:
            if char in ('"', "'"):
                in_string = True
                string_char = char
            elif char == "{":
                brace_level += 1
            elif char == "}":
                brace_level -= 1

        if brace_level == 0:
            return i + 1
    return -1


def process_yara_file(filepath, rules_to_remove):
    """Reads a YARA file, removes the specified rules, and overwrites the file.
    Returns a list of the removed rule blocks (their full source text), in the
    order they appeared in the file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            original_content = f.read()
    except Exception as e:
        log_message(f"Error: Could not read file {filepath}. Skipping. Details: {e}")
        return []

    modified_content = original_content
    removed_blocks = []
    rule_pattern = re.compile(r"^\s*(?:private\s+)?rule\s+([a-zA-Z0-9_]+)", re.MULTILINE)

    for match in reversed(list(rule_pattern.finditer(original_content))):
        rule_name = match.group(1)
        if rule_name in rules_to_remove:
            start_index = match.start()
            end_index = find_rule_end_index(original_content, start_index)
            if end_index != -1:
                # Capture the exact source of the rule before it is sliced out.
                removed_blocks.append(original_content[start_index:end_index])
                modified_content = modified_content[:start_index] + modified_content[end_index:]
            else:
                log_message(f"Warning: Could not find matching closing brace for rule '{rule_name}' in {filepath}. Skipping.")

    if removed_blocks:
        # Iterated in reverse; restore source order for the archive.
        removed_blocks.reverse()
        log_message(f"INFO: Marked {len(removed_blocks)} rule(s) for removal from {filepath}")
        try:
            with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
                f.write(modified_content)
        except Exception as e:
            log_message(f"Error: Could not write changes to {filepath}. Details: {e}")

    return removed_blocks


def parse_fp_rules_from_log(log_path):
    """Parses the removal.log file and extracts all identified FP rule names."""
    fp_rules = set()
    pattern = re.compile(r"Identified FP: Rule '([^']+)'")
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    fp_rules.add(match.group(1))
    except FileNotFoundError:
        log_message(f"Error: Log file '{log_path}' not found.")
    except IOError as e:
        log_message(f"Error: Could not read log file '{log_path}': {e}")
    return fp_rules


def extract_yara_rules_from_threat(threat):
    """
    Pulls YARA-X rule names out of a scan-results 'Threat' cell, e.g.
    'yara_x: rule_a, rule_b  |  ml p=0.000' -> {'rule_a', 'rule_b'}.
    Only the yara_x:/yara: segment is considered; other engines (ml, clamav,
    hydradragonsig, ...) are ignored since they are not rule-name based.
    """
    rules = set()
    # Detections from different engines are separated by '|'.
    for segment in threat.split("|"):
        match = re.match(r"(?i)\s*yara(?:_x)?\s*:\s*(.+)", segment)
        if not match:
            continue
        for name in match.group(1).split(","):
            name = name.strip()
            # Keep only valid YARA rule identifiers (drops stray text/counters).
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                rules.add(name)
    return rules


def parse_fp_rules_from_csv(csv_path):
    """Parses a HydraDragon scan-results CSV and returns the set of YARA rule
    names that fired (from the 'Threat' column)."""
    fp_rules = set()
    try:
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            # Skip the leading '# ...' comment lines that precede the header row.
            data_lines = (line for line in f if not line.lstrip().startswith("#"))
            reader = csv.DictReader(data_lines)
            if not reader.fieldnames or "Threat" not in reader.fieldnames:
                log_message(f"Error: CSV '{csv_path}' has no 'Threat' column. Found: {reader.fieldnames}")
                return fp_rules
            for row in reader:
                threat = row.get("Threat") or ""
                fp_rules.update(extract_yara_rules_from_threat(threat))
    except FileNotFoundError:
        log_message(f"Error: CSV file '{csv_path}' not found.")
    except (IOError, csv.Error) as e:
        log_message(f"Error: Could not read CSV file '{csv_path}': {e}")
    return fp_rules


def collect_yara_files(yara_path, recursive):
    """Returns the list of YARA source files to clean for the given path."""
    if os.path.isfile(yara_path):
        return [yara_path]
    files_to_clean = []
    if recursive:
        for root, _, files in os.walk(yara_path):
            for f in files:
                if f.endswith((".yar", ".yara")):
                    files_to_clean.append(os.path.join(root, f))
    else:
        for f in os.listdir(yara_path):
            fp = os.path.join(yara_path, f)
            if os.path.isfile(fp) and f.endswith((".yar", ".yara")):
                files_to_clean.append(fp)
    return files_to_clean


def clean_yara_files(yara_path, rules_to_remove, recursive):
    """Removes the named rules from every YARA file under yara_path.
    Returns the list of removed rule blocks (full source text) across all files."""
    files_to_clean = collect_yara_files(yara_path, recursive)
    log_message(f"Cleaning {len(files_to_clean)} YARA file(s)...")
    removed_blocks = []
    for f in tqdm(files_to_clean, desc="Cleaning YARA Files"):
        removed_blocks.extend(process_yara_file(f, rules_to_remove))
    return removed_blocks


def next_available_path(base_name):
    """Return base_name if it doesn't exist, else base_name with an incrementing
    _1, _2, ... suffix inserted before the extension (e.g. removed_fp_rules_1.yar)."""
    if not os.path.exists(base_name):
        return base_name
    root, ext = os.path.splitext(base_name)
    i = 1
    while os.path.exists(f"{root}_{i}{ext}"):
        i += 1
    return f"{root}_{i}{ext}"


def write_removed_rules_archive(removed_blocks, base_name="removed_fp_rules.yar"):
    """Write the removed rule blocks to removed_fp_rules.yar (or _1, _2, ... if it
    already exists). Returns the path written, or None if there was nothing to write."""
    if not removed_blocks:
        log_message("No rules were removed, so no archive file was created.")
        return None
    out_path = next_available_path(base_name)
    header = (
        f"// {len(removed_blocks)} false-positive rule(s) removed by "
        f"false_positive_remover.py\n\n"
    )
    body = "\n\n".join(block.strip() for block in removed_blocks)
    try:
        with open(out_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(header + body + "\n")
        log_message(f"INFO: Archived {len(removed_blocks)} removed rule(s) to {out_path}")
    except Exception as e:
        log_message(f"Error: Could not write removed-rules archive {out_path}. Details: {e}")
        return None
    return out_path


def update_excluded_rules_file(rule_names, path=EXCLUDED_RULES_FILE):
    """Append the given FP rule names to the master exclusion list, preserving the
    existing order and skipping any that are already present. Returns the number
    of newly added names."""
    if not rule_names:
        return 0

    # Keep the first occurrence of each existing name (collapsing any pre-existing
    # duplicates) and remember what's already present so we never re-add a name.
    existing = []
    seen = set()
    dropped_dupes = 0
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    name = line.strip()
                    if not name:
                        continue
                    if name in seen:
                        dropped_dupes += 1
                        continue
                    seen.add(name)
                    existing.append(name)
        except IOError as e:
            log_message(f"Error: Could not read exclusion list '{path}': {e}")
            return 0

    new_names = sorted(n for n in rule_names if n and n not in seen)
    if not new_names and not dropped_dupes:
        log_message(f"INFO: All {len(rule_names)} FP rule(s) already in {os.path.basename(path)}.")
        return 0

    try:
        with open(path, "w", encoding="utf-8") as f:
            for name in existing:
                f.write(name + "\n")
            for name in new_names:
                f.write(name + "\n")
    except IOError as e:
        log_message(f"Error: Could not update exclusion list '{path}': {e}")
        return 0

    if dropped_dupes:
        log_message(f"INFO: Collapsed {dropped_dupes} pre-existing duplicate(s) in {os.path.basename(path)}.")
    log_message(f"INFO: Added {len(new_names)} rule(s) to {os.path.basename(path)} "
                f"(now {len(seen) + len(new_names)} total).")
    return len(new_names)


def main():
    """Main function to parse arguments and start the process."""
    parser = build_cli_parser()
    opts, _ = parser.parse_args()

    # Convenience: if -f points at a .csv file (rather than a benign-files dir),
    # treat it as --from-csv so `-f results.csv` just works.
    if opts.fp_path and not opts.from_csv and os.path.isfile(opts.fp_path) \
            and opts.fp_path.lower().endswith(".csv"):
        log_message(f"Note: '-f' given a CSV file; routing to --from-csv mode.")
        opts.from_csv = opts.fp_path
        opts.fp_path = None

    # The "skip scanning" modes (--from-log / --from-csv) don't need benign files.
    skip_scan = opts.from_log or bool(opts.from_csv)

    # Only require fp_path when actually scanning benign files.
    if not skip_scan and not opts.fp_path:
        parser.print_help()
        sys.exit(1)

    log_message("--- YARA False Positive Remover Started ---")

    yara_path = opts.yara_path
    if not yara_path or not os.path.exists(yara_path):
        log_message(f"Error: YARA path does not exist: '{yara_path}'")
        sys.exit(1)
    # Check benign files path only when scanning.
    if not skip_scan:
        if not os.path.isdir(opts.fp_path):
            log_message(f"Error: Path for benign files must be a directory: '{opts.fp_path}'")
            sys.exit(1)

    # --from-csv mode: skip scanning, parse FP rule names from a scan-results CSV.
    if opts.from_csv:
        log_message(f"--- From-CSV Mode: Reading FP rules from '{opts.from_csv}' ---")
        false_positive_rules = parse_fp_rules_from_csv(opts.from_csv)
        if not false_positive_rules:
            log_message("Info: No YARA FP rules found in the CSV. Exiting.")
            sys.exit(0)
        log_message(f"Found {len(false_positive_rules)} unique FP rule(s) in the CSV. Proceeding to clean...")
        removed_blocks = clean_yara_files(yara_path, false_positive_rules, opts.subdirectories)
        write_removed_rules_archive(removed_blocks)
        update_excluded_rules_file(false_positive_rules)
        log_message("--- YARA False Positive Remover Finished ---")
        sys.exit(0)

    # --from-log mode: skip scanning, parse rules directly from removal.log
    if opts.from_log:
        log_message(f"--- From-Log Mode: Reading FP rules from '{LOG_FILE}' ---")
        false_positive_rules = parse_fp_rules_from_log(LOG_FILE)
        if not false_positive_rules:
            log_message("Info: No FP rules found in log. Exiting.")
            sys.exit(0)
        log_message(f"Found {len(false_positive_rules)} unique FP rules in log. Proceeding to clean...")
        clean_yara_files(yara_path, false_positive_rules, opts.subdirectories)
        update_excluded_rules_file(false_positive_rules)
        log_message("--- YARA False Positive Remover Finished ---")
        sys.exit(0)

    scan_entrypoint, temp_file_obj = get_scan_entrypoint(yara_path, opts.subdirectories)
    if not scan_entrypoint:
        log_message(f"Error: No .yar or .yara files found in '{yara_path}'. Aborting.")
        sys.exit(1)

    false_positive_rules = set()
    try:
        # 1. Generate the set of false positive rule names by scanning benign files in parallel
        false_positive_rules = generate_fp_rules_from_scan(
            scan_entrypoint,
            opts.fp_path,
            opts.workers,
            skip_yara_files=opts.skip_yara_files,
        )
    finally:
        if temp_file_obj:
            os.unlink(temp_file_obj.name)

    if not false_positive_rules:
        log_message("Info: Scan complete. No false positives were identified.")
        log_message("--- YARA False Positive Remover Finished ---")
        sys.exit(0)

    log_message(f"Identified {len(false_positive_rules)} unique false positive rules to be removed.")

    # 2. Process the YARA path to remove the identified rules
    clean_yara_files(yara_path, false_positive_rules, opts.subdirectories)
    update_excluded_rules_file(false_positive_rules)

    log_message("--- YARA False Positive Remover Finished ---")


if __name__ == "__main__":
    main()
