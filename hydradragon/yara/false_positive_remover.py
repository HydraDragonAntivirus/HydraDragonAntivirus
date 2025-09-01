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

def build_cli_parser():
    """Builds the command-line interface for the script."""
    parser = OptionParser(
        usage="%prog -y <YARA_PATH> -f <BENIGN_FILES_DIR> [options]",
        description="Identifies false positive rules by scanning benign files, then removes those rules from the source."
    )
    parser.add_option(
        "-y", "--yara-path",
        dest="yara_path",
        help="Required: Path to the YARA file or directory to scan and clean."
    )
    parser.add_option(
        "-f", "--false-positives-dir",
        dest="fp_path",
        help="Required: Path to the directory of benign files to scan for false positives."
    )
    parser.add_option(
        "-s", "--subdirectories",
        action="store_true",
        default=False,
        help="If --yara-path is a directory, recurse into its subdirectories."
    )
    parser.add_option(
        "-w", "--workers",
        dest="workers",
        type="int",
        default=os.cpu_count(),
        help=f"Number of parallel processes to use for scanning. (Default: {os.cpu_count()})"
    )
    return parser

def log_message(message):
    """Logs a message to the console and the log file."""
    print(message)
    try:
        with open(LOG_FILE, "a", encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now()}] {message}\n")
    except IOError as e:
        print(f"Error: Could not write to log file {LOG_FILE}: {e}")

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

    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yar", encoding='utf-8')
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

def generate_fp_rules_from_scan(scan_entrypoint_path, benign_files_dir, num_workers):
    """
    Scans a directory of benign files in parallel and returns the names of all matching rules.
    """
    fp_rule_names = set()
    
    # 1. Collect all benign files to be scanned
    benign_files = [os.path.join(r, f) for r, _, fs in os.walk(benign_files_dir) for f in fs]
    if not benign_files:
        log_message("Warning: No files found in the benign files directory.")
        return fp_rule_names

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
        first_brace_index = content.index('{', start_index)
    except ValueError:
        return -1 

    brace_level = 1
    in_string = False
    string_char = ''

    for i in range(first_brace_index + 1, len(content)):
        char = content[i]
        prev_char = content[i-1]

        if in_string:
            if char == string_char and prev_char != '\\':
                in_string = False
        else:
            if char in ('"', "'"):
                in_string = True
                string_char = char
            elif char == '{':
                brace_level += 1
            elif char == '}':
                brace_level -= 1

        if brace_level == 0:
            return i + 1
    return -1

def process_yara_file(filepath, rules_to_remove):
    """Reads a YARA file, removes the specified rules, and overwrites the file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            original_content = f.read()
    except Exception as e:
        log_message(f"Error: Could not read file {filepath}. Skipping. Details: {e}")
        return

    modified_content = original_content
    rules_removed_in_file = 0
    rule_pattern = re.compile(r"^\s*(?:private\s+)?rule\s+([a-zA-Z0-9_]+)", re.MULTILINE)

    for match in reversed(list(rule_pattern.finditer(original_content))):
        rule_name = match.group(1)
        if rule_name in rules_to_remove:
            start_index = match.start()
            end_index = find_rule_end_index(original_content, start_index)
            if end_index != -1:
                modified_content = modified_content[:start_index] + modified_content[end_index:]
                rules_removed_in_file += 1
            else:
                log_message(f"Warning: Could not find matching closing brace for rule '{rule_name}' in {filepath}. Skipping.")
    
    if rules_removed_in_file > 0:
        log_message(f"INFO: Marked {rules_removed_in_file} rule(s) for removal from {filepath}")
        try:
            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(modified_content)
        except Exception as e:
            log_message(f"Error: Could not write changes to {filepath}. Details: {e}")

def main():
    """Main function to parse arguments and start the process."""
    parser = build_cli_parser()
    opts, _ = parser.parse_args()

    if not all([opts.yara_path, opts.fp_path]):
        parser.print_help()
        sys.exit(1)

    log_message("--- YARA False Positive Remover Started ---")

    yara_path = opts.yara_path
    if not os.path.exists(yara_path):
        log_message(f"Error: YARA path does not exist: '{yara_path}'"); sys.exit(1)
    if not os.path.isdir(opts.fp_path):
        log_message(f"Error: Path for benign files must be a directory: '{opts.fp_path}'"); sys.exit(1)

    scan_entrypoint, temp_file_obj = get_scan_entrypoint(yara_path, opts.subdirectories)
    if not scan_entrypoint:
        log_message(f"Error: No .yar or .yara files found in '{yara_path}'. Aborting."); sys.exit(1)
    
    false_positive_rules = set()
    try:
        # 1. Generate the set of false positive rule names by scanning benign files in parallel
        false_positive_rules = generate_fp_rules_from_scan(scan_entrypoint, opts.fp_path, opts.workers)
    finally:
        if temp_file_obj:
            os.unlink(temp_file_obj.name)

    if not false_positive_rules:
        log_message("Info: Scan complete. No false positives were identified.")
        log_message("--- YARA False Positive Remover Finished ---")
        sys.exit(0)

    log_message(f"Identified {len(false_positive_rules)} unique false positive rules to be removed.")

    # 2. Process the YARA path to remove the identified rules
    files_to_clean = []
    if os.path.isfile(yara_path):
        files_to_clean.append(yara_path)
    else: # is a directory
        if opts.subdirectories:
            for root, _, files in os.walk(yara_path):
                for f in files:
                    if f.endswith((".yar", ".yara")): files_to_clean.append(os.path.join(root, f))
        else:
            for f in os.listdir(yara_path):
                fp = os.path.join(yara_path, f)
                if os.path.isfile(fp) and f.endswith((".yar", ".yara")): files_to_clean.append(fp)

    log_message(f"Cleaning {len(files_to_clean)} YARA file(s)...")
    for f in tqdm(files_to_clean, desc="Cleaning YARA Files"):
        process_yara_file(f, false_positive_rules)

    log_message("--- YARA False Positive Remover Finished ---")

if __name__ == "__main__":
    main()
