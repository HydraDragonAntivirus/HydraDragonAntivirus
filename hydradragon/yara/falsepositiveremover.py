#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This script scans a YARA file or directory and removes rules that are
# listed in a separate "false positives" file or directory.
#
# Copyright (c) 2020 Ryan Boyle randomrhythm@rhythmengineering.com.
# Modified in 2024.
# All rights reserved.
#
# This program is free software under the GNU General Public License v3.
# See <http://www.gnu.org/licenses/> for details.

import os
import sys
import re
import datetime
from optparse import OptionParser

LOG_FILE = "removal.log"

def build_cli_parser():
    """Builds the command-line interface for the script."""
    parser = OptionParser(
        usage="%prog -t <TARGET> -fp <FALSE_POSITIVES> [options]",
        description="Removes false positive YARA rules from a target file or directory."
    )
    parser.add_option(
        "-t", "--target",
        dest="target_path",
        help="Required: Path to the YARA file or directory to clean."
    )
    parser.add_option(
        "-fp", "--false-positives",
        dest="fp_path",
        help="Required: Path to the file or directory with false positive rules."
    )
    parser.add_option(
        "-s", "--subdirectories",
        action="store_true",
        default=False,
        help="If target is a directory, recurse into its subdirectories."
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

def get_rule_names_from_file(filepath):
    """Extracts all YARA rule names from a given file."""
    rule_names = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Regex to find lines starting with 'rule' or 'private rule'
                match = re.match(r"^\s*(?:private\s+)?rule\s+([a-zA-Z0-9_]+)", line)
                if match:
                    rule_names.add(match.group(1))
    except FileNotFoundError:
        log_message(f"Error: File not found: {filepath}")
        return None
    except Exception as e:
        log_message(f"An unexpected error occurred while reading {filepath}: {e}")
        return None
    return rule_names

def get_rule_names_from_directory(directory_path):
    """Walks a directory and extracts all YARA rule names from .yar/.yara files."""
    all_rule_names = set()
    try:
        for root, _, files in os.walk(directory_path):
            for filename in files:
                if filename.endswith((".yar", ".yara")):
                    filepath = os.path.join(root, filename)
                    rule_names = get_rule_names_from_file(filepath)
                    if rule_names:
                        all_rule_names.update(rule_names)
    except Exception as e:
        log_message(f"An error occurred while scanning directory {directory_path}: {e}")
        return None
    return all_rule_names

def find_rule_end_index(content, start_index):
    """Finds the matching closing brace for a rule block."""
    brace_level = 0
    in_string = False
    
    # Find the first opening brace after the rule definition
    try:
        first_brace_index = content.index('{', start_index)
        brace_level = 1
    except ValueError:
        return -1 # Should not happen in a valid YARA file

    # Start scanning from the character after the first opening brace
    for i in range(first_brace_index + 1, len(content)):
        char = content[i]
        
        if char == '"':
            # Check for escaped quotes
            if i > 0 and content[i-1] != '\\':
                in_string = not in_string
        
        if in_string:
            continue
            
        if char == '{':
            brace_level += 1
        elif char == '}':
            brace_level -= 1
        
        if brace_level == 0:
            return i + 1 # Return the index right after the closing brace
            
    return -1 # Return -1 if matching brace is not found

def process_yara_file(filepath, rules_to_remove):
    """
    Reads a YARA file, removes the specified rules, and overwrites the file
    if any changes were made.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            original_content = f.read()
    except Exception as e:
        log_message(f"Error: Could not read file {filepath}. Skipping. Details: {e}")
        return

    content_to_keep = original_content
    modified = False

    # Find all rule definitions and their boundaries
    # Using a negative lookbehind to avoid matching rules inside comments
    rule_definitions = list(re.finditer(r"^(?<!//.*)(?:private\s+)?rule\s+([a-zA-Z0-9_]+)", original_content, re.MULTILINE))

    # We iterate backwards to ensure that removing content doesn't mess up the indices
    # of subsequent rules that we still need to check.
    for match in reversed(rule_definitions):
        rule_name = match.group(1)
        
        if rule_name in rules_to_remove:
            start_index = match.start()
            end_index = find_rule_end_index(original_content, start_index)

            if end_index != -1:
                # Remove the entire rule block from the content
                content_to_keep = content_to_keep[:start_index] + content_to_keep[end_index:]
                log_message(f"INFO: Removed rule '{rule_name}' from {filepath}")
                modified = True
            else:
                log_message(f"Warning: Could not find matching closing brace for rule '{rule_name}' in {filepath}. Skipping removal.")

    if modified:
        try:
            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(content_to_keep)
            log_message(f"SUCCESS: Overwrote {filepath} with false positives removed.")
        except Exception as e:
            log_message(f"Error: Could not write changes to {filepath}. Details: {e}")

def main():
    """Main function to parse arguments and start the process."""
    parser = build_cli_parser()
    opts, _ = parser.parse_args()

    if not opts.target_path or not opts.fp_path:
        parser.print_help()
        sys.exit(1)

    log_message("--- YARA False Positive Remover Started ---")

    # 1. Get the set of false positive rule names from the FP path
    fp_path = opts.fp_path
    false_positive_rules = set()

    if not os.path.exists(fp_path):
        log_message(f"Error: False positive path does not exist: {fp_path}")
        sys.exit(1)
    
    if os.path.isfile(fp_path):
        log_message(f"Reading false positive rules from file: {fp_path}")
        false_positive_rules = get_rule_names_from_file(fp_path)
    elif os.path.isdir(fp_path):
        log_message(f"Scanning false positive directory: {fp_path}")
        false_positive_rules = get_rule_names_from_directory(fp_path)

    if false_positive_rules is None:
        log_message("Error: Could not process the false positives path. Aborting.")
        sys.exit(1)
    if not false_positive_rules:
        log_message("Warning: No rule names found in the false positives path.")
    else:
        log_message(f"Found {len(false_positive_rules)} unique false positive rules to remove.")

    # 2. Process the target path
    target_path = opts.target_path
    if not os.path.exists(target_path):
        log_message(f"Error: Target path does not exist: {target_path}")
        sys.exit(1)

    if os.path.isfile(target_path):
        log_message(f"Processing target file: {target_path}")
        process_yara_file(target_path, false_positive_rules)
    elif os.path.isdir(target_path):
        log_message(f"Scanning target directory to clean: {target_path}")
        if opts.subdirectories:
            log_message("Recursive scan of target directory enabled.")
            for root, _, files in os.walk(target_path):
                for filename in files:
                    if filename.endswith((".yar", ".yara")):
                        filepath = os.path.join(root, filename)
                        process_yara_file(filepath, false_positive_rules)
        else:
            log_message("Recursive scan of target directory disabled.")
            for filename in os.listdir(target_path):
                if filename.endswith((".yar", ".yara")):
                    filepath = os.path.join(target_path, filename)
                    if os.path.isfile(filepath):
                        process_yara_file(filepath, false_positive_rules)

    log_message("--- YARA False Positive Remover Finished ---")

if __name__ == "__main__":
    main()
