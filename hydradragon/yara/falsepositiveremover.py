#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#This script can identify and remove duplicate rules (based on rule name) from YARA files contained within a directory.
#Duplicate rules are logged to duplicate.log in the current directory.
#Rule names are echoed to standard out.
#Be sure to backup your data before using the remove option.

#Copyright (c) 2020 Ryan Boyle randomrhythm@rhythmengineering.com.
#All rights reserved.

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
from optparse import OptionParser
import sys
import datetime
import re
import subprocess
import shutil

# ---------------------------
# CLI parser (no rename flag)
# ---------------------------
def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Find duplicate YARA rules in a directory")
    parser.add_option("-r", "--remove", help="Remove rules flagged as false positives", action="store_true")
    parser.add_option("-d", "--directory", action="store", default=None, dest="YARA_Directory_Path",
                      help="Folder path to directory containing YARA files")
    parser.add_option("-c", "--consolidate", action="store", default=None, dest="YARA_File_Path",
                      help="File path for consolidated YARA file")
    parser.add_option("-i", "--index", action="store", default=None, dest="YARA_Index_Path",
                      help="Create an index of YARA files")
    parser.add_option("-t", "--type", action="store", default=None, dest="YARA_Index_Type",
                      help="Index YARA files based on parent folder match.")
    parser.add_option("-b", "--BaseDirectory", action="store", default=None, dest="Base_Folder_Path",
                      help="Base folder to mark as current directory ./")
    parser.add_option("-s", "--subdirectories", help="Recurse into subdirectories", action="store_true")
    parser.add_option("-v", "--verboselog", help="log all rules and the associated file", action="store_true")
    # False-positive scanning options
    parser.add_option("--fp-scan-folder", action="store", default=None, dest="FP_Scan_Folder",
                      help="Folder path containing sample files to scan for false positives")
    parser.add_option("--fp-match-threshold", action="store", default=5, type="int", dest="FP_MATCH_THRESHOLD",
                      help="Mark rule as FP if it matches >= N files in the FP folder (default 5)")
    parser.add_option("--fp-match-ratio", action="store", default=None, dest="FP_MATCH_RATIO",
                      help="Mark rule as FP if it matches >= fraction (0<ratio<=1) of files in FP folder (overrides threshold)")
    return parser

# ---------------------------
# Utilities
# ---------------------------
def logToFile(strfilePathOut, strDataToLog, boolDeleteFile=False, strWriteMode="a"):
    parent = os.path.dirname(strfilePathOut)
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except Exception:
            pass
    with open(strfilePathOut, strWriteMode, encoding='utf-8', errors='ignore') as target:
        if boolDeleteFile:
            target.truncate()
        target.write(strDataToLog)

def which(exe):
    return shutil.which(exe)

# ---------------------------
# YARA scanning helpers
# ---------------------------
def yara_available_python():
    try:
        import yara
        return True
    except Exception:
        return False

def yara_compile_rules_from_file(filepath):
    import yara
    return yara.compile(filepath=filepath)

def yara_scan_file_with_rules_py(compiled_rules, target_path):
    # returns set of matching rule names (may be empty)
    matches = set()
    try:
        # `matches = compiled_rules.match(target_path)` returns list of Match objects or names
        res = compiled_rules.match(target_path)
        # res items may be yara.Match objects or simple strings depending on yara version
        for r in res:
            # try to extract rule name
            try:
                # if Match object
                if hasattr(r, 'rule'):
                    matches.add(r.rule)
                else:
                    matches.add(str(r))
            except Exception:
                matches.add(str(r))
    except Exception:
        # some yara-python versions use scan(..., callback) or different return; tolerate failure
        return set()
    return matches

def yara_scan_file_with_cli(rules_file, target_path):
    # Use yara CLI: `yara -n rules_file target_path` -> outputs lines like '<rule> <file>'
    # We'll parse stdout lines for rule names. Return set of rule names.
    matches = set()
    yara_exec = which('yara') or which('yara64') or which('yara.exe') or which('yara64.exe')
    if not yara_exec:
        return set()
    try:
        # -r not needed because rules_file is a rules file; simply run: yara rules_file target_path
        cmd = [yara_exec, rules_file, target_path]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', errors='ignore', timeout=30)
        out = proc.stdout.strip()
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # yara CLI prints: RULE_NAME  path — split on whitespace
            parts = line.split()
            if len(parts) >= 1:
                matches.add(parts[0])
    except Exception:
        return set()
    return matches

# ---------------------------
# ProcessRule (core) — preserves comments, no renaming
# ---------------------------
def ProcessRule(lstRuleFile, strYARApath, strOutPath,
                remove_false_positives=False,
                fp_scan_folder=None,
                fp_match_threshold=5,
                fp_match_ratio=None,
                yara_py_available=False,
                yara_cli_available=False):
    """
    Processes a single YARA file's lines:
      - Detects duplicate rules (based on strings + condition key). DOES NOT remove duplicates.
      - Merges hashN meta entries from duplicates into the first occurrence, preserving comments and other meta lines.
      - Detects false-positive rules using:
           * meta/condition heuristics OR
           * (if provided) scanning a folder of sample files to count rule matches.
        If remove_false_positives==True, removes rules detected as FP (backs up with .bak).
    """
    strYARAout = ""
    strLogOut = ""
    boolOverwrite = False
    if strOutPath == "":
        strOutPath = strYARApath

    current_rule_lines = []
    current_rule_name = None
    current_metadata = []
    current_strings = []
    current_condition = []
    in_metadata = in_strings = in_condition = False

    # Store non-rule lines at the top of the file
    pre_rule_lines = []
    first_rule_found = False

    dictRuleKey = {}
    processed_rules = []

    # conservative meta/condition heuristics
    def fp_from_meta(meta_lines, fp_meta_key="false_positive"):
        for line in meta_lines:
            m = re.search(r'^\s*' + re.escape(fp_meta_key) + r'\s*=\s*("?)(true|yes|1)("?)(\s*#.*)?$', line.strip(), re.IGNORECASE)
            if m:
                return True
        return False

    def fp_from_condition(cond_lines):
        joined = " ".join([l.strip().lower() for l in cond_lines])
        if re.search(r'\btrue\b', joined):
            return True
        if re.search(r'1\s*==\s*1', joined):
            return True
        return False

    # if folder scanning enabled, prepare compiled rules object (if possible) to speed up repeated scans
    compiled_rules = None
    temp_rules_path = None
    compiled_ready = False
    if fp_scan_folder:
        # if yara_py_available, compile the entire YARA file once and use it to get per-rule matches
        if yara_py_available:
            try:
                compiled_rules = yara_compile_rules_from_file(strYARApath)
                compiled_ready = True
            except Exception:
                compiled_ready = False
        else:
            # if CLI available, use the file itself (no compile needed)
            compiled_ready = yara_cli_available

    # helper to decide FP by scanning folder for a given rule name
    def fp_by_scanning_folder(rule_name):
        # if user provided a ratio, compute threshold from folder size
        try:
            files = []
            for root, _, filenames in os.walk(fp_scan_folder):
                for fn in filenames:
                    fp = os.path.join(root, fn)
                    # skip directories, only regular files
                    if os.path.isfile(fp):
                        files.append(fp)
            if len(files) == 0:
                return False, 0, 0
        except Exception:
            return False, 0, 0

        match_count = 0
        total = len(files)
        # if compiled_rules ready, use python API and check which rules matched per file
        if compiled_ready and compiled_rules is not None:
            for f in files:
                try:
                    matches = yara_scan_file_with_rules_py(compiled_rules, f)
                except Exception:
                    matches = set()
                if rule_name in matches:
                    match_count += 1
        elif yara_cli_available:
            # fallback to CLI: run yara file f and parse its output
            # to reduce CLI calls, run yara once on the whole folder with rules file and parse all outputs:
            # but simpler: call per-file (safer)
            for f in files:
                try:
                    matches = yara_scan_file_with_cli(strYARApath, f)
                except Exception:
                    matches = set()
                if rule_name in matches:
                    match_count += 1
        else:
            # cannot scan — fallback to False
            return False, 0, total

        # decide threshold
        if fp_match_ratio is not None:
            try:
                ratio = float(fp_match_ratio)
                if ratio <= 0 or ratio > 1:
                    ratio = None
                else:
                    required = max(1, int(total * ratio))
                    is_fp = (match_count >= required)
                    return is_fp, match_count, total
            except Exception:
                pass

        # absolute threshold fallback
        is_fp = (match_count >= fp_match_threshold)
        return is_fp, match_count, total

    # --- parse yara file into rules (preserve everything) ---
    for strRuleLine in lstRuleFile + ["\nENDRULE\n"]:
        stripped = strRuleLine.strip()
        if stripped.startswith("rule ") or stripped.startswith("private rule ") or stripped == "ENDRULE":
            if current_rule_name:
                key = "\n".join([s.strip() for s in current_strings]) + "\n" + "\n".join([c.strip() for c in current_condition])

                # meta/cond heuristics
                is_fp_meta = fp_from_meta(current_metadata)
                is_fp_cond = fp_from_condition(current_condition)
                is_fp_scan = False
                scan_match_count = 0
                scan_total = 0

                # If folder scanning requested, check by scanning folder for this rule name
                if fp_scan_folder:
                    # NOTE: compiled_rules (entire file) may include many rules; the rule names will be the same
                    # We'll try to detect by scanning the sample folder for occurrences of this rule name
                    is_fp_scan, scan_match_count, scan_total = fp_by_scanning_folder(current_rule_name)

                # final FP decision: folder-scan (if provided) has priority; else heuristics
                is_fp = False
                if fp_scan_folder:
                    is_fp = is_fp_scan
                else:
                    is_fp = is_fp_meta or is_fp_cond

                if key in dictRuleKey:
                    # Duplicate: merge hashes only; preserve comments
                    idx = dictRuleKey[key]["index"]
                    existing_rule = processed_rules[idx]
                    existing_lines = existing_rule["lines"]

                    meta_start = None
                    meta_end = None
                    for j, line in enumerate(existing_lines):
                        if line.strip().startswith("meta:") or line.strip().startswith("metadata:"):
                            meta_start = j
                            break
                    if meta_start is not None:
                        meta_end = meta_start + 1
                        while meta_end < len(existing_lines):
                            s = existing_lines[meta_end].strip()
                            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*:', s) and not s.lower().startswith("meta"):
                                break
                            meta_end += 1

                        existing_hashes = []
                        meta_segment = existing_lines[meta_start+1:meta_end]
                        preserved_meta_lines = []
                        for mline in meta_segment:
                            if re.match(r'^\s*hash\d*\s*=\s*"([^"]+)"', mline):
                                match = re.match(r'^\s*hash\d*\s*=\s*"([^"]+)"', mline)
                                if match:
                                    existing_hashes.append(match.group(1))
                                continue
                            else:
                                preserved_meta_lines.append(mline)

                        for line in current_metadata:
                            if line.strip().startswith("hash"):
                                match = re.match(r'hash\d*\s*=\s*"([^"]+)"', line.strip())
                                if match:
                                    val = match.group(1)
                                    if val not in existing_hashes:
                                        existing_hashes.append(val)

                        if preserved_meta_lines:
                            indent_match = re.match(r'^(\s*)', preserved_meta_lines[0])
                            indent = indent_match.group(1) if indent_match else "      "
                        else:
                            indent_match = re.match(r'^(\s*)', existing_lines[meta_start+1]) if (meta_start+1 < len(existing_lines)) else None
                            indent = indent_match.group(1) if indent_match else "      "

                        rebuilt_hash_lines = []
                        for i, hval in enumerate(existing_hashes, 1):
                            rebuilt_hash_lines.append(f'{indent}hash{i} = "{hval}"\n')

                        new_meta_section = [existing_lines[meta_start]] + preserved_meta_lines + rebuilt_hash_lines
                        existing_lines = existing_lines[:meta_start] + new_meta_section + existing_lines[meta_end:]
                        existing_rule["lines"] = existing_lines
                        strLogOut += f"Detected duplicate rule {current_rule_name} in {strYARApath}, merged hashes into {existing_rule['name']}\n"
                        boolOverwrite = True
                    else:
                        insertion_idx = len(existing_lines)
                        for j, line in enumerate(existing_lines):
                            if line.strip().startswith("strings:") or line.strip().startswith("condition:"):
                                insertion_idx = j
                                break
                        existing_hashes = []
                        for line in current_metadata:
                            if line.strip().startswith("hash"):
                                match = re.match(r'hash\d*\s*=\s*"([^"]+)"', line.strip())
                                if match:
                                    val = match.group(1)
                                    if val not in existing_hashes:
                                        existing_hashes.append(val)
                        if existing_hashes:
                            indent = "      "
                            new_meta_section = ["\n", "meta:\n"]
                            for i, hval in enumerate(existing_hashes, 1):
                                new_meta_section.append(f'{indent}hash{i} = "{hval}"\n')
                            existing_lines = existing_lines[:insertion_idx] + new_meta_section + existing_lines[insertion_idx:]
                            existing_rule["lines"] = existing_lines
                            strLogOut += f"Added meta.hashes to {existing_rule['name']} from duplicate {current_rule_name} in {strYARApath}\n"
                            boolOverwrite = True

                else:
                    # First occurrence: remove only if FP detected and user requested removal
                    if is_fp and remove_false_positives:
                        # log removal reason
                        if fp_scan_folder:
                            strLogOut += f"Removed false-positive rule {current_rule_name} from {strYARApath} (matched {scan_match_count}/{scan_total} files in {fp_scan_folder})\n"
                        else:
                            why = []
                            if is_fp_meta:
                                why.append("meta flag")
                            if is_fp_cond:
                                why.append("condition heuristic")
                            strLogOut += f"Removed false-positive rule {current_rule_name} from {strYARApath} ({', '.join(why)})\n"
                        boolOverwrite = True
                        # do not append this rule to processed_rules -> effectively removed
                    else:
                        rule_data = {
                            "name": current_rule_name,
                            "metadata": current_metadata.copy(),
                            "strings": current_strings.copy(),
                            "condition": current_condition.copy(),
                            "lines": current_rule_lines.copy()
                        }
                        dictRuleKey[key] = {"index": len(processed_rules)}
                        processed_rules.append(rule_data)

            # Reset for next rule
            if stripped != "ENDRULE":
                current_rule_lines = [strRuleLine]
                current_metadata = []
                current_strings = []
                current_condition = []
                in_metadata = in_strings = in_condition = False
                match = re.findall(r'rule\s+(\w+)', stripped)
                if match:
                    current_rule_name = match[0]
                    first_rule_found = True
            else:
                current_rule_name = None

        else:
            # Collect top-of-file non-rule lines
            if not first_rule_found:
                pre_rule_lines.append(strRuleLine)
            current_rule_lines.append(strRuleLine)
            if stripped.startswith("meta:") or stripped.startswith("metadata:"):
                in_metadata = True
                in_strings = in_condition = False
            elif stripped.startswith("strings:"):
                in_strings = True
                in_metadata = in_condition = False
            elif stripped.startswith("condition:"):
                in_condition = True
                in_metadata = in_strings = False
            elif in_metadata and stripped != "":
                current_metadata.append(strRuleLine)
            elif in_strings and stripped != "":
                current_strings.append(strRuleLine)
            elif in_condition and stripped != "":
                current_condition.append(strRuleLine)

    # Build final output with pre-rule lines + processed rules
    strYARAout = "".join(pre_rule_lines)
    for rule in processed_rules:
        strYARAout += "".join(rule["lines"])

    # Write consolidated file (backup first)
    if strOutPath != strYARApath:
        strYARAout += "\n"
        logToFile(strOutPath, strYARAout, False, "a")
    elif boolOverwrite:
        try:
            backup_path = strYARApath + ".bak"
            if not os.path.exists(backup_path):
                with open(strYARApath, 'r', encoding='utf-8', errors='ignore') as orig:
                    content = orig.read()
                with open(backup_path, 'w', encoding='utf-8', errors='ignore') as bak:
                    bak.write(content)
        except Exception:
            pass
        logToFile(strYARApath, strYARAout, True, "w")

    if strLogOut:
        strLogOut = "-------------\n" + strLogOut
        logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), strLogOut, False, "a")


# --------------------------
# createIndexFile / fast_scandir
# --------------------------
def createIndexFile(boolNew, strFilePath, yaraPath, baseDir):
  includePath = ""
  if boolNew == True:
    logToFile(strFilePath, "/*\n", False, "a")
    logToFile(strFilePath, "Generated by YARA_Rules_Util\n", False, "a")
    logToFile(strFilePath, "On " + str(datetime.date.today()) + "\n", False, "a")
    logToFile(strFilePath, "*/\n", False, "a")
  if "\\" in yaraPath or "/" in yaraPath:
    if "\\" in yaraPath:
      splitChar = "\\"
    else:
      splitChar = "/"
    arrayPath = yaraPath.split(splitChar)
    for i in range(len(arrayPath),0, -1):
      if includePath == "":
        includePath = arrayPath[i -1]
      else:
        includePath = arrayPath[i -1] + "/" + includePath
      if arrayPath[i -2] == baseDir:
        break
    if i != 1:
      includePath = "./" + includePath
    else:
      includePath = yaraPath
    includeStatement = "include \"" + includePath + "\""
    logToFile(strFilePath, includeStatement + "\n", False, "a")

def fast_scandir(dirname):
    subfolders= [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders

# --------------------------
# Main CLI handling & loop
# --------------------------
boolRemoveFalsePositives = False
boolRecurse = False
boolLogging = False
folderMatch = ""
indexPath = ""
outputPath = ""
baseDirectory = ""
strCurrentDirectory = os.getcwd()
strYARADirectory = os.getcwd()
parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if opts.remove:
  boolRemoveFalsePositives = True
if opts.subdirectories:
  boolRecurse = True
  print("recusing subdirectories")
if opts.verboselog:
  boolLogging = True
if opts.YARA_Index_Path:
  indexPath = opts.YARA_Index_Path
  print("creating index file: " + indexPath)
  boolNewIndex = True
if opts.YARA_Index_Type:
  folderMatch = opts.YARA_Index_Type
if opts.Base_Folder_Path:
  baseDirectory = opts.Base_Folder_Path
if opts.YARA_Directory_Path:
  strYARADirectory = opts.YARA_Directory_Path
else:
  print ("Missing required parameter argument")
  exit()
if opts.YARA_File_Path:
  outputPath = opts.YARA_File_Path

# FP scan folder & thresholds
fp_scan_folder = getattr(opts, "FP_Scan_Folder", None)
fp_match_threshold = int(getattr(opts, "FP_MATCH_THRESHOLD", 5))
fp_match_ratio = None
if getattr(opts, "FP_MATCH_RATIO", None) is not None:
    try:
        fp_match_ratio = float(opts.FP_MATCH_RATIO)
    except Exception:
        fp_match_ratio = None

# detect yara availability
yara_py_available = yara_available_python()
yara_cli_available = bool(which('yara') or which('yara64') or which('yara.exe') or which('yara64.exe'))

if fp_scan_folder and not (yara_py_available or yara_cli_available):
    print("Warning: FP scanning folder requested but neither yara-python nor yara CLI found. FP-by-scan will be skipped.")
    logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), "Warning: FP scanning skipped (no yara available)\n", False, "a")

print (strYARADirectory)
logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), "Started " + str(datetime.datetime.now()) + "\n", False, "a")

if boolRecurse == True:
  parentDir = fast_scandir(strYARADirectory)
  parentDir.append(strYARADirectory)
  parentDir.sort()
else:
  parentDir = [strYARADirectory]

print(parentDir)
for scanDirs in parentDir:
  for i in os.listdir(scanDirs):
    if i.endswith(".yar") or i.endswith(".yara"):
      if opts.YARA_File_Path != '' and folderMatch != '':
        if not scanDirs.endswith(folderMatch):
          continue
      if indexPath == "":
        print (i)
        file_path = os.path.join(scanDirs, i)
        try:
            with open(file_path, encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                ProcessRule(lines,
                            file_path,
                            outputPath,
                            remove_false_positives=boolRemoveFalsePositives,
                            fp_scan_folder=fp_scan_folder,
                            fp_match_threshold=fp_match_threshold,
                            fp_match_ratio=fp_match_ratio,
                            yara_py_available=yara_py_available,
                            yara_cli_available=yara_cli_available)
        except Exception as e:
            logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), f"ERROR reading {file_path}: {e}\n", False, "a")
      else:
        # index every matching file (still respect folderMatch)
        if folderMatch != "" and not scanDirs.endswith(folderMatch):
          continue
        createIndexFile(boolNewIndex, indexPath,  os.path.join(scanDirs, i), baseDirectory)
        boolNewIndex = False
    else:
        continue
logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), "Completed " + str(datetime.datetime.now()) + "\n", False, "a")
