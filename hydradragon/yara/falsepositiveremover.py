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
    # False-positive scanning option (single flag)
    parser.add_option("-f", "--fp", action="store", default=None, dest="FP_Scan_Folder",
                      help="Folder path containing sample files to scan for false positives (if a rule matches ANY file, it's removed)")
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
    matches = set()
    try:
        res = compiled_rules.match(target_path)
        for r in res:
            if hasattr(r, 'rule'):
                matches.add(r.rule)
            else:
                matches.add(str(r))
    except Exception:
        return set()
    return matches

def yara_scan_file_with_cli(rules_file, target_path):
    matches = set()
    yara_exec = which('yara') or which('yara64') or which('yara.exe') or which('yara64.exe')
    if not yara_exec:
        return set()
    try:
        cmd = [yara_exec, rules_file, target_path]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', errors='ignore', timeout=30)
        out = proc.stdout.strip()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 1:
                matches.add(parts[0])
    except Exception:
        return set()
    return matches

# ---------------------------
# ProcessRule
# ---------------------------
def ProcessRule(lstRuleFile, strYARApath, strOutPath,
                remove_false_positives=False,
                fp_scan_folder=None,
                yara_py_available=False,
                yara_cli_available=False):

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

    pre_rule_lines = []
    first_rule_found = False

    dictRuleKey = {}
    processed_rules = []

    # prepare YARA compiler if possible
    compiled_rules = None
    compiled_ready = False
    if fp_scan_folder:
        if yara_py_available:
            try:
                compiled_rules = yara_compile_rules_from_file(strYARApath)
                compiled_ready = True
            except Exception:
                compiled_ready = False
        else:
            compiled_ready = yara_cli_available

    def fp_by_scanning_folder(rule_name):
        try:
            files = []
            for root, _, filenames in os.walk(fp_scan_folder):
                for fn in filenames:
                    fp = os.path.join(root, fn)
                    if os.path.isfile(fp):
                        files.append(fp)
            if len(files) == 0:
                return False, 0
        except Exception:
            return False, 0

        match_count = 0
        if compiled_ready and compiled_rules is not None:
            for f in files:
                matches = yara_scan_file_with_rules_py(compiled_rules, f)
                if rule_name in matches:
                    match_count += 1
        elif yara_cli_available:
            for f in files:
                matches = yara_scan_file_with_cli(strYARApath, f)
                if rule_name in matches:
                    match_count += 1
        else:
            return False, 0

        # FP rule if it matched ANY file
        return match_count > 0, match_count

    for strRuleLine in lstRuleFile + ["\nENDRULE\n"]:
        stripped = strRuleLine.strip()
        if stripped.startswith("rule ") or stripped.startswith("private rule ") or stripped == "ENDRULE":
            if current_rule_name:
                key = "\n".join([s.strip() for s in current_strings]) + "\n" + "\n".join([c.strip() for c in current_condition])

                is_fp = False
                scan_match_count = 0
                if fp_scan_folder:
                    is_fp, scan_match_count = fp_by_scanning_folder(current_rule_name)

                if key in dictRuleKey:
                    strLogOut += f"Duplicate rule {current_rule_name} in {strYARApath}\n"
                    boolOverwrite = True
                else:
                    if is_fp and remove_false_positives:
                        strLogOut += f"Removed false-positive rule {current_rule_name} from {strYARApath} (matched {scan_match_count} files in {fp_scan_folder})\n"
                        boolOverwrite = True
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

    strYARAout = "".join(pre_rule_lines)
    for rule in processed_rules:
        strYARAout += "".join(rule["lines"])

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
# Main
# --------------------------
boolRemoveFalsePositives = False
boolRecurse = False
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
if opts.YARA_Index_Path:
  indexPath = opts.YARA_Index_Path
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

fp_scan_folder = getattr(opts, "FP_Scan_Folder", None)

yara_py_available = yara_available_python()
yara_cli_available = bool(which('yara') or which('yara64') or which('yara.exe') or which('yara64.exe'))

if fp_scan_folder and not (yara_py_available or yara_cli_available):
    print("Warning: FP scanning folder requested but neither yara-python nor yara CLI found. FP-by-scan will be skipped.")
    logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), "Warning: FP scanning skipped (no yara available)\n", False, "a")

logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), "Started " + str(datetime.datetime.now()) + "\n", False, "a")

if boolRecurse == True:
  parentDir = fast_scandir(strYARADirectory)
  parentDir.append(strYARADirectory)
  parentDir.sort()
else:
  parentDir = [strYARADirectory]

for scanDirs in parentDir:
  for i in os.listdir(scanDirs):
    if i.endswith(".yar") or i.endswith(".yara"):
      if opts.YARA_File_Path != '' and folderMatch != '':
        if not scanDirs.endswith(folderMatch):
          continue
      if indexPath == "":
        file_path = os.path.join(scanDirs, i)
        try:
            with open(file_path, encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                ProcessRule(lines,
                            file_path,
                            outputPath,
                            remove_false_positives=boolRemoveFalsePositives,
                            fp_scan_folder=fp_scan_folder,
                            yara_py_available=yara_py_available,
                            yara_cli_available=yara_cli_available)
        except Exception as e:
            logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), f"ERROR reading {file_path}: {e}\n", False, "a")
      else:
        if folderMatch != "" and not scanDirs.endswith(folderMatch):
          continue
        createIndexFile(boolNewIndex, indexPath,  os.path.join(scanDirs, i), baseDirectory)
        boolNewIndex = False
    else:
        continue
logToFile(os.path.join(strCurrentDirectory, "duplicate.log"), "Completed " + str(datetime.datetime.now()) + "\n", False, "a")
