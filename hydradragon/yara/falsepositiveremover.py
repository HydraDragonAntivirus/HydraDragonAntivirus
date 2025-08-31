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

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Find duplicate YARA rules in a directory")
    parser.add_option("-r", "--remove", help="Remove duplicate rules", action="store_true")
    parser.add_option("-d", "--directory", action="store", default=None, dest="YARA_Directory_Path",
                      help="Folder path to directory containing YARA files")
    parser.add_option("-c", "--consolidate", action="store", default=None, dest="YARA_File_Path",
                      help="File path for consolidated YARA file")
    parser.add_option("-m", "--modify", help="Modify the file to rename duplicate rules", action="store_true")
    parser.add_option("-i", "--index", action="store", default=None, dest="YARA_Index_Path",
                      help="Create an index of YARA files") 
    parser.add_option("-t", "--type", action="store", default=None, dest="YARA_Index_Type",
                      help="Index YARA files based on parent folder match.") 
    parser.add_option("-b", "--BaseDirectory", action="store", default=None, dest="Base_Folder_Path",
                      help="Base folder to mark as current directory ./") 
    parser.add_option("-s", "--subdirectories", help="Recurse into subdirectories", action="store_true")
    parser.add_option("-v", "--verboselog", help="log all rules and the associated file", action="store_true")
    return parser

def ProcessRule(lstRuleFile, strYARApath, strOutPath):
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

    # Dictionary to store unique rules based on strings + condition
    dictRuleKey = {}
    processed_rules = []

    for strRuleLine in lstRuleFile + ["\nENDRULE\n"]:
        stripped = strRuleLine.strip()
        if stripped.startswith("rule ") or stripped.startswith("private rule ") or stripped == "ENDRULE":
            if current_rule_name:
                # Build a key using strings + condition
                key = "\n".join([s.strip() for s in current_strings]) + "\n" + "\n".join([c.strip() for c in current_condition])

                if key in dictRuleKey:
                    # Duplicate detected: merge only hash values but DO NOT alter comments
                    idx = dictRuleKey[key]["index"]
                    existing_rule = processed_rules[idx]

                    # We'll operate on existing_rule["lines"] preserving all non-hash meta lines and comments
                    existing_lines = existing_rule["lines"]

                    # Find meta: section indices (if present)
                    meta_start = None
                    meta_end = None
                    for j, line in enumerate(existing_lines):
                        if line.strip().startswith("meta:") or line.strip().startswith("metadata:"):
                            meta_start = j
                            break
                    if meta_start is not None:
                        # find end of meta section (next top-level section like 'strings:' or 'condition:')
                        meta_end = meta_start + 1
                        while meta_end < len(existing_lines):
                            s = existing_lines[meta_end].strip()
                            # stop if another section header encountered (e.g., strings:, condition:)
                            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*:', s) and not s.lower().startswith("meta"):
                                break
                            meta_end += 1

                        # Collect existing hash values and preserve all other meta lines and comments
                        existing_hashes = []
                        meta_segment = existing_lines[meta_start+1:meta_end]
                        preserved_meta_lines = []
                        for mline in meta_segment:
                            if re.match(r'^\s*hash\d*\s*=\s*"([^"]+)"', mline):
                                match = re.match(r'^\s*hash\d*\s*=\s*"([^"]+)"', mline)
                                if match:
                                    existing_hashes.append(match.group(1))
                                # skip original hash lines (we'll rebuild hashes in canonical order)
                                continue
                            else:
                                preserved_meta_lines.append(mline)

                        # Extract new hash values from current rule metadata without touching comments
                        for line in current_metadata:
                            if line.strip().startswith("hash"):
                                match = re.match(r'hash\d*\s*=\s*"([^"]+)"', line.strip())
                                if match:
                                    val = match.group(1)
                                    if val not in existing_hashes:
                                        existing_hashes.append(val)

                        # Build canonical hash lines using indentation style from preserved_meta_lines or default
                        if preserved_meta_lines:
                            # infer indent from first preserved meta line
                            indent_match = re.match(r'^(\s*)', preserved_meta_lines[0])
                            indent = indent_match.group(1) if indent_match else "      "
                        else:
                            # infer indent from the 'meta:' line itself if possible
                            indent_match = re.match(r'^(\s*)', existing_lines[meta_start+1]) if (meta_start+1 < len(existing_lines)) else None
                            indent = indent_match.group(1) if indent_match else "      "

                        rebuilt_hash_lines = []
                        for i, hval in enumerate(existing_hashes, 1):
                            rebuilt_hash_lines.append(f'{indent}hash{i} = "{hval}"\n')

                        # Reconstruct the meta section: meta: + preserved_meta_lines + rebuilt_hash_lines
                        new_meta_section = [existing_lines[meta_start]] + preserved_meta_lines + rebuilt_hash_lines

                        # Rebuild existing_lines replacing the old meta segment
                        existing_lines = existing_lines[:meta_start] + new_meta_section + existing_lines[meta_end:]
                        # Assign back
                        existing_rule["lines"] = existing_lines
                        strLogOut += f"Detected duplicate rule {current_rule_name} in {strYARApath}, merged hashes into {existing_rule['name']}\n"
                        boolOverwrite = True
                    else:
                        # No meta: section in existing rule; append a meta: block before strings: or condition:
                        # We'll try to find insertion point (before 'strings:' or 'condition:'), otherwise append to end of rule lines
                        insertion_idx = len(existing_lines)
                        for j, line in enumerate(existing_lines):
                            if line.strip().startswith("strings:") or line.strip().startswith("condition:"):
                                insertion_idx = j
                                break

                        # collect existing hashes (none) and new ones from current_metadata
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
                    # First occurrence: store rule
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

    # Write consolidated file
    if strOutPath != strYARApath:
        strYARAout += "\n"
        logToFile(strOutPath, strYARAout, False, "a")
    elif boolOverwrite:
        logToFile(strYARApath, strYARAout, True, "w")

    if strLogOut:
        strLogOut = "-------------\n" + strLogOut
        logToFile(strCurrentDirectory + "/duplicate.log", strLogOut, False, "a")

def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode):
    with open(strfilePathOut, strWriteMode, encoding='utf-8', errors='ignore') as target:
      if boolDeleteFile == True:
        target.truncate()
      target.write(strDataToLog)


def createIndexFile(boolNew, strFilePath, yaraPath, baseDir): # if index creation is not working on Windows check that you are escaping backslashes
  includePath = ""
  if boolNew == True:
    logToFile(strFilePath, "/*\n", False, "a")
    logToFile(strFilePath, "Generated by YARA_Rules_Util\n", False, "a")
    logToFile(strFilePath, "On " + str(datetime.date.today()) + "\n", False, "a")
    logToFile(strFilePath, "*/\n", False, "a")
  if "\\" in yaraPath or "/" in yaraPath: #windows or nix directory
    if "\\" in yaraPath:
      splitChar = "\\"
    else:
      splitChar = "/"
    arrayPath = yaraPath.split(splitChar) #need to determine the relative path between strFilePath and yaraPath. If different then use full file path. If same then truncate appropriatly
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

def fast_scandir(dirname): #https://stackoverflow.com/questions/973473/getting-a-list-of-all-subdirectories-in-the-current-directory/38245063
    subfolders= [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders

boolRemoveDuplicate = False
boolRename = False
boolRecurse = False
boolLogging = False
folderMatch = ""
indexPath = ""
outputPath = ""
baseDirectory = ""
dictExclude = {"deprecated", "index.yar", "_index", "index_"}
strCurrentDirectory = os.getcwd()
strYARADirectory = os.getcwd()
parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if opts.remove:
  boolRemoveDuplicate = True
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
if opts.modify:
  boolRename = True
if opts.YARA_File_Path:
  outputPath = opts.YARA_File_Path
dictRuleName = dict()
dictRuleKey = dict()

print (strYARADirectory)
logToFile(strCurrentDirectory + "\\duplicate.log","Started " + str(datetime.datetime.now()) + "\n", False, "a")

if boolRecurse == True:
  parentDir = fast_scandir(strYARADirectory)
  parentDir.append(strYARADirectory)
  parentDir.sort()
else:
  parentDir = {strYARADirectory}
print(parentDir)
for scanDirs in parentDir:
  for i in os.listdir(scanDirs):
    if i.endswith(".yar") or i.endswith(".yara"): 
      if opts.YARA_File_Path != '' and folderMatch != '': #File path for consolidated YARA file and folderMatch file type both provided  
        if not scanDirs.endswith(folderMatch): # Not the file type specified so move to next file
          continue
      if indexPath == "":
        print (i)
        with open(scanDirs + '/' + i, encoding='utf-8', errors='ignore') as f:
          lines = f.readlines()
          ProcessRule(lines, scanDirs + '/' + i, outputPath)
      else: #create index
        # previously we excluded certain files via dictExclude; that filter has been removed
        if folderMatch != "" and not scanDirs.endswith(folderMatch):
          # still respect folderMatch for indexing
          continue
        createIndexFile(boolNewIndex, indexPath,  scanDirs + '/' + i, baseDirectory)
        boolNewIndex = False
        #print("indexing file: " +  scanDirs + '/' + i)
    else:
        continue
logToFile(strCurrentDirectory + "/duplicate.log","Completed " + str(datetime.datetime.now()) + "\n", False, "a")
