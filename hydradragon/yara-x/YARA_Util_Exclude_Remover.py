#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This script can identify and remove duplicate rules (based on rule name) from YARA files contained within a directory.
# It can also remove rules listed in an exclusion file (-x flag).
# Duplicate rules are logged to duplicate.log in the current directory.
# Rule names are echoed to standard out.
# Be sure to backup your data before using the remove option.

# Copyright (c) 2020 Ryan Boyle randomrhythm@rhythmengineering.com.
# All rights reserved.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
from optparse import OptionParser
import sys
import datetime


def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Find duplicate YARA rules in a directory")
    parser.add_option("-r", "--remove", help="Remove duplicate rules", action="store_true")
    parser.add_option("-d", "--directory", action="store", default=None, dest="YARA_Directory_Path", help="Folder path to directory containing YARA files")
    parser.add_option("-c", "--consolidate", action="store", default=None, dest="YARA_File_Path", help="File path for consolidated YARA file")
    parser.add_option("-m", "--modify", help="Modify the file to rename duplicate rules", action="store_true")
    parser.add_option("-i", "--index", action="store", default=None, dest="YARA_Index_Path", help="Create an index of YARA files")
    parser.add_option("-t", "--type", action="store", default=None, dest="YARA_Index_Type", help="Index YARA files based on parent folder match.")
    parser.add_option("-b", "--BaseDirectory", action="store", default=None, dest="Base_Folder_Path", help="Base folder to mark as current directory ./")
    parser.add_option("-s", "--subdirectories", help="Recurse into subdirectories", action="store_true")
    parser.add_option("-v", "--verboselog", help="log all rules and the associated file", action="store_true")
    # NEW: exclusion list option
    parser.add_option("-x", "--exclude", action="store", default=None, dest="YARA_Exclude_Path", help="Path to a text file containing rule names to exclude/remove (one per line)")
    # NEW: output directory option
    parser.add_option("-o", "--output", action="store", default=None, dest="YARA_Output_Dir", help="Output directory for cleaned YARA files (copies processed files here instead of overwriting originals)")
    return parser


def load_exclude_list(filepath):
    """Load rule names to exclude from a text file (one rule name per line)."""
    exclude_set = set()
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                rule_name = line.strip()
                if rule_name:
                    exclude_set.add(rule_name)
        print(f"[*] Loaded {len(exclude_set)} rule(s) from exclusion list: {filepath}")
    except Exception as e:
        print(f"[!] Failed to load exclusion list: {e}")
    return exclude_set


def ProcessRule(lstRuleFile, strYARApath, strOutPath, output_dir=None):
    strYARAout = ""
    strLogOut = ""
    boolExcludeLine = False
    boolOverwrite = False

    # Determine final output path
    if output_dir:
        # Mirror the file into output_dir, preserving filename
        filename = os.path.basename(strYARApath)
        effective_out_path = os.path.join(output_dir, filename)
    elif strOutPath != "":
        effective_out_path = strOutPath
    else:
        effective_out_path = strYARApath

    strCurrentRuleBlock = ""  # buffer the current rule block being parsed
    boolCapturingRemoved = False  # whether the current block is flagged for removal

    for strRuleLine in lstRuleFile:
        strRuleOut = strRuleLine
        nameDepth = 0
        boolPrivateRule = False
        if strRuleLine[:5] == "rule ":
            nameDepth = 5
        elif strRuleLine[:13] == "private rule ":
            nameDepth = 13
            boolPrivateRule = True
        if nameDepth != 0:
            strCurrentRuleBlock = strRuleLine
            boolCapturingRemoved = False

            strRuleName = strRuleLine[-(len(strRuleLine) - nameDepth):]
            strRuleName = strRuleName[:len(strRuleName) - 1]
            if strRuleName[-1:] == "\r":
                strRuleName = strRuleName[:-1]
            if strRuleName[-1:] == "{":
                strRuleName = strRuleName[:-1]
            if strRuleName[-1:] == " ":
                while strRuleName[-1:] == " ":
                    strRuleName = strRuleName[:-1]
            print(strRuleName)
            if boolLogging:
                logToFile(strCurrentDirectory + "/all_rules.csv", strRuleName + "," + strYARApath + "\n", False, "a")

            # Only exclude public rules — private rules don't trigger detections
            # so excluding them has no effect and would break rules that depend on them
            if strRuleName in setExcludeRules and not boolPrivateRule:
                strLogOut += "Excluded rule " + strRuleName + " from " + strYARApath + "\n"
                boolExcludeLine = True
                boolCapturingRemoved = True
                boolOverwrite = True
                print(f"  [-] Excluding rule: {strRuleName}")

            elif strRuleName in dictRuleName:
                strLogOut += ("Duplicate rule \n" + strRuleName + " in " + dictRuleName[strRuleName]
                              + "\n" + strRuleName + " in " + strYARApath + "\n")
                if boolRename is False:
                    boolExcludeLine = True
                    if boolRemoveDuplicate:
                        boolCapturingRemoved = True
                        boolOverwrite = True
                        strLogOut += "Removed rule " + strRuleName + " from " + strYARApath + "\n"
                else:
                    intCount = 1
                    while strRuleName + "_" + str(intCount) in dictRuleName:
                        intCount += 1
                    strRuleOut = str.replace(strRuleOut, strRuleName, strRuleName + "_" + str(intCount))
                    strLogOut += "Renamed " + strRuleName + " to " + strRuleName + "_" + str(intCount) + " from " + strYARApath + "\n"
                    strYARAout += strRuleOut
                    strCurrentRuleBlock = strRuleOut
                    boolOverwrite = True
            else:
                dictRuleName[strRuleName] = strYARApath
                strYARAout += strRuleOut
                boolExcludeLine = False

        elif boolExcludeLine is False:
            strYARAout += strRuleLine
            strCurrentRuleBlock += strRuleLine
        else:
            # Still inside a removed rule block — keep buffering it
            strCurrentRuleBlock += strRuleLine
            # Once we hit the closing brace, flush the whole block to removed_rules.yar
            if strRuleLine.strip() == "}":
                logToFile(strCurrentDirectory + "/removed_rules.yar", strCurrentRuleBlock + "\n", False, "a")
                strCurrentRuleBlock = ""
                boolCapturingRemoved = False

    # Write output
    if output_dir:
        # Always write to output dir (even if no changes — keeps full copy)
        os.makedirs(output_dir, exist_ok=True)
        logToFile(effective_out_path, strYARAout, True, "w")
    elif strOutPath != "" and strOutPath != strYARApath:
        strYARAout += "\n"  # extra new line to separate rules in combined file
        logToFile(effective_out_path, strYARAout, False, "a")
    elif boolOverwrite:
        logToFile(strYARApath, strYARAout, True, "w")

    if len(strLogOut) > 1:
        strLogOut = "-------------\n" + strLogOut
    logToFile(strCurrentDirectory + "/duplicate.log", strLogOut, False, "a")


def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode):
    with open(strfilePathOut, strWriteMode, encoding="utf-8", errors="ignore") as target:
        if boolDeleteFile:
            target.truncate()
        target.write(strDataToLog)


def createIndexFile(boolNew, strFilePath, yaraPath, baseDir):
    includePath = ""
    if boolNew:
        logToFile(strFilePath, "/*\n", False, "a")
        logToFile(strFilePath, "Generated by YARA_Rules_Util\n", False, "a")
        logToFile(strFilePath, "On " + str(datetime.date.today()) + "\n", False, "a")
        logToFile(strFilePath, "*/\n", False, "a")
    if "\\" in yaraPath or "/" in yaraPath:
        splitChar = "\\" if "\\" in yaraPath else "/"
        arrayPath = yaraPath.split(splitChar)
        for i in range(len(arrayPath), 0, -1):
            if includePath == "":
                includePath = arrayPath[i - 1]
            else:
                includePath = arrayPath[i - 1] + "/" + includePath
            if arrayPath[i - 2] == baseDir:
                break
        if i != 1:
            includePath = "./" + includePath
        else:
            includePath = yaraPath
        includeStatement = 'include "' + includePath + '"'
        logToFile(strFilePath, includeStatement + "\n", False, "a")


def fast_scandir(dirname):
    subfolders = [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders


# --- Globals ---
boolRemoveDuplicate = False
boolRename = False
boolRecurse = False
boolLogging = False
folderMatch = ""
indexPath = ""
outputPath = ""
baseDirectory = ""
outputDir = ""
setExcludeRules = set()   # NEW: holds excluded rule names
dictExclude = {"deprecated", "index.yar", "_index", "index_"}
strCurrentDirectory = os.getcwd()
strYARADirectory = os.getcwd()

parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])

if opts.remove:
    boolRemoveDuplicate = True
if opts.subdirectories:
    boolRecurse = True
    print("Recursing subdirectories")
if opts.verboselog:
    boolLogging = True
if opts.YARA_Index_Path:
    indexPath = opts.YARA_Index_Path
    print("Creating index file: " + indexPath)
    boolNewIndex = True
if opts.YARA_Index_Type:
    folderMatch = opts.YARA_Index_Type
if opts.Base_Folder_Path:
    baseDirectory = opts.Base_Folder_Path
if opts.YARA_Directory_Path:
    strYARADirectory = opts.YARA_Directory_Path
else:
    print("Missing required parameter: -d <directory>")
    exit()
if opts.modify:
    boolRename = True
if opts.YARA_File_Path:
    outputPath = opts.YARA_File_Path

# NEW: load exclusion list
if opts.YARA_Exclude_Path:
    setExcludeRules = load_exclude_list(opts.YARA_Exclude_Path)

# NEW: output directory
if opts.YARA_Output_Dir:
    outputDir = opts.YARA_Output_Dir
    os.makedirs(outputDir, exist_ok=True)
    print(f"[*] Output directory: {outputDir}")

dictRuleName = dict()
print(strYARADirectory)
logToFile(strCurrentDirectory + "/duplicate.log", "Started " + str(datetime.datetime.now()) + "\n", False, "a")

if boolRecurse:
    parentDir = fast_scandir(strYARADirectory)
    parentDir.append(strYARADirectory)
    parentDir.sort()
else:
    parentDir = {strYARADirectory}

print(parentDir)
for scanDirs in parentDir:
    for i in os.listdir(scanDirs):
        if i.endswith(".yar") or i.endswith(".yara"):
            if opts.YARA_File_Path != "" and folderMatch != "":
                if not scanDirs.endswith(folderMatch):
                    continue
            if indexPath == "":
                print(i)
                with open(scanDirs + "/" + i, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    ProcessRule(lines, scanDirs + "/" + i, outputPath, outputDir if outputDir else None)
            else:
                boolIndexExclude = False
                for excludeItem in dictExclude:
                    if excludeItem in scanDirs + "/" + i:
                        boolIndexExclude = True
                if folderMatch != "" and not scanDirs.endswith(folderMatch):
                    boolIndexExclude = True
                if not boolIndexExclude:
                    createIndexFile(boolNewIndex, indexPath, scanDirs + "/" + i, baseDirectory)
                    boolNewIndex = False
        else:
            continue

logToFile(strCurrentDirectory + "/duplicate.log", "Completed " + str(datetime.datetime.now()) + "\n", False, "a")
print("[*] Done. See duplicate.log for details.")
