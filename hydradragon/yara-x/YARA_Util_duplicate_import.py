#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This script identifies and removes duplicate import statements from YARA files contained within a directory.
# For each YARA file, the FIRST occurrence of every unique import (e.g. import "hash") is kept;
# all subsequent duplicate occurrences of that same import are removed.
# Removed import lines are logged to duplicate.log in the current directory.
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
import re
from optparse import OptionParser
import sys
import datetime


# Matches a YARA import statement, capturing the module name.
# Examples: import "pe"  /  import "hash"  /    import   "elf"
IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"\s*$')


def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Remove duplicate import statements from YARA files in a directory")
    parser.add_option("-r", "--remove", help="Remove duplicate import statements (overwrite originals)", action="store_true")
    parser.add_option("-d", "--directory", action="store", default=None, dest="YARA_Directory_Path", help="Folder path to directory containing YARA files")
    parser.add_option("-c", "--consolidate", action="store", default=None, dest="YARA_File_Path", help="File path for consolidated YARA file")
    parser.add_option("-b", "--BaseDirectory", action="store", default=None, dest="Base_Folder_Path", help="Base folder to mark as current directory ./")
    parser.add_option("-s", "--subdirectories", help="Recurse into subdirectories", action="store_true")
    parser.add_option("-v", "--verboselog", help="log all imports and the associated file", action="store_true")
    # output directory option
    parser.add_option("-o", "--output", action="store", default=None, dest="YARA_Output_Dir", help="Output directory for cleaned YARA files (copies processed files here instead of overwriting originals)")
    return parser


def ProcessImports(lstRuleFile, strYARApath, strOutPath, output_dir=None):
    """Keep the first occurrence of each unique import in the file; drop later duplicates."""
    strYARAout = ""
    strLogOut = ""
    boolOverwrite = False
    seenImports = set()  # module names already seen in THIS file

    # Determine final output path
    if output_dir:
        filename = os.path.basename(strYARApath)
        effective_out_path = os.path.join(output_dir, filename)
    elif strOutPath != "":
        effective_out_path = strOutPath
    else:
        effective_out_path = strYARApath

    for strRuleLine in lstRuleFile:
        match = IMPORT_RE.match(strRuleLine)
        if match:
            moduleName = match.group(1)
            if boolLogging:
                logToFile(strCurrentDirectory + "/all_imports.csv", moduleName + "," + strYARApath + "\n", False, "a")
            if moduleName in seenImports:
                # Duplicate import within this file -> remove it
                strLogOut += 'Removed duplicate import "' + moduleName + '" from ' + strYARApath + "\n"
                print(f'  [-] Removing duplicate import "{moduleName}"')
                boolOverwrite = True
                continue  # skip the line (do not append to output)
            else:
                # First time seeing this import -> keep it
                seenImports.add(moduleName)
                print(f'  [+] import "{moduleName}"')
                strYARAout += strRuleLine
        else:
            # Not an import line -> always keep
            strYARAout += strRuleLine

    # Write output
    if output_dir:
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


def fast_scandir(dirname):
    subfolders = [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders


# --- Globals ---
boolRecurse = False
boolLogging = False
outputPath = ""
baseDirectory = ""
outputDir = ""
dictExclude = {"deprecated", "index.yar", "_index", "index_"}
strCurrentDirectory = os.getcwd()
strYARADirectory = os.getcwd()

parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])

if opts.subdirectories:
    boolRecurse = True
    print("Recursing subdirectories")
if opts.verboselog:
    boolLogging = True
if opts.Base_Folder_Path:
    baseDirectory = opts.Base_Folder_Path
if opts.YARA_Directory_Path:
    strYARADirectory = opts.YARA_Directory_Path
else:
    print("Missing required parameter: -d <directory>")
    exit()
if opts.YARA_File_Path:
    outputPath = opts.YARA_File_Path

# output directory
if opts.YARA_Output_Dir:
    outputDir = opts.YARA_Output_Dir
    os.makedirs(outputDir, exist_ok=True)
    print(f"[*] Output directory: {outputDir}")

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
            print(i)
            with open(scanDirs + "/" + i, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                ProcessImports(lines, scanDirs + "/" + i, outputPath, outputDir if outputDir else None)
        else:
            continue

logToFile(strCurrentDirectory + "/duplicate.log", "Completed " + str(datetime.datetime.now()) + "\n", False, "a")
print("[*] Done. See duplicate.log for details.")
