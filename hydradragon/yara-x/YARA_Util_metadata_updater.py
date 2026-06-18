#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This script can identify and remove duplicate rules (based on rule name) from YARA files contained within a directory.
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
    parser.add_option("", "--strip-meta", help="Remove metadata blocks from YARA rules", action="store_true")
    parser.add_option("", "--strip-comments", help="Remove full-line comments only (keeps inline comments)", action="store_true")
    parser.add_option("", "--strip-blank", help="Remove empty and whitespace-only lines", action="store_true")
    parser.add_option("-O", "--optimize", help="Strip meta + comments + blank lines (smallest readable form)", action="store_true")
    parser.add_option("", "--perf", help="Check YARA rules for performance anti-patterns", action="store_true")
    return parser


def check_performance(lines, filepath):
    import re
    warnings = []
    lineno = 0
    in_block_comment = False
    for line in lines:
        lineno += 1
        stripped = line.strip()
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped[2:]:
                in_block_comment = True
            continue
        if stripped.startswith("//"):
            continue
        if not stripped:
            continue

        s = stripped.lower()

        # pe.is_pe
        if "pe.is_pe" in s:
            warnings.append((lineno, "pe.is_pe  → use uint16(0) == 0x5A4D instead (avoids full PE parse)"))

        # import "magic"
        if 'import "magic"' in s:
            warnings.append((lineno, 'import "magic"  → slow, unavailable on Windows; use uint32be(0) == 0x47494638 etc.'))

        # import "pe" hint (only if not needed for deeper inspection)
        if 'import "pe"' in s:
            warnings.append((lineno, 'import "pe"  → use uint16(0) == 0x5A4D for PE detection unless you need sections/directories'))

        # nocase on plain strings
        if "nocase" in s and ('"' in s or "'" in s):
            warnings.append((lineno, "nocase  → generates atoms for every case variant; use explicit case or regex [Aa] instead if only 1-2 letters vary"))

        # math.entropy
        if "math.entropy" in s:
            warnings.append((lineno, "math.entropy  → expensive; place after cheap filesize/uint checks in condition"))

        # for all i in (1..filesize)
        if "for all i in (1..filesize)" in s or "for any i in (1..filesize)" in s:
            warnings.append((lineno, "loop over filesize  → can iterate millions of times; add filesize < X guard"))

        # {00 00 00 00}
        if "{00 00 00 00}" in s or "{00 00 00 00" in s:
            warnings.append((lineno, "{00 00 00 00}  → too common atom, causes too many matches"))

        # .* or .+ in regex strings
        if re.search(r'/[^"]*\.[\*\+]', stripped) and not stripped.startswith("//"):
            warnings.append((lineno, ".* or .+ in regex  → greedy; use bounded quantifier like .{1,30} instead"))

        # alternation in hex
        if re.search(r'\(\s*(?:[0-9a-f]{2}\s*\|)+\s*[0-9a-f]{2}\s*\)', stripped, re.IGNORECASE):
            warnings.append((lineno, "alternation in hex  → split into separate strings for better atom selection"))

        # metadata with many lines (bloat)
        if stripped == "meta:":
            meta_count = 0
            end = min(lineno + 50, len(lines) + 1)
            for j in range(lineno, end):
                t = lines[j - 1].strip()
                if t in ("strings:", "condition:", "}"):
                    break
                if t and not t.startswith("//"):
                    meta_count += 1
            if meta_count > 20:
                warnings.append((lineno, f"large metadata block ({meta_count} lines)  → loaded into RAM for every scan; consider stripping with --strip-meta"))

    if warnings:
        print(f"\n[PERF] {filepath}")
        for ln, msg in warnings:
            print(f"  L{ln}: {msg}")


def ProcessRule(lstRuleFile, strYARApath, strOutPath):
    strYARAout = ""
    strLogOut = ""
    boolExcludeLine = False
    boolOverwrite = False
    boolInMeta = False
    boolInBlockComment = False
    if strOutPath == "":
        strOutPath = strYARApath
    for strRuleLine in lstRuleFile:
        if boolStripMeta:
            strTrimmed = strRuleLine.strip()
            if strTrimmed == "meta:":
                boolInMeta = True
                continue
            if boolInMeta:
                if strTrimmed.startswith("strings:") or strTrimmed.startswith("condition:") or strTrimmed == "}" or strTrimmed.startswith("}"):
                    boolInMeta = False
                else:
                    continue
        if boolStripComments:
            strTrimmed = strRuleLine.strip()
            if boolInBlockComment:
                if "*/" in strTrimmed:
                    boolInBlockComment = False
                    afterIdx = strTrimmed.index("*/") + 2
                    if strTrimmed[afterIdx:].strip():
                        pass
                    else:
                        continue
                else:
                    continue
            elif strTrimmed.startswith("//"):
                continue
            elif strTrimmed.startswith("/*"):
                if "*/" in strTrimmed[2:]:
                    endIdx = strTrimmed.index("*/", 2) + 2
                    if strTrimmed[endIdx:].strip():
                        pass
                    else:
                        continue
                else:
                    boolInBlockComment = True
                    continue
        if boolStripBlank:
            if not strRuleLine.strip():
                continue
        strRuleOut = strRuleLine
        nameDepth = 0
        if strRuleLine[:5] == "rule ":
            nameDepth = 5
        elif strRuleLine[:13] == "private rule ":
            nameDepth = 13
        if nameDepth != 0:
            strRuleName = strRuleLine[-(len(strRuleLine) - nameDepth) :]
            strRuleName = strRuleName[: len(strRuleName) - 1]
            if strRuleName[-1:] == "\r":
                strRuleName = strRuleName[:-1]
            if strRuleName[-1:] == "{":
                strRuleName = strRuleName[:-1]
            if strRuleName[-1:] == " ":
                while strRuleName[-1:] == " ":
                    strRuleName = strRuleName[:-1]
            print(strRuleName)
            if boolLogging == True:
                logToFile(strCurrentDirectory + "/all_rules.csv", strRuleName + "," + strYARApath + "\n", False, "a")
            if strRuleName in dictRuleName:
                # print "duplicate rule in file " + strYARApath + " : " + strRuleName
                strLogOut = strLogOut + "Duplicate rule " + "\n" + strRuleName + " in " + dictRuleName[strRuleName] + "\n" + strRuleName + " in " + strYARApath + "\n"
                if boolRename == False:
                    boolExcludeLine = True

                    if boolRemoveDuplicate == True:
                        boolOverwrite = True
                        strLogOut = strLogOut + "Removed rule " + strRuleName + " from " + strYARApath + "\n"
                else:
                    intCount = 1
                    while strRuleName + "_" + str(intCount) in dictRuleName:
                        intCount += 1
                    strRuleOut = str.replace(strRuleOut, strRuleName, strRuleName + "_" + str(intCount))
                    strLogOut = strLogOut + "Renamed " + strRuleName + " to " + strRuleName + "_" + str(intCount) + " from " + strYARApath + "\n"
                    strYARAout = strYARAout + strRuleOut
                    boolOverwrite = True
            else:
                dictRuleName[strRuleName] = strYARApath
                strYARAout = strYARAout + strRuleOut
                boolExcludeLine = False
        elif boolExcludeLine == False:
            strYARAout = strYARAout + strRuleLine
    if strOutPath != strYARApath:
        strYARAout = strYARAout + "\n"  # extra new line to separate rules in combined file
        logToFile(strOutPath, strYARAout, False, "a")
    elif boolOverwrite == True or boolStripMeta == True or boolStripComments == True or boolStripBlank == True:
        logToFile(strYARApath, strYARAout, True, "w")
    if len(strLogOut) > 1:
        strLogOut = "-------------" + "\n" + strLogOut
    logToFile(strCurrentDirectory + "/duplicate.log", strLogOut, False, "a")


def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode):
    with open(strfilePathOut, strWriteMode, encoding="utf-8", errors="ignore") as target:
        if boolDeleteFile == True:
            target.truncate()
        target.write(strDataToLog)


def createIndexFile(boolNew, strFilePath, yaraPath, baseDir):  # if index creation is not working on Windows check that you are escaping backslashes
    includePath = ""
    if boolNew == True:
        logToFile(strFilePath, "/*\n", False, "a")
        logToFile(strFilePath, "Generated by YARA_Rules_Util\n", False, "a")
        logToFile(strFilePath, "On " + str(datetime.date.today()) + "\n", False, "a")
        logToFile(strFilePath, "*/\n", False, "a")
    if "\\" in yaraPath or "/" in yaraPath:  # windows or nix directory
        if "\\" in yaraPath:
            splitChar = "\\"
        else:
            splitChar = "/"
        arrayPath = yaraPath.split(splitChar)  # need to determine the relative path between strFilePath and yaraPath. If different then use full file path. If same then truncate appropriatly
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


def fast_scandir(dirname):  # https://stackoverflow.com/questions/973473/getting-a-list-of-all-subdirectories-in-the-current-directory/38245063
    subfolders = [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders


boolRemoveDuplicate = False
boolRename = False
boolRecurse = False
boolLogging = False
boolStripMeta = False
boolStripComments = False
boolStripBlank = False
boolPerf = False
boolInMeta = False
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
    print("Missing required parameter argument")
    exit()
if opts.modify:
    boolRename = True
if opts.strip_meta:
    boolStripMeta = True
    print("stripping metadata blocks")
if opts.strip_comments:
    boolStripComments = True
    print("stripping full-line comments")
if opts.strip_blank:
    boolStripBlank = True
    print("stripping blank lines")
if opts.optimize:
    boolStripMeta = True
    boolStripComments = True
    boolStripBlank = True
    print("optimizing: stripping meta + comments + blank lines")
if opts.perf:
    boolPerf = True
    print("checking performance anti-patterns")
if opts.YARA_File_Path:
    outputPath = opts.YARA_File_Path
dictRuleName = dict()
print(strYARADirectory)
logToFile(strCurrentDirectory + "\\duplicate.log", "Started " + str(datetime.datetime.now()) + "\n", False, "a")

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
            if opts.YARA_File_Path != "" and folderMatch != "":  # File path for consolidated YARA file and folderMatch file type both provided
                if not scanDirs.endswith(folderMatch):  # Not the file type specified so move to next file
                    continue
            if indexPath == "":
                print(i)
                with open(scanDirs + "/" + i, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                if boolPerf:
                    check_performance(lines, scanDirs + "/" + i)
                ProcessRule(lines, scanDirs + "/" + i, outputPath)
            else:  # create index
                boolIndexExclude = False
                for excludeItem in dictExclude:
                    if excludeItem in scanDirs + "/" + i:
                        boolIndexExclude = True
                if folderMatch != "" and not scanDirs.endswith(folderMatch):
                    boolIndexExclude = True
                if boolIndexExclude == False:
                    createIndexFile(boolNewIndex, indexPath, scanDirs + "/" + i, baseDirectory)
                    boolNewIndex = False
                    # print("indexing file: " +  scanDirs + '/' + i)
        else:
            continue
logToFile(strCurrentDirectory + "/duplicate.log", "Completed " + str(datetime.datetime.now()) + "\n", False, "a")
