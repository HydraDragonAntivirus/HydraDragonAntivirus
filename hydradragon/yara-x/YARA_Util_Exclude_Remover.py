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
    parser.add_option("-x", "--exclude", action="store", default="excluded_yara_x_rules.txt", dest="YARA_Exclude_Path", help="Path to a text file containing rule names to exclude/remove, one per line. Lines may be a bare rule name (SEH__vba) or 'rule SEH__vba' - both are accepted. Default: excluded_yara_x_rules.txt")
    # NEW: output directory option
    parser.add_option("-o", "--output", action="store", default=None, dest="YARA_Output_Dir", help="Output directory for cleaned YARA files (copies processed files here instead of overwriting originals)")
    # NEW: short scan mode
    parser.add_option("", "--short-scan", help="Non-destructive: scan all rule names in the directory and report which entries in the exclusion list were NOT found anywhere (stale/typo'd exclude entries). Removes/excludes nothing.", action="store_true")
    # NEW: short scan THEN remove, scoped only to confirmed matches
    parser.add_option("", "--short-scan-remove", help="Two-phase removal: first does a read-only pre-scan to find which exclusion-list entries actually exist in the scanned files (same check as --short-scan), then removes ONLY those confirmed matches. Stale/typo'd entries are skipped instead of being checked uselessly on every rule. Writes short_scan_remove_report.txt listing exactly what was targeted.", action="store_true")
    # NEW: content-based duplicate detection (ignores metadata, ignores rule name)
    parser.add_option("", "--dedupe-content", help="Detect rules that are duplicates by CONTENT (strings:/condition:, ignoring metadata and ignoring rule name) across all scanned files. Report-only unless combined with --remove-content-dupes. When duplicates are found, the copy with the richest (most) metadata is preferred as the one to keep.", action="store_true")
    parser.add_option("", "--remove-content-dupes", help="With --dedupe-content, actually remove the non-preferred duplicate copies (overwrites originals unless -o/--output is set). Removed rules are logged to removed_content_duplicates.yar.", action="store_true")
    return parser


def load_exclude_list(filepath):
    """Load rule names to exclude from a text file (one rule name per line).
    Accepts either a bare rule name ('SEH__vba') or a 'rule NAME' style line
    ('rule SEH__vba') - the 'rule ' prefix is stripped either way."""
    exclude_set = set()
    if not filepath or not os.path.isfile(filepath):
        print(f"[!] Exclusion list not found: {filepath} (continuing with no exclusions)")
        return exclude_set
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                rule_name = line.strip()
                if not rule_name:
                    continue
                if rule_name.lower().startswith("rule "):
                    rule_name = rule_name[5:].strip()
                if rule_name:
                    exclude_set.add(rule_name)
        print(f"[*] Loaded {len(exclude_set)} rule(s) from exclusion list: {filepath}")
    except Exception as e:
        print(f"[!] Failed to load exclusion list: {e}")
    return exclude_set


def extract_rule_names(lines):
    """Lightweight, read-only pass that returns the set of rule names
    (public and private) defined in a YARA file's lines. Used by
    --short-scan so it can report on rule presence without touching
    anything ProcessRule would otherwise modify or remove."""
    names = set()
    for line in lines:
        nameDepth = 0
        if line[:5] == "rule ":
            nameDepth = 5
        elif line[:13] == "private rule ":
            nameDepth = 13
        if nameDepth == 0:
            continue
        name = line[nameDepth:].rstrip("\n").rstrip("\r")
        if name.endswith("{"):
            name = name[:-1]
        name = name.strip()
        if name:
            names.add(name)
    return names


def extract_rule_blocks(lines):
    """Split a YARA file's lines into per-rule blocks. A block runs from its
    'rule '/'private rule ' declaration line up to (not including) the next
    such line, or end of file - this mirrors how the rest of this script
    already delimits rule boundaries (see ProcessRule above). Lines before
    the first rule (imports, includes) are not part of any block."""
    blocks = []
    current = None
    for line in lines:
        nameDepth = 0
        if line[:5] == "rule ":
            nameDepth = 5
        elif line[:13] == "private rule ":
            nameDepth = 13
        if nameDepth != 0:
            if current is not None:
                blocks.append(current)
            name = line[nameDepth:]
            name = name.split("{", 1)[0]
            name = name.split(":", 1)[0]  # drop rule tags, e.g. 'rule foo : tag1 tag2'
            name = name.strip().rstrip("\r")
            current = {"name": name, "lines": [line]}
            continue
        if current is not None:
            current["lines"].append(line)
    if current is not None:
        blocks.append(current)
    return blocks


def analyze_rule_block(block_lines):
    """Return (meta_richness, body_key) for a single rule block.

    meta_richness: count of non-blank, non-comment lines inside meta: - used
    to decide which copy to KEEP when two rules are functionally identical
    but carry different amounts of metadata. More metadata wins.

    body_key: the rule's strings:/condition:/everything-after content with
    metadata stripped out and whitespace normalized, used to detect 'same
    rule in everything but name and metadata'. Two rules with an identical
    body_key are content-duplicates."""
    in_meta = False
    meta_richness = 0
    capturing_body = False
    body_lines = []
    for line in block_lines:
        t = line.strip()
        if t == "meta:":
            in_meta = True
            continue
        if in_meta:
            if t in ("strings:", "condition:") or t == "}" or t.startswith("}"):
                in_meta = False
            else:
                if t and not t.startswith("//"):
                    meta_richness += 1
                continue
        if t in ("strings:", "condition:"):
            capturing_body = True
        if capturing_body:
            if t and not t.startswith("//") and not t.startswith("/*"):
                body_lines.append(t)
    body_key = "\n".join(body_lines)
    return meta_richness, body_key


def find_content_duplicates(file_paths):
    """Pass 1 (read-only): read every candidate file once, group rule blocks
    by normalized body. Returns (groups, file_lines_cache) where groups maps
    body_key -> list of {filepath, name, meta_richness} dicts, and
    file_lines_cache holds each file's lines so a later removal pass doesn't
    need to re-read disk."""
    groups = {}
    file_lines_cache = {}
    for fp in file_paths:
        with open(fp, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        file_lines_cache[fp] = lines
        for block in extract_rule_blocks(lines):
            meta_richness, body_key = analyze_rule_block(block["lines"])
            if not body_key:
                continue  # empty/malformed rule body, nothing to compare
            groups.setdefault(body_key, []).append({
                "filepath": fp, "name": block["name"], "meta_richness": meta_richness
            })
    return groups, file_lines_cache


def resolve_content_duplicates(groups):
    """For every body_key shared by 2+ rules, keep the entry with the richest
    metadata; the rest are marked for removal. Ties keep whichever entry was
    encountered first (stable scan order), so results are deterministic.
    Returns (remove_by_file, dup_report) where remove_by_file maps
    filepath -> set of rule names to drop, and dup_report is a list of
    (winner, losers) tuples for printing/logging."""
    remove_by_file = {}
    dup_report = []
    for body_key, entries in groups.items():
        if len(entries) < 2:
            continue
        winner = max(entries, key=lambda e: e["meta_richness"])
        losers = [e for e in entries if e is not winner]
        dup_report.append((winner, losers))
        for loser in losers:
            remove_by_file.setdefault(loser["filepath"], set()).add(loser["name"])
    return remove_by_file, dup_report


def remove_named_rule_blocks(lines, names_to_remove):
    """Stream through a file's lines, dropping any rule block whose declared
    name is in names_to_remove. Block boundaries are delimited the same way
    as extract_rule_blocks. Returns (kept_text, removed_text)."""
    kept = []
    removed = []
    excluding = False
    for line in lines:
        nameDepth = 0
        if line[:5] == "rule ":
            nameDepth = 5
        elif line[:13] == "private rule ":
            nameDepth = 13
        if nameDepth != 0:
            name = line[nameDepth:]
            name = name.split("{", 1)[0]
            name = name.split(":", 1)[0]
            name = name.strip().rstrip("\r")
            excluding = name in names_to_remove
        if excluding:
            removed.append(line)
        else:
            kept.append(line)
    return "".join(kept), "".join(removed)


def apply_content_dedupe_removal(remove_by_file, file_lines_cache, output_dir, current_dir):
    """Pass 2: actually rewrite files to drop the losing duplicate rule
    blocks. Removed rules are appended to removed_content_duplicates.yar."""
    removed_log_text = ""
    for fp, names_to_remove in remove_by_file.items():
        lines = file_lines_cache[fp]
        kept_text, removed_text = remove_named_rule_blocks(lines, names_to_remove)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            out_path = os.path.join(output_dir, os.path.basename(fp))
            logToFile(out_path, kept_text, True, "w")
        else:
            logToFile(fp, kept_text, True, "w")
        if removed_text:
            removed_log_text += removed_text + "\n"
        print(f"  [content-dedupe] {fp}: removed {len(names_to_remove)} duplicate rule(s): {', '.join(sorted(names_to_remove))}")
    if removed_log_text:
        logToFile(os.path.join(current_dir, "removed_content_duplicates.yar"), removed_log_text, False, "a")


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
boolShortScan = False
boolShortScanRemove = False
boolDedupeContent = False
boolRemoveContentDupes = False
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

# NEW: load exclusion list (defaults to excluded_yara_x_rules.txt)
setExcludeRules = load_exclude_list(opts.YARA_Exclude_Path)

# NEW: short scan mode
if opts.short_scan:
    boolShortScan = True
    print("[*] Short scan mode: read-only, will report exclusion entries that were never found")

# NEW: short-scan-remove (validate then remove only confirmed matches)
if opts.short_scan_remove:
    boolShortScanRemove = True
    print("[*] Short-scan-remove mode: validating exclusion list against actual content before removing")

# NEW: content-based duplicate detection
if opts.dedupe_content:
    boolDedupeContent = True
    print("[*] Content-dedupe mode: detecting rules identical in strings/condition (ignoring metadata)")
if opts.remove_content_dupes:
    boolRemoveContentDupes = True

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

if boolShortScanRemove:
    print("[*] Pre-scan: collecting all rule names to confirm which exclusion entries actually exist...")
    preScanFound = set()
    for scanDirs in parentDir:
        for i in os.listdir(scanDirs):
            if i.endswith(".yar") or i.endswith(".yara"):
                with open(scanDirs + "/" + i, encoding="utf-8", errors="ignore") as f:
                    preScanFound.update(extract_rule_names(f.readlines()))
    matchedForRemoval = setExcludeRules & preScanFound
    missingForRemoval = setExcludeRules - preScanFound
    print(f"[SHORT SCAN REMOVE] Exclusion list entries           : {len(setExcludeRules)}")
    print(f"[SHORT SCAN REMOVE] Confirmed present, will be removed: {len(matchedForRemoval)}")
    print(f"[SHORT SCAN REMOVE] Stale/typo'd, skipped untouched   : {len(missingForRemoval)}")
    reportLines = [
        "Short scan remove report - " + str(datetime.datetime.now()),
        f"Directory scanned: {strYARADirectory}",
        f"Exclusion list: {opts.YARA_Exclude_Path}",
        f"Total exclusion entries: {len(setExcludeRules)}",
        f"Confirmed present, targeted for removal: {len(matchedForRemoval)}",
    ]
    for name in sorted(matchedForRemoval):
        reportLines.append(f"  {name}")
    reportLines.append(f"Stale/typo'd, skipped untouched: {len(missingForRemoval)}")
    logToFile(strCurrentDirectory + "/short_scan_remove_report.txt", "\n".join(reportLines) + "\n", True, "w")
    print(f"[*] Pre-scan report written to {strCurrentDirectory}/short_scan_remove_report.txt")
    # Narrow the active exclusion set so the removal pass below only ever
    # acts on confirmed rule names - the 1765 stale entries are never
    # looked up per-rule during the real pass.
    setExcludeRules = matchedForRemoval

print(parentDir)
foundRuleNames = set()
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
                if boolShortScan:
                    foundRuleNames.update(extract_rule_names(lines))
                else:
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

if boolShortScan:
    missing = sorted(setExcludeRules - foundRuleNames)
    matched = setExcludeRules & foundRuleNames
    print(f"\n[SHORT SCAN] Exclusion list entries: {len(setExcludeRules)}")
    print(f"[SHORT SCAN] Found in scanned rules : {len(matched)}")
    print(f"[SHORT SCAN] Missing (stale/typo'd) : {len(missing)}")
    reportLines = [
        "Short scan report - " + str(datetime.datetime.now()),
        f"Directory scanned: {strYARADirectory}",
        f"Exclusion list: {opts.YARA_Exclude_Path}",
        f"Total exclusion entries: {len(setExcludeRules)}",
        f"Matched (will be removed by a normal run): {len(matched)}",
        f"Missing (not found in any scanned .yar/.yara file):",
    ]
    if missing:
        for name in missing:
            print(f"  [MISSING] {name}")
            reportLines.append(f"  {name}")
    else:
        print("  (none - every exclusion entry was found)")
        reportLines.append("  (none - every exclusion entry was found)")
    logToFile(strCurrentDirectory + "/short_scan_report.txt", "\n".join(reportLines) + "\n", True, "w")
    print(f"\n[*] Full report written to {strCurrentDirectory}/short_scan_report.txt")

if boolDedupeContent:
    print("\n[*] Scanning for content-duplicate rules (ignoring metadata)...")
    candidate_files = []
    for scanDirs in parentDir:
        for i in os.listdir(scanDirs):
            if i.endswith(".yar") or i.endswith(".yara"):
                candidate_files.append(scanDirs + "/" + i)

    groups, file_lines_cache = find_content_duplicates(candidate_files)
    remove_by_file, dup_report = resolve_content_duplicates(groups)

    reportLines = [
        "Content-dedupe report - " + str(datetime.datetime.now()),
        f"Directory scanned: {strYARADirectory}",
        f"Files scanned: {len(candidate_files)}",
        f"Duplicate group(s) found: {len(dup_report)}",
        f"Mode: {'REMOVED' if boolRemoveContentDupes else 'REPORT-ONLY (pass --remove-content-dupes to actually remove)'}",
        "",
    ]
    if not dup_report:
        print("[*] No content-duplicate rules found.")
        reportLines.append("(no content-duplicate rules found)")
    else:
        print(f"[*] Found {len(dup_report)} group(s) of content-duplicate rules:")
        for winner, losers in dup_report:
            keep_line = f"KEEP   {winner['name']}  ({winner['filepath']}, {winner['meta_richness']} meta line(s))"
            print(f"  {keep_line}")
            reportLines.append(keep_line)
            for loser in losers:
                tag = "REMOVED" if boolRemoveContentDupes else "DUPLICATE"
                loser_line = f"  {tag}  {loser['name']}  ({loser['filepath']}, {loser['meta_richness']} meta line(s))"
                print(f"  {loser_line}")
                reportLines.append(loser_line)
            reportLines.append("")

    logToFile(strCurrentDirectory + "/content_dedupe_report.txt", "\n".join(reportLines) + "\n", True, "w")
    print(f"[*] Full report written to {strCurrentDirectory}/content_dedupe_report.txt")

    if boolRemoveContentDupes:
        if remove_by_file:
            apply_content_dedupe_removal(remove_by_file, file_lines_cache, outputDir if outputDir else None, strCurrentDirectory)
            print(f"[*] Removed duplicates logged to {strCurrentDirectory}/removed_content_duplicates.yar")
        else:
            print("[*] Nothing to remove.")
    elif dup_report:
        print("[*] Report-only: nothing was modified. Re-run with --remove-content-dupes to remove the duplicates.")



logToFile(strCurrentDirectory + "/duplicate.log", "Completed " + str(datetime.datetime.now()) + "\n", False, "a")
print("[*] Done. See duplicate.log for details.")
