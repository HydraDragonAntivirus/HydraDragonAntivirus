#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yarGen
# A Rule Generator for YARA Rules
#
# Florian Roth

__version__ = "0.24.0"

import os
import sys
import io

# Re-wrap stdout/stderr so that file paths with surrogate characters (e.g.
# from os.walk on Windows with malformed filenames) are replaced with '?'
# instead of raising UnicodeEncodeError on every print statement.
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

import argparse
import math
import re
import traceback
import operator
import datetime
import time
import lief
import json
import codecs
import gzip
import urllib.request
import binascii
import base64
import shutil
import tempfile
from collections import Counter, defaultdict
from hashlib import sha256
import signal as signal_module
from lxml import etree
import nltk
import glob
import struct
import zipfile
import gc
import pefile


class _YoungGenerationGC:
    """pefile calls a FULL gc.collect() every time a PE object is closed (always on a
    parse error, i.e. for every malformed sample). A full collection walks every object
    in the process, and string_stats grows to tens of millions of objects on a large
    corpus, so each sample cost more than the one before: seconds per file after a few
    thousand files. Collecting the young generations still frees pefile's own cycles."""

    @staticmethod
    def collect(generation=2):
        return gc.collect(1)


pefile.gc = _YoungGenerationGC

# Ensure that necessary NLTK resources are available
nltk.download("punkt")
nltk.download("punkt_tab")
nltk.download("words")

from nltk.corpus import words
from nltk.tokenize import word_tokenize


# A simple filter function to consider only meaningful words (ignoring non-English or arbitrary symbols)
def filter_meaningful_words(word_list):
    # Only allow alphabetic, lowercase words
    return [word for word in word_list if word.isalpha() and word.islower()]


# Load NLTK word corpus
nltk_words = set(words.words())

_meaningful_cache = {}


def is_meaningful_string(string: str) -> bool:
    """--meaningful-words-only check (same rule as before): the string has a token of
    4+ characters that is an English word. Cached, because the same string was
    tokenized again for every file and every combination it appears in."""
    r = _meaningful_cache.get(string)
    if r is None:
        # Strip the wide-string marker so the content, not "UTF16LE:", is evaluated.
        target = string[8:] if string.startswith("UTF16LE:") else string
        r = any(word.lower() in nltk_words and len(word) >= 4 for word in word_tokenize(target))
        if len(_meaningful_cache) < 5_000_000:
            _meaningful_cache[string] = r
    return r

RELEVANT_EXTENSIONS = [
    ".asp",
    ".vbs",
    ".ps",
    ".ps1",
    ".tmp",
    ".bas",
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".crt",
    ".dll",
    ".exe",
    ".msc",
    ".scr",
    ".sys",
    ".vb",
    ".vbe",
    ".vbs",
    ".wsc",
    ".wsf",
    ".wsh",
    ".input",
    ".war",
    ".jsp",
    ".php",
    ".asp",
    ".aspx",
    ".psd1",
    ".psm1",
    ".py",
]

AI_COMMENT = """
The provided rule is a YARA rule, encompassing a wide range of suspicious strings. Kindly review the list and pinpoint the twenty strings that are most distinctive or appear most suited for a YARA rule focused on malware detection. Arrange them in descending order based on their level of suspicion. Then, swap out the current list of strings in the YARA rule with your chosen set and supply the revised rule.
---
"""

REPO_URLS = {
    "good-opcodes-part1.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part1.db",
    "good-opcodes-part2.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part2.db",
    "good-opcodes-part3.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part3.db",
    "good-opcodes-part4.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part4.db",
    "good-opcodes-part5.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part5.db",
    "good-opcodes-part6.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part6.db",
    "good-opcodes-part7.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part7.db",
    "good-opcodes-part8.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part8.db",
    "good-opcodes-part9.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part9.db",
    "good-strings-part1.db": "https://www.bsk-consulting.de/yargen/good-strings-part1.db",
    "good-strings-part2.db": "https://www.bsk-consulting.de/yargen/good-strings-part2.db",
    "good-strings-part3.db": "https://www.bsk-consulting.de/yargen/good-strings-part3.db",
    "good-strings-part4.db": "https://www.bsk-consulting.de/yargen/good-strings-part4.db",
    "good-strings-part5.db": "https://www.bsk-consulting.de/yargen/good-strings-part5.db",
    "good-strings-part6.db": "https://www.bsk-consulting.de/yargen/good-strings-part6.db",
    "good-strings-part7.db": "https://www.bsk-consulting.de/yargen/good-strings-part7.db",
    "good-strings-part8.db": "https://www.bsk-consulting.de/yargen/good-strings-part8.db",
    "good-strings-part9.db": "https://www.bsk-consulting.de/yargen/good-strings-part9.db",
    "good-exports-part1.db": "https://www.bsk-consulting.de/yargen/good-exports-part1.db",
    "good-exports-part2.db": "https://www.bsk-consulting.de/yargen/good-exports-part2.db",
    "good-exports-part3.db": "https://www.bsk-consulting.de/yargen/good-exports-part3.db",
    "good-exports-part4.db": "https://www.bsk-consulting.de/yargen/good-exports-part4.db",
    "good-exports-part5.db": "https://www.bsk-consulting.de/yargen/good-exports-part5.db",
    "good-exports-part6.db": "https://www.bsk-consulting.de/yargen/good-exports-part6.db",
    "good-exports-part7.db": "https://www.bsk-consulting.de/yargen/good-exports-part7.db",
    "good-exports-part8.db": "https://www.bsk-consulting.de/yargen/good-exports-part8.db",
    "good-exports-part9.db": "https://www.bsk-consulting.de/yargen/good-exports-part9.db",
    "good-imphashes-part1.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part1.db",
    "good-imphashes-part2.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part2.db",
    "good-imphashes-part3.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part3.db",
    "good-imphashes-part4.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part4.db",
    "good-imphashes-part5.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part5.db",
    "good-imphashes-part6.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part6.db",
    "good-imphashes-part7.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part7.db",
    "good-imphashes-part8.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part8.db",
    "good-imphashes-part9.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part9.db",
}

PE_STRINGS_FILE = "./3rdparty/strings.xml"

good_strings_db = Counter()
good_opcodes_db = Counter()
good_imphashes_db = Counter()
good_exports_db = Counter()

# Maximum length of a YARA rule identifier. Long names cause parse errors in
# some YARA builds; 64 characters is a safe, widely-compatible limit.
MAX_RULE_NAME_LEN = 64

KNOWN_IMPHASHES = {"a04dd9f5ee88d7774203e0a0cfa1b941": "PsExec", "2b8c9d9ab6fefc247adaf927e83dcea6": "RAR SFX variant"}

# Maximum byte length for a YARA rule description value (64 KB).
MAX_DESCRIPTION_BYTES = 64 * 1024  # 65 536 bytes


def truncate_description(desc: str, max_bytes: int = MAX_DESCRIPTION_BYTES) -> str:
    """Return *desc* truncated to *max_bytes* UTF-8 bytes.

    Truncation is performed on a word boundary when possible so the resulting
    string is still readable.  An ellipsis ("...") is appended to make it clear
    that the text was cut.
    """
    encoded = desc.encode("utf-8")
    if len(encoded) <= max_bytes:
        return desc
    # Reserve 3 bytes for the "..." suffix.
    truncated_bytes = encoded[: max_bytes - 3]
    truncated_str = truncated_bytes.decode("utf-8", errors="ignore")
    # Try to cut at the last word boundary.
    if " " in truncated_str:
        truncated_str = truncated_str.rsplit(" ", 1)[0]
    return truncated_str + "..."


def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def get_files(folder, notRecursive):
    # Not Recursive
    if notRecursive:
        for filename in os.listdir(folder):
            filePath = os.path.join(folder, filename)
            if os.path.isdir(filePath):
                continue
            yield filePath
    # Recursive
    else:
        for root, dirs, files in os.walk(folder, topdown=False):
            for name in files:
                filePath = os.path.join(root, name)
                yield filePath


def parse_sample_dir(dir, notRecursive=False, generateInfo=False, onlyRelevantExtensions=False):
    # Prepare dictionary
    string_stats = {}
    opcode_stats = {}
    file_info = {}
    known_sha256sums = set()

    for filePath in get_files(dir, notRecursive):
        try:
            print("[+] Processing %s ..." % filePath)

            # Get Extension
            extension = os.path.splitext(filePath)[1].lower()
            if extension not in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
                if args.debug:
                    print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
                continue

            # Info file check
            if os.path.basename(filePath) == os.path.basename(args.b) or os.path.basename(filePath) == os.path.basename(args.r):
                continue

            # Size Check
            size = 0
            try:
                size = os.stat(filePath).st_size
                if size > (args.fs * 1024 * 1024):
                    if args.debug:
                        print("[-] File is to big - Skipping file %s (use -fs to adjust this behaviour)" % (filePath))
                    continue
            except Exception:
                pass

            # Check and read file
            try:
                with open(filePath, "rb") as f:
                    fileData = f.read()
            except Exception:
                print("[-] Cannot read file - skipping %s" % filePath)
                continue

            # Skip duplicates BEFORE the expensive parts (strings, lief, pefile, icons)
            sha256sum = sha256(fileData).hexdigest()
            if sha256sum in known_sha256sums:
                print("[-] Skipping %s (duplicate of an already processed file)" % filePath)
                continue
            known_sha256sums.add(sha256sum)

            # Extract strings from file
            strings = extract_strings(fileData)

            # --excludegood / --meaningful-words-only: drop those strings right away.
            # filter_string_set() drops them later anyway; dropping them here keeps
            # millions of goodware strings out of memory, and makes the flags work for
            # the YAML output too (it is written from these strings directly).
            if args.excludegood or args.meaningful_words_only:
                strings = [
                    st for st in strings
                    if not (args.excludegood and st in good_strings_db)
                    and not (args.meaningful_words_only and not is_meaningful_string(st))
                ]

            # Extract opcodes from file
            opcodes = []
            if use_opcodes:
                print("[-] Extracting OpCodes: %s" % filePath)
                opcodes = extract_opcodes(fileData)

            # Add sha256 value
            if generateInfo:
                file_info[filePath] = {}
                file_info[filePath]["hash"] = sha256sum
                file_info[filePath]["imphash"], file_info[filePath]["exports"] = get_pe_info(fileData)
                file_info[filePath]["entropy"] = calculate_shannon_entropy(fileData)
                if fileData[:2] == b"MZ":
                    pe_imps, susp_imps, max_ent, is_pkd, pkd_secs, dist_secs, cap_dlls, exps = extract_pe_advanced(filePath, fileData)
                    file_info[filePath]["suspicious_imports"] = susp_imps
                    file_info[filePath]["max_section_entropy"] = max_ent
                    file_info[filePath]["is_packed"] = is_pkd
                    file_info[filePath]["packed_sections"] = pkd_secs
                    file_info[filePath]["distinctive_sections"] = dist_secs
                    file_info[filePath]["capability_dlls"] = cap_dlls
                    file_info[filePath]["exports"] = exps
                    file_info[filePath]["icons"] = extract_pe_icons(filePath, fileData)
                else:
                    file_info[filePath]["suspicious_imports"] = []
                    file_info[filePath]["max_section_entropy"] = 0.0
                    file_info[filePath]["is_packed"] = False
                    file_info[filePath]["packed_sections"] = []
                    file_info[filePath]["distinctive_sections"] = []
                    file_info[filePath]["capability_dlls"] = []
                    file_info[filePath]["exports"] = []
                    file_info[filePath]["icons"] = []
                file_info[filePath]["apk"] = extract_apk_metadata(filePath)
            else:
                file_info[filePath] = {}

            # Magic evaluation
            if not args.nomagic:
                file_info[filePath]["magic"] = binascii.hexlify(fileData[:2]).decode("ascii")
            else:
                file_info[filePath]["magic"] = ""

            # File Size
            file_info[filePath]["size"] = len(fileData)
            del fileData

            # Add stats for basename (needed for inverse rule generation)
            fileName = os.path.basename(filePath)
            folderName = os.path.basename(os.path.dirname(filePath))
            if fileName not in file_info:
                file_info[fileName] = {}
                file_info[fileName]["count"] = 0
                file_info[fileName]["hashes"] = []
                file_info[fileName]["folder_names"] = []
            file_info[fileName]["count"] += 1
            file_info[fileName]["hashes"].append(sha256sum)
            if folderName not in file_info[fileName]["folder_names"]:
                file_info[fileName]["folder_names"].append(folderName)

            # Add strings to statistics. extract_strings() returns every string once
            # per file and every path is processed once, so the path is appended
            # without the old "not in list" scan (that scan was quadratic: a string
            # found in 100k files was compared against up to 100k paths per file).
            for string in strings:
                st = string_stats.get(string)
                if st is None:
                    st = string_stats[string] = {"count": 0, "files": [], "files_basename": {}}
                st["count"] += 1
                fb = st["files_basename"]
                fb[fileName] = fb.get(fileName, 0) + 1
                st["files"].append(filePath)

            # Add opcodes to statistics (an opcode can repeat within a file)
            seen_ops = set()
            for opcode in opcodes:
                op = opcode_stats.get(opcode)
                if op is None:
                    op = opcode_stats[opcode] = {"count": 0, "files": [], "files_basename": {}}
                op["count"] += 1
                fb = op["files_basename"]
                fb[fileName] = fb.get(fileName, 0) + 1
                if opcode not in seen_ops:
                    seen_ops.add(opcode)
                    op["files"].append(filePath)

            if args.debug:
                print("[+] Processed " + filePath + " Size: " + str(size) + " Strings: " + str(len(string_stats)) + " OpCodes: " + str(len(opcode_stats)) + " ... ")

        except Exception:
            traceback.print_exc()
            print("[E] ERROR reading file: %s" % filePath)

    return string_stats, opcode_stats, file_info


def parse_good_dir(dir, notRecursive=False, onlyRelevantExtensions=True):
    # Prepare dictionary
    all_strings = Counter()
    all_opcodes = Counter()
    all_imphashes = Counter()
    all_exports = Counter()

    for filePath in get_files(dir, notRecursive):
        # Get Extension
        extension = os.path.splitext(filePath)[1].lower()
        if extension not in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
            if args.debug:
                print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
            continue

        # Size Check
        size = 0
        try:
            size = os.stat(filePath).st_size
            if size > (args.fs * 1024 * 1024):
                continue
        except Exception:
            pass

        # Check and read file
        try:
            with open(filePath, "rb") as f:
                fileData = f.read()
        except Exception:
            print("[-] Cannot read file - skipping %s" % filePath)

        # Extract strings from file
        strings = extract_strings(fileData)
        # Append to all strings
        all_strings.update(strings)

        # Extract Opcodes from file
        opcodes = []
        if use_opcodes:
            print("[-] Extracting OpCodes: %s" % filePath)
            opcodes = extract_opcodes(fileData)
            # Append to all opcodes
            all_opcodes.update(opcodes)

        # Imphash and Exports
        (imphash, exports) = get_pe_info(fileData)
        if imphash != "":
            all_imphashes.update([imphash])
        all_exports.update(exports)
        if args.debug:
            print("[+] Processed %s - %d strings %d opcodes %d exports and imphash %s" % (filePath, len(strings), len(opcodes), len(exports), imphash))

    # return it as a set (unique strings)
    return all_strings, all_opcodes, all_imphashes, all_exports


def extract_strings(fileData) -> list[str]:
    # String list
    cleaned_strings = []
    # Read file data
    try:
        # Read strings
        strings_full = re.findall(b"[\x1f-\x7e]{6,}", fileData)
        strings_limited = re.findall(b"[\x1f-\x7e]{6,%d}" % args.s, fileData)
        strings_hex = extract_hex_strings(fileData)
        strings = list(set(strings_full) | set(strings_limited) | set(strings_hex))
        wide_strings = [ws for ws in re.findall(b"(?:[\x1f-\x7e][\x00]){6,}", fileData)]

        # Post-process
        # WIDE (set for the membership test: "not in list" was quadratic on big files)
        seen = set(strings)
        for ws in wide_strings:
            # Decode UTF16 and prepend a marker (facilitates handling)
            wide_string = ("UTF16LE:%s" % ws.decode("utf-16")).encode("utf-8")
            if wide_string not in seen:
                seen.add(wide_string)
                strings.append(wide_string)
        for string in strings:
            # Escape strings
            if len(string) > 0:
                string = string.replace(b"\\", b"\\\\")
                string = string.replace(b'"', b'\\"')
            try:
                if isinstance(string, str):
                    cleaned_strings.append(string)
                else:
                    cleaned_strings.append(string.decode("utf-8"))
            except AttributeError:
                print(string)
                traceback.print_exc()

    except Exception:
        if args.debug:
            print(string)
            traceback.print_exc()
        pass

    return cleaned_strings


def extract_opcodes(fileData) -> list[str]:
    # Opcode list
    opcodes = []

    # Size-aware bounds: opcodes are great on short code but explode on long
    # code (thousands of 16-byte hex patterns = huge scan-time matching cost).
    # - Sections bigger than --opcode-max-mb are skipped entirely (strings
    #   carry those files instead).
    # - Smaller sections are scanned through an entrypoint-centered window so
    #   the most distinctive bytes are kept with bounded work.
    # - The emitted opcode list itself is capped as well.
    try:
        cap_mb = float(getattr(args, "opcode_max_mb", 4))
    except Exception:
        cap_mb = 4.0
    OPCODE_WINDOW_BYTES = 1024 * 1024
    MAX_OPCODE_PARTS = 4096

    try:
        # Read file data
        binary = lief.parse(fileData)
        ep = binary.entrypoint

        # Locate .text section
        text = None
        ep_offset = 0
        if isinstance(binary, lief.PE.Binary):
            for sec in binary.sections:
                if sec.virtual_address + binary.imagebase <= ep < sec.virtual_address + binary.imagebase + sec.virtual_size:
                    if args.debug:
                        print(f"EP is located at {sec.name} section")
                    content = sec.content.tobytes()
                    ep_offset = ep - (sec.virtual_address + binary.imagebase)
                    text = content
                    break
        elif isinstance(binary, lief.ELF.Binary):
            for sec in binary.sections:
                if sec.virtual_address <= ep < sec.virtual_address + sec.size:
                    if args.debug:
                        print(f"EP is located at {sec.name} section")
                    content = sec.content.tobytes()
                    ep_offset = ep - sec.virtual_address
                    text = content
                    break

        if text is not None:
            # 1. Skip code that is too long for opcodes (strings handle it).
            if cap_mb > 0 and len(text) > cap_mb * 1024 * 1024:
                if args.debug:
                    print(f"Skipping opcodes: EP section too long ({len(text)} bytes > {cap_mb} MB cap)")
                return opcodes
            # 2. Entrypoint-centered window on the remaining (short) code.
            if len(text) > OPCODE_WINDOW_BYTES:
                ep_offset = max(0, min(ep_offset, len(text)))
                start = ep_offset - OPCODE_WINDOW_BYTES // 2
                start = max(0, min(start, len(text) - OPCODE_WINDOW_BYTES))
                text = text[start:start + OPCODE_WINDOW_BYTES]
            # Split text into subs
            text_parts = re.split(b"[\x00]{3,}", text)
            # Now truncate and encode opcodes
            for text_part in text_parts:
                if len(opcodes) >= MAX_OPCODE_PARTS:
                    break
                if text_part == "" or len(text_part) < 8:
                    continue
                opcodes.append(binascii.hexlify(text_part[:16]).decode(encoding="ascii"))
    except Exception:
        if args.debug:
            traceback.print_exc()
        pass

    return opcodes


def get_pe_info(fileData: bytes) -> tuple[str, list[str]]:
    """
    Get different PE attributes and hashes by lief
    :param fileData:
    :return:
    """
    imphash = ""
    exports = []
    # Check for MZ header (speed improvement)
    if fileData[:2] != b"MZ":
        return imphash, exports
    try:
        if args.debug:
            print("Extracting PE information")
        binary: lief.PE.Binary = lief.parse(fileData)
        # Imphash
        imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
        # Exports (names)
        for exp in binary.get_export().entries:
            exp: lief.PE.ExportEntry
            exports.append(str(exp.name))
    except Exception:
        if args.debug:
            traceback.print_exc()
        pass

    return imphash, exports


SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext", "ResumeThread",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "URLDownloadToFileA", "URLDownloadToFileW", "HttpSendRequestA", "HttpSendRequestW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "RegSetValueExA", "RegSetValueExW", "CryptDecrypt", "CryptEncrypt",
    "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW"
}


def decode_dib_icon(data: bytes):
    """Decode Windows DIB icon payload into (width, rgba_bytes)."""
    if len(data) < 40:
        return None
    header_size = struct.unpack("<I", data[:4])[0]
    if header_size < 40 or len(data) < header_size:
        return None
    width = struct.unpack("<I", data[4:8])[0]
    raw_height = struct.unpack("<I", data[8:12])[0]
    depth = struct.unpack("<H", data[14:16])[0]
    if raw_height == 0 or raw_height % 2 != 0:
        return None
    height = raw_height // 2
    if not (16 <= width <= 256) or not (16 <= height <= 256):
        return None
    if depth not in (1, 4, 8, 16, 24, 32):
        return None
    offset = header_size
    palette = [0] * 256
    if depth in (1, 4, 8):
        entries = 1 << depth
        pal_bytes = entries * 4
        if len(data) < offset + pal_bytes:
            return None
        pal = data[offset : offset + pal_bytes]
        for i in range(entries):
            palette[i] = struct.unpack("<I", pal[i * 4 : (i + 1) * 4])[0]
        offset += pal_bytes

    row_bytes = ((width * depth + 31) // 32) * 4
    and_row_bytes = ((width + 31) // 32) * 4
    colour_bytes = row_bytes * height
    and_bytes = and_row_bytes * height
    if len(data) < offset + colour_bytes + and_bytes:
        return None
    body = data[offset : offset + colour_bytes + and_bytes]

    pixels = [0] * (width * height)
    for y in range(height):
        row = y * row_bytes
        for x in range(width):
            if depth in (1, 4, 8):
                bit = x * depth
                byte = body[row + bit // 8]
                shift = 8 - depth - (bit % 8)
                idx = (byte >> shift) & ((1 << depth) - 1)
                val = palette[idx] if idx < len(palette) else 0
            elif depth == 16:
                p = row + x * 2
                b0 = body[p]
                b1 = body[p + 1]
                b = (b0 & 0x1F) << 3
                g = (((b0 >> 5) | ((b1 & 0x03) << 3))) << 3
                r = (b1 & 0x7C) << 1
                val = b | (g << 8) | (r << 16) | 0xFF000000
            elif depth == 24:
                p = row + x * 3
                val = body[p] | (body[p + 1] << 8) | (body[p + 2] << 16) | 0xFF000000
            elif depth == 32:
                p = row + x * 4
                val = body[p] | (body[p + 1] << 8) | (body[p + 2] << 16) | (body[p + 3] << 24)
            else:
                val = 0
            pixels[(height - 1 - y) * width + x] = val

    rgba = bytearray(width * height * 4)
    for i, px in enumerate(pixels):
        rgba[i * 4] = px & 0xFF
        rgba[i * 4 + 1] = (px >> 8) & 0xFF
        rgba[i * 4 + 2] = (px >> 16) & 0xFF
        rgba[i * 4 + 3] = (px >> 24) & 0xFF
    return width, rgba


def compute_dhash_8x8(rgba: bytearray, side: int) -> str:
    """Compute 64-bit difference hash matching hydradragonsig rules/icon.rs."""
    LUMA = [0.299, 0.587, 0.114]
    n = side
    gray = [0.0] * (n * n)
    for i in range(n * n):
        gray[i] = LUMA[0] * rgba[i * 4] + LUMA[1] * rgba[i * 4 + 1] + LUMA[2] * rgba[i * 4 + 2]
    GRID = 9
    cells = [0.0] * (GRID * GRID)
    for cy in range(GRID):
        for cx in range(GRID):
            x0 = cx * n // GRID
            y0 = cy * n // GRID
            x1 = max((cx + 1) * n // GRID, x0 + 1)
            y1 = max((cy + 1) * n // GRID, y0 + 1)
            s = 0.0
            cnt = 0
            for y in range(y0, min(y1, n)):
                row_off = y * n
                for x in range(x0, min(x1, n)):
                    s += gray[row_off + x]
                    cnt += 1
            cells[cy * GRID + cx] = s / cnt if cnt > 0 else 0.0
    h = 0
    for y in range(GRID - 1):
        for x in range(GRID - 1):
            if cells[y * GRID + x] > cells[y * GRID + x + 1]:
                bit = 63 - (y * (GRID - 1) + x)
                h |= 1 << bit
    return f"{h:016x}"


def compute_phash_64_from_gray(gray: list[float], side: int) -> str:
    """Compute 64-bit DCT perceptual hash matching ClamAV / hydradragonsig fuzzy.rs."""
    try:
        import numpy as np
        import scipy.fftpack

        arr = np.array(gray, dtype=np.float32).reshape((side, side))
        row_idx = (np.linspace(0, side - 1, 32)).astype(int)
        col_idx = (np.linspace(0, side - 1, 32)).astype(int)
        grid32 = arr[np.ix_(row_idx, col_idx)]
        dct_col = scipy.fftpack.dct(grid32, axis=0, type=2, norm=None) * 2.0
        dct_2d = scipy.fftpack.dct(dct_col, axis=1, type=2, norm=None) * 2.0
        block = dct_2d[:8, :8].flatten()
        med = float(np.median(block))
        h = 0
        for i, val in enumerate(block):
            if val > med:
                h |= 1 << (63 - i)
        return f"{h:016x}"
    except Exception:
        return ""


def extract_pe_icons(file_path: str, file_data: bytes = None) -> list[tuple[str, str]]:
    """Extract (dhash_hex, phash_hex) for each icon in a PE file."""
    results = []
    try:
        pe = pefile.PE(data=file_data, fast_load=True) if file_data is not None else pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return results
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == pefile.RESOURCE_TYPE["RT_ICON"]:
                if hasattr(entry, "directory"):
                    for subentry in entry.directory.entries:
                        if hasattr(subentry, "directory"):
                            for data_entry in subentry.directory.entries:
                                rva = data_entry.data.struct.OffsetToData
                                size = data_entry.data.struct.Size
                                raw = pe.get_data(rva, size)
                                dec = decode_dib_icon(raw)
                                if dec:
                                    side, rgba = dec
                                    dh = compute_dhash_8x8(rgba, side)
                                    LUMA = [0.299, 0.587, 0.114]
                                    gray = [LUMA[0] * rgba[i * 4] + LUMA[1] * rgba[i * 4 + 1] + LUMA[2] * rgba[i * 4 + 2] for i in range(side * side)]
                                    ph = compute_phash_64_from_gray(gray, side)
                                    if dh and dh not in [r[0] for r in results]:
                                        results.append((dh, ph))
    except Exception:
        pass
    return results


MITRE_API_MAP = {
    # Process Injection
    "VirtualAlloc": ("T1055", "Process Injection", "Defense Evasion"),
    "VirtualAllocEx": ("T1055", "Process Injection", "Defense Evasion"),
    "VirtualProtect": ("T1055", "Process Injection", "Defense Evasion"),
    "VirtualProtectEx": ("T1055", "Process Injection", "Defense Evasion"),
    "WriteProcessMemory": ("T1055", "Process Injection", "Defense Evasion"),
    "ReadProcessMemory": ("T1055", "Process Injection", "Defense Evasion"),
    "CreateRemoteThread": ("T1055.002", "Process Injection: Portable Executable Injection", "Defense Evasion"),
    "NtCreateThreadEx": ("T1055.002", "Process Injection: Portable Executable Injection", "Defense Evasion"),
    "QueueUserAPC": ("T1055.004", "Process Injection: Asynchronous Procedure Call", "Defense Evasion"),
    "SetThreadContext": ("T1055.003", "Process Injection: Thread Execution Hijacking", "Defense Evasion"),
    # Persistence
    "RegSetValueExA": ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    "RegSetValueExW": ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    # Privilege Escalation / Token Manipulation
    "AdjustTokenPrivileges": ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    "LookupPrivilegeValueA": ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    "LookupPrivilegeValueW": ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    # Anti-Debugging
    "IsDebuggerPresent": ("T1497.001", "Virtualization/Sandbox Evasion: System Checks", "Defense Evasion"),
    "CheckRemoteDebuggerPresent": ("T1497.001", "Virtualization/Sandbox Evasion: System Checks", "Defense Evasion"),
    "NtQueryInformationProcess": ("T1497.001", "Virtualization/Sandbox Evasion: System Checks", "Defense Evasion"),
    # Ingress Tool Transfer / Command & Control
    "InternetOpenA": ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "InternetOpenUrlA": ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "URLDownloadToFileA": ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "URLDownloadToFileW": ("T1105", "Ingress Tool Transfer", "Command and Control"),
    # Encryption for Impact
    "CryptEncrypt": ("T1486", "Data Encrypted for Impact", "Impact"),
    "CryptDecrypt": ("T1486", "Data Encrypted for Impact", "Impact"),
}

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    # bytes.count runs in C; Counter(data) walked every byte in Python (seconds on a 50 MB file)
    total = len(data)
    ent = 0.0
    for count in (data.count(bytes((b,))) for b in range(256)):
        if count == 0:
            continue
        p_x = count / total
        ent -= p_x * math.log2(p_x)
    return round(ent, 3)


SUSPICIOUS_CAPABILITY_DLLS = {
    "ws2_32.dll", "wsock32.dll", "wininet.dll", "urlmon.dll", "winhttp.dll",
    "netapi32.dll", "psapi.dll", "vaultcli.dll", "wtsapi32.dll", "crypt32.dll",
    "iphlpapi.dll", "sensapi.dll", "rasapi32.dll", "dnsapi.dll", "samlib.dll"
}

STANDARD_PE_SECTIONS = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc",
    ".pdata", ".tls", ".bss", ".didata", ".cormeta", ".sbss", ".sdata",
    ".debug", ".drectve", ".gfids", ".giats", ".gljmp", ".guard",
    "text", "data", "rdata", "rsrc", "bss"
}

KNOWN_PACKER_SECTIONS = re.compile(r"^(upx[0-9]?|\.upx|\.aspack|\.vmp[0-9]?|\.themida|\.fsg|\.petite|\.nsp[0-9]?|\.pecrypt)$", re.IGNORECASE)


def extract_pe_advanced(file_path: str, file_data: bytes = None):
    """Extract imports, suspicious APIs, max section entropy, packed status, distinctive sections, capability DLLs, and exports."""
    imports = []
    suspicious_found = []
    imported_dlls = []
    max_entropy = 0.0
    is_packed = False
    packed_section_names = []
    distinctive_section_names = []
    pe_exports = []
    try:
        # Only the import and export directories are used: parse just those
        # (fast_load=False also parsed relocations, resources, debug, TLS ...),
        # from the bytes already in memory instead of reading the file again.
        if file_data is not None:
            pe = pefile.PE(data=file_data, fast_load=True)
        else:
            pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll:
                    dll_name = entry.dll.decode("ascii", errors="ignore").strip().lower()
                    if dll_name and dll_name not in imported_dlls:
                        imported_dlls.append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("ascii", errors="ignore")
                        imports.append(name)
                        if name in SUSPICIOUS_IMPORTS:
                            suspicious_found.append(name)
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []):
                if exp.name:
                    exp_name = exp.name.decode("ascii", errors="ignore")
                    if exp_name not in ("DllMain", "malloc", "free"):
                        pe_exports.append(exp_name)
        if hasattr(pe, "sections"):
            for sec in pe.sections:
                ent = sec.get_entropy()
                if ent > max_entropy:
                    max_entropy = ent
                s_name = sec.Name.decode("latin1", errors="ignore").strip("\x00").strip()
                if not s_name:
                    continue
                if KNOWN_PACKER_SECTIONS.match(s_name) or s_name.upper().startswith("UPX") or s_name.upper().startswith("MEW"):
                    is_packed = True
                    packed_section_names.append(s_name)
                # Check for distinctive, non-standard section names
                if s_name.lower() not in STANDARD_PE_SECTIONS:
                    if all(32 <= ord(c) < 127 for c in s_name) and len(s_name) >= 3:
                        distinctive_section_names.append(s_name)

            if len(packed_section_names) > 0 or (max_entropy >= 7.2 and (len(pe.sections) <= 3 or max_entropy >= 7.5)):
                is_packed = True
    except Exception:
        pass

    cap_dlls = [d for d in imported_dlls if d in SUSPICIOUS_CAPABILITY_DLLS]
    return (
        imports,
        sorted(list(set(suspicious_found))),
        max_entropy,
        is_packed,
        packed_section_names,
        sorted(list(set(distinctive_section_names))),
        sorted(list(set(cap_dlls))),
        sorted(list(set(pe_exports))),
    )


def extract_apk_metadata(file_path: str):
    """Extract APK DEX, manifest, permissions, and feature metrics."""
    res = {
        "is_apk": False,
        "permissions": [],
        "dangerous_perm_count": 0,
        "dex_files": 0,
    }
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as z:
                names = z.namelist()
                dex_count = sum(1 for n in names if n.endswith(".dex"))
                has_manifest = "AndroidManifest.xml" in names
                if dex_count > 0 or has_manifest:
                    res["is_apk"] = True
                    res["dex_files"] = dex_count
                    if has_manifest:
                        m_data = z.read("AndroidManifest.xml")
                        found_perms = re.findall(rb"android\.permission\.[A-Za-z0-9_]+", m_data)
                        perms = sorted(list(set(p.decode("ascii", errors="ignore") for p in found_perms)))
                        res["permissions"] = perms
                        dangerous = {
                            "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_PHONE_STATE",
                            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO",
                            "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG",
                            "WRITE_CALL_LOG", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
                            "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES"
                        }
                        res["dangerous_perm_count"] = sum(
                            1 for p in perms if any(d in p for d in dangerous)
                        )
    except Exception:
        pass
    return res


def sample_string_evaluation(string_stats, opcode_stats, file_info):
    # Generate Stats -----------------------------------------------------------
    print("[+] Generating statistical data ...")
    file_strings = {}
    file_opcodes = {}
    combinations = {}
    inverse_stats = {}
    max_combi_count = 0
    super_rules = []
    skip_super = nosuper or args.inverse

    # OPCODE EVALUATION --------------------------------------------------------
    for opcode in opcode_stats:
        # If string occurs not too often in sample files
        if opcode_stats[opcode]["count"] < 10:
            # If string list in file dictionary not yet exists
            for filePath in opcode_stats[opcode]["files"]:
                if filePath in file_opcodes:
                    # Append string
                    file_opcodes[filePath].append(opcode)
                else:
                    # Create list and then add the first string to the file
                    file_opcodes[filePath] = []
                    file_opcodes[filePath].append(opcode)

    # STRING EVALUATION -------------------------------------------------------

    # Iterate through strings found in malware files
    for string in string_stats:
        # If string occurs not too often in (goodware) sample files
        if string_stats[string]["count"] < 10:
            # If string list in file dictionary not yet exists
            for filePath in string_stats[string]["files"]:
                if filePath in file_strings:
                    # Append string
                    file_strings[filePath].append(string)
                else:
                    # Create list and then add the first string to the file
                    file_strings[filePath] = []
                    file_strings[filePath].append(string)

                # INVERSE RULE GENERATION -------------------------------------
                if args.inverse:
                    for fileName in string_stats[string]["files_basename"]:
                        string_occurrance_count = string_stats[string]["files_basename"][fileName]
                        total_count_basename = file_info[fileName]["count"]
                        # print "string_occurance_count %s - total_count_basename %s" % ( string_occurance_count,
                        # total_count_basename )
                        if string_occurrance_count == total_count_basename:
                            if fileName not in inverse_stats:
                                inverse_stats[fileName] = []
                            if args.trace:
                                print("Appending %s to %s" % (string, fileName))
                            inverse_stats[fileName].append(string)

        # SUPER RULE GENERATION -----------------------------------------------
        if not skip_super:
            # SUPER RULES GENERATOR	- preliminary work
            # If a string occurs more than once in different files
            # print sample_string_stats[string]["count"]
            if string_stats[string]["count"] > 1:
                if args.debug:
                    print('OVERLAP Count: %s\nString: "%s"%s' % (string_stats[string]["count"], string, "\nFILE: ".join(string_stats[string]["files"])))
                # Create a combination string from the file set that matches to that string
                combi = ":".join(sorted(string_stats[string]["files"]))
                # print "STRING: " + string
                if args.debug:
                    print("COMBI: " + combi)
                # If combination not yet known
                if combi not in combinations:
                    combinations[combi] = {}
                    combinations[combi]["count"] = 1
                    combinations[combi]["strings"] = []
                    combinations[combi]["strings"].append(string)
                    combinations[combi]["files"] = string_stats[string]["files"]
                else:
                    combinations[combi]["count"] += 1
                    combinations[combi]["strings"].append(string)
                # Set the maximum combination count
                if combinations[combi]["count"] > max_combi_count:
                    max_combi_count = combinations[combi]["count"]
                    # print "Max Combi Count set to: %s" % max_combi_count

    print("[+] Generating Super Rules ... (a lot of magic)")
    # Same order as before (highest count first, then insertion order) but one
    # pass over the combinations instead of one pass per possible count.
    ordered_combis = sorted((c for c in combinations if combinations[c]["count"] > 1), key=lambda c: -combinations[c]["count"])
    for combi in ordered_combis:
            if True:
                # print "Count %s - Combi %s" % ( str(combinations[combi]["count"]), combi )
                # Filter the string set
                # print "BEFORE"
                # print len(combinations[combi]["strings"])
                # print combinations[combi]["strings"]
                string_set = combinations[combi]["strings"]
                combinations[combi]["strings"] = []
                combinations[combi]["strings"] = filter_string_set(string_set)
                # print combinations[combi]["strings"]
                # print "AFTER"
                # print len(combinations[combi]["strings"])
                # Combi String count after filtering
                # print "String count after filtering: %s" % str(len(combinations[combi]["strings"]))

                # If the string set of the combination has a required size
                if len(combinations[combi]["strings"]) >= int(args.w):
                    # Remove the files in the combi rule from the simple set
                    if args.nosimple:
                        for file in combinations[combi]["files"]:
                            if file in file_strings:
                                del file_strings[file]
                    # Add it as a super rule
                    print("[-] Adding Super Rule with %s strings." % str(len(combinations[combi]["strings"])))
                    # if args.debug:
                    # print "Rule Combi: %s" % combi
                    super_rules.append(combinations[combi])

    # Return all data
    return (file_strings, file_opcodes, combinations, super_rules, inverse_stats)


def filter_opcode_set(opcode_set: list[str]) -> list[str]:
    # Preferred Opcodes
    pref_opcodes = [" 34 ", "ff ff ff "]

    # Useful set
    useful_set = []
    pref_set = []

    for opcode in opcode_set:
        opcode: str
        # Exclude all opcodes found in goodware
        if opcode in good_opcodes_db:
            if args.debug:
                print("skipping %s" % opcode)
            continue

        # Format the opcode
        formatted_opcode = get_opcode_string(opcode)

        # Preferred opcodes
        set_in_pref = False
        for pref in pref_opcodes:
            if pref in formatted_opcode:
                pref_set.append(formatted_opcode)
                set_in_pref = True
        if set_in_pref:
            continue

        # Else add to useful set
        useful_set.append(get_opcode_string(opcode))

    # Preferred opcodes first
    useful_set = pref_set + useful_set

    # Only return the number of opcodes defined with the "-n" parameter
    return useful_set[: int(args.n)]


def filter_string_set(string_set):
    # Local string scores
    localStringScores = {}

    # Local UTF strings (set: membership is checked for every result string)
    utfstrings = set()

    for string in string_set:
        # Filter meaningful words based on the flag
        if args.meaningful_words_only and not is_meaningful_string(string):
            continue

        # Goodware string marker
        goodstring = False
        goodcount = 0

        # Goodware Strings
        if string in good_strings_db:
            goodstring = True
            goodcount = good_strings_db[string]
            # print "%s - %s" % ( goodstring, good_strings[string] )
            if args.excludegood:
                continue

        # UTF
        original_string = string
        if string[:8] == "UTF16LE:":
            # print "removed UTF16LE from %s" % string
            string = string[8:]
            utfstrings.add(string)

        # Good string evaluation (after the UTF modification)
        if goodstring:
            # Reduce the score by the number of occurence in goodware files
            localStringScores[string] = (goodcount * -1) + 5
        else:
            localStringScores[string] = 0

        # PEStudio String Blacklist Evaluation
        if pestudio_available:
            (pescore, type) = get_pestudio_score(string)
            # print("PE Match: %s" % string)
            # Reset score of goodware files to 5 if blacklisted in PEStudio
            if type != "":
                pestudioMarker[string] = type
                # Modify the PEStudio blacklisted strings with their goodware stats count
                if goodstring:
                    pescore = pescore - (goodcount / 1000.0)
                    # print "%s - %s - %s" % (string, pescore, goodcount)
                localStringScores[string] = pescore

        if not goodstring:
            # Length Score
            # length = len(string)
            # if length > int(args.y) and length < int(args.s):
            #    localStringScores[string] += round(len(string) / 8, 2)
            # if length >= int(args.s):
            #    localStringScores[string] += 1

            # Reduction
            if ".." in string:
                localStringScores[string] -= 5
            if "   " in string:
                localStringScores[string] -= 5
            # Packer Strings
            if re.search(r"(WinRAR\\SFX)", string):
                localStringScores[string] -= 4
            # US ASCII char
            if "\x1f" in string:
                localStringScores[string] -= 4
            # Chains of 00s
            if string.count("0000000000") > 2:
                localStringScores[string] -= 5
            # Repeated characters
            if re.search(r"(?!.* ([A-Fa-f0-9])\1{8,})", string):
                localStringScores[string] -= 5

            # Certain strings add-ons ----------------------------------------------
            # Extensions - Drive
            if re.search(r"[A-Za-z]:\\", string, re.IGNORECASE):
                localStringScores[string] += 2
            # Relevant file extensions
            if re.search(
                r"(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.vbs|"
                r"\.tmp|\.sys|\.ps1|\.vbp|\.hta|\.lnk)",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 4
            # System keywords
            if re.search(r"(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)", string, re.IGNORECASE):
                localStringScores[string] += 5
            # Protocol Keywords
            if re.search(r"(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)", string, re.IGNORECASE):
                localStringScores[string] += 5
            # Connection keywords
            if re.search(r"(error|http|closed|fail|version|proxy)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Browser User Agents
            if re.search(r"(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)", string, re.IGNORECASE):
                localStringScores[string] += 5
            # Temp and Recycler
            if re.search(r"(TEMP|Temporary|Appdata|Recycler)", string, re.IGNORECASE):
                localStringScores[string] += 4
            # Malicious keywords - hacktools
            if re.search(
                r"(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|"
                r"credentials|creds|coded|p0c|Content|host)",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 5
            # Network keywords
            if re.search(r"(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Drive
            if re.search(r"([C-Zc-z]:\\)", string, re.IGNORECASE):
                localStringScores[string] += 4
            # IP
            if re.search(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", string, re.IGNORECASE):  # IP Address
                localStringScores[string] += 5
            # Copyright Owner
            if re.search(r"(coded | c0d3d |cr3w\b|Coded by |codedby)", string, re.IGNORECASE):
                localStringScores[string] += 7
            # Extension generic
            if re.search(r"\.[a-zA-Z]{3}\b", string):
                localStringScores[string] += 3
            # All upper case
            if re.search(r"^[A-Z]{6,}$", string):
                localStringScores[string] += 2.5
            # All lower case
            if re.search(r"^[a-z]{6,}$", string):
                localStringScores[string] += 2
            # All lower with space
            if re.search(r"^[a-z\s]{6,}$", string):
                localStringScores[string] += 2
            # All characters
            if re.search(r"^[A-Z][a-z]{5,}$", string):
                localStringScores[string] += 2
            # URL
            if re.search(r"(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)", string):
                localStringScores[string] += 2.5
            # certificates
            if re.search(r"(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)", string, re.IGNORECASE):
                localStringScores[string] -= 4
            # Parameters
            if re.search(r"( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)", string, re.IGNORECASE):
                localStringScores[string] += 4
            # Directory
            if re.search(r"([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\", string):
                localStringScores[string] += 4
            # Executable - not in directory
            if re.search(r"^[^\\]+\.(exe|com|scr|bat|sys)$", string, re.IGNORECASE):
                localStringScores[string] += 4
            # Date placeholders
            if re.search(r"(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Placeholders
            if re.search(r"[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]", string, re.IGNORECASE):
                localStringScores[string] += 3
            # String parts from file system elements
            if re.search(r"(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Programming
            if re.search(r"(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Credentials
            if re.search(
                r"(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|"
                r"identif|account|login|auth|privilege)",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 3
            # Malware
            if re.search(r"(\.[a-z]/[^/]+\.txt|)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Variables
            if re.search(r"%[A-Z_]+%", string, re.IGNORECASE):
                localStringScores[string] += 4
            # RATs / Malware
            if re.search(r"(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit|/veil|Blood)", string, re.IGNORECASE):
                localStringScores[string] += 5
            # Missed user profiles
            if re.search(
                r"[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|"
                r"Usuários)[\\]",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 3
            # Strings: Words ending with numbers
            if re.search(r"^[A-Z][a-z]+[0-9]+$", string, re.IGNORECASE):
                localStringScores[string] += 1
            # Spying
            if re.search(r"(implant)", string, re.IGNORECASE):
                localStringScores[string] += 1
            # Program Path - not Programs or Windows
            if re.search(r"^[Cc]:\\\\[^PW]", string):
                localStringScores[string] += 3
            # Special strings
            if re.search(r"(\\\\\.\\|kernel|.dll|usage|\\DosDevices\\)", string, re.IGNORECASE):
                localStringScores[string] += 5
            # Parameters
            if re.search(r"( \-[a-z] | /[a-z] | \-[a-z]:[a-zA-Z]| \/[a-z]:[a-zA-Z])", string):
                localStringScores[string] += 4
            # File
            if re.search(r"^[a-zA-Z0-9]{3,40}\.[a-zA-Z]{3}", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Comment Line / Output Log
            if re.search(r"^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )", string):
                localStringScores[string] += 4
            # Output typo / special expression
            if re.search(r"(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)", string):
                localStringScores[string] += 4
            # Base64
            if re.search(r"^(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", string) and re.search(r"[A-Za-z]", string) and re.search(r"[0-9]", string):
                localStringScores[string] += 7
            # Base64 Executables
            if re.search(
                r"(TVqQAAMAAAAEAAAA//8AALgAAAA|TVpQAAIAAAAEAA8A//8AALgAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|"
                r"TVoAAAAAAAAAAAAAAAAAAAAAAAA|TVpTAQEAAAAEAAAA//8AALgAAAA)",
                string,
            ):
                localStringScores[string] += 5
            # Malicious intent
            if re.search(
                r"(loader|cmdline|ntlmhash|lmhash|infect|encrypt|exec|elevat|dump|target|victim|override|"
                r"traverse|mutex|pawnde|exploited|shellcode|injected|spoofed|dllinjec|exeinj|reflective|"
                r"payload|inject|back conn)",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 5
            # Privileges
            if re.search(r"(administrator|highest|system|debug|dbg|admin|adm|root) privilege", string, re.IGNORECASE):
                localStringScores[string] += 4
            # System file/process names
            if re.search(r"(LSASS|SAM|lsass.exe|cmd.exe|LSASRV.DLL)", string):
                localStringScores[string] += 4
            # System file/process names
            if re.search(r"(\.exe|\.dll|\.sys)$", string, re.IGNORECASE):
                localStringScores[string] += 4
            # Indicators that string is valid
            if re.search(r"(^\\\\)", string, re.IGNORECASE):
                localStringScores[string] += 1
            # Compiler output directories
            if re.search(r"(\\Release\\|\\Debug\\|\\bin|\\sbin)", string, re.IGNORECASE):
                localStringScores[string] += 2
            # Special - Malware related strings
            if re.search(r"(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)", string):
                localStringScores[string] += 4
            # Powershell
            if re.search(
                r"(bypass|windowstyle | hidden |-command|IEX |Invoke-Expression|Net.Webclient|Invoke[A-Z]|"
                r"Net.WebClient|-w hidden |-encoded"
                r"-encodedcommand| -nop |MemoryLoadLibrary|FromBase64String|Download|EncodedCommand)",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 4
            # WMI
            if re.search(r"( /c WMIC)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Windows Commands
            if re.search(
                r"( net user | net group |ping |whoami |bitsadmin |rundll32.exe javascript:|"
                r"schtasks.exe /create|/c start )",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 3
            # JavaScript
            if re.search(
                r'(new ActiveXObject\("WScript.Shell"\).Run|.Run\("cmd.exe|.Run\("%comspec%\)|'
                r'.Run\("c:\\Windows|.RegisterXLL\()',
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 3
            # Signing Certificates
            if re.search(r"( Inc | Co.|  Ltd.,| LLC| Limited)", string):
                localStringScores[string] += 2
            # Privilege escalation
            if re.search(r"(sysprep|cryptbase|secur32)", string, re.IGNORECASE):
                localStringScores[string] += 2
            # Webshells
            if re.search(r"(isset\($post\[|isset\($get\[|eval\(Request)", string, re.IGNORECASE):
                localStringScores[string] += 2
            # Suspicious words 1
            if re.search(r"(impersonate|drop|upload|download|execute|shell|\bcmd\b|decode|rot13|decrypt)", string, re.IGNORECASE):
                localStringScores[string] += 2
            # Suspicious words 1
            if re.search(
                r"([+] |[-] |[*] |injecting|exploit|dumped|dumping|scanning|scanned|elevation|"
                r"elevated|payload|vulnerable|payload|reverse connect|bind shell|reverse shell| dump | "
                r"back connect |privesc|privilege escalat|debug privilege| inject |interactive shell|"
                r"shell commands| spawning |] target |] Transmi|] Connect|] connect|] Dump|] command |"
                r"] token|] Token |] Firing | hashes | etc/passwd| SAM | NTML|unsupported target|"
                r"race condition|Token system |LoaderConfig| add user |ile upload |ile download |"
                r"Attaching to |ser has been successfully added|target system |LSA Secrets|DefaultPassword|"
                r"Password: |loading dll|.Execute\(|Shellcode|Loader|inject x86|inject x64|bypass|katz|"
                r"sploit|ms[0-9][0-9][^0-9]|\bCVE[^a-zA-Z]|privilege::|lsadump|door)",
                string,
                re.IGNORECASE,
            ):
                localStringScores[string] += 4
            # Mutex / Named Pipes
            if re.search(r"(Mutex|NamedPipe|\\Global\\|\\pipe\\)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Usage
            if re.search(r"(isset\($post\[|isset\($get\[)", string, re.IGNORECASE):
                localStringScores[string] += 2
            # Hash
            if re.search(r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", string, re.IGNORECASE):
                localStringScores[string] += 2
            # Persistence
            if re.search(r"(sc.exe |schtasks|at \\\\|at [0-9]{2}:[0-9]{2})", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Unix/Linux
            if re.search(r"(;chmod |; chmod |sh -c|/dev/tcp/|/bin/telnet|selinux| shell| cp /bin/sh )", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Attack
            if re.search(r"(attacker|brute force|bruteforce|connecting back|EXHAUSTIVE|exhaustion| spawn| evil| elevated)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Strings with less value
            if re.search(r"(abcdefghijklmnopqsst|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789:;)", string, re.IGNORECASE):
                localStringScores[string] -= 5
            # VB Backdoors
            if re.search(r"(kill|wscript|plugins|svr32|Select |)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # Suspicious strings - combo / special characters
            if re.search(r"([a-z]{4,}[!\?]|\[[!+\-]\] |[a-zA-Z]{4,}...)", string, re.IGNORECASE):
                localStringScores[string] += 3
            if re.search(r"(-->|!!!| <<< | >>> )", string, re.IGNORECASE):
                localStringScores[string] += 5
            # Swear words
            if re.search(r"\b(fuck|damn|shit|penis)\b", string, re.IGNORECASE):
                localStringScores[string] += 5
            # Scripting Strings
            if re.search(r"(%APPDATA%|%USERPROFILE%|Public|Roaming|& del|& rm| && |script)", string, re.IGNORECASE):
                localStringScores[string] += 3
            # UACME Bypass
            if re.search(r"(Elevation|pwnd|pawn|elevate to)", string, re.IGNORECASE):
                localStringScores[string] += 3

            # ENCODING DETECTIONS --------------------------------------------------
            try:
                if len(string) > 8:
                    # Try different ways - fuzz string
                    # Base64
                    if args.trace:
                        print("Starting Base64 string analysis ...")
                    for m_string in (string, string[1:], string[:-1], string[1:] + "=", string + "=", string + "=="):
                        if is_base_64(m_string):
                            try:
                                decoded_string = base64.b64decode(m_string, validate=False)
                            except binascii.Error:
                                continue
                            if is_ascii_string(decoded_string, padding_allowed=True):
                                # print "match"
                                localStringScores[string] += 10
                                base64strings[string] = decoded_string
                    # Hex Encoded string
                    if args.trace:
                        print("Starting Hex encoded string analysis ...")
                    for m_string in [string, re.sub("[^a-zA-Z0-9]", "", string)]:
                        # print m_string
                        if is_hex_encoded(m_string):
                            # print("^ is HEX")
                            decoded_string = bytes.fromhex(m_string)
                            # print removeNonAsciiDrop(decoded_string)
                            if is_ascii_string(decoded_string, padding_allowed=True):
                                # not too many 00s
                                if "00" in m_string:
                                    if len(m_string) / float(m_string.count("0")) <= 1.2:
                                        continue
                                # print("^ is ASCII / WIDE")
                                localStringScores[string] += 8
                                hexEncStrings[string] = decoded_string
            except Exception:
                if args.debug:
                    traceback.print_exc()
                pass

            # Reversed String -----------------------------------------------------
            if string[::-1] in good_strings_db:
                if not args.excludegood:
                    localStringScores[string] += 10
                    reversedStrings[string] = string[::-1]

            # Certain string reduce	-----------------------------------------------
            if re.search(r"(rundll32\.exe$|kernel\.dll$)", string, re.IGNORECASE):
                localStringScores[string] -= 4

        # Set the global string score
        stringScores[original_string] = localStringScores[string]

    sorted_set = sorted(localStringScores.items(), key=operator.itemgetter(1), reverse=True)

    # Only the top X strings
    result_set = []
    for string in sorted_set:
        # Skip the one with a score lower than -z X
        if not args.noscorefilter and not args.inverse:
            if string[1] < int(args.z):
                continue

        if string[0] in utfstrings:
            result_set.append("UTF16LE:%s" % string[0])
        else:
            result_set.append(string[0])

        # c += 1
        # if c > int(args.rc):
        #    break

    if args.trace:
        print("RESULT SET:")
        print(result_set)

    # return the filtered set
    return result_set


def generate_general_condition(file_info):
    """
    Generates a general condition for a set of files
    :param file_info:
    :return:
    """
    conditions = []
    pe_module_neccessary = False

    # Different Magic Headers and File Sizes
    magic_headers = []
    file_sizes = []
    imphashes = []

    try:
        for filePath in file_info:
            # Short file name info used for inverse generation has no magic/size fields
            if "magic" not in file_info[filePath]:
                continue
            magic = file_info[filePath]["magic"]
            size = file_info[filePath]["size"]
            imphash = file_info[filePath]["imphash"]

            # Add them to the lists
            if magic not in magic_headers and magic != "":
                magic_headers.append(magic)
            if size not in file_sizes:
                file_sizes.append(size)
            if imphash not in imphashes and imphash != "":
                imphashes.append(imphash)

        # If different magic headers are less than 5 (and at least one exists)
        if 0 < len(magic_headers) <= 5:
            magic_string = " or ".join(get_uint_string(h) for h in magic_headers)
            if " or " in magic_string:
                conditions.append("( {0} )".format(magic_string))
            else:
                conditions.append("{0}".format(magic_string))

        # Biggest size multiplied with maxsize_multiplier
        if not args.nofilesize and len(file_sizes) > 0:
            conditions.append(get_file_range(max(file_sizes)))

        # If different magic headers are less than 5
        if len(imphashes) == 1:
            conditions.append('pe.imphash() == "{0}"'.format(imphashes[0]))
            pe_module_neccessary = True

        # If enough attributes were special
        condition_string = " and ".join(conditions)

    except Exception:
        if args.debug:
            traceback.print_exc()
            exit(1)
        print("[E] ERROR while generating general condition - check the global rule and remove it if it's faulty")

    return condition_string, pe_module_neccessary


def get_file_name_stem(filename: str) -> str:
    """Extract base name from malware filename by stripping sample counter / index suffixes."""
    fileBase = os.path.splitext(filename)[0]
    fileBase = re.sub(r"\.(vir|v|exe|bin|dll|dat)$", "", fileBase, flags=re.I)
    stem = re.sub(r"_\d+(_\d+)*$", "", fileBase)
    stem = re.sub(r"[^\w]", "_", stem).strip("_")
    return stem or fileBase


def is_clean_string(s: str) -> bool:
    """Check if string is printable text without unprintable control characters."""
    if not s or len(s.strip()) < 3:
        return False
    return not any(ord(c) < 32 or ord(c) == 127 for c in s)


def yaml_escape(s: str) -> str:
    """Escape backslashes, double quotes, and control characters for YAML double-quoted scalar."""
    out = []
    for c in s:
        code = ord(c)
        if c == "\\":
            out.append("\\\\")
        elif c == '"':
            out.append('\\"')
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        else:
            out.append(c)
    return "".join(out)


def generate_hydradragonsig_yaml(file_strings, file_opcodes, super_rules, file_info, good_opcodes_db, out_path):
    """Generate deterministic HydraDragonSig YAML rules with multi-factor conditions and exclude bytes."""
    lines = [
        "name: HydraDragon Threat Signatures",
        'version: "1.0"',
        f"# Generated by yarGen-Sig on {get_timestamp_basic()}",
        "# Strict benign veto + exclude bytes + multi-factor verification",
        "",
        "rules:"
    ]

    # Group files by filename stem
    file_groups = defaultdict(list)
    for filePath in file_strings:
        if len(file_strings[filePath]) == 0 and len(file_opcodes.get(filePath, [])) == 0:
            continue
        (_, file) = os.path.split(filePath)
        stem = get_file_name_stem(file)
        file_groups[stem].append(filePath)

    # Pick top benign opcodes from good_opcodes_db as exclude bytes
    benign_excludes = []
    if good_opcodes_db:
        for op, count in good_opcodes_db.most_common(10):
            formatted_op = get_opcode_string(op).upper()
            if formatted_op not in benign_excludes:
                benign_excludes.append(formatted_op)

    rule_idx = 1
    for stem, member_files in sorted(file_groups.items()):
        fmt = "pe"
        for fp in member_files:
            info = file_info.get(fp, {})
            magic = info.get("magic", "")
            if magic == "MZ":
                fmt = "pe"
                break
            elif magic.startswith("504b") or fp.lower().endswith(".apk"):
                fmt = "apk"
                break
            elif fp.lower().endswith((".js", ".jse", ".vbs", ".ps1")):
                fmt = "javascript" if fp.lower().endswith((".js", ".jse")) else "script"

        # Merge strings across member files
        merged_str_counter = Counter()
        for fp in member_files:
            for s in file_strings.get(fp, []):
                merged_str_counter[s] += 1

        clean_candidates = [
            s for s in merged_str_counter.keys()
            if is_clean_string(s[8:] if s.startswith("UTF16LE:") else s)
        ]

        ranked_strings = sorted(
            clean_candidates,
            key=lambda s: (merged_str_counter[s], stringScores.get(s, 0)),
            reverse=True
        )[:15]

        # Merge opcodes across member files (ignoring any opcode in benign db)
        merged_opcodes = []
        for fp in member_files:
            for op in file_opcodes.get(fp, []):
                if good_opcodes_db and op in good_opcodes_db:
                    continue
                formatted_op = get_opcode_string(op).upper()
                if formatted_op not in merged_opcodes:
                    merged_opcodes.append(formatted_op)

        if not ranked_strings and not merged_opcodes:
            continue

        rule_id = f"MALW_{fmt.upper()}_{rule_idx:04d}"
        rule_idx += 1

        file_listing = ", ".join(os.path.basename(f) for f in member_files)
        clean_tag = re.sub(r"[^\w-]", "-", stem.lower())
        tags = [fmt, "malware", clean_tag]
        tags_str = ", ".join(list(dict.fromkeys(tags)))

        # Feature 1: MITRE ATT&CK Technique Mapping
        mitre_entries = []
        for fp in member_files:
            for imp in file_info.get(fp, {}).get("suspicious_imports", []):
                if imp in MITRE_API_MAP:
                    m_id, m_name, m_tac = MITRE_API_MAP[imp]
                    if not any(m["id"] == m_id for m in mitre_entries):
                        mitre_entries.append({"id": m_id, "name": m_name, "tactic": m_tac})
            apk_info = file_info.get(fp, {}).get("apk", {})
            if apk_info.get("dangerous_perm_count", 0) >= 3:
                if not any(m["id"] == "T1437" for m in mitre_entries):
                    mitre_entries.append({"id": "T1437", "name": "Application Layer Protocol: Mobile C2", "tactic": "Command and Control"})

        # Build condition blocks
        condition_blocks = []

        # Condition 1: file_type
        c_ft = [
            "      - type: file_type",
            f"        values: [{fmt}]"
        ]
        condition_blocks.append(c_ft)

        # Condition 1b: file_size_lte (Generous performance guardrail based on sample size)
        max_sz = max([file_info.get(fp, {}).get("size", 1000000) for fp in member_files] or [1000000])
        size_limit = min(max(int(max_sz * 2.5), 5 * 1024 * 1024), 35 * 1024 * 1024)
        c_sz = [
            "      - type: file_size_lte",
            f"        bytes: {size_limit}"
        ]
        condition_blocks.append(c_sz)

        # Condition 2: string_set (with decoded, wide, and ascii support)
        if ranked_strings:
            min_str = 2 if len(ranked_strings) >= 3 else 1
            has_wide = any(s.startswith("UTF16LE:") for s in ranked_strings)
            c_str = [
                "      - type: string_set",
                f"        min: {min_str}",
                "        nocase: true",
                "        ascii: true",
                "        decoded: true"
            ]
            if has_wide:
                c_str.append("        wide: true")
            c_str.append("        values:")
            for s in ranked_strings:
                raw_val = s[8:] if s.startswith("UTF16LE:") else s
                escaped = yaml_escape(raw_val)
                c_str.append(f'          - "{escaped}"')
            condition_blocks.append(c_str)

        # Condition 3: byte_pattern / byte_set (opcodes strictly absent from benign database)
        if merged_opcodes:
            c_bytes = []
            if len(merged_opcodes) == 1:
                c_bytes.append("      - type: byte_pattern")
                c_bytes.append(f'        pattern: "{{ {merged_opcodes[0]} }}"')
            else:
                c_bytes.append("      - type: byte_set")
                c_bytes.append("        min: 1")
                c_bytes.append("        patterns:")
                for op in merged_opcodes[:3]:
                    c_bytes.append(f'          - "{{ {op} }}"')
            condition_blocks.append(c_bytes)

        # Condition 4: PE Icon fingerprints (dhash & phash)
        merged_icon_dhashes = []
        merged_icon_phashes = []
        for fp in member_files:
            for dh, ph in file_info.get(fp, {}).get("icons", []):
                if dh and dh not in merged_icon_dhashes:
                    merged_icon_dhashes.append(dh)
                if ph and ph not in merged_icon_phashes:
                    merged_icon_phashes.append(ph)

        if merged_icon_dhashes:
            c_icon = [
                "      - type: pe_icon_any",
                "        dhash:"
            ]
            for dh in merged_icon_dhashes[:3]:
                c_icon.append(f'          - "{dh}"')
            c_icon.append("        dhash_max_distance: 4")
            if merged_icon_phashes:
                c_icon.append("        phash:")
                for ph in merged_icon_phashes[:3]:
                    c_icon.append(f'          - "{ph}"')
                c_icon.append("        phash_max_distance: 4")
            condition_blocks.append(c_icon)

        # Condition 5: Suspicious PE Imports
        merged_susp_imports = []
        for fp in member_files:
            for imp in file_info.get(fp, {}).get("suspicious_imports", []):
                if imp not in merged_susp_imports:
                    merged_susp_imports.append(imp)

        if merged_susp_imports:
            c_imp = [
                "      - type: import_any",
                "        names:"
            ]
            for imp in merged_susp_imports[:5]:
                c_imp.append(f'          - "{imp}"')
            condition_blocks.append(c_imp)

        # Condition 5b: Capability DLL Imports
        merged_cap_dlls = []
        for fp in member_files:
            for d in file_info.get(fp, {}).get("capability_dlls", []):
                if d not in merged_cap_dlls:
                    merged_cap_dlls.append(d)

        if merged_cap_dlls:
            c_dll = [
                "      - type: dll_any",
                "        names:"
            ]
            for d in merged_cap_dlls[:3]:
                c_dll.append(f'          - "{d}"')
            condition_blocks.append(c_dll)

        # Condition 6: Suspicious Import Count Threshold
        max_susp_cnt = max([len(file_info.get(fp, {}).get("suspicious_imports", [])) for fp in member_files] or [0])
        if max_susp_cnt >= 3:
            c_cnt = [
                "      - type: suspicious_import_count",
                f"        min: {min(max_susp_cnt, 3)}"
            ]
            condition_blocks.append(c_cnt)

        # Condition 7: Export Set (Characteristic DLL / PE Exports)
        merged_exports = []
        for fp in member_files:
            for exp in file_info.get(fp, {}).get("exports", []):
                if exp not in merged_exports:
                    merged_exports.append(exp)

        if merged_exports:
            c_exp = [
                "      - type: export_set",
                "        min: 1",
                "        names:"
            ]
            for exp in merged_exports[:5]:
                c_exp.append(f'          - "{exp}"')
            condition_blocks.append(c_exp)

        # Condition 8: High Section Entropy
        max_ent = max([file_info.get(fp, {}).get("max_section_entropy", 0.0) for fp in member_files] or [0.0])
        if max_ent >= 7.2:
            c_ent = [
                "      - type: section_entropy",
                "        min: 7.2"
            ]
            condition_blocks.append(c_ent)

        # Condition 9: Packed PE (Heuristic Check)
        any_packed = any(file_info.get(fp, {}).get("is_packed", False) for fp in member_files)
        if any_packed:
            condition_blocks.append(["      - type: packed_pe"])

        # Condition 10: Section Name Regex (Strictly from ACTUAL distinctive sections observed in samples)
        merged_dist_secs = []
        for fp in member_files:
            for s in file_info.get(fp, {}).get("distinctive_sections", []):
                if s not in merged_dist_secs:
                    merged_dist_secs.append(s)

        if merged_dist_secs:
            escaped_sec_names = [re.escape(s) for s in merged_dist_secs[:4]]
            sec_pattern = f"(?i)^({'|'.join(escaped_sec_names)})$"
            c_sec = [
                "      - type: section_name_regex",
                f"        pattern: '{sec_pattern}'"
            ]
            condition_blocks.append(c_sec)

        # Condition 11: APK Features & Permissions
        max_dangerous_perms = max([file_info.get(fp, {}).get("apk", {}).get("dangerous_perm_count", 0) for fp in member_files] or [0])
        max_dex_files = max([file_info.get(fp, {}).get("apk", {}).get("dex_files", 0) for fp in member_files] or [0])
        if fmt == "apk":
            if max_dangerous_perms >= 3:
                c_apk = [
                    "      - type: feature_gte",
                    "        name: dangerous_perm_count",
                    f"        value: {float(max_dangerous_perms):.1f}"
                ]
                condition_blocks.append(c_apk)
            elif max_dex_files >= 1:
                c_apk = [
                    "      - type: feature_gte",
                    "        name: dex_files",
                    f"        value: {float(max_dex_files):.1f}"
                ]
                condition_blocks.append(c_apk)

        # Condition 12: High File Entropy (for obfuscated scripts and packed non-PE payloads)
        max_file_entropy = max([file_info.get(fp, {}).get("entropy", 0.0) for fp in member_files] or [0.0])
        if fmt != "pe" and max_file_entropy >= 6.0:
            c_f_ent = [
                "      - type: file_entropy",
                f"        min: {round(min(max_file_entropy, 6.0), 1)}"
            ]
            condition_blocks.append(c_f_ent)

        # Build rule header and metadata
        lines.append(f"  - id: {rule_id}")
        lines.append(f'    title: "Malware.{fmt.upper()}.{stem}"')
        lines.append("    description: >")
        lines.append(f"      Detection for {stem} ({len(member_files)} sample(s)).")
        lines.append(f"      Samples: {file_listing}")
        lines.append("    severity: critical")
        lines.append("    verdict: malware")
        lines.append("    confidence: 95")
        lines.append(f'    family: "{stem}"')
        lines.append("    score: 95")
        lines.append(f"    tags: [{tags_str}]")

        # MITRE ATT&CK Mapping output
        if mitre_entries:
            lines.append("    mitre:")
            for m in mitre_entries:
                lines.append(f'      - id: {m["id"]}')
                lines.append(f'        name: "{m["name"]}"')
                lines.append(f'        tactic: {m["tactic"]}')

        # Feature 6: Adaptive Rule Logic & Threshold
        if len(condition_blocks) >= 4:
            lines.append("    logic: threshold")
            lines.append("    threshold: 3")
        elif len(condition_blocks) == 3:
            lines.append("    logic: threshold")
            lines.append("    threshold: 2")
        else:
            lines.append("    logic: all")

        lines.append("    conditions:")
        for block in condition_blocks:
            lines.extend(block)

        lines.append("")

    super_count = 0
    if getattr(args, "sig_super", False) and super_rules:
        super_count = append_sig_super_rules(lines, super_rules, file_info)

    content = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Successfully wrote HydraDragonSig YAML rules to: {out_path} ({len(file_groups)} simple + {super_count} super rules)")
    return len(file_groups), super_count


def append_sig_super_rules(lines, super_rules, file_info):
    """Write yarGen super rules (a string set shared by several samples) as HydraDragonSig rules.

    Kept strict because shared strings are more often toolchain / packer / installer text
    than family-specific text:
      * only sets that span at least two different sample families (file name stems);
        a set inside one family is already covered by that family's simple rule,
      * at least args.w clean strings, of which 80 % (at least 4) must match,
      * logic "all": file type + size guard + the string set must all hold.
    """
    written = 0
    seen_sets = set()
    for sr in super_rules:
        files = sorted(sr.get("files", []))
        if len(files) < 2:
            continue
        stems = sorted({get_file_name_stem(os.path.basename(fp)) for fp in files})
        if len(stems) < 2:
            continue
        strings = [x for x in sr.get("strings", []) if is_clean_string(x[8:] if x.startswith("UTF16LE:") else x)]
        strings = sorted(dict.fromkeys(strings), key=lambda x: (-stringScores.get(x, 0), x))[:20]
        if len(strings) < max(int(args.w), 4):
            continue
        key = tuple(sorted(strings))
        if key in seen_sets:
            continue
        seen_sets.add(key)

        fmt = "pe"
        for fp in files:
            info = file_info.get(fp, {})
            magic = info.get("magic", "")
            if magic == "MZ":
                fmt = "pe"
                break
            if magic.startswith("504b") or fp.lower().endswith(".apk"):
                fmt = "apk"
                break
            if fp.lower().endswith((".js", ".jse", ".vbs", ".ps1")):
                fmt = "javascript" if fp.lower().endswith((".js", ".jse")) else "script"

        max_sz = max([file_info.get(fp, {}).get("size", 1000000) for fp in files] or [1000000])
        size_limit = min(max(int(max_sz * 2.5), 5 * 1024 * 1024), 35 * 1024 * 1024)
        need = max(4, -(-len(strings) * 4 // 5))  # ceil(80 %)

        written += 1
        family = "_".join(stems[:3]) + ("_etc" if len(stems) > 3 else "")
        listing = ", ".join(os.path.basename(f) for f in files[:10]) + (f" (+{len(files) - 10} more)" if len(files) > 10 else "")
        lines.append(f"  - id: MALW_SUPER_{written:04d}")
        lines.append(f'    title: "Malware.{fmt.upper()}.Super.{family}"')
        lines.append("    description: >")
        lines.append(f"      Super rule: {len(strings)} strings shared by {len(files)} samples of {len(stems)} families.")
        lines.append(f"      Samples: {listing}")
        lines.append("    severity: high")
        lines.append("    verdict: malware")
        lines.append("    confidence: 80")
        lines.append(f'    family: "{yaml_escape(family)}"')
        lines.append("    score: 80")
        lines.append(f"    tags: [{fmt}, malware, super]")
        lines.append("    logic: all")
        lines.append("    conditions:")
        lines.append("      - type: file_type")
        lines.append(f"        values: [{fmt}]")
        lines.append("      - type: file_size_lte")
        lines.append(f"        bytes: {size_limit}")
        lines.append("      - type: string_set")
        lines.append(f"        min: {need}")
        lines.append("        nocase: true")
        lines.append("        ascii: true")
        lines.append("        decoded: true")
        if any(x.startswith("UTF16LE:") for x in strings):
            lines.append("        wide: true")
        lines.append("        values:")
        for x in strings:
            raw = x[8:] if x.startswith("UTF16LE:") else x
            lines.append(f'          - "{yaml_escape(raw)}"')
        lines.append("")
    return written


def generate_rules(file_strings, file_opcodes, super_rules, file_info, inverse_stats):
    # Check if HydraDragonSig YAML output is requested
    sig_yaml_path = None
    if getattr(args, "sig_yaml", ""):
        sig_yaml_path = args.sig_yaml
    elif args.o and (args.o.endswith(".yaml") or args.o.endswith(".yml")):
        sig_yaml_path = args.o

    if sig_yaml_path:
        count, sig_super_count = generate_hydradragonsig_yaml(file_strings, file_opcodes, super_rules, file_info, good_opcodes_db, sig_yaml_path)
        if args.o == sig_yaml_path:
            return (count, 0, sig_super_count)

    # Write to file ---------------------------------------------------
    if args.o:
        try:
            fh = open(args.o, "w", encoding="utf-8", errors="replace")
        except Exception:
            traceback.print_exc()

    # General Info
    general_info = "/*\n"
    general_info += "   YARA Rule Set\n"
    general_info += "   Author: {0}\n".format(args.a)
    general_info += "   Date: {0}\n".format(get_timestamp_basic())
    general_info += "   Identifier: {0}\n".format(identifier)
    general_info += "   Reference: {0}\n".format(reference)
    if args.l != "":
        general_info += "   License: {0}\n".format(args.l)
    general_info += "*/\n\n"

    if args.ai:
        fh.write(AI_COMMENT)
    else:
        fh.write(general_info)

    # GLOBAL RULES ----------------------------------------------------
    if args.globalrule:
        condition, pe_module_necessary = generate_general_condition(file_info)

        # Global Rule
        if condition != "":
            global_rule = "/* Global Rule -------------------------------------------------------------- */\n"
            global_rule += "/* Will be evaluated first, speeds up scanning process, remove at will */\n\n"
            global_rule += "global private rule gen_characteristics {\n"
            global_rule += "   condition:\n"
            global_rule += "      {0}\n".format(condition)
            global_rule += "}\n\n"

            # Write rule
            if args.o:
                fh.write(global_rule)

    # General vars
    rules = ""
    printed_rules = {}
    rule_count = 0
    inverse_rule_count = 0
    super_rule_count = 0
    pe_module_necessary = False

    if not args.inverse:
        # PROCESS SIMPLE RULES ----------------------------------------------------
        print("[+] Generating Simple Rules ...")
        # Apply intelligent filters
        print("[-] Applying intelligent filters to string findings ...")
        for filePath in file_strings:
            print("[-] Filtering string set for %s ..." % filePath)

            # Replace the original string set with the filtered one
            file_strings[filePath] = filter_string_set(file_strings[filePath])

            print("[-] Filtering opcode set for %s ..." % filePath)

            # Replace the original opcode set with the filtered one
            file_opcodes[filePath] = filter_opcode_set(file_opcodes[filePath]) if filePath in file_opcodes else []

        # GENERATE SIMPLE RULES -------------------------------------------
        fh.write("/* Rule Set ----------------------------------------------------------------- */\n\n")

        for filePath in file_strings:
            # Skip if there is nothing to do
            if len(file_strings[filePath]) == 0:
                print("[W] Not enough high scoring strings to create a rule. (Try -z 0 to reduce the min score or --opcodes to include opcodes) FILE: %s" % filePath)
                continue
            elif len(file_strings[filePath]) == 0 and len(file_opcodes[filePath]) == 0:
                print("[W] Not enough high scoring strings and opcodes to create a rule. (Try -z 0 to reduce the min score) FILE: %s" % filePath)
                continue

            # Create Rule
            try:
                rule = ""
                (path, file) = os.path.split(filePath)
                # Prepare name
                fileBase = os.path.splitext(file)[0]
                # Create a clean new name
                cleanedName = fileBase
                # Adapt length of rule name
                if len(fileBase) < 8:  # if name is too short add part from path
                    cleanedName = path.split("\\")[-1:][0] + "_" + cleanedName
                # File name starts with a number
                if re.search(r"^[0-9]", cleanedName):
                    cleanedName = "sig_" + cleanedName
                # clean name from all characters that would cause errors
                cleanedName = re.sub(r"[^\w]", "_", cleanedName)
                # Enforce maximum rule name length (long names cause YARA parse errors)
                cleanedName = cleanedName[:MAX_RULE_NAME_LEN]
                # Check if already printed
                if cleanedName in printed_rules:
                    printed_rules[cleanedName] += 1
                    cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
                else:
                    printed_rules[cleanedName] = 1

                # Print rule title ----------------------------------------
                rule += "rule %s {\n" % cleanedName

                # Meta data -----------------------------------------------
                rule += "   meta:\n"
                rule += '      description = "%s"\n' % truncate_description("%s - file %s" % (prefix, file))
                rule += '      author = "%s"\n' % args.a
                rule += '      reference = "%s"\n' % reference
                rule += '      date = "%s"\n' % get_timestamp_basic()
                rule += '      hash1 = "%s"\n' % file_info[filePath]["hash"]
                rule += "   strings:\n"

                # Get the strings -----------------------------------------
                # Rule String generation
                (rule_strings, opcodes_included, string_rule_count, high_scoring_strings) = get_rule_strings(file_strings[filePath], file_opcodes[filePath])
                rule += rule_strings

                # Extract rul strings
                if args.strings:
                    strings = get_strings(file_strings[filePath])
                    write_strings(filePath, strings, args.e, args.score)

                # Condition -----------------------------------------------
                # Conditions list (will later be joined with 'or')
                conditions = []  # AND connected
                subconditions = []  # OR connected

                # Condition PE
                # Imphash and Exports - applicable to PE files only
                condition_pe = []
                condition_pe_part1 = []
                condition_pe_part2 = []
                if not args.noextras and file_info[filePath]["magic"] == "MZ":
                    # Add imphash - if certain conditions are met
                    if file_info[filePath]["imphash"] not in good_imphashes_db and file_info[filePath]["imphash"] != "":
                        # Comment to imphash
                        imphash = file_info[filePath]["imphash"]
                        comment = ""
                        if imphash in KNOWN_IMPHASHES:
                            comment = " /* {0} */".format(KNOWN_IMPHASHES[imphash])
                        # Add imphash to condition
                        condition_pe_part1.append('pe.imphash() == "{0}"{1}'.format(imphash, comment))
                        pe_module_necessary = True
                    if file_info[filePath]["exports"]:
                        e_count = 0
                        for export in file_info[filePath]["exports"]:
                            if export not in good_exports_db:
                                condition_pe_part2.append('pe.exports("{0}")'.format(export))
                                e_count += 1
                                pe_module_necessary = True
                            if e_count > 5:
                                break

                # 1st Part of Condition 1
                basic_conditions = []
                # Filesize
                if not args.nofilesize:
                    basic_conditions.insert(0, get_file_range(file_info[filePath]["size"]))
                # Magic
                if file_info[filePath]["magic"] != "":
                    uint_string = get_uint_string(file_info[filePath]["magic"])
                    basic_conditions.insert(0, uint_string)
                # Basic Condition
                if len(basic_conditions):
                    conditions.append(" and ".join(basic_conditions))

                # Add extra PE conditions to condition 1
                pe_conditions_add = False
                if condition_pe_part1 or condition_pe_part2:
                    if len(condition_pe_part1) == 1:
                        condition_pe.append(condition_pe_part1[0])
                    elif len(condition_pe_part1) > 1:
                        condition_pe.append("( %s )" % " or ".join(condition_pe_part1))
                    if len(condition_pe_part2) == 1:
                        condition_pe.append(condition_pe_part2[0])
                    elif len(condition_pe_part2) > 1:
                        condition_pe.append("( %s )" % " and ".join(condition_pe_part2))
                    # Marker that PE conditions have been added
                    pe_conditions_add = True
                    # Add to sub condition
                    subconditions.append(" and ".join(condition_pe))

                # String combinations
                cond_op = ""  # opcodes condition
                cond_hs = ""  # high scoring strings condition
                cond_ls = ""  # low scoring strings condition

                low_scoring_strings = string_rule_count - high_scoring_strings
                if high_scoring_strings > 0:
                    cond_hs = "1 of ($x*)"
                if low_scoring_strings > 0:
                    if low_scoring_strings > 10:
                        if high_scoring_strings > 0:
                            cond_ls = "4 of them"
                        else:
                            cond_ls = "8 of them"
                    else:
                        cond_ls = "all of them"

                # If low scoring and high scoring
                cond_combined = "all of them"
                needs_brackets = False
                if low_scoring_strings > 0 and high_scoring_strings > 0:
                    # If PE conditions have been added, don't be so strict with the strings
                    if pe_conditions_add:
                        cond_combined = "{0} or {1}".format(cond_hs, cond_ls)
                        needs_brackets = True
                    else:
                        cond_combined = "{0} and {1}".format(cond_hs, cond_ls)
                elif low_scoring_strings > 0 and not high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_ls)
                elif not low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_hs)
                if opcodes_included:
                    cond_op = " and all of ($op*)"

                # Opcodes (if needed)
                if cond_op or needs_brackets:
                    subconditions.append("( {0}{1} )".format(cond_combined, cond_op))
                else:
                    subconditions.append(cond_combined)

                # Now add string condition to the conditions
                if len(subconditions) == 1:
                    conditions.append(subconditions[0])
                elif len(subconditions) > 1:
                    conditions.append("( %s )" % " or ".join(subconditions))

                # Create condition string
                condition_string = " and\n      ".join(conditions)

                rule += "   condition:\n"
                rule += "      %s\n" % condition_string
                rule += "}\n\n"

                # Add to rules string
                rules += rule

                rule_count += 1
            except Exception:
                traceback.print_exc()

    # GENERATE SUPER RULES --------------------------------------------
    if not nosuper and not args.inverse:
        rules += "/* Super Rules ------------------------------------------------------------- */\n\n"
        super_rule_names = []

        print("[+] Generating Super Rules ...")
        printed_combi = {}
        for super_rule in super_rules:
            try:
                rule = ""
                # Prepare Name
                rule_name = ""
                file_list = []

                # Loop through files
                imphashes = Counter()
                for filePath in super_rule["files"]:
                    (path, file) = os.path.split(filePath)
                    file_list.append(file)
                    # Prepare name
                    fileBase = os.path.splitext(file)[0]
                    # Create a clean new name
                    cleanedName = fileBase
                    # Append it to the full name
                    rule_name += "_" + cleanedName
                    # Check if imphash of all files is equal
                    imphash = file_info[filePath]["imphash"]
                    if imphash != "-" and imphash != "":
                        imphashes.update([imphash])

                # Imphash usable
                if len(imphashes) == 1:
                    unique_imphash = list(imphashes.items())[0][0]
                    if unique_imphash in good_imphashes_db:
                        unique_imphash = ""

                # Shorten rule name (enforce maximum identifier length)
                rule_name = rule_name[:MAX_RULE_NAME_LEN]
                # Add count if rule name already taken
                if rule_name not in super_rule_names:
                    rule_name = "%s_%s" % (rule_name, super_rule_count)
                super_rule_names.append(rule_name)

                # Create a list of files
                file_listing = ", ".join(file_list)

                # File name starts with a number
                if re.search(r"^[0-9]", rule_name):
                    rule_name = "sig_" + rule_name
                # clean name from all characters that would cause errors
                rule_name = re.sub(r"[^\w]", "_", rule_name)
                # Check if already printed
                if rule_name in printed_rules:
                    printed_combi[rule_name] += 1
                    rule_name = rule_name + "_" + str(printed_combi[rule_name])
                else:
                    printed_combi[rule_name] = 1

                # Print rule title
                rule += "rule %s {\n" % rule_name
                rule += "   meta:\n"
                rule += '      description = "%s"\n' % truncate_description("%s - from files %s" % (prefix, file_listing))
                rule += '      author = "%s"\n' % args.a
                rule += '      reference = "%s"\n' % reference
                rule += '      date = "%s"\n' % get_timestamp_basic()
                for i, filePath in enumerate(super_rule["files"]):
                    rule += '      hash%s = "%s"\n' % (str(i + 1), file_info[filePath]["hash"])

                rule += "   strings:\n"

                # Adding the opcodes
                if file_opcodes.get(filePath) is None:
                    tmp_file_opcodes = {}
                else:
                    tmp_file_opcodes = file_opcodes.get(filePath)
                (rule_strings, opcodes_included, string_rule_count, high_scoring_strings) = get_rule_strings(super_rule["strings"], tmp_file_opcodes)
                rule += rule_strings

                # Condition -----------------------------------------------
                # Conditions list (will later be joined with 'or')
                conditions = []

                # 1st condition
                # Evaluate the general characteristics
                file_info_super = {}
                for filePath in super_rule["files"]:
                    file_info_super[filePath] = file_info[filePath]
                condition_strings, pe_module_necessary_gen = generate_general_condition(file_info_super)
                if pe_module_necessary_gen:
                    pe_module_necessary = True

                # 2nd condition
                # String combinations
                cond_op = ""  # opcodes condition
                cond_hs = ""  # high scoring strings condition
                cond_ls = ""  # low scoring strings condition

                low_scoring_strings = string_rule_count - high_scoring_strings
                if high_scoring_strings > 0:
                    cond_hs = "1 of ($x*)"
                if low_scoring_strings > 0:
                    if low_scoring_strings > 10:
                        if high_scoring_strings > 0:
                            cond_ls = "4 of them"
                        else:
                            cond_ls = "8 of them"
                    else:
                        cond_ls = "all of them"

                # If low scoring and high scoring
                cond_combined = "all of them"
                if low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0} and {1}".format(cond_hs, cond_ls)
                elif low_scoring_strings > 0 and not high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_ls)
                elif not low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_hs)
                if opcodes_included:
                    cond_op = " and all of ($op*)"

                condition2 = "( {0} ){1}".format(cond_combined, cond_op)
                # Only prepend general conditions when they are non-empty; joining
                # an empty string with " and " would produce "and ( … )" which is
                # invalid YARA syntax.
                if condition_strings:
                    conditions.append("{0} and {1}".format(condition_strings, condition2))
                else:
                    conditions.append(condition2)

                # 3nd condition
                # In memory detection base condition (no magic, no filesize)
                condition_pe = "all of them"
                conditions.append(condition_pe)

                # Create condition string
                condition_string = "\n      ) or ( ".join(conditions)

                rule += "   condition:\n"
                rule += "      ( %s )\n" % condition_string
                rule += "}\n\n"

                # print rule
                # Add to rules string
                rules += rule

                super_rule_count += 1
            except Exception:
                traceback.print_exc()

    try:
        # WRITING RULES TO FILE
        # PE Module -------------------------------------------------------
        if not args.noextras:
            if pe_module_necessary:
                fh.write('import "pe"\n\n')
        # RULES -----------------------------------------------------------
        if args.o:
            fh.write(rules)
    except Exception:
        traceback.print_exc()

    # PROCESS INVERSE RULES ---------------------------------------------------
    # print inverse_stats.keys()
    if args.inverse:
        print("[+] Generating inverse rules ...")
        inverse_rules = ""
        # Apply intelligent filters -------------------------------------------
        print("[+] Applying intelligent filters to string findings ...")
        for fileName in inverse_stats:
            print("[-] Filtering string set for %s ..." % fileName)

            # Replace the original string set with the filtered one
            string_set = inverse_stats[fileName]
            inverse_stats[fileName] = []
            inverse_stats[fileName] = filter_string_set(string_set)

            # Preset if empty
            if fileName not in file_opcodes:
                file_opcodes[fileName] = {}

        # GENERATE INVERSE RULES -------------------------------------------
        fh.write("/* Inverse Rules ------------------------------------------------------------- */\n\n")

        for fileName in inverse_stats:
            try:
                rule = ""
                # Create a clean new name
                cleanedName = fileName.replace(".", "_")
                # Add ANOMALY
                cleanedName += "_ANOMALY"
                # File name starts with a number
                if re.search(r"^[0-9]", cleanedName):
                    cleanedName = "sig_" + cleanedName
                # clean name from all characters that would cause errors
                cleanedName = re.sub(r"[^\w]", "_", cleanedName)
                # Enforce maximum rule name length (long names cause YARA parse errors)
                cleanedName = cleanedName[:MAX_RULE_NAME_LEN]
                # Check if already printed
                if cleanedName in printed_rules:
                    printed_rules[cleanedName] += 1
                    cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
                else:
                    printed_rules[cleanedName] = 1

                # Print rule title ----------------------------------------
                rule += "rule %s {\n" % cleanedName

                # Meta data -----------------------------------------------
                rule += "   meta:\n"
                rule += '      description = "%s"\n' % truncate_description("%s for anomaly detection - file %s" % (prefix, fileName))
                rule += '      author = "%s"\n' % args.a
                rule += '      reference = "%s"\n' % reference
                rule += '      date = "%s"\n' % get_timestamp_basic()
                for i, hash in enumerate(file_info[fileName]["hashes"]):
                    rule += '      hash%s = "%s"\n' % (str(i + 1), hash)

                rule += "   strings:\n"

                # Get the strings -----------------------------------------
                # Rule String generation
                (rule_strings, opcodes_included, string_rule_count, high_scoring_strings) = get_rule_strings(inverse_stats[fileName], file_opcodes[fileName])
                rule += rule_strings

                # Condition -----------------------------------------------
                folderNames = ""
                if not args.nodirname:
                    folderNames += "and ( filepath matches /"
                    folderNames += "$/ or filepath matches /".join(file_info[fileName]["folder_names"])
                    folderNames += "$/ )"
                condition = 'filename == "%s" %s and not ( all of them )' % (fileName, folderNames)

                rule += "   condition:\n"
                rule += "      %s\n" % condition
                rule += "}\n\n"

                # print rule
                # Add to rules string
                inverse_rules += rule

            except Exception:
                traceback.print_exc()

        try:
            # Try to write rule to file
            if args.o:
                fh.write(inverse_rules)
            inverse_rule_count += 1
        except Exception:
            traceback.print_exc()

    # Close the rules file --------------------------------------------
    if args.o:
        try:
            fh.close()
        except Exception:
            traceback.print_exc()

    # Print rules to command line -------------------------------------
    if args.debug:
        print(rules)

    return (rule_count, inverse_rule_count, super_rule_count)


def get_rule_strings(string_elements, opcode_elements):
    rule_strings = ""
    high_scoring_strings = 0
    string_rule_count = 0

    # Adding the strings --------------------------------------
    for i, string in enumerate(string_elements):
        # Collect the data
        is_fullword = True
        initial_string = string
        enc = " ascii"
        base64comment = ""
        hexEncComment = ""
        reversedComment = ""
        fullword = ""
        pestudio_comment = ""
        score_comment = ""
        goodware_comment = ""

        if string in good_strings_db:
            goodware_comment = " /* Goodware String - occured %s times */" % (good_strings_db[string])

        if string in stringScores:
            if args.score:
                score_comment += " /* score: '%.2f'*/" % (stringScores[string])
        else:
            print("NO SCORE: %s" % string)

        if string[:8] == "UTF16LE:":
            string = string[8:]
            enc = " wide"
        if string in base64strings:
            base64comment = " /* base64 encoded string '%s' */" % base64strings[string].decode()
        if string in hexEncStrings:
            hexEncComment = " /* hex encoded string '%s' */" % removeNonAsciiDrop(hexEncStrings[string]).decode()
        if string in pestudioMarker and args.score:
            pestudio_comment = " /* PEStudio Blacklist: %s */" % pestudioMarker[string]
        if string in reversedStrings:
            reversedComment = " /* reversed goodware string '%s' */" % reversedStrings[string]

        # Extra checks
        if is_hex_encoded(string, check_length=False):
            is_fullword = False

        # Checking string length
        if len(string) >= args.s:
            # cut string
            string = string[: args.s].rstrip("\\")
            # not fullword anymore
            is_fullword = False
        # Show as fullword
        if is_fullword:
            fullword = " fullword"

        # Now compose the rule line
        if float(stringScores[initial_string]) > score_highly_specific:
            high_scoring_strings += 1
            rule_strings += '      $x%s = "%s"%s%s%s%s%s%s%s%s\n' % (str(i + 1), string, fullword, enc, base64comment, reversedComment, pestudio_comment, score_comment, goodware_comment, hexEncComment)
        else:
            rule_strings += '      $s%s = "%s"%s%s%s%s%s%s%s%s\n' % (str(i + 1), string, fullword, enc, base64comment, reversedComment, pestudio_comment, score_comment, goodware_comment, hexEncComment)

        # If too many string definitions found - cut it at the
        # count defined via command line param -rc
        if (i + 1) >= strings_per_rule:
            break

        string_rule_count += 1

    # Adding the opcodes --------------------------------------
    opcodes_included = False
    if len(opcode_elements) > 0:
        rule_strings += "\n"
        for i, opcode in enumerate(opcode_elements):
            rule_strings += "      $op%s = { %s }\n" % (str(i), opcode)
            opcodes_included = True
    else:
        if args.opcodes:
            print("[-] Not enough unique opcodes found to include them")

    return rule_strings, opcodes_included, string_rule_count, high_scoring_strings


def get_strings(string_elements):
    """
    Get a dictionary of all string types
    :param string_elements:
    :return:
    """
    strings = {"ascii": [], "wide": [], "base64 encoded": [], "hex encoded": [], "reversed": []}

    # Adding the strings --------------------------------------
    for i, string in enumerate(string_elements):
        if string[:8] == "UTF16LE:":
            string = string[8:]
            strings["wide"].append(string)
        elif string in base64strings:
            strings["base64 encoded"].append(string)
        elif string in hexEncStrings:
            strings["hex encoded"].append(string)
        elif string in reversedStrings:
            strings["reversed"].append(string)
        else:
            strings["ascii"].append(string)

    return strings


def write_strings(filePath, strings, output_dir, scores):
    """
    Writes string information to an output file
    :param filePath:
    :param strings:
    :param output_dir:
    :param scores:
    :return:
    """
    SECTIONS = ["ascii", "wide", "base64 encoded", "hex encoded", "reversed"]
    # File
    filename = os.path.basename(filePath)
    strings_filename = os.path.join(output_dir, "%s_strings.txt" % filename)
    print("[+] Writing strings to file %s" % strings_filename)
    # Strings
    output_string = []
    for key in SECTIONS:
        # Skip empty
        if len(strings[key]) < 1:
            continue
        # Section
        output_string.append("%s Strings" % key.upper())
        output_string.append("------------------------------------------------------------------------")
        for string in strings[key]:
            if scores:
                score = "unknown"
                if key == "wide":
                    score = stringScores["UTF16LE:%s" % string]
                else:
                    score = stringScores[string]
                output_string.append("%d;%s" % (score, string))
            else:
                output_string.append(string)
        # Empty line between sections
        output_string.append("\n")
    with open(strings_filename, "w", encoding="utf-8", errors="replace") as fh:
        fh.write("\n".join(output_string))


def initialize_pestudio_strings():
    pestudio_strings = {}

    tree = etree.parse(get_abs_path(PE_STRINGS_FILE))

    pestudio_strings["strings"] = tree.findall(".//string")
    pestudio_strings["av"] = tree.findall(".//av")
    pestudio_strings["folder"] = tree.findall(".//folder")
    pestudio_strings["os"] = tree.findall(".//os")
    pestudio_strings["reg"] = tree.findall(".//reg")
    pestudio_strings["guid"] = tree.findall(".//guid")
    pestudio_strings["ssdl"] = tree.findall(".//ssdl")
    pestudio_strings["ext"] = tree.findall(".//ext")
    pestudio_strings["agent"] = tree.findall(".//agent")
    pestudio_strings["oid"] = tree.findall(".//oid")
    pestudio_strings["priv"] = tree.findall(".//priv")

    # Obsolete
    # for elem in string_elems:
    #    strings.append(elem.text)

    return pestudio_strings


def get_pestudio_score(string):
    for type in pestudio_strings:
        for elem in pestudio_strings[type]:
            # Full match
            if elem.text.lower() == string.lower():
                # Exclude the "extension" black list for now
                if type != "ext":
                    return 5, type
    return 0, ""


def get_opcode_string(opcode):
    return " ".join(opcode[i : i + 2] for i in range(0, len(opcode), 2))


def get_uint_string(magic):
    if len(magic) == 2:
        return "uint8(0) == 0x{0}{1}".format(magic[0], magic[1])
    if len(magic) == 4:
        return "uint16(0) == 0x{2}{3}{0}{1}".format(magic[0], magic[1], magic[2], magic[3])
    return ""


def get_file_range(size):
    size_string = ""
    try:
        # max sample size - args.fm times the original size
        max_size_b = size * args.fm
        # Minimum size
        if max_size_b < 1024:
            max_size_b = 1024
        # in KB
        max_size = int(max_size_b / 1024)
        max_size_kb = max_size
        # Round
        if len(str(max_size)) == 2:
            max_size = int(round(max_size, -1))
        elif len(str(max_size)) == 3:
            max_size = int(round(max_size, -2))
        elif len(str(max_size)) == 4:
            max_size = int(round(max_size, -3))
        elif len(str(max_size)) >= 5:
            max_size = int(round(max_size, -3))
        size_string = "filesize < {0}KB".format(max_size)
        if args.debug:
            print("File Size Eval: SampleSize (b): {0} SizeWithMultiplier (b/Kb): {1} / {2} RoundedSize: {3}".format(str(size), str(max_size_b), str(max_size_kb), str(max_size)))
    except Exception:
        traceback.print_exc()
    return size_string


def get_timestamp_basic(date_obj=None):
    if not date_obj:
        date_obj = datetime.datetime.now()
    date_str = date_obj.strftime("%Y-%m-%d")
    return date_str


def is_ascii_char(b, padding_allowed=False):
    if padding_allowed:
        if (ord(b) < 127 and ord(b) > 31) or ord(b) == 0:
            return 1
    else:
        if ord(b) < 127 and ord(b) > 31:
            return 1
    return 0


def is_ascii_string(string, padding_allowed=False):
    for b in [i.to_bytes(1, sys.byteorder) for i in string]:
        if padding_allowed:
            if not ((ord(b) < 127 and ord(b) > 31) or ord(b) == 0):
                return 0
        else:
            if not (ord(b) < 127 and ord(b) > 31):
                return 0
    return 1


def is_base_64(s):
    return (len(s) % 4 == 0) and re.match("^[A-Za-z0-9+/]+[=]{0,2}$", s)


def is_hex_encoded(s, check_length=True):
    if re.match("^[A-Fa-f0-9]+$", s):
        if check_length:
            if len(s) % 2 == 0:
                return True
        else:
            return True
    return False


# TODO: Still buggy after port to Python3
def extract_hex_strings(s):
    strings = []
    hex_strings = re.findall(b"([a-fA-F0-9]{10,})", s)
    for string in list(hex_strings):
        hex_strings += string.split(b"0000")
        hex_strings += string.split(b"0d0a")
        hex_strings += re.findall(b"((?:0000|002[a-f0-9]|00[3-9a-f][0-9a-f]){6,})", string, re.IGNORECASE)
    hex_strings = list(set(hex_strings))
    # ASCII Encoded Strings
    for string in hex_strings:
        for x in string.split(b"00"):
            if len(x) > 10:
                strings.append(x)
    # WIDE Encoded Strings
    for string in hex_strings:
        try:
            if len(string) % 2 != 0 or len(string) < 8:
                continue
            # Skip
            if b"0000" in string:
                continue
            dec = string.replace(b"00", b"")
            if is_ascii_string(dec, padding_allowed=False):
                strings.append(string)
        except Exception:
            traceback.print_exc()
    return strings


def removeNonAsciiDrop(string):
    nonascii = "error"
    try:
        byte_list = [i.to_bytes(1, sys.byteorder) for i in string]
        # Generate a new string without disturbing characters
        nonascii = b"".join(i for i in byte_list if ord(i) < 127 and ord(i) > 31)
    except Exception:
        traceback.print_exc()
        pass
    return nonascii


def save(object, filename):
    # Large goodware databases become painfully slow if we pretty-print JSON
    # into gzip directly. Write compact JSON to a temp file first, then atomically
    # replace the destination so interrupted updates do not leave a corrupt DB.
    abs_filename = get_abs_path(filename)
    target_dir = os.path.dirname(abs_filename) or "."
    os.makedirs(target_dir, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(prefix=os.path.basename(abs_filename) + ".", suffix=".tmp", dir=target_dir)

    try:
        with os.fdopen(fd, "wb") as raw_file:
            with gzip.GzipFile(fileobj=raw_file, mode="wb", compresslevel=1, mtime=0) as gz_file:
                with codecs.getwriter("utf-8")(gz_file) as writer:
                    json.dump(object, writer, ensure_ascii=False, separators=(",", ":"))
        os.replace(temp_path, abs_filename)
    except Exception:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        raise


def load(filename):
    abs_filename = get_abs_path(filename)
    with gzip.open(abs_filename, "rt", encoding="utf-8", errors="replace") as file:
        return json.load(file)


def update_databases():
    # Preparations
    try:
        dbDir = "./dbs/"
        if not os.path.exists(dbDir):
            os.makedirs(dbDir)
    except Exception:
        if args.debug:
            traceback.print_exc()
        print("Error while creating the database directory ./dbs")
        sys.exit(1)

    # Downloading current repository
    try:
        for filename, repo_url in REPO_URLS.items():
            print("Downloading %s from %s ..." % (filename, repo_url))
            with urllib.request.urlopen(repo_url) as response, open("./dbs/%s" % filename, "wb") as out_file:
                shutil.copyfileobj(response, out_file)
    except Exception:
        if args.debug:
            traceback.print_exc()
        print("Error while downloading the database file - check your Internet connection (try to run it with --debug to see the full error message)")
        sys.exit(1)


def processSampleDir(targetDir):
    """
    Processes samples in a given directory and creates a yara rule file
    :param directory:
    :return:
    """
    # Extract all information
    (sample_string_stats, sample_opcode_stats, file_info) = parse_sample_dir(targetDir, args.nr, generateInfo=True, onlyRelevantExtensions=args.oe)

    # Evaluate Strings
    (file_strings, file_opcodes, combinations, super_rules, inverse_stats) = sample_string_evaluation(sample_string_stats, sample_opcode_stats, file_info)

    # Create Rule Files
    (rule_count, inverse_rule_count, super_rule_count) = generate_rules(file_strings, file_opcodes, super_rules, file_info, inverse_stats)

    if args.inverse:
        print("[=] Generated %s INVERSE rules." % str(inverse_rule_count))
    else:
        print("[=] Generated %s SIMPLE rules." % str(rule_count))
        if not nosuper:
            print("[=] Generated %s SUPER rules." % str(super_rule_count))
        print("[=] All rules written to %s" % args.o)


def emptyFolder(dir):
    """
    Removes all files from a given folder
    :return:
    """
    for file in os.listdir(dir):
        filePath = os.path.join(dir, file)
        try:
            if os.path.isfile(filePath):
                print("[!] Removing %s ..." % filePath)
                os.unlink(filePath)
        except Exception as e:
            print(e)


def getReference(ref):
    """
    Get a reference string - if the provided string is the path to a text file, then read the contents and return it as
    reference
    :param ref:
    :return:
    """
    if os.path.exists(ref):
        reference = getFileContent(ref)
        print("[+] Read reference from file %s > %s" % (ref, reference))
        return reference
    else:
        return ref


def getIdentifier(id, path):
    """
    Get a identifier string - if the provided string is the path to a text file, then read the contents and return it as
    reference, otherwise use the last element of the full path
    :param ref:
    :return:
    """
    # Identifier
    if id == "not set" or not os.path.exists(id):
        # Identifier is the highest folder name
        return os.path.basename(path.rstrip("/"))
    else:
        # Read identifier from file
        identifier = getFileContent(id)
        print("[+] Read identifier from file %s > %s" % (id, identifier))
        return identifier


def getPrefix(prefix, identifier):
    """
    Get a prefix string for the rule description based on the identifier
    :param prefix:
    :param identifier:
    :return:
    """
    if prefix == "Auto-generated rule":
        return identifier
    else:
        return prefix


def getFileContent(file):
    """
    Gets the contents of a file (limited to 1024 characters)
    :param file:
    :return:
    """
    try:
        with open(file, encoding="utf-8", errors="replace") as f:
            return f.read(1024)
    except Exception:
        return "not found"


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    print("> yarGen's work has been interrupted")
    sys.exit(0)


def print_welcome():
    print("------------------------------------------------------------------------")
    print("                   _____            ")
    print("    __ _____ _____/ ___/__ ___      ")
    print("   / // / _ `/ __/ (_ / -_) _ \\     ")
    print("   \\_, /\\_,_/_/  \\___/\\__/_//_/     ")
    print("  /___/  Yara Rule Generator        ")
    print("         Florian Roth, August 2023, Version %s" % __version__)
    print("   ")
    print("  Note: Rules have to be post-processed")
    print("  See this post for details: https://medium.com/@cyb3rops/121d29322282")
    print("------------------------------------------------------------------------")


# MAIN ################################################################
if __name__ == "__main__":
    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # Parse Arguments
    parser = argparse.ArgumentParser(description="yarGen")

    group_creation = parser.add_argument_group("Rule Creation")
    group_creation.add_argument("-m", help="Path to scan for malware")
    group_creation.add_argument("-y", help="Minimum string length to consider (default=8)", metavar="min-size", default=8)
    group_creation.add_argument("-z", help="Minimum score to consider (default=0)", metavar="min-score", default=0)
    group_creation.add_argument("-x", help="Score required to set string as 'highly specific string' (default: 30)", metavar="high-scoring", default=30)
    group_creation.add_argument("-w", help="Minimum number of strings that overlap to create a super rule (default: 5)", metavar="superrule-overlap", default=5)
    group_creation.add_argument("-s", help="Maximum length to consider (default=128)", metavar="max-size", default=128, type=int)
    group_creation.add_argument("-rc", help="Maximum number of strings per rule (default=20, intelligent filtering will be applied)", metavar="maxstrings", default=20)
    group_creation.add_argument("--excludegood", help="Force the exclude all goodware strings", action="store_true", default=False)

    group_output = parser.add_argument_group("Rule Output")
    group_output.add_argument("-o", help="Output rule file", metavar="output_rule_file", default="yargen_rules.yar")
    group_output.add_argument("-e", help="Output directory for string exports", metavar="output_dir_strings", default="")
    group_output.add_argument("-a", help="Author Name", metavar="author", default="yarGen Rule Generator")
    group_output.add_argument("-r", help="Reference (can be string or text file)", metavar="ref", default="https://github.com/Neo23x0/yarGen")
    group_output.add_argument("-l", help="License", metavar="lic", default="")
    group_output.add_argument("-p", help="Prefix for the rule description", metavar="prefix", default="Auto-generated rule")
    group_output.add_argument("-b", help='Text file from which the identifier is read (default: last folder name in the full path, e.g. "myRAT" if -m points to /mnt/mal/myRAT)', metavar="identifier", default="not set")
    group_output.add_argument("--score", help="Show the string scores as comments in the rules", action="store_true", default=False)
    group_output.add_argument("--strings", help="Show the string scores as comments in the rules", action="store_true", default=False)
    group_output.add_argument("--nosimple", help="Skip simple rule creation for files included in super rules", action="store_true", default=False)
    group_output.add_argument("--nomagic", help="Don't include the magic header condition statement", action="store_true", default=False)
    group_output.add_argument("--nofilesize", help="Don't include the filesize condition statement", action="store_true", default=False)
    group_output.add_argument("-fm", help="Multiplier for the maximum 'filesize' condition value (default: 3)", default=3)
    group_output.add_argument("--globalrule", help="Create global rules (improved rule set speed)", action="store_true", default=False)
    group_output.add_argument("--nosuper", action="store_true", default=False, help="Don't try to create super rules that match against various files")
    group_output.add_argument("--sig-yaml", help="Path to output HydraDragonSig YAML rules", metavar="output_sig_yaml", default="")
    group_output.add_argument("--sig-super", action="store_true", default=False, help="Also write super rules (strings shared by several samples) to the HydraDragonSig YAML. Off by default: shared strings are more often runtime / packer / installer strings, so test them for false positives first")

    group_db = parser.add_argument_group("Database Operations")
    group_db.add_argument("--update", action="store_true", default=False, help="Update the local strings and opcodes dbs from the online repository")
    group_db.add_argument("-g", help="Path to scan for goodware (dont use the database shipped with yaraGen)")
    group_db.add_argument("--create-mal-db", metavar="malware-dir", help="Scan a malware directory and create a malicious string database (mal-strings-identifier.db)")
    group_db.add_argument("-mal", dest="create_mal_db", help=argparse.SUPPRESS)
    group_db.add_argument("-u", action="store_true", default=False, help="Update local standard goodware database with a new analysis result (used with -g)")
    group_db.add_argument("-c", action="store_true", default=False, help='Create new local goodware database (use with -g and optionally -i "identifier")')
    group_db.add_argument("-i", default="", help="Specify an identifier for the newly created databases (good-strings-identifier.db, good-opcodes-identifier.db)")

    group_general = parser.add_argument_group("General Options")
    group_general.add_argument("--dropzone", action="store_true", default=False, help="Dropzone mode - monitors a directory [-m] for new samples to process. WARNING: Processed files will be deleted!")
    group_general.add_argument("--nr", action="store_true", default=False, help="Do not recursively scan directories")
    group_general.add_argument("--oe", action="store_true", default=False, help="Only scan executable extensions EXE, DLL, ASP, JSP, PHP, BIN, INFECTED")
    group_general.add_argument("-fs", help="Max file size in MB to analyze (default=10)", metavar="size-in-MB", default=10)
    group_general.add_argument("--noextras", action="store_true", default=False, help="Don't use extras like Imphash or PE header specifics")
    group_general.add_argument("--ai", action="store_true", default=False, help="Create output to be used as ChatGPT4 input")
    group_general.add_argument("--debug", action="store_true", default=False, help="Debug output")
    group_general.add_argument("--trace", action="store_true", default=False, help="Trace output")

    group_opcode = parser.add_argument_group("Other Features")
    group_opcode.add_argument("--opcodes", action="store_true", default=False, help="Do use the OpCode feature (use this if not enough high scoring strings can be found)")
    group_opcode.add_argument("--no-opcodes", action="store_true", default=False, help="Never use opcodes, even when the output format would otherwise enable them (strings-only rules)")
    group_opcode.add_argument("-n", help="Number of opcodes to add if not enough high scoring string could be found (default=3)", metavar="opcode-num", default=3)
    group_opcode.add_argument("--opcode-max-mb", help="Skip opcode extraction when the entrypoint section is bigger than this (MB). Opcodes are kept for short code; long code is carried by strings. 0 = no cap (default=4)", metavar="opcode-max-MB", default=4)

    group_inverse = parser.add_argument_group("Inverse Mode (unstable)")
    group_inverse.add_argument("--inverse", help=argparse.SUPPRESS, action="store_true", default=False)
    group_inverse.add_argument("--nodirname", help=argparse.SUPPRESS, action="store_true", default=False)
    group_inverse.add_argument("--noscorefilter", help=argparse.SUPPRESS, action="store_true", default=False)

    group_creation.add_argument("--meaningful-words-only", help="Only include strings containing meaningful words (default: False)", action="store_true", default=False)

    args = parser.parse_args()

    # Print Welcome
    print_welcome()

    if not args.update and not args.m and not args.g and not args.create_mal_db:
        parser.print_help()
        print("")
        print("""
[E] You have to select --update to update yarGens database or -m for signature generation or -g for the 
creation of goodware string collections 
(see https://github.com/Neo23x0/yarGen#examples for more details)

Recommended command line:
    python yarGen.py -a 'Your Name' --opcodes --dropzone -m ./dropzone""")
        sys.exit(1)

    # Update
    if args.update:
        update_databases()
        print("[+] Updated databases - you can now start creating YARA rules")
        sys.exit(0)

    # Check if the meaningful-words-only flag is set and handle accordingly
    if args.meaningful_words_only:
        print("[+] Only including strings containing meaningful words (non-trivial, dictionary-based).")

    # Typical input erros
    if args.m:
        if os.path.isfile(args.m):
            print("[E] Input is a file, please use a directory instead (-m path)")
            sys.exit(0)

    # Opcodes evaluation or not.
    # --sig-yaml / .yaml output does NOT force opcodes: strings carry the
    # rules, opcodes are only used when explicitly asked with --opcodes.
    # --no-opcodes always wins (explicit opt-out).
    use_opcodes = False
    if getattr(args, "opcodes", False) and not getattr(args, "no_opcodes", False):
        use_opcodes = True

    # Read PEStudio string list
    pestudio_strings = {}
    pestudio_available = False

    # Super Rule Generation
    nosuper = args.nosuper

    # Identifier
    sourcepath = args.m
    if args.g:
        sourcepath = args.g
    if args.create_mal_db:
        sourcepath = args.create_mal_db
    identifier = getIdentifier(args.b, sourcepath)
    print("[+] Using identifier '%s'" % identifier)

    # Reference
    reference = getReference(args.r)
    print("[+] Using reference '%s'" % reference)

    # Prefix
    prefix = getPrefix(args.p, identifier)
    print("[+] Using prefix '%s'" % prefix)

    if os.path.isfile(get_abs_path(PE_STRINGS_FILE)):
        print("[+] Processing PEStudio strings ...")
        pestudio_strings = initialize_pestudio_strings()
        pestudio_available = True

    # Highly specific string score
    score_highly_specific = int(args.x)

    # Scan malware files for Malicious Database creation (--create-mal-db)
    if args.create_mal_db:
        print("[+] Processing MALWARE files for Malicious Database creation ...")
        mal_strings_db, mal_opcodes_db, mal_imphashes_db, mal_exports_db = parse_good_dir(args.create_mal_db, args.nr, args.oe)

        # Evaluate identifier
        db_identifier = ""
        if args.i != "":
            db_identifier = "-%s" % args.i
        else:
            db_identifier = "-%s" % identifier

        strings_db = "./dbs/mal-strings%s.db" % db_identifier
        opcodes_db = "./dbs/mal-opcodes%s.db" % db_identifier
        imphashes_db = "./dbs/mal-imphashes%s.db" % db_identifier
        exports_db = "./dbs/mal-exports%s.db" % db_identifier

        if args.excludegood:
            print("[+] Excluding goodware strings from malicious database (--excludegood)...")
            good_strings = set()
            for db_f in glob.glob("./dbs/good-strings*.db"):
                try:
                    good_d = load(get_abs_path(db_f))
                    good_strings.update(good_d.keys())
                except Exception:
                    pass
            filtered_mal = Counter()
            dropped_cnt = 0
            for s, cnt in mal_strings_db.items():
                if s in good_strings:
                    dropped_cnt += 1
                else:
                    filtered_mal[s] = cnt
            print(f"[+] Dropped {dropped_cnt:,} goodware collisions! Kept {len(filtered_mal):,} pure malware strings.")
            mal_strings_db = filtered_mal

        print("[+] Creating local malware databases ...")
        print("[+] Saving '%s' (%s entries) ..." % (strings_db, len(mal_strings_db)))
        save(mal_strings_db, strings_db)
        if use_opcodes:
            save(mal_opcodes_db, opcodes_db)
        save(mal_imphashes_db, imphashes_db)
        save(mal_exports_db, exports_db)
        print("[+] Successfully created Malicious Databases in ./dbs/ for Machine Learning!")
        sys.exit(0)

    # Scan goodware files
    if args.g:
        print("[+] Processing goodware files ...")
        good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = parse_good_dir(args.g, args.nr, args.oe)

        # Update existing databases
        if args.u:
            try:
                print("[+] Updating databases ...")

                # Evaluate the database identifiers
                db_identifier = ""
                if args.i != "":
                    db_identifier = "-%s" % args.i
                strings_db = "./dbs/good-strings%s.db" % db_identifier
                opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
                imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
                exports_db = "./dbs/good-exports%s.db" % db_identifier

                # Strings -----------------------------------------------------
                print("[+] Updating %s ..." % strings_db)
                good_pickle = load(get_abs_path(strings_db))
                print("Old string database entries: %s" % len(good_pickle))
                good_pickle.update(good_strings_db)
                print("New string database entries: %s" % len(good_pickle))
                save(good_pickle, strings_db)

                # Opcodes -----------------------------------------------------
                print("[+] Updating %s ..." % opcodes_db)
                good_opcode_pickle = load(get_abs_path(opcodes_db))
                print("Old opcode database entries: %s" % len(good_opcode_pickle))
                good_opcode_pickle.update(good_opcodes_db)
                print("New opcode database entries: %s" % len(good_opcode_pickle))
                save(good_opcode_pickle, opcodes_db)

                # Imphashes ---------------------------------------------------
                print("[+] Updating %s ..." % imphashes_db)
                good_imphashes_pickle = load(get_abs_path(imphashes_db))
                print("Old opcode database entries: %s" % len(good_imphashes_pickle))
                good_imphashes_pickle.update(good_imphashes_db)
                print("New opcode database entries: %s" % len(good_imphashes_pickle))
                save(good_imphashes_pickle, imphashes_db)

                # Exports -----------------------------------------------------
                print("[+] Updating %s ..." % exports_db)
                good_exports_pickle = load(get_abs_path(exports_db))
                print("Old opcode database entries: %s" % len(good_exports_pickle))
                good_exports_pickle.update(good_exports_db)
                print("New opcode database entries: %s" % len(good_exports_pickle))
                save(good_exports_pickle, exports_db)

            except Exception:
                traceback.print_exc()

        # Create new databases
        if args.c:
            print("[+] Creating local database ...")
            # Evaluate the database identifiers
            db_identifier = ""
            if args.i != "":
                db_identifier = "-%s" % args.i
            strings_db = "./dbs/good-strings%s.db" % db_identifier
            opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
            imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
            exports_db = "./dbs/good-exports%s.db" % db_identifier

            # Creating the databases
            print("[+] Using '%s' as filename for newly created strings database" % strings_db)
            print("[+] Using '%s' as filename for newly created opcodes database" % opcodes_db)
            print("[+] Using '%s' as filename for newly created opcodes database" % imphashes_db)
            print("[+] Using '%s' as filename for newly created opcodes database" % exports_db)

            try:
                if os.path.isfile(strings_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % strings_db)
                    os.remove(strings_db)
                if os.path.isfile(opcodes_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % opcodes_db)
                    os.remove(opcodes_db)
                if os.path.isfile(imphashes_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % imphashes_db)
                    os.remove(imphashes_db)
                if os.path.isfile(exports_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % exports_db)
                    os.remove(exports_db)

                # Strings
                good_json = Counter()
                good_json = good_strings_db
                # Opcodes
                good_op_json = Counter()
                good_op_json = good_opcodes_db
                # Imphashes
                good_imphashes_json = Counter()
                good_imphashes_json = good_imphashes_db
                # Exports
                good_exports_json = Counter()
                good_exports_json = good_exports_db

                # Save
                save(good_json, strings_db)
                save(good_op_json, opcodes_db)
                save(good_imphashes_json, imphashes_db)
                save(good_exports_json, exports_db)

                print(
                    "New database with %d string, %d opcode, %d imphash, %d export entries created. "
                    "(remember to use --opcodes to extract opcodes from the samples and create the opcode databases)" % (len(good_strings_db), len(good_opcodes_db), len(good_imphashes_db), len(good_exports_db))
                )
            except Exception:
                traceback.print_exc()

    # Analyse malware samples and create rules
    else:
        print("[+] Reading goodware strings from database 'good-strings.db' ...")
        print("    (This could take some time and uses several Gigabytes of RAM depending on your db size)")

        good_strings_db = Counter()
        good_opcodes_db = Counter()
        good_imphashes_db = Counter()
        good_exports_db = Counter()

        opcodes_num = 0
        strings_num = 0
        imphash_num = 0
        exports_num = 0

        # Initialize all databases
        for file in os.listdir(get_abs_path("./dbs/")):
            if not file.endswith(".db"):
                continue
            filePath = os.path.join("./dbs/", file)
            # String databases
            if file.startswith("good-strings"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_json = load(get_abs_path(filePath))
                    good_strings_db.update(good_json)
                    print("[+] Total: %s / Added %d entries" % (len(good_strings_db), len(good_strings_db) - strings_num))
                    strings_num = len(good_strings_db)
                except Exception:
                    traceback.print_exc()
            # Opcode databases
            if file.startswith("good-opcodes"):
                try:
                    if use_opcodes:
                        print("[+] Loading %s ..." % filePath)
                        good_op_json = load(get_abs_path(filePath))
                        good_opcodes_db.update(good_op_json)
                        print("[+] Total: %s (removed duplicates) / Added %d entries" % (len(good_opcodes_db), len(good_opcodes_db) - opcodes_num))
                        opcodes_num = len(good_opcodes_db)
                except Exception:
                    use_opcodes = False
                    traceback.print_exc()
            # Imphash databases
            if file.startswith("good-imphash"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_imphashes_json = load(get_abs_path(filePath))
                    good_imphashes_db.update(good_imphashes_json)
                    print("[+] Total: %s / Added %d entries" % (len(good_imphashes_db), len(good_imphashes_db) - imphash_num))
                    imphash_num = len(good_imphashes_db)
                except Exception:
                    traceback.print_exc()
            # Export databases
            if file.startswith("good-exports"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_exports_json = load(get_abs_path(filePath))
                    good_exports_db.update(good_exports_json)
                    print("[+] Total: %s / Added %d entries" % (len(good_exports_db), len(good_exports_db) - exports_num))
                    exports_num = len(good_exports_db)
                except Exception:
                    traceback.print_exc()

        if use_opcodes and len(good_opcodes_db) < 1:
            print("[E] Missing goodware opcode databases.    Please run 'yarGen.py --update' to retrieve the newest database set.")
            use_opcodes = False

        if len(good_exports_db) < 1 and len(good_imphashes_db) < 1:
            print("[E] Missing goodware imphash/export databases.     Please run 'yarGen.py --update' to retrieve the newest database set.")

        if len(good_strings_db) < 1 and not args.c:
            print("[E] Error - no goodware databases found.     Please run 'yarGen.py --update' to retrieve the newest database set.")
            sys.exit(1)

    # If malware directory given
    if args.m:
        # Deactivate super rule generation if there's only a single file in the folder
        if len(os.listdir(args.m)) < 2:
            nosuper = True

        # AI input generation
        strings_per_rule = int(args.rc)
        if args.ai:
            strings_per_rule = 200

        # Special strings
        base64strings = {}
        reversedStrings = {}
        hexEncStrings = {}
        pestudioMarker = {}
        stringScores = {}

        # Dropzone mode
        if args.dropzone:
            # Monitoring folder for changes
            print("Monitoring %s for new sample files (processed samples will be removed)" % args.m)
            while True:
                if len(os.listdir(args.m)) > 0:
                    # Deactivate super rule generation if there's only a single file in the folder
                    if len(os.listdir(args.m)) < 2:
                        nosuper = True
                    else:
                        nosuper = False
                    # Read a new identifier
                    identifier = getIdentifier(args.b, args.m)
                    # Read a new reference
                    reference = getReference(args.r)
                    # Generate a new description prefix
                    prefix = getPrefix(args.p, identifier)
                    # Process the samples
                    processSampleDir(args.m)
                    # Delete all samples from the dropzone folder
                    emptyFolder(args.m)
                time.sleep(1)
        else:
            # Scan malware files
            print("[+] Processing malware files ...")
            processSampleDir(args.m)

        print("[+] yarGen run finished")
