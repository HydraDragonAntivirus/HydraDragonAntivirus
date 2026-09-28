#!/usr/bin/env python3
"""
hydragen - signature generator for HydraDragonSig.

Ported from ``yarGen.py`` (same repository, ``yarGen/``). The extraction,
scoring and rule-synthesis logic is the same; the output is not YARA-only any
more. ``--format`` picks the backend:

  yara    classic yarGen output: ``strings:`` / ``condition:`` blocks
  hydra   HydraDragonSig native YAML, consumed by ``hydradragonsig``
  both    write both files side by side (YARA first, as the lossless reference)

Why keep both: the YARA emitter is lossless, so it is the specification of what
was detected. The hydra emitter is a best-effort native rendering, because
HydraDragonSig's condition vocabulary does not cover every YARA construct. Any
construct that cannot be expressed is collected and reported instead of being
silently dropped - see ``--strict``.

No third-party dependency beyond ``lief`` (already required by yarGen). The YAML
is emitted directly rather than through PyYAML, so the exact field order and
quoting stay under our control and no extra install step is needed.

Usage:
    python hydragen.py --sample-dir ./malware --output ./gen --format both
    python hydragen.py --sample-dir ./m --good-dir ./benign --format hydra
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import re
import string as _string
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Sequence

try:
    import lief
except ImportError:  # pragma: no cover - dependency check
    sys.exit("hydragen: 'lief' is required (pip install lief)")

__version__ = "1.0.0"

DEFAULT_MIN_STRING = 6
DEFAULT_MAX_STRING = 64
#: The regexes are compiled at import time, so the shortest run they will ever
#: look for is baked in. ``--min-string`` can raise this at runtime, never lower it.
MIN_STRING = 6
#: Hard cap, matching yarGen: some YARA builds reject very long literals.
MAX_STRING_BYTES = 64
#: yarGen keeps a few hundred candidate strings per sample; beyond that the
#: ranking stops being useful and the rule stops being reviewable.
MAX_STRINGS_PER_RULE = 60
MAX_OPCODES_PER_RULE = 12
#: A sample string is interesting only if it is rarer in the benign corpus than
#: in the malware corpus, by at least this much (0..1).
MIN_DISCRIMINATION = 0.15
#: PEStudio-style "strange string" score at or above which a string is treated
#: as high scoring and is allowed to satisfy a condition on its own.
HIGH_SCORE_THRESHOLD = 8
LOW_SCORE_THRESHOLD = 1

PRINTABLE = bytes(range(0x1F, 0x7F))  # [\x1f-\x7e]
WIDE_RE = re.compile(rb"(?:[\x1f-\x7e][\x00]){6,}")
ASCII_RE = re.compile(rb"[\x1f-\x7e]{%d,}" % MIN_STRING)
OPCODE_SPLIT_RE = re.compile(rb"[\x00]{3,}")

#: File extensions worth opening when scanning a directory.
RELEVANT_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi",
    ".bin", ".dat", ".tmp", ".log", ".ini", ".cfg", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".pif", ".com",
    ".msi", ".jar", ".apk", ".elf", ".so", ".dylib", ".text", ".txt",
    ".pdb", ".config", ".xml", ".json",
}

#: Strings that appear in the overwhelming majority of binaries and therefore
#: carry no information. This is the same idea as yarGen's PEStudio list but
#: spelled out so the tool has no download step.
BORING_SUBSTRINGS = {
    "microsoft", "windows", "kernel32", "user32", "advapi32", "gdi32",
    "comctl32", "shell32", "ole32", "oleaut32", "ntdll", "msvcrt", "msvcr",
    "this program cannot be run in dos mode", "richsignature", "padding",
    "getproccaddress", "loadlibrary", "getmodulehandle", "virtualalloc",
    "virtualfree", "createfile", "readfile", "writefile", "closehandle",
    "getlasterror", "exitprocess", "getprocaddress", "getcommandline",
    "getmodulefilename", "getsystemdirectory", "getwindowsdirectory",
    "getversion", "gettickcount", "queryperformancecounter", "sleep",
    "tostring", "toint", "tostring()", "system32", "syswow64", "programfiles",
    "appdata", "temp", "\\dll", ".dll", ".exe", ".sys", "http", "www",
    ".com", ".net", ".org", "error", "warning", "exception", "assert",
    "debug", "release", "version", "copyright", "license", "text", "data",
    "rdata", "rsrc", "reloc", "idata", "edata", "pdata", "xdata", "tls",
    "bss", "id", "ip", "dbg", "null", "true", "false", "none", "main",
}

B64_STD = _string.ascii_letters + _string.digits + "+/"
B64_URL = _string.ascii_letters + _string.digits + "-_"


# --------------------------------------------------------------------------
# Intermediate representation
# --------------------------------------------------------------------------


@dataclass
class RuleString:
    """One literal in a rule, with its modifiers."""

    identifier: str
    value: str
    score: int = 0
    ascii: bool = True
    wide: bool = False
    nocase: bool = False
    fullword: bool = False
    base64: bool = False
    base64wide: bool = False
    hex: bool = False
    comment: str = ""

    def yara_modifiers(self) -> str:
        mods = []
        if self.ascii:
            mods.append("ascii")
        if self.wide:
            mods.append("wide")
        if self.nocase:
            mods.append("nocase")
        if self.fullword:
            mods.append("fullword")
        if self.base64:
            mods.append("base64")
        if self.base64wide:
            mods.append("base64wide")
        return " ".join(mods)


@dataclass
class Rule:
    """A rule in the shared IR, before it is rendered to a backend."""

    name: str
    identifier: str = ""
    kind: str = "simple"  # simple | super | inverse | global
    title: str = ""
    description: str = ""
    severity: str = "medium"
    verdict: str = "suspicious"
    confidence: int = 60
    score: int = 30
    family: str = ""
    tags: list[str] = field(default_factory=list)
    mitre: list[dict] = field(default_factory=list)
    private: bool = False

    strings: list[RuleString] = field(default_factory=list)
    opcodes: list[str] = field(default_factory=list)
    #: Textual YARA conditions carried over verbatim (pe.is_dll(), uint16(0)...).
    pe_conditions: list[str] = field(default_factory=list)
    #: High scoring string identifiers; these may satisfy the condition alone.
    high: list[str] = field(default_factory=list)
    low: list[str] = field(default_factory=list)
    #: YARA quantifier: "all" | "any" | "threshold" | "high" | "low"
    quantifier: str = "all"
    threshold: int = 0
    #: Inverse rules only: the filename or folder this exception applies to.
    filename: str = ""
    folders: list[str] = field(default_factory=list)
    #: Reference note pointing at the samples the rule came from.
    reference: str = ""

    # Filled in by the hydra emitter when something cannot be expressed.
    gaps: list[str] = field(default_factory=list)

    def hydra_id(self) -> str:
        """
        The rule's `id`. The name already carries the identifier prefix, so
        slugging the name alone avoids a doubled `gen_gen_...`.
        """
        return _slug(self.name)[:64]


@dataclass
class SampleInfo:
    """Everything the generator learned about one sample."""

    path: str
    name: str = ""
    size: int = 0
    magic: str = ""
    is_pe: bool = False
    is_dll: bool = False
    is_elf: bool = False
    bitness: str = ""
    ep_section: str = ""
    sections: list[str] = field(default_factory=list)
    section_entropy: dict[str, float] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)
    import_dlls: list[str] = field(default_factory=list)
    entry: str = ""
    imphash: str = ""
    timestamp: str = ""
    sha256: str = ""
    strings: list[str] = field(default_factory=list)
    opcodes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# String classification helpers
# --------------------------------------------------------------------------


def is_printable(data: bytes) -> bool:
    return all(b in PRINTABLE or b in (0x09, 0x0A, 0x0D) for b in data)


def is_ascii_string(text: str, min_len: int = MIN_STRING) -> bool:
    stripped = text.strip()
    if len(stripped) < min_len:
        return False
    return all(c in _string.printable for c in stripped)


def is_base64(text: str) -> bool:
    """True when the text looks like standard or URL-safe base64."""
    if len(text) < 16 or len(text) % 4 != 0:
        return False
    for alphabet in (B64_STD, B64_URL):
        body = text.rstrip("=")
        if body and all(c in alphabet for c in body):
            # Decoding must actually work, otherwise it is just a coincidence.
            padded = body + "=" * ((4 - len(body) % 4) % 4)
            try:
                base64.b64decode(padded, altchars=b"-_" if alphabet is B64_URL else None)
                return True
            except (binascii.Error, ValueError):
                continue
    return False


def is_hex_encoded(text: str) -> bool:
    """True when the text is a hex blob that decodes to printable ASCII."""
    body = text.strip()
    if len(body) < 12 or len(body) % 2 != 0:
        return False
    if not re.fullmatch(r"[0-9a-fA-F]+", body):
        return False
    try:
        decoded = bytes.fromhex(body)
    except ValueError:
        return False
    return is_printable(decoded)


def extract_hex_runs(data: bytes) -> list[str]:
    """Find hex-encoded ASCII runs embedded in a binary."""
    found: list[str] = []
    # 6+ consecutive hex characters, each pair decoding to a printable byte.
    for match in re.finditer(rb"(?:[0-9a-fA-F]{2}){6,}", data):
        blob = match.group()
        if is_hex_encoded(blob.decode("ascii", "ignore")):
            found.append(blob.decode("ascii"))
    return found


def is_boring(text: str) -> bool:
    """True when a string is too common to be worth a rule slot."""
    lowered = text.lower()
    if len(lowered) < 4:
        return True
    for boring in BORING_SUBSTRINGS:
        if boring in lowered:
            return True
    return False


def looks_like_junk(text: str) -> bool:
    """
    True for byte soup that happened to be printable.

    The ASCII window is ``\\x1f-\\x7e``, so disassembly bytes land in the
    candidate set constantly (``D$$)D$D`` and friends). A real literal carries
    words, paths, format specifiers or keys; junk carries a symbol soup with
    almost nothing readable in it. Without this a small benign corpus lets that
    junk through, because nothing knows it is common.
    """
    stripped = text.strip()
    if len(stripped) < 6:
        return True
    alnum = sum(1 for c in stripped if c.isalnum())
    if alnum < 4:
        return True
    # A real string is mostly alnum, or a format string with a little structure.
    if alnum / len(stripped) < 0.55:
        return True
    # No letters at all: hex and base64 blobs are handled by their own scores,
    # and an all-digit run is a version number or a checksum, not a signature.
    if not any(c.isalpha() for c in stripped):
        return not (is_base64(stripped) or is_hex_encoded(stripped))
    return False


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


#: Keyword weights, taken from yarGen's ``filter_string_set``. These are the
#: heuristics that decide which literals are worth a rule slot, so they are
#: reproduced rather than reinvented.
BONUSES: tuple[tuple[str, float, str, int], ...] = (
    # (label, bonus, pattern, flags)
    ("drive prefix", 2, r"[A-Za-z]:\\", re.IGNORECASE),
    ("file extension", 4,
     r"(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|"
     r"\.dll|\.vbs|\.tmp|\.sys|\.ps1|\.vbp|\.hta|\.lnk)", re.IGNORECASE),
    ("system keyword", 5,
     r"(cmd\.exe|system32|users|Documents and|SystemRoot|Grant|hello|"
     r"password|process|log)", re.IGNORECASE),
    ("protocol keyword", 5,
     r"(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)", re.IGNORECASE),
    ("connection keyword", 3,
     r"(error|http|closed|fail|version|proxy)", re.IGNORECASE),
    ("browser user agent", 5,
     r"(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)", re.IGNORECASE),
    ("temp or recycler", 4, r"(TEMP|Temporary|Appdata|Recycler)", re.IGNORECASE),
    ("hacktool keyword", 5,
     r"(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|"
     r"forward|vulnerable|credentials|creds|coded|p0c|Content|host)", re.IGNORECASE),
    ("network keyword", 3,
     r"(address|port|listen|remote|local|service|mutex|pipe|frame|key|"
     r"lookup|connection)", re.IGNORECASE),
    ("drive", 4, r"([C-Zc-z]:\\)", re.IGNORECASE),
    ("ip address", 5,
     r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
     r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", re.IGNORECASE),
    ("coded by", 7, r"(coded | c0d3d |cr3w\b|Coded by |codedby)", re.IGNORECASE),
    ("generic extension", 3, r"\.[a-zA-Z]{3}\b", 0),
    ("all caps", 2.5, r"^[A-Z]{6,}$", 0),
    ("all lower", 2, r"^[a-z]{6,}$", 0),
    ("lower with spaces", 2, r"^[a-z\s]{6,}$", 0),
    ("capitalised", 2, r"^[A-Z][a-z]{5,}$", 0),
    ("format string url", 2.5,
     r"(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)", 0),
    ("command line parameter", 4,
     r"( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)", re.IGNORECASE),
    ("directory", 4, r"([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\", 0),
    ("bare executable", 4, r"^[^\\]+\.(exe|com|scr|bat|sys)$", re.IGNORECASE),
    ("date placeholder", 3,
     r"(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)", re.IGNORECASE),
    ("format placeholder", 3,
     r"[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]", re.IGNORECASE),
    ("filesystem element", 3,
     r"(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|"
     r"config)", re.IGNORECASE),
    ("programming", 3,
     r"(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|"
     r"netuse|script|share)", re.IGNORECASE),
    ("credentials", 3,
     r"(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|"
     r"kerberos|spnego|session|identif|account|auth|privilege)", re.IGNORECASE),
    ("environment variable", 4, r"%[A-Z_]+%", re.IGNORECASE),
    ("rat or malware", 5,
     r"(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|"
     r"metasploit|/veil|Blood)", re.IGNORECASE),
    ("user profile path", 3,
     r"[\\](users|profiles|username|benutzer|Documents and Settings|"
     r"Utilisateurs|Utenti)[\\]", re.IGNORECASE),
    ("word then digits", 1, r"^[A-Z][a-z]+[0-9]+$", re.IGNORECASE),
)


class PestudioStrings:
    """
    PEStudio's suspicious-string taxonomy, loaded from ``3rdparty/strings.xml``.

    yarGen parses this with lxml and scores an exact case-insensitive match at
    5, except for the ``ext`` category which it deliberately ignores. The same
    file ships with yarGen, so the taxonomy is the same one; the standard library
    parser is used so the tool gains no dependency.
    """

    #: Category order matters: the first category a string appears in wins,
    #: mirroring yarGen's dict iteration.
    CATEGORIES = ("string", "av", "folder", "os", "reg", "guid", "ssdl",
                  "ext", "agent", "oid", "priv")
    SCORE = 5.0
    IGNORED = "ext"

    def __init__(self) -> None:
        self.table: dict[str, str] = {}
        #: PEStudio's own allow list. A string here is known-benign regardless
        #: of how it scores, so it never becomes a rule atom. yarGen ignores
        #: this section; honouring it is what keeps C runtime banners and
        #: compiler noise out of the output.
        self.white: set[str] = set()
        self.available = False
        self.path = ""

    @classmethod
    def load(cls, path: str | os.PathLike) -> "PestudioStrings":
        self = cls()
        self.path = str(path)
        if not os.path.isfile(self.path):
            return self
        try:
            import xml.etree.ElementTree as ET

            root = ET.parse(self.path).getroot()
        except Exception as exc:  # pragma: no cover - malformed file
            print(f"[!] pestudio strings: cannot parse {self.path}: {exc}")
            return self

        for category in cls.CATEGORIES:
            for element in root.findall(f".//{category}"):
                text = (element.text or "").strip()
                if text:
                    self.table.setdefault(text.lower(), category)
        for element in root.findall(".//white/item"):
            text = (element.text or "").strip()
            if text:
                self.white.add(text.lower())
        self.available = bool(self.table)
        return self

    def is_white(self, text: str) -> bool:
        return text.strip().lower() in self.white

    def score(self, text: str) -> tuple[float, str]:
        """Return (score, category) for an exact case-insensitive match."""
        category = self.table.get(text.lower())
        if category is None or category == self.IGNORED:
            return 0.0, ""
        return self.SCORE, category

    def __len__(self) -> int:
        return len(self.table)


def _structural_score(text: str) -> float:
    """
    Length and character-class scoring.

    yarGen deliberately has this part commented out; it is kept here because a
    literal that is both long and mixed-class makes a better signature candidate
    than a short lowercase word, and it is what the base score falls back to
    when no goodware or PEStudio evidence exists.
    """
    score = 0.0
    length = len(text)
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 20:
        score += 1
    if length >= 32:
        score += 1
    classes = sum(
        (
            any(c.islower() for c in text),
            any(c.isupper() for c in text),
            any(c.isdigit() for c in text),
            any(not c.isalnum() for c in text),
        )
    )
    return score + classes - 1


def score_string(
    text: str, good_count: int = 0, pestudio: PestudioStrings | None = None
) -> float:
    """
    Score one literal, following yarGen's model.

    ``good_count`` is how many benign files the literal appeared in and
    ``pestudio`` is the loaded taxonomy. A string that goodware is full of
    scores negative no matter how suspicious it looks, which is the whole point:
    a compiler banner or a certificate string looks distinctive and is worthless.
    """
    if not text:
        return 0.0

    pe_score, pe_category = pestudio.score(text) if pestudio is not None else (0.0, "")
    is_goodware = good_count > 0

    if pe_category:
        # yarGen replaces the score with the PEStudio one, discounted by how
        # common the string is in goodware.
        score = pe_score - (good_count / 1000.0 if is_goodware else 0.0)
    elif is_goodware:
        score = good_count * -1.0 + 5.0
    else:
        score = _structural_score(text)

    if is_goodware:
        return score

    if ".." in text:
        score -= 5
    if "   " in text:
        score -= 5
    if re.search(r"WinRAR\\SFX", text, re.IGNORECASE):
        score -= 4
    if "\x1f" in text:
        score -= 4
    if text.count("0000000000") > 2:
        score -= 5
    # Deviation from yarGen: upstream writes this as
    #   r"(?!.*([A-Fa-f0-9])\1{8,})"
    # which, because of the negative lookahead, matches on *every* string - it
    # asserts that no 9+ repeated-character run exists, and almost none do. So
    # upstream subtracts 5 from every candidate, which drives the whole scoring
    # model negative. The evident intent is "penalise a run of 9+ repeats", so
    # that is what is implemented here.
    if re.search(r"([A-Fa-f0-9])\1{8,}", text, re.IGNORECASE):
        score -= 5

    for _label, bonus, pattern, flags in BONUSES:
        if re.search(pattern, text, flags):
            score += bonus

    if is_base64(text):
        score += 2
    if is_hex_encoded(text):
        score += 2
    return score
def discrimination(malware_count: int, benign_count: int, samples: int) -> float:
    """
    How much a string favours malware over the benign corpus, in 0..1.

    A string present in every benign binary is worthless no matter how odd it
    looks, so the benign corpus has to be able to veto a high raw score.
    """
    if samples == 0:
        return 0.0
    mal_rate = malware_count / samples
    ben_rate = benign_count / samples
    return max(0.0, min(1.0, mal_rate - ben_rate))


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


def extract_strings(
    data: bytes, min_len: int = DEFAULT_MIN_STRING, max_len: int = DEFAULT_MAX_STRING
) -> list[str]:
    """Pull candidate literals out of a binary, marking the wide ones."""
    out: list[str] = []
    seen: set[str] = set()
    floor = max(min_len, MIN_STRING)

    def add(value: str) -> None:
        if len(value) >= floor and value not in seen:
            seen.add(value)
            out.append(value)

    try:
        for match in ASCII_RE.finditer(data):
            add(match.group().decode("utf-8", "ignore")[:max_len])
        for match in WIDE_RE.finditer(data):
            try:
                add(match.group().decode("utf-16-le", "ignore")[:max_len])
            except UnicodeDecodeError:
                pass
        for blob in extract_hex_runs(data):
            add(blob[:max_len])
    except Exception:  # pragma: no cover - malformed input
        traceback.print_exc()

    return [s for s in out if is_ascii_string(s, floor)]


def extract_opcodes(data: bytes, count: int = MAX_OPCODES_PER_RULE) -> list[str]:
    """
    Pick distinctive byte runs from the code section.

    The heuristic is the same as yarGen's: split the section on long zero runs
    and keep the first 16 bytes of each chunk. Those are entry stubs and
    function prologues, which survive recompilation far better than data.
    """
    opcodes: list[str] = []
    try:
        binary = lief.parse(list(data) and data or data)
    except Exception:
        return opcodes
    if binary is None:
        return opcodes

    text: bytes | None = None
    if isinstance(binary, lief.PE.Binary):
        ep = binary.entrypoint
        for section in binary.sections:
            start = section.virtual_address + binary.imagebase
            if start <= ep < start + section.virtual_size:
                text = bytes(section.content)
                break
    elif isinstance(binary, lief.ELF.Binary):
        ep = binary.entrypoint
        for section in binary.sections:
            if section.virtual_address <= ep < section.virtual_address + section.size:
                text = bytes(section.content)
                break

    if not text:
        return opcodes

    for chunk in OPCODE_SPLIT_RE.split(text):
        if len(chunk) < 8:
            continue
        opcodes.append(binascii.hexlify(chunk[:16]).decode("ascii"))
        if len(opcodes) >= count:
            break
    return opcodes


def get_pe_info(data: bytes, path: str = "") -> SampleInfo:
    """Collect everything we can learn about a sample without reading it twice."""
    info = SampleInfo(path=path, name=os.path.basename(path))
    info.size = len(data)
    info.magic = binascii.hexlify(data[:2]).decode("ascii")
    if len(data) >= 64:
        info.sha256 = _sha256(data)

    binary = None
    try:
        binary = lief.parse(data)
    except Exception:
        binary = None
    if binary is None:
        return info

    if isinstance(binary, lief.PE.Binary):
        info.is_pe = True
        try:
            info.is_dll = bool(binary.is_dll())
        except Exception:
            info.is_dll = False
        info.bitness = "pe64" if binary.optional_header.magic == 0x20B else "pe32"
        info.entry = f"0x{binary.entrypoint:x}"
        # lief exposes the timestamp on the header, not the binary.
        try:
            info.timestamp = _format_timestamp(binary.header.time_date_stamps)
        except Exception:
            info.timestamp = ""
        for section in binary.sections:
            name = section.name.rstrip("\x00")
            if not name:
                continue
            info.sections.append(name)
            try:
                info.section_entropy[name] = round(section.entropy, 3)
            except Exception:
                pass
            start = section.virtual_address + binary.imagebase
            if start <= binary.entrypoint < start + section.virtual_size:
                info.ep_section = name
        for entry in binary.imports:
            dll = entry.name.rstrip("\x00")
            if dll:
                info.import_dlls.append(dll)
            for function in entry.entries:
                name = getattr(function, "name", None)
                if name:
                    info.imports.append(name)
        try:
            info.imphash = binary.imphash
        except Exception:
            info.imphash = ""
    elif isinstance(binary, lief.ELF.Binary):
        info.is_elf = True
        info.bitness = "elf64" if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else "elf32"
        info.entry = f"0x{binary.entrypoint:x}"
        for section in binary.sections:
            name = section.name.rstrip("\x00")
            if name:
                info.sections.append(name)

    return info


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _format_timestamp(stamps) -> str:
    try:
        stamp = int(stamps[0])
    except Exception:
        return ""
    if stamp <= 0:
        return ""
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


# --------------------------------------------------------------------------
# Corpus walking
# --------------------------------------------------------------------------


def iter_files(folder: str, recursive: bool = True) -> Iterator[Path]:
    root = Path(folder)
    if not root.is_dir():
        return
    if recursive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                yield path
    else:
        for path in sorted(root.iterdir()):
            if path.is_file():
                yield path


def parse_sample_dir(
    folder: str,
    recursive: bool = True,
    only_relevant: bool = True,
    min_string: int = MIN_STRING,
    max_string: int = DEFAULT_MAX_STRING,
) -> dict[str, SampleInfo]:
    """Read every sample and extract its strings, opcodes and PE facts."""
    samples: dict[str, SampleInfo] = {}
    for path in iter_files(folder, recursive):
        if only_relevant and path.suffix.lower() not in RELEVANT_EXTENSIONS:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if not data:
            continue
        info = get_pe_info(data, str(path))
        info.strings = extract_strings(data, min_string, max_string)
        info.opcodes = extract_opcodes(data)
        samples[info.path] = info
    return samples


def parse_good_dir(
    folder: str, recursive: bool = True, only_relevant: bool = True
) -> dict[str, SampleInfo]:
    """Same extraction over a benign corpus, used to veto common strings."""
    return parse_sample_dir(folder, recursive, only_relevant)


# --------------------------------------------------------------------------
# Rule synthesis
# --------------------------------------------------------------------------


def build_global_rule(samples: dict[str, SampleInfo], identifier: str) -> Rule | None:
    """
    A private, always-evaluated rule that narrows the scan.

    Worth emitting only when the corpus is homogeneous, otherwise a condition
    like "is PE" is just noise that costs a parse per file.
    """
    if not samples:
        return None

    total = len(samples)
    pe_count = sum(1 for s in samples.values() if s.is_pe)
    elf_count = sum(1 for s in samples.values() if s.is_elf)
    dll_count = sum(1 for s in samples.values() if s.is_dll)
    magic = defaultdict(int)
    for sample in samples.values():
        magic[sample.magic] += 1
    common_magic, common_count = max(magic.items(), key=lambda kv: kv[1], default=("", 0))

    conditions: list[str] = []
    if pe_count == total:
        conditions.append("uint16(0) == 0x5A4D")
        if dll_count == total:
            conditions.append("pe.is_dll()")
    elif elf_count == total:
        conditions.append("uint32(0) == 0x464C457F")
    elif common_count == total and common_magic:
        conditions.append(f"uint16(0) == 0x{common_magic.upper()}")

    if not conditions:
        return None

    return Rule(
        name="gen_characteristics",
        identifier=identifier,
        kind="global",
        title="Generated scan pre-filter",
        private=True,
        pe_conditions=conditions,
        quantifier="all",
    )


def build_simple_rule(
    sample: SampleInfo,
    kept: list[tuple[str, int]],
    identifier: str,
    author: str,
) -> Rule | None:
    """One rule per sample, from its best surviving strings."""
    if not kept:
        return None

    rule = Rule(
        name=f"{identifier}_{_slug(sample.name)}",
        identifier=identifier,
        kind="simple",
        title=f"Generated signature for {sample.name}",
        description=(
            f"Auto-generated from {sample.name} "
            f"({sample.size} bytes"
            + (f", {sample.bitness}" if sample.bitness else "")
            + ")"
        ),
        reference=sample.name,
        quantifier="all",
    )

    used = 0
    for index, (text, score) in enumerate(kept):
        if used >= MAX_STRINGS_PER_RULE:
            break
        identifier_ = _atom_id(index)
        rule.strings.append(_make_string(identifier_, text, score))
        (rule.high if score >= HIGH_SCORE_THRESHOLD else rule.low).append(identifier_)
        used += 1

    if not rule.strings:
        return None

    _apply_quantifier(rule)
    _add_opcodes(rule, sample)
    return rule


def build_super_rule(
    members: list[SampleInfo],
    shared: list[tuple[str, int]],
    identifier: str,
) -> Rule | None:
    """A rule for a cluster of samples that share a string set."""
    if len(members) < 2 or not shared:
        return None

    rule = Rule(
        name=f"{identifier}_super_{_slug(members[0].name)}",
        identifier=identifier,
        kind="super",
        title=f"Shared signature for {len(members)} samples",
        description="Auto-generated from samples sharing a common string set: "
        + ", ".join(m.name for m in members[:8])
        + ("..." if len(members) > 8 else ""),
        family=f"Super.{_slug(members[0].name)}",
        quantifier="all",
    )

    for index, (text, score) in enumerate(shared[:MAX_STRINGS_PER_RULE]):
        identifier_ = _atom_id(index)
        rule.strings.append(_make_string(identifier_, text, score))
        (rule.high if score >= HIGH_SCORE_THRESHOLD else rule.low).append(identifier_)

    _apply_quantifier(rule)
    return rule


def build_inverse_rule(
    good_sample: SampleInfo,
    kept: list[tuple[str, int]],
    identifier: str,
    folders: Sequence[str],
) -> Rule | None:
    """
    A benign exception rule: "this filename is fine even if it looks bad".

    Inverse rules never fire on their own - they are private, and they exist so
    a false positive can be subtracted.
    """
    if not kept:
        return None

    rule = Rule(
        name=f"{identifier}_inv_{_slug(good_sample.name)}",
        identifier=identifier,
        kind="inverse",
        title=f"Benign exception for {good_sample.name}",
        description=f"Auto-generated exception from {good_sample.name}",
        private=True,
        verdict="clean",
        confidence=20,
        score=0,
        severity="info",
        quantifier="all",
        filename=good_sample.name,
        folders=list(folders),
    )

    for index, (text, score) in enumerate(kept[:MAX_STRINGS_PER_RULE]):
        identifier_ = _atom_id(index)
        rule.strings.append(_make_string(identifier_, text, score))
        (rule.high if score >= HIGH_SCORE_THRESHOLD else rule.low).append(identifier_)

    _apply_quantifier(rule)
    return rule


def _make_string(identifier: str, text: str, score: int) -> RuleString:
    """Decide the modifiers a literal needs, from what it looks like."""
    base64_ = is_base64(text)
    hexed = is_hex_encoded(text)
    return RuleString(
        identifier=identifier,
        value=text,
        score=score,
        ascii=not hexed,
        wide=not hexed,
        # A path, a URL or a registry key only matters case-insensitively.
        nocase=(":" in text or "\\\\" in text or "/" in text),
        fullword=False,
        base64=base64_,
        base64wide=base64_,
        hex=hexed,
        comment=f"score={score}",
    )


def _add_opcodes(rule: Rule, sample: SampleInfo) -> None:
    """Attach the code-section byte patterns, the way yarGen's $op* group does."""
    for index, opcode in enumerate(sample.opcodes[:MAX_OPCODES_PER_RULE]):
        rule.opcodes.append(opcode)
        rule.high.append(f"op{index}")


def _apply_quantifier(rule: Rule) -> None:
    """
    Decide whether the rule needs every string, or only the good ones.

    Mirrors yarGen: when the corpus already has strong PE conditions, weak
    strings are allowed as alternatives so the rule does not become brittle.
    """
    high = [s for s in rule.high if not s.startswith("op")]
    low = [s for s in rule.low if not s.startswith("op")]
    has_pe = bool(rule.pe_conditions)

    if high and low and has_pe:
        rule.quantifier = "mixed_or"
    elif high and low:
        rule.quantifier = "mixed_and"
    elif high:
        rule.quantifier = "high"
    else:
        rule.quantifier = "all"


class GoodwareIndex:
    """
    How often each literal shows up in benign software.

    Two sources, merged: the counts derived from ``--good-dir`` (what yarGen
    itself uses) and, optionally, the prebuilt ``yarGen/dbs/good-strings*.db``
    shards.

    Those shards total ~1.7 GB compressed and roughly 95 million keys, so they
    are deliberately **not** loaded whole. A veto only needs evidence that a
    string is common in goodware, not an exact census, so shards are read in
    sorted order until an entry budget is reached and the rest are reported as
    skipped. Point ``--good-db-max-entries`` at zero for a sample of a single
    shard when you only want a quick pass.
    """

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.samples = 0
        self.shards_loaded: list[str] = []
        self.shards_skipped: list[str] = []

    def add_directory(self, folder: str) -> None:
        samples = parse_good_dir(folder)
        self.samples += len(samples)
        for sample in samples.values():
            for text in set(sample.strings):
                self.counts[text] = self.counts.get(text, 0) + 1

    def add_shards(self, folder: str, max_entries: int) -> None:
        """Read ``good-strings*.db`` shards until the entry budget runs out."""
        import glob
        import gzip
        import json

        pattern = os.path.join(folder, "good-strings*.db")
        shards = sorted(glob.glob(pattern))
        if not shards:
            print(f"[!] no good-strings*.db under {folder}")
            return

        # Cheapest shard first. Sorting by name would put the 850 MB
        # `benign_*` corpora ahead of every `part*` shard and spend the whole
        # budget on a single platform, which is exactly the wrong trade.
        shards.sort(key=lambda path: (os.path.getsize(path), path))

        budget = max_entries if max_entries > 0 else float("inf")
        spent = 0.0
        for shard in shards:
            if spent >= budget:
                self.shards_skipped.append(os.path.basename(shard))
                continue
            try:
                with gzip.open(shard, "rt", encoding="utf-8", errors="replace") as handle:
                    data = json.load(handle)
            except Exception as exc:
                print(f"[!] cannot read {os.path.basename(shard)}: {exc}")
                continue
            for text, count in data.items():
                self.counts[text] = self.counts.get(text, 0) + int(count)
            spent += len(data)
            self.shards_loaded.append(
                f"{os.path.basename(shard)} ({len(data):,} entries)"
            )
            del data

        if self.shards_skipped:
            print(
                f"[!] {len(self.shards_skipped)} goodware shard(s) skipped "
                f"past the {max_entries:,} entry budget"
            )

    def count(self, text: str) -> int:
        return self.counts.get(text, 0)

    def __len__(self) -> int:
        return len(self.counts)


def rank_strings(
    sample: SampleInfo,
    malware_counts: dict[str, int],
    malware_total: int,
    goodware: GoodwareIndex,
    pestudio: PestudioStrings | None,
    exclude_good: bool = False,
) -> list[tuple[str, int]]:
    """
    Score and filter one sample's strings, best first.

    A literal is dropped outright when PEStudio allow-lists it, and is scored
    down to nothing when goodware is full of it, so compiler banners and
    certificate strings stop winning on length alone.
    """
    out: list[tuple[str, int]] = []
    for text in sample.strings:
        if len(text.encode("utf-8", "ignore")) > MAX_STRING_BYTES:
            continue
        if pestudio is not None and pestudio.is_white(text):
            continue
        if is_boring(text) or looks_like_junk(text):
            continue

        good_count = goodware.count(text)
        if exclude_good and good_count > 0:
            continue

        raw = score_string(text, good_count=good_count, pestudio=pestudio)
        if raw <= 0:
            continue
        disc = discrimination(
            malware_counts.get(text, 0), good_count, malware_total
        )
        if goodware.samples and disc < MIN_DISCRIMINATION and good_count == 0:
            # Rare in the malware corpus too: not worth a slot.
            continue
        out.append((text, int(round(raw))))

    out.sort(key=lambda item: (-item[1], -len(item[0]), item[0]))
    return out


def cluster_by_shared_strings(
    samples: dict[str, SampleInfo], min_shared: int = 3
) -> list[list[str]]:
    """
    Group samples that share enough strings to be worth a super rule.

    Only distinctive strings count: a shared "kernel32" tells us nothing, so
    boring strings are dropped before the counting.
    """
    postings: dict[str, set[str]] = defaultdict(set)
    for path, sample in samples.items():
        for text in set(sample.strings):
            if is_boring(text):
                continue
            postings[text].add(path)

    parent: dict[str, str] = {path: path for path in samples}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for members in postings.values():
        if len(members) < 2:
            continue
        members = list(members)
        for other in members[1:]:
            union(members[0], other)

    groups: dict[str, list[str]] = defaultdict(list)
    for path in samples:
        groups[find(path)].append(path)
    return [paths for paths in groups.values() if len(paths) >= min_shared]


# --------------------------------------------------------------------------
# YAML writing (no PyYAML dependency)
# --------------------------------------------------------------------------


# A backslash is deliberately absent from the plain-safe set. YAML plain
# scalars treat it literally, so emitting one unquoted is valid, but these values
# end up inside regexes and Windows paths where an explicit double-quoted scalar
# is far easier to read and less easy to mis-edit.
_YAML_PLAIN_SAFE = re.compile(r"^[A-Za-z_][A-Za-z0-9_./-]*$")


def yaml_scalar(value) -> str:
    """Render a scalar, quoting only when it has to."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "":
        return '""'
    if _YAML_PLAIN_SAFE.match(text) and text not in ("y", "n", "yes", "no", "on", "off", "true", "false"):
        return text
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def yaml_block(lines: list[str], indent: int, key: str, values: Iterable) -> None:
    """Emit a list under `key` in block style, one item per line."""
    items = list(values)
    if not items:
        return
    pad = " " * indent
    lines.append(f"{pad}{key}:")
    for item in items:
        lines.append(f"{pad}  - {yaml_scalar(item)}")


# --------------------------------------------------------------------------
# YARA emitter
# --------------------------------------------------------------------------


def emit_yara(rules: list[Rule], header: dict) -> str:
    out: list[str] = []
    out.append("/*")
    out.append("   YARA Rule Set (hydragen)")
    for key, value in header.items():
        out.append(f"   {key}: {value}")
    out.append("*/")
    out.append("")

    for rule in rules:
        if rule.kind == "global":
            out.append(
                "/* Global rule: evaluated first, remove at will */\n"
            )
            out.append(f"global private rule {rule.name} {{")
            out.append("   condition:")
            for condition in rule.pe_conditions:
                out.append(f"      {condition}")
            out.append("}")
            out.append("")
            continue

        out.append("rule " + _yara_rule_name(rule.name) + " {")
        out.append("   meta:")
        if rule.title:
            out.append(f'      description = "{_yara_escape(rule.title)}"')
        if rule.family:
            out.append(f'      family = "{_yara_escape(rule.family)}"')
        if rule.tags:
            out.append(f'      tags = "{_yara_escape(" ".join(rule.tags))}"')
        out.append(f'      reference = "{_yara_escape(rule.reference)}"')
        out.append(f"      hydragen_confidence = {rule.confidence}")
        out.append("")

        if rule.strings:
            out.append("   strings:")
            for item in rule.strings:
                line = f'      ${item.identifier} = "{_yara_escape(item.value)}"'
                mods = item.yara_modifiers()
                if mods:
                    line += " " + mods
                if item.comment:
                    line += f"  /* {item.comment} */"
                out.append(line)
            for index, opcode in enumerate(rule.opcodes):
                out.append(f"      $op{index} = {{ {opcode} }}  /* code section */")
            out.append("")

        out.append("   condition:")
        for line in _yara_condition(rule):
            out.append(f"      {line}")
        out.append("}")
        out.append("")

    return "\n".join(out)


def _yara_rule_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not cleaned or cleaned[0].isdigit():
        cleaned = "r_" + cleaned
    return cleaned


def _yara_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _yara_condition(rule: Rule) -> list[str]:
    """Rebuild the condition block, mirroring yarGen's quantifier logic."""
    lines: list[str] = []
    for condition in rule.pe_conditions:
        lines.append(condition)

    op_refs = [f"$op{i}" for i in range(len(rule.opcodes))]
    high = [f"${s}" for s in rule.high if not s.startswith("op")]
    low = [f"${s}" for s in rule.low if not s.startswith("op")]

    def combine(refs: list[str], quantifier: str) -> str:
        if quantifier == "all":
            return " and ".join(refs) if refs else ""
        if quantifier == "any":
            return " or ".join(refs) if refs else ""
        return f"{quantifier} of them"

    string_clause = ""
    if rule.quantifier == "high":
        string_clause = combine(high, "all")
    elif rule.quantifier == "low":
        string_clause = combine(low, "all")
    elif rule.quantifier == "mixed_and":
        string_clause = f"({combine(high, 'all')}) and ({combine(low, 'all')})"
    elif rule.quantifier == "mixed_or":
        string_clause = f"({combine(high, 'all')}) or ({combine(low, 'all')})"
    elif rule.threshold:
        string_clause = f"{rule.threshold} of them"
    else:
        string_clause = combine([f"${s.identifier}" for s in rule.strings], "all")

    if op_refs:
        op_clause = "all of ($op*)"
        string_clause = f"( {string_clause} and {op_clause} )" if string_clause else op_clause

    if rule.kind == "inverse":
        # Inverse rules must not fire on their own; they are private and are
        # only subtracted from a detection.
        inner = string_clause or "true"
        target = f'filename == "{_yara_escape(rule.filename)}"'
        lines.append(f"({target} and not ( {inner} ))")
        return lines

    if string_clause:
        lines.append(string_clause)
    elif not lines:
        lines.append("true")
    return lines


# --------------------------------------------------------------------------
# HydraDragonSig emitter
# --------------------------------------------------------------------------

#: yarGen/hydradragonsig condition vocabulary gaps, filled in as they are hit.
_GAP_JOIN = " and "

#: File magic a `uintN(0) == ...` check maps onto, using the tag
#: HydraDragonSig's classifier assigns. Anything else becomes a byte_pattern.
KNOWN_MAGIC = {
    b"MZ": ["pe"],
    b"\x7fELF": ["elf"],
    b"\xcf\xfa\xed\xfe": ["macho"],
    b"\xce\xfa\xed\xfe": ["macho"],
    b"\xca\xfe\xba\xbe": ["macho"],
    b"PK": ["zip", "jar", "apk"],
}


def emit_hydra(rules: list[Rule], header: dict, set_name: str) -> tuple[str, list[str]]:
    """
    Render rules as a HydraDragonSig YAML rule set.

    Returns the YAML text and a list of constructs that had no Hydra equivalent
    and were therefore dropped, so the caller can report them instead of
    pretending the conversion was lossless.
    """
    lines: list[str] = []
    gaps: list[str] = []

    lines.append(f"# {header.get('Set', 'Generated')}")
    lines.append("# Generated by hydragen " + __version__ + " (ported from yarGen.py)")
    lines.append(f"# Author: {header.get('Author', 'unknown')}")
    lines.append(f"# Date: {header.get('Date', '')}")
    lines.append(f"# Identifier: {header.get('Identifier', '')}")
    if header.get("Reference"):
        lines.append(f"# Reference: {header['Reference']}")
    if header.get("License"):
        lines.append(f"# License: {header['License']}")
    lines.append("name: " + yaml_scalar(set_name))
    lines.append('version: "1.0"')
    lines.append("rules:")

    for rule in rules:
        before = len(gaps)
        lines.extend(_hydra_rule(rule, gaps))
        if len(gaps) == before:
            lines.append("")

    if gaps:
        lines.append("# --- constructs with no HydraDragonSig equivalent ---")
        for gap in dict.fromkeys(gaps):
            lines.append("#   - " + gap)

    return "\n".join(lines) + "\n", gaps


def _hydra_rule(rule: Rule, gaps: list[str]) -> list[str]:
    lines: list[str] = []
    lines.append("")
    lines.append("  # " + ("-" * 66))
    lines.append("  # " + f"{rule.kind} rule: {rule.name}")
    if rule.reference:
        lines.append("  # " + f"from: {rule.reference}")
    lines.append("")
    lines.append("  - id: " + yaml_scalar(rule.hydra_id()))
    lines.append("    title: " + yaml_scalar(rule.title or rule.name))
    if rule.description:
        lines.append("    description: " + yaml_scalar(rule.description))
    lines.append("    severity: " + yaml_scalar(rule.severity))
    lines.append("    verdict: " + yaml_scalar(rule.verdict))
    lines.append(f"    confidence: {rule.confidence}")
    lines.append(f"    score: {rule.score}")
    if rule.family:
        lines.append("    family: " + yaml_scalar(rule.family))
    if rule.tags:
        lines.append("    tags: [" + ", ".join(t for t in rule.tags) + "]")
    if rule.mitre:
        lines.append("    mitre:")
        for entry in rule.mitre:
            lines.append(f"      - id: {yaml_scalar(entry.get('id', ''))}")
            lines.append(f"        name: {yaml_scalar(entry.get('name', ''))}")
            lines.append(f"        tactic: {yaml_scalar(entry.get('tactic', ''))}")
    if rule.private:
        lines.append("    private: true")

    logic, threshold = _hydra_logic(rule)
    lines.append("    logic: " + logic)
    if threshold:
        lines.append(f"    threshold: {threshold}")

    conditions, rule_gaps = _hydra_conditions(rule)
    lines.append("    conditions:")
    lines.extend(conditions)
    gaps.extend(rule_gaps)
    return lines


def _hydra_logic(rule: Rule) -> tuple[str, int]:
    """Map the quantifier onto HydraDragonSig's rule-level logic."""
    if rule.kind == "inverse":
        # An exception must not raise a verdict; it is private and evaluated
        # as a negative, so it gets its own single condition.
        return "any", 0
    if rule.quantifier == "high":
        return "any", 0
    if rule.quantifier == "low":
        return "any", 0
    if rule.quantifier in ("mixed_and", "all"):
        return "all", 0
    if rule.quantifier == "mixed_or":
        return "any", 0
    if rule.threshold:
        return "threshold", rule.threshold
    return "all", 0


def _hydra_conditions(rule: Rule) -> tuple[list[str], list[str]]:
    """
    Render one rule's conditions.

    Strings become a single ``native_signature`` because HydraDragonSig's atom
    model carries YARA's modifiers (ascii/wide/nocase/fullword/base64/xor)
    natively, which is a closer fit than the cruder string conditions.
    """
    gaps: list[str] = []
    lines: list[str] = []

    if rule.kind == "inverse":
        inner = _hydra_string_condition(rule)
        target = rule.filename or ".*"
        if rule.folders:
            folder = "|".join(re.escape(f) for f in rule.folders)
            pattern = f"^({folder})[/\\\\]{re.escape(target)}$"
        else:
            pattern = f"^[/\\\\]*{re.escape(target)}$"
        lines.append("      - type: path_regex")
        lines.append("        pattern: " + yaml_scalar(pattern))
        if inner:
            lines.append("      # NOTE: an exception rule cannot be expressed as a")
            lines.append("      # negative condition; this rule marks the path as clean")
            lines.append("      # and must be evaluated before the detection rules.")
            gaps.append(
                "inverse rule: a HydraDragonSig rule cannot express "
                "'filename == x and not (strings)'; emitted as a path_regex "
                "exception instead"
            )
        return lines, gaps

    for condition in rule.pe_conditions:
        rendered = _hydra_pe_condition(condition, gaps)
        lines.extend(rendered)

    string_condition = _hydra_string_condition(rule)
    if string_condition:
        lines.extend(string_condition)

    if rule.opcodes:
        lines.append("      - type: byte_set")
        patterns = "[" + ", ".join(yaml_scalar(p) for p in rule.opcodes) + "]"
        lines.append("        patterns: " + patterns)
        lines.append("        min: 1")
        lines.append("        # Code section only: half the file plus one section, so a")
        lines.append("        # data blob cannot satisfy the rule on its own.")
        lines.append("        scope: { start: 0x400, end: 0x200000 }")

    if not any(line.strip() and not line.strip().startswith("#") for line in lines):
        # Everything this rule had to say turned out to be inexpressible. A rule
        # with an empty condition list is worse than useless - it can never
        # match but still costs a parse per file - so say so explicitly.
        gaps.append(
            f"rule {rule.name}: no condition could be expressed; "
            "emitted a non-matching placeholder"
        )
        lines.append("      - type: file_type")
        lines.append("        values: [hydragen_placeholder]")

    return lines, gaps


def _hydra_pe_condition(condition: str, gaps: list[str]) -> list[str]:
    """Translate the textual YARA PE conditions yarGen generates."""
    text = condition.strip()
    lowered = text.lower()

    if lowered == "pe.is_dll()":
        gaps.append("pe.is_dll(): HydraDragonSig has no DLL-only condition")
        return []

    match = re.match(r"uint(16|32)\(0\)\s*==\s*(0x[0-9a-fA-F]+|\d+)", text)
    if match:
        value = int(match.group(2), 0)
        width = int(match.group(1)) // 8
        # HydraDragonSig has no uint16/uint32 condition, but its file-type
        # classifier keys off the same magic, so map the well-known ones and
        # fall back to an explicit byte pattern for anything else.
        raw = value.to_bytes(width, "little")
        for probe in (raw[:4], raw[:2]):
            if probe in KNOWN_MAGIC:
                return [
                    "      - type: file_type",
                    "        values: [" + ", ".join(KNOWN_MAGIC[probe]) + "]",
                ]
        pattern = " ".join(f"{b:02X}" for b in raw)
        return [
            "      - type: byte_pattern",
            "        pattern: " + yaml_scalar(pattern),
            "        scope: { start: 0, end: 4 }",
        ]

    if "filesize" in lowered:
        match = re.search(r"filesize\s*(<|<=|>|>=)\s*(\d+)\s*(KB|MB|GB)?", text)
        if match:
            operator, number, unit = match.group(1), int(match.group(2)), (match.group(3) or "").upper()
            scale = {"KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}.get(unit, 1)
            total = number * scale
            kind = "file_size_lte" if operator in ("<", "<=") else "file_size_gte"
            return ["      - type: " + kind, f"        bytes: {total}"]

    match = re.match(r'pe\.imports?\((.*)\)', text)
    if match:
        names = [n.strip().strip('"') for n in match.group(1).split(",") if n.strip()]
        lines = ["      - type: import_any", "        names:"]
        for name in names:
            lines.append("          - " + yaml_scalar(name))
        return lines

    gaps.append(f"PE condition not translatable: {text}")
    return []


def _hydra_string_condition(rule: Rule) -> list[str]:
    """The string/byte atom block, as a single native_signature condition."""
    if not rule.strings and not rule.opcodes:
        return []

    lines = ["      - type: native_signature"]
    if rule.strings:
        lines.append("        atoms:")
        for item in rule.strings:
            lines.append(f"          - id: {yaml_scalar(item.identifier)}")
            lines.append("            kind: text")
            lines.append("            value: " + yaml_scalar(item.value))
            if not item.ascii:
                lines.append("            ascii: false")
            if item.wide:
                lines.append("            wide: true")
            if item.nocase:
                lines.append("            nocase: true")
            if item.fullword:
                lines.append("            fullword: true")
            if item.base64:
                lines.append("            base64: true")
            if item.base64wide:
                lines.append("            base64wide: true")

    expression = _hydra_expression(rule)
    lines.append("        expression: " + yaml_scalar(expression))
    return lines


def _hydra_expression(rule: Rule) -> str:
    """
    Rebuild the string quantifier as a HydraDragonSig signature expression.

    The expression language deliberately mirrors YARA's, so this is close to a
    transliteration: ``all of them`` / ``N of them`` / ``$a and $b`` all work as
    written.
    """
    if not rule.strings:
        return "true"

    high = [s for s in rule.high if not s.startswith("op")]
    low = [s for s in rule.low if not s.startswith("op")]

    def ref(name: str) -> str:
        return name if name.startswith("$") else f"${name}"

    if rule.quantifier == "high":
        return _join([ref(s) for s in high], " and ") or "true"
    if rule.quantifier == "low":
        return _join([ref(s) for s in low], " and ") or "true"
    if rule.quantifier == "mixed_and":
        left = _join([ref(s) for s in high], " and ")
        right = _join([ref(s) for s in low], " and ")
        return f"({left}) and ({right})"
    if rule.quantifier == "mixed_or":
        left = _join([ref(s) for s in high], " and ")
        right = _join([ref(s) for s in low], " and ")
        return f"({left}) or ({right})"
    if rule.threshold:
        return f"{rule.threshold} of them"
    return "all of them"


def _join(parts: list[str], operator: str) -> str:
    return operator.join(part for part in parts if part)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _atom_id(index: int) -> str:
    """$a, $b, ... $z, $aa, $ab - same alphabet yarGen uses."""
    out = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(ord("a") + rem) + out
    return out


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", text or "").strip("_").lower()
    return slug[:40] or "unnamed"


def _collect_counts(samples: dict[str, SampleInfo]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for sample in samples.values():
        for text in set(sample.strings):
            counts[text] += 1
    return counts


def _benign_samples(folder: str | None) -> dict[str, SampleInfo]:
    """
    Re-read the benign corpus for inverse-rule generation.

    Only the literal ``--good-dir`` is walked here: a prebuilt shard has no
    individual files to carve exception rules out of, so inverse rules come from
    the user's own benign set.
    """
    if not folder:
        return {}
    return parse_good_dir(folder)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hydragen",
        description="Generate signature rules from a sample corpus (hydradragonsig or YARA).",
    )
    parser.add_argument("-s", "--sample-dir", required=True, help="malware sample directory")
    parser.add_argument("-g", "--good-dir", help="benign corpus used to veto common strings")
    parser.add_argument(
        "--good-db", help="directory of yarGen good-strings*.db shards to use as a "
        "benign corpus (read in sorted order up to the entry budget)",
    )
    parser.add_argument(
        "--good-db-max-entries", type=int, default=10_000_000,
        help="entry budget for --good-db; 0 means load every shard (~95M entries, "
        "several GB of RAM)",
    )
    parser.add_argument(
        "--pestudio", help="PEStudio strings.xml (default: ../yarGen/3rdparty/strings.xml "
        "when present)",
    )
    parser.add_argument(
        "--excludegood", action="store_true",
        help="drop any string that appears in the benign corpus instead of just "
        "scoring it down",
    )
    parser.add_argument("-o", "--output", required=True, help="output file or directory")
    parser.add_argument(
        "-f", "--format", choices=("yara", "hydra", "both"), default="hydra",
        help="output backend (default: hydra)",
    )
    parser.add_argument("-a", "--author", default="hydragen", help="author recorded in the header")
    parser.add_argument("-l", "--license", default="", help="license recorded in the header")
    parser.add_argument("-r", "--reference", default="", help="reference URL recorded in the header")
    parser.add_argument("-i", "--identifier", default="gen", help="rule name prefix")
    parser.add_argument("--set-name", default="Generated Rules", help="name for the YAML rule set")
    parser.add_argument("--min-string", type=int, default=DEFAULT_MIN_STRING)
    parser.add_argument("--max-string", type=int, default=DEFAULT_MAX_STRING)
    parser.add_argument("--max-strings", type=int, default=MAX_STRINGS_PER_RULE)
    parser.add_argument("--no-opcodes", action="store_true", help="skip code-section byte patterns")
    parser.add_argument("--no-super", action="store_true", help="skip super rules")
    parser.add_argument("--no-inverse", action="store_true", help="skip benign exception rules")
    parser.add_argument("--no-global", action="store_true", help="skip the scan pre-filter rule")
    parser.add_argument("--not-recursive", action="store_true")
    parser.add_argument("--all-files", action="store_true", help="do not filter by extension")
    parser.add_argument(
        "--strict", action="store_true",
        help="exit non-zero if any construct had no HydraDragonSig equivalent",
    )
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--version", action="version", version=f"hydragen {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    recursive = not args.not_recursive
    only_relevant = not args.all_files

    print(f"[+] Reading malware samples from {args.sample_dir}")
    malware = parse_sample_dir(
        args.sample_dir, recursive, only_relevant, args.min_string, args.max_string
    )
    print(f"[+] {len(malware)} sample(s)")

    goodware = GoodwareIndex()
    if args.good_dir:
        print(f"[+] Reading benign corpus from {args.good_dir}")
        goodware.add_directory(args.good_dir)
        print(f"[+] {goodware.samples} benign sample(s)")
    if args.good_db:
        print(f"[+] Reading prebuilt goodware shards from {args.good_db}")
        goodware.add_shards(args.good_db, args.good_db_max_entries)
        print(
            f"[+] benign index: {len(goodware):,} distinct literals "
            f"from {len(goodware.shards_loaded)} shard(s)"
        )
    if not args.good_dir and not args.good_db:
        print("[!] No benign corpus: common strings cannot be vetoed, expect noise")

    pestudio_path = args.pestudio or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "yarGen", "3rdparty", "strings.xml"
    )
    pestudio = PestudioStrings.load(pestudio_path)
    if pestudio.available:
        print(
            f"[+] PEStudio taxonomy: {len(pestudio):,} entries, "
            f"{len(pestudio.white)} allow-listed"
        )
    else:
        print(f"[!] PEStudio taxonomy not loaded from {pestudio_path}")

    if not malware:
        print("[!] No samples found, nothing to do")
        return 1

    malware_counts = _collect_counts(malware)

    header = {
        "Set": args.set_name,
        "Author": args.author,
        "Date": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Identifier": args.identifier,
        "Reference": args.reference,
        "License": args.license,
        "Samples": str(len(malware)),
    }

    rules: list[Rule] = []

    if not args.no_global:
        global_rule = build_global_rule(malware, args.identifier)
        if global_rule:
            print("[+] Added global pre-filter rule")
            rules.append(global_rule)

    print("[+] Generating simple rules")
    for path, sample in malware.items():
        kept = rank_strings(
            sample,
            malware_counts,
            len(malware),
            goodware,
            pestudio,
            args.excludegood,
        )
        kept = kept[: args.max_strings]
        if not kept:
            print(f"    - {sample.name}: no string survived, skipped")
            continue
        rule = build_simple_rule(sample, kept, args.identifier, args.author)
        if rule:
            if args.no_opcodes:
                rule.opcodes = []
            rules.append(rule)

    if not args.no_super and len(malware) >= 3:
        print("[+] Generating super rules")
        for group in cluster_by_shared_strings(malware):
            members = [malware[p] for p in group]
            shared: dict[str, int] = defaultdict(int)
            for member in members:
                for text in set(member.strings):
                    if not is_boring(text):
                        shared[text] += 1
            common = sorted(
                (
                    (text, count)
                    for text, count in shared.items()
                    if count >= max(2, len(members) - 1)
                ),
                key=lambda item: (-item[1], -score_string(item[0], goodware.count(item[0]), pestudio)),
            )[: args.max_strings]
            if common:
                rule = build_super_rule(members, common, args.identifier)
                if rule:
                    rules.append(rule)

    if not args.no_inverse and goodware.samples:
        print("[+] Generating inverse (benign exception) rules")
        for path, sample in _benign_samples(args.good_dir).items():
            kept = [
                (text, score_string(text, goodware.count(text), pestudio))
                for text in sample.strings
                if not is_boring(text)
                and score_string(text, goodware.count(text), pestudio) >= LOW_SCORE_THRESHOLD
            ][: args.max_strings]
            folders = [str(Path(path).parent)]
            rule = build_inverse_rule(sample, kept, args.identifier, folders)
            if rule:
                rules.append(rule)

    print(f"[+] {len(rules)} rule(s) total "
          f"({sum(1 for r in rules if r.kind == 'simple')} simple, "
          f"{sum(1 for r in rules if r.kind == 'super')} super, "
          f"{sum(1 for r in rules if r.kind == 'inverse')} inverse)")

    out = Path(args.output)
    gaps: list[str] = []
    written: list[Path] = []

    if args.format in ("yara", "both"):
        path = out.with_suffix(".yara") if out.suffix == ".yaml" else out
        if args.format == "both":
            path = out.with_suffix(".yara")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(emit_yara(rules, header), encoding="utf-8")
        written.append(path)
        print(f"[+] Wrote {path}")

    if args.format in ("hydra", "both"):
        path = out.with_suffix(".yaml") if out.suffix in (".yara", ".yml") else out
        if args.format == "both":
            path = out.with_suffix(".yaml")
        text, gaps = emit_hydra(rules, header, args.set_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)
        print(f"[+] Wrote {path}")

    if gaps:
        unique = list(dict.fromkeys(gaps))
        print(f"[!] {len(unique)} construct(s) had no HydraDragonSig equivalent:")
        for gap in unique:
            print(f"      - {gap}")

    for path in written:
        print(f"[+] {path} : {path.stat().st_size} bytes")

    if args.strict and gaps:
        print("[!] --strict: exiting non-zero because the conversion was lossy")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
