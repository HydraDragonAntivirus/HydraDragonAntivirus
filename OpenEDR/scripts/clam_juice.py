#!/usr/bin/env python3
"""
ClamAV Signature Database Filter Tool

This tool filters all major ClamAV signature file formats by platform prefix,
allowing significant database size reduction for specialized environments.

Supported formats:
- .ndb - Extended signatures (filters by type field and name)
- .hdb - Hash database (filters by name prefix)
- .mdb - PE section hash (100% Windows)
- .hsb - SHA256 hash database (filters by name prefix where available)
- .ldb - Logical signatures (filters by name prefix)

Usage:
    ./clam_juice.py --input main.cvd --output ./filtered --profile linux-only
    ./clam_juice.py --input main.cvd --output ./filtered \
        --exclude-platforms Win,Doc,Osx
    ./clam_juice.py --input main.cvd --output ./filtered \
        --include-platforms Unix,Linux --exclude-types mdb,hsb
    ./clam_juice.py --directory ./database --output ./filtered \
        --profile android-only
"""

import argparse
import fnmatch
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from collections import defaultdict
from pathlib import Path


class ComprehensiveFilter:
    """Filter all ClamAV signature file formats."""

    # Signature database files dropped entirely (matched case-insensitively by
    # filename). JavaScript and phish/email formats are not meaningfully
    # scannable on Android.
    EXCLUDE_FILES = {"javascript.ndb", "phish.ndb"}

    # Predefined filtering profiles
    PROFILES = {
        "cross-platform": {
            "description": "Keep Andr, Unix, Linux, PUA + all Phishing; drop Win, Osx, Java, Email (email formats unsupported on Android)",
            "include_platforms": ["Andr", "Unix", "Linux"],
            "exclude_platforms": ["Win", "Osx", "Java", "Email"],
            "keep_if_contains": ["Phishing"],
            "exclude_types": [],
            # NDB target types kept: 0 Any, 3 HTML, 5 Graphics, 6 ELF,
            # 7 ASCII, 10 PDF. Dropped: 1 PE, 2 OLE2, 4 Mail, 9 Mach-O,
            # 11 Flash, 12 Java.
            "ndb_types": ["0", "3", "5", "6", "7", "10"],
        },
        "android-only": {
            "description": "Android-only antivirus — keep only Andr-prefixed signatures",
            "include_platforms": ["Andr"],
            "exclude_types": [],
            "ndb_types": None,
        },
        "linux-only": {
            "description": "Linux-only system, no Windows/Mac clients",
            "exclude_platforms": ["Win", "Osx", "Doc", "Xls", "Ppt", "Rtf"],
            "exclude_types": ["mdb"],  # MDB is 100% Windows
            "ndb_types": [
                "0",
                "5",
                "6",
                "7",
                "10",
                "12",
            ],  # Any, Graphics, ELF, ASCII, PDF, Java
        },
        "embedded": {
            "description": "Embedded/IoT device with minimal resources",
            "exclude_platforms": [
                "Win",
                "Osx",
                "Doc",
                "Xls",
                "Ppt",
                "Html",
                "Swf",
                "Java",
            ],
            "exclude_types": ["mdb", "hsb", "ldb"],  # Exclude large/complex formats
            "ndb_types": ["0", "6"],  # Any, ELF only
        },
        "mail-server": {
            "description": "Mail server scanning attachments",
            "exclude_platforms": ["Osx", "Dos", "Andr"],
            "exclude_types": [],
            "ndb_types": [
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "10",
                "12",
            ],  # Keep mail-relevant types (excludes Mach-O, Flash)
        },
        "web-server": {
            "description": "Web server scanning uploads",
            "exclude_platforms": ["Win", "Osx", "Dos"],
            "exclude_types": ["mdb"],
            "ndb_types": [
                "0",
                "3",
                "5",
                "7",
                "10",
                "12",
            ],  # Any, HTML, Graphics, ASCII, PDF, Java
        },
        "windows-exe": {
            "description": "Windows workstation: PE executables ( NOT Android ). "
            "Keeps Win/W32 + Eicar/Heuristics names; NDB targets Any+PE; LDB "
            "targets Any+PE; .ftm/.idb/.crb kept whole (first field is not a "
            "platform name there); hash DBs + container metadata dropped "
            "(the engine evaluates neither on the simple scan path).",
            "include_platforms": ["Win", "W32"],
            "exclude_platforms": [],
            # ditekSHen = author tag on 100+ Target-1 PE indicators in
            # clamav.ldb / indicator_rmm.ldb; Foxhole = Sanesecurity
            # malicious-attachment archive sigs (filename-based, evaluable
            # once member names are wired).
            "keep_if_contains": ["Eicar", "Heuristics", "ditekSHen", "Foxhole"],
            # ALL TwinWave/TwinClams branches: measured 0 confirmations across
            # malicious PE sets while burning full-buffer re-verification on
            # every binary (including the DROPADABASE mimikatz set — kept out
            # for the speed trial; restore by dropping "twinw" below if a
            # TwinWave FOUND ever matters). Case-insensitive.
            "exclude_name_contains": [],
            # Hash DBs: engine skips them (xor-filter pipeline owns hashes).
            # cvd/cld/sign: carriers the engine cannot read (bytecode.cvd is
            # unpacked to .cbc instead, see below). .cdb IS kept (Win/Foxhole
            # names): the extractor wiring feeds member metadata, so archive
            # member size/position/name signatures evaluate.
            "exclude_types": ["hdb", "hdu", "hsb", "hsu", "mdb", "mdu",
                              "msb", "msu", "imp", "fp", "sfp",
                              "cvd", "cld", "sign"],
            "ndb_types": ["0", "1"],  # Any, PE ("*" normalized to Any)
            "ldb_targets": ["0", "1"],  # Any, PE (missing Target = generic)
            # First field is NOT a signature name here: ftm starts with the
            # magictype, crb with a serial label, idb names are tiny anyway.
            "keep_files_unfiltered": ["ftm", "idb", "crb"],
            # Drop legacy base database (main.*) and metadata (.info, COPYING, cfg)
            # to save ~350MB RAM while keeping fresh active daily.* and heuristics.
            # "exclude_files": ["main.*", "*.info", "COPYING*", "*.cfg", "freshclam.dat"],
            "exclude_files": ["*.info", "COPYING*", "*.cfg", "freshclam.dat"],
            "drop_extensions": ["cvd", "cld", "sign"],
            "unpack_bytecode_cvd": True,
        },
        "hydradragon": {
            "description": "HydraDragon AV engine (hydradragonclamav / openedr_static): "
            "keep ALL platforms and ALL signature types except hash-based DBs "
            "(bloom filters handle those) and specific PUA packer categories "
            "that the engine unpacks itself. Unpacks CVDs to loose files. "
            "Loads .ign2 files from --external-ign2-dir to drop false positives.",
            # No platform filtering — keep everything.
            "include_platforms": [],
            "exclude_platforms": [],
            # PUA packer categories HydraDragon unpacks natively.
            "exclude_pua": [
                "PUA.Win.Packer",
                "PUA.Win.Trojan.Packed",
                "PUA.Win.Trojan.Molebox",
                "PUA.Win.Packer.Upx",
                "PUA.Doc.Packed",
            ],
            # Hash DBs: engine skips them (xor-filter pipeline owns hashes).
            # cvd/cld/sign: carriers the engine cannot read (bytecode.cvd is
            # unpacked to .cbc instead).
            "exclude_types": ["hdb", "hdu", "hsb", "hsu", "mdb", "mdu",
                              "msb", "msu", "imp", "fp", "sfp",
                              "cvd", "cld", "sign"],
            # No NDB/LDB target restriction — keep all file types.
            "ndb_types": None,
            "ldb_targets": None,
            "keep_files_unfiltered": ["ftm", "idb", "crb"],
            "exclude_files": ["*.info", "COPYING*", "*.cfg", "freshclam.dat"],
            "drop_extensions": ["cvd", "cld", "sign"],
            "unpack_bytecode_cvd": True,
        },
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.stats = defaultdict(lambda: {"original": 0, "filtered": 0})
        # Signature names listed in .ign / .ign2 ignore files — any signature
        # with one of these names is dropped during filtering.
        self.ignore_names = set()
        # PUA signature-name prefixes to drop (prefix match, so
        # "PUA.Win.Packer" also covers "PUA.Win.Packer.Upx-6").
        self.exclude_pua = []

    def log(self, message):
        """Log an informational message if verbose mode is enabled."""
        if self.verbose:
            print(f"[INFO] {message}", file=sys.stderr)

    def error(self, message):
        """Log an error message to stderr."""
        print(f"[ERROR] {message}", file=sys.stderr)

    def run_command(self, cmd, cwd=None):
        """Run a shell command and return its stdout."""
        self.log(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.error(f"Command failed: {' '.join(cmd)}")
            self.error(f"stderr: {e.stderr}")
            raise

    def unpack_cvd(self, cvd_path, extract_dir):
        """Unpack a CVD/CLD file. Falls back to pure-Python when sigtool is unavailable."""
        self.log(f"Unpacking {cvd_path}")
        try:
            self.run_command(["sigtool", "--unpack", cvd_path], cwd=extract_dir)
            return
        except (FileNotFoundError, OSError, subprocess.CalledProcessError):
            self.log("sigtool not found, using Python fallback")
        # Pure-Python: 512-byte ClamAV-VDB header + gzip tar.
        import gzip
        import tarfile
        import io
        with open(cvd_path, "rb") as f:
            blob = f.read()
        if len(blob) <= 512:
            return
        body = blob[512:]
        raw = gzip.decompress(body)
        tar = tarfile.open(fileobj=io.BytesIO(raw))
        tar.extractall(path=extract_dir)
        tar.close()

    def _get_effective_prefix(self, name):
        """Extract the effective platform prefix (e.g. Win, Andr, Linux).
        Handles PUA (PUA.Win.X -> Win) and third-party unofficial vendors
        (SecuriteInfo.com.Win.X -> Win, SecuriteInfo.Win.X -> Win, Sanesecurity.Win.X -> Win).
        """
        parts = name.split(".")
        if not parts:
            return ""

        idx = 0
        p0_lower = parts[0].lower()
        if p0_lower in ("securiteinfo", "sanesecurity", "porcupine", "malwarepatrol", "yararules"):
            idx = 1
            if p0_lower == "securiteinfo" and len(parts) > 2 and parts[1].lower() == "com":
                idx = 2

        rem = parts[idx:]
        if not rem:
            return parts[0]

        if len(rem) >= 2 and rem[0].upper() == "PUA":
            return rem[1]
        return rem[0]

    def _is_excluded_pua(self, name):
        """True when a signature name matches an excluded PUA prefix."""
        if not self.exclude_pua or not name:
            return False
        return any(name.startswith(p) for p in self.exclude_pua)

    def _load_ignore_file(self, file_path, is_ign2=False):
        """Read signature ignore list from .ign or .ign2 file."""
        if not os.path.exists(file_path):
            return
        self.log(f"Loading ignore file: {os.path.basename(file_path)}")
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if is_ign2:
                        self.ignore_names.add(line)
                    else:
                        # Format is dbname:lineno:signaturename
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            self.ignore_names.add(parts[2].strip())
                        else:
                            self.ignore_names.add(parts[-1].strip())
        except Exception as e:
            self.error(f"Failed to read ignore file {file_path}: {e}")

    def _is_unofficial_signature(self, name):
        """Check if a signature comes from an unofficial third-party source."""
        if not name:
            return False
        lowered = name.lower()
        if "unofficial" in lowered:
            return True
        unofficial_vendors = (
            "securiteinfo", "sanesecurity", "porcupine", "malwarepatrol",
            "oitc", "scamnailer", "foxhole", "yararules", "interserver",
            "miscreantpunch", "crdf", "bofhland", "junk"
        )
        parts = lowered.split(".")
        if parts[0] in unofficial_vendors or (len(parts) > 1 and parts[1] == "com"):
            return True
        return False

    def should_keep_signature(self, name, exclude_platforms, include_platforms, keep_if_contains=None, exclude_contains=None):
        """Determine if a signature should be kept based on its name."""
        if name and name in self.ignore_names:
            return False

        if name and ("eicar" in name.lower() or "test.eicar" in name.lower()):
            return True

        # Drop signatures matching excluded PUA packer prefixes (prefix match,
        # so "PUA.Win.Packer" also covers "PUA.Win.Packer.Upx-6").
        if self._is_excluded_pua(name):
            return False

        # Subfamily kill-list (e.g. doc/macro-oriented TwinWave branches that
        # can never confirm on PE in this engine yet burn full-buffer
        # re-verification on every binary). Checked before anything else.
        if name and exclude_contains:
            lowered = name.lower()
            for sub in exclude_contains:
                if sub.lower() in lowered:
                    return False

        if not name or "." not in name:
            return len(include_platforms) == 0

        prefix = self._get_effective_prefix(name)

        if exclude_platforms and prefix in exclude_platforms:
            return False

        # Unofficial / third-party community signatures: preserve unless explicitly excluded by platform
        if self._is_unofficial_signature(name):
            return True

        if include_platforms and prefix in include_platforms:
            return True

        # Generic malware types without explicit OS prefix (e.g. SecuriteInfo.com.Trojan-1234 or Trojan.Generic)
        if include_platforms and "Win" in include_platforms:
            if prefix.lower() in ("trojan", "malware", "backdoor", "exploit", "ransomware", "virus", "worm", "dropper", "heuristics", "heuristic", "generic"):
                return True

        if keep_if_contains and name:
            for kw in keep_if_contains:
                if kw.lower() in name.lower():
                    return True

        if include_platforms:
            return False

        return True

    def filter_ndb(self, file_path, exclude_platforms, include_platforms, ndb_types, keep_if_contains=None, exclude_contains=None):
        """Filter .ndb extended signature file."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                parts = line.split(":", 3)

                if len(parts) >= 4:
                    name = parts[0]
                    sig_type = parts[1]
                    # "*" / "" target = generic Any (engine treats both as
                    # target None -> matches every file type, incl. PE).
                    if sig_type in ("*", ""):
                        sig_type = "0"

                    keep_platform = self.should_keep_signature(
                        name, exclude_platforms, include_platforms, keep_if_contains,
                        exclude_contains,
                    )
                    keep_type = ndb_types is None or sig_type in ndb_types

                    if keep_platform and keep_type:
                        filtered_lines.append(line)
                        filtered_count += 1
                else:
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["ndb"]["original"] += original_count
        self.stats["ndb"]["filtered"] += filtered_count
        self.log(f"NDB: kept {filtered_count}/{original_count}")

    def filter_hdb(self, file_path, exclude_platforms, include_platforms, keep_if_contains=None):
        """Filter .hdb hash database file."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                parts = line.split(":")

                if len(parts) >= 3:
                    name = parts[2]
                    if self.should_keep_signature(
                        name, exclude_platforms, include_platforms, keep_if_contains
                    ):
                        filtered_lines.append(line)
                        filtered_count += 1
                else:
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["hdb"]["original"] += original_count
        self.stats["hdb"]["filtered"] += filtered_count
        self.log(f"HDB: kept {filtered_count}/{original_count}")

    def filter_hsb(self, file_path, exclude_platforms, include_platforms, keep_if_contains=None):
        """Filter .hsb SHA256 hash database file."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                parts = line.split(":")

                if len(parts) >= 3:
                    name = parts[2]
                    if self.should_keep_signature(
                        name, exclude_platforms, include_platforms, keep_if_contains
                    ):
                        filtered_lines.append(line)
                        filtered_count += 1
                else:
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["hsb"]["original"] += original_count
        self.stats["hsb"]["filtered"] += filtered_count
        self.log(f"HSB: kept {filtered_count}/{original_count}")

    def filter_mdb(self, file_path, exclude_platforms, include_platforms, keep_if_contains=None):
        """Filter .mdb PE section hash file (100% Windows)."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")

        if "Win" in exclude_platforms and not keep_if_contains:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                original_count = sum(
                    1 for line in f if line.strip() and not line.startswith("#")
                )
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("# MDB signatures filtered (100% Windows PE)\n")
            self.stats["mdb"]["original"] += original_count
            self.stats["mdb"]["filtered"] += 0
            self.log(
                f"MDB: excluded entire file ({original_count} Windows PE signatures)"
            )
            return

        self.filter_hdb(file_path, exclude_platforms, include_platforms, keep_if_contains)

    def filter_first_field(self, file_path, exclude_platforms, include_platforms, keep_if_contains=None):
        """Generic filter for files where the first colon-delimited field is the signature name."""
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(raw)
                    continue

                original_count += 1
                name = line.split(":", 1)[0]
                if self.should_keep_signature(
                    name, exclude_platforms, include_platforms, keep_if_contains
                ):
                    filtered_lines.append(raw)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(filtered_lines)

        ext = os.path.basename(file_path).rsplit(".", 1)[-1]
        self.stats[ext]["original"] += original_count
        self.stats[ext]["filtered"] += filtered_count
        self.log(f"{ext.upper()}: kept {filtered_count}/{original_count}")

    @staticmethod
    def _ldb_target(line):
        """Extract the `Target:` value from an .ldb TDB block.

        Returns the raw value ("0".."14", "*") or None when the line carries
        no Target field — the engine treats that as generic (matches every
        file type, incl. PE), so callers must keep it.
        """
        import re
        segments = line.split(";")
        if len(segments) < 2:
            return None
        m = re.search(r"(?:^|,)Target:(\*|\d+)", segments[1])
        return m.group(1) if m else None

    def filter_ldb(self, file_path, exclude_platforms, include_platforms, keep_if_contains=None, ldb_targets=None, exclude_contains=None):
        """Filter .ldb logical signature file.

        When `ldb_targets` is given (e.g. ["0", "1"] for Windows PE), a line
        is additionally required to target one of those types; lines without
        a Target field (generic) are always kept.
        """
        if not os.path.exists(file_path):
            return

        self.log(f"Filtering {os.path.basename(file_path)}")
        filtered_lines = []
        original_count = 0
        filtered_count = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    filtered_lines.append(line)
                    continue

                original_count += 1
                parts = line.split(";", 1)

                if len(parts) >= 1:
                    name = parts[0]
                    if self.should_keep_signature(
                        name, exclude_platforms, include_platforms, keep_if_contains,
                        exclude_contains,
                    ):
                        target = self._ldb_target(line)
                        if target in ("*", ""):
                            target = "0"
                        if ldb_targets is None or target is None or target in ldb_targets:
                            filtered_lines.append(line)
                            filtered_count += 1
                else:
                    filtered_lines.append(line)
                    filtered_count += 1

        with open(file_path, "w", encoding="utf-8") as f:
            for line in filtered_lines:
                f.write(line + "\n")

        self.stats["ldb"]["original"] += original_count
        self.stats["ldb"]["filtered"] += filtered_count
        self.log(f"LDB: kept {filtered_count}/{original_count}")

    def exclude_file_type(self, file_path):
        """Exclude an entire file type by deleting it."""
        if not os.path.exists(file_path):
            return

        basename = os.path.basename(file_path)
        ext = basename.split(".")[-1]

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            original_count = sum(
                1 for line in f if line.strip() and not line.startswith("#")
            )

        try:
            os.remove(file_path)
        except OSError:
            pass

        self.stats[ext]["original"] += original_count
        self.stats[ext]["filtered"] += 0
        self.log(f"Removed excluded file: {basename} ({original_count} signatures)")

    def _get_bytecode_platform(self, file_path):
        """Extract the platform prefix from a ClamAV bytecode .cbc file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(500)
            s = data.decode("latin-1")
            import re
            m = re.search(r"BC\.(\w+)", s)
            return m.group(1) if m else None
        except Exception:
            return None

    def filter_bytecode_dir(self, src_bc_dir, dst_bc_dir, exclude_platforms,
                            include_platforms, keep_if_contains=None):
        """Filter bytecode .cbc files by platform prefix."""
        os.makedirs(dst_bc_dir, exist_ok=True)
        total = kept = 0
        for fname in os.listdir(src_bc_dir):
            if not fname.endswith(".cbc"):
                continue
            src = os.path.join(src_bc_dir, fname)
            dst = os.path.join(dst_bc_dir, fname)
            total += 1
            platform = self._get_bytecode_platform(src)
            if platform is None:
                shutil.copy2(src, dst)
                kept += 1
                continue
            prefix = platform
            if exclude_platforms and prefix in exclude_platforms:
                continue
            if include_platforms and prefix in include_platforms:
                shutil.copy2(src, dst)
                kept += 1
                continue
            if keep_if_contains:
                s = Path(src).read_bytes().decode("latin-1", errors="replace")
                for kw in keep_if_contains:
                    if kw.lower() in s.lower():
                        shutil.copy2(src, dst)
                        kept += 1
                        break
                continue
            # Not matching any keep rule → exclude
        self.stats["cbc"]["original"] += total
        self.stats["cbc"]["filtered"] += kept
        self.log(f"Bytecode: kept {kept}/{total}")

    def _filter_dir(self, src_dir, dst_dir, exclude_platforms, include_platforms,
                    ndb_types, exclude_file_types, keep_if_contains=None,
                    exclude_files=None, ldb_targets=None,
                    keep_unfiltered=None, drop_extensions=None,
                    unpack_bytecode=False, exclude_contains=None):
        """Filter files in src_dir and copy results to dst_dir."""
        os.makedirs(dst_dir, exist_ok=True)
        if exclude_files is None:
            exclude_files = self.EXCLUDE_FILES
        else:
            exclude_files = {e.lower() for e in exclude_files}
        keep_unfiltered = {e.lower() for e in (keep_unfiltered or [])}
        drop_extensions = {e.lower() for e in (drop_extensions or [])}

        # Load ignore list from .ign and .ign2 files in the source directory,
        # merging with any externally-loaded names (--external-ign2-dir).
        external_names = set(self.ignore_names)  # preserve pre-loaded names
        self.ignore_names = external_names
        for item in os.listdir(src_dir):
            item_lower = item.lower()
            if item_lower.endswith(".ign") or item_lower.endswith(".ign2"):
                file_path = os.path.join(src_dir, item)
                if os.path.isfile(file_path):
                    self._load_ignore_file(file_path, is_ign2=item_lower.endswith(".ign2"))

        # Copy all files first, skipping databases that are dropped entirely.
        # Default (Android flow): javascript.ndb / phish.ndb are excluded since
        # JavaScript and email/phish formats are not meaningfully scannable on
        # Android. Profiles may override via `exclude_files` / `drop_extensions`
        # (e.g. windows-exe drops unreadable .cvd/.cld/.sign carriers).
        for item in os.listdir(src_dir):
            item_lower = item.lower()
            if exclude_files and any(fnmatch.fnmatch(item_lower, pat.lower()) for pat in exclude_files):
                self.log(f"Dropping excluded file: {item}")
                continue
            if "." in item and item.rsplit(".", 1)[-1].lower() in drop_extensions:
                self.log(f"Dropping carrier file: {item}")
                continue
            src = os.path.join(src_dir, item)
            dst = os.path.join(dst_dir, item)
            if os.path.isfile(src):
                shutil.copy2(src, dst)

        # Filter each file type in-place in dst_dir
        for ndb_file in Path(dst_dir).glob("*.ndb"):
            self.filter_ndb(str(ndb_file), exclude_platforms, include_platforms, ndb_types, keep_if_contains, exclude_contains)

        for hdb_file in Path(dst_dir).glob("*.hdb"):
            if "hdb" in exclude_file_types:
                self.exclude_file_type(str(hdb_file))
            else:
                self.filter_hdb(str(hdb_file), exclude_platforms, include_platforms, keep_if_contains)

        for hsb_file in Path(dst_dir).glob("*.hsb"):
            if "hsb" in exclude_file_types:
                self.exclude_file_type(str(hsb_file))
            else:
                self.filter_hsb(str(hsb_file), exclude_platforms, include_platforms, keep_if_contains)

        for mdb_file in Path(dst_dir).glob("*.mdb"):
            if "mdb" in exclude_file_types:
                self.exclude_file_type(str(mdb_file))
            else:
                self.filter_mdb(str(mdb_file), exclude_platforms, include_platforms, keep_if_contains)

        for ldb_file in Path(dst_dir).glob("*.ldb"):
            if "ldb" in exclude_file_types:
                self.exclude_file_type(str(ldb_file))
            else:
                self.filter_ldb(str(ldb_file), exclude_platforms, include_platforms, keep_if_contains, ldb_targets, exclude_contains)

        # Update files (same format as base)
        for ext in ("ndu", "ldu", "hdu", "hsu", "mdu"):
            for f in Path(dst_dir).glob(f"*.{ext}"):
                if ext in exclude_file_types:
                    self.exclude_file_type(str(f))
                else:
                    ext_base = ext[:-1] + "b"
                    fn = getattr(self, f"filter_{ext_base}", None)
                    if fn is None:
                        continue
                    if ext_base == "ndb":
                        fn(str(f), exclude_platforms, include_platforms, ndb_types, keep_if_contains, exclude_contains)
                    elif ext_base == "ldb":
                        fn(str(f), exclude_platforms, include_platforms, keep_if_contains, ldb_targets, exclude_contains)
                    else:
                        fn(str(f), exclude_platforms, include_platforms, keep_if_contains)

        # Additional formats where first colon-field is the name.
        # NOTE: .ftm (first field = magictype) and .crb (first field = serial
        # label) do NOT carry platform names there — name-filtering them would
        # wipe the whole file. Profiles list such extensions in
        # `keep_files_unfiltered` (windows-exe does for ftm/idb/crb).
        for ext in ("cdb", "crb", "idb", "ign", "ign2", "ftm", "msb"):
            for f in Path(dst_dir).glob(f"*.{ext}"):
                if ext in exclude_file_types:
                    self.exclude_file_type(str(f))
                elif ext in keep_unfiltered:
                    self.log(f"Keeping {f.name} whole (first field is not a platform name)")
                else:
                    self.filter_first_field(str(f), exclude_platforms, include_platforms, keep_if_contains)

        for ext in exclude_file_types:
            if ext not in ["ndb", "hdb", "hsb", "mdb", "ldb"]:
                for file in Path(dst_dir).glob(f"*.{ext}"):
                    self.exclude_file_type(str(file))

        # Filter bytecode subdirectory
        src_bc = os.path.join(src_dir, "bytecode")
        dst_bc = os.path.join(dst_dir, "bytecode")
        if os.path.isdir(src_bc):
            self.filter_bytecode_dir(src_bc, dst_bc, exclude_platforms,
                                     include_platforms, keep_if_contains)

        # Unpack *.cvd carriers (512-byte header + gzip tar) and keep only
        # platform-relevant .cbc programs, written FLAT into the output root
        # (no bytecode/ subdir): the engine reads loose *.cbc files only.
        # Raw .cvd/.cld files are unreadable to it, so profiles that drop
        # those carriers (windows-exe) still recover their bytecode here.
        if unpack_bytecode:
            self._unpack_bytecode_cvds(src_dir, dst_dir, exclude_platforms,
                                       include_platforms, keep_if_contains)

        # Remove empty database files
        self._remove_empty_dbs(dst_dir)

        # Remove .ign and .ign2 files from the filtered output directory
        self.log("Removing ignore files from the filtered output directory")
        for item in os.listdir(dst_dir):
            item_lower = item.lower()
            if item_lower.endswith(".ign") or item_lower.endswith(".ign2"):
                file_path = os.path.join(dst_dir, item)
                if os.path.isfile(file_path):
                    try:
                        os.unlink(file_path)
                    except Exception as e:
                        self.error(f"Failed to remove ignore file {file_path}: {e}")

    def _iter_cvd_members(self, cvd_path):
        """Yield (name, bytes) for members of a .cvd/.cld carrier.

        Layout: 512-byte `ClamAV-VDB:` header + gzip-compressed tar. Falls
        back to `sigtool --unpack` when the Python path fails.
        """
        import gzip
        import tarfile
        import io
        with open(cvd_path, "rb") as f:
            blob = f.read()
        if len(blob) <= 512:
            return
        body = blob[512:]
        try:
            raw = gzip.decompress(body)
            tar = tarfile.open(fileobj=io.BytesIO(raw))
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                fh = tar.extractfile(member)
                if fh is not None:
                    yield member.name, fh.read()
            return
        except Exception as e:
            self.log(f"Python CVD unpack failed for {os.path.basename(cvd_path)}: {e}")
        # Fallback: sigtool, when installed.
        with tempfile.TemporaryDirectory() as tmp:
            try:
                self.run_command(["sigtool", "--unpack", cvd_path], cwd=tmp)
                for root, _, files in os.walk(tmp):
                    for fn in files:
                        p = os.path.join(root, fn)
                        with open(p, "rb") as fh:
                            yield fn, fh.read()
            except Exception as e:
                self.error(f"sigtool unpack failed for {cvd_path}: {e}")

    def _unpack_bytecode_cvds(self, src_dir, dst_root_dir, exclude_platforms,
                              include_platforms, keep_if_contains=None):
        """Extract platform-relevant .cbc programs from *.cvd carriers,
        written flat into the output root (no subdirectories)."""
        os.makedirs(dst_root_dir, exist_ok=True)
        total = kept = 0
        for item in sorted(os.listdir(src_dir)):
            if not item.lower().endswith((".cvd", ".cld")):
                continue
            for name, data in self._iter_cvd_members(os.path.join(src_dir, item)):
                if not name.endswith(".cbc"):
                    continue
                total += 1
                try:
                    text = data.decode("latin-1")
                except Exception:
                    continue
                import re
                m = re.search(r"BC\.(\w+)", text[:500])
                platform = m.group(1) if m else None
                keep = False
                if platform is None:
                    keep = True
                elif exclude_platforms and platform in exclude_platforms:
                    keep = False
                elif include_platforms and platform in include_platforms:
                    keep = True
                elif keep_if_contains and any(
                    kw.lower() in text.lower() for kw in keep_if_contains
                ):
                    keep = True
                elif not include_platforms:
                    keep = True
                if keep:
                    with open(os.path.join(dst_root_dir, os.path.basename(name)), "wb") as f:
                        f.write(data)
                    kept += 1
        self.stats["cbc"]["original"] += total
        self.stats["cbc"]["filtered"] += kept
        self.log(f"Bytecode from CVD: kept {kept}/{total}")

    def _remove_empty_dbs(self, directory):
        """Delete database files that contain no real signatures."""
        db_exts = {"ndb", "hdb", "hsb", "mdb", "ldb", "cdb", "crb", "ftm",
                    "idb", "ign", "ign2", "msb", "ndu", "hdu", "hsu", "mdu",
                    "msu", "ldu", "pdb", "wdb", "fp", "sfp"}
        for f in Path(directory).iterdir():
            if not f.is_file():
                continue
            ext = f.suffix.lstrip(".").lower()
            if ext not in db_exts:
                continue
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                has_sig = any(
                    line.strip() and not line.startswith("#")
                    for line in fh
                )
            if not has_sig:
                f.unlink()

    def filter_database(
        self,
        input_path,
        output_dir,
        exclude_platforms=None,
        include_platforms=None,
        ndb_types=None,
        exclude_file_types=None,
        keep_if_contains=None,
        exclude_files=None,
        ldb_targets=None,
        keep_unfiltered=None,
        drop_extensions=None,
        unpack_bytecode=False,
        exclude_contains=None,
    ):
        """Main filtering workflow for CVD files."""

        exclude_platforms = set(exclude_platforms or [])
        include_platforms = set(include_platforms or [])
        exclude_file_types = set(exclude_file_types or [])
        keep_if_contains = set(keep_if_contains or [])

        with tempfile.TemporaryDirectory() as temp_dir:
            self.log(f"Using temporary directory: {temp_dir}")
            self.unpack_cvd(input_path, temp_dir)
            self._filter_dir(temp_dir, output_dir, exclude_platforms,
                             include_platforms, ndb_types, exclude_file_types,
                             keep_if_contains, exclude_files, ldb_targets,
                             keep_unfiltered, drop_extensions, unpack_bytecode,
                             exclude_contains)

    def filter_directory(
        self,
        src_dir,
        output_dir,
        exclude_platforms=None,
        include_platforms=None,
        ndb_types=None,
        exclude_file_types=None,
        keep_if_contains=None,
        exclude_files=None,
        ldb_targets=None,
        keep_unfiltered=None,
        drop_extensions=None,
        unpack_bytecode=False,
        exclude_contains=None,
    ):
        """Filter an already-extracted database directory."""

        exclude_platforms = set(exclude_platforms or [])
        include_platforms = set(include_platforms or [])
        exclude_file_types = set(exclude_file_types or [])
        keep_if_contains = set(keep_if_contains or [])

        self._filter_dir(src_dir, output_dir, exclude_platforms,
                         include_platforms, ndb_types, exclude_file_types,
                         keep_if_contains, exclude_files, ldb_targets,
                         keep_unfiltered, drop_extensions, unpack_bytecode,
                         exclude_contains)

        # Print statistics
        self.print_statistics()
        print(f"\nFiltered database deployed to: {output_dir}")
        print("\nTo use with ClamAV, add to /etc/clamav/clamd.conf:")
        print(f"  DatabaseDirectory {output_dir}")

    def filter_cvds_only(
        self,
        src_dir,
        output_dir,
        exclude_platforms=None,
        include_platforms=None,
        ndb_types=None,
        exclude_file_types=None,
        keep_if_contains=None,
        exclude_files=None,
        ldb_targets=None,
        keep_unfiltered=None,
        drop_extensions=None,
        unpack_bytecode=False,
        exclude_contains=None,
    ):
        """Unpack and filter only CVD/CLD files from src_dir.

        Unlike filter_directory (which copies and filters ALL files), this
        method finds every *.cvd and *.cld in src_dir, unpacks each one into
        a temporary directory, filters the unpacked content, and writes the
        results into output_dir.  Loose .ndb/.ldb/etc. files in src_dir are
        ignored.
        """
        exclude_platforms = set(exclude_platforms or [])
        include_platforms = set(include_platforms or [])
        exclude_file_types = set(exclude_file_types or [])
        keep_if_contains = set(keep_if_contains or [])

        os.makedirs(output_dir, exist_ok=True)

        # Collect CVD/CLD files to process.
        cvd_files = sorted(
            f for f in os.listdir(src_dir)
            if f.lower().endswith((".cvd", ".cld"))
        )
        if not cvd_files:
            self.error(f"No CVD/CLD files found in {src_dir}")
            return

        for cvd_name in cvd_files:
            cvd_path = os.path.join(src_dir, cvd_name)
            print(f"[ClamJuice] Unpacking and filtering {cvd_name} ...")
            with tempfile.TemporaryDirectory() as temp_unpack_dir, tempfile.TemporaryDirectory() as temp_filter_dir:
                self.unpack_cvd(cvd_path, temp_unpack_dir)
                self._filter_dir(
                    temp_unpack_dir, temp_filter_dir, exclude_platforms,
                    include_platforms, ndb_types, exclude_file_types,
                    keep_if_contains, exclude_files, ldb_targets,
                    keep_unfiltered, drop_extensions, unpack_bytecode,
                    exclude_contains,
                )
                for item in os.listdir(temp_filter_dir):
                    s = os.path.join(temp_filter_dir, item)
                    d = os.path.join(output_dir, item)
                    if os.path.isfile(s):
                        shutil.copy2(s, d)

        self._remove_empty_dbs(output_dir)
        # If drop_extensions includes CVD carriers, make sure no raw CVD/CLD
        # archives remain in the output directory (e.g. if src_dir == output_dir).
        if drop_extensions:
            for item in os.listdir(output_dir):
                if "." in item and item.rsplit(".", 1)[-1].lower() in drop_extensions:
                    try:
                        os.remove(os.path.join(output_dir, item))
                    except OSError:
                        pass
        self.print_statistics()
        print(f"\nFiltered database deployed to: {output_dir}")
        print("\nTo use with ClamAV, add to /etc/clamav/clamd.conf:")
        print(f"  DatabaseDirectory {output_dir}")

    def print_statistics(self):
        """Print filtering statistics."""
        print("\n" + "=" * 70)
        print("FILTERING STATISTICS")
        print("=" * 70)

        total_original = 0
        total_filtered = 0

        for file_type in sorted(self.stats.keys()):
            original = self.stats[file_type]["original"]
            filtered = self.stats[file_type]["filtered"]
            total_original += original
            total_filtered += filtered

            if original > 0:
                pct = 100 * filtered / original
                reduction = 100 * (1 - filtered / original)
                print(f"\n.{file_type.upper()} files:")
                print(f"  Original:  {original:10,} signatures")
                print(f"  Filtered:  {filtered:10,} signatures ({pct:5.1f}%)")
                removed = original - filtered
                print(
                    f"  Removed:   {removed:10,} signatures ({reduction:5.1f}% reduction)"
                )

        if total_original > 0:
            total_pct = 100 * total_filtered / total_original
            total_reduction = 100 * (1 - total_filtered / total_original)
            print("\n" + "=" * 70)
            print("TOTAL:")
            print(f"  Original:  {total_original:10,} signatures")
            print(f"  Filtered:  {total_filtered:10,} signatures ({total_pct:5.1f}%)")
            total_removed = total_original - total_filtered
            print(
                f"  Removed:   {total_removed:10,} signatures "
                f"({total_reduction:5.1f}% reduction)"
            )
            print("=" * 70)


def main():
    """Parse arguments and run the ClamAV signature database filter."""
    parser = argparse.ArgumentParser(
        description="ClamAV signature database filter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Filtering Profiles:
  android-only   - Android-only antivirus (keeps only Andr-prefixed signatures)

  linux-only     - Linux-only system (excludes Windows, Mac, Office)

  embedded       - Embedded/IoT device with minimal resources
                   Removes ~95%% of signatures (aggressive filtering)

  mail-server    - Mail server scanning attachments
                   Keeps most formats, excludes mobile/Mac

  web-server     - Web server scanning uploads
                   Excludes Windows PE, keeps web-relevant formats

  windows-exe    - Windows workstation: PE executables (NOT Android)
                   Keeps Win/W32 + Eicar/Heuristics, NDB/LDB targets Any+PE,
                   icons/certs/ftm whole, drops hash DBs + .cdb + .cvd carriers
                   (bytecode.cvd is unpacked to filtered .cbc instead)

Examples:
  # Windows-EXE filtering from an extracted database directory
  %(prog)s --directory ./clamav_database_filterme --output ./clamav_database_windows --profile windows-exe

  # Android-only filtering from CVD
  %(prog)s --input main.cvd --output ./filtered --profile android-only

  # Android-only filtering from extracted database directory
  %(prog)s --directory ./database --output ./filtered --profile android-only

  # Use a predefined profile
  %(prog)s --input /var/lib/clamav/main.cvd --output ./filtered --profile linux-only

  # Custom filtering: exclude Windows and Office
  %(prog)s --input main.cvd --output ./filtered --exclude-platforms Win,Doc,Xls

  # Keep only specific platforms
  %(prog)s --input main.cvd --output ./filtered --include-platforms Andr

  # Exclude entire file types (e.g., MDB is 100%% Windows)
  %(prog)s --input main.cvd --output ./filtered --exclude-types mdb,hsb

  # Combine multiple filters
  %(prog)s --input main.cvd --output ./filtered \\
           --exclude-platforms Win,Osx,Doc \\
           --exclude-types mdb \\
           --ndb-types 0,5,6,7

Platform Prefixes (case-sensitive):
  Andr   - Android applications
  Win    - Windows executables (63.5%% of all signatures)
  Doc    - Office documents (.doc, etc.)
  Xls    - Excel spreadsheets
  Pdf    - PDF documents
  Html   - HTML files
  Unix   - Unix/Linux files
  Osx    - macOS executables
  Java   - Java files
  Swf    - Flash files

File Types:
  ndb    - Extended signatures (23M, mixed platforms)
  hdb    - Hash database (5M, 53%% Windows)
  mdb    - PE section hash (244M, 100%% Windows)
  hsb    - SHA256 hash (161M, mostly generic)
  ldb    - Logical signatures (12M, mixed)
""",
    )

    parser.add_argument("--input", "-i", help="Input CVD/CLD file path")
    parser.add_argument("--directory", "-d", help="Already-extracted database directory (alternative to --input)")
    parser.add_argument("--output", "-o", help="Output directory path")
    parser.add_argument(
        "--cvd-only", action="store_true",
        help="With --directory: process ONLY .cvd/.cld files (unpack each, "
        "filter, merge into output). Ignores loose .ndb/.ldb/etc. files.",
    )

    parser.add_argument(
        "--profile",
        "-p",
        choices=ComprehensiveFilter.PROFILES.keys(),
        help="Use a predefined filtering profile",
    )

    parser.add_argument(
        "--exclude-platforms",
        "-e",
        help="Comma-separated platforms to EXCLUDE (e.g., Win,Doc,Osx)",
    )
    parser.add_argument(
        "--include-platforms",
        help="Comma-separated platforms to INCLUDE (excludes all others)",
    )

    parser.add_argument(
        "--ndb-types", "-t", help="NDB signature types to keep (e.g., 0,5,6,7)"
    )

    parser.add_argument(
        "--exclude-types", help="File types to exclude entirely (e.g., mdb,hsb)"
    )

    parser.add_argument(
        "--exclude-files", help="Comma-separated filenames or wildcards to exclude (e.g., main.*,*.info,COPYING)"
    )

    parser.add_argument(
        "--exclude-pua",
        help="Comma-separated PUA signature-name prefixes to drop (prefix match). "
        "E.g., PUA.Win.Packer,PUA.Doc.Packed",
    )

    parser.add_argument(
        "--external-ign2-dir",
        help="Directory containing .ign2 files to load for signature exclusion "
        "(e.g., HydraDragonAVPortable/database)",
    )

    parser.add_argument(
        "--keep-if-contains",
        help="Comma-separated substrings: keep signature if name contains any (e.g., Phishing)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--list-profiles", action="store_true", help="List available profiles and exit"
    )

    args = parser.parse_args()

    if args.list_profiles:
        print("Available Filtering Profiles:\n")
        for name, profile in ComprehensiveFilter.PROFILES.items():
            print(f"{name}:")
            print(f"  Description: {profile['description']}")
            if profile.get("include_platforms"):
                print(f"  Includes: {', '.join(profile['include_platforms'])}")
            if profile.get("exclude_platforms"):
                print(f"  Excludes: {', '.join(profile['exclude_platforms'])}")
            if profile.get("exclude_types"):
                print(f"  Excluded file types: {', '.join(profile['exclude_types'])}")
            if profile.get("ndb_types"):
                print(f"  NDB types: {', '.join(profile['ndb_types'])}")
            if profile.get("ldb_targets"):
                print(f"  LDB targets: {', '.join(profile['ldb_targets'])}")
            if profile.get("keep_if_contains"):
                print(f"  Keep if name contains: {', '.join(profile['keep_if_contains'])}")
            if profile.get("exclude_name_contains"):
                print(f"  Drop if name contains: {', '.join(profile['exclude_name_contains'])}")
            if profile.get("exclude_pua"):
                print(f"  Excluded PUA prefixes: {', '.join(profile['exclude_pua'])}")
            if profile.get("keep_files_unfiltered"):
                print(f"  Kept whole: {', '.join(profile['keep_files_unfiltered'])}")
            if profile.get("drop_extensions"):
                print(f"  Dropped carriers: {', '.join(profile['drop_extensions'])}")
            print()
        return

    # Validate required arguments (after --list-profiles check)
    if not args.input and not args.directory:
        parser.error("either --input/-i or --directory/-d is required")
    if args.input and args.directory:
        parser.error("use either --input or --directory, not both")
    if not args.output:
        parser.error("the following argument is required: --output/-o")

    # Parse arguments
    exclude_platforms = None
    include_platforms = None
    ndb_types = None
    exclude_types = None
    keep_if_contains = None
    exclude_pua = None

    if args.profile:
        profile = ComprehensiveFilter.PROFILES[args.profile]
        exclude_platforms = profile.get("exclude_platforms")
        include_platforms = profile.get("include_platforms")
        exclude_types = profile.get("exclude_types", [])
        ndb_types = profile.get("ndb_types")
        keep_if_contains = profile.get("keep_if_contains")
        exclude_pua = profile.get("exclude_pua")
        extra_opts = {
            "exclude_files": profile.get("exclude_files"),
            "ldb_targets": profile.get("ldb_targets"),
            "keep_unfiltered": profile.get("keep_files_unfiltered"),
            "drop_extensions": profile.get("drop_extensions"),
            "unpack_bytecode": profile.get("unpack_bytecode_cvd", False),
            "exclude_contains": profile.get("exclude_name_contains"),
        }
        print(f"Using profile: {args.profile}")
        print(f"Description: {profile['description']}\n")
    else:
        extra_opts = {}
        if (
            not args.exclude_platforms
            and not args.include_platforms
            and not args.exclude_types
            and not args.exclude_pua
        ):
            print(
                "Error: Must specify --profile, --exclude-platforms, "
                "--include-platforms, --exclude-types, or --exclude-pua"
            )
            sys.exit(1)

    # Override with command-line arguments
    if args.exclude_platforms:
        exclude_platforms = [p.strip() for p in args.exclude_platforms.split(",")]

    if args.include_platforms:
        include_platforms = [p.strip() for p in args.include_platforms.split(",")]

    if args.ndb_types:
        ndb_types = set(t.strip() for t in args.ndb_types.split(","))

    if args.exclude_types:
        exclude_types = [t.strip() for t in args.exclude_types.split(",")]

    if args.keep_if_contains:
        keep_if_contains = [k.strip() for k in args.keep_if_contains.split(",")]

    if args.exclude_files:
        extra_opts["exclude_files"] = [f.strip() for f in args.exclude_files.split(",")]

    if args.exclude_pua:
        exclude_pua = [p.strip() for p in args.exclude_pua.split(",")]

    if exclude_platforms and include_platforms:
        print("Note: exclude_platforms checked first, then include_platforms")

    # Run filter
    filter_tool = ComprehensiveFilter(verbose=args.verbose)

    # Set PUA exclusion prefixes on the filter instance.
    if exclude_pua:
        filter_tool.exclude_pua = list(exclude_pua)
        print(f"Excluding PUA prefixes: {', '.join(filter_tool.exclude_pua)}")

    # Load external .ign2 files (e.g. from HydraDragonAVPortable/database or securiteinfo.ign2).
    external_ign2_dir = args.external_ign2_dir
    if not external_ign2_dir:
        cand_dirs = [
            os.path.join(os.path.dirname(__file__), "..", "..", "HydraDragonAVPortable", "database"),
            os.path.join(os.path.dirname(__file__), "..", "..", "hydradragon", "database"),
            os.path.join(os.path.dirname(__file__), "..", "database"),
        ]
        for cd in cand_dirs:
            if os.path.isdir(cd) and any(f.lower().endswith((".ign2", ".ign")) for f in os.listdir(cd)):
                external_ign2_dir = cd
                break

    if external_ign2_dir and os.path.isdir(external_ign2_dir):
        print(f"Loading official & SecuriteInfo FP ignore rules from: {external_ign2_dir}")
        for item in sorted(os.listdir(external_ign2_dir)):
            if item.lower().endswith((".ign2", ".ign")):
                fp = os.path.join(external_ign2_dir, item)
                if os.path.isfile(fp):
                    filter_tool._load_ignore_file(fp, is_ign2=item.lower().endswith(".ign2"))
                    print(f"Loaded ignore file: {item} ({len(filter_tool.ignore_names)} names total)")

    try:
        if args.directory and getattr(args, 'cvd_only', False):
            filter_tool.filter_cvds_only(
                src_dir=args.directory,
                output_dir=args.output,
                exclude_platforms=exclude_platforms,
                include_platforms=include_platforms,
                ndb_types=ndb_types,
                exclude_file_types=exclude_types,
                keep_if_contains=keep_if_contains,
                **extra_opts,
            )
        elif args.directory:
            filter_tool.filter_directory(
                src_dir=args.directory,
                output_dir=args.output,
                exclude_platforms=exclude_platforms,
                include_platforms=include_platforms,
                ndb_types=ndb_types,
                exclude_file_types=exclude_types,
                keep_if_contains=keep_if_contains,
                **extra_opts,
            )
        else:
            filter_tool.filter_database(
                input_path=args.input,
                output_dir=args.output,
                exclude_platforms=exclude_platforms,
                include_platforms=include_platforms,
                ndb_types=ndb_types,
                exclude_file_types=exclude_types,
                keep_if_contains=keep_if_contains,
                **extra_opts,
            )
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
