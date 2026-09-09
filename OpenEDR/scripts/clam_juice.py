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
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.stats = defaultdict(lambda: {"original": 0, "filtered": 0})
        # Signature names listed in .ign / .ign2 ignore files — any signature
        # with one of these names is dropped during filtering.
        self.ignore_names = set()

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
        """Unpack a CVD/CLD file."""
        self.log(f"Unpacking {cvd_path}")
        self.run_command(["sigtool", "--unpack", cvd_path], cwd=extract_dir)

    def _get_effective_prefix(self, name):
        """For PUA.X.Y, return X as the effective platform. Otherwise return first segment."""
        parts = name.split(".")
        if len(parts) >= 2 and parts[0] == "PUA":
            return parts[1]
        return parts[0]

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

    def should_keep_signature(self, name, exclude_platforms, include_platforms, keep_if_contains=None):
        """Determine if a signature should be kept based on its name."""
        if name and name in self.ignore_names:
            return False

        if name and ("eicar" in name.lower() or "test.eicar" in name.lower()):
            return True

        if not name or "." not in name:
            return len(include_platforms) == 0

        prefix = self._get_effective_prefix(name)

        if exclude_platforms and prefix in exclude_platforms:
            return False

        if include_platforms and prefix in include_platforms:
            return True

        if keep_if_contains and name:
            for kw in keep_if_contains:
                if kw.lower() in name.lower():
                    return True

        if include_platforms:
            return False

        return True

    def filter_ndb(self, file_path, exclude_platforms, include_platforms, ndb_types, keep_if_contains=None):
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

                    keep_platform = self.should_keep_signature(
                        name, exclude_platforms, include_platforms, keep_if_contains
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

    def filter_ldb(self, file_path, exclude_platforms, include_platforms, keep_if_contains=None):
        """Filter .ldb logical signature file."""
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

        self.stats["ldb"]["original"] += original_count
        self.stats["ldb"]["filtered"] += filtered_count
        self.log(f"LDB: kept {filtered_count}/{original_count}")

    def exclude_file_type(self, file_path):
        """Exclude an entire file type by making it empty."""
        if not os.path.exists(file_path):
            return

        basename = os.path.basename(file_path)
        ext = basename.split(".")[-1]

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            original_count = sum(
                1 for line in f if line.strip() and not line.startswith("#")
            )

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"# {ext.upper()} signatures excluded entirely\n")

        self.stats[ext]["original"] += original_count
        self.stats[ext]["filtered"] += 0
        self.log(f"Excluded entire file: {basename} ({original_count} signatures)")

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
                    ndb_types, exclude_file_types, keep_if_contains=None):
        """Filter files in src_dir and copy results to dst_dir."""
        os.makedirs(dst_dir, exist_ok=True)

        # Load ignore list from .ign and .ign2 files in the source directory
        self.ignore_names = set()
        for item in os.listdir(src_dir):
            item_lower = item.lower()
            if item_lower.endswith(".ign") or item_lower.endswith(".ign2"):
                file_path = os.path.join(src_dir, item)
                if os.path.isfile(file_path):
                    self._load_ignore_file(file_path, is_ign2=item_lower.endswith(".ign2"))

        # Copy all files first, skipping databases that are dropped entirely.
        # javascript.ndb / phish.ndb are excluded: JavaScript and email/phish
        # formats are not meaningfully scannable on Android.
        for item in os.listdir(src_dir):
            if item.lower() in self.EXCLUDE_FILES:
                continue
            src = os.path.join(src_dir, item)
            dst = os.path.join(dst_dir, item)
            if os.path.isfile(src):
                shutil.copy2(src, dst)

        # Filter each file type in-place in dst_dir
        for ndb_file in Path(dst_dir).glob("*.ndb"):
            self.filter_ndb(str(ndb_file), exclude_platforms, include_platforms, ndb_types, keep_if_contains)

        for hdb_file in Path(dst_dir).glob("*.hdb"):
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
                self.filter_ldb(str(ldb_file), exclude_platforms, include_platforms, keep_if_contains)

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
                        fn(str(f), exclude_platforms, include_platforms, ndb_types, keep_if_contains)
                    else:
                        fn(str(f), exclude_platforms, include_platforms, keep_if_contains)

        # Additional formats where first colon-field is the name
        for ext in ("cdb", "crb", "idb", "ign", "ign2", "ftm", "msb"):
            for f in Path(dst_dir).glob(f"*.{ext}"):
                if ext in exclude_file_types:
                    self.exclude_file_type(str(f))
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

    def _remove_empty_dbs(self, directory):
        """Delete database files that contain no real signatures."""
        db_exts = {"ndb", "hdb", "hsb", "mdb", "ldb", "cdb", "crb", "ftm",
                    "idb", "ign", "ign2", "msb", "ndu", "hdu", "hsu", "mdu",
                    "msu", "ldu", "pdb", "wdb"}
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
                             keep_if_contains)

    def filter_directory(
        self,
        src_dir,
        output_dir,
        exclude_platforms=None,
        include_platforms=None,
        ndb_types=None,
        exclude_file_types=None,
        keep_if_contains=None,
    ):
        """Filter an already-extracted database directory."""

        exclude_platforms = set(exclude_platforms or [])
        include_platforms = set(include_platforms or [])
        exclude_file_types = set(exclude_file_types or [])
        keep_if_contains = set(keep_if_contains or [])

        self._filter_dir(src_dir, output_dir, exclude_platforms,
                         include_platforms, ndb_types, exclude_file_types,
                         keep_if_contains)

        # Print statistics
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

Examples:
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
            if profile.get("keep_if_contains"):
                print(f"  Keep if name contains: {', '.join(profile['keep_if_contains'])}")
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

    if args.profile:
        profile = ComprehensiveFilter.PROFILES[args.profile]
        exclude_platforms = profile.get("exclude_platforms")
        include_platforms = profile.get("include_platforms")
        exclude_types = profile.get("exclude_types", [])
        ndb_types = profile.get("ndb_types")
        keep_if_contains = profile.get("keep_if_contains")
        print(f"Using profile: {args.profile}")
        print(f"Description: {profile['description']}\n")
    else:
        if (
            not args.exclude_platforms
            and not args.include_platforms
            and not args.exclude_types
        ):
            print(
                "Error: Must specify --profile, --exclude-platforms, "
                "--include-platforms, or --exclude-types"
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

    if exclude_platforms and include_platforms:
        print("Note: exclude_platforms checked first, then include_platforms")

    # Run filter
    filter_tool = ComprehensiveFilter(verbose=args.verbose)

    try:
        if args.directory:
            filter_tool.filter_directory(
                src_dir=args.directory,
                output_dir=args.output,
                exclude_platforms=exclude_platforms,
                include_platforms=include_platforms,
                ndb_types=ndb_types,
                exclude_file_types=exclude_types,
                keep_if_contains=keep_if_contains,
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
            )
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
