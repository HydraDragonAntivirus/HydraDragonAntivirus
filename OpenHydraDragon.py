#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
OpenHydraDragon (Automated Edition): 
  - Fully automates sandbox vs. non-sandbox comparison.
  - Captures registry, filesystem, and Windows Event Logs.
  - Cleans up Sandboxie between runs.
  - Supports scanning a directory of samples.
  - Loads SIGMA‐style .ohd rules.
"""

import os
import sys
import logging
import subprocess
import time
import winreg
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple

# ------------------------------------------------------------------------------
# 1) VERBOSE LOGGING SETUP (console + file)
# ------------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR / "log"
LOG_DIR.mkdir(exist_ok=True)

# All logs go to "openhydradragon.log" plus console at INFO level
application_log_file = LOG_DIR / "openhydradragon.log"

# Configure logging for application log
logging.basicConfig(
    filename=application_log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Console handler (INFO and above)
console_handler = logging.StreamHandler(sys.stdout)
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.INFO)

logging.info("=== OpenHydraDragon Automated Engine Started ===")

# Resolve system drive path
system_drive = os.getenv("SystemDrive", "C:") + os.sep
# Resolve Program Files directory via environment (fallback to standard path)
program_files = os.getenv("ProgramFiles", os.path.join(system_drive, "Program Files"))

sandboxie_dir = os.path.join(program_files, "Sandboxie")
username = os.getlogin()
sandboxie_path = os.path.join(sandboxie_dir, "Start.exe")
sandboxie_control_path = os.path.join(sandboxie_dir, "SbieCtrl.exe")

try:
    SANDBOXIE_PATH = sandboxie_path
    SANDBOXIE_CONTROL = sandboxie_control_path
    SANDBOXIE_BOX_NAME = f"Sandbox\\{username}\\DefaultBox"
except ImportError:
    SANDBOXIE_PATH = r"C:\Program Files\Sandboxie\Start.exe"
    SANDBOXIE_CONTROL = r"C:\Program Files\Sandboxie\SbieCtrl.exe"

# ------------------------------------------------------------------------------
# 3) SANDBOX MANAGER (LAUNCH & CLEANUP)
# ------------------------------------------------------------------------------

def full_cleanup_sandbox():
    """
    Fully cleans up the Sandboxie environment using Start.exe termination commands.
    It issues:
      1) Start.exe /terminate
      2) Start.exe /box:DefaultBox /terminate
      3) Start.exe /terminate_all
      4) SbieCtrl.exe /delete DefaultBox
    with short delays between each command.
    """
    try:
        logging.info("Starting full sandbox cleanup using Start.exe termination commands...")
        cmds = [
            [SANDBOXIE_PATH, "/terminate"],
            [SANDBOXIE_PATH, "/box:DefaultBox", "/terminate"],
            [SANDBOXIE_PATH, "/terminate_all"],
            [SANDBOXIE_CONTROL, "/delete", SANDBOXIE_BOX_NAME]
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Command {cmd} failed: {result.stderr.strip()}")
            else:
                logging.info(f"Command {cmd} successful.")
            time.sleep(2)
    except Exception as ex:
        logging.error(f"Full sandbox cleanup encountered an exception: {ex}")

class SandboxManager:
    """
    Handles launching a target under Sandboxie vs. outside of it, plus cleanup.
    """
    def __init__(self, box_name: str = SANDBOXIE_BOX_NAME):
        self.box_name = box_name
        logging.debug(f"SandboxManager initialized for box '{self.box_name}'")

    def run_in_sandbox(self, target_exe: str, args: List[str] = None, timeout: int = 60) -> int:
        """
        Launch `target_exe` under Sandboxie (visible) with /box:DefaultBox.
        Blocks until process exits or timeout. Returns exit code.
        """
        args = args or []

        # 1) Convert to absolute path (no quotes)
        if not os.path.isabs(target_exe):
            target_exe = os.path.abspath(target_exe)

        # 2) Build the command: [ Start.exe, /box:DefaultBox, <absolute-exe-path> ]
        cmd = [
            SANDBOXIE_PATH,
            "/box:DefaultBox",
            target_exe
        ] + args

        logging.info(f"[Sandbox] Launching under Sandboxie: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                if stdout:
                    logging.debug(f"[Sandbox] stdout:\n{stdout.decode(errors='ignore')}")
                if stderr:
                    logging.error(f"[Sandbox] stderr:\n{stderr.decode(errors='ignore')}")
                return proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                logging.error("[Sandbox] Process timed out and was killed.")
                return -1
        except Exception as e:
            logging.exception(f"[Sandbox] Failed to launch: {e}")
            return -1

    def run_outside_sandbox_debug(self, target_exe: str, args: List[str]=None, timeout: int=60) -> int:
        """
        Launch `target_exe` in normal (non-sandboxed) debug mode.
        For now, just runs the binary; you can replace this with WinAppDbg hooks.
        """
        args = args or []
        cmd = [target_exe] + args

        logging.info(f"[Debug] Launching outside sandbox (debug mode): {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                if stdout:
                    logging.debug(f"[Debug] stdout:\n{stdout.decode(errors='ignore')}")
                if stderr:
                    logging.error(f"[Debug] stderr:\n{stderr.decode(errors='ignore')}")
                return proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                logging.error("[Debug] Process timed out and was killed.")
                return -1
        except Exception as e:
            logging.exception(f"[Debug] Failed to launch: {e}")
            return -1


# ------------------------------------------------------------------------------
# 4) SNAPSHOT CAPTURE (REGISTRY + FILESYSTEM + EVENT LOGS)
# ------------------------------------------------------------------------------

class Snapshot:
    r"""
    Captures:
      - Registry: HKLM\Software, HKCU\Software (expandable)
      - Filesystem: targeted directories (C:\Windows\System32, %TEMP%)
      - Event Logs: Application, Security, System
    """

    def __init__(self, fs_roots: List[str] = None):
        r"""
        fs_roots: list of directories to snapshot (e.g., [r"C:\Windows\System32", r"C:\Users\<User>\AppData\Local\Temp"])
        If None, defaults to:
           - C:\Windows\System32
           - %TEMP% (e.g., C:\Windows\Temp or your user’s temp)
        """
        if fs_roots:
            self.fs_roots = [Path(p) for p in fs_roots]
        else:
            system_root = Path(os.getenv("SystemRoot", r"C:\Windows"))
            user_temp = Path(os.getenv("TEMP", r"C:\Windows\Temp"))
            self.fs_roots = [
                system_root / "System32",
                user_temp
            ]
        self.registry_dump: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.filesystem_index: Dict[str, float] = {}
        self.event_logs: Dict[str, List[str]] = {}
        logging.debug(f"Snapshot initialized for FS roots: {self.fs_roots}")

    def capture_registry(self):
        r"""
        Crawl the following hives:
          - HKLM\Software
          - HKCU\Software
        """
        hives = {
            "HKLM_SOFTWARE": (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
            "HKCU_SOFTWARE": (winreg.HKEY_CURRENT_USER, r"Software")
        }
        for hive_name, (root, subkey) in hives.items():
            self.registry_dump[hive_name] = {}
            try:
                with winreg.OpenKey(root, subkey) as hkey:
                    self.registry_dump[hive_name] = self._walk_registry(hkey, prefix=subkey)
                    logging.debug(f"[Snapshot] Captured registry hive '{hive_name}' with {len(self.registry_dump[hive_name])} keys")
            except Exception as e:
                logging.error(f"[Snapshot] Failed to open registry hive '{hive_name}': {e}")

    def _walk_registry(self, hkey, prefix: str = "") -> Dict[str, Dict[str, Any]]:
        r"""
        Recursively read all values under a given registry handle.
        Returns dict: full_key_path -> {value_name: value_data}
        """
        result = {}
        # Capture current key's values
        result[prefix] = self._get_values(hkey)
        # Enumerate subkeys
        try:
            i = 0
            while True:
                subname = winreg.EnumKey(hkey, i)
                i += 1
                try:
                    with winreg.OpenKey(hkey, subname) as subh:
                        full_path = f"{prefix}\\{subname}"
                        result[full_path] = self._get_values(subh)
                        # Recurse
                        sub_result = self._walk_registry(subh, prefix=full_path)
                        result.update(sub_result)
                except OSError:
                    break
        except OSError:
            pass
        return result

    def _get_values(self, hkey) -> Dict[str, Any]:
        r"""
        Return all (value_name: value_data) under a given key handle.
        """
        out = {}
        try:
            j = 0
            while True:
                name, data, _ = winreg.EnumValue(hkey, j)
                j += 1
                out[name] = data
        except OSError:
            pass
        return out

    def capture_filesystem(self):
        r"""
        Walk each directory in self.fs_roots and record last-modified timestamps.
        """
        logging.debug(f"[Snapshot] Starting filesystem capture under {self.fs_roots}")
        for root in self.fs_roots:
            for dirpath, dirs, files in os.walk(root):
                # Optionally skip WinSxS and other enormous directories
                if "\\WinSxS" in str(dirpath):
                    continue
                for fname in files:
                    full_path = Path(dirpath) / fname
                    try:
                        self.filesystem_index[str(full_path)] = full_path.stat().st_mtime
                    except (OSError, PermissionError):
                        continue
        logging.debug(f"[Snapshot] Captured {len(self.filesystem_index)} files in filesystem index")

    def capture_event_logs(self):
        r"""
        Exports the last 1000 entries of Application, Security, System via wevtutil.
        Stores lines in self.event_logs under keys "Application", "Security", "System".
        """
        logs_to_query = ["Application", "Security", "System"]
        for log_name in logs_to_query:
            try:
                # wevtutil qe Application /f:text /c:1000
                cmd = ["wevtutil", "qe", log_name, "/f:text", "/c:1000"]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
                stdout, stderr = proc.communicate(timeout=30)
                if stderr:
                    logging.error(f"[EventLog] wevtutil stderr for {log_name}: {stderr.decode(errors='ignore')}")
                text = stdout.decode(errors="ignore").splitlines()
                self.event_logs[log_name] = text
                logging.debug(f"[Snapshot] Captured {len(text)} lines from {log_name} log")
            except Exception as e:
                logging.error(f"[Snapshot] Failed to export {log_name} log: {e}")
                self.event_logs[log_name] = []

    def capture(self):
        """
        Take registry, filesystem, and event-log snapshots.
        """
        self.capture_registry()
        self.capture_filesystem()
        self.capture_event_logs()

    def diff(self, other: "Snapshot") -> Dict[str, Any]:
        """
        Compare this snapshot to `other`, return dict with:
          - new_registry_keys
          - modified_registry_values
          - new_files
          - modified_files
          - new_event_log_lines

        Logs each change as plain text (removes control chars).
        """
        import re
        # Regex to remove ASCII control characters
        _CONTROL_CHAR_RE = re.compile(r'[\x00-\x1F\x7F]')

        def _sanitize(s: str) -> str:
            return _CONTROL_CHAR_RE.sub('', s)

        diffs = {
            "new_registry_keys": [],
            "modified_registry_values": [],
            "new_files": [],
            "modified_files": [],
            "new_event_log_lines": []
        }

        # Registry diffs
        for hive, tree in self.registry_dump.items():
            other_tree = other.registry_dump.get(hive, {})
            for key_path, values in tree.items():
                if key_path not in other_tree:
                    diffs["new_registry_keys"].append((hive, key_path))
                else:
                    other_vals = other_tree.get(key_path, {})
                    for vname, vdata in values.items():
                        if other_vals.get(vname) != vdata:
                            diffs["modified_registry_values"].append(
                                (hive, key_path, vname, other_vals.get(vname), vdata)
                            )

        # Filesystem diffs
        for path, mtime in self.filesystem_index.items():
            other_mtime = other.filesystem_index.get(path)
            if other_mtime is None:
                diffs["new_files"].append(path)
            elif other_mtime != mtime:
                diffs["modified_files"].append(path)

        # Event Log diffs
        for log_name, lines in self.event_logs.items():
            prev_lines = set(other.event_logs.get(log_name, []))
            for ln in lines:
                if ln not in prev_lines:
                    diffs["new_event_log_lines"].append((log_name, ln))

        # Now log everything as clean text
        for change_type, items in diffs.items():
            if not items:
                continue
            logging.info(f"[Snapshot.diff] {len(items)} {change_type}:")
            for item in items:
                # item is a tuple, e.g. (hive, key_path) or (hive, path, vname, old, new)
                # Sanitize each element separately:
                clean_parts = [_sanitize(str(elem)) for elem in item]
                # Join with a separator that makes sense for the type of diff:
                if change_type.startswith("new_registry_keys"):
                    joined = f"{clean_parts[0]}\\{clean_parts[1]}"
                elif change_type.startswith("modified_registry_values"):
                    # hive \ key_path \ value_name: old → new
                    joined = f"{clean_parts[0]}\\{clean_parts[1]}\\{clean_parts[2]}: {clean_parts[3]} → {clean_parts[4]}"
                else:
                    # For files or event‑logs, just join with " | "
                    joined = " | ".join(clean_parts)

                logging.info(f"    {change_type}: {joined}")

        return diffs


# ------------------------------------------------------------------------------
# 5) RULE ENGINE (SIGMA-STYLE .ohd PARSER + EVALUATOR)
# ------------------------------------------------------------------------------

r"""
Rule syntax (.ohd):

rule MyTrojanRule {
    meta:
        id = "TROJAN-0002"
        description = "Detect stealthy registry key creation outside sandbox"
    condition:
        registry.new_keys contains "Software\\EvilCorp"
        filesystem.new_files contains "AppData\\Local\\Temp\\evil.dll"
        eventlog.System matches "malicious.*exe"
}

Supported fields:
  - registry.new_keys
  - registry.modified_registry_values
  - filesystem.new_files
  - filesystem.modified_files
  - eventlog.<LogName> matches "<regex>"

Operators:
  - contains (substring match, case-insensitive)
  - matches (regex match, case-insensitive)
"""

RULE_RE = re.compile(r'^\s*rule\s+([A-Za-z0-9_-]+)\s*\{')
META_RE = re.compile(r'^\s*meta\s*:\s*$')
COND_RE = re.compile(r'^\s*condition\s*:\s*$')
KEYVAL_RE = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]+)"\s*$')
# e.g. registry.new_keys contains "pattern"
# e.g. eventlog.Application matches "regex"
COND_LINE_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+\.(?:new_keys|modified_registry_values|new_files|modified_files|'
    r'new_event_log_lines|eventlog\.[A-Za-z0-9_]+))\s*'
    r'(contains|matches)\s*"([^"]+)"\s*$'
)

class Rule:
    """
    Representation of a single OpenHydraDragon rule.
    """
    def __init__(self, name: str):
        self.name = name
        self.meta: Dict[str, str] = {}
        self.condition_lines: List[Tuple[str, str, str]] = []
        logging.debug(f"[Rule] Created skeleton for rule '{name}'")

    def add_meta(self, key: str, value: str):
        self.meta[key] = value

    def add_condition(self, field: str, operator: str, pattern: str):
        self.condition_lines.append((field, operator, pattern))

    def evaluate(self, diffs: Dict[str, Any]) -> bool:
        """
        Evaluate the rule against:
          - diffs: output of Snapshot.diff()
        Returns True if ANY condition line matches.
        Supports:
          - text 'contains' and 'matches' (regex) as before
          - hex‑escape patterns like '\\x41\\x42' via byte‑level contains
        """
        import re
        # Precompile control‑char sanitizer (if you want to clean up entries)
        _CONTROL_CHAR_RE = re.compile(r'[\x00-\x1F\x7F]')

        def byte_contains(entry_text: str, pat_bytes: bytes) -> bool:
            """Return True if pat_bytes is a substring of entry_text.encode(...)"""
            try:
                entry_b = entry_text.encode('utf-8', 'ignore')
                return pat_bytes in entry_b
            except Exception:
                return False

        for (field, operator, pattern) in self.condition_lines:
            # Detect a hex‑escape pattern (\xHH)
            if r'\x' in pattern:
                # Convert pattern "\x41\x42" → b'\x41\x42'
                try:
                    hex_str = pattern.replace(r'\x', '')
                    pat_bytes = bytes.fromhex(hex_str)
                except ValueError:
                    pat_bytes = None

                # Registry fields
                if field.startswith("registry."):
                    if field.endswith("new_keys"):
                        items = [f"{hive}\\{path}"
                                 for hive, path in diffs.get("new_registry_keys", [])]
                    else:
                        items = [f"{hive}\\{path}\\{vname}"
                                 for hive, path, vname, _, _
                                 in diffs.get("modified_registry_values", [])]
                    for entry in items:
                        if operator == "contains" and pat_bytes and byte_contains(entry, pat_bytes):
                            logging.info(f"[Rule:{self.name}] byte‑registry match {pattern!r} in {entry!r}")
                            return True

                # Filesystem fields
                elif field.startswith("filesystem."):
                    if field.endswith("new_files"):
                        items = diffs.get("new_files", [])
                    else:
                        items = diffs.get("modified_files", [])
                    for entry in items:
                        if operator == "contains" and pat_bytes and byte_contains(entry, pat_bytes):
                            logging.info(f"[Rule:{self.name}] byte‑filesystem match {pattern!r} in {entry!r}")
                            return True

                # Event Log fields
                elif field.startswith("eventlog."):
                    _, log_name = field.split(".", 1)
                    items = [ln for (lg, ln) in diffs.get("new_event_log_lines", [])
                             if lg == log_name]
                    for entry in items:
                        if operator == "contains" and pat_bytes and byte_contains(entry, pat_bytes):
                            logging.info(f"[Rule:{self.name}] byte‑eventlog match {pattern!r} in {entry!r}")
                            return True

                # Skip the normal text path for this pattern
                continue

            # --- Fallback to original text‑based logic ---

            # Registry fields
            if field.startswith("registry."):
                if field.endswith("new_keys"):
                    items = [f"{hive}\\{path}"
                             for hive, path in diffs.get("new_registry_keys", [])]
                else:
                    items = [
                        f"{hive}\\{path}\\{vname} -> {oldval} => {newval}"
                        for hive, path, vname, oldval, newval
                        in diffs.get("modified_registry_values", [])
                    ]
                for entry in items:
                    if operator == "contains" and pattern.lower() in entry.lower():
                        logging.info(f"[Rule:{self.name}] registry match: '{pattern}' in '{entry}'")
                        return True

            # Filesystem fields
            elif field.startswith("filesystem."):
                if field.endswith("new_files"):
                    items = diffs.get("new_files", [])
                else:
                    items = diffs.get("modified_files", [])
                for fpath in items:
                    if operator == "contains":
                        if pattern.lower() in fpath.lower():
                            logging.info(f"[Rule:{self.name}] filesystem match: '{pattern}' in '{fpath}'")
                            return True
                    elif operator == "matches":
                        if re.search(pattern, fpath, re.IGNORECASE):
                            logging.info(
                                f"[Rule:{self.name}] filesystem regex match: '{pattern}' matches '{fpath}'"
                            )
                            return True

            # Event Log fields
            elif field.startswith("eventlog."):
                _, log_name = field.split(".", 1)
                items = [ln for (lg, ln) in diffs.get("new_event_log_lines", [])
                         if lg == log_name]
                for ln in items:
                    if operator == "contains" and pattern.lower() in ln.lower():
                        logging.info(f"[Rule:{self.name}] eventlog match: '{pattern}' in '{ln}'")
                        return True
                    elif operator == "matches" and re.search(pattern, ln, re.IGNORECASE):
                        logging.info(
                            f"[Rule:{self.name}] eventlog regex match: '{pattern}' matches '{ln}'"
                        )
                        return True

        return False


class RuleEngine:
    """
    Loads all .ohd rule files from a directory and can evaluate them against diffs.
    """
    def __init__(self, rules_dir: str):
        self.rules: List[Rule] = []
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str):
        logging.info(f"[RuleEngine] Loading rules from '{rules_dir}'")
        for file in os.listdir(rules_dir):
            if file.lower().endswith(".ohd"):
                path = Path(rules_dir) / file
                self._parse_rule_file(path)

    def _parse_rule_file(self, filepath: Path):
        current_rule = None
        mode = None  # None / "meta" / "condition"
        for line in filepath.read_text(encoding="utf-8").splitlines():
            m = RULE_RE.match(line)
            if m:
                current_rule = Rule(m.group(1))
                mode = None
                continue

            if META_RE.match(line):
                mode = "meta"
                continue

            if COND_RE.match(line):
                mode = "condition"
                continue

            if mode == "meta" and current_rule:
                kv = KEYVAL_RE.match(line)
                if kv:
                    current_rule.add_meta(kv.group(1), kv.group(2))
                continue

            if mode == "condition" and current_rule:
                cond = COND_LINE_RE.match(line)
                if cond:
                    field, op, pat = cond.groups()
                    current_rule.add_condition(field, op, pat)
                continue

            if line.strip().startswith("}") and current_rule:
                self.rules.append(current_rule)
                logging.debug(
                    f"[RuleEngine] Loaded rule '{current_rule.name}' (meta: {current_rule.meta}) with {len(current_rule.condition_lines)} conditions"
                )
                current_rule = None
                mode = None

    def evaluate_all(self, diffs: Dict[str, Any]) -> List[str]:
        matches = []
        for rule in self.rules:
            try:
                if rule.evaluate(diffs):
                    matches.append(rule.name)
            except Exception as e:
                logging.error(f"[RuleEngine] Error evaluating rule '{rule.name}': {e}")
        return matches


# ------------------------------------------------------------------------------
# 6) SUPPORT FUNCTIONS
# ------------------------------------------------------------------------------

def gather_custom_logs(log_dirs: List[str]) -> List[str]:
    """
    Recursively read all .log / .txt files in given directories,
    return a list of lines. You can add more paths here if needed.
    """
    collected = []
    for ld in log_dirs:
        for root, dirs, files in os.walk(ld):
            for fname in files:
                if fname.lower().endswith((".log", ".txt")):
                    full_path = os.path.join(root, fname)
                    try:
                        with open(full_path, encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                            collected.extend(lines)
                    except Exception:
                        continue
    logging.debug(f"[CustomLogs] Collected {len(collected)} lines from {log_dirs}")
    return collected


def merge_diffs(diff_sbx: Dict[str, Any], diff_dbg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge sandbox vs. debug diffs. We want to detect changes that only occur outside the sandbox
    (i.e., stealthy behavior). For simplicity:
      - new keys/files present in debug but NOT in sandbox -> stealthy.
      - modified items present in debug but NOT in sandbox -> stealthy.
      - event log lines in debug but NOT in sandbox -> stealthy.
    """
    stealthy = {
        "new_registry_keys": [],
        "modified_registry_values": [],
        "new_files": [],
        "modified_files": [],
        "new_event_log_lines": []
    }

    # Registry new keys
    set_sbx_reg = {f"{hive}\\{kp}" for hive, kp in diff_sbx.get("new_registry_keys", [])}
    for hive, kp in diff_dbg.get("new_registry_keys", []):
        full = f"{hive}\\{kp}"
        if full not in set_sbx_reg:
            stealthy["new_registry_keys"].append((hive, kp))

    # Registry modified values
    set_sbx_modreg = {
        f"{hive}\\{kp}\\{vn}\\{ov}\\{nv}"
        for hive, kp, vn, ov, nv in diff_sbx.get("modified_registry_values", [])
    }
    for hive, kp, vn, ov, nv in diff_dbg.get("modified_registry_values", []):
        repr_dbg = f"{hive}\\{kp}\\{vn}\\{ov}\\{nv}"
        if repr_dbg not in set_sbx_modreg:
            stealthy["modified_registry_values"].append((hive, kp, vn, ov, nv))

    # Filesystem new files
    set_sbx_files = set(diff_sbx.get("new_files", []))
    for f in diff_dbg.get("new_files", []):
        if f not in set_sbx_files:
            stealthy["new_files"].append(f)

    # Filesystem modified files
    set_sbx_modfiles = set(diff_sbx.get("modified_files", []))
    for f in diff_dbg.get("modified_files", []):
        if f not in set_sbx_modfiles:
            stealthy["modified_files"].append(f)

    # Event logs: only lines in debug not in sandbox
    set_sbx_ev = set(line for _, line in diff_sbx.get("new_event_log_lines", []))
    for lg, ln in diff_dbg.get("new_event_log_lines", []):
        if ln not in set_sbx_ev:
            stealthy["new_event_log_lines"].append((lg, ln))

    return stealthy


# ------------------------------------------------------------------------------
# 7) MAIN WORKFLOW (AUTOMATED)
# ------------------------------------------------------------------------------

def process_sample(
    sample_path: str,
    rules_dir: str,
    fs_roots: List[str],
    custom_log_dirs: List[str],
    timeout: int = 60
) -> List[str]:
    """
    Processes a single sample:
      1) Clean Sandboxie box.
      2) Pre‐snapshot sandboxed (clean state).
      3) Run in sandbox.
      4) Post‐snapshot sandboxed → diff_sbx.
      5) Clean Sandboxie box.
      6) Pre‐snapshot outside sandbox.
      7) Run outside sandbox.
      8) Post‐snapshot outside sandbox → diff_dbg.
      9) Merge diffs to get stealthy changes.
     10) Load & evaluate rules → return matched rule names.
    """
    sandbox_mgr = SandboxManager()

    # 1) Ensure sandbox is clean
    full_cleanup_sandbox()
    time.sleep(1)

    # 2) Pre‐snapshot sandboxed
    snap_before_sbx = Snapshot(fs_roots=fs_roots)
    snap_before_sbx.capture()

    # 3) Run in sandbox
    ret_sbx = sandbox_mgr.run_in_sandbox(sample_path, timeout=timeout)
    logging.info(f"[Sandbox] Exit code for '{sample_path}': {ret_sbx}")

    # 4) Post‐snapshot sandboxed
    snap_after_sbx = Snapshot(fs_roots=fs_roots)
    snap_after_sbx.capture()
    diff_sbx = snap_after_sbx.diff(snap_before_sbx)
    logging.debug(f"[Sandbox] Diffs for '{sample_path}': { {k: len(v) for k,v in diff_sbx.items()} }")

    # 5) Clean sandbox again (so next run is fresh)
    full_cleanup_sandbox()
    time.sleep(1)

    # 6) Pre‐snapshot outside sandbox
    snap_before_dbg = Snapshot(fs_roots=fs_roots)
    snap_before_dbg.capture()

    # 7) Run outside sandbox (debug mode)
    ret_dbg = sandbox_mgr.run_outside_sandbox_debug(sample_path, timeout=timeout)
    logging.info(f"[Debug] Exit code for '{sample_path}': {ret_dbg}")

    # 8) Post‐snapshot outside sandbox
    snap_after_dbg = Snapshot(fs_roots=fs_roots)
    snap_after_dbg.capture()
    diff_dbg = snap_after_dbg.diff(snap_before_dbg)
    logging.debug(f"[Debug] Diffs for '{sample_path}': { {k: len(v) for k,v in diff_dbg.items()} }")

    # 9) Merge diffs to isolate stealthy changes
    stealthy = merge_diffs(diff_sbx, diff_dbg)
    logging.info(f"[Stealthy Changes for '{sample_path}'] { {k: len(v) for k,v in stealthy.items()} }")

    # 10) Gather custom logs (if any)
    custom_lines = gather_custom_logs(custom_log_dirs)
    # Incorporate them into new_event_log_lines under label "CustomLog"
    for ln in custom_lines:
        stealthy["new_event_log_lines"].append(("CustomLog", ln))

    # 11) Load and evaluate rules
    engine = RuleEngine(rules_dir)
    matched = engine.evaluate_all(stealthy)

    return matched


def main():
    """
    Usage:
      python OpenHydraDragon.py <path_to_sample_or_directory> <path_to_rules_directory>
    """
    if len(sys.argv) < 3:
        logging.error("Usage: python OpenHydraDragon.py <sample_or_dir> <rules_dir>")
        sys.exit(1)

    target = sys.argv[1]
    rules_dir = sys.argv[2]

    # 1) Determine FS roots to snapshot
    system_root = Path(os.getenv("SystemRoot", r"C:\Windows"))
    user_temp = Path(os.getenv("TEMP", r"C:\Windows\Temp"))
    fs_roots = [str(system_root / "System32"), str(user_temp)]

    # 2) Any custom log directories (e.g., your AV sandbox logs)
    custom_log_dirs = [
        str(SCRIPT_DIR / "HydraDragonAVSandboxie" / "Logs"),
        # Add more paths as needed
    ]

    # 3) If target is a directory, iterate all .exe files inside
    samples = []
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            for fname in files:
                if fname.lower().endswith(".exe"):
                    samples.append(os.path.join(root, fname))
    else:
        samples = [target]

    # 4) Process each sample
    for sample in samples:
        logging.info(f"=== Processing Sample: {sample} ===")
        try:
            matched_rules = process_sample(
                sample_path=sample,
                rules_dir=rules_dir,
                fs_roots=fs_roots,
                custom_log_dirs=custom_log_dirs,
                timeout=60
            )
            if matched_rules:
                logging.warning(f"[Alert] Sample '{sample}' matched rules: {matched_rules}")
            else:
                logging.info(f"[Result] No rules matched for '{sample}'")
        except Exception as e:
            logging.exception(f"Error processing sample '{sample}': {e}")

    logging.info("=== OpenHydraDragon Automated Run Completed ===")


if __name__ == "__main__":
    main()
