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
from scapy.config import conf
conf.use_pcap = True
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP
from scapy.packet import Raw
from scapy.arch.windows import get_windows_if_list as get_if_list
from typing import Set

# ------------------------------------------------------------------------------
# 1) VERBOSE LOGGING SETUP (console + file)
# ------------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR / "log"
LOG_DIR.mkdir(exist_ok=True)

# All logs go to "openhydradragon.log" plus console at DEBUG level
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
console_handler.setLevel(logging.DEBUG)

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

# Set to track already logged items (used to prevent duplicate rule writing)
logged_network_events = set()

# ------------------------------------------------------------------------------
# 2) NETWORK RULE WRITER (Scapy-based)
# ------------------------------------------------------------------------------
def extract_http_requests(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        try:
            text = pkt[Raw].load.decode('utf-8', errors='ignore')
        except Exception:
            return
        m = re.match(r"^(GET|POST) (/[^ ]*) HTTP/1\.[01]\r\n", text)
        if m:
            host_m = re.search(r"Host:\s*([^\r\n]+)", text)
            if host_m:
                yield host_m.group(1), m.group(2)

def extract_raw_payload(pkt):
    if pkt.haslayer(Raw):
        yield pkt[Raw].load

def write_ohd_rule(host: str, path: str, rules_dir: str):
    safe_host = re.sub(r'[^A-Za-z0-9]', '_', host)
    safe_path = re.sub(r'[^A-Za-z0-9]', '_', path)
    rule_id = f"NET_{safe_host}_{safe_path}"
    filename = os.path.join(rules_dir, f"{rule_id}.ohd")
    if os.path.exists(filename):
        return
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"rule {rule_id}\n")
        f.write("{\n")
        f.write("    meta:\n")
        f.write(f'        id = "{rule_id}"\n')
        f.write(f'        description = "Network I/O to {host}{path}"\n')
        f.write("    condition:\n")
        f.write(f'        eventlog.new_event_log_lines contains "{host}{path}"\n')
        f.write("}\n")
    logging.info(f"[NetRule] Wrote HTTP rule: {filename}")

def write_raw_rule(payload: bytes, rules_dir: str):
    hexpat = payload.hex()
    rule_id = f"RAW_{hexpat[:16]}"
    filename = os.path.join(rules_dir, f"{rule_id}.ohd")
    if os.path.exists(filename):
        return
    pattern = ''.join(f"\\x{hexpat[i:i+2]}" for i in range(0, len(hexpat), 2))
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"rule {rule_id}\n")
        f.write("{\n")
        f.write("    meta:\n")
        f.write(f'        id = "{rule_id}"\n')
        f.write(f'        description = "Raw packet pattern {rule_id}"\n')
        f.write("    condition:\n")
        f.write(f'        eventlog.new_event_log_lines contains "{pattern}"\n')
        f.write("}\n")
    logging.info(f"[NetRule] Wrote RAW rule: {filename}")

def sniff_and_generate(rules_dir: str, iface: str = None, count: int = 0, timeout: int = None):
    """
    Sniff on `iface` (or first available if None) using BPF "tcp port 80 or tcp port 443",
    generate .ohd rules for HTTP and raw bytes.
    """
    os.makedirs(rules_dir, exist_ok=True)

    if iface is None:
        iface = get_if_list()[0]
    logging.info(f"[NetRule] Sniffing on {iface} → {rules_dir}")

    def _callback(pkt):
        for h, p in extract_http_requests(pkt):
            write_ohd_rule(h, p, rules_dir)
        for raw in extract_raw_payload(pkt):
            write_raw_rule(raw, rules_dir)

    # store=False avoids buffering packets in memory
    sniff(
        iface=iface,
        filter="tcp port 80 or tcp port 443",
        prn=_callback,
        count=count,
        timeout=timeout,
        store=False
    )

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
    """
    Captures:
        - Registry: HKLM\\Software, HKCU\\Software
        - Filesystem: targeted directories (System32 + TEMP)
        - Event Logs: Application, Security, System
    """

    def __init__(self, fs_roots: List[str] = None, watchlist: Dict[str, Set[str]] = None):
            self.watchlist = watchlist or {"registry": set(), "filesystem": set()}

            if fs_roots:
                self.fs_roots = [Path(p) for p in fs_roots]
            else:
                system_root = Path(os.getenv("SystemRoot", r"C:\Windows"))
                user_temp = Path(os.getenv("TEMP", r"C:\Windows\Temp"))
                self.fs_roots = [system_root / "System32", user_temp]

            self.registry_dump: Dict[str, Dict[str, Any]] = {}
            self.filesystem_index: Dict[str, float] = {}
            self.event_logs: Dict[str, List[str]] = {}
            logging.debug(f"[Snapshot] Initialized for FS roots: {self.fs_roots}")

    def capture_registry(self):
            hives = {
                "HKLM_SOFTWARE": (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
                "HKCU_SOFTWARE": (winreg.HKEY_CURRENT_USER, r"Software")
            }
            for hive_name, (root, subkey) in hives.items():
                self.registry_dump[hive_name] = {}
                try:
                    with winreg.OpenKey(root, subkey) as hkey:
                        self.registry_dump[hive_name] = self._walk_registry(hkey, prefix=subkey)
                        logging.debug(
                            f"[Snapshot] Captured {len(self.registry_dump[hive_name])} keys under {hive_name}")
                except Exception as e:
                    logging.error(f"[Snapshot] Failed to open {hive_name}: {e}")

    def _walk_registry(self, hkey, prefix: str = "") -> Dict[str, Dict[str, Any]]:
        """
        Recursively read all values under a given registry handle, but only
        descend into keys that match one of our watchlist prefixes.
        """
        result = {}

        # If we have registry prefixes to watch, and this prefix doesn’t contain any of them, skip entirely
        watched = self.watchlist.get("registry", set())
        if watched and not any(pat.lower() in prefix.lower() for pat in watched):
            return {}

        # Capture current key’s values
        result[prefix] = self._get_values(hkey)

        # Enumerate and recurse
        i = 0
        while True:
            try:
                subname = winreg.EnumKey(hkey, i)
                i += 1
                with winreg.OpenKey(hkey, subname) as subh:
                    full = f"{prefix}\\{subname}"
                    # Recurse into this subkey (it will itself check watchlist)
                    sub_tree = self._walk_registry(subh, prefix=full)
                    if sub_tree:
                        # Only add if any values or descendants matched
                        result.update(sub_tree)
            except OSError:
                break

        return result

    def _get_values(self, hkey) -> Dict[str, Any]:
            out = {}
            j = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(hkey, j)
                    out[name] = data
                    j += 1
                except OSError:
                    break
            return out

    def capture_filesystem(self):
        for root in self.fs_roots:
            for dirpath, dirs, files in os.walk(root):
                for fname in files:
                    full = str(Path(dirpath) / fname)
                    if self.watchlist["filesystem"] and not any(
                        p.lower() in full.lower() for p in self.watchlist["filesystem"]
                    ):
                        continue
                    self.filesystem_index[full] = Path(full).stat().st_mtime
            logging.debug(f"[Snapshot] Indexed {len(self.filesystem_index)} files")

    def capture_event_logs(self):
            logs = ["Application", "Security", "System"]
            for log in logs:
                try:
                    cmd = ["wevtutil", "qe", log, "/f:text", "/c:1000"]
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = proc.communicate(timeout=30)
                    if err:
                        logging.error(f"[EventLog] {log} stderr: {err.decode(errors='ignore')}")
                    self.event_logs[log] = out.decode(errors="ignore").splitlines()
                    logging.debug(f"[Snapshot] Captured {len(self.event_logs[log])} lines from {log}")
                except Exception as e:
                    logging.error(f"[Snapshot] Failed to capture {log}: {e}")
                    self.event_logs[log] = []

    def capture(self):
        self.capture_registry()
        self.capture_filesystem()
        self.capture_event_logs()

    def diff(self, other: "Snapshot") -> Dict[str, Any]:
        """
        Compare this snapshot to `other`, return a dict with:
          - new_registry_keys
          - modified_registry_values
          - new_files
          - modified_files
          - new_event_log_lines

        Logs each change as clean text (removes control chars, redacts raw bytes,
        and prints full file paths instead of character-by-character).
        """
        import re
        # Regex to remove ASCII control characters
        _CONTROL_CHAR_RE = re.compile(r'[\x00-\x1F\x7F]')

        def _sanitize(s: str) -> str:
            return _CONTROL_CHAR_RE.sub('', s)

        # 1) Build diffs
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
                    other_vals = other_tree[key_path]
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
            prev = set(other.event_logs.get(log_name, []))
            for ln in lines:
                if ln not in prev:
                    diffs["new_event_log_lines"].append((log_name, ln))

        # 2) Log them cleanly
        for change_type, items in diffs.items():
            if not items:
                continue
            logging.info(f"[Snapshot.diff] {len(items)} {change_type}:")
            for item in items:
                # Wrap lone-string items into a single-element tuple
                elems = item if isinstance(item, tuple) else (item,)
                clean_parts = []
                for elem in elems:
                    if isinstance(elem, (bytes, bytearray)):
                        clean_parts.append("<binary data>")
                    else:
                        clean_parts.append(_sanitize(str(elem)))

                # Format based on diff type
                if change_type == "new_registry_keys":
                    joined = f"{clean_parts[0]}\\{clean_parts[1]}"
                elif change_type == "modified_registry_values":
                    joined = (
                        f"{clean_parts[0]}\\{clean_parts[1]}\\{clean_parts[2]}: "
                        f"{clean_parts[3]} → {clean_parts[4]}"
                    )
                else:
                    # new_files, modified_files, new_event_log_lines
                    joined = clean_parts[0]

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
    r'new_event_log_lines|eventlog\.[A-Za-z0-9_]+|network\.(?:http_requests|raw_payloads)))\s*'
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

    def get_watchlist(self) -> Dict[str, Set[str]]:
        """
        Return a dict with keys 'registry' and 'filesystem', each mapping
        to a set of path-prefixes our rules actually touch.
        """
        regs = set()
        files = set()
        for rule in self.rules:
            for field, op, pat in rule.condition_lines:
                if field.startswith("registry."):
                    # strip off registry.new_keys -> we only care about the value (pattern)
                    regs.add(pat)
                elif field.startswith("filesystem."):
                    files.add(pat)
        return {"registry": regs, "filesystem": files}

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
      0) Load rules + extract watch-list
      1) Clean Sandboxie
      2) Pre-snapshot sandbox
      3) Run in sandbox
      4) Post-snapshot sandbox -> diff_sbx
      5) Clean Sandboxie
      6) Pre-snapshot debug (filtered)
      7) Run outside sandbox
      8) Post-snapshot debug -> diff_dbg
      9) Merge diffs -> stealthy
     10) Gather custom logs
     11) Evaluate rules -> return matched rule names
    """
    # 0) Load rules and get watch-list
    engine = RuleEngine(rules_dir)
    watch = engine.get_watchlist()

    sandbox_mgr = SandboxManager()

    # 1) Ensure sandbox is clean
    full_cleanup_sandbox()
    time.sleep(1)

    # 2) Pre-snapshot sandbox (filtered)
    snap_before_sbx = Snapshot(fs_roots=fs_roots, watchlist=watch)
    snap_before_sbx.capture()

    # 3) Run in sandbox
    ret_sbx = sandbox_mgr.run_in_sandbox(sample_path, timeout=timeout)
    logging.info(f"[Sandbox] Exit code for '{sample_path}': {ret_sbx}")

    # 4) Post-snapshot sandbox (filtered)
    snap_after_sbx = Snapshot(fs_roots=fs_roots, watchlist=watch)
    snap_after_sbx.capture()
    diff_sbx = snap_after_sbx.diff(snap_before_sbx)
    logging.info(
        f"[Sandbox] Diffs: {{new_keys={len(diff_sbx['new_registry_keys'])}, "
        f"mod_vals={len(diff_sbx['modified_registry_values'])}, "
        f"new_files={len(diff_sbx['new_files'])}, "
        f"mod_files={len(diff_sbx['modified_files'])}, "
        f"new_logs={len(diff_sbx['new_event_log_lines'])}}}"
    )

    # 5) Clean sandbox again
    full_cleanup_sandbox()
    time.sleep(1)

    # 6) Pre-snapshot outside sandbox (filtered for performance)
    snap_before_dbg = Snapshot(fs_roots=fs_roots, watchlist=watch)
    snap_before_dbg.capture()

    # 7) Run outside sandbox (debug mode)
    ret_dbg = sandbox_mgr.run_outside_sandbox_debug(sample_path, timeout=timeout)
    logging.info(f"[Debug] Exit code for '{sample_path}': {ret_dbg}")

    # 8) Post-snapshot debug (filtered)
    snap_after_dbg = Snapshot(fs_roots=fs_roots, watchlist=watch)
    snap_after_dbg.capture()
    diff_dbg = snap_after_dbg.diff(snap_before_dbg)
    logging.info(
        f"[Debug] Diffs: {{new_keys={len(diff_dbg['new_registry_keys'])}, "
        f"mod_vals={len(diff_dbg['modified_registry_values'])}, "
        f"new_files={len(diff_dbg['new_files'])}, "
        f"mod_files={len(diff_dbg['modified_files'])}, "
        f"new_logs={len(diff_dbg['new_event_log_lines'])}}}"
    )

    # 9) Merge diffs to isolate stealthy changes
    stealthy = merge_diffs(diff_sbx, diff_dbg)
    logging.info(
        f"[Stealthy] {{new_keys={len(stealthy['new_registry_keys'])}, "
        f"mod_vals={len(stealthy['modified_registry_values'])}, "
        f"new_files={len(stealthy['new_files'])}, "
        f"mod_files={len(stealthy['modified_files'])}, "
        f"new_logs={len(stealthy['new_event_log_lines'])}}}"
    )

    # 10) Gather custom logs
    custom_lines = gather_custom_logs(custom_log_dirs)
    for ln in custom_lines:
        stealthy["new_event_log_lines"].append(("CustomLog", ln))

    # 11) Evaluate rules
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
