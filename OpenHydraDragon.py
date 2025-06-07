#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
OpenHydraDragon (Always-Debug + Window/Message Detection Edition):
  - Captures registry, filesystem, Windows Event Logs, and live window messages.
  - Supports scanning a directory of samples.
  - Loads SIGMA‐style .ohd rules.
  - Runs every sample normally (no Sandboxie).
  - Allows rules to match on new window titles/text (e.g., dialogs, message boxes).
"""

import os
import sys
import logging
import subprocess
import winreg
import re
import ctypes
from ctypes import wintypes
import psutil
from comtypes.client import CreateObject
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set

from scapy.config import conf
conf.use_pcap = True
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP
from scapy.packet import Raw
from scapy.arch.windows import get_windows_if_list as get_if_list

# -------------------------------------------------------------------
# 0) WINDOWS API + UI AUTOMATION SETUP FOR COMMANDLINE & MESSAGE DETECTION
# -------------------------------------------------------------------

# Constants for Windows API calls
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E

# WinEvent constants ‐ not used directly in this file but kept for reference
EVENT_OBJECT_CREATE       = 0x8000
EVENT_OBJECT_SHOW         = 0x8002
EVENT_SYSTEM_DIALOGSTART  = 0x0010
EVENT_OBJECT_HIDE         = 0x8003
EVENT_OBJECT_NAMECHANGE   = 0x800C
WINEVENT_OUTOFCONTEXT     = 0x0000

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Load libraries
kernel32 = ctypes.windll.kernel32
user32   = ctypes.windll.user32
ole32    = ctypes.windll.ole32

# UI Automation COM object (for retrieving control names if WM_GETTEXT fails)
try:
    uia = CreateObject('UIAutomationClient.CUIAutomation')
except Exception:
    uia = None

def get_process_path(hwnd: int) -> str:
    """
    Return the executable path of the process owning the given HWND.
    Tries Windows API (QueryFullProcessImageNameW); falls back to psutil if needed.
    """
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == 0:
        return "<unknown_pid>"

    # Try using the Windows API
    hproc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if hproc:
        try:
            buff_len = wintypes.DWORD(260)
            buff = ctypes.create_unicode_buffer(buff_len.value)
            if kernel32.QueryFullProcessImageNameW(hproc, 0, buff, ctypes.byref(buff_len)):
                return buff.value
        except Exception:
            pass
        finally:
            kernel32.CloseHandle(hproc)

    # Fallback to psutil
    try:
        proc = psutil.Process(pid.value)
        return proc.exe()
    except psutil.NoSuchProcess:
        return f"<terminated_pid:{pid.value}>"
    except psutil.AccessDenied:
        return f"<access_denied_pid:{pid.value}>"
    except Exception as e:
        return f"<error_pid:{pid.value}:{type(e).__name__}>"

def get_window_text(hwnd: int) -> str:
    """
    Retrieve the text of a window (title). Always returns a string (possibly empty).
    """
    length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) + 1
    buf = ctypes.create_unicode_buffer(length)
    user32.SendMessageW(hwnd, WM_GETTEXT, length, ctypes.byref(buf))
    return buf.value or ""

def get_control_text(hwnd: int) -> str:
    """
    Retrieve the text of a control. Same approach as get_window_text.
    """
    length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) + 1
    buf = ctypes.create_unicode_buffer(length)
    user32.SendMessageW(hwnd, WM_GETTEXT, length, ctypes.byref(buf))
    return buf.value or ""

def get_uia_text(hwnd: int) -> str:
    """
    Retrieve control text via UI Automation if available.
    """
    if not uia:
        return ""
    try:
        element = uia.ElementFromHandle(hwnd)
        name = element.CurrentName
        return name or ""
    except Exception:
        return ""

def find_child_windows(parent_hwnd: int) -> List[int]:
    """
    Find all direct child windows of the given parent window.
    """
    child_windows: List[int] = []
    def _enum_proc(hwnd: int, lParam: ctypes.c_void_p) -> bool:
        child_windows.append(hwnd)
        return True
    EnumChildProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    user32.EnumChildWindows(parent_hwnd, EnumChildProc(_enum_proc), None)
    return child_windows

def find_descendant_windows(root_hwnd: int) -> List[int]:
    """
    Recursively enumerate all descendant windows of a given top-level window.
    """
    descendants: List[int] = []
    stack = [root_hwnd]
    while stack:
        parent = stack.pop()
        children = find_child_windows(parent)
        for ch in children:
            descendants.append(ch)
            stack.append(ch)
    return descendants

def find_windows_with_text() -> List[Tuple[int, str, str]]:
    """
    Enumerate all top‐level windows and their descendants, retrieving text
    via WM_GETTEXT or UI Automation. Returns a list of (hwnd, text, exe_path).
    """
    window_handles: List[Tuple[int, str, str]] = []

    def scan_hwnd(hwnd: int):
        # 1) Standard window text
        raw = get_window_text(hwnd).strip()
        # 2) Control text if no window text
        if not raw:
            raw = get_control_text(hwnd).strip()
        # 3) Fallback to UI Automation if still empty
        if not raw:
            raw = get_uia_text(hwnd).strip()
        if raw:
            window_handles.append((hwnd, raw, get_process_path(hwnd)))

    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    def enum_proc(hwnd: int, lParam: ctypes.c_void_p) -> bool:
        scan_hwnd(hwnd)
        for desc in find_descendant_windows(hwnd):
            scan_hwnd(desc)
        return True

    user32.EnumWindows(EnumWindowsProc(enum_proc), None)
    return window_handles

# -------------------------------------------------------------------
# 1) VERBOSE LOGGING SETUP (console + file)
# -------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR / "log"
LOG_DIR.mkdir(exist_ok=True)

application_log_file = LOG_DIR / "openhydradragon.log"

logging.basicConfig(
    filename=application_log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

console_handler = logging.StreamHandler(sys.stdout)
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(console_handler)

logging.info("=== OpenHydraDragon Always-Debug + Window Detection Started ===")

# -------------------------------------------------------------------
# 2) NETWORK RULE WRITER (Scapy-based)
# -------------------------------------------------------------------

def extract_http_requests(pkt) -> List[Tuple[str, str]]:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        try:
            text = pkt[Raw].load.decode('utf-8', errors='ignore')
        except Exception:
            return []
        m = re.match(r"^(GET|POST) (/[^ ]*) HTTP/1\.[01]\r\n", text)
        if m:
            host_m = re.search(r"Host:\s*([^\r\n]+)", text)
            if host_m:
                return [(host_m.group(1), m.group(2))]
    return []

def extract_raw_payload(pkt) -> List[bytes]:
    if pkt.haslayer(Raw):
        return [pkt[Raw].load]
    return []

def write_ohd_rule(host: str, path: str, rules_dir: str):
    # Sanitize host and path to use only letters, digits, or underscores
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
        # We assume eventlog.new_event_log_lines is the catch‐all for packet content
        f.write(f'        eventlog.new_event_log_lines contains "{host}{path}"\n')
        f.write("}\n")
    logging.info(f"[NetRule] Wrote HTTP rule: {filename}")

def write_raw_rule(payload: bytes, rules_dir: str):
    hexpat = payload.hex()
    rule_id = f"RAW_{hexpat[:16]}"
    filename = os.path.join(rules_dir, f"{rule_id}.ohd")
    if os.path.exists(filename):
        return
    # Build a pattern like "\x41\x42..." from the raw bytes
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

    sniff(
        iface=iface,
        filter="tcp port 80 or tcp port 443",
        prn=_callback,
        count=count,
        timeout=timeout,
        store=False
    )

# -------------------------------------------------------------------
# 3) SNAPSHOT CAPTURE (REGISTRY + FILESYSTEM + EVENT LOGS + WINDOW MESSAGES)
# -------------------------------------------------------------------

class Snapshot:
    """
    Captures:
        - Registry: HKLM\Software, HKCU\Software
        - Filesystem: targeted directories (System32 + TEMP)
        - Event Logs: Application, Security, System
        - Window Messages: new windows/dialogs that appear
    """

    def __init__(self, fs_roots: List[str] = None, watchlist: Dict[str, Set[str]] = None):
        # watchlist keys: "registry" and "filesystem", each being a set of prefixes to monitor
        self.watchlist = watchlist or {"registry": set(), "filesystem": set()}

        if fs_roots:
            self.fs_roots = [Path(p) for p in fs_roots]
        else:
            system_root = Path(os.getenv("SystemRoot", r"C:\Windows"))
            user_temp   = Path(os.getenv("TEMP", r"C:\Windows\Temp"))
            self.fs_roots = [system_root / "System32", user_temp]

        # Data structures to hold captures
        self.registry_dump: Dict[str, Dict[str, Any]] = {}
        self.filesystem_index: Dict[str, float] = {}
        self.event_logs: Dict[str, List[str]] = {}
        # Store window messages as a set of (hwnd, text, exe_path)
        self.window_messages: Set[Tuple[int, str, str]] = set()

        logging.debug(f"[Snapshot] Initialized for FS roots: {self.fs_roots}")

    def capture_registry(self):
        """
        Dump all relevant registry keys under HKLM\Software and HKCU\Software,
        but only descend into keys whose path contains any of the watchlist prefixes.
        """
        hives = {
            "HKLM_SOFTWARE": (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
            "HKCU_SOFTWARE": (winreg.HKEY_CURRENT_USER,    r"Software")
        }
        for hive_name, (root, subkey) in hives.items():
            self.registry_dump[hive_name] = {}
            try:
                with winreg.OpenKey(root, subkey) as hkey:
                    self.registry_dump[hive_name] = self._walk_registry(hkey, prefix=subkey)
                    logging.debug(
                        f"[Snapshot] Captured {len(self.registry_dump[hive_name])} keys under {hive_name}"
                    )
            except Exception as e:
                logging.error(f"[Snapshot] Failed to open {hive_name}: {e}")

    def _walk_registry(self, hkey, prefix: str = "") -> Dict[str, Dict[str, Any]]:
        """
        Recursively read all values under a given registry handle, but only
        descend into keys whose full path (prefix) contains any watched substring.
        """
        result: Dict[str, Dict[str, Any]] = {}

        watched = self.watchlist.get("registry", set())
        # If watchlist is non‐empty, skip subtrees that don't match any prefix
        if watched and not any(pat.lower() in prefix.lower() for pat in watched):
            return {}

        # Record this key's values
        result[prefix] = self._get_values(hkey)

        i = 0
        while True:
            try:
                subname = winreg.EnumKey(hkey, i)
                i += 1
                with winreg.OpenKey(hkey, subname) as subh:
                    full = f"{prefix}\\{subname}"
                    sub_tree = self._walk_registry(subh, prefix=full)
                    if sub_tree:
                        result.update(sub_tree)
            except OSError:
                break

        return result

    def _get_values(self, hkey) -> Dict[str, Any]:
        """
        Read all name/data pairs under the open registry handle `hkey`.
        """
        out: Dict[str, Any] = {}
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
        """
        Walk each fs_root; record mtime of every file whose full path contains
        any of the watched prefixes (or all files if watchlist["filesystem"] is empty).
        """
        for root in self.fs_roots:
            for dirpath, dirs, files in os.walk(root):
                for fname in files:
                    full = str(Path(dirpath) / fname)
                    if (
                        self.watchlist["filesystem"] and
                        not any(pat.lower() in full.lower() for pat in self.watchlist["filesystem"])
                    ):
                        continue
                    try:
                        self.filesystem_index[full] = Path(full).stat().st_mtime
                    except Exception:
                        continue
            logging.debug(f"[Snapshot] Indexed {len(self.filesystem_index)} files")

    def capture_event_logs(self):
        """
        Use `wevtutil` to grab the last ~1000 lines from Application, Security, System.
        """
        logs = ["Application", "Security", "System"]
        for log in logs:
            try:
                cmd = ["wevtutil", "qe", log, "/f:text", "/c:1000"]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate(timeout=30)
                if err:
                    logging.error(f"[EventLog] {log} stderr: {err.decode(errors='ignore')}")
                lines = out.decode(errors="ignore").splitlines()
                self.event_logs[log] = lines
                logging.debug(f"[Snapshot] Captured {len(lines)} lines from {log}")
            except Exception as e:
                logging.error(f"[Snapshot] Failed to capture {log}: {e}")
                self.event_logs[log] = []

    def capture_window_messages(self):
        """
        Enumerate all windows and capture (hwnd, text, exe_path) tuples.
        """
        entries = find_windows_with_text()
        self.window_messages = set(entries)
        logging.debug(f"[Snapshot] Captured {len(self.window_messages)} window messages")

    def capture(self):
        """
        Perform a full snapshot: registry, filesystem, event logs, window messages.
        """
        self.capture_registry()
        self.capture_filesystem()
        self.capture_event_logs()
        self.capture_window_messages()

    def diff(self, other: "Snapshot") -> Dict[str, Any]:
        """
        Compare this snapshot to `other`, return a dict with:
          - new_registry_keys            : List[(hive, key_path)]
          - modified_registry_values     : List[(hive, key_path, value_name, old, new)]
          - new_files                    : List[file_path]
          - modified_files               : List[file_path]
          - new_event_log_lines          : List[(log_name, line_text)]
          - new_window_messages          : List[(hwnd, text, exe_path)]
          - deleted_registry_keys        : List[(hive, key_path)]
          - deleted_registry_values      : List[(hive, key_path, value_name)]
          - deleted_files                : List[file_path]
        """
        _CONTROL_CHAR_RE = re.compile(r'[\x00-\x1F\x7F]')

        def _sanitize(s: str) -> str:
            return _CONTROL_CHAR_RE.sub('', s)

        diffs: Dict[str, Any] = {
            "new_registry_keys": [],            # (hive, key_path)
            "modified_registry_values": [],     # (hive, key_path, vname, old, new)
            "new_files": [],                    # file paths
            "modified_files": [],               # file paths
            "new_event_log_lines": [],          # (log_name, line_text)
            "new_window_messages": [],          # (hwnd, text, exe_path)
            "deleted_registry_keys": [],        # (hive, key_path)
            "deleted_registry_values": [],      # (hive, key_path, vname)
            "deleted_files": []                 # file paths
        }

        # Deleted registry keys
        for hive, other_tree in other.registry_dump.items():
            tree = self.registry_dump.get(hive, {})
            for key_path in other_tree:
                if key_path not in tree:
                    diffs["deleted_registry_keys"].append((hive, key_path))

        # Deleted registry values
        for hive, other_tree in other.registry_dump.items():
            tree = self.registry_dump.get(hive, {})
            for key_path, values in other_tree.items():
                current_values = tree.get(key_path, {})
                for vname in values:
                    if vname not in current_values:
                        diffs["deleted_registry_values"].append((hive, key_path, vname))

        # Deleted files
        for path in other.filesystem_index:
            if path not in self.filesystem_index:
                diffs["deleted_files"].append(path)

        # New registry keys & modified values
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

        # Filesystem diffs (new or modified)
        for path, mtime in self.filesystem_index.items():
            other_mtime = other.filesystem_index.get(path)
            if other_mtime is None:
                diffs["new_files"].append(path)
            elif other_mtime != mtime:
                diffs["modified_files"].append(path)

        # Event Log diffs (any new lines)
        for log_name, lines in self.event_logs.items():
            prev = set(other.event_logs.get(log_name, []))
            for ln in lines:
                if ln not in prev:
                    diffs["new_event_log_lines"].append((log_name, ln))

        # Window message diffs (new windows/dialogs/text)
        for wnd in self.window_messages:
            if wnd not in other.window_messages:
                diffs["new_window_messages"].append(wnd)

        # Logging each category
        for change_type, items in diffs.items():
            if not items:
                continue
            logging.info(f"[Snapshot.diff] {len(items)} {change_type}:")
            for item in items:
                if change_type == "new_window_messages":
                    hwnd, text, exe = item
                    sanitized_text = _sanitize(text)
                    joined = f"HWND={hwnd} | \"{sanitized_text}\" | {exe}"
                else:
                    if isinstance(item, tuple):
                        clean_parts: List[str] = []
                        for elem in item:
                            if isinstance(elem, (bytes, bytearray)):
                                clean_parts.append("<binary data>")
                            else:
                                clean_parts.append(_sanitize(str(elem)))
                        # Build a readable string for certain types
                        if change_type == "new_registry_keys":
                            joined = f"{clean_parts[0]}\\{clean_parts[1]}"
                        elif change_type == "modified_registry_values":
                            joined = (
                                f"{clean_parts[0]}\\{clean_parts[1]}\\{clean_parts[2]}: "
                                f"{clean_parts[3]} → {clean_parts[4]}"
                            )
                        else:
                            joined = " | ".join(clean_parts)
                    else:
                        joined = _sanitize(str(item))
                logging.info(f"    {change_type}: {joined}")

        return diffs

# -------------------------------------------------------------------
# 4) RULE ENGINE (SIGMA‐STYLE .ohd PARSER + EVALUATOR)
# -------------------------------------------------------------------

r"""
Rule syntax (.ohd):

    rule MyTrojanRule {
        meta:
            id = "TROJAN-0002"
            description = "Detect stealthy registry key creation or window dialog"
        condition:
            registry.new_registry_keys contains "Software\\EvilCorp"
            filesystem.new_files contains "AppData\\Local\\Temp\\evil.dll"
            eventlog.System matches "malicious.*exe"
            window_messages contains "Error connecting to server"
    }

Supported fields:
  - registry.new_registry_keys
  - registry.modified_registry_values
  - filesystem.new_files
  - filesystem.modified_files
  - eventlog.<LogName> matches "<regex>"
  - window_messages contains "<substring>" or matches "<regex>"

Operators:
  - contains (case‐insensitive substring)
  - matches  (case‐insensitive regex)
"""

RULE_RE      = re.compile(r'^\s*rule\s+([A-Za-z0-9_-]+)\s*\{')
META_RE      = re.compile(r'^\s*meta\s*:\s*$')
COND_RE      = re.compile(r'^\s*condition\s*:\s*$')
KEYVAL_RE    = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]+)"\s*$')
COND_LINE_RE = re.compile(
    r'^\s*('
    r'registry\.(?:new_registry_keys|modified_registry_values)|'
    r'filesystem\.(?:new_files|modified_files)|'
    r'eventlog\.[A-Za-z0-9_]+|'
    r'window_messages'
    r')\s*'
    r'(contains|matches)\s*"([^"]+)"\s*$'
)

class Rule:
    """
    Representation of a single OpenHydraDragon rule.
    """

    def __init__(self, name: str):
        self.name = name
        self.meta: Dict[str, str] = {}
        # Each condition_line is (field, operator, pattern)
        self.condition_lines: List[Tuple[str, str, str]] = []
        logging.debug(f"[Rule] Created skeleton for rule '{name}'")

    def add_meta(self, key: str, value: str):
        self.meta[key] = value

    def add_condition(self, field: str, operator: str, pattern: str):
        self.condition_lines.append((field, operator, pattern))

    def evaluate(self, diffs: Dict[str, Any]) -> bool:
        """
        Evaluate this rule against the snapshot‐diff `diffs`.
        Returns True only if **ALL** condition lines match.
        Supports:
          - 'contains' (case‐insensitive substring match)
          - 'matches'  (case‐insensitive regex match)
          - hex‐escape patterns like '\\x41\\x42' via byte‐level search
        """

        _CONTROL_CHAR_RE = re.compile(r'[\x00-\x1F\x7F]')

        def byte_contains(entry_text: str, pat_bytes: bytes) -> bool:
            try:
                entry_b = entry_text.encode('utf-8', 'ignore')
                return pat_bytes in entry_b
            except Exception:
                return False

        for (field, operator, pattern) in self.condition_lines:
            # If pattern contains '\x', try hex‐escape logic
            if r'\x' in pattern:
                # Convert '\\x41\\x42' → '4142' → bytes.fromhex('4142')
                try:
                    hex_str = pattern.replace(r'\x', '')
                    pat_bytes = bytes.fromhex(hex_str)
                except Exception:
                    pat_bytes = None

                if field.startswith("registry."):
                    if field.endswith("new_registry_keys"):
                        items = [
                            f"{hive}\\{path}"
                            for hive, path in diffs.get("new_registry_keys", [])
                        ]
                    else:
                        items = [
                            f"{hive}\\{path}\\{vname} -> {oldv} => {newv}"
                            for hive, path, vname, oldv, newv
                            in diffs.get("modified_registry_values", [])
                        ]
                    matched = False
                    if pat_bytes:
                        for entry in items:
                            if operator == "contains" and byte_contains(entry, pat_bytes):
                                matched = True
                                break
                        if not matched:
                            return False
                        continue

                elif field.startswith("filesystem."):
                    if field.endswith("new_files"):
                        items = diffs.get("new_files", [])
                    else:
                        items = diffs.get("modified_files", [])
                    matched = False
                    if pat_bytes:
                        for entry in items:
                            if operator == "contains" and byte_contains(entry, pat_bytes):
                                matched = True
                                break
                        if not matched:
                            return False
                        continue

                elif field.startswith("eventlog."):
                    _, log_name = field.split(".", 1)
                    items = [
                        ln for (lg, ln) in diffs.get("new_event_log_lines", [])
                        if lg.lower() == log_name.lower()
                    ]
                    matched = False
                    if pat_bytes:
                        for entry in items:
                            if operator == "contains" and byte_contains(entry, pat_bytes):
                                matched = True
                                break
                        if not matched:
                            return False
                        continue

                elif field == "window_messages":
                    items = [text for (_, text, _) in diffs.get("new_window_messages", [])]
                    matched = False
                    if pat_bytes:
                        for entry in items:
                            if operator == "contains" and byte_contains(entry, pat_bytes):
                                matched = True
                                break
                        if not matched:
                            return False
                        continue

                # If we get here, hex‐escape logic failed → treat as non‐match
                return False

            # Otherwise, do normal text‐based logic
            if field.startswith("registry."):
                if field.endswith("new_registry_keys"):
                    items = [
                        f"{hive}\\{path}"
                        for hive, path in diffs.get("new_registry_keys", [])
                    ]
                    matched = False
                    for entry in items:
                        if operator == "contains" and pattern.lower() in entry.lower():
                            matched = True
                            break
                        elif operator == "matches" and re.search(pattern, entry, re.IGNORECASE):
                            matched = True
                            break
                    if not matched:
                        return False

                else:  # registry.modified_registry_values
                    items = [
                        f"{hive}\\{path}\\{vname} -> {oldv} => {newv}"
                        for hive, path, vname, oldv, newv
                        in diffs.get("modified_registry_values", [])
                    ]
                    matched = False
                    for entry in items:
                        if operator == "contains" and pattern.lower() in entry.lower():
                            matched = True
                            break
                        elif operator == "matches" and re.search(pattern, entry, re.IGNORECASE):
                            matched = True
                            break
                    if not matched:
                        return False

            elif field.startswith("filesystem."):
                if field.endswith("new_files"):
                    items = diffs.get("new_files", [])
                else:
                    items = diffs.get("modified_files", [])
                matched = False
                for fpath in items:
                    if operator == "contains":
                        if pattern.lower() in fpath.lower():
                            matched = True
                            break
                    elif operator == "matches":
                        if re.search(pattern, fpath, re.IGNORECASE):
                            matched = True
                            break
                if not matched:
                    return False

            elif field.startswith("eventlog."):
                _, log_name = field.split(".", 1)
                items = [
                    ln for (lg, ln) in diffs.get("new_event_log_lines", [])
                    if lg.lower() == log_name.lower()
                ]
                matched = False
                for ln in items:
                    if operator == "contains" and pattern.lower() in ln.lower():
                        matched = True
                        break
                    elif operator == "matches" and re.search(pattern, ln, re.IGNORECASE):
                        matched = True
                        break
                if not matched:
                    return False

            elif field == "window_messages":
                items = diffs.get("new_window_messages", [])
                matched = False
                for (_, text, exe_path) in items:
                    if operator == "contains" and pattern.lower() in text.lower():
                        matched = True
                        break
                    elif operator == "matches" and re.search(pattern, text, re.IGNORECASE):
                        matched = True
                        break
                if not matched:
                    return False

            else:
                # Unknown field
                return False

        # If we never returned False above, all conditions matched
        return True

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
        to a set of path‐prefix substrings our rules actually reference.
        """
        regs: Set[str] = set()
        files: Set[str] = set()
        for rule in self.rules:
            for field, op, pat in rule.condition_lines:
                if field.startswith("registry."):
                    # treat pattern as a potential registry key substring
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
            # Check for "rule <Name> {"
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
                # End of this rule block
                self.rules.append(current_rule)
                logging.debug(
                    f"[RuleEngine] Loaded rule '{current_rule.name}' (meta: {current_rule.meta}) "
                    f"with {len(current_rule.condition_lines)} condition(s)"
                )
                current_rule = None
                mode = None

    def evaluate_all(self, diffs: Dict[str, Any]) -> List[str]:
        """
        Evaluate every loaded rule against `diffs`; return a list of rule names that matched.
        """
        matches: List[str] = []
        for rule in self.rules:
            try:
                if rule.evaluate(diffs):
                    matches.append(rule.name)
            except Exception as e:
                logging.error(f"[RuleEngine] Error evaluating rule '{rule.name}': {e}")
        return matches

# -------------------------------------------------------------------
# 5) SUPPORT FUNCTIONS
# -------------------------------------------------------------------

def gather_custom_logs(log_dirs: List[str]) -> List[str]:
    """
    Recursively read all .log / .txt files in given directories,
    return a list of lines.
    """
    collected: List[str] = []
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

# -------------------------------------------------------------------
# 6) MAIN WORKFLOW (AUTOMATED)
# -------------------------------------------------------------------

def process_sample(
    sample_path: str,
    rules_dir: str,
    fs_roots: List[str],
    custom_log_dirs: List[str],
    timeout: int = 60
) -> List[str]:
    """
    Processes a single sample in always-debug + window-detection mode:
      0) Load rules + extract watch‐list
      1) Pre‐snapshot (registry, fs, event logs, window messages)
      2) Run sample normally (no sandbox)
      3) Post‐snapshot → diff_dbg
      4) Treat diff_dbg as "stealthy"
      5) Gather custom logs (append to event_log changes)
      6) Evaluate rules → return matched rule names
    """
    # 0) Load rules and get watch‐list
    engine = RuleEngine(rules_dir)
    watch = engine.get_watchlist()

    # 1) Pre‐snapshot
    snap_before = Snapshot(fs_roots=fs_roots, watchlist=watch)
    snap_before.capture()

    # 2) Run sample normally
    cmd = [sample_path]
    logging.info(f"[Run] Launching sample: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            if stdout:
                logging.debug(f"[Run] stdout:\n{stdout.decode(errors='ignore')}")
            if stderr:
                logging.error(f"[Run] stderr:\n{stderr.decode(errors='ignore')}")
            ret_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            logging.error("[Run] Process timed out and was killed.")
            ret_code = -1
    except Exception as e:
        logging.exception(f"[Run] Failed to launch sample: {e}")
        ret_code = -1

    logging.info(f"[Run] Exit code for '{sample_path}': {ret_code}")

    # 3) Post‐snapshot
    snap_after = Snapshot(fs_roots=fs_roots, watchlist=watch)
    snap_after.capture()
    diff_dbg = snap_after.diff(snap_before)
    logging.info(
        "[Run] Diffs summary: "
        f"new_keys={len(diff_dbg['new_registry_keys'])}, "
        f"mod_vals={len(diff_dbg['modified_registry_values'])}, "
        f"new_files={len(diff_dbg['new_files'])}, "
        f"mod_files={len(diff_dbg['modified_files'])}, "
        f"new_logs={len(diff_dbg['new_event_log_lines'])}, "
        f"new_wnd_msgs={len(diff_dbg['new_window_messages'])}"
    )

    # 4) Treat diff_dbg as "stealthy"
    stealthy = diff_dbg

    # 5) Gather custom logs
    custom_lines = gather_custom_logs(custom_log_dirs)
    for ln in custom_lines:
        stealthy["new_event_log_lines"].append(("CustomLog", ln))

    # 6) Evaluate rules
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

    target    = sys.argv[1]
    rules_dir = sys.argv[2]

    # 1) Determine FS roots to snapshot
    system_root = Path(os.getenv("SystemRoot", r"C:\Windows"))
    user_temp   = Path(os.getenv("TEMP",       r"C:\Windows\Temp"))
    fs_roots    = [str(system_root / "System32"), str(user_temp)]

    # 2) Any custom log directories (e.g., your AV sandbox logs)
    custom_log_dirs = [
        str(SCRIPT_DIR / "HydraDragonAVSandboxie" / "Logs"),
        # You can add more paths here if needed
    ]

    # 3) If target is a directory, iterate all .exe files inside
    samples: List[str] = []
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

    logging.info("=== OpenHydraDragon Run Completed ===")

if __name__ == "__main__":
    main()
