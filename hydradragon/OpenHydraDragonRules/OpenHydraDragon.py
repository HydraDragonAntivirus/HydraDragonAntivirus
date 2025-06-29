#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenHydraDragon (Sigma-Focused Edition):
 - Captures registry, filesystem, Windows Event Logs, and live window messages.
 - Captures process creation events (with command line/user) and DNS queries.
 - Supports scanning a directory of samples.
 - Loads SIGMA-style .ohd rules with an enhanced, flexible syntax.
 - Scanning scope for filesystem and registry is now driven by rule content.
 - Runs every sample normally (no Sandboxie).
 - Allows rules to match on new window titles/text (e.g., dialogs, message boxes).
 - 'generic.activity' field unifies matching for window messages and process command lines.
 - Network event handling generates OHD rules and saves full packet dumps.
 - **NEW**: Advanced operator support and proper AND/OR logic for complex rules.
"""

import os
import sys
import logging
import subprocess
import winreg
import re
import threading
import ctypes
from ctypes import wintypes
import psutil
import base64
import binascii
import pefile
from comtypes.client import CreateObject
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set, Optional, Callable
from collections import defaultdict

from scapy.config import conf
conf.use_pcap = True
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.dns import DNSQR
from scapy.packet import Raw
from scapy.arch.windows import get_windows_if_list
from cryptography import x509

# -------------------------------------------------------------------
# 0) WINDOWS API + UI AUTOMATION SETUP FOR COMMANDLINE & MESSAGE DETECTION
# -------------------------------------------------------------------

# Constants for Windows API calls
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Load libraries
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
ole32 = ctypes.windll.ole32

# UI Automation COM object (for retrieving control names if WM_GETTEXT fails)
try:
    uia = CreateObject('UIAutomationClient.CUIAutomation')
except Exception:
    uia = None

# Map for converting string hive names to winreg constants
HIVE_MAP = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS,
    "HKEY_USERS": winreg.HKEY_USERS,
}

# -------------------------------------------------------------------
# 1) WINDOWS API HELPERS
# -------------------------------------------------------------------

def get_certificate_serial(pe_path: str) -> Optional[str]:
    pe = pefile.PE(pe_path, fast_load=False)
    # Tell pefile to parse only the Security directory (index 4)
    security_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    pe.parse_data_directories(directories=[security_idx])

    # Now this should exist:
    if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        return None

    sec_entry = pe.DIRECTORY_ENTRY_SECURITY[0]
    der_blob  = sec_entry.cert  # raw DER bytes of the WIN_CERTIFICATE blob

    # Parse the DER with cryptography
    cert = x509.load_der_x509_certificate(der_blob)
    return format(cert.serial_number, 'X')

def extract_resp_mime_types(sample_path: str) -> list[str]:
    """
    Placeholder: parse WebDAV or HTTP response MIME types from network_events
    """
    # TODO: implement actual extraction logic
    return []


def extract_http_fields(diffs: dict, key: str) -> list[str]:
    """
    Extract HTTP fields (method, uri, host) from diffs['new_network_events']
    """
    return [ ev.get(key) for ev in diffs.get('new_network_events', []) if ev.get(key) ]


def extract_address(diffs: dict) -> list[str]:
    """
    Extract remote addresses (e.g. ngrok or RDP) from network events
    """
    return [ ev.get('address') for ev in diffs.get('new_network_events', []) if ev.get('address') ]


def extract_id_orig_h(diffs: dict) -> list[str]:
    """
    Extract original host IP from network events
    """
    return [ ev.get('source_ip') for ev in diffs.get('new_network_events', []) if ev.get('source_ip') ]


def extract_id_resp_h(diffs: dict) -> list[str]:
    """
    Extract response host IP from network events
    """
    return [ ev.get('destination_ip') for ev in diffs.get('new_network_events', []) if ev.get('destination_ip') ]


def extract_eventlog_field(diffs: dict, field: str) -> list[str]:
    """
    Extract specified field values from Windows event logs
    """
    return [ e.get(field) for e in diffs.get('new_event_logs', []) if e.get(field) ]


def extract_scheduled_tasks(diffs: dict, which: str) -> list[str]:
    """
    Extract TaskContent or NewTaskContent from scheduled tasks diffs
    """
    tasks = diffs.get('new_scheduled_tasks', []) + diffs.get('updated_scheduled_tasks', [])
    return [ t.get(which) for t in tasks if t.get(which) ]

def get_process_path(hwnd: int):
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
# 2) VERBOSE LOGGING SETUP (console + file)
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

logging.info("=== OpenHydraDragon Sigma-Focused Edition Started ===")


# -------------------------------------------------------------------
# 3) NETWORK AND EVENT PARSING HELPERS
# -------------------------------------------------------------------

def extract_http_details(payload: bytes) -> Optional[Dict[str, str]]:
    try:
        text = payload.decode('utf-8', errors='ignore')
        lines = text.split('\r\n')
        request_line = lines[0]
        match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(/.*?)\s+HTTP/1\.[01]", request_line)
        if not match:
            return None
        details = {'method': match.group(1), 'uri': match.group(2)}
        for line in lines[1:]:
            if line.lower().startswith('host:'):
                details['host'] = line.split(':', 1)[1].strip()
            elif line.lower().startswith('user-agent:'):
                details['user_agent'] = line.split(':', 1)[1].strip()
        return details
    except Exception:
        return None

def extract_dns_query(pkt) -> Optional[Dict[str, str]]:
    if pkt.haslayer(DNSQR):
        try:
            # Handle potential multiple queries, return the first
            qname = pkt[DNSQR][0].qname if isinstance(pkt[DNSQR], list) else pkt[DNSQR].qname
            return {'query_name': qname.decode('utf-8')}
        except Exception:
            return None
    return None

def parse_wevtutil_output(lines: List[str]) -> List[Dict[str, str]]:
    """Parses the text output of wevtutil into a list of event dictionaries."""
    events = []
    current_event = {}
    for line in lines:
        line = line.strip()
        if not line and current_event:
            # Check for a minimal set of keys to constitute a valid event
            if "Event ID" in current_event or "Provider Name" in current_event:
                events.append(current_event)
            current_event = {}
            continue
        if ':' in line:
            key, val = line.split(":", 1)
            current_event[key.strip()] = val.strip()
    if current_event and ("Event ID" in current_event or "Provider Name" in current_event):
        events.append(current_event)
    return events


# -------------------------------------------------------------------
# 4) SNAPSHOT CAPTURE
# -------------------------------------------------------------------

class Snapshot:
    def __init__(self, fs_roots: List[str] = None, reg_roots: List[str] = None):
        self.fs_roots = [Path(p) for p in fs_roots] if fs_roots else []
        self.reg_roots = reg_roots or []
        self.registry_dump: Dict[str, Dict[str, Any]] = {}
        self.filesystem_index: Dict[str, float] = {}
        self.event_logs: Dict[str, List[Dict[str, str]]] = {}
        self.window_messages: Set[Tuple[int, str, str]] = set()
        self.network_events: Set[frozenset] = set()
        self.dns_events: Set[frozenset] = set()
        self.process_events: Set[frozenset] = set()

    def capture_registry(self) -> None:
        self.registry_dump = {}
        if not self.reg_roots:
            logging.warning(
                "[Snapshot] No registry roots specified by rules. Skipping registry capture."
            )
            return

        # Stack holds tuples of (hive_handle, subkey_path, full_registry_path)
        stack: List[Tuple[winreg.HKEYType, str, str]] = []

        for root_path in self.reg_roots:
            hive_str, _, key_path = root_path.partition('\\')
            hive_handle = HIVE_MAP.get(hive_str.upper())
            if not hive_handle:
                logging.error(f"[Snapshot] Unknown registry hive in path: {root_path}")
                continue

            # Seed the stack with the root hive handle directly
            stack.append((hive_handle, key_path, f"{hive_str}\\{key_path}"))

            while stack:
                hkey, sub_key_path, full_path = stack.pop(0)
                try:
                    with winreg.OpenKey(hkey, sub_key_path) as current_hkey:
                        # Capture all values under this key
                        self.registry_dump[full_path] = self._get_values(current_hkey)

                        # Enumerate subkeys and push them onto the stack
                        i = 0
                        while True:
                            try:
                                sub_name = winreg.EnumKey(current_hkey, i)
                                stack.append((hkey, sub_name, f"{full_path}\\{sub_name}"))
                                i += 1
                            except OSError:
                                break  # no more subkeys
                except FileNotFoundError:
                    logging.debug(
                        f"[Snapshot] Registry path not found (will be detected if created): {full_path}"
                    )
                except Exception as e:
                    logging.error(f"[Snapshot] Failed to process registry key {full_path}: {e}")

    def _get_values(self, hkey) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        j = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(hkey, j)
                out[name or "(Default)"] = data
                j += 1
            except OSError:
                break
        return out

    def capture_filesystem(self):
        self.filesystem_index = {}
        if not self.fs_roots:
            logging.warning("[Snapshot] No filesystem roots specified by rules. Skipping filesystem capture.")
            return
        for root in self.fs_roots:
            if not root.exists(): continue
            for dirpath, _, files in os.walk(root):
                for fname in files:
                    full = str(Path(dirpath) / fname)
                    try:
                        self.filesystem_index[full] = Path(full).stat().st_mtime
                    except Exception:
                        continue

    def capture_event_logs(self):
        logs = ["Application", "Security", "System"]
        for log in logs:
            try:
                # Using shell=True for wevtutil as it's a built-in command
                cmd = f'wevtutil qe {log} /f:text /rd:true /c:5000'
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
                out, err = proc.communicate(timeout=45)
                if err: logging.error(f"[EventLog] {log} stderr: {err.decode(errors='ignore')}")
                
                lines = out.decode(errors="ignore").splitlines()
                parsed_events = parse_wevtutil_output(lines)
                self.event_logs[log] = parsed_events
                
                if log == "Security":
                    self._parse_process_creation_events(parsed_events)
            except Exception as e:
                logging.error(f"[Snapshot] Failed to capture {log}: {e}")

    def _parse_process_creation_events(self, events: List[Dict[str, str]]):
        for event in events:
            if event.get("Event ID") == "4688" and "New Process Name" in event and "Command Line" in event:
                proc_event = {
                    'image': event.get("New Process Name"),
                    'command_line': event.get("Command Line"),
                    'user': event.get("Security ID", "N/A"),
                    'parent_image': event.get("Creator Process Name", "N/A")
                }
                self.process_events.add(frozenset(proc_event.items()))

    def capture_window_messages(self):
        self.window_messages = set(find_windows_with_text())

    def capture_network(self, timeout: int):
        self.network_events = set()
        self.dns_events = set()

        def _collector(pkt):
            dns_query = extract_dns_query(pkt)
            if dns_query:
                self.dns_events.add(frozenset(dns_query.items()))

            if pkt.haslayer(IP):
                proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "ip"
                net_event = {
                    "protocol": proto, 
                    "source_ip": pkt[IP].src, 
                    "source_port": pkt.sport, 
                    "destination_ip": pkt[IP].dst, 
                    "destination_port": pkt.dport
                }
                
                if pkt.haslayer(Raw):
                    http_details = extract_http_details(pkt[Raw].load)
                    if http_details:
                        net_event.update(http_details)
                
                self.network_events.add(frozenset(net_event.items()))
        
        interfaces = [i['name'] for i in get_windows_if_list()]
        def sniff_on_interface(iface):
            try:
                sniff(iface=iface, filter="ip", prn=_collector, timeout=timeout, store=False)
            except Exception as e:
                logging.debug(f"[Sniffer] Error on interface '{iface}': {e}")
        
        threads = [threading.Thread(target=sniff_on_interface, args=(iface,), daemon=True) for iface in interfaces]
        for t in threads: t.start()
        for t in threads: t.join()

    def capture(self):
        self.capture_registry()
        self.capture_filesystem()
        self.capture_event_logs()
        self.capture_window_messages()

    def diff(self, other: "Snapshot") -> Dict[str, Any]:
        _CONTROL_CHAR_RE = re.compile(r'[\x00-\x1F\x7F]')
        def _sanitize(s: str) -> str:
            return _CONTROL_CHAR_RE.sub('', str(s))

        diffs: Dict[str, Any] = {
            "new_registry_keys": [], "modified_registry_values": [], "deleted_registry_keys": [],
            "new_files": [], "modified_files": [], "deleted_files": [],
            "new_event_logs": [], "new_window_messages": [],
            "new_network_events": [dict(e) for e in self.network_events - other.network_events],
            "new_dns_events": [dict(e) for e in self.dns_events - other.dns_events],
            "new_process_events": [dict(e) for e in self.process_events - other.process_events]
        }

        # Filesystem Diffs
        self_files = set(self.filesystem_index.keys())
        other_files = set(other.filesystem_index.keys())
        diffs["new_files"] = list(self_files - other_files)
        diffs["deleted_files"] = list(other_files - self_files)
        diffs["modified_files"] = [p for p in self_files.intersection(other_files) if self.filesystem_index[p] != other.filesystem_index[p]]

        # Registry Diffs
        self_reg_keys = set(self.registry_dump.keys())
        other_reg_keys = set(other.registry_dump.keys())
        diffs["new_registry_keys"] = list(self_reg_keys - other_reg_keys)
        diffs["deleted_registry_keys"] = list(other_reg_keys - self_reg_keys)

        common_keys = self_reg_keys.intersection(other_reg_keys)
        for key in common_keys:
            self_vals = self.registry_dump[key]
            other_vals = other.registry_dump[key]
            if self_vals != other_vals:
                diffs["modified_registry_values"].append({'key': key, 'old': other_vals, 'new': self_vals})
        
        # Event Log Diffs
        for log_name, events in self.event_logs.items():
            other_events_set = {frozenset(e.items()) for e in other.event_logs.get(log_name, [])}
            new_events = [e for e in events if frozenset(e.items()) not in other_events_set]
            if new_events:
                diffs["new_event_logs"].extend(new_events)
        
        # Other Diffs
        diffs["new_window_messages"] = list(self.window_messages - other.window_messages)
        # Combine command lines and window titles into a single source for generic matching
        diffs["generic_activity"] = [w[1] for w in diffs["new_window_messages"]] + [p.get('command_line', '') for p in diffs.get('new_process_events', [])]

        
        for change_type, items in diffs.items():
            if not items: continue
            logging.info(f"[Snapshot.diff] {len(items)} {change_type}:")
            # Log first 5 items for brevity
            for item in items[:5]:
                logging.info(f"    {change_type}: {_sanitize(str(item))}")
        return diffs

# -------------------------------------------------------------------
# 5) RULE ENGINE (SIGMA-AWARE)
# -------------------------------------------------------------------
# Pattern to match a 'rule NAME' line, with optional '{' on same line
RULE_START_RE = re.compile(r'^\s*rule\s+([A-Za-z0-9_-]+)\s*\{?\s*$', re.IGNORECASE)
META_RE = re.compile(r'^\s*meta\s*:\s*$', re.IGNORECASE)
COND_RE = re.compile(r'^\s*condition\s*:\s*$', re.IGNORECASE)
KEYVAL_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"(.+?)"\s*$', re.DOTALL)
COND_LINE_RE = re.compile(
    r'^\s*([a-zA-Z0-9_.-]+)\s+'
    r'(contains|matches|equals|startswith|endswith|re|eq)\s+"(.+?)"\s*$',
    re.IGNORECASE | re.DOTALL
)

def normalize_pattern(pattern: str) -> str:
    """
    Normalize backslashes in pattern without causing decode errors.

    - Replace escaped double backslashes with a single backslash.
    - Escape single backslashes not part of valid escape sequences.
    """
    # Replace double backslashes with single backslash first
    pattern = pattern.replace('\\\\', '\\')

    # Function to escape invalid backslashes
    def escape_invalid_backslash(match):
        next_char = match.group(1)
        if re.match(r'[ntr\\\'"xuU]', next_char):
            return '\\' + next_char  # valid escape, keep as-is
        else:
            return '\\\\' + next_char  # escape invalid backslash

    # Escape invalid backslashes
    pattern = re.sub(r'\\(.)', escape_invalid_backslash, pattern)

    return pattern

class Rule:
    # Maps common Sigma field names to their canonical OHD names.
    SIGMA_FIELD_MAP = {
        'commandline': 'process.creation_commandline', 'processcommandline': 'process.creation_commandline',
        'image': 'process.image', 'processimage': 'process.image',
        'parentimage': 'process.parent_image', 'parentprocessimage': 'process.parent_image',
        'parentcommandline': 'process.parent_commandline',
        'user': 'process.user', 'logontype': 'process.logon_type', 'targetusername': 'process.user',
        'filename': 'file.path', 'filepath': 'file.path',
        'targetfilename': 'file.path', 'sourcefilename': 'file.path',
        'targetobject': 'registry.key', 'details': 'registry.value',
        'eventtype': 'registry.event_type',
        'destinationhostname': 'network.destination_hostname', 'destinationip': 'network.destination_ip',
        'destinationport': 'network.destination_port', 'sourceip': 'network.source_ip',
        'sourceport': 'network.source_port', 'protocol': 'network.protocol',
        'c-useragent': 'http.user_agent', 'c-uri': 'http.uri', 'cs-host': 'http.host', 'cs-method': 'http.method',
        'eventid': 'eventlog.event_id', 'channel': 'eventlog.channel',
        'provider_name': 'eventlog.provider', 'computer': 'eventlog.computer', 'message': 'eventlog.message',
        'queryname': 'dns.query_name', 'querytype': 'dns.query_type', 'queryresults': 'dns.query_results',
        'servicename': 'eventlog.servicename', 'imagepath': 'eventlog.imagepath',
        'hivename': 'eventlog.hivename', 'taskname': 'eventlog.taskname',
        'accesslist': 'eventlog.accesslist', 'relativetargetname': 'eventlog.relativetargetname',
        'sharename': 'eventlog.sharename', 'objectname': 'eventlog.objectname',
        'objecttype': 'eventlog.objecttype', 'processname': 'eventlog.processname',
        'query': 'dns.query_name', 'uri': 'http.uri', 'host': 'http.host',
        'user_agent': 'http.user_agent', 'method': 'http.method',
        'path': 'file.path', # Generic path for file or network
    }

    def __init__(self, name: str):
        self.name = name
        self.meta: Dict[str, str] = {}
        self.condition_lines: List[Tuple[str, str, str]] = []

    def _get_data_sources(self, diffs: Dict[str, Any]) -> Dict[str, Callable[[], List[Any]]]:
        """Maps canonical field names to functions that extract data from diffs."""
        all_events = diffs.get('new_event_logs', [])
        return {
            'generic.activity':           lambda: diffs.get('generic_activity', []),
            # File
            'file.path':                  lambda: diffs.get('new_files', []) + diffs.get('modified_files', []),
            'file.name':                  lambda: [Path(p).name for p in diffs.get('new_files', []) + diffs.get('modified_files', [])],
            # Registry
            'registry.key':               lambda: diffs.get('new_registry_keys', []) + [m['key'] for m in diffs.get('modified_registry_values', [])],
            'registry.value':             lambda: [str(v) for m in diffs.get('modified_registry_values', []) for v in m['new'].values()],
            # Process
            'process.image':              lambda: [p.get('image') for p in diffs.get('new_process_events', [])],
            'process.creation_commandline': lambda: [p.get('command_line') for p in diffs.get('new_process_events', [])],
            'process.parent_image':       lambda: [p.get('parent_image') for p in diffs.get('new_process_events', [])],
            'process.user':               lambda: [p.get('user') for p in diffs.get('new_process_events', [])],
            # DNS
            'dns.query_name':             lambda: [d.get('query_name') for d in diffs.get('new_dns_events', [])],
            # Network
            'network.destination_ip':     lambda: [n.get('destination_ip') for n in diffs.get('new_network_events', [])],
            'network.destination_port':   lambda: [str(n.get('destination_port')) for n in diffs.get('new_network_events', [])],
            'http.uri':                   lambda: [n.get('uri') for n in diffs.get('new_network_events', []) if 'uri' in n],
            'http.method':                lambda: diffs.get('http.method', []),
            'http.host':                  lambda: diffs.get('http.host', []),
            'http.user_agent':            lambda: [n.get('user_agent') for n in diffs.get('new_network_events', []) if 'user_agent' in n],
            'resp_mime_types':            lambda: diffs.get('resp_mime_types', []),
            'certificate.serial':         lambda: diffs.get('certificate.serial', []),
            'address':                    lambda: diffs.get('address', []),
            'id.orig_h':                  lambda: diffs.get('id.orig_h', []),
            'id.resp_h':                  lambda: diffs.get('id.resp_h', []),
            # EventLog - Expanded for korna.txt compatibility
            'eventlog.event_id':          lambda: [e.get('Event ID') for e in all_events],
            'eventlog.provider':          lambda: [e.get('Provider Name') for e in all_events],
            'eventlog.message':           lambda: [e.get('Message') for e in all_events],
            'eventlog.channel':           lambda: [e.get('Channel') for e in all_events],
            'eventlog.servicename':       lambda: [e.get('Service Name') for e in all_events],
            'eventlog.imagepath':         lambda: [e.get('Image Path') for e in all_events],
            'eventlog.hivename':          lambda: [e.get('HiveName') for e in all_events],
            'eventlog.taskname':          lambda: [e.get('TaskName') for e in all_events],
            'eventlog.accesslist':        lambda: [e.get('AccessList') for e in all_events],
            'eventlog.relativetargetname': lambda: [e.get('RelativeTargetName') for e in all_events],
            'eventlog.sharename':         lambda: [e.get('ShareName') for e in all_events],
            'eventlog.objectname':        lambda: [e.get('ObjectName') for e in all_events],
            'eventlog.objecttype':        lambda: [e.get('ObjectType') for e in all_events],
            'eventlog.processname':       lambda: [e.get('Process Name') for e in all_events],
            # Scheduled Tasks
            'taskcontent':                lambda: diffs.get('taskcontent', []),
            'taskcontentnew':             lambda: diffs.get('taskcontentnew', []),
        }

    def evaluate(self, diffs: Dict[str, Any]) -> bool:
        """
        Evaluates the rule with proper AND/OR logic.
        - Conditions for the same field are OR'd.
        - Groups of different fields are AND'd.
        """
        data_sources = self._get_data_sources(diffs)
        
        # Group conditions by their canonical field name
        grouped_conditions = defaultdict(list)
        for field, op, pattern in self.condition_lines:
            norm_field = field.lower().replace('_', '').replace('-', '')
            canonical_field = self.SIGMA_FIELD_MAP.get(norm_field, field.lower())
            grouped_conditions[canonical_field].append((op, pattern))

        if not grouped_conditions:
            return False

        # Iterate through each field group. All groups must have a match (AND logic).
        for canonical_field, conditions in grouped_conditions.items():
            source_func = data_sources.get(canonical_field)
            
            # If we don't know how to get data for this field, the condition can't be met.
            if not source_func:
                logging.debug(f"Rule '{self.name}' check failed: No data source for field '{canonical_field}'")
                return False
            
            items_to_check = [item for item in source_func() if item is not None]
            
            # If there's no data for this field, the condition group fails.
            if not items_to_check:
                logging.debug(f"Rule '{self.name}' check failed: No data items found for field '{canonical_field}'")
                return False

            # Check if ANY condition in this group matches (OR logic)
            group_matched = False
            for op, pattern in conditions:
                if any(self._check(str(item), op, pattern) for item in items_to_check):
                    group_matched = True
                    break  # One match is enough for this group
            
            if not group_matched:
                # If a single group doesn't find a match, the whole rule fails.
                return False

        # If all groups have found at least one match, the rule is triggered.
        logging.warning(f"✅ [ALERT] Rule '{self.name}' triggered. All condition groups matched.")
        return True

    def _check(self, text: str, op: str, pat: str) -> bool:
        """
        Enhanced check function. It automatically tries to match against plain,
        base64, and utf-16 string representations.
        """
        op = op.lower()
        pat_lower = pat.lower()
        
        representations = []
        # 1. Raw text
        representations.append(text.lower())
        # 2. Base64 decoded text
        try:
            # Attempt to decode, adding padding if necessary.
            padding_needed = len(text) % 4
            if padding_needed: text += '=' * (4 - padding_needed)
            decoded_b64 = base64.b64decode(text, validate=True).decode('utf-8', errors='ignore').lower()
            representations.append(decoded_b64)
        except (ValueError, TypeError, binascii.Error):
            pass # Not a valid base64 string
        # 3. UTF-16 ("wide") decoded text
        try:
            if '\x00' in text:
                representations.append(text.replace('\x00', '').lower())
        except Exception:
            pass

        for representation in representations:
            if op == 'contains':
                if pat_lower in representation: return True
            elif op in ('matches', 're'):
                try:
                    if re.search(pat, representation, re.IGNORECASE): return True
                except re.error: # Invalid regex in rule
                    if pat_lower in representation: return True # Fallback to contains
            elif op in ('equals', 'eq'):
                if representation == pat_lower: return True
            elif op == 'startswith':
                if representation.startswith(pat_lower): return True
            elif op == 'endswith':
                if representation.endswith(pat_lower): return True
        return False

class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules: List[Rule] = []
        self._load_rules(rules_dir)

    def get_scan_scopes(self) -> Dict[str, Set[str]]:
        fs_paths, reg_paths = set(), set()
        for rule in self.rules:
            for field, _, pat in rule.condition_lines:
                try:
                    exp_pat = os.path.expandvars(pat)
                    norm_field = field.lower().replace('_', '').replace('-', '')
                    canonical_field = Rule.SIGMA_FIELD_MAP.get(norm_field, field.lower())
                    
                    if canonical_field.startswith('file.'):
                        p = Path(exp_pat)
                        if p.is_absolute(): fs_paths.add(str(p.parent))
                    elif canonical_field.startswith('registry.'):
                        if '\\' in exp_pat and any(exp_pat.upper().startswith(h) for h in HIVE_MAP):
                            reg_paths.add(exp_pat.rsplit('\\', 1)[0])
                except Exception as e:
                    logging.debug(f"Could not parse scope from rule line '{field}': {e}")
        return {'filesystem': fs_paths, 'registry': reg_paths}

    def _load_rules(self, rules_dir: str):
        for file in os.listdir(rules_dir):
            # Only load .ohd rule files
            if file.lower().endswith('.ohd'):
                self._parse_rule_file(Path(rules_dir) / file)
        logging.info(f"[RuleEngine] Total rules loaded: {len(self.rules)}")

    def _parse_rule_file(self, filepath: Path):
        """
        Read a single .ohd rule file, normalize concatenated blocks,
        parse each rule into a Rule object, and append to self.rules.
        """
        logging.debug(f"[RuleEngine] Parsing rule file: {filepath}")
        try:
            # Read entire file and ensure each 'rule' starts on its own line
            raw_content = filepath.read_text(encoding='utf-8')
            normalized = raw_content.replace('}rule', '}\nrule')
            lines = normalized.splitlines()
        except Exception as e:
            logging.error(f"Failed to read rule file {filepath}: {e}")
            return

        current_rule = None
        mode = None
        awaiting_brace = False

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            # Skip empty lines and comments
            if not stripped or stripped.startswith(('#', '//')):
                continue

            # Detect start of rule block
            m = RULE_START_RE.match(stripped)
            if m and current_rule is None:
                rule_name = m.group(1)
                logging.debug(f"[RuleEngine] Found rule definition '{rule_name}' at line {idx}")
                current_rule = Rule(rule_name)
                # Determine if brace is on same line
                awaiting_brace = not stripped.endswith('{')
                mode = None
                continue

            # Skip a standalone '{' if awaiting it
            if awaiting_brace and stripped == '{':
                awaiting_brace = False
                continue

            # Enter meta section
            if current_rule and META_RE.match(stripped):
                mode = 'meta'
                logging.debug(f"[RuleEngine] Entering meta section at line {idx}")
                continue
            # Enter condition section
            if current_rule and COND_RE.match(stripped):
                mode = 'condition'
                logging.debug(f"[RuleEngine] Entering condition section at line {idx}")
                continue
            # End of rule block
            if current_rule and stripped == '}' and not awaiting_brace:
                logging.debug(f"[RuleEngine] Closing rule '{current_rule.name}' at line {idx}")
                self.rules.append(current_rule)
                current_rule = None
                mode = None
                continue

            # Inside meta: key = "value"
            if mode == 'meta' and current_rule:
                kv = KEYVAL_RE.match(stripped)
                if kv:
                    current_rule.meta[kv.group(1)] = kv.group(2)
                    logging.debug(
                        f"[RuleEngine] Parsed meta '{kv.group(1)}'='{kv.group(2)}' "
                        f"for rule '{current_rule.name}' at line {idx}"
                    )
            # Inside condition: field op "pattern"
            elif mode == 'condition' and current_rule:
                cond = COND_LINE_RE.match(stripped)
                if cond:
                    field, op, raw_pattern = cond.groups()
                    # Use safe normalization instead of unicode_escape decode
                    clean_pattern = normalize_pattern(raw_pattern)
                    current_rule.condition_lines.append((field, op, clean_pattern))
                    logging.debug(
                        f"[RuleEngine] Parsed condition {(field, op, clean_pattern)} "
                        f"for rule '{current_rule.name}' at line {idx}"
                    )

        # Handle unterminated rule at EOF
        if current_rule:
            logging.debug(f"[RuleEngine] Appending unterminated rule '{current_rule.name}' at EOF")
            self.rules.append(current_rule)

        # Normalize all condition patterns across rules
        for rule in self.rules:
            normalized_conditions = []
            for field, op, pattern in rule.condition_lines:
                try:
                    normalized_pattern = normalize_pattern(pattern)
                except Exception as e:
                    logging.warning(f"Failed to normalize pattern '{pattern}' in rule '{rule.name}': {e}")
                    normalized_pattern = pattern
                normalized_conditions.append((field, op, normalized_pattern))
            rule.condition_lines = normalized_conditions

# -------------------------------------------------------------------
# 6) MAIN WORKFLOW
# -------------------------------------------------------------------

def process_sample(sample_path: str, rules_dir: str, timeout: int) -> List[str]:
    engine = RuleEngine(rules_dir)
    if not engine.rules:
        logging.error(f"No rules were loaded from '{rules_dir}'. Aborting scan.")
        return []
        
    scopes = engine.get_scan_scopes()
    # Scopes are now determined only by rule content.
    fs_roots = list(scopes['filesystem'])
    reg_roots = list(scopes['registry'])

    logging.info(f"Rule-driven FS roots: {fs_roots}")
    logging.info(f"Rule-driven Registry roots: {reg_roots}")
    
    snap_before = Snapshot(fs_roots=fs_roots, reg_roots=reg_roots)
    snap_before.capture()

    snap_during = Snapshot()
    sniff_thread = threading.Thread(target=snap_during.capture_network, args=(timeout,), daemon=True)
    sniff_thread.start()

    proc = None
    try:
        proc = subprocess.Popen([sample_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info(f"[Run] Executing sample: {sample_path} (PID: {proc.pid})")
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if proc: proc.kill()
        logging.warning("[Run] Sample timed out and was terminated.")
    except Exception as e:
        logging.exception(f"[Run] Failed to launch sample: {e}")
        sniff_thread.join()
        return []
    
    sniff_thread.join()

    snap_after = Snapshot(fs_roots=fs_roots, reg_roots=reg_roots)
    snap_after.capture()
    # Merge network/DNS data captured during execution
    snap_after.network_events = snap_during.network_events
    snap_after.dns_events = snap_during.dns_events
    
    diffs = snap_after.diff(snap_before)

    # --- New: extract & include PE certificate serial under diffs['certificate.serial'] ---
    cs = get_certificate_serial(sample_path)
    if cs:
        # store as a list to match the engine’s expectations for iterable fields
        diffs['certificate.serial'] = [cs]

    # Inject resp_mime_types
    diffs['resp_mime_types'] = extract_resp_mime_types(sample_path)

    # Inject HTTP fields
    diffs['http.method'] = extract_http_fields(diffs, 'method')
    diffs['http.uri']    = extract_http_fields(diffs, 'uri')
    diffs['http.host']   = extract_http_fields(diffs, 'host')

    # Inject network addresses
    diffs['address']     = extract_address(diffs)
    diffs['id.orig_h']   = extract_id_orig_h(diffs)
    diffs['id.resp_h']   = extract_id_resp_h(diffs)

    # Inject event log fields
    for fld in ('Description','Caption','State','Operation',
                'SubjectUserName','DeviceName','AuditSourceName'):
        key = fld.lower()
        diffs[key] = extract_eventlog_field(diffs, fld)

    # Inject scheduled task content
    diffs['taskcontent']    = extract_scheduled_tasks(diffs, 'TaskContent')
    diffs['taskcontentnew'] = extract_scheduled_tasks(diffs, 'NewTaskContent')

    # Finally, evaluate every rule against these enriched diffs
    return [
        rule.name
        for rule in engine.rules
        if rule.evaluate(diffs)
    ]

def process_sample_with_engine(sample_path: str, engine: RuleEngine, timeout: int) -> List[str]:
    """Refactored processing logic to accept a pre-loaded RuleEngine."""
    scopes = engine.get_scan_scopes()
    # Scopes are now determined only by rule content.
    fs_roots = list(scopes['filesystem'])
    reg_roots = list(scopes['registry'])

    logging.info(f"Rule-driven FS roots: {fs_roots}")
    logging.info(f"Rule-driven Registry roots: {reg_roots}")
    
    snap_before = Snapshot(fs_roots=fs_roots, reg_roots=reg_roots)
    snap_before.capture()

    snap_during = Snapshot()
    sniff_thread = threading.Thread(target=snap_during.capture_network, args=(timeout,), daemon=True)
    sniff_thread.start()

    proc = None
    try:
        proc = subprocess.Popen([sample_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info(f"[Run] Executing sample: {sample_path} (PID: {proc.pid})")
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if proc: proc.kill()
        logging.warning("[Run] Sample timed out and was terminated.")
    except Exception as e:
        logging.exception(f"[Run] Failed to launch sample: {e}")
        sniff_thread.join()
        return []
    
    sniff_thread.join()

    snap_after = Snapshot(fs_roots=fs_roots, reg_roots=reg_roots)
    snap_after.capture()
    snap_after.network_events = snap_during.network_events
    snap_after.dns_events = snap_during.dns_events
    
    diffs = snap_after.diff(snap_before)
    
    return [rule.name for rule in engine.rules if rule.evaluate(diffs)]

def main():
    if len(sys.argv) < 3:
        logging.error("Usage: python OpenHydraDragon.py <sample_or_dir> <rules_dir>")
        sys.exit(1)

    target, rules_dir = sys.argv[1], sys.argv[2]
    samples = []

    if os.path.isdir(target):
        # Recursively include every file under the target directory
        for root, _, files in os.walk(target):
            for fname in files:
                samples.append(os.path.join(root, fname))
    else:
        # Single file target: include it directly if it exists
        if os.path.isfile(target):
            samples.append(target)
        else:
            logging.error(f"Target '{target}' is not a directory or file.")
            sys.exit(1)

    if not samples:
        logging.error(f"No samples found in '{target}'")
        sys.exit(1)

    # Load rules once before processing samples
    engine = RuleEngine(rules_dir)
    if not engine.rules:
        logging.error(f"No rules were loaded from '{rules_dir}'. Aborting.")
        sys.exit(1)

    for sample in samples:
        logging.info(f"=== Processing Sample: {sample} ===")
        try:
            matched_rules = process_sample_with_engine(sample, engine, timeout=60)
            if matched_rules:
                logging.warning(f"🚨 [ALERT] Sample '{Path(sample).name}' matched rules: {matched_rules}")
            else:
                logging.info(f"✔️ [Result] No rules matched for '{Path(sample).name}'")
        except Exception as e:
            logging.exception(f"Error processing sample '{sample}': {e}")

    logging.info("=== OpenHydraDragon Run Completed ===")

if __name__ == "__main__":
    main()
