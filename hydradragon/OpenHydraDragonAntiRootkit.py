#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HydraDragonAntivirus Unified Scanner with Enhanced Detection
- Signature via WinVerifyTrust (ctypes)
- DIE analysis for hidden+unsigned files to detect PE, then PE heuristics
- Parallel scanning (ThreadPoolExecutor)
- Enhanced detection: timing, memory (fixed), network, filesystem, registry timestamps, process hollowing (disabled), boot config
- Outputs suspicious indicators + enhanced results + risk assessment as JSON
- Includes desktop notifications for detections.
- Scans registry for network indicators (IPs, Domains, URLs) and saves to a separate report.
"""

import os
import sys
import logging
import json
import subprocess
import ctypes
from ctypes import wintypes
import winreg
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import pefile
import psutil
import wmi
import win32api
import win32con
import win32security
from notifypy import Notify
import re


# Set script directory
script_dir = os.getcwd()

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Separate log files for different purposes
stdout_console_log_file = os.path.join(
    log_directory, "DONTREMOVEantivirusconsolestdout.log"
)
stderr_console_log_file = os.path.join(
    log_directory, "DONTREMOVEantivirusconsolestderr.log"
)
application_log_file = os.path.join(
    log_directory, "DONTREMOVEantivirus.log"
)

# Configure logging for application log
logging.basicConfig(
    filename=application_log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Redirect stdout to stdout console log
sys.stdout = open(
    stdout_console_log_file, "w", encoding="utf-8", errors="ignore"
)

# Redirect stderr to stderr console log
sys.stderr = open(
    stderr_console_log_file, "w", encoding="utf-8", errors="ignore"
)

# Logging for application initialization
logging.info(
    "Application started at %s",
    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
)

# ========== CONFIGURATION ==========
CWD              = Path(os.getcwd())
DETECTIEASY_PATH = CWD / "detectiteasy" / "diec.exe"
DIE_OUTPUT_DIR   = CWD / "die_outputs"
REPORTS_DIR      = CWD / "reports"
ANTIVIRUS_PROCESS_LIST_PATH = CWD / "known_extensions" / "antivirusprocesslist.txt"

# Read antivirus process list from antivirusprocesslist.txt with try-except
antivirus_process_list = []
try:
    if os.path.exists(ANTIVIRUS_PROCESS_LIST_PATH):
        with open(ANTIVIRUS_PROCESS_LIST_PATH, 'r', encoding='utf-8', errors='ignore') as av_file:
            antivirus_process_list = [line.strip() for line in av_file if line.strip()]
except Exception as ex:
    logging.info(f"Error reading {ANTIVIRUS_PROCESS_LIST_PATH}: {ex}")

logging.info(f"Antivirus process list read from {ANTIVIRUS_PROCESS_LIST_PATH}: {antivirus_process_list}")


SYSTEM_DIRS      = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32\drivers"
]
REGION_KEYS      = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
]
MAX_WORKERS = min(32, (os.cpu_count() or 1) * 2)

# ========== NOTIFICATION FUNCTION ==========
def notify_user_for_rootkit(file_path, virus_name):
    """
    Sends a notification about rootkit behaviour detected.
    """
    try:
        notification = Notify()
        notification.title = f"Rootkit detected: {virus_name}"
        notification_message = f"Suspicious rootkit behaviour detected in: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        notification.send()
        logging.error(notification_message) # Also log it as an error for record-keeping
    except Exception as e:
        logging.error(f"Failed to send notification: {e}")

# ========== WinVerifyTrust SETUP ==========
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)
class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]
class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]
WTD_UI_NONE           = 2
WTD_REVOKE_NONE       = 0
WTD_CHOICE_FILE       = 1
WTD_STATEACTION_IGNORE = 0x00000000
_wintrust = ctypes.windll.wintrust

def verify_authenticode_signature(file_path: str) -> bool:
    """
    Returns True if signature is valid per WinVerifyTrust, False otherwise.
    """
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
    wtd = WINTRUST_DATA()
    ctypes.memset(ctypes.byref(wtd), 0, ctypes.sizeof(wtd))
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = WTD_UI_NONE
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE
    wtd.dwUnionChoice = WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(file_info)
    wtd.dwStateAction = WTD_STATEACTION_IGNORE
    result = _wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))
    return result == 0  # ERROR_SUCCESS

# ========== HELPER FUNCTIONS ==========
def generate_detection_name(detection_type: str, details: str) -> str:
    """Generates a standardized detection name."""
    sanitized_details = ''.join(c for c in details if c.isalnum() or c in ('-', '_')).capitalize()
    return f"HEUR:Win32.Susp.Rootkit.{detection_type}.{sanitized_details}.gen"

def get_unique_output_path(output_dir: Path, base_name: Path) -> Path:
    candidate = output_dir / base_name.name
    counter = 1
    while candidate.exists():
        candidate = output_dir / f"{base_name.stem}_{counter}{base_name.suffix}"
        counter += 1
    return candidate

def is_hidden_file(path: Path) -> bool:
    FILE_ATTRIBUTE_HIDDEN = 0x2
    FILE_ATTRIBUTE_SYSTEM = 0x4
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == -1:
            return False
        return bool(attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
    except Exception:
        return False

def check_valid_signature(file_path: str) -> dict:
    """
    Use WinVerifyTrust instead of PowerShell.
    Returns {"is_valid": bool, "status": str}.
    """
    try:
        is_valid = verify_authenticode_signature(file_path)
        status = "Valid" if is_valid else "Invalid or no signature"
        return {"is_valid": is_valid, "status": status}
    except Exception as ex:
        logging.error(f"[Signature] {file_path}: {ex}")
        return {"is_valid": False, "status": str(ex)}

def analyze_file_with_die(file_path: str, die_path: Path, die_output_dir: Path) -> str:
    """
    Run DIE once (-p) and save output under die_output_dir; return stdout.
    """
    try:
        die_output_dir.mkdir(parents=True, exist_ok=True)
        stub = Path(file_path).with_suffix(".txt").name
        outpath = get_unique_output_path(die_output_dir, Path(stub))
        result = subprocess.run(
            [str(die_path), "-p", file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="ignore"
        )
        with open(outpath, "w", encoding="utf-8", errors="ignore") as f:
            f.write(result.stdout)
        logging.info(f"[DIE] {file_path} → {outpath}")
        return result.stdout
    except Exception as ex:
        logging.error(f"[DIE] error for {file_path}: {ex}")
        return ""

def is_pe_file_from_output(die_output: str) -> bool:
    return bool(die_output and ("PE32" in die_output or "PE64" in die_output))

def pe_heuristic_analysis(path: str) -> dict:
    """
    Simple PE heuristics: section entropy and imports via pefile.
    """
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        entropy_list = []
        for sec in pe.sections:
            try:
                name = sec.Name.decode(errors='ignore').strip('\x00')
            except:
                name = str(sec.Name)
            entropy_list.append({"section": name, "entropy": sec.get_entropy()})
        imports = [imp.dll.decode(errors='ignore') for imp in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])]
        return {"entropy": entropy_list, "imports": imports}
    except Exception as ex:
        logging.debug(f"[PE] {path}: {ex}")
        return {}

# ========== SCANNING FUNCTIONS ==========
def process_file(fp: Path) -> dict:
    """
    Process a single file to check for suspicious indicators.
    """
    rec = {"path": str(fp)}
    try:
        # A file is suspicious if it's hidden AND has an invalid signature.
        h = is_hidden_file(fp)
        sig = check_valid_signature(str(fp))
        if not (h and not sig["is_valid"]):
            return {} # Not suspicious, skip further analysis

        # If DIE is not available, we can't do PE analysis.
        if not DETECTIEASY_PATH.exists():
            return {}

        # Run DIE to determine if the file is a PE file.
        die_out = analyze_file_with_die(str(fp), DETECTIEASY_PATH, DIE_OUTPUT_DIR)
        if not is_pe_file_from_output(die_out):
            return {} # Not a PE file, nothing more to do.

        # Perform heuristic analysis on the PE file.
        heur = pe_heuristic_analysis(str(fp))
        rec.update({
            "detection_name": generate_detection_name("File", "HiddenUnsigned"),
            "hidden_attr": h,
            "signature_status": sig["status"],
            "die_output_snippet": die_out[:500],
            "pe_heuristics": heur
        })
        return rec
    except Exception as ex:
        logging.error(f"[File] error for {fp}: {ex}")
        return {"path": str(fp), "error": str(ex)}

def scan_files_parallel() -> list[dict]:
    findings = []
    paths = []
    for dir_path in SYSTEM_DIRS:
        root = Path(dir_path)
        if not root.exists():
            logging.warning(f"[Scan] Dir not found: {dir_path}")
            continue
        for fp in root.rglob("*"):
            if fp.is_file():
                paths.append(fp)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_path = {executor.submit(process_file, fp): fp for fp in paths}
        for fut in as_completed(future_to_path):
            rec = fut.result()
            if rec:
                findings.append(rec)
    return findings

def process_driver(svc) -> dict:
    path = svc.PathName.strip('"') if svc.PathName else None
    if not path or not Path(path.split()[0]).exists():
        return {}
    p = Path(path.split()[0])
    try:
        h = is_hidden_file(p)
        sig = check_valid_signature(str(p))
        if not (h and not sig["is_valid"]):
            return {}
        if not DETECTIEASY_PATH.exists():
            return {}
        die_out = analyze_file_with_die(str(p), DETECTIEASY_PATH, DIE_OUTPUT_DIR)
        if not is_pe_file_from_output(die_out):
            return {}
        heur = pe_heuristic_analysis(str(p))
        return {
            "detection_name": generate_detection_name("Driver", "HiddenUnsigned"),
            "name": svc.Name,
            "display_name": svc.DisplayName,
            "state": svc.State,
            "start_mode": svc.StartMode,
            "path": str(p),
            "die_output_snippet": die_out[:500],
            "pe_heuristics": heur
        }
    except Exception as ex:
        logging.error(f"[Driver] error for {path}: {ex}")
        return {"path": path, "error": str(ex)}

def scan_drivers_parallel() -> list[dict]:
    findings = []
    try:
        c = wmi.WMI()
        svcs = list(c.Win32_SystemDriver())
    except Exception as ex:
        logging.error(f"[Drivers] WMI query failed: {ex}")
        return findings
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_svc = {executor.submit(process_driver, svc): svc for svc in svcs}
        for fut in as_completed(future_to_svc):
            rec = fut.result()
            if rec:
                findings.append(rec)
    return findings

def analyze_process(pinfo: dict) -> dict:
    exe = pinfo.get('exe')
    if not exe:
        return {}
    try:
        h = is_hidden_file(Path(exe))
        sig = check_valid_signature(exe)
        if not (h and not sig["is_valid"]):
            return {}
        if not DETECTIEASY_PATH.exists():
            return {}
        die_out = analyze_file_with_die(exe, DETECTIEASY_PATH, DIE_OUTPUT_DIR)
        if not is_pe_file_from_output(die_out):
            return {}
        heur = pe_heuristic_analysis(exe)
        return {
            "detection_name": generate_detection_name("Process", "HiddenUnsigned"),
            "pid": pinfo['pid'], "name": pinfo['name'], "exe": exe,
            "die_output_snippet": die_out[:500], "pe_heuristics": heur
        }
    except Exception as ex:
        logging.error(f"[Process] error for {exe}: {ex}")
        return {"pid": pinfo.get('pid'), "exe": exe, "error": str(ex)}

def scan_processes_parallel() -> dict:
    try:
        ps_list = [p.info for p in psutil.process_iter(['pid','name','exe']) if p.info.get('exe')]
    except Exception:
        ps_list = []
    try:
        wmi_list = []
        c = wmi.WMI()
        for p in c.Win32_Process():
            wmi_list.append({"pid": int(p.ProcessId), "name": p.Name, "exe": p.ExecutablePath})
    except Exception:
        wmi_list = []
    cross = {
        "only_psutil": [{"pid":pid,"exe":exe} for pid,exe in {(p['pid'],p['exe']) for p in ps_list} - {(p['pid'],p['exe']) for p in wmi_list}],
        "only_wmi":    [{"pid":pid,"exe":exe} for pid,exe in {(p['pid'],p['exe']) for p in wmi_list} - {(p['pid'],p['exe']) for p in ps_list}]
    }
    cross_ret = cross if cross["only_psutil"] or cross["only_wmi"] else {}
    findings = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proc = {executor.submit(analyze_process, pinfo): pinfo for pinfo in ps_list}
        for fut in as_completed(future_to_proc):
            rec = fut.result()
            if rec:
                findings.append(rec)
    return {"cross_check": cross_ret, "suspicious_processes": findings}

def analyze_registry_acl_item(item: tuple) -> dict:
    root, subkey_path = item
    try:
        handle = win32api.RegOpenKeyEx(root, subkey_path, 0, win32con.KEY_READ | win32con.KEY_WOW64_64KEY)
    except PermissionError:
        return {"detection_name": generate_detection_name("Registry", "HiddenKey"), "root": str(root), "subkey": subkey_path, "hidden_key": True}
    except Exception:
        return {}
    try:
        sd = win32security.GetSecurityInfo(
            handle,
            win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        owner_sid = sd.GetSecurityDescriptorOwner()
        try:
            owner_name, _, _ = win32security.LookupAccountSid(None, owner_sid)
        except:
            owner_name = str(owner_sid)
        issues = []
        if owner_name not in ("Administrators", "SYSTEM"):
            issues.append(f"owner unexpected: {owner_name}")
        everyone_sid = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)
        users_sid    = win32security.CreateWellKnownSid(win32security.WinBuiltinUsersSid, None)
        if dacl:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                access_mask = ace[2]
                sid = ace[3]
                try:
                    name, _, _ = win32security.LookupAccountSid(None, sid)
                except:
                    name = str(sid)
                if sid == everyone_sid or sid == users_sid:
                    if access_mask & win32con.KEY_ALL_ACCESS or access_mask & win32con.GENERIC_ALL:
                        issues.append(f"{name} has full control")
        if issues:
            return {"detection_name": generate_detection_name("Registry", "ACL"), "root": str(root), "subkey": subkey_path, "acl_issues": issues}
    except Exception:
        return {}
    finally:
        win32api.RegCloseKey(handle)
    return {}

def scan_registry_acl_parallel() -> list[dict]:
    items = []
    for root, sub in REGION_KEYS:
        items.append((root, sub))
        try:
            with winreg.OpenKey(root, sub) as key:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, i)
                        items.append((root, sub + "\\" + name))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
    findings = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_item = {executor.submit(analyze_registry_acl_item, item): item for item in items}
        for fut in as_completed(future_to_item):
            rec = fut.result()
            if rec:
                findings.append(rec)
    return findings

def scan_autorun_registry() -> list[dict]:
    out = []
    for root, sub in REGION_KEYS:
        try:
            with winreg.OpenKey(root, sub) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        exe = None
                        if '"' in val:
                            parts = val.split('"')
                            if len(parts) >= 2:
                                exe = parts[1]
                        else:
                            first = val.split()[0] if val else ""
                            if first.lower().endswith((".exe", ".sys")):
                                exe = first
                        if exe and Path(exe).exists():
                            h = is_hidden_file(Path(exe))
                            sig = check_valid_signature(exe)
                            if not (h and not sig["is_valid"]):
                                i += 1
                                continue
                            if not DETECTIEASY_PATH.exists():
                                i += 1
                                continue
                            die_out = analyze_file_with_die(exe, DETECTIEASY_PATH, DIE_OUTPUT_DIR)
                            if not is_pe_file_from_output(die_out):
                                i += 1
                                continue
                            heur = pe_heuristic_analysis(exe)
                            out.append({
                                "detection_name": generate_detection_name("Autorun", "HiddenUnsigned"),
                                "reg_root": str(root),
                                "reg_path": sub,
                                "value_name": name,
                                "exe": exe,
                                "die_output_snippet": die_out[:500],
                                "pe_heuristics": heur
                            })
                        i += 1
                    except OSError:
                        break
        except Exception:
            continue
    return out

def scan_ifeo_antivirus_blocking() -> list[dict]:
    """
    Scan Image File Execution Options registry for antivirus process blocking.
    Detects IFEO entries that may prevent antivirus software from running.
    """
    findings = []
    
    ifeo_key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_key_path) as ifeo_key:
            i = 0
            while True:
                try:
                    # Get each subkey name (executable name)
                    exe_name = winreg.EnumKey(ifeo_key, i)
                    
                    # Check if this executable name matches any antivirus process
                    if exe_name.lower() in [av.lower() for av in antivirus_process_list]:
                        try:
                            # Open the specific executable's IFEO subkey
                            with winreg.OpenKey(ifeo_key, exe_name) as exe_key:
                                # Check for suspicious values that could block execution
                                suspicious_values = {}
                                
                                try:
                                    # Check for Debugger value (most common blocking method)
                                    debugger_value, _ = winreg.QueryValueEx(exe_key, "Debugger")
                                    suspicious_values["Debugger"] = debugger_value
                                except FileNotFoundError:
                                    pass
                                
                                try:
                                    # Check for DisableExceptionChainValidation
                                    disable_exc_chain, _ = winreg.QueryValueEx(exe_key, "DisableExceptionChainValidation")
                                    suspicious_values["DisableExceptionChainValidation"] = disable_exc_chain
                                except FileNotFoundError:
                                    pass
                                
                                try:
                                    # Check for other suspicious values
                                    disable_heap_coalesce, _ = winreg.QueryValueEx(exe_key, "DisableHeapCoalesce")
                                    suspicious_values["DisableHeapCoalesce"] = disable_heap_coalesce
                                except FileNotFoundError:
                                    pass
                                
                                # If any suspicious values found, report it
                                if suspicious_values:
                                    findings.append({
                                        "detection_name": generate_detection_name("FileBlocker", exe_name.replace('.exe', '')),
                                        "blocked_process": exe_name,
                                        "ifeo_path": f"{ifeo_key_path}\\{exe_name}",
                                        "suspicious_values": suspicious_values,
                                        "description": f"IFEO entry may be blocking antivirus process: {exe_name}",
                                        "risk": "HIGH" if "Debugger" in suspicious_values else "MEDIUM"
                                    })
                                    
                        except Exception as e:
                            logging.debug(f"Error checking IFEO subkey {exe_name}: {e}")
                    
                    i += 1
                except OSError:
                    # No more subkeys
                    break
                    
    except Exception as e:
        logging.error(f"Error scanning IFEO registry: {e}")
    
    return findings

def scan_registry_for_network_indicators() -> list[dict]:
    """
    Scans the entire registry for network indicators like IPs, domains, and URLs.
    This is a heavy operation and may take time.
    """
    findings = []
    # Regex patterns for network indicators
    patterns = {
        "IPv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "IPv6": r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',
        "URL": r'(?:https?|ftp|file)://[^\s"\']+',
        "Domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b'
    }
    
    compiled_patterns = {name: re.compile(pattern) for name, pattern in patterns.items()}

    # A set to keep track of found indicators to avoid duplicates in the report
    found_indicators = set()

    def _scan_key(hkey, subkey_path, hkey_name):
        full_key_path = f"{hkey_name}\\{subkey_path}"
        try:
            # Open key with 64-bit view access
            with winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                # Scan values in the current key
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        if value_type == winreg.REG_SZ or value_type == winreg.REG_EXPAND_SZ:
                            if isinstance(value_data, str):
                                for name, pattern in compiled_patterns.items():
                                    for match in pattern.finditer(value_data):
                                        indicator = match.group(0)
                                        # Avoid adding duplicate domains found by URL regex
                                        if name == 'Domain' and any(indicator in url for url in re.findall(compiled_patterns['URL'], value_data)):
                                            continue
                                        
                                        unique_indicator_tuple = (full_key_path, value_name, indicator, name)
                                        if unique_indicator_tuple not in found_indicators:
                                            findings.append({
                                                "detection_name": generate_detection_name("Registry", f"NetworkIndicator-{name}"),
                                                "key_path": full_key_path,
                                                "value_name": value_name,
                                                "indicator": indicator,
                                                "indicator_type": name
                                            })
                                            found_indicators.add(unique_indicator_tuple)
                        i += 1
                    except OSError:
                        break  # No more values
                
                # Recursively scan subkeys
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        _scan_key(hkey, os.path.join(subkey_path, subkey_name), hkey_name)
                        i += 1
                    except OSError:
                        break # No more subkeys
        except (PermissionError, FileNotFoundError):
            pass # Skip keys we can't access
        except Exception as e:
            logging.debug(f"Error scanning registry key {full_key_path}: {e}")

    # List of root keys to start scanning from
    root_keys_to_scan = [
        (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
        (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
        (winreg.HKEY_USERS, "HKEY_USERS"),
        (winreg.HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
    ]

    logging.info("Starting full registry scan for network indicators...")
    for hkey, hkey_name in root_keys_to_scan:
        _scan_key(hkey, "", hkey_name)
    logging.info(f"Finished full registry scan. Found {len(findings)} indicators.")
    
    return findings

# ========== ENHANCED DETECTION CLASSES ==========
class TimingBasedDetection:
    @staticmethod
    def detect_hooking_via_timing():
        findings = []
        test_apis = ['CreateFileW', 'ReadFile', 'WriteFile', 'RegOpenKeyW', 'RegQueryValueW', 'OpenProcess', 'CreateProcessW']
        for api_name in test_apis:
            try:
                times = []
                for _ in range(50):
                    start = time.perf_counter()
                    if api_name == 'CreateFileW':
                        handle = ctypes.windll.kernel32.CreateFileW("nul", 0x80000000, 0, None, 3, 0, None)
                        if handle != -1:
                            ctypes.windll.kernel32.CloseHandle(handle)
                    elif api_name == 'ReadFile':
                        buf = ctypes.create_string_buffer(1)
                        handle = ctypes.windll.kernel32.CreateFileW("nul", 0x80000000, 0, None, 3, 0, None)
                        if handle != -1:
                            ctypes.windll.kernel32.ReadFile(handle, buf, 0, ctypes.byref(ctypes.c_ulong()), None)
                            ctypes.windll.kernel32.CloseHandle(handle)
                    # other APIs could be added if needed...
                    end = time.perf_counter()
                    times.append(end - start)
                avg_time = sum(times) / len(times)
                variance = sum((t - avg_time) ** 2 for t in times) / len(times)
                if variance > avg_time * 0.5:
                    findings.append({
                        'detection_name': generate_detection_name("Hook", "TimingVariance"),
                        'api': api_name,
                        'avg_time': avg_time,
                        'variance': variance,
                        'suspicion': 'High timing variance - possible hooking'
                    })
            except Exception as e:
                logging.debug(f"Timing test failed for {api_name}: {e}")
        return findings

class MemoryAnomalyDetection:
    @staticmethod
    def scan_memory_regions():
        findings = []
        try:
            kernel32 = ctypes.windll.kernel32
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]
            address = 0
            max_address = 0x7FFFFFFF
            while address < max_address:
                mbi = MEMORY_BASIC_INFORMATION()
                result = kernel32.VirtualQuery(
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi)
                )
                if result == 0:
                    break
                base = mbi.BaseAddress
                size = mbi.RegionSize
                if not base or not size:
                    break
                PAGE_EXECUTE = 0x10
                PAGE_EXECUTE_READ = 0x20
                PAGE_EXECUTE_READWRITE = 0x40
                MEM_PRIVATE = 0x20000
                if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
                        and mbi.Type == MEM_PRIVATE):
                    findings.append({
                        'detection_name': generate_detection_name("Memory", "ExecPrivate"),
                        'base_address': hex(base),
                        'size': size,
                        'protection': hex(mbi.Protect),
                        'type': 'Suspicious executable private memory'
                    })
                next_addr = base + size
                if next_addr <= address:
                    break
                address = next_addr
        except Exception as e:
            logging.error(f"Memory scan failed: {e}")
        return findings

class NetworkAnomalyDetection:
    @staticmethod
    def detect_hidden_network_connections():
        findings = []
        try:
            netstat_result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True, encoding="utf-8", errors="ignore",
                timeout=30
            )
            netstat_connections = set()
            for line in netstat_result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        netstat_connections.add(parts[1])
            # fallback wmi not used for per-connection here
            wmi_connections = netstat_connections
            hidden_connections = netstat_connections - wmi_connections
            if hidden_connections:
                findings.append({
                    'detection_name': generate_detection_name("Network", "HiddenConnection"),
                    'type': 'Hidden network connections',
                    'connections': list(hidden_connections)
                })
        except Exception as e:
            logging.error(f"Network detection failed: {e}")
        return findings

class FileSystemAnomalyDetection:
    @staticmethod
    def detect_file_redirection():
        findings = []
        test_files = [r'C:\Windows\System32\notepad.exe', r'C:\Windows\System32\calc.exe', r'C:\Windows\System32\cmd.exe']
        for file_path in test_files:
            try:
                path_obj = Path(file_path)
                stat1 = path_obj.stat()
                size1 = stat1.st_size
                handle = ctypes.windll.kernel32.CreateFileW(file_path, 0x80000000, 1, None, 3, 0, None)
                if handle != -1:
                    size2 = ctypes.windll.kernel32.GetFileSize(handle, None)
                    ctypes.windll.kernel32.CloseHandle(handle)
                else:
                    continue
                if abs(size1 - size2) > 0:
                    findings.append({
                        'detection_name': generate_detection_name("FS", "FileRedirection"),
                        'file': file_path,
                        'size_method1': size1,
                        'size_method2': size2,
                        'suspicion': 'File size mismatch - possible redirection'
                    })
            except Exception as e:
                logging.debug(f"File redirection test failed for {file_path}: {e}")
        return findings

    @staticmethod
    def detect_ads_streams():
        findings = []
        critical_dirs = [r'C:\Windows\System32', r'C:\Windows\SysWOW64',
                         r'C:\Program Files', r'C:\Program Files (x86)']
        for dir_path in critical_dirs:
            try:
                for root_dir, dirs, files in os.walk(dir_path):
                    for file in files[:50]:
                        file_path = os.path.join(root_dir, file)
                        try:
                            result = subprocess.run(
                                ['cmd', '/c', 'dir', '/r', file_path],
                                capture_output=True,
                                text=True, encoding="utf-8", errors="ignore",
                                timeout=5
                            )
                            if ':$DATA' in result.stdout:
                                for line in result.stdout.split('\n'):
                                    if ':$DATA' in line and file not in line:
                                        findings.append({
                                            'detection_name': generate_detection_name("FS", "ADS"),
                                            'file': file_path,
                                            'ads_info': line.strip(),
                                            'type': 'Alternate Data Stream detected'
                                        })
                        except:
                            continue
                    break
            except Exception as e:
                logging.debug(f"ADS scan failed for {dir_path}: {e}")
        return findings

class RegistryAnomalyDetection:
    @staticmethod
    def detect_registry_timestamp_anomalies():
        findings = []
        suspicious_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ]
        for hkey, key_path in suspicious_keys:
            try:
                with winreg.OpenKey(hkey, key_path) as key:
                    num_subkeys, num_values, last_modified = winreg.QueryInfoKey(key)
                    current_time = time.time()
                    if current_time - last_modified < 3600:
                        findings.append({
                            'detection_name': generate_detection_name("Registry", "RecentTimestamp"),
                            'key': f"{hkey}\\{key_path}",
                            'last_modified': time.ctime(last_modified),
                            'suspicion': 'Recently modified critical registry key'
                        })
            except Exception as e:
                logging.debug(f"Registry timestamp check failed for {key_path}: {e}")
        return findings

class BootKitDetection:
    @staticmethod
    def check_boot_configuration():
        findings = []
        try:
            result = subprocess.run(
                ['bcdedit', '/enum', 'all'],
                capture_output=True,
                text=True, encoding="utf-8", errors="ignore",
                timeout=30
            )
            suspicious_patterns = ['loadoptions']
            for line in result.stdout.split('\n'):
                for pattern in suspicious_patterns:
                    if pattern.lower() in line.lower():
                        detection_name = generate_detection_name("Boot", pattern)
                        findings.append({
                            'detection_name': detection_name,
                            'type': 'Suspicious boot configuration',
                            'line': line.strip(),
                            'pattern': pattern
                        })
        except Exception as e:
            logging.debug(f"Boot configuration check failed: {e}")
        return findings

def run_enhanced_detection():
    results = {}

    # Each block now calls the detection method, then immediately iterates and notifies.
    try:
        timing_anomalies = TimingBasedDetection.detect_hooking_via_timing()
        for finding in timing_anomalies:
            notify_user_for_rootkit(finding.get('api', 'N/A'), finding.get('detection_name', 'UnknownTiming'))
        results['timing_anomalies'] = timing_anomalies
    except Exception as e:
        logging.error(f"Timing detection failed: {e}")

    try:
        memory_anomalies = MemoryAnomalyDetection.scan_memory_regions()
        for finding in memory_anomalies:
            notify_user_for_rootkit(finding.get('base_address', 'N/A'), finding.get('detection_name', 'UnknownMemory'))
        results['memory_anomalies'] = memory_anomalies
    except Exception as e:
        logging.error(f"Memory detection failed: {e}")

    try:
        network_anomalies = NetworkAnomalyDetection.detect_hidden_network_connections()
        for finding in network_anomalies:
            notify_user_for_rootkit('System Network State', finding.get('detection_name', 'UnknownNetwork'))
        results['network_anomalies'] = network_anomalies
    except Exception as e:
        logging.error(f"Network detection failed: {e}")

    try:
        file_redirection = FileSystemAnomalyDetection.detect_file_redirection()
        for finding in file_redirection:
            notify_user_for_rootkit(finding.get('file', 'N/A'), finding.get('detection_name', 'UnknownFS'))
        results['file_redirection'] = file_redirection

        ads_streams = FileSystemAnomalyDetection.detect_ads_streams()
        for finding in ads_streams:
            notify_user_for_rootkit(finding.get('file', 'N/A'), finding.get('detection_name', 'UnknownADS'))
        results['ads_streams'] = ads_streams
    except Exception as e:
        logging.error(f"Filesystem detection failed: {e}")

    try:
        registry_timestamp_anomalies = RegistryAnomalyDetection.detect_registry_timestamp_anomalies()
        for finding in registry_timestamp_anomalies:
            notify_user_for_rootkit(finding.get('key', 'N/A'), finding.get('detection_name', 'UnknownRegistryTimestamp'))
        results['registry_timestamp_anomalies'] = registry_timestamp_anomalies
    except Exception as e:
        logging.error(f"Registry detection failed: {e}")

    try:
        boot_anomalies = BootKitDetection.check_boot_configuration()
        for finding in boot_anomalies:
            notify_user_for_rootkit(finding.get('pattern', 'N/A'), finding.get('detection_name', 'UnknownBoot'))
        results['boot_anomalies'] = boot_anomalies
    except Exception as e:
        logging.error(f"Boot detection failed: {e}")

    return results

def check_file_deleted_from_sandbox() -> dict:
    """
    Checks if file was deleted from sandbox using anti-self-delete report.
    Reads main_file_path_report.txt and checks current file existence.
    """
    report_path = Path("main_file_path_report.txt")
    
    # Read the report file
    try:
        with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Could not read report file: {e}")
        return {"error": f"Could not read report file: {e}"}
    
    if len(lines) < 2:
        return {"error": "Invalid report file format"}
    
    # Extract file path from line 1
    file_path_str = None
    for line in lines:
        if "Checking existence of:" in line:
            file_path_str = line.split("Checking existence of:")[1].strip()
            break
    
    if not file_path_str:
        return {"error": "Could not extract file path from report"}
    
    main_file = Path(file_path_str)
    
    # Get previous existence status from report
    previous_exists = None
    for line in lines:
        if "Exists:" in line:
            if "Exists: Yes" in line:
                previous_exists = True
            elif "Exists: No" in line:
                previous_exists = False
            break
    
    # Check current existence
    current_exists = main_file.exists()
    
    # Determine status
    if previous_exists is True and not current_exists:
        status = "DELETED"
        note = f"File {main_file} existed in previous check but now deleted from sandbox! Self-delete behavior detected."
    elif previous_exists is False and current_exists:
        status = "CREATED"
        note = f"File {main_file} did not exist in previous check but now exists in sandbox."
    elif previous_exists is True and current_exists:
        status = "EXISTS"
        note = f"File {main_file} existed in previous check and still exists in sandbox."
    elif previous_exists is False and not current_exists:
        status = "NOT_FOUND"
        note = f"File {main_file} did not exist in previous check and still does not exist."
    else:
        status = "UNKNOWN"
        note = f"Could not determine previous existence status for {main_file}"
    
    result = {
        "file_path": str(main_file),
        "previous_exists": previous_exists,
        "current_exists": current_exists,
        "status": status,
        "note": note,
        "timestamp": datetime.now().isoformat()
    }
    
    # Write two-line deletion check report
    try:
        with open("deletion_check_report.txt", "w", encoding="utf-8") as f:
            f.write(f"File deletion check: {main_file} - Status: {status}\n")
            f.write(f"[{datetime.now()}] {note}\n")
    except Exception as e:
        logging.error(f"Could not write deletion report: {e}")
    
    return result

def generate_detailed_report(original_report, enhanced_results):
    combined_report = original_report.copy()
    combined_report['enhanced_detection'] = enhanced_results
    risk_factors = []
    suspicious_count = (
        len(original_report.get('suspicious_files', [])) +
        len(original_report.get('suspicious_drivers', [])) +
        len(original_report.get('process_scan', {}).get('suspicious_processes', []))
    )
    if suspicious_count > 0:
        risk_factors.append(f"Found {suspicious_count} suspicious files/processes")
    
    # Check for self-delete behavior
    self_delete_check = check_file_deleted_from_sandbox()
    if self_delete_check.get('status') == 'DELETED':
        risk_factors.append("HEUR:Win32.Susp.Trojan.SelfDelete - File deleted after execution")
        combined_report['self_delete_detection'] = self_delete_check
    
    for category, results in enhanced_results.items():
        if results:
            risk_factors.append(f"Detected {len(results)} {category}")
    
    if len(risk_factors) > 5:
        risk_level = "HIGH"
    elif len(risk_factors) > 2:
        risk_level = "MEDIUM"
    elif len(risk_factors) > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"
    
    combined_report['risk_assessment'] = {
        'level': risk_level,
        'factors': risk_factors,
        'total_findings': sum(len(v) for v in enhanced_results.values() if isinstance(v, list))
    }
    return combined_report

def generate_scan_report():
    report = {}

    suspicious_files = scan_files_parallel()
    for finding in suspicious_files:
        notify_user_for_rootkit(finding.get("path"), finding.get("detection_name", "UnknownFile"))
    report["suspicious_files"] = suspicious_files

    suspicious_drivers = scan_drivers_parallel()
    for finding in suspicious_drivers:
        notify_user_for_rootkit(finding.get("path"), finding.get("detection_name", "UnknownDriver"))
    report["suspicious_drivers"] = suspicious_drivers

    process_scan_results = scan_processes_parallel()
    for finding in process_scan_results.get("suspicious_processes", []):
         notify_user_for_rootkit(finding.get("exe"), finding.get("detection_name", "UnknownProcess"))
    report["process_scan"] = process_scan_results

    autorun = scan_autorun_registry()
    for finding in autorun:
        notify_user_for_rootkit(finding.get("exe"), finding.get("detection_name", "UnknownAutorun"))
    if autorun:
        report["suspicious_autorun"] = autorun

    acl = scan_registry_acl_parallel()
    for finding in acl:
        notify_user_for_rootkit(finding.get("subkey"), finding.get("detection_name", "UnknownACL"))
    if acl:
        report["registry_acl_issues"] = acl

    ifeo_blocking = scan_ifeo_antivirus_blocking()
    for finding in ifeo_blocking:
        notify_user_for_rootkit(finding.get("blocked_process"), finding.get("detection_name", "UnknownIFEO"))
    if ifeo_blocking:
        report["ifeo_antivirus_blocking"] = ifeo_blocking

    # New scan for network indicators in the registry
    network_indicators = scan_registry_for_network_indicators()
    if network_indicators:
        save_network_report(network_indicators)


    report["scan_time"] = datetime.now().isoformat()
    return report

def save_report(report: dict):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORTS_DIR / "scan_report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logging.info(f"Report -> {out}")

def save_network_report(network_indicators: list):
    """Saves the network indicators to a separate file."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "network_indicators_for_av.json"
    report_data = {
        "report_generated_at": datetime.now().isoformat(),
        "indicator_count": len(network_indicators),
        "indicators": network_indicators
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    logging.info(f"Network indicators report saved to -> {out_path}")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    if not DETECTIEASY_PATH.exists():
        logging.warning(f"DIE missing at {DETECTIEASY_PATH}; PE detection will be skipped.")
    DIE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    logging.info("=== Starting unified rootkit indicator scan ===")
    original_report = generate_scan_report()
    enhanced_results = run_enhanced_detection()
    combined = generate_detailed_report(original_report, enhanced_results)
    save_report(combined)
    print(json.dumps(combined, indent=2))
    logging.info("=== Scan complete ===")

if __name__ == "__main__":
    main()
