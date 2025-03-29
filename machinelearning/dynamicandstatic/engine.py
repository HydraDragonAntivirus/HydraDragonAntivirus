#!/usr/bin/env python

import os
import sys
import time
import json
import logging
import argparse
import subprocess
import numpy as np
import hashlib
import pefile
import shutil
import ctypes
import difflib
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any

# =============================================================================
# Windows API Functions for GUI Text Extraction
# =============================================================================

# Constants for Windows API calls
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E

def get_window_text(hwnd):
    """Retrieve the text of a window."""
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd) + 1
    buffer = ctypes.create_unicode_buffer(length)
    ctypes.windll.user32.GetWindowTextW(hwnd, buffer, length)
    return buffer.value

def get_control_text(hwnd):
    """Retrieve the text from a control."""
    length = ctypes.windll.user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) + 1
    buffer = ctypes.create_unicode_buffer(length)
    ctypes.windll.user32.SendMessageW(hwnd, WM_GETTEXT, length, buffer)
    return buffer.value

def find_child_windows(parent_hwnd):
    """Find all child windows of the given parent window."""
    child_windows = []

    def enum_child_windows_callback(hwnd, lParam):
        child_windows.append(hwnd)
        return True

    EnumChildWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    ctypes.windll.user32.EnumChildWindows(parent_hwnd, EnumChildWindowsProc(enum_child_windows_callback), None)
    
    return child_windows

def find_windows_with_text():
    """Find all windows and their child windows along with their text."""
    window_handles = []

    def enum_windows_callback(hwnd, lParam):
        if ctypes.windll.user32.IsWindowVisible(hwnd):
            window_text = get_window_text(hwnd)
            window_handles.append((hwnd, window_text))
            for child in find_child_windows(hwnd):
                control_text = get_control_text(child)
                window_handles.append((child, control_text))
        return True

    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    ctypes.windll.user32.EnumWindows(EnumWindowsProc(enum_windows_callback), None)
    return window_handles

# =============================================================================
# Logging Setup
# =============================================================================

# Set script directory and create log directory if it doesn't exist
script_dir = os.getcwd()
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Define separate log files for console and application logs
console_log_file = os.path.join(log_directory, "antivirusconsole.log")
application_log_file = os.path.join(log_directory, "antivirus.log")

# Configure logging for the application log file
logging.basicConfig(
    filename=application_log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Redirect stdout and stderr to the console log file for full logging
sys.stdout = open(console_log_file, "w", encoding="utf-8", errors="ignore")
sys.stderr = open(console_log_file, "w", encoding="utf-8", errors="ignore")

logging.info("Hydra Dragon Antivirus Engine started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# =============================================================================
# Global Directories for Dynamic Analysis (Sandbox Environment)
# =============================================================================

DYNAMIC_LOG_DIR = r"C:\sandbox_logs"
DUMP_DIR = r"C:\sandbox_dumps"
os.makedirs(DYNAMIC_LOG_DIR, exist_ok=True)
os.makedirs(DUMP_DIR, exist_ok=True)

dynamic_log_file_path = os.path.join(DYNAMIC_LOG_DIR, "dynamictrain.log")

SANDBOXIE_PATH = r"C:\Program Files\Sandboxie\Start.exe"

# =============================================================================
# Dynamic Analysis Engine (Sandbox / Memory Signature Extraction)
# =============================================================================

def full_cleanup_sandbox():
    """
    Fully cleans up the Sandboxie environment using Sandboxie's termination commands.
    It issues:
      - Start.exe /terminate
      - Start.exe /box:DefaultBox /terminate
      - Start.exe /terminate_all
    with short delays between each command.
    """
    try:
        logging.info("Starting full sandbox cleanup using Start.exe termination commands...")
        cmds = [
            [SANDBOXIE_PATH, "/terminate"],
            [SANDBOXIE_PATH, "/box:DefaultBox", "/terminate"],
            [SANDBOXIE_PATH, "/terminate_all"]
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Command {cmd} failed: {result.stderr}")
            else:
                logging.info(f"Command {cmd} successful.")
            time.sleep(2)
    except Exception as ex:
        logging.error(f"Full sandbox cleanup encountered an exception: {ex}")

def cleanup_old_sandbox_data():
    """
    Cleans up previous sandbox training data in the dump directory,
    excluding the baseline memory file.
    """
    try:
        logging.info("Cleaning up previous sandbox data in dump directory...")
        for fname in os.listdir(DUMP_DIR):
            if fname.lower() == "baseline_memory.bin":
                continue
            file_path = os.path.join(DUMP_DIR, fname)
            if os.path.isdir(file_path):
                shutil.rmtree(file_path, ignore_errors=True)
                logging.info(f"Removed old directory: {file_path}")
            else:
                os.remove(file_path)
                logging.info(f"Removed old file: {file_path}")
    except Exception as ex:
        logging.error(f"Failed to cleanup old sandbox data: {ex}")

def is_process_closed(process_name):
    """
    Checks if the given process (by image name) is closed.
    Returns True if not found in tasklist; otherwise, False.
    """
    try:
        cmd = ["tasklist", "/FI", f"IMAGENAME eq {process_name}", "/NH"]
        output = subprocess.check_output(cmd, text=True)
        if "No tasks are running" in output or process_name.lower() not in output.lower():
            return True
        return False
    except Exception as ex:
        logging.error(f"Error checking process status for {process_name}: {ex}")
        return True

def run_in_sandbox(file_path):
    """
    Runs the given file in the Sandboxie environment using DefaultBox.
    """
    try:
        logging.info(f"Running {file_path} in sandbox (DefaultBox)...")
        subprocess.run([SANDBOXIE_PATH, "/box:DefaultBox", file_path], check=True)
        return True
    except subprocess.CalledProcessError as ex:
        logging.error(f"Sandboxie execution failed for {file_path}: {ex}")
        return False

def scan_memory(file_path):
    """
    Simulates a dynamic memory scan by reading the file content as a byte array.
    """
    try:
        with open(file_path, "rb") as f:
            memory_dump = f.read()
        logging.info(f"Scanned memory from {file_path} (size: {len(memory_dump)} bytes)")
        return memory_dump
    except Exception as ex:
        logging.error(f"Memory scan failed for {file_path}: {ex}")
        return b""

def get_baseline_memory():
    """
    Retrieves the baseline (clean) memory state from a hardcoded file in the dump directory.
    """
    baseline_file = os.path.join(DUMP_DIR, "baseline_memory.bin")
    if os.path.exists(baseline_file):
        with open(baseline_file, "rb") as f:
            baseline = f.read()
        logging.info("Loaded baseline memory from file.")
    else:
        baseline = b"CLEAN_MEMORY_STATE" * 64
        with open(baseline_file, "wb") as f:
            f.write(baseline)
        logging.info("Created new baseline memory file.")
    return baseline

def extract_malicious_signature(baseline, current):
    """
    Compares the clean baseline memory with the current memory dump.
    Returns a dynamic dump signature composed of:
      - The total number of difference bytes
      - The hexadecimal representation of the first 16 bytes of the diff
    If no differences are found, returns "0".
    (No hashlib is used.)
    """
    common_length = min(len(baseline), len(current))
    diff = bytearray()
    for i in range(common_length):
        if baseline[i] != current[i]:
            diff.append(current[i])
    if len(current) > common_length:
        diff.extend(current[common_length:])
    
    if diff:
        signature = f"{len(diff)}-{diff[:16].hex()}"
        logging.info(f"Extracted dynamic dump signature: {signature}")
        return signature, diff
    else:
        logging.info("No malicious changes detected.")
        return "0", None

def extract_features_from_signature(signature):
    """
    Converts the dynamic dump signature string into a numerical feature vector.
    The signature is expected in the form "diffLength-hexPrefix". If signature is "0",
    returns a vector of zeros (length 64).
    """
    try:
        if signature == "0":
            return np.zeros(64, dtype=int)
        parts = signature.split('-')
        # We ignore the diff length and use the hexPrefix.
        diff_prefix = [int(parts[1][i:i+2], 16) for i in range(0, len(parts[1]), 2)]
        if len(diff_prefix) < 64:
            diff_prefix += [0] * (64 - len(diff_prefix))
        else:
            diff_prefix = diff_prefix[:64]
        return np.array(diff_prefix, dtype=int)
    except Exception as ex:
        logging.error(f"Feature extraction failed: {ex}")
        return None

def process_file(file_path):
    """
    Runs the given file in the sandbox and performs dynamic memory analysis 
    and target window message collection. Returns a tuple 
    (dynamic_signature, original_file_name, messages) or None on failure.
    """
    # Cleanup previous Sandboxie sessions.
    full_cleanup_sandbox()

    # If file is not an .exe, rename it.
    original_path = file_path
    if not file_path.lower().endswith(".exe"):
        file_path_exe = file_path + ".exe"
        try:
            os.rename(file_path, file_path_exe)
            logging.info(f"Renamed {original_path} to {file_path_exe}")
            file_path = file_path_exe
        except Exception as ex:
            logging.error(f"Failed to rename file {original_path} to .exe: {ex}")
            return None

    # Start the sandbox execution in a separate thread so it doesn't block message collection.
    sandbox_thread = threading.Thread(target=run_in_sandbox, args=(file_path,))
    sandbox_thread.start()

    # Create an event to signal when to stop message collection.
    stop_event = threading.Event()
    collected_messages = []
    # Use the full path (or at least the basename) of the file as the target.
    target_exe = file_path
    message_thread = threading.Thread(target=collect_messages, args=(target_exe, collected_messages, stop_event))
    message_thread.start()

    # Allow the executable to run for 10 seconds.
    time.sleep(10)

    # Signal the message collection thread to stop.
    stop_event.set()

    # Terminate the executable by cleaning up the sandbox environment.
    full_cleanup_sandbox()

    # Join the threads.
    sandbox_thread.join()
    message_thread.join(timeout=2)

    # Perform the memory scan.
    baseline = get_baseline_memory()
    current_memory = scan_memory(file_path)
    dynamic_signature, diff = extract_malicious_signature(baseline, current_memory)

    # If a malicious signature is found, save the memory dump.
    if dynamic_signature != "0":
        dump_file = os.path.join(DUMP_DIR, f"{os.path.basename(original_path)}_malicious_dump.bin")
        try:
            with open(dump_file, "wb") as f:
                f.write(current_memory)
            logging.info(f"Saved malicious memory dump to {dump_file}")
        except Exception as ex:
            logging.error(f"Failed to save malicious dump for {original_path}: {ex}")

    # Return the dynamic signature, original file name, and collected messages.
    return dynamic_signature, os.path.basename(original_path), collected_messages

# =============================================================================
# Static Analysis Engine (PE Feature Extraction)
# =============================================================================

class PEFeatureExtractor:
    def __init__(self):
        self.features_cache = {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy

    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash of file."""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    def extract_section_data(self, section) -> Dict[str, Any]:
        """Extract comprehensive section data including entropy."""
        raw_data = section.get_data()
        return {
            'name': section.Name.decode(errors='ignore').strip('\x00'),
            'virtual_size': section.Misc_VirtualSize,
            'virtual_address': section.VirtualAddress,
            'raw_size': section.SizeOfRawData,
            'pointer_to_raw_data': section.PointerToRawData,
            'characteristics': section.Characteristics,
            'entropy': self._calculate_entropy(raw_data),
            'raw_data_size': len(raw_data) if raw_data else 0
        }

    def extract_imports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed import information."""
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_imports = {
                    'dll_name': entry.dll.decode() if entry.dll else None,
                    'imports': [{
                        'name': imp.name.decode() if imp.name else None,
                        'address': imp.address,
                        'ordinal': imp.ordinal
                    } for imp in entry.imports]
                }
                imports.append(dll_imports)
        return imports

    def extract_exports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed export information."""
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'name': exp.name.decode() if exp.name else None,
                    'address': exp.address,
                    'ordinal': exp.ordinal,
                    'forwarder': exp.forwarder.decode() if exp.forwarder else None
                }
                exports.append(export_info)
        return exports

    def analyze_tls_callbacks(self, pe) -> Dict[str, Any]:
        """Analyze TLS (Thread Local Storage) callbacks and extract relevant details."""
        try:
            tls_callbacks = {}
            # Check if the PE file has a TLS directory
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls = pe.DIRECTORY_ENTRY_TLS.struct
                tls_callbacks = {
                    'start_address_raw_data': tls.StartAddressOfRawData,
                    'end_address_raw_data': tls.EndAddressOfRawData,
                    'address_of_index': tls.AddressOfIndex,
                    'address_of_callbacks': tls.AddressOfCallBacks,
                    'size_of_zero_fill': tls.SizeOfZeroFill,
                    'characteristics': tls.Characteristics,
                    'callbacks': []
                }

                # If there are callbacks, extract their addresses
                if tls.AddressOfCallBacks:
                    callback_array = self._get_callback_addresses(pe, tls.AddressOfCallBacks)
                    if callback_array:
                        tls_callbacks['callbacks'] = callback_array

            return tls_callbacks
        except Exception as e:
            logging.error(f"Error analyzing TLS callbacks: {e}")
            return {}

    def _get_callback_addresses(self, pe, address_of_callbacks) -> List[int]:
        """Retrieve callback addresses from the TLS directory."""
        try:
            callback_addresses = []
            # Read callback addresses from the memory-mapped file
            while True:
                callback_address = pe.get_dword_at_rva(address_of_callbacks - pe.OPTIONAL_HEADER.ImageBase)
                if callback_address == 0:
                    break  # End of callback list
                callback_addresses.append(callback_address)
                address_of_callbacks += 4  # Move to the next address (4 bytes for DWORD)

            return callback_addresses
        except Exception as e:
            logging.error(f"Error retrieving TLS callback addresses: {e}")
            return []

    def analyze_dos_stub(self, pe) -> Dict[str, Any]:
        """Analyze DOS stub program."""
        try:
            dos_stub = {
                'exists': False,
                'size': 0,
                'entropy': 0.0,
            }

            if hasattr(pe, 'DOS_HEADER'):
                stub_offset = pe.DOS_HEADER.e_lfanew - 64  # Typical DOS stub starts after DOS header
                if stub_offset > 0:
                    dos_stub_data = pe.__data__[64:pe.DOS_HEADER.e_lfanew]
                    if dos_stub_data:
                        dos_stub['exists'] = True
                        dos_stub['size'] = len(dos_stub_data)
                        dos_stub['entropy'] = self.calculate_entropy(list(dos_stub_data))

            return dos_stub
        except Exception as e:
            logging.error(f"Error analyzing DOS stub: {e}")
            return {}

    def calculate_entropy(self, data: list) -> float:
        """Calculate Shannon entropy of data (provided as a list of integers)."""
        if not data:
            return 0.0

        total_items = len(data)
        value_counts = [data.count(i) for i in range(256)]  # Count occurrences of each byte (0-255)

        entropy = 0.0
        for count in value_counts:
            if count > 0:
                # Calculate probability of each value and its contribution to entropy
                p_x = count / total_items
                entropy -= p_x * np.log2(p_x)

        return entropy

    def analyze_certificates(self, pe) -> Dict[str, Any]:
        """Analyze security certificates."""
        try:
            cert_info = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                cert_info['virtual_address'] = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
                cert_info['size'] = pe.DIRECTORY_ENTRY_SECURITY.Size

                # Extract certificate attributes if available
                if hasattr(pe, 'VS_FIXEDFILEINFO'):
                    cert_info['fixed_file_info'] = {
                        'signature': pe.VS_FIXEDFILEINFO.Signature,
                        'struct_version': pe.VS_FIXEDFILEINFO.StrucVersion,
                        'file_version': f"{pe.VS_FIXEDFILEINFO.FileVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.FileVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionLS & 0xFFFF}",
                        'product_version': f"{pe.VS_FIXEDFILEINFO.ProductVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.ProductVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionLS & 0xFFFF}",
                        'file_flags': pe.VS_FIXEDFILEINFO.FileFlags,
                        'file_os': pe.VS_FIXEDFILEINFO.FileOS,
                        'file_type': pe.VS_FIXEDFILEINFO.FileType,
                        'file_subtype': pe.VS_FIXEDFILEINFO.FileSubtype,
                    }

            return cert_info
        except Exception as e:
            logging.error(f"Error analyzing certificates: {e}")
            return {}

    def analyze_delay_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze delay-load imports with error handling for missing attributes."""
        try:
            delay_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    imports = []
                    for imp in entry.imports:
                        import_info = {
                            'name': imp.name.decode() if imp.name else None,
                            'address': imp.address,
                            'ordinal': imp.ordinal,
                        }
                        imports.append(import_info)

                    delay_import = {
                        'dll': entry.dll.decode() if entry.dll else None,
                        'attributes': getattr(entry.struct, 'Attributes', None),  # Use getattr for safe access
                        'name': getattr(entry.struct, 'Name', None),
                        'handle': getattr(entry.struct, 'Handle', None),
                        'iat': getattr(entry.struct, 'IAT', None),
                        'bound_iat': getattr(entry.struct, 'BoundIAT', None),
                        'unload_iat': getattr(entry.struct, 'UnloadIAT', None),
                        'timestamp': getattr(entry.struct, 'TimeDateStamp', None),
                        'imports': imports
                    }
                    delay_imports.append(delay_import)

            return delay_imports
        except Exception as e:
            logging.error(f"Error analyzing delay imports: {e}")
            return []

    def analyze_load_config(self, pe) -> Dict[str, Any]:
        """Analyze load configuration."""
        try:
            load_config = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                load_config = {
                    'size': config.Size,
                    'timestamp': config.TimeDateStamp,
                    'major_version': config.MajorVersion,
                    'minor_version': config.MinorVersion,
                    'global_flags_clear': config.GlobalFlagsClear,
                    'global_flags_set': config.GlobalFlagsSet,
                    'critical_section_default_timeout': config.CriticalSectionDefaultTimeout,
                    'decommit_free_block_threshold': config.DeCommitFreeBlockThreshold,
                    'decommit_total_free_threshold': config.DeCommitTotalFreeThreshold,
                    'security_cookie': config.SecurityCookie,
                    'se_handler_table': config.SEHandlerTable,
                    'se_handler_count': config.SEHandlerCount
                }

            return load_config
        except Exception as e:
            logging.error(f"Error analyzing load config: {e}")
            return {}

    def analyze_relocations(self, pe) -> List[Dict[str, Any]]:
        """Analyze base relocations with summarized entries."""
        try:
            relocations = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                    # Summarize relocation entries
                    entry_types = {}
                    offsets = []

                    for entry in base_reloc.entries:
                        entry_types[entry.type] = entry_types.get(entry.type, 0) + 1
                        offsets.append(entry.rva - base_reloc.struct.VirtualAddress)

                    reloc_info = {
                        'virtual_address': base_reloc.struct.VirtualAddress,
                        'size_of_block': base_reloc.struct.SizeOfBlock,
                        'summary': {
                            'total_entries': len(base_reloc.entries),
                            'types': entry_types,  # Counts of each relocation type
                            'offset_range': (min(offsets), max(offsets)) if offsets else None
                        }
                    }

                    relocations.append(reloc_info)

            return relocations
        except Exception as e:
            logging.error(f"Error analyzing relocations: {e}")
            return []

    def analyze_bound_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze bound imports with robust error handling."""
        try:
            bound_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
                for bound_imp in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                    bound_import = {
                        'name': bound_imp.name.decode() if bound_imp.name else None,
                        'timestamp': bound_imp.struct.TimeDateStamp,
                        'references': []
                    }

                    # Check if `references` exists
                    if hasattr(bound_imp, 'references') and bound_imp.references:
                        for ref in bound_imp.references:
                            reference = {
                                'name': ref.name.decode() if ref.name else None,
                                'timestamp': getattr(ref.struct, 'TimeDateStamp', None)
                            }
                            bound_import['references'].append(reference)
                    else:
                        logging.warning(f"Bound import {bound_import['name']} has no references.")

                    bound_imports.append(bound_import)

            return bound_imports
        except Exception as e:
            logging.error(f"Error analyzing bound imports: {e}")
            return []

    def analyze_section_characteristics(self, pe) -> Dict[str, Dict[str, Any]]:
        """Analyze detailed section characteristics."""
        try:
            characteristics = {}
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                flags = section.Characteristics

                # Decode section characteristics flags
                section_flags = {
                    'CODE': bool(flags & 0x20),
                    'INITIALIZED_DATA': bool(flags & 0x40),
                    'UNINITIALIZED_DATA': bool(flags & 0x80),
                    'MEM_DISCARDABLE': bool(flags & 0x2000000),
                    'MEM_NOT_CACHED': bool(flags & 0x4000000),
                    'MEM_NOT_PAGED': bool(flags & 0x8000000),
                    'MEM_SHARED': bool(flags & 0x10000000),
                    'MEM_EXECUTE': bool(flags & 0x20000000),
                    'MEM_READ': bool(flags & 0x40000000),
                    'MEM_WRITE': bool(flags & 0x80000000)
                }

                characteristics[section_name] = {
                    'flags': section_flags,
                    'entropy': self._calculate_entropy(list(section.get_data())),
                    'size_ratio': section.SizeOfRawData / pe.OPTIONAL_HEADER.SizeOfImage if pe.OPTIONAL_HEADER.SizeOfImage else 0,
                    'pointer_to_raw_data': section.PointerToRawData,
                    'pointer_to_relocations': section.PointerToRelocations,
                    'pointer_to_line_numbers': section.PointerToLinenumbers,
                    'number_of_relocations': section.NumberOfRelocations,
                    'number_of_line_numbers': section.NumberOfLinenumbers,
                }

            return characteristics
        except Exception as e:
            logging.error(f"Error analyzing section characteristics: {e}")
            return {}

    def analyze_extended_headers(self, pe) -> Dict[str, Any]:
        """Analyze extended header information."""
        try:
            headers = {
                'dos_header': {
                    'e_magic': pe.DOS_HEADER.e_magic,
                    'e_cblp': pe.DOS_HEADER.e_cblp,
                    'e_cp': pe.DOS_HEADER.e_cp,
                    'e_crlc': pe.DOS_HEADER.e_crlc,
                    'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
                    'e_minalloc': pe.DOS_HEADER.e_minalloc,
                    'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
                    'e_ss': pe.DOS_HEADER.e_ss,
                    'e_sp': pe.DOS_HEADER.e_sp,
                    'e_csum': pe.DOS_HEADER.e_csum,
                    'e_ip': pe.DOS_HEADER.e_ip,
                    'e_cs': pe.DOS_HEADER.e_cs,
                    'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
                    'e_ovno': pe.DOS_HEADER.e_ovno,
                    'e_oemid': pe.DOS_HEADER.e_oemid,
                    'e_oeminfo': pe.DOS_HEADER.e_oeminfo
                },
                'nt_headers': {}
            }

            # Ensure NT_HEADERS exists and contains FileHeader
            if hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS is not None:
                nt_headers = pe.NT_HEADERS
                if hasattr(nt_headers, 'FileHeader'):
                    headers['nt_headers'] = {
                        'signature': nt_headers.Signature,
                        'machine': nt_headers.FileHeader.Machine,
                        'number_of_sections': nt_headers.FileHeader.NumberOfSections,
                        'time_date_stamp': nt_headers.FileHeader.TimeDateStamp,
                        'characteristics': nt_headers.FileHeader.Characteristics
                    }

            return headers
        except Exception as e:
            logging.error(f"Error analyzing extended headers: {e}")
            return {}

    def serialize_data(self, data) -> Any:
        """Serialize data for output, ensuring compatibility."""
        try:
            return list(data) if data else None
        except Exception:
            return None

    def analyze_rich_header(self, pe) -> Dict[str, Any]:
        """Analyze Rich header details."""
        try:
            rich_header = {}
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
                rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
                rich_header['values'] = self.serialize_data(pe.RICH_HEADER.values)
                rich_header['clear_data'] = self.serialize_data(pe.RICH_HEADER.clear_data)
                rich_header['key'] = self.serialize_data(pe.RICH_HEADER.key)
                rich_header['raw_data'] = self.serialize_data(pe.RICH_HEADER.raw_data)

                # Decode CompID and build number information
                compid_info = []
                for i in range(0, len(pe.RICH_HEADER.values), 2):
                    if i + 1 < len(pe.RICH_HEADER.values):
                        comp_id = pe.RICH_HEADER.values[i] >> 16
                        build_number = pe.RICH_HEADER.values[i] & 0xFFFF
                        count = pe.RICH_HEADER.values[i + 1]
                        compid_info.append({
                            'comp_id': comp_id,
                            'build_number': build_number,
                            'count': count
                        })
                rich_header['comp_id_info'] = compid_info

            return rich_header
        except Exception as e:
            logging.error(f"Error analyzing Rich header: {e}")
            return {}

    def analyze_overlay(self, pe, file_path: str) -> Dict[str, Any]:
        """Analyze file overlay (data appended after the PE structure)."""
        try:
            overlay_info = {
                'exists': False,
                'offset': 0,
                'size': 0,
                'entropy': 0.0
            }

            # Calculate the end of the PE structure
            last_section = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
            end_of_pe = last_section.PointerToRawData + last_section.SizeOfRawData

            # Get file size
            file_size = os.path.getsize(file_path)

            # Check for overlay
            if file_size > end_of_pe:
                with open(file_path, 'rb') as f:
                    f.seek(end_of_pe)
                    overlay_data = f.read()

                    overlay_info['exists'] = True
                    overlay_info['offset'] = end_of_pe
                    overlay_info['size'] = len(overlay_data)
                    overlay_info['entropy'] = self._calculate_entropy(list(overlay_data))

            return overlay_info
        except Exception as e:
            logging.error(f"Error analyzing overlay: {e}")
            return {}

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extract numeric features of a file using pefile.
        """
        try:
            # Load the PE file
            pe = pefile.PE(file_path)

            # Extract features
            numeric_features = {
                # Optional Header Features
                'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
                'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
                'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
                'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
                'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
                'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
                'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
                'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
                'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
                'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
                'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,

                # Section Headers
                'sections': [
                    {
                        'name': section.Name.decode(errors='ignore').strip('\x00'),
                        'virtual_size': section.Misc_VirtualSize,
                        'virtual_address': section.VirtualAddress,
                        'size_of_raw_data': section.SizeOfRawData,
                        'pointer_to_raw_data': section.PointerToRawData,
                        'characteristics': section.Characteristics,
                    }
                    for section in pe.sections
                ],

                # Imported Functions
                'imports': [
                    imp.name.decode(errors='ignore') if imp.name else "Unknown"
                    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                    for imp in getattr(entry, 'imports', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],

                # Exported Functions
                'exports': [
                    exp.name.decode(errors='ignore') if exp.name else "Unknown"
                    for exp in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],

                # Resources
                'resources': [
                    {
                        'type_id': getattr(getattr(resource_type, 'struct', None), 'Id', None),
                        'resource_id': getattr(getattr(resource_id, 'struct', None), 'Id', None),
                        'lang_id': getattr(getattr(resource_lang, 'struct', None), 'Id', None),
                        'size': getattr(getattr(resource_lang, 'data', None), 'Size', None),
                        'codepage': getattr(getattr(resource_lang, 'data', None), 'CodePage', None),
                    }
                    for resource_type in
                    (pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') else [])
                    for resource_id in (resource_type.directory.entries if hasattr(resource_type, 'directory') else [])
                    for resource_lang in (resource_id.directory.entries if hasattr(resource_id, 'directory') else [])
                    if hasattr(resource_lang, 'data')
                ] if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else [],

                # Debug Information
                'debug': [
                    {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': f"{debug.struct.MajorVersion}.{debug.struct.MinorVersion}",
                        'size': debug.struct.SizeOfData,
                    }
                    for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else [],

                # Certificates
                'certificates': self.analyze_certificates(pe),  # Analyze certificates

                # DOS Stub Analysis
                'dos_stub': self.analyze_dos_stub(pe),  # DOS stub analysis here

                # TLS Callbacks
                'tls_callbacks': self.analyze_tls_callbacks(pe),  # TLS callback analysis here

                # Delay Imports
                'delay_imports': self.analyze_delay_imports(pe),  # Delay imports analysis here

                # Load Config
                'load_config': self.analyze_load_config(pe),  # Load config analysis here

                # Bound Imports
                'bound_imports': self.analyze_bound_imports(pe),  # Bound imports analysis here

                # Section Characteristics
                'section_characteristics': self.analyze_section_characteristics(pe),
                # Section characteristics analysis here

                # Extended Headers
                'extended_headers': self.analyze_extended_headers(pe),  # Extended headers analysis here

                # Rich Header
                'rich_header': self.analyze_rich_header(pe),  # Rich header analysis here

                # Overlay
                'overlay': self.analyze_overlay(pe, file_path),  # Overlay analysis here

                #Relocations
                'relocations': self.analyze_relocations(pe) #Relocations analysis here
            }

            # Add numeric tag if provided
            if rank is not None:
                numeric_features['numeric_tag'] = rank

            return numeric_features

        except Exception as ex:
            logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return None

# =============================================================================
# Helper Function to Extract Sandbox Environment Messages
# =============================================================================

def get_process_name(hwnd):
    """
    Retrieves the process executable name for the given window handle.
    """
    pid = ctypes.c_ulong()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    
    # Open the process with limited query permissions
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    process_name = ""
    if handle:
        buffer = ctypes.create_unicode_buffer(512)
        size = ctypes.c_ulong(512)
        # Use GetModuleBaseNameW from psapi.dll to retrieve the executable name
        if ctypes.windll.psapi.GetModuleBaseNameW(handle, None, buffer, size):
            process_name = buffer.value
        ctypes.windll.kernel32.CloseHandle(handle)
    return process_name

def get_target_hwnd(target_exe_name):
    """
    Retrieves the window handles (HWND) for windows whose associated process
    executable name matches the target_exe_name (case-insensitive).
    """
    target_hwnds = []
    current_pid = os.getpid()

    def enum_windows_proc(hwnd):
        # Exclude windows belonging to the scanning process
        pid = ctypes.c_ulong()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == current_pid:
            return True

        proc_name = get_process_name(hwnd)
        # Only add the window if its process name matches the target executable name
        if proc_name.lower() == target_exe_name.lower():
            target_hwnds.append(hwnd)
        return True

    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    ctypes.windll.user32.EnumWindows(EnumWindowsProc(enum_windows_proc), None)
    return target_hwnds

def hwnd_to_executable(hwnd):
    """
    Converts a window handle (HWND) to the full executable path of the process
    that owns the window.
    """
    # Retrieve the process ID associated with the HWND.
    pid = ctypes.c_ulong()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    
    # Define necessary access rights.
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    
    # Open the process with the required permissions.
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid.value)
    if handle:
        # Allocate a buffer for the executable path (MAX_PATH=260).
        buffer = ctypes.create_unicode_buffer(260)
        # Get the full path of the executable.
        ctypes.windll.psapi.GetModuleFileNameExW(handle, None, buffer, 260)
        executable_path = buffer.value
        ctypes.windll.kernel32.CloseHandle(handle)
        return executable_path
    else:
        return None

def extract_target_messages(target_exe, stop_event):
    """
    Iterates through all window handles, converts each hwnd to its full executable path,
    and collects the window text for those windows whose executable (or its basename)
    matches target_exe. The loop stops when stop_event is set.
    """
    collected_messages = set()
    while not stop_event.is_set():
        window_handles = find_windows_with_text()
        for hwnd, text in window_handles:
            exe_path = hwnd_to_executable(hwnd)
            if exe_path:
                exe_basename = os.path.basename(exe_path).lower()
                target_basename = os.path.basename(target_exe).lower()
                logging.debug(f"Window HWND {hwnd} is from '{exe_path}' with text '{text}'")
                if exe_basename == target_basename:
                    if text and text not in collected_messages:
                        # Format the message to include the full executable path.
                        formatted_message = f"{exe_path} -> {text}"
                        collected_messages.add(formatted_message)
                        logging.info(f"Collected message: {formatted_message}")
    return list(collected_messages)

# =============================================================================
# Main Functionality for Static & Dynamic Scanning and Signature Matching
# =============================================================================

def load_signatures(signatures_file="signatures.json"):
    """Loads human-defined signatures from a JSON file."""
    if not os.path.exists(signatures_file):
        print(f"Signatures file {signatures_file} not found.", file=sys.stderr)
        return []
    with open(signatures_file, "r") as f:
        try:
            return json.load(f)
        except Exception as e:
            print(f"Error loading signatures: {e}", file=sys.stderr)
            return []

def dynamic_scan(file_path):
    """
    Runs dynamic analysis on an executable using process_file.
    Returns a tuple (memdump_token, messages) where memdump_token is a string
    and messages is a list of collected window messages.
    """
    try:
        result = process_file(file_path)
    except Exception as e:
        print(f"Dynamic analysis error: {e}", file=sys.stderr)
        return "MEMDUMP:0", []
    
    if result:
        dynamic_signature, fname, messages = result  # Unpack three values
        if dynamic_signature != "0":
            return f"MEMDUMP:{dynamic_signature}", messages
    return "MEMDUMP:0", messages

def detailed_static_scan(file_path):
    """
    Runs static analysis using PEFeatureExtractor.
    Constructs detailed tokens for every feature extracted.
    """
    extractor = PEFeatureExtractor()
    try:
        nf = extractor.extract_numeric_features(file_path)
    except Exception as e:
        print(f"Static analysis failed: {e}", file=sys.stderr)
        nf = {}

    tokens = []
    tokens.append(f"OPTIONALHEADER:SizeOfOptionalHeader={nf.get('SizeOfOptionalHeader','NA')}")
    tokens.append(f"LINKERVERSION:{nf.get('MajorLinkerVersion','NA')}.{nf.get('MinorLinkerVersion','NA')}")
    tokens.append(f"SizeOfCode={nf.get('SizeOfCode','NA')}")
    tokens.append(f"SizeOfInitializedData={nf.get('SizeOfInitializedData','NA')}")
    tokens.append(f"SizeOfUninitializedData={nf.get('SizeOfUninitializedData','NA')}")
    tokens.append(f"AddressOfEntryPoint={hex(nf.get('AddressOfEntryPoint',0))}")
    tokens.append(f"BaseOfCode={hex(nf.get('BaseOfCode',0))}")
    tokens.append(f"BaseOfData={hex(nf.get('BaseOfData',0))}")
    tokens.append(f"ImageBase={hex(nf.get('ImageBase',0))}")
    tokens.append(f"SectionAlignment={nf.get('SectionAlignment','NA')}")
    tokens.append(f"FileAlignment={nf.get('FileAlignment','NA')}")
    tokens.append(f"OSVersion:{nf.get('MajorOperatingSystemVersion','NA')}.{nf.get('MinorOperatingSystemVersion','NA')}")
    tokens.append(f"ImageVersion:{nf.get('MajorImageVersion','NA')}.{nf.get('MinorImageVersion','NA')}")
    tokens.append(f"SubsystemVersion:{nf.get('MajorSubsystemVersion','NA')}.{nf.get('MinorSubsystemVersion','NA')}")
    tokens.append(f"SizeOfImage={nf.get('SizeOfImage','NA')}")
    tokens.append(f"SizeOfHeaders={nf.get('SizeOfHeaders','NA')}")
    tokens.append(f"CheckSum={nf.get('CheckSum','NA')}")
    tokens.append(f"Subsystem={nf.get('Subsystem','NA')}")
    tokens.append(f"DllCharacteristics={nf.get('DllCharacteristics','NA')}")
    tokens.append(f"SizeOfStackReserve={nf.get('SizeOfStackReserve','NA')}")
    tokens.append(f"SizeOfStackCommit={nf.get('SizeOfStackCommit','NA')}")
    tokens.append(f"SizeOfHeapReserve={nf.get('SizeOfHeapReserve','NA')}")
    tokens.append(f"SizeOfHeapCommit={nf.get('SizeOfHeapCommit','NA')}")
    tokens.append(f"LoaderFlags={nf.get('LoaderFlags','NA')}")
    tokens.append(f"NumberOfRvaAndSizes={nf.get('NumberOfRvaAndSizes','NA')}")
    
    sections = nf.get("sections", [])
    tokens.append(f"SECTIONS:count={len(sections)}")
    for sec in sections:
        tokens.append(f"SECTION:{sec.get('name','NA')},virtSize={sec.get('virtual_size','NA')},rawSize={sec.get('size_of_raw_data','NA')},entropy={sec.get('entropy','NA')}")
    
    imports = nf.get("imports", [])
    tokens.append(f"IMPORTS:count={len(imports)}")
    exports = nf.get("exports", [])
    tokens.append(f"EXPORTS:count={len(exports)}")
    
    resources = nf.get("resources", [])
    tokens.append(f"RESOURCES:count={len(resources)}")
    
    debug = nf.get("debug", [])
    tokens.append(f"DEBUG:count={len(debug)}")
    
    cert = nf.get("certificates", {})
    if cert:
        tokens.append(f"CERTIFICATES:present,size={cert.get('size','NA')}")
    else:
        tokens.append("CERTIFICATES:absent")
    
    dos_stub = nf.get("dos_stub", {})
    if dos_stub.get("exists"):
        tokens.append(f"DOSSTUB:exists,size={dos_stub.get('size','NA')},entropy={dos_stub.get('entropy','NA')}")
    else:
        tokens.append("DOSSTUB:absent")
    
    tls = nf.get("tls_callbacks", {})
    callbacks = tls.get("callbacks", [])
    if callbacks:
        tokens.append("TLS:callbacks=[" + ",".join(hex(cb) for cb in callbacks) + "]")
    else:
        tokens.append("TLS:absent")
    
    delay_imports = nf.get("delay_imports", [])
    tokens.append(f"DELAYIMPORTS:count={len(delay_imports)}")
    
    load_config = nf.get("load_config", {})
    if load_config:
        tokens.append(f"LOADCONFIG:size={load_config.get('size','NA')},timestamp={load_config.get('timestamp','NA')}")
    else:
        tokens.append("LOADCONFIG:absent")
    
    bound_imports = nf.get("bound_imports", [])
    tokens.append(f"BOUNDIMPORTS:count={len(bound_imports)}")
    
    section_chars = nf.get("section_characteristics", {})
    tokens.append(f"SECTIONCHAR:count={len(section_chars)}")
    for sec_name, details in section_chars.items():
        tokens.append(f"SECTIONCHAR:{sec_name},entropy={details.get('entropy','NA')},flags={details.get('flags','NA')}")
    
    ext_headers = nf.get("extended_headers", {})
    if ext_headers:
        tokens.append("EXTHEADER:present")
    else:
        tokens.append("EXTHEADER:absent")
    
    rich_header = nf.get("rich_header", {})
    if rich_header and rich_header.get("values"):
        tokens.append(f"RICHHEADER:present,count={len(rich_header.get('values'))}")
    else:
        tokens.append("RICHHEADER:absent")
    
    overlay = nf.get("overlay", {})
    if overlay.get("exists"):
        tokens.append(f"OVERLAY:exists,offset={overlay.get('offset','NA')},size={overlay.get('size','NA')},entropy={overlay.get('entropy','NA')}")
    else:
        tokens.append("OVERLAY:absent")
    
    return " ".join(tokens)

def calculate_similarity(a: str, b: str) -> float:
    """
    Computes the similarity ratio between two strings.
    A ratio of 1.0 means an exact match.
    """
    return difflib.SequenceMatcher(None, a, b).ratio()

def collect_messages(target_exe, collected_messages, stop_event):
    """
    Helper function to collect messages using extract_target_messages with a stop_event.
    """
    msgs = extract_target_messages(target_exe, stop_event)
    collected_messages.extend(msgs)

def scan_file(file_path, auto_create=False, benign=False):
    print(f"Scanning file: {file_path}")
    report_tokens = []

    # Run dynamic and static analysis
    dynamic_result, collected_messages = dynamic_scan(file_path)
    static_result = detailed_static_scan(file_path)
    report_tokens.append(dynamic_result)
    report_tokens.append(static_result)
    
    # Process collected messages to remove full file path
    if collected_messages:
        clean_messages = []
        for msg in collected_messages:
            # Expecting messages like "C:\full\path\program.exe -> window text"
            if "->" in msg:
                clean_messages.append(msg.split("->")[-1].strip())
            else:
                clean_messages.append(msg)
        report_tokens.append("TARGETMESSAGES:" + " ".join(clean_messages))
    
    # Combine tokens into a full scan report.
    scan_report = " ".join(report_tokens)
    print("Scan Report:", scan_report)
    
    # Load user-defined signatures and perform similarity matching.
    signatures = load_signatures()
    matched_signatures = []
    threshold = 0.8  # Similarity threshold
    for sig in signatures:
        pattern = sig.get("pattern", "")
        similarity = calculate_similarity(pattern, scan_report)
        if similarity >= threshold:
            matched_signatures.append((sig.get("name"), similarity))
    
    if matched_signatures:
        print("Matched Signatures:")
        for name, sim in matched_signatures:
            print(f" - {name} (Similarity: {sim:.2f})")
    else:
        print("No signatures matched.")
        # --- Auto signature creator ---
        if auto_create:
            label = "benign" if benign else ("malware" if dynamic_result != "MEMDUMP:0" else "benign")
            new_signature = {
                "name": os.path.basename(file_path),  # Use file name instead of auto-generated name
                "pattern": scan_report,
                "label": label
            }
            auto_sig_file = "auto_signatures.json"
            try:
                if os.path.exists(auto_sig_file):
                    with open(auto_sig_file, "r") as f:
                        auto_sigs = json.load(f)
                else:
                    auto_sigs = []
                auto_sigs.append(new_signature)
                with open(auto_sig_file, "w") as f:
                    json.dump(auto_sigs, f, indent=4)
                print("Auto-created signature:", new_signature)
            except Exception as ex:
                print("Failed to auto-create signature:", ex)

def scan_directory(directory, auto_create=False, benign=False):
    """
    Recursively scans all files in the given directory.
    For each file, it calls scan_file with the provided flags.
    """
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"\nScanning file: {file_path}")
            scan_file(file_path, auto_create=auto_create, benign=benign)

def main():
    parser = argparse.ArgumentParser(description="Comprehensive Scanner for Hydra Dragon Antivirus Engine using all features")
    parser.add_argument("path", help="Path to the file or directory to scan")
    parser.add_argument("--auto-create", action="store_true", help="Auto create new signature if none matched")
    parser.add_argument("--benign", action="store_true", help="Force auto-created signature to be labeled as benign")
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print("Error: The specified path does not exist.", file=sys.stderr)
        return
    
    if os.path.isfile(args.path):
        scan_file(args.path, auto_create=args.auto_create, benign=args.benign)
    elif os.path.isdir(args.path):
        scan_directory(args.path, auto_create=args.auto_create, benign=args.benign)
    else:
        print("Error: The specified path is neither a file nor a directory.", file=sys.stderr)

if __name__ == "__main__":
    main()

