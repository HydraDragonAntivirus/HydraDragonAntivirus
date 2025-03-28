#!/usr/bin/env python

import os
import sys
import glob
import time
import json
import pickle
import logging
import argparse
import subprocess
import numpy as np
import hashlib
import pefile
import joblib
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from fastapi import FastAPI, HTTPException
import uvicorn

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

logging.info("OpenHydra Antivirus Engine started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# =============================================================================
# Global Directories for Dynamic Analysis (Sandbox Environment)
# =============================================================================

DYNAMIC_LOG_DIR = r"C:\sandbox_logs"
DUMP_DIR = r"C:\sandbox_dumps"
os.makedirs(DYNAMIC_LOG_DIR, exist_ok=True)
os.makedirs(DUMP_DIR, exist_ok=True)

dynamic_log_file_path = os.path.join(DYNAMIC_LOG_DIR, "dynamictrain.log")

# =============================================================================
# Dynamic Analysis Engine (Sandbox / Memory Signature Extraction)
# =============================================================================

SANDBOXIE_PATH = r"C:\Program Files\Sandboxie\Start.exe"

def full_cleanup_sandbox():
    """
    Fully cleans up the Sandboxie environment using termination commands.
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
    Checks if the given process is closed.
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
    Runs the given file in the Sandboxie environment.
    """
    try:
        logging.info(f"Running {file_path} in sandbox (DefaultBox)...")
        subprocess.run([SANDBOXIE_PATH, "/box:DefaultBox", file_path], check=True)
        return True
    except subprocess.CalledProcessError as ex:
        logging.error(f"Sandboxie execution failed for {file_path}: {ex}")
        return False

def check_program_executed(file_path):
    """
    Waits then checks if the target process is closed.
    """
    time.sleep(10)
    proc_name = os.path.basename(file_path)
    if is_process_closed(proc_name):
        logging.info(f"Process {proc_name} has terminated.")
        return True
    else:
        logging.warning(f"Process {proc_name} is still running.")
        return False

def scan_memory(file_path):
    """
    Simulates a dynamic memory scan.
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
    Retrieves or creates a baseline memory file.
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
    Compares baseline and current memory to extract a signature.
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
    Converts signature string into a numerical feature vector.
    """
    try:
        if signature == "0":
            return np.zeros(64, dtype=int)
        parts = signature.split('-')
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
    Processes a file: renames if needed, runs it in sandbox, extracts dynamic signature.
    """
    full_cleanup_sandbox()
    
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

    baseline = get_baseline_memory()

    if not run_in_sandbox(file_path):
        full_cleanup_sandbox()
        return None

    if not check_program_executed(file_path):
        logging.error(f"Program did not execute properly: {file_path}")
        full_cleanup_sandbox()
        return None

    current_memory = scan_memory(file_path)
    dynamic_signature, diff = extract_malicious_signature(baseline, current_memory)
    
    if dynamic_signature != "0":
        dump_file = os.path.join(DUMP_DIR, f"{os.path.basename(original_path)}_malicious_dump.bin")
        try:
            with open(dump_file, "wb") as f:
                f.write(current_memory)
            logging.info(f"Saved malicious memory dump to {dump_file}")
        except Exception as ex:
            logging.error(f"Failed to save malicious dump for {original_path}: {ex}")
    
    full_cleanup_sandbox()
    return dynamic_signature, os.path.basename(original_path)

def collect_dynamic_features(directory, label):
    """
    Processes all benign files in the given directory.
    """
    features = []
    labels = []
    file_names = []
    file_list = glob.glob(os.path.join(directory, "*"))
    logging.info(f"Found {len(file_list)} files in {directory}")
    for file_path in file_list:
        logging.info(f"Processing file: {file_path}")
        result = process_file(file_path)
        if result:
            signature, fname = result
            feat = extract_features_from_signature(signature)
            if feat is not None:
                if len(feat) < 64:
                    feat = np.pad(feat, (0, 64 - len(feat)), 'constant')
                else:
                    feat = feat[:64]
                features.append(feat)
                labels.append(label)
                file_names.append(fname)
    return features, labels, file_names

def collect_dynamic_features_malicious(directory):
    """
    Processes all malicious files in the given directory.
    """
    features = []
    labels = []
    file_names = []
    file_list = glob.glob(os.path.join(directory, "*"))
    logging.info(f"Found {len(file_list)} malicious files in {directory}")
    for idx, file_path in enumerate(file_list):
        logging.info(f"Processing malicious file: {file_path}")
        result = process_file(file_path)
        if result:
            signature, fname = result
            feat = extract_features_from_signature(signature)
            if feat is not None:
                if len(feat) < 64:
                    feat = np.pad(feat, (0, 64 - len(feat)), 'constant')
                else:
                    feat = feat[:64]
                features.append(feat)
                labels.append(idx + 1)
                file_names.append(fname)
    return features, labels, file_names

def train_model(features, labels):
    """
    Trains a Random Forest classifier using dynamic features.
    """
    X = np.array(features)
    y = np.array(labels)
    if X.shape[1] > 64:
        X = X[:, :64]
    elif X.shape[1] < 64:
        X = np.pad(X, ((0, 0), (0, 64 - X.shape[1])), 'constant')
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred)
    logging.info("Dynamic Analysis Classification Report:\n" + report)
    model_path = os.path.join(DUMP_DIR, "dynamic_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    logging.info(f"Dynamic model trained and saved as {model_path}")
    return clf

def save_databases(benign_names, benign_features, malicious_names, malicious_features):
    """
    Saves JSON databases and pickle files mapping file names to features.
    """
    benign_db_path = os.path.join(DUMP_DIR, "benign_database.json")
    malicious_db_path = os.path.join(DUMP_DIR, "malicious_database.json")
    
    benign_mapping = {str(i+1): name for i, name in enumerate(benign_names)}
    with open(benign_db_path, "w") as f:
        json.dump(benign_mapping, f, indent=2)
    logging.info(f"Saved benign database to {benign_db_path}")
    
    malicious_mapping = {str(i+1): name for i, name in enumerate(malicious_names)}
    with open(malicious_db_path, "w") as f:
        json.dump(malicious_mapping, f, indent=2)
    logging.info(f"Saved malicious database to {malicious_db_path}")
    
    benign_features_path = os.path.join(DUMP_DIR, "benign_features.pkl")
    malicious_features_path = os.path.join(DUMP_DIR, "malicious_features.pkl")
    benign_features_mapping = {str(i+1): feat.tolist() for i, feat in enumerate(benign_features)}
    malicious_features_mapping = {str(i+1): feat.tolist() for i, feat in enumerate(malicious_features)}
    with open(benign_features_path, "wb") as f:
        pickle.dump(benign_features_mapping, f)
    logging.info(f"Saved benign features mapping to {benign_features_path}")
    with open(malicious_features_path, "wb") as f:
        pickle.dump(malicious_features_mapping, f)
    logging.info(f"Saved malicious features mapping to {malicious_features_path}")

def run_dynamic_analysis(benign_dir, malicious_dir):
    """
    Runs the dynamic analysis workflow.
    """
    cleanup_old = True
    if cleanup_old:
        try:
            for fname in os.listdir(DUMP_DIR):
                if fname.lower() != "baseline_memory.bin":
                    file_path = os.path.join(DUMP_DIR, fname)
                    if os.path.isdir(file_path):
                        shutil.rmtree(file_path, ignore_errors=True)
                        logging.info(f"Removed old directory: {file_path}")
                    else:
                        os.remove(file_path)
                        logging.info(f"Removed old file: {file_path}")
        except Exception as ex:
            logging.error(f"Failed to cleanup old sandbox data: {ex}")

    benign_features, benign_labels, benign_names = collect_dynamic_features(benign_dir, label=0)
    malicious_features, malicious_labels, malicious_names = collect_dynamic_features_malicious(malicious_dir)

    all_features = benign_features + malicious_features
    all_labels = benign_labels + malicious_labels

    if not all_features:
        logging.error("No dynamic features extracted. Exiting dynamic analysis.")
        return

    clf = train_model(all_features, all_labels)
    save_databases(benign_names, benign_features, malicious_names, malicious_features)

# =============================================================================
# Static Analysis Engine (PE Feature Extraction)
# =============================================================================

class PEFeatureExtractor:
    """
    Extracts various features from PE files.
    """
    def __init__(self):
        self.features_cache = {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy

    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash of a file."""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    def extract_section_data(self, section) -> Dict[str, Any]:
        """Extracts section data with entropy."""
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
        """Extracts import information."""
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
        """Extracts export information."""
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
        """Analyzes TLS callbacks."""
        try:
            tls_callbacks = {}
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
                if tls.AddressOfCallBacks:
                    callback_array = self._get_callback_addresses(pe, tls.AddressOfCallBacks)
                    if callback_array:
                        tls_callbacks['callbacks'] = callback_array
            return tls_callbacks
        except Exception as e:
            logging.error(f"Error analyzing TLS callbacks: {e}")
            return {}

    def _get_callback_addresses(self, pe, address_of_callbacks) -> List[int]:
        """Retrieves callback addresses from the TLS directory."""
        try:
            callback_addresses = []
            while True:
                callback_address = pe.get_dword_at_rva(address_of_callbacks - pe.OPTIONAL_HEADER.ImageBase)
                if callback_address == 0:
                    break
                callback_addresses.append(callback_address)
                address_of_callbacks += 4
            return callback_addresses
        except Exception as e:
            logging.error(f"Error retrieving TLS callback addresses: {e}")
            return []

    def analyze_dos_stub(self, pe) -> Dict[str, Any]:
        """Analyzes the DOS stub."""
        try:
            dos_stub = {
                'exists': False,
                'size': 0,
                'entropy': 0.0,
            }
            if hasattr(pe, 'DOS_HEADER'):
                stub_offset = pe.DOS_HEADER.e_lfanew - 64
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
        """Calculates entropy from a list of integers."""
        if not data:
            return 0.0
        total_items = len(data)
        value_counts = [data.count(i) for i in range(256)]
        entropy = 0.0
        for count in value_counts:
            if count > 0:
                p_x = count / total_items
                entropy -= p_x * np.log2(p_x)
        return entropy

    def analyze_certificates(self, pe) -> Dict[str, Any]:
        """Analyzes file certificates."""
        try:
            cert_info = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                cert_info['virtual_address'] = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
                cert_info['size'] = pe.DIRECTORY_ENTRY_SECURITY.Size
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
        """Analyzes delay-load imports."""
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
                        'attributes': getattr(entry.struct, 'Attributes', None),
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
        """Analyzes the load configuration."""
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
        """Analyzes base relocations."""
        try:
            relocations = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
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
                            'types': entry_types,
                            'offset_range': (min(offsets), max(offsets)) if offsets else None
                        }
                    }
                    relocations.append(reloc_info)
            return relocations
        except Exception as e:
            logging.error(f"Error analyzing relocations: {e}")
            return []

    def analyze_bound_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyzes bound imports."""
        try:
            bound_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
                for bound_imp in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                    bound_import = {
                        'name': bound_imp.name.decode() if bound_imp.name else None,
                        'timestamp': bound_imp.struct.TimeDateStamp,
                        'references': []
                    }
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
        """Analyzes detailed section characteristics."""
        try:
            characteristics = {}
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                flags = section.Characteristics
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
        """Analyzes extended header information."""
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
        """Serializes data for compatibility."""
        try:
            return list(data) if data else None
        except Exception:
            return None

    def analyze_rich_header(self, pe) -> Dict[str, Any]:
        """Analyzes the Rich header."""
        try:
            rich_header = {}
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
                rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
                rich_header['values'] = self.serialize_data(pe.RICH_HEADER.values)
                rich_header['clear_data'] = self.serialize_data(pe.RICH_HEADER.clear_data)
                rich_header['key'] = self.serialize_data(pe.RICH_HEADER.key)
                rich_header['raw_data'] = self.serialize_data(pe.RICH_HEADER.raw_data)
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
        """Analyzes file overlay (data appended after PE structure)."""
        try:
            overlay_info = {
                'exists': False,
                'offset': 0,
                'size': 0,
                'entropy': 0.0
            }
            last_section = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
            end_of_pe = last_section.PointerToRawData + last_section.SizeOfRawData
            file_size = os.path.getsize(file_path)
            if file_size > end_of_pe:
                with open(file_path, 'rb') as f:
                    f.seek(end_of_pe)
                    overlay_data = f.read()
                    overlay_info['exists'] = True
                    overlay_info['offset'] = end_of_pe
                    overlay_info['size'] = len(overlay_data)
                    overlay_info['entropy'] = self._calculate_entropy(overlay_data)
            return overlay_info
        except Exception as e:
            logging.error(f"Error analyzing overlay: {e}")
            return {}

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extracts numeric features from a PE file.
        """
        try:
            pe = pefile.PE(file_path)
            numeric_features = {
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
                'imports': [
                    imp.name.decode(errors='ignore') if imp.name else "Unknown"
                    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                    for imp in getattr(entry, 'imports', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],
                'exports': [
                    exp.name.decode(errors='ignore') if exp.name else "Unknown"
                    for exp in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],
                'resources': [
                    {
                        'type_id': getattr(getattr(resource_type, 'struct', None), 'Id', None),
                        'resource_id': getattr(getattr(resource_id, 'struct', None), 'Id', None),
                        'lang_id': getattr(getattr(resource_lang, 'struct', None), 'Id', None),
                        'size': getattr(getattr(resource_lang, 'data', None), 'Size', None),
                        'codepage': getattr(getattr(resource_lang, 'data', None), 'CodePage', None),
                    }
                    for resource_type in (pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') else [])
                    for resource_id in (resource_type.directory.entries if hasattr(resource_type, 'directory') else [])
                    for resource_lang in (resource_id.directory.entries if hasattr(resource_id, 'directory') else [])
                    if hasattr(resource_lang, 'data')
                ] if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else [],
                'debug': [
                    {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': f"{debug.struct.MajorVersion}.{debug.struct.MinorVersion}",
                        'size': debug.struct.SizeOfData,
                    }
                    for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else [],
                'certificates': self.analyze_certificates(pe),
                'dos_stub': self.analyze_dos_stub(pe),
                'tls_callbacks': self.analyze_tls_callbacks(pe),
                'delay_imports': self.analyze_delay_imports(pe),
                'load_config': self.analyze_load_config(pe),
                'bound_imports': self.analyze_bound_imports(pe),
                'section_characteristics': self.analyze_section_characteristics(pe),
                'extended_headers': self.analyze_extended_headers(pe),
                'rich_header': self.analyze_rich_header(pe),
                'overlay': self.analyze_overlay(pe, file_path)
            }
            if rank is not None:
                numeric_features['numeric_tag'] = rank
            return numeric_features
        except Exception as ex:
            logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return None
