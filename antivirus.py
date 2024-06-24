import sys
import os
import shutil
import subprocess
import threading
from platform import architecture
import re
import json
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QStackedWidget)
from PySide6.QtCore import Qt, QObject, QThread, Signal, Slot, QMetaObject
from PySide6.QtGui import QIcon
import sklearn
import joblib
import pefile
import zipfile
import tarfile
import yara
import yara_x
import psutil
from notifypy import Notify
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import win32file
import win32con
from datetime import datetime, timedelta
sys.modules['sklearn.externals.joblib'] = joblib
# Set script directory
script_dir = os.getcwd()
# Configure logging
log_directory = os.path.join(script_dir, "log")  # Replace with the path to your log directory
log_file = os.path.join(log_directory, "antivirus.log")

if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

def extract_infos(file_path, rank=None):
    """Extract information about file"""
    file_name = os.path.basename(file_path)
    if rank is not None:
        return {'file_name': file_name, 'numeric_tag': rank}
    else:
        return {'file_name': file_name}

def extract_numeric_features(file_path, rank=None):
    """Extract numeric features of a file using pefile"""
    res = {}
    try:
        pe = pefile.PE(file_path)
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData') else 0
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        if rank is not None:
            res['numeric_tag'] = rank
    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")

    return res

def calculate_similarity(features1, features2, threshold=0.86):
    """Calculate similarity between two dictionaries of features"""
    common_keys = set(features1.keys()) & set(features2.keys())
    matching_keys = sum(1 for key in common_keys if features1[key] == features2[key])
    similarity = matching_keys / max(len(features1), len(features2))
    return similarity
malicious_file_names = os.path.join(script_dir, "machinelearning", "malicious_file_names.json")
malicious_numeric_features = os.path.join(script_dir, "machinelearning", "malicious_numeric.pkl")
benign_numeric_features = os.path.join(script_dir, "machinelearning", "benign_numeric.pkl")
yara_folder_path = os.path.join(script_dir, "yara")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")

# Load excluded rules from text file
with open(excluded_rules_path, "r") as file:
        excluded_rules = file.read()
        print("YARA Excluded Rules Definitions loaded!")

# Load malicious file names from JSON file
with open(malicious_file_names, 'r') as f:
    malicious_file_names = json.load(f)
    print("Machine Learning Definitions loaded!")

# Load malicious numeric features from pickle file
with open(malicious_numeric_features, 'rb') as f:
    malicious_numeric_features = joblib.load(f)
    print("Malicious Feature Signatures loaded!")

# Load benign numeric features from pickle file
with open(benign_numeric_features, 'rb') as f:
    benign_numeric_features = joblib.load(f)
    print("Benign Feature Signatures loaded!")

print("Machine Learning AI Signatures loaded!")

try:
    # Load the precompiled rules from the .yrc file
    compiled_rule = yara.load(os.path.join(yara_folder_path, "compiled_rule.yrc"))
    print("YARA Rules Definitions loaded!")
except yara.Error as e:
    print(f"Error loading precompiled YARA rule: {e}")

try:
    # Load the precompiled rule from the .yrc file using yara_x
    with open(os.path.join(yara_folder_path, "yaraxtr.yrc"), 'rb') as f:
        yaraxtr_rule = yara_x.Rules.deserialize_from(f)
    print("YARA-X Rules Definitions loaded!")
except FileNotFoundError:
    print("Error: File not found.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

# Additional function to check if a file is an SQLite database
def is_sqlite_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            header = file.read(16)
            # SQLite database files have a specific header
            if header.startswith(b'SQLite format 3'):
                return True
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return False

# Add the setup MBRFilter button function
def setup_mbrfilter():
    QMessageBox.warning(None, "Unsupported Platform", "MBRFilter setup is only supported on Windows.")
    return
    
    # Check system architecture
    arch = architecture()[0]
    if arch == '64bit':
        mbrfilter_path = os.path.join(script_dir, "mbrfilter", "x64", "MBRFilter.inf")
    else:
        mbrfilter_path = os.path.join(script_dir, "mbrfilter", "x86", "MBRFilter.inf")

    if os.path.exists(mbrfilter_path):
        try:
            # Run infdefaultinstall.exe to setup MBRFilter
            result = subprocess.run(["infdefaultinstall.exe", mbrfilter_path], capture_output=True, text=True, check=True)
            QMessageBox.information(None, "Success", "MBRFilter has been setup successfully.")
        except subprocess.CalledProcessError as e:
            error_message = e.stderr if e.stderr else str(e)
            if "dijital imza" in error_message or "digital signature" in error_message:
                error_message += "\n\nThe INF file does not contain a digital signature, which is required for 64-bit Windows."
            QMessageBox.critical(None, "Error", f"Failed to setup MBRFilter: {error_message}")
    else:
        QMessageBox.critical(None, "Error", f"MBRFilter.inf not found at {mbrfilter_path}.")
        
def safe_remove(file_path):
    try:
        os.remove(file_path)
        print(f"File {file_path} deleted successfully.")
    except Exception as e:
        print(f"Error deleting file {file_path}: {e}")

def scan_file_with_machine_learning_ai(file_path, threshold=0.86):
    """Scan a file for malicious activity using machine learning."""

    try:
        malware_definition = "Benign"  # Default
        pe = pefile.PE(file_path)
        if not pe:
            return False, malware_definition

        file_info = extract_infos(file_path)
        file_numeric_features = extract_numeric_features(file_path)

        is_malicious = False
        malware_rank = None
        nearest_malicious_similarity = 0
        nearest_benign_similarity = 0

        for malicious_features, info in zip(malicious_numeric_features, malicious_file_names):
            rank = info['numeric_tag']
            similarity = calculate_similarity(file_numeric_features, malicious_features)
            if similarity > nearest_malicious_similarity:
                nearest_malicious_similarity = similarity
            if similarity >= threshold:
                is_malicious = True
                malware_rank = rank
                malware_definition = info['file_name']
                break

        for benign_features in benign_numeric_features:
            similarity = calculate_similarity(file_numeric_features, benign_features)
            if similarity > nearest_benign_similarity:
                nearest_benign_similarity = similarity

        if is_malicious:
            if nearest_benign_similarity >= 0.93:
                return False, malware_definition, nearest_benign_similarity
            else:
                return True, malware_definition, nearest_benign_similarity
        else:
            return False, malware_definition, nearest_benign_similarity

    except pefile.PEFormatError:
        return False, malware_definition, nearest_benign_similarity
    except Exception as e:
        print(f"An error occurred while scanning file {file_path}: {e}")
        return False, malware_definition, nearest_benign_similarity

def is_clamd_running():
    """Check if clamd is running."""
    result = subprocess.run(['sc', 'query', 'clamd'], capture_output=True, text=True)
    return "RUNNING" in result.stdout
 
def scan_file_with_clamd(file_path):
    """Scan file using clamd."""
    file_path = os.path.abspath(file_path)  # Get absolute path
    if not is_clamd_running():
        start_clamd_thread()  # Start clamd if it's not running

    result = subprocess.run(["clamdscan", file_path], capture_output=True, text=True)
    clamd_output = result.stdout
    print(f"Clamdscan output: {clamd_output}")

    if "ERROR" in clamd_output:
        print(f"Clamdscan reported an error: {clamd_output}")
        return "Clean"
    elif "FOUND" in clamd_output:
        match = re.search(r": (.+) FOUND", clamd_output)
        if match:
            virus_name = match.group(1).strip()
            return virus_name
    elif "OK" in clamd_output or "Infected files: 0" in clamd_output:
        return "Clean"
    else:
        print(f"Unexpected clamdscan output: {clamd_output}")
        return "Clean"

def verify_executable_signature(path):
    cmd = " " + f'"{path}"'
    command = "(Get-AuthenticodeSignature" + cmd + ").Status"
    process = subprocess.run(['Powershell', '-Command', command], stdout=subprocess.PIPE, encoding='utf-8')
    
    status = process.stdout.strip()
    
    if status in ["HashMismatch", "NotTrusted"]:
        return True
    else:
        return False

def scan_file_real_time(file_path):
    """Scan file in real-time using multiple engines."""
    logging.info(f"Started scanning file: {file_path}")

    try:
        # Skip scanning if the file is in the script directory
        if os.path.commonpath([file_path, script_dir]) == script_dir:
            logging.info(f"Skipping file in script directory: {file_path}")
            return False, "Clean"

        # Skip scanning if the file is an SQLite file
        if is_sqlite_file(file_path):
            logging.info(f"Skipping SQLite file: {file_path}")
            return False, "Clean"

        # Scan PE files with Static Machine Learning
        if is_pe_file(file_path):
            is_malicious, malware_definition, benign_score = scan_file_with_machine_learning_ai(file_path)
            if is_malicious:
                if benign_score < 0.93:
                    logging.warning(f"Infected file detected (ML): {file_path} - Virus: {malware_definition}")
                    return True, malware_definition
                elif benign_score >= 0.93:
                    logging.info(f"File is clean based on ML benign score: {file_path}")
                    return False, "Clean"
            logging.info(f"No malware detected by Machine Learning in file: {file_path}")

        # Scan with ClamAV
        try:
            result = scan_file_with_clamd(file_path)
            if result not in ("Clean", ""):
                logging.warning(f"Infected file detected (ClamAV): {file_path} - Virus: {result}")
                return True, result
            logging.info(f"No malware detected by ClamAV in file: {file_path}")
        except Exception as e:
            logging.error(f"An error occurred while scanning file with ClamAV: {file_path}. Error: {str(e)}")

        # Scan with YARA
        try:
            yara_result = yara_scanner.scan_data(file_path)
            
            if yara_result is not None and yara_result not in ("Clean", ""):
                logging.warning(f"Infected file detected (YARA): {file_path} - Virus: {yara_result}")
                # Add your GUI-related code here if necessary (e.g., adding items to a list widget)
                return True, yara_result

            logging.info(f"Scanned file with YARA: {file_path} - No viruses detected")
            return False, None
        
        except Exception as e:
            logging.error(f"An error occurred while scanning file with YARA: {file_path}. Error: {e}")
            return False, None

        # Scan PE files
        if is_pe_file(file_path):
            try:
                scan_result, virus_name = scan_pe_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    logging.warning(f"Infected file detected (PE): {file_path} - Virus: {virus_name}")
                    return True, virus_name
                logging.info(f"No malware detected in PE file: {file_path}")
            except PermissionError:
                logging.error(f"Permission error occurred while scanning PE file: {file_path}")
            except FileNotFoundError:
                logging.error(f"PE file not found error occurred while scanning PE file: {file_path}")
            except Exception as e:
                logging.error(f"An error occurred while scanning PE file: {file_path}. Error: {str(e)}")

        # Scan TAR files
        if tarfile.is_tarfile(file_path):
            try:
                scan_result, virus_name = scan_tar_file(file_path)
                if scan_result and virus_name not in ("Clean", "F", ""):
                    logging.warning(f"Infected file detected (TAR): {file_path} - Virus: {virus_name}")
                    return True, virus_name
                logging.info(f"No malware detected in TAR file: {file_path}")
            except PermissionError:
                logging.error(f"Permission error occurred while scanning TAR file: {file_path}")
            except FileNotFoundError:
                logging.error(f"TAR file not found error occurred while scanning TAR file: {file_path}")
            except Exception as e:
                logging.error(f"An error occurred while scanning TAR file: {file_path}. Error: {str(e)}")

        # Scan ZIP files
        if zipfile.is_zipfile(file_path):
            try:
                scan_result, virus_name = scan_zip_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    logging.warning(f"Infected file detected (ZIP): {file_path} - Virus: {virus_name}")
                    return True, virus_name
                logging.info(f"No malware detected in ZIP file: {file_path}")
            except PermissionError:
                logging.error(f"Permission error occurred while scanning ZIP file: {file_path}")
            except FileNotFoundError:
                logging.error(f"ZIP file not found error occurred while scanning ZIP file: {file_path}")
            except Exception as e:
                logging.error(f"An error occurred while scanning ZIP file: {file_path}. Error: {str(e)}")

        # Verify executable signature
        if is_pe_file(file_path) and verify_executable_signature(file_path):
            logging.warning(f"File has invalid signature: {file_path}")
            return True, "Invalid signature"

    except Exception as e:
        logging.error(f"An error occurred while scanning file: {file_path}. Error: {str(e)}")

    return False, "Clean"

def is_pe_file(file_path):
    """Check if the file at the specified path is a Portable Executable (PE) file."""
    if not os.path.exists(file_path):
        return False
    
    try:
        with open(file_path, 'rb') as file:
            pe = pefile.PE(data=file.read())
            return True
    except pefile.PEFormatError:
        return False
    except Exception as e:
        print(f"Error occurred while checking if file is PE: {e}")
        return False

def scan_pe_file(file_path):
    """Scan files within an exe file."""
    try:
        pe = pefile.PE(file_path)
        virus_names = ""
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry, 'directory'):
                for resource in entry.directory.entries:
                    if hasattr(resource, 'directory'):
                        for res in resource.directory.entries:
                            if hasattr(res, 'directory'):
                                for r in res.directory.entries:
                                    if hasattr(r, 'data'):
                                        data = pe.get_data(r.data.struct.OffsetToData, r.data.struct.Size)
                                        scan_result, virus_name = scan_file_real_time(data)
                                        if scan_result:
                                            virus_names.append(virus_name)
                                            # Return immediately if malware is detected
                                            return True, virus_names
        return False, virus_names
    except Exception as e:
        logging.error(f"Error scanning exe file: {file_path} - {str(e)}")
        return False, ""

def scan_zip_file(file_path):
    """Scan files within a zip archive."""
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()  # Create a temporary directory to extract files
        with zipfile.ZipFile(file_path, 'r') as zfile:
            zfile.extractall(temp_dir)  # Extract all files to temporary directory
            for root, _, files in os.walk(temp_dir):
                for file_name in files:
                    extracted_file_path = os.path.join(root, file_name)
                    scan_result, virus_name = scan_file_real_time(extracted_file_path)
                    if scan_result:
                        return True, virus_name
    except Exception as e:
        logging.error(f"Error scanning zip file: {file_path} - {str(e)}")
    finally:
        if temp_dir:
            # Try to remove the directory, with retries on failure
            for _ in range(5):
                try:
                    shutil.rmtree(temp_dir)
                    break  # If successful, exit the loop
                except PermissionError:
                    logging.warning(f"Permission error while deleting {temp_dir}. Retrying...")
                    time.sleep(1)  # Wait a bit before retrying
                except Exception as e:
                    logging.error(f"Unexpected error while deleting {temp_dir}: {e}")
                    break  # Exit the loop on unexpected errors
    return False, ""

def scan_tar_file(file_path):
    """Scan files within a tar archive."""
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()  # Create a temporary directory to extract files
        with tarfile.TarFile(file_path, 'r') as tar:
            tar.extractall(temp_dir)  # Extract all files to temporary directory
            for root, _, files in os.walk(temp_dir):
                for file_name in files:
                    extracted_file_path = os.path.join(root, file_name)
                    scan_result, virus_name = scan_file_real_time(extracted_file_path)
                    if scan_result:
                        return True, virus_name
    except Exception as e:
        logging.error(f"Error scanning tar file: {file_path} - {str(e)}")
    finally:
        if temp_dir:
            # Try to remove the directory, with retries on failure
            for _ in range(5):
                try:
                    shutil.rmtree(temp_dir)
                    break  # If successful, exit the loop
                except PermissionError:
                    logging.warning(f"Permission error while deleting {temp_dir}. Retrying...")
                    time.sleep(1)  # Wait a bit before retrying
                except Exception as e:
                    logging.error(f"Unexpected error while deleting {temp_dir}: {e}")
                    break  # Exit the loop on unexpected errors
    return False, ""
 
def notify_user(file_path, virus_name):
    notification = Notify()
    notification.title = "Malware Alert"
    notification.message = f"Malicious file detected: {file_path}\nVirus: {virus_name}"
    notification.send()

class YaraScanner:
    def scan_data(self, file_path):
        matched_rules = []

        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                data = file.read()
                
                # Check matches for compiled_rule (assuming compiled_rule is defined somewhere)
                if compiled_rule:
                    matches = compiled_rule.match(data=data)
                    if matches:
                        for match in matches:
                            if match.rule not in excluded_rules:
                                matched_rules.append(match.rule)
                            else:
                                logging.info(f"Rule {match.rule} is excluded.")
                
                # Check matches for yaraxtr_rule (loaded with yara_x)
                if yaraxtr_rule:
                    scanner = yara_x.Scanner(yaraxtr_rule)
                    results = scanner.scan(data=data)
                    if results.matching_rules:
                        for rule in results.matching_rules:
                            if hasattr(rule, 'identifier') and rule.identifier not in excluded_rules:
                                matched_rules.append(rule.identifier)
                            else:
                                logging.info(f"Rule {rule.identifier} is excluded.")

        # Return matched rules as the yara_result if not empty, otherwise return None
        return matched_rules if matched_rules else None

yara_scanner = YaraScanner()

antivirus_style = """
QWidget {
    background-color: #2b2b2b;
    color: #e0e0e0;
    font-family: Arial, sans-serif;
    font-size: 14px;
}

QPushButton {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #007bff, stop:0.8 #0056b3);
    color: white;
    border: 2px solid #007bff;
    padding: 4px 10px;  /* Adjusted padding */
    border-radius: 8px;  /* Adjusted border-radius */
    min-width: 70px;  /* Adjusted min-width */
    font-weight: bold;
    text-align: center;
    qproperty-iconSize: 16px;
}

QPushButton:hover {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #0056b3, stop:0.8 #004380);
    border-color: #0056b3;
}

QPushButton:pressed {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #004380, stop:0.8 #003d75);
    border-color: #004380;
}

QFileDialog {
    background-color: #2b2b2b;
    color: #e0e0e0;
}
"""

class AnalysisThread(QThread):
    result_signal = Signal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            print(f"Running analysis for: {self.file_path}")  # Debug statement
            result = perform_sandbox_analysis(self.file_path)
            print(f"Analysis result: {result}")  # Debug statement
            self.result_signal.emit(result)
        except Exception as e:
            error_message = f"An error occurred during sandbox analysis: {str(e)}"
            print(error_message)  # Debug statement
            self.result_signal.emit(error_message)

class WorkerSignals(QObject):
    success = Signal()
    failure = Signal()

class AntivirusUI(QWidget):
    folder_scan_finished = Signal()
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hydra Dragon Antivirus")
        self.stacked_widget = QStackedWidget()
        self.main_widget = QWidget()
        self.setup_main_ui()
        self.stacked_widget.addWidget(self.main_widget)
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.stacked_widget)
        self.setLayout(main_layout)
        # Set the window icon
        self.setWindowIcon(QIcon("assets/HydraDragonAV.png"))
        self.signals = WorkerSignals()
        self.signals.success.connect(self.show_success_message)
        self.signals.failure.connect(self.show_failure_message)

        # Automatically update definitions during initialization
        self.start_update_definitions_thread()

    def setup_main_ui(self):
        layout = QVBoxLayout()

        self.mbrfilter_button = QPushButton('Setup MBRFilter')
        self.mbrfilter_button.clicked.connect(setup_mbrfilter)
        layout.addWidget(self.mbrfilter_button)

        self.sandbox_button = QPushButton("Scan File")
        self.sandbox_button.clicked.connect(self.sandbox_analysis_for_file)
        layout.addWidget(self.sandbox_button)

        self.setLayout(layout)

    def sandbox_analysis_for_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File for Sandbox Analysis")
        print(f"Selected file path: {file_path}")  # Debug statement
        if isinstance(file_path, str) and file_path:
            self.run_analysis_thread(file_path)
        else:
            print(f"Invalid file path: {file_path}")

    def run_analysis_thread(self, file_path):
        self.analysis_thread = AnalysisThread(file_path)
        self.analysis_thread.result_signal.connect(self.display_result)
        self.analysis_thread.start()

    def display_result(self, result):
        print(f"Displaying result: {result}")  # Debug statement
        QMessageBox.information(self, "Sandbox Analysis Result", result)

    def show_success_message(self):
        QMessageBox.information(self, "Update Definitions", "Antivirus definitions updated successfully. Please restart clamd.")

    def show_failure_message(self):
        QMessageBox.critical(self, "Update Definitions", "Failed to update antivirus definitions.")

    def update_definitions(self):
        file_path = r"C:\Program Files\ClamAV\daily.cvd"
        
        # Check if the file exists
        if os.path.exists(file_path):
            # Get the file's modification time
            file_mod_time = os.path.getmtime(file_path)
            file_mod_time = datetime.fromtimestamp(file_mod_time)
            
            # Calculate the age of the file
            file_age = datetime.now() - file_mod_time
            
            # Check if the file is older than 12 hours
            if file_age > timedelta(hours=12):
                result = subprocess.run(["freshclam"], capture_output=True, text=True)
                if result.returncode == 0:
                    self.success.emit()
                    self.restart_clamd_thread()
                else:
                    self.failure.emit()
                    print(f"freshclam failed with output: {result.stdout}\n{result.stderr}")
            else:
                print("The daily.cvd file is not older than 12 hours. No update needed.")
        else:
            print("The daily.cvd file does not exist.")

    def restart_clamd_thread(self):
        threading.Thread(target=self.restart_clamd).start()

    def restart_clamd(self):
        if is_clamd_running():
            stop_result = subprocess.run(["sc", "stop", "clamd"], capture_output=True, text=True)
            if stop_result.returncode != 0:
                QMessageBox.critical(self, "ClamAV", "Failed to stop ClamAV.")
                return
        start_result = subprocess.run(["sc", "start", "clamd"], capture_output=True, text=True)
        if start_result.returncode == 0:
            QMessageBox.information(self, "ClamAV", "ClamAV restarted successfully.")
        else:
            QMessageBox.critical(self, "ClamAV", "Failed to start ClamAV.")

    def start_update_definitions_thread(self):
        threading.Thread(target=self.update_definitions).start()

# Regex for Snort alerts
alert_regex = re.compile(r'\[Priority: (\d+)\].*?\{(?:UDP|TCP)\} (\d+\.\d+\.\d+\.\d+):\d+ -> (\d+\.\d+\.\d+\.\d+):\d+')

# File paths and configurations
log_path = r"C:\Snort\log\alert.ids"
log_folder = r"C:\Snort\log"
snort_config_path = r"C:\Snort\etc\snort.conf"
sandboxie_path = r"C:\Program Files\Sandboxie\Start.exe"
device_args = [f"-i {i}" for i in range(1, 26)]  # Fixed device arguments
username = os.getlogin()
sandbox_folder = rf'C:\Sandbox\{username}\DefaultBox'
command = ["snort"] + device_args + ["-c", snort_config_path, "-A", "fast"]

# Custom flags for directory changes
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800

def monitor_sandbox(sandbox_path):
    hDir = win32file.CreateFile(
        sandbox_path,
        1,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )
    try:
        while True:
            results = win32file.ReadDirectoryChangesW(
                hDir,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY |
                FILE_NOTIFY_CHANGE_LAST_ACCESS |
                FILE_NOTIFY_CHANGE_CREATION |
                FILE_NOTIFY_CHANGE_EA |
                FILE_NOTIFY_CHANGE_STREAM_NAME |
                FILE_NOTIFY_CHANGE_STREAM_SIZE |
                FILE_NOTIFY_CHANGE_STREAM_WRITE,
                None,
                None
            )
            for action, file in results:
                pathToScan = os.path.join(sandbox_path, file)
                print(pathToScan)
                scan_and_warn(pathToScan)
    except Exception as e:
        print("An error occurred at monitor_sandbox:", e)
        logging.error(f"An error occurred at monitor_sandbox: {e}")
    finally:
        win32file.CloseHandle(hDir)

def process_alert(line):
    match = alert_regex.search(line)
    if match:
        priority = int(match.group(1))
        src_ip = match.group(2)
        dst_ip = match.group(3)
        logging.info(f"Alert detected: Priority {priority}, Source {src_ip}, Destination {dst_ip}")
        print(f"Alert detected: Priority {priority}, Source {src_ip}, Destination {dst_ip}")
        if priority == 1:
            logging.info(f"Potential malware detected: {line.strip()}")
            print(f"Potential malware detected from {src_ip} to {dst_ip} with priority {priority}")
            return True
    return False

def run_snort():    
    try:
        # Run snort without capturing output
        subprocess.run(command, check=True)
        
        logging.info("Snort completed analysis.")
        print("Snort completed analysis.")

    except subprocess.CalledProcessError as e:
        logging.error(f"Snort encountered an error: {e}")
        print(f"Snort encountered an error: {e}")

    except Exception as e:
        logging.error(f"Failed to run Snort: {e}")
        print(f"Failed to run Snort: {e}")

def scan_and_warn(file_path):
    logging.info(f"Scanning file: {file_path}")
    is_malicious, virus_name = scan_file_real_time(file_path)
    if is_malicious:
        logging.info(f"File {file_path} is malicious. Virus: {virus_name}")
        notify_user_thread = threading.Thread(target=notify_user, args=(file_path, virus_name))
        notify_user_thread.start()
    return is_malicious

def start_monitoring_sandbox(sandbox_path):
    sandbox_thread = threading.Thread(target=monitor_sandbox, args=(sandbox_path,))
    sandbox_thread.start()
    return sandbox_thread

def monitor_snort_log(log_path):
    with open(log_path, 'r') as log_file:
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file
        while True:
            line = log_file.readline()
            if not line:
                continue
            process_alert(line)

def clean_directory(directory_path):
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            logging.error(f'Failed to delete {file_path}. Reason: {e}')

def perform_sandbox_analysis(file_path):
    try:
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            raise ValueError(f"Expected str, bytes or os.PathLike object, not {type(file_path).__name__}")

        logging.info(f"Performing sandbox analysis on: {file_path}")

        file_path = os.path.normpath(file_path)
        if not os.path.isfile(file_path):
            logging.error(f"File does not exist: {file_path}")
            return f"File does not exist: {file_path}"

        # Clean sandbox and log folders
        clean_directory(sandbox_folder)
        clean_directory(log_folder)

        scan_warn_thread = threading.Thread(target=scan_and_warn, args=(file_path,))
        scan_warn_thread.start()

        sandbox_thread = threading.Thread(target=start_monitoring_sandbox, args=(sandbox_folder,))
        sandbox_thread.start()

        snort_thread = threading.Thread(target=run_snort)
        snort_thread.start()

        sandboxie_thread = threading.Thread(target=run_sandboxie, args=(file_path,))
        sandboxie_thread.start()

        # Monitor Snort log for new lines and process alerts
        snort_log_thread = threading.Thread(target=monitor_snort_log, args=(log_path,))
        snort_log_thread.start()

        scan_sandbox_thread = threading.Thread(target=scan_sandbox_folder, args=(sandbox_folder,))
        scan_sandbox_thread.start()


        time.sleep(600)  # Wait for 10 minutes (600 seconds)

        sandbox_thread.join()
        snort_thread.join()
        sandboxie_thread.join()
        snort_log_thread.join()

        results = "Sandbox analysis completed. Please check log."

        return results

    except Exception as e:
        logging.error(f"An error occurred during sandbox analysis: {e}")
        return f"An error occurred during sandbox analysis: {str(e)}"

def run_sandboxie(file_path):
    try:
        subprocess.run([sandboxie_path, '/box:DefaultBox', file_path], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run Sandboxie on {file_path}: {e}")

def scan_sandbox_folder(sandbox_folder):
    for root, _, files in os.walk(sandbox_folder):
        for file in files:
            file_path = os.path.join(root, file)
            scan_and_warn(file_path)

def main():
    try:
        app = QApplication(sys.argv)
        app.setStyleSheet(antivirus_style)  # Apply the style sheet
        main_gui = AntivirusUI()
        main_gui.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()