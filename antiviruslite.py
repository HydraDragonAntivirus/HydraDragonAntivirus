import sys
import os
import shutil
import subprocess
import threading
from platform import system as system_platform
from platform import architecture
import re
import json
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog,
    QListWidget, QListWidgetItem, QHBoxLayout, QMessageBox, QCheckBox, QStackedWidget,
    QComboBox, QDialog, QDialogButtonBox
)
from PySide6.QtCore import Qt, QObject, QThread, Signal, Slot
import sklearn
import joblib
import pefile
import zipfile
import tarfile
import yara
import psutil
from notifypy import Notify
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.modules['sklearn.externals.joblib'] = joblib
# Set script directory
script_dir = os.getcwd()

# Configure logging
log_directory = os.path.join(script_dir, "log")  # Replace with the path to your log directory
log_file = os.path.join(log_directory, "scan_directory.log")

if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Path to the config folder
config_folder_path = os.path.join(script_dir, "config")
if not os.path.exists(config_folder_path):
    os.makedirs(config_folder_path)

user_preference_file = os.path.join(config_folder_path, "user_preference.json")
quarantine_file_path = os.path.join(config_folder_path, "quarantine.json")
# Get the root directory of the system drive based on the platform
if system_platform() == 'Windows':
    system_drives = [drive.mountpoint for drive in psutil.disk_partitions()]
    if system_drives:
        folder_to_watch = system_drives
    else:
        folder_to_watch = os.path.expandvars("%systemdrive%")  # Default to %systemdrive% if no drives are detected
elif system_platform() in ['Linux', 'FreeBSD', 'Darwin']:
    folder_to_watch = "/"     # Root directory on Linux, FreeBSD, and macOS
else:
    folder_to_watch = "/"     # Default to root directory on other platforms

def activate_uefi_drive():
    # Check if the platform is Windows
    if system_platform() == 'Windows':
        mount_command = 'mountvol X: /S'  # Command to mount UEFI drive
        try:
            # Execute the mountvol command
            subprocess.run(mount_command, shell=True, check=True)
            print("UEFI drive activated!")
        except subprocess.CalledProcessError as e:
            print(f"Error mounting UEFI drive: {e}")
    else:
        print("You are not in the Windows. No need to mountvol X: /S")

# Call the UEFI function
activate_uefi_drive()

def save_preferences(preferences):
    with open(user_preference_file, 'w') as f:
        json.dump(preferences, f, indent=4)

def load_quarantine_data():
    if os.path.exists(quarantine_file_path):
        with open(quarantine_file_path, 'r') as f:
            data = json.load(f)
            # Ensure the data is a list
            if isinstance(data, list):
                return data
            else:
                return []
    else:
        # If the file doesn't exist, create it with an empty list
        with open(quarantine_file_path, 'w') as f:
            json.dump([], f)
        return []

quarantine_data = load_quarantine_data()
def save_quarantine_data(quarantine_data):
    with open(quarantine_file_path, 'w') as f:
        json.dump(quarantine_data, f, indent=4)

def quarantine_file(file_path, virus_name):
    quarantine_folder = os.path.abspath(os.path.join(os.getcwd(), "quarantine"))
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)
    try:
        # Extract the filename from the file_path
        filename = os.path.basename(file_path)
        # Create the destination path in the quarantine folder
        destination_path = os.path.join(quarantine_folder, filename)
        # Move the file to the quarantine folder
        shutil.move(file_path, destination_path)
        # Store the original file path in the quarantine data
        original_path = os.path.abspath(file_path)
        # Update the quarantine_data list with the new quarantine entry
        quarantine_data.append({"original_path": original_path, "quarantine_path": destination_path, "virus_name": virus_name})
        # Save the updated quarantine data
        save_quarantine_data(quarantine_data)
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to quarantine file: {str(e)}")

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

def load_preferences():
    if os.path.exists(user_preference_file):
        with open(user_preference_file, 'r') as f:
            return json.load(f)
    else:
        default_preferences = {
            "use_machine_learning": True,
            "use_clamav": True,
            "use_yara": True,
            "enable_pup_detection": True
        }
        save_preferences(default_preferences)
        return default_preferences

preferences = load_preferences()
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
    pyas_rule = yara.load(os.path.join(yara_folder_path, "PYAS.yrc"))
    print("YARA Rules Definitions loaded!")
except yara.Error as e:
    print(f"Error loading precompiled YARA rule: {e}")

# Add the setup MBRFilter button function
def setup_mbrfilter():
    if system_platform() != 'Windows':
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
        # Initialize default response
        malware_definition = "Benign"
        benign_score = 0.5  # Default benign score

        # Create a temporary copy of the file
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            shutil.copyfile(file_path, temp_file.name)
            temp_file.flush()  # Ensure all data is written to disk

            try:
                pe = pefile.PE(temp_file.name)
            except pefile.PEFormatError:
                return False, malware_definition, benign_score

            try:
                # Extract features
                file_info = extract_infos(temp_file.name)
                file_numeric_features = extract_numeric_features(temp_file.name)

                is_malicious = False
                malware_rank = None
                nearest_malicious_similarity = 0
                nearest_benign_similarity = 0

                # Compare with malicious features
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

                # Compare with benign features
                for benign_features in benign_numeric_features:
                    similarity = calculate_similarity(file_numeric_features, benign_features)
                    if similarity > nearest_benign_similarity:
                        nearest_benign_similarity = similarity

                # Calculate the benign score based on the nearest similarities
                benign_score = nearest_benign_similarity / (nearest_malicious_similarity + nearest_benign_similarity + 1e-5)

                # Determine final verdict
                if is_malicious:
                    if nearest_benign_similarity >= 0.9:
                        return False, malware_definition, benign_score
                    else:
                        return True, malware_definition, benign_score
                else:
                    return False, malware_definition, benign_score

            finally:
                # Ensure the PE file is closed
                pe.close()

    except Exception as e:
        print(f"An error occurred while scanning file {file_path}: {e}")
        return False, str(e), 0.5

def is_clamd_running():
    """Check if clamd is running."""
    if system_platform() in ['Linux', 'Darwin', 'FreeBSD']:
        result = subprocess.run(['pgrep', 'clamd'], capture_output=True, text=True)
        return result.returncode == 0
    elif system_platform() == 'Windows':
        result = subprocess.run(['sc', 'query', 'clamd'], capture_output=True, text=True)
        return "RUNNING" in result.stdout
    return False  # Unsupported platform

def start_clamd():
    """Start clamd service based on the platform."""
    if system_platform() == 'Windows':
        subprocess.run(["net", "start", "clamd"], shell=True)
    elif system_platform() in ['Linux', 'Darwin']:
        subprocess.run(["clamd"], shell=True)
    elif system_platform() == 'FreeBSD':
        subprocess.run(["service", "clamd", "start"])
    else:
        print("Unsupported platform for ClamAV")
        
def scan_file_with_clamd(file_path):
    """Scan file using clamd."""
    file_path = os.path.abspath(file_path)  # Get absolute path
    if not is_clamd_running():
        start_clamd()  # Start clamd if it's not running

    result = subprocess.run(["clamdscan", file_path], capture_output=True)
    clamd_output = result.stdout.decode('utf-8')  # Decode bytes to string
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

def kill_malicious_process(file_path):
    try:
        process_list = psutil.process_iter()
        for process in process_list:
            try:
                process_exe = process.exe()
                if process_exe and file_path == process_exe:
                    process.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        print(f"Error while terminating malicious process: {e}")

def scan_file_real_time(file_path):
    """Scan file in real-time using multiple engines."""
    logging.info(f"Started scanning file: {file_path}")

    # Scan with Machine Learning
    if preferences["use_machine_learning"]:
        is_malicious, malware_definition, benign_score = scan_file_with_machine_learning_ai(file_path)
        if is_malicious:
            if (malware_definition.startswith("PUA") or malware_definition.startswith("PUP")) and not preferences["enable_pup_detection"]:
                logging.info(f"Detected {malware_definition} but skipping as PUP detection is not enabled.")
                return False, "Clean"
            if benign_score < 0.93:
                logging.warning(f"Infected file detected (ML): {file_path} - Virus: {malware_definition}")
                return True, malware_definition
            elif benign_score >= 0.93:
                logging.info(f"File is clean based on ML benign score: {file_path}")
                return False, "Clean"
        logging.info(f"No malware detected by Machine Learning in file: {file_path}")

    # Scan with ClamAV
    if preferences["use_clamav"]:
        result = scan_file_with_clamd(file_path)
        if result not in ("Clean", ""):
            if (result.startswith("PUA") or result.startswith("PUP")) and not preferences["enable_pup_detection"]:
                logging.info(f"Detected {result} but skipping as PUP detection is not enabled.")
                return False, "Clean"
            logging.warning(f"Infected file detected (ClamAV): {file_path} - Virus: {result}")
            return True, result
        logging.info(f"No malware detected by ClamAV in file: {file_path}")

    # Scan with YARA
    if preferences["use_yara"]:
            yara_result = self.yara_scanner.static_analysis(file_path)
                
            # Ensure yara_result is a string
            if isinstance(yara_result, list):
                yara_result = ', '.join(yara_result)
                
            if yara_result not in ("Clean", ""):
                if (yara_result.startswith("PUA") or yara_result.startswith("PUP")) and not preferences["enable_pup_detection"]:
                    logging.info(f"Detected {yara_result} but skipping as PUP detection is not enabled.")
                    return False, "Clean"
                logging.warning(f"Infected file detected (YARA): {file_path} - Virus: {yara_result}")
                return True, yara_result
    # Scan PE files
    if is_pe_file(file_path):
        scan_result, virus_name = scan_pe_file(file_path)
        if scan_result and virus_name not in ("Clean", ""):
            if (virus_name.startswith("PUA") or virus_name.startswith("PUP")) and not preferences["enable_pup_detection"]:
                logging.info(f"Detected {virus_name} but skipping as PUP detection is not enabled.")
                return False, "Clean"
            logging.warning(f"Infected file detected (PE): {file_path} - Virus: {virus_name}")
            return True, virus_name
        logging.info(f"No malware detected in PE file: {file_path}")

    # Scan TAR files
    if tarfile.is_tarfile(file_path):
        scan_result, virus_name = scan_tar_file(file_path)
        if scan_result and virus_name not in ("Clean", "F", ""):
            if (virus_name.startswith("PUA") or virus_name.startswith("PUP")) and not preferences["enable_pup_detection"]:
                logging.info(f"Detected {virus_name} but skipping as PUP detection is not enabled.")
                return False, "Clean"
            logging.warning(f"Infected file detected (TAR): {file_path} - Virus: {virus_name}")
            return True, virus_name
        logging.info(f"No malware detected in TAR file: {file_path}")

    # Scan ZIP files
    if zipfile.is_zipfile(file_path):
        scan_result, virus_name = scan_zip_file(file_path)
        if scan_result and virus_name not in ("Clean", ""):
            if (virus_name.startswith("PUA") or virus_name.startswith("PUP")) and not preferences["enable_pup_detection"]:
                logging.info(f"Detected {virus_name} but skipping as PUP detection is not enabled.")
                return False, "Clean"
            logging.warning(f"Infected file detected (ZIP): {file_path} - Virus: {virus_name}")
            return True, virus_name
        logging.info(f"No malware detected in ZIP file: {file_path}")

    return False, "Clean"
   
def is_pe_file(file_path):
    """Check if the file is a PE file (executable)."""
    try:
        pefile.PE(file_path)
        return True
    except pefile.PEFormatError:
        return False

def scan_pe_file(file_path):
    """Scan files within an exe file."""
    try:
        pe = pefile.PE(file_path)
        virus_names = []
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
                                            break  # Stop scanning if malware is detected
                                if virus_names:
                                    break
                        if virus_names:
                            break
                if virus_names:
                    break
        if virus_names:
            return True, virus_names
    except Exception as e:
        logging.error(f"Error scanning exe file: {file_path} - {str(e)}")
    return False, ""

def scan_zip_file(file_path):
    """Scan files within a zip archive."""
    try:
        temp_dir = tempfile.mkdtemp()  # Create a temporary directory to extract files
        with zipfile.ZipFile(file_path, 'r') as zfile:
            zfile.extractall(temp_dir)  # Extract all files to temporary directory
            for root, _, files in os.walk(temp_dir):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    scan_result, virus_name = scan_file_real_time(file_path)
                    if scan_result:
                        return True, virus_name
    except Exception as e:
        logging.error(f"Error scanning zip file: {file_path} - {str(e)}")
    finally:
        shutil.rmtree(temp_dir)  # Cleanup temporary directory
    return False, ""

def scan_tar_file(file_path):
    """Scan files within a tar archive."""
    try:
        temp_dir = tempfile.mkdtemp()  # Create a temporary directory to extract files
        with tarfile.TarFile(file_path, 'r') as tar:
            tar.extractall(temp_dir)  # Extract all files to temporary directory
            for root, _, files in os.walk(temp_dir):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    scan_result, virus_name = scan_file_real_time(file_path)
                    if scan_result:
                        return True, virus_name
    except Exception as e:
        logging.error(f"Error scanning tar file: {file_path} - {str(e)}")
    finally:
        shutil.rmtree(temp_dir)  # Cleanup temporary directory
    return False, ""

class YaraScanner:
    def scan_data(self, file_path):
        matched_rules = []
        
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                data = file.read()
                
                # Check matches for compiled_rule
                if compiled_rule:
                    matches = compiled_rule.match(data=data)
                    if matches:
                        for match in matches:
                            if match.rule not in excluded_rules:
                                matched_rules.append(match.rule)
                        return matched_rules  # Return immediately if a match is found

                # Check matches for pyas_rule
                if pyas_rule:
                    matches = pyas_rule.match(data=data)
                    if matches:
                        for match in matches:
                            if match.rule not in excluded_rules:
                                matched_rules.append(match.rule)
                        return matched_rules  # Return immediately if a match is found

    def static_analysis(self, file_path):
        return self.scan_data(file_path)

yara_scanner = YaraScanner()

class ScanManager(QDialog):
    folder_scan_finished = Signal()
    memory_scan_finished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan Manager")
        self.setup_ui()
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.pause_event.set()
        self.preferences = load_preferences()
        # Connect signals to slots
        self.folder_scan_finished.connect(self.show_scan_finished_message)
        self.memory_scan_finished.connect(self.show_memory_scan_finished_message)
        # Initialize counters
        self.total_scanned = 0
        self.infected_files = 0
        self.clean_files = 0

    def setup_ui(self):
        main_layout = QVBoxLayout()

        self.pause_button = QPushButton("Pause Scan", self)
        self.pause_button.clicked.connect(self.pause_scanning)
        main_layout.addWidget(self.pause_button)

        self.stop_button = QPushButton("Stop Scan", self)
        self.stop_button.clicked.connect(self.stop_scanning)
        main_layout.addWidget(self.stop_button)

        self.resume_button = QPushButton("Resume Scan", self)
        self.resume_button.clicked.connect(self.resume_scanning)
        main_layout.addWidget(self.resume_button)

        self.quick_scan_button = QPushButton("Quick Scan")
        self.quick_scan_button.clicked.connect(self.quick_scan)
        main_layout.addWidget(self.quick_scan_button)

        self.full_scan_button = QPushButton("Full Scan")
        self.full_scan_button.clicked.connect(self.full_scan)
        main_layout.addWidget(self.full_scan_button)

        self.uefi_scan_button = QPushButton("UEFI Scan")
        self.uefi_scan_button.clicked.connect(self.uefi_scan)
        main_layout.addWidget(self.uefi_scan_button)

        self.scan_folder_button = QPushButton("Scan Folder")
        self.scan_folder_button.clicked.connect(self.scan_folder)
        main_layout.addWidget(self.scan_folder_button)

        self.scan_file_button = QPushButton("Scan File")
        self.scan_file_button.clicked.connect(self.scan_file)
        main_layout.addWidget(self.scan_file_button)

        self.scan_memory_button = QPushButton("Scan Memory")
        self.scan_memory_button.clicked.connect(self.scan_memory)
        main_layout.addWidget(self.scan_memory_button)

        # Save Results button
        self.save_results_button = QPushButton("Save Results")
        self.save_results_button.clicked.connect(self.save_results)
        main_layout.addWidget(self.save_results_button)

        self.detected_list_label = QLabel("Detected Threats:")
        main_layout.addWidget(self.detected_list_label)

        self.detected_list = QListWidget()
        main_layout.addWidget(self.detected_list)

        self.current_file_label = QLabel("Currently Scanning:")
        main_layout.addWidget(self.current_file_label)

        self.scanned_files_label = QLabel("Total Scanned Files: 0")
        main_layout.addWidget(self.scanned_files_label)

        self.infected_files_label = QLabel("Infected Files: 0")
        main_layout.addWidget(self.infected_files_label)

        self.clean_files_label = QLabel("Clean Files: 0")
        main_layout.addWidget(self.clean_files_label)

        self.action_button_layout = QHBoxLayout()

        self.quarantine_button = QPushButton("Quarantine")
        self.quarantine_button.clicked.connect(self.quarantine_selected)
        self.action_button_layout.addWidget(self.quarantine_button)

        self.skip_button = QPushButton("Skip")
        self.skip_button.clicked.connect(self.skip_selected)
        self.action_button_layout.addWidget(self.skip_button)

        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_selected)
        self.action_button_layout.addWidget(self.delete_button)

        self.action_combobox = QComboBox()
        self.action_combobox.addItems(["Quarantine All", "Delete All", "Skip All"])
        self.action_button_layout.addWidget(self.action_combobox)

        self.apply_action_button = QPushButton("Apply Action")
        self.apply_action_button.clicked.connect(self.apply_action)
        self.action_button_layout.addWidget(self.apply_action_button)

        self.kill_button = QPushButton("Kill Malicious Processes")
        self.kill_button.clicked.connect(self.kill_all_malicious_processes)
        self.action_button_layout.addWidget(self.kill_button)

        main_layout.addLayout(self.action_button_layout)
        self.setLayout(main_layout)

    def save_results(self):
        summary_data = self.collect_summary_data()
        threats_data = self.collect_threats_data()
        results_data = f"{summary_data}\n\n{threats_data}"
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(results_data)
                QMessageBox.information(self, "Success", "Results file saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save results file: {str(e)}")

    def collect_summary_data(self):
        summary_lines = []
        summary_lines.append("----------- SCAN SUMMARY -----------")
        summary_lines.append(f"Infected files: {self.infected_files}")
        summary_lines.append(f"Clean files: {self.clean_files}")
        summary_lines.append(f"Total files scanned: {self.total_scanned}")
        summary_lines.append("-----------------------------------")
        return "\n".join(summary_lines)

    def collect_threats_data(self):
        threats_lines = []
        threats_lines.append("----------- DETECTED THREATS -----------")
        for index in range(self.detected_list.count()):
            item = self.detected_list.item(index)
            threats_lines.append(item.text())
        return "\n".join(threats_lines)

    def reset_scan(self):
        self.total_scanned = 0
        self.infected_files = 0
        self.clean_files = 0
        self.update_scan_labels()
        self.detected_list.clear()
        self.current_file_label.setText("Currently Scanning:")

    def start_scan(self, path):
        self.reset_scan()
        self.thread = QThread()
        self.thread.run = lambda: self.scan(path)
        self.thread.finished.connect(self.folder_scan_finished.emit)  # Connect to signal emit
        self.thread.start()

    def scan(self, path):
        if os.path.isdir(path):
            self.scan_directory(path)
        else:
            self.scan_file_path(path)

    def get_uefi_folder(self):
        if system_platform() == 'Windows':
            return "X:\\"
        else:
            return "/boot/efi" if system_platform() in ['Linux', 'FreeBSD', 'Darwin'] else "/boot/efi"
    
    def scan_memory(self):
        self.reset_scan()

        def scan():
            scanned_files = set()  # Set to store scanned file paths
            detected_files = []

            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        process_name = proc.info['name']
                        executable_path = proc.info['exe']
                        # Check if the process has an executable path
                        if executable_path and executable_path not in scanned_files:
                            detected_files.append(executable_path)
                            scanned_files.add(executable_path)  # Add path to scanned files set
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                        print(f"Error while accessing process info: {e}")
            except Exception as e:
                print(f"Error while iterating over processes: {e}")

            # Send detected memory file paths for scanning
            with ThreadPoolExecutor(max_workers=1000) as executor:
                for file_path in detected_files:
                    executor.submit(self.scan_file_path, file_path)

            # Emit the signal when the memory scan is finished
            self.memory_scan_finished.emit()

        # Start the scan in a separate thread
        threading.Thread(target=scan).start()

    def scan_directory(self, directory):
        detected_threats = []
        clean_files = []

        def scan_file(file_path):
            with ThreadPoolExecutor(max_workers=1000) as executor:
                future = executor.submit(self.scan_file_path, file_path)
                is_infected, virus_name = future.result()

            if is_infected:
                # If the file is infected, add it to the detected list
                item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
                item.setData(Qt.UserRole, file_path)
                detected_threats.append((file_path, virus_name))
            else:
                clean_files.append(file_path)

        with ThreadPoolExecutor(max_workers=1000) as executor:
            futures = []
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    futures.append(executor.submit(scan_file, file_path))

            # Ensure all futures are completed
            for future in as_completed(futures):
                future.result()

        self.show_summary(detected_threats, clean_files)

    def show_summary(self, detected_threats, clean_files):
        num_detected = len(detected_threats)
        num_clean = len(clean_files)
        total_files = num_detected + num_clean

        logging.info(f"----------- SCAN SUMMARY -----------")
        logging.info(f"Infected files: {num_detected}")
        logging.info(f"Clean files: {num_clean}")
        logging.info(f"Total files scanned: {total_files}")
        logging.info("-----------------------------------")

    def scan_file_path(self, file_path):
        self.pause_event.wait()  # Wait if the scan is paused
        if self.stop_event.is_set():
            return False, "Scan stopped"
        
        # Show the currently scanned file
        self.current_file_label.setText(f"Currently Scanning: {file_path}")

        virus_name = ""

        if self.preferences["use_machine_learning"]:
            is_malicious, malware_definition, benign_score = scan_file_with_machine_learning_ai(file_path)
            if is_malicious and virus_name not in ["Clean", ""] and benign_score < 0.93:  
                virus_name = malware_definition
                item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
                item.setData(Qt.UserRole, file_path)
                self.detected_list.addItem(item)
                self.total_scanned += 1
                self.infected_files += 1
                self.update_scan_labels()
            elif benign_score >= 0.93:
                logging.info(f"File is clean based on ML benign score: {file_path}")
                self.total_scanned += 1
                self.clean_files += 1
                self.update_scan_labels()
                return False, ""

        if self.preferences["use_clamav"]:
            virus_name = scan_file_with_clamd(file_path)
            if virus_name != "Clean" and virus_name != "":
                logging.warning(f"Scanned file with ClamAV: {file_path} - Virus: {virus_name}")
                item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
                item.setData(Qt.UserRole, file_path)
                self.detected_list.addItem(item)
                self.total_scanned += 1
                self.infected_files += 1
                self.update_scan_labels()
                return True, virus_name

        if self.preferences["use_yara"]:
            yara_result = yara_scanner.static_analysis(file_path)
            if yara_result != "Clean" and yara_result != "":
                virus_name = ', '.join(yara_result) if isinstance(yara_result, list) else yara_result
                if virus_name != "":
                    logging.warning(f"Scanned file with YARA: {file_path} - Virus: {virus_name}")
                    item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
                    item.setData(Qt.UserRole, file_path)
                    self.detected_list.addItem(item)
                    self.total_scanned += 1
                    self.infected_files += 1
                    self.update_scan_labels()
                    return True, virus_name

        # Scan PE files
        if is_pe_file(file_path):
             scan_result, pe_virus_name = scan_pe_file(file_path)
             if scan_result != "Clean" or scan_result == "":
                virus_name = pe_virus_name
                if virus_name != "":
                   logging.warning(f"Scanned PE file: {file_path} - Virus: {virus_name}")
                   item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
                   item.setData(Qt.UserRole, file_path)
                   self.detected_list.addItem(item)
                   self.total_scanned += 1
                   self.infected_files += 1
                   self.update_scan_labels()
                   return True, virus_name

        # Scan TAR files
        if tarfile.is_tarfile(file_path):
            scan_result, tar_virus_name = scan_tar_file(file_path)
            if scan_result != "Clean" or scan_result == "":
                virus_name = tar_virus_name
                if virus_name != "":
                    logging.warning(f"Scanned TAR file: {file_path} - Virus: {virus_name}")
                    item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
                    item.setData(Qt.UserRole, file_path)
                    self.detected_list.addItem(item)
                    self.total_scanned += 1
                    self.infected_files += 1
                    self.update_scan_labels()
                    return True, virus_name

        # Scan ZIP files
        if zipfile.is_zipfile(file_path):
            scan_result, zip_virus_name = scan_zip_file(file_path)
            if scan_result != "Clean" or scan_result == "":
                virus_name = zip_virus_name
                if virus_name != "Clean" and virus_name != "":
                    logging.warning(f"Scanned ZIP file: {file_path} - Virus: {virus_name}")
                    item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
                    item.setData(Qt.UserRole, file_path)
                    self.detected_list.addItem(item)
                    self.total_scanned += 1
                    self.infected_files += 1
                    self.update_scan_labels()
                    return True, virus_name

        if virus_name != "Clean" and virus_name != "":
            item = QListWidgetItem(f"Scanned file: {file_path} - Virus: {virus_name}")
            item.setData(Qt.UserRole, file_path)
            self.detected_list.addItem(item)
            self.total_scanned += 1
            self.infected_files += 1
            self.update_scan_labels()
            return True, virus_name
        else:
            logging.info(f"File is clean: {file_path}")
            self.total_scanned += 1
            self.clean_files += 1
            self.update_scan_labels()
            return False, ""

    def full_scan(self):
        if self.system_platform() == 'Windows':  # Windows platform
            disk_partitions = [drive.mountpoint for drive in psutil.disk_partitions()]
            for drive in disk_partitions:
                self.start_scan(drive)
                self.folder_scan_finished.emit()
        else:
            self.start_scan(self.folder_to_watch)

    def quick_scan(self):
        user_folder = os.path.expanduser("~")  # Get user's home directory
        self.start_scan(user_folder)

    def uefi_scan(self):
        folder_path = self.get_uefi_folder()
        self.start_scan(folder_path)

    def scan_folder(self):
        folder_path = QFileDialog.getExistingDirectory(None, "Select Folder to Scan")
        if folder_path:
            self.start_scan(folder_path)

    def scan_file(self):
        file_path, _ = QFileDialog.getOpenFileName(None, "Select File to Scan")
        if file_path:
            self.start_scan(file_path)

    def update_scan_labels(self):
        self.scanned_files_label.setText(f"Total Scanned Files: {self.total_scanned}")
        self.infected_files_label.setText(f"Infected Files: {self.infected_files}")
        self.clean_files_label.setText(f"Clean Files: {self.clean_files}")

    def pause_scanning(self):
        self.pause_event.clear()
        logging.info("Scanning paused")

    def resume_scanning(self):
        self.pause_event.set()
        logging.info("Scanning resumed")
        
    def stop_scanning(self):
        self.stop_event.set()
        logging.info("Scanning stopped")
        
    def reset_stop_event(self):
        self.stop_event.clear()
         
    def show_scan_finished_message(self):
        QMessageBox.information(self, "Scan Finished", "File scan has finished.")

    def show_memory_scan_finished_message(self):
        QMessageBox.information(self, "Scan Finished", "Memory scan has finished.")

    def apply_action(self):
        action = self.action_combobox.currentText()
        if action == "Quarantine All":
            self.quarantine_all_files()
        elif action == "Delete All":
            self.delete_all_files()
        elif action == "Skip All":
            self.skip_all_files()

    def handle_detected_files(self, quarantine=True):
        files_to_process = []
        for index in range(self.detected_list.count()):
            item = self.detected_list.item(index)
            file_path = item.data(Qt.UserRole)
            files_to_process.append(file_path)

        # Quarantine or delete all files simultaneously
        with ThreadPoolExecutor() as executor:
            if quarantine:
                executor.map(quarantine_file, files_to_process)
            else:
                executor.map(safe_remove, files_to_process)

        self.detected_list.clear()

    def quarantine_selected(self):
        selected_items = self.detected_list.selectedItems()
        for item in selected_items:
            file_path = item.data(Qt.UserRole)
            virus_name = item.text().split("-")[-1].strip()
            quarantine_file(file_path, virus_name)

    def skip_selected(self):
        selected_items = self.detected_list.selectedItems()
        for item in selected_items:
            item_index = self.detected_list.row(item)
            self.detected_list.takeItem(item_index)

    def delete_selected(self):
        selected_items = self.detected_list.selectedItems()
        for item in selected_items:
            file_path = item.data(Qt.UserRole)
            try:
                os.remove(file_path)
                self.detected_list.takeItem(self.detected_list.row(item))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete file: {str(e)}")

    def quarantine_all_files(self):
        self.handle_detected_files(quarantine=True)

    def delete_all_files(self):
        self.handle_detected_files(quarantine=False)

    def skip_all_files(self):
        self.detected_list.clear()

    def kill_all_malicious_processes(self):
        detected_threats = [self.detected_list.item(i) for i in range(self.detected_list.count())]
        malicious_processes = []

        for item in detected_threats:
            file_path = item.data(Qt.UserRole)
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if proc.info['exe'] and os.path.abspath(proc.info['exe']) == os.path.abspath(file_path):
                        malicious_processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                print(f"Error accessing process: {e}")

        for proc in malicious_processes:
            try:
                proc.kill()
                print(f"Killed process: {proc.info['pid']} ({proc.info['name']})")
            except psutil.NoSuchProcess:
                print(f"Process already killed: {proc.info['pid']} ({proc.info['name']})")
            except psutil.AccessDenied:
                print(f"Access denied when trying to kill process: {proc.info['pid']} ({proc.info['name']})")

class WorkerSignals(QObject):
    success = Signal()
    failure = Signal()

class AntivirusUI(QWidget):
    folder_scan_finished = Signal()
    # Define a new signal for memory scan finished
    memory_scan_finished = Signal()
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
        # Define pause_event and stop_event attributes
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.signals = WorkerSignals()
        self.signals.success.connect(self.show_success_message)
        self.signals.failure.connect(self.show_failure_message)

    def setup_main_ui(self):
        layout = QVBoxLayout()

        # Add the setup MBRFilter button only if on Windows
        if system_platform() == 'Windows':
            self.mbrfilter_button = QPushButton('Setup MBRFilter')
            self.mbrfilter_button.clicked.connect(setup_mbrfilter)
            layout.addWidget(self.mbrfilter_button)

        self.start_clamd_button = QPushButton("Start ClamAV")
        self.start_clamd_button.clicked.connect(start_clamd)
        layout.addWidget(self.start_clamd_button)

        self.preferences_button = QPushButton("Preferences")
        self.preferences_button.clicked.connect(self.show_preferences)
        layout.addWidget(self.preferences_button)

        self.scan_manager_button = QPushButton("Scan Manager")  # Add Scan Manager button
        self.scan_manager_button.clicked.connect(self.show_scan_manager)
        layout.addWidget(self.scan_manager_button)

        self.quarantine_button = QPushButton("Quarantine Manager")
        self.quarantine_button.clicked.connect(self.manage_quarantine)
        layout.addWidget(self.quarantine_button)

        self.update_definitions_button = QPushButton("Update Definitions")
        self.update_definitions_button.clicked.connect(self.update_definitions)
        layout.addWidget(self.update_definitions_button)

        self.setLayout(layout)

    def show_success_message(self):
        QMessageBox.information(self, "Update Definitions", "Antivirus definitions updated successfully.")

    def show_failure_message(self):
        QMessageBox.critical(self, "Update Definitions", "Failed to update antivirus definitions.")

    def show_scan_manager(self):
        scan_manager = ScanManager(self)
        scan_manager.show()

    def show_preferences(self):
        preferences_dialog = PreferencesDialog(self)
        if preferences_dialog.show() == QDialog.Accepted:
            global preferences
            preferences["use_machine_learning"] = preferences_dialog.use_machine_learning_checkbox.isChecked()
            preferences["use_clamav"] = preferences_dialog.use_clamav_checkbox.isChecked()
            preferences["use_yara"] = preferences_dialog.use_yara_checkbox.isChecked()
            preferences["enable_pup_detection"] = preferences_dialog.enable_pup_detection_checkbox.isChecked()  # Save PUP detection preference
            save_preferences(preferences)

    def manage_quarantine(self):
        quarantine_manager = QuarantineManager(self)
        quarantine_manager.show()

    def update_definitions(self):
        def run_update():
            result = subprocess.run(["freshclam"], capture_output=True)
            if result.returncode == 0:
                self.signals.success.emit()
            else:
                self.signals.failure.emit()

        update_thread = threading.Thread(target=run_update)
        update_thread.start()

class PreferencesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        layout = QVBoxLayout()

        self.use_clamav_checkbox = QCheckBox("Use ClamAV Engine")
        self.use_clamav_checkbox.setChecked(preferences["use_clamav"])
        layout.addWidget(self.use_clamav_checkbox)

        self.use_yara_checkbox = QCheckBox("Use YARA Engine")
        self.use_yara_checkbox.setChecked(preferences["use_yara"])
        layout.addWidget(self.use_yara_checkbox)

        self.use_machine_learning_checkbox = QCheckBox("Use Machine Learning AI Engine")
        self.use_machine_learning_checkbox.setChecked(preferences["use_machine_learning"])
        layout.addWidget(self.use_machine_learning_checkbox)

        self.enable_pup_detection_checkbox = QCheckBox("Enable PUP Detection")
        self.enable_pup_detection_checkbox.setChecked(preferences["enable_pup_detection"])
        layout.addWidget(self.enable_pup_detection_checkbox)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)        

    def toggle_real_time_protection(self, state):
        preferences["real_time_protection"] = (state == Qt.Checked)
        save_preferences(preferences)
        if state == Qt.Checked:
            self.start_real_time_protection()
        else:
            self.stop_real_time_protection()

    def toggle_real_time_web_protection(self, state):
        preferences["real_time_web_protection"] = (state == Qt.Checked)
        save_preferences(preferences)
        if state == Qt.Checked:
            self.start_real_time_web_protection()
        else:
            self.stop_real_time_web_protection()

    def accept(self):
        preferences["use_clamav"] = self.use_clamav_checkbox.isChecked()
        preferences["use_yara"] = self.use_yara_checkbox.isChecked()
        preferences["use_machine_learning"] = self.use_machine_learning_checkbox.isChecked()
        preferences["real_time_protection"] = self.real_time_protection_checkbox.isChecked()
        preferences["real_time_web_protection"] = self.real_time_web_protection_checkbox.isChecked()
        
        save_preferences(preferences)
        super().accept()

class QuarantineManager(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Quarantine Manager")
        layout = QVBoxLayout()

        self.quarantine_list = QListWidget()
        for entry in quarantine_data:
            item = QListWidgetItem(f"{entry['original_path']} - Virus: {entry['virus_name']}")
            item.setData(Qt.UserRole, entry['original_path'])
            self.quarantine_list.addItem(item)
        layout.addWidget(self.quarantine_list)

        self.action_button_layout = QHBoxLayout()

        self.restore_button = QPushButton("Restore Selected")
        self.restore_button.clicked.connect(self.restore_selected)
        self.action_button_layout.addWidget(self.restore_button)

        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.clicked.connect(self.delete_selected)
        self.action_button_layout.addWidget(self.delete_button)

        self.restore_all_button = QPushButton("Restore All")
        self.restore_all_button.clicked.connect(self.restore_all)
        self.action_button_layout.addWidget(self.restore_all_button)

        self.delete_all_button = QPushButton("Delete All")
        self.delete_all_button.clicked.connect(self.delete_all_files_quar)
        self.action_button_layout.addWidget(self.delete_all_button)

        layout.addLayout(self.action_button_layout)

        self.setLayout(layout)

    def delete_all_files_quar(self):
        save_quarantine_data(quarantine_data)
        self.quarantine_list.clear()

    def restore_selected(self):
        selected_items = self.quarantine_list.selectedItems()
        for item in selected_items:
            file_path = item.data(Qt.UserRole)
            try:
                # Find the entry in quarantine_data corresponding to the selected file
                selected_entry = next(entry for entry in quarantine_data if entry['quarantine_path'] == file_path)
                original_path = selected_entry['original_path']
                # Restore the file to its original location
                shutil.move(file_path, original_path)
                # Remove the item from the list widget
                self.quarantine_list.takeItem(self.quarantine_list.row(item))
                # Remove the entry from quarantine_data
                quarantine_data.remove(selected_entry)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to restore file: {str(e)}")
        # Save the updated quarantine data
        save_quarantine_data(quarantine_data)

    def delete_selected(self):
        selected_items = self.quarantine_list.selectedItems()
        for item in selected_items:
            file_path = item.data(Qt.UserRole)
            try:
                os.remove(file_path)
                self.quarantine_list.takeItem(self.quarantine_list.row(item))
                quarantine_data = [entry for entry in quarantine_data if entry['file_path'] != file_path]
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete file: {str(e)}")
        save_quarantine_data(quarantine_data)

    def restore_all(self):
        for entry in quarantine_data:
            file_path = entry['file_path']
            try:
                shutil.move(file_path, os.path.join(os.getcwd(), os.path.basename(file_path)))
                self.quarantine_list.clear()
                quarantine_data = []
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to restore file: {str(e)}")
        save_quarantine_data(quarantine_data)

def main():
    try:
        app = QApplication(sys.argv)
        main_gui = AntivirusUI()

        scan_manager = ScanManager()

        # Connect signals to the ScanManager's slots
        scan_manager.folder_scan_finished.connect(scan_manager.show_scan_finished_message)
        scan_manager.memory_scan_finished.connect(scan_manager.show_memory_scan_finished_message)

        main_gui.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()