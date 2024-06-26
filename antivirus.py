import sys
import os
import shutil
import subprocess
import threading
from platform import architecture
import re
import json
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QStackedWidget
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
import winreg
from scapy.all import IP, IPv6, DNS, DNSQR, DNSRR, sniff

sys.modules['sklearn.externals.joblib'] = joblib
# Set script directory
script_dir = os.getcwd()
# Configure logging
log_directory = os.path.join(script_dir, "log")
log_file = os.path.join(log_directory, "antivirus.log")
# Counter for ransomware detection
ransomware_detection_count = 0 
has_warned_ransomware = False  # Flag to check if ransomware warning has been issued

if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

main_file_path = None

fileTypes = ['.pyd', '.elf', '.ps1', '.bas', '.bat', '.chm', '.cmd', '.com', '.cpl', '.dll', '.exe', '.msc', '.ocx', '.pcd', '.pif', '.reg', '.scr', '.sct', '.url', '.vbe', '.wsc', '.wsf', '.wsh', '.ct', '.t', '.input', '.war', '.jspx', '.tmp', '.dump', '.pwd', '.w', '.cfg', '.psd1', '.psm1', '.ps1xml', '.clixml', '.psc1', '.pssc', '.www', '.rdp', '.msi', '.dat', '.contact', '.settings', '.odt', '.jpg', '.mka','shtml', '.mhtml', '.oqy', '.png', '.csv', '.py', '.sql', '.mdb', '.html', '.htm', '.xml', '.psd', '.pdf', '.xla', '.cub', '.dae', '.indd', '.cs', '.mp3', '.mp4', '.dwg', '.rar', '.mov', '.rtf', '.bmp', '.mkv', '.avi', '.apk', '.lnk', '.dib', '.dic', '.dif', '.divx', '.iso', '.7zip', '.ace', '.arj', '.bz2', '.cab', '.gzip', '.lzh', '.jpeg', '.xz', '.mpeg', '.torrent', '.mpg', '.core', '.pdb', '.ico', '.pas', '.db', '.wmv', '.swf', '.cer', '.bak', '.backup', '.accdb', '.bay', '.p7c', '.exif', '.vss', '.raw', '.m4a', '.wma', '.flv', '.sie', '.sum', '.ibank', '.wallet', '.css', '.js', '.rb', '.xlsm', '.xlsb', '.7z', '.cpp', '.java', '.jpe', '.ini', '.blob', '.wps', '.wav', '.3gp', '.webm', '.m4v', '.amv', '.m4p', '.svg', '.ods', '.bk', '.vdi', '.vmdk', '.accde', '.json', '.gif', '.gz', '.m1v', '.sln', '.pst', '.obj', '.xlam', '.djvu', '.inc', '.cvs', '.dbf', '.tbi', '.wpd', '.dot', '.dotx', '.xltx', '.pptm', '.potx', '.potm', '.xlw', '.xps', '.xsd', '.xsf', '.xsl', '.kmz', '.accdr', '.stm', '.accdt', '.ppam', '.pps', '.ppsm', '.1cd', '.3ds', '.3fr', '.3g2', '.accda', '.accdc', '.accdw', '.adp', '.ai', '.ai3', '.ai4', '.ai5', '.ai6', '.ai7', '.ai8', '.arw', '.ascx', '.asm', '.asmx', '.avs', '.bin', '.cfm', '.dbx', '.dcm', '.dcr', '.pict', '.rgbe', '.dwt', '.f4v', '.exr', '.kwm', '.max', '.mda', '.mde', '.mdf', '.mdw', '.mht', '.mpv', '.msg', '.myi', '.nef', '.odc', '.geo', '.swift', '.odm', '.odp', '.oft', '.orf', '.pfx', '.p12', '.pls', '.safe', '.tab', '.vbs', '.xlk', '.xlm', '.xlt', '.xltm', '.svgz', '.slk', '.dmg', '.ps', '.psb', '.tif', '.rss', '.key', '.vob', '.epsp', '.dc3', '.iff', '.onepkg', '.onetoc2', '.opt', '.p7b', '.pam', '.r3d', '.pkg', '.yml', '.old', '.thmx', '.keytab', '.h', '.php', '.c', '.zip,' '.log', '.log1', '.log2', '.tm', '.blf', '.uic', '.widget-plugin', '.regtrans-ms', '.efi']

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
ip_addresses_path = os.path.join(script_dir, "website", "IP_Addresses.txt")
ipv6_addresses_path = os.path.join(script_dir, "website", "ipv6.txt")
domains_path = os.path.join(script_dir, "website", "Domains.txt")
ip_addresses_signatures_data = {}
ipv6_addresses_signatures_data = {}
domains_signatures_data = {}

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

def load_data():
    try:
        # Load IPv4 addresses
        with open(ip_addresses_path, 'r') as ip_file:
            ip_addresses = ip_file.read().splitlines()
            ip_addresses_signatures_data = {ip: "" for ip in ip_addresses}

        # Load IPv6 addresses
        with open(ipv6_addresses_path, 'r') as ipv6_file:
            ipv6_addresses = ipv6_file.read().splitlines()
            ipv6_addresses_signatures_data = {ipv6: "" for ipv6 in ipv6_addresses}

        print("IP Addresses (ipv4, ipv6) loaded successfully!")
    except Exception as e:
        print(f"Error loading IP Addresses: {e}")

    try:
        # Load domains
        with open(domains_path, 'r') as domains_file:
            domains = domains_file.read().splitlines()
            domains_signatures_data = {domain: "" for domain in domains}
        print("Domains loaded successfully!")
    except Exception as e:
        print(f"Error loading Domains from {DOMAINS_PATH}: {e}")

    print("Domain and IPv4 IPv6 signatures loaded successfully!")

def is_mbrfilter_installed():
    # This function checks the Windows Registry for the presence of MBRFilter.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\MBRFilter")
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"Error checking MBRFilter installation: {e}")
        return False

def setup_mbrfilter():
    # Check if MBRFilter is already installed
    if is_mbrfilter_installed():
        print("MBRFilter is already installed.")
        return
    
    # Check system architecture
    arch = architecture()[0]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if arch == '64bit':
        mbrfilter_path = os.path.join(script_dir, "mbrfilter", "x64", "MBRFilter.inf")
    else:
        mbrfilter_path = os.path.join(script_dir, "mbrfilter", "x86", "MBRFilter.inf")

    if os.path.exists(mbrfilter_path):
        try:
            # Run infdefaultinstall.exe to setup MBRFilter
            result = subprocess.run(["infdefaultinstall.exe", mbrfilter_path], capture_output=True, text=True, check=True)
            print("MBRFilter has been setup successfully.")
        except subprocess.CalledProcessError as e:
            error_message = e.stderr if e.stderr else str(e)
            if "dijital imza" in error_message or "digital signature" in error_message:
                error_message += "\n\nThe INF file does not contain a digital signature, which is required for 64-bit Windows."
            print(f"Failed to setup MBRFilter: {error_message}")
    else:
        print(f"MBRFilter.inf not found at {mbrfilter_path}.")
     
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
 
def restart_clamd_thread():
    threading.Thread(target=self.restart_clamd).start()

def restart_clamd():
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

def scan_file_with_clamd(file_path):
    """Scan file using clamd."""
    file_path = os.path.abspath(file_path)  # Get absolute path
    if not is_clamd_running():
        restart_clamd_thread()  # Start clamd if it's not running

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

def restart_clamd_if_not_running():
    try:
        if not is_clamd_running():
            restart_clamd_thread()  # Start clamd if it's not running
    except Exception as e:
        logging.error(f"An error occurred while restarting clamd: {e}")
        print(f"An error occurred while restarting clamd: {e}")

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

def notify_user_startup(file_path, virus_name):
    notification = Notify()
    notification.title = "Startup Malware Alert"
    notification.message = f"Suspicious startup file detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_uefi(file_path, virus_name):
    notification = Notify()
    notification.title = "UEFI Malware Alert"
    notification.message = f"Suspicious UEFI file detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_ransomware(file_path, virus_name):
    notification = Notify()
    notification.title = "Ransomware Alert"
    notification.message = f"Potential ransomware detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_worm(file_path, virus_name):
    notification = Notify()
    notification.title = "Worm Alert"
    notification.message = f"Potential worm detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_for_web(ip_address=None, dst_ip_address=None):
    notification = Notify()
    notification.title = "Malware or Phishing Alert"
    if ip_address and dst_ip_address:
        notification.message = f"Phishing or Malicious activity detected:\nIP Addresses involved:\nSource: {ip_address}\nDestination: {dst_ip_address}"
    elif ip_address:
        notification.message = f"Phishing or Malicious activity detected:\nIP Address: {ip_address}"
    elif dst_ip_address:
        notification.message = f"Phishing or Malicious activity detected:\nIP Address: {dst_ip_address}"
    else:
        notification.message = "Phishing or Malicious activity detected"
    notification.send()

def is_local_ip(ip):
    if re.match(r'^192\.168\.\d{1,3}\.\d{1,3}$', ip):
        return True
    if re.match(r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return True
    if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$', ip):
        return True
    return False

class RealTimeWebProtectionHandler:
    def __init__(self):
        self.scanned_domains = set()
        self.scanned_ipv4_addresses = set()
        self.scanned_ipv6_addresses = set()

    def scan_domain(self, domain):
        if domain in self.scanned_domains:
            logging.info(f"Domain {domain} already scanned, skipping.")
            return
        self.scanned_domains.add(domain)

        message = f"Scanning domain: {domain}"
        logging.info(message)
        print(message)
        parts = domain.split(".")
        if len(parts) < 3:
            main_domain = domain
        else:
            main_domain = ".".join(parts[-2:])

        for parent_domain in domains_signatures_data:
            if main_domain == parent_domain or main_domain.endswith(f".{parent_domain}"):
                message = f"Main domain {main_domain} or its parent domain {parent_domain} matches the signatures."
                logging.info(message)
                print(message)
                notify_user_for_web(domain=main_domain)
                return

    def scan_ip_address(self, ip_address, is_ipv6=False):
        if is_ipv6:
            if ip_address in self.scanned_ipv6_addresses:
                logging.info(f"IPv6 address {ip_address} already scanned, skipping.")
                return
            self.scanned_ipv6_addresses.add(ip_address)
        else:
            if ip_address in self.scanned_ipv4_addresses:
                logging.info(f"IPv4 address {ip_address} already scanned, skipping.")
                return
            self.scanned_ipv4_addresses.add(ip_address)

        if is_local_ip(ip_address):
            message = f"Skipping local IP address: {ip_address}"
            logging.info(message)
            print(message)
            return
        
        message = f"Scanning IP address: {ip_address}"
        logging.info(message)
        print(message)
        if is_ipv6 and ip_address in ipv6_addresses_signatures_data:
            message = f"IPv6 address {ip_address} matches the signatures."
            logging.info(message)
            print(message)
            notify_user_for_web(ip_address=ip_address)
        elif ip_address in ip_addresses_signatures_data:
            message = f"IPv4 address {ip_address} matches the signatures."
            logging.info(message)
            print(message)
            notify_user_for_web(ip_address=ip_address)

    def on_packet_received(self, packet):
        if IP in packet:
            self.handle_ipv4(packet)
        elif IPv6 in packet:
            self.handle_ipv6(packet)

    def handle_ipv4(self, packet):
        if DNS in packet:
            if packet[DNS].qd:
                for i in range(packet[DNS].qdcount):
                    query_name = packet[DNSQR][i].qname.decode().rstrip('.')
                    self.scan_domain(query_name)
                    message = f"DNS Query (IPv4): {query_name}"
                    logging.info(message)
                    print(message)
            if packet[DNS].an:
                for i in range(packet[DNS].ancount):
                    answer_name = packet[DNSRR][i].rrname.decode().rstrip('.')
                    self.scan_domain(answer_name)
                    message = f"DNS Answer (IPv4): {answer_name}"
                    logging.info(message)
                    print(message)

        # Scan IPv4 addresses
        self.scan_ip_address(packet[IP].src)
        self.scan_ip_address(packet[IP].dst)

    def handle_ipv6(self, packet):
        if DNS in packet:
            if packet[DNS].qd:
                for i in range(packet[DNS].qdcount):
                    query_name = packet[DNSQR][i].qname.decode().rstrip('.')
                    self.scan_domain(query_name)
                    message = f"DNS Query (IPv6): {query_name}"
                    logging.info(message)
                    print(message)
            if packet[DNS].an:
                for i in range(packet[DNS].ancount):
                    answer_name = packet[DNSRR][i].rrname.decode().rstrip('.')
                    self.scan_domain(answer_name)
                    message = f"DNS Answer (IPv6): {answer_name}"
                    logging.info(message)
                    print(message)

        # Scan IPv6 addresses
        self.scan_ip_address(packet[IPv6].src, is_ipv6=True)
        self.scan_ip_address(packet[IPv6].dst, is_ipv6=True)


class RealTimeWebProtectionObserver:
    def __init__(self):
        self.handler = RealTimeWebProtectionHandler()
        self.is_started = False
        self.thread = None

    def start(self):
        if not self.is_started:
            self.thread = threading.Thread(target=self.start_sniffing)
            self.thread.start()
            self.is_started = True
            message = "Real-time web protection observer started"
            logging.info(message)
            print(message)

    def stop(self):
        if self.is_started:
            self.thread.join()  # Wait for the thread to finish
            self.is_started = False
            message = "Real-time web protection observer stopped"
            logging.info(message)
            print(message)

    def start_sniffing(self):
        # Define a custom filter to exclude localhost and local IPs
        filter_expression = f"(tcp or udp)"
        sniff(filter=filter_expression, prn=self.handler.on_packet_received, store=0)

web_protection_observer = RealTimeWebProtectionObserver()

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
    min-width: 250px;  /* Adjusted min-width */
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
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            print(f"Running analysis for: {self.file_path}")  
            logging.info(f"Running analysis for: {self.file_path}")
            perform_sandbox_analysis(self.file_path)
        except Exception as e:
            error_message = f"An error occurred during sandbox analysis: {str(e)}"
            logging.error(error_message)
            print(error_message)

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
        self.analysis_thread.start()

    def show_success_message(self):
        QMessageBox.information(self, "Update Definitions", "Antivirus definitions updated successfully.")

    def show_failure_message(self):
        QMessageBox.critical(self, "Update Definitions", "Failed to update antivirus definitions.")

    def update_definitions(self):
        file_paths = [r"C:\Program Files\ClamAV\database\daily.cvd", r"C:\Program Files\ClamAV\database\daily.cld"]
        directory_path = r"C:\Program Files\ClamAV\database"
        file_found = False

        # Check if either daily.cvd or daily.cld exists
        for file_path in file_paths:
            if os.path.exists(file_path):
                file_found = True
                # Get the file's modification time
                file_mod_time = os.path.getmtime(file_path)
                file_mod_time = datetime.fromtimestamp(file_mod_time)
                
                # Calculate the age of the file
                file_age = datetime.now() - file_mod_time
                
                # If the file is older than 6 hours, check other files in the directory
                if file_age > timedelta(hours=6):
                    all_files_old = True
                    for root, dirs, files in os.walk(directory_path):
                        for file_name in files:
                            other_file_path = os.path.join(root, file_name)
                            other_file_mod_time = os.path.getmtime(other_file_path)
                            other_file_mod_time = datetime.fromtimestamp(other_file_mod_time)
                            other_file_age = datetime.now() - other_file_mod_time
                            if other_file_age <= timedelta(hours=6):
                                all_files_old = False
                                break
                        if not all_files_old:
                            break
                    if all_files_old:
                        result = subprocess.run(["freshclam"], capture_output=True, text=True)
                        if result.returncode == 0:
                            self.signals.success.emit()
                            restart_clamd_thread()
                        else:
                            self.signals.failure.emit()
                            print(f"freshclam failed with output: {result.stdout}\n{result.stderr}")
                        return
                    else:
                        print("One of the other files is not older than 6 hours. No update needed.")
                        return
                else:
                    print("The database is not older than 6 hours. No update needed.")
                return

        # If neither daily.cvd nor daily.cld exists, run freshclam
        if not file_found:
            print("Neither daily.cvd nor daily.cld files exist. Running freshclam.")
            result = subprocess.run(["freshclam"], capture_output=True, text=True)
            if result.returncode == 0:
                self.signals.success.emit()
                restart_clamd_thread()
            else:
                self.signals.failure.emit()
                print(f"freshclam failed with output: {result.stdout}\n{result.stderr}")

    def start_update_definitions_thread(self):
        threading.Thread(target=self.update_definitions).start()

# Regex for Snort alerts
alert_regex = re.compile(r'\[Priority: (\d+)\].*?\{(?:UDP|TCP)\} (\d+\.\d+\.\d+\.\d+):\d+ -> (\d+\.\d+\.\d+\.\d+):\d+')

# File paths and configurations
log_path = r"C:\Snort\log\alert.ids"
log_folder = r"C:\Snort\log"
snort_config_path = r"C:\Snort\etc\snort.conf"
sandboxie_path = r"C:\Program Files\Sandboxie\Start.exe"
sandboxie_control_path = r"C:\Program Files\Sandboxie\SbieCtrl.exe"
device_args = [f"-i {i}" for i in range(1, 26)]  # Fixed device arguments
username = os.getlogin()
sandbox_folder = rf'C:\Sandbox\{username}\DefaultBox'

uefi_100kb_paths = [
    rf'{sandbox_folder}\drive\X\EFI\Microsoft\Boot\SecureBootRecovery.efi'
]

uefi_paths = [
    rf'{sandbox_folder}\drive\X\EFI\Microsoft\Boot\bootmgfw.efi',
    rf'{sandbox_folder}\drive\X\EFI\Microsoft\Boot\bootmgr.efi',
    rf'{sandbox_folder}\drive\X\EFI\Microsoft\Boot\memtest.efi',
    rf'{sandbox_folder}\drive\X\EFI\Boot\bootx64.efi'
]
snort_command = ["snort"] + device_args + ["-c", snort_config_path, "-A", "fast"]

# Custom flags for directory changes
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800

def monitor_sandbox():
    hDir = win32file.CreateFile(
        sandbox_folder,
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
                pathToScan = os.path.join(sandbox_folder, file)
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
            logging.warning(f"Potential malware detected: {line.strip()}")
            print(f"Potential malware detected from {src_ip} to {dst_ip} with priority {priority}")
            notify_user_for_web(ip_address=src_ip, dst_ip_address=dst_ip)
            return True
    return False

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

def run_snort():    
    try:
        clean_directory(log_folder)
        # Run snort without capturing output
        subprocess.run(snort_command, check=True)
        
        logging.info("Snort completed analysis.")
        print("Snort completed analysis.")

    except subprocess.CalledProcessError as e:
        logging.error(f"Snort encountered an error: {e}")
        print(f"Snort encountered an error: {e}")

    except Exception as e:
        logging.error(f"Failed to run Snort: {e}")
        print(f"Failed to run Snort: {e}")

def activate_uefi_drive():
    # Check if the platform is Windows
    mount_command = 'mountvol X: /S'  # Command to mount UEFI drive
    try:
        # Execute the mountvol command
        subprocess.run(mount_command, shell=True, check=True)
        print("UEFI drive activated!")
    except subprocess.CalledProcessError as e:
        print(f"Error mounting UEFI drive: {e}")

setup_mbrfilter()
activate_uefi_drive() # Call the UEFI function
snort_thread = threading.Thread(target=run_snort)
snort_thread.start()
restart_clamd_if_not_running()
load_data()
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

def scan_and_warn(file_path):
    logging.info(f"Scanning file: {file_path}")
    is_malicious, virus_name = scan_file_real_time(file_path)
    ransomware_alert(file_path)
    worm_alert(file_path)

    if is_malicious:
        logging.warning(f"File {file_path} is malicious. Virus: {virus_name}")
        notify_user_thread = threading.Thread(target=notify_user, args=(file_path, virus_name))
        notify_user_thread.start()
    
    return is_malicious

def start_monitoring_sandbox():
    sandbox_thread = threading.Thread(target=monitor_sandbox)
    sandbox_thread.start()
    return sandbox_thread

def monitor_snort_log(log_path):
    if not os.path.exists(log_path):
        open(log_path, 'w').close()  # Create an empty file if it doesn't exist

    with open(log_path, 'r') as log_file:
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file
        while True:
            line = log_file.readline()
            if not line:
                continue
            process_alert(line)

# Main function to monitor startup directories
def check_startup_directories():
    # Define the paths to check
    defaultbox_user_startup_folder = rf'{sandbox_folder}\user\current\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    defaultbox_programdata_startup_folder = rf'{sandbox_folder}\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'

    # List of directories to check
    directories_to_check = [
        defaultbox_user_startup_folder,
        defaultbox_programdata_startup_folder
    ]

    # Set to keep track of already alerted files
    alerted_files = set()

    while True:
        for directory in directories_to_check:
            if os.path.exists(directory):
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        if file_path not in alerted_files:
                            logging.info(f"Startup file detected in {directory}: {file}")
                            print(f"Startup file detected in {directory}: {file}")
                            notify_user_startup(file_path, "HEUR:Win32.Startup.Generic.Malware")
                            alerted_files.add(file_path)

def is_malicious_file(file_path, size_limit_kb):
    """ Check if the file is less than the given size limit """
    return os.path.getsize(file_path) < size_limit_kb * 1024

def check_uefi_directories():
    """ Continuously check the specified UEFI directories for malicious files """
    alerted_uefi_files = set()
    known_uefi_files = set(uefi_100kb_paths + uefi_paths)

    while True:
        for uefi_path in uefi_paths + uefi_100kb_paths:
            if os.path.isfile(uefi_path):
                if uefi_path.endswith(".efi"):
                    if uefi_path not in alerted_uefi_files:
                        if uefi_path in uefi_100kb_paths and is_malicious_file(uefi_path, 100):
                            logging.warning(f"Malicious file detected: {uefi_path}")
                            print(f"Malicious file detected: {uefi_path}")
                            notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.SecureBootRecovery.Generic.Malware")
                            alerted_uefi_files.add(uefi_path)
                        elif uefi_path in uefi_paths and is_malicious_file(uefi_path, 1024):
                            logging.warning(f"Malicious file detected: {uefi_path}")
                            print(f"Malicious file detected: {uefi_path}")
                            notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.ScreenLocker.Ransomware.Generic.Malware")
                            alerted_uefi_files.add(uefi_path)

        # Check for any new files in the EFI directory
        efi_dir = rf'{sandbox_folder}\drive\X\EFI'
        for root, dirs, files in os.walk(efi_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith(".efi") and file_path not in known_uefi_files and file_path not in alerted_uefi_files:
                    logging.warning(f"Unknown file detected: {file_path}")
                    print(f"Unknown file detected: {file_path}")
                    notify_user_uefi(file_path, "HEUR:Win32.Startup.UEFI.Generic.Malware")
                    alerted_uefi_files.add(file_path)

def has_known_extension(file_path):
    try:
        ext = os.path.splitext(file_path)[1].lower()
        logging.info(f"Extracted extension '{ext}' for file '{file_path}'")
        return ext in fileTypes
    except Exception as e:
        logging.error(f"Error checking extension for file {file_path}: {e}")
        return False

def is_readable(file_path):
    try:
        logging.info(f"Attempting to read file '{file_path}'")
        with open(file_path, 'r', encoding='utf-8') as file:
            file_data = file.read(1024)
            if file_data:  # Check if file has readable content
                logging.info(f"File '{file_path}' is readable")
                return True
            return False
    except UnicodeDecodeError:
        logging.warning(f"UnicodeDecodeError while reading file '{file_path}'")
        return False
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return False

def is_ransomware(file_path):
    try:
        filename = os.path.basename(file_path)
        parts = filename.split('.')
        
        logging.info(f"Checking ransomware conditions for file '{file_path}' with parts '{parts}'")

        # Check if there are multiple extensions
        if len(parts) < 3:
            logging.info(f"File '{file_path}' does not have multiple extensions, not flagged as ransomware")
            return False

        # Check if the second last extension is known
        previous_extension = '.' + parts[-2].lower()
        if previous_extension not in fileTypes:
            logging.info(f"Previous extension '{previous_extension}' of file '{file_path}' is not known, not flagged as ransomware")
            return False

        # Check if the final extension is not in fileTypes
        final_extension = '.' + parts[-1].lower()
        if final_extension not in fileTypes:
            logging.warning(f"File '{file_path}' has unrecognized final extension '{final_extension}', checking if it might be ransomware sign")
            # Check if the file has a known extension or is readable
            if has_known_extension(file_path) or is_readable(file_path):
                logging.info(f"File '{file_path}' is not ransomware")
                return False
            else:
                logging.warning(f"File '{file_path}' might be ransomware sign")
                return True

        logging.info(f"File '{file_path}' does not meet ransomware conditions")
        return False
    except Exception as e:
        logging.error(f"Error checking ransomware for file {file_path}: {e}")
        return False

def search_files_with_same_extension(directory, extension):
    try:
        logging.info(f"Searching for files with extension '{extension}' in directory '{directory}'")
        files_with_same_extension = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(extension):
                    files_with_same_extension.append(os.path.join(root, file))
        logging.info(f"Found {len(files_with_same_extension)} files with extension '{extension}'")
        return files_with_same_extension
    except Exception as e:
        logging.error(f"Error searching for files with extension '{extension}' in directory '{directory}': {e}")
        return []

def ransomware_alert(file_path):
    global main_file_path
    global has_warned_ransomware
    global ransomware_detection_count

    if has_warned_ransomware:
        logging.info("Ransomware alert already triggered, skipping...")
        return

    try:
        logging.info(f"Running ransomware alert check for file '{file_path}'")
        if is_ransomware(file_path):
            ransomware_detection_count += 1
            logging.warning(f"File '{file_path}' might be ransomware sign. Count: {ransomware_detection_count}")
            
            # If two alerts happen, search directories for files with the same extension
            if ransomware_detection_count == 2:
                _, ext = os.path.splitext(file_path)
                if ext:
                    directory = os.path.dirname(file_path)
                    files_with_same_extension = search_files_with_same_extension(directory, ext)
                    for file in files_with_same_extension:
                        logging.info(f"Checking file '{file}' with same extension '{ext}'")
                        if is_ransomware(file):
                            logging.warning(f"File '{file}' might also be related to ransomware")

            # Notify user if the detection count reaches the threshold
            if ransomware_detection_count >= 10:
                notify_user_ransomware(main_file_path, "HEUR:Win32.Ransomware.Generic")
                has_warned_ransomware = True
                logging.warning(f"User has been notified about potential ransomware in {main_file_path}")
                print(f"User has been notified about potential ransomware in {main_file_path}")
    except Exception as e:
        logging.error(f"Error in ransomware_alert: {e}")

# Global variables for worm detection
worm_alerted_files = set()
worm_detected_count = {}
file_paths = []

def calculate_similarity_worm(features1, features2, threshold=0.86):
    """
    Calculate similarity between two dictionaries of features for worm detection.
    Adjusted threshold for worm detection.
    """
    common_keys = set(features1.keys()) & set(features2.keys())
    matching_keys = sum(1 for key in common_keys if features1[key] == features2[key])
    similarity = matching_keys / max(len(features1), len(features2))
    return similarity

def extract_numeric_worm_features(file_path):
    """
    Extract numeric features of a file using pefile for worm detection.
    """
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
    except Exception as e:
        logging.error(f"An error occurred while processing {file_path}: {e}")

    return res

# Worm alert function
def worm_alert(file_path):
    global main_file_path
    global worm_alerted_files
    global worm_detected_count
    global file_paths

    if file_path in worm_alerted_files:
        logging.info(f"Worm alert already triggered for {file_path}, skipping...")
        return

    try:
        logging.info(f"Running worm detection for file '{file_path}'")

        if is_pe_file(file_path):
            logging.info(f"File '{file_path}' is identified as a PE file")
            features_current = extract_numeric_worm_features(file_path)

            system32_dir = rf'{sandbox_folder}\drive\C\Windows\System32'
            syswow64_dir = rf'{sandbox_folder}\drive\C\Windows\SysWOW64'

            detected_in_syswow64 = os.path.exists(syswow64_dir) and \
                                   os.path.isfile(os.path.join(syswow64_dir, os.path.basename(file_path)))
            detected_in_system32 = False

            if detected_in_syswow64:
                if os.path.exists(system32_dir):
                    detected_in_system32 = os.path.isfile(os.path.join(system32_dir, os.path.basename(file_path)))
                    logging.info(f"File '{file_path}' detected in SysWOW64 and checking System32...")

            if main_file_path:
                features_main = extract_numeric_worm_features(main_file_path)
                similarity_main = calculate_similarity_worm(features_current, features_main)
                if similarity_main > 0.86:
                    logging.warning(f"Main file '{main_file_path}' is spreading the worm to '{file_path}' with similarity score {similarity_main}")
                    detected_in_system32 = True

            for collected_file_path in file_paths:
                if collected_file_path != file_path:
                    features_collected = extract_numeric_worm_features(collected_file_path)
                    similarity_collected = calculate_similarity_worm(features_current, features_collected)
                    if similarity_collected > 0.86:
                        logging.warning(f"Worm has spread to '{collected_file_path}' with similarity score {similarity_collected}")
                        detected_in_system32 = True

            worm_detected_count[file_path] = worm_detected_count.get(file_path, 0) + 1
            if detected_in_syswow64 and detected_in_system32:
                logging.warning(f"Worm '{file_path}' detected in both SysWOW64 and System32. Alerting user.")
                notify_user_worm(file_path, "HEUR:Win32.Worm.Critical.Generic.Malware")
                worm_alerted_files.add(file_path)
            elif worm_detected_count[file_path] >= 5:
                logging.warning(f"Worm '{file_path}' detected under 5 different names in critical directories. Alerting user.")
                notify_user_worm(file_path, "HEUR:Win32.Worm.Classic.Generic.Malware")
                worm_alerted_files.add(file_path)
        else:
            logging.info(f"File '{file_path}' is not a PE file, skipping worm detection.")

    except Exception as e:
        logging.error(f"Error in worm detection for file {file_path}: {e}")

# Function to monitor System32 and SysWOW64 directories
def check_critical_directories():
    system32_dir = rf'{sandbox_folder}\drive\C\Windows\System32'
    syswow64_dir = rf'{sandbox_folder}\drive\C\Windows\SysWOW64'

    critical_directories = [system32_dir, syswow64_dir]
    alerted_files = set()

    while True:
        for directory in critical_directories:
            if os.path.exists(directory):
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path) and file_path not in alerted_files:
                        logging.info(f"File detected in {directory}: {file}")
                        print(f"File detected in {directory}: {file}")
                        file_paths.append(file_path)
                        worm_alert(file_path)
                        alerted_files.add(file_path)

class ScanAndWarnHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process(event.dest_path)

    def process(self, file_path):
        scan_and_warn(file_path)

event_handler = ScanAndWarnHandler()

def run_sandboxie_control():
    try:
        logging.info("Running Sandboxie control.")
        result = subprocess.run(sandboxie_control_path, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logging.info(f"Sandboxie control output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Sandboxie control: {e.stderr}")
    except Exception as e:
        logging.error(f"Unexpected error running Sandboxie control: {e}")

def perform_sandbox_analysis(file_path):
    global main_file_path
    try:
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            raise ValueError(f"Expected str, bytes or os.PathLike object, not {type(file_path).__name__}")

        logging.info(f"Performing sandbox analysis on: {file_path}")

        file_path = os.path.normpath(file_path)
        if not os.path.isfile(file_path):
            logging.error(f"File does not exist: {file_path}")
            return

        # Set main file path globally
        main_file_path = file_path

        # Clean sandbox folder
        clean_directory(sandbox_folder)

        # Monitor Snort log for new lines and process alerts
        threading.Thread(target=monitor_snort_log, args=(log_path,)).start()
        threading.Thread(target=web_protection_observer.start).start()

        # Initialize Watchdog Observer to monitor file system events
        observer = Observer()
        observer.schedule(event_handler, path=sandbox_folder, recursive=False)
        observer.start()
        
        logging.info("File system event monitoring started.")

        # Start other sandbox analysis tasks in separate threads
        threading.Thread(target=scan_and_warn, args=(file_path,)).start()
        threading.Thread(target=start_monitoring_sandbox).start()
        threading.Thread(target=scan_sandbox_folder).start()
        threading.Thread(target=check_startup_directories).start()
        threading.Thread(target=check_critical_directories).start()
        threading.Thread(target=check_uefi_directories).start() # Start monitoring UEFI directories for malicious files in a separate thread
        threading.Thread(target=run_sandboxie_control).start()
        threading.Thread(target=run_sandboxie, args=(file_path,)).start()

        logging.info("Sandbox analysis started. Please check log after you close program. There is no limit to scan time.")

    except Exception as e:
        logging.error(f"An error occurred during sandbox analysis: {e}")

    finally:
        observer.stop()
        observer.join()

def run_sandboxie(file_path):
    try:
        subprocess.run([sandboxie_path, '/box:DefaultBox', file_path], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run Sandboxie on {file_path}: {e}")

def scan_sandbox_folder():
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