import os
import sys
import logging
from datetime import datetime
import time
import io

# Set script directory
script_dir = os.getcwd()

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Separate log files for different purposes
console_log_file = os.path.join(log_directory, "antivirusconsole.log")
application_log_file = os.path.join(log_directory, "antivirus.log")

# Configure logging for application log
logging.basicConfig(
    filename=application_log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Redirect stdout to console log
sys.stdout = open(console_log_file, "w", encoding="utf-8", errors="ignore")

# Redirect stderr to console log
sys.stderr = open(console_log_file, "w", encoding="utf-8", errors="ignore")

# Logging for application initialization
logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Start timing total duration
total_start_time = time.time()

# Measure and print time taken for each import
start_time = time.time()
import shutil
print(f"shutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import subprocess
print(f"subprocess module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import threading
print(f"threading module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import re
print(f"re module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import json
print(f"json module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QStackedWidget
print(f"PySide6.QtWidgets modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtCore import QObject, QThread, Signal
print(f"PySide6.QtCore modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtGui import QIcon
print(f"PySide6.QtGui.QIcon module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import joblib
print(f"joblib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pefile
print(f"pefile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zipfile
print(f"zipfile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import tarfile
print(f"tarfile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara
print(f"yara module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara_x
print(f"yara_x module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import psutil
print(f"psutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from notifypy import Notify
print(f"notifypy.Notify module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from watchdog.observers import Observer
print(f"watchdog.observers.Observer module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from watchdog.events import FileSystemEventHandler
print(f"watchdog.events.FileSystemEventHandler module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32file
print(f"win32file module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32con
print(f"win32con module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from datetime import timedelta
print(f"datetime.timedelta modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import numpy as np
print(f"numpy module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sniff

print(f"scapy modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ctypes
print(f"ctypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ipaddress
print(f"ipaddress module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from urllib.parse import urlparse
print(f"urlib.parse.urlparse module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import spacy
print(f"spacy module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import csv
print(f"csv module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import struct
print(f"struct module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zlib
print(f"zlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import marshal
print(f"marshal module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import base64
print(f"base64 module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import base32_crockford
print(f"base32_crockford module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import binascii
print(f"binascii module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from transformers import AutoTokenizer, AutoModelForCausalLM
print(f"transformers.AutoTokenizer and AutoModelForCausalLM modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from accelerate import Accelerator
print(f"accelerate.Accelerator module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import py7zr
print(f"py7zr module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import uncompyle6
print(f"uncompyle6 module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pymem
print(f"pymem module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import inspect
print(f"pymem module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zstandard
print(f"zstandard module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from elftools.elf.elffile import ELFFile
print(f"elftools.elf.effile, ELFFile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.MachO
print(f"macholib.Mach0 module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.mach_o
print(f"macholib.mach_o module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from typing import Optional, Tuple, BinaryIO, Dict, Any, List
print(f"typing, Optional, Tuple, BinaryIO, Dict and Any module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
print(f"cryptography.hazmat.primitives.ciphers, Cipher, algorithms, modes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import debloat.processor
print(f"debloat modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from pathlib import Path
print(f"pathlib.Path module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import hashlib
print(f"hashlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import requests
print(f"reqeusts module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from functools import lru_cache
print(f"functools.lru_cache module loaded in {time.time() - start_time:.6f} seconds")

# Calculate and print total time
total_end_time = time.time()
total_duration = total_end_time - total_start_time
print(f"Total time for all imports: {total_duration:.6f} seconds")

sys.modules['sklearn.externals.joblib'] = joblib

# Load the spaCy model globally
nlp_spacy_lang = spacy.load("en_core_web_md")
print("spaCy model 'en_core_web_md' loaded successfully")

# Initialize the accelerator
accelerator = Accelerator()

# Define the paths to the ghidra related directories
decompile_dir = os.path.join(script_dir, "decompile")
assets_dir = os.path.join(script_dir, "assets")
digital_signatures_list_dir = os.path.join(script_dir, "digitalsignatureslist")
pyinstaller_dir = os.path.join(script_dir, "pyinstaller")
ghidra_projects_dir = os.path.join(script_dir, "ghidra_projects")
ghidra_logs_dir = os.path.join(script_dir, "ghidra_logs")
ghidra_scripts_dir = os.path.join(script_dir, "ghidra_scripts")
compiled_scripts_dir = os.path.join(script_dir, "compiled_scripts")
jar_extracted_dir = os.path.join(script_dir, "jar_extracted")
dotnet_dir = os.path.join(script_dir, "dotnet")
nuitka_dir = os.path.join(script_dir, "nuitka")
extensions_dir = os.path.join(script_dir, "extensions")
extensions_path = os.path.join(extensions_dir, "extensions.txt")
magic_bytes_path = os.path.join(extensions_dir, "magicbytes.txt")
pyintstaller_dir = os.path.join(script_dir, "pyinstaller")
deepseek_dir = os.path.join(script_dir, "deepseek")
deepseek_1b_dir = os.path.join(deepseek_dir, "DeepSeek-Coder-1.3B")
python_source_code_dir = os.path.join(script_dir, "pythonsourcecode")
pycdc_dir = os.path.join(python_source_code_dir, "pycdc")
pycdas_dir = os.path.join(python_source_code_dir, "pycdas")
united_python_source_code_dir = os.path.join(python_source_code_dir, "united")
pycdas_deepseek_dir = os.path.join(python_source_code_dir, "pycdas_deepseek")
nuitka_source_code_dir = os.path.join(script_dir, "nuitkasourcecode")
commandlineandmessage_dir = os.path.join(script_dir, "commandlineandmessage")
pe_extracted_dir = os.path.join(script_dir, "pe_extracted")
zip_extracted_dir = os.path.join(script_dir, "zip_extracted")
tar_extracted_dir = os.path.join(script_dir, "tar_extracted")
seven_zip_extracted_dir = os.path.join(script_dir, "seven_zip_extracted")
general_extracted_dir = os.path.join(script_dir, "general_extracted")
processed_dir = os.path.join(script_dir, "processed")
detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_json_dir = os.path.join(script_dir, "detectiteasy_json")
memory_dir = os.path.join(script_dir, "memory")
debloat_dir = os.path.join(script_dir, "debloat")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
ilspycmd_path = os.path.join(script_dir, "ilspycmd.exe")
pycdc_path = os.path.join(script_dir, "pycdc.exe")
pycdas_path = os.path.join(script_dir, "pycdas.exe")
digital_signautres_list_antivirus_path = os.path.join(digital_signatures_list_dir, "antivirus.txt")
digital_signautres_list_microsoft_path = os.path.join(digital_signatures_list_dir, "microsoft.txt")
malicious_file_names = os.path.join(script_dir, "machinelearning", "malicious_file_names.json")
malicious_numeric_features = os.path.join(script_dir, "machinelearning", "malicious_numeric.pkl")
benign_file_names = os.path.join(script_dir, "machinelearning", "benign_file_names.json")
benign_numeric_features = os.path.join(script_dir, "machinelearning", "benign_numeric.pkl")
yara_folder_path = os.path.join(script_dir, "yara")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")
website_rules_dir = os.path.join(script_dir, "website")
ipv4_addresses_path = os.path.join(website_rules_dir, "IPv4Malware.txt")
ipv4_addresses_ddos_path = os.path.join(website_rules_dir, "IPv4DDoS.txt")
ipv4_addresses_phishing_active_path = os.path.join(website_rules_dir, "IPv4PhishingActive.txt")
ipv4_addresses_phishing_inactive_path = os.path.join(website_rules_dir, "IPv4PhishingInActive.txt")
ipv4_whitelist_path = os.path.join(website_rules_dir, "IPv4Whitelist.txt")
ipv6_addresses_path = os.path.join(website_rules_dir, "IPv6Malware.txt")
ipv6_whitelist_path = os.path.join(website_rules_dir, "IPv6Whitelist.txt")
# Define all website file paths
malware_domains_path = os.path.join(website_rules_dir, "MalwareDomains.txt")
malware_domains_mail_path = os.path.join(website_rules_dir, "MalwareDomainsMail.txt")
phishing_domains_path = os.path.join(website_rules_dir, "PhishingDomains.txt")
abuse_domains_path = os.path.join(website_rules_dir, "AbuseDomains.txt")
mining_domains_path = os.path.join(website_rules_dir, "MiningDomains.txt")
spam_domains_path = os.path.join(website_rules_dir, "SpamDomains.txt")
whitelist_domains_path = os.path.join(website_rules_dir, "WhiteListDomains.txt")
whitelist_domains_mail_path = os.path.join(website_rules_dir, "WhiteListDomainsMail.txt")
# Define corresponding subdomain files
malware_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomains.txt")
malware_mail_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomainsMail.txt")
phishing_sub_domains_path = os.path.join(website_rules_dir, "PhishingSubDomains.txt")
abuse_sub_domains_path = os.path.join(website_rules_dir, "AbuseSubDomains.txt")
mining_sub_domains_path = os.path.join(website_rules_dir, "MiningSubDomains.txt")
spam_sub_domains_path = os.path.join(website_rules_dir, "SpamSubDomains.txt")
whitelist_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomains.txt")
whitelist_mail_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomainsMail.txt")
urlhaus_path = os.path.join(website_rules_dir, "urlhaus.txt")
antivirus_list_path = os.path.join(script_dir, "hosts", "antivirus_list.txt")
yaraxtr_yrc_path = os.path.join(yara_folder_path, "yaraxtr.yrc")
compiled_rule_path = os.path.join(yara_folder_path, "compiled_rule.yrc")
yarGen_rule_path = os.path.join(yara_folder_path, "machinelearning.yrc")
icewater_rule_path = os.path.join(yara_folder_path, "icewater.yrc")
valhalla_rule_path = os.path.join(yara_folder_path, "valhalla-rules.yrc")
antivirus_domains_data = []
ipv4_addresses_signatures_data = []
ipv4_addresses_ddos_signatures_data = []
ipv4_addresses_phishing_active_signatures_data = []
ipv4_addresses_phishing_inactive_signatures_data = []
ipv6_addresses_signatures_data = []
ipv4_whitelist_data = []
ipv6_whitelist_data = []
urlhaus_data = []
malware_domains_data = []
malware_domains_mail_data = []
phishing_domains_data = []
abuse_domains_data = []
mining_domains_data = []
spam_domains_data = []
whitelist_domains_data = []
whitelist_domains_mail_data = []
malware_sub_domains_data = []
malware_mail_sub_domains_data = []
phishing_sub_domains_data = []
abuse_sub_domains_data = []
mining_sub_domains_data = []
spam_sub_domains_data = []
whitelist_sub_domains_data = []
whitelist_mail_sub_domains_data = []
# Scanned entities with "_general" suffix
scanned_urls_general = []
scanned_domains_general = []
scanned_ipv4_addresses_general = []
scanned_ipv6_addresses_general = []
# Digital Signatures data
digital_signautres_list_antivirus_path = []
digital_signautres_list_microsoft_path = []

clamdscan_path = "C:\\Program Files\\ClamAV\\clamdscan.exe"
freshclam_path = "C:\\Program Files\\ClamAV\\freshclam.exe"
clamav_file_paths = ["C:\\Program Files\\ClamAV\\database\\daily.cvd", "C:\\Program Files\\ClamAV\\database\\daily.cld"]
clamav_database_directory_path = "C:\\Program Files\\ClamAV\\database"
seven_zip_path = "C:\\Program Files\\7-Zip\\7z.exe"  # Path to 7z.exe

IPv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'  # Simple IPv4 regex
IPv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'  # Simple IPv6 regex
# Regular expressions for Discord links
discord_webhook_pattern = r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
discord_canary_webhook_pattern = r'https://canary\.discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
discord_invite_pattern = r'https://discord\.gg/[A-Za-z0-9]+'

os.makedirs(python_source_code_dir, exist_ok=True)
os.makedirs(nuitka_source_code_dir, exist_ok=True)
os.makedirs(commandlineandmessage_dir, exist_ok=True)
os.makedirs(processed_dir, exist_ok=True)
os.makedirs(memory_dir, exist_ok=True)
os.makedirs(pe_extracted_dir, exist_ok=True)
os.makedirs(zip_extracted_dir, exist_ok=True)
os.makedirs(tar_extracted_dir, exist_ok=True)
os.makedirs(seven_zip_extracted_dir, exist_ok=True)
os.makedirs(general_extracted_dir, exist_ok=True)
os.makedirs(debloat_dir, exist_ok=True)
os.makedirs(jar_extracted_dir, exist_ok=True)
os.makedirs(detectiteasy_json_dir, exist_ok=True)
os.makedirs(pycdc_dir, exist_ok=True)
os.makedirs(pycdas_dir, exist_ok=True)
os.makedirs(united_python_source_code_dir, exist_ok=True)

# Counter for ransomware detection
ransomware_detection_count = 0 
has_warned_ransomware = False  # Flag to check if ransomware warning has been issued

# Read the file types from extensions.txt with try-except
fileTypes = []
try:
    if os.path.exists(extensions_path):
        with open(extensions_path, 'r') as ext_file:
            fileTypes = [line.strip() for line in ext_file.readlines()]
except Exception as ex:
    print(f"Error reading {extensions_path}: {ex}")

print(f"File types read from {extensions_path}: {fileTypes}")

pe_file_paths = []  # List to store the PE file paths

# Initialize an empty dictionary for magic_bytes
magic_bytes = {}

try:
    # Read the magicbytes.txt file and populate the dictionary
    with open(magicbytes_path, "r") as file:
        for line in file:
            # Split each line into magic bytes and file type
            parts = line.strip().split(": ")
            if len(parts) == 2:
                magic, file_type = parts
                magic_bytes[magic] = file_type

    # If reading and processing is successful, print the dictionary
    print("Magic bytes have been successfully loaded.")

except FileNotFoundError:
    print(f"Error: The file {magicbytes_path} was not found.")
except Exception as e:
    print(f"An error occurred: {e}")

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

# --- Query MD5 Online Function with Caching ---
@lru_cache(maxsize=1024)
def query_md5_online_sync(md5_hash):
    """
    Queries the online API and returns a tuple:
        (risk_level, virus_name)

    The function inspects risk percentages:
      - If the response indicates "[100% risk]", it returns ("Malware", virus_name)
      - If the response indicates "[70% risk]", it returns ("Suspicious", virus_name)
      - For safe statuses, it returns ("Benign", "") or ("Benign (auto verdict)", "")
      - If the file is not yet rated or the result is unknown, returns ("Unknown", "")

    The virus_name is extracted from a "detected as" phrase if present.

    This function caches its results so that repeated calls with the same MD5 hash 
    will return the cached result instead of re-querying the API.
    """
    try:
        md5_hash_upper = md5_hash.upper()
        url = f"https://www.nictasoft.com/ace/md5/{md5_hash_upper}"
        response = requests.get(url)

        if response.status_code == 200:
            result = response.text.strip()
            lower_result = result.lower()

            # Check for high-risk (malware) indication.
            if "[100% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return ("Malware", virus_name)
                else:
                    return ("Malware", "")
            
            # Check for 70% risk which we treat as suspicious.
            if "[70% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return ("Suspicious", virus_name)
                else:
                    return ("Suspicious", "")
            
            # Check safe statuses.
            if "[0% risk]" in lower_result:
                return ("Benign", "")
            if "[10% risk]" in lower_result:
                return ("Benign (auto verdict)", "")
            
            # Unknown status.
            if "this file is not yet rated" in lower_result:
                return ("Unknown", "")
            
            # Default case.
            return ("Unknown (Result)", "")
        else:
            return ("Unknown (API error)", "")
    except Exception as ex:
        return (f"Error: {ex}", "")

def get_unique_output_path(output_dir: Path, base_name: str, suffix: int = 1) -> Path:
    """
    Generate a unique file path by appending a suffix (e.g., _1, _2) if the file already exists.
    """
    new_path = output_dir / f"{base_name.stem}_{suffix}{base_name.suffix}"

    while new_path.exists():  # If the file exists, increment the suffix
        suffix += 1
        new_path = output_dir / f"{base_name.stem}_{suffix}{base_name.suffix}"

    return new_path

def run_jar_extractor(file_path):
    extracted_files = []  # List to store the paths of the extracted files
    try:
        # Ensure the output directory exists
        output_dir = Path(jar_extracted_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
        
        # Path to the JarExtractor compiled .jar file
        jar_extractor_path = os.path.join(compiled_scripts_dir, "JarExtractor.jar")  # Ensure this path points to the correct JAR file

        # Command to run the JarExtractor (JAR file path and output directory)
        java_command = ["java", "-jar", jar_extractor_path, file_path, str(output_dir)]

        # Run the command to extract the JAR file
        result = subprocess.run(java_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check if the extraction was successful
        if result.returncode == 0:
            logging.info(f"Extraction completed successfully: {result.stdout}")
        else:
            logging.error(f"Extraction failed: {result.stderr}")

        # Get all files from the extracted directory and apply the unique naming
        for extracted_file in Path(output_dir).rglob("*"):  # Recursively go through the extracted files
            if extracted_file.is_file():
                # Get a unique output path for each file
                unique_file_path = get_unique_output_path(output_dir, extracted_file.name)
                
                # Optionally rename or move the file to the new unique path
                extracted_file.rename(unique_file_path)
                logging.info(f"File {extracted_file.name} saved to {unique_file_path}")

                # Append the unique file path to the list of extracted files
                extracted_files.append(unique_file_path)

        # Return the list of extracted file paths
        return extracted_files

    except subprocess.SubprocessError as ex:
        logging.error(f"Error while running JarExtractor: {ex}")
    except Exception as ex:
        logging.error(f"General error while running JarExtractor: {ex}")
        return []  # Return an empty list in case of an error

def is_jar_file(file_path):
    try:
        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check if the output contains information about JVM (indicating it's a JAR file)
        if "Virtual machine: JVM" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"JSON output saved to {json_output_path}")
            return True

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

    return False

def extract_pe_sections(file_path: str):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)
        logging.info(f"Loaded PE file: {file_path}")

        # Ensure output directory exists
        output_dir = Path(pe_extracted_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
            logging.info(f"Created output directory: {output_dir}")

        # Extract sections
        for section in pe.sections:
            # Get section name and clean it
            section_name = section.Name.decode().strip('\x00')
            section_data = section.get_data()

            # Use the provided get_unique_output_path to generate a unique file name
            section_file = get_unique_output_path(output_dir, section_name)

            # Write section data to the unique file
            with open(section_file, "wb") as f:
                f.write(section_data)
            
            logging.info(f"Section '{section_name}' saved to {section_file}")
            pe_file_paths.append(section_file)  # Add the file path to the list

            # Scan and warn after saving the file
            for file_path in pe_file_paths:
                scan_and_warn(file_path)

        logging.info("Extraction completed successfully.")
        return pe_file_paths  # Return the list of file paths

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return []  # Return an empty list in case of error

def is_hex_data(data_content):
    """Check if the given binary data can be valid hex-encoded data."""
    try:
        # Convert binary data to hex representation and back to binary
        binascii.unhexlify(binascii.hexlify(data_content))
        return True
    except (TypeError, binascii.Error):
        return False

def debloat_pe_file(file_path):
    try:
        logging.info(f"Debloating PE file {file_path} for faster scanning.")

        # Set the last_ditch_processing flag directly inside the function
        last_ditch_processing = False  # Set to True if you want to enable it

        # Read the PE file into memory
        with open(file_path, "rb") as bloated_file:
            pe_data = bloated_file.read()

        # Create the PE object
        pe = pefile.PE(data=pe_data, fast_load=True)

        # Set output path (ensure debloat_dir is properly set, assuming it's defined elsewhere)
        out_path = get_unique_output_path(debloat_dir, file_path)  # out_path should be a directory

        # Use debloat.processor.process_pe to debloat the file, passing last_ditch_processing
        debloat.processor.process_pe(
            pe,
            log_message=print,  # Log via print or a logger if preferred
            last_ditch_processing=last_ditch_processing,  # Pass last_ditch_processing
            out_path=out_path,  # out_path is now a directory
        )

        # Check if the debloated file exists in the output directory
        output_files = os.listdir(out_path)
        if output_files:
            logging.info(f"Debloated file(s) saved in: {out_path}")
            return out_path  # Return the directory where the optimized files are saved
        else:
            logging.warning(f"Debloating failed for {file_path}, no files found in output directory {out_path}.")
            return None
    except ImportError as ex:
        logging.error(f"Debloat library is not installed. Install it with pip install debloat: {ex}")
    except Exception as ex:
        logging.error(f"Error during debloating of {file_path}: {ex}")

    return None

def remove_magic_bytes(data_content):
    """Remove magic bytes from data, considering it might be hex-encoded."""
    try:
        if is_hex_data(data_content):
            # Convert binary data to hex representation for easier pattern removal
            hex_data = binascii.hexlify(data_content).decode("utf-8", errors="ignore")

            # Remove magic bytes by applying regex patterns
            for magic_byte in magic_bytes.keys():
                pattern = re.compile(rf'{magic_bytes[magic_byte].replace(" ", "")}', re.IGNORECASE)
                hex_data = pattern.sub('', hex_data)

            # Convert hex data back to binary
            return binascii.unhexlify(hex_data)
        else:
            try:
                # Decode the data using UTF-8
                decoded_content = data_content.decode("utf-8", errors="ignore")
            except (AttributeError, TypeError) as ex:
                logging.error(f"Error decoding data: {ex}")
                return data_content  # Return original data if decoding fails

            # Convert decoded content back to bytes for magic byte removal
            hex_data = binascii.hexlify(decoded_content.encode("utf-8")).decode(errors="ignore")

            for magic_byte in magic_bytes.keys():
                pattern = re.compile(rf'{magic_bytes[magic_byte].replace(" ", "")}', re.IGNORECASE)
                hex_data = pattern.sub('', hex_data)

            try:
                return binascii.unhexlify(hex_data)
            except Exception as ex:
                logging.error(f"Error unhexlifying data: {ex}")
                return data_content  # Return original data if unhexlifying fails
    except Exception as ex:
        logging.error(f"Unexpected error in remove_magic_bytes: {ex}")
        return data_content  # Return original data in case of unexpected errors

def decode_base64(data_content):
    """Decode base64-encoded data."""
    try:
        return base64.b64decode(data_content, validate=True)
    except (binascii.Error, ValueError):
        logging.error("Base64 decoding failed.")
        return None

def decode_base32(data_content):
    """Decode base32-encoded data."""
    try:
        # Ensure the input is bytes
        if isinstance(data_content, str):
            data_content = data_content.encode("utf-8")
        return base32_crockford.decode(data_content)
    except (binascii.Error, ValueError) as ex:
        logging.error(f"Base32 decoding error: {ex}")
        return None

def process_file_data(file_path):
    """Process file data by decoding and removing magic bytes."""
    try:
        with open(file_path, 'rb') as data_file:
            data_content = data_file.read()

        while True:
            if isinstance(data_content, bytes):
                base64_decoded = decode_base64(data_content)
                if base64_decoded is not None:
                    data_content = base64_decoded
                    continue

                base32_decoded = decode_base32(data_content)
                if base32_decoded is not None:
                    data_content = base32_decoded
                    continue

            logging.warning("No more base64 or base32 encoded data found.")
            break

        # Remove magic bytes
        processed_data = remove_magic_bytes(data_content)

        # Save processed data
        output_file_path = os.path.join(processed_dir, 'processed_' + os.path.basename(file_path))
        with open(output_file_path, 'wb') as processed_file:
            processed_file.write(processed_data)

        logging.info(f"Processed data from {file_path} saved to {output_file_path}")

    except Exception as ex:
        logging.error(f"Error processing file {file_path}: {ex}")
        print(f"Error processing file {file_path}: {ex}")

def extract_infos(file_path, rank=None):
    """Extract information about file"""
    file_name = os.path.basename(file_path)
    if rank is not None:
        return {'file_name': file_name, 'numeric_tag': rank}
    else:
        return {'file_name': file_name}

def calculate_entropy(data: list) -> float:
    """Calculate Shannon entropy of data (provided as a list of integers)."""
    if not data:
        return 0.0

    total_items = len(data)
    value_counts = [data.count(i) for i in range(256)]  # Count occurrences of each byte (0-255)

    entropy = 0.0
    for count in value_counts:
        if count > 0:
            p_x = count / total_items
            entropy -= p_x * np.log2(p_x)

    return entropy

def analyze_tls_callbacks(pe: pefile.PE) -> Dict[str, Any]:
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
                callback_array = get_callback_addresses(pe, tls.AddressOfCallBacks)
                if callback_array:
                    tls_callbacks['callbacks'] = callback_array

        return tls_callbacks
    except Exception as e:
        logging.error(f"Error analyzing TLS callbacks: {e}")
        return {}

def get_callback_addresses(pe: pefile.PE, address_of_callbacks: int) -> List[int]:
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

def analyze_dos_stub(pe) -> Dict[str, Any]:
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
                    dos_stub['entropy'] = calculate_entropy(list(dos_stub_data))

        return dos_stub
    except Exception as ex:
          logging.error(f"Error analyzing DOS stub: {ex}")
          return None

def analyze_certificates(pe) -> Dict[str, Any]:
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

def analyze_delay_imports(pe) -> List[Dict[str, Any]]:
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

def analyze_load_config(pe) -> Dict[str, Any]:
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

def analyze_relocations(pe) -> List[Dict[str, Any]]:
    """Analyze base relocations with summarized entries."""
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

def analyze_overlay(pe, file_path: str) -> Dict[str, Any]:
    """Analyze file overlay (data appended after the PE structure)."""
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
                overlay_info['entropy'] = calculate_entropy(list(overlay_data))

        return overlay_info
    except Exception as e:
        logging.error(f"Error analyzing overlay: {e}")
        return {}

def analyze_bound_imports(pe) -> List[Dict[str, Any]]:
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

def analyze_section_characteristics(pe) -> Dict[str, Dict[str, Any]]:
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
                'entropy': calculate_entropy(list(section.get_data())),
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

def analyze_extended_headers(pe) -> Dict[str, Any]:
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

def serialize_data(data) -> Any:
    """Serialize data for output, ensuring compatibility."""
    try:
        return list(data) if data else None
    except Exception:
        return None

def analyze_rich_header(pe) -> Dict[str, Any]:
    """Analyze Rich header details."""
    try:
        rich_header = {}
        if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
            rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
            rich_header['values'] = serialize_data(pe.RICH_HEADER.values)
            rich_header['clear_data'] = serialize_data(pe.RICH_HEADER.clear_data)
            rich_header['key'] = serialize_data(pe.RICH_HEADER.key)
            rich_header['raw_data'] = serialize_data(pe.RICH_HEADER.raw_data)

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

def extract_numeric_features(file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
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

            # Relocations
            'relocations': [
                {
                    'virtual_address': entry.rva,
                    'type': entry.type
                }
                for relocation in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', [])
                for entry in getattr(relocation, 'entries', [])
            ] if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') else [],

            # Certificates
            'certificates': analyze_certificates(pe),  # Analyze certificates

            # DOS Stub Analysis
            'dos_stub': analyze_dos_stub(pe),  # DOS stub analysis here

            # TLS Callbacks
            'tls_callbacks': analyze_tls_callbacks(pe),  # TLS callback analysis here

            # Delay Imports
            'delay_imports': analyze_delay_imports(pe),  # Delay imports analysis here

            # Load Config
            'load_config': analyze_load_config(pe),  # Load config analysis here

            # Relocations
            'relocations': analyze_relocations(pe),  # Relocations analysis here

            # Bound Imports
            'bound_imports': analyze_bound_imports(pe),  # Bound imports analysis here

            # Section Characteristics
            'section_characteristics': analyze_section_characteristics(pe),  # Section characteristics analysis here

            # Extended Headers
            'extended_headers': analyze_extended_headers(pe),  # Extended headers analysis here

            # Rich Header
            'rich_header': analyze_rich_header(pe),  # Rich header analysis here

            # Overlay
            'overlay': analyze_overlay(pe, file_path),  # Overlay analysis here
        }

        # Add numeric tag if provided
        if rank is not None:
            numeric_features['numeric_tag'] = rank

        return numeric_features

    except Exception as ex:
        logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
        return None

def calculate_similarity(features1, features2):
    """Calculate similarity between two dictionaries of features"""
    common_keys = set(features1.keys()) & set(features2.keys())
    matching_keys = sum(1 for key in common_keys if features1[key] == features2[key])
    similarity = matching_keys / max(len(features1), len(features2))
    return similarity

def notify_user_nichta(file_path, virus_name):
    """
    Notify function for cloud analysis (Nichta) warnings.
    Uses a different notification title or method as desired.
    """
    notification = Notify()  # Assuming Notify() is defined elsewhere
    notification.title = "Nichta Cloud Analysis Alert"
    notification.message = (f"Cloud analysis flagged the file:\n"
                            f"Path: {file_path}\n"
                            f"Risk: {virus_name}\n")
    notification.send()

def notify_user(file_path, virus_name, engine_detected): 
    notification = Notify()
    notification.title = "Malware Alert"
    notification.message = f"Malicious file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.send()

def notify_user_pua(file_path, virus_name, engine_detected):
    notification = Notify()
    notification.title = "PUA Alert"
    notification.message = f"PUA file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.send()

def notify_user_for_malicious_source_code(file_path, virus_name):
    """
    Sends a notification about malicious source code detected.
    """
    notification_title = f"Malicious Source Code detected: {virus_name}"
    notification_message = f"Suspicious source code detected in: {file_path}\nVirus: {virus_name}"
    logging.warning(notification_title)
    logging.warning(notification_message)
    print(notification_title)
    print(notification_message)

def notify_user_for_detected_command(message):
    logging.warning(f"Notification: {message}")
    notification = Notify()
    notification.title = f"Malware Message Alert"
    notification.message = message
    notification.send()
    
def notify_user_for_deepseek(file_path, virus_name, malware_status):
    notification = Notify()
    notification.title = "DeepSeek-Coder-1.3b Security Alert"  # Updated title
    
    if malware_status.lower() == "maybe":
        notification.message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    elif malware_status.lower() == "yes":
        notification.message = f"Malware detected: {file_path}\nVirus: {virus_name}"

    notification.send()

def notify_size_warning(file_path, archive_type, virus_name):
    """Send a notification for size-related warnings."""
    notification = Notify()
    notification.title = "Size Warning"
    notification.message = (f"{archive_type} file {file_path} is smaller than 20MB but contains a large file "
                            f"which might be suspicious. Virus Name: {virus_name}")
    notification.send()

def notify_rlo_warning(file_path, archive_type, virus_name):
    """Send a notification for RLO-related warnings."""
    notification = Notify()
    notification.title = "RLO Warning"
    notification.message = (f"Filename in {archive_type} file {file_path} contains RLO character after a dot. "
                            f"This could indicate suspicious activity. Virus Name: {virus_name}")
    notification.send()

def notify_user_rlo(file_path, virus_name):
    notification = Notify()
    notification.title = "Suspicious RLO Name Alert"
    notification.message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    notification.send()
    
def notify_user_for_detected_fake_system_file(file_path, file_name, virus_name):
    notification = Notify()
    notification.title = "Fake System File Alert"
    notification.message = (
        f"Fake system file detected:\n"
        f"File Path: {file_path}\n"
        f"File Name: {file_name}\n"
        f"Threat: {virus_name}"
    )
    notification.send()

def notify_user_for_detected_rootkit(file_path, virus_name):
    notification = Notify()
    notification.title = "Rootkit Detection Alert"
    notification.message = (
        f"Potential rootkit file detected:\n"
        f"File Path: {file_path}\n"
        f"Threat: {virus_name}"
    )
    notification.send()

def notify_user_invalid(file_path, virus_name):
    notification = Notify()
    notification.title = "Invalid signature Alert"
    notification.message = f"Invalid signature file detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_ghidra(file_path, virus_name):
    notification = Notify()
    notification.title = "Decompiled Malicious File Alert"
    notification.message = f"Malicious decompiled file detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_fake_size(file_path, virus_name):
    notification = Notify()
    notification.title = "Fake Size Alert"
    notification.message = f"Fake size file detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_startup(file_path, message):
    """Notify the user about suspicious or malicious startup files."""
    notification = Notify()
    notification.title = "Startup File Alert"

    # Include file_path in the message
    notification.message = f"File: {file_path}\n{message}"
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

def notify_user_hosts(file_path, virus_name):
    notification = Notify()
    notification.title = "Host Hijacker Alert"
    notification.message = f"Potential host hijacker detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_worm(file_path, virus_name):
    notification = Notify()
    notification.title = "Worm Alert"
    notification.message = f"Potential worm detected: {file_path}\nVirus: {virus_name}"
    notification.send()

def notify_user_for_web(domain=None, ip_address=None, url=None, file_path=None, detection_type=None):
    notification = Notify()
    notification.title = "Malware or Phishing Alert"

    # Build the notification message dynamically
    message_parts = []
    if detection_type:
        message_parts.append(f"Detection Type: {detection_type}")
    if domain:
        message_parts.append(f"Domain: {domain}")
    if ip_address:
        message_parts.append(f"IP Address: {ip_address}")
    if url:
        message_parts.append(f"URL: {url}")
    if file_path:
        message_parts.append(f"File Path: {file_path}")

    if message_parts:
        notification.message = f"Phishing or Malicious activity detected:\n" + "\n".join(message_parts)
    else:
        notification.message = "Phishing or Malicious activity detected"

    notification.send()

def notify_user_for_hips(ip_address=None, dst_ip_address=None):
    notification = Notify()
    notification.title = "Malicious Activity Detected"
    
    if ip_address and dst_ip_address:
        notification.message = f"Malicious activity detected:\nSource: {ip_address}\nDestination: {dst_ip_address}"
    elif ip_address:
        notification.message = f"Malicious activity detected:\nSource IP Address: {ip_address}"
    elif dst_ip_address:
        notification.message = f"Malicious activity detected:\nDestination IP Address: {dst_ip_address}"
    else:
        notification.message = "Malicious activity detected"
    
    notification.send()

def notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status):
    """
    Function to send notification for detected HIPS file.
    """
    notification = Notify()
    notification.title = "Web Malware Alert For File"
    notification.message = f"{status} file detected by Web related Message: {file_path}\nSource IP: {src_ip}\nAlert Line: {alert_line}"
    notification.send()
    print(f"Real-time web message notification: Detected {status} file {file_path} from {src_ip} with alert line: {alert_line}")

# Function to load antivirus list
def load_antivirus_list():
    global antivirus_domains_data
    try:
        with open(antivirus_list_path, 'r') as antivirus_file:
            antivirus_domains_data = antivirus_file.read().splitlines()
        return antivirus_domains_data
    except Exception as ex:
        logging.error(f"Error loading Antivirus domains: {ex}")
        return []

def load_digital_signatures(file_path, description="Digital signatures"):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            signatures = file.read().splitlines()
        print(f"{description} loaded successfully!")
        return signatures
    except Exception as ex:
        print(f"Error loading {description}: {ex}")
        return []
    
def load_website_data():
    global ipv4_addresses_signatures_data, ipv4_whitelist_data, ipv4_addresses_ddos_signatures_data, ipv4_addresses_phishing_active_signatures_data, ipv4_addresses_phishing_inactive_signatures_data, ipv6_addresses_signatures_data, ipv6_whitelist_data, urlhaus_data, malware_domains_data, malware_domains_mail_data, phishing_domains_data, abuse_domains_data, mining_domains_data, spam_domains_data, whitelist_domains_data, whitelist_domains_mail_data, malware_sub_domains_data, malware_mail_sub_domains_data, phishing_sub_domains_data, abuse_sub_domains_data, mining_sub_domains_data, spam_sub_domains_data, whitelist_sub_domains_data, whitelist_mail_sub_domains_data

    try:
        # Load Malicious IPv4 addresses
        with open(ipv4_addresses_path, 'r') as ip_file:
            ipv4_addresses_signatures_data = ip_file.read().splitlines()
        print("Malicious IPv4 Addresses loaded successfully!")
    except Exception as ex:
        print(f"Error loading malicious IPv4 Addresses: {ex}")

    try:
        # Load DDoS IPv4 addresses
        with open(ipv4_addresses_ddos_path, 'r') as ip_file:
            ipv4_addresses_ddos_signatures_data = ip_file.read().splitlines()
        print("Malicious IPv4 Addresses loaded successfully!")
    except Exception as ex:
        print(f"Error loading malicious IPv4 Addresses: {ex}")

    try:
        # Load phishing active IPv4 addresses
        with open(ipv4_addresses_phishing_active_path, 'r') as ip_file:
            ipv4_addresses_phishing_active_signatures_data = ip_file.read().splitlines()
        print("Active phishing IPv4 Addresses loaded successfully!")
    except Exception as ex:
        print(f"Error loading active phishing IPv4 Addresses: {ex}")

    try:
        # Load phishing inactive IPv4 addresses
        with open(ipv4_addresses_phishing_inactive_path, 'r') as ip_file:
            ipv4_addresses_phishing_inactive_signatures_data = ip_file.read().splitlines()
        print("Inactive phishing IPv4 Addresses loaded successfully!")
    except Exception as ex:
        print(f"Error loading inactive phishing IPv4 Addresses: {ex}")
    
    try:
        # Load IPv4 whitelist
        with open(ipv4_whitelist_path, 'r') as whitelist_file:
            ipv4_whitelist_data = whitelist_file.read().splitlines()
        print("IPv4 Whitelist loaded successfully!")
    except Exception as ex:
        print(f"Error loading IPv4 Whitelist: {ex}")

    try:
        # Load IPv6 addresses
        with open(ipv6_addresses_path, 'r') as ipv6_file:
            ipv6_addresses_signatures_data = ipv6_file.read().splitlines()
        print("IPv6 Addresses loaded successfully!")
    except Exception as ex:
        print(f"Error loading IPv6 Addresses: {ex}")

    try:
        # Load IPv6 whitelist
        with open(ipv6_whitelist_path, 'r') as whitelist_file:
            ipv6_whitelist_data = whitelist_file.read().splitlines()
        print("IPv6 Whitelist loaded successfully!")
    except Exception as ex:
        print(f"Error loading IPv6 Whitelist: {ex}")
        ipv6_whitelist_data = []

    try:
        # Load URLhaus data
        urlhaus_data = []
        with open(urlhaus_path, 'r') as urlhaus_file:
            reader = csv.DictReader(urlhaus_file)
            for row in reader:
                urlhaus_data.append(row)
        print("URLhaus data loaded successfully!")
    except Exception as ex:
        print(f"Error loading URLhaus data: {ex}")

    try:
        # Load malware domains
        with open(malware_domains_path, 'r') as domains_file:
            malware_domains_data = domains_file.read().splitlines()
        print("Malware domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware domains: {ex}")
        malware_domains_data = []

    try:
        # Load malware domains email path
        with open(malware_domains_mail_path, 'r') as mail_domains_file:
            malware_domains_mail_data = mail_domains_file.read().splitlines()
        print("Malware email domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware email domains: {ex}")
        malware_domains_mail_data = []

    try:
        # Load phishing domains
        with open(phishing_domains_path, 'r') as domains_file:
            phishing_domains_data = domains_file.read().splitlines()
        print("Phishing domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Phishing domains: {ex}")
        phishing_domains_data = []

    try:
        # Load abuse domains
        with open(abuse_domains_path, 'r') as domains_file:
            abuse_domains_data = domains_file.read().splitlines()
        print("Abuse domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Abuse domains: {ex}")
        abuse_domains_data = []

    try:
        # Load mining domains
        with open(mining_domains_path, 'r') as domains_file:
            mining_domains_data = domains_file.read().splitlines()
        print("Mining domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Mining domains: {ex}")
        mining_domains_data = []

    try:
        # Load spam domains
        with open(spam_domains_path, 'r') as domains_file:
            spam_domains_data = domains_file.read().splitlines()
        print("Spam domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Spam domains: {ex}")
        spam_domains_data = []

    try:
        # Load whitelist domains
        with open(whitelist_domains_path, 'r') as domains_file:
            whitelist_domains_data = domains_file.read().splitlines()
        print("Whitelist domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Whitelist domains: {ex}")
        whitelist_domains_data = []

    try:
        # Load Malware subdomains
        with open(malware_sub_domains_path, 'r') as file:
            malware_sub_domains_data = file.read().splitlines()
        print("Malware subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware subdomains: {ex}")
        malware_sub_domains_data = []

    try:
        # Load Malware mail subdomains
        with open(malware_mail_sub_domains_path, 'r') as file:
            malware_mail_sub_domains_data = file.read().splitlines()
        print("Malware mail subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware mail subdomains: {ex}")
        malware_mail_sub_domains_data = []

    try:
        # Load Phishing subdomains
        with open(phishing_sub_domains_path, 'r') as file:
            phishing_sub_domains_data = file.read().splitlines()
        print("Phishing subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Phishing subdomains: {ex}")
        phishing_sub_domains_data = []

    try:
        # Load Abuse subdomains
        with open(abuse_sub_domains_path, 'r') as file:
            abuse_sub_domains_data = file.read().splitlines()
        print("Abuse subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Abuse subdomains: {ex}")
        abuse_sub_domains_data = []

    try:
        # Load Mining subdomains
        with open(mining_sub_domains_path, 'r') as file:
            mining_sub_domains_data = file.read().splitlines()
        print("Mining subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Mining subdomains: {ex}")
        mining_sub_domains_data = []

    try:
        # Load Spam subdomains
        with open(spam_sub_domains_path, 'r') as file:
            spam_sub_domains_data = file.read().splitlines()
        print("Spam subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Spam subdomains: {ex}")
        spam_sub_domains_data = []

    try:
        # Load Whitelist subdomains
        with open(whitelist_sub_domains_path, 'r') as file:
            whitelist_sub_domains_data = file.read().splitlines()
        print("Whitelist subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Whitelist subdomains: {ex}")
        whitelist_sub_domains_data = []

    try:
        # Load Whitelist mail subdomains
        with open(whitelist_mail_sub_domains_path, 'r') as file:
            whitelist_mail_sub_domains_data = file.read().splitlines()
        print("Whitelist mail subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Whitelist mail subdomains: {ex}")
        whitelist_mail_sub_domains_data = []

    print("All domain and ip address files loaded successfully!")

# --------------------------------------------------------------------------
# Check for Discord webhook URLs and invite links (including Canary)
def contains_discord_code(decompiled_code, file_path, cs_file_path=None,
                            nuitka_flag=False, pyinstaller_flag=False, pyinstaller_deepseek_flag=False, dotnet_flag=False):
    """
    Scan the decompiled code for Discord webhook URLs, Discord Canary webhook URLs, or Discord invite links.
    For every detection, log a warning and immediately notify the user with an explicit unique heuristic
    signature that depends on the flags provided.
    """
    discord_webhook_matches = re.findall(discord_webhook_pattern, decompiled_code)
    discord_canary_webhook_matches = re.findall(discord_canary_webhook_pattern, decompiled_code)
    discord_invite_matches = re.findall(discord_invite_pattern, decompiled_code)

    if discord_webhook_matches:
        if dotnet_flag:
            if cs_file_path:
                logging.warning(f"Discord webhook URL detected in .NET source code file: {cs_file_path} - Matches: {discord_webhook_matches}")
            else:
                logging.warning(f"Discord webhook URL detected in .NET source code file: [cs_file_path not provided] - Matches: {discord_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.DotNET')
        elif nuitka_flag:
            logging.warning(f"Discord webhook URL detected in Nuitka compiled file: {file_path} - Matches: {discord_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.Nuitka')
        elif pyinstaller_flag or pyinstaller_deepseek_flag:
            # In both cases, add the notice.
            logging.warning(f"Discord webhook URL detected in PyInstaller compiled file: {file_path} - Matches: {discord_webhook_matches} NOTICE: There still a chance the file is not related with PyInstaller")
            if pyinstaller_deepseek_flag:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.PyInstallerDeepSeek')
            else:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.PyInstaller')
        else:
            logging.warning(f"Discord webhook URL detected in decompiled code: {discord_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook')

    if discord_canary_webhook_matches:
        if dotnet_flag:
            if cs_file_path:
                logging.warning(f"Discord Canary webhook URL detected in .NET source code file: {cs_file_path} - Matches: {discord_canary_webhook_matches}")
            else:
                logging.warning(f"Discord Canary webhook URL detected in .NET source code file: [cs_file_path not provided] - Matches: {discord_canary_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook.DotNET')
        elif nuitka_flag:
            logging.warning(f"Discord Canary webhook URL detected in Nuitka compiled file: {file_path} - Matches: {discord_canary_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook.Nuitka')
        elif pyinstaller_flag or pyinstaller_deepseek_flag:
            logging.warning(f"Discord Canary webhook URL detected in PyInstaller compiled file: {file_path} - Matches: {discord_canary_webhook_matches} NOTICE: There still a chance the file is not related with PyInstaller")
            if pyinstaller_deepseek_flag:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook.PyInstallerDeepSeek')
            else:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook.PyInstaller')
        else:
            logging.warning(f"Discord Canary webhook URL detected in decompiled code: {discord_canary_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook')

    if discord_invite_matches:
        if dotnet_flag:
            if cs_file_path:
                logging.warning(f"Discord invite link detected in .NET source code file: {cs_file_path} - Matches: {discord_invite_matches}")
            else:
                logging.warning(f"Discord invite link detected in .NET source code file: [cs_file_path not provided] - Matches: {discord_invite_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Invite.DotNET')
        elif nuitka_flag:
            logging.warning(f"Discord invite link detected in Nuitka compiled file: {file_path} - Matches: {discord_invite_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Invite.Nuitka')
        elif pyinstaller_flag or pyinstaller_deepseek_flag:
            logging.warning(f"Discord invite link detected in PyInstaller compiled file: {file_path} - Matches: {discord_invite_matches} NOTICE: There still a chance the file is not related with PyInstaller")
            if pyinstaller_deepseek_flag:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Invite.PyInstallerDeepSeek')
            else:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Invite.PyInstaller')
        else:
            logging.info(f"Discord invite link detected in decompiled code: {discord_invite_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Invite')

# --------------------------------------------------------------------------
# Generalized scan for domains
def scan_domain_general(url, dotnet_flag=False, nuitka_flag=False, pyinstaller_flag=False, pyinstaller_deepseek_flag=False):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            raise ValueError("Invalid URL or domain format")
        full_domain = parsed_url.netloc.lower()
        domain_parts = full_domain.split('.')
        if len(domain_parts) > 2:
            main_domain = '.'.join(domain_parts[-2:])
            subdomain = '.'.join(domain_parts[:-2])
        else:
            main_domain = full_domain
            subdomain = None

        if full_domain in scanned_domains_general:
            logging.info(f"Domain {full_domain} has already been scanned.")
            return
        scanned_domains_general.append(full_domain)
        logging.info(f"Scanning domain: {full_domain}")
        logging.info(f"Main domain: {main_domain}")
        if subdomain:
            logging.info(f"Subdomain: {subdomain}")

        whitelist_checks = [
            (full_domain in whitelist_domains_data, "domain"),
            (full_domain in whitelist_domains_mail_data, "mail domain"),
            (full_domain in whitelist_sub_domains_data, "subdomain"),
            (full_domain in whitelist_mail_sub_domains_data, "mail subdomain")
        ]
        for is_whitelisted, whitelist_type in whitelist_checks:
            if is_whitelisted:
                logging.info(f"Domain {full_domain} is whitelisted ({whitelist_type}).")
                return

        if subdomain:
            if full_domain in spam_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Spam subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Spam.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Spam subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Spam.SubDomain")
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Spam subdomain detected in PyInstaller compiled file: {full_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstallerDeepSeek.Spam.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstaller.Spam.SubDomain")
                else:
                    logging.warning(f"Spam subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Spam.SubDomain")
                return

            if full_domain in mining_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Mining subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Mining.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Mining subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Mining.SubDomain")
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Mining subdomain detected in PyInstaller compiled file: {full_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstallerDeepSeek.Mining.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstaller.Mining.SubDomain")
                else:
                    logging.warning(f"Mining subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Mining.SubDomain")
                return

            if full_domain in abuse_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Abuse subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Abuse.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Abuse subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Abuse.SubDomain")
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Abuse subdomain detected in PyInstaller compiled file: {full_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstallerDeepSeek.Abuse.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstaller.Abuse.SubDomain")
                else:
                    logging.warning(f"Abuse subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Abuse.SubDomain")
                return

            if full_domain in phishing_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Phishing subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Phishing.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Phishing subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Phishing.SubDomain")
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Phishing subdomain detected in PyInstaller compiled file: {full_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstallerDeepSeek.Phishing.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstaller.Phishing.SubDomain")
                else:
                    logging.warning(f"Phishing subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Phishing.SubDomain")
                return

            if full_domain in malware_mail_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Malware mail subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Malware.Mail.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Malware mail subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Malware.Mail.SubDomain")
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Malware mail subdomain detected in PyInstaller compiled file: {full_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstallerDeepSeek.Malware.Mail.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstaller.Malware.Mail.SubDomain")
                else:
                    logging.warning(f"Malware mail subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Malware.Mail.SubDomain")
                return

            if full_domain in malware_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Malware subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Malware.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Malware subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Malware.SubDomain")
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Malware subdomain detected in PyInstaller compiled file: {full_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstallerDeepSeek.Malware.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PyInstaller.Malware.SubDomain")
                else:
                    logging.warning(f"Malware subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Malware.SubDomain")
                return

        # Main domain threat checks
        if full_domain in spam_domains_data or main_domain in spam_domains_data:
            if dotnet_flag:
                logging.warning(f"Spam domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Spam.Domain")
            elif nuitka_flag:
                logging.warning(f"Spam domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Spam.Domain")
            elif pyinstaller_flag or pyinstaller_deepseek_flag:
                logging.warning(f"Spam domain detected in PyInstaller compiled file: {main_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                if pyinstaller_deepseek_flag:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstallerDeepSeek.Spam.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstaller.Spam.Domain")
            else:
                logging.warning(f"Spam domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Spam.Domain")
            return

        if full_domain in mining_domains_data or main_domain in mining_domains_data:
            if dotnet_flag:
                logging.warning(f"Mining domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Mining.Domain")
            elif nuitka_flag:
                logging.warning(f"Mining domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Mining.Domain")
            elif pyinstaller_flag or pyinstaller_deepseek_flag:
                logging.warning(f"Mining domain detected in PyInstaller compiled file: {main_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                if pyinstaller_deepseek_flag:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstallerDeepSeek.Mining.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstaller.Mining.Domain")
            else:
                logging.warning(f"Mining domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Mining.Domain")
            return

        if full_domain in abuse_domains_data or main_domain in abuse_domains_data:
            if dotnet_flag:
                logging.warning(f"Abuse domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Abuse.Domain")
            elif nuitka_flag:
                logging.warning(f"Abuse domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Abuse.Domain")
            elif pyinstaller_flag or pyinstaller_deepseek_flag:
                logging.warning(f"Abuse domain detected in PyInstaller compiled file: {main_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                if pyinstaller_deepseek_flag:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstallerDeepSeek.Abuse.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstaller.Abuse.Domain")
            else:
                logging.warning(f"Abuse domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Abuse.Domain")
            return

        if full_domain in phishing_domains_data or main_domain in phishing_domains_data:
            if dotnet_flag:
                logging.warning(f"Phishing domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Phishing.Domain")
            elif nuitka_flag:
                logging.warning(f"Phishing domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Phishing.Domain")
            elif pyinstaller_flag or pyinstaller_deepseek_flag:
                logging.warning(f"Phishing domain detected in PyInstaller compiled file: {main_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                if pyinstaller_deepseek_flag:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstallerDeepSeek.Phishing.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstaller.Phishing.Domain")
            else:
                logging.warning(f"Phishing domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Phishing.Domain")
            return

        if full_domain in malware_domains_mail_data or main_domain in malware_domains_mail_data:
            if dotnet_flag:
                logging.warning(f"Malware mail domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Malware.Mail.Domain")
            elif nuitka_flag:
                logging.warning(f"Malware mail domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Malware.Mail.Domain")
            elif pyinstaller_flag or pyinstaller_deepseek_flag:
                logging.warning(f"Malware mail domain detected in PyInstaller compiled file: {main_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                if pyinstaller_deepseek_flag:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstallerDeepSeek.Malware.Mail.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstaller.Malware.Mail.Domain")
            else:
                logging.warning(f"Malware mail domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Malware.Mail.Domain")
            return

        if full_domain in malware_domains_data or main_domain in malware_domains_data:
            if dotnet_flag:
                logging.warning(f"Malware domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Malware.Domain")
            elif nuitka_flag:
                logging.warning(f"Malware domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Malware.Domain")
            elif pyinstaller_flag or pyinstaller_deepseek_flag:
                logging.warning(f"Malware domain detected in PyInstaller compiled file: {main_domain} NOTICE: There still a chance the file is not related with PyInstaller")
                if pyinstaller_deepseek_flag:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstallerDeepSeek.Malware.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PyInstaller.Malware.Domain")
            else:
                logging.warning(f"Malware domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Malware.Domain")
            return

        logging.info(f"Domain {full_domain} passed all checks.")

    except Exception as ex:
        logging.error(f"Error scanning domain {url}: {ex}")
        print(f"Error scanning domain {url}: {ex}")

# --------------------------------------------------------------------------
# Generalized scan for URLs
def scan_url_general(url, dotnet_flag=False, nuitka_flag=False, pyinstaller_flag=False, pyinstaller_deepseek_flag=False):
    try:
        if url in scanned_urls_general:
            logging.info(f"URL {url} has already been scanned.")
            return

        scanned_urls_general.append(url)
        logging.info(f"Scanning URL: {url}")

        for entry in urlhaus_data:
            if entry['url'] in url:
                message = (
                    f"URL {url} matches the URLhaus signatures.\n"
                    f"ID: {entry['id']}\n"
                    f"Date Added: {entry['dateadded']}\n"
                    f"URL Status: {entry['url_status']}\n"
                    f"Last Online: {entry['last_online']}\n"
                    f"Threat: {entry['threat']}\n"
                    f"Tags: {entry['tags']}\n"
                    f"URLhaus Link: {entry['urlhaus_link']}\n"
                    f"Reporter: {entry['reporter']}"
                )
                logging.warning(message)
                print(message)
                if dotnet_flag:
                    notify_user_for_malicious_source_code(url, 'HEUR:Win32.DotNET.URLhaus.Match')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(url, 'HEUR:Win32.Nuitka.URLhaus.Match')
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"URL {url} matches the URLhaus signatures. NOTICE: There still a chance the file is not related with PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(url, 'HEUR:Win32.PyInstallerDeepSeek.URLhaus.Match')
                    else:
                        notify_user_for_malicious_source_code(url, 'HEUR:Win32.PyInstaller.URLhaus.Match')
                else:
                    notify_user_for_malicious_source_code(url, 'HEUR:Win32.URLhaus.Match')
                return

        logging.info(f"No match found for URL: {url}")
        print(f"No match found for URL: {url}")

    except Exception as ex:
        logging.error(f"Error scanning URL {url}: {ex}")
        print(f"Error scanning URL {url}: {ex}")

# --------------------------------------------------------------------------
# Generalized scan for IP addresses
def scan_ip_address_general(ip_address, dotnet_flag=False, nuitka_flag=False, pyinstaller_flag=False, pyinstaller_deepseek_flag=False):
    try:
        # Check if the IP address is local
        if is_local_ip(ip_address):
            message = f"Skipping local IP address: {ip_address}"
            logging.info(message)
            print(message)
            return

        # Check if the IP address has already been scanned
        if ip_address in scanned_ipv4_addresses_general or ip_address in scanned_ipv6_addresses_general:
            message = f"IP address {ip_address} has already been scanned."
            logging.info(message)
            print(message)
            return

        # Process IPv6 addresses
        if re.match(IPv6_pattern, ip_address):
            scanned_ipv6_addresses_general.append(ip_address)
            message = f"Scanning IPv6 address: {ip_address}"
            logging.info(message)
            print(message)
            if ip_address in ipv6_addresses_signatures_data:
                logging.warning(f"Malicious IPv6 address detected: {ip_address}")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.Malware.IPv6')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.Malware.IPv6')
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Malicious IPv6 address detected: {ip_address} NOTICE: There is still a chance the file is not related to PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PyInstallerDeepSeek.Malware.IPv6')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PyInstaller.Malware.IPv6')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Malware.IPv6')
            elif ip_address in ipv6_whitelist_data:
                logging.info(f"IPv6 address {ip_address} is whitelisted.")
                return
            else:
                logging.info(f"Unknown IPv6 address detected: {ip_address}")
                print(f"Unknown IPv6 address detected: {ip_address}")

        # Process IPv4 addresses
        elif re.match(IPv4_pattern, ip_address):
            scanned_ipv4_addresses_general.append(ip_address)
            message = f"Scanning IPv4 address: {ip_address}"
            logging.info(message)
            print(message)
            
            # Check for standard malware signatures first
            if ip_address in ipv4_addresses_signatures_data:
                logging.warning(f"Malicious IPv4 address detected: {ip_address}")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.Malware.IPv4')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.Malware.IPv4')
                elif pyinstaller_flag or pyinstaller_deepseek_flag:
                    logging.warning(f"Malicious IPv4 address detected: {ip_address} NOTICE: There is still a chance the file is not related to PyInstaller")
                    if pyinstaller_deepseek_flag:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PyInstallerDeepSeek.Malware.IPv4')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PyInstaller.Malware.IPv4')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Malware.IPv4')
            
            # Check for DDoS threat signatures
            elif ip_address in ipv4_addresses_ddos_signatures_data:
                logging.warning(f"IPv4 address {ip_address} detected as a potential DDoS threat.")
                notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DDOS.Malware.IPv4')
            
            # Check for active phishing threat signatures
            elif ip_address in ipv4_addresses_phishing_active_signatures_data:
                logging.warning(f"IPv4 address {ip_address} detected as an active phishing threat.")
                notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PhishingActive.Malware.IPv4')
            
            # Check for inactive phishing threat signatures
            elif ip_address in ipv4_addresses_phishing_inactive_signatures_data:
                logging.warning(f"IPv4 address {ip_address} detected as an inactive phishing threat.")
                notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PhishingInactive.Malware.IPv4')
            
            # Check if the IPv4 address is whitelisted
            elif ip_address in ipv4_whitelist_data:
                logging.info(f"IPv4 address {ip_address} is whitelisted.")
                return
            else:
                logging.info(f"Unknown IPv4 address detected: {ip_address}")
                print(f"Unknown IPv4 address detected: {ip_address}")
        else:
            logging.debug(f"Invalid IP address format detected: {ip_address}")
            print(f"Invalid IP address format detected: {ip_address}")

    except Exception as ex:
        logging.error(f"Error scanning IP address {ip_address}: {ex}")
        print(f"Error scanning IP address {ip_address}: {ex}")

# --------------------------------------------------------------------------
# Main scanner: combine all individual scans and pass the flags along
def scan_code_for_links(decompiled_code, file_path, cs_file_path=None,
                          dotnet_flag=False, nuitka_flag=False, pyinstaller_flag=False, pyinstaller_deepseek_flag=False):
    """
    Scan the decompiled code for Discord-related URLs (via contains_discord_code),
    general URLs, domains, and IP addresses. The provided flags are passed along
    to each individual scanning function so that every detection scenario uses its unique
    virus signature.
    """
    contains_discord_code(decompiled_code, file_path, cs_file_path,
                            dotnet_flag=dotnet_flag, nuitka_flag=nuitka_flag,
                            pyinstaller_flag=pyinstaller_flag, pyinstaller_deepseek_flag=pyinstaller_deepseek_flag)
    urls = set(re.findall(r'https?://[^\s/$.?#]\S*', decompiled_code))
    for url in urls:
        scan_url_general(url, dotnet_flag=dotnet_flag, nuitka_flag=nuitka_flag,
                          pyinstaller_flag=pyinstaller_flag, pyinstaller_deepseek_flag=pyinstaller_deepseek_flag)
        scan_domain_general(url, dotnet_flag=dotnet_flag, nuitka_flag=nuitka_flag,
                            pyinstaller_flag=pyinstaller_flag, pyinstaller_deepseek_flag=pyinstaller_deepseek_flag)
    ipv4_addresses = set(re.findall(
        r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        decompiled_code
    ))
    for ip in ipv4_addresses:
        scan_ip_address_general(ip, dotnet_flag=dotnet_flag, nuitka_flag=nuitka_flag,
                                pyinstaller_flag=pyinstaller_flag, pyinstaller_deepseek_flag=pyinstaller_deepseek_flag)
    ipv6_addresses = set(re.findall(
        r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
        decompiled_code
    ))
    for ip in ipv6_addresses:
        scan_ip_address_general(ip, dotnet_flag=dotnet_flag, nuitka_flag=nuitka_flag,
                                pyinstaller_flag=pyinstaller_flag, pyinstaller_deepseek_flag=pyinstaller_deepseek_flag)

def enum_process_modules(handle):
    """Enumerate and retrieve loaded modules in a process."""
    hmodules = (ctypes.c_void_p * 1024)
    needed = ctypes.c_ulong()
    if not pymem.ressources.psapi.EnumProcessModulesEx(
        handle,
        ctypes.byref(hmodules),
        ctypes.sizeof(hmodules),
        ctypes.byref(needed),
        pymem.ressources.structure.EnumProcessModuleEX.LIST_MODULES_ALL
    ):
        raise RuntimeError("Failed to enumerate process modules")
    return [module for module in hmodules if module]

def get_module_info(handle, base_addr):
    """Retrieve module information."""
    module_info = pymem.ressources.structure.MODULEINFO()
    pymem.ressources.psapi.GetModuleInformation(
        handle,
        ctypes.c_void_p(base_addr),
        ctypes.byref(module_info),
        ctypes.sizeof(module_info)
    )
    return module_info

def read_memory_data(pm, base_addr, size):
    """Read memory data from a specific module."""
    return pm.read_bytes(base_addr, size)

def extract_ascii_strings(data):
    """Extract readable ASCII strings from binary data."""
    return re.findall(r'[ -~]{4,}', data.decode('ascii', errors='ignore'))

def save_memory_data(base_addr, data):
    """Save raw memory data to a file."""
    memory_file = os.path.join(memory_dir, f"module_{hex(base_addr)}.bin")
    with open(memory_file, 'wb') as mem_file:
        mem_file.write(data)

def save_extracted_strings(output_filename, extracted_strings):
    """Save extracted ASCII strings to a file."""
    with open(output_filename, 'w', encoding='utf-8') as output_file:
        output_file.writelines(f"{line}\n" for line in extracted_strings)

def analyze_process_memory(file_path):
    """Perform memory analysis on the specified file path."""
    try:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        logging.info(f"Starting analysis on: {file_path}")

        # Attach to the process
        pm = pymem.Pymem(file_path)
        logging.info(f"Attached to process: {file_path}")

        extracted_strings = []
        try:
            for module in enum_process_modules(pm.process_handle):
                base_addr = ctypes.cast(module, ctypes.POINTER(ctypes.c_void_p)).contents.value
                module_info = get_module_info(pm.process_handle, base_addr)

                try:
                    data = read_memory_data(pm, base_addr, module_info.SizeOfImage)
                    save_memory_data(base_addr, data)

                    ascii_strings = extract_ascii_strings(data)
                    extracted_strings.append(f"{file_path}: Module {hex(base_addr)}:")
                    extracted_strings.extend(ascii_strings)
                except Exception as ex:
                    extracted_strings.append(f"Error reading {hex(base_addr)}: {ex}")
        finally:
            pm.close_process()  # Explicitly release the process handle
            logging.info(f"Released process handle for: {file_path}")

        # Check for existing output file and create a unique filename
        base_filename = "extracted_strings"
        output_filename = os.path.join(memory_dir, f"{base_filename}.txt")
        count = 1
        while os.path.exists(output_filename):
            output_filename = os.path.join(memory_dir, f"{base_filename}_{count}.txt")
            count += 1

        # Save the extracted strings
        save_extracted_strings(output_filename, extracted_strings)

        logging.info(f"Analysis complete. Results saved in {output_filename}")

        # Return the new file path
        return output_filename

    except Exception as ex:
        logging.error(f"An error occurred: {ex}")
        return None

def scan_file_with_machine_learning_ai(file_path, threshold=0.86):
    """Scan a file for malicious activity using machine learning."""

    # Default assignment of malware_definition before starting the process
    malware_definition = "Unknown"  # Assume unknown until checked
    logging.info(f"Starting machine learning scan for file: {file_path}")

    try:
        pe = pefile.PE(file_path)
        if not pe:
            logging.warning(f"File {file_path} is not a valid PE file. Returning default value 'Unknown'.")
            return False, malware_definition, 0  # If it's not a PE file, return the default value

        logging.info(f"File {file_path} is a valid PE file, proceeding with feature extraction.")
        file_info = extract_infos(file_path)  # Extract detailed file info
        file_numeric_features = extract_numeric_features(file_path)

        is_malicious_machine_learning_ai = False
        malware_rank = None
        nearest_malicious_similarity = 0
        nearest_benign_similarity = 0

        # Logging the file info for detailed output
        logging.info(f"File information: {file_info}")

        # Checking against malicious features
        for malicious_features, info in zip(malicious_numeric_features, malicious_file_names):
            rank = info['numeric_tag']
            similarity = calculate_similarity(file_numeric_features, malicious_features)
            if similarity > nearest_malicious_similarity:
                nearest_malicious_similarity = similarity
            if similarity >= threshold:
                is_malicious_machine_learning_ai = True
                malware_rank = rank
                malware_definition = info['file_name']  # Set malware definition if malicious match is found
                logging.warning(f"Malicious activity detected in {file_path}. Malware definition: {malware_definition}, similarity: {similarity}, rank: {malware_rank}")
                break

        # If malicious not detected, check for benign features
        if not is_malicious_machine_learning_ai:
            for benign_features, info in zip(benign_numeric_features, benign_file_names):
                similarity = calculate_similarity(file_numeric_features, benign_features)
                if similarity > nearest_benign_similarity:
                    nearest_benign_similarity = similarity
                    benign_definition = info['file_name']  # Store the benign file name for logging

            # If similarity exceeds threshold, return as benign (no malicious detected)
            if nearest_benign_similarity >= 0.93:
                malware_definition = "Benign"
                logging.info(f"File {file_path} is classified as benign (Benign Definition: {benign_definition}) with similarity: {nearest_benign_similarity}")
            else:
                malware_definition = "Unknown"
                logging.info(f"File {file_path} is classified as unknown with similarity: {nearest_benign_similarity}")

        # Return True for malicious or False for benign/unknown
        if is_malicious_machine_learning_ai:
            logging.info(f"File {file_path} is flagged as malicious. Returning: False, {malware_definition}, rank: {malware_rank}.")
            return False, malware_definition, nearest_benign_similarity  # Malicious detected, return False
        else:
            logging.info(f"File {file_path} is not malicious. Returning: False, {malware_definition}.")
            return False, malware_definition, nearest_benign_similarity  # For benign or unknown, still False

    except pefile.PEFormatError:
        logging.error(f"Error: {file_path} does not have a valid PE format.")
        return False, malware_definition, 0  # Default return value if the PE format is invalid
    except Exception as ex:
        print(f"An error occurred while scanning file {file_path}: {ex}")
        logging.error(f"An error occurred while scanning file {file_path}: {ex}")
        return False, malware_definition, 0  # Default return value in case of general exception

def restart_clamd_thread():
    try:
        threading.Thread(target=restart_clamd).start()
    except Exception as ex:
        logging.error(f"Error starting clamd restart thread: {ex}")
        print(f"Error starting clamd restart thread: {ex}")

def restart_clamd():
    try:
        print("Stopping ClamAV...")
        stop_result = subprocess.run(["net", "stop", 'clamd'], capture_output=True, text=True)
        if stop_result.returncode != 0:
                logging.error("Failed to stop ClamAV.")
                print("Failed to stop ClamAV.")
            
        print("Starting ClamAV...")
        start_result = subprocess.run(["net", "start", 'clamd'], capture_output=True, text=True)
        if start_result.returncode == 0:
            logging.info("ClamAV restarted successfully.")
            print("ClamAV restarted successfully.")
            return True
        else:
            logging.error("Failed to start ClamAV.")
            print("Failed to start ClamAV.")
            return False
    except Exception as ex:
        logging.error(f"An error occurred while restarting ClamAV: {ex}")
        print(f"An error occurred while restarting ClamAV: {ex}")
        return False

def scan_file_with_clamd(file_path):
    """Scan file using clamd."""
    try:
        file_path = os.path.abspath(file_path)  # Get absolute path
        result = subprocess.run([clamdscan_path, file_path], capture_output=True, text=True)
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
    except Exception as ex:
        logging.error(f"Error scanning file {file_path}: {ex}")
        print(f"Error scanning file {file_path}: {ex}")
        return "Clean"

def is_related_to_critical_paths(file_path):
    return file_path.startswith(sandboxie_folder) or file_path == main_file_path

class RealTimeWebProtectionHandler:
    def __init__(self):
        self.scanned_domains = []
        self.scanned_ipv4_addresses = []
        self.scanned_ipv6_addresses = []
        self.scanned_urls = []
        self.domain_ip_to_file_map = {}

    def map_domain_ip_to_file(self, entity):
        return self.domain_ip_to_file_map.get(entity)

    def handle_detection(self, entity_type, entity_value, detection_type=None):
        file_path = self.map_domain_ip_to_file(entity_value)
        notify_info = {'domain': None, 'ip_address': None, 'url': None, 'file_path': None,
                       'detection_type': detection_type}

        try:
            if file_path and is_related_to_critical_paths(file_path):
                message = f"{entity_type.capitalize()} {entity_value} is related to a critical path: {file_path}"
                if detection_type:
                    message = f"{detection_type} {message}"
                logging.warning(message)
                print(message)
                notify_info[entity_type] = entity_value
                notify_info['file_path'] = file_path
            else:
                if file_path:
                    message = f"{entity_type.capitalize()} {entity_value} is not related to critical paths but associated with file path: {file_path}"
                else:
                    message = f"{entity_type.capitalize()} {entity_value} is not related to critical paths and has no associated file path."
                if detection_type:
                    message = f"{detection_type} {message}"
                logging.info(message)
                print(message)

            if any(notify_info.values()):
                notify_user_for_web(**notify_info)
        except Exception as ex:
            logging.error(f"Error in handle_detection: {ex}")
            print(f"Error in handle_detection: {ex}")

    def scan_domain(self, domain):
        try:
            if domain in self.scanned_domains:
                return
            self.scanned_domains.append(domain)
            message = f"Scanning domain: {domain}"
            logging.info(message)
            print(message)

            if domain.lower().startswith("www."):
                domain = domain[4:]

            parts = domain.split(".")
            main_domain = domain if len(parts) < 3 else ".".join(parts[-2:])

            # Check against spam subdomains first
            if main_domain in spam_sub_domains_data:
                self.handle_detection('subdomain', main_domain, 'SPAM SUBDOMAIN')
                return

            # Check against mining subdomains
            if main_domain in mining_sub_domains_data:
                self.handle_detection('subdomain', main_domain, 'MINING SUBDOMAIN')
                return

            # Check against abuse subdomains
            if main_domain in abuse_sub_domains_data:
                self.handle_detection('subdomain', main_domain, 'ABUSE SUBDOMAIN')
                return

            # Check against phishing subdomains
            if main_domain in phishing_sub_domains_data:
                self.handle_detection('subdomain', main_domain, 'PHISHING SUBDOMAIN')
                return

            # Check against malware subdomains
            if main_domain in malware_sub_domains_data:
                self.handle_detection('subdomain', main_domain, 'MALWARE SUBDOMAIN')
                return

            # Check against whitelist subdomains
            if main_domain in whitelist_sub_domains_data:
                logging.info(f"Domain {main_domain} is whitelisted (subdomain)")
                return

            # Check against malware mail subdomains
            if main_domain in malware_mail_sub_domains_data:
                self.handle_detection('subdomain', main_domain, 'MALWARE MAIL SUBDOMAIN')
                return

            # Check against whitelist mail subdomains
            if main_domain in whitelist_mail_sub_domains_data:
                logging.info(f"Domain {main_domain} is whitelisted (mail subdomain)")
                return

            # Check against spam domains
            if main_domain in spam_domains_data:
                self.handle_detection('domain', main_domain, 'SPAM')
                return

            # Check against mining domains
            if main_domain in mining_domains_data:
                self.handle_detection('domain', main_domain, 'MINING')
                return

            # Check against abuse domains
            if main_domain in abuse_domains_data:
                self.handle_detection('domain', main_domain, 'ABUSE')
                return

            # Check against phishing domains
            if main_domain in phishing_domains_data:
                self.handle_detection('domain', main_domain, 'PHISHING')
                return

            # Check against malware domains
            if main_domain in malware_domains_data:
                self.handle_detection('domain', main_domain, 'MALWARE')
                return

            # Check against malware domains in mail data
            if main_domain in malware_domains_mail_data:
                self.handle_detection('domain', main_domain, 'MALWARE MAIL')
                return

            # Check if domain is whitelisted
            if main_domain in whitelist_domains_data:
                logging.info(f"Domain {main_domain} is whitelisted")
                return

            # Check if domain is whitelisted in mail data
            if main_domain in whitelist_domains_mail_data:
                logging.info(f"Domain {main_domain} is whitelisted (mail)")
                return

        except Exception as ex:
            logging.error(f"Error scanning domain {domain}: {ex}")
            print(f"Error scanning domain {domain}: {ex}")

    def scan_ip_address(self, ip_address):
        try:
            # First, check if the IP address is local
            if is_local_ip(ip_address):
                message = f"Skipping local IP address: {ip_address}"
                logging.info(message)
                print(message)
                return

            # Check if the IP address has already been scanned
            if ip_address in self.scanned_ipv6_addresses or ip_address in self.scanned_ipv4_addresses:
                return

            # Determine whether it's an IPv6 or IPv4 address
            if ':' in ip_address:  # IPv6 address
                self.scanned_ipv6_addresses.append(ip_address)
                message = f"Scanning IPv6 address: {ip_address}"
                logging.info(message)
                print(message)

                # Check against IPv6 signatures
                if ip_address in ipv6_addresses_signatures_data:
                    self.handle_detection('ip_address', ip_address, 'MALWARE')

                # Check if it is in the IPv6 whitelist
                elif ip_address in ipv6_whitelist_data:
                    message = f"IPv6 address {ip_address} is whitelisted"
                    logging.info(message)
                    print(message)
                else:
                    message = f"Unknown IPv6 address detected: {ip_address}"
                    logging.info(message)
                    print(message)

            else:  # IPv4 address
                self.scanned_ipv4_addresses.append(ip_address)
                message = f"Scanning IPv4 address: {ip_address}"
                logging.info(message)
                print(message)

                # Check against IPv4 malware signatures
                if ip_address in ipv4_addresses_signatures_data:
                    self.handle_detection('ip_address', ip_address, 'MALWARE')

                # Check against IPv4 DDoS signatures
                elif ip_address in ipv4_addresses_ddos_signatures_data:
                    self.handle_detection('ip_address', ip_address, 'DDOS')

                # Check against active phishing signatures
                elif ip_address in ipv4_addresses_phishing_active_signatures_data:
                    self.handle_detection('ip_address', ip_address, 'PHISHING_ACTIVE')

                # Check against inactive phishing signatures
                elif ip_address in ipv4_addresses_phishing_inactive_signatures_data:
                    self.handle_detection('ip_address', ip_address, 'PHISHING_INACTIVE')

                # Check if it is in the IPv4 whitelist
                elif ip_address in ipv4_whitelist_data:
                    message = f"IPv4 address {ip_address} is whitelisted"
                    logging.info(message)
                    print(message)
                else:
                    message = f"Unknown IPv4 address detected: {ip_address}"
                    logging.info(message)
                    print(message)

        except Exception as ex:
            logging.error(f"Error scanning IP address {ip_address}: {ex}")
            print(f"Error scanning IP address {ip_address}: {ex}")

    def scan_url(self, url):
        try:
            if url in self.scanned_urls:
                logging.info(f"URL {url} has already been scanned.")
                return

            self.scanned_urls.append(url)  # Add to the scanned list
            for entry in urlhaus_data:
                if entry['url'] in url:
                    message = (
                        f"URL {url} matches the URLhaus signatures.\n"
                        f"ID: {entry['id']}\n"
                        f"Date Added: {entry['dateadded']}\n"
                        f"URL Status: {entry['url_status']}\n"
                        f"Last Online: {entry['last_online']}\n"
                        f"Threat: {entry['threat']}\n"
                        f"Tags: {entry['tags']}\n"
                        f"URLhaus Link: {entry['urlhaus_link']}\n"
                        f"Reporter: {entry['reporter']}"
                    )
                    logging.warning(message)
                    print(message)

                    # Use handle_detection for related file path and notification logic
                    self.handle_detection(
                        entity_type="url",
                        entity_value=url,
                        detection_type="URLhaus Match"
                    )
                    return

            logging.info(f"No match found for URL: {url}")
            print(f"No match found for URL: {url}")

        except Exception as ex:
            logging.error(f"Error scanning URL {url}: {ex}")
            print(f"Error scanning URL {url}: {ex}")

    def handle_ipv4(self, packet):
        try:
            if IP in packet and DNS in packet:
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

                self.scan_ip_address(packet[IP].src)
                self.scan_ip_address(packet[IP].dst)
                
        except Exception as ex:
            logging.error(f"Error handling IPv4 packet: {ex}")
            print(f"Error handling IPv4 packet: {ex}")

    def handle_ipv6(self, packet):
        try:
            if IPv6 in packet and DNS in packet:
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

                self.scan_ip_address(packet[IPv6].src)
                self.scan_ip_address(packet[IPv6].dst)
            else:
                logging.debug("IPv6 layer or DNS layer not found in the packet.")
                
        except Exception as ex:
            logging.error(f"Error handling IPv6 packet: {ex}")
            print(f"Error handling IPv6 packet: {ex}")

    def on_packet_received(self, packet):
        try:
            if IP in packet:
                self.handle_ipv4(packet)
                if TCP in packet or UDP in packet:
                    url = f"{packet[IP].src}:{packet[IP].dport}"
                    self.scan_url(url)

            if IPv6 in packet:
                self.handle_ipv6(packet)

            if DNS in packet:
                if packet[DNS].qd:
                    for i in range(packet[DNS].qdcount):
                        query_name = packet[DNSQR][i].qname.decode().rstrip('.')
                        self.scan_domain(query_name)
                        message = f"DNS Query: {query_name}"
                        logging.info(message)
                        print(message)

                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        answer_name = packet[DNSRR][i].rrname.decode().rstrip('.')
                        self.scan_domain(answer_name)
                        message = f"DNS Answer: {answer_name}"
                        logging.info(message)
                        print(message)

                if IP in packet:
                    self.scan_ip_address(packet[IP].src)
                    self.scan_ip_address(packet[IP].dst)

        except Exception as ex:
            logging.error(f"Error processing packet: {ex}")
            print(f"Error processing packet: {ex}")

class RealTimeWebProtectionObserver:
    def __init__(self):
        self.handler = RealTimeWebProtectionHandler()
        self.is_started = False
        self.thread = None

    def begin_observing(self):
        if not self.is_started:
            self.thread = threading.Thread(target=self.start_sniffing)
            self.thread.start()
            self.is_started = True
            message = "Real-time web protection observer started"
            logging.info(message)
            print(message)

    def start_sniffing(self):
        filter_expression = "(tcp or udp)"
        try:
            sniff(filter=filter_expression, prn=self.handler.on_packet_received, store=0)
        except Exception as ex:
            logging.error(f"An error occurred while sniffing packets: {ex}")
            print(f"Error while sniffing packets: {ex}")

web_protection_observer = RealTimeWebProtectionObserver()

def scan_yara(file_path):
    matched_rules = []

    try:
        if not os.path.exists(file_path):
            logging.error(f"File not found during YARA scan: {file_path}")
            return None

        with open(file_path, 'rb') as yara_file:
            data_content = yara_file.read()

            # Check matches for compiled_rule
            if compiled_rule:
                matches = compiled_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from compiled_rule.")
            else:
                logging.warning("compiled_rule is not defined.")

            # Check matches for yarGen_rule
            if yarGen_rule:
                matches = yarGen_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from yarGen_rule.")
            else:
                logging.warning("yarGen_rule is not defined.")

            # Check matches for icewater_rule
            if icewater_rule:
                matches = icewater_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from icewater_rule.")
            else:
                logging.warning("icewater_rule is not defined.")

            # Check matches for valhalla_rule
            if valhalla_rule:
                matches = valhalla_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from valhalla_rule.")
            else:
                logging.warning("valhalla_rule is not defined.")

            # Check matches for yaraxtr_rule (loaded with yara_x)
            if yaraxtr_rule:
                scanner = yara_x.Scanner()
                results = scanner.scan(data=data_content)
                if results.matching_rules:
                    for rule in results.matching_rules:
                        if hasattr(rule, 'identifier') and rule.identifier not in excluded_rules:
                            matched_rules.append(rule.identifier)
                        else:
                            logging.info(f"Rule {rule.identifier} is excluded from yaraxtr_rule.")
            else:
                logging.warning("yaraxtr_rule is not defined.")

        # Return matched rules as the yara_result if not empty, otherwise return None
        return matched_rules if matched_rules else None

    except Exception as ex:
        logging.error(f"An error occurred during YARA scan: {ex}")
        return None

# Function to check the signature of a file
def check_signature(file_path):
    try:
        # Command to verify the executable signature status
        cmd = f'"{file_path}"'
        verify_command = "(Get-AuthenticodeSignature " + cmd + ").Status"
        process = subprocess.run(['powershell.exe', '-Command', verify_command], stdout=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')

        status = process.stdout.strip() if process.stdout else ""
        is_valid = "Valid" in status
        signature_status_issues = "HashMismatch" in status or "NotTrusted" in status

        # Command to check for Microsoft signature if there are no issues
        if not signature_status_issues:
            ms_command = f"Get-AuthenticodeSignature '{file_path}' | Format-List"
            ms_result = subprocess.run(["powershell.exe", "-Command", ms_command], capture_output=True, text=True, encoding='utf-8', errors='replace')
            signature_data = ms_result.stdout if ms_result.stdout else ""

            # Check if the signature is from Microsoft using the loaded Microsoft signatures list
            has_microsoft_signature = any(sig in signature_data for sig in microsoft_signatures)
        else:
            has_microsoft_signature = False

        # Check if the file matches an antivirus signature
        matches_antivirus_signature = any(sig in signature_data for sig in antivirus_signatures)
        if matches_antivirus_signature:
            warning_msg = f"TThe file '{file_path}' matches an antivirus signature. It might be a vulnerable driver or antivirus software, which may cause false positives!"
            print(warning_msg)
            logging.warning(warning_msg)

        return {
            "is_valid": is_valid,
            "has_microsoft_signature": has_microsoft_signature,
            "signature_status_issues": signature_status_issues
        }

    except Exception as ex:
        error_msg = f"An error occurred while checking signature: {ex}"
        print(error_msg)
        logging.error(error_msg)
        return {
            "is_valid": False,
            "has_microsoft_signature": False,
            "signature_status_issues": False
        }

def check_valid_signature_only(file_path):
    try:
        # Command to verify the executable signature status
        verify_command = f"(Get-AuthenticodeSignature '{file_path}').Status"
        process = subprocess.run(['powershell.exe', '-Command', verify_command], capture_output=True, text=True)
        
        status = process.stdout.strip()
        is_valid = "Valid" in status
        
        return {
            "is_valid": is_valid
        }
    except Exception as ex:
        print(f"An error occurred while verifying a valid signature: {ex}")
        logging.error(f"An error occurred while verifying a valid signature: {ex}")
        return {
            "is_valid": False
        }

def clean_directories():
    try:
        # Clean decompile directory if it exists, otherwise create it
        if os.path.isdir(decompile_dir):
            shutil.rmtree(decompile_dir)
            logging.info(f"Successfully cleaned the decompile folder at: {decompile_dir}")
        else:
            logging.info(f"Decompile folder does not exist at: {decompile_dir}")
        os.makedirs(decompile_dir)
        logging.info(f"Created the decompile folder at: {decompile_dir}")
        
        # Clean ghidra_projects directory if it exists, otherwise create it
        if os.path.isdir(ghidra_projects_dir):
            shutil.rmtree(ghidra_projects_dir)
            logging.info(f"Successfully cleaned the ghidra_projects folder at: {ghidra_projects_dir}")
        else:
            logging.info(f"Ghidra projects folder does not exist at: {ghidra_projects_dir}")
        os.makedirs(ghidra_projects_dir)
        logging.info(f"Created the ghidra_projects folder at: {ghidra_projects_dir}")

        # Check if ghidra_logs directory exists, create if not
        if not os.path.isdir(ghidra_logs_dir):
            os.makedirs(ghidra_logs_dir)
            logging.info(f"Created the ghidra_logs folder at: {ghidra_logs_dir}")
        else:
            logging.info(f"Ghidra logs folder exists at: {ghidra_logs_dir}")

    except Exception as ex:
        logging.error(f"An error occurred while cleaning the directories: {ex}")

def is_pe_file(file_path):
    """Check if the file at the specified path is a PE (Portable Executable) file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be PE check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for PE32 or PE64 in the result
        if "PE32" in result.stdout or "PE64" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"PE file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a PE file. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def is_elf_file(file_path):
    """Check if the file at the specified path is an ELF file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be ELF check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for ELF format in the result
        if "ELF" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"ELF file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not an ELF file. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def is_macho_file(file_path):
    """Check if the file at the specified path is a Mach-O file using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be Mach-O check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for Mach-O in the result
        if "Mach-O" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"Mach-O file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a Mach-O file. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def is_encrypted(zip_info):
    """Check if a ZIP entry is encrypted."""
    return zip_info.flag_bits & 0x1 != 0

def contains_rlo_after_dot(filename):
    """Check if the filename contains an RLO character after a dot."""
    return ".\u202E" in filename

class FileType:
    UNKNOWN = -1
    ELF = 0
    PE = 1
    MACHO = 2

class CompressionFlag:
    UNKNOWN = -1
    NON_COMPRESSED = 0
    COMPRESSED = 1

class PayloadError(Exception):
    """Custom exception for payload processing errors"""
    def __init__(self, message):
        super().__init__(message)
        logging.error(f"PayloadError: {message}")

class NuitkaPayload:
    MAGIC_KA = b'KA'
    MAGIC_UNCOMPRESSED = ord('X')
    MAGIC_COMPRESSED = ord('Y')
    
    def __init__(self, data: bytes, offset: int, size: int):
        self.data = data
        self.offset = offset
        self.size = size
        self.compression = CompressionFlag.UNKNOWN
        self._validate()
    
    def _validate(self):
        """Validate payload magic and set compression flag"""
        if not self.data.startswith(self.MAGIC_KA):
            raise PayloadError("Invalid Nuitka payload magic")
        
        magic_type = self.data[2]
        if magic_type == self.MAGIC_UNCOMPRESSED:
            self.compression = CompressionFlag.NON_COMPRESSED
        elif magic_type == self.MAGIC_COMPRESSED:
            self.compression = CompressionFlag.COMPRESSED
        else:
            raise PayloadError(f"Unknown compression magic: {magic_type}")
    
    def get_stream(self) -> BinaryIO:
        """Get a file-like object for reading the payload"""
        # Skip the 3-byte magic header
        payload_data = self.data[3:]
        stream = io.BytesIO(payload_data)
        
        if self.compression == CompressionFlag.COMPRESSED:
            try:
                dctx = zstandard.ZstdDecompressor()
                # Create a stream reader with a large read size
                return dctx.stream_reader(stream, read_size=8192)
            except zstandard.ZstdError as ex:
                raise PayloadError(f"Failed to initialize decompression: {str(ex)}")
        return stream

class NuitkaExtractor:
    def __init__(self, filepath: str, output_dir: str):
        self.filepath = filepath
        self.output_dir = output_dir
        self.file_type = FileType.UNKNOWN
        self.payload: Optional[NuitkaPayload] = None
    
    def _detect_file_type(self) -> int:
        """Detect the executable file type using Detect It Easy methods"""
        if is_nuitka_file(self.filepath):
            return FileType.PE  # Assuming Nuitka files are detected as PE files
        elif is_pe_file(self.filepath):
            return FileType.PE
        elif is_elf_file(self.filepath):
            return FileType.ELF
        elif is_macho_file(self.filepath):
            return FileType.MACHO
        return FileType.UNKNOWN

    def _find_pe_resource(self, pe: pefile.PE) -> Tuple[Optional[int], Optional[int]]:
        """Find the Nuitka resource in PE file"""
        try:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'directory'):
                    for entry1 in entry.directory.entries:
                        if entry1.id == 27:  # Nuitka's resource ID
                            if hasattr(entry1, 'directory'):
                                data_entry = entry1.directory.entries[0]
                                if hasattr(data_entry, 'data'):
                                    offset = pe.get_offset_from_rva(data_entry.data.struct.OffsetToData)
                                    size = data_entry.data.struct.Size
                                    return offset, size
        except Exception:
            pass
        return None, None

    def _extract_pe_payload(self) -> Optional[NuitkaPayload]:
        """Extract payload from PE file"""
        try:
            pe = pefile.PE(self.filepath, fast_load=False)
            
            # Find RT_RCDATA resource with ID 27
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                raise PayloadError("No resource directory found")
            
            offset, size = self._find_pe_resource(pe)
            if offset is None or size is None:
                raise PayloadError("No Nuitka payload found in PE resources")
            
            # Read the payload data
            with open(self.filepath, 'rb') as f:
                f.seek(offset)
                payload_data = f.read(size)
                
            return NuitkaPayload(payload_data, offset, size)
            
        except Exception as ex:
            raise PayloadError(f"PE payload extraction failed: {str(ex)}")

    def _extract_elf_payload(self) -> Optional[NuitkaPayload]:
        """Extract payload from ELF file"""
        try:
            with open(self.filepath, 'rb') as f:
                elf = ELFFile(f)
                
                # Find last section to locate appended data
                last_section = max(elf.iter_sections(), 
                                 key=lambda s: s.header.sh_offset + s.header.sh_size)
                
                # Read trailer for payload size
                f.seek(-8, io.SEEK_END)
                payload_size = struct.unpack('<Q', f.read(8))[0]
                
                # Read payload
                payload_offset = last_section.header.sh_offset + last_section.sh_size
                f.seek(payload_offset)
                payload_data = f.read(payload_size)
                
                return NuitkaPayload(payload_data, payload_offset, payload_size)
                
        except Exception as ex:
            raise PayloadError(f"ELF payload extraction failed: {str(ex)}")

    def _extract_macho_payload(self) -> Optional[NuitkaPayload]:
        """Extract payload from Mach-O file"""
        try:
            macho = macholib.MachO.MachO(self.filepath)
            
            for header in macho.headers:
                for cmd in header.commands:
                    if cmd[0].cmd in (macholib.mach_o.LC_SEGMENT, macholib.mach_o.LC_SEGMENT_64):
                        for section in cmd[1].sections:
                            if section[0].decode('utf-8') == 'payload':
                                offset = section[2]
                                size = section[3]
                                
                                with open(self.filepath, 'rb') as f:
                                    f.seek(offset)
                                    payload_data = f.read(size)
                                    return NuitkaPayload(payload_data, offset, size)
                                    
            raise PayloadError("No payload section found in Mach-O file")
            
        except Exception as ex:
            raise PayloadError(f"Mach-O payload extraction failed: {str(ex)}")

    def _read_string(self, stream: BinaryIO, is_wide: bool = False) -> Optional[str]:
        """Read a null-terminated string from the stream"""
        result = bytearray()
        while True:
            char = stream.read(2 if is_wide else 1)
            if not char or char == b'\0' * len(char):
                break
            result.extend(char)
        
        if not result:
            return None
            
        try:
            return result.decode('utf-16-le' if is_wide else 'utf-8')
        except UnicodeDecodeError:
            return None

    def _extract_files(self, stream: BinaryIO):
        """Extract files from the payload stream"""
        total_files = 0
        os.makedirs(self.output_dir, exist_ok=True)

        try:
            while True:
                # Read filename
                filename = self._read_string(stream, is_wide=(self.file_type == FileType.PE))
                if not filename:
                    break

                # Read file flags for ELF
                if self.file_type == FileType.ELF:
                    stream.read(1)  # Skip flags

                # Read file size
                size_data = stream.read(8)
                if not size_data or len(size_data) != 8:
                    break
                    
                file_size = struct.unpack('<Q', size_data)[0]

                # Sanitize output path
                safe_output_dir = str(self.output_dir).replace('..', '__')
                outpath = os.path.join(safe_output_dir, filename)
                os.makedirs(os.path.dirname(outpath), exist_ok=True)

                # Extract file
                try:
                    with open(outpath, 'wb') as f:
                        remaining = file_size
                        while remaining > 0:
                            chunk_size = min(remaining, 8192)
                            data = stream.read(chunk_size)
                            if not data:
                                logging.warning(f"Incomplete read for {filename}")
                                break
                            f.write(data)
                            remaining -= len(data)
                    total_files += 1
                    logging.info(f"[+] Extracted: {filename}")
                except Exception as ex:
                    logging.error(f"Failed to extract {filename}: {ex}")
                    continue

        except Exception as ex:
            logging.error(f"Extraction error: {ex}")

        return total_files

    def extract(self):
        """Main extraction process"""
        try:
            # Detect file type using the new detection methods
            self.file_type = self._detect_file_type()
            if self.file_type == FileType.UNKNOWN:
                raise PayloadError("Unsupported file type")
            
            logging.info(f"[+] Processing: {self.filepath}")
            logging.info(f"[+] Detected file type: {['ELF', 'PE', 'MACHO'][self.file_type]}")

            # Extract payload based on file type
            if self.file_type == FileType.PE:
                self.payload = self._extract_pe_payload()
            elif self.file_type == FileType.ELF:
                self.payload = self._extract_elf_payload()
            else:  # MACHO
                self.payload = self._extract_macho_payload()
            
            if not self.payload:
                raise PayloadError("Failed to extract payload")
            
            logging.info(f"[+] Payload size: {self.payload.size} bytes")
            logging.info(f"[+] Compression: {'Yes' if self.payload.compression == CompressionFlag.COMPRESSED else 'No'}")
            
            # Extract files from payload
            stream = self.payload.get_stream()
            total_files = self._extract_files(stream)
            
            logging.info(f"[+] Successfully extracted {total_files} files to {self.output_dir}")
            
        except PayloadError as ex:
            logging.error(f"[!] {str(ex)}")
        except Exception as ex:
            logging.error(f"[!] Unexpected error: {str(ex)}")

def scan_zip_file(file_path):
    """Scan files within a zip archive."""
    try:
        zip_size = os.path.getsize(file_path)

        with zipfile.ZipFile(file_path, 'r') as zfile:
            for zip_info in zfile.infolist():

                # Check for RLO in filenames before handling encryption
                if contains_rlo_after_dot(zip_info.filename):
                    virus_name = "HEUR:RLO.Suspicious.Name.Encrypted.ZIP.Generic"
                    logging.warning(
                        f"Filename {zip_info.filename} in {file_path} contains RLO character after a comma - "
                        f"flagged as {virus_name}"
                    )
                    notify_rlo_warning(file_path, "ZIP", virus_name)
                
                if is_encrypted(zip_info):
                    logging.info(f"Skipping encrypted file: {zip_info.filename}")
                    continue

                extracted_file_path = os.path.join(zip_extracted_dir, zip_info.filename)
                zfile.extract(zip_info, zip_extracted_dir)

                # Check for suspicious conditions: large files in small ZIP archives
                extracted_file_size = os.path.getsize(extracted_file_path)
                if zip_size < 20 * 1024 * 1024 and extracted_file_size > 650 * 1024 * 1024:
                    virus_name = "HEUR:Win32.Suspicious.Size.Encrypted.ZIP"
                    logging.warning(
                        f"ZIP file {file_path} is smaller than 20MB but contains a large file: {zip_info.filename} "
                        f"({extracted_file_size / (1024 * 1024)} MB) - flagged as {virus_name}. "
                        "Potential ZIPbomb or Fake Size detected to avoid VirusTotal detections."
                    )
                    notify_size_warning(file_path, "ZIP", virus_name)

        return True, []
    except Exception as ex:
        logging.error(f"Error scanning zip file: {file_path} - {ex}")
        return False, ""

def scan_7z_file(file_path):
    """Scan files within a 7z archive."""
    try:
        # Get the size of the 7z file
        archive_size = os.path.getsize(file_path)

        with py7zr.SevenZipFile(file_path, mode='r') as archive:
            for entry in archive.list():
                filename = entry.filename

                # RLO check
                if contains_rlo_after_dot(filename):
                    virus_name = "HEUR:RLO.Suspicious.Name.Encrypted.7z.Generic"
                    logging.warning(
                        f"Filename {filename} in {file_path} contains RLO character after a dot - "
                        f"flagged as {virus_name}"
                    )
                    notify_rlo_warning(file_path, "7z", virus_name)

                if archive.is_encrypted(entry):
                    logging.info(f"Skipping encrypted file: {filename}")
                    continue

                # Extract the file
                extracted_file_path = os.path.join(seven_zip_extracted_dir, filename)
                # Corrected extraction method
                archive.extract(path=seven_zip_extracted_dir)

                # Check for suspicious conditions: large files in small 7z archives
                extracted_file_size = os.path.getsize(extracted_file_path)
                if archive_size < 20 * 1024 * 1024 and extracted_file_size > 650 * 1024 * 1024:
                    virus_name = "HEUR:Win32.Suspicious.Size.Encrypted.7z"
                    logging.warning(
                        f"7z file {file_path} is smaller than 20MB but contains a large file: {filename} "
                        f"({extracted_file_size / (1024 * 1024)} MB) - flagged as {virus_name}. "
                        "Potential 7z bomb or Fake Size detected to avoid VirusTotal detections."
                    )
                    notify_size_warning(file_path, "7z", virus_name)

        return True, []
    except Exception as ex:
        logging.error(f"Error scanning 7z file: {file_path} - {ex}")
        return False, ""

def is_7z_file(file_path):
    """
    Check if the file is a valid 7z archive using Detect It Easy console.
    """
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be 7z check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for 7-Zip in the result
        if "Archive: 7-Zip" in result.stdout:
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"7z file analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a 7z file. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def scan_tar_file(file_path):
    """Scan files within a tar archive."""
    try:
        tar_size = os.path.getsize(file_path)

        with tarfile.open(file_path, 'r') as tar:
            for member in tar.getmembers():
                # Check for RLO in filenames
                if contains_rlo_after_dot(member.name):
                    virus_name = "HEUR:RLO.Suspicious.Name.Encrypted.TAR.Generic"
                    logging.warning(
                        f"Filename {member.name} in {file_path} contains RLO character after a dot - "
                        f"flagged as {virus_name}"
                    )
                    notify_rlo_warning(file_path, "TAR", virus_name)

                if member.isreg():  # Check if it's a regular file
                    extracted_file_path = os.path.join(tar_extracted_dir, member.name)

                    # Skip if the file has already been processed
                    if os.path.isfile(extracted_file_path):
                        logging.info(f"File {member.name} already processed, skipping...")
                        continue

                    # Extract the file
                    tar.extract(member, tar_extracted_dir)

                    # Check for suspicious conditions: large files in small TAR archives
                    extracted_file_size = os.path.getsize(extracted_file_path)
                    if tar_size < 20 * 1024 * 1024 and extracted_file_size > 650 * 1024 * 1024:
                        virus_name = "HEUR:Win32.Suspicious.Size.Encrypted.TAR"
                        logging.warning(
                            f"TAR file {file_path} is smaller than 20MB but contains a large file: {member.name} "
                            f"({extracted_file_size / (1024 * 1024):.2f} MB) - flagged as {virus_name}. "
                            "Potential TARbomb or Fake Size detected to avoid VirusTotal detections."
                        )
                        notify_size_warning(file_path, "TAR", virus_name)

        return True, []
    except Exception as ex:
        logging.error(f"Error scanning tar file: {file_path} - {ex}")
        return False, ""

def scan_file_real_time(file_path, signature_check, pe_file=False):
    """Scan file in real-time using multiple engines."""
    logging.info(f"Started scanning file: {file_path}")

    try:
        # Scan with Machine Learning AI for PE files
        try:
            if pe_file:
                is_malicious_machine_learning , malware_definition, benign_score = scan_file_with_machine_learning_ai(file_path)
                if is_malicious_machine_learning:
                    if benign_score < 0.93:
                        if signature_check["is_valid"]:
                            malware_definition = "SIG." + malware_definition
                        logging.warning(f"Infected file detected (ML): {file_path} - Virus: {malware_definition}")
                        return True, malware_definition, "ML"
                    elif benign_score >= 0.93:
                        logging.info(f"File is clean based on ML benign score: {file_path}")
                logging.info(f"No malware detected by Machine Learning in file: {file_path}")
        except Exception as ex:
            logging.error(f"An error occurred while scanning file with Machine Learning AI: {file_path}. Error: {ex}")

        # Scan with ClamAV
        try:
            result = scan_file_with_clamd(file_path)
            if result not in ("Clean", ""):
                if signature_check["is_valid"]:
                    result = "SIG." + result
                logging.warning(f"Infected file detected (ClamAV): {file_path} - Virus: {result}")
                return True, result, "ClamAV"
            logging.info(f"No malware detected by ClamAV in file: {file_path}")
        except Exception as ex:
            logging.error(f"An error occurred while scanning file with ClamAV: {file_path}. Error: {ex}")

        # Scan with YARA
        try:
            yara_result = scan_yara(file_path)
            if yara_result is not None and yara_result not in ("Clean", ""):
                if signature_check["is_valid"]:
                    yara_result = "SIG." + yara_result
                logging.warning(f"Infected file detected (YARA): {file_path} - Virus: {yara_result}")
                return True, yara_result, "YARA"
            logging.info(f"Scanned file with YARA: {file_path} - No viruses detected")
        except Exception as ex:
            logging.error(f"An error occurred while scanning file with YARA: {file_path}. Error: {ex}")

        # Scan TAR files
        try:
            if tarfile.is_tarfile(file_path):
                scan_result, virus_name = scan_tar_file(file_path)
                if scan_result and virus_name not in ("Clean", "F", ""):
                    if signature_check["is_valid"]:
                        virus_name = "SIG." + virus_name
                    logging.warning(f"Infected file detected (TAR): {file_path} - Virus: {virus_name}")
                    return True, virus_name, "TAR"
                logging.info(f"No malware detected in TAR file: {file_path}")
        except PermissionError:
            logging.error(f"Permission error occurred while scanning TAR file: {file_path}")
        except FileNotFoundError:
            logging.error(f"TAR file not found error occurred while scanning TAR file: {file_path}")
        except Exception as ex:
            logging.error(f"An error occurred while scanning TAR file: {file_path}. Error: {ex}")

        # Scan ZIP files
        try:
            if zipfile.is_zipfile(file_path):
                scan_result, virus_name = scan_zip_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    if signature_check["is_valid"]:
                        virus_name = "SIG." + virus_name
                    logging.warning(f"Infected file detected (ZIP): {file_path} - Virus: {virus_name}")
                    return True, virus_name, "ZIP"
                logging.info(f"No malware detected in ZIP file: {file_path}")
        except PermissionError:
            logging.error(f"Permission error occurred while scanning ZIP file: {file_path}")
        except FileNotFoundError:
            logging.error(f"ZIP file not found error occurred while scanning ZIP file: {file_path}")
        except Exception as ex:
            logging.error(f"An error occurred while scanning ZIP file: {file_path}. Error: {ex}")

        # Scan 7z files
        try:
            if is_7z_file(file_path):
                scan_result, virus_name = scan_7z_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    if signature_check["is_valid"]:
                        virus_name = "SIG." + virus_name
                    logging.warning(f"Infected file detected (7z): {file_path} - Virus: {virus_name}")
                    return True, virus_name, "7z"
                logging.info(f"No malware detected in 7z file: {file_path}")
            else:
                logging.info(f"File is not a valid 7z archive: {file_path}")
        except PermissionError:
            logging.error(f"Permission error occurred while scanning 7Z file: {file_path}")
        except FileNotFoundError:
            logging.error(f"7Z file not found error occurred while scanning 7Z file: {file_path}")
        except Exception as ex:
            logging.error(f"An error occurred while scanning 7Z file: {file_path}. Error: {ex}")

    except Exception as ex:
        logging.error(f"An error occurred while scanning file: {file_path}. Error: {ex}")

    return False, "Clean", ""  # Default to clean if no malware found

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
        self.setWindowIcon(QIcon(os.path.join(assets_dir,"HydraDragonAV.png")))
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
        self.analysis_thread.execute_analysis()

    def show_success_message(self):
        QMessageBox.information(self, "Update Definitions", "AntiVirus definitions updated successfully and ClamAV has been restarted.")

    def show_failure_message(self):
        QMessageBox.critical(self, "Update Definitions", "Failed to update antivirus definitions.")

    def update_definitions(self):
        try:
            # Iterate over the list of ClamAV database files and check each
            for file_path in clamav_file_paths:
                if os.path.exists(file_path):
                    # File found, check its modification time
                    file_mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    file_age = datetime.now() - file_mod_time

                    if file_age > timedelta(hours=6):
                        # All files in directory must be older than 6 hours
                        all_files_old = True
                        for root, dirs, files in os.walk(clamav_database_directory_path):
                            for file_name in files:
                                other_file_path = os.path.join(root, file_name)
                                other_file_mod_time = datetime.fromtimestamp(os.path.getmtime(other_file_path))
                                other_file_age = datetime.now() - other_file_mod_time
                                if other_file_age <= timedelta(hours=6):
                                    all_files_old = False
                                    break
                            if not all_files_old:
                                break

                        if all_files_old:
                            # Run freshclam to update definitions
                            result = subprocess.run([freshclam_path], capture_output=True, text=True)
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
                    return  # File checked, exit function

            # If neither daily.cvd nor daily.cld exists, run freshclam
            print("Neither daily.cvd nor daily.cld files exist. Running freshclam.")
            result = subprocess.run([freshclam_path], capture_output=True, text=True)
            if result.returncode == 0:
                restart_clamd_thread()
                self.signals.success.emit()
            else:
                self.signals.failure.emit()
                print(f"freshclam failed with output: {result.stdout}\n{result.stderr}")

        except Exception as ex:
            logging.error(f"Error in update_definitions: {ex}")
            self.signals.failure.emit()

    def start_update_definitions_thread(self):
        threading.Thread(target=self.update_definitions).start()

# Regex for Snort alerts
alert_regex = re.compile(r'\[Priority: (\d+)].*?\{(?:UDP|TCP)} (\d+\.\d+\.\d+\.\d+):\d+ -> (\d+\.\d+\.\d+\.\d+):\d+')

# File paths and configurations
log_path = "C:\\Snort\\log\\alert.ids"
log_folder = "C:\\Snort\\log"
snort_config_path = "C:\\Snort\\etc\\snort.conf"
sandboxie_path = "C:\\Program Files\\Sandboxie\\Start.exe"
sandboxie_control_path = "C:\\Program Files\\Sandboxie\\SbieCtrl.exe"
sbie_ini_path = "C:\\Program Files\\Sandboxie\\SbieIni.exe"
device_args = [f"-i {i}" for i in range(1, 26)]  # Fixed device arguments
username = os.getlogin()
sandboxie_folder = rf'C:\Sandbox\{username}\DefaultBox'
hosts_path = rf'{sandboxie_folder}\drive\C\Windows\System32\drivers\etc\hosts'
drivers_path = rf'{sandboxie_folder}\drive\C\Windows\System32\drivers'
main_drive_path = rf'{sandboxie_folder}\drive\C'

# Define the list of known rootkit filenames
known_rootkit_files = [
    'MoriyaStreamWatchmen.sys',
    # Add more rootkit filenames here if needed
]

uefi_100kb_paths = [
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\SecureBootRecovery.efi'
]

uefi_paths = [
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\bootmgfw.efi',
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\bootmgr.efi',
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\memtest.efi',
    rf'{sandboxie_folder}\drive\X\EFI\Boot\bootx64.efi'
]
snort_command = ["C:\\Snort\\bin\\snort.exe"] + device_args + ["-c", snort_config_path, "-A", "fast"]

# Custom flags for directory changes
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800

fake_system_files = [
    'svchost.exe',
    'rundll32.exe',
    'powershell.exe',
    'regsvr32.exe',
    'spoolsv.exe',
    'lsass.exe',
    'smss.exe',
    'csrss.exe',
    'conhost.exe',
    'wininit.exe',
    'winlogon.exe',
    'taskhost.exe',
    'taskmgr.exe',
    'runtimebroker.exe',
    'smartscreen.exe',
    'dllhost.exe',
    'services.exe'
]

def convert_ip_to_file(src_ip, dst_ip, alert_line, status):
    """
    Convert IP addresses to associated file paths.
    This function will log the status and simulate the detection of files.
    """
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            connections = proc.net_connections()
            if connections:
                for conn in connections:
                    if conn.raddr and (conn.raddr.ip == src_ip or conn.raddr.ip == dst_ip):
                        file_path = proc.info['exe']
                        if file_path:
                            logging.info(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip}")

                            # Only proceed with files in the Sandboxie folder or the main file path
                            if sandboxie_folder.lower() not in file_path.lower() and file_path.lower() != main_file_path.lower():
                                logging.info(f"File {file_path} is not located in the monitored directories. Skipping...")
                                continue

                            signature_info = check_valid_signature_only(file_path)
                            if status == "Info":
                                if not signature_info["is_valid"]:
                                    logging.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has an invalid or no signature. Alert Line: {alert_line}")
                                    print(f"[INFO] File {file_path} associated with IP {src_ip} or {dst_ip} has an invalid or no signature. Alert Line: {alert_line}")
                                else:
                                    logging.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature. Alert Line: {alert_line}")
                                    print(f"[INFO] File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature. Alert Line: {alert_line}")
                            else:
                                if not signature_info["is_valid"]:
                                    logging.warning(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip} has invalid or no signature. Alert Line: {alert_line}")
                                    print(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip} has invalid or no signature. Alert Line: {alert_line}")
                                    notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status)
                                else:
                                    logging.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature and is not flagged as malicious. Alert Line: {alert_line}")
                                    print(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature and is not flagged as malicious. Alert Line: {alert_line}")

        except psutil.ZombieProcess:
            logging.error(f"Zombie process encountered: {proc.info.get('pid')}")
        except psutil.NoSuchProcess:
            logging.error(f"Process no longer exists: {proc.info.get('pid')}")
        except psutil.AccessDenied:
            logging.error(f"Access denied to process: {proc.info.get('pid')}")
        except Exception as ex:
            logging.error(f"Unexpected error while processing process {proc.info.get('pid')}: {ex}")

def process_alert(line):
    try:
        match = alert_regex.search(line)
        if match:
            try:
                priority = int(match.group(1))
                src_ip = match.group(2)
                dst_ip = match.group(3)
                # Check if the source IP is in the IPv4 whitelist
                if src_ip in ipv4_whitelist_data:
                    logging.info(f"Source IP {src_ip} is in the whitelist. Ignoring alert.")
                    print(f"Source IP {src_ip} is in the whitelist. Ignoring alert.")
                    return False

                if priority == 1:
                    logging.warning(f"Malicious activity detected: {line.strip()}")
                    print(f"Malicious activity detected from {src_ip} to {dst_ip} with priority {priority}")
                    try:
                        notify_user_for_hips(ip_address=src_ip, dst_ip_address=dst_ip)
                    except Exception as ex:
                        logging.error(f"Error notifying user for HIPS (malicious): {ex}")
                    convert_ip_to_file(src_ip, dst_ip, line.strip(), "Malicious")
                    return True
                elif priority == 2:
                    convert_ip_to_file(src_ip, dst_ip, line.strip(), "Suspicious")
                    return True
                elif priority == 3:
                    convert_ip_to_file(src_ip, dst_ip, line.strip(), "Info")
                    return True
            except Exception as ex:
                logging.error(f"Error processing alert details: {ex}")
                print(f"Error processing alert details: {ex}")
    except Exception as ex:
        logging.error(f"Error matching alert regex: {ex}")
        print(f"Error matching alert regex: {ex}")

def clean_directory():
    for filename in os.listdir(log_folder):
        file_path = os.path.join(log_folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as ex:
            logging.error(f'Failed to delete {file_path}. Reason: {ex}')

def run_snort():    
    try:
        clean_directory()
        # Run snort without capturing output
        subprocess.run(snort_command, check=True)
        
        logging.info("Snort completed analysis.")
        print("Snort completed analysis.")

    except subprocess.CalledProcessError as ex:
        logging.error(f"Snort encountered an error: {ex}")
        print(f"Snort encountered an error: {ex}")

    except Exception as ex:
        logging.error(f"Failed to run Snort: {ex}")
        print(f"Failed to run Snort: {ex}")

def activate_uefi_drive():
    # Check if the platform is Windows
    mount_command = 'mountvol X: /S'  # Command to mount UEFI drive
    try:
        # Execute the mountvol command
        subprocess.run(mount_command, shell=True, check=True)
        print("UEFI drive activated!")
    except subprocess.CalledProcessError as ex:
        print(f"Error mounting UEFI drive: {ex}")

threading.Thread(target=run_snort).start()
restart_clamd_thread()
clean_directories()
activate_uefi_drive() # Call the UEFI function
load_website_data()
load_antivirus_list()
# Load Antivirus and Microsoft digital signatures
antivirus_signatures = load_signatures(digital_signautres_list_antivirus_path, "Antivirus digital signatures")
microsoft_signatures = load_signatures(digital_signautres_list_microsoft_path, "Microsoft digital signatures")

try:
    # Load malicious file names from JSON file
    with open(malicious_file_names, 'r') as malicious_file:
        malicious_file_names = json.load(malicious_file)
        print("Machine Learning Malicious Definitions loaded!")
except Exception as ex:
    print(f"Error loading malicious file names: {ex}")

try:
    # Load malicious file names from JSON file
    with open(benign_file_names, 'r') as benign_file:
        benign_file_names = json.load(benign_file)
        print("Machine Learning Benign Definitions loaded!")
except Exception as ex:
    print(f"Error loading benign file names: {ex}")

try:
    # Load malicious numeric features from pickle file
    with open(malicious_numeric_features, 'rb') as malicious_numeric_file:
        malicious_numeric_features = joblib.load(malicious_numeric_file)
        print("Malicious Feature Signatures loaded!")
except Exception as ex:
    print(f"Error loading malicious numeric features: {ex}")

try:
    # Load benign numeric features from pickle file
    with open(benign_numeric_features, 'rb') as benign_numeric_file:
        benign_numeric_features = joblib.load(benign_numeric_file)
        print("Benign Feature Signatures loaded!")
except Exception as ex:
    print(f"Error loading benign numeric features: {ex}")

print("Machine Learning AI Signatures loaded!")

try:
    # Load excluded rules from text file
    with open(excluded_rules_path, "r") as excluded_file:
        excluded_rules = excluded_file.read()
        print("YARA Excluded Rules Definitions loaded!")
except Exception as ex:
    print(f"Error loading excluded rules: {ex}")

try:
    # Load the precompiled yarGen rules from the .yrc file
    yarGen_rule = yara.load(yarGen_rule_path)
    print("yarGen Rules Definitions loaded!")
except yara.Error as ex:
    print(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled icewater rules from the .yrc file
    icewater_rule = yara.load(icewater_rule_path)
    print("Icewater Rules Definitions loaded!")
except yara.Error as ex:
    print(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled valhalla rules from the .yrc file
    valhalla_rule = yara.load(valhalla_rule_path)
    print("Vallhalla Demo Rules Definitions loaded!")
except yara.Error as ex:
    print(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled rules from the .yrc file
    compiled_rule = yara.load(compiled_rule_path)
    print("YARA Rules Definitions loaded!")
except yara.Error as ex:
    print(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled rule from the .yrc file using yara_x
    with open(yaraxtr_yrc_path, 'rb') as yara_x_f:
        yaraxtr_rule = yara_x.Rules.deserialize_from(yara_x_f)
    print("YARA-X Rules Definitions loaded!")
except Exception as ex:
    print(f"Error loading YARA-X rules: {ex}")

# Function to load DeepSeek-Coder-1.3b model and tokenizer
def load_deepseek_1b_model(deepseek_dir):
    try:
        deepseek_1b_dir = os.path.join(deepseek_dir, "DeepSeek-Coder-1.3B")
        
        message = "Attempting to load DeepSeek-Coder-1.3B model and tokenizer..."
        print(message)
        logging.info(message)
        
        deepseek_tokenizer = AutoTokenizer.from_pretrained(deepseek_1b_dir, local_files_only=True)
        deepseek_model = AutoModelForCausalLM.from_pretrained(deepseek_1b_dir, local_files_only=True)
        
        success_message = "DeepSeek-Coder-1.3B successfully loaded!"
        print(success_message)
        logging.info(success_message)
        
        return deepseek_model, deepseek_tokenizer
    except Exception as ex:
        error_message = f"Error loading DeepSeek-Coder-1.3B model or tokenizer: {ex}"
        print(error_message)
        logging.error(error_message)
        sys.exit(1)

# Load the DeepSeek-Coder-1.3B model
deepseek_1b_model, deepseek_1b_tokenizer = load_deepseek_1b_model(deepseek_dir)

# List to keep track of existing project names
existing_projects = []

# List of already scanned files and their modification times
scanned_files = []
file_mod_times = {}
directories_to_scan = [sandboxie_folder, decompile_dir, nuitka_dir, dotnet_dir, pyinstaller_dir, commandlineandmessage_dir, pe_extracted_dir,zip_extracted_dir, tar_extracted_dir, seven_zip_extracted_dir, general_extracted_dir, processed_dir, python_source_code_dir, pycdc_dir, pycdas_dir, pycdas_deepseek_dir, nuitka_source_code_dir, memory_dir, debloat_dir]

def get_next_project_name(base_name):
    """Generate the next available project name with an incremental suffix."""
    try:
        suffix = 1
        while f"{base_name}_{suffix}" in existing_projects:
            suffix += 1
        return f"{base_name}_{suffix}"
    except Exception as ex:
        logging.error(f"An error occurred while generating project name: {ex}")

def decompile_file(file_path):
    """Decompile the file using Ghidra."""
    try:
        logging.info(f"Decompiling file: {file_path}")

        # Path to Ghidra's analyzeHeadless.bat
        analyze_headless_path = os.path.join(script_dir, 'ghidra', 'support', 'analyzeHeadless.bat')
        project_location = os.path.join(script_dir, 'ghidra_projects')

        # Ensure the project location exists
        if not os.path.exists(project_location):
            os.makedirs(project_location)

        # Generate a unique project name
        base_project_name = 'temporary'
        try:
            project_name = get_next_project_name(base_project_name)
        except Exception as ex:
            logging.error(f"Failed to generate project name: {ex}")
            return  # Exit the function if project name generation fails

        existing_projects.append(project_name)

        # Build the command to run analyzeHeadless.bat
        command = [
            analyze_headless_path,
            project_location,
            project_name,
            '-import', file_path,
            '-postScript', 'DecompileAndSave.java',
            '-scriptPath', ghidra_scripts_dir,
            '-log', os.path.join(ghidra_logs_dir, 'analyze.log')
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)

        # Check and log the results
        if result.returncode == 0:
            logging.info(f"Decompilation completed successfully for file: {file_path}")
        else:
            logging.error(f"Decompilation failed for file: {file_path}.")
            logging.error(f"Return code: {result.returncode}")
            logging.error(f"Error output: {result.stderr}")
            logging.error(f"Standard output: {result.stdout}")
    except Exception as ex:
        logging.error(f"An error occurred during decompilation: {ex}")

def extract_original_file_path_from_decompiled(file_path):
    try:
        with open(file_path, 'r') as original_file:
            for line in original_file:
                if line.startswith("// Original file:"):
                    parts = line.split(':', 2)
                    # Construct the path without using an rf-string
                    drive_letter = parts[1].upper() + ":"
                    path = parts[2].replace('/', '\\')
                    original_file_path = f"{drive_letter}\\{path}".strip()

                    # Log the extracted original file path
                    logging.info(f"Original file path extracted: {original_file_path}")

                    return original_file_path
        return None
    except Exception as ex:
        logging.error(f"An error occurred while extracting the original file path: {ex}")
        return None

def is_nuitka_file(file_path):
    """Check if the file is a Nuitka executable using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be Nuitka check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for Nuitka executable and OneFile
        if "Packer: Nuitka[OneFile]" in result.stdout:
            logging.info(f"File {file_path} is a Nuitka OneFile executable.")
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"Nuitka OneFile analysis result saved to {json_output_path}")
            return "Nuitka OneFile"
        elif "Packer: Nuitka" in result.stdout:
            logging.info(f"File {file_path} is a Nuitka executable.")
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"Nuitka analysis result saved to {json_output_path}")
            return "Nuitka"
        else:
            logging.info(f"File {file_path} is not a Nuitka executable. Result: {result.stdout}")
            return None

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return None
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return None

def clean_text(input_text):
    """
    Remove non-printable ASCII control characters from the input text.

    :param input_text: The string to clean.
    :return: Cleaned text with control characters removed.
    """
    # Remove non-printable characters (ASCII 0-31 and 127)
    cleaned_text = re.sub(r'[\x00-\x1F\x7F]+', '', input_text)
    return cleaned_text

def scan_rsrc_directory(extracted_files):
    """
    Scans all files in the extracted_files list for .rsrc\\RCDATA, extracts
    the last 11 lines, the full source code, cleans them, and performs scans for domains, URLs, IP addresses,
    and Discord webhooks.
    
    :param extracted_files: List of files extracted by 7z.
    """
    try:
        for extracted_file in extracted_files:
            # Check if the file path contains .rsrc\RCDATA
            if ".rsrc\\RCDATA" in extracted_file or ".rsrc/RCDATA" in extracted_file:
                logging.info(f"Processing RCDATA file: {extracted_file}")

                # Ensure the path refers to an actual file
                if os.path.isfile(extracted_file):
                    try:
                        # Read the full content of the file, handling invalid UTF-8 gracefully
                        with open(extracted_file, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                            if lines:
                                # Clean the last lines
                                lines_cleaned = [clean_text(line.strip()) for line in lines]

                                # Log the success of processing last 11 lines
                                logging.info(f"Extracted and cleaned last 11 lines from {extracted_file}.")

                                # Save the last 11 lines to a uniquely named file
                                base_name = os.path.splitext(os.path.basename(extracted_file))[0]
                                last_lines_path = os.path.join(nuitka_source_code_dir, f"{base_name}_last_lines.txt")
                                counter = 1
                                while os.path.exists(last_lines_path):
                                    last_lines_path = os.path.join(
                                        nuitka_source_code_dir, f"{base_name}_last_lines_{counter}.txt"
                                    )
                                    counter += 1

                                # Write each cleaned line to the file
                                with open(last_lines_path, "w", encoding="utf-8") as save_file:
                                    for line in lines_cleaned:
                                        save_file.write(line + '\n')
                                logging.info(f"Saved last 11 lines from {extracted_file} to {last_lines_path}")

                                # Save the full source code to a separate file
                                full_code_path = os.path.join(nuitka_source_code_dir, f"{base_name}_full_code.txt")
                                counter = 1
                                while os.path.exists(full_code_path):
                                    full_code_path = os.path.join(
                                        nuitka_source_code_dir, f"{base_name}_full_code_{counter}.txt"
                                    )
                                    counter += 1

                                # Write the full content to the file
                                with open(full_code_path, "w", encoding="utf-8") as full_code_file:
                                    full_code_file.writelines(lines)
                                logging.info(f"Saved full source code from {extracted_file} to {full_code_path}")

                                # Scan the entire file content
                                rsrc_content = ''.join(lines)  # Use the entire content of the file

                                # Perform the scans
                                scan_code_for_links(rsrc_content, nuitka_flag=True)

                            else:
                                logging.info(f"File {extracted_file} is empty.")
                    except Exception as ex:
                        logging.error(f"Error reading file {extracted_file}: {ex}")
                else:
                    logging.warning(f"Path {extracted_file} is not a valid file.")
            else:
                logging.debug(f"Skipping non-RCDATA file: {extracted_file}")

    except Exception as ex:
        logging.error(f"Error during RCDATA file scanning: {ex}")

def scan_directory_for_executables(directory):
    """
    Recursively scan a directory for .exe, .dll, and other files, prioritizing Nuitka executables.
    If an .exe file is found and confirmed as Nuitka, stop further scanning.
    """
    found_executables = []

    # Look for .exe files first
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.exe'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .exe is found

    # If no .exe found, look for .dll files
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.dll'):
                file_path = os.path.join(root, file)
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .dll is found

    # If no .exe or .dll found, check other files
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not file.lower().endswith(('.exe', '.dll')):  # Skip .exe and .dll files
                nuitka_type = is_nuitka_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as Nuitka file is found

    return found_executables

def is_dotnet_file(file_path):
    """Check if the file is a .NET executable using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be .NET check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for .NET executable (Microsoft .NET or CLR)
        if "Microsoft .NET" in result.stdout or "CLR" in result.stdout:
            logging.info(f"File {file_path} is a .NET executable.")
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f".NET analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a .NET executable. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

class CTOCEntry:
    def __init__(self, position, cmprsddatasize, uncmprsddatasize, cmprsflag, typecmprsdata, name):
        self.position = position
        self.cmprsddatasize = cmprsddatasize
        self.uncmprsddatasize = uncmprsddatasize
        self.cmprsflag = cmprsflag
        self.typecmprsdata = typecmprsdata
        self.name = name

class PyInstArchive:
    MAGIC = b'MEI\014\013\012\013\016'
    PYINST20_COOKIE_SIZE = 24
    PYINST21_COOKIE_SIZE = 24 + 64

    def __init__(self, path):
        self.py_filepath = path
        self.pycMagic = b'\0' * 4
        self.barePycList = []  # List of pyc files whose headers need to be fixed

    def open_file(self):
        try:
            self.fPtr = open(self.py_filepath, 'rb')
            self.fileSize = os.stat(self.py_filepath).st_size
            return True
        except IOError as ex:
            logging.error(f"Error opening file: {ex}")
            return False

    def close(self):
        try:
            self.fPtr.close()
        except AttributeError:
            pass

    def checkfile(self):
        endpos = self.fileSize
        searchchunksize = 8192

        try:
            while True:
                startpos = max(0, endpos - searchchunksize)
                self.fPtr.seek(startpos, os.SEEK_SET)
                data_content = self.fPtr.read(endpos - startpos)
                offs = data_content.rfind(self.MAGIC)
                if offs != -1:
                    self.cookiePos = startpos + offs
                    break
                endpos = startpos + len(self.MAGIC) - 1
                if startpos == 0:
                    return False
        except Exception as ex:
            logging.error(f"Error during checkfile: {ex}")
            return False

        try:
            self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
            self.pyinstVer = 21 if b'python' in self.fPtr.read(64).lower() else 20
            return True
        except Exception as ex:
            logging.error(f"Error reading Python version: {ex}")
            return False

    def getcarchiveinfo(self):
        self.fPtr.seek(self.cookiePos, os.SEEK_SET)
        try:
            if self.pyinstVer == 20:
                _, lengthofpackage, toc, toclen, pyver = struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))
            else:
                _, lengthofpackage, toc, toclen, pyver, _ = struct.unpack('!8sIIii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))
        except struct.error as ex:
            logging.error(f"Error unpacking data: {ex}")
            return False

        self.pymaj, self.pymin = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        self.overlaySize = lengthofpackage + (self.fileSize - self.cookiePos - (self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE))
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = toclen
        return True

    def parsetoc(self):
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)
        self.tocList = []
        parsedlen = 0

        try:
            while parsedlen < self.tableOfContentsSize:
                entrysize = struct.unpack('!i', self.fPtr.read(4))[0]

                if entrysize <= 0 or entrysize > self.fileSize - self.tableOfContentsPos:
                    return False

                namelen = struct.calcsize('!iIIIBc')

                try:
                    entry = struct.unpack(f'!IIIBc{entrysize - namelen}s', self.fPtr.read(entrysize - 4))
                except struct.error as ex:
                    logging.error(f"Error unpacking TOC entry: {ex}")
                    return False

                name = entry[5].decode("utf-8", errors="ignore").rstrip('\0')
                self.tocList.append(CTOCEntry(
                    self.overlayPos + entry[0],
                    entry[1],
                    entry[2],
                    entry[3],
                    entry[4],
                    name
                ))

                parsedlen += entrysize
        except Exception as ex:
            logging.error(f"Error during TOC parsing: {ex}")
            return False

        return True

    def extractfiles(self):
        folder_number = 1
        base_extraction_dir = os.path.join(script_dir, os.path.basename(self.py_filepath) + '_extracted')

        while os.path.exists(f"{base_extraction_dir}_{folder_number}"):
            folder_number += 1

        extractiondir = f"{base_extraction_dir}_{folder_number}"
        os.makedirs(extractiondir, exist_ok=True)
        os.chdir(extractiondir)

        try:
            for entry in self.tocList:
                self.fPtr.seek(entry.position, os.SEEK_SET)
                data_content = self.fPtr.read(entry.cmprsddatasize)
                if entry.cmprsflag == 1:
                    try:
                        data_content = zlib.decompress(data_content)
                    except zlib.error:
                        return False

                with open(entry.name, 'wb') as entry_f:
                    entry_f.write(data_content)

                if entry.name.endswith('.pyz'):
                    self._extractpyz(entry.name)

                # Check for entry points (python scripts or pyc files)
                if entry.typecmprsdata == b's':
                    print(f"[+] Possible entry point: {entry.name}")

                if self.pycMagic == b'\0' * 4:
                    self.barePycList.append(entry.name + '.pyc')
        except Exception as ex:
            logging.error(f"Error during file extraction: {ex}")
            return False

        # Fix bare pyc files if necessary
        self._fixbarepycs()

        return True

    def _extractpyz(self, name):
        dirname = name + '_extracted'
        os.makedirs(dirname, exist_ok=True)

        try:
            with open(name, 'rb') as pyz_f:
                pyzmagic = pyz_f.read(4)
                assert pyzmagic == b'PYZ\0'

                pyzpycmagic = pyz_f.read(4)

                if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                    return False

                tocposition = struct.unpack('!i', pyz_f.read(4))[0]
                pyz_f.seek(tocposition, os.SEEK_SET)

                try:
                    toc = marshal.load(pyz_f)
                except (EOFError, ValueError, TypeError) as ex:
                    logging.error(f"Error loading PYZ TOC: {ex}")
                    return False

                if isinstance(toc, list):
                    toc = dict(toc)

                for key, (ispkg, pos, length) in toc.items():
                    pyz_f.seek(pos, os.SEEK_SET)
                    py_filename = key.decode("utf-8", errors="ignore")
                    py_filename = py_filename.replace('..', '__').replace('.', os.path.sep)

                    if ispkg:
                        py_filepath = os.path.join(dirname, py_filename, '__init__.pyc')
                    else:
                        py_filepath = os.path.join(dirname, py_filename + '.pyc')

                    os.makedirs(os.path.dirname(py_filepath), exist_ok=True)

                    data_content = pyz_f.read(length)
                    try:
                        data_content = zlib.decompress(data_content)
                    except zlib.error:
                        with open(py_filepath + '.encrypted', 'wb') as e_f:
                            e_f.write(data_content)
                        continue

                    with open(py_filepath, 'wb') as pyc_f:
                        pyc_f.write(pyzpycmagic)
                        pyc_f.write(b'\0' * 4)
                        if self.pymaj >= 3 and self.pymin >= 7:
                            pyc_f.write(b'\0' * 8)
                        pyc_f.write(data_content)
        except Exception as ex:
            logging.error(f"Error during PYZ extraction: {ex}")
            return False

        return True

    def _fixbarepycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, 'r+b') as pycFile:
                pycFile.write(self.pycMagic)  # Overwrite the first four bytes with pyc magic

def is_pyinstaller_archive(file_path):
    """Check if the file is a PyInstaller archive using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be PyInstaller check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for PyInstaller archive and Python language
        if "Packer: PyInstaller" in result.stdout and "Language: Python" in result.stdout:
            logging.info(f"File {file_path} is a PyInstaller archive.")
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"PyInstaller analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a PyInstaller archive. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def extract_pyinstaller_archive(file_path):
    try:
        # Ensure the extraction directory exists
        os.makedirs(pyinstaller_dir, exist_ok=True)

        archive = PyInstArchive(file_path)
        
        # Open the PyInstaller archive
        if not archive.open_file():
            logging.error(f"Failed to open PyInstaller archive: {file_path}")
            return None

        # Check if the file is a valid PyInstaller archive
        if not archive.checkfile():
            logging.error(f"File {file_path} is not a valid PyInstaller archive.")
            return None

        # Retrieve CArchive info from the archive
        if not archive.getcarchiveinfo():
            logging.error(f"Failed to get CArchive info from {file_path}.")
            return None

        # Parse the Table of Contents (TOC) from the archive
        if not archive.parsetoc():
            logging.error(f"Failed to parse TOC from {file_path}.")
            return None

        # Extract files to the specified pyinstaller_dir
        extraction_success = archive.extractfiles()
        
        # Close the archive
        archive.close()

        return pyinstaller_dir if extraction_success else None

    except Exception as ex:
        logging.error(f"An error occurred while extracting PyInstaller archive {file_path}: {ex}")
        return None

def has_known_extension(file_path):
    try:
        ext = os.path.splitext(file_path)[1].lower()
        logging.info(f"Extracted extension '{ext}' for file '{file_path}'")
        return ext in fileTypes
    except Exception as ex:
        logging.error(f"Error checking extension for file {file_path}: {ex}")
        return False

def is_readable(file_path):
    try:
        logging.info(f"Attempting to read file '{file_path}'")
        with open(file_path, 'r') as readable_file:
            file_data = readable_file.read(1024)
            if file_data:  # Check if file has readable content
                logging.info(f"File '{file_path}' is readable")
                return True
            return False
    except UnicodeDecodeError:
        logging.error(f"UnicodeDecodeError while reading file '{file_path}'")
        return False
    except Exception as ex:
        logging.error(f"Error reading file {file_path}: {ex}")
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
                
                # Add Detect It Easy check at this stage
                try:
                    die_result = subprocess.run([detectiteasy_console_path, file_path], 
                                                stdout=subprocess.PIPE, 
                                                stderr=subprocess.PIPE, 
                                                text=True)
                    
                    # Check Detect It Easy output
                    if "Binary" in die_result.stdout and "Unknown: Unknown" in die_result.stdout:
                        logging.warning(f"Detect It Easy confirmed suspicious file: {file_path}")
                        return True
                    else:
                        logging.info(f"Detect It Easy did not confirm suspicious status for {file_path}")
                        return False
                
                except Exception as die_ex:
                    logging.error(f"Error running Detect It Easy for {file_path}: {die_ex}")
                    return True

        logging.info(f"File '{file_path}' does not meet ransomware conditions")
        return False
    
    except Exception as ex:
        logging.error(f"Error checking ransomware for file {file_path}: {ex}")
        return False

def search_files_with_same_extension(directory, extension):
    try:
        logging.info(f"Searching for files with extension '{extension}' in directory '{directory}'")
        files_with_same_extension = []
        for root, _, files in os.walk(directory):
            for search_file in files:
                if search_file.endswith(extension):
                    files_with_same_extension.append(os.path.join(root, search_file))
        logging.info(f"Found {len(files_with_same_extension)} files with extension '{extension}'")
        return files_with_same_extension
    except Exception as ex:
        logging.error(f"Error searching for files with extension '{extension}' in directory '{directory}': {ex}")
        return []

def ransomware_alert(file_path):
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
                    for ransom_file in files_with_same_extension:
                        logging.info(f"Checking file '{ransom_file}' with same extension '{ext}'")
                        if is_ransomware(ransom_file):
                            logging.warning(f"File '{ransom_file}' might also be related to ransomware")

            # Notify user if the detection count reaches the threshold
            if ransomware_detection_count >= 10:
                notify_user_ransomware(main_file_path, "HEUR:Win32.Ransom.Generic")
                has_warned_ransomware = True
                logging.warning(f"User has been notified about potential ransomware in {main_file_path}")
                print(f"User has been notified about potential ransomware in {main_file_path}")
    except Exception as ex:
        logging.error(f"Error in ransomware_alert: {ex}")

# Global variables for worm detection
worm_alerted_files = []
worm_detected_count = {}
worm_file_paths = []

def calculate_similarity_worm(features1, features2):
    """
    Calculate similarity between two dictionaries of features for worm detection.
    Adjusted threshold for worm detection.
    """
    try:
        common_keys = set(features1.keys()) & set(features2.keys())
        matching_keys = sum(1 for key in common_keys if features1[key] == features2[key])
        similarity = matching_keys / max(len(features1), len(features2)) if max(len(features1), len(features2)) > 0 else 0
        return similarity
    except Exception as ex:
        logging.error(f"Error calculating similarity: {ex}")
        return 0  # Return a default value in case of an error

def extract_numeric_worm_features(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract numeric features of a file using pefile for worm detection.
    """
    res = {}
    try:
        # Reuse the numeric features extraction function for base data
        res.update(extract_numeric_features(file_path) or {})

    except Exception as ex:
        logging.error(f"An error occurred while processing {file_path}: {ex}", exc_info=True)

    return res

def check_worm_similarity(file_path, features_current):
    """
    Check similarity between the main file, collected files, and the current file for worm detection.
    """
    worm_detected = False

    try:
        # Compare with the main file if available and distinct from the current file
        if main_file_path and main_file_path != file_path:
            features_main = extract_numeric_worm_features(main_file_path)
            similarity_main = calculate_similarity_worm(features_current, features_main)
            if similarity_main > 0.86:
                logging.warning(
                    f"Main file '{main_file_path}' is potentially spreading the worm to '{file_path}' "
                    f"with similarity score: {similarity_main:.2f}"
                )
                worm_detected = True

        # Compare with each collected file in the file paths
        for collected_file_path in worm_file_paths:
            if collected_file_path != file_path:
                features_collected = extract_numeric_worm_features(collected_file_path)
                similarity_collected = calculate_similarity_worm(features_current, features_collected)
                if similarity_collected > 0.86:
                    logging.warning(
                        f"Worm has potentially spread to '{collected_file_path}' "
                        f"from '{file_path}' with similarity score: {similarity_collected:.2f}"
                    )
                    worm_detected = True

    except FileNotFoundError as fnf_error:
        logging.error(f"File not found: {fnf_error}")
    except Exception as ex:
        logging.error(f"An unexpected error occurred while checking worm similarity for '{file_path}': {ex}")

    return worm_detected

def worm_alert(file_path):
    global worm_alerted_files
    global worm_detected_count
    global worm_file_paths

    if file_path in worm_alerted_files:
        logging.info(f"Worm alert already triggered for {file_path}, skipping...")
        return

    try:
        logging.info(f"Running worm detection for file '{file_path}'")

        # Define directory paths
        critical_directory = os.path.join('C:', 'Windows')
        sandbox_critical_directory = os.path.join(sandboxie_folder, 'drive', 'C', 'Windows')

        # Extract features
        features_current = extract_numeric_worm_features(file_path)
        is_critical = file_path.startswith(main_drive_path) or file_path.startswith(critical_directory) or file_path.startswith(sandbox_critical_directory)

        if is_critical:
            original_file_path = os.path.join(critical_directory, os.path.basename(file_path))
            sandbox_file_path = os.path.join(sandbox_critical_directory, os.path.basename(file_path))

            if os.path.exists(original_file_path) and os.path.exists(sandbox_file_path):
                original_file_size = os.path.getsize(original_file_path)
                current_file_size = os.path.getsize(sandbox_file_path)
                size_difference = abs(current_file_size - original_file_size) / original_file_size

                original_file_mtime = os.path.getmtime(original_file_path)
                current_file_mtime = os.path.getmtime(sandbox_file_path)
                mtime_difference = abs(current_file_mtime - original_file_mtime)

                if size_difference > 0.10:
                    logging.warning(f"File size difference for '{file_path}' exceeds 10%.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Critical.Agnostic.Generic.Malware")
                    worm_alerted_files.append(file_path)
                    return  # Only flag once if a critical difference is found

                if mtime_difference > 3600:  # 3600 seconds = 1 hour
                    logging.warning(f"Modification time difference for '{file_path}' exceeds 1 hour.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Critical.Time.Agnostic.Generic.Malware")
                    worm_alerted_files.append(file_path)
                    return  # Only flag once if a critical difference is found

            # Proceed with worm detection based on critical file comparison
            worm_detected = check_worm_similarity(file_path, features_current)

            if worm_detected:
                logging.warning(f"Worm '{file_path}' detected in critical directory. Alerting user.")
                notify_user_worm(file_path, "HEUR:Win32.Worm.Classic.Critical.Generic.Malware")
                worm_alerted_files.append(file_path)
        
        else:
            # Check for generic worm detection
            worm_detected = check_worm_similarity(file_path, features_current)
            worm_detected_count[file_path] = worm_detected_count.get(file_path, 0) + 1

            if worm_detected or worm_detected_count[file_path] >= 5:
                if file_path not in worm_alerted_files:
                    logging.warning(f"Worm '{file_path}' detected under 5 different names or as potential worm. Alerting user.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Classic.Generic.Malware")
                    worm_alerted_files.append(file_path)

                # Notify for all files that have reached the detection threshold
                for detected_file in worm_detected_count:
                    if worm_detected_count[detected_file] >= 5 and detected_file not in worm_alerted_files:
                        notify_user_worm(detected_file, "HEUR:Win32.Worm.Classic.Generic.Malware")
                        worm_alerted_files.append(detected_file)

    except Exception as ex:
        logging.error(f"Error in worm detection for file {file_path}: {ex}")

def log_directory_type(file_path):
    try:
        if file_path.startswith(sandboxie_folder):
            logging.info(f"{file_path}: It's a Sandbox environment file.")
        elif file_path.startswith(decompile_dir):
            logging.info(f"{file_path}: Decompiled.")
        elif file_path.startswith(nuitka_dir):
            logging.info(f"{file_path}: Nuitka onefile extracted.")
        elif file_path.startswith(dotnet_dir):
            logging.info(f"{file_path}: .NET decompiled.")
        elif file_path.startswith(pyinstaller_dir):
            logging.info(f"{file_path}: PyInstaller onefile extracted.")
        elif file_path.startswith(commandlineandmessage_dir):
            logging.info(f"{file_path}: Command line message extracted.")
        elif file_path.startswith(pe_extracted_dir):
            logging.info(f"{file_path}: PE file extracted.")
        elif file_path.startswith(zip_extracted_dir):
            logging.info(f"{file_path}: ZIP extracted.")
        elif file_path.startswith(seven_zip_extracted_dir):
            logging.info(f"{file_path}: 7zip extracted.")
        elif file_path.startswith(general_extracted_dir):
            logging.info(f"{file_path}: all extractable files go here.")
        elif file_path.startswith(tar_extracted_dir):
            logging.info(f"{file_path}: TAR extracted.")
        elif file_path.startswith(processed_dir):
            logging.info(f"{file_path}: Processed - File is base64/base32, signature/magic bytes removed.")
        elif file_path == main_file_path:  # Check for main file path
            logging.info(f"{file_path}: This is the main file.")
        elif file_path.startswith(memory_dir):
            logging.info(f"{file_path}: It's a dynamic analysis memory dump file.")
        elif file_path.startswith(debloat_dir):
            logging.info(f"{file_path}: It's a debloated file dir.")
        elif file_path.startswith(jar_extracted_dir):
           logging.info(f"{file_path}: It's a directory containing extracted files from a JAR (Java Archive) file.")
        elif file_path.startswith(pycdc_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc (Python Compiled Module) reversed-engineered Python source code directory with pycdc.exe.")
        elif file_path.startswith(pycdas_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc (Python Compiled Module) reversed-engineered Python source code directory with pycdas.exe.")
        elif file_path.startswith(python_source_code_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc (Python Compiled Module) reversed-engineered Python source code directory with uncompyle6.")
        elif file_path.startswith(nuitka_source_code_dir):
            logging.info(f"{file_path}: It's a Nuitka reversed-engineered Python source code directory.")
        else:
            logging.warning(f"{file_path}: File does not match known directories.")
    except Exception as ex:
        logging.error(f"Error logging directory type for {file_path}: {ex}")

def scan_file_with_deepseek(file_path, united_python_code_flag=False, decompiled_flag=False):
    """
    Processes a file and analyzes it using DeepSeek-Coder-1.3b.
    If united_python_code_flag is True (i.e. the file comes from pycdas, pycdc, uncomplye6 decompilation), the summary will consist solely of the full source code.
    If decompiled_flag is True (and united_python_code_flag is False), a normal summary is generated with an additional note indicating that the file was decompiled by our tool and is Python source code.
    
    Args:
        file_path (str): The path to the file to be scanned.
        united_python_code_flag (bool): If True, indicates that the file was produced by the pycdas decompiler.
        decompiled_flag (bool): If True (and united_python_code_flag is False), indicates that the file was decompiled by our tool.
    """
    try:
        # Log directory type based on the global variables
        if file_path.startswith(sandboxie_folder):
            logging.info(f"{file_path}: It's a Sandbox environment file.")
        elif file_path.startswith(decompile_dir):
            logging.info(f"{file_path}: Decompiled.")
        elif file_path.startswith(nuitka_dir):
            logging.info(f"{file_path}: Nuitka onefile extracted.")
        elif file_path.startswith(dotnet_dir):
            logging.info(f"{file_path}: .NET decompiled.")
        elif file_path.startswith(pyinstaller_dir):
            logging.info(f"{file_path}: PyInstaller onefile extracted.")
        elif file_path.startswith(commandlineandmessage_dir):
            logging.info(f"{file_path}: Command line message extracted.")
        elif file_path.startswith(pe_extracted_dir):
            logging.info(f"{file_path}: PE file extracted.")
        elif file_path.startswith(zip_extracted_dir):
            logging.info(f"{file_path}: ZIP extracted.")
        elif file_path.startswith(seven_zip_extracted_dir):
            logging.info(f"{file_path}: 7zip extracted.")
        elif file_path.startswith(general_extracted_dir):
            logging.info(f"{file_path}: all extractable files go here.")
        elif file_path.startswith(tar_extracted_dir):
            logging.info(f"{file_path}: TAR extracted.")
        elif file_path.startswith(processed_dir):
            logging.info(f"{file_path}: Processed - File is base64/base32, signature/magic bytes removed.")
        elif file_path == main_file_path:  # Check for main file path
            logging.info(f"{file_path}: This is the main file.")
        elif file_path.startswith(memory_dir):
            logging.info(f"{file_path}: It's a dynamic analysis memory dump file.")
        elif file_path.startswith(debloat_dir):
            logging.info(f"{file_path}: It's a debloated file dir.")
        elif file_path.startswith(jar_extracted_dir):
            logging.info(f"{file_path}: It's a directory containing extracted files from a JAR (Java Archive) file.")
        elif file_path.startswith(pycdc_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc reversed-engineered source code directory with pycdc.exe.")
        elif file_path.startswith(pycdas_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc reversed-engineered source code directory with pycdas.exe.")
        elif file_path.startswith(pycdas_deepseek_dir):
            logging.info(f"{file_path}: This is a PyInstaller .pyc reverse-engineered source code directory, decompiled with pycdas.exe and converted to non-bytecode Python code using DeepSeek-Coder 1.3b.")
        elif file_path.startswith(python_source_code_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc reversed-engineered source code directory with uncompyle6.")
        elif file_path.startswith(nuitka_source_code_dir):
            logging.info(f"{file_path}: It's a Nuitka reversed-engineered Python source code directory.")

        # Build the initial message based on flags
        if united_python_code_flag:
            initial_message = (
                "This file was decompiled using pycdas.exe and further analyzed with DeepSeek-Coder-1.3b.\n"
                "Based on the source code extracted via pycdas, please follow these instructions:\n"
                "- If the file is obfuscated, deobfuscate it by detecting and removing any gibberish output and decoding any encoded strings.\n"
                "- Extract the full, accurate source code as completely as possible.\n"
                "- Your output must consist solely of the complete source code, with no additional commentary, as I will save it with a .py extension.\n"
                "After extraction, I will send you the same text again for further analysis to determine if the file is malware.\n"
                "Decode any encoded strings, such as base64 or base32, as needed.\n"
            )
        elif decompiled_flag:
            initial_message = (
                "The result should always include four lines. Here are the lines that you must include all of them:\n"
                "- Malware: [Yes/No/Maybe]\n"
                "- Virus Name:\n"
                "- Confidence: [percentage]\n"
                "- Malicious Content: [Explanation]\n"
                f"File name: {os.path.basename(file_path)}\n"
                f"File path: {file_path}\n\n"
                "This file was decompiled by our tool and is Python source code.\n"
                "Based on the file name, file path, and file content analysis:\n\n"
                "If this file is obfuscated, it may be dangerous. I provide readable text for you to analyze it to determine if this file is malware.\n"
                "If it is a script file and obfuscated, it is probably suspicious or malware.\n"
                "If it registers itself in 'Shell Common Startup' or 'Shell Startup' and has these extensions, it could be harmful:\n"
                "- .vbs, .vbe, .js, .jse, .bat, .url, .cmd, .hta, .ps1, .psm1, .wsf, .wsb, .sct (Windows script files)\n"
                "- .dll, .jar, .msi, .scr (suspicious extensions) at Windows common startup (shell:common startup or shell:startup)\n"
                "If it tries to register as .wll instead of .dll, it could also be harmful.\n"
                "Decode any encoded strings, such as base64 or base32, as needed.\n"
            )
        else:
            initial_message = (
                "The result should always include four lines. Here are the lines that you must include all of them:\n"
                "- Malware: [Yes/No/Maybe]\n"
                "- Virus Name:\n"
                "- Confidence: [percentage]\n"
                "- Malicious Content: [Explanation]\n"
                f"File name: {os.path.basename(file_path)}\n"
                f"File path: {file_path}\n\n"
                f"This file is categorized as:\n"
                f"- Sandboxie environment file: {sandboxie_folder}\n"
                f"- Main file: {main_file_path}\n"
                f"- Decompiled file: {decompile_dir}\n"
                f"- .NET decompiled file: {dotnet_dir}\n"
                f"- Command line message or Windows readable messages: {commandlineandmessage_dir}\n\n"
                "Based on the file name, file path, and file content analysis:\n\n"
                "If this file is obfuscated, it may be dangerous. I provide readable text for you to analyze it to determine if this file is malware.\n"
                "If it is a script file and obfuscated, it is probably suspicious or malware.\n"
                "If it registers itself in 'Shell Common Startup' or 'Shell Startup' and has these extensions, it could be harmful:\n"
                "- .vbs, .vbe, .js, .jse, .bat, .url, .cmd, .hta, .ps1, .psm1, .wsf, .wsb, .sct (Windows script files)\n"
                "- .dll, .jar, .msi, .scr (suspicious extensions) at Windows common startup (shell:common startup or shell:startup)\n"
                "If it tries to register as .wll instead of .dll, it could also be harmful.\n"
                "Decode any encoded strings, such as base64 or base32, as needed.\n"
            )

        # Tokenize the initial message
        initial_inputs = deepseek_1b_tokenizer(initial_message, return_tensors="pt")
        initial_token_length = initial_inputs['input_ids'].shape[1]

        # Define token limits
        max_tokens = 2048
        remaining_tokens = max_tokens - initial_token_length

        # Read the file content
        readable_file_content = ""
        line_count = 0

        # Define max_lines for how many lines you want to read from the file
        max_lines = 100000

        try:
            # Read the file with UTF-8 encoding
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as deepseek_file:
                for line in deepseek_file:
                    if line_count < max_lines:
                        readable_file_content += line
                        line_count += 1
                    else:
                        break
        except Exception as ex:
            logging.error(f"Error reading file {file_path}: {ex}")
            return None  # Handle error appropriately

        # Tokenize the readable file content
        file_inputs = deepseek_1b_tokenizer(readable_file_content, return_tensors="pt")
        file_token_length = file_inputs['input_ids'].shape[1]

        # Truncate the file content if needed
        if file_token_length > remaining_tokens:
            truncated_file_content = deepseek_1b_tokenizer.decode(
                file_inputs['input_ids'][0, :remaining_tokens], skip_special_tokens=True)
        else:
            truncated_file_content = readable_file_content

        # Combine the initial message with the truncated file content
        combined_message = initial_message + f"File content:\n{truncated_file_content}\n"

        # Tokenize the combined message
        inputs = deepseek_1b_tokenizer(combined_message, return_tensors="pt")

        # Generate the response
        try:
            response = accelerator.unwrap_model(deepseek_1b_model).generate(
                input_ids=inputs['input_ids'],
                max_new_tokens=1000,
                num_return_sequences=1
            )
            response = deepseek_1b_tokenizer.decode(response[0], skip_special_tokens=True).strip()
        except Exception as ex:
            logging.error(f"Error generating response: {ex}")
            return

        # Extract the relevant part of the response
        start_index = response.lower().find("based on the analysis:")
        if start_index != -1:
            start_index += len("Based on the analysis:")
        else:
            start_index = 0

        relevant_response = response[start_index:].strip()

        # Initialize variables to store extracted information
        malware = "Unknown"
        confidence = "Unknown"
        virus_name = "Unknown"
        explanation = "No explanation provided"

        # Extract the required four lines from the response
        for line in relevant_response.split("\n"):
            line_lower = line.lower()
            if "malware:" in line_lower:
                malware = line.split(":")[-1].strip()
            if "virus name:" in line_lower:
                potential_name = line.split(":")[-1].strip()
                if os.path.basename(file_path) not in potential_name:
                    virus_name = potential_name
            if "confidence:" in line_lower:
                confidence = line.split(":")[-1].strip()
            if "malicious content:" in line_lower:
                explanation = line.split(":")[-1].strip()

        # Build the final summary response
        final_response = (
            f"Malware: {malware}\n"
            f"Virus Name: {virus_name}\n"
            f"Confidence: {confidence}\n"
            f"Malicious Content: {explanation}\n"
        )

        if united_python_code_flag:
            final_response = readable_file_content
        elif decompiled_flag:
            final_response += "\nNote: This file was decompiled by our tool and is Python source code.\n"

        print(final_response)
        logging.info(final_response)

        # Log the raw model response
        answer_log_path = os.path.join(script_dir, "log", "answer.log")
        try:
            with open(answer_log_path, "a") as answer_log_file:
                answer_log_file.write(relevant_response + "\n\n")  # Write the raw model response
        except Exception as ex:
            logging.error(f"Error writing to log file {answer_log_path}: {ex}")

        # Log the final summary
        log_file_path = os.path.join(script_dir, "log", "DeepSeek-Coder-1.3b.log")
        try:
            with open(log_file_path, "a") as log_file:
                log_file.write(final_response + "\n")
        except Exception as ex:
            logging.error(f"Error writing to log file {log_file_path}: {ex}")

        # If malware is detected (Maybe or Yes), notify the user
        if malware.lower() in ["maybe", "yes"]:
            try:
                notify_user_for_deepseek(file_path, virus_name, malware)
            except Exception as ex:
                logging.error(f"Error notifying user: {ex}")

        # --- For pycdas decompiled files: save the extracted source code with a .py extension ---
        if united_python_code_flag:
            pycdas_deepseek_dir = os.path.join(python_source_code_dir, "united_deepseek")
            if not os.path.exists(pycdas_deepseek_dir):
                os.makedirs(pycdas_deepseek_dir)
            deepseek_source_filename = os.path.splitext(os.path.basename(file_path))[0] + "_deepseek.py"
            deepseek_source_path = os.path.join(pycdas_deepseek_dir, deepseek_source_filename)
            try:
                with open(deepseek_source_path, "w", encoding="utf-8") as deepseek_source_file:
                    deepseek_source_file.write(readable_file_content)
                logging.info(f"DeepSeek extracted source code saved to {deepseek_source_path}")
                # Now scan .pyc source code
                scan_code_for_links(deepseek_source_path, pyinstaller_deepseek_flag=True)
            except Exception as ex:
                logging.error(f"Error writing DeepSeek extracted source code to {deepseek_source_path}: {ex}")

    except Exception as ex:
        logging.error(f"An unexpected error occurred in scan_file_with_deepseek: {ex}")

def extract_and_return_pyinstaller(file_path):
    """
    Extracts a PyInstaller archive and returns the paths of the extracted files.
    
    :param file_path: Path to the PyInstaller archive.
    :return: A list of extracted file paths.
    """
    extracted_pyinstaller_file_paths = []  # List to store the paths of the extracted files

    # Extract PyInstaller archive
    pyinstaller_archive = extract_pyinstaller_archive(file_path)
    
    if pyinstaller_archive:
        logging.info(f"PyInstaller archive extracted to {pyinstaller_archive}")
        
        # Traverse the extracted files
        for root, dirs, files in os.walk(pyinstaller_archive):
            for pyinstaller_file in files:
                extracted_file_path = os.path.join(root, pyinstaller_file)
                # Add the file path to the list of extracted file paths
                extracted_pyinstaller_file_paths.append(extracted_file_path)

    return extracted_pyinstaller_file_paths

def decompile_dotnet_file(file_path):
    """
    Decompiles a .NET assembly using ILSpy and scans all decompiled .cs files 
    for URLs, IP addresses, domains, and Discord webhooks.

    :param file_path: Path to the .NET assembly file.
    """
    try:
        logging.info(f"Detected .NET assembly: {file_path}")

        # Create a unique directory for decompiled output
        folder_number = 1
        while os.path.exists(f"{dotnet_dir}_{folder_number}"):
            folder_number += 1
        dotnet_output_dir = f"{dotnet_dir}_{folder_number}"
        os.makedirs(dotnet_output_dir, exist_ok=True)

        # Run ILSpy decompilation command
        ilspy_command = f"{ilspycmd_path} -o {dotnet_output_dir} {file_path}"
        os.system(ilspy_command)
        logging.info(f".NET content decompiled to {dotnet_output_dir}")

        # Scan all .cs files in the output directory
        for root, _, files in os.walk(dotnet_output_dir):
            for file in files:
                if file.endswith(".cs"):  # Only process .cs files
                    cs_file_path = os.path.join(root, file)
                    logging.info(f"Scanning .cs file: {cs_file_path}")

                    try:
                        # Read the content of the .cs file
                        with open(cs_file_path, "r", encoding="utf-8", errors="ignore") as f:
                            cs_file_content = f.read()

                        # Scan for links, IPs, domains, and Discord webhooks
                        scan_code_for_links(cs_file_content, dotnet_flag=True)

                    except Exception as ex:
                        logging.error(f"Error scanning .cs file {cs_file_path}: {ex}")

    except Exception as ex:
        logging.error(f"Error decompiling .NET file {file_path}: {ex}")

def check_pe_file(file_path, pe_file, signature_check, file_name):
    try:
        logging.info(f"File {file_path} is a valid PE file.")
        worm_alert(file_path)

        # Check for fake system files after signature validation
        if file_name in fake_system_files and os.path.abspath(file_path).startswith(main_drive_path):
            if pe_file and not signature_check["is_valid"]:
                logging.warning(f"Detected fake system file: {file_path}")
                notify_user_for_detected_fake_system_file(file_path, file_name, "HEUR:Win32.FakeSystemFile.Dropper.Generic")

    except Exception as ex:
        logging.error(f"Error checking PE file {file_path}: {ex}")

def extract_all_files_with_7z(file_path):
    try:
        counter = 1
        base_output_dir = os.path.join(general_extracted_dir, os.path.splitext(os.path.basename(file_path))[0])

        # Ensure output directory is unique
        while os.path.exists(f"{base_output_dir}_{counter}"):
            counter += 1

        output_dir = f"{base_output_dir}_{counter}"
        os.makedirs(output_dir, exist_ok=True)

        logging.info(f"Attempting to extract file {file_path} into {output_dir}...")

        # Run the 7z extraction
        command = [seven_zip_path, "x", file_path, f"-o{output_dir}", "-y", "-snl", "-spe"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            logging.error(f"7z extraction failed with return code {result.returncode}: {result.stderr}")
            return []

        logging.info(f"7z extraction successful for {file_path}.")

        # Gather all files in the output directory after extraction
        extracted_files = []
        for root, _, files in os.walk(output_dir):
            for name in files:
                extracted_files.append(os.path.join(root, name))

        if not extracted_files:
            logging.warning(f"No files were extracted from {file_path}.")
        else:
            logging.info(f"Extracted {len(extracted_files)} files from {file_path}.")

        return extracted_files

    except Exception as ex:
        logging.error(f"Error during 7z extraction: {ex}")
        return []

def is_pyc_file(file_path):
    """Check if the file is a Python compiled file (.pyc) using Detect It Easy."""
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")

        # Ensure the JSON output directory exists
        output_dir = Path(detectiteasy_json_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Define the base name for the output JSON file (output will be PyInstaller check result)
        base_name = Path(file_path).with_suffix(".json")

        # Get a unique file path for the JSON output
        json_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE console command with the -j flag to generate a JSON output
        result = subprocess.run([detectiteasy_console_path, "-j", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check if the file is detected as a Python compiled module
        if "Python" in result.stdout and "Compiled Module" in result.stdout and "Magic tag" in result.stdout:
            logging.info(f"File {file_path} is detected as a Python compiled module by DIE.")
            
            # Save the JSON output to the specified unique file
            with open(json_output_path, "w") as json_file:
                json_file.write(result.stdout)
            logging.info(f"Python compiled module analysis result saved to {json_output_path}")
            return True
        else:
            logging.info(f"File {file_path} is not a Python compiled module. Result: {result.stdout}")
            return False

    except subprocess.SubprocessError as ex:
        logging.error(f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False
    except Exception as ex:
        logging.error(f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}")
        return False

def extract_line(content, prefix):
    """
    Extracts a line from the content that starts with the given prefix.

    Args:
        content: Content to search.
        prefix: Line prefix to look for.

    Returns:
        The matched line or None.
    """
    lines = [line for line in content.splitlines() if line.startswith(prefix)]
    return lines[0] if lines else None

def decode_base64_from_line(line):
    """
    Decodes a base64 string from a given line.

    Args:
        line: The line containing the base64 string.

    Returns:
        Decoded bytes.
    """
    base64_str = extract_base64_string(line)
    return base64.b64decode(add_base64_padding(base64_str))

def DecryptString(key, tag, nonce, _input):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(_input) + decryptor.finalize()
    return decrypted_data.decode(errors="ignore")

def add_base64_padding(b64_string):
    padding = len(b64_string) % 4
    if padding != 0:
        b64_string += '=' * (4 - padding)
    return b64_string

def extract_base64_string(line):
    match = re.search(r"'([^']+)'|\"([^\"]+)\"", line)
    return match.group(1) or match.group(2) if match else None

def save_to_file(file_path, content):
    """
    Saves content to a file in the 'python_source_code_dir' directory and returns the file path.

    Args:
        file_path: Path to the file.
        content: Content to save.

    Returns:
        file_path: Path to the saved file.
    """

    # Update the file path to save within the specified directory
    file_path = os.path.join(python_source_code_dir, file_path)

    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        return file_path
    except Exception as ex:
        logging.error(f"Error saving file {file_path}: {ex}")
        return None

def process_decompiled_code(output_file):
    """
    Processes the decompiled code to extract and decrypt payloads.

    Args:
        output_file: Path to the decompiled code file.
    """
    try:
        with open(output_file, 'r', encoding='utf-8') as file:
            content = file.read()

        # Extract key, tag, nonce, and encrypted data
        key_line = extract_line(content, "key = ")
        tag_line = extract_line(content, "tag = ")
        nonce_line = extract_line(content, "nonce = ")
        encrypted_data_line = extract_line(content, "encrypted_data")

        key = decode_base64_from_line(key_line)
        tag = decode_base64_from_line(tag_line)
        nonce = decode_base64_from_line(nonce_line)
        encrypted_data = decode_base64_from_line(encrypted_data_line)

        # First decryption
        intermediate_data = DecryptString(key, tag, nonce, encrypted_data)
        temp_file = 'intermediate_data.py'
        saved_temp_file = save_to_file(temp_file, intermediate_data)

        # Process intermediate data
        if saved_temp_file:
            with open(saved_temp_file, 'r', encoding='utf-8') as temp:
                intermediate_content = temp.read()
        else:
            logging.error("Failed to save intermediate data.")
            return

        key_2 = decode_base64_from_line(extract_line(intermediate_content, "key = "))
        tag_2 = decode_base64_from_line(extract_line(intermediate_content, "tag = "))
        nonce_2 = decode_base64_from_line(extract_line(intermediate_content, "nonce = "))
        encrypted_data_2 = decode_base64_from_line(extract_line(intermediate_content, "encrypted_data"))

        # Second decryption
        final_decrypted_data = DecryptString(key_2, tag_2, nonce_2, encrypted_data_2)
        source_code_file = 'exela_stealer_last_stage.py'
        source_code_path = save_to_file(source_code_file, final_decrypted_data)

        # Process final stage and extract webhook URLs
        webhooks = extract_webhooks(final_decrypted_data)
        if webhooks:
            logging.warning(f"[+] Webhook URLs found: {webhooks}")
            if source_code_path:
                notify_user_for_malicious_source_code(source_code_path, 'HEUR:Win32.Discord.Pyinstaller.Exela.V2.Stealer.Generic.Malware')
            else:
                logging.error("Failed to save the final decrypted source code.")
        else:
            logging.error("[!] No webhook URLs found.")

    except Exception as ex:
        logging.error(f"Error during payload extraction: {ex}")

def extract_webhooks(content):
    """
    Extracts webhook URLs (regular and Canary versions) from the content.

    Args:
        content: The content to scan for Discord webhooks.

    Returns:
        A list of webhook URLs found in the content.
    """
    # Combine matches from both patterns
    webhooks = re.findall(discord_webhook_pattern, content) + re.findall(discord_canary_webhook_pattern, content)
    return webhooks

def run_pycdc_decompiler(file_path):
    """
    Runs the pycdc decompiler to decompile a .pyc file and saves it to a specified output directory.
    
    Args:
        file_path: Path to the .pyc file to be decompiled
    
    Returns:
        The decompiled file path, or None if the process fails
    """
    try:
        # Extract the file name and create the output path in the pycdc subfolder
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = os.path.join(pycdc_dir, f"{base_name}_pycdc_decompiled.py")

        # Build the pycdc command with the -o argument
        command = [pycdc_path, "-o", output_path, file_path]

        # Run the pycdc command
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            logging.info(f"Successfully decompiled using pycdc. Output saved to {output_path}")
            return output_path
        else:
            logging.error(f"pycdc error: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error running pycdc: {e}")
        return None

def run_pycdas_decompiler(file_path):
    """
    Runs the pycdas decompiler to decompile a .pyc file and saves it to a specified output directory.
    
    Args:
        file_path: Path to the .pyc file to be decompiled.
    
    Returns:
        The decompiled file path, or None if the process fails.
    """
    try:
        # Extract the file name and create the output path in the pycdas subfolder
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = os.path.join(pycdas_dir, f"{base_name}_pycdas_decompiled.py")

        # Build the pycdas command with the -o argument
        command = [pycdas_path, "-o", output_path, file_path]

        # Run the pycdas command
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            logging.info(f"Successfully decompiled using pycdas. Output saved to {output_path}")
            return output_path
        else:
            logging.error(f"pycdas error: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error running pycdas: {e}")
        return None

def show_code_with_uncompyle6_pycdc_pycdas(file_path, file_name):
    """
    Decompiles a .pyc file using uncompyle6, pycdc, and pycdas, and saves the results to the appropriate directories.
    Combines the outputs into one united file (saved in a subdirectory "united" of python_source_code_dir) and then
    scans the combined code for malicious content such as Discord webhooks, IP addresses, domains, and URLs.

    Args:
        file_path: Path to the .pyc file to decompile.
        file_name: The name of the .pyc file to be decompiled.

    Returns:
        A tuple of paths: (uncompyle6_output_path, pycdc_output_path, pycdas_output_path, united_output_path),
        or (None, None, None, None) if processing fails.
    """
    try:
        logging.info(f"Processing python file: {file_path}")

        # Ensure the main output directory exists
        if not os.path.exists(python_source_code_dir):
            os.makedirs(python_source_code_dir)

        # Derive a base name from the file name (without extension)
        base_name = os.path.splitext(file_name)[0]

        # Check if it's source code using PyInstaller's method
        is_source = False
        with open(file_path, "rb") as pyc_file:
            # Skip the pyc header (assumes 16 bytes header)
            pyc_file.seek(16)
            # Read the TOC entry structure
            entry_data = pyc_file.read(struct.calcsize('!IIIBc'))
            if len(entry_data) >= struct.calcsize('!IIIBc'):
                try:
                    # Unpack the structure and check the type field
                    _, _, _, _, type_cmprs_data = struct.unpack('!IIIBc', entry_data)
                    is_source = (type_cmprs_data == b's')
                except struct.error:
                    pass

        # Determine an output filename for uncompyle6 (versioned if needed)
        version = 1
        while True:
            if is_source:
                uncompyle6_output_path = os.path.join(
                    python_source_code_dir,
                    f"{base_name}_{version}_source_code.py"
                )
            else:
                uncompyle6_output_path = os.path.join(
                    python_source_code_dir,
                    f"{base_name}_{version}_decompile.py"
                )
            if not os.path.exists(uncompyle6_output_path):
                break
            version += 1

        # --- uncompyle6 decompilation ---
        try:
            with open(file_path, "rb") as dec_f:
                decompiled_code = uncompyle6.pyeval.evaluate(dec_f)
        except Exception as e:
            logging.warning(f"uncompyle6 failed: {e}")
            decompiled_code = None

        # Save the uncompyle6 output if decompilation succeeded
        if decompiled_code:
            with open(uncompyle6_output_path, "w") as output_file:
                output_file.write(decompiled_code)
            logging.info(f"Successfully decompiled using uncompyle6. Output saved to {uncompyle6_output_path}")
        else:
            logging.error("Failed to decompile with uncompyle6.")

        # --- PyCDC decompilation branch ---
        if os.path.exists(pycdc_path):
            pycdc_output_path = run_pycdc_decompiler(file_path)
        else:
            logging.error("pycdc executable not found")
            pycdc_output_path = None

        # Process uncompyle6 output (no scanning here)
        if decompiled_code:
            logging.info(f"Processing uncompyle6 output at {uncompyle6_output_path}")
            process_decompiled_code(uncompyle6_output_path)

        if pycdc_output_path:
            with open(pycdc_output_path, "r") as pycdc_file:
                pycdc_code = pycdc_file.read()
            logging.info(f"Processing pycdc output at {pycdc_output_path}")
            process_decompiled_code(pycdc_output_path)

        # --- PyCDAS decompilation branch ---
        if os.path.exists(pycdas_path):
            pycdas_output_path = run_pycdas_decompiler(file_path)
        else:
            logging.error("pycdas executable not found")
            pycdas_output_path = None

        if pycdas_output_path:
            with open(pycdas_output_path, "r") as pycdas_file:
                pycdas_code = pycdas_file.read()
            logging.info(f"Processing pycdas output at {pycdas_output_path}")
            process_decompiled_code(pycdas_output_path)

        # --- United output: combine all decompiled code ---
        united_python_source_code_dir = os.path.join(python_source_code_dir, "united")
        if not os.path.exists(united_python_source_code_dir):
            os.makedirs(united_python_source_code_dir)

        combined_code = ""

        # Append uncompyle6 output (if available)
        if decompiled_code:
            with open(uncompyle6_output_path, "r") as f:
                uncompyle6_code = f.read()
            combined_code += "# uncompyle6 output\n" + uncompyle6_code + "\n\n"

        # Append pycdc output (if available)
        if pycdc_output_path and os.path.exists(pycdc_output_path):
            with open(pycdc_output_path, "r") as f:
                pycdc_code = f.read()
            combined_code += "# pycdc output\n" + pycdc_code + "\n\n"

        # Append pycdas output (if available)
        if pycdas_output_path and os.path.exists(pycdas_output_path):
            with open(pycdas_output_path, "r") as f:
                pycdas_code = f.read()
            combined_code += "# pycdas output\n" + pycdas_code + "\n\n"

        # Now scan only the united combined code for links/malicious content
        scan_code_for_links(combined_code, pyinstaller_flag=True)

        united_output_path = os.path.join(united_python_source_code_dir, f"{base_name}_united.py")
        with open(united_output_path, "w") as united_file:
            united_file.write(combined_code)
        logging.info(f"United decompiled output saved to {united_output_path}")

        try:
            scan_file_with_deepseek(united_output_path, united_python_code=True)
            logging.info(f"United decompiled output saved to {united_output_path}")
        except Exception as e:
            logging.error(f"Error during scanning: {e}")

        return uncompyle6_output_path, pycdc_output_path, pycdas_output_path, united_output_path

    except Exception as ex:
        logging.error(f"Error processing python file {file_path}: {ex}")
        return None, None, None, None

# --- Main Scanning Function ---
def scan_and_warn(file_path, flag=False, flag_debloat=False):
    """
    Scans a file for potential issues, starting with an online cloud analysis
    using the file's MD5 hash. If the cloud analysis indicates the file is clean,
    no further scanning is done. If the file is flagged (malware/suspicious), a warning 
    is sent via a dedicated notify_user_nichta function.
    
    :param file_path: Path to the file or archive to scan.
    :param flag: Indicates if the file should be reprocessed even if already scanned.
    :return: True if the scan was successful (or the file was flagged), False otherwise.
    """
    try:
        logging.info(f"Scanning file: {file_path}, Type: {type(file_path).__name__}")

        # Ensure the file_path is a string.
        if not isinstance(file_path, str):
            logging.error(f"Invalid file_path type: {type(file_path).__name__}")
            return False

        # Ensure the file exists before proceeding.
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return False

        # Check if the file is empty.
        if os.path.getsize(file_path) == 0:
            logging.debug(f"File {file_path} is empty. Skipping scan. That doesn't mean it's not malicious. See here: https://github.com/HydraDragonAntivirus/0KBAttack")
            return False

        # Read the file content once for hash calculation (and later if needed).
        with open(file_path, 'rb') as scan_file:
            data_content = scan_file.read()

        # --- Cloud Analysis with Hash Calculation ---
        file_md5 = hashlib.md5(data_content).hexdigest()
        risk, virus = query_md5_online_sync(file_md5)
        # Create a descriptive result string that includes the virus name if available.
        cloud_result = risk if not virus else f"{risk} (detected as {virus})"
        logging.info(f"Cloud analysis result for {file_path}: {cloud_result}")

        # --- Decision Based on Cloud Analysis ---
        if risk == "Benign":
            logging.info(f"File {file_path} flagged as benign (exact match) by cloud analysis. Skipping further scanning.")
            return False  # Clean file; no further scan
        if risk == "Benign (auto verdict)":
            logging.info(f"File {file_path} flagged as benign (auto verdict) by cloud analysis. Skipping further scanning.")
            return False  # Clean file; no further scan
        elif risk == "Malware":
            logging.warning(f"File {file_path} flagged as malware by cloud analysis: {cloud_result}")
            notify_user_nichta(file_path, cloud_result)
            return True
        elif risk == "Suspicious":
            logging.warning(f"File {file_path} flagged as suspicious by cloud analysis: {cloud_result}")
            notify_user_nichta(file_path, cloud_result)
            return True
        elif risk.startswith("Unknown"):
            logging.info(f"Cloud analysis returned unknown for file {file_path}. Proceeding with local scanning.")
        elif risk.startswith("Unknown (Result)"):
            logging.info(f"Cloud analysis returned an unknown result for file {file_path}. Proceeding with local scanning.")
        elif risk.startswith("Unknown (API Error)"):
            logging.info(f"Cloud analysis returned an API error for file {file_path}. Proceeding with local scanning.")
        else:
            logging.info(f"Cloud analysis returned an unhandled result for file {file_path}: {cloud_result}. Proceeding with local scanning.")

        with open(file_path, 'rb') as scan_file:
            data_content = scan_file.read()

       # Extract the file name
        file_name = os.path.basename(file_path)

        # Check if it's a .pyc file and decompile if needed
        if is_pyc_file(file_path):
            logging.info(f"File {file_path} is a .pyc (Python Compiled Module) file. Attempting to decompile...")

            # Call the show_code_with_uncompyle6_pycdc_pycdas function to decompile the .pyc file
            decompiled_file_paths = show_code_with_uncompyle6_pycdc_pycdas(file_path, file_name)

            # If decompilation was successful for either uncompyle6 or pycdc, scan the decompiled files
            uncompyle6_file_path, pycdc_file_path = decompiled_file_paths

            # Scan and warn for the uncompyle6 decompiled file, if available
            if uncompyle6_file_path:
                logging.info(f"Scanning decompiled file from uncompyle6: {uncompyle6_file_path}")
                scan_and_warn(uncompyle6_file_path)
            else:
                logging.error(f"Uncompyle6 decompilation failed for file {file_path}.")

            # Scan and warn for the pycdc decompiled file, if available
            if pycdc_file_path:
                logging.info(f"Scanning decompiled file from pycdc: {pycdc_file_path}")
                scan_and_warn(pycdc_file_path)
            else:
                logging.error(f"pycdc decompilation failed for file {file_path}.")

        # Initialize variables
        is_decompiled = False
        pe_file = False
        signature_check = {
            "has_microsoft_signature": False,
            "is_valid": False,
            "signature_status_issues": False
        }

        # Check if the file content is valid hex data
        if is_hex_data(data_content):
            logging.info(f"File {file_path} contains valid hex-encoded data.")

            # Attempt to extract the file, regardless of its type
            try:
                logging.info(f"Attempting to extract file {file_path}...")
                extracted_files = extract_all_files_with_7z(file_path)

                if extracted_files:
                    logging.info(f"Extraction successful for {file_path}. Scanning extracted files...")
                    # Recursively scan each extracted file
                    for extracted_file in extracted_files:
                        logging.info(f"Scanning extracted file: {extracted_file}")
                        scan_and_warn(extracted_file)

                logging.info(f"File {file_path} is not a valid archive or extraction failed. Proceeding with scanning.")
            except Exception as extraction_error:
                logging.warning(f"Error during extraction of {file_path}: {extraction_error}")

            # Decompile the file in a separate thread
            decompile_thread = threading.Thread(target=decompile_file, args=(file_path,))
            decompile_thread.start()

            # Perform signature check only if the file is valid hex data
            signature_check = check_signature(file_path)
            if not isinstance(signature_check, dict):
                logging.error(f"check_signature did not return a dictionary for file: {file_path}, received: {signature_check}")

            # Handle signature results
            if signature_check["has_microsoft_signature"]:
                logging.info(f"Valid Microsoft signature detected for file: {file_path}")
                return False
            if signature_check["is_valid"]:
                logging.info(f"File '{file_path}' has a valid signature. Skipping worm detection.")
            elif signature_check["signature_status_issues"]:
                logging.warning(f"File '{file_path}' has signature issues. Proceeding with further checks.")
                notify_user_invalid(file_path, "Win32.Suspicious.InvalidSignature")

            # Additional checks for PE files and .NET files
            if is_pe_file(file_path):
                logging.info(f"File {file_path} is a valid PE file.")
                pe_file = True

            # Call analyze_process_memory if the file is a PE file
            if pe_file:
                logging.info(f"File {file_path} is identified as a PE file. Performing process memory analysis...")
                saved_file_path = analyze_process_memory(file_path)

                if saved_file_path:
                    try:
                        scan_and_warn(saved_file_path)
                    except Exception as e:
                        logging.error(f"Error processing file {saved_file_path}: {e}")

                # Use the `debloat` library to optimize PE file for scanning
                try:
                    if not flag_debloat:
                        logging.info(f"Debloating PE file {file_path} for faster scanning.")
                        optimized_file_path = debloat_pe_file(file_path)
                        if optimized_file_path:
                             logging.info(f"Debloated file saved at: {optimized_file_path}")
                             scan_and_warn(optimized_file_path, flag_debloat=True)
                        else:
                             logging.warning(f"Debloating failed for {file_path}, continuing with the original file.")
                except ImportError as ex:
                    logging.error(f"Debloat library is not installed. Install it with `pip install debloat`: {ex}")
                except Exception as ex:
                    logging.error(f"Error during debloating of {file_path}: {ex}")

            if is_dotnet_file(file_path):
                dotnet_thread = threading.Thread(target=decompile_dotnet_file, args=(file_path,))
                dotnet_thread.start()

            if is_jar_file(file_path):
                extracted_jar_files = run_jar_extractor(file_path)
                for extracted_jar_file in extracted_jar_files:
                    scan_and_warn(extracted_jar_file)

            # Check if the file contains Nuitka executable
            nuitka_type = is_nuitka_file(file_path)

            # Only proceed with extraction if Nuitka is detected
            if nuitka_type:
                try:
                    logging.info(f"Checking if the file {file_path} contains Nuitka executable of type: {nuitka_type}")
                    # Pass both the file path and Nuitka type to the check_and_extract_nuitka function
                    extract_nuitka_file(file_path, nuitka_type)
                except Exception as ex:
                    logging.error(f"Error checking or extracting Nuitka content from {file_path}: {ex}")
            else:
                logging.info(f"No Nuitka executable detected in {file_path}")
        else:
            # If the file content is not valid hex data, perform scanning with DeepSeek-Coder-1.3b
            logging.info(f"File {file_path} does not contain valid hex-encoded data. Scanning with DeepSeek-Coder-1.3b...")
            try:
                scan_thread = threading.Thread(target=scan_file_with_deepseek, args=(file_path,))
                scan_thread.start()
                scan_thread.join()  # Wait for scanning to complete
            except Exception as ex:
                logging.error(f"Error during scanning with DeepSeek-Coder-1.3b for file {file_path}: {ex}")

            # Scan for malware in real-time only for non-hex data
            logging.info(f"Performing real-time malware detection for non-hex data file: {file_path}...")
            real_time_scan_thread = threading.Thread(target=monitor_message.detect_malware, args=(file_path,))
            real_time_scan_thread.start()

        # Log directory type based on file path
        log_directory_type(file_path)

        # Perform ransomware alert check
        ransomware_alert(file_path)

        # Check if the file is in decompile_dir
        if file_path.startswith(decompile_dir):
            logging.info(f"File {file_path} is in decompile_dir.")
            is_decompiled = True

        # Check if the file is a known rootkit file
        if file_name in known_rootkit_files:
            logging.warning(f"Detected potential rootkit file: {file_path}")
            rootkit_thread = threading.Thread(target=notify_user_for_detected_rootkit, args=(file_path, f"HEUR:Rootkit.{file_name}"))
            rootkit_thread.start()

        # Process the file data including magic byte removal
        if not os.path.commonpath([file_path, processed_dir]) == processed_dir:
            process_thread = threading.Thread(target=process_file_data, args=(file_path,))
            process_thread.start()

        # Check if the file is a PyInstaller archive
        if is_pyinstaller_archive(file_path):
            logging.info(f"File {file_path} is a PyInstaller archive. Extracting...")

            # Extract the PyInstaller files and get their paths
            extracted_files_pyinstaller = extract_and_return_pyinstaller(file_path)

            if extracted_files_pyinstaller:
                # Scan each extracted file
                for extracted_file in extracted_files_pyinstaller:
                    logging.info(f"Scanning extracted file: {extracted_file}")
                    scan_and_warn(extracted_file)
            else:
                logging.warning(f"No files extracted from PyInstaller archive: {file_path}")

        # Check for fake file size
        if os.path.getsize(file_path) > 100 * 1024 * 1024:  # File size > 100MB
            with open(file_path, 'rb') as fake_file:
                file_content_read = fake_file.read(100 * 1024 * 1024)
                if file_content_read == b'\x00' * 100 * 1024 * 1024:  # 100MB of continuous `0x00` bytes
                    logging.warning(f"File {file_path} is flagged as HEUR:FakeSize.Generic")
                    fake_size = "HEUR:FakeSize.Generic"
                    if signature_check and signature_check["is_valid"]:
                        fake_size = "HEUR:SIG.Win32.FakeSize.Generic"
                    notify_user_fake_size_thread = threading.Thread(target=notify_user_fake_size, args=(file_path, fake_size))
                    notify_user_fake_size_thread.start()

        # Perform real-time scan
        is_malicious, virus_names, engine_detected = scan_file_real_time(file_path, signature_check, pe_file=pe_file)

        # Inside the scan check logic
        if is_malicious:
            # Concatenate multiple virus names into a single string without delimiters
            virus_name = ''.join(virus_names)
            logging.warning(f"File {file_path} is malicious. Virus: {virus_name}")

            if virus_name.startswith("PUA."):
                notify_user_pua_thread = threading.Thread(target=notify_user_pua, args=(file_path, virus_name, engine_detected))
                notify_user_pua_thread.start()
            else:
                notify_user_thread = threading.Thread(target=notify_user, args=(file_path, virus_name, engine_detected))
                notify_user_thread.start()

        # Additional post-decompilation actions based on extracted file path
        if is_decompiled:
            logging.info(f"Checking original file path from decompiled data for: {file_path}")
            original_file_path_thread = threading.Thread(target=extract_original_file_path_from_decompiled, args=(file_path,))
            original_file_path_thread.start()

        # Continue processing even if flag is True, to handle files already processed
        if flag:
            logging.info(f"Reprocessing file {file_path} with all checks enabled...")

        return False

    except Exception as ex:
        logging.error(f"Error scanning file {file_path}: {ex}")
        return False

def extract_nuitka_file(file_path, nuitka_type):
    """
    Detect Nuitka type, extract Nuitka executable content, and scan for additional Nuitka executables.
    :param file_path: Path to the Nuitka executable file.
    :param nuitka_type: Type of Nuitka executable ("Nuitka OneFile" or "Nuitka").
    """
    try:
        if nuitka_type == "Nuitka OneFile":
            logging.info(f"Nuitka OneFile executable detected in {file_path}")

            # Extract the file name (without extension) to include in the folder name
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]

            # Find the next available directory number for OneFile extraction
            folder_number = 1
            while os.path.exists(os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")):
                folder_number += 1

            # Create the new directory with the executable file name and folder number
            nuitka_output_dir = os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")
            os.makedirs(nuitka_output_dir, exist_ok=True)

            logging.info(f"Extracting Nuitka OneFile {file_path} to {nuitka_output_dir}")

            # Use NuitkaExtractor for extraction
            extractor = NuitkaExtractor(file_path, nuitka_output_dir)
            extractor.extract()

            # Scan the extracted directory for additional Nuitka executables
            logging.info(f"Scanning extracted directory for additional Nuitka executables...")
            found_executables = scan_directory_for_executables(nuitka_output_dir)

            # Process any found normal Nuitka executables
            for exe_path, exe_type in found_executables:
                if exe_type == "Nuitka":
                    logging.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                    extract_nuitka_file(exe_path, exe_type)

        elif nuitka_type == "Nuitka":
            logging.info(f"Nuitka executable detected in {file_path}")

            # Extract the Nuitka executable
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]
            nuitka_output_dir = os.path.join(nuitka_dir, f"Nuitka_{file_name_without_extension}")
            os.makedirs(nuitka_output_dir, exist_ok=True)

            logging.info(f"Extracting Nuitka executable {file_path} to {nuitka_output_dir}")

            # Use enhanced 7z extraction
            extracted_files = extract_all_files_with_7z(file_path)

            if extracted_files:
                logging.info(f"Successfully extracted files from Nuitka executable: {file_path}")
                # Scan for RSRC/RCDATA resources
                scan_rsrc_directory(extracted_files)
            else:
                logging.error(f"Failed to extract normal Nuitka executable: {file_path}")

        else:
            logging.info(f"No Nuitka content found in {file_path}")

    except PayloadError as ex:
        logging.error(f"Payload error while extracting Nuitka file: {ex}")
    except Exception as ex:
        logging.error(f"Unexpected error while extracting Nuitka file: {ex}")

def monitor_sandbox():
    if not os.path.exists(sandboxie_folder):
        print(f"The sandboxie folder path does not exist: {sandboxie_folder}")
        logging.error(f"The sandboxie folder path does not exist: {sandboxie_folder}")
        return

    hDir = win32file.CreateFile(
        sandboxie_folder,
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
                pathToScan = os.path.join(sandboxie_folder, file)
                if os.path.exists(pathToScan):
                    print(pathToScan)
                    scan_and_warn(pathToScan)
                else:
                    print(f"File or folder not found: {pathToScan}")
                    logging.warning(f"File or folder not found: {pathToScan}")

    except Exception as ex:
        print(f"An error occurred at monitor_sandbox: {ex}")
        logging.error(f"An error occurred at monitor_sandbox: {ex}")
    finally:
        win32file.CloseHandle(hDir)

def start_monitoring_sandbox():
    threading.Thread(target=monitor_sandbox).start()

def monitor_snort_log():
    if not os.path.exists(log_path):
        open(log_path, 'w').close()  # Create an empty file if it doesn't exist

    with open(log_path, 'r') as log_file:
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file
        while True:
            try:
                line = log_file.readline()
                if not line:
                    continue
                process_alert(line)
            except Exception as ex:
                print(f"Error processing line: {ex}")

def check_startup_directories():
    """Monitor startup directories for new files and handle them."""
    # Define the paths to check
    defaultbox_user_startup_folder = rf'{sandboxie_folder}\user\current\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    defaultbox_programdata_startup_folder = rf'{sandboxie_folder}\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'

    # List of directories to check
    directories_to_check = [
        defaultbox_user_startup_folder,
        defaultbox_programdata_startup_folder
    ]

    # List to keep track of already alerted files
    alerted_files = []

    while True:
        try:
            for directory in directories_to_check:
                if os.path.exists(directory):
                    for file in os.listdir(directory):
                        file_path = os.path.join(directory, file)
                        if os.path.isfile(file_path) and file_path not in alerted_files:
                            if file_path.endswith('.wll') and is_pe_file(file_path):
                                malware_type = "HEUR:Win32.Startup.DLLwithWLL.Generic.Malware"
                                message = f"Confirmed DLL malware detected: {file_path}\nVirus: {malware_type}"
                            elif file_path.endswith(('.vbs', '.vbe', '.js', '.jse', '.bat', '.url', '.cmd', '.hta', '.ps1', '.psm1', '.wsf', '.wsb', '.sct')):
                                malware_type = "HEUR:Win32.Startup.Script.Generic.Malware"
                                message = f"Confirmed script malware detected: {file_path}\nVirus: {malware_type}"
                            elif file_path.endswith(('.dll', '.jar', '.msi', '.scr', '.hta',)):
                                malware_type = "HEUR:Win32.Startup.Suspicious.Extension.Generic.Malware"
                                message = f"Confirmed malware with suspicious extension detected: {file_path}\nVirus: {malware_type}"
                            else:
                                malware_type = "HEUR:Win32.Startup.Suspicious.Generic.Malware"
                                message = f"Suspicious startup file detected: {file_path}\nVirus: {malware_type}"

                            logging.warning(f"Suspicious or malicious startup file detected in {directory}: {file}")
                            print(f"Suspicious or malicious startup file detected in {directory}: {file}")
                            notify_user_startup(file_path, message)
                            scan_and_warn(file_path)
                            alerted_files.append(file_path)
        except Exception as ex:
            logging.error(f"An error occurred while checking startup directories: {ex}")

def check_hosts_file_for_blocked_antivirus():
    try:
        if not os.path.exists(hosts_path):
            return False

        with open(hosts_path, 'r') as hosts_file:
            hosts_content = hosts_file.read()

        blocked_domains = []

        # Regular expression pattern to match domain or any subdomain
        domain_patterns = [re.escape(domain) + r'\b' for domain in antivirus_domains_data]
        pattern = r'\b(?:' + '|'.join(domain_patterns) + r')\b'

        # Find all matching domains/subdomains in hosts content
        matches = re.findall(pattern, hosts_content, flags=re.IGNORECASE)

        if matches:
            blocked_domains = list(set(matches))  # Remove duplicates

        if blocked_domains:
            logging.warning(f"Malicious hosts file detected: {hosts_path}")
            print(f"Malicious hosts file detected: {hosts_path}")
            notify_user_hosts(hosts_path, "HEUR:Win32.Trojan.Hosts.Hijacker.DisableAV.Generic")
            return True
        else:
            logging.warning(f"Suspicious hosts file detected: {hosts_path}")
            print(f"Suspicious hosts file detected: {hosts_path}")
            notify_user_hosts(hosts_path, "HEUR:Win32.Trojan.Hosts.Hijacker.Generic")
            return True

    except Exception as ex:
        logging.error(f"Error reading hosts file: {ex}")

    return False

# Function to continuously monitor hosts file
def monitor_hosts_file():
    # Continuously check the hosts file
    while True:
        is_malicious_host = check_hosts_file_for_blocked_antivirus()

        if is_malicious_host:
            print("Malicious hosts file detected and flagged.")
            break  # Stop monitoring after notifying once

def is_malicious_file(file_path, size_limit_kb):
    """ Check if the file is less than the given size limit """
    return os.path.getsize(file_path) < size_limit_kb * 1024

def check_uefi_directories():
    """ Continuously check the specified UEFI directories for malicious files """
    alerted_uefi_files = []
    known_uefi_files = list(set(uefi_100kb_paths + uefi_paths))  # Convert to list and ensure uniqueness

    while True:
        for uefi_path in uefi_paths + uefi_100kb_paths:
            if os.path.isfile(uefi_path) and uefi_path.endswith(".efi"):
                if uefi_path not in alerted_uefi_files:
                    if uefi_path in uefi_100kb_paths and is_malicious_file(uefi_path, 100):
                        logging.warning(f"Malicious file detected: {uefi_path}")
                        print(f"Malicious file detected: {uefi_path}")
                        notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.SecureBootRecovery.Generic.Malware")
                        scan_and_warn(uefi_path)
                        alerted_uefi_files.append(uefi_path)
                    elif uefi_path in uefi_paths and is_malicious_file(uefi_path, 1024):
                        logging.warning(f"Malicious file detected: {uefi_path}")
                        print(f"Malicious file detected: {uefi_path}")
                        notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.ScreenLocker.Ransomware.Generic.Malware")
                        scan_and_warn(uefi_path)
                        alerted_uefi_files.append(uefi_path)

        # Check for any new files in the EFI directory
        efi_dir = rf'{sandboxie_folder}\drive\X\EFI'
        for root, dirs, files in os.walk(efi_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith(".efi") and file_path not in known_uefi_files and file_path not in alerted_uefi_files:
                    logging.warning(f"Unknown file detected: {file_path}")
                    print(f"Unknown file detected: {file_path}")
                    notify_user_uefi(file_path, "HEUR:Win32.Rootkit.Startup.UEFI.Generic.Malware")
                    scan_and_warn(file_path)
                    alerted_uefi_files.append(file_path)

class ScanAndWarnHandler(FileSystemEventHandler):

    def process_file(self, file_path):
        try:
            scan_and_warn(file_path)
            logging.info(f"Processed file: {file_path}")
        except Exception as ex:
            logging.error(f"Error processing file (scan_and_warn) {file_path}: {ex}")

    def process_directory(self, dir_path):
        try:
            for root, _, files in os.walk(dir_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    self.process_file(file_path)
            logging.info(f"Processed all files in directory: {dir_path}")
        except Exception as ex:
            logging.error(f"Error processing directory {dir_path}: {ex}")

    def on_any_event(self, event):
        if event.is_directory:
            self.process_directory(event.src_path)
            logging.info(f"Directory event detected: {event.src_path}")
        else:
            logging.info(f"Event detected: {event.event_type} for file: {event.src_path}")

    def on_created(self, event):
        if event.is_directory:
            self.process_directory(event.src_path)
            logging.info(f"Directory created: {event.src_path}")
        else:
            self.process_file(event.src_path)
            logging.info(f"File created: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)
            logging.info(f"File modified: {event.src_path}")

    def on_moved(self, event):
        if event.is_directory:
            self.process_directory(event.dest_path)
            logging.info(f"Directory moved: {event.src_path} to {event.dest_path}")
        else:
            self.process_file(event.dest_path)
            logging.info(f"File moved: {event.src_path} to {event.dest_path}")

event_handler = ScanAndWarnHandler()
observer = Observer()
observer.schedule(event_handler, path=sandboxie_folder, recursive=False)

def run_sandboxie_control():
    try:
        logging.info("Running Sandboxie control.")
        # Include the '/open' argument to open the Sandboxie control window
        result = subprocess.run([sandboxie_control_path, "/open"], shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logging.info(f"Sandboxie control output: {result.stdout}")
    except subprocess.CalledProcessError as ex:
        logging.error(f"Error running Sandboxie control: {ex.stderr}")
    except Exception as ex:
        logging.error(f"Unexpected error running Sandboxie control: {ex}")

# Constants for Windows API calls
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E

# Function to get window text
def get_window_text(hwnd):
    """Retrieve the text of a window."""
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd) + 1
    buffer = ctypes.create_unicode_buffer(length)
    ctypes.windll.user32.GetWindowTextW(hwnd, buffer, length)
    return buffer.value

# Function to get control text
def get_control_text(hwnd):
    """Retrieve the text from a control."""
    length = ctypes.windll.user32.SendMessageW(hwnd, WM_GETTEXTLENGTH) + 1
    buffer = ctypes.create_unicode_buffer(length)
    ctypes.windll.user32.SendMessageW(hwnd, WM_GETTEXT, length, buffer)
    return buffer.value

# Function to find child windows of a given window
def find_child_windows(parent_hwnd):
    """Find all child windows of the given parent window."""
    child_windows = []

    def enum_child_windows_callback(hwnd):
        child_windows.append(hwnd)
        return True

    EnumChildWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    ctypes.windll.user32.EnumChildWindows(parent_hwnd, EnumChildWindowsProc(enum_child_windows_callback), None)
    
    return child_windows

# Function to find windows containing text
def find_windows_with_text():
    """Find all windows and their child windows."""
    def enum_windows_callback(hwnd):
        if ctypes.windll.user32.IsWindowVisible(hwnd):
            window_text = get_window_text(hwnd)
            window_handles.append((hwnd, window_text))
            for child in find_child_windows(hwnd):
                control_text = get_control_text(child)
                window_handles.append((child, control_text))
        return True

    window_handles = []
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    ctypes.windll.user32.EnumWindows(EnumWindowsProc(enum_windows_callback), None)
    return window_handles

class MonitorMessageCommandLine:
    def __init__(self):
        self.known_malware_messages = {
            "classic": {
                "message": "this program cannot be run under virtual environment or debugging software",
                "virus_name": "HEUR:Win32.Trojan.Guloader.C4D9Dd33.Generic",
                "process_function": self.process_detected_text_classic
            },
            "av": {
                "message": "disable your antivirus",
                "virus_name": "HEUR:Win32.DisableAV.Generic",
                "process_function": self.process_detected_text_av
            },
            "debugger": {
                "message": "a debugger has been found running in your system please unload it from memory and restart your program",
                "virus_name": "HEUR:Win32.Themida.Generic",
                "process_function": self.process_detected_text_debugger
            },
            "fanmade": {
                "patterns": [
                    "executed a trojan", "this is the last warning", "creator of this malware", "creator of this trojan",
                    "this trojan has", "by this trojan", "this is a malware", "considered malware", "destroy your computer",
                    "destroy this computer", "execute this malware", "run a malware", "this malware contains", "and makes it unusable",
                    "contains flashing lights", "run malware", "executed is a malware", "resulting in an unusable machine", "this malware will harm your computer",
                    "this trojan and", "using this malware", "this malware can", "gdi malware", "win32 trojan specifically", "malware will run"
                ],
                "virus_name": "HEUR:Win32.GDI.Fanmade.Generic",
                "process_function": self.process_detected_text_fanmade
            },
            "rogue": {
                "patterns": [
                    "your pc is infected", "your computer is infected", "your system is infected", "windows is infected",
                    "has found viruses on computer", "windows security alert", "pc is at risk", "malicious program has been detected",
                    "warning virus detected"
                ],
                "virus_name": "HEUR:Win32.Rogue.Generic",
                "process_function": self.process_detected_text_rogue
            },
            "powershell_iex_download": {
                "patterns": [
                    r'*powershell.exe* iex *((New-Object Net.WebClient).DownloadString(*',
                    r'*powershell*[string][char[]]@(0x*Set-Alias*Net.WebClient*.DownloadString(*',
                    r'*powershell*iex (new-object system.net.webclient).downloadstring*',
                    r'*iex ( [string][system.text.encoding]::ascii.getstring([system.convert]::frombase64string( ((new-object net.webclient).downloadstring(*',
                    r'*powershell*.DownloadFile([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(*>&*',
                    r'*iex (new-object net.webclient).downloadstring(*',
                    r'*powershell -command iex (*downloadstring*',
                    r'*iex (new-object net.webclient).downloadfile(*',
                    r'*powershell*-command*iex(*http*',
                    r'*-command iex (new-object*downloadstring*',
                    r'*$path*iex(*.web*-replace*',
                    r'*iex ((new-object system.net.webclient).downloadstring(*',
                    r'*powershell*.webclient)*iex*',
                    r'*iex(new-object net.webclient).downloadstring(*',
                    r'*iex ((new-object net.webclient).downloadstring(*',
                    r'*http*.replace(*iex*'
                ],
                "virus_name": "HEUR:Win32.PowerShell.IEX.Download.Generic",
                "process_function": self.process_detected_powershell_iex_download
            },
            "xmrig": {
                "patterns": [
                    'xmrig',
                    'xmrig.exe',
                    'start xmrig',
                    'xmrig --help',
                    'xmrig --version',
                    'xmrig --config'
                ],
                "virus_name": "HEUR:Win32.Miner.XMRig.Generic",
                "process_function": self.process_detected_command_xmrig
            },
            "wifi": {
                "command": 'netsh wlan show profile',
                "virus_name": "HEUR:Win32.Trojan.Password.Stealer.Wi-Fi.Generic",
                "process_function": self.process_detected_command_wifi
            },
            "shadowcopy": {
                "command": 'get-wmiobject win32_shadowcopy | foreach-object {$_.delete();}',
                "virus_name": "HEUR:Win32.Ransom.ShadowCopy.Generic",
                "process_function": self.process_detected_command_ransom_shadowcopy
            },
            "wmic": {
                "command": 'wmic shadowcopy delete',
                "virus_name": "HEUR:Win32.Ransom.ShadowCopy.WMIC.Generic",
                "process_function": self.process_detected_command_wmic_shadowcopy
            },
            "startup": {
                "command": 'copy-item \\roaming\\microsoft\\windows\\start menu\\programs\\startup',
                "virus_name": "HEUR:Win32.Startup.PowerShell.Injection.Generic",
                "process_function": self.process_detected_command_copy_to_startup
                },
            "schtasks": {
                "command": 'schtasks*/create*/xml*\\temp\\*.tmp',
                "virus_name": "HEUR:Win32.TaskScheduler.TempFile.Generic",
                "process_function": self.process_detected_command_schtasks_temp
            },
            "stopeventlog": {
                "command": 'sc.exe stop eventlog',
                "virus_name": "HEUR:Win32.StopEventLog.Generic",
                "process_function": self.process_detected_command_stop_eventlog
            },
            "koadic": {
                "patterns": [
                'chcp 437 & schtasks /query /tn k0adic',
                'chcp 437 & schtasks /create /tn k0adic'
                ],
                "virus_name": "HEUR:Win32.Rootkit.Koadic.Generic",
                "process_function": self.process_detected_command_rootkit_koadic
                },
            "fodhelper": {
                "command": [
                'reg add hkcu\\software\\classes\\ms-settings\\shell\\open\\command'
            ],
                "virus_name": "HEUR:Fodhelper.UAC.Bypass.Command",
                "process_function": self.process_detected_command_fodhelper
                },
            "antivirus": {
                "patterns": [
                    'findstr avastui.exe',
                    'findstr avgui.exe',
                    'findstr nswscsvc.exe',
                    'findstr sophoshealth.exe',
                    'findstr antivirus.exe'
                ],
                "virus_name": "HEUR:Antivirus.Process.Search.Command",
                "process_function": self.process_detected_command_antivirus_search
                }
            }

    def preprocess_text(self, text):
        return text.lower().replace(",", "").replace(".", "").replace("!", "").replace("?", "").replace("'", "")

    def capture_command_lines(self):
        command_lines = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline']:
                    cmdline_str = " ".join(proc.info['cmdline'])
                    executable_path = proc.exe()  # Capture the executable path
                    command_lines.append((cmdline_str, executable_path))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as ex:
                logging.error(f"Process error: {ex}")
            except Exception as ex:
                logging.error(f"Unexpected error while processing process {proc.info.get('pid')}: {ex}")
        return command_lines

    def contains_keywords_within_max_distance(self, text, max_distance):
        words = text.split()
        your_computer_positions = [i for i, word in enumerate(words) if word in {"your", "computer"}]
        files_positions = [i for i, word in enumerate(words) if word == "files"]
        encrypted_positions = [i for i, word in enumerate(words) if word == "encrypted"]

        for yp in your_computer_positions:
            for fp in files_positions:
                if 0 < fp - yp <= max_distance:
                    for ep in encrypted_positions:
                        if 0 < ep - fp <= max_distance:
                            return True
        return False

    def calculate_similarity_text(self, text1, text2):
        doc1 = nlp_spacy_lang(text1)
        doc2 = nlp_spacy_lang(text2)
        return doc1.similarity(doc2)

    def process_detected_text_classic(self, text, file_path):
        virus_name = self.known_malware_messages["classic"]["virus_name"]
        message = f"Detected potential anti-vm anti-debug malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_text_av(self, text, file_path):
        virus_name = self.known_malware_messages["av"]["virus_name"]
        message = f"Detected potential anti-AV malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_text_debugger(self, text, file_path):
        virus_name = self.known_malware_messages["debugger"]["virus_name"]
        message = f"Detected potential anti-debugger malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_text_fanmade(self, text, file_path):
        virus_name = self.known_malware_messages["fanmade"]["virus_name"]
        message = f"Detected potential fanmade malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_text_rogue(self, text, file_path):
        virus_name = self.known_malware_messages["rogue"]["virus_name"]
        message = f"Detected potential rogue security software: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_text_ransom(self, text, file_path):
        message = f"Potential ransomware detected in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_wifi(self, text, file_path):
        virus_name = self.known_malware_messages["wifi"]["virus_name"]
        message = f"Detected Wi-Fi credentials stealing malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_ransom_shadowcopy(self, text, file_path):
        virus_name = self.known_malware_messages["shadowcopy"]["virus_name"]
        message = f"Detected ransomware shadow copy deletion: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_wmic_shadowcopy(self, text, file_path):
        virus_name = self.known_malware_messages["wmic"]["virus_name"]
        message = f"Detected WMIC shadow copy deletion: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_copy_to_startup(self, text, file_path):
        virus_name = self.known_malware_messages["startup"]["virus_name"]
        message = f"Detected startup copy malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_schtasks_temp(self, text, file_path):
        virus_name = self.known_malware_messages["schtasks"]["virus_name"]
        message = f"Detected scheduled task creation using temp file: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_stop_eventlog(self, text, file_path):
        virus_name = self.known_malware_messages["stopeventlog"]["virus_name"]
        message = f"Detected Stop EventLog command execution: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_rootkit_koadic(self, text, file_path):
        virus_name = self.known_malware_messages["koadic"]["virus_name"]
        message = f"Detected rootkit behavior associated with Koadic: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_fodhelper(self, text, file_path):
        virus_name = self.known_malware_messages["fodhelper"]["virus_name"]
        message = f"Detected UAC bypass attempt using Fodhelper: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_antivirus_search(self, text, file_path):
        virus_name = self.known_malware_messages["antivirus"]["virus_name"]
        message = f"Detected search for antivirus processes: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_powershell_iex_download(self, text, file_path):
        virus_name = self.known_malware_messages["powershell_iex_download"]["virus_name"]
        message = f"Detected PowerShell IEX download command: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def process_detected_command_xmrig(self, text, file_path):
        virus_name = self.known_malware_messages["xmrig"]["virus_name"]
        message = f"Detected XMRig mining activity: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message)

    def detect_malware(self, file_path=None):
        if file_path is None:
            logging.error("file_path cannot be None.")
            return

        logging.info(f"Type of file_path received: {type(file_path).__name__}")
        if not isinstance(file_path, str):
            logging.error(f"Expected a string for file_path, but got {type(file_path).__name__}")
            return

        try:
            file_content = []
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as monitor_file:
                for line_number, line in enumerate(monitor_file):
                    if line_number < 1000000:  # Only read the first 1 million lines
                        file_content.append(line)
                    else:
                        logging.warning("Exceeded 1 million lines; stopping read.")
                        break

            file_content = ''.join(file_content)

            if not isinstance(file_content, str):
                logging.error("File content is not a valid string.")
                return

            # Process known malware messages
            for category, details in self.known_malware_messages.items():
                if "patterns" in details:
                    for pattern in details["patterns"]:
                        similarity = self.calculate_similarity_text(file_content, pattern)
                        if similarity > 0.8:
                            details["process_function"](file_content, file_path)
                            logging.info(f"Detected malware pattern in {file_path}.")
                            return
                elif "message" in details:
                    similarity = self.calculate_similarity_text(file_content, details["message"])
                    if similarity > 0.8:
                        details["process_function"](file_content, file_path)
                        logging.info(f"Detected malware message in {file_path}.")
                        return
                elif "command" in details:
                    similarity = self.calculate_similarity_text(file_content, details["command"])
                    if similarity > 0.8:
                        details["process_function"](file_content, file_path)
                        logging.info(f"Detected malware command in {file_path}.")
                        return

            # Adding ransomware check
            if self.contains_keywords_within_max_distance(file_content, max_distance=10):
                self.process_detected_text_ransom(file_content, file_path)
                logging.info(f"Detected ransomware keywords in {file_path}.")

            logging.info(f"Finished processing detection for {file_path}. No malware detected (detect_malware).")
            return False  # Indicate no malware detected

        except FileNotFoundError as ex:
            logging.error(f"File not found: {file_path}. Error: {ex}")
        except IsADirectoryError as ex:
            logging.error(f"Expected a file but got a directory: {file_path}. Error: {ex}")
        except Exception as ex:
            logging.error(f"Error handling file {file_path}: {ex}")

        return None  # Indicate an error occurred

    def get_unique_filename(self, base_name):
        """Generate a unique filename by appending a number if necessary."""
        counter = 1
        unique_name = os.path.join(commandlineandmessage_dir, f"{base_name}.txt")
        while os.path.exists(unique_name):
            unique_name = os.path.join(commandlineandmessage_dir, f"{base_name}_{counter}.txt")
            counter += 1
        return unique_name

    def monitoring_command_line_and_messages(self):
        try:
            while True:
                # Capture windows with text
                windows = find_windows_with_text()
                for hwnd, text in windows:
                    # Preprocess the text
                    preprocessed_text = self.preprocess_text(text)

                    # Generate unique file names for preprocessed and original text
                    preprocessed_file_path = self.get_unique_filename(f"preprocessed_{hwnd}")
                    original_file_path = self.get_unique_filename(f"original_{hwnd}")

                    # Write preprocessed text to a file if not empty
                    if preprocessed_text:
                        try:
                            with open(preprocessed_file_path, 'w', encoding="utf-8", errors="ignore") as pre_proc_file:
                                pre_proc_file.write(preprocessed_text[:1_000_000])
                            if os.path.getsize(preprocessed_file_path) == 0:
                                logging.error(f"Preprocessed file is empty: {preprocessed_file_path}.")
                            else:
                                logging.info(f"Wrote preprocessed text to {preprocessed_file_path}.")
                                scan_and_warn(preprocessed_file_path)
                        except Exception as ex:
                            logging.error(f"Error writing preprocessed text to {preprocessed_file_path}: {ex}")

                    # Write original text to a file if not empty
                    if text:
                        try:
                            with open(original_file_path, 'w', encoding="utf-8", errors="ignore") as original_text_file:
                                original_text_file.write(text[:1_000_000])
                            if os.path.getsize(original_file_path) == 0:
                                logging.error(f"Original file is empty: {original_file_path}.")
                            else:
                                logging.info(f"Wrote original text to {original_file_path}.")
                                scan_and_warn(original_file_path)
                        except Exception as ex:
                            logging.error(f"Error writing original text to {original_file_path}: {ex}")

                # Capture command lines
                command_lines = self.capture_command_lines()
                for command_line, executable_path in command_lines:
                    preprocessed_command_line = self.preprocess_text(command_line)

                    original_command_file_path = self.get_unique_filename(f"command_{executable_path}")
                    preprocessed_command_file_path = self.get_unique_filename(f"command_preprocessed_{executable_path}")

                    # Write original command line to a file if not empty
                    if command_line:
                        try:
                            with open(original_command_file_path, 'w', encoding="utf-8", errors="ignore") as original_file:
                                original_file.write(command_line[:1_000_000])
                            if os.path.getsize(original_command_file_path) == 0:
                                logging.error(f"Original command line file is empty: {original_command_file_path}.")
                            else:
                                logging.info(f"Wrote original command line to {original_command_file_path}.")
                                scan_and_warn(original_command_file_path)
                        except Exception as ex:
                            logging.error(f"Error writing original command line to {original_command_file_path}: {ex}")

                    # Write preprocessed command line to a file if not empty
                    if preprocessed_command_line:
                        try:
                            with open(preprocessed_command_file_path, 'w', encoding="utf-8", errors="ignore") as file:
                                file.write(preprocessed_command_line[:1_000_000])
                            if os.path.getsize(preprocessed_command_file_path) == 0:
                                logging.error(f"Preprocessed command line file is empty: {preprocessed_command_file_path}.")
                            else:
                                logging.info(f"Wrote preprocessed command line to {preprocessed_command_file_path}.")
                                scan_and_warn(preprocessed_command_file_path)
                        except Exception as ex:
                            logging.error(f"Error writing preprocessed command line to {preprocessed_command_file_path}: {ex}")

        except Exception as ex:
            logging.error(f"Error in monitor: {ex}")

def monitor_sandboxie_directory():
    """
    Monitor sandboxie folder for new or modified files and scan them.
    This includes functionality from both monitoring methods.
    """
    try:
        alerted_files = []

        while True:
            for directory in directories_to_scan:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            last_mod_time = os.path.getmtime(file_path)

                            if file_path not in alerted_files:
                                logging.info(f"New file detected in {root}: {file}")
                                print(f"New file detected in {root}: {file}")
                                alerted_files.append(file_path)
                                scan_and_warn(file_path)

                            if file_path not in scanned_files:
                                # New file detected
                                scanned_files.append(file_path)
                                file_mod_times[file_path] = last_mod_time
                            elif file_mod_times[file_path] != last_mod_time:
                                # File modified
                                logging.info(f"File modified in {root}: {file}")
                                print(f"File modified in {root}: {file}")
                                scan_and_warn(file_path)
                                file_mod_times[file_path] = last_mod_time

    except Exception as ex:
        logging.error(f"Error in monitor_sandboxie_directory: {ex}")

def perform_sandbox_analysis(file_path):
    global main_file_path
    global monitor_message
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

        monitor_message = MonitorMessageCommandLine()

        # Monitor Snort log for new lines and process alerts
        threading.Thread(target=monitor_snort_log).start()
        threading.Thread(target=web_protection_observer.begin_observing).start()

        # Start other sandbox analysis tasks in separate threads
        threading.Thread(target=observer.start).start()
        threading.Thread(target=scan_and_warn, args=(file_path,)).start()
        threading.Thread(target=start_monitoring_sandbox).start()
        threading.Thread(target=monitor_sandboxie_directory).start()
        threading.Thread(target=check_startup_directories).start()
        threading.Thread(target=monitor_hosts_file).start()
        threading.Thread(target=check_uefi_directories).start() # Start monitoring UEFI directories for malicious files in a separate thread
        threading.Thread(target=monitor_message.monitoring_command_line_and_messages).start() # Function to monitor specific windows in a separate thread
        threading.Thread(target=run_sandboxie_control).start()
        threading.Thread(target=run_sandboxie, args=(file_path,)).start()

        logging.info("Sandbox analysis started. Please check log after you close program. There is no limit to scan time.")

    except Exception as ex:
        logging.error(f"An error occurred during sandbox analysis: {ex}")

class AnalysisThread(QThread):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def execute_analysis(self):
        try:
            print(f"Running analysis for: {self.file_path}")  
            logging.info(f"Running analysis for: {self.file_path}")
            perform_sandbox_analysis(self.file_path)
        except Exception as ex:
            error_message = f"An error occurred during sandbox analysis: {ex}"
            logging.error(error_message)
            print(error_message)

def run_sandboxie(file_path):
    try:
        subprocess.run([sandboxie_path, '/box:DefaultBox', file_path], check=True)
    except subprocess.CalledProcessError as ex:
        logging.error(f"Failed to run Sandboxie on {file_path}: {ex}")

def main():
    try:
        app = QApplication(sys.argv)
        app.setStyleSheet(antivirus_style)  # Apply the style sheet
        main_gui = AntivirusUI()
        main_gui.show()
        sys.exit(app.exec())
    except Exception as ex:
        print(f"An error occurred: {ex}")

if __name__ == "__main__":
    main()