import sys
import os
import shutil
import subprocess
import threading
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import win32file
import win32con
from datetime import datetime, timedelta
import winreg
from scapy.all import IP, IPv6, DNS, DNSQR, DNSRR, TCP, UDP, sniff
import ctypes
import ipaddress
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import io
import spacy
import codecs
import csv
from elftools.elf.elffile import ELFFile
import struct
import zlib
import marshal
import base64
from base32_crockford import base32_crockford
import binascii

sys.modules['sklearn.externals.joblib'] = joblib

# Set the default encoding to UTF-8 for standard output and input
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')
sys.stdin = io.TextIOWrapper(sys.stdin.detach(), encoding='utf-8')

# Load the spaCy model globally
nlp_spacy_lang = spacy.load("en_core_web_md")

# Set script directory
script_dir = os.getcwd()

# Define the paths to the ghidra related directories
decompile_dir = os.path.join(script_dir, "decompile")
pyinstaller_dir = os.path.join(script_dir, "pyinstaller")
ghidra_projects_dir = os.path.join(script_dir, "ghidra_projects")
ghidra_logs_dir = os.path.join(script_dir, "ghidra_logs")
ghidra_scripts_dir = os.path.join(script_dir, "scripts")
dotnet_dir = os.path.join(script_dir, "dotnet")
base_dir = os.path.join(script_dir, "base32and64")
nuitka_dir = os.path.join(script_dir, "nuitka")
pyintstaller_dir = os.path.join(script_dir, "pyinstaller")
commandlineandmessage_dir = os.path.join(script_dir, "commandlineandmessage")
pe_extracted_dir = os.path.join(script_dir, "pe_extracted")
zip_extracted_dir = os.path.join(script_dir, "zip_extracted")
tar_extracted_dir = os.path.join(script_dir, "tar_extracted")
processed_dir = os.path.join(script_dir, "processed")
detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
ilspycmd_path = os.path.join(script_dir, "ilspycmd.exe")
extractor_path = os.path.join(script_dir, "nuitka-extractor.exe")
malicious_file_names = os.path.join(script_dir, "machinelearning", "malicious_file_names.json")
malicious_numeric_features = os.path.join(script_dir, "machinelearning", "malicious_numeric.pkl")
benign_numeric_features = os.path.join(script_dir, "machinelearning", "benign_numeric.pkl")
yara_folder_path = os.path.join(script_dir, "yara")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")
ip_addresses_path = os.path.join(script_dir, "website", "IP_Addresses.txt")
ipv6_addresses_path = os.path.join(script_dir, "website", "ipv6.txt")
ipv4_whitelist_path = os.path.join(script_dir, "website", "ipv4whitelist.txt")
domains_path = os.path.join(script_dir, "website", "Domains.txt")
urlhaus_path = os.path.join(script_dir, "website", "urlhaus.txt")
antivirus_list_path = os.path.join(script_dir, "hosts", "antivirus_list.txt")
antivirus_domains_data = {}
ip_addresses_signatures_data = {}
ipv4_whitelist_data = {}
ipv6_addresses_signatures_data = {}
domains_signatures_data = {}
urlhaus_data = {}

clamd_dir = r"C:\Program Files\ClamAV\clamd.exe"
clamdscan_path = r"C:\Program Files\ClamAV\clamdscan.exe"
freshclam_path = r"C:\Program Files\ClamAV\freshclam.exe"

# Ensure base64 and base32 directories exist
os.makedirs(base_dir, exist_ok=True)

os.makedirs(commandlineandmessage_dir, exist_ok=True)
os.makedirs(processed_dir, exist_ok=True)
os.makedirs(pe_extracted_dir, exist_ok=True)
os.makedirs(zip_extracted_dir, exist_ok=True)
os.makedirs(tar_extracted_dir, exist_ok=True)

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

fileTypes = ['.pyd', '.elf', '.ps1', '.bas', '.bat', '.chm', '.cmd', '.com', '.cpl', '.dll', '.exe', '.msc', '.ocx', '.pcd', '.pif', '.reg', '.scr', '.sct', '.url', '.vbe', '.wsc', '.wsf', '.wsh', '.ct', '.t', '.input', '.war', '.jspx', '.tmp', '.dump', '.pwd', '.w', '.cfg', '.psd1', '.psm1', '.ps1xml', '.clixml', '.psc1', '.pssc', '.www', '.rdp', '.msi', '.dat', '.contact', '.settings', '.odt', '.jpg', '.mka','shtml', '.mhtml', '.oqy', '.png', '.csv', '.py', '.sql', '.mdb', '.html', '.htm', '.xml', '.psd', '.pdf', '.xla', '.cub', '.dae', '.indd', '.cs', '.mp3', '.mp4', '.dwg', '.rar', '.mov', '.rtf', '.bmp', '.mkv', '.avi', '.apk', '.lnk', '.dib', '.dic', '.dif', '.divx', '.iso', '.7zip', '.ace', '.arj', '.bz2', '.cab', '.gzip', '.lzh', '.jpeg', '.xz', '.mpeg', '.torrent', '.mpg', '.core', '.pdb', '.ico', '.pas', '.db', '.wmv', '.swf', '.cer', '.bak', '.backup', '.accdb', '.bay', '.p7c', '.exif', '.vss', '.raw', '.m4a', '.wma', '.flv', '.sie', '.sum', '.ibank', '.wallet', '.css', '.js', '.rb', '.xlsm', '.xlsb', '.7z', '.cpp', '.java', '.jpe', '.ini', '.blob', '.wps', '.wav', '.3gp', '.webm', '.m4v', '.amv', '.m4p', '.svg', '.ods', '.bk', '.vdi', '.vmdk', '.accde', '.json', '.gif', '.gz', '.m1v', '.sln', '.pst', '.obj', '.xlam', '.djvu', '.inc', '.cvs', '.dbf', '.tbi', '.wpd', '.dot', '.dotx', '.xltx', '.pptm', '.potx', '.potm', '.xlw', '.xps', '.xsd', '.xsf', '.xsl', '.kmz', '.accdr', '.stm', '.accdt', '.ppam', '.pps', '.ppsm', '.1cd', '.3ds', '.3fr', '.3g2', '.accda', '.accdc', '.accdw', '.adp', '.ai', '.ai3', '.ai4', '.ai5', '.ai6', '.ai7', '.ai8', '.arw', '.ascx', '.asm', '.asmx', '.avs', '.bin', '.cfm', '.dbx', '.dcm', '.dcr', '.pict', '.rgbe', '.dwt', '.f4v', '.exr', '.kwm', '.max', '.mda', '.mde', '.mdf', '.mdw', '.mht', '.mpv', '.msg', '.myi', '.nef', '.odc', '.geo', '.swift', '.odm', '.odp', '.oft', '.orf', '.pfx', '.p12', '.pls', '.safe', '.tab', '.vbs', '.xlk', '.xlm', '.xlt', '.xltm', '.svgz', '.slk', '.dmg', '.ps', '.psb', '.tif', '.rss', '.key', '.vob', '.epsp', '.dc3', '.iff', '.onepkg', '.onetoc2', '.opt', '.p7b', '.pam', '.r3d', '.pkg', '.yml', '.old', '.thmx', '.keytab', '.h', '.php', '.c', '.zip', '.log', '.log1', '.log2', '.tm', '.blf', '.uic', '.widget-plugin', '.regtrans-ms', '.efi', '.rule', '.rules', '.yar', '.yara', '.yrc', '.inf', '.ini', '.ndb', '.cvd', '.cld', '.ign2', '.dmp', '.conf' '.config', '.pyc']

magic_bytes = {
    "23 21": "sh",
    "02 00 5A 57 52 54": "cwk",
    "00 00 02 00 06 04 06 00": "wk1",
    "00 00 1A 00 00 10 04 00": "wk3",
    "00 00 1A 00 02 10 04 00": "wk4",
    "00 00 1A 00 05 10 04": "123",
    "00 00 03 F3": "amiga",
    "00 00 49 49 58 50 52": "qxd",
    "50 57 53 33": "psafe3",
    "D4 C3 B2 A1": "pcap",
    "4D 3C B2 A1": "pcap",
    "0A 0D 0D 0A": "pcapng",
    "ED AB EE DB": "rpm",
    "53 51 4C 69 74 65 20 66": "sqlite",
    "53 50 30 31": "bin",
    "49 57 41 44": "wad",
    "00": "pic",
    "BE BA FE CA": "dba",
    "00 01 42 44": "dba",
    "00 01 44 54": "tda",
    "54 44 46 24": "tdf",
    "54 44 45 46": "tdef",
    "00 01 00 00": "palm",
    "00 00 01 00": "ico",
    "69 63 6E 73": "icns",
    "66 74 79 70 33 67": "3gp",
    "66 74 79 70 68 65 69 63": "heic",
    "1F 9D": "z",
    "1F A0": "z",
    "2D 68 6C 30 2D": "lzh",
    "42 41 43 4B 4D 49 4B 45": "bac",
    "49 4E 44 58": "idx",
    "62 70 6C 69 73 74": "plist",
    "42 5A 68": "bz2",
    "47 49 46 38 37 61": "gif",
    "47 49 46 38 39 61": "gif",
    "49 49 2A 00": "tif",
    "4D 4D 00 2A": "tif",
    "49 49 2A 00 10 00 00 00": "cr2",
    "80 2A 5F D7": "cin",
    "52 4E 43 01": "rnc",
    "4E 55 52 55 49 4D 47": "nui",
    "53 44 50 58": "dpx",
    "76 2F 31 01": "exr",
    "42 50 47 FB": "bpg",
    "FF D8 FF DB": "jpg",
    "FF D8 FF E0 00 10 4A 46": "jpg",
    "FF D8 FF EE": "jpg",
    "FF D8 FF E1": "jpg",
    "00 00 00 0C 6A 50 20 20": "jp2",
    "FF 4F FF 51": "jp2",
    "71 6F 69 66": "qoi",
    "46 4F 52 4D": "ilbm",
    "4C 5A 49 50": "lz",
    "30 37 30 37 30 37": "cpio",
    "4D 5A": "exe",
    "53 4D 53 4E 46 32 30 30": "ssp",
    "5A 4D": "exe",
    "50 4B 03 04": "zip",
    "52 61 72 21 1A 07 00": "rar",
    "52 61 72 21 1A 07 01 00": "rar",
    "7F 45 4C 46": "elf",
    "89 50 4E 47 0D 0A 1A 0A": "png",
    "0E 03 13 01": "hdf4",
    "89 48 44 46 0D 0A 1A 0A": "hdf5",
    "C9": "com",
    "CA FE BA BE": "class",
    "EF BB BF": "txt",
    "FF FE": "txt",
    "FE FF": "txt",
    "FF FE 00 00": "txt",
    "00 00 FE FF": "txt",
    "2B 2F 76 38": "txt",
    "0E FE FF": "txt",
    "DD 73 66 73": "txt",
    "FE ED FA CE": "macho",
    "FE ED FA CF": "macho",
    "FE ED FE ED": "jks",
    "CE FA ED FE": "macho",
    "CF FA ED FE": "macho",
    "25 21 50 53": "ps",
    "25 50 44 46 2D": "pdf",
    "30 26 B2 75 8E 66 CF 11": "asf",
    "24 53 44 49 30 30 30 31": "sdi",
    "4F 67 67 53": "ogg",
    "38 42 50 53": "psd",
    "52 49 46 46": "avi",
    "FF FB": "mp3",
    "49 44 33": "mp3",
    "42 4D": "bmp",
    "43 44 30 30 31": "iso",
    "4C 00 00 00 01 14 02 00": "lnk",
    "62 6F 6F 6B 00 00 00 00": "alias",
    "75 73 74 61 72 00 30 30": "tar",
    "4D 53 43 46": "cab",
    "4B 44 4D": "vmdk",
    "43 72 32 34": "crx",
    "41 47 44 33": "fh8",
    "05 07 00 00 42 4F 42 4F": "cwk",
    "00 00 00 14 66 74 79 70": "mov",
    "4D 54 68 64": "mid",
    "4D 41 52 31 00": "mar",
    "4E 45 53 1A": "nes",
    "75 73 74 61 72": "tar",
}

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

def is_hex_data(data):
    """Check if the given binary data can be valid hex-encoded data."""
    try:
        # Convert binary data to hex representation and back to binary
        binascii.unhexlify(binascii.hexlify(data))
        return True
    except (TypeError, binascii.Error):
        return False

def remove_magic_bytes(data):
    """Remove magic bytes from data, considering it might be hex-encoded."""
    if is_hex_data(data):
        # Convert binary data to hex representation for easier pattern removal
        hex_data = binascii.hexlify(data).decode('utf-8')

        # Remove magic bytes by applying regex patterns
        for magic_byte in magic_bytes.keys():
            pattern = re.compile(rf'{magic_bytes[magic_byte].replace(" ", "")}', re.IGNORECASE)
            hex_data = pattern.sub('', hex_data)

        # Convert hex data back to binary
        return binascii.unhexlify(hex_data)
    else:
        # If data is not hex-encoded, process it directly
        hex_data = binascii.hexlify(data).decode('utf-8')
        for magic_byte in magic_bytes.keys():
            pattern = re.compile(rf'{magic_bytes[magic_byte].replace(" ", "")}', re.IGNORECASE)
            hex_data = pattern.sub('', hex_data)
        return binascii.unhexlify(hex_data)

def decode_base64(data):
    """Decode base64-encoded data."""
    try:
        return base64.b64decode(data)
    except (binascii.Error, ValueError):
        return None

def decode_base32(data):
    """Decode base32-encoded data."""
    try:
        return base32_crockford.decode(data)
    except (binascii.Error, ValueError):
        return None

def process_file_data(file_path):
    """Process file data by decoding and removing magic bytes."""
    with open(file_path, 'rb') as file:
        data = file.read()

    original_data = data
    # Initial processing of the data
    while True:
        # Try to decode base64 and base32 repeatedly until no more decoding is possible
        base64_decoded = decode_base64(data)
        if base64_decoded is not None:
            data = base64_decoded
            continue

        base32_decoded = decode_base32(data)
        if base32_decoded is not None:
            data = base32_decoded
            continue

        # No more base64 or base32 encoded data
        break

    # Process the data to handle possible mixed content
    processed_data = remove_magic_bytes(data)

    # Save processed data
    output_file_path = os.path.join(processed_dir, 'processed_' + os.path.basename(file_path))
    with open(output_file_path, 'wb') as processed_file:
        processed_file.write(processed_data)
    logging.info(f"Processed data from {file_path} saved to {output_file_path}")

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

def notify_user(file_path, virus_name):
    notification = Notify()
    notification.title = "Malware Alert"
    notification.message = f"Malicious file detected: {file_path}\nVirus: {virus_name}"
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
    notification.message = (f"Filename in {archive_type} file {file_path} contains RLO character after a comma. "
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

def notify_user_pua(file_path, virus_name):
    notification = Notify()
    notification.title = "PUA Alert"
    notification.message = f"PUA file detected: {file_path}\nVirus: {virus_name}"
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
    notification.message = message
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

def notify_user_for_web(domain=None, ip_address=None, url=None, file_path=None):
    notification = Notify()
    notification.title = "Malware or Phishing Alert"
    
    # Build the notification message dynamically
    message_parts = []
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
    global anntivirus_domains_data
    try:
        with open(antivirus_list_path, 'r') as antivirus_file:
            antivirus_domains_data = antivirus_file.read().splitlines()
        return antivirus_domains_data
    except Exception as e:
        logging.error(f"Error loading Antivirus domains: {e}")
        return []

def load_data():
    global ip_addresses_signatures_data, ipv6_addresses_signatures_data, domains_signatures_data, ipv4_whitelist_data, urlhaus_data
    
    try:
        # Load IPv4 addresses
        with open(ip_addresses_path, 'r') as ip_file:
            ip_addresses_signatures_data = ip_file.read().splitlines()
        print("IPv4 Addresses loaded successfully!")
    except Exception as e:
        print(f"Error loading IPv4 Addresses: {e}")

    try:
        # Load IPv6 addresses
        with open(ipv6_addresses_path, 'r') as ipv6_file:
            ipv6_addresses_signatures_data = ipv6_file.read().splitlines()
        print("IPv6 Addresses loaded successfully!")
    except Exception as e:
        print(f"Error loading IPv6 Addresses: {e}")

    try:
        # Load domains
        with open(domains_path, 'r') as domains_file:
            domains_signatures_data = domains_file.read().splitlines()
        print("Domains loaded successfully!")
    except Exception as e:
        print(f"Error loading Domains: {e}")

    try:
        # Load IPv4 whitelist
        with open(ipv4_whitelist_path, 'r') as whitelist_file:
            ipv4_whitelist_data = whitelist_file.read().splitlines()
        print("IPv4 Whitelist loaded successfully!")
    except Exception as e:
        print(f"Error loading IPv4 Whitelist: {e}")

    try:
        # Load URLhaus data
        urlhaus_data = []
        with open(urlhaus_path, 'r') as urlhaus_file:
            reader = csv.DictReader(urlhaus_file)
            for row in reader:
                urlhaus_data.append(row)
        print("URLhaus data loaded successfully!")
    except Exception as e:
        print(f"Error loading URLhaus data: {e}")

    print("Domain, IPv4, IPv6, Whitelist, and URLhaus signatures loaded successfully!")

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
 
def restart_clamd_thread():
    threading.Thread(target=restart_clamd).start()

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
    except Exception as e:
        logging.error(f"An error occurred while restarting ClamAV: {str(e)}")
        print(f"An error occurred while restarting ClamAV: {str(e)}")
        return False

def scan_file_with_clamd(file_path):
    """Scan file using clamd."""
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

def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# Regular expressions for matching IP addresses, IPv6 addresses, domains, and URLs
ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
ipv6_regex = re.compile(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b')
domain_regex = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
url_regex = re.compile(r'\b(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b')

class RealTimeWebProtectionHandler:
    def __init__(self):
        self.scanned_domains = []
        self.scanned_ipv4_addresses = []
        self.scanned_ipv6_addresses = []
        self.scanned_urls = []
        self.domain_ip_to_file_map = {}

    def is_related_to_critical_paths(self, file_path):
        # Check if file path starts with the sandboxie folder or matches the main file path
        return file_path.startswith(sandboxie_folder) or file_path == main_file_path

    def map_domain_ip_to_file(self, entity):
        return self.domain_ip_to_file_map.get(entity)

    def handle_detection(self, entity_type, entity_value):
        file_path = self.map_domain_ip_to_file(entity_value)
        notify_info = {'domain': None, 'ip_address': None, 'url': None, 'file_path': None}

        if file_path and self.is_related_to_critical_paths(file_path):
            message = f"{entity_type.capitalize()} {entity_value} is related to a critical path: {file_path}"
            logging.warning(message)
            print(message)
            notify_info[entity_type] = entity_value
            notify_info['file_path'] = file_path  # Add file_path to notification info
        else:
            if file_path:
                message = f"{entity_type.capitalize()} {entity_value} is not related to critical paths but associated with file path: {file_path}"
            else:
                message = f"{entity_type.capitalize()} {entity_value} is not related to critical paths and has no associated file path."
            logging.info(message)
            print(message)
        
        if any(notify_info.values()):
            notify_user_for_web(**notify_info)

    def scan_domain(self, domain):
        if domain in self.scanned_domains:
            return
        self.scanned_domains.append(domain)
        message = f"Scanning domain: {domain}"
        logging.info(message)
        print(message)

        if domain.lower() == 'www.com':
            self.handle_detection('domain', domain)
            return

        if domain.lower().startswith("www.") and not domain.lower().endswith(".com"):
            domain = domain[4:]

        parts = domain.split(".")
        main_domain = domain if len(parts) < 3 else ".".join(parts[-2:])

        for parent_domain in domains_signatures_data:
            if main_domain == parent_domain or main_domain.endswith(f".{parent_domain}"):
                self.handle_detection('domain', main_domain)
                return

    def scan_ip_address(self, ip_address):
        if ip_address in self.scanned_ipv6_addresses or ip_address in self.scanned_ipv4_addresses:
            return

        if ':' in ip_address:  # IPv6 address
            self.scanned_ipv6_addresses.append(ip_address)
            message = f"Scanning IPv6 address: {ip_address}"
            logging.info(message)
            print(message)
            self.handle_detection('ip_address', ip_address)
        else:  # IPv4 address
            self.scanned_ipv4_addresses.append(ip_address)
            message = f"Scanning IPv4 address: {ip_address}"
            logging.info(message)
            print(message)
            if is_local_ip(ip_address):
                message = f"Skipping local IP address: {ip_address}"
                logging.info(message)
                print(message)
                return
            self.handle_detection('ip_address', ip_address)

    def scan_url(self, url):
        if url in self.scanned_urls:
            return
        self.scanned_urls.append(url)
        for entry in urlhaus_data:
            if entry['url'] in url:
                message = f"URL {url} matches the URLhaus signatures."
                logging.warning(message)
                print(message)

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
                    self.scan_ip_address(packet[IP].src)
                    self.scan_ip_address(packet[IP].dst)

    def handle_ipv6(self, packet):
        if DNS in packet:
            if packet[DNS].qd:
                for i in range(packet[DNS].qdcount()):
                    query_name = packet[DNSQR][i].qname.decode().rstrip('.')
                    self.scan_domain(query_name)
                    message = f"DNS Query (IPv6): {query_name}"
                    logging.info(message)
                    print(message)
            if packet[DNS].an:
                for i in range(packet[DNS].ancount()):
                    answer_name = packet[DNSRR][i].rrname.decode().rstrip('.')
                    self.scan_domain(answer_name)
                    message = f"DNS Answer (IPv6): {answer_name}"
                    logging.info(message)
                    print(message)
                    self.scan_ip_address(packet[IPv6].src)
                    self.scan_ip_address(packet[IPv6].dst)

    def on_packet_received(self, packet):
        if IP in packet:
            self.handle_ipv4(packet)
        elif IPv6 in packet:
            self.handle_ipv6(packet)
        elif DNS in packet:
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
                    if TCP in packet or UDP in packet:
                        url = f"{packet[IP].src}:{packet[IP].dport}"
                        self.scan_url(url)

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
        sniff(filter=filter_expression, prn=self.handler.on_packet_received, store=0)

web_protection_observer = RealTimeWebProtectionObserver()

class YaraScanner:
    def scan_data(self, file_path):
        matched_rules = []

        if not os.path.exists(file_path):
            logging.error(f"File not found during YARA scan: {file_path}")
            return None

        with open(file_path, 'rb') as file:
            data = file.read()

            # Check matches for compiled_rule
            if compiled_rule:
                matches = compiled_rule.match(data=data)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded.")
            else:
                logging.warning("compiled_rule is not defined.")

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
            else:
                logging.warning("yaraxtr_rule is not defined.")

        # Return matched rules as the yara_result if not empty, otherwise return None
        return matched_rules if matched_rules else None

yara_scanner = YaraScanner()

# Function to check the signature of a file
def check_signature(file_path):
    try:
        # Command to verify the executable signature status
        cmd = f'"{file_path}"'
        verify_command = "(Get-AuthenticodeSignature " + cmd + ").Status"
        process = subprocess.run(['powershell.exe', '-Command', verify_command], stdout=subprocess.PIPE, text=True)

        status = process.stdout.strip()
        is_valid = "Valid" in status
        signature_status_issues = "HashMismatch" in status or "NotTrusted" in status

        # Command to check for Microsoft signature if there are no issues
        if not signature_status_issues:
            ms_command = f"Get-AuthenticodeSignature '{file_path}' | Format-List"
            ms_result = subprocess.run(["powershell.exe", "-Command", ms_command], capture_output=True, text=True)
            has_microsoft_signature = "O=Microsoft Corporation" in ms_result.stdout
        else:
            has_microsoft_signature = False

        return {
            "is_valid": is_valid,
            "has_microsoft_signature": has_microsoft_signature,
            "signature_status_issues": signature_status_issues
        }
    except Exception as e:
        print(f"An error occurred while checking signature: {e}")
        logging.error(f"An error occurred while checking signature: {e}")
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
    except Exception as e:
        print(f"An error occurred while verifying a valid signature: {e}")
        logging.error(f"An error occurred while verifying a valid signature: {e}")
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

    except Exception as e:
        logging.error(f"An error occurred while cleaning the directories: {e}")

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

def is_encrypted(zip_info):
    """Check if a ZIP entry is encrypted."""
    return zip_info.flag_bits & 0x1 != 0

def contains_rlo_after_comma(filename):
    """Check if the filename contains an RLO character after a comma."""
    return ",\u202E" in filename

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
                                        
                                        # Save data to file in the extracted directory
                                        extracted_file_path = os.path.join(pe_extracted_dir, "pe_extracted_data.bin")
                                        with open(extracted_file_path, 'wb') as temp_file:
                                            temp_file.write(data)
        
        return True, virus_names
    except Exception as e:
        logging.error(f"Error scanning exe file: {file_path} - {str(e)}")
        return False, ""

def scan_zip_file(file_path):
    """Scan files within a zip archive."""
    try:
        zip_size = os.path.getsize(file_path)

        with zipfile.ZipFile(file_path, 'r') as zfile:
            for zip_info in zfile.infolist():

                # Check for RLO in filenames before handling encryption
                if contains_rlo_after_comma(zip_info.filename):
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
    except Exception as e:
        logging.error(f"Error scanning zip file: {file_path} - {str(e)}")
        return False, ""

def scan_tar_file(file_path):
    """Scan files within a tar archive."""
    try:
        tar_size = os.path.getsize(file_path)

        with tarfile.open(file_path, 'r') as tar:
            for member in tar.getmembers():
                # Check for RLO in filenames
                if contains_rlo_after_comma(member.name):
                    logging.warning(
                        f"Filename {member.name} in {file_path} contains RLO character after a comma - "
                        "flagged as HEUR:RLO.Suspicious.Name.Encrypted.TAR.Generic"
                    )
                    notify_rlo_warning(file_path, "TAR", virus_name)

                if member.isreg():  # Check if it's a regular file
                    extracted_file_path = os.path.join(tar_extracted_dir, member.name)
                    tar.extract(member, tar_extracted_dir)

                    # Check for suspicious conditions: large files in small TAR archives
                    extracted_file_size = os.path.getsize(extracted_file_path)
                    if tar_size < 20 * 1024 * 1024 and extracted_file_size > 650 * 1024 * 1024:
                        logging.warning(
                            f"TAR file {file_path} is smaller than 20MB but contains a large file: {member.name} "
                            f"({extracted_file_size / (1024 * 1024)} MB) - flagged as HEUR:Win32.Suspicious.Size.Encrypted.TAR. "
                            "Potential TARbomb or Fake Size detected to avoid VirusTotal detections."
                        )
                        notify_size_warning(file_path, "TAR", virus_name)

        return True, []
    except Exception as e:
        logging.error(f"Error scanning tar file: {file_path} - {str(e)}")
        return False, ""

def scan_file_real_time(file_path, signature_check, pe_file=False):
    """Scan file in real-time using multiple engines."""
    logging.info(f"Started scanning file: {file_path}")

    try:
        # Scan PE files with Static Machine Learning
        if pe_file:
            is_malicious, malware_definition, benign_score = scan_file_with_machine_learning_ai(file_path)
            if is_malicious:
                if benign_score < 0.93:
                    if signature_check["is_valid"]:
                        malware_definition = "SIG." + malware_definition
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
                if signature_check["is_valid"]:
                    result = "SIG." + result
                logging.warning(f"Infected file detected (ClamAV): {file_path} - Virus: {result}")
                return True, result
            logging.info(f"No malware detected by ClamAV in file: {file_path}")
        except Exception as e:
            logging.error(f"An error occurred while scanning file with ClamAV: {file_path}. Error: {str(e)}")

        # Scan with YARA
        try:
            yara_result = yara_scanner.scan_data(file_path)
            if yara_result is not None and yara_result not in ("Clean", ""):
                if signature_check["is_valid"]:
                    yara_result = "SIG." + yara_result
                logging.warning(f"Infected file detected (YARA): {file_path} - Virus: {yara_result}")
                return True, yara_result
            logging.info(f"Scanned file with YARA: {file_path} - No viruses detected")
            return False, None
        except Exception as e:
            logging.error(f"An error occurred while scanning file with YARA: {file_path}. Error: {e}")
            return False, None

        # Scan PE files
        if pe_file:
            try:
                scan_result, virus_name = scan_pe_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    if signature_check["is_valid"]:
                        virus_name = "SIG." + virus_name
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
                    if signature_check["is_valid"]:
                        virus_name = "SIG." + virus_name
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
                    if signature_check["is_valid"]:
                        virus_name = "SIG." + virus_name
                    logging.warning(f"Infected file detected (ZIP): {file_path} - Virus: {virus_name}")
                    return True, virus_name
                logging.info(f"No malware detected in ZIP file: {file_path}")
            except PermissionError:
                logging.error(f"Permission error occurred while scanning ZIP file: {file_path}")
            except FileNotFoundError:
                logging.error(f"ZIP file not found error occurred while scanning ZIP file: {file_path}")
            except Exception as e:
                logging.error(f"An error occurred while scanning ZIP file: {file_path}. Error: {str(e)}")

    except Exception as e:
        logging.error(f"An error occurred while scanning file: {file_path}. Error: {str(e)}")

    return False, "Clean"

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
        self.analysis_thread.execute_analysis()

    def show_success_message(self):
        QMessageBox.information(self, "Update Definitions", "AntiVirus definitions updated successfully and ClamAV has been restarted.")

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
                return

        # If neither daily.cvd nor daily.cld exists, run freshclam
        if not file_found:
            print("Neither daily.cvd nor daily.cld files exist. Running freshclam.")
            result = subprocess.run([freshclam_path], capture_output=True, text=True)
            if result.returncode == 0:
                restart_clamd_thread()
                self.signals.success.emit()
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
sbie_ini_path = r"C:\Program Files\Sandboxie\SbieIni.exe"
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
snort_command = [r'C:\Snort\bin\snort.exe'] + device_args + ["-c", snort_config_path, "-A", "fast"]

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
    This function will only warn the user and simulate the detection of files.
    """
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            connections = proc.connections()
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
                            if not signature_info["is_valid"]:
                                logging.warning(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip} has invalid or no signature. Alert Line: {alert_line}")
                                print(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip} has invalid or no signature. Alert Line: {alert_line}")
                                notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status)
                            else:
                                logging.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature and is not flagged as malicious. Alert Line: {alert_line}")
                                print(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature and is not flagged as malicious. Alert Line: {alert_line}")

        except psutil.NoSuchProcess:
            logging.error(f"Process no longer exists: {proc.info.get('pid')}")
        except psutil.AccessDenied:
            logging.error(f"Access denied to process: {proc.info.get('pid')}")
        except psutil.ZombieProcess:
            logging.error(f"Zombie process encountered: {proc.info.get('pid')}")
        except Exception as e:
            logging.error(f"Unexpected error while processing process {proc.info.get('pid')}: {e}")

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
                    except Exception as e:
                        logging.error(f"Error notifying user for HIPS (malicious): {e}")
                    convert_ip_to_file(src_ip, dst_ip, line.strip(), "Malicious")
                    return True
                elif priority == 2:
                    convert_ip_to_file(src_ip, dst_ip, line.strip(), "Suspicious")
                    return True
            except Exception as e:
                logging.error(f"Error processing alert details: {e}")
                print(f"Error processing alert details: {e}")
    except Exception as e:
        logging.error(f"Error matching alert regex: {e}")
        print(f"Error matching alert regex: {e}")

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

threading.Thread(target=run_snort).start()
restart_clamd_thread()
clean_directories()
activate_uefi_drive() # Call the UEFI function
load_data()
load_antivirus_list()
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

yaraxtr_yrc_path = os.path.join(yara_folder_path, "yaraxtr.yrc")

try:
    # Load the precompiled rule from the .yrc file using yara_x
    with open(yaraxtr_yrc_path, 'rb') as f:
        yaraxtr_rule = yara_x.Rules.deserialize_from(f)
    print("YARA-X Rules Definitions loaded!")
except Exception as e:
    print(f"Error loading YARA-X rules: {e}")

# List to keep track of existing project names
existing_projects = []

def get_next_project_name(base_name):
    """Generate the next available project name with an incremental suffix."""
    try:
        suffix = 1
        while f"{base_name}_{suffix}" in existing_projects:
            suffix += 1
        return f"{base_name}_{suffix}"
    except Exception as e:
        logging.error(f"An error occurred while generating project name: {e}")

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
        except Exception as e:
            logging.error(f"Failed to generate project name: {e}")
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
    except Exception as e:
        logging.error(f"An error occurred during decompilation: {e}")

def extract_original_file_path_from_decompiled(file_path):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.startswith("// Original file:"):
                    parts = line.split(':', 2)
                    # Construct the path without using an rf-string
                    drive_letter = parts[1].upper() + ":"
                    path = parts[2].replace('/', '\\')
                    original_file_path = f"{drive_letter}\\{path}"
                    return original_file_path.strip()
        return None
    except Exception as e:
        print(f"An error occurred while extracting the original file path: {e}")
        return None

def ensure_unique_folder(base_folder):
    """Create a uniquely named folder by appending a number if necessary."""
    folder = base_folder
    counter = 1
    while os.path.exists(folder):
        folder = f"{base_folder}_{counter}"
        counter += 1
    os.makedirs(folder)
    return folder

def is_nuitka_file(file_path):
    """Check if the file is a Nuitka executable using Detect It Easy."""
    try:
        # Run the DIE console command to analyze the file
        result = subprocess.run([detectiteasy_console_path, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if the output indicates the file is a Nuitka-compiled executable
        if "Nuitka" in result.stdout:
            return True
        
    except subprocess.SubprocessError as e:
        logging.error(f"Error running Detect It Easy for {file_path}: {e}")
        return False
    
    return False

def extract_nuitka_file(file_path):
    """Extract Nuitka file content into uniquely named folders."""
    try:
        # Check if the file is a Nuitka executable
        if is_nuitka_file(file_path):
            logging.info(f"Nuitka executable detected in {file_path}")
            
            # Find the next available directory number
            folder_number = 1
            while os.path.exists(f"{nuitka_dir}_{folder_number}"):
                folder_number += 1
            nuitka_output_dir = f"{nuitka_dir}_{folder_number}"
            
            if not os.path.exists(nuitka_output_dir):
                os.makedirs(nuitka_output_dir)

            logging.info(f"Extracting Nuitka file {file_path} to {output_dir}")
            
            # Use nuitka_extractor to extract the file
            command = [nuitka_extractor_path, "-output", output_dir, file_path]
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                logging.info(f"Successfully extracted Nuitka file: {file_path} to {output_dir}")
            else:
                logging.error(f"Failed to extract Nuitka file: {file_path}. Error: {result.stderr}")
        else:
            logging.info(f"No Nuitka content found in {file_path}")
    
    except Exception as e:
        logging.error(f"Error extracting Nuitka file: {e}")

def is_elf_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            elf = ELFFile(file)
            return elf.header.e_ident[:4] == b'\x7FELF'
    except Exception as e:
        logging.error(f"Error checking ELF file status: {e}")
        return False

def is_dotnet_file(file_path, detectiteasy_console_path):
    try:
        # Run the DIE console command to analyze the file
        result = subprocess.run([detectiteasy_console_path, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if the output indicates that the file is a .NET executable
        if "Microsoft .NET" in result.stdout or "CLR" in result.stdout:
            return True
        
    except subprocess.SubprocessError as e:
        logging.error(f"Error running Detect It Easy for {file_path}: {e}")
        return False
    
    return False

class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name

class PyInstArchive:
    MAGIC = b'MEI\014\013\012\013\016'
    PYINST20_COOKIE_SIZE = 24
    PYINST21_COOKIE_SIZE = 24 + 64

    def __init__(self, path):
        self.filePath = path

    def open_file(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
            return True
        except IOError as e:
            print(f"Error opening file: {e}")
            return False

    def close(self):
        try:
            self.fPtr.close()
        except AttributeError:
            pass

    def checkFile(self):
        endPos = self.fileSize
        searchChunkSize = 8192

        while True:
            startPos = max(0, endPos - searchChunkSize)
            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(endPos - startPos)
            offs = data.rfind(self.MAGIC)
            if offs != -1:
                self.cookiePos = startPos + offs
                break
            endPos = startPos + len(self.MAGIC) - 1
            if startPos == 0:
                return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        self.pyinstVer = 21 if b'python' in self.fPtr.read(64).lower() else 20
        return True

    def getCArchiveInfo(self):
        self.fPtr.seek(self.cookiePos, os.SEEK_SET)
        try:
            if self.pyinstVer == 20:
                _, lengthofPackage, toc, tocLen, pyver = struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))
            else:
                _, lengthofPackage, toc, tocLen, pyver, _ = struct.unpack('!8sIIii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))
        except struct.error as e:
            print(f"Error unpacking data: {e}")
            return False

        self.pymaj, self.pymin = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        self.overlaySize = lengthofPackage + (self.fileSize - self.cookiePos - (self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE))
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen
        return True

    def parseTOC(self):
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)
        self.tocList = []
        parsedLen = 0

        while parsedLen < self.tableOfContentsSize:
            entrySize = struct.unpack('!i', self.fPtr.read(4))[0]

            if entrySize <= 0 or entrySize > self.fileSize - self.tableOfContentsPos:
                return False

            nameLen = struct.calcsize('!iIIIBc')

            try:
                entry = struct.unpack(f'!IIIBc{entrySize - nameLen}s', self.fPtr.read(entrySize - 4))
            except struct.error as e:
                print(f"Error unpacking TOC entry: {e}")
                return False

            name = entry[5].decode('utf-8', errors='replace').rstrip('\0')
            self.tocList.append(CTOCEntry(
                self.overlayPos + entry[0],
                entry[1],
                entry[2],
                entry[3],
                entry[4],
                name
            ))

            parsedLen += entrySize

        return True

    def extractFiles(self):
        folder_number = 1
        base_extraction_dir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')

        while os.path.exists(f"{base_extraction_dir}_{folder_number}"):
            folder_number += 1

        extractionDir = f"{base_extraction_dir}_{folder_number}"
        os.makedirs(extractionDir, exist_ok=True)
        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)
            if entry.cmprsFlag == 1:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    return False

            with open(entry.name, 'wb') as f:
                f.write(data)

            if entry.name.endswith('.pyz'):
                self._extractPyz(entry.name)

        return True

    def _extractPyz(self, name):
        dirName =  name + '_extracted'
        os.makedirs(dirName, exist_ok=True)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0' 

            pyzPycMagic = f.read(4) 

            if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                return False

            tocPosition = struct.unpack('!i', f.read(4))[0]
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except (EOFError, ValueError, TypeError) as e:
                print(f"Error loading PYZ TOC: {e}")
                return False

            if isinstance(toc, list):
                toc = dict(toc)

            for key, (ispkg, pos, length) in toc.items():
                f.seek(pos, os.SEEK_SET)
                fileName = key.decode('utf-8', errors='replace')
                fileName = fileName.replace('..', '__').replace('.', os.path.sep)

                if ispkg:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')
                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                os.makedirs(os.path.dirname(filePath), exist_ok=True)

                data = f.read(length)
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    with open(filePath + '.encrypted', 'wb') as e_f:
                        e_f.write(data)
                    continue

                with open(filePath, 'wb') as pyc_f:
                    pyc_f.write(pyzPycMagic)
                    pyc_f.write(b'\0' * 4)
                    if self.pymaj >= 3 and self.pymin >= 7:
                        pyc_f.write(b'\0' * 8)
                    pyc_f.write(data)

        return True

def is_pyinstaller_archive(file_path):
    archive = PyInstArchive(file_path)
    if archive.open_file():
        result = archive.checkFile()
        archive.close_file()
        return result
    return False

def extract_pyinstaller_archive(file_path):
    try:
        archive = PyInstArchive(file_path)
        if not archive.open():
            logging.error(f"Failed to open PyInstaller archive: {file_path}")
            return None

        if not archive.checkFile():
            logging.error(f"File {file_path} is not a valid PyInstaller archive.")
            return None

        if not archive.getCArchiveInfo():
            logging.error(f"Failed to get CArchive info from {file_path}.")
            return None

        if not archive.parseTOC():
            logging.error(f"Failed to parse TOC from {file_path}.")
            return None

        extraction_success = archive.extractFiles()
        extraction_dir = os.getcwd() if extraction_success else None
        archive.close()

        return extraction_dir if extraction_success else None

    except Exception as e:
        logging.error(f"An error occurred while extracting PyInstaller archive {file_path}: {e}")
        return None

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
        with open(file_path, 'r') as file:
            file_data = file.read(1024)
            if file_data:  # Check if file has readable content
                logging.info(f"File '{file_path}' is readable")
                return True
            return False
    except UnicodeDecodeError:
        logging.error(f"UnicodeDecodeError while reading file '{file_path}'")
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
                notify_user_ransomware(main_file_path, "HEUR:Win32.Ransom.Generic")
                has_warned_ransomware = True
                logging.warning(f"User has been notified about potential ransomware in {main_file_path}")
                print(f"User has been notified about potential ransomware in {main_file_path}")
    except Exception as e:
        logging.error(f"Error in ransomware_alert: {e}")

# Global variables for worm detection
worm_alerted_files = []
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

def check_worm_similarity(file_path, features_current):
    """Check similarity with main file and collected files."""
    worm_detected = False

    if main_file_path and main_file_path != file_path:
        features_main = extract_numeric_worm_features(main_file_path)
        similarity_main = calculate_similarity_worm(features_current, features_main)
        if similarity_main > 0.86:
            logging.warning(f"Main file '{main_file_path}' is spreading the worm to '{file_path}' with similarity score {similarity_main}")
            worm_detected = True

    for collected_file_path in file_paths:
        if collected_file_path != file_path:
            features_collected = extract_numeric_worm_features(collected_file_path)
            similarity_collected = calculate_similarity_worm(features_current, features_collected)
            if similarity_collected > 0.86:
                logging.warning(f"Worm has spread to '{collected_file_path}' with similarity score {similarity_collected}")
                worm_detected = True

    return worm_detected

def worm_alert(file_path):
    global worm_alerted_files
    global worm_detected_count
    global file_paths

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
        worm_detected = False
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

    except Exception as e:
        logging.error(f"Error in worm detection for file {file_path}: {e}")

def scan_and_warn(file_path, flag=False):
    logging.info(f"Scanning file: {file_path}")

    try:
        # Perform ransomware alert check
        ransomware_alert(file_path)

        # Extract the file name
        file_name = os.path.basename(file_path)

        # Check if the file is a known rootkit file
        if file_name in known_rootkit_files:
            logging.warning(f"Detected potential rootkit file: {file_path}")
            notify_user_for_detected_rootkit(file_path, f"HEUR:Rootkit.{file_name}")

        # Initialize variables
        is_decompiled = False
        pe_file = False
        signature_check = {
            "has_microsoft_signature": False,
            "is_valid": False,
            "signature_status_issues": False
        }

        # Check if the file is in decompile_dir
        if file_path.startswith(decompile_dir):
            logging.info(f"File {file_path} is in decompile_dir.")
            is_decompiled = True

        # Check if the file is not in the processed directory
        if not os.path.commonpath([file_path, processed_dir]) == processed_dir:
            # Process the file data including magic byte removal
            process_file_data(file_path)

        # Check if the file is a PyInstaller archive
        if is_pyinstaller_archive(file_path):
            logging.info(f"File {file_path} is a PyInstaller archive. Extracting...")
            pyinstaller_dir = extract_pyinstaller_archive(file_path)
            if pyinstaller_dir:
                logging.info(f"PyInstaller archive extracted to {pyinstaller_dir}")
                # Scan extracted contents
                for root, dirs, files in os.walk(pyinstaller_dir):
                    for file in files:
                        extracted_file_path = os.path.join(root, file)
                        scan_and_warn(extracted_file_path, flag)

        # Check if the file is a PE file
        if is_pe_file(file_path):
            logging.info(f"File {file_path} is a valid PE file.")
            pe_file = True

        # Check signature
        signature_check = check_signature(file_path)
        if not isinstance(signature_check, dict):
            logging.error(f"check_signature did not return a dictionary for file: {file_path}, received: {signature_check}")

        if signature_check["has_microsoft_signature"]:
            logging.info(f"Valid Microsoft signature detected for file: {file_path}")
            return False
        elif signature_check["is_valid"]:
            logging.info(f"File '{file_path}' has a valid signature. Skipping worm detection.")
        elif signature_check["signature_status_issues"]:
            logging.warning(f"File '{file_path}' has signature issues. Proceeding with further checks.")
            notify_user_invalid(file_path, "Win32.InvalidSignature")

        # Check for fake file size
        if os.path.getsize(file_path) > 100 * 1024 * 1024:  # File size > 100MB
            with open(file_path, 'rb') as file:
                file_content_read = file.read(100 * 1024 * 1024)
                if file_content_read == b'\x00' * 100 * 1024 * 1024:  # 100MB of continuous `0x00` bytes
                    logging.warning(f"File {file_path} is flagged as HEUR:FakeSize.Generic")
                    fake_size = "HEUR:FakeSize.Generic"
                    if signature_check and signature_check["is_valid"]:
                        fake_size = "HEUR:SIG.Win32.FakeSize.Generic"
                    notify_user_fake_size_thread = threading.Thread(target=notify_user_fake_size, args=(file_path, fake_size))
                    notify_user_fake_size_thread.start()

        # Check if the file contains Nuitka and extract if present
        try:
            logging.info(f"Checking if the file {file_path} contains Nuitka executable.")
            
            # Extract Nuitka file content using the extract_nuitka_file function
            extract_nuitka_file(file_path)
                
        except Exception as e:
            logging.error(f"Error checking or extracting Nuitka content from {file_path}: {e}")

        # Decompile the file
        decompile_file(file_path)

        # Check if .NET data is detected
        if is_dotnet_file(file_path):
            logging.info(f"Detected .NET assembly: {file_path}")
            folder_number = 1
            while os.path.exists(f"{dotnet_dir}_{folder_number}"):
                folder_number += 1
            dotnet_output_dir = f"{dotnet_dir}_{folder_number}"
            os.makedirs(dotnet_output_dir, exist_ok=True)
            ilspy_command = f"{ilspycmd_path} -o {dotnet_output_dir} {file_path}"
            os.system(ilspy_command)
            logging.info(f".NET content decompiled to {dotnet_output_dir}")

        # Check for PE file and signatures
        if pe_file:
            logging.info(f"File {file_path} is a valid PE file.")
            worm_alert(file_path)

            # Check for fake system files after signature validation
            if file_name in fake_system_files and os.path.abspath(file_path).startswith(main_drive_path):
                if pe_file and not signature_check["is_valid"]:
                    logging.warning(f"Detected fake system file: {file_path}")
                    notify_user_for_detected_fake_system_file(file_path, file_name, "HEUR:Win32.FakeSystemFile.Dropper.Generic")

        # Perform real-time scan
        is_malicious, virus_names = scan_file_real_time(file_path, signature_check, pe_file=pe_file)

        if is_malicious:
            # Concatenate multiple virus names into a single string without delimiters
            virus_name = ''.join(virus_names)
            logging.warning(f"File {file_path} is malicious. Virus: {virus_name}")

            if virus_name.startswith("PUA."):
                notify_user_pua_thread = threading.Thread(target=notify_user_pua, args=(file_path, virus_name))
                notify_user_pua_thread.start()
            else:
                notify_user_thread = threading.Thread(target=notify_user, args=(file_path, virus_name))
                notify_user_thread.start()

        # Additional post-decompilation actions based on extracted file path
        if is_decompiled:
            logging.info(f"Checking original file path from decompiled data for: {file_path}")
            original_file_path = extract_original_file_path_from_decompiled(file_path)
            if original_file_path:
                logging.info(f"Original file path extracted: {original_file_path}")

        # Continue processing even if flag is True, to handle files already processed
        if flag:
            logging.info(f"Reprocessing file {file_path} with all checks enabled...")

        return True

    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
        return False

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

    except Exception as e:
        print(f"An error occurred at monitor_sandbox: {e}")
        logging.error(f"An error occurred at monitor_sandbox: {e}")
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
            except Exception as e:
                print(f"Error processing line: {e}")

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
                            elif file_path.endswith(('.vbs', '.js', '.jse', '.bat', '.url', '.cmd', '.hta', '.ps1', '.wsf')):
                                malware_type = "HEUR:Win32.Startup.Script.Generic.Malware"
                                message = f"Confirmed script malware detected: {file_path}\nVirus: {malware_type}"
                            else:
                                malware_type = "HEUR:Win32.Startup.Generic.Malware"
                                message = f"Suspicious startup file detected: {file_path}"

                            logging.warning(f"Suspicious or malicious startup file detected in {directory}: {file}")
                            print(f"Suspicious or malicious startup file detected in {directory}: {file}")
                            notify_user_startup(file_path, message)
                            scan_and_warn(file_path)
                            alerted_files.append(file_path)
        except Exception as e:
            logging.error(f"An error occurred while checking startup directories: {e}")

def check_hosts_file_for_blocked_antivirus():
    try:
        if not os.path.exists(hosts_path):
            return False

        with open(hosts_path, 'r') as hosts_file:
            hosts_content = hosts_file.read()

        blocked_domains = []

        # Regular expression pattern to match domain or any subdomain
        domain_patterns = [re.escape(domain) + r'\b' for domain in antivirus_domains]
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
        return False
    except Exception as e:
        logging.error(f"Error reading hosts file: {e}")
        return False

# Function to continuously monitor hosts file
def monitor_hosts_file():
    # Continuously check the hosts file
    while True:
        is_malicious = check_hosts_file_for_blocked_antivirus()

        if is_malicious:
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
                    notify_user_uefi(file_path, "HEUR:Win32.Startup.UEFI.Generic.Malware")
                    scan_and_warn(file_path)
                    alerted_uefi_files.append(file_path)

class ScanAndWarnHandler(FileSystemEventHandler):

    def process_file(self, file_path):
        try:
            scan_and_warn(file_path)
            logging.info(f"Processed file: {file_path}")
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {e}")

    def process_directory(self, dir_path):
        try:
            for root, _, files in os.walk(dir_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    self.process_file(file_path)
            logging.info(f"Processed all files in directory: {dir_path}")
        except Exception as e:
            logging.error(f"Error processing directory {dir_path}: {e}")

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
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Sandboxie control: {e.stderr}")
    except Exception as e:
        logging.error(f"Unexpected error running Sandboxie control: {e}")

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

    def enum_child_windows_callback(hwnd, lParam):
        child_windows.append(hwnd)
        return True

    EnumChildWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    ctypes.windll.user32.EnumChildWindows(parent_hwnd, EnumChildWindowsProc(enum_child_windows_callback), None)
    
    return child_windows

# Function to find windows containing text
def find_windows_with_text():
    """Find all windows and their child windows."""
    def enum_windows_callback(hwnd, lParam):
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

# Helper function to check if a string contains a known IP address
def contains_ip_address(text):
    for ip in ip_addresses_signatures_data:
        if ip in text:
            if ip_regex.search(text):
                return True
    return False

# Helper function to check if a string contains a known IPv6 address
def contains_ipv6_address(text):
    for ipv6 in ipv6_addresses_signatures_data:
        if ipv6 in text:
            if ipv6_regex.search(text):
                return True
    return False

# Helper function to check if a string contains a known domain
def contains_domain(text):
    for domain in domains_signatures_data:
        if domain in text:
            if domain_regex.search(text):
                return True
    return False

# Helper function to check if a string contains a known URL from urlhaus_data
def contains_url(text):
    # Extract all URLs from the text using the URL regex
    extracted_urls = url_regex.findall(text)
    
    for url in extracted_urls:
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
                return True
    return False

class Monitor:
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
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.error(f"Process error: {e}")
            except Exception as e:
                logging.error(f"Unexpected error while processing process {proc.info.get('pid')}: {e}")
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

    def notify_user_for_detected_command(self, message):
        logging.warning(f"Notification: {message}")
        notification = Notify()
        notification.title = f"Malware Message Alert"
        notification.message = message
        notification.send()

    def process_detected_text_classic(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["classic"]["virus_name"]
        message = f"Detected potential anti-vm anti-debug malware: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_text_av(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["av"]["virus_name"]
        message = f"Detected potential anti-AV malware: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_text_debugger(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["debugger"]["virus_name"]
        message = f"Detected potential anti-debugger malware: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_text_fanmade(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["fanmade"]["virus_name"]
        message = f"Detected potential fanmade malware: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_text_rogue(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["rogue"]["virus_name"]
        message = f"Detected potential rogue security software: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_text_ransom(self, text, file_path=None, hwnd=None):
        message = f"Potential ransomware detected in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_wifi(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["wifi"]["virus_name"]
        message = f"Detected Wi-Fi credentials stealing malware: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_ransom_shadowcopy(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["shadowcopy"]["virus_name"]
        message = f"Detected ransomware shadow copy deletion: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_wmic_shadowcopy(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["wmic"]["virus_name"]
        message = f"Detected WMIC shadow copy deletion: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_copy_to_startup(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["startup"]["virus_name"]
        message = f"Detected startup copy malware: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_schtasks_temp(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["commands"]["schtasks"]["virus_name"]
        message = f"Detected scheduled task creation using temp file: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_rootkit_koadic(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["koadic"]["virus_name"]
        message = f"Detected rootkit behavior associated with Koadic: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_fodhelper(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["fodhelper"]["virus_name"]
        message = f"Detected UAC bypass attempt using Fodhelper: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_antivirus_search(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["antivirus"]["virus_name"]
        message = f"Detected search for antivirus processes: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_powershell_iex_download(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["powershell_iex_download"]["virus_name"]
        message = f"Detected PowerShell IEX download command: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected_command_xmrig(self, text, file_path=None, hwnd=None):
        virus_name = self.known_malware_messages["xmrig"]["virus_name"]
        message = f"Detected XMRig mining activity: {virus_name} in text: {text} from {file_path} {hwnd}"
        logging.warning(message)
        self.notify_user_for_detected_command(message)

    def process_detected(self, input_string, file_path=None, hwnd=None):
        if file_path:
            base_name = os.path.basename(file_path)
            full_cleaned_file_path = os.path.join(commandlineandmessage_dir, f"{base_name}.full_cleaned")
        else:
            full_cleaned_file_path = os.path.join(commandlineandmessage_dir, "input_string.full_cleaned")

        if not file_path:
            # Handle text input
            cleaned_text = remove_magic_bytes_from_text(input_string)

            # Save cleaned text to the designated folder
            with open(full_cleaned_file_path, 'w', encoding='utf-8') as file:
                file.write(cleaned_text)
        else:
            # Handle file input
            with open(file_path, 'r', encoding='utf-8') as file:
                file_content = file.read()

            # Process the file content with cleanups
            full_cleaned_file_content = remove_magic_bytes_from_text(file_content)

            # Save cleaned content to the designated folder
            with open(full_cleaned_file_path, 'w', encoding='utf-8') as file:
                file.write(full_cleaned_file_content)

        # Log the cleaned file path
        if file_path:
            logging.info(f"Processed file: {file_path} -> Cleaned file: {full_cleaned_file_path}")
        else:
            logging.info(f"Processed input string -> Cleaned file: {full_cleaned_file_path}")

        # Process the file content for known malware messages
        with open(full_cleaned_file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()

        for category, details in self.known_malware_messages.items():
            if "patterns" in details:
                for pattern in details["patterns"]:
                    similarity = calculate_similarity_text(file_content, pattern)
                    if similarity > 0.8:  # Adjust similarity threshold as needed
                        details["process_function"](file_content, file_path, hwnd)
                        return
            elif "message" in details:
                similarity = calculate_similarity_text(file_content, details["message"])
                if similarity > 0.8:  # Adjust similarity threshold as needed
                    details["process_function"](file_content, file_path, hwnd)
                    return
            elif "command" in details:
                similarity = calculate_similarity_text(file_content, details["command"])
                if similarity > 0.8:  # Adjust similarity threshold as needed
                    details["process_function"](file_content, file_path, hwnd)
                    return

        # Adding ransomware check
        if self.contains_keywords_within_max_distance(file_content, max_distance=10):
            self.process_detected_text_ransom(file_content, file_path, hwnd)

        logging.info(f"Finished processing detection {input_string} (process_detected).")

    def monitor(self):
        try:
            while True:
                # Capture windows with text
                windows = find_windows_with_text()
                for hwnd, text in windows:
                    # Process both preprocessed and original text
                    preprocessed_text = self.preprocess_text(text)
                    self.process_detected(preprocessed_text, hwnd=hwnd)  # Process preprocessed text
                    self.process_detected(text, hwnd=hwnd)  # Process original text

                # Capture command lines
                command_lines = self.capture_command_lines()
                for command_line, executable_path in command_lines:
                    # Convert command_line to lowercase
                    command_line_lower = command_line.lower()
                    
                    # Process both preprocessed and original command lines
                    self.process_detected(preprocessed_command_line, file_path=executable_path)  # Process preprocessed command line
                    self.process_detected(command_line, file_path=executable_path)  # Process original command line
                    self.process_detected(command_line_lower, file_path=executable_path)

        except Exception as e:
            logging.error(f"Unexpected error in monitor loop: {e}")

# List of already scanned files and their modification times
scanned_files = []
file_mod_times = {}
directories_to_scan = [sandboxie_folder, decompile_dir, nuitka_dir, dotnet_dir, pyinstaller_dir, base_dir, commandlineandmessage_dir, pe_extracted_dir,zip_extracted_dir, tar_extracted_dir, processed_dir]

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

    except Exception as e:
        logging.error(f"Error in monitor_sandboxie_directory: {e}")

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

        monitor = Monitor()

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
        threading.Thread(target=monitor.monitor).start() # Function to monitor specific windows in a separate thread
        threading.Thread(target=run_sandboxie_control).start()
        threading.Thread(target=run_sandboxie, args=(file_path,)).start()

        logging.info("Sandbox analysis started. Please check log after you close program. There is no limit to scan time.")

    except Exception as e:
        logging.error(f"An error occurred during sandbox analysis: {e}")

class AnalysisThread(QThread):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def execute_anylsis(self):
        try:
            print(f"Running analysis for: {self.file_path}")  
            logging.info(f"Running analysis for: {self.file_path}")
            perform_sandbox_analysis(self.file_path)
        except Exception as e:
            error_message = f"An error occurred during sandbox analysis: {str(e)}"
            logging.error(error_message)
            print(error_message)

def run_sandboxie(file_path):
    try:
        subprocess.run([sandboxie_path, '/box:DefaultBox', file_path], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run Sandboxie on {file_path}: {e}")

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