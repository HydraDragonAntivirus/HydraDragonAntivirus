#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
from datetime import datetime, timedelta
import time

main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)
sys.path.insert(0, main_dir)

# Set script directory
script_dir = os.getcwd()

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Separate log files for different purposes
stdout_console_log_file = os.path.join(
    log_directory, "antivirusconsolestdout.log"
)
stderr_console_log_file = os.path.join(
    log_directory, "antivirusconsolestderr.log"
)
application_log_file = os.path.join(
    log_directory, "antivirus.log"
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

# Start timing total duration
total_start_time = time.time()

# Measure and logging.info time taken for each import
start_time = time.time()
import hashlib
logging.info(f"hashlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import io
logging.info(f"io module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import webbrowser
logging.info(f"webbrowser module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from uuid import uuid4 as uniquename
logging.info(f"uuid.uuid4.uniquename loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import shutil
logging.info(f"shutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import subprocess
logging.info(f"subprocess module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import threading
logging.info(f"threading module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from concurrent.futures import ThreadPoolExecutor
logging.info(f"concurrent.futures.ThreadPoolExecutor module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import re
logging.info(f"re module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import json
logging.info(f"json module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QLabel, QTextEdit, QFileDialog,
                               QFrame, QStackedWidget,
                               QApplication, QButtonGroup, QGroupBox)
logging.info(f"PySide6.QtWidgets modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtCore import (Qt, QPropertyAnimation, QEasingCurve, QThread,
                            Signal, QPoint, QParallelAnimationGroup, Property, QRect)
logging.info(f"PySide6.QtCore modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtGui import (QColor, QPainter, QBrush, QLinearGradient, QPen,
                           QPainterPath, QRadialGradient, QIcon, QPixmap)
logging.info(f"PySide6.QtGui.QIcon module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pefile
logging.info(f"pefile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pyzipper
logging.info(f"pyzipper module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import tarfile
logging.info(f"tarfile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara
logging.info(f"yara module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara_x
logging.info(f"yara_x module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import psutil
logging.info(f"psutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from notifypy import Notify
logging.info(f"notifypy.Notify module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from watchdog.observers import Observer
logging.info(f"watchdog.observers.Observer module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from watchdog.events import FileSystemEventHandler
logging.info(f"watchdog.events.FileSystemEventHandler module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32file
logging.info(f"win32file module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32con
logging.info(f"win32con module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import wmi
logging.info(f"wmi module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import numpy as np
logging.info(f"numpy module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sniff

logging.info(f"scapy modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ast
logging.info(f"ast module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ctypes
logging.info(f"ctypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from ctypes import wintypes
logging.info(f"ctypes.wintypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from ctypes import byref
logging.info(f"ctypes.byref module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import comtypes
logging.info(f"comtypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from comtypes.automation import VARIANT
logging.info(f"comtypes.automation.VARIANT module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from comtypes import CoInitialize
logging.info(f"comtypes.CoInitialize module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from comtypes.client import CreateObject, GetModule
logging.info(f"comtypes.client.CreateObject and GetModule modules loaded in {time.time() - start_time:.6f} seconds")

# Generate the oleacc module
start_time = time.time()
GetModule('oleacc.dll')
from comtypes.gen import Accessibility  # Usually oleacc maps to this
logging.info(f"comtypes.gen.Accessibility module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ipaddress
logging.info(f"ipaddress module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from urllib.parse import urlparse
logging.info(f"urllib.parse.urlparse module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import spacy
logging.info(f"spacy module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import csv
logging.info(f"csv module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import struct
logging.info(f"struct module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from importlib.util import MAGIC_NUMBER
logging.info(f"importlib.util.MAGIC_NUMBER module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import string
logging.info(f"string module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import chardet
logging.info(f"chardet module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import difflib
logging.info(f"difflib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zlib
logging.info(f"zlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import marshal
logging.info(f"marshal module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import base64
logging.info(f"base64 module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import base32_crockford
logging.info(f"base32_crockford module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import binascii
logging.info(f"binascii module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from transformers import AutoTokenizer, AutoModelForCausalLM
logging.info(f"transformers.AutoTokenizer and AutoModelForCausalLM modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from accelerate import Accelerator
logging.info(f"accelerate.Accelerator module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import py7zr
logging.info(f"py7zr module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pymem
logging.info(f"pymem module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import inspect
logging.info(f"inspect module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zstandard
logging.info(f"zstandard module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from elftools.elf.elffile import ELFFile
logging.info(f"elftools.elf.elffile, ELFFile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.MachO
logging.info(f"macholib.MachO module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.mach_o
logging.info(f"macholib.mach_o module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from typing import Optional, Tuple, BinaryIO, Dict, Any, List, Set
logging.info(f"typing, Optional, Tuple, BinaryIO, Dict and Any module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import types
logging.info(f"types module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
logging.info(f"cryptography.hazmat.primitives.ciphers, Cipher, algorithms, modes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import debloat.processor
logging.info(f"debloat modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from Crypto.Cipher import AES
logging.info(f"Crpyto.Cipher.AES module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from Crypto.Util import Counter
logging.info(f"Crpyto.Cipher.Counter module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from pathlib import Path, WindowsPath
logging.info(f"pathlib.Path module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import requests
logging.info(f"requests module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from functools import wraps
logging.info("functoools.wraps module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from xdis.unmarshal import load_code
logging.info("xdis.unmarshal.load_code module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from GoStringUngarbler.gostringungarbler_lib import process_file_go
logging.info(f"GoStringUngarbler.gostringungarbler_lib.process_file_go module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from pylingual.main import main as pylingual_main
logging.info(f"pylingual.main module loaded in {time.time() - start_time:.6f} seconds")

# Calculate and logging.info total time
total_end_time = time.time()
total_duration = total_end_time - total_start_time
logging.info(f"Total time for all imports: {total_duration:.6f} seconds")

# Load the spaCy model globally
nlp_spacy_lang = spacy.load("en_core_web_md")
logging.info("spaCy model 'en_core_web_md' loaded successfully")

# Initialize the accelerator and device
accelerator = Accelerator()
device = accelerator.device

# get the full path to the currently running Python interpreter
python_path = sys.executable

# Define the paths
reports_dir = os.path.join(script_dir, "reports")
scan_report_path = os.path.join(reports_dir, "scan_report.json")
enigma_extracted_dir = os.path.join(script_dir, "enigma_extracted")
inno_unpack_dir = os.path.join(script_dir, "innounp-2")
upx_dir = os.path.join(script_dir, "upx-5.0.1-win64")
upx_path = os.path.join(upx_dir, "upx.exe")
upx_extracted_dir = os.path.join(script_dir, "upx_extracted_dir")
inno_unpack_path = os.path.join(inno_unpack_dir, "innounp.exe")
inno_setup_unpacked_dir = os.path.join(script_dir, "inno_setup_unpacked")
decompiled_dir = os.path.join(script_dir, "decompiled")
assets_dir = os.path.join(script_dir, "assets")
icon_path = os.path.join(assets_dir, "HydraDragonAVLogo.png")
digital_signatures_list_dir = os.path.join(script_dir, "digitalsignatureslist")
pyinstaller_extracted_dir = os.path.join(script_dir, "pyinstaller_extracted")
cx_freeze_extracted_dir = os.path.join(script_dir, "cx_freeze_extracted")
ghidra_projects_dir = os.path.join(script_dir, "ghidra_projects")
ghidra_logs_dir = os.path.join(script_dir, "ghidra_logs")
ghidra_scripts_dir = os.path.join(script_dir, "ghidra_scripts")
jar_decompiler_dir = os.path.join(script_dir, "jar_decompiler")
FernFlower_decompiled_dir = os.path.join(script_dir, "FernFlower_decompiled")
jar_extracted_dir = os.path.join(script_dir, "jar_extracted")
dotnet_dir = os.path.join(script_dir, "dotnet")
obfuscar_dir = os.path.join(script_dir, "obfuscar")
nuitka_dir = os.path.join(script_dir, "nuitka")
extensions_dir = os.path.join(script_dir, "knownextensions")
FernFlower_path = os.path.join(jar_decompiler_dir, "fernflower.jar")
system_file_names_path = os.path.join(extensions_dir, "systemfilenames.txt")
extensions_path = os.path.join(extensions_dir, "extensions.txt")
antivirus_process_list_path = os.path.join(extensions_dir, "antivirusprocesslist.txt")
magic_bytes_path = os.path.join(extensions_dir, "magicbytes.txt")
meta_llama_dir = os.path.join(script_dir, "meta_llama")
meta_llama_1b_dir = os.path.join(meta_llama_dir, "Llama-3.2-1B")
python_source_code_dir = os.path.join(script_dir, "python_sourcecode")
python_deobfuscated_dir = os.path.join(script_dir, "python_deobfuscated")
python_deobfuscated_marshal_pyc_dir = os.path.join(python_deobfuscated_dir, "python_deobfuscated_marshal_pyc")
pylingual_extracted_dir = os.path.join(python_source_code_dir, "pylingual_extracted")
pycdas_extracted_dir = os.path.join(python_source_code_dir, "pycdas_extracted")
de4dot_cex_dir = os.path.join(script_dir, "de4dot-cex")
de4dot_cex_x64_path = os.path.join(de4dot_cex_dir, "de4dot-x64.exe")
de4dot_extracted_dir = os.path.join(script_dir, "de4dot_extracted")
nuitka_source_code_dir = os.path.join(script_dir, "nuitka_source_code")
commandlineandmessage_dir = os.path.join(script_dir, "commandlineandmessage")
pe_extracted_dir = os.path.join(script_dir, "pe_extracted")
zip_extracted_dir = os.path.join(script_dir, "zip_extracted")
tar_extracted_dir = os.path.join(script_dir, "tar_extracted")
seven_zip_extracted_dir = os.path.join(script_dir, "seven_zip_extracted")
general_extracted_with_7z_dir = os.path.join(script_dir, "general_extracted_with_7z")
nuitka_extracted_dir = os.path.join(script_dir, "nuitka_extracted")
advanced_installer_extracted_dir = os.path.join(script_dir, "advanced_installer_extracted")
processed_dir = os.path.join(script_dir, "processed")
detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
deteciteasy_plain_text_dir = os.path.join(script_dir, "deteciteasy_plain_text")
memory_dir = os.path.join(script_dir, "memory")
debloat_dir = os.path.join(script_dir, "debloat")
copied_sandbox_and_main_files_dir = os.path.join(script_dir, "copied_sandbox_and_main_files")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
ilspycmd_path = os.path.join(script_dir, "ilspycmd.exe")
pycdas_path = os.path.join(script_dir, "pycdas.exe")
pd64_path = os.path.join(script_dir, "pd64.exe")
pd64_extracted_dir = os.path.join(script_dir, "pd64_extracted")
deobfuscar_path = os.path.join(script_dir, "Deobfuscar-Standalone-Win64.exe")
digital_signatures_list_antivirus_path = os.path.join(digital_signatures_list_dir, "antivirus.txt")
digital_signatures_list_goodsign_path = os.path.join(digital_signatures_list_dir, "goodsign.txt")
machine_learning_dir = os.path.join(script_dir, "machinelearning")
machine_learning_results_json = os.path.join(machine_learning_dir, "results.json")
resource_extractor_dir = os.path.join(script_dir, "resources_extracted")
ungarbler_dir = os.path.join(script_dir, "ungarbler")
ungarbler_string_dir = os.path.join(script_dir, "ungarbler_string")
yara_dir = os.path.join(script_dir, "yara")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")
html_extracted_dir = os.path.join(script_dir, "html_extracted")
website_rules_dir = os.path.join(script_dir, "website")
# Define all website file paths
ipv4_addresses_path = os.path.join(website_rules_dir, "IPv4Malware.txt")
ipv4_addresses_spam_path = os.path.join(website_rules_dir, "IPv4Spam.txt")
ipv4_addresses_bruteforce_path = os.path.join(website_rules_dir, "IPv4BruteForce.txt")
ipv4_addresses_phishing_active_path = os.path.join(website_rules_dir, "IPv4PhishingActive.txt")
ipv4_addresses_phishing_inactive_path = os.path.join(website_rules_dir, "IPv4PhishingInActive.txt")
ipv4_whitelist_path = os.path.join(website_rules_dir, "IPv4Whitelist.txt")
ipv6_addresses_path = os.path.join(website_rules_dir, "IPv6Malware.txt")
ipv6_addresses_spam_path = os.path.join(website_rules_dir, "IPv6Spam.txt")
ipv4_addresses_ddos_path = os.path.join(website_rules_dir, "IPv4DDoS.txt")
ipv6_addresses_ddos_path = os.path.join(website_rules_dir, "IPv6DDoS.txt")
ipv6_whitelist_path = os.path.join(website_rules_dir, "IPv6Whitelist.txt")
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
yaraxtr_yrc_path = os.path.join(yara_dir, "yaraxtr.yrc")
cx_freeze_yrc_path = os.path.join(yara_dir, "cx_freeze.yrc")
compiled_rule_path = os.path.join(yara_dir, "compiled_rule.yrc")
yarGen_rule_path = os.path.join(yara_dir, "machinelearning.yrc")
icewater_rule_path = os.path.join(yara_dir, "icewater.yrc")
valhalla_rule_path = os.path.join(yara_dir, "valhalla-rules.yrc")
HydraDragonAV_sandboxie_dir = os.path.join(script_dir, "HydraDragonAVSandboxie")
HydraDragonAV_sandboxie_DLL_path = os.path.join(HydraDragonAV_sandboxie_dir, "HydraDragonAVSandboxie.dll")
Open_Hydra_Dragon_Anti_Rootkit_path = os.path.join(script_dir, "OpenHydraDragonAntiRootkit.py")

antivirus_domains_data = []
ipv4_addresses_signatures_data = []
ipv4_addresses_spam_signatures_data = []
ipv4_addresses_bruteforce_signatures_data = []
ipv4_addresses_phishing_active_signatures_data = []
ipv4_addresses_phishing_inactive_signatures_data = []
ipv4_addresses_ddos_signatures_data = []
ipv6_addresses_signatures_data = []
ipv6_addresses_spam_signatures_data = []
ipv6_addresses_ddos_signatures_data = []
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

# Regex for Snort alerts
alert_regex = re.compile(r'\[Priority: (\d+)].*?\{(?:UDP|TCP)} (\d+\.\d+\.\d+\.\d+):\d+ -> (\d+\.\d+\.\d+\.\d+):\d+')

# Resolve system drive path
system_drive = os.getenv("SystemDrive", "C:") + os.sep
# Resolve Program Files directory via environment (fallback to standard path)
program_files = os.getenv("ProgramFiles", os.path.join(system_drive, "Program Files"))
# Get SystemRoot (usually C:\Windows)
system_root = os.getenv("SystemRoot", os.path.join(system_drive, "Windows"))
# Fallback to %SystemRoot%\System32 if %System32% is not set
system32_dir = os.getenv("System32", os.path.join(system_root, "System32"))

# Snort base folder path
snort_folder = os.path.join(system_drive, "Snort")

# File paths and configurations
log_folder = os.path.join(snort_folder, "log")
log_path = os.path.join(log_folder, "alert.ids")
snort_config_path = os.path.join(snort_folder, "etc", "snort.conf")
snort_exe_path = os.path.join(snort_folder, "bin", "snort.exe")
sandboxie_dir = os.path.join(program_files, "Sandboxie")
sandboxie_path = os.path.join(sandboxie_dir, "Start.exe")
sandboxie_control_path = os.path.join(sandboxie_dir, "SbieCtrl.exe")
device_args = [f"-i {i}" for i in range(1, 26)]  # Fixed device arguments
username = os.getlogin()
sandboxie_folder = os.path.join(system_drive, "Sandbox", username, "DefaultBox")
main_drive_path = os.path.join(sandboxie_folder, "drive", system_drive.strip(":"))

def get_sandbox_path(original_path: str | Path) -> Path:
    original_path = Path(original_path)
    sandboxie_folder_path = Path(sandboxie_folder)

    drive_letter = original_path.drive.rstrip(":")  # e.g., "C"
    rest_path = original_path.relative_to(original_path.anchor).parts

    sandbox_path = sandboxie_folder_path / "drive" / drive_letter / Path(*rest_path)
    return sandbox_path

# Derived sandbox system root path
sandbox_system_root_directory = get_sandbox_path(system_root)

# Derived sandbox system32 path
sandbox_system32_directory = get_sandbox_path(system32_dir)

# Derived sandbox scan report path
sandbox_scan_report_path = get_sandbox_path(scan_report_path)

# Constant special item ID list value for desktop folder
CSIDL_DESKTOPDIRECTORY = 0x0010

# Flag for SHGetFolderPath
SHGFP_TYPE_CURRENT = 0

# Convenient shorthand for this function
SHGetFolderPathW = ctypes.windll.shell32.SHGetFolderPathW


def _get_folder_path(csidl):
    """Get the path of a folder identified by a CSIDL value."""
    # Create a buffer to hold the return value from SHGetFolderPathW
    buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)

    # Return the path as a string
    SHGetFolderPathW(None, csidl, None, SHGFP_TYPE_CURRENT, buf)
    return str(buf.value)


def get_desktop():
    """Return the current user's Desktop folder."""
    return _get_folder_path(CSIDL_DESKTOPDIRECTORY)

def get_sandboxie_log_folder():
    """Return the sandboxie log folder path on the desktop."""
    return f'{get_desktop()}\\DONTREMOVEHydraDragonAntivirusLogs'

ntdll_path = os.path.join(system32_dir, "ntdll.dll")
sandboxed_ntdll_path = os.path.join(sandbox_system32_directory, "ntdll.dll")
drivers_path = os.path.join(system32_dir, "drivers")
hosts_path = f'{drivers_path}\\hosts'
HydraDragonAntivirus_sandboxie_path = get_sandbox_path(script_dir)
sandboxie_log_folder = get_sandboxie_log_folder()
homepage_change_path = f'{sandboxie_log_folder}\\DONTREMOVEHomePageChange.txt'
HiJackThis_log_path = f'{HydraDragonAntivirus_sandboxie_path}\\HiJackThis\\HiJackThis.log'
de4dot_sandboxie_dir = f'{HydraDragonAntivirus_sandboxie_path}\\de4dot_extracted_dir'
python_deobfuscated_sandboxie_dir = f'{HydraDragonAntivirus_sandboxie_path}\\python_deobfuscated'
version_flag = f"-{sys.version_info.major}.{sys.version_info.minor}"

script_exts = {
    '.vbs', '.vbe', '.js', '.jse', '.bat', '.url',
    '.cmd', '.hta', '.ps1', '.psm1', '.wsf', '.wsb', '.sct'
}

# Known Enigma versions -> working evbunpack flags
PACKER_FLAGS = {
    "11.00": ["-pe", "10_70"],
    "10.70": ["-pe", "10_70"],
    "9.70":  ["-pe", "9_70"],
    "7.80":  ["-pe", "7_80", "--legacy-fs"],
}

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
snort_command = [snort_exe_path] + device_args + ["-c", snort_config_path, "-A", "fast"]

# Custom flags for directory changes
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800

directories_to_scan = [pd64_extracted_dir, enigma_extracted_dir, sandboxie_folder, copied_sandbox_and_main_files_dir, decompiled_dir, inno_setup_unpacked_dir, FernFlower_decompiled_dir, jar_extracted_dir, nuitka_dir, dotnet_dir, obfuscar_dir, de4dot_extracted_dir, pyinstaller_extracted_dir, cx_freeze_extracted_dir, commandlineandmessage_dir, pe_extracted_dir, zip_extracted_dir, tar_extracted_dir, seven_zip_extracted_dir, general_extracted_with_7z_dir, nuitka_extracted_dir, advanced_installer_extracted_dir, processed_dir, python_source_code_dir, pylingual_extracted_dir, python_deobfuscated_dir, python_deobfuscated_marshal_pyc_dir, pycdas_extracted_dir, nuitka_source_code_dir, memory_dir, debloat_dir, resource_extractor_dir, ungarbler_dir, ungarbler_string_dir, html_extracted_dir]

# ClamAV base folder path
clamav_folder = os.path.join(program_files, "ClamAV")

# 7-Zip base folder path
seven_zip_folder = os.path.join(program_files, "7-Zip")

# ClamAV file paths and configurations
clamdscan_path = os.path.join(clamav_folder, "clamdscan.exe")
freshclam_path = os.path.join(clamav_folder, "freshclam.exe")
clamav_database_directory_path = os.path.join(clamav_folder, "database")
clamav_file_paths = [
    os.path.join(clamav_database_directory_path, "daily.cvd"),
    os.path.join(clamav_database_directory_path, "daily.cld")
]

# 7-Zip executable path
seven_zip_path = os.path.join(seven_zip_folder, "7z.exe")

HiJackThis_directory = os.path.join(script_dir, "HiJackThis")
HiJackThis_exe = os.path.join(HiJackThis_directory, "HiJackThis.exe")
HiJackThis_logs_dir = os.path.join(script_dir, "HiJackThis_logs")

IPv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' # Simple IPv4 regex
IPv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b' # Simple IPv6 regex
# Regular expressions for Discord links
discord_webhook_pattern = (
    r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    r'|aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3Mv'
    r'|/skoohbew/ipa/moc\.drocsid//:sptth'
)

discord_canary_webhook_pattern = (
    r'https://canary\.discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    r'|aHR0cHM6Ly9jYW5hcnkuZGlzY29yZC5jb20vYXBpL3dlYmhvb2tzLw=='
    r'|/skoohbew/ipa/moc\.drocsid\.yranac//:sptth'
)

cdn_attachment_pattern = re.compile(
    r'https://(?:cdn\.discordapp\.com|media\.discordapp\.net)/attachments/\d+/\d+/[A-Za-z0-9_\-\.%]+(?:\?size=\d+)?'
    r'|aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMv'
    r'|/stnemhcatta/moc\.ppadrocsid\.ndc//:sptth'
)

telegram_token_pattern = (
    r'\d{9,10}:[A-Za-z0-9_-]{35}'                          # Normal token
    r'|[A-Za-z0-9_-]{35}:\d{9,10}'                         # Reversed structure (still forward matching)
    r'|[A-Za-z0-9+/]{35}OmX{9,12}'                         # Loose base64 + marker pattern
)

telegram_keyword_pattern = (
    r'\b(?:telegram|token)\b'
    r'|dGVsZWdyYW0=|dG9rZW4='
    r'|margel et|nekot'[::-1]
)

# Discord webhook (standard)
discord_webhook_pattern_standard = r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'

# Discord Canary webhook (standard)
discord_canary_webhook_pattern_standard = r'https://canary\.discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'

# Discord CDN attachments (standard)
cdn_attachment_pattern_standard = re.compile(
    r'https://(?:cdn\.discordapp\.com|media\.discordapp\.net)/attachments/\d+/\d+/[A-Za-z0-9_\-\.%]+(?:\?size=\d+)?'
)

# Telegram bot (standard)
telegram_pattern_standard = (
    r'https?://api\.telegram\.org/bot\d{9,10}:[A-Za-z0-9_-]{35}'   # Normal token URL (Telegram Bot API)
    r'|\b\d{9,10}:[A-Za-z0-9_-]{35}\b'                               # Standard Telegram Bot token format
)

UBLOCK_REGEX = re.compile(
    r'^https:\/\/s[cftz]y?[ace][aemnu][a-z]{1,4}o[mn][a-z]{4,8}[iy][a-z]?\.com\/$'
)

# Pattern for a single zip-based join obfuscation (chr((x-y)%128) generator)
ZIP_JOIN = re.compile(
    r'''(?:""?|''?)(?:\w*\.)?join\(\s*\(chr\(\(x\s*-\s*y\)\s*%\s*128\)\s*for\s*x\s*,\s*y\s*in\s*zip\(\s*(\[[^\]]*\])\s*,\s*(\[[^\]]*\])\s*\)\)\)''',
    re.DOTALL
)
# Pattern for chained .join calls: literal.join(...).join(...)
CHAINED_JOIN = re.compile(
    r"(\(['\"][^'\"]*['\"]\))\.(?:join\([^)]*\))+"
)
# Pattern for base64 literals inside b64decode
B64_LITERAL = re.compile(r"base64\.b64decode\(\s*(['\"])([A-Za-z0-9+/=]+)\1\s*\)")

# Unified list of all directories to manage
MANAGED_DIRECTORIES = [
    pd64_extracted_dir, enigma_extracted_dir, upx_extracted_dir, ungarbler_dir, ungarbler_string_dir,
    resource_extractor_dir, pyinstaller_extracted_dir, cx_freeze_extracted_dir,
    inno_setup_unpacked_dir, python_source_code_dir, nuitka_source_code_dir,
    commandlineandmessage_dir, processed_dir, memory_dir, dotnet_dir,
    de4dot_extracted_dir, obfuscar_dir, nuitka_dir, pe_extracted_dir,
    zip_extracted_dir, tar_extracted_dir, seven_zip_extracted_dir,
    general_extracted_with_7z_dir, nuitka_extracted_dir, advanced_installer_extracted_dir,
    debloat_dir, jar_extracted_dir, FernFlower_decompiled_dir, deteciteasy_plain_text_dir,
    python_deobfuscated_dir, python_deobfuscated_marshal_pyc_dir, pylingual_extracted_dir,
    pycdas_extracted_dir, copied_sandbox_and_main_files_dir, HiJackThis_logs_dir,
    html_extracted_dir, log_directory
]

for make_directory in MANAGED_DIRECTORIES:
  if not os.path.exists(make_directory):
    os.makedirs(make_directory)

# Sandboxie folders
os.makedirs(sandboxie_folder, exist_ok=True)
os.makedirs(sandbox_system_root_directory, exist_ok=True)

# Counter for ransomware detection
ransomware_detection_count = 0

def reset_flags():
    global main_file_path, pyinstaller_archive, full_python_version, pyz_version_match
    main_file_path = None
    pyinstaller_archive = None
    full_python_version = None
    pyz_version_match = False
reset_flags()

# Cache of { file_path: last_md5 }
file_md5_cache: dict[str, str] = {}

# Global cache: md5 -> (die_output, plain_text_flag)
die_cache: Dict[str, Tuple[str, bool]] = {}

# Separate cache for "binary-only" DIE results
binary_die_cache: Dict[str, str] = {}

def compute_md5_via_text(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def compute_md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def try_unpack_enigma1(input_exe: str) -> str | None:
    """
    Attempts to unpack an Enigma protected EXE by trying each known
    version+flag combo until one succeeds.

    :param input_exe: Path to the Enigma protected executable.
    :return: Path to the directory where files were extracted, or
             None if all attempts failed.
    """
    exe_name = Path(input_exe).stem

    for version, flags in PACKER_FLAGS.items():
        # Create a subdir for this version attempt: <exe_name>_v<version>
        version_dir = os.path.join(enigma_extracted_dir, f"{exe_name}_v{version}")
        os.makedirs(version_dir, exist_ok=True)

        cmd = ["evbunpack"] + flags + [input_exe, version_dir]
        logging.info(f"Trying Enigma protected v{version} flags: {flags}")
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        if proc.returncode == 0:
            logging.info(f"Successfully unpacked with version {version} into {version_dir}")
            return version_dir

        logging.warning(
            f"Attempt v{version} failed (exit {proc.returncode}). Output:\n{proc.stdout}"
        )

    logging.error(
        f"All unpack attempts failed for {input_exe}. Tried versions: {', '.join(PACKER_FLAGS)}"
    )
    return None

def is_plain_text(data: bytes,
                  null_byte_threshold: float = 0.01,
                  printable_threshold: float = 0.95) -> bool:
    """
    Heuristic: data is plain text if
      1. It contains very few null bytes,
      2. A high fraction of bytes are printable or common whitespace,
      3. And it decodes cleanly in some text encoding (e.g. UTF-8, Latin-1).

    :param data:       raw file bytes
    :param null_byte_threshold:
                       max fraction of bytes that can be zero (0x00)
    :param printable_threshold:
                       min fraction of bytes in printable + whitespace set
    """
    if not data:
        return True

    # 1) Null byte check
    nulls = data.count(0)
    if nulls / len(data) > null_byte_threshold:
        return False

    # 2) Printable char check
    printable = set(bytes(string.printable, 'ascii'))
    count_printable = sum(b in printable for b in data)
    if count_printable / len(data) < printable_threshold:
        return False

    # 3) Try a text decoding
    #    Use chardet to guess encoding
    guess = chardet.detect(data)
    enc = guess.get('encoding') or 'utf-8'
    try:
        data.decode(enc)
        return True
    except (UnicodeDecodeError, LookupError):
        return False

def is_plain_text_data(die_output):
    """
    Checks if the DIE output does indicate plain text, suggesting it is plain text data.
    """
    if die_output and "Format: plain text" in die_output.lower():
        logging.info("DIE output does not contain plain text; identified as non-plain text data.")
        return True
    return False

def is_valid_ip(ip_string: str) -> bool:
    """
    Returns True if ip_string is a valid public IPv4 or IPv6 address,
    False otherwise. Logs details about invalid cases.
    """

    # --- strip off port if present ---
    original = ip_string
    # IPv6 with brackets, e.g. "[2001:db8::1]:443"
    if ip_string.startswith('[') and ']' in ip_string:
        ip_core, sep, port = ip_string.partition(']')
        if sep and port.startswith(':') and port[1:].isdigit():
            ip_string = ip_core.lstrip('[')
            logging.debug(f"Stripped port from bracketed IPv6: {original!r} {ip_string!r}")
    # IPv4 or unbracketed IPv6: split on last colon only if it looks like a port
    elif ip_string.count(':') == 1:
        ip_part, port = ip_string.rsplit(':', 1)
        if port.isdigit():
            ip_string = ip_part
            logging.debug(f"Stripped port from IPv4/unbracketed: {original!r} {ip_string!r}")
    # else: leave IPv6 with multiple colons intact

    logging.info(f"Validating IP: {ip_string!r}")
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        logging.debug(f"Parsed IP object: {ip_obj} (version {ip_obj.version})")
    except ValueError:
        logging.error(f"Invalid IP syntax: {ip_string!r}")
        return False

    # exclusion categories
    if ip_obj.is_private:
        logging.info(f"Excluded private IP: {ip_obj}")
        return False
    if ip_obj.is_loopback:
        logging.info(f"Excluded loopback IP: {ip_obj}")
        return False
    if ip_obj.is_link_local:
        logging.info(f"Excluded link-local IP: {ip_obj}")
        return False
    if ip_obj.is_multicast:
        logging.info(f"Excluded multicast IP: {ip_obj}")
        return False
    if ip_obj.is_reserved:
        logging.info(f"Excluded reserved IP: {ip_obj}")
        return False

    # valid public IP
    logging.info(f"Valid public IPv{ip_obj.version} address: {ip_obj}")
    return True

def sanitize_filename(filename: str) -> str:
    """
    Sanitize the filename by replacing invalid characters for Windows.
    """
    return filename.replace(':', '_').replace('\\', '_').replace('/', '_')

def ublock_detect(url):
    """
    Check if the given URL should be detected by the uBlock-style rule.

    The rule matches:
      - URLs that fit the regex pattern.
      - Only applies to main document requests.

    The exception: if the URL includes 'steamcommunity.com', then the rule is not applied.
    """
    # First, check if the URL matches the regex pattern.
    if not UBLOCK_REGEX.match(url):
        return False

    # Apply exception: if the URL's domain includes "steamcommunity.com", ignore it.
    if 'steamcommunity.com' in url:
        return False

    return True

def get_resource_name(entry):
    # Get the resource name, which might be a string or an ID
    if hasattr(entry, 'name') and entry.name is not None:
        return str(entry.name)
    else:
        return str(entry.id)

# Read the file types from extensions.txt with try-except
fileTypes = []
try:
    if os.path.exists(extensions_path):
        with open(extensions_path, 'r') as ext_file:
            fileTypes = [line.strip() for line in ext_file.readlines()]
except Exception as ex:
    logging.info(f"Error reading {extensions_path}: {ex}")

logging.info(f"File types read from {extensions_path}: {fileTypes}")

# Read antivirus process list from antivirusprocesslist.txt with try-except.
antivirus_process_list = []
try:
    if os.path.exists(antivirus_process_list_path):
        with open(antivirus_process_list_path, 'r') as av_file:
            antivirus_process_list = [line.strip() for line in av_file if line.strip()]
except Exception as ex:
    logging.info(f"Error reading {antivirus_process_list_path}: {ex}")

logging.info(f"Antivirus process list read from {antivirus_process_list_path}: {antivirus_process_list}")

pe_file_paths = []  # List to store the PE file paths

# Initialize an empty dictionary for magic_bytes
magic_bytes = {}

try:
    # Read the magicbytes.txt file and populate the dictionary
    with open(magic_bytes_path, "r") as file:
        for line in file:
            # Split each line into magic bytes and file type
            parts = line.strip().split(": ")
            if len(parts) == 2:
                magic, file_type = parts
                magic_bytes[magic] = file_type

    # If reading and processing is successful, logging.info the dictionary
    logging.info("Magic bytes have been successfully loaded.")

except FileNotFoundError:
    logging.error(f"Error: The file {magic_bytes_path} was not found.")
except Exception as e:
    logging.error(f"An error occurred: {e}")

def get_unique_output_path(output_dir: Path, base_name) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    base_name = Path(base_name)  # <- convert here

    stem = sanitize_filename(base_name.stem)
    suffix = base_name.suffix

    timestamp = int(time.time())
    candidate = output_dir / f"{stem}_{timestamp}{suffix}"

    if candidate.exists():
        counter = 1
        while True:
            candidate = output_dir / f"{stem}_{timestamp}_{counter}{suffix}"
            if not candidate.exists():
                break
            counter += 1

    return candidate

#inspired by https://aluigi.altervista.org/bms/advanced_installer.bms
#with some additionaly reverse engeneering, quite heursitic (footer search, xor guessing etc)
#licence: public domain
# https://gist.github.com/KasparNagu/9ee02cb62d81d9e4c7a833518a710d6e

class AdvancedInstallerFileInfo:
    def __init__(self, name, size, offset, xorSize):
        self.name = name
        self.size = size
        self.offset = offset
        self.xorSize = xorSize

    def __repr__(self):
        return "[%s size=%d offset=%d]" % (self.name, self.size, self.offset)


class AdvancedInstallerFileReader:
    def __init__(self, filehandle, size, keepOpen, xorLength):
        self.filehandle = filehandle
        self.size = size
        self.xorLength = xorLength
        self.pos = 0
        self.keepOpen = keepOpen

    def xorFF(self, block):
        if isinstance(block, str):
            return "".join([chr(ord(i) ^ 0xff) for i in block])
        else:
            return bytes([i ^ 0xff for i in block])

    def read(self, size=None):
        if size is None:
            return self.read(self.size - self.pos)
        if self.pos < self.xorLength:
            xorLen = min(self.xorLength - self.pos, size)
            xorBlock = self.filehandle.read(xorLen)
            xorLenEffective = len(xorBlock)
            self.pos += xorLenEffective
            xorBlock = self.xorFF(xorBlock)
            if xorLenEffective < size:
                return xorBlock + self.read(size - xorLenEffective)
            return xorBlock
        blk = self.filehandle.read(min(size, self.size - self.pos))
        self.pos += len(blk)
        return blk

    def close(self):
        if not self.keepOpen:
            self.filehandle.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()


class AdvancedInstallerReader:
    def __init__(self, filename, debug=None):
        self.filename = filename
        self.filehandle = open(filename, "rb")
        self.search_back = 10000
        self.xorSize = 0x200
        self.footer_position = None
        self.debug = debug
        self.threadsafeReopen = False
        self.files = []

    def close(self):
        self.filehandle.close()

    def search_footer(self):
        for i in range(0, 10000):
            self.filehandle.seek(-i, os.SEEK_END)
            magic = self.filehandle.read(10)
            if magic == b"ADVINSTSFX":
                self.footer_position = i + 0x48 - 12
                break
        if self.footer_position is None:
            logging.error("ADVINSTSFX not found")

    def read_footer(self):
        if self.footer_position is None:
            self.search_footer()
        self.filehandle.seek(-self.footer_position, os.SEEK_END)
        footer = self.filehandle.read(0x48)

        if self.debug:
            self.debug.write("Footer data (%d bytes): %s\n" % (len(footer), footer.hex()))

        # Try different unpacking strategies based on actual footer structure
        try:
            # Original format - try first
            offset, self.nfiles, _, offset1, self.info_off, file_off, hexhash, _, name = struct.unpack(
                "<llllll32sl12s", footer)
        except struct.error:
            try:
                # Alternative format without the last name field
                data = struct.unpack("<llllll32sl", footer[:60])
                offset, self.nfiles, _, offset1, self.info_off, file_off, hexhash, _ = data
                name = footer[60:] if len(footer) > 60 else b""
            except struct.error:
                try:
                    # Simplified format - just the essential fields
                    data = struct.unpack("<llllll", footer[:24])
                    offset, self.nfiles, _, offset1, self.info_off, file_off = data
                    hexhash = footer[24:56] if len(footer) > 56 else b""
                    name = footer[56:] if len(footer) > 56 else b""
                except struct.error:
                    # Last resort - extract what we can
                    if len(footer) >= 8:
                        offset, self.nfiles = struct.unpack("<ll", footer[:8])
                        offset1 = 0
                        self.info_off = struct.unpack("<l", footer[16:20])[0] if len(footer) >= 20 else 0
                        file_off = struct.unpack("<l", footer[20:24])[0] if len(footer) >= 24 else 0
                    else:
                        logging.error("Footer too short to parse")
                    hexhash = b""
                    name = b""

        if self.debug:
            self.debug.write(
                "offset=%d files=%d offset1=%d  info_off=%d file_off=%d hexhash=%s name=%s\n" % (offset, self.nfiles,
                                                                                                 offset1, self.info_off,
                                                                                                 file_off, hexhash,
                                                                                                 name))

    def read_info(self):
        self.read_footer()
        self.files = []
        self.filehandle.seek(self.info_off, os.SEEK_SET)
        for i in range(0, self.nfiles):
            info = self.filehandle.read(24)
            if len(info) < 24:
                if self.debug:
                    self.debug.write("Warning: incomplete info block for file %d\n" % i)
                break
            _, _, xor_flag, size, offset, namesize = struct.unpack("<llllll", info)
            if self.debug:
                self.debug.write(
                    " size=%d offset=%d namesize=%d xor_flag=0x%x\n" % (size, offset, namesize, xor_flag))
            if 0 < namesize < 0xFFFF:
                name_data = self.filehandle.read(namesize * 2)
                if len(name_data) == namesize * 2:
                    try:
                        name = name_data.decode("UTF-16LE")
                        # Remove null terminator if present
                        name = name.rstrip('\x00')
                    except UnicodeDecodeError:
                        # Fallback to UTF-16BE or raw bytes
                        try:
                            name = name_data.decode("UTF-16BE")
                            name = name.rstrip('\x00')
                        except UnicodeDecodeError:
                            name = "file_%d.bin" % i
                    if self.debug:
                        self.debug.write("  name=%s\n" % name)
                    self.files.append(AdvancedInstallerFileInfo(name, size, offset, self.xorSize if xor_flag == 2 else 0))
                else:
                    if self.debug:
                        self.debug.write("Warning: incomplete name data for file %d\n" % i)
            elif namesize == 0:
                # Handle files with no name
                name = "unnamed_file_%d.bin" % i
                if self.debug:
                    self.debug.write("  name=%s (unnamed)\n" % name)
                self.files.append(AdvancedInstallerFileInfo(name, size, offset, self.xorSize if xor_flag == 2 else 0))
            else:
                if self.debug:
                    self.debug.write("Warning: Invalid name size %d for file %d\n" % (namesize, i))
                # Skip this file or use a default name
                continue

    def open(self, infoFile):
        if isinstance(infoFile, AdvancedInstallerFileInfo):
            if self.threadsafeReopen:
                fh = open(self.filename, "rb")
            else:
                fh = self.filehandle
            fh.seek(infoFile.offset, os.SEEK_SET)
            return AdvancedInstallerFileReader(fh, infoFile.size, not self.threadsafeReopen, infoFile.xorSize)
        else:
            if not self.files:
                self.read_info()
            for f in self.files:
                if f.name == infoFile:
                    return self.open(f)
        return None

    def infolist(self):
        if not self.files:
            self.read_info()
        return self.files

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __repr__(self):
        return "[path=%s footer=%s nFiles=%d]" % (self.filename, self.footer_position, len(self.files))

def advanced_installer_extractor(file_path):
        """
        Extract files from Advanced Installer archive.

        Args:
            file_path (str): Path to the Advanced Installer file

        Returns:
            list: List of extracted file paths
        """
        extracted_files = []

        with AdvancedInstallerReader(file_path) as ar:
                for f in ar.infolist():
                        logging.debug(f)
                        path = f.name.replace("\\","/")
                        full_path = os.path.join(advanced_installer_extracted_dir, path)
                        dirname = os.path.dirname(full_path)
                        if dirname:
                                if not os.path.exists(dirname):
                                        os.makedirs(dirname)
                        with ar.open(f) as inf, open(full_path,"wb") as out:
                                while True:
                                         blk = inf.read(1<<16)
                                         if len(blk) == 0:
                                                 break
                                         out.write(blk)
                        extracted_files.append(full_path)

                logging.debug(ar)

        return extracted_files

def analyze_file_with_die(file_path):
    """
    Runs Detect It Easy (DIE) on the given file once and returns the DIE output (plain text).
    The output is also saved to a unique .txt file.
    """
    try:
        logging.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(deteciteasy_plain_text_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Define the base name for the output text file
        base_name = Path(file_path).with_suffix(".txt")
        txt_output_path = get_unique_output_path(output_dir, base_name)

        # Run the DIE command once with the -p flag for plain output
        result = subprocess.run(
            [detectiteasy_console_path, "-p", file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore"
        )

        # Save the plain text output
        with open(txt_output_path, "w", encoding="utf-8") as txt_file:
            txt_file.write(result.stdout)

        logging.info(f"Analysis result saved to {txt_output_path}")
        return result.stdout

    except subprocess.SubprocessError as ex:
        logging.error(
            f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}"
        )
        return None
    except Exception as ex:
        logging.error(
            f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}"
        )
        return None

def get_die_output(path: str) -> Tuple[str, bool]:
    """
    Returns (die_output, plain_text_flag), caching results by content MD5.
    """
    file_md5 = compute_md5(path)
    if file_md5 in die_cache:
        return die_cache[file_md5]

    # first time for this content:
    with open(path, "rb") as f:
        peek = f.read(8192)
    if is_plain_text(peek):
        die_output = "Binary\n    Format: plain text"
        plain_text_flag = True
    else:
        die_output = analyze_file_with_die(path)
        plain_text_flag = is_plain_text_data(die_output)

    die_cache[file_md5] = (die_output, plain_text_flag)
    return die_output, plain_text_flag

def get_die_output_binary(path: str) -> str:
    """
    Returns die_output for a non plain text file, caching by content MD5.
    (Assumes the file isn't plain text, so always calls analyze_file_with_die()
     on cache miss.)
    """
    file_md5 = compute_md5(path)
    if file_md5 in binary_die_cache:
        return binary_die_cache[file_md5]

    # First time for this content: run DIE and cache
    die_output = analyze_file_with_die(path)
    binary_die_cache[file_md5] = die_output
    return die_output

def is_go_garble_from_output(die_output):
    """
    Check if the DIE output indicates a Go garbled file.
    A file is considered garble if the output contains:
      - "Compiler: Go(unknown)"
    """
    if die_output and ("Compiler: Go(unknown)" in die_output):
        logging.info("DIE output indicates a garbled Go file.")
        return True
    logging.info(f"DIE output does not indicate a garbled Go file: {die_output}")
    return False

def is_pyc_file_from_output(die_output):
    """
    Check if the DIE output indicates a Python compiled module (.pyc file).
    It looks for markers that suggest it's a Python compiled module.
    """
    if die_output and "Python Compiled Module" in die_output:
        logging.info("DIE output indicates a Python compiled module.")
        return True
    logging.info(f"DIE output does not indicate a Python compiled module: {die_output}")
    return False

def is_pe_file_from_output(die_output):
    """Checks if DIE output indicates a PE (Portable Executable) file."""
    if die_output and ("PE32" in die_output or "PE64" in die_output):
        logging.info("DIE output indicates a PE file.")
        return True
    logging.info(f"DIE output does not indicate a PE file: {die_output}")
    return False

def is_advanced_installer_file_from_output(die_output):
    """Checks if DIE output indicates a Advanced Installer file."""
    if die_output and ("Advanced Installer" in die_output):
        logging.info("DIE output indicates a Advanced Installer file.")
        return True
    logging.info(f"DIE output does not indicate a Advanced Installer file: {die_output}")
    return False

def is_nsis_from_output(die_output: str) -> bool:
    """Checks if DIE output indicates an NSIS installer file."""
    if not die_output:
        logging.info("DIE output is empty or None.")
        return False

    # Look for NSIS installer signatures in the output
    indicators = [
        "Nullsoft Scriptable Install System",  # e.g. Installer: Nullsoft Scriptable Install System(2.46-Unicode)[lzma]
        "Data: NSIS data"
    ]

    if any(indicator in die_output for indicator in indicators):
        logging.info("DIE output indicates an NSIS installer.")
        return True

    logging.info(f"DIE output does not indicate an NSIS installer: {die_output!r}")
    return False

def is_elf_file_from_output(die_output):
    """Checks if DIE output indicates an ELF file."""
    if die_output and ("ELF32" in die_output or "ELF64" in die_output):
        logging.info("DIE output indicates an ELF file.")
        return True
    logging.info(f"DIE output does not indicate an ELF file: {die_output}")
    return False

def is_enigma1_protector(die_output):
    """
    Checks if DIE output indicates the Enigma protector.
    Returns True if 'Protector: Enigma' is found, else False.
    """
    if die_output and ".enigma1" in die_output:
        logging.info("DIE output indicates Protector: Enigma.")
        return True

    logging.info(f"DIE output does not indicate Protector: Enigma: {die_output}")
    return False

def is_macho_file_from_output(die_output):
    """Checks if DIE output indicates a Mach-O file."""
    if die_output and "Mach-O" in die_output:
        logging.info("DIE output indicates a Mach-O file.")
        return True
    logging.info(f"DIE output does not indicate a Mach-O file: {die_output}")
    return False

def is_dotnet_file_from_output(die_output):
    """
    Checks if DIE output indicates a .NET executable file.

    Returns:
      - False
        if "C++" appears anywhere in the output.
      - "Protector: Obfuscar" or "Protector: Obfuscar(<version>)"
        if it's protected with Obfuscar.
      - "Protector: <Name>" or "Protector: <Name>(<version>)"
        for any other Protector: marker (full line captured).
      - True
        if it's a .NET file and no protector is detected.
      - None
        if none of these markers are found.
    """
    if not die_output:
        logging.info("Empty DIE output; no .NET markers found.")
        return None

    # 0) If it contains a C++ indicator, treat as non-.NET and return False
    if "C++" in die_output:
        logging.info("DIE output indicates native C++; not a .NET assembly.")
        return False

    # 1) Specific Obfuscar protector
    obfuscar_match = re.search(r'Protector:\s*Obfuscar(?:\(([^)]+)\))?', die_output)
    if obfuscar_match:
        version = obfuscar_match.group(1)
        result = f"Protector: Obfuscar({version})" if version else "Protector: Obfuscar"
        logging.info(f"DIE output indicates a .NET assembly protected with {result}.")
        return result

    # 2) Generic Protector marker – capture the full line
    line_match = re.search(r'^Protector:.*$', die_output, re.MULTILINE)
    if line_match:
        marker = line_match.group(0).strip()
        logging.info(f"DIE output indicates .NET assembly requires de4dot: {marker}.")
        return marker

    # 3) .NET runtime indication (only if no protector found)
    if ".NET" in die_output:
        logging.info("DIE output indicates a .NET executable without protection.")
        return True

    # 4) Nothing .NET/protector-related found
    logging.info(f"DIE output does not indicate a .NET executable or known protector: {die_output!r}")
    return None

def is_file_fully_unknown(die_output: str) -> bool:
    """
    Determines whether DIE output indicates an unrecognized binary file,
    ignoring any trailing error messages or extra lines.

    Returns True if the first two non-empty, whitespace-stripped lines are:
        Binary
        Unknown: Unknown
    """
    if not die_output:
        logging.info("No DIE output provided.")
        return False

    # Normalize: split into lines, strip whitespace, drop empty lines
    lines = [line.strip() for line in die_output.splitlines() if line.strip()]

    # We only care about the first two markers; ignore anything after.
    if len(lines) >= 2 and lines[0] == "Binary" and lines[1] == "Unknown: Unknown":
        logging.info("DIE output indicates an unknown file (ignoring extra errors).")
        return True
    else:
        logging.info(f"DIE output does not indicate an unknown file: {die_output!r}")
        return False

def is_packer_upx_output(die_output):
    """
    Checks if DIE output indicates that the file is packed with UPX.
    Looks for the marker 'Packer: UPX' (optionally with version/modifier).
    """
    if die_output and re.search(r"Packer:\s*UPX\b", die_output):
        logging.info("DIE output indicates UPX packer.")
        return True

    logging.info(f"DIE output does not indicate UPX packer: {die_output}")
    return False

def is_jar_file_from_output(die_output):
    """Checks if DIE output indicates a JAR file (Java archive)."""
    if die_output and "Virtual machine: JVM" in die_output:
        logging.info("DIE output indicates a JAR file.")
        return True
    logging.info(f"DIE output does not indicate a JAR file: {die_output}")
    return False

def is_java_class_from_output(die_output):
    """
    Checks if the DIE output indicates a Java class file.
    It does this by looking for 'Format: Java Class File' in the output.
    """
    if die_output and "Format: Java Class " in die_output:
        logging.info("DIE output indicates a Java class file.")
        return True
    logging.info(f"DIE output does not indicate a Java class file: {die_output}")
    return False

def debloat_pe_file(file_path):
    """
    Runs debloat.processor.process_pe on a PE file, writing all
    output into its own uniquely-named subdirectory of debloat_dir.
    """
    try:
        logging.info(f"Debloating PE file {file_path} for faster scanning.")

        # Flag for last-ditch processing
        last_ditch_processing = False

        # Normalize paths
        file_path = Path(file_path)
        base_dir  = Path(debloat_dir)

        # Build a unique output directory: debloat_dir/<stem>_<n>
        output_dir = base_dir / file_path.stem
        suffix = 1
        while output_dir.exists():
            output_dir = base_dir / f"{file_path.stem}_{suffix}"
            suffix += 1
        output_dir.mkdir(parents=True)

        # Load the PE into memory
        pe_data = file_path.read_bytes()
        pe      = pefile.PE(data=pe_data, fast_load=True)

        # Wrap logging.info so it accepts and ignores an 'end' kwarg
        def log_message(msg, *args, **kwargs):
            kwargs.pop('end', None)      # drop any 'end' argument
            logging.info(msg, *args, **kwargs)

        # Debloat into our new directory
        debloat.processor.process_pe(
            pe,
            log_message=log_message,
            last_ditch_processing=last_ditch_processing,
            out_path=str(output_dir),   # pass the folder path
            cert_preservation=True
        )

        # Verify that something landed in there
        if any(output_dir.iterdir()):
            logging.info(f"Debloated file(s) saved in: {output_dir}")
            return str(output_dir)
        else:
            logging.error(f"Debloating failed for {file_path}; {output_dir} is empty.")
            return None

    except Exception as ex:
        logging.error("Error during debloating of %s: %s", file_path, ex)

def remove_magic_bytes(data_content, die_output):
    """Remove magic bytes from data, considering it might be hex-encoded."""
    try:
        if is_plain_text_data(die_output):
            # Convert binary data to hex representation for easier pattern removal
            hex_data = binascii.hexlify(data_content).decode("utf-8", errors="ignore")

            # Remove magic bytes by applying regex patterns
            for magic_byte in magic_bytes.keys():
                pattern = re.compile(rf'{magic_byte}', re.IGNORECASE)
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
                pattern = re.compile(rf'{magic_byte}', re.IGNORECASE)
                hex_data = pattern.sub('', hex_data)

            try:
                return binascii.unhexlify(hex_data)
            except Exception as ex:
                logging.error(f"Error unhexlifying data: {ex}")
                return data_content  # Return original data if unhexlifying fails
    except Exception as ex:
        logging.error(f"Unexpected error in remove_magic_bytes: {ex}")
        return data_content  # Return original data in case of unexpected errors

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

def save_to_file(file_path, content):
    """
    Saves content to a file in the 'python_deobfuscated_dir' directory and returns the file path.

    Args:
        file_path: Path to the file.
        content: Content to save.

    Returns:
        file_path: Path to the saved file.
    """

    # Update the file path to save within the specified directory
    file_path = os.path.join(python_deobfuscated_dir, file_path)

    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        return file_path
    except Exception as ex:
        logging.error(f"Error saving file {file_path}: {ex}")
        return None

def decode_base64(data_content):
    """Decode base64-encoded data."""
    try:
        return base64.b64decode(data_content, validate=True)
    except (binascii.Error, ValueError):
        logging.error("Base64 decoding failed.")
        return None

def decode_b64_import(match: re.Match) -> str:
    """Decode base64 constant to literal bytes or string repr."""
    raw = match.group(2)
    try:
        data = __import__('base64').b64decode(raw)
        try:
            s = data.decode('utf-8')
            return repr(s)
        except UnicodeDecodeError:
            return repr(data)
    except Exception:
        return match.group(0)

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

# match only Base64 characters plus 0_2 padding"="
_BASE64_RE = re.compile(br'^[A-Za-z0-9+/]+={0,2}$')

# match only Base32 chars A_Z2_7 plus up to 6"=" padding at end
_BASE32_RE = re.compile(br'^[A-Z2-7]+={0,6}$')

def is_base32(data: bytes) -> bool:
    """
    Return True if `data` consists entirely of Base32 chars
    and up to six '=' padding bytes at the end.
    """
    # strip whitespace/newlines before testing
    data = data.strip().upper()  # Base32 is case insensitive, normalize to uppercase
    return bool(_BASE32_RE.fullmatch(data))

def is_base64(data: bytes) -> bool:
    """
    Return True if `data` consists entirely of Base64 chars
    and up to two '=' padding bytes at the end.
    """
    # strip any whitespace/newlines before testing
    data = data.strip()
    return bool(_BASE64_RE.fullmatch(data))

def process_file_data(file_path, die_output):
    """Process file data by decoding, removing magic bytes, and emitting a reversed lines version, saving outputs with .txt extension."""
    try:
        with open(file_path, 'rb') as data_file:
            data_content = data_file.read()

        # Peel off Base64/Base32 layers
        while True:
            # Base-64 first
            if isinstance(data_content, (bytes, bytearray)) and is_base64(data_content):
                decoded = decode_base64(data_content)
                if decoded is not None:
                    logging.info("Base64 layer removed.")
                    data_content = decoded
                    continue

            # then Base-32
            if isinstance(data_content, (bytes, bytearray)) and is_base32(data_content):
                decoded = decode_base32(data_content)
                if decoded is not None:
                    logging.info("Base32 layer removed.")
                    data_content = decoded
                    continue

            logging.info("No more base64 or base32 encoded data found.")
            break

        # strip out your magic bytes
        processed_data = remove_magic_bytes(data_content, die_output)

        # write the normal processed output with .txt extension
        base_name = os.path.basename(file_path)
        output_file_path = os.path.join(
            processed_dir,
            f'processed_{base_name}.txt'
        )
        with open(output_file_path, 'wb') as processed_file:
            processed_file.write(processed_data)
        logging.info(f"Processed data from {file_path} saved to {output_file_path}")

        # now create a reversed lines variant with .txt extension
        lines = processed_data.splitlines(keepends=True)
        reversed_lines_data = b''.join(lines[::-1])

        reversed_output_path = os.path.join(
            processed_dir,
            f'processed_reversed_lines_{base_name}.txt'
        )
        with open(reversed_output_path, 'wb') as rev_file:
            rev_file.write(reversed_lines_data)
        logging.info(f"Reversed lines data from {file_path} saved to {reversed_output_path}")

    except Exception as ex:
        logging.error(f"Error processing file {file_path}: {ex}")

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
          return {}

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
                    logging.info(f"Bound import {bound_import['name']} has no references.")

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

def notify_user(file_path, virus_name, engine_detected):
    notification = Notify()
    notification.title = "Malware Alert"
    notification_message = f"Malicious file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_pua(file_path, virus_name, engine_detected):
    notification = Notify()
    notification.title = "PUA Alert"
    notification_message = f"PUA file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_for_malicious_source_code(file_path, virus_name):
    """
    Sends a notification about malicious source code detected.
    """
    notification = Notify()
    notification.title = f"Malicious Source Code detected: {virus_name}"
    notification_message = f"Suspicious source code detected in: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.error(notification_message)

def notify_user_for_detected_command(message, file_path):
    notification = Notify()
    notification.title = "Malware Message Alert"
    notification.message = (
        f"{message}\n\n"
        f"Related to: {file_path}\n"
        f"(This does not necessarily mean the file is malware.)"
    )

    notification.send()
    logging.warning(f"Notification: {notification.message}")


def notify_user_for_meta_llama(file_path, virus_name, malware_status, HiJackThis_flag=False):
    notification = Notify()
    if HiJackThis_flag:
        notification.title = "Meta Llama-3.2-1B Security HiJackThis Alert"  # Updated title
    else:
        notification.title = "Meta Llama-3.2-1B Security Alert"  # Updated title

    if malware_status.lower() == "maybe":
        notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    elif malware_status.lower() == "yes":
        notification_message = f"Malware detected: {file_path}\nVirus: {virus_name}"

    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_size_warning(file_path, archive_type, virus_name):
    """Send a notification for size-related warnings."""
    notification = Notify()
    notification.title = "Size Warning"
    notification_message = (f"{archive_type} file {file_path} is smaller than 20MB but contains a large file "
                            f"which might be suspicious. Virus Name: {virus_name}")
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_susp_archive_file_name_warning(file_path, archive_type, virus_name):
    """Send a notification for warnings related to suspicious filenames in archive files."""
    notification = Notify()
    notification.title = "Suspicious Filename In Archive Warning"
    notification_message = (
        f"The filename in the {archive_type} archive '{file_path}' contains a suspicious pattern: {virus_name}."
    )
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_susp_name(file_path, virus_name):
    notification = Notify()
    notification.title = "Suspicious Name Alert"
    notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_scr(file_path, virus_name):
    """
    Notifies the user about a suspicious .scr PE file.
    """
    notification = Notify()
    notification.title = "Suspicious .SCR File Detected"
    notification_message = f"Suspicious .scr file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(f"ALERT: {notification_message}")

def notify_user_etw_tampering(file_path, virus_name):
    notification = Notify()
    notification.title = "ETW Tampering Alert"
    notification_message = f"ETW Tampering detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_for_detected_fake_system_file(file_path, file_name, virus_name):
    notification = Notify()
    notification.title = "Fake System File Alert"
    notification_message = (
        f"Fake system file detected:\n"
        f"File Path: {file_path}\n"
        f"File Name: {file_name}\n"
        f"Threat: {virus_name}"
    )
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_for_detected_rootkit(file_path, virus_name):
    notification = Notify()
    notification.title = "Rootkit Detection Alert"
    notification_message = (
        f"Potential rootkit file detected:\n"
        f"File Path: {file_path}\n"
        f"Threat: {virus_name}"
    )
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_invalid(file_path, virus_name):
    notification = Notify()
    notification.title = "Invalid signature Alert"
    notification_message = f"Invalid signature file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_fake_size(file_path, virus_name):
    notification = Notify()
    notification.title = "Fake Size Alert"
    notification_message = f"Fake size file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_startup(file_path, message):
    """Notify the user about suspicious or malicious startup files."""
    notification = Notify()
    notification.title = "Startup File Alert"

    # Include file_path in the message
    notification_message = f"File: {file_path}\n{message}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_uefi(file_path, virus_name):
    notification = Notify()
    notification.title = "UEFI Malware Alert"
    notification_message = f"Suspicious UEFI file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_ransomware(file_path, virus_name):
    notification = Notify()
    notification.title = "Ransomware Alert"
    notification_message = f"Potential ransomware detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_exela_stealer_v2(file_path, virus_name):
    notification = Notify()
    notification.title = "Exela Stealer version 2 Alert in Python source code"
    notification_message = f"Potential Exela Stealer version 2 detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_hosts(file_path, virus_name):
    notification = Notify()
    notification.title = "Host Hijacker Alert"
    notification_message = f"Potential host hijacker detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_worm(file_path, virus_name):
    notification = Notify()
    notification.title = "Worm Alert"
    notification_message = f"Potential worm detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_for_web(domain=None, ipv4_address=None, ipv6_address=None, url=None, file_path=None, detection_type=None):
    notification = Notify()
    notification.title = "Malware or Phishing Alert"

    # Build the notification message dynamically
    message_parts = []
    if detection_type:
        message_parts.append(f"Detection Type: {detection_type}")
    if domain:
        message_parts.append(f"Domain: {domain}")
    if ipv4_address:
        message_parts.append(f"IPv4 Address: {ipv4_address}")
    if ipv6_address:
        message_parts.append(f"IPv6 Address: {ipv6_address}")
    if url:
        message_parts.append(f"URL: {url}")
    if file_path:
        message_parts.append(f"File Path: {file_path}")

    if message_parts:
        notification_message = "Phishing or Malicious activity detected:\n" + "\n".join(message_parts)
    else:
        notification_message = "Phishing or Malicious activity detected"

    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_for_hips(ip_address=None, dst_ip_address=None):
    notification = Notify()
    notification.title = "Malicious Activity Detected"

    if ip_address and dst_ip_address:
        notification_message = f"Malicious activity detected:\nSource: {ip_address}\nDestination: {dst_ip_address}"
    elif ip_address:
        notification_message = f"Malicious activity detected:\nSource IP Address: {ip_address}"
    elif dst_ip_address:
        notification_message = f"Malicious activity detected:\nDestination IP Address: {dst_ip_address}"
    else:
        notification_message = "Malicious activity detected"

    notification.message = notification_message
    notification.send()

    logging.warning(notification_message)

def notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status):
    """
    Function to send notification for detected HIPS file.
    """
    notification = Notify()
    notification.title = "Web Malware Alert For File"
    notification_message = f"{status} file detected by Web related Message: {file_path}\nSource IP: {src_ip}\nAlert Line: {alert_line}"
    notification.message = notification_message
    notification.send()
    logging.warning(notification_message)

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
        logging.info(f"{description} loaded successfully!")
        return signatures
    except Exception as ex:
        logging.error(f"Error loading {description}: {ex}")
        return []

def load_website_data():
    global ipv4_addresses_signatures_data, ipv4_addresses_spam_signatures_data, ipv4_whitelist_data, ipv4_addresses_bruteforce_signatures_data, ipv4_addresses_phishing_active_signatures_data, ipv4_addresses_phishing_inactive_signatures_data, ipv6_addresses_signatures_data, ipv6_addresses_spam_signatures_data, ipv6_addresses_ddos_signatures_data, ipv4_addresses_ddos_signatures_data, ipv6_whitelist_data, urlhaus_data, malware_domains_data, malware_domains_mail_data, phishing_domains_data, abuse_domains_data, mining_domains_data, spam_domains_data, whitelist_domains_data, whitelist_domains_mail_data, malware_sub_domains_data, malware_mail_sub_domains_data, phishing_sub_domains_data, abuse_sub_domains_data, mining_sub_domains_data, spam_sub_domains_data, whitelist_sub_domains_data, whitelist_mail_sub_domains_data

    try:
        # Load IPv4 Malicious addresses
        with open(ipv4_addresses_path, 'r') as ip_malicious_file:
            ipv4_addresses_signatures_data = ip_malicious_file.read().splitlines()
        logging.info("Malicious IPv4 Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading malicious IPv4 Addresses: {ex}")

    try:
        # Load IPv4 Spam addresses
        with open(ipv4_addresses_spam_path, 'r') as ip_spam_file:
            ipv4_addresses_spam_signatures_data = ip_spam_file.read().splitlines()
        logging.info("Spam IPv4 Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading spam IPv4 Addresses: {ex}")

    try:
        # Load IPv6 Spam addresses
        with open(ipv6_addresses_spam_path, 'r') as ipv6_spam_file:
            ipv6_addresses_spam_signatures_data = ipv6_spam_file.read().splitlines()
        logging.info("IPv6 Spam Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv6 spam Addresses: {ex}")

    try:
        # Load BruteForce IPv4 addresses
        with open(ipv4_addresses_bruteforce_path, 'r') as ip_bruteforce_file:
            ipv4_addresses_bruteforce_signatures_data = ip_bruteforce_file.read().splitlines()
        logging.info("Malicious IPv4 Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading malicious IPv4 Addresses: {ex}")

    try:
        # Load phishing active IPv4 addresses
        with open(ipv4_addresses_phishing_active_path, 'r') as ip_phishing_active_file:
            ipv4_addresses_phishing_active_signatures_data = ip_phishing_active_file.read().splitlines()
        logging.info("Active phishing IPv4 Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading active phishing IPv4 Addresses: {ex}")

    try:
        # Load phishing inactive IPv4 addresses
        with open(ipv4_addresses_phishing_inactive_path, 'r') as ip_phishing_inactive_file:
            ipv4_addresses_phishing_inactive_signatures_data = ip_phishing_inactive_file.read().splitlines()
        logging.info("Inactive phishing IPv4 Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading inactive phishing IPv4 Addresses: {ex}")

    try:
        # Load IPv4 whitelist
        with open(ipv4_whitelist_path, 'r') as whitelist_file:
            ipv4_whitelist_data = whitelist_file.read().splitlines()
        logging.info("IPv4 Whitelist loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv4 Whitelist: {ex}")

    try:
        # Load IPv6 Malicious addresses
        with open(ipv6_addresses_path, 'r') as ipv6_malicious_file:
            ipv6_addresses_signatures_data = ipv6_malicious_file.read().splitlines()
        logging.info("IPv6 Malicious Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv6 Malicious Addresses: {ex}")

    try:
        # Load IPv6 DDoS addresses
        with open(ipv6_addresses_ddos_path, 'r') as ipv6_ddos_file:
            ipv6_addresses_ddos_signatures_data = ipv6_ddos_file.read().splitlines()
        logging.info("IPv6 DDoS Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv6 DDoS Addresses: {ex}")

    try:
        # Load IPv4 DDoS addresses
        with open(ipv4_addresses_ddos_path, 'r') as ipv4_ddos_file:
            ipv4_addresses_ddos_signatures_data = ipv4_ddos_file.read().splitlines()
        logging.info("IPv4 DDoS Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv4 DDoS Addresses: {ex}")

    try:
        # Load IPv6 whitelist
        with open(ipv6_whitelist_path, 'r') as whitelist_file:
            ipv6_whitelist_data = whitelist_file.read().splitlines()
        logging.info("IPv6 Whitelist loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv6 Whitelist: {ex}")
        ipv6_whitelist_data = []

    try:
        # Load URLhaus data
        urlhaus_data = []
        with open(urlhaus_path, 'r') as urlhaus_file:
            reader = csv.DictReader(urlhaus_file)
            for row in reader:
                urlhaus_data.append(row)
        logging.info("URLhaus data loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading URLhaus data: {ex}")

    try:
        # Load malware domains
        with open(malware_domains_path, 'r') as domains_file:
            malware_domains_data = domains_file.read().splitlines()
        logging.info("Malware domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware domains: {ex}")
        malware_domains_data = []

    try:
        # Load malware domains email path
        with open(malware_domains_mail_path, 'r') as mail_domains_file:
            malware_domains_mail_data = mail_domains_file.read().splitlines()
        logging.info("Malware email domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware email domains: {ex}")
        malware_domains_mail_data = []

    try:
        # Load phishing domains
        with open(phishing_domains_path, 'r') as domains_file:
            phishing_domains_data = domains_file.read().splitlines()
        logging.info("Phishing domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Phishing domains: {ex}")
        phishing_domains_data = []

    try:
        # Load abuse domains
        with open(abuse_domains_path, 'r') as domains_file:
            abuse_domains_data = domains_file.read().splitlines()
        logging.info("Abuse domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Abuse domains: {ex}")
        abuse_domains_data = []

    try:
        # Load mining domains
        with open(mining_domains_path, 'r') as domains_file:
            mining_domains_data = domains_file.read().splitlines()
        logging.info("Mining domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Mining domains: {ex}")
        mining_domains_data = []

    try:
        # Load spam domains
        with open(spam_domains_path, 'r') as domains_file:
            spam_domains_data = domains_file.read().splitlines()
        logging.info("Spam domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Spam domains: {ex}")
        spam_domains_data = []

    try:
        # Load whitelist domains
        with open(whitelist_domains_path, 'r') as domains_file:
            whitelist_domains_data = domains_file.read().splitlines()
        logging.info("Whitelist domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Whitelist domains: {ex}")
        whitelist_domains_data = []

    try:
        # Load whitelist mail domains
        with open(whitelist_domains_mail_path, 'r') as domains_file:
            whitelist_domains_mail_data = domains_file.read().splitlines()
        logging.info("Whitelist mail domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Whitelist mail domains: {ex}")
        whitelist_domains_mail_data = []

    try:
        # Load Malware subdomains
        with open(malware_sub_domains_path, 'r') as file:
            malware_sub_domains_data = file.read().splitlines()
        logging.info("Malware subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware subdomains: {ex}")
        malware_sub_domains_data = []

    try:
        # Load Malware mail subdomains
        with open(malware_mail_sub_domains_path, 'r') as file:
            malware_mail_sub_domains_data = file.read().splitlines()
        logging.info("Malware mail subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware mail subdomains: {ex}")
        malware_mail_sub_domains_data = []

    try:
        # Load Phishing subdomains
        with open(phishing_sub_domains_path, 'r') as file:
            phishing_sub_domains_data = file.read().splitlines()
        logging.info("Phishing subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Phishing subdomains: {ex}")
        phishing_sub_domains_data = []

    try:
        # Load Abuse subdomains
        with open(abuse_sub_domains_path, 'r') as file:
            abuse_sub_domains_data = file.read().splitlines()
        logging.info("Abuse subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Abuse subdomains: {ex}")
        abuse_sub_domains_data = []

    try:
        # Load Mining subdomains
        with open(mining_sub_domains_path, 'r') as file:
            mining_sub_domains_data = file.read().splitlines()
        logging.info("Mining subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Mining subdomains: {ex}")
        mining_sub_domains_data = []

    try:
        # Load Spam subdomains
        with open(spam_sub_domains_path, 'r') as file:
            spam_sub_domains_data = file.read().splitlines()
        logging.info("Spam subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Spam subdomains: {ex}")
        spam_sub_domains_data = []

    try:
        # Load Whitelist subdomains
        with open(whitelist_sub_domains_path, 'r') as file:
            whitelist_sub_domains_data = file.read().splitlines()
        logging.info("Whitelist subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Whitelist subdomains: {ex}")
        whitelist_sub_domains_data = []

    try:
        # Load Whitelist mail subdomains
        with open(whitelist_mail_sub_domains_path, 'r') as file:
            whitelist_mail_sub_domains_data = file.read().splitlines()
        logging.info("Whitelist mail subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Whitelist mail subdomains: {ex}")
        whitelist_mail_sub_domains_data = []

    logging.info("All domain and ip address files loaded successfully!")

# --------------------------------------------------------------------------
# Check for Discord webhook URLs (including Canary)
def contains_discord_or_telegram_code(decompiled_code, file_path, cs_file_path=None, nsis_flag=False,
                            nuitka_flag=False, pyc_flag=False, pyc_meta_llama_flg=False, dotnet_flag=False):
    """
    Scan the decompiled code for Discord webhook URLs, Discord Canary webhook URLs or Telegram bot links.
    For every detection, log a warning and immediately notify the user with an explicit unique heuristic
    signature that depends on the flags provided.
    """
    # Perform matches (case-insensitive)
    discord_webhook_matches        = re.findall(discord_webhook_pattern, decompiled_code, flags=re.IGNORECASE)
    discord_canary_webhook_matches = re.findall(discord_canary_webhook_pattern, decompiled_code, flags=re.IGNORECASE)
    cdn_attachment_matches         = re.findall(cdn_attachment_pattern, decompiled_code, flags=re.IGNORECASE)

    # Telegram token (case-sensitive): run on original code
    telegram_token_matches = re.findall(telegram_token_pattern, decompiled_code)

    # Telegram keyword (case-insensitive)
    telegram_keyword_matches = re.findall(telegram_keyword_pattern, decompiled_code, flags=re.IGNORECASE)

    if discord_webhook_matches:
        if dotnet_flag:
            if cs_file_path:
                logging.warning(f"Discord webhook URL detected in .NET source code file: {cs_file_path} - Matches: {discord_webhook_matches}")
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Src.Discord.Webhook.DotNET')
            else:
                logging.warning(f"Discord webhook URL detected in .NET source code file: [cs_file_path not provided] - Matches: {discord_webhook_matches}")
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.DotNET')
        elif nuitka_flag:
            logging.warning(f"Discord webhook URL detected in Nuitka compiled file: {file_path} - Matches: {discord_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.Nuitka')
        elif nsis_flag:
            logging.warning(f"Discord webhook URL detected in NSIS script compiled file (.nsi): {file_path} - Matches: {discord_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.NSIS')
        elif pyc_flag or pyc_meta_llama_flg:
            logging.warning(f"Discord webhook URL detected in Python Compilled Module file: {file_path} - Matches: {discord_webhook_matches}")
            if pyc_meta_llama_flg:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.PYC.MetaLlama')
            else:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Webhook.PYC.Python')
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
        elif nsis_flag:
            logging.warning(f"Discord Canary webhook URL detected in NSIS script compiled file (.nsi): {file_path} - Matches: {discord_canary_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook.NSIS')
        elif pyc_flag or pyc_meta_llama_flg:
            logging.warning(f"Discord Canary webhook URL detected in Python Compilled Module file:{file_path} - Matches: {discord_canary_webhook_matches}")
            if pyc_meta_llama_flg:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook.PYC.Python.MetaLlama')
            else:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook.PYC.Python')
        else:
            logging.warning(f"Discord Canary webhook URL detected in decompiled code: {discord_canary_webhook_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.Canary.Webhook')

    if cdn_attachment_matches:
        if dotnet_flag:
            if cs_file_path:
                logging.warning(
                    f"Discord CDN attachment URL detected in .NET source code file: {cs_file_path} - Matches: {cdn_attachment_matches}")
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Src.Discord.CDNAttachment.DotNET')
            else:
                logging.warning(
                    f"Discord CDN attachment URL detected in .NET source code file: [cs_file_path not provided] - Matches: {cdn_attachment_matches}")
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.CDNAttachment.DotNET')
        elif nuitka_flag:
            logging.warning(
                f"Discord CDN attachment URL detected in Nuitka compiled file: {file_path} - Matches: {cdn_attachment_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.CDNAttachment.Nuitka')
        elif nsis_flag:
            logging.warning(
                f"Discord CDN attachment URL detected in NSIS script compiled file (.nsi): {file_path} - Matches: {cdn_attachment_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.CDNAttachment.NSIS')
        elif pyc_flag or pyc_meta_llama_flg:
            logging.warning(
                f"Discord CDN attachment URL detected in Python Compilled Module file: {file_path} - Matches: {cdn_attachment_matches}")
            if pyc_meta_llama_flg:
                notify_user_for_malicious_source_code(file_path,
                                                      'HEUR:Win32.Discord.CDNAttachment.PYC.Python.MetaLlama')
            else:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.CDNAttachment.PYC.Python')
        else:
            logging.warning(f"Discord CDN attachment URL detected in decompiled code: {cdn_attachment_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Discord.CDNAttachment')

    if telegram_token_matches and telegram_keyword_matches:
        if dotnet_flag:
            if cs_file_path:
                logging.warning(f"Telegram bot detected in .NET source code file: {cs_file_path} - Matches: {telegram_token_matches}")
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Src.Telegram.Bot.DotNET')
            else:
                logging.warning(f"Telegram bot detected in .NET source code file: [cs_file_path not provided] - Matches: {telegram_token_matches}")
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Telegram.Bot.DotNET')
        elif nuitka_flag:
            logging.warning(f"Telegram bot detected in Nuitka compiled file: {file_path} - Matches: {telegram_token_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Telegram.Bot.Nuitka')
        elif nsis_flag:
            logging.warning(f"Telegram bot detected in NSIS script compiled file (.nsi): {file_path} - Matches: {telegram_token_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Telegram.Bot.NSIS')
        elif pyc_flag or pyc_meta_llama_flg:
            logging.warning(f"Telegram bot detected in Python Compilled Module file: {file_path} - Matches: {telegram_token_matches}")
            if pyc_meta_llama_flg:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Telegram.Bot.PYC.Python.MetaLlama')
            else:
                notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Telegram.Bot.PYC.Python')
        else:
            logging.info(f"Telegram bot link detected in decompiled code: {telegram_token_matches}")
            notify_user_for_malicious_source_code(file_path, 'HEUR:Win32.Telegram.Bot')

# --------------------------------------------------------------------------
# Generalized scan for domains
def scan_domain_general(url, dotnet_flag=False, nsis_flag=False, nuitka_flag=False, pyc_flag=False, pyc_meta_llama_flg=False, homepage_flag=""):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            logging.error("Invalid URL or domain format")
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
                elif nsis_flag:
                    logging.warning(f"Spam subdomain detected in NSIS script compiled file (.nsi): {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.NSIS.Spam.SubDomain")
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Spam subdomain detected in Python compiled file: {full_domain}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.MetaLlama.Spam.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.Spam.SubDomain")
                else:
                    logging.warning(f"Spam subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Spam.SubDomain")
                if homepage_flag:
                    notify_user_for_malicious_source_code(full_domain, f"HEUR:Win32.Adware.{homepage_flag}.Spam.HomePage.gen")
                return

            if full_domain in mining_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Mining subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Mining.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Mining subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Mining.SubDomain")
                elif nsis_flag:
                    logging.warning(f"Mining subdomain detected in NSIS script compiled file (.nsi): {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.NSIS.Mining.SubDomain")
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Mining subdomain detected in Python compiled file: {full_domain}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.MetaLlama.Mining.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.Mining.SubDomain")
                else:
                    logging.warning(f"Mining subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Mining.SubDomain")
                if homepage_flag:
                    notify_user_for_malicious_source_code(full_domain, f"HEUR:Win32.Adware.{homepage_flag}.Mining.HomePage.gen")
                return

            if full_domain in abuse_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Abuse subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Abuse.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Abuse subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Abuse.SubDomain")
                elif nsis_flag:
                    logging.warning(f"Abuse subdomain detected in NSIS script compiled file (.nsi): {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.NSIS.Abuse.SubDomain")
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Abuse subdomain detected in Python compiled file: {full_domain}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.MetaLlama.Abuse.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.Abuse.SubDomain")
                else:
                    logging.warning(f"Abuse subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Abuse.SubDomain")
                if homepage_flag:
                    notify_user_for_malicious_source_code(full_domain, f"HEUR:Win32.Adware.{homepage_flag}.Abuse.HomePage.gen")
                return

            if full_domain in phishing_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Phishing subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Phishing.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Phishing subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Phishing.SubDomain")
                elif nsis_flag:
                    logging.warning(f"Phishing subdomain detected in NSIS script compiled file (.nsi): {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.NSIS.Phishing.SubDomain")
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Phishing subdomain detected in Python compiled file: {full_domain}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.MetaLlama.Phishing.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.Phishing.SubDomain")
                else:
                    logging.warning(f"Phishing subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Phishing.SubDomain")
                if homepage_flag:
                    notify_user_for_malicious_source_code(full_domain, f"HEUR:Win32.Adware.{homepage_flag}.Phishing.HomePage.gen")
                return

            if full_domain in malware_mail_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Malware mail subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Malware.Mail.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Malware mail subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Malware.Mail.SubDomain")
                elif nsis_flag:
                    logging.warning(f"Malware mail subdomain detected in NSIS script compiled file (.nsi): {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.NSIS.Malware.Mail.SubDomain")
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Malware mail subdomain detected in Python compiled file: {full_domain}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.MetaLlama.Malware.Mail.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.Malware.Mail.SubDomain")
                else:
                    logging.warning(f"Malware mail subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Malware.Mail.SubDomain")
                if homepage_flag:
                    notify_user_for_malicious_source_code(full_domain, f"HEUR:Win32.Adware.{homepage_flag}.Malware.HomePage.gen")
                return

            if full_domain in malware_sub_domains_data:
                if dotnet_flag:
                    logging.warning(f"Malware subdomain detected in .NET source code: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.DotNET.Malware.SubDomain")
                elif nuitka_flag:
                    logging.warning(f"Malware subdomain detected in Nuitka compiled file: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Nuitka.Malware.SubDomain")
                elif nsis_flag:
                    logging.warning(f"Malware subdomain detected in NSIS script compiled file (.nsi): {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.NSIS.Malware.SubDomain")
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Malware subdomain detected in Python compiled file: {full_domain}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.MetaLlama.Malware.SubDomain")
                    else:
                        notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.PYC.Python.Malware.SubDomain")
                else:
                    logging.warning(f"Malware subdomain detected: {full_domain}")
                    notify_user_for_malicious_source_code(full_domain, "HEUR:Win32.Malware.SubDomain")
                if homepage_flag:
                    notify_user_for_malicious_source_code(full_domain, f"HEUR:Win32.Adware.{homepage_flag}.Malware.HomePage.gen")
                return

        # Main domain threat checks
        if full_domain in spam_domains_data or main_domain in spam_domains_data:
            if dotnet_flag:
                logging.warning(f"Spam domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Spam.Domain")
            elif nuitka_flag:
                logging.warning(f"Spam domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Spam.Domain")
            elif nsis_flag:
                logging.warning(f"Spam domain detected in NSIS script compiled file (.nsi): {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.NSIS.Spam.Domain")
            elif pyc_flag or pyc_meta_llama_flg:
                logging.warning(f"Spam domain detected in Python compiled file: {main_domain}")
                if pyc_meta_llama_flg:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.MetaLlama.Spam.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.Spam.Domain")
            else:
                logging.warning(f"Spam domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Spam.Domain")
            if homepage_flag:
                notify_user_for_malicious_source_code(main_domain, f"HEUR:Win32.Adware.{homepage_flag}.Spam.HomePage.gen")
            return

        if full_domain in mining_domains_data or main_domain in mining_domains_data:
            if dotnet_flag:
                logging.warning(f"Mining domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Mining.Domain")
            elif nuitka_flag:
                logging.warning(f"Mining domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Mining.Domain")
            elif nsis_flag:
                logging.warning(f"Mining domain detected in NSIS script compiled file (.nsi): {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.NSIS.Mining.Domain")
            elif pyc_flag or pyc_meta_llama_flg:
                logging.warning(f"Mining domain detected in Python compiled file: {main_domain}")
                if pyc_meta_llama_flg:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.MetaLlama.Mining.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.Mining.Domain")
            else:
                logging.warning(f"Mining domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Mining.Domain")
            if homepage_flag:
                notify_user_for_malicious_source_code(main_domain, f"HEUR:Win32.Adware.{homepage_flag}.Mining.HomePage.gen")
            return

        if full_domain in abuse_domains_data or main_domain in abuse_domains_data:
            if dotnet_flag:
                logging.warning(f"Abuse domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Abuse.Domain")
            elif nuitka_flag:
                logging.warning(f"Abuse domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Abuse.Domain")
            elif nsis_flag:
                logging.warning(f"Abuse domain detected in NSIS script compiled file (.nsi): {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.NSIS.Abuse.Domain")
            elif pyc_flag or pyc_meta_llama_flg:
                logging.warning(f"Abuse domain detected in Python compiled file: {main_domain}")
                if pyc_meta_llama_flg:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.MetaLlama.Abuse.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.Abuse.Domain")
            else:
                logging.warning(f"Abuse domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Abuse.Domain")
            if homepage_flag:
                notify_user_for_malicious_source_code(main_domain, f"HEUR:Win32.Adware.{homepage_flag}.Abuse.HomePage.gen")
            return

        if full_domain in phishing_domains_data or main_domain in phishing_domains_data:
            if dotnet_flag:
                logging.warning(f"Phishing domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Phishing.Domain")
            elif nuitka_flag:
                logging.warning(f"Phishing domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Phishing.Domain")
            elif nsis_flag:
                logging.warning(f"Phishing domain detected in NSIS script compiled file (.nsi): {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.NSIS.Phishing.Domain")
            elif pyc_flag or pyc_meta_llama_flg:
                logging.warning(f"Phishing domain detected in Python compiled file: {main_domain}")
                if pyc_meta_llama_flg:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.MetaLlama.Phishing.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.Phishing.Domain")
            else:
                logging.warning(f"Phishing domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Phishing.Domain")
            if homepage_flag:
                notify_user_for_malicious_source_code(main_domain, f"HEUR:Win32.Adware.{homepage_flag}.Phishing.HomePage.gen")
            return

        if full_domain in malware_domains_mail_data or main_domain in malware_domains_mail_data:
            if dotnet_flag:
                logging.warning(f"Malware mail domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Malware.Mail.Domain")
            elif nuitka_flag:
                logging.warning(f"Malware mail domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Malware.Mail.Domain")
            elif nsis_flag:
                logging.warning(f"Malware mail domain detected in NSIS script compiled file (.nsi): {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.NSIS.Malware.Mail.Domain")
            elif pyc_flag or pyc_meta_llama_flg:
                logging.warning(f"Malware mail domain detected in Python compiled file: {main_domain}")
                if pyc_meta_llama_flg:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.MetaLlama.Malware.Mail.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.Malware.Mail.Domain")
            else:
                logging.warning(f"Malware mail domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Malware.Mail.Domain")
            if homepage_flag:
                notify_user_for_malicious_source_code(main_domain, f"HEUR:Win32.Adware.{homepage_flag}.Malware.HomePage.gen")
            return

        if full_domain in malware_domains_data or main_domain in malware_domains_data:
            if dotnet_flag:
                logging.warning(f"Malware domain detected in .NET source code: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.DotNET.Malware.Domain")
            elif nuitka_flag:
                logging.warning(f"Malware domain detected in Nuitka compiled file: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Nuitka.Malware.Domain")
            elif nsis_flag:
                logging.warning(f"Malware domain detected in NSIS script compiled file (.nsi): {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.NSIS.Malware.Domain")
            elif pyc_flag or pyc_meta_llama_flg:
                logging.warning(f"Malware domain detected in Python compiled file: {main_domain}")
                if pyc_meta_llama_flg:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.MetaLlama.Malware.Domain")
                else:
                    notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.PYC.Python.Malware.Domain")
            else:
                logging.warning(f"Malware domain detected: {main_domain}")
                notify_user_for_malicious_source_code(main_domain, "HEUR:Win32.Malware.Domain")
            if homepage_flag:
                notify_user_for_malicious_source_code(main_domain, f"HEUR:Win32.Adware.{homepage_flag}.Malware.HomePage.gen")
            return

        logging.info(f"Domain {full_domain} passed all checks.")

    except Exception as ex:
        logging.error(f"Error scanning domain {url}: {ex}")

# --------------------------------------------------------------------------
# Generalized scan for URLs
def scan_url_general(url, dotnet_flag=False, nsis_flag=False, nuitka_flag=False, pyc_flag=False, pyc_meta_llama_flg=False, homepage_flag=""):
    try:
        if url in scanned_urls_general:
            logging.info(f"URL {url} has already been scanned.")
            return

        scanned_urls_general.append(url)
        logging.info(f"Scanning URL: {url}")

        # First, check against URLhaus signatures.
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
                logging.info(message)
                if dotnet_flag:
                    notify_user_for_malicious_source_code(url, 'HEUR:Win32.DotNET.URLhaus.Match')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(url, 'HEUR:Win32.Nuitka.URLhaus.Match')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(url, 'HEUR:Win32.NSIS.URLhaus.Match')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"URL {url} matches the URLhaus signatures.")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(url, 'HEUR:Win32.PYC.Python.MetaLlama.URLhaus.Match')
                    else:
                        notify_user_for_malicious_source_code(url, 'HEUR:Win32.PYC.Python.URLhaus.Match')
                else:
                    notify_user_for_malicious_source_code(url, 'HEUR:Win32.URLhaus.Match')
                # Use the homepage_flag string to append a browser tag to the virus signature.
                if homepage_flag:
                    notify_user_for_malicious_source_code(url, f"HEUR:Win32.Adware.{homepage_flag}.URLhaus.HomePage.gen")
                return

        # Heuristic check using uBlock Origin style detection.
        if ublock_detect(url):
            notify_user_for_malicious_source_code(url, 'HEUR:Phish.Steam.Community.gen')
            logging.warning(f"URL {url} flagged by uBlock detection using HEUR:Phish.Steam.Community.gen.")
            if homepage_flag:
                notify_user_for_malicious_source_code(url, f"HEUR:Win32.Adware.{homepage_flag}.Phishing.HomePage.gen")
            return

        logging.info(f"No match found for URL: {url}")

    except Exception as ex:
        logging.error(f"Error scanning URL {url}: {ex}")

def ensure_http_prefix(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        return 'http://' + url
    return url

# a global (or outer-scope) list to collect every saved path
saved_paths = []
saved_pyc_paths = []
deobfuscated_saved_paths = []
path_lists = [saved_paths, deobfuscated_saved_paths, saved_pyc_paths]

def fetch_html(url, return_file_path=False):
    """Fetch HTML content from the given URL, always save it, and optionally return the file path."""
    try:
        # Checking for valid IP
        if not is_valid_ip(url):
            logging.info(f"Invalid or disallowed IP address in URL: {url}")
            return ("", None) if return_file_path else ""

        safe_url = ensure_http_prefix(url)
        response = requests.get(safe_url, timeout=120)
        if response.status_code == 200:
            html = response.text
            # Determine a safe filename from the URL path
            parsed = urlparse(safe_url)
            fname = Path(parsed.path if parsed.path else "index.html").name or "index.html"
            base_name = Path(fname)
            # Generate unique output path
            out_path = get_unique_output_path(Path(html_extracted_dir), base_name)
            # Save the HTML
            with open(out_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(html)
            logging.info(f"Saved HTML for {safe_url} to {out_path}")
            # record the new path
            saved_paths.append(out_path)
            return (html, out_path) if return_file_path else html
        else:
            logging.warning(f"Non-OK status {response.status_code} for URL: {safe_url}")
            return ("", None) if return_file_path else ""
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error while fetching HTML content from {url}: {e}")
        return ("", None) if return_file_path else ""
    except Exception as e:
        logging.error(f"Unexpected error fetching HTML content from {url}: {e}")
        return ("", None) if return_file_path else ""

# --------------------------------------------------------------------------
# Generalized scan for IP addresses
def scan_ip_address_general(ip_address, dotnet_flag=False, nsis_flag=False, nuitka_flag=False, pyc_flag=False, pyc_meta_llama_flg=False, homepage_flag=""):
    try:
        # Check if the IP address is valid
        if is_valid_ip(ip_address):
            message = f"Skipping non valid IP address: {ip_address}"
            logging.info(message)
            return

        # Check if the IP address has already been scanned
        if ip_address in scanned_ipv4_addresses_general or ip_address in scanned_ipv6_addresses_general:
            message = f"IP address {ip_address} has already been scanned."
            logging.info(message)
            return

        # Process IPv6 addresses
        if re.match(IPv6_pattern, ip_address):
            scanned_ipv6_addresses_general.append(ip_address)
            message = f"Scanning IPv6 address: {ip_address}"
            logging.info(message)

            if ip_address in ipv6_whitelist_data:
                logging.info(f"IPv6 address {ip_address} is whitelisted.")
                return
            elif ip_address in ipv6_addresses_ddos_signatures_data:
                logging.warning(f"DDoS IPv6 address detected: {ip_address}")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.DDoS.IPv6')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.DDoS.IPv6')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.DDoS.IPv6')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"DDoS IPv6 address detected: {ip_address}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.DDoS.IPv6')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.DDoS.IPv6')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DDoS.IPv6')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.DDoS.HomePage.gen")
            elif ip_address in ipv6_addresses_spam_signatures_data:
                logging.warning(f"Spam IPv6 address detected: {ip_address}")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.Spam.IPv6')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.Spam.IPv6')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.Spam.IPv6')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Spam IPv6 address detected: {ip_address}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.Spam.IPv6')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.Spam.IPv6')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Spam.IPv6')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.Spam.HomePage.gen")
            elif ip_address in ipv6_addresses_signatures_data:
                logging.warning(f"Malicious IPv6 address detected: {ip_address}")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.Malware.IPv6')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.Malware.IPv6')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.Malware.IPv6')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Malicious IPv6 address detected: {ip_address}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.Malware.IPv6')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.Malware.IPv6')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Malware.IPv6')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.Malware.HomePage.gen")
            else:
                logging.info(f"Unknown IPv6 address detected: {ip_address}")

        # Process IPv4 addresses
        elif re.match(IPv4_pattern, ip_address):
            scanned_ipv4_addresses_general.append(ip_address)
            message = f"Scanning IPv4 address: {ip_address}"
            logging.info(message)

            # Check if the IPv4 address is whitelisted
            if ip_address in ipv4_whitelist_data:
                logging.info(f"IPv4 address {ip_address} is whitelisted.")
                return
            # Detailed Active phishing threat signature check for IPv4
            elif ip_address in ipv4_addresses_phishing_active_signatures_data:
                logging.warning(f"IPv4 address {ip_address} detected as an active phishing threat.")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.PhishingActive.IPv4')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.PhishingActive.IPv4')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.PhishingActive.IPv4')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"IPv4 address {ip_address} detected as an active phishing threat.")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.PhishingActive.IPv4')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.PhishingActive.IPv4')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PhishingActive.IPv4')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.Phishing.HomePage.gen")
            elif ip_address in ipv4_addresses_ddos_signatures_data:
                logging.warning(f"IPv4 address {ip_address} detected as a potential DDoS threat.")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.DDoS.IPv4')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.DDoS.IPv4')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.DDoS.IPv4')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"IPv4 address {ip_address} detected as a potential DDoS threat.")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.DDoS.IPv4')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.DDoS.IPv4')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DDoS.IPv4')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.DDoS.HomePage.gen")
            elif ip_address in ipv4_addresses_phishing_inactive_signatures_data:
                logging.warning(f"IPv4 address {ip_address} detected as an inactive phishing threat.")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.PhishingInactive.IPv4')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.PhishingInactive.IPv4')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.PhishingInactive.IPv4')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"IPv4 address {ip_address} detected as an inactive phishing threat.")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.PhishingInactive.IPv4')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.PhishingInactive.IPv4')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PhishingInactive.IPv4')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.Phishing.HomePage.gen")
            elif ip_address in ipv4_addresses_bruteforce_signatures_data:
                logging.warning(f"IPv4 address {ip_address} detected as a potential BruteForce threat.")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.BruteForce.IPv4')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.BruteForce.IPv4')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.BruteForce.IPv4')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"IPv4 address {ip_address} detected as a potential BruteForce threat.")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.BruteForce.IPv4')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.BruteForce.IPv4')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.BruteForce.IPv4')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.BruteForce.HomePage.gen")
            elif ip_address in ipv4_addresses_spam_signatures_data:
                logging.warning(f"Spam IPv4 address detected: {ip_address}")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.Spam.IPv4')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.Spam.IPv4')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.Spam.IPv4')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Spam IPv4 address detected: {ip_address}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.Spam.IPv4')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.Spam.IPv4')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Spam.IPv4')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.Spam.HomePage.gen")
            elif ip_address in ipv4_addresses_signatures_data:
                logging.warning(f"Malicious IPv4 address detected: {ip_address}")
                if dotnet_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.DotNET.Malware.IPv4')
                elif nuitka_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Nuitka.Malware.IPv4')
                elif nsis_flag:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.NSIS.Malware.IPv4')
                elif pyc_flag or pyc_meta_llama_flg:
                    logging.warning(f"Malicious IPv4 address detected: {ip_address}")
                    if pyc_meta_llama_flg:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.MetaLlama.Malware.IPv4')
                    else:
                        notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.PYC.Python.Malware.IPv4')
                else:
                    notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.Malware.IPv4')
                if homepage_flag:
                    notify_user_for_malicious_source_code(ip_address, f"HEUR:Win32.Adware.{homepage_flag}.Malware.HomePage.gen")
            else:
                logging.info(f"Unknown IPv4 address detected: {ip_address}")
        else:
            logging.debug(f"Invalid IP address format detected: {ip_address}")

    except Exception as ex:
        logging.error(f"Error scanning IP address {ip_address}: {ex}")

def scan_html_content(html_content, html_content_file_path, dotnet_flag=False, nuitka_flag=False, pyc_flag=False, nsis_flag=False, pyc_meta_llama_flg=False):
    """Scan extracted HTML content for any potential threats."""
    contains_discord_or_telegram_code(html_content, html_content_file_path, None,
                          dotnet_flag, nuitka_flag,
                          pyc_flag, nsis_flag, pyc_meta_llama_flg)
    urls = set(re.findall(r'https?://[^\s/$.?#]\S*', html_content))
    for url in urls:
        scan_url_general(url, dotnet_flag, nuitka_flag,
                          pyc_flag, nsis_flag, pyc_meta_llama_flg)
        scan_domain_general(url, dotnet_flag, nuitka_flag,
                            pyc_flag, nsis_flag, pyc_meta_llama_flg)
    ipv4_addresses = set(re.findall(
        r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        html_content
    ))
    for ip in ipv4_addresses:
        scan_ip_address_general(ip, dotnet_flag, nuitka_flag,
                                pyc_flag, nsis_flag ,pyc_meta_llama_flg)
    ipv6_addresses = set(re.findall(
        r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
        html_content
    ))
    for ip in ipv6_addresses:
        scan_ip_address_general(ip, dotnet_flag, nuitka_flag,
                                pyc_flag, nsis_flag, pyc_meta_llama_flg)

# --------------------------------------------------------------------------
# Main scanner: combine all individual scans and pass the flags along
def scan_code_for_links(decompiled_code, file_path, cs_file_path=None,
                          dotnet_flag=False, nuitka_flag=False, pyc_flag=False, pyc_meta_llama_flg=False, nsis_flag=False,
                          homepage_flag=""):
    """
    Scan the decompiled code for Discord-related URLs (via contains_discord_or_telegram_code),
    general URLs, domains, and IP addresses. The provided flags are passed along
    to each individual scanning function so that every detection scenario uses its unique
    virus signature.
    """

    # Call the Discord/Telegram scanner
    contains_discord_or_telegram_code(decompiled_code, file_path, cs_file_path,
                            dotnet_flag, nuitka_flag,
                            pyc_flag, nsis_flag ,pyc_meta_llama_flg)

    # Extract URLs from the decompiled code
    urls = set(re.findall(r'https?://[^\s/$.?#]\S*', decompiled_code))
    for url in urls:
        html_content, html_content_file_path = fetch_html(url, return_file_path=True)
        contains_discord_or_telegram_code(html_content, file_path, cs_file_path,
                              dotnet_flag, nuitka_flag,
                              pyc_flag, nsis_flag ,pyc_meta_llama_flg)
        # Pass the homepage flag string into the scanning functions
        scan_url_general(url, dotnet_flag, nuitka_flag,
                          pyc_flag, nsis_flag, pyc_meta_llama_flg,
                          homepage_flag)
        scan_domain_general(url, dotnet_flag, nuitka_flag,
                            pyc_flag, nsis_flag, pyc_meta_llama_flg,
                            homepage_flag)
        scan_html_content(html_content, html_content_file_path, dotnet_flag, nuitka_flag,
                          pyc_flag, nsis_flag, pyc_meta_llama_flg)

    ipv4_addresses = set(re.findall(
        r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        decompiled_code
    ))
    for ip in ipv4_addresses:
        scan_ip_address_general(ip, dotnet_flag, nuitka_flag,
                                pyc_flag, nsis_flag, pyc_meta_llama_flg,
                                homepage_flag)

    ipv6_addresses = set(re.findall(
        r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
        decompiled_code
    ))
    for ip in ipv6_addresses:
        scan_ip_address_general(ip, dotnet_flag, nuitka_flag,
                                pyc_flag, nsis_flag ,pyc_meta_llama_flg,
                                homepage_flag)

# Load Psapi.dll and define the filter flag
_psapi = ctypes.WinDLL('Psapi.dll')
LIST_MODULES_ALL = 0x03

def enum_process_modules(process_handle):
    """Enumerate and retrieve loaded modules in a process."""
    # Prepare an array for up to 1024 HMODULEs
    hmodules = (ctypes.c_void_p * 1024)()
    needed = ctypes.c_ulong()
    cb = ctypes.sizeof(hmodules)

    # BOOL EnumProcessModulesEx(
    #   HANDLE hProcess,
    #   HMODULE *lphModule,
    #   DWORD cb,
    #   LPDWORD lpcbNeeded,
    #   DWORD dwFilterFlag
    # );
    success = _psapi.EnumProcessModulesEx(
        process_handle,
        ctypes.byref(hmodules),
        cb,
        ctypes.byref(needed),
        LIST_MODULES_ALL
    )
    if not success:
        logging.error("Failed to enumerate process modules")
        return []

    # Calculate how many module handles were actually returned
    count = needed.value // ctypes.sizeof(ctypes.c_void_p)
    return list(hmodules)[:count]


# Define the MODULEINFO struct
class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_uint32),
        ("EntryPoint", ctypes.c_void_p),
    ]


def get_module_info(process_handle, base_addr):
    """Retrieve module information via Psapi.GetModuleInformation."""
    module_info = MODULEINFO()
    success = _psapi.GetModuleInformation(
        process_handle,
        ctypes.c_void_p(base_addr),
        byref(module_info),
        ctypes.sizeof(module_info)
    )
    if not success:
        logging.error("GetModuleInformation failed")
        return None
    return module_info

def read_memory_data(pm, base_addr, size):
    """Read memory data from a specific module using pymem.Pymem."""
    try:
        return pm.read_bytes(base_addr, size)
    except Exception as e:
        logging.error(f"read_bytes failed: {e}")
        return None

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

def run_pd64_db_gen():
    """Run pd64 -db gen to create/update clean.hashes in script_dir."""
    try:
        subprocess.run([pd64_path, "-db", "gen"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to generate clean.hashes: {e}")
        return False

def extract_with_pd64(dump_path: str, output_dir: str) -> bool:
    """Run pd64.exe to extract files from a memory dump."""
    try:
        subprocess.run([
            pd64_path,
            "-e",  # extract switch
            dump_path,
            "-o",
            output_dir
        ], check=True)
        logging.info(f"Extraction complete for {dump_path} into {output_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"PD64 extraction failed for {dump_path}: {e}")
        return False

def scan_file_with_machine_learning_ai(file_path, threshold=0.86):
    """Scan a file for malicious activity using machine learning definitions loaded from JSON."""

    # Default assignment of malware_definition before starting the process
    malware_definition = "Unknown"  # Assume unknown until checked
    logging.info(f"Starting machine learning scan for file: {file_path}")

    try:
        pe = pefile.PE(file_path)
        if not pe:
            logging.warning(f"File {file_path} is not a valid PE file. Returning default value 'Unknown'.")
            return False, malware_definition, 0

        logging.info(f"File {file_path} is a valid PE file, proceeding with feature extraction.")
        file_info = extract_infos(file_path)
        file_numeric_features = extract_numeric_features(file_path)

        is_malicious_ml = False
        nearest_malicious_similarity = 0
        nearest_benign_similarity = 0

        logging.info(f"File information: {file_info}")

        # Check malicious definitions
        for ml_feats, info in zip(malicious_numeric_features, malicious_file_names):
            rank = info['numeric_tag']
            similarity = calculate_similarity(file_numeric_features, ml_feats)
            nearest_malicious_similarity = max(nearest_malicious_similarity, similarity)
            if similarity >= threshold:
                is_malicious_ml = True
                malware_definition = info['file_name']
                logging.warning(f"Malicious activity detected in {file_path}. Definition: {malware_definition}, similarity: {similarity}, rank: {rank}")

        # If not malicious, check benign
        if not is_malicious_ml:
            for ml_feats, info in zip(benign_numeric_features, benign_file_names):
                similarity = calculate_similarity(file_numeric_features, ml_feats)
                nearest_benign_similarity = max(nearest_benign_similarity, similarity)
                benign_definition = info['file_name']

            if nearest_benign_similarity >= 0.93:
                malware_definition = "Benign"
                logging.info(f"File {file_path} is classified as benign ({benign_definition}) with similarity: {nearest_benign_similarity}")
            else:
                malware_definition = "Unknown"
                logging.info(f"File {file_path} is classified as unknown with similarity: {nearest_benign_similarity}")

        # Return result
        if is_malicious_ml:
            return False, malware_definition, nearest_malicious_similarity
        else:
            return False, malware_definition, nearest_benign_similarity

    except pefile.PEFormatError:
        logging.error(f"Error: {file_path} does not have a valid PE format.")
        return False, malware_definition, 0
    except Exception as ex:
        logging.error(f"An error occurred while scanning file {file_path}: {ex}")
        return False, malware_definition, 0

def restart_clamd_thread():
    try:
        threading.Thread(target=restart_clamd).start()
    except Exception as ex:
        logging.error(f"Error starting clamd restart thread: {ex}")

def restart_clamd():
    try:
        logging.info("Stopping ClamAV...")
        stop_result = subprocess.run(["net", "stop", 'clamd'], capture_output=True, text=True, encoding="utf-8", errors="ignore")
        if stop_result.returncode != 0:
                logging.error("Failed to stop ClamAV.")

        logging.info("Starting ClamAV...")
        start_result = subprocess.run(["net", "start", 'clamd'], capture_output=True, text=True, encoding="utf-8", errors="ignore")
        if start_result.returncode == 0:
            logging.info("ClamAV restarted successfully.")
            return True
        else:
            logging.error("Failed to start ClamAV.")
            return False
    except Exception as ex:
        logging.error(f"An error occurred while restarting ClamAV: {ex}")
        return False

def scan_file_with_clamd(file_path):
    """Scan file using clamd."""
    try:
        file_path = os.path.abspath(file_path)  # Get absolute path
        result = subprocess.run([clamdscan_path, file_path], capture_output=True, text=True, encoding="utf-8", errors="ignore")
        clamd_output = result.stdout
        logging.info(f"Clamdscan output: {clamd_output}")

        if "ERROR" in clamd_output:
            logging.info(f"Clamdscan reported an error: {clamd_output}")
            return "Clean"
        elif "FOUND" in clamd_output:
            match = re.search(r": (.+) FOUND", clamd_output)
            if match:
                virus_name = match.group(1).strip()
                return virus_name
        elif "OK" in clamd_output or "Infected files: 0" in clamd_output:
            return "Clean"
        else:
            logging.info(f"Unexpected clamdscan output: {clamd_output}")
            return "Clean"
    except Exception as ex:
        logging.error(f"Error scanning file {file_path}: {ex}")
        return "Clean"

def is_related_to_critical_paths(file_path):
    return file_path.startswith(sandboxie_folder) or file_path == main_file_path


# --- The RealTimeWebProtectionHandler Class ---
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
        """
        Handle a detection event for a given entity (domain, IP, URL).
        Only notify if there is a non-empty entity value and it maps to a file or critical path.
        """
        # Early exit if entity_value is empty or None
        if not entity_value:
            logging.info(f"handle_detection called with empty entity_value for type '{entity_type}'. Skipping.")
            return

        file_path = self.map_domain_ip_to_file(entity_value)
        notify_info = {
            'domain': None,
            'ipv4_address': None,
            'ipv6_address': None,
            'url': None,
            'file_path': None,
            'detection_type': detection_type
        }

        try:
            # Determine message and notification fields
            if file_path and is_related_to_critical_paths(file_path):
                # Critical path detection
                message = f"{entity_type.capitalize()} {entity_value} is related to a critical path: {file_path}"
                if detection_type:
                    message = f"{detection_type} {message}"
                logging.warning(message)
                logging.info(message)

                notify_info[entity_type] = entity_value
                notify_info['file_path'] = file_path

            else:
                # Non-critical or no file mapping
                if file_path:
                    message = (
                        f"{entity_type.capitalize()} {entity_value} is not related to critical paths "
                        f"but associated with file path: {file_path}"
                    )
                    notify_info[entity_type] = entity_value
                    notify_info['file_path'] = file_path
                else:
                    message = (
                        f"{entity_type.capitalize()} {entity_value} is not related to critical paths "
                        "and has no associated file path."
                    )
                if detection_type:
                    message = f"{detection_type} {message}"
                logging.info(message)

            # Only notify if there's meaningful data (ignore detection_type alone)
            has_data = any(
                notify_info[field] for field in ['domain', 'ipv4_address', 'ipv6_address', 'url', 'file_path']
            )
            if has_data:
                notify_user_for_web(**notify_info)

        except Exception as ex:
            logging.error(f"Error in handle_detection: {ex}")

    def extract_ip_addresses(self, text):
        """Extract IPv4 and IPv6 addresses from text using regex."""
        ips = re.findall(IPv4_pattern, text)
        ips += re.findall(IPv6_pattern, text)
        return ips

    def extract_urls(self, text):
        """Extract URLs from text using regex."""
        url_regex = r'https?://[^\s"<>]+'
        return re.findall(url_regex, text)

    def extract_domains(self, text):
        """Extract domain names from text using regex."""
        domain_regex = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        return re.findall(domain_regex, text)

    def scan(self, entity_type, entity_value, detection_type=None):
        """
        Unified scan entry-point.
        Dedupe, detect, fetch, extract, and recurse all via this one method.
        """
        # 1) classify into our four buckets
        if entity_type in ('subdomain', 'domain'):
            kind = 'domain'
        elif entity_type in ('ipv4_address', 'ipv6_address'):
            kind = 'ipv6' if ':' in entity_value else 'ipv4'
        elif entity_type == 'url':
            kind = 'url'
        else:
            # unrecognized type
            return

        # 2) dedupe
        if kind == 'domain':
            if entity_value in self.scanned_domains:
                return
            self.scanned_domains.append(entity_value)

        elif kind == 'ipv4':
            if entity_value in self.scanned_ipv4_addresses:
                return
            self.scanned_ipv4_addresses.append(entity_value)

        elif kind == 'ipv6':
            if entity_value in self.scanned_ipv6_addresses:
                return
            self.scanned_ipv6_addresses.append(entity_value)

        else:  # kind == 'url'
            if entity_value in self.scanned_urls:
                return
            self.scanned_urls.append(entity_value)

        # 3) run the same detection logic you had
        self.handle_detection(entity_type, entity_value, detection_type)

        # 4) now do fetch + extract + recurse
        if kind == 'domain':
            domain = entity_value
            # strip www.
            if domain.lower().startswith("www."):
                domain = domain[4:]

            parts = domain.split(".")
            main_domain = domain if len(parts) < 3 else ".".join(parts[-2:])

            # Check against spam subdomains
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

            # fetch & parse HTML
            full_url = f"http://{domain}"
            html_content = fetch_html(full_url)
            if html_content:
                for ip in self.extract_ip_addresses(html_content):
                    # recurse via scan()
                    self.scan('ipv4_address' if '.' in ip else 'ipv6_address', ip)
                for url in self.extract_urls(html_content):
                    self.scan('url', url)
                for dom in self.extract_domains(html_content):
                    self.scan('domain', dom)

        elif kind in ('ipv4', 'ipv6'):
            ip_address = entity_value
            # valid ip check
            if is_valid_ip(ip_address):
                logging.info(f"Skipping non valid IP address: {ip_address}")
                return

            # signatures
            if kind == 'ipv6':
                logging.info(f"Scanning IPv6 address: {ip_address}")
                if ip_address in ipv6_addresses_ddos_signatures_data:
                    self.handle_detection('ipv6_address', ip_address, 'DDOS')

                # Check against IPv6 Malware signatures
                elif ip_address in ipv6_addresses_spam_signatures_data:
                    self.handle_detection('ipv6_address', ip_address, 'SPAM')

                # Check against IPv6 Malware signatures
                elif ip_address in ipv6_addresses_signatures_data:
                    self.handle_detection('ipv6_address', ip_address, 'MALWARE')

                # Check if it is in the IPv6 whitelist
                elif ip_address in ipv6_whitelist_data:
                    logging.info(f"IPv6 address {ip_address} is whitelisted")
                else:
                    logging.info(f"Unknown IPv6 address detected: {ip_address}")

            else:  # ipv4
                logging.info(f"Scanning IPv4 address: {ip_address}")
                if ip_address in ipv4_addresses_phishing_active_signatures_data:
                    self.handle_detection('ipv4_address', ip_address, 'PHISHING_ACTIVE')

                # Check against inactive phishing signatures
                if ip_address in ipv4_addresses_phishing_inactive_signatures_data:
                    self.handle_detection('ipv4_address', ip_address, 'PHISHING_INACTIVE')

                # Check against IPv4 BruteForce signatures
                if ip_address in ipv4_addresses_bruteforce_signatures_data:
                    self.handle_detection('ipv4_address', ip_address, 'BRUTEFORCE')

                # Check against IPv4 Malware signatures
                if ip_address in ipv4_addresses_spam_signatures_data:
                    self.handle_detection('ipv4_address', ip_address, 'SPAM')

                # Check against IPv4 Malware signatures
                if ip_address in ipv4_addresses_signatures_data:
                    self.handle_detection('ipv4_address', ip_address, 'MALWARE')

                # Check if it is in the IPv4 whitelist
                elif ip_address in ipv4_whitelist_data:
                    logging.info(f"IPv4 address {ip_address} is whitelisted")
                else:
                    logging.info(f"Unknown IPv4 address detected: {ip_address}")

            # fetch & parse
            full_url = f"http://{ip_address}"
            html_content = fetch_html(full_url)
            if html_content:
                for dom in self.extract_domains(html_content):
                    self.scan('domain', dom)
                for url in self.extract_urls(html_content):
                    self.scan('url', url)

        else:  # kind == 'url'
            url = entity_value
            html_content = fetch_html(url)
            if html_content:
                for ip in self.extract_ip_addresses(html_content):
                    self.scan('ipv4_address' if '.' in ip else 'ipv6_address', ip)
                for dom in self.extract_domains(html_content):
                    self.scan('domain', dom)
                for u in self.extract_urls(html_content):
                    self.scan('url', u)

            # --- Heuristic Checks for Discord & Telegram ---
            if re.compile(discord_webhook_pattern_standard).search(url):
                self.handle_detection('url', url, 'HEUR:Discord.Webhook')
                return
            if re.compile(discord_canary_webhook_pattern_standard).search(url):
                self.handle_detection('url', url, 'HEUR:Discord.CanaryWebhook')
                return
            if re.compile(cdn_attachment_pattern_standard).search(url):
                self.handle_detection('url', url, 'HEUR:Discord.CDNAttachment')
                return
            if re.compile(telegram_pattern_standard).search(url):
                self.handle_detection('url', url, 'HEUR:Telegram.Token')
                return

            # URLhaus signatures
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
                    self.handle_detection('url', url, 'URLhaus Match')
                    return

            # Heuristic check using uBlock detection (e.g., Steam Community pattern).
            if ublock_detect(url):
                self.handle_detection('url', url, 'HEUR:Phish.Steam.Community.gen')
                logging.warning(
                    f"URL {url} flagged by uBlock detection using HEUR:Phish.Steam.Community.gen."
                )
                return

            logging.info(f"No match found for URL: {url}")

    def scan_domain(self, domain):
        self.scan('domain', domain)

    def scan_ipv4_address(self, ip_address):
        self.scan('ipv4_address', ip_address)

    def scan_ipv6_address(self, ip_address):
        self.scan('ipv6_address', ip_address)

    def scan_url(self, url):
        self.scan('url', url)

    def handle_ipv4(self, packet):
        try:
            if IP in packet and DNS in packet:
                if packet[DNS].qd:
                    for i in range(packet[DNS].qdcount):
                        qn = packet[DNSQR][i].qname.decode().rstrip('.')
                        self.scan_domain(qn)
                        logging.info(f"DNS Query (IPv4): {qn}")
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        an = packet[DNSRR][i].rrname.decode().rstrip('.')
                        self.scan_domain(an)
                        logging.info(f"DNS Answer (IPv4): {an}")

                self.scan_ipv4_address(packet[IP].src)
                self.scan_ipv4_address(packet[IP].dst)
        except Exception as ex:
            logging.error(f"Error handling IPv4 packet: {ex}")

    def handle_ipv6(self, packet):
        try:
            if IPv6 in packet and DNS in packet:
                if packet[DNS].qd:
                    for i in range(packet[DNS].qdcount):
                        qn = packet[DNSQR][i].qname.decode().rstrip('.')
                        self.scan_domain(qn)
                        logging.info(f"DNS Query (IPv6): {qn}")
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        an = packet[DNSRR][i].rrname.decode().rstrip('.')
                        self.scan_domain(an)
                        logging.info(f"DNS Answer (IPv6): {an}")

                self.scan_ipv6_address(packet[IPv6].src)
                self.scan_ipv6_address(packet[IPv6].dst)
            else:
                logging.debug("IPv6 layer or DNS layer not found in the packet.")
        except Exception as ex:
            logging.error(f"Error handling IPv6 packet: {ex}")

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
                        qn = packet[DNSQR][i].qname.decode().rstrip('.')
                        self.scan_domain(qn)
                        logging.info(f"DNS Query: {qn}")
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        an = packet[DNSRR][i].rrname.decode().rstrip('.')
                        self.scan_domain(an)
                        logging.info(f"DNS Answer: {an}")
                if IP in packet:
                    self.scan_ipv4_address(packet[IP].src)
                    self.scan_ipv4_address(packet[IP].dst)
                if IPv6 in packet:
                    self.scan_ipv6_address(packet[IPv6].src)
                    self.scan_ipv6_address(packet[IPv6].dst)
        except Exception as ex:
            logging.error(f"Error processing packet: {ex}")


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

    def start_sniffing(self):
        filter_expression = "(tcp or udp)"
        try:
            sniff(filter=filter_expression, prn=self.handler.on_packet_received, store=0)
        except Exception as ex:
            logging.error(f"An error occurred while sniffing packets: {ex}")


web_protection_observer = RealTimeWebProtectionObserver()

def scan_yara(file_path):
    matched_rules = []

    try:
        if not os.path.exists(file_path):
            logging.error(f"File not found during YARA scan: {file_path}")
            return None

        with open(file_path, 'rb') as yara_file:
            data_content = yara_file.read()

            # compiled_rule
            try:
                if compiled_rule:
                    matches = compiled_rule.match(data=data_content)
                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from compiled_rule.")
                else:
                    logging.error("compiled_rule is not defined.")
            except Exception as e:
                logging.error(f"Error scanning with compiled_rule: {e}")

            # yarGen_rule
            try:
                if yarGen_rule:
                    matches = yarGen_rule.match(data=data_content)
                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from yarGen_rule.")
                else:
                    logging.error("yarGen_rule is not defined.")
            except Exception as e:
                logging.error(f"Error scanning with yarGen_rule: {e}")

            # icewater_rule
            try:
                if icewater_rule:
                    matches = icewater_rule.match(data=data_content)
                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from icewater_rule.")
                else:
                    logging.error("icewater_rule is not defined.")
            except Exception as e:
                logging.error(f"Error scanning with icewater_rule: {e}")

            # valhalla_rule
            try:
                if valhalla_rule:
                    matches = valhalla_rule.match(data=data_content)
                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from valhalla_rule.")
                else:
                    logging.error("valhalla_rule is not defined.")
            except Exception as e:
                logging.error(f"Error scanning with valhalla_rule: {e}")

            # yaraxtr_rule (YARA-X)
            try:
                if yaraxtr_rule:
                    scanner = yara_x.Scanner(rules=yaraxtr_rule)
                    results = scanner.scan(data=data_content)
                    for rule in getattr(results, 'matching_rules', []) or []:
                        identifier = getattr(rule, 'identifier', None)
                        if identifier and identifier not in excluded_rules:
                            matched_rules.append(identifier)
                        else:
                            logging.info(f"Rule {identifier} is excluded from yaraxtr_rule.")
                else:
                    logging.error("yaraxtr_rule is not defined.")
            except Exception as e:
                logging.error(f"Error scanning with yaraxtr_rule: {e}")

        return matched_rules if matched_rules else None

    except Exception as ex:
        logging.error(f"An error occurred during YARA scan: {ex}")
        return None

def detect_etw_tampering_sandbox(moved_sandboxed_ntdll_path):
    """
    Compare the NtTraceEvent bytes in the sandboxed ntdll.dll file against the original
    on-disk ntdll.dll in System32.
    Logs a warning if the sandboxed copy is tampered (bytes differ).
    Returns True if tampered, False otherwise.
    """
    try:
        if not os.path.isfile(ntdll_path):
            logging.error(f"[ETW Sandbox Detection] Original ntdll.dll not found at {ntdll_path}")
            return False
        if not os.path.isfile(moved_sandboxed_ntdll_path):
            logging.error(f"[ETW Sandbox Detection] Sandboxed ntdll.dll not found at {moved_sandboxed_ntdll_path}")
            return False

        # Load original PE to find NtTraceEvent RVA
        try:
            pe_orig = pefile.PE(ntdll_path, fast_load=True)
            pe_orig.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        except Exception as e:
            logging.error(f"[ETW Sandbox Detection] Failed to parse original PE: {e}")
            return False

        nttrace_rva = None
        for exp in getattr(pe_orig, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
            if exp.name and exp.name.decode(errors='ignore') == "NtTraceEvent":
                nttrace_rva = exp.address
                break
        if nttrace_rva is None:
            logging.error("[ETW Sandbox Detection] Export NtTraceEvent not found in original ntdll.dll")
            return False

        # Compute offset in original file
        try:
            orig_offset = pe_orig.get_offset_from_rva(nttrace_rva)
        except Exception as e:
            logging.error(f"[ETW Sandbox Detection] Cannot compute offset in original for RVA {hex(nttrace_rva)}: {e}")
            return False

        # Load sandboxed PE to compute offset there
        try:
            pe_sandbox = pefile.PE(moved_sandboxed_ntdll_path, fast_load=True)
            pe_sandbox.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        except Exception as e:
            logging.error(f"[ETW Sandbox Detection] Failed to parse sandboxed PE: {e}")
            return False

        # Verify that sandboxed export table contains NtTraceEvent (optional but good)
        found_in_sandbox = False
        for exp in getattr(pe_sandbox, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
            if exp.name and exp.name.decode(errors='ignore') == "NtTraceEvent":
                found_in_sandbox = True
                break
        if not found_in_sandbox:
            logging.error("[ETW Sandbox Detection] Export NtTraceEvent not found in sandboxed ntdll.dll")
            return False

        # Compute offset in sandboxed file
        try:
            sandbox_offset = pe_sandbox.get_offset_from_rva(nttrace_rva)
        except Exception as e:
            logging.error(f"[ETW Sandbox Detection] Cannot compute offset in sandboxed for RVA {hex(nttrace_rva)}: {e}")
            return False

        # Read bytes
        length = 16
        try:
            with open(ntdll_path, "rb") as f_orig:
                f_orig.seek(orig_offset)
                orig_bytes = f_orig.read(length)
            if len(orig_bytes) < length:
                logging.error(f"[ETW Sandbox Detection] Could not read {length} bytes from original ntdll.dll")
                return False
        except Exception as e:
            logging.error(f"[ETW Sandbox Detection] Error reading original file: {e}")
            return False

        try:
            with open(moved_sandboxed_ntdll_path, "rb") as f_s:
                f_s.seek(sandbox_offset)
                sandbox_bytes = f_s.read(length)
            if len(sandbox_bytes) < length:
                logging.error(f"[ETW Sandbox Detection] Could not read {length} bytes from sandboxed ntdll.dll")
                return False
        except Exception as e:
            logging.error(f"[ETW Sandbox Detection] Error reading sandboxed file: {e}")
            return False

        # Compare
        if sandbox_bytes != orig_bytes:
            orig_hex = orig_bytes[:8].hex()
            sand_hex = sandbox_bytes[:8].hex()
            logging.warning(
                f"[ETW Sandbox Detection] Sandboxed ntdll.dll NtTraceEvent seems patched: "
                f"original bytes={orig_hex}, sandbox bytes={sand_hex}"
            )
            return True

        # No tampering detected
        return False

    except Exception as ex:
        logging.error(f"[ETW Sandbox Detection] Unexpected error: {ex}")
        return False

# Constants for CryptQueryObject
CERT_QUERY_OBJECT_FILE = 0x00000001
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x00000080
CERT_QUERY_FORMAT_FLAG_BINARY = 0x00000002

# CertGetNameStringW flags/types
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG = 1

crypt32 = ctypes.windll.crypt32

# Define CERT_CONTEXT struct for extracting raw encoded certificate bytes
class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_byte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]

PCCERT_CONTEXT = ctypes.POINTER(CERT_CONTEXT)

def get_signer_cert_details(file_path: str) -> tuple[dict, bytes] | None:
    """
    Uses CryptoAPI CryptQueryObject to extract the first signer certificate's
    subject, issuer, and raw encoded bytes. Returns ({"Subject": str, "Issuer": str}, raw_bytes)
    or None on failure / no cert.
    """
    hCertStore = wintypes.HANDLE()
    hMsg = wintypes.HANDLE()
    encoding = wintypes.DWORD()
    content_type = wintypes.DWORD()
    format_type = wintypes.DWORD()
    pCertCtx = None

    # CryptQueryObject to get a cert store from the signed file
    res = crypt32.CryptQueryObject(
        wintypes.DWORD(CERT_QUERY_OBJECT_FILE),
        ctypes.c_wchar_p(file_path),
        wintypes.DWORD(CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED),
        wintypes.DWORD(CERT_QUERY_FORMAT_FLAG_BINARY),
        0,
        ctypes.byref(encoding),
        ctypes.byref(content_type),
        ctypes.byref(format_type),
        ctypes.byref(hCertStore),
        ctypes.byref(hMsg),
        None
    )
    if not res:
        return None

    try:
        # Enumerate certificates in store: get first
        pCertCtx = crypt32.CertEnumCertificatesInStore(hCertStore, None)
        if not pCertCtx:
            return None

        # Cast to CERT_CONTEXT pointer
        cert_ctx = ctypes.cast(pCertCtx, PCCERT_CONTEXT).contents

        # Extract raw encoded bytes
        raw_bytes = b""
        if cert_ctx.pbCertEncoded and cert_ctx.cbCertEncoded:
            raw_bytes = ctypes.string_at(cert_ctx.pbCertEncoded, cert_ctx.cbCertEncoded)

        # Helper to get name string
        def _get_name(pCtx, name_flag):
            # First call to get length
            length = crypt32.CertGetNameStringW(
                pCtx,
                wintypes.DWORD(CERT_NAME_SIMPLE_DISPLAY_TYPE),
                wintypes.DWORD(name_flag),
                None,
                None,
                wintypes.DWORD(0)
            )
            if length <= 1:
                return ""
            buf = (wintypes.WCHAR * length)()
            crypt32.CertGetNameStringW(
                pCtx,
                wintypes.DWORD(CERT_NAME_SIMPLE_DISPLAY_TYPE),
                wintypes.DWORD(name_flag),
                None,
                buf,
                wintypes.DWORD(length)
            )
            return "".join(buf).rstrip("\x00")

        subject = _get_name(pCertCtx, 0)
        issuer = _get_name(pCertCtx, CERT_NAME_ISSUER_FLAG)

        return ({"Subject": subject, "Issuer": issuer}, raw_bytes)

    except Exception as e:
        logging.debug(f"Failed to extract certificate info: {e}")
        return None

    finally:
        # Free the certificate context if one was returned
        if pCertCtx:
            crypt32.CertFreeCertificateContext(pCertCtx)
        # Close the certificate store
        if hCertStore:
            crypt32.CertCloseStore(hCertStore, 0)
        # Close the message handle
        if hMsg:
            crypt32.CryptMsgClose(hMsg)

# HRESULT codes for "no signature" cases
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0008
TRUST_E_PROVIDER_UNKNOWN     = 0x800B0001
NO_SIGNATURE_CODES = {
    TRUST_E_NOSIGNATURE,
    TRUST_E_SUBJECT_FORM_UNKNOWN,
    TRUST_E_PROVIDER_UNKNOWN,
}

# Constants for WinVerifyTrust
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

# UI and revocation options
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0x00000000

# Load WinTrust DLL
_wintrust = ctypes.windll.wintrust


def _build_wtd_for(file_path: str) -> WINTRUST_DATA:
    """Internal helper to populate a WINTRUST_DATA for the given file."""
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None
    )
    wtd = WINTRUST_DATA()
    ctypes.memset(ctypes.byref(wtd), 0, ctypes.sizeof(wtd))
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = WTD_UI_NONE
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE
    wtd.dwUnionChoice = WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(file_info)
    wtd.dwStateAction = WTD_STATEACTION_IGNORE
    return wtd


def verify_authenticode_signature(file_path: str) -> int:
    """Calls WinVerifyTrust and returns the raw HRESULT."""
    wtd = _build_wtd_for(file_path)
    return _wintrust.WinVerifyTrust(
        None,
        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.byref(wtd)
    )

def check_signature(file_path: str) -> dict:
    # --- 1) Try to open the signature store --- #
    hStore = wintypes.HANDLE()
    hMsg   = wintypes.HANDLE()
    encoding = wintypes.DWORD()
    content_type = wintypes.DWORD()
    format_type  = wintypes.DWORD()

    ok = crypt32.CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        ctypes.c_wchar_p(file_path),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        ctypes.byref(encoding),
        ctypes.byref(content_type),
        ctypes.byref(format_type),
        ctypes.byref(hStore),
        ctypes.byref(hMsg),
        None
    )
    if not ok:
        return {
            "is_valid": False,
            "status": "No signature",
            "signature_status_issues": False,
            "no_signature": True,
            "has_microsoft_signature": False,
            "has_valid_goodsign_signature": False,
            "matches_antivirus_signature": False
        }

    try:
        # --- 2) Do we actually have any signer certs? --- #
        pCertCtx = crypt32.CertEnumCertificatesInStore(hStore, None)
        if not pCertCtx:
            # no certs in store -> unsigned
            return {
                "is_valid": False,
                "status": "No signature",
                "signature_status_issues": False,
                "no_signature": True,
                "has_microsoft_signature": False,
                "has_valid_goodsign_signature": False,
                "matches_antivirus_signature": False
            }

        # --- 3) We found a cert, so let's verify the signature chain --- #
        hresult = verify_authenticode_signature(file_path)
        is_valid = (hresult == 0)
        status = (
            "Valid" if is_valid
            else "No signature" if hresult in NO_SIGNATURE_CODES
            else "Invalid signature"
        )
        signature_status_issues = not (is_valid or (hresult in NO_SIGNATURE_CODES))

        # --- 4) (optional) inspect the cert if valid, as before --- #
        has_ms_sig = False
        has_goodsign = False
        matches_av = False
        if is_valid:
            (cert_info, raw) = get_signer_cert_details(file_path)
            subj_iss = (cert_info["Subject"] + cert_info["Issuer"]).upper()
            has_ms_sig = "MICROSOFT" in subj_iss
            has_goodsign = any(s.upper() in subj_iss for s in goodsign_signatures)
            if raw:
                hex_buf = raw.hex().upper()
                for sig in antivirus_signatures:
                    if sig.upper() in hex_buf:
                        matches_av = True
                        break

        return {
            "is_valid": is_valid,
            "status": status,
            "signature_status_issues": signature_status_issues,
            "no_signature": (hresult in NO_SIGNATURE_CODES),
            "has_microsoft_signature": has_ms_sig,
            "has_valid_goodsign_signature": has_goodsign,
            "matches_antivirus_signature": matches_av
        }

    finally:
        # always clean up
        if pCertCtx:
            crypt32.CertFreeCertificateContext(pCertCtx)
        if hStore:
            crypt32.CertCloseStore(hStore, 0)
        if hMsg:
            crypt32.CryptMsgClose(hMsg)

def check_valid_signature(file_path: str) -> dict:
    """
    Returns {"is_valid": bool, "status": str}.
    """
    try:
        result = verify_authenticode_signature(file_path)

        if result == 0:
            is_valid = True
            status = "Valid"
        elif result in NO_SIGNATURE_CODES:
            is_valid = False
            status = "No signature"
        else:
            is_valid = False
            status = "Invalid signature"

        return {"is_valid": is_valid, "status": status}
    except Exception as ex:
        logging.error(f"[Signature] {file_path}: {ex}")
        return {"is_valid": False, "status": str(ex)}

def clean_directories():
    try:
        # Clean decompile directory if it exists, otherwise create it
        if os.path.isdir(decompiled_dir):
            shutil.rmtree(decompiled_dir)
            logging.info(f"Successfully cleaned the decompile folder at: {decompiled_dir}")
        else:
            logging.info(f"Decompile folder does not exist at: {decompiled_dir}")
        os.makedirs(decompiled_dir, exist_ok=True)
        logging.info(f"Created the decompile folder at: {decompiled_dir}")

        # Clean ghidra_projects directory if it exists, otherwise create it
        if os.path.isdir(ghidra_projects_dir):
            shutil.rmtree(ghidra_projects_dir)
            logging.info(f"Successfully cleaned the ghidra_projects folder at: {ghidra_projects_dir}")
        else:
            logging.info(f"Ghidra projects folder does not exist at: {ghidra_projects_dir}")
        os.makedirs(ghidra_projects_dir, exist_ok=True)
        logging.info(f"Created the ghidra_projects folder at: {ghidra_projects_dir}")

        # Check if ghidra_logs directory exists, create if not
        if not os.path.isdir(ghidra_logs_dir):
            os.makedirs(ghidra_logs_dir, exist_ok=True)
            logging.info(f"Created the ghidra_logs folder at: {ghidra_logs_dir}")
        else:
            logging.info(f"Ghidra logs folder exists at: {ghidra_logs_dir}")

    except Exception as ex:
        logging.error(f"An error occurred while cleaning the directories: {ex}")

def is_encrypted(zip_info):
    """Check if a ZIP entry is encrypted."""
    return zip_info.flag_bits & 0x1 != 0

def contains_rlo_after_dot_with_extension_check(filename, fileTypes):
    """
    Check if the filename contains an RLO character after a dot AND has a known extension.
    This helps detect potential RLO attacks that try to disguise malicious files.

    Args:
        filename (str): The filename to check
        fileTypes (set/list): Collection of known/allowed file extensions

    Returns:
        bool: True if RLO found after dot AND file has known extension, False otherwise
    """
    try:
        # First check if there's an RLO character after a dot
        if ".\u202E" not in filename:
            return False
        # If RLO found after dot, check if file has a known extension
        ext = os.path.splitext(filename)[1].lower()
        logging.info(f"RLO detected after dot in '{filename}', checking extension '{ext}'")
        has_known_ext = ext in fileTypes
        if has_known_ext:
            logging.warning(f"POTENTIAL RLO ATTACK: File '{filename}' has RLO after dot with known extension '{ext}'")
        else:
            logging.info(f"RLO found after dot but extension '{ext}' not in known types")
        return has_known_ext
    except Exception as ex:
        logging.error(f"Error checking RLO and extension for file {filename}: {ex}")
        return False

def detect_suspicious_filename_patterns(filename, fileTypes, max_spaces=10):
    """
    Detect various filename obfuscation techniques including:
    - RLO (Right-to-Left Override) attacks
    - Excessive spaces to hide real extensions
    - Multiple extensions

    Args:
        filename (str): The filename to check
        fileTypes (set/list): Collection of known/allowed file extensions
        max_spaces (int): Maximum allowed consecutive spaces

    Returns:
        dict: Detection results with attack types found
    """
    results = {
        'rlo_attack': False,
        'excessive_spaces': False,
        'multiple_extensions': False,
        'suspicious': False,
        'details': []
    }

    try:
        # Check for RLO attack
        if ".\u202E" in filename:
            ext = os.path.splitext(filename)[1].lower()
            if ext in fileTypes:
                results['rlo_attack'] = True
                results['details'].append(f"RLO character found after dot with known extension '{ext}'")

        # Check for excessive spaces (potential extension hiding)
        if '  ' in filename:  # Start with double space check
            space_count = 0
            max_consecutive_spaces = 0

            for char in filename:
                if char == ' ':
                    space_count += 1
                    max_consecutive_spaces = max(max_consecutive_spaces, space_count)
                else:
                    space_count = 0

            if max_consecutive_spaces > max_spaces:
                results['excessive_spaces'] = True
                results['details'].append(f"Excessive spaces detected: {max_consecutive_spaces} consecutive spaces")

                # Check if there's a hidden extension after the spaces
                trimmed_filename = filename.rstrip()
                if trimmed_filename != filename:
                    hidden_ext = os.path.splitext(trimmed_filename)[1].lower()
                    if hidden_ext in fileTypes:
                        results['details'].append(f"Potential hidden extension: '{hidden_ext}'")

        # Check for multiple extensions (only flag if more than 4 extensions)
        parts = filename.split('.')
        if len(parts) > 5:  # More than 4 extensions (5 parts = filename + 4 extensions)
            extensions = ['.' + part.lower() for part in parts[1:]]
            known_extensions = [ext for ext in extensions if ext in fileTypes]

            if known_extensions:  # Only flag if there are known extensions
                results['multiple_extensions'] = True
                results['details'].append(f"Excessive extensions detected ({len(parts)-1} extensions): {known_extensions}")

        # Mark as suspicious if any attack detected
        results['suspicious'] = any([
            results['rlo_attack'],
            results['excessive_spaces'],
            results['multiple_extensions']
        ])

        if results['suspicious']:
            logging.warning(f"SUSPICIOUS FILENAME DETECTED: {filename} - {results['details']}")

        return results

    except Exception as ex:
        logging.error(f"Error analyzing filename {filename}: {ex}")
        return results

class FileType:
    UNKNOWN = -1
    ELF = 0
    PE = 1
    MACHO = 2


class CompressionFlag:
    UNKNOWN = -1
    NON_COMPRESSED = 0
    COMPRESSED = 1


class NuitkaPayload:
    MAGIC_KA = b'KA'
    MAGIC_UNCOMPRESSED = ord('X')
    MAGIC_COMPRESSED = ord('Y')

    def _validate(self):
        """Validate payload magic and set compression flag"""
        if not self.data.startswith(self.MAGIC_KA):
            logging.error("Invalid Nuitka payload magic")

        magic_type = self.data[2]
        if magic_type == self.MAGIC_UNCOMPRESSED:
            self.compression = CompressionFlag.NON_COMPRESSED
        elif magic_type == self.MAGIC_COMPRESSED:
            self.compression = CompressionFlag.COMPRESSED
        else:
            logging.error(f"Unknown compression magic: {magic_type}")

    def __init__(self, data: bytes, offset: int, size: int):
        self.data = data
        self.offset = offset
        self.size = size
        self.compression = CompressionFlag.UNKNOWN
        self._validate()


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
                logging.error(f"Failed to initialize decompression: {str(ex)}")
        return stream


class NuitkaExtractor:
    def __init__(self, filepath: str, output_dir: str):
        self.filepath = filepath
        self.output_dir = output_dir
        self.file_type = FileType.UNKNOWN
        self.payload: Optional[NuitkaPayload] = None

    def _detect_file_type(self) -> int:
        """Detect the executable file type using Detect It Easy methods"""
        die_output = get_die_output_binary(self.filepath)

        if is_pe_file_from_output(die_output):
            return FileType.PE
        if is_elf_file_from_output(die_output):
            return FileType.ELF
        if is_macho_file_from_output(die_output):
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
                logging.error("No resource directory found")

            offset, size = self._find_pe_resource(pe)
            if offset is None or size is None:
                logging.error("No Nuitka payload found in PE resources")

            # Read the payload data
            with open(self.filepath, 'rb') as f:
                f.seek(offset)
                payload_data = f.read(size)

            return NuitkaPayload(payload_data, offset, size)

        except Exception as ex:
            logging.error(f"PE payload extraction failed: {str(ex)}")

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
            logging.error(f"ELF payload extraction failed: {str(ex)}")

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

            logging.error("No payload section found in Mach-O file")

        except Exception as ex:
            logging.error(f"Mach-O payload extraction failed: {str(ex)}")

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
                logging.error("Unsupported file type")

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
                logging.error("Failed to extract payload")

            logging.info(f"[+] Payload size: {self.payload.size} bytes")
            logging.info(f"[+] Compression: {'Yes' if self.payload.compression == CompressionFlag.COMPRESSED else 'No'}")

            # Extract files from payload
            stream = self.payload.get_stream()
            total_files = self._extract_files(stream)

            logging.info(f"[+] Successfully extracted {total_files} files to {self.output_dir}")

        except Exception as ex:
            logging.error(f"[!] Unexpected error: {str(ex)}")


def scan_zip_file(file_path):
    """
    Scan a ZIP archive for:
      - RLO in filename warnings (encrypted vs non-encrypted)
      - Size bomb warnings (even if AES encrypted)
      - Single entry text files containing"Password:" (HEUR:Win32.Susp.Encrypted.Zip.SingleEntry)

    Returns:
      (success: bool, entries: List[(filename, uncompressed_size, encrypted_flag)])
    """
    try:
        zip_size = os.path.getsize(file_path)
        entries = []

        with pyzipper.ZipFile(file_path, 'r') as zf:
            for info in zf.infolist():
                encrypted = bool(info.flag_bits & 0x1)

                detection_result = detect_suspicious_filename_patterns(info.filename, fileTypes)
                if detection_result['suspicious']:
                    # Build attack type string
                    attack_types = []
                    if detection_result['rlo_attack']:
                        attack_types.append("RLO")
                    if detection_result['excessive_spaces']:
                        attack_types.append("Spaces")
                    if detection_result['multiple_extensions']:
                        attack_types.append("MultiExt")

                    attack_string = "+".join(attack_types) if attack_types else "Generic"
                    virus = f"HEUR:{attack_string}.Susp.Name.Encrypted.ZIP.gen" if encrypted else f"HEUR:{attack_string}.Susp.Name.ZIP.gen"

                    notify_susp_archive_file_name_warning(file_path, "ZIP", virus)

                # Record metadata
                entries.append((info.filename, info.file_size, encrypted))

                # Size-bomb check
                if zip_size < 20 * 1024 * 1024 and info.file_size > 650 * 1024 * 1024:
                    virus = "HEUR:Win32.Susp.Size.Encrypted.ZIP" if encrypted else "HEUR:Win32.Susp.Size.ZIP"
                    notify_size_warning(file_path, "ZIP", virus)

        # Single-entry password logic
        if len(entries) == 1:
            fname, _, encrypted = entries[0]
            if not encrypted:
                with pyzipper.ZipFile(file_path, 'r') as zf:
                    snippet = zf.open(fname).read(4096)
                if is_plain_text(snippet) and 'Password:' in snippet.decode('utf-8', errors='ignore'):
                    notify_size_warning(file_path, "ZIP", "HEUR:Win32.Susp.Encrypted.Zip.SingleEntry")

        return True, entries

    except pyzipper.zipfile.BadZipFile:
        logging.error(f"Not a valid ZIP archive: {file_path}")
        return False, []
    except Exception as ex:
        logging.error(f"Error scanning zip file: {file_path} {ex}")
        return False, []


def scan_7z_file(file_path):
    """
    Scan a 7z archive for:
      - RLO in filename warnings (encrypted vs non-encrypted)
      - Size bomb warnings (even if encrypted)
      - Single entry text files containing"Password:" (HEUR:Win32.Susp.Encrypted.7z.SingleEntry)

    Returns:
      (success: bool, entries: List[(filename, uncompressed_size, encrypted_flag)])
    """
    try:
        archive_size = os.path.getsize(file_path)
        entries = []

        with py7zr.SevenZipFile(file_path, mode='r') as archive:
            for entry in archive.list():
                filename = entry.filename
                encrypted = entry.is_encrypted

                detection_result = detect_suspicious_filename_patterns(filename, fileTypes)
                if detection_result['suspicious']:
                    # Build attack type string
                    attack_types = []
                    if detection_result['rlo_attack']:
                        attack_types.append("RLO")
                    if detection_result['excessive_spaces']:
                        attack_types.append("Spaces")
                    if detection_result['multiple_extensions']:
                        attack_types.append("MultiExt")

                    attack_string = "+".join(attack_types) if attack_types else "Generic"
                    virus = f"HEUR:{attack_string}.Susp.Name.Encrypted.7z.gen" if encrypted else f"HEUR:{attack_string}.Susp.Name.7z.gen"

                    notify_susp_archive_file_name_warning(file_path, "7z", virus)

                # Record metadata
                entries.append((filename, entry.uncompressed, encrypted))

                # Size-bomb check
                if archive_size < 20 * 1024 * 1024 and entry.uncompressed > 650 * 1024 * 1024:
                    virus = "HEUR:Win32.Susp.Size.Encrypted.7z" if encrypted else "HEUR:Win32.Susp.Size.7z"
                    notify_size_warning(file_path, "7z", virus)

        # Single-entry password logic
        if len(entries) == 1:
            fname, _, encrypted = entries[0]
            if not encrypted:
                data_map = archive.read([fname])
                snippet = data_map.get(fname, b'')[:4096]
                if is_plain_text(snippet) and 'Password:' in snippet.decode('utf-8', errors='ignore'):
                    notify_size_warning(file_path, "7z", "HEUR:Win32.Susp.Encrypted.7z.SingleEntry")

        return True, entries

    except py7zr.exceptions.Bad7zFile:
        logging.error(f"Not a valid 7z archive: {file_path}")
        return False, []
    except Exception as ex:
        logging.error(f"Error scanning 7z file: {file_path} {ex}")
        return False, []

def is_7z_file_from_output(die_output: str) -> bool:
    """
    Checks if DIE output indicates a 7-Zip archive.
    Expects the raw stdout (or equivalent) from a Detect It Easy run.
    """
    if die_output and "Archive: 7-Zip" in die_output:
        logging.info("DIE output indicates a 7z archive.")
        return True

    logging.info(f"DIE output does not indicate a 7z archive: {die_output!r}")
    return False

def scan_tar_file(file_path):
    """Scan files within a tar archive."""
    try:
        tar_size = os.path.getsize(file_path)

        with tarfile.open(file_path, 'r') as tar:
            for member in tar.getmembers():
                detection_result = detect_suspicious_filename_patterns(member.name, fileTypes)
                if detection_result['suspicious']:
                    # Build attack type string
                    attack_types = []
                    if detection_result['rlo_attack']:
                        attack_types.append("RLO")
                    if detection_result['excessive_spaces']:
                        attack_types.append("Spaces")
                    if detection_result['multiple_extensions']:
                        attack_types.append("MultiExt")

                    attack_string = "+".join(attack_types) if attack_types else "Generic"
                    virus_name = f"HEUR:{attack_string}.Susp.Name.TAR.gen"

                    logging.warning(
                        f"Filename '{member.name}' in archive '{file_path}' contains suspicious pattern(s): {attack_string} - "
                        f"flagged as {virus_name}"
                    )
                    notify_susp_archive_file_name_warning(file_path, "TAR", virus_name)

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
                        virus_name = "HEUR:Win32.Susp.Size.Encrypted.TAR"
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

    if file_path in worm_alerted_files:
        logging.info(f"Worm alert already triggered for {file_path}, skipping...")
        return

    try:
        logging.info(f"Running worm detection for file '{file_path}'")

        # Extract features
        features_current = extract_numeric_worm_features(file_path)
        is_critical = file_path.startswith(main_drive_path) or file_path.startswith(system_root) or file_path.startswith(sandbox_system_root_directory)

        if is_critical:
            original_file_path = os.path.join(system_root, os.path.basename(file_path))
            sandbox_file_path = os.path.join(sandbox_system_root_directory, os.path.basename(file_path))

            if os.path.exists(original_file_path) and os.path.exists(sandbox_file_path):
                original_file_size = os.path.getsize(original_file_path)
                current_file_size = os.path.getsize(sandbox_file_path)
                size_difference = abs(current_file_size - original_file_size) / original_file_size

                original_file_mtime = os.path.getmtime(original_file_path)
                current_file_mtime = os.path.getmtime(sandbox_file_path)
                mtime_difference = abs(current_file_mtime - original_file_mtime)

                if size_difference > 0.10:
                    logging.warning(f"File size difference for '{file_path}' exceeds 10%.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Critical.Agnostic.gen.Malware")
                    worm_alerted_files.append(file_path)
                    return  # Only flag once if a critical difference is found

                if mtime_difference > 3600:  # 3600 seconds = 1 hour
                    logging.warning(f"Modification time difference for '{file_path}' exceeds 1 hour.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Critical.Time.Agnostic.gen.Malware")
                    worm_alerted_files.append(file_path)
                    return  # Only flag once if a critical difference is found

            # Proceed with worm detection based on critical file comparison
            worm_detected = check_worm_similarity(file_path, features_current)

            if worm_detected:
                logging.warning(f"Worm '{file_path}' detected in critical directory. Alerting user.")
                notify_user_worm(file_path, "HEUR:Win32.Worm.Classic.Critical.gen.Malware")
                worm_alerted_files.append(file_path)

        else:
            # Check for generic worm detection
            worm_detected = check_worm_similarity(file_path, features_current)
            worm_detected_count[file_path] = worm_detected_count.get(file_path, 0) + 1

            if worm_detected or worm_detected_count[file_path] >= 5:
                if file_path not in worm_alerted_files:
                    logging.warning(f"Worm '{file_path}' detected under 5 different names or as potential worm. Alerting user.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Classic.gen.Malware")
                    worm_alerted_files.append(file_path)

                # Notify for all files that have reached the detection threshold
                for detected_file in worm_detected_count:
                    if worm_detected_count[detected_file] >= 5 and detected_file not in worm_alerted_files:
                        notify_user_worm(detected_file, "HEUR:Win32.Worm.Classic.gen.Malware")
                        worm_alerted_files.append(detected_file)

    except Exception as ex:
        logging.error(f"Error in worm detection for file {file_path}: {ex}")

def check_pe_file(file_path, signature_check, file_name):
    try:
        # Normalize the file path to lowercase for comparison
        normalized_path = os.path.abspath(file_path).lower()
        normalized_sandboxie = sandboxie_folder.lower()

        logging.info(f"File {file_path} is a valid PE file.")

        # Check if file is inside the Sandboxie folder
        if normalized_path.startswith(normalized_sandboxie):
            worm_alert(file_path)
            logging.info(f"File {file_path} is inside Sandboxie folder, scanned with worm_alert.")

        # Check for fake system files after signature validation
        if file_name in fake_system_files and os.path.abspath(file_path).startswith(main_drive_path):
            if not signature_check["is_valid"]:
                logging.warning(f"Detected fake system file: {file_path}")
                notify_user_for_detected_fake_system_file(file_path, file_name, "HEUR:Win32.FakeSystemFile.Dropper.gen")

    except Exception as ex:
        logging.error(f"Error checking PE file {file_path}: {ex}")

def is_zip_file(file_path):
    """
    Return True if file_path is a valid ZIP (AES or standard), False otherwise.
    """
    try:
        # Try standard ZIP
        with pyzipper.ZipFile(file_path, 'r'):
            return True
    except pyzipper.zipfile.BadZipFile:
        # Try AES ZIP
        try:
            with pyzipper.AESZipFile(file_path, 'r'):
                return True
        except Exception:
            return False
    except Exception as e:
        logging.error(f"Unexpected error checking ZIP: {e}")
        return False

def scan_file_real_time(file_path, signature_check, file_name, die_output, pe_file=False):
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

        # Worm analysis and fake file analysis
        try:
            if pe_file:
                check_pe_file(file_path, signature_check, file_name)
        except Exception as ex:
            logging.error(f"An error occurred while scanning the file for fake system files and worm analysis: {file_path}. Error: {ex}")

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
                if scan_result and virus_name not in ("Clean", "F", "", [], None):
                    virus_str = str(virus_name) if virus_name else "Unknown"
                    if signature_check["is_valid"]:
                        virus_name = "SIG." + virus_str
                    logging.warning(f"Infected file detected (TAR): {file_path} - Virus: {virus_str}")
                    return True, virus_str, "TAR"
                logging.info(f"No malware detected in TAR file: {file_path}")
        except PermissionError:
            logging.error(f"Permission error occurred while scanning TAR file: {file_path}")
        except FileNotFoundError:
            logging.error(f"TAR file not found error occurred while scanning TAR file: {file_path}")
        except Exception as ex:
            logging.error(f"An error occurred while scanning TAR file: {file_path}. Error: {ex}")

        # Scan ZIP files
        try:
            if is_zip_file(file_path):
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
            if is_7z_file_from_output(die_output):
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

# Read the file and store the names in a list (ignoring empty lines)
with open(system_file_names_path, "r") as f:
    fake_system_files = [line.strip() for line in f if line.strip()]

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

                            signature_info = check_valid_signature(file_path)
                            if status == "Info":
                                if not signature_info["is_valid"]:
                                    logging.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has an invalid or no signature. Alert Line: {alert_line}")
                                else:
                                    logging.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature. Alert Line: {alert_line}")
                            else:
                                if not signature_info["is_valid"]:
                                    logging.warning(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip} has invalid or no signature. Alert Line: {alert_line}")
                                    notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status)
                                else:
                                    logging.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature and is not flagged as malicious. Alert Line: {alert_line}")

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
                    return False

                if priority == 1:
                    logging.warning(f"Malicious activity detected: {line.strip()} | Source: {src_ip} -> Destination: {dst_ip} | Priority: {priority}")
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
    except Exception as ex:
        logging.error(f"Error matching alert regex: {ex}")

def clean_directory():
    """
    Remove all files, symlinks, and subdirectories under the given log_folder.
    If the folder does not exist, logs a warning and does nothing.
    """
    # Only proceed if the directory exists
    if not os.path.exists(log_folder):
        logging.info(f"Directory '{log_folder}' does not exist. Skipping cleanup.")
        return

    # Iterate through all entries in the directory
    for filename in os.listdir(log_folder):
        file_path = os.path.join(log_folder, filename)
        try:
            # Remove files or symlinks
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            # Remove directories
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as ex:
            logging.error(f"Failed to delete '{file_path}'. Reason: {ex}")

def run_snort():
    try:
        clean_directory()
        # Run snort without capturing output
        subprocess.run(snort_command, check=True, encoding="utf-8", errors="ignore")

        logging.info("Snort completed analysis.")

    except subprocess.CalledProcessError as ex:
        logging.error(f"Snort encountered an error: {ex}")

    except Exception as ex:
        logging.error(f"Failed to run Snort: {ex}")

def activate_uefi_drive():
    # Check if the platform is Windows
    mount_command = 'mountvol X: /S'  # Command to mount UEFI drive
    try:
        # Execute the mountvol command
        subprocess.run(mount_command, shell=True, check=True, encoding="utf-8", errors="ignore")
        logging.info("UEFI drive activated!")
    except subprocess.CalledProcessError as ex:
        logging.error(f"Error mounting UEFI drive: {ex}")

threading.Thread(target=run_snort).start()
restart_clamd_thread()
clean_directories()
activate_uefi_drive() # Call the UEFI function
load_website_data()
load_antivirus_list()
# Load Antivirus and Microsoft digital signatures
antivirus_signatures = load_digital_signatures(digital_signatures_list_antivirus_path, "Antivirus digital signatures")
goodsign_signatures = load_digital_signatures(digital_signatures_list_antivirus_path, "UnHackMe digital signatures")

# Load ML definitions
try:
    with open(machine_learning_results_json, 'r') as results_file:
        ml_defs = json.load(results_file)
        malicious_numeric_features = ml_defs.get('malicious_numeric_features', [])
        malicious_file_names = ml_defs.get('malicious_file_names', [])
        benign_numeric_features = ml_defs.get('benign_numeric_features', [])
        benign_file_names = ml_defs.get('benign_file_names', [])
        logging.info("Machine Learning Definitions loaded!")
except Exception as ex:
    logging.error(f"Error loading ML definitions from {machine_learning_results_json}: {ex}")

try:
    # Load excluded rules from text file
    with open(excluded_rules_path, "r") as excluded_file:
        excluded_rules = excluded_file.read()
        logging.info("YARA Excluded Rules Definitions loaded!")
except Exception as ex:
    logging.error(f"Error loading excluded rules: {ex}")

try:
    # Load the precompiled yarGen rules from the .yrc file
    yarGen_rule = yara.load(yarGen_rule_path)
    logging.info("yarGen Rules Definitions loaded!")
except yara.Error as ex:
    logging.error(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled icewater rules from the .yrc file
    icewater_rule = yara.load(icewater_rule_path)
    logging.info("Icewater Rules Definitions loaded!")
except yara.Error as ex:
    logging.error(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled valhalla rules from the .yrc file
    valhalla_rule = yara.load(valhalla_rule_path)
    logging.info("Vallhalla Demo Rules Definitions loaded!")
except yara.Error as ex:
    logging.error(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled rules from the .yrc file
    compiled_rule = yara.load(compiled_rule_path)
    logging.info("YARA Rules Definitions loaded!")
except yara.Error as ex:
    logging.error(f"Error loading precompiled YARA rule: {ex}")

try:
    # Load the precompiled yaraxtr rule from the .yrc file using yara_x
    with open(yaraxtr_yrc_path, 'rb') as yara_x_f:
        yaraxtr_rule = yara_x.Rules.deserialize_from(yara_x_f)
    logging.info("YARA-X yaraxtr Rules Definitions loaded!")
except Exception as ex:
    logging.error(f"Error loading YARA-X rules: {ex}")

try:
    # Load the precompiled cx_freeze rule from the .yrc file using yara_x
    with open(cx_freeze_yrc_path, 'rb') as yara_x_cx_freeze:
        cx_freeze_rule = yara_x.Rules.deserialize_from(yara_x_cx_freeze)
    logging.info("YARA-X cx_freeze Rules Definitions loaded!")
except Exception as ex:
    logging.error(f"Error loading YARA-X rules: {ex}")

# Function to load Meta Llama-3.2-1B model and tokenizer
def load_meta_llama_1b_model():
    try:
        message = "Attempting to load Llama-3.2-1B model and tokenizer..."
        logging.info(message)

        llama32_tokenizer = AutoTokenizer.from_pretrained(meta_llama_1b_dir, local_files_only=True)
        llama32_model = AutoModelForCausalLM.from_pretrained(meta_llama_1b_dir, local_files_only=True)

        success_message = "Llama-3.2-1B successfully loaded!"
        logging.info(success_message)

        return llama32_model, llama32_tokenizer
    except Exception as ex:
        error_message = f"Error loading Llama-3.2-1B model or tokenizer: {ex}"
        logging.error(error_message)
        sys.exit(1)

# Load the Meta Llama-3.2-1B model
meta_llama_1b_model, meta_llama_1b_tokenizer = load_meta_llama_1b_model()

# List to keep track of existing project names
existing_projects = []

# List of already scanned files and their modification times
scanned_files = []
file_mod_times = {}

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
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore")

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

def extract_original_norm_path_from_decompiled(file_path):
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

def is_nuitka_file_from_output(die_output):
    """
    Check if the DIE output indicates a Nuitka executable.
    Returns:
      - "Nuitka OneFile" if the DIE output contains "Packer: Nuitka[OneFile]"
      - "Nuitka" if the DIE output contains "Packer: Nuitka"
      - None otherwise.
    """
    if die_output is None:
        logging.error("No DIE output available for Nuitka check.")
        return None

    if "Packer: Nuitka[OneFile]" in die_output:
        logging.info("DIE output indicates a Nuitka OneFile executable.")
        return "Nuitka OneFile"
    elif "Packer: Nuitka" in die_output:
        logging.info("DIE output indicates a Nuitka executable.")
        return "Nuitka"
    else:
        logging.info(f"DIE output does not indicate a Nuitka executable. Output: {die_output}")
        return None

def clean_text(input_text):
    """
    Remove non-logging.infoable ASCII control characters from the input text.

    :param input_text: The string to clean.
    :return: Cleaned text with control characters removed.
    """
    # Remove non-logging.infoable characters (ASCII 0-31 and 127)
    cleaned_text = re.sub(r'[\x00-\x1F\x7F]+', '', input_text)
    return cleaned_text

def scan_rsrc_files(file_paths):
    """
    Given a list of file paths for rsrcdata resources, this function scans each file
    and processes only the first file that contains the string 'upython.exe'.
    Once found, it extracts the source code portion starting after 'upython.exe',
    cleans it, saves it to a uniquely named file, and scans the code for domains,
    URLs, IP addresses, and Discord webhooks-passing both the code and the file path.
    """
    if isinstance(file_paths, str):
        file_paths = [file_paths]

    executable_file = None

    # First, find the file containing 'upython.exe'
    for file_path in file_paths:
        if os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    if "upython.exe" in f.read():
                        executable_file = file_path
                        logging.info(f"Found executable in: {file_path}")
                        break
            except Exception as ex:
                logging.error(f"Error reading file {file_path}: {ex}")
        else:
            logging.warning(f"Path {file_path} is not a valid file.")

    if executable_file is None:
        logging.info("No file containing 'upython.exe' was found.")
        return

    # Process the matched file
    try:
        logging.info(f"Processing file: {executable_file}")
        with open(executable_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        if lines:
            # Locate the marker line
            source_index = next((i for i, line in enumerate(lines) if "upython.exe" in line), None)

            if source_index is not None:
                line_with_marker = lines[source_index]
                marker_index = line_with_marker.find("upython.exe")
                remainder = line_with_marker[marker_index + len("upython.exe"):].lstrip()

                # Build the source code lines
                source_code_lines = ([remainder] if remainder else []) + lines[source_index + 1:]
                cleaned_source_code = [clean_text(line.rstrip()) for line in source_code_lines]

                # Determine unique save path
                base_name = os.path.splitext(os.path.basename(executable_file))[0]
                save_filename = f"{base_name}_source_code.txt"
                save_path = os.path.join(nuitka_source_code_dir, save_filename)

                # If a file with the same name exists, append a counter
                counter = 1
                while os.path.exists(save_path):
                    save_filename = f"{base_name}_source_code_{counter}.txt"
                    save_path = os.path.join(nuitka_source_code_dir, save_filename)
                    counter += 1

                # Make absolutely sure the parent directory exists
                os.makedirs(os.path.dirname(save_path), exist_ok=True)

                # Write out the cleaned source
                with open(save_path, "w", encoding="utf-8") as save_file:
                    for line in cleaned_source_code:
                        save_file.write(line + "\n")
                logging.info(f"Saved extracted source code from {executable_file} to {save_path}")

                # Now pass both the code *and* the original file path
                extracted_source_code = ''.join(source_code_lines)
                scan_code_for_links(extracted_source_code, executable_file)

            else:
                logging.info(f"No line containing 'upython.exe' found in {executable_file}.")
        else:
            logging.info(f"File {executable_file} is empty.")
    except Exception as ex:
        logging.error(f"Error during file scanning of {executable_file}: {ex}")

def scan_directory_for_executables(directory):
    """
    Recursively scan a directory for .exe, .dll, .msi, and .kext files,
    prioritizing Nuitka executables.
    If a file is found and confirmed as Nuitka, stop further scanning.
    """
    found_executables = []

    # Helper to analyze + test one file
    def check_file(path):
        die_output = get_die_output_binary(path)
        return is_nuitka_file_from_output(die_output)

    # Look for .exe files first
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.exe'):
                file_path = os.path.join(root, file)
                nuitka_type = check_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .exe is found

    # If no .exe found, look for .dll files
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.dll'):
                file_path = os.path.join(root, file)
                nuitka_type = check_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .dll is found

    # Check for macOS kernel extensions (.kext files)
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.kext'):
                file_path = os.path.join(root, file)
                nuitka_type = check_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as .kext is found

    # If none of the above, check other files
    for root, _, files in os.walk(directory):
        for file in files:
            if not file.lower().endswith(('.exe', '.dll', '.kext')):
                file_path = os.path.join(root, file)
                nuitka_type = check_file(file_path)
                if nuitka_type:
                    found_executables.append((file_path, nuitka_type))
                    return found_executables  # Stop scanning further as a Nuitka file is found

    return found_executables

def is_pyinstaller_archive_from_output(die_output):
    """
    Check if the DIE output indicates a PyInstaller archive.
    A file is considered a PyInstaller archive if the output contains:
      - "Packer: PyInstaller"
    """
    if die_output and "Packer: PyInstaller" in die_output:
        logging.info("DIE output indicates a PyInstaller archive.")
        return True

    logging.info(f"DIE output does not indicate a PyInstaller archive: {die_output}")
    return False

def pycHeader2Magic(header):
    header = bytearray(header)
    magicNumber = bytearray(header[:2])
    return magicNumber[1] << 8 | magicNumber[0]

class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name

class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    MAGIC = b"MEI\014\013\012\013\016"  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b"\0" * 4
        self.barePycList = []  # List of pyc's whose headers have to be fixed
        self.cryptoKey = None
        self.cryptoKeyFileData = None

    def open(self):
        try:
            self.fPtr = open(self.filePath, "rb")
            self.fileSize = os.stat(self.filePath).st_size
        except:
            logging.error("Could not open %s", self.filePath)
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    def checkFile(self):
        logging.info("Processing %s", self.filePath)

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            logging.error("File is too short or truncated")
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            logging.error(
                "Missing cookie, unsupported pyinstaller version or not a pyinstaller archive"
            )
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b"python" in self.fPtr.read(64).lower():
            logging.info("Pyinstaller version: 2.1+")
            self.pyinstVer = 21  # pyinstaller 2.1+
        else:
            self.pyinstVer = 20  # pyinstaller 2.0
            logging.info("Pyinstaller version: 2.0")

        return True

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = struct.unpack(
                    "!8siiii", self.fPtr.read(self.PYINST20_COOKIE_SIZE)
                )

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = struct.unpack(
                    "!8sIIii64s", self.fPtr.read(self.PYINST21_COOKIE_SIZE)
                )

        except:
            logging.error("Error: The file is not a pyinstaller archive")
            return False

        self.pymaj, self.pymin = (
            (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        )
        logging.info("Python version: %s.%s", self.pymaj, self.pymin)

        # Additional data after the cookie
        tailBytes = (
            self.fileSize
            - self.cookiePos
            - (
                self.PYINST20_COOKIE_SIZE
                if self.pyinstVer == 20
                else self.PYINST21_COOKIE_SIZE
            )
        )

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        logging.info("Length of package: %s bytes", lengthofPackage)
        return True

    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize,) = struct.unpack("!i", self.fPtr.read(4))
            nameLen = struct.calcsize("!iIIIBc")

            (
                entryPos,
                cmprsdDataSize,
                uncmprsdDataSize,
                cmprsFlag,
                typeCmprsData,
                name,
            ) = struct.unpack(
                "!IIIBc{0}s".format(entrySize - nameLen), self.fPtr.read(entrySize - 4)
            )

            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                newName = str(uniquename())
                logging.warning("File name %s contains invalid bytes. Using random name %s", name, newName)
                name = newName

            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                logging.warning("Found an unnamed file in CArchive. Using random name %s", name)

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name,
                )
            )

            parsedLen += entrySize
        logging.info("Found %d files in CArchive", len(self.tocList))

    def _writeRawData(self, filepath, data):
        nm = (
            filepath.replace("\\", os.path.sep)
            .replace("/", os.path.sep)
            .replace("..", "__")
        )
        nmDir = os.path.dirname(nm)
        if nmDir != "" and not os.path.exists(
            nmDir
        ):  # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, "wb") as f:
            f.write(data)

    def extractFiles(self, one_dir):
        logging.info("Beginning extraction...please standby")
        extractionDir = pyinstaller_extracted_dir
        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            if entry.typeCmprsData == b"d" or entry.typeCmprsData == b"o":
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != "":
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b"s":
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                logging.info("Possible entry point: %s.pyc", entry.name)

                if self.pycMagic == b"\0" * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + ".pyc")
                self._writePyc(entry.name + ".pyc", data)

            elif entry.typeCmprsData == b"M" or entry.typeCmprsData == b"m":
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b"\r\n":
                    # < pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        logging.info(
                            "Detected _crypto_key file, saving key for automatic decryption"
                        )
                        # This is a pyc file with a header (8,12, or 16 bytes)
                        # Extract the code object after the header
                        self.cryptoKeyFileData = self._extractCryptoKeyObject(data)

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + ".pyc")

                    self._writePyc(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        logging.info(
                            "Detected _crypto_key file, saving key for automatic decryption"
                        )
                        # This is a plain code object without a header
                        self.cryptoKeyFileData = data

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b"z" or entry.typeCmprsData == b"Z":
                    self._extractPyz(entry.name, one_dir)

        # Fix bare pyc's if any
        self._fixBarePycs()

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, "r+b") as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def _extractCryptoKeyObject(self, data):
        if self.pymaj >= 3 and self.pymin >= 7:
            # 16 byte header for 3.7 and above
            return data[16:]
        elif self.pymaj >= 3 and self.pymin >= 3:
            # 12 byte header for 3.3-3.6
            return data[12:]
        else:
            # 8 byte header for 2.x, 3.0-3.2
            return data[8:]

    def _writePyc(self, filename, data):
        with open(filename, "wb") as pycFile:
            pycFile.write(self.pycMagic)  # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:  # PEP 552 -- Deterministic pycs
                pycFile.write(b"\0" * 4)  # Bitfield
                pycFile.write(b"\0" * 8)  # (Timestamp + size) || hash

            else:
                pycFile.write(b"\0" * 4)  # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b"\0" * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)

    def _getCryptoKey(self):
        if self.cryptoKey:
            return self.cryptoKey

        if not self.cryptoKeyFileData:
            return None

        co = load_code(self.cryptoKeyFileData, pycHeader2Magic(self.pycMagic))
        self.cryptoKey = co.co_consts[0]
        return self.cryptoKey

    def _tryDecrypt(self, ct, aes_mode):
        CRYPT_BLOCK_SIZE = 16

        key = bytes(self._getCryptoKey(), "utf-8")
        assert len(key) == 16

        # Initialization vector
        iv = ct[:CRYPT_BLOCK_SIZE]

        if aes_mode == "ctr":
            # Pyinstaller >= 4.0 uses AES in CTR mode
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])

        elif aes_mode == "cfb":
            # Pyinstaller < 4.0 uses AES in CFB mode
            cipher = AES.new(key, AES.MODE_CFB, iv)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])

    def _extractPyz(self, name, one_dir):
        if one_dir == True:
            dirName = "."
        else:
            dirName = name + "_extracted"
            # Create a directory for the contents of the pyz
            if not os.path.exists(dirName):
                os.mkdir(dirName)

        with open(name, "rb") as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b"PYZ\0"  # Sanity Check

            pyzPycMagic = f.read(4)  # Python magic value

            if self.pycMagic == b"\0" * 4:
                self.pycMagic = pyzPycMagic

            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                logging.warning(
                    "pyc magic of files inside PYZ archive are different from those in CArchive"
                )

            (tocPosition,) = struct.unpack("!i", f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = load_code(f, pycHeader2Magic(pyzPycMagic))
            except:
                logging.error("Unmarshalling FAILED. Cannot extract %s. Extracting remaining files.", name)
                return

            logging.info("Found %d files in PYZ archive", len(toc))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode("utf-8")
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace("..", "__").replace(".", os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, "__init__.pyc")

                else:
                    filePath = os.path.join(dirName, fileName + ".pyc")

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    try:
                        # Automatic decryption
                        # Make a copy
                        data_copy = data

                        # Try CTR mode, Pyinstaller >= 4.0 uses AES in CTR mode
                        data = self._tryDecrypt(data, "ctr")
                        data = zlib.decompress(data)
                    except:
                        # Try CFB mode, Pyinstaller < 4.0 uses AES in CFB mode
                        try:
                            data = data_copy
                            data = self._tryDecrypt(data, "cfb")
                            data = zlib.decompress(data)
                        except:
                            logging.error("Failed to decrypt & decompress %s. Extracting as is.", filePath)
                            open(filePath + ".encrypted", "wb").write(data_copy)
                            continue

                self._writePyc(filePath, data)

def extract_pyinstaller_archive(file_path):
    try:
        archive = PyInstArchive(file_path)

        # Open the PyInstaller archive
        if not archive.open():
            logging.error(f"Failed to open PyInstaller archive: {file_path}")
            return None

        # Check if the file is a valid PyInstaller archive
        if not archive.checkFile():
            logging.error(f"File {file_path} is not a valid PyInstaller archive.")
            return None

        # Retrieve CArchive info from the archive
        if not archive.getCArchiveInfo():
            logging.error(f"Failed to get CArchive info from {file_path}.")
            return None

        # Parse the Table of Contents (TOC) from the archive
        if not archive.parseTOC():
            logging.error(f"Failed to parse TOC from {file_path}.")
            return None

        # Extract files to the specified pyinstaller_extracted_dir
        extraction_dir = archive.extractFiles(one_dir=True)

        # Close the archive
        archive.close()

        logging.info(f"[+] Extraction completed successfully: {extraction_dir}")

        return extraction_dir

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
                logging.warning(f"File '{file_path}' might be a ransomware sign")
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
    global ransomware_detection_count

    try:
        logging.info(f"Running ransomware alert check for file '{file_path}'")

        # Check the ransomware flag once.
        if is_ransomware(file_path):
            # If file is from the Sandboxie log folder, trigger Sandboxie-specific alert.
            if file_path.startswith(sandboxie_log_folder):
                ransomware_detection_count += 1
                logging.warning(f"File '{file_path}' (Sandboxie log) flagged as potential ransomware. Count: {ransomware_detection_count}")
                notify_user_ransomware(main_file_path, "HEUR:Win32.Ransom.Log.gen")
                logging.warning(f"User has been notified about potential ransomware in {main_file_path} (Sandboxie log alert)")

            # Normal processing for all flagged files.
            ransomware_detection_count += 1
            logging.warning(f"File '{file_path}' might be a ransomware sign. Count: {ransomware_detection_count}")

            # When exactly two alerts occur, search for files with the same extension.
            if ransomware_detection_count == 2:
                _, ext = os.path.splitext(file_path)
                if ext:
                    directory = os.path.dirname(file_path)
                    files_with_same_extension = search_files_with_same_extension(directory, ext)
                    for ransom_file in files_with_same_extension:
                        logging.info(f"Checking file '{ransom_file}' with same extension '{ext}'")
                        if is_ransomware(ransom_file):
                            logging.warning(f"File '{ransom_file}' might also be related to ransomware")

            # When detections reach a threshold, notify the user with a generic flag.
            if ransomware_detection_count >= 10:
                notify_user_ransomware(main_file_path, "HEUR:Win32.Ransom.gen")
                logging.warning(f"User has been notified about potential ransomware in {main_file_path}")

    except Exception as ex:
        logging.error(f"Error in ransomware_alert: {ex}")

def log_directory_type(file_path):
    try:
        if file_path.startswith(pd64_extracted_dir):
            logging.info(f"{file_path}: Process Dump x64 output extracted.")
        if file_path.startswith(enigma_extracted_dir):
            logging.info(f"{file_path}: Enigma extracted.")
        elif file_path.startswith(sandboxie_folder):
            logging.info(f"{file_path}: It's a Sandbox environment file.")
        elif file_path.startswith(copied_sandbox_and_main_files_dir):
            logging.info(f"{file_path}: It's a restored sandbox environment file.")
        elif file_path.startswith(decompiled_dir):
            logging.info(f"{file_path}: Decompiled.")
        elif file_path.startswith(upx_extracted_dir):
            logging.info(f"{file_path}: UPX extracted.")
        elif file_path.startswith(inno_setup_unpacked_dir):
            logging.info(f"{file_path}: Inno Setup unpacked.")
        elif file_path.startswith(nuitka_dir):
            logging.info(f"{file_path}: Nuitka onefile extracted.")
        elif file_path.startswith(dotnet_dir):
            logging.info(f"{file_path}: .NET decompiled.")
        elif file_path.startswith(obfuscar_dir):
            logging.info(f"{file_path}: .NET file obfuscated with Obfuscar.")
        elif file_path.startswith(de4dot_sandboxie_dir):
            logging.info(f"{file_path}: It's a Sandbox environment file, also a .NET file deobfuscated with de4dot.")
        elif file_path.startswith(de4dot_extracted_dir):
            logging.info(f"{file_path}: .NET file deobfuscated with de4dot.")
        elif file_path.startswith(pyinstaller_extracted_dir):
            logging.info(f"{file_path}: PyInstaller onefile extracted.")
        elif file_path.startswith(cx_freeze_extracted_dir):
            logging.info(f"{file_path}: cx_freeze library.zip extracted.")
        elif file_path.startswith(commandlineandmessage_dir):
            logging.info(f"{file_path}: Command line message extracted.")
        elif file_path.startswith(pe_extracted_dir):
            logging.info(f"{file_path}: PE file extracted.")
        elif file_path.startswith(zip_extracted_dir):
            logging.info(f"{file_path}: ZIP extracted.")
        elif file_path.startswith(seven_zip_extracted_dir):
            logging.info(f"{file_path}: 7zip extracted.")
        elif file_path.startswith(general_extracted_with_7z_dir):
            logging.info(f"{file_path}: All files extracted with 7-Zip go here.")
        elif file_path.startswith(nuitka_extracted_dir):
            logging.info(f"{file_path}: The Nuitka binary files can be found here.")
        elif file_path.startswith(advanced_installer_extracted_dir):
            logging.info(f"{file_path}: The extracted files from Advanced Installer can be found here.")
        elif file_path.startswith(tar_extracted_dir):
            logging.info(f"{file_path}: TAR extracted.")
        elif file_path.startswith(processed_dir):
            logging.info(f"{file_path}: Processed - File is base64/base32, signature/magic bytes removed.")
        elif file_path == main_file_path:  # Check for main file path
            logging.info(f"{file_path}: This is the main file.")
        elif file_path.startswith(memory_dir):
            logging.info(f"{file_path}: It's a dynamic analysis memory dump file.")
        elif file_path.startswith(resource_extractor_dir):
            logging.info(f"{file_path}: It's an RCData resources extracted directory.")
        elif file_path.startswith(ungarbler_dir):
            logging.info(f"{file_path}: It's a deobfuscated Go Garble directory.")
        elif file_path.startswith(ungarbler_string_dir):
            logging.info(f"{file_path}: It's a directory of deobfuscated Go Garble strings.")
        elif file_path.startswith(debloat_dir):
            logging.info(f"{file_path}: It's a debloated file dir.")
        elif file_path.startswith(jar_extracted_dir):
           logging.info(f"{file_path}: It's a directory containing extracted files from a JAR (Java Archive) file.")
        elif file_path.startswith(FernFlower_decompiled_dir):
           logging.info(f"{file_path}: It's a directory containing decompiled files from a JAR (Java Archive) file, decompiled using Fernflower decompiler.")
        elif file_path.startswith(pylingual_extracted_dir):
            logging.info(f"{file_path}: It's a .pyc (Python Compiled Module) reversed-engineered Python source code directory with pylingaul.")
        elif file_path.startswith(python_deobfuscated_dir):
            logging.info(f"{file_path}: It's an unobfuscated Python directory.")
        elif file_path.startswith(python_deobfuscated_marshal_pyc_dir):
            logging.info(f"{file_path}: It's a deobfuscated .pyc (Python Compiled Module) from marshal data.")
        elif file_path.startswith(python_deobfuscated_sandboxie_dir):
            logging.info(f"{file_path}: It's an unobfuscated Python directory within Sandboxie.")
        elif file_path.startswith(pycdas_extracted_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc (Python Compiled Module) reversed-engineered Python source code directory with pycdas.exe.")
        elif file_path.startswith(python_source_code_dir):
            logging.info(f"{file_path}: It's a PyInstaller, .pyc (Python Compiled Module) reversed-engineered Python source code base directory.")
        elif file_path.startswith(nuitka_source_code_dir):
            logging.info(f"{file_path}: It's a Nuitka reversed-engineered Python source code directory.")
        elif file_path.startswith(html_extracted_dir):
            logging.info(f"{file_path}: This is the directory for HTML files of visited websites.")
        else:
            logging.warning(f"{file_path}: File does not match known directories.")
    except Exception as ex:
        logging.error(f"Error logging directory type for {file_path}: {ex}")

def scan_file_with_meta_llama(file_path, decompiled_flag=False, HiJackThis_flag=False):
    """
    Processes a file and analyzes it using Meta Llama-3.2-1B.
    If decompiled_flag is True, a normal summary is generated with
    an additional note indicating that the file was decompiled by our tool and is Python source code.

    Args:
        file_path (str): The path to the file to be scanned.
        decompiled_flag (bool): If True, indicates that the file was decompiled by our tool.
    """
    try:
        # List of directory conditions and their corresponding logging messages.
        # Note: For conditions that need an exact match (like the main file), a lambda is used accordingly.
        directory_logging_info = [
            (lambda fp: fp.startswith(pd64_extracted_dir), "Process Dump x64 output extracted."),
            (lambda fp: fp.startswith(enigma_extracted_dir), "Enigma extracted."),
            (lambda fp: fp.startswith(sandboxie_folder), "It's a Sandbox environment file."),
            (lambda fp: fp.startswith(copied_sandbox_and_main_files_dir), "It's a restored sandbox environment file."),
            (lambda fp: fp.startswith(decompiled_dir), "Decompiled."),
            (lambda fp: fp.startswith(upx_extracted_dir), "UPX extracted."),
            (lambda fp: fp.startswith(inno_setup_unpacked_dir), "Inno Setup unpacked."),
            (lambda fp: fp.startswith(nuitka_dir), "Nuitka onefile extracted."),
            (lambda fp: fp.startswith(dotnet_dir), ".NET decompiled."),
            (lambda fp: fp.startswith(obfuscar_dir), ".NET file obfuscated with Obfuscar."),
            (lambda fp: fp.startswith(de4dot_extracted_dir), ".NET file deobfuscated with de4dot."),
            (lambda fp: fp.startswith(de4dot_sandboxie_dir), "It's a Sandbox environment file, also a .NET file deobfuscated with de4dot"),
            (lambda fp: fp.startswith(pyinstaller_extracted_dir), "PyInstaller onefile extracted."),
            (lambda fp: fp.startswith(cx_freeze_extracted_dir), "cx_freeze library.zip extracted."),
            #(lambda fp: fp.startswith(commandlineandmessage_dir), "Command line message extracted."), # Due to the excessive output generated, we have disabled it.
            (lambda fp: fp.startswith(pe_extracted_dir), "PE file extracted."),
            (lambda fp: fp.startswith(zip_extracted_dir), "ZIP extracted."),
            (lambda fp: fp.startswith(seven_zip_extracted_dir), "7zip extracted."),
            (lambda fp: fp.startswith(general_extracted_with_7z_dir), "All files extracted with 7-Zip go here."),
            (lambda fp: fp.startswith(nuitka_extracted_dir), "The Nuitka binary files can be found here."),
            (lambda fp: fp.startswith(advanced_installer_extracted_dir), "The extracted files from Advanced Installer can be found here."),
            (lambda fp: fp.startswith(tar_extracted_dir), "TAR extracted."),
            (lambda fp: fp.startswith(processed_dir), "Processed - File is base64/base32, signature/magic bytes removed."),
            (lambda fp: fp == main_file_path, "This is the main file."),
            (lambda fp: fp.startswith(memory_dir), "It's a dynamic analysis memory dump file."),
            (lambda fp: fp.startswith(debloat_dir), "It's a debloated file dir."),
            (lambda fp: fp.startswith(jar_extracted_dir), "Directory containing extracted files from a JAR (Java Archive) file."),
            (lambda fp: fp.startswith(FernFlower_decompiled_dir), "This directory contains source files decompiled from a JAR (Java Archive) using the Fernflower decompiler.."),
            (lambda fp: fp.startswith(pylingual_extracted_dir), "PyInstaller, .pyc reversed-engineered source code directory with pylingual."),
            (lambda fp: fp.startswith(python_deobfuscated_dir), "It's an unobfuscated Python directory."),
            (lambda fp: fp.startswith(python_deobfuscated_marshal_pyc_dir), "It's a deobfuscated .pyc (Python Compiled Module) from marshal data."),
            (lambda fp: fp.startswith(python_deobfuscated_sandboxie_dir), "It's an unobfuscated Python directory within Sandboxie."),
            (lambda fp: fp.startswith(pycdas_extracted_dir), "PyInstaller, .pyc reversed-engineered source code directory with pycdas.exe."),
            (lambda fp: fp.startswith(python_source_code_dir), "PyInstaller, .pyc reversed-engineered source code base directory."),
            (lambda fp: fp.startswith(nuitka_source_code_dir), "Nuitka reversed-engineered Python source code directory."),
            (lambda fp: fp.startswith(html_extracted_dir), "This is the directory for HTML files of visited websites.")
        ]

        # 1) Find and log the first matching directory message, also save it for the prompt
        dir_note = None
        for condition, message in directory_logging_info:
            if condition(file_path):
                logging.info(f"{file_path}: {message}")
                dir_note = message
                break
        if dir_note is None:
            dir_note = "No special directory context."

        # 2) Build a prefix that includes the directory note
        prefix = f"[Context] {dir_note}\n\n"

        # 3) Build the initial message. Prepend prefix to every branch.
        if HiJackThis_flag:
            initial_message = prefix + (
                "Meta Llama-3.2-1B Report for HiJackThis log analysis:\n"
                "The following report is produced based on HiJackThis log differences. "
                "Analyze the file content and determine if there are suspicious changes that may indicate malware. "
                "Include the following four lines in your response:\n"
                "- Malware: [Yes/No/Maybe]\n"
                "- Virus Name:\n"
                "- Confidence: [percentage]\n"
                "- Malicious Content: [Explanation]\n"
                f"File name: {os.path.basename(file_path)}\n"
                f"File path: {file_path}\n"
            )
        elif decompiled_flag:
            initial_message = prefix + (
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
            initial_message = prefix + (
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
                "Based on the file name, file path, and file content analysis:\n\n"
                "If this file is obfuscated, it may be dangerous. I provide readable text for you to analyze it to determine if this file is malware.\n"
                "If it is a script file and obfuscated, it is probably suspicious or malware.\n"
                "If it registers itself in 'Shell Common Startup' or 'Shell Startup' and has these extensions, it could be harmful.\n"
                "Decode any encoded strings, such as base64 or base32, as needed.\n"
            )

        # Tokenize the initial message
        initial_inputs = meta_llama_1b_tokenizer(initial_message, return_tensors="pt")
        initial_token_length = initial_inputs['input_ids'].shape[1]

        # Define token limits
        max_tokens = 2048
        remaining_tokens = max_tokens - initial_token_length

        # Read the file content
        readable_file_content = ""
        line_count = 0
        max_lines = 10000  # Maximum number of lines to read

        try:
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as meta_llama_file:
                for line in meta_llama_file:
                    if line_count < max_lines:
                        readable_file_content += line
                        line_count += 1
                    else:
                        break
        except Exception as ex:
            logging.error(f"Error reading file {file_path}: {ex}")
            return None

        # Tokenize the readable file content
        file_inputs = meta_llama_1b_tokenizer(readable_file_content, return_tensors="pt")
        file_token_length = file_inputs['input_ids'].shape[1]

        # Truncate the file content if needed
        if file_token_length > remaining_tokens:
            truncated_file_content = meta_llama_1b_tokenizer.decode(
                file_inputs['input_ids'][0, :remaining_tokens], skip_special_tokens=True)
        else:
            truncated_file_content = readable_file_content

        # Combine the initial message with the truncated file content
        combined_message = initial_message + f"File content:\n{truncated_file_content}\n"

        # Padding token
        meta_llama_1b_tokenizer.pad_token = meta_llama_1b_tokenizer.eos_token

        # === Updated tokenization: include padding, truncation, and attention mask ===
        inputs = meta_llama_1b_tokenizer(
            combined_message,
            return_tensors="pt",
            padding=True,             # pad to batch max
            truncation=True,          # cut off anything beyond context window
            max_length=meta_llama_1b_model.config.max_position_embeddings,
            return_attention_mask=True
        )

        # === Updated generate: pass attention_mask and pad_token_id ===
        try:
            response_ids = accelerator.unwrap_model(meta_llama_1b_model).generate(
                input_ids=inputs["input_ids"].to(device),
                attention_mask=inputs["attention_mask"].to(device),
                pad_token_id=meta_llama_1b_tokenizer.eos_token_id,
                max_new_tokens=1000,
                num_return_sequences=1
            )
            response = meta_llama_1b_tokenizer.decode(response_ids[0], skip_special_tokens=True).strip()
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

        logging.info(final_response)

        # Log the raw model response
        answer_log_path = os.path.join(script_dir, "log", "answer.log")
        try:
            with open(answer_log_path, "a") as answer_log_file:
                answer_log_file.write(relevant_response + "\n\n")
        except Exception as ex:
            logging.error(f"Error writing to log file {answer_log_path}: {ex}")

        # Log the final summary
        log_file_path = os.path.join(script_dir, "log", "Meta Llama-3.2-1B.log")
        try:
            with open(log_file_path, "a") as log_file:
                log_file.write(final_response + "\n")
        except Exception as ex:
            logging.error(f"Error writing to log file {log_file_path}: {ex}")

        # If malware is detected (Maybe or Yes), notify the user
        if malware.lower() in ["maybe", "yes"]:
            try:
                if HiJackThis_flag:
                    notify_user_for_meta_llama(main_file_path, virus_name, malware, HiJackThis_flag=True)
                else:
                    notify_user_for_meta_llama(file_path, virus_name, malware)
            except Exception as ex:
                logging.error(f"Error notifying user: {ex}")

        # Otherwise, log and do not return (implicit None)
        logging.info("Meta Llama analysis completed.")
        return final_response

    except Exception as ex:
        logging.error(f"An unexpected error occurred in scan_file_with_meta_llama: {ex}")
        return f"[!] Llama analysis failed: {ex}"

def is_exela_v2_payload(content):
    # Simple heuristic: check if keys/tag/nonce/encrypted_data appear in content
    keys = ["key = ", "tag = ", "nonce = ", "encrypted_data"]
    return all(k in content for k in keys)

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

def process_exela_v2_payload(output_file):
    """
    Processes a decompiled Exela v2 payload:
    - Performs two-stage AES decryption.
    - Extracts and saves the final stage.
    - Searches for webhook URLs and triggers alert.
    """
    try:
        with open(output_file, 'r', encoding='utf-8') as file:
            content = file.read()

        # First layer decryption
        key_line = extract_line(content, "key = ")
        tag_line = extract_line(content, "tag = ")
        nonce_line = extract_line(content, "nonce = ")
        encrypted_data_line = extract_line(content, "encrypted_data")

        key = decode_base64_from_line(key_line)
        tag = decode_base64_from_line(tag_line)
        nonce = decode_base64_from_line(nonce_line)
        encrypted_data = decode_base64_from_line(encrypted_data_line)

        intermediate_data = DecryptString(key, tag, nonce, encrypted_data)
        temp_file = 'intermediate_data.py'
        saved_temp_file = save_to_file(temp_file, intermediate_data)

        if not saved_temp_file:
            logging.error("Failed to save intermediate data.")
            return

        with open(saved_temp_file, 'r', encoding='utf-8') as temp:
            intermediate_content = temp.read()

        # Second layer decryption
        key_2 = decode_base64_from_line(extract_line(intermediate_content, "key = "))
        tag_2 = decode_base64_from_line(extract_line(intermediate_content, "tag = "))
        nonce_2 = decode_base64_from_line(extract_line(intermediate_content, "nonce = "))
        encrypted_data_2 = decode_base64_from_line(extract_line(intermediate_content, "encrypted_data"))

        final_decrypted_data = DecryptString(key_2, tag_2, nonce_2, encrypted_data_2)
        source_code_file = 'exela_stealer_last_stage.py'
        source_code_path = save_to_file(source_code_file, final_decrypted_data)

        # Search for webhook URLs
        webhooks_discord = re.findall(discord_webhook_pattern, final_decrypted_data)
        webhooks_canary = re.findall(discord_canary_webhook_pattern, final_decrypted_data)
        webhooks = webhooks_discord + webhooks_canary

        if webhooks:
            logging.warning(f"[+] Webhook URLs found: {webhooks}")
            if source_code_path:
                notify_user_exela_stealer_v2(source_code_path, 'HEUR:Win32.Discord.PYC.Python.Exela.Stealer.v2.gen')
            else:
                logging.error("Failed to save the final decrypted source code.")
        else:
            logging.info("[!] No webhook URLs found in Exela v2 payload.")

    except Exception as ex:
        logging.error(f"Error during Exela v2 payload processing: {ex}")

def decode_zip(match: re.Match) -> str:
    """Decode one zip->chr join."""
    l1 = ast.literal_eval(match.group(1))
    l2 = ast.literal_eval(match.group(2))
    decoded = ''.join(chr((x - y) % 128) for x, y in zip(l1, l2))
    return repr(decoded)

def collapse_joins(src: str) -> str:
    """Iteratively collapse zip-join patterns until none remain."""
    prev = None
    while prev != src:
        prev = src
        src = ZIP_JOIN.sub(decode_zip, src)
    return src

def clean_source(src: str) -> str:
    # 1) Collapse chained string.join(...).join(...) of literals to single literal
    src = CHAINED_JOIN.sub(lambda m: m.group(1), src)
    # 2) Collapse zip-based joins repeatedly
    src = collapse_joins(src)
    # 3) Decode base64 constants
    src = B64_LITERAL.sub(decode_b64_import, src)
    return src

def extract_marshal_code_from_source(source: str) -> types.CodeType | None:
    """
    More flexible AST walker to find marshal.loads(...) with nested base64.b64decode calls,
    even if using __import__('zlib').decompress(...)
    """
    try:
        tree = ast.parse(source)
    except Exception as e:
        logging.error(f"Failed to parse source as AST: {e}")
        return None

    class Extractor(ast.NodeVisitor):
        def __init__(self):
            self.code_obj = None

        def is_base64_b64decode(self, func):
            # Handle base64.b64decode or __import__('base64').b64decode
            if isinstance(func, ast.Attribute):
                if func.attr == "b64decode":
                    # func.value could be Name(base64) or call __import__('base64')
                    if isinstance(func.value, ast.Name):
                        if func.value.id == "base64":
                            return True
                    elif isinstance(func.value, ast.Call):
                        # Check if __import__('base64')
                        if (
                            isinstance(func.value.func, ast.Name)
                            and func.value.func.id == "__import__"
                            and len(func.value.args) == 1
                        ):
                            arg0 = func.value.args[0]
                            if isinstance(arg0, (ast.Str, ast.Constant)):
                                val = arg0.s if hasattr(arg0, "s") else arg0.value
                                if val == "base64":
                                    return True
            return False

        def extract_base64_arg(self, node):
            """
            Recursively extract a base64 string literal passed to base64.b64decode or similar call chains.

            Args:
                node (ast.AST): The AST node to inspect.

            Returns:
                str or None: The extracted base64 string if found, otherwise None.
            """
            if isinstance(node, ast.Call):
                if self.is_base64_b64decode(node.func):
                    # Direct base64.b64decode("...") call
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            return arg.value
                else:
                    # Handle nested calls like zlib.decompress(base64.b64decode(...))
                    for arg in node.args:
                        res = self.extract_base64_arg(arg)
                        if res:
                            return res

            elif isinstance(node, ast.Attribute):
                # Continue searching through chained attributes
                return self.extract_base64_arg(node.value)

            elif isinstance(node, ast.Name):
                # Variable name - can't resolve its value statically
                return None

            return None

        def is_marshal_loads(self, func):
            # Handles marshal.loads or getattr(marshal, 'loads') style
            if isinstance(func, ast.Attribute):
                if (
                    (isinstance(func.value, ast.Name) and func.value.id == "marshal")
                    and func.attr == "loads"
                ):
                    return True
            return False

        def visit_Call(self, node):
            # Look for marshal.loads call
            if self.is_marshal_loads(node.func):
                # Try to extract base64 string recursively
                base64_data = self.extract_base64_arg(node.args[0])
                if base64_data:
                    try:
                        decoded = base64.b64decode(base64_data)
                        decompressed = zlib.decompress(decoded)
                        code_obj = marshal.loads(decompressed)
                        if isinstance(code_obj, types.CodeType):
                            self.code_obj = code_obj
                    except Exception as e:
                        logging.error(f"Failed to decode/unmarshal: {e}")
            self.generic_visit(node)

    extractor = Extractor()
    extractor.visit(tree)

    if extractor.code_obj:
        return extractor.code_obj

    logging.error("[!] marshal.loads pattern with base64 blob not found in AST")
    return None


def decompile_pyc_with_pylingual(pyc_path: str) -> str | None:
    """
    Decompile a .pyc file using Pylingual main function directly.
    Returns the combined decompiled source as a string if successful, else None.

    Decompiles to the same folder as the .pyc file. If a file with the same name
    already exists, creates a separate folder for the output.

    Args:
        pyc_path: Path to the .pyc file to decompile

    Returns:
        Combined decompiled source code as string, or None if failed
    """
    try:
        pyc_file = Path(pyc_path)

        # Check if the .pyc file exists
        if not pyc_file.exists():
            logging.error(f"[Pylingual] .pyc file does not exist: {pyc_path}")
            return None

        # Check if the file is readable
        if not os.access(pyc_file, os.R_OK):
            logging.error(f"[Pylingual] .pyc file is not readable: {pyc_path}")
            return None

        base_name = pyc_file.stem
        parent_dir = pyc_file.parent

        # Check if parent directory is writable
        if not os.access(parent_dir, os.W_OK):
            logging.error(f"[Pylingual] Parent directory is not writable: {parent_dir}")
            return None

        # Check if a .py file with the same name already exists
        potential_output_file = parent_dir / f"{base_name}.py"

        if potential_output_file.exists():
            # File exists, create a separate folder
            output_path = parent_dir / f"decompiled_{base_name}"
            logging.info(f"[Pylingual] Output file exists, using folder: {output_path}")
        else:
            # File doesn't exist, use the parent directory directly (no folder creation)
            output_path = parent_dir
            logging.info(f"[Pylingual] Decompiling directly to parent directory: {output_path}")

        # Ensure output directory exists (but don't create unnecessary folders)
        if output_path != parent_dir:
            try:
                output_path.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                logging.error(f"[Pylingual] Failed to create output directory {output_path}: {e}")
                return None

        # Call pylingual main function directly with parameters
        start_time = time.time()
        try:
            # Add more detailed logging
            logging.info(f"[Pylingual] Starting decompilation of {pyc_file}")
            logging.info(f"[Pylingual] Output directory: {output_path}")
            logging.info(f"[Pylingual] File size: {pyc_file.stat().st_size} bytes")

            # Check if file is actually a valid .pyc file by reading magic number
            try:
                with open(pyc_file, 'rb') as f:
                    magic = f.read(4)
                    logging.info(f"[Pylingual] Magic number: {magic.hex()}")
            except Exception as magic_error:
                logging.warning(f"[Pylingual] Could not read magic number: {magic_error}")

            pylingual_main(
                files=[str(pyc_file)],
                out_dir=output_path,
                config_file=None,
                version=None,
                top_k=10,
                trust_lnotab=False,
                init_pyenv=False,
                quiet=False
            )
            logging.info(f"pylingual.main execution completed in {time.time() - start_time:.6f} seconds")
        except Exception as pylingual_error:
            logging.error(f"[Pylingual] pylingual_main failed: {pylingual_error}")
            logging.error(f"[Pylingual] Error type: {type(pylingual_error).__name__}")
            # Try to get more details about the error
            import traceback
            logging.error(f"[Pylingual] Traceback: {traceback.format_exc()}")
            raise

        # Find all generated .py files
        py_files = list(output_path.rglob("*.py"))

        # If no files found in the expected location, try looking in subdirectories
        if not py_files and output_path == parent_dir:
            # Sometimes pylingual creates its own subdirectory
            possible_subdir = parent_dir / f"decompiled_{base_name}"
            if possible_subdir.exists():
                py_files = list(possible_subdir.rglob("*.py"))
                logging.info(f"[Pylingual] Found files in subdirectory: {possible_subdir}")

        if not py_files:
            logging.warning(f"[Pylingual] No .py files found in output for: {pyc_path}")
            # List all files in the output directory for debugging
            all_files = list(output_path.rglob("*"))
            logging.info(f"[Pylingual] All files in output directory: {[str(f) for f in all_files]}")
            return None

        # Combine all decompiled source files
        combined_source = ""
        for py_file in sorted(py_files):  # Sort for consistent ordering
            try:
                source_content = py_file.read_text(encoding="utf-8", errors="ignore")
                combined_source += f"# From: {py_file.name}\n"
                combined_source += source_content.strip() + "\n\n"
            except Exception as read_error:
                logging.warning(f"[Pylingual] Could not read {py_file}: {read_error}")
                continue

        if not combined_source.strip():
            logging.warning(f"[Pylingual] All decompiled files were empty for: {pyc_path}")
            return None

        logging.info(f"[Pylingual] Successfully decompiled {pyc_path} -> {output_path}")
        logging.info(f"[Pylingual] Generated {len(py_files)} Python files")

        return combined_source

    except Exception as e:
        logging.error(f"[Pylingual] Decompilation failed for {pyc_path}: {e}")
        return None


def codeobj_to_source(codeobj: types.CodeType, base_name: str) -> str:
    try:
        output_dir = Path(python_deobfuscated_marshal_pyc_dir)
        base_path = Path(base_name).with_suffix(".pyc")
        pyc_path = get_unique_output_path(output_dir, base_path)

        header = MAGIC_NUMBER
        if sys.version_info >= (3, 7):
            header += struct.pack("<I", 0)  # Bitfield
        header += struct.pack("<I", int(time.time()))  # Timestamp
        header += struct.pack("<I", 0)  # Source size (can be 0)

        with pyc_path.open("wb") as f:
            f.write(header)
            marshal.dump(codeobj, f)

        source = decompile_pyc_with_pylingual(str(pyc_path))
        if source:
            return source
        else:
            return "# Failed to decompile code object with both tools"

    except Exception as e:
        logging.error(f"Error in codeobj_to_source: {e}")
        return "# Exception during decompilation"

class ImportCleaner(ast.NodeTransformer):
    """
    Removes unused imports and merges all import statements into one per type,
    with duplicates removed.
    """

    def __init__(self):
        super().__init__()
        self.used_names = set()
        self.import_nodes = []
        self.importfrom_nodes = []

    def visit_Name(self, node):
        self.used_names.add(node.id)
        return node

    def visit_Import(self, node):
        self.import_nodes.append(node)
        return None

    def visit_ImportFrom(self, node):
        self.importfrom_nodes.append(node)
        return None

    def remove_unused_aliases(self, aliases):
        filtered = []
        for alias in aliases:
            name_to_check = alias.asname or alias.name  # don't split or parse here
            if name_to_check in self.used_names:
                filtered.append(alias)
        return filtered

    def merge_aliases(self, aliases):
        seen = set()
        merged = []
        for alias in aliases:
            key = (alias.name, alias.asname)
            if key not in seen:
                seen.add(key)
                merged.append(alias)
        return merged

    def clean_imports(self):
        all_import_aliases = []
        for node in self.import_nodes:
            all_import_aliases.extend(node.names)
        filtered = self.remove_unused_aliases(all_import_aliases)
        merged = self.merge_aliases(filtered)
        if merged:
            return ast.Import(names=merged)
        return None

    def clean_importfroms(self):
        grouped = {}
        for node in self.importfrom_nodes:
            key = (node.module, node.level)
            grouped.setdefault(key, []).extend(node.names)

        new_nodes = []
        for (module, level), aliases in grouped.items():
            filtered = self.remove_unused_aliases(aliases)
            merged = self.merge_aliases(filtered)
            if merged:
                new_nodes.append(ast.ImportFrom(module=module, names=merged, level=level))
        return new_nodes

    def visit_Module(self, node):
        self.generic_visit(node)
        new_body = []

        import_node = self.clean_imports()
        if import_node:
            new_body.append(import_node)

        importfrom_nodes = self.clean_importfroms()
        new_body.extend(importfrom_nodes)

        for n in node.body:
            if not isinstance(n, (ast.Import, ast.ImportFrom)):
                new_body.append(n)

        node.body = new_body
        return node

    def clean_until_stable(self, source_code: str | Path, output_path: Path) -> Path:
        if isinstance(source_code, Path):
            source_code = source_code.read_text(encoding='utf-8', errors='replace')

        prev_source = None
        current_source = source_code

        while prev_source != current_source:
            self.used_names = set()
            self.import_nodes = []
            self.importfrom_nodes = []

            tree = ast.parse(current_source)
            tree = self.visit(tree)
            ast.fix_missing_locations(tree)

            prev_source = current_source
            current_source = ast.unparse(tree)

        output_path.write_text(current_source, encoding='utf-8')
        return output_path

def clean_syntax(source_code: str, max_attempts=20) -> str:
    def normalize_indentation(code: str) -> str:
        return "\n".join(line.expandtabs(4).rstrip() for line in code.splitlines())

    def is_valid(code: str) -> bool:
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False

    code = normalize_indentation(source_code)
    lines = code.splitlines()
    attempt = 0

    while attempt < max_attempts:
        try:
            compile("\n".join(lines), "<string>", "exec")
            break  # Code is now valid
        except SyntaxError as e:
            lineno = e.lineno
            if lineno is None or lineno < 1 or lineno > len(lines):
                break

            bad_line = lines[lineno - 1].strip()
            logging.info(f"[Clean Syntax] Removing line {lineno}: {bad_line}")
            lines.pop(lineno - 1)

            # ALSO remove orphaned identifiers (like `lambda_output`) if any
            symbol = bad_line.split('=')[0].strip() if '=' in bad_line else bad_line
            lines = [line for line in lines if symbol not in line or line.strip().startswith('#')]
            attempt += 1

    cleaned_code = "\n".join(lines)

    if is_valid(cleaned_code):
        return cleaned_code
    else:
        logging.info("[Clean Syntax] Could not fully clean code.")
        return cleaned_code

# Robust exec-call detection
def contains_exec_calls(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        # Look only for Call nodes
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == 'exec':
                return True
            if isinstance(func, ast.Attribute) and func.attr == 'exec':
                return True
            if (
                isinstance(func, ast.Call)
                and isinstance(func.func, ast.Name)
                and func.func.id == 'getattr'
                and len(func.args) >= 2
                and isinstance(func.args[1], ast.Constant)
                and func.args[1].value == 'exec'
            ):
                return True
    return False

def prune_ifs_and_write(output_path: Path, source_code: str) -> None:
    """
    Clean, prune 'if' statements from the AST, and write back the resulting code.

    Args:
        output_path (Path): Path to write the transformed Python code.
        source_code (str): Original source code string.
    """
    import ast

    cleaned = clean_source(source_code)  # Apply basic text cleanup
    try:
        tree = ast.parse(cleaned)
        tree = PruneIfs().visit(tree)
        ast.fix_missing_locations(tree)
        result = ast.unparse(tree)
        output_path.write_text(result, encoding="utf-8")
        logging.debug(f"[PRUNE_IFS] Wrote transformed code to: {output_path}")
    except Exception as e:
        logging.error(f"[PRUNE_IFS] Failed to parse or transform: {e}")
        # Optional: write cleaned original as fallback
        output_path.write_text(cleaned, encoding="utf-8")

def sandbox_deobfuscate_file(transformed_path: Path) -> Path | None:
    """
    Runs the Python deobfuscator inside Sandboxie (DefaultBox),
    expecting the AST-transformed script to write '<script_stem>_execs.py'.
    Waits until the file is fully written before copying it back to the host.
    Returns the copied path or None if it failed.
    """
    name = transformed_path.stem
    execs_filename = f"{name}_execs.py"
    sandbox_inner_execs = Path(python_deobfuscated_sandboxie_dir) / execs_filename
    sandbox_inner_execs.parent.mkdir(parents=True, exist_ok=True)

    sandboxie_exe = str(sandboxie_path)
    python_exe = str(sys.executable)
    script_path = str(transformed_path)

    shell_cmd = (
        f'"{sandboxie_exe}" /box:DefaultBox /elevate '
        f'"{python_exe}" "{script_path}"'
    )

    exec_path_str = sandbox_inner_execs.as_posix().replace('/', '\\')
    logging.info(f"[SANDBOX] Running shell command: {shell_cmd!r}")
    logging.info(f"[SANDBOX] Expect exec output at: {exec_path_str}")

    try:
        subprocess.run(
            shell_cmd,
            shell=True,
            check=True,
            timeout=600,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        logging.error(f"[SANDBOX] Run failed: {e}")
        return None

    # Real-time file watch loop with stability check (10 minutes timeout)
    deadline = time.monotonic() + 600
    last_size = -1
    stable_count = 0

    while time.monotonic() < deadline:
        try:
            if sandbox_inner_execs.exists():
                size = sandbox_inner_execs.stat().st_size
                if size > 0:
                    if size == last_size:
                        stable_count += 1
                    else:
                        stable_count = 0
                    last_size = size

                    if stable_count >= 3:
                        break
                else:
                    last_size = -1
                    stable_count = 0
        except (FileNotFoundError, OSError):
            pass

    else:
        logging.error("[SANDBOX] Timed out waiting for execs file to stabilize.")
        return None

    # Copy result back to host
    host_output_dir = Path(python_deobfuscated_dir)
    host_output_dir.mkdir(parents=True, exist_ok=True)
    host_target = host_output_dir / f"{name}_deobf.py"

    try:
        content = sandbox_inner_execs.read_bytes()
        if not content:
            logging.error("[SANDBOX] Execs file content empty on read, aborting.")
            return None
        host_target.write_bytes(content)
        logging.info(f"[SANDBOX] Copied execs output back to host: {host_target}")
        return host_target
    except Exception as copy_exc:
        logging.error(f"[SANDBOX] Failed to copy from sandbox: {copy_exc}")
        return None

# Main loop: apply exec->file and remove unused imports, with stuck-detection
def deobfuscate_until_clean(source_path: Path) -> Optional[Path]:
    source_path = Path(source_path)
    base_name = source_path.stem
    logging.info(f"Starting deobfuscation for: {source_path}")

    # Each queue entry: (depth, stage_tag, cleaned_flag, offloaded_flag, candidate_path)
    processing_queue: List[Tuple[int, str, bool, bool, Path]] = []
    # Track seen states as (stage_tag, cleaned_flag, offloaded_flag, content_hash)
    seen_hashes: Set[Tuple[str, bool, bool, str]] = set()

    try:
        _ = source_path.read_text(encoding="utf-8", errors="replace")
        processing_queue.append((0, "original", False, False, source_path))
    except Exception as e:
        logging.error(f"Failed to read source file: {e}")
        return None

    while processing_queue:
        logging.info(f"--- New Pass (queue size = {len(processing_queue)}) ---")
        next_queue: List[Tuple[int, str, bool, bool, Path]] = []

        for depth, stage_tag, cleaned, offloaded, candidate_path in processing_queue:
            try:
                # Read raw content
                raw = candidate_path.read_text(encoding="utf-8", errors="replace")
                content = clean_source(raw)
                content_hash = compute_md5_via_text(content)

                state = (stage_tag, cleaned, offloaded, content_hash)
                if state in seen_hashes:
                    continue
                seen_hashes.add(state)

                # Stage 1: marshal.loads extraction
                if "marshal.loads" in content and stage_tag != "marshal":
                    try:
                        codeobj = extract_marshal_code_from_source(content)
                        if codeobj is not None:
                            extracted_src = codeobj_to_source(codeobj, f"{base_name}_d{depth}_marshal")
                            extracted_hash = compute_md5_via_text(extracted_src)
                            state2 = ("marshal", False, False, extracted_hash)
                            if state2 not in seen_hashes:
                                new_path = get_unique_output_path(
                                    Path(python_deobfuscated_dir),
                                    Path(f"{base_name[:8]}_d{depth}_m.py")
                                )
                                new_path.write_text(extracted_src, encoding="utf-8")
                                logging.info(f"[MARSHAL] Extracted and wrote: {new_path}")
                                next_queue.append((depth + 1, "marshal", False, False, new_path))
                                continue
                    except Exception as e:
                        logging.error(f"[MARSHAL] Failed on {candidate_path}: {e}")

                # Stage 2: AST transform (exec->file + import cleaning)
                if stage_tag not in ("marshal", "zlib", "ast"):
                    try:
                        tree = ast.parse(content)
                        tree = ExecToFileTransformer().visit(tree)
                        ast.fix_missing_locations(tree)

                        cleaner = ImportCleaner()
                        clean_output_path = get_unique_output_path(
                            Path(python_deobfuscated_dir),
                            f"{base_name[:8]}_d{depth}_importclean.py"
                        )
                        cleaned_source_path = cleaner.clean_until_stable(
                            ast.unparse(tree), clean_output_path
                        )
                        transformed = cleaned_source_path.read_text(encoding="utf-8", errors="replace")
                    except Exception as e:
                        logging.error(f"[AST] Transform failed on {candidate_path}: {e}")
                        transformed = content

                    transformed_hash = compute_md5_via_text(transformed)
                    state3 = ("ast", False, True, transformed_hash)
                    if transformed_hash != content_hash and state3 not in seen_hashes:
                        new_path = get_unique_output_path(
                            Path(python_deobfuscated_dir),
                            f"{base_name[:8]}_d{depth}_ast.py"
                        )
                        new_path.write_text(transformed, encoding="utf-8")
                        logging.info(f"[AST] Transformed and wrote: {new_path}")
                        # Mark offloaded=True because exec was moved to a file
                        next_queue.append((depth + 1, "ast", False, True, new_path))
                        continue

                # Stage 3: clean_syntax
                if not cleaned:
                    cleaned_code = clean_syntax(content)
                    clean_path = get_unique_output_path(
                        Path(python_deobfuscated_dir),
                        f"{base_name[:8]}_d{depth}_clean.py"
                    )
                    clean_path.write_text(cleaned_code, encoding="utf-8")
                    logging.debug(f"[CLEAN_SYNTAX] Wrote cleaned code to: {clean_path}")

                    clean_content = clean_path.read_text(encoding="utf-8", errors="replace")
                    clean_hash = compute_md5_via_text(clean_content)
                    state4 = ("clean", True, offloaded, clean_hash)
                    if state4 not in seen_hashes:
                        logging.info(f"[CLEAN_SYNTAX] Cleaned and wrote: {clean_path}")

                        # Only finalize if exec truly gone and not offloaded
                        if not offloaded and not contains_exec_calls(clean_content) and "eval" not in clean_content:
                            final_candidate = get_unique_output_path(
                                Path(python_deobfuscated_dir),
                                f"{base_name[:8]}_final.py"
                            )
                            prune_ifs_and_write(final_candidate, clean_content)
                            logging.info(
                                f"[FINAL] No exec/eval found post-clean_syntax, saved: {final_candidate}"
                            )
                            return final_candidate

                        next_queue.append((depth + 1, "clean", True, offloaded, clean_path))
                        continue
                else:
                    logging.debug("[CLEAN_SYNTAX] Skipping clean_syntax (already cleaned)")

                # Stage 4: Sandbox simulation
                try:
                    # Re-read the on-disk content (post-clean or post-AST)
                    disk_text = candidate_path.read_text(encoding="utf-8", errors="replace")

                    # Only finalize if from clean_syntax stage AND not offloaded, with no exec/eval
                    if stage_tag == "clean" and not offloaded and not contains_exec_calls(disk_text) and "eval" not in disk_text:
                        final_candidate = get_unique_output_path(
                            Path(python_deobfuscated_dir),
                            f"{base_name[:8]}_final.py"
                        )
                        prune_ifs_and_write(final_candidate, disk_text)
                        logging.info(
                            f"[FINAL] No exec/eval present post-clean, saved: {final_candidate}"
                        )
                        return final_candidate

                    # Otherwise, still needs sandbox (either offloaded or exec remains)
                    if pyinstaller_archive and Path(pyinstaller_archive).is_dir() and pyz_version_match:
                        sandbox_copy = Path(pyinstaller_archive) / candidate_path.name
                        shutil.copy(candidate_path, sandbox_copy)
                    else:
                        sandbox_copy = candidate_path

                    output_path = sandbox_deobfuscate_file(sandbox_copy)
                    if output_path and output_path.exists() and output_path.stat().st_size > 0:
                        result = output_path.read_text(encoding="utf-8", errors="replace")
                        result_hash = compute_md5_via_text(result)

                        logging.info(f"[SANDBOX] Produced sandbox output: {output_path}")

                        # After sandbox, queue as new "original" (offloaded=False)
                        next_queue.append((depth + 1, "original", False, False, output_path))
                        seen_hashes.add(("sandbox", False, False, result_hash))

                        # If sandbox result is truly clean, prune and save final
                        if not contains_exec_calls(result) and "eval" not in result:
                            final_candidate = get_unique_output_path(
                                Path(python_deobfuscated_dir),
                                f"{base_name[:8]}_final.py"
                            )
                            prune_ifs_and_write(final_candidate, result)
                            logging.info(f"[FINAL_CANDIDATE] Clean code candidate saved: {final_candidate}")
                            return final_candidate

                        continue
                    else:
                        logging.error(f"[SANDBOX] No output for {candidate_path}; dropping it")
                        seen_hashes.add(("sandbox", False, False, content_hash))
                        continue

                except Exception as e:
                    logging.error(f"[SANDBOX] Failed on {candidate_path}: {e}")
                    seen_hashes.add(("sandbox", False, False, content_hash))
                    continue

            except Exception as e:
                logging.error(f"[ERROR] While processing {candidate_path}: {e}")
                seen_hashes.add((stage_tag, cleaned, offloaded, compute_md5_via_text(candidate_path.read_text(encoding="utf-8", errors="replace"))))
                continue

        processing_queue = next_queue

    logging.info("No more clean code found; transformations exhausted.")
    return None

def process_decompiled_code(output_file):
    """
    Dispatches payload processing based on type.
    Detects whether the payload is Exela v2 or generic.
    """
    try:
        with open(output_file, 'r', encoding='utf-8') as file:
            content = file.read()

        if is_exela_v2_payload(content):
            logging.info("[*] Detected Exela Stealer v2 payload.")
            process_exela_v2_payload(output_file)

        elif 'exec(' not in content:
            logging.info(f"[+] No exec() found in {output_file}, probably not obfuscated.")

        else:
            logging.info("[*] Detected non-Exela payload. Using generic processing.")
            deobfuscated = deobfuscate_until_clean(output_file)
            if deobfuscated:
                deobfuscated_saved_paths.append(deobfuscated)  # Add to global list
                notify_user_for_malicious_source_code(
                    deobfuscated,
                    "HEUR:Win32.Susp.Src.PYC.Python.Obfuscated.exec.gen"
                )
            else:
                logging.error("[!] Generic deobfuscation failed; skipping scan and notification.")

    except Exception as ex:
        logging.error(f"[!] Error during payload dispatch: {ex}")

def extract_and_return_pyinstaller(file_path):
    """
    Extracts a PyInstaller archive and returns:
      1) A list of extracted file paths
      2) The output directory where files were extracted

    :param file_path: Path to the PyInstaller archive.
    :return: Tuple (extracted_file_paths, extracted_output_dir)
    """
    extracted_pyinstaller_file_paths = []

    # Extract PyInstaller archive
    output_dir = extract_pyinstaller_archive(file_path)

    if output_dir:
        logging.info(f"PyInstaller archive extracted to {output_dir}")

        # Traverse and collect all extracted files
        for root, _, files in os.walk(output_dir):
            for pyinstaller_file in files:
                extracted_file_path = os.path.join(root, pyinstaller_file)
                extracted_pyinstaller_file_paths.append(extracted_file_path)

    return extracted_pyinstaller_file_paths, output_dir

def decompile_dotnet_file(file_path):
    """
    Decompiles a .NET assembly using ILSpy and scans all decompiled .cs files
    for URLs, IP addresses, domains, and Discord webhooks.

    :param file_path: Path to the .NET assembly file.
    """
    try:
        logging.info(f"Detected .NET assembly: {file_path}")

        # Create a unique numbered subdirectory under dotnet_dir
        folder_number = 1
        while os.path.exists(os.path.join(dotnet_dir, str(folder_number))):
            folder_number += 1
        dotnet_output_dir = os.path.join(dotnet_dir, str(folder_number))
        os.makedirs(dotnet_output_dir, exist_ok=True)

        # Run ILSpy decompilation command
        ilspy_command = [
            ilspycmd_path,
            "-o", dotnet_output_dir,
            file_path
        ]
        subprocess.run(ilspy_command, check=True)
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

def extract_all_files_with_7z(file_path, nsis_flag=False):
    """
    Extracts all files from an archive via 7-Zip CLI.
    Always returns a list of extracted file paths.

    Side effects:
      - If nsis_flag is True, every .nsi script found will be scanned asynchronously via scan_code_for_links(..., nsis_flag=True).
    """
    extracted_files = []
    try:
        # Prepare a unique output directory
        counter = 1
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        base_output_dir = os.path.join(general_extracted_with_7z_dir, base_name)
        while os.path.exists(f"{base_output_dir}_{counter}"):
            counter += 1
        output_dir = f"{base_output_dir}_{counter}"
        os.makedirs(output_dir, exist_ok=True)

        logging.info(f"Extracting {file_path} into {output_dir}...")
        cmd = [
            seven_zip_path, "x", file_path,
            f"-o{output_dir}", "-y", "-snl", "-spe"
        ]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="ignore"
        )
        if proc.returncode != 0:
            logging.error(
                f"7z extraction failed (code {proc.returncode}): {proc.stderr.strip()}"
            )
            return extracted_files

        # Collect all extracted file paths
        for root, _, files in os.walk(output_dir):
            for fname in files:
                extracted_files.append(os.path.join(root, fname))

        # If nsis_flag is set, scan all .nsi scripts asynchronously
        if nsis_flag:
            def _scan_nsi(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    links = scan_code_for_links(content, nsis_flag=True)
                    logging.info(f"Scanned NSIS script {path}, found {len(links)} links.")
                except Exception as e:
                    logging.error(f"Failed to scan NSIS script {path}: {e}")

            for path in extracted_files:
                if path.lower().endswith('.nsi'):
                    t = threading.Thread(target=_scan_nsi, args=(path,))
                    t.start()

        return extracted_files

    except Exception as ex:
        logging.error(f"Error during 7z extraction: {ex}")
        return extracted_files

# Generic obfuscation decoder: reverse -> Base64 -> zlib
def decode_blob(blob: str) -> str | None:
    """
    Attempt to decode a base64 blob (with optional reverse) via zlib.
    Returns decoded string or None if failure.
    """
    try:
        data = blob.encode('utf-8')
        # Try direct decode
        decoded = zlib.decompress(base64.b64decode(data))
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        pass
    try:
        # Try reversed
        data = data[::-1]
        decoded = zlib.decompress(base64.b64decode(data))
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        return None


def find_blobs(code: str) -> list[str]:
    """
    Find all string literals that look like large Base64 blobs.
    """
    pattern = r"[rb]?'([A-Za-z0-9+/=]{80,})'"
    return re.findall(pattern, code)


def recursive_generic_deobf(code: str) -> str:
    """
    Recursively detect and decode blobs until no more new content.
    """
    result = code
    seen = set()
    while True:
        blobs = find_blobs(result)
        decoded_any = False
        for blob in blobs:
            if blob in seen:
                continue
            seen.add(blob)
            decoded = decode_blob(blob)
            if decoded:
                # replace the blob literal with decoded content
                result = result.replace(blob, decoded)
                decoded_any = True
        if not decoded_any:
            break
    return result


def script_contains_obf(code: str) -> bool:
    """
    Heuristic to detect obfuscation: presence of large Base64 blobs and exec or decompress.
    """
    if re.search(r"[rb]?'[A-Za-z0-9+/=]{80,}'", code) and \
       ("exec(" in code or "decompress" in code):
        return True
    return False


class ExecToFileTransformer(ast.NodeTransformer):
    """
    Replaces top-level 'exec(...)' calls with writes to a file located
    next to the script (absolute path), like:
        C:/.../PhantomB_execs.py

    Ensures imports and assignments are injected only once.
    """

    def visit_Module(self, node: ast.Module) -> ast.Module:
        already_injected = any(
            isinstance(stmt, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id == "__exec_out" for t in stmt.targets)
            for stmt in node.body
        )

        if not already_injected:
            # Inject: import sys, pathlib
            import_stmt = ast.Import(names=[
                ast.alias(name="sys", asname=None),
                ast.alias(name="pathlib", asname=None)
            ])

            # __exec_filename = str(Path(sys.argv[0]).with_name(Path(sys.argv[0]).stem + "_execs.py"))
            filename_assign = ast.Assign(
                targets=[ast.Name(id="__exec_filename", ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id="str", ctx=ast.Load()),
                    args=[
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id="pathlib", ctx=ast.Load()),
                                        attr="Path", ctx=ast.Load()
                                    ),
                                    args=[
                                        ast.Subscript(
                                            value=ast.Attribute(
                                                value=ast.Name(id="sys", ctx=ast.Load()),
                                                attr="argv", ctx=ast.Load()
                                            ),
                                            slice=ast.Constant(value=0),
                                            ctx=ast.Load()
                                        )
                                    ],
                                    keywords=[]
                                ),
                                attr="with_name", ctx=ast.Load()
                            ),
                            args=[
                                ast.BinOp(
                                    left=ast.Attribute(
                                        value=ast.Call(
                                            func=ast.Attribute(
                                                value=ast.Name(id="pathlib", ctx=ast.Load()),
                                                attr="Path", ctx=ast.Load()
                                            ),
                                            args=[
                                                ast.Subscript(
                                                    value=ast.Attribute(
                                                        value=ast.Name(id="sys", ctx=ast.Load()),
                                                        attr="argv", ctx=ast.Load()
                                                    ),
                                                    slice=ast.Constant(value=0),
                                                    ctx=ast.Load()
                                                )
                                            ],
                                            keywords=[]
                                        ),
                                        attr="stem", ctx=ast.Load()
                                    ),
                                    op=ast.Add(),
                                    right=ast.Constant(value="_execs.py")
                                )
                            ],
                            keywords=[]
                        )
                    ],
                    keywords=[]
                )
            )

            # __exec_out = open(__exec_filename, 'w', encoding='utf-8')
            file_assign = ast.Assign(
                targets=[ast.Name(id="__exec_out", ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id="open", ctx=ast.Load()),
                    args=[
                        ast.Name(id="__exec_filename", ctx=ast.Load()),
                        ast.Constant(value="w")
                    ],
                    keywords=[
                        ast.keyword(arg="encoding", value=ast.Constant(value="utf-8"))
                    ]
                )
            )

            # Insert at top
            node.body.insert(0, file_assign)
            node.body.insert(0, filename_assign)
            node.body.insert(0, import_stmt)

        self.generic_visit(node)
        return node

    def visit_Expr(self, node: ast.Expr) -> list[ast.AST] | ast.Expr:
        self.generic_visit(node)

        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "exec"
        ):
            code_arg = node.value.args[0] if node.value.args else ast.Constant(value="")

            # If compile(...), extract the source
            if (
                isinstance(code_arg, ast.Call)
                and isinstance(code_arg.func, ast.Name)
                and code_arg.func.id == "compile"
                and len(code_arg.args) > 0
            ):
                source_expr = code_arg.args[0]
            else:
                source_expr = code_arg

            assign_exec_val = ast.Assign(
                targets=[ast.Name(id="__exec_val", ctx=ast.Store())],
                value=source_expr
            )

            strip_expr = ast.IfExp(
                test=ast.Call(
                    func=ast.Name(id="isinstance", ctx=ast.Load()),
                    args=[
                        ast.Name(id="__exec_val", ctx=ast.Load()),
                        ast.Name(id="bytes", ctx=ast.Load())
                    ],
                    keywords=[]
                ),
                body=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id="__exec_val", ctx=ast.Load()),
                                attr="decode", ctx=ast.Load()
                            ),
                            args=[ast.Constant(value="utf-8")],
                            keywords=[]
                        ),
                        attr="rstrip", ctx=ast.Load()
                    ),
                    args=[ast.Constant(value="\n")],
                    keywords=[]
                ),
                orelse=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="__exec_val", ctx=ast.Load()),
                        attr="rstrip", ctx=ast.Load()
                    ),
                    args=[ast.Constant(value="\n")],
                    keywords=[]
                )
            )

            write_expr = ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="__exec_out", ctx=ast.Load()),
                        attr="write", ctx=ast.Load()
                    ),
                    args=[strip_expr],
                    keywords=[]
                )
            )

            return [assign_exec_val, write_expr]

        return node

# Generic normalization using literal_eval
def normalize_code_text(raw_text: str) -> str:
    try:
        val = ast.literal_eval(raw_text)
    except Exception:
        return raw_text
    if isinstance(val, (bytes, bytearray)):
        return val.decode('utf-8', errors='ignore')
    if isinstance(val, str):
        return val
    return raw_text

def safe_eval_node(node):
    """
    Safely evaluate AST nodes for specific known functions like
    base64.b64decode, zlib.decompress, bytes literals, and nested calls.
    Returns bytes or string as appropriate.
    """
    if isinstance(node, ast.Call):
        func = node.func
        args = node.args

        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            mod_name = func.value.id
            func_name = func.attr

            # handle base64.b64decode(...)
            if mod_name == "base64" and func_name == "b64decode":
                # single argument expected
                arg_val = safe_eval_node(args[0])
                return base64.b64decode(arg_val)

            # handle zlib.decompress(...)
            if mod_name == "zlib" and func_name == "decompress":
                arg_val = safe_eval_node(args[0])
                return zlib.decompress(arg_val)

            # Could extend for other modules if needed

        logging.error(f"Unsupported function call: {ast.dump(node)}")

    elif isinstance(node, ast.Constant):
        # Python 3.8+: constant node (str, bytes, etc.)
        return node.value

    elif isinstance(node, ast.Str):
        # Older python versions
        return node.s

    elif isinstance(node, ast.Bytes):
        return node.s

    else:
        logging.error(f"Unsupported AST node type: {ast.dump(node)}")

def find_balanced_parens(s, start_idx):
    count = 0
    for i in range(start_idx, len(s)):
        if s[i] == '(':
            count += 1
        elif s[i] == ')':
            count -= 1
            if count == 0:
                return s[start_idx + 1:i], i
    return None, None

def pack_uint32(val):
    return struct.pack("<I", val)

def write_pyc(code: types.CodeType, input_path: Path, output_dir: Path) -> None:
    """
    Write the given code object to a uniquely named .pyc file in the output directory,
    avoiding overwriting the original file.

    Args:
        code: The code object to write.
        input_path: The original .pyc file path (to avoid overwriting).
        output_dir: Directory to save the new .pyc file.

    Returns:
        None
    """
    # Ensure input_path and output_dir are Path objects
    input_path = Path(input_path)
    output_dir = Path(output_dir)

    # 1) Build a base Path for naming: same stem but extension ".pyc"
    base = input_path.with_suffix(".pyc")

    # 2) Get a unique candidate using get_unique_output_path
    output_path = get_unique_output_path(output_dir, base)

    # 3) If by any chance we got the same absolute file as input_path, tweak the stem
    if output_path.resolve() == input_path.resolve():
        # Append "_out" to input_path.stem, then re-run unique
        new_base = input_path.with_name(f"{input_path.stem}_out.pyc")
        output_path = get_unique_output_path(output_dir, new_base)

    # 4) Build .pyc header + marshal.dumps(code)
    pyc_data = bytearray()
    pyc_data.extend(MAGIC_NUMBER)

    if sys.version_info >= (3, 7):
        # 3.7+: 4-byte bitfield (usually zero), then 4-byte timestamp, then 4-byte source-size.
        pyc_data.extend(pack_uint32(0))                # Bitfield
        pyc_data.extend(pack_uint32(int(time.time()))) # Timestamp
        pyc_data.extend(pack_uint32(0))                # Source size (0 when unknown)
    else:
        # <3.7: just 4-byte timestamp, then marshaled code
        pyc_data.extend(pack_uint32(int(time.time()))) # Timestamp

    pyc_data.extend(marshal.dumps(code))

    # 5) Write to the chosen output_path
    try:
        with output_path.open("wb") as f:
            f.write(pyc_data)
        logging.info(f"[+] .pyc written to: {output_path}")
    except Exception as e:
        logging.error(f"Failed to write .pyc to {output_path}: {e}")

class PruneIfs(ast.NodeTransformer):
    """Prune if statements with constant conditions."""
    def visit_If(self, node: ast.If):
        self.generic_visit(node)
        # handle tests like `if CONST:` or `if CONST == False:`
        if isinstance(node.test, ast.Constant):
            return node.body if node.test.value else []
        if (isinstance(node.test, ast.Compare) \
                and len(node.test.ops) == 1 \
                and isinstance(node.test.comparators[0], ast.Constant)):
            val = node.test.comparators[0].value
            if isinstance(node.test.ops[0], ast.Eq):
                return node.body if val else []
            if isinstance(node.test.ops[0], ast.NotEq):
                return node.orelse
        return node

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
        output_path = os.path.join(pycdas_extracted_dir, f"{base_name}_pycdas_decompiled.py")

        # Build the pycdas command with the -o argument
        command = [pycdas_path, "-o", output_path, file_path]

        # Run the pycdas command
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="ignore")

        if result.returncode == 0:
            logging.info(f"Successfully decompiled using pycdas. Output saved to {output_path}")
            return output_path
        else:
            logging.error(f"pycdas error: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error running pycdas: {e}")
        return None

def deobfuscate_with_obfuscar(file_path, file_basename):
    """
    Deobfuscate a .NET assembly protected with Obfuscar.

    This function:
      1. Copies the original file from file_path into the obfuscar directory.
      2. Calls the Deobfuscar-Standalone-Win64.exe executable with the copied file.
      3. Waits indefinitely until a file prefixed with "unpacked_" appears in obfuscar_dir.
      4. Returns the path of the deobfuscated file.

    Parameters:
      file_path (str): Path to the file to be deobfuscated.
      file_basename (str): The name of the file (e.g., from os.path.basename(file_path)).

    Returns:
      str | None: Path to the deobfuscated file, or None on error.
    """
    if not os.path.exists(deobfuscar_path):
        logging.error(f"Deobfuscar executable not found at {deobfuscar_path}")
        return None

    # Copy the file to the obfuscar directory
    copied_file_path = os.path.join(obfuscar_dir, file_basename)
    try:
        shutil.copy(file_path, copied_file_path)
        logging.info(f"Copied file {file_path} to {copied_file_path}")
    except Exception as e:
        logging.error(f"Failed to copy file to obfuscar directory: {e}")
        return None

    # Run the deobfuscation tool
    try:
        command = [deobfuscar_path, copied_file_path]
        logging.info(f"Running deobfuscation: {' '.join(command)}")
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
    except Exception as e:
        logging.error(f"Error during deobfuscation execution: {e}")
        return None

    # Monitor directory for the unpacked output
    logging.info("Waiting for unpacked_ file to appear...")
    deobfuscated_file_path = None
    while True:
        for entry in os.listdir(obfuscar_dir):
            if entry.startswith("unpacked_"):
                deobfuscated_file_path = os.path.join(obfuscar_dir, entry)
                logging.info(f"Deobfuscated file found: {deobfuscated_file_path}")
                break
        if deobfuscated_file_path:
            break

    return deobfuscated_file_path

def extract_rcdata_resource(pe_path):
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        logging.error(f"Error loading PE file: {e}")
        return None, []

    # Check if the PE file has any resources
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        logging.error("No resources found in this file.")
        return None, []

    first_rcdata_file = None  # Will hold the first RCData resource file path we care about
    all_extracted_files = []  # Store all extracted file paths for scanning

    # Ensure the output directory exists
    output_dir = os.path.join(
        nuitka_extracted_dir,
        os.path.splitext(os.path.basename(pe_path))[0]
    )
    os.makedirs(output_dir, exist_ok=True)

    # Traverse the resource directory tree
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = get_resource_name(resource_type)
        if not hasattr(resource_type, 'directory'):
            continue

        for resource_id in resource_type.directory.entries:
            res_id = get_resource_name(resource_id)
            if not hasattr(resource_id, 'directory'):
                continue

            for resource_lang in resource_id.directory.entries:
                lang_id = resource_lang.id
                data_rva = resource_lang.data.struct.OffsetToData
                size = resource_lang.data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

                # Construct the filename: "<type>_<id>_<lang>.bin"
                file_name = f"{type_name}_{res_id}_{lang_id}.bin"
                output_path = os.path.join(output_dir, file_name)

                # Save the extracted resource to disk
                with open(output_path, "wb") as f:
                    f.write(data)

                logging.info(f"Extracted resource saved: {output_path}")
                all_extracted_files.append(output_path)

                # If it's an RCData resource (type "10") and matches 10_3_0.bin, record and stop
                if type_name == "10" and res_id == "3" and lang_id == 0:
                    first_rcdata_file = output_path
                    logging.info(f"Using RCData resource file: {first_rcdata_file}")
                    # Break out of all loops once found
                    break
            if first_rcdata_file:
                break
        if first_rcdata_file:
            break

    if first_rcdata_file is None:
        logging.info("No matching RCData resource (10_3_0.bin) found.")
    return first_rcdata_file, all_extracted_files

def extract_nuitka_file(file_path, nuitka_type):
    """
    Detect Nuitka type, extract Nuitka executable content, and scan for additional Nuitka executables.

    Parameters:
      file_path (str): Path to the Nuitka executable file.
      nuitka_type (str): Type of Nuitka executable ("Nuitka OneFile" or "Nuitka").

    Returns:
      list[str] | None: List of extracted file paths for further analysis, or None on error.
    """
    extracted_files_list = []
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
            logging.info("Scanning extracted directory for additional Nuitka executables...")
            found_executables = scan_directory_for_executables(nuitka_output_dir)

            # Process any found normal Nuitka executables
            for exe_path, exe_type in found_executables:
                if exe_type == "Nuitka":
                    logging.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                    nested_files = extract_nuitka_file(exe_path, exe_type)
                    if nested_files:
                        extracted_files_list.extend(nested_files)

            return extracted_files_list

        elif nuitka_type == "Nuitka":
            logging.info(f"Nuitka executable detected in {file_path}")

            # Extract the Nuitka executable
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]

            # Use enhanced pefile extraction
            extracted_files_nuitka, all_extracted_files = extract_rcdata_resource(file_path)

            if extracted_files_nuitka:
                logging.info(f"Successfully extracted bytecode or RCDATA file from Nuitka executable: {file_path}")
                scan_rsrc_files(extracted_files_nuitka)
                extracted_files_list.extend(extracted_files_nuitka)
            else:
                logging.error(f"Failed to extract normal Nuitka executable: {file_path}")

            if all_extracted_files:
                extracted_files_list.extend(all_extracted_files)

            return extracted_files_list

        else:
            logging.info(f"No Nuitka content found in {file_path}")
            return None

    except Exception as ex:
        logging.error(f"Unexpected error while extracting Nuitka file: {ex}")
        return None

def extract_resources(pe_path, output_dir):
    """
    Extract resources from a PE file and scan each extracted file.

    Returns:
      list[str] | None: List of paths to extracted resource files, or None on error.
    """
    extracted_files = []
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        logging.error(f"Error loading PE file: {e}")
        return None

    # Check if the PE file has resources
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        logging.error("No resources found in this file.")
        return None

    os.makedirs(output_dir, exist_ok=True)
    resource_count = 0

    # Traverse the resource directory
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = get_resource_name(resource_type)
        if not hasattr(resource_type, 'directory'):
            continue

        for resource_id in resource_type.directory.entries:
            res_id = get_resource_name(resource_id)
            if not hasattr(resource_id, 'directory'):
                continue

            for resource_lang in resource_id.directory.entries:
                lang_id = resource_lang.id
                data_rva = resource_lang.data.struct.OffsetToData
                size = resource_lang.data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

                # Create a filename: resourceType_resourceID_langID.bin
                file_name = f"{type_name}_{res_id}_{lang_id}.bin"
                output_path = os.path.join(output_dir, file_name)
                with open(output_path, "wb") as f:
                    f.write(data)
                logging.info(f"Resource saved: {output_path}")

                extracted_files.append(output_path)
                resource_count += 1

    if resource_count == 0:
        logging.info("No resources were extracted.")
    else:
        logging.info(f"Extracted a total of {resource_count} resources.")

    return extracted_files

def run_fernflower_decompiler(file_path, flag_fernflower=True):
    """
    Uses FernFlower to decompile the given JAR file.
    The FernFlower JAR is expected to be located in jar_decompiler_dir.
    The decompiled output is saved to a folder in script_dir.
    The flag_java_class indicates if a Java class file was detected.

    Returns:
      list[str] | None: List of paths to files in the decompiled output directory, or None on error.
    """
    try:

        # Build the path to fernflower.jar.
        FernFlower_path = os.path.join(jar_decompiler_dir, "fernflower.jar")
        base_name = os.path.splitext(os.path.basename(file_path))[0]

        # Find the next available numbered subfolder
        folder_number = 1
        while os.path.exists(os.path.join(FernFlower_decompiled_dir, f"{base_name}_{folder_number}")):
            folder_number += 1

        # Final output dir: FernFlower_decompiled/<jarname>_N
        FernFlower_output_dir = os.path.join(FernFlower_decompiled_dir, f"{base_name}_{folder_number}")
        Path(FernFlower_output_dir).mkdir(parents=True, exist_ok=True)

        command = ["java", "-jar", FernFlower_path, file_path, FernFlower_output_dir]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if result.returncode == 0:
            logging.info(f"FernFlower decompilation successful to: {FernFlower_output_dir}")
            # List all files in output dir (recursively)
            decompiled_files = []
            for root, dirs, files in os.walk(FernFlower_output_dir):
                for name in files:
                    decompiled_files.append(os.path.join(root, name))
            return decompiled_files
        else:
            logging.error(f"FernFlower decompilation failed: {result.stderr}")
            return None
    except Exception as ex:
        logging.error(f"Error in run_fernflower_decompiler: {ex}")
        return None

def run_jar_extractor(file_path, flag_fernflower):
    """
    Extracts a JAR file to an "extracted_files" folder in script_dir.
    Then conditionally calls the FernFlower decompiler unless decompilation was already performed.
    The flag_java_class indicates if the DIE output also detected a Java class file.

    Returns:
      list[str] | None: List of file paths extracted or decompiled, or None on error.
    """
    extracted_file_paths = []

    try:
        # Define the extraction output directory
        extracted_dir = os.path.join(script_dir, "extracted_files")
        Path(extracted_dir).mkdir(parents=True, exist_ok=True)

        # Build the command to extract the JAR file using the JDK jar tool.
        # "jar xf" will extract the contents into the current working directory.
        jar_command = ["jar", "xf", file_path]
        result = subprocess.run(
            jar_command,
            cwd=extracted_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if result.returncode == 0:
            logging.info("JAR extraction completed successfully.")
        else:
            logging.error(f"JAR extraction failed: {result.stderr}")

        # Collect all files from extracted_dir
        for root, _, files in os.walk(extracted_dir):
            for name in files:
                extracted_file_paths.append(os.path.join(root, name))

        # Decompile via FernFlower if not already done
        if not flag_fernflower:
            fernflower_decompiler_results = run_fernflower_decompiler(file_path)
            if fernflower_decompiler_results:
                extracted_file_paths.extend(fernflower_decompiler_results)
            else:
                logging.info("No files returned from FernFlower decompiler.")
        else:
            logging.info("FernFlower analysis already performed; skipping decompilation.")

        return extracted_file_paths

    except Exception as ex:
        logging.error(f"Error in run_jar_extractor: {ex}")
        return None

def extract_inno_setup(file_path):
    """
    Extracts an Inno Setup installer using innounp-2.
    Returns a list of extracted file paths, or None on failure.

    :param file_path: Path to the Inno Setup installer (.exe)
    :return: List of file paths under extraction directory, or None if extraction failed.
    """
    try:
        logging.info(f"Detected Inno Setup installer: {file_path}")

        # Create a unique output directory
        folder_number = 1
        while os.path.exists(f"{inno_setup_unpacked_dir}_{folder_number}"):
            folder_number += 1
        output_dir = f"{inno_setup_unpacked_dir}_{folder_number}"
        os.makedirs(output_dir, exist_ok=True)

        # Run innounp-2 to extract files
        cmd = [
            inno_unpack_path,
            "-e",                # extract files
            file_path,
            "-d", output_dir     # output directory
        ]
        # Improved innounp command for extraction
        cmd = [
            inno_unpack_path,
            "-x",               # extract files with full paths
            "-b",               # batch mode (non-interactive)
            "-u",               # use UTF-8 output (for filenames with unicode)
            "-a",               # extract all copies of duplicate files
            "-d", output_dir,   # output directory
            file_path           # the installer to unpack
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
        if result.returncode != 0:
            logging.error(f"innounp-2 failed: {result.stderr}")
            return None

        logging.info(f"Inno Setup content extracted to {output_dir}")

        # Gather all extracted file paths
        extracted_paths = []
        for root, _, files in os.walk(output_dir):
            for filename in files:
                extracted_paths.append(os.path.join(root, filename))

        return extracted_paths

    except Exception as ex:
        logging.error(f"Error extracting Inno Setup file {file_path}: {ex}")
        return None

def is_inno_setup_archive_from_output(die_output):
    """
    Check if the DIE output indicates an Inno Setup installer.
    A file is considered an Inno Setup installer if the output contains both:
      - "Data: Inno Setup Installer data"
      - "Installer: Inno Setup Module"
    """
    if die_output and \
       "Data: Inno Setup Installer data" in die_output and \
       "Installer: Inno Setup Module" in die_output:
        logging.info("DIE output indicates an Inno Setup installer.")
        return True

    logging.info(f"DIE output does not indicate an Inno Setup installer: {die_output!r}")
    return False

def extract_upx(file_path):
    """
    Unpacks a UPX-compressed executable using UPX.
    Returns the path to the unpacked file, or None on failure.

    :param file_path: Path to the UPX-packed executable (.exe, .dll, etc.)
    :return: Path to the unpacked file, or None if unpacking failed.
    """
    try:
        logging.info(f"Detected UPX-packed file: {file_path}")

        # Create a unique output filename inside that directory
        base_name = os.path.basename(file_path)
        name, ext = os.path.splitext(base_name)
        folder_number = 1
        while True:
            out_filename = f"{name}_unpacked{'' if folder_number == 1 else f'_{folder_number}'}{ext}"
            output_path = os.path.join(upx_extracted_dir, out_filename)
            if not os.path.exists(output_path):
                break
            folder_number += 1

        # Run UPX to decompress
        cmd = [
            upx_path,
            "-d",                 # decompress mode
            file_path,
            "-o", output_path     # output file
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        if result.returncode != 0:
            logging.error(f"UPX unpack failed: {result.stderr.strip()}")
            return None

        logging.info(f"UPX unpacked file written to: {output_path}")
        return output_path

    except Exception as ex:
        logging.error(f"Error unpacking UPX file {file_path}: {ex}")
        return None

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

        logging.info("Extraction completed successfully.")
        return pe_file_paths  # Return the list of file paths

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return []  # Return an empty list in case of error

def create_shadow_copy(drive_letter):
    """
    Uses WMI to create a Volume Shadow Copy (VSS) for the given drive (e.g. 'C:').
    Returns the shadow ID on success, or None on failure.
    """
    try:
        c = wmi.WMI(namespace='root\\cimv2')
        # Note: Format of the Create method is (Volume, Context)
        # Context "ClientAccessible" means the copy is exposed under a drive letter.
        result, shadow_id = c.Win32_ShadowCopy.Create(Volume=drive_letter + "\\", Context="ClientAccessible")
        if result == 0:
            logging.info(f"Shadow copy created, ID = {shadow_id}")
            return shadow_id
        else:
            logging.error(f"Failed to create shadow (WMI code {result})")
            return None
    except Exception:
        logging.error("Error creating shadow copy via WMI")
        return None

def copy_from_shadow(shadow_root, rel_path, dest_path):
    """
    Copy a file from the shadow copy. Returns True on success, False on failure.
    """
    shadow_file = os.path.join(shadow_root, rel_path)
    if not os.path.exists(shadow_file):
        logging.error(f"Not found in shadow: {shadow_file}")
        return False
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    try:
        shutil.copy2(shadow_file, dest_path)
        return True
    except Exception as e:
        logging.error(f"Failed to copy from shadow: {e}")
        return False

def _copy_to_dest(file_path, dest_root):
    """
    Copy file_path into dest_root, preserving subpath.
    Returns the copied-destination path on success, or None on failure.
    Uses a Volume Shadow Copy on Windows to handle locked files.
    """
    if not os.path.exists(file_path):
        logging.error(f"Source does not exist: {file_path}")
        return None

    src_root = os.path.dirname(file_path)
    rel_path = os.path.relpath(file_path, src_root)
    dest_path = os.path.join(dest_root, rel_path)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # Try normal copy first
    try:
        shutil.copy2(file_path, dest_path)
        logging.info(f"Copied '{file_path}' '{dest_path}'")
        return dest_path
    except Exception as e:
        logging.error(f"Normal copy failed ({e}), attempting shadow copy")

    # Fallback: shadow copy
    drive = os.path.splitdrive(file_path)[0]  # e.g. "C:"
    shadow_root = create_shadow_copy(drive)
    if shadow_root and copy_from_shadow(shadow_root, rel_path, dest_path):
        logging.info(f"Copied from shadow '{file_path}' '{dest_path}'")
        return dest_path

    logging.error(f"All copy methods failed for: {file_path}")
    return None

def decompile_cx_freeze(executable_path):
    """
    Extracts <exe_name>__main__.pyc from a CX_Freeze library.zip using pyzipper,
    and returns the path to the extracted .pyc file.
    """
    exe_name = os.path.splitext(os.path.basename(executable_path))[0]
    dist_dir = os.path.join(os.path.dirname(executable_path), "dist")
    lib_zip_path = os.path.join(dist_dir, "lib", "library.zip")

    if not os.path.isfile(lib_zip_path):
        logging.error("CXFreeze library.zip not found: %s", lib_zip_path)
        return None

    target_pyc_name = f"{exe_name}__main__.pyc"

    try:
        os.makedirs(cx_freeze_extracted_dir, exist_ok=True)
    except Exception as e:
        logging.error("Failed to create directory %s: %s", cx_freeze_extracted_dir, e)
        return None

    extracted_pyc_path = os.path.join(cx_freeze_extracted_dir, target_pyc_name)

    try:
        with pyzipper.AESZipFile(lib_zip_path, 'r') as zipf:
            if target_pyc_name not in zipf.namelist():
                logging.error("File '%s' not found in archive: %s", target_pyc_name, lib_zip_path)
                return None

            with zipf.open(target_pyc_name) as src, open(extracted_pyc_path, "wb") as dst:
                dst.write(src.read())

            logging.info("Extracted file: %s", extracted_pyc_path)

    except Exception as e:
        logging.error("Failed to extract '%s' from '%s': %s", target_pyc_name, lib_zip_path, e)
        return None

    return extracted_pyc_path

executor = ThreadPoolExecutor(max_workers=1000)

def run_in_thread(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        return executor.submit(fn, *args, **kwargs)
    return wrapper

def show_code_with_pylingual_pycdas(
    file_path: str,
) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, str]]]:
    """
    Decompile a .pyc file using both Pylingual and pycdas decompilers.

    Returns:
        Tuple:
          - pylingual: A dict mapping each decompiled .py filename to its source code string, or None
          - pycdas: A dict mapping each decompiled .py filename to its source code string, or None
    """
    try:
        logging.info(f"Decompiling with Pylingual and pycdas: {file_path}")
        pyc_path = Path(file_path)
        if not pyc_path.exists():
            logging.error(f".pyc file not found: {file_path}")
            return None, None

        pylingual_results: Dict[str, str] = {}
        pycdas_results: Dict[str, str] = {}

        # === Pylingual Decompilation ===
        try:
            # Create an output directory under the base dir for Pylingual
            target_dir = Path(pylingual_extracted_dir) / f"decompiled_{pyc_path.stem}"
            target_dir.mkdir(parents=True, exist_ok=True)

            # Run the unified decompiler; writes files into target_dir
            decompile_pyc_with_pylingual(str(pyc_path))

            # Read the decompiled files from Pylingual
            for file in target_dir.iterdir():
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if file.suffix == ".py":
                            pylingual_results[file.name] = content
                except Exception as read_ex:
                    logging.warning(f"Failed to read Pylingual file {file}: {read_ex}")

            logging.info(f"Pylingual decompilation completed. Found {len(pylingual_results)} Python files.")

        except Exception as pylingual_ex:
            logging.error(f"Pylingual decompilation failed for {file_path}: {pylingual_ex}")

        # === pycdas Decompilation ===
        try:
            pycdas_output_path = run_pycdas_decompiler(file_path)

            if pycdas_output_path and os.path.exists(pycdas_output_path):
                # Read the decompiled file from pycdas
                with open(pycdas_output_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    file_name = os.path.basename(pycdas_output_path)
                    pycdas_results[file_name] = content

                logging.info(f"pycdas decompilation completed. Output: {pycdas_output_path}")
            else:
                logging.warning(f"pycdas decompilation failed or produced no output for {file_path}")

        except Exception as pycdas_ex:
            logging.error(f"pycdas decompilation failed for {file_path}: {pycdas_ex}")

        # Return results (None if empty)
        return (
            pylingual_results if pylingual_results else None,
            pycdas_results if pycdas_results else None
        )

    except Exception as ex:
        logging.error(f"Unexpected error in show_code_with_pylingual_pycdas for {file_path}: {ex}")
        return None, None

# --- Main Scanning Function ---
@run_in_thread
def scan_and_warn(file_path,
                  mega_optimization_with_anti_false_positive=True,
                  command_flag=False,
                  flag_debloat=False,
                  flag_obfuscar=False,
                  flag_de4dot=False,
                  flag_fernflower=False,
                  nsis_flag=False,
                  ntdll_dropped=False):
    """
    Scans a file for potential issues.
    Only does ransomware_alert and worm_alert once per unique file path.
    """
    try:
        # Initialize variables
        perform_special_scan = False
        is_decompiled = False
        pe_file = False
        signature_check = {
            "has_microsoft_signature": False,
            "is_valid": False,
            "signature_status_issues": False
        }

        # Convert WindowsPath to string if necessary
        if isinstance(file_path, WindowsPath):
            file_path = str(file_path)

        # Ensure path is a string, exists, and is non-empty
        if not isinstance(file_path, str):
            logging.error(f"Invalid file_path type: {type(file_path).__name__}")
            return False

        # Ensure the file exists before proceeding.
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return False

        # Check if the file is empty.
        if os.path.getsize(file_path) == 0:
            logging.debug(f"File {file_path} is empty. Skipping scan.")
            return False

        # Normalize the original path
        norm_path = os.path.abspath(file_path)

        # Compute a quick MD5
        md5 = compute_md5(norm_path)

        # Initialize our seen-set once, on the function object
        if not hasattr(scan_and_warn, "_seen"):
            scan_and_warn._seen = set()

        # If we've already scanned this exact (path, hash), skip immediately
        key = (norm_path.lower(), md5)
        if key in scan_and_warn._seen:
            logging.debug(f"Skipping duplicate scan for {norm_path} (hash={md5})")
            return False

         # Mark it seen and proceed
        scan_and_warn._seen.add(key)

        # SNAPSHOT the cache entry _once_ up front:
        initial_md5_in_cache = file_md5_cache.get(norm_path)

        normalized_path = norm_path.lower()
        normalized_sandbox = os.path.abspath(sandboxie_folder).lower()
        normalized_de4dot = os.path.abspath(de4dot_sandboxie_dir).lower()

        # --- Route files based on origin folder ---
        if normalized_path.startswith(normalized_de4dot):
            perform_special_scan = True
            # Copy from de4dot sandbox to extracted directory and rescan
            dest = _copy_to_dest(norm_path, de4dot_extracted_dir)
            if dest is not None:
                scan_and_warn(dest,
                                mega_optimization_with_anti_false_positive,
                                command_flag,
                                flag_debloat,
                                flag_obfuscar,
                                flag_de4dot,
                                flag_fernflower,
                                nsis_flag,
                                ntdll_dropped)
        elif normalized_path.startswith(normalized_sandbox):
            # Check if this is a dropped ntdll.dll in the sandbox
            if normalized_path == sandboxed_ntdll_path:
                ntdll_dropped = True
                logging.warning(f"ntdll.dll dropped in sandbox at path: {normalized_path}")
                # Optionally force a special scan for this file
                perform_special_scan = True
                # You may choose a specific dir for ntdll analysis, or reuse existing staging dir
                dest = _copy_to_dest(norm_path, copied_sandbox_and_main_files_dir)
                if dest is not None:
                    scan_and_warn(
                        dest,
                        mega_optimization_with_anti_false_positive,
                        command_flag,
                        flag_debloat,
                        flag_obfuscar,
                        flag_de4dot,
                        flag_fernflower,
                        nsis_flag,
                        ntdll_dropped
                    )

            # --- General sandbox routing for other files ---
            perform_special_scan = True
            dest = _copy_to_dest(norm_path, copied_sandbox_and_main_files_dir)
            if dest is not None:
                scan_and_warn(
                    dest,
                    mega_optimization_with_anti_false_positive,
                    command_flag,
                    flag_debloat,
                    flag_obfuscar,
                    flag_de4dot,
                    flag_fernflower,
                    nsis_flag,
                    ntdll_dropped
                )

        # 1) Is this the first time we've seen this path?
        is_first_pass = norm_path not in file_md5_cache

        # Extract the file name
        file_name = os.path.basename(norm_path)

        # Try cache first
        if md5 in die_cache:
            die_output, plain_text_flag = die_cache[md5]
        else:
            die_output, plain_text_flag = get_die_output(norm_path)

        # Store for next time
        die_cache[md5] = (die_output, plain_text_flag)

        # Perform ransomware alert check
        if is_file_fully_unknown(die_output):
            if perform_special_scan:
                ransomware_alert(norm_path)
            if mega_optimization_with_anti_false_positive:
                logging.info(
                    f"Stopped analysis; unknown data detected in {norm_path}"
                )
                return False

        if is_advanced_installer_file_from_output(die_output):
            logging.info(f"File {norm_path} is a valid Advanced Installer file.")
            extracted_files = advanced_installer_extractor(file_path)
            for extracted_file in extracted_files:
                scan_and_warn(extracted_file)

        if is_pe_file_from_output(die_output):
            logging.info(f"File {norm_path} is a valid PE file.")
            pe_file = True

        if not is_first_pass and perform_special_scan and pe_file:
                worm_alert(norm_path)
                return True

        # On subsequent passes: skip if unchanged (unless forced)
        if initial_md5_in_cache == md5:
            logging.info(f"Skipping scan for unchanged file: {norm_path}")
            return False
        else:
            # File changed or forced: update MD5 and deep scan
            file_md5_cache[norm_path] = md5

        logging.info(f"Deep scanning file: {norm_path}")

        # Wrap norm_path in a Path once, up front
        wrap_norm_path = Path(norm_path)

        # Read raw binary data (for scanning, YARA, hashing, etc.)
        data_content = b""
        try:
            with open(norm_path, "rb") as f:
                data_content = f.read()
        except Exception as e:
            logging.error(f"Failed to read binary data from {norm_path}: {e}")

        # Read as UTF-8 text lines (for processing code/config/scripts/etc.)
        lines = []
        try:
            with open(norm_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            logging.error(f"Failed to read text lines from {norm_path}: {e}")

        # 1) Obfuscar-dir check
        if Path(obfuscar_dir) in wrap_norm_path.parents and not flag_obfuscar:
            flag_obfuscar = True
            logging.info(f"Flag set to True because '{norm_path}' is inside the Obfuscar directory '{obfuscar_dir}'.")

        # 2) de4dot directories check
        match = next(
            (Path(p) for p in (de4dot_extracted_dir, de4dot_sandboxie_dir)
            if Path(p) in wrap_norm_path.parents),
            None
        )
        if match and not flag_de4dot:
            flag_de4dot = True
            logging.info(
                f"Flag set to True because '{norm_path}' is inside the de4dot directory '{match}'"
        )

        # Check if the file content is valid non plain text data
        if not plain_text_flag:
            logging.info(f"File {norm_path} contains valid non plain text data.")
            # Attempt to extract the file
            try:
                logging.info(f"Attempting to extract file {norm_path}...")
                extracted_files = extract_all_files_with_7z(norm_path, nsis_flag)

                if extracted_files:
                    logging.info(f"Extraction successful for {norm_path}. Scanning extracted files...")
                    # Recursively scan each extracted file
                    for extracted_file in extracted_files:
                        logging.info(f"Scanning extracted file: {extracted_file}")
                        threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()

                logging.info(f"File {norm_path} is not a valid archive or extraction failed. Proceeding with scanning.")
            except Exception as extraction_error:
                logging.error(f"Error during extraction of {norm_path}: {extraction_error}")

            if is_enigma1_protector(die_output):
                extracted_path = try_unpack_enigma1(norm_path)
                if extracted_path:
                    logging.info(f"Unpack succeeded. Files are in: {extracted_path}")
                    threading.Thread(target=scan_and_warn, args=(extracted_path,)).start()
                else:
                    logging.info("Unpack failed for all known Enigma1 Virtual Box protected versions.")

            if is_packer_upx_output(die_output):
                upx_unpacked = extract_upx(norm_path)
                if upx_unpacked:
                    threading.Thread(target=scan_and_warn, args=(upx_unpacked,)).start()
                else:
                    logging.error(f"Failed to unpack {norm_path}")
            else:
                logging.info(f"Skipping non-UPX file: {norm_path}")

            if is_nsis_from_output(die_output):
                nsis_flag= True

            # Detect Inno Setup installer
            if is_inno_setup_archive_from_output(die_output):
                # Extract Inno Setup installer files
                extracted = extract_inno_setup(norm_path)
                if extracted is not None:
                    logging.info(f"Extracted {len(extracted)} files. Scanning...")
                    for inno_norm_path in extracted:
                        try:
                            # send to scan_and_warn for analysis
                            threading.Thread(target=scan_and_warn, args=(inno_norm_path,)).start()
                        except Exception as e:
                            logging.error(f"Error scanning {inno_norm_path}: {e}")
                else:
                    logging.error("Extraction failed; nothing to scan.")

            # Deobfuscate binaries obfuscated by Go Garble.
            if is_go_garble_from_output(die_output):
                # Generate output paths based on the file name and the specified directories
                output_path = os.path.join(ungarbler_dir, os.path.basename(norm_path))
                string_output_path = os.path.join(ungarbler_string_dir, os.path.basename(norm_path) + "_strings.txt")

                # Process the file and get the results
                results = process_file_go(norm_path, output_path, string_output_path)

                # Send the output files for scanning if they are created
                if results.get("patched_data"):
                    # Scan the patched binary file
                    threading.Thread(target=scan_and_warn, args=(output_path,)).start()

                if results.get("decrypt_func_list"):
                    # Scan the extracted strings file
                    threading.Thread(target=scan_and_warn, args=(string_output_path,)).start()

            # ------------- Step A: YARA check for CXFreeze -------------
            if cx_freeze_rule:
                try:
                    # Run YARA-X over the raw bytes
                    scanner = yara_x.Scanner(rules=cx_freeze_rule)
                    results = scanner.scan(data=data_content)

                    for rule in getattr(results, "matching_rules", []) or []:
                        identifier = getattr(rule, "identifier", None)
                        if identifier and identifier not in excluded_rules:
                            logging.info(
                                f"YARA rule '{identifier}' matched on {file_path}. Invoking CXFreeze decompiler."
                            )

                            # Extract + decompile the CXFreeze __main__.pyc
                            cx_freeze_main_pyc_path = decompile_cx_freeze(file_path)

                            if cx_freeze_main_pyc_path:
                                scan_and_warn(cx_freeze_main_pyc_path)
                            # Once a non-excluded YARA rule triggered CXFreeze decompilation, skip the rest.
                            return
                        else:
                            if identifier:
                                logging.info(f"YARA rule '{identifier}' is excluded.")
                    # No matching (non-excluded) rule-continue into the normal .pyc logic below.
                except Exception as e:
                    logging.error(f"Error scanning {file_path} with cx_freeze_rule: {e}")
            # ---------------------------------------------------------------------

            # Check if it's a .pyc file and decompile via Pylingual
            if is_pyc_file_from_output(die_output):
                logging.info(
                    f"File {norm_path} is a .pyc (Python Compiled Module). Attempting Pylingual decompilation...")

                # 1) Decompile
                pylingual, pycdas = show_code_with_pylingual_pycdas(
                    file_path=norm_path,
                )

                # 2) Scan .py sources in-memory
                if pylingual:
                    logging.info("Scanning all decompiled .py files from Pylingual output.")
                    for fname, source in pylingual.items():
                        logging.info(f"Scheduling scan for decompiled file: {fname}")
                        threading.Thread(
                            target=scan_and_warn,
                            kwargs={"file_path": None, "content": source}
                        ).start()
                else:
                    logging.error(f"Pylingual decompilation failed for {norm_path}.")

                # 3) Scan non-.py resources in-memory
                if pycdas:
                    logging.info("Scanning all extracted resources from PyCDAS output.")
                    for rname, rcontent in pycdas.items():
                        logging.info(f"Scheduling scan for resource: {rname}")
                        threading.Thread(
                            target=scan_and_warn,
                            kwargs={"file_path": None, "content": rcontent}
                        ).start()
                else:
                    logging.info(f"No extra resources extracted for {norm_path}.")

            # Operation of the PE file
            if pe_file:
                logging.info(f"File {norm_path} is identified as a PE file.")

                # Perform signature check only if the file is non plain text data
                signature_check = check_signature(norm_path)
                logging.info(f"Signature check result for {norm_path}: {signature_check}")
                if not isinstance(signature_check, dict):
                    logging.error(f"check_signature did not return a dictionary for file: {norm_path}, received: {signature_check}")

                # Handle signature results
                if signature_check["has_microsoft_signature"]:
                    logging.info(f"Valid Microsoft signature detected for file: {norm_path}")
                    return False

                # Check for good digital signatures (valid_goodsign_signatures) and return false if they exist and are valid
                if signature_check.get("valid_goodsign_signatures"):
                    logging.info(f"Valid good signature(s) detected for file: {norm_path}: {signature_check['valid_goodsign_signatures']}")
                    return False

                if signature_check["is_valid"]:
                    logging.info(f"File '{norm_path}' has a valid signature. Skipping worm detection.")
                elif signature_check["signature_status_issues"] and not signature_check["no_signature"]:
                    logging.warning(f"File '{norm_path}' has signature issues. Proceeding with further checks.")
                    notify_user_invalid(norm_path, "Win32.Susp.InvalidSignature")

                # Detect .scr extension and trigger heuristic warning
                if norm_path.lower().endswith(".scr"):
                    logging.warning(f"Suspicious .scr file detected: {norm_path}")
                    notify_user_scr(norm_path, "HEUR:Win32.Susp.PE.SCR.gen")

                # Decompile the file in a separate thread
                decompile_thread = threading.Thread(target=decompile_file, args=(norm_path,))
                decompile_thread.start()

                # PE section extraction and scanning
                section_files = extract_pe_sections(norm_path)
                if section_files:
                    logging.info(f"Extracted {len(section_files)} PE sections. Scanning...")
                    for fpath in section_files:
                        try:
                            threading.Thread(target=scan_and_warn, args=(fpath,)).start()
                        except Exception as e:
                            logging.error(f"Error scanning PE section {fpath}: {e}")
                else:
                    logging.error("PE section extraction failed or no sections found.")

                # Extract resources
                extracted = extract_resources(norm_path, resource_extractor_dir)
                if extracted:
                    for file in extracted:
                        threading.Thread(target=scan_and_warn, args=(file,)).start()

                # Use the `debloat` library to optimize PE file for scanning
                try:
                    if not flag_debloat:
                        logging.info(f"Debloating PE file {norm_path} for faster scanning.")
                        optimized_norm_path = debloat_pe_file(norm_path)
                        if optimized_norm_path:
                            logging.info(f"Debloated file saved at: {optimized_norm_path}")
                            threading.Thread(
                                target=scan_and_warn,
                                args=(optimized_norm_path,),
                                kwargs={'flag_debloat': True}
                            ).start()
                        else:
                             logging.error(f"Debloating failed for {norm_path}, continuing with the original file.")
                except Exception as ex:
                    logging.error(f"Error during debloating of {norm_path}: {ex}")

            dotnet_result = False

            # Analyze the DIE output for .NET file information
            dotnet_result = is_dotnet_file_from_output(die_output)

            if dotnet_result is True:
                dotnet_thread = threading.Thread(target=decompile_dotnet_file, args=(norm_path,))
                dotnet_thread.start()
            elif isinstance(dotnet_result, str) and "Protector: Obfuscar" in dotnet_result and not flag_obfuscar:
                logging.info(f"The file is a .NET assembly protected with Obfuscar: {dotnet_result}")
                deobfuscated_path = deobfuscate_with_obfuscar(norm_path, file_name)
                if deobfuscated_path:
                    threading.Thread(
                        target=scan_and_warn,
                        args=(deobfuscated_path,),
                        kwargs={'flag_obfuscar': True}
                    ).start()
                else:
                    logging.warning("Deobfuscation failed or unpacked file not found.")

            elif dotnet_result is not None and not flag_de4dot and not "Protector: Obfuscar" in dotnet_result:
                de4dot_thread = threading.Thread(target=run_de4dot_in_sandbox, args=(norm_path,))
                de4dot_thread.start()

            if is_jar_file_from_output(die_output):
                jar_extractor_paths = run_jar_extractor(norm_path, flag_fernflower)
                if jar_extractor_paths:
                    for jar_extractor_path in jar_extractor_paths:
                        threading.Thread(
                            target=scan_and_warn,
                            args=(jar_extractor_path,),
                            kwargs={'flag_fernflower': True}
                        ).start()
                else:
                    logging.warning("Java Archive Extraction or decompilation failed. Skipping scan.")

            if is_java_class_from_output(die_output):
                threading.Thread(target=run_fernflower_decompiler, args=(norm_path,)).start()

            # Check if the file contains Nuitka executable
            nuitka_type = is_nuitka_file_from_output(die_output)

            # Only proceed with extraction if Nuitka is detected
            if nuitka_type:
                try:
                    logging.info(f"Checking if the file {norm_path} contains Nuitka executable of type: {nuitka_type}")
                    # Pass both the file path and Nuitka type to the check_and_extract_nuitka function
                    nuitka_files = extract_nuitka_file(norm_path, nuitka_type)
                    if nuitka_files:
                        for extracted_file in nuitka_files:
                            try:
                                threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()
                            except Exception as e:
                                logging.error(f"Failed to analyze extracted file {extracted_file}: {e}")
                    else:
                        logging.warning("No Nuitka files were extracted for scanning.")
                except Exception as ex:
                    logging.error(f"Error checking or extracting Nuitka content from {norm_path}: {ex}")
            else:
                logging.info(f"No Nuitka executable detected in {norm_path}")

            # Check if the file is a PyInstaller archive
            if is_pyinstaller_archive_from_output(die_output):
                # Determine whether to treat it as ELF or EXE
                if is_elf_file_from_output(die_output):
                    type_hint = "elf"
                else:
                    type_hint = "exe"

                logging.info(f"File {norm_path} is a PyInstaller archive. Will treat as '{type_hint}'.")
                extracted_files_pyinstaller, main_decompiled_output = extract_and_return_pyinstaller(norm_path,
                                                                                                     file_type=type_hint)

                # Scan the main decompiled output (if it exists)
                if main_decompiled_output:
                    logging.info(f"Scanning main decompiled output: {main_decompiled_output}")
                    threading.Thread(target=scan_and_warn, args=(main_decompiled_output,)).start()
                else:
                    logging.warning(f"No main decompiled output for: {norm_path}")

                # Scan each extracted file (if any)
                if extracted_files_pyinstaller:
                    for extracted_file in extracted_files_pyinstaller:
                        logging.info(f"Scanning extracted file: {extracted_file}")
                        threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()
                else:
                    logging.error(f"No files extracted from PyInstaller archive: {norm_path}")
        else:
            # If the file content is plain text, perform scanning with Meta Llama-3.2-1B
            logging.info(f"File {norm_path} does contain plain text data.")
            # Check if the norm_path equals the homepage change path.
            if norm_path == homepage_change_path:
                try:
                    for line in lines:
                        line = line.strip()
                        if line:
                            # Expecting a format like "Firefox,google.com"
                            parts = line.split(',')
                            if len(parts) == 2:
                                browser_tag, homepage_value = parts[0].strip(), parts[1].strip()
                                logging.info(
                                    f"Processing homepage change entry: Browser={browser_tag}, Homepage={homepage_value}")
                                # Call scan_code_for_links, using the homepage value as the code to scan.
                                # Pass the browser tag as the homepage_flag.
                                scan_code_for_links(homepage_value, norm_path, homepage_flag=browser_tag)
                            else:
                                logging.error(f"Invalid format in homepage change file: {line}")
                except Exception as ex:
                    logging.error(f"Error processing homepage change file {norm_path}: {ex}")

            # Log directory type based on file path
            log_directory_type(norm_path)

            # Check if the file is in decompiled_dir
            if norm_path.startswith(decompiled_dir):
                logging.info(f"File {norm_path} is in decompiled_dir.")
                is_decompiled = True

            source_dirs = [
                Path(decompiled_dir).resolve(),
                Path(FernFlower_decompiled_dir).resolve(),
                Path(dotnet_dir).resolve(),
                Path(nuitka_source_code_dir).resolve(),
            ]

            norm_path_resolved = Path(norm_path).resolve()
            ext = norm_path_resolved.suffix.lower()

            if ext in script_exts:
                try:
                    threading.Thread(
                        target=scan_file_with_meta_llama,
                        args=(norm_path,),
                    ).start()
                except Exception as ex:
                    logging.error(f"Error during scanning with Meta Llama-3.2-1B for file {norm_path}: {ex}")
            else:
                for src in source_dirs:
                    try:
                        norm_path_resolved.relative_to(src)
                    except ValueError:
                        continue
                    else:
                        try:
                            threading.Thread(
                                target=scan_file_with_meta_llama,
                                args=(norm_path,),
                            ).start()
                        except Exception as ex:
                            logging.error(
                                f"Error during scanning with Meta Llama-3.2-1B for file {norm_path}: {ex}"
                            )
                        break

            # Scan for malware in real-time only for plain text and command flag
            if command_flag:
                logging.info(f"Performing real-time malware detection for plain text file: {norm_path}...")
                real_time_scan_thread = threading.Thread(target=monitor_message.detect_malware, args=(norm_path,))
                real_time_scan_thread.start()

        # Check if the file is a known rootkit file
        if file_name in known_rootkit_files:
            logging.warning(f"Detected potential rootkit file: {norm_path}")
            rootkit_thread = threading.Thread(target=notify_user_for_detected_rootkit, args=(norm_path, f"HEUR:Rootkit.{file_name}"))
            rootkit_thread.start()

        # Process the file data including magic byte removal
        if not os.path.commonpath([norm_path, processed_dir]) == processed_dir:
            process_thread = threading.Thread(target=process_file_data, args=(norm_path, die_output))
            process_thread.start()

        # Check for fake file size
        if os.path.getsize(norm_path) > 100 * 1024 * 1024:  # File size > 100MB
            with open(norm_path, 'rb') as fake_file:
                file_content_read = fake_file.read(100 * 1024 * 1024)
                if file_content_read == b'\x00' * 100 * 1024 * 1024:  # 100MB of continuous `0x00` bytes
                    logging.warning(f"File {norm_path} is flagged as HEUR:FakeSize.gen")
                    fake_size = "HEUR:FakeSize.gen"
                    if signature_check and signature_check["is_valid"]:
                        fake_size = "HEUR:SIG.Win32.FakeSize.gen"
                    notify_user_fake_size_thread = threading.Thread(target=notify_user_fake_size, args=(norm_path, fake_size))
                    notify_user_fake_size_thread.start()

        # Perform real-time scan
        is_malicious, virus_names, engine_detected = scan_file_real_time(norm_path, signature_check, file_name, die_output, pe_file=pe_file)

        # Inside the scan check logic
        if is_malicious:
            # Concatenate multiple virus names into a single string without delimiters
            virus_name = ''.join(virus_names)
            logging.warning(f"File {norm_path} is malicious. Virus: {virus_name}")

            if virus_name.startswith("PUA."):
                notify_user_pua_thread = threading.Thread(target=notify_user_pua, args=(norm_path, virus_name, engine_detected))
                notify_user_pua_thread.start()
            else:
                notify_user_thread = threading.Thread(target=notify_user, args=(norm_path, virus_name, engine_detected))
                notify_user_thread.start()

        # Additional post-decompilation actions based on extracted file path
        if is_decompiled:
            logging.info(f"Checking original file path from decompiled data for: {norm_path}")
            original_norm_path_thread = threading.Thread(target=extract_original_norm_path_from_decompiled, args=(norm_path,))
            original_norm_path_thread.start()

        detection_result = detect_suspicious_filename_patterns(file_name, fileTypes)
        if detection_result['suspicious']:
            # Handle multiple attack types if present
            attack_types = []
            if detection_result['rlo_attack']:
                attack_types.append("RLO")
            if detection_result['excessive_spaces']:
                attack_types.append("Spaces")
            if detection_result['multiple_extensions']:
                attack_types.append("MultiExt")

            virus_name = f"HEUR:Susp.Name.{'+'.join(attack_types)}.gen"
            notify_user_susp_name(file_path, virus_name)

    except Exception as ex:
        logging.error(f"Error scanning file {norm_path}: {ex}")
        return False


def analyze_process_memory(file_path: str) -> str:
    """Perform memory analysis on the specified process and extract files using pymem and pd64."""
    # Verify input path exists
    if not os.path.isfile(file_path):
        logging.error(f"File not found: {file_path}")
        return None

    logging.info(f"Starting pymem attachment on: {file_path}")
    try:
        pm = pymem.Pymem(file_path)

        saved_dumps = []
        extracted_strings = []

        try:
            for module in enum_process_modules(pm.process_handle):
                base_addr = ctypes.cast(module, ctypes.POINTER(ctypes.c_void_p)).contents.value
                module_info = get_module_info(pm.process_handle, base_addr)

                try:
                    data = read_memory_data(pm, base_addr, module_info.SizeOfImage)
                    # Save raw memory dump for this module
                    os.makedirs(memory_dir, exist_ok=True)
                    dump_filename = os.path.join(
                        memory_dir,
                        f"mem_{hex(base_addr)}.bin"
                    )
                    save_memory_data(dump_filename, data)
                    saved_dumps.append(dump_filename)

                    ascii_strings = extract_ascii_strings(data)
                    extracted_strings.append(f"Module {hex(base_addr)} Strings:")
                    extracted_strings.extend(ascii_strings)
                except Exception as ex:
                    logging.warning(f"Error reading memory at {hex(base_addr)}: {ex}")
        finally:
            pm.close_process()  # Explicitly release the process handle
            logging.info(f"Released process handle for: {file_path}")

        # Save extracted ASCII strings
        base_filename = "extracted_strings"
        output_txt = os.path.join(memory_dir, f"{base_filename}.txt")
        count = 1
        while os.path.exists(output_txt):
            output_txt = os.path.join(memory_dir, f"{base_filename}_{count}.txt")
            count += 1
        save_extracted_strings(output_txt, extracted_strings)
        logging.info(f"Strings analysis complete. Results saved in {output_txt}")

        # Use PD64 to extract embedded files from each memory dump
        for dump in saved_dumps:
            logging.info(f"Running pd64 on dump: {dump}")
            subdir = os.path.join(pd64_extracted_dir, os.path.basename(dump))
            os.makedirs(subdir, exist_ok=True)
            if extract_with_pd64(dump, subdir):
                # Scan all extracted files
                for root, _, files in os.walk(subdir):
                    for fname in files:
                        full_path = os.path.join(root, fname)
                        logging.info(f"Scanning extracted file: {full_path}")
                        scan_and_warn(full_path)
            else:
                logging.error(f"Skipping scan for dumps in {dump} due to extraction failure.")

        return output_txt
    except Exception as ex:
        logging.error(f"An error occurred during analysis: {ex}")
        return None

def monitor_memory_changes(change_threshold_bytes=0):
    """
    Continuously monitor all processes for RSS memory changes.

    When a change greater than change_threshold_bytes is detected, attempt to
    dump and analyze the process memory. Only scans dumps located within
    the sandboxie_folder or matching the main_file_path.

    :param change_threshold_bytes: Minimum number of bytes RSS must change
                                   before triggering analysis.
    """
    last_rss = {}

    while True:
        for proc in psutil.process_iter(['pid', 'memory_info']):
            pid = proc.info['pid']
            try:
                rss = proc.info['memory_info'].rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            prev_rss = last_rss.get(pid)
            if prev_rss is None or abs(rss - prev_rss) > change_threshold_bytes:
                last_rss[pid] = rss
                logging.info(f"Memory change detected: PID={pid}, RSS={rss}")

                # Only analyze processes where we can retrieve the executable path
                try:
                    exe_path = proc.exe()
                    logging.info(f"Executable path for PID {pid}: {exe_path}")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logging.info(f"Skipping PID {pid}: cannot retrieve executable path ({e})")
                    continue

                # At this point exe_path is guaranteed non-None
                logging.info(f"Analyzing process executable: {exe_path}")

                try:
                    saved_file = analyze_process_memory(exe_path)
                except Exception as e:
                    logging.error(
                        f"analyze_process_memory failed for {exe_path}: {e}"
                    )
                    continue

                if not saved_file:
                    continue

                # Normalize paths for comparison
                sfp = str(saved_file).lower()
                sandbox_path = sandboxie_folder.lower()
                main_path = main_file_path.lower()

                # Only proceed if dump is under Sandboxie or exactly the main file path
                if sandbox_path not in sfp and sfp != main_path:
                    logging.info(
                        f"File {saved_file!r} is outside monitored dirs. Skipping."
                    )
                    continue

                # OK—this dump is in the sandbox or is the main file: scan it
                try:
                    threading.Thread(target=scan_and_warn, args=(saved_file,)).start()
                except Exception as scan_err:
                    logging.error(
                        f"scan_and_warn failed for {saved_file!r}: {scan_err}"
                    )

def monitor_saved_paths():
    """Continuously monitor all path lists in global path_lists and scan new items in threads."""
    seen = set()
    while True:
        for path_list in path_lists:
            for path in path_list:
                if path not in seen:
                    seen.add(path)
                    threading.Thread(target=scan_and_warn, args=(path,)).start()

# Constants for all notification filters
NOTIFY_FILTER = (
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
    FILE_NOTIFY_CHANGE_STREAM_WRITE
)

def monitor_directory(path):
    """
    Monitor a single directory for changes and invoke scan_and_warn on new/modified items.
    """
    if not os.path.exists(path):
        logging.error(f"The directory does not exist: {path}")
        return

    hDir = win32file.CreateFile(
        path,
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
                NOTIFY_FILTER,
                None,
                None
            )
            for action, filename in results:
                full_path = os.path.join(path, filename)
                if os.path.exists(full_path):
                    logging.info(f"Detected change in: {full_path}")
                    threading.Thread(target=scan_and_warn, args=(full_path,)).start()
                else:
                    logging.error(f"File or folder not found: {full_path}")
    except Exception as e:
        logging.error(f"Error monitoring {path}: {e}")
    finally:
        win32file.CloseHandle(hDir)

def monitor_directories():
    """
    Start a background thread for each directory in the list.
    """
    threads = []
    for d in directories_to_scan:
        t = threading.Thread(target=monitor_directory, args=(d,))
        t.start()
        threads.append(t)
        logging.info(f"Started monitoring thread for: {d}")

def start_monitoring_sandbox():
    threading.Thread(target=monitor_directories).start()

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
                logging.info(f"Error processing line: {ex}")

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
                            die_output = get_die_output_binary(file_path)
                            if file_path.endswith('.wll') and is_pe_file_from_output(die_output):
                                malware_type = "HEUR:Win32.Startup.DLLwithWLL.gen.Malware"
                                message = f"Confirmed DLL malware detected: {file_path}\nVirus: {malware_type}"
                            ext = Path(file_path).suffix.lower()
                            if ext in script_exts:
                                malware_type = "HEUR:Win32.Startup.Script.gen.Malware"
                                message = f"Confirmed script malware detected: {file_path}\nVirus: {malware_type}"
                            elif file_path.endswith(('.dll', '.jar', '.msi', '.scr', '.hta',)):
                                malware_type = "HEUR:Win32.Startup.Susp.Extension.gen.Malware"
                                message = f"Confirmed malware with suspicious extension detected: {file_path}\nVirus: {malware_type}"
                            else:
                                malware_type = "HEUR:Win32.Startup.Susp.gen.Malware"
                                message = f"Suspicious startup file detected: {file_path}\nVirus: {malware_type}"

                            logging.warning(f"Suspicious or malicious startup file detected in {directory}: {file}")
                            notify_user_startup(file_path, message)
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()
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
            notify_user_hosts(hosts_path, "HEUR:Win32.Trojan.Hosts.Hijacker.DisableAV.gen")
            return True
        else:
            logging.warning(f"Suspicious hosts file detected: {hosts_path}")
            notify_user_hosts(hosts_path, "HEUR:Win32.Trojan.Hosts.Hijacker.gen")
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
            logging.info("Malicious hosts file detected and flagged.")
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
                        notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.SecureBootRecovery.gen.Malware")
                        threading.Thread(target=scan_and_warn, args=(uefi_path,)).start()
                        alerted_uefi_files.append(uefi_path)
                    elif uefi_path in uefi_paths and is_malicious_file(uefi_path, 1024):
                        logging.warning(f"Malicious file detected: {uefi_path}")
                        notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.ScreenLocker.Ransomware.gen.Malware")
                        threading.Thread(target=scan_and_warn, args=(uefi_path,)).start()
                        alerted_uefi_files.append(uefi_path)

        # Check for any new files in the EFI directory
        efi_dir = rf'{sandboxie_folder}\drive\X\EFI'
        for root, dirs, files in os.walk(efi_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith(".efi") and file_path not in known_uefi_files and file_path not in alerted_uefi_files:
                    logging.warning(f"Unknown file detected: {file_path}")
                    notify_user_uefi(file_path, "HEUR:Win32.Bootkit.Startup.UEFI.gen.Malware")
                    threading.Thread(target=scan_and_warn, args=(file_path,)).start()
                    alerted_uefi_files.append(file_path)


class ScanAndWarnHandler(FileSystemEventHandler):

    def process_file(self, file_path):
        try:
            threading.Thread(target=scan_and_warn, args=(file_path,)).start()
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


def monitor_directories_with_watchdog():
    """
    Use watchdog Observer to monitor multiple directories with the ScanAndWarnHandler.
    """
    event_handler = ScanAndWarnHandler()
    observer = Observer()
    for path in directories_to_scan:
        observer.schedule(event_handler, path=path, recursive=False)
        logging.info(f"Scheduled watchdog observer for: {path}")
    observer.start()

def run_sandboxie_control():
    try:
        logging.info("Running Sandboxie control.")
        # Include the '/open' argument to open the Sandboxie control window
        result = subprocess.run([sandboxie_control_path, "/open"], shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
        logging.info(f"Sandboxie control output: {result.stdout}")
    except subprocess.CalledProcessError as ex:
        logging.error(f"Error running Sandboxie control: {ex.stderr}")
    except Exception as ex:
        logging.error(f"Unexpected error running Sandboxie control: {ex}")

threading.Thread(target=run_sandboxie_control).start()

# ----------------------------------------------------
# Constants for Windows API calls
# ----------------------------------------------------
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E

# WinEvent constants to capture live window events
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_SHOW        = 0x8002
EVENT_SYSTEM_DIALOGSTART = 0x0010
EVENT_OBJECT_HIDE        = 0x8003
EVENT_OBJECT_NAMECHANGE  = 0x800C
WINEVENT_OUTOFCONTEXT    = 0x0000

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Load libraries
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
ole32  = ctypes.windll.ole32

# ----------------------------------------------------
# Process helper: get PID and executable path of a window
# ----------------------------------------------------

def get_process_path(hwnd):
    """Return the executable path of the process owning the given HWND. Try WinAPI first, fall back to psutil."""
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

# ----------------------------------------------------
# Helper functions for enumeration
# ----------------------------------------------------
def get_window_text(hwnd):
    """Retrieve the text of a window; always returns a string."""
    # figure out how many characters we need (plus terminating null)
    length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) + 1
    buf = ctypes.create_unicode_buffer(length)
    # actually pull the text into our buffer
    user32.SendMessageW(hwnd, WM_GETTEXT, length, ctypes.byref(buf))
    # buf.value is always a str (possibly empty)
    return buf.value or ""

def get_control_text(hwnd):
    length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) + 1
    buf = ctypes.create_unicode_buffer(length)
    user32.SendMessageW(hwnd, WM_GETTEXT, length, ctypes.byref(buf))
    return buf.value or ""

def find_child_windows(parent_hwnd):
    """Find all child windows of the given parent window."""
    child_windows = []
    def _enum_proc(hwnd, lParam):
        child_windows.append(hwnd)
        return True
    EnumChildProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    user32.EnumChildWindows(parent_hwnd, EnumChildProc(_enum_proc), None)
    return child_windows

# Signature for the WinEventProc callback
WinEventProcType = ctypes.WINFUNCTYPE(
    None,
    wintypes.HANDLE,  # hWinEventHook
    wintypes.DWORD,   # event
    wintypes.HWND,    # hwnd
    wintypes.LONG,    # idObject
    wintypes.LONG,    # idChild
    wintypes.DWORD,   # dwEventThread
    wintypes.DWORD    # dwmsEventTime
)

# --- UI Automation Setup ---
try:
    uia = CreateObject('UIAutomationClient.CUIAutomation')
except Exception:
    uia = None


def get_uia_text(hwnd):
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

def find_descendant_windows(root_hwnd):
    """
    Recursively enumerate all descendant windows of a given window.
    """
    descendants = []
    stack = [root_hwnd]
    while stack:
        parent = stack.pop()
        children = find_child_windows(parent)
        for ch in children:
            descendants.append(ch)
            stack.append(ch)
    return descendants

# ----------------------------------------------------
# Enumeration-based capture
# ----------------------------------------------------

def find_windows_with_text():
    """
    Enhanced: Recursively enumerate all windows and controls,
    retrieving text via WM_GETTEXT or UI Automation fallback.
    """
    window_handles = []

    def scan_hwnd(hwnd):
        # 1) Standard window text
        raw = get_window_text(hwnd).strip()
        # 2) Control text
        if not raw:
            raw = get_control_text(hwnd).strip()
        # 3) Fallback to UI Automation
        if not raw:
            raw = get_uia_text(hwnd).strip()
        if raw:
            window_handles.append((hwnd, raw, get_process_path(hwnd)))

    # Enumerate top-level windows and scan recursively
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
    def enum_proc(hwnd, lParam):
        scan_hwnd(hwnd)
        for desc in find_descendant_windows(hwnd):
            scan_hwnd(desc)
        return True

    user32.EnumWindows(EnumWindowsProc(enum_proc), None)
    return window_handles


class MonitorMessageCommandLine:
    def __init__(self, max_workers: int = 100):
        self.max_workers = max_workers
        self._win_event_proc = WinEventProcType(self.handle_event)
        self._hooks = []
        # Store monitored paths
        self.main_file_path = os.path.abspath(main_file_path)
        self.sandboxie_folder = os.path.abspath(sandboxie_folder)
        self.known_malware_messages = {
            "classic": {
                "message": "this program cannot be run under virtual environment or debugging software",
                "virus_name": "HEUR:Win32.Trojan.Guloader.C4D9Dd33.gen",
                "process_function": self.process_detected_text_classic
            },
            "av": {
                "message": "disable your antivirus",
                "virus_name": "HEUR:Win32.DisableAV.gen",
                "process_function": self.process_detected_text_av
            },
            "debugger": {
                "message": "a debugger has been found running in your system please unload it from memory and restart your program",
                "virus_name": "HEUR:Win32.Themida.gen",
                "process_function": self.process_detected_text_debugger
            },
            "fanmade": {
                "patterns": [
                    "executed a trojan", "this is the last warning", "creator of this malware", "creator of this trojan",
                    "this trojan has", "by this trojan", "this is a malware", "considered malware", "destroy your computer",
                    "destroy this computer", "execute this malware", "run a malware", "this malware contains", "and makes it unusable",
                    "contains flashing lights", "run malware", "executed is a malware", "resulting in an unusable machine", "this malware will harm your computer",
                    "this trojan and", "using this malware", "this malware can", "gdi malware", "win32 trojan specifically", "malware will run", "this malware is no joke",
                ],
                "virus_name": "HEUR:Win32.GDI.Fanmade.gen",
                "process_function": self.process_detected_text_fanmade
            },
            "rogue": {
                "patterns": [
                    "your pc is infected", "your computer is infected", "your system is infected", "windows is infected",
                    "has found viruses on computer", "windows security alert", "pc is at risk", "malicious program has been detected",
                    "warning virus detected"
                ],
                "virus_name": "HEUR:Win32.Rogue.gen",
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
                "virus_name": "HEUR:Win32.PowerShell.IEX.Downloader.gen",
                "process_function": self.process_detected_powershell_iex_download
            },
            "xmrig": {
                "patterns": [
                    # 'xmrig', # Due to its shortness, it is disabled.
                    'xmrig.exe',
                    'start xmrig',
                    'xmrig --help',
                    'xmrig --version',
                    'xmrig --config'
                ],
                "virus_name": "HEUR:Win32.Miner.XMRig.gen",
                "process_function": self.process_detected_command_xmrig
            },
            "wifi": {
                "command": 'netsh wlan show profile',
                "virus_name": "HEUR:Win32.Trojan.Password.Stealer.Wi-Fi.gen",
                "process_function": self.process_detected_command_wifi
            },
            "shadowcopy": {
                "command": 'get-wmiobject win32_shadowcopy | foreach-object {$_.delete();}',
                "virus_name": "HEUR:Win32.Ransom.ShadowCopy.gen",
                "process_function": self.process_detected_command_ransom_shadowcopy
            },
            "wmic": {
                "command": 'wmic shadowcopy delete',
                "virus_name": "HEUR:Win32.Ransom.ShadowCopy.WMIC.gen",
                "process_function": self.process_detected_command_wmic_shadowcopy
            },
            "startup": {
                "command": 'copy-item \\roaming\\microsoft\\windows\\start menu\\programs\\startup',
                "virus_name": "HEUR:Win32.Startup.PowerShell.Injection.gen",
                "process_function": self.process_detected_command_copy_to_startup
                },
            "schtasks": {
                "command": 'schtasks*/create*/xml*\\temp\\*.tmp',
                "virus_name": "HEUR:Win32.TaskScheduler.TempFile.gen",
                "process_function": self.process_detected_command_schtasks_temp
            },
            "stopeventlog": {
                "command": 'sc.exe stop eventlog',
                "virus_name": "HEUR:Win32.StopEventLog.gen",
                "process_function": self.process_detected_command_stop_eventlog
            },
            "koadic": {
                "patterns": [
                'chcp 437 & schtasks /query /tn k0adic',
                'chcp 437 & schtasks /create /tn k0adic'
                ],
                "virus_name": "HEUR:Win32.Rootkit.Koadic.gen",
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
                "patterns": [rf"findstr.*\b({ '|'.join(re.escape(p) for p in antivirus_process_list) })\b"],
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
        # If the inputs came in as a list of lines, glue them back together.
        if isinstance(text1, list):
            text1 = "".join(text1)
        if isinstance(text2, list):
            text2 = "".join(text2)

        # Now both are plain strings, safe to feed into spaCy
        doc1 = nlp_spacy_lang(text1)
        doc2 = nlp_spacy_lang(text2)
        return doc1.similarity(doc2)

    def process_detected_text_classic(self, text, file_path):
        virus_name = self.known_malware_messages["classic"]["virus_name"]
        message = f"Detected potential anti-vm anti-debug malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_text_av(self, text, file_path):
        virus_name = self.known_malware_messages["av"]["virus_name"]
        message = f"Detected potential anti-AV malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_text_debugger(self, text, file_path):
        virus_name = self.known_malware_messages["debugger"]["virus_name"]
        message = f"Detected potential anti-debugger malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_text_fanmade(self, text, file_path):
        virus_name = self.known_malware_messages["fanmade"]["virus_name"]
        message = f"Detected potential fanmade malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_text_rogue(self, text, file_path):
        virus_name = self.known_malware_messages["rogue"]["virus_name"]
        message = f"Detected potential rogue security software: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_text_ransom(self, text, file_path):
        message = f"Potential ransomware detected in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_wifi(self, text, file_path):
        virus_name = self.known_malware_messages["wifi"]["virus_name"]
        message = f"Detected Wi-Fi credentials stealing malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_ransom_shadowcopy(self, text, file_path):
        virus_name = self.known_malware_messages["shadowcopy"]["virus_name"]
        message = f"Detected ransomware shadow copy deletion: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_wmic_shadowcopy(self, text, file_path):
        virus_name = self.known_malware_messages["wmic"]["virus_name"]
        message = f"Detected WMIC shadow copy deletion: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_copy_to_startup(self, text, file_path):
        virus_name = self.known_malware_messages["startup"]["virus_name"]
        message = f"Detected startup copy malware: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_schtasks_temp(self, text, file_path):
        virus_name = self.known_malware_messages["schtasks"]["virus_name"]
        message = f"Detected scheduled task creation using temp file: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_stop_eventlog(self, text, file_path):
        virus_name = self.known_malware_messages["stopeventlog"]["virus_name"]
        message = f"Detected Stop EventLog command execution: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_rootkit_koadic(self, text, file_path):
        virus_name = self.known_malware_messages["koadic"]["virus_name"]
        message = f"Detected rootkit behavior associated with Koadic: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_fodhelper(self, text, file_path):
        virus_name = self.known_malware_messages["fodhelper"]["virus_name"]
        message = f"Detected UAC bypass attempt using Fodhelper: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_antivirus_search(self, text, file_path):
        virus_name = self.known_malware_messages["antivirus"]["virus_name"]
        message = f"Detected search for antivirus processes: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_powershell_iex_download(self, text, file_path):
        virus_name = self.known_malware_messages["powershell_iex_download"]["virus_name"]
        message = f"Detected PowerShell IEX download command: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_command_xmrig(self, text, file_path):
        virus_name = self.known_malware_messages["xmrig"]["virus_name"]
        message = f"Detected XMRig mining activity: {virus_name} in text: {text} from {file_path}"
        logging.warning(message)
        notify_user_for_detected_command(message, file_path)

    def detect_malware(self, file_path: str):
        if file_path is None:
            logging.error("file_path cannot be None.")
            return

        logging.info(f"Type of file_path received: {type(file_path).__name__}")
        if not isinstance(file_path, str):
            logging.error(f"Expected a string for file_path, but got {type(file_path).__name__}")
            return

        try:
            lines = []
            non_empty_count = 0
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as monitor_file:
                for line in monitor_file:
                    if not line.strip():
                        continue
                    if non_empty_count < 100000:
                        lines.append(line)
                        non_empty_count += 1
                    else:
                        logging.info("Exceeded 100K non-empty lines; stopping read.")
                        break

            file_content = ''.join(lines)
            if not isinstance(file_content, str):
                logging.error("File content is not a valid string.")
                return

            basename = os.path.basename(file_path)

            # Process known malware messages
            for category, details in self.known_malware_messages.items():
                # Check text patterns
                for pattern in details.get("patterns", []):
                    if self.calculate_similarity_text(file_content, pattern) > 0.92:
                        details["process_function"](file_content, file_path)
                        logging.warning(f"Detected malware pattern for '{category}' in {file_path}.")

                # Check fixed message
                if "message" in details and self.calculate_similarity_text(file_content, details["message"]) > 0.92:
                    details["process_function"](file_content, file_path)
                    logging.warning(f"Detected malware message for '{category}' in {file_path}.")

                # Check command patterns only for files named cmd_*.txt
                if "command" in details:
                    if basename.startswith("cmd_") and basename.endswith(".txt"):
                        if self.calculate_similarity_text(file_content, details["command"]) > 0.92:
                            details["process_function"](file_content, file_path)
                            logging.warning(f"Detected malware command for '{category}' in {file_path}.")
                    else:
                        logging.info(f"Skipping command checks for {file_path}: filename does not match cmd_*.txt")

            # Ransomware keyword distance check
            if self.contains_keywords_within_max_distance(file_content, max_distance=10):
                self.process_detected_text_ransom(file_content, file_path)
                logging.warning(f"Detected ransomware keywords in {file_path}.")

            logging.info(f"Finished processing detection for {file_path}.")
            return False

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

    def process_window_text(self, hwnd, text, path):
        """
        Process text from a window - this contains the original logic.
        """
        # If there is no text then return
        if not text:
            return

        # Log the incoming parameters and full text
        logging.info(f"Processing window - hwnd={hwnd}, path={path}, text={text}")

        # write original text
        orig_fn = self.get_unique_filename(f"original_{hwnd}")
        with open(orig_fn, "w", encoding="utf-8", errors="ignore") as f:
            f.write(text[:1_000_000])
        logging.info(f"Wrote original -> {orig_fn}")
        threading.Thread(
            target=scan_and_warn,
            args=(orig_fn,),
            kwargs={'command_flag': True}
        ).start()

        # write preprocessed text
        pre = self.preprocess_text(text)
        if pre:
            pre_fn = self.get_unique_filename(f"preprocessed_{hwnd}")
            with open(pre_fn, "w", encoding="utf-8", errors="ignore") as f:
                f.write(pre[:1_000_000])
            logging.info(f"Wrote preprocessed -> {pre_fn}")
            threading.Thread(
                target=scan_and_warn,
                args=(pre_fn,),
                kwargs={'command_flag': True}
            ).start()

    def handle_event(self, hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime):
        """
        WinEvent callback that re-scans *all* windows and controls on every event,
        *regardless* of whether hwnd is non-zero.  Then falls back to AccessibleObjectFromEvent.
        """
        logging.debug(f"WinEvent: event=0x{event:04X} hwnd={hwnd} obj={idObject} child={idChild}")

        # --- 1) Brute-force scan of *all* top-level windows & their text, on every event
        try:
            all_entries = find_windows_with_text()
            for h, txt, p in all_entries:
                self.process_window_text(h, txt, p)
        except Exception:
            logging.error("Error during brute-force window enumeration")

        # --- 2) COM fallback for non-HWND UI elements
        if idObject != Accessibility.OBJID_WINDOW:
            try:
                CoInitialize()
                pacc = ctypes.POINTER(Accessibility.IAccessible)()
                varChild = VARIANT()

                hr = Accessibility.AccessibleObjectFromEvent(
                    hwnd, idObject, idChild,
                    ctypes.byref(pacc), ctypes.byref(varChild)
                )
                if hr != 0 or not pacc:
                    logging.error(f"AccessibleObjectFromEvent failed: HRESULT=0x{hr:08X}")
                    return

                name = pacc.get_accName(varChild)
                if name:
                    context = f"obj={idObject}, child={idChild}"
                    self.process_window_text(hwnd or 0, name, context)

            except Exception:
                logging.error(
                    f"Error retrieving AccessibleObject for hwnd={hwnd}, "
                    f"idObject={idObject}, idChild={idChild}"
                )

    def start_event_monitoring(self):
        """Install WinEvent hooks and spin up the message pump thread."""
        # initialize COM for this thread
        comtypes.CoInitialize()

        # hook dialog start, show, hide, name-change
        hooks = [
            (EVENT_SYSTEM_DIALOGSTART, EVENT_SYSTEM_DIALOGSTART),
            (EVENT_OBJECT_SHOW,        EVENT_OBJECT_SHOW),
            (EVENT_OBJECT_HIDE,        EVENT_OBJECT_HIDE),
            (EVENT_OBJECT_NAMECHANGE,  EVENT_OBJECT_NAMECHANGE),
        ]
        for ev_min, ev_max in hooks:
            hook = user32.SetWinEventHook(
                EVENT_OBJECT_CREATE,
                EVENT_OBJECT_NAMECHANGE,
                0,
                self._win_event_proc,
                0, 0,
                WINEVENT_OUTOFCONTEXT
            )
            self._hooks.append(hook)

        # pump messages so callbacks get delivered
        threading.Thread(target=self._pump_messages).start()
        logging.info("UIWatcher: WinEvent hooks installed (brute-force scanning).")

    @staticmethod
    def _pump_messages():
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def monitoring_window_text(self):
        """
        Window/control monitoring loop.
        Runs event monitoring and processes windows in parallel.
        """
        logging.debug("Started window/control monitoring loop")

        # Start event monitoring in its own thread
        event_thread = threading.Thread(
            target=self.start_event_monitoring,
            name="EventMonitor"
        )
        event_thread.start()

        # Use a thread pool to process windows concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while True:
                try:
                    windows = find_windows_with_text()
                    logging.debug(f"Enumerated {len(windows)} window(s)/control(s)")
                    for hwnd, text, path in windows:
                        executor.submit(
                            self.process_window_text,
                            hwnd,
                            text,
                            path
                        )
                except Exception:
                    logging.error("Window/control enumeration error:")

    def monitoring_command_line(self):
        logging.debug("Started command-line monitoring loop")
        while True:
            try:
                cmdlines = self.capture_command_lines()
                logging.debug(f"Enumerated {len(cmdlines)} commandline(s)")
                for cmd, exe_path in cmdlines:
                    # normalize to absolute paths and lowercase for comparison
                    exe_path = os.path.abspath(exe_path).lower()
                    main_path = os.path.abspath(self.main_file_path).lower()

                    # skip if not from main executable or in the Sandboxie folder
                    if exe_path != main_path or exe_path.startswith(self.sandboxie_folder.lower()):
                        logging.debug(f"Skipping command from excluded path: {exe_path}")
                        continue

                    # now exe_path is the main executable and not excluded, so log and scan
                    orig_fn = self.get_unique_filename(f"cmd_{os.path.basename(exe_path)}")
                    with open(orig_fn, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(cmd[:1_000_000])
                    logging.info(f"Wrote cmd -> {orig_fn}")
                    threading.Thread(
                        target=scan_and_warn,
                        args=(orig_fn,),
                        kwargs={'command_flag': True}
                    ).start()

                    pre_cmd = self.preprocess_text(cmd)
                    if pre_cmd:
                        pre_fn = self.get_unique_filename(f"cmd_pre_{os.path.basename(exe_path)}")
                        with open(pre_fn, "w", encoding="utf-8", errors="ignore") as f:
                            f.write(pre_cmd[:1_000_000])
                        logging.info(f"Wrote cmd pre -> {pre_fn}")
                        threading.Thread(
                            target=scan_and_warn,
                            args=(pre_fn,),
                            kwargs={'command_flag':True}
                        ).start()

            except Exception as ex:
                logging.exception(f"Command-line snapshot error:{ex}")

    def start_monitoring_threads(self):
        threading.Thread(target=self.monitoring_window_text).start()
        threading.Thread(target=self.monitoring_command_line).start()

def monitor_sandboxie_directory():
    """
    Monitor sandboxie folder for new or modified files and scan/copy them.
    """
    try:
        alerted_files = set()
        scanned_files = set()
        file_mod_times = {}

        while True:
            for directory in directories_to_scan:
                if not os.path.isdir(directory):
                    continue

                for root, _, files in os.walk(directory):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        last_mod_time = os.path.getmtime(file_path)

                        # on first sight: alert + scan + copy
                        if file_path not in alerted_files:
                            logging.info(f"New file detected in {root}: {filename}")
                            alerted_files.add(file_path)
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()

                        # on modification: rescan + recopy
                        if file_path not in scanned_files:
                            scanned_files.add(file_path)
                            file_mod_times[file_path] = last_mod_time
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()  # Scan immediately
                        elif file_mod_times[file_path] != last_mod_time:
                            logging.info(f"File modified in {root}: {filename}")
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()
                            file_mod_times[file_path] = last_mod_time

    except Exception as ex:
        logging.error(f"Error in monitor_sandboxie_directory: {ex}")

def _async_raise(tid, exctype):
    if not isinstance(exctype, type):
        raise TypeError("Only types can be raised")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(tid), ctypes.py_object(exctype)
    )
    if res == 0:
        raise ValueError("Invalid thread ID")
    elif res > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

def kill_thread_silently(thread):
    _async_raise(thread.ident, SystemExit)

def terminate_analysis_threads_immediately():
    logging.info("Forcefully terminating all analysis threads...")

    for thread in analysis_threads:
        if thread.is_alive():
            name = thread_function_map.get(thread, thread.name)
            logging.info(f"Killing thread: {name}")
            kill_thread_silently(thread)

    time.sleep(0.1)  # short delay to let threads exit

    still_alive = [t.name for t in analysis_threads if t.is_alive()]
    if still_alive:
        logging.warning(f"Some threads are still running: {still_alive}")
    else:
        logging.info("All analysis threads have been terminated.")

def perform_sandbox_analysis(file_path, stop_callback=None):
    global main_file_path
    global monitor_message
    global analysis_threads
    global thread_function_map  # Track thread -> function

    try:
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            logging.error(f"Expected str, bytes or os.PathLike object, not {type(file_path).__name__}")
            return

        logging.info(f"Performing sandbox analysis on: {file_path}")

        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        file_path = os.path.normpath(file_path)
        if not os.path.isfile(file_path):
            logging.error(f"File does not exist: {file_path}")
            return

        main_file_path = file_path
        analysis_threads = []
        thread_function_map = {}

        monitor_message = MonitorMessageCommandLine()

        main_dest = _copy_to_dest(file_path, copied_sandbox_and_main_files_dir)

        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        def create_monitored_thread(target_func, *args, **kwargs):
            def monitored_wrapper():
                try:
                    if 'stop_callback' in target_func.__code__.co_varnames:
                        target_func(*args, stop_callback=stop_callback, **kwargs)
                    else:
                        target_func(*args, **kwargs)
                except Exception as e:
                    if stop_callback and stop_callback():
                        logging.info(f"Thread {target_func.__name__} stopped by user request")
                    else:
                        logging.error(f"Error in thread {target_func.__name__}: {e}")

            thread = threading.Thread(target=monitored_wrapper, name=f"Analysis_{target_func.__name__}")
            analysis_threads.append(thread)
            thread_function_map[thread] = target_func.__name__
            return thread

        threads_to_start = [
            (scan_and_warn, (main_dest,)),
            (monitor_memory_changes,),
            (run_sandboxie_plugin,),
            (monitor_snort_log,),
            (web_protection_observer.begin_observing,),
            (monitor_directories_with_watchdog,),
            (start_monitoring_sandbox,),
            (monitor_sandboxie_directory,),
            (check_startup_directories,),
            (monitor_hosts_file,),
            (check_uefi_directories,),
            (monitor_message.start_monitoring_threads,),
            (monitor_saved_paths,),
            (run_sandboxie, (file_path,)),
        ]

        for thread_info in threads_to_start:
            if stop_callback and stop_callback():
                logging.info("Analysis stopped before all threads could start")
                return "[!] Analysis stopped by user request"

            target_func = thread_info[0]
            args = thread_info[1] if len(thread_info) > 1 else ()

            thread = create_monitored_thread(target_func, *args)
            thread.start()

        logging.info("Sandbox analysis started. Please check log after you close program. There is no limit to scan time.")

        while any(thread.is_alive() for thread in analysis_threads):
            if stop_callback and stop_callback():
                logging.info("Stop requested, terminating analysis threads...")
                terminate_analysis_threads_immediately()
                return "[!] Analysis stopped by user request"
            time.sleep(0.1)  # Still needed to avoid CPU spinning

        return "[+] Sandbox analysis completed successfully"

    except Exception as ex:
        if stop_callback and stop_callback():
            logging.info("Analysis stopped by user request during exception handling")
            return "[!] Analysis stopped by user request"

        error_message = f"An error occurred during sandbox analysis: {ex}"
        logging.error(error_message)
        return error_message

def run_sandboxie_plugin_script():
    # build the inner python invocation
    python_entry = f'"{Open_Hydra_Dragon_Anti_Rootkit_path}",Run'
    # build the full command line for Start.exe
    cmd = f'"{sandboxie_path}" /box:DefaultBox /elevate "{python_path}" {python_entry}'
    try:
        logging.info(f"Running python script via Sandboxie: {cmd}")
        # shell=True so that Start.exe sees the switches correctly
        subprocess.run(cmd, check=True, shell=True, encoding="utf-8", errors="ignore")
        logging.info("Python plugin ran successfully in Sandboxie.")
    except subprocess.CalledProcessError as ex:
        logging.error(f"Failed to run python plugin in Sandboxie: {ex}")

def run_sandboxie_plugin():
    # build the inner rundll32 invocation
    dll_entry = f'"{HydraDragonAV_sandboxie_DLL_path}",Run'
    # build the full command line for Start.exe
    cmd = f'"{sandboxie_path}" /box:DefaultBox /elevate rundll32.exe {dll_entry}'
    try:
        logging.info(f"Running DLL via Sandboxie: {cmd}")
        # shell=True so that Start.exe sees the switches correctly
        subprocess.run(cmd, check=True, shell=True, encoding="utf-8", errors="ignore")
        logging.info("Plugin ran successfully in Sandboxie.")
    except subprocess.CalledProcessError as ex:
        logging.error(f"Failed to run plugin in Sandboxie: {ex}")

def run_sandboxie(file_path):
    try:
        subprocess.run([sandboxie_path, '/box:DefaultBox', '/elevate', file_path], check=True, encoding="utf-8", errors="ignore")
    except subprocess.CalledProcessError as ex:
        logging.error(f"Failed to run Sandboxie on {file_path}: {ex}")

def run_de4dot_in_sandbox(file_path):
    """
    Runs de4dot inside Sandboxie to avoid contaminating the host.
    Extracts all files into de4dot_extracted_dir via -ro.
    Uses -r for recursive processing.
    """

    # de4dot-x64.exe -r <input_dir> -ro <output_dir>
    cmd = [
        sandboxie_path,
        "/box:DefaultBox",
        "/elevate",
        de4dot_cex_x64_path,
        "-r",
        file_path,
        "-ro",
        de4dot_extracted_dir
    ]

    try:
        subprocess.run(cmd, check=True, encoding="utf-8", errors="ignore")
        logging.info(f"de4dot extraction succeeded for {file_path} in sandbox DefaultBox")
    except subprocess.CalledProcessError as ex:
        logging.error(f"Failed to run de4dot on {file_path} in sandbox DefaultBox: {ex}")

def run_analysis(file_path: str, stop_callback=None):
    """
    This function mirrors the original AnalysisThread.execute_analysis method.
    It logs the file path, performs the sandbox analysis, and handles any exceptions.
    Now supports a stop_callback to allow graceful interruption.
    """
    try:
        logging.info(f"Running analysis for: {file_path}")

        # Check for stop request before starting
        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        # Perform the sandbox analysis with stop checking
        result = perform_sandbox_analysis(file_path, stop_callback=stop_callback)

        # Check for stop request after analysis
        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        return result if result else "[+] Analysis completed successfully"

    except Exception as ex:
        # Check if the exception was due to a stop request
        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        error_message = f"An error occurred during sandbox analysis: {ex}"
        logging.error(error_message)
        return error_message

# ----- Global Variables to hold captured data -----
pre_analysis_log_path = None
post_analysis_log_path = None
pre_analysis_entries = {}
post_analysis_entries = {}

# ----- Utility Functions -----
def force_remove_log():
    """Forcefully remove the log file in the sandbox if it exists."""
    if os.path.exists(HiJackThis_log_path):
        try:
            os.chmod(HiJackThis_log_path, 0o777)
            os.remove(HiJackThis_log_path)
            logging.info("Previous log removed successfully.")
        except Exception as e:
            logging.error("Failed to remove previous log: %s", e)

def run_and_copy_log(label="orig"):
    """
    Remove any existing log file, launch HiJackThis via Sandboxie,
    then wait until that log file is actually written (modification time changes),
    copy it to a timestamped file, and return its path.

    :param label: Prefix for the copied log filename
    :returns: Path to the copied log file
    """
    force_remove_log()

    # Launch the tool
    cmd = [sandboxie_path, '/box:DefaultBox', '/elevate', HiJackThis_exe]
    subprocess.run(cmd, cwd=script_dir, check=True, encoding="utf-8", errors="ignore")
    logging.debug("HiJackThis launched.")

    # Wait until the log file appears _and_ has been modified with content
    while True:
        if os.path.exists(HiJackThis_log_path):
            stat = os.stat(HiJackThis_log_path)
            if stat.st_size > 0:
                break

    # Copy to timestamped destination
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(HiJackThis_logs_dir, f"{label}_{ts}.txt")
    shutil.copy(HiJackThis_log_path, dest)
    logging.info("Log copied to %s", dest)
    return dest

def parse_report(path):
    """
    Parse the HiJackThis report and return a dictionary where:
      key   -> The log line (lines starting with O2, O4, or O23)
      value -> A 1-tuple containing the first existing file path found on that line,
                or (None,) if no path could be opened.
    """
    entries = {}
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line.startswith(('O2', 'O4', 'O23')):
                continue

            file_path = None
            for part in line.split():
                if os.path.exists(part):
                    try:
                        # test open for readability
                        with open(part, 'rb'):
                            file_path = part
                    except (OSError, IOError):
                        # couldn't open; treat as if not found
                        file_path = None
                    # in either case, stop scanning further parts
                    break

            # store a 1-tuple as the spec'd"tuple containing (file path)"
            entries[line] = (file_path,)

    return entries

# --- Helper Function ---
def get_latest_clamav_def_time():
    """Checks the ClamAV database folder for the latest definition file time."""
    try:
        if not os.path.isdir(clamav_database_directory_path):
            return "ClamAV DB Not Found"

        files = [os.path.join(clamav_database_directory_path, f) for f in os.listdir(clamav_database_directory_path) if os.path.isfile(os.path.join(clamav_database_directory_path, f))]
        if not files:
            return "Definitions DB Empty"

        latest_file = max(files, key=os.path.getmtime)
        mod_time = os.path.getmtime(latest_file)
        return f"Definitions: {datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M')}"
    except Exception as e:
        logging.error(f"Could not read ClamAV DB time: {e}")
        return "Error Reading Definitions"

# --- Custom Hydra Icon Widget ---
class HydraIconWidget(QWidget):
    """A custom widget to draw the Hydra Dragon icon."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pixmap = None
        if os.path.exists(icon_path):
            self.pixmap = QPixmap(icon_path)
        else:
            logging.warning(f"Sidebar icon not found at {icon_path}. Drawing fallback.")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.pixmap and not self.pixmap.isNull():
            painter.drawPixmap(self.rect(), self.pixmap)
        else:
            # Fallback drawing if image is not found
            primary_color = QColor("#88C0D0")
            shadow_color = QColor("#4C566A")
            path = QPainterPath()
            path.moveTo(0, 20)
            path.quadTo(15, 0, 30, 20)
            path.quadTo(15, 10, 0, 20)
            path.moveTo(5, 15)
            path.cubicTo(-20, 0, -10, -25, 0, -20)
            path.quadTo(-5, -18, 5, 15)
            path.moveTo(25, 15)
            path.cubicTo(50, 0, 40, -25, 30, -20)
            path.quadTo(35, -18, 25, 15)
            path.moveTo(15, 10)
            path.cubicTo(10, -20, 20, -20, 15, 10)
            painter.setPen(QPen(primary_color, 3))
            painter.setBrush(shadow_color)
            painter.drawPath(path)


# --- Custom Shield Widget for Status (MODIFIED) ---
class ShieldWidget(QWidget):
    """A custom widget to draw an animated status shield with a glowing effect."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAutoFillBackground(True)
        self.is_protected = True
        self._glow_opacity = 0.0
        self._check_progress = 1.0
        self._scale_factor = 1.0
        self.setMinimumSize(250, 250)

        # Load the hydra image for the protected state
        self.hydra_pixmap = None
        script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else os.getcwd()
        assets_dir = os.path.join(script_dir, "assets")
        if os.path.exists(icon_path):
            self.hydra_pixmap = QPixmap(icon_path)
        else:
            logging.warning(f"Shield icon not found at {icon_path}. Will use fallback drawing.")


        # Animation for the icon appearing/disappearing
        self.check_animation = QPropertyAnimation(self, b"check_progress")
        self.check_animation.setDuration(500)
        self.check_animation.setEasingCurve(QEasingCurve.Type.InOutCubic)

        # Animation for the background glow
        self.glow_animation = QPropertyAnimation(self, b"glow_opacity")
        self.glow_animation.setDuration(2500)
        self.glow_animation.setLoopCount(-1)
        self.glow_animation.setStartValue(0.2)
        self.glow_animation.setKeyValueAt(0.5, 0.7)
        self.glow_animation.setEndValue(0.2)
        self.glow_animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.glow_animation.start()

        # Breathing animation for the shield
        self.breathe_animation = QPropertyAnimation(self, b"scale_factor")
        self.breathe_animation.setDuration(5000)
        self.breathe_animation.setLoopCount(-1)
        self.breathe_animation.setStartValue(1.0)
        self.breathe_animation.setKeyValueAt(0.5, 1.05)
        self.breathe_animation.setEndValue(1.0)
        self.breathe_animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.breathe_animation.start()

    # --- Getter/Setter for check_progress ---
    def get_check_progress(self):
        return self._check_progress

    def set_check_progress(self, value):
        self._check_progress = value
        self.update()

    # --- Getter/Setter for glow_opacity ---
    def get_glow_opacity(self):
        return self._glow_opacity

    def set_glow_opacity(self, value):
        self._glow_opacity = value
        self.update()

    # --- Getter/Setter for scale_factor ---
    def get_scale_factor(self):
        return self._scale_factor

    def set_scale_factor(self, value):
        self._scale_factor = value
        self.update()

    # --- Qt Properties for Animation ---
    check_progress = Property(float, get_check_progress, set_check_progress)
    glow_opacity = Property(float, get_glow_opacity, set_glow_opacity)
    scale_factor = Property(float, get_scale_factor, set_scale_factor)

    def set_status(self, is_protected):
        if self.is_protected != is_protected:
            self.is_protected = is_protected
            self.check_animation.setStartValue(0.0)
            self.check_animation.setEndValue(1.0)
            self.check_animation.start()
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        side = min(self.width(), self.height())
        painter.translate(self.width() / 2, self.height() / 2)
        painter.scale(self._scale_factor, self._scale_factor)
        painter.scale(side / 220.0, side / 220.0)

        # Draw the outer glow
        glow_color = QColor(0, 255, 127) if self.is_protected else QColor(255, 80, 80)
        gradient = QRadialGradient(0, 0, 110)
        glow_color.setAlphaF(self._glow_opacity)
        gradient.setColorAt(0.5, glow_color)
        glow_color.setAlphaF(0)
        gradient.setColorAt(1.0, glow_color)
        painter.setBrush(QBrush(gradient))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(-110, -110, 220, 220)

        # Draw the main shield shape
        path = QPainterPath()
        path.moveTo(0, -90)
        path.cubicTo(80, -80, 80, 0, 80, 0)
        path.lineTo(80, 40)
        path.quadTo(80, 90, 0, 100)
        path.quadTo(-80, 90, -80, 40)
        path.lineTo(-80, 0)
        path.cubicTo(-80, -80, 0, -90, 0, -90)

        # Draw the user's PNG inside the shield if protected and available
        if self.is_protected and self.hydra_pixmap and not self.hydra_pixmap.isNull():
             # Fill shield with a gradient behind the image
            shield_gradient = QLinearGradient(0, -90, 0, 100)
            shield_gradient.setColorAt(0, QColor("#434C5E"))
            shield_gradient.setColorAt(1, QColor("#3B4252"))
            painter.fillPath(path, QBrush(shield_gradient))

            painter.setOpacity(self._check_progress)
            # Define the rectangle to draw the pixmap in
            pixmap_rect = QRect(-75, -85, 150, 150)
            painter.drawPixmap(pixmap_rect, self.hydra_pixmap)
            painter.setOpacity(1.0) # Reset opacity
        else:
            # Fallback to old behavior if image is not loaded or not protected
            shield_gradient = QLinearGradient(0, -90, 0, 100)
            shield_gradient.setColorAt(0, QColor("#4C566A"))
            shield_gradient.setColorAt(1, QColor("#3B4252"))
            painter.fillPath(path, QBrush(shield_gradient))

        painter.setBrush(Qt.BrushStyle.NoBrush)
        progress = self._check_progress

        if not self.is_protected:
            # Draw the original cross for the 'unprotected' status
            painter.setPen(QPen(QColor("white"), 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawLine(-35 * progress, -35 * progress, 35 * progress, 35 * progress)
            painter.drawLine(35 * progress, -35 * progress, -35 * progress, 35 * progress)


# --- Main Application Window ---
class AntivirusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.workers = []
        self.log_outputs = []
        self.animation_group = QParallelAnimationGroup()
        self.setup_ui()
        self.apply_stylesheet()

    def start_worker(self, task_type, *args):
        worker = Worker(task_type, *args)
        worker.output_signal.connect(self.append_log_output)
        worker.finished.connect(lambda w=worker: self.on_worker_finished(w))

        self.workers.append(worker)
        worker.start()
        self.append_log_output(f"[*] Task '{task_type}' started.")
        self.shield_widget.set_status(False)
        self.status_text.setText("System is busy...")

    def on_worker_finished(self, worker):
        self.append_log_output(f"[+] Task '{worker.task_type}' finished.")
        if worker in self.workers:
            self.workers.remove(worker)
        if not self.workers:
            self.shield_widget.set_status(True)
            self.status_text.setText("Ready for analysis!")

    def append_log_output(self, text):
        current_page_index = self.main_stack.currentIndex()
        if 0 <= current_page_index < len(self.log_outputs):
            log_widget = self.log_outputs[current_page_index]
            if log_widget:
                log_widget.append(text)

    def switch_page_with_animation(self, index):
        if self.animation_group.state() == QParallelAnimationGroup.State.Running:
            return

        current_widget = self.main_stack.currentWidget()
        next_widget = self.main_stack.widget(index)

        if current_widget == next_widget:
            return

        current_index = self.main_stack.currentIndex()

        animation_duration = 400
        easing_curve = QEasingCurve.Type.InOutCubic

        next_widget.show()
        next_widget.raise_()

        slide_out_x = -self.main_stack.width() if index > current_index else self.main_stack.width()
        current_pos_anim = QPropertyAnimation(current_widget, b"pos")
        current_pos_anim.setDuration(animation_duration)
        current_pos_anim.setEasingCurve(easing_curve)
        current_pos_anim.setStartValue(QPoint(0, 0))
        current_pos_anim.setEndValue(QPoint(slide_out_x, 0))

        slide_in_x = self.main_stack.width() if index > current_index else -self.main_stack.width()
        next_widget.move(slide_in_x, 0)
        next_pos_anim = QPropertyAnimation(next_widget, b"pos")
        next_pos_anim.setDuration(animation_duration)
        next_pos_anim.setEasingCurve(easing_curve)
        next_pos_anim.setStartValue(QPoint(slide_in_x, 0))
        next_pos_anim.setEndValue(QPoint(0, 0))

        self.animation_group = QParallelAnimationGroup()
        self.animation_group.addAnimation(current_pos_anim)
        self.animation_group.addAnimation(next_pos_anim)

        self.animation_group.finished.connect(lambda: self.main_stack.setCurrentIndex(index))
        self.animation_group.start()

    def create_sidebar(self):
        sidebar_frame = QFrame()
        sidebar_frame.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar_frame)
        sidebar_layout.setContentsMargins(10, 20, 10, 20)
        sidebar_layout.setSpacing(15)

        logo_area = QHBoxLayout()
        icon_widget = HydraIconWidget()
        icon_widget.setFixedSize(30, 30)
        logo_label = QLabel("HYDRA")
        logo_label.setObjectName("logo")
        logo_area.addWidget(icon_widget)
        logo_area.addWidget(logo_label)
        sidebar_layout.addLayout(logo_area)
        sidebar_layout.addSpacing(20)

        nav_buttons = [
            "Status", "Update Definitions", "Generate Clean DB",
            "Analyze File", "Capture Analysis Logs", "Compare Logs",
            "Rootkit Scan", "Cleanup Environment", "About"
        ]
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        for i, name in enumerate(nav_buttons):
            button = QPushButton(name)
            button.setCheckable(True)
            button.setObjectName("nav_button")
            button.clicked.connect(lambda checked, index=i: self.switch_page_with_animation(index))
            sidebar_layout.addWidget(button)
            self.nav_group.addButton(button, i)

        self.nav_group.button(0).setChecked(True)
        sidebar_layout.addStretch()
        return sidebar_frame

    def create_main_content(self):
        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self.create_status_page())
        self.main_stack.addWidget(self.create_task_page("Update Definitions", "update_defs"))
        self.main_stack.addWidget(self.create_task_page("Generate Clean DB", "generate_clean_db"))
        self.main_stack.addWidget(self.create_analysis_page())
        self.main_stack.addWidget(self.create_task_page("Capture Analysis Logs", "capture_analysis_logs"))
        self.main_stack.addWidget(self.create_task_page("Compare Analysis Logs", "compare_logs"))
        self.main_stack.addWidget(self.create_task_page("Rootkit Scan", "rootkit_scan"))
        self.main_stack.addWidget(self.create_cleanup_page())
        self.main_stack.addWidget(self.create_about_page())
        return self.main_stack

    def create_status_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)

        main_area = QHBoxLayout()
        self.shield_widget = ShieldWidget()
        main_area.addWidget(self.shield_widget, 2)

        status_vbox = QVBoxLayout()
        status_vbox.addStretch()
        title = QLabel("System Status")
        title.setObjectName("page_title")
        self.status_text = QLabel("Ready for analysis!")
        self.status_text.setObjectName("page_subtitle")
        version_label = QLabel("HydraDragon Antivirus v0.1 (Beta 3)")
        version_label.setObjectName("version_label")
        defs_label = QLabel(get_latest_clamav_def_time())
        defs_label.setObjectName("version_label")

        status_vbox.addWidget(title)
        status_vbox.addWidget(self.status_text)
        status_vbox.addSpacing(20)
        status_vbox.addWidget(version_label)
        status_vbox.addWidget(defs_label)
        status_vbox.addStretch()
        main_area.addLayout(status_vbox, 3)

        layout.addLayout(main_area)
        self.log_outputs.append(None)
        return page

    def create_task_page(self, title_text, task_name):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        title = QLabel(title_text)
        title.setObjectName("page_title")
        layout.addWidget(title)
        button = QPushButton(f"Run {title_text}")
        button.setObjectName("action_button")
        button.clicked.connect(lambda: self.start_worker(task_name))
        layout.addWidget(button)
        log_output = QTextEdit(f"{title_text} logs will appear here...")
        log_output.setObjectName("log_output")
        layout.addWidget(log_output, 1)
        self.log_outputs.append(log_output)
        layout.addStretch()
        return page

    def create_analysis_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        title = QLabel("Deep File Analysis")
        title.setObjectName("page_title")
        layout.addWidget(title)
        warning_box = QGroupBox("Recommended Workflow")
        warning_layout = QVBoxLayout(warning_box)
        warning_text = QLabel(
            "<b>IMPORTANT:</b> Only run this application from a Virtual Machine.<br><br>"
            "<b>Recommended Workflow:</b><br>"
            "1. Update Virus Definitions<br>"
            "2. Generate Clean DB (Process Dump x64)<br>"
            "3. Capture Analysis Logs<br>"
            "4. Analyze a File<br>"
            "5. Stop Analysis<br>"
            "6. Capture and Compare Analysis Logs<br>"
            "7. Rootkit Scan<br>"
            "8. Cleanup Environment<br><br>"
            "<i>Return to a clean snapshot before starting a new analysis.</i>"
        )
        warning_text.setWordWrap(True)
        warning_text.setObjectName("warning_text")
        warning_layout.addWidget(warning_text)
        layout.addWidget(warning_box)
        button_layout = QHBoxLayout()
        analyze_btn = QPushButton("Analyze File...")
        analyze_btn.setObjectName("action_button")
        analyze_btn.clicked.connect(self.analyze_file)
        stop_btn = QPushButton("Stop Analysis")
        stop_btn.setObjectName("action_button_danger")
        stop_btn.clicked.connect(self.stop_analysis)
        button_layout.addWidget(analyze_btn)
        button_layout.addWidget(stop_btn)
        layout.addLayout(button_layout)
        log_output = QTextEdit("Analysis logs will appear here...")
        log_output.setObjectName("log_output")
        layout.addWidget(log_output, 1)
        self.log_outputs.append(log_output)
        return page

    def analyze_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to analyze", "", "All Files (*)")
        if file_path:
            self.start_worker("analyze_file", file_path)

    def stop_analysis(self):
        for worker in self.workers:
            if worker.isRunning():
                worker.stop_requested = True
        self.append_log_output("[!] Stop request sent to all running tasks.")

    def create_cleanup_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        title = QLabel("System Cleanup & Reset")
        title.setObjectName("page_title")
        layout.addWidget(title)
        cleanup_button = QPushButton("Perform Full Environment Cleanup")
        cleanup_button.setObjectName("action_button_danger")
        cleanup_button.clicked.connect(lambda: self.start_worker("cleanup_environment"))
        layout.addWidget(cleanup_button)
        log_output = QTextEdit("Cleanup process logs will appear here...")
        log_output.setObjectName("log_output")
        layout.addWidget(log_output, 1)
        self.log_outputs.append(log_output)
        layout.addStretch()
        return page

    def create_about_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        title = QLabel("About HydraDragon")
        title.setObjectName("page_title")
        layout.addWidget(title)
        about_text = QLabel(
            "HydraDragon Antivirus is a tool designed for malware analysis and system security research. "
            "It provides a sandboxed environment to safely analyze potential threats."
        )
        about_text.setWordWrap(True)
        layout.addWidget(about_text)
        github_button = QPushButton("View Project on GitHub")
        github_button.setObjectName("action_button")
        github_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus"))
        layout.addWidget(github_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()
        self.log_outputs.append(None)
        return page

    def setup_ui(self):
        # --- Set Window Icon ---
        # Determine the script directory robustly
        script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else os.getcwd()
        assets_dir = os.path.join(script_dir, "assets")

        # Set the window icon if the file exists
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            logging.warning(f"Icon file not found at: {icon_path}")

        self.setWindowTitle("HydraDragon Antivirus v0.1 (Beta 3)")
        self.setMinimumSize(1024, 768)
        self.resize(1200, 800)
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(self.create_sidebar())
        main_layout.addWidget(self.create_main_content(), 1)

    def apply_stylesheet(self):
        stylesheet = """
            QWidget {
                background-color: #2E3440;
                color: #D8DEE9;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 14px;
            }
            QTextEdit {
                background-color: #3B4252;
                border: 1px solid #4C566A;
                border-radius: 5px;
                padding: 8px;
                color: #ECEFF4;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            #sidebar {
                background-color: #3B4252;
                max-width: 220px;
            }
            #logo {
                color: #88C0D0;
                font-size: 28px;
                font-weight: bold;
            }
            #nav_button {
                background-color: transparent;
                border: none;
                color: #ECEFF4;
                padding: 12px;
                text-align: left;
                border-radius: 5px;
            }
            #nav_button:hover {
                background-color: #434C5E;
            }
            #nav_button:checked {
                background-color: #88C0D0;
                color: #2E3440;
                font-weight: bold;
            }
            #page_title {
                font-size: 28px;
                font-weight: 300;
                color: #ECEFF4;
                padding-bottom: 15px;
            }
            #page_subtitle {
                font-size: 16px;
                color: #A3BE8C;
            }
            #version_label {
                font-size: 13px;
                color: #81A1C1;
            }
            #action_button {
                background-color: #5E81AC;
                color: #ECEFF4;
                border-radius: 8px;
                padding: 12px 20px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                max-width: 300px;
            }
            #action_button:hover {
                background-color: #81A1C1;
            }
            #action_button_danger {
                background-color: #BF616A;
                color: #ECEFF4;
                border-radius: 8px;
                padding: 12px 20px;
                font-size: 14px;
                font-weight: bold;
                border: none;
            }
            #action_button_danger:hover {
                background-color: #d08770;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #4C566A;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
            }
            #warning_text {
                font-size: 13px;
                line-height: 1.5;
            }
        """
        self.setStyleSheet(stylesheet)

# --- Worker Thread for Background Tasks ---
class Worker(QThread):
    """
    Handles long-running tasks in the background to prevent the UI from freezing.
    """
    output_signal = Signal(str)

    def __init__(self, task_type, *args):
        super().__init__()
        self.task_type = task_type
        self.args = args
        self.stop_requested = False

    def generate_clean_db(self):
        success = run_pd64_db_gen()
        msg = "[+] clean.hashes generated." if success else "[!] Failed to generate clean.hashes."
        self.output_signal.emit(msg)

    def capture_analysis_logs(self):
        global pre_analysis_log_path, post_analysis_log_path, pre_analysis_entries, post_analysis_entries
        if pre_analysis_log_path is None:
            path = run_and_copy_log(label="pre")
            pre_analysis_log_path = path
            pre_analysis_entries = parse_report(path)
            self.output_signal.emit(f"[+] Pre-analysis log captured: {os.path.basename(path)}")
        elif post_analysis_log_path is None:
            path = run_and_copy_log(label="post")
            post_analysis_log_path = path
            post_analysis_entries = parse_report(path)
            self.output_signal.emit(f"[+] Post-analysis log captured: {os.path.basename(path)}")
        else:
            self.output_signal.emit("[!] Both pre and post-analysis captures have already been completed.")

    def compare_analysis_logs(self):
        if not pre_analysis_log_path or not post_analysis_log_path:
            self.output_signal.emit("[!] Please capture both pre and post-analysis logs first!")
            return
        try:
            with open(pre_analysis_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                pre_lines = f.readlines()
            with open(post_analysis_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                post_lines = f.readlines()

            diff = difflib.ndiff(pre_lines, post_lines)
            filtered_diff = [line for line in diff if line.startswith(('+', '-'))]

            diff_file_path = os.path.join(log_directory, 'HiJackThis_diff.log')
            with open(diff_file_path, 'w', encoding='utf-8') as df:
                df.writelines(filtered_diff)
            self.output_signal.emit(f"[+] Diff log created at: {diff_file_path}")

            llama_response = scan_file_with_meta_llama(diff_file_path, HiJackThis_flag=True)
            self.output_signal.emit("\n[*] Llama analysis of the diff log:")
            self.output_signal.emit(llama_response)

        except Exception as e:
            self.output_signal.emit(f"[!] Error comparing logs: {str(e)}")

    def update_definitions(self):
        try:
            self.output_signal.emit("[*] Checking virus definitions...")
            updated = False
            # Check if freshclam exists before trying to run it
            if not os.path.exists(freshclam_path):
                 self.output_signal.emit(f"[!] Error: freshclam not found at '{freshclam_path}'. Please check the path.")
                 return

            for file_path in clamav_file_paths:
                if os.path.exists(file_path):
                    file_mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if (datetime.now() - file_mod_time) > timedelta(hours=6):
                        updated = True
                        break
                else: # If a definition file doesn't exist, we should update.
                    updated = True
                    break

            if updated:
                self.output_signal.emit("[*] Definitions are outdated or missing. Starting update...")
                # Using subprocess.run for simplicity. For real-time output, Popen is better.
                result = subprocess.run([freshclam_path], capture_output=True, text=True, encoding="utf-8", errors="ignore")
                if result.returncode == 0:
                    restart_clamd_thread()
                    self.output_signal.emit("[+] Virus definitions updated successfully and ClamAV restarted.")
                    self.output_signal.emit(f"Output:\n{result.stdout}")
                else:
                    self.output_signal.emit(f"[!] Failed to update definitions. Error:\n{result.stderr}")
            else:
                self.output_signal.emit("[*] Definitions are already up-to-date.")
        except Exception as e:
            self.output_signal.emit(f"[!] Error updating definitions: {str(e)}")

    def analyze_file(self, file_path):
        if self.stop_requested:
            self.output_signal.emit("[!] Analysis stopped by user request")
            return

        self.output_signal.emit(f"[*] Starting analysis for: {file_path}")

        # Create a stop callback function
        def check_stop():
            return self.stop_requested

        try:
            # Call the modified run_analysis function with stop callback
            analysis_result = run_analysis(file_path, stop_callback=check_stop)

            if self.stop_requested:
                self.output_signal.emit("[!] Analysis was stopped by user")
                return

            self.output_signal.emit(analysis_result)

        except Exception as e:
            if self.stop_requested:
                self.output_signal.emit("[!] Analysis stopped by user request")
            else:
                self.output_signal.emit(f"[!] Error during analysis: {str(e)}")

    def perform_rootkit_scan(self):
        """
        Runs the rootkit scan script and displays the report.
        """
        try:
            self.output_signal.emit("[*] Starting Rootkit Scan via Sandboxie Plugin...")
            run_sandboxie_plugin_script()  # This creates the report file

            # Get the path to the generated report
            sandbox_scan_report_path = get_sandbox_path(scan_report_path)
            self.output_signal.emit(f"[+] Rootkit scan finished. Report located at: {sandbox_scan_report_path}")

            if os.path.exists(sandbox_scan_report_path):
                with open(sandbox_scan_report_path, 'r', encoding='utf-8') as f:
                    report_content = f.read()
                self.output_signal.emit("\n--- Rootkit Scan Report ---")
                self.output_signal.emit(report_content)
                self.output_signal.emit("--- End of Report ---")
            else:
                self.output_signal.emit("[!] Error: Sandboxie report file was not found after the scan.")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during rootkit scan: {str(e)}")

    def full_cleanup_sandbox(self):
        """
        Fully cleans up the Sandboxie environment by terminating and deleting the DefaultBox sandbox.
        """
        try:
            self.output_signal.emit("[*] Starting full sandbox cleanup using Start.exe termination commands...")
            cmds = [
                [sandboxie_path, "/terminate"],
                [sandboxie_path, "/box:DefaultBox", "/terminate"],
                [sandboxie_path, "/terminate_all"],
            ]
            for cmd in cmds:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    self.output_signal.emit(f"[!] Command {' '.join(cmd)} failed: {result.stderr.strip()}")
                else:
                    self.output_signal.emit(f"[+] Command {' '.join(cmd)} successful.")
                time.sleep(1)

            # Delete (cleanup) the DefaultBox sandbox
            cleanup_cmd = [sandboxie_path, "delete_sandbox"]
            result = subprocess.run(cleanup_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.output_signal.emit(f"[!] Sandbox delete command failed: {result.stderr.strip()}")
            else:
                self.output_signal.emit("[+] Sandbox 'DefaultBox' deleted successfully.")

        except Exception as ex:
            self.output_signal.emit(f"[!] Full sandbox cleanup encountered an exception: {ex}")

    def cleanup_directories(self):
        """
        Removes all the managed directories and their contents.
        """
        cleaned_count = 0
        for directory in  MANAGED_DIRECTORIES:
            try:
                if os.path.exists(directory):
                    shutil.rmtree(directory)
                    self.output_signal.emit(f"[+] Cleaned directory: {directory}")
                    cleaned_count += 1
            except Exception as e:
                self.output_signal.emit(f"[!] Error cleaning directory {directory}: {str(e)}")

        self.output_signal.emit(f"[+] Total directories cleaned: {cleaned_count}")

    def stop_snort(self):
        """
        Stops Snort processes and cleans up log files.
        """
        try:
            # Kill all snort processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if 'snort' in proc.info['name'].lower():
                        proc.terminate()
                        proc.wait(timeout=5)
                        self.output_signal.emit(f"[+] Terminated Snort process (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    pass

            # Clean up log folder
            if os.path.exists(log_folder):
                os.remove(log_folder)
                self.output_signal.emit(f"[+] Removed Snort log file: {log_folder}")

        except Exception as e:
            self.output_signal.emit(f"[!] Error stopping Snort: {str(e)}")

    def restart_services(self):
        """
        Restarts ClamAV and Snort services.
        """
        try:
            # Restart ClamAV
            self.output_signal.emit("[*] Restarting ClamAV daemon...")
            restart_clamd_thread()
            self.output_signal.emit("[+] ClamAV daemon restarted.")

            # Restart Snort
            self.output_signal.emit("[*] Starting Snort...")
            threading.Thread(target=run_snort).start()
            self.output_signal.emit("[+] Snort started.")

        except Exception as e:
            self.output_signal.emit(f"[!] Error restarting services: {str(e)}")

    def recreate_directories(self):
        """
        Recreates all the managed directories after cleanup.
        """
        created_count = 0
        for directory in MANAGED_DIRECTORIES:
            try:
                # Skip log_directory as it shouldn't be recreated in the normal workflow
                if directory == log_directory:
                    continue

                os.makedirs(directory, exist_ok=True)
                created_count += 1
            except Exception as e:
                self.output_signal.emit(f"[!] Error creating directory {directory}: {str(e)}")

        self.output_signal.emit(f"[+] Total directories recreated: {created_count}")

    def perform_cleanup(self):
        """
        Performs comprehensive cleanup of the environment.
        """
        try:
            global pre_analysis_log_path, post_analysis_log_path, pre_analysis_entries, post_analysis_entries

            self.output_signal.emit("[*] Starting comprehensive environment cleanup...")

            # Step 1: Stop Snort and cleanup logs
            self.output_signal.emit("[*] Step 1: Stopping Snort and cleaning logs...")
            self.stop_snort()
            self.stop_snort()

            # Step 2: Cleanup Sandboxie
            self.output_signal.emit("[*] Step 2: Cleaning up Sandboxie environment...")
            self.full_cleanup_sandbox()
            self.full_cleanup_sandbox()

            # Step 3: Clean up directories
            self.output_signal.emit("[*] Step 3: Cleaning up generated directories...")
            self.cleanup_directories()
            self.cleanup_directories()

            # Step 4: Reset global variables
            self.output_signal.emit("[*] Step 4: Resetting analysis state...")
            pre_analysis_log_path = None
            post_analysis_log_path = None
            pre_analysis_entries = None
            post_analysis_entries = None
            reset_flags()

            # Step 5: Restart services
            self.output_signal.emit("[*] Step 5: Restarting services...")
            self.restart_services()

            # Step 6: Recreate directories
            self.output_signal.emit("[*] Step 6: Recreating clean directories...")
            self.recreate_directories()

            self.output_signal.emit("[+] Environment cleanup completed successfully!")
            self.output_signal.emit("[+] System is ready for new analysis.")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during cleanup: {str(e)}")

    def run(self):
        """The entry point for the thread."""
        try:
            if self.task_type == "capture_analysis_logs":
                self.capture_analysis_logs()
            elif self.task_type == "compare_analysis_logs":
                self.compare_analysis_logs()
            elif self.task_type == "update_defs":
                self.update_definitions()
            elif self.task_type == "generate_clean_db":
                self.generate_clean_db()
            elif self.task_type == "analyze_file":
                self.analyze_file(*self.args)
            elif self.task_type == "rootkit_scan":
                self.perform_rootkit_scan()
            elif self.task_type == "cleanup_environment":
                self.perform_cleanup()
            else:
                self.output_signal.emit(f"[!] Unknown task type: {self.task_type}")
        except Exception as e:
            if not self.stop_requested:
                self.output_signal.emit(f"[!] Worker thread error: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = AntivirusApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
