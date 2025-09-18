#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from datetime import datetime, timedelta
import time

main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)
sys.path.insert(0, main_dir)

from hydra_logger import application_log_file, log_directory, script_dir, logger, reinitialize_hydra_logger

# Separate log files for different purposes
stdout_console_log_file = os.path.join(
    log_directory, "antivirusconsolestdout.log"
)
stderr_console_log_file = os.path.join(
    log_directory, "antivirusconsolestderr.log"
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
logger.info(
    "Application started at %s",
    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
)

# Start timing total duration
total_start_time = time.time()

start_time = time.time()
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QLabel, QTextEdit,
                               QFrame, QStackedWidget, QLineEdit,
                               QApplication, QButtonGroup, QGroupBox, QFileDialog)
logger.info(f"PySide6.QtWidgets modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtCore import (Qt, QPropertyAnimation, QEasingCurve, QThread,
                            Signal, QPoint, QParallelAnimationGroup, Property, QRect)
logger.info(f"PySide6.QtCore modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtGui import (QColor, QPainter, QBrush, QLinearGradient, QPen,
                           QPainterPath, QRadialGradient, QIcon, QPixmap)
logger.info(f"PySide6.QtGui.QIcon module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import clamav
logger.info(f"clamav imported in {time.time() - start_time:.6f} seconds")

# Measure and logger.info time taken for each import
start_time = time.time()
import hashlib
logger.info(f"hashlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import io
logger.info(f"io module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import webbrowser
logger.info(f"webbrowser module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from uuid import uuid4 as uniquename
logger.info(f"uuid.uuid4.uniquename loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import shutil
logger.info(f"shutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import subprocess
logger.info(f"subprocess module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import threading
logger.info(f"threading module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from concurrent.futures import ThreadPoolExecutor
logger.info(f"concurrent.futures.ThreadPoolExecutor module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import re
logger.info(f"re module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import json
logger.info(f"json module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pefile
logger.info(f"pefile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import traceback
logger.info(f"traceback module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pyzipper
logger.info(f"pyzipper module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import tarfile
logger.info(f"tarfile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara
logger.info(f"yara module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara_x
logger.info(f"yara_x module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import psutil
logger.info(f"psutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from notifypy import Notify
logger.info(f"notifypy.Notify module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from watchdog.observers import Observer
logger.info(f"watchdog.observers.Observer module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from watchdog.events import FileSystemEventHandler
logger.info(f"watchdog.events.FileSystemEventHandler module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32file
logger.info(f"win32file module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32con
logger.info(f"win32con module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32service
logger.info(f"win32service module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32serviceutil
logger.info(f"win32serviceutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import wmi
logger.info(f"wmi module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import numpy as np
logger.info(f"numpy module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sniff

logger.info(f"scapy modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import comtypes
logger.info(f"comtypes modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import comtypes.client
logger.info(f"comtypes.client modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from comtypes import cast, GUID
logger.info(f"comtypes.cast, GUID modules loaded in {time.time() - start_time:.6f} seconds")

from comtypes.automation import POINTER
logger.info(f"comtypes.automation.POINTER module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from comtypes.client import CreateObject
logger.info(f"comtypes.client.CreateObject module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import atexit
logger.info(f"atexit module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ast
logger.info(f"ast module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ctypes
logger.info(f"ctypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from ctypes import wintypes
logger.info(f"ctypes.wintypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32gui
logger.info(f"win32gui module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ipaddress
logger.info(f"ipaddress module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from urllib.parse import urlparse
logger.info(f"urllib.parse.urlparse module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import spacy
logger.info(f"spacy module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import csv
logger.info(f"csv module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import struct
logger.info(f"struct module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import lzma
logger.info(f"lzma module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from importlib.util import MAGIC_NUMBER
logger.info(f"importlib.util.MAGIC_NUMBER module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import string
logger.info(f"string module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import chardet
logger.info(f"chardet module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import difflib
logger.info(f"difflib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zlib
logger.info(f"zlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import marshal
logger.info(f"marshal module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import base64
logger.info(f"base64 module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import base32_crockford
logger.info(f"base32_crockford module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import binascii
logger.info(f"binascii module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from accelerate import Accelerator
logger.info(f"accelerate.Accelerator module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import py7zr
logger.info(f"py7zr module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import inspect
logger.info(f"inspect module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zstandard
logger.info(f"zstandard module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from elftools.elf.elffile import ELFFile
logger.info(f"elftools.elf.elffile, ELFFile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from elftools.common.exceptions import ELFError
logger.info(f"elftools.common.exceptions, ELFFError module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.MachO
logger.info(f"macholib.MachO module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.mach_o
logger.info(f"macholib.mach_o module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from dataclasses import dataclass
logger.info(f"dataclasses module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from typing import Optional, Tuple, BinaryIO, Dict, Any, List, Set, Union, Callable
logger.info(f"typing, Optional, Tuple, BinaryIO, Dict, Any, List, Set and Union, Callable module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from androguard.misc import AnalyzeAPK
logger.info(f"androguard.core.misc.AnalyzeAPK module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import types
logger.info(f"types module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
logger.info(f"cryptography.hazmat.primitives.ciphers, Cipher, algorithms, modes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import debloat.processor
logger.info(f"debloat modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from Crypto.Cipher import AES
logger.info(f"Crpyto.Cipher.AES module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from Crypto.Util import Counter
logger.info(f"Crpyto.Cipher.Counter module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from pathlib import Path, WindowsPath
logger.info(f"pathlib.Path module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import requests
logger.info(f"requests module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from functools import wraps
logger.info(f"functoools.wraps module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from xdis.unmarshal import load_code
logger.info(f"xdis.unmarshal.load_code module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import capstone
logger.info(f"capstone imported in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import nltk
logger.info(f"nltk imported in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from nltk.corpus import words
logger.info(f"nltk.corpus.words imported in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from nltk.tokenize import word_tokenize
logger.info(f"nltk.tokenize.word_tokenize imported in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from GoStringUngarbler.gostringungarbler_lib import process_file_go
logger.info(f"GoStringUngarbler.gostringungarbler_lib.process_file_go module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from View8.view8 import disassemble, decompile, export_to_file
logger.info(f"view8.view8, disassemble, decompile, export_to_file modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from pylingual.main import main as pylingual_main
logger.info(f"pylingual.main.main module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from unipacker.core import Sample, UnpackerEngine, SimpleClient
logger.info(f"unipacker.core.Sample , UnpackerEngine, SimpleClient modules loaded in {time.time() - start_time:.6f} seconds")

# Calculate and logger.info total time
total_end_time = time.time()
total_duration = total_end_time - total_start_time
logger.info(f"Total time for all imports: {total_duration:.6f} seconds")

# Load the spaCy model globally
nlp_spacy_lang = spacy.load("en_core_web_md")
logger.info("spaCy model 'en_core_web_md' loaded successfully")

try:
    nltk.data.find('tokenizers/punkt')
except Exception:
    logger.info("NLTK 'punkt' resource not found. Downloading...")
    nltk.download('punkt', quiet=True)

try:
    nltk.data.find('corpora/words')
except Exception:
    logger.info("NLTK 'words' resource not found. Downloading...")
    nltk.download('words', quiet=True)

# Create a set of English words for efficient lookup.
ENGLISH_WORDS = set(words.words())

# Precompute English words set and dynamic maximum length for words containing 'u'.
# This runs once at import time for performance.
try:
    english_words_set = set(w.lower() for w in ENGLISH_WORDS)
    u_word_lengths = [len(w) for w in english_words_set if 'u' in w]
    if u_word_lengths:
        max_u_len = max(u_word_lengths)
    else:
        # fallback to longest word length in the set, or 30 if set is empty
        max_u_len = max((len(w) for w in english_words_set), default=30)
except Exception as e:
    logger.warning(f"Failed to prepare english words set: {e}")
    english_words_set = set(w.lower() for w in (ENGLISH_WORDS or []))
    max_u_len = 30

# Initialize the accelerator and device
accelerator = Accelerator()
device = accelerator.device

# get the full path to the currently running Python interpreter
python_path = sys.executable

# Define the paths
unlicense_path  = os.path.join(script_dir, "unlicense.exe")
unlicense_x64_path  = os.path.join(script_dir, "unlicense-x64.exe")
capa_rules_dir = os.path.join(script_dir, "capa-rules-9.2.1")
capa_results_dir = os.path.join(script_dir, "capa_results")
hayabusa_dir = os.path.join(script_dir, "hayabusa")
webcrack_javascript_deobfuscated_dir = os.path.join(script_dir, "webcrack_javascript_deobfuscated")
pkg_unpacker_dir = os.path.join(script_dir, "pkg-unpacker")
hayabusa_path = os.path.join(hayabusa_dir, "hayabusa-3.3.0-win-x64.exe")
av_events_json_file_path = os.path.join(script_dir, "av_events.json")
reports_dir = os.path.join(script_dir, "reports")
network_indicators_path = os.path.join(reports_dir, "network_indicators_for_av.json")
scan_report_path = os.path.join(reports_dir, "scan_report.json")
enigma_extracted_dir = os.path.join(script_dir, "enigma_extracted")
inno_unpack_dir = os.path.join(script_dir, "innounp-2")
upx_dir = os.path.join(script_dir, "upx-5.0.1-win64")
upx_path = os.path.join(upx_dir, "upx.exe")
upx_extracted_dir = os.path.join(script_dir, "upx_extracted_dir")
inno_unpack_path = os.path.join(inno_unpack_dir, "innounp.exe")
inno_setup_unpacked_dir = os.path.join(script_dir, "inno_setup_unpacked")
themida_unpacked_dir = os.path.join(script_dir, "themida_unpacked")
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
androguard_dir = os.path.join(script_dir, "androguard")
decompiled_jsc_dir = os.path.join(script_dir, "decompiled_jsc")
npm_pkg_extracted_dir = os.path.join(script_dir, "npm_pkg_extracted")
asar_dir = os.path.join(script_dir, "asar")
un_confuser_ex_dir = os.path.join(script_dir, "UnConfuserEx")
un_confuser_ex_path = os.path.join(un_confuser_ex_dir, "UnConfuserEx.exe")
un_confuser_ex_extracted_dir = os.path.join(script_dir, "UnConfuserEx_extracted")
net_reactor_slayer_dir = os.path.join(script_dir, "NETReactorSlayer-windows")
net_reactor_slayer_x64_cli_path  = os.path.join(net_reactor_slayer_dir, "NETReactorSlayer-x64.CLI.exe")
nuitka_dir = os.path.join(script_dir, "nuitka")
known_extensions_dir = os.path.join(script_dir, "known_extensions")
FernFlower_path = os.path.join(jar_decompiler_dir, "fernflower.jar")
system_file_names_path = os.path.join(known_extensions_dir, "system_filenames.txt")
extensions_path = os.path.join(known_extensions_dir, "extensions.txt")
antivirus_process_list_path = os.path.join(known_extensions_dir, "antivirus_process_list.txt")
magic_bytes_path = os.path.join(known_extensions_dir, "magic_bytes.txt")
meta_llama_dir = os.path.join(script_dir, "meta_llama")
vmprotect_unpacked_dir = os.path.join(script_dir, "vmprotect_unpacked")
meta_llama_1b_dir = os.path.join(meta_llama_dir, "Llama-3.2-1B")
python_source_code_dir = os.path.join(script_dir, "python_sourcecode")
python_deobfuscated_dir = os.path.join(script_dir, "python_deobfuscated")
python_deobfuscated_marshal_pyc_dir = os.path.join(python_deobfuscated_dir, "python_deobfuscated_marshal_pyc")
pylingual_extracted_dir = os.path.join(python_source_code_dir, "pylingual_extracted")
pycdas_extracted_dir = os.path.join(python_source_code_dir, "pycdas_extracted")
de4dot_cex_dir = os.path.join(script_dir, "de4dot-cex")
de4dot_cex_x64_path = os.path.join(de4dot_cex_dir, "de4dot-x64.exe")
net_reactor_extracted_dir = os.path.join(script_dir, "net_reactor_extracted")
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
detectiteasy_db_dir = os.path.join(detectiteasy_dir, "db")
detectiteasy_plain_text_dir = os.path.join(script_dir, "detectiteasy_plain_text")
memory_dir = os.path.join(script_dir, "memory")
debloat_dir = os.path.join(script_dir, "debloat")
copied_sandbox_and_main_files_dir = os.path.join(script_dir, "copied_sandbox_and_main_files")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
ilspycmd_path = os.path.join(script_dir, "ilspycmd.exe")
pycdas_path = os.path.join(script_dir, "pycdas.exe")
ISx_installshield_extractor_path = os.path.join(script_dir, "ISx.exe")
installshield_extracted_dir = os.path.join(script_dir, "installshield_extracted")
autoit_extracted_dir = os.path.join(script_dir, "autoit_extracted")
pd64_path = os.path.join(script_dir, "pd64.exe")
pd64_extracted_dir = os.path.join(script_dir, "pd64_extracted")
deobfuscar_path = os.path.join(script_dir, "Deobfuscar-Standalone-Win64.exe")
digital_signatures_list_antivirus_path = os.path.join(digital_signatures_list_dir, "antivirus.txt")
digital_signatures_list_goodsign_path = os.path.join(digital_signatures_list_dir, "goodsign.txt")
machine_learning_dir = os.path.join(script_dir, "machine_learning")
machine_learning_results_json = os.path.join(machine_learning_dir, "results.json")
resource_extractor_dir = os.path.join(script_dir, "resources_extracted")
ungarbler_dir = os.path.join(script_dir, "ungarbler")
ungarbler_string_dir = os.path.join(script_dir, "ungarbler_string")
yara_dir = os.path.join(script_dir, "yara")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")
html_extracted_dir = os.path.join(script_dir, "html_extracted")
website_rules_dir = os.path.join(script_dir, "website")
# Email last 365 days
spam_email_365_path = os.path.join(website_rules_dir, "listed_email_365.txt")
# Define all website file paths
ipv4_addresses_path = os.path.join(website_rules_dir, "IPv4Malware.csv")
ipv4_addresses_spam_path = os.path.join(website_rules_dir, "IPv4Spam.csv")
ipv4_addresses_bruteforce_path = os.path.join(website_rules_dir, "IPv4BruteForce.csv")
ipv4_addresses_phishing_active_path = os.path.join(website_rules_dir, "IPv4PhishingActive.csv")
ipv4_addresses_phishing_inactive_path = os.path.join(website_rules_dir, "IPv4PhishingInActive.csv")
ipv4_whitelist_path = os.path.join(website_rules_dir, "WhitelistIPv4.csv")
ipv6_addresses_path = os.path.join(website_rules_dir, "IPv6Malware.csv")
ipv6_addresses_spam_path = os.path.join(website_rules_dir, "IPv6Spam.csv")
ipv4_addresses_ddos_path = os.path.join(website_rules_dir, "IPv4DDoS.csv")
ipv6_addresses_ddos_path = os.path.join(website_rules_dir, "IPv6DDoS.csv")
ipv6_whitelist_path = os.path.join(website_rules_dir, "WhiteListIPv6.csv")
malware_domains_path = os.path.join(website_rules_dir, "MalwareDomains.csv")
malware_domains_mail_path = os.path.join(website_rules_dir, "MaliciousMailDomains.csv")
phishing_domains_path = os.path.join(website_rules_dir, "PhishingDomains.csv")
abuse_domains_path = os.path.join(website_rules_dir, "AbuseDomains.csv")
mining_domains_path = os.path.join(website_rules_dir, "MiningDomains.csv")
spam_domains_path = os.path.join(website_rules_dir, "SpamDomains.csv")
whitelist_domains_path = os.path.join(website_rules_dir, "WhiteListDomains.csv")
whitelist_domains_mail_path = os.path.join(website_rules_dir, "BenignMailDomains.csv")
# Define corresponding subdomain files
malware_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomains.csv")
malware_mail_sub_domains_path = os.path.join(website_rules_dir, "MaliciousMailSubDomains.csv")
phishing_sub_domains_path = os.path.join(website_rules_dir, "PhishingSubDomains.csv")
abuse_sub_domains_path = os.path.join(website_rules_dir, "AbuseSubDomains.csv")
mining_sub_domains_path = os.path.join(website_rules_dir, "MiningSubDomains.csv")
spam_sub_domains_path = os.path.join(website_rules_dir, "SpamSubDomains.csv")
whitelist_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomains.csv")
whitelist_mail_sub_domains_path = os.path.join(website_rules_dir, "BenignMailSubDomains.csv")
urlhaus_path = os.path.join(website_rules_dir, "urlhaus.txt")
antivirus_list_path = os.path.join(script_dir, "hosts", "antivirus_list.txt")
yaraxtr_yrc_path = os.path.join(yara_dir, "yaraxtr.yrc")
clean_rules_path = os.path.join(yara_dir, "clean_rules.yrc")
yarGen_rule_path = os.path.join(yara_dir, "machine_learning.yrc")
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

APP_NAME = "HydraDragon Antivirus"
APP_VERSION = "v0.1 (Beta 5)"
WINDOW_TITLE = f"{APP_NAME} {APP_VERSION}"

# Resolve system drive path
system_drive = os.getenv("SystemDrive", "C:") + os.sep
# Resolve Program Files directory via environment (fallback to standard path)
program_files = os.getenv("ProgramFiles", os.path.join(system_drive, "Program Files"))
# Get SystemRoot (usually C:\Windows)
system_root = os.getenv("SystemRoot", os.path.join(system_drive, "Windows"))
# Fallback to %SystemRoot%\System32 if %System32% is not set
system32_dir = os.getenv("System32", os.path.join(system_root, "System32"))

# Windows event logs
evtx_logs_path = os.path.join(system32_dir, "winevt\\Logs")

# PE file format constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
LZMA_PROPERTIES_SIZE = 5  # Standard LZMA properties size

@dataclass
class PACKER_INFO:
    """Python implementation corresponding to C++ struct"""
    Src: int  # uint32
    Dst: int  # uint32

def to_hex_string(val, prefix=True):
    """Convert value to hexadecimal string for better error message display"""
    return f"0x{val:x}" if prefix else f"{val:x}"

def find_pattern(data: bytes, pattern: bytes) -> Optional[int]:
    """
    Find pattern in data, supporting 0xFF as wildcard
    Returns position where found, or None if not found
    """
    if not pattern or len(data) < len(pattern):
        return None

    for i in range(len(data) - len(pattern) + 1):
        match = True
        for j in range(len(pattern)):
            if pattern[j] != 0xFF and data[i + j] != pattern[j]:
                match = False
                break
        if match:
            return i
    return None

def unpack_pe(packed_pe_data: bytes) -> bytes:
    """
    Unpack a VMProtect protected PE file
    """
    if not packed_pe_data:
        raise RuntimeError("Packed PE data is null or empty.")

    try:
        pe = pefile.PE(data=packed_pe_data)
    except pefile.PEFormatError as e:
        raise RuntimeError(f"Invalid PE file format: {str(e)}")

    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders

    unpacked_image = bytearray(size_of_image)
    unpacked_image[:size_of_headers] = packed_pe_data[:size_of_headers]

    rva_patterns_array = []
    for section in pe.sections:
        condition1 = (section.SizeOfRawData == 0)
        condition2 = (section.PointerToRawData == 0)
        condition3 = not (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

        if condition1 and condition2 and condition3:
            pattern_value = ((section.VirtualAddress << 32) | 0xFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
            pattern_bytes = struct.pack("<Q", pattern_value)
            rva_patterns_array.append(pattern_bytes)

    packer_info_array = []
    num_packer_entries = 0

    if rva_patterns_array:
        pattern_bytes = b''.join(rva_patterns_array)
        pattern_pos = find_pattern(packed_pe_data, pattern_bytes)

        if pattern_pos is not None:
            if pattern_pos < 8:
                raise RuntimeError("Located RVA pattern is too close to the beginning of the file to precede PACKER_INFO[0].")

            packer_info_offset = pattern_pos - 8
            num_packer_entries = len(rva_patterns_array)

            if num_packer_entries > 0:
                end_of_packer_info_array = packer_info_offset + (num_packer_entries + 1) * 8
                if end_of_packer_info_array > len(packed_pe_data) or packer_info_offset < 0:
                    raise RuntimeError("Located PACKER_INFO array extends beyond packed PE buffer or has invalid start.")

            for j in range(num_packer_entries + 1):
                info_offset = packer_info_offset + j * 8
                src = struct.unpack("<I", packed_pe_data[info_offset:info_offset+4])[0]
                dst = struct.unpack("<I", packed_pe_data[info_offset+4:info_offset+8])[0]
                packer_info_array.append(PACKER_INFO(src, dst))
        else:
            raise RuntimeError("RVA pattern sequence for PACKER_INFO not found in packed PE, but patterns were expected.")
    else:
        logger.info("RVA pattern array is empty. No PACKER_INFO entries to process for LZMA.")

    for i, section in enumerate(pe.sections):
        virtual_address = section.VirtualAddress
        virtual_size = section.Misc_VirtualSize
        size_of_raw_data = section.SizeOfRawData
        pointer_to_raw_data = section.PointerToRawData
        section_name = section.Name.decode('ascii', errors='ignore').strip('\0')

        if pointer_to_raw_data != 0 and size_of_raw_data > 0:
            if pointer_to_raw_data + size_of_raw_data <= len(packed_pe_data) and virtual_address + size_of_raw_data <= size_of_image:
                section_data = packed_pe_data[pointer_to_raw_data:pointer_to_raw_data+size_of_raw_data]
                unpacked_image[virtual_address:virtual_address+len(section_data)] = section_data
            else:
                logger.error(f"Section {section_name} data exceeds boundaries. RawOffset={to_hex_string(pointer_to_raw_data)}, "
                              f"RawSize={to_hex_string(size_of_raw_data)}, VA={to_hex_string(virtual_address)}. Skipping copy.")

        section_offset = pe.OPTIONAL_HEADER.get_file_offset() + pe.FILE_HEADER.SizeOfOptionalHeader + i * 40
        unpacked_section_offset = section_offset

        struct.pack_into("<I", unpacked_image, unpacked_section_offset+20, virtual_address)
        if virtual_size > 0:
            struct.pack_into("<I", unpacked_image, unpacked_section_offset+16, virtual_size)

    if packer_info_array and len(packer_info_array) > 1:
        props_info = packer_info_array[0]
        props_raw_offset = pe.get_offset_from_rva(props_info.Src)

        lzma_props_size = props_info.Dst
        lzma_props_data = packed_pe_data[props_raw_offset:props_raw_offset+lzma_props_size]

        if props_raw_offset + lzma_props_size > len(packed_pe_data):
            raise RuntimeError("LZMA properties data extends beyond packed PE size.")

        if lzma_props_size != LZMA_PROPERTIES_SIZE:
            logger.error(f"PACKER_INFO[0].Dst (LZMA properties size) is {lzma_props_size}. Standard is {LZMA_PROPERTIES_SIZE}. Using provided size.")

        try:
            for block_idx in range(1, len(packer_info_array)):
                current_block_info = packer_info_array[block_idx]
                compressed_data_rva = current_block_info.Src
                uncompressed_target_rva = current_block_info.Dst

                try:
                    compressed_block_raw_offset = pe.get_offset_from_rva(compressed_data_rva)
                except Exception as e:
                    raise RuntimeError(f"Block {block_idx}: Cannot convert RVA to file offset: {str(e)}")

                compressed_data = packed_pe_data[compressed_block_raw_offset:]

                if uncompressed_target_rva >= size_of_image:
                    raise RuntimeError(f"Block {block_idx}: PACKER_INFO.Dst (decompression target RVA {to_hex_string(uncompressed_target_rva)}) exceeds image boundary.")

                lc = lzma_props_data[0] % 9
                lp = (lzma_props_data[0] // 9) % 5
                pb = lzma_props_data[0] // 45
                dict_size = int.from_bytes(lzma_props_data[1:5], byteorder='little')

                filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]

                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)

                try:
                    decompressed_data = decompressor.decompress(compressed_data)
                    available_space = size_of_image - uncompressed_target_rva
                    if len(decompressed_data) <= available_space:
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+len(decompressed_data)] = decompressed_data
                    else:
                        logger.error(f"Block {block_idx}: Decompressed data size exceeds available space in image")
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+available_space] = decompressed_data[:available_space]

                    logger.info(f"Block {block_idx}: Decompressed. Output size={len(decompressed_data)}")
                except lzma.LZMAError as e:
                    raise RuntimeError(f"LZMA decompression error: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error processing LZMA data: {str(e)}")

    return bytes(unpacked_image)

def service_exists(service_name):
   """Check if a Windows service exists."""
   try:
       win32serviceutil.QueryServiceStatus(service_name)
       return True
   except win32service.error:
       return False

def is_service_running(service_name):
   """Check if a Windows service is running."""
   try:
       status = win32serviceutil.QueryServiceStatus(service_name)[1]
       return status == win32service.SERVICE_RUNNING
   except win32service.error:
       return False

# Regex for Suricata EVE JSON alerts (assuming EVE JSON format)
# This will parse the JSON structure instead of text-based alerts
def parse_suricata_alert(json_line):
    """Parse Suricata EVE JSON alert format"""
    try:
        alert_data = json.loads(json_line)
        if alert_data.get('event_type') == 'alert':
            # Suricata uses severity levels, convert to priority (lower number = higher priority)
            severity = alert_data.get('alert', {}).get('severity', 3)
            priority = severity  # Use severity as priority directly

            src_ip = alert_data.get('src_ip', '')
            dest_ip = alert_data.get('dest_ip', '')

            # Additional data that might be useful
            signature = alert_data.get('alert', {}).get('signature', '')
            category = alert_data.get('alert', {}).get('category', '')

            return priority, src_ip, dest_ip, signature, category
    except (json.JSONDecodeError, KeyError) as ex:
        logger.debug(f"Error parsing JSON alert: {ex}")
        return None, None, None, None, None
    return None, None, None, None, None

# Alternative regex for fast.log format if not using EVE JSON
alert_regex = re.compile(r'\[Priority: (\d+)].*?\{(?:UDP|TCP)} (\d+\.\d+\.\d+\.\d+):\d+ -> (\d+\.\d+\.\d+\.\d+):\d+')

# Suricata base folder path
suricata_dir = os.path.join(program_files, "Suricata")

# File paths and configurations
suricata_log_dir = os.path.join(suricata_dir, "log")
# Suricata typically uses eve.json for structured logging
eve_log_path = os.path.join(suricata_log_dir, "eve.json")
suricata_config_path = os.path.join(suricata_dir, "suricata.yaml")
suricata_exe_path = os.path.join(suricata_dir, "suricata.exe")

sandboxie_dir = os.path.join(program_files, "Sandboxie")
sandboxie_path = os.path.join(sandboxie_dir, "Start.exe")
sandboxie_control_path = os.path.join(sandboxie_dir, "SbieCtrl.exe")
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

thread_lock = threading.Lock()

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
drivers_sandboxie_path = get_sandbox_path(drivers_path)
hosts_path = f'{drivers_path}\\hosts'
hosts_sandboxie_path = get_sandbox_path(hosts_path)
HydraDragonAntivirus_sandboxie_path = get_sandbox_path(script_dir)
sandboxie_log_folder = get_sandboxie_log_folder()
homepage_change_path = f'{sandboxie_log_folder}\\DONTREMOVEHomePageChange.txt'
HiJackThis_log_path = f'{HydraDragonAntivirus_sandboxie_path}\\HiJackThis\\HiJackThis.log'
de4dot_sandboxie_dir = f'{HydraDragonAntivirus_sandboxie_path}\\de4dot_extracted_dir'
python_deobfuscated_sandboxie_dir = f'{HydraDragonAntivirus_sandboxie_path}\\python_deobfuscated'
version_flag = f"-{sys.version_info.major}.{sys.version_info.minor}"

# --- Global tracking sets ---
seen_files = set()  # Tracks already-scanned (path, md5) tuples

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

uefi_100kb_paths = [
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\SecureBootRecovery.efi'
]

uefi_paths = [
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\bootmgfw.efi',
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\bootmgr.efi',
    rf'{sandboxie_folder}\drive\X\EFI\Microsoft\Boot\memtest.efi',
    rf'{sandboxie_folder}\drive\X\EFI\Boot\bootx64.efi'
]

# Custom flags for directory changes
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800

# ClamAV base folder path
clamav_folder = os.path.join(program_files, "ClamAV")

# 7-Zip base folder path
seven_zip_folder = os.path.join(program_files, "7-Zip")

# ClamAV file paths and configurations
freshclam_path = os.path.join(clamav_folder, "freshclam.exe")
libclamav_path = os.path.join(clamav_folder, "libclamav.dll")
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

# IPv4 patterns (standard and all variations)
IPv4_pattern_standard = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# IPv6 patterns (standard and all variations)
IPv6_pattern_standard = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}::'

# Discord webhook patterns (normal, reversed, base64, base32)
discord_webhook_pattern = (
    r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    r'|aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3Mv[A-Za-z0-9+/]+'
    r'|/skoohbew/ipa/moc\.drocsid//:sptth'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64Q='
    r'|=Q4G6X4O35X6SHIHDT4IH2BEPD3YWQZNJDI4WXFNCDIKGZFNCDIKGF2MT4OGXFNUL6SHAQUEEVS33SGW5NDDIKGZFNCDIKGZFMT4TKXXBN'
)

# Discord Canary webhook patterns (normal, reversed, base64, base32)
discord_canary_webhook_pattern = (
    r'https://canary\.discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    r'|aHR0cHM6Ly9jYW5hcnkuZGlzY29yZC5jb20vYXBpL3dlYmhvb2tzL[A-Za-z0-9+/]+'
    r'|/skoohbew/ipa/moc\.drocsid\.yranac//:sptth'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64TJNF2GS4DFOQQGC3DJMRZXIZJ5'
    r'|5JZIXZRMJD3CGQOFD4SG2FNJT46G6X4O35X6SHIHDT4IH2BEPD3YWQZNJDI4WXFNCDIKGZFNCDIKGZFMT4OGXFNUL6SHAQUEEVS33SGW5NDDIKGZFNCDIKGZFMT4TKXXBN'
)

# CDN attachment patterns (normal, reversed, base64, base32)
cdn_attachment_pattern = re.compile(
    r'https://(?:cdn\.discordapp\.com|media\.discordapp\.net)/attachments/\d+/\d+/[A-Za-z0-9_\-\.%]+(?:\?size=\d+)?'
    r'|aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMv[A-Za-z0-9+/]+'
    r'|aHR0cHM6Ly9tZWRpYS5kaXNjb3JkYXBwLm5ldC9hdHRhY2htZW50cy8=[A-Za-z0-9+/]*'
    r'|/stnemhcatta/moc\.ppadrocsid\.ndc//:sptth'
    r'|/stnemhcatta/ten\.ppadrocsid\.aidem//:sptth'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64Q=[A-Z2-7]*'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64Q=[A-Z2-7]*'
)

# Telegram token patterns (normal, reversed, base64, base32)
telegram_token_pattern = (
    r'\d{9,10}:[A-Za-z0-9_-]{35}'
    r'|[A-Za-z0-9_-]{35}:\d{9,10}'
    r'|[A-Za-z0-9+/]{35}:\d{9,10}[A-Za-z0-9+/]*={0,2}'
    r'|\d{9,10}:[A-Za-z0-9+/]{35}={0,2}'
    r'|[A-Z2-7]{35}:\d{9,10}[A-Z2-7]*={0,6}'
    r'|\d{9,10}:[A-Z2-7]{35}={0,6}'
)

# Telegram keyword patterns (normal, reversed, base64, base32)
telegram_keyword_pattern = (
    r'\b(?:telegram|token)\b'
    r'|dGVsZWdyYW0=|dG9rZW4='
    r'|bWFyZ2VsZXQ=|bmVrb3Q='
    r'|ORSXG5DJNZTSA===|ORZXIZLB'
    r'|===ASTZNDJD5GXSRO|BLIZXRO'
    r'|margelet|nekot'
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
    r'https?://api\.telegram\.org/bot\d{9,10}:[A-Za-z0-9_-]{35}'
    r'|\b\d{9,10}:[A-Za-z0-9_-]{35}\b'
)

# UBlock regex (improved with more variations)
UBLOCK_REGEX = re.compile(
    r'^https:\/\/s[cftz]y?[ace][aemnu][a-z]{1,4}o[mn][a-z]{4,8}[iy][a-z]?\.com\/$'
    r'|^aHR0cHM6Ly9z[A-Za-z0-9+/]*o[A-Za-z0-9+/]*\.Y29t[A-Za-z0-9+/]*={0,2}$'
    r'|^\/moc\.[a-z]*[yi][a-z]{4,8}[nm]o[a-z]{1,4}[une][eca][a-z]?y?[zftc]s\/\/:sptth$'
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

# Base directories common to both lists
COMMON_DIRECTORIES = [
    pd64_extracted_dir, enigma_extracted_dir, inno_setup_unpacked_dir, themida_unpacked_dir,
    FernFlower_decompiled_dir, jar_extracted_dir, nuitka_dir, dotnet_dir, npm_pkg_extracted_dir,
    androguard_dir, asar_dir, obfuscar_dir, de4dot_extracted_dir, decompiled_jsc_dir,
    net_reactor_extracted_dir, pyinstaller_extracted_dir, cx_freeze_extracted_dir,
    commandlineandmessage_dir, pe_extracted_dir, zip_extracted_dir, tar_extracted_dir,
    seven_zip_extracted_dir, general_extracted_with_7z_dir, nuitka_extracted_dir,
    advanced_installer_extracted_dir, processed_dir, python_source_code_dir,
    pylingual_extracted_dir, python_deobfuscated_dir, python_deobfuscated_marshal_pyc_dir,
    pycdas_extracted_dir, nuitka_source_code_dir, memory_dir, debloat_dir,
    resource_extractor_dir, ungarbler_dir, ungarbler_string_dir, html_extracted_dir, webcrack_javascript_deobfuscated_dir,
    upx_extracted_dir, installshield_extracted_dir, autoit_extracted_dir, un_confuser_ex_extracted_dir,
    copied_sandbox_and_main_files_dir, decompiled_dir, capa_results_dir, vmprotect_unpacked_dir,
]

# Additional directories only in MANAGED_DIRECTORIES
MANAGED_ONLY_DIRECTORIES = [
    detectiteasy_plain_text_dir,
    HiJackThis_logs_dir
]

# Final directory lists
directories_to_scan = COMMON_DIRECTORIES + [sandboxie_folder]
MANAGED_DIRECTORIES = COMMON_DIRECTORIES + MANAGED_ONLY_DIRECTORIES

for make_directory in MANAGED_DIRECTORIES:
    if os.path.exists(make_directory):
        try:
            shutil.rmtree(make_directory)
            logger.info(f"Removed directory: {make_directory}")
        except Exception as e:
            logger.error(f"Failed to remove directory '{make_directory}': {e}")
            continue  # Skip creating the directory if removal failed

    try:
        os.makedirs(make_directory)
        logger.info(f"Created directory: {make_directory}")
    except Exception as e:
        logger.error(f"Failed to create directory '{make_directory}': {e}")

# Directory conditions and their corresponding logging messages
DIRECTORY_MESSAGES = [
    (lambda fp: fp.startswith(pd64_extracted_dir), "Process Dump x64 output extracted."),
    (lambda fp: fp.startswith(enigma_extracted_dir), "Enigma extracted."),
    (lambda fp: fp.startswith(sandboxie_folder), "It's a Sandbox environment file."),
    (lambda fp: fp.startswith(copied_sandbox_and_main_files_dir), "It's a restored sandbox environment file."),
    (lambda fp: fp.startswith(decompiled_dir), "Decompiled."),
    (lambda fp: fp.startswith(capa_results_dir), "CAPA program capabilities extracted."),
    (lambda fp: fp.startswith(upx_extracted_dir), "UPX extracted."),
    (lambda fp: fp.startswith(webcrack_javascript_deobfuscated_dir), "JavaScript file deobfuscated with webcrack."),
    (lambda fp: fp.startswith(inno_setup_unpacked_dir), "Inno Setup unpacked."),
    (lambda fp: fp.startswith(themida_unpacked_dir), "Themida unpacked."),
    (lambda fp: fp.startswith(nuitka_dir), "Nuitka onefile extracted."),
    (lambda fp: fp.startswith(dotnet_dir), ".NET decompiled."),
    (lambda fp: fp.startswith(androguard_dir), "APK decompiled with androguard."),
    (lambda fp: fp.startswith(asar_dir), "ASAR archive (Electron) extracted."),
    (lambda fp: fp.startswith(npm_pkg_extracted_dir), "NPM packer (JavaScript) extracted."),
    (lambda fp: fp.startswith(decompiled_jsc_dir), "V8 bytecode objects (JSC files) extracted."),
    (lambda fp: fp.startswith(obfuscar_dir), ".NET file obfuscated with Obfuscar."),
    (lambda fp: fp.startswith(de4dot_sandboxie_dir), "It's a Sandbox environment file, also a .NET file deobfuscated with de4dot."),
    (lambda fp: fp.startswith(de4dot_extracted_dir), ".NET file deobfuscated with de4dot."),
    (lambda fp: fp.startswith(net_reactor_extracted_dir), ".NET file deobfuscated with .NET Reactor Slayer."),
    (lambda fp: fp.startswith(un_confuser_ex_extracted_dir), ".NET file deobfuscated with UnConfuserEx."),
    (lambda fp: fp.startswith(pyinstaller_extracted_dir), "PyInstaller onefile extracted."),
    (lambda fp: fp.startswith(cx_freeze_extracted_dir), "cx_freeze library.zip extracted."),
    (lambda fp: fp.startswith(commandlineandmessage_dir), "Command line message extracted."),
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
    (lambda fp: fp.startswith(resource_extractor_dir), "It's an RCData resources extracted directory."),
    (lambda fp: fp.startswith(ungarbler_dir), "It's a deobfuscated Go Garble directory."),
    (lambda fp: fp.startswith(ungarbler_string_dir), "It's a directory of deobfuscated Go Garble strings."),
    (lambda fp: fp.startswith(debloat_dir), "It's a debloated file dir."),
    (lambda fp: fp.startswith(jar_extracted_dir), "It's a directory containing extracted files from a JAR (Java Archive) file."),
    (lambda fp: fp.startswith(FernFlower_decompiled_dir), "It's a directory containing decompiled files from a JAR (Java Archive) file, decompiled using Fernflower decompiler."),
    (lambda fp: fp.startswith(pylingual_extracted_dir), "It's a .pyc (Python Compiled Module) reversed-engineered Python source code directory with pylingual."),
    (lambda fp: fp.startswith(vmprotect_unpacked_dir), "It's a VMProtect unpacked directory."),
    (lambda fp: fp.startswith(python_deobfuscated_dir), "It's an unobfuscated Python directory."),
    (lambda fp: fp.startswith(python_deobfuscated_marshal_pyc_dir), "It's a deobfuscated .pyc (Python Compiled Module) from marshal data."),
    (lambda fp: fp.startswith(python_deobfuscated_sandboxie_dir), "It's an unobfuscated Python directory within Sandboxie."),
    (lambda fp: fp.startswith(pycdas_extracted_dir), "It's a PyInstaller, .pyc (Python Compiled Module) reversed-engineered Python source code directory with pycdas.exe."),
    (lambda fp: fp.startswith(python_source_code_dir), "It's a PyInstaller, .pyc (Python Compiled Module) reversed-engineered Python source code base directory."),
    (lambda fp: fp.startswith(nuitka_source_code_dir), "It's a Nuitka reversed-engineered Python source code directory."),
    (lambda fp: fp.startswith(html_extracted_dir), "This is the directory for HTML files of visited websites."),
    (lambda fp: fp.startswith(installshield_extracted_dir), "InstallShield extracted with ISx."),
    (lambda fp: fp.startswith(autoit_extracted_dir), "AutoIt extracted with AutoIt-Ripper.")
]

# Counter for ransomware detection
ransomware_detection_count = 0

# Global flags and caches
main_file_path: str | None = None
pyinstaller_archive: str | None = None
full_python_version: str | None = None
pyz_version_match: bool = False

# Cache of { file_path: last_md5 }
file_md5_cache: dict[str, str] = {}

# Global cache: md5 -> (die_output, plain_text_flag)
die_cache: dict[str, tuple[str, bool]] = {}

# Separate cache for "binary-only" DIE results
binary_die_cache: dict[str, str] = {}

def reset_flags():
    """
    Reset all global flags and caches to their initial state.
    """
    global main_file_path, pyinstaller_archive, full_python_version, pyz_version_match
    global ransomware_detection_count

    main_file_path = None
    pyinstaller_archive = None
    full_python_version = None
    pyz_version_match = False

    file_md5_cache.clear()
    die_cache.clear()
    binary_die_cache.clear()

    ransomware_detection_count = 0

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
        logger.info(f"Trying Enigma protected v{version} flags: {flags}")
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        if proc.returncode == 0:
            logger.info(f"Successfully unpacked with version {version} into {version_dir}")
            return version_dir

        logger.error(
            f"Attempt v{version} failed (exit {proc.returncode}). Output:\n{proc.stdout}"
        )

    logger.error(
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
        logger.info("DIE output does not contain plain text; identified as non-plain text data.")
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
            logger.debug(f"Stripped port from bracketed IPv6: {original!r} {ip_string!r}")
    # IPv4 or unbracketed IPv6: split on last colon only if it looks like a port
    elif ip_string.count(':') == 1:
        ip_part, port = ip_string.rsplit(':', 1)
        if port.isdigit():
            ip_string = ip_part
            logger.debug(f"Stripped port from IPv4/unbracketed: {original!r} {ip_string!r}")
    # else: leave IPv6 with multiple colons intact

    logger.info(f"Validating IP: {ip_string!r}")
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        logger.debug(f"Parsed IP object: {ip_obj} (version {ip_obj.version})")
    except ValueError:
        logger.error(f"Invalid IP syntax: {ip_string!r}")
        return False

    # exclusion categories
    if ip_obj.is_private:
        logger.info(f"Excluded private IP: {ip_obj}")
        return False
    if ip_obj.is_loopback:
        logger.info(f"Excluded loopback IP: {ip_obj}")
        return False
    if ip_obj.is_link_local:
        logger.info(f"Excluded link-local IP: {ip_obj}")
        return False
    if ip_obj.is_multicast:
        logger.info(f"Excluded multicast IP: {ip_obj}")
        return False
    if ip_obj.is_reserved:
        logger.info(f"Excluded reserved IP: {ip_obj}")
        return False

    # valid public IP
    logger.info(f"Valid public IPv{ip_obj.version} address: {ip_obj}")
    return True

def sanitize_filename(filename: str) -> str:
    """
    Sanitize the filename by replacing invalid characters for Windows.
    """
    # Replace all invalid Windows filename characters with underscores
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)

    # Replace control characters with underscores
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '_', filename)

    # Remove leading/trailing dots and spaces (Windows doesn't like these)
    filename = filename.strip('. ')

    # Handle empty filename
    if not filename:
        filename = "file"

    # Limit length to avoid path issues
    if len(filename) > 200:
        filename = filename[:200]

    return filename

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
    logger.info(f"Error reading {extensions_path}: {ex}")

logger.info(f"File types read from {extensions_path}: {fileTypes}")

# Read antivirus process list from antivirusprocesslist.txt with try-except.
antivirus_process_list = []
try:
    if os.path.exists(antivirus_process_list_path):
        with open(antivirus_process_list_path, 'r') as av_file:
            antivirus_process_list = [line.strip() for line in av_file if line.strip()]
except Exception as ex:
    logger.info(f"Error reading {antivirus_process_list_path}: {ex}")

logger.info(f"Antivirus process list read from {antivirus_process_list_path}: {antivirus_process_list}")

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

    # If reading and processing is successful, logger.info the dictionary
    logger.info("Magic bytes have been successfully loaded.")

except FileNotFoundError:
    logger.error(f"Error: The file {magic_bytes_path} was not found.")
except Exception as e:
    logger.error(f"An error occurred: {e}")

def get_unique_output_path(output_dir: Path, base_name) -> Path:
    """
    Generate a unique output path by sanitizing the filename and adding timestamp/counter if needed.

    Args:
        output_dir: Directory where the file will be created
        base_name: Base filename (can be string or Path)

    Returns:
        Path: Unique file path that doesn't exist yet
    """
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Convert to Path object to easily extract stem and suffix
    base_name = Path(base_name)
    stem = sanitize_filename(base_name.stem)
    suffix = base_name.suffix

    # Generate initial candidate with timestamp
    timestamp = int(time.time())
    candidate = output_dir / f"{stem}_{timestamp}{suffix}"

    # If it doesn't exist, we're done
    if not candidate.exists():
        return candidate

    # If it exists, add a counter
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
            logger.error("ADVINSTSFX not found")

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
                        logger.error("Footer too short to parse")
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
                        logger.debug(f)
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

                logger.debug(ar)

        return extracted_files

def analyze_file_with_die(file_path):
    """
    Runs Detect It Easy (DIE) on the given file once and returns the DIE output (plain text).
    The output is also saved to a unique .txt file and displayed to the user.
    """
    try:
        logger.info(f"Analyzing file: {file_path} using Detect It Easy...")
        output_dir = Path(detectiteasy_plain_text_dir)
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

        logger.info(f"Analysis result saved to {txt_output_path}")

        # Display the result using logging
        if result.stdout.strip():
            logger.info(f"{'='*60}")
            logger.info(f"DIE Analysis Result for: {Path(file_path).name}")
            logger.info(f"{'='*60}")
            logger.info(result.stdout)
            logger.info(f"{'='*60}")
            logger.info(f"Result saved to: {txt_output_path}")
        else:
            logger.error(f"No DIE output for {Path(file_path).name}")
            if result.stderr:
                logger.error(f"DIE stderr output: {result.stderr}")

        return result.stdout

    except subprocess.SubprocessError as ex:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}"
        logger.error(error_msg)
        return None
    except Exception as ex:
        error_msg = f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}"
        logger.error(error_msg)
        return None

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

def get_die_output(path: str) -> Tuple[str, bool]:
    """
    Returns (die_output, plain_text_flag), caching results by content MD5.
    Uses get_die_output_binary() if the file is not plain text.
    """
    # --- Special rule: force plain text for files in commandlineandmessage_dir --- #
    if os.path.commonpath([path, commandlineandmessage_dir]) == commandlineandmessage_dir:
        return "Binary\n    Format: plain text", True

    file_md5 = compute_md5(path)
    if file_md5 in die_cache:
        return die_cache[file_md5]

    # First time for this content
    with open(path, "rb") as f:
        peek = f.read(8192)

    if is_plain_text(peek):
        die_output = "Binary\n    Format: plain text"
        plain_text_flag = True
    else:
        die_output = get_die_output_binary(path)  # delegate to binary cache
        plain_text_flag = False  # skip text detection here

    die_cache[file_md5] = (die_output, plain_text_flag)
    return die_output, plain_text_flag

def is_go_garble_from_output(die_output):
    """
    Check if the DIE output indicates a Go garbled file.
    A file is considered garble if the output contains:
      - "Compiler: Go(unknown)"
    """
    if die_output and ("Compiler: Go(unknown)" in die_output):
        logger.info("DIE output indicates a garbled Go file.")
        return True
    return False

def is_pyc_file_from_output(die_output):
    """
    Check if the DIE output indicates a Python compiled module (.pyc file).
    It looks for markers that suggest it's a Python compiled module.
    """
    if die_output and "Python Compiled Module" in die_output:
        logger.info("DIE output indicates a Python compiled module.")
        return True
    return False

def is_themida_from_output(die_output):
    """
    Check if the DIE output indicates Themida/WinLicense protection.
    Matches 'Protector: Themida/Winlicense (2.XX)' or '(3.XX)' in PE32/PE64 binaries.
    Case-sensitive; does NOT use startswith.
    """
    if not die_output:
        return None

    s = die_output.strip()

    if "Protector: Themida/Winlicense (2.XX)" in s or \
       "Protector: Themida/Winlicense (3.XX)" in s:

        if "PE32" in s:
            logger.info("DIE output indicates PE32 protected with Themida/WinLicense.")
            return "PE32 Themida"
        if "PE64" in s:
            logger.info("DIE output indicates PE64 protected with Themida/WinLicense.")
            return "PE64 Themida"

    return None

def is_vm_protect_from_output(die_output):
    """
    Check if the DIE output indicates VMProtect protection for PE32 or PE64.
    Case-sensitive; does NOT use startswith. Returns True only if the output
    contains 'Protector: VMProtect' AND either 'PE32' or 'PE64' anywhere.
    Otherwise returns False.
    """
    if not die_output:
        return False

    s = die_output.strip()

    # must contain the exact protector token
    if "Protector: VMProtect" not in s:
        return False

    # must contain one of the PE markers somewhere in the output
    if "PE32" in s:
        logger.info("DIE output indicates PE32 protected with VMProtect.")
        return True
    if "PE64" in s:
        logger.info("DIE output indicates PE64 protected with VMProtect.")
        return True

    return False

def is_pe_file_from_output(die_output: str, file_path: str) -> Union[bool, str]:
    """
    Checks if DIE output or pefile validation indicates a PE (Portable Executable) file.

    Args:
        die_output: The output string from DIE (Detect It Easy).
        file_path: The path to the suspected PE file.

    Returns:
        True if the file appears to be a PE file,
        "Broken Executable" if DIE indicates PE but pefile fails to parse it,
        False otherwise.
    """
    # Check DIE output first (case-sensitive, no startswith)
    if die_output:
        s = die_output.strip()
        if "PE32" in s or "PE64" in s:
            logger.info("DIE output indicates a PE file.")

            # Cross-validate using pefile
            try:
                pefile.PE(file_path, fast_load=True)
                logger.info("pefile successfully parsed the file as PE.")
                return True
            except pefile.PEFormatError:
                logger.error("DIE said PE, but pefile couldn't parse it. Possibly corrupted.")
                return "Broken Executable"

    # If DIE doesn't indicate PE (or die_output is empty), try pefile directly
    try:
        pefile.PE(file_path, fast_load=True)
        logger.info("pefile detected a PE file even though DIE did not.")
        return True
    except pefile.PEFormatError:
        return False

def is_cx_freeze_file_from_output(die_output):
    """Checks if DIE output indicates a cx_Freeze file."""
    if die_output and ("Packer: cx_Freeze(5.x+)" in die_output):
        logger.info("DIE output indicates a cx_Freeze file.")
        return True
    return False

def is_advanced_installer_file_from_output(die_output):
    """Checks if DIE output indicates a Advanced Installer file."""
    if die_output and ("Advanced Installer" in die_output):
        logger.info("DIE output indicates a Advanced Installer file.")
        return True
    return False

def is_autoit_file_from_output(die_output):
    """Checks if DIE output indicates a AutoIt file."""
    if die_output and ("AutoIt" in die_output):
        logger.info("DIE output indicates a AutoIt file.")
        return True
    return False

def is_jsc_from_output(die_output: str) -> Optional[str]:
    """
    Detect JavaScript Compiled/Bytenode (.JSC) files from DIE output.

    Requirements (case-sensitive):
      - die_output must start with "Binary"
      - must contain "Language: JavaScript"
      - must contain "Format: JavaScript Compiled/Bytenode" or ".JSC"

    Tries to extract:
      - a Bytenode/JSC version like v9.4.146.24 (looks for "v\\d+\\.\\d+\\.\\d+\\.\\d+")
      - V8 Version occurrences like "V8 Version 9.4.146.24"
      - architecture: "x86" or "x64" (looks for tokens near the version or anywhere in output)

    Returns:
      - e.g. "JSC v9.4.146.24 x64"  (best case: version + arch)
      - e.g. "JSC (unknown version) x86" (if arch found but no explicit version)
      - "JSC (unknown version)" (if format & language matched but no arch/version)
      - None if detection requirements are not satisfied.
    """
    if not die_output:
        return None

    s = die_output.strip()

    # require startswith Binary (case-sensitive)
    if not s.startswith("Binary"):
        return None

    # require both tokens present (case-sensitive)
    if "Language: JavaScript" not in s:
        return None
    if "Format: JavaScript Compiled/Bytenode" not in s and ".JSC" not in s:
        return None

    # Attempt to find a explicit bytenode-style version: (v9.4.146.24) or v9.4.146.24
    version = None
    # look for "(vX.Y.Z.W" or "vX.Y.Z.W" possibly followed by " x64"/" x86"
    m = re.search(r'\(v(\d+\.\d+\.\d+\.\d+)\s*(x86|x64)?\)', s)
    if m:
        version = m.group(1)
        # arch_in_paren = m.group(2)
    else:
        m = re.search(r'\bv(\d+\.\d+\.\d+\.\d+)\b', s)
        if m:
            version = m.group(1)
        # also check "V8 Version" occurrences
        if not version:
            m2 = re.search(r'V8 Version\s+(\d+\.\d+\.\d+\.\d+)', s)
            if m2:
                version = m2.group(1)

    # Determine architecture: try to find x64/x86 near version first, else anywhere
    arch = None
    if version:
        # search for "version ... x64" on the same line or within small window
        # find position of version and scan nearby characters
        pos = s.find(version)
        if pos != -1:
            window = s[max(0, pos - 60): pos + 60]
            if "x64" in window:
                arch = "x64"
            elif "x86" in window:
                arch = "x86"

    # fallback: look anywhere in the output for common arch tokens
    if not arch:
        if " x64" in s or "x64)" in s or " x64 " in s:
            arch = "x64"
        elif " x86" in s or "x86)" in s or " x86 " in s:
            arch = "x86"

    # Build return string
    if version and arch:
        logger.info(f"DIE output indicates JavaScript Compiled/Bytenode (.JSC): v{version} {arch}.")
        return f"JSC v{version} {arch}"
    if version:
        logger.info(f"DIE output indicates JavaScript Compiled/Bytenode (.JSC): v{version} (arch unknown).")
        return f"JSC v{version} (arch unknown)"
    if arch:
        logger.info(f"DIE output indicates JavaScript Compiled/Bytenode (.JSC) {arch} (version unknown).")
        return f"JSC (unknown version) {arch}"

    logger.info("DIE output indicates JavaScript Compiled/Bytenode (.JSC) but no version/arch could be determined.")
    return "JSC (unknown version)"

def is_npm_from_output(die_output):
    """
    Case-sensitive check: return True if die_output contains the exact tokens
    'Packer: npm', 'Language: JavaScript', and either 'PE32' or 'PE64' anywhere.
    Otherwise return False.
    """
    if not die_output:
        return False

    s = die_output.strip()

    if "Packer: npm" in s and "Language: JavaScript" in s and ("PE32" in s or "PE64" in s):
        pe = "PE32" if "PE32" in s else "PE64"
        logger.info(f"DIE output indicates {pe} packed with npm and Language: JavaScript.")
        return True

    return False

def is_asar_archive_from_output(die_output):
    """
    Checks if the first two lines of DIE output indicate an Asar Archive (Electron).
    Ignores all other lines and warnings.
    """
    if not die_output:
        return False

    # Split lines and strip whitespace
    lines = [line.strip() for line in die_output.splitlines() if line.strip()]

    # Only consider the first two lines
    first_two = lines[:2]

    expected = ["Binary", "Archive: Asar Archive (Electron)"]

    if first_two == expected:
        logger.info("DIE output indicates an Asar Archive (Electron).")
        return True

    return False

def is_installshield_file_from_output(die_output):
    """Checks if DIE output indicates a Install Shield file."""
    if die_output and ("InstallShield" in die_output):
        logger.info("DIE output indicates a Install Shield file.")
        return True
    return False

def is_nsis_from_output(die_output: str) -> bool:
    """Checks if DIE output indicates an NSIS installer file."""
    if not die_output:
        logger.info("DIE output is empty or None.")
        return False

    # Look for NSIS installer signatures in the output
    indicators = [
        "Nullsoft Scriptable Install System",  # e.g. Installer: Nullsoft Scriptable Install System(2.46-Unicode)[lzma]
        "Data: NSIS data"
    ]

    if any(indicator in die_output for indicator in indicators):
        logger.info("DIE output indicates an NSIS installer.")
        return True

    return False

def is_elf_file_from_output(die_output: str, file_path: str) -> bool:
    """
    Checks if DIE output or ELF validation indicates an ELF file.

    Args:
        die_output: The output string from DIE (Detect It Easy).
        file_path: The path to the suspected ELF file.

    Returns:
        True if the file appears to be an ELF file,
        "Broken Executable" if DIE detects ELF but parsing fails,
        False otherwise.
    """
    # Check DIE output first
    if die_output and (die_output.startswith("ELF32") or die_output.startswith("ELF64")):
        logger.info("DIE output indicates an ELF file.")

        # Cross-validate using pyelftools
        try:
            with open(file_path, 'rb') as f:
                elf_file = ELFFile(f)
                # Basic validation - check if we can read the header
                header = elf_file.header
                logger.info(f"ELF file successfully parsed. Architecture: {header['e_machine']}")
                return True
        except (ELFError, IOError, ValueError) as e:
            logger.error(f"DIE said ELF, but pyelftools couldn't parse it: {e}. Possibly corrupted.")
            return "Broken Executable"

    # If DIE doesn't say ELF, try pyelftools directly
    try:
        with open(file_path, 'rb') as f:
            elf_file = ELFFile(f)
            header = elf_file.header
            logger.info("pyelftools detected an ELF file even though DIE did not.")
            return True
    except (ELFError, IOError, ValueError):
        return False

def is_apk_file_from_output(die_output: str, file_path: str) -> Union[bool, str]:
    """
    Determines whether the given file is an APK by first checking DIE's detection
    result and, if positive, validating it via Androguard.

    Args:
        die_output: The raw output string from DIE (Detect It Easy).
        file_path:  The path to the file under test.

    Returns:
        True           - if Androguard confirms a valid APK.
        "Broken APK"   - if DIE claimed "APK" but Androguard failed to parse it.
        False          - otherwise.
    """
    if die_output:
        logger.info(f"DIE output: {die_output.strip()}")

    # Only continue if DIE flagged the file as APK
    if not die_output or not die_output.strip().upper().startswith("APK"):
        return False

    # Try Androguard validation
    try:
        a, d, dx = AnalyzeAPK(file_path)
        if a.is_valid_APK():
            logger.info("Androguard confirms this is a valid APK.")
            return True
        else:
            logger.error("Androguard opened the file but it failed APK validity checks.")
            return "Broken APK"

    except Exception as e:
        logger.error(f"Androguard failed to parse APK: {e}")
        return "Broken APK"

def is_enigma1_virtual_box(die_output):
    """
    Checks if DIE output indicates the Enigma Virutal Box.
    Returns True if 'Protector: Enigma' is found, else False.
    """
    if die_output and ".enigma1" in die_output:
        logger.info("DIE output indicates Protector: Enigma.")
        return True

    return False

def is_macho_file_from_output(die_output: str, file_path: str) -> bool:
    """
    Checks if DIE output or macholib validation indicates a Mach-O file.

    Args:
        die_output: The output string from DIE (Detect It Easy).
        file_path: The path to the suspected Mach-O file.

    Returns:
        True if the file appears to be a Mach-O file,
        "Broken Executable" if DIE detects Mach-O but parsing fails,
        False otherwise.
    """
    # Check DIE output first
    if die_output and (die_output.startswith("Mach-O")):
        logger.info("DIE output indicates a Mach-O file.")

        # Cross-validate using macholib
        try:
            macho = macholib.MachO.MachO(file_path)
            # Basic validation - check if we can access the headers
            for header in macho.headers:
                logger.info(f"Mach-O file successfully parsed. CPU type: {header.header.cputype}")
            return True
        except (IOError, ValueError, struct.error, IndexError, Exception) as e:
            logger.error(f"DIE said Mach-O, but macholib couldn't parse it: {e}. Possibly corrupted.")
            return "Broken Executable"

    # If DIE doesn't say Mach-O, try macholib directly
    try:
        macho = macholib.MachO.MachO(file_path)
        # Verify we can read at least one header
        headers = list(macho.headers)
        if headers:
            logger.info("macholib detected a Mach-O file even though DIE did not.")
            return True
        else:
            logger.debug("macholib found no valid headers in the file.")
            return False
    except (IOError, ValueError, struct.error, IndexError, Exception):
        return False

def is_dotnet_file_from_output(die_output):
    """
    Checks whether the DIE output indicates a .NET executable file.

    Returns:
      - False
        if "C++" appears anywhere in the output.
      - "Already Deobfuscated"
        if "Tool: de4dot[deobfuscated]" is found.
      - "Protector: Obfuscar" or "Protector: Obfuscar(<version>)"
        if it's protected with Obfuscar.
      - "Protector: ConfuserEx" or "Protector: ConfuserEx(<version>)"
        if it's protected with ConfuserEx.
      - "Protector: .NET Reactor" or "Protector: .NET Reactor(<version>)"
        if it's protected with .NET Reactor.
      - "Protector: <Name>" or "Protector: <Name>(<version>)"
        for any other Protector marker (full line captured).
      - "Probably No Protector"
        if it's a .NET file and no protector is detected.
      - None
        if none of these markers are found.
    """
    try:
        if not die_output:
            logger.info("Empty DIE output; no .NET markers found.")
            return None

        # 0) If it contains a C++ indicator, treat as non-.NET and return False
        if "C++" in die_output:
            logger.info("DIE output indicates native C++ with .NET.")
            return False

        # 1) Check if already deobfuscated by de4dot
        if "Tool: de4dot[deobfuscated]" in die_output:
            logger.info("DIE output indicates file was already deobfuscated by de4dot.")
            return "Already Deobfuscated"

        # 2) Specific Obfuscar protector
        obfuscar_match = re.search(r'Protector:\s*Obfuscar(?:\(([^)]+)\))?', die_output)
        if obfuscar_match:
            version = obfuscar_match.group(1)
            result = f"Protector: Obfuscar({version})" if version else "Protector: Obfuscar"
            logger.info(f"DIE output indicates a .NET assembly protected with {result}.")
            return result

        # 3) Specific ConfuserEx protector
        confuser_match = re.search(r'Protector:\s*ConfuserEx(?:\(([^)]+)\))?', die_output, re.IGNORECASE)
        if confuser_match:
            version = confuser_match.group(1)
            result = f"Protector: ConfuserEx({version})" if version else "Protector: ConfuserEx"
            logger.info(f"DIE output indicates a .NET assembly protected with {result}.")
            return result

        # 4) Specific .NET Reactor protector (version 6.X only)
        reactor_match = re.search(r'Protector:\s*\.NET\s*Reactor\(6\.\d+\)', die_output, re.IGNORECASE)
        if reactor_match:
            version = reactor_match.group(0).split('(')[1].rstrip(')')
            result = f"Protector: .NET Reactor({version})"
            logger.info(f"DIE output indicates a .NET assembly protected with {result}.")
            return result

        # 5) Generic Protector marker - capture the full line
        line_match = re.search(r'^Protector:.*$', die_output, re.MULTILINE)
        if line_match:
            marker = line_match.group(0).strip()
            logger.info(f"DIE output indicates .NET assembly requiring de4dot: {marker}.")
            return marker

        # 6) .NET runtime indication (only if no protector found)
        if ".NET" in die_output:
            logger.info("DIE output indicates a .NET executable without protection; we'll still process it with de4dot.")
            return "Probably No Protector"

        # 7) Nothing .NET/protector-related found
        return None

    except re.error as e:
        logger.error(f"Regular expression error in is_dotnet_file_from_output: {e}")
        return None
    except AttributeError as e:
        logger.error(f"Attribute error in is_dotnet_file_from_output (possibly invalid die_output): {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in is_dotnet_file_from_output: {e}")
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
        logger.info("No DIE output provided.")
        return False

    # Normalize: split into lines, strip whitespace, drop empty lines
    lines = [line.strip() for line in die_output.splitlines() if line.strip()]

    # We only care about the first two markers; ignore anything after.
    if len(lines) >= 2 and lines[0] == "Binary" and lines[1] == "Unknown: Unknown":
        logger.info("DIE output indicates an unknown file (ignoring extra errors).")
        return True
    else:
        return False

def is_packed_from_output(die_output):
    """
    Check if the DIE output indicates a packed/protected binary.
    Case-sensitive checks; does NOT use startswith. Based on YARA-like signatures
    (UPX, ASPack, FSG, PECompact, Upack, PEtite, MEW, YZPack, MPRESS) and a generic
    "Packer:" indicator.

    Returns:
        - "PE64 Packed (<PACKER>)" or "PE32 Packed (<PACKER>)" if a PE marker and a packer are found,
        - "Packed (<PACKER>)" if a packer is found but no PE marker,
        - None if nothing matched or die_output is empty.
    """
    if not die_output:
        return None

    s = die_output.strip()

    # Specific packer signatures based on your YARA rules only
    packer_signatures = {
        # UPX variants
        'UPX': ['UPX', 'UPX0', 'UPX1', 'UPX2', 'UPX!', 'upX'],

        # ASPack
        'ASPACK': ['.aspack', '.adata'],

        # FSG (Fast Small Good)
        'FSG': ['FSG'],

        # PECompact
        'PECOMPACT': ['PECompact', 'PECompact2'],

        # Upack
        'UPACK': ['Upack'],

        # PEtite
        'PETITE': ['.petite', 'petite'],

        # MEW (Magic Executable Wizard)
        'MEW': ['MEW'],

        # YZPack
        'YZPACK': ['.yzpack', '.yzpack2'],

        # MPRESS
        'MPRESS': ['.MPRESS1', '.MPRESS2']
    }

    detected_packer = None

    # Case-sensitive "Packer:" indicator first
    if 'Packer:' in s:
        detected_packer = "GENERIC"
    else:
        # Check for specific packer signatures from your YARA rules
        for packer_name, signatures in packer_signatures.items():
            for signature in signatures:
                if signature in s:
                    detected_packer = packer_name
                    break
            if detected_packer:
                break

    # Return result based on presence of PE markers anywhere (no startswith)
    if detected_packer:
        if "PE64" in s:
            logger.info(f"DIE output indicates PE64 packed/protected binary: {detected_packer}")
            return f"PE64 Packed ({detected_packer})"
        if "PE32" in s:
            logger.info(f"DIE output indicates PE32 packed/protected binary: {detected_packer}")
            return f"PE32 Packed ({detected_packer})"

        logger.info(f"DIE output indicates packed/protected binary: {detected_packer}")
        return f"Packed ({detected_packer})"

    return None

def is_packer_upx_output(die_output):
    """
    Checks if DIE output indicates that the file is packed with UPX.
    Looks for the marker 'Packer: UPX' (optionally with version/modifier).
    """
    if die_output and re.search(r"Packer:\s*UPX\b", die_output):
        logger.info("DIE output indicates UPX packer.")
        return True

    return False

def is_jar_file_from_output(die_output):
    """Checks if DIE output indicates a JAR file (Java archive)."""
    if die_output and "Virtual machine: JVM" in die_output:
        logger.info("DIE output indicates a JAR file.")
        return True
    return False

def is_java_class_from_output(die_output):
    """
    Checks if the DIE output indicates a Java class file.
    It does this by looking for 'Format: Java Class File' in the output.
    """
    if die_output and "Format: Java Class " in die_output:
        logger.info("DIE output indicates a Java class file.")
        return True
    return False

def debloat_pe_file(file_path):
    """
    Runs debloat.processor.process_pe on a PE file, writing all
    output into its own uniquely-named subdirectory of debloat_dir.
    """
    try:
        logger.info(f"Debloating PE file {file_path} for faster scanning.")

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

        # Wrap logger.info so it accepts and ignores print-style kwargs
        def log_message(msg, *args, **kwargs):
            # Remove print-style arguments that logging doesn't support
            kwargs.pop('end', None)
            kwargs.pop('flush', None)
            logger.info(msg, *args, **kwargs)

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
            logger.info(f"Debloated file(s) saved in: {output_dir}")
            return str(output_dir)
        else:
            logger.error(f"Debloating failed for {file_path}; {output_dir} is empty.")
            return None

    except Exception as ex:
        logger.error("Error during debloating of %s: %s", file_path, ex)

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
                logger.error(f"Error decoding data: {ex}")
                return data_content  # Return original data if decoding fails

            # Convert decoded content back to bytes for magic byte removal
            hex_data = binascii.hexlify(decoded_content.encode("utf-8")).decode(errors="ignore")

            for magic_byte in magic_bytes.keys():
                pattern = re.compile(rf'{magic_byte}', re.IGNORECASE)
                hex_data = pattern.sub('', hex_data)

            try:
                return binascii.unhexlify(hex_data)
            except Exception as ex:
                logger.error(f"Error unhexlifying data: {ex}")
                return data_content  # Return original data if unhexlifying fails
    except Exception as ex:
        logger.error(f"Unexpected error in remove_magic_bytes: {ex}")
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
        logger.error(f"Error saving file {file_path}: {ex}")
        return None

def decode_base64(data_content):
    """Decode base64-encoded data."""
    try:
        return base64.b64decode(data_content, validate=True)
    except (binascii.Error, ValueError):
        logger.error("Base64 decoding failed.")
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
        logger.error(f"Base32 decoding error: {ex}")
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
                    logger.info("Base64 layer removed.")
                    data_content = decoded
                    continue

            # then Base-32
            if isinstance(data_content, (bytes, bytearray)) and is_base32(data_content):
                decoded = decode_base32(data_content)
                if decoded is not None:
                    logger.info("Base32 layer removed.")
                    data_content = decoded
                    continue

            logger.info("No more base64 or base32 encoded data found.")
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
        logger.info(f"Processed data from {file_path} saved to {output_file_path}")

        # now create a reversed lines variant with .txt extension
        lines = processed_data.splitlines(keepends=True)
        reversed_lines_data = b''.join(lines[::-1])

        reversed_output_path = os.path.join(
            processed_dir,
            f'processed_reversed_lines_{base_name}.txt'
        )
        with open(reversed_output_path, 'wb') as rev_file:
            rev_file.write(reversed_lines_data)
        logger.info(f"Reversed lines data from {file_path} saved to {reversed_output_path}")

    except Exception as ex:
        logger.error(f"Error processing file {file_path}: {ex}")

# --- PE Analysis and Feature Extraction Functions ---

class PEFeatureExtractor:
    def __init__(self):
        self.features_cache = {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        # Use a more efficient way to get byte counts
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        total_bytes = len(data)

        # Filter out zero counts to avoid log(0)
        probs = counts[counts > 0] / total_bytes
        entropy = -np.sum(probs * np.log2(probs))

        return float(entropy)

    def disassemble_all_sections(self, pe) -> Dict[str, Any]:
        """
        Disassembles all sections of the PE file using Capstone and returns
        instruction counts and a packing heuristic for each section and the file overall.
        """
        analysis = {
            'overall_analysis': {
                'total_instructions': 0,
                'add_count': 0,
                'mov_count': 0,
                'is_likely_packed': None
            },
            'sections': {},
            'error': None
        }

        try:
            # Determine architecture for Capstone
            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                analysis['error'] = "Unsupported architecture."
                return analysis

            total_add_count = 0
            total_mov_count = 0
            grand_total_instructions = 0

            # Disassemble each section individually
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                code = section.get_data()
                base_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                instruction_counts = {}
                total_instructions_in_section = 0

                if not code:
                    analysis['sections'][section_name] = {
                        'instruction_counts': {},
                        'total_instructions': 0,
                        'add_count': 0,
                        'mov_count': 0,
                        'is_likely_packed': False
                    }
                    continue

                instructions = md.disasm(code, base_address)

                for i in instructions:
                    mnemonic = i.mnemonic
                    instruction_counts[mnemonic] = instruction_counts.get(mnemonic, 0) + 1
                    total_instructions_in_section += 1

                add_count = instruction_counts.get('add', 0)
                mov_count = instruction_counts.get('mov', 0)

                # Aggregate counts for overall file analysis
                total_add_count += add_count
                total_mov_count += mov_count
                grand_total_instructions += total_instructions_in_section

                # Per-section packing analysis
                analysis['sections'][section_name] = {
                    'instruction_counts': instruction_counts,
                    'total_instructions': total_instructions_in_section,
                    'add_count': add_count,
                    'mov_count': mov_count,
                    'is_likely_packed': add_count > mov_count if total_instructions_in_section > 0 else False
                }

            # Populate the overall, file-wide analysis
            analysis['overall_analysis']['total_instructions'] = grand_total_instructions
            analysis['overall_analysis']['add_count'] = total_add_count
            analysis['overall_analysis']['mov_count'] = total_mov_count
            analysis['overall_analysis']['is_likely_packed'] = total_add_count > total_mov_count if grand_total_instructions > 0 else False

        except Exception as e:
            logger.error(f"Capstone disassembly failed: {e}")
            analysis['error'] = str(e)

        return analysis

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
            logger.error(f"Error retrieving TLS callback addresses: {e}")
            return []

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
            logger.error(f"Error analyzing TLS callbacks: {e}")
            return {}

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
                        dos_stub['entropy'] = self._calculate_entropy(dos_stub_data)

            return dos_stub
        except Exception as e:
            logger.error(f"Error analyzing DOS stub: {e}")
            return {}

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
            logger.error(f"Error analyzing certificates: {e}")
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
            logger.error(f"Error analyzing delay imports: {e}")
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
            logger.error(f"Error analyzing load config: {e}")
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
            logger.error(f"Error analyzing relocations: {e}")
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
                        logger.warning(f"Bound import {bound_import['name']} has no references.")

                    bound_imports.append(bound_import)

            return bound_imports
        except Exception as e:
            logger.error(f"Error analyzing bound imports: {e}")
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
                    'entropy': self._calculate_entropy(section.get_data()),
                    'size_ratio': section.SizeOfRawData / pe.OPTIONAL_HEADER.SizeOfImage if pe.OPTIONAL_HEADER.SizeOfImage else 0,
                    'pointer_to_raw_data': section.PointerToRawData,
                    'pointer_to_relocations': section.PointerToRelocations,
                    'pointer_to_line_numbers': section.PointerToLinenumbers,
                    'number_of_relocations': section.NumberOfRelocations,
                    'number_of_line_numbers': section.NumberOfLinenumbers,
                }

            return characteristics
        except Exception as e:
            logger.error(f"Error analyzing section characteristics: {e}")
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
            logger.error(f"Error analyzing extended headers: {e}")
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
                if rich_header['values']:
                    for i in range(0, len(rich_header['values']), 2):
                        if i + 1 < len(rich_header['values']):
                            comp_id = rich_header['values'][i] >> 16
                            build_number = rich_header['values'][i] & 0xFFFF
                            count = rich_header['values'][i + 1]
                            compid_info.append({
                                'comp_id': comp_id,
                                'build_number': build_number,
                                'count': count
                            })
                rich_header['comp_id_info'] = compid_info

            return rich_header
        except Exception as e:
            logger.error(f"Error analyzing Rich header: {e}")
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
            if not pe.sections:
                 return overlay_info

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
                    overlay_info['entropy'] = self._calculate_entropy(overlay_data)

            return overlay_info
        except Exception as e:
            logger.error(f"Error analyzing overlay: {e}")
            return {}

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extract numeric features of a file using pefile.
        Ensures pefile.PE is closed even on exceptions to avoid leaking file handles on Windows.
        """
        pe = None
        try:

            try:
                # Attempt to load PE file directly
                pe = pefile.PE(file_path, fast_load=True)
            except pefile.PEFormatError:
                logger.error(f"{file_path} is not a valid PE file.")
                return None
            except Exception as ex:
                logger.error(f"Error loading {file_path} as PE: {str(ex)}", exc_info=True)
                return None
            try:
                pe.parse_data_directories()
            except Exception:
                logger.debug(f"pe.parse_data_directories() failed for {file_path}", exc_info=True)

            # Extract features
            numeric_features = {
                # Capstone analysis for packing
                'section_disassembly': self.disassemble_all_sections(pe),

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
                    (pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') else [])
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
            logger.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return None
        finally:
            # ensure PE handle is closed to release underlying file descriptor
            try:
                if pe is not None:
                    pe.close()
            except Exception:
                logger.debug(f"Failed to close pe for {file_path}", exc_info=True)

pe_extractor = PEFeatureExtractor()

def calculate_vector_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculates similarity between two numeric vectors using cosine similarity."""
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0

    # Convert to numpy arrays for vector operations
    vec1 = np.array(vec1, dtype=np.float64)
    vec2 = np.array(vec2, dtype=np.float64)

    # Calculate cosine similarity
    dot_product = np.dot(vec1, vec2)
    norm_vec1 = np.linalg.norm(vec1)
    norm_vec2 = np.linalg.norm(vec2)

    if norm_vec1 == 0 or norm_vec2 == 0:
        return 1.0 if norm_vec1 == norm_vec2 else 0.0

    # The result of dot_product / (norm_vec1 * norm_vec2) is between -1 and 1.
    # We scale it to be in the [0, 1] range for easier interpretation.
    cosine_similarity = dot_product / (norm_vec1 * norm_vec2)
    return (cosine_similarity + 1) / 2

def notify_user(file_path, virus_name, engine_detected):
    notification = Notify()
    notification.title = "Malware Alert"
    notification_message = f"Malicious file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_pua(file_path, virus_name, engine_detected):
    notification = Notify()
    notification.title = "PUA Alert"
    notification_message = f"PUA file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_for_malicious_source_code(file_path, virus_name):
    """
    Sends a notification about malicious source code detected.
    """
    notification = Notify()
    notification.title = f"Malicious Source Code detected: {virus_name}"
    notification_message = f"Suspicious source code detected in: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.error(notification_message)

def notify_user_for_detected_command(message, file_path):
    notification = Notify()
    notification.title = "Malware Message Alert"
    notification.message = (
        f"{message}\n\n"
        f"Related to: {file_path}\n"
        f"(This does not necessarily mean the file is malware.)"
    )

    notification.send()
    logger.critical(f"Notification: {notification.message}")


def notify_user_for_meta_llama(file_path, virus_name, malware_status, HiJackThis_flag=False):
    notification = Notify()
    if HiJackThis_flag:
        notification.title = "Meta Llama-3.2-1B Security HiJackThis Alert"
    else:
        notification.title = "Meta Llama-3.2-1B Security Alert"

    if malware_status.lower() == "maybe":
        notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    elif malware_status.lower() == "yes":
        notification_message = f"Malware detected: {file_path}\nVirus: {virus_name}"

    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_size_warning(file_path, archive_type, virus_name):
    """Send a notification for size-related warnings."""
    notification = Notify()
    notification.title = "Size Warning"
    notification_message = (f"{archive_type} file {file_path} is smaller than 20MB but contains a large file "
                            f"which might be suspicious. Virus Name: {virus_name}")
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_susp_archive_file_name_warning(file_path, archive_type, virus_name):
    """Send a notification for warnings related to suspicious filenames in archive files."""
    notification = Notify()
    notification.title = "Suspicious Filename In Archive Warning"
    notification_message = (
        f"The filename in the {archive_type} archive '{file_path}' contains a suspicious pattern: {virus_name}."
    )
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_susp_name(file_path, virus_name):
    notification = Notify()
    notification.title = "Suspicious Name Alert"
    notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_scr(file_path, virus_name):
    """
    Notifies the user about a suspicious .scr PE file.
    """
    notification = Notify()
    notification.title = "Suspicious .SCR File Detected"
    notification_message = f"Suspicious .scr file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(f"ALERT: {notification_message}")

def notify_user_etw_tampering(file_path, virus_name):
    notification = Notify()
    notification.title = "ETW Tampering Alert"
    notification_message = f"ETW Tampering detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

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

    logger.critical(notification_message)

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

    logger.critical(notification_message)

def notify_user_invalid(file_path, virus_name):
    notification = Notify()
    notification.title = "Fully Invalid signature Alert"
    notification_message = f"Fully Invalid signature file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_fake_size(file_path, virus_name):
    notification = Notify()
    notification.title = "Fake Size Alert"
    notification_message = f"Fake size file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_startup(file_path, message):
    """Notify the user about suspicious or malicious startup files."""
    notification = Notify()
    notification.title = "Startup File Alert"

    # Include file_path in the message
    notification_message = f"File: {file_path}\n{message}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_uefi(file_path, virus_name):
    notification = Notify()
    notification.title = "UEFI Malware Alert"
    notification_message = f"Suspicious UEFI file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_ransomware(file_path, virus_name):
    notification = Notify()
    notification.title = "Ransomware Alert"
    notification_message = f"Potential ransomware detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_exela_stealer_v2(file_path, virus_name):
    notification = Notify()
    notification.title = "Exela Stealer version 2 Alert in Python source code"
    notification_message = f"Potential Exela Stealer version 2 detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_hosts(file_path, virus_name):
    notification = Notify()
    notification.title = "Host Hijacker Alert"
    notification_message = f"Potential host hijacker detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

def notify_user_worm(file_path, virus_name):
    notification = Notify()
    notification.title = "Worm Alert"
    notification_message = f"Potential worm detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

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

    logger.critical(notification_message)

def notify_user_for_hips(ip_address=None, dst_ip_address=None):
    notification = Notify()
    notification.title = "(Not Verified) Malicious Network Activity Detected"

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

    logger.critical(notification_message)

def notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status):
    """
    Function to send notification for detected HIPS file.
    """
    notification = Notify()
    notification.title = "(Verified) Web Malware Alert For File"
    notification_message = f"{status} file detected by Web related Message: {file_path}\nSource IP: {src_ip}\nAlert Line: {alert_line}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)

# Function to load antivirus list
def load_antivirus_list():
    global antivirus_domains_data
    try:
        with open(antivirus_list_path, 'r') as antivirus_file:
            antivirus_domains_data = antivirus_file.read().splitlines()
        return antivirus_domains_data
    except Exception as ex:
        logger.error(f"Error loading Antivirus domains: {ex}")
        return []

def load_digital_signatures(file_path, description="Digital signatures"):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            signatures = file.read().splitlines()
        logger.info(f"{description} loaded successfully!")
        return signatures
    except Exception as ex:
        logger.error(f"Error loading {description}: {ex}")
        return []

def load_website_data():
    global ipv4_addresses_signatures_data, ipv4_addresses_spam_signatures_data, ipv4_whitelist_data, ipv4_addresses_bruteforce_signatures_data, ipv4_addresses_phishing_active_signatures_data, ipv4_addresses_phishing_inactive_signatures_data, ipv6_addresses_signatures_data, ipv6_addresses_spam_signatures_data, ipv6_addresses_ddos_signatures_data, ipv4_addresses_ddos_signatures_data, ipv6_whitelist_data, urlhaus_data, malware_domains_data, malware_domains_mail_data, phishing_domains_data, abuse_domains_data, mining_domains_data, spam_domains_data, whitelist_domains_data, whitelist_domains_mail_data, malware_sub_domains_data, malware_mail_sub_domains_data, phishing_sub_domains_data, abuse_sub_domains_data, mining_sub_domains_data, spam_sub_domains_data, whitelist_sub_domains_data, whitelist_mail_sub_domains_data, spam_email_365_data

    def load_csv_data(file_path, data_name):
        """Helper function to load CSV data with IP/Domain,Reference format"""
        try:
            data = []
            with open(file_path, 'r', encoding='utf-8') as file:
                csv_reader = csv.reader(file)
                for row in csv_reader:
                    if len(row) >= 2:  # Ensure we have both columns
                        # Store as dictionary with 'address' and 'reference' keys
                        data.append({
                            'address': row[0].strip(),
                            'reference': row[1].strip()
                        })
                    elif len(row) == 1:  # Handle cases with only IP/Domain
                        data.append({
                            'address': row[0].strip(),
                            'reference': ''
                        })
            logger.info(f"{data_name} loaded successfully! ({len(data)} entries)")
            return data
        except Exception as ex:
            logger.error(f"Error loading {data_name}: {ex}")
            return []

    # Load IPv4 Malicious addresses
    ipv4_addresses_signatures_data = load_csv_data(ipv4_addresses_path, "Malicious IPv4 Addresses")

    # Load IPv4 Spam addresses
    ipv4_addresses_spam_signatures_data = load_csv_data(ipv4_addresses_spam_path, "Spam IPv4 Addresses")

    # Load IPv6 Spam addresses
    ipv6_addresses_spam_signatures_data = load_csv_data(ipv6_addresses_spam_path, "IPv6 Spam Addresses")

    # Load BruteForce IPv4 addresses
    ipv4_addresses_bruteforce_signatures_data = load_csv_data(ipv4_addresses_bruteforce_path, "BruteForce IPv4 Addresses")

    # Load phishing active IPv4 addresses
    ipv4_addresses_phishing_active_signatures_data = load_csv_data(ipv4_addresses_phishing_active_path, "Active Phishing IPv4 Addresses")

    # Load phishing inactive IPv4 addresses
    ipv4_addresses_phishing_inactive_signatures_data = load_csv_data(ipv4_addresses_phishing_inactive_path, "Inactive Phishing IPv4 Addresses")

    # Load IPv4 whitelist
    ipv4_whitelist_data = load_csv_data(ipv4_whitelist_path, "IPv4 Whitelist")

    # Load IPv6 Malicious addresses
    ipv6_addresses_signatures_data = load_csv_data(ipv6_addresses_path, "IPv6 Malicious Addresses")

    # Load IPv6 DDoS addresses
    ipv6_addresses_ddos_signatures_data = load_csv_data(ipv6_addresses_ddos_path, "IPv6 DDoS Addresses")

    # Load IPv4 DDoS addresses
    ipv4_addresses_ddos_signatures_data = load_csv_data(ipv4_addresses_ddos_path, "IPv4 DDoS Addresses")

    # Load IPv6 whitelist
    ipv6_whitelist_data = load_csv_data(ipv6_whitelist_path, "IPv6 Whitelist")

    # Load URLhaus data (keeping original format as it's already CSV with DictReader)
    try:
        urlhaus_data = []
        with open(urlhaus_path, 'r', encoding='utf-8') as urlhaus_file:
            reader = csv.DictReader(urlhaus_file)
            for row in reader:
                urlhaus_data.append(row)
        logger.info(f"URLhaus data loaded successfully! ({len(urlhaus_data)} entries)")
    except Exception as ex:
        logger.error(f"Error loading URLhaus data: {ex}")
        urlhaus_data = []

    # Load malware domains
    malware_domains_data = load_csv_data(malware_domains_path, "Malware Domains")

    # Load malware domains email
    malware_domains_mail_data = load_csv_data(malware_domains_mail_path, "Malware Email Domains")

    # Load phishing domains
    phishing_domains_data = load_csv_data(phishing_domains_path, "Phishing Domains")

    # Load abuse domains
    abuse_domains_data = load_csv_data(abuse_domains_path, "Abuse Domains")

    # Load mining domains
    mining_domains_data = load_csv_data(mining_domains_path, "Mining Domains")

    # Load spam domains
    spam_domains_data = load_csv_data(spam_domains_path, "Spam Domains")

    # Load whitelist domains
    whitelist_domains_data = load_csv_data(whitelist_domains_path, "Whitelist Domains")

    # Load whitelist mail domains
    whitelist_domains_mail_data = load_csv_data(whitelist_domains_mail_path, "Whitelist Mail Domains")

    # Load Malware subdomains
    malware_sub_domains_data = load_csv_data(malware_sub_domains_path, "Malware Subdomains")

    # Load Malware mail subdomains
    malware_mail_sub_domains_data = load_csv_data(malware_mail_sub_domains_path, "Malware Mail Subdomains")

    # Load Phishing subdomains
    phishing_sub_domains_data = load_csv_data(phishing_sub_domains_path, "Phishing Subdomains")

    # Load Abuse subdomains
    abuse_sub_domains_data = load_csv_data(abuse_sub_domains_path, "Abuse Subdomains")

    # Load Mining subdomains
    mining_sub_domains_data = load_csv_data(mining_sub_domains_path, "Mining Subdomains")

    # Load Spam subdomains
    spam_sub_domains_data = load_csv_data(spam_sub_domains_path, "Spam Subdomains")

    # Load Whitelist subdomains
    whitelist_sub_domains_data = load_csv_data(whitelist_sub_domains_path, "Whitelist Subdomains")

    # Load Whitelist mail subdomains
    whitelist_mail_sub_domains_data = load_csv_data(whitelist_mail_sub_domains_path, "Whitelist Mail Subdomains")

    # Load Spam Email 365 data (simple text file, one word per line)
    try:
        with open(spam_email_365_path, 'r', encoding='utf-8') as file:
            spam_email_365_data = [line.strip() for line in file.readlines() if line.strip()]
        logger.info(f"Spam Email 365 data loaded successfully! ({len(spam_email_365_data)} entries)")
    except Exception as ex:
        logger.error(f"Error loading Spam Email 365 data: {ex}")
        spam_email_365_data = []

    logger.info("All domain and IP address CSV files loaded successfully!")

# --------------------------------------------------------------------------
# Helper function to generate platform-specific signatures
def get_signature(base_signature, **flags):
    """Generate platform-specific signature based on flags."""
    platform_map = {
        'dotnet_flag': 'DotNET',
        'fernflower_flag': 'Java',
        'jsc_flag': 'JavaScript.ByteCode.v8',
        'javascript_deobfuscated_flag': 'JavaScript',
        'nuitka_flag': 'Nuitka',
        'nsis_flag': 'NSIS',
        'pyc_flag': 'PYC.Python',
        'androguard_flag': 'Android',
        'asar_flag': 'Electron',
        'registry_flag': 'Registry'
    }

    for flag, platform in platform_map.items():
        if flags.get(flag):
            return f"HEUR:Win32.{platform}.{base_signature}"

    return f"HEUR:Win32.{base_signature}"

# --------------------------------------------------------------------------
# Check for Discord webhook URLs (including Canary)
def contains_discord_or_telegram_code(decompiled_code, file_path, **flags):
    """
    Scan the decompiled code for Discord webhook URLs, Discord Canary webhook URLs,
    or Telegram bot links. For every detection, log a warning and immediately
    notify the user with an explicit unique heuristic signature that depends on the flags provided.
    """
    # Define detection patterns and their corresponding signatures
    detections = [
        (re.findall(discord_webhook_pattern, decompiled_code, flags=re.IGNORECASE), "Discord webhook URL", "Discord.Webhook"),
        (re.findall(discord_canary_webhook_pattern, decompiled_code, flags=re.IGNORECASE), "Discord Canary webhook URL", "Discord.Canary.Webhook"),
        (re.findall(cdn_attachment_pattern, decompiled_code, flags=re.IGNORECASE), "Discord CDN attachment URL", "Discord.CDNAttachment")
    ]

    # Check for Telegram (requires both token and keyword matches)
    telegram_token_matches = re.findall(telegram_token_pattern, decompiled_code)
    telegram_keyword_matches = re.findall(telegram_keyword_pattern, decompiled_code, flags=re.IGNORECASE)
    if telegram_token_matches and telegram_keyword_matches:
        detections.append((telegram_token_matches, "Telegram bot", "Telegram.Bot"))

    # Process all detections
    for matches, description, signature_base in detections:
        if matches:
            # Use the new get_signature helper
            signature = get_signature(signature_base, **flags)

            # Log appropriate message
            if signature_base == "Telegram.Bot":
                logger.info(f"{description} detected in decompiled code: {matches}")
            else:
                platform_desc_map = {
                    "DotNET": ".NET source code file",
                    "JavaScript.ByteCode.v8": "JavaScript ByteCode V8 file",
                    "Nuitka": "Nuitka compiled file",
                    "NSIS": "NSIS script compiled file (.nsi)",
                    "PYC.Python": "Python Compiled Module file",
                    "Android": "Android APK file",
                    "Electron": "Electron ASAR file",
                    "Registry": "Registry"
                }
                # Extract platform part from signature
                platform_part = signature.split(".")[2] if len(signature.split(".")) > 2 else ""
                platform_desc = platform_desc_map.get(platform_part, "decompiled code")
                logger.critical(f"{description} detected in {platform_desc}: {file_path} - Matches: {matches}")

            # Notify the user
            notify_user_for_malicious_source_code(file_path, signature)

# --------------------------------------------------------------------------
# Helper function to check if domain/IP exists in CSV data with reference support
def check_in_csv_data(target, csv_data):
    """Check if target exists in CSV data and return reference if found"""
    for entry in csv_data:
        if entry['address'] == target:
            return True, entry['reference']
    return False, None

def notify_with_homepage(target, base_signature, threat_name, **flags):
    """Helper to handle both main signature and homepage signature notifications."""
    # Main signature
    signature = get_signature(base_signature, **flags)
    notify_user_for_malicious_source_code(target, signature)

    # Homepage signature if flag exists
    homepage_flag = flags.get('homepage_flag')
    if homepage_flag:
        homepage_sig = f"HEUR:Win32.Adware.{homepage_flag}.{threat_name}.HomePage.gen"
        notify_user_for_malicious_source_code(target, homepage_sig)

# --------------------------------------------------------------------------
# Generalized scan for domains (CSV format with reference support)
def scan_domain_general(url, **flags):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            logger.error("Invalid URL or domain format")
        full_domain = parsed_url.netloc.lower()
        domain_parts = full_domain.split('.')

        if len(domain_parts) > 2:
            main_domain = '.'.join(domain_parts[-2:])
            subdomain = '.'.join(domain_parts[:-2])
        else:
            main_domain = full_domain
            subdomain = None

        if full_domain in scanned_domains_general:
            logger.info(f"Domain {full_domain} has already been scanned.")
            return
        scanned_domains_general.append(full_domain)
        logger.info(f"Scanning domain: {full_domain}")

        # Helper function to check if domain is in CSV data
        def is_domain_in_data_general(domain, data_list):
            for entry in data_list:
                if entry['address'] == domain:
                    return True, entry['reference']
            return False, ""

        # Whitelist checks
        whitelist_data = [
            (whitelist_domains_data, "domain"),
            (whitelist_domains_mail_data, "mail domain"),
            (whitelist_sub_domains_data, "subdomain"),
            (whitelist_mail_sub_domains_data, "mail subdomain")
        ]

        for data_list, whitelist_type in whitelist_data:
            is_whitelisted, reference = is_domain_in_data_general(full_domain, data_list)
            if is_whitelisted:
                logger.info(f"Domain {full_domain} is whitelisted ({whitelist_type}). Reference: {reference}")
                return

        # Threat check configurations
        subdomain_threats = [
            (spam_sub_domains_data, "Spam", "Spam.SubDomain", "Spam"),
            (mining_sub_domains_data, "Mining", "Mining.SubDomain", "Mining"),
            (abuse_sub_domains_data, "Abuse", "Abuse.SubDomain", "Abuse"),
            (phishing_sub_domains_data, "Phishing", "Phishing.SubDomain", "Phishing"),
            (malware_mail_sub_domains_data, "Malware.Mail", "Malware.Mail.SubDomain", "Malware"),
            (malware_sub_domains_data, "Malware", "Malware.SubDomain", "Malware")
        ]

        main_threats = [
            (spam_domains_data, "Spam", "Spam.Domain", "Spam"),
            (mining_domains_data, "Mining", "Mining.Domain", "Mining"),
            (abuse_domains_data, "Abuse", "Abuse.Domain", "Abuse"),
            (phishing_domains_data, "Phishing", "Phishing.Domain", "Phishing"),
            (malware_domains_mail_data, "Malware.Mail", "Malware.Mail.Domain", "Malware"),
            (malware_domains_data, "Malware", "Malware.Domain", "Malware")
        ]

        # Check subdomain threats
        if subdomain:
            for data_list, threat_name, signature_suffix, homepage_threat in subdomain_threats:
                is_threat, reference = is_domain_in_data_general(full_domain, data_list)
                if is_threat:
                    logger.critical(f"{threat_name} subdomain detected: {full_domain} (Reference: {reference})")
                    notify_with_homepage(full_domain, signature_suffix, homepage_threat, **flags)
                    return

        # Check main domain threats
        for data_list, threat_name, signature_suffix, homepage_threat in main_threats:
            is_full_threat, full_ref = is_domain_in_data_general(full_domain, data_list)
            is_main_threat, main_ref = is_domain_in_data_general(main_domain, data_list)

            if is_full_threat or is_main_threat:
                reference = full_ref if is_full_threat else main_ref
                domain_to_report = full_domain if is_full_threat else main_domain
                logger.critical(f"{threat_name} domain detected: {domain_to_report} (Reference: {reference})")
                notify_with_homepage(domain_to_report, signature_suffix, homepage_threat, **flags)
                return

        logger.info(f"Domain {full_domain} passed all checks.")

    except Exception as ex:
        logger.error(f"Error scanning domain {url}: {ex}")

# --------------------------------------------------------------------------
# Generalized scan for IP addresses (CSV format with reference support)
def scan_ip_address_general(ip_address, **flags):
    try:
        if is_valid_ip(ip_address):
            logger.info(f"Skipping non valid IP address: {ip_address}")
            return

        if ip_address in scanned_ipv4_addresses_general or ip_address in scanned_ipv6_addresses_general:
            logger.info(f"IP address {ip_address} has already been scanned.")
            return

        def is_ip_in_data_general(ip, data_list):
            for entry in data_list:
                if entry['address'] == ip:
                    return True, entry['reference']
            return False, ""

        # IPv6 processing
        if re.match(IPv6_pattern_standard, ip_address):
            scanned_ipv6_addresses_general.append(ip_address)
            logger.info(f"Scanning IPv6 address: {ip_address}")

            # IPv6 whitelist check
            is_whitelisted, reference = is_ip_in_data_general(ip_address, ipv6_whitelist_data)
            if is_whitelisted:
                logger.info(f"IPv6 address {ip_address} is whitelisted. Reference: {reference}")
                return

            # IPv6 threat checks
            ipv6_threats = [
                (ipv6_addresses_ddos_signatures_data, "DDoS", "DDoS.IPv6", "DDoS"),
                (ipv6_addresses_spam_signatures_data, "Spam", "Spam.IPv6", "Spam"),
                (ipv6_addresses_signatures_data, "Malware", "Malware.IPv6", "Malware")
            ]

            for data_list, threat_name, signature_suffix, homepage_threat in ipv6_threats:
                is_threat, reference = is_ip_in_data_general(ip_address, data_list)
                if is_threat:
                    logger.critical(f"{threat_name} IPv6 address detected: {ip_address} (Reference: {reference})")
                    notify_with_homepage(ip_address, signature_suffix, homepage_threat, **flags)
                    return

            logger.info(f"Unknown IPv6 address detected: {ip_address}")

        # IPv4 processing
        elif re.match(IPv4_pattern_standard, ip_address):
            scanned_ipv4_addresses_general.append(ip_address)
            logger.info(f"Scanning IPv4 address: {ip_address}")

            # IPv4 whitelist check
            is_whitelisted, reference = is_ip_in_data_general(ip_address, ipv4_whitelist_data)
            if is_whitelisted:
                logger.info(f"IPv4 address {ip_address} is whitelisted. Reference: {reference}")
                return

            # IPv4 threat checks
            ipv4_threats = [
                (ipv4_addresses_phishing_active_signatures_data, "PhishingActive", "PhishingActive.IPv4", "Phishing"),
                (ipv4_addresses_ddos_signatures_data, "DDoS", "DDoS.IPv4", "DDoS"),
                (ipv4_addresses_phishing_inactive_signatures_data, "PhishingInactive", "PhishingInactive.IPv4", "Phishing"),
                (ipv4_addresses_bruteforce_signatures_data, "BruteForce", "BruteForce.IPv4", "BruteForce"),
                (ipv4_addresses_spam_signatures_data, "Spam", "Spam.IPv4", "Spam"),
                (ipv4_addresses_signatures_data, "Malware", "Malware.IPv4", "Malware")
            ]

            for data_list, threat_name, signature_suffix, homepage_threat in ipv4_threats:
                is_threat, reference = is_ip_in_data_general(ip_address, data_list)
                if is_threat:
                    # Custom logging messages for different threat types
                    if threat_name in ["PhishingActive", "PhishingInactive"]:
                        status = "active" if threat_name == "PhishingActive" else "inactive"
                        logger.critical(f"IPv4 address {ip_address} detected as an {status} phishing threat. (Reference: {reference})")
                    elif threat_name in ["DDoS", "BruteForce"]:
                        logger.critical(f"IPv4 address {ip_address} detected as a potential {threat_name} threat. (Reference: {reference})")
                    else:
                        logger.critical(f"{threat_name} IPv4 address detected: {ip_address} (Reference: {reference})")

                    notify_with_homepage(ip_address, signature_suffix, homepage_threat, **flags)
                    return

            logger.info(f"Unknown IPv4 address detected: {ip_address}")
        else:
            logger.debug(f"Invalid IP address format detected: {ip_address}")

    except Exception as ex:
        logger.error(f"Error scanning IP address {ip_address}: {ex}")

# --------------------------------------------------------------------------
# Spam Email 365 Scanner
def scan_spam_email_365_general(email_content, **flags):
    """Scans email content for spam keywords from StopForum Spam Database."""
    try:
        if not email_content:
            logger.info("No email content provided for spam scanning.")
            return False

        email_content_lower = email_content.lower()
        detected_spam_words = [word for word in spam_email_365_data if word.lower() in email_content_lower]

        if detected_spam_words:
            logger.critical(f"Spam email detected! Found {len(detected_spam_words)} spam indicators: {', '.join(detected_spam_words[:5])}")
            notify_with_homepage("Email Content", "Spam.Email365d", "Spam.Email.365d", **flags)
            return True
        else:
            logger.info("Email content passed spam check - no spam indicators found.")
            return False

    except Exception as ex:
        logger.error(f"Error scanning email content for spam: {ex}")
        return False

# --------------------------------------------------------------------------
# Generalized scan for URLs
def scan_url_general(url, **flags):
    try:
        if url in scanned_urls_general:
            logger.info(f"URL {url} has already been scanned.")
            return

        scanned_urls_general.append(url)
        logger.info(f"Scanning URL: {url}")

        # Check against URLhaus signatures
        for entry in urlhaus_data:
            if entry['url'] in url:
                message = (f"URL {url} matches the URLhaus signatures.\n"
                          f"ID: {entry['id']}, Date Added: {entry['dateadded']}\n"
                          f"URL Status: {entry['url_status']}, Last Online: {entry['last_online']}\n"
                          f"Threat: {entry['threat']}, Tags: {entry['tags']}\n"
                          f"URLhaus Link: {entry['urlhaus_link']}, Reporter: {entry['reporter']}")
                logger.critical(message)
                notify_with_homepage(url, "URLhaus.Match", "URLhaus", **flags)
                return

        # Heuristic check using uBlock Origin style detection
        if ublock_detect(url):
            notify_user_for_malicious_source_code(url, 'HEUR:Phish.Steam.Community.gen')
            logger.critical(f"URL {url} flagged by uBlock detection using HEUR:Phish.Steam.Community.gen.")
            homepage_flag = flags.get('homepage_flag')
            if homepage_flag:
                notify_user_for_malicious_source_code(url, f"HEUR:Win32.Adware.{homepage_flag}.Phishing.HomePage.gen")
            return

        logger.info(f"No match found for URL: {url}")

    except Exception as ex:
        logger.error(f"Error scanning URL {url}: {ex}")

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
            logger.info(f"Invalid or disallowed IP address in URL: {url}")
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
            logger.info(f"Saved HTML for {safe_url} to {out_path}")
            # record the new path
            saved_paths.append(out_path)
            return (html, out_path) if return_file_path else html
        else:
            logger.error(f"Non-OK status {response.status_code} for URL: {safe_url}")
            return ("", None) if return_file_path else ""
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while fetching HTML content from {url}: {e}")
        return ("", None) if return_file_path else ""
    except Exception as e:
        logger.error(f"Unexpected error fetching HTML content from {url}: {e}")
        return ("", None) if return_file_path else ""


def scan_html_content(html_content, html_content_file_path, **flags):
    """Scan extracted HTML content for any potential threats."""
    contains_discord_or_telegram_code(html_content, html_content_file_path, None, **flags)

    # Extract and scan URLs
    urls = set(re.findall(r'https?://[^\s/$.?#]\S*', html_content))
    for url in urls:
        scan_url_general(url, **flags)
        scan_domain_general(url, **flags)
        scan_spam_email_365_general(url, **flags)

    # Extract and scan IP addresses (IPv4 and IPv6)
    ip_patterns = [
        (r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', 'IPv4'),
        (r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', 'IPv6')
    ]

    for pattern, ip_type in ip_patterns:
        ip_addresses = set(re.findall(pattern, html_content))
        for ip in ip_addresses:
            scan_ip_address_general(ip, **flags)

# --------------------------------------------------------------------------
# Helpers for decoding regex fragments
def _dec(b64: str) -> str:
    """Decode Base64-encoded ASCII/UTF-8 text fragments."""
    return base64.b64decode(b64.encode()).decode("utf-8", errors="replace")

def _dec32(b32: str) -> str:
    """Decode Base32-encoded ASCII/UTF-8 text fragments."""
    return base64.b32decode(b32.encode()).decode("utf-8", errors="replace")

# --------------------------------------------------------------------------
# Build URL regex at runtime
def detect_obfuscated_urls(text):
    """
    Detect and return both original obfuscated URLs and their decoded versions
    """
    import re

    if not text:
        return []

    obfuscated_patterns = {
        'hxxp': 'http',
        'hxxps': 'https',
        'fxp': 'ftp',
        'h**p': 'http',
        'h**ps': 'https',
        'ht*p': 'http',
        'ht*ps': 'https',
        'htt*p': 'http',
        'htt*s': 'https',
        'h_t_t_p': 'http',
        'h_t_t_p_s': 'https',
    }

    bracket_patterns = {
        '[.]': '.',
        '[dot]': '.',
        '(.)': '.',
        '(dot)': '.',
        '{.}': '.',
        '{dot}': '.',
    }

    results = []

    # Find obfuscated URLs with protocols
    obfuscated_url_pattern = re.compile(
        r'(h[tx*_\s]{1,6}ps?|f[tx*_\s]{1,3}p)://[^\s<>"\'{}|\\^`]*',
        re.IGNORECASE
    )

    for match in obfuscated_url_pattern.finditer(text):
        original = match.group(0)
        decoded = original.lower()

        # Fix protocol
        for obf, real in obfuscated_patterns.items():
            if decoded.startswith(obf):
                decoded = decoded.replace(obf, real, 1)
                break

        # Fix domain brackets
        for bracket, dot in bracket_patterns.items():
            decoded = decoded.replace(bracket, dot)

        # Remove extra spaces and underscores from protocol
        decoded = re.sub(r'h[\s_]*t[\s_]*t[\s_]*p[\s_]*s?[\s_]*:', 'https:', decoded)
        decoded = re.sub(r'h[\s_]*t[\s_]*t[\s_]*p[\s_]*:', 'http:', decoded)
        decoded = re.sub(r'f[\s_]*t[\s_]*p[\s_]*:', 'ftp:', decoded)

        results.append({
            'original': original,
            'decoded': decoded,
            'type': 'obfuscated_url'
        })

    # Find bracket-obfuscated domains without protocol
    domain_pattern = re.compile(r'[a-zA-Z0-9-]+(?:\[[.\]dot\]|\(\.\)|\{[\.\]dot\})[a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?')

    for match in domain_pattern.finditer(text):
        original = match.group(0)
        decoded = original

        for bracket, dot in bracket_patterns.items():
            decoded = decoded.replace(bracket, dot)

        results.append({
            'original': original,
            'decoded': decoded,
            'type': 'obfuscated_domain'
        })

    return results

# Also update your build_url_regex function with these additional patterns:
def build_url_regex():
    parts = [
        # Normal protocols
        r'https?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'ftp://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Obfuscated protocols (hxxps://, hxxp://, fxp://)
        r'hxxps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'fxp://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # X-obfuscated protocols (more variations)
        r'h[tx]{2}ps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'f[tx]p://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Bracket-obfuscated domains (e.g., example[.]com, test[dot]com)
        r'https?://[^\s<>"\'{}|\\^`\[\]]*\[[.\]dot\]][^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'hxxps?://[^\s<>"\'{}|\\^`\[\]]*\[[.\]dot\]][^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'h[tx]{2}ps?://[^\s<>"\'{}|\\^`\[\]]*\[[.\]dot\]][^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Specific bracket patterns for domains
        r'[a-zA-Z0-9-]+\[[\.\]dot]\][a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?',
        r'[a-zA-Z0-9-]+\(\.\)[a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?',
        r'[a-zA-Z0-9-]+\{[\.\]dot]\}[a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?',

        # Base64-obfuscated protocols (your existing code)
        _dec("aHR0cHM6Ly8") + r"[A-Za-z0-9+/]*={0,2}",   # https://
        _dec("aHR0cDovL") + r"[A-Za-z0-9+/]*={0,2}",   # http://
        _dec("ZnRwOi8v") + r"[A-Za-z0-9+/]*={0,2}",    # ftp://

        # Reversed/obfuscated (your existing code)
        r'//:[a-z]{4,5}sptth',
        r'//:[a-z]{4}ptth',
        r'//:[a-z]{3}ptf',

        # Base32 obfuscations
        r'NBXXK4TFMFZGKIDCNFZGKIDDOJSWCZ3P[A-Z2-7]*={0,6}',
        r'NBXXK4TFMFZGKIDCMJUWC2LP[A-Z2-7]*={0,6}',
        r'MZXW6IDCMFZWK4Q=[A-Z2-7]*={0,6}',

        # Additional obfuscation patterns
        r'h\*\*ps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',  # h**ps://
        r'ht\*ps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',   # ht*ps://
        r'htt\*s?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',   # htt*s://

        # Protocol with underscores
        r'h_t_t_p_s?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Spaced protocols
        r'h\s*t\s*t\s*p\s*s?\s*:\s*/\s*/[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
    ]
    return re.compile(r'|'.join(parts), re.IGNORECASE)

# --------------------------------------------------------------------------
# Build IPv4/IPv6 regex at runtime
def build_ip_patterns():
    # IPv4
    octet = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    ipv4_standard = r'\b(?:(?:' + octet + r')\.){3}(?:' + octet + r')\b'
    ipv4_nonstandard = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    ipv4_base64 = r'[A-Za-z0-9+/]{8,24}={0,2}'
    ipv4_base32 = r'[A-Z2-7]{8,40}={0,6}'
    ipv4_reversed_like = r'\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'

    IPv4_pattern = r'|'.join([
        ipv4_standard,
        ipv4_nonstandard,
        ipv4_base64,
        ipv4_base32,
        ipv4_reversed_like,
    ])

    # IPv6
    h16 = r'[0-9a-fA-F]{1,4}'
    full_ipv6 = r'\b(?:' + h16 + r':){7}' + h16 + r'\b'
    compressed_leading = r'::(?:' + h16 + r':){0,6}' + h16
    compressed_trailing = r'(?:' + h16 + r':){1,7}::'
    various_compressed = r'(?:' + h16 + r':){1,6}:' + h16
    flexible = r'[0-9a-fA-F:]{15,39}'
    ipv6_base64 = r'[A-Za-z0-9+/]{16,64}={0,2}'
    ipv6_base32 = r'[A-Z2-7]{16,64}={0,6}'
    reversed_compressed_leading = r'::(?:[Ff][A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}'
    reversed_compressed_trailing = r'(?:[A-Fa-f0-9]{1,4}:){1,7}::'

    IPv6_pattern = r'|'.join([
        full_ipv6,
        compressed_leading,
        compressed_trailing,
        various_compressed,
        flexible,
        ipv6_base64,
        ipv6_base32,
        reversed_compressed_leading,
        reversed_compressed_trailing,
    ])

    return [
        (IPv4_pattern, 'IPv4'),
        (IPv6_pattern, 'IPv6'),
    ]

# --------------------------------------------------------------------------
# Main scanner
def scan_code_for_links(decompiled_code, file_path, **flags):
    """
    Scan the decompiled code for Discord-related URLs, general URLs, domains,
    IP addresses, and obfuscated URLs. The provided flags are passed along to each scanning function.
    """

    # Scan for Discord/Telegram
    contains_discord_or_telegram_code(decompiled_code, file_path, **flags)

    # Scan regular URLs
    url_regex = build_url_regex()
    urls = set(url_regex.findall(decompiled_code))

    # Scan for obfuscated URLs and add decoded versions to the URL set
    obfuscated_results = []
    try:
        obfuscated_results = detect_obfuscated_urls(decompiled_code)
        logger.info(f"Found {len(obfuscated_results)} obfuscated URLs/domains")

        # Add both original and decoded URLs to scanning
        for result in obfuscated_results:
            urls.add(result['original'])
            urls.add(result['decoded'])

            # Log the obfuscated URL detection
            logger.info(f"Obfuscated {result['type']}: {result['original']} -> {result['decoded']}")
    except Exception as e:
        logger.error(f"Error detecting obfuscated URLs: {e}")

    # Process all URLs (regular + obfuscated)
    processed_urls = 0
    for url in urls:
        if not url or len(url.strip()) < 7:  # Skip very short/empty URLs
            continue

        try:
            logger.debug(f"Processing URL: {url}")
            processed_urls += 1

            # Fetch HTML content
            html_content, html_content_file_path = fetch_html(url, return_file_path=True)

            # Scan the fetched HTML content
            if html_content:
                contains_discord_or_telegram_code(html_content, file_path, **flags)
                scan_html_content(html_content, html_content_file_path, **flags)

            # Perform various URL scans
            scan_url_general(url, **flags)
            scan_domain_general(url, **flags)
            scan_spam_email_365_general(url, **flags)

        except Exception as e:
            logger.error(f"Error processing URL {url}: {e}")
            continue

    logger.info(f"Processed {processed_urls} URLs (including {len(obfuscated_results)} obfuscated)")

    # Scan IPs
    ip_patterns = build_ip_patterns()
    processed_ips = 0
    for pattern, ip_type in ip_patterns:
        for m in re.finditer(pattern, decompiled_code):
            ip = m.group(0)
            try:
                scan_ip_address_general(ip, **flags)
                processed_ips += 1
            except Exception as e:
                logger.error(f"Error processing IP {ip}: {e}")
                continue

    logger.info(f"Processed {processed_ips} IP addresses")

    # Save summary of obfuscated findings if any were found
    if obfuscated_results and file_path:
        try:
            obfuscated_summary_path = file_path.replace('.txt', '_obfuscated_summary.txt')
            with open(obfuscated_summary_path, 'w', encoding='utf-8') as f:
                f.write("# Obfuscated URLs/Domains Found\n")
                f.write(f"# Total found: {len(obfuscated_results)}\n")
                f.write(f"# Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                for result in obfuscated_results:
                    f.write(f"Type: {result['type']}\n")
                    f.write(f"Original: {result['original']}\n")
                    f.write(f"Decoded:  {result['decoded']}\n")
                    f.write("-" * 50 + "\n")

            logger.info(f"Obfuscated URL summary saved to: {obfuscated_summary_path}")
        except Exception as e:
            logger.error(f"Error saving obfuscated URL summary: {e}")

def extract_ascii_strings(data):
    """Extract readable ASCII strings from binary data."""
    return re.findall(r'[ -~]{4,}', data.decode('ascii', errors='ignore'))

def save_extracted_strings(output_filename, extracted_strings):
    """Save extracted ASCII strings to a file."""
    with open(output_filename, 'w', encoding='utf-8') as output_file:
        output_file.writelines(f"{line}\n" for line in extracted_strings)

def run_pd64_db_gen(quick=False):
    """Run pd64 -db gen or pd64 -db genquick to create/update clean.hashes in script_dir.

    Args:
        quick (bool): If True, runs 'pd64 -db genquick' instead of 'pd64 -db gen'.

    Returns:
        bool: True if command succeeded, False otherwise.
    """
    cmd = [pd64_path, "-db"]
    if quick:
        cmd.append("genquick")
    else:
        cmd.append("gen")

    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate clean.hashes: {e}")
        return False

def extract_with_unipacker(file_path):
    """
    Extract packed binary using Unipacker library.

    Args:
        file_path (str): Path to the packed executable

    Returns:
        str: Path to unpacked file if successful, None otherwise
    """
    try:
        # Create output path for unpacked file
        base_name = os.path.splitext(file_path)[0]
        unpack_path = f"{base_name}.unpacked.exe"

        logger.info(f"Starting Unipacker extraction for {file_path}")

        # Initialize sample
        sample = Sample(file_path, auto_default_unpacker=True)

        if sample.unpacker is None:
            logger.warning(f"No suitable unpacker found for {file_path}")
            return None

        logger.info(f"Detected packer: {sample.unpacker.name}")

        # Create unpacker engine
        engine = UnpackerEngine(sample, unpack_path)

        # Create a simple client to handle emulation events
        event = threading.Event()
        client = SimpleClient(event)
        engine.register_client(client)

        # Start emulation in a separate thread
        emu_thread = threading.Thread(target=engine.emu)
        emu_thread.daemon = True
        emu_thread.start()

        # Wait for emulation to complete or timeout
        emu_thread.join(timeout=1200)  # 20 minute timeout

        if emu_thread.is_alive():
            logger.warning(f"Unipacker timeout for {file_path}")
            engine.stop()
            return None

        # Check if unpacked file was created
        if os.path.exists(unpack_path) and os.path.getsize(unpack_path) > 0:
            logger.info(f"Successfully unpacked {file_path} to {unpack_path}")
            return unpack_path
        else:
            logger.warning(f"Unpacking failed or produced empty file for {file_path}")
            return None

    except Exception as e:
        logger.error(f"Unipacker extraction failed for {file_path}: {e}")
        return None

def extract_with_pd64(pid: str, output_dir: str) -> bool:
    """Run pd64.exe to dump suspicious modules from a process PID."""
    try:
        subprocess.run([
            pd64_path,
            "-pid",
            pid,
            "-o",
            output_dir
        ], check=True)
        logger.info(f"pd64 extraction complete for PID {pid} into {output_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"pd64 extraction failed for PID {pid}: {e}")
        return False

# Global variables for worm detection
worm_alerted_files = []
worm_detected_count = {}
worm_file_paths = []

# Unified cache for all PE feature extractions (replaces both worm_scan_cache and any ML cache)
unified_pe_cache = {}

def clear_pe_cache():
    """Clear the unified PE feature cache."""
    unified_pe_cache.clear()
    logger.info("Unified PE feature cache cleared")

def get_cached_pe_features(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract and cache PE file numeric features with unified caching.
    Returns cached features if available, otherwise extracts and caches them.
    Used by both ML scanning and worm detection.
    """
    # Calculate MD5 hash for caching
    file_md5 = compute_md5(file_path)
    if not file_md5:
        return None

    # Check if we already have features for this MD5
    if file_md5 in unified_pe_cache:
        logger.debug(f"Using cached features for {file_path} (MD5: {file_md5})")
        return unified_pe_cache[file_md5]

    try:
        # Extract numeric features
        features = pe_extractor.extract_numeric_features(file_path)
        if features:
            # Cache the result with MD5 as key
            unified_pe_cache[file_md5] = features
            logger.debug(f"Cached features for {file_path} (MD5: {file_md5})")
            return features
        else:
            # Cache negative result too to avoid re-processing failed files
            unified_pe_cache[file_md5] = None
            return None

    except Exception as ex:
        logger.error(f"An error occurred while processing {file_path}: {ex}", exc_info=True)
        # Cache the failure to avoid repeated attempts
        unified_pe_cache[file_md5] = None
        return None

def scan_file_with_machine_learning_ai(file_path, threshold=0.86):
    """Scan a file for malicious activity using machine learning definitions loaded from JSON."""
    malware_definition = "Unknown"
    logger.info(f"Starting machine learning scan for file: {file_path}")

    try:
        pe = pefile.PE(file_path)
        pe.close()
    except pefile.PEFormatError:
        logger.error(f"File {file_path} is not a valid PE file. Returning default value 'Unknown'.")
        return False, malware_definition, 0

    logger.info(f"File {file_path} is a valid PE file, proceeding with feature extraction.")

    # Use unified cache for feature extraction
    file_numeric_features = get_cached_pe_features(file_path)
    if not file_numeric_features:
        return False, "Feature-Extraction-Failed", 0

    is_malicious_ml = False
    nearest_malicious_similarity = 0
    nearest_benign_similarity = 0

    # Check malicious definitions
    for ml_feats, info in zip(malicious_numeric_features, malicious_file_names):
        similarity = calculate_vector_similarity(file_numeric_features, ml_feats)
        nearest_malicious_similarity = max(nearest_malicious_similarity, similarity)

        if similarity >= threshold:
            is_malicious_ml = True

            # Handle both string and dict cases
            if isinstance(info, dict):
                malware_definition = info.get('file_name', 'Unknown')
                rank = info.get('numeric_tag', 'N/A')
            elif isinstance(info, str):
                malware_definition = info
                rank = 'N/A'
            else:
                malware_definition = str(info)
                rank = 'N/A'

            logger.critical(f"Malicious activity detected in {file_path}. Definition: {malware_definition}, similarity: {similarity}, rank: {rank}")

    # If not malicious, check benign
    if not is_malicious_ml:
        for ml_feats, info in zip(benign_numeric_features, benign_file_names):
            similarity = calculate_vector_similarity(file_numeric_features, ml_feats)
            nearest_benign_similarity = max(nearest_benign_similarity, similarity)

            # Handle both string and dict cases
            if isinstance(info, dict):
                benign_definition = info.get('file_name', 'Unknown')
            elif isinstance(info, str):
                benign_definition = info
            else:
                benign_definition = str(info)

        if nearest_benign_similarity >= 0.93:
            malware_definition = "Benign"
            logger.info(f"File {file_path} is classified as benign ({benign_definition}) with similarity: {nearest_benign_similarity}")
        else:
            malware_definition = "Unknown"
            logger.info(f"File {file_path} is classified as unknown with similarity: {nearest_benign_similarity}")

    # Return result
    if is_malicious_ml:
        return True, malware_definition, nearest_malicious_similarity
    else:
        return False, malware_definition, nearest_benign_similarity

def restart_service(service_name, stop_only=False):
    """Restart or stop a Windows service using native service management."""
    try:
        # Check if service exists
        if not service_exists(service_name):
            logger.error(f"Service '{service_name}' does not exist on this system.")
            return False

        # Stop service if running
        if is_service_running(service_name):
            logger.info(f"Stopping service '{service_name}'...")
            try:
                win32serviceutil.StopService(service_name)
                logger.info(f"Service '{service_name}' stopped successfully.")
            except Exception as ex:
                logger.error(f"Failed to stop service '{service_name}': {ex}")
                return False
        else:
            logger.info(f"Service '{service_name}' is not running, skipping stop step.")

        # If only stopping, return now
        if stop_only:
            return True

        # Start service
        logger.info(f"Starting service '{service_name}'...")
        try:
            win32serviceutil.StartService(service_name)

            # Verify service is running
            if is_service_running(service_name):
                logger.info(f"Service '{service_name}' started successfully.")
                return True
            else:
                logger.error(f"Service start command succeeded but '{service_name}' is not running.")
                return False

        except Exception as ex:
            logger.error(f"Failed to start service '{service_name}': {ex}")
            return False

    except Exception as ex:
        logger.error(f"An error occurred while managing service '{service_name}': {ex}")
        return False

clamav_scanner = clamav.Scanner(libclamav_path=libclamav_path, dbpath=clamav_database_directory_path)

def reload_clamav_database():
    """
    Reloads the ClamAV engine with the updated database.
    Required after updating signatures.
    """
    try:
        logger.info("Reloading ClamAV database...")
        clamav_scanner.loadDB()
        logger.info("ClamAV database reloaded successfully.")
    except Exception as ex:
        logger.error(f"Failed to reload ClamAV database: {ex}")

def restart_owlyshield_threaded(stop_only=False):
    """Restart or stop Owlyshield services in a separate thread."""
    def manage_owlyshield():
        try:
            logger.info(f"{'Stopping' if stop_only else 'Restarting'} OwlyshieldRansomFilter service...")
            if restart_service('OwlyshieldRansomFilter', stop_only=stop_only):
                logger.info(f"OwlyshieldRansomFilter service {'stopped' if stop_only else 'restarted'} successfully.")
            else:
                logger.error(f"OwlyshieldRansomFilter service {'stop' if stop_only else 'restart'} failed.")
        except Exception as ex:
            logger.error(f"Exception during OwlyshieldRansomFilter {'stop' if stop_only else 'restart'}: {ex}")

        try:
            logger.info(f"{'Stopping' if stop_only else 'Restarting'} Owlyshield Service...")
            if restart_service('Owlyshield Service', stop_only=stop_only):
                logger.info(f"Owlyshield Service {'stopped' if stop_only else 'restarted'} successfully.")
            else:
                logger.error(f"Owlyshield Service {'stop' if stop_only else 'restart'} failed.")
        except Exception as ex:
            logger.error(f"Exception during Owlyshield Service {'stop' if stop_only else 'restart'}: {ex}")

    try:
        thread = threading.Thread(target=manage_owlyshield)
        thread.start()
        thread.join()  # Wait for the thread to finish
    except Exception as ex:
        logger.error(f"Error starting thread for Owlyshield {'stop' if stop_only else 'restart'}: {ex}")

def scan_file_with_clamav(file_path):
    """Scan file using the in-process ClamAV wrapper (scanner) and return virus name or 'Clean'."""
    try:
        file_path = os.path.abspath(file_path)
        ret, virus_name = clamav_scanner.scanFile(file_path)

        if ret == clamav.CL_CLEAN:
            return "Clean"
        elif ret == clamav.CL_VIRUS:
            return virus_name or "Infected"
        else:
            logger.error(f"Unexpected ClamAV scan result for {file_path}: {ret}")
            return "Error"
    except Exception as ex:
        logger.error(f"Error scanning file {file_path}: {ex}")
        return "Error"

def is_related_to_critical_paths(file_path: str) -> bool:
    """
    Checks whether a file is part of critical paths.
    Returns True if:
    - The file is inside sandboxie_folder
    - The file is the main file
    - The file has already been scanned (is in seen_files)
    """
    if not isinstance(file_path, str):
        return False
    norm_path = os.path.abspath(file_path)

    # Check if file is in seen_files
    if any(norm_path.lower() == path for path, _ in seen_files):
        return True

    # Check sandbox folder or main file
    return norm_path.startswith(sandboxie_folder) or norm_path == main_file_path

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

    # Helper function to check if domain is in CSV data
    def is_domain_in_data(self, domain, data_list):
        for entry in data_list:
            if entry['address'] == domain:
                return True, entry['reference']
        return False, ""

    # Helper function to check if IP is in CSV data
    def is_ip_in_data(self, ip, data_list):
        for entry in data_list:
            if entry['address'] == ip:
                return True, entry['reference']
        return False, ""

    def handle_detection(self, entity_type, entity_value, detection_type=None, reference=""):
        """
        Handle a detection event for a given entity (domain, IP, URL).
        Only notify if there is a non-empty entity value and it maps to a file or critical path.
        """
        # Early exit if entity_value is empty or None
        if not entity_value:
            return

        file_path = self.map_domain_ip_to_file(entity_value)
        notify_info = {
            'domain': None,
            'ipv4_address': None,
            'ipv6_address': None,
            'url': None,
            'file_path': None,
            'detection_type': detection_type,
            'reference': reference
        }

        try:
            # Determine message and notification fields
            if file_path and is_related_to_critical_paths(file_path):
                # Critical path detection
                message = f"{entity_type.capitalize()} {entity_value} is related to a critical path: {file_path}"
                if detection_type:
                    message = f"{detection_type} {message}"
                if reference:
                    message += f" Reference: {reference}"
                logger.critical(message)

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
                if reference:
                    message += f" Reference: {reference}"
                logger.info(message)

            # Only notify if there's meaningful data (ignore detection_type alone)
            has_data = any(
                notify_info[field] for field in ['domain', 'ipv4_address', 'ipv6_address', 'url', 'file_path']
            )
            if has_data:
                notify_user_for_web(**notify_info)

        except Exception as ex:
            logger.error(f"Error in handle_detection: {ex}")

    def extract_ip_addresses(self, text):
        """Extract IPv4 and IPv6 addresses from text using regex."""
        ips = re.findall(IPv4_pattern_standard, text)
        ips += re.findall(IPv6_pattern_standard, text)
        return ips

    def extract_urls(self, text):
        """Extract URLs from text using regex."""
        url_regex_standard = r'https?://[^\s"<>]+'
        return re.findall(url_regex_standard, text)

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

            # Define whitelist checks with their respective types
            whitelist_checks = [
                (whitelist_sub_domains_data, "subdomain"),
                (whitelist_mail_sub_domains_data, "mail subdomain"),
                (whitelist_domains_data, "domain"),
                (whitelist_domains_mail_data, "mail domain")
            ]

            # Check whitelists first
            for data_list, whitelist_type in whitelist_checks:
                is_whitelisted, reference = self.is_domain_in_data(main_domain, data_list)
                if is_whitelisted:
                    logger.info(f"Domain {main_domain} is whitelisted ({whitelist_type}). Reference: {reference}")
                    return

            # Check against threat lists with address-reference structure
            threat_checks = [
                (spam_sub_domains_data, 'subdomain', 'SPAM SUBDOMAIN'),
                (mining_sub_domains_data, 'subdomain', 'MINING SUBDOMAIN'),
                (abuse_sub_domains_data, 'subdomain', 'ABUSE SUBDOMAIN'),
                (phishing_sub_domains_data, 'subdomain', 'PHISHING SUBDOMAIN'),
                (malware_sub_domains_data, 'subdomain', 'MALWARE SUBDOMAIN'),
                (malware_mail_sub_domains_data, 'subdomain', 'MALWARE MAIL SUBDOMAIN'),
                (spam_domains_data, 'domain', 'SPAM'),
                (mining_domains_data, 'domain', 'MINING'),
                (abuse_domains_data, 'domain', 'ABUSE'),
                (phishing_domains_data, 'domain', 'PHISHING'),
                (malware_domains_data, 'domain', 'MALWARE'),
                (malware_domains_mail_data, 'domain', 'MALWARE MAIL')
            ]

            for data_list, entity_type_check, detection_type_check in threat_checks:
                is_threat, reference = self.is_domain_in_data(main_domain, data_list)
                if is_threat:
                    self.handle_detection(entity_type_check, main_domain, detection_type_check, reference)
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
            if not is_valid_ip(ip_address):
                logger.info(f"Skipping non valid IP address: {ip_address}")
                return

            # signatures
            if kind == 'ipv6':
                logger.info(f"Scanning IPv6 address: {ip_address}")

                # Check whitelist first
                is_whitelisted, reference = self.is_ip_in_data(ip_address, ipv6_whitelist_data)
                if is_whitelisted:
                    logger.info(f"IPv6 address {ip_address} is whitelisted. Reference: {reference}")
                    return

                # Check threat lists
                threat_checks = [
                    (ipv6_addresses_ddos_signatures_data, 'DDOS'),
                    (ipv6_addresses_spam_signatures_data, 'SPAM'),
                    (ipv6_addresses_signatures_data, 'MALWARE')
                ]

                for data_list, detection_type_check in threat_checks:
                    is_threat, reference = self.is_ip_in_data(ip_address, data_list)
                    if is_threat:
                        self.handle_detection('ipv6_address', ip_address, detection_type_check, reference)
                        return

                logger.info(f"Unknown IPv6 address detected: {ip_address}")

            else:  # ipv4
                logger.info(f"Scanning IPv4 address: {ip_address}")

                # Check whitelist first
                is_whitelisted, reference = self.is_ip_in_data(ip_address, ipv4_whitelist_data)
                if is_whitelisted:
                    logger.info(f"IPv4 address {ip_address} is whitelisted. Reference: {reference}")
                    return

                # Check threat lists
                threat_checks = [
                    (ipv4_addresses_phishing_active_signatures_data, 'PHISHING_ACTIVE'),
                    (ipv4_addresses_phishing_inactive_signatures_data, 'PHISHING_INACTIVE'),
                    (ipv4_addresses_bruteforce_signatures_data, 'BRUTEFORCE'),
                    (ipv4_addresses_spam_signatures_data, 'SPAM'),
                    (ipv4_addresses_signatures_data, 'MALWARE')
                ]

                for data_list, detection_type_check in threat_checks:
                    is_threat, reference = self.is_ip_in_data(ip_address, data_list)
                    if is_threat:
                        self.handle_detection('ipv4_address', ip_address, detection_type_check, reference)
                        return

                logger.info(f"Unknown IPv4 address detected: {ip_address}")

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
                    logger.critical(message)
                    self.handle_detection('url', url, 'URLhaus Match')
                    return

            # Heuristic check using uBlock detection (e.g., Steam Community pattern).
            if ublock_detect(url):
                self.handle_detection('url', url, 'HEUR:Phish.Steam.Community.gen')
                logger.critical(
                    f"URL {url} flagged by uBlock detection using HEUR:Phish.Steam.Community.gen."
                )
                return

            logger.info(f"No match found for URL: {url}")

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
                        logger.info(f"DNS Query (IPv4): {qn}")
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        an = packet[DNSRR][i].rrname.decode().rstrip('.')
                        self.scan_domain(an)
                        logger.info(f"DNS Answer (IPv4): {an}")

                self.scan_ipv4_address(packet[IP].src)
                self.scan_ipv4_address(packet[IP].dst)
        except Exception as ex:
            logger.error(f"Error handling IPv4 packet: {ex}")

    def handle_ipv6(self, packet):
        try:
            if IPv6 in packet and DNS in packet:
                if packet[DNS].qd:
                    for i in range(packet[DNS].qdcount):
                        qn = packet[DNSQR][i].qname.decode().rstrip('.')
                        self.scan_domain(qn)
                        logger.info(f"DNS Query (IPv6): {qn}")
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        an = packet[DNSRR][i].rrname.decode().rstrip('.')
                        self.scan_domain(an)
                        logger.info(f"DNS Answer (IPv6): {an}")

                self.scan_ipv6_address(packet[IPv6].src)
                self.scan_ipv6_address(packet[IPv6].dst)
            else:
                logger.debug("IPv6 layer or DNS layer not found in the packet.")
        except Exception as ex:
            logger.error(f"Error handling IPv6 packet: {ex}")

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
                        logger.info(f"DNS Query: {qn}")
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        an = packet[DNSRR][i].rrname.decode().rstrip('.')
                        self.scan_domain(an)
                        logger.info(f"DNS Answer: {an}")
                if IP in packet:
                    self.scan_ipv4_address(packet[IP].src)
                    self.scan_ipv4_address(packet[IP].dst)
                if IPv6 in packet:
                    self.scan_ipv6_address(packet[IPv6].src)
                    self.scan_ipv6_address(packet[IPv6].dst)
        except Exception as ex:
            logger.error(f"Error processing packet: {ex}")


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
            logger.info(message)

    def start_sniffing(self):
        filter_expression = "(tcp or udp)"
        try:
            sniff(filter=filter_expression, prn=self.handler.on_packet_received, store=0)
        except Exception as ex:
            logger.error(f"An error occurred while sniffing packets: {ex}")


web_protection_observer = RealTimeWebProtectionObserver()

def scan_yara(file_path):
    """Scan file with multiple YARA rule sets in parallel using threads."""

    # Shared variables for results
    results = {
        'matched_rules': [],
        'matched_results': [],
        'vmprotect_unpacked_file': None
    }

    # Lock for thread-safe access to shared variables
    threads = []

    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found during YARA scan: {file_path}")
            return None, None, None

        with open(file_path, 'rb') as yara_file:
            data_content = yara_file.read()

        # Helper function to extract detailed match info for regular YARA
        def extract_match_details(match, rule_source):
            match_info = {
                'rule_name': match.rule,
                'rule_source': rule_source,
                'strings': [],
                'tags': getattr(match, 'tags', []),
                'meta': getattr(match, 'meta', {}),
                'namespace': getattr(match, 'namespace', None)
            }

            # Extract string matches with offsets
            if hasattr(match, 'strings'):
                for string_match in match.strings:
                    string_info = {
                        'identifier': string_match.identifier,
                        'instances': []
                    }

                    for instance in string_match.instances:
                        instance_info = {
                            'offset': instance.offset,
                            'length': instance.length,
                            'matched_data': data_content[instance.offset:instance.offset + instance.length]
                        }
                        # Convert bytes to hex for binary data, or decode as text if possible
                        try:
                            instance_info['matched_text'] = instance_info['matched_data'].decode('utf-8', errors='ignore')
                        except:
                            instance_info['matched_text'] = None

                        instance_info['matched_hex'] = instance_info['matched_data'].hex()
                        string_info['instances'].append(instance_info)

                    match_info['strings'].append(string_info)

            return match_info

        # Fixed helper function for YARA-X matches
        def extract_yarax_match_details(rule, rule_source):
            match_info = {
                'rule_name': rule.identifier,
                'rule_source': rule_source,
                'strings': [],
                'tags': list(rule.tags) if hasattr(rule, 'tags') else [],
                'meta': dict(rule.metadata) if hasattr(rule, 'metadata') else {},
                'namespace': rule.namespace if hasattr(rule, 'namespace') else None
            }

            # YARA-X string pattern extraction
            if hasattr(rule, 'patterns'):
                for pattern in rule.patterns:
                    string_info = {
                        'identifier': pattern.identifier,
                        'instances': []
                    }

                    # Get matches for this pattern
                    for match in pattern.matches:
                        instance_info = {
                            'offset': match.offset,
                            'length': match.length,
                            'matched_data': data_content[match.offset:match.offset + match.length]
                        }

                        # Convert bytes to text/hex
                        try:
                            instance_info['matched_text'] = instance_info['matched_data'].decode('utf-8', errors='ignore')
                        except:
                            instance_info['matched_text'] = None

                        instance_info['matched_hex'] = instance_info['matched_data'].hex()
                        string_info['instances'].append(instance_info)

                    match_info['strings'].append(string_info)

            return match_info

        # Thread worker for compiled_rule scanning
        def clean_rules_worker():
            try:
                if clean_rules:
                    matches = clean_rules.match(data=data_content)
                    local_matched_rules = []
                    local_matched_results = []
                    local_vmprotect_file = None

                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            local_matched_rules.append(match.rule)
                            match_details = extract_match_details(match, 'clean_rules')
                            local_matched_results.append(match_details)

                        # VMProtect unpacking
                        if match.rule == "INDICATOR_EXE_Packed_VMProtect":
                            try:
                                with open(file_path, 'rb') as f:
                                    packed_data = f.read()
                                unpacked_data = unpack_pe(packed_data)
                                if unpacked_data:
                                    base_name, ext = os.path.splitext(os.path.basename(file_path))
                                    unpacked_name = f"{base_name}_vmprotect_unpacked{ext}"
                                    unpacked_path = os.path.join(vmprotect_unpacked_dir, unpacked_name)

                                    with open(unpacked_path, 'wb') as f:
                                        f.write(unpacked_data)

                                    local_vmprotect_file = unpacked_path
                                    logger.info(f"VMProtect unpacked successfully: {unpacked_path}")
                            except Exception as e:
                                logger.error(f"Error unpacking after VMProtect indicator: {e}")

                    # Update shared results
                    with thread_lock:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                        if local_vmprotect_file:
                            results['vmprotect_unpacked_file'] = local_vmprotect_file
                else:
                    logger.error("clean_rules is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with clean_rules: {e}")

        # Thread worker for yarGen_rule scanning
        def yargen_rule_worker():
            try:
                if yarGen_rule:
                    matches = yarGen_rule.match(data=data_content)
                    local_matched_rules = []
                    local_matched_results = []

                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            local_matched_rules.append(match.rule)
                            match_details = extract_match_details(match, 'yarGen_rule')
                            local_matched_results.append(match_details)
                        else:
                            logger.info(f"Rule {match.rule} is excluded from yarGen_rule.")

                    # Update shared results
                    with thread_lock:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                else:
                    logger.error("yarGen_rule is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with yarGen_rule: {e}")

        # Thread worker for icewater_rule scanning
        def icewater_rule_worker():
            try:
                if icewater_rule:
                    matches = icewater_rule.match(data=data_content)
                    local_matched_rules = []
                    local_matched_results = []

                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            local_matched_rules.append(match.rule)
                            match_details = extract_match_details(match, 'icewater_rule')
                            local_matched_results.append(match_details)
                        else:
                            logger.info(f"Rule {match.rule} is excluded from icewater_rule.")

                    # Update shared results
                    with thread_lock:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                else:
                    logger.error("icewater_rule is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with icewater_rule: {e}")

        # Thread worker for valhalla_rule scanning
        def valhalla_rule_worker():
            try:
                if valhalla_rule:
                    matches = valhalla_rule.match(data=data_content)
                    local_matched_rules = []
                    local_matched_results = []

                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            local_matched_rules.append(match.rule)
                            match_details = extract_match_details(match, 'valhalla_rule')
                            local_matched_results.append(match_details)
                        else:
                            logger.info(f"Rule {match.rule} is excluded from valhalla_rule.")

                    # Update shared results
                    with thread_lock:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                else:
                    logger.error("valhalla_rule is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with valhalla_rule: {e}")

        # Thread worker for yaraxtr_rule scanning (YARA-X)
        def yaraxtr_rule_worker():
            try:
                if yaraxtr_rule:
                    scanner = yara_x.Scanner(rules=yaraxtr_rule)
                    scan_results = scanner.scan(data_content)
                    local_matched_rules = []
                    local_matched_results = []

                    # Iterate through matching rules
                    for rule in scan_results.matching_rules:
                        if rule.identifier not in excluded_rules:
                            local_matched_rules.append(rule.identifier)
                            match_details = extract_yarax_match_details(rule, 'yaraxtr_rule')
                            local_matched_results.append(match_details)
                        else:
                            logger.info(f"Rule {rule.identifier} is excluded from yaraxtr_rule.")

                    # Update shared results
                    with thread_lock:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                else:
                    logger.error("yaraxtr_rule is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with yaraxtr_rule: {e}")

        # Create and start all threads
        workers = [
            clean_rules_worker,
            yargen_rule_worker,
            icewater_rule_worker,
            valhalla_rule_worker,
            yaraxtr_rule_worker
        ]

        for worker in workers:
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Return results
        return (results['matched_rules'] if results['matched_rules'] else None,
                results['matched_results'] if results['matched_results'] else None,
                results['vmprotect_unpacked_file'])

    except Exception as ex:
        logger.error(f"An error occurred during YARA scan: {ex}")
        return None, None, None

def detect_etw_tampering_sandbox(moved_sandboxed_ntdll_path):
    """
    Compare the NtTraceEvent bytes in the sandboxed ntdll.dll file against the original
    on-disk ntdll.dll in System32.
    Logs a warning if the sandboxed copy is tampered (bytes differ).
    Returns True if tampered, False otherwise.
    """
    try:
        if not os.path.isfile(ntdll_path):
            logger.error(f"[ETW Sandbox Detection] Original ntdll.dll not found at {ntdll_path}")
            return False
        if not os.path.isfile(moved_sandboxed_ntdll_path):
            logger.error(f"[ETW Sandbox Detection] Sandboxed ntdll.dll not found at {moved_sandboxed_ntdll_path}")
            return False

        # Load original PE to find NtTraceEvent RVA
        try:
            pe_orig = pefile.PE(ntdll_path, fast_load=True)
            pe_orig.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        except Exception as e:
            logger.error(f"[ETW Sandbox Detection] Failed to parse original PE: {e}")
            return False

        nttrace_rva = None
        for exp in getattr(pe_orig, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
            if exp.name and exp.name.decode(errors='ignore') == "NtTraceEvent":
                nttrace_rva = exp.address
                break
        if nttrace_rva is None:
            logger.error("[ETW Sandbox Detection] Export NtTraceEvent not found in original ntdll.dll")
            return False

        # Compute offset in original file
        try:
            orig_offset = pe_orig.get_offset_from_rva(nttrace_rva)
        except Exception as e:
            logger.error(f"[ETW Sandbox Detection] Cannot compute offset in original for RVA {hex(nttrace_rva)}: {e}")
            return False

        # Load sandboxed PE to compute offset there
        try:
            pe_sandbox = pefile.PE(moved_sandboxed_ntdll_path, fast_load=True)
            pe_sandbox.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        except Exception as e:
            logger.error(f"[ETW Sandbox Detection] Failed to parse sandboxed PE: {e}")
            return False

        # Verify that sandboxed export table contains NtTraceEvent (optional but good)
        found_in_sandbox = False
        for exp in getattr(pe_sandbox, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
            if exp.name and exp.name.decode(errors='ignore') == "NtTraceEvent":
                found_in_sandbox = True
                break
        if not found_in_sandbox:
            logger.error("[ETW Sandbox Detection] Export NtTraceEvent not found in sandboxed ntdll.dll")
            return False

        # Compute offset in sandboxed file
        try:
            sandbox_offset = pe_sandbox.get_offset_from_rva(nttrace_rva)
        except Exception as e:
            logger.error(f"[ETW Sandbox Detection] Cannot compute offset in sandboxed for RVA {hex(nttrace_rva)}: {e}")
            return False

        # Read bytes
        length = 16
        try:
            with open(ntdll_path, "rb") as f_orig:
                f_orig.seek(orig_offset)
                orig_bytes = f_orig.read(length)
            if len(orig_bytes) < length:
                logger.error(f"[ETW Sandbox Detection] Could not read {length} bytes from original ntdll.dll")
                return False
        except Exception as e:
            logger.error(f"[ETW Sandbox Detection] Error reading original file: {e}")
            return False

        try:
            with open(moved_sandboxed_ntdll_path, "rb") as f_s:
                f_s.seek(sandbox_offset)
                sandbox_bytes = f_s.read(length)
            if len(sandbox_bytes) < length:
                logger.error(f"[ETW Sandbox Detection] Could not read {length} bytes from sandboxed ntdll.dll")
                return False
        except Exception as e:
            logger.error(f"[ETW Sandbox Detection] Error reading sandboxed file: {e}")
            return False

        # Compare
        if sandbox_bytes != orig_bytes:
            orig_hex = orig_bytes[:8].hex()
            sand_hex = sandbox_bytes[:8].hex()
            logger.critical(
                f"[ETW Sandbox Detection] Sandboxed ntdll.dll NtTraceEvent seems patched: "
                f"original bytes={orig_hex}, sandbox bytes={sand_hex}"
            )
            return True

        # No tampering detected
        return False

    except Exception as ex:
        logger.error(f"[ETW Sandbox Detection] Unexpected error: {ex}")
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
        logger.debug(f"Failed to extract certificate info: {e}")
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
CERT_E_UNTRUSTEDROOT         = 0x800B0109
TRUST_E_BAD_DIGEST           = 0x80096010
TRUST_E_CERT_SIGNATURE       = 0x80096004

NO_SIGNATURE_CODES = {
    TRUST_E_NOSIGNATURE,
    TRUST_E_SUBJECT_FORM_UNKNOWN,
    TRUST_E_PROVIDER_UNKNOWN,
}

# Constants for WinVerifyTrust
class WinVerifyTrust_GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

WINTRUST_ACTION_GENERIC_VERIFY_V2 = WinVerifyTrust_GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(WinVerifyTrust_GUID)),
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
    # --- cache check first --- #
    try:
        md5 = compute_md5(file_path)
    except FileNotFoundError:
        return {
            "is_valid": False,
            "status": "File not found",
            "signature_status_issues": False,
            "no_signature": True,
            "has_microsoft_signature": False,
            "has_valid_goodsign_signature": False,
            "matches_antivirus_signature": False
        }

    if file_path in file_md5_cache:
        last_md5, cached_result = file_md5_cache[file_path]
        if last_md5 == md5:
            return cached_result  # return from cache

    # --- run full signature verification --- #
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
        result = {
            "is_valid": False,
            "status": "No signature",
            "signature_status_issues": False,
            "no_signature": True,
            "has_microsoft_signature": False,
            "has_valid_goodsign_signature": False,
            "matches_antivirus_signature": False
        }
        file_md5_cache[file_path] = (md5, result)
        return result

    try:
        pCertCtx = crypt32.CertEnumCertificatesInStore(hStore, None)
        if not pCertCtx:
            result = {
                "is_valid": False,
                "status": "No signature",
                "signature_status_issues": False,
                "no_signature": True,
                "has_microsoft_signature": False,
                "has_valid_goodsign_signature": False,
                "matches_antivirus_signature": False
            }
            file_md5_cache[file_path] = (md5, result)
            return result

        hresult = verify_authenticode_signature(file_path)
        hresult = hresult & 0xFFFFFFFF

        is_valid = (hresult == 0)
        no_sig   = (hresult in NO_SIGNATURE_CODES)

        if is_valid:
            status = "Valid"
        elif no_sig:
            status = "No signature"
        elif hresult == CERT_E_UNTRUSTEDROOT:
            status = "Untrusted root"
        elif hresult == TRUST_E_BAD_DIGEST:
            status = f"Fully invalid (bad digest) (HRESULT=0x{hresult:08X})"
        elif hresult == TRUST_E_CERT_SIGNATURE:
            status = f"Fully invalid (cert signature verify failed) (HRESULT=0x{hresult:08X})"
        else:
            status = f"Invalid signature (HRESULT=0x{hresult:08X})"

        signature_status_issues = (not is_valid) and (not no_sig)

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

        result = {
            "is_valid": is_valid,
            "status": status,
            "signature_status_issues": signature_status_issues,
            "no_signature": no_sig,
            "has_microsoft_signature": has_ms_sig,
            "has_valid_goodsign_signature": has_goodsign,
            "matches_antivirus_signature": matches_av
        }

        # save to cache
        file_md5_cache[file_path] = (md5, result)
        return result

    finally:
        # always clean up
        if pCertCtx:
            crypt32.CertFreeCertificateContext(pCertCtx)
        if hStore:
            crypt32.CertCloseStore(hStore, 0)
        if hMsg:
            crypt32.CryptMsgClose(hMsg)

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
        logger.info(f"RLO detected after dot in '{filename}', checking extension '{ext}'")
        has_known_ext = ext in fileTypes
        if has_known_ext:
            logger.critical(f"POTENTIAL RLO ATTACK: File '{filename}' has RLO after dot with known extension '{ext}'")
        else:
            logger.info(f"RLO found after dot but extension '{ext}' not in known types")
        return has_known_ext
    except Exception as ex:
        logger.error(f"Error checking RLO and extension for file {filename}: {ex}")
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
            logger.critical(f"SUSPICIOUS FILENAME DETECTED: {filename} - {results['details']}")

        return results

    except Exception as ex:
        logger.error(f"Error analyzing filename {filename}: {ex}")
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
            logger.error("Invalid Nuitka payload magic")

        magic_type = self.data[2]
        if magic_type == self.MAGIC_UNCOMPRESSED:
            self.compression = CompressionFlag.NON_COMPRESSED
        elif magic_type == self.MAGIC_COMPRESSED:
            self.compression = CompressionFlag.COMPRESSED
        else:
            logger.error(f"Unknown compression magic: {magic_type}")

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
                logger.error(f"Failed to initialize decompression: {str(ex)}")
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

        if is_pe_file_from_output(die_output, self.filepath):
            return FileType.PE
        if is_elf_file_from_output(die_output, self.filepath):
            return FileType.ELF
        if is_macho_file_from_output(die_output, self.filepath):
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
                logger.error("No resource directory found")

            offset, size = self._find_pe_resource(pe)
            if offset is None or size is None:
                logger.error("No Nuitka payload found in PE resources")

            # Read the payload data
            with open(self.filepath, 'rb') as f:
                f.seek(offset)
                payload_data = f.read(size)

            return NuitkaPayload(payload_data, offset, size)

        except Exception as ex:
            logger.error(f"PE payload extraction failed: {str(ex)}")

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
            logger.error(f"ELF payload extraction failed: {str(ex)}")

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

            logger.error("No payload section found in Mach-O file")

        except Exception as ex:
            logger.error(f"Mach-O payload extraction failed: {str(ex)}")

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
                                logger.error(f"Incomplete read for {filename}")
                                break
                            f.write(data)
                            remaining -= len(data)
                    total_files += 1
                    logger.info(f"[+] Extracted: {filename}")
                except Exception as ex:
                    logger.error(f"Failed to extract {filename}: {ex}")
                    continue

        except Exception as ex:
            logger.error(f"Extraction error: {ex}")

        return total_files

    def extract(self):
        """Main extraction process"""
        try:
            # Detect file type using the new detection methods
            self.file_type = self._detect_file_type()
            if self.file_type == FileType.UNKNOWN:
                logger.error("Unsupported file type")

            logger.info(f"[+] Processing: {self.filepath}")
            logger.info(f"[+] Detected file type: {['ELF', 'PE', 'MACHO'][self.file_type]}")

            # Extract payload based on file type
            if self.file_type == FileType.PE:
                self.payload = self._extract_pe_payload()
            elif self.file_type == FileType.ELF:
                self.payload = self._extract_elf_payload()
            else:  # MACHO
                self.payload = self._extract_macho_payload()

            if not self.payload:
                logger.error("Failed to extract payload")

            logger.info(f"[+] Payload size: {self.payload.size} bytes")
            logger.info(f"[+] Compression: {'Yes' if self.payload.compression == CompressionFlag.COMPRESSED else 'No'}")

            # Extract files from payload
            stream = self.payload.get_stream()
            total_files = self._extract_files(stream)

            logger.info(f"[+] Successfully extracted {total_files} files to {self.output_dir}")

        except Exception as ex:
            logger.error(f"[!] Unexpected error: {str(ex)}")


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
        logger.error(f"Not a valid ZIP archive: {file_path}")
        return False, []
    except Exception as ex:
        logger.error(f"Error scanning zip file: {file_path} {ex}")
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
        logger.error(f"Not a valid 7z archive: {file_path}")
        return False, []
    except Exception as ex:
        logger.error(f"Error scanning 7z file: {file_path} {ex}")
        return False, []

def is_7z_file_from_output(die_output: str) -> bool:
    """
    Checks if DIE output indicates a 7-Zip archive.
    Expects the raw stdout (or equivalent) from a Detect It Easy run.
    """
    if die_output and "Archive: 7-Zip" in die_output:
        logger.info("DIE output indicates a 7z archive.")
        return True

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

                    logger.critical(
                        f"Filename '{member.name}' in archive '{file_path}' contains suspicious pattern(s): {attack_string} - "
                        f"flagged as {virus_name}"
                    )
                    notify_susp_archive_file_name_warning(file_path, "TAR", virus_name)

                if member.isreg():  # Check if it's a regular file
                    extracted_file_path = os.path.join(tar_extracted_dir, member.name)

                    # Skip if the file has already been processed
                    if os.path.isfile(extracted_file_path):
                        logger.info(f"File {member.name} already processed, skipping...")
                        continue

                    # Extract the file
                    tar.extract(member, tar_extracted_dir)

                    # Check for suspicious conditions: large files in small TAR archives
                    extracted_file_size = os.path.getsize(extracted_file_path)
                    if tar_size < 20 * 1024 * 1024 and extracted_file_size > 650 * 1024 * 1024:
                        virus_name = "HEUR:Win32.Susp.Size.Encrypted.TAR"
                        logger.critical(
                            f"TAR file {file_path} is smaller than 20MB but contains a large file: {member.name} "
                            f"({extracted_file_size / (1024 * 1024):.2f} MB) - flagged as {virus_name}. "
                            "Potential TARbomb or Fake Size detected to avoid VirusTotal detections."
                        )
                        notify_size_warning(file_path, "TAR", virus_name)

        return True, []
    except Exception as ex:
        logger.error(f"Error scanning tar file: {file_path} - {ex}")
        return False, ""

def extract_numeric_worm_features(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract numeric features of a file using pefile for worm detection.
    Uses unified caching system shared with ML scanning.

    Returns:
        Dict containing numeric features if successful, None if failed
    """
    return get_cached_pe_features(file_path)

def check_worm_similarity(file_path: str, features_current: List[float]) -> bool:
    """
    Check similarity between the main file, collected files, and the current file for worm detection.
    Uses cached features when available.
    """
    worm_detected = False

    try:
        # Compare with the main file if available and distinct from the current file
        if main_file_path and main_file_path != file_path:
            features_main = extract_numeric_worm_features(main_file_path)
            if features_main:
                similarity_main = calculate_vector_similarity(features_current, features_main)
                if similarity_main > 0.86:
                    logger.critical(
                        f"Main file '{main_file_path}' is potentially spreading the worm to '{file_path}' "
                        f"with similarity score: {similarity_main:.2f}"
                    )
                    worm_detected = True

        # Compare with each collected file in the file paths
        for collected_file_path in worm_file_paths:
            if collected_file_path != file_path:
                features_collected = extract_numeric_worm_features(collected_file_path)
                if features_collected:
                    similarity_collected = calculate_vector_similarity(features_current, features_collected)
                    if similarity_collected > 0.86:
                        logger.critical(
                            f"Worm has potentially spread to '{collected_file_path}' "
                            f"from '{file_path}' with similarity score: {similarity_collected:.2f}"
                        )
                        worm_detected = True

    except FileNotFoundError as fnf_error:
        logger.error(f"File not found: {fnf_error}")
    except Exception as ex:
        logger.error(f"An unexpected error occurred while checking worm similarity for '{file_path}': {ex}")

    return worm_detected

def worm_alert(file_path):

    if file_path in worm_alerted_files:
        logger.info(f"Worm alert already triggered for {file_path}, skipping...")
        return

    try:
        logger.info(f"Running worm detection for file '{file_path}'")

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
                    logger.critical(f"File size difference for '{file_path}' exceeds 10%.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Critical.Agnostic.gen.Malware")
                    worm_alerted_files.append(file_path)
                    return  # Only flag once if a critical difference is found

                if mtime_difference > 3600:  # 3600 seconds = 1 hour
                    logger.critical(f"Modification time difference for '{file_path}' exceeds 1 hour.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Critical.Time.Agnostic.gen.Malware")
                    worm_alerted_files.append(file_path)
                    return  # Only flag once if a critical difference is found

            # Proceed with worm detection based on critical file comparison
            worm_detected = check_worm_similarity(file_path, features_current)

            if worm_detected:
                logger.critical(f"Worm '{file_path}' detected in critical directory. Alerting user.")
                notify_user_worm(file_path, "HEUR:Win32.Worm.Classic.Critical.gen.Malware")
                worm_alerted_files.append(file_path)

        else:
            # Check for generic worm detection
            worm_detected = check_worm_similarity(file_path, features_current)
            worm_detected_count[file_path] = worm_detected_count.get(file_path, 0) + 1

            if worm_detected or worm_detected_count[file_path] >= 5:
                if file_path not in worm_alerted_files:
                    logger.critical(f"Worm '{file_path}' detected under 5 different names or as potential worm. Alerting user.")
                    notify_user_worm(file_path, "HEUR:Win32.Worm.Classic.gen.Malware")
                    worm_alerted_files.append(file_path)

                # Notify for all files that have reached the detection threshold
                for detected_file in worm_detected_count:
                    if worm_detected_count[detected_file] >= 5 and detected_file not in worm_alerted_files:
                        notify_user_worm(detected_file, "HEUR:Win32.Worm.Classic.gen.Malware")
                        worm_alerted_files.append(detected_file)

    except Exception as ex:
        logger.error(f"Error in worm detection for file {file_path}: {ex}")

def check_pe_file(file_path, signature_check, file_name):
    try:
        # Normalize the file path to lowercase for comparison
        normalized_path = os.path.abspath(file_path).lower()
        normalized_sandboxie = sandboxie_folder.lower()

        logger.info(f"File {file_path} is a valid PE file.")

        # Check if file is inside the Sandboxie folder
        if normalized_path.startswith(normalized_sandboxie):
            worm_alert(file_path)
            logger.info(f"File {file_path} is inside Sandboxie folder, scanned with worm_alert.")

        # Check for fake system files after signature validation
        if file_name in fake_system_files and os.path.abspath(file_path).startswith(main_drive_path):
            if not signature_check["is_valid"]:
                logger.critical(f"Detected fake system file: {file_path}")
                notify_user_for_detected_fake_system_file(file_path, file_name, "HEUR:Win32.FakeSystemFile.Dropper.gen")

    except Exception as ex:
        logger.error(f"Error checking PE file {file_path}: {ex}")

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
        logger.error(f"Unexpected error checking ZIP: {e}")
        return False

def scan_file_ml(
    file_path: str,
    *,
    pe_file: bool = False,
    signature_check: Optional[Dict[str, Any]] = None,
    benign_threshold: float = 0.93,
) -> Tuple[bool, str, float]:
    """
    Perform ML-only scan and return simplified result.
    Returns (malware_found, virus_name, benign_score)
    """
    try:
        if not pe_file:
            logger.debug("ML scan skipped: not a PE file: %s", os.path.basename(file_path))
            return False, "Clean", 0.0

        # Unpack only the first 3 values (ignore matched_rules from ML)
        is_malicious_ml, malware_definition, benign_score, _ = scan_file_with_machine_learning_ai(file_path)

        sig_valid = bool(signature_check and signature_check.get("is_valid", False))

        if is_malicious_ml:
            if benign_score is None:
                benign_score = 0.0
            # Decide malware vs benign using threshold
            if benign_score < benign_threshold:
                # ML -> malware
                if sig_valid and isinstance(malware_definition, str):
                    malware_definition = f"{malware_definition}.SIG"
                logger.critical(
                    "Infected file detected (ML): %s - Virus: %s",
                    os.path.basename(file_path),
                    malware_definition,
                )
                return True, malware_definition, benign_score
            else:
                logger.info(
                    "File marked benign by ML (score=%s): %s",
                    benign_score,
                    os.path.basename(file_path),
                )
                return False, "Benign", benign_score
        else:
            logger.info("No malware detected by ML: %s", os.path.basename(file_path))
            return False, "Clean", benign_score

    except Exception as ex:
        err_msg = f"ML scan error: {ex}"
        logger.error(err_msg)
        return False, "Clean", 0.0

def ml_fastpath_should_continue(
    norm_path,
    signature_check,
    pe_file,
    benign_threshold: float = 0.93
) -> bool:
    """
    ML fast-path:
      - Return False => ML marked benign -> EARLY EXIT (skip heavy scan)
      - Return True  => proceed with full realtime scan
    """
    if not pe_file:
        return True

    try:
        malware_found, virus_name, benign_score = scan_file_ml(
            norm_path,
            pe_file=True,
            signature_check=signature_check,
            benign_threshold=benign_threshold,
        )
    except Exception as e:
        logger.warning("ML fast-path failed for %s: %s. Proceeding to full scan.", os.path.basename(norm_path), e)
        return True

    # ML marked benign -> skip heavy scan
    if not malware_found and virus_name == "Benign":
        logger.info("ML marked %s as benign (score=%s). Skipping full scan.", os.path.basename(norm_path), benign_score)
        return False

    # ML detected malware -> notify but continue scanning
    if malware_found:
        if isinstance(virus_name, (list, tuple)):
            virus_name = ''.join(virus_name)

        logger.critical("ML detected malware in %s. Virus: %s (continuing to full scan)", os.path.basename(norm_path), virus_name)

        # spawn notification but continue
        if virus_name.startswith("PUA."):
            threading.Thread(target=notify_user_pua, args=(norm_path, virus_name, "ML"), daemon=True).start()
        else:
            threading.Thread(target=notify_user, args=(norm_path, virus_name, "ML"), daemon=True).start()

        return True

    # Otherwise (ML said Clean or gave no opinion) -> continue to full scan
    return True

def scan_file_real_time(
    file_path: str,
    signature_check: dict,
    file_name: str,
    die_output,
    pe_file: bool = False
) -> Tuple[bool, str, str, Optional[str]]:
    """
    Scan file in real-time using multiple engines in parallel.
    Runs ALL workers to completion (no short-circuit). First detection wins.

    Returns: (malware_found: bool, virus_name: str, engine: str, vmprotect_path: Optional[str])
    """
    logger.info(f"Started scanning file: {file_path}")

    # Shared results and synchronization primitive
    results = {
        'malware_found': False,
        'virus_name': 'Clean',
        'engine': '',
        'vmprotect_path': None
    }

    thread_lock = threading.Lock()
    sig_valid = bool(signature_check and signature_check.get("is_valid", False))

    def pe_scan_worker():
        """Worker function for PE file analysis"""
        try:
            if pe_file:
                check_pe_file(file_path, signature_check, file_name)
        except Exception as ex:
            logger.error(f"An error occurred while scanning the file for fake system files and worm analysis: {file_path}. Error: {ex}")

    def clamav_scan_worker():
        """Worker function for ClamAV scan"""
        try:
            result = scan_file_with_clamav(file_path)
            if result not in ("Clean", "Error"):
                if sig_valid:
                    result = f"{result}.SIG"
                logger.critical(f"Infected file detected (ClamAV): {file_path} - Virus: {result}")

                with thread_lock:
                    if not results['malware_found']:  # first detection wins
                        results['malware_found'] = True
                        results['virus_name'] = result
                        results['engine'] = "ClamAV"
                # continue running other workers (no return that short-circuits outside of this worker)
            else:
                logger.info(f"No malware detected by ClamAV in file: {file_path}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning file with ClamAV: {file_path}. Error: {ex}")

    def yara_scan_worker():
        """Worker function for YARA scan"""
        try:
            yara_match, yara_result, vmprotect_unpacked_path = scan_yara(file_path)
            if yara_match is not None and yara_match not in ("Clean", ""):
                if sig_valid:
                    yara_match = f"{yara_match}.SIG"
                logger.critical(f"Infected file detected (YARA): {file_path} - Virus: {yara_match} - Result: {yara_result}")

                with thread_lock:
                    if not results['malware_found']:
                        results['malware_found'] = True
                        results['virus_name'] = yara_match
                        results['engine'] = "YARA"
                        results['vmprotect_path'] = vmprotect_unpacked_path
            else:
                logger.info(f"Scanned file with YARA: {file_path} - No viruses detected")
        except Exception as ex:
            logger.error(f"An error occurred while scanning file with YARA: {file_path}. Error: {ex}")

    def tar_scan_worker():
        """Worker function for TAR scan"""
        try:
            if tarfile.is_tarfile(file_path):
                scan_result, virus_name = scan_tar_file(file_path)
                if scan_result and virus_name not in ("Clean", "F", "", [], None):
                    virus_str = str(virus_name) if virus_name else "Unknown"
                    if sig_valid:
                        virus_str = f"{virus_str}.SIG"
                    logger.critical(f"Infected file detected (TAR): {file_path} - Virus: {virus_str}")

                    with thread_lock:
                        if not results['malware_found']:
                            results['malware_found'] = True
                            results['virus_name'] = virus_str
                            results['engine'] = "TAR"
                else:
                    logger.info(f"No malware detected in TAR file: {file_path}")
        except PermissionError:
            logger.error(f"Permission error occurred while scanning TAR file: {file_path}")
        except FileNotFoundError:
            logger.error(f"TAR file not found error occurred while scanning TAR file: {file_path}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning TAR file: {file_path}. Error: {ex}")

    def zip_scan_worker():
        """Worker function for ZIP scan"""
        try:
            if is_zip_file(file_path):
                scan_result, virus_name = scan_zip_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    if sig_valid:
                        virus_name = f"{virus_name}.SIG"
                    logger.critical(f"Infected file detected (ZIP): {file_path} - Virus: {virus_name}")

                    with thread_lock:
                        if not results['malware_found']:
                            results['malware_found'] = True
                            results['virus_name'] = virus_name
                            results['engine'] = "ZIP"
                else:
                    logger.info(f"No malware detected in ZIP file: {file_path}")
        except PermissionError:
            logger.error(f"Permission error occurred while scanning ZIP file: {file_path}")
        except FileNotFoundError:
            logger.error(f"ZIP file not found error occurred while scanning ZIP file: {file_path}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning ZIP file: {file_path}. Error: {ex}")

    def sevenz_scan_worker():
        """Worker function for 7z scan"""
        try:
            if is_7z_file_from_output(die_output):
                scan_result, virus_name = scan_7z_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    if sig_valid:
                        virus_name = f"{virus_name}.SIG"
                    logger.critical(f"Infected file detected (7z): {file_path} - Virus: {virus_name}")

                    with thread_lock:
                        if not results['malware_found']:
                            results['malware_found'] = True
                            results['virus_name'] = virus_name
                            results['engine'] = "7z"
                else:
                    logger.info(f"No malware detected in 7z file: {file_path}")
        except PermissionError:
            logger.error(f"Permission error occurred while scanning 7Z file: {file_path}")
        except FileNotFoundError:
            logger.error(f"7Z file not found error occurred while scanning 7Z file: {file_path}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning 7Z file: {file_path}. Error: {ex}")

    try:
        # Create and start all threads (no early-exit / cancel logic)
        workers = [
            pe_scan_worker,
            clamav_scan_worker,
            yara_scan_worker,
            tar_scan_worker,
            zip_scan_worker,
            sevenz_scan_worker
        ]

        threads = []
        for worker in workers:
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait for all threads to finish
        for t in threads:
            t.join()

        # Final decision:
        if results['malware_found']:
            return True, results['virus_name'], results['engine'], results.get('vmprotect_path')
        else:
            logger.info(f"File is clean - no malware detected by any engine: {file_path}")
            return False, "Clean", "", None

    except Exception as ex:
        logger.error(f"An error occurred while scanning file: {file_path}. Error: {ex}")
        return False, "Error", "", None

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
                            logger.info(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip}")

                            # Only proceed with files in the Sandboxie folder or the main file path
                            if sandboxie_folder.lower() not in file_path.lower() and file_path.lower() != main_file_path.lower():
                                continue

                            signature_info = check_signature(file_path)
                            if status == "Info":
                                if not signature_info["is_valid"]:
                                    logger.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has an invalid or no signature. Alert Line: {alert_line}")
                                else:
                                    logger.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature. Alert Line: {alert_line}")
                            else:
                                if not signature_info["is_valid"]:
                                    logger.critical(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip} has invalid or no signature. Alert Line: {alert_line}")
                                    notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status)
                                else:
                                    logger.info(f"File {file_path} associated with IP {src_ip} or {dst_ip} has a valid signature and is not flagged as malicious. Alert Line: {alert_line}")

        except psutil.ZombieProcess:
            logger.error(f"Zombie process encountered: {proc.info.get('pid')}")
        except psutil.NoSuchProcess:
            logger.error(f"Process no longer exists: {proc.info.get('pid')}")
        except psutil.AccessDenied:
            logger.error(f"Access denied to process: {proc.info.get('pid')}")
        except Exception as ex:
            logger.error(f"Unexpected error while processing process {proc.info.get('pid')}: {ex}")

def process_alert_data(priority, src_ip, dest_ip):
    """Process parsed alert data from EVE JSON format"""
    try:
        # Check if the source IP is in the IPv4 or IPv6 whitelist
        if src_ip in ipv4_whitelist_data or src_ip in ipv6_whitelist_data:
            logger.info(f"Source IP {src_ip} is in the whitelist. Ignoring alert.")
            return False

        # Determine threat type based on signature lists
        threat_type = "Unknown Threat Detected"

        # Check IPv4 signatures
        if src_ip in ipv4_addresses_signatures_data:
            threat_type = "General Threat (IPv4)"
        elif src_ip in ipv4_addresses_spam_signatures_data:
            threat_type = "Spam"
        elif src_ip in ipv4_addresses_bruteforce_signatures_data:
            threat_type = "Brute Force"
        elif src_ip in ipv4_addresses_phishing_active_signatures_data:
            threat_type = "Active Phishing"
        elif src_ip in ipv4_addresses_phishing_inactive_signatures_data:
            threat_type = "Inactive Phishing"
        elif src_ip in ipv4_addresses_ddos_signatures_data:
            threat_type = "DDoS"
        # Check IPv6 signatures
        elif src_ip in ipv6_addresses_signatures_data:
            threat_type = "General Threat (IPv6)"
        elif src_ip in ipv6_addresses_spam_signatures_data:
            threat_type = "Spam"
        elif src_ip in ipv6_addresses_ddos_signatures_data:
            threat_type = "DDoS"

        # Create a formatted line for logging (similar to fast.log format)
        formatted_line = f"[Priority: {priority}] {src_ip} -> {dest_ip} | Threat Type: {threat_type}"

        if priority == 1:
            logger.critical(
                f"Malicious activity detected: {formatted_line} | Source: {src_ip} -> Destination: {dest_ip} | Priority: {priority} | Threat: {threat_type}")
            try:
                notify_user_for_hips(ip_address=src_ip, dst_ip_address=dest_ip)
            except Exception as ex:
                logger.error(f"Error notifying user for HIPS (malicious): {ex}")
            convert_ip_to_file(src_ip, dest_ip, formatted_line, f"Malicious - {threat_type}")
            return True
        elif priority == 2:
            convert_ip_to_file(src_ip, dest_ip, formatted_line, f"Suspicious - {threat_type}")
            return True
        elif priority == 3:
            convert_ip_to_file(src_ip, dest_ip, formatted_line, f"Info - {threat_type}")
            return True

    except Exception as ex:
        logger.error(f"Error processing alert data: {ex}")
        return False

def activate_uefi_drive():
    # Check if the platform is Windows
    mount_command = 'mountvol X: /S'  # Command to mount UEFI drive
    try:
        # Execute the mountvol command
        subprocess.run(mount_command, shell=True, check=True, encoding="utf-8", errors="ignore")
        logger.info("UEFI drive activated!")
    except subprocess.CalledProcessError as ex:
        logger.error(f"Error mounting UEFI drive: {ex}")

def is_suricata_running():
    """
    Check if Suricata process is already running.
    """
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and 'suricata' in proc.info['name'].lower():
                return True
    except psutil.Error:
        pass
    return False

def run_suricata():
    """
    Run Suricata as a process using command line.
    """
    try:
        # Validate paths exist
        if not os.path.exists(suricata_exe_path):
            logger.error(f"Suricata executable not found at: {suricata_exe_path}")
            return False

        if not os.path.exists(suricata_config_path):
            logger.error(f"Suricata config not found at: {suricata_config_path}")
            return False

        # Check if executable has proper permissions
        if not os.access(suricata_exe_path, os.X_OK):
            logger.error(f"Suricata executable is not executable: {suricata_exe_path}")
            return False

        # Check if config file is readable
        if not os.access(suricata_config_path, os.R_OK):
            logger.error(f"Suricata config is not readable: {suricata_config_path}")
            return False

        # Ensure log directory exists
        if not os.path.exists(suricata_log_dir):
            try:
                os.makedirs(suricata_log_dir, exist_ok=True)
                logger.info(f"Created Suricata log directory: {suricata_log_dir}")
            except OSError as e:
                logger.error(f"Failed to create log directory {suricata_log_dir}: {e}")
                return False

        # Verify log directory is writable
        if not os.access(suricata_log_dir, os.W_OK):
            logger.error(f"Suricata log directory is not writable: {suricata_log_dir}")
            return False

        # Check if Suricata is already running
        if is_suricata_running():
            logger.info("Suricata process is already running.")
            return True

        # Log the paths being used
        logger.info(f"Using Suricata executable: {suricata_exe_path}")
        logger.info(f"Using Suricata config: {suricata_config_path}")

        # Build the Suricata command
        suricata_cmd = [
            suricata_exe_path,
            "-c", suricata_config_path,
            "--windivert-forward", "true"
        ]

        logger.info(f"Starting Suricata with command: {' '.join(suricata_cmd)}")

        # Start Suricata process
        process = subprocess.Popen(
            suricata_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        logger.info(f"Suricata started with PID: {process.pid}")

        # Wait a moment to check if process started successfully
        import time
        time.sleep(1)

        # Check if process is still running
        if process.poll() is None:
            logger.info("Suricata process is running successfully")
            return True
        else:
            # Process exited, get error output
            stdout, stderr = process.communicate()
            logger.error(f"Suricata process exited with code: {process.returncode}")
            if stdout:
                logger.error(f"Suricata stdout: {stdout.decode('utf-8', errors='ignore')}")
            if stderr:
                logger.error(f"Suricata stderr: {stderr.decode('utf-8', errors='ignore')}")
            return False

    except FileNotFoundError as ex:
        logger.error(f"Suricata executable not found: {ex}")
        return False
    except PermissionError as ex:
        logger.error(f"Permission denied when starting Suricata: {ex}")
        return False
    except subprocess.SubprocessError as ex:
        logger.error(f"Failed to start Suricata process: {ex}")
        return False
    except Exception as ex:
        logger.error(f"Unexpected error when running Suricata: {ex}")
        logger.exception("Full traceback:")
        return False

def stop_suricata():
    """
    Stop running Suricata processes.
    """
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and 'suricata' in proc.info['name'].lower():
                logger.info(f"Terminating Suricata process with PID: {proc.info['pid']}")
                proc.terminate()
                proc.wait(timeout=10)  # Wait up to 10 seconds for graceful termination
    except psutil.Error as ex:
        logger.error(f"Failed to stop Suricata: {ex}")

def suricata_callback():
    """Start Suricata and verify it's running properly."""
    try:
        success = run_suricata()
        if success:
            # Wait a moment and double-check
            time.sleep(1)
            if is_suricata_running():
                logger.info("Suricata started successfully.")
            else:
                logger.error("Suricata may have failed to start properly.")
        else:
            logger.error("Failed to start Suricata.")
    except Exception as ex:
        logger.error("Error starting Suricata: %s", ex)

threading.Thread(target=suricata_callback).start()

def monitor_suricata_log():
    """Monitor Suricata EVE JSON log file"""
    log_path = eve_log_path  # Use EVE JSON by default

    # Wait for the file to exist instead of creating it
    while not os.path.exists(log_path):
        logger.info(f"Waiting for log file to be created: {log_path}")
        time.sleep(1)  # Wait 5 seconds before checking again

    logger.info(f"Log file found: {log_path}")

    with open(log_path, 'r') as log_file:
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file
        while True:
            try:
                line = log_file.readline()
                if not line:
                    continue

                # Process EVE JSON format
                if line.strip():
                    priority, src_ip, dest_ip, signature, category = parse_suricata_alert(line)
                    if priority is not None:
                        # Enhanced logging with signature and category info
                        full_line = f"[Priority: {priority}] [{category}] {signature} {src_ip} -> {dest_ip}"
                        logger.debug(full_line)
                        process_alert_data(priority, src_ip, dest_ip)

            except Exception as ex:
                logger.info(f"Error processing line: {ex}")

reload_clamav_database()
activate_uefi_drive() # Call the UEFI function
load_website_data()
load_antivirus_list()
# Load Antivirus and Microsoft digital signatures
antivirus_signatures = load_digital_signatures(digital_signatures_list_antivirus_path, "Antivirus digital signatures")
goodsign_signatures = load_digital_signatures(digital_signatures_list_antivirus_path, "UnHackMe digital signatures")

# Load ML definitions

def load_ml_definitions(filepath: str) -> bool:
    """
    Load ML definitions from a JSON file and populate global numeric feature lists.
    This version understands the extended feature set produced by PEFeatureExtractor
    (section_disassembly, section_characteristics, overlay size, relocations, TLS callbacks, etc.)
    and is defensive about missing or unexpected types.
    """
    global malicious_numeric_features, malicious_file_names, benign_numeric_features, benign_file_names

    def to_float(x, default=0.0):
        try:
            if x is None:
                return float(default)
            return float(x)
        except Exception:
            return float(default)

    def safe_len(x):
        try:
            return len(x) if x is not None else 0
        except Exception:
            return 0

    def section_entropy_stats(section_characteristics):
        # section_characteristics may be a dict keyed by section name with 'entropy' values
        entropies = []
        try:
            if isinstance(section_characteristics, dict):
                for v in section_characteristics.values():
                    e = v.get('entropy') if isinstance(v, dict) else None
                    if e is not None:
                        try:
                            entropies.append(float(e))
                        except Exception:
                            continue
        except Exception:
            pass
        if not entropies:
            return 0.0, 0.0, 0.0  # mean, min, max
        mean = sum(entropies) / len(entropies)
        return float(mean), float(min(entropies)), float(max(entropies))

    def reloc_summary(relocs):
        # relocs is expected to be a list of relocation blocks with 'summary':{'total_entries':N}
        try:
            total = 0
            blocks = 0
            if isinstance(relocs, list):
                for r in relocs:
                    blocks += 1
                    try:
                        total += int(r.get('summary', {}).get('total_entries', 0))
                    except Exception:
                        continue
            return total, blocks
        except Exception:
            return 0, 0

    def entry_to_numeric(entry: dict) -> Tuple[List[float], str]:
        if not isinstance(entry, dict):
            entry = {}

        # Core header values (kept from your original vector)
        size_of_optional_header = to_float(entry.get("SizeOfOptionalHeader", 0))
        major_linker = to_float(entry.get("MajorLinkerVersion", 0))
        minor_linker = to_float(entry.get("MinorLinkerVersion", 0))
        size_of_code = to_float(entry.get("SizeOfCode", 0))
        size_of_init_data = to_float(entry.get("SizeOfInitializedData", 0))
        size_of_uninit_data = to_float(entry.get("SizeOfUninitializedData", 0))
        address_of_entry = to_float(entry.get("AddressOfEntryPoint", 0))
        image_base = to_float(entry.get("ImageBase", 0))
        subsystem = to_float(entry.get("Subsystem", 0))
        dll_characteristics = to_float(entry.get("DllCharacteristics", 0))
        size_of_stack_reserve = to_float(entry.get("SizeOfStackReserve", 0))
        size_of_heap_reserve = to_float(entry.get("SizeOfHeapReserve", 0))
        checksum = to_float(entry.get("CheckSum", 0))
        num_rva_and_sizes = to_float(entry.get("NumberOfRvaAndSizes", 0))
        size_of_image = to_float(entry.get("SizeOfImage", 0))

        # Counts
        imports_count = safe_len(entry.get("imports", []))
        exports_count = safe_len(entry.get("exports", []))
        resources_count = safe_len(entry.get("resources", []))
        sections_count = safe_len(entry.get("sections", []))

        # Overlay info
        overlay = entry.get("overlay", {}) or {}
        overlay_exists = int(bool(overlay.get("exists")))
        overlay_size = to_float(overlay.get("size", 0))

        # Section characteristics entropy stats (mean, min, max)
        sec_char = entry.get("section_characteristics", {}) or {}
        sec_entropy_mean, sec_entropy_min, sec_entropy_max = section_entropy_stats(sec_char)

        # Capstone disassembly overall numbers (if available)
        sec_disasm = entry.get("section_disassembly", {}) or {}
        overall = sec_disasm.get("overall_analysis", {}) or {}
        total_instructions = to_float(overall.get("total_instructions", 0))
        total_adds = to_float(overall.get("add_count", 0))
        total_movs = to_float(overall.get("mov_count", 0))
        is_likely_packed = int(bool(overall.get("is_likely_packed")))

        # Derived ratios (guard divide-by-zero)
        add_mov_ratio = (total_adds / (total_movs + 1.0)) if (total_movs is not None) else 0.0
        instrs_per_kb = 0.0
        try:
            instrs_per_kb = total_instructions / ((size_of_image / 1024.0) + 1e-6)
        except Exception:
            instrs_per_kb = 0.0

        # TLS callbacks
        tls = entry.get("tls_callbacks", {}) or {}
        tls_callbacks_list = tls.get("callbacks", []) if isinstance(tls, dict) else []
        num_tls_callbacks = safe_len(tls_callbacks_list)

        # Delay imports
        delay_imports_list = entry.get("delay_imports", []) or []
        num_delay_imports = safe_len(delay_imports_list)

        # Relocations
        relocs = entry.get("relocations", []) or []
        num_reloc_entries, num_reloc_blocks = reloc_summary(relocs)

        # Bound imports
        bound_imports = entry.get("bound_imports", []) or []
        num_bound_imports = safe_len(bound_imports)

        # Debug / certs
        debug_entries = entry.get("debug", []) or []
        num_debug_entries = safe_len(debug_entries)
        cert_info = entry.get("certificates", {}) or {}
        cert_size = to_float(cert_info.get("size", 0))

        # Delay / other counts
        num_delay_imports = safe_len(delay_imports_list)

        # Rich header info (presence)
        rich_header = entry.get("rich_header", {}) or {}
        has_rich = int(bool(rich_header))

        # relocations count already computed above
        # bound imports count above

        # Build the numeric vector (order matters - keep consistent)
        numeric = [
            # original fields (keep these in same order for backwards compatibility)
            size_of_optional_header,
            major_linker,
            minor_linker,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            address_of_entry,
            image_base,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_heap_reserve,
            checksum,
            num_rva_and_sizes,
            size_of_image,

            # counts (originally present)
            float(imports_count),
            float(exports_count),
            float(resources_count),
            float(overlay_exists),

            # new / extended features
            float(sections_count),
            float(sec_entropy_mean),
            float(sec_entropy_min),
            float(sec_entropy_max),
            float(total_instructions),
            float(total_adds),
            float(total_movs),
            float(is_likely_packed),
            float(add_mov_ratio),
            float(instrs_per_kb),

            float(overlay_size),
            float(num_tls_callbacks),
            float(num_delay_imports),
            float(num_reloc_entries),
            float(num_reloc_blocks),
            float(num_bound_imports),
            float(num_debug_entries),
            float(cert_size),
            float(has_rich)
        ]

        filename = (entry.get("file_info", {}) or {}).get("filename", "unknown")
        return numeric, filename

    # --- main loader body ---
    if not os.path.exists(filepath):
        logger.error(f"Machine learning definitions file not found: {filepath}. ML scanning will be disabled.")
        return False

    try:
        with open(filepath, 'r', encoding='utf-8-sig') as results_file:
            ml_defs = json.load(results_file)

        # Malicious section
        malicious_entries = ml_defs.get("malicious", []) or []
        malicious_numeric_features = []
        malicious_file_names = []
        for entry in malicious_entries:
            numeric, filename = entry_to_numeric(entry)
            malicious_numeric_features.append(numeric)
            malicious_file_names.append(filename)

        # Benign section
        benign_entries = ml_defs.get("benign", []) or []
        benign_numeric_features = []
        benign_file_names = []
        for entry in benign_entries:
            numeric, filename = entry_to_numeric(entry)
            benign_numeric_features.append(numeric)
            benign_file_names.append(filename)

        logger.info(f"[!] Loaded {len(malicious_numeric_features)} malicious and {len(benign_numeric_features)} benign ML definitions (vectors length = {len(malicious_numeric_features[0]) if malicious_numeric_features else 'N/A'}).")
        return True

    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load or parse ML definitions from {filepath}: {e}. ML scanning will be disabled.")
        return False

try:
    success = load_ml_definitions(machine_learning_results_json)
    if not success:
        logger.error("ML definitions could not be loaded properly.")
except Exception as ex:
    logger.exception(f"Unexpected error while loading ML definitions: {ex}")

try:
    # Load excluded rules from text file
    with open(excluded_rules_path, "r") as excluded_file:
        excluded_rules = [line.strip() for line in excluded_file if line.strip()]
        logger.info(f"YARA Excluded Rules loaded: {len(excluded_rules)} rules")
except FileNotFoundError:
    logger.error(f"Excluded rules file not found: {excluded_rules_path}")
    excluded_rules = []
except Exception as ex:
    logger.error(f"Error loading excluded rules: {ex}")
    excluded_rules = []

def load_yara_rule(path: str, display_name: str = None, is_yara_x: bool = False):
    """
    Load a YARA or YARA-X rule from a precompiled .yrc file.

    :param path: Path to the precompiled rule file.
    :param display_name: Optional friendly name for logger.
    :param is_yara_x: If True, use YARA-X deserialization.
    :return: Loaded rule object or None if failed.
    """
    try:
        if is_yara_x:
            with open(path, 'rb') as f:
                rule = yara_x.Rules.deserialize_from(f)
        else:
            rule = yara.load(path)

        name = display_name or path
        logger.info(f"{name} loaded successfully!")
        return rule
    except Exception as ex:
        name = display_name or path
        logger.error(f"Error loading {name}: {ex}")
        return None

yarGen_rule   = load_yara_rule(yarGen_rule_path, display_name="yarGen Rules")
icewater_rule = load_yara_rule(icewater_rule_path, display_name="Icewater Rules")
valhalla_rule = load_yara_rule(valhalla_rule_path, display_name="Vallhalla Demo Rules")
clean_rules   = load_yara_rule(clean_rules_path, display_name="(clean) YARA Rules")
yaraxtr_rule  = load_yara_rule(yaraxtr_yrc_path, display_name="YARA-X yaraxtr Rules", is_yara_x=True)

# Initialize variables as None (empty)
meta_llama_1b_model = None
meta_llama_1b_tokenizer = None

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
        logger.error(f"An error occurred while generating project name: {ex}")

def decompile_file(file_path):
    """Decompile the file using Ghidra."""
    try:
        logger.info(f"Decompiling file: {file_path}")

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
            logger.error(f"Failed to generate project name: {ex}")
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
            logger.info(f"Decompilation completed successfully for file: {file_path}")
        else:
            logger.error(f"Decompilation failed for file: {file_path}.")
            logger.error(f"Return code: {result.returncode}")
            logger.error(f"Error output: {result.stderr}")
            logger.error(f"Standard output: {result.stdout}")
    except Exception as ex:
        logger.error(f"An error occurred during decompilation: {ex}")

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
                    logger.info(f"Original file path extracted: {original_file_path}")

                    return original_file_path
        return None
    except Exception as ex:
        logger.error(f"An error occurred while extracting the original file path: {ex}")
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
        logger.error("No DIE output available for Nuitka check.")
        return None

    if "Packer: Nuitka[OneFile]" in die_output:
        logger.info("DIE output indicates a Nuitka OneFile executable.")
        return "Nuitka OneFile"
    elif "Packer: Nuitka" in die_output:
        logger.info("DIE output indicates a Nuitka executable.")
        return "Nuitka"
    else:
        return None

def clean_text(input_text):
    """
    Remove non-logger.infoable ASCII control characters from the input text.

    :param input_text: The string to clean.
    :return: Cleaned text with control characters removed.
    """
    # Remove non-logger.infoable characters (ASCII 0-31 and 127)
    cleaned_text = re.sub(r'[\x00-\x1F\x7F]+', '', input_text)
    return cleaned_text

def is_likely_junk(line):
    """
    Return True if the line should be considered JUNK (and therefore deleted).

    Rules:
    - If the line does NOT contain 'u' -> JUNK (True).
    - Only examine alphabetic tokens that CONTAIN 'u' (excluding the single token 'u').
      * If any such token is longer than max_u_len -> treat as NOT JUNK (False).
      * If any such token is NOT in english_words_set -> NOT JUNK (False).
      * If at least one alphabetic 'u'-containing token exists AND all such tokens are
        present in english_words_set and <= max_u_len -> JUNK (True).
    - Single 'u' token is always NOT JUNK (False).
    """
    line = (line or "").strip()
    if not line:
        return True

    # Rule 1: lines without 'u' are junk
    if 'u' not in line.lower():
        return True

    try:
        # Normalize so 'u' becomes its own token for tokenization (prevents 'udef' being hidden)
        normalized = re.sub(r'u', ' u ', line.lower())
        tokens = word_tokenize(normalized)

        saw_u_alpha_token = False

        for token in tokens:
            if token == 'u':
                # single 'u' token: keep
                continue

            # Only consider alphabetic tokens that contain 'u' (and length > 1)
            if 'u' in token and token.isalpha() and len(token) > 1:
                saw_u_alpha_token = True

                # If token is longer than known 'u' words -> treat as NOT JUNK
                if len(token) > max_u_len:
                    return False

                # If token is not in the English words set -> NOT JUNK
                if token not in english_words_set:
                    return False

                # otherwise token is a valid English word containing 'u' -> keep checking others

        # If we saw at least one alphabetic 'u' token and all were valid English words, mark as JUNK
        if saw_u_alpha_token:
            return True

        # No alphabetic 'u' tokens (only single 'u' tokens or non-alpha) -> NOT JUNK
        return False

    except Exception as e:
        logger.warning(f"NLTK processing failed for line: {line[:50]}... Error: {e}")
        # On error be conservative: keep the line
        return False

def split_source_by_u_delimiter(source_code, base_name="initial_code"):
    """
    Reconstructs source code using 'u'-delimiter splitting.

    Features:
    - Preserves protected fragments (URLs, IPs, Discord/Telegram/webhooks)
    - Splits content on 'u', merging tokens safely
    - Groups into modules by <module ...> markers
    - Saves reconstructed modules
    - Creates separate file with extracted links/webhooks/tokens
    - Keeps only lines starting with 'u' (case-insensitive)
    """
    logger.info("Reconstructing source code with unified 'u' delimiter logic...")

    if not source_code or is_likely_junk(source_code.strip()):
        return

    # Build regex patterns for URLs and IPs
    url_regex = build_url_regex()
    ip_patterns = build_ip_patterns()

    preserve_patterns = [
        discord_webhook_pattern,
        discord_canary_webhook_pattern,
        cdn_attachment_pattern,
        telegram_token_pattern,
        telegram_keyword_pattern,
        discord_webhook_pattern_standard,
        discord_canary_webhook_pattern_standard,
        cdn_attachment_pattern_standard,
        telegram_pattern_standard,
        UBLOCK_REGEX,
        ZIP_JOIN,
        CHAINED_JOIN,
        B64_LITERAL,
    ]

    combined_preserve = re.compile(
        '|'.join([p if isinstance(p, str) else p.pattern for p in preserve_patterns] +
                 [url_regex.pattern] +
                 [p[0] for p in ip_patterns])
    )

    # --- STEP 1: Tokenize and extract protected links ---
    tokens = []
    extracted_links = []

    for line in [source_code]:
        start = 0
        for m in combined_preserve.finditer(line):
            unprotected = line[start:m.start()]
            if 'u' in unprotected:
                parts = re.split(r'(u)', unprotected)
                tokens.extend([p for p in parts if p])
            else:
                if unprotected:
                    tokens.append(unprotected)

            # Add preserved/protected content
            protected_content = m.group(0)
            tokens.append(protected_content)
            extracted_links.append(protected_content)

            start = m.end()

        tail = line[start:]
        if 'u' in tail:
            parts = re.split(r'(u)', tail)
            tokens.extend([p for p in parts if p])
        else:
            if tail:
                tokens.append(tail)

    # --- STEP 2: Merge 'u' tokens safely ---
    merged_tokens = []
    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]
        if t == 'u':
            if i + 1 < n:
                next_token = tokens[i + 1]
                # Merge only if next token is likely valid code/URL
                if next_token.startswith(('"', "'", 'http')):
                    merged_tokens.append('u' + next_token)
                else:
                    merged_tokens.append('u')
                i += 2
            else:
                merged_tokens.append('u')
                i += 1
        else:
            merged_tokens.append(t)
            i += 1

    final_lines = [t.strip() for t in merged_tokens if t.strip()]

    # --- STEP 3: Save extracted links to separate file ---
    def save_links_file(links, base_filename):
        if not links:
            logger.info("No links/webhooks/tokens found to save.")
            return

        links_filename = f"{base_filename}_extracted_links.txt"
        links_path = os.path.join(nuitka_source_code_dir, links_filename)

        obfuscated_results = []
        try:
            obfuscated_results = detect_obfuscated_urls(source_code)
        except Exception as e:
            logger.warning(f"Error detecting obfuscated URLs: {e}")

        try:
            with open(links_path, "w", encoding="utf-8") as f:
                total_items = len(links) + len(obfuscated_results)
                f.write(f"# Extracted Links/Webhooks/Tokens ({total_items} items)\n")
                f.write(f"# From: {base_filename}\n\n")

                discord_webhooks, telegram_tokens, urls, obfuscated_urls, ips, other_content = [], [], [], [], [], []

                for link in links:
                    l = link.lower()
                    if 'discord' in l and 'webhook' in l:
                        discord_webhooks.append(link)
                    elif 'telegram' in l or 'bot' in l:
                        telegram_tokens.append(link)
                    elif link.startswith(('http://', 'https://', 'ftp://', 'hxxp://', 'hxxps://')):
                        urls.append(link)
                    elif re.match(r'\d+\.\d+\.\d+\.\d+', link):
                        ips.append(link)
                    else:
                        other_content.append(link)

                for r in obfuscated_results:
                    obfuscated_urls.append(f"{r['original']} -> {r['decoded']} ({r['type']})")

                # Write categorized content
                if discord_webhooks:
                    f.write("## Discord Webhooks\n" + "\n".join(discord_webhooks) + "\n\n")
                if telegram_tokens:
                    f.write("## Telegram Tokens\n" + "\n".join(telegram_tokens) + "\n\n")
                if urls:
                    f.write("## URLs\n" + "\n".join(urls) + "\n\n")
                if obfuscated_urls:
                    f.write("## Obfuscated URLs\n" + "\n".join(obfuscated_urls) + "\n\n")
                if ips:
                    f.write("## IPs\n" + "\n".join(ips) + "\n\n")
                if other_content:
                    f.write("## Other Protected Content\n" + "\n".join(other_content) + "\n\n")

            logger.info(f"Links file saved: {links_path} ({total_items} items)")
            scan_code_for_links(source_code, links_path, nuitka_flag=True)

        except IOError as e:
            logger.error(f"Failed to write links file {links_path}: {e}")

    save_links_file(extracted_links, base_name)

    # --- STEP 4: Group lines into modules ---
    module_start_pattern = re.compile(r"^\s*<module\s+['\"]?([^>'\"]+)['\"]?>")
    current_module_name, current_module_code, modules = base_name, [], []

    def save_module_file(name, code_lines):
        if not code_lines:
            return
        safe_filename = name.replace('.', '_') + ".py"
        output_path = os.path.join(nuitka_source_code_dir, safe_filename)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(code_lines))
            logger.info(f"Module saved: {output_path}")
        except IOError as e:
            logger.error(f"Failed to write module file {output_path}: {e}")

    for line in final_lines:
        match = module_start_pattern.match(line)
        if match:
            if current_module_code:
                modules.append((current_module_name, current_module_code))
            current_module_name = match.group(1)
            current_module_code = []
        else:
            current_module_code.append(line)

    if current_module_code:
        modules.append((current_module_name, current_module_code))

    # --- STEP 5: Keep only 'u'-starting lines and save ---
    for name, code_lines in modules:
        forced_lines = [l for l in code_lines if l.lower().startswith('u')]
        save_module_file(name, forced_lines)

    logger.info("Reconstruction complete (only 'u'-lines kept).")
    logger.info(f"Extracted {len(extracted_links)} links/webhooks/tokens to separate file.")

def scan_rsrc_files(file_paths):
    """
    Given a list of file paths for rsrcdata resources, this function scans each file.

    If 'upython.exe' or '\\python.exe' is found in a file:
        - Extract and clean code from that file.
        - Save to disk.
        - Do NOT scan for links.

    If neither marker is found:
        - Find the largest file.
        - Extract and clean its code.
        - Scan for links with nuitka_flag=True.
    """
    if isinstance(file_paths, str):
        file_paths = [file_paths]

    executable_file = None
    found_marker = None

    # Check for python exe markers - prefer upython.exe over \python.exe
    for file_path in file_paths:
        if os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # Check for upython.exe first (preferred)
                    if "upython.exe" in content:
                        executable_file = file_path
                        found_marker = "upython.exe"
                        logger.info(f"Found upython.exe in: {file_path}")
                        break
                    # If no upython.exe, check for \\python.exe
                    elif "\\python.exe" in content:
                        # Only set if we haven't found upython.exe yet
                        if executable_file is None:
                            executable_file = file_path
                            found_marker = "\\python.exe"
                            logger.info(f"Found \\python.exe in: {file_path}")
            except Exception as ex:
                logger.error(f"Error reading file {file_path}: {ex}")
        else:
            logger.error(f"Path {file_path} is not a valid file.")

    # Case 1: No markers found -> use largest file and scan with nuitka_flag=True
    if executable_file is None:
        logger.info("No file containing python exe markers was found.")
        largest_file = None
        largest_size = -1
        for file_path in file_paths:
            if os.path.isfile(file_path):
                try:
                    size = os.path.getsize(file_path)
                    if size > largest_size:
                        largest_size = size
                        largest_file = file_path
                except Exception as ex:
                    logger.error(f"Error checking size for {file_path}: {ex}")

        if largest_file:
            try:
                with open(largest_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                cleaned_source_code = [clean_text(line.rstrip()) for line in lines]
                decompiled_code = "\n".join(cleaned_source_code)
            except Exception as ex:
                logger.error(f"Error processing largest file {largest_file}: {ex}")
        else:
            logger.info("No valid files found to scan.")
        return

    # Case 2: Marker found -> extract but no scan
    try:
        logger.info(f"Processing file: {executable_file}")
        with open(executable_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        if lines:
            # Locate the marker line
            source_index = next((i for i, line in enumerate(lines) if found_marker in line), None)

            if source_index is not None:
                line_with_marker = lines[source_index]
                marker_index = line_with_marker.find(found_marker)
                remainder = line_with_marker[marker_index + len(found_marker):].lstrip()

                # Build the source code lines
                source_code_lines = ([remainder] if remainder else []) + lines[source_index + 1:]
                cleaned_source_code = [clean_text(line.rstrip()) for line in source_code_lines]
                decompiled_code = "\n".join(cleaned_source_code)

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
                    save_file.write(decompiled_code)
                logger.info(f"Saved extracted source code from {executable_file} to {save_path}")
                # Send only the saved file path
                split_source_by_u_delimiter(decompiled_code)

            else:
                logger.info(f"No line containing '{found_marker}' found in {executable_file}.")
        else:
            logger.info(f"File {executable_file} is empty.")
    except Exception as ex:
        logger.error(f"Error during file scanning of {executable_file}: {ex}")

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
        logger.info("DIE output indicates a PyInstaller archive.")
        return True

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
            logger.error("Could not open %s", self.filePath)
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    def checkFile(self):
        logger.info("Processing %s", self.filePath)

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            logger.error("File is too short or truncated")
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
            logger.error(
                "Missing cookie, unsupported pyinstaller version or not a pyinstaller archive"
            )
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b"python" in self.fPtr.read(64).lower():
            logger.info("Pyinstaller version: 2.1+")
            self.pyinstVer = 21  # pyinstaller 2.1+
        else:
            self.pyinstVer = 20  # pyinstaller 2.0
            logger.info("Pyinstaller version: 2.0")

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
            logger.error("Error: The file is not a pyinstaller archive")
            return False

        self.pymaj, self.pymin = (
            (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        )
        logger.info("Python version: %s.%s", self.pymaj, self.pymin)

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

        logger.info("Length of package: %s bytes", lengthofPackage)
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
                logger.error("File name %s contains invalid bytes. Using random name %s", name, newName)
                name = newName

            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                logger.error("Found an unnamed file in CArchive. Using random name %s", name)

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
        logger.info("Found %d files in CArchive", len(self.tocList))

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
                logger.error(
                    "pyc magic of files inside PYZ archive are different from those in CArchive"
                )

            (tocPosition,) = struct.unpack("!i", f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = load_code(f, pycHeader2Magic(pyzPycMagic))
            except:
                logger.error("Unmarshalling FAILED. Cannot extract %s. Extracting remaining files.", name)
                return

            logger.info("Found %d files in PYZ archive", len(toc))

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
                            logger.error("Failed to decrypt & decompress %s. Extracting as is.", filePath)
                            open(filePath + ".encrypted", "wb").write(data_copy)
                            continue

                self._writePyc(filePath, data)

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, "r+b") as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def extractFiles(self, one_dir):
        logger.info("Beginning extraction...please standby")
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
                logger.info("Possible entry point: %s.pyc", entry.name)

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
                        logger.info(
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
                        logger.info(
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

def extract_pyinstaller_archive(file_path):
    try:
        archive = PyInstArchive(file_path)

        # Open the PyInstaller archive
        if not archive.open():
            logger.error(f"Failed to open PyInstaller archive: {file_path}")
            return None

        # Check if the file is a valid PyInstaller archive
        if not archive.checkFile():
            logger.error(f"File {file_path} is not a valid PyInstaller archive.")
            return None

        # Retrieve CArchive info from the archive
        if not archive.getCArchiveInfo():
            logger.error(f"Failed to get CArchive info from {file_path}.")
            return None

        # Parse the Table of Contents (TOC) from the archive
        archive.parseTOC()

        # Extract files to the specified pyinstaller_extracted_dir
        extraction_dir = archive.extractFiles(one_dir=True)

        # Close the archive
        archive.close()

        logger.info(f"[+] Extraction completed successfully: {extraction_dir}")

        return extraction_dir

    except Exception as ex:
        logger.error(f"An error occurred while extracting PyInstaller archive {file_path}: {ex}")
        return None

def has_known_extension(file_path):
    try:
        ext = os.path.splitext(file_path)[1].lower()
        logger.info(f"Extracted extension '{ext}' for file '{file_path}'")
        return ext in fileTypes
    except Exception as ex:
        logger.error(f"Error checking extension for file {file_path}: {ex}")
        return False

def is_readable(file_path):
    try:
        logger.info(f"Attempting to read file '{file_path}'")
        with open(file_path, 'r') as readable_file:
            file_data = readable_file.read(1024)
            if file_data:  # Check if file has readable content
                logger.info(f"File '{file_path}' is readable")
                return True
            return False
    except UnicodeDecodeError:
        logger.error(f"UnicodeDecodeError while reading file '{file_path}'")
        return False
    except Exception as ex:
        logger.error(f"Error reading file {file_path}: {ex}")
        return False

def is_ransomware(file_path):
    try:
        filename = os.path.basename(file_path)
        parts = filename.split('.')
        logger.info(f"Checking ransomware conditions for file '{file_path}' with parts '{parts}'")

        # Check if there are multiple extensions
        if len(parts) < 3:
            logger.info(f"File '{file_path}' does not have multiple extensions, not flagged as ransomware")
            return False

        # Check if the second last extension is known
        previous_extension = '.' + parts[-2].lower()
        if previous_extension not in fileTypes:
            logger.info(f"Previous extension '{previous_extension}' of file '{file_path}' is not known, not flagged as ransomware")
            return False

        # Check if the final extension is not in fileTypes
        final_extension = '.' + parts[-1].lower()
        if final_extension not in fileTypes:
            logger.critical(f"File '{file_path}' has unrecognized final extension '{final_extension}', checking if it might be ransomware sign")

            # Check if the file has a known extension or is readable
            if has_known_extension(file_path) or is_readable(file_path):
                logger.info(f"File '{file_path}' is not ransomware")
                return False
            else:
                logger.critical(f"File '{file_path}' might be a ransomware sign")
                return True

        logger.info(f"File '{file_path}' does not meet ransomware conditions")
        return False

    except Exception as ex:
        logger.error(f"Error checking ransomware for file {file_path}: {ex}")
        return False

def search_files_with_same_extension(directory, extension):
    try:
        logger.info(f"Searching for files with extension '{extension}' in directory '{directory}'")
        files_with_same_extension = []
        for root, _, files in os.walk(directory):
            for search_file in files:
                if search_file.endswith(extension):
                    files_with_same_extension.append(os.path.join(root, search_file))
        logger.info(f"Found {len(files_with_same_extension)} files with extension '{extension}'")
        return files_with_same_extension
    except Exception as ex:
        logger.error(f"Error searching for files with extension '{extension}' in directory '{directory}': {ex}")
        return []

def ransomware_alert(file_path):
    global ransomware_detection_count

    try:
        logger.info(f"Running ransomware alert check for file '{file_path}'")

        # Check the ransomware flag once.
        if is_ransomware(file_path):
            # If file is from the Sandboxie log folder, trigger Sandboxie-specific alert.
            if file_path.startswith(sandboxie_log_folder):
                ransomware_detection_count += 1
                logger.critical(f"File '{file_path}' (Sandboxie log) flagged as potential ransomware. Count: {ransomware_detection_count}")
                notify_user_ransomware(main_file_path, "HEUR:Win32.Ransom.logger.gen")
                logger.critical(f"User has been notified about potential ransomware in {main_file_path} (Sandboxie log alert)")

            # Normal processing for all flagged files.
            ransomware_detection_count += 1
            logger.critical(f"File '{file_path}' might be a ransomware sign. Count: {ransomware_detection_count}")

            # When exactly two alerts occur, search for files with the same extension.
            if ransomware_detection_count == 2:
                _, ext = os.path.splitext(file_path)
                if ext:
                    directory = os.path.dirname(file_path)
                    files_with_same_extension = search_files_with_same_extension(directory, ext)
                    for ransom_file in files_with_same_extension:
                        logger.info(f"Checking file '{ransom_file}' with same extension '{ext}'")
                        if is_ransomware(ransom_file):
                            logger.critical(f"File '{ransom_file}' might also be related to ransomware")

            # When detections reach a threshold, notify the user with a generic flag.
            if ransomware_detection_count >= 10:
                notify_user_ransomware(main_file_path, "HEUR:Win32.Ransom.gen")
                logger.critical(f"User has been notified about potential ransomware in {main_file_path}")

    except Exception as ex:
        logger.error(f"Error in ransomware_alert: {ex}")

def log_directory_type(file_path):
    try:
        for condition, message in DIRECTORY_MESSAGES:
            if condition(file_path):
                logger.info(f"{file_path}: {message}")
                return

        logger.error(f"{file_path}: File does not match known directories.")
    except Exception as ex:
        logger.error(f"Error logging directory type for {file_path}: {ex}")

def scan_file_with_meta_llama(file_path, decompiled_flag=False, HiJackThis_flag=False, capa_flag=False):
    """
    Processes a file and analyzes it using Meta Llama-3.2-1B.
    If decompiled_flag is True, a normal summary is generated with
    an additional note indicating that the file was decompiled by our tool and is Python source code.

    Args:
        file_path (str): The path to the file to be scanned.
        decompiled_flag (bool): If True, indicates that the file was decompiled by our tool.
    """
    if not meta_llama_1b_model or not meta_llama_1b_tokenizer:
        logger.error("Llama model is not loaded. Cannot perform analysis.")
        return "Llama model is not loaded. Cannot perform analysis."

    try:

        # 1) Find and log the first matching directory message, also save it for the prompt
        dir_note = None
        for condition, message in DIRECTORY_MESSAGES:
            if condition(file_path):
                logger.info(f"{file_path}: {message}")
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
        if capa_flag:
            initial_message = prefix + (
                "Meta Llama-3.2-1B Report for CAPA detects capabilities in executable PE files:\n"
                "The following report is produced based on CAPA analysis. "
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
            logger.error(f"Error reading file {file_path}: {ex}")
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
            logger.error(f"Error generating response: {ex}")
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

        logger.info(final_response)

        # Log the raw model response
        answer_log_path = os.path.join(script_dir, "log", "answer.log")
        try:
            with open(answer_log_path, "a") as answer_log_file:
                answer_log_file.write(relevant_response + "\n\n")
        except Exception as ex:
            logger.error(f"Error writing to log file {answer_log_path}: {ex}")

        # Log the final summary
        log_file_path = os.path.join(script_dir, "log", "Meta Llama-3.2-1B.log")
        try:
            with open(log_file_path, "a") as log_file:
                log_file.write(final_response + "\n")
        except Exception as ex:
            logger.error(f"Error writing to log file {log_file_path}: {ex}")

        # If malware is detected (Maybe or Yes), notify the user
        if malware.lower() in ["maybe", "yes"]:
            try:
                if HiJackThis_flag:
                    notify_user_for_meta_llama(main_file_path, virus_name, malware, HiJackThis_flag=True)
                else:
                    notify_user_for_meta_llama(file_path, virus_name, malware)
            except Exception as ex:
                logger.error(f"Error notifying user: {ex}")

        # Otherwise, log and do not return (implicit None)
        logger.info("Meta Llama analysis completed.")
        return final_response

    except Exception as ex:
        logger.error(f"An unexpected error occurred in scan_file_with_meta_llama: {ex}")
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
            logger.error("Failed to save intermediate data.")
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
            logger.critical(f"[+] Webhook URLs found: {webhooks}")
            if source_code_path:
                notify_user_exela_stealer_v2(source_code_path, 'HEUR:Win32.Discord.PYC.Python.Exela.Stealer.v2.gen')
            else:
                logger.error("Failed to save the final decrypted source code.")
        else:
            logger.info("[!] No webhook URLs found in Exela v2 payload.")

    except Exception as ex:
        logger.error(f"Error during Exela v2 payload processing: {ex}")

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
        logger.error(f"Failed to parse source as AST: {e}")
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
                        logger.error(f"Failed to decode/unmarshal: {e}")
            self.generic_visit(node)

    extractor = Extractor()
    extractor.visit(tree)

    if extractor.code_obj:
        return extractor.code_obj

    logger.error("[!] marshal.loads pattern with base64 blob not found in AST")
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
            logger.error(f"[Pylingual] .pyc file does not exist: {pyc_path}")
            return None

        # Check if the file is readable
        if not os.access(pyc_file, os.R_OK):
            logger.error(f"[Pylingual] .pyc file is not readable: {pyc_path}")
            return None

        base_name = pyc_file.stem
        parent_dir = pyc_file.parent

        # Check if parent directory is writable
        if not os.access(parent_dir, os.W_OK):
            logger.error(f"[Pylingual] Parent directory is not writable: {parent_dir}")
            return None

        # Check if a .py file with the same name already exists
        potential_output_file = parent_dir / f"{base_name}.py"

        if potential_output_file.exists():
            # File exists, create a separate folder
            output_path = parent_dir / f"decompiled_{base_name}"
            logger.info(f"[Pylingual] Output file exists, using folder: {output_path}")
        else:
            # File doesn't exist, use the parent directory directly (no folder creation)
            output_path = parent_dir
            logger.info(f"[Pylingual] Decompiling directly to parent directory: {output_path}")

        # Ensure output directory exists (but don't create unnecessary folders)
        if output_path != parent_dir:
            try:
                output_path.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                logger.error(f"[Pylingual] Failed to create output directory {output_path}: {e}")
                return None

        # Call pylingual main function directly with parameters
        start_time = time.time()
        try:
            # Add more detailed logging
            logger.info(f"[Pylingual] Starting decompilation of {pyc_file}")
            logger.info(f"[Pylingual] Output directory: {output_path}")
            logger.info(f"[Pylingual] File size: {pyc_file.stat().st_size} bytes")

            # Check if file is actually a valid .pyc file by reading magic number
            try:
                with open(pyc_file, 'rb') as f:
                    magic = f.read(4)
                    logger.info(f"[Pylingual] Magic number: {magic.hex()}")
            except Exception as magic_error:
                logger.error(f"[Pylingual] Could not read magic number: {magic_error}")

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
            logger.info(f"pylingual.main execution completed in {time.time() - start_time:.6f} seconds")
        except Exception as pylingual_error:
            logger.error(f"[Pylingual] pylingual_main failed: {pylingual_error}")
            logger.error(f"[Pylingual] Error type: {type(pylingual_error).__name__}")
            # Try to get more details about the error
            logger.error(f"[Pylingual] Traceback: {traceback.format_exc()}")
            raise

        # Find all generated .py files
        py_files = list(output_path.rglob("*.py"))

        # If no files found in the expected location, try looking in subdirectories
        if not py_files and output_path == parent_dir:
            # Sometimes pylingual creates its own subdirectory
            possible_subdir = parent_dir / f"decompiled_{base_name}"
            if possible_subdir.exists():
                py_files = list(possible_subdir.rglob("*.py"))
                logger.info(f"[Pylingual] Found files in subdirectory: {possible_subdir}")

        if not py_files:
            logger.error(f"[Pylingual] No .py files found in output for: {pyc_path}")
            # List all files in the output directory for debugging
            all_files = list(output_path.rglob("*"))
            logger.info(f"[Pylingual] All files in output directory: {[str(f) for f in all_files]}")
            return None

        # Combine all decompiled source files
        combined_source = ""
        for py_file in sorted(py_files):  # Sort for consistent ordering
            try:
                source_content = py_file.read_text(encoding="utf-8", errors="ignore")
                combined_source += f"# From: {py_file.name}\n"
                combined_source += source_content.strip() + "\n\n"
            except Exception as read_error:
                logger.error(f"[Pylingual] Could not read {py_file}: {read_error}")
                continue

        if not combined_source.strip():
            logger.error(f"[Pylingual] All decompiled files were empty for: {pyc_path}")
            return None

        logger.info(f"[Pylingual] Successfully decompiled {pyc_path} -> {output_path}")
        logger.info(f"[Pylingual] Generated {len(py_files)} Python files")

        return combined_source

    except Exception as e:
        logger.error(f"[Pylingual] Decompilation failed for {pyc_path}: {e}")
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
        logger.error(f"Error in codeobj_to_source: {e}")
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
            logger.info(f"[Clean Syntax] Removing line {lineno}: {bad_line}")
            lines.pop(lineno - 1)

            # ALSO remove orphaned identifiers (like `lambda_output`) if any
            symbol = bad_line.split('=')[0].strip() if '=' in bad_line else bad_line
            lines = [line for line in lines if symbol not in line or line.strip().startswith('#')]
            attempt += 1

    cleaned_code = "\n".join(lines)

    if is_valid(cleaned_code):
        return cleaned_code
    else:
        logger.info("[Clean Syntax] Could not fully clean code.")
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
        logger.debug(f"[PRUNE_IFS] Wrote transformed code to: {output_path}")
    except Exception as e:
        logger.error(f"[PRUNE_IFS] Failed to parse or transform: {e}")
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
    logger.info(f"[SANDBOX] Running shell command: {shell_cmd!r}")
    logger.info(f"[SANDBOX] Expect exec output at: {exec_path_str}")

    try:
        subprocess.run(
            shell_cmd,
            shell=True,
            check=True,
            timeout=600,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        logger.error(f"[SANDBOX] Run failed: {e}")
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
        logger.error("[SANDBOX] Timed out waiting for execs file to stabilize.")
        return None

    # Copy result back to host
    host_output_dir = Path(python_deobfuscated_dir)
    host_output_dir.mkdir(parents=True, exist_ok=True)
    host_target = host_output_dir / f"{name}_deobf.py"

    try:
        content = sandbox_inner_execs.read_bytes()
        if not content:
            logger.error("[SANDBOX] Execs file content empty on read, aborting.")
            return None
        host_target.write_bytes(content)
        logger.info(f"[SANDBOX] Copied execs output back to host: {host_target}")
        return host_target
    except Exception as copy_exc:
        logger.error(f"[SANDBOX] Failed to copy from sandbox: {copy_exc}")
        return None

# Main loop: apply exec->file and remove unused imports, with stuck-detection
def deobfuscate_until_clean(source_path: Path) -> Optional[Path]:
    source_path = Path(source_path)
    base_name = source_path.stem
    logger.info(f"Starting deobfuscation for: {source_path}")

    # Each queue entry: (depth, stage_tag, cleaned_flag, offloaded_flag, candidate_path)
    processing_queue: List[Tuple[int, str, bool, bool, Path]] = []
    # Track seen states as (stage_tag, cleaned_flag, offloaded_flag, content_hash)
    seen_hashes: Set[Tuple[str, bool, bool, str]] = set()

    try:
        _ = source_path.read_text(encoding="utf-8", errors="replace")
        processing_queue.append((0, "original", False, False, source_path))
    except Exception as e:
        logger.error(f"Failed to read source file: {e}")
        return None

    while processing_queue:
        logger.info(f"--- New Pass (queue size = {len(processing_queue)}) ---")
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
                                logger.info(f"[MARSHAL] Extracted and wrote: {new_path}")
                                next_queue.append((depth + 1, "marshal", False, False, new_path))
                                continue
                    except Exception as e:
                        logger.error(f"[MARSHAL] Failed on {candidate_path}: {e}")

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
                        logger.error(f"[AST] Transform failed on {candidate_path}: {e}")
                        transformed = content

                    transformed_hash = compute_md5_via_text(transformed)
                    state3 = ("ast", False, True, transformed_hash)
                    if transformed_hash != content_hash and state3 not in seen_hashes:
                        new_path = get_unique_output_path(
                            Path(python_deobfuscated_dir),
                            f"{base_name[:8]}_d{depth}_ast.py"
                        )
                        new_path.write_text(transformed, encoding="utf-8")
                        logger.info(f"[AST] Transformed and wrote: {new_path}")
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
                    logger.debug(f"[CLEAN_SYNTAX] Wrote cleaned code to: {clean_path}")

                    clean_content = clean_path.read_text(encoding="utf-8", errors="replace")
                    clean_hash = compute_md5_via_text(clean_content)
                    state4 = ("clean", True, offloaded, clean_hash)
                    if state4 not in seen_hashes:
                        logger.info(f"[CLEAN_SYNTAX] Cleaned and wrote: {clean_path}")

                        # Only finalize if exec truly gone and not offloaded
                        if not offloaded and not contains_exec_calls(clean_content) and "eval" not in clean_content:
                            final_candidate = get_unique_output_path(
                                Path(python_deobfuscated_dir),
                                f"{base_name[:8]}_final.py"
                            )
                            prune_ifs_and_write(final_candidate, clean_content)
                            logger.info(
                                f"[FINAL] No exec/eval found post-clean_syntax, saved: {final_candidate}"
                            )
                            return final_candidate

                        next_queue.append((depth + 1, "clean", True, offloaded, clean_path))
                        continue
                else:
                    logger.debug("[CLEAN_SYNTAX] Skipping clean_syntax (already cleaned)")

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
                        logger.info(
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

                        logger.info(f"[SANDBOX] Produced sandbox output: {output_path}")

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
                            logger.info(f"[FINAL_CANDIDATE] Clean code candidate saved: {final_candidate}")
                            return final_candidate

                        continue
                    else:
                        logger.error(f"[SANDBOX] No output for {candidate_path}; dropping it")
                        seen_hashes.add(("sandbox", False, False, content_hash))
                        continue

                except Exception as e:
                    logger.error(f"[SANDBOX] Failed on {candidate_path}: {e}")
                    seen_hashes.add(("sandbox", False, False, content_hash))
                    continue

            except Exception as e:
                logger.error(f"[ERROR] While processing {candidate_path}: {e}")
                seen_hashes.add((stage_tag, cleaned, offloaded, compute_md5_via_text(candidate_path.read_text(encoding="utf-8", errors="replace"))))
                continue

        processing_queue = next_queue

    logger.info("No more clean code found; transformations exhausted.")
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
            logger.info("[*] Detected Exela Stealer v2 payload.")
            process_exela_v2_payload(output_file)

        elif 'exec(' not in content:
            logger.info(f"[+] No exec() found in {output_file}, probably not obfuscated.")

        else:
            logger.info("[*] Detected non-Exela payload. Using generic processing.")
            deobfuscated = deobfuscate_until_clean(output_file)
            if deobfuscated:
                deobfuscated_saved_paths.append(deobfuscated)  # Add to global list
                notify_user_for_malicious_source_code(
                    deobfuscated,
                    "HEUR:Win32.Susp.Src.PYC.Python.Obfuscated.exec.gen"
                )
            else:
                logger.error("[!] Generic deobfuscation failed; skipping scan and notification.")

    except Exception as ex:
        logger.error(f"[!] Error during payload dispatch: {ex}")

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
        logger.info(f"PyInstaller archive extracted to {output_dir}")

        # Traverse and collect all extracted files
        for root, _, files in os.walk(output_dir):
            for pyinstaller_file in files:
                extracted_file_path = os.path.join(root, pyinstaller_file)
                extracted_pyinstaller_file_paths.append(extracted_file_path)

    return extracted_pyinstaller_file_paths, output_dir

def decompile_apk_file(file_path):
    """
    Decompile an Android APK using Androguard (via subprocess) and scan
    all decompiled files for URLs, IPs, domains, and Discord webhooks.
    """
    try:
        logger.info(f"Detected APK file: {file_path}")

        # Find a free output folder number
        folder_number = 1
        while os.path.exists(os.path.join(androguard_dir, str(folder_number))):
            folder_number += 1
        output_dir = os.path.join(androguard_dir, str(folder_number))
        os.makedirs(output_dir, exist_ok=True)

        # Build the command:
        #   python -m androguard decompile -o <output_dir> <apk>
        cmd = [
            sys.executable,
            "-m", "androguard",
            "decompile",
            "-o", output_dir,
            file_path
        ]
        subprocess.run(cmd, check=True)
        logger.info(f"APK decompiled to {output_dir}")

        # Walk and scan any generated .smali or .java files
        for root, _, files in os.walk(output_dir):
            for fname in files:
                if fname.endswith((".smali", ".java")):
                    full_path = os.path.join(root, fname)
                    logger.info(f"Scanning file: {full_path}")
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        scan_code_for_links(content, full_path, androguard_flag=True)
                    except Exception as ex:
                        logger.error(f"Error scanning {full_path}: {ex}")

    except subprocess.CalledProcessError as cpe:
        logger.error(f"Androguard subprocess failed: {cpe}")
    except Exception as ex:
        logger.error(f"Error decompiling APK {file_path}: {ex}")

def decompile_dotnet_file(file_path):
    """
    Decompiles a .NET assembly using ILSpy and scans all decompiled .cs files
    for URLs, IP addresses, domains, and Discord webhooks.

    :param file_path: Path to the .NET assembly file.
    """
    try:
        logger.info(f"Detected .NET assembly: {file_path}")

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
        logger.info(f".NET content decompiled to {dotnet_output_dir}")

        # Scan all .cs files in the output directory
        for root, _, files in os.walk(dotnet_output_dir):
            for file in files:
                if file.endswith(".cs"):  # Only process .cs files
                    cs_file_path = os.path.join(root, file)
                    logger.info(f"Scanning .cs file: {cs_file_path}")

                    try:
                        # Read the content of the .cs file
                        with open(cs_file_path, "r", encoding="utf-8", errors="ignore") as f:
                            cs_file_content = f.read()

                        # Scan for links, IPs, domains, and Discord webhooks
                        scan_code_for_links(cs_file_content, cs_file_path, dotnet_flag=True)

                    except Exception as ex:
                        logger.error(f"Error scanning .cs file {cs_file_path}: {ex}")

    except Exception as ex:
        logger.error(f"Error decompiling .NET file {file_path}: {ex}")

def run_capa_analysis(file_path):
    """
    Runs CAPA analysis on a file using capa.exe and saves results.

    :param file_path: Path to the file to analyze
    :return: Path to the text results file or None if failed
    """
    try:
        logger.info(f"Running CAPA analysis on: {file_path}")

        # Create a unique numbered subdirectory under capa_results_dir
        folder_number = 1
        while os.path.exists(os.path.join(capa_results_dir, str(folder_number))):
            folder_number += 1
        capa_output_dir = os.path.join(capa_results_dir, str(folder_number))
        os.makedirs(capa_output_dir, exist_ok=True)

        # Generate output file name
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        txt_output_file = os.path.join(capa_output_dir, f"{base_name}_capa_results.txt")

        # Run CAPA analysis command for human-readable text output
        capa_command = [
            "capa.exe",
            "-s", capa_rules_dir,  # Use the signatures (rules) directory
            "-r", capa_rules_dir,  # Use the rules directory
            "-v",                  # Verbose output for more details
            file_path
        ]

        # Execute CAPA and capture output
        result = subprocess.run(
            capa_command,
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8'
        )

        # Save text results
        with open(txt_output_file, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        logger.info(f"CAPA text results saved to: {txt_output_file}")
        logger.info(f"CAPA analysis completed successfully for {file_path}")
        return txt_output_file

    except subprocess.CalledProcessError as ex:
        logger.error(f"CAPA analysis failed for {file_path}: {ex}")
        logger.error(f"CAPA stderr: {ex.stderr}")

        # Save error information
        if 'capa_output_dir' in locals():
            error_file = os.path.join(capa_output_dir, f"{base_name}_capa_error.txt")
            with open(error_file, "w", encoding="utf-8") as f:
                f.write(f"CAPA Error for {file_path}\n")
                f.write(f"Return code: {ex.returncode}\n")
                f.write(f"STDOUT:\n{ex.stdout}\n")
                f.write(f"STDERR:\n{ex.stderr}\n")
            logger.info(f"Error details saved to: {error_file}")

        return None

    except Exception as ex:
        logger.error(f"Error running CAPA analysis on {file_path}: {ex}")
        return None

def analyze_file_with_capa(file_path):
    """
    Wrapper function that runs CAPA analysis and returns JSON file path.

    :param file_path: Path to the file to analyze
    :return: Path to JSON results file or None if failed
    """
    try:
        # Run CAPA analysis
        capa_file_path = run_capa_analysis(file_path)

        if not capa_file_path:
            logger.info(f"No CAPA results obtained for {file_path}")
            return None

        logger.info(f"CAPA analysis completed for {file_path}, results: {capa_file_path}")
        return capa_file_path

    except Exception as ex:
        logger.error(f"Error processing CAPA results for {file_path}: {ex}")
        return None

def extract_npm_file(file_path):
    """
    Extracts a pkg-compiled Node.js application using pkg-unpacker
    and scans all extracted files.

    :param file_path: Path to the .pkg or .exe file
    :return: List of extracted file paths
    """
    extracted_files = []
    try:
        file_path = Path(file_path)
        logger.info(f"Detected npm/pkg binary: {file_path}")

        # Create a unique numbered subdirectory under npm_pkg_extracted_dir
        folder_number = 1
        while os.path.exists(os.path.join(npm_pkg_extracted_dir, str(folder_number))):
            folder_number += 1
        output_dir = os.path.join(npm_pkg_extracted_dir, str(folder_number))
        os.makedirs(output_dir, exist_ok=True)

        # Run pkg-unpacker CLI: npm start -i <file_path> -o <output_dir>
        unpack_command = [
            "npm", "start",
            "-i", str(file_path),
            "-o", output_dir
        ]
        subprocess.run(unpack_command, cwd=pkg_unpacker_dir, check=True)
        logger.info(f"Pkg binary extracted to {output_dir}")

        # Scan all extracted files
        for root, _, files in os.walk(output_dir):
            for file in files:
                file_path_full = os.path.join(root, file)
                extracted_files.append(file_path_full)
                logger.info(f"Scanning file: {file_path_full}")

                try:
                    with open(file_path_full, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    scan_code_for_links(content, file_path_full, npm_flag=True)
                except Exception as ex:
                    logger.error(f"Error scanning file {file_path_full}: {ex}")

    except subprocess.CalledProcessError as ex:
        logger.error(f"pkg-unpacker extraction failed for {file_path}: {ex}")
    except Exception as ex:
        logger.error(f"Error processing npm/pkg file {file_path}: {ex}")

    return extracted_files

def extract_asar_file(file_path):
    """
    Extracts an Electron .asar archive using the 'asar' npm CLI
    and scans all extracted files for URLs, IPs, domains, and Discord webhooks.

    :param file_path: Path to the .asar file
    """
    try:
        logger.info(f"Detected Asar archive: {file_path}")

        # Create a unique numbered subdirectory under asar_dir
        folder_number = 1
        while os.path.exists(os.path.join(asar_dir, str(folder_number))):
            folder_number += 1
        asar_output_dir = os.path.join(asar_dir, str(folder_number))
        os.makedirs(asar_output_dir, exist_ok=True)

        # Run asar extraction command
        asar_command = [
            "asar",
            "extract",
            file_path,
            asar_output_dir
        ]
        subprocess.run(asar_command, check=True)
        logger.info(f"Asar archive extracted to {asar_output_dir}")

        # Scan all extracted files
        for root, _, files in os.walk(asar_output_dir):
            for file in files:
                file_path_full = os.path.join(root, file)
                logger.info(f"Scanning file: {file_path_full}")

                try:
                    # Read the file content (skip binary decoding errors)
                    with open(file_path_full, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Scan for links, IPs, domains, Discord webhooks
                    scan_code_for_links(content, file_path_full, asar_flag=True)

                except Exception as ex:
                    logger.error(f"Error scanning file {file_path_full}: {ex}")

    except subprocess.CalledProcessError as ex:
        logger.error(f"asar extraction failed for {file_path}: {ex}")
    except Exception as ex:
        logger.error(f"Error processing Asar file {file_path}: {ex}")

def deobfuscate_webcrack_js(file_path) -> str:
    """
    Deobfuscates a JavaScript bundle using 'webcrack' CLI and returns
    the output directory containing deobfuscated files.

    :param file_path: Path to the JavaScript file (e.g., bundle.js)
    :return: Path to the deobfuscated output directory
    """
    try:
        logger.info(f"Detected JavaScript bundle: {file_path}")

        # Create a unique numbered subdirectory under webcrack_javascript_deobfuscated_dir
        folder_number = 1
        while os.path.exists(os.path.join(webcrack_javascript_deobfuscated_dir, str(folder_number))):
            folder_number += 1
        js_output_dir = os.path.join(webcrack_javascript_deobfuscated_dir, str(folder_number))
        os.makedirs(js_output_dir, exist_ok=True)

        # Run webcrack deobfuscation command
        webcrack_command = [
            "webcrack",
            file_path,
            "-o",
            js_output_dir
        ]
        subprocess.run(webcrack_command, check=True)
        logger.info(f"JavaScript deobfuscated to {js_output_dir}")

        # Return the path for later scanning
        return js_output_dir

    except subprocess.CalledProcessError as ex:
        logger.error(f"webcrack deobfuscation failed for {file_path}: {ex}")
        return ""
    except Exception as ex:
        logger.error(f"Error processing JavaScript file {file_path}: {ex}")
        return ""

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

        logger.info(f"Extracting {file_path} into {output_dir}...")
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
            logger.error(
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
                    links = scan_code_for_links(content, path, nsis_flag=True)
                    logger.info(f"Scanned NSIS script {path}, found {len(links)} links.")
                except Exception as e:
                    logger.error(f"Failed to scan NSIS script {path}: {e}")

            for path in extracted_files:
                if path.lower().endswith('.nsi'):
                    t = threading.Thread(target=_scan_nsi, args=(path,))
                    t.start()

        return extracted_files

    except Exception as ex:
        logger.error(f"Error during 7z extraction: {ex}")
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

        logger.error(f"Unsupported function call: {ast.dump(node)}")

    elif isinstance(node, ast.Constant):
        # Python 3.8+: constant node (str, bytes, etc.)
        return node.value

    elif isinstance(node, ast.Str):
        # Older python versions
        return node.s

    elif isinstance(node, ast.Bytes):
        return node.s

    else:
        logger.error(f"Unsupported AST node type: {ast.dump(node)}")

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
            logger.info(f"Successfully decompiled using pycdas. Output saved to {output_path}")
            return output_path
        else:
            logger.error(f"pycdas error: {result.stderr}")
            return None
    except Exception as e:
        logger.error(f"Error running pycdas: {e}")
        return None

def deobfuscate_with_net_reactor(file_path, file_basename):
    """
    Deobfuscate a .NET assembly protected with .NET Reactor using NETReactorSlayer-x64.CLI.exe.

    This function:
      1. Copies the original file from file_path into the net_reactor_extracted_dir directory.
      2. Calls the NETReactorSlayer-x64.CLI.exe executable with the copied file and --no-pause option.
      3. Waits for the deobfuscated file (with "_Slayed" suffix) to appear in net_reactor_extracted_dir.
      4. Returns the path of the deobfuscated file.

    Parameters:
      file_path (str): Path to the file to be deobfuscated.
      file_basename (str): The name of the file (e.g., from os.path.basename(file_path)).

    Returns:
      str | None: Path to the deobfuscated file (with "_Slayed" suffix), or None on error.
    """
    if not os.path.exists(net_reactor_slayer_x64_cli_path):
        logger.error(f".NET Reactor Slayer x64 CLI executable not found at {net_reactor_slayer_x64_cli_path}")
        return None

    # Copy the file to the net_reactor directory
    copied_file_path = os.path.join(net_reactor_extracted_dir, file_basename)
    try:
        shutil.copy(file_path, copied_file_path)
        logger.info(f"Copied file {file_path} to {copied_file_path}")
    except Exception as e:
        logger.error(f"Failed to copy file to .NET Reactor directory: {e}")
        return None

    # Run the deobfuscation tool with --no-pause option
    try:
        command = [net_reactor_slayer_x64_cli_path, copied_file_path, "--no-pause", "True"]
        logger.info(f"Running .NET Reactor deobfuscation: {' '.join(command)}")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")

        # Log the output for debugging
        if result.stdout:
            logger.info(f".NET Reactor Slayer output: {result.stdout}")
        if result.stderr:
            logger.error(f".NET Reactor Slayer errors: {result.stderr}")

    except Exception as e:
        logger.error(f"Error during .NET Reactor deobfuscation execution: {e}")
        return None

    # Monitor directory for the deobfuscated output
    logger.info("Waiting for deobfuscated file to appear...")

    # The tool adds "_Slayed" to the end of the filename
    name_without_ext = os.path.splitext(file_basename)[0]
    original_ext = os.path.splitext(file_basename)[1]
    expected_output = f"{name_without_ext}_Slayed{original_ext}"

    max_wait_time = 300  # 5 minutes timeout
    start_time = time.time()

    while time.time() - start_time < max_wait_time:
        try:
            # Check for the expected output file with "_Slayed" suffix
            expected_path = os.path.join(net_reactor_extracted_dir, expected_output)
            if os.path.exists(expected_path):
                logger.info(f"Deobfuscated file found: {expected_path}")
                return expected_path

        except OSError as e:
            logger.error(f"Error checking for output file: {e}")

        time.sleep(1)  # Wait 1 second before checking again

    logger.error(f"Timeout: No deobfuscated file found after {max_wait_time} seconds")
    return None

def deobfuscate_with_confuserex(file_path, file_basename, max_wait_time=1200):
    """
    Deobfuscate a .NET assembly protected with ConfuserEx using UnConfuserEx.exe.

    - Copies the original file into un_confuser_ex_extracted_dir
    - Runs UnConfuserEx.exe <input> <output>
    - Waits for the output file to appear and returns its path
    """
    if not os.path.exists(un_confuser_ex_path):
        logger.error(f"UnConfuserEx executable not found at {un_confuser_ex_path}")
        return None

    # Prepare copied input and output paths
    copied_file_path = os.path.join(un_confuser_ex_extracted_dir, file_basename)
    name_without_ext, original_ext = os.path.splitext(file_basename)
    expected_output_name = f"{name_without_ext}_UnConfuserEx{original_ext}"
    expected_output_path = os.path.join(un_confuser_ex_extracted_dir, expected_output_name)

    try:
        shutil.copy(file_path, copied_file_path)
        logger.info(f"Copied file {file_path} to {copied_file_path} for UnConfuserEx processing")
    except Exception as e:
        logger.error(f"Failed to copy file to UnConfuserEx directory: {e}")
        return None

    # Build and run command: UnConfuserEx.exe <input> <output>
    try:
        command = [un_confuser_ex_path, copied_file_path, expected_output_path]
        logger.info(f"Running UnConfuserEx: {' '.join(command)}")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")

        if result.stdout:
            logger.info(f"UnConfuserEx stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"UnConfuserEx stderr: {result.stderr.strip()}")

    except Exception as e:
        logger.error(f"Error during UnConfuserEx execution: {e}")
        return None

    # Wait for the expected output file to appear
    logger.info("Waiting for UnConfuserEx output file to appear...")
    start_time = time.time()
    while time.time() - start_time < max_wait_time:
        try:
            if os.path.exists(expected_output_path):
                logger.info(f"UnConfuserEx produced deobfuscated file: {expected_output_path}")
                return expected_output_path
        except OSError as e:
            logger.error(f"Error checking for UnConfuserEx output: {e}")

        time.sleep(1)

    logger.error(f"Timeout: No UnConfuserEx output found after {max_wait_time} seconds")
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
        logger.error(f"Deobfuscar executable not found at {deobfuscar_path}")
        return None

    # Copy the file to the obfuscar directory
    copied_file_path = os.path.join(obfuscar_dir, file_basename)
    try:
        shutil.copy(file_path, copied_file_path)
        logger.info(f"Copied file {file_path} to {copied_file_path}")
    except Exception as e:
        logger.error(f"Failed to copy file to obfuscar directory: {e}")
        return None

    # Run the deobfuscation tool
    try:
        command = [deobfuscar_path, copied_file_path]
        logger.info(f"Running deobfuscation: {' '.join(command)}")
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.error(f"Error during deobfuscation execution: {e}")
        return None

    # Monitor directory for the unpacked output
    logger.info("Waiting for unpacked_ file to appear...")
    deobfuscated_file_path = None
    while True:
        for entry in os.listdir(obfuscar_dir):
            if entry.startswith("unpacked_"):
                deobfuscated_file_path = os.path.join(obfuscar_dir, entry)
                logger.info(f"Deobfuscated file found: {deobfuscated_file_path}")
                break
        if deobfuscated_file_path:
            break

    return deobfuscated_file_path

def extract_rcdata_resource(pe_path):
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        logger.error(f"Error loading PE file: {e}")
        return None, []

    # Check if the PE file has any resources
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        logger.error("No resources found in this file.")
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

                logger.info(f"Extracted resource saved: {output_path}")
                all_extracted_files.append(output_path)

                # If it's an RCData resource (type "10") and matches 10_3_0.bin, record and stop
                if type_name == "10" and res_id == "3" and lang_id == 0:
                    first_rcdata_file = output_path
                    logger.info(f"Using RCData resource file: {first_rcdata_file}")
                    # Break out of all loops once found
                    break
            if first_rcdata_file:
                break
        if first_rcdata_file:
            break

    if first_rcdata_file is None:
        logger.info("No matching RCData resource (10_3_0.bin) found.")
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
            logger.info(f"Nuitka OneFile executable detected in {file_path}")

            # Extract the file name (without extension) to include in the folder name
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]

            # Find the next available directory number for OneFile extraction
            folder_number = 1
            while os.path.exists(os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")):
                folder_number += 1

            # Create the new directory with the executable file name and folder number
            nuitka_output_dir = os.path.join(nuitka_dir, f"OneFile_{file_name_without_extension}_{folder_number}")
            os.makedirs(nuitka_output_dir, exist_ok=True)

            logger.info(f"Extracting Nuitka OneFile {file_path} to {nuitka_output_dir}")

            # Use NuitkaExtractor for extraction
            extractor = NuitkaExtractor(file_path, nuitka_output_dir)
            extractor.extract()

            # Scan the extracted directory for additional Nuitka executables
            logger.info("Scanning extracted directory for additional Nuitka executables...")
            found_executables = scan_directory_for_executables(nuitka_output_dir)

            # Process any found normal Nuitka executables
            for exe_path, exe_type in found_executables:
                if exe_type == "Nuitka":
                    logger.info(f"Found normal Nuitka executable in extracted files: {exe_path}")
                    nested_files = extract_nuitka_file(exe_path, exe_type)
                    if nested_files:
                        extracted_files_list.extend(nested_files)

            return extracted_files_list

        elif nuitka_type == "Nuitka":
            logger.info(f"Nuitka executable detected in {file_path}")

            # Extract the Nuitka executable
            file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]

            # Use enhanced pefile extraction
            extracted_files_nuitka, all_extracted_files = extract_rcdata_resource(file_path)

            if extracted_files_nuitka:
                logger.info(f"Successfully extracted bytecode or RCDATA file from Nuitka executable: {file_path}")
                scan_rsrc_files(extracted_files_nuitka)
                extracted_files_list.extend(extracted_files_nuitka)
            else:
                logger.error(f"Failed to extract normal Nuitka executable: {file_path}")

            if all_extracted_files:
                extracted_files_list.extend(all_extracted_files)

            return extracted_files_list

        else:
            logger.info(f"No Nuitka content found in {file_path}")
            return None

    except Exception as ex:
        logger.error(f"Unexpected error while extracting Nuitka file: {ex}")
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
        logger.error(f"Error loading PE file: {e}")
        return None

    # Check if the PE file has resources
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
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
                logger.info(f"Resource saved: {output_path}")

                extracted_files.append(output_path)
                resource_count += 1

    if resource_count == 0:
        logger.info("No resources were extracted.")
    else:
        logger.info(f"Extracted a total of {resource_count} resources.")

    return extracted_files

def run_fernflower_decompiler(file_path):
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
            logger.info(f"FernFlower decompilation successful to: {FernFlower_output_dir}")
            # List all files in output dir (recursively)
            decompiled_files = []
            for root, dirs, files in os.walk(FernFlower_output_dir):
                for name in files:
                    decompiled_files.append(os.path.join(root, name))
            return decompiled_files
        else:
            logger.error(f"FernFlower decompilation failed: {result.stderr}")
            return None
    except Exception as ex:
        logger.error(f"Error in run_fernflower_decompiler: {ex}")
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
            logger.info("JAR extraction completed successfully.")
        else:
            logger.error(f"JAR extraction failed: {result.stderr}")

        # Collect all files from extracted_dir
        for root, _, files in os.walk(extracted_dir):
            for name in files:
                full_path = os.path.join(root, name)
                extracted_file_paths.append(full_path)

        # Decompile via FernFlower if not already done
        if not flag_fernflower:
            fernflower_results = run_fernflower_decompiler(file_path)
            if fernflower_results:
                extracted_file_paths.extend(fernflower_results)
            else:
                logger.info("No files returned from FernFlower decompiler.")
        else:
            logger.info("FernFlower analysis already performed; skipping decompilation.")

        # Scan every Java file
        for f in extracted_file_paths:
            if f.endswith(".java"):
                try:
                    scan_code_for_links(decompiled_code=f, file_path=f)
                except Exception as e:
                    logger.error(f"Failed to scan {f}: {e}")

        return extracted_file_paths

    except Exception as ex:
        logger.error(f"Error in run_jar_extractor: {ex}")
        return None

def extract_inno_setup(file_path):
    """
    Extracts an Inno Setup installer using innounp-2.
    Returns a list of extracted file paths, or None on failure.

    :param file_path: Path to the Inno Setup installer (.exe)
    :return: List of file paths under extraction directory, or None if extraction failed.
    """
    try:
        logger.info(f"Detected Inno Setup installer: {file_path}")

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
            "-m",               # extract internal embedded files (such as license and uninstall.exe)
            "-d", output_dir,   # output directory
            file_path           # the installer to unpack
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
        if result.returncode != 0:
            logger.error(f"innounp-2 failed: {result.stderr}")
            return None

        logger.info(f"Inno Setup content extracted to {output_dir}")

        # Gather all extracted file paths
        extracted_paths = []
        for root, _, files in os.walk(output_dir):
            for filename in files:
                extracted_paths.append(os.path.join(root, filename))

        return extracted_paths

    except Exception as ex:
        logger.error(f"Error extracting Inno Setup file {file_path}: {ex}")
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
        logger.info("DIE output indicates an Inno Setup installer.")
        return True

    return False

def extract_installshield(file_path):
    """
    Unpacks an InstallShield file using ISx.exe.
    Returns the path to the output directory, or None on failure.

    :param file_path: Path to the InstallShield file (e.g., .cab, .exe)
    :return: Path to the directory containing extracted files, or None if extraction failed.
    """
    try:
        logger.info(f"Detected InstallShield file: {file_path}")

        # create a unique subdirectory inside installshield-extracted_dir
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        folder_number = 1
        while True:
            out_dir_name = f"{base_name}_extracted{'' if folder_number == 1 else f'_{folder_number}'}"
            output_dir = os.path.join(installshield_extracted_dir, out_dir_name)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                break
            folder_number += 1

        # run ISx.exe: `ISx.exe <InstallShield file> [output dir]`
        cmd = [
            ISx_installshield_extractor_path,
            file_path,
            output_dir
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
            logger.error(f"ISx extraction failed ({result.returncode}): {result.stderr.strip()}")
            return None

        logger.info(f"Files extracted to: {output_dir}")
        return output_dir

    except Exception as ex:
        logger.error(f"Error extracting InstallShield file {file_path}: {ex}")
        return None

def extract_autoit(file_path):
    """
    Extracts AutoIt scripts from PE binaries using autoit-ripper.
    Returns the path to the output directory, or None on failure.

    :param file_path: Path to the PE binary file (e.g., .exe)
    :return: Path to the directory containing extracted files, or None if extraction failed.
    """
    try:
        logger.info(f"Detected AutoIt binary: {file_path}")

        # Create a unique subdirectory inside autoit_extracted_dir
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        folder_number = 1
        while True:
            out_dir_name = f"{base_name}_extracted{'' if folder_number == 1 else f'_{folder_number}'}"
            output_dir = os.path.join(autoit_extracted_dir, out_dir_name)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                break
            folder_number += 1

        # Run autoit-ripper: `autoit-ripper <binary> <output_dir>`
        cmd = [
            "autoit-ripper",
            file_path,
            output_dir
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
            logger.error(f"autoit-ripper extraction failed ({result.returncode}): {result.stderr.strip()}")
            return None

        logger.info(f"AutoIt scripts extracted to: {output_dir}")
        return output_dir

    except Exception as ex:
        logger.error(f"Error extracting AutoIt binary {file_path}: {ex}")
        return None

def extract_upx(file_path):
    """
    Unpacks a UPX-compressed executable using UPX.
    Returns the path to the unpacked file, or None on failure.

    :param file_path: Path to the UPX-packed executable (.exe, .dll, etc.)
    :return: Path to the unpacked file, or None if unpacking failed.
    """
    try:
        logger.info(f"Detected UPX-packed file: {file_path}")

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
            logger.error(f"UPX unpack failed: {result.stderr.strip()}")
            return None

        logger.info(f"UPX unpacked file written to: {output_path}")
        return output_path

    except Exception as ex:
        logger.error(f"Error unpacking UPX file {file_path}: {ex}")
        return None

def extract_pe_sections(file_path: str):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)
        logger.info(f"Loaded PE file: {file_path}")

        # Ensure output directory exists
        output_dir = Path(pe_extracted_dir)
        if not output_dir.exists():
            output_dir.mkdir(parents=True)
            logger.info(f"Created output directory: {output_dir}")

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

            logger.info(f"Section '{section_name}' saved to {section_file}")
            pe_file_paths.append(section_file)  # Add the file path to the list

        logger.info("Extraction completed successfully.")
        return pe_file_paths  # Return the list of file paths

    except Exception as e:
        logger.error(f"An error occurred: {e}")
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
            logger.info(f"Shadow copy created, ID = {shadow_id}")
            return shadow_id
        else:
            logger.error(f"Failed to create shadow (WMI code {result})")
            return None
    except Exception:
        logger.error("Error creating shadow copy via WMI")
        return None

def copy_from_shadow(shadow_root, rel_path, dest_path):
    """
    Copy a file from the shadow copy. Returns True on success, False on failure.
    """
    shadow_file = os.path.join(shadow_root, rel_path)
    if not os.path.exists(shadow_file):
        logger.error(f"Not found in shadow: {shadow_file}")
        return False
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    try:
        shutil.copy2(shadow_file, dest_path)
        return True
    except Exception as e:
        logger.error(f"Failed to copy from shadow: {e}")
        return False

def _copy_to_dest(file_path, dest_root):
    """
    Copy file_path into dest_root, preserving the original directory structure.
    Returns the copied-destination path on success, or None on failure.
    Uses Volume Shadow Copy on Windows to handle locked files.
    """
    if not os.path.exists(file_path):
        logger.error(f"Source does not exist: {file_path}")
        return None

    if file_path.startswith(sandboxie_folder):
        # File is in sandboxie, preserve structure relative to sandboxie folder
        rel_path = os.path.relpath(file_path, sandboxie_folder)
        dest_path = os.path.join(dest_root, rel_path)
    else:
        # File is not in sandboxie, create under main file folder
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(dest_root, file_name)

    # Create destination directory structure
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # Try normal copy first
    try:
        shutil.copy2(file_path, dest_path)
        logger.info(f"Copied '{file_path}' to '{dest_path}'")
        return dest_path
    except Exception as e:
        logger.error(f"Normal copy failed ({e}), attempting shadow copy")

    # Fallback: shadow copy
    drive = os.path.splitdrive(file_path)[0]  # e.g. "C:"
    shadow_root = create_shadow_copy(drive)
    if shadow_root:
        if file_path.startswith(sandboxie_folder):
            shadow_rel_path = os.path.relpath(file_path, sandboxie_folder)
        else:
            shadow_rel_path = os.path.basename(file_path)

        if copy_from_shadow(shadow_root, shadow_rel_path, dest_path):
            logger.info(f"Copied from shadow '{file_path}' to '{dest_path}'")
            return dest_path

    logger.error(f"All copy methods failed for: {file_path}")
    return None

def decompile_cx_freeze(executable_path):
    """
    Extracts <exe_name>__main__.pyc from a cx_Freeze library.zip using pyzipper,
    and returns the path to the extracted .pyc file.
    """
    exe_name = os.path.splitext(os.path.basename(executable_path))[0]
    dist_dir = os.path.join(os.path.dirname(executable_path), "dist")
    lib_zip_path = os.path.join(dist_dir, "lib", "library.zip")

    if not os.path.isfile(lib_zip_path):
        logger.error("CXFreeze library.zip not found: %s", lib_zip_path)
        return None

    target_pyc_name = f"{exe_name}__main__.pyc"

    try:
        os.makedirs(cx_freeze_extracted_dir, exist_ok=True)
    except Exception as e:
        logger.error("Failed to create directory %s: %s", cx_freeze_extracted_dir, e)
        return None

    extracted_pyc_path = os.path.join(cx_freeze_extracted_dir, target_pyc_name)

    try:
        with pyzipper.AESZipFile(lib_zip_path, 'r') as zipf:
            if target_pyc_name not in zipf.namelist():
                logger.error("File '%s' not found in archive: %s", target_pyc_name, lib_zip_path)
                return None

            with zipf.open(target_pyc_name) as src, open(extracted_pyc_path, "wb") as dst:
                dst.write(src.read())

            logger.info("Extracted file: %s", extracted_pyc_path)

    except Exception as e:
        logger.error("Failed to extract '%s' from '%s': %s", target_pyc_name, lib_zip_path, e)
        return None

    return extracted_pyc_path

num_cores = os.cpu_count()  # returns the number of logical CPUs
max_workers=num_cores * 2
executor = ThreadPoolExecutor(max_workers=max_workers)

def run_in_thread(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        return executor.submit(fn, *args, **kwargs)
    return wrapper

def show_code_with_pylingual_pycdas(
    file_path: str,
) -> Tuple[Optional[List[str]], Optional[List[str]]]:
    """
    Decompile a .pyc file using both Pylingual and pycdas decompilers.

    Returns:
        Tuple:
          - pylingual_files: List of file paths to decompiled .py files by Pylingual, or None
          - pycdas_files: List of file paths to decompiled files by pycdas, or None
    """
    try:
        logger.info(f"Decompiling with Pylingual and pycdas: {file_path}")
        pyc_path = Path(file_path)
        if not pyc_path.exists():
            logger.error(f".pyc file not found: {file_path}")
            return None, None

        pylingual_files: List[str] = []
        pycdas_files: List[str] = []

        # === Pylingual Decompilation ===
        try:
            # Create output directory for Pylingual
            target_dir = Path(pylingual_extracted_dir) / f"decompiled_{pyc_path.stem}"
            target_dir.mkdir(parents=True, exist_ok=True)

            # Run Pylingual decompiler (writes files into target_dir)
            decompile_pyc_with_pylingual(str(pyc_path))

            # Collect all .py files produced by Pylingual
            py_files = list(target_dir.rglob("*.py"))

            if not py_files:
                # Sometimes Pylingual might output in a subdirectory
                possible_subdir = target_dir / f"decompiled_{pyc_path.stem}"
                if possible_subdir.exists():
                    py_files = list(possible_subdir.rglob("*.py"))

            pylingual_files = [str(p) for p in py_files]
            logger.info(f"Pylingual decompiled {len(pylingual_files)} .py files")

        except Exception as pylingual_ex:
            logger.error(f"Pylingual decompilation failed for {file_path}: {pylingual_ex}")

        # === pycdas Decompilation ===
        try:
            pycdas_output_path = run_pycdas_decompiler(file_path)

            if pycdas_output_path and os.path.exists(pycdas_output_path):
                pycdas_files.append(str(pycdas_output_path))
                logger.info(f"pycdas decompilation completed. Output: {pycdas_output_path}")
            else:
                logger.error(f"pycdas decompilation failed or produced no output for {file_path}")

        except Exception as pycdas_ex:
            logger.error(f"pycdas decompilation failed for {file_path}: {pycdas_ex}")

        # Return lists or None if empty
        return (
            pylingual_files if pylingual_files else None,
            pycdas_files if pycdas_files else None,
        )

    except Exception as ex:
        logger.error(f"Unexpected error in show_code_with_pylingual_pycdas for {file_path}: {ex}")
        return None, None

def run_themida_unlicense(file_path, x64=False):
    """
    Runs Themida/WinLicense unpacker inside Sandboxie.
    Uses unlicense.exe (x86) or unlicense-x64.exe (x64) based on arch.
    The unpacker creates a new file with 'unpacked_' prefix in the same directory,
    which we then move into themida_unpacked_dir for consistency.
    """
    if not os.path.isfile(file_path):
        logger.error(f"Invalid input file: {file_path}")
        return None

    # choose correct unpacker
    unpacker = unlicense_x64_path if x64 else unlicense_path
    if not os.path.isfile(unpacker):
        logger.error(f"Unpacker not found: {unpacker}")
        return None

    # build Sandboxie command
    HydraDragonAntivirus_sandboxie_path = get_sandbox_path(script_dir)
    cmd = [
        HydraDragonAntivirus_sandboxie_path,
        "/box:DefaultBox",
        "/elevate",
        unpacker,
        file_path
    ]

    try:
        subprocess.run(cmd, check=True, encoding="utf-8", errors="ignore")
        logger.info(f"Unlicense unpacking succeeded for {file_path} in sandbox DefaultBox")

        # Expected unpacked file in same directory
        unpacked_path = os.path.join(
            os.path.dirname(file_path),
            "unpacked_" + os.path.basename(file_path)
        )

        if os.path.isfile(unpacked_path):
            # Move unpacked file into themida_unpacked_dir with unique name
            final_path = os.path.join(
                themida_unpacked_dir,
                "unpacked_" + os.path.basename(file_path)
            )
            if os.path.exists(final_path):
                base, ext = os.path.splitext(final_path)
                counter = 1
                while os.path.exists(f"{base}_{counter}{ext}"):
                    counter += 1
                final_path = f"{base}_{counter}{ext}"

            shutil.move(unpacked_path, final_path)
            logger.info(f"Unpacked file moved to: {final_path}")
            return final_path
        else:
            logger.error(f"Unpacker finished but no unpacked file found for {file_path}")
            return None

    except subprocess.CalledProcessError as ex:
        logger.error(f"Failed to run unlicense on {file_path} in sandbox DefaultBox: {ex}")
        return None

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
                  ntdll_dropped=False,
                  flag_confuserex=False):
    """
    Scans a file for potential issues with comprehensive threading for performance.
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
        die_output = ""
        plain_text_flag = False

        # Convert WindowsPath to string if necessary
        if isinstance(file_path, WindowsPath):
            file_path = str(file_path)

        # Ensure path is a string, exists, and is non-empty
        if not isinstance(file_path, str):
            logger.error(f"Invalid file_path type: {type(file_path).__name__}")
            return False

        # Ensure the file exists before proceeding.
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False

        # Check if the file is empty.
        if os.path.getsize(file_path) == 0:
            logger.debug(f"File {file_path} is empty. Skipping scan.")
            return False

        # Normalize the original path
        norm_path = os.path.abspath(file_path)

        # Compute a quick MD5
        md5 = compute_md5(norm_path)

        # If we've already scanned this exact (path, hash), skip immediately
        key = (norm_path.lower(), md5)
        if key in seen_files:
            logger.debug(f"Skipping duplicate scan for {norm_path} (hash={md5})")
            return False

         # Mark it seen and proceed
        seen_files.add(key)

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
                threading.Thread(target=scan_and_warn, args=(dest,
                                mega_optimization_with_anti_false_positive,
                                command_flag, flag_debloat, flag_obfuscar,
                                flag_de4dot, flag_fernflower, nsis_flag, ntdll_dropped)).start()
        elif normalized_path.startswith(normalized_sandbox):
            # Check if this is a dropped ntdll.dll in the sandbox
            if normalized_path == sandboxed_ntdll_path:
                ntdll_dropped = True
                logger.critical(f"ntdll.dll dropped in sandbox at path: {normalized_path}")
                # Optionally force a special scan for this file
                perform_special_scan = True
                # You may choose a specific dir for ntdll analysis, or reuse existing staging dir
                dest = _copy_to_dest(norm_path, copied_sandbox_and_main_files_dir)
                if dest is not None:
                    threading.Thread(target=scan_and_warn, args=(dest,
                        mega_optimization_with_anti_false_positive, command_flag,
                        flag_debloat, flag_obfuscar, flag_de4dot, flag_fernflower,
                        nsis_flag, ntdll_dropped)).start()

            perform_special_scan = True
            dest = _copy_to_dest(norm_path, copied_sandbox_and_main_files_dir)
            if dest is not None:
                threading.Thread(target=scan_and_warn, args=(dest,
                    mega_optimization_with_anti_false_positive, command_flag,
                    flag_debloat, flag_obfuscar, flag_de4dot, flag_fernflower,
                    nsis_flag, ntdll_dropped)).start()

        # 1) Is this the first time we've seen this path?
        is_first_pass = norm_path not in file_md5_cache
        file_name = os.path.basename(norm_path)

        # ========== CRITICAL PATH - NO THREADING (affects return behavior) ==========

        # Get DIE output first (needed for early exit decisions)
        if md5 in die_cache:
            die_output, plain_text_flag = die_cache[md5]
        else:
            die_output, plain_text_flag = get_die_output(norm_path)
            die_cache[md5] = (die_output, plain_text_flag)

        # CRITICAL: Ransomware check that can cause early return - NO THREADING
        if is_file_fully_unknown(die_output):
            if perform_special_scan:
                ransomware_alert(norm_path)  # Direct call, not threaded
            if mega_optimization_with_anti_false_positive:
                logger.info(f"Stopped analysis; unknown data detected in {norm_path}")
                return False  # EARLY EXIT - must not be threaded

        # CRITICAL: File type checks that can cause early return - NO THREADING
        pefile_result = is_pe_file_from_output(die_output, norm_path)
        if pefile_result:
            logger.info(f"The file {norm_path} is a valid PE file.")
            pe_file = True
        elif pefile_result == "Broken Executable" and mega_optimization_with_anti_false_positive:
            logger.info(f"The file {norm_path} is a broken PE file. Skipping scan...")
            return False  # EARLY EXIT

        apk_result = is_apk_file_from_output(die_output, norm_path)
        if apk_result == "Broken APK" and mega_optimization_with_anti_false_positive:
            logger.info(f"The file {norm_path} is a broken APK file. Skipping scan...")
            return False  # EARLY EXIT

        elf_result = is_elf_file_from_output(die_output, norm_path)
        if elf_result == "Broken Executable" and mega_optimization_with_anti_false_positive:
            logger.info(f"The file {norm_path} is a broken ELF file. Skipping scan...")
            return False  # EARLY EXIT

        macho_result = is_macho_file_from_output(die_output, norm_path)
        if macho_result == "Broken Executable" and mega_optimization_with_anti_false_positive:
            logger.info(f"The file {norm_path} is a broken Mach-0 file. Skipping scan...")
            return False  # EARLY EXIT

        # Handle first pass worm detection - CRITICAL PATH
        if not is_first_pass and perform_special_scan and pe_file:
            worm_alert(norm_path)  # Direct call, not threaded
            return False  # EARLY EXIT

        # ========== THREADED OPERATIONS START HERE ==========
        # Now we can safely use threading since no more early returns

        # Shared data for threads
        thread_results = {
            'signature_check': None,
            'file_lines': [],
            'dotnet_result': None
        }

        def signature_check_thread():
            """Thread for digital signature verification - can be slow"""
            try:
                sig_check = check_signature(norm_path)
                with thread_lock:
                    thread_results['signature_check'] = sig_check
                logger.debug(f"Signature check completed for {norm_path}")
            except Exception as e:
                logger.error(f"Error in signature check thread for {norm_path}: {e}")
                with thread_lock:
                    thread_results['signature_check'] = {
                        "has_microsoft_signature": False,
                        "is_valid": False,
                        "signature_status_issues": False
                    }


            # Use the signature_check produced by the thread when calling ML fast-path
            sig_for_ml = thread_results.get('signature_check', None)

            # ML fast-path: if returns False -> ML marked benign => EARLY EXIT (do not start realtime thread)
            if not ml_fastpath_should_continue(norm_path, sig_for_ml, pe_file):
                return False

        def file_reading_thread():
            """Thread for reading file content as text"""
            try:
                lines = []
                with open(norm_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                with thread_lock:
                    thread_results['file_lines'] = lines
            except Exception as e:
                logger.error(f"Failed to read text lines from {norm_path}: {e}")

        # Start background threads for I/O operations
        signature_thread = threading.Thread(target=signature_check_thread)
        file_read_thread = threading.Thread(target=file_reading_thread)

        signature_thread.start()
        file_read_thread.start()

        # Path analysis - direct execution (fast)
        wrap_norm_path = Path(norm_path)

        if Path(obfuscar_dir) in wrap_norm_path.parents and not flag_obfuscar:
            flag_obfuscar = True
            logger.info(f"Flag set to True because '{norm_path}' is inside the Obfuscar directory.")

        match = next((Path(p) for p in (de4dot_extracted_dir, de4dot_sandboxie_dir)
                     if Path(p) in wrap_norm_path.parents), None)
        if match and not flag_de4dot:
            flag_de4dot = True
            logger.info(f"Flag set to True because '{norm_path}' is inside the de4dot directory '{match}'")

        # ========== SPECIALIZED ANALYSIS THREADS ==========
        def vmprotect_detection():
            """
            Detects VMProtect in a PE file using is_vm_protect_from_output.
            Attempts to unpack if detected and logs PE32/PE64 type.
            """
            try:
                if is_vm_protect_from_output(die_output):  # Use the VMProtect checker
                    # Attempt to unpack
                    try:
                        with open(file_path, 'rb') as f:
                            packed_data = f.read()

                        unpacked_data = unpack_pe(packed_data)  # unpacking function
                        if unpacked_data:
                            base_name, ext = os.path.splitext(os.path.basename(file_path))
                            unpacked_name = f"{base_name}_vmprotect_unpacked{ext}"
                            unpacked_path = os.path.join(vmprotect_unpacked_dir, unpacked_name)

                            with open(unpacked_path, 'wb') as f:
                                f.write(unpacked_data)

                            logger.info(f"VMProtect unpacked successfully: {unpacked_path}")

                            # Optional: further scanning/warning in a thread
                            threading.Thread(target=scan_and_warn, args=(unpacked_path,)).start()

                    except Exception as e:
                        logger.error(f"Error unpacking VMProtect file '{file_path}': {e}")

            except Exception as e:
                logger.error(f"Error in VMProtect detection for '{file_path}': {e}")

        def themida_detection():
            try:
                is_themida_protected = is_themida_from_output(die_output)
                if is_themida_protected == "PE32 Themida":
                    logger.info(f"File '{norm_path}' is protected by Themida 32 bit.")
                    run_themida_unlicense(norm_path)
                    threading.Thread(target=scan_and_warn, args=(norm_path,)).start()
                elif is_themida_protected == "PE64 Themida":
                    logger.info(f"File '{norm_path}' is protected by Themida 64 bit.")
                    run_themida_unlicense(norm_path, x64=True)
                    threading.Thread(target=scan_and_warn, args=(norm_path,)).start()
            except Exception as e:
                logger.error(f"Error in Themida detection for {norm_path}: {e}")

        def autoit_analysis():
            try:
                if is_autoit_file_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid AutoIt file.")
                    extracted_autoit_files = extract_autoit(norm_path)
                    for extracted_autoit_file in extracted_autoit_files:
                        threading.Thread(target=scan_and_warn, args=(extracted_autoit_file,)).start()
            except Exception as e:
                logger.error(f"Error in AutoIt analysis for {norm_path}: {e}")

        def asar_analysis():
            try:
                if is_asar_archive_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid Asar Archive (Electron).")
                    extracted_asar_files = extract_asar_file(norm_path)
                    for extracted_asar_file in extracted_asar_files:
                        threading.Thread(target=scan_and_warn, args=(extracted_asar_file,)).start()
            except Exception as e:
                logger.error(f"Error in ASAR analysis for {norm_path}: {e}")

        def npm_analysis():
            try:
                if is_npm_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid npm package.")
                    extracted_npm_files = extract_npm_file(norm_path)
                    for extracted_file in extracted_npm_files:
                        threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()
            except Exception as e:
                logger.error(f"Error in npm analysis for {norm_path}: {e}")

        def jsc_analysis():
            """
            If DIE output indicates a compiled JavaScript (Bytenode .JSC or bundle.js),
            first decode/decompile using View8, then optionally deobfuscate with Webcrack,
            and finally scan the resulting files.
            """
            try:
                # Detect if it's a JSC or JS bundle file
                jsc_result = is_jsc_from_output(die_output)
                if not jsc_result:
                    return  # Not a JSC file, skip

                logger.info(f"File {norm_path} detected as {jsc_result} (Bytenode / .JSC / JS bundle).")

                # Step 0: Create a unique subfolder for this decompiled JSC
                folder_number = 1
                while os.path.exists(os.path.join(decompiled_jsc_dir, str(folder_number))):
                    folder_number += 1
                file_decompiled_dir = os.path.join(decompiled_jsc_dir, str(folder_number))
                os.makedirs(file_decompiled_dir, exist_ok=True)

                # Step 1: Decode/Decompile using View8
                try:
                    all_func = disassemble(norm_path, input_is_disassembled=False, disassembler=None)
                    export_file_path = os.path.join(file_decompiled_dir, Path(norm_path).stem + "_decompiled.js")
                    decompile(all_func)
                    export_to_file(export_file_path, all_func, ["decompiled"])
                    logger.info(f"Successfully decompiled {norm_path} to {export_file_path}")
                except Exception as decomp_err:
                    logger.error(f"View8 decompilation failed for {norm_path}: {decomp_err}")
                    return

                # Step 2: Optionally deobfuscate with Webcrack
                try:
                    js_output_dir = deobfuscate_webcrack_js(export_file_path)
                except Exception as deobf_err:
                    logger.error(f"Webcrack deobfuscation failed for {export_file_path}: {deobf_err}")
                    js_output_dir = export_file_path  # fallback: just scan the decompiled file

                # Step 3: Scan decompiled/deobfuscated files
                scan_paths = []
                if os.path.isdir(js_output_dir):
                    for root, _, files in os.walk(js_output_dir):
                        for file in files:
                            scan_paths.append(os.path.join(root, file))
                else:
                    scan_paths.append(js_output_dir)

                for file_path_full in scan_paths:
                    try:
                        with open(file_path_full, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        threading.Thread(
                            target=scan_code_for_links,
                            args=(content, file_path_full),
                            kwargs={"jsc_flag": True}
                        ).start()

                        threading.Thread(
                            target=scan_and_warn,
                            args=(file_path_full,),
                        ).start()

                    except Exception as scan_err:
                        logger.error(f"Error scanning file {file_path_full}: {scan_err}")

            except Exception as e:
                logger.error(f"Error in JSC analysis for {norm_path}: {e}")

        def installshield_analysis():
            try:
                if is_installshield_file_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid Install Shield file.")
                    extracted_installshield_files = extract_installshield(norm_path)
                    for extracted_installshield_file in extracted_installshield_files:
                        threading.Thread(target=scan_and_warn, args=(extracted_installshield_file,)).start()
            except Exception as e:
                logger.error(f"Error in InstallShield analysis for {norm_path}: {e}")

        def advanced_installer_analysis():
            try:
                if is_advanced_installer_file_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid Advanced Installer file.")
                    extracted_files = advanced_installer_extractor(norm_path)
                    for extracted_file in extracted_files:
                        threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()
            except Exception as e:
                logger.error(f"Error in Advanced Installer analysis for {norm_path}: {e}")

        def apk_analysis():
            try:
                if apk_result:
                    logger.info(f"File {norm_path} is a valid APK file.")
                    decompile_apk_files = decompile_apk_file(norm_path)
                    if decompile_apk_files:
                        for decompiled_apk_file in decompile_apk_files:
                            threading.Thread(target=scan_and_warn, args=(decompiled_apk_file,)).start()
            except Exception as e:
                logger.error(f"Error in APK analysis for {norm_path}: {e}")

        def dotnet_analysis():
            try:
                dotnet_result = is_dotnet_file_from_output(die_output)
                if os.path.isfile(norm_path):
                    input_dir = os.path.dirname(norm_path)
                else:
                    input_dir = norm_path

                normalized_input = os.path.abspath(input_dir).lower()

                if normalized_input.startswith(normalized_sandbox):
                    if dotnet_result is not None and not flag_de4dot and "Protector: Obfuscar" not in dotnet_result:
                        de4dot_thread = threading.Thread(target=run_de4dot_in_sandbox, args=(input_dir,))
                        de4dot_thread.start()

                        if "Probably No Protector" in dotnet_result or "Already Deobfuscated" in dotnet_result:
                            dotnet_thread = threading.Thread(target=decompile_dotnet_file, args=(input_dir,))
                            dotnet_thread.start()

                with thread_lock:
                    thread_results['dotnet_result'] = dotnet_result
            except Exception as e:
                logger.error(f"Error in .NET analysis for {norm_path}: {e}")

        def cx_freeze_thread():
            try:
                if is_cx_freeze_file_from_output(die_output):
                    logger.info(f"Invoking cx_Freeze decompiler on {norm_path}")
                    cx_main_pyc = decompile_cx_freeze(norm_path)
                    if cx_main_pyc:
                        threading.Thread(target=scan_and_warn, args=(cx_main_pyc,)).start()
            except Exception as e:
                logger.error(f"Error decompiling cx_Freeze stub at {norm_path}: {e}")

        # Start all specialized analysis threads
        analysis_threads = [
            threading.Thread(target=vmprotect_detection),
            threading.Thread(target=themida_detection),
            threading.Thread(target=autoit_analysis),
            threading.Thread(target=asar_analysis),
            threading.Thread(target=npm_analysis),
            threading.Thread(target=jsc_analysis),
            threading.Thread(target=installshield_analysis),
            threading.Thread(target=advanced_installer_analysis),
            threading.Thread(target=apk_analysis),
            threading.Thread(target=dotnet_analysis),
            threading.Thread(target=cx_freeze_thread)
        ]

        for thread in analysis_threads:
            thread.start()

        # Cache check - CRITICAL PATH
        if initial_md5_in_cache == md5:
            logger.info(f"Skipping scan for unchanged file: {norm_path}")
            return False  # EARLY EXIT
        else:
            file_md5_cache[norm_path] = md5

        logger.info(f"Deep scanning file: {norm_path}")

        # ========== BINARY vs TEXT FILE PROCESSING ==========

        if not plain_text_flag:
            # Binary file processing with threading
            logger.info(f"File {norm_path} contains valid non plain text data.")

            # Heavy extraction operations in threads
            def extraction_thread():
                try:
                    logger.info(f"Attempting to extract file {norm_path}...")
                    extracted_files = extract_all_files_with_7z(norm_path, nsis_flag)
                    if extracted_files:
                        logger.info(f"Extraction successful for {norm_path}. Scanning extracted files...")
                        for extracted_file in extracted_files:
                            threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()
                except Exception as e:
                    logger.error(f"Error during extraction of {norm_path}: {e}")

            def enigma_thread():
                try:
                    if is_enigma1_virtual_box(die_output):
                        extracted_path = try_unpack_enigma1(norm_path)
                        if extracted_path:
                            logger.info(f"Unpack succeeded. Files are in: {extracted_path}")
                            threading.Thread(target=scan_and_warn, args=(extracted_path,)).start()
                except Exception as e:
                    logger.error(f"Error in Enigma1 unpacking for {norm_path}: {e}")

            def upx_thread():
                try:
                    if is_packer_upx_output(die_output):
                        upx_unpacked = extract_upx(norm_path)
                        if upx_unpacked:
                            threading.Thread(target=scan_and_warn, args=(upx_unpacked,)).start()
                except Exception as e:
                    logger.error(f"Error in UPX unpacking for {norm_path}: {e}")

            def unipacker_thread():
                try:
                    if is_packed_from_output(die_output):
                        unpacked_file = extract_with_unipacker(norm_path)
                        if unpacked_file:
                            threading.Thread(target=scan_and_warn, args=(unpacked_file,)).start()
                except Exception as e:
                    logger.error(f"Error in Unipacker unpacking for {norm_path}: {e}")

            def inno_setup_thread():
                try:
                    if is_inno_setup_archive_from_output(die_output):
                        extracted = extract_inno_setup(norm_path)
                        if extracted is not None:
                            logger.info(f"Extracted {len(extracted)} files. Scanning...")
                            for inno_norm_path in extracted:
                                threading.Thread(target=scan_and_warn, args=(inno_norm_path,)).start()
                except Exception as e:
                    logger.error(f"Error in Inno Setup extraction for {norm_path}: {e}")

            def go_garble_thread():
                try:
                    if is_go_garble_from_output(die_output):
                        output_path = os.path.join(ungarbler_dir, os.path.basename(norm_path))
                        string_output_path = os.path.join(ungarbler_string_dir, os.path.basename(norm_path) + "_strings.txt")
                        results = process_file_go(norm_path, output_path, string_output_path)

                        if results.get("patched_data"):
                            threading.Thread(target=scan_and_warn, args=(output_path,)).start()
                        if results.get("decrypt_func_list"):
                            threading.Thread(target=scan_and_warn, args=(string_output_path,)).start()
                except Exception as e:
                    logger.error(f"Error in Go Garble processing for {norm_path}: {e}")

            def pyc_thread():
                try:
                    if is_pyc_file_from_output(die_output):
                        logger.info(f"File {norm_path} is a .pyc file. Attempting Pylingual decompilation...")
                        pylingual, pycdas = show_code_with_pylingual_pycdas(file_path=norm_path)

                        if pylingual:
                            for fname in pylingual.keys():
                                threading.Thread(target=scan_and_warn, kwargs={"file_path": fname}).start()
                                threading.Thread(target=process_decompiled_code, args=(fname,)).start()

                        if pycdas:
                            for rname in pycdas.keys():
                                threading.Thread(target=scan_and_warn, kwargs={"file_path": rname}).start()
                except Exception as e:
                    logger.error(f"Error in PYC processing for {norm_path}: {e}")

            def nsis_thread():
                try:
                    if is_nsis_from_output(die_output):
                        nonlocal nsis_flag
                        nsis_flag = True
                except Exception as e:
                    logger.error(f"Error in NSIS detection for {norm_path}: {e}")

            # Start binary processing threads
            binary_threads = [
                threading.Thread(target=extraction_thread),
                threading.Thread(target=enigma_thread),
                threading.Thread(target=unipacker_thread),
                threading.Thread(target=upx_thread),
                threading.Thread(target=inno_setup_thread),
                threading.Thread(target=go_garble_thread),
                threading.Thread(target=pyc_thread),
                threading.Thread(target=nsis_thread)
            ]

            for thread in binary_threads:
                thread.start()

        # ========== PE FILE SPECIFIC PROCESSING ==========
        if pe_file:
            logger.info(f"File {norm_path} is identified as a PE file.")

            # Wait for signature check to complete (needed for PE logic)
            signature_thread.join()
            signature_check = thread_results.get('signature_check', {
                "has_microsoft_signature": False,
                "is_valid": False,
                "signature_status_issues": False
            })

            # CRITICAL: Early returns for valid signatures - NO THREADING
            if signature_check["has_microsoft_signature"]:
                logger.info(f"Valid Microsoft signature detected for file: {norm_path}")
                return False

            if signature_check.get("valid_goodsign_signatures"):
                logger.info(f"Valid good signature(s) detected for file: {norm_path}")
                return False

            # Handle signature validation
            if signature_check["is_valid"]:
                logger.info(f"File '{norm_path}' has a valid signature. Skipping worm detection.")
            elif signature_check["signature_status_issues"] and not signature_check.get("no_signature"):
                logger.critical(f"File '{norm_path}' has signature issues. Proceeding with further checks.")
                threading.Thread(target=notify_user_invalid, args=(norm_path, "Win32.Susp.InvalidSignature")).start()

            # PE-specific threaded operations
            def capa_analysis_thread():
                try:
                    capa_analysis_results = analyze_file_with_capa(norm_path)
                    if capa_analysis_results:
                        threading.Thread(target=scan_file_with_meta_llama,
                                       args=(capa_analysis_results,),
                                       kwargs={"capa_flag": True}).start()
                        threading.Thread(target=scan_and_warn, args=(capa_analysis_results,)).start()
                except Exception as e:
                    logger.error(f"Error in CAPA analysis for {norm_path}: {e}")

            def scr_detection_thread():
                try:
                    if norm_path.lower().endswith(".scr"):
                        logger.critical(f"Suspicious .scr file detected: {norm_path}")
                        threading.Thread(target=notify_user_scr, args=(norm_path, "HEUR:Win32.Susp.PE.SCR.gen")).start()
                except Exception as e:
                    logger.error(f"Error in SCR detection for {norm_path}: {e}")

            def decompile_thread():
                try:
                    decompile_file(norm_path)
                except Exception as e:
                    logger.error(f"Error in decompilation for {norm_path}: {e}")

            def pe_section_thread():
                try:
                    section_files = extract_pe_sections(norm_path)
                    if section_files:
                        logger.info(f"Extracted {len(section_files)} PE sections. Scanning...")
                        for fpath in section_files:
                            threading.Thread(target=scan_and_warn, args=(fpath,)).start()
                except Exception as e:
                    logger.error(f"Error in PE section extraction for {norm_path}: {e}")

            def resource_extraction_thread():
                try:
                    extracted = extract_resources(norm_path, resource_extractor_dir)
                    if extracted:
                        for file in extracted:
                            threading.Thread(target=scan_and_warn, args=(file,)).start()
                except Exception as e:
                    logger.error(f"Error in resource extraction for {norm_path}: {e}")

            def debloat_thread():
                try:
                    if not flag_debloat:
                        logger.info(f"Debloating PE file {norm_path} for faster scanning.")
                        optimized_norm_path = debloat_pe_file(norm_path)
                        if optimized_norm_path:
                            logger.info(f"Debloated file saved at: {optimized_norm_path}")
                            threading.Thread(target=scan_and_warn,
                                           args=(optimized_norm_path,),
                                           kwargs={'flag_debloat': True}).start()
                except Exception as e:
                    logger.error(f"Error during debloating of {norm_path}: {e}")

            # Start PE processing threads
            pe_threads = [
                threading.Thread(target=capa_analysis_thread),
                threading.Thread(target=scr_detection_thread),
                threading.Thread(target=decompile_thread),
                threading.Thread(target=pe_section_thread),
                threading.Thread(target=resource_extraction_thread),
                threading.Thread(target=debloat_thread)
            ]

            for thread in pe_threads:
                thread.start()

        # ========== POST-ANALYSIS PROCESSING ==========

        # Wait for dotnet analysis to complete (needed for obfuscation logic)
        for thread in analysis_threads:
            if thread.name == 'dotnet_analysis':
                thread.join()
                break

        dotnet_result = thread_results.get('dotnet_result')

        # .NET specific processing (threaded)
        def dotnet_obfuscar_thread():
            try:
                if isinstance(dotnet_result, str) and "Protector: Obfuscar" in dotnet_result and not flag_obfuscar:
                    logger.info(f"The file is a .NET assembly protected with Obfuscar: {dotnet_result}")
                    deobfuscated_path = deobfuscate_with_obfuscar(norm_path, file_name)
                    if deobfuscated_path:
                        threading.Thread(target=scan_and_warn,
                                       args=(deobfuscated_path,),
                                       kwargs={'flag_obfuscar': True}).start()
            except Exception as e:
                logger.error(f"Error in Obfuscar deobfuscation for {norm_path}: {e}")

        def dotnet_reactor_thread():
            try:
                if isinstance(dotnet_result, str) and "Protector: .NET Reactor" in dotnet_result:
                    logger.info(f"The file is a .NET assembly protected with .NET Reactor: {dotnet_result}")
                    deobfuscated_path = deobfuscate_with_net_reactor(norm_path, file_name)
                    if deobfuscated_path:
                        threading.Thread(target=scan_and_warn, args=(deobfuscated_path,)).start()
            except Exception as e:
                logger.error(f"Error in .NET Reactor deobfuscation for {norm_path}: {e}")

        def dotnet_confuserex_thread():
            """
            Thread handler for ConfuserEx-protected .NET assemblies.

            Behavior:
            - If `dotnet_result` indicates "Protector: ConfuserEx" and `flag_confuserex` is not set,
                it will attempt to deobfuscate using `deobfuscate_with_confuserex`.
            - If deobfuscation succeeds, it starts a new thread that calls `scan_and_warn`
                with the deobfuscated file and sets `flag_confuserex=True` in kwargs.
            """
            try:
                # NOTE: dotnet_result, norm_path, file_name, flag_confuserex and scan_and_warn
                # are expected to be available in the surrounding scope / caller.
                if isinstance(dotnet_result, str) and "Protector: ConfuserEx" in dotnet_result and not flag_confuserex:
                    logger.info(f"The file is a .NET assembly protected with ConfuserEx: {dotnet_result}")
                    deobfuscated_path = deobfuscate_with_confuserex(norm_path, file_name)
                    if deobfuscated_path:
                        threading.Thread(
                            target=scan_and_warn,
                            args=(deobfuscated_path,),
                            kwargs={'flag_confuserex': True}
                        ).start()

            except Exception as e:
                logger.error(f"Error in ConfuserEx deobfuscation for {norm_path}: {e}")

        def jar_analysis_thread():
            try:
                if is_jar_file_from_output(die_output):
                    jar_extractor_paths = run_jar_extractor(norm_path, flag_fernflower)
                    if jar_extractor_paths:
                        for jar_extractor_path in jar_extractor_paths:
                            threading.Thread(target=scan_and_warn,
                                           args=(jar_extractor_path,),
                                           kwargs={'flag_fernflower': True}).start()
            except Exception as e:
                logger.error(f"Error in JAR analysis for {norm_path}: {e}")

        def java_class_thread():
            try:
                if is_java_class_from_output(die_output):
                    threading.Thread(target=run_fernflower_decompiler, args=(norm_path,)).start()
            except Exception as e:
                logger.error(f"Error in Java class analysis for {norm_path}: {e}")

        def nuitka_thread():
            try:
                nuitka_type = is_nuitka_file_from_output(die_output)
                if nuitka_type:
                    logger.info(f"Checking if the file {norm_path} contains Nuitka executable of type: {nuitka_type}")
                    nuitka_files = extract_nuitka_file(norm_path, nuitka_type)
                    if nuitka_files:
                        for extracted_file in nuitka_files:
                            threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()
            except Exception as e:
                logger.error(f"Error in Nuitka analysis for {norm_path}: {e}")

        def pyinstaller_thread():
            try:
                if is_pyinstaller_archive_from_output(die_output):
                    extracted_files_pyinstaller, main_decompiled_output = extract_and_return_pyinstaller(norm_path)

                    if main_decompiled_output:
                        threading.Thread(target=scan_and_warn, args=(main_decompiled_output,)).start()

                    if extracted_files_pyinstaller:
                        for extracted_file in extracted_files_pyinstaller:
                            threading.Thread(target=scan_and_warn, args=(extracted_file,)).start()
            except Exception as e:
                logger.error(f"Error in PyInstaller analysis for {norm_path}: {e}")

        # Start additional analysis threads
        additional_threads = [
            threading.Thread(target=dotnet_obfuscar_thread),
            threading.Thread(target=dotnet_reactor_thread),
            threading.Thread(target=dotnet_confuserex_thread),
            threading.Thread(target=jar_analysis_thread),
            threading.Thread(target=java_class_thread),
            threading.Thread(target=nuitka_thread),
            threading.Thread(target=pyinstaller_thread)
        ]

        for thread in additional_threads:
            thread.start()

        # ========== TEXT FILE PROCESSING ==========
        else:
            # Plain text file processing
            logger.info(f"File {norm_path} does contain plain text data.")

            # Wait for file reading to complete
            file_read_thread.join()
            lines = thread_results['file_lines']

        # If file is a .js file, deobfuscate it first
        if norm_path.lower().endswith(".js"):
            try:
                logger.info(f"Detected JavaScript file: {norm_path}, deobfuscating with Webcrack...")
                output_dir = deobfuscate_webcrack_js(norm_path)

                if output_dir and os.path.exists(output_dir):
                    logger.info(f"Scanning deobfuscated JS files in: {output_dir}")

                    for root, _, files in os.walk(output_dir):
                        for file in files:
                            file_path_full = os.path.join(root, file)
                            logger.info(f"Scanning deobfuscated file: {file_path_full}")

                            try:
                                with open(file_path_full, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()

                                # Scan for links, IPs, domains, Discord webhooks
                                threading.Thread(
                                    target=scan_code_for_links,
                                    args=(content, file_path_full),
                                    kwargs={"javascript_deobfuscated_flag": True}
                                ).start()

                                # Optional additional scanning/warnings
                                threading.Thread(
                                    target=scan_and_warn,
                                    args=(file_path_full,),
                                ).start()

                            except Exception as scan_err:
                                logger.error(f"Error scanning file {file_path_full}: {scan_err}")

            except Exception as deobf_err:
                logger.error(f"Webcrack deobfuscation failed for {norm_path}: {deobf_err}")

            # Homepage change processing (direct execution - needs early processing)
            if norm_path == homepage_change_path:
                try:
                    for line in lines:
                        line = line.strip()
                        if line:
                            parts = line.split(',')
                            if len(parts) == 2:
                                browser_tag, homepage_value = parts[0].strip(), parts[1].strip()
                                logger.info(f"Processing homepage change entry: Browser={browser_tag}, Homepage={homepage_value}")
                                scan_code_for_links(homepage_value, norm_path, homepage_flag=browser_tag)
                            else:
                                logger.error(f"Invalid format in homepage change file: {line}")
                except Exception as ex:
                    logger.error(f"Error processing homepage change file {norm_path}: {ex}")

            # Directory type logging
            log_directory_type(norm_path)

            # Check if file is in decompiled directory
            if norm_path.startswith(decompiled_dir):
                logger.info(f"File {norm_path} is in decompiled_dir.")
                is_decompiled = True

            # Meta Llama scanning for text files (threaded)
            def meta_llama_text_thread():
                try:
                    source_dirs = [
                        Path(decompiled_dir).resolve(),
                        Path(FernFlower_decompiled_dir).resolve(),
                        Path(dotnet_dir).resolve(),
                        Path(nuitka_source_code_dir).resolve(),
                    ]

                    norm_path_resolved = Path(norm_path).resolve()
                    ext = norm_path_resolved.suffix.lower()

                    if meta_llama_1b_model and meta_llama_1b_tokenizer:
                        if ext in script_exts:
                            threading.Thread(target=scan_file_with_meta_llama, args=(norm_path,)).start()
                        else:
                            for src in source_dirs:
                                try:
                                    norm_path_resolved.relative_to(src)
                                except ValueError:
                                    continue
                                else:
                                    threading.Thread(target=scan_file_with_meta_llama, args=(norm_path,)).start()
                                    break
                except Exception as e:
                    logger.error(f"Error in Meta Llama text processing for {norm_path}: {e}")

            # Real-time malware detection for command flag (threaded)
            def command_flag_thread():
                try:
                    if command_flag:
                        logger.info(f"Performing real-time malware detection for plain text file: {norm_path}...")
                        monitor_message.detect_malware(norm_path)
                except Exception as e:
                    logger.error(f"Error in command flag processing for {norm_path}: {e}")

            # Start text processing threads
            text_threads = [
                threading.Thread(target=meta_llama_text_thread),
                threading.Thread(target=command_flag_thread)
            ]

            for thread in text_threads:
                thread.start()

        # ========== COMMON PROCESSING FOR ALL FILES ==========

        # File processing thread (heavy I/O)
        def file_processing_thread():
            try:
                if not os.path.commonpath([norm_path, processed_dir]) == processed_dir:
                    process_file_data(norm_path, die_output)
            except Exception as e:
                logger.error(f"Error in file processing for {norm_path}: {e}")

        # Fake size check thread (heavy I/O for large files)
        def fake_size_check_thread():
            try:
                file_size = os.path.getsize(norm_path)
                if file_size > 100 * 1024 * 1024:  # File size > 100MB
                    with open(norm_path, 'rb') as fake_file:
                        file_content_read = fake_file.read(100 * 1024 * 1024)
                        if file_content_read == b'\x00' * 100 * 1024 * 1024:
                            logger.critical(f"File {norm_path} is flagged as HEUR:FakeSize.gen")
                            fake_size = "HEUR:FakeSize.gen"
                            if signature_check and signature_check["is_valid"]:
                                fake_size = "HEUR:SIG.Win32.FakeSize.gen"
                            threading.Thread(target=notify_user_fake_size, args=(norm_path, fake_size)).start()
            except Exception as e:
                logger.error(f"Error in fake size check for {norm_path}: {e}")

        # Real-time malware scan thread (CPU intensive)
        def realtime_malware_thread():
            try:
                is_malicious, virus_names, engine_detected, vmprotect_unpacked_path = scan_file_real_time(
                    norm_path, signature_check, file_name, die_output, pe_file=pe_file)

                if is_malicious:
                    virus_name = ''.join(virus_names)
                    logger.critical(f"File {norm_path} is malicious. Virus: {virus_name}")

                    if virus_name.startswith("PUA."):
                        threading.Thread(target=notify_user_pua, args=(norm_path, virus_name, engine_detected)).start()
                    else:
                        threading.Thread(target=notify_user, args=(norm_path, virus_name, engine_detected)).start()
                if vmprotect_unpacked_path:
                    threading.Thread(target=scan_and_warn, args=(vmprotect_unpacked_path,)).start()
            except Exception as e:
                logger.error(f"Error in real-time malware scan for {norm_path}: {e}")

        # Suspicious filename detection thread
        def filename_detection_thread():
            try:
                detection_result = detect_suspicious_filename_patterns(file_name, fileTypes)
                if detection_result['suspicious']:
                    attack_types = []
                    if detection_result['rlo_attack']:
                        attack_types.append("RLO")
                    if detection_result['excessive_spaces']:
                        attack_types.append("Spaces")
                    if detection_result['multiple_extensions']:
                        attack_types.append("MultiExt")

                    virus_name = f"HEUR:Susp.Name.{'+'.join(attack_types)}.gen"
                    threading.Thread(target=notify_user_susp_name, args=(norm_path, virus_name)).start()
            except Exception as e:
                logger.error(f"Error in filename detection for {norm_path}: {e}")

        # Decompilation post-processing thread
        def decompilation_postprocess_thread():
            try:
                if is_decompiled:
                    logger.info(f"Checking original file path from decompiled data for: {norm_path}")
                    extract_original_norm_path_from_decompiled(norm_path)
            except Exception as e:
                logger.error(f"Error in decompilation post-processing for {norm_path}: {e}")

        # Start common processing threads
        common_threads = [
            threading.Thread(target=file_processing_thread),
            threading.Thread(target=fake_size_check_thread),
            threading.Thread(target=realtime_malware_thread),
            threading.Thread(target=filename_detection_thread),
            threading.Thread(target=decompilation_postprocess_thread)
        ]

        for thread in common_threads:
            thread.start()

        # ========== CLEANUP AND RETURN ==========

        # Note: We don't join all threads here because many are fire-and-forget
        # operations that don't affect the main scan flow. The function can return
        # while background threads continue processing.

        logger.info(f"Main scan completed for {norm_path}, background processing continues...")
        return False  # Scan completed successfully

    except Exception as ex:
        logger.error(f"Error scanning file {norm_path}: {ex}")
        return False


class LogFileEventHandler(FileSystemEventHandler):
    """Handles file system events for the log file."""
    def __init__(self, filename):
        self.filename = os.path.abspath(filename)
        # Start reading from the end of the file.
        try:
            self.last_position = os.path.getsize(self.filename)
        except FileNotFoundError:
            self.last_position = 0
        logger.info(f"Handler initialized for {self.filename}, starting at position {self.last_position}")

    def on_modified(self, event):
        """
        Called when a file or directory is modified.
        """
        # We only care about modifications to our specific log file.
        if event.src_path != self.filename:
            return

        try:
            current_position = os.path.getsize(self.filename)

            # Handle log rotation or truncation.
            if current_position < self.last_position:
                logger.info("Log file has been reset. Reading from the beginning.")
                self.last_position = 0

            # If the file has grown, read the new lines.
            if current_position > self.last_position:
                with open(self.filename, 'r', encoding='utf-8') as f:
                    f.seek(self.last_position)
                    new_lines = f.readlines()
                    self.last_position = f.tell()

                # Process new lines after closing the file to release the lock.
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event_data = json.loads(line)
                        file_path_to_scan = event_data.get("file_path")

                        if file_path_to_scan:
                            process_name = event_data.get('process_name', 'N/A')
                            logger.info(f"New event detected for process '{process_name}'")
                            scan_and_warn(file_path_to_scan)
                        else:
                            logger.error("Found event log line without a 'file_path' key.")

                    except json.JSONDecodeError:
                        logger.error(f"Could not decode JSON from line: {line}")
                    except Exception as e:
                        logger.error(f"An error occurred while processing an event: {e}")

        except FileNotFoundError:
             logger.error(f"Log file '{self.filename}' not found during modification check.")
             self.last_position = 0 # Reset position for when it's recreated.
        except Exception as e:
            logger.error(f"A critical error occurred in the event handler: {e}")


def monitor_log_file(json_file_path: str):
    """
    Monitors a JSON log file for new entries using file system events.
    """
    logger.info(f"Starting to monitor log file: {json_file_path}")

    # Ensure the file and its directory exist before starting the observer.
    log_dir = os.path.dirname(os.path.abspath(json_file_path))
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        logger.info(f"Created directory: {log_dir}")

    if not os.path.exists(json_file_path):
        with open(json_file_path, 'w', encoding='utf-8'):
            logger.info(f"Log file not found. Created an empty file at: {json_file_path}")

    event_handler = LogFileEventHandler(json_file_path)
    observer = Observer()
    # We watch the directory containing the file, not the file itself.
    observer.schedule(event_handler, log_dir, recursive=False)

    logger.info(f"Observer started. Watching directory: '{log_dir}'")
    observer.start()

    try:
        while True:
            # Keep the main thread alive to allow the observer to run.
            time.sleep(0)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Observer stopped by user.")
    observer.join()

def remove_log_file(json_file_path: str):
    """
    Removes the specified log file if it exists.

    Args:
        json_file_path (str): The path to the av_events.json file to be removed.
    """
    logger.info("Owlyshield has stopped. Cleaning up event file.")
    try:
        if os.path.exists(json_file_path):
            os.remove(json_file_path)
            logger.info(f"Successfully removed log file: {json_file_path}")
        else:
            logger.error(f"Log file not found, nothing to remove: {json_file_path}")
    except OSError as e:
        logger.error(f"Error removing file {json_file_path}: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during file removal: {e}")

def analyze_specific_process(process_name_or_path: str, memory_dir: str, pd64_extracted_dir: str) -> Optional[str]:
    """
    Analyze a specific process using pd64 to dump suspicious modules.

    :param process_name_or_path: Process name (e.g., 'guloader.exe') or full path
    :param memory_dir: Directory where string output is saved.
    :param pd64_extracted_dir: Directory where pd64 will extract embedded files.
    :return: Path to the extracted ASCII strings text file, or None if an error occurred.
    """
    try:
        # Extract process name from path if needed
        process_name = os.path.basename(process_name_or_path) if os.path.sep in process_name_or_path else process_name_or_path

        # Find all processes matching the name
        matching_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    matching_processes.append((proc.info['pid'], proc.info['exe']))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not matching_processes:
            logger.error(f"No running processes found matching: {process_name}")
            return None

        if len(matching_processes) > 1:
            logger.info(f"Multiple processes found matching {process_name}: {matching_processes}")

        # Use the first matching process
        target_pid, target_exe = matching_processes[0]
        logger.info(f"Found target process: {target_exe} (PID: {target_pid})")

        # Ensure output directories exist
        os.makedirs(memory_dir, exist_ok=True)
        os.makedirs(pd64_extracted_dir, exist_ok=True)

        extracted_strings = []

        # Run pd64 on the process PID to dump suspicious modules
        logger.info(f"Running pd64 on process PID: {target_pid}")
        pid_pd64_dir = os.path.join(pd64_extracted_dir, f"pid_{target_pid}")
        os.makedirs(pid_pd64_dir, exist_ok=True)

        try:
            if extract_with_pd64(str(target_pid), pid_pd64_dir):
                logger.info(f"pd64 successfully extracted from PID {target_pid}")

                # Scan all extracted files
                for root, _, files in os.walk(pid_pd64_dir):
                    for fname in files:
                        full_path = os.path.join(root, fname)

                        try:
                            # Check file size before processing
                            file_size = os.path.getsize(full_path)
                            if file_size > 50 * 1024 * 1024:  # Skip files larger than 50MB
                                logger.info(f"Skipping large file: {full_path} ({file_size} bytes)")
                                continue

                            logger.info(f"Scanning pd64 extracted file: {full_path}")

                            # Extract strings from pd64 results
                            try:
                                with open(full_path, 'rb') as f:
                                    # Read in chunks to prevent memory issues
                                    chunk_size = 1024 * 1024  # 1MB chunks
                                    file_strings = []

                                    while True:
                                        chunk = f.read(chunk_size)
                                        if not chunk:
                                            break
                                        chunk_strings = extract_ascii_strings(chunk)
                                        if chunk_strings:
                                            file_strings.extend(chunk_strings[:100])  # Limit strings per chunk

                                        # Limit total strings to prevent memory overflow
                                        if len(file_strings) > 1000:
                                            break

                                    if file_strings:
                                        extracted_strings.append(f"pd64 extracted file {fname} Strings:")
                                        extracted_strings.extend(file_strings[:500])  # Limit total strings per file

                            except Exception as file_ex:
                                logger.error(f"Could not read pd64 extracted file {full_path}: {file_ex}")

                            # Scan the extracted file for threats
                            scan_and_warn(full_path)

                        except Exception as file_process_ex:
                            logger.error(f"Error processing file {full_path}: {file_process_ex}")
                            continue

            else:
                logger.error(f"pd64 extraction failed for PID {target_pid}")
                return None

        except Exception as pd64_ex:
            logger.error(f"Error during pd64 extraction for PID {target_pid}: {pd64_ex}")
            return None

        # Save extracted ASCII strings to file if we got any
        output_txt = None
        if extracted_strings:
            base_filename = f"extracted_strings_pid_{target_pid}"
            output_txt = os.path.join(memory_dir, f"{base_filename}.txt")
            counter = 1
            while os.path.exists(output_txt):
                output_txt = os.path.join(memory_dir, f"{base_filename}_{counter}.txt")
                counter += 1
            save_extracted_strings(output_txt, extracted_strings)
            logger.info(f"Strings analysis complete. Results saved in {output_txt}")
        else:
            logger.error(f"No strings extracted from process {target_pid}")

        return output_txt

    except Exception as overall_ex:
        logger.error(f"Overall error in analyze_specific_process: {overall_ex}")
        return None

@dataclass
class ProcessInfo:
    """Safe container for process information"""
    pid: int
    name: str
    exe_path: str
    rss: int
    is_in_sandbox: bool
    is_main_file: bool


class SafeProcessMonitor:
    """Thread-safe process monitor with proper resource management"""

    def __init__(self, sandboxie_folder: str, main_file_path: str):
        self.sandboxie_folder = sandboxie_folder.lower()
        self.main_file_path = main_file_path.lower()
        self.current_pid = os.getpid()

        # Thread-safe tracking structures
        self._lock = threading.RLock()
        self._last_rss: Dict[int, int] = {}
        self._analysis_cooldown: Dict[int, float] = {}
        self._stop_requested = threading.Event()

        # Thread pool for analysis tasks
        self._executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="MemAnalysis")
        self._active_futures: Set = set()

    def _cleanup_stale_data(self, existing_pids: Set[int]) -> None:
        """Remove tracking data for processes that no longer exist"""
        with self._lock:
            stale_pids = set(self._last_rss.keys()) - existing_pids
            for pid in stale_pids:
                self._last_rss.pop(pid, None)
                self._analysis_cooldown.pop(pid, None)

    def _get_safe_process_info(self, proc) -> Optional[ProcessInfo]:
        """Safely extract process information with comprehensive error handling"""
        try:
            # Get basic info that was pre-fetched
            pid = proc.info.get('pid')
            name = proc.info.get('name', 'Unknown')
            memory_info = proc.info.get('memory_info')

            if not all([pid, memory_info]):
                return None

            # Skip our own process immediately
            if pid == self.current_pid:
                return None

            # Verify process still exists before getting exe path
            if not psutil.pid_exists(pid):
                return None

            # Get RSS from pre-fetched info
            rss = memory_info.rss

            # Try to get executable path with multiple fallback strategies
            exe_path = None
            try:
                # Primary method
                exe_path = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return None
            except Exception:
                # Fallback: try cmdline for path hints
                try:
                    cmdline = proc.cmdline()
                    if cmdline:
                        exe_path = cmdline[0]
                    else:
                        return None
                except Exception:
                    return None

            if not exe_path:
                return None

            exe_lower = exe_path.lower()
            is_in_sandbox = exe_lower.startswith(self.sandboxie_folder)
            is_main_file = exe_lower == self.main_file_path

            # Only track processes in our scope
            if not (is_in_sandbox or is_main_file):
                return None

            return ProcessInfo(
                pid=pid,
                name=name,
                exe_path=exe_path,
                rss=rss,
                is_in_sandbox=is_in_sandbox,
                is_main_file=is_main_file
            )

        except Exception as e:
            # Log unexpected exceptions for debugging
            logger.debug(f"Unexpected error getting process info: {e}")
            return None

    def _should_analyze_process(self, proc_info: ProcessInfo, change_threshold: int) -> tuple[bool, str]:
        """Determine if process should be analyzed based on memory change and cooldown"""
        with self._lock:
            prev_rss = self._last_rss.get(proc_info.pid)
            current_time = time.time()

            # Check memory change threshold
            if prev_rss is not None:
                memory_change = abs(proc_info.rss - prev_rss)
                if memory_change <= change_threshold:
                    return False, "Below threshold"
            else:
                memory_change = proc_info.rss

            # Check analysis cooldown (30 seconds minimum)
            last_analysis = self._analysis_cooldown.get(proc_info.pid, 0)
            if current_time - last_analysis < 30:
                return False, "In cooldown"

            # Update tracking data
            self._last_rss[proc_info.pid] = proc_info.rss
            self._analysis_cooldown[proc_info.pid] = current_time

            # Determine change type for logging
            if prev_rss is None:
                change_type = "initial"
            elif proc_info.rss > prev_rss:
                change_type = "increase"
            else:
                change_type = "decrease"

            change_amount = proc_info.rss - prev_rss if prev_rss else proc_info.rss

            logger.info(f"Memory {change_type} detected: {proc_info.exe_path} (PID: {proc_info.pid})")
            logger.info(f"  Previous RSS: {prev_rss or 'N/A'} bytes")
            logger.info(f"  Current RSS: {proc_info.rss} bytes")
            logger.info(f"  Change: {change_amount:+} bytes")
            logger.info(f"  In sandbox: {proc_info.is_in_sandbox}, Is main file: {proc_info.is_main_file}")

            return True, "Ready for analysis"

    def _submit_analysis_task(self, proc_info: ProcessInfo, memory_dir: str, pd64_extracted_dir: str) -> None:
        """Submit memory analysis task to thread pool"""
        if self._stop_requested.is_set():
            return

        def analysis_task():
            try:
                if self._stop_requested.is_set():
                    logger.debug(f"Analysis cancelled for PID {proc_info.pid} (stop requested)")
                    return None

                # Verify process still exists before analysis
                if not psutil.pid_exists(proc_info.pid):
                    logger.info(f"Process {proc_info.pid} no longer exists, skipping analysis")
                    return None

                logger.info(f"Starting memory analysis for: {proc_info.exe_path} (PID: {proc_info.pid})")

                # Call the external analysis function
                result_file = analyze_specific_process(
                    proc_info.name, memory_dir, pd64_extracted_dir
                )

                if self._stop_requested.is_set():
                    logger.debug(f"Analysis completed but stop requested for PID {proc_info.pid}")
                    return result_file

                if result_file:
                    logger.info(f"Memory analysis completed for PID {proc_info.pid}, result: {result_file}")

                    # Launch scan in separate thread if not stopping
                    if not self._stop_requested.is_set():
                        scan_thread = threading.Thread(
                            target=self._safe_scan_and_warn,
                            args=(result_file,),
                            name=f"Scan-{proc_info.pid}",
                        )
                        scan_thread.start()
                else:
                    logger.error(f"Memory analysis for PID {proc_info.pid} returned no results")

                return result_file

            except Exception as e:
                logger.error(f"Memory analysis failed for PID {proc_info.pid}: {e}")
                return None

        # Submit task to thread pool
        try:
            future = self._executor.submit(analysis_task)
            self._active_futures.add(future)

            # Clean up completed futures
            completed_futures = {f for f in self._active_futures if f.done()}
            self._active_futures -= completed_futures

        except Exception as e:
            logger.error(f"Failed to submit analysis task for PID {proc_info.pid}: {e}")

    def _safe_scan_and_warn(self, result_file: str) -> None:
        """Safely execute scan_and_warn with error handling"""
        try:
            if not self._stop_requested.is_set():
                scan_and_warn(result_file)
        except Exception as e:
            logger.error(f"Scan and warn failed for {result_file}: {e}")

    def request_monitor_stop(self) -> None:
        """Request graceful shutdown of the monitor"""
        logger.info("Memory monitor stop requested")
        self._stop_requested.set()

    def cleanup(self) -> None:
        """Clean up resources"""
        logger.info("Memory monitor shutting down...")

        # Cancel pending futures
        for future in self._active_futures:
            future.cancel()

        # Shutdown thread pool with timeout
        self._executor.shutdown(wait=True, timeout=10)

        logger.info("Memory monitor shutdown complete")

    def monitor_processes(self, change_threshold_bytes: int, memory_dir: str,
                         pd64_extracted_dir: str, sleep_interval: float = 0.1) -> None:
        """Main monitoring loop"""
        logger.info(f"Starting memory monitor for sandbox: {self.sandboxie_folder}")
        logger.info(f"Monitoring main file: {self.main_file_path}")
        logger.info(f"Memory change threshold: {change_threshold_bytes} bytes")
        logger.info(f"Our PID (excluded from analysis): {self.current_pid}")

        iteration_count = 0

        try:
            while not self._stop_requested.is_set():
                iteration_count += 1
                current_pids = set()

                try:
                    # Get process list with required info pre-fetched
                    processes = list(psutil.process_iter(['pid', 'memory_info', 'name']))

                    for proc in processes:
                        if self._stop_requested.is_set():
                            break

                        proc_info = self._get_safe_process_info(proc)
                        if not proc_info:
                            continue

                        current_pids.add(proc_info.pid)

                        should_analyze, reason = self._should_analyze_process(
                            proc_info, change_threshold_bytes
                        )

                        if should_analyze:
                            logger.info(f"Analyzing process {proc_info.pid}: {reason}")
                            self._submit_analysis_task(proc_info, memory_dir, pd64_extracted_dir)

                    # Cleanup stale tracking data every 100 iterations
                    if iteration_count % 100 == 0:
                        self._cleanup_stale_data(current_pids)

                except Exception as e:
                    logger.error(f"Error in monitoring iteration {iteration_count}: {e}")
                    # Add longer delay on error to prevent rapid error loops
                    time.sleep(min(sleep_interval * 10, 5.0))
                    continue

                # Sleep between iterations
                if not self._stop_requested.wait(timeout=sleep_interval):
                    continue  # Timeout expired, continue monitoring
                else:
                    break  # Stop was requested

        except KeyboardInterrupt:
            logger.info("Memory monitor interrupted by user")
        except Exception as e:
            logger.error(f"Fatal error in memory monitor: {e}")
            raise
        finally:
            self.cleanup()


def monitor_memory_changes(
    change_threshold_bytes: int = 1024,
    stop_callback: Optional[Callable[[], bool]] = None,
) -> None:
    """
    Continuously monitor processes in sandbox and main file for RSS memory changes and trigger analysis.
    Uses pd64 extraction methods with robust error handling and resource management.

    :param change_threshold_bytes: Minimum delta in RSS to trigger analysis.
    :param stop_callback: Function that returns True when monitoring should stop
    :param memory_dir: Directory for memory dumps
    :param pd64_extracted_dir: Directory for pd64 extracted data
    """

    monitor = SafeProcessMonitor(sandboxie_folder, main_file_path)

    # Set up stop callback integration
    def check_stop_callback():
        return monitor._stop_requested.is_set() or (stop_callback and stop_callback())

    try:
        # Start monitoring in a separate thread if stop_callback is provided
        if stop_callback:
            def monitor_with_callback():
                while not check_stop_callback():
                    try:
                        monitor.monitor_processes(
                            change_threshold_bytes,
                            memory_dir,
                            pd64_extracted_dir,
                            sleep_interval=0.1
                        )
                        break  # Normal exit
                    except Exception as e:
                        if not check_stop_callback():
                            logger.error(f"Monitor restarting due to error: {e}")
                            time.sleep(1)
                        break

            monitor_thread = threading.Thread(target=monitor_with_callback, name="MemoryMonitor")
            monitor_thread.start()

            # Wait for stop condition or thread completion
            while monitor_thread.is_alive() and not check_stop_callback():
                time.sleep(0.1)

            if monitor_thread.is_alive():
                monitor.request_monitor_stop()
                monitor_thread.join(timeout=30)
        else:
            # Run directly in current thread
            monitor.monitor_processes(change_threshold_bytes, memory_dir, pd64_extracted_dir)

    except KeyboardInterrupt:
        logger.info("Memory monitoring interrupted")
        monitor.request_monitor_stop()
    except Exception as e:
        logger.error(f"Memory monitoring failed: {e}")
        monitor.request_monitor_stop()
        raise
    finally:
        monitor.cleanup()

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
        logger.error(f"The directory does not exist: {path}")
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
                    logger.info(f"Detected change in: {full_path}")
                    threading.Thread(target=scan_and_warn, args=(full_path,)).start()
                else:
                    logger.error(f"File or folder not found: {full_path}")
    except Exception as e:
        logger.error(f"Error monitoring {path}: {e}")
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
        logger.info(f"Started monitoring thread for: {d}")

def start_monitoring_sandbox():
    threading.Thread(target=monitor_directories).start()

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
                            if file_path.endswith('.wll') and is_pe_file_from_output(die_output, file_path):
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

                            logger.critical(f"Suspicious or malicious startup file detected in {directory}: {file}")
                            notify_user_startup(file_path, message)
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()
                            alerted_files.append(file_path)
        except Exception as ex:
            logger.error(f"An error occurred while checking startup directories: {ex}")

def check_hosts_file_for_blocked_antivirus():
    """
    Scan hosts_sandboxie_path for any entries that match one of your lists:
      - IPv4 whitelist
      - IPv6 whitelist
      - Exact domain whitelist
      - Mail-domain whitelist
      - Subdomain whitelist
      - Mail-subdomain whitelist
      - Antivirus domain list

    For each category that triggers, we call notify_user_hosts() with its
    specific HEUR signature. Returns True if anything was flagged.
    """
    # Precompile antivirus regex
    ant_patterns = [r'(?:^|\.)' + re.escape(d) + r'$'
                    for d in antivirus_domains_data]
    antivirus_re = re.compile('|'.join(ant_patterns), re.IGNORECASE)

    # Buckets for each reason
    flagged = {
        'ipv4': set(),
        'ipv6': set(),
        'domain': set(),
        'mail_domain': set(),
        'sub_domain': set(),
        'mail_sub_domain': set(),
        'antivirus': set(),
    }

    try:
        if not os.path.exists(hosts_sandboxie_path):
            return False

        with open(hosts_sandboxie_path, 'r') as hf:
            for raw in hf:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue

                parts = re.split(r'\s+', line)
                ip = parts[0]
                hosts = parts[1:]

                # IP-based buckets
                if ip in ipv4_whitelist_data:
                    flagged['ipv4'].update(hosts)
                if ip in ipv6_whitelist_data:
                    flagged['ipv6'].update(hosts)

                for host in hosts:
                    # Exact domain
                    if host in whitelist_domains_data:
                        flagged['domain'].add(host)
                        continue
                    # Exact mail-domain
                    if host in whitelist_domains_mail_data:
                        flagged['mail_domain'].add(host)
                        continue
                    # Subdomain
                    if any(host.endswith('.' + d) for d in whitelist_sub_domains_data):
                        flagged['sub_domain'].add(host)
                        continue
                    # Mail subdomain
                    if any(host.endswith('.' + d) for d in whitelist_mail_sub_domains_data):
                        flagged['mail_sub_domain'].add(host)
                        continue
                    # Antivirus pattern
                    if antivirus_re.search(host):
                        flagged['antivirus'].add(host)

        any_flagged = False

        # Emit pre-bucket notifications
        if flagged['ipv4']:
            any_flagged = True
            notify_user_hosts(
                hosts_sandboxie_path,
                "HEUR:Win32.Trojan.Hosts.WhiteIP.v4.gen",
                details=list(flagged['ipv4'])
            )
        if flagged['ipv6']:
            any_flagged = True
            notify_user_hosts(
                hosts_sandboxie_path,
                "HEUR:Win32.Trojan.Hosts.WhiteIP.v6.gen",
                details=list(flagged['ipv6'])
            )
        if flagged['domain']:
            any_flagged = True
            notify_user_hosts(
                hosts_sandboxie_path,
                "HEUR:Win32.Trojan.Hosts.WhiteDomain.gen",
                details=list(flagged['domain'])
            )
        if flagged['mail_domain']:
            any_flagged = True
            notify_user_hosts(
                hosts_sandboxie_path,
                "HEUR:Win32.Trojan.Hosts.Hijacker.Mail.gen",
                details=list(flagged['mail_domain'])
            )
        if flagged['sub_domain']:
            any_flagged = True
            notify_user_hosts(
                hosts_sandboxie_path,
                "HEUR:Win32.Trojan.Hosts.WhiteSubdomain.gen",
                details=list(flagged['sub_domain'])
            )
        if flagged['mail_sub_domain']:
            any_flagged = True
            notify_user_hosts(
                hosts_sandboxie_path,
                "HEUR:Win32.Trojan.Hosts.Hijacker.MailSub.gen",
                details=list(flagged['mail_sub_domain'])
            )
        if flagged['antivirus']:
            any_flagged = True
            notify_user_hosts(
                hosts_sandboxie_path,
                "HEUR:Win32.Trojan.Hosts.Hijacker.DisableAV.gen",
                details=list(flagged['antivirus'])
            )

        return any_flagged

    except Exception as ex:
        logger.error(f"Error reading hosts file: {ex}")
        return False

# Function to continuously monitor hosts file
def monitor_hosts_file():
    # Continuously check the hosts file
    while True:
        is_malicious_host = check_hosts_file_for_blocked_antivirus()

        if is_malicious_host:
            logger.critical("Malicious hosts file detected and flagged.")
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
                    # --- NEW: perform DIE/PE + signature check and skip if signed/valid ---
                    try:
                        die_output = get_die_output_binary(uefi_path)  # assumes this helper exists
                        pe_file = is_pe_file_from_output(die_output, uefi_path)
                    except Exception:
                        pe_file = False
                        die_output = None

                    if pe_file:
                        try:
                            signature_check = check_signature(uefi_path)
                        except Exception:
                            signature_check = None

                        if isinstance(signature_check, dict):
                            # If file has a valid Microsoft/good signature or 'is_valid', skip notifications
                            if signature_check.get("has_microsoft_signature") \
                               or signature_check.get("valid_goodsign_signatures") \
                               or signature_check.get("is_valid"):
                                # Considered benign; don't alert
                                continue
                    # --- END NEW CHECK ---

                    if uefi_path in uefi_100kb_paths and is_malicious_file(uefi_path, 100):
                        logger.critical(f"Malicious file detected: {uefi_path}")
                        notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.SecureBootRecovery.gen.Malware")
                        threading.Thread(target=scan_and_warn, args=(uefi_path,)).start()
                        alerted_uefi_files.append(uefi_path)
                    elif uefi_path in uefi_paths and is_malicious_file(uefi_path, 1024):
                        logger.critical(f"Malicious file detected: {uefi_path}")
                        notify_user_uefi(uefi_path, "HEUR:Win32.UEFI.ScreenLocker.Ransomware.gen.Malware")
                        threading.Thread(target=scan_and_warn, args=(uefi_path,)).start()
                        alerted_uefi_files.append(uefi_path)

        # Check for any new files in the EFI directory
        efi_dir = rf'{sandboxie_folder}\drive\X\EFI'
        for root, dirs, files in os.walk(efi_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # only consider .efi files
                if not file_path.endswith(".efi"):
                    continue

                if file_path not in known_uefi_files and file_path not in alerted_uefi_files:
                    # --- NEW: perform DIE/PE + signature check and skip if signed/valid ---
                    try:
                        die_output = get_die_output_binary(file_path)
                        pe_file = is_pe_file_from_output(die_output, file_path)
                    except Exception:
                        pe_file = False
                        die_output = None

                    if pe_file:
                        try:
                            signature_check = check_signature(file_path)
                        except Exception:
                            signature_check = None

                        if isinstance(signature_check, dict):
                            if signature_check.get("has_microsoft_signature") \
                               or signature_check.get("valid_goodsign_signatures") \
                               or signature_check.get("is_valid"):
                                # Signed/valid PE - do not alert, just record as known
                                known_uefi_files.append(file_path)
                                continue
                    # --- END NEW CHECK ---

                    logger.critical(f"Unknown malicious UEFI file detected: {file_path}")
                    notify_user_uefi(file_path, "HEUR:Win32.Bootkit.Startup.UEFI.gen.Malware")
                    threading.Thread(target=scan_and_warn, args=(file_path,)).start()
                    alerted_uefi_files.append(file_path)
                    known_uefi_files.append(file_path)

class ScanAndWarnHandler(FileSystemEventHandler):

    def process_file(self, file_path):
        try:
            threading.Thread(target=scan_and_warn, args=(file_path,)).start()
            logger.info(f"Processed file: {file_path}")
        except Exception as ex:
            logger.error(f"Error processing file (scan_and_warn) {file_path}: {ex}")

    def process_directory(self, dir_path):
        try:
            for root, _, files in os.walk(dir_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    self.process_file(file_path)
            logger.info(f"Processed all files in directory: {dir_path}")
        except Exception as ex:
            logger.error(f"Error processing directory {dir_path}: {ex}")

    def on_any_event(self, event):
        if event.is_directory:
            self.process_directory(event.src_path)
            logger.info(f"Directory event detected: {event.src_path}")
        else:
            logger.info(f"Event detected: {event.event_type} for file: {event.src_path}")

    def on_created(self, event):
        if event.is_directory:
            self.process_directory(event.src_path)
            logger.info(f"Directory created: {event.src_path}")
        else:
            self.process_file(event.src_path)
            logger.info(f"File created: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)
            logger.info(f"File modified: {event.src_path}")

    def on_moved(self, event):
        if event.is_directory:
            self.process_directory(event.dest_path)
            logger.info(f"Directory moved: {event.src_path} to {event.dest_path}")
        else:
            self.process_file(event.dest_path)
            logger.info(f"File moved: {event.src_path} to {event.dest_path}")


def monitor_directories_with_watchdog():
    """
    Use watchdog Observer to monitor multiple directories with the ScanAndWarnHandler.
    """
    event_handler = ScanAndWarnHandler()
    observer = Observer()
    for path in directories_to_scan:
        observer.schedule(event_handler, path=path, recursive=False)
        logger.info(f"Scheduled watchdog observer for: {path}")
    observer.start()

def run_sandboxie_control():
    try:
        logger.info("Running Sandboxie control.")
        # Include the '/open' argument to open the Sandboxie control window
        result = subprocess.run([sandboxie_control_path, "/open"], shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
        logger.info(f"Sandboxie control output: {result.stdout}")
    except subprocess.CalledProcessError as ex:
        logger.error(f"Error running Sandboxie control: {ex.stderr}")
    except Exception as ex:
        logger.error(f"Unexpected error running Sandboxie control: {ex}")

# ----------------------------------------------------
# Constants for Windows API calls
# ----------------------------------------------------
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_CLOSE = 0x0010

# WinEvent constants to capture live window events
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_SHOW = 0x8002
EVENT_SYSTEM_DIALOGSTART = 0x0010
EVENT_OBJECT_HIDE = 0x8003
EVENT_OBJECT_NAMECHANGE = 0x800C
WINEVENT_OUTOFCONTEXT = 0x0000

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Load libraries
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
ole32 = ctypes.windll.ole32

ENUM_WINDOWS_PROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

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
    length = user32.GetWindowTextLengthW(hwnd)
    if length == 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    if user32.GetWindowTextW(hwnd, buf, length + 1) == 0:
        return ""
    return buf.value

def get_control_text(hwnd):
    """Enhanced control text extraction using multiple methods."""
    # Method 1: WM_GETTEXT message (original approach)
    try:
        length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) + 1
        if length > 1:
            buf = ctypes.create_unicode_buffer(length)
            actual_length = user32.SendMessageW(hwnd, WM_GETTEXT, length, buf)
            if actual_length > 0:
                text = buf.value
                if text and text.strip():
                    return text.strip()
    except Exception as e:
        logger.debug(f"WM_GETTEXT failed for {hwnd}: {e}")

    # Method 2: Fallback to original simple method
    try:
        length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) + 1
        buf = ctypes.create_unicode_buffer(length)
        user32.SendMessageW(hwnd, WM_GETTEXT, length, buf)
        return buf.value or ""
    except Exception:
        return ""

def find_child_windows(parent_hwnd):
   """Find all child windows of the given parent window."""
   child_windows = []
   count = 0
   max_children = 200  # Safety limit

   def _enum_proc(hwnd, lParam):
       nonlocal count
       count += 1
       if count > max_children:
           return False  # Stop enumeration
       child_windows.append(hwnd)
       return True

   try:
       EnumChildProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_void_p)
       user32.EnumChildWindows(parent_hwnd, EnumChildProc(_enum_proc), None)
   except Exception as e:
       logger.debug(f"EnumChildWindows failed for {parent_hwnd}: {e}")

   return child_windows

def is_window_valid(hwnd):
    return bool(user32.IsWindow(hwnd))

# --- UIA loader (ensures type library is generated before import) ---
def _load_uia_types():
    """Safely load UIAutomation types when needed."""
    try:
        # Try to import existing generated module first
        import comtypes.gen.UIAutomationClient
        return comtypes.gen.UIAutomationClient
    except (ImportError, SyntaxError):
        # Clear corrupted cache and regenerate
        try:
            # Clear the comtypes cache
            gen_dir = comtypes.client._code_cache._find_gen_dir()
            if gen_dir and os.path.exists(gen_dir):
                shutil.rmtree(gen_dir)
                os.makedirs(gen_dir)
                # Recreate __init__.py
                init_file = os.path.join(gen_dir, '__init__.py')
                with open(init_file, 'w') as f:
                    f.write('# comtypes generated packages\n')

            # Regenerate the type library
            from comtypes.client import GetModule
            GetModule("UIAutomationCore.dll")
            import comtypes.gen.UIAutomationClient
            return comtypes.gen.UIAutomationClient

        except Exception as e:
            logger.error("Failed to load UIAutomationClient types: %s", e)
            return None
    except Exception as e:
        logger.error("Failed to load UIAutomationClient types: %s", e)
        return None

@atexit.register
def cleanup_com():
    try:
        comtypes.client._shutdown()
    except Exception:
        pass

def _extract_uia_text(hwnd: int, uia, UIA):
    """Internal: Extract UIA text with robust error handling and no pythoncom."""
    try:
        try:
            elem = uia.ElementFromHandle(hwnd)
            if not elem:
                return []
        except Exception as e:
            logger.debug("Failed to get element from handle %s: %s", hwnd, e)
            return []

        all_texts = []

        # Helper to cast patterns safely
        def _get_pattern(element, pattern_id, iface):
            try:
                unk = element.GetCurrentPattern(pattern_id)
                if not unk:
                    return None
                return cast(unk, POINTER(iface))
            except Exception:
                return None

        # 1) CurrentName
        try:
            name = elem.CurrentName
            if name and name.strip():
                all_texts.append(name.strip())
        except Exception as e:
            logger.debug("Failed to get CurrentName: %s", e)

        # 2) ValuePattern
        try:
            vp = _get_pattern(elem, UIA.UIA_ValuePatternId, UIA.IUIAutomationValuePattern)
            if vp:
                value = vp.CurrentValue
                if value is not None:
                    s = str(value).strip()
                    if s:
                        all_texts.append(s)
        except Exception as e:
            logger.debug("Failed to get ValuePattern: %s", e)

        # 3) TextPattern
        try:
            tp = _get_pattern(elem, UIA.UIA_TextPatternId, UIA.IUIAutomationTextPattern)
            if tp:
                doc_range = tp.DocumentRange
                if doc_range:
                    text = doc_range.GetText(-1)
                    if text:
                        s = text.strip()
                        if s:
                            all_texts.append(s)
        except Exception as e:
            logger.debug("Failed to get TextPattern: %s", e)

        # 4) LegacyIAccessiblePattern
        try:
            lap = _get_pattern(elem, UIA.UIA_LegacyIAccessiblePatternId, UIA.IUIAutomationLegacyIAccessiblePattern)
            if lap:
                try:
                    n = lap.CurrentName
                    if n:
                        s = n.strip()
                        if s:
                            all_texts.append(s)
                except Exception:
                    pass
                try:
                    v = lap.CurrentValue
                    if v is not None:
                        s = str(v).strip()
                        if s:
                            all_texts.append(s)
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Failed to get LegacyIAccessiblePattern: %s", e)

        # 5) RangeValuePattern
        try:
            rvp = _get_pattern(elem, UIA.UIA_RangeValuePatternId, UIA.IUIAutomationRangeValuePattern)
            if rvp:
                try:
                    v = rvp.CurrentValue
                    if v is not None:
                        s = str(v).strip()
                        if s and s.lower() != "none":
                            all_texts.append(s)
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Failed to get RangeValuePattern: %s", e)

        # 6) SelectionPattern
        try:
            sp = _get_pattern(elem, UIA.UIA_SelectionPatternId, UIA.IUIAutomationSelectionPattern)
            if sp:
                try:
                    selection = sp.GetCurrentSelection()
                    if selection and getattr(selection, "Length", 0) > 0:
                        for i in range(selection.Length):
                            try:
                                item = selection.GetElement(i)
                                if item:
                                    nm = item.CurrentName
                                    if nm:
                                        s = nm.strip()
                                        if s:
                                            all_texts.append(s)
                            except Exception as e:
                                logger.debug("Failed to get selection item %s: %s", i, e)
                except Exception as e:
                    logger.debug("SelectionPattern GetCurrentSelection failed: %s", e)
        except Exception as e:
            logger.debug("Failed to get SelectionPattern: %s", e)

        # 7) Child elements (limit to 50)
        try:
            condition = uia.CreateTrueCondition()
            children = elem.FindAll(UIA.TreeScope_Children, condition)
            if children and hasattr(children, "Length"):
                max_children = min(50, children.Length)
                for i in range(max_children):
                    try:
                        child = children.GetElement(i)
                        if child:
                            cn = child.CurrentName
                            if cn:
                                s = cn.strip()
                                if s:
                                    all_texts.append(s)
                    except Exception as e:
                        logger.debug("Failed to get child element %s: %s", i, e)
        except Exception as e:
            logger.debug("Failed to enumerate child elements: %s", e)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for t in all_texts:
            try:
                if t and t not in seen:
                    seen.add(t)
                    unique.append(t)
            except Exception:
                continue

        return unique
    except Exception as e:
        logger.error("_extract_uia_text failed: %s", e, exc_info=True)
        return []

def get_uia_text(hwnd: int):
   """Public API: returns list of unique, non-empty text strings for a window handle."""
   try:
       if not is_window_valid(hwnd):
           return []

       UIA = _load_uia_types()
       if UIA is None:
           return []

       try:
           # Use ProgID first, fallback to CLSID if needed
           try:
               uia = CreateObject("UIAutomation.CUIAutomation", interface=UIA.IUIAutomation)
           except Exception:
               # CLSID form (safe fallback)
               CLSID_CUIAutomation = GUID("{FF48DBA4-60EF-4201-AA87-54103EEF594E}")
               uia = CreateObject(CLSID_CUIAutomation, interface=UIA.IUIAutomation)

       except Exception as e:
           logger.error("Failed to create UI Automation object: %s", e, exc_info=True)
           return []

       return _extract_uia_text(hwnd, uia, UIA)

   except Exception as e:
       logger.error("get_uia_text failed: %s", e, exc_info=True)
       return []

# ----------------------------------------------------
# Advanced enumeration-based capture
# ----------------------------------------------------
class MonitorMessageCommandLine:
    def __init__(self):
        self.processed_texts = set()
        self._seen_texts = set()
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=1000)
        self._hooks = []

        # Patterns for window text content (dialog boxes, messages, etc.)
        self.known_malware_messages_text = {
            "classic": {
                "message": "this program cannot be run under virtual environment or debugging software",
                "virus_name": "HEUR:Win32.Trojan.Guloader.C4D9Dd33.gen"
            },
            "av": {
                "message": "disable your antivirus",
                "virus_name": "HEUR:Win32.DisableAV.gen"
            },
            "debugger": {
                "message": "a debugger has been found running in your system please unload it from memory and restart your program",
                "virus_name": "HEUR:Win32.Themida.gen"
            },
            "fanmade": {
                "patterns": [
                    "executed a trojan", "this is the last warning", "creator of this malware", "creator of this trojan",
                    "this trojan has", "by this trojan", "this is a malware", "considered malware", "destroy your computer",
                    "destroy this computer", "execute this malware", "run a malware", "this malware contains", "and makes it unusable",
                    "contains flashing lights", "run malware", "executed is a malware", "resulting in an unusable machine", "this malware will harm your computer",
                    "this trojan and", "using this malware", "this malware can", "gdi malware", "win32 trojan specifically", "malware will run", "this malware is no joke",
                ],
                "virus_name": "HEUR:Win32.GDI.Fanmade.gen"
            },
            "rogue": {
                "patterns": [
                    "your pc is infected", "your computer is infected", "your system is infected", "windows is infected",
                    "has found viruses on computer", "windows security alert", "pc is at risk", "malicious program has been detected",
                    "warning virus detected"
                ],
                "virus_name": "HEUR:Win32.Rogue.gen"
            },
        }

        # Patterns for command-line arguments and process execution
        self.known_malware_messages_cmd = {
            "powershell_iex_download": {
                "patterns": [
                    r'powershell.exe.*iex.*New-Object.*Net.WebClient.*DownloadString',
                    r'powershell.*\[string\]\[char\[\]\]@\(0x.*Set-Alias.*Net.WebClient.*DownloadString',
                    r'powershell.*iex \(new-object system.net.webclient\).downloadstring',
                    r'iex \(\s*\[string\]\[system.text.encoding\]::ascii.getstring\(\[system.convert\]::frombase64string\(\s*\(\(new-object net.webclient\).downloadstring',
                    r'powershell.*\.DownloadFile\(\[System.Text.Encoding\]::ASCII.GetString\(\[System.Convert\]::FromBase64String',
                    r'iex \(new-object net.webclient\).downloadstring',
                    r'powershell -command iex \(.*downloadstring',
                    r'iex \(new-object net.webclient\).downloadfile',
                    r'powershell.*-command.*iex\(.*http',
                    r'-command iex \(new-object.*downloadstring',
                    r'\$path.*iex\(.*\.web.*-replace',
                    r'iex \(\(new-object system.net.webclient\).downloadstring',
                    r'powershell.*\.webclient\).*iex',
                    r'iex\(new-object net.webclient\).downloadstring',
                    r'iex \(\(new-object net.webclient\).downloadstring',
                    r'http.*\.replace\(.*iex'
                ],
                "virus_name": "HEUR:Win32.PowerShell.IEX.Downloader.gen"
            },
            "xmrig": {
                "patterns": [r"xmrig(?:\.exe)?", "start xmrig", "xmrig --help", "xmrig --version", "xmrig --config"],
                "virus_name": "HEUR:Win32.Miner.XMRig.gen"
            },
            "wifi": {
                "patterns": [r"netsh(?:\.exe)? wlan show profile"],
                "virus_name": "HEUR:Win32.Trojan.Password.Stealer.Wi-Fi.gen"
            },
            "shadowcopy": {
                "patterns": [
                    r"get-wmiobject win32_shadowcopy \| foreach-object \{\$\._\.delete\(\);\}",
                    r"Get-WmiObject Win32_Shadowcopy \| ForEach-Object \{\$\._\.Delete\(\);\}"
                ],
                "virus_name": "HEUR:Win32.Ransom.ShadowCopy.gen"
            },
            "wmic": {
                "patterns": [r"wmic(?:\.exe)? shadowcopy delete"],
                "virus_name": "HEUR:Win32.Ransom.ShadowCopy.WMIC.gen"
            },
            "vssadmin": {
                "patterns": [r"vssadmin(?:\.exe)? delete shadows"],
                "virus_name": "HEUR:Win32.Ransom.ShadowCopy.VSSAdmin.gen"
            },
            "windefend": {
                "patterns": [r"sc(?:\.exe)?\s+(?:stop|delete)\s+windefend"],
                "virus_name": "HEUR:Win32.KillAV.WinDefend.gen"
            },
            "killfirewall": {
                "patterns": [r"netsh(?:\.exe)?\s+advfirewall\s+set\s+allprofiles\s+state\s+off"],
                "virus_name": "HEUR:Win32.KillFirewall.gen"
            },
            "stopeventlog": {
                "patterns": [r"sc(?:\.exe)?\s+(?:stop|delete)\s+eventlog"],
                "virus_name": "HEUR:Win32.StopEventlogger.gen"
            },
            "delete_av_services": {
                "patterns": [
                    rf"sc(?:\.exe)?\s+(?:stop|delete)\s+{svc}"
                    for svc in [
                        "AvastSvc", "AvastWscReporter", "aswVmm", "MBAMService", "WinDefend",
                        "VSSERV", "McAfee Service Controller", "McAfee Firewall Core Service",
                        "McAfee Validation Trust Protection", "WRSkyClient", "WRCoreService",
                        "WRSVC", "aswbIDSAgent", "aswElam"
                    ]
                ],
                "virus_name": "HEUR:Win32.KillAV.ServiceControl.gen"
            },
            "startup": {
                "patterns": [
                    r'copy-item.*\\roaming\\microsoft\\windows\\start menu\\programs\\startup',
                ],
                "virus_name": "HEUR:Win32.Startup.PowerShell.Injection.gen"
            },
            "schtasks": {
                "patterns": [
                    r'schtasks(?:\.exe)?.*\/create.*\/xml.*\\temp\\.*\.tmp',
                ],
                "virus_name": "HEUR:Win32.TaskScheduler.TempFile.gen"
            },
            "koadic": {
                "patterns": [
                    r'chcp 437 & schtasks(?:\.exe)?\s+/(?:query|create)\s+/tn\s+k0adic'
                ],
                "virus_name": "HEUR:Win32.Rootkit.Koadic.gen"
            },
            "fodhelper": {
                "patterns": [
                    r'reg(?:\.exe)?\s+add\s+hkcu\\software\\classes\\ms-settings\\shell\\open\\command',
                ],
                "virus_name": "HEUR:Fodhelper.UAC.Bypass.Command"
            },
            "antivirus_process_search": {
                "patterns": [
                    rf"findstr(?:\.exe)?.*\b({ '|'.join(fr'{re.escape(p)}(?:\.exe)?' for p in antivirus_process_list) })\b"
                ],
                "virus_name": "HEUR:Antivirus.Process.Search.Command"
            },
            "delete_critical_registry_keys": {
                "patterns": [
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    r'reg(?:\.exe)?\s+delete\s+HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SYSTEM\\ControlSet001\\Services\\aswbIDSAgent',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SYSTEM\\ControlSet001\\Services\\aswElam',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SOFTWARE\\WOW6432Node\\Webroot',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SYSTEM\\CurrentControlSet\\Services\\AVP21.3',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SYSTEM\\CurrentControlSet\\Services\\MBAMService',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSSERV',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SYSTEM\\CurrentControlSet\\Services\\eamonm',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SOFTWARE\\AVIRA',
                    r'reg(?:\.exe)?\s+delete\s+HKLM\\SOFTWARE\\CheckPoint',
                ],
                "virus_name": "HEUR:Win32.Destructive.AV.RegDelete.gen"
            },
        }

        # Create a combined set of all command-line patterns for efficient lookup
        self.all_cmd_patterns = set()
        for details in self.known_malware_messages_cmd.values():
            self.all_cmd_patterns.update(details.get("patterns", []))


    def get_unique_filename(self, base_name):
        """Generate a unique filename by appending a number if necessary."""
        counter = 1
        unique_name = os.path.join(commandlineandmessage_dir, f"{base_name}.txt")
        while os.path.exists(unique_name):
            unique_name = os.path.join(commandlineandmessage_dir, f"{base_name}_{counter}.txt")
            counter += 1
        return unique_name

    def preprocess_text(self, text):
        return re.sub(r"[,.!?']", "", text.lower()).strip()

    def find_and_process_windows(self):
        """
        Enumerate all top-level windows and process their text.
        Uses a ThreadPoolExecutor to prevent unbounded thread creation.
        """

        # Make sure executor is available
        if not hasattr(self, "executor"):
            self.executor = ThreadPoolExecutor(max_workers=1000)

        def safe_run(fn, *args, **kwargs):
            """Wrapper to catch & log exceptions inside executor threads."""
            try:
                fn(*args, **kwargs)
            except Exception as e:
                logger.exception(f"Thread {fn.__name__} failed: {e}")

        def process_text(hwnd, label, text, process_path, win_type):
            try:
                # Build sanitized base filename
                filename = process_path.split("\\")[-1] if process_path else "unknown"
                base = sanitize_filename(filename) + f"_{label}"

                # Preprocess + normalize
                pre = self.preprocess_text(text)
                def normalize(s): return ' '.join(s.strip().lower().split())
                orig_norm = normalize(text)
                pre_norm  = normalize(pre) if pre else ""

                # Dedup
                key = orig_norm
                with self.lock:
                    if key in self._seen_texts:
                        return
                    self._seen_texts.add(key)

                # File writing
                with self.lock:
                    if pre and pre_norm != orig_norm:
                        fn = self.get_unique_filename(f"preprocessed_{base}")
                        with open(fn, "w", encoding="utf-8", errors="ignore") as f:
                            f.write(pre[:1_000_000])
                        self.executor.submit(safe_run, scan_and_warn, fn, command_flag=False)

                    elif orig_norm:
                        fn = self.get_unique_filename(f"original_{base}")
                        with open(fn, "w", encoding="utf-8", errors="ignore") as f:
                            f.write(text[:1_000_000])
                        self.executor.submit(safe_run, scan_and_warn, fn, command_flag=False)

            except Exception as e:
                logger.error(
                    f"Error processing text [{label}] for HWND {hwnd} from {process_path}: {e}"
                )

        def handle_hwnd(hwnd, win_type):
            # Skip invalid handles
            if not is_window_valid(hwnd):
                return

            try:
                path = get_process_path(hwnd)
            except Exception:
                path = ""

            def process_win_text():
                wt = get_window_text(hwnd) or ""
                if wt.strip():
                    process_text(hwnd, "win_text", wt, path, win_type)

            def process_ctrl_text():
                ct = get_control_text(hwnd) or ""
                if ct.strip():
                    process_text(hwnd, "ctrl_text", ct, path, win_type)

            def process_uia_texts():
                for t in get_uia_text(hwnd):
                    if t and t.strip():
                        process_text(hwnd, "uia_text", t, path, win_type)

            # Submit tasks to executor (not new raw threads)
            self.executor.submit(safe_run, process_win_text)
            self.executor.submit(safe_run, process_ctrl_text)
            self.executor.submit(safe_run, process_uia_texts)

        def start_enum():
            try:
                def enum_callback(hwnd, _):
                    self.executor.submit(safe_run, handle_hwnd, hwnd, "main_window")
                    return True
                win32gui.EnumWindows(enum_callback, None)
            except Exception as e:
                logger.error(f"Failed during window enumeration: {e}")

        # Launch enumeration in background
        self.executor.submit(safe_run, start_enum)

    def monitoring_window_text(self):
        logger.info("Started window/control monitoring loop")
        try:
            while True:
                try:
                    threading.Thread(
                        target=self.find_and_process_windows
                    ).start()
                except Exception as e:
                    logger.error(f"Window/control enumeration error: {e}")
        except Exception as e:
            logger.error(f"Error at monitoring_window_text: {e}")

    def capture_command_lines(self):
        command_lines = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline']:
                    cmdline_str = " ".join(proc.info['cmdline'])
                    try:
                        executable_path = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        executable_path = proc.info['name']
                    command_lines.append((cmdline_str, executable_path))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as ex:
                logger.error(f"Process error: {ex}")
            except Exception as ex:
                logger.error(f"Unexpected error while processing process {proc.info.get('pid')}: {ex}")
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

        # Ensure inputs are non-empty strings
        text1 = text1.strip() if text1 else ""
        text2 = text2.strip() if text2 else ""

        if not text1 or not text2:
            return 0.0  # nothing to compare

        # Now both are plain strings, safe to feed into spaCy
        doc1 = nlp_spacy_lang(text1)
        doc2 = nlp_spacy_lang(text2)

        # Guard against empty vector norms
        if doc1.vector_norm == 0 or doc2.vector_norm == 0:
            return 0.0

        return doc1.similarity(doc2)

    def process_detected_malware(self, text, file_path, virus_name, category):
        message = f"Detected malware ({category}): {virus_name} in text: {text} from {file_path}"
        logger.critical(message)
        notify_user_for_detected_command(message, file_path)

    def process_detected_text_ransom(self, text, file_path):
        message = f"Potential ransomware detected in text: {text} from {file_path}"
        logger.critical(message)
        notify_user_for_detected_command(message, file_path)

    def detect_malware(self, file_path: str, command_flag: bool = False):
        if not file_path or not isinstance(file_path, str):
            logger.error(f"Invalid file_path provided: {file_path}")
            return

        try:
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as monitor_file:
                file_content = monitor_file.read(1000000)

            if not file_content.strip():
                return

            if command_flag:
                # For command lines, check against ALL patterns (command and text)
                logger.info(f"Scanning {file_path} as command content against ALL patterns.")
                all_dicts = {**self.known_malware_messages_cmd, **self.known_malware_messages_text}
                for category, details in all_dicts.items():
                    for pattern in details.get("patterns", []):
                        if re.search(pattern, file_content, re.IGNORECASE):
                            self.process_detected_malware(file_content, file_path, details["virus_name"], category)
                            logger.critical(f"Detected command pattern for '{category}' in {file_path}.")
                    if "message" in details:
                         if self.calculate_similarity_text(file_content, details["message"]) > 0.92:
                            self.process_detected_malware(file_content, file_path, details["virus_name"], category)
                            logger.critical(f"Detected malware message for '{category}' in {file_path}.")
            else:
                # For UI/window text, check ONLY against text patterns, excluding command patterns
                logger.info(f"Scanning {file_path} as text content against TEXT patterns only.")
                for category, details in self.known_malware_messages_text.items():
                    # Check text patterns, but skip if it's a known command pattern
                    for pattern in details.get("patterns", []):
                        if pattern in self.all_cmd_patterns:
                            continue # Skip command-specific patterns
                        if self.calculate_similarity_text(file_content, pattern) > 0.92:
                            self.process_detected_malware(file_content, file_path, details["virus_name"], category)
                            logger.critical(f"Detected text pattern for '{category}' in {file_path}.")

                    # Check fixed messages, but skip if it's a known command pattern
                    if "message" in details:
                        if details["message"] in self.all_cmd_patterns:
                            continue # Skip command-specific patterns
                        if self.calculate_similarity_text(file_content, details["message"]) > 0.92:
                            self.process_detected_malware(file_content, file_path, details["virus_name"], category)
                            logger.critical(f"Detected malware message for '{category}' in {file_path}.")

                # Ransomware keyword distance check (only for text content)
                if self.contains_keywords_within_max_distance(file_content, max_distance=10):
                    self.process_detected_text_ransom(file_content, file_path)
                    logger.critical(f"Detected ransomware keywords in {file_path}.")

        except FileNotFoundError:
            logger.error(f"File not found: {file_path}.")
        except Exception as ex:
            logger.error(f"Error handling file {file_path}: {ex}")

    def monitoring_command_line(self):
        logger.info("Started command-line monitoring loop")
        while True:
            try:
                cmdlines = self.capture_command_lines()
                logger.debug(f"Enumerated {len(cmdlines)} commandline(s)")
                for cmd, exe_path in cmdlines:

                    process_name = os.path.basename(exe_path)
                    safe_process_name = sanitize_filename(process_name)

                    with self.lock:
                        if cmd in self.processed_texts:
                            continue
                        self.processed_texts.add(cmd)

                    orig_fn = self.get_unique_filename(f"cmd_{safe_process_name}")
                    with open(orig_fn, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(cmd[:1_000_000])
                    logger.info(f"Wrote cmd -> {orig_fn}")
                    # Scan command line (command_flag=True)
                    threading.Thread(
                        target=scan_and_warn,
                        args=(orig_fn,),
                        kwargs={'command_flag': True}
                    ).start()

            except Exception as ex:
                logger.exception(f"Command-line snapshot error:{ex}")

    def start_monitoring_threads(self):
        # Start the main monitoring threads
        threading.Thread(target=self.monitoring_window_text).start()
        threading.Thread(target=self.monitoring_command_line).start()
        logger.info("All monitoring threads have been started.")

monitor_message = MonitorMessageCommandLine()

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
                            logger.info(f"New file detected in {root}: {filename}")
                            alerted_files.add(file_path)
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()

                        # on modification: rescan + recopy
                        if file_path not in scanned_files:
                            scanned_files.add(file_path)
                            file_mod_times[file_path] = last_mod_time
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()  # Scan immediately
                        elif file_mod_times[file_path] != last_mod_time:
                            logger.info(f"File modified in {root}: {filename}")
                            threading.Thread(target=scan_and_warn, args=(file_path,)).start()
                            file_mod_times[file_path] = last_mod_time

    except Exception as ex:
        logger.error(f"Error in monitor_sandboxie_directory: {ex}")

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
    logger.info("Forcefully terminating all analysis threads...")

    for thread in analysis_threads:
        if thread.is_alive():
            name = thread_function_map.get(thread, thread.name)
            logger.info(f"Killing thread: {name}")
            kill_thread_silently(thread)

    time.sleep(0.1)  # short delay to let threads exit

    still_alive = [t.name for t in analysis_threads if t.is_alive()]
    if still_alive:
        logger.error(f"Some threads are still running: {still_alive}")
    else:
        logger.info("All analysis threads have been terminated.")

def windows_yield_cpu():
    """Windows-specific CPU yielding using SwitchToThread()"""
    ctypes.windll.kernel32.SwitchToThread()

def periodic_yield_worker(stop_event, yield_interval=0.1):
    """Background thread that yields CPU periodically until analysis finishes"""
    while not stop_event.is_set():
        windows_yield_cpu()
        time.sleep(yield_interval)

def perform_sandbox_analysis(file_path, stop_callback=None):
    global main_file_path
    global analysis_threads
    global thread_function_map  # Track thread -> function

    try:
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            logger.error(f"Expected str, bytes or os.PathLike object, not {type(file_path).__name__}")
            return

        logger.info(f"Performing sandbox analysis on: {file_path}")

        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        file_path = os.path.normpath(file_path)
        if not os.path.isfile(file_path):
            logger.error(f"File does not exist: {file_path}")
            return

        main_file_path = file_path
        analysis_threads = []
        thread_function_map = {}

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
                        logger.info(f"Thread {target_func.__name__} stopped by user request")
                    else:
                        logger.error(f"Error in thread {target_func.__name__}: {e}")

            thread = threading.Thread(target=monitored_wrapper, name=f"Analysis_{target_func.__name__}")
            analysis_threads.append(thread)
            thread_function_map[thread] = target_func.__name__
            return thread

        stop_flag = threading.Event()

        def stop_callback():
            return stop_flag.is_set()

        restart_owlyshield_threaded()

        threads_to_start = [
            (monitor_message.start_monitoring_threads,),
            (scan_and_warn, (main_dest,)),
            (monitor_memory_changes, (), {'change_threshold_bytes': 1024, 'stop_callback': stop_callback}),
            (run_sandboxie_plugin,),
            (monitor_suricata_log,),
            (web_protection_observer.begin_observing,),
            (monitor_directories_with_watchdog,),
            (start_monitoring_sandbox,),
            (monitor_log_file, (av_events_json_file_path,)),
            (monitor_sandboxie_directory,),
            (check_startup_directories,),
            (monitor_hosts_file,),
            (check_uefi_directories,),
            (monitor_saved_paths,),
            (run_sandboxie, (file_path,)),
        ]

        for thread_info in threads_to_start:
            if stop_callback and stop_callback():
                logger.info("Analysis stopped before all threads could start")
                return "[!] Analysis stopped by user request"

            target_func = thread_info[0]
            args = thread_info[1] if len(thread_info) > 1 else ()

            thread = create_monitored_thread(target_func, *args)
            thread.start()

        logger.info("Sandbox analysis started. Please check log after you close program. There is no limit to scan time.")

        # Instead of blocking loop, use a monitoring thread
        def monitor_threads():
            while any(thread.is_alive() for thread in analysis_threads):
                if stop_callback and stop_callback():
                    logger.info("Stop requested, terminating analysis threads...")
                    terminate_analysis_threads_immediately()
                    return
                time.sleep(0.1)

        # Run monitoring in separate thread
        monitor_thread = threading.Thread(target=monitor_threads)
        monitor_thread.start()

        # Wait for monitoring thread to finish
        monitor_thread.join()

        return "[+] Sandbox analysis completed successfully"

    except Exception as ex:
        if stop_callback and stop_callback():
            logger.info("Analysis stopped by user request during exception handling")
            return "[!] Analysis stopped by user request"

        error_message = f"An error occurred during sandbox analysis: {ex}"
        logger.error(error_message)
        return error_message

def run_analysis_with_yield(file_path: str, stop_callback=None):
    """
    This function mirrors the original AnalysisThread.execute_analysis method.
    It logs the file path, performs the sandbox analysis, and handles any exceptions.
    Now supports a stop_callback to allow graceful interruption with Windows CPU yielding.
    Runs a background thread that periodically yields CPU during analysis.
    """
    # Create stop event for background yielding thread
    yield_stop_event = threading.Event()

    # Start background yielding thread
    yield_thread = threading.Thread(target=periodic_yield_worker, args=(yield_stop_event, 0.1))
    yield_thread.start()

    try:
        logger.info(f"Running analysis for: {file_path}")

        # Check for stop request before starting
        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        # Let Qt process events before heavy work
        QApplication.processEvents()
        windows_yield_cpu()

        # Perform the sandbox analysis with stop checking
        result = perform_sandbox_analysis(file_path, stop_callback=stop_callback)

        # Let Qt process events after heavy work
        QApplication.processEvents()
        windows_yield_cpu()

        # Check for stop request after analysis
        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        return result if result else "[+] Analysis completed successfully"

    except Exception as ex:
        # Check if the exception was due to a stop request
        if stop_callback and stop_callback():
            return "[!] Analysis stopped by user request"

        error_message = f"An error occurred during sandbox analysis: {ex}"
        logger.error(error_message)
        return error_message

    finally:
        # Stop the background yielding thread
        yield_stop_event.set()
        yield_thread.join(timeout=1.0)  # Wait max 1 second for thread to finish

def run_anti_self_delete_check():
    # normalize main_file_path (assumes main_file_path variable exists)
    mp = Path(main_file_path)

    # report file
    report_path = Path("main_file_path_report.txt")

    # Line 1: existence check label
    line1 = f"Checking existence of: {mp}"

    # Existence boolean
    exists = mp.exists()

    # Line 2: minimal details with timestamp and existence status
    checked_at = datetime.now().isoformat()
    line2 = f"Anti-Self-Delete details: Checked at: {checked_at} - Exists: {'Yes' if exists else 'No'}"

    # Write the two-line report
    try:
        with report_path.open("w", encoding="utf-8", errors="ignore") as fh:
            fh.write(line1 + "\n")
            fh.write(line2 + "\n")
        logger.info("Main-file existence report written.")
    except Exception as e:
        logger.error(f"Failed to write report file: {e}")

def run_sandboxie_plugin_script():
    # Anti-self-delete check for plugin
    run_anti_self_delete_check()

    # build the inner python invocation
    python_entry = f'"{Open_Hydra_Dragon_Anti_Rootkit_path}",Run'
    # build the full command line for Start.exe
    cmd = f'"{sandboxie_path}" /box:DefaultBox /elevate "{python_path}" {python_entry}'
    try:
        logger.info(f"Running python script via Sandboxie: {cmd}")
        # shell=True so that Start.exe sees the switches correctly
        subprocess.run(cmd, check=True, shell=True, encoding="utf-8", errors="ignore")
        logger.info("Python plugin ran successfully in Sandboxie.")
    except subprocess.CalledProcessError as ex:
        logger.error(f"Failed to run python plugin in Sandboxie: {ex}")

def run_sandboxie_plugin():
    # build the inner rundll32 invocation
    dll_entry = f'"{HydraDragonAV_sandboxie_DLL_path}",Run'
    # build the full command line for Start.exe
    cmd = f'"{sandboxie_path}" /box:DefaultBox /elevate rundll32.exe {dll_entry}'
    try:
        logger.info(f"Running DLL via Sandboxie: {cmd}")
        # shell=True so that Start.exe sees the switches correctly
        subprocess.run(cmd, check=True, shell=True, encoding="utf-8", errors="ignore")
        logger.info("Plugin ran successfully in Sandboxie.")
    except subprocess.CalledProcessError as ex:
        logger.error(f"Failed to run plugin in Sandboxie: {ex}")

def run_sandboxie(file_path):
    try:
        subprocess.run([sandboxie_path, '/box:DefaultBox', '/elevate', file_path], check=True, encoding="utf-8", errors="ignore")
    except subprocess.CalledProcessError as ex:
        logger.error(f"Failed to run Sandboxie on {file_path}: {ex}")

def run_de4dot_in_sandbox(file_path):
    """
    Runs de4dot inside Sandboxie to avoid contaminating the host.
    Extracts all files into de4dot_extracted_dir via -ro.
    Uses -r for recursive processing.
    """

    # Convert file path to directory path
    if os.path.isfile(file_path):
        input_dir = os.path.dirname(file_path)
    else:
        input_dir = file_path

    # de4dot-x64.exe -r <input_dir> -ro <output_dir>
    cmd = [
        sandboxie_path,
        "/box:DefaultBox",
        "/elevate",
        de4dot_cex_x64_path,
        "-r",
        input_dir,
        "-ro",
        de4dot_extracted_dir
    ]

    try:
        subprocess.run(cmd, check=True, encoding="utf-8", errors="ignore")
        logger.info(f"de4dot extraction succeeded for {input_dir} in sandbox DefaultBox")
    except subprocess.CalledProcessError as ex:
        logger.error(f"Failed to run de4dot on {input_dir} in sandbox DefaultBox: {ex}")

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
            logger.info("Previous log removed successfully.")
        except Exception as e:
            logger.error("Failed to remove previous log: %s", e)

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
    logger.debug("HiJackThis launched.")

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
    logger.info("Log copied to %s", dest)
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
        logger.error(f"Could not read ClamAV DB time: {e}")
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
            logger.error(f"Sidebar icon not found at {icon_path}. Drawing fallback.")

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


# --- Custom Shield Widget for Status ---
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
        if os.path.exists(icon_path):
            self.hydra_pixmap = QPixmap(icon_path)
        else:
            logger.error(f"Shield icon not found at {icon_path}. Will use fallback drawing.")


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

        # Fill shield with a gradient
        shield_gradient = QLinearGradient(0, -90, 0, 100)
        shield_gradient.setColorAt(0, QColor("#434C5E"))
        shield_gradient.setColorAt(1, QColor("#3B4252"))
        painter.fillPath(path, QBrush(shield_gradient))

        progress = self._check_progress

        # Draw the correct icon based on protection status
        if self.is_protected:
            # Draw the user's PNG inside the shield if protected and available
            if self.hydra_pixmap and not self.hydra_pixmap.isNull():
                painter.setOpacity(progress)
                # Define the rectangle to draw the pixmap in
                pixmap_rect = QRect(-75, -85, 150, 150)
                painter.drawPixmap(pixmap_rect, self.hydra_pixmap)
                painter.setOpacity(1.0) # Reset opacity
        else:
            # Draw the cross for the 'unprotected' status
            painter.setPen(QPen(QColor("white"), 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawLine(int(-35 * progress), int(-35 * progress), int(35 * progress), int(35 * progress))
            painter.drawLine(int(35 * progress), int(-35 * progress), int(-35 * progress), int(35 * progress))


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

    def request_stop(self):
        """Public method to request stopping the worker"""
        self.stop_requested = True
    # --- Task-Specific Methods (Called by run()) ---

    def load_meta_llama_1b_model(self):
        """
        Function to load Meta Llama-3.2-1B model and tokenizer.
        This is a resource-intensive operation.
        Checks that the local folder exists before attempting to load.
        """
        # Check if the local model directory exists
        if not os.path.isdir(meta_llama_1b_dir):
            logger.error(f"Meta Llama-3.2-1B directory not found: {meta_llama_1b_dir}")
            return None, None

        # --- Hugging Face Transformers for Llama model (Optional Feature) ---
        # This feature is experimental and requires significant RAM.
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
        except Exception as ex:
            error_message = f"Error importing transformers: {ex}"
            logger.error(error_message)
            return None, None

        try:
            logger.info("Attempting to load Llama-3.2-1B model and tokenizer...")

            # Load tokenizer and model from the local directory
            llama32_tokenizer = AutoTokenizer.from_pretrained(
                meta_llama_1b_dir,
                local_files_only=True
            )
            llama32_model = AutoModelForCausalLM.from_pretrained(
                meta_llama_1b_dir,
                local_files_only=True,
                # Optional: Add device_map="auto" if you have a GPU and want to use it
            )

            logger.info("Llama-3.2-1B successfully loaded!")
            return llama32_model, llama32_tokenizer
        except Exception as ex:
            error_message = f"Error loading Llama-3.2-1B model or tokenizer: {ex}"
            logger.error(error_message)
            return None, None

    def generate_clean_db(self):
        success = run_pd64_db_gen()
        msg = "[+] clean.hashes generated." if success else "[!] Failed to generate clean.hashes."
        self.output_signal.emit(msg)

    def quick_generate_clean_db_task(self):
        success = run_pd64_db_gen(quick=True)
        msg = "[+] clean.hashes generated." if success else "[!] Failed to generate clean.hashes."
        self.output_signal.emit(msg)

    def capture_analysis_logs(self):
        global pre_analysis_log_path, post_analysis_log_path, pre_analysis_entries, post_analysis_entries
        if pre_analysis_log_path is None:
            path = run_and_copy_log(label="pre")
            pre_analysis_log_path = path
            pre_analysis_entries = parse_report(path)
            self.output_signal.emit(f"[+] Pre-analysis log captured. Don't forget to capture the post-analysis logger.: {os.path.basename(path)}")
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
                    if (datetime.now() - file_mod_time) > timedelta(hours=12):
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
                    reload_clamav_database()
                    self.output_signal.emit("[+] Virus definitions updated successfully and ClamAV restarted.")
                    self.output_signal.emit(f"Output:\n{result.stdout}")
                else:
                    self.output_signal.emit(f"[!] Failed to update ClamAV definitions. Error:\n{result.stderr}")
            else:
                self.output_signal.emit("[*] Definitions are already up-to-date.")
        except Exception as e:
            self.output_signal.emit(f"[!] Error updating definitions: {str(e)}")

    def analyze_file_worker(self, file_path):
        """
        Runs file analysis in a separate thread without freezing.
        Results or errors are emitted via output_signal.
        """

        if self.stop_requested:
            self.output_signal.emit("[!] Analysis stopped by user request")
            return

        self.output_signal.emit(f"[*] Starting analysis for: {file_path}")

        # Stop callback
        def check_stop():
            return self.stop_requested

        # Analysis task to run in a separate thread
        def analysis_task():
            try:
                result = run_analysis_with_yield(file_path, stop_callback=check_stop)
                if not self.stop_requested:
                    self.output_signal.emit(result)
                    self.output_signal.emit("[+] File analysis completed successfully")
                else:
                    self.output_signal.emit("[!] Analysis stopped by user")
            except Exception as e:
                self.output_signal.emit(f"[!] Error during analysis: {str(e)}")
                logger.error(f"File analysis error: {str(e)}")

        # Start analysis in a background thread - fully non-blocking
        threading.Thread(target=analysis_task).start()

    def scan_network_indicators(self, network_indicators: list):
        """
        Scan the already extracted network indicators using the existing scanning functions.
        """
        try:
            self.output_signal.emit(f"\n[*] Scanning {len(network_indicators)} network indicators...")

            for indicator in network_indicators:
                # Assuming indicator is a string (URL, IP, domain, etc.)
                self.output_signal.emit(f"[*] Scanning indicator: {indicator}")

                # Create mock decompiled code containing the indicator
                mock_code = f"Network indicator from rootkit scan: {indicator}"

                # Use the existing scan_code_for_links function with registry_flag=True
                scan_code_for_links(
                    mock_code,
                    "registry_indicator",
                    registry_flag=True
                )

        except Exception as e:
            logger.error(f"Error scanning network indicators: {str(e)}")
            self.output_signal.emit(f"[!] Error scanning network indicators: {str(e)}")

    def check_and_scan_network_indicators(self, reports_dir=None):
        """
        Check for network indicators file and scan the indicators only if file exists.
        """
        try:
            network_indicators_path = os.path.join(reports_dir, "network_indicators_for_av.json")

            # Only proceed if network indicators file exists
            if os.path.exists(network_indicators_path):
                self.output_signal.emit(f"[*] Found network indicators file: {network_indicators_path}")

                # Load network indicators from file
                with open(network_indicators_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Extract indicators from the JSON structure
                if 'indicators' in data:
                    file_indicators = data['indicators']
                    if isinstance(file_indicators, list) and file_indicators:
                        self.output_signal.emit(f"[+] Loaded {len(file_indicators)} network indicators from file")
                        self.scan_network_indicators(file_indicators)
                    else:
                        self.output_signal.emit("[!] No indicators found in the file")
                else:
                    self.output_signal.emit("[!] Invalid network indicators file format")
            # No message if file doesn't exist - just silently skip

        except Exception as e:
            logger.error(f"Error checking network indicators: {str(e)}")
            self.output_signal.emit(f"[!] Error checking network indicators: {str(e)}")

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

            # Check for network indicators file and scan them if file exists
            self.check_and_scan_network_indicators()

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
        for directory in MANAGED_DIRECTORIES:
            try:
                if os.path.exists(directory):
                    shutil.rmtree(directory)
                    self.output_signal.emit(f"[+] Cleaned directory: {directory}")
                    cleaned_count += 1
            except Exception as e:
                self.output_signal.emit(f"[!] Error cleaning directory {directory}: {str(e)}")

        self.output_signal.emit(f"[+] Total directories cleaned: {cleaned_count}")

    def restart_suricata(self):
        """Restart Suricata with proper status reporting"""
        # Restart Suricata
        self.output_signal.emit("[*] Starting Suricata...")

        try:
            success = run_suricata()
            if success:
                time.sleep(1)  # Brief wait for startup
                if is_suricata_running():
                    self.output_signal.emit("[+] Suricata started successfully.")
                else:
                    self.output_signal.emit("[!] Suricata startup uncertain - check logs.")
            else:
                self.output_signal.emit("[-] Failed to start Suricata - check logs.")
        except Exception as ex:
            self.output_signal.emit(f"[-] Suricata startup error: {ex}")

    def restart_services(self):
        """
        Restarts ClamAV and Suricata services.
        """
        try:
            # Restart ClamAV
            self.output_signal.emit("[*] Restarting Owlyshield and ClamAV wrapper...")
            reload_clamav_database()
            restart_owlyshield_threaded(stop_only=True)
            self.output_signal.emit("[+] Owlyshield stopped and ClamAV wrapper restarted.")

            # Stop Suricata and cleanup logs
            self.output_signal.emit("[*] Step 1: Stopping Suricata and cleaning logs...")
            stop_suricata()

            # Restart Suricata with proper status reporting
            self.restart_suricata()

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

    def cleanup_logging_files(self):
        """
        Stops logging and removes/cleans up log files.
        """
        try:
            # Get the main script directory
            log_directory = os.path.join(script_dir, "log")

            # Close current stdout/stderr redirections
            if hasattr(sys.stdout, 'close') and sys.stdout != sys.__stdout__:
                sys.stdout.close()
            if hasattr(sys.stderr, 'close') and sys.stderr != sys.__stderr__:
                sys.stderr.close()

            # Restore original stdout/stderr
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

            # Stop the logging handlers
            logger.shutdown()

            # Remove log files if they exist
            log_files = [stdout_console_log_file, stderr_console_log_file,
                         application_log_file]

            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        os.remove(log_file)
                        self.output_signal.emit(f"[+] Removed log file: {log_file}")
                    except (OSError, PermissionError) as e:
                        self.output_signal.emit(f"[!] Could not remove {log_file}: {str(e)}")

            # Optionally remove the entire log directory if empty
            if os.path.exists(log_directory) and not os.listdir(log_directory):
                try:
                    os.rmdir(log_directory)
                    self.output_signal.emit(f"[+] Removed empty log directory: {log_directory}")
                except (OSError, PermissionError) as e:
                    self.output_signal.emit(f"[!] Could not remove log directory: {str(e)}")

            self.output_signal.emit("[+] Logging cleanup completed successfully!")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during logging cleanup: {str(e)}")

    def reinitialize_logging(self):
        """
        Reinitializes logging after cleanup using hydra_logger.
        Keeps stdout/stderr redirection.
        """
        try:
            log_directory = os.path.join(script_dir, "log")
            os.makedirs(log_directory, exist_ok=True)

            # Define log file paths
            stdout_console_log_file = os.path.join(log_directory, "antivirusconsolestdout.log")
            stderr_console_log_file = os.path.join(log_directory, "antivirusconsolestderr.log")

            # --- Reset Hydra logger via hydra_logger.py ---
            reinitialize_hydra_logger()

            # --- Stdout/Stderr redirection ---
            sys.stdout = open(stdout_console_log_file, "w", encoding="utf-8", errors="ignore")
            sys.stderr = open(stderr_console_log_file, "w", encoding="utf-8", errors="ignore")

            # --- Log reinitialization event ---
            from datetime import datetime
            logger.info("Logging reinitialized at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            self.output_signal.emit("[+] Logging reinitialized successfully!")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during logging reinitialization: {str(e)}")

    def perform_cleanup(self):
        """
        Performs comprehensive cleanup of the environment including logging files.
        """
        try:
            global pre_analysis_log_path, post_analysis_log_path, pre_analysis_entries, post_analysis_entries

            self.output_signal.emit("[*] Starting comprehensive environment cleanup...")

            # Step 1: Stop Snort and cleanup logs
            self.output_signal.emit("[*] Step 1: Stopping Suricata and cleaning logs...")
            stop_suricata()

            # Step 2: Cleanup Sandboxie
            self.output_signal.emit("[*] Step 2: Cleaning up Sandboxie environment...")
            self.full_cleanup_sandbox()
            self.full_cleanup_sandbox()

            # Step 3: Clean up directories
            self.output_signal.emit("[*] Step 3: Cleaning up generated directories...")
            self.cleanup_directories()
            self.cleanup_directories()

            # Step 4: Stop and cleanup logging files
            self.output_signal.emit("[*] Step 4: Stopping logging and cleaning log files...")
            self.cleanup_logging_files()
            self.reinitialize_logging()

            # Step 5: Reset global variables
            self.output_signal.emit("[*] Step 5: Resetting analysis state...")
            pre_analysis_log_path = None
            post_analysis_log_path = None
            pre_analysis_entries = None
            post_analysis_entries = None
            reset_flags()
            clear_pe_cache()

            # Step 6: Restart services
            self.output_signal.emit("[*] Step 6: Restarting services...")
            self.restart_services()

            # Step 7: Remove Owlyshield av events json file
            remove_log_file(av_events_json_file_path)

            # Step 8: Recreate directories
            self.output_signal.emit("[*] Step 8: Recreating clean directories...")
            self.recreate_directories()

            self.output_signal.emit("[+] Environment cleanup completed successfully!")
            self.output_signal.emit("[+] System is ready for new analysis.")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during cleanup: {str(e)}")

    def update_hayabusa_rules(self):
        """
        Updates Hayabusa rules to the latest version from the GitHub repository.
        """
        try:
            self.output_signal.emit("[*] Updating Hayabusa rules...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Run the update-rules command
            cmd = [hayabusa_path, "update-rules"]
            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa rules updated successfully!")
            else:
                self.output_signal.emit(f"[!] Failed to update Hayabusa rules. Return code: {rc}")

        except Exception as e:
            self.output_signal.emit(f"[!] Error updating Hayabusa rules: {str(e)}")

    def run_hayabusa_timeline(self, output_format="csv"):
        """
        Creates a DFIR timeline using Hayabusa for event log analysis.
        """
        try:
            self.output_signal.emit("[*] Starting Hayabusa timeline analysis...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_analysis_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)

            # Set output file based on format
            if output_format.lower() == "json":
                output_file = os.path.join(output_dir, f"hayabusa_timeline_{timestamp}.jsonl")
                cmd = [hayabusa_path, "json-timeline", "-d", evtx_logs_path, "-o", output_file]
            else:
                output_file = os.path.join(output_dir, f"hayabusa_timeline_{timestamp}.csv")
                cmd = [hayabusa_path, "csv-timeline", "-d", evtx_logs_path, "-o", output_file]

            # Add profile but keep colors and progress
            cmd.extend(["--profile", "standard"])

            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa timeline analysis completed successfully!")
                self.output_signal.emit(f"[+] Output saved to: {output_file}")

                # Show basic statistics if available
                if os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    self.output_signal.emit(f"[+] Timeline file size: {file_size:,} bytes")

                    # Count lines for CSV or events for JSON
                    try:
                        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                            line_count = sum(1 for _ in f)
                            if output_format.lower() == "json":
                                self.output_signal.emit(f"[+] Total events analyzed: {line_count:,}")
                            else:
                                self.output_signal.emit(f"[+] Total events in timeline: {line_count - 1:,}")
                    except Exception as e:
                        self.output_signal.emit(f"[!] Could not count events: {str(e)}")
            else:
                self.output_signal.emit(f"[!] Hayabusa timeline analysis failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa timeline: {str(e)}")

    def run_hayabusa_search(self, keywords, regex=False):
        """
        Search Windows event logs using Hayabusa for specific keywords or patterns.
        """
        try:
            self.output_signal.emit(f"[*] Searching event logs with Hayabusa for: {keywords}")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_search_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"hayabusa_search_{timestamp}.csv")

            # Build search command
            cmd = [hayabusa_path, "search", "-d", evtx_logs_path, "-o", output_file]

            # Add keywords or regex
            if regex:
                cmd.extend(["-r", keywords])
            else:
                cmd.extend(["-k", keywords])

            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa search completed successfully!")
                self.output_signal.emit(f"[+] Results saved to: {output_file}")

                # Show search results summary
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            if len(lines) > 1:  # More than just header
                                result_count = len(lines) - 1
                                self.output_signal.emit(f"[+] Found {result_count} matching events")
                                self.output_signal.emit("[*] Sample results:")
                                for i, line in enumerate(lines[:6]):  # Header + 5 results
                                    self.output_signal.emit(f"  {line.strip()}")
                                    if i == 5:
                                        self.output_signal.emit("  ...")
                                        break
                            else:
                                self.output_signal.emit("[*] No matching events found")
                    except Exception as e:
                        self.output_signal.emit(f"[!] Could not read results: {str(e)}")
            else:
                self.output_signal.emit(f"[!] Hayabusa search failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa search: {str(e)}")

    def run_hayabusa_logon_summary(self):
        """
        Generate a logon summary report using Hayabusa.
        """
        try:
            self.output_signal.emit("[*] Generating logon summary with Hayabusa...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_logon_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"logon_summary_{timestamp}.csv")

            cmd = [hayabusa_path, "logon-summary", "-d", evtx_logs_path, "-o", output_file]

            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa logon summary completed successfully!")
                self.output_signal.emit(f"[+] Results saved to: {output_file}")

                # Show logon summary
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                self.output_signal.emit("[*] Logon Summary:")
                                self.output_signal.emit(content)
                            else:
                                self.output_signal.emit("[*] No logon data found")
                    except Exception as e:
                        self.output_signal.emit(f"[!] Could not read logon summary: {str(e)}")
            else:
                self.output_signal.emit(f"[!] Hayabusa logon summary failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa logon summary: {str(e)}")

    def run_hayabusa_metrics(self):
        """
        Generate various metrics using Hayabusa (log metrics, EID metrics, etc.).
        """
        try:
            self.output_signal.emit("[*] Generating system metrics with Hayabusa...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_metrics_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)

            # Run different metrics commands
            metrics_commands = [
                ("log-metrics", "log_metrics.csv"),
                ("eid-metrics", "eid_metrics.csv"),
                ("computer-metrics", "computer_metrics.csv")
            ]

            for metric_type, output_filename in metrics_commands:
                output_file = os.path.join(output_dir, output_filename)
                cmd = [hayabusa_path, metric_type, "-d", evtx_logs_path, "-o", output_file]

                self.output_signal.emit(f"[*] Running {metric_type} analysis...")
                self.output_signal.emit(f"[*] Command: {' '.join(cmd)}")

                # Use Popen with terminal popup for real-time output
                process = subprocess.Popen(
                    cmd,
                    cwd=os.path.dirname(hayabusa_path)
                )

                # Wait for process to complete and get return code
                rc = process.wait()

                if rc == 0:
                    self.output_signal.emit(f"[+] {metric_type} completed successfully!")
                    self.output_signal.emit(f"[+] Results saved to: {output_file}")

                    # Show brief summary of results
                    if os.path.exists(output_file):
                        try:
                            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                                if len(lines) > 1:
                                    self.output_signal.emit(f"[+] Generated {len(lines) - 1} {metric_type} entries")
                                else:
                                    self.output_signal.emit(f"[*] No {metric_type} data found")
                        except Exception as e:
                            self.output_signal.emit(f"[!] Could not read {metric_type} results: {str(e)}")
                else:
                    self.output_signal.emit(f"[!] {metric_type} failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa metrics: {str(e)}")

    def run(self):
        """The entry point for the thread."""
        try:
            task_mapping = {
                "capture_analysis_logs": self.capture_analysis_logs,
                "compare_analysis_logs": self.compare_analysis_logs,
                "update_defs": self.update_definitions,
                "quick_generate_clean_db_task": self.quick_generate_clean_db_task,
                "generate_clean_db": self.generate_clean_db,
                "rootkit_scan": self.perform_rootkit_scan,
                "cleanup_environment": self.perform_cleanup,
                "load_meta_llama_1b_model": self.load_meta_llama_1b_model,
                "update_hayabusa_rules": self.update_hayabusa_rules,
                "hayabusa_timeline_csv": lambda: self.run_hayabusa_timeline("csv"),
                "hayabusa_timeline_json": lambda: self.run_hayabusa_timeline("json"),
                "hayabusa_logon_summary": self.run_hayabusa_logon_summary,
                "hayabusa_metrics": self.run_hayabusa_metrics,
                "analyze_file": lambda: self.analyze_file_worker(*self.args),
                "hayabusa_search": lambda: self.run_hayabusa_search(*self.args)
            }

            task_function = task_mapping.get(self.task_type)
            if task_function:
                task_function()
            else:
                self.output_signal.emit(f"[!] Unknown task type: {self.task_type}")
        except Exception as e:
            if not self.stop_requested:
                self.output_signal.emit(f"[!] Worker thread error: {str(e)}")

# --- Main Application Window ---
class AntivirusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.workers = []
        self.log_outputs = []
        self.animation_group = QParallelAnimationGroup()
        self.worker_lock = threading.RLock()  # Safer choice

        self.apply_stylesheet()
        self.setup_ui()

    def apply_stylesheet(self):
        stylesheet = """
            QWidget { background-color: #2E3440; color: #D8DEE9; font-family: 'Segoe UI', Arial, sans-serif; font-size: 14px; }
            QTextEdit { background-color: #3B4252; border: 1px solid #4C566A; border-radius: 5px; padding: 8px; color: #ECEFF4; font-family: 'Consolas', 'Courier New', monospace; }
            #sidebar { background-color: #2E3440; max-width: 220px; }
            #logo { color: #88C0D0; font-size: 28px; font-weight: bold; }
            #nav_button { background-color: transparent; border: none; color: #ECEFF4; padding: 12px; text-align: left; border-radius: 5px; }
            #nav_button:hover { background-color: #434C5E; }
            #nav_button:checked { background-color: #88C0D0; color: #2E3440; font-weight: bold; }
            #page_title { font-size: 28px; font-weight: 300; color: #ECEFF4; padding-bottom: 15px; }
            #page_subtitle { font-size: 16px; color: #A3BE8C; }
            #version_label { font-size: 13px; color: #81A1C1; }
            #action_button { background-color: #5E81AC; color: #ECEFF4; border-radius: 8px; padding: 12px 20px; font-size: 14px; font-weight: bold; border: none; max-width: 350px; }
            #action_button_secondary { background-color: #D08770; color: #ECEFF4; border-radius: 8px; padding: 12px 20px; font-size: 14px; font-weight: bold; border: none; max-width: 350px; }
            #action_button_secondary:hover { background-color: #EBCB8B; }
            #action_button:hover { background-color: #81A1C1; }
            #action_button_danger { background-color: #BF616A; color: #ECEFF4; border-radius: 8px; padding: 12px 20px; font-size: 14px; font-weight: bold; border: none; }
            #action_button_danger:hover { background-color: #d08770; }
            QGroupBox { font-weight: bold; border: 1px solid #4C566A; border-radius: 8px; margin-top: 10px; padding: 15px; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; }
            #warning_text { font-size: 13px; }
        """
        self.setStyleSheet(stylesheet)

    def append_log_output(self, text):
        """Append text to the current page's log output widget."""
        current_page_index = self.main_stack.currentIndex()
        if 0 <= current_page_index < len(self.log_outputs):
            log_widget = self.log_outputs[current_page_index]
            if log_widget:
                log_widget.append(text)
                # Auto-scroll to bottom
                log_widget.verticalScrollBar().setValue(
                    log_widget.verticalScrollBar().maximum()
                )

    def on_worker_finished(self, worker):
        """Handle worker thread completion."""
        self.append_log_output(f"[+] Task '{worker.task_type}' finished.")

        with self.worker_lock:
            if worker in self.workers:
                self.workers.remove(worker)

        # Update UI status when all workers are done
        with self.worker_lock:
            if not self.workers:
                if hasattr(self, 'shield_widget'):
                    self.shield_widget.set_status(True)
                if hasattr(self, 'status_text'):
                    self.status_text.setText("Ready for analysis!")

    def _update_ui_for_worker_start(self, task_type):
        """Update UI elements when worker starts (called from main thread)."""
        self.append_log_output(f"[*] Task '{task_type}' started.")
        if hasattr(self, 'shield_widget'):
            self.shield_widget.set_status(False)
        if hasattr(self, 'status_text'):
            self.status_text.setText("System is busy...")

    def start_worker(self, task_type, *args):
        """Start a new worker thread for the given task."""
        # This method is called from the main GUI thread (e.g., button clicks),
        # so it's safe to create workers and update the UI directly.
        try:
            # Create a new worker
            worker = Worker(task_type, *args)
            worker.output_signal.connect(self.append_log_output)
            # When the worker finishes, call on_worker_finished
            worker.finished.connect(lambda: self.on_worker_finished(worker))

            # Add to the active workers list (thread-safe)
            with self.worker_lock:
                self.workers.append(worker)

            # Start the worker's run() method in a new thread.
            worker.start()

            # Update UI to show the system is busy *after* successfully starting.
            self._update_ui_for_worker_start(task_type)

        except Exception as e:
            # Handle any errors during worker creation
            self.append_log_output(f"[!] Error starting task '{task_type}': {str(e)}")

    def stop_analysis(self):
        """Stop all running analysis tasks."""
        if not self.workers:
            self.append_log_output("[!] No running tasks to stop.")
            return

        self.append_log_output("[*] Requesting stop for all running tasks...")

        # Request stop for all workers
        for worker in self.workers[:]:  # Create a copy of the list
            if worker.isRunning():
                worker.request_stop()
                self.append_log_output(f"[*] Stop requested for task: {worker.task_type}")

        # Run force_stop_remaining_workers in 1 second without QTimer
        threading.Timer(1.0, self.force_stop_remaining_workers).start()

    def force_stop_remaining_workers(self):
        """Force stop any workers that didn't stop gracefully."""
        remaining_workers = [w for w in self.workers if w.isRunning()]

        if remaining_workers:
            self.append_log_output(f"[*] Force stopping {len(remaining_workers)} remaining tasks...")

            for worker in remaining_workers:
                try:
                    worker.terminate()  # Force termination
                    worker.wait(2000)  # Wait up to 2 seconds
                    if worker.isRunning():
                        self.append_log_output(f"[!] Could not stop task: {worker.task_type}")
                    else:
                        self.append_log_output(f"[+] Force stopped task: {worker.task_type}")
                except Exception as e:
                    self.append_log_output(f"[!] Error stopping task {worker.task_type}: {str(e)}")

        # Clear workers list and update UI
        self.workers.clear()
        if hasattr(self, 'shield_widget'):
            self.shield_widget.set_status(True)
        if hasattr(self, 'status_text'):
            self.status_text.setText("Ready for analysis!")

    def open_sandboxie_control(self):
        """Starts run_sandboxie_control in a thread."""
        self.append_log_output("[*] Opening Sandboxie Control window...")

        def run_thread():
            try:
                run_sandboxie_control()
                self.append_log_output("[+] Sandboxie Control window opened successfully.")
            except Exception as e:
                self.append_log_output(f"[!] Error opening Sandboxie Control: {str(e)}")

        # Use QThread instead of threading.Thread for better Qt integration
        thread = threading.Thread(target=run_thread)
        thread.start()

    def analyze_file(self):
        """Open file dialog and start file analysis."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select a file to analyze",
            "",
            "All Files (*)"
        )
        if file_path:
            self.append_log_output(f"[*] Selected file for analysis: {file_path}")
            self.start_worker("analyze_file", file_path)
        else:
            self.append_log_output("[*] File selection cancelled.")

    def perform_hayabusa_search(self):
        """Performs a search using the text from the search input field."""
        if not hasattr(self, 'search_input'):
            self.append_log_output("[!] Search input not available.")
            return

        keywords = self.search_input.text().strip()
        if keywords:
            self.start_worker("hayabusa_search", keywords, False)  # False for keyword search
        else:
            self.append_log_output("[!] Please enter search keywords first.")

    def switch_page_with_animation(self, index):
        """Switch between pages with slide animation."""
        if (self.animation_group.state() == QParallelAnimationGroup.State.Running or
            self.main_stack.currentIndex() == index):
            return

        current_widget = self.main_stack.currentWidget()
        next_widget = self.main_stack.widget(index)
        current_index = self.main_stack.currentIndex()

        slide_out_x = -self.main_stack.width() if index > current_index else self.main_stack.width()
        slide_in_x = -slide_out_x

        next_widget.move(slide_in_x, 0)
        next_widget.show()
        next_widget.raise_()

        current_pos_anim = QPropertyAnimation(current_widget, b"pos")
        current_pos_anim.setEndValue(QPoint(slide_out_x, 0))
        next_pos_anim = QPropertyAnimation(next_widget, b"pos")
        next_pos_anim.setEndValue(QPoint(0, 0))

        self.animation_group = QParallelAnimationGroup()
        for anim in [current_pos_anim, next_pos_anim]:
            anim.setDuration(400)
            anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
            self.animation_group.addAnimation(anim)

        self.animation_group.finished.connect(lambda: self.main_stack.setCurrentIndex(index))
        self.animation_group.start()

    def closeEvent(self, event):
        """Handle application close event - stop all workers first."""
        if self.workers:
            self.append_log_output("[*] Stopping all running tasks before exit...")

            # Request stop for all workers
            for worker in self.workers:
                if worker.isRunning():
                    worker.request_stop()

            # Force terminate if needed
            for worker in self.workers:
                if worker.isRunning():
                    worker.terminate()
                    worker.wait(3000)  # Wait up to 3 seconds

        event.accept()

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
        version_label = QLabel(WINDOW_TITLE)
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
        self.log_outputs.append(None) # No log output on status page
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
        log_output.setReadOnly(True)  # Make read-only to prevent user input
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
            "<b>NOTICE:</b> Process Dump x64 must be used to create clean hashes before you download malware.<br><br>"
            "<b>Recommended Workflow:</b><br>"
            "1. Update ClamAV and Hayabusa Virus Definitions<br>"
            "2. Generate Clean DB (Process Dump x64)<br>"
            "3. Capture Pre-analysis Logs<br>"
            "4. Analyze a File<br>"
            "5. Stop Analysis<br>"
            "6. Capture Post-analysis Logs and Compare Results (with Llama AI)<br>"
            "7. Rootkit Scan<br>"
            "8. Hayabusa SIGMA SIEM CSV-timeline Scan<br>"
            "9. Cleanup Environment<br><br>"
            "<i>Return to a clean snapshot before starting a new analysis.</i>"
        )
        warning_text.setWordWrap(True)
        warning_text.setObjectName("warning_text")
        warning_layout.addWidget(warning_text)
        layout.addWidget(warning_box)
        # First row of buttons
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
        # Second row of buttons
        control_layout = QHBoxLayout()
        sandboxie_control_btn = QPushButton("Open Sandboxie Control")
        sandboxie_control_btn.setObjectName("action_button")
        sandboxie_control_btn.clicked.connect(self.open_sandboxie_control)
        control_layout.addWidget(sandboxie_control_btn)
        control_layout.addStretch()  # Push button to the left
        layout.addLayout(control_layout)
        log_output = QTextEdit("Analysis logs will be saved in the logs folder.")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)
        self.log_outputs.append(log_output)
        return page

    def create_hayabusa_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        title = QLabel("Hayabusa Event Log Analysis")
        title.setObjectName("page_title")
        layout.addWidget(title)
        info_box = QGroupBox("About Hayabusa")
        info_layout = QVBoxLayout(info_box)
        info_text = QLabel(
            "Hayabusa is a Windows event log fast forensics timeline generator and threat hunting tool. "
            "It can create DFIR timelines, search for specific events, and generate various security metrics."
        )
        info_text.setWordWrap(True)
        info_text.setObjectName("warning_text")
        info_layout.addWidget(info_text)
        layout.addWidget(info_box)
        update_rules_btn = QPushButton("Update Hayabusa Rules Database")
        update_rules_btn.setObjectName("action_button")
        update_rules_btn.clicked.connect(lambda: self.start_worker("update_hayabusa_rules"))
        layout.addWidget(update_rules_btn)
        timeline_layout = QHBoxLayout()
        csv_timeline_btn = QPushButton("Generate CSV Timeline")
        csv_timeline_btn.setObjectName("action_button")
        csv_timeline_btn.clicked.connect(lambda: self.start_worker("hayabusa_timeline_csv"))
        json_timeline_btn = QPushButton("Generate JSON Timeline")
        json_timeline_btn.setObjectName("action_button")
        json_timeline_btn.clicked.connect(lambda: self.start_worker("hayabusa_timeline_json"))
        timeline_layout.addWidget(csv_timeline_btn)
        timeline_layout.addWidget(json_timeline_btn)
        layout.addLayout(timeline_layout)
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter keywords to search in event logs...")
        search_btn = QPushButton("Search Events")
        search_btn.setObjectName("action_button")
        search_btn.clicked.connect(self.perform_hayabusa_search)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)
        analysis_layout = QHBoxLayout()
        logon_summary_btn = QPushButton("Logon Summary")
        logon_summary_btn.setObjectName("action_button")
        logon_summary_btn.clicked.connect(lambda: self.start_worker("hayabusa_logon_summary"))
        metrics_btn = QPushButton("System Metrics")
        metrics_btn.setObjectName("action_button")
        metrics_btn.clicked.connect(lambda: self.start_worker("hayabusa_metrics"))
        analysis_layout.addWidget(logon_summary_btn)
        analysis_layout.addWidget(metrics_btn)
        layout.addLayout(analysis_layout)
        log_output = QTextEdit("Hayabusa analysis results will appear here...")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)
        self.log_outputs.append(log_output)
        return page

    def create_generate_clean_db_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Generate Clean DB")
        title.setObjectName("page_title")
        layout.addWidget(title)

        # Main Generate Clean DB button
        generate_button = QPushButton("Run Generate Clean DB (Recommended)")
        generate_button.setObjectName("action_button")
        generate_button.clicked.connect(lambda: self.start_worker("generate_clean_db"))
        layout.addWidget(generate_button)

        # Quick Clean DB button (secondary option)
        quick_button = QPushButton("Run Quick Clean DB")
        quick_button.setObjectName("action_button_secondary")
        quick_button.clicked.connect(lambda: self.start_worker("quick_generate_clean_db_task"))
        layout.addWidget(quick_button)

        log_output = QTextEdit("Generate Clean DB logs will appear here...")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)
        self.log_outputs.append(log_output)

        layout.addStretch()
        return page

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
        log_output.setReadOnly(True)
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
        llama_load_button = QPushButton("Load Meta Llama AI Model (Requires >8GB RAM)")
        llama_load_button.setObjectName("action_button")
        llama_load_button.clicked.connect(lambda: self.start_worker("load_meta_llama_1b_model"))
        layout.addWidget(llama_load_button, 0, Qt.AlignmentFlag.AlignLeft)
        github_button = QPushButton("View Project on GitHub")
        github_button.setObjectName("action_button")
        github_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus"))
        layout.addWidget(github_button, 0, Qt.AlignmentFlag.AlignLeft)
        llama_release_button = QPushButton("View Meta Llama Release")
        llama_release_button.setObjectName("action_button")
        llama_release_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus/releases/tag/MetaLlama"))
        layout.addWidget(llama_release_button, 0, Qt.AlignmentFlag.AlignLeft)
        log_output = QTextEdit("Llama AI model status will appear here...")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)
        self.log_outputs.append(log_output)
        layout.addStretch()
        return page

    def create_main_content(self):
        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self.create_status_page())
        self.main_stack.addWidget(self.create_task_page("Update ClamAV Definitions", "update_defs"))
        self.main_stack.addWidget(self.create_generate_clean_db_page())
        self.main_stack.addWidget(self.create_analysis_page())
        self.main_stack.addWidget(self.create_task_page("Capture Analysis Logs", "capture_analysis_logs"))
        self.main_stack.addWidget(self.create_task_page("Compare Logs (Llama AI)", "compare_analysis_logs"))
        self.main_stack.addWidget(self.create_task_page("Rootkit Scan", "rootkit_scan"))
        self.main_stack.addWidget(self.create_hayabusa_page())
        self.main_stack.addWidget(self.create_cleanup_page())
        self.main_stack.addWidget(self.create_about_page())
        return self.main_stack

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
            "Status", "Update ClamAV Definitions", "Generate Clean DB",
            "Analyze File", "Capture Analysis Logs", "Compare Logs",
            "Rootkit Scan", "Hayabusa Analysis", "Cleanup Environment", "About And Load AI"
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

    def setup_ui(self):
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            logger.error(f"Icon file not found at: {icon_path}")
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(1024, 768)
        self.resize(1200, 800)
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(self.create_sidebar())
        main_layout.addWidget(self.create_main_content(), 1)

def main():
    app = QApplication(sys.argv)
    window = AntivirusApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
