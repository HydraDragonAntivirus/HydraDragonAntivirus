#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
from datetime import datetime
from .hydra_logger import (
    logger,
    log_directory,
)

from .path_and_variables import (
    script_dir,
    PIPE_EDR_TO_AV,
    hayabusa_path,
    python_path,
    jadx_decompiled_dir,
    nexe_javascript_unpacked_dir,
    unlicense_path,
    unlicense_x64_path,
    webcrack_javascript_deobfuscated_dir,
    pkg_unpacker_dir,
    enigma1_extracted_dir,
    upx_path,
    upx_extracted_dir,
    inno_unpack_path,
    autohotkey_decompiled_dir,
    inno_setup_unpacked_dir,
    themida_unpacked_dir,
    decompiled_dir,
    pyinstaller_extracted_dir,
    pyarmor8_and_9_extracted_dir,
    pyarmor7_extracted_dir,
    cx_freeze_extracted_dir,
    ghidra_logs_dir,
    ghidra_scripts_dir,
    FernFlower_decompiled_dir,
    jar_extracted_dir,
    dotnet_dir,
    obfuscar_dir,
    androguard_dir,
    decompiled_jsc_dir,
    npm_pkg_extracted_dir,
    asar_dir,
    un_confuser_ex_path,
    un_confuser_ex_extracted_dir,
    net_reactor_slayer_x64_cli_path,
    nuitka_dir,
    ole2_dir,
    FernFlower_path,
    system_file_names_path,
    extensions_path,
    vmprotect_unpacked_dir,
    python_source_code_dir,
    python_deobfuscated_dir,
    python_deobfuscated_marshal_pyc_dir,
    pylingual_extracted_dir,
    pycdas_extracted_dir,
    de4dot_cex_x64_path,
    net_reactor_extracted_dir,
    de4dot_extracted_dir,
    nuitka_source_code_dir,
    pe_extracted_dir,
    zip_extracted_dir,
    tar_extracted_dir,
    seven_zip_extracted_dir,
    general_extracted_with_7z_dir,
    nuitka_extracted_dir,
    advanced_installer_extracted_dir,
    memory_dir,
    debloat_dir,
    detectiteasy_console_path,
    ilspycmd_path,
    pycdas_path,
    ISx_installshield_extractor_path,
    installshield_extracted_dir,
    autoit_extracted_dir,
    hydra_dragon_dumper_path,
    hydra_dragon_dumper_extracted_dir,
    deobfuscar_path,
    machine_learning_pickle_path,
    resource_extractor_dir,
    ungarbler_dir,
    ungarbler_string_dir,
    excluded_rules_path,
    html_extracted_dir,
    website_rules_dir,
    spam_email_365_path,
    ipv4_addresses_path,
    ipv4_addresses_spam_path,
    ipv4_addresses_bruteforce_path,
    ipv4_addresses_phishing_active_path,
    ipv4_addresses_phishing_inactive_path,
    ipv4_whitelist_path,
    ipv6_addresses_path,
    ipv6_addresses_spam_path,
    ipv4_addresses_ddos_path,
    ipv6_addresses_ddos_path,
    ipv6_whitelist_path,
    malware_domains_path,
    malware_domains_mail_path,
    phishing_domains_path,
    abuse_domains_path,
    mining_domains_path,
    spam_domains_path,
    whitelist_domains_path,
    whitelist_domains_mail_path,
    malware_sub_domains_path,
    malware_mail_sub_domains_path,
    phishing_sub_domains_path,
    abuse_sub_domains_path,
    mining_sub_domains_path,
    spam_sub_domains_path,
    whitelist_sub_domains_path,
    whitelist_mail_sub_domains_path,
    urlhaus_path,
    antivirus_list_path,
    yaraxtr_yrc_path,
    clean_rules_path,
    yarGen_rule_path,
    icewater_rule_path,
    valhalla_rule_path,
    bypass_pyarmor7_path,
    scanned_urls_general,
    scanned_domains_general,
    scanned_ipv4_addresses_general,
    scanned_ipv6_addresses_general,
    unified_pe_cache,
    existing_projects,
    system_drive,
    system32_dir,
    file_md5_cache,
    die_cache,
    binary_die_cache,
    malicious_hashes,
    malicious_hashes_lock,
    scan_and_warn_lock,
    decompile_outputs,
    decompile_outputs_lock,
    uefi_100kb_paths,
    uefi_paths,
    get_startup_paths,
    eve_log_path,
    suricata_log_dir,
    suricata_config_path,
    suricata_exe_path,
    seven_zip_path,
    libclamav_path,
    clamav_database_directory_path,
)

# Separate log files for different purposes
stdout_console_log_file = os.path.join(
    log_directory, "antivirusconsolestdout.log"
)
stderr_console_log_file = os.path.join(
    log_directory, "antivirusconsolestderr.log"
)

pyarmor7_console_log_file = os.path.join(
    log_directory, "antiviruspyarmor7.log"
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
logger.debug(
    "Application started at %s",
    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
)

# Start timing total duration
total_start_time = time.time()

# Measure and logger.debug time taken for each import
start_time = time.time()
import asyncio
logger.debug(f"asyncio module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import aiofiles
logger.debug(f"aiofiles module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import io
logger.debug(f"io module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from uuid import uuid4 as uniquename
logger.debug(f"uuid.uuid4.uniquename loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import shutil
logger.debug(f"shutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import subprocess
logger.debug(f"subprocess module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import threading
logger.debug(f"threading module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import re
logger.debug(f"re module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import json
logger.debug(f"json module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pickle
logger.debug(f"pickle module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pefile
logger.debug(f"pefile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import traceback
logger.debug(f"traceback module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pyzipper
logger.debug(f"pyzipper module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import tarfile
logger.debug(f"tarfile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara
logger.debug(f"yara module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara_x
logger.debug(f"yara_x module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import psutil
logger.debug(f"psutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32service
logger.debug(f"win32service module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32serviceutil
logger.debug(f"win32serviceutil module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from wmi import WMI
logger.debug(f"wmi.WMI module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import pythoncom
logger.debug"pythoncom module loaded in {time.time() - start_time:.6f} seconds")
start_time = time.time()

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sniff

logger.debug(f"scapy modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ast
logger.debug(f"ast module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ctypes
logger.debug(f"ctypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from ctypes import wintypes
logger.debug(f"ctypes.wintypes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ipaddress
logger.debug(f"ipaddress module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from urllib.parse import urlparse
logger.debug(f"urllib.parse.urlparse module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import csv
logger.debug(f"csv module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import struct
logger.debug(f"struct module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from importlib.util import MAGIC_NUMBER
logger.debug(f"importlib.util.MAGIC_NUMBER module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zlib
logger.debug(f"zlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import marshal
logger.debug(f"marshal module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import base64
logger.debug(f"base64 module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from pathlib import Path, WindowsPath
logger.debug(f"pathlib.Path module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import inspect
logger.debug(f"inspect module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import py7zr
logger.debug(f"py7zr module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import zstandard
logger.debug(f"zstandard module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from elftools.elf.elffile import ELFFile
logger.debug(f"elftools.elf.elffile, ELFFile module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.MachO
logger.debug(f"macholib.MachO module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import macholib.mach_o
logger.debug(f"macholib.mach_o module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from typing import Optional, Tuple, BinaryIO, Dict, Any, List, Set
logger.debug(f"typing, Optional, Tuple, BinaryIO, Dict, Any, List and Set module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import types
logger.debug(f"types module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
logger.debug(f"cryptography.hazmat.primitives.ciphers, Cipher, algorithms, modes module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import debloat.processor
logger.debug(f"debloat modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from Crypto.Cipher import AES
logger.debug(f"Crpyto.Cipher.AES module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from Crypto.Util import Counter
logger.debug(f"Crpyto.Cipher.Counter module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import win32file
import win32pipe
logger.debug(f"pywin32 modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import requests
logger.debug(f"requests module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from xdis.unmarshal import load_code
logger.debug(f"xdis.unmarshal.load_code module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
logger.debug(f"oletools.olevba.VBA_Parser , TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from unipacker.core import Sample, UnpackerEngine, SimpleClient
logger.debug(f"unipacker.core.Sample , UnpackerEngine, SimpleClient modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from GoStringUngarbler.gostringungarbler_lib import process_file_go
logger.debug(f"GoStringUngarbler.gostringungarbler_lib.process_file_go module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from View8.view8 import disassemble, decompile, export_to_file
logger.debug(f"view8.view8, disassemble, decompile, export_to_file modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from pylingual.main import main as pylingual_main
logger.debug(f"pylingual.main.main module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from oneshot.shot import run_oneshot_python
logger.debug(f"oneshot.shot.run_oneshot_python module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from decompilers.sourceundefender import is_sourcedefender_file, unprotect_sourcedefender_file, get_sourcedefender_info
logger.debug(f"decompilers.sourceundefender.unprotect_sourcedefender_file and is_sourcedefender_file, get_sourcedefender_info modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from decompilers.advancedInstallerExtractor import AdvancedInstallerReader
logger.debug(f"decompilers.advancedInstallerExtractor.AdvancedInstallerReader module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from decompilers.vmprotectunpacker import unpack_pe
logger.debug(f"decompilers.vmprotectunpacker.unpack_pe module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from .utils_and_helpers import (
    get_signature,
    compute_md5_via_text,
    compute_md5,
    _norm
)
logger.debug(f"utils_and_helpers functions loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from . import clamav
logger.debug(f"clamav impforted in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from .detect_type import (
    is_protector_from_output,
    is_nexe_file_from_output,
    is_go_garble_from_output,
    is_pyc_file_from_output,
    is_pyarmor_archive_from_output,
    is_themida_from_output,
    is_vm_protect_from_output,
    is_pe_file_from_output,
    is_cx_freeze_file_from_output,
    is_advanced_installer_file_from_output,
    is_autoit_file_from_output,
    is_jsc_from_output,
    is_npm_from_output,
    is_asar_archive_from_output,
    is_installshield_file_from_output,
    is_nsis_from_output,
    is_elf_file_from_output,
    is_apk_file_from_output,
    is_enigma1_virtual_box,
    is_macho_file_from_output,
    is_dotnet_file_from_output,
    is_file_fully_unknown,
    is_packed_from_output,
    is_packer_upx_output,
    is_jar_file_from_output,
    is_java_class_from_output,
    is_plain_text,
    is_plain_text_file_from_output,
    is_7z_file_from_output,
    is_pyinstaller_archive_from_output,
    is_microsoft_compound_file_from_output,
    is_nuitka_file_from_output,
    is_compiled_autohotkey_file_from_output,
    is_inno_setup_file_from_output
)
logger.debug(f"detect_type detection functions loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from .notify_user import (
    notify_user,
    notify_user_pua,
    notify_user_for_malicious_source_code,
    notify_user_size_warning,
    notify_user_susp_archive_file_name_warning,
    notify_user_susp_name,
    notify_user_scr,
    notify_user_for_detected_fake_system_file,
    notify_user_invalid,
    notify_user_fake_size,
    notify_user_startup,
    notify_user_exela_stealer_v2,
    notify_user_hosts,
    notify_user_for_web,
    notify_user_for_web_source,
    notify_user_for_detected_hips_file,
    notify_user_duplicate,
    notify_user_for_uefi,
    notify_user_hayabusa_critical
)
logger.debug(f"notify_user functions loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from .pipe_events import start_all_pipe_listeners, normalize_nt_path, _is_protected_path, _sync_close_handle
logger.debug(f"pipe_events functions loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from .pattern import (
    IPv4_pattern_standard,
    IPv6_pattern_standard,
    discord_webhook_pattern,
    discord_attachment_pattern,
    discord_canary_webhook_pattern,
    cdn_attachment_pattern,
    telegram_token_pattern,
    telegram_keyword_pattern,
    discord_webhook_pattern_standard,
    discord_attachment_pattern_standard,
    discord_canary_webhook_pattern_standard,
    cdn_attachment_pattern_standard,
    telegram_token_pattern_standard,
    UBLOCK_REGEX,
    ZIP_JOIN,
    CHAINED_JOIN,
    B64_LITERAL,
    EMAIL_RE,
    EMAIL_FULLMATCH_RE,
    build_url_regex,
    build_ip_patterns
)
logger.debug(f"pattern functions loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from .pe_feature_extractor import (
    pe_extractor,
    calculate_vector_similarity
)
logger.debug(f"pe_feature_extractor functions loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from .reference_registry import ReferenceRegistry
logger.debug(f"pe_feature_extractor function loaded in {time.time() - start_time:.6f} seconds")

# Calculate and logger.debug total time
total_end_time = time.time()
total_duration = total_end_time - total_start_time
logger.debug(f"Total time for all imports: {total_duration:.6f} seconds")

user_startup, common_startup = get_startup_paths()

startup_dirs = [user_startup, common_startup]

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

drivers_path = os.path.join(system32_dir, "drivers")
hosts_path = f'{drivers_path}\\hosts'
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

# Base directories common to both lists
MANAGED_DIRECTORIES = [
    hydra_dragon_dumper_extracted_dir, enigma1_extracted_dir, inno_setup_unpacked_dir, themida_unpacked_dir, autohotkey_decompiled_dir,
    FernFlower_decompiled_dir, jar_extracted_dir, nuitka_dir, dotnet_dir, npm_pkg_extracted_dir, ole2_dir,
    androguard_dir, asar_dir, obfuscar_dir, de4dot_extracted_dir, decompiled_jsc_dir,
    net_reactor_extracted_dir, pyinstaller_extracted_dir, cx_freeze_extracted_dir, pyarmor8_and_9_extracted_dir,
    pe_extracted_dir, zip_extracted_dir, tar_extracted_dir, pyarmor7_extracted_dir,
    seven_zip_extracted_dir, general_extracted_with_7z_dir, nuitka_extracted_dir,
    advanced_installer_extracted_dir, python_source_code_dir,
    pylingual_extracted_dir, python_deobfuscated_dir, python_deobfuscated_marshal_pyc_dir,
    pycdas_extracted_dir, nuitka_source_code_dir, memory_dir, debloat_dir,
    resource_extractor_dir, ungarbler_dir, ungarbler_string_dir, html_extracted_dir, webcrack_javascript_deobfuscated_dir,
    upx_extracted_dir, installshield_extracted_dir, autoit_extracted_dir, un_confuser_ex_extracted_dir,
    decompiled_dir, vmprotect_unpacked_dir, jadx_decompiled_dir
]

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
        version_dir = os.path.join(enigma1_extracted_dir, f"{exe_name}_v{version}")
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

def is_valid_ip(ip_string: str) -> bool:
    """
    Returns True if ip_string is a valid public IPv4 or IPv6 address,
    False otherwise. Logs details about invalid cases.
    """
    
    # --- FIX: Use urlparse to handle URLs properly ---
    original = ip_string
    
    # Check if it looks like a URL (has scheme)
    if '://' in ip_string:
        try:
            parsed = urlparse(ip_string)
            # Extract hostname/IP from netloc (handles port automatically)
            ip_string = parsed.hostname if parsed.hostname else parsed.netloc
            logger.debug(f"Extracted IP/host from URL: {original!r} -> {ip_string!r}")
        except Exception as e:
            logger.error(f"Failed to parse URL {original!r}: {e}")
            return False
    
    # --- strip off port if present (for non-URL cases) ---
    # IPv6 with brackets, e.g. "[2001:db8::1]:443"
    elif ip_string.startswith('[') and ']' in ip_string:
        ip_core, sep, port = ip_string.partition(']')
        if sep and port.startswith(':') and port[1:].isdigit():
            ip_string = ip_core.lstrip('[')
            logger.debug(f"Stripped port from bracketed IPv6: {original!r} -> {ip_string!r}")
    # IPv4 or unbracketed IPv6: split on last colon only if it looks like a port
    elif ip_string.count(':') == 1:
        ip_part, port = ip_string.rsplit(':', 1)
        if port.isdigit():
            ip_string = ip_part
            logger.debug(f"Stripped port from IPv4/unbracketed: {original!r} -> {ip_string!r}")
    # else: leave IPv6 with multiple colons intact

    # Handle empty result
    if not ip_string:
        logger.error(f"Empty IP string after parsing: {original!r}")
        return False

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

async def ublock_detect(url):
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

pe_file_paths = []  # List to store the PE file paths

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

def advanced_installer_extractor(file_path):
        """
        Extract files from Advanced Installer archive.

        Args:
            file_path (str): Path to the Advanced Installer file

        Returns:
            list: List of extracted file paths
        """
        extracted_files = []

        with AdvancedInstallerReader(file_path, debug=logger) as ar:
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

        # Run the DIE command once with the -p flag for plain output
        result = subprocess.run(
            [detectiteasy_console_path, "-p", file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore"
        )

        # Display the result using logging
        if result.stdout.strip():
            logger.info(f"{'='*60}")
            logger.info(f"DIE Analysis Result for: {Path(file_path).name}")
            logger.info(f"{'='*60}")
            logger.info(result.stdout)
            logger.info(f"{'='*60}")
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

# Function to load antivirus list
def load_antivirus_list():
    global antivirus_domains_data
    try:
        with open(antivirus_list_path, 'r') as antivirus_file:
            antivirus_domains_data = antivirus_file.read().splitlines()
    except Exception as ex:
        logger.error(f"Error loading Antivirus domains: {ex}")

def load_website_data():
    global ipv4_addresses_signatures_data, ipv4_addresses_spam_signatures_data, \
           ipv4_addresses_bruteforce_signatures_data, ipv4_addresses_phishing_active_signatures_data, \
           ipv4_addresses_phishing_inactive_signatures_data, ipv4_addresses_ddos_signatures_data, \
           ipv4_whitelist_data, ipv6_addresses_signatures_data, ipv6_addresses_spam_signatures_data, \
           ipv6_addresses_ddos_signatures_data, ipv6_whitelist_data, \
           malware_domains_data, malware_domains_mail_data, phishing_domains_data, abuse_domains_data, \
           mining_domains_data, spam_domains_data, whitelist_domains_data, whitelist_domains_mail_data, \
           malware_sub_domains_data, malware_mail_sub_domains_data, phishing_sub_domains_data, \
           abuse_sub_domains_data, mining_sub_domains_data, spam_sub_domains_data, whitelist_sub_domains_data, \
           whitelist_mail_sub_domains_data, urlhaus_data, spam_email_365_data, registry

    registry = ReferenceRegistry()

    def load_csv(file_path, data_name):
        data = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row:
                        continue
                    address = row[0].strip()
                    refs = row[1:] if len(row) > 1 else []
                    data.append({
                        'address': address,
                        'ref_ids': [registry.register(r.strip()) for r in refs if r.strip()]
                    })
            logger.info(f"{data_name} loaded ({len(data)} entries)")
        except Exception as e:
            logger.error(f"Failed to load {data_name}: {e}")
        return data

    # Directly use your file path variables
    ipv4_addresses_signatures_data = load_csv(ipv4_addresses_path, "IPv4 Malicious Addresses")
    ipv4_addresses_spam_signatures_data = load_csv(ipv4_addresses_spam_path, "IPv4 Spam Addresses")
    ipv4_addresses_bruteforce_signatures_data = load_csv(ipv4_addresses_bruteforce_path, "IPv4 BruteForce Addresses")
    ipv4_addresses_phishing_active_signatures_data = load_csv(ipv4_addresses_phishing_active_path, "IPv4 Active Phishing Addresses")
    ipv4_addresses_phishing_inactive_signatures_data = load_csv(ipv4_addresses_phishing_inactive_path, "IPv4 Inactive Phishing Addresses")
    ipv4_addresses_ddos_signatures_data = load_csv(ipv4_addresses_ddos_path, "IPv4 DDoS Addresses")
    ipv4_whitelist_data = load_csv(ipv4_whitelist_path, "IPv4 Whitelist")
    ipv6_addresses_signatures_data = load_csv(ipv6_addresses_path, "IPv6 Malicious Addresses")
    ipv6_addresses_spam_signatures_data = load_csv(ipv6_addresses_spam_path, "IPv6 Spam Addresses")
    ipv6_addresses_ddos_signatures_data = load_csv(ipv6_addresses_ddos_path, "IPv6 DDoS Addresses")
    ipv6_whitelist_data = load_csv(ipv6_whitelist_path, "IPv6 Whitelist")

    malware_domains_data = load_csv(malware_domains_path, "Malware Domains")
    malware_domains_mail_data = load_csv(malware_domains_mail_path, "Malware Mail Domains")
    phishing_domains_data = load_csv(phishing_domains_path, "Phishing Domains")
    abuse_domains_data = load_csv(abuse_domains_path, "Abuse Domains")
    mining_domains_data = load_csv(mining_domains_path, "Mining Domains")
    spam_domains_data = load_csv(spam_domains_path, "Spam Domains")
    whitelist_domains_data = load_csv(whitelist_domains_path, "Whitelist Domains")
    whitelist_domains_mail_data = load_csv(whitelist_domains_mail_path, "Whitelist Mail Domains")

    malware_sub_domains_data = load_csv(malware_sub_domains_path, "Malware Subdomains")
    malware_mail_sub_domains_data = load_csv(malware_mail_sub_domains_path, "Malware Mail Subdomains")
    phishing_sub_domains_data = load_csv(phishing_sub_domains_path, "Phishing Subdomains")
    abuse_sub_domains_data = load_csv(abuse_sub_domains_path, "Abuse Subdomains")
    mining_sub_domains_data = load_csv(mining_sub_domains_path, "Mining Subdomains")
    spam_sub_domains_data = load_csv(spam_sub_domains_path, "Spam Subdomains")
    whitelist_sub_domains_data = load_csv(whitelist_sub_domains_path, "Whitelist Subdomains")
    whitelist_mail_sub_domains_data = load_csv(whitelist_mail_sub_domains_path, "Whitelist Mail Subdomains")

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

    # Spam Email 365 (plain text)
    spam_email_365_data = []
    try:
        with spam_email_365_path.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    spam_email_365_data.append(line)  # no registry, single source
        logger.info(f"Spam Email 365 loaded ({len(spam_email_365_data)} entries)")
    except Exception as e:
        logger.error(f"Failed to load Spam Email 365: {e}")

    # Save registry
    try:
        registry_path = Path(website_rules_dir) / "references.txt"
        registry.save_text(registry_path)
        logger.info(f"Reference registry saved ({len(registry.id_to_ref)} entries)")
    except Exception as e:
        logger.error(f"Failed to save reference registry: {e}")

    logger.info("All website data loaded successfully.")

def get_reference_strings(ref_ids):
    """Convert reference IDs to human-readable strings."""
    if not ref_ids:
        return ""
    refs = []
    for rid in ref_ids:
        ref_str = registry.id_to_ref.get(rid)
        if ref_str:
            refs.append(ref_str)
        else:
            refs.append(f"Unknown-{rid}")
    return ", ".join(refs)

# --------------------------------------------------------------------------
# Check for Discord and Telegram indicators in code
async def contains_discord_or_telegram_code(decompiled_code, file_path, **flags):
    """
    Scan the decompiled code for Discord webhook URLs, Discord Canary webhook URLs,
    or Telegram bot links. Stop immediately after the first valid detection.
    """

    detections = [
        (re.findall(discord_webhook_pattern, decompiled_code, flags=re.IGNORECASE),
         "Discord webhook URL", "Discord.Webhook"),
        (re.findall(discord_attachment_pattern, decompiled_code, flags=re.IGNORECASE),
         "Discord attachment URL", "Discord.Attachment"),
        (re.findall(discord_canary_webhook_pattern, decompiled_code, flags=re.IGNORECASE),
         "Discord Canary webhook URL", "Discord.Canary.Webhook"),
        (re.findall(cdn_attachment_pattern, decompiled_code, flags=re.IGNORECASE),
         "Discord CDN attachment URL", "Discord.CDNAttachment")
    ]

    # Telegram detection (token + keyword)
    telegram_token_matches = re.findall(telegram_token_pattern, decompiled_code)
    telegram_keyword_matches = re.findall(telegram_keyword_pattern, decompiled_code, flags=re.IGNORECASE)
    if telegram_token_matches and telegram_keyword_matches:
        detections.append((telegram_token_matches, "Telegram bot", "Telegram.Bot"))

    # Stop after first detection
    for matches, description, signature_base in detections:
        if matches:
            signature = await get_signature(signature_base, **flags)
            logger.critical(f"{description} detected: {file_path} - Matches: {matches}")
            await notify_user_for_web_source(
                file_path=file_path,
                detection_type=signature,
                main_file_path=flags.get('main_file_path')
            )
            return True  # Stop after first detection

    return False  # No detection

# --------------------------------------------------------------------------
# Generalized scan for domains (CSV format with reference support)
async def scan_domain_general(url, file_path, **flags):
    try:
        # Normalize and parse URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            logger.error(f"Invalid URL or domain format: {url}")
            return False

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
            return False

        scanned_domains_general.append(full_domain)
        logger.info(f"Scanning domain: {full_domain}")

        # Helper to check CSV-like data lists
        def is_domain_in_data_general(domain, data_list):
            for entry in data_list:
                if entry.get('address') == domain:
                    return True, entry.get('ref_ids', [])
            return False, []

        # Whitelist checks
        whitelist_data = [
            (whitelist_domains_data, "domain"),
            (whitelist_domains_mail_data, "mail domain"),
            (whitelist_sub_domains_data, "subdomain"),
            (whitelist_mail_sub_domains_data, "mail subdomain")
        ]

        for data_list, whitelist_type in whitelist_data:
            is_whitelisted, ref_ids = is_domain_in_data_general(full_domain, data_list)
            if is_whitelisted:
                ref_strings = get_reference_strings(ref_ids)
                logger.info(f"Domain {full_domain} is whitelisted ({whitelist_type}). References: {ref_strings}")
                return False

        # Threat check configurations
        subdomain_threats = [
            (spam_sub_domains_data, "Spam", "Spam.SubDomain"),
            (mining_sub_domains_data, "Mining", "Mining.SubDomain"),
            (abuse_sub_domains_data, "Abuse", "Abuse.SubDomain"),
            (phishing_sub_domains_data, "Phishing", "Phishing.SubDomain"),
            (malware_mail_sub_domains_data, "Malware.Mail", "Malware.Mail.SubDomain"),
            (malware_sub_domains_data, "Malware", "Malware.SubDomain")
        ]

        main_threats = [
            (spam_domains_data, "Spam", "Spam.Domain"),
            (mining_domains_data, "Mining", "Mining.Domain"),
            (abuse_domains_data, "Abuse", "Abuse.Domain"),
            (phishing_domains_data, "Phishing", "Phishing.Domain"),
            (malware_domains_mail_data, "Malware.Mail", "Malware.Mail.Domain"),
            (malware_domains_data, "Malware", "Malware.Domain")
        ]

        # Check subdomain threats
        if subdomain:
            for data_list, threat_name, signature_suffix in subdomain_threats:
                is_threat, ref_ids = is_domain_in_data_general(full_domain, data_list)
                if is_threat:
                    ref_strings = get_reference_strings(ref_ids)
                    logger.critical(f"{threat_name} subdomain detected: {full_domain} (References: {ref_strings})")
                    await notify_user_for_web_source(domain=full_domain,
                                                     detection_type=signature_suffix,
                                                     file_path=file_path,
                                                     main_file_path=flags.get('main_file_path'))
                    return True

        # Check main domain threats (full domain and main domain)
        for data_list, threat_name, signature_suffix in main_threats:
            is_full_threat, full_ref_ids = is_domain_in_data_general(full_domain, data_list)
            is_main_threat, main_ref_ids = is_domain_in_data_general(main_domain, data_list)

            if is_full_threat or is_main_threat:
                ref_ids = full_ref_ids if is_full_threat else main_ref_ids
                ref_strings = get_reference_strings(ref_ids)
                domain_to_report = full_domain if is_full_threat else main_domain
                logger.critical(f"{threat_name} domain detected: {domain_to_report} (References: {ref_strings})")
                await notify_user_for_web_source(domain=domain_to_report,
                                                 detection_type=signature_suffix,
                                                 file_path=file_path,
                                                 main_file_path=flags.get('main_file_path'))
                return True

        logger.info(f"Domain {full_domain} passed all checks.")
        return False

    except Exception as ex:
        logger.error(f"Error scanning domain {url}: {ex}")
        return False

# --------------------------------------------------------------------------
# Generalized scan for IP addresses (CSV format with reference support)
async def scan_ip_address_general(ip_address, file_path, **flags):
    try:
        # Skip invalid IPs
        if not is_valid_ip(ip_address):
            logger.info(f"Skipping non-valid IP address: {ip_address}")
            return False

        if ip_address in scanned_ipv4_addresses_general or ip_address in scanned_ipv6_addresses_general:
            logger.info(f"IP address {ip_address} has already been scanned.")
            return False

        def is_ip_in_data_general(ip, data_list):
            for entry in data_list:
                if entry.get('address') == ip:
                    return True, entry.get('ref_ids', [])
            return False, []

        # IPv6 processing
        if re.match(IPv6_pattern_standard, ip_address):
            scanned_ipv6_addresses_general.append(ip_address)
            logger.info(f"Scanning IPv6 address: {ip_address}")

            # Whitelist
            is_whitelisted, ref_ids = is_ip_in_data_general(ip_address, ipv6_whitelist_data)
            if is_whitelisted:
                ref_strings = get_reference_strings(ref_ids)
                logger.info(f"IPv6 address {ip_address} is whitelisted. References: {ref_strings}")
                return False

            # Threat checks
            ipv6_threats = [
                (ipv6_addresses_ddos_signatures_data, "DDoS", "DDoS.IPv6"),
                (ipv6_addresses_spam_signatures_data, "Spam", "Spam.IPv6"),
                (ipv6_addresses_signatures_data, "Malware", "Malware.IPv6")
            ]

            for data_list, threat_name, signature_suffix in ipv6_threats:
                is_threat, ref_ids = is_ip_in_data_general(ip_address, data_list)
                if is_threat:
                    ref_strings = get_reference_strings(ref_ids)
                    logger.critical(f"{threat_name} IPv6 address detected: {ip_address} (References: {ref_strings})")
                    await notify_user_for_web_source(ipv6_address=ip_address,
                                                     detection_type=signature_suffix,
                                                     file_path=file_path,
                                                     main_file_path=flags.get('main_file_path'))
                    return True

            logger.info(f"Unknown IPv6 address scanned (no matches): {ip_address}")
            return False

        # IPv4 processing
        elif re.match(IPv4_pattern_standard, ip_address):
            scanned_ipv4_addresses_general.append(ip_address)
            logger.info(f"Scanning IPv4 address: {ip_address}")

            # Whitelist
            is_whitelisted, ref_ids = is_ip_in_data_general(ip_address, ipv4_whitelist_data)
            if is_whitelisted:
                ref_strings = get_reference_strings(ref_ids)
                logger.info(f"IPv4 address {ip_address} is whitelisted. References: {ref_strings}")
                return False

            # Threat checks
            ipv4_threats = [
                (ipv4_addresses_phishing_active_signatures_data, "PhishingActive", "PhishingActive.IPv4"),
                (ipv4_addresses_ddos_signatures_data, "DDoS", "DDoS.IPv4"),
                (ipv4_addresses_phishing_inactive_signatures_data, "PhishingInactive", "PhishingInactive.IPv4"),
                (ipv4_addresses_bruteforce_signatures_data, "BruteForce", "BruteForce.IPv4"),
                (ipv4_addresses_spam_signatures_data, "Spam", "Spam.IPv4"),
                (ipv4_addresses_signatures_data, "Malware", "Malware.IPv4")
            ]

            for data_list, threat_name, signature_suffix in ipv4_threats:
                is_threat, ref_ids = is_ip_in_data_general(ip_address, data_list)
                if is_threat:
                    ref_strings = get_reference_strings(ref_ids)
                    logger.critical(f"{threat_name} IPv4 address detected: {ip_address} (References: {ref_strings})")
                    await notify_user_for_web_source(ipv4_address=ip_address,
                                                     detection_type=signature_suffix,
                                                     file_path=file_path,
                                                     main_file_path=flags.get('main_file_path'))
                    return True

            logger.info(f"Unknown IPv4 address scanned (no matches): {ip_address}")
            return False

        else:
            logger.debug(f"Invalid IP address format detected: {ip_address}")
            return False

    except Exception as ex:
        logger.error(f"Error scanning IP address {ip_address}: {ex}")
        return False

async def _extract_and_verify_emails(text: str) -> tuple[List[str], List[str]]:
    """
    Returns (valid_emails, invalid_emails) found in text.
    Strips surrounding punctuation commonly attached to emails in plain text.
    """
    candidates = [m.group(0) for m in EMAIL_RE.finditer(text)]
    cleaned = [c.strip("()[]<>'\".,;:") for c in candidates]
    valid: List[str] = []
    invalid: List[str] = []
    for e in cleaned:
        if EMAIL_FULLMATCH_RE.fullmatch(e):
            valid.append(e)
        else:
            invalid.append(e)
    return valid, invalid

# --------------------------------------------------------------------------
# Spam Email 365 Scanner (updated)
async def scan_spam_email_365_general(email_content, file_path, *, treat_invalid_email_as_spam=True, **flags):
    """
    Scans email content for spam keywords from StopForum Spam Database and
    verifies extracted email addresses with EMAIL_RE.
    If `treat_invalid_email_as_spam` is True, finding invalid email-like tokens
    will cause the function to treat the message as suspicious.
    """
    try:
        if not email_content:
            logger.info("No email content provided for spam scanning.")
            return False

        # normalize for keyword scanning
        email_content_lower = email_content.lower()
        detected_spam_words = [word for word in spam_email_365_data if word.lower() in email_content_lower]

        # extract & verify emails
        valid_emails, invalid_emails = await _extract_and_verify_emails(email_content)

        # Log email verification result (useful for debugging/analysis)
        if valid_emails:
            logger.debug(f"Found valid emails: {valid_emails[:5]}")
        if invalid_emails:
            logger.warning(f"Found invalid/odd email-like tokens: {invalid_emails[:5]}")

        # Decide whether this counts as spam
        flagged = False
        reasons = []

        if detected_spam_words:
            flagged = True
            reasons.append(f"Spam words ({len(detected_spam_words)})")

        if treat_invalid_email_as_spam and invalid_emails:
            flagged = True
            reasons.append(f"Invalid emails ({len(invalid_emails)})")

        if flagged:
            # include up to 5 items from each category in logs/notification
            details = []
            if detected_spam_words:
                details.append(f"spam_words: {', '.join(detected_spam_words[:5])}")
            if invalid_emails:
                details.append(f"invalid_emails: {', '.join(invalid_emails[:5])}")
            logger.critical(f"Spam email detected! Reasons: {', '.join(reasons)}. Details: {' | '.join(details)}")
            await notify_user_for_web_source(
                domain="EmailContent",
                detection_type="Spam.Email365d",
                file_path=file_path,
                main_file_path=flags.get('main_file_path')
            )
            return True

        logger.info("Email content passed spam check - no spam indicators found.")
        return False

    except Exception as ex:
        logger.error(f"Error scanning email content for spam: {ex}", exc_info=True)
        return False

# --------------------------------------------------------------------------
# Generalized scan for URLs
async def scan_url_general(url, file_path, **flags):
    try:
        if url in scanned_urls_general:
            logger.info(f"URL {url} has already been scanned.")
            return False

        scanned_urls_general.append(url)
        logger.info(f"Scanning URL: {url}")

        # Check against URLhaus signatures
        for entry in urlhaus_data:
            # be resilient if entry missing keys
            entry_url = entry.get('url', '')
            if entry_url and entry_url in url:
                message = (f"URL {url} matches the URLhaus signatures.\n"
                           f"ID: {entry.get('id')}, Date Added: {entry.get('dateadded')}\n"
                           f"URL Status: {entry.get('url_status')}, Last Online: {entry.get('last_online')}\n"
                           f"Threat: {entry.get('threat')}, Tags: {entry.get('tags')}\n"
                           f"URLhaus Link: {entry.get('urlhaus_link')}, Reporter: {entry.get('reporter')}")
                logger.critical(message)
                await notify_user_for_web_source(url=url,
                                                 detection_type="URLhaus.Match",
                                                 file_path=file_path,
                                                 main_file_path=flags.get('main_file_path'))
                return True

        # Heuristic check using uBlock Origin style detection
        try:
            if await ublock_detect(url):
                await notify_user_for_web_source(url=url,
                                                 detection_type='HEUR:Phish.Steam.Community.gen',
                                                 file_path=file_path,
                                                 main_file_path=flags.get('main_file_path'))
                logger.critical(f"URL {url} flagged by uBlock detection using HEUR:Phish.Steam.Community.gen.")
                return True
        except Exception as e:
            logger.error(f"Error running ublock_detect on {url}: {e}")

        logger.info(f"No match found for URL: {url}")
        return False

    except Exception as ex:
        logger.error(f"Error scanning URL {url}: {ex}")
        return False

def ensure_http_prefix(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        return 'http://' + url
    return url

# a global (or outer-scope) list to collect every saved path
saved_paths = []
saved_pyc_paths = []
deobfuscated_saved_paths = []
deobfuscated_paths_lock = threading.Lock()
path_lists = [saved_paths, deobfuscated_saved_paths, saved_pyc_paths]

def _write_file(path, content):
    """Helper for writing files synchronously"""
    with open(path, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(content)
    
async def fetch_html(url, return_file_path=False):
    """Fetch HTML content from the given URL, always save it, and optionally return the file path."""
    try:
        if not is_valid_ip(url):
            logger.info(f"Invalid or disallowed IP address in URL: {url}")
            return ("", None) if return_file_path else ""

        safe_url = ensure_http_prefix(url)
        
        # Blocking network call'u thread'de çalıştır
        response = await asyncio.to_thread(requests.get, safe_url, timeout=120)
        
        if response.status_code == 200:
            html = response.text
            parsed = urlparse(safe_url)
            fname = Path(parsed.path if parsed.path else "index.html").name or "index.html"
            base_name = Path(fname)
            out_path = get_unique_output_path(Path(html_extracted_dir), base_name)
            
            # File write'ı thread'de çalıştır
            await asyncio.to_thread(_write_file, out_path, html)
            
            logger.info(f"Saved HTML for {safe_url} to {out_path}")
            saved_paths.append(out_path)
            return (html, out_path) if return_file_path else html
        else:
            logger.error(f"Non-OK status {response.status_code} for URL: {safe_url}")
            return ("", None) if return_file_path else ""
    except Exception as e:
        logger.error(f"Error fetching HTML content from {url}: {e}")
        return ("", None) if return_file_path else ""

# --------------------------------------------------------------------------
# HTML Content Scanner (stops after first detection)
def scan_html_content(html_content, html_content_file_path, **flags):
    """
    Scan extracted HTML content for potential threats.
    Stops immediately after the first confirmed detection.
    """
    # MODIFIED: Prioritize main_file_path from flags
    local_flags = dict(flags) if flags else {}
    primary_main_file_path = local_flags.get('main_file_path', html_content_file_path)


    # --- 1. Discord / Telegram check ---
    try:
        if contains_discord_or_telegram_code(html_content, html_content_file_path, main_file_path=primary_main_file_path, **local_flags):
            logger.info(f"Early exit: Discord/Telegram indicator detected in HTML: {html_content_file_path}")
            return True
    except Exception as e:
        logger.error(f"Error scanning HTML for Discord/Telegram: {e}")

    # --- 2. Extract and scan URLs ---
    try:
        urls = set(re.findall(r'https?://[^\s/$.?#]\S*', html_content))
        for url in urls:
            # Scan URL-level indicators
            try:
                if scan_url_general(url, html_content_file_path, main_file_path=primary_main_file_path, **local_flags):
                    logger.info(f"Early exit: Malicious URL detected in HTML: {url}")
                    return True
            except Exception as e:
                logger.error(f"Error in scan_url_general for {url}: {e}")

            try:
                if scan_domain_general(url, html_content_file_path, main_file_path=primary_main_file_path, **local_flags):
                    logger.info(f"Early exit: Malicious domain detected in HTML: {url}")
                    return True
            except Exception as e:
                logger.error(f"Error in scan_domain_general for {url}: {e}")

            try:
                if scan_spam_email_365_general(url, html_content_file_path, main_file_path=primary_main_file_path, **local_flags):
                    logger.info(f"Early exit: Spam/email indicator detected in HTML: {url}")
                    return True
            except Exception as e:
                logger.error(f"Error in scan_spam_email_365_general for {url}: {e}")
    except Exception as e:
        logger.error(f"Error scanning URLs in HTML: {e}")

    # --- 3. Extract and scan IP addresses ---
    ip_patterns = [
        (r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}', 'IPv4'),
        (r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', 'IPv6'),
    ]

    for pattern, ip_type in ip_patterns:
        try:
            ip_addresses = set(re.findall(pattern, html_content))
            for ip in ip_addresses:
                try:
                    if scan_ip_address_general(ip, file_path=html_content_file_path, main_file_path=primary_main_file_path, **local_flags):
                        logger.info(f"Early exit: Malicious {ip_type} detected in HTML: {ip}")
                        return True
                except Exception as e:
                    logger.error(f"Error scanning {ip_type} {ip}: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error applying {ip_type} regex: {e}")

    # --- No detections ---
    return False

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
    domain_pattern = re.compile(
        r'[a-zA-Z0-9-]+(?:\.|\[\.\]|\(\.\)|\{dot\})[a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?'
    )

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

# --------------------------------------------------------------------------
# Main scanner (stops after first detection)
def scan_code_for_links(decompiled_code, file_path, **flags):
    """
    Scan the decompiled code for Discord-related URLs, general URLs, domains,
    IP addresses, and obfuscated URLs. Stops immediately after the first detection.
    Ensures file_path/main_file_path are forwarded to downstream scanners and notifications.
    """
    # MODIFIED: Prioritize main_file_path from flags
    local_flags = dict(flags) if flags else {}
    primary_main_file_path = local_flags.get('main_file_path', file_path)


    # --- 1. Discord / Telegram check ---
    try:
        if contains_discord_or_telegram_code(decompiled_code, file_path, main_file_path=primary_main_file_path, **local_flags):
            logger.info(f"Early exit: Discord/Telegram indicator detected in {file_path}")
            return True  # Stop scanning immediately
    except Exception as e:
        logger.error(f"Error scanning decompiled content for Discord/Telegram: {e}")

    # --- 2. Regular URLs ---
    try:
        url_regex = build_url_regex()
        urls = set(url_regex.findall(decompiled_code))
    except Exception as e:
        logger.error(f"Error building or applying URL regex: {e}")
        urls = set()

    # --- 3. Obfuscated URLs ---
    obfuscated_results = []
    try:
        obfuscated_results = detect_obfuscated_urls(decompiled_code)
        logger.info(f"Found {len(obfuscated_results)} obfuscated URLs/domains")

        for result in obfuscated_results:
            urls.add(result['original'])
            urls.add(result['decoded'])
            logger.info(f"Obfuscated {result['type']}: {result['original']} -> {result['decoded']}")
    except Exception as e:
        logger.error(f"Error detecting obfuscated URLs: {e}")

    # --- 4. Process URLs ---
    processed_urls = 0
    for url in urls:
        if not url or len(url.strip()) < 7:
            continue

        try:
            logger.debug(f"Processing URL: {url}")
            processed_urls += 1

            # Fetch HTML
            html_content, html_content_file_path = fetch_html(url, return_file_path=True)

            # --- Scan fetched HTML ---
            if html_content:
                try:
                    if contains_discord_or_telegram_code(
                        html_content,
                        html_content_file_path,
                        main_file_path=primary_main_file_path,
                        **local_flags
                    ):
                        logger.info(f"Early exit: Discord/Telegram detected in HTML from {url}")
                        return True
                except Exception as e:
                    logger.error(f"Error scanning HTML for Discord/Telegram: {e}")

                try:
                    if scan_html_content(
                        html_content,
                        html_content_file_path,
                        file_path=html_content_file_path,
                        main_file_path=primary_main_file_path,
                        **local_flags
                    ):
                        logger.info(f"Early exit: Malicious indicator detected in HTML content for {url}")
                        return True
                except Exception as e:
                    logger.error(f"Error scanning fetched HTML content: {e}")

            # --- Scan URL/domain ---
            try:
                if scan_url_general(url, file_path=file_path, main_file_path=primary_main_file_path, **local_flags):
                    logger.info(f"Early exit: Malicious URL detected: {url}")
                    return True
            except Exception as e:
                logger.error(f"Error in scan_url_general for {url}: {e}")

            try:
                if scan_domain_general(url, file_path=file_path, main_file_path=primary_main_file_path, **local_flags):
                    logger.info(f"Early exit: Malicious domain detected: {url}")
                    return True
            except Exception as e:
                logger.error(f"Error in scan_domain_general for {url}: {e}")

            try:
                if scan_spam_email_365_general(url, file_path=file_path, main_file_path=primary_main_file_path, **local_flags):
                    logger.info(f"Early exit: Spam/email indicator detected: {url}")
                    return True
            except Exception as e:
                logger.error(f"Error in scan_spam_email_365_general for {url}: {e}")

        except Exception as e:
            logger.error(f"Error processing URL {url}: {e}")
            continue

    logger.info(f"Processed {processed_urls} URLs (including {len(obfuscated_results)} obfuscated)")

    # --- 5. IP scanning ---
    processed_ips = 0
    try:
        ip_patterns = build_ip_patterns()
        for pattern, ip_type in ip_patterns:
            for m in re.finditer(pattern, decompiled_code):
                ip = m.group(0)
                try:
                    if scan_ip_address_general(ip, file_path=file_path, main_file_path=primary_main_file_path, **local_flags):
                        logger.info(f"Early exit: Malicious IP detected: {ip}")
                        return True
                    processed_ips += 1
                except Exception as e:
                    logger.error(f"Error processing IP {ip}: {e}")
                    continue
    except Exception as e:
        logger.error(f"Error building or applying IP patterns: {e}")

    logger.info(f"Processed {processed_ips} IP addresses")

    # --- 6. Save obfuscated summary (if no early exit occurred) ---
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

    # --- No detections triggered early exit ---
    return False

def extract_ascii_strings(data):
    """Extract readable ASCII strings from binary data."""
    return re.findall(r'[ -~]{4,}', data.decode('ascii', errors='ignore'))

def save_extracted_strings(output_filename, extracted_strings):
    """Save extracted ASCII strings to a file."""
    with open(output_filename, 'w', encoding='utf-8') as output_file:
        output_file.writelines(f"{line}\n" for line in extracted_strings)

def extract_with_hydra(pid: str, output_dir: str) -> bool:
    """
    Run HydraDragonDumper (Mega Dumper CLI) to dump suspicious modules from a process PID.

    Args:
        pid: PID of the target process (as string).
        output_dir: Directory where the dumper will place extracted files.

    Returns:
        bool: True if extraction succeeded, False otherwise.
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        # HydraDragonDumper (Mega Dumper CLI) expected arguments:
        #   -pid <PID> -o <output_dir>
        # If the Hydra CLI has different switches, update accordingly.
        subprocess.run(
            [
                hydra_dragon_dumper_path,
                "--pid",
                pid,
                "--output",
                output_dir
            ],
            check=True
        )
        logger.info(f"HydraDragonDumper extraction complete for PID {pid} into {output_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"HydraDragonDumper extraction failed for PID {pid}: {e}")
        return False
    except FileNotFoundError:
        logger.error(f"HydraDragonDumper executable not found at: {hydra_dragon_dumper_path}")
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
        emu_thread = threading.Thread(daemon=True, target=engine.emu)
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
    """Scan a file for malicious activity using machine learning definitions loaded from pickle."""
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

# --------------------------------------------------------------------------
# --- The RealTimeWebProtectionHandler Class ---
# --------------------------------------------------------------------------

class RealTimeWebProtectionHandler:

    def __init__(self):
        self.scanned_domains = []
        self.scanned_ipv4_addresses = []
        self.scanned_ipv6_addresses = []
        self.scanned_urls = []
        self.domain_ip_to_file_map = {}
        self.loop = None

    def set_event_loop(self, loop):
        """Assign the main asyncio event loop."""
        self.loop = loop

    def map_domain_ip_to_file(self, entity):
        return self.domain_ip_to_file_map.get(entity)

    async def handle_detection(self, entity_type, entity_value, detection_type=None):
        """
        Handle a detection event for a given entity (domain, IP, URL).
        Looks up references from global data automatically.
        """
        if not entity_value:
            return

        # Look up ref_ids from global data based on entity_type and entity_value
        ref_ids = []
        reference = ""

        if entity_type == 'domain':
            # Check all domain datasets
            for data_list in [malware_domains_data, malware_domains_mail_data, phishing_domains_data,
                              abuse_domains_data, mining_domains_data, spam_domains_data]:
                for entry in data_list:
                    if entry.get('address') == entity_value:
                        ref_ids = entry.get('ref_ids', [])
                        break
                if ref_ids:
                    break

        elif entity_type == 'subdomain':
            # Check all subdomain datasets
            for data_list in [malware_sub_domains_data, malware_mail_sub_domains_data, phishing_sub_domains_data,
                              abuse_sub_domains_data, mining_sub_domains_data, spam_sub_domains_data]:
                for entry in data_list:
                    if entry.get('address') == entity_value:
                        ref_ids = entry.get('ref_ids', [])
                        break
                if ref_ids:
                    break

        elif entity_type == 'ipv4_address':
            # Check all IPv4 datasets
            for data_list in [ipv4_addresses_signatures_data, ipv4_addresses_spam_signatures_data,
                              ipv4_addresses_bruteforce_signatures_data, ipv4_addresses_phishing_active_signatures_data,
                              ipv4_addresses_phishing_inactive_signatures_data, ipv4_addresses_ddos_signatures_data]:
                for entry in data_list:
                    if entry.get('address') == entity_value:
                        ref_ids = entry.get('ref_ids', [])
                        break
                if ref_ids:
                    break

        elif entity_type == 'ipv6_address':
            # Check all IPv6 datasets
            for data_list in [ipv6_addresses_signatures_data, ipv6_addresses_spam_signatures_data,
                              ipv6_addresses_ddos_signatures_data]:
                for entry in data_list:
                    if entry.get('address') == entity_value:
                        ref_ids = entry.get('ref_ids', [])
                        break
                if ref_ids:
                    break

        elif entity_type == 'url':
            # Check URLhaus
            for entry in urlhaus_data:
                if entry.get('url') == entity_value:
                    # URLhaus uses urlhaus_link as reference, not ref_ids
                    reference = entry.get('urlhaus_link', '')
                    break
            else:
                reference = ""

        # Convert ref_ids to reference strings (except for URLhaus which has direct reference)
        if entity_type != 'url':
            reference = get_reference_strings(ref_ids)

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
            if file_path:
                message = f"{entity_type.capitalize()} {entity_value} {file_path}"
                if detection_type:
                    message = f"{detection_type} {message}"
                if reference:
                    message += f" Reference: {reference}"
                logger.critical(message)

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

            has_data = any(
                notify_info[field] for field in ['domain', 'ipv4_address', 'ipv6_address', 'url', 'file_path']
            )
            if has_data:
                await notify_user_for_web(**notify_info)

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

    async def scan(self, entity_type, entity_value, detection_type=None):
        """
        Unified scan entry-point.
        Dedupe, detect, fetch, extract, and recurse via this one method.
        Uses ReferenceRegistry-aware data structures.
        """
        # 1) classify entity
        if entity_type in ('subdomain', 'domain'):
            kind = 'domain'
        elif entity_type in ('ipv4_address', 'ipv6_address'):
            kind = 'ipv6' if ':' in entity_value else 'ipv4'
        elif entity_type == 'url':
            kind = 'url'
        else:
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
        else:
            if entity_value in self.scanned_urls:
                return
            self.scanned_urls.append(entity_value)

        # 3) detection logic helpers
        def lookup_domain(domain, data_list):
            for entry in data_list:
                if entry.get('address') == domain:
                    return True, entry.get('ref_ids', [])
            return False, []

        def lookup_ip(ip, data_list):
            for entry in data_list:
                if entry.get('address') == ip:
                    return True, entry.get('ref_ids', [])
            return False, []

        # 4) run detection for domains
        if kind == 'domain':
            domain = entity_value.lower()
            if domain.startswith("www."):
                domain = domain[4:]

            parts = domain.split(".")
            main_domain = domain if len(parts) < 3 else ".".join(parts[-2:])

            # Whitelist check
            whitelist_checks = [
                (whitelist_sub_domains_data, "subdomain"),
                (whitelist_mail_sub_domains_data, "mail subdomain"),
                (whitelist_domains_data, "domain"),
                (whitelist_domains_mail_data, "mail domain")
            ]
            for data_list, whitelist_type in whitelist_checks:
                is_whitelisted, ref_ids = lookup_domain(main_domain, data_list)
                if is_whitelisted:
                    ref_strings = get_reference_strings(ref_ids)
                    logger.info(f"Domain {main_domain} is whitelisted ({whitelist_type}). References: {ref_strings}")
                    return

            # Threat checks
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
            for data_list, etype, d_type in threat_checks:
                is_threat, ref_ids = lookup_domain(main_domain, data_list)
                if is_threat:
                    await self.handle_detection(etype, main_domain, d_type)
                    return

            # Fetch HTML and recurse
            html_content = await fetch_html(f"http://{domain}")
            if html_content:
                for ip in self.extract_ip_addresses(html_content):
                    await self.scan('ipv4_address' if '.' in ip else 'ipv6_address', ip)
                for url in self.extract_urls(html_content):
                    await self.scan('url', url)
                for dom in self.extract_domains(html_content):
                    await self.scan('domain', dom)

        # 5) detection for IP addresses
        elif kind in ('ipv4', 'ipv6'):
            ip_address = entity_value
            if not is_valid_ip(ip_address):
                logger.info(f"Skipping non-valid IP: {ip_address}")
                return

            if kind == 'ipv6':
                logger.info(f"Scanning IPv6 address: {ip_address}")
                # Whitelist
                is_whitelisted, ref_ids = lookup_ip(ip_address, ipv6_whitelist_data)
                if is_whitelisted:
                    ref_strings = get_reference_strings(ref_ids)
                    logger.info(f"IPv6 {ip_address} is whitelisted. References: {ref_strings}")
                    return
                # Threats
                ipv6_threats = [
                    (ipv6_addresses_ddos_signatures_data, 'DDOS'),
                    (ipv6_addresses_spam_signatures_data, 'SPAM'),
                    (ipv6_addresses_signatures_data, 'MALWARE')
                ]
                for data_list, d_type in ipv6_threats:
                    is_threat, ref_ids = lookup_ip(ip_address, data_list)
                    if is_threat:
                        await self.handle_detection('ipv6_address', ip_address, d_type)
                        return
                logger.info(f"Unknown IPv6 address detected: {ip_address}")
            else:
                logger.info(f"Scanning IPv4 address: {ip_address}")
                is_whitelisted, ref_ids = lookup_ip(ip_address, ipv4_whitelist_data)
                if is_whitelisted:
                    ref_strings = get_reference_strings(ref_ids)
                    logger.info(f"IPv4 {ip_address} is whitelisted. References: {ref_strings}")
                    return
                ipv4_threats = [
                    (ipv4_addresses_phishing_active_signatures_data, 'PHISHING_ACTIVE'),
                    (ipv4_addresses_phishing_inactive_signatures_data, 'PHISHING_INACTIVE'),
                    (ipv4_addresses_bruteforce_signatures_data, 'BRUTEFORCE'),
                    (ipv4_addresses_spam_signatures_data, 'SPAM'),
                    (ipv4_addresses_signatures_data, 'MALWARE')
                ]
                for data_list, d_type in ipv4_threats:
                    is_threat, ref_ids = lookup_ip(ip_address, data_list)
                    if is_threat:
                        await self.handle_detection('ipv4_address', ip_address, d_type)
                        return
                logger.info(f"Unknown IPv4 address detected: {ip_address}")

            # Fetch HTML and recurse
            html_content = await fetch_html(f"http://{ip_address}")
            if html_content:
                for dom in self.extract_domains(html_content):
                    await self.scan('domain', dom)
                for url in self.extract_urls(html_content):
                    await self.scan('url', url)

        # 6) detection for URLs
        elif kind == 'url':
            url = entity_value
            html_content = await fetch_html(url)
            if html_content:
                for ip in self.extract_ip_addresses(html_content):
                    await self.scan('ipv4_address' if '.' in ip else 'ipv6_address', ip)
                for dom in self.extract_domains(html_content):
                    await self.scan('domain', dom)
                for u in self.extract_urls(html_content):
                    await self.scan('url', u)

            # Heuristic Discord/Telegram checks (using patterns from file context)
            heuristic_patterns = {
                'HEUR:Discord.Webhook': discord_webhook_pattern_standard,
                'HEUR:Discord.Attachment': discord_attachment_pattern_standard,
                'HEUR:Discord.CanaryWebhook': discord_canary_webhook_pattern_standard,
                'HEUR:Discord.CDNAttachment': cdn_attachment_pattern_standard,
                'HEUR:Telegram.Token': telegram_token_pattern_standard,
            }
            for label, pattern in heuristic_patterns.items():
                if re.search(pattern, url):
                    await self.handle_detection('url', url, label)
                    return

            # URLhaus
            for entry in urlhaus_data:
                if entry.get('url', '') in url:
                    await self.handle_detection('url', url, 'URLhaus Match')
                    return

            # uBlock heuristic
            if await ublock_detect(url):
                await self.handle_detection('url', url, 'HEUR:Phish.Steam.Community.gen')
                return

            logger.info(f"No match found for URL: {url}")

    async def scan_domain(self, domain):
        await self.scan('domain', domain)

    async def scan_ipv4_address(self, ip_address):
        await self.scan('ipv4_address', ip_address)

    async def scan_ipv6_address(self, ip_address):
        await self.scan('ipv6_address', ip_address)

    async def scan_url(self, url):
        await self.scan('url', url)

    async def handle_ipv4(self, packet):
        try:
            if IP in packet:
                if DNS in packet:
                    if packet[DNS].qd:
                        for i in range(packet[DNS].qdcount):
                            qn = packet[DNSQR][i].qname.decode().rstrip('.')
                            await self.scan_domain(qn)
                            logger.info(f"DNS Query (IPv4): {qn}")
                    if packet[DNS].an:
                        for i in range(packet[DNS].ancount):
                            an = packet[DNSRR][i].rrname.decode().rstrip('.')
                            await self.scan_domain(an)
                            logger.info(f"DNS Answer (IPv4): {an}")

                await self.scan_ipv4_address(packet[IP].src)
                await self.scan_ipv4_address(packet[IP].dst)
        except Exception as ex:
            logger.error(f"Error handling IPv4 packet: {ex}")

    async def handle_ipv6(self, packet):
        try:
            if IPv6 in packet:
                if DNS in packet:
                    if packet[DNS].qd:
                        for i in range(packet[DNS].qdcount):
                            qn = packet[DNSQR][i].qname.decode().rstrip('.')
                            await self.scan_domain(qn)
                            logger.info(f"DNS Query (IPv6): {qn}")
                    if packet[DNS].an:
                        for i in range(packet[DNS].ancount):
                            an = packet[DNSRR][i].rrname.decode().rstrip('.')
                            await self.scan_domain(an)
                            logger.info(f"DNS Answer (IPv6): {an}")

                await self.scan_ipv6_address(packet[IPv6].src)
                await self.scan_ipv6_address(packet[IPv6].dst)
            else:
                logger.debug("IPv6 layer not found in the packet.")
        except Exception as ex:
            logger.error(f"Error handling IPv6 packet: {ex}")

    def sync_packet_handler(self, packet):
        """
        Synchronous bridge function to schedule the async handler
        on the main event loop from scapy's thread.
        """
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.on_packet_received(packet), self.loop)
        else:
            logger.warning("Event loop not available for packet handler.")

    async def on_packet_received(self, packet):
        """Async packet processing logic."""
        try:
            if IP in packet:
                await self.handle_ipv4(packet)
                if TCP in packet or UDP in packet:
                    layer = packet.getlayer(TCP) or packet.getlayer(UDP)
                    if layer and hasattr(layer, 'dport'):
                        # Note: This URL logic is simplistic, real HTTP URL extraction is more complex
                        url = f"{packet[IP].src}:{layer.dport}"
                        await self.scan_url(url)

            if IPv6 in packet:
                await self.handle_ipv6(packet)

            # This DNS check might be redundant if already handled in handle_ipv4/ipv6
            # But we keep it as a fallback
            if DNS in packet:
                if packet[DNS].qd:
                    for i in range(packet[DNS].qdcount):
                        qn = packet[DNSQR][i].qname.decode().rstrip('.')
                        await self.scan_domain(qn)
                        logger.info(f"DNS Query: {qn}")
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        an = packet[DNSRR][i].rrname.decode().rstrip('.')
                        await self.scan_domain(an)
                        logger.info(f"DNS Answer: {an}")
                if IP in packet:
                    await self.scan_ipv4_address(packet[IP].src)
                    await self.scan_ipv4_address(packet[IP].dst)
                if IPv6 in packet:
                    await self.scan_ipv6_address(packet[IPv6].src)
                    await self.scan_ipv6_address(packet[IPv6].dst)
        except Exception as ex:
            logger.error(f"Error processing packet: {ex}")

# ========== ASYNC WEB PROTECTION OBSERVER ==========

class RealTimeWebProtectionObserver:
    def __init__(self):
        self.handler = RealTimeWebProtectionHandler()
        self.is_started = False
        self.sniff_task = None

    async def begin_observing_async(self):
        """Async version of begin_observing"""
        if not self.is_started:
            try:
                self.handler.set_event_loop(asyncio.get_event_loop())
            except RuntimeError:
                logger.error("Could not get asyncio event loop. Packet handler will fail.")
                return

            self.sniff_task = asyncio.create_task(self._start_sniffing_async())
            self.is_started = True
            logger.info("Real-time web protection observer started (async)")

    async def _start_sniffing_async(self):
        """Async sniffing wrapper"""
        filter_expression = "(tcp or udp)"
        try:
            # Run scapy's blocking sniff in a thread
            await asyncio.to_thread(
                sniff,
                filter=filter_expression,
                prn=self.handler.sync_packet_handler,
                store=0
            )
        except Exception as ex:
            if "Operation not permitted" in str(ex) or "Socket error" in str(ex):
                logger.error("Sniffing failed: Must be run as root or with network permissions.")
            else:
                logger.error(f"An error occurred while sniffing packets: {ex}")

web_protection_observer = RealTimeWebProtectionObserver()

# Global variables for rules
yarGen_rules = None
icewater_rules = None
valhalla_rules = None
clean_rules = None
yaraxtr_rules = None

def scan_yara(file_path):
    """Scan file with multiple YARA rule sets in parallel using threads.

    Change: when a VMProtect unpacking indicator is matched, we do NOT
    attempt to unpack the PE or write any metadata file. Instead we set
    a boolean flag `is_vmprotect` which is returned as the third
    return value.

    Note: YARA-X scanning is performed sequentially (not in a thread) due to
    Rust thread safety constraints. The yara_x.Scanner and compiled rules
    cannot be safely shared across threads.
    """

    # Shared variables for results
    results = {
        'matched_rules': [],
        'matched_results': [],
        'is_vmprotect': False
    }

    # Lock for thread-safe access to shared variables
    thread_lock_yara = threading.Lock()
    threads = []

    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found during YARA scan: {file_path}")
            return None, None, None

        with open(file_path, 'rb') as yara_file:
            data_content = yara_file.read()

        def extract_match_details(match, rule_source):
            """Robust extraction for yara-python style matches (tuples or objects)."""
            match_info = {
                'rule_name': getattr(match, 'rule', None),
                'rule_source': rule_source,
                'strings': [],
                'tags': getattr(match, 'tags', []),
                'meta': getattr(match, 'meta', {}),
                'namespace': getattr(match, 'namespace', None)
            }

            if not hasattr(match, 'strings'):
                return match_info

            for string_match in match.strings:
                # string_match can be a tuple like (offset, identifier, data)
                # or an object with .identifier and .instances
                string_info = {'identifier': None, 'instances': []}

                if isinstance(string_match, (tuple, list)):
                    # Try to unpack common tuple shapes:
                    # (offset, identifier, data)  OR  (offset, data)
                    if len(string_match) >= 3:
                        offset, identifier, data = string_match[:3]
                    elif len(string_match) == 2:
                        offset, data = string_match
                        identifier = None
                    else:
                        continue

                    matched_data = data if isinstance(data, (bytes, bytearray)) else (
                        data.encode('utf-8', errors='ignore') if isinstance(data, str) else b''
                    )
                    length = len(matched_data)

                    instance_info = {
                        'offset': offset,
                        'length': length,
                        'matched_data': matched_data
                    }
                    try:
                        instance_info['matched_text'] = matched_data.decode('utf-8', errors='ignore')
                    except Exception:
                        instance_info['matched_text'] = None
                    instance_info['matched_hex'] = matched_data.hex()
                    string_info['identifier'] = identifier
                    string_info['instances'].append(instance_info)

                else:
                    # Assume object-like: string_match.identifier and string_match.instances (or .matches)
                    identifier = getattr(string_match, 'identifier', getattr(string_match, 'name', None))
                    instances = getattr(string_match, 'instances', getattr(string_match, 'matches', []))
                    string_info['identifier'] = identifier

                    for inst in instances:
                        # inst can be tuple/list or object
                        if isinstance(inst, (tuple, list)):
                            # common tuple forms: (offset, length, data) or (offset, data)
                            if len(inst) >= 3:
                                off, length, data = inst[:3]
                            elif len(inst) == 2:
                                off, data = inst
                                length = len(data) if isinstance(data, (bytes, bytearray)) else 0
                            else:
                                continue

                            matched_data = data if isinstance(data, (bytes, bytearray)) else (
                                data.encode('utf-8', errors='ignore') if isinstance(data, str) else b''
                            )

                        else:
                            # object: try typical attributes
                            off = getattr(inst, 'offset', getattr(inst, 'start', None))
                            length = getattr(inst, 'length', None)
                            matched_data = getattr(inst, 'data', None) or getattr(inst, 'matched_data', None) or getattr(inst, 'value', None)

                            if matched_data is None and off is not None:
                                # Fall back to slicing the file content if we have offset and length
                                if length is not None:
                                    matched_data = data_content[off: off + length]
                                else:
                                    # No length available - try to take a small slice (best-effort)
                                    matched_data = data_content[off: off + 64]

                            if isinstance(matched_data, str):
                                matched_data = matched_data.encode('utf-8', errors='ignore')

                        length = length if (length is not None) and isinstance(length, int) else (len(matched_data) if matched_data is not None else 0)
                        instance_info = {
                            'offset': off,
                            'length': length,
                            'matched_data': matched_data or b''
                        }
                        try:
                            instance_info['matched_text'] = instance_info['matched_data'].decode('utf-8', errors='ignore')
                        except Exception:
                            instance_info['matched_text'] = None
                        instance_info['matched_hex'] = (instance_info['matched_data'] or b'').hex()
                        string_info['instances'].append(instance_info)

                match_info['strings'].append(string_info)

            return match_info


        def extract_yarax_match_details(rule, rule_source):
            """Robust extraction for YARA-X style rule/pattern matches."""
            match_info = {
                'rule_name': getattr(rule, 'identifier', None),
                'rule_source': rule_source,
                'strings': [],
                'tags': list(rule.tags) if hasattr(rule, 'tags') else [],
                'meta': dict(rule.metadata) if hasattr(rule, 'metadata') else {},
                'namespace': getattr(rule, 'namespace', None)
            }

            # Patterns may be an iterable; each pattern may expose .identifier and .matches
            if not hasattr(rule, 'patterns'):
                return match_info

            for pattern in rule.patterns:
                string_info = {
                    'identifier': getattr(pattern, 'identifier', getattr(pattern, 'name', None)),
                    'instances': []
                }

                matches_iter = getattr(pattern, 'matches', []) or getattr(pattern, 'instances', [])

                for m in matches_iter:
                    # match object may have .offset and optionally .length or may be a tuple
                    if isinstance(m, (tuple, list)):
                        if len(m) >= 3:
                            offset, length, data = m[:3]
                        elif len(m) == 2:
                            offset, data = m
                            length = len(data) if isinstance(data, (bytes, bytearray)) else 0
                        else:
                            continue

                        matched_data = data if isinstance(data, (bytes, bytearray)) else (
                            data.encode('utf-8', errors='ignore') if isinstance(data, str) else b''
                        )

                    else:
                        offset = getattr(m, 'offset', getattr(m, 'start', None))
                        length = getattr(m, 'length', None)
                        matched_data = getattr(m, 'data', None) or getattr(m, 'matched_data', None) or None

                        if matched_data is None and offset is not None:
                            if length is not None:
                                matched_data = data_content[offset: offset + length]
                            else:
                                matched_data = data_content[offset: offset + 64]

                        if isinstance(matched_data, str):
                            matched_data = matched_data.encode('utf-8', errors='ignore')

                    length = length if (isinstance(length, int) and length >= 0) else (len(matched_data) if matched_data is not None else 0)
                    instance_info = {
                        'offset': offset,
                        'length': length,
                        'matched_data': matched_data or b''
                    }
                    try:
                        instance_info['matched_text'] = instance_info['matched_data'].decode('utf-8', errors='ignore')
                    except Exception:
                        instance_info['matched_text'] = None
                    instance_info['matched_hex'] = (instance_info['matched_data'] or b'').hex()
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
                    local_is_vmprotect = False

                    for match in matches or []:
                        # Detect VMProtect even if excluded
                        if match.rule == "INDICATOR_EXE_Packed_VMProtect":
                            local_is_vmprotect = True

                        if match.rule not in excluded_rules:
                            local_matched_rules.append(match.rule)
                            match_details = extract_match_details(match, 'clean_rules')
                            local_matched_results.append(match_details)

                    # Update shared results
                    with thread_lock_yara:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                        if local_is_vmprotect:
                            results['is_vmprotect'] = True
                else:
                    logger.error("clean_rules is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with clean_rules: {e}")

        # Thread worker for yarGen_rule scanning
        def yargen_rule_worker():
            try:
                if yarGen_rules:
                    matches = yarGen_rules.match(data=data_content)
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
                    with thread_lock_yara:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                else:
                    logger.error("yarGen_rule is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with yarGen_rule: {e}")

        # Thread worker for icewater_rule scanning
        def icewater_rule_worker():
            try:
                if icewater_rules:
                    matches = icewater_rules.match(data=data_content)
                    local_matched_rules = []
                    local_matched_results = []

                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            local_matched_rules.append(match.rule)
                            match_details = extract_match_details(match, 'icewater_rule')
                            local_matched_results.append(match_details)
                        else:
                            logger.info(f"Rule {match.rule} is excluded from icewater_rules.")

                    # Update shared results
                    with thread_lock_yara:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                else:
                    logger.error("icewater_rule is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with icewater_rule: {e}")

        # Thread worker for valhalla_rule scanning
        def valhalla_rule_worker():
            try:
                if valhalla_rules:
                    matches = valhalla_rules.match(data=data_content)
                    local_matched_rules = []
                    local_matched_results = []

                    for match in matches or []:
                        if match.rule not in excluded_rules:
                            local_matched_rules.append(match.rule)
                            match_details = extract_match_details(match, 'valhalla_rule')
                            local_matched_results.append(match_details)
                        else:
                            logger.info(f"Rule {match.rule} is excluded from valhalla_rules.")

                    # Update shared results
                    with thread_lock_yara:
                        results['matched_rules'].extend(local_matched_rules)
                        results['matched_results'].extend(local_matched_results)
                else:
                    logger.error("valhalla_rule is not defined.")
            except Exception as e:
                logger.error(f"Error scanning with valhalla_rule: {e}")

        # Create and start threads for yara-python rules ONLY
        # YARA-X is NOT included in threading
        workers = [
            clean_rules_worker,
            yargen_rule_worker,
            icewater_rule_worker,
            valhalla_rule_worker
        ]

        for worker in workers:
            thread = threading.Thread(daemon=True, target=worker)
            thread.start()
            threads.append(thread)

        # Run YARA-X scanning sequentially in the main thread AFTER threads complete
        # This avoids all thread safety issues with Rust-based yara_x objects
        if yaraxtr_rules:
            yaraxtr_scanner = None
            try:
                # create scanner on THIS thread
                yaraxtr_scanner = yara_x.Scanner(rules=yaraxtr_rules)
                scan_results = yaraxtr_scanner.scan(data_content)

                for rule in getattr(scan_results, "matching_rules", []) or []:
                    if rule.identifier not in excluded_rules:
                        results['matched_rules'].append(rule.identifier)
                        match_details = extract_yarax_match_details(rule, 'yaraxtr_rules')
                        results['matched_results'].append(match_details)
                    else:
                        logger.info(f"Rule {rule.identifier} is excluded from yaraxtr_rules.")

            except Exception as e:
                logger.error(f"Error scanning with yaraxtr_rules: {e}")
            finally:
                # IMPORTANT: ensure the Scanner is destroyed on THIS thread.
                # Deleting it and forcing a GC here makes the Rust destructor run on this thread.
                try:
                    if yaraxtr_scanner is not None:
                        del yaraxtr_scanner
                        import gc
                        gc.collect()
                except Exception:
                    logger.exception("Exception during yara_x cleanup")

        # Return results (third value is a boolean `is_vmprotect`)
        return (results['matched_rules'] if results['matched_rules'] else None,
                results['matched_results'] if results['matched_results'] else None,
                results['is_vmprotect'])

    except Exception as ex:
        logger.error(f"An error occurred during YARA scan: {ex}")
        return None, None, None

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
            "no_signature": True
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
            "no_signature": True
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
                "no_signature": True
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

        result = {
            "is_valid": is_valid,
            "status": status,
            "signature_status_issues": signature_status_issues,
            "no_signature": no_sig,
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


# --------------------------------------------------------------------------
# --- NEWLY ADDED ASYNC ARCHIVE/ML FUNCTIONS ---
# --------------------------------------------------------------------------

async def scan_zip_file(file_path):
    """
    Scan a ZIP archive for:
      - RLO in filename warnings (encrypted vs non-encrypted)
      - Size bomb warnings (even if AES encrypted)
      - Single entry text files containing"Password:" (HEUR:Win32.Susp.Encrypted.Zip.SingleEntry)

    Returns:
      (success: bool, payload: str or List)
      - Returns (False, "Clean") when clean
      - Returns (True, "virus_name") when malware detected
      - Returns (True, entries) when suspicious patterns found (for heuristic processing)
    """
    if not pyzipper:
        logger.warning("pyzipper is not installed. Skipping ZIP scan.")
        return False, "Clean"

    try:
        zip_size = os.path.getsize(file_path)
        entries = []
        malware_detected = False

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

                    await notify_user_susp_archive_file_name_warning(file_path, "ZIP", virus)
                    malware_detected = True

                # Record metadata
                entries.append((info.filename, info.file_size, encrypted))

                # Size-bomb check
                if zip_size < 20 * 1024 * 1024 and info.file_size > 650 * 1024 * 1024:
                    virus = "HEUR:Win32.Susp.Size.Encrypted.ZIP" if encrypted else "HEUR:Win32.Susp.Size.ZIP"
                    await notify_user_size_warning(file_path, "ZIP", virus)
                    malware_detected = True

        # Single-entry password logic
        if len(entries) == 1:
            fname, _, encrypted = entries[0]
            if not encrypted:
                with pyzipper.ZipFile(file_path, 'r') as zf:
                    snippet = zf.open(fname).read(4096)
                decoded = snippet.decode("utf-8", errors="ignore").lower()
                if is_plain_text_file_from_output(snippet) and "pass" in decoded:
                    await notify_user_size_warning(file_path, "ZIP", "HEUR:Win32.Susp.Encrypted.Zip.SingleEntry")
                    malware_detected = True

        # Return based on detection status
        if malware_detected:
            return True, entries
        else:
            return False, "Clean"

    except pyzipper.zipfile.BadZipFile:
        logger.error(f"Not a valid ZIP archive: {file_path}")
        return False, "Clean"
    except Exception as ex:
        logger.error(f"Error scanning zip file: {file_path} {ex}")
        return False, "Clean"


async def scan_7z_file(file_path):
    """
    Scan a 7z archive for:
      - RLO in filename warnings (encrypted vs non-encrypted)
      - Size bomb warnings (even if encrypted)
      - Single entry text files containing"Password:" (HEUR:Win32.Susp.Encrypted.7z.SingleEntry)

    Returns:
      (success: bool, payload: str or List)
      - Returns (False, "Clean") when clean
      - Returns (True, "virus_name") when malware detected
      - Returns (True, entries) when suspicious patterns found (for heuristic processing)
    """
    if not py7zr:
        logger.warning("py7zr is not installed. Skipping 7z scan.")
        return False, "Clean"

    try:
        archive_size = os.path.getsize(file_path)
        entries = []
        malware_detected = False

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

                    await notify_user_susp_archive_file_name_warning(file_path, "7z", virus)
                    malware_detected = True

                # Record metadata
                entries.append((filename, entry.uncompressed, encrypted))

                # Size-bomb check
                if archive_size < 20 * 1024 * 1024 and entry.uncompressed > 650 * 1024 * 1024:
                    virus = "HEUR:Win32.Susp.Size.Encrypted.7z" if encrypted else "HEUR:Win32.Susp.Size.7z"
                    await notify_user_size_warning(file_path, "7z", virus)
                    malware_detected = True

        # Single-entry password logic
        if len(entries) == 1:
            fname, _, encrypted = entries[0]
            if not encrypted:
                with py7zr.SevenZipFile(file_path, mode='r') as archive:
                    data_map = archive.read([fname])
                    snippet = data_map.get(fname, b'')[:4096]
                decoded = snippet.decode("utf-8", errors="ignore").lower()
                if is_plain_text_file_from_output(snippet) and "pass" in decoded:
                    await notify_user_size_warning(file_path, "7z", "HEUR:Win32.Susp.Encrypted.7z.SingleEntry")
                    malware_detected = True

        # Return based on detection status
        if malware_detected:
            return True, entries
        else:
            return False, "Clean"

    except py7zr.exceptions.Bad7zFile:
        logger.error(f"Not a valid 7z archive: {file_path}")
        return False, "Clean"
    except Exception as ex:
        logger.error(f"Error scanning 7z file: {file_path} {ex}")
        return False, "Clean"

async def scan_tar_file(file_path):
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
                    await notify_user_susp_archive_file_name_warning(file_path, "TAR", virus_name)

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
                        await notify_user_size_warning(file_path, "TAR", virus_name)

        return True, []
    except Exception as ex:
        logger.error(f"Error scanning tar file: {file_path} - {ex}")
        return False, ""

async def check_pe_file(file_path, signature_check, file_name):
    """
    Check a PE file for fake system file indicators after signature validation.

    Returns:
        True  -> detection found (e.g., fake system file)
        False -> no detection
    """
    try:
        logger.info(f"File {file_path} is a valid PE file.")

        # Defensive access to signature_check (in case it's missing keys)
        is_valid_sig = bool(signature_check and signature_check.get("is_valid"))

        # Check for fake system files after signature validation
        if file_name in fake_system_files and os.path.abspath(file_path).startswith(system_drive):
            # If signature is not valid, consider it a fake system file
            if not is_valid_sig:
                logger.critical(f"Detected fake system file: {file_path}")
                await notify_user_for_detected_fake_system_file(file_path, file_name, "HEUR:Win32.FakeSystemFile.Dropper.gen")
                return True

        # No detection
        return False

    except Exception as ex:
        logger.error(f"Error checking PE file {file_path}: {ex}")
        return False

def is_zip_file(file_path):
    """
    Return True if file_path is a valid ZIP (AES or standard), False otherwise.
    """
    if not pyzipper:
        return False

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

async def scan_file_ml(
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

        # Unpack only the first 3 values
        is_malicious_ml, malware_definition, benign_score = await scan_file_with_machine_learning_ai(file_path)

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

async def ml_fastpath_should_continue(
    norm_path,
    signature_check,
    pe_file,
    benign_threshold: float = 0.93
) -> bool:
    """
    ML fast-path:
      - Return False => ML marked benign or malicious -> EARLY EXIT (skip heavy scan)
      - Return True  => proceed with full realtime scan
    """
    if not pe_file:
        return True

    try:
        malware_found, virus_name, benign_score = await scan_file_ml(
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

    # ML detected malware -> notify and stop scanning
    if malware_found:
        if isinstance(virus_name, (list, tuple)):
            virus_name = ''.join(virus_name)

        logger.critical("ML detected malware in %s. Virus: %s (stopping full scan)", os.path.basename(norm_path), virus_name)

        # Spawn notification and stop further scanning for this .
        # False return value to actually stop the other scanning threads for this file.
        if virus_name.startswith("PUA."):
            asyncio.create_task(notify_user_pua(norm_path, virus_name, "ML"))
        else:
            asyncio.create_task(notify_user(norm_path, virus_name, "ML"))

        # Tell the caller to stop scanning this file.
        return False

    # Otherwise (ML said Clean or gave no opinion) -> continue to full scan
    return True

# Read the file and store the names in a list (ignoring empty lines)
with open(system_file_names_path, "r") as f:
    fake_system_files = [line.strip() for line in f if line.strip()]

# --- Synchronous helper to run in a thread ---

def _sync_find_files_for_ips(src_ip, dst_ip):
    """
    Synchronous helper to run in a thread.
    Iterates over processes and connections to find associated files.
    """
    if not psutil:
        logger.warning("psutil is not loaded, cannot find files for IPs.")
        return []

    found_files = []
    # Iterate over all running processes
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            # Get network connections for the process
            connections = proc.net_connections()
            if connections:
                for conn in connections:
                    # Check if the remote address matches src_ip or dst_ip
                    if conn.raddr and (conn.raddr.ip == src_ip or conn.raddr.ip == dst_ip):
                        file_path = proc.info.get('exe')
                        if file_path:
                            found_files.append(file_path)
                            # We found a match for this process, break inner loop
                            break
        except psutil.ZombieProcess:
            logger.debug(f"Zombie process encountered: {proc.info.get('pid')}")
        except psutil.NoSuchProcess:
            logger.debug(f"Process no longer exists: {proc.info.get('pid')}")
        except psutil.AccessDenied:
            logger.debug(f"Access denied to process: {proc.info.get('pid')}")
        except Exception as ex:
            # Log other potential errors during connection checking
            logger.error(f"Error processing process {proc.info.get('pid')}: {ex}")

    # Return a list of unique file paths
    return list(set(found_files))


# --- Asynchronous Public Functions ---

async def convert_ip_to_file(src_ip, dst_ip, alert_line, status):
    """
    Convert IP addresses to associated file paths asynchronously.
    This function will log the status and trigger notifications for detected files.
    """
    try:
        # Run the blocking psutil scan in a separate thread
        # asyncio.to_thread is the modern way (Python 3.9+)
        file_paths = await asyncio.to_thread(_sync_find_files_for_ips, src_ip, dst_ip)

        # Iterate over the results and notify
        for file_path in file_paths:
            logger.info(f"Detected file {file_path} associated with IP {src_ip} or {dst_ip}")
            # Only send critical alerts for non-info statuses
            if not status.startswith("Info"):
                logger.critical(
                    f"Detected file {file_path} associated with IP {src_ip} or {dst_ip}. "
                    f"Alert Line: {alert_line}"
                )
                # Await the asynchronous notification
                await notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status)

    except Exception as ex:
        logger.error(f"Unexpected error in convert_ip_to_file: {ex}")

async def process_alert_data(priority, src_ip, dest_ip):
    """Process parsed alert data from EVE JSON format using reference registry"""
    try:
        # Check if the source IP is in the IPv4 or IPv6 whitelist
        if any(entry['address'] == src_ip for entry in ipv4_whitelist_data + ipv6_whitelist_data):
            logger.info(f"Source IP {src_ip} is in the whitelist. Ignoring alert.")
            return False

        # Default threat type
        threat_type = "Unknown Threat Detected"
        ref_ids = []

        # Check IPv4 and IPv6 signature lists
        for dataset, label in [
            (ipv4_addresses_signatures_data, "General Threat (IPv4)"),
            (ipv4_addresses_spam_signatures_data, "Spam"),
            (ipv4_addresses_bruteforce_signatures_data, "Brute Force"),
            (ipv4_addresses_phishing_active_signatures_data, "Active Phishing"),
            (ipv4_addresses_phishing_inactive_signatures_data, "Inactive Phishing"),
            (ipv4_addresses_ddos_signatures_data, "DDoS"),
            (ipv6_addresses_signatures_data, "General Threat (IPv6)"),
            (ipv6_addresses_spam_signatures_data, "Spam"),
            (ipv6_addresses_ddos_signatures_data, "DDoS"),
        ]:
            match = next((entry for entry in dataset if entry['address'] == src_ip), None)
            if match:
                threat_type = label
                ref_ids = match.get('ref_ids', [])
                break

        # Convert reference IDs to human-readable strings for logging
        ref_strings = get_reference_strings(ref_ids)
        ref_str = f" | References: {ref_strings}" if ref_strings else ""

        # Create a formatted line
        formatted_line = f"[Priority: {priority}] {src_ip} -> {dest_ip} | Threat Type: {threat_type}{ref_str}"

        # Handle actions based on priority
        if priority == 1:
            logger.critical(f"Malicious activity detected: {formatted_line}")
            await convert_ip_to_file(src_ip, dest_ip, formatted_line, f"Malicious - {threat_type}")
            return True
        elif priority == 2:
            logger.warning(f"Suspicious activity detected: {formatted_line}")
            await convert_ip_to_file(src_ip, dest_ip, formatted_line, f"Suspicious - {threat_type}")
            return True
        elif priority == 3:
            logger.info(f"Info alert: {formatted_line}")
            await convert_ip_to_file(src_ip, dest_ip, formatted_line, f"Info - {threat_type}")
            return True

        # No match or ignored
        return False

    except Exception as ex:
        logger.error(f"Error processing alert data: {ex}")
        return False

# Dictionary to track running Suricata processes per interface
running_processes = {}

started_interfaces = []  # using list instead of set

def validate_paths():
    for path, desc in [(suricata_exe_path, "Suricata executable"),
                       (suricata_config_path, "Suricata config")]:
        if not os.path.exists(path):
            logger.error(f"{desc} not found at: {path}")
            return False
        if not os.access(path, os.R_OK):
            logger.error(f"{desc} is not readable: {path}")
            return False
    os.makedirs(suricata_log_dir, exist_ok=True)
    if not os.access(suricata_log_dir, os.W_OK):
        logger.error(f"Suricata log directory is not writable: {suricata_log_dir}")
        return False
    return True


# ============================================================================#
# Windows Suricata-compatible interface detection
# ============================================================================#
# And simplify get_suricata_interfaces (no COM init needed):
def get_suricata_interfaces():
    """Return interfaces compatible with Suricata (WinPcap/Npcap format)."""
    # COM should already be initialized by monitor_interfaces()
    w = WMI()
    interfaces = []
    for nic in w.Win32_NetworkAdapter(ConfigurationManagerErrorCode=0):
        if nic.NetEnabled:
            # Build NPF device name
            npf_name = f"\\Device\\NPF_{{{nic.GUID}}}"
            interfaces.append(npf_name)
    return interfaces

# ============================================================================#
# Start Suricata on interface
# ============================================================================#
def start_suricata_on_interface(iface):
    if iface in running_processes:
        return running_processes[iface]  # already running
    cmd = [suricata_exe_path, "-c", suricata_config_path, "-i", iface, "--pcap-file-continuous"]
    logger.info(f"Starting Suricata on interface: {iface}")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    running_processes[iface] = process
    logger.info(f"Suricata PID {process.pid} started for {iface}")
    return process

# ============================================================================#
# Monitor interfaces
# ============================================================================#
def monitor_interfaces():
    global running_processes, started_interfaces
    
    # Initialize COM once for this thread
    pythoncom.CoInitialize()
    
    try:
        while True:
            # Now WMI calls will work
            interfaces = get_suricata_interfaces()

            # Start Suricata for new interfaces
            for iface in interfaces:
                if iface not in started_interfaces:
                    proc = start_suricata_on_interface(iface)
                    started_interfaces.append(iface)

            # Check for stopped processes
            stopped = [iface for iface, proc in running_processes.items() if proc.poll() is not None]
            for iface in stopped:
                logger.warning(f"Suricata process for {iface} stopped unexpectedly")
                del running_processes[iface]
                if iface in started_interfaces:
                    started_interfaces.remove(iface)

            # Remove interfaces that are no longer active
            inactive = [iface for iface in started_interfaces if iface not in interfaces]
            for iface in inactive:
                logger.info(f"Interface {iface} no longer active, stopping Suricata")
                if iface in running_processes:
                    proc = running_processes[iface]
                    if proc:
                        try:
                            proc.terminate()
                        except Exception as e:
                            logger.error(f"Error terminating process for {iface}: {e}")
                    del running_processes[iface]
                started_interfaces.remove(iface)

            time.sleep(1)
            
    except Exception as e:
        logger.error("Monitor interfaces error: %s", e, exc_info=True)
    finally:
        # Clean up COM
        pythoncom.CoUninitialize()s

async def suricata_callback():
    """
    Asynchronously start Suricata interface monitoring.
    Runs monitor_interfaces() in a daemon thread (non-blocking).
    Returns immediately.
    """
    loop = asyncio.get_event_loop()

    try:
        # Validate paths (CPU-bound, run in thread to avoid blocking)
        valid = await loop.run_in_executor(None, validate_paths)
        if not valid:
            logger.error("Suricata paths are invalid. Cannot start.")
            return False

        logger.info("Starting Suricata interface monitor (async-thread)...")

        # Target for background thread
        def monitor_thread_target():
            try:
                monitor_interfaces()  # This is the blocking monitoring function
            except Exception as e:
                logger.error("Suricata monitor thread crashed: %s", e, exc_info=True)

        # Start the monitoring in a daemon thread (fire-and-forget)
        thread = threading.Thread(
            target=monitor_thread_target,
            daemon=True,
            name="SuricataMonitorThread"
        )
        thread.start()

    except Exception as ex:
        logger.error("Unexpected error starting Suricata: %s", ex, exc_info=True)
        return False

    # Immediately return — main thread is not blocked
    return True

# ========== ASYNC SURICATA MONITORING ==========

async def monitor_suricata_log_async():
    """Async monitor for Suricata EVE JSON log file"""
    log_path = eve_log_path

    # Wait for the file to exist
    while not await asyncio.to_thread(os.path.exists, log_path):
        logger.info(f"Waiting for log file to be created: {log_path}")
        await asyncio.sleep(1)

    logger.info(f"Log file found: {log_path}")

    async with aiofiles.open(log_path, 'r') as log_file:
        await log_file.seek(0, os.SEEK_END)  # Move to end
        
        while True:
            try:
                line = await log_file.readline()

                if line.strip():
                    priority, src_ip, dest_ip, signature, category = parse_suricata_alert(line)
                    if priority is not None:
                        full_line = f"[Priority: {priority}] [{category}] {signature} {src_ip} -> {dest_ip}"
                        logger.debug(full_line)
                        await process_alert_data(priority, src_ip, dest_ip)

            except Exception as ex:
                logger.info(f"Error processing line: {ex}")

# ---------------------------
# Helper functions
# ---------------------------
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
        return 0.0, 0.0, 0.0
    mean = sum(entropies) / len(entropies)
    return float(mean), float(min(entropies)), float(max(entropies))

def reloc_summary(relocs):
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

    imports_count = safe_len(entry.get("imports", []))
    exports_count = safe_len(entry.get("exports", []))
    resources_count = safe_len(entry.get("resources", []))
    sections_count = safe_len(entry.get("sections", []))

    overlay = entry.get("overlay", {}) or {}
    overlay_exists = int(bool(overlay.get("exists")))
    overlay_size = to_float(overlay.get("size", 0))

    sec_char = entry.get("section_characteristics", {}) or {}
    sec_entropy_mean, sec_entropy_min, sec_entropy_max = section_entropy_stats(sec_char)

    sec_disasm = entry.get("section_disassembly", {}) or {}
    overall = sec_disasm.get("overall_analysis", {}) or {}
    total_instructions = to_float(overall.get("total_instructions", 0))
    total_adds = to_float(overall.get("add_count", 0))
    total_movs = to_float(overall.get("mov_count", 0))
    is_likely_packed = int(bool(overall.get("is_likely_packed")))

    add_mov_ratio = (total_adds / (total_movs + 1.0)) if (total_movs is not None) else 0.0
    instrs_per_kb = 0.0
    try:
        instrs_per_kb = total_instructions / ((size_of_image / 1024.0) + 1e-6)
    except Exception:
        instrs_per_kb = 0.0

    tls = entry.get("tls_callbacks", {}) or {}
    tls_callbacks_list = tls.get("callbacks", []) if isinstance(tls, dict) else []
    num_tls_callbacks = safe_len(tls_callbacks_list)

    delay_imports_list = entry.get("delay_imports", []) or []
    num_delay_imports = safe_len(delay_imports_list)

    relocs = entry.get("relocations", []) or []
    num_reloc_entries, num_reloc_blocks = reloc_summary(relocs)

    bound_imports = entry.get("bound_imports", []) or []
    num_bound_imports = safe_len(bound_imports)

    debug_entries = entry.get("debug", []) or []
    num_debug_entries = safe_len(debug_entries)
    cert_info = entry.get("certificates", {}) or {}
    cert_size = to_float(cert_info.get("size", 0))

    rich_header = entry.get("rich_header", {}) or {}
    has_rich = int(bool(rich_header))

    numeric = [
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
        float(imports_count),
        float(exports_count),
        float(resources_count),
        float(overlay_exists),
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

# ---------------------------
# Pickle-based loader
# ---------------------------
def load_ml_definitions_pickle(filepath: str) -> bool:
    """
    Load ML definitions from a pickle file.
    Expected format: a dict with keys 'malicious' and 'benign', each containing a list of entries.
    Each entry is a dict compatible with `entry_to_numeric()`.
    """
    global malicious_numeric_features, malicious_file_names, benign_numeric_features, benign_file_names

    if not os.path.exists(filepath):
        logger.error(f"Pickle ML definitions file not found: {filepath}. ML scanning will be disabled.")
        return False

    malicious_numeric_features = []
    malicious_file_names = []
    benign_numeric_features = []
    benign_file_names = []

    try:
        with open(filepath, 'rb') as f:
            data = pickle.load(f)  # Expecting dict: {'malicious': [...], 'benign': [...]}

        # Load malicious entries
        for entry in data.get('malicious', []):
            try:
                numeric, filename = entry_to_numeric(entry)
                malicious_numeric_features.append(numeric)
                malicious_file_names.append(filename)
            except Exception:
                logger.debug("Skipped a malformed malicious entry during pickle loader.", exc_info=True)
                continue

        # Load benign entries
        for entry in data.get('benign', []):
            try:
                numeric, filename = entry_to_numeric(entry)
                benign_numeric_features.append(numeric)
                benign_file_names.append(filename)
            except Exception:
                logger.debug("Skipped a malformed benign entry during pickle loader.", exc_info=True)
                continue

        if malicious_numeric_features:
            vec_len = len(malicious_numeric_features[0])
        elif benign_numeric_features:
            vec_len = len(benign_numeric_features[0])
        else:
            vec_len = 'N/A'

        logger.info(f"[!] Loaded {len(malicious_numeric_features)} malicious and {len(benign_numeric_features)} benign ML definitions (vectors length = {vec_len}).")
        return True

    except Exception as e:
        logger.exception(f"Failed to load ML definitions from pickle: {e}")
        return False

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

def scan_file_real_time_yara(
    file_path: str,
    signature_check: dict
) -> Tuple[bool, str, str, bool]:
    """
    Scan file with YARA only (blocking, no threads).

    Returns: (malware_found: bool, virus_name: str, engine: str, is_vmprotect: bool)
    """
    logger.info(f"Started YARA scanning file: {file_path}")

    sig_valid = bool(signature_check and signature_check.get("is_valid", False))

    try:
        yara_match, yara_result, is_vmprotect = scan_yara(file_path)

        if yara_match and yara_match not in ("Clean", ""):
            if sig_valid:
                yara_match = f"{yara_match}.SIG"
            logger.critical(
                f"Infected file detected (YARA): {file_path} - Virus: {yara_match} - Result: {yara_result}"
            )
            return True, yara_match, "YARA", is_vmprotect
        else:
            logger.info(f"Scanned file with YARA: {file_path} - No viruses detected")
            return False, "Clean", "", is_vmprotect

    except Exception as ex:
        logger.error(f"An error occurred while scanning file with YARA: {file_path}. Error: {ex}")
        return False, "Error", "", False


def scan_file_real_time(
    file_path: str,
    signature_check: dict,
    file_name: str,
    die_output,
    pe_file: bool = False
) -> Tuple[bool, str, str, Optional[bool]]:
    """
    Scan file in real-time using multiple engines in parallel (WITHOUT YARA).
    Stops all workers on first detection.

    Returns: (malware_found: bool, virus_name: str, engine: str)
    """
    logger.info(f"Started scanning file: {file_path}")

    # Shared results and synchronization primitives
    results = {
        'malware_found': False,
        'virus_name': 'Clean',
        'engine': '',
    }
    stop_event = threading.Event()
    thread_lock_real_time = threading.Lock()
    sig_valid = bool(signature_check and signature_check.get("is_valid", False))

    def pe_scan_worker():
        """Worker function for PE file analysis."""
        if stop_event.is_set():
            return False

        try:
            if pe_file:
                match_found = check_pe_file(file_path, signature_check, file_name)
                if match_found:
                    logger.info(f"PE scan worker: detection found for {file_path}")
                    return False
            return True
        except Exception as ex:
            logger.error(f"An error occurred while scanning the file for fake system files and worm analysis: {file_path}. Error: {ex}")
            return False

    def clamav_scan_worker():
        """Worker function for ClamAV scan"""
        if stop_event.is_set():
            return
        try:
            result = scan_file_with_clamav(file_path)
            if result not in ("Clean", "Error"):
                if sig_valid:
                    result = f"{result}.SIG"
                logger.critical(f"Infected file detected (ClamAV): {file_path} - Virus: {result}")

                with thread_lock_real_time:
                    if not results['malware_found']:
                        results['malware_found'] = True
                        results['virus_name'] = result
                        results['engine'] = "ClamAV"
                        stop_event.set()
            else:
                if not stop_event.is_set():
                    logger.info(f"No malware detected by ClamAV in file: {file_path}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning file with ClamAV: {file_path}. Error: {ex}")

    def tar_scan_worker():
        """Worker function for TAR scan"""
        if stop_event.is_set():
            return
        try:
            if tarfile.is_tarfile(file_path):
                scan_result, virus_name = scan_tar_file(file_path)
                if scan_result and virus_name not in ("Clean", "F", "", [], None):
                    virus_str = str(virus_name) if virus_name else "Unknown"
                    if sig_valid:
                        virus_str = f"{virus_str}.SIG"
                    logger.critical(f"Infected file detected (TAR): {file_path} - Virus: {virus_str}")

                    with thread_lock_real_time:
                        if not results['malware_found']:
                            results['malware_found'] = True
                            results['virus_name'] = virus_str
                            results['engine'] = "TAR"
                            stop_event.set()
                else:
                    if not stop_event.is_set():
                        logger.info(f"No malware detected in TAR file: {file_path}")
        except (PermissionError, FileNotFoundError) as ferr:
            logger.error(f"File error occurred while scanning TAR file: {file_path}. Error: {ferr}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning TAR file: {file_path}. Error: {ex}")

    def zip_scan_worker():
        """Worker function for ZIP scan"""
        if stop_event.is_set():
            return
        try:
            if is_zip_file(file_path):
                scan_result, virus_name = scan_zip_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    if sig_valid:
                        virus_name = f"{virus_name}.SIG"
                    logger.critical(f"Infected file detected (ZIP): {file_path} - Virus: {virus_name}")

                    with thread_lock_real_time:
                        if not results['malware_found']:
                            results['malware_found'] = True
                            results['virus_name'] = virus_name
                            results['engine'] = "ZIP"
                            stop_event.set()
                else:
                    if not stop_event.is_set():
                        logger.info(f"No malware detected in ZIP file: {file_path}")
        except (PermissionError, FileNotFoundError) as ferr:
            logger.error(f"File error occurred while scanning ZIP file: {file_path}. Error: {ferr}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning ZIP file: {file_path}. Error: {ex}")

    def sevenz_scan_worker():
        """Worker function for 7z scan"""
        if stop_event.is_set():
            return
        try:
            if is_7z_file_from_output(die_output):
                scan_result, virus_name = scan_7z_file(file_path)
                if scan_result and virus_name not in ("Clean", ""):
                    if sig_valid:
                        virus_name = f"{virus_name}.SIG"
                    logger.critical(f"Infected file detected (7z): {file_path} - Virus: {virus_name}")

                    with thread_lock_real_time:
                        if not results['malware_found']:
                            results['malware_found'] = True
                            results['virus_name'] = virus_name
                            results['engine'] = "7z"
                            stop_event.set()
                else:
                    if not stop_event.is_set():
                        logger.info(f"No malware detected in 7z file: {file_path}")
        except (PermissionError, FileNotFoundError) as ferr:
            logger.error(f"File error occurred while scanning 7Z file: {file_path}. Error: {ferr}")
        except Exception as ex:
            logger.error(f"An error occurred while scanning 7Z file: {file_path}. Error: {ex}")

    try:
        workers = [
            pe_scan_worker,
            clamav_scan_worker,
            tar_scan_worker,
            zip_scan_worker,
            sevenz_scan_worker
        ]

        threads = []
        for worker in workers:
            t = threading.Thread(daemon=True, target=worker)
            t.start()
            threads.append(t)

        with thread_lock_real_time:
            if results['malware_found']:
                return True, results['virus_name'], results['engine']
            else:
                logger.info(f"File is clean - no malware detected by any engine: {file_path}")
                return False, "Clean", ""

    except Exception as ex:
        logger.error(f"An error occurred while scanning file: {file_path}. Error: {ex}")
        return False, "Error", "", False

def get_next_project_name(base_name):
    """Generate the next available project name with an incremental suffix."""
    try:
        suffix = 1
        while f"{base_name}_{suffix}" in existing_projects:
            suffix += 1
        return f"{base_name}_{suffix}"
    except Exception as ex:
        logger.error(f"An error occurred while generating project name: {ex}")

def decompile_file(file_path, main_file_path=None, timeout=1500):
    """
    Run Ghidra analyzeHeadless with DecompileAndSave.java, remember produced artifacts
    for the absolute input path, and return the list of artifact paths.
    """
    try:
        norm_path = os.path.abspath(file_path)
        logger.info(f"Decompiling file: {norm_path} (initiator: {main_file_path})")

        analyze_headless_path = os.path.join(script_dir, 'ghidra', 'support', 'analyzeHeadless.bat')
        project_location = os.path.join(script_dir, 'ghidra_projects')
        os.makedirs(project_location, exist_ok=True)

        # Generate project name
        try:
            project_name = get_next_project_name('temporary')
        except Exception as ex:
            logger.error(f"Failed to generate project name: {ex}")
            with decompile_outputs_lock:
                decompile_outputs[norm_path] = []
            return []

        try:
            existing_projects.append(project_name)
        except Exception:
            pass

        # Prepare command
        command = [
            analyze_headless_path,
            project_location,
            project_name,
            '-import', norm_path,
            '-postScript', 'DecompileAndSave.java',
            '-scriptPath', ghidra_scripts_dir,
            '-log', os.path.join(ghidra_logs_dir, 'analyze.log')
        ]

        start_time = time.time()

        # Run Ghidra headless
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=timeout,
                cwd=script_dir
            )
        except subprocess.TimeoutExpired as te:
            logger.error(f"Ghidra analyzeHeadless timed out for {norm_path}: {te}")
            with decompile_outputs_lock:
                decompile_outputs[norm_path] = []
            return []

        if result.returncode != 0:
            logger.error(f"Decompilation failed for {norm_path}. Return code: {result.returncode}")
            logger.error(f"stderr: {result.stderr}")
            logger.error(f"stdout: {result.stdout}")
            with decompile_outputs_lock:
                decompile_outputs[norm_path] = []
            return []

        logger.info(f"Decompilation completed successfully for: {norm_path}")

        # --- Find candidate artifact files ---
        candidate_roots = [
            os.path.join(script_dir, "decompiled"),
            project_location,
            os.getcwd(),
            ghidra_scripts_dir
        ]
        candidate_roots = list(dict.fromkeys(p for p in candidate_roots if p))  # unique + keep order

        candidates = []
        toler = 5
        for root in candidate_roots:
            if not os.path.exists(root):
                continue
            for r, _, files in os.walk(root):
                for fname in files:
                    full = os.path.join(r, fname)
                    try:
                        mtime = os.path.getmtime(full)
                    except Exception:
                        mtime = 0
                    lname = fname.lower()
                    score = 0
                    if "_analysis" in lname or lname.endswith("_analysis.txt"):
                        score += 200
                    if lname.endswith(('.txt', '.c', '.cpp', '.asm', '.idb', '.bytes', '.json')):
                        score += 50
                    if mtime >= (start_time - toler):
                        score += 100
                    if score > 0:
                        candidates.append((score, mtime, full))

        # Broad fallback: *_analysis*.txt under script_dir
        if not candidates:
            for r, _, files in os.walk(script_dir):
                for fname in files:
                    if "_analysis" in fname.lower() and fname.lower().endswith('.txt'):
                        full = os.path.join(r, fname)
                        try:
                            mtime = os.path.getmtime(full)
                        except Exception:
                            mtime = 0
                        candidates.append((150, mtime, full))

        # Fallback: any recent file under project_location or script_dir
        if not candidates:
            for root in (project_location, script_dir):
                if not os.path.exists(root):
                    continue
                for r, _, files in os.walk(root):
                    for fname in files:
                        full = os.path.join(r, fname)
                        try:
                            mtime = os.path.getmtime(full)
                        except Exception:
                            mtime = 0
                        if mtime >= (start_time - toler):
                            candidates.append((10, mtime, full))

        # Sort and deduplicate
        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
            found_paths = list(dict.fromkeys(path for _, _, path in candidates))
        else:
            found_paths = []

        # Record and return
        with decompile_outputs_lock:
            decompile_outputs[norm_path] = found_paths

        logger.info(f"Decompile artifacts for {norm_path}: {found_paths}")
        return found_paths

    except Exception as ex:
        logger.error(f"An error occurred during decompilation of {file_path}: {ex}")
        try:
            with decompile_outputs_lock:
                decompile_outputs[os.path.abspath(file_path)] = []
        except Exception:
            pass
        return []

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

def clean_text(input_text):
    """
    Remove non-logger.infoable ASCII control characters from the input text.

    :param input_text: The string to clean.
    :return: Cleaned text with control characters removed.
    """
    # Remove non-logger.infoable characters (ASCII 0-31 and 127)
    cleaned_text = re.sub(r'[\x00-\x1F\x7F]+', '', input_text)
    return cleaned_text

def split_source_by_u_delimiter(source_code, base_name="initial_code"):
    """
    Reconstructs source code using 'u'-delimiter splitting.

    Features:
    - Preserves protected fragments (URLs, IPs, Discord/Telegram/webhooks)
    - Splits content on 'u', merging tokens safely
    - Groups into modules by <module ...> markers
  y  - Saves reconstructed modules
    - Creates separate file with extracted links/webhooks/tokens
    """
    logger.info("Reconstructing nuitka source code...")

    # Build regex patterns for URLs and IPs
    url_regex = build_url_regex()
    ip_patterns = build_ip_patterns()

    preserve_patterns = [
        discord_webhook_pattern,
        discord_attachment_pattern,
        discord_canary_webhook_pattern,
        cdn_attachment_pattern,
        telegram_token_pattern,
        telegram_keyword_pattern,
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

    for line in source_code.splitlines():
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
                    i += 2
                else:
                    merged_tokens.append('u')
                    i += 1
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

    # --- STEP 5: Save all reconstructed lines (keep everything) ---
    for name, code_lines in modules:
        cleaned_lines = []
        first_upython_removed = False

        for l in code_lines:
            line_strip = l.strip()
            if line_strip == "upython.exe" and not first_upython_removed:
                first_upython_removed = True
                continue  # still skip the first 'upython.exe' only
            cleaned_lines.append(l)

        save_module_file(name, cleaned_lines)

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

# Async Exela v2 processor — notifier awaited directly (async)
async def process_exela_v2_payload(output_file: str, main_file_path: Optional[str] = None) -> bool:
    """
    Async version of process_exela_v2_payload that awaits notifier(s) directly
    (notify_user_exela_stealer_v2 MUST be async).
    """
    try:
        # Blocking file read -> thread
        def _read_file(path: str) -> str:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()

        content = await asyncio.to_thread(_read_file, output_file)

        # First layer decryption inputs (helpers assumed sync)
        key_line = extract_line(content, "key = ")
        tag_line = extract_line(content, "tag = ")
        nonce_line = extract_line(content, "nonce = ")
        encrypted_data_line = extract_line(content, "encrypted_data")

        key = decode_base64_from_line(key_line)
        tag = decode_base64_from_line(tag_line)
        nonce = decode_base64_from_line(nonce_line)
        encrypted_data = decode_base64_from_line(encrypted_data_line)

        # Decrypt first stage (CPU/blocking) in thread
        intermediate_data = await asyncio.to_thread(DecryptString, key, tag, nonce, encrypted_data)

        saved_temp_file = await asyncio.to_thread(save_to_file, 'intermediate_data.py', intermediate_data)
        if not saved_temp_file:
            logger.error("Failed to save intermediate data.")
            return False

        intermediate_content = await asyncio.to_thread(_read_file, saved_temp_file)

        # Second layer decryption inputs
        key_2 = decode_base64_from_line(extract_line(intermediate_content, "key = "))
        tag_2 = decode_base64_from_line(extract_line(intermediate_content, "tag = "))
        nonce_2 = decode_base64_from_line(extract_line(intermediate_content, "nonce = "))
        encrypted_data_2 = decode_base64_from_line(extract_line(intermediate_content, "encrypted_data"))

        # Decrypt second stage
        final_decrypted_data = await asyncio.to_thread(DecryptString, key_2, tag_2, nonce_2, encrypted_data_2)

        # Save final source
        source_code_path = await asyncio.to_thread(save_to_file, 'exela_stealer_last_stage.py', final_decrypted_data)

        if source_code_path:
            # Append to global list under lock (blocking) in thread
            def _append_deobfuscated(path: str):
                with deobfuscated_paths_lock:
                    deobfuscated_saved_paths.append(path)
            await asyncio.to_thread(_append_deobfuscated, source_code_path)
            logger.info(f"Saved final Exela v2 source to {source_code_path} and appended to deobfuscated_saved_paths.")
        else:
            logger.error("Failed to save the final decrypted source code.")

        # Search for webhook URLs
        webhooks_discord = re.findall(discord_webhook_pattern, final_decrypted_data)
        webhooks_canary = re.findall(discord_canary_webhook_pattern, final_decrypted_data)
        webhooks = webhooks_discord + webhooks_canary

        if webhooks:
            logger.critical(f"[+] Webhook URLs found: {webhooks}")
            if source_code_path:
                # NOTIFIER IS ASYNC — await it directly
                await notify_user_exela_stealer_v2(
                    source_code_path,
                    'HEUR:Win32.Discord.PYC.Python.Exela.Stealer.v2.gen',
                    main_file_path=main_file_path
                )
                return True
            else:
                logger.error("Failed to save the final decrypted source code.")
                return False
        else:
            logger.info("[!] No webhook URLs found in Exela v2 payload.")
            return False

    except Exception as ex:
        logger.error(f"Error during Exela v2 payload processing: {ex}")
        return False

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

def process_pyarmor7(
    target_path: str,
    timeout: int = 600
) -> List[str]:
    """
    Run bypass_pyarmor7.py directly (without Sandboxie) and collect unpacked files.

    - target_path: path to the protected .py / .pyc to unpack.
    - timeout: total seconds to wait for dump to appear and stabilize.

    Returns list of absolute paths to extracted files.
    """
    unpacked_files: List[str] = []

    # Validate bypass helper exists
    if not os.path.isfile(bypass_pyarmor7_path):
        logger.error(f"bypass helper not found: {bypass_pyarmor7_path}")
        return unpacked_files

    # Validate target exists
    if not os.path.exists(target_path):
        logger.error(f"target does not exist: {target_path}")
        return unpacked_files

    # Setup directories
    try:
        extracted_base = Path(pyarmor7_extracted_dir)
        extracted_base.mkdir(parents=True, exist_ok=True)
    except NameError:
        extracted_base = Path("pyarmor7_extracted")
        extracted_base.mkdir(parents=True, exist_ok=True)
        logger.warning(f"pyarmor7_extracted_dir not set, using: {extracted_base}")
    except Exception as e:
        logger.error(f"Could not create extracted dir: {e}")
        return unpacked_files

    # Working directory for helper (where dump/ will be created)
    helper_cwd = os.path.dirname(bypass_pyarmor7_path)
    dump_dir = Path(helper_cwd) / "dump"

    # Target file name
    target_name = os.path.basename(target_path)
    bypass_helper = str(bypass_pyarmor7_path)

    # Build command
    cmd = [
        python_path,
        bypass_helper,
        target_name
    ]

    logger.info(f"Running PyArmor7 bypass helper: {' '.join(cmd)}")
    logger.info(f"Working directory: {helper_cwd}")
    logger.info(f"Expected dump location: {dump_dir}")

    # Run the bypass helper
    try:
        result = subprocess.run(
            cmd,
            cwd=helper_cwd,
            capture_output=True,
            text=True,
            timeout=min(timeout, 120),  # Initial run timeout
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        )

        # Log output
        if result.stdout:
            logger.info(f"Helper stdout:\n{result.stdout}")
        if result.stderr:
            logger.warning(f"Helper stderr:\n{result.stderr}")

        if result.returncode != 0:
            logger.error(f"Helper returned non-zero exit code: {result.returncode}")
            # Continue to check for dumps anyway

    except subprocess.TimeoutExpired:
        logger.warning("Helper process timed out. Proceeding to check for dumps...")
    except Exception as e:
        logger.error(f"Failed to run helper: {e}")
        return unpacked_files

    # Wait for dump directory to stabilize
    deadline = time.monotonic() + timeout
    stable_threshold = 3  # consecutive unchanged checks
    check_interval = 1.0
    last_sizes = {}
    stable_counts = {}

    logger.info("Waiting for dump folder to stabilize...")

    while time.monotonic() < deadline:
        try:
            if dump_dir.exists() and dump_dir.is_dir():
                all_files = list(dump_dir.rglob("*"))

                # Track file sizes
                for p in all_files:
                    if p.is_file():
                        try:
                            size = p.stat().st_size
                        except (FileNotFoundError, OSError):
                            size = -1

                        prev = last_sizes.get(str(p))
                        if prev is None or prev != size:
                            last_sizes[str(p)] = size
                            stable_counts[str(p)] = 0
                        else:
                            stable_counts[str(p)] = stable_counts.get(str(p), 0) + 1

                # Wait if no files yet
                if not all_files:
                    time.sleep(check_interval)
                    continue

                # Check if all files are stable
                if all(stable_counts.get(str(p), 0) >= stable_threshold
                       for p in all_files if p.is_file()):
                    logger.info("Dump directory stabilized, collecting files.")
                    break

            time.sleep(check_interval)

        except Exception as e:
            logger.debug(f"Wait loop exception: {e}")
            time.sleep(check_interval)
    else:
        logger.error("Timed out waiting for dump to stabilize.")
        return unpacked_files

    # Copy files from dump to extracted directory
    try:
        for root, _, files in os.walk(dump_dir):
            rel_root = os.path.relpath(root, dump_dir)
            dest_dir = extracted_base if rel_root in (".", "") else extracted_base / rel_root
            os.makedirs(dest_dir, exist_ok=True)

            for fname in files:
                src = Path(root) / fname
                dest = Path(dest_dir) / fname
                try:
                    shutil.copy2(src, dest)
                    unpacked_files.append(str(dest.resolve()))
                    logger.info(f"Extracted: {dest}")
                except Exception as e:
                    logger.error(f"Failed to copy {src} -> {dest}: {e}")

    except Exception as e:
        logger.error(f"Error copying from dump: {e}")
        return unpacked_files

    # Optional: Clean up dump directory after copying
    try:
        shutil.rmtree(dump_dir)
        logger.info(f"Cleaned up dump directory: {dump_dir}")
    except Exception as e:
        logger.debug(f"Could not clean dump dir: {e}")

    logger.info(f"Completed PyArmor7 unpack for {target_path}; {len(unpacked_files)} files extracted.")
    return unpacked_files

def deobfuscate_file(transformed_path: Path, timeout: int = 600) -> Optional[Path]:
    """
    Run the AST-transformed script directly (no Sandboxie) and wait for it to
    write '<stem>_execs.py'. When the execs file stabilizes, copy it to
    '<stem>_deobf.py' inside `python_deobfuscated_dir`.

    Returns the path to the copied file, or None on failure.
    """
    name = transformed_path.stem
    execs_filename = f"{name}_execs.py"

    # candidate locations where the transformed script might write the execs file
    candidates = [
        transformed_path.parent / execs_filename,        # next to the transformed script
        Path.cwd() / execs_filename,                     # current working directory
        Path(python_deobfuscated_dir) / execs_filename,  # configured output dir (if script writes here)
    ]

    python_exe = str(python_path)
    script_path = str(transformed_path)

    logger.info(f"Running deobfuscator script: {python_exe!r} {script_path!r}")

    try:
        # Run the transformed script directly. Use cwd=transformed_path.parent so relative writes
        # by the script land next to the transformed file (most common behavior).
        subprocess.run(
            [python_exe, script_path],
            check=True,
            timeout=timeout,
            cwd=str(transformed_path.parent),
        )
    except Exception as e:
        logger.error(f"Run failed: {e}")
        return None

    # Real-time file watch loop with stability check
    deadline = time.monotonic() + timeout
    last_size = -1
    stable_count = 0
    found_path: Optional[Path] = None

    while time.monotonic() < deadline:
        for candidate in candidates:
            try:
                if candidate.exists():
                    size = candidate.stat().st_size
                    if size > 0:
                        if candidate == found_path and size == last_size:
                            stable_count += 1
                        else:
                            # new candidate or size changed -> reset stability counters
                            found_path = candidate
                            last_size = size
                            stable_count = 0

                        logger.debug(f"Observed {candidate} size={size} stable_count={stable_count}")

                        if stable_count >= 3:
                            break
                    else:
                        # zero-byte file seen: treat as not-yet-written
                        found_path = None
                        last_size = -1
                        stable_count = 0
            except (FileNotFoundError, OSError):
                # transient filesystem issue; ignore and continue polling
                continue
        else:
            # inner loop did not break -> no candidate stabilized yet
            time.sleep(0.05)
            continue

        # one of the candidates stabilized
        break

    if not found_path or not found_path.exists():
        logger.error("Timed out waiting for execs file to stabilize.")
        return None

    # Copy result to configured output dir as '<stem>_deobf.py'
    host_output_dir = Path(python_deobfuscated_dir)
    host_output_dir.mkdir(parents=True, exist_ok=True)
    host_target = host_output_dir / f"{name}_deobf.py"

    try:
        content = found_path.read_bytes()
        if not content:
            logger.error("Execs file content empty on read, aborting.")
            return None
        host_target.write_bytes(content)
        logger.info(f"Copied execs output: {host_target}")
        return host_target
    except Exception as copy_exc:
        logger.error(f"Failed to copy execs file: {copy_exc}")
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
                                    f"{base_name[:8]}_d{depth}_m.py"
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

                # Stage 4: Direct processing (no sandbox)
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

                    # Otherwise, treat candidate file itself as the processed result
                    result = disk_text
                    result_hash = compute_md5_via_text(result)

                    logger.info(f"Processed candidate: {candidate_path}")

                    # After processing, queue as new "original" (offloaded=False)
                    next_queue.append((depth + 1, "original", False, False, candidate_path))
                    seen_hashes.add(("direct", False, False, result_hash))

                    # If result is clean, prune and save final
                    if not contains_exec_calls(result) and "eval" not in result:
                        final_candidate = get_unique_output_path(
                            Path(python_deobfuscated_dir),
                            f"{base_name[:8]}_final.py"
                        )
                        prune_ifs_and_write(final_candidate, result)
                        logger.info(f"[FINAL_CANDIDATE] Clean code candidate saved: {final_candidate}")
                        return final_candidate

                    continue

                except Exception as e:
                    logger.error(f"Stage4 failed on {candidate_path}: {e}")
                    # mark the content as seen to avoid retrying
                    seen_hashes.add(("direct", False, False, content_hash))
                    continue

            except Exception as e:
                logger.error(f"While processing {candidate_path}: {e}")
                try:
                    bad_hash = compute_md5_via_text(candidate_path.read_text(encoding="utf-8", errors="replace"))
                    seen_hashes.add((stage_tag, cleaned, offloaded, bad_hash))
                except Exception:
                    pass
                continue

        processing_queue = next_queue

    logger.info("No more clean code found; transformations exhausted.")
    return None

def is_pyarmor_content(data: bytes) -> Tuple[bool, str]:
    """
    Inspect raw bytes and decide whether they look like a PyArmor-protected object.

    Returns:
        (is_pyarmor, reason)
        - is_pyarmor: True if it looks like PyArmor / PY00
        - reason: brief text why it matched (or empty if no match)
    """
    if not data or len(data) == 0:
        return False, "empty"

    # Quick `PY00` header check (common for embedded PYZ-style objects / pyc payloads)
    try:
        if data.startswith(b'PY00'):
            return True, 'PY00 header'
    except Exception:
        pass

    # Primary PyArmor marker used by detect_process in your code
    if b'__pyarmor__' in data:
        return True, '__pyarmor__ marker found'

    # Some PyArmor versions embed 'PYARMOR' or 'pyarmor' strings in the header/metadata
    # (case-insensitive check)
    if b'PYARMOR' in data[:4096] or b'pyarmor' in data[:4096]:
        return True, 'PYARMOR marker in header'

    # Last resort: look for the PY00 magic somewhere near the beginning (not only at 0)
    # (helps for files with a short wrapper before the PY00)
    if data[:65536].find(b'PY00') != -1:
        return True, 'PY00 found in first 64KB'

    return False, ''


def is_pyarmor_file(file_path: str, read_bytes: int = 64 * 1024) -> Tuple[bool, str]:
    """
    Check whether a file is PyArmor-protected or contains a PY00 payload.

    Args:
        file_path: path to the file to check
        read_bytes: how many bytes to read from the start (default 64 KiB)

    Returns:
        (is_pyarmor, reason) same as is_pyarmor_content
    """
    if not os.path.isfile(file_path):
        return False, "not a file"

    try:
        with open(file_path, 'rb') as f:
            head = f.read(read_bytes)
    except Exception as e:
        return False, f"read error: {e}"

    return is_pyarmor_content(head)

def process_sourcedefender_payload(output_file):
    """
    Process SourceDefender protected files by attempting to decrypt them.
    Thread-safe appending to deobfuscated_saved_paths is used.
    Returns the path to the decrypted file on success, otherwise None.
    """
    try:
        logger.info(f"[*] Processing SourceDefender file: {output_file}")

        # Get file info (we already know it's SourceDefender, so just get details)
        file_info = get_sourcedefender_info(output_file)
        logger.info(f"[+] SourceDefender file info - Size: {file_info.get('file_size')} bytes, Lines: {file_info.get('line_count')}")

        # Attempt to unprotect the file
        result = unprotect_sourcedefender_file(output_file)

        if result.get('success'):
            output_saved = result.get('output_file')
            version = result.get('version', 'unknown')

            logger.info(f"[+] Successfully decrypted SourceDefender {version} protected file.")
            logger.info(f"[+] Decrypted file saved as: {output_saved}")

            # Thread-safe append to global list
            try:
                with deobfuscated_paths_lock:
                    deobfuscated_saved_paths.append(output_saved)
                logger.info(f"[+] Appended decrypted SourceDefender file to deobfuscated_saved_paths: {output_saved}")
            except NameError:
                # If the lock/list are not defined, fall back to non-locked append but log a warning
                logger.warning("[!] deobfuscated_paths_lock or deobfuscated_saved_paths not found; appending without lock.")
                try:
                    deobfuscated_saved_paths.append(output_saved)
                except Exception as ex:
                    logger.error(f"[!] Failed to append decrypted path to deobfuscated_saved_paths: {ex}")

            # Log SourceDefender decryption success but don't flag as suspicious
            logger.info(f"[+] SourceDefender {version} file successfully decrypted and available for analysis.")

            # Re-process the decrypted file through the main pipeline if desired
            logger.info("[*] Re-analyzing decrypted SourceDefender content...")
            return output_saved

        else:
            logger.error(f"[!] SourceDefender decryption failed: {result.get('error')}")
            return None

    except Exception as ex:
        logger.error(f"[!] Error processing SourceDefender payload: {ex}")
        return None

# Async dispatch/driver — notifier awaited directly (async)
async def process_decompiled_code(output_file: str, main_file_path: Optional[str] = None) -> bool:
    """
    Async version of process_decompiled_code.
    Dispatches payload processing (PyArmor v7, Exela v2, SourceDefender, generic).
    NOTIFIERS MUST BE async (awaited directly).
    """
    try:
        # Check for PyArmor v7 protected files (blocking) in a thread
        is_pa_result = await asyncio.to_thread(is_pyarmor_file, output_file)
        is_pa, pa_reason = is_pa_result if isinstance(is_pa_result, tuple) else (bool(is_pa_result), None)

        if is_pa:
            logger.info(f"[*] Detected PyArmor-protected file ({pa_reason}). Treating as PyArmor v7.")
            unpacked_files = await asyncio.to_thread(process_pyarmor7, output_file)

            if unpacked_files:
                malware_found = False
                for extracted_file in unpacked_files:
                    # Append extracted file to global deobfuscated_saved_paths under lock (thread)
                    def _append_path(p: str):
                        with deobfuscated_paths_lock:
                            deobfuscated_saved_paths.append(p)
                    await asyncio.to_thread(_append_path, extracted_file)
                    logger.info(f"Appended unpacked file to deobfuscated_saved_paths: {extracted_file}")

                    # Recursively process each extracted file
                    try:
                        if await process_decompiled_code(extracted_file, main_file_path=main_file_path):
                            malware_found = True
                    except Exception as ex:
                        logger.error(f"Error while processing extracted file {extracted_file}: {ex}")

                return malware_found
            else:
                logger.warning(f"[*] No files extracted from PyArmor v7 file: {output_file}")
                return False

        # SourceDefender detection (run in thread)
        is_sd = await asyncio.to_thread(is_sourcedefender_file, output_file)
        if is_sd:
            logger.info("[*] Detected SourceDefender protected file.")
            try:
                # process_sourcedefender_payload may be sync or async in your codebase; handle both
                if inspect.iscoroutinefunction(process_sourcedefender_payload):
                    return bool(await process_sourcedefender_payload(output_file, main_file_path=main_file_path))
                else:
                    return bool(await asyncio.to_thread(process_sourcedefender_payload, output_file, main_file_path))
            except Exception as ex:
                logger.error(f"Error processing SourceDefender payload: {ex}")
                return False

        # Read content (blocking) in thread
        def _read_file(path: str) -> str:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()

        content = await asyncio.to_thread(_read_file, output_file)

        # Exela v2 detection
        if await asyncio.to_thread(is_exela_v2_payload, content):
            logger.info("[*] Detected Exela Stealer v2 payload.")
            try:
                # process_exela_v2_payload is async (per earlier change) — await it directly
                return bool(await process_exela_v2_payload(output_file, main_file_path=main_file_path))
            except Exception as ex:
                logger.error(f"Error processing Exela v2 payload: {ex}")
                return False

        # Quick heuristic: if there's no exec() it's likely not obfuscated
        if 'exec(' not in content:
            logger.info(f"[+] No exec() found in {output_file}, probably not obfuscated.")
            return False

        # Generic processing
        logger.info("[*] Detected non-Exela payload. Using generic processing.")
        deobfuscated = await asyncio.to_thread(deobfuscate_until_clean, Path(output_file))
        if deobfuscated:
            # Append deobfuscated path under lock in a thread
            def _append_deob(p: str):
                with deobfuscated_paths_lock:
                    deobfuscated_saved_paths.append(p)
            await asyncio.to_thread(_append_deob, str(deobfuscated))
            logger.info(f"Appended deobfuscated path to deobfuscated_saved_paths: {deobfuscated}")

            # NOTIFIER IS ASYNC — await it directly
            try:
                await notify_user_for_malicious_source_code(
                    str(deobfuscated),
                    "HEUR:Win32.Susp.Src.PYC.Python.Obfuscated.exec.gen",
                    main_file_path=main_file_path
                )
                return True
            except Exception as ex:
                logger.error(f"Error while notifying user about malicious source: {ex}")
                # Even if notification failed, treat the deobfuscated result as a detection
                return True
        else:
            logger.error("[!] Generic deobfuscation failed; skipping scan and notification.")
            return False

    except Exception as ex:
        logger.error(f"[!] Error during payload dispatch: {ex}")
        return False

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

def extract_and_return_pyarmor(file_path: str, runtime_paths: List[str] = None) -> Tuple[List[str], str]:
    """
    Extract PyArmor-protected .pyc files and return decrypted outputs
    using oneshot.shot.run_oneshot_python.

    Args:
        file_path: path to the .pyc file
        runtime_paths: list of runtime paths (e.g. pytransform.dll etc.)

    Returns:
        pyarmor_files: list of paths to all extracted files
        main_decrypted_output: path to the main decrypted file (if any)
    """
    pyarmor_files: List[str] = []
    main_decrypted_output: str = None

    # Ensure output directory exists
    os.makedirs(pyarmor8_and_9_extracted_dir, exist_ok=True)

    # Default runtimes list
    if runtime_paths is None:
        runtime_paths = []

    # Run the oneshot pure-Python decryption
    run_oneshot_python(
        directory=os.path.dirname(file_path),
        runtime_paths=runtime_paths,
        output_dir=pyarmor8_and_9_extracted_dir
    )

    # Collect all decrypted files from pyarmor8_and_9_extracted_dir
    for root, _, files in os.walk(pyarmor8_and_9_extracted_dir):
        for f in files:
            full_path = os.path.join(root, f)
            pyarmor_files.append(full_path)
            if main_decrypted_output is None and f.endswith(".pyc"):
                main_decrypted_output = full_path

    return pyarmor_files, main_decrypted_output

def _try_jadx_decompile(file_path, main_file_path: Optional[str] = None) -> bool:
    """
    Attempt to decompile APK using JADX.
    Returns True if successful, False otherwise.
    """
    try:
        jadx_dir = os.path.join(script_dir, "jadx-1.5.3")
        jadx_bin = os.path.join(jadx_dir, "bin", "jadx")

        # Use .bat for Windows, regular jadx for Unix
        if os.name == 'nt':
            jadx_bin += ".bat"

        if not os.path.exists(jadx_bin):
            logger.warning(f"JADX binary not found at {jadx_bin}")
            return False

        # Find a free output folder number
        jadx_decompiled_dir = os.path.join(script_dir, "jadx_decompiled")
        os.makedirs(jadx_decompiled_dir, exist_ok=True)

        folder_number = 1
        while os.path.exists(os.path.join(jadx_decompiled_dir, str(folder_number))):
            folder_number += 1
        output_dir = os.path.join(jadx_decompiled_dir, str(folder_number))

        # Build the JADX command
        cmd = [
            jadx_bin,
            "-d", output_dir,
            file_path
        ]

        logger.info(f"Running JADX decompilation: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, timeout=300)  # 5 minute timeout
        logger.info(f"APK decompiled with JADX to {output_dir}")

        # Walk and scan generated .java files
        files_scanned = 0
        for root, _, files in os.walk(output_dir):
            for fname in files:
                if fname.endswith(".java"):
                    full_path = os.path.join(root, fname)
                    logger.info(f"Scanning file: {full_path}")
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        scan_code_for_links(content, full_path, androguard_flag=True, main_file_path=main_file_path)
                        files_scanned += 1
                    except Exception as ex:
                        logger.error(f"Error scanning {full_path}: {ex}")

        logger.info(f"JADX: Scanned {files_scanned} files")
        return True

    except subprocess.TimeoutExpired:
        logger.error("JADX decompilation timed out")
        return False
    except subprocess.CalledProcessError as cpe:
        logger.error(f"JADX subprocess failed: {cpe}")
        return False
    except Exception as ex:
        logger.error(f"JADX decompilation error: {ex}")
        return False


def _try_androguard_decompile(file_path, main_file_path: Optional[str] = None) -> bool:
    """
    Attempt to decompile APK using Androguard.
    Returns True if successful, False otherwise.
    """
    try:
        # Find a free output folder number
        folder_number = 1
        while os.path.exists(os.path.join(androguard_dir, str(folder_number))):
            folder_number += 1
        output_dir = os.path.join(androguard_dir, str(folder_number))
        os.makedirs(output_dir, exist_ok=True)

        # Build the command: androguard decompile -o <output_dir> <apk>
        cmd = [
            "androguard",
            "decompile",
            "-o", output_dir,
            file_path
        ]

        logger.info(f"Running Androguard decompilation: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, timeout=300)  # 5 minute timeout
        logger.info(f"APK decompiled with Androguard to {output_dir}")

        # Walk and scan generated .smali or .java files
        files_scanned = 0
        for root, _, files in os.walk(output_dir):
            for fname in files:
                if fname.endswith((".smali", ".java")):
                    full_path = os.path.join(root, fname)
                    logger.info(f"Scanning file: {full_path}")
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        scan_code_for_links(content, full_path, androguard_flag=True, main_file_path=main_file_path)
                        files_scanned += 1
                    except Exception as ex:
                        logger.error(f"Error scanning {full_path}: {ex}")

        logger.info(f"Androguard: Scanned {files_scanned} files")
        return True

    except subprocess.TimeoutExpired:
        logger.error("Androguard decompilation timed out")
        return False
    except subprocess.CalledProcessError as cpe:
        logger.error(f"Androguard subprocess failed: {cpe}")
        return False
    except Exception as ex:
        logger.error(f"Androguard decompilation error: {ex}")
        return False


def decompile_apk_file(file_path, main_file_path: Optional[str] = None):
    """
    Decompile an Android APK using JADX first, falling back to Androguard if needed.
    Scans all decompiled files for URLs, IPs, domains, and Discord webhooks.
    """
    try:
        logger.info(f"Detected APK file: {file_path}")

        # Try JADX first
        success = _try_jadx_decompile(file_path, main_file_path)

        if not success:
            logger.warning("JADX decompilation failed, falling back to Androguard...")
            _try_androguard_decompile(file_path, main_file_path)

    except Exception as ex:
        logger.error(f"Error decompiling APK {file_path}: {ex}")

def decompile_dotnet_file(file_path, main_file_path: Optional[str] = None):
    """
    Decompiles a .NET assembly using ILSpy and scans all decompiled .cs files
    for URLs, IP addresses, domains, and Discord webhooks.

    :param file_path: Path to the .NET assembly file.
    :param main_file_path: The original file path for threat tracing.
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

                        # MODIFIED: Pass main_file_path to the scanner
                        scan_code_for_links(cs_file_content, cs_file_path, dotnet_flag=True, main_file_path=main_file_path)

                    except Exception as ex:
                        logger.error(f"Error scanning .cs file {cs_file_path}: {ex}")

    except Exception as ex:
        logger.error(f"Error decompiling .NET file {file_path}: {ex}")

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
    and scans all extracted files for URLs, IPs, domains, and Discord webhooks
    in separate threads.

    :param file_path: Path to the .asar file
    :return: Path to the extracted folder or None if extraction failed
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

        # Scan all extracted files in separate threads
        for root, _, files in os.walk(asar_output_dir):
            for file in files:
                file_path_full = os.path.join(root, file)
                logger.info(f"Scanning file: {file_path_full}")

                # Run scan_code_for_links in a thread
                threading.Thread(daemon=True,
                    target=lambda fp=file_path_full: scan_code_for_links(fp, asar_flag=True)
                ).start()

        return asar_output_dir  # Return the extracted folder path

    except subprocess.CalledProcessError as ex:
        logger.error(f"asar extraction failed for {file_path}: {ex}")
        return None
    except Exception as ex:
        logger.error(f"Error processing Asar file {file_path}: {ex}")
        return None

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
                    t = threading.Thread(daemon=True, target=_scan_nsi, args=(path,))
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
    The flag_fernflower indicates if a Java class file was detected.

    Returns:
      list[str] | None: List of paths to files in the decompiled output directory, or None on error.
    """
    try:

        # Build the path to fernflower.jar.
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
    The flag_fernflower indicates if the DIE output also detected a Java class file.

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
                    scan_code_for_links(decompiled_code=f, file_path=f, fernflower_flag=True)
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

        # --- Added: scan the first extracted .iss file ---
        if extracted_paths:
            first_file = extracted_paths[0]
            if os.path.splitext(first_file)[1].lower() == ".iss":
                try:
                    with open(first_file, "r", encoding="utf-8", errors="ignore") as f:
                        source_code = f.read()
                    scan_code_for_links(source_code, first_file, inno_setup_flag=True)
                except Exception as ex:
                    logger.error(f"Failed to read/scan .iss file {first_file}: {ex}")

        return extracted_paths

    except Exception as ex:
        logger.error(f"Error extracting Inno Setup file {file_path}: {ex}")
        return None

def decompile_ahk_exe(file_path):
    """
    Decompile an AutoHotkey EXE using pefile.
    Extracts RCData resource to a unique subdirectory under autohotkey_decompiled_dir,
    then scans its source code with scan_code_for_links(autohotkey_flag=True).

    :param file_path: Path to compiled AutoHotkey EXE
    :return: Path to RCData.rc or None if failed
    """
    try:
        if not os.path.isfile(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        # Create a unique subdirectory for this decompile
        folder_number = 1
        while os.path.exists(f"{autohotkey_decompiled_dir}_{folder_number}"):
            folder_number += 1
        output_dir = f"{autohotkey_decompiled_dir}_{folder_number}"
        os.makedirs(output_dir, exist_ok=True)

        rc_output_path = os.path.join(output_dir, "RCData.rc")
        logger.info(f"Starting AHK decompilation: {file_path} -> {output_dir}")

        # Load EXE with pefile
        pe = pefile.PE(file_path)
        resource_extracted = False

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.name and entry.name.decode(errors="ignore") == "RCData":
                    for res in entry.directory.entries:
                        data_rva = res.directory.entries[0].data.struct.OffsetToData
                        size = res.directory.entries[0].data.struct.Size
                        data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                        with open(rc_output_path, "wb") as f:
                            f.write(data)
                        resource_extracted = True
                        logger.info(f"Extracted RCData to {rc_output_path}")
                        break

        if not resource_extracted:
            logger.warning("No RCData resource found in EXE")
            return None

        # Read RCData.rc and scan it
        try:
            with open(rc_output_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            logger.info("Scanning RCData.rc for links")
            scan_code_for_links(source_code, rc_output_path, autohotkey_flag=True)
        except Exception as ex:
            logger.error(f"Failed to read/scan RCData.rc {rc_output_path}: {ex}")

        logger.info("AHK decompilation finished")
        return rc_output_path

    except Exception as ex:
        logger.error(f"Failed to decompile AHK EXE {file_path}: {ex}")
        return None

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
    Runs Themida/WinLicense unpacker directly (no Sandboxie).
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

    cmd = [unpacker, file_path]

    try:
        subprocess.run(cmd, check=True)
        logger.info(f"Unlicense unpacking succeeded for {file_path}")

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
        logger.error(f"Failed to run unlicense on {file_path}: {ex}")
        return None


class VBADeobfuscator:
    """
    Advanced VBA deobfuscator for common obfuscation techniques.
    """

    def __init__(self):
        self.decoded_strings = []

    def deobfuscate(self, vba_code: str) -> Tuple[str, List[Dict]]:
        """
        Deobfuscate VBA code using multiple techniques.

        Args:
            vba_code: Raw VBA source code

        Returns:
            Tuple of (deobfuscated_code, list_of_decoded_strings)
        """
        self.decoded_strings = []
        deobfuscated = vba_code

        # Apply deobfuscation techniques in order
        deobfuscated = self._decode_hex_strings(deobfuscated)
        deobfuscated = self._decode_base64_strings(deobfuscated)
        deobfuscated = self._decode_chr_sequences(deobfuscated)
        deobfuscated = self._decode_strreverse(deobfuscated)
        deobfuscated = self._decode_concatenations(deobfuscated)
        deobfuscated = self._decode_split_strings(deobfuscated)
        deobfuscated = self._decode_replace_functions(deobfuscated)
        deobfuscated = self._decode_ascii_codes(deobfuscated)
        deobfuscated = self._decode_dridex(deobfuscated)

        return deobfuscated, self.decoded_strings

    def _decode_hex_strings(self, code: str) -> str:
        """Decode hex-encoded strings like &H41&H42&H43."""
        pattern = r'(?:&H[0-9A-Fa-f]{2})+(?:&H[0-9A-Fa-f]{2})*'

        def replace_hex(match):
            hex_str = match.group(0)
            hex_values = re.findall(r'&H([0-9A-Fa-f]{2})', hex_str)
            try:
                decoded = ''.join(chr(int(h, 16)) for h in hex_values)
                if decoded.isprintable():
                    self.decoded_strings.append({
                        'type': 'Hex',
                        'encoded': hex_str,
                        'decoded': decoded
                    })
                    return f'"{decoded}"'
            except:
                pass
            return hex_str

        return re.sub(pattern, replace_hex, code)

    def _decode_base64_strings(self, code: str) -> str:
        """Decode Base64 encoded strings."""
        # Look for potential Base64 strings (at least 20 chars, ends with = or not)
        pattern = r'"([A-Za-z0-9+/]{20,}={0,2})"'

        def replace_base64(match):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                if len(decoded) > 3 and decoded.isprintable():
                    self.decoded_strings.append({
                        'type': 'Base64',
                        'encoded': b64_str,
                        'decoded': decoded
                    })
                    return f'"{decoded}"'
            except:
                pass
            return match.group(0)

        return re.sub(pattern, replace_base64, code)

    def _decode_chr_sequences(self, code: str) -> str:
        """Decode Chr() function sequences like Chr(65) & Chr(66) & Chr(67)."""
        pattern = r'Chr[W$]?\s*\(\s*(\d+)\s*\)'

        def replace_chr(match):
            char_code = int(match.group(1))
            try:
                if 0 <= char_code <= 255:
                    char = chr(char_code)
                    return f'"{char}"'
            except:
                pass
            return match.group(0)

        # Replace individual Chr calls
        result = re.sub(pattern, replace_chr, code, flags=re.IGNORECASE)

        # Now collapse concatenated strings
        result = self._collapse_string_concatenations(result)

        return result

    def _decode_strreverse(self, code: str) -> str:
        """Decode StrReverse function calls."""
        pattern = r'StrReverse\s*\(\s*"([^"]+)"\s*\)'

        def replace_strreverse(match):
            original = match.group(1)
            reversed_str = original[::-1]
            self.decoded_strings.append({
                'type': 'StrReverse',
                'encoded': original,
                'decoded': reversed_str
            })
            return f'"{reversed_str}"'

        return re.sub(pattern, replace_strreverse, code, flags=re.IGNORECASE)

    def _decode_concatenations(self, code: str) -> str:
        """Decode simple string concatenations."""
        # Pattern for "str1" & "str2" or "str1" + "str2"
        pattern = r'"([^"]*)"[\s]*[&+][\s]*"([^"]*)"'

        def replace_concat(match):
            return f'"{match.group(1)}{match.group(2)}"'

        # Keep replacing until no more matches
        prev = ""
        while prev != code:
            prev = code
            code = re.sub(pattern, replace_concat, code)

        return code

    def _collapse_string_concatenations(self, code: str) -> str:
        """Collapse multiple concatenated strings into one."""
        pattern = r'"([^"]*)"[\s]*[&+][\s]*"([^"]*)"'

        prev = ""
        while prev != code:
            prev = code
            code = re.sub(pattern, r'"\1\2"', code)

        return code

    def _decode_split_strings(self, code: str) -> str:
        """Decode Split() function usage for obfuscation."""
        pattern = r'Split\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)'

        def replace_split(match):
            string = match.group(1)
            delimiter = match.group(2)
            # Just show what it would produce
            parts = string.split(delimiter)
            if len(parts) > 1:
                self.decoded_strings.append({
                    'type': 'Split',
                    'encoded': f'Split("{string}", "{delimiter}")',
                    'decoded': str(parts)
                })

        re.sub(pattern, replace_split, code, flags=re.IGNORECASE)
        return code

    def _decode_replace_functions(self, code: str) -> str:
        """Decode Replace() function calls."""
        pattern = r'Replace\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\)'

        def replace_func(match):
            original = match.group(1)
            find = match.group(2)
            replace_with = match.group(3)
            result = original.replace(find, replace_with)
            self.decoded_strings.append({
                'type': 'Replace',
                'encoded': f'Replace("{original}", "{find}", "{replace_with}")',
                'decoded': result
            })
            return f'"{result}"'

        return re.sub(pattern, replace_func, code, flags=re.IGNORECASE)

    def _decode_ascii_codes(self, code: str) -> str:
        """Decode arrays of ASCII codes like Array(65, 66, 67)."""
        pattern = r'Array\s*\(\s*((?:\d+\s*,\s*)*\d+)\s*\)'

        def replace_array(match):
            numbers = [int(n.strip()) for n in match.group(1).split(',')]
            try:
                decoded = ''.join(chr(n) for n in numbers if 0 <= n <= 255)
                if decoded.isprintable():
                    self.decoded_strings.append({
                        'type': 'ASCII Array',
                        'encoded': match.group(0),
                        'decoded': decoded
                    })
                    return f'"{decoded}"'
            except:
                pass
            return match.group(0)

        return re.sub(pattern, replace_array, code, flags=re.IGNORECASE)

    def _decode_dridex(self, code: str) -> str:
        """Decode Dridex-style obfuscation (custom encoding)."""
        # Dridex often uses custom character substitution
        # Pattern: look for suspicious character patterns
        pattern = r'"([^"]{10,})"'

        def check_dridex(match):
            encoded = match.group(1)
            # Check if string looks obfuscated (high entropy, unusual chars)
            if self._looks_obfuscated(encoded):
                # Try common Dridex decoding
                decoded = self._try_dridex_decode(encoded)
                if decoded:
                    self.decoded_strings.append({
                        'type': 'Dridex',
                        'encoded': encoded,
                        'decoded': decoded
                    })
                    return f'"{decoded}"'
            return match.group(0)

        return re.sub(pattern, check_dridex, code)

    def _looks_obfuscated(self, s: str) -> bool:
        """Check if string appears to be obfuscated."""
        if len(s) < 10:
            return False

        # High ratio of non-alphanumeric characters
        non_alnum = sum(1 for c in s if not c.isalnum())
        if non_alnum / len(s) > 0.3:
            return True

        # Check for repeating patterns
        if len(set(s)) < len(s) * 0.3:
            return True

        return False

    def _try_dridex_decode(self, s: str) -> Optional[str]:
        """Attempt Dridex decoding algorithm."""
        try:
            # Dridex typically uses XOR with a key
            # Try common keys
            for key in [0x42, 0x55, 0x7A, 0xFF]:
                decoded = ''.join(chr(ord(c) ^ key) for c in s)
                if decoded.isprintable() and ' ' in decoded:
                    return decoded
        except:
            pass
        return None


class OLE2Handler:
    """
    Handler for extracting and processing OLE2/Microsoft Office files
    including VBA macros, embedded objects, and IOCs.
    """

    def __init__(self, script_dir: str):
        """
        Initialize the OLE2 handler.

        Args:
            script_dir: Base script directory (output will be in script_dir/ole2/)
        """
        self.ole2_dir = os.path.join(script_dir, "ole2")
        os.makedirs(self.ole2_dir, exist_ok=True)
        self.deobfuscator = VBADeobfuscator()

    def run_ole_extractor(self, file_path: str) -> Optional[str]:
        """
        Extract VBA macros and other content from OLE2 file.

        Args:
            file_path: Path to the OLE2 file to process

        Returns:
            Path to directory containing extracted content, or None if extraction failed
        """
        try:
            # Create extraction directory
            base_name = Path(file_path).stem
            extract_dir = os.path.join(self.ole2_dir, f"{base_name}_extracted")
            os.makedirs(extract_dir, exist_ok=True)

            # Parse the file
            vbaparser = VBA_Parser(file_path)

            # Get file type
            file_type = self._get_file_type(vbaparser.type)
            logger.info(f"Detected file type: {file_type}")

            # Check for VBA macros
            has_macros = vbaparser.detect_vba_macros()

            if has_macros:
                logger.info(f"VBA Macros detected in {file_path}")

                # Extract macro source code
                macro_count = self._extract_macros(vbaparser, extract_dir)
                logger.info(f"Extracted {macro_count} VBA macro(s)")

                # Analyze macros for suspicious content
                self._analyze_and_save_results(vbaparser, extract_dir)

                # Extract deobfuscated code using oletools
                self._extract_revealed_code(vbaparser, extract_dir)

                # Apply custom advanced deobfuscation
                self._apply_advanced_deobfuscation(extract_dir)
            else:
                logger.info(f"No VBA Macros found in {file_path}")

            # Close parser
            vbaparser.close()

            # Return extraction directory if we extracted anything
            if os.listdir(extract_dir):
                return extract_dir
            else:
                logger.info("No content was extracted")
                return None

        except Exception as e:
            logger.error(f"Error extracting OLE2 content from {file_path}: {e}")
            return None

    def _get_file_type(self, type_constant) -> str:
        """Convert type constant to readable string."""
        type_map = {
            TYPE_OLE: "OLE (MS Office 97-2003)",
            TYPE_OpenXML: "OpenXML (MS Office 2007+)",
            TYPE_Word2003_XML: "Word 2003 XML",
            TYPE_MHTML: "MHTML"
        }
        return type_map.get(type_constant, "Unknown")

    def _extract_macros(self, vbaparser: VBA_Parser, output_dir: str) -> int:
        """
        Extract all VBA macro source code to separate files.

        Returns:
            Number of macros extracted
        """
        macro_count = 0

        for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
            macro_count += 1

            # Create safe filename
            safe_name = sanitize_filename(vba_filename)
            output_file = os.path.join(output_dir, f"macro_{macro_count}_{safe_name}.vba")

            # Save macro with metadata
            with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write(f"' Source File: {filename}\n")
                f.write(f"' OLE Stream: {stream_path}\n")
                f.write(f"' VBA Module: {vba_filename}\n")
                f.write("'" + "="*70 + "\n\n")
                f.write(vba_code)

            logger.info(f"Extracted macro to: {output_file}")

        return macro_count

    def _analyze_and_save_results(self, vbaparser: VBA_Parser, output_dir: str):
        """
        Analyze macros for suspicious patterns and save results.
        """
        try:
            # Analyze macros (include decoded strings)
            results = vbaparser.analyze_macros(show_decoded_strings=True)

            if not results:
                logger.info("No suspicious patterns found")
                return

            # Save analysis results
            analysis_file = os.path.join(output_dir, "analysis_results.txt")

            with open(analysis_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write("VBA MACRO ANALYSIS RESULTS\n")
                f.write("="*70 + "\n\n")

                # Group results by type
                categories = {
                    'AutoExec': [],
                    'Suspicious': [],
                    'IOC': [],
                    'Hex String': [],
                    'Base64 String': [],
                    'Dridex String': [],
                    'VBA obfuscated Strings': []
                }

                for kw_type, keyword, description in results:
                    if kw_type in categories:
                        categories[kw_type].append((keyword, description))

                # Write categorized results
                for category, items in categories.items():
                    if items:
                        f.write(f"\n{category.upper()}\n")
                        f.write("-"*70 + "\n")
                        for keyword, description in items:
                            f.write(f"  Keyword: {keyword}\n")
                            f.write(f"  Description: {description}\n")
                            f.write("\n")

                # Write statistics
                f.write("\n" + "="*70 + "\n")
                f.write("STATISTICS\n")
                f.write("="*70 + "\n")
                f.write(f"AutoExec keywords: {vbaparser.nb_autoexec}\n")
                f.write(f"Suspicious keywords: {vbaparser.nb_suspicious}\n")
                f.write(f"IOCs: {vbaparser.nb_iocs}\n")
                f.write(f"Hex obfuscated strings: {vbaparser.nb_hexstrings}\n")
                f.write(f"Base64 obfuscated strings: {vbaparser.nb_base64strings}\n")
                f.write(f"Dridex obfuscated strings: {vbaparser.nb_dridexstrings}\n")
                f.write(f"VBA obfuscated strings: {vbaparser.nb_vbastrings}\n")

            logger.info(f"Analysis results saved to: {analysis_file}")

            # Log critical findings
            if vbaparser.nb_autoexec > 0:
                logger.warning(f"ALERT: {vbaparser.nb_autoexec} auto-executable macro(s) found!")
            if vbaparser.nb_suspicious > 0:
                logger.warning(f"ALERT: {vbaparser.nb_suspicious} suspicious keyword(s) found!")
            if vbaparser.nb_iocs > 0:
                logger.warning(f"ALERT: {vbaparser.nb_iocs} potential IOC(s) found!")

        except Exception as e:
            logger.error(f"Error analyzing macros: {e}")

    def _extract_revealed_code(self, vbaparser: VBA_Parser, output_dir: str):
        """
        Extract deobfuscated macro code with strings revealed (oletools method).
        """
        try:
            revealed_code = vbaparser.reveal()

            if revealed_code:
                output_file = os.path.join(output_dir, "deobfuscated_oletools.vba")

                with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                    f.write("' DEOBFUSCATED VBA MACRO CODE (oletools)\n")
                    f.write("' (Obfuscated strings replaced with decoded content)\n")
                    f.write("'" + "="*70 + "\n\n")
                    f.write(revealed_code)

                logger.info(f"Deobfuscated code (oletools) saved to: {output_file}")
        except Exception as e:
            logger.error(f"Error extracting revealed code: {e}")

    def _apply_advanced_deobfuscation(self, output_dir: str):
        """
        Apply advanced custom deobfuscation to all extracted macros.
        """
        try:
            # Find all macro files
            macro_files = [f for f in os.listdir(output_dir) if f.startswith('macro_') and f.endswith('.vba')]

            if not macro_files:
                return

            # Create advanced deobfuscation output file
            advanced_output = os.path.join(output_dir, "deobfuscated_advanced.vba")
            decoded_strings_file = os.path.join(output_dir, "decoded_strings.txt")

            all_decoded = []

            with open(advanced_output, 'w', encoding='utf-8', errors='replace') as out_f:
                out_f.write("' ADVANCED DEOBFUSCATED VBA MACRO CODE\n")
                out_f.write("' (Multiple deobfuscation techniques applied)\n")
                out_f.write("'" + "="*70 + "\n\n")

                for macro_file in macro_files:
                    macro_path = os.path.join(output_dir, macro_file)

                    with open(macro_path, 'r', encoding='utf-8', errors='replace') as in_f:
                        vba_code = in_f.read()

                    # Apply deobfuscation
                    deobfuscated, decoded_strings = self.deobfuscator.deobfuscate(vba_code)
                    all_decoded.extend(decoded_strings)

                    out_f.write(f"\n' {'='*70}\n")
                    out_f.write(f"' Source: {macro_file}\n")
                    out_f.write(f"' {'='*70}\n\n")
                    out_f.write(deobfuscated)
                    out_f.write("\n\n")

            logger.info(f"Advanced deobfuscated code saved to: {advanced_output}")

            # Save decoded strings separately
            if all_decoded:
                with open(decoded_strings_file, 'w', encoding='utf-8', errors='replace') as f:
                    f.write("DECODED STRINGS FROM VBA MACROS\n")
                    f.write("="*70 + "\n\n")

                    for item in all_decoded:
                        f.write(f"Type: {item['type']}\n")
                        f.write(f"Encoded: {item['encoded']}\n")
                        f.write(f"Decoded: {item['decoded']}\n")
                        f.write("-"*70 + "\n")

                logger.info(f"Decoded strings saved to: {decoded_strings_file}")
                logger.info(f"Total decoded strings: {len(all_decoded)}")

        except Exception as e:
            logger.error(f"Error in advanced deobfuscation: {e}")

    def extract_iocs(self, analysis_file: str) -> List[Tuple[str, str]]:
        """
        Parse analysis results file to extract IOCs.

        Args:
            analysis_file: Path to analysis results file

        Returns:
            List of tuples (ioc_type, ioc_value)
        """
        iocs = []

        try:
            with open(analysis_file, 'r', encoding='utf-8', errors='replace') as f:
                in_ioc_section = False
                keyword = None

                for line in f:
                    if 'IOC' in line and '-'*50 in line:
                        in_ioc_section = True
                        continue

                    if in_ioc_section:
                        if line.startswith('\n') or '='*50 in line:
                            break

                        if 'Keyword:' in line:
                            keyword = line.split('Keyword:', 1)[1].strip()
                        elif 'Description:' in line and keyword:
                            description = line.split('Description:', 1)[1].strip()
                            iocs.append((description, keyword))
                            keyword = None

        except Exception as e:
            logger.error(f"Error extracting IOCs: {e}")

        return iocs

def is_malicious_file(file_path, size_limit_kb):
    """ Check if the file is less than the given size limit """
    return os.path.getsize(file_path) < size_limit_kb * 1024

def nexe_unpacker(file_path) -> list:
    """
    Unpacks a nexe executable and extracts the embedded JavaScript bundle.
    Returns a list of paths to extracted files.

    :param file_path: Path to the nexe executable
    :return: List of paths to the extracted JavaScript files
    """
    try:
        logger.info(f"Detected nexe executable: {file_path}")

        # Get the base filename without extension for directory naming
        base_filename = os.path.splitext(os.path.basename(file_path))[0]

        # Create a unique numbered subdirectory under nexe_javascript_unpacked_dir
        folder_number = 1
        while os.path.exists(os.path.join(nexe_javascript_unpacked_dir, f"{base_filename}_{folder_number}")):
            folder_number += 1
        js_output_dir = os.path.join(nexe_javascript_unpacked_dir, f"{base_filename}_{folder_number}")
        os.makedirs(js_output_dir, exist_ok=True)

        # Run nexe_unpacker command to extract the JavaScript bundle
        nexe_command = [
            "nexe_unpacker",
            file_path,
            "-o",
            js_output_dir
        ]
        subprocess.run(nexe_command, check=True)
        logger.info(f"nexe JavaScript extracted to {js_output_dir}")

        # Collect all extracted files from the output directory
        extracted_files = []
        for root, dirs, files in os.walk(js_output_dir):
            for file in files:
                extracted_files.append(os.path.join(root, file))

        return extracted_files

    except subprocess.CalledProcessError as ex:
        logger.error(f"nexe_unpacker extraction failed for {file_path}: {ex}")
        return []
    except Exception as ex:
        logger.error(f"Error processing nexe file {file_path}: {ex}")
        return []

async def check_hosts_file_for_blocked_antivirus() -> bool:
    """
    Async version:
    - Offloads blocking file I/O and parsing to a thread.
    - Awaits notify_user_hosts(...) directly (notifier MUST be async).
    - Returns True if any hosts entries were flagged and notifications sent (or attempted).
    """
    try:
        # check existence in a thread to avoid blocking the event loop
        if not await asyncio.to_thread(os.path.exists, hosts_path):
            return False

        # Perform parsing and flagging inside a thread (keeps CPU + I/O off the event loop)
        def _parse_hosts_and_flag() -> dict:
            # Build fast lookup sets/lists
            ipv4_set = set(entry['address'] for entry in ipv4_whitelist_data)
            ipv6_set = set(entry['address'] for entry in ipv6_whitelist_data)
            domain_set = set(entry['address'] for entry in whitelist_domains_data)
            mail_domain_set = set(entry['address'] for entry in whitelist_domains_mail_data)
            subdomain_list = [entry['address'] for entry in whitelist_sub_domains_data]
            mail_subdomain_list = [entry['address'] for entry in whitelist_mail_sub_domains_data]
            antivirus_list = [entry['address'] for entry in antivirus_domains_data]

            # Precompile antivirus regex if present
            if antivirus_list:
                ant_patterns = [r'(?:^|\.)' + re.escape(d) + r'$' for d in antivirus_list]
                antivirus_re_local = re.compile('|'.join(ant_patterns), re.IGNORECASE)
            else:
                antivirus_re_local = None

            flagged_local = {
                'ipv4': set(),
                'ipv6': set(),
                'domain': set(),
                'mail_domain': set(),
                'sub_domain': set(),
                'mail_sub_domain': set(),
                'antivirus': set(),
            }

            with open(hosts_path, 'r', encoding='utf-8') as hf:
                for raw in hf:
                    line = raw.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = re.split(r'\s+', line)
                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    hosts = parts[1:]

                    # IP-based buckets
                    if ip in ipv4_set:
                        flagged_local['ipv4'].update(hosts)
                    if ip in ipv6_set:
                        flagged_local['ipv6'].update(hosts)

                    # Host/domain checks
                    for host in hosts:
                        if host in domain_set:
                            flagged_local['domain'].add(host)
                            continue
                        if host in mail_domain_set:
                            flagged_local['mail_domain'].add(host)
                            continue
                        # subdomain checks
                        if any(host.endswith('.' + d) for d in subdomain_list):
                            flagged_local['sub_domain'].add(host)
                            continue
                        if any(host.endswith('.' + d) for d in mail_subdomain_list):
                            flagged_local['mail_sub_domain'].add(host)
                            continue
                        if antivirus_re_local and antivirus_re_local.search(host):
                            flagged_local['antivirus'].add(host)

            return flagged_local

        flagged = await asyncio.to_thread(_parse_hosts_and_flag)

        # Emit async notifications for each bucket that triggered
        any_flagged = False
        heur_mapping = {
            'ipv4': "HEUR:Win32.Trojan.Hosts.WhiteIP.v4.gen",
            'ipv6': "HEUR:Win32.Trojan.Hosts.WhiteIP.v6.gen",
            'domain': "HEUR:Win32.Trojan.Hosts.WhiteDomain.gen",
            'mail_domain': "HEUR:Win32.Trojan.Hosts.Hijacker.Mail.gen",
            'sub_domain': "HEUR:Win32.Trojan.Hosts.WhiteSubdomain.gen",
            'mail_sub_domain': "HEUR:Win32.Trojan.Hosts.Hijacker.MailSub.gen",
            'antivirus': "HEUR:Win32.Trojan.Hosts.Hijacker.DisableAV.gen"
        }

        for key, heuristic in heur_mapping.items():
            if flagged.get(key):
                any_flagged = True
                details = list(flagged[key])
                try:
                    # notifier is async — await it directly
                    await notify_user_hosts(hosts_path, heuristic, details=details)
                except Exception as ex:
                    # log and continue notifying other buckets
                    logger.error(f"Error notifying for hosts ({key}): {ex}")

        return any_flagged

    except Exception as ex:
        logger.error(f"Error reading hosts file: {ex}")
        return False

def analyze_specific_process(process_name_or_path: str) -> Optional[str]:
    """
    Dump a process using HydraDragonDumper and return a dumped .exe according to:
      1) Any .exe directly in the dump folder (root) -> highest priority.
      2) Otherwise, look inside subfolders whose name contains 'vdump' and return
         a vdump_*.exe if present, else the first .exe in that folder.
      3) Return None if nothing suitable found.

    Does NOT extract strings and does NOT remove dumps.
    """
    try:
        process_name = os.path.basename(process_name_or_path) if os.path.sep in process_name_or_path else process_name_or_path

        # Find matching processes
        matching_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pname = proc.info.get('name')
                if pname and pname.lower() == process_name.lower():
                    matching_processes.append((proc.info['pid'], proc.info.get('exe')))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not matching_processes:
            logger.error(f"No running processes found matching: {process_name}")
            return None

        if len(matching_processes) > 1:
            logger.info(f"Multiple processes found matching {process_name}: {matching_processes}")

        target_pid, target_exe = matching_processes[0]
        logger.info(f"Found target process: {target_exe} (PID: {target_pid})")

        pid_hydra_dir = os.path.join(hydra_dragon_dumper_extracted_dir, f"pid_{target_pid}")
        os.makedirs(pid_hydra_dir, exist_ok=True)

        logger.info(f"Running HydraDragonDumper on process PID: {target_pid}")
        try:
            if not extract_with_hydra(str(target_pid), pid_hydra_dir):
                logger.error(f"HydraDragonDumper extraction failed for PID {target_pid}")
                return None

            logger.info(f"HydraDragonDumper successfully extracted to: {pid_hydra_dir}")

            # 1) Highest priority: any .exe directly in pid_hydra_dir (no subfolders)
            if os.path.exists(pid_hydra_dir):
                for fname in os.listdir(pid_hydra_dir):
                    full_path = os.path.join(pid_hydra_dir, fname)
                    if os.path.isfile(full_path) and fname.lower().endswith('.exe'):
                        logger.info(f"Returning .exe found in root of dump folder: {full_path}")
                        return full_path

            # 2) If none in root, search subfolders that look like 'vdump' (non-recursive)
            if os.path.exists(pid_hydra_dir):
                vdump_dirs = []
                for fname in os.listdir(pid_hydra_dir):
                    sub_path = os.path.join(pid_hydra_dir, fname)
                    if os.path.isdir(sub_path):
                        lname = fname.lower()
                        if 'vdump' in lname:  # includes names like 'vdump', 'vdump_1', 'something_vdump'
                            vdump_dirs.append(sub_path)

                for d in vdump_dirs:
                    try:
                        vdump_pref = None
                        fallback = None
                        for sf in os.listdir(d):
                            sf_full = os.path.join(d, sf)
                            if not os.path.isfile(sf_full):
                                continue
                            sl = sf.lower()
                            if sl.startswith('vdump_') and sl.endswith('.exe'):
                                vdump_pref = sf_full
                                break
                            if fallback is None and sl.endswith('.exe'):
                                fallback = sf_full
                        if vdump_pref:
                            logger.info(f"Returning prioritized vdump exe from {d}: {vdump_pref}")
                            return vdump_pref
                        if fallback:
                            logger.info(f"Returning first .exe from vdump folder {d}: {fallback}")
                            return fallback
                    except Exception as e:
                        logger.error(f"Error scanning vdump folder {d}: {e}")
                        continue

            # 3) Nothing found
            logger.error(f"No dumped executables found for PID {target_pid} in {pid_hydra_dir} or vdump subfolders")
            return None

        except Exception as hydra_ex:
            logger.error(f"Error during HydraDragonDumper extraction for PID {target_pid}: {hydra_ex}")
            return None

    except Exception as overall_ex:
        logger.error(f"Overall error in analyze_specific_process: {overall_ex}")
        return None

# --- Helper function for file reading ---
def _open_and_read_lines_sync(norm_path: str) -> List[str]:
    """Synchronous helper to read file lines for asyncio.to_thread."""
    try:
        with open(norm_path, 'r', encoding='utf-8') as f:
            return f.readlines()
    except Exception as e:
        logger.error(f"Failed to read text lines from {norm_path}: {e}")
        return []

# --- Updated scan_and_warn with main_file_path propagation ---
async def scan_and_warn(file_path,
                  mega_optimization_with_anti_false_positive=True,
                  flag_debloat=False,
                  flag_obfuscar=False,
                  flag_de4dot=False,
                  flag_fernflower=False,
                  nsis_flag=False,
                  flag_confuserex=False,
                  flag_vmprotect=False,
                  main_file_path=None):
    """
    Scans a file for potential issues with comprehensive threading for performance.

    Args:
        main_file_path: Original main file that initiated this scan chain (for tracking)
    """
    try:
        # MODIFIED: Set main_file_path to the current file_path if it's None at the top level
        if main_file_path is None:
            main_file_path = file_path

        # Initialize variables
        is_decompiled = False
        pe_file = False
        signature_check = {
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

        # Check if this hash is already known to be malicious
        with malicious_hashes_lock:
            if md5 in malicious_hashes:
                known_virus_name = malicious_hashes[md5]
                logger.warning(f"File {norm_path} matches known malicious hash: {md5} -> {known_virus_name}")
                await notify_user_duplicate(norm_path, md5, known_virus_name)
                return False  # Skip full scan, we already know it's bad

        # If we've already scanned this exact (path, hash), skip immediately
        key = (norm_path.lower(), md5)
        if key in seen_files:
            return False

        # Mark it seen and proceed
        seen_files.add(key)

        # SNAPSHOT the cache entry _once_ up front:
        initial_md5_in_cache = file_md5_cache.get(norm_path)

        file_name = os.path.basename(norm_path)

        # ========== CRITICAL PATH - NO THREADING (affects return behavior) ==========

        # Get DIE output first (needed for early exit decisions)
        if md5 in die_cache:
            die_output, plain_text_flag = die_cache[md5]
        else:
            die_output, plain_text_flag = get_die_output(norm_path)
            die_cache[md5] = (die_output, plain_text_flag)

        # CRITICAL: Unknown file check that can cause early return - NO THREADING
        if is_file_fully_unknown(die_output):
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

        if norm_path == hosts_path:
            check_hosts_file_for_blocked_antivirus(norm_path)

        file_norm = os.path.normpath(norm_path).lower()

        # --- CHECK IF FILE IS IN STARTUP ---
        if any(file_norm.startswith(os.path.normpath(d).lower()) for d in startup_dirs if d):
            malware_type = None
            if file_norm.endswith('.wll') and pe_file:
                malware_type = "HEUR:Win32.Startup.DLLwithWLL.gen.Malware"
            else:
                ext = Path(file_norm).suffix.lower()
                if ext in script_exts:
                    malware_type = "HEUR:Win32.Startup.Script.gen.Malware"
                elif ext in ('.dll', '.jar', '.msi', '.scr', '.hta'):
                    malware_type = "HEUR:Win32.Startup.Susp.Extension.gen.Malware"

            if malware_type:
                logger.critical(f"Suspicious startup file detected: {file_path} ({malware_type})")
                # MODIFIED: Pass main_file_path to notifier and await it
                await notify_user_startup(file_path, f"Startup malware detected: {file_path}", main_file_path=main_file_path)
                return True

        # --- UEFI detection ---
        try:
            candidate_norm = _norm(norm_path)

            # Check 100 KB group first
            in_100kb_group = any(_norm(p) in candidate_norm for p in (uefi_100kb_paths or []))
            if in_100kb_group and is_malicious_file(norm_path, 100):
                logger.critical(f"UEFI (100kb) suspicious: {norm_path}")
                await notify_user_for_uefi(
                    norm_path,
                    "HEUR:Win32.UEFI.SecureBootRecovery.gen.Malware",
                    main_file_path=main_file_path
                )
                return True  # stop scanning here if detected

            # Check normal UEFI group
            in_uefi_group = any(_norm(p) in candidate_norm for p in (uefi_paths or []))
            if in_uefi_group and is_malicious_file(norm_path, 1024):
                logger.critical(f"UEFI suspicious: {norm_path}")
                await notify_user_for_uefi(
                    norm_path,
                    "HEUR:Win32.UEFI.ScreenLocker.Ransomware.gen.Malware",
                    main_file_path=main_file_path
                )
                return True  # stop scanning here if detected

        except Exception as e:
            logger.debug(f"UEFI detection check failed for {norm_path}: {e}")

        # ========== ASYNC/THREADED OPERATIONS START HERE ==========
        # Now we can safely use threading since no more early returns

        # Shared data for tasks
        thread_results = {
            'signature_check': None,
            'file_lines': [],
            'dotnet_result': None
        }

        async def signature_check_thread():
            """Async Task: Digital signature verification - can be slow"""
            try:
                sig_check = await asyncio.to_thread(check_signature, norm_path)
                with scan_and_warn_lock:
                    thread_results['signature_check'] = sig_check
                logger.debug(f"Signature check completed for {norm_path}")
            except Exception as e:
                logger.error(f"Error in signature check task for {norm_path}: {e}")
                with scan_and_warn_lock:
                    thread_results['signature_check'] = {
                        "has_microsoft_signature": False,
                        "is_valid": False,
                        "signature_status_issues": False
                    }

            # Use the signature_check produced by the task when calling ML fast-path
            sig_for_ml = thread_results.get('signature_check', None)

            # ML fast-path: if returns False -> ML marked benign or malware => EARLY EXIT (do not start realtime thread)
            if not ml_fastpath_should_continue(norm_path, sig_for_ml, pe_file):
                return False

        async def file_reading_thread():
            """Async Task: Reading file content as text"""
            try:
                lines = await asyncio.to_thread(_open_and_read_lines_sync, norm_path)
                with scan_and_warn_lock:
                    thread_results['file_lines'] = lines
            except Exception as e:
                logger.error(f"Failed to read text lines from {norm_path}: {e}")

        # Start background tasks for I/O operations
        signature_task = asyncio.create_task(signature_check_thread())
        file_read_task = asyncio.create_task(file_reading_thread())

        # Path analysis - direct execution (fast)
        wrap_norm_path = Path(norm_path)

        if Path(obfuscar_dir) in wrap_norm_path.parents and not flag_obfuscar:
            flag_obfuscar = True
            logger.info(f"Flag set to True because '{norm_path}' is inside the Obfuscar directory.")

        match = next((Path(p) for p in de4dot_extracted_dir
                     if Path(p) in wrap_norm_path.parents), None)
        if match and not flag_de4dot:
            flag_de4dot = True
            logger.info(f"Flag set to True because '{norm_path}' is inside the de4dot directory '{match}'")

        # ========== SPECIALIZED ANALYSIS TASKS ==========
        async def vmprotect_detection():
            try:
                if flag_vmprotect:
                    return

                if is_vm_protect_from_output(die_output):
                    try:
                        packed_data = await asyncio.to_thread(Path(file_path).read_bytes)
                        unpacked_data = await asyncio.to_thread(unpack_pe, packed_data)

                        if unpacked_data:
                            base_name, ext = os.path.splitext(os.path.basename(file_path))
                            unpacked_name = f"{base_name}_vmprotect_unpacked{ext}"
                            unpacked_path = os.path.join(vmprotect_unpacked_dir, unpacked_name)

                            await asyncio.to_thread(Path(unpacked_path).write_bytes, unpacked_data)

                            logger.info(f"VMProtect unpacked successfully: {unpacked_path}")

                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(unpacked_path, flag_vmprotect=True, main_file_path=main_file_path))

                    except Exception as e:
                        logger.error(f"Error unpacking VMProtect file '{file_path}': {e}")

            except Exception as e:
                logger.error(f"Error in VMProtect detection for '{file_path}': {e}")

        async def themida_detection():
            try:
                is_themida_protected = is_themida_from_output(die_output)
                if is_themida_protected == "PE32 Themida":
                    logger.info(f"File '{norm_path}' is protected by Themida 32 bit.")
                    await asyncio.to_thread(run_themida_unlicense, norm_path)
                    # MODIFIED: Call async scan_and_warn as a new task
                    asyncio.create_task(scan_and_warn(norm_path, main_file_path=main_file_path))
                elif is_themida_protected == "PE64 Themida":
                    logger.info(f"File '{norm_path}' is protected by Themida 64 bit.")
                    await asyncio.to_thread(run_themida_unlicense, norm_path, x64=True)
                    # MODIFIED: Call async scan_and_warn as a new task
                    asyncio.create_task(scan_and_warn(norm_path, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in Themida detection for {norm_path}: {e}")

        async def nexe_thread():
            try:
                if is_nexe_file_from_output(die_output):
                    logger.info(f"Checking if the file {norm_path} contains nexe executable")

                    # Step 1: Extract nexe files
                    nexe_files = await asyncio.to_thread(nexe_unpacker, norm_path)
                    if not nexe_files:
                        return

                    for extracted_file in nexe_files:
                        # Step 2: Optionally deobfuscate with Webcrack
                        try:
                            js_output_dir = await asyncio.to_thread(deobfuscate_webcrack_js, extracted_file)
                        except Exception as deobf_err:
                            logger.error(f"Webcrack deobfuscation failed for {extracted_file}: {deobf_err}")
                            js_output_dir = extracted_file  # fallback: just scan the extracted file

                        # Step 3: Scan extracted/deobfuscated files
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

                                # MODIFIED: Run sync scan_code_for_links in a thread as a task
                                asyncio.create_task(asyncio.to_thread(
                                    scan_code_for_links,
                                    content, file_path_full, nexe_flag=True, main_file_path=main_file_path
                                ))

                                # MODIFIED: Call async scan_and_warn as a new task
                                asyncio.create_task(scan_and_warn(file_path_full, main_file_path=main_file_path))

                            except Exception as scan_err:
                                logger.error(f"Error scanning file {file_path_full}: {scan_err}")

            except Exception as e:
                logger.error(f"Error in nexe analysis for {norm_path}: {e}")

        async def autoit_analysis():
            try:
                if is_autoit_file_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid AutoIt file.")
                    extracted_autoit_files = await asyncio.to_thread(extract_autoit, norm_path)
                    for extracted_autoit_file in extracted_autoit_files:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(extracted_autoit_file, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in AutoIt analysis for {norm_path}: {e}")

        async def asar_analysis():
            try:
                if is_asar_archive_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid Asar Archive (Electron).")
                    extracted_asar_files = await asyncio.to_thread(extract_asar_file, norm_path)
                    for extracted_asar_file in extracted_asar_files:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(extracted_asar_file, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in ASAR analysis for {norm_path}: {e}")

        async def npm_analysis():
            try:
                if is_npm_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid npm package.")
                    extracted_npm_files = await asyncio.to_thread(extract_npm_file, norm_path)
                    for extracted_file in extracted_npm_files:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(extracted_file, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in npm analysis for {norm_path}: {e}")

        async def jsc_analysis():
            """
            Async Task: If DIE output indicates a compiled JavaScript (Bytenode .JSC or bundle.js),
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
                    all_func = await asyncio.to_thread(disassemble, norm_path, input_is_disassembled=False, disassembler=None)
                    export_file_path = os.path.join(file_decompiled_dir, Path(norm_path).stem + "_decompiled.js")
                    await asyncio.to_thread(decompile, all_func)
                    await asyncio.to_thread(export_to_file, export_file_path, all_func, ["decompiled"])
                    logger.info(f"Successfully decompiled {norm_path} to {export_file_path}")
                except Exception as decomp_err:
                    logger.error(f"View8 decompilation failed for {norm_path}: {decomp_err}")
                    return

                # Step 2: Optionally deobfuscate with Webcrack
                try:
                    js_output_dir = await asyncio.to_thread(deobfuscate_webcrack_js, export_file_path)
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

                        # MODIFIED: Run sync scan_code_for_links in a thread as a task
                        asyncio.create_task(asyncio.to_thread(
                            scan_code_for_links,
                            content, file_path_full, jsc_flag=True, main_file_path=main_file_path
                        ))

                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(file_path_full, main_file_path=main_file_path))

                    except Exception as scan_err:
                        logger.error(f"Error scanning file {file_path_full}: {scan_err}")

            except Exception as e:
                logger.error(f"Error in JSC analysis for {norm_path}: {e}")

        async def installshield_analysis():
            try:
                if is_installshield_file_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid Install Shield file.")
                    extracted_installshield_files = await asyncio.to_thread(extract_installshield, norm_path)
                    for extracted_installshield_file in extracted_installshield_files:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(extracted_installshield_file, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in InstallShield analysis for {norm_path}: {e}")

        async def advanced_installer_analysis():
            try:
                if is_advanced_installer_file_from_output(die_output):
                    logger.info(f"File {norm_path} is a valid Advanced Installer file.")
                    extracted_files = await asyncio.to_thread(advanced_installer_extractor, norm_path)
                    for extracted_file in extracted_files:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(extracted_file, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in Advanced Installer analysis for {norm_path}: {e}")

        async def apk_analysis():
            """
            Async Task: Analyze and decompile an APK, then scan decompiled files in tasks.
            """
            try:
                if not apk_result:
                    return

                logger.info(f"File {norm_path} is a valid APK file.")

                # MODIFIED: Pass main_file_path to the decompiler (run in thread)
                decompiled_files = await asyncio.to_thread(decompile_apk_file, norm_path, main_file_path=main_file_path)

                if not decompiled_files:
                    logger.error(f"Failed to decompile {norm_path} (no files returned).")
                    return

                logger.debug(f"Decompiled {len(decompiled_files)} files from {norm_path}.")

                for f in decompiled_files:
                    # MODIFIED: Call async scan_and_warn as a new task
                    asyncio.create_task(scan_and_warn(f, main_file_path=main_file_path))

            except Exception as e:
                logger.exception(f"Error in APK analysis for {norm_path}: {e}")

        async def dotnet_analysis():
            try:
                dotnet_result = is_dotnet_file_from_output(die_output)
                if os.path.isfile(norm_path):
                    input_dir = os.path.dirname(norm_path)
                else:
                    input_dir = norm_path

                if dotnet_result is not None and not flag_de4dot and "Protector: Obfuscar" not in dotnet_result:
                    # MODIFIED: Run sync worker in a thread as a task
                    asyncio.create_task(asyncio.to_thread(run_de4dot, input_dir))

                    if "Probably No Protector" in dotnet_result or "Already Deobfuscated" in dotnet_result:
                        # MODIFIED: Run sync worker in a thread as a task
                        asyncio.create_task(asyncio.to_thread(decompile_dotnet_file, input_dir, main_file_path=main_file_path))

                with scan_and_warn_lock:
                    thread_results['dotnet_result'] = dotnet_result
            except Exception as e:
                logger.error(f"Error in .NET analysis for {norm_path}: {e}")

        async def cx_freeze_thread():
            try:
                if is_cx_freeze_file_from_output(die_output):
                    logger.info(f"Invoking cx_Freeze decompiler on {norm_path}")
                    cx_main_pyc = await asyncio.to_thread(decompile_cx_freeze, norm_path)
                    if cx_main_pyc:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(cx_main_pyc, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error decompiling cx_Freeze stub at {norm_path}: {e}")

        # Start all specialized analysis tasks, including VMProtect detection
        # These are fire-and-forget, except dotnet_task which we await later
        dotnet_task = asyncio.create_task(dotnet_analysis(), name="dotnet_analysis_task")

        analysis_tasks = [
            asyncio.create_task(themida_detection()),
            asyncio.create_task(autoit_analysis()),
            asyncio.create_task(asar_analysis()),
            asyncio.create_task(npm_analysis()),
            asyncio.create_task(jsc_analysis()),
            asyncio.create_task(installshield_analysis()),
            asyncio.create_task(advanced_installer_analysis()),
            asyncio.create_task(apk_analysis()),
            dotnet_task,
            asyncio.create_task(cx_freeze_thread()),
            asyncio.create_task(nexe_thread()),
            asyncio.create_task(vmprotect_detection()) # vmprotect_detection now handles its own logic
        ]

        # FIXED: Wait for tasks to complete to fix flake8 error and address user feedback
        await asyncio.gather(*analysis_tasks)

        # We don't await all tasks, just the ones we depend on (dotnet_task) - This was already awaited via gather

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

            # Heavy extraction operations in tasks
            async def extraction_thread():
                try:
                    logger.info(f"Attempting to extract file {norm_path}...")
                    extracted_files = await asyncio.to_thread(extract_all_files_with_7z, norm_path, nsis_flag)
                    if extracted_files:
                        logger.info(f"Extraction successful for {norm_path}. Scanning extracted files...")
                        for extracted_file in extracted_files:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(extracted_file, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error during extraction of {norm_path}: {e}")

            async def upx_thread():
                try:
                    if is_packer_upx_output(die_output):
                        upx_unpacked = await asyncio.to_thread(extract_upx, norm_path)
                        if upx_unpacked:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(upx_unpacked, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error in UPX unpacking for {norm_path}: {e}")

            async def protected_process_thread(file_path: str, die_output: Optional[str], main_file_path: Optional[str] = None) -> bool:
                """
                Async Task: if a process is running and is marked 'protected' according to die_output,
                queue a scan via scan_and_warn(file_path, main_file_path=...) instead of calling analyze_specific_process.

                Returns:
                    True if a scan was queued, False otherwise.
                """
                try:
                    if not die_output:
                        return False

                    target_basename = os.path.basename(file_path).lower()

                    # Run blocking psutil iterator in a thread
                    proc_list = await asyncio.to_thread(list, psutil.process_iter(['pid', 'name', 'exe']))

                    for proc in proc_list:
                        try:
                            pname = proc.info.get('name')
                            if not pname:
                                continue

                            if pname.lower() == target_basename:
                                protector = is_protector_from_output(die_output)
                                if protector:
                                    # prefer the actual exe path for main_file_path if caller didn't provide one
                                    resolved_main = main_file_path or proc.info.get('exe') or file_path

                                    logger.info(
                                        f"Process {file_path} (PID {proc.info.get('pid')}) is protected: {protector}. "
                                        "Queuing scan via scan_and_warn."
                                    )

                                    # MODIFIED: Call async scan_and_warn as a new task
                                    asyncio.create_task(scan_and_warn(file_path, main_file_path=resolved_main))
                                    return True  # end this helper task after queuing the scan
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            # Process disappeared or we couldn't access it — skip
                            continue
                        except Exception as e:
                            logger.error(f"Unexpected error while checking process {proc}: {e}")
                            continue

                    # no matching protected process found
                    return False

                except Exception as e:
                    logger.error(f"Error in protected_process_thread for {file_path}: {e}")
                    return False

            async def unipacker_thread():
                try:
                    if is_packed_from_output(die_output):
                        unpacked_file = await asyncio.to_thread(extract_with_unipacker, norm_path)
                        if unpacked_file:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(unpacked_file, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error in Unipacker unpacking for {norm_path}: {e}")

            async def inno_setup_thread():
                try:
                    if is_inno_setup_file_from_output(die_output):
                        extracted = await asyncio.to_thread(extract_inno_setup, norm_path)
                        if extracted is not None:
                            logger.info(f"Extracted {len(extracted)} files. Scanning...")
                            for inno_norm_path in extracted:
                                # MODIFIED: Call async scan_and_warn as a new task
                                asyncio.create_task(scan_and_warn(inno_norm_path, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error in Inno Setup extraction for {norm_path}: {e}")

            async def go_garble_thread():
                try:
                    if is_go_garble_from_output(die_output):
                        output_path = os.path.join(ungarbler_dir, os.path.basename(norm_path))
                        string_output_path = os.path.join(ungarbler_string_dir, os.path.basename(norm_path) + "_strings.txt")
                        results = await asyncio.to_thread(process_file_go, norm_path, output_path, string_output_path)

                        if results.get("patched_data"):
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(output_path, main_file_path=main_file_path))
                        if results.get("decrypt_func_list"):
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(string_output_path, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error in Go Garble processing for {norm_path}: {e}")

            async def pyc_thread():
                """
                Async Task: Process a single .pyc file.
                - If PyArmor-protected, extract and scan decrypted files.
                - Always attempt Pylingual decompilation.
                """
                try:
                    # Check if this is a .pyc file
                    if is_pyc_file_from_output(die_output):
                        logger.info(f"File {norm_path} is a .pyc file.")

                        # Handle PyArmor-protected .pyc
                        if is_pyarmor_archive_from_output(die_output):
                            logger.info(f"File {norm_path} is PyArmor-protected. Extracting...")
                            try:
                                pyarmor_files, main_decrypted_output = await asyncio.to_thread(extract_and_return_pyarmor, norm_path)

                                # Scan main decrypted output if present
                                if main_decrypted_output:
                                    # MODIFIED: Call async scan_and_warn as a new task
                                    asyncio.create_task(scan_and_warn(main_decrypted_output, main_file_path=main_file_path))

                                # Scan extracted PyArmor files
                                if pyarmor_files:
                                    for extracted_file in pyarmor_files:
                                        # MODIFIED: Call async scan_and_warn as a new task
                                        asyncio.create_task(scan_and_warn(extracted_file, main_file_path=main_file_path))
                            except Exception as e_extract:
                                logger.error(f"Error extracting PyArmor .pyc {norm_path}: {e_extract}")

                        # Original Pylingual decompilation
                        try:
                            logger.info(f"Attempting Pylingual decompilation for {norm_path}...")
                            pylingual, pycdas = await asyncio.to_thread(show_code_with_pylingual_pycdas, file_path=norm_path)

                            if pylingual:
                                for fname in pylingual: # MODIFIED: pylingual is a list
                                    # MODIFIED: Call async scan_and_warn as a new task
                                    asyncio.create_task(scan_and_warn(file_path=fname, main_file_path=main_file_path))
                                    # MODIFIED: Run sync worker in a thread as a task
                                    asyncio.create_task(asyncio.to_thread(process_decompiled_code, fname, main_file_path=main_file_path))

                            if pycdas:
                                for rname in pycdas: # MODIFIED: pycdas is a list
                                    # MODIFIED: Call async scan_and_warn as a new task
                                    asyncio.create_task(scan_and_warn(file_path=rname, main_file_path=main_file_path))

                        except Exception as e_pyl:
                            logger.error(f"Pylingual decompilation error for {norm_path}: {e_pyl}")

                except Exception as e:
                    logger.error(f"Error in PYC processing for {norm_path}: {e}")

            async def nsis_thread():
                try:
                    if is_nsis_from_output(die_output):
                        nonlocal nsis_flag
                        nsis_flag = True
                except Exception as e:
                    logger.error(f"Error in NSIS detection for {norm_path}: {e}")

            # Start binary processing tasks
            binary_tasks = [
                asyncio.create_task(extraction_thread()),
                asyncio.create_task(protected_process_thread(norm_path, die_output, main_file_path)),
                asyncio.create_task(unipacker_thread()),
                asyncio.create_task(upx_thread()),
                asyncio.create_task(inno_setup_thread()),
                asyncio.create_task(go_garble_thread()),
                asyncio.create_task(pyc_thread()),
                asyncio.create_task(nsis_thread())
            ]
            # FIXED: Wait for tasks to complete to fix flake8 error and address user feedback
            await asyncio.gather(*binary_tasks)

        # ========== PE FILE SPECIFIC PROCESSING ==========
        if pe_file:
            logger.info(f"File {norm_path} is identified as a PE file.")

            # Wait for signature check to complete (needed for PE logic)
            await signature_task
            signature_check = thread_results.get('signature_check', {
                "is_valid": False,
                "signature_status_issues": False
            })

            if signature_check["signature_status_issues"] and not signature_check.get("no_signature"):
                logger.critical(f"File '{norm_path}' has signature issues. Proceeding with further checks.")
                # MODIFIED: await notify function
                await notify_user_invalid(norm_path, "Win32.Susp.InvalidSignature", main_file_path=main_file_path)
                # One detection enough
                return False

            async def scr_detection_thread():
                try:
                    if norm_path.lower().endswith(".scr"):
                        logger.critical(f"Suspicious .scr file detected: {norm_path}")
                        # MODIFIED: await notify function
                        await notify_user_scr(norm_path, "HEUR:Win32.Susp.PE.SCR.gen", main_file_path=main_file_path)
                        # One detection enough
                        return False
                except Exception as e:
                    logger.error(f"Error in SCR detection for {norm_path}: {e}")

            async def decompile_thread():
                """
                Async Task: Decompile norm_path (propagating main_file_path) and send any exported
                artifact(s) into scan_and_warn for further processing.
                """
                try:
                    exported = await asyncio.to_thread(decompile_file, norm_path, main_file_path=main_file_path)
                    if not exported:
                        logger.debug(f"No decompiled artifacts returned for {norm_path}")
                        return

                    # Normalize into list
                    if isinstance(exported, (list, tuple, set)):
                        candidates = list(exported)
                    else:
                        candidates = [exported]

                    queued = 0
                    for candidate in candidates:
                        try:
                            if not candidate or not os.path.exists(candidate):
                                continue

                            if os.path.isdir(candidate):
                                for root, _, files in os.walk(candidate):
                                    for fname in files:
                                        file_path_full = os.path.join(root, fname)
                                        # MODIFIED: Call async scan_and_warn as a new task
                                        asyncio.create_task(scan_and_warn(file_path_full, main_file_path=main_file_path))
                                        queued += 1
                            else:
                                # MODIFIED: Call async scan_and_warn as a new task
                                asyncio.create_task(scan_and_warn(candidate, main_file_path=main_file_path))
                                queued += 1

                        except Exception as inner_e:
                            logger.error(f"Failed to queue scan for decompiled artifact '{candidate}': {inner_e}")

                    logger.info(f"Queued {queued} artifact(s) from decompilation of {norm_path} for scanning.")

                except Exception as e:
                    logger.error(f"Error in decompilation thread for {norm_path}: {e}")

            async def pe_section_thread():
                try:
                    section_files = await asyncio.to_thread(extract_pe_sections, norm_path)
                    if section_files:
                        logger.info(f"Extracted {len(section_files)} PE sections. Scanning...")
                        for fpath in section_files:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(fpath, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error in PE section extraction for {norm_path}: {e}")

            async def resource_extraction_thread():
                try:
                    extracted = await asyncio.to_thread(extract_resources, norm_path, resource_extractor_dir)
                    if extracted:
                        for file in extracted:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(file, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error in resource extraction for {norm_path}: {e}")

            async def autohotkey_thread():
                """
                Async Task: Handle AutoHotkey EXE decompilation and scanning.
                """
                try:
                    if is_compiled_autohotkey_file_from_output(die_output):
                        rc_path = await asyncio.to_thread(decompile_ahk_exe, norm_path)
                        if rc_path:
                            logger.info(f"Decompiled RCData.rc at {rc_path}. Scanning...")
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(rc_path, main_file_path=main_file_path))
                        else:
                            logger.warning(f"No RCData extracted from {norm_path}")
                    else:
                        logger.info(f"{norm_path} is not a compiled AutoHotkey executable.")
                except Exception as e:
                    logger.error(f"Error in AutoHotkey extraction for {norm_path}: {e}")

            async def enigma1_virtual_box_thread():
                try:
                    if is_enigma1_virtual_box(die_output):
                        extracted_path = await asyncio.to_thread(try_unpack_enigma1, norm_path)
                        if extracted_path:
                            logger.info(f"Unpack succeeded. Files are in: {extracted_path}")
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(extracted_path, main_file_path=main_file_path))
                except Exception as e:
                    logger.error(f"Error in Enigma1 unpacking for {norm_path}: {e}")

            async def debloat_thread():
                try:
                    if not flag_debloat:
                        logger.info(f"Debloating PE file {norm_path} for faster scanning.")
                        optimized_norm_path = await asyncio.to_thread(debloat_pe_file, norm_path)
                        if optimized_norm_path:
                            logger.info(f"Debloated file saved at: {optimized_norm_path}")
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(
                                optimized_norm_path, flag_debloat=True, main_file_path=main_file_path
                            ))
                except Exception as e:
                    logger.error(f"Error during debloating of {norm_path}: {e}")

            # Start PE processing tasks
            pe_tasks = [
                asyncio.create_task(scr_detection_thread()),
                asyncio.create_task(decompile_thread()),
                asyncio.create_task(pe_section_thread()),
                asyncio.create_task(resource_extraction_thread()),
                asyncio.create_task(autohotkey_thread()),
                asyncio.create_task(enigma1_virtual_box_thread()),
                asyncio.create_task(debloat_thread())
            ]
            # FIXED: Wait for tasks to complete to fix flake8 error and address user feedback
            await asyncio.gather(*pe_tasks)

        # ========== POST-ANALYSIS PROCESSING ==========

        # Wait for dotnet analysis to complete (needed for obfuscation logic)
        await dotnet_task

        dotnet_result = thread_results.get('dotnet_result')

        # .NET specific processing (tasks)
        async def dotnet_obfuscar_thread():
            try:
                if isinstance(dotnet_result, str) and "Protector: Obfuscar" in dotnet_result and not flag_obfuscar:
                    logger.info(f"The file is a .NET assembly protected with Obfuscar: {dotnet_result}")
                    deobfuscated_path = await asyncio.to_thread(deobfuscate_with_obfuscar, norm_path, file_name)
                    if deobfuscated_path:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(
                            deobfuscated_path, flag_obfuscar=True, main_file_path=main_file_path
                        ))
            except Exception as e:
                logger.error(f"Error in Obfuscar deobfuscation for {norm_path}: {e}")

        async def dotnet_reactor_thread():
            try:
                if isinstance(dotnet_result, str) and "Protector: .NET Reactor" in dotnet_result:
                    logger.info(f"The file is a .NET assembly protected with .NET Reactor: {dotnet_result}")
                    deobfuscated_path = await asyncio.to_thread(deobfuscate_with_net_reactor, norm_path, file_name)
                    if deobfuscated_path:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(deobfuscated_path, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in .NET Reactor deobfuscation for {norm_path}: {e}")

        async def dotnet_confuserex_thread():
            """
            Async Task: Handler for ConfuserEx-protected .NET assemblies.
            """
            try:
                if isinstance(dotnet_result, str) and "Protector: ConfuserEx" in dotnet_result and not flag_confuserex:
                    logger.info(f"The file is a .NET assembly protected with ConfuserEx: {dotnet_result}")
                    deobfuscated_path = await asyncio.to_thread(deobfuscate_with_confuserex, norm_path, file_name)
                    if deobfuscated_path:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(deobfuscated_path, flag_confuserex=True, main_file_path=main_file_path))

            except Exception as e:
                logger.error(f"Error in ConfuserEx deobfuscation for {norm_path}: {e}")

        async def jar_analysis_thread():
            try:
                if is_jar_file_from_output(die_output):
                    jar_extractor_paths = await asyncio.to_thread(run_jar_extractor, norm_path, flag_fernflower)
                    if jar_extractor_paths:
                        for jar_extractor_path in jar_extractor_paths:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(
                                jar_extractor_path, flag_fernflower=True, main_file_path=main_file_path
                            ))
            except Exception as e:
                logger.error(f"Error in JAR analysis for {norm_path}: {e}")

        async def java_class_thread():
            try:
                if is_java_class_from_output(die_output):
                    decompiled_file = await asyncio.to_thread(run_fernflower_decompiler, norm_path)
                    if decompiled_file:
                        # Task 1: scan_and_warn
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(decompiled_file, main_file_path=main_file_path))

                        # Task 2: scan_code_for_links with flag_fernflower (run sync in thread)
                        asyncio.create_task(asyncio.to_thread(
                            scan_code_for_links, file_path=decompiled_file, fernflower_flag=True
                        ))
                    else:
                        logger.info("No file returned from FernFlower decompiler.")
            except Exception as e:
                logger.error(f"Error in Java class analysis for {norm_path}: {e}")

        async def ole2_handler_thread():
            """
            Async Task: Handle OLE2 file detection and extraction.
            """
            try:
                if is_microsoft_compound_file_from_output(die_output):
                    logger.info(f"OLE2/Microsoft Office file detected: {norm_path}")

                    handler = OLE2Handler(script_dir)

                    # Extract VBA macros and content
                    extracted_path = await asyncio.to_thread(handler.run_ole_extractor, norm_path)

                    if extracted_path:
                        logger.info(f"Extraction completed. Content saved to: {extracted_path}")

                        # Task 1: Scan extracted artifacts for threats
                        asyncio.create_task(scan_and_warn(extracted_path, main_file_path=main_file_path))

                        # Task 2: Scan code for suspicious links (with OLE2 flag) (run sync in thread)
                        asyncio.create_task(asyncio.to_thread(
                            scan_code_for_links, "", extracted_path, ole2_flag=True, main_file_path=main_file_path
                        ))

                        logger.info("Spawned analysis tasks for extracted content")
                    else:
                        logger.info("No content extracted from OLE2 file")

            except Exception as e:
                logger.error(f"Error in OLE2 handling for {norm_path}: {e}")

        async def nuitka_thread():
            try:
                nuitka_type = is_nuitka_file_from_output(die_output)
                if nuitka_type:
                    logger.info(f"Checking if the file {norm_path} contains Nuitka executable of type: {nuitka_type}")
                    nuitka_files = await asyncio.to_thread(extract_nuitka_file, norm_path, nuitka_type)
                    if nuitka_files:
                        for extracted_file in nuitka_files:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(extracted_file, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in Nuitka analysis for {norm_path}: {e}")

        async def pyinstaller_thread():
            try:
                if is_pyinstaller_archive_from_output(die_output):
                    extracted_files_pyinstaller, main_decompiled_output = await asyncio.to_thread(extract_and_return_pyinstaller, norm_path)

                    if main_decompiled_output:
                        # MODIFIED: Call async scan_and_warn as a new task
                        asyncio.create_task(scan_and_warn(main_decompiled_output, main_file_path=main_file_path))

                    if extracted_files_pyinstaller:
                        for extracted_file in extracted_files_pyinstaller:
                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(extracted_file, main_file_path=main_file_path))
            except Exception as e:
                logger.error(f"Error in PyInstaller analysis for {norm_path}: {e}")

        # Start additional analysis tasks
        additional_tasks = [
            asyncio.create_task(dotnet_obfuscar_thread()),
            asyncio.create_task(dotnet_reactor_thread()),
            asyncio.create_task(dotnet_confuserex_thread()),
            asyncio.create_task(jar_analysis_thread()),
            asyncio.create_task(java_class_thread()),
            asyncio.create_task(ole2_handler_thread()),
            asyncio.create_task(nuitka_thread()),
            asyncio.create_task(pyinstaller_thread())
        ]
        # FIXED: Wait for tasks to complete to fix flake8 error and address user feedback
        await asyncio.gather(*additional_tasks)

        # ========== TEXT FILE PROCESSING ==========
        if plain_text_flag:
            # Plain text file processing
            logger.info(f"File {norm_path} does contain plain text data.")

            # Wait for file reading to complete
            await file_read_task

        # If file is a .js file, deobfuscate it first
        if norm_path.lower().endswith(".js"):
            try:
                logger.info(f"Detected JavaScript file: {norm_path}, deobfuscating with Webcrack...")
                output_dir = await asyncio.to_thread(deobfuscate_webcrack_js, norm_path)

                if output_dir and os.path.exists(output_dir):
                    logger.info(f"Scanning deobfuscated JS files in: {output_dir}")

                    for root, _, files in os.walk(output_dir):
                        for file in files:
                            file_path_full = os.path.join(root, file)
                            logger.info(f"Scanning deobfuscated file: {file_path_full}")

                            try:
                                with open(file_path_full, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()

                                # Scan for links, IPs, domains, Discord webhooks (run sync in thread)
                                asyncio.create_task(asyncio.to_thread(
                                    scan_code_for_links,
                                    content, file_path_full, javascript_deobfuscated_flag=True, main_file_path=main_file_path
                                ))

                                # Optional additional scanning/warnings
                                # MODIFIED: Call async scan_and_warn as a new task
                                asyncio.create_task(scan_and_warn(file_path_full, main_file_path=main_file_path))

                            except Exception as scan_err:
                                logger.error(f"Error scanning file {file_path_full}: {scan_err}")

            except Exception as deobf_err:
                logger.error(f"Webcrack deobfuscation failed for {norm_path}: {deobf_err}")

            # Check if file is in decompiled directory
            if norm_path.startswith(decompiled_dir):
                logger.info(f"File {norm_path} is in decompiled_dir.")
                is_decompiled = True

        # ========== COMMON PROCESSING FOR ALL FILES ==========
        # Fake size check task (heavy I/O for large files)
        async def fake_size_check_thread():
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
                            # MODIFIED: await notify function
                            await notify_user_fake_size(norm_path, fake_size, main_file_path=main_file_path)
                            # One detection enough
                            return False
            except Exception as e:
                logger.error(f"Error in fake size check for {norm_path}: {e}")

        # YARA REALTIME TASK
        async def realtime_malware_thread_yara(norm_path, signature_check, main_file_path, already_vmprotect_unpacked, vmprotect_unpacked_dir):
            try:
                is_malicious, virus_names, engine_detected, is_vmprotect = await asyncio.to_thread(
                    scan_file_real_time_yara, norm_path, signature_check
                )

                if is_malicious:
                    virus_name = ''.join(virus_names)
                    logger.critical(f"File {norm_path} is malicious. Virus: {virus_name}")

                    if virus_name.startswith("PUA."):
                        # MODIFIED: await notify function
                        await notify_user_pua(norm_path, virus_name, engine_detected, main_file_path=main_file_path)
                        return False
                    else:
                        # MODIFIED: await notify function
                        await notify_user(norm_path, virus_name, engine_detected, main_file_path=main_file_path)
                        return False

                if already_vmprotect_unpacked:
                    return

                # VMProtect unpacking logic
                if is_vmprotect:
                    try:
                        logger.info(f"VMProtect detected in {norm_path}. Starting unpack process...")

                        packed_data = await asyncio.to_thread(Path(norm_path).read_bytes)
                        unpacked_data = await asyncio.to_thread(unpack_pe, packed_data)

                        if unpacked_data:
                            base_name, ext = os.path.splitext(os.path.basename(norm_path))
                            unpacked_name = f"{base_name}_vmprotect_unpacked{ext}"
                            unpacked_path = os.path.join(vmprotect_unpacked_dir, unpacked_name)

                            await asyncio.to_thread(Path(unpacked_path).write_bytes, unpacked_data)

                            logger.info(f"VMProtect unpacked successfully: {unpacked_path}")

                            # MODIFIED: Call async scan_and_warn as a new task
                            asyncio.create_task(scan_and_warn(unpacked_path, flag_vmprotect=True, main_file_path=main_file_path))
                        else:
                            logger.warning(f"Unpacking VMProtect failed for {norm_path}")

                    except Exception as e:
                        logger.error(f"Error unpacking VMProtect file {norm_path}: {e}")

            except Exception as e:
                logger.error(f"Error in YARA real-time malware scan for {norm_path}: {e}")


        # NON-YARA REALTIME TASK
        async def realtime_malware_thread(norm_path, signature_check, file_name, die_output, pe_file, main_file_path):
            try:
                is_malicious, virus_names, engine_detected = await asyncio.to_thread(
                    scan_file_real_time,
                    norm_path, signature_check, file_name, die_output, pe_file=pe_file
                )

                if is_malicious:
                    virus_name = ''.join(virus_names)
                    logger.critical(f"File {norm_path} is malicious. Virus: {virus_name}")

                    if virus_name.startswith("PUA."):
                        # MODIFIED: await notify function
                        await notify_user_pua(norm_path, virus_name, engine_detected, main_file_path=main_file_path)
                        return False
                    else:
                        # MODIFIED: await notify function
                        await notify_user(norm_path, virus_name, engine_detected, main_file_path=main_file_path)
                        return False

            except Exception as e:
                logger.error(f"Error in real-time malware scan for {norm_path}: {e}")

        # Suspicious filename detection task
        async def filename_detection_thread():
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
                    # MODIFIED: await notify function
                    await notify_user_susp_name(norm_path, virus_name, main_file_path=main_file_path)
                    # One detection enough
                    return False
            except Exception as e:
                logger.error(f"Error in filename detection for {norm_path}: {e}")

        # Decompilation post-processing task
        async def decompilation_postprocess_thread():
            try:
                if is_decompiled:
                    logger.info(f"Checking original file path from decompiled data for: {norm_path}")
                    await asyncio.to_thread(extract_original_norm_path_from_decompiled, norm_path)
            except Exception as e:
                logger.error(f"Error in decompilation post-processing for {norm_path}: {e}")

        # Start common processing tasks
        common_tasks = [
            asyncio.create_task(fake_size_check_thread()),
            asyncio.create_task(realtime_malware_thread_yara(norm_path, signature_check, main_file_path, globals().get("already_vmprotect_unpacked"), vmprotect_unpacked_dir)),
            asyncio.create_task(realtime_malware_thread(norm_path, signature_check, file_name, die_output, pe_file, main_file_path)),
            asyncio.create_task(filename_detection_thread()),
            asyncio.create_task(decompilation_postprocess_thread())
        ]
        # FIXED: Wait for tasks to complete to fix flake8 error and address user feedback
        await asyncio.gather(*common_tasks)

        # ========== CLEANUP AND RETURN ==========

        # Note: We don't await all tasks here because many are fire-and-forget
        # operations that don't affect the main scan flow. The function can return
        # while background tasks continue processing.
        # FIXED: The tasks are now awaited above.

        logger.info(f"Main scan completed for {norm_path}, background processing continues...")
        return False  # Scan completed successfully

    except Exception as ex:
        logger.error(f"Error scanning file {norm_path}: {ex}")
        return False

# =========================
# EDR -> AV (Scan Requests)
# =========================
async def monitor_scan_requests_from_edr():
    """AV side: listen for scan requests FROM EDR (server)"""
    logger.info(f"[AV] Starting scan request listener on {PIPE_EDR_TO_AV}")
    
    while True:
        pipe = None
        try:
            # Create server pipe
            pipe = await asyncio.to_thread(
                lambda: win32pipe.CreateNamedPipe(
                    PIPE_EDR_TO_AV,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    65536, 65536, 0, None
                )
            )

            await asyncio.to_thread(lambda: win32pipe.ConnectNamedPipe(pipe, None))
            hr, data = await asyncio.to_thread(lambda: win32file.ReadFile(pipe, 4096))

            if data:
                message = data.decode("utf-8", errors="replace")
                request = json.loads(message)

                file_path = request.get("file_path")
                if file_path:
                    file_path = await normalize_nt_path(file_path)

                    if not await _is_protected_path(file_path):
                        logger.info(f"[AV] Received scan request: {file_path} (hr: {hr})")
                        await scan_and_warn(file_path)
                    else:
                        logger.debug(f"[AV] Skipping protected path: {file_path}")
                else:
                    logger.debug(f"[AV] Invalid scan request: {request}")

        except Exception as e:
            logger.error(f"[AV] Scan request listener error: {e}")
        finally:
            if pipe:
                await asyncio.to_thread(win32pipe.DisconnectNamedPipe, pipe)
                await asyncio.to_thread(_sync_close_handle, pipe)

async def load_all_resources_async():
    """
    Asynchronously load all core HydraDragon resources concurrently.
    Runs blocking functions in threads and awaits async functions directly.
    Returns a dict mapping task names to results or exceptions.

    Additionally: assigns successful results into module globals for key resources.
    """
    # Explicitly declare globals
    global yarGen_rules, icewater_rules, valhalla_rules, clean_rules
    global yaraxtr_rules, clamav_scanner, ml_definitions, excluded_rules

    logger.info("Starting to load all resources asynchronously...")

    # Load each resource individually, assign directly to globals
    try:
        if inspect.iscoroutinefunction(suricata_callback):
            suricata_callback_result = await suricata_callback()
        else:
            suricata_callback_result = await asyncio.to_thread(suricata_callback)
    except Exception as e:
        suricata_callback_result = e
        logger.error(f"Error loading suricata_callback: {e}", exc_info=e)

    try:
        load_website_data_result = await asyncio.to_thread(load_website_data)
    except Exception as e:
        load_website_data_result = e
        logger.error(f"Error loading load_website_data: {e}", exc_info=e)

    try:
        load_antivirus_list_result = await asyncio.to_thread(load_antivirus_list)
    except Exception as e:
        load_antivirus_list_result = e
        logger.error(f"Error loading load_antivirus_list: {e}", exc_info=e)

    try:
        yarGen_rules = await asyncio.to_thread(load_yara_rule, yarGen_rule_path, "yarGen Rules")
    except Exception as e:
        yarGen_rules = e
        logger.error(f"Error loading yarGen_rules: {e}", exc_info=e)

    try:
        icewater_rules = await asyncio.to_thread(load_yara_rule, icewater_rule_path, "Icewater Rules")
    except Exception as e:
        icewater_rules = e
        logger.error(f"Error loading icewater_rules: {e}", exc_info=e)

    try:
        valhalla_rules = await asyncio.to_thread(load_yara_rule, valhalla_rule_path, "Vallhalla Demo Rules")
    except Exception as e:
        valhalla_rules = e
        logger.error(f"Error loading valhalla_rules: {e}", exc_info=e)

    try:
        clean_rules = await asyncio.to_thread(load_yara_rule, clean_rules_path, "(clean) YARA Rules")
    except Exception as e:
        clean_rules = e
        logger.error(f"Error loading clean_rules: {e}", exc_info=e)

    try:
        yaraxtr_rules = await asyncio.to_thread(load_yara_rule, yaraxtr_yrc_path, "YARA-X yaraxtr Rules", True)
    except Exception as e:
        yaraxtr_rules = e
        logger.error(f"Error loading yaraxtr_rules: {e}", exc_info=e)

    try:
        clamav_scanner = await asyncio.to_thread(clamav.Scanner, libclamav_path=libclamav_path,
                                                 dbpath=clamav_database_directory_path)
    except Exception as e:
        clamav_scanner = e
        logger.error(f"Error loading clamav_scanner: {e}", exc_info=e)

    try:
        ml_definitions = await asyncio.to_thread(load_ml_definitions_pickle, machine_learning_pickle_path)
    except Exception as e:
        ml_definitions = e
        logger.error(f"Error loading ml_definitions: {e}", exc_info=e)

    try:
        with open(excluded_rules_path, "r") as f:
            excluded_rules = [line.strip() for line in f if line.strip()]
    except Exception as e:
        excluded_rules = e
        logger.error(f"Error loading excluded_rules: {e}", exc_info=e)

    logger.info("Resource loading completed.")

    # Collect all results in a dict
    results = {
        "suricata_callback": suricata_callback_result,
        "load_website_data": load_website_data_result,
        "load_antivirus_list": load_antivirus_list_result,
        "yarGen_rules": yarGen_rules,
        "icewater_rules": icewater_rules,
        "valhalla_rules": valhalla_rules,
        "clean_rules": clean_rules,
        "yaraxtr_rules": yaraxtr_rules,
        "clamav_scanner": clamav_scanner,
        "ml_definitions": ml_definitions,
        "excluded_rules": excluded_rules,
    }

    return results

async def run_hayabusa_live_async():
    """
    Continuous Hayabusa live monitoring loop (resilient, with sleeps to avoid tight loops).
    """
    while True:
        try:
            if not os.path.exists(hayabusa_path):
                logger.warning(f"Hayabusa executable not found at: {hayabusa_path}")
                # sleep to avoid busy retrying when binary is missing
                await asyncio.sleep(5)
                continue

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_live_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"hayabusa_live_{timestamp}.csv")

            # Use explicit long-form args so hayabusa doesn't complain
            cmd = [
                hayabusa_path,
                "csv-timeline",
                "--no-wizard",
                "--output", output_file,
                "--profile", "standard",
                "--min-level", "critical",
                "--live-analysis"
            ]
            logger.info(f"Launching Hayabusa: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=os.path.dirname(hayabusa_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            async def stream_reader(pipe, label):
                try:
                    while True:
                        line = await pipe.readline()
                        if not line:
                            break
                        decoded = line.decode("utf-8", errors="ignore").strip()
                        logger.info(f"[{label}] {decoded}")
                except asyncio.CancelledError:
                    # Task cancelled during shutdown
                    return
                except Exception:
                    logger.exception(f"Exception in stream_reader ({label})")

            stdout_task = asyncio.create_task(stream_reader(process.stdout, "Hayabusa"))
            stderr_task = asyncio.create_task(stream_reader(process.stderr, "Hayabusa-ERR"))

            # background waiter to detect process exit and ensure tasks are cancelled
            async def process_waiter():
                try:
                    rc = await process.wait()
                    logger.info(f"Hayabusa exited with returncode {rc}")
                except asyncio.CancelledError:
                    # if we cancel waiter, try to terminate process
                    try:
                        process.terminate()
                    except Exception:
                        pass
                    raise

            waiter_task = asyncio.create_task(process_waiter())

            async def tail_csv(csv_path):
                seen = set()
                last_pos = 0
                while True:
                    # if process finished and file processing done, break
                    if waiter_task.done() and not os.path.exists(csv_path):
                        break

                    try:
                        async with aiofiles.open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                            # move to last read position
                            await f.seek(last_pos)
                            content = await f.read()
                            last_pos = await f.tell()
                            if content:
                                reader = csv.DictReader(content.splitlines())
                                for row in reader:
                                    key = (row.get("Timestamp"), row.get("EventID"), row.get("RuleTitle"))
                                    if key in seen:
                                        continue
                                    seen.add(key)
                                    level = (row.get("Level") or "").lower()
                                    if level in ("critical", "crit"):
                                        rule = row.get("RuleTitle", "N/A")
                                        details = row.get("Details", "N/A")
                                        logger.warning(f"[!] CRITICAL: {rule} | {details[:100]}")
                                        try:
                                            await notify_user_hayabusa_critical(
                                                event_log=row.get("Channel", ""),
                                                rule_title=rule,
                                                details=details,
                                                computer=row.get("Computer", "")
                                            )
                                        except Exception:
                                            logger.exception("notify_user_hayabusa_critical failed")
                    except asyncio.CancelledError:
                        return
                    except Exception:
                        # log exception and continue; small sleep to avoid busy looping on repeated errors
                        logger.exception("Error while tailing hayabusa csv")
                        await asyncio.sleep(0.5)

            csv_tail_task = asyncio.create_task(tail_csv(output_file))

            # Wait for process to exit or for any task to raise — gather ensures we capture exceptions
            done, pending = await asyncio.wait(
                [stdout_task, stderr_task, csv_tail_task, waiter_task],
                return_when=asyncio.FIRST_EXCEPTION
            )

            # If any task raised, log them
            for d in done:
                if d.cancelled():
                    continue
                exc = d.exception()
                if exc:
                    logger.exception("Task in hayabusa group raised", exc_info=exc)

            # Cancel any remaining tasks and await them
            for p in pending:
                p.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        except asyncio.CancelledError:
            # propagate cancellation so outer event loop can shut down
            raise
        except Exception:
            logger.exception("Unhandled exception in Hayabusa live loop, restarting after short delay...")
            await asyncio.sleep(2)
            continue

# --- start_real_time_protection_async ---
async def start_real_time_protection_async():
    """
    Start all real-time protection and resource-loading tasks concurrently.
    Fully async; does not return tasks, runs in background.
    """

    async def wrap_async_function(name: str, coro_func):
        try:
            logger.info(f"{name} starting...")
            await coro_func()
            logger.info(f"{name} completed.")
        except Exception as e:
            logger.exception(f"Error in {name}: {e}")

    async def run_hayabusa_live_task():
        try:
            await run_hayabusa_live_async()
        except Exception:
            logger.exception("Hayabusa live task failed.")

    # Fire-and-forget tasks
    asyncio.create_task(wrap_async_function("EDRMonitor", monitor_scan_requests_from_edr))
    asyncio.create_task(wrap_async_function("SuricataMonitor", monitor_suricata_log_async))
    asyncio.create_task(wrap_async_function("WebProtection", web_protection_observer.begin_observing_async))
    asyncio.create_task(wrap_async_function("PipeListeners", start_all_pipe_listeners))
    asyncio.create_task(wrap_async_function("ResourceLoader", load_all_resources_async))
    asyncio.create_task(wrap_async_function("HayabusaLive", run_hayabusa_live_task))

    logger.info("All protection, resource, and Hayabusa tasks launched (fire-and-forget).")

def run_de4dot(file_path):
    """
    Runs de4dot inside host.
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
