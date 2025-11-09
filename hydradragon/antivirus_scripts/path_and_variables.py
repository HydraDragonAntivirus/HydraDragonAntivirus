#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import threading
import ctypes
import asyncio

# get the full path to the currently running Python interpreter
python_path = sys.executable

# Resolve system drive path
system_drive = os.getenv("SystemDrive", "C:") + os.sep
# Resolve Program Files directory via environment (fallback to standard path)
program_files = os.getenv("ProgramFiles", os.path.join(system_drive, "Program Files"))
# Get SystemRoot (usually C:\Windows)
system_root = os.getenv("SystemRoot", os.path.join(system_drive, "Windows"))
# Fallback to %SystemRoot%\System32 if %System32% is not set
system32_dir = os.getenv("System32", os.path.join(system_root, "System32"))

# Suricata base folder path
suricata_dir = os.path.join(program_files, "Suricata")

# Hydra Dragon Antivirus base folder path
hydra_dragon_antivirus_dir = os.path.join(program_files, "HydraDragonAntivirus")

script_dir = os.path.join(hydra_dragon_antivirus_dir, "hydradragon")

# Define the paths
jadx_decompiler_dir = os.path.join(script_dir, "jadx-1.5.3")
jadx_decompiler_path = os.path.join(jadx_decompiler_dir, "jadx.bat")
jadx_decompiled_dir = os.path.join(script_dir, "jadx_decompiled")
nexe_javascript_unpacked_dir = os.path.join(script_dir, "nexe_unpacked")
unlicense_dir = os.path.join(script_dir, "unlicense")
unlicense_path  = os.path.join(unlicense_dir, "unlicense.exe")
unlicense_x64_path  = os.path.join(unlicense_dir, "unlicense-x64.exe")
hayabusa_dir = os.path.join(script_dir, "hayabusa")
webcrack_javascript_deobfuscated_dir = os.path.join(script_dir, "webcrack_javascript_deobfuscated")
pkg_unpacker_dir = os.path.join(script_dir, "pkg-unpacker")
hayabusa_path = os.path.join(hayabusa_dir, "hayabusa-3.6.0-win-x64.exe")
enigma1_extracted_dir = os.path.join(script_dir, "enigma1_extracted")
inno_unpack_dir = os.path.join(script_dir, "innounp-2")
upx_dir = os.path.join(script_dir, "upx-5.0.2-win64")
upx_path = os.path.join(upx_dir, "upx.exe")
upx_extracted_dir = os.path.join(script_dir, "upx_extracted_dir")
inno_unpack_path = os.path.join(inno_unpack_dir, "innounp.exe")
autohotkey_decompiled_dir = os.path.join(script_dir, "autohotkey_decompiled")
inno_setup_unpacked_dir = os.path.join(script_dir, "inno_setup_unpacked")
themida_unpacked_dir = os.path.join(script_dir, "themida_unpacked")
decompiled_dir = os.path.join(script_dir, "decompiled")
assets_dir = os.path.join(script_dir, "assets")
icon_path = os.path.join(assets_dir, "HydraDragonAVLogo.png")
icon_animated_protected_path = os.path.join(assets_dir, "hydra_protected.gif")
icon_animated_unprotected_path = os.path.join(assets_dir, "hydra_unprotected.gif")
pyinstaller_extracted_dir = os.path.join(script_dir, "pyinstaller_extracted")
pyarmor8_and_9_extracted_dir = os.path.join(script_dir, "pyarmor8_and_9_extracted")
pyarmor7_extracted_dir = os.path.join(script_dir, "pyarmor7_extracted")
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
ole2_dir = os.path.join(script_dir, "ole2")
known_extensions_dir = os.path.join(script_dir, "known_extensions")
FernFlower_path = os.path.join(jar_decompiler_dir, "fernflower.jar")
system_file_names_path = os.path.join(known_extensions_dir, "system_filenames.txt")
extensions_path = os.path.join(known_extensions_dir, "extensions.txt")
vmprotect_unpacked_dir = os.path.join(script_dir, "vmprotect_unpacked")
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
pe_extracted_dir = os.path.join(script_dir, "pe_extracted")
zip_extracted_dir = os.path.join(script_dir, "zip_extracted")
tar_extracted_dir = os.path.join(script_dir, "tar_extracted")
seven_zip_extracted_dir = os.path.join(script_dir, "seven_zip_extracted")
general_extracted_with_7z_dir = os.path.join(script_dir, "general_extracted_with_7z")
nuitka_extracted_dir = os.path.join(script_dir, "nuitka_extracted")
advanced_installer_extracted_dir = os.path.join(script_dir, "advanced_installer_extracted")
detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_db_dir = os.path.join(detectiteasy_dir, "db")
memory_dir = os.path.join(script_dir, "memory")
debloat_dir = os.path.join(script_dir, "debloat")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
ilspycmd_dir = os.path.join(script_dir, "ILSpyCmd")
ilspycmd_path = os.path.join(ilspycmd_dir, "ilspycmd.exe")
pycdas_path = os.path.join(script_dir, "pycdas.exe")
ISx_installshield_extractor_path = os.path.join(script_dir, "ISx.exe")
installshield_extracted_dir = os.path.join(script_dir, "installshield_extracted")
autoit_extracted_dir = os.path.join(script_dir, "autoit_extracted")
hydra_dragon_dumper_dir = os.path.join(script_dir, "HydraDragonDumper")
hydra_dragon_dumper_path = os.path.join(hydra_dragon_dumper_dir, "HydraDragonDumper.exe")
hydra_dragon_dumper_extracted_dir = os.path.join(script_dir, "HydraDragonDumper_extracted")
deobfuscar_path = os.path.join(script_dir, "Deobfuscar-Standalone-Win64.exe")
machine_learning_dir = os.path.join(script_dir, "machine_learning")
machine_learning_pickle_path = os.path.join(machine_learning_dir, "results.pkl")
resource_extractor_dir = os.path.join(script_dir, "resources_extracted")
ungarbler_dir = os.path.join(script_dir, "ungarbler")
ungarbler_string_dir = os.path.join(script_dir, "ungarbler_string")
yara_dir = os.path.join(script_dir, "yara")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")
html_extracted_dir = os.path.join(script_dir, "html_extracted")
website_rules_dir = os.path.join(script_dir, "website")
# other small files we still load in original format if present:
urlhaus_path = os.path.join(website_rules_dir, "urlhaus.txt")
antivirus_list_path = os.path.join(script_dir, "hosts", "antivirus_list.txt")
yaraxtr_yrc_path = os.path.join(yara_dir, "yaraxtr.yrc")
clean_rules_path = os.path.join(yara_dir, "clean_rules.yrc")
yarGen_rule_path = os.path.join(yara_dir, "machine_learning.yrc")
icewater_rule_path = os.path.join(yara_dir, "icewater.yrc")
valhalla_rule_path = os.path.join(yara_dir, "valhalla-rules.yrc")
decompilers_dir = os.path.join(script_dir, "decompilers")
bypass_pyarmor7_path = os.path.join(decompilers_dir, "bypass_pyarmor7.py")

# Email last 365 days
spam_email_365_path = os.path.join(website_rules_dir, "listed_email_365.txt")
# Define all website file paths
ipv4_addresses_path = os.path.join(website_rules_dir, "IPv4Malware.optimized.csv")
ipv4_addresses_spam_path = os.path.join(website_rules_dir, "IPv4Spam.optimized.csv")
ipv4_addresses_bruteforce_path = os.path.join(website_rules_dir, "IPv4BruteForce.optimized.csv")
ipv4_addresses_phishing_active_path = os.path.join(website_rules_dir, "IPv4PhishingActive.optimized.csv")
ipv4_addresses_phishing_inactive_path = os.path.join(website_rules_dir, "IPv4PhishingInActive.optimized.csv")
ipv4_whitelist_path = os.path.join(website_rules_dir, "WhitelistIPv4.optimized.csv")
ipv6_addresses_path = os.path.join(website_rules_dir, "IPv6Malware.optimized.csv")
ipv6_addresses_spam_path = os.path.join(website_rules_dir, "IPv6Spam.optimized.csv")
ipv4_addresses_ddos_path = os.path.join(website_rules_dir, "IPv4DDoS.optimized.csv")
ipv6_addresses_ddos_path = os.path.join(website_rules_dir, "IPv6DDoS.optimized.csv")
ipv6_whitelist_path = os.path.join(website_rules_dir, "WhiteListIPv6.optimized.csv")
malware_domains_path = os.path.join(website_rules_dir, "MalwareDomains.optimized.csv")
malware_domains_mail_path = os.path.join(website_rules_dir, "MaliciousMailDomains.optimized.csv")
phishing_domains_path = os.path.join(website_rules_dir, "PhishingDomains.optimized.csv")
abuse_domains_path = os.path.join(website_rules_dir, "AbuseDomains.optimized.csv")
mining_domains_path = os.path.join(website_rules_dir, "MiningDomains.optimized.csv")
spam_domains_path = os.path.join(website_rules_dir, "SpamDomains.optimized.csv")
whitelist_domains_path = os.path.join(website_rules_dir, "WhiteListDomains.optimized.csv")
whitelist_domains_mail_path = os.path.join(website_rules_dir, "BenignMailDomains.optimized.csv")
# Define corresponding subdomain files
malware_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomains.optimized.csv")
malware_mail_sub_domains_path = os.path.join(website_rules_dir, "MaliciousMailSubDomains.optimized.csv")
phishing_sub_domains_path = os.path.join(website_rules_dir, "PhishingSubDomains.optimized.csv")
abuse_sub_domains_path = os.path.join(website_rules_dir, "AbuseSubDomains.optimized.csv")
mining_sub_domains_path = os.path.join(website_rules_dir, "MiningSubDomains.optimized.csv")
spam_sub_domains_path = os.path.join(website_rules_dir, "SpamSubDomains.optimized.csv")
whitelist_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomains.optimized.csv")
whitelist_mail_sub_domains_path = os.path.join(website_rules_dir, "BenignMailSubDomains.optimized.csv")
registry_path = os.path.join(website_rules_dir, "references.txt")

# Scanned entities with "_general" suffix
scanned_urls_general = []
scanned_domains_general = []
scanned_ipv4_addresses_general = []
scanned_ipv6_addresses_general = []
# Unified cache for all PE feature extractions
unified_pe_cache = {}

# List to keep track of existing project names
existing_projects = []

# Dictionary to track running Suricata processes per interface
running_processes = {}

started_interfaces = []  # using list instead of set

APP_NAME = "HydraDragon Antivirus"
APP_VERSION = "v0.1 (Beta 6)"
WINDOW_TITLE = f"{APP_NAME} {APP_VERSION}"

# File paths and configurations
suricata_log_dir = os.path.join(suricata_dir, "log")
# Suricata typically uses eve.json for structured logging
eve_log_path = os.path.join(suricata_log_dir, "eve.json")
suricata_config_path = os.path.join(suricata_dir, "suricata.yaml")
suricata_exe_path = os.path.join(suricata_dir, "suricata.exe")

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

# Cache of { file_path: last_md5 }
file_md5_cache: dict[str, str] = {}

# Global cache: md5 -> (die_output, plain_text_flag)
die_cache: dict[str, tuple[str, bool]] = {}

# Separate cache for "binary-only" DIE results
binary_die_cache: dict[str, str] = {}

# global, near top-level of module
malicious_hashes = set()
malicious_hashes_lock = asyncio.Lock()
scan_and_warn_lock = asyncio.Lock()

# Thread-safe map of original input -> list of decompiled artifacts produced by Ghidra
decompile_outputs = {}               # maps abs_input_path -> [artifact_path, ...]
decompile_outputs_lock = threading.Lock()

uefi_100kb_paths = [
    r'EFI\Microsoft\Boot\SecureBootRecovery.efi'
]

uefi_paths = [
    r'EFI\Microsoft\Boot\bootmgfw.efi',
    r'EFI\Microsoft\Boot\bootmgr.efi',
    r'EFI\Microsoft\Boot\memtest.efi',
    r'EFI\Boot\bootx64.efi'
]

# tuning knobs
RAW_PREVIEW_LEN = 128 # how many raw bytes to log for inspection
READ_BUFFER_SIZE = 65536

# Config
_WAIT_TIMEOUT_MS = 5000        # WaitNamedPipe timeout when opening (ms)
_OPEN_RETRIES = 10             # retries for opening the pipe
_RETRY_DELAY = 0.5             # seconds between open retries

# Internal queue other code will push scan requests into
_SCAN_REQUEST_SEND_QUEUE: "asyncio.Queue[dict]" = asyncio.Queue()

# Pipe 1: HydraDragon SENDS threat events TO Owlyshield (Owlyshield receives)
PIPE_AV_TO_EDR = r"\\.\pipe\Global\hydradragon_to_owlyshield"

# Pipe 2: Owlyshield SENDS scan requests TO HydraDragon (HydraDragon receives)
PIPE_EDR_TO_AV = r"\\.\pipe\Global\owlyshield_to_hydradragon"

# Pipe 3: MBR write alerts from the kernel driver
PIPE_MBR_ALERT = r"\\.\pipe\Global\mbr_filter_alerts"

# Pipe 4: Self-defense alerts from file/process/registry drivers
PIPE_SELF_DEFENSE_ALERT = r"\\.\pipe\Global\self_defense_alerts"

def get_startup_paths():
    """Return a tuple of (user_startup, common_startup) using ctypes Windows API."""
    MAX_PATH = 260
    CSIDL_STARTUP = 0x0A       # User startup
    CSIDL_COMMON_STARTUP = 0x19 # Common startup

    buf_user = ctypes.create_unicode_buffer(MAX_PATH)
    buf_common = ctypes.create_unicode_buffer(MAX_PATH)

    ctypes.windll.shell32.SHGetSpecialFolderPathW(None, buf_user, CSIDL_STARTUP, False)
    ctypes.windll.shell32.SHGetSpecialFolderPathW(None, buf_common, CSIDL_COMMON_STARTUP, False)

    return buf_user.value, buf_common.value
