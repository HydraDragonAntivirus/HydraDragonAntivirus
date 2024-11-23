import sys
from cx_Freeze import setup, Executable
from pathlib import Path
import spacy

# Increase maximum recursion depth
sys.setrecursionlimit(50000)

# Locate site-packages directory and handle versioned folder names
site_packages = Path(spacy.__file__).parent.parent
model_folder_prefix = "en_core_web_md"  # Base name for the model

# Dynamically find the model directory (e.g., en_core_web_md-3.8.0)
spacy_model_path = next(
    (p for p in site_packages.glob(f"{model_folder_prefix}*") if p.is_dir()), None
)

if not spacy_model_path:
    raise FileNotFoundError(f"Model folder for {model_folder_prefix} not found in {site_packages}")

# Define the executable and options
executables = [
    Executable(
        "antivirus.py",
        target_name="antivirus.exe",
        base="Console",
        icon="assets/HydraDragonAV.ico",
        uac_admin=True,
    )
]

# Fine-tune build options (adjust as needed)
build_options = {
    "packages": ["scapy", "srsly", "blis", "spacy"],
    "includes": ["preshed.maps"],
    "excludes": ["tkinter"],
    "include_msvcr": True,
    "include_files": [
        (str(spacy_model_path), model_folder_prefix)  # Include the model as en_core_web_md
    ],
}

# Setup configuration for cx_Freeze
setup(
    name="HydraDragon Antivirus",
    version="0.1",
    description="HydraDragon Antivirus for Windows - A comprehensive malware analysis tool utilizing dynamic/static analysis, machine learning, and behavior analysis.",
    options={"build_exe": build_options},
    executables=executables,
)
