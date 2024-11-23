import sys
from cx_Freeze import setup, Executable
from pathlib import Path
import spacy

# Increase maximum recursion depth
sys.setrecursionlimit(50000)  # Adjust as necessary (default is usually 1000)

# Locate site-packages directory
site_packages = Path(spacy.__file__).parent.parent
spacy_model_path = site_packages / "en_core_web_md"

# Define the executable and options
executables = [
    Executable(
        "antivirus.py",  # Your script
        target_name="antivirus.exe",  # Output executable name
        base="Console",  # Console application
        icon="assets/HydraDragonAV.ico",  # Path to your .ico file
        uac_admin=True  # Request admin privileges
    )
]

# Fine-tune build options (adjust as needed)
build_options = {
    "packages": ["scapy", "srsly", "blis", "spacy"],
    "includes": ["preshed.maps"],
    "excludes": ["tkinter"],
    "include_msvcr": True,
    "include_files": [
        (str(spacy_model_path), "en_core_web_md")  # Include the model
    ],
}

# Setup configuration for cx_Freeze
setup(
    name="HydraDragon Antivirus",  # Application name
    version="1.0",  # Version number
    description="HydraDragon Antivirus for Windows - A comprehensive malware analysis tool utilizing dynamic/static analysis, machine learning, and behavior analysis.",
    options={"build_exe": build_options},  # Build options
    executables=executables,  # List of executables
)
