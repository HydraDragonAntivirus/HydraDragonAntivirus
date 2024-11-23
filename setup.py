import sys
from cx_Freeze import setup, Executable

# Increase maximum recursion depth
sys.setrecursionlimit(50000)  # Adjust as necessary (default is usually 1000)

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
    "packages": ["scapy", "srsly"],  # List packages if any are required
    "includes": ["preshed.maps"],  # Include necessary modules
    "excludes": ["tkinter"],  # Exclude unnecessary modules like tkinter
    "include_msvcr": True  # Include Microsoft Visual C Runtime libraries
}

# Setup configuration for cx_Freeze
setup(
    name="HydraDragon Antivirus",  # Application name
    version="1.0",  # Version number
    description="HydraDragon Antivirus for Windows - A comprehensive malware analysis tool utilizing dynamic/static analysis, machine learning, and behavior analysis.",
    options={"build_exe": build_options},  # Build options
    executables=executables,  # List of executables
)
