#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
installer_clean_vm.py - Clean VM installer script (replaces .ps1 version)

This script configures a clean VM to have the right folders and required files
which are statically pulled from GitHub.

Requirements:
- Must be run as Administrator on Windows
- Internet connection for downloading files from GitHub
"""

import ctypes
import os
import subprocess
import sys
from pathlib import Path
from urllib.request import urlretrieve
from urllib.error import URLError

# Configure UTF-8 output for Windows console
try:
    # Try to set UTF-8 mode for stdout/stderr
    import io
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding='utf-8')
    if isinstance(sys.stderr, io.TextIOWrapper):
        sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    # Fallback: replace stdout/stderr with UTF-8 versions
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')

# ----------------------
# Administrator check
# ----------------------
def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if not is_admin():
    print("ERROR: This script must be run as Administrator.", file=sys.stderr)
    sys.exit(1)

# ----------------------
# Constants
# ----------------------
GITHUB_BASE_URL = "https://raw.githubusercontent.com/0xflux/Sanctum/refs/heads/main/clean_files"
FILES_TO_DOWNLOAD = [
    ("ioc_list.txt", "ioc_list.txt"),
    ("config.cfg", "config.cfg")
]

# ----------------------
# Helper functions
# ----------------------
def get_special_folder(csidl):
    """Get Windows special folder path using Shell API."""
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    return buf.value

def create_directory(path, description):
    """Create a directory if it doesn't exist."""
    if path.exists():
        print(f"WARNING: Directory '{path}' already exists.", file=sys.stderr)
        return False
    
    try:
        path.mkdir(parents=True, exist_ok=False)
        print(f"✓ Created directory: {path}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to create {description}: {e}", file=sys.stderr)
        return False

def download_file(url, dest_path, description):
    """Download a file from a URL to the destination path."""
    print(f"Downloading {description} from {url}...")
    print(f"  → {dest_path}")
    
    try:
        urlretrieve(url, dest_path)
        print(f"✓ Download completed successfully: {description}")
        return True
    except URLError as e:
        print(f"ERROR: Failed to download {description}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error downloading {description}: {e}", file=sys.stderr)
        return False

def configure_bcd():
    """Configure BCD settings for test-signing and kernel debug."""
    print("\nConfiguring BCD for test-signing and kernel debug...")
    
    commands = [
        (["bcdedit", "/set", "TESTSIGNING", "ON"], "Enable test signing"),
        (["bcdedit", "/debug", "ON"], "Enable debug mode"),
        (["bcdedit", "/dbgsettings", "serial", "debugport:1", "baudrate:115200"], 
         "Configure debug settings")
    ]
    
    success = True
    for cmd, desc in commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode == 0:
                print(f"✓ {desc}")
            else:
                print(f"WARNING: {desc} returned code {result.returncode}", file=sys.stderr)
                if result.stderr:
                    print(f"  Error: {result.stderr.strip()}", file=sys.stderr)
                success = False
        except FileNotFoundError:
            print(f"ERROR: bcdedit not found. Cannot configure {desc}", file=sys.stderr)
            success = False
        except Exception as e:
            print(f"ERROR: Failed to configure {desc}: {e}", file=sys.stderr)
            success = False
    
    return success

# ----------------------
# Main execution
# ----------------------
def main():
    """Main installation routine."""
    print("=" * 70)
    print("Clean VM Installer - Sanctum Setup")
    print("=" * 70)
    print()
    
    errors = []
    
    # 1. Create %AppData%\Sanctum
    appdata = os.environ.get("APPDATA")
    if not appdata:
        print("ERROR: APPDATA environment variable not found.", file=sys.stderr)
        sys.exit(1)
    
    appdata_sanctum = Path(appdata) / "Sanctum"
    if not create_directory(appdata_sanctum, "%AppData%\\Sanctum"):
        errors.append("AppData Sanctum directory creation")
    
    # 2. Create ~/Desktop/sanctum
    # Use CSIDL_DESKTOPDIRECTORY (0x0010) to get Desktop folder
    try:
        desktop_path = get_special_folder(0x0010)
        desktop_sanctum = Path(desktop_path) / "sanctum"
    except Exception as e:
        print(f"WARNING: Failed to get Desktop path via Shell API: {e}", file=sys.stderr)
        # Fallback to user profile
        desktop_sanctum = Path.home() / "Desktop" / "sanctum"
    
    if not create_directory(desktop_sanctum, "Desktop\\sanctum"):
        errors.append("Desktop sanctum directory creation")
    
    # 3. Download required files to %AppData%\Sanctum
    print("\nDownloading required files from GitHub...")
    for remote_name, local_name in FILES_TO_DOWNLOAD:
        url = f"{GITHUB_BASE_URL}/{remote_name}"
        dest = appdata_sanctum / local_name
        
        if not download_file(url, dest, local_name):
            errors.append(f"Download {local_name}")
    
    # 4. Configure BCD settings
    if not configure_bcd():
        errors.append("BCD configuration")
    
    # 5. Summary
    print("\n" + "=" * 70)
    if errors:
        print("⚠ Setup completed with warnings/errors:")
        for error in errors:
            print(f"  - {error}")
        print("\nPlease review the errors above and retry if necessary.")
        sys.exit(1)
    else:
        print("✓ Clean VM setup complete!")
        print(f"\nCreated directories:")
        print(f"  - {appdata_sanctum}")
        print(f"  - {desktop_sanctum}")
        print(f"\nDownloaded files to {appdata_sanctum}:")
        for _, local_name in FILES_TO_DOWNLOAD:
            print(f"  - {local_name}")
        print("\nPlease follow the remaining instructions to complete installation.")
        print("=" * 70)
        sys.exit(0)

if __name__ == "__main__":
    main()
