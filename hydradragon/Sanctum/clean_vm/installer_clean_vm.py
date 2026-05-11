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
import shutil
from pathlib import Path

# Configure UTF-8 output for Windows console
try:
    # Try to set UTF-8 mode for stdout/stderr
    import io

    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    if isinstance(sys.stderr, io.TextIOWrapper):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    # Fallback: replace stdout/stderr with UTF-8 versions
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "ignore")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "ignore")


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
        print(f"INFO: Directory already exists: {path}")
        return True

    try:
        path.mkdir(parents=True, exist_ok=False)
        print(f"✓ Created directory: {path}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to create {description}: {e}", file=sys.stderr)
        return False


def configure_bcd():
    """Configure BCD settings for test-signing and kernel debug."""
    print("\nConfiguring BCD for test-signing and kernel debug...")

    commands = [(["bcdedit", "/set", "TESTSIGNING", "ON"], "Enable test signing"), (["bcdedit", "/debug", "ON"], "Enable debug mode"), (["bcdedit", "/dbgsettings", "serial", "debugport:1", "baudrate:115200"], "Configure debug settings")]

    success = True
    for cmd, desc in commands:
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",  # ← FIXED: explicit UTF-8 encoding
                errors="ignore",
                check=False,
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

    # 1. Ensure the installed Sanctum folder exists under Program Files
    program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles") or r"C:\Program Files"
    sanctum_install_dir = Path(program_files) / "HydraDragonAntivirus" / "hydradragon" / "Sanctum"
    if not create_directory(sanctum_install_dir, r"C:\Program Files\HydraDragonAntivirus\hydradragon\Sanctum"):
        errors.append("Installed Sanctum directory creation")

    # 2. Dynamic System32 Deployment (EDR DLL)
    print("\nDeploying EDR component to System32...")
    base_dir = Path(__file__).parent.absolute()
    sanctum_dir = base_dir.parent
    local_dll_source = sanctum_dir / "System32" / "sanctum.dll"

    # Target: Real Windows System32
    win_system32 = Path(os.environ["SystemRoot"]) / "System32"
    final_dest = win_system32 / "sanctum.dll"

    if local_dll_source.exists():
        prev_value = ctypes.c_void_p()
        try:
            # Disable WOW64 Redirection to ensure we hit 64-bit System32
            ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(prev_value))

            shutil.copy2(str(local_dll_source), str(final_dest))

            # Re-enable Redirection
            ctypes.windll.kernel32.Wow64RevertWow64FsRedirection(prev_value)
            print(f"✓ Successfully deployed: {final_dest}")
        except Exception as e:
            ctypes.windll.kernel32.Wow64RevertWow64FsRedirection(prev_value)
            print(f"ERROR: Failed to copy to System32: {e}", file=sys.stderr)
            errors.append("System32 DLL deployment")
    else:
        print(f"WARNING: Source DLL not found at {local_dll_source}. Skipping deployment.", file=sys.stderr)

    # 3. Configure BCD settings
    if not configure_bcd():
        errors.append("BCD configuration")

    # 4. Summary
    print("\n" + "=" * 70)
    if errors:
        print("⚠ Setup completed with warnings/errors:")
        for error in errors:
            print(f"  - {error}")
        print("\nPlease review the errors above and retry if necessary.")
        sys.exit(1)
    else:
        print("✓ Clean VM setup complete!")
        print("\nCreated directories:")
        print(f"  - {sanctum_install_dir}")
        print("\nPlease follow the remaining instructions to complete installation.")
        print("=" * 70)
        sys.exit(0)


if __name__ == "__main__":
    main()
