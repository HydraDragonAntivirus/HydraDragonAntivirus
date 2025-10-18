#!/usr/bin/env python3
"""
setup.py - Robust Windows setup script to replace the .bat installer.
Run with: py -3.12 setup.py

Options:
  --dry-run       : print actions but don't perform them
  --log-file PATH : write verbose log to PATH (default: ./setup.log)
  --retries N     : number of retry attempts for commands (default: 3)
  --retry-delay S : seconds between retries (default: 5)
"""

from __future__ import annotations
import argparse
import logging
import locale
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Union
import ctypes
from ctypes import wintypes

# ----------------------
# CLI / configuration
# ----------------------
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 5  # seconds

# --- Windows Shell API helper for special folders ---
CSIDL_DESKTOPDIRECTORY = 0x0010
SHGFP_TYPE_CURRENT = 0

parser = argparse.ArgumentParser(description="Robust Windows setup script for HydraDragonAntivirus")
parser.add_argument("--dry-run", action="store_true", help="Show actions without performing them")
parser.add_argument("--log-file", default="setup.log", help="Path to log file")
parser.add_argument("--retries", type=int, default=DEFAULT_MAX_RETRIES, help="Number of retry attempts")
parser.add_argument("--retry-delay", type=int, default=DEFAULT_RETRY_DELAY, help="Seconds between retries")
args = parser.parse_args()

DRY_RUN: bool = args.dry_run
MAX_RETRIES: int = args.retries
RETRY_DELAY: int = args.retry_delay
LOGFILE: Path = Path(args.log_file)

# ----------------------
# Logging
# ----------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOGFILE, mode="a", encoding="utf-8"),
    ],
)
log = logging.getLogger("setup")

# ----------------------
# Platform guard
# ----------------------
if os.name != "nt":
    log.error("This script targets Windows only. Aborting.")
    sys.exit(2)

# ----------------------
# Path configuration (mirror your batch)
# ----------------------
def get_env_programw6432() -> Path:
    programw6432 = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
    if not programw6432:
        log.error("Neither ProgramW6432 nor ProgramFiles defined. Using C:\\Program Files as fallback.")
        programw6432 = r"C:\Program Files"
    return Path(programw6432)

PROGRAMW6432 = get_env_programw6432()
HYDRADRAGON_ROOT_PATH = PROGRAMW6432 / "HydraDragonAntivirus"
HYDRADRAGON_PATH = HYDRADRAGON_ROOT_PATH / "hydradragon"
CLAMAV_DIR = PROGRAMW6432 / "ClamAV"
SURICATA_DIR = PROGRAMW6432 / "Suricata"
NODEJS_PATH = PROGRAMW6432 / "nodejs"
PKG_UNPACKER_DIR = HYDRADRAGON_PATH / "pkg-unpacker"
CLEAN_VM_PSB_PATH = HYDRADRAGON_PATH / "Sanctum" / "clean_vm" / "installer_clean_vm.ps1"
CLEAN_VM_FOLDER = HYDRADRAGON_PATH / "Sanctum" / "clean_vm"
SANCTUM_APPDATA_PATH = HYDRADRAGON_PATH / "Sanctum" / "appdata"
SANCTUM_ROOT_PATH = HYDRADRAGON_PATH / "Sanctum"
ROAMING_SANCTUM = Path(os.environ.get("APPDATA", "")) / "Sanctum"

def _get_folder_path(csidl: int) -> str:
    """Return a Unicode folder path for the given CSIDL using SHGetFolderPathW."""
    buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    res = ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, SHGFP_TYPE_CURRENT, buf)
    if res != 0:
        raise OSError(f"SHGetFolderPathW failed with code {res}")
    return buf.value

def get_desktop() -> Path:
    """Return Path of current user's Desktop folder. Falls back to ~/Desktop on error."""
    try:
        p = _get_folder_path(CSIDL_DESKTOPDIRECTORY)
        return Path(p)
    except Exception as e:
        log.warning("SHGetFolderPathW failed, falling back to user home Desktop: %s", e)
        return Path(os.path.expanduser("~")) / "Desktop"

DESKTOP_SANCTUM = get_desktop() / "sanctum"

# ----------------------
# Helpers
# ----------------------
def run_cmd(
    cmd: Union[Sequence[str], str],
    description: str,
    retries: int = MAX_RETRIES,
    retry_delay: int = RETRY_DELAY,
    npm_clear_on_retry: bool = False,
    success_exit_codes: Optional[Iterable[int]] = None,
    always_log_output: bool = False,
) -> int:
    """
    Run a command with retries. Capture stdout and stderr and decode safely.
    - cmd: list of command + args (for shell=False) or a single string (for shell=True).
    - description: human-friendly description for logging.
    - retries/retry_delay: retry policy.
    - npm_clear_on_retry: if True and command looks like npm, run npm cache clean between attempts.
    - success_exit_codes: iterable of ints considered success; default {0}. If any returned rc is in this set, function returns 0.
    - always_log_output: if True, log output at INFO level even for successful commands.
    Returns:
        0 on success (rc in success_exit_codes), non-zero last rc on failure.
    """
    if success_exit_codes is None:
        success_codes: Set[int] = {0}
    else:
        success_codes = set(success_exit_codes)

    last_rc = 1
    prefer_enc = locale.getpreferredencoding(False) or "utf-8"
    use_shell = isinstance(cmd, str)
    cmd_str_for_log = cmd if use_shell else " ".join(cmd)

    for attempt in range(1, retries + 1):
        log.info("[%d/%d] %s: %s", attempt, retries, description, cmd_str_for_log)
        if DRY_RUN:
            log.info("DRY RUN - would run: %s", cmd_str_for_log)
            return 0
        try:
            proc = subprocess.run(
                cmd, 
                check=False, 
                shell=use_shell,
                capture_output=True
            )
            last_rc = proc.returncode
            
            # Decode stdout
            raw_out = proc.stdout or b""
            out = None
            try:
                out = raw_out.decode(prefer_enc, errors="strict")
            except Exception:
                try:
                    out = raw_out.decode("utf-8", errors="strict")
                except Exception:
                    out = raw_out.decode("latin-1", errors="replace")
            
            # Decode stderr
            raw_err = proc.stderr or b""
            err = None
            try:
                err = raw_err.decode(prefer_enc, errors="strict")
            except Exception:
                try:
                    err = raw_err.decode("utf-8", errors="strict")
                except Exception:
                    err = raw_err.decode("latin-1", errors="replace")
            
            # Combine output for logging
            combined_output = ""
            if out:
                combined_output += "STDOUT:\n" + out
            if err:
                if combined_output:
                    combined_output += "\n"
                combined_output += "STDERR:\n" + err
            
            if combined_output:
                if last_rc not in success_codes or always_log_output:
                    log.info("%s output (rc=%d):\n%s", description, last_rc, combined_output)
                else:
                    log.debug("%s output:\n%s", description, combined_output)
            if last_rc in success_codes:
                log.info("%s completed successfully (rc=%d).", description, last_rc)
                return 0
            else:
                log.warning("%s returned rc=%d (not in success codes).", description, last_rc)
        except Exception:
            log.exception("Exception while running %s:", description)
            last_rc = 1

        # Retry handling
        if attempt < retries:
            if npm_clear_on_retry and "npm" in cmd_str_for_log:
                try:
                    log.info("Clearing npm cache (force) before retry.")
                    npm_exe = shutil.which("npm.cmd") or shutil.which("npm")
                    if npm_exe and not DRY_RUN:
                        subprocess.run([npm_exe, "cache", "clean", "--force"], check=False)
                except Exception:
                    log.exception("npm cache clear failed (ignored).")
            log.info("Waiting %d seconds before retry...", retry_delay)
            time.sleep(retry_delay)

    log.error("%s failed after %d attempts (last rc=%d).", description, retries, last_rc)
    return last_rc

def ensure_parent(path: Path):
    parent = path.parent
    if not parent.exists():
        if DRY_RUN:
            log.info("DRY RUN - would create parent dir: %s", parent)
        else:
            parent.mkdir(parents=True, exist_ok=True)

def safe_delete_dir(target: Path) -> int:
    """
    Robust directory deletion.
    Returns 0 on success, non-zero on failure.
    """
    desc = f"Remove dir {target}"
    if not target.exists():
        log.info("%s - not present (treated as removed).", desc)
        return 0

    # Try a few attempts
    for attempt in range(1, MAX_RETRIES + 1):
        log.info("[%d/%d] Attempt delete: %s", attempt, MAX_RETRIES, target)
        if DRY_RUN:
            log.info("DRY RUN - would shutil.rmtree %s", target)
            return 0
        try:
            shutil.rmtree(target)
            log.info("Deleted %s (shutil.rmtree)", target)
            return 0
        except Exception as e:
            log.warning("shutil.rmtree failed for %s: %s", target, e)

        # Try takeown/icacls to fix permission issues
        try:
            log.info("Attempting takeown/icacls for %s", target)
            subprocess.run(["takeown", "/F", str(target), "/R", "/A"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.run(["icacls", str(target), "/grant", "Administrators:F", "/T", "/C"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception:
            log.exception("takeown/icacls attempt failed (ignored).")

        # PowerShell Remove-Item fallback (force, recurse). Make PowerShell output UTF-8.
        try:
            ps_cmd = [
                "powershell",
                "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Try {{ Remove-Item -LiteralPath '{str(target)}' -Recurse -Force -ErrorAction Stop; exit 0 }} Catch {{ exit 1 }}"
            ]
            rc = run_cmd(ps_cmd, f"PowerShell Remove-Item {target}", retries=1, retry_delay=0)
            if rc == 0:
                log.info("PowerShell Remove-Item succeeded for %s", target)
                return 0
        except Exception:
            log.exception("PowerShell fallback failed (ignored).")

        # Try rename to break locks and delete renamed folder
        try:
            alt = target.parent / (target.name + "_DELETE_" + str(int(time.time())))
            log.info("Attempting rename %s -> %s", target, alt)
            try:
                target.rename(alt)
            except Exception:
                log.debug("Rename failed (probably locked) for %s", target)
                alt = None
            if alt and alt.exists():
                try:
                    shutil.rmtree(alt)
                    log.info("Deleted renamed %s", alt)
                    return 0
                except Exception:
                    log.warning("Failed to delete renamed %s", alt)
        except Exception:
            log.debug("Rename attempt failed (ignored).")

        if attempt < MAX_RETRIES:
            log.info("Retrying delete after %d seconds...", RETRY_DELAY)
            time.sleep(RETRY_DELAY)

    log.error("Failed to remove directory after %d attempts: %s", MAX_RETRIES, target)
    return 1

def safe_copy_dir(src: Path, dst: Path) -> int:
    """
    Copy a directory tree robustly. Prefer robocopy when available.
    Returns 0 on success, non-zero on failure.
    """
    desc = f"Copy {src} -> {dst}"
    if not src.exists():
        log.error("Source not found: %s", src)
        return 2

    robocopy = shutil.which("robocopy")
    if robocopy:
        # Ensure dest parent exists
        ensure_parent(dst)
        # Robocopy returns bitmapped codes; 0-7 are success-ish
        cmd = [robocopy, str(src), str(dst), "/E", "/COPYALL", "/R:2", "/W:2", "/NFL", "/NDL"]
        # Let run_cmd treat 0..7 as success set; return 0 when success
        rc = run_cmd(cmd, desc, retries=MAX_RETRIES, retry_delay=RETRY_DELAY, npm_clear_on_retry=False, success_exit_codes=range(0, 8))
        if rc == 0:
            log.info("robocopy treated as success for %s -> %s", src, dst)
            return 0
        else:
            log.warning("robocopy failed for %s -> %s with rc=%d", src, dst, rc)
            # fallback to shutil copy
    # shutil fallback
    try:
        if DRY_RUN:
            log.info("DRY RUN - would copytree/shutil copy %s -> %s", src, dst)
            return 0
        if dst.exists():
            # Copy contents into existing dir
            for root, dirs, files in os.walk(src):
                rel = Path(root).relative_to(src)
                dest_dir = dst / rel
                dest_dir.mkdir(parents=True, exist_ok=True)
                for f in files:
                    sfile = Path(root) / f
                    dfile = dest_dir / f
                    shutil.copy2(sfile, dfile)
            log.info("Copied (shutil) %s -> %s", src, dst)
            return 0
        else:
            shutil.copytree(src, dst, dirs_exist_ok=True)
            log.info("Copied (shutil.copytree) %s -> %s", src, dst)
            return 0
    except Exception as e:
        log.exception("shutil copy failed: %s", e)
        return 1

def ensure_path_includes(directory: Path) -> bool:
    """
    Ensure a directory is in PATH for the current process.
    Returns True if successful, False otherwise.
    """
    if not directory.exists():
        log.warning("Directory %s does not exist", directory)
        return False
    
    # Get current PATH
    current_path = os.environ.get("PATH", "")
    dir_str = str(directory)
    
    # Check if already in PATH (case-insensitive on Windows)
    if dir_str.lower() not in current_path.lower():
        log.info("Adding to PATH: %s", dir_str)
        # Prepend to PATH so it takes precedence
        os.environ["PATH"] = f"{dir_str}{os.pathsep}{current_path}"
        log.info("Successfully added to PATH: %s", dir_str)
        return True
    else:
        log.debug("Already in PATH: %s", dir_str)
        return True

def ensure_nodejs_in_path():
    """
    Ensure Node.js bin directory is in PATH for the current process.
    This fixes the 'node is not recognized' error during npm operations.
    """
    return ensure_path_includes(NODEJS_PATH)

def verify_node_accessible():
    """
    Verify that 'node' command is accessible.
    Returns True if accessible, False otherwise.
    """
    node_exe = shutil.which("node") or shutil.which("node.exe")
    if node_exe:
        log.info("node.exe found at: %s", node_exe)
        try:
            result = subprocess.run(
                [node_exe, "--version"],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode == 0:
                log.info("Node.js version: %s", result.stdout.strip())
                return True
            else:
                log.error("node --version failed with rc=%d", result.returncode)
                return False
        except Exception as e:
            log.error("Failed to verify node: %s", e)
            return False
    else:
        log.error("node.exe not found in PATH")
        return False

# ----------------------
# Main workflow
# ----------------------
def summary_and_exit(errors: List[tuple]):
    if errors:
        log.error("Setup completed with errors:")
        for label, rc in errors:
            log.error(" - %s (rc=%s)", label, rc)
        log.error("See %s for full logs.", LOGFILE)

        if not DRY_RUN:
            try:
                subprocess.run(["notepad.exe", str(LOGFILE)], check=False)
                log.info("Opened setup log in Notepad (errors present).")
            except Exception as e:
                log.warning("Failed to open Notepad automatically: %s", e)

        sys.exit(3)
    else:
        log.info("Setup completed successfully.")
        sys.exit(0)

def main():
    errors: List[tuple] = []
    log.info("Starting setup (DRY_RUN=%s)", DRY_RUN)

    # 1. Copy clamavconfig
    clamavconf_src = HYDRADRAGON_PATH / "clamavconfig"
    if clamavconf_src.exists():
        log.info("Copying clamavconfig -> %s", CLAMAV_DIR)
        rc = safe_copy_dir(clamavconf_src, CLAMAV_DIR)
        if rc == 0:
            rc_del = safe_delete_dir(clamavconf_src)
            if rc_del != 0:
                log.warning("Failed to remove clamavconfig after copy. rc=%d", rc_del)
                errors.append(("clamavconfig delete", rc_del))
        else:
            errors.append(("clamavconfig copy", rc))
    else:
        log.info("clamavconfig directory not found.")

    # 2-3. Copy suricata.yaml & threshold.config
    hipsconfig = HYDRADRAGON_PATH / "hipsconfig"
    for cfg in ("suricata.yaml", "threshold.config"):
        src = hipsconfig / cfg
        dst = SURICATA_DIR / cfg
        if src.exists():
            try:
                log.info("Copying %s -> %s", src, dst)
                ensure_parent(dst)
                if not DRY_RUN:
                    shutil.copy2(src, dst)
                log.info("Copied %s", cfg)
            except Exception as e:
                log.exception("Failed to copy %s: %s", cfg, e)
                errors.append((f"copy {cfg}", 1))
        else:
            log.info("%s not found in hipsconfig directory.", cfg)

    # 4. Copy hips rules
    hips_dir = HYDRADRAGON_PATH / "hips"
    if hips_dir.exists():
        try:
            rules_src = hips_dir / "emerging-all.rules"
            rules_dst_dir = SURICATA_DIR / "rules"
            if rules_src.exists():
                ensure_parent(rules_dst_dir / "dummy")
                if not DRY_RUN:
                    shutil.copy2(rules_src, rules_dst_dir / "emerging-all.rules")
                log.info("Copied emerging-all.rules to %s", rules_dst_dir)
            else:
                log.info("emerging-all.rules missing in hips.")
            rc_del = safe_delete_dir(hips_dir)
            if rc_del != 0:
                log.warning("Failed to remove hips directory.")
                errors.append(("hips delete", rc_del))
        except Exception:
            log.exception("hips copy/remove failed")
            errors.append(("hips copy/remove", 1))
    else:
        log.info("hips directory not found.")

    # 5. Copy database
    database_src = HYDRADRAGON_PATH / "database"
    if database_src.exists():
        rc = safe_copy_dir(database_src, CLAMAV_DIR / "database")
        if rc == 0:
            rc_del = safe_delete_dir(database_src)
            if rc_del != 0:
                log.warning("Failed to remove database folder after copy.")
                errors.append(("database delete", rc_del))
        else:
            errors.append(("database copy", rc))
    else:
        log.info("database directory not found.")

    # 6. Update ClamAV virus definitions with retry
    freshclam = CLAMAV_DIR / "freshclam.exe"
    if freshclam.exists():
        # Change to ClamAV directory so it can find its DLLs
        original_cwd = os.getcwd()
        try:
            os.chdir(str(CLAMAV_DIR))
            log.info("Changed directory to: %s", CLAMAV_DIR)
            rc = run_cmd([str(freshclam)], "ClamAV virus definitions update", 
                         retries=MAX_RETRIES, retry_delay=RETRY_DELAY, always_log_output=True)
            if rc != 0:
                errors.append(("freshclam", rc))
        finally:
            os.chdir(original_cwd)
            log.info("Restored directory to: %s", original_cwd)
    else:
        log.warning("freshclam.exe not found at %s", freshclam)

    # ------------------------------
    # Hayabusa Rules Update
    # ------------------------------
    log.info("Updating Hayabusa rules...")

    # 7. Update Hayabusa rules
    HAYABUSA_DIR = HYDRADRAGON_PATH / "hayabusa"
    HAYABUSA_EXE = HAYABUSA_DIR / "hayabusa-3.6.0-win-x64.exe"

    if HAYABUSA_EXE.exists():
        # Change to Hayabusa directory so it can find its DLLs
        original_cwd = os.getcwd()
        try:
            os.chdir(str(HAYABUSA_DIR))
            log.info("Changed directory to: %s", HAYABUSA_DIR)
            rc = run_cmd(
                [str(HAYABUSA_EXE), "update-rules"],
                "Hayabusa rules update",
                retries=MAX_RETRIES,
                retry_delay=RETRY_DELAY,
                always_log_output=True
            )
            if rc != 0:
                log.warning("Hayabusa update-rules returned rc=%d", rc)
                errors.append(("hayabusa update-rules", rc))
            else:
                log.info("Hayabusa rules updated successfully")
        finally:
            os.chdir(original_cwd)
            log.info("Restored directory to: %s", original_cwd)
    else:
        log.warning("hayabusa-3.6.0-win-x64.exe not found at %s", HAYABUSA_EXE)
        log.info("Skipping Hayabusa rules update")

    # ------------------------------
    # Sanctum Processing
    # ------------------------------
    log.info("Processing Sanctum folder...")

    # 8. Run installer_clean_vm.ps1 if present (force PowerShell to UTF-8 output)
    if CLEAN_VM_PSB_PATH.exists():
        log.info("Running installer_clean_vm.ps1...")
        # Use -Command with OutputEncoding set to UTF8 to improve decoding reliability
        ps_cmd = [
            "powershell",
            "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & '{str(CLEAN_VM_PSB_PATH)}'"
        ]
        rc = run_cmd(ps_cmd, "installer_clean_vm.ps1", retries=1, retry_delay=0)
        if rc != 0:
            log.warning("installer_clean_vm.ps1 exited with code %d", rc)
            errors.append(("installer_clean_vm.ps1", rc))
    else:
        log.info("installer_clean_vm.ps1 not found. Skipping.")

    # 9. Remove clean_vm folder
    if CLEAN_VM_FOLDER.exists():
        rc = safe_delete_dir(CLEAN_VM_FOLDER)
        if rc != 0:
            errors.append(("clean_vm delete", rc))
    else:
        log.info("clean_vm folder not found. Skipping.")

    # 10. Copy Sanctum\appdata to %APPDATA%\Sanctum and remove it
    if SANCTUM_APPDATA_PATH.exists():
        log.info("Copying Sanctum\\appdata to %s", ROAMING_SANCTUM)
        rc = safe_copy_dir(SANCTUM_APPDATA_PATH, ROAMING_SANCTUM)
        if rc == 0:
            rc_del = safe_delete_dir(SANCTUM_APPDATA_PATH)
            if rc_del != 0:
                log.warning("Failed to remove Sanctum\\appdata after copy.")
                errors.append(("sanctum appdata delete", rc_del))
        else:
            log.error("Failed to copy Sanctum\\appdata (rc=%d). Original left intact.", rc)
            errors.append(("sanctum appdata copy", rc))
    else:
        log.info("Sanctum\\appdata folder not found. Skipping.")

    # 11. Copy entire Sanctum folder to Desktop and remove original
    if SANCTUM_ROOT_PATH.exists():
        log.info("Copying Sanctum folder to Desktop: %s", DESKTOP_SANCTUM)
        rc = safe_copy_dir(SANCTUM_ROOT_PATH, DESKTOP_SANCTUM)
        if rc == 0:
            rc_del = safe_delete_dir(SANCTUM_ROOT_PATH)
            if rc_del != 0:
                log.warning("Failed to remove original Sanctum folder.")
                errors.append(("sanctum root delete", rc_del))
        else:
            log.error("Failed to copy Sanctum root (rc=%d)", rc)
            errors.append(("sanctum root copy", rc))
    else:
        log.info("Sanctum folder not found. Skipping.")

    # ------------------------------
    # Python / Development environment setup
    # ------------------------------
    log.info("Setting up Python environment...")

    if not HYDRADRAGON_ROOT_PATH.exists():
        log.error('ERROR: "%s" directory not found.', HYDRADRAGON_ROOT_PATH)
        errors.append(("missing root path", 1))
        summary_and_exit(errors)

    # 12. Create Python virtual environment inside HydraDragonAntivirus folder
    venv_dir = HYDRADRAGON_ROOT_PATH / "venv"
    try:
        import venv as venv_module  # type: ignore
        if not venv_dir.exists():
            log.info("Creating virtual environment at %s", venv_dir)
            if DRY_RUN:
                log.info("DRY RUN - venv create skipped")
            else:
                venv_module.EnvBuilder(with_pip=True).create(str(venv_dir))
        else:
            log.info("venv already exists at %s", venv_dir)
    except Exception:
        log.exception("Failed to create venv via venv module. Falling back to py -3.12 -m venv")
        # fallback: try subprocess py -3.12 -m venv
        pylauncher = shutil.which("py") or shutil.which("py.exe")
        if pylauncher:
            rc = run_cmd([pylauncher, "-3.12", "-m", "venv", str(venv_dir)], "Python venv creation (py -3.12 -m venv)")
            if rc != 0:
                errors.append(("venv create", rc))
                summary_and_exit(errors)
        else:
            errors.append(("venv create", 1))
            summary_and_exit(errors)

    # 13. Resolve venv activate script
    activate_bat = venv_dir / "Scripts" / "activate.bat"
    if not activate_bat.exists():
        log.error("Virtual environment activate.bat not found at %s", activate_bat)
        errors.append(("venv activate.bat missing", 1))
        summary_and_exit(errors)

    # 14. Upgrade pip in the venv using activate.bat
    log.info("Upgrading pip in virtual environment...")
    pip_cmd = f'"{activate_bat}" && python -m pip install --upgrade pip'
    rc = run_cmd(pip_cmd, "pip upgrade", retries=MAX_RETRIES, retry_delay=RETRY_DELAY)
    if rc != 0:
        log.warning("pip upgrade returned rc=%s (continuing anyway)", rc)

    # 15. Install Poetry in the venv
    log.info("Installing Poetry in virtual environment...")
    poetry_install_cmd = f'"{activate_bat}" && python -m pip install poetry'
    rc = run_cmd(poetry_install_cmd, "poetry installation", retries=MAX_RETRIES, retry_delay=RETRY_DELAY)
    if rc != 0:
        log.error("Failed to install Poetry. Poetry-based dependency installation will be skipped.")
        errors.append(("poetry install", rc))
        # Skip poetry operations if installation failed
        poetry_available = False
    else:
        poetry_available = True

    # 16. Poetry install dependencies if pyproject.toml exists
    pyproject = HYDRADRAGON_ROOT_PATH / "pyproject.toml"
    if pyproject.exists() and poetry_available:
        log.info("pyproject.toml found at: %s", pyproject)
        
        # Change to the project directory for Poetry operations
        original_cwd = os.getcwd()
        try:
            os.chdir(str(HYDRADRAGON_ROOT_PATH))
            log.info("Changed directory to: %s", HYDRADRAGON_ROOT_PATH)
            
            # Ensure poetry installs into the current venv
            config_cmd = f'"{activate_bat}" && poetry config virtualenvs.create false'
            rc = run_cmd(config_cmd, "poetry config virtualenvs.create false")
            if rc != 0:
                log.warning("poetry config returned rc=%s", rc)

            # Run poetry install
            install_deps_cmd = f'"{activate_bat}" && poetry install -vvv --no-interaction --no-ansi'
            rc = run_cmd(
                install_deps_cmd,
                "Poetry dependency installation",
                retries=MAX_RETRIES,
                retry_delay=RETRY_DELAY,
                always_log_output=True,
            )
            if rc != 0:
                errors.append(("poetry install deps", rc))
        finally:
            os.chdir(original_cwd)
            log.info("Restored directory to: %s", original_cwd)
    elif not poetry_available:
        log.warning("Poetry not available, skipping Poetry dependency installation.")
    else:
        log.info("No pyproject.toml found, skipping Poetry dependency installation.")

    # ------------------------------
    # NPM PACKAGES INSTALLATION
    # ------------------------------
    log.info("Installing npm packages...")
    
    # CRITICAL: Ensure Node.js is in PATH
    if not ensure_nodejs_in_path():
        log.error("Failed to add Node.js to PATH")
        errors.append(("nodejs path setup", 1))
    
    if not verify_node_accessible():
        log.error("Node.js is not accessible. NPM package installations will likely fail.")
        log.error("Please verify Node.js is properly installed at: %s", NODEJS_PATH)
        errors.append(("nodejs verification", 1))
        # Continue anyway in case npm.cmd can work without direct node access
    
    npm_cmd_path = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm_cmd_path:
        alt_npm = NODEJS_PATH / "npm.cmd"
        if alt_npm.exists():
            npm_cmd_path = str(alt_npm)
        else:
            log.warning("npm not found in PATH or at expected %s. NPM installs will be skipped.", NODEJS_PATH)
            npm_cmd_path = None

    def npm_run(args_list: List[str], desc: str) -> int:
        if not npm_cmd_path:
            log.error("Skipping %s because npm is not available", desc)
            return 1
        # Construct command string with explicit PATH setting to include Node.js
        nodejs_bin = str(NODEJS_PATH)
        cmd = f'set "PATH={nodejs_bin};%PATH%" && "{npm_cmd_path}" {" ".join(args_list)}'
        return run_cmd(cmd, desc, retries=MAX_RETRIES, retry_delay=RETRY_DELAY, npm_clear_on_retry=True)

    # 17. asar
    rc = npm_run(["install", "-g", "asar"], "asar installation")
    if rc != 0:
        errors.append(("asar install", rc))
    
    # 18. webcrack
    rc = npm_run(["install", "-g", "webcrack"], "webcrack installation")
    if rc != 0:
        errors.append(("webcrack install", rc))
    
    # 19. nexe_unpacker
    rc = npm_run(["install", "-g", "nexe_unpacker"], "nexe_unpacker installation")
    if rc != 0:
        errors.append(("nexe_unpacker install", rc))

    # 20. pkg-unpacker build
    if PKG_UNPACKER_DIR.exists():
        log.info("Building pkg-unpacker in %s", PKG_UNPACKER_DIR)
        # Save current directory
        original_cwd = os.getcwd()
        try:
            os.chdir(str(PKG_UNPACKER_DIR))
            rc = npm_run(["install"], "pkg-unpacker npm dependencies installation")
            if rc != 0:
                errors.append(("pkg-unpacker npm install", rc))
            else:
                rc = npm_run(["run", "build"], "pkg-unpacker npm project build")
                if rc != 0:
                    errors.append(("pkg-unpacker npm build", rc))
        finally:
            # Restore original directory
            os.chdir(original_cwd)
    else:
        log.info("HydraDragon pkg-unpacker folder not found, skipping npm build.")

    summary_and_exit(errors)

if __name__ == "__main__":
    main()
