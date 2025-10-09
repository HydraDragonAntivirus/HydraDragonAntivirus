#!/usr/bin/env python3
"""
setup.py - Robust Windows setup script to replace the .bat installer.
Run with: py -3.12 setup.py

Options:
  --dry-run       : print actions but don't perform destructive operations
  --log-file PATH : write verbose log to PATH (default: ./setup.log)
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List

# ----------------------
# Configuration / Defaults
# ----------------------
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 5  # seconds

parser = argparse.ArgumentParser()
parser.add_argument("--dry-run", action="store_true", help="Show actions without performing them")
parser.add_argument("--log-file", default="setup.log", help="Path to log file")
parser.add_argument("--retries", type=int, default=DEFAULT_MAX_RETRIES, help="Number of retry attempts")
parser.add_argument("--retry-delay", type=int, default=DEFAULT_RETRY_DELAY, help="Seconds between retries")
args = parser.parse_args()

LOGFILE = Path(args.log_file)
DRY_RUN = args.dry_run
MAX_RETRIES = args.retries
RETRY_DELAY = args.retry_delay

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOGFILE, mode="a", encoding="utf-8"),
    ],
)
log = logging.getLogger("setup")

# ----------------------
# Platform checks
# ----------------------
if os.name != "nt":
    log.error("This script targets Windows only. Aborting.")
    sys.exit(2)

# ----------------------
# Helper utilities
# ----------------------
def run_cmd(cmd: List[str], description: str, retries=MAX_RETRIES, retry_delay=RETRY_DELAY, npm_clear_on_retry=False) -> int:
    """Run a command with retries. Returns final returncode."""
    last_rc = 1
    for attempt in range(1, retries + 1):
        log.info("[%d/%d] %s: %s", attempt, retries, description, " ".join(cmd))
        if DRY_RUN:
            log.info("DRY RUN - would run: %s", " ".join(cmd))
            return 0
        try:
            proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            last_rc = proc.returncode
            log.debug(proc.stdout)
            if last_rc == 0:
                log.info("%s completed successfully.", description)
                return 0
            else:
                log.warning("%s failed with exit code %d.", description, last_rc)
        except Exception as e:
            log.exception("Exception while running %s: %s", description, e)
            last_rc = 1

        if attempt < retries:
            if npm_clear_on_retry and "npm" in cmd[0].lower():
                try:
                    log.info("Clearing npm cache (force) before retry.")
                    if not DRY_RUN:
                        subprocess.run([cmd[0], "cache", "clean", "--force"], check=False)
                except Exception:
                    log.exception("npm cache clean failed (ignored).")
            log.info("Retrying after %d seconds...", retry_delay)
            time.sleep(retry_delay)
    log.error("%s failed after %d attempts (last rc=%d).", description, retries, last_rc)
    return last_rc

def ensure_parent(path: Path):
    parent = path.parent
    if not parent.exists():
        if DRY_RUN:
            log.info("DRY RUN - would create parent: %s", parent)
        else:
            parent.mkdir(parents=True, exist_ok=True)

def safe_delete_dir(target: Path) -> int:
    """
    Try to remove a directory tree robustly.
    Returns 0 on success, non-zero error code on failure.
    """
    desc = f"Remove dir {target}"
    if not target.exists():
        log.info("%s - not present, considered removed.", desc)
        return 0

    # Try shutil.rmtree first
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            log.info("[%d/%d] Attempt delete: %s", attempt, MAX_RETRIES, target)
            if DRY_RUN:
                log.info("DRY RUN - would rmtree %s", target)
                return 0
            shutil.rmtree(target, ignore_errors=False)
            log.info("Deleted %s (shutil.rmtree)", target)
            return 0
        except Exception as e:
            log.warning("shutil.rmtree failed for %s: %s", target, e)

        # try to fix permissions and retry
        try:
            log.info("Attempting takeown/icacls to reset permissions...")
            if not DRY_RUN:
                subprocess.run(["takeown", "/F", str(target), "/R", "/A"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                subprocess.run(["icacls", str(target), "/grant", "Administrators:F", "/T", "/C"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception:
            log.exception("takeown/icacls attempt failed (ignored).")

        # Next try PowerShell Remove-Item with -Force -Recurse
        try:
            ps_cmd = [
                "powershell",
                "-NoProfile", "-NonInteractive",
                "-Command",
                f"Try {{ Remove-Item -LiteralPath '{str(target)}' -Recurse -Force -ErrorAction Stop; exit 0 }} Catch {{ exit 1 }}"
            ]
            log.info("Attempting PowerShell Remove-Item fallback.")
            rc = run_cmd(ps_cmd, f"PowerShell Remove-Item {target}", retries=1, retry_delay=0)
            if rc == 0:
                log.info("PowerShell Remove-Item succeeded for %s", target)
                return 0
        except Exception:
            log.exception("PowerShell fallback failed (ignored).")

        # Try rename and then delete the renamed location
        try:
            alt = target.parent / (target.name + "_DELETE_" + str(int(time.time())))
            log.info("Attempting rename %s -> %s to break locks", target, alt)
            if DRY_RUN:
                log.info("DRY RUN - would rename")
                return 0
            target.rename(alt)
            # try to remove renamed
            try:
                shutil.rmtree(alt)
                log.info("Deleted renamed %s", alt)
                return 0
            except Exception:
                log.warning("Failed to delete renamed %s; giving up on this attempt.", alt)
        except Exception:
            log.debug("Rename attempt failed (likely locked).")

        if attempt < MAX_RETRIES:
            log.info("Waiting %d seconds before next delete attempt...", RETRY_DELAY)
            time.sleep(RETRY_DELAY)

    log.error("Failed to remove directory after %d attempts: %s", MAX_RETRIES, target)
    return 1

def safe_copy_dir(src: Path, dst: Path) -> int:
    """
    Copy a directory tree with retries. Uses shutil.copytree when possible, falls back to robocopy for robustness.
    Returns 0 on success.
    """
    desc = f"Copy {src} -> {dst}"
    if not src.exists():
        log.error("Source not found: %s", src)
        return 2
    # robocopy is robust for large trees and windows features; prefer when available
    robocopy = shutil.which("robocopy")
    if robocopy:
        # robocopy's syntax: robocopy <src> <dst> <filespec> /E /COPYALL /R:2 /W:2
        ensure_parent(dst)
        for attempt in range(1, MAX_RETRIES + 1):
            cmd = [robocopy, str(src), str(dst), "/E", "/COPYALL", "/R:2", "/W:2", "/NFL", "/NDL"]
            rc = run_cmd(cmd, desc, retries=1, retry_delay=0)
            # robocopy returns bitmapped codes; <8 is success-ish
            if rc < 8:
                log.info("robocopy finished with %d (treated as success)", rc)
                return 0
            log.warning("robocopy returned %d", rc)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
        log.error("robocopy failed for %s -> %s", src, dst)
        return rc
    else:
        # pure shutil fallback
        try:
            if DRY_RUN:
                log.info("DRY RUN - would copytree %s -> %s", src, dst)
                return 0
            if dst.exists():
                # copy contents into existing dir
                for root, dirs, files in os.walk(src):
                    rel = Path(root).relative_to(src)
                    dest_dir = dst / rel
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    for f in files:
                        s = Path(root) / f
                        d = dest_dir / f
                        shutil.copy2(s, d)
                log.info("Copied (shutil) %s -> %s", src, dst)
                return 0
            else:
                shutil.copytree(src, dst, dirs_exist_ok=True)
                log.info("Copied (shutil.copytree) %s -> %s", src, dst)
                return 0
        except Exception as e:
            log.exception("shutil copy failed: %s", e)
            return 1

def get_env_programw6432() -> Path:
    programw6432 = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
    if not programw6432:
        log.error("Neither ProgramW6432 nor ProgramFiles defined. Using C:\\Program Files as fallback.")
        programw6432 = r"C:\Program Files"
    return Path(programw6432)

# ----------------------
# Paths (mirror your batch)
# ----------------------
PROGRAMW6432 = get_env_programw6432()
HYDRADRAGON_PATH = Path(PROGRAMW6432) / "HydraDragonAntivirus" / "hydradragon"
HYDRADRAGON_ROOT_PATH = Path(PROGRAMW6432) / "HydraDragonAntivirus"
CLAMAV_DIR = Path(PROGRAMW6432) / "ClamAV"
SURICATA_DIR = Path(PROGRAMW6432) / "Suricata"
NODEJS_PATH = Path(PROGRAMW6432) / "nodejs"
PKG_UNPACKER_DIR = HYDRADRAGON_PATH / "pkg-unpacker"
CLEAN_VM_PSB_PATH = HYDRADRAGON_PATH / "Sanctum" / "clean_vm" / "installer_clean_vm.ps1"
CLEAN_VM_FOLDER = HYDRADRAGON_PATH / "Sanctum" / "clean_vm"
SANCTUM_APPDATA_PATH = HYDRADRAGON_PATH / "Sanctum" / "appdata"
SANCTUM_ROOT_PATH = HYDRADRAGON_PATH / "Sanctum"
ROAMING_SANCTUM = Path(os.environ.get("APPDATA", "")) / "Sanctum"
DESKTOP_SANCTUM = Path(os.path.expanduser("~")) / "Desktop" / "sanctum"

# ----------------------
# Main workflow (mirrors your batch)
# ----------------------
def main():
    errors = []

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
                shutil.copy2(rules_src, rules_dst_dir / "emerging-all.rules")
                log.info("Copied emerging-all.rules to %s", rules_dst_dir)
            else:
                log.info("emerging-all.rules missing in hips.")
            # remove hips folder
            rc_del = safe_delete_dir(hips_dir)
            if rc_del != 0:
                log.warning("Failed to remove hips directory.")
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
        else:
            errors.append(("database copy", rc))
    else:
        log.info("database directory not found.")

    # 6. Update ClamAV virus definitions with retry
    freshclam = CLAMAV_DIR / "freshclam.exe"
    if freshclam.exists():
        rc = run_cmd([str(freshclam),], "ClamAV virus definitions update", retries=MAX_RETRIES, retry_delay=RETRY_DELAY)
        if rc != 0:
            errors.append(("freshclam", rc))
    else:
        log.warning("freshclam.exe not found at %s", freshclam)

    # ------------------------------
    # Sanctum Processing
    # ------------------------------
    log.info("Processing Sanctum folder...")

    # 7. Run installer_clean_vm.ps1 if present
    if CLEAN_VM_PSB_PATH.exists():
        log.info("Running installer_clean_vm.ps1...")
        ps_cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", str(CLEAN_VM_PSB_PATH)]
        rc = run_cmd(ps_cmd, "installer_clean_vm.ps1", retries=1)
        if rc != 0:
            log.warning("installer_clean_vm.ps1 exited with code %d", rc)
    else:
        log.info("installer_clean_vm.ps1 not found. Skipping.")

    # 8. Remove clean_vm folder
    if CLEAN_VM_FOLDER.exists():
        rc = safe_delete_dir(CLEAN_VM_FOLDER)
        if rc != 0:
            errors.append(("clean_vm delete", rc))
    else:
        log.info("clean_vm folder not found. Skipping.")

    # 9. Copy Sanctum\\appdata to %APPDATA%\\Sanctum and remove it
    if SANCTUM_APPDATA_PATH.exists():
        log.info("Copying Sanctum\\appdata to %s", ROAMING_SANCTUM)
        rc = safe_copy_dir(SANCTUM_APPDATA_PATH, ROAMING_SANCTUM)
        if rc == 0:
            rc_del = safe_delete_dir(SANCTUM_APPDATA_PATH)
            if rc_del != 0:
                log.warning("Failed to remove appdata folder after copy.")
                errors.append(("sanctum appdata delete", rc_del))
        else:
            log.error("Failed to copy Sanctum appdata (rc=%d).", rc)
            errors.append(("sanctum appdata copy", rc))
    else:
        log.info("Sanctum\\appdata folder not found. Skipping.")

    # 10. Copy entire Sanctum folder to Desktop and remove original
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
        log.error("HydraDragon root path not found: %s", HYDRADRAGON_ROOT_PATH)
        errors.append(("missing root path", 1))
        # Fail early – original bat went to :end
        summary_and_exit(errors)

    # 11. Create Python virtual environment inside HydraDragonAntivirus folder
    venv_dir = HYDRADRAGON_ROOT_PATH / "venv"
    try:
        import venv as venv_module
        if not venv_dir.exists():
            log.info("Creating virtual environment at %s", venv_dir)
            if not DRY_RUN:
                venv_module.EnvBuilder(with_pip=True).create(str(venv_dir))
            else:
                log.info("DRY RUN - venv create skipped")
    except Exception:
        log.exception("Failed to create venv")
        errors.append(("venv create", 1))
        summary_and_exit(errors)

    # Helper: path to venv python
    venv_python = venv_dir / "Scripts" / "python.exe"
    if not venv_python.exists():
        # try py -3.12 to create environment using subprocess fallback
        log.warning("venv python not found at expected location: %s", venv_python)

    # 12. No activation inside script: use venv python directly for pip installs
    # 13. Upgrade pip with retry
    rc = run_cmd([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"], "pip upgrade", retries=MAX_RETRIES)
    if rc != 0:
        errors.append(("pip upgrade", rc))

    # 14. Install Poetry in the activated virtual environment with retry
    rc = run_cmd([str(venv_python), "-m", "pip", "install", "poetry"], "Poetry installation", retries=MAX_RETRIES)
    if rc != 0:
        errors.append(("poetry install", rc))

    # 15. Install dependencies with Poetry (if pyproject.toml exists)
    pyproject = HYDRADRAGON_ROOT_PATH / "pyproject.toml"
    if pyproject.exists():
        # Use poetry executable from venv python -m poetry if installed
        poetry_cmd = [str(venv_python), "-m", "poetry", "install"]
        rc = run_cmd(poetry_cmd, "Poetry dependency installation", retries=MAX_RETRIES)
        if rc != 0:
            errors.append(("poetry install deps", rc))
    else:
        log.info("No pyproject.toml found, skipping Poetry dependency installation.")

    # 16. Install spaCy English medium model
    rc = run_cmd([str(venv_python), "-m", "spacy", "download", "en_core_web_md"], "spaCy model installation", retries=MAX_RETRIES)
    if rc != 0:
        errors.append(("spacy model", rc))

    # ------------------------------
    # NPM PACKAGES INSTALLATION
    # ------------------------------
    log.info("Installing npm packages...")

    npm_cmd = shutil.which("npm")
    if not npm_cmd:
        # fallback to NODEJS_PATH\npm.cmd
        alt_npm = NODEJS_PATH / "npm.cmd"
        if alt_npm.exists():
            npm_cmd = str(alt_npm)
        else:
            log.warning("npm not found in PATH or at expected %s. NPM installs will be skipped.", NODEJS_PATH)
            npm_cmd = None

    def npm_run(args_list, desc):
        if not npm_cmd:
            log.error("Skipping %s because npm is not available", desc)
            return 1
        cmd = [npm_cmd] + args_list
        # On npm failures, clear cache on retry
        return run_cmd(cmd, desc, retries=MAX_RETRIES, retry_delay=RETRY_DELAY, npm_clear_on_retry=True)

    # 17. asar
    npm_run(["install", "-g", "asar"], "asar installation")
    # 18. webcrack
    npm_run(["install", "-g", "webcrack"], "webcrack installation")
    # 19. nexe_unpacker
    npm_run(["install", "-g", "nexe_unpacker"], "nexe_unpacker installation")

    # 20. Build pkg-unpacker project
    if PKG_UNPACKER_DIR.exists():
        log.info("Building pkg-unpacker project in %s", PKG_UNPACKER_DIR)
        # install dependencies
        rc = npm_run(["install"], "npm dependencies installation")
        if rc != 0:
            errors.append(("pkg-unpacker npm install", rc))
        else:
            # run build
            rc = npm_run(["run", "build"], "npm project build")
            if rc != 0:
                errors.append(("pkg-unpacker npm build", rc))
    else:
        log.info("HydraDragon pkg-unpacker folder not found, skipping npm build.")

    summary_and_exit(errors)

def summary_and_exit(errors):
    if errors:
        log.error("Setup completed with errors:")
        for label, rc in errors:
            log.error(" - %s (rc=%s)", label, rc)
        log.error("See %s for full logs.", LOGFILE)
        sys.exit(3)
    else:
        log.info("Setup completed successfully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
