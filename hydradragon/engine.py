#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import subprocess
from datetime import datetime, timedelta
import threading

# Ensure the script's directory is the working directory
main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)

# Add the main directory to sys.path to allow absolute imports
if main_dir not in sys.path:
    sys.path.insert(0, main_dir)

from hydradragon.antivirus_scripts.antivirus import logger

# --- Import paths ---
from hydradragon.antivirus_scripts.path_and_variables import (
    freshclam_path,
    hayabusa_path,
    clamav_file_paths,
    clamav_folder
)

# --- Import necessary functions from antivirus script ---
from hydradragon.antivirus_scripts.antivirus import (
    start_real_time_protection_async,
    reload_clamav_database,
    get_latest_clamav_def_time
)

# ---------------------------
# Definition Update Functions (Blocking)
# ---------------------------

def update_definitions_clamav_sync():
    """
    Checks and updates ClamAV virus definitions if they are older than 12 hours.
    This is a blocking function and should be run in a separate thread.
    """
    logger.info("[*] Checking virus definitions (ClamAV)...")
    try:
        if not os.path.exists(freshclam_path):
            logger.error(f"[!] freshclam not found at '{freshclam_path}'")
            return False

        # --- Check if definitions are older than 12 hours ---
        needs_update = any(
            not os.path.exists(fp) or
            (datetime.now() - datetime.fromtimestamp(os.path.getmtime(fp))) > timedelta(hours=12)
            for fp in clamav_file_paths
        )

        if needs_update:
            logger.info("[*] Definitions are older than 12 hours. Running freshclam update...")
            
            # --- Use the explicitly imported clamav_folder for CWD ---
            if not clamav_folder:
                logger.error("[!] clamav_folder path is missing. Cannot run freshclam safely.")
                return False

            logger.info(f"[*] CWD set to: {clamav_folder}")
            proc = subprocess.Popen(
                [freshclam_path],
                cwd=clamav_folder,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="ignore"
            )
            stdout, stderr = proc.communicate()
            if stdout:
                for line in stdout.splitlines():
                    logger.info(line)
            if stderr:
                for line in stderr.splitlines():
                    logger.warning(f"[!] {line}")
            if proc.returncode == 0:
                reload_clamav_database()
                logger.info("[+] Virus definitions updated successfully.")
                return True
            else:
                logger.error(f"[!] freshclam failed with exit code {proc.returncode}")
                return False
        else:
            logger.info("[*] ClamAV definitions are already up to date (less than 12 hours old).")
            return True
    except Exception:
        logger.exception("ClamAV update failed")
        return False

def update_definitions_hayabusa_sync():
    """
    Updates Hayabusa rules.
    This is a blocking function and should be run in a separate thread.
    """
    logger.info("[*] Updating Hayabusa rules...")
    try:
        if not os.path.exists(hayabusa_path):
            logger.error(f"[!] Hayabusa executable not found at: {hayabusa_path}")
            return False
        cmd = [hayabusa_path, "update-rules"]
        logger.info(f"[*] Running command: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            cwd=os.path.dirname(hayabusa_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="ignore"
        )
        stdout, stderr = process.communicate()
        if stdout:
            for line in stdout.splitlines():
                logger.info(f"[Hayabusa Update] {line}")
        if stderr:
            for line in stderr.splitlines():
                logger.warning(f"[Hayabusa Update ERR] {line}")
        if process.returncode == 0:
            logger.info("[+] Hayabusa rules update completed successfully!")
            return True
        else:
            logger.error(f"[!] Hayabusa rules update failed (code {process.returncode})")
            return False
    except Exception:
        logger.exception("Exception during Hayabusa rule update")
        return False

def update_definitions_sync():
    """
    Wrapper to run all synchronous update tasks sequentially.
    """
    logger.info("--- Starting scheduled definition update ---")
    try:
        update_definitions_clamav_sync()
        update_definitions_hayabusa_sync()
    except Exception:
        logger.exception("Error during synchronous update wrapper")
    finally:
        logger.info("--- Scheduled definition update finished ---")
        logger.info(f"Latest ClamAV Defs: {get_latest_clamav_def_time()}")

# ---------------------------
# Asynchronous Function Thread Wrapper
# ---------------------------

def run_rtp_in_thread_sync():
    """
    Wrapper to run the async real-time protection function in its own dedicated
    event loop within a standard thread.
    """
    logger.info("[*] Starting RTP in new dedicated thread loop...")
    try:
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run the async function until it completes (effectively forever)
        loop.run_until_complete(start_real_time_protection_async())
    except Exception:
        logger.exception("A critical RTP service task has failed within its thread.")
    finally:
        logger.info("[+] RTP thread finished.")


# ---------------------------
# Periodic Updates Loop
# ---------------------------

def run_periodic_updates_thread(update_interval_sec: float = 5.0):
    """
    Runs the update check periodically with a small delay to avoid 100% CPU usage.
    """
    logger.info(f"Starting periodic update thread (interval: {update_interval_sec}s)")
    while True:
        try:
            update_definitions_sync()
        except Exception:
            logger.exception("Error in periodic update thread loop")
        
        # The loop continues immediately after update_definitions_sync completes.

# ---------------------------
# Main Execution (Bootstrap)
# ---------------------------

def main():
    logger.info("--- HydraDragon EDR Service Starting ---")

    # 1. Run an initial update immediately
    threading.Thread(target=update_definitions_sync, daemon=False).start()

    # 2. Start real-time protection
    threading.Thread(target=run_rtp_in_thread_sync, daemon=False).start()

    # 3. Start periodic updates
    threading.Thread(target=run_periodic_updates_thread, daemon=False).start()

    logger.info("[*] All service threads started. Main thread will now wait for them.")

    # Optionally wait forever by joining non-daemon threads
    # This avoids using asyncio.Future()
    for thread in threading.enumerate():
        if thread is not threading.current_thread():
            thread.join()

if __name__ == "__main__":
    main()
