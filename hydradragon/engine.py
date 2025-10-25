#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import subprocess
from datetime import datetime, timedelta
import threading
import time

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
            
            if not clamav_folder:
                logger.error("[!] clamav_folder path is missing. Cannot run freshclam safely.")
                return False

            logger.info(f"[*] CWD set to: {clamav_folder}")
            logger.info(f"[*] Executing: {freshclam_path}")
            
            try:
                # Use subprocess.run with timeout
                result = subprocess.run(
                    [freshclam_path],
                    cwd=clamav_folder,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=1500
                )
                
                if result.stdout:
                    for line in result.stdout.splitlines():
                        logger.info(f"[freshclam] {line}")
                if result.stderr:
                    for line in result.stderr.splitlines():
                        logger.warning(f"[freshclam ERR] {line}")
                
                if result.returncode == 0:
                    reload_clamav_database()
                    logger.info("[+] Virus definitions updated successfully.")
                    return True
                else:
                    logger.error(f"[!] freshclam failed with exit code {result.returncode}")
                    return False
                    
            except subprocess.TimeoutExpired:
                logger.error("[!] freshclam timed out after 5 minutes")
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
        
        try:
            # Use subprocess.run with timeout
            result = subprocess.run(
                cmd,
                cwd=os.path.dirname(hayabusa_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=1500
            )
            
            if result.stdout:
                for line in result.stdout.splitlines():
                    logger.info(f"[Hayabusa Update] {line}")
            if result.stderr:
                for line in result.stderr.splitlines():
                    logger.warning(f"[Hayabusa Update ERR] {line}")
            
            if result.returncode == 0:
                logger.info("[+] Hayabusa rules update completed successfully!")
                return True
            else:
                logger.error(f"[!] Hayabusa rules update failed (code {result.returncode})")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("[!] Hayabusa update timed out after 5 minutes")
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
# Synchronous Function Thread Wrapper
# ---------------------------

def run_rtp_in_thread_sync():
    """
    Run the async real-time protection function in a separate thread
    without manually creating an event loop.
    """
    async def rtp_runner():
        try:
            await start_real_time_protection_async()
        except Exception:
            logger.exception("A critical RTP service task has failed.")
        finally:
            logger.info("[+] RTP task finished.")

    def thread_target():
        logger.info("[*] Starting RTP in new thread via asyncio.run...")
        asyncio.run(rtp_runner())

    thread = threading.Thread(target=thread_target, daemon=True)
    thread.start()
    logger.info("[+] RTP thread started.")

# ---------------------------
# Periodic Updates Loop
# ---------------------------
def run_periodic_updates_thread(update_interval_sec: int = 7200):
    """
    Runs the update check periodically with a fixed interval.
    First update runs immediately on startup.
    """
    logger.info(f"[*] Starting periodic update thread (interval: {update_interval_sec}s)")
    
    # Run first update immediately
    logger.info("[*] Running initial definition update...")
    try:
        update_definitions_sync()
    except Exception:
        logger.exception("Error in initial update")
    
    # Then run periodically
    next_run = time.time() + update_interval_sec
    
    while True:
        sleep_time = max(0, next_run - time.time())
        logger.info(f"[*] Next update in {sleep_time/60:.1f} minutes")
        time.sleep(sleep_time)
        
        try:
            update_definitions_sync()
        except Exception:
            logger.exception("Error in periodic update")
        
        next_run += update_interval_sec

# ---------------------------
# Main Execution (Bootstrap)
# ---------------------------

def main():
    logger.info("--- HydraDragon EDR Service Starting ---")

    # 1. Start real-time protection FIRST (most important)
    threading.Thread(target=run_rtp_in_thread_sync, daemon=False, name="RTP-Thread").start()
    logger.info("[*] Real-time protection thread started")

    # 2. Start periodic updates (includes initial update)
    threading.Thread(target=run_periodic_updates_thread, daemon=False, name="Updates-Thread").start()
    logger.info("[*] Periodic update thread started")

    logger.info("[*] All service threads started. Main thread will now wait for them.")

    # Wait for non-daemon threads
    for thread in threading.enumerate():
        if thread is not threading.current_thread() and not thread.daemon:
            thread.join()

if __name__ == "__main__":
    main()
