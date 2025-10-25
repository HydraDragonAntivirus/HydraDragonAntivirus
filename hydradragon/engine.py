#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import subprocess
from datetime import datetime, timedelta

# Ensure the script's directory is the working directory
main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)

# Add the main directory to sys.path to allow absolute imports
if main_dir not in sys.path:
    sys.path.insert(0, main_dir)

from hydradragon.antivirus_scripts.antivirus import logger

# --- Import paths ---
from hydradragon.antivirus_scripts.path_and_variables import (
    async_executor,
    freshclam_path,
    hayabusa_path,
    clamav_file_paths,
)

# --- Import necessary functions from antivirus script ---
from hydradragon.antivirus_scripts.antivirus import (
    start_real_time_protection_async,  # Async function (not generator)
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
            proc = subprocess.Popen(
                [freshclam_path],
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
# Main Service Loops
# ---------------------------

async def run_periodic_updates(interval_seconds=3600):
    """
    Runs the update check every N seconds (default 1 hour = 3600s).
    """
    logger.info(f"Starting periodic update loop. Check interval: {interval_seconds} seconds.")
    while True:
        try:
            # Run the blocking update functions in a separate thread
            await asyncio.to_thread(update_definitions_sync)
        except Exception:
            logger.exception("Error in periodic update loop")
        
        logger.info(f"Update check complete. Sleeping for {interval_seconds} seconds...")
        await asyncio.sleep(interval_seconds)

async def main():
    """
    Main entry point for the headless EDR service.
    """
    loop = asyncio.get_event_loop()
    loop.set_default_executor(async_executor)
    
    logger.info("--- HydraDragon EDR Service Starting ---")

    # 1. Run an initial update check immediately on start
    #    Run in a thread so it doesn't block startup
    logger.info("Running initial definition update on startup...")
    asyncio.create_task(asyncio.to_thread(update_definitions_sync))

    # 2. Start the real-time protection
    logger.info("Starting real-time protection...")
    rtp_task = asyncio.create_task(start_real_time_protection_async())

    # 3. Start the periodic update loop (check every 1 hour)
    update_loop_task = asyncio.create_task(run_periodic_updates(interval_seconds=3600))

    # 4. Wait for tasks to complete (which they shouldn't, unless they crash)
    #    This will keep the main coroutine alive.
    try:
        await asyncio.gather(rtp_task, update_loop_task)
    except Exception:
        logger.exception("A critical service task has failed.")
    finally:
        logger.info("--- HydraDragon EDR Service Shutting Down ---")
