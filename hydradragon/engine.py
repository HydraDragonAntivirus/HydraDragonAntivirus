#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
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
# Async Definition Update Functions
# ---------------------------

async def update_definitions_clamav_async():
    """
    Checks and updates ClamAV virus definitions if they are older than 12 hours.
    Fully asynchronous, non-blocking implementation.
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
            
            # Use asyncio subprocess for non-blocking execution
            process = await asyncio.create_subprocess_exec(
                freshclam_path,
                cwd=clamav_folder,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=1500
                )
                
                if stdout:
                    for line in stdout.decode('utf-8', errors='ignore').splitlines():
                        logger.info(f"[freshclam] {line}")
                if stderr:
                    for line in stderr.decode('utf-8', errors='ignore').splitlines():
                        logger.warning(f"[freshclam ERR] {line}")
                
                if process.returncode == 0:
                    reload_clamav_database()
                    logger.info("[+] Virus definitions updated successfully.")
                    return True
                else:
                    logger.error(f"[!] freshclam failed with exit code {process.returncode}")
                    return False
                    
            except asyncio.TimeoutError:
                logger.error("[!] freshclam timed out after 1500 seconds")
                process.kill()
                await process.wait()
                return False
        else:
            logger.info("[*] ClamAV definitions are already up to date (less than 12 hours old).")
            return True
            
    except Exception:
        logger.exception("ClamAV update failed")
        return False


async def update_definitions_hayabusa_async():
    """
    Updates Hayabusa rules.
    Fully asynchronous, non-blocking implementation.
    """
    logger.info("[*] Updating Hayabusa rules...")
    try:
        if not os.path.exists(hayabusa_path):
            logger.error(f"[!] Hayabusa executable not found at: {hayabusa_path}")
            return False
            
        logger.info(f"[*] Running command: {hayabusa_path} update-rules")
        
        # Use asyncio subprocess for non-blocking execution
        process = await asyncio.create_subprocess_exec(
            hayabusa_path,
            "update-rules",
            cwd=os.path.dirname(hayabusa_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=1500
            )
            
            if stdout:
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    logger.info(f"[Hayabusa Update] {line}")
            if stderr:
                for line in stderr.decode('utf-8', errors='ignore').splitlines():
                    logger.warning(f"[Hayabusa Update ERR] {line}")
            
            if process.returncode == 0:
                logger.info("[+] Hayabusa rules update completed successfully!")
                return True
            else:
                logger.error(f"[!] Hayabusa rules update failed (code {process.returncode})")
                return False
                
        except asyncio.TimeoutError:
            logger.error("[!] Hayabusa update timed out after 1500 seconds")
            process.kill()
            await process.wait()
            return False
                
    except Exception:
        logger.exception("Exception during Hayabusa rule update")
        return False


async def update_definitions_async():
    """
    Wrapper to run all async update tasks concurrently.
    """
    logger.info("--- Starting scheduled definition update ---")
    try:
        # Run both updates concurrently for faster completion
        await asyncio.gather(
            update_definitions_clamav_async(),
            update_definitions_hayabusa_async(),
            return_exceptions=True
        )
    except Exception:
        logger.exception("Error during async update wrapper")
    finally:
        logger.info("--- Scheduled definition update finished ---")
        logger.info(f"Latest ClamAV Defs: {get_latest_clamav_def_time()}")

# ---------------------------
# Periodic Updates Loop (Async)
# ---------------------------

async def run_periodic_updates_async(update_interval_sec: int = 7200):
    """
    Runs the update check periodically with a fixed interval.
    First update runs immediately on startup.
    """
    logger.info(f"[*] Starting periodic update task (interval: {update_interval_sec}s)")
    
    # Run first update immediately
    logger.info("[*] Running initial definition update...")
    try:
        await update_definitions_async()
    except Exception:
        logger.exception("Error in initial update")
    
    # Then run periodically
    while True:
        logger.info(f"[*] Next update in {update_interval_sec/60:.1f} minutes")
        await asyncio.sleep(update_interval_sec)
        
        try:
            await update_definitions_async()
        except Exception:
            logger.exception("Error in periodic update")

# ---------------------------
# Main Execution (Bootstrap)
# ---------------------------

async def main_async():
    """
    Main async entry point that runs all tasks concurrently.
    """
    logger.info("--- HydraDragon EDR Service Starting ---")

    # Create all tasks
    rtp_task = asyncio.create_task(start_real_time_protection_async(), name="RTP-Task")
    logger.info("[*] Real-time protection task created")

    updates_task = asyncio.create_task(run_periodic_updates_async(), name="Updates-Task")
    logger.info("[*] Periodic update task created")

    logger.info("[*] All service tasks started. Running event loop.")

    # Wait for all tasks (they should run indefinitely)
    await asyncio.gather(rtp_task, updates_task, return_exceptions=True)


def main():
    """
    Synchronous entry point that starts the async event loop.
    """
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.info("[*] Received keyboard interrupt, shutting down...")
    except Exception:
        logger.exception("Fatal error in main event loop")


if __name__ == "__main__":
    main()
