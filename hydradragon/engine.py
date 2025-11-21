#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import concurrent.futures
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

# ==============================================================================
# Thread Pool Setup
# ==============================================================================

# Bounded thread pool to prevent thread exhaustion
_THREAD_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=50,
    thread_name_prefix="HydraWorker"
)
logger.info("[INIT] Created bounded thread pool (max_workers=50)")

# ==============================================================================
# Async to Thread Helper
# ==============================================================================

async def async_to_thread(func, *args, operation_name="UNKNOWN", timeout=300, **kwargs):
    """Run blocking function in thread pool."""
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(_THREAD_POOL, lambda: func(*args, **kwargs)),
        timeout=timeout
    )

# ==============================================================================
# Exception Handling
# ==============================================================================

def handle_task_exception(loop, context):
    """Global handler for uncaught task exceptions."""
    exception = context.get('exception')
    message = context.get('message', 'No message')
    task = context.get('task')

    logger.error("=" * 60)
    logger.error(f"[TASK EXCEPTION] {message}")
    if task:
        logger.error(f"[TASK] {task.get_name()}: done={task.done()}, cancelled={task.cancelled()}")
    if exception:
        logger.exception("Exception details:", exc_info=exception)
    logger.error("=" * 60)

def create_safe_task(coro, *, name=None):
    """Create task with automatic exception logging."""
    async def wrapped():
        try:
            return await coro
        except asyncio.CancelledError:
            logger.info(f"[TASK] Cancelled: {name or 'unnamed'}")
            raise
        except Exception as e:
            logger.exception(f"[TASK] Failed: {name or 'unnamed'} - {e}")
            raise

    return asyncio.create_task(wrapped(), name=name)


# ==============================================================================
# Definition Updates
# ==============================================================================

async def update_definitions_clamav_async():
    """Checks and updates ClamAV virus definitions if older than 12 hours."""
    logger.info("[UPDATES] Checking ClamAV definitions...")

    try:
        if not os.path.exists(freshclam_path):
            logger.error(f"[UPDATES] freshclam not found at '{freshclam_path}'")
            return False

        # Check if definitions are older than 12 hours
        needs_update = any(
            not os.path.exists(fp) or
            (datetime.now() - datetime.fromtimestamp(os.path.getmtime(fp))) > timedelta(hours=12)
            for fp in clamav_file_paths
        )

        if needs_update:
            logger.info("[UPDATES] Definitions older than 12h. Running freshclam...")

            if not clamav_folder:
                logger.error("[UPDATES] clamav_folder path missing")
                return False

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
                    logger.info("[UPDATES] Reloading ClamAV database...")

                    await async_to_thread(
                        reload_clamav_database,
                        operation_name="DATABASE_RELOAD",
                        timeout=120
                    )

                    logger.info("[UPDATES] ✓ ClamAV definitions updated")
                    return True
                else:
                    logger.error(f"[UPDATES] ✗ freshclam failed (code {process.returncode})")
                    return False

            except asyncio.TimeoutError:
                logger.error("[UPDATES] ✗ freshclam timed out")
                process.kill()
                await process.wait()
                return False
        else:
            logger.info("[UPDATES] ✓ ClamAV definitions up to date")
            return True

    except Exception as e:
        logger.exception(f"[UPDATES] ClamAV update failed: {e}")
        return False


async def update_definitions_hayabusa_async():
    """Updates Hayabusa rules."""
    logger.info("[UPDATES] Updating Hayabusa rules...")

    try:
        if not os.path.exists(hayabusa_path):
            logger.error(f"[UPDATES] Hayabusa not found at: {hayabusa_path}")
            return False

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
                    logger.info(f"[Hayabusa] {line}")
            if stderr:
                for line in stderr.decode('utf-8', errors='ignore').splitlines():
                    logger.warning(f"[Hayabusa ERR] {line}")

            if process.returncode == 0:
                logger.info("[UPDATES] ✓ Hayabusa rules updated")
                return True
            else:
                logger.error(f"[UPDATES] ✗ Hayabusa failed (code {process.returncode})")
                return False

        except asyncio.TimeoutError:
            logger.error("[UPDATES] ✗ Hayabusa timed out")
            process.kill()
            await process.wait()
            return False

    except Exception as e:
        logger.exception(f"[UPDATES] Hayabusa update failed: {e}")
        return False


async def update_definitions_async():
    """Run all async update tasks concurrently."""
    logger.info("[UPDATES] Starting definition update")

    try:
        results = await asyncio.gather(
            update_definitions_clamav_async(),
            update_definitions_hayabusa_async(),
            return_exceptions=True
        )

        clamav_result, hayabusa_result = results

        if isinstance(clamav_result, Exception):
            logger.error(f"[UPDATES] ClamAV exception: {clamav_result}")
        if isinstance(hayabusa_result, Exception):
            logger.error(f"[UPDATES] Hayabusa exception: {hayabusa_result}")

    except Exception as e:
        logger.exception(f"[UPDATES] Error during update: {e}")
    finally:
        logger.info(f"[UPDATES] Update finished - {get_latest_clamav_def_time()}")


async def run_periodic_updates_async(update_interval_sec: int = 7200):
    """
    Runs update check periodically.
    First update runs immediately on startup.
    Default: 7200s (2 hours)
    """
    logger.info(f"[UPDATES] Starting periodic updates (interval: {update_interval_sec/3600:.1f}h)")

    # Run first update immediately
    try:
        await update_definitions_async()
    except Exception as e:
        logger.exception(f"[UPDATES] Error in initial update: {e}")

    # Then run periodically
    update_count = 1
    while True:
        try:
            # Sleep between updates
            await asyncio.sleep(update_interval_sec)

            # Run update
            update_count += 1
            logger.info(f"[UPDATES] Starting update #{update_count}")
            await update_definitions_async()

        except asyncio.CancelledError:
            logger.info("[UPDATES] Periodic updates cancelled")
            raise
        except Exception as e:
            logger.exception(f"[UPDATES] Error in update #{update_count}: {e}")

# ==============================================================================
# Main Entry Point
# ==============================================================================

async def main_async():
    """Main async entry point that runs all tasks concurrently."""
    logger.info("=" * 60)
    logger.info("=== HydraDragon EDR Service Starting ===")
    logger.info("=" * 60)

    loop = asyncio.get_running_loop()

    # Configure event loop
    loop.set_debug(False)  # Disable debug mode in production
    loop.set_exception_handler(handle_task_exception)
    loop.set_default_executor(_THREAD_POOL)

    logger.info("[INIT] Event loop configured")

    # Create main service tasks
    logger.info("[INIT] Creating service tasks...")
    rtp_task = create_safe_task(start_real_time_protection_async(), name="RealTimeProtection")
    updates_task = create_safe_task(run_periodic_updates_async(), name="PeriodicUpdates")

    logger.info("=" * 60)
    logger.info("[INIT] ✓ All services started")
    logger.info("[INIT] Services: RealTimeProtection, PeriodicUpdates")
    logger.info("=" * 60)

    # Wait for all tasks
    try:
        await asyncio.gather(
            rtp_task,
            updates_task,
            return_exceptions=True
        )
    except asyncio.CancelledError:
        logger.info("[INIT] Main tasks cancelled")
        raise
    except Exception as e:
        logger.exception(f"[FATAL] Error in main: {e}")
        raise


def main():
    """Synchronous entry point that starts the async event loop."""
    logger.info("[INIT] HydraDragon EDR initializing...")
    logger.info(f"[INIT] Python: {sys.version}")
    logger.info(f"[INIT] CWD: {os.getcwd()}")

    try:
        asyncio.run(main_async())

    except KeyboardInterrupt:
        logger.info("[SHUTDOWN] Received Ctrl+C")

    except Exception as e:
        logger.critical("=" * 60)
        logger.critical("[FATAL] Fatal error in main event loop")
        logger.critical("=" * 60)
        logger.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
