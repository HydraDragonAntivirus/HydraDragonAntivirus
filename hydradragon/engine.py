#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import concurrent.futures

# Ensure the script's directory is the working directory
main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)

# Add the main directory to sys.path to allow absolute imports
if main_dir not in sys.path:
    sys.path.insert(0, main_dir)

from hydradragon.antivirus_scripts.antivirus import logger

# --- Import paths ---
from hydradragon.antivirus_scripts.path_and_variables import hayabusa_path

# --- Import necessary functions from antivirus script ---
from hydradragon.antivirus_scripts.antivirus import start_real_time_protection_async

from hydradragon.antivirus_scripts.rule_sync import sync_dynamic_protection_rules

# ==============================================================================
# Thread Pool Setup
# ==============================================================================

# Bounded thread pool to prevent thread exhaustion
_THREAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=50, thread_name_prefix="HydraWorker")
logger.info("[INIT] Created bounded thread pool (max_workers=50)")

# ==============================================================================
# Async to Thread Helper
# ==============================================================================


async def async_to_thread(func, *args, operation_name="UNKNOWN", timeout=300, **kwargs):
    """Run blocking function in thread pool."""
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(loop.run_in_executor(_THREAD_POOL, lambda: func(*args, **kwargs)), timeout=timeout)


# ==============================================================================
# Exception Handling
# ==============================================================================


# ==============================================================================
# Definition Updates
# ==============================================================================


async def update_definitions_hayabusa_async():
    """Updates Hayabusa rules."""
    logger.info("[UPDATES] Updating Hayabusa rules...")

    try:
        if not os.path.exists(hayabusa_path):
            logger.error(f"[UPDATES] Hayabusa not found at: {hayabusa_path}")
            return False

        process = await asyncio.create_subprocess_exec(hayabusa_path, "update-rules", cwd=os.path.dirname(hayabusa_path), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1500)

            if stdout:
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    logger.info(f"[Hayabusa] {line}")
            if stderr:
                for line in stderr.decode("utf-8", errors="ignore").splitlines():
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
        hayabusa_result = await update_definitions_hayabusa_async()
        if isinstance(hayabusa_result, Exception):
            logger.error(f"[UPDATES] Hayabusa exception: {hayabusa_result}")

    except Exception as e:
        logger.exception(f"[UPDATES] Error during update: {e}")
    finally:
        logger.info("[UPDATES] Update finished")


async def run_periodic_updates_async(update_interval_sec: int = 7200):
    """
    Runs update check periodically.
    First update runs immediately on startup.
    Default: 7200s (2 hours)
    """
    logger.info(f"[UPDATES] Starting periodic updates (interval: {update_interval_sec / 3600:.1f}h)")

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

    loop.set_default_executor(_THREAD_POOL)

    logger.info("[INIT] Event loop configured")

    # Create main service tasks
    logger.info("[INIT] Creating service tasks...")
    rtp_task = asyncio.create_task(start_real_time_protection_async(), name="RealTimeProtection")
    updates_task = asyncio.create_task(run_periodic_updates_async(), name="PeriodicUpdates")

    logger.info("=" * 60)
    logger.info("[INIT] ✓ All services started")
    logger.info("[INIT] Services: RealTimeProtection, PeriodicUpdates")
    logger.info("=" * 60)

    # Wait for all tasks
    try:
        await asyncio.gather(rtp_task, updates_task, return_exceptions=True)
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

    # Synchronize dynamic protection rules (installed Sanctum path, System32 drivers, etc.) on start
    try:
        sync_dynamic_protection_rules()
    except Exception as e:
        logger.error(f"[INIT] Failed to synchronize dynamic protection rules: {e}")

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
