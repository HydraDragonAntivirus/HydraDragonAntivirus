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

# --- Import necessary functions from antivirus script ---
from hydradragon.antivirus_scripts.antivirus import start_real_time_protection_async

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

    logger.info("=" * 60)
    logger.info("[INIT] ✓ All services started")
    logger.info("[INIT] Services: RealTimeProtection, PeriodicUpdates")
    logger.info("=" * 60)

    # Wait for all tasks
    try:
        await asyncio.gather(rtp_task, return_exceptions=True)
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
