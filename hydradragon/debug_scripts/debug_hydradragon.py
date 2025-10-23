#!/usr/bin/env python3
"""
Async Launcher that starts operation tracing BEFORE importing/running HydraDragon.
Ensures `operation_tracer.py` is imported and active early.
"""

import asyncio
import threading
import sys
import time
import atexit
import signal
import traceback

# ---- CONFIG ----
THREAD_MONITOR_INTERVAL = 15       # Optional thread monitor interval
ENABLE_THREAD_MONITOR = False      # Enable if you want to monitor threads

# ---- Import the operation tracer ----
try:
    import operation_tracer
    print("[Launcher] Operation tracer imported.")
except Exception as e:
    print("[Launcher] CRITICAL ERROR: could not import operation_tracer:", e, file=sys.stderr)
    raise

# --- Simple thread monitor (Optional, can be noisy with tracing) ---
if ENABLE_THREAD_MONITOR:
    async def monitor_threads_async():
        try:
            while True:
                await asyncio.sleep(THREAD_MONITOR_INTERVAL)
                threads = threading.enumerate()
                print(f"[Thread Monitor @ {time.time():.2f}] Active threads: {len(threads)}")
        except asyncio.CancelledError:
            print("[Thread Monitor] Cancelled.")
            raise
        except Exception:
            print("[Thread Monitor] Error in monitor loop:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    print("[Launcher] Thread monitor will be started.")
else:
    print("[Launcher] Thread monitor is disabled.")

# --- Cleanup function (ensures tracing is stopped) ---
_cleanup_called = False
async def _cleanup_async():
    global _cleanup_called
    if _cleanup_called:
        return
    _cleanup_called = True
    print("[Launcher] Cleaning up: stopping tracers...")
    try:
        # Run blocking cleanup in thread to avoid blocking event loop
        await asyncio.to_thread(operation_tracer.stop_global_tracing)
    except Exception:
        print("[Launcher] Error stopping operation tracer:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
    print("[Launcher] Cleanup finished.")

def _cleanup_sync():
    """Synchronous cleanup for atexit (fallback)"""
    global _cleanup_called
    if _cleanup_called:
        return
    _cleanup_called = True
    print("[Launcher] Sync cleanup: stopping tracers...")
    try:
        operation_tracer.stop_global_tracing()
    except Exception:
        print("[Launcher] Error stopping operation tracer:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
    print("[Launcher] Sync cleanup finished.")

atexit.register(_cleanup_sync)

# --- Signal handling (async-aware) ---
_shutdown_event = asyncio.Event()

def _signal_handler(sig, frame):
    print(f"\n[Launcher] Signal {sig} received, initiating async cleanup and exit...")
    _shutdown_event.set()

signal.signal(signal.SIGINT, _signal_handler)
try:
    signal.signal(signal.SIGTERM, _signal_handler)
except AttributeError:
    pass  # SIGTERM not available on Windows

# --- Main async function ---
async def async_main():
    """Main async entry point for the launcher."""
    main_app_started = False
    monitor_task = None
    hydra_task = None
    
    try:
        # Start tracing BEFORE importing the main app
        print("[Launcher] Starting global operation tracing...")
        await asyncio.to_thread(operation_tracer.start_global_tracing)
        await asyncio.sleep(0.1)  # Allow tracer to attach

        # Start thread monitor if enabled
        if ENABLE_THREAD_MONITOR:
            monitor_task = asyncio.create_task(monitor_threads_async())
            print("[Launcher] Thread monitor task started.")

        # Import HydraDragon main after tracing is active
        print("[Launcher] Importing hydradragon.engine.main...")
        from hydradragon.engine import main as hydra_main
        print("[Launcher] Import successful.")
        
        # Run the main application
        print("[Launcher] --- Starting HydraDragon main() ---")
        main_app_started = True
        
        # Run main app with shutdown monitoring
        hydra_task = asyncio.create_task(hydra_main())
        
        # Wait for either the app to finish or shutdown signal
        done, pending = await asyncio.wait(
            [hydra_task, asyncio.create_task(_shutdown_event.wait())],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        if _shutdown_event.is_set():
            print("[Launcher] Shutdown signal received, cancelling main app...")
            if hydra_task and not hydra_task.done():
                hydra_task.cancel()
                try:
                    await hydra_task
                except asyncio.CancelledError:
                    print("[Launcher] Main app task cancelled successfully.")
        else:
            print("[Launcher] --- HydraDragon main() returned normally ---")

    except asyncio.CancelledError:
        print("\n[Launcher] Main launcher task cancelled.")
        raise
    except KeyboardInterrupt:
        print("\n[Launcher] KeyboardInterrupt received during main execution.")
    except SystemExit as e:
        print(f"[Launcher] SystemExit({e.code}) called.")
        raise
    except Exception as e:
        print(f"[Launcher] CRITICAL ERROR: Exception raised from hydra_main(): {type(e).__name__}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print("[Launcher] Keeping tracer active for 10 seconds post-crash...", file=sys.stderr)
        await asyncio.sleep(10)
        sys.exit(1)
    finally:
        # Cancel monitor task if running
        if monitor_task and not monitor_task.done():
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
        
        if main_app_started:
            print("[Launcher] Main execution finished or interrupted. Running cleanup...")
        else:
            print("[Launcher] Exiting before main app started. Running cleanup...")
        
        await _cleanup_async()
        print("[Launcher] Exit.")

# --- Run the async main ---
if __name__ == "__main__":
    try:
        print("[Launcher] Starting async launcher...")
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n[Launcher] KeyboardInterrupt at top level.")
    except SystemExit:
        raise
    except Exception as e:
        print(f"[Launcher] Top-level exception: {type(e).__name__}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
