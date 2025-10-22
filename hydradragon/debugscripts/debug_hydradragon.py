#!/usr/bin/env python3
"""
Launcher that starts operation tracing BEFORE importing/running HydraDragon.
Ensures `operation_tracer.py` is imported and active early.
"""

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
    def monitor_threads():
        try:
            while True:
                time.sleep(THREAD_MONITOR_INTERVAL)
                threads = threading.enumerate()
                print(f"[Thread Monitor @ {time.time():.2f}] Active threads: {len(threads)}")
        except Exception:
            print("[Thread Monitor] Error in monitor loop:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    monitor_thread = threading.Thread(target=monitor_threads, daemon=True, name="ThreadMonitor")
    monitor_thread.start()
    print("[Launcher] Thread monitor started.")
else:
    print("[Launcher] Thread monitor is disabled.")

# --- Cleanup function (ensures tracing is stopped) ---
_cleanup_called = False
def _cleanup():
    global _cleanup_called
    if _cleanup_called:
        return
    _cleanup_called = True
    print("[Launcher] Cleaning up: stopping tracers...")
    try:
        operation_tracer.stop_global_tracing()
    except Exception:
        print("[Launcher] Error stopping operation tracer:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
    print("[Launcher] Cleanup finished.")

atexit.register(_cleanup)

# --- Signal handling ---
def _signal_handler(sig, frame):
    print(f"[Launcher] Signal {sig} received, initiating cleanup and exit...")
    _cleanup()
    sys.exit(1 if sig == signal.SIGTERM else 0)

signal.signal(signal.SIGINT, _signal_handler)
try:
    signal.signal(signal.SIGTERM, _signal_handler)
except AttributeError:
    pass  # SIGTERM not available on Windows

# --- Run HydraDragon main ---
if __name__ == "__main__":
    main_app_started = False
    try:
        # Start tracing BEFORE importing the main app
        print("[Launcher] Starting global operation tracing...")
        operation_tracer.start_global_tracing()
        time.sleep(0.1)  # Allow tracer to attach

        # Import HydraDragon main after tracing is active
        print("[Launcher] Importing hydradragon.engine.main...")
        from hydradragon.engine import main as hydra_main
        print("[Launcher] Import successful.")
        # Run the main application
        print("[Launcher] --- Starting HydraDragon main() ---")
        main_app_started = True
        hydra_main()
        print("[Launcher] --- HydraDragon main() returned normally ---")

    except KeyboardInterrupt:
        print("\n[Launcher] KeyboardInterrupt received during main execution.")
    except SystemExit as e:
        print(f"[Launcher] SystemExit({e.code}) called.")
        raise
    except Exception as e:
        print(f"[Launcher] CRITICAL ERROR: Exception raised from hydra_main(): {type(e).__name__}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print("[Launcher] Keeping tracer active for 10 seconds post-crash...", file=sys.stderr)
        time.sleep(10)
        sys.exit(1)
    finally:
        if main_app_started:
            print("[Launcher] Main execution finished or interrupted. Running cleanup...")
        else:
            print("[Launcher] Exiting before main app started. Running cleanup...")
        _cleanup()
        print("[Launcher] Exit.")
