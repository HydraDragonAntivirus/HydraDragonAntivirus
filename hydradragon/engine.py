#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import psutil
import time
import traceback
import threading
import concurrent.futures
from datetime import datetime, timedelta
from collections import defaultdict

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
# CRITICAL FIXES - Application Stability & Monitoring
# ==============================================================================

# 1. Global Exception Handler for Async Tasks
def handle_task_exception(loop, context):
    """
    Global handler for uncaught task exceptions.
    Prevents silent task failures that can cause random stops.
    """
    exception = context.get('exception')
    message = context.get('message', 'No message')
    task = context.get('task')
    
    logger.error("=" * 80)
    logger.error(f"[TASK EXCEPTION] {message}")
    if task:
        logger.error(f"[TASK] Name: {task.get_name()}")
        logger.error(f"[TASK] Done: {task.done()}, Cancelled: {task.cancelled()}")
    if exception:
        logger.exception("Exception details:", exc_info=exception)
    else:
        logger.error("[TASK] No exception object available")
    logger.error("=" * 80)
    
    # Don't stop the loop - just log and continue
    # This prevents one failed task from crashing the entire application


# ==============================================================================
# Thread Pool Monitoring System
# ==============================================================================

class ThreadPoolMonitor:
    """
    Monitors thread pool operations to detect hung/deadlocked threads.
    Tracks when threads enter/exit blocking operations.
    """
    
    def __init__(self):
        self.active_operations = {}  # thread_id -> (operation_name, start_time)
        self.lock = threading.Lock()
        self.operation_timeouts = defaultdict(lambda: 300)  # 5 minute default
        logger.info("[THREAD-MONITOR] Initialized")
    
    def set_timeout(self, operation_name: str, timeout_seconds: int):
        """Set custom timeout for specific operation types"""
        self.operation_timeouts[operation_name] = timeout_seconds
        logger.debug(f"[THREAD-MONITOR] Set timeout for {operation_name}: {timeout_seconds}s")
    
    def enter_operation(self, operation_name: str):
        """Call this when entering a blocking operation"""
        thread_id = threading.get_ident()
        with self.lock:
            self.active_operations[thread_id] = (operation_name, time.time())
            logger.debug(f"[THREAD-MONITOR] Thread {thread_id} entered: {operation_name}")
    
    def exit_operation(self):
        """Call this when exiting a blocking operation"""
        thread_id = threading.get_ident()
        with self.lock:
            if thread_id in self.active_operations:
                operation_name, start_time = self.active_operations.pop(thread_id)
                duration = time.time() - start_time
                if duration > 10:  # Log operations taking more than 10 seconds
                    logger.info(f"[THREAD-MONITOR] Thread {thread_id} completed: {operation_name} (took {duration:.2f}s)")
                else:
                    logger.debug(f"[THREAD-MONITOR] Thread {thread_id} completed: {operation_name} (took {duration:.2f}s)")
    
    def check_hung_threads(self) -> list:
        """
        Check for threads that have been in operations too long.
        Returns list of (thread_id, operation_name, duration) tuples.
        """
        hung_threads = []
        current_time = time.time()
        
        with self.lock:
            for thread_id, (operation_name, start_time) in self.active_operations.items():
                duration = current_time - start_time
                timeout = self.operation_timeouts[operation_name]
                
                if duration > timeout:
                    hung_threads.append((thread_id, operation_name, duration))
        
        return hung_threads
    
    def get_active_operations(self) -> dict:
        """Get copy of active operations for monitoring"""
        with self.lock:
            return dict(self.active_operations)


# Global thread pool monitor instance
thread_monitor = ThreadPoolMonitor()

# Set custom timeouts for known long-running operations
thread_monitor.set_timeout("ML_LOADING", 120)  # 2 minutes max for ML
thread_monitor.set_timeout("CLAMAV_INIT", 180)  # 3 minutes max for ClamAV
thread_monitor.set_timeout("FILE_SCAN", 60)  # 1 minute max for single file scan
thread_monitor.set_timeout("DATABASE_RELOAD", 120)  # 2 minutes for DB reload
thread_monitor.set_timeout("FRESHCLAM_UPDATE", 1800)  # 30 minutes for updates
thread_monitor.set_timeout("BLOCKING_OP", 300)  # 5 minutes default


# ==============================================================================
# Monitored Thread Pool Executor
# ==============================================================================

class MonitoredThreadPoolExecutor(concurrent.futures.ThreadPoolExecutor):
    """
    Thread pool executor that automatically monitors all operations.
    Wraps submitted functions to track enter/exit.
    """
    
    def submit(self, fn, *args, operation_name="UNKNOWN", **kwargs):
        """Override submit to add monitoring"""
        
        def monitored_fn(*args, **kwargs):
            thread_monitor.enter_operation(operation_name)
            try:
                return fn(*args, **kwargs)
            finally:
                thread_monitor.exit_operation()
        
        return super().submit(monitored_fn, *args, **kwargs)


# 2. Bounded Thread Pool with Monitoring (prevents thread exhaustion)
_THREAD_POOL = MonitoredThreadPoolExecutor(
    max_workers=50,  # Limit concurrent blocking operations
    thread_name_prefix="hydra-worker"
)
logger.info(f"[INIT] Monitored thread pool created with max_workers=50")


# ==============================================================================
# Helper Function: Run Blocking Code with Monitoring
# ==============================================================================

async def run_in_executor_monitored(func, *args, operation_name="BLOCKING_OP", timeout=None):
    """
    Run blocking function in thread pool with automatic monitoring.
    
    Args:
        func: Blocking function to run
        *args: Arguments to pass to func
        operation_name: Name for monitoring/logging
        timeout: Optional timeout in seconds
    
    Returns:
        Result of func(*args)
    
    Raises:
        asyncio.TimeoutError: If operation exceeds timeout
    """
    loop = asyncio.get_running_loop()
    
    def monitored_func():
        thread_monitor.enter_operation(operation_name)
        try:
            return func(*args)
        finally:
            thread_monitor.exit_operation()
    
    try:
        if timeout:
            return await asyncio.wait_for(
                loop.run_in_executor(_THREAD_POOL, monitored_func),
                timeout=timeout
            )
        else:
            return await loop.run_in_executor(_THREAD_POOL, monitored_func)
    except asyncio.TimeoutError:
        logger.error(f"[EXECUTOR] ❌ Operation '{operation_name}' timed out after {timeout}s")
        raise


# 3. Safe Task Creation Helper
def create_safe_task(coro, *, name=None):
    """
    Create task with automatic exception logging.
    Wraps coroutine to catch and log any unhandled exceptions.
    """
    async def wrapped():
        task_name = name or "unnamed"
        try:
            logger.debug(f"[TASK] Starting: {task_name}")
            result = await coro
            logger.debug(f"[TASK] Completed: {task_name}")
            return result
        except asyncio.CancelledError:
            logger.info(f"[TASK] Cancelled: {task_name}")
            raise  # Re-raise to properly propagate cancellation
        except Exception as e:
            logger.exception(f"[TASK] Failed: {task_name} - {e}")
            raise  # Re-raise so task.exception() works
    
    return asyncio.create_task(wrapped(), name=name)


# 4. Application Monitor (Enhanced with Thread Monitoring)
class ApplicationMonitor:
    """
    Monitors application health: tasks, memory, CPU, threads.
    Detects hung tasks and resource issues.
    NOW INCLUDES THREAD POOL MONITORING!
    """
    
    def __init__(self):
        self.task_registry = {}
        self.last_heartbeat = {}
        self.running = True
        self.start_time = time.time()
        logger.info("[MONITOR] Initialized")
    
    def register_task(self, task, name):
        """Register a task for monitoring"""
        self.task_registry[name] = task
        self.last_heartbeat[name] = time.time()
        
        # Add done callback to detect task completion/failure
        task.add_done_callback(
            lambda t: self._task_done_callback(name, t)
        )
        
        logger.debug(f"[MONITOR] Registered task: {name}")
    
    def _task_done_callback(self, name, task):
        """Handle task completion"""
        try:
            if task.cancelled():
                logger.warning(f"[MONITOR] Task '{name}' was cancelled")
            elif task.exception():
                logger.error(f"[MONITOR] Task '{name}' failed with exception")
                try:
                    exc = task.exception()
                    logger.exception(f"[MONITOR] Exception from '{name}':", exc_info=exc)
                except Exception as e:
                    logger.error(f"[MONITOR] Could not get exception from '{name}': {e}")
            else:
                logger.info(f"[MONITOR] Task '{name}' completed successfully")
        except Exception as e:
            logger.error(f"[MONITOR] Error in done callback for '{name}': {e}")
    
    async def heartbeat(self, name):
        """Update task heartbeat timestamp"""
        self.last_heartbeat[name] = time.time()
    
    async def monitor_loop(self):
        """
        Main monitoring loop - runs every 30 seconds.
        Checks for hung tasks, hung threads, memory leaks, thread exhaustion.
        """
        logger.info("[MONITOR] Starting system monitor loop...")
        
        while self.running:
            await asyncio.sleep(30)  # Check every 30 seconds
            
            try:
                current_time = time.time()
                uptime_hours = (current_time - self.start_time) / 3600
                
                # === 1. Check for hung ASYNC TASKS ===
                hung_tasks = []
                for name, last_beat in self.last_heartbeat.items():
                    age = current_time - last_beat
                    if age > 300:  # 5 minutes
                        hung_tasks.append((name, age))
                
                if hung_tasks:
                    logger.critical("=" * 80)
                    logger.critical("[MONITOR] ⚠️  HUNG ASYNC TASKS DETECTED:")
                    for task_name, age in hung_tasks:
                        logger.critical(f"  - {task_name}: no heartbeat for {age:.0f} seconds")
                    logger.critical("=" * 80)
                
                # === 2. Check for hung THREADS (NEW!) ===
                hung_threads = thread_monitor.check_hung_threads()
                
                if hung_threads:
                    logger.critical("=" * 80)
                    logger.critical("[MONITOR] ⚠️  HUNG THREADS DETECTED:")
                    for thread_id, operation_name, duration in hung_threads:
                        logger.critical(
                            f"  - Thread {thread_id}: {operation_name} "
                            f"running for {duration:.0f} seconds (DEADLOCKED?)"
                        )
                    logger.critical("=" * 80)
                    
                    # Optionally dump thread stack traces
                    try:
                        logger.critical("[MONITOR] Thread stack traces:")
                        for thread_id, operation_name, duration in hung_threads:
                            if thread_id in sys._current_frames():
                                frame = sys._current_frames()[thread_id]
                                logger.critical(f"\n=== Thread {thread_id} ({operation_name}) ===")
                                stack_lines = traceback.format_stack(frame)
                                for line in stack_lines[-10:]:  # Last 10 frames
                                    logger.critical(line.strip())
                    except Exception as e:
                        logger.error(f"[MONITOR] Could not dump thread stacks: {e}")
                
                # === 3. System resource checks ===
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                cpu_percent = process.cpu_percent(interval=1)
                thread_count = process.num_threads()
                
                # Count active async tasks
                all_tasks = asyncio.all_tasks()
                active_tasks = [t for t in all_tasks if not t.done()]
                
                # Get active thread pool operations
                active_ops = thread_monitor.get_active_operations()
                active_ops_count = len(active_ops)
                
                # Log system status
                logger.info(
                    f"[MONITOR] "
                    f"Uptime: {uptime_hours:.1f}h | "
                    f"Memory: {memory_mb:.1f}MB | "
                    f"CPU: {cpu_percent:.1f}% | "
                    f"Threads: {thread_count} | "
                    f"Tasks: {len(active_tasks)}/{len(all_tasks)} | "
                    f"ThreadOps: {active_ops_count}/50"
                )
                
                # Log active thread operations if any
                if active_ops_count > 0:
                    logger.debug(f"[MONITOR] Active thread operations:")
                    for thread_id, (op_name, start_time) in list(active_ops.items())[:5]:
                        duration = current_time - start_time
                        logger.debug(f"  - Thread {thread_id}: {op_name} ({duration:.1f}s)")
                
                # Resource warnings
                if memory_mb > 2000:
                    logger.warning(f"[MONITOR] ⚠️  HIGH MEMORY: {memory_mb:.1f}MB (>2GB)")
                
                if thread_count > 200:
                    logger.warning(f"[MONITOR] ⚠️  HIGH THREAD COUNT: {thread_count} (>200)")
                
                if len(active_tasks) > 500:
                    logger.warning(f"[MONITOR] ⚠️  HIGH TASK COUNT: {len(active_tasks)} (>500)")
                
                if active_ops_count > 40:
                    logger.warning(f"[MONITOR] ⚠️  HIGH THREAD POOL USAGE: {active_ops_count}/50")
                
                # Check event loop health
                loop = asyncio.get_running_loop()
                if loop.is_closed():
                    logger.critical("[MONITOR] ❌ EVENT LOOP IS CLOSED!")
                    self.running = False
                    break
                
                # Check if event loop is responsive
                loop_time = loop.time()
                logger.debug(f"[MONITOR] Event loop time: {loop_time:.2f}")
                    
            except Exception as e:
                logger.exception(f"[MONITOR] Error in monitor loop: {e}")
        
        logger.warning("[MONITOR] Monitor loop stopped")


# Global monitor instance
monitor = ApplicationMonitor()


# 5. Monitored Task Wrapper
async def monitored_task(name, coro):
    """
    Wrap a coroutine with monitoring and automatic registration.
    Returns the created task.
    """
    task = create_safe_task(coro, name=name)
    monitor.register_task(task, name)
    logger.info(f"[MONITOR] Created monitored task: {name}")
    return task


# 6. Periodic Task Logger
async def log_active_tasks():
    """Periodically log active tasks for debugging"""
    logger.info("[TASK-LOGGER] Starting periodic task logger...")
    
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        
        try:
            tasks = asyncio.all_tasks()
            active = [t for t in tasks if not t.done()]
            done = [t for t in tasks if t.done()]
            
            logger.info("=" * 80)
            logger.info(f"[TASK-LOGGER] Active: {len(active)}, Done: {len(done)}, Total: {len(tasks)}")
            
            # Log top 15 active tasks by name
            if active:
                task_names = [t.get_name() for t in active[:15]]
                logger.info(f"[TASK-LOGGER] Top active tasks:")
                for i, name in enumerate(task_names, 1):
                    logger.info(f"  {i}. {name}")
            
            # Check for tasks with exceptions
            failed_tasks = []
            for t in done:
                try:
                    if t.exception():
                        failed_tasks.append(t.get_name())
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
            
            if failed_tasks:
                logger.warning(f"[TASK-LOGGER] Tasks with exceptions: {', '.join(failed_tasks[:5])}")
            
            # Log thread pool status
            active_ops = thread_monitor.get_active_operations()
            if active_ops:
                logger.info(f"[TASK-LOGGER] Active thread operations: {len(active_ops)}")
                current_time = time.time()
                for thread_id, (op_name, start_time) in list(active_ops.items())[:5]:
                    duration = current_time - start_time
                    logger.info(f"  - {op_name}: {duration:.1f}s")
            
            logger.info("=" * 80)
                
        except Exception as e:
            logger.error(f"[TASK-LOGGER] Error logging tasks: {e}")


# ==============================================================================
# END OF CRITICAL FIXES
# ==============================================================================


# ---------------------------
# Async Definition Update Functions
# ---------------------------

async def update_definitions_clamav_async():
    """
    Checks and updates ClamAV virus definitions if they are older than 12 hours.
    Fully asynchronous, non-blocking implementation.
    """
    logger.info("[UPDATES] Checking ClamAV virus definitions...")
    
    # Send heartbeat
    await monitor.heartbeat("PeriodicUpdates")
    
    try:
        if not os.path.exists(freshclam_path):
            logger.error(f"[UPDATES] freshclam not found at '{freshclam_path}'")
            return False

        # --- Check if definitions are older than 12 hours ---
        needs_update = any(
            not os.path.exists(fp) or
            (datetime.now() - datetime.fromtimestamp(os.path.getmtime(fp))) > timedelta(hours=12)
            for fp in clamav_file_paths
        )

        if needs_update:
            logger.info("[UPDATES] Definitions are older than 12 hours. Running freshclam update...")

            if not clamav_folder:
                logger.error("[UPDATES] clamav_folder path is missing. Cannot run freshclam safely.")
                return False

            logger.info(f"[UPDATES] CWD set to: {clamav_folder}")
            logger.info(f"[UPDATES] Executing: {freshclam_path}")

            # Use asyncio subprocess for non-blocking execution
            process = await asyncio.create_subprocess_exec(
                freshclam_path,
                cwd=clamav_folder,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                # Send heartbeat before long operation
                await monitor.heartbeat("PeriodicUpdates")
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=1500  # 25 minute timeout
                )

                if stdout:
                    for line in stdout.decode('utf-8', errors='ignore').splitlines():
                        logger.info(f"[freshclam] {line}")
                if stderr:
                    for line in stderr.decode('utf-8', errors='ignore').splitlines():
                        logger.warning(f"[freshclam ERR] {line}")

                if process.returncode == 0:
                    logger.info("[UPDATES] Reloading ClamAV database...")
                    
                    # Use monitored executor for database reload
                    await run_in_executor_monitored(
                        reload_clamav_database,
                        operation_name="DATABASE_RELOAD",
                        timeout=120
                    )
                    
                    logger.info("[UPDATES] ✓ ClamAV definitions updated successfully")
                    return True
                else:
                    logger.error(f"[UPDATES] ✗ freshclam failed with exit code {process.returncode}")
                    return False

            except asyncio.TimeoutError:
                logger.error("[UPDATES] ✗ freshclam timed out after 1500 seconds")
                process.kill()
                await process.wait()
                return False
        else:
            logger.info("[UPDATES] ✓ ClamAV definitions are up to date (less than 12 hours old)")
            return True

    except Exception as e:
        logger.exception(f"[UPDATES] ClamAV update failed: {e}")
        return False


async def update_definitions_hayabusa_async():
    """
    Updates Hayabusa rules.
    Fully asynchronous, non-blocking implementation.
    """
    logger.info("[UPDATES] Updating Hayabusa rules...")
    
    # Send heartbeat
    await monitor.heartbeat("PeriodicUpdates")
    
    try:
        if not os.path.exists(hayabusa_path):
            logger.error(f"[UPDATES] Hayabusa executable not found at: {hayabusa_path}")
            return False

        logger.info(f"[UPDATES] Running command: {hayabusa_path} update-rules")

        # Use asyncio subprocess for non-blocking execution
        process = await asyncio.create_subprocess_exec(
            hayabusa_path,
            "update-rules",
            cwd=os.path.dirname(hayabusa_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            # Send heartbeat before long operation
            await monitor.heartbeat("PeriodicUpdates")
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=1500  # 25 minute timeout
            )

            if stdout:
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    logger.info(f"[Hayabusa] {line}")
            if stderr:
                for line in stderr.decode('utf-8', errors='ignore').splitlines():
                    logger.warning(f"[Hayabusa ERR] {line}")

            if process.returncode == 0:
                logger.info("[UPDATES] ✓ Hayabusa rules updated successfully")
                return True
            else:
                logger.error(f"[UPDATES] ✗ Hayabusa update failed (code {process.returncode})")
                return False

        except asyncio.TimeoutError:
            logger.error("[UPDATES] ✗ Hayabusa update timed out after 1500 seconds")
            process.kill()
            await process.wait()
            return False

    except Exception as e:
        logger.exception(f"[UPDATES] Hayabusa update failed: {e}")
        return False


async def update_definitions_async():
    """
    Wrapper to run all async update tasks concurrently.
    """
    logger.info("=" * 80)
    logger.info("[UPDATES] Starting scheduled definition update")
    logger.info("=" * 80)
    
    # Send heartbeat
    await monitor.heartbeat("PeriodicUpdates")
    
    try:
        # Run both updates concurrently for faster completion
        results = await asyncio.gather(
            update_definitions_clamav_async(),
            update_definitions_hayabusa_async(),
            return_exceptions=True
        )
        
        # Check results
        clamav_result, hayabusa_result = results
        
        if isinstance(clamav_result, Exception):
            logger.error(f"[UPDATES] ClamAV update exception: {clamav_result}")
        
        if isinstance(hayabusa_result, Exception):
            logger.error(f"[UPDATES] Hayabusa update exception: {hayabusa_result}")
        
    except Exception as e:
        logger.exception(f"[UPDATES] Error during async update wrapper: {e}")
    finally:
        logger.info("=" * 80)
        logger.info("[UPDATES] Scheduled definition update finished")
        logger.info(f"[UPDATES] {get_latest_clamav_def_time()}")
        logger.info("=" * 80)


# ---------------------------
# Periodic Updates Loop (Async)
# ---------------------------

async def run_periodic_updates_async(update_interval_sec: int = 7200):
    """
    Runs the update check periodically with a fixed interval.
    First update runs immediately on startup.
    Default interval: 7200 seconds (2 hours)
    """
    logger.info(f"[UPDATES] Starting periodic update task (interval: {update_interval_sec}s = {update_interval_sec/3600:.1f}h)")

    # Run first update immediately
    logger.info("[UPDATES] Running initial definition update...")
    try:
        await update_definitions_async()
    except Exception as e:
        logger.exception(f"[UPDATES] Error in initial update: {e}")

    # Then run periodically
    update_count = 1
    while True:
        try:
            logger.info(f"[UPDATES] Next update in {update_interval_sec/60:.1f} minutes")
            
            # Sleep with periodic heartbeats
            for _ in range(update_interval_sec // 30):  # Every 30 seconds
                await asyncio.sleep(30)
                await monitor.heartbeat("PeriodicUpdates")
            
            # Run update
            update_count += 1
            logger.info(f"[UPDATES] Starting update #{update_count}")
            await update_definitions_async()
            
        except asyncio.CancelledError:
            logger.info("[UPDATES] Periodic updates cancelled")
            raise
        except Exception as e:
            logger.exception(f"[UPDATES] Error in periodic update #{update_count}: {e}")
            # Continue running despite errors


# ---------------------------
# Main Execution (Bootstrap)
# ---------------------------

async def main_async():
    """
    Main async entry point that runs all tasks concurrently.
    Configures event loop and starts all services.
    """
    logger.info("=" * 80)
    logger.info("=== HydraDragon EDR Service Starting ===")
    logger.info("=" * 80)
    
    # Get event loop and configure it
    loop = asyncio.get_running_loop()
    
    # Enable debug mode (helps catch issues like slow callbacks)
    loop.set_debug(True)
    logger.info("[INIT] Event loop debug mode enabled")
    
    # Set custom exception handler
    loop.set_exception_handler(handle_task_exception)
    logger.info("[INIT] Global exception handler configured")
    
    # Set default executor to our bounded thread pool
    loop.set_default_executor(_THREAD_POOL)
    logger.info("[INIT] Bounded thread pool set as default executor")
    
    # Start system monitor
    logger.info("[INIT] Starting system monitor...")
    monitor_task = create_safe_task(
        monitor.monitor_loop(),
        name="SystemMonitor"
    )
    
    # Start task logger
    logger.info("[INIT] Starting task logger...")
    log_task = create_safe_task(
        log_active_tasks(),
        name="TaskLogger"
    )
    
    # Create main service tasks with monitoring
    logger.info("[INIT] Creating real-time protection task...")
    rtp_task = await monitored_task(
        "RealTimeProtection",
        start_real_time_protection_async()
    )

    logger.info("[INIT] Creating periodic updates task...")
    updates_task = await monitored_task(
        "PeriodicUpdates",
        run_periodic_updates_async()
    )

    logger.info("=" * 80)
    logger.info("[INIT] ✓ All service tasks started successfully")
    logger.info("[INIT] Services: RealTimeProtection, PeriodicUpdates, SystemMonitor, TaskLogger")
    logger.info("[INIT] Event loop is now running...")
    logger.info("=" * 80)

    # Wait for all tasks (they should run indefinitely)
    try:
        await asyncio.gather(
            monitor_task,
            rtp_task,
            updates_task,
            log_task,
            return_exceptions=True
        )
    except asyncio.CancelledError:
        logger.info("[INIT] Main tasks cancelled")
        raise
    except Exception as e:
        logger.exception(f"[FATAL] Error in main task gather: {e}")
        raise


def main():
    """
    Synchronous entry point that starts the async event loop.
    Handles graceful shutdown and error reporting.
    """
    logger.info("[INIT] HydraDragon EDR initializing...")
    logger.info(f"[INIT] Python version: {sys.version}")
    logger.info(f"[INIT] Working directory: {os.getcwd()}")
    
    try:
        # Run the async main
        asyncio.run(main_async())
        
    except KeyboardInterrupt:
        logger.info("\n" + "=" * 80)
        logger.info("[SHUTDOWN] Received keyboard interrupt (Ctrl+C)")
        logger.info("=" * 80)
        
        # Give tasks time to cleanup
        logger.info("[SHUTDOWN] Waiting for tasks to cleanup...")
        try:
            # Create new event loop for cleanup
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Get all tasks and cancel them
            tasks = asyncio.all_tasks(loop)
            for task in tasks:
                task.cancel()
            
            # Wait briefly for cancellation
            loop.run_until_complete(asyncio.sleep(2))
            loop.close()
            
        except Exception as e:
            logger.error(f"[SHUTDOWN] Error during cleanup: {e}")
        
        logger.info("[SHUTDOWN] ✓ Shutdown complete")
        sys.exit(0)
        
    except Exception as e:
        logger.critical("=" * 80)
        logger.critical("[FATAL] Fatal error in main event loop")
        logger.critical("=" * 80)
        logger.exception(e)
        
        # Dump debug info
        try:
            logger.critical("\n[DEBUG] Thread dump:")
            for thread_id, frame in sys._current_frames().items():
                logger.critical(f"\nThread {thread_id}:")
                logger.critical(''.join(traceback.format_stack(frame)))
        except Exception as dump_error:
            logger.error(f"[DEBUG] Could not dump threads: {dump_error}")
        
        # Try to dump async tasks
        try:
            logger.critical("\n[DEBUG] Async task dump:")
            tasks = asyncio.all_tasks()
            for i, task in enumerate(tasks, 1):
                logger.critical(f"{i}. {task.get_name()}: done={task.done()}, cancelled={task.cancelled()}")
        except Exception as task_dump_error:
            logger.error(f"[DEBUG] Could not dump tasks: {task_dump_error}")
        
        # Dump thread pool status
        try:
            logger.critical("\n[DEBUG] Thread pool operations:")
            active_ops = thread_monitor.get_active_operations()
            if active_ops:
                current_time = time.time()
                for thread_id, (op_name, start_time) in active_ops.items():
                    duration = current_time - start_time
                    logger.critical(f"  Thread {thread_id}: {op_name} ({duration:.1f}s)")
            else:
                logger.critical("  No active thread operations")
        except Exception as pool_dump_error:
            logger.error(f"[DEBUG] Could not dump thread pool: {pool_dump_error}")
        
        sys.exit(1)


if __name__ == "__main__":
    main()
