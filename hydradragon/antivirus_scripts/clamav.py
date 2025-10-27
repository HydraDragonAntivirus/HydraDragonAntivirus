#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Fixed and optimized 64-bit ClamAV Python wrapper with ASYNC support
# Author: Emirhan Ucan
# Inspired by: https://github.com/clamwin/python-clamav/blob/master/clamav.py

import os
import asyncio
import threading
import queue
from ctypes import (
    c_char_p, c_ulong, byref, c_uint
)
from concurrent.futures import Future as SyncFuture

class Scanner:
    """
    ClamAV Scanner with async initialization and a dedicated serial scan worker.

    Usage (async):
        scanner = await Scanner.create_async(lib_path, db_path)
        result, virus = await scanner.scanFileAsync(filepath)

    Usage (sync):
        scanner = Scanner(lib_path, db_path)  # blocks during init
        ret, virus = scanner.scanFile(filepath)  # blocking scan (sync wrapper)

    Important:
        - Do not call scanFile() from an asyncio event loop thread.
        - Prefer scanFileAsync() from async code.
    """

    def __init__(self, libclamav_path, dbpath=None, autoreload=False,
                 dboptions=CL_DB_STDOPT, engine_options=None, _skip_init=False):
        # Public configuration
        self.libclamav_path = libclamav_path
        self.dbpath = dbpath
        self.autoreload = autoreload
        self.dboptions = dboptions
        self.engine_options = engine_options or self.def_engine_options()

        # ClamAV runtime objects
        self.libclamav = None
        self.engine = None

        # Init / state flags
        self._is_ready = False
        self._init_in_progress = False
        self._init_stage = "Not started"
        self.ready_event = asyncio.Event()
        self._initialization_task = None
        self._init_success = False
        self._init_error = None
        self._progress_task = None

        # Scan worker fields
        self._scan_queue = None            # queue.Queue of (filepath, future)
        self._scan_thread = None
        self._scan_thread_stop = threading.Event()
        self._scan_lock = threading.Lock() # protects engine calls in _do_scan
        self._scan_loop = None             # asyncio loop for setting asyncio.Future results

        if _skip_init:
            return

        # Synchronous initialization path (legacy)
        if self._init_sync(libclamav_path, dbpath):
            self._init_success = True
            self._is_ready = True
            # start scan worker when ready
            self._start_scan_worker()
            # set ready event for any waiters
            try:
                # if loop not running, this will raise — that's fine for sync use
                self.ready_event.set()
            except Exception:
                # ready_event may be tied to an asyncio loop; ignore if no loop available
                pass
        else:
            self._init_success = False
            self._init_error = "Initialization failed (sync)"
            try:
                self.ready_event.set()
            except Exception:
                pass

    # --------------------
    # Async factory
    # --------------------
    @classmethod
    async def create_async(cls, libclamav_path, dbpath=None, autoreload=False,
                           dboptions=CL_DB_STDOPT, engine_options=None,
                           progress_log_interval: float = 5.0):
        """
        Async factory that returns immediately while initialization runs in background.
        """
        logger.info("Starting async ClamAV initialization (background)...")
        scanner = cls(libclamav_path, dbpath, autoreload, dboptions, engine_options, _skip_init=True)

        # progress logger task (optional)
        if progress_log_interval and progress_log_interval > 0:
            scanner._progress_task = asyncio.create_task(scanner._log_init_progress(progress_log_interval))

        # mark init started and run background init
        scanner._init_in_progress = True
        scanner._init_stage = "Starting"
        scanner._initialization_task = asyncio.create_task(scanner._init_async_task(libclamav_path, dbpath))
        return scanner

    async def _log_init_progress(self, interval):
        try:
            while self._init_in_progress:
                await asyncio.sleep(interval)
                if self._init_in_progress:
                    logger.info(f"ClamAV initialization in progress — stage: {self._init_stage}")
        except asyncio.CancelledError:
            pass

    async def _init_async_task(self, libclamav_path, dbpath):
        """Run blocking initialization in executor and start scan worker if successful."""
        try:
            self._init_stage = "Loading library"
            loop = asyncio.get_running_loop()
            success = await loop.run_in_executor(None, self._init_sync, libclamav_path, dbpath)

            if success:
                logger.info("ClamAV initialized in background")
                self._init_success = True
                self._is_ready = True
                self._init_stage = "Complete"
                # start the scan worker thread now that engine is ready
                # capture running loop for future callbacks
                try:
                    self._scan_loop = asyncio.get_running_loop()
                except RuntimeError:
                    self._scan_loop = None
                self._start_scan_worker()
            else:
                logger.error("ClamAV background initialization failed")
                self._init_success = False
                self._init_error = "Initialization returned False"
                self._init_stage = "Failed"
        except Exception as e:
            logger.exception("Exception during async initialization: %s", e)
            self._init_success = False
            self._init_error = str(e)
            self._init_stage = f"Error: {e}"
        finally:
            self._init_in_progress = False
            try:
                self.ready_event.set()
            except Exception:
                pass
            if self._progress_task:
                self._progress_task.cancel()
            logger.debug("Background init task finished (stage: %s)", self._init_stage)

    # --------------------
    # Synchronous initialization (runs in thread)
    # --------------------
    def _init_sync(self, libclamav_path, dbpath):
        """Blocking initialization - safe to call inside executor or sync code."""
        try:
            self._init_stage = "Checking library path"
            logger.debug("Library path: %s", libclamav_path)
            if not libclamav_path or not os.path.exists(libclamav_path):
                logger.error("Invalid libclamav path: %s", libclamav_path)
                self._init_stage = "Failed: lib not found"
                return False

            self._init_stage = "Loading library (may block)"
            self.libclamav = load_clamav(libclamav_path)
            if not self.libclamav:
                logger.error("load_clamav() failed")
                self._init_stage = "Failed: load_clamav"
                return False

            self._init_stage = "Calling cl_init"
            res = self.libclamav.cl_init(0)
            logger.debug("cl_init returned: %s", res)
            if res != CL_SUCCESS:
                logger.error("cl_init failed: %s", self.get_error_message(res))
                self._init_stage = f"Failed: cl_init {res}"
                return False

            self._init_stage = "Validating DB path"
            if not dbpath or not os.path.isdir(dbpath):
                logger.error("Invalid DB path: %s", dbpath)
                self._init_stage = "Failed: invalid db path"
                return False

            self.dbpath = dbpath
            self._init_stage = "Loading DB (may block 30-60s)"
            if not self.loadDB():
                logger.error("loadDB() failed")
                self._init_stage = "Failed: loadDB"
                return False

            self._init_stage = "Complete"
            return True

        except Exception as e:
            logger.exception("Exception in _init_sync: %s", e)
            self._init_stage = f"Exception: {e}"
            return False

    # --------------------
    # Engine options helper
    # --------------------
    @staticmethod
    def def_engine_options():
        return {
            0: 512 * 1024 * 1024,  # CL_ENGINE_MAX_SCANSIZE
            1: 512 * 1024 * 1024,  # CL_ENGINE_MAX_FILESIZE
            2: 50,                 # CL_ENGINE_MAX_RECURSION
            3: 2000                # CL_ENGINE_MAX_FILES
        }

    def get_error_message(self, error_code):
        if not self.libclamav or not hasattr(self.libclamav, 'cl_strerror'):
            return f"Error code: {error_code}"
        try:
            msg = self.libclamav.cl_strerror(error_code)
            if msg:
                return msg.decode('utf-8', errors='ignore')
        except Exception:
            pass
        return f"Error code: {error_code}"

    # --------------------
    # Database loading (blocking)
    # --------------------
    def loadDB(self):
        """Blocking DB load — returns True on success."""
        if not self.libclamav:
            logger.error("libclamav not loaded")
            return False

        # Free existing engine if present
        if self.engine:
            try:
                self.libclamav.cl_engine_free(self.engine)
            except Exception:
                logger.exception("Error freeing previous engine")
            self.engine = None

        # Create new engine
        try:
            self._init_stage = "Creating engine"
            self.engine = self.libclamav.cl_engine_new()
            if not self.engine:
                logger.error("cl_engine_new failed")
                return False
        except Exception:
            logger.exception("Exception creating engine")
            return False

        # Load signatures
        try:
            signo = c_uint()
            dbpath_b = _to_bytes_or_none(self.dbpath)
            if not dbpath_b:
                logger.error("Invalid DB path encoding")
                return False

            self._init_stage = "Loading signatures"
            res = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))
            if res != CL_SUCCESS:
                logger.error("cl_load failed: %s", self.get_error_message(res))
                return False

            self._init_stage = "Applying engine options"
            for opt, val in self.engine_options.items():
                r = self.libclamav.cl_engine_set_num(self.engine, c_uint(opt), c_ulong(val))
                if r != CL_SUCCESS:
                    logger.warning("Failed to set engine option %s=%s: %s", opt, val, self.get_error_message(r))

        except Exception:
            logger.exception("Exception during cl_load")
            return False

        # Compile engine
        try:
            self._init_stage = "Compiling engine"
            r = self.libclamav.cl_engine_compile(self.engine)
            if r != CL_SUCCESS:
                logger.error("cl_engine_compile failed: %s", self.get_error_message(r))
                return False
        except Exception:
            logger.exception("Exception while compiling engine")
            return False

        logger.info("ClamAV DB loaded, signatures: %s", getattr(locals().get('signo'), 'value', 'unknown'))
        # worker will be started by caller (after loadDB returns True)
        return True

    # --------------------
    # Scan worker management
    # --------------------
    def _start_scan_worker(self):
        """Create queue and start background thread that executes scans serially."""
        if self._scan_queue is not None:
            return
        self._scan_queue = queue.Queue()
        self._scan_thread_stop.clear()

        # capture event loop for asyncio.Future callbacks if available
        try:
            self._scan_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._scan_loop = None

        self._scan_thread = threading.Thread(target=self._scan_worker, name="ClamAVScanWorker", daemon=True)
        self._scan_thread.start()
        logger.debug("Scan worker thread started")

    def _scan_worker(self):
        """Thread worker loop: process jobs from queue, perform _do_scan, set future results."""
        while not self._scan_thread_stop.is_set():
            try:
                job = self._scan_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if job is None:
                # sentinel to exit
                break

            filepath, fut = job
            try:
                result = self._do_scan(filepath)
                # set result on future (asyncio.Future or concurrent.futures.Future)
                if isinstance(fut, asyncio.Future):
                    loop = self._scan_loop or asyncio.get_event_loop()
                    loop.call_soon_threadsafe(fut.set_result, result)
                elif isinstance(fut, SyncFuture):
                    fut.set_result(result)
                else:
                    # fall back: try call set_result if exists
                    try:
                        fut.set_result(result)
                    except Exception:
                        logger.exception("Unknown future type in scan worker")
            except Exception as e:
                if isinstance(fut, asyncio.Future):
                    loop = self._scan_loop or asyncio.get_event_loop()
                    loop.call_soon_threadsafe(fut.set_exception, e)
                elif isinstance(fut, SyncFuture):
                    fut.set_exception(e)
                else:
                    logger.exception("Unhandled exception in scan worker: %s", e)
            finally:
                try:
                    self._scan_queue.task_done()
                except Exception:
                    pass

    def _do_scan(self, filepath):
        """Blocking call into libclamav; executed in worker thread."""
        if not self._is_ready or not self.engine or not self.libclamav:
            raise RuntimeError("Scanner not ready")

        if not filepath or not os.path.exists(filepath):
            logger.error("scan target does not exist: %s", filepath)
            return None, None

        fname_b = _to_bytes_or_none(filepath)
        if not fname_b:
            logger.error("Invalid file path encoding for: %s", filepath)
            return None, None

        with self._scan_lock:
            try:
                virname = c_char_p()
                bytes_scanned = c_ulong(0)
                scan_opts = cl_scan_options()
                scan_opts.general = CL_SCAN_GENERAL_HEURISTICS

                ret = self.libclamav.cl_scanfile(
                    fname_b,
                    byref(virname),
                    byref(bytes_scanned),
                    self.engine,
                    byref(scan_opts)
                )

                if ret == CL_CLEAN:
                    logger.debug("File clean: %s", filepath)
                    return CL_CLEAN, None
                elif ret == CL_VIRUS:
                    v = virname.value.decode("utf-8", errors="ignore") if virname.value else "Unknown"
                    logger.warning("Virus found: %s -> %s", filepath, v)
                    return CL_VIRUS, v
                else:
                    err = self.get_error_message(ret)
                    logger.error("Scan error (%s) for %s: %s", ret, filepath, err)
                    return ret, None
            except Exception:
                logger.exception("Exception during cl_scanfile call")
                raise

    # --------------------
    # Async scan API
    # --------------------
    async def scanFileAsync(self, filepath):
        """
        Submit a scan job to the worker and await result (non-blocking to event loop).
        Returns: (ret_code, virus_name_or_None)
        """
        # wait until init ready
        if not self._is_ready:
            ok = await self.wait_until_ready()
            if not ok:
                logger.error("Scanner not ready, cannot scan")
                return None, None

        # ensure worker running
        if self._scan_queue is None:
            self._start_scan_worker()

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._scan_queue.put((filepath, fut))
        return await fut

    # --------------------
    # Sync scan API (blocks)
    # --------------------
    def scanFile(self, filepath, timeout=None):
        """
        Blocking wrapper for synchronous code. Posts job to scan worker and waits.
        WARNING: do not call from within asyncio event loop thread.
        """
        if not self._is_ready:
            raise RuntimeError("Scanner not ready")

        if self._scan_queue is None:
            self._start_scan_worker()

        sync_fut = SyncFuture()
        self._scan_queue.put((filepath, sync_fut))
        return sync_fut.result(timeout=timeout)

    # --------------------
    # Shutdown / cleanup
    # --------------------
    def shutdown_scan_worker(self):
        """Stop worker thread cleanly."""
        if self._scan_queue is None:
            return
        try:
            self._scan_thread_stop.set()
            # send sentinel
            try:
                self._scan_queue.put(None, timeout=1)
            except Exception:
                # best effort
                pass
            if self._scan_thread:
                self._scan_thread.join(timeout=2.0)
        except Exception:
            logger.exception("Error shutting down scan worker")
        finally:
            self._scan_queue = None
            self._scan_thread = None
            self._scan_thread_stop.clear()

    async def shutdown(self):
        """Async-friendly shutdown: cancel init, shutdown worker, free engine."""
        # cancel async init tasks
        try:
            if self._initialization_task and not self._initialization_task.done():
                self._initialization_task.cancel()
                try:
                    await self._initialization_task
                except Exception:
                    pass
        except Exception:
            pass

        # cancel progress logging
        if self._progress_task:
            self._progress_task.cancel()
            try:
                await self._progress_task
            except Exception:
                pass

        # shutdown worker
        self.shutdown_scan_worker()

        # free engine (best effort)
        try:
            if self.libclamav and self.engine:
                try:
                    self.libclamav.cl_engine_free(self.engine)
                except Exception:
                    logger.exception("Error freeing engine")
                self.engine = None
        except Exception:
            pass

        # reset flags
        self._is_ready = False
        self._init_success = False

    # --------------------
    # State helpers
    # --------------------
    def is_ready(self):
        return self._is_ready

    def is_initializing(self):
        return self._init_in_progress

    def get_init_stage(self):
        return self._init_stage

    def get_init_error(self):
        return self._init_error

    async def wait_until_ready(self, check_interval=0.1):
        """Wait for initialization completion asynchronously."""
        if self._is_ready:
            return True
        try:
            await self.ready_event.wait()
        except Exception:
            pass
        return self._is_ready and self._init_success
