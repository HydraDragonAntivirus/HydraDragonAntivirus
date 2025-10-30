#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Fixed and optimized 64-bit ClamAV Python wrapper with ASYNC support
# Author: Emirhan Ucan
# Inspired by: https://github.com/clamwin/python-clamav/blob/master/clamav.py

import os
import asyncio
from ctypes import (
    CDLL, Structure, POINTER, c_uint, c_int, c_char_p, c_ulong,
    c_void_p, byref, WinDLL
)
from .hydra_logger import logger

# --- helpers ---
def _to_bytes_or_none(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise TypeError(f"Cannot convert {type(value)} to bytes")

# --- ctypes types ---
cl_engine_p = c_void_p
c_char_pp = POINTER(c_char_p)
c_ulong_p = POINTER(c_ulong)

class cl_scan_options(Structure):
    _fields_ = [
        ('general', c_uint),
        ('parse', c_uint),
        ('heuristic', c_uint),
        ('mail', c_uint),
        ('dev', c_uint),
    ]

# --- constants ---
CL_CLEAN = 0
CL_VIRUS = 1
CL_SUCCESS = 0
CL_DB_STDOPT = 0

# Scan Options
CL_SCAN_GENERAL_HEURISTICS = (1 << 2)

# Error codes
CL_EMEM = 2
CL_EOPEN = 3
CL_EMALFDB = 4
CL_EPARSE = 5

def _has_export(lib, name):
    try:
        getattr(lib, name)
        return True
    except AttributeError:
        return False

def _setup_lib_prototypes(lib, libfile):
    """
    Safe prototype setup: only assign argtypes/restype for symbols that exist.
    Returns True on success, False on unrecoverable failure.
    """
    try:
        # Required minimal functions
        if not _has_export(lib, 'cl_init'):
            logger.error(f"cl_init not found in {libfile}")
            return False
        lib.cl_init.argtypes = (c_uint,)
        lib.cl_init.restype = c_int

        if not _has_export(lib, 'cl_engine_new'):
            logger.error(f"cl_engine_new not found in {libfile}")
            return False
        lib.cl_engine_new.argtypes = None
        lib.cl_engine_new.restype = cl_engine_p

        # Optional but expected
        if _has_export(lib, 'cl_engine_free'):
            lib.cl_engine_free.argtypes = (cl_engine_p,)
            lib.cl_engine_free.restype = c_int
        else:
            logger.warning(f"cl_engine_free missing in {libfile}")

        if _has_export(lib, 'cl_load'):
            lib.cl_load.argtypes = (c_char_p, cl_engine_p, POINTER(c_uint), c_uint)
            lib.cl_load.restype = c_int
        else:
            logger.warning(f"cl_load missing in {libfile}")

        if _has_export(lib, 'cl_engine_compile'):
            lib.cl_engine_compile.argtypes = (cl_engine_p,)
            lib.cl_engine_compile.restype = c_int
        else:
            logger.warning(f"cl_engine_compile missing in {libfile}")

        if _has_export(lib, 'cl_engine_set_num'):
            lib.cl_engine_set_num.argtypes = (cl_engine_p, c_uint, c_ulong)
            lib.cl_engine_set_num.restype = c_int
        else:
            logger.debug(f"cl_engine_set_num not present in {libfile}")

        # NOTE: last arg of cl_scanfile should be pointer to cl_scan_options (your struct)
        if _has_export(lib, 'cl_scanfile'):
            lib.cl_scanfile.argtypes = [
                c_char_p,
                POINTER(c_char_p),   # virname pointer-to-pointer (c_char **)
                c_ulong_p,
                cl_engine_p,
                POINTER(cl_scan_options)
            ]
            lib.cl_scanfile.restype = c_int
        else:
            logger.warning(f"cl_scanfile missing in {libfile}")

        if _has_export(lib, 'cl_retver'):
            lib.cl_retver.argtypes = None
            lib.cl_retver.restype = c_char_p
        else:
            logger.debug(f"cl_retver not exported in {libfile}")

        if _has_export(lib, 'cl_strerror'):
            lib.cl_strerror.argtypes = (c_int,)
            lib.cl_strerror.restype = c_char_p

        logger.debug(f"Set libclamav prototypes for: {libfile}")
        return True

    except Exception as e:
        # something went wrong while setting prototypes — do not let it kill the host
        logger.exception(f"Exception while setting prototypes for {libfile}: {e}")
        return False

# --- loader ---
def load_clamav(libpath, try_add_dll_dir=True):
    """
    Robust loader: add DLL dir, try CDLL then WinDLL, set prototypes safely.
    Returns the loaded lib object or None on failure.
    """
    if not libpath or not os.path.exists(libpath):
        logger.error(f"Invalid or missing libclamav.dll path: {libpath}")
        return None

    dll_dir = os.path.dirname(os.path.abspath(libpath))

    # add DLL directory so dependencies resolve
    if try_add_dll_dir:
        try:
            logger.debug(f"Adding DLL directory: {dll_dir}")
            os.add_dll_directory(dll_dir)
        except Exception as e:
            logger.warning(f"os.add_dll_directory failed: {e}")

    last_err = None
    for loader_name, loader in (('CDLL', CDLL), ('WinDLL', WinDLL)):
        try:
            logger.debug(f"Attempting to load {libpath} using {loader_name}")
            lib = loader(libpath)
            logger.debug(f"{loader_name} loaded OK — verifying prototypes")
            ok = _setup_lib_prototypes(lib, libpath)
            if not ok:
                # prototypes failed — unload by deleting reference and try next loader
                logger.error(f"Prototype setup failed for {libpath} using {loader_name}")
                del lib
                last_err = RuntimeError("Prototype setup failure")
                continue

            logger.info(f"Loaded libclamav ({loader_name}): {libpath}")
            return lib

        except Exception as e:
            logger.exception(f"Failed to load {libpath} with {loader_name}: {e}")
            last_err = e
            # try next loader

    logger.error(f"Could not load libclamav (tried CDLL and WinDLL). Last error: {last_err}")
    return None

# --- Scanner class with ASYNC initialization ---
class Scanner:
    """
    ClamAV Scanner with async initialization support.

    Usage:
        # Async (Fire and Forget - RECOMMENDED):
        # Returns immediately, DB loads in background
        scanner = await Scanner.create_async(libclamav_path, dbpath)

        # First scan will wait for DB to be ready asynchronously
        result, virus = await scanner.scanFileAsync(filepath)

        # Check if ready (non-blocking)
        if scanner.is_ready():
            result, virus = scanner.scanFile(filepath)

        # Sync (blocks event loop - NOT recommended):
        scanner = Scanner(libclamav_path, dbpath)
    """

    def __init__(self, libclamav_path, dbpath=None, autoreload=False,
                 dboptions=CL_DB_STDOPT, engine_options=None, _skip_init=False):
        """
        DO NOT call this directly for async code!
        Use Scanner.create_async() instead.
        """
        self.libclamav = None
        self.engine = None
        self.libclamav_path = libclamav_path # Store path
        self.dbpath = dbpath # Store path
        self.autoreload = autoreload
        self.dboptions = dboptions
        self.engine_options = engine_options or self.def_engine_options()

        # --- Fields for Async Fire-and-Forget Initialization ---
        self._is_ready = False
        self._init_in_progress = False
        self._init_stage = "Not started"  # Track current initialization stage
        self.ready_event = asyncio.Event() # Event to signal initialization completion
        self._initialization_task = None
        self._init_success = False
        self._init_error = None
        self._progress_task = None  # Background task for progress logging
        # --------------------------------------------------------

        if _skip_init:
            # Used by create_async() to defer initialization
            return

        # Synchronous initialization (BLOCKS!)
        if self._init_sync(libclamav_path, dbpath):
            self._init_success = True
            self._is_ready = True
            self.ready_event.set() # Set ready for sync init
        else:
            logger.error("Scanner initialization failed")
            self._init_success = False
            self.ready_event.set() # Set 'done', but 'failed'

    @classmethod
    async def create_async(cls, libclamav_path, dbpath=None, autoreload=False,
                           dboptions=CL_DB_STDOPT, engine_options=None,
                           progress_log_interval=5):
        """
        Async factory method to create Scanner instance (FIRE AND FORGET).

        This method returns *immediately*. The database loading is started
        in a background task, preventing the event loop from freezing.
        Scan calls will wait asynchronously until the scanner is ready.

        Args:
            progress_log_interval: Log progress every N seconds (default: 5, 0 to disable)

        Returns:
            Scanner instance (not yet ready to scan)
        """
        logger.info("Starting async ClamAV initialization (background task)...")

        # Create instance, passing paths for background init
        scanner = cls(libclamav_path, dbpath, autoreload, dboptions, engine_options, _skip_init=True)

        # Start progress logging task if enabled
        if progress_log_interval > 0:
            scanner._progress_task = asyncio.create_task(
                scanner._log_init_progress(progress_log_interval)
            )

        # Start the background initialization task (FIRE AND FORGET)
        scanner._init_in_progress = True
        scanner._init_stage = "Starting"
        scanner._initialization_task = asyncio.create_task(
            scanner._init_async_task(libclamav_path, dbpath)
        )

        return scanner # IMMEDIATE RETURN

    async def _log_init_progress(self, interval):
        """Background task to log initialization progress"""
        try:
            while self._init_in_progress:
                await asyncio.sleep(interval)
                if self._init_in_progress:
                    logger.info(f"ClamAV initialization still in progress... Stage: {self._init_stage}")
        except asyncio.CancelledError:
            pass

    async def _init_async_task(self, libclamav_path, dbpath):
        """Internal task to run blocking init in a thread and set ready event."""
        try:
            logger.debug("Running background initialization (no timeout)...")
            self._init_stage = "Loading library"

            # Run the synchronous init method in a thread without timeout
            # Using a dedicated thread instead of thread pool to avoid blocking other tasks
            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,  # Uses default ThreadPoolExecutor
                self._init_sync,
                libclamav_path,
                dbpath
            )

            if success:
                logger.info("ClamAV scanner initialized successfully (background)")
                self._init_success = True
                self._is_ready = True
                self._init_stage = "Complete"
            else:
                logger.error("ClamAV initialization failed (background)")
                self._init_success = False
                self._init_error = "Initialization returned False"
                self._init_stage = "Failed"

        except Exception as e:
            logger.error(f"ClamAV async initialization error (background): {e}")
            self._init_success = False
            self._init_error = str(e)
            self._init_stage = f"Error: {e}"
        finally:
            # Signal that initialization (or attempt) is complete
            self._init_in_progress = False
            self.ready_event.set()

            # Cancel progress logging
            if self._progress_task:
                self._progress_task.cancel()

            logger.debug(f"Background initialization task completed. Final stage: {self._init_stage}")

    # --- _init_sync safety ---
    def _init_sync(self, libclamav_path, dbpath):
        try:
            self._init_stage = "Checking library path"
            if not os.path.exists(libclamav_path):
                self._init_success = False
                self._init_error = f"Library path does not exist: {libclamav_path}"
                self.ready_event.set()
                return False

            self.libclamav = load_clamav(libclamav_path)
            if not self.libclamav:
                self._init_success = False
                self._init_error = "Failed to load libclamav DLL"
                self.ready_event.set()
                return False

            res = self.libclamav.cl_init(0)
            if res != CL_SUCCESS:
                self._init_success = False
                self._init_error = f"cl_init failed with code {res}"
                self.ready_event.set()
                return False

            # Resolve DB path
            if not os.path.isabs(dbpath):
                dll_dir = os.path.dirname(os.path.abspath(libclamav_path))
                dbpath = os.path.normpath(os.path.join(dll_dir, dbpath))

            if not os.path.isdir(dbpath):
                self._init_success = False
                self._init_error = f"Database path invalid: {dbpath}"
                self.ready_event.set()
                return False

            self.dbpath = dbpath
            if not self.loadDB():
                self._init_success = False
                self._init_error = "Failed to load database"
                self.ready_event.set()
                return False

            self._init_success = True
            self._is_ready = True
            self.ready_event.set()
            return True

        except Exception as e:
            self._init_success = False
            self._init_error = str(e)
            self.ready_event.set()
            return False

    @staticmethod
    def def_engine_options():
        return {
            0: 512*1024*1024,  # CL_ENGINE_MAX_SCANSIZE
            1: 512*1024*1024,  # CL_ENGINE_MAX_FILESIZE
            2: 50,             # CL_ENGINE_MAX_RECURSION
            3: 2000            # CL_ENGINE_MAX_FILES
        }

    def get_error_message(self, error_code):
        if not self.libclamav or not hasattr(self.libclamav, 'cl_strerror'):
            return f"Error code: {error_code}"

        try:
            err_msg = self.libclamav.cl_strerror(error_code)
            if err_msg:
                return err_msg.decode('utf-8', errors='ignore')
        except Exception:
            pass

        return f"Error code: {error_code}"

    # --- loadDB fixed ---
    def loadDB(self):
        if not self.libclamav:
            logger.error("libclamav is not loaded, cannot load DB.")
            return False

        logger.debug("Loading ClamAV signature database...")

        # Free existing engine
        if self.engine:
            try:
                self.libclamav.cl_engine_free(self.engine)
            except Exception as e:
                logger.warning(f"Error freeing engine: {e}")
            self.engine = None

        # Create new engine
        try:
            self._init_stage = "Creating engine"
            self.engine = self.libclamav.cl_engine_new()
            if not self.engine:
                logger.error("Failed to create ClamAV engine")
                return False
        except Exception as e:
            logger.error(f"Exception creating engine: {e}")
            return False

        # Load database
        try:
            dbpath_b = _to_bytes_or_none(self.dbpath)
            signo = c_uint()
            self._init_stage = "Loading signatures"
            res = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))
            if res != CL_SUCCESS:
                error_msg = self.get_error_message(res)
                logger.error(f"cl_load failed: {error_msg}")
                return False

            # Apply engine options
            for opt, val in self.engine_options.items():
                res = self.libclamav.cl_engine_set_num(self.engine, opt, c_ulong(val))
                if res != CL_SUCCESS:
                    logger.warning(f"Failed to set engine option {opt}={val}: {self.get_error_message(res)}")

        except Exception as e:
            logger.error(f"Exception during cl_load: {e}")
            return False

        # Compile engine
        try:
            self._init_stage = "Compiling engine"
            res = self.libclamav.cl_engine_compile(self.engine)
            if res != CL_SUCCESS:
                error_msg = self.get_error_message(res)
                logger.error(f"cl_engine_compile failed: {error_msg}")
                return False
        except Exception as e:
            logger.error(f"Exception during cl_engine_compile: {e}")
            return False

        logger.info(f"ClamAV database ready. Signatures loaded: {signo.value}")
        return True

    def is_ready(self):
        """Check if scanner is ready (non-blocking)"""
        return self._is_ready

    def is_initializing(self):
        """Check if initialization is in progress"""
        return self._init_in_progress

    def get_init_stage(self):
        """Get current initialization stage"""
        return self._init_stage

    def get_init_error(self):
        """Get initialization error message if any"""
        return self._init_error

    async def wait_until_ready(self, check_interval=0.1):
        """
        Wait asynchronously until scanner is ready.

        Args:
            check_interval: How often to check status (seconds)

        Returns:
            bool: True if ready, False if initialization failed
        """
        if self._is_ready:
            return True

        logger.debug("Waiting for ClamAV initialization to complete...")

        # Wait for the ready event
        await self.ready_event.wait()

        if self._init_success and self._is_ready:
            logger.debug("ClamAV scanner is now ready")
            return True
        else:
            error_msg = self._init_error or "Unknown error"
            logger.error(f"ClamAV initialization failed: {error_msg}")
            return False

    async def scanFileAsync(self, filepath):
        """
        Scan file asynchronously.

        This will wait for the scanner to be ready if initialization is still in progress,
        then run the scan in a thread pool to avoid blocking the event loop.

        Returns:
            tuple: (result_code, virus_name or None)
        """
        # Wait for initialization to complete if needed
        if not self._is_ready:
            ready = await self.wait_until_ready()
            if not ready:
                logger.error("Cannot scan: Scanner initialization failed")
                return None, None

        # Run the blocking scan in a thread pool
        return await asyncio.to_thread(self.scanFile, filepath)

    # --- scanFile fixed ---
    def scanFile(self, filepath):
        if not self._is_ready:
            if self._init_in_progress:
                logger.error("Scanner not ready. Initialization still in progress. Use scanFileAsync() instead.")
            else:
                logger.error("Scanner not ready. Initialization failed.")
            return None, None

        if not self.libclamav or not self.engine:
            logger.error("Engine not initialized.")
            return None, None

        if not filepath or not os.path.exists(filepath):
            logger.error(f"File does not exist: {filepath}")
            return None, None

        try:
            fname_b = _to_bytes_or_none(filepath)

            # Initialize variables properly
            virname_pp = c_char_pp()
            bytes_scanned = c_ulong(0)

            # Scan options with heuristics
            scan_opts = cl_scan_options()
            scan_opts.general = CL_SCAN_GENERAL_HEURISTICS

            # Call cl_scanfile
            ret = self.libclamav.cl_scanfile(
                fname_b,
                byref(virname_pp),
                byref(bytes_scanned),
                self.engine,
                byref(scan_opts)
            )

            # Process results
            if ret == CL_CLEAN:
                logger.debug(f"File clean (ClamAV): {filepath}")
                return CL_CLEAN, None
            elif ret == CL_VIRUS:
                virus_name = virname_pp[0].decode("utf-8", errors="ignore") if virname_pp[0] else "Unknown"
                logger.warning(f"Virus found in {filepath}: {virus_name}")
                return CL_VIRUS, virus_name
            else:
                error_msg = self.get_error_message(ret)
                logger.error(f"Scan error for {filepath}: {error_msg}")
                return ret, None

        except Exception as e:
            logger.error(f"Exception during file scan: {e}")
            return None, None
