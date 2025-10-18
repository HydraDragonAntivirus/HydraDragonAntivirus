#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Fixed and optimized 64-bit ClamAV Python wrapper
# Author: Emirhan Ucan
# Inspired by: https://github.com/clamwin/python-clamav/blob/master/clamav.py

import os
import threading
from hydra_logger import logger
from ctypes import (
    CDLL, Structure, POINTER, c_uint, c_int, c_char_p, c_ulong,
    c_void_p, byref
)

# --- module-level synchronization & init flag ---
_clamav_lock = threading.RLock()
_clamav_inited = False

# --- helpers ---
def _to_bytes_or_none(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    return None

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

# Error codes (only some common ones)
CL_EMEM = 2
CL_EOPEN = 3
CL_EMALFDB = 4
CL_EPARSE = 5

# --- loader ---
def load_clamav(libpath):
    if not libpath or not os.path.exists(libpath):
        logger.error(f"Invalid or missing libclamav.dll path: {libpath}")
        return None

    try:
        lib = CDLL(libpath)
    except Exception as e:
        logger.error(f"Failed to load DLL: {e}")
        return None

    try:
        # define prototypes with proper types
        lib.cl_init.argtypes = (c_uint,)
        lib.cl_init.restype = c_int

        # cl_engine_new returns pointer to engine
        lib.cl_engine_new.argtypes = ()
        lib.cl_engine_new.restype = cl_engine_p

        # cl_engine_free is void in many builds
        lib.cl_engine_free.argtypes = (cl_engine_p,)
        lib.cl_engine_free.restype = None

        lib.cl_load.argtypes = (c_char_p, cl_engine_p, POINTER(c_uint), c_uint)
        lib.cl_load.restype = c_int

        lib.cl_engine_compile.argtypes = (cl_engine_p,)
        lib.cl_engine_compile.restype = c_int

        # Apply engine options
        lib.cl_engine_set_num.argtypes = (cl_engine_p, c_uint, c_ulong)
        lib.cl_engine_set_num.restype = c_int

        # cl_scanfile: const char *filename, char **virname, unsigned long *scanned, struct cl_engine *engine, struct cl_scan_options *opts
        lib.cl_scanfile.argtypes = [
            c_char_p,
            POINTER(c_char_p),
            c_ulong_p,
            cl_engine_p,
            POINTER(cl_scan_options)
        ]
        lib.cl_scanfile.restype = c_int

        lib.cl_retver.argtypes = ()
        lib.cl_retver.restype = c_char_p

        # Optional: string -> error message
        if hasattr(lib, 'cl_strerror'):
            lib.cl_strerror.argtypes = (c_int,)
            lib.cl_strerror.restype = c_char_p

        # Optional: free function to release memory allocated by clamav (for returned strings)
        if hasattr(lib, 'cl_free'):
            lib.cl_free.argtypes = (c_void_p,)
            lib.cl_free.restype = None

        logger.debug(f"Loaded libclamav: {libpath}")
        return lib

    except Exception as e:
        logger.error(f"Failed to setup function prototypes: {e}")
        return None

# --- Scanner class ---
class Scanner:
    def __init__(self, libclamav_path, dbpath=None, autoreload=False, dboptions=CL_DB_STDOPT, engine_options=None):
        self.libclamav = None
        self.engine = None
        self.dbpath = None
        self._scan_lock = threading.RLock()  # serialize scan calls for this Scanner instance

        self.libclamav = load_clamav(libclamav_path)
        if not self.libclamav:
            logger.error("Scanner could not initialize because libclamav failed to load.")
            return

        # Protect cl_init and DB/engine creation with the module-level lock
        global _clamav_inited
        with _clamav_lock:
            try:
                if not _clamav_inited:
                    res = self.libclamav.cl_init(0)
                    if res != CL_SUCCESS:
                        logger.error(f"cl_init failed with code {res}")
                        return
                    _clamav_inited = True
            except Exception as e:
                logger.error(f"cl_init exception: {e}")
                return

            # database path validation
            if dbpath is None:
                pf = os.environ.get("ProgramFiles", r"C:\\Program Files")
                dbpath = os.path.join(pf, "ClamAV", "database")

            if not os.path.isdir(dbpath):
                logger.error(f"Invalid database path: {dbpath}")
                return

            self.dbpath = dbpath
            self.autoreload = autoreload
            self.dboptions = dboptions
            self.engine_options = engine_options or self.def_engine_options()

            # Load database (this uses the same _clamav_lock internally)
            if not self.loadDB():
                logger.error("Failed to load ClamAV database")
                return

        logger.debug("Scanner initialized successfully")

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
                # lib returns bytes; decode safely
                return err_msg.decode('utf-8', errors='ignore')
        except Exception:
            pass

        return f"Error code: {error_code}"

    def loadDB(self):
        """Load ClamAV database with improved error handling"""
        if not self.libclamav:
            logger.error("libclamav is not loaded, cannot load DB.")
            return False

        logger.debug("Loading ClamAV database...")

        with _clamav_lock:
            # Free existing engine
            if self.engine:
                try:
                    # restype is None (void), safe to call
                    self.libclamav.cl_engine_free(self.engine)
                except Exception as e:
                    logger.warning(f"Error freeing engine: {e}")
                self.engine = None

            # Create new engine
            try:
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
                if not dbpath_b:
                    logger.error("Invalid database path")
                    return False

                signo = c_uint()
                res = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))

                if res != CL_SUCCESS:
                    error_msg = self.get_error_message(res)
                    logger.error(f"cl_load failed: {error_msg}")
                    return False

                # Apply custom engine options here
                for opt, val in self.engine_options.items():
                    res = self.libclamav.cl_engine_set_num(self.engine, opt, c_ulong(val))
                    if res != CL_SUCCESS:
                        logger.warning(f"Failed to set engine option {opt}={val}: {self.get_error_message(res)}")

            except Exception as e:
                logger.error(f"Exception during cl_load: {e}")
                return False

            # Compile engine
            try:
                res = self.libclamav.cl_engine_compile(self.engine)
                if res != CL_SUCCESS:
                    error_msg = self.get_error_message(res)
                    logger.error(f"cl_engine_compile failed: {error_msg}")
                    return False
            except Exception as e:
                logger.error(f"Exception during cl_engine_compile: {e}")
                return False

        logger.debug(f"ClamAV database loaded successfully. Signatures: {signo.value}")
        return True

    def scanFile(self, filepath):
        """Scan file with improved error handling and memory safety"""
        if not self.libclamav or not self.engine:
            logger.error("Engine not initialized.")
            return None, None

        if not filepath or not os.path.exists(filepath):
            logger.error(f"File does not exist: {filepath}")
            return None, None

        # Acquire the instance scan lock and also the global lock to avoid concurrent load/compile/free races.
        # Always acquire _clamav_lock first to keep lock ordering consistent.
        with _clamav_lock:
            with self._scan_lock:
                try:
                    fname_b = _to_bytes_or_none(filepath)
                    if not fname_b:
                        logger.error("Invalid file path encoding")
                        return None, None

                    # virname as c_char_p; cl_scanfile expects POINTER(c_char_p)
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
                        logger.info(f"File clean (ClamAV): {filepath}")
                        return CL_CLEAN, None

                    elif ret == CL_VIRUS:
                        virus_name = "Unknown"
                        try:
                            if virname.value:
                                virus_name = virname.value.decode("utf-8", errors="ignore")
                        except Exception:
                            virus_name = "Unknown"

                        # free returned string if cl_free exists
                        if hasattr(self.libclamav, 'cl_free'):
                            try:
                                # pass the pointer (virname) to cl_free
                                self.libclamav.cl_free(virname)
                            except Exception:
                                pass

                        logger.warning(f"Virus found in {filepath}: {virus_name}")
                        return CL_VIRUS, virus_name

                    else:
                        error_msg = self.get_error_message(ret)
                        logger.error(f"Unexpected ClamAV scan result ({ret}): {error_msg}")
                        return ret, None

                except Exception as e:
                    logger.error(f"Exception during file scan: {e}")
                    return None, None
