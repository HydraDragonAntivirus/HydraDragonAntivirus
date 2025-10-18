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
        """
        Robust DB loader: try loading every file in the DB directory (no extension filtering).
        Logs which files fail and continues loading the rest. Falls back to directory-level
        cl_load if individual file loads do not succeed.
        """
        if not self.libclamav:
            logger.error("libclamav is not loaded, cannot load DB.")
            return False

        logger.debug("Loading ClamAV database (robust mode, no extension filtering)...")

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

            dbpath_b = _to_bytes_or_none(self.dbpath)
            if not dbpath_b:
                logger.error("Invalid database path")
                return False

            try:
                if os.path.isdir(self.dbpath):
                    logger.debug("Database path is a directory; enumerating all files for per-file load (no extension filtering).")
                    files = sorted(os.listdir(self.dbpath))

                    # include every regular file (skip directories and hidden files), skip zero-length files
                    candidate_files = []
                    for f in files:
                        full = os.path.join(self.dbpath, f)
                        if not os.path.isfile(full):
                            continue
                        if f.startswith('.'):
                            continue
                        try:
                            if os.path.getsize(full) == 0:
                                logger.warning("Skipping zero-length file: %s", full)
                                continue
                        except Exception:
                            # if size can't be determined, still attempt to load it
                            pass
                        candidate_files.append(f)

                    loaded_any = False
                    total_signatures = 0

                    for fname in candidate_files:
                        full = os.path.join(self.dbpath, fname)
                        try:
                            logger.debug("Attempting to load DB file: %s", full)
                            full_b = _to_bytes_or_none(full)
                            local_signo = c_uint(0)
                            res = self.libclamav.cl_load(full_b, self.engine, byref(local_signo), c_uint(self.dboptions))
                            if res == CL_SUCCESS:
                                total_signatures += local_signo.value
                                loaded_any = True
                                logger.info("Loaded DB file: %s (signatures=%d)", full, local_signo.value)
                            else:
                                err_msg = self.get_error_message(res)
                                logger.error("Failed to load DB file %s: %s (code=%d)", full, err_msg, res)
                        except Exception as e:
                            logger.exception("Exception while loading DB file %s: %s", full, e)
                            # continue to next file

                    if not loaded_any:
                        # Nothing loaded — try directory-level load as a fallback
                        logger.warning("No individual DB files loaded successfully; attempting directory-level load as fallback.")
                        signo = c_uint(0)
                        res_all = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))
                        if res_all != CL_SUCCESS:
                            logger.error("Directory-level cl_load also failed: %s", self.get_error_message(res_all))
                            return False
                        else:
                            logger.info("Directory-level cl_load succeeded. Signatures: %d", signo.value)
                    else:
                        logger.debug("Per-file loading done. Total signatures accumulated (approx): %d", total_signatures)

                else:
                    # dbpath is a single file — try loading directly
                    logger.debug("Database path is a file; attempting to load directly.")
                    signo = c_uint(0)
                    res = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))
                    if res != CL_SUCCESS:
                        logger.error("cl_load failed for file %s: %s", self.dbpath, self.get_error_message(res))
                        return False

                # Apply custom engine options
                for opt, val in self.engine_options.items():
                    try:
                        res = self.libclamav.cl_engine_set_num(self.engine, opt, c_ulong(val))
                        if res != CL_SUCCESS:
                            logger.warning("Failed to set engine option %s=%s: %s", opt, val, self.get_error_message(res))
                    except Exception as e:
                        logger.warning("Exception setting engine option %s=%s: %s", opt, val, e)

            except Exception as e:
                logger.exception("Exception during cl_load stage: %s", e)
                return False

            # Compile engine
            try:
                res = self.libclamav.cl_engine_compile(self.engine)
                if res != CL_SUCCESS:
                    logger.error("cl_engine_compile failed: %s", self.get_error_message(res))
                    return False
            except Exception as e:
                logger.exception("Exception during cl_engine_compile: %s", e)
                return False

        logger.debug("ClamAV database loaded and engine compiled successfully.")
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
