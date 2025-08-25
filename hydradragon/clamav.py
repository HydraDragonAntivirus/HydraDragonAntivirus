#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Fixed 64-bit ClamAV Python wrapper with improved error handling
# Author: Emirhan Ucan
# Inspired by: https://github.com/clamwin/python-clamav/blob/master/clamav.py

import os
import logging
from ctypes import (
    CDLL, Structure, POINTER, c_uint, c_int, c_char_p, c_ulong,
    c_void_p, byref
)

logging.basicConfig(level=logging.INFO, format='[clamav-wrapper] %(levelname)s: %(message)s')

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

# Error codes
CL_EMEM = 2
CL_EOPEN = 3
CL_EMALFDB = 4
CL_EPARSE = 5

# --- loader ---
def load_clamav(libpath):
    if not libpath or not os.path.exists(libpath):
        logging.error(f"Invalid or missing libclamav.dll path: {libpath}")
        return None

    try:
        lib = CDLL(libpath)
    except Exception as e:
        logging.error(f"Failed to load DLL: {e}")
        return None

    try:
        # define prototypes with proper error checking
        lib.cl_init.argtypes = (c_uint,)
        lib.cl_init.restype = c_int

        lib.cl_engine_new.argtypes = None
        lib.cl_engine_new.restype = cl_engine_p

        lib.cl_engine_free.argtypes = (cl_engine_p,)
        lib.cl_engine_free.restype = c_int

        lib.cl_load.argtypes = (c_char_p, cl_engine_p, POINTER(c_uint), c_uint)
        lib.cl_load.restype = c_int

        lib.cl_engine_compile.argtypes = (cl_engine_p,)
        lib.cl_engine_compile.restype = c_int

        # Fixed scanfile prototype - removed POINTER from cl_scan_options
        lib.cl_scanfile.argtypes = [
            c_char_p, POINTER(c_char_p), POINTER(c_ulong), cl_engine_p, c_uint
        ]
        lib.cl_scanfile.restype = c_int

        lib.cl_retver.argtypes = None
        lib.cl_retver.restype = c_char_p

        # Add error message function
        if hasattr(lib, 'cl_strerror'):
            lib.cl_strerror.argtypes = (c_int,)
            lib.cl_strerror.restype = c_char_p

        logging.info(f"Loaded libclamav: {libpath}")
        return lib
    
    except Exception as e:
        logging.error(f"Failed to setup function prototypes: {e}")
        return None

# --- Scanner class ---
class Scanner:
    def __init__(self, libclamav_path, dbpath=None, autoreload=False, dboptions=CL_DB_STDOPT, engine_options=None):
        self.libclamav = None
        self.engine = None
        self.dbpath = None
        
        self.libclamav = load_clamav(libclamav_path)
        if not self.libclamav:
            logging.error("Scanner could not initialize because libclamav failed to load.")
            return

        # init clamav engine
        try:
            res = self.libclamav.cl_init(0)
            if res != CL_SUCCESS:
                logging.error(f"cl_init failed with code {res}")
                return
        except Exception as e:
            logging.error(f"cl_init exception: {e}")
            return

        # database path validation
        if dbpath is None:
            pf = os.environ.get("ProgramFiles", r"C:\Program Files")
            dbpath = os.path.join(pf, "ClamAV", "db")
        
        if not os.path.isdir(dbpath):
            logging.error(f"Invalid database path: {dbpath}")
            return

        self.dbpath = dbpath
        self.autoreload = autoreload
        self.dboptions = dboptions
        self.engine_options = engine_options or self.def_engine_options()
        
        # Load database
        if not self.loadDB():
            logging.error("Failed to load ClamAV database")
            return
            
        logging.info("Scanner initialized successfully")

    def __del__(self):
        """Cleanup resources"""
        if self.engine and self.libclamav:
            try:
                self.libclamav.cl_engine_free(self.engine)
            except Exception:
                pass

    @staticmethod
    def def_engine_options():
        return {
            0: 50*1024*1024,  # CL_ENGINE_MAX_SCANSIZE
            1: 50*1024*1024,  # CL_ENGINE_MAX_FILESIZE
            2: 20,            # CL_ENGINE_MAX_RECURSION
            3: 500            # CL_ENGINE_MAX_FILES
        }

    def get_error_message(self, error_code):
        """Get human readable error message"""
        if not self.libclamav or not hasattr(self.libclamav, 'cl_strerror'):
            return f"Error code: {error_code}"
        
        try:
            err_msg = self.libclamav.cl_strerror(error_code)
            if err_msg:
                return err_msg.decode('utf-8', errors='ignore')
        except Exception:
            pass
        
        return f"Error code: {error_code}"

    def loadDB(self):
        """Load ClamAV database with improved error handling"""
        if not self.libclamav:
            logging.error("libclamav is not loaded, cannot load DB.")
            return False

        logging.info("Loading ClamAV database...")
        
        # Free existing engine
        if self.engine:
            try:
                self.libclamav.cl_engine_free(self.engine)
            except Exception as e:
                logging.warning(f"Error freeing engine: {e}")
            self.engine = None

        # Create new engine
        try:
            self.engine = self.libclamav.cl_engine_new()
            if not self.engine:
                logging.error("Failed to create ClamAV engine")
                return False
        except Exception as e:
            logging.error(f"Exception creating engine: {e}")
            return False

        # Load database
        try:
            dbpath_b = _to_bytes_or_none(self.dbpath)
            if not dbpath_b:
                logging.error("Invalid database path")
                return False
                
            signo = c_uint()
            res = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))
            
            if res != CL_SUCCESS:
                error_msg = self.get_error_message(res)
                logging.error(f"cl_load failed: {error_msg}")
                return False
                
        except Exception as e:
            logging.error(f"Exception during cl_load: {e}")
            return False

        # Compile engine
        try:
            res = self.libclamav.cl_engine_compile(self.engine)
            if res != CL_SUCCESS:
                error_msg = self.get_error_message(res)
                logging.error(f"cl_engine_compile failed: {error_msg}")
                return False
        except Exception as e:
            logging.error(f"Exception during cl_engine_compile: {e}")
            return False

        logging.info(f"ClamAV database loaded successfully. Signatures: {signo.value}")
        return True

    def scanFile(self, filepath):
        """Scan file with improved error handling and memory safety"""
        if not self.libclamav or not self.engine:
            logging.error("Engine not initialized.")
            return None, None

        if not filepath or not os.path.exists(filepath):
            logging.error(f"File does not exist: {filepath}")
            return None, None

        try:
            fname_b = _to_bytes_or_none(filepath)
            if not fname_b:
                logging.error("Invalid file path encoding")
                return None, None

            # Initialize variables properly
            virname = c_char_p()
            bytes_scanned = c_ulong(0)
            scan_opts = c_uint(0)  # Use c_uint instead of creating cl_scan_options

            # Call cl_scanfile
            ret = self.libclamav.cl_scanfile(
                fname_b, 
                byref(virname), 
                byref(bytes_scanned),
                self.engine, 
                scan_opts  # Pass c_uint directly
            )

            # Process results
            if ret == CL_CLEAN:
                logging.info(f"File clean: {filepath}")
                return CL_CLEAN, None
            elif ret == CL_VIRUS:
                virus_name = virname.value.decode("utf-8", errors="ignore") if virname.value else "Unknown"
                logging.warning(f"Virus found in {filepath}: {virus_name}")
                return CL_VIRUS, virus_name
            else:
                error_msg = self.get_error_message(ret)
                logging.error(f"Scan failed for {filepath}: {error_msg}")
                return ret, None

        except Exception as e:
            logging.error(f"Exception during file scan: {e}")
            return None, None

    def getVersions(self):
        """Get ClamAV version with error handling"""
        if not self.libclamav:
            return None
        try:
            ver = self.libclamav.cl_retver()
            return ver.decode("utf-8", errors="ignore") if ver else None
        except Exception as e:
            logging.error(f"Error getting version: {e}")
            return None

    def updateDB(self, dbpath=None):
        """Update/reload database"""
        if dbpath:
            if not os.path.isdir(dbpath):
                logging.error(f"Invalid new database path: {dbpath}")
                return False
            self.dbpath = dbpath
        
        success = self.loadDB()
        if success:
            logging.info("Database updated/reloaded successfully.")
        else:
            logging.error("Failed to update/reload database.")
        return success

    def is_initialized(self):
        """Check if scanner is properly initialized"""
        return self.libclamav is not None and self.engine is not None
