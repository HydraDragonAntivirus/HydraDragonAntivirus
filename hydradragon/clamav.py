#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Full 64-bit ClamAV Python wrapper with Scanner + argument-based DLL path
# Author: Emirhan Ucan
# Inspired by: https://github.com/clamwin/python-clamav/blob/master/clamav.py

import os
import logging
from ctypes import (
    CDLL, Structure, POINTER, c_uint, c_int, c_char_p, c_ulong,
    c_void_p, byref, pointer
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

    # define prototypes
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

    lib.cl_scanfile.argtypes = [
        c_char_p, POINTER(c_char_p), POINTER(c_ulong), cl_engine_p, POINTER(cl_scan_options)
    ]
    lib.cl_scanfile.restype = c_int

    lib.cl_retver.argtypes = None
    lib.cl_retver.restype = c_char_p

    logging.info(f"Loaded libclamav: {libpath}")
    return lib

# --- Scanner class ---
class Scanner:
    def __init__(self, libclamav_path, dbpath=None, autoreload=False, dboptions=CL_DB_STDOPT, engine_options=None):
        self.libclamav = load_clamav(libclamav_path)
        if not self.libclamav:
            logging.error("Scanner could not initialize because libclamav failed to load.")
            return

        # init clamav engine
        res = self.libclamav.cl_init(0)
        if res != CL_SUCCESS:
            logging.error(f"cl_init failed with code {res}")
            return

        # database path
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
        self.engine = None
        self.loadDB()

    @staticmethod
    def def_engine_options():
        return {
            0: 50*1024*1024,  # CL_ENGINE_MAX_SCANSIZE
            1: 50*1024*1024,  # CL_ENGINE_MAX_FILESIZE
            2: 20,            # CL_ENGINE_MAX_RECURSION
            3: 500            # CL_ENGINE_MAX_FILES
        }

    def loadDB(self):
        if not self.libclamav:
            logging.error("libclamav is not loaded, cannot load DB.")
            return

        logging.info("Loading ClamAV database...")
        if self.engine:
            try:
                self.libclamav.cl_engine_free(self.engine)
            except Exception:
                pass

        self.engine = self.libclamav.cl_engine_new()
        if not self.engine:
            logging.error("Failed to create ClamAV engine")
            return

        dbpath_b = _to_bytes_or_none(self.dbpath)
        signo = c_uint()
        res = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))
        if res != CL_SUCCESS:
            logging.error(f"cl_load failed: {res}")
            return
        res = self.libclamav.cl_engine_compile(self.engine)
        if res != CL_SUCCESS:
            logging.error(f"cl_engine_compile failed: {res}")
            return

        logging.info(f"ClamAV database loaded. Signatures: {signo.value}")

    def scanFile(self, filepath):
        if not self.libclamav or not self.engine:
            logging.error("Engine not initialized.")
            return None, None

        fname_b = _to_bytes_or_none(filepath)
        virname = c_char_p()
        bytes_scanned = c_ulong(0)
        options = cl_scan_options(0,0,0,0,0)
        ret = self.libclamav.cl_scanfile(fname_b, byref(virname), byref(bytes_scanned), self.engine, pointer(options))
        if ret not in (CL_CLEAN, CL_VIRUS):
            logging.error(f"Scan failed with code {ret}")
            return None, None
        return ret, virname.value.decode("utf-8", errors="ignore") if virname.value else None

    def getVersions(self):
        if not self.libclamav:
            return None
        try:
            ver = self.libclamav.cl_retver()
            return ver.decode("utf-8", errors="ignore") if ver else None
        except Exception:
            return None

    def updateDB(self, dbpath=None):
        if dbpath:
            self.dbpath = dbpath
        self.loadDB()
        logging.info("Database updated/reloaded.")
