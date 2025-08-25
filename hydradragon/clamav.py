#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Full 64-bit ClamAV Python wrapper with Scanner + argument-based DLL path
# Author: Emirhan Ucan
# Inspired by: https://github.com/clamwin/python-clamav/blob/master/clamav.py

import os
import sys
import argparse
import logging
from ctypes import *
from ctypes.util import find_library

logging.basicConfig(level=logging.INFO, format='[clamav-wrapper] %(levelname)s: %(message)s')

# --- helpers ---
def _to_bytes_or_none(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise TypeError(f'Invalid value type: {type(value)}')

# --- types ---
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

# --- load libclamav with argument support ---
def load_clamav(libpath=None):
    dll_candidates = []

    if libpath:  # priority: user-specified path
        dll_candidates.append(libpath)
    else:  # fallback: Program Files and find_library()
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        dll_candidates += [
            os.path.join(pf, "ClamAV", "libclamav.dll"),
            find_library("clamav"),
            find_library("libclamav"),
            "libclamav",
        ]

    libclamav = None
    last_exc = None
    for cand in dll_candidates:
        if not cand:
            continue
        try:
            if os.path.exists(cand) or cand in ("libclamav", "clamav"):
                libclamav = CDLL(cand)
                logging.info(f"Loaded libclamav.dll: {cand}")
                break
        except Exception as e:
            last_exc = e

    if libclamav is None:
        raise ImportError("Failed to load libclamav.dll") from last_exc
    return libclamav


# --- constants ---
CL_CLEAN = 0
CL_VIRUS = 1
CL_SUCCESS = 0
CL_DB_STDOPT = 0

# --- exception ---
class ClamavException(Exception):
    def __init__(self, message):
        if isinstance(message, int):
            try:
                msg = libclamav.cl_strerror(message)
                if isinstance(msg, bytes):
                    msg = msg.decode("utf-8", errors="ignore")
            except Exception:
                msg = str(message)
            message = msg
        super().__init__(message)


# --- Scanner class ---
class Scanner:
    def __init__(self, libclamav, dbpath=None, autoreload=False, dboptions=CL_DB_STDOPT, engine_options=None):
        self.libclamav = libclamav

        # initialize clamav engine
        res = self.libclamav.cl_init(0)
        if res != CL_SUCCESS:
            raise ClamavException(res)

        # Auto-detect default database path
        if dbpath is None:
            pf = os.environ.get("ProgramFiles", r"C:\Program Files")
            dbpath = os.path.join(pf, "ClamAV", "db")
        if not os.path.isdir(dbpath):
            raise ClamavException(f"Invalid database path: {dbpath}")

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
        """Load or reload the ClamAV database"""
        logging.info("Loading ClamAV database...")
        if self.engine:
            try:
                self.libclamav.cl_engine_free(self.engine)
            except Exception:
                pass
        self.engine = self.libclamav.cl_engine_new()
        if not self.engine:
            raise ClamavException("Failed to create ClamAV engine")

        dbpath_b = _to_bytes_or_none(self.dbpath)
        signo = c_uint()
        res = self.libclamav.cl_load(dbpath_b, self.engine, byref(signo), c_uint(self.dboptions))
        if res != CL_SUCCESS:
            raise ClamavException(f"cl_load failed: {res}")
        res = self.libclamav.cl_engine_compile(self.engine)
        if res != CL_SUCCESS:
            raise ClamavException(f"cl_engine_compile failed: {res}")
        logging.info(f"ClamAV database loaded. Signatures: {signo.value}")

    def scanFile(self, filepath):
        """Scan a single file"""
        fname_b = _to_bytes_or_none(filepath)
        virname = c_char_p()
        bytes_scanned = c_ulong(0)
        options = cl_scan_options(0,0,0,0,0)
        ret = self.libclamav.cl_scanfile(fname_b, byref(virname), byref(bytes_scanned), self.engine, pointer(options))
        if ret not in (CL_CLEAN, CL_VIRUS):
            raise ClamavException(ret)
        return ret, virname.value.decode("utf-8", errors="ignore") if virname.value else None

    def getVersions(self):
        try:
            ver = self.libclamav.cl_retver()
            return ver.decode("utf-8", errors="ignore") if ver else None
        except Exception:
            return None

    def updateDB(self, dbpath=None):
        """Reload database, optionally from a different path"""
        if dbpath:
            self.dbpath = dbpath
        self.loadDB()
        logging.info("Database updated/reloaded.")


# --- example usage ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python ClamAV Scanner Wrapper")
    parser.add_argument("--libpath", help="Full path to libclamav.dll", default=None)
    parser.add_argument("--file", help="File to scan", default=r"C:\Windows\notepad.exe")
    args = parser.parse_args()

    libclamav = load_clamav(args.libpath)

    # set prototypes AFTER load
    libclamav.cl_init.argtypes = (c_uint,)
    libclamav.cl_init.restype = c_int
    libclamav.cl_engine_new.argtypes = None
    libclamav.cl_engine_new.restype = cl_engine_p
    libclamav.cl_engine_free.argtypes = (cl_engine_p,)
    libclamav.cl_engine_free.restype = c_int
    libclamav.cl_load.argtypes = (c_char_p, cl_engine_p, POINTER(c_uint), c_uint)
    libclamav.cl_load.restype = c_int
    libclamav.cl_engine_compile.argtypes = (cl_engine_p,)
    libclamav.cl_engine_compile.restype = c_int
    libclamav.cl_scanfile.argtypes = [
        c_char_p, POINTER(c_char_p), POINTER(c_ulong), cl_engine_p, POINTER(cl_scan_options)
    ]
    libclamav.cl_scanfile.restype = c_int
    libclamav.cl_retver.argtypes = None
    libclamav.cl_retver.restype = c_char_p

    scanner = Scanner(libclamav)
    ret, virus = scanner.scanFile(args.file)
    print(f"Scan result: {ret}, Virus: {virus}")
