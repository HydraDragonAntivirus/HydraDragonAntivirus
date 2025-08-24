#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Full 64-bit ClamAV Python wrapper with Scanner
# Author: patched
# Version: 0.103.0-patched

import sys
import os
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
    raise TypeError('Invalid value for string arg: %r' % type(value))

# --- types ---
cl_engine_p = c_void_p
c_int_p = POINTER(c_int)
c_uint_p = POINTER(c_uint)
c_ulong_p = POINTER(c_ulong)
c_char_pp = POINTER(c_char_p)

class cl_scan_options(Structure):
    _fields_ = [
        ('general', c_uint),
        ('parse', c_uint),
        ('heuristic', c_uint),
        ('mail', c_uint),
        ('dev', c_uint),
    ]

# --- load libclamav ---
dll_candidates = []
if sys.platform == 'win32':
    dll_candidates.append(os.path.join(os.path.dirname(__file__), 'libclamav.dll'))
dll_candidates += [find_library('clamav'), find_library('libclamav'), 'libclamav']

libclamav = None
last_exc = None
for cand in dll_candidates:
    if not cand:
        continue
    try:
        libclamav = CDLL(cand)
        break
    except Exception as e:
        last_exc = e
if libclamav is None:
    raise ImportError("Failed to load libclamav.dll") from last_exc

# --- prototypes ---
libclamav.cl_init.argtypes = (c_uint,)
libclamav.cl_init.restype = c_int

libclamav.cl_retdbdir.argtypes = None
libclamav.cl_retdbdir.restype = c_char_p

libclamav.cl_strerror.argtypes = (c_int,)
libclamav.cl_strerror.restype = c_char_p

libclamav.cl_initialize_crypto.argtypes = None
libclamav.cl_initialize_crypto.restype = c_int
libclamav.cl_initialize_crypto()

libclamav.cl_engine_new.argtypes = None
libclamav.cl_engine_new.restype = cl_engine_p

libclamav.cl_engine_free.argtypes = (cl_engine_p,)
libclamav.cl_engine_free.restype = c_int

libclamav.cl_load.argtypes = (c_char_p, cl_engine_p, POINTER(c_uint), c_uint)
libclamav.cl_load.restype = c_int

libclamav.cl_engine_compile.argtypes = (cl_engine_p,)
libclamav.cl_engine_compile.restype = c_int

libclamav.cl_engine_set_num.argtypes = (cl_engine_p, c_int, c_longlong)
libclamav.cl_engine_set_num.restype = c_int

libclamav.cl_engine_set_str.argtypes = (cl_engine_p, c_int, c_char_p)
libclamav.cl_engine_set_str.restype = c_int

libclamav.cl_scanfile.argtypes = [
    c_char_p,             # filename
    POINTER(c_char_p),    # virus name
    POINTER(c_ulong),     # scanned bytes
    cl_engine_p,          # engine
    POINTER(cl_scan_options)  # options
]
libclamav.cl_scanfile.restype = c_int

libclamav.cl_retver.argtypes = None
libclamav.cl_retver.restype = c_char_p

class cl_stat(Structure):
    _fields_ = [('dir', c_char_p),
                ('stattab', c_void_p),
                ('statdname', c_char_pp),
                ('entries', c_uint)]
cl_stat_p = POINTER(cl_stat)

libclamav.cl_statinidir.argtypes = (c_char_p, cl_stat_p)
libclamav.cl_statinidir.restype = c_int

libclamav.cl_statfree.argtypes = (cl_stat_p,)
libclamav.cl_statfree.restype = c_int

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
                    msg = msg.decode('utf-8', errors='ignore')
            except Exception:
                msg = str(message)
            message = msg
        super().__init__(message)

# --- init ---
res = libclamav.cl_init(0)
if res != CL_SUCCESS:
    raise ClamavException(res)
del res

# --- default engine options ---
def def_engine_options():
    return {
        0: 50*1024*1024,  # CL_ENGINE_MAX_SCANSIZE
        1: 50*1024*1024,  # CL_ENGINE_MAX_FILESIZE
        2: 20,            # CL_ENGINE_MAX_RECURSION
        3: 500            # CL_ENGINE_MAX_FILES
    }

# --- Scanner class ---
class Scanner:
    dbstats = cl_stat()
    dbstats_p = byref(dbstats)
    signo = c_uint()
    engine = None

    def __init__(self, dbpath, autoreload=False, dboptions=CL_DB_STDOPT, engine_options=None, debug=False):
        if dbpath is None or not os.path.isdir(dbpath):
            raise ClamavException('Invalid database path')
        self.dbpath = dbpath
        self.autoreload = autoreload
        self.dboptions = dboptions
        self.engine_options = engine_options or def_engine_options()
        if debug and hasattr(libclamav, 'cl_debug'):
            libclamav.cl_debug()

        # New ClamAV only
        libclamav.cl_scanfile.argtypes = (
            c_char_p,          # filename
            POINTER(c_char_p), # virus name
            POINTER(c_ulong),  # scanned bytes
            cl_engine_p,       # engine
            POINTER(cl_scan_options) # options
        )
        libclamav.cl_scanfile.restype = c_int

    def loadDB(self):
        logging.info("Loading ClamAV database...")
        if getattr(self, 'engine', None):
            try:
                libclamav.cl_engine_free(self.engine)
            except Exception:
                pass
        self.engine = libclamav.cl_engine_new()
        if not self.engine:
            raise ClamavException("cl_engine_new failed")
        dbpath_b = _to_bytes_or_none(self.dbpath)

        # statindir
        res = libclamav.cl_statinidir(c_char_p(dbpath_b), self.dbstats_p)
        if res != CL_SUCCESS:
            raise ClamavException(f"cl_statinidir failed: {res}")

        # load db
        res = libclamav.cl_load(
            c_char_p(dbpath_b),
            self.engine,
            byref(self.signo),
            c_ulong(self.dboptions)
        )
        if res != CL_SUCCESS:
            raise ClamavException(f"cl_load failed: {res}")

        # compile engine
        res = libclamav.cl_engine_compile(self.engine)
        if res != CL_SUCCESS:
            raise ClamavException(f"cl_engine_compile failed: {res}")
        logging.info("ClamAV database loaded successfully")

    def scanFile(self, filename):
        fname_b = _to_bytes_or_none(filename)
        virname = c_char_p()
        bytes_scanned = c_ulong(0)
        options = cl_scan_options(general=0, parse=0, heuristic=0, mail=0, dev=0)

        ret = libclamav.cl_scanfile(
            c_char_p(fname_b),
            byref(virname),
            byref(bytes_scanned),
            self.engine,
            pointer(options)
        )

        if ret not in (CL_CLEAN, CL_VIRUS):
            raise ClamavException(ret)
        return ret, virname.value.decode('utf-8', errors='ignore') if virname.value else None

    def getVersions(self):
        try:
            ver = libclamav.cl_retver()
            return ver.decode('utf-8', errors='ignore') if ver else None
        except Exception:
            return None
