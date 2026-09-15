import ctypes
import json
import os
from typing import Optional, Dict, Any

class OpenEdrScanner:
    """
    Python SDK for OpenEDR / HydraDragon Static Antivirus Engine.
    Wraps openedr_static.dll C FFI.
    """
    def __init__(self, dll_path: str = "openedr_static.dll", rules_dir: Optional[str] = None):
        if not os.path.isabs(dll_path) and not os.path.exists(dll_path):
            candidates = [
                dll_path,
                os.path.join(os.path.dirname(__file__), "..", "..", "OpenMalwareScannerPortable", "openedr_static.dll"),
                os.path.join(os.path.dirname(__file__), "openedr_static.dll"),
            ]
            for c in candidates:
                if os.path.exists(c):
                    dll_path = os.path.abspath(c)
                    break

        self.dll = ctypes.CDLL(dll_path)
        self._setup_prototypes()

        # Initialize engine
        b_rules = rules_dir.encode("utf-8") if rules_dir else None
        res = self.dll.openedr_static_init(b_rules)
        if res != 0:
            raise RuntimeError(f"Failed to initialize OpenEDR Static Engine (code: {res})")

    def _setup_prototypes(self):
        self.dll.openedr_static_init.restype = ctypes.c_int32
        self.dll.openedr_static_init.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_scan_file.restype = ctypes.c_char_p
        self.dll.openedr_static_scan_file.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_scan_bytes.restype = ctypes.c_char_p
        self.dll.openedr_static_scan_bytes.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]

        self.dll.openedr_static_scan_url.restype = ctypes.c_char_p
        self.dll.openedr_static_scan_url.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_check_registry.restype = ctypes.c_char_p
        self.dll.openedr_static_check_registry.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_check_fls_sha1.restype = ctypes.c_int32
        self.dll.openedr_static_check_fls_sha1.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_free_string.restype = None
        self.dll.openedr_static_free_string.argtypes = [ctypes.c_char_p]

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a file on disk by its path."""
        res_ptr = self.dll.openedr_static_scan_file(file_path.encode("utf-8"))
        if not res_ptr:
            return {"error": True, "message": "Null pointer returned from scanner"}
        try:
            json_str = res_ptr.decode("utf-8")
            return json.loads(json_str)
        finally:
            self.dll.openedr_static_free_string(res_ptr)

    def scan_bytes(self, data: bytes, virtual_name: str = "sample.bin") -> Dict[str, Any]:
        """Scan raw bytes in memory."""
        res_ptr = self.dll.openedr_static_scan_bytes(data, len(data), virtual_name.encode("utf-8"))
        if not res_ptr:
            return {"error": True, "message": "Null pointer returned from scanner"}
        try:
            json_str = res_ptr.decode("utf-8")
            return json.loads(json_str)
        finally:
            self.dll.openedr_static_free_string(res_ptr)

    def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan a URL for phishing or malicious patterns."""
        res_ptr = self.dll.openedr_static_scan_url(url.encode("utf-8"))
        if not res_ptr:
            return {"error": True, "message": "Null pointer returned from scanner"}
        try:
            json_str = res_ptr.decode("utf-8")
            return json.loads(json_str)
        finally:
            self.dll.openedr_static_free_string(res_ptr)

    def check_registry(self, reg_path: str) -> Dict[str, Any]:
        """Check a Windows Registry key against PUA rules."""
        res_ptr = self.dll.openedr_static_check_registry(reg_path.encode("utf-8"))
        if not res_ptr:
            return {"error": True, "message": "Null pointer returned from scanner"}
        try:
            json_str = res_ptr.decode("utf-8")
            return json.loads(json_str)
        finally:
            self.dll.openedr_static_free_string(res_ptr)

    def query_fls(self, sha1_hex: str) -> str:
        """Query Comodo FLS cloud for a 40-character SHA-1 hash."""
        code = self.dll.openedr_static_check_fls_sha1(sha1_hex.encode("utf-8"))
        verdicts = {
            1: "Safe / Trusted",
            2: "Malicious / Malware",
            0: "Unknown / Absent",
            -1: "Network / Protocol Error"
        }
        return verdicts.get(code, f"Unknown Code ({code})")
