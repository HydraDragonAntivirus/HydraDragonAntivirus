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
        # NOTE: heap-string returns use c_void_p (NOT c_char_p): ctypes would
        # otherwise copy the bytes and lose the original pointer, so
        # openedr_static_free_string would free the wrong address.
        self.dll.openedr_static_init.restype = ctypes.c_int32
        self.dll.openedr_static_init.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_scan_file.restype = ctypes.c_void_p
        self.dll.openedr_static_scan_file.argtypes = [ctypes.c_char_p]

        # data is c_void_p: c_char_p would truncate binary input at the first NUL.
        self.dll.openedr_static_scan_bytes.restype = ctypes.c_void_p
        self.dll.openedr_static_scan_bytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]

        self.dll.openedr_static_scan_url.restype = ctypes.c_void_p
        self.dll.openedr_static_scan_url.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_check_registry.restype = ctypes.c_void_p
        self.dll.openedr_static_check_registry.argtypes = [ctypes.c_char_p]

        self.dll.openedr_static_free_string.restype = None
        self.dll.openedr_static_free_string.argtypes = [ctypes.c_void_p]

    def _call_json(self, ptr) -> Dict[str, Any]:
        """Decode a heap JSON string from the engine and free it."""
        if not ptr:
            return {"error": True, "message": "Null pointer returned from scanner"}
        try:
            return json.loads(ctypes.string_at(ptr).decode("utf-8"))
        finally:
            self.dll.openedr_static_free_string(ptr)

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a file on disk by its path."""
        return self._call_json(self.dll.openedr_static_scan_file(file_path.encode("utf-8")))

    def scan_bytes(self, data: bytes, virtual_name: str = "sample.bin") -> Dict[str, Any]:
        """Scan raw bytes in memory."""
        if not data:
            return {"error": True, "message": "Empty data buffer"}
        buf = ctypes.create_string_buffer(bytes(data))
        return self._call_json(self.dll.openedr_static_scan_bytes(
            ctypes.cast(buf, ctypes.c_void_p), len(data), virtual_name.encode("utf-8")))

    def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan a URL for phishing or malicious patterns."""
        return self._call_json(self.dll.openedr_static_scan_url(url.encode("utf-8")))

    def check_registry(self, reg_path: str) -> Dict[str, Any]:
        """Check a Windows Registry key against PUA rules."""
        return self._call_json(self.dll.openedr_static_check_registry(reg_path.encode("utf-8")))
