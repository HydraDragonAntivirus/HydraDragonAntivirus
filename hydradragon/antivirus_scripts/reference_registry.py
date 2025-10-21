import struct
from pathlib import Path
from typing import Dict, Optional
from hydra_logger import logger

class ReferenceRegistry:
    """
    Maps reference strings to integer IDs and vice versa.
    Saves and loads a compact binary registry.
    """

    VERSION = 1

    def __init__(self):
        self.ref_to_id: Dict[str, int] = {}
        self.id_to_ref: Dict[int, str] = {}
        self.next_id: int = 0

    def register(self, ref: str) -> Optional[int]:
        """
        Register a reference string.
        Returns numeric ID or None if empty/blank.
        """
        ref = ref.strip()
        if not ref:
            return None

        if ref not in self.ref_to_id:
            rid = self.next_id
            self.ref_to_id[ref] = rid
            self.id_to_ref[rid] = ref
            self.next_id += 1
            return rid
        return self.ref_to_id[ref]

    def get(self, ref_id: int) -> Optional[str]:
        return self.id_to_ref.get(ref_id)

    def save(self, path: str):
        """Save registry to a compact binary format."""
        path = Path(path)
        with path.open('wb') as f:
            f.write(b'HREF')  # magic
            f.write(struct.pack('B', self.VERSION))
            f.write(struct.pack('I', len(self.id_to_ref)))
            for rid in sorted(self.id_to_ref.keys()):
                ref_bytes = self.id_to_ref[rid].encode('utf-8')
                f.write(struct.pack('I', rid))
                f.write(struct.pack('I', len(ref_bytes)))
                f.write(ref_bytes)
        logger.info(f"Reference registry saved: {path} ({len(self.id_to_ref)} entries)")

    @classmethod
    def load(cls, path: str) -> 'ReferenceRegistry':
        """Load registry from binary file."""
        path = Path(path)
        if not path.exists():
            logger.warning(f"Reference registry file not found: {path}")
            return cls()

        reg = cls()
        with path.open('rb') as f:
            magic = f.read(4)
            if magic != b'HREF':
                raise ValueError("Invalid reference registry file")
            version_b = f.read(1)
            if not version_b:
                raise EOFError("Unexpected EOF reading registry version")
            version = struct.unpack('B', version_b)[0]
            if version != cls.VERSION:
                raise ValueError(f"Unsupported registry version {version}")
            count_b = f.read(4)
            if len(count_b) < 4:
                raise EOFError("Unexpected EOF reading registry count")
            count = struct.unpack('I', count_b)[0]
            for _ in range(count):
                rid_b = f.read(4)
                if len(rid_b) < 4:
                    raise EOFError("Unexpected EOF reading ref ID")
                rid = struct.unpack('I', rid_b)[0]
                len_b = f.read(4)
                if len(len_b) < 4:
                    raise EOFError("Unexpected EOF reading ref length")
                rlen = struct.unpack('I', len_b)[0]
                ref_bytes = f.read(rlen)
                if len(ref_bytes) < rlen:
                    raise EOFError("Unexpected EOF reading ref string")
                ref_str = ref_bytes.decode('utf-8')
                reg.id_to_ref[rid] = ref_str
                reg.ref_to_id[ref_str] = rid
            reg.next_id = max(reg.id_to_ref.keys(), default=-1) + 1
        logger.info(f"Reference registry loaded: {path} ({len(reg.id_to_ref)} entries)")
        return reg
