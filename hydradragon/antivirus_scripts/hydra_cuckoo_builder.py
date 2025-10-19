#!/usr/bin/env python3
# hydra_cuckoo_builder.py
"""
HydraDragonAntivirus Custom Cuckoo Filter Builder
ULTRA MINIMAL BINARY FORMAT

References saved as numbers (0,1,2,3...)
Domains saved as hash only
Maximum compression for huge databases
"""

import mmh3
import random
import struct
from typing import Optional, Dict, List, Tuple


class ReferenceRegistry:
    """Map references to IDs for compression"""
    
    VERSION = 1
    
    def __init__(self):
        self.ref_to_id: Dict[str, int] = {}
        self.id_to_ref: Dict[int, str] = {}
        self.next_id = 0

    def register(self, ref: str) -> int:
        """Get or create ID for reference"""
        if ref not in self.ref_to_id:
            self.ref_to_id[ref] = self.next_id
            self.id_to_ref[self.next_id] = ref
            self.next_id += 1
        return self.ref_to_id[ref]

    def save(self, path: str):
        """Save registry to binary"""
        with open(path, 'wb') as f:
            f.write(b'HREF')  # Magic
            f.write(struct.pack('B', self.VERSION))  # Version
            f.write(struct.pack('I', len(self.id_to_ref)))  # Count (4 bytes)
            for ref_id, ref_str in sorted(self.id_to_ref.items()):
                ref_bytes = ref_str.encode('utf-8')
                f.write(struct.pack('I', ref_id))  # ID (4 bytes)
                f.write(struct.pack('I', len(ref_bytes)))  # Length (4 bytes)
                f.write(ref_bytes)  # String data

    @classmethod
    def load(cls, path: str) -> 'ReferenceRegistry':
        """Load registry from binary"""
        reg = cls()
        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic != b'HREF':
                raise ValueError("Invalid reference registry")
            
            version = struct.unpack('B', f.read(1))[0]
            if version != cls.VERSION:
                raise ValueError(f"Unsupported registry version {version}")
            
            count = struct.unpack('I', f.read(4))[0]
            for _ in range(count):
                ref_id = struct.unpack('I', f.read(4))[0]
                ref_len = struct.unpack('I', f.read(4))[0]
                ref_str = f.read(ref_len).decode('utf-8')
                reg.id_to_ref[ref_id] = ref_str
                reg.ref_to_id[ref_str] = ref_id

            reg.next_id = max(reg.id_to_ref.keys()) + 1 if reg.id_to_ref else 0
        return reg


class HydraCuckooBucket:
    """Single bucket in the Cuckoo filter table"""

    def __init__(self, bucket_size: int):
        self.bucket_size = bucket_size
        self.bucket = []

    def __contains__(self, fingerprint: bytes) -> bool:
        return fingerprint in self.bucket

    def insert(self, fingerprint: bytes) -> bool:
        if len(self.bucket) < self.bucket_size:
            self.bucket.append(fingerprint)
            return True
        return False

    def swap(self, fingerprint: bytes) -> bytes:
        idx = random.randrange(len(self.bucket))
        old = self.bucket[idx]
        self.bucket[idx] = fingerprint
        return old

    def to_bytes(self) -> bytes:
        """Serialize bucket to bytes"""
        data = struct.pack('B', len(self.bucket))
        for fp in self.bucket:
            data += fp
        return data

    @classmethod
    def from_bytes(cls, data: bytes, bucket_size: int, fp_size: int) -> Tuple['HydraCuckooBucket', int]:
        """Deserialize bucket from bytes"""
        count = data[0]
        bucket = cls(bucket_size)
        offset = 1
        for _ in range(count):
            fp = data[offset:offset + fp_size]
            bucket.bucket.append(fp)
            offset += fp_size
        return bucket, offset


class HydraCuckooFilter:
    """Custom Cuckoo filter with native binary serialization"""

    MAGIC = b'HDCF'
    VERSION = 1

    def __init__(self, capacity: int = 10000, bucket_size: int = 4,
                 fingerprint_size: int = 2, max_swaps: int = 500):
        self.capacity = capacity
        self.bucket_size = bucket_size
        self.fingerprint_size = fingerprint_size
        self.max_swaps = max_swaps
        self.table_size = self._next_power_of_2(capacity // bucket_size)
        self.table = [HydraCuckooBucket(bucket_size) for _ in range(self.table_size)]
        self.item_count = 0

    @staticmethod
    def _next_power_of_2(n: int) -> int:
        power = 1
        while power < n:
            power *= 2
        return max(power, 16)

    def _fingerprint(self, item: bytes) -> bytes:
        h = mmh3.hash_bytes(item)
        return h[:self.fingerprint_size]

    def _index(self, item: bytes) -> int:
        h = mmh3.hash_bytes(item)
        return int.from_bytes(h[:4], 'big') % self.table_size

    def _alt_index(self, index: int, fingerprint: bytes) -> int:
        fp_hash = int.from_bytes(fingerprint, 'big')
        return (index ^ fp_hash) % self.table_size

    def insert(self, item: str) -> bool:
        item_bytes = item.encode('utf-8')
        fp = self._fingerprint(item_bytes)
        i1 = self._index(item_bytes)
        i2 = self._alt_index(i1, fp)

        if self.table[i1].insert(fp):
            self.item_count += 1
            return True

        if self.table[i2].insert(fp):
            self.item_count += 1
            return True

        idx = random.choice([i1, i2])
        for _ in range(self.max_swaps):
            fp = self.table[idx].swap(fp)
            idx = self._alt_index(idx, fp)
            if self.table[idx].insert(fp):
                self.item_count += 1
                return True

        raise Exception(f"Filter full after {self.max_swaps} swaps")

    def __contains__(self, item: str) -> bool:
        item_bytes = item.encode('utf-8')
        fp = self._fingerprint(item_bytes)
        i1 = self._index(item_bytes)
        i2 = self._alt_index(i1, fp)
        return fp in self.table[i1] or fp in self.table[i2]

    def save(self, path: str):
        with open(path, 'wb') as f:
            f.write(self.MAGIC)
            f.write(struct.pack('B', self.VERSION))
            f.write(struct.pack('I', self.table_size))
            f.write(struct.pack('B', self.bucket_size))
            f.write(struct.pack('B', self.fingerprint_size))
            f.write(struct.pack('H', self.max_swaps))
            f.write(struct.pack('I', self.item_count))

            for bucket in self.table:
                f.write(bucket.to_bytes())

    @classmethod
    def load(cls, path: str) -> 'HydraCuckooFilter':
        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic != cls.MAGIC:
                raise ValueError("Invalid file format")
            
            version = struct.unpack('B', f.read(1))[0]
            table_size = struct.unpack('I', f.read(4))[0]
            bucket_size = struct.unpack('B', f.read(1))[0]
            fingerprint_size = struct.unpack('B', f.read(1))[0]
            max_swaps = struct.unpack('H', f.read(2))[0]
            item_count = struct.unpack('I', f.read(4))[0]

            cf = cls.__new__(cls)
            cf.table_size = table_size
            cf.bucket_size = bucket_size
            cf.fingerprint_size = fingerprint_size
            cf.max_swaps = max_swaps
            cf.item_count = item_count
            cf.capacity = table_size * bucket_size
            cf.table = []

            remaining = f.read()
            offset = 0
            for _ in range(table_size):
                bucket, consumed = HydraCuckooBucket.from_bytes(
                    remaining[offset:], bucket_size, fingerprint_size
                )
                cf.table.append(bucket)
                offset += consumed

            return cf


class MinimalMetadataStore:
    """
    ULTRA MINIMAL metadata storage
    Only stores domain hash (8 bytes) + reference IDs (2 bytes each)
    No timestamps, no strings - maximum compression
    """

    MAGIC = b'HDMM'  # HydraDragon Minimal Metadata
    VERSION = 1

    def __init__(self):
        self.entries = []  # List of (domain_hash, [ref_ids])

    def add_threat(self, domain: str, ref_ids: List[int]):
        """Add threat with minimal data"""
        # Use 64-bit hash of domain
        domain_hash = mmh3.hash64(domain.encode('utf-8'))[0]
        self.entries.append((domain_hash, ref_ids))

    def save(self, path: str):
        """Save in ultra-compact binary format"""
        with open(path, 'wb') as f:
            f.write(self.MAGIC)
            f.write(struct.pack('B', self.VERSION))
            f.write(struct.pack('I', len(self.entries)))

            for domain_hash, ref_ids in self.entries:
                # 8 bytes for hash
                f.write(struct.pack('q', domain_hash))
                # 1 byte for ref count
                f.write(struct.pack('B', min(len(ref_ids), 255)))
                # 2 bytes per reference ID
                for ref_id in ref_ids[:255]:
                    f.write(struct.pack('H', ref_id))

    @classmethod
    def load(cls, path: str) -> 'MinimalMetadataStore':
        """Load from binary"""
        meta = cls()

        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic != cls.MAGIC:
                raise ValueError("Invalid metadata format")
            
            version = struct.unpack('B', f.read(1))[0]
            entry_count = struct.unpack('I', f.read(4))[0]

            for _ in range(entry_count):
                domain_hash = struct.unpack('q', f.read(8))[0]
                ref_count = struct.unpack('B', f.read(1))[0]
                ref_ids = []
                for _ in range(ref_count):
                    ref_id = struct.unpack('H', f.read(2))[0]
                    ref_ids.append(ref_id)

                meta.entries.append((domain_hash, ref_ids))

        return meta

    def get_threat(self, domain: str) -> Optional[List[int]]:
        """Get reference IDs for domain"""
        domain_hash = mmh3.hash64(domain.encode('utf-8'))[0]
        for d_hash, ref_ids in self.entries:
            if d_hash == domain_hash:
                return ref_ids
        return None
