#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
from pathlib import Path
from tqdm import tqdm

class ReferenceRegistry:
    """Map reference strings -> small integer IDs; save/load to binary HREF format."""

    VERSION = 1

    def __init__(self):
        self.ref_to_id: Dict[str, int] = {}
        self.id_to_ref: Dict[int, str] = {}
        self.next_id = 0

    def register(self, ref: str) -> int:
        """Return existing ID or create a new one."""
        # normalize small variations
        key = ref.strip()
        if key == '':
            return -1  # sentinel for "no ref" (optional, adjust logic if you don't want -1)
        if key not in self.ref_to_id:
            rid = self.next_id
            self.ref_to_id[key] = rid
            self.id_to_ref[rid] = key
            self.next_id += 1
            return rid
        return self.ref_to_id[key]

    def get(self, ref_id: int) -> Optional[str]:
        return self.id_to_ref.get(ref_id)

    def save(self, path: str):
        with open(path, 'wb') as f:
            f.write(b'HREF')
            f.write(struct.pack('B', self.VERSION))
            f.write(struct.pack('I', len(self.id_to_ref)))
            # write in id order for compatibility/readability
            for ref_id in sorted(self.id_to_ref.keys()):
                ref_str = self.id_to_ref[ref_id].encode('utf-8')
                f.write(struct.pack('I', ref_id))
                f.write(struct.pack('I', len(ref_str)))
                f.write(ref_str)

    @classmethod
    def load(cls, path: str) -> 'ReferenceRegistry':
        reg = cls()
        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic != b'HREF':
                raise ValueError("Invalid reference registry file")
            version_b = f.read(1)
            if len(version_b) < 1:
                raise EOFError("Unexpected EOF while reading registry version")
            version = struct.unpack('B', version_b)[0]
            if version != cls.VERSION:
                raise ValueError(f"Unsupported registry version {version}")

            count_b = f.read(4)
            if len(count_b) < 4:
                raise EOFError("Unexpected EOF while reading registry count")
            count = struct.unpack('I', count_b)[0]

            for _ in range(count):
                ref_id_b = f.read(4)
                if len(ref_id_b) < 4:
                    raise EOFError("Unexpected EOF while reading ref id")
                ref_id = struct.unpack('I', ref_id_b)[0]

                ref_len_b = f.read(4)
                if len(ref_len_b) < 4:
                    raise EOFError("Unexpected EOF while reading ref len")
                ref_len = struct.unpack('I', ref_len_b)[0]

                ref_bytes = f.read(ref_len)
                if len(ref_bytes) < ref_len:
                    raise EOFError("Unexpected EOF while reading ref string")
                ref_str = ref_bytes.decode('utf-8')

                reg.id_to_ref[ref_id] = ref_str
                reg.ref_to_id[ref_str] = ref_id

            reg.next_id = max(reg.id_to_ref.keys()) + 1 if reg.id_to_ref else 0
        return reg

class HydraCuckooFilter:
    MAGIC = b'HDCF'
    VERSION = 1

    def __init__(self, capacity: int = 10000, bucket_size: int = 4,
                 fingerprint_size: int = 2, max_swaps: int = 500):
        # same interface but memory-compact internals
        self.capacity = capacity
        self.bucket_size = bucket_size
        self.fingerprint_size = fingerprint_size
        self.max_swaps = max_swaps

        # compute table size as before
        self.table_size = self._next_power_of_2(max(1, capacity // bucket_size))
        # ensure fingerprint_size fits
        if not (1 <= self.fingerprint_size <= 8):
            raise ValueError("fingerprint_size should be between 1 and 8")

        # compact storage
        self.counts = bytearray(self.table_size)  # one byte per bucket (0..bucket_size)
        total_slots = self.table_size * self.bucket_size * self.fingerprint_size
        self.slots = bytearray(total_slots)  # contiguous area for all fingerprints
        self.item_count = 0

    @staticmethod
    def _next_power_of_2(n: int) -> int:
        power = 1
        while power < n:
            power <<= 1
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

    def _slot_offset(self, bucket_index: int, slot_index: int) -> int:
        # byte offset into self.slots for slot (bucket_index, slot_index)
        return ((bucket_index * self.bucket_size) + slot_index) * self.fingerprint_size

    def _read_fp_at(self, bucket_index: int, slot_index: int) -> bytes:
        off = self._slot_offset(bucket_index, slot_index)
        return bytes(self.slots[off:off + self.fingerprint_size])

    def _write_fp_at(self, bucket_index: int, slot_index: int, fp: bytes):
        off = self._slot_offset(bucket_index, slot_index)
        self.slots[off:off + self.fingerprint_size] = fp

    def insert(self, item: str) -> bool:
        item_bytes = item.encode('utf-8')
        fp = self._fingerprint(item_bytes)
        i1 = self._index(item_bytes)
        i2 = self._alt_index(i1, fp)

        # try i1
        c1 = self.counts[i1]
        if c1 < self.bucket_size:
            self._write_fp_at(i1, c1, fp)
            self.counts[i1] = c1 + 1
            self.item_count += 1
            return True

        # try i2
        c2 = self.counts[i2]
        if c2 < self.bucket_size:
            self._write_fp_at(i2, c2, fp)
            self.counts[i2] = c2 + 1
            self.item_count += 1
            return True

        # evict loop
        idx = random.choice([i1, i2])
        cur_fp = fp
        for _ in range(self.max_swaps):
            cnt = self.counts[idx]
            chosen_slot = random.randrange(cnt)  # pick an occupied slot
            old_fp = self._read_fp_at(idx, chosen_slot)
            self._write_fp_at(idx, chosen_slot, cur_fp)
            cur_fp = old_fp
            idx = self._alt_index(idx, cur_fp)
            cnt = self.counts[idx]
            if cnt < self.bucket_size:
                # append at end of that bucket
                self._write_fp_at(idx, cnt, cur_fp)
                self.counts[idx] = cnt + 1
                self.item_count += 1
                return True

        raise Exception(f"Filter full after {self.max_swaps} swaps")

    def __contains__(self, item: str) -> bool:
        item_bytes = item.encode('utf-8')
        fp = self._fingerprint(item_bytes)
        i1 = self._index(item_bytes)
        i2 = self._alt_index(i1, fp)

        # check bucket i1
        c1 = self.counts[i1]
        for s in range(c1):
            if self._read_fp_at(i1, s) == fp:
                return True

        # check bucket i2
        c2 = self.counts[i2]
        for s in range(c2):
            if self._read_fp_at(i2, s) == fp:
                return True

        return False

    def save(self, path: str):
        with open(path, 'wb') as f:
            f.write(self.MAGIC)
            f.write(struct.pack('B', self.VERSION))
            f.write(struct.pack('I', self.table_size))
            f.write(struct.pack('B', self.bucket_size))
            f.write(struct.pack('B', self.fingerprint_size))
            f.write(struct.pack('H', self.max_swaps))
            f.write(struct.pack('I', self.item_count))

            # write counts (exactly table_size bytes)
            f.write(self.counts)

            # write raw slots
            f.write(self.slots)

    @classmethod
    def load(cls, path: str) -> 'HydraCuckooFilter':
        """
        Stream-based loader: reads header, then reads each bucket progressively.
        Avoids reading the entire file into memory.
        """
        with open(path, 'rb') as f:
            magic = f.read(4)
            if len(magic) < 4 or magic != cls.MAGIC:
                raise ValueError("Invalid file format")

            version_b = f.read(1)
            if len(version_b) < 1:
                raise EOFError("Unexpected EOF while reading version")
            version = struct.unpack('B', version_b)[0]
            if version != cls.VERSION:
                raise ValueError(f"Unsupported filter version {version}")

            ts_b = f.read(4)
            if len(ts_b) < 4:
                raise EOFError("Unexpected EOF while reading table_size")
            table_size = struct.unpack('I', ts_b)[0]

            bucket_size_b = f.read(1)
            if len(bucket_size_b) < 1:
                raise EOFError("Unexpected EOF while reading bucket_size")
            bucket_size = struct.unpack('B', bucket_size_b)[0]

            fp_size_b = f.read(1)
            if len(fp_size_b) < 1:
                raise EOFError("Unexpected EOF while reading fingerprint_size")
            fingerprint_size = struct.unpack('B', fp_size_b)[0]

            max_swaps_b = f.read(2)
            if len(max_swaps_b) < 2:
                raise EOFError("Unexpected EOF while reading max_swaps")
            max_swaps = struct.unpack('H', max_swaps_b)[0]

            item_count_b = f.read(4)
            if len(item_count_b) < 4:
                raise EOFError("Unexpected EOF while reading item_count")
            item_count = struct.unpack('I', item_count_b)[0]

            # create instance without running __init__
            cf = cls.__new__(cls)
            cf.table_size = table_size
            cf.bucket_size = bucket_size
            cf.fingerprint_size = fingerprint_size
            cf.max_swaps = max_swaps
            cf.item_count = item_count
            cf.capacity = table_size * bucket_size

            # read counts
            counts = f.read(table_size)
            if len(counts) < table_size:
                raise EOFError("Unexpected EOF while reading counts")
            cf.counts = bytearray(counts)

            # read slots
            total_slots = table_size * bucket_size * fingerprint_size
            slots = f.read(total_slots)
            if len(slots) < total_slots:
                raise EOFError("Unexpected EOF while reading slots")
            cf.slots = bytearray(slots)

            return cf


class MinimalMetadataStore:
    """
    Memory-lean metadata store: keep only a single dict mapping domain_hash -> list(ref_ids).
    Avoid duplicated structures (no entries+_map).
    """
    MAGIC = b'HDMM'
    VERSION = 1

    def __init__(self):
        # Keep list for backward-compatible save order, but also build a dict for O(1) lookup
        self._map: Dict[int, List[int]] = {}

    def add_threat(self, domain: str, ref_ids: List[int]):
        """Add threat with minimal data"""
        # Use 64-bit hash of domain
        domain_hash = mmh3.hash64(domain.encode('utf-8'))[0]
        self._map[domain_hash] = list(ref_ids)  # copy

    def save(self, path: str):
        """Save in ultra-compact binary format"""
        with open(path, 'wb') as f:
            f.write(self.MAGIC)
            f.write(struct.pack('B', self.VERSION))
                # 8 bytes for hash (signed long long)
            f.write(struct.pack('I', len(self._map)))
            for domain_hash, ref_ids in self._map.items():
                f.write(struct.pack('q', domain_hash))
                # 1 byte for ref count
                f.write(struct.pack('B', min(len(ref_ids), 255)))
                # 2 bytes per reference ID
                for ref_id in ref_ids[:255]:
                    f.write(struct.pack('H', ref_id))

    @classmethod
    def load(cls, path: str) -> 'MinimalMetadataStore':
        """Load from binary; builds a dict for fast lookups"""
        meta = cls()

        with open(path, 'rb') as f:
            magic = f.read(4)
            if len(magic) < 4 or magic != cls.MAGIC:
                raise ValueError("Invalid metadata format")

            version_b = f.read(1)
            if len(version_b) < 1:
                raise EOFError("Unexpected EOF while reading version")
            version = struct.unpack('B', version_b)[0]
            if version != cls.VERSION:
                raise ValueError(f"Unsupported metadata version {version}")

            entry_count_b = f.read(4)
            if len(entry_count_b) < 4:
                raise EOFError("Unexpected EOF while reading entry count")
            entry_count = struct.unpack('I', entry_count_b)[0]

            for _ in range(entry_count):
                dh_b = f.read(8)
                if len(dh_b) < 8:
                    raise EOFError("Unexpected EOF while reading domain hash")
                domain_hash = struct.unpack('q', dh_b)[0]

                ref_count_b = f.read(1)
                if len(ref_count_b) < 1:
                    raise EOFError("Unexpected EOF while reading ref count")
                ref_count = struct.unpack('B', ref_count_b)[0]

                ref_ids: List[int] = []
                if ref_count:
                    expected = ref_count * 2
                    ref_bytes = f.read(expected)
                    if len(ref_bytes) < expected:
                        raise EOFError("Unexpected EOF while reading ref ids")
                    off = 0
                    for _ in range(ref_count):
                        ref_id = struct.unpack('H', ref_bytes[off:off + 2])[0]
                        ref_ids.append(ref_id)
                        off += 2

                meta.entries.append((domain_hash, ref_ids))
                meta._map[domain_hash] = ref_ids

        return meta

    def get_threat(self, domain: str) -> Optional[List[int]]:
        """Get reference IDs for domain (O(1))"""
        domain_hash = mmh3.hash64(domain.encode('utf-8'))[0]
        return self._map.get(domain_hash)
