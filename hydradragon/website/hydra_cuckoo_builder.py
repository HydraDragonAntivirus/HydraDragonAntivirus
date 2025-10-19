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
from typing import Optional, Dict, List, Tuple, BinaryIO
from pathlib import Path
import tqdm

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

            version_bytes = f.read(1)
            if len(version_bytes) < 1:
                raise EOFError("Unexpected EOF while reading registry version")
            version = struct.unpack('B', version_bytes)[0]
            if version != cls.VERSION:
                raise ValueError(f"Unsupported registry version {version}")

            count_bytes = f.read(4)
            if len(count_bytes) < 4:
                raise EOFError("Unexpected EOF while reading registry count")
            count = struct.unpack('I', count_bytes)[0]
            for _ in range(count):
                ref_id_b = f.read(4)
                if len(ref_id_b) < 4:
                    raise EOFError("Unexpected EOF while reading ref id")
                ref_id = struct.unpack('I', ref_id_b)[0]

                ref_len_b = f.read(4)
                if len(ref_len_b) < 4:
                    raise EOFError("Unexpected EOF while reading ref len")
                ref_len = struct.unpack('I', ref_len_b)[0]

                ref_str_b = f.read(ref_len)
                if len(ref_str_b) < ref_len:
                    raise EOFError("Unexpected EOF while reading ref string")
                ref_str = ref_str_b.decode('utf-8')

                reg.id_to_ref[ref_id] = ref_str
                reg.ref_to_id[ref_str] = ref_id

            reg.next_id = max(reg.id_to_ref.keys()) + 1 if reg.id_to_ref else 0
        return reg


class HydraCuckooBucket:
    """Single bucket in the Cuckoo filter table"""

    def __init__(self, bucket_size: int):
        self.bucket_size = bucket_size
        self.bucket: List[bytes] = []

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
    def from_stream(cls, stream: BinaryIO, bucket_size: int, fp_size: int) -> 'HydraCuckooBucket':
        """
        Read a single bucket from a file-like stream.
        Format: 1 byte count, then count * fp_size bytes.
        """
        count_b = stream.read(1)
        if not count_b or len(count_b) < 1:
            raise EOFError("Unexpected EOF while reading bucket count")
        count = count_b[0]
        bucket = cls(bucket_size)
        if count:
            to_read = count * fp_size
            data = stream.read(to_read)
            if len(data) < to_read:
                raise EOFError("Unexpected EOF while reading bucket fingerprints")
            offset = 0
            for _ in range(count):
                fp = data[offset:offset + fp_size]
                bucket.bucket.append(fp)
                offset += fp_size
        return bucket


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
        self.table: List[HydraCuckooBucket] = [HydraCuckooBucket(bucket_size) for _ in range(self.table_size)]
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

            cf = cls.__new__(cls)
            cf.table_size = table_size
            cf.bucket_size = bucket_size
            cf.fingerprint_size = fingerprint_size
            cf.max_swaps = max_swaps
            cf.item_count = item_count
            cf.capacity = table_size * bucket_size
            cf.table = []

            # Read each bucket sequentially to avoid reading whole file
            for _ in range(table_size):
                bucket = HydraCuckooBucket.from_stream(f, bucket_size, fingerprint_size)
                cf.table.append(bucket)

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
        # Keep list for backward-compatible save order, but also build a dict for O(1) lookup
        self.entries: List[Tuple[int, List[int]]] = []  # List of (domain_hash, [ref_ids])
        self._map: Dict[int, List[int]] = {}

    def add_threat(self, domain: str, ref_ids: List[int]):
        """Add threat with minimal data"""
        # Use 64-bit hash of domain
        domain_hash = mmh3.hash64(domain.encode('utf-8'))[0]
        self.entries.append((domain_hash, ref_ids))
        self._map[domain_hash] = ref_ids

    def save(self, path: str):
        """Save in ultra-compact binary format"""
        with open(path, 'wb') as f:
            f.write(self.MAGIC)
            f.write(struct.pack('B', self.VERSION))
            f.write(struct.pack('I', len(self.entries)))

            for domain_hash, ref_ids in self.entries:
                # 8 bytes for hash (signed long long)
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

def parse_threat_line(line: str) -> Tuple[str, List[str]]:
    """
    Parse: dangerous.domains,Unknown(Malware) | github.com/T145/black-mirror(WhiteList)
    Returns: (domain, [full_references])
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None, []
    
    parts = line.split(',', 1)
    domain = parts[0].strip().lower()
    
    references = []
    
    if len(parts) > 1:
        refs_part = parts[1]
        ref_items = [r.strip() for r in refs_part.split('|')]
        
        for ref in ref_items:
            if ref:  # Store entire reference string
                references.append(ref)
    
    return domain, references


def build_filter_from_csv(csv_path: Path, output_dir: Path, registry: ReferenceRegistry, 
                          shard_size: int = 1_000_000):
    """Build HDF shards with minimal binary format"""
    
    print(f"\n{'='*60}")
    print(f"Processing: {csv_path.name}")
    print(f"{'='*60}")
    
    # Count lines
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        total_lines = sum(1 for _ in f)
    
    print(f"Total lines: {total_lines:,}")
    
    shard_idx = 0
    cf = HydraCuckooFilter(capacity=min(shard_size, total_lines))
    meta = MinimalMetadataStore()
    inserted = 0
    
    basename = csv_path.stem
    
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        pbar = tqdm(f, total=total_lines, desc="Building filter", unit="lines")
        
        for line in pbar:
            domain, references = parse_threat_line(line)
            if not domain:
                continue
            
            # Convert references to IDs
            ref_ids = [registry.register(ref) for ref in references]
            
            try:
                cf.insert(domain)
                meta.add_threat(domain, ref_ids)
                inserted += 1
                
                if inserted >= shard_size:
                    save_shard(output_dir, basename, shard_idx, cf, meta)
                    shard_idx += 1
                    cf = HydraCuckooFilter(capacity=shard_size)
                    meta = MinimalMetadataStore()
                    inserted = 0
                    
            except Exception:
                if inserted > 0:
                    save_shard(output_dir, basename, shard_idx, cf, meta)
                    shard_idx += 1
                    cf = HydraCuckooFilter(capacity=shard_size)
                    meta = MinimalMetadataStore()
                    inserted = 0
                    try:
                        cf.insert(domain)
                        meta.add_threat(domain, ref_ids)
                        inserted += 1
                    except:
                        print(f"\nFailed: {domain}")
    
    if inserted > 0:
        save_shard(output_dir, basename, shard_idx, cf, meta)
    
    total_shards = shard_idx + 1 if inserted > 0 else shard_idx
    print(f"\n✓ Created {total_shards} shard(s)")
    
    # Calculate size
    total_size = 0
    for i in range(total_shards):
        shard_name = f"{basename}-{i:03d}"
        filter_path = output_dir / f"{shard_name}.hdf"
        meta_path = output_dir / f"{shard_name}.hdm"
        if filter_path.exists():
            total_size += filter_path.stat().st_size
        if meta_path.exists():
            total_size += meta_path.stat().st_size
    
    print(f"Size: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
    return total_size


def save_shard(output_dir: Path, basename: str, shard_idx: int, 
               cf: HydraCuckooFilter, meta: MinimalMetadataStore):
    """Save shard - minimal binary"""
    shard_name = f"{basename}-{shard_idx:03d}"
    
    filter_path = output_dir / f"{shard_name}.hdf"
    cf.save(str(filter_path))
    
    meta_path = output_dir / f"{shard_name}.hdm"
    meta.save(str(meta_path))
    
    filter_size = filter_path.stat().st_size
    meta_size = meta_path.stat().st_size
    
    print(f"\n✓ {shard_name}: {cf.item_count:,} items, {filter_size + meta_size:,} bytes")


def main():
    """Main entry point"""
    data_dir = Path(".")
    output_dir = Path("blacklists")
    output_dir.mkdir(exist_ok=True)
    
    csv_files = sorted([p for p in data_dir.iterdir() 
                       if p.is_file() and p.suffix.lower() == '.csv'])
    
    if not csv_files:
        print("No CSV files found")
        return
    
    print(f"\nHydraDragonAntivirus - MINIMAL BINARY FORMAT")
    print(f"Found {len(csv_files)} CSV file(s)")
    print("Format: References as IDs (0,1,2...), Domains as hashes")
    print(f"Shard size: 1,000,000 domains\n")
    
    # Global reference registry
    registry = ReferenceRegistry()
    total_size = 0
    
    for csv_path in csv_files:
        try:
            size = build_filter_from_csv(csv_path, output_dir, registry)
            total_size += size
        except Exception as e:
            print(f"\n✗ Error: {csv_path.name}: {e}")
            import traceback
            traceback.print_exc()
    
    # Save reference registry
    reg_path = output_dir / "references.hrf"
    registry.save(str(reg_path))
    reg_size = reg_path.stat().st_size
    total_size += reg_size
    
    print(f"\n{'='*60}")
    print(f"✓ BUILD COMPLETE")
    print(f"References: {len(registry.id_to_ref)} unique")
    print(f"Registry size: {reg_size:,} bytes")
    print(f"Total database size: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
