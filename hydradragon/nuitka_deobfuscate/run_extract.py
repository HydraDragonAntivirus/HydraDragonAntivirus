"""
run_extract.py
------------------------------------------------------
- Removed raw blob scan (Pass 1); section-based extraction covers all cases.
- emit_pyc enabled by default (True); Pass 2 writes .pyc files from section items.
- Added all marshal code object tags for Python 3.x (0xe3, 0x63, 0xf3).
- Added -v/--version CLI argument (was missing in V14, causing argparse rejection).
- Version propagated to get_pyc_header() and marshal.dumps() correctly.
- Auto-detection of Python version via scored marshal brute-force probe.
- py -3.12 usage in run.bat (handled externally).
"""

from __future__ import annotations
import hashlib
import os
import sys
import struct
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re

# ============================================================================
# SAFE MARSHAL — ONLY XDIS, NO C-MARSHAL (avoids SegFaults on 3.12 blobs)
# ============================================================================
import xdis.marsh as marshal
from xdis.magics import by_version, magic2int, magic_int2tuple
from xdis.unmarshal import FLAG_REF, TYPE_STRING, load_code as xdis_load_code


import zlib
import random

class CommercialBypass:
    """Research implementation for Nuitka Commercial data-hiding metadata.

    Use this only for binaries that you own or are authorized to inspect.

    Algorithm summary (from DataHidingPlugin.py):
    - Protected constants metadata uses substitution cipher + XOR with running counter + MD5 digest feedback
    - Key material: _mapping[] (256 byte inverse subst table) + d0-d7 (8 MD5 digest bytes)
    - Module names: mapping2 seeded with Random(27), always reconstructible

    Detection: if CRC32 of the payload doesn't match after header, the blob is protected.
    Key extraction: scan .text/.rdata for _mapping[] (256 byte lookup table) and d0-d7.
    Strategy v2: try ALL mapping candidates x ALL d0-d7 candidates,
                 validate each combination with CRC32 before accepting.
    """

    def __init__(self):
        # mapping2 for module names - ALWAYS seed=27, reconstructible without the binary
        r = random.Random(27)
        fwd = list(range(1, 256))
        r.shuffle(fwd)
        fwd.insert(0, 0)
        self.mapping2_forward = list(fwd)
        # Inverse mapping2 for name decoding
        self.name_decode_table = [0] * 256
        for i, v in enumerate(fwd):
            self.name_decode_table[v] = i
        # Expected _mapping2 table as stored in the binary (= inverse of forward mapping2)
        self.expected_binary_mapping2 = list(self.name_decode_table)

    def decode_module_name(self, encoded_name: bytes) -> str:
        """Decode a module name obfuscated with mapping2 (seed=27)."""
        decoded = bytearray()
        for b in encoded_name:
            decoded.append(self.name_decode_table[b])
        return decoded.decode('utf-8', errors='replace')

    def is_blob_encrypted(self, blob_data: bytes) -> bool:
        """Determine if the blob is encrypted by checking CRC32."""
        if len(blob_data) < 16:
            return False
        crc_stored = struct.unpack('<I', blob_data[0:4])[0]
        size_stored = struct.unpack('<I', blob_data[4:8])[0]
        if 8 + size_stored > len(blob_data):
            return True
        actual_crc = zlib.crc32(blob_data[8:8 + size_stored]) & 0xFFFFFFFF
        if actual_crc != crc_stored:
            return True
        return False

    def has_commercial_digest(self, blob_data: bytes) -> bool:
        """Detect a supported protected layout marker."""
        if len(blob_data) < 24:
            return False
        size_stored = struct.unpack('<I', blob_data[4:8])[0]
        extra = len(blob_data) - 8 - size_stored
        return extra == 16

    def get_blob_layout(self, blob_data: bytes) -> dict:
        """Return structural metadata for open-source and commercial blobs."""
        if len(blob_data) < 8:
            return {
                'declared_size': 0,
                'available_payload': 0,
                'extra_bytes': 0,
                'has_commercial_digest': False,
            }
        declared_size = struct.unpack('<I', blob_data[4:8])[0]
        available_payload = max(0, len(blob_data) - 8)
        extra_bytes = len(blob_data) - 8 - declared_size
        return {
            'declared_size': declared_size,
            'available_payload': available_payload,
            'extra_bytes': extra_bytes,
            'has_commercial_digest': extra_bytes == 16,
        }

    def _decrypt_raw(self, encrypted_blob: bytes, mapping: list, d_values: list,
                      max_bytes: int = 0) -> bytes:
        """Decrypt the blob (or only the first max_bytes for quick validation)."""
        original_size = struct.unpack('<I', encrypted_blob[4:8])[0]
        if max_bytes > 0:
            out_needed = min(max_bytes + 8, original_size + 8)
        else:
            out_needed = original_size + 8
        output = bytearray(out_needed)
        output[:8] = encrypted_blob[:8]
        total_enc = original_size + 16
        if max_bytes > 0:
            loop_end = min(8 + out_needed + 16, 8 + total_enc, len(encrypted_blob))
        else:
            loop_end = min(8 + total_enc, len(encrypted_blob))
        mapping_tbl = mapping
        d0, d1, d2, d3, d4, d5, d6, d7 = d_values[0], d_values[1], d_values[2], d_values[3], d_values[4], d_values[5], d_values[6], d_values[7]
        d_lut = (d0, d1, d2, d3, d4, d5, d6, d7)
        last = 0
        enc = encrypted_blob
        for i in range(8, loop_end):
            c = enc[i]
            temp = (last + (i - 8)) & 0xFF
            c = c ^ temp
            c = mapping_tbl[c]
            if i >= 24:
                idx = i - 16
                if idx < out_needed:
                    output[idx] = c
            last = (c + d_lut[i & 7]) & 0xFF
        return bytes(output)

    def _check_crc(self, decrypted: bytes) -> bool:
        """Verify CRC32 of the decrypted blob. True = OK."""
        if len(decrypted) < 8:
            return False
        crc_stored = struct.unpack('<I', decrypted[0:4])[0]
        size_stored = struct.unpack('<I', decrypted[4:8])[0]
        if 8 + size_stored > len(decrypted):
            return False
        actual_crc = zlib.crc32(decrypted[8:8 + size_stored]) & 0xFFFFFFFF
        return actual_crc == crc_stored

    def _quick_validate(self, encrypted_blob: bytes, mapping: list, d_values: list) -> bool:
        """Quick validation: decrypt first ~64 bytes and verify module structure."""
        try:
            partial = self._decrypt_raw(encrypted_blob, mapping, d_values, max_bytes=64)
            data_start = partial[8:] if len(partial) > 8 else b''
            if not data_start:
                return False
            null_pos = data_start.find(b'\x00')
            if null_pos < 1:
                return False
            raw_name = data_start[:null_pos]
            decoded = self.decode_module_name(raw_name)
            printable_ok = sum(1 for c in decoded if c.isprintable() or c == '.') / max(len(decoded), 1) >= 0.8
            if not printable_ok:
                printable_ok = sum(1 for b in raw_name if 0x20 <= b < 0x7F) / max(len(raw_name), 1) >= 0.8
            if not printable_ok:
                return False
            size_pos = null_pos + 1
            if size_pos + 4 <= len(data_start):
                chunk_size = struct.unpack('<I', data_start[size_pos:size_pos + 4])[0]
                orig_size = struct.unpack('<I', encrypted_blob[4:8])[0]
                if chunk_size > orig_size or chunk_size == 0:
                    return False
            return True
        except Exception:
            return False

    def decrypt_blob_auto(self, encrypted_blob: bytes, mapping_candidates: list, d_candidates: list) -> bytes:
        """Try all mapping x d0-d7 combinations with quick validation."""
        filtered = [m for m in mapping_candidates if m != self.expected_binary_mapping2]
        if filtered and len(filtered) < len(mapping_candidates):
            mapping_candidates = filtered
        for mi, mapping in enumerate(mapping_candidates):
            derived_d = self._derive_d_from_blob(encrypted_blob, mapping)
            if derived_d:
                try:
                    result = self._decrypt_raw(encrypted_blob, mapping, derived_d)
                    if self._check_crc(result):
                        return result, mapping, derived_d
                except Exception:
                    pass
        valid_pairs = []
        for mi, mapping in enumerate(mapping_candidates):
            for di, d_vals in enumerate(d_candidates):
                if self._quick_validate(encrypted_blob, mapping, d_vals):
                    valid_pairs.append((mi, mapping, di, d_vals))
        if not valid_pairs:
            valid_pairs = [(mi, m, di, d) for mi, m in enumerate(mapping_candidates)
                           for di, d in enumerate(d_candidates)]
        for mi, mapping, di, d_vals in valid_pairs:
            try:
                result = self._decrypt_raw(encrypted_blob, mapping, d_vals)
                if self._check_crc(result):
                    return result, mapping, d_vals
            except Exception:
                continue
        best = self._decrypt_raw(encrypted_blob, mapping_candidates[0], d_candidates[0])
        return best, mapping_candidates[0], d_candidates[0]

    def _find_all_mapping_candidates(self, pe, rdata_only: bool = False):
        """Collect ALL _mapping[] candidates (complete 0-255 permutations)."""
        candidates = []
        _identity = list(range(256))
        section_order = {'.rdata': 0, '.data': 1, '.text': 2}
        sections_sorted = sorted(
            pe.sections,
            key=lambda s: section_order.get(
                s.Name.rstrip(b'\x00').decode('ascii', errors='replace'), 3)
        )
        for section in sections_sorted:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            sec_key = next((k for k in ('.rdata', '.data', '.text') if k in name), None)
            if sec_key is None:
                continue
            if rdata_only and sec_key != '.rdata':
                continue
            sec_data = section.get_data()
            sec_size = len(sec_data)
            if sec_size < 256:
                continue
            freq = [0] * 256
            distinct = 0
            for b in sec_data[:256]:
                if freq[b] == 0:
                    distinct += 1
                freq[b] += 1

            def _check(offset, _sec_data=sec_data, _sec_key=sec_key, _section=section):
                if distinct != 256:
                    return
                table = list(_sec_data[offset:offset + 256])
                if table == _identity:
                    return
                if any(c[1] == table for c in candidates):
                    return
                rva = _section.VirtualAddress + offset
                candidates.append((rva, table, _sec_key))

            _check(0)
            for offset in range(1, sec_size - 256):
                out_b = sec_data[offset - 1]
                freq[out_b] -= 1
                if freq[out_b] == 0:
                    distinct -= 1
                in_b = sec_data[offset + 255]
                if freq[in_b] == 0:
                    distinct += 1
                freq[in_b] += 1
                _check(offset)
            if rdata_only and candidates:
                break
        order = {'.rdata': 0, '.data': 1, '.text': 2}
        candidates.sort(key=lambda x: order.get(x[2], 3))
        return [c[1] for c in candidates]

    def _find_all_digest_candidates(self, pe, pe_data: bytes, mapping_candidates: list) -> list:
        """Find all d0-d7 candidate sets using multiple strategies."""
        all_candidates = []
        seen = set()
        data_mappings = [m for m in mapping_candidates if m != self.expected_binary_mapping2]
        if not data_mappings:
            data_mappings = mapping_candidates
        xref_results = self._find_d_via_mapping_xref(pe, pe_data, data_mappings)
        for d in xref_results:
            key = tuple(d)
            if key not in seen:
                seen.add(key)
                all_candidates.append(d)
        scan_results = self._scan_imm8_clusters(pe)
        for d in scan_results:
            key = tuple(d)
            if key not in seen:
                seen.add(key)
                all_candidates.append(d)
        raw_results = self._scan_raw_imm8_sequences(pe)
        for d in raw_results:
            key = tuple(d)
            if key not in seen and any(v > 0 for v in d):
                seen.add(key)
                all_candidates.append(d)
        return all_candidates

    def _find_d_via_mapping_xref(self, pe, pe_data: bytes, mapping_candidates: list) -> list:
        """Search .text for LEA/MOV instructions that reference _mapping[]."""
        results = []
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_section = None
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if '.text' in name:
                text_section = section
                break
        if not text_section:
            return results
        text_data = text_section.get_data()
        text_va = image_base + text_section.VirtualAddress
        for section in pe.sections:
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if sec_name not in ('.rdata', '.data'):
                continue
            sec_data = section.get_data()
            sec_va = image_base + section.VirtualAddress
            for mapping_table in mapping_candidates:
                mapping_bytes = bytes(mapping_table)
                offset_in_sec = sec_data.find(mapping_bytes)
                if offset_in_sec == -1:
                    continue
                mapping_va = sec_va + offset_in_sec
                for text_off in range(0, len(text_data) - 8):
                    for insn_len in [3, 4, 5, 6, 7]:
                        if text_off + insn_len + 4 > len(text_data):
                            break
                        disp = struct.unpack('<i', text_data[text_off + insn_len:text_off + insn_len + 4])[0]
                        next_insn_va = text_va + text_off + insn_len + 4
                        target_va = next_insn_va + disp
                        if target_va == mapping_va:
                            func_start = max(0, text_off - 512)
                            func_end = min(len(text_data), text_off + 1024)
                            func_bytes = text_data[func_start:func_end]
                            d_vals = self._extract_imm8_from_switch(func_bytes)
                            if d_vals:
                                results.append(d_vals)
                            break
        return results

    def _extract_imm8_from_switch(self, code_window: bytes) -> list:
        """Extract 8 imm8 values from a code block (switch-case d0-d7)."""
        imm8_by_pos = []
        i = 0
        while i < len(code_window) - 2:
            b = code_window[i]
            if b in (0x80, 0x82) and (code_window[i+1] & 0xF8) in (0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8):
                imm8_by_pos.append((i, code_window[i+2]))
                i += 3; continue
            if 0xB0 <= b <= 0xB7:
                imm8_by_pos.append((i, code_window[i+1]))
                i += 2; continue
            if b == 0x6A:
                imm8_by_pos.append((i, code_window[i+1]))
                i += 2; continue
            if b == 0x04:
                imm8_by_pos.append((i, code_window[i+1]))
                i += 2; continue
            i += 1
        for j in range(len(imm8_by_pos) - 7):
            cluster = imm8_by_pos[j:j+8]
            spread = cluster[7][0] - cluster[0][0]
            if spread < 200:
                vals = [c[1] for c in cluster]
                if len(set(vals)) > 2:
                    return vals
        return []

    def _scan_imm8_clusters(self, pe) -> list:
        """Generic scan for clusters of 8 ADD/MOV imm8 in .text."""
        results = []
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if '.text' not in name:
                continue
            sec_data = section.get_data()
            for prefix in [b'\x80\xc1', b'\x80\xc0', b'\x80\xc2']:
                positions = []
                pos = 0
                while pos < len(sec_data) - 3:
                    idx = sec_data.find(prefix, pos)
                    if idx == -1:
                        break
                    imm = sec_data[idx + 2]
                    positions.append((idx, imm))
                    pos = idx + 1
                for j in range(len(positions) - 7):
                    cluster = positions[j:j+8]
                    spread = cluster[7][0] - cluster[0][0]
                    if spread < 600:
                        vals = [c[1] for c in cluster]
                        if len(set(vals)) > 3:
                            results.append(vals)
        return results

    def _scan_raw_imm8_sequences(self, pe) -> list:
        """Search for d0-d7 byte sequences in .text near switch-case instructions."""
        results = []
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if '.text' not in name:
                continue
            sec_data = section.get_data()
            for anchor_prefix in [b'\x83\xe1\x07', b'\x83\xe0\x07', b'\x83\xe2\x07']:
                pos = 0
                while pos < len(sec_data) - 200:
                    idx = sec_data.find(anchor_prefix, pos)
                    if idx == -1:
                        break
                    window = sec_data[idx:idx + 256]
                    d_vals = self._extract_imm8_from_switch(window)
                    if d_vals and len(set(d_vals)) >= 3:
                        results.append(d_vals)
                    pos = idx + 1
                    if len(results) > 20:
                        return results
        return results

    def _derive_d_from_blob(self, encrypted_blob: bytes, mapping: list) -> list:
        """Derive d0-d7 directly from the encrypted blob using the mapping."""
        if len(encrypted_blob) < 16:
            return None
        d = [0] * 8
        last = 0
        for k in range(8):
            c = encrypted_blob[8 + k]
            temp = (last + k) & 0xFF
            c = c ^ temp
            c = mapping[c]
            d[k] = c
            last = (c + c) & 0xFF
        return d

    def decrypt_blob(self, encrypted_blob: bytes, mapping: list, d_values: list) -> bytes:
        """Decrypt the blob with known mapping and d_values."""
        if len(encrypted_blob) < 24:
            return encrypted_blob
        result = self._decrypt_raw(encrypted_blob, mapping, d_values)
        crc_stored = struct.unpack('<I', result[0:4])[0]
        size_stored = struct.unpack('<I', result[4:8])[0]
        if 8 + size_stored <= len(result):
            actual_crc = zlib.crc32(result[8:8 + size_stored]) & 0xFFFFFFFF
            if actual_crc != crc_stored:
                pass
        return result


class PBKDF2AESBypass:
    """Detect and decrypt Nuitka Commercial PBKDF2+AES-CBC protected payloads.

    Newer Nuitka Commercial versions (post-2024) use PBKDF2-HMAC-SHA256 key
    derivation + AES-128-CBC to encrypt individual module code objects.

    Detection pattern (from decoded NBC constants):
        - Strings: 'hashlib', 'pbkdf2_hmac', 'sha256', 'marshal', 'loads', 'exec'
        - Integer: 100000 (PBKDF2 iterations)
        - Dict:    {'dklen': 32}
        - Integer: 16 (AES block size)
        - Slices:  (None, 16, None), (16, 32, None), (32, None, None)
        - Large bytes blob (the encrypted payload)
    """

    # PBKDF2 parameters
    DEFAULT_ITERATIONS = 100000
    DEFAULT_DKLEN = 32
    DEFAULT_HASH = 'sha256'

    # AES parameters
    AES_BLOCK_SIZE = 16
    IV_SIZE = 16
    SALT_SIZE = 16

    # Minimum header that must precede the real encrypted payload
    # Format: [16 bytes IV][16 bytes salt][rest: AES-CBC data]
    # (The 4-byte size prefix appears only in the DECRYPTED data, not the encrypted blob)
    ENC_HEADER_SIZE = 16 + 16

    @staticmethod
    def detect_pbkdf2_pattern(constants: list) -> bool:
        """Scan decoded NBC constants for the PBKDF2+AES-CBC signature.

        Returns True if the constants match the known pattern from
        Nuitka's icondata/hidden module decryption stub.
        """
        has_hashlib = False
        has_pbkdf2 = False
        has_sha256 = False
        has_100k = False
        has_dklen32 = False
        has_marshal = False
        has_loads = False
        has_exec = False
        has_slice_16 = False
        has_slice_16_32 = False
        has_slice_32 = False
        has_block16 = False

        def _walk(v, depth=0):
            nonlocal has_hashlib, has_pbkdf2, has_sha256, has_100k
            nonlocal has_dklen32, has_marshal, has_loads, has_exec
            nonlocal has_slice_16, has_slice_16_32, has_slice_32, has_block16
            if depth > 20:
                return
            if isinstance(v, str):
                if v == 'hashlib': has_hashlib = True
                elif v == 'pbkdf2_hmac': has_pbkdf2 = True
                elif v == 'sha256': has_sha256 = True
                elif v == 'marshal': has_marshal = True
                elif v == 'loads': has_loads = True
                elif v == 'exec': has_exec = True
                return
            if isinstance(v, int):
                if v == 100000: has_100k = True
                elif v == 16: has_block16 = True
                return
            if isinstance(v, dict):
                if v.get('dklen') == 32:
                    has_dklen32 = True
                for val in v.values():
                    _walk(val, depth + 1)
                return
            if isinstance(v, tuple) and len(v) == 4 and v[0] == 'slice':
                if v[1] is None and v[2] == 16 and v[3] is None:
                    has_slice_16 = True
                elif v[1] == 16 and v[2] == 32 and v[3] is None:
                    has_slice_16_32 = True
                elif v[1] == 32 and v[2] is None and v[3] is None:
                    has_slice_32 = True
                return
            if isinstance(v, (list, tuple)):
                for item in v:
                    _walk(item, depth + 1)
                return
            if isinstance(v, (set, frozenset)):
                for item in v:
                    _walk(item, depth + 1)

        for c in constants:
            _walk(c, 0)

        score = sum([has_hashlib, has_pbkdf2, has_sha256, has_100k,
                     has_dklen32, has_marshal, has_loads, has_exec,
                     has_slice_16, has_slice_16_32, has_slice_32, has_block16])
        return score >= 8

    @staticmethod
    def find_encrypted_payload(constants: list) -> bytes | None:
        """Find the encrypted payload blob within the decoded constants.

        The encrypted payload is typically a large bytes/bytearray value
        (>= ENC_HEADER_SIZE bytes) within the constants.
        """
        candidates = []

        def _walk(v, depth=0):
            if depth > 20:
                return
            if isinstance(v, (bytes, bytearray)):
                b = bytes(v)
                if len(b) >= PBKDF2AESBypass.ENC_HEADER_SIZE:
                    candidates.append(b)
                return
            if isinstance(v, (list, tuple)):
                for item in v:
                    _walk(item, depth + 1)
                return
            if isinstance(v, dict):
                for val in v.values():
                    _walk(val, depth + 1)
                return
            if isinstance(v, (set, frozenset)):
                for item in v:
                    _walk(item, depth + 1)

        for c in constants:
            _walk(c, 0)

        candidates.sort(key=lambda x: -len(x))
        return candidates[0] if candidates else None

    @staticmethod
    def find_salt_in_constants(constants: list,
                                exclude: bytes | None = None) -> bytes | None:
        """Find the PBKDF2 salt bytes within the decoded NBC constants.

        The salt is stored as a separate bytes value (typically 16-64 bytes)
        alongside the encrypted payload in Nuitka Commercial modules.
        Excludes the large ciphertext payload via the `exclude` parameter.
        """
        candidates: list[bytes] = []

        def _walk(v, depth=0):
            if depth > 20:
                return
            if isinstance(v, (bytes, bytearray)):
                b = bytes(v)
                if exclude is not None and b == exclude:
                    return
                if 16 <= len(b) <= 64:
                    candidates.append(b)
                return
            if isinstance(v, (list, tuple)):
                for item in v:
                    _walk(item, depth + 1)
                return
            if isinstance(v, dict):
                for val in v.values():
                    _walk(val, depth + 1)
                return
            if isinstance(v, (set, frozenset)):
                for item in v:
                    _walk(item, depth + 1)

        for c in constants:
            _walk(c, 0)

        candidates.sort(key=lambda x: -len(x))
        return candidates[0] if candidates else None

    @staticmethod
    def extract_password_candidates_from_constants(constants: list) -> list[bytes]:
        """Extract likely password candidates from module constants.

        In Nuitka Commercial, the PBKDF2 password is stored as a string or
        bytes literal in the same module's NBC constant stream (the
        decryption stub module). Walk all constants and collect printable
        strings and bytes values that could be the password.
        """
        candidates: list[bytes] = []
        seen = set()

        def _walk(v, depth=0):
            if depth > 20:
                return
            if isinstance(v, str):
                if 4 <= len(v) <= 128 and v.isprintable():
                    b = v.encode('utf-8')
                    if b not in seen:
                        seen.add(b)
                        candidates.append(b)
                return
            if isinstance(v, bytes):
                if 4 <= len(v) <= 128 and v not in seen:
                    seen.add(v)
                    candidates.append(v)
                return
            if isinstance(v, (list, tuple)):
                for item in v:
                    _walk(item, depth + 1)
                return
            if isinstance(v, dict):
                for val in v.values():
                    _walk(val, depth + 1)
                return
            if isinstance(v, (set, frozenset)):
                for item in v:
                    _walk(item, depth + 1)
                return

        for c in constants:
            _walk(c, 0)

        return candidates

    @staticmethod
    def generate_path_based_candidates(mod_name: str) -> list[bytes]:
        """Generate password candidates from the module's dotted name hierarchy.

        Nuitka Commercial derives the PBKDF2 password from the module file's
        directory path (_here = dirname(abspath(__file__))). The auto_disassemble
        logic tries several derivations: b'', _here.encode(),
        basename(_here).encode(), abspath(_here).encode().

        By splitting the dotted module name (e.g. "Features.Aimbot") into path
        components, we can reconstruct likely _here and basename values.
        """
        candidates: list[bytes] = []
        seen: set[bytes] = set()

        # The empty password is one of the auto_disassemble candidates
        candidates.append(b'')
        seen.add(b'')

        parts = mod_name.split('.')
        # Each component as a standalone candidate (possible basename)
        for part in parts:
            b = part.encode('utf-8')
            if b not in seen and 1 <= len(b) <= 128:
                seen.add(b)
                candidates.append(b)

        # Full dotted name
        full_dotted = mod_name.encode('utf-8')
        if full_dotted not in seen and len(full_dotted) <= 128:
            seen.add(full_dotted)
            candidates.append(full_dotted)

        # Path-like: parts joined by backslash (e.g. Features\Aimbot)
        for i in range(len(parts)):
            sub_path = '\\'.join(parts[i:])
            b = sub_path.encode('utf-8')
            if b not in seen and len(b) <= 128:
                seen.add(b)
                candidates.append(b)

        # For each prefix of the path (parent directories)
        for i in range(1, len(parts)):
            prefix = '\\'.join(parts[:i])
            b = prefix.encode('utf-8')
            if b not in seen and len(b) <= 128:
                seen.add(b)
                candidates.append(b)

        return candidates

    @staticmethod
    def is_pbkdf2_encrypted_blob(blob_data: bytes) -> bool:
        """Check if a raw blob appears to be PBKDF2+AES-CBC encrypted.

        Heuristic: if declared size doesn't match CRC32 check AND
        the blob has at least ENC_HEADER_SIZE bytes of payload after
        the standard 8-byte header, flag it.
        """
        if len(blob_data) < 8 + PBKDF2AESBypass.ENC_HEADER_SIZE:
            return False
        try:
            crc_stored = struct.unpack('<I', blob_data[0:4])[0]
            size_stored = struct.unpack('<I', blob_data[4:8])[0]
            if 8 + size_stored > len(blob_data):
                return True
            actual_crc = zlib.crc32(blob_data[8:8 + size_stored]) & 0xFFFFFFFF
            if actual_crc != crc_stored:
                return True
            return False
        except Exception:
            return False

    def try_decrypt(self, encrypted_payload: bytes, password: bytes,
                    salt: bytes | None = None,
                    iterations: int = DEFAULT_ITERATIONS,
                    dklen: int = DEFAULT_DKLEN) -> bytes | None:
        """Attempt PBKDF2 key derivation + AES-CBC decryption.

        Salt is stored as a separate bytes constant in the module.
        Tries multiple payload layouts since the exact internal structure
        of the ciphertext blob depends on the Nuitka version.

        Returns decrypted bytes on success, None on failure.
        """
        if len(encrypted_payload) < 4:
            return None
        if salt is None:
            return None

        data = encrypted_payload

        # Try several possible layouts for the payload blob.
        # Each layout is (iv_offset, enc_offset, use_seed):
        #   iv_offset   – bytes to read for IV (or IV seed)
        #   enc_offset  – byte offset where encrypted data starts
        #   use_seed    – if True, first 4 bytes at iv_offset are uint32-LE seed
        layouts = [
            (0, 4, True),    # new format: [4 seed][metadata][enc] from stub
            (0, 16, False),  # old format: [16 IV][enc] (enc aligned if %16==0)
            (0, 0, False),   # entire blob is enc data (zero IV)
        ]

        for iv_off, enc_off, use_seed in layouts:
            if enc_off > len(data):
                continue
            enc_data = data[enc_off:]
            if len(enc_data) == 0:
                continue
            if len(enc_data) % self.AES_BLOCK_SIZE != 0:
                continue
            if use_seed:
                if iv_off + 4 > len(data):
                    continue
                iv_seed = struct.unpack('<I', data[iv_off:iv_off + 4])[0]
                iv = iv_seed.to_bytes(16, 'little')
            else:
                if iv_off + 16 > len(data):
                    continue
                iv = data[iv_off:iv_off + 16]
            result = self._do_decrypt(enc_data, iv, salt, password, iterations, dklen)
            if result is not None and len(result) > 16:
                return result

        return None

    def _do_decrypt(self, enc_data: bytes, iv: bytes, salt: bytes,
                     password: bytes, iterations: int, dklen: int) -> bytes | None:
        """Internal: PBKDF2 + AES-CBC decryption via pycryptodome."""
        try:
            from Crypto.Cipher import AES
            key = hashlib.pbkdf2_hmac(
                self.DEFAULT_HASH, password, salt, iterations, dklen=dklen
            )
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plain = bytearray(cipher.decrypt(enc_data))
            if len(plain) > 0:
                pad_len = plain[-1]
                if 1 <= pad_len <= self.AES_BLOCK_SIZE:
                    if all(b == pad_len for b in plain[-pad_len:]):
                        return bytes(plain[:-pad_len])
            return bytes(plain)
        except Exception:
            return None


def _is_plausible_module_name(name: str) -> bool:
    """Validate DataComposer chunk names."""
    if name == "":
        return True
    if name in (".bytecode", ".files"):
        return True
    if len(name) > 4096:
        return False
    if any(ord(c) < 32 for c in name):
        return False
    return all(c.isalnum() or c in "._-+/\\:" for c in name)

# =============================================================================
# INLINE CONSTANT STREAM DECODER
# Verbatim port of the VLQ reader, tag dispatcher, CodeObject tag parser,
# stream decoder, and string extractor. No external imports required.
# =============================================================================
import sys as _sys
from math import copysign as _copysign

_NBC_END_OF_STREAM = object()
_NBC_PARSE_ERROR = object()
_nbc_last_unpacked = None
_NBC_TARGET_PYTHON = _sys.version_info[:2]


def _nbc_normalize_python_version(version):
    if version is None:
        return tuple(_NBC_TARGET_PYTHON[:2])
    if isinstance(version, (list, tuple)):
        if not version:
            return tuple(_NBC_TARGET_PYTHON[:2])
        return (int(version[0]), int(version[1]))
    if isinstance(version, str):
        import re as _re_nbc
        m = _re_nbc.match(r"^\s*(\d+)\.(\d+)", version)
        if m:
            return (int(m.group(1)), int(m.group(2)))
        return tuple(_NBC_TARGET_PYTHON[:2])
    try:
        return (int(version[0]), int(version[1]))
    except Exception:
        return tuple(_NBC_TARGET_PYTHON[:2])


def _nbc_set_target(version):
    global _NBC_TARGET_PYTHON
    _NBC_TARGET_PYTHON = _nbc_normalize_python_version(version)


def _nbc_target_hex(version=None):
    major, minor = _nbc_normalize_python_version(version)
    return (major << 8) | (minor << 4)


def _nbc_read_vlq(data, pos, *, max_bits=64):
    result = 0
    shift = 0
    end = len(data)
    while pos < end:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, pos
        shift += 7
        if shift >= max_bits + 7:
            break
    return result, pos


def _nbc_parse_code_object_tag(data, pos, python_version=None):
    try:
        py_hex = _nbc_target_hex(python_version)
        flags, pos = _nbc_read_vlq(data, pos)
        flag_base = 1
        func_name, pos = _nbc_unpack_single(data, pos)
        if not isinstance(func_name, str):
            func_name = str(func_name) if func_name else "<unknown>"
        line_number, pos = _nbc_read_vlq(data, pos)
        line_number += 1
        arg_names, pos = _nbc_unpack_single(data, pos)
        if not isinstance(arg_names, tuple):
            arg_names = ()
        arg_count, pos = _nbc_read_vlq(data, pos)
        qualname = func_name
        if py_hex >= 0x3B0:
            if flags & flag_base:
                qualname, pos = _nbc_unpack_single(data, pos)
                if not isinstance(qualname, str):
                    qualname = func_name
            flag_base <<= 1
        free_vars = ()
        if flags & flag_base:
            free_vars, pos = _nbc_unpack_single(data, pos)
            if not isinstance(free_vars, tuple):
                free_vars = ()
        flag_base <<= 1
        kw_only = 0
        if py_hex >= 0x300:
            if flags & flag_base:
                kw_only, pos = _nbc_read_vlq(data, pos)
                kw_only += 1
            flag_base <<= 1
        pos_only = 0
        if py_hex >= 0x380:
            if flags & flag_base:
                pos_only, pos = _nbc_read_vlq(data, pos)
                pos_only += 1
            flag_base <<= 1
        co_flags = 0
        gen_bits = (flags >> (flag_base.bit_length() - 1)) & 3
        if py_hex >= 0x360 and gen_bits == 3:
            co_flags |= 0x200
        elif py_hex >= 0x350 and gen_bits == 2:
            co_flags |= 0x100
        elif gen_bits == 1:
            co_flags |= 0x20
        flag_base <<= 2
        if flags & flag_base:
            co_flags |= 0x01
        flag_base <<= 1
        if flags & flag_base:
            co_flags |= 0x02
        flag_base <<= 1
        if flags & flag_base:
            co_flags |= 0x04
        flag_base <<= 1
        if flags & flag_base:
            co_flags |= 0x08
        return {
            '_type': 'CodeObject',
            'name': func_name,
            'qualname': qualname,
            'line': line_number,
            'args': list(arg_names),
            'argcount': arg_count,
            'kwonly': kw_only,
            'posonly': pos_only,
            'freevars': list(free_vars),
            'flags': co_flags,
        }, pos
    except Exception:
        return {'_type': 'CodeObject', 'name': '<parse_error>'}, pos


def _nbc_unpack_constant_inner(data, pos, ch, marker):
    if ch in ('a', 'u'):
        end = data.find(b'\x00', pos)
        if end == -1 or end > pos + 65536:
            return "", pos
        return data[pos:end].decode('utf-8', errors='replace'), end + 1
    elif ch == 'w':
        if pos < len(data):
            return data[pos:pos + 1].decode('utf-8', errors='replace'), pos + 1
        return "", pos
    elif ch == 'v':
        size, pos = _nbc_read_vlq(data, pos)
        if pos + size > len(data):
            return "", pos
        return data[pos:pos + size].decode('utf-8', errors='replace'), pos + size
    elif ch == 's':
        return "", pos
    elif ch == 'c':
        end = data.find(b'\x00', pos)
        if end == -1 or end > pos + 65536:
            return b'', pos
        return data[pos:end], end + 1
    elif ch == 'b':
        size, pos = _nbc_read_vlq(data, pos)
        if pos + size > len(data):
            return b'', pos
        return data[pos:pos + size], pos + size
    elif ch == 'B':
        size, pos = _nbc_read_vlq(data, pos)
        if pos + size > len(data):
            return bytearray(), pos
        return bytearray(data[pos:pos + size]), pos + size
    elif ch == 'd':
        if pos < len(data):
            return bytes([data[pos]]), pos + 1
        return b'', pos
    elif ch == 'n':
        return None, pos
    elif ch == 't':
        return True, pos
    elif ch == 'F':
        return False, pos
    elif ch == 'l':
        value, pos = _nbc_read_vlq(data, pos)
        return value, pos
    elif ch == 'q':
        value, pos = _nbc_read_vlq(data, pos)
        return -value, pos
    elif ch == 'I':
        value, pos = _nbc_read_vlq(data, pos)
        return -value, pos
    elif ch == 'i':
        value, pos = _nbc_read_vlq(data, pos)
        return value, pos
    elif ch in ('g', 'G'):
        is_negative = (ch == 'G')
        num_parts, pos = _nbc_read_vlq(data, pos)
        result = 0
        for _ in range(num_parts):
            result <<= 31
            part, pos = _nbc_read_vlq(data, pos)
            result += part
        return (-result if is_negative else result), pos
    elif ch == 'f':
        if pos + 8 <= len(data):
            return struct.unpack('<d', data[pos:pos + 8])[0], pos + 8
        return 0.0, pos
    elif ch == 'Z':
        if pos < len(data):
            v = data[pos]
            pos += 1
            if v == 0:
                return 0.0, pos
            elif v == 1:
                return -0.0, pos
            elif v == 2:
                return float('nan'), pos
            elif v == 3:
                return _copysign(float('nan'), -1.0), pos
            elif v == 4:
                return float('inf'), pos
            elif v == 5:
                return float('-inf'), pos
            else:
                return 0.0, pos
        return 0.0, pos
    elif ch == 'j':
        if pos + 16 <= len(data):
            real = struct.unpack('<d', data[pos:pos + 8])[0]
            imag = struct.unpack('<d', data[pos + 8:pos + 16])[0]
            return complex(real, imag), pos + 16
        return 0j, pos
    elif ch == 'J':
        parts = []
        for _ in range(2):
            item, pos = _nbc_unpack_single(data, pos)
            parts.append(item if item is not None else 0.0)
        try:
            return complex(parts[0], parts[1]), pos
        except (TypeError, ValueError):
            return 0j, pos
    elif ch == 'T':
        count, pos = _nbc_read_vlq(data, pos)
        if count > 50000:
            return (), pos
        items = []
        for _ in range(count):
            item, pos = _nbc_unpack_single(data, pos)
            items.append(item)
        return tuple(items), pos
    elif ch == 'L':
        count, pos = _nbc_read_vlq(data, pos)
        if count > 50000:
            return [], pos
        items = []
        for _ in range(count):
            item, pos = _nbc_unpack_single(data, pos)
            items.append(item)
        return items, pos
    elif ch == 'D':
        count, pos = _nbc_read_vlq(data, pos)
        if count > 50000:
            return {}, pos
        keys = []
        for _ in range(count):
            k, pos = _nbc_unpack_single(data, pos)
            keys.append(k)
        values = []
        for _ in range(count):
            v, pos = _nbc_unpack_single(data, pos)
            values.append(v)
        d = {}
        for k, v in zip(keys, values):
            try:
                d[k] = v
            except TypeError:
                pass
        return d, pos
    elif ch == 'S':
        count, pos = _nbc_read_vlq(data, pos)
        if count > 50000:
            return set(), pos
        items = []
        for _ in range(count):
            item, pos = _nbc_unpack_single(data, pos)
            items.append(item)
        try:
            return set(items), pos
        except TypeError:
            return set(), pos
    elif ch in ('P', 'R'):
        count, pos = _nbc_read_vlq(data, pos)
        if count > 50000:
            return frozenset(), pos
        items = []
        for _ in range(count):
            item, pos = _nbc_unpack_single(data, pos)
            items.append(item)
        try:
            return frozenset(items), pos
        except TypeError:
            return frozenset(), pos
    elif ch == 'X':
        size, pos = _nbc_read_vlq(data, pos)
        blob = data[pos:pos + size] if pos + size <= len(data) else b''
        return blob, pos + size
    elif ch == 'M':
        if pos < len(data):
            anon_values = {
                0: '<type NoneType>',
                1: '<type ellipsis>',
                2: '<type NotImplementedType>',
                3: '<type function>',
                4: '<type generator>',
                5: '<type builtin_function_or_method>',
                6: '<type code>',
                7: '<type module>',
                8: '<type file>',
                9: '<type classobj>',
                10: '<type UnionType>',
                11: '<type instancemethod>',
            }
            return anon_values.get(data[pos], f'<builtin_M_{data[pos]}>'), pos + 1
        return _NBC_PARSE_ERROR, pos
    elif ch == 'Q':
        if pos < len(data):
            special_values = {
                0: Ellipsis,
                1: NotImplemented,
                2: '<sys.version_info>',
            }
            return special_values.get(data[pos], f'<builtin_Q_{data[pos]}>'), pos + 1
        return _NBC_PARSE_ERROR, pos
    elif ch in ('O', 'E'):
        end = data.find(b'\x00', pos)
        if end == -1:
            return _NBC_PARSE_ERROR, pos
        return data[pos:end].decode('utf-8', errors='replace'), end + 1
    elif ch == ':':
        items = []
        for _ in range(3):
            item, pos = _nbc_unpack_single(data, pos)
            items.append(item)
        return ('slice', items[0], items[1], items[2]), pos
    elif ch == ';':
        items = []
        for _ in range(3):
            item, pos = _nbc_unpack_single(data, pos)
            items.append(item)
        return ('range', items[0], items[1], items[2]), pos
    elif ch == 'A':
        parts = []
        for _ in range(2):
            item, pos = _nbc_unpack_single(data, pos)
            parts.append(item)
        return ('GenericAlias', parts[0], parts[1]), pos
    elif ch == 'H':
        args, pos = _nbc_unpack_single(data, pos)
        return ('UnionType', args), pos
    elif ch == 'C':
        co_info, pos = _nbc_parse_code_object_tag(data, pos)
        return co_info, pos
    elif ch == '.':
        return _NBC_END_OF_STREAM, pos
    else:
        return _NBC_PARSE_ERROR, pos


def _nbc_unpack_single(data, pos):
    global _nbc_last_unpacked
    if pos >= len(data):
        return _NBC_PARSE_ERROR, pos
    marker = data[pos]
    ch = chr(marker) if 32 <= marker < 127 else None
    pos += 1
    if ch == 'p':
        return _nbc_last_unpacked, pos
    if ch == '.':
        return _NBC_END_OF_STREAM, pos
    result = _nbc_unpack_constant_inner(data, pos, ch, marker)
    if result is not None:
        val, pos = result
        _nbc_last_unpacked = val
        return val, pos
    _nbc_last_unpacked = None
    return _NBC_PARSE_ERROR, pos


def _nbc_decode_constants_stream(stream_data: bytes, count: int, *, python_version=None, start_pos: int = 0):
    global _nbc_last_unpacked
    _nbc_last_unpacked = None
    old_target = _NBC_TARGET_PYTHON
    _nbc_set_target(python_version or old_target)
    constants = []
    pos = start_pos
    try:
        for _ in range(count):
            if pos >= len(stream_data):
                break
            val, new_pos = _nbc_unpack_single(stream_data, pos)
            if new_pos <= pos:
                break
            pos = new_pos
            if val is _NBC_END_OF_STREAM:
                break
            if val is _NBC_PARSE_ERROR:
                break
            constants.append(val)
    finally:
        _nbc_last_unpacked = None
        _nbc_set_target(old_target)
    return constants, pos


def _nbc_parse_module_constants(chunk_data: bytes, python_version=None) -> list:
    if len(chunk_data) < 2:
        return []
    try:
        count = struct.unpack('<H', chunk_data[0:2])[0]
    except Exception:
        return []
    if count == 0 or count > 50000:
        return []
    constants, _pos = _nbc_decode_constants_stream(
        chunk_data,
        count,
        python_version=python_version,
        start_pos=2,
    )
    return constants


def _nbc_extract_all_strings(constants: list, *, max_depth: int = 25) -> list:
    seen: set = set()
    out: list = []

    def add(s: str):
        if not s:
            return
        if s in seen:
            return
        seen.add(s)
        out.append(s)

    def walk(v, depth: int):
        if depth > max_depth:
            return
        if isinstance(v, str):
            add(v)
            return
        if isinstance(v, (bytes, bytearray)):
            b = bytes(v)
            if not b:
                return
            try:
                s = b.decode("utf-8")
            except Exception:
                return
            printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
            if printable / max(len(s), 1) >= 0.85:
                add(s)
            return
        if isinstance(v, (tuple, list)):
            for item in v:
                walk(item, depth + 1)
            return
        if isinstance(v, dict):
            for k, val in v.items():
                walk(k, depth + 1)
                walk(val, depth + 1)
            return
        if isinstance(v, (set, frozenset)):
            for item in v:
                walk(item, depth + 1)
            return
        if isinstance(v, tuple) and v and isinstance(v[0], str) and v[0] in ("slice", "range", "GenericAlias", "UnionType"):
            for item in v[1:]:
                walk(item, depth + 1)
            return

    for c in constants:
        walk(c, 0)
    return out


def _is_live_code_object(value) -> bool:
    return type(value).__name__ == "code" or type(value).__name__.startswith("Code") or hasattr(value, "co_code") or hasattr(value, "co_code_adaptive")


def _iter_marshaled_bytecode_payloads(
    value,
    magic_int: int | None = None,
    _seen=None,
    _depth: int = 0,
):
    if _depth > 20:
        return

    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
        if len(payload) >= 16 and payload[:1] in MARSHAL_VERSION_HINT_TAGS:
            if (
                guess_version_from_marshal_bytes(payload) is not None
                or payload[:1] in MARSHAL_CODE_TAGS
                or (magic_int is not None and (looks_like_code_header(payload, 0, magic_int) or try_detect_code_object(payload, 0, magic_int) is not None))
            ):
                yield payload
        return

    if _is_live_code_object(value):
        yield value
        for child in getattr(value, "co_consts", ()) or ():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )
        return

    if isinstance(value, (str, int, float, complex, bool, type(None))):
        return

    if _seen is None:
        _seen = set()
    obj_id = id(value)
    if obj_id in _seen:
        return
    _seen.add(obj_id)

    if isinstance(value, dict):
        for child in value.keys():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )
        for child in value.values():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )
        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for child in value:
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )



# ============================================================================
# PYC HEADER
# ============================================================================


def get_pyc_header(version: str, timestamp: int = None, filesize: int = 0) -> bytes:
    """Generate a valid 16-byte .pyc header using xdis magic."""
    magic = by_version.get(version)
    if not magic:
        raise ValueError(f"xdis has no magic for Python {version}.\nKnown: {sorted(by_version.keys())}")
    header = bytes(magic)
    header += struct.pack("<I", 0)  # Bitfield (timestamp-based)
    if timestamp is None:
        import time

        timestamp = int(time.time())
    header += struct.pack("<I", timestamp)
    header += struct.pack("<I", filesize & 0xFFFFFFFF)
    return header


# ============================================================================
# VERSION HELPERS
# ============================================================================


def parse_version(ver_str: str) -> tuple:
    try:
        parts = ver_str.split(".")
        if len(parts) != 2:
            raise ValueError
        return int(parts[0]), int(parts[1])
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid version '{ver_str}'. Expected MAJOR.MINOR e.g. 3.13") from exc


def get_magic_int(version: str | tuple[int, int]) -> int | None:
    """Resolve a stable xdis magic integer for a MAJOR.MINOR version."""
    if isinstance(version, tuple):
        version = f"{version[0]}.{version[1]}"
    magic = by_version.get(version)
    if not magic:
        return None
    return magic2int(bytes(magic))


def _xdis_version_sort_key(version: str) -> tuple[int, int]:
    major, minor = version.split(".", 1)
    return int(major), int(minor)


def guess_version_from_marshal_bytes(data: bytes) -> str | None:
    """
    Guess Python version from raw marshal code object bytes
    by reading structural fields directly, without full parsing.
    """
    if not data or data[0:1] not in (b"\xe3", b"\x63", b"\xf3"):
        return None

    if data[0:1] == b"\xf3":
        return "3.11+"

    if len(data) < 25:
        return None

    try:
        argcount = struct.unpack_from("<I", data, 1)[0]
        posonlycount = struct.unpack_from("<I", data, 5)[0]
        kwonlycount = struct.unpack_from("<I", data, 9)[0]
        nlocals = struct.unpack_from("<I", data, 13)[0]
        stacksize = struct.unpack_from("<I", data, 17)[0]
        flags = struct.unpack_from("<I", data, 21)[0]

        if argcount > 255 or kwonlycount > 255 or stacksize > 65535:
            kwonlycount2 = struct.unpack_from("<I", data, 5)[0]
            nlocals2 = struct.unpack_from("<I", data, 9)[0]
            flags2 = struct.unpack_from("<I", data, 17)[0]
            if kwonlycount2 <= 255 and nlocals2 <= 65535 and flags2 >= 0:
                return "3.7"

        if flags & 0x0200:
            lower_bound = "3.6"
        else:
            lower_bound = "3.5"

        if posonlycount <= argcount and stacksize <= 65535 and nlocals <= 65535:
            if flags & 0x0100 and not (flags & 0x0200):
                return "3.8"
            return "3.8+"

        return lower_bound
    except Exception:
        return None


def _marshal_candidate_versions(version_hint: str | None) -> list[str]:
    versions = sorted(
        {version for version in by_version if re.fullmatch(r"\d+\.\d+", version) and _xdis_version_sort_key(version) >= (3, 5)},
        key=_xdis_version_sort_key,
        reverse=True,
    )

    runtime_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    if runtime_version in versions:
        runtime_key = _xdis_version_sort_key(runtime_version)
        lower_or_equal = [version for version in versions if version != runtime_version and _xdis_version_sort_key(version) <= runtime_key]
        higher = [version for version in versions if _xdis_version_sort_key(version) > runtime_key]
        versions = [runtime_version] + lower_or_equal + higher

    if version_hint is None:
        return versions

    if version_hint.endswith("+"):
        lower_bound = _xdis_version_sort_key(version_hint[:-1])
        prioritized = [version for version in versions if _xdis_version_sort_key(version) >= lower_bound]
        fallback = [version for version in versions if _xdis_version_sort_key(version) < lower_bound]
        return prioritized + fallback

    if version_hint in versions:
        return [version_hint] + [version for version in versions if version != version_hint]

    return versions


# Marshal code object first-byte tags (Python 3.x)
MARSHAL_CODE_TAGS: frozenset[bytes] = frozenset({b"\xe3", b"\x63", b"\xf3"})
# Extended set: includes pyc-header-prefixed payloads (magic 4 bytes + timestamp)
MARSHAL_VERSION_HINT_TAGS: frozenset[bytes] = frozenset({b"\xe3", b"\x63", b"\xf3"})
import re as _re_mvht
MARSHAL_VERSION_HINT_TAG_PATTERN = _re_mvht.compile(rb"[\xe3\x63\xf3]")


class MemoryReader:
    """Minimal file-like reader over a bytes buffer without slicing the suffix."""

    def __init__(self, data: bytes | bytearray | memoryview, start: int = 0):
        self._data = data if isinstance(data, memoryview) else memoryview(data)
        self._pos = start

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data) - self._pos
        end = min(len(self._data), self._pos + n)
        chunk = self._data[self._pos : end].tobytes()
        self._pos = end
        return chunk


def score_code_object(code_obj) -> int:
    score = 3
    score += len(getattr(code_obj, "co_consts", ()))
    score += len(getattr(code_obj, "co_varnames", ()))
    score += int(bool(getattr(code_obj, "co_filename", None)))
    return score


def try_detect_code_object(
    data: bytes | bytearray | memoryview,
    offset: int,
    magic_int: int | None,
):
    if magic_int is None or len(data) - offset < 32:
        return None

    try:
        reader = MemoryReader(data, offset)
        obj = xdis_load_code(reader, magic_int)
    except Exception:
        return None

    name = type(obj).__name__
    if name == "code" or name.startswith("Code"):
        return obj
    return None


def looks_like_code_header(
    data: bytes | bytearray | memoryview,
    offset: int,
    magic_int: int | None,
) -> bool:
    if magic_int is None:
        return False

    version = magic_int2tuple(magic_int)
    field_count = 1  # argcount
    if version >= (3, 8):
        field_count += 1  # posonlyargcount
    if version >= (3, 0):
        field_count += 1  # kwonlyargcount
    if version < (3, 11):
        field_count += 1  # nlocals
    field_count += 2  # stacksize, flags

    header_end = offset + 1 + (field_count * 4)
    if len(data) < header_end + 1:
        return False

    fields = struct.unpack_from("<" + ("I" * field_count), data, offset + 1)
    cursor = 0

    argcount = fields[cursor]
    cursor += 1
    if argcount > 4096:
        return False

    if version >= (3, 8):
        posonlyargcount = fields[cursor]
        cursor += 1
        if posonlyargcount > 4096:
            return False

    if version >= (3, 0):
        kwonlyargcount = fields[cursor]
        cursor += 1
        if kwonlyargcount > 4096:
            return False

    if version < (3, 11):
        nlocals = fields[cursor]
        cursor += 1
        if nlocals > 65536:
            return False

    stacksize = fields[cursor]
    flags = fields[cursor + 1]
    if stacksize == 0 or stacksize > 65536:
        return False
    if flags > 0x3FFFFFFF:
        return False

    next_tag = data[header_end]
    return next_tag in (ord(TYPE_STRING), FLAG_REF | ord(TYPE_STRING))


def try_load_code_object(
    data: bytes | bytearray | memoryview,
    offset: int,
    magic_int: int | None,
):
    if not looks_like_code_header(data, offset, magic_int):
        return None
    return try_detect_code_object(data, offset, magic_int)


def detect_version_from_marshal(data: bytes) -> str | None:
    """
    Probe stable MAJOR.MINOR xdis versions against likely code-object offsets.
    Scores successful parses by richness to avoid false positives.
    """
    version_hint = guess_version_from_marshal_bytes(data)
    candidates = _marshal_candidate_versions(version_hint)
    probe_offsets = [match.start() for match in MARSHAL_VERSION_HINT_TAG_PATTERN.finditer(data)]
    if not probe_offsets and data[:1] in MARSHAL_VERSION_HINT_TAGS:
        probe_offsets = [0]
    if not probe_offsets:
        return None

    scores = {}

    for ver in candidates:
        magic_int = get_magic_int(ver)
        best_score = 0
        for offset in probe_offsets[:128]:
            obj = try_detect_code_object(data, offset, magic_int)
            if obj is None:
                continue
            best_score = max(best_score, score_code_object(obj))
            if best_score >= 4:
                break

        if best_score > 0:
            scores[ver] = best_score

    if not scores:
        if version_hint:
            fallback_versions = _marshal_candidate_versions(version_hint)
            if fallback_versions:
                print(f"[*] Version structural hint: {version_hint} -> {fallback_versions[0]}")
                return fallback_versions[0]
        return None

    best = max(scores, key=lambda v: scores[v])
    top5 = sorted(scores.items(), key=lambda x: -x[1])[:5]
    print(f"[*] Version probe scores (top 5): {top5}")
    return best


# ============================================================================
# FILENAME HELPERS
# ============================================================================


# Characters invalid on Windows paths + non-ASCII / control characters
_INVALID_PATH_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f-\xff]')

# Pattern to find Python source paths embedded in marshal data
MARSHAL_PYC_PATH_PATTERN = re.compile(rb'[\x00-\x03]([^\x00]{4,256}\.py[co]?)\x00', re.DOTALL)

# Pattern to identify sections emitted by the C extension decoder
# e.g. "__nuitka__.module_name@1234"
DISCOVERED_SECTION_PATTERN = re.compile(r'^(?:__nuitka__\.)?(.+?)@(\d+)$')


def _decode_blob_module_name(raw_name: bytes) -> str:
    """Decode a raw module name bytes from the blob, falling back to utf-8 replace."""
    try:
        name = raw_name.decode('utf-8', errors='strict')
        if _is_plausible_module_name(name):
            return name
    except Exception:
        pass
    return raw_name.decode('utf-8', errors='replace')


def sanitize_filename(filepath: str) -> str:
    """
    Convert a source-path string into a valid, relative Windows-safe path.

    - Normalises backslashes to forward slashes
    - Strips drive-letter prefix (e.g. 'C:')
    - Removes known Nuitka prefixes ('module.', 'nuitka_build/')
    - Replaces all Windows-invalid characters (control, upper-ASCII, special) with '_'
    - Collapses consecutive underscores into one
    - Strips leading/trailing '_' and '.' from each path component
    """
    # If the input is bytes (binary garbage from a blob), decode safely
    if isinstance(filepath, (bytes, bytearray)):
        filepath = filepath.decode("ascii", errors="replace")

    filepath = filepath.replace("\\", "/")
    if ":" in filepath:
        filepath = filepath.split(":", 1)[1]
    filepath = filepath.lstrip("/")
    for p in ["module.", "nuitka_build/"]:
        if filepath.startswith(p):
            filepath = filepath[len(p):]

    # Replace every invalid character with underscore
    filepath = _INVALID_PATH_CHARS_RE.sub("_", filepath)
    # Collapse runs of underscores
    filepath = re.sub(r"_+", "_", filepath)
    # Clean each path component: drop empty parts and trim edge underscores/dots
    parts = []
    for part in filepath.split("/"):
        part = part.strip("_.")
        if part:
            parts.append(part)
    return "/".join(parts) if parts else "unknown"


def extract_path_from_code(code_obj) -> str | None:
    try:
        if hasattr(code_obj, "co_filename"):
            return str(code_obj.co_filename)
        if hasattr(code_obj, "co_qualname"):
            return str(code_obj.co_qualname)
    except Exception:
        pass
    return None


def extract_code_label(code_obj) -> str | None:
    try:
        for attr in ("co_qualname", "co_name", "co_filename"):
            value = getattr(code_obj, attr, None)
            if not value:
                continue
            label = str(value).strip().replace("\\", "/")
            if not label:
                continue
            if attr == "co_filename" and ":" in label:
                label = label.split(":", 1)[1]
            label = label.lstrip("/")
            if label == "<module>":
                label = "module"
            if attr == "co_filename":
                label = Path(label).stem or label
            label = re.sub(r'[<>:"/\\|?*\x00]+', "_", label).strip("._ ")
            if label:
                return label[:96]
    except Exception:
        pass
    return None


def extract_path_from_marshaled_bytes(data: bytes | bytearray) -> str | None:
    try:
        candidates = []
        for match in MARSHAL_PYC_PATH_PATTERN.finditer(bytes(data)[:65536]):
            candidate = match.group(1).decode("utf-8", errors="ignore").replace("\\", "/")
            candidate = candidate.lstrip("./")
            if candidate:
                candidates.append(candidate)
        if not candidates:
            return None
        return max(candidates, key=lambda value: (value.count("/"), len(value)))
    except Exception:
        return None


def _discovered_alias_matches(discovered_name: str, plain_name: str) -> bool:
    if discovered_name == plain_name:
        return True
    if len(discovered_name) > 1 and discovered_name[1:] == plain_name:
        return True
    if len(discovered_name) > 2 and discovered_name[2:] == plain_name:
        return True
    return False


def parse_blob_modules(blob_data: bytes):
    """Parse the Nuitka constants blob into named modules.

    Format: [CRC32(4)][size(4)][name\0 chunk_size(4) chunk_data]...
    """
    if not blob_data or len(blob_data) < 8:
        return []

    size_stored = struct.unpack('<I', blob_data[4:8])[0]
    data_end = len(blob_data)
    if 8 + size_stored <= len(blob_data):
        data_end = 8 + size_stored

    data = blob_data[8:data_end]
    offset = 0
    modules = []

    while offset < len(data) - 5:
        name_end = data.find(b'\x00', offset, min(offset + 4096, len(data)))
        if name_end == -1:
            break

        raw_name = data[offset:name_end]
        module_name = _decode_blob_module_name(raw_name)

        offset = name_end + 1

        if offset + 4 > len(data):
            break

        chunk_size = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        if chunk_size > 100 * 1024 * 1024 or offset + chunk_size > len(data):
            break

        chunk_data = data[offset:offset + chunk_size]
        offset += chunk_size

        modules.append((module_name, chunk_data))

    return modules


def extract_bytecode_modules(bytecode_chunk: bytes, output_dir: Path, python_version: str, magic_int: int | None = None) -> tuple[int, list[str]]:
    """Extract .pyc modules from the .bytecode chunk (Nuitka constants blob)."""
    if len(bytecode_chunk) < 4:
        return 0, []

    count = struct.unpack('<H', bytecode_chunk[0:2])[0]
    print(f"[*] .bytecode chunk: {count} compiled modules (target Python {python_version})")

    pos = 2
    extracted = 0
    pyc_dir = output_dir / "pyc"
    pyc_dir.mkdir(parents=True, exist_ok=True)

    header = get_pyc_header(python_version)
    used_paths = {}
    manifest_entries = []
    recovered_file_paths = []

    for i in range(count):
        if pos >= len(bytecode_chunk):
            break

        if bytecode_chunk[pos] != 0x58:
            resync = None
            for skip in range(1, 64):
                if pos + skip < len(bytecode_chunk) and bytecode_chunk[pos + skip] == 0x58:
                    resync = pos + skip
                    break
            if resync is None:
                print(f"[!] Warning: Lost bytecode stream alignment at index {i} (offset 0x{pos:X})")
                break
            pos = resync

        pos += 1  # skip 'X'
        try:
            marshal_size = 0
            shift = 0
            while True:
                b = bytecode_chunk[pos]
                pos += 1
                marshal_size |= (b & 0x7F) << shift
                if b < 0x80:
                    break
                shift += 7
                if shift > 63:
                    raise ValueError("VLQ overflow")
        except (IndexError, ValueError) as e:
            print(f"[!] Warning: VLQ decode error at index {i}: {e}")
            break

        if marshal_size <= 0 or pos + marshal_size > len(bytecode_chunk):
            print(f"[!] Warning: Bad size {marshal_size} at index {i} (offset 0x{pos:X})")
            break

        marshal_data = bytecode_chunk[pos:pos + marshal_size]
        pos += marshal_size

        co_filename = extract_path_from_marshaled_bytes(marshal_data)
        if not co_filename:
            # Try loading the code object so we can pull co_filename / co_name
            # before falling back to the generic module_NNNN placeholder.
            try:
                _co = try_load_code_object(marshal_data, 0, magic_int)
                if _co is not None:
                    co_filename = extract_path_from_code(_co) or extract_code_label(_co)
            except Exception:
                pass
        if not co_filename:
            co_filename = f"module_{i:04d}.py"

        rel_path = _safe_pyc_relpath(co_filename)

        path_str = str(rel_path)
        if path_str in used_paths:
            used_paths[path_str] += 1
            rel_path = rel_path.parent / f"{rel_path.stem}__dup{used_paths[path_str]}{rel_path.suffix}"
        else:
            used_paths[path_str] = 0

        dest = pyc_dir / rel_path
        try:
            written_path = _write_bytes_unique(dest, header + marshal_data)
            extracted += 1
            path_written_str = str(written_path)
            recovered_file_paths.append(path_written_str)
            manifest_entries.append({
                "index": i,
                "co_filename": co_filename,
                "marshal_size": marshal_size,
                "pyc_path": os.path.relpath(written_path, output_dir).replace(os.sep, "/")
            })
        except Exception as exc:
            print(f"[!] Warning: failed to write bytecode module {i}: {exc}")

    try:
        manifest_path = output_dir / "BYTECODE_MANIFEST.json"
        manifest_data = {
            "target_python": python_version,
            "total_modules": extracted,
            "entries": manifest_entries
        }
        manifest_path.write_text(json.dumps(manifest_data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[*] Manifest written to {manifest_path}")
        recovered_file_paths.append(str(manifest_path))
    except Exception as exc:
        print(f"[!] Warning: failed to write manifest: {exc}")

    return extracted, recovered_file_paths


def _load_module_metadata(raw: bytes) -> list[dict]:
    try:
        from . import list_modules
    except ImportError:
        try:
            import list_modules
        except ImportError:
            return []

    parser = getattr(list_modules, "parse_module_names", None)
    if parser is None:
        return []

    try:
        return list(parser(raw))
    except Exception as exc:
        print(f"[!] Warning: list_modules.parse_module_names failed: {exc}")
        return []


def _clean_module_name(name: object, *, preserve_metadata: bool = False) -> str | None:
    """Normalize a decoded/list_modules module name without dropping real modules."""
    if not isinstance(name, str):
        return None

    name = name.strip().replace("\\", "/")
    if not name:
        return None

    # list_modules may return a source path instead of a dotted module name.
    # Keep package structure, but turn it into the same dotted form used by sections.
    if name.lower().endswith(".py"):
        name = name[:-3]
    name = name.strip("./")
    name = name.replace("/", ".")
    while ".." in name:
        name = name.replace("..", ".")
    name = name.strip(".")

    if not name:
        return None

    # Only filter synthetic decoder sections. Metadata from list_modules is source of truth
    # and must not be dropped just because the decoder failed to expose a matching section.
    if not preserve_metadata:
        if name == "bytecode":
            return None
        if "hidden_segment" in name or name.startswith("hidden_"):
            return None

    return name


def _metadata_module_name(meta: dict) -> str | None:
    """Extract the module name/path reported by list_modules, preserving it."""
    for key in ("name", "module", "module_name", "fullname", "qualified_name"):
        name = _clean_module_name(meta.get(key), preserve_metadata=True)
        if name:
            return name

    for key in ("filename", "file", "path", "source", "source_path"):
        name = _clean_module_name(meta.get(key), preserve_metadata=True)
        if name:
            return name

    return None


def _metadata_name_maps(module_metadata: list[dict] | None) -> tuple[dict[int, str], list[str]]:
    by_offset: dict[int, str] = {}
    ordered_names: list[str] = []
    seen_names: set[str] = set()

    for meta in module_metadata or []:
        if not isinstance(meta, dict):
            continue
        name = _metadata_module_name(meta)
        if not name:
            continue

        if name not in seen_names:
            ordered_names.append(name)
            seen_names.add(name)

        for key in ("section_offset", "offset", "module_offset", "blob_offset", "start", "start_offset"):
            try:
                by_offset[int(meta[key])] = name
            except Exception:
                pass

    return by_offset, ordered_names


def _lookup_metadata_name(offset: int, by_offset: dict[int, str]) -> str | None:
    if offset in by_offset:
        return by_offset[offset]

    # Decoder/list_modules offsets can differ by a few bytes depending on whether the
    # marker/header or the payload start is reported. Prefer nearby metadata names, but
    # do not let a random far-away offset rename a section.
    nearest = None
    nearest_distance = 32
    for known_offset, name in by_offset.items():
        distance = abs(known_offset - offset)
        if distance < nearest_distance:
            nearest = name
            nearest_distance = distance
    return nearest


def _section_items_tuple(items) -> tuple:
    if isinstance(items, tuple):
        return items
    if isinstance(items, list):
        return tuple(items)
    if isinstance(items, (set, frozenset)):
        return tuple(items)
    return (items,)


def _merge_section_items(existing, incoming) -> tuple:
    return _section_items_tuple(existing) + _section_items_tuple(incoming)


def _add_normalized_section(normalized: dict[str, tuple], section_name: str, items) -> None:
    """Add a section without silently losing data when names collide."""
    if section_name in normalized:
        normalized[section_name] = _merge_section_items(normalized[section_name], items)
    else:
        normalized[section_name] = _section_items_tuple(items)


def normalize_decoded_sections(sections: dict, module_metadata: list[dict] | None = None) -> dict[str, tuple]:
    """
    Rename decoded sections using list_modules metadata without filtering metadata-only
    modules out of --list-only output.

    Rules:
    1. list_modules names are authoritative when an offset/ordered mapping exists.
    2. decoded/discovered names are fallback labels only.
    3. colliding section names are merged, not dropped.
    4. every module reported by list_modules is preserved, even if no decoded constants
       section was emitted for it.
    """
    metadata_by_offset, metadata_names = _metadata_name_maps(module_metadata)
    metadata_index = 0
    claimed_metadata: set[str] = set()
    normalized: dict[str, tuple] = {}

    def claim_metadata_name(name: str | None) -> str | None:
        if not name:
            return None
        claimed_metadata.add(name)
        return name

    def next_metadata_name() -> str | None:
        nonlocal metadata_index
        while metadata_index < len(metadata_names):
            name = metadata_names[metadata_index]
            metadata_index += 1
            if name not in claimed_metadata:
                claimed_metadata.add(name)
                return name
        return None

    for section_name, items in sections.items():
        match = DISCOVERED_SECTION_PATTERN.fullmatch(section_name)
        if match:
            discovered_name = match.group(1).lstrip(".")
            section_offset = int(match.group(2))

            # Prefer the name list_modules found. This fixes corrupt decoder labels like
            # "stomtkinter" when metadata knows the real module name.
            real_name = claim_metadata_name(_lookup_metadata_name(section_offset, metadata_by_offset))
            if real_name is None:
                real_name = next_metadata_name()
            if real_name is None:
                real_name = _clean_module_name(discovered_name)

            if real_name is not None:
                _add_normalized_section(normalized, real_name, items)
            continue

        plain_name = _clean_module_name(section_name.lstrip("."))
        if plain_name is not None:
            _add_normalized_section(normalized, plain_name, items)

    # Preserve metadata-only modules. They may not have decoded constants, but --list-only
    # must still show them so list_modules output is not lost/filtered.
    for name in metadata_names:
        if name not in normalized:
            normalized[name] = ()

    return normalized


# ============================================================================
# SECTION-BASED CODE FINDER — for blobs that DO embed marshal bytes as items
# ============================================================================



def _normalize_section_items(items):
    """Return section payload as an iterable of root items without splitting bytes into ints."""
    if isinstance(items, (list, tuple)):
        return items
    if isinstance(items, (set, frozenset)):
        return tuple(items)
    return (items,)


def _safe_pyc_relpath(filepath: str) -> Path:
    """Convert a source-like path into a safe relative .pyc path."""
    cleaned = sanitize_filename(filepath).replace("\\", "/")
    if cleaned.lower().endswith(".py"):
        cleaned = cleaned[:-3] + ".pyc"
    elif not cleaned.lower().endswith(".pyc"):
        cleaned += ".pyc"

    parts = [part for part in cleaned.split("/") if part not in ("", ".", "..")]
    if not parts:
        return Path("unknown.pyc")
    return Path(*parts)


def _unique_path_for_write(dest: Path) -> Path:
    """Return dest or a numbered sibling that does not exist yet."""
    if not dest.exists():
        return dest
    stem = dest.stem
    suffix = dest.suffix
    parent = dest.parent
    for counter in range(1, 10000):
        candidate = parent / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"Could not find a free output path for {dest}")


def _write_bytes_unique(dest: Path, data: bytes) -> Path:
    """Write bytes without overwriting an existing extraction result."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    for counter in range(0, 10000):
        candidate = dest if counter == 0 else dest.parent / f"{dest.stem}_{counter}{dest.suffix}"
        try:
            with candidate.open("xb") as handle:
                handle.write(data)
            return candidate
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not find a free output path for {dest}")



def _payload_dedupe_key(value):
    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
        return ("bytes", len(payload), payload[:64], payload[-64:])
    return ("object", id(value))


def _dump_code_object(code_obj, target_ver_tuple: tuple[int, int]) -> bytes:
    """Dump a live/xdis code object while keeping compatibility across xdis versions."""
    try:
        return marshal.dumps(code_obj, python_version=target_ver_tuple)
    except TypeError:
        return marshal.dumps(code_obj)


def recursive_find_code(item, results, processed_ids, magic_int: int | None, depth=0):
    """
    Recursively search structured section items for code objects.
    Works on blobs where marshal bytes appear as list/dict/tuple items.
    """
    if depth > 20 or id(item) in processed_ids:
        return
    processed_ids.add(id(item))

    if type(item).__name__ == "code" or type(item).__name__.startswith("Code"):
        results.append(item)
        try:
            for c in getattr(item, "co_consts", []):
                recursive_find_code(c, results, processed_ids, magic_int, depth + 1)
        except Exception:
            pass

    elif isinstance(item, (bytes, bytearray)) and len(item) > 16:
        if item[:1] in MARSHAL_VERSION_HINT_TAGS:
            obj = try_load_code_object(item, 0, magic_int)
            if obj is not None:
                recursive_find_code(obj, results, processed_ids, magic_int, depth + 1)

    elif isinstance(item, (list, tuple)):
        for x in item:
            recursive_find_code(x, results, processed_ids, magic_int, depth + 1)

    elif isinstance(item, dict):
        for v in item.values():
            recursive_find_code(v, results, processed_ids, magic_int, depth + 1)


def process_section(
    section_name: str,
    items,
    out_dir: Path,
    header: bytes,
    target_ver_tuple: tuple[int, int],
    magic_int: int | None,
    OmniDecompiler,
    generate_omni_source,
    generate_omni_nbc,
    emit_pyc: bool = True,
) -> tuple[int, int, int, list[str]]:
    clean_section = sanitize_filename(section_name).replace("/", "_").replace(".", "_").strip("_") or "section"
    # Cap at 80 characters — safe ceiling for long binary-garbage section names
    clean_section = clean_section[:80]
    root_items = _normalize_section_items(items)
    recovered_file_paths = []
    count_pyc = 0
    count_other = 0
    omni_count = 0

    # ── Per-item partition: classify before acting ────────────────────────────
    # A section can be mixed: some items are marshal bytecode blobs, others are
    # plain Nuitka constants. Checking the whole section as a unit (the old
    # is_marshaled_bytecode_section gate) caused OMNI to be skipped entirely
    # whenever any item in the section contained bytecode. We now classify each
    # item individually so that bytecode items are always dumped as .pyc and
    # constant items are always passed to OMNI — nothing is lost either way.
    bytecode_item_indices: set[int] = set()

    for i, root_item in enumerate(root_items):
        if any(True for _ in _iter_marshaled_bytecode_payloads(root_item, magic_int=magic_int)):
            bytecode_item_indices.add(i)

    omni_items = tuple(
        item for i, item in enumerate(root_items) if i not in bytecode_item_indices
    )

    # ── OMNI on pure-constant items ───────────────────────────────────────────
    # Always attempted when the framework is available. Bytecode items are
    # excluded so OMNI never receives raw marshal bytes it cannot interpret.
    if OmniDecompiler and omni_items:
        try:
            omp = OmniDecompiler()
            omp.run_pass_1_structural_mapping(omni_items)
            omp.run_pass_2_ast_synthesis()
            source = generate_omni_source(
                omp,
                section_name,
                raw_constants=list(omni_items),
                python_version=target_ver_tuple,
            )
            if source.strip():
                if generate_omni_nbc:
                    nbc_text = generate_omni_nbc(
                        omp, section_name, list(omni_items), python_version=target_ver_tuple
                    )
                    source += "\n\n" + '"""' + "\n" + nbc_text + "\n" + '"""'

                _raw_sn = section_name.encode("utf-8", errors="replace") if isinstance(section_name, str) else bytes(section_name)
                _ascii_sn = re.sub(r"[^A-Za-z0-9._-]", "_", section_name if isinstance(section_name, str) else section_name.decode("ascii", errors="replace"))
                _ascii_sn = re.sub(r"_+", "_", _ascii_sn).strip("_.")[:48]
                _hash_sn = hashlib.sha1(_raw_sn).hexdigest()[:8]
                safe_name = f"{_ascii_sn}_{_hash_sn}" if _ascii_sn else f"section_{_hash_sn}"
                omni_out = out_dir / "omni_reconstructed"
                target_py_path = _write_bytes_unique(
                    omni_out / f"{safe_name}.py", source.encode("utf-8")
                )
                recovered_file_paths.append(str(target_py_path))
                omni_count += 1
        except Exception as exc:
            print(f"[!] Warning: OMNI reconstruction failed for {section_name}: {exc}")

    # ── Per-item pyc extraction ───────────────────────────────────────────────
    # Operates on ALL root_items (both bytecode and constant). Bytecode items
    # are dumped as .pyc; constant items land in count_other as before.
    section_items_metadata = []

    for i, root_item in enumerate(root_items):
        item_id = f"{i:04d}"
        item_info = {"id": item_id, "type": type(root_item).__name__}
        seen_payloads: set = set()
        raw_payloads: list[bytes] = []
        code_objects = []

        for payload in _iter_marshaled_bytecode_payloads(root_item, magic_int=magic_int):
            key = _payload_dedupe_key(payload)
            if key in seen_payloads:
                continue
            seen_payloads.add(key)
            if isinstance(payload, (bytes, bytearray)):
                raw_payloads.append(bytes(payload))
            elif _is_live_code_object(payload):
                code_objects.append(payload)

        actions = []

        if raw_payloads:
            item_info["marshal_payload_count"] = len(raw_payloads)
            item_info["detected_code_paths"] = []
            item_info["written_pyc"] = []
            item_info["errors"] = []

            for j, payload in enumerate(raw_payloads):
                guessed_path = extract_path_from_marshaled_bytes(payload)
                if guessed_path:
                    item_info["detected_code_paths"].append(guessed_path)
                    dest = out_dir / "pyc" / _safe_pyc_relpath(guessed_path)
                else:
                    dest = out_dir / "pyc" / clean_section / f"bytecode_{item_id}_{j:02d}.pyc"

                if emit_pyc:
                    try:
                        written = _write_bytes_unique(dest, header + payload)
                        item_info["written_pyc"].append(str(written))
                        recovered_file_paths.append(str(written))
                        count_pyc += 1
                    except Exception as exc:
                        item_info["errors"].append(f"raw_payload_{j}: {exc}")
                        print(
                            f"[!] Warning: failed to write pyc for {section_name} item {item_id}: {exc}"
                        )

            actions.append("bytecode_extracted" if emit_pyc else "bytecode_detected")

        if code_objects:
            item_info["code_object_count"] = len(code_objects)
            detected_paths = [
                path
                for path in (extract_path_from_code(code_obj) for code_obj in code_objects)
                if path and "<" not in path
            ][:16]
            if detected_paths:
                item_info.setdefault("detected_code_paths", []).extend(detected_paths)
            item_info.setdefault("written_pyc", [])
            item_info.setdefault("errors", [])

            if emit_pyc:
                for j, code_obj in enumerate(code_objects):
                    try:
                        raw_bytes = _dump_code_object(code_obj, target_ver_tuple)
                        path_str = extract_path_from_code(code_obj)
                        sub_id = f"{i:04d}_{j:02d}"
                        code_label = extract_code_label(code_obj)

                        if path_str and "<" not in path_str:
                            dest = out_dir / "pyc" / _safe_pyc_relpath(path_str)
                        elif code_label:
                            dest = out_dir / "pyc" / clean_section / f"{code_label}_{sub_id}.pyc"
                        else:
                            dest = out_dir / "pyc" / clean_section / f"bytecode_{sub_id}.pyc"

                        written = _write_bytes_unique(dest, header + raw_bytes)
                        item_info["written_pyc"].append(str(written))
                        recovered_file_paths.append(str(written))
                        count_pyc += 1
                    except Exception as exc:
                        item_info["errors"].append(f"code_object_{j}: {exc}")
                        print(
                            f"[!] Warning: failed to dump code object for {section_name} "
                            f"item {item_id}: {exc}"
                        )
                actions.append("code_objects_extracted")
            else:
                actions.append("code_objects_detected")

        if not raw_payloads and not code_objects:
            if isinstance(root_item, (bytes, bytearray)):
                item_info["data_preview"] = root_item[:64].hex()
                item_info["size"] = len(root_item)
            else:
                item_info["repr"] = repr(root_item)[:200]
            count_other += 1
        else:
            item_info["action"] = "+".join(actions)
            if not item_info.get("detected_code_paths"):
                item_info.pop("detected_code_paths", None)
            if not item_info.get("written_pyc"):
                item_info.pop("written_pyc", None)
            if not item_info.get("errors"):
                item_info.pop("errors", None)

        section_items_metadata.append(item_info)

    # ── Write unified metadata ────────────────────────────────────────────────
    if section_items_metadata:
        meta_dir = out_dir / "_metadata"
        meta_file = meta_dir / f"{clean_section}_metadata.json"
        try:
            written_meta = _write_bytes_unique(
                meta_file, json.dumps(section_items_metadata, indent=2).encode("utf-8")
            )
            recovered_file_paths.append(str(written_meta))
        except Exception as exc:
            print(f"[!] Warning: failed to write metadata for {section_name}: {exc}")

    return count_pyc, count_other, omni_count, recovered_file_paths

# ============================================================================
# MAIN
# ============================================================================

from dataclasses import dataclass


@dataclass
class ExtractionResult:
    pyc_count: int
    omni_recon_count: int
    metadata_count: int
    output_dir: Path
    recovered_files: list[str]


def extract_blob(
    blob_path: Path | str,
    output_dir: Path | str,
    target_version: str | tuple[int, int] | None = None,
    list_only: bool = False,
    emit_pyc: bool = True,
) -> ExtractionResult | None:
    blob_path = Path(blob_path)
    output_dir = Path(output_dir)

    if not blob_path.is_file():
        print(f"[!] Error: blob not found: {blob_path}")
        return None

    # Load raw bytes first so we can auto-detect version from content
    raw = blob_path.read_bytes()
    print(f"[*] Loaded {len(raw)} bytes from {blob_path}")

    # Resolve target Python version
    if target_version is not None:
        if isinstance(target_version, str):
            target_ver_tuple = tuple(map(int, target_version.split(".")))
            target_ver_str = target_version
        else:
            target_ver_tuple = target_version
            target_ver_str = f"{target_ver_tuple[0]}.{target_ver_tuple[1]}"
        print(f"[*] Target Python version : {target_ver_str} (from args)")
    else:
        print("[*] No target version specified, detecting Python version from marshal code objects...")
        probe_detected = None
        for tag in (b"\xf3", b"\xe3", b"\x63"):
            offset = raw.find(tag)
            if offset != -1:
                probe_detected = detect_version_from_marshal(raw[offset : offset + 65536])
                if probe_detected:
                    break

        if probe_detected and probe_detected in by_version:
            target_ver_str = probe_detected
            target_ver_tuple = tuple(int(x) for x in probe_detected.split("."))
            print(f"[*] Auto-detected version : {target_ver_str}")
        else:
            target_ver_tuple = sys.version_info[:2]
            target_ver_str = f"{target_ver_tuple[0]}.{target_ver_tuple[1]}"
            print(f"[*] Could not detect version, falling back to running interpreter: {target_ver_str}")

    if target_ver_str not in by_version:
        print(f"[!] ERROR: xdis has no magic for Python {target_ver_str}.")
        print(f"    Known: {sorted(by_version.keys())}")
        print("    Fix:   pip install --upgrade xdis")
        return None

    print(f"[*] Running Python        : {sys.version_info.major}.{sys.version_info.minor}")

    try:
        from .omni_nuitka_framework import OmniDecompiler, generate_omni_source, generate_omni_nbc
    except ImportError:
        try:
            from omni_nuitka_framework import OmniDecompiler, generate_omni_source, generate_omni_nbc
        except ImportError:
            print("[!] Warning: omni_nuitka_framework.py missing. Bytecode extraction only.")
            OmniDecompiler = None
            generate_omni_source = None
            generate_omni_nbc = None

    # -------------------------------------------------------------------------
    # Decode sections
    # -------------------------------------------------------------------------
    print("[*] Starting extraction sequence...")

    blob_for_parse = raw
    _is_blob_encrypted = CommercialBypass().is_blob_encrypted(raw)
    _edition = ("commercial" if CommercialBypass().has_commercial_digest(raw) else "unknown")

    _use_bypass = _is_blob_encrypted or _edition == "commercial"

    def _parse_blob_modules_inline(blob_data: bytes) -> list:
        if not blob_data or len(blob_data) < 8:
            return []
        size_stored = struct.unpack('<I', blob_data[4:8])[0]
        data_end = len(blob_data)
        if 8 + size_stored <= len(blob_data):
            data_end = 8 + size_stored
        data = blob_data[8:data_end]
        offset = 0
        modules = []
        while offset < len(data) - 5:
            name_end = data.find(b'\x00', offset, min(offset + 4096, len(data)))
            if name_end == -1:
                break
            raw_name = data[offset:name_end]
            plain = None
            try:
                plain = raw_name.decode('utf-8', errors='strict')
                if _is_plausible_module_name(plain):
                    module_name = plain
                else:
                    raise ValueError
            except Exception:
                if _use_bypass:
                    decoded = CommercialBypass().decode_module_name(raw_name)
                    module_name = decoded if _is_plausible_module_name(decoded) else (plain or raw_name.decode('utf-8', errors='replace'))
                else:
                    module_name = plain if plain is not None else raw_name.decode('utf-8', errors='replace')
            offset = name_end + 1
            if offset + 4 > len(data):
                break
            chunk_size = struct.unpack('<I', data[offset:offset + 4])[0]
            offset += 4
            if chunk_size > 100 * 1024 * 1024 or offset + chunk_size > len(data):
                break
            chunk_data = data[offset:offset + chunk_size]
            offset += chunk_size
            modules.append((module_name, chunk_data))
        return modules

    modules = _parse_blob_modules_inline(blob_for_parse)
    constants_modules = []
    bytecode_chunk = None
    for name, chunk_data in modules:
        if name == ".bytecode":
            bytecode_chunk = chunk_data
        else:
            constants_modules.append((name, chunk_data))

    # Build sections dict directly from named modules — no C extension aggressive scan
    sections: dict[str, tuple] = {}
    for mod_name, chunk_data in constants_modules:
        try:
            constants = _nbc_parse_module_constants(chunk_data, python_version=target_ver_tuple)
            sections[mod_name] = tuple(constants)
        except Exception:
            sections[mod_name] = ()

    module_metadata = _load_module_metadata(blob_for_parse)
    if module_metadata:
        print(f"[*] list_modules resolved {len(module_metadata)} module name(s).")

    print(f"[*] Discovered {len(sections)} sections/fragments.")

    if list_only:
        for name in sections:
            print(f"  {name}")
        return ExtractionResult(0, 0, 0, output_dir, [])

    base_out = output_dir / blob_path.stem
    out_dir = base_out
    counter = 1
    while out_dir.exists() and any(out_dir.iterdir()):
        out_dir = output_dir / f"{blob_path.stem}_{counter}"
        counter += 1

    print(f"[*] Output directory      : {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    header = get_pyc_header(target_ver_str)
    magic_int = get_magic_int(target_ver_str)

    # -------------------------------------------------------------------------
    # PBKDF2+AES-CBC detection & decryption
    # -------------------------------------------------------------------------
    _pbkdf2_bypass = PBKDF2AESBypass()
    _pbkdf2_recovered: dict[str, list[bytes]] = {}
    for mod_name, chunk_data in constants_modules:
        try:
            constants = _nbc_parse_module_constants(chunk_data, python_version=target_ver_tuple)
            if PBKDF2AESBypass.detect_pbkdf2_pattern(constants):
                print(f"[*] PBKDF2+AES-CBC pattern detected in module: {mod_name}")
                enc_payload = PBKDF2AESBypass.find_encrypted_payload(constants)
                if enc_payload:
                    # Extract the PBKDF2 salt from the module's constants.
                    # Nuitka Commercial stores the salt as a separate bytes
                    # value (typically 32 bytes) alongside the ciphertext.
                    salt = PBKDF2AESBypass.find_salt_in_constants(constants, exclude=enc_payload)
                    if salt:
                        print(f"    [*] Found salt: {salt.hex()[:32]}... ({len(salt)} bytes)")
                    else:
                        print(f"    [!] No salt found in constants, will try embedded fallback")
                    # Extract candidate passwords from the module's own constants.
                    pw_candidates = PBKDF2AESBypass.extract_password_candidates_from_constants(constants)
                    print(f"    [*] Extracted {len(pw_candidates)} password candidate(s) from module constants")
                    for pw in pw_candidates:
                        decrypted = _pbkdf2_bypass.try_decrypt(enc_payload, pw, salt=salt)
                        if not decrypted or len(decrypted) <= 16:
                            continue

                        # Verify: parse decrypted output and look for code objects.
                        # NBC parse alone can false-positive on garbage (first 2 bytes
                        # as constant count is ~76% likely to pass). Only accept when
                        # actual code objects are found.
                        try:
                            nbc_consts = _nbc_parse_module_constants(
                                decrypted, python_version=target_ver_tuple
                            )
                        except Exception:
                            nbc_consts = []
                        if not nbc_consts:
                            continue

                        nbc_code_objs = []
                        _rcf_seen: set = set()
                        for _c in nbc_consts:
                            recursive_find_code(_c, nbc_code_objs, _rcf_seen, magic_int)

                        if not nbc_code_objs:
                            continue  # false positive from NBC parse on garbage

                        payloads: list[bytes] = []
                        for _co in nbc_code_objs:
                            try:
                                payloads.append(_dump_code_object(_co, target_ver_tuple))
                            except Exception:
                                pass
                        if payloads:
                            _pbkdf2_recovered[mod_name] = payloads
                            print(f"[+] PBKDF2 decryption succeeded for {mod_name} "
                                  f"(password: {pw!r}), extracted {len(nbc_code_objs)} "
                                  f"code object(s) from NBC stream")
                            break

                    if mod_name not in _pbkdf2_recovered:
                        # Path-based candidates derived from module name hierarchy
                        path_pw_candidates = PBKDF2AESBypass.generate_path_based_candidates(mod_name)
                        print(f"    [*] Trying {len(path_pw_candidates)} path-based password candidate(s)")
                        for pw in path_pw_candidates:
                            decrypted = _pbkdf2_bypass.try_decrypt(enc_payload, pw, salt=salt)
                            if not decrypted or len(decrypted) <= 16:
                                continue
                            try:
                                nbc_consts = _nbc_parse_module_constants(
                                    decrypted, python_version=target_ver_tuple
                                )
                            except Exception:
                                nbc_consts = []
                            if not nbc_consts:
                                continue
                            nbc_code_objs = []
                            _rcf_seen: set = set()
                            for _c in nbc_consts:
                                recursive_find_code(_c, nbc_code_objs, _rcf_seen, magic_int)
                            if not nbc_code_objs:
                                continue
                            payloads: list[bytes] = []
                            for _co in nbc_code_objs:
                                try:
                                    payloads.append(_dump_code_object(_co, target_ver_tuple))
                                except Exception:
                                    pass
                            if payloads:
                                _pbkdf2_recovered[mod_name] = payloads
                                print(f"[+] PBKDF2 decryption succeeded for {mod_name} "
                                      f"(password: {pw!r}), extracted {len(nbc_code_objs)} "
                                      f"code object(s) from NBC stream")
                                break
        except Exception:
            pass
    if _pbkdf2_recovered:
        print(f"[*] PBKDF2 recovery: {len(_pbkdf2_recovered)} module(s) decrypted")
        for mod_name, payloads in _pbkdf2_recovered.items():
            existing = sections.get(mod_name, ())
            sections[mod_name] = existing + tuple(payloads)

    recovered_file_paths = []

    count_pyc = 0
    count_other = 0

    # Extract bytecode modules from the .bytecode chunk if present
    if bytecode_chunk and emit_pyc:
        print("[*] Extracting bytecode modules from .bytecode chunk...")
        extracted_bc, bc_paths = extract_bytecode_modules(bytecode_chunk, out_dir, target_ver_str, magic_int)
        count_pyc += extracted_bc
        recovered_file_paths.extend(bc_paths)

    # =========================================================================
    # PASS 2: SECTION-BASED SCAN + OMNI DECOMPILATION
    # Handles blobs that store marshal bytes as structured section items,
    # and runs the OMNI heuristic reconstruction pipeline.
    # =========================================================================
    print("[*] Pass 2: Section-based bytecode extraction & OMNI pipeline...")

    sc = 0
    work_items = [(section_name, items) for section_name, items in sections.items() if items]
    if work_items:
        max_workers = max(1, min(len(work_items), os.cpu_count() or 1))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(
                    process_section,
                    section_name,
                    items,
                    out_dir,
                    header,
                    target_ver_tuple,
                    magic_int,
                    OmniDecompiler,
                    generate_omni_source,
                    generate_omni_nbc,
                    emit_pyc,
                )
                for section_name, items in work_items
            ]

            for future in futures:
                section_pyc, section_other, section_sc, section_files = future.result()
                count_pyc += section_pyc
                count_other += section_other
                sc += section_sc
                recovered_file_paths.extend(section_files)


    # =========================================================================
    # PASS 3: PER-MODULE CONSTANTS DUMP
    # =========================================================================
    constants_dir = out_dir / "module_constants"
    constants_dir.mkdir(parents=True, exist_ok=True)
    print("[*] Pass 3: per-module constants string extraction...")
    dumped_constants = 0
    for mod_name, chunk_data in constants_modules:
        try:
            constants = _nbc_parse_module_constants(chunk_data, python_version=target_ver_tuple)
            strings = _nbc_extract_all_strings(constants)
            strings = list(dict.fromkeys(strings))

            safe_name = re.sub(r"[<>:\"|?*\\]", "_", mod_name.replace(".", "_")).strip("_") or "module"
            safe_name = re.sub(r"_+", "_", safe_name)[:80]
            const_file = constants_dir / f"{safe_name}_constants.txt"

            with const_file.open("w", encoding="utf-8", errors="replace") as fh:
                fh.write(f"# Module: {mod_name}\n")
                fh.write(f"# Constants count: {len(constants)}\n\n")
                for idx, val in enumerate(constants):
                    fh.write(f"[{idx}] {type(val).__name__}: {repr(val)[:300]}\n")
                fh.write("\n" + "=" * 70 + "\n")
                fh.write(f"# Strings extracted (recursive): {len(strings)}\n")
                fh.write("=" * 70 + "\n\n")
                for s in strings:
                    fh.write(s.replace("\r\n", "\n"))
                    fh.write("\n")
            dumped_constants += 1
        except Exception as exc:
            print(f"[!] Warning: constants dump failed for {mod_name}: {exc}")
    print(f"[*]   Written {dumped_constants} module constants files -> {constants_dir}")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n[!] Orchestration Complete!")
    print(f"    Target version  : Python {target_ver_str}")
    print(f"    Bytecode (.pyc) : {count_pyc} modules extracted")
    print(f"    Metadata items  : {count_other}")
    if OmniDecompiler:
        print(f"    OMNI recon      : {sc} Python reconstructions")
    print(f"    Output          : {out_dir.absolute()}")

    return ExtractionResult(pyc_count=count_pyc, omni_recon_count=sc if OmniDecompiler else 0, metadata_count=count_other, output_dir=out_dir, recovered_files=recovered_file_paths)
