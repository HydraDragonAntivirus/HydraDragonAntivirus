#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_train_pefile.py
--------------------
Tests for train_pefile.py covering:
  - PEFeatureExtractor  (entropy, disassembly, radare2, feature extraction)
  - DataProcessor       (MD5 pre-filter, worker, move, vector store, dataset run)
  - features_to_numeric (vector shape, dtype, index correctness)
  - analyze_with_radare2 (PATH injection/restore, all fallback paths)

Run with:
    pytest test_train_pefile.py -v
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import pickle
import struct
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch

import numpy as np
import pytest

# ---------------------------------------------------------------------------
# Stub out third-party dependencies that may not be installed in CI
# ---------------------------------------------------------------------------

def _make_stub(name: str) -> types.ModuleType:
    m = types.ModuleType(name)
    return m

for _dep in ("hydra_logger", "tqdm", "capstone", "pefile", "r2pipe"):
    if _dep not in sys.modules:
        sys.modules[_dep] = _make_stub(_dep)

# hydra_logger must expose 'logger'
sys.modules["hydra_logger"].logger = MagicMock()

# tqdm must be iterable-transparent
sys.modules["tqdm"].tqdm = lambda it, **kw: it

# capstone constants used at module level
_capstone = sys.modules["capstone"]
_capstone.CS_ARCH_X86 = 1
_capstone.CS_MODE_32 = 4
_capstone.CS_MODE_64 = 8
_capstone.Cs = MagicMock()

# pefile constants
_pefile = sys.modules["pefile"]
_pefile.MACHINE_TYPE = {
    "IMAGE_FILE_MACHINE_I386": 0x014C,
    "IMAGE_FILE_MACHINE_AMD64": 0x8664,
}
_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
_pefile.PE = MagicMock()

# Now we can safely import the module under test
import train_pefile as tp  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mz_bytes(size: int = 512) -> bytes:
    """Return a fake MZ-header binary of the given size."""
    header = b"MZ" + b"\x00" * (size - 2)
    return header


def _make_temp_mz(tmp_path: Path, size: int = 512, name: str = "sample.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(_make_mz_bytes(size))
    return p


def _make_temp_text(tmp_path: Path, content: bytes = b"not a PE", name: str = "bad.bin") -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


def _minimal_features(is_malicious: bool = True) -> dict:
    """Return the smallest features dict that passes features_to_numeric."""
    return {
        "SizeOfOptionalHeader": 224,
        "MajorLinkerVersion": 14,
        "MinorLinkerVersion": 0,
        "SizeOfCode": 0x1000,
        "SizeOfInitializedData": 0x2000,
        "SizeOfUninitializedData": 0,
        "AddressOfEntryPoint": 0x1000,
        "ImageBase": 0x400000,
        "Subsystem": 2,
        "DllCharacteristics": 0,
        "SizeOfStackReserve": 0x100000,
        "SizeOfHeapReserve": 0x1000,
        "CheckSum": 0,
        "NumberOfRvaAndSizes": 16,
        "SizeOfImage": 0x5000,
        "imports": ["CreateFile", "WriteFile"],
        "exports": [],
        "resources": [],
        "sections": [{"name": ".text"}],
        "overlay": {"exists": False, "size": 0},
        "section_characteristics": {},
        "section_disassembly": {
            "overall_analysis": {
                "total_instructions": 100,
                "add_count": 10,
                "mov_count": 30,
                "is_likely_packed": False,
            }
        },
        "tls_callbacks": {},
        "delay_imports": [],
        "relocations": [],
        "bound_imports": [],
        "debug": [],
        "certificates": {},
        "rich_header": {},
        "radare2": {
            "function_count": 5,
            "basic_block_count": 20,
            "avg_basic_blocks_per_function": 4.0,
            "cyclomatic_complexity_mean": 3.0,
            "xref_count": 12,
            "r2_string_count": 8,
            "r2_analysis_success": True,
        },
        "file_info": {
            "filename": "sample.exe",
            "path": "/tmp/sample.exe",
            "md5": "abc123",
            "size": 512,
            "is_malicious": is_malicious,
        },
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def extractor():
    return tp.PEFeatureExtractor()


@pytest.fixture()
def data_processor(tmp_path):
    """DataProcessor wired to temporary directories."""
    mal_dir = tmp_path / "malicious"
    ben_dir = tmp_path / "benign"
    mal_dir.mkdir()
    ben_dir.mkdir()
    return tp.DataProcessor(
        malicious_dir=str(mal_dir),
        benign_dir=str(ben_dir),
        out_dir_prefix=str(tmp_path / "out"),
        bin_path="vectors.bin",
        index_path="index.jsonl",
        malicious_pickle_path="mal.pkl",
        benign_pickle_path="ben.pkl",
        reset=False,
    )


# ===========================================================================
# 1. PEFeatureExtractor._calculate_entropy
# ===========================================================================

class TestCalculateEntropy:
    def test_empty_returns_zero(self, extractor):
        assert extractor._calculate_entropy(b"") == 0.0

    def test_uniform_bytes_max_entropy(self, extractor):
        # 256 distinct bytes → entropy ≈ 8.0
        data = bytes(range(256))
        e = extractor._calculate_entropy(data)
        assert abs(e - 8.0) < 0.01

    def test_single_byte_zero_entropy(self, extractor):
        data = b"\xAA" * 1024
        assert extractor._calculate_entropy(data) == 0.0

    def test_returns_float(self, extractor):
        result = extractor._calculate_entropy(b"hello world")
        assert isinstance(result, float)

    def test_high_entropy_random_like(self, extractor):
        import os as _os
        data = _os.urandom(4096)
        e = extractor._calculate_entropy(data)
        assert e > 7.0


# ===========================================================================
# 2. PEFeatureExtractor.disassemble_all_sections
# ===========================================================================

class TestDisassembleAllSections:
    def _make_pe(self, machine=0x014C):
        pe = MagicMock()
        pe.FILE_HEADER.Machine = machine
        pe.OPTIONAL_HEADER.ImageBase = 0x400000
        return pe

    def test_unsupported_architecture(self, extractor):
        pe = self._make_pe(machine=0xAA64)  # ARM64, not handled
        result = extractor.disassemble_all_sections(pe)
        assert result["error"] == "Unsupported architecture."
        assert result["overall_analysis"]["total_instructions"] == 0

    def test_empty_section_handled(self, extractor):
        pe = self._make_pe()
        section = MagicMock()
        section.Name = b".text\x00\x00\x00"
        section.get_data.return_value = b""
        section.VirtualAddress = 0x1000
        pe.sections = [section]

        cs_mock = MagicMock()
        cs_mock.disasm.return_value = iter([])
        sys.modules["capstone"].Cs.return_value = cs_mock

        result = extractor.disassemble_all_sections(pe)
        assert result["overall_analysis"]["total_instructions"] == 0
        assert ".text" in result["sections"]

    def test_x64_mode_selected(self, extractor):
        pe = self._make_pe(machine=0x8664)  # AMD64
        pe.sections = []
        cs_mock = MagicMock()
        cs_mock.disasm.return_value = iter([])
        sys.modules["capstone"].Cs.return_value = cs_mock

        extractor.disassemble_all_sections(pe)
        sys.modules["capstone"].Cs.assert_called_with(
            sys.modules["capstone"].CS_ARCH_X86,
            sys.modules["capstone"].CS_MODE_64,
        )

    def test_instruction_counts_aggregated(self, extractor):
        pe = self._make_pe()
        section = MagicMock()
        section.Name = b".text\x00\x00\x00"
        section.get_data.return_value = b"\x90" * 16
        section.VirtualAddress = 0x1000
        pe.sections = [section]

        # Fake instructions: 3 mov, 5 add
        instr_add = MagicMock(); instr_add.mnemonic = "add"
        instr_mov = MagicMock(); instr_mov.mnemonic = "mov"
        instrs = [instr_add] * 5 + [instr_mov] * 3

        cs_mock = MagicMock()
        cs_mock.disasm.return_value = iter(instrs)
        sys.modules["capstone"].Cs.return_value = cs_mock

        result = extractor.disassemble_all_sections(pe)
        overall = result["overall_analysis"]
        assert overall["add_count"] == 5
        assert overall["mov_count"] == 3
        assert overall["total_instructions"] == 8
        assert overall["is_likely_packed"] is True  # add > mov

    def test_capstone_exception_sets_error(self, extractor):
        pe = self._make_pe()
        sys.modules["capstone"].Cs.side_effect = RuntimeError("boom")
        result = extractor.disassemble_all_sections(pe)
        assert result["error"] is not None
        sys.modules["capstone"].Cs.side_effect = None  # reset


# ===========================================================================
# 3. PEFeatureExtractor.analyze_with_radare2
# ===========================================================================

class TestAnalyzeWithRadare2:
    """All r2pipe interaction is fully mocked."""

    def _make_r2(self):
        r2 = MagicMock()
        r2.cmd.side_effect = lambda c: {
            "aa": "",
            "aflc": "3",
            "axl": "xref1\nxref2\n",
        }.get(c, "")
        r2.cmdj.side_effect = lambda c: {
            "aflj": [
                {"nbbs": 4, "cc": 2},
                {"nbbs": 6, "cc": 3},
                {"nbbs": 2, "cc": 1},
            ],
            "izj": [{"string": "hello"}, {"string": "world"}],
        }.get(c, [])
        return r2

    # --- availability guard ---

    def test_r2pipe_not_available(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        with patch.object(tp, "_R2PIPE_AVAILABLE", False):
            result = extractor.analyze_with_radare2(str(f))
        assert result["error"] == "r2pipe_not_installed"
        assert result["r2_analysis_success"] is False

    # --- size guard ---

    def test_file_too_large_skipped(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path, size=512)
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=11 * 1024 * 1024):
            result = extractor.analyze_with_radare2(str(f))
        assert result["error"] == "file_too_large"
        assert result["r2_analysis_success"] is False

    def test_file_at_exactly_10mb_not_skipped(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=10 * 1024 * 1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            result = extractor.analyze_with_radare2(str(f))
        # Should proceed (10 MB is not > 10 MB)
        assert result["error"] is None
        assert result["r2_analysis_success"] is True

    # --- happy path ---

    def test_success_all_fields_populated(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            result = extractor.analyze_with_radare2(str(f))

        assert result["r2_analysis_success"] is True
        assert result["function_count"] == 3
        assert result["basic_block_count"] == 12         # 4+6+2
        assert abs(result["avg_basic_blocks_per_function"] - 4.0) < 0.01
        assert abs(result["cyclomatic_complexity_mean"] - 2.0) < 0.01
        assert result["xref_count"] == 2
        assert result["r2_string_count"] == 2
        assert result["error"] is None

    def test_invalid_aflc_response_defaults_to_zero(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        r2.cmd.side_effect = lambda c: "" if c == "aflc" else \
            {"aa": "", "axl": ""}.get(c, "")
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            result = extractor.analyze_with_radare2(str(f))
        assert result["function_count"] == 0

    def test_empty_function_list(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        r2.cmdj.side_effect = lambda c: [] if c == "aflj" else \
            [{"string": "s"}] if c == "izj" else []
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            result = extractor.analyze_with_radare2(str(f))
        assert result["basic_block_count"] == 0
        assert result["avg_basic_blocks_per_function"] == 0.0
        assert result["cyclomatic_complexity_mean"] == 0.0

    def test_empty_xrefs_returns_zero(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        r2.cmd.side_effect = lambda c: {"aa": "", "aflc": "1", "axl": ""}.get(c, "")
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            result = extractor.analyze_with_radare2(str(f))
        assert result["xref_count"] == 0

    def test_r2pipe_open_exception_caught(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.side_effect = OSError("radare2 not found")
            result = extractor.analyze_with_radare2(str(f))
        assert result["r2_analysis_success"] is False
        assert "radare2 not found" in result["error"]

    def test_r2_cmd_exception_caught(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = MagicMock()
        r2.cmd.side_effect = RuntimeError("pipe broke")
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            result = extractor.analyze_with_radare2(str(f))
        assert result["r2_analysis_success"] is False
        assert result["error"] is not None

    def test_r2_quit_failure_does_not_raise(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        r2.quit.side_effect = Exception("quit failed")
        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            result = extractor.analyze_with_radare2(str(f))
        # Should still succeed despite quit() raising
        assert result["r2_analysis_success"] is True

    # --- PATH injection ---

    def test_path_prepended_before_open(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        captured_path_at_open = []

        def fake_open(fp, flags):
            captured_path_at_open.append(os.environ.get("PATH", ""))
            return r2

        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.side_effect = fake_open
            extractor.analyze_with_radare2(str(f))

        assert len(captured_path_at_open) == 1
        assert str(tp._R2_DIR) in captured_path_at_open[0]
        # _R2_DIR should be FIRST entry
        assert captured_path_at_open[0].startswith(str(tp._R2_DIR))

    def test_path_restored_after_success(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        original_path = os.environ.get("PATH", "")

        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            extractor.analyze_with_radare2(str(f))

        assert os.environ.get("PATH", "") == original_path

    def test_path_restored_when_open_raises(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        original_path = os.environ.get("PATH", "")

        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.side_effect = OSError("no r2")
            extractor.analyze_with_radare2(str(f))

        assert os.environ.get("PATH", "") == original_path

    def test_path_restored_when_cmd_raises(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = MagicMock()
        r2.cmd.side_effect = RuntimeError("dead pipe")
        original_path = os.environ.get("PATH", "")

        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            extractor.analyze_with_radare2(str(f))

        assert os.environ.get("PATH", "") == original_path

    def test_path_restored_when_quit_raises(self, extractor, tmp_path):
        f = _make_temp_mz(tmp_path)
        r2 = self._make_r2()
        r2.quit.side_effect = Exception("quit error")
        original_path = os.environ.get("PATH", "")

        with patch.object(tp, "_R2PIPE_AVAILABLE", True), \
             patch("os.path.getsize", return_value=1024), \
             patch.object(tp, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open.return_value = r2
            extractor.analyze_with_radare2(str(f))

        assert os.environ.get("PATH", "") == original_path


# ===========================================================================
# 4. features_to_numeric — vector contract
# ===========================================================================

class TestFeaturesToNumeric:
    EXPECTED_LEN = 45  # 38 PE + 7 r2

    def test_vector_length(self, data_processor):
        vec = data_processor.features_to_numeric(_minimal_features())
        assert len(vec) == self.EXPECTED_LEN, (
            f"Expected {self.EXPECTED_LEN} features, got {len(vec)}"
        )

    def test_vector_dtype_float32(self, data_processor):
        vec = data_processor.features_to_numeric(_minimal_features())
        assert vec.dtype == np.float32

    def test_empty_dict_all_zeros(self, data_processor):
        vec = data_processor.features_to_numeric({})
        assert len(vec) == self.EXPECTED_LEN
        assert np.all(vec == 0.0)

    def test_non_dict_all_zeros(self, data_processor):
        vec = data_processor.features_to_numeric(None)
        assert len(vec) == self.EXPECTED_LEN
        assert np.all(vec == 0.0)

    def test_r2_success_flag_at_last_index(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["r2_analysis_success"] = True
        vec = data_processor.features_to_numeric(feat)
        assert vec[-1] == 1.0  # r2_success is last

    def test_r2_success_false_gives_zero(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["r2_analysis_success"] = False
        vec = data_processor.features_to_numeric(feat)
        assert vec[-1] == 0.0

    def test_r2_function_count_in_vector(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["function_count"] = 42
        vec = data_processor.features_to_numeric(feat)
        # r2 block starts at index 38
        assert vec[38] == 42.0

    def test_r2_basic_block_count_in_vector(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["basic_block_count"] = 77
        vec = data_processor.features_to_numeric(feat)
        assert vec[39] == 77.0

    def test_r2_avg_bb_per_func_in_vector(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["avg_basic_blocks_per_function"] = 3.5
        vec = data_processor.features_to_numeric(feat)
        assert abs(vec[40] - 3.5) < 1e-5

    def test_r2_cc_mean_in_vector(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["cyclomatic_complexity_mean"] = 2.75
        vec = data_processor.features_to_numeric(feat)
        assert abs(vec[41] - 2.75) < 1e-5

    def test_r2_xref_count_in_vector(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["xref_count"] = 99
        vec = data_processor.features_to_numeric(feat)
        assert vec[42] == 99.0

    def test_r2_string_count_in_vector(self, data_processor):
        feat = _minimal_features()
        feat["radare2"]["r2_string_count"] = 15
        vec = data_processor.features_to_numeric(feat)
        assert vec[43] == 15.0

    def test_missing_radare2_key_fills_zeros(self, data_processor):
        feat = _minimal_features()
        del feat["radare2"]
        vec = data_processor.features_to_numeric(feat)
        # indices 38..44 should all be 0
        assert np.all(vec[38:] == 0.0)

    def test_imports_count_at_index_15(self, data_processor):
        feat = _minimal_features()
        feat["imports"] = ["A", "B", "C"]
        vec = data_processor.features_to_numeric(feat)
        assert vec[15] == 3.0

    def test_is_likely_packed_flag(self, data_processor):
        feat = _minimal_features()
        feat["section_disassembly"]["overall_analysis"]["is_likely_packed"] = True
        vec = data_processor.features_to_numeric(feat)
        assert vec[26] == 1.0  # is_likely_packed index


# ===========================================================================
# 5. DataProcessor._get_file_md5
# ===========================================================================

class TestGetFileMd5:
    def test_valid_mz_returns_md5_and_true(self, data_processor, tmp_path):
        f = _make_temp_mz(tmp_path)
        md5, is_pe = data_processor._get_file_md5(f)
        assert is_pe is True
        assert md5 == hashlib.md5(f.read_bytes()).hexdigest()

    def test_non_mz_returns_none_false(self, data_processor, tmp_path):
        f = _make_temp_text(tmp_path, b"RIFF\x00\x00\x00\x00")
        md5, is_pe = data_processor._get_file_md5(f)
        assert is_pe is False
        assert md5 is None

    def test_text_file_returns_none_false(self, data_processor, tmp_path):
        f = _make_temp_text(tmp_path, b"#!/usr/bin/python\n")
        md5, is_pe = data_processor._get_file_md5(f)
        assert is_pe is False

    def test_nonexistent_file_returns_none_true(self, data_processor, tmp_path):
        f = tmp_path / "does_not_exist.exe"
        md5, is_pe = data_processor._get_file_md5(f)
        # Should not raise; treats as PE but failed to read
        assert md5 is None

    def test_md5_correct(self, data_processor, tmp_path):
        data = b"MZ" + b"\xab\xcd" * 100
        f = tmp_path / "chk.exe"
        f.write_bytes(data)
        md5, is_pe = data_processor._get_file_md5(f)
        assert is_pe is True
        assert md5 == hashlib.md5(data).hexdigest()


# ===========================================================================
# 6. DataProcessor._move
# ===========================================================================

class TestMove:
    def test_moves_file_to_dest(self, data_processor, tmp_path):
        src = _make_temp_mz(tmp_path, name="move_me.exe")
        dest_root = tmp_path / "dest"
        data_processor._move(src, dest_root)
        assert (dest_root / "move_me.exe").exists()
        assert not src.exists()

    def test_no_error_if_dest_already_exists(self, data_processor, tmp_path):
        src = _make_temp_mz(tmp_path, name="dup.exe")
        dest_root = tmp_path / "dest"
        dest_root.mkdir()
        (dest_root / "dup.exe").write_bytes(b"MZ")
        # Should silently skip without raising
        data_processor._move(src, dest_root)

    def test_permission_error_silently_skipped(self, data_processor, tmp_path):
        src = _make_temp_mz(tmp_path, name="locked.exe")
        dest_root = tmp_path / "dest"
        with patch("shutil.move", side_effect=PermissionError("locked")):
            data_processor._move(src, dest_root)
        # No exception raised

    def test_creates_dest_directory(self, data_processor, tmp_path):
        src = _make_temp_mz(tmp_path, name="a.exe")
        dest_root = tmp_path / "new" / "nested" / "dir"
        assert not dest_root.exists()
        data_processor._move(src, dest_root)
        assert dest_root.exists()


# ===========================================================================
# 7. DataProcessor._append_vector_and_index
# ===========================================================================

class TestAppendVectorAndIndex:
    def test_writes_binary_vector(self, data_processor):
        feat = _minimal_features(is_malicious=True)
        data_processor._append_vector_and_index(feat)
        content = data_processor.bin_path.read_bytes()
        vec = data_processor.features_to_numeric(feat)
        assert content == vec.tobytes()

    def test_writes_jsonl_index_entry(self, data_processor):
        feat = _minimal_features(is_malicious=False)
        entry = data_processor._append_vector_and_index(feat)
        lines = data_processor.index_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["md5"] == "abc123"
        assert obj["label"] == "benign"

    def test_index_entry_has_offset_zero_for_first_write(self, data_processor):
        feat = _minimal_features()
        entry = data_processor._append_vector_and_index(feat)
        assert entry["offset"] == 0

    def test_second_write_has_correct_offset(self, data_processor):
        feat = _minimal_features()
        data_processor._append_vector_and_index(feat)
        entry2 = data_processor._append_vector_and_index(feat)
        vec_len = len(data_processor.features_to_numeric(feat).tobytes())
        assert entry2["offset"] == vec_len

    def test_pickle_appended_to_correct_file(self, data_processor):
        feat_mal = _minimal_features(is_malicious=True)
        feat_ben = _minimal_features(is_malicious=False)
        data_processor._append_vector_and_index(feat_mal)
        data_processor._append_vector_and_index(feat_ben)

        def load_pickles(path: Path):
            records = []
            with open(path, "rb") as f:
                while True:
                    try:
                        records.append(pickle.load(f))
                    except EOFError:
                        break
            return records

        mal_records = load_pickles(data_processor.malicious_pickle_path)
        ben_records = load_pickles(data_processor.benign_pickle_path)
        assert len(mal_records) == 1
        assert len(ben_records) == 1

    def test_vec_len_in_index_matches_actual(self, data_processor):
        feat = _minimal_features()
        entry = data_processor._append_vector_and_index(feat)
        assert entry["vec_len"] == 45


# ===========================================================================
# 8. DataProcessor._process_one
# ===========================================================================

class TestProcessOne:
    def _make_args(self, file_path, rank=1, is_malicious=True, md5="abc"):
        return (file_path, rank, is_malicious, md5)

    def test_success_returns_features_with_file_info(self, data_processor, tmp_path):
        f = _make_temp_mz(tmp_path)
        feat = _minimal_features()
        with patch.object(data_processor.pe_extractor, "extract_numeric_features",
                          return_value=feat):
            result = data_processor._process_one(self._make_args(f))
        assert result is not None
        assert "file_info" in result
        assert result["file_info"]["md5"] == "abc"
        assert result["file_info"]["is_malicious"] is True

    def test_extractor_returns_none_gives_none(self, data_processor, tmp_path):
        f = _make_temp_mz(tmp_path)
        with patch.object(data_processor.pe_extractor, "extract_numeric_features",
                          return_value=None):
            result = data_processor._process_one(self._make_args(f))
        assert result is None

    def test_permission_error_retried_then_none(self, data_processor, tmp_path):
        f = _make_temp_mz(tmp_path)
        with patch.object(data_processor.pe_extractor, "extract_numeric_features",
                          side_effect=PermissionError("locked")):
            result = data_processor._process_one(self._make_args(f))
        assert result is None

    def test_unexpected_exception_returns_none(self, data_processor, tmp_path):
        f = _make_temp_mz(tmp_path)
        with patch.object(data_processor.pe_extractor, "extract_numeric_features",
                          side_effect=ValueError("oops")):
            result = data_processor._process_one(self._make_args(f))
        assert result is None

    def test_file_info_size_populated(self, data_processor, tmp_path):
        f = _make_temp_mz(tmp_path, size=1024)
        feat = _minimal_features()
        with patch.object(data_processor.pe_extractor, "extract_numeric_features",
                          return_value=feat):
            result = data_processor._process_one(self._make_args(f))
        assert result["file_info"]["size"] == 1024


# ===========================================================================
# 9. DataProcessor._run_global_prefilter
# ===========================================================================

class TestRunGlobalPrefilter:
    def test_non_pe_files_excluded(self, data_processor, tmp_path):
        # Put text files in malicious dir
        mal_dir = Path(data_processor.malicious_dir)
        (mal_dir / "script.js").write_bytes(b"var x = 1;")
        (mal_dir / "legit.exe").write_bytes(b"MZ" + b"\x00" * 100)

        malicious, benign = data_processor._run_global_prefilter()
        # Only the MZ file should pass
        assert len(malicious) == 1
        assert malicious[0][0].name == "legit.exe"

    def test_intra_class_duplicates_moved(self, data_processor, tmp_path):
        mal_dir = Path(data_processor.malicious_dir)
        # Two identical files
        data = b"MZ" + b"\xff" * 200
        (mal_dir / "a.exe").write_bytes(data)
        (mal_dir / "b.exe").write_bytes(data)

        malicious, _ = data_processor._run_global_prefilter()
        assert len(malicious) == 1  # duplicate removed

    def test_cross_class_conflict_benign_moved(self, data_processor, tmp_path):
        data = b"MZ" + b"\xaa" * 200
        mal_dir = Path(data_processor.malicious_dir)
        ben_dir = Path(data_processor.benign_dir)
        (mal_dir / "mal.exe").write_bytes(data)
        (ben_dir / "ben.exe").write_bytes(data)  # same content

        malicious, benign = data_processor._run_global_prefilter()
        # Malicious wins; benign with same MD5 discarded
        assert len(malicious) == 1
        assert len(benign) == 0

    def test_empty_dirs_return_empty_lists(self, data_processor):
        malicious, benign = data_processor._run_global_prefilter()
        assert malicious == []
        assert benign == []


# ===========================================================================
# 10. DataProcessor.process_dir
# ===========================================================================

class TestProcessDir:
    def _make_task(self, tmp_path, name="sample.exe"):
        f = _make_temp_mz(tmp_path, name=name)
        md5 = hashlib.md5(f.read_bytes()).hexdigest()
        return (f, md5)

    def test_empty_task_list_returns_stats(self, data_processor):
        stats = data_processor.process_dir(is_malicious=True, prefiltered_tasks=[])
        assert stats["inserted"] == 0

    def test_successful_processing_increments_inserted(self, data_processor, tmp_path):
        task = self._make_task(tmp_path)
        feat = _minimal_features()
        feat["file_info"]["md5"] = task[1]

        with patch.object(data_processor, "_process_one", return_value=feat), \
             patch("train_pefile.ProcessPoolExecutor") as MockExec:
            # Make map() behave synchronously
            MockExec.return_value.__enter__.return_value.map.return_value = iter([feat])
            data_processor.process_dir(is_malicious=True, prefiltered_tasks=[task])

        assert data_processor.stats["malicious"]["inserted"] == 1

    def test_none_result_counted_as_failed(self, data_processor, tmp_path):
        task = self._make_task(tmp_path)

        with patch("train_pefile.ProcessPoolExecutor") as MockExec:
            MockExec.return_value.__enter__.return_value.map.return_value = iter([None])
            data_processor.process_dir(is_malicious=True, prefiltered_tasks=[task])

        assert data_processor.stats["malicious"]["failed"] == 1
        assert data_processor.stats["malicious"]["inserted"] == 0


# ===========================================================================
# 11. DataProcessor.process_dataset (smoke test)
# ===========================================================================

class TestProcessDataset:
    def test_summary_json_created(self, data_processor, tmp_path):
        # No files in either directory → trivial run
        with patch.object(data_processor, "_run_global_prefilter",
                          return_value=([], [])), \
             patch.object(data_processor, "process_dir",
                          return_value=data_processor._new_label_stats()):
            data_processor.process_dataset()

        summary_files = list(data_processor.output_dir.glob("summary.json"))
        assert len(summary_files) == 1

    def test_summary_has_required_keys(self, data_processor):
        with patch.object(data_processor, "_run_global_prefilter",
                          return_value=([], [])), \
             patch.object(data_processor, "process_dir",
                          return_value=data_processor._new_label_stats()):
            data_processor.process_dataset()

        summary_path = data_processor.output_dir / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        for key in ("timestamp", "malicious_count", "benign_count", "totals"):
            assert key in summary, f"Missing key: {key}"

    def test_reset_clears_existing_files(self, tmp_path):
        mal_dir = tmp_path / "mal"
        ben_dir = tmp_path / "ben"
        mal_dir.mkdir(); ben_dir.mkdir()

        dp1 = tp.DataProcessor(str(mal_dir), str(ben_dir),
                                out_dir_prefix=str(tmp_path / "out"), reset=False)
        # Write something to the bin
        dp1.bin_path.write_bytes(b"\xff" * 64)

        dp2 = tp.DataProcessor(str(mal_dir), str(ben_dir),
                                out_dir_prefix=str(tmp_path / "out"), reset=True)
        # After reset the new bin should be empty
        assert dp2.bin_path.read_bytes() == b""


# ===========================================================================
# 12. _load_seen_md5s / resume support
# ===========================================================================

class TestLoadSeenMd5s:
    def test_loads_existing_index(self, data_processor):
        entry = json.dumps({"md5": "deadbeef", "label": "malicious"})
        data_processor.index_path.write_text(entry + "\n", encoding="utf-8")
        seen = data_processor._load_seen_md5s()
        assert seen.get("deadbeef") == "malicious"

    def test_skips_malformed_lines(self, data_processor):
        data_processor.index_path.write_text(
            '{"md5":"aaa","label":"benign"}\nnot json\n{"md5":"bbb","label":"malicious"}\n',
            encoding="utf-8"
        )
        seen = data_processor._load_seen_md5s()
        assert "aaa" in seen
        assert "bbb" in seen

    def test_empty_index_returns_empty_dict(self, data_processor):
        seen = data_processor._load_seen_md5s()
        assert seen == {}