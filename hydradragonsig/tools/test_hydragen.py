#!/usr/bin/env python3
"""
Tests for hydragen.

Run with:
    python -m unittest discover -s tools -v
    python tools/test_hydragen.py

The interesting tests are the round-trip ones: generate rules from a synthetic
corpus, then check the emitter produced something a HydraDragonSig loader can
consume and that the rules actually match the samples they came from.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hydragen as hg  # noqa: E402


def make_pe_like(marker: str, extra: str = "", code: bytes = b"") -> bytes:
    """
    A minimal MZ/PE blob that lief accepts and hydradragonsig calls a PE.

    It is not a runnable executable and does not need to be: the generator only
    reads the header, sections and imports. The layout is:

        0x000 .. 0x400   headers
        0x400 .. 0x800   .text   (RVA 0x1000)
        0x800 .. 0xC00   .rdata  (RVA 0x2000)  - holds the import directory

    Pass `code` to fill .text, which is what the opcode extractor looks at.
    """
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")

    # IMAGE_NT_HEADERS at 0x40: signature, file header, optional header.
    # The optional header is PE32+, whose field offsets differ from PE32's, so
    # they are spelled out rather than hardcoded inline.
    OPT = 0x18  # optional header offset inside IMAGE_NT_HEADERS
    nt = bytearray(OPT + 0xF0)
    nt[0:4] = b"PE\0\0"
    nt[4:6] = (0x8664).to_bytes(2, "little")  # machine: x86-64
    nt[6:8] = (2).to_bytes(2, "little")  # number of sections
    nt[20:22] = (0xF0).to_bytes(2, "little")  # size of optional header

    def opt(field_offset: int, value: int, width: int) -> None:
        nt[OPT + field_offset : OPT + field_offset + width] = value.to_bytes(
            width, "little"
        )

    opt(0, 0x20B, 2)  # Magic: PE32+
    opt(16, 0x1000, 4)  # AddressOfEntryPoint -> inside .text
    opt(20, 0x1000, 4)  # BaseOfCode
    opt(24, 0x400000, 8)  # ImageBase
    opt(32, 0x200, 4)  # SectionAlignment
    opt(36, 0x200, 4)  # FileAlignment
    opt(56, 0x4000, 4)  # SizeOfImage
    opt(60, 0x400, 4)  # SizeOfHeaders
    opt(68, 2, 2)  # Subsystem: GUI
    opt(108, 16, 4)  # NumberOfRvaAndSizes

    # Data directory 1 = imports. No resource directory: nothing here needs one,
    # and pointing it outside a section only makes lief complain.
    DD = OPT + 112
    nt[DD + 1 * 8 : DD + 1 * 8 + 4] = (0x2000).to_bytes(4, "little")
    nt[DD + 1 * 8 + 4 : DD + 1 * 8 + 8] = (0xA0).to_bytes(4, "little")

    sec_off = 0x58 + 0xF0
    text = bytearray(40)
    text[0:6] = b".text\0"
    text[8:12] = (0x1000).to_bytes(4, "little")  # virtual address
    text[12:16] = (0x1000).to_bytes(4, "little")  # virtual size
    text[16:20] = (0x400).to_bytes(4, "little")  # size of raw data
    text[20:24] = (0x400).to_bytes(4, "little")  # pointer to raw data
    text[36:40] = (0x60000020).to_bytes(4, "little")  # code|execute|read

    rdata = bytearray(40)
    rdata[0:7] = b".rdata\0"
    rdata[8:12] = (0x2000).to_bytes(4, "little")
    rdata[12:16] = (0x2000).to_bytes(4, "little")
    rdata[16:20] = (0x400).to_bytes(4, "little")  # size of raw data
    rdata[20:24] = (0x800).to_bytes(4, "little")
    rdata[36:40] = (0x40000040).to_bytes(4, "little")  # initialised data|read

    body = bytearray(0xC00)
    body[0:len(dos)] = dos
    body[0x40 : 0x40 + len(nt)] = nt
    body[sec_off : sec_off + 40] = text
    body[sec_off + 40 : sec_off + 80] = rdata

    # Code section: the entrypoint stub the opcode extractor latches onto.
    stub = code or bytes([0x48, 0x89, 0x5C, 0x24, 0x48, 0x83, 0xEC, 0x28])
    body[0x400 : 0x400 + len(stub)] = stub

    # A real IMAGE_IMPORT_DESCRIPTOR tree in .rdata, so the import extraction
    # path is actually exercised. RVA 0x2000 == file 0x800 here.
    def put(rva: int, blob: bytes) -> None:
        offset = 0x800 + (rva - 0x2000)
        body[offset : offset + len(blob)] = blob

    put(0x2000, (0x2080).to_bytes(4, "little") + b"\0" * 12 + (0x20A0).to_bytes(4, "little")
        + (0x2080).to_bytes(4, "little"))
    put(0x2000 + 0x50, b"\0" * 20)  # null terminator for the descriptor array
    # Import name table: 8-byte thunks, terminated by a null entry.
    put(0x2080, (0x20B0).to_bytes(8, "little"))
    put(0x2088, (0x20C8).to_bytes(8, "little"))
    put(0x2090, b"\0" * 8)
    put(0x20A0, b"kernel32.dll\x00")
    put(0x20B0, b"\x00\x00" + b"CloseHandle\x00")
    put(0x20C8, b"\x00\x00" + b"CreateProcessA\x00")

    # A distinctive wide marker plus padding, so the extractor has something.
    body[0xA00 : 0xA00 + len(marker)] = marker.encode()
    wide = marker.encode("utf-16-le")
    body[0xA40 : 0xA40 + len(wide)] = wide
    if extra:
        body[0xA80 : 0xA80 + len(extra)] = extra.encode()

    return bytes(body)


def find_clamav_test_exe() -> Path | None:
    """The ClamAV test binary, used where a real PE is needed."""
    root = Path(__file__).resolve().parents[2]
    for candidate in (
        root / "clamav" / "unit_tests" / "input" / "pe_allmatch" / "test.exe",
        root.parent / "clamav" / "unit_tests" / "input" / "pe_allmatch" / "test.exe",
    ):
        if candidate.is_file():
            return candidate
    return None


class TestStringHelpers(unittest.TestCase):
    def test_ascii_string_length_floor(self):
        self.assertFalse(hg.is_ascii_string("abc"))
        self.assertTrue(hg.is_ascii_string("abcdef"))

    def test_is_base64_needs_valid_alphabet_and_decodability(self):
        encoded = base64.b64encode(b"a" * 24).decode()
        self.assertTrue(hg.is_base64(encoded))
        self.assertFalse(hg.is_base64("short"))
        # Characters outside the base64 alphabets.
        self.assertFalse(hg.is_base64("!" * 16))
        self.assertFalse(hg.is_base64("not valid base64!!"))
        # Right length but the trailing padding is wrong.
        self.assertFalse(hg.is_base64("A" * 15 + "=="))

    def test_is_hex_encoded_detects_encoded_ascii(self):
        self.assertTrue(hg.is_hex_encoded("48656c6c6f20776f726c64"))
        self.assertFalse(hg.is_hex_encoded("zzz"))
        self.assertFalse(hg.is_hex_encoded("48656c"))

    def test_is_boring_rejects_infrastructure(self):
        self.assertTrue(hg.is_boring("kernel32.dll"))
        self.assertTrue(hg.is_boring("This program cannot be run in DOS mode"))
        self.assertFalse(hg.is_boring("Qw7Zx2Lm9Rt4Yu1"))

    def test_extract_finds_ascii_and_wide(self):
        marker = "UniqMarkerAbCdEf"
        data = b"\x00" * 32 + marker.encode() + b"\x00" * 8 + marker.encode("utf-16-le")
        found = hg.extract_strings(data)
        self.assertIn(marker, found)

    def test_min_length_is_respected(self):
        # A 9-character run: found by the regex, then dropped by the floor.
        data = b"abcdefghi"
        self.assertEqual(hg.extract_strings(data, min_len=10), [])
        self.assertEqual(hg.extract_strings(data, min_len=8), ["abcdefghi"])
        # The floor can be raised at runtime but never lowered below the regex.
        self.assertEqual(hg.extract_strings(data, min_len=2), ["abcdefghi"])


class TestScoring(unittest.TestCase):
    def test_long_mixed_marker_scores_higher_than_short_word(self):
        marker = "Qw7Zx2Lm9Rt4Yu1pQ"
        self.assertGreater(hg.score_string(marker), hg.score_string("kernel32"))

    def test_sentence_is_penalised(self):
        self.assertLess(
            hg.score_string("this is a normal english sentence that was written"),
            hg.score_string("Zx9#Qm2vLp7Wc4Kz"),
        )

    def test_base64_blob_gets_a_bonus(self):
        blob = base64.b64encode(b"payload" * 8).decode()
        self.assertGreaterEqual(hg.score_string(blob), hg.score_string("payload"))

    def test_discrimination_favours_malware_only_strings(self):
        # In every sample, but never in benign: should be high.
        malware_only = hg.discrimination(malware_count=10, benign_count=0, samples=10)
        # In every benign sample too: should be zero.
        everywhere = hg.discrimination(malware_count=10, benign_count=10, samples=10)
        self.assertEqual(malware_only, 1.0)
        self.assertEqual(everywhere, 0.0)

    def test_benign_corpus_vetoes_a_string(self):
        marker = "RareMarkerXyZ98765"
        benign = {"RareMarkerXyZ98765"}
        sample = hg.SampleInfo(path="a.exe", name="a.exe", strings=[marker])
        malware_counts = {marker: 5}
        benign_counts = {marker: 5}
        ranked = hg.rank_strings(sample, malware_counts, 5, benign_counts, 5)
        self.assertEqual(ranked, [], "a string in every benign file must be dropped")

    def test_rank_sorts_by_score(self):
        a, b = "Qw7Zx2Lm9Rt4Yu1", "Zx9#Qm2vLp7Wc4Kz"
        sample = hg.SampleInfo(path="a.exe", name="a.exe", strings=[a, b])
        counts = {a: 4, b: 4}
        ranked = hg.rank_strings(sample, counts, 4, {}, 0)
        self.assertEqual(len(ranked), 2)
        self.assertGreaterEqual(ranked[0][1], ranked[1][1])


class TestPeInfo(unittest.TestCase):
    def test_pe_like_blob_is_recognised(self):
        info = hg.get_pe_info(make_pe_like("MarkerAbCdEf12"), "a.exe")
        self.assertTrue(info.is_pe, "the synthetic blob should parse as PE")
        self.assertEqual(info.size, 0xC00)
        self.assertEqual(info.magic, "4d5a")
        self.assertEqual(info.bitness, "pe64")

    def test_non_pe_is_not_flagged(self):
        info = hg.get_pe_info(b"just some text, not an executable", "a.txt")
        self.assertFalse(info.is_pe)
        self.assertFalse(info.is_elf)

    def test_entrypoint_section_is_located(self):
        # The opcode extractor depends on this: without it there is no .text.
        info = hg.get_pe_info(make_pe_like("MarkerAbCdEf12"), "a.exe")
        self.assertEqual(info.ep_section, ".text")
        self.assertIn(".rdata", info.sections)

    def test_opcode_stub_is_extracted(self):
        stub = bytes([0x55, 0x48, 0x89, 0xE5, 0x83, 0xEC, 0x20, 0xC3])
        opcodes = hg.extract_opcodes(make_pe_like("MarkerAbCdEf12", code=stub))
        self.assertEqual(opcodes, [stub.hex()])

    def test_imports_are_read_from_a_real_pe(self):
        """
        lief is stricter than it looks about hand-built import tables, so the
        import path is covered against a real executable instead.
        """
        real = find_clamav_test_exe()
        if real is None:
            self.skipTest("ClamAV test.exe not available")
        info = hg.get_pe_info(real.read_bytes(), str(real))
        self.assertTrue(info.is_pe)
        self.assertTrue(info.import_dlls, "expected at least one import DLL")
        self.assertTrue(
            any("CloseHandle" in name for name in info.imports),
            f"expected CloseHandle in {info.imports[:10]}",
        )
        self.assertIn("kernel32.dll", [d.lower() for d in info.import_dlls])


class TestEmitters(unittest.TestCase):
    def _rule(self, **kwargs) -> hg.Rule:
        base = dict(
            name="gen_sample",
            identifier="gen",
            title="Generated signature for sample.exe",
            strings=[hg.RuleString("a", "MarkerAbCdEf12", score=9)],
            high=["a"],
            low=[],
            quantifier="high",
        )
        base.update(kwargs)
        return hg.Rule(**base)

    def test_yara_output_has_the_expected_scaffolding(self):
        text = hg.emit_yara([self._rule()], {"Set": "S", "Author": "t"})
        self.assertIn("rule gen_sample {", text)
        self.assertIn("strings:", text)
        self.assertIn('$a = "MarkerAbCdEf12"', text)
        self.assertIn("condition:", text)

    def test_yara_rule_name_is_sanitised(self):
        rule = self._rule(name="9 bad name!")
        text = hg.emit_yara([rule], {})
        self.assertIn("rule r_9_bad_name_ {", text)

    def test_hydra_output_shape(self):
        text, gaps = hg.emit_hydra([self._rule()], {"Author": "t"}, "Set")
        self.assertIn("name: Set", text)
        self.assertIn("rules:", text)
        self.assertIn("- id: gen_sample", text)
        self.assertIn("type: native_signature", text)
        self.assertIn("value: MarkerAbCdEf12", text)
        self.assertIn("kind: text", text)
        self.assertEqual(gaps, [])

    def test_hydra_id_is_not_doubled(self):
        rule = self._rule()
        self.assertEqual(rule.hydra_id(), "gen_sample")

    def test_hydra_atoms_carry_modifiers(self):
        item = hg.RuleString("a", "C:\\Windows\\System32", wide=True, nocase=True)
        rule = self._rule(strings=[item], high=["a"])
        text, _ = hg.emit_hydra([rule], {}, "S")
        self.assertIn("wide: true", text)
        self.assertIn("nocase: true", text)

    def test_unsupported_constructs_are_reported_not_hidden(self):
        rule = self._rule(pe_conditions=["pe.is_dll()"])
        _, gaps = hg.emit_hydra([rule], {}, "S")
        self.assertTrue(
            any("is_dll" in g for g in gaps),
            f"pe.is_dll() should be reported as a gap, got {gaps}",
        )

    def test_inverse_rule_reports_its_gap(self):
        rule = self._rule(kind="inverse", private=True, filename="setup.exe")
        _, gaps = hg.emit_hydra([rule], {}, "S")
        self.assertTrue(any("inverse" in g for g in gaps))

    def test_yaml_scalar_quotes_only_when_needed(self):
        self.assertEqual(hg.yaml_scalar("abc_def"), "abc_def")
        self.assertEqual(hg.yaml_scalar("with space"), '"with space"')
        self.assertEqual(hg.yaml_scalar("yes"), '"yes"')
        self.assertEqual(hg.yaml_scalar(""), '""')
        self.assertEqual(hg.yaml_scalar(12), "12")
        self.assertEqual(hg.yaml_scalar(True), "true")

    def test_yaml_scalar_escapes_quotes_and_backslashes(self):
        self.assertEqual(hg.yaml_scalar('a"b'), '"a\\"b"')
        self.assertEqual(hg.yaml_scalar("a\\b"), '"a\\\\b"')


class TestAtomIds(unittest.TestCase):
    def test_sequence_matches_yara_alphabet(self):
        self.assertEqual([hg._atom_id(i) for i in range(3)], ["a", "b", "c"])
        self.assertEqual(hg._atom_id(25), "z")
        self.assertEqual(hg._atom_id(26), "aa")


class TestEndToEnd(unittest.TestCase):
    """Generate from a synthetic corpus and check the output is usable."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.mal = root / "mal"
        self.good = root / "good"
        self.mal.mkdir()
        self.good.mkdir()
        self.sample = self.mal / "evil_sample.exe"
        self.sample.write_bytes(
            make_pe_like("Zx9Qm2vLp7Wc4Kz", extra="helperpayload_9f8e7d6c")
        )
        (self.mal / "evil_two.exe").write_bytes(
            make_pe_like("Zx9Qm2vLp7Wc4Kz", extra="secondfamily_1a2b3c4d")
        )
        (self.good / "benign_one.exe").write_bytes(make_pe_like("KERNEL32.dll is here"))
        (self.good / "benign_two.exe").write_bytes(
            make_pe_like("benignprogramstring_0000")
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *extra: str) -> tuple[str, str]:
        out = Path(self.tmp.name) / "gen"
        proc = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent / "hydragen.py"),
                "-s", str(self.mal),
                "-g", str(self.good),
                "-o", str(out),
                "-f", "both",
                "--no-super",
                *extra,
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return (out.with_suffix(".yara")).read_text(encoding="utf-8"), (
            out.with_suffix(".yaml")
        ).read_text(encoding="utf-8")

    def test_generates_both_formats(self):
        yara, hydra = self._run()
        self.assertIn("rule ", yara)
        self.assertIn("rules:", hydra)
        self.assertIn("type: native_signature", hydra)

    def test_every_rule_id_is_unique(self):
        _, hydra = self._run()
        # Rule ids sit at 2-space indent; the `id:` under `atoms:` is at 10
        # spaces and is a different namespace entirely.
        ids = [
            line.split("- id:", 1)[1].strip()
            for line in hydra.splitlines()
            if line.startswith("  - id:")
        ]
        self.assertTrue(ids)
        self.assertEqual(len(ids), len(set(ids)), f"duplicate rule ids: {ids}")

    def test_atom_ids_are_scoped_to_their_condition(self):
        _, hydra = self._run()
        # Two rules both using $a/$b is correct: atom ids are per-signature.
        self.assertGreaterEqual(hydra.count("          - id: a"), 2)

    def test_generator_does_not_veto_its_own_markers(self):
        yara, hydra = self._run()
        # The shared marker is in every malware sample and no benign one, so it
        # has to survive scoring and reach both outputs.
        self.assertIn("Zx9Qm2vLp7Wc4Kz", yara)
        self.assertIn("Zx9Qm2vLp7Wc4Kz", hydra)

    def test_benign_strings_do_not_leak_into_malware_rules(self):
        _, hydra = self._run()
        # "benignprogramstring_0000" only exists in the good corpus; a rule built
        # from the malware corpus must not claim it.
        malware_block = hydra.split("name:", 1)[-1]
        self.assertNotIn("benignprogramstring_0000", malware_block)

    def test_strict_mode_fails_when_conversion_is_lossy(self):
        # Inverse rules always report a gap, so --strict must be non-zero.
        out = Path(self.tmp.name) / "strict"
        proc = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent / "hydragen.py"),
                "-s", str(self.mal),
                "-g", str(self.good),
                "-o", str(out),
                "-f", "hydra",
                "--no-super",
                "--strict",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("lossy", proc.stdout)

    def test_no_opcodes_flag_removes_byte_patterns(self):
        _, with_ops = self._run()
        _, without = self._run("--no-opcodes")
        self.assertIn("type: byte_set", with_ops)
        self.assertNotIn("type: byte_set", without)

    def test_empty_sample_dir_exits_nonzero(self):
        empty = Path(self.tmp.name) / "empty"
        empty.mkdir()
        proc = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent / "hydragen.py"),
                "-s", str(empty),
                "-o", str(Path(self.tmp.name) / "x"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
