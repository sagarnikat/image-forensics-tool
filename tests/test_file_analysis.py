"""Unit tests for Module 1 (file analysis and integrity).

Run from the project root:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from forensics.file_analysis import analyse_file, compute_hashes, detect_container

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "original" / "original_demo.jpg"


class FileAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ifx-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_hashes_match_hashlib(self) -> None:
        expected = hashlib.sha256(SAMPLE.read_bytes()).hexdigest()
        self.assertEqual(compute_hashes(SAMPLE)["sha256"], expected)

    def test_clean_sample_is_consistent(self) -> None:
        result = analyse_file(SAMPLE)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["score"], 0.0)
        self.assertTrue(result["metrics"]["extension_match"])
        self.assertEqual(result["metrics"]["format"], "JPEG")
        self.assertEqual(result["metrics"]["hashes"]["sha256"], compute_hashes(SAMPLE)["sha256"])

    def test_magic_detection(self) -> None:
        head = SAMPLE.read_bytes()[:32]
        self.assertEqual(detect_container(head)["format"], "JPEG")
        self.assertEqual(detect_container(b"not an image at all") is None, True)

    def test_renamed_extension_is_flagged(self) -> None:
        renamed = self.tmp / "renamed.png"
        shutil.copyfile(SAMPLE, renamed)
        result = analyse_file(renamed)
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(result["score"], 60)
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Extension does not match the real container", titles)

    def test_double_extension_is_flagged(self) -> None:
        suspicious = self.tmp / "holiday.jpg.exe"
        shutil.copyfile(SAMPLE, suspicious)
        result = analyse_file(suspicious)
        self.assertTrue(result["metrics"]["double_extension"])
        self.assertGreaterEqual(result["score"], 75)
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Double extension detected", titles)

    def test_corrupt_file_returns_structured_error(self) -> None:
        corrupt = self.tmp / "corrupt.jpg"
        corrupt.write_text("this is not an image\n")
        result = analyse_file(corrupt)
        self.assertEqual(result["status"], "error")
        self.assertGreaterEqual(result["score"], 80)
        self.assertTrue(any(item["severity"] == "critical" for item in result["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
