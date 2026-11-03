"""Unit tests for the PDF evidence report (Module 6, part 2)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from forensics.pipeline import run_pipeline
from forensics.report import generate_report

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "samples" / "original" / "original_demo.jpg"
SPLICED = ROOT / "samples" / "tampered" / "spliced_demo.jpg"
METADATA_EDIT = ROOT / "samples" / "tampered" / "edited_metadata.jpg"


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ifx-report-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _assert_valid_pdf(self, path: Path) -> None:
        self.assertTrue(path.is_file(), path)
        self.assertGreater(path.stat().st_size, 20_000, "PDF is suspiciously small")
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(5), b"%PDF-")

    def test_clean_image_report_is_authentic(self) -> None:
        facts = generate_report(CLEAN, output_path=self.tmp / "clean.pdf")
        self._assert_valid_pdf(Path(facts["path"]))
        self.assertEqual(facts["verdict"]["label"], "Likely authentic")
        self.assertGreaterEqual(facts["pages"], 3)
        self.assertTrue(facts["case_id"].startswith("PP-"))

    def test_tampered_image_report_is_flagged(self) -> None:
        facts = generate_report(SPLICED, output_path=self.tmp / "spliced.pdf",
                                examiner="Test Examiner")
        self._assert_valid_pdf(Path(facts["path"]))
        self.assertEqual(facts["verdict"]["label"], "Likely tampered")
        self.assertGreaterEqual(facts["verdict"]["score"], 50.0)
        self.assertGreaterEqual(facts["pages"], 4)

    def test_metadata_only_edit_reports_suspicious(self) -> None:
        facts = generate_report(METADATA_EDIT, output_path=self.tmp / "meta.pdf")
        self._assert_valid_pdf(Path(facts["path"]))
        self.assertEqual(facts["verdict"]["label"], "Suspicious")
        self.assertTrue(facts["verdict"]["escalations"])

    def test_corrupt_file_still_produces_a_report(self) -> None:
        broken = self.tmp / "broken.jpg"
        broken.write_text("not an image")
        facts = generate_report(broken, output_path=self.tmp / "broken.pdf")
        self._assert_valid_pdf(Path(facts["path"]))
        self.assertEqual(facts["verdict"]["label"], "Inconclusive")
        self.assertEqual(facts["verdict"]["evaluated"], [])

    def test_directory_output_and_custom_case_id(self) -> None:
        facts = generate_report(CLEAN, output_path=self.tmp, case_id="PP-TEST-0001")
        self._assert_valid_pdf(Path(facts["path"]))
        self.assertEqual(facts["case_id"], "PP-TEST-0001")
        self.assertEqual(Path(facts["path"]).parent, self.tmp)

    def test_pipeline_reports_optional_modules_as_unavailable(self) -> None:
        pipeline = run_pipeline(CLEAN)
        self.assertEqual(
            [item["module"] for item in pipeline["results"]],
            ["file_analysis", "metadata", "ela"],
        )
        self.assertIn("copymove", pipeline["not_available"])
        self.assertIn("stego", pipeline["not_available"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
