"""Unit tests for Module 2 (EXIF / metadata analysis)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from forensics.metadata import analyse_metadata, parse_datetime

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "original" / "original_demo.jpg"


def make_jpeg(path: Path, *, software: str | None = None,
              original: str | None = None, modified: str | None = None) -> Path:
    image = Image.new("RGB", (96, 64), (110, 130, 150))
    exif = Image.Exif()
    if software:
        exif[0x0131] = software
    if modified:
        exif[0x0132] = modified
    sub = exif.get_ifd(0x8769)
    if original:
        sub[0x9003] = original
    image.save(path, "JPEG", quality=90, exif=exif)
    return path


class MetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ifx-meta-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sample_camera_and_xmp(self) -> None:
        result = analyse_metadata(SAMPLE)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["metrics"]["camera"]["make"], "Canon")
        self.assertEqual(result["metrics"]["camera"]["model"], "EOS 90D")
        self.assertGreater(result["metrics"]["tag_count"], 10)
        self.assertEqual(result["metrics"]["xmp"].get("xmp:CreatorTool"), "Canon EOS 90D")

    def test_gps_conversion_and_map_link(self) -> None:
        result = analyse_metadata(SAMPLE)
        gps = result["metrics"]["gps"]
        self.assertIsNotNone(gps)
        self.assertAlmostEqual(gps["latitude"], 12.975, places=3)
        self.assertAlmostEqual(gps["longitude"], 77.594444, places=3)
        self.assertIn("openstreetmap.org", gps["map_url"])
        self.assertIn("12.975", gps["location_text"])
        self.assertEqual(gps["altitude_m"], 920.0)

    def test_missing_exif_is_low_severity_not_crash(self) -> None:
        path = self.tmp / "no_exif.png"
        Image.new("RGB", (64, 64), (30, 40, 50)).save(path, "PNG")
        result = analyse_metadata(path)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["metrics"]["has_exif"])
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("No EXIF metadata found", titles)

    def test_editor_software_is_flagged(self) -> None:
        path = make_jpeg(self.tmp / "edited.jpg", software="Adobe Photoshop 25.0 (Windows)")
        result = analyse_metadata(path)
        self.assertIn("Adobe Photoshop", result["metrics"]["editors"])
        self.assertGreaterEqual(result["score"], 30)
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Editing or processing software recorded", titles)

    def test_ai_generator_metadata_is_flagged(self) -> None:
        path = make_jpeg(self.tmp / "ai.jpg", software="Stable Diffusion / ComfyUI")
        result = analyse_metadata(path)
        self.assertIn("Stable Diffusion", result["metrics"]["generators"])
        self.assertGreaterEqual(result["score"], 60)
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Generative-AI metadata detected", titles)

    def test_date_mismatch_is_flagged(self) -> None:
        path = make_jpeg(
            self.tmp / "date.jpg",
            original="2026:09:10 10:00:00",
            modified="2026:09:10 12:00:00",
        )
        result = analyse_metadata(path)
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("DateTime differs from DateTimeOriginal", titles)
        self.assertGreaterEqual(result["score"], 25)

    def test_future_date_is_flagged(self) -> None:
        path = make_jpeg(self.tmp / "future.jpg", original="2035:01:01 00:00:00")
        result = analyse_metadata(path)
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Capture timestamp is in the future", titles)

    def test_parse_datetime_variants(self) -> None:
        self.assertEqual(str(parse_datetime("2026:09:10 16:42:11")), "2026-09-10 16:42:11")
        self.assertEqual(str(parse_datetime("2026-09-10 16:42:11")), "2026-09-10 16:42:11")
        self.assertIsNone(parse_datetime("not a date"))

    def test_corrupt_file_returns_structured_error(self) -> None:
        path = self.tmp / "corrupt.jpg"
        path.write_text("not an image")
        result = analyse_metadata(path)
        self.assertEqual(result["status"], "error")
        self.assertTrue(any(item["severity"] == "critical" for item in result["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
