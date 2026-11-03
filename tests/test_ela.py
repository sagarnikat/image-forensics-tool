"""Unit tests for Module 3 (Error Level Analysis)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

from forensics.ela import analyse_ela, block_grid, density_map

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "samples" / "original" / "original_demo.jpg"
SPLICED = ROOT / "samples" / "tampered" / "spliced_demo.jpg"
METADATA_EDIT = ROOT / "samples" / "tampered" / "edited_metadata.jpg"

# The foreign patch in samples/tampered/spliced_demo.jpg.
SPLICE_BOX = (160, 120, 460, 340)


def _overlap(first: list[int], second: tuple[int, int, int, int]) -> float:
    """Intersection-over-union for two (x0, y0, x1, y1) boxes."""
    x0 = max(first[0], second[0])
    y0 = max(first[1], second[1])
    x1 = min(first[2], second[2])
    y1 = min(first[3], second[3])
    if x1 <= x0 or y1 <= y0:
        return 0.0
    intersection = (x1 - x0) * (y1 - y0)
    area_first = (first[2] - first[0]) * (first[3] - first[1])
    area_second = (second[2] - second[0]) * (second[3] - second[1])
    return intersection / float(area_first + area_second - intersection)


class ElaTests(unittest.TestCase):
    def test_clean_sample_scores_low(self) -> None:
        result = analyse_ela(CLEAN)
        self.assertEqual(result["status"], "ok")
        self.assertLess(result["score"], 20.0)
        self.assertEqual(result["metrics"]["clusters"], [])
        self.assertFalse(any(item["severity"] in ("high", "medium") for item in result["findings"]))

    def test_spliced_sample_is_detected(self) -> None:
        result = analyse_ela(SPLICED)
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(result["score"], 50.0)
        clusters = result["metrics"]["clusters"]
        self.assertTrue(clusters)
        self.assertTrue(any(_overlap(item["pixel_bbox"], SPLICE_BOX) > 0.35 for item in clusters))
        self.assertTrue(any(item["severity"] == "high" for item in result["findings"]))
        self.assertGreaterEqual(clusters[0]["bbox_mean_residual"], 0.70)
        self.assertGreaterEqual(clusters[0]["contrast"], 2.0)

    def test_artifacts_are_written(self) -> None:
        result = analyse_ela(SPLICED)
        artifacts = [Path(item) for item in result["artifacts"]]
        self.assertEqual(len(artifacts), 3)
        for path in artifacts:
            self.assertTrue(path.exists(), path)
            self.assertGreater(path.stat().st_size, 0)
            with Image.open(path) as image:
                image.verify()

    def test_metadata_only_edit_does_not_raise_ela(self) -> None:
        result = analyse_ela(METADATA_EDIT)
        self.assertEqual(result["status"], "ok")
        self.assertLess(result["score"], 20.0)
        self.assertEqual(result["metrics"]["clusters"], [])

    def test_corrupt_file_returns_structured_error(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="ifx-ela-"))
        try:
            path = tmp / "corrupt.jpg"
            path.write_text("not an image")
            result = analyse_ela(path)
            self.assertEqual(result["status"], "error")
            self.assertTrue(any(item["severity"] == "critical" for item in result["findings"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_block_grid_and_density_map(self) -> None:
        values = np.arange(16, dtype=np.float32).reshape(4, 4)
        grid = block_grid(values, 2)
        self.assertEqual(grid.shape, (2, 2))
        np.testing.assert_allclose(grid, [[2.5, 4.5], [10.5, 12.5]])

        mask = np.zeros((10, 10), dtype=bool)
        mask[4:7, 4:7] = True
        density = density_map(mask, 3)
        self.assertAlmostEqual(float(density[5, 5]), 1.0)
        self.assertAlmostEqual(float(density[0, 0]), 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
