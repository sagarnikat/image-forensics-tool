"""Unit tests for the verdict aggregation (Module 6, part 1)."""

from __future__ import annotations

import unittest

from forensics import finding, module_result
from forensics.verdict import combine_scores


def result(name: str, score: float, *, status: str = "ok",
           findings: list[dict] | None = None) -> dict:
    return module_result(name, status=status, summary=f"{name} summary",
                         score=score, findings=findings or [])


class VerdictTests(unittest.TestCase):
    def test_clean_image_is_likely_authentic(self) -> None:
        verdict = combine_scores([
            result("file_analysis", 0.0),
            result("metadata", 0.0),
            result("ela", 0.0),
        ])
        self.assertEqual(verdict["band"], "authentic")
        self.assertEqual(verdict["score"], 0.0)
        self.assertEqual(verdict["label"], "Likely authentic")
        self.assertFalse(verdict["escalated"])
        self.assertTrue(verdict["evaluated"])

    def test_strong_ela_signal_reaches_tampered_band(self) -> None:
        verdict = combine_scores([
            result("file_analysis", 0.0),
            result("metadata", 0.0),
            result("ela", 84.3),
        ])
        self.assertEqual(verdict["band"], "tampered")
        self.assertGreaterEqual(verdict["score"], 50.0)
        self.assertEqual(verdict["strongest"]["module"], "ela")
        self.assertTrue(any("ELA" in line or "Error Level" in line
                            for line in verdict["supporting"]))

    def test_single_medium_signal_is_escalated_out_of_authentic(self) -> None:
        # Metadata-only edit: 30/100 from one module.  The blended score would
        # be below 20, but a supporting signal must not read as authentic.
        verdict = combine_scores([
            result("file_analysis", 0.0),
            result("metadata", 30.0),
            result("ela", 0.0),
        ])
        self.assertEqual(verdict["band"], "suspicious")
        self.assertEqual(verdict["score"], 20.0)
        self.assertTrue(verdict["escalated"])
        self.assertTrue(verdict["escalations"])

    def test_high_severity_finding_forces_review_band(self) -> None:
        verdict = combine_scores([
            result("file_analysis", 10.0, findings=[
                finding("high", "Extension mismatch", "JPEG named .png", 0.95)
            ]),
        ])
        self.assertGreaterEqual(verdict["score"], 20.0)
        self.assertNotEqual(verdict["band"], "authentic")

    def test_all_errors_is_inconclusive(self) -> None:
        verdict = combine_scores([
            result("file_analysis", 80.0, status="error"),
            result("metadata", 0.0, status="error"),
            result("ela", 0.0, status="error"),
        ])
        self.assertEqual(verdict["band"], "inconclusive")
        self.assertEqual(verdict["confidence"], 0.0)
        self.assertEqual(verdict["evaluated"], [])
        self.assertEqual(len(verdict["errors"]), 3)
        self.assertIsNone(verdict["strongest"])

    def test_weights_are_renormalised_over_available_modules(self) -> None:
        verdict = combine_scores([
            result("file_analysis", 0.0),
            result("metadata", 30.0),
            result("ela", 0.0),
        ])
        self.assertAlmostEqual(sum(verdict["weights_used"].values()), 1.0, places=2)
        self.assertAlmostEqual(verdict["weights_used"]["metadata"], 0.36, places=2)
        self.assertAlmostEqual(verdict["weighted"], 10.9, places=1)

    def test_error_modules_are_reported_separately(self) -> None:
        verdict = combine_scores([
            result("file_analysis", 0.0),
            result("metadata", 0.0, status="error"),
            result("ela", 60.0),
        ])
        self.assertEqual(verdict["skipped"], ["metadata"])
        self.assertEqual(len(verdict["errors"]), 1)
        self.assertEqual(verdict["module_scores"]["ela"], 60.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
