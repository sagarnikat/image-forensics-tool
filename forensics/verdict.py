"""Module 6 (part 1) - combine analyzer results into one defensible verdict.

Design notes
------------
* A pure weighted average hides a strong single signal while only a few
  modules exist (copy-move and stego are still being added).  The final score
  therefore blends the weighted consensus with the strongest module score::

      weighted = sum(weight_i * score_i) / sum(weight_i)     (modules that ran)
      final    = 0.55 * weighted + 0.45 * strongest

  The weights sum to 1.0 for the full five-module design, but they are
  re-normalised over the modules that actually ran, so a partial pipeline
  still produces a meaningful number instead of a capped one.

* The verdict is a **triage label**, never a legal conclusion.  Supporting
  and contradicting evidence are always returned next to it, and a single
  high-severity finding is never allowed to report as "likely authentic".

The module has no side effects and no file I/O.  It only reads analyzer
results, which makes it trivial to unit-test.
"""

from __future__ import annotations

from typing import Any, Iterable

from utils import config

MODULE_LABELS = {
    "file_analysis": "File analysis & integrity",
    "metadata": "Metadata / EXIF",
    "ela": "Error Level Analysis",
    "copymove": "Copy-move detection",
    "stego": "Steganography checks",
}

BAND_LABELS = {
    "authentic": "Likely authentic",
    "suspicious": "Suspicious",
    "tampered": "Likely tampered",
    "inconclusive": "Inconclusive",
}

HEADLINES = {
    "authentic": "No module produced a strong tampering signal.",
    "suspicious": "At least one signal warrants examiner review.",
    "tampered": "A strong forensic signal is consistent with tampering; corroborate before concluding.",
    "inconclusive": "One or more modules could not analyse the evidence.",
}


def _severity_counts(results: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for result in results:
        for item in result.get("findings", []):
            severity = item.get("severity", "info")
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def _band(score: float) -> str:
    if score >= config.VERDICT_THRESHOLDS["suspicious"]:
        return "tampered"
    if score >= config.VERDICT_THRESHOLDS["authentic"]:
        return "suspicious"
    return "authentic"


def combine_scores(
    results: list[dict[str, Any]],
    *,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Aggregate module results into a verdict dictionary.

    Parameters
    ----------
    results:
        Standard module results (``module``, ``status``, ``score`` ...).
    weights:
        Optional override of :data:`utils.config.MODULE_WEIGHTS`.
    """
    weights = dict(weights or config.MODULE_WEIGHTS)
    counts = _severity_counts(results)
    evaluated = [item for item in results if item.get("status") == "ok"]
    skipped = [item["module"] for item in results if item.get("status") != "ok"]

    module_scores = {
        item["module"]: round(float(item.get("score", 0.0)), 1) for item in evaluated
    }
    errors = [
        {
            "module": item["module"],
            "summary": item.get("summary", "analysis failed"),
        }
        for item in results
        if item.get("status") != "ok"
    ]

    if not evaluated:
        return {
            "score": 0.0,
            "band": "inconclusive",
            "label": BAND_LABELS["inconclusive"],
            "headline": HEADLINES["inconclusive"],
            "confidence": 0.0,
            "weighted": 0.0,
            "strongest": None,
            "agreement": 0.0,
            "module_scores": {},
            "weights_used": {},
            "severity_counts": counts,
            "supporting": [],
            "contradicting": [],
            "errors": errors,
            "evaluated": [],
            "skipped": skipped,
            "escalated": False,
            "escalations": [],
        }

    total_weight = sum(max(0.0, weights.get(item["module"], 0.1)) for item in evaluated)
    total_weight = total_weight or 1.0
    weights_used = {
        item["module"]: round(max(0.0, weights.get(item["module"], 0.1)) / total_weight, 3)
        for item in evaluated
    }
    weighted = sum(
        max(0.0, weights.get(item["module"], 0.1)) * float(item.get("score", 0.0))
        for item in evaluated
    ) / total_weight
    strongest_item = max(evaluated, key=lambda item: float(item.get("score", 0.0)))
    strongest = float(strongest_item.get("score", 0.0))

    score = (
        config.VERDICT_BLEND["weighted"] * weighted
        + config.VERDICT_BLEND["strongest"] * strongest
    )
    # Guard-rails: a real signal must never be reported as "likely authentic".
    # 1. A high-severity finding always reaches the review band.
    # 2. Any module that crossed the review threshold is a supporting signal,
    #    so a sub-20 blended score cannot stay in the authentic band.
    escalations: list[str] = []
    review_floor = float(config.VERDICT_THRESHOLDS["authentic"])
    if counts.get("high", 0) and score < review_floor:
        score = review_floor
        escalations.append(
            "A high-severity finding is present, so the score was raised to the review band."
        )
    if score < review_floor and any(value >= review_floor for value in module_scores.values()):
        score = review_floor
        escalations.append(
            "At least one module crossed the review threshold, so the blended score was "
            "raised to the review band instead of reporting the image as likely authentic."
        )
    score = round(max(0.0, min(100.0, score)), 1)

    band = _band(score)

    # Confidence rewards module coverage and agreement between modules.
    coverage = len(evaluated) / max(1, len(results))
    if len(evaluated) > 1:
        spread = (strongest - min(module_scores.values())) / 100.0
        agreement = 1.0 - min(1.0, spread)
    else:
        agreement = 0.5
    confidence = round(min(0.98, 0.30 + 0.40 * coverage + 0.28 * agreement), 2)

    supporting: list[str] = []
    contradicting: list[str] = []
    for item in sorted(evaluated, key=lambda entry: float(entry.get("score", 0.0)), reverse=True):
        label = MODULE_LABELS.get(item["module"], item["module"])
        line = f"{label} scored {float(item.get('score', 0.0)):.1f}/100 - {item.get('summary', '')}".strip()
        if float(item.get("score", 0.0)) >= config.VERDICT_THRESHOLDS["authentic"]:
            supporting.append(line)
        else:
            contradicting.append(line)

    return {
        "score": score,
        "band": band,
        "label": BAND_LABELS[band],
        "headline": HEADLINES[band],
        "confidence": confidence,
        "weighted": round(weighted, 1),
        "strongest": {
            "module": strongest_item["module"],
            "label": MODULE_LABELS.get(strongest_item["module"], strongest_item["module"]),
            "score": round(strongest, 1),
        },
        "agreement": round(agreement, 2),
        "escalated": bool(escalations),
        "escalations": escalations,
        "module_scores": module_scores,
        "weights_used": weights_used,
        "severity_counts": counts,
        "supporting": supporting,
        "contradicting": contradicting,
        "errors": errors,
        "evaluated": [item["module"] for item in evaluated],
        "skipped": skipped,
    }
