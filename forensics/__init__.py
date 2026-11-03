"""Shared, UI-independent helpers for the forensics package."""

from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}


def finding(
    severity: str,
    title: str,
    detail: str,
    confidence: float = 0.8,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Create one standard finding consumed by the verdict and PDF modules.

    Keeping findings in one shape means every module can be displayed by the
    same Streamlit component and scored by the same verdict function.
    """
    severity = severity if severity in SEVERITY_ORDER else "info"
    return {
        "severity": severity,
        "title": title,
        "detail": detail,
        "confidence": round(max(0.05, min(0.99, confidence)), 2),
        "tags": tags or [],
    }


def module_result(
    module: str,
    *,
    status: str = "ok",
    summary: str = "",
    findings: list[dict[str, Any]] | None = None,
    metrics: dict[str, Any] | None = None,
    artifacts: list[str] | None = None,
    score: float = 0.0,
) -> dict[str, Any]:
    """Uniform return value for every analyzer.

    ``score`` is this module's own 0-100 manipulation signal.  It is *not* the
    final verdict; ``verdict.py`` combines scores and findings later.
    """
    return {
        "module": module,
        "status": status,
        "summary": summary,
        "score": round(max(0.0, min(100.0, score)), 1),
        "findings": sorted(findings or [], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9)),
        "metrics": metrics or {},
        "artifacts": artifacts or [],
    }
