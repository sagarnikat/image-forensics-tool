"""Analysis pipeline - run every available analyzer on one evidence file.

The pipeline is the single entry point shared by the PDF report and (later)
the Streamlit UI, so both always present the same numbers.

Rules
-----
* The evidence file is only read.  Analyzers write derived artifacts under
  ``output/``; the original bytes are never touched.
* A failing analyzer is converted into a structured error result instead of
  aborting the run, so one bad module cannot hide the others.
* Optional modules (copy-move, stego) are picked up automatically when their
  file exists.  While they are still being built they are reported as
  "not available in this build" instead of silently disappearing.
"""

from __future__ import annotations

import importlib
import importlib.util
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from forensics import finding, module_result
from forensics.ela import analyse_ela
from forensics.file_analysis import analyse_file
from forensics.metadata import analyse_metadata
from forensics.verdict import MODULE_LABELS, combine_scores

# name -> callable.  Order is the order results appear in reports.
CORE_ANALYZERS: tuple[tuple[str, Callable[[str | Path], dict[str, Any]]], ...] = (
    ("file_analysis", analyse_file),
    ("metadata", analyse_metadata),
    ("ela", analyse_ela),
)

# name, module path, function name.  Loaded only if the module exists.
OPTIONAL_ANALYZERS: tuple[tuple[str, str, str], ...] = (
    ("copymove", "forensics.copymove", "analyse_copymove"),
    ("stego", "forensics.stego", "analyse_stego"),
)


def _load_optional(module_path: str, function_name: str) -> Callable[..., dict[str, Any]] | None:
    """Return the analyzer callable, or ``None`` when the module is absent."""
    try:
        if importlib.util.find_spec(module_path) is None:
            return None
        module = importlib.import_module(module_path)
    except (ImportError, ValueError):
        return None
    function = getattr(module, function_name, None)
    return function if callable(function) else None


def _failed(name: str, exc: Exception, elapsed: float) -> dict[str, Any]:
    result = module_result(
        name,
        status="error",
        summary=f"Analyzer raised an unexpected error after {elapsed:.2f}s",
        findings=[
            finding(
                "critical",
                "Analyzer failed",
                f"{type(exc).__name__}: {exc}",
                0.99,
                ["pipeline"],
            )
        ],
    )
    return result


def run_pipeline(
    path: str | Path,
    *,
    include_optional: bool = True,
) -> dict[str, Any]:
    """Execute all available analyzers and combine them into a verdict.

    Returns a dictionary with ``results`` (one per module), ``verdict``,
    timing information and the list of modules that were not available.
    """
    path = Path(path)
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()

    analyzers: list[tuple[str, Callable[..., dict[str, Any]]]] = list(CORE_ANALYZERS)
    not_available: list[str] = []

    for name, module_path, function_name in OPTIONAL_ANALYZERS:
        if not include_optional:
            not_available.append(name)
            continue
        function = _load_optional(module_path, function_name)
        if function is None:
            not_available.append(name)
        else:
            analyzers.append((name, function))

    results: list[dict[str, Any]] = []
    timings: dict[str, float] = {}

    for name, function in analyzers:
        module_started = time.perf_counter()
        try:
            result = function(path)
        except Exception as exc:  # noqa: BLE001 - a bad module must not kill the report
            elapsed = time.perf_counter() - module_started
            result = _failed(name, exc, elapsed)
        elapsed = time.perf_counter() - module_started
        timings[name] = round(elapsed, 3)
        # Defensive: guarantee the shared contract even for third-party analyzers.
        result.setdefault("module", name)
        result.setdefault("status", "ok")
        result.setdefault("summary", "")
        result.setdefault("score", 0.0)
        result.setdefault("findings", [])
        result.setdefault("metrics", {})
        result.setdefault("artifacts", [])
        results.append(result)

    verdict = combine_scores(results)
    finished_at = datetime.now(timezone.utc)

    return {
        "path": str(path),
        "name": path.name,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_s": round(time.perf_counter() - started, 3),
        "results": results,
        "verdict": verdict,
        "timings": timings,
        "available": [item["module"] for item in results],
        "not_available": not_available,
        "module_labels": MODULE_LABELS,
    }
