#!/usr/bin/env bash
# PixelProof — one command -> PDF report for one image (Linux / macOS).
#
# Runs the analysis models that exist in this build (file analysis,
# EXIF / metadata and Error Level Analysis), writes a PDF evidence report and
# prints its path. It does not launch a viewer.
#
# Usage:
#   ./report.sh samples/tampered/spliced_demo.jpg
#   ./report.sh photo.jpg --examiner "Sagar" -o /tmp/evidence.pdf
#
# Windows: use report.bat instead (same arguments).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer the project virtual environment, fall back to the system interpreter.
if [[ -x "$HERE/.venv/bin/python" ]]; then
    PY="$HERE/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PY="$(command -v python)"
else
    echo "error: no Python interpreter found (create .venv first)" >&2
    exit 2
fi

exec "$PY" "$HERE/report.py" "$@"
