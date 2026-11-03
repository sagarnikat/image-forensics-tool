"""PixelProof - one command -> PDF report for one image.

Cross-platform entry point used by both ``report.sh`` (Linux/macOS) and
``report.bat`` (Windows).  It runs the analysis models that exist in this
build - file analysis, EXIF / metadata and Error Level Analysis - writes the
PDF evidence report and prints its absolute path.  No viewer is launched.

Usage::

    python report.py samples/tampered/spliced_demo.jpg
    python report.py photo.jpg --examiner "Sagar" -o C:\\tmp\\report.pdf

Any extra argument is passed through to the report builder.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the project importable no matter which directory the script is run from.
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from forensics.report import _print_summary, generate_report  # noqa: E402
from utils import config  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in {"-h", "--help"}:
        print("usage: python report.py <image> [extra options]", file=sys.stderr)
        print("       python report.py samples/tampered/spliced_demo.jpg", file=sys.stderr)
        print()
        print("extra options are forwarded to `python -m forensics.report`:", file=sys.stderr)
        print("  -o PATH            PDF path or directory", file=sys.stderr)
        print("  --examiner NAME    examiner printed on the report", file=sys.stderr)
        print("  --case-id ID       override the generated case id", file=sys.stderr)
        return 0 if args else 2

    # Parse only what this wrapper needs; the rest goes to the report builder.
    image = None
    passthrough: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-o", "--output"}:
            if index + 1 >= len(args):
                print(f"error: {token} needs a value", file=sys.stderr)
                return 2
            passthrough.extend([token, args[index + 1]])
            index += 2
            continue
        if token in {"--examiner", "--case-id"}:
            if index + 1 >= len(args):
                print(f"error: {token} needs a value", file=sys.stderr)
                return 2
            passthrough.extend([token, args[index + 1]])
            index += 2
            continue
        if token.startswith("-") and token != "-":
            print(f"error: unknown option: {token}", file=sys.stderr)
            return 2
        if image is not None:
            print(f"error: only one image can be examined at a time: {token}", file=sys.stderr)
            return 2
        image = token
        index += 1

    if image is None:
        print("error: no image given", file=sys.stderr)
        return 2

    # Pull known options back out of the passthrough list.
    options = {"output": None, "examiner": "", "case_id": None}
    pointer = 0
    while pointer < len(passthrough):
        token = passthrough[pointer]
        value = passthrough[pointer + 1]
        if token in {"-o", "--output"}:
            options["output"] = value
        elif token == "--examiner":
            options["examiner"] = value
        elif token == "--case-id":
            options["case_id"] = value
        pointer += 2

    config.ensure_dirs()

    try:
        facts = generate_report(
            image,
            output_path=options["output"],
            examiner=options["examiner"],
            case_id=options["case_id"],
            include_optional=False,  # existing models only
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - surface a clean command-line error
        print(f"error: report could not be generated: {exc}", file=sys.stderr)
        return 2

    _print_summary(facts, None)  # None = viewer not requested
    print(f"PDF: {Path(facts['path']).resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
