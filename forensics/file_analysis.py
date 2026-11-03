"""Module 1 - File analysis and integrity.

Forensic concepts
-----------------
* **Hash digest**: a one-way fingerprint of the exact bytes.  MD5/SHA-1 are
  kept for compatibility with older case-management systems; SHA-256 is the
  value to quote in court.  Re-hashing later proves the file did not change.
* **Magic bytes**: the first few bytes identify the real container regardless
  of the filename.  Attackers rename ``malware.exe`` to ``holiday.jpg``; a
  mismatch between magic and extension is therefore a red flag.
* **Timestamps**: filesystem times are volatile and easy to change.  They are
  supporting context, never proof on their own.

The module only reads the evidence.  It never writes to the input path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forensics import finding, module_result
from utils import config
from utils.image_utils import ImageLoadError, human_bytes, load_image

READ_CHUNK = 1024 * 1024

# (container, signature, accepted extensions) - order matters for short prefixes.
MAGIC_SIGNATURES: tuple[tuple[str, bytes, set[str]], ...] = (
    ("JPEG", b"\xff\xd8\xff", {".jpg", ".jpeg", ".jpe", ".jfif"}),
    ("PNG", b"\x89PNG\r\n\x1a\n", {".png"}),
    ("GIF", b"GIF87a", {".gif"}),
    ("GIF", b"GIF89a", {".gif"}),
    ("BMP", b"BM", {".bmp"}),
    ("TIFF", b"II*\x00", {".tif", ".tiff"}),
    ("TIFF", b"MM\x00*", {".tif", ".tiff"}),
    ("ICO", b"\x00\x00\x01\x00", {".ico"}),
    ("PSD", b"8BPS", {".psd"}),
)


def compute_hashes(path: str | Path) -> dict[str, str]:
    """Return MD5, SHA-1 and SHA-256 of the file, streamed in 1 MiB blocks.

    Streaming keeps memory flat even for large evidence files and mirrors how
    forensic imaging tools hash a disk.
    """
    hashers = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as handle:
        while True:
            block = handle.read(READ_CHUNK)
            if not block:
                break
            for hasher in hashers.values():
                hasher.update(block)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def detect_container(head: bytes) -> dict[str, Any] | None:
    """Identify the real container from its first bytes.

    Returns ``None`` for unknown data.  WEBP and HEIF need a two-part check
    because their signatures are not at offset 0.
    """
    for name, signature, extensions in MAGIC_SIGNATURES:
        if head.startswith(signature):
            return {"format": name, "extensions": extensions}
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return {"format": "WEBP", "extensions": {".webp"}}
    if head[4:8] == b"ftyp" and head[8:12] in {b"heic", b"heix", b"hevc", b"mif1", b"msf1"}:
        return {"format": "HEIF/HEIC", "extensions": {".heic", ".heif"}}
    return None


def file_timestamps(path: str | Path) -> dict[str, str]:
    """Collect filesystem times in UTC ISO-8601, with platform caveats."""
    stat = os.stat(path)
    ctime_label = "inode_change" if os.name == "posix" else "created"

    def iso(timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

    return {
        "modified": iso(stat.st_mtime),
        "accessed": iso(stat.st_atime),
        ctime_label: iso(stat.st_ctime),
        "ctime_note": (
            "On Linux, ctime is the inode-change time, not the creation time."
            if os.name == "posix"
            else "ctime is the file creation time on this platform."
        ),
    }


def analyse_file(path: str | Path) -> dict[str, Any]:
    """Run Module 1 and always return a serialisable result.

    The function is deliberately non-throwing for bad evidence: the UI and the
    report need a structured error, not a stack trace.
    """
    path = Path(path).expanduser()
    findings: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    score = 0.0

    try:
        stat = path.stat()
    except OSError as exc:
        return module_result(
            "file_analysis",
            status="error",
            summary=f"File cannot be accessed: {exc}",
            findings=[finding("critical", "Evidence file unreadable", str(exc), 0.99)],
            metrics={"path": str(path)},
            score=80.0,
        )

    metrics["path"] = str(path)
    metrics["name"] = path.name
    metrics["size_bytes"] = stat.st_size
    metrics["size_human"] = human_bytes(stat.st_size)
    metrics["timestamps"] = file_timestamps(path)
    metrics["extension"] = path.suffix.lower() or "(none)"

    # Hashes are computed even if decoding fails: the bytes are still evidence.
    try:
        metrics["hashes"] = compute_hashes(path)
    except OSError as exc:
        metrics["hashes"] = {}
        findings.append(finding("high", "Hashing failed", str(exc), 0.9))

    with open(path, "rb") as handle:
        head = handle.read(32)
    container = detect_container(head)
    metrics["magic_format"] = container["format"] if container else None
    metrics["magic_hex"] = head[:12].hex(" ")
    metrics["extension_expected"] = sorted(container["extensions"]) if container else []
    metrics["extension_match"] = (
        path.suffix.lower() in container["extensions"] if container else False
    )
    metrics["double_extension"] = bool(
        re.search(config.DOUBLE_EXTENSION_PATTERN, path.name.lower())
    )

    # ------------------------------------------------------------- decoding
    try:
        loaded = load_image(path)
    except ImageLoadError as exc:
        findings.append(
            finding(
                "critical",
                "Image cannot be decoded",
                f"{exc}. The container may be corrupt, truncated or simply not an image.",
                0.97,
            )
        )
        metrics["decoded"] = False
        return module_result(
            "file_analysis",
            status="error",
            summary=f"Undecodable file · {human_bytes(stat.st_size)} · {metrics['extension']}",
            findings=findings,
            metrics=metrics,
            score=80.0,
        )

    metrics["decoded"] = True
    metrics.update(
        {
            "format": loaded.format,
            "width": loaded.width,
            "height": loaded.height,
            "megapixels": loaded.megapixels,
            "mode": loaded.mode,
            "frames": loaded.frames,
            "lossless": loaded.is_lossless,
            "warnings": loaded.warnings,
        }
    )

    # ------------------------------------------------------------- findings
    if metrics["hashes"]:
        findings.append(
            finding(
                "info",
                "Cryptographic digests computed",
                "SHA-256 " + metrics["hashes"]["sha256"]
                + " · SHA-1 " + metrics["hashes"]["sha1"]
                + " · MD5 " + metrics["hashes"]["md5"],
                0.99,
                ["integrity", "custody"],
            )
        )

    if container is None:
        findings.append(
            finding(
                "medium",
                "Unknown or unsupported file signature",
                f"First bytes are {metrics['magic_hex']}. The extension '{metrics['extension']}' "
                "is not backed by a recognised image signature.",
                0.8,
                ["container"],
            )
        )
        score = max(score, 40.0)
    elif not metrics["extension_match"]:
        findings.append(
            finding(
                "high",
                "Extension does not match the real container",
                f"Content is {container['format']} but the filename ends in "
                f"'{metrics['extension']}'. Renaming is a common concealment technique.",
                0.95,
                ["container", "mismatch"],
            )
        )
        score = max(score, 60.0)

    if container and container["format"] != loaded.format:
        # Pillow may report MPO for multi-picture JPEG; normalise that first.
        if not ({container["format"], loaded.format} <= {"JPEG", "MPO"}):
            findings.append(
                finding(
                    "high",
                    "Container and decoder disagree",
                    f"Magic bytes say {container['format']} while Pillow decoded {loaded.format}. "
                    "This can indicate a polyglot file crafted to be read differently by different tools.",
                    0.85,
                    ["container"],
                )
            )
            score = max(score, 65.0)

    if metrics["double_extension"]:
        findings.append(
            finding(
                "high",
                "Double extension detected",
                f"'{path.name}' ends with an executable/archive extension after an image extension. "
                "This is a classic phishing disguise and must be escalated.",
                0.9,
                ["container", "social-engineering"],
            )
        )
        score = max(score, 75.0)

    if loaded.warnings:
        for warning in loaded.warnings:
            findings.append(finding("low", "Container warning", warning, 0.7, ["container"]))

    if stat.st_size < 1024:
        findings.append(
            finding(
                "low",
                "Unusually small image file",
                f"Only {human_bytes(stat.st_size)}. It may be a thumbnail or a heavily stripped file.",
                0.5,
                ["container"],
            )
        )

    if not findings or all(item["severity"] == "info" for item in findings):
        findings.append(
            finding(
                "info",
                "Filename and signature are consistent",
                f"{loaded.format} content, {loaded.width}×{loaded.height}, extension "
                f"'{metrics['extension']}' accepted.",
                0.95,
                ["container"],
            )
        )

    summary = (
        f"{loaded.format} · {loaded.width}×{loaded.height} · {human_bytes(stat.st_size)} · "
        + ("signature/extension match" if metrics["extension_match"] else "SIGNATURE MISMATCH")
    )
    return module_result(
        "file_analysis",
        status="ok",
        summary=summary,
        findings=findings,
        metrics=metrics,
        score=score,
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Module 1: hashes, magic bytes and basic file facts."
    )
    parser.add_argument("image", help="path to the evidence image")
    parser.add_argument("--json", action="store_true", help="print raw JSON (default: pretty JSON)")
    args = parser.parse_args(argv)

    result = analyse_file(args.image)
    print(json.dumps(result, indent=None if args.json else 2, ensure_ascii=False))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    sys.exit(_main())
