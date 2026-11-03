"""Module 2 - EXIF / metadata analysis.

Forensic concepts
-----------------
* **EXIF** is a TIFF-style metadata block written by cameras and phones.  It
  can contain camera identity, lens, capture time, GPS, orientation and an
  embedded thumbnail.  It is useful corroboration, but it is also trivial to
  edit or strip, so it is a *lead*, not proof.
* **Timestamp coherence**: cameras write ``DateTimeOriginal`` at capture,
  ``DateTimeDigitized`` when the file is written, and ``DateTime`` when the
  tag block is last changed.  Editors often update only one of them.  A
  mismatch, a future date, or a file modified days after capture is worth
  explaining.
* **GPS**: EXIF stores latitude/longitude as three rationals (degrees, minutes,
  seconds) plus N/S and E/W references.  Converting to decimal gives a map
  link and a location anchor.  A reverse-geocoded place name is intentionally
  *not* requested online; the tool stays offline and provides the OSM link.
* **Embedded thumbnail**: many cameras store a small preview.  If the preview
  no longer resembles the full image, the main image was probably replaced or
  edited after the camera wrote the file.

The original evidence file is never modified.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import exifread
import numpy as np
from PIL import Image

from forensics import finding, module_result
from utils import config
from utils.image_utils import ImageLoadError, load_image, safe_name

# Software that indicates post-processing rather than a camera firmware.
EDITOR_KEYWORDS: dict[str, str] = {
    "photoshop": "Adobe Photoshop",
    "lightroom": "Adobe Lightroom",
    "camera raw": "Adobe Camera Raw",
    "gimp": "GIMP",
    "paint.net": "Paint.NET",
    "pixlr": "Pixlr",
    "snapseed": "Snapseed",
    "picsart": "PicsArt",
    "canva": "Canva",
    "pixelmator": "Pixelmator",
    "affinity": "Affinity Photo",
    "capture one": "Capture One",
    "darktable": "darktable",
    "rawtherapee": "RawTherapee",
    "facetune": "Facetune",
    "meitu": "Meitu",
    "vsco": "VSCO",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
}

# Metadata written by generative models or AI editing tools.
AI_KEYWORDS: dict[str, str] = {
    "midjourney": "Midjourney",
    "dall-e": "DALL·E",
    "dall·e": "DALL·E",
    "stable diffusion": "Stable Diffusion",
    "stablediffusion": "Stable Diffusion",
    "comfyui": "ComfyUI",
    "automatic1111": "AUTOMATIC1111",
    "invokeai": "InvokeAI",
    "firefly": "Adobe Firefly",
    "leonardo.ai": "Leonardo AI",
    "leonardo": "Leonardo AI",
    "flux.1": "FLUX",
    "generative fill": "Generative Fill",
    "trainedalgorithmicmedia": "C2PA trained algorithmic media",
    "compositewithtrainedalgorithmicmedia": "C2PA composite with AI media",
    "ai-generated": "AI-generated content",
}

DATE_KEYS = ("DateTimeOriginal", "DateTimeDigitized", "DateTime")
SKIP_TAG_PARTS = ("thumbnail", "makernote", "applicationnotes")


def _text(tag: Any) -> str:
    """Convert an exifread IfdTag into a printable string."""
    if tag is None:
        return ""
    return str(tag).strip()


def _values(tag: Any) -> list[Any]:
    if tag is None:
        return []
    values = getattr(tag, "values", None)
    if values is None:
        return []
    if isinstance(values, (list, tuple)):
        return list(values)
    return [values]


def _number(value: Any) -> float:
    """Convert int / float / bytes / exifread Ratio into a float."""
    if isinstance(value, (bytes, bytearray)):
        return float(value[0]) if value else 0.0
    if hasattr(value, "num") and hasattr(value, "den"):
        return float(value.num) / float(value.den) if value.den else 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _matches(text: str, keyword: str) -> bool:
    """Word-aware keyword match, with a safe fallback for punctuation."""
    if not text:
        return False
    if not keyword.replace(" ", "").isalnum():
        return keyword in text
    return re.search(rf"\b{re.escape(keyword)}\b", text) is not None


def extract_exif_tags(path: str | Path) -> dict[str, Any]:
    """Read all EXIF tags with exifread.

    ``details=False`` skips the expensive MakerNote walk; ``strict=False``
    keeps going when a camera writes a malformed tag, which is common.
    """
    tags: dict[str, Any] = {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with open(path, "rb") as handle:
                tags = exifread.process_file(handle, details=False, strict=False)
    except (OSError, ValueError, TypeError):
        return {}
    return tags or {}


def tag_dict(tags: dict[str, Any]) -> dict[str, str]:
    """Serialisable, size-limited tag dump for the report."""
    output: dict[str, str] = {}
    for key in sorted(tags):
        lowered = key.lower()
        if any(part in lowered for part in SKIP_TAG_PARTS):
            continue
        value = _text(tags[key])
        if not value:
            continue
        output[key] = value[:300]
        if len(output) >= 150:
            break
    return output


def parse_gps(tags: dict[str, Any]) -> dict[str, Any] | None:
    """Convert EXIF GPS rationals into decimal coordinates and an OSM link."""
    lat_tag = tags.get("GPS GPSLatitude")
    lon_tag = tags.get("GPS GPSLongitude")
    if lat_tag is None or lon_tag is None:
        return None

    lat_values = [_number(item) for item in _values(lat_tag)[:3]]
    lon_values = [_number(item) for item in _values(lon_tag)[:3]]
    if len(lat_values) != 3 or len(lon_values) != 3:
        return None

    lat_ref = (_text(tags.get("GPS GPSLatitudeRef")) or "N").upper()[:1]
    lon_ref = (_text(tags.get("GPS GPSLongitudeRef")) or "E").upper()[:1]
    lat = lat_values[0] + lat_values[1] / 60.0 + lat_values[2] / 3600.0
    lon = lon_values[0] + lon_values[1] / 60.0 + lon_values[2] / 3600.0
    if lat_ref == "S":
        lat = -lat
    if lon_ref == "W":
        lon = -lon

    altitude = None
    alt_tag = tags.get("GPS GPSAltitude")
    if alt_tag is not None and _values(alt_tag):
        altitude = _number(_values(alt_tag)[0])
        ref_values = _values(tags.get("GPS GPSAltitudeRef"))
        if ref_values and _number(ref_values[0]) != 0:
            altitude = -altitude

    utc = None
    time_values = [_number(item) for item in _values(tags.get("GPS GPSTimeStamp"))[:3]]
    gps_date = _text(tags.get("GPS GPSDate"))
    if len(time_values) == 3 and gps_date:
        utc = (
            f"{gps_date} {int(time_values[0]):02d}:{int(time_values[1]):02d}:"
            f"{int(round(time_values[2])):02d}Z"
        )

    def dms(parts: list[float], reference: str) -> str:
        return f"{int(parts[0])}°{int(parts[1])}'{parts[2]:04.1f}\"{reference}"

    return {
        "latitude": round(lat, 6),
        "longitude": round(lon, 6),
        "latitude_dms": dms(lat_values, lat_ref),
        "longitude_dms": dms(lon_values, lon_ref),
        "location_text": (
            f"{abs(lat):.6f}° {lat_ref}, {abs(lon):.6f}° {lon_ref}"
        ),
        "altitude_m": round(altitude, 1) if altitude is not None else None,
        "utc": utc,
        "map_url": f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}",
    }


def parse_datetime(value: Any) -> datetime | None:
    """Parse the EXIF ``YYYY:MM:DD HH:MM:SS`` format (and common variants)."""
    text = _text(value).replace("\x00", "")
    if not text:
        return None
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            continue
    return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def extract_xmp(path: str | Path) -> str:
    """Find the XMP packet in JPEG APP1 or a PNG text/iTXt chunk."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return ""
    start = raw.find(b"<x:xmpmeta")
    if start == -1:
        start = raw.find(b"<?xpacket")
    if start == -1:
        return ""
    end = raw.find(b"</x:xmpmeta>", start)
    if end == -1:
        end = raw.find(b"<?xpacket end", start)
    chunk = raw[start : end + 40 if end != -1 else start + 200_000]
    return chunk.decode("utf-8", "replace")[:200_000]


def parse_xmp(text: str) -> dict[str, str]:
    """Extract the XMP properties that matter for provenance."""
    if not text:
        return {}
    properties: dict[str, str] = {}
    for match in re.finditer(r'([A-Za-z0-9_]+:[A-Za-z0-9_]+)\s*=\s*"([^"]{0,400})"', text):
        properties.setdefault(match.group(1), match.group(2))
    for match in re.finditer(r"<([A-Za-z0-9_]+:[A-Za-z0-9_]+)[^>]*>([^<]{1,400})</\1>", text):
        properties.setdefault(match.group(1), match.group(2).strip())
    return dict(list(properties.items())[:60])


def png_text(image: Image.Image) -> dict[str, str]:
    """Collect PNG text chunks that often carry editor or AI parameters."""
    skip = {"exif", "icc_profile", "jfif", "jfif_version", "jfif_unit", "jfif_density", "adobe", "adobe_transform", "dpi"}
    output: dict[str, str] = {}
    for key, value in image.info.items():
        if not isinstance(value, str) or key.lower() in skip:
            continue
        if 0 < len(value) <= 2000:
            output[str(key)] = value
        if len(output) >= 30:
            break
    return output


def _read_ifd_next(blob: bytes, offset: int, endian: str) -> tuple[dict[int, int], int]:
    """Read numeric IFD entries and the next-IFD pointer from a TIFF block."""
    entries: dict[int, int] = {}
    if offset <= 0 or offset + 2 > len(blob):
        return entries, 0
    count = struct.unpack_from(endian + "H", blob, offset)[0]
    position = offset + 2
    for _ in range(min(count, 512)):
        if position + 12 > len(blob):
            break
        tag, kind, number = struct.unpack_from(endian + "HHI", blob, position)
        field = blob[position + 8 : position + 12]
        if kind in (3, 4) and number == 1:
            fmt = "H" if kind == 3 else "I"
            entries[tag] = struct.unpack(endian + fmt, field)[0]
        position += 12
    try:
        next_offset = struct.unpack_from(endian + "I", blob, position)[0]
    except struct.error:
        next_offset = 0
    return entries, next_offset


def extract_exif_thumbnail(path: str | Path) -> bytes:
    """Extract the JPEG preview stored in EXIF IFD1 (tags 0x0201/0x0202)."""
    try:
        with Image.open(path) as image:
            blob = image.info.get("exif", b"")
    except OSError:
        return b""
    if not blob:
        return b""
    base = 6 if blob[:6] == b"Exif\x00\x00" else 0
    tiff = blob[base:]
    if len(tiff) < 8:
        return b""
    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return b""
    try:
        magic, ifd0_offset = struct.unpack_from(endian + "HI", tiff, 2)
    except struct.error:
        return b""
    if magic != 42:
        return b""
    _, ifd1_offset = _read_ifd_next(tiff, ifd0_offset, endian)
    if not ifd1_offset:
        return b""
    ifd1, _ = _read_ifd_next(tiff, ifd1_offset, endian)
    offset = ifd1.get(0x0201)
    length = ifd1.get(0x0202)
    if not offset or not length or length > 2_000_000:
        return b""
    return tiff[offset : offset + length]


def dhash(image: Image.Image, size: int = 8) -> str:
    """64-bit difference hash: robust to resizing and mild recompression."""
    gray = np.asarray(
        image.convert("L").resize((size + 1, size), Image.Resampling.LANCZOS),
        dtype=np.int16,
    )
    bits = (gray[:, 1:] > gray[:, :-1]).reshape(-1)
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return f"{value:0{len(bits) // 4}x}"


def compare_thumbnail(path: str | Path, main_image: Image.Image) -> dict[str, Any]:
    """Compare the embedded preview with the full image using dHash."""
    blob = extract_exif_thumbnail(path)
    if not blob:
        return {"present": False}
    try:
        import io

        preview = Image.open(io.BytesIO(blob)).convert("RGB")
    except Exception:  # noqa: BLE001 - preview is untrusted camera data
        return {"present": True, "error": "thumbnail could not be decoded", "bytes": len(blob)}

    distance = (int(dhash(main_image), 16) ^ int(dhash(preview), 16)).bit_count()
    config.METADATA_DIR.mkdir(parents=True, exist_ok=True)
    artifact = config.METADATA_DIR / f"thumb_{safe_name(Path(path).stem)}.png"
    preview.save(artifact, "PNG")
    return {
        "present": True,
        "width": preview.width,
        "height": preview.height,
        "bytes": len(blob),
        "dhash_distance": distance,
        "match": distance <= 16,
        "artifact": str(artifact),
    }


def analyse_metadata(path: str | Path) -> dict[str, Any]:
    """Run Module 2 and return the standard module result."""
    path = Path(path)
    try:
        loaded = load_image(path)
    except ImageLoadError as exc:
        return module_result(
            "metadata",
            status="error",
            summary=f"Metadata could not be read: {exc}",
            findings=[finding("critical", "Image cannot be decoded", str(exc), 0.97)],
            score=0.0,
        )

    tags = extract_exif_tags(path)
    dump = tag_dict(tags)
    camera = {
        "make": _text(tags.get("Image Make")),
        "model": _text(tags.get("Image Model")),
        "lens": _text(tags.get("EXIF LensModel")),
        "serial": _text(tags.get("EXIF BodySerialNumber")),
        "software": _text(tags.get("Image Software")),
        "artist": _text(tags.get("Image Artist")),
        "copyright": _text(tags.get("Image Copyright")),
    }
    camera = {key: value for key, value in camera.items() if value}

    gps = parse_gps(tags)
    xmp_text = extract_xmp(path)
    xmp = parse_xmp(xmp_text)
    png_meta = png_text(loaded.image)

    timestamps: dict[str, Any] = {}
    parsed_dates: dict[str, datetime | None] = {}
    for key in DATE_KEYS:
        value = parse_datetime(tags.get(f"EXIF {key}") or tags.get(f"Image {key}"))
        parsed_dates[key] = value
        if value:
            timestamps[key] = _iso(value)
    for key in ("OffsetTimeOriginal", "OffsetTimeDigitized", "OffsetTime"):
        value = _text(tags.get(f"EXIF {key}"))
        if value:
            timestamps[key] = value

    try:
        fs_modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).replace(tzinfo=None)
        timestamps["FileModified"] = fs_modified.isoformat()
    except OSError:
        fs_modified = None

    software_text = " ".join(
        [str(value) for value in camera.values()]
        + [f"{key}={value}" for key, value in xmp.items()]
        + [f"{key}={value}" for key, value in png_meta.items()]
    ).lower()
    editors = sorted({label for key, label in EDITOR_KEYWORDS.items() if _matches(software_text, key)})
    generators = sorted({label for key, label in AI_KEYWORDS.items() if _matches(software_text, key)})

    thumbnail = compare_thumbnail(path, loaded.rgb)
    findings: list[dict[str, Any]] = []
    score = 0.0

    if not tags:
        findings.append(
            finding(
                "low",
                "No EXIF metadata found",
                "The file has no readable EXIF block. Social-media uploads and screenshots often strip it, "
                "but a camera original that lost its metadata also lost its provenance anchor.",
                0.55,
                ["metadata", "provenance"],
            )
        )
    else:
        if camera.get("make") or camera.get("model"):
            findings.append(
                finding(
                    "info",
                    "Camera identity present",
                    f"{camera.get('make', '')} {camera.get('model', '')}".strip()
                    + (f" · lens {camera['lens']}" if camera.get("lens") else "")
                    + (f" · software {camera['software']}" if camera.get("software") else ""),
                    0.9,
                    ["provenance", "metadata"],
                )
            )
        else:
            findings.append(
                finding(
                    "low",
                    "No camera make/model tags",
                    "EXIF exists but does not identify a camera. This happens after editing, "
                    "social-media processing, screenshots and AI generation.",
                    0.6,
                    ["metadata", "provenance"],
                )
            )

        if gps:
            findings.append(
                finding(
                    "low",
                    "GPS coordinates embedded",
                    f"{gps['location_text']}"
                    + (f" · altitude {gps['altitude_m']} m" if gps.get("altitude_m") is not None else "")
                    + f" · map {gps['map_url']}. Location is sensitive personal data and a strong corroboration point.",
                    0.99,
                    ["privacy", "gps"],
                )
            )

        if editors:
            findings.append(
                finding(
                    "medium",
                    "Editing or processing software recorded",
                    "Metadata names " + ", ".join(editors) + ". Post-processing is not automatically malicious, "
                    "but it breaks the camera-original chain and must be explained.",
                    0.85,
                    ["editor", "provenance"],
                )
            )
            score = max(score, 30.0)

        if generators:
            findings.append(
                finding(
                    "high",
                    "Generative-AI metadata detected",
                    "Metadata names " + ", ".join(generators) + ". Treat the file as synthetic or AI-edited "
                    "until independent provenance is available.",
                    0.92,
                    ["ai", "provenance"],
                )
            )
            score = max(score, 60.0)

        original = parsed_dates.get("DateTimeOriginal")
        digitized = parsed_dates.get("DateTimeDigitized")
        modified = parsed_dates.get("DateTime")

        if original and modified and abs((modified - original).total_seconds()) > 2:
            findings.append(
                finding(
                    "low",
                    "DateTime differs from DateTimeOriginal",
                    f"DateTime {modified} vs DateTimeOriginal {original}. Some editors rewrite only one tag; "
                    "this is a useful corroboration point but not proof of tampering.",
                    0.6,
                    ["timestamp"],
                )
            )
            score = max(score, 25.0)

        if original and digitized and digitized < original - timedelta(seconds=2):
            findings.append(
                finding(
                    "medium",
                    "Digitised time precedes capture time",
                    f"DateTimeDigitized {digitized} is earlier than DateTimeOriginal {original}.",
                    0.7,
                    ["timestamp"],
                )
            )
            score = max(score, 35.0)

        if original and fs_modified and abs((fs_modified - original).total_seconds()) > 2 * 86400:
            findings.append(
                finding(
                    "low",
                    "File modified well after capture",
                    f"Filesystem mtime {fs_modified} is more than two days from DateTimeOriginal {original}. "
                    "Copying, exporting and editing all change mtime; compare with the other timestamps.",
                    0.45,
                    ["timestamp"],
                )
            )

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for label, value in (("DateTimeOriginal", original), ("DateTime", modified)):
            if value and value > now + timedelta(days=1):
                findings.append(
                    finding(
                        "medium",
                        "Capture timestamp is in the future",
                        f"{label} is {value}, ahead of the examination clock. A wrong camera clock or a forged "
                        "tag would produce this.",
                        0.75,
                        ["timestamp"],
                    )
                )
                score = max(score, 35.0)
                break

    if thumbnail.get("present") and thumbnail.get("dhash_distance", 0) > 16:
        findings.append(
            finding(
                "high",
                "Embedded thumbnail does not match the main image",
                f"The EXIF preview differs from the full image by {thumbnail['dhash_distance']} bits. "
                "Cameras normally write a preview of the same pixels, so this suggests the main image was "
                "replaced or heavily edited after capture.",
                0.8,
                ["thumbnail", "tamper"],
            )
        )
        score = max(score, 70.0)

    if len([item for item in findings if item["severity"] in ("high", "medium")]) >= 2:
        score = min(85.0, score + 8.0)

    summary_parts = [f"{len(tags)} EXIF tags" if tags else "no EXIF"]
    if camera.get("make") or camera.get("model"):
        summary_parts.append(f"{camera.get('make', '')} {camera.get('model', '')}".strip())
    if gps:
        summary_parts.append(f"GPS {gps['latitude']:.4f}, {gps['longitude']:.4f}")
    if editors:
        summary_parts.append("editor: " + ", ".join(editors))
    if generators:
        summary_parts.append("generator: " + ", ".join(generators))
    if thumbnail.get("present"):
        summary_parts.append(
            "thumbnail " + ("matches" if thumbnail.get("match") else "MISMATCH")
        )

    artifacts = [thumbnail["artifact"]] if thumbnail.get("artifact") else []
    return module_result(
        "metadata",
        status="ok",
        summary=" · ".join(summary_parts),
        findings=findings,
        metrics={
            "has_exif": bool(tags),
            "tag_count": len(tags),
            "tags": dump,
            "camera": camera,
            "gps": gps,
            "timestamps": timestamps,
            "editors": editors,
            "generators": generators,
            "software_text": software_text[:1000],
            "xmp": xmp,
            "png_text": png_meta,
            "thumbnail": thumbnail,
            "icc_profile": bool(loaded.image.info.get("icc_profile")),
            "exif_bytes": len(loaded.image.info.get("exif", b"") or b""),
        },
        artifacts=artifacts,
        score=score,
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Module 2: EXIF, GPS, timestamps and suspicious metadata tags."
    )
    parser.add_argument("image", help="path to the evidence image")
    parser.add_argument("--json", action="store_true", help="print compact JSON")
    args = parser.parse_args(argv)
    result = analyse_metadata(args.image)
    print(json.dumps(result, indent=None if args.json else 2, ensure_ascii=False))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    sys.exit(_main())
