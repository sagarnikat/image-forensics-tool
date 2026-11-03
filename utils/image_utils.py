"""Image loading, validation and conversion helpers.

Forensic rule: never modify the evidence file.  Every function here either
reads the original or writes a *new* artifact under ``output/``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

from . import config

Image.MAX_IMAGE_PIXELS = config.MAX_IMAGE_PIXELS

LOSSLESS_FORMATS = {"PNG", "BMP", "TIFF", "GIF", "TGA", "WEBP"}


class ImageLoadError(Exception):
    """Raised when a file is missing, too large, corrupt or not an image."""


@dataclass
class LoadedImage:
    """A decoded image plus the facts needed by every analyzer."""

    path: Path
    image: Image.Image
    format: str
    width: int
    height: int
    mode: str
    size_bytes: int
    frames: int = 1
    warnings: list[str] = field(default_factory=list)

    @property
    def is_lossless(self) -> bool:
        return self.format in LOSSLESS_FORMATS

    @property
    def megapixels(self) -> float:
        return round(self.width * self.height / 1_000_000, 2)

    def rgb(self) -> Image.Image:
        return to_rgb(self.image)


def human_bytes(size: int | float) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def safe_name(name: str, default: str = "evidence") -> str:
    """Strip paths and shell-hostile characters from an uploaded filename."""
    base = Path(name or default).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return cleaned[:120] or default


def load_image(path: str | Path) -> LoadedImage:
    """Open and fully decode an image with clear, user-facing errors.

    Two passes are used on purpose: ``verify()`` catches truncated/corrupt
    containers without trusting the decoder, then the file is reopened and
    ``load()`` forces pixel decoding so later modules cannot fail lazily.
    """
    path = Path(path)
    if not path.is_file():
        raise ImageLoadError(f"File not found: {path}")

    size = path.stat().st_size
    if size == 0:
        raise ImageLoadError("File is empty (0 bytes)")
    if size > config.MAX_FILE_MB * 1024 * 1024:
        raise ImageLoadError(
            f"File is {human_bytes(size)}; limit is {config.MAX_FILE_MB} MB"
        )

    try:
        with Image.open(path) as probe:
            probe.verify()
    except Image.DecompressionBombError as exc:
        raise ImageLoadError(f"Image exceeds the pixel safety limit: {exc}") from exc
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ImageLoadError(f"Unsupported, corrupt or non-image file: {exc}") from exc

    try:
        image = Image.open(path)
        image.load()
    except Exception as exc:  # Pillow raises format-specific exceptions
        raise ImageLoadError(f"Image header is valid but pixels cannot be decoded: {exc}") from exc

    fmt = (image.format or path.suffix.lstrip(".")).upper()
    frames = getattr(image, "n_frames", 1) or 1
    warnings: list[str] = []
    if frames > 1:
        warnings.append(f"Animated container: {frames} frames; only frame 1 is analysed.")
        image.seek(0)
    if fmt not in LOSSLESS_FORMATS and fmt not in {"JPEG", "MPO", "JPG"}:
        warnings.append(f"Uncommon image container: {fmt}")

    return LoadedImage(
        path=path,
        image=image,
        format="JPEG" if fmt == "MPO" else fmt,
        width=image.width,
        height=image.height,
        mode=image.mode,
        size_bytes=size,
        frames=frames,
        warnings=warnings,
    )


def to_rgb(image: Image.Image) -> Image.Image:
    """Convert any Pillow mode into a display-safe RGB image.

    Conversion is done on a copy; the evidence object is never changed.
    """
    if image.mode in ("I;16", "I;16B", "I;16L", "I", "F"):
        array = np.asarray(image, dtype=np.float32)
        peak = float(array.max()) or 1.0
        array = np.clip(array / peak * 255.0, 0, 255).astype(np.uint8)
        return Image.fromarray(array, "L").convert("RGB")
    if image.mode == "P":
        image = image.convert("RGBA")
    if image.mode in ("RGBA", "LA"):
        background = Image.new("RGB", image.size, (255, 255, 255))
        rgba = image.convert("RGBA")
        background.paste(rgba, mask=rgba.split()[-1])
        return background
    return image.convert("RGB")


def to_gray_array(image: Image.Image) -> np.ndarray:
    """Rec. 601 luma as float32, used by ELA/copy-move/stego."""
    return np.asarray(to_rgb(image).convert("L"), dtype=np.float32)


def save_uploaded_bytes(data: bytes, destination: str | Path) -> Path:
    """Persist an uploaded file exactly as received (no re-encoding)."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if len(data) > config.MAX_FILE_MB * 1024 * 1024:
        raise ImageLoadError(f"Upload exceeds {config.MAX_FILE_MB} MB")
    destination.write_bytes(data)
    return destination


def make_thumbnail(image: Image.Image, max_side: int = 900) -> Image.Image:
    """Create a display copy without touching the original."""
    copy = image.copy()
    copy.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)
    return copy


def exif_orientation_applied(image: Image.Image) -> Image.Image:
    """Display helper only.  Analysis always uses the unrotated pixels."""
    return ImageOps.exif_transpose(image.copy())


def describe(image: LoadedImage) -> dict[str, Any]:
    return {
        "format": image.format,
        "width": image.width,
        "height": image.height,
        "megapixels": image.megapixels,
        "mode": image.mode,
        "frames": image.frames,
        "size_bytes": image.size_bytes,
        "size_human": human_bytes(image.size_bytes),
        "lossless": image.is_lossless,
        "warnings": image.warnings,
    }
