"""Module 3 - Error Level Analysis (ELA).

Forensic concept
----------------
JPEG is lossy: every save quantises 8x8 DCT blocks.  If an image is re-saved
at a known quality, pixels that were already at that "compression level" change
very little, while a region pasted or retouched after the last save often has a
different residual.  ELA amplifies that difference into a heatmap.

ELA is a **screening technique**, not proof.  Sharp edges, texture, denoising,
resizing and earlier JPEG saves all create residuals.  A long horizon or a
textured field can look "hot" even in an untouched photo.  The module therefore
looks for **compact, dense regions** whose residual stands out from the rest of
the image, reports them, and never declares an image forged by itself.

Detection outline
-----------------
1. Re-save the image at a fixed JPEG quality and take the maximum-channel
   absolute difference (the ELA residual).
2. Average the residual into 16x16 blocks.  This suppresses single-pixel noise
   and makes the statistics stable.
3. Mark blocks above a robust threshold: ``max(abs_floor, median + 4*MAD)``.
   The absolute floor stops tiny residuals from becoming "significant".
4. Compute the local density of marked blocks in a 9x9-block window.  A real
   edited region is a **filled** area; a horizon, roof edge or branch is a thin
   line, so its local density stays low.  This is the step that removes most
   edge false positives.
5. Group dense blocks into connected components, require a minimum area,
   absolute residual and contrast against a surrounding ring, then score.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
from matplotlib import colormaps
from PIL import Image, ImageDraw

from forensics import finding, module_result
from utils import config
from utils.image_utils import ImageLoadError, load_image, safe_name


# --------------------------------------------------------------------- core ELA

def compute_ela(image: Image.Image, quality: int = 90) -> np.ndarray:
    """Return the per-pixel maximum-channel difference after JPEG re-saving.

    ``subsampling=0`` keeps chroma at full resolution so colour edges do not
    create artificial differences between the two encodes.
    """
    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, "JPEG", quality=quality, subsampling=0)
    buffer.seek(0)
    recompressed = Image.open(buffer).convert("RGB")
    original = np.asarray(image.convert("RGB"), dtype=np.int16)
    again = np.asarray(recompressed, dtype=np.int16)
    return np.abs(original - again).max(axis=2).astype(np.float32)


def colorize(residual: np.ndarray, amplify: int = 15) -> Image.Image:
    """Map the residual through Matplotlib's ``inferno`` colormap.

    The display is normalised to the 99.5th percentile so that a low-contrast
    synthetic sample and a normal camera photo both produce a readable heatmap.
    ``amplify`` acts as a relative gain: larger values make weak residuals
    brighter.  This affects only the picture, never the numeric score.
    """
    scale = max(2.0, float(np.percentile(residual, 99.5)))
    scale *= 15.0 / max(1.0, float(amplify))
    normalised = np.clip(residual / scale, 0.0, 1.0) ** 0.8
    rgba = colormaps["inferno"](normalised, bytes=True)
    return Image.fromarray(rgba[..., :3], "RGB")


def blend_overlay(original: Image.Image, heat: Image.Image, alpha: float = 0.55) -> Image.Image:
    """Overlay the heatmap on the original for a human-readable artifact."""
    base = np.asarray(original.convert("RGB"), dtype=np.float32)
    glow = np.asarray(heat.convert("RGB"), dtype=np.float32)
    mixed = np.clip(base * (1.0 - alpha) + glow * alpha, 0, 255).astype(np.uint8)
    return Image.fromarray(mixed, "RGB")


def draw_regions(image: Image.Image, clusters: list[dict[str, Any]], width: int = 3) -> Image.Image:
    """Outline detected regions on a copy of an artifact image."""
    marked = image.copy()
    if not clusters:
        return marked
    draw = ImageDraw.Draw(marked)
    for cluster in clusters:
        box = cluster.get("pixel_bbox")
        if not box:
            continue
        draw.rectangle(box, outline=(255, 64, 48), width=width)
    return marked


def comparison_sheet(original: Image.Image, heat: Image.Image,
                     clusters: list[dict[str, Any]] | None = None) -> Image.Image:
    """Side-by-side original/ELA panel used in the PDF report."""
    max_side = 700
    left = original.convert("RGB").copy()
    left.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)
    right = heat.convert("RGB").copy()
    if clusters:
        for cluster in clusters:
            box = cluster.get("pixel_bbox")
            if not box:
                continue
            scaled = (
                box[0] * right.width / max(1, original.width),
                box[1] * right.height / max(1, original.height),
                box[2] * right.width / max(1, original.width),
                box[3] * right.height / max(1, original.height),
            )
            ImageDraw.Draw(right).rectangle(scaled, outline=(255, 64, 48), width=3)
    right.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)
    label_height = 30
    gap = 12
    canvas = Image.new(
        "RGB",
        (left.width + right.width + gap, max(left.height, right.height) + label_height),
        (16, 18, 24),
    )
    canvas.paste(left, (0, label_height))
    canvas.paste(right, (left.width + gap, label_height))
    draw = ImageDraw.Draw(canvas)
    draw.text((8, 8), "ORIGINAL", fill=(220, 225, 235))
    draw.text((left.width + gap + 8, 8), "ELA HEATMAP", fill=(220, 225, 235))
    return canvas


# --------------------------------------------------------------- block statistics

def block_grid(values: np.ndarray, block: int) -> np.ndarray:
    """Mean of each non-overlapping block (edge remainder is ignored)."""
    height, width = values.shape
    rows, columns = height // block, width // block
    if rows == 0 or columns == 0:
        return np.zeros((1, 1), dtype=np.float32)
    cropped = values[: rows * block, : columns * block]
    return cropped.reshape(rows, block, columns, block).mean(axis=(1, 3))


def density_map(mask: np.ndarray, window: int) -> np.ndarray:
    """Fraction of ``True`` cells inside a sliding square window.

    Implemented with an integral image so the cost is independent of the
    window size.  The output has the same shape as ``mask`` (edge padding is
    zero, not reflected, because an edit cannot continue outside the frame).
    """
    rows, columns = mask.shape
    window = max(3, min(int(window), rows, columns))
    if window % 2 == 0:
        window -= 1
    if window < 3:
        return mask.astype(np.float32)

    pad = window // 2
    padded = np.pad(mask.astype(np.float32), pad, mode="constant", constant_values=0)
    integral = padded.cumsum(axis=0).cumsum(axis=1)
    integral = np.pad(integral, ((1, 0), (1, 0)))
    total = (
        integral[window:, window:]
        - integral[:-window, window:]
        - integral[window:, :-window]
        + integral[:-window, :-window]
    )
    return total / float(window * window)


def ring_median(grid: np.ndarray, bbox: list[int], pad: int = 2) -> float:
    """Median residual in a ring around a component's bounding box."""
    x0, y0, x1, y1 = bbox
    ry0, ry1 = max(0, y0 - pad), min(grid.shape[0], y1 + pad + 1)
    rx0, rx1 = max(0, x0 - pad), min(grid.shape[1], x1 + pad + 1)
    window = grid[ry0:ry1, rx0:rx1].astype(np.float32).copy()
    window[y0 - ry0 : y1 - ry0 + 1, x0 - rx0 : x1 - rx0 + 1] = np.nan
    values = window[np.isfinite(window)]
    return float(np.median(values)) if values.size else float(np.median(grid))


def components(mask: np.ndarray, grid: np.ndarray) -> list[dict[str, Any]]:
    """8-connected components with size, bounding box, density and mean residual."""
    rows, columns = mask.shape
    seen = np.zeros_like(mask, dtype=bool)
    output: list[dict[str, Any]] = []
    for start_row in range(rows):
        for start_column in range(columns):
            if not mask[start_row, start_column] or seen[start_row, start_column]:
                continue
            stack = [(start_row, start_column)]
            seen[start_row, start_column] = True
            cells: list[tuple[int, int]] = []
            while stack:
                row, column = stack.pop()
                cells.append((row, column))
                for delta_row in (-1, 0, 1):
                    for delta_column in (-1, 0, 1):
                        next_row, next_column = row + delta_row, column + delta_column
                        if (
                            0 <= next_row < rows
                            and 0 <= next_column < columns
                            and mask[next_row, next_column]
                            and not seen[next_row, next_column]
                        ):
                            seen[next_row, next_column] = True
                            stack.append((next_row, next_column))
            ys = [cell[0] for cell in cells]
            xs = [cell[1] for cell in cells]
            left, right = min(xs), max(xs)
            top, bottom = min(ys), max(ys)
            width, height = right - left + 1, bottom - top + 1
            values = [float(grid[y, x]) for y, x in cells]
            output.append(
                {
                    "size": len(cells),
                    "bbox_blocks": [left, top, right, bottom],
                    "width_blocks": width,
                    "height_blocks": height,
                    "density": round(len(cells) / (width * height), 3),
                    "mean_residual": round(float(np.mean(values)), 3),
                }
            )
    return output


# ------------------------------------------------------------------- orchestration

def analyse_ela(path: str | Path, quality: int | None = None) -> dict[str, Any]:
    """Run Module 3 and return the standard module result."""
    path = Path(path)
    quality = int(quality or config.ELA["quality"])
    amplify = int(config.ELA["amplify"])
    block = int(config.ELA["block_size"])
    window = int(config.ELA["density_window"])
    sigma = float(config.ELA["outlier_z"])
    abs_floor = float(config.ELA["abs_floor"])
    density_threshold = float(config.ELA["density_threshold"])
    min_blocks = int(config.ELA["min_cluster_blocks"])
    min_residual = float(config.ELA["min_mean_residual"])
    min_contrast = float(config.ELA["min_contrast"])

    try:
        loaded = load_image(path)
    except ImageLoadError as exc:
        return module_result(
            "ela",
            status="error",
            summary=f"ELA could not run: {exc}",
            findings=[finding("critical", "Image cannot be decoded", str(exc), 0.97)],
        )

    residual = compute_ela(loaded.rgb(), quality=quality)
    grid = block_grid(residual, block)
    median = float(np.median(grid))
    mad = float(np.median(np.abs(grid - median))) * 1.4826
    if mad <= 1e-6:
        mad = float(np.std(grid)) or 1.0
    threshold = max(abs_floor, median + sigma * mad)

    high = grid >= threshold
    if high.shape[0] > 2 and high.shape[1] > 2:
        # Frame edges are padded by the encoder and are not evidence.
        high[0, :] = high[-1, :] = False
        high[:, 0] = high[:, -1] = False

    density = density_map(high, window)
    seed = density >= density_threshold

    candidates = components(seed, grid)
    clusters: list[dict[str, Any]] = []
    for item in candidates:
        if item["size"] < min_blocks:
            continue
        if item["width_blocks"] < 3 or item["height_blocks"] < 3:
            continue
        x0, y0, x1, y1 = item["bbox_blocks"]
        bbox_mean = float(np.mean(grid[y0 : y1 + 1, x0 : x1 + 1]))
        ring = ring_median(grid, item["bbox_blocks"])
        contrast = bbox_mean / (ring + 0.05)
        if bbox_mean < min_residual or contrast < min_contrast:
            continue
        item["bbox_mean_residual"] = round(bbox_mean, 3)
        item["ring_median"] = round(ring, 3)
        item["contrast"] = round(contrast, 2)
        item["pixel_bbox"] = [
            x0 * block,
            y0 * block,
            min(loaded.width, (x1 + 1) * block),
            min(loaded.height, (y1 + 1) * block),
        ]
        item["area_fraction"] = round(item["size"] / float(grid.size), 4)
        clusters.append(item)
    clusters.sort(key=lambda item: item["size"] * item["bbox_mean_residual"], reverse=True)

    # ---- artifacts -----------------------------------------------------
    config.ELA_DIR.mkdir(parents=True, exist_ok=True)
    stem = safe_name(path.stem)
    heat = colorize(residual, amplify=amplify)
    overlay = draw_regions(blend_overlay(loaded.rgb(), heat), clusters)
    sheet = comparison_sheet(loaded.rgb(), heat, clusters)
    heat_path = config.ELA_DIR / f"ela_{stem}_heat.png"
    overlay_path = config.ELA_DIR / f"ela_{stem}_overlay.png"
    sheet_path = config.ELA_DIR / f"ela_{stem}_comparison.png"
    heat.save(heat_path, "PNG")
    overlay.save(overlay_path, "PNG")
    sheet.save(sheet_path, "PNG")

    # ---- score ---------------------------------------------------------
    mean = float(np.mean(residual))
    p95 = float(np.percentile(residual, 95))
    p99 = float(np.percentile(residual, 99.5))
    peak = float(np.max(residual))
    outlier_fraction = float(high.mean())

    findings: list[dict[str, Any]] = []
    score = 0.0
    if clusters:
        best = clusters[0]
        area_term = min(1.0, best["area_fraction"] / 0.04)
        strength_term = min(1.0, max(0.0, best["bbox_mean_residual"] - min_residual) / 0.6)
        contrast_term = min(1.0, max(0.0, best["contrast"] - min_contrast) / 3.5)
        score = min(95.0, 20.0 + 40.0 * area_term + 25.0 * strength_term + 10.0 * contrast_term)
        severity = "high" if score >= 60 else "medium" if score >= 35 else "low"
        x0, y0, x1, y1 = best["pixel_bbox"]
        findings.append(
            finding(
                severity,
                "Localised compression inconsistency",
                f"{len(clusters)} dense residual region(s) found. The largest covers "
                f"{best['width_blocks']}x{best['height_blocks']} blocks ({x1 - x0}x{y1 - y0} px) "
                f"around ({x0}, {y0})-({x1}, {y1}) with mean residual "
                f"{best['bbox_mean_residual']:.2f} versus {best['ring_median']:.2f} in the "
                f"surrounding ring ({best['contrast']:.1f}x). This is consistent with a locally "
                "edited, pasted or re-encoded region. Confirm with copy-move and noise analysis: "
                "texture, sharpening and earlier JPEG saves can produce a similar pattern.",
                min(0.95, 0.55 + 0.30 * area_term + 0.10 * strength_term),
                ["ela", "tamper", "compression"],
            )
        )
    else:
        findings.append(
            finding(
                "info",
                "No compact ELA anomaly",
                f"{outlier_fraction:.1%} of blocks are above the residual threshold, but they do "
                "not form a dense region larger than the minimum cluster size. Edges, texture and "
                "prior compression explain such scattered responses. This supports, but does not "
                "prove, a single compression history.",
                0.6,
                ["ela"],
            )
        )

    summary = (
        f"mean residual {mean:.2f} · p99.5 {p99:.1f} · "
        f"{len(clusters)} dense region(s) · outlier fraction {outlier_fraction:.1%}"
    )
    return module_result(
        "ela",
        status="ok",
        summary=summary,
        findings=findings,
        artifacts=[str(heat_path), str(overlay_path), str(sheet_path)],
        score=score,
        metrics={
            "quality": quality,
            "amplification": amplify,
            "block_size": block,
            "density_window": window,
            "density_threshold": density_threshold,
            "residual_threshold": round(threshold, 3),
            "mean": round(mean, 3),
            "p95": round(p95, 3),
            "p99_5": round(p99, 3),
            "max": round(peak, 3),
            "block_median": round(median, 3),
            "block_mad": round(mad, 3),
            "outlier_fraction": round(outlier_fraction, 4),
            "clusters": clusters[:8],
            "artifact_paths": [str(heat_path), str(overlay_path), str(sheet_path)],
        },
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Module 3: Error Level Analysis with dense-region detection."
    )
    parser.add_argument("image", help="path to the evidence image")
    parser.add_argument("--quality", type=int, default=config.ELA["quality"], help="JPEG re-save quality")
    parser.add_argument("--json", action="store_true", help="print compact JSON")
    args = parser.parse_args(argv)
    result = analyse_ela(args.image, quality=args.quality)
    print(json.dumps(result, indent=None if args.json else 2, ensure_ascii=False))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    sys.exit(_main())
