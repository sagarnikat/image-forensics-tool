"""Configuration constants and tunable forensic thresholds.

All magic numbers live here so the examiner can justify them in the report and
so the demo can be tuned without editing analysis logic.
"""

from __future__ import annotations

from pathlib import Path

APP_NAME = "PixelProof"
APP_TAGLINE = "Image Forensic Examination Toolkit"
VERSION = "1.0.0"

# --------------------------------------------------------------------- paths
BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_DIR = BASE_DIR / "output"
ELA_DIR = OUTPUT_DIR / "ela_results"
COPYMOVE_DIR = OUTPUT_DIR / "copymove_results"
METADATA_DIR = OUTPUT_DIR / "metadata_results"
REPORT_DIR = OUTPUT_DIR / "reports"
TEMP_DIR = OUTPUT_DIR / "cases"

# ---------------------------------------------------------------- input rules
MAX_FILE_MB = 50
MAX_IMAGE_PIXELS = 80_000_000  # decompression-bomb guard (~80 MP)
SUPPORTED_EXTENSIONS = {
    ".jpg", ".jpeg", ".jpe", ".jfif",
    ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
}
# Extensions that must never appear after an image extension, e.g. photo.jpg.exe
DOUBLE_EXTENSION_PATTERN = r"\.(jpe?g|png|gif|bmp|tiff?|webp)\.(exe|bat|cmd|js|jse|vbs|scr|ps1|zip|rar|7z|iso)$"

# ---------------------------------------------------------------- ELA tuning
ELA = {
    "quality": 90,             # fixed JPEG recompression quality
    "amplify": 15,             # heat-map gain (visual only)
    "block_size": 16,          # block grid used for statistics
    "outlier_z": 4.0,          # robust cut-off: median + 4*MAD
    "abs_floor": 0.50,         # ignore residual differences below this value
    "density_window": 9,       # 9x9-block window for local density
    "density_threshold": 0.50, # >=50% of a window must be high-residual
    "min_cluster_blocks": 12,  # minimum dense area (12 blocks = 3072 px)
    "min_mean_residual": 0.70, # minimum mean residual inside a region
    "min_contrast": 2.0,       # region vs surrounding-ring ratio
}

# ------------------------------------------------------------ copy-move tuning
COPYMOVE = {
    "orb_features": 3000,
    "match_ratio": 0.75,    # Lowe ratio test
    "min_matches": 8,
    "min_spatial_distance": 30,  # ignore matches that are almost on top of each other
    "ransac_px": 3.0,
    "max_side": 900,        # downscale huge photos before ORB
}

# ---------------------------------------------------------------- stego tuning
STEGO = {
    "min_appended_bytes": 16,
    "lsb_entropy_threshold": 0.92,
    "chi_square_p_threshold": 0.95,
}

# ------------------------------------------------------------ verdict tuning
# Reliability weight of each module when combining scores (0-1).
MODULE_WEIGHTS = {
    "file_analysis": 0.15,
    "metadata": 0.20,
    "ela": 0.20,
    "copymove": 0.30,
    "stego": 0.15,
}
VERDICT_THRESHOLDS = {
    "authentic": 20,    # score < 20
    "suspicious": 50,   # 20 <= score < 50
    # >= 50 is "Likely tampered"
}


def ensure_dirs() -> None:
    """Create runtime output folders; safe to call on every app start."""
    for path in (OUTPUT_DIR, ELA_DIR, COPYMOVE_DIR, METADATA_DIR, REPORT_DIR, TEMP_DIR,
                 SAMPLES_DIR / "original", SAMPLES_DIR / "tampered", SAMPLES_DIR / "stego"):
        path.mkdir(parents=True, exist_ok=True)
