# PixelProof — Image Forensic Examination Toolkit

A modular, offline image-forensics tool for the SPPU **BE Computer Engineering**
course **Cyber Security and Digital Forensics (CSDF)**.

**Problem statement:** *Design and develop a tool for digital forensics of images.*

The tool helps an investigator answer three questions about a submitted image:

1. **Is the file what it claims to be, and has it changed?**
   Hashes, magic bytes, extension agreement, timestamps.
2. **Was it edited or composited?**
   EXIF clues, Error Level Analysis (ELA), copy-move detection.
3. **Is data hidden in it?**
   LSB plane analysis and appended-payload detection.

Every module returns structured findings, and the final stage produces a PDF
evidence report with a verdict and reasoning.

> **Status:** Modules 1–3 and the verdict + PDF report are complete.
> Completed: file analysis & integrity, EXIF/metadata analysis, Error Level Analysis,
> verdict aggregation, PDF evidence report, one-command CLI, Streamlit UI (`app.py`).
> Pending: copy-move detection and steganography checks.

---

## Quick start — how to run

Run every command from the project root (`image-forensics-tool/`).

### 1. Install (Linux / macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 1. Install (Windows)

```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start the web app

```bash
streamlit run app.py
```

Open <http://localhost:8501> in your browser. In the sidebar, pick a built-in
sample or upload your own image, then browse the module tabs. A
**Download PDF report** button appears under the verdict (and again in the
**Report** tab) as soon as the analysis finishes.

### Or run the command-line report

```bash
python report.py samples/tampered/spliced_demo.jpg
```

The PDF is written to `output/reports/`. For all options:

```bash
python report.py --help
```

> If `streamlit` is not found, the virtual environment is not active. Run
> `source .venv/bin/activate` (Linux/macOS) or `.venv\Scripts\activate` (Windows)
> first, then retry.

---

## 1. Current feature status

| # | Module | File | Status |
|---|---|---|---|
| 1 | File analysis & integrity | `forensics/file_analysis.py` | ✅ Complete |
| 2 | EXIF / GPS / metadata | `forensics/metadata.py` | ✅ Complete |
| 3 | Error Level Analysis | `forensics/ela.py` | ✅ Complete |
| 4 | Copy-move forgery detection | `forensics/copymove.py` | ⏳ Next |
| 5 | Steganography checks | `forensics/stego.py` | ⏳ Pending |
| 6a | Verdict aggregation | `forensics/verdict.py`, `forensics/pipeline.py` | ✅ Complete |
| 6b | PDF evidence report | `forensics/report.py` | ✅ Complete |
| 6c | Streamlit UI | `app.py` | ✅ Complete |

### What works today

- MD5 / SHA-1 / SHA-256 of the exact evidence bytes
- Real container detection from magic bytes
- Extension/signature mismatch and double-extension detection
- Dimensions, colour mode, frames, file size, filesystem timestamps
- Full EXIF tag extraction (camera, lens, serial, software, artist)
- GPS conversion to decimal + DMS + OpenStreetMap link
- XMP and PNG text metadata
- Timestamp coherence checks
- Editing-software and AI-generator keyword detection
- Embedded EXIF thumbnail vs main image comparison (dHash)
- ELA residual heatmap at a fixed JPEG quality
- Dense-region detection with a 9×9 block density window
- Region-vs-surrounding-ring contrast check (suppresses horizon/edge lines)
- Annotated ELA overlay and side-by-side comparison sheet
- Structured findings with severity and confidence
- Weighted verdict with supporting/contradicting evidence and escalation guard-rails
- One command runs every available module and writes a multi-page PDF evidence report
- The PDF opens automatically in the system viewer (`--no-open` to suppress)
- Unit tests for all completed modules (34 tests passing)

---

## 2. Tech stack

| Layer | Library / tool |
|---|---|
| Language | Python 3.10+ |
| Image decoding | Pillow |
| Pixel analysis | OpenCV (`opencv-python-headless`), NumPy |
| EXIF | ExifRead + Pillow |
| Plots / heatmaps | Matplotlib |
| PDF report | ReportLab |
| UI | Streamlit (`app.py`) |
| Hashing | `hashlib` (standard library) |
| Tests | `unittest` (standard library) |

Everything runs locally. There are **no network calls** and no uploads to a
third-party service.

---

## 3. Architecture

```text
┌────────────────────────────── app.py (Streamlit) ──────────────────────────────┐
│  upload  →  validate  →  run pipeline  →  tabs/results  →  download PDF         │
│  UI only: no forensic logic and no thresholds                                   │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │ orchestrates
       ┌───────────────────────────▼───────────────────────────┐
       │ forensics modules (pure functions)                     │
       │                                                        │
       │ file_analysis → metadata → ela → copymove → stego     │
       │      │              │         │        │        │      │
       │      └──────────────┴─────────┴────────┴────────┘      │
       │              each returns a ModuleResult               │
       └───────────────────────────┬───────────────────────────┘
                                   │ list[ModuleResult]
       ┌───────────────────────────▼───────────────────────────┐
       │ verdict.py                                             │
       │ weighted score + severity + reasoning → verdict label  │
       └───────────────────────────┬───────────────────────────┘
                                   │
       ┌───────────────────────────▼───────────────────────────┐
       │ report.py (ReportLab)                                  │
       │ case ID, examiner, hashes, findings, images, verdict   │
       └────────────────────────────────────────────────────────┘
```

### Data flow

1. **Upload** — bytes are saved exactly as received under
   `output/cases/<case_id>/evidence/`. No re-encoding, no metadata stripping.
2. **Validation** — `utils/image_utils.load_image()` runs Pillow `verify()`,
   then reopens and forces `load()`. Corrupt files become structured errors,
   not crashes.
3. **Analysis** — each module receives the evidence path and a `LoadedImage`.
   The original file is never written to.
4. **Standard result** — every analyzer returns the same dictionary:

   ```python
   {
       "module": "metadata",
       "status": "ok" | "error",
       "summary": "22 EXIF tags · Canon EOS 90D · GPS 12.9750, 77.5944",
       "score": 0.0,             # this module's 0–100 manipulation signal
       "findings": [
           {
               "severity": "medium",
               "title": "Editing or processing software recorded",
               "detail": "Metadata names Adobe Photoshop ...",
               "confidence": 0.85,
               "tags": ["editor", "provenance"],
           }
       ],
       "metrics": { ... },       # raw facts used by the report
       "artifacts": ["output/metadata_results/thumb_x.png"],
   }
   ```

5. **Verdict** — `verdict.py` combines module scores and findings into
   **Likely authentic / Suspicious / Likely tampered**.
6. **Report** — `report.py` embeds the original, ELA artifacts, EXIF thumbnail and
   all findings into a PDF, with the thresholds and a custody declaration.
7. **Display** — Streamlit renders tabs: Overview, Metadata, ELA, Copy-Move,
   Stego, Report.

### Core design rules

| Rule | Reason |
|---|---|
| Evidence is read-only | Repeatability and chain of custody |
| Artifacts go under `output/` | Nothing pollutes the evidence folder |
| Thresholds live in `utils/config.py` | Easy to justify and tune |
| Modules never raise to the UI | Partial failure still produces a report |
| No network calls | Offline lab tool; does not leak evidence |
| SHA-256 is the report digest | MD5/SHA-1 are kept only for compatibility |

---

## 4. Project structure

```text
image-forensics-tool/
├── app.py                      # Streamlit UI
├── requirements.txt
├── README.md
│
├── forensics/                  # Core analysis: no UI code here
│   ├── __init__.py             # finding() + module_result() contract
│   ├── file_analysis.py        # ✅ Module 1: hashes, magic bytes, timestamps
│   ├── metadata.py             # ✅ Module 2: EXIF, GPS, suspicious tags
│   ├── ela.py                  # ✅ Module 3: ELA heatmap + dense regions
│   ├── copymove.py             # ⏳ Module 4
│   ├── stego.py                # ⏳ Module 5
│   ├── verdict.py              # ✅ score aggregation + escalation rules
│   ├── pipeline.py             # ✅ runs every available analyzer
│   └── report.py               # ✅ PDF report + one-command CLI
│
├── utils/
│   ├── __init__.py
│   ├── image_utils.py          # safe load/validate/convert
│   └── config.py               # thresholds, paths, constants
│
├── samples/
│   ├── original/
│   │   ├── original_demo.jpg   # ✅ clean camera-style sample with GPS
│   │   └── original_demo.png   # ✅ lossless sibling for later stego tests
│   ├── tampered/
│   │   ├── edited_metadata.jpg   # ✅ Photoshop tag + date mismatch
│   │   ├── spliced_demo.jpg      # ✅ foreign patch pasted into the sky
│   │   ├── copymove_demo.jpg     # ✅ duplicated region (Module 4)
│   │   ├── retouched_demo.jpg    # ✅ smooth brightness/contrast retouch
│   │   └── retouched_strong.jpg  # ✅ blur/sharpen retouch
│   └── stego/                    # ⏳ generated in Module 5
│
├── output/
│   ├── ela_results/
│   ├── copymove_results/
│   ├── metadata_results/       # extracted EXIF thumbnails
│   ├── reports/                # generated PDF evidence reports
│   └── cases/                  # per-case evidence copies
│
├── tests/
│   ├── test_file_analysis.py   # ✅ 6 tests
│   ├── test_metadata.py        # ✅ 9 tests
│   ├── test_ela.py             # ✅ 6 tests
│   ├── test_verdict.py         # ✅ 7 tests
│   └── test_report.py          # ✅ 6 tests
│
└── docs/
    ├── architecture.png        # to be exported for submission
    ├── dataflow.png
    └── screenshots/
```

---

## 5. Installation

### Linux / macOS

```bash
cd image-forensics-tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Windows (PowerShell / CMD)

```bat
cd image-forensics-tool
py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> If `pip` refuses to install with `externally-managed-environment`, you are
> outside the virtual environment. Activate `.venv` first.

### Verify the installation

```bash
python -c "import PIL, numpy, cv2, exifread, reportlab, streamlit; print('ok')"
```

---

## 6. How to run (current modules)

Run every command **from the project root** (`image-forensics-tool/`), with the
virtual environment active.

### Module 1 — file analysis

```bash
python -m forensics.file_analysis samples/original/original_demo.jpg
```

Compact JSON:

```bash
python -m forensics.file_analysis samples/original/original_demo.jpg --json
```

Exit code:

- `0` — image decoded and analysed
- `2` — file missing, corrupt, too large or not an image

### Module 2 — metadata / EXIF / GPS

```bash
python -m forensics.metadata samples/original/original_demo.jpg
```

Read only the fields you need:

```bash
python -m forensics.metadata samples/original/original_demo.jpg \
  | python -c "import sys, json; d=json.load(sys.stdin); \
print(d['summary']); print(d['metrics']['camera']); print(d['metrics']['gps'])"
```

Expected clean-sample result:

```text
status: ok
score: 0.0
summary: 22 EXIF tags · Canon EOS 90D · GPS 12.9750, 77.5944
camera: Canon / EOS 90D / EF-S 18-135mm ...
GPS: 12.975, 77.594444, altitude 920 m
```

Expected edited-metadata sample:

```bash
python -m forensics.metadata samples/tampered/edited_metadata.jpg
```

```text
score: 30.0
summary: 22 EXIF tags · Canon EOS 90D · GPS 12.9750, 77.5944 · editor: Adobe Photoshop
[medium] Editing or processing software recorded
[low]    DateTime differs from DateTimeOriginal
```

### Module 3 — Error Level Analysis

```bash
python -m forensics.ela samples/original/original_demo.jpg
python -m forensics.ela samples/tampered/spliced_demo.jpg
```

Expected clean result:

```text
status: ok
score: 0.0
summary: mean residual 0.21 · p99.5 3.0 · 0 dense region(s) · outlier fraction 11.6%
[info] No compact ELA anomaly
```

Scattered high-residual blocks are expected on mountain rims, the shoreline and
bushes. They do not form a dense region, so the clean image is not flagged.

Expected spliced result:

```text
status: ok
score: 84.3
summary: mean residual 0.30 · p99.5 4.0 · 1 dense region(s) · outlier fraction 16.1%
[high] Localised compression inconsistency
region: pixel box (144, 128)-(432, 352), 172 blocks,
        mean residual 1.044, ring 0.190, contrast 5.5x
```

The box surrounds the foreign patch pasted at `(160, 120)-(460, 340)`.

Change the recompression quality if the evidence has a known history:

```bash
python -m forensics.ela samples/tampered/spliced_demo.jpg --quality 85
```

ELA artifacts are written to:

```text
output/ela_results/ela_original_demo_heat.png
output/ela_results/ela_original_demo_overlay.png
output/ela_results/ela_original_demo_comparison.png
```

The overlay and comparison sheet outline every detected region in red.

> **Important:** `samples/tampered/retouched_demo.jpg` and
> `retouched_strong.jpg` score **0** in ELA. A smooth brightness change does not
> create a new high-frequency residual, and blurring actually *lowers* the
> residual. This is a real limitation of ELA, not a bug: copy-move and noise
> analysis are needed for those edits.

### Run all current modules in sequence

```bash
python -m forensics.file_analysis samples/original/original_demo.jpg
python -m forensics.metadata     samples/original/original_demo.jpg
python -m forensics.ela          samples/original/original_demo.jpg
```

### One command → PDF evidence report

`forensics.report` runs every available analyzer through
`forensics.pipeline`, combines the scores with `forensics.verdict`, writes the
PDF under `output/reports/`, prints a summary and opens the file:

```bash
python -m forensics.report samples/tampered/spliced_demo.jpg
```

Shortcut that uses only the models present in this build (file analysis,
metadata, ELA), builds the PDF and **prints the path** without opening a viewer
(the same arguments work on every platform):

```bash
# Linux / macOS
./report.sh samples/tampered/spliced_demo.jpg

# Windows (cmd.exe or PowerShell)
report.bat samples\tampered\spliced_demo.jpg

# Any platform, no shell wrapper needed
python report.py samples/tampered/spliced_demo.jpg
```

```text
  report   : /…/output/reports/report_spliced_demo_jpg.pdf  (814.8 KB)
PDF: /…/output/reports/report_spliced_demo_jpg.pdf
```

The wrappers pick the project `.venv` automatically (`.venv/bin/python` on
Linux/macOS, `.venv\Scripts\python.exe` on Windows) and fall back to the system
interpreter. Pass the normal report flags after the image, for example
`./report.sh photo.jpg --examiner "Sagar" -o /tmp/report.pdf` (Windows:
`report.bat photo.jpg --examiner "Sagar" -o C:\tmp\report.pdf`).

Terminal output:

```text
PixelProof — image forensic report
  evidence : samples/tampered/spliced_demo.jpg
  verdict  : Likely tampered  (54.8/100, confidence 74%)
  modules  : File analysis & integrity 0.0 · Metadata / EXIF 0.0 · Error Level Analysis 84.3
  skipped  : copymove, stego (not in this build)
  report   : output/reports/report_spliced_demo_jpg.pdf  (814.7 KB)
  viewer   : opened
```

Options:

| Flag | Effect |
|---|---|
| `-o PATH` | Write to a specific PDF path (or a directory) |
| `--examiner "Name"` | Print the examiner on the report and chain-of-custody block |
| `--case-id ID` | Override the generated case ID (`PP-YYYYMMDD-HHMMSS-XXXX`) |
| `--no-open` | Build the PDF but do not launch a viewer (CI/headless) |
| `--no-optional` | Skip optional modules (copy-move, stego) even when present |

The PDF contains, in order:

1. Case metadata and title block
2. Verdict card — band, score, confidence, coverage and agreement
3. Executive summary — supporting and contradicting evidence
4. Evidence and integrity — size, container, dimensions, SHA-256/SHA-1/MD5
5. Module score table with signal bars
6. Findings sorted by severity, each with source module and confidence
7. Visual evidence — original, ELA comparison sheet, overlay and heatmap, EXIF thumbnail
8. Metadata detail — camera, GPS + OpenStreetMap link, timestamps, top EXIF tags
9. Method and thresholds, verdict formula and limitations
10. Chain-of-custody declaration, disclaimer and reproduction commands

The evidence file is only read. Every report states the exact thresholds used,
so another examiner can reproduce the run.

### Full Streamlit app

```bash
streamlit run app.py
```

Then open <http://localhost:8501>. Pick a built-in sample or upload an image,
run the analysis, browse each module tab, and download the PDF report.

---

## 7. Sample data and test plan

### 7.1 Ready-made samples

| Sample | Purpose | Current expected result |
|---|---|---|
| `samples/original/original_demo.jpg` | Camera-style original with EXIF + GPS | Module 1 score 0; Module 2 score 0; Module 3 score 0; Canon EOS 90D; GPS 12.9750, 77.5944 |
| `samples/original/original_demo.png` | Lossless sibling for LSB tests | Module 1 clean; Module 2 “no EXIF” |
| `samples/tampered/edited_metadata.jpg` | Editor tag + date mismatch, pixels unchanged | Module 2 score 30; Module 3 score 0 (metadata-only edit) |
| `samples/tampered/spliced_demo.jpg` | Foreign textured patch pasted into the sky | Module 3 score 84.3; high ELA region around the patch |
| `samples/tampered/copymove_demo.jpg` | Duplicated region | Reserved for Module 4 |
| `samples/tampered/retouched_demo.jpg` | Smooth brightness/contrast retouch | Module 3 score 0; demonstrates the ELA limitation |
| `samples/tampered/retouched_strong.jpg` | Blur/sharpen retouch | Module 3 score 0; blur lowers the residual |

### 7.2 Final three-case test plan (after all modules)

1. **Original image**
   - Use `samples/original/original_demo.jpg`.
   - Expect: matching hashes, no editor tag, ELA uniform, no copy-move,
     no appended data, verdict **Likely authentic**.
2. **Edited image (splice, copy-paste or retouch)**
   - Use `samples/tampered/spliced_demo.jpg` for ELA and the copy-move sample
     generated in Module 4 for duplication.
   - Expect: ELA dense region over the foreign patch; copy-move match; verdict
     **Likely tampered** or **Suspicious**.
   - Also run `retouched_demo.jpg`. If ELA is negative, record that as a
     limitation instead of forcing a positive result.
3. **Image with hidden data**
   - Use the LSB/appended-payload sample generated in Module 5.
   - Expect: high-entropy LSB plane and/or a ZIP payload after the PNG `IEND`
     marker; verdict **Suspicious/Likely tampered**.
4. **Negative controls**
   - Renamed file (`JPEG` bytes named `.png`) → Module 1 high finding.
   - `holiday.jpg.exe` → double-extension high finding.
   - Corrupt file → structured error, exit code 2.
   - PNG without EXIF → Module 2 low “No EXIF metadata” finding.

### 7.3 Manual negative tests (Module 1)

```bash
cp samples/original/original_demo.jpg /tmp/renamed.png
python -m forensics.file_analysis /tmp/renamed.png

cp samples/original/original_demo.jpg /tmp/holiday.jpg.exe
python -m forensics.file_analysis /tmp/holiday.jpg.exe

printf 'not an image\n' > /tmp/corrupt.jpg
python -m forensics.file_analysis /tmp/corrupt.jpg
```

### 7.4 Manual metadata tests (Module 2)

Create an image with an editor tag:

```bash
python - <<'PY'
from PIL import Image
img = Image.new("RGB", (128, 96), (90, 120, 160))
exif = Image.Exif()
exif[0x0131] = "Adobe Photoshop 25.0"
exif[0x0132] = "2026:09:10 18:00:00"
sub = exif.get_ifd(0x8769)
sub[0x9003] = "2026:09:10 10:00:00"
img.save("/tmp/edited.jpg", "JPEG", exif=exif)
PY
python -m forensics.metadata /tmp/edited.jpg
```

Create an image with no EXIF:

```bash
python -c "from PIL import Image; Image.new('RGB',(64,64),(20,30,40)).save('/tmp/no_exif.png')"
python -m forensics.metadata /tmp/no_exif.png
```

### 7.5 Manual ELA tests (Module 3)

```bash
# Clean control: no dense region, score 0
python -m forensics.ela samples/original/original_demo.jpg

# Foreign patch: high score and one dense region
python -m forensics.ela samples/tampered/spliced_demo.jpg

# Metadata-only edit: pixels are unchanged, so ELA must stay at 0
python -m forensics.ela samples/tampered/edited_metadata.jpg

# Retouch controls: ELA is expected to miss smooth brightness/blur edits
python -m forensics.ela samples/tampered/retouched_demo.jpg
python -m forensics.ela samples/tampered/retouched_strong.jpg
```

Inspect the artifacts:

```text
output/ela_results/ela_<stem>_heat.png
output/ela_results/ela_<stem>_overlay.png
output/ela_results/ela_<stem>_comparison.png
```

### 7.6 Unit tests

```bash
python -m unittest discover -s tests -v
```

Current result:

```text
Ran 34 tests in 8.643s
OK
```

Coverage:

- hashes match `hashlib`
- clean sample consistency
- magic-byte detection
- renamed extension
- double extension
- corrupt file handling
- camera/XMP extraction
- GPS decimal + map link + altitude
- missing EXIF
- editor software
- AI generator metadata
- date mismatch
- future date
- datetime parser
- corrupt metadata input
- clean image scores low in ELA
- spliced image is detected with an overlapping region
- ELA artifacts are written and readable
- metadata-only edit does not raise ELA
- corrupt ELA input returns a structured error
- block-grid and density-map maths
- clean image verdict is likely authentic
- strong ELA signal reaches the tampered band
- metadata-only signal is escalated out of the authentic band
- all-error pipeline is inconclusive
- weights re-normalise over modules that ran
- clean/tampered/metadata reports produce valid PDFs
- a corrupt file still produces an inconclusive report
- directory output and custom case IDs

---

## 8. Output and artifacts

| Path | Content |
|---|---|
| `output/metadata_results/thumb_<name>.png` | Extracted EXIF thumbnail |
| `output/ela_results/ela_<stem>_heat.png` | ELA heatmap |
| `output/ela_results/ela_<stem>_overlay.png` | Heatmap blended on the original, regions outlined |
| `output/ela_results/ela_<stem>_comparison.png` | Side-by-side original/ELA panel |
| `output/copymove_results/` | Copy-move overlay/mask (Module 4) |
| `output/reports/report_<stem>_<ext>.pdf` | Final evidence report |
| `output/cases/<case_id>/evidence/` | Read-only evidence copies (UI phase) |

For Modules 1–3, the primary output is JSON on stdout plus the extracted
thumbnail and the three ELA images.

### Key JSON fields

| Field | Meaning |
|---|---|
| `metrics.hashes.sha256` | Digest to quote in the report |
| `metrics.magic_format` | Real container from bytes |
| `metrics.extension_match` | `false` = renamed/mismatched file |
| `metrics.double_extension` | `true` = `photo.jpg.exe` pattern |
| `metrics.camera` | Make, model, lens, serial, software |
| `metrics.gps` | Decimal, DMS, altitude, OSM link |
| `metrics.timestamps` | EXIF times + filesystem mtime |
| `metrics.editors` / `generators` | Post-processing / AI fingerprints |
| `metrics.thumbnail` | Embedded preview comparison |
| `metrics.residual_threshold` | ELA block cut-off used for this image |
| `metrics.outlier_fraction` | Fraction of blocks above that cut-off |
| `metrics.clusters` | Dense ELA regions with `pixel_bbox`, size, mean residual and ring contrast |
| `findings[].severity` | `critical / high / medium / low / info` |
| `score` | That module's own manipulation signal, 0–100 |

---

## 9. Verdict logic

Implemented in `forensics/verdict.py` and `forensics/pipeline.py`.

```text
weighted = Σ(weight × module score) / Σ(weight of modules that ran)
final    = 0.55 × weighted + 0.45 × strongest module score
```

Module weights: file analysis 0.15, metadata 0.20, ELA 0.20, copy-move 0.30,
steganography 0.15. Because copy-move and stego are not built yet, the weights
are **re-normalised over the modules that actually ran** — a partial pipeline
still produces a meaningful score instead of being capped.

The blend with the strongest module prevents one strong signal (for example
ELA at 84/100) from being diluted to nothing by modules that had no evidence.

| Score | Verdict |
|---:|---|
| 0–19 | **Likely authentic** (no strong manipulation indicators) |
| 20–49 | **Suspicious** (manual review required) |
| 50–100 | **Likely tampered** |
| — | **Inconclusive** (no module completed) |

Two guard-rails stop a contradictory label:

1. A **high-severity finding** always lifts the score to the review band.
2. Any module that **crossed the review threshold (≥ 20)** also lifts the
   blended score to 20, so a supporting signal is never reported as
   "likely authentic". This is why `edited_metadata.jpg` reports
   **Suspicious (20.0)** even though its blended average is only 10.9.

The report always lists supporting *and* contradicting findings, because a
single high score must never be presented without its reasoning.

---

## 10. Configuration (`utils/config.py`)

| Setting | Default | Meaning |
|---|---:|---|
| `MAX_FILE_MB` | 50 | Upload/file size limit |
| `MAX_IMAGE_PIXELS` | 80,000,000 | Decompression-bomb guard |
| `ELA.quality` | 90 | JPEG recompression quality |
| `ELA.amplify` | 15 | Heatmap display gain (does not affect the score) |
| `ELA.block_size` | 16 | Block grid used for statistics |
| `ELA.outlier_z` | 4.0 | Robust cut-off: median + 4×MAD |
| `ELA.abs_floor` | 0.50 | Ignore residual differences below this value |
| `ELA.density_window` | 9 | 9×9-block window for local density |
| `ELA.density_threshold` | 0.50 | At least 50% of a window must be high-residual |
| `ELA.min_cluster_blocks` | 12 | Minimum dense area (12 blocks ≈ 3072 px) |
| `ELA.min_mean_residual` | 0.70 | Minimum mean residual inside a region |
| `ELA.min_contrast` | 2.0 | Region vs surrounding-ring ratio |
| `COPYMOVE.orb_features` | 3000 | ORB keypoint budget |
| `COPYMOVE.match_ratio` | 0.75 | Lowe ratio test |
| `COPYMOVE.min_matches` | 8 | Minimum matches for a finding |
| `STEGO.lsb_entropy_threshold` | 0.92 | LSB-plane suspicion threshold |
| `STEGO.chi_square_p_threshold` | 0.95 | Chi-square attack threshold |
| `VERDICT_BLEND.weighted` | 0.55 | Share of the weighted consensus in the final score |
| `VERDICT_BLEND.strongest` | 0.45 | Share of the strongest module in the final score |

Change these only with a documented reason; the report should state the values
used.

---

## 11. Forensic principles used

1. **Never modify the evidence.** Modules open files read-only; temporary or
   derived images are written under `output/`.
2. **Hash before and after analysis.** SHA-256 is the primary digest; a change
   means the result is invalid.
3. **Record the tool and thresholds.** The report states the version and the
   parameters used, so another examiner can reproduce the result.
4. **Separate observation from interpretation.** `metrics` contains raw facts;
   `findings` contains interpretations with confidence.
5. **Corroborate.** A metadata mismatch, ELA cluster or LSB anomaly is a lead,
   not a verdict. The final score combines independent signals.
6. **Stay offline.** No automatic reverse geocoding, cloud AI or upload. GPS is
   shown as coordinates + an OpenStreetMap link that the examiner opens
   deliberately.

---

## 12. Viva / theory notes

### Cryptographic hashing

A hash maps arbitrary bytes to a fixed-length fingerprint. A one-bit change
produces a completely different digest (avalanche effect). SHA-256 is used for
integrity; MD5/SHA-1 are retained for legacy compatibility but are not
collision-resistant.

### Magic bytes

The first bytes of a file identify the real format (JPEG `FF D8 FF`, PNG
`89 50 4E 47 0D 0A 1A 0A`). The extension is only a name. Comparing magic,
extension and decoder output detects renamed or polyglot files.

### EXIF

Exchangeable Image File Format is a TIFF-style metadata block. It stores camera
make/model, lens, exposure, capture time, GPS and an embedded thumbnail. It can
be edited with libraries such as ExifTool or piexif, so it is corroboration,
not proof.

### Error Level Analysis (ELA)

The image is re-saved as JPEG at a fixed quality (90 by default) and compared
with the original pixel by pixel. Areas edited after the last JPEG save often
have a different recompression residual. The absolute maximum-channel
difference is the ELA residual.

An automatic detector cannot simply threshold that residual: sharp edges,
texture, noise, denoising and repeated JPEG saves all produce residuals. The
tool therefore reduces the residual to a 16×16 block grid and applies four
filters:

1. **Robust cut-off** — a block is high-residual if it exceeds
   `median + 4×MAD` and at least `0.50` in absolute terms.
2. **Local density** — in a 9×9-block window, at least 50% of blocks must be
   high-residual. A real edit is a *filled* region; a horizon, roof line or
   branch is a thin line, so its density stays below the threshold.
3. **Minimum area** — a region must cover at least 12 blocks (≈3072 px).
4. **Ring contrast** — the region's mean residual must be at least 2× the
   median of a surrounding ring. This rejects broad, uniformly textured areas
   that happen to be hot everywhere.

The final heatmap is normalised to the 99.5th percentile for display; the score
uses the raw residual, not the colours. ELA remains a **screening** technique:
it can miss a smooth brightness change or a blur (which lowers the residual),
and a small pasted object can fall below the minimum area.

### Copy-move forgery

A region is copied and pasted elsewhere in the same image. ORB/SIFT keypoints
are extracted, matched with a ratio test, and geometrically verified (RANSAC).
The matched points reveal the duplicated region. Flat/uniform areas have few
keypoints, so block-matching is a useful fallback.

### LSB steganography

In an 8-bit channel, the least-significant bit changes the pixel value by at
most 1 and is visually invisible. Sequential LSB replacement makes the
even/odd value pairs unusually equal, which a chi-square attack can detect. It
also raises the entropy of the LSB plane. JPEG compression destroys most LSB
payloads, so this check is strongest on PNG/BMP/TIFF.

### Appended data

Many formats declare an end marker (PNG `IEND`, JPEG `FF D9`, GIF `3B`). Bytes
after that marker are ignored by viewers but can carry a ZIP, PDF or executable.
The tool extracts and hashes them without executing anything.

### Chain of custody

A documented record of who handled the evidence, when, and what they did. The
hash chain in the UI phase will make tampering with the audit log detectable.

---

## 13. Limitations

- **Not court-validated software.** It is an educational tool, not a
  replacement for validated forensic suites.
- **ELA is not proof.** Strong texture, denoising, resizing and repeated JPEG
  compression create false positives.
- **ELA misses some edits.** A smooth brightness/contrast change does not create
  a new high-frequency residual, and blurring lowers it. Small pasted objects
  can fall below the 12-block minimum area. A negative ELA result is not proof
  of authenticity.
- **ELA detects compression history, not intent.** A region that was re-saved at
  a different quality is flagged even if the change was a harmless export.
- **Copy-move misses some edits.** Flat regions (sky, walls) have few ORB
  keypoints; rotation/scaling can reduce matches; block matching is limited.
- **LSB checks only work on lossless images.** JPEG compression destroys LSB
  payloads; a negative LSB result does not prove there is no steganography.
- **EXIF is easy to forge or strip.** Missing EXIF is common after social media
  and screenshots; an editor tag is not automatically malicious.
- **No reverse geocoding.** The tool stays offline; it provides coordinates and
  an OpenStreetMap link instead of a place name.
- **No PRNU / CFA / deepfake model.** Source-camera identification and
  AI-generated image detection are limited to metadata heuristics.
- **Thresholds are empirical.** They are documented and configurable but not
  trained on a large labelled corpus.
- **Single-file analysis.** No batch mode, case database, video or disk images.
- **GPS link needs a browser and internet** to display the map; the analysis
  itself remains offline.

---

## 14. Future scope

- PRNU-based camera identification and CFA/interpolation analysis
- JPEG ghost and double-compression detection
- Deep-learning tamper/localisation models (CASIA, Coverage, NIST16)
- C2PA / Content Credentials verification
- Perceptual-hash reverse-image-search integration
- Batch analysis and a searchable case database
- Signed, timestamped PDF/A reports with an audit hash chain
- Role-based access and evidence encryption at rest
- Video frame extraction and deepfake detection
- Mobile/field capture companion app
- Integration with Autopsy/FTK as a plug-in

---

## 15. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'forensics'` | Run from the project root, not from inside `forensics/` |
| `externally-managed-environment` | Activate the virtual environment; do not install globally |
| `cv2` import error | `pip install opencv-python-headless` inside the venv |
| `UnidentifiedImageError` | File is corrupt or not an image; Module 1 returns a structured error |
| `DecompressionBombError` | Image exceeds 80 MP; analyse a verified resized copy, never the evidence |
| `PNG file does not have exif data` warning | Harmless ExifRead message; the module handles missing EXIF |
| GPS link does not show a map | The tool is offline; open the link in a browser |
| ELA score is 0 on a visibly edited image | Smooth brightness/blur edits do not change the JPEG residual; rely on copy-move/noise analysis and the heatmap |
| ELA box is offset by up to 16 px | The detector works on a 16×16 block grid; the box is approximate |
| `streamlit: command not found` | Activate `.venv` and `pip install -r requirements.txt` |
| Permission denied on evidence | The tool only reads it; check file permissions, not write access |

---

## 16. Submission checklist

- [x] Module 1: file analysis and integrity
- [x] Module 2: EXIF/GPS metadata
- [x] Module 3: ELA
- [ ] Module 4: copy-move
- [ ] Module 5: steganography
- [x] Module 6: verdict + PDF + Streamlit UI
- [x] `requirements.txt`
- [x] README with setup and test steps
- [x] Unit tests for completed modules
- [ ] Architecture and data-flow diagrams exported to `docs/`
- [ ] Screenshots of clean, edited and stego cases
- [ ] Final PDF report sample
- [ ] Viva notes (Section 12)

---

## 17. Credits and scope

Built as a standalone SPPU CSDF mini project. The EXIF/TIFF parsing approach
was informed by the existing local prototypes `cyber_forensics_lab` and
`digital_forensic`; this tool adds image-specific analysis (ELA, copy-move,
structured verdict, evidence report) that those suites do not provide.

Use only on images you are authorised to examine. The tool is intended for
education, lab exercises and preliminary triage — not as the sole basis for a
legal finding.
