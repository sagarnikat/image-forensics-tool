"""Module 6 (part 2) - PDF evidence report.

One command produces a complete, self-contained report::

    python -m forensics.report samples/tampered/spliced_demo.jpg

The report runs every available analyzer through :mod:`forensics.pipeline`,
then renders a layered PDF:

1. Title block and case metadata
2. Verdict card (score, band, confidence)
3. Executive summary with supporting and contradicting evidence
4. Evidence and integrity facts (hashes, container, timestamps)
5. Per-module score table
6. Findings with severity, confidence and source module
7. Visual evidence (original, ELA comparison, overlay, EXIF thumbnail)
8. Metadata detail (camera, GPS, timestamps, EXIF tags)
9. Method and thresholds (reproducibility)
10. Chain-of-custody declaration and reproduction commands

Forensic rules honoured here
----------------------------
* The evidence file is only read; the display copies are generated in memory.
* Every number in the report comes from the module results, not from the
  renderer, so the PDF cannot disagree with the JSON/CLI output.
* The verdict is presented with its reasoning and a disclaimer.  A PDF is not
  a legal conclusion and the report says so.
"""

from __future__ import annotations

import argparse
import io
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    CondPageBreak,
    Flowable,
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from forensics import SEVERITY_ORDER
from forensics.pipeline import run_pipeline
from forensics.verdict import MODULE_LABELS
from utils import config
from utils.image_utils import human_bytes, safe_name

# --------------------------------------------------------------------- layout
PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 18 * mm
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN
TOP_MARGIN = 22 * mm
BOTTOM_MARGIN = 20 * mm

# --------------------------------------------------------------------- colours
INK = colors.HexColor("#101828")
BODY = colors.HexColor("#344054")
MUTED = colors.HexColor("#667085")
LINE = colors.HexColor("#E4E7EC")
SOFT = colors.HexColor("#F9FAFB")
ACCENT = colors.HexColor("#4338CA")
ACCENT_SOFT = colors.HexColor("#EEF2FF")
GOOD = colors.HexColor("#067647")
GOOD_SOFT = colors.HexColor("#ECFDF3")
WARN = colors.HexColor("#B54708")
WARN_SOFT = colors.HexColor("#FFFAEB")
BAD = colors.HexColor("#B42318")
BAD_SOFT = colors.HexColor("#FEF3F2")
NEUTRAL = colors.HexColor("#475467")
NEUTRAL_SOFT = colors.HexColor("#F2F4F7")

BAND_STYLE = {
    "authentic": (GOOD, GOOD_SOFT),
    "suspicious": (WARN, WARN_SOFT),
    "tampered": (BAD, BAD_SOFT),
    "inconclusive": (NEUTRAL, NEUTRAL_SOFT),
}

SEVERITY_STYLE = {
    "critical": (colors.HexColor("#7A271A"), colors.HexColor("#FEE4E2")),
    "high": (BAD, colors.HexColor("#FEE4E2")),
    "medium": (WARN, colors.HexColor("#FEF0C7")),
    "low": (colors.HexColor("#175CD3"), colors.HexColor("#EFF8FF")),
    "info": (NEUTRAL, NEUTRAL_SOFT),
}

BAND_RANGE = {
    "authentic": "score below 20",
    "suspicious": "score 20 to 49",
    "tampered": "score 50 or above",
    "inconclusive": "not scored",
}

# ------------------------------------------------------------------ typefaces
# matplotlib ships DejaVu, which covers the arrows, degree signs and bullets
# used in the report.  Helvetica is a safe fallback if that ever changes.
FONT = {
    "regular": "Helvetica",
    "bold": "Helvetica-Bold",
    "italic": "Helvetica-Oblique",
    "bold_italic": "Helvetica-BoldOblique",
    "mono": "Courier",
    "mono_bold": "Courier-Bold",
}


def _register_fonts() -> None:
    global FONT
    try:
        import matplotlib

        root = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
        files = {
            "regular": ("PP", "DejaVuSans.ttf"),
            "bold": ("PP-Bold", "DejaVuSans-Bold.ttf"),
            "italic": ("PP-Italic", "DejaVuSans-Oblique.ttf"),
            "bold_italic": ("PP-BoldItalic", "DejaVuSans-BoldOblique.ttf"),
            "mono": ("PPMono", "DejaVuSansMono.ttf"),
            "mono_bold": ("PPMono-Bold", "DejaVuSansMono-Bold.ttf"),
        }
        for key, (name, filename) in files.items():
            pdfmetrics.registerFont(TTFont(name, str(root / filename)))
        pdfmetrics.registerFontFamily(
            "PP", normal="PP", bold="PP-Bold", italic="PP-Italic", boldItalic="PP-BoldItalic"
        )
        pdfmetrics.registerFontFamily("PPMono", normal="PPMono", bold="PPMono-Bold")
        FONT = {key: name for key, (name, _) in files.items()}
    except Exception:  # noqa: BLE001 - the report must build on any machine
        FONT = {
            "regular": "Helvetica",
            "bold": "Helvetica-Bold",
            "italic": "Helvetica-Oblique",
            "bold_italic": "Helvetica-BoldOblique",
            "mono": "Courier",
            "mono_bold": "Courier-Bold",
        }


_register_fonts()


def _make_styles() -> dict[str, ParagraphStyle]:
    def style(name: str, **kwargs: Any) -> ParagraphStyle:
        return ParagraphStyle(name, **kwargs)

    return {
        "eyebrow": style("eyebrow", fontName=FONT["bold"], fontSize=7.2, leading=9, textColor=ACCENT),
        "title": style("title", fontName=FONT["bold"], fontSize=21, leading=25, textColor=INK),
        "subtitle": style("subtitle", fontName=FONT["regular"], fontSize=9.6, leading=13, textColor=MUTED),
        "h1": style("h1", fontName=FONT["bold"], fontSize=12, leading=15, textColor=INK,
                    spaceBefore=12, spaceAfter=6),
        "h2": style("h2", fontName=FONT["bold"], fontSize=9, leading=12, textColor=INK,
                    spaceBefore=8, spaceAfter=3),
        "body": style("body", fontName=FONT["regular"], fontSize=8.7, leading=12.4, textColor=BODY),
        "body_tight": style("body_tight", fontName=FONT["regular"], fontSize=8.4, leading=11.8,
                            textColor=BODY, spaceAfter=0),
        "bullet": style("bullet", fontName=FONT["regular"], fontSize=8.4, leading=11.6, textColor=BODY,
                        leftIndent=10, bulletIndent=2, spaceAfter=2),
        "small": style("small", fontName=FONT["regular"], fontSize=7.3, leading=10, textColor=MUTED),
        "cell": style("cell", fontName=FONT["regular"], fontSize=7.9, leading=10.6, textColor=BODY),
        "cell_bold": style("cell_bold", fontName=FONT["bold"], fontSize=8, leading=10.6, textColor=INK),
        "label": style("label", fontName=FONT["bold"], fontSize=7.1, leading=9, textColor=MUTED),
        "mono": style("mono", fontName=FONT["mono"], fontSize=7.1, leading=10, textColor=BODY),
        "mono_small": style("mono_small", fontName=FONT["mono"], fontSize=6.4, leading=8.6, textColor=BODY),
        "chip": style("chip", fontName=FONT["bold"], fontSize=6.2, leading=7.6, textColor=colors.white,
                      alignment=TA_CENTER),
        "caption": style("caption", fontName=FONT["italic"], fontSize=7, leading=9.4, textColor=MUTED,
                         alignment=TA_CENTER, spaceBefore=3),
        "verdict": style("verdict", fontName=FONT["bold"], fontSize=18, leading=21),
        "verdict_sub": style("verdict_sub", fontName=FONT["regular"], fontSize=8.3, leading=11, textColor=BODY),
        "score_big": style("score_big", fontName=FONT["bold"], fontSize=25, leading=26, textColor=INK,
                           alignment=TA_CENTER),
        "score_caption": style("score_caption", fontName=FONT["regular"], fontSize=6.8, leading=8.4,
                               textColor=MUTED, alignment=TA_CENTER),
        "stat": style("stat", fontName=FONT["bold"], fontSize=9.4, leading=11, textColor=INK,
                      alignment=TA_CENTER),
        "stat_label": style("stat_label", fontName=FONT["regular"], fontSize=6.4, leading=8,
                            textColor=MUTED, alignment=TA_CENTER),
    }


STYLES = _make_styles()


# --------------------------------------------------------------------- helpers

def _esc(value: Any) -> str:
    """Escape arbitrary analyzer text for ReportLab paragraph markup."""
    if value is None:
        return "&mdash;"
    text = str(value)
    text = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    return escape(text).replace("\n", "<br/>")


def _p(value: Any, style: str | ParagraphStyle) -> Paragraph:
    if isinstance(style, str):
        style = STYLES[style]
    return Paragraph(_esc(value), style)


def _bullets(items: Iterable[str], style: str = "bullet") -> list[Paragraph]:
    return [Paragraph(f"&#8226;&nbsp;&nbsp;{_esc(item)}", STYLES[style]) for item in items]


def _section(title: str, number: int | None = None, min_space: float = 46) -> list[Any]:
    """Section heading that never leaves an orphan at the bottom of a page."""
    heading = f"{number}. {title}" if number is not None else title
    return [CondPageBreak(min_space * mm), Paragraph(_esc(heading), STYLES["h1"])]


def _h2(title: str) -> list[Any]:
    return [CondPageBreak(32 * mm), Paragraph(_esc(title), STYLES["h2"])]


def _image_flow(path: str | Path | None, max_width: float, max_height: float) -> Image | None:
    """Build a ReportLab image from a downscaled in-memory PNG, or ``None``."""
    if not path:
        return None
    try:
        candidate = Path(path)
        if not candidate.is_file():
            return None
        with PILImage.open(candidate) as source:
            image = source.convert("RGB")
            source_width, source_height = image.size
            image.thumbnail((1800, 1800), PILImage.Resampling.LANCZOS)
            buffer = io.BytesIO()
            image.save(buffer, "JPEG", quality=88, optimize=True)
            width, height = image.size
        buffer.seek(0)
        scale = min(max_width / width, max_height / height, 1.0)
        return Image(buffer, width=width * scale, height=height * scale)
    except Exception:  # noqa: BLE001 - a missing artifact must not break the PDF
        return None


def _figure(path: str | Path | None, caption: str, max_width: float, max_height: float) -> list[Any]:
    flowable = _image_flow(path, max_width, max_height)
    if flowable is None:
        return []
    frame = Table([[flowable]], colWidths=[flowable.drawWidth + 6])
    frame.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    frame.hAlign = "CENTER"
    return [frame, Paragraph(_esc(caption), STYLES["caption"])]


class ScoreBar(Flowable):
    """Small horizontal bar used in the module score table."""

    def __init__(self, value: float, width: float = 30 * mm, height: float = 5.5) -> None:
        super().__init__()
        self.value = max(0.0, min(100.0, float(value)))
        self.width = width
        self.height = height

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        canvas.setFillColor(colors.HexColor("#EAECF0"))
        canvas.roundRect(0, 0, self.width, self.height, self.height / 2, stroke=0, fill=1)
        if self.value <= 0:
            return
        color = GOOD if self.value < 20 else WARN if self.value < 50 else BAD
        canvas.setFillColor(color)
        filled = max(self.height, self.width * self.value / 100.0)
        canvas.roundRect(0, 0, min(self.width, filled), self.height, self.height / 2, stroke=0, fill=1)


def _kv_table(rows: list[tuple[str, Any]], *, label_width: float = 34 * mm,
              mono_keys: set[str] | None = None,
              uppercase: bool = True) -> Table:
    mono_keys = mono_keys or set()
    data = []
    for label, value in rows:
        value_style = "mono" if label in mono_keys else "cell"
        shown = label.upper() if uppercase else label
        data.append([_p(shown, "label"), _p(value, value_style)])
    table = Table(data, colWidths=[label_width, CONTENT_WIDTH - label_width])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4.2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4.2),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
            ]
        )
    )
    return table


def _chip(text: str, color: colors.Color, background: colors.Color) -> Table:
    label_style = ParagraphStyle(
        f"chip_{text}_{id(background)}",
        parent=STYLES["chip"],
        textColor=color,
    )
    chip = Table([[Paragraph(_esc(text.upper()), label_style)]], colWidths=[20 * mm])
    chip.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("TEXTCOLOR", (0, 0), (-1, -1), color),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2.4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return chip


class NumberedCanvas(pdfcanvas.Canvas):
    """Two-pass canvas so the footer can print ``Page X of Y``."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:  # noqa: N802 - ReportLab API
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(total)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_page_number(self, total: int) -> None:
        self.saveState()
        self.setFont(FONT["regular"], 6.8)
        self.setFillColor(MUTED)
        self.drawRightString(PAGE_WIDTH - MARGIN, 10.2 * mm, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _decorate(canvas: pdfcanvas.Canvas, doc: Any) -> None:
    """Header bar on every page and a footer rule on every page."""
    data = doc.pp_data
    canvas.saveState()

    if doc.page > 1:
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_HEIGHT - 9 * mm, PAGE_WIDTH, 9 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont(FONT["bold"], 7.4)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 6.1 * mm, "PIXELPROOF")
        canvas.setFont(FONT["regular"], 7.1)
        canvas.drawRightString(
            PAGE_WIDTH - MARGIN,
            PAGE_HEIGHT - 6.1 * mm,
            f"{data['case_id']}  ·  {data['name']}",
        )
    else:
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_HEIGHT - 6 * mm, PAGE_WIDTH, 6 * mm, stroke=0, fill=1)

    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.6)
    canvas.line(MARGIN, 15 * mm, PAGE_WIDTH - MARGIN, 15 * mm)
    canvas.setFont(FONT["regular"], 6.7)
    canvas.setFillColor(MUTED)
    digest = (
        f"SHA-256 {data['sha256'][:20]}…" if data["sha256"] else "SHA-256 not computed"
    )
    canvas.drawString(
        MARGIN,
        10.2 * mm,
        f"PixelProof {config.VERSION}  ·  {digest}  ·  read-only examination",
    )
    canvas.restoreState()


# ------------------------------------------------------------------ data access

def _result(results: list[dict[str, Any]], module: str) -> dict[str, Any] | None:
    return next((item for item in results if item.get("module") == module), None)


def _metrics(results: list[dict[str, Any]], module: str) -> dict[str, Any]:
    result = _result(results, module)
    return result.get("metrics", {}) if result and result.get("status") == "ok" else {}


def _band_range(band: str) -> str:
    return BAND_RANGE.get(band, "not scored")


def _pretty_time(value: Any) -> str:
    """Render an ISO timestamp in a readable forensic form."""
    text = str(value)
    if "T" in text and len(text) >= 19:
        return text.replace("T", " ", 1)[:19] + " UTC"
    return text


# ------------------------------------------------------------------ story parts

def _title_block(pipeline: dict[str, Any], case: dict[str, Any]) -> list[Any]:
    story: list[Any] = [
        Paragraph("DIGITAL FORENSICS &nbsp;·&nbsp; IMAGE EXAMINATION", STYLES["eyebrow"]),
        Spacer(1, 4),
        Paragraph("Image Forensic Examination Report", STYLES["title"]),
        Spacer(1, 3),
        Paragraph(f"Evidence file: <b>{_esc(case['name'])}</b>", STYLES["subtitle"]),
        Spacer(1, 9),
    ]

    strip = Table(
        [
            [
                _p("CASE ID", "label"),
                _p("EXAMINER", "label"),
                _p("GENERATED (UTC)", "label"),
                _p("TOOL", "label"),
            ],
            [
                _p(case["case_id"], "cell_bold"),
                _p(case["examiner"], "cell"),
                _p(case["generated"], "cell"),
                _p(f"PixelProof {config.VERSION}", "cell"),
            ],
        ],
        colWidths=[CONTENT_WIDTH * 0.28, CONTENT_WIDTH * 0.26, CONTENT_WIDTH * 0.26, CONTENT_WIDTH * 0.20],
    )
    strip.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SOFT),
                ("LINEABOVE", (0, 0), (-1, 0), 0.6, LINE),
                ("LINEBELOW", (0, -1), (-1, -1), 0.6, LINE),
                ("LINEBEFORE", (1, 0), (-1, -1), 0.5, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(strip)
    return story


def _verdict_card(verdict: dict[str, Any]) -> list[Any]:
    color, soft = BAND_STYLE.get(verdict["band"], (NEUTRAL, NEUTRAL_SOFT))
    evaluated = len(verdict.get("evaluated", []))
    coverage = evaluated / max(1, evaluated + len(verdict.get("skipped", [])))

    left = [
        Paragraph(_esc(verdict["label"]), ParagraphStyle(
            "verdict_dynamic", parent=STYLES["verdict"], textColor=color)),
        Spacer(1, 2),
        Paragraph(_esc(verdict["headline"]), STYLES["verdict_sub"]),
        Spacer(1, 4),
        Paragraph(
            f"Confidence {verdict['confidence'] * 100:.0f}% &nbsp;·&nbsp; "
            f"coverage {evaluated} module(s) &nbsp;·&nbsp; "
            f"agreement {verdict['agreement'] * 100:.0f}%",
            STYLES["small"],
        ),
    ]
    right = [
        Paragraph(f"{verdict['score']:.1f}", STYLES["score_big"]),
        Paragraph("out of 100", STYLES["score_caption"]),
    ]

    card = Table([[left, right]], colWidths=[CONTENT_WIDTH - 38 * mm, 38 * mm])
    card.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), soft),
                ("LINEBEFORE", (0, 0), (0, -1), 3.2, color),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#EAECF0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (0, 0), 12),
                ("RIGHTPADDING", (0, 0), (0, 0), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    strongest = verdict.get("strongest")
    strongest_text = (
        f"the strongest single module ({strongest['score']:.1f})"
        if strongest
        else "no usable module score"
    )
    return [Spacer(1, 10), card, Paragraph(
        f"<b>Banding:</b> {_band_range(verdict['band'])} &nbsp;·&nbsp; "
        f"final score blends the weighted consensus ({verdict['weighted']:.1f}) with "
        f"{strongest_text}.",
        STYLES["small"],
    )]


def _executive_summary(pipeline: dict[str, Any]) -> list[Any]:
    verdict = pipeline["verdict"]
    counts = verdict["severity_counts"]
    findings_total = counts.get("critical", 0) + counts.get("high", 0) + counts.get("medium", 0) + counts.get("low", 0)
    strongest = verdict.get("strongest") or {"label": "none", "score": 0.0}

    story = _section("Executive summary", 1)
    if not verdict["evaluated"]:
        story.append(Paragraph(
            f"<b>No analysis module completed successfully in {pipeline['duration_s']:.1f} s</b>, "
            "so no manipulation score could be computed. The evidence may be corrupt, truncated, "
            "empty or not an image at all. The structured error from each module is reproduced "
            "under Findings; the file itself should be preserved unchanged and re-obtained from "
            "the source where possible.",
            STYLES["body"],
        ))
        return story

    story.append(Paragraph(
        f"PixelProof executed <b>{len(verdict['evaluated'])}</b> analysis module(s) in "
        f"<b>{pipeline['duration_s']:.1f} s</b>.  The combined manipulation score is "
        f"<b>{verdict['score']:.1f}/100</b>, placing the image in the "
        f"<b>{_esc(verdict['label'])}</b> band ({_esc(_band_range(verdict['band']))}).  "
        f"The strongest contribution came from <b>{_esc(strongest['label'])}</b> "
        f"({strongest['score']:.1f}/100).  "
        f"<b>{findings_total}</b> finding(s) above info level were recorded: "
        f"{counts.get('high', 0)} high, {counts.get('medium', 0)} medium, "
        f"{counts.get('low', 0)} low.",
        STYLES["body"],
    ))

    if verdict.get("supporting"):
        story.extend(_h2("Signals supporting manipulation"))
        story.extend(_bullets(verdict["supporting"]))

    if verdict.get("contradicting"):
        story.extend(_h2("Signals against manipulation"))
        story.extend(_bullets(verdict["contradicting"]))

    for note in verdict.get("escalations", []):
        story.append(Paragraph(_esc(note), STYLES["small"]))

    if pipeline.get("not_available"):
        story.append(Paragraph(
            "Not available in this build: "
            + ", ".join(MODULE_LABELS.get(name, name) for name in pipeline["not_available"])
            + ". These modules are excluded from the score rather than scored as zero.",
            STYLES["small"],
        ))

    return story


def _evidence_section(pipeline: dict[str, Any]) -> list[Any]:
    results = pipeline["results"]
    file_metrics = _metrics(results, "file_analysis")
    hashes = file_metrics.get("hashes", {})
    timestamps = file_metrics.get("timestamps", {})

    story = _section("Evidence and integrity", 2)
    if not file_metrics:
        file_result = _result(results, "file_analysis")
        story.append(_p(
            (file_result or {}).get("summary", "The evidence file could not be analysed."),
            "body",
        ))
        return story

    extension = file_metrics.get("extension", "")
    match = file_metrics.get("extension_match")
    match_text = "match" if match else "MISMATCH"
    container = (
        f"{file_metrics.get('format', '?')} · magic {file_metrics.get('magic_format') or 'unknown'} · "
        f"extension {extension} ({match_text})"
    )

    rows: list[tuple[str, Any]] = [
        ("File name", file_metrics.get("name", pipeline["name"])),
        ("Full path", file_metrics.get("path", pipeline["path"])),
        ("Size", f"{file_metrics.get('size_human', '?')} ({file_metrics.get('size_bytes', 0):,} bytes)"),
        ("Container", container),
        ("Dimensions", f"{file_metrics.get('width', 0)} x {file_metrics.get('height', 0)} px · "
                        f"{file_metrics.get('megapixels', 0)} MP · {file_metrics.get('mode', '?')} mode"),
        ("Frames", file_metrics.get("frames", 1)),
        ("Filesystem modified", timestamps.get("modified", "unknown")),
        ("Analysis window", f"{pipeline['started_at']} to {pipeline['finished_at']} ({pipeline['duration_s']:.2f} s)"),
        ("SHA-256", hashes.get("sha256", "not computed")),
        ("SHA-1", hashes.get("sha1", "not computed")),
        ("MD5", hashes.get("md5", "not computed")),
    ]

    table = _kv_table(rows, mono_keys={"SHA-256", "SHA-1", "MD5", "Full path"})
    story.append(table)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Hashes cover the exact bytes on disk. Re-hashing the same file later must reproduce "
        "SHA-256 exactly; any difference invalidates this report's link to the evidence.",
        STYLES["small"],
    ))
    return story


def _module_section(pipeline: dict[str, Any]) -> list[Any]:
    results = pipeline["results"]
    verdict = pipeline["verdict"]
    story = _section("Module results", 3)

    header = [
        _p("Module", "label"),
        _p("Status", "label"),
        _p("Weight", "label"),
        _p("Signal", "label"),
        _p("Score", "label"),
        _p("Summary", "label"),
    ]
    data: list[list[Any]] = [header]
    for result in results:
        name = result["module"]
        label = MODULE_LABELS.get(name, name)
        status = result.get("status", "ok")
        weight = verdict["weights_used"].get(name)
        score = float(result.get("score", 0.0))

        status_color = GOOD if status == "ok" else BAD
        status_style = ParagraphStyle(
            "status_dynamic", parent=STYLES["cell"],
            textColor=status_color, fontName=FONT["bold"], fontSize=7.2,
        )

        score_style = ParagraphStyle(
            "score_dynamic", parent=STYLES["cell_bold"],
            textColor=GOOD if score < 20 else WARN if score < 50 else BAD,
        )
        ok = status == "ok"
        data.append(
            [
                _p(label, "cell_bold"),
                Paragraph(_esc(status.upper()), status_style),
                _p(f"{weight:.2f}" if weight is not None else "—", "cell"),
                ScoreBar(score) if ok else _p("—", "cell"),
                Paragraph(f"{score:.1f}", score_style) if ok else _p("—", "cell"),
                _p(result.get("summary", ""), "cell"),
            ]
        )

    table = Table(
        data,
        colWidths=[31 * mm, 14 * mm, 15 * mm, 34 * mm, 13 * mm, CONTENT_WIDTH - 107 * mm],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F4F7")),
                ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (2, 1), (4, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
                ("LINEBELOW", (0, -1), (-1, -1), 0.6, LINE),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Weights are re-normalised over the modules that ran, so a partial pipeline still "
        "produces a meaningful score. The Signal column is each module's own 0-100 "
        "manipulation signal, not the final verdict.",
        STYLES["small"],
    ))
    return story


def _findings_section(pipeline: dict[str, Any]) -> list[Any]:
    entries: list[tuple[str, dict[str, Any]]] = []
    for result in pipeline["results"]:
        for item in result.get("findings", []):
            entries.append((result["module"], item))
    entries.sort(key=lambda pair: (
        SEVERITY_ORDER.get(pair[1].get("severity", "info"), 9),
        -float(pair[1].get("confidence", 0)),
    ))

    story = _section("Findings", 4)
    if not entries:
        story.append(Paragraph("No findings were recorded by any module.", STYLES["body"]))
        return story

    rows: list[list[Any]] = []
    for module, item in entries:
        severity = item.get("severity", "info")
        color, soft = SEVERITY_STYLE.get(severity, (NEUTRAL, NEUTRAL_SOFT))
        meta = (
            f"Source: {MODULE_LABELS.get(module, module)} &nbsp;·&nbsp; "
            f"Confidence {float(item.get('confidence', 0)) * 100:.0f}%"
        )
        tags = item.get("tags") or []
        if tags:
            meta += " &nbsp;·&nbsp; " + ", ".join(_esc(tag) for tag in tags)

        content = [
            Paragraph(_esc(item.get("title", "Finding")), STYLES["cell_bold"]),
            Spacer(1, 1.5),
            Paragraph(_esc(item.get("detail", "")), STYLES["cell"]),
            Spacer(1, 1.5),
            Paragraph(meta, STYLES["small"]),
        ]
        rows.append([
            _chip(severity, color, soft),
            content,
        ])

    table = Table(rows, colWidths=[22 * mm, CONTENT_WIDTH - 22 * mm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (0, -1), 0),
                ("RIGHTPADDING", (0, 0), (0, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
            ]
        )
    )
    story.append(table)
    return story


def _visual_section(pipeline: dict[str, Any]) -> list[Any]:
    results = pipeline["results"]
    ela = _result(results, "ela")
    metadata = _result(results, "metadata")
    story = _section("Visual evidence", 5, min_space=104)
    figures: list[Any] = []

    original = pipeline.get("path")
    original_figure = _figure(
        original, "Figure 1 — Evidence image as submitted (display copy only).",
        CONTENT_WIDTH, 92 * mm,
    )
    if original_figure:
        figures.append(CondPageBreak(70 * mm))
        figures.extend(original_figure)

    if ela and ela.get("status") == "ok":
        artifacts = [Path(item) for item in ela.get("artifacts", [])]
        sheet = next((path for path in artifacts if path.name.endswith("_comparison.png")), None)
        overlay = next((path for path in artifacts if path.name.endswith("_overlay.png")), None)
        heat = next((path for path in artifacts if path.name.endswith("_heat.png")), None)

        if sheet:
            figures.append(CondPageBreak(60 * mm))
            figures.extend(_figure(
                sheet,
                "Figure 2 — Original (left) and ELA heatmap (right). Bright areas changed most "
                "after recompression at the configured quality.",
                CONTENT_WIDTH, 88 * mm,
            ))

        pair = [path for path in (overlay, heat) if path]
        if len(pair) == 2:
            left = _image_flow(pair[0], CONTENT_WIDTH / 2 - 8, 58 * mm)
            right = _image_flow(pair[1], CONTENT_WIDTH / 2 - 8, 58 * mm)
            if left and right:
                figures.append(CondPageBreak(55 * mm))
                panel = Table(
                    [
                        [left, right],
                        [
                            Paragraph("Figure 3 — ELA overlay with detected regions outlined", STYLES["caption"]),
                            Paragraph("Figure 4 — Colourised ELA residual", STYLES["caption"]),
                        ],
                    ],
                    colWidths=[CONTENT_WIDTH / 2, CONTENT_WIDTH / 2],
                )
                panel.setStyle(
                    TableStyle(
                        [
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 0), (-1, -1), 2),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                            ("LEFTPADDING", (0, 0), (-1, -1), 2),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                        ]
                    )
                )
                figures.append(panel)

    if metadata and metadata.get("status") == "ok":
        thumbnail = metadata.get("metrics", {}).get("thumbnail", {})
        artifact = thumbnail.get("artifact")
        thumbnail_figure = _figure(
            artifact,
            "Figure 5 — Thumbnail embedded in the EXIF block. A large visual difference from "
            "Figure 1 indicates the main image was replaced after capture.",
            65 * mm, 55 * mm,
        )
        if thumbnail_figure:
            figures.append(CondPageBreak(50 * mm))
            figures.extend(thumbnail_figure)

    if not figures:
        story.append(Paragraph("No visual artifacts were produced for this evidence.", STYLES["body"]))
    else:
        story.extend(figures)
    return story


def _metadata_section(pipeline: dict[str, Any]) -> list[Any]:
    metrics = _metrics(pipeline["results"], "metadata")
    story = _section("Metadata detail", 6, min_space=72)

    if not metrics:
        story.append(Paragraph("Metadata could not be read for this evidence.", STYLES["body"]))
        return story

    camera = metrics.get("camera", {})
    if camera:
        rows = [
            ("Make", camera.get("make", "—")),
            ("Model", camera.get("model", "—")),
            ("Lens", camera.get("lens", "—")),
            ("Body serial", camera.get("serial", "—")),
            ("Software", camera.get("software", "—")),
            ("Artist", camera.get("artist", "—")),
            ("Copyright", camera.get("copyright", "—")),
        ]
        story.extend(_h2("Camera and software"))
        story.append(_kv_table(rows))
    else:
        story.extend(_h2("Camera and software"))
        story.append(Paragraph("No camera identity tags were present.", STYLES["body"]))

    gps = metrics.get("gps")
    story.extend(_h2("Location"))
    if gps:
        rows = [
            ("Latitude", f"{gps['latitude']:.6f} ({gps['latitude_dms']})"),
            ("Longitude", f"{gps['longitude']:.6f} ({gps['longitude_dms']})"),
            ("Altitude", f"{gps.get('altitude_m')} m" if gps.get("altitude_m") is not None else "not recorded"),
            ("GPS UTC", gps.get("utc") or "not recorded"),
        ]
        story.append(_kv_table(rows))
        link = Paragraph(
            f'<link href="{_esc(gps["map_url"])}" color="#4338CA">{_esc(gps["map_url"])}</link>',
            STYLES["mono_small"],
        )
        story.append(Spacer(1, 3))
        story.append(link)
        story.append(Paragraph(
            "Coordinates are shown as stored. The tool does not reverse-geocode online, so the "
            "location name is not inferred and no evidence leaves the machine.",
            STYLES["small"],
        ))
    else:
        story.append(Paragraph("No GPS block was present.", STYLES["body"]))

    timestamps = metrics.get("timestamps", {})
    if timestamps:
        story.extend(_h2("Timestamp coherence"))
        time_labels = {
            "DateTimeOriginal": "Capture time",
            "DateTimeDigitized": "Digitised time",
            "DateTime": "Tag change time",
            "FileModified": "File modified",
            "OffsetTimeOriginal": "Capture offset",
            "OffsetTimeDigitized": "Digitised offset",
            "OffsetTime": "Tag offset",
        }
        story.append(_kv_table(
            [(time_labels.get(key, key), _pretty_time(value)) for key, value in timestamps.items()],
            uppercase=False,
        ))

    editors = metrics.get("editors", [])
    generators = metrics.get("generators", [])
    story.extend(_h2("Provenance keywords"))
    story.append(_kv_table([
        ("Editing software", ", ".join(editors) if editors else "none detected"),
        ("AI generators", ", ".join(generators) if generators else "none detected"),
        ("EXIF tags read", metrics.get("tag_count", 0)),
        ("ICC profile", "present" if metrics.get("icc_profile") else "absent"),
    ], uppercase=False))

    tags = metrics.get("tags", {})
    if tags:
        limit = 45
        items = sorted(tags.items())[:limit]
        data = [[_p("Tag", "label"), _p("Value", "label")]]
        data += [[_p(key, "cell_bold"), _p(value, "cell")] for key, value in items]
        table = Table(data, colWidths=[58 * mm, CONTENT_WIDTH - 58 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F4F7")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.4),
                    ("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE),
                ]
            )
        )
        story.extend(_h2("EXIF tags"))
        story.append(table)
        if len(tags) > limit:
            story.append(Paragraph(
                f"Showing {limit} of {len(tags)} tags. The full dump is retained in the module result.",
                STYLES["small"],
            ))

    return story


def _method_section(pipeline: dict[str, Any]) -> list[Any]:
    story = _section("Method and thresholds", 7)
    story.append(Paragraph(
        "Every threshold used below is stored in <font name=\"%s\">utils/config.py</font>. "
        "They are empirical values chosen for this project's sample set, not trained on a "
        "labelled corpus. The report records them so another examiner can reproduce the run."
        % FONT["mono"],
        STYLES["body"],
    ))

    rows = [
        (
            "File analysis",
            "MD5, SHA-1 and SHA-256 over the exact bytes; magic-byte container detection; "
            f"extension agreement; double-extension regex; {config.MAX_FILE_MB} MB and "
            f"{config.MAX_IMAGE_PIXELS:,} pixel limits.",
        ),
        (
            "Metadata",
            "ExifRead tag extraction; GPS rationals to decimal, DMS and OSM link; timestamp "
            "coherence checks; editing and AI keyword lists; EXIF thumbnail dHash compared with "
            "the main image (Hamming distance > 16 is a mismatch).",
        ),
        (
            "ELA",
            f"JPEG re-save at quality {config.ELA['quality']}; {config.ELA['block_size']} px blocks; "
            f"robust threshold median + {config.ELA['outlier_z']:g}×MAD with an absolute floor of "
            f"{config.ELA['abs_floor']}; {config.ELA['density_window']}×{config.ELA['density_window']}"
            f" density window requiring {config.ELA['density_threshold'] * 100:.0f}% high-residual "
            f"blocks; at least {config.ELA['min_cluster_blocks']} blocks; mean residual ≥ "
            f"{config.ELA['min_mean_residual']}; region/ring contrast ≥ {config.ELA['min_contrast']}.",
        ),
    ]
    if "copymove" in pipeline.get("available", []):
        rows.append(("Copy-move", "ORB keypoints, Lowe ratio test, RANSAC geometric verification."))
    if "stego" in pipeline.get("available", []):
        rows.append(("Steganography", "LSB entropy, chi-square attack and appended-payload scan."))
    if pipeline.get("not_available"):
        rows.append((
            "Not available",
            ", ".join(MODULE_LABELS.get(name, name) for name in pipeline["not_available"])
            + " — excluded from scoring in this build.",
        ))

    data = [[_p("Module", "label"), _p("Settings used", "label")]]
    data += [[_p(name, "cell_bold"), _p(text, "cell")] for name, text in rows]
    table = Table(data, colWidths=[32 * mm, CONTENT_WIDTH - 32 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F4F7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE),
            ]
        )
    )
    story.append(table)

    story.extend(_h2("Verdict formula"))
    story.append(Paragraph(
        "<font name=\"%s\">weighted = sum(weight × module score) / sum(weight)</font><br/>"
        "<font name=\"%s\">final = %.2f × weighted + %.2f × strongest module</font><br/>"
        "Weights: file %.2f, metadata %.2f, ELA %.2f, copy-move %.2f, stego %.2f."
        % (
            FONT["mono"],
            FONT["mono"],
            config.VERDICT_BLEND["weighted"],
            config.VERDICT_BLEND["strongest"],
            config.MODULE_WEIGHTS["file_analysis"],
            config.MODULE_WEIGHTS["metadata"],
            config.MODULE_WEIGHTS["ela"],
            config.MODULE_WEIGHTS["copymove"],
            config.MODULE_WEIGHTS["stego"],
        ),
        STYLES["body_tight"],
    ))

    band_rows = [[_p("Band", "label"), _p("Score", "label"), _p("Meaning", "label")]]
    meanings = {
        "authentic": "No strong tampering signal; still requires examiner judgement.",
        "suspicious": "At least one signal warrants review and corroboration.",
        "tampered": "A strong signal is consistent with manipulation.",
        "inconclusive": "Not enough usable evidence to score.",
    }
    for band in ("authentic", "suspicious", "tampered", "inconclusive"):
        color, soft = BAND_STYLE[band]
        band_rows.append([
            _p(verdict_label(band), "cell_bold"),
            _p(_band_range(band), "cell"),
            _p(meanings[band], "cell"),
        ])
        band_rows[-1][0] = Paragraph(
            _esc(verdict_label(band)),
            ParagraphStyle("band_dynamic", parent=STYLES["cell_bold"], textColor=color),
        )

    band_table = Table(band_rows, colWidths=[38 * mm, 34 * mm, CONTENT_WIDTH - 72 * mm], repeatRows=1)
    band_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F4F7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE),
            ]
        )
    )
    story.append(Spacer(1, 6))
    story.append(band_table)

    story.extend(_h2("Limitations"))
    story.extend(_bullets([
        "ELA detects compression-history discontinuity, not intent. Smooth brightness changes and "
        "blurring can produce a low score even when the image was edited.",
        "A negative result is not proof of authenticity. Absence of evidence is not evidence of absence.",
        "Copy-move and steganography modules are not part of this build, so duplicated regions and "
        "LSB payloads are not assessed here.",
        "EXIF can be forged or stripped. Editor tags are leads, not findings of malicious intent.",
        "Thresholds are empirical and were not validated against a large labelled corpus.",
        "This tool is an educational prototype, not court-validated forensic software.",
    ]))
    return story


def verdict_label(band: str) -> str:
    return {
        "authentic": "Likely authentic",
        "suspicious": "Suspicious",
        "tampered": "Likely tampered",
        "inconclusive": "Inconclusive",
    }.get(band, band.title())


def _custody_section(pipeline: dict[str, Any], case: dict[str, Any]) -> list[Any]:
    story = _section("Declaration and chain of custody", 8)
    story.append(Paragraph(
        "The evidence file was opened read-only for this examination. All derived images, "
        "heatmaps and thumbnails were written under <font name=\"%s\">output/</font>; the original "
        "bytes were never modified. The SHA-256 digest printed in Section 2 can be recomputed at "
        "any time to prove that the examined file is unchanged." % FONT["mono"],
        STYLES["body"],
    ))
    story.append(Spacer(1, 4))

    table = Table(
        [
            [_p("EXAMINED BY", "label"), _p(case["examiner"], "cell")],
            [_p("DATE (UTC)", "label"), _p(case["generated"], "cell")],
            [_p("CASE ID", "label"), _p(case["case_id"], "mono")],
            [_p("SIGNATURE", "label"), _p("", "cell")],
        ],
        colWidths=[34 * mm, CONTENT_WIDTH - 34 * mm],
        rowHeights=[None, None, None, 14 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
                ("LINEBELOW", (0, -1), (-1, -1), 0.6, INK),
            ]
        )
    )
    story.append(table)

    story.extend(_h2("Disclaimer"))
    story.append(Paragraph(
        "This report is the output of an automated screening tool. Findings are investigative "
        "leads, not legal proof. A qualified examiner must interpret them alongside the original "
        "evidence, the chain of custody and any corroborating sources. Scores are relative to the "
        "documented thresholds and do not express a probability of tampering.",
        STYLES["small"],
    ))

    story.extend(_h2("Reproduction"))
    story.append(Paragraph(
        f"<font name=\"{FONT['mono']}\">python -m forensics.report {_esc(pipeline['path'])}</font><br/>"
        f"<font name=\"{FONT['mono']}\">python -m unittest discover -s tests -v</font>",
        STYLES["mono"],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph("— End of report —", STYLES["caption"]))
    return story


# --------------------------------------------------------------------- build

def _make_case_id(sha256: str, when: datetime) -> str:
    suffix = (sha256 or "0" * 4)[:4].upper()
    return f"PP-{when:%Y%m%d}-{when:%H%M%S}-{suffix}"


def build_pdf(
    pipeline: dict[str, Any],
    output_path: str | Path,
    *,
    examiner: str = "",
    case_id: str | None = None,
) -> dict[str, Any]:
    """Render a pipeline result into a PDF and return build facts."""
    generated_dt = datetime.now(timezone.utc)
    file_metrics = _metrics(pipeline["results"], "file_analysis")
    sha256 = file_metrics.get("hashes", {}).get("sha256", "")

    case = {
        "case_id": case_id or _make_case_id(sha256, generated_dt),
        "examiner": examiner.strip() or "Not recorded",
        "generated": generated_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "name": pipeline["name"],
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    story: list[Any] = []
    story.extend(_title_block(pipeline, case))
    story.extend(_verdict_card(pipeline["verdict"]))
    story.extend(_executive_summary(pipeline))
    story.extend(_evidence_section(pipeline))
    story.extend(_module_section(pipeline))
    story.extend(_findings_section(pipeline))
    story.extend(_visual_section(pipeline))
    story.extend(_metadata_section(pipeline))
    story.extend(_method_section(pipeline))
    story.extend(_custody_section(pipeline, case))

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title=f"Image Forensic Examination Report — {pipeline['name']}",
        author=case["examiner"],
        subject=f"{case['case_id']} · {pipeline['verdict']['label']} · score {pipeline['verdict']['score']}/100",
        creator=f"PixelProof {config.VERSION}",
    )
    document.pp_data = {"case_id": case["case_id"], "name": case["name"], "sha256": sha256}

    document.build(story, onFirstPage=_decorate, onLaterPages=_decorate, canvasmaker=NumberedCanvas)

    return {
        "path": str(output_path),
        "case_id": case["case_id"],
        "pages": getattr(document, "page", 0),
        "size_bytes": output_path.stat().st_size,
        "verdict": pipeline["verdict"],
    }


def generate_report(
    image: str | Path,
    *,
    output_path: str | Path | None = None,
    examiner: str = "",
    case_id: str | None = None,
    include_optional: bool = True,
    pipeline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the full pipeline on one image and write the PDF report."""
    image = Path(image).expanduser()
    if not image.is_file():
        raise FileNotFoundError(f"Evidence file not found: {image}")

    pipeline = pipeline or run_pipeline(image, include_optional=include_optional)
    if output_path is None:
        extension = image.suffix.lstrip(".").lower() or "img"
        destination = config.REPORT_DIR / f"report_{safe_name(image.stem)}_{extension}.pdf"
    else:
        destination = Path(output_path).expanduser()
        if destination.is_dir():
            extension = image.suffix.lstrip(".").lower() or "img"
            destination = destination / f"report_{safe_name(image.stem)}_{extension}.pdf"

    facts = build_pdf(pipeline, destination, examiner=examiner, case_id=case_id)
    facts["pipeline"] = pipeline
    return facts


def open_report(path: str | Path) -> tuple[bool, str]:
    """Open the PDF with the platform viewer. Returns (opened, reason)."""
    path = Path(path)
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.Popen(["open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, ""
        if system == "Windows":
            os.startfile(str(path))  # type: ignore[attr-defined]
            return True, ""
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return False, "no graphical session detected (DISPLAY/WAYLAND_DISPLAY unset)"
        subprocess.Popen(
            ["xdg-open", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True, ""
    except Exception as exc:  # noqa: BLE001 - opening is a convenience, not the deliverable
        return False, str(exc)


# ----------------------------------------------------------------------- CLI

def _print_summary(facts: dict[str, Any], opened: tuple[bool, str] | None) -> None:
    verdict = facts["verdict"]
    pipeline = facts["pipeline"]
    scores = " · ".join(
        f"{MODULE_LABELS.get(name, name)} {score:.1f}"
        for name, score in verdict["module_scores"].items()
    )
    print()
    print("PixelProof — image forensic report")
    print(f"  evidence : {pipeline['path']}")
    print(f"  verdict  : {verdict['label']}  ({verdict['score']:.1f}/100, confidence {verdict['confidence'] * 100:.0f}%)")
    print(f"  modules  : {scores or 'none completed'}")
    if pipeline.get("not_available"):
        print(f"  skipped  : {', '.join(pipeline['not_available'])} (not in this build)")
    print(f"  report   : {facts['path']}  ({human_bytes(facts['size_bytes'])})")
    if opened is not None:
        if opened[0]:
            print("  viewer   : opened")
        else:
            print(f"  viewer   : not opened — {opened[1]}")
    print()


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m forensics.report",
        description=(
            "Run every available image-forensics module on one image and write a "
            "PDF evidence report, then open it."
        ),
    )
    parser.add_argument("image", help="path to the evidence image")
    parser.add_argument("-o", "--output", help="PDF path or directory (default: output/reports/)")
    parser.add_argument("--examiner", default="", help="examiner name printed on the report")
    parser.add_argument("--case-id", default=None, help="override the generated case identifier")
    parser.add_argument("--no-open", action="store_true", help="build the PDF but do not open a viewer")
    parser.add_argument("--no-optional", action="store_true",
                        help="skip optional modules (copy-move, stego) even if present")
    args = parser.parse_args(argv)

    path = Path(args.image).expanduser()
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    if path.is_dir():
        print(f"error: expected an image file, got a directory: {path}", file=sys.stderr)
        return 2

    try:
        facts = generate_report(
            path,
            output_path=args.output,
            examiner=args.examiner,
            case_id=args.case_id,
            include_optional=not args.no_optional,
        )
    except Exception as exc:  # noqa: BLE001 - surface a clean CLI error
        print(f"error: report could not be generated: {exc}", file=sys.stderr)
        return 2

    opened = None if args.no_open else open_report(facts["path"])
    _print_summary(facts, opened)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
