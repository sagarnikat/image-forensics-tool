"""PixelProof - simple Streamlit front end.

Run with::

    streamlit run app.py

The UI is deliberately thin: it only calls :func:`forensics.pipeline.run_pipeline`
and renders the returned dictionary.  No forensic logic or thresholds live here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import streamlit as st

from forensics.pipeline import run_pipeline
from forensics.report import build_pdf
from forensics.verdict import MODULE_LABELS
from utils import config
from utils.image_utils import safe_name

# --------------------------------------------------------------------- setup
st.set_page_config(
    page_title=f"{config.APP_NAME} - {config.APP_TAGLINE}",
    page_icon="🔍",
    layout="wide",
)

UPLOAD_DIR = config.TEMP_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff", ".gif")

BAND_STYLE = {
    "authentic": ("#067647", "#ECFDF3"),
    "suspicious": ("#B54708", "#FFFAEB"),
    "tampered": ("#B42318", "#FEF3F2"),
    "inconclusive": ("#475467", "#F2F4F7"),
}

SEVERITY_STYLE = {
    "critical": ("#7A271A", "#FEE4E2"),
    "high": ("#B42318", "#FEE4E2"),
    "medium": ("#B54708", "#FEF0C7"),
    "low": ("#175CD3", "#EFF8FF"),
    "info": ("#475467", "#F2F4F7"),
}


# --------------------------------------------------------------------- cache
@st.cache_data(show_spinner=False, max_entries=8)
def cached_pipeline(path: str, include_optional: bool) -> dict[str, Any]:
    """Run the shared pipeline once per (file, options) pair."""
    return run_pipeline(path, include_optional=include_optional)


@st.cache_data(show_spinner=False, max_entries=8)
def cached_report(path: str, include_optional: bool, examiner: str) -> bytes:
    """Build the PDF report from the same pipeline output and return its bytes."""
    pipeline = cached_pipeline(path, include_optional)
    self_path = Path(path)
    destination = config.REPORT_DIR / f"web_{safe_name(self_path.stem)}.pdf"
    build_pdf(pipeline, destination, examiner=examiner)
    return destination.read_bytes()


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _report_key(path: Path, include_optional: bool, examiner: str) -> tuple[str, bool, str]:
    return (str(path), bool(include_optional), examiner.strip())


def current_report(path: Path, include_optional: bool, examiner: str) -> bytes | None:
    """Return the PDF already built for this exact evidence + options, if any."""
    if st.session_state.get("report_key") == _report_key(path, include_optional, examiner):
        return st.session_state.get("report_bytes")
    return None


def build_and_store_report(path: Path, include_optional: bool, examiner: str) -> bytes:
    """Build the PDF once and remember it for the download button."""
    pdf_bytes = cached_report(str(path), include_optional, examiner)
    st.session_state["report_bytes"] = pdf_bytes
    st.session_state["report_key"] = _report_key(path, include_optional, examiner)
    st.session_state["report_name"] = f"pixelproof_{safe_name(path.stem)}.pdf"
    return pdf_bytes


def ensure_report(path: Path, include_optional: bool, examiner: str) -> bytes | None:
    """Auto-build the PDF so the download button is available immediately."""
    existing = current_report(path, include_optional, examiner)
    if existing is not None:
        return existing
    try:
        with st.spinner("Preparing PDF report..."):
            return build_and_store_report(path, include_optional, examiner)
    except Exception as exc:  # noqa: BLE001 - report failure must not hide the analysis
        st.warning(f"PDF report could not be generated: {type(exc).__name__}: {exc}")
        return None


def render_report_actions(path: Path, include_optional: bool, examiner: str, *, key: str) -> None:
    """Download button + regenerate control, reused on the Overview and Report tabs."""
    report_bytes = ensure_report(path, include_optional, examiner)
    if report_bytes:
        st.download_button(
            "⬇️ Download PDF report",
            data=report_bytes,
            file_name=st.session_state.get("report_name", "report.pdf"),
            mime="application/pdf",
            type="primary",
            key=f"download_{key}",
        )
        st.caption("Built from the same analysis shown above.")
    elif st.button("Generate PDF report", key=f"generate_{key}"):
        try:
            build_and_store_report(path, include_optional, examiner)
            st.rerun()
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not build the report: {type(exc).__name__}: {exc}")


# --------------------------------------------------------------------- input
def sample_options() -> dict[str, Path]:
    options: dict[str, Path] = {}
    for path in sorted(config.SAMPLES_DIR.rglob("*")):
        if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES:
            label = f"{path.parent.name}/{path.name}"
            options[label] = path
    return options


def save_upload(uploaded) -> Path:
    data = uploaded.getvalue()
    digest = sha256_of(data)
    destination = UPLOAD_DIR / f"{digest[:10]}_{safe_name(uploaded.name)}"
    if not destination.exists():
        destination.write_bytes(data)
    return destination


st.sidebar.title("🔍 PixelProof")
st.sidebar.caption(config.APP_TAGLINE)

samples = sample_options()
source = st.sidebar.radio("Evidence source", ["Built-in sample", "Upload image"])

evidence: Path | None = None
if source == "Built-in sample":
    if samples:
        label = st.sidebar.selectbox("Sample image", list(samples))
        evidence = samples[label]
    else:
        st.sidebar.warning("No sample images found in samples/.")
else:
    uploaded = st.sidebar.file_uploader(
        "Choose an image",
        type=[suffix.lstrip(".") for suffix in IMAGE_SUFFIXES],
    )
    if uploaded is not None:
        evidence = save_upload(uploaded)

include_optional = st.sidebar.checkbox(
    "Run copy-move / stego modules (if installed)",
    value=True,
    help="These modules are optional. The app shows them as unavailable when absent.",
)
examiner = st.sidebar.text_input("Examiner (for the PDF)", value="")

if evidence is None:
    st.title("Image Forensic Examination")
    st.info("Pick a built-in sample or upload an image from the sidebar to begin.")
    st.markdown(
        """
        This tool screens an image for tampering evidence using:

        * **File analysis** - hashes, signature, container and extension checks
        * **Metadata / EXIF** - camera, GPS, timestamps, editor tags
        * **Error Level Analysis** - JPEG residual heatmap and dense regions
        * **Copy-move / stego** - optional modules when present in the build

        Results are a **triage label**, not a legal conclusion.
        """
    )
    st.stop()

# ------------------------------------------------------------------ analysis
st.title("Image Forensic Examination")
st.caption(f"Evidence: `{evidence.name}`")

with st.spinner("Running forensic analysis..."):
    try:
        pipeline = cached_pipeline(str(evidence), include_optional)
    except Exception as exc:  # noqa: BLE001 - show a useful message instead of a traceback
        st.error(f"Analysis failed: {type(exc).__name__}: {exc}")
        st.stop()

verdict = pipeline["verdict"]
color, background = BAND_STYLE.get(verdict["band"], BAND_STYLE["inconclusive"])

# ------------------------------------------------------------------- verdict
st.markdown(
    f"""
    <div style="border:1px solid {color};background:{background};border-radius:10px;
                padding:16px 20px;margin-bottom:12px;">
      <div style="font-size:13px;letter-spacing:.08em;color:{color};
                  text-transform:uppercase;font-weight:700;">Verdict</div>
      <div style="font-size:28px;font-weight:800;color:{color};margin:4px 0;">
        {verdict['label']} &nbsp;·&nbsp; {verdict['score']}/100
      </div>
      <div style="color:{color};font-size:15px;">{verdict['headline']}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Score", f"{verdict['score']}/100")
col2.metric("Confidence", f"{verdict['confidence'] * 100:.0f}%")
col3.metric("Modules run", len(verdict["evaluated"]))
col4.metric("Analysis time", f"{pipeline['duration_s']:.2f}s")

if verdict["escalated"]:
    for note in verdict["escalations"]:
        st.warning(note)

# ------------------------------------------------------- report download (top)
download_col, note_col = st.columns([1, 3])
with download_col:
    render_report_actions(evidence, include_optional, examiner, key="top")
with note_col:
    st.write("")
    st.caption(
        "The PDF evidence report uses the same pipeline result as this screen, "
        "so its numbers cannot disagree with the UI."
    )

# ---------------------------------------------------------------------- tabs
tab_names = ["Overview"] + [
    MODULE_LABELS.get(result["module"], result["module"]) for result in pipeline["results"]
] + ["Findings", "Report"]
tabs = st.tabs(tab_names)

with tabs[0]:
    left, right = st.columns([1, 1])

    with left:
        st.subheader("Module scores")
        for result in pipeline["results"]:
            label = MODULE_LABELS.get(result["module"], result["module"])
            score = float(result.get("score", 0.0))
            st.write(f"**{label}** - {score:.1f}/100")
            st.progress(min(1.0, score / 100.0))
            st.caption(result.get("summary", ""))

        if pipeline["not_available"]:
            st.info(
                "Not available in this build: "
                + ", ".join(
                    MODULE_LABELS.get(name, name) for name in pipeline["not_available"]
                )
            )

    with right:
        st.subheader("Evidence")
        try:
            st.image(str(evidence), width="stretch")
        except Exception:  # noqa: BLE001 - preview is optional
            st.caption("Preview unavailable.")
        st.caption(f"{evidence.name} · {pipeline['duration_s']:.2f}s")

        st.subheader("Supporting signals")
        if verdict["supporting"]:
            for line in verdict["supporting"]:
                st.write("- " + line)
        else:
            st.write("None above the review threshold.")

        st.subheader("Contradicting signals")
        if verdict["contradicting"]:
            for line in verdict["contradicting"]:
                st.write("- " + line)
        else:
            st.write("None.")

# ----------------------------------------------------------- module details
for tab, result in zip(tabs[1:], pipeline["results"]):
    with tab:
        status = result.get("status", "ok")
        if status != "ok":
            st.error(result.get("summary", "Analyzer failed."))
        else:
            st.write(result.get("summary", ""))

        if result.get("artifacts"):
            image_paths = [
                Path(item)
                for item in result["artifacts"]
                if Path(item).is_file() and Path(item).suffix.lower() in IMAGE_SUFFIXES
            ]
            if image_paths:
                columns = st.columns(min(3, len(image_paths)))
                for index, image_path in enumerate(image_paths):
                    with columns[index % len(columns)]:
                        st.image(str(image_path), caption=image_path.name, width="stretch")

        if result.get("findings"):
            st.subheader("Findings")
            for item in result["findings"]:
                severity = item.get("severity", "info")
                fg, bg = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
                with st.expander(
                    f"{severity.upper()} · {item.get('title', '')} "
                    f"(confidence {item.get('confidence', 0):.0%})"
                ):
                    st.markdown(
                        f"<span style='background:{bg};color:{fg};padding:2px 8px;"
                        f"border-radius:6px;font-weight:700;'>{severity}</span>",
                        unsafe_allow_html=True,
                    )
                    st.write(item.get("detail", ""))
                    if item.get("tags"):
                        st.caption("Tags: " + ", ".join(item["tags"]))
        else:
            st.caption("No findings from this module.")

        with st.expander("Metrics (raw values)"):
            st.json(result.get("metrics", {}))

with tabs[-2]:
    if verdict["severity_counts"]:
        st.subheader("Severity counts")
        st.json(verdict["severity_counts"])
    if verdict["errors"]:
        st.subheader("Errors")
        st.json(verdict["errors"])

    all_findings = [
        (result["module"], item)
        for result in pipeline["results"]
        for item in result.get("findings", [])
    ]
    if all_findings:
        st.subheader("All findings")
        for module, item in all_findings:
            severity = item.get("severity", "info")
            fg, bg = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
            st.markdown(
                f"<span style='background:{bg};color:{fg};padding:2px 8px;"
                f"border-radius:6px;font-weight:700;'>{severity}</span> "
                f"**{item.get('title', '')}** - "
                f"{MODULE_LABELS.get(module, module)}",
                unsafe_allow_html=True,
            )
            st.caption(item.get("detail", ""))
    else:
        st.info("No findings were produced.")

with tabs[-1]:
    st.subheader("PDF evidence report")
    st.write(
        "The PDF is built from the same pipeline result shown above, so the "
        "numbers cannot disagree with the screen. It includes the verdict, "
        "hashes, per-module findings, ELA images, metadata details and the "
        "chain-of-custody declaration."
    )
    render_report_actions(evidence, include_optional, examiner, key="report")
    if st.button("Rebuild PDF report", key="rebuild_report"):
        try:
            with st.spinner("Building PDF..."):
                build_and_store_report(evidence, include_optional, examiner)
            st.rerun()
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not build the report: {type(exc).__name__}: {exc}")

st.divider()
st.caption(
    "PixelProof is a screening tool. A tampering signal is not proof; "
    "corroborate findings manually before drawing conclusions."
)
