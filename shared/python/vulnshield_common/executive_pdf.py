"""Executive-grade PDF report generation for security assessments."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:
    SimpleDocTemplate = None  # type: ignore

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626") if SimpleDocTemplate else None,
    "high": colors.HexColor("#ea580c") if SimpleDocTemplate else None,
    "medium": colors.HexColor("#ca8a04") if SimpleDocTemplate else None,
    "low": colors.HexColor("#2563eb") if SimpleDocTemplate else None,
    "info": colors.HexColor("#6b7280") if SimpleDocTemplate else None,
}


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ExecTitle",
            parent=base["Title"],
            fontSize=22,
            textColor=colors.HexColor("#0e7490"),
            spaceAfter=12,
            alignment=TA_CENTER,
        ),
        "subtitle": ParagraphStyle(
            "ExecSubtitle",
            parent=base["Normal"],
            fontSize=12,
            textColor=colors.HexColor("#374151"),
            alignment=TA_CENTER,
            spaceAfter=24,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontSize=14,
            textColor=colors.HexColor("#111827"),
            spaceBefore=16,
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontSize=11,
            textColor=colors.HexColor("#0e7490"),
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1f2937"),
        ),
        "muted": ParagraphStyle(
            "Muted",
            parent=base["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#6b7280"),
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#111827"),
            fontName="Helvetica-Bold",
            spaceBefore=8,
        ),
    }


def _esc(text: str | None) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def build_executive_pdf(
    *,
    report_title: str,
    assessment_type: str,
    target: str,
    executive_summary: str,
    methodology: str,
    findings: list[dict[str, Any]],
    severity_counts: dict[str, int] | None = None,
    metadata: dict[str, Any] | None = None,
) -> bytes:
    """Build a professional executive security assessment PDF."""
    if SimpleDocTemplate is None:
        import json

        return json.dumps(
            {
                "title": report_title,
                "findings": findings,
                "summary": executive_summary,
            },
            indent=2,
        ).encode()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )
    s = _styles()
    story: list[Any] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(Paragraph("VulnShield", s["muted"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(_esc(report_title), s["title"]))
    story.append(Paragraph(f"{_esc(assessment_type)} — Executive Report", s["subtitle"]))
    story.append(Paragraph(f"Target: {_esc(target)}", s["body"]))
    story.append(Paragraph(f"Generated: {now}", s["muted"]))
    if metadata:
        for k, v in metadata.items():
            story.append(Paragraph(f"{_esc(str(k))}: {_esc(str(v))}", s["muted"]))
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("Executive Summary", s["h1"]))
    story.append(Paragraph(_esc(executive_summary), s["body"]))
    story.append(Spacer(1, 0.15 * inch))

    counts = severity_counts or {}
    if not counts and findings:
        for f in findings:
            sev = str(f.get("severity", "medium")).lower()
            counts[sev] = counts.get(sev, 0) + 1

    if counts:
        story.append(Paragraph("Risk Overview", s["h1"]))
        table_data = [["Severity", "Count"]] + [
            [k.upper(), str(v)] for k, v in sorted(counts.items(), key=lambda x: -x[1])
        ]
        t = Table(table_data, colWidths=[2.5 * inch, 1.2 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Methodology", s["h1"]))
    story.append(Paragraph(_esc(methodology), s["body"]))
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings &amp; Remediation", s["h1"]))
    if not findings:
        story.append(Paragraph("No security findings were identified during this assessment.", s["body"]))
    else:
        for i, f in enumerate(findings[:50], 1):
            sev = str(f.get("severity", "medium")).upper()
            title = f.get("title") or f"Finding {i}"
            story.append(Paragraph(f"{i}. [{sev}] {_esc(title)}", s["finding_title"]))
            for label, key in [
                ("Category", "category"),
                ("OWASP", "owasp_category"),
                ("CWE", "cwe_id"),
                ("CVSS", "cvss_score"),
                ("Location", "location"),
                ("File", "file_path"),
                ("Lines", "line_range"),
            ]:
                val = f.get(key)
                if key == "line_range" and not val:
                    ls, le = f.get("line_start"), f.get("line_end")
                    if ls is not None:
                        val = f"{ls}-{le}" if le else str(ls)
                if val:
                    story.append(Paragraph(f"<b>{label}:</b> {_esc(str(val))}", s["body"]))
            if f.get("description"):
                story.append(Paragraph(f"<b>Description:</b> {_esc(f['description'])}", s["body"]))
            if f.get("root_cause"):
                story.append(Paragraph(f"<b>Root Cause:</b> {_esc(f['root_cause'])}", s["body"]))
            if f.get("proof"):
                story.append(Paragraph(f"<b>Proof of Concept:</b> {_esc(f['proof'])}", s["body"]))
            rem = f.get("remediation") or f.get("recommended_fix")
            if rem:
                story.append(Paragraph(f"<b>Remediation:</b> {_esc(rem)}", s["body"]))
            story.append(Spacer(1, 0.1 * inch))

    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            "CONFIDENTIAL — This report contains sensitive security information. "
            "Distribution is restricted to authorized personnel only.",
            ParagraphStyle("Footer", parent=s["muted"], alignment=TA_CENTER),
        )
    )

    doc.build(story)
    return buf.getvalue()
