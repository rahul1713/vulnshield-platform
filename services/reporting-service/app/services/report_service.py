import csv
import io
import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event
from vulnshield_common.storage import upload_file

try:
    from openpyxl import Workbook
except ImportError:
    Workbook = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except ImportError:
    canvas = None


async def list_reports(db: AsyncSession, limit=50, offset=0):
    r = await db.execute(
        text("""
            SELECT id, name, report_type::text, format::text, status::text, file_path, generated_at, created_at
            FROM reports ORDER BY created_at DESC LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def get_report(db: AsyncSession, report_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, name, report_type::text, format::text, parameters, status::text,
                   file_path, generated_by, generated_at, created_at
            FROM reports WHERE id = :id
        """),
        {"id": str(report_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Report not found")
    return dict(row._mapping)


async def _fetch_report_data(db: AsyncSession, report_type: str, parameters: dict) -> list[dict]:
    if report_type in ("executive", "risk", "technical"):
        r = await db.execute(
            text("""
                SELECT v.cve_identifier, v.title, v.severity::text, v.cvss_score, v.status::text,
                       a.name AS asset_name, a.criticality
                FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id
                WHERE v.status NOT IN ('closed', 'false_positive')
                ORDER BY v.cvss_score DESC NULLS LAST LIMIT 500
            """)
        )
    elif report_type == "compliance":
        r = await db.execute(
            text("""
                SELECT ca.score, cf.name AS framework, a.name AS asset_name, ca.passed_controls, ca.failed_controls
                FROM compliance_assessments ca
                JOIN compliance_frameworks cf ON ca.framework_id = cf.id
                LEFT JOIN assets a ON ca.asset_id = a.id
                ORDER BY ca.assessed_at DESC LIMIT 200
            """)
        )
    elif report_type == "asset":
        r = await db.execute(
            text("""
                SELECT name, asset_type::text, status::text, host(ip_address) AS ip_address, criticality, business_unit
                FROM assets ORDER BY criticality DESC, name LIMIT 500
            """)
        )
    else:
        r = await db.execute(
            text("""
                SELECT cve_id, cvss_v3_score, epss_score, is_kev FROM cves ORDER BY cvss_v3_score DESC NULLS LAST LIMIT 200
            """)
        )
    return [dict(row._mapping) for row in r.fetchall()]


def _render_csv(rows: list[dict]) -> bytes:
    if not rows:
        return b"no data\n"
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode()


def _render_json(rows: list[dict]) -> bytes:
    return json.dumps({"records": rows}, default=str, indent=2).encode()


def _render_excel(rows: list[dict]) -> bytes:
    if Workbook is None:
        return _render_csv(rows)
    wb = Workbook()
    ws = wb.active
    ws.title = "Report"
    if rows:
        ws.append(list(rows[0].keys()))
        for row in rows:
            ws.append([row.get(k) for k in rows[0].keys()])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _render_pdf(rows: list[dict], title: str) -> bytes:
    if canvas is None:
        return _render_json(rows)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, 750, title)
    c.setFont("Helvetica", 10)
    y = 720
    for i, row in enumerate(rows[:40]):
        line = ", ".join(f"{k}={v}" for k, v in list(row.items())[:6])
        c.drawString(50, y, line[:110])
        y -= 14
        if y < 50:
            c.showPage()
            y = 750
    c.save()
    return buf.getvalue()


async def generate_report(db: AsyncSession, data: dict, user_id: UUID | None = None):
    r = await db.execute(
        text("""
            INSERT INTO reports (name, report_type, format, parameters, status, generated_by)
            VALUES (:name, :rtype, :fmt, CAST(:params AS jsonb), 'running', :uid) RETURNING id
        """),
        {
            "name": data["name"],
            "rtype": data["report_type"],
            "fmt": data["format"],
            "params": json.dumps(data.get("parameters", {})),
            "uid": str(user_id) if user_id else None,
        },
    )
    report_id = r.fetchone().id
    rows = await _fetch_report_data(db, data["report_type"], data.get("parameters", {}))
    fmt = data["format"]
    if fmt == "csv":
        content = _render_csv(rows)
        content_type = "text/csv"
    elif fmt == "json":
        content = _render_json(rows)
        content_type = "application/json"
    elif fmt == "excel":
        content = _render_excel(rows)
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "pdf":
        content = _render_pdf(rows, data["name"])
        content_type = "application/pdf"
    else:
        raise HTTPException(400, "Unsupported format")
    ext = {"csv": "csv", "json": "json", "excel": "xlsx", "pdf": "pdf"}[fmt]
    object_name = f"reports/{report_id}.{ext}"
    file_path = await upload_file(object_name, content, content_type)
    await db.execute(
        text("""
            UPDATE reports SET status = 'completed', file_path = :path, generated_at = NOW() WHERE id = :id
        """),
        {"id": str(report_id), "path": file_path},
    )
    await publish_event("report.generated", {"report_id": str(report_id), "format": fmt})
    return await get_report(db, report_id)
