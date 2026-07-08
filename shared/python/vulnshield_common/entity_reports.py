"""Generate and persist executive PDF reports for scans, code reviews, and red team campaigns."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.executive_pdf import build_executive_pdf
from vulnshield_common.messaging import publish_event
from vulnshield_common.storage import upload_file


METHODOLOGY = {
    "scan": (
        "Vulnerability assessment combining authenticated/unauthenticated scanning, CVE correlation "
        "(NVD, EPSS, CISA KEV), configuration checks, and risk-based prioritization aligned with "
        "industry frameworks (CVSS v3.1, CIS Controls)."
    ),
    "codereview": (
        "Static Application Security Testing (SAST) using pattern-based rulesets (OWASP Top 10, CWE) "
        "and optional LLM-assisted deep analysis. Covers injection, XSS, insecure deserialization, "
        "cryptographic failures, and secrets management."
    ),
    "redteam": (
        "Adversary simulation mapped to MITRE ATT&CK. Attack chains model reconnaissance through impact "
        "phases. Findings include proof-of-concept narratives and prioritized remediation."
    ),
    "webscan": (
        "Dynamic Application Security Testing (DAST) including crawl, parameter fuzzing, OWASP Top 10 "
        "test cases, security header analysis, and session management review."
    ),
}


async def _insert_report(
    db: AsyncSession,
    name: str,
    report_type: str,
    parameters: dict,
    content: bytes,
    user_id: UUID | None,
) -> dict:
    r = await db.execute(
        text("""
            INSERT INTO reports (name, report_type, format, parameters, status, generated_by, file_path, generated_at)
            VALUES (:name, :rtype, 'pdf', CAST(:params AS jsonb), 'completed', :uid, :path, NOW())
            RETURNING id, name, report_type::text, format::text, status::text, file_path, generated_at, created_at
        """),
        {
            "name": name,
            "rtype": report_type,
            "params": json.dumps(parameters),
            "uid": str(user_id) if user_id else None,
            "path": "pending",
        },
    )
    row = r.fetchone()
    report_id = row.id
    object_name = f"reports/{report_id}.pdf"
    file_path = await upload_file(object_name, content, "application/pdf")
    await db.execute(
        text("UPDATE reports SET file_path = :path WHERE id = :id"),
        {"id": str(report_id), "path": file_path},
    )
    await publish_event("report.generated", {"report_id": str(report_id), "format": "pdf"})
    return {
        "id": str(report_id),
        "name": row.name,
        "report_type": row.report_type,
        "format": row.format,
        "status": row.status,
        "file_path": file_path,
        "generated_at": row.generated_at.isoformat() if row.generated_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "parameters": parameters,
    }


async def generate_scan_executive_report(
    db: AsyncSession,
    scan_id: UUID,
    user_id: UUID | None = None,
) -> dict:
    scan_r = await db.execute(
        text("""
            SELECT s.id, s.name, s.scan_type::text, s.findings_count, s.critical_count, s.high_count,
                   s.medium_count, s.low_count, s.info_count, s.started_at, s.completed_at,
                   a.name AS asset_name
            FROM scans s LEFT JOIN assets a ON s.target_asset_id = a.id WHERE s.id = :id
        """),
        {"id": str(scan_id)},
    )
    scan = scan_r.fetchone()
    if not scan:
        raise ValueError("Scan not found")

    vuln_r = await db.execute(
        text("""
            SELECT title, severity::text, cve_identifier, cvss_score, description, remediation, status::text
            FROM vulnerabilities WHERE scan_id = :sid
            ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
            LIMIT 50
        """),
        {"sid": str(scan_id)},
    )
    vulns = [dict(row._mapping) for row in vuln_r.fetchall()]

    if not vulns:
        vuln_r = await db.execute(
            text("""
                SELECT title, severity::text, cve_identifier, cvss_score, description, remediation, status::text
                FROM vulnerabilities
                ORDER BY cvss_score DESC NULLS LAST LIMIT 25
            """)
        )
        vulns = [dict(row._mapping) for row in vuln_r.fetchall()]

    findings = [
        {
            "title": v.get("title"),
            "severity": v.get("severity"),
            "category": "Vulnerability",
            "cve_id": v.get("cve_identifier"),
            "cvss_score": v.get("cvss_score"),
            "description": v.get("description"),
            "remediation": v.get("remediation") or "Apply vendor patch, implement compensating controls, or accept risk per policy.",
            "location": v.get("cve_identifier"),
        }
        for v in vulns
    ]

    counts = {
        "critical": scan.critical_count or 0,
        "high": scan.high_count or 0,
        "medium": scan.medium_count or 0,
        "low": scan.low_count or 0,
        "info": scan.info_count or 0,
    }
    total = scan.findings_count or sum(counts.values())
    summary = (
        f"Assessment '{scan.name}' ({scan.scan_type}) identified {total} findings: "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium. "
        f"Immediate remediation is recommended for critical and high severity items. "
        f"Target asset: {scan.asset_name or 'Multiple / Network scope'}."
    )

    pdf = build_executive_pdf(
        report_title=f"Vulnerability Scan — {scan.name}",
        assessment_type="Vulnerability Assessment",
        target=scan.asset_name or scan.name,
        executive_summary=summary,
        methodology=METHODOLOGY["scan"],
        findings=findings,
        severity_counts=counts,
        metadata={"Scan ID": str(scan_id), "Scan Type": scan.scan_type},
    )
    return await _insert_report(
        db,
        f"Executive Scan Report — {scan.name}",
        "executive",
        {"entity_type": "scan", "entity_id": str(scan_id)},
        pdf,
        user_id,
    )


async def generate_codereview_executive_report(
    db: AsyncSession,
    review_id: UUID,
    user_id: UUID | None = None,
) -> dict:
    rev_r = await db.execute(
        text("""
            SELECT id, repository_url, branch, language, findings_count
            FROM code_reviews WHERE id = :id
        """),
        {"id": str(review_id)},
    )
    review = rev_r.fetchone()
    if not review:
        raise ValueError("Code review not found")

    find_r = await db.execute(
        text("""
            SELECT title, severity::text, category, description, root_cause, recommended_fix,
                   owasp_category, cwe_id, cvss_score, file_path, line_start, line_end
            FROM code_review_findings WHERE review_id = :rid
            ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
        """),
        {"rid": str(review_id)},
    )
    rows = [dict(row._mapping) for row in find_r.fetchall()]
    findings = [
        {
            **r,
            "remediation": r.get("recommended_fix"),
            "location": f"{r.get('file_path')}:{r.get('line_start')}",
            "line_range": f"{r.get('line_start')}-{r.get('line_end')}" if r.get("line_start") else None,
        }
        for r in rows
    ]
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "medium")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    target = review.repository_url or f"{review.language} source"
    summary = (
        f"Static application security review of {target} ({review.language}) identified "
        f"{review.findings_count or len(findings)} issues. "
        f"Critical and high findings require remediation before production deployment."
    )

    pdf = build_executive_pdf(
        report_title=f"SAST Report — {target[:60]}",
        assessment_type="Application Security Code Review",
        target=target,
        executive_summary=summary,
        methodology=METHODOLOGY["codereview"],
        findings=findings,
        severity_counts=counts,
        metadata={"Review ID": str(review_id), "Language": review.language},
    )
    return await _insert_report(
        db,
        f"Executive Code Review — {review.language}",
        "technical",
        {"entity_type": "codereview", "entity_id": str(review_id)},
        pdf,
        user_id,
    )


async def generate_redteam_executive_report(
    db: AsyncSession,
    campaign_id: UUID,
    user_id: UUID | None = None,
) -> dict:
    camp_r = await db.execute(
        text("""
            SELECT id, name, description, findings_count, executive_summary
            FROM red_team_campaigns WHERE id = :id
        """),
        {"id": str(campaign_id)},
    )
    camp = camp_r.fetchone()
    if not camp:
        raise ValueError("Campaign not found")

    find_r = await db.execute(
        text("""
            SELECT title, description, severity::text, attack_phase, mitre_technique_id, mitre_tactic,
                   kill_chain_phase, proof, remediation
            FROM red_team_findings WHERE campaign_id = :cid
            ORDER BY attack_chain_step
        """),
        {"cid": str(campaign_id)},
    )
    rows = [dict(row._mapping) for row in find_r.fetchall()]
    findings = [
        {
            **r,
            "category": r.get("mitre_tactic") or "Attack Simulation",
            "location": r.get("mitre_technique_id"),
            "recommended_fix": r.get("remediation"),
        }
        for r in rows
    ]
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "high")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    summary = camp.executive_summary or (
        f"Red team campaign '{camp.name}' completed with {camp.findings_count or len(findings)} findings. "
        f"Attack paths demonstrate exploitable weaknesses requiring defensive hardening."
    )

    pdf = build_executive_pdf(
        report_title=f"Red Team Assessment — {camp.name}",
        assessment_type="Adversary Simulation (MITRE ATT&CK)",
        target=camp.name,
        executive_summary=summary,
        methodology=METHODOLOGY["redteam"],
        findings=findings,
        severity_counts=counts,
        metadata={"Campaign ID": str(campaign_id)},
    )
    return await _insert_report(
        db,
        f"Executive Red Team — {camp.name}",
        "executive",
        {"entity_type": "redteam", "entity_id": str(campaign_id)},
        pdf,
        user_id,
    )
