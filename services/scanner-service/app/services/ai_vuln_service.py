import json
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.llm import SecurityLLMConfigurationError, get_local_security_llm_provider
from vulnshield_common.messaging import publish_event


async def ai_analyze_scan(db: AsyncSession, scan_id: UUID) -> dict:
    """AI-enhanced vulnerability analysis using local Ollama Qwen 3.6 only."""
    scan_r = await db.execute(
        text("""
            SELECT s.id, s.name, s.scan_type::text, s.target_asset_id, s.target_config,
                   a.name AS asset_name, a.hostname, a.os_family, a.os_version
            FROM scans s LEFT JOIN assets a ON s.target_asset_id = a.id WHERE s.id = :id
        """),
        {"id": str(scan_id)},
    )
    scan = scan_r.fetchone()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    asset_id = scan.target_asset_id
    software, ports, existing_vulns = [], [], []
    if asset_id:
        sw_r = await db.execute(
            text("SELECT name, version, vendor FROM asset_software WHERE asset_id = :aid LIMIT 100"),
            {"aid": str(asset_id)},
        )
        software = [dict(r._mapping) for r in sw_r.fetchall()]
        port_r = await db.execute(
            text("SELECT port, protocol, service_name, service_version FROM asset_ports WHERE asset_id = :aid"),
            {"aid": str(asset_id)},
        )
        ports = [dict(r._mapping) for r in port_r.fetchall()]
        vuln_r = await db.execute(
            text("""
                SELECT title, severity::text, cve_identifier, category, status::text
                FROM vulnerabilities WHERE asset_id = :aid AND scan_id = :sid
                LIMIT 50
            """),
            {"aid": str(asset_id), "sid": str(scan_id)},
        )
        existing_vulns = [dict(r._mapping) for r in vuln_r.fetchall()]

    try:
        llm = get_local_security_llm_provider()
    except SecurityLLMConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    system = (
        "You are an expert vulnerability analyst. Analyze scan and asset data to identify security risks. "
        "Return JSON with key 'findings': list of objects with title, severity (critical|high|medium|low|info), "
        "category, description, remediation, affected_software, cve_guess (optional CVE ID if applicable), "
        "confidence_score (0-1). Focus on misconfigurations, missing patches, weak services, and exploit paths."
    )
    user_prompt = json.dumps(
        {
            "scan": {
                "id": str(scan_id),
                "name": scan.name,
                "type": scan.scan_type,
                "target_config": scan.target_config,
            },
            "asset": {
                "name": scan.asset_name,
                "hostname": scan.hostname,
                "os_family": scan.os_family,
                "os_version": scan.os_version,
            },
            "software_inventory": software,
            "open_ports": ports,
            "existing_findings": existing_vulns,
        },
        default=str,
    )

    result = await llm.generate_json(system, user_prompt)
    findings = result.get("findings", [])
    if isinstance(findings, dict):
        findings = [findings]

    created = 0
    if asset_id:
        for f in findings:
            if not isinstance(f, dict):
                continue
            await db.execute(
                text("""
                    INSERT INTO vulnerabilities (asset_id, scan_id, cve_identifier, title, description,
                        severity, category, affected_software, remediation, status, metadata)
                    VALUES (:aid, :sid, :cve, :title, :desc,
                        CAST(:sev AS severity), :cat, :sw, :rem, 'open',
                        CAST(:meta AS jsonb))
                """),
                {
                    "aid": str(asset_id),
                    "sid": str(scan_id),
                    "cve": f.get("cve_guess"),
                    "title": (f.get("title") or "AI-detected finding")[:500],
                    "desc": f.get("description"),
                    "sev": f.get("severity", "medium"),
                    "cat": f.get("category", "ai_analysis"),
                    "sw": f.get("affected_software"),
                    "rem": f.get("remediation"),
                    "meta": json.dumps({"ai_generated": True, "confidence": f.get("confidence_score")}),
                },
            )
            created += 1

    await publish_event("scan.ai_analyzed", {"scan_id": str(scan_id), "ai_findings": created})
    return {
        "scan_id": str(scan_id),
        "model": "qwen3.6",
        "provider": "ollama",
        "ai_findings_created": created,
        "analysis_summary": result.get("summary") or f"AI analysis completed with {created} new findings.",
    }
