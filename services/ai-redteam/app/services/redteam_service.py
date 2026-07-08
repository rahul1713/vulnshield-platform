import json
import os
from urllib.parse import urlparse
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.ai_orchestrator import plan_scan, sanitize_for_llm, triage_findings
from vulnshield_common.config import get_settings
from vulnshield_common.entity_reports import generate_redteam_executive_report
from vulnshield_common.llm import SecurityLLMConfigurationError, get_security_llm
from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_engines import (
    EngineUnavailableError,
    dns_lookup,
    engines_status,
    httpx_probe,
    run_nmap,
    run_nuclei,
)


def _allow_simulated() -> bool:
    settings = get_settings()
    return settings.allow_simulated_scans or os.getenv("ALLOW_SIMULATED_SCANS", "").lower() in ("1", "true", "yes")


def _allowed_targets(scope: dict) -> list[str]:
    targets = scope.get("targets") or scope.get("hosts") or []
    if isinstance(targets, str):
        targets = [targets]
    allowed = scope.get("allowed_targets") or targets
    return [str(t).strip() for t in allowed if t]


async def _execute_safe_checks(targets: list[str]) -> list[dict]:
    """Run sandbox-safe recon checks and return raw observations."""
    observations: list[dict] = []
    for target in targets[:10]:
        host = target
        if target.startswith("http"):
            parsed = urlparse(target)
            host = parsed.hostname or target
            try:
                observations.append({"check": "httpx_probe", "target": target, "result": await httpx_probe(target)})
            except Exception as exc:
                observations.append({"check": "httpx_probe", "target": target, "error": str(exc)})
        try:
            observations.append({"check": "dns_lookup", "target": host, "result": dns_lookup(host)})
        except Exception as exc:
            observations.append({"check": "dns_lookup", "target": host, "error": str(exc)})
        if engines_status().get("nuclei") and target.startswith("http"):
            try:
                hits = await run_nuclei(target, tags=["safe", "passive", "tech"])
                observations.append({"check": "nuclei_safe", "target": target, "findings_count": len(hits), "sample": hits[:5]})
            except EngineUnavailableError as exc:
                observations.append({"check": "nuclei_safe", "target": target, "error": str(exc)})
        if engines_status().get("nmap") and host:
            try:
                observations.append({"check": "nmap_top_ports", "target": host, "result": await run_nmap(host, top_ports=100)})
            except EngineUnavailableError as exc:
                observations.append({"check": "nmap_top_ports", "target": host, "error": str(exc)})
    return observations


async def create_campaign(db: AsyncSession, data: dict, user_id: UUID | None = None):
    r = await db.execute(
        text("""
            INSERT INTO red_team_campaigns (name, description, scope, status, created_by, started_at)
            VALUES (:name, :desc, CAST(:scope AS jsonb), 'running', :uid, NOW()) RETURNING id
        """),
        {
            "name": data["name"],
            "desc": data.get("description"),
            "scope": json.dumps(data.get("scope", {})),
            "uid": str(user_id) if user_id else None,
        },
    )
    campaign_id = r.fetchone().id
    await publish_event("redteam.started", {"campaign_id": str(campaign_id)})
    return await plan_and_execute(db, campaign_id, data, user_id)


async def plan_and_execute(db: AsyncSession, campaign_id: UUID, data: dict, user_id: UUID | None = None):
    scope = data.get("scope", {})
    targets = _allowed_targets(scope)
    if not targets:
        raise HTTPException(400, "Campaign scope must include targets or allowed_targets")

    try:
        plan = await plan_scan("red_team", targets[0], {"name": data["name"], "scope": scope})
    except SecurityLLMConfigurationError as exc:
        raise HTTPException(503, str(exc)) from exc

    chains = plan.get("phases") or plan.get("attack_chains") or []
    mappings = plan.get("mitre_mappings") or []
    summary = plan.get("executive_summary")

    observations = await _execute_safe_checks(targets)
    real_checks = sum(1 for o in observations if o.get("result") or o.get("findings_count"))
    used_simulated = False

    if real_checks == 0 and not _allow_simulated():
        raise HTTPException(
            503,
            f"No safe checks could be executed. Engine status: {engines_status()}. "
            "Install nmap/nuclei or set ALLOW_SIMULATED_SCANS=true.",
        )

    try:
        llm = get_security_llm()
        system = (
            "You are a red team analyst. Given attack plan and REAL observation results only, "
            "return JSON with keys: findings (title, severity, attack_phase, mitre_technique_id, "
            "mitre_tactic, kill_chain_phase, proof, remediation), executive_summary."
        )
        user_prompt = sanitize_for_llm(
            json.dumps(
                {
                    "campaign": data["name"],
                    "plan": {"phases": chains, "objectives": plan.get("objectives")},
                    "observations": observations,
                },
                default=str,
            ),
            6000,
        )
        analysis = await llm.generate_json(system, user_prompt)
        findings = analysis.get("findings", []) or []
        summary = analysis.get("executive_summary") or summary
    except SecurityLLMConfigurationError as exc:
        raise HTTPException(503, str(exc)) from exc

    if isinstance(findings, dict):
        findings = [findings]
    findings = await triage_findings([f for f in findings if isinstance(f, dict)])

    scope_with_obs = {**scope, "observations": observations, "ai_plan": plan}
    await db.execute(
        text("""
            UPDATE red_team_campaigns SET attack_chains = CAST(:chains AS jsonb),
                mitre_mappings = CAST(:maps AS jsonb), scope = CAST(:scope AS jsonb) WHERE id = :id
        """),
        {
            "id": str(campaign_id),
            "chains": json.dumps(chains),
            "maps": json.dumps(mappings),
            "scope": json.dumps(scope_with_obs, default=str),
        },
    )

    is_simulated = used_simulated or (real_checks == 0 and _allow_simulated())
    count = 0
    for i, f in enumerate(findings):
        proof = f.get("proof")
        if not proof and observations:
            proof = sanitize_for_llm(json.dumps(observations[:3], default=str), 1500)
        await db.execute(
            text("""
                INSERT INTO red_team_findings (campaign_id, title, description, severity, attack_phase,
                    mitre_technique_id, mitre_tactic, kill_chain_phase, proof, remediation, attack_chain_step, is_simulated)
                VALUES (:cid, :title, :desc, :sev, :phase, :tech, :tactic, :kc, :proof, :rem, :step, :sim)
            """),
            {
                "cid": str(campaign_id),
                "title": f.get("title", "Red team finding")[:500],
                "desc": f.get("description"),
                "sev": f.get("severity", "high"),
                "phase": f.get("attack_phase"),
                "tech": f.get("mitre_technique_id"),
                "tactic": f.get("mitre_tactic"),
                "kc": f.get("kill_chain_phase"),
                "proof": proof,
                "rem": f.get("remediation"),
                "step": i + 1,
                "sim": is_simulated,
            },
        )
        count += 1

    if not summary:
        summary = (
            f"Campaign '{data['name']}' completed {real_checks} safe checks across "
            f"{len(targets)} target(s) with {count} triaged findings."
        )

    await db.execute(
        text("""
            UPDATE red_team_campaigns SET status = 'completed', findings_count = :fc,
                completed_at = NOW(), executive_summary = :summary, findings_simulated = :sim WHERE id = :id
        """),
        {"id": str(campaign_id), "fc": count, "summary": summary, "sim": is_simulated},
    )
    await publish_event("redteam.completed", {"campaign_id": str(campaign_id), "findings": count})

    report_id = None
    try:
        report = await generate_redteam_executive_report(db, campaign_id, user_id)
        report_id = report["id"]
    except Exception:
        pass

    campaign = await get_campaign(db, campaign_id)
    if report_id:
        campaign["report_id"] = report_id
    return campaign


async def get_campaign(db: AsyncSession, campaign_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, name, description, status::text, scope, attack_chains, mitre_mappings,
                   findings_count, executive_summary, findings_simulated, started_at, completed_at, created_at
            FROM red_team_campaigns WHERE id = :id
        """),
        {"id": str(campaign_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Campaign not found")
    return dict(row._mapping)


async def list_campaigns(db: AsyncSession, limit=50, offset=0):
    r = await db.execute(
        text("""
            SELECT id, name, description, status::text, findings_count, findings_simulated, created_at
            FROM red_team_campaigns ORDER BY created_at DESC LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def list_findings(db: AsyncSession, campaign_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, title, description, severity::text, attack_phase, mitre_technique_id,
                   mitre_tactic, kill_chain_phase, proof, remediation, attack_chain_step, is_simulated, created_at
            FROM red_team_findings WHERE campaign_id = :cid ORDER BY attack_chain_step
        """),
        {"cid": str(campaign_id)},
    )
    return [dict(row._mapping) for row in r.fetchall()]
