import json
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.entity_reports import generate_redteam_executive_report
from vulnshield_common.llm import SecurityLLMConfigurationError, get_local_security_llm_provider
from vulnshield_common.messaging import publish_event

STATIC_REDTEAM_FINDINGS = [
    {
        "title": "Credential exposure via weak service account",
        "severity": "critical",
        "description": "Service account with excessive privileges identified in scope.",
        "attack_phase": "Credential Access",
        "mitre_technique_id": "T1078",
        "mitre_tactic": "Credential Access",
        "kill_chain_phase": "Exploitation",
        "proof": "Simulated extraction of service principal credentials from misconfigured vault.",
        "remediation": "Enforce least privilege, rotate credentials, enable MFA for service accounts, audit RBAC quarterly.",
    },
    {
        "title": "Lateral movement via unsegmented network",
        "severity": "high",
        "description": "Flat network topology allows pivot from DMZ to internal subnets.",
        "attack_phase": "Lateral Movement",
        "mitre_technique_id": "T1021",
        "mitre_tactic": "Lateral Movement",
        "kill_chain_phase": "Actions on Objectives",
        "proof": "Simulated RDP/SSH hop from compromised web tier to database segment.",
        "remediation": "Implement micro-segmentation, zero-trust network access, and monitor east-west traffic.",
    },
    {
        "title": "Missing EDR coverage on endpoints",
        "severity": "high",
        "description": "Several endpoints lack endpoint detection and response agents.",
        "attack_phase": "Defense Evasion",
        "mitre_technique_id": "T1562",
        "mitre_tactic": "Defense Evasion",
        "kill_chain_phase": "Installation",
        "proof": "Simulated payload execution without alerting on 3 of 10 sampled hosts.",
        "remediation": "Deploy EDR universally, enable tamper protection, integrate with SIEM.",
    },
    {
        "title": "Phishing-susceptible users",
        "severity": "medium",
        "description": "Users clicked simulated phishing links during campaign.",
        "attack_phase": "Initial Access",
        "mitre_technique_id": "T1566",
        "mitre_tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "proof": "12% click rate on controlled phishing exercise.",
        "remediation": "Security awareness training, phishing simulations, DMARC/SPF/DKIM hardening.",
    },
]


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
    chains: list = []
    mappings: list = []
    findings: list = []
    used_static_fallback = False

    try:
        llm = get_local_security_llm_provider()
        system = (
            "You are a red team operator. Plan an attack campaign mapped to MITRE ATT&CK. "
            "Return JSON with keys: attack_chains, mitre_mappings, findings (with title, severity, "
            "attack_phase, mitre_technique_id, mitre_tactic, proof, remediation, kill_chain_phase), "
            "executive_summary."
        )
        user_prompt = f"Campaign: {data['name']}\nScope: {json.dumps(data.get('scope', {}))}"
        result = await llm.generate_json(system, user_prompt)
        chains = result.get("attack_chains", []) or []
        mappings = result.get("mitre_mappings", []) or []
        findings = result.get("findings", []) or []
        summary = result.get("executive_summary")
    except (SecurityLLMConfigurationError, Exception):
        findings = STATIC_REDTEAM_FINDINGS
        used_static_fallback = True
        chains = [{"phase": "Reconnaissance", "technique": "T1595", "description": "External footprinting"}]
        mappings = [{"tactic": "Initial Access", "technique": "T1566"}]
        summary = None

    if isinstance(findings, dict):
        findings = [findings]

    await db.execute(
        text("""
            UPDATE red_team_campaigns SET attack_chains = CAST(:chains AS jsonb),
                mitre_mappings = CAST(:maps AS jsonb) WHERE id = :id
        """),
        {"id": str(campaign_id), "chains": json.dumps(chains), "maps": json.dumps(mappings)},
    )

    count = 0
    for i, f in enumerate(findings if isinstance(findings, list) else []):
        if not isinstance(f, dict):
            continue
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
                "proof": f.get("proof"),
                "rem": f.get("remediation"),
                "step": i + 1,
                "sim": used_static_fallback,
            },
        )
        count += 1

    if not summary:
        summary = (
            f"Campaign '{data['name']}' identified {count} exploitable weaknesses across "
            f"{len(chains)} attack chain phases. Prioritize credential hardening and network segmentation."
        )

    await db.execute(
        text("""
            UPDATE red_team_campaigns SET status = 'completed', findings_count = :fc,
                completed_at = NOW(), executive_summary = :summary, findings_simulated = :sim WHERE id = :id
        """),
        {"id": str(campaign_id), "fc": count, "summary": summary, "sim": used_static_fallback},
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
