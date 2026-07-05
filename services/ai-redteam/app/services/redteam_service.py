import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.llm import get_llm_provider
from vulnshield_common.messaging import publish_event

MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
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
    return await plan_and_execute(db, campaign_id, data)


async def plan_and_execute(db: AsyncSession, campaign_id: UUID, data: dict):
    llm = get_llm_provider()
    system = (
        "You are a red team operator. Plan an attack campaign mapped to MITRE ATT&CK. "
        "Return JSON with keys: attack_chains (list of steps with technique_id, tactic, phase, description), "
        "mitre_mappings (list), findings (list with title, severity, attack_phase, mitre_technique_id, "
        "mitre_tactic, proof, remediation, kill_chain_phase)."
    )
    user_prompt = f"Campaign: {data['name']}\nScope: {json.dumps(data.get('scope', {}))}\nPlan attack chains with MITRE mapping."
    result = await llm.generate_json(system, user_prompt)
    chains = result.get("attack_chains", [])
    mappings = result.get("mitre_mappings", [])
    findings = result.get("findings", [])
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
                    mitre_technique_id, mitre_tactic, kill_chain_phase, proof, remediation, attack_chain_step)
                VALUES (:cid, :title, :desc, :sev, :phase, :tech, :tactic, :kc, :proof, :rem, :step)
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
            },
        )
        count += 1
    summary = result.get("executive_summary") or f"Campaign completed with {count} findings across {len(chains)} attack chain steps."
    await db.execute(
        text("""
            UPDATE red_team_campaigns SET status = 'completed', findings_count = :fc,
                completed_at = NOW(), executive_summary = :summary WHERE id = :id
        """),
        {"id": str(campaign_id), "fc": count, "summary": summary},
    )
    await publish_event("redteam.completed", {"campaign_id": str(campaign_id), "findings": count})
    return await get_campaign(db, campaign_id)


async def get_campaign(db: AsyncSession, campaign_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, name, description, status::text, scope, attack_chains, mitre_mappings,
                   findings_count, executive_summary, started_at, completed_at, created_at
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
            SELECT id, name, description, status::text, findings_count, created_at
            FROM red_team_campaigns ORDER BY created_at DESC LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def list_findings(db: AsyncSession, campaign_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, title, description, severity::text, attack_phase, mitre_technique_id,
                   mitre_tactic, kill_chain_phase, proof, remediation, attack_chain_step, created_at
            FROM red_team_findings WHERE campaign_id = :cid ORDER BY attack_chain_step, created_at
        """),
        {"cid": str(campaign_id)},
    )
    return [dict(row._mapping) for row in r.fetchall()]
