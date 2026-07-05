import json
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from vulnshield_common.messaging import publish_event
from app.schemas import AgentIngestPayload
from app.services import agent_service, scan_service

router = APIRouter(prefix="/ingestion", tags=["Agent Ingestion"])


@router.post("/agent")
async def ingest_agent_data(
    body: AgentIngestPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    agent = await agent_service.get_agent(db, body.agent_id)
    if not agent_service.verify_mtls(request, agent.get("certificate_fingerprint") or body.certificate_fingerprint):
        raise HTTPException(401, "mTLS certificate verification failed")

    scan = await scan_service.create_scan(
        db,
        {"name": f"agent-ingest-{body.agent_id}", "scan_type": "agent", "target_config": {"agent_id": body.agent_id}},
    )
    await db.execute(
        text("""
            INSERT INTO scan_results (scan_id, asset_id, raw_data, processed_at)
            VALUES (:sid, :aid, CAST(:raw AS jsonb), NOW())
        """),
        {
            "sid": str(scan["id"]),
            "aid": str(agent["asset_id"]) if agent.get("asset_id") else None,
            "raw": json.dumps(body.scan_data),
        },
    )
    await agent_service.heartbeat(db, {"agent_id": body.agent_id, "status": "online"})
    await scan_service.complete_scan(db, scan["id"])
    await publish_event("scan.agent.ingested", {"scan_id": str(scan["id"]), "agent_id": body.agent_id})
    return {"scan_id": str(scan["id"]), "status": "processed"}
