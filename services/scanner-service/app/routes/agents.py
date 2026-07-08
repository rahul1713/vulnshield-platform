from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import AgentHeartbeat, AgentInventory, AgentRegister
from app.services import agent_service

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.get("")
async def list_agents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await agent_service.list_agents(db, limit, offset)


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await agent_service.get_agent(db, agent_id)


@router.post("/register", status_code=201)
async def register(
    body: AgentRegister,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    if not agent_service.verify_mtls(request, body.certificate_fingerprint):
        from fastapi import HTTPException

        raise HTTPException(401, "mTLS certificate verification failed")
    return await agent_service.register_agent(db, body.model_dump())


@router.post("/heartbeat")
async def agent_heartbeat_legacy(
    body: AgentHeartbeat,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    return await agent_service.heartbeat(db, body.model_dump())


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    body: AgentHeartbeat,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    payload = body.model_dump()
    payload["agent_id"] = agent_id
    return await agent_service.heartbeat(db, payload)


@router.post("/{agent_id}/inventory")
async def agent_inventory(
    agent_id: str,
    body: AgentInventory,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    return await agent_service.ingest_inventory(db, agent_id, body.model_dump())
