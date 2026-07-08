import json
from uuid import UUID
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_sandbox import validate_scan_config_or_raise
from app.services import scan_service


async def queue_agentless_scan(db: AsyncSession, data: dict, user_id: UUID | None = None):
    validate_scan_config_or_raise(data.get("target_config", {}))
    scan = await scan_service.create_scan(
        db,
        {
            "name": data["name"],
            "scan_type": data["scan_type"],
            "target_asset_id": data.get("target_asset_id"),
            "target_config": data.get("target_config", {}),
        },
        user_id,
    )
    await scan_service.start_scan(db, scan["id"])
    await publish_event(
        "scan.agentless.queued",
        {"scan_id": str(scan["id"]), "scan_type": data["scan_type"], "config": data.get("target_config", {})},
    )
    return scan
