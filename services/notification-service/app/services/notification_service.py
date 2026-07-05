import json
from uuid import UUID
import httpx
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event


async def _dispatch(channel: str, recipient: str, subject: str | None, message: str, payload: dict | None) -> tuple[bool, str | None]:
    try:
        if channel == "email":
            return True, None
        if channel == "slack":
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.post(recipient, json={"text": message, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": message}}]})
            return True, None
        if channel == "teams":
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.post(recipient, json={"text": message})
            return True, None
        if channel == "webhook":
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.post(recipient, json={"subject": subject, "message": message, "payload": payload or {}})
            return True, None
        return False, f"Unsupported channel: {channel}"
    except Exception as exc:
        return False, str(exc)


async def send_notification(db: AsyncSession, data: dict):
    r = await db.execute(
        text("""
            INSERT INTO notifications (channel, recipient, subject, message, payload)
            VALUES (:ch, :rec, :sub, :msg, CAST(:payload AS jsonb)) RETURNING id
        """),
        {
            "ch": data["channel"],
            "rec": data["recipient"],
            "sub": data.get("subject"),
            "msg": data["message"],
            "payload": json.dumps(data.get("payload") or {}),
        },
    )
    nid = r.fetchone().id
    ok, err = await _dispatch(data["channel"], data["recipient"], data.get("subject"), data["message"], data.get("payload"))
    await db.execute(
        text("""
            UPDATE notifications SET sent = :sent, sent_at = CASE WHEN :sent THEN NOW() ELSE NULL END,
                error_message = :err WHERE id = :id
        """),
        {"id": str(nid), "sent": ok, "err": err},
    )
    await publish_event("notification.sent" if ok else "notification.failed", {"notification_id": str(nid), "channel": data["channel"]})
    return await get_notification(db, nid)


async def get_notification(db: AsyncSession, notification_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, channel::text, recipient, subject, message, payload, sent, sent_at, error_message, created_at
            FROM notifications WHERE id = :id
        """),
        {"id": str(notification_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Notification not found")
    return dict(row._mapping)


async def list_notifications(db: AsyncSession, limit=50, offset=0, channel: str | None = None):
    q = """SELECT id, channel::text, recipient, subject, sent, sent_at, created_at FROM notifications WHERE 1=1"""
    params: dict = {"limit": limit, "offset": offset}
    if channel:
        q += " AND channel = :ch"
        params["ch"] = channel
    q += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]


async def create_rule(db: AsyncSession, data: dict):
    r = await db.execute(
        text("""
            INSERT INTO notification_rules (name, event_type, severity_threshold, channels, recipients)
            VALUES (:name, :evt, :sev, CAST(:ch AS jsonb), CAST(:rec AS jsonb)) RETURNING id, created_at
        """),
        {
            "name": data["name"],
            "evt": data["event_type"],
            "sev": data.get("severity_threshold"),
            "ch": json.dumps(data.get("channels", [])),
            "rec": json.dumps(data.get("recipients", [])),
        },
    )
    row = r.fetchone()
    return {"id": row.id, "name": data["name"], "event_type": data["event_type"], "created_at": row.created_at}


async def list_rules(db: AsyncSession):
    r = await db.execute(
        text("""
            SELECT id, name, event_type, severity_threshold::text, channels, recipients, is_active, created_at
            FROM notification_rules ORDER BY created_at DESC
        """)
    )
    return [dict(row._mapping) for row in r.fetchall()]
