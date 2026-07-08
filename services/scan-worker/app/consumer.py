"""RabbitMQ event consumer for scan-worker."""

from __future__ import annotations

import json

import aio_pika
import structlog

from vulnshield_common.database import AsyncSessionLocal
from vulnshield_common.messaging import consume_events

from app.handlers.codereview import handle_codereview_started
from app.handlers.network_scan import handle_network_scan
from app.handlers.redteam import handle_redteam_started
from app.handlers.webscan import handle_webscan_started

logger = structlog.get_logger()

ROUTING_KEYS = [
    "webscan.started",
    "scan.started",
    "scan.agentless.queued",
    "codereview.started",
    "redteam.started",
]

HANDLERS = {
    "webscan.started": handle_webscan_started,
    "scan.started": handle_network_scan,
    "scan.agentless.queued": handle_network_scan,
    "codereview.started": handle_codereview_started,
    "redteam.started": handle_redteam_started,
}


async def _dispatch(routing_key: str, payload: dict) -> None:
    handler = HANDLERS.get(routing_key)
    if not handler:
        logger.warning("unknown_routing_key", routing_key=routing_key)
        return

    async with AsyncSessionLocal() as db:
        try:
            await handler(db, payload)
            await db.commit()
        except Exception:
            await db.rollback()
            raise


async def _on_message(message: aio_pika.IncomingMessage) -> None:
    async with message.process():
        routing_key = message.routing_key or ""
        try:
            payload = json.loads(message.body.decode())
        except json.JSONDecodeError:
            logger.error("invalid_message_json", routing_key=routing_key)
            return

        logger.info("event_received", routing_key=routing_key, keys=list(payload.keys()))
        try:
            await _dispatch(routing_key, payload)
        except Exception as exc:
            logger.exception("event_handler_failed", routing_key=routing_key, error=str(exc))


async def start_consumer() -> None:
    logger.info("consumer_starting", routing_keys=ROUTING_KEYS)
    await consume_events("scan-worker.events", ROUTING_KEYS, _on_message)
