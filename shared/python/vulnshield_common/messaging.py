import json
from typing import Any

import aio_pika
import structlog

from vulnshield_common.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

_connection: aio_pika.RobustConnection | None = None
_channel: aio_pika.RobustChannel | None = None


async def get_rabbitmq_channel() -> aio_pika.RobustChannel:
    global _connection, _channel
    if _channel is None or _channel.is_closed:
        _connection = await aio_pika.connect_robust(settings.rabbitmq_url)
        _channel = await _connection.channel()
        await _channel.set_qos(prefetch_count=10)
    return _channel


async def publish_event(routing_key: str, payload: dict[str, Any]) -> None:
    channel = await get_rabbitmq_channel()
    exchange = await channel.declare_exchange("vulnshield.events", aio_pika.ExchangeType.TOPIC, durable=True)
    message = aio_pika.Message(
        body=json.dumps(payload, default=str).encode(),
        content_type="application/json",
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
    )
    await exchange.publish(message, routing_key=routing_key)
    logger.info("event_published", routing_key=routing_key)


async def consume_events(queue_name: str, routing_keys: list[str], callback) -> None:
    channel = await get_rabbitmq_channel()
    exchange = await channel.declare_exchange("vulnshield.events", aio_pika.ExchangeType.TOPIC, durable=True)
    queue = await channel.declare_queue(queue_name, durable=True)
    for key in routing_keys:
        await queue.bind(exchange, routing_key=key)
    await queue.consume(callback)
