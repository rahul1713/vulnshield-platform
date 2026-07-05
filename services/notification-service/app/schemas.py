from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class NotificationCreate(BaseModel):
    channel: str
    recipient: str
    subject: str | None = None
    message: str
    payload: dict | None = None


class NotificationResponse(BaseModel):
    id: UUID
    channel: str
    recipient: str
    subject: str | None
    sent: bool
    sent_at: datetime | None
    created_at: datetime


class NotificationRuleCreate(BaseModel):
    name: str
    event_type: str
    severity_threshold: str | None = None
    channels: list = []
    recipients: list = []
