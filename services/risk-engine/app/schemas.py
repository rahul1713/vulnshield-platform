from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class RiskScoreRequest(BaseModel):
    entity_type: str
    entity_id: UUID


class RiskScoreResponse(BaseModel):
    id: UUID
    entity_type: str
    entity_id: UUID
    technical_risk: float | None
    business_risk: float | None
    overall_score: float | None
    calculated_at: datetime
