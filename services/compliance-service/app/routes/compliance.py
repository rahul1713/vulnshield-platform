from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import AssessmentCreate, CISBenchmarkRequest, FrameworkResponse
from app.services import compliance_service

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.get("/frameworks", response_model=list[FrameworkResponse])
async def frameworks(
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("compliance:read")),
):
    return await compliance_service.list_frameworks(db)


@router.get("/frameworks/{framework_id}")
async def get_framework(
    framework_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("compliance:read")),
):
    return await compliance_service.get_framework(db, framework_id)


@router.get("/map/{framework}/{control_id}")
async def map_control(
    framework: str,
    control_id: str,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("compliance:read")),
):
    return await compliance_service.map_control(db, framework, control_id)


@router.post("/assessments")
async def assess(
    body: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("compliance:write")),
):
    return await compliance_service.create_assessment(db, body.model_dump())


@router.get("/assessments")
async def list_assessments(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("compliance:read")),
):
    return await compliance_service.list_assessments(db, limit, offset)


@router.post("/cis-benchmark")
async def cis_benchmark(
    body: CISBenchmarkRequest,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("compliance:write")),
):
    return await compliance_service.run_cis_benchmark(db, body.model_dump())
