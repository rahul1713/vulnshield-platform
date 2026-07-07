from uuid import UUID
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from vulnshield_common.storage import download_file
from app.schemas import ReportCreate, ReportResponse
from app.services import report_service
from vulnshield_common.entity_reports import (
    generate_codereview_executive_report,
    generate_redteam_executive_report,
    generate_scan_executive_report,
)

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("", response_model=list[ReportResponse])
async def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("reports:read")),
):
    return await report_service.list_reports(db, limit, offset)


@router.post("", response_model=ReportResponse, status_code=201)
async def generate_report(
    body: ReportCreate,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("reports:write")),
):
    from uuid import UUID as U

    return await report_service.generate_report(db, body.model_dump(), U(user.user_id))


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("reports:read")),
):
    return await report_service.get_report(db, report_id)


@router.post("/from-scan/{scan_id}", response_model=ReportResponse, status_code=201)
async def report_from_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("reports:write")),
):
    from uuid import UUID as U

    return await generate_scan_executive_report(db, scan_id, U(user.user_id))


@router.post("/from-codereview/{review_id}", response_model=ReportResponse, status_code=201)
async def report_from_codereview(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("reports:write")),
):
    from uuid import UUID as U

    return await generate_codereview_executive_report(db, review_id, U(user.user_id))


@router.post("/from-redteam/{campaign_id}", response_model=ReportResponse, status_code=201)
async def report_from_redteam(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("reports:write")),
):
    from uuid import UUID as U

    return await generate_redteam_executive_report(db, campaign_id, U(user.user_id))


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("reports:read")),
):
    report = await report_service.get_report(db, report_id)
    if not report.get("file_path"):
        from fastapi import HTTPException

        raise HTTPException(404, "Report file not available")
    object_name = report["file_path"].split("/", 1)[-1]
    data = await download_file(object_name)
    media = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json",
        "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    return Response(content=data, media_type=media.get(report["format"], "application/octet-stream"))
