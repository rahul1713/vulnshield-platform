from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event


async def list_patches(db: AsyncSession, limit=50, offset=0, patch_available: bool | None = None):
    q = """SELECT id, vulnerability_id, cve_id, patch_available, patch_id, patch_title, patch_severity::text,
           patch_release_date, patch_download_url, vendor_advisory_url, eol_status, eol_date, created_at
           FROM patch_information WHERE 1=1"""
    params: dict = {"limit": limit, "offset": offset}
    if patch_available is not None:
        q += " AND patch_available = :pa"
        params["pa"] = patch_available
    q += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]


async def get_patch(db: AsyncSession, patch_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, vulnerability_id, cve_id, patch_available, patch_id, patch_title, patch_severity::text,
                   patch_release_date, patch_download_url, vendor_advisory_url, workaround,
                   compensating_controls, eol_status, eol_date, created_at, updated_at
            FROM patch_information WHERE id = :id
        """),
        {"id": str(patch_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Patch record not found")
    return dict(row._mapping)


async def create_patch(db: AsyncSession, data: dict):
    r = await db.execute(
        text("""
            INSERT INTO patch_information (vulnerability_id, cve_id, patch_available, patch_id, patch_title,
                patch_severity, patch_release_date, patch_download_url, vendor_advisory_url, workaround, eol_status, eol_date)
            VALUES (:vid, :cid, :pa, :pid, :title, :sev, :rel, :dl, :adv, :wa, :eol, :eol_date)
            RETURNING id
        """),
        {
            "vid": str(data["vulnerability_id"]) if data.get("vulnerability_id") else None,
            "cid": str(data["cve_id"]) if data.get("cve_id") else None,
            "pa": data.get("patch_available", False),
            "pid": data.get("patch_id"),
            "title": data.get("patch_title"),
            "sev": data.get("patch_severity"),
            "rel": data.get("patch_release_date"),
            "dl": data.get("patch_download_url"),
            "adv": data.get("vendor_advisory_url"),
            "wa": data.get("workaround"),
            "eol": data.get("eol_status", False),
            "eol_date": data.get("eol_date"),
        },
    )
    patch_id = r.fetchone().id
    await publish_event("patch.created", {"patch_id": str(patch_id)})
    return await get_patch(db, patch_id)


async def check_eol(db: AsyncSession, software_name: str):
    r = await db.execute(
        text("""
            SELECT id, patch_title, eol_status, eol_date, vendor_advisory_url
            FROM patch_information
            WHERE patch_title ILIKE :name OR workaround ILIKE :name
            ORDER BY eol_date NULLS LAST LIMIT 10
        """),
        {"name": f"%{software_name}%"},
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def get_advisories(db: AsyncSession, cve_identifier: str | None = None):
    q = """SELECT pi.id, pi.patch_title, pi.vendor_advisory_url, pi.patch_release_date, c.cve_id
           FROM patch_information pi LEFT JOIN cves c ON pi.cve_id = c.id WHERE vendor_advisory_url IS NOT NULL"""
    params: dict = {}
    if cve_identifier:
        q += " AND c.cve_id = :cve"
        params["cve"] = cve_identifier
    q += " ORDER BY pi.patch_release_date DESC NULLS LAST LIMIT 50"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]
