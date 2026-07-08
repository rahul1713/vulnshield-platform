"""Handle redteam.started events with nuclei against scope targets."""

from __future__ import annotations

import json
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_engines import run_nuclei
from vulnshield_common.scan_sandbox import is_allowed_scan_target, sanitize_log_text, truncate_for_storage

logger = structlog.get_logger()


def _extract_scope_urls(scope: dict) -> list[str]:
    urls: list[str] = []
    for key in ("targets", "urls", "web_targets", "hosts"):
        val = scope.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.startswith(("http://", "https://")):
                    urls.append(item)
                elif isinstance(item, dict) and item.get("url"):
                    urls.append(item["url"])
    base = scope.get("base_url") or scope.get("target_url")
    if isinstance(base, str) and base.startswith(("http://", "https://")):
        urls.append(base)
    return list(dict.fromkeys(urls))


async def handle_redteam_started(db: AsyncSession, payload: dict) -> None:
    campaign_id = UUID(payload["campaign_id"])

    row = await db.execute(
        text("SELECT id, status::text, scope FROM red_team_campaigns WHERE id = :id"),
        {"id": str(campaign_id)},
    )
    campaign = row.fetchone()
    if not campaign:
        logger.warning("redteam_not_found", campaign_id=str(campaign_id))
        return

    scope = campaign.scope if isinstance(campaign.scope, dict) else {}
    urls = _extract_scope_urls(scope)
    if not urls:
        logger.info("redteam_no_scope_urls", campaign_id=str(campaign_id))
        return

    total = 0
    for url in urls[:5]:
        try:
            if not is_allowed_scan_target(url):
                raise ValueError(f"Target not allowed: {url}")
        except ValueError as exc:
            logger.warning("redteam_target_blocked", url=url, error=sanitize_log_text(str(exc)))
            continue
        try:
            findings = await run_nuclei(url)
        except Exception as exc:
            logger.error("redteam_nuclei_failed", url=url, error=sanitize_log_text(str(exc)))
            continue

        for i, f in enumerate(findings):
            await db.execute(
                text("""
                    INSERT INTO red_team_findings (
                        campaign_id, title, description, severity, attack_phase,
                        proof, remediation, attack_chain_step, is_simulated
                    ) VALUES (
                        :cid, :title, :desc, :sev, 'Reconnaissance',
                        :proof, :rem, :step, FALSE
                    )
                """),
                {
                    "cid": str(campaign_id),
                    "title": str(f.get("title", "Nuclei finding"))[:500],
                    "desc": truncate_for_storage(f.get("description")),
                    "sev": f.get("severity", "medium"),
                    "proof": truncate_for_storage(f.get("proof") or f.get("url")),
                    "rem": truncate_for_storage(f.get("remediation")),
                    "step": 100 + i,
                },
            )
            total += 1

    if total:
        await db.execute(
            text("UPDATE red_team_campaigns SET findings_count = findings_count + :fc WHERE id = :id"),
            {"id": str(campaign_id), "fc": total},
        )
        await publish_event("redteam.engine.completed", {"campaign_id": str(campaign_id), "findings": total})

    logger.info("redteam_engine_done", campaign_id=str(campaign_id), findings=total)
