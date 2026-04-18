"""
Discovery router.

Endpoints
---------
POST   /discovery/scan                  – start a scan job
GET    /discovery/                       – list jobs for current org
GET    /discovery/{job_id}              – job detail + found hosts
GET    /discovery/{job_id}/stream       – SSE live stream (token via query param)
POST   /discovery/{job_id}/cancel       – cancel a running job
POST   /discovery/{job_id}/import       – import selected hosts into devices
DELETE /discovery/{job_id}              – delete a completed/failed job

SSE event types published to the stream
----------------------------------------
  started      – job kicked off           {total}
  progress     – after each IP probed     {scanned, total, found}
  host_found   – alive host detected      {host: {...}}
  completed    – scan finished            {total, found}
  cancelled    – job was cancelled        {scanned, found}
  error        – fatal error              {message}
"""
import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db, AsyncSessionLocal
from app.core.deps import get_current_user
from app.core.security import decode_token
from app.models.device import Device
from app.models.discovery import DiscoveredHost, DiscoveryJob
from app.models.user import User
from app.schemas.discovery import (
    DiscoveryJobDetail,
    DiscoveryJobOut,
    DiscoveredHostOut,
    ImportRequest,
    ImportedDeviceOut,
    ScanRequest,
)
from app.workers.discovery_task import CANCEL_KEY, run_discovery

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/discovery", tags=["discovery"])


# ── helpers ───────────────────────────────────────────────────────────────────

async def _get_job_or_404(job_id: str, org_id: str, db: AsyncSession) -> DiscoveryJob:
    result = await db.execute(
        select(DiscoveryJob).where(
            DiscoveryJob.id == job_id,
            DiscoveryJob.org_id == org_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return job


# ── POST /discovery/scan ──────────────────────────────────────────────────────

@router.post("/scan", response_model=DiscoveryJobOut, status_code=202)
async def start_scan(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = DiscoveryJob(
        org_id=current_user.org_id,
        created_by=current_user.id,
        ip_range=payload.ip_range,
        ports=payload.ports,
        timeout=payload.timeout,
        status="pending",
    )
    db.add(job)
    await db.flush()          # get job.id before commit
    job_id = job.id
    await db.commit()

    # Fire-and-forget Celery task
    run_discovery.delay(job_id)

    return job


# ── GET /discovery/ ───────────────────────────────────────────────────────────

@router.get("/", response_model=list[DiscoveryJobOut])
async def list_jobs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(DiscoveryJob)
        .where(DiscoveryJob.org_id == current_user.org_id)
        .order_by(DiscoveryJob.created_at.desc())
    )
    return result.scalars().all()


# ── GET /discovery/{job_id} ───────────────────────────────────────────────────

@router.get("/{job_id}", response_model=DiscoveryJobDetail)
async def get_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = await _get_job_or_404(job_id, current_user.org_id, db)

    hosts_result = await db.execute(
        select(DiscoveredHost)
        .where(DiscoveredHost.job_id == job_id)
        .order_by(DiscoveredHost.discovered_at)
    )
    hosts = hosts_result.scalars().all()

    detail = DiscoveryJobDetail.model_validate(job)
    detail.hosts = [DiscoveredHostOut.model_validate(h) for h in hosts]
    return detail


# ── GET /discovery/{job_id}/stream  (SSE) ─────────────────────────────────────

@router.get("/{job_id}/stream")
async def stream_job(
    job_id: str,
    token: str = Query(..., description="Bearer access token"),
):
    """
    Server-Sent Events stream for a discovery job.

    Because EventSource (browser) cannot send an Authorization header,
    the access token is accepted as a query parameter here.
    """
    # ── Authenticate from query param ────────────────────────────────────────
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id: str = payload["sub"]
        org_id: str = payload["org"]
    except (JWTError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # ── Verify job belongs to user's org ──────────────────────────────────────
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(DiscoveryJob).where(
                DiscoveryJob.id == job_id,
                DiscoveryJob.org_id == org_id,
            )
        )
        job = result.scalar_one_or_none()
        if not job:
            raise HTTPException(status_code=404, detail="Discovery job not found")

        already_done = job.status in ("completed", "failed", "cancelled")

        if already_done:
            hosts_result = await db.execute(
                select(DiscoveredHost)
                .where(DiscoveredHost.job_id == job_id)
                .order_by(DiscoveredHost.discovered_at)
            )
            past_hosts = hosts_result.scalars().all()
        else:
            past_hosts = []

    # ── Generator ─────────────────────────────────────────────────────────────
    async def event_generator():
        # If the job already finished, replay all hosts then send terminal event
        if already_done:
            for h in past_hosts:
                data = json.dumps({
                    "event": "host_found",
                    "host": {
                        "id": h.id,
                        "ip_address": h.ip_address,
                        "hostname": h.hostname,
                        "open_ports": h.open_ports,
                        "vendor_hint": h.vendor_hint,
                        "os_type_hint": h.os_type_hint,
                    },
                })
                yield f"data: {data}\n\n"

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(DiscoveryJob).where(DiscoveryJob.id == job_id)
                )
                j = result.scalar_one()
                terminal = json.dumps({
                    "event": j.status,
                    "total": j.total_hosts,
                    "found": j.found_hosts,
                })
            yield f"data: {terminal}\n\n"
            return

        # Job still running — subscribe to Redis pub/sub
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        pubsub = r.pubsub()
        channel = f"discovery:{job_id}"
        await pubsub.subscribe(channel)

        try:
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue

                raw: str = message["data"]
                yield f"data: {raw}\n\n"

                # Close the stream once the job reaches a terminal state
                try:
                    parsed = json.loads(raw)
                    if parsed.get("event") in ("completed", "cancelled", "error"):
                        break
                except json.JSONDecodeError:
                    pass
        finally:
            await pubsub.unsubscribe(channel)
            await r.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable Nginx buffering
            "Connection": "keep-alive",
        },
    )


# ── POST /discovery/{job_id}/cancel ──────────────────────────────────────────

@router.post("/{job_id}/cancel", status_code=202)
async def cancel_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = await _get_job_or_404(job_id, current_user.org_id, db)

    if job.status not in ("pending", "running"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel a job with status '{job.status}'"
        )

    # Set the Redis flag; the worker checks it each iteration
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    await r.set(CANCEL_KEY.format(job_id), "1", ex=300)
    await r.aclose()

    return {"message": "Cancellation requested", "job_id": job_id}


# ── POST /discovery/{job_id}/import ──────────────────────────────────────────

@router.post("/{job_id}/import", response_model=list[ImportedDeviceOut], status_code=201)
async def import_hosts(
    job_id: str,
    payload: ImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _get_job_or_404(job_id, current_user.org_id, db)

    hosts_result = await db.execute(
        select(DiscoveredHost).where(
            DiscoveredHost.id.in_(payload.host_ids),
            DiscoveredHost.job_id == job_id,
            DiscoveredHost.org_id == current_user.org_id,
        )
    )
    hosts = hosts_result.scalars().all()

    if not hosts:
        raise HTTPException(status_code=404, detail="No matching hosts found")

    imported: list[ImportedDeviceOut] = []

    for host in hosts:
        if host.imported:
            # Already imported — skip silently
            continue

        device = Device(
            org_id=current_user.org_id,
            credential_id=payload.credential_id,
            hostname=host.hostname or host.ip_address,
            ip_address=host.ip_address,
            vendor=host.vendor_hint,
            os_type=host.os_type_hint,
            is_active=True,
        )
        db.add(device)
        await db.flush()

        host.imported = True
        host.device_id = device.id

        imported.append(ImportedDeviceOut(
            host_id=host.id,
            device_id=device.id,
            ip_address=host.ip_address,
        ))

    await db.commit()
    return imported


# ── DELETE /discovery/{job_id} ────────────────────────────────────────────────

@router.delete("/{job_id}", status_code=204)
async def delete_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = await _get_job_or_404(job_id, current_user.org_id, db)

    if job.status in ("pending", "running"):
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a running job. Cancel it first."
        )

    await db.delete(job)
