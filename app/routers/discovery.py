"""
Discovery router.

Endpoints
---------
POST   /discovery/scan                        – start a scan job
GET    /discovery/                             – list jobs for current org
POST   /discovery/hosts/{host_id}/ssh-pull    – SSH into a host, pull config
GET    /discovery/{job_id}                    – job detail + found hosts
GET    /discovery/{job_id}/stream             – SSE live stream (token via query param)
POST   /discovery/{job_id}/cancel             – cancel a running job
POST   /discovery/{job_id}/import             – import selected hosts into devices
DELETE /discovery/{job_id}                    – delete a completed/failed job

SSE event types published to the stream
----------------------------------------
  started      – job kicked off           {total}
  progress     – after each IP probed     {scanned, total, found}
  host_found   – alive host detected      {host: {...}}
  completed    – scan finished            {total, found}
  cancelled    – job was cancelled        {scanned, found}
  error        – fatal error              {message}
"""
import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from jose import JWTError
from netmiko import NetmikoAuthenticationException, NetmikoTimeoutException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db, AsyncSessionLocal
from app.core.deps import get_current_user
from app.core.security import decode_token, decrypt_secret
from app.models.config_snapshot import ConfigSnapshot
from app.models.credential import Credential
from app.models.device import Device
from app.models.discovery import DiscoveredHost, DiscoveryJob
from app.models.user import User
from app.schemas.discovery import (
    BulkJobRequest,
    BulkJobResponse,
    BulkJobResultItem,
    DiscoveryJobDetail,
    DiscoveryJobOut,
    DiscoveredHostOut,
    HostSshPullRequest,
    HostSshPullResult,
    ImportRequest,
    ImportedDeviceOut,
    ScanRequest,
)
from app.services.collector import _apply_facts_to_device, ssh_pull_direct
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


# ── POST /discovery/bulk/cancel ──────────────────────────────────────────────
# NOTE: bulk routes are declared BEFORE /{job_id}/* routes so that "bulk"
# is never accidentally interpreted as a job_id by FastAPI.

@router.post("/bulk/cancel", response_model=BulkJobResponse)
async def bulk_cancel_jobs(
    payload: BulkJobRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cancel multiple discovery jobs. Only pending/running jobs are cancelled."""
    result = await db.execute(
        select(DiscoveryJob).where(
            DiscoveryJob.id.in_(payload.job_ids),
            DiscoveryJob.org_id == current_user.org_id,
        )
    )
    jobs = {j.id: j for j in result.scalars().all()}

    items: list[BulkJobResultItem] = []
    succeeded = skipped = not_found = 0

    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        for job_id in payload.job_ids:
            job = jobs.get(job_id)
            if job is None:
                not_found += 1
                items.append(BulkJobResultItem(
                    job_id=job_id, status="not_found", detail="Job not found",
                ))
                continue

            if job.status not in ("pending", "running"):
                skipped += 1
                items.append(BulkJobResultItem(
                    job_id=job_id,
                    status="skipped",
                    detail=f"Status '{job.status}' is not cancellable",
                ))
                continue

            await r.set(CANCEL_KEY.format(job_id), "1", ex=300)
            succeeded += 1
            items.append(BulkJobResultItem(job_id=job_id, status="ok"))
    finally:
        await r.aclose()

    return BulkJobResponse(
        requested=len(payload.job_ids),
        succeeded=succeeded,
        skipped=skipped,
        not_found=not_found,
        results=items,
    )


# ── POST /discovery/bulk/delete ──────────────────────────────────────────────

@router.post("/bulk/delete", response_model=BulkJobResponse)
async def bulk_delete_jobs(
    payload: BulkJobRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete multiple discovery jobs.
    Running jobs are skipped (cancel them first); other statuses are deleted.
    """
    result = await db.execute(
        select(DiscoveryJob).where(
            DiscoveryJob.id.in_(payload.job_ids),
            DiscoveryJob.org_id == current_user.org_id,
        )
    )
    jobs = {j.id: j for j in result.scalars().all()}

    items: list[BulkJobResultItem] = []
    succeeded = skipped = not_found = 0

    for job_id in payload.job_ids:
        job = jobs.get(job_id)
        if job is None:
            not_found += 1
            items.append(BulkJobResultItem(
                job_id=job_id, status="not_found", detail="Job not found",
            ))
            continue

        if job.status == "running":
            skipped += 1
            items.append(BulkJobResultItem(
                job_id=job_id,
                status="skipped",
                detail="Job is running. Cancel it first.",
            ))
            continue

        await db.delete(job)
        succeeded += 1
        items.append(BulkJobResultItem(job_id=job_id, status="ok"))

    await db.commit()

    return BulkJobResponse(
        requested=len(payload.job_ids),
        succeeded=succeeded,
        skipped=skipped,
        not_found=not_found,
        results=items,
    )


# ── POST /discovery/hosts/{host_id}/ssh-pull ─────────────────────────────────
# NOTE: this route is declared BEFORE /{job_id}/* so that the literal path
# segment "hosts" is never treated as a job_id by FastAPI's router.

@router.post("/hosts/{host_id}/ssh-pull", response_model=HostSshPullResult)
async def ssh_pull_host(
    host_id: str,
    payload: HostSshPullRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    SSH into a discovered host, pull its running configuration, and persist it
    as a ConfigSnapshot.

    If the host has not yet been imported into the device inventory, it is
    automatically imported (a new Device record is created) and ``newly_imported``
    is set to ``true`` in the response.

    The endpoint accepts either a saved ``credential_id`` *or* inline
    ``username`` / ``password`` / ``port`` values.
    """
    logger.info(
        f"[SSH-PULL] ▶ Request | host_id={host_id} | user={current_user.email} | "
        f"cred={'saved:' + payload.credential_id if payload.credential_id else 'manual'} | "
        f"port={payload.port}"
    )

    # ── 1. Resolve the discovered host ───────────────────────────────────────
    host_result = await db.execute(
        select(DiscoveredHost).where(
            DiscoveredHost.id == host_id,
            DiscoveredHost.org_id == current_user.org_id,
        )
    )
    host = host_result.scalar_one_or_none()
    if not host:
        logger.warning(f"[SSH-PULL] host_id={host_id} not found for org={current_user.org_id}")
        raise HTTPException(status_code=404, detail="Discovered host not found")

    logger.info(
        f"[SSH-PULL] Host resolved | ip={host.ip_address} | "
        f"hostname={host.hostname!r} | os_hint={host.os_type_hint!r} | "
        f"imported={host.imported} | device_id={host.device_id}"
    )

    # ── 2. Resolve credentials ────────────────────────────────────────────────
    credential_id: str | None = None

    if payload.credential_id:
        cred_result = await db.execute(
            select(Credential).where(
                Credential.id == payload.credential_id,
                Credential.org_id == current_user.org_id,
            )
        )
        cred = cred_result.scalar_one_or_none()
        if not cred:
            logger.warning(
                f"[SSH-PULL] Credential {payload.credential_id} not found "
                f"for org={current_user.org_id}"
            )
            raise HTTPException(status_code=404, detail="Credential not found")
        username = cred.username
        password = decrypt_secret(cred.encrypted_password)
        credential_id = cred.id
        logger.info(
            f"[SSH-PULL] Using saved credential | label={cred.label!r} | "
            f"username={username!r}"
        )
    else:
        # Manual one-time credentials — validated by the schema already
        username = payload.username  # type: ignore[assignment]
        password = payload.password  # type: ignore[assignment]
        logger.info(
            f"[SSH-PULL] Using manual credential | username={username!r}"
        )

    port = payload.port

    # ── 3. SSH pull (blocking I/O → thread-pool) ──────────────────────────────
    logger.info(
        f"[SSH-PULL] Starting SSH connect → {host.ip_address}:{port}"
    )
    loop = asyncio.get_event_loop()
    try:
        config_raw, detected_os, facts = await loop.run_in_executor(
            None,
            lambda: ssh_pull_direct(
                ip_address=host.ip_address,
                port=port,
                os_type=host.os_type_hint,
                username=username,
                password=password,
            ),
        )
    except NetmikoAuthenticationException:
        logger.error(
            f"[SSH-PULL] ✗ Auth failed | ip={host.ip_address}:{port} | "
            f"username={username!r}"
        )
        raise HTTPException(status_code=401, detail="SSH authentication failed — check username/password")
    except NetmikoTimeoutException:
        logger.error(
            f"[SSH-PULL] ✗ Timeout | ip={host.ip_address}:{port}"
        )
        raise HTTPException(status_code=408, detail="SSH connection timed out — is the device reachable?")
    except Exception as exc:
        logger.exception(
            f"[SSH-PULL] ✗ Unexpected error | ip={host.ip_address}:{port} | {exc}"
        )
        raise HTTPException(status_code=500, detail=f"SSH error: {exc}")

    config_hash = hashlib.sha256(config_raw.encode()).hexdigest()
    logger.info(
        f"[SSH-PULL] ✓ Config received | ip={host.ip_address} | "
        f"os={detected_os!r} | chars={len(config_raw)} | hash={config_hash[:12]}…"
    )

    # ── 4. Get or create Device record ────────────────────────────────────────
    newly_imported = False

    if host.device_id:
        dev_result = await db.execute(
            select(Device).where(Device.id == host.device_id)
        )
        device = dev_result.scalar_one_or_none()
        if device is None:
            logger.warning(
                f"[SSH-PULL] host.device_id={host.device_id} points to missing "
                f"Device — treating as not-yet-imported"
            )
            host.device_id = None
        else:
            logger.info(
                f"[SSH-PULL] Host already imported | device_id={device.id} | "
                f"hostname={device.hostname!r}"
            )

    if not host.device_id:
        logger.info(
            f"[SSH-PULL] Creating new Device from host {host.ip_address}"
        )
        device = Device(
            org_id=current_user.org_id,
            credential_id=credential_id,
            hostname=host.hostname or host.ip_address,
            ip_address=host.ip_address,
            port=port,
            vendor=host.vendor_hint,
            os_type=detected_os,
            is_active=True,
        )
        db.add(device)
        await db.flush()          # get device.id

        host.imported = True
        host.device_id = device.id
        host.os_type_hint = detected_os
        newly_imported = True
        logger.info(
            f"[SSH-PULL] Device created | device_id={device.id} | "
            f"hostname={device.hostname!r} | os={detected_os!r}"
        )
    else:
        # Update OS type if we just learned it for the first time
        if not device.os_type:  # type: ignore[union-attr]
            device.os_type = detected_os   # type: ignore[union-attr]
            logger.info(
                f"[SSH-PULL] Updated device os_type → {detected_os!r}"
            )

    # Apply harvested inventory facts (model, serial, OS version, etc.)
    _apply_facts_to_device(device, facts)  # type: ignore[arg-type]

    # ── 5. Save ConfigSnapshot ────────────────────────────────────────────────
    snapshot = ConfigSnapshot(
        device_id=device.id,    # type: ignore[union-attr]
        triggered_by=current_user.id,
        config_raw=config_raw,
        hash=config_hash,
        trigger_type="manual",
    )
    db.add(snapshot)
    await db.flush()

    device.last_seen = datetime.now(timezone.utc)  # type: ignore[union-attr]

    await db.commit()

    logger.info(
        f"[SSH-PULL] ✓ Done | ip={host.ip_address} | device_id={device.id} | "  # type: ignore[union-attr]
        f"snapshot_id={snapshot.id} | newly_imported={newly_imported}"
    )

    return HostSshPullResult(
        device_id=device.id,      # type: ignore[union-attr]
        snapshot_id=snapshot.id,
        config_hash=config_hash,
        config_preview=config_raw[:500],
        os_type=detected_os,
        newly_imported=newly_imported,
    )


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

    # Build the response without touching `job.hosts` (lazy relationship would
    # trigger a sync IO call on an async session and raise MissingGreenlet).
    base = DiscoveryJobOut.model_validate(job)
    return DiscoveryJobDetail(
        **base.model_dump(),
        hosts=[DiscoveredHostOut.model_validate(h) for h in hosts],
    )


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

    if job.status == "running":
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a running job. Cancel it first."
        )

    await db.delete(job)
    await db.commit()
    return None
