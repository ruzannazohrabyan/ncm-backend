from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import encrypt_secret
from app.models.device import Device
from app.models.credential import Credential
from app.models.user import User
from app.schemas.device import (
    DeviceCreate,
    DeviceUpdate,
    DeviceOut,
    CredentialCreate,
    CredentialOut,
    DevicePullRequest,
    DevicePullResult,
)
from app.services.collector import pull_config, refresh_device_facts

router = APIRouter(prefix="/devices", tags=["devices"])

# ── Credentials ──────────────────────────────────────────────────────────────

@router.get("/credentials", response_model=list[CredentialOut])
async def list_credentials(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Credential).where(Credential.org_id == current_user.org_id)
    )
    return result.scalars().all()


@router.post("/credentials", response_model=CredentialOut, status_code=201)
async def create_credential(
    payload: CredentialCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cred = Credential(
        org_id=current_user.org_id,
        label=payload.label,
        username=payload.username,
        encrypted_password=encrypt_secret(payload.password),
        auth_type=payload.auth_type,
    )
    db.add(cred)
    await db.flush()
    return cred


@router.delete("/credentials/{cred_id}", status_code=204)
async def delete_credential(
    cred_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Credential).where(Credential.id == cred_id, Credential.org_id == current_user.org_id)
    )
    cred = result.scalar_one_or_none()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    await db.delete(cred)


# ── Devices ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[DeviceOut])
async def list_devices(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Device).where(Device.org_id == current_user.org_id)
    )
    return result.scalars().all()


@router.post("", response_model=DeviceOut, status_code=201)
async def create_device(
    payload: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = Device(**payload.model_dump(), org_id=current_user.org_id)
    db.add(device)
    await db.flush()
    return device


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == current_user.org_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.put("/{device_id}", response_model=DeviceOut)
async def update_device(
    device_id: str,
    payload: DeviceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == current_user.org_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(device, field, value)
    return device


@router.delete("/{device_id}", status_code=204)
async def delete_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == current_user.org_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    await db.delete(device)


@router.post("/{device_id}/pull", response_model=DevicePullResult)
async def manual_pull(
    device_id: str,
    payload: DevicePullRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Pull the running- (and startup-, where supported) config for a device
    on demand.

    The endpoint runs the pull *synchronously* and returns a rich result,
    matching the shape the discovery SSH-pull endpoint uses. This lets the UI
    show snapshot ids, hashes, previews, and the running⇄startup ``in_sync``
    flag immediately after the action.

    Credential resolution priority:

      1. ``payload.credential_id``                  – an existing saved credential
      2. ``payload.username`` + ``payload.password`` – inline manual credentials
      3. ``device.credential_id``                   – the device's saved credential
      4. None of the above → HTTP 400 with
         ``{"code": "credentials_required", ...}`` so the UI can prompt the
         operator to enter credentials manually and retry the same endpoint.
    """
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == current_user.org_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    body = payload or DevicePullRequest()

    # If the caller passed a saved credential_id, verify it belongs to this org
    # before handing it down to `pull_config` (which doesn't know about orgs).
    if body.credential_id:
        cred_check = await db.execute(
            select(Credential).where(
                Credential.id == body.credential_id,
                Credential.org_id == current_user.org_id,
            )
        )
        if cred_check.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=404,
                detail="Credential not found or not accessible to your organization",
            )

    outcome = await pull_config(
        device_id=device_id,
        triggered_by=current_user.id,
        credential_id=body.credential_id,
        username=body.username,
        password=body.password,
        port=body.port,
    )

    if not outcome.success:
        # Map domain error codes onto HTTP status codes. The "code" field in
        # detail lets the frontend pattern-match without parsing free text —
        # in particular, "credentials_required" should trigger the manual
        # credentials form.
        status_map = {
            "credentials_required": 400,
            "credential_not_found": 404,
            "device_missing": 404,
            "auth_failed": 401,
            "timeout": 408,
            "ssh_error": 502,
        }
        status_code = status_map.get(outcome.error_code or "", 500)
        raise HTTPException(
            status_code=status_code,
            detail={
                "code": outcome.error_code,
                "message": outcome.error_message
                or "Failed to pull configuration",
            },
        )

    return DevicePullResult(
        device_id=device_id,
        detected_os=outcome.detected_os or device.os_type or "",
        snapshot_id=outcome.running_snapshot_id,        # type: ignore[arg-type]
        config_hash=outcome.running_hash,               # type: ignore[arg-type]
        config_preview=outcome.running_preview or "",
        change_event_id=outcome.change_event_id,
        startup_supported=outcome.startup_supported,
        startup_pull_failed=outcome.startup_pull_failed,
        startup_snapshot_id=outcome.startup_snapshot_id,
        startup_hash=outcome.startup_hash,
        startup_preview=outcome.startup_preview,
        in_sync=outcome.in_sync,
    )


@router.post("/{device_id}/refresh-facts", response_model=DeviceOut)
async def refresh_facts(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Re-collect inventory facts (model, serial, OS version, image, uptime, ...)
    for a device by SSH-ing in and running ``show version`` (or the platform
    equivalent). Returns the freshly updated device.
    """
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == current_user.org_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    facts = await refresh_device_facts(device_id)
    if facts is None:
        raise HTTPException(
            status_code=502,
            detail="Could not refresh device facts — check connectivity, credentials and OS type.",
        )

    # Re-fetch the now-updated row so the response reflects the new values.
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == current_user.org_id)
    )
    return result.scalar_one()
