from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import encrypt_secret
from app.models.device import Device
from app.models.credential import Credential
from app.models.user import User
from app.schemas.device import DeviceCreate, DeviceUpdate, DeviceOut, CredentialCreate, CredentialOut
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


@router.post("/{device_id}/pull", status_code=202)
async def manual_pull(
    device_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == current_user.org_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    background_tasks.add_task(pull_config, device_id=device_id, triggered_by=current_user.id)
    return {"message": "Backup triggered", "device_id": device_id}


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
