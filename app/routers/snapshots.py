from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.device import Device
from app.models.config_snapshot import ConfigSnapshot
from app.models.change_event import ChangeEvent
from app.models.user import User
from app.schemas.snapshot import SnapshotOut, SnapshotDetail, DiffResponse, ChangeEventOut
from app.services.diff_engine import compute_diff

router = APIRouter(tags=["snapshots"])


@router.get("/devices/{device_id}/snapshots", response_model=list[SnapshotOut])
async def list_snapshots(
    device_id: str,
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = await _get_device_or_404(device_id, current_user.org_id, db)
    result = await db.execute(
        select(ConfigSnapshot)
        .where(ConfigSnapshot.device_id == device.id)
        .order_by(ConfigSnapshot.captured_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotDetail)
async def get_snapshot(
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ConfigSnapshot).where(ConfigSnapshot.id == snapshot_id)
    )
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    await _get_device_or_404(snapshot.device_id, current_user.org_id, db)
    return snapshot


@router.get("/snapshots/diff", response_model=DiffResponse)
async def diff_snapshots(
    before: str = Query(..., description="Snapshot ID before"),
    after: str = Query(..., description="Snapshot ID after"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    s_before = await _get_snapshot_or_404(before, db)
    s_after = await _get_snapshot_or_404(after, db)

    await _get_device_or_404(s_before.device_id, current_user.org_id, db)

    diff_text = compute_diff(s_before.config_raw, s_after.config_raw)
    return DiffResponse(
        before_id=before,
        after_id=after,
        before_captured_at=s_before.captured_at,
        after_captured_at=s_after.captured_at,
        diff_text=diff_text,
        has_changes=bool(diff_text.strip()),
    )


@router.get("/changes", response_model=list[ChangeEventOut])
async def list_changes(
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ChangeEvent)
        .join(Device, ChangeEvent.device_id == Device.id)
        .where(Device.org_id == current_user.org_id)
        .order_by(ChangeEvent.detected_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/changes/{change_id}", response_model=ChangeEventOut)
async def get_change(
    change_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ChangeEvent)
        .join(Device, ChangeEvent.device_id == Device.id)
        .where(ChangeEvent.id == change_id, Device.org_id == current_user.org_id)
    )
    change = result.scalar_one_or_none()
    if not change:
        raise HTTPException(status_code=404, detail="Change event not found")
    return change


async def _get_device_or_404(device_id: str, org_id: str, db: AsyncSession) -> Device:
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.org_id == org_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


async def _get_snapshot_or_404(snapshot_id: str, db: AsyncSession) -> ConfigSnapshot:
    result = await db.execute(
        select(ConfigSnapshot).where(ConfigSnapshot.id == snapshot_id)
    )
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found")
    return snapshot
