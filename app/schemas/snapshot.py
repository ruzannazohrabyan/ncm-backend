from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class SnapshotOut(BaseModel):
    id: str
    device_id: str
    hash: str
    config_type: str  # "running" | "startup"
    trigger_type: str
    captured_at: datetime
    triggered_by: Optional[str]
    is_latest: bool
    synced_at: Optional[datetime]

    model_config = {"from_attributes": True}


class SnapshotDetail(SnapshotOut):
    config_raw: str


class DiffResponse(BaseModel):
    before_id: str
    after_id: str
    before_captured_at: datetime
    after_captured_at: datetime
    diff_text: str
    has_changes: bool


class ChangeEventOut(BaseModel):
    id: str
    device_id: str
    snapshot_before_id: Optional[str]
    snapshot_after_id: Optional[str]
    diff_text: Optional[str]
    severity: str
    notified: bool
    detected_at: datetime

    model_config = {"from_attributes": True}
