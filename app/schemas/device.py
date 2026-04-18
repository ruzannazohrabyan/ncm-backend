from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class DeviceCreate(BaseModel):
    hostname: str
    ip_address: str
    port: int = 22
    vendor: Optional[str] = None
    model: Optional[str] = None
    os_type: Optional[str] = None
    credential_id: Optional[str] = None
    backup_interval_minutes: int = 60


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os_type: Optional[str] = None
    credential_id: Optional[str] = None
    is_active: Optional[bool] = None
    backup_interval_minutes: Optional[int] = None


class DeviceOut(BaseModel):
    id: str
    org_id: str
    hostname: str
    ip_address: str
    port: int
    vendor: Optional[str]
    model: Optional[str]
    os_type: Optional[str]
    is_active: bool
    backup_interval_minutes: int
    last_seen: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class CredentialCreate(BaseModel):
    label: str
    username: str
    password: str
    auth_type: str = "password"


class CredentialOut(BaseModel):
    id: str
    org_id: str
    label: str
    username: str
    auth_type: str
    created_at: datetime

    model_config = {"from_attributes": True}
