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
    # Inventory facts — usually populated automatically, but exposed here so
    # operators can override / correct values manually.
    serial_number: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_image: Optional[str] = None
    hardware: Optional[str] = None
    uptime: Optional[str] = None


class DeviceOut(BaseModel):
    id: str
    org_id: str
    hostname: str
    ip_address: str
    port: int
    vendor: Optional[str]
    model: Optional[str]
    os_type: Optional[str]
    serial_number: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_image: Optional[str] = None
    hardware: Optional[str] = None
    uptime: Optional[str] = None
    facts_updated_at: Optional[datetime] = None
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
