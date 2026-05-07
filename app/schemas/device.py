from pydantic import BaseModel, model_validator
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


# ── Manual / on-demand pull from the Devices page ─────────────────────────────

class DevicePullRequest(BaseModel):
    """
    Body for POST /devices/{device_id}/pull.

    All fields are optional. Credentials are resolved with this priority:

      1. ``credential_id`` from the body, if provided.
      2. Inline ``username`` + ``password`` from the body, if both provided.
      3. The device's saved ``credential_id``, if set.
      4. Otherwise the API returns HTTP 400 with
         ``{"code": "credentials_required", ...}`` so the UI can prompt for
         manual credentials.

    ``port`` overrides the device's stored port for this pull only — it is not
    persisted back onto the Device row.
    """
    credential_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    port: Optional[int] = None

    @model_validator(mode="after")
    def validate_manual_pair(self) -> "DevicePullRequest":
        # If one of username/password is provided, the other is required.
        if (self.username is None) != (self.password is None):
            raise ValueError(
                "Both 'username' and 'password' must be provided together for manual credentials"
            )
        # If the caller passed both a saved credential_id AND inline creds,
        # we accept it but credential_id wins (documented above).
        return self


class DevicePullResult(BaseModel):
    """Result of POST /devices/{device_id}/pull. Mirrors HostSshPullResult shape."""
    device_id: str
    detected_os: str

    # Running config (always present on success)
    snapshot_id: str
    config_hash: str
    config_preview: str          # first 500 chars
    change_event_id: Optional[str] = None  # populated when running-config changed

    # Startup config (optional, depends on platform support)
    startup_supported: bool = False
    startup_pull_failed: bool = False
    startup_snapshot_id: Optional[str] = None
    startup_hash: Optional[str] = None
    startup_preview: Optional[str] = None
    in_sync: Optional[bool] = None
