from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, field_validator
import ipaddress


class ScanRequest(BaseModel):
    ip_range: str
    ports: list[int] = [22, 23, 80, 443, 830]
    timeout: float = 1.0

    @field_validator("ip_range")
    @classmethod
    def validate_ip_range(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP range (e.g. 192.168.1.0/24)")
        return v

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: list[int]) -> list[int]:
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} is out of range (1-65535)")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if not (0.1 <= v <= 10.0):
            raise ValueError("timeout must be between 0.1 and 10 seconds")
        return v


class DiscoveryJobOut(BaseModel):
    id: str
    org_id: str
    created_by: Optional[str]
    ip_range: str
    ports: list[int]
    timeout: float
    status: str
    total_hosts: int
    scanned_hosts: int
    found_hosts: int
    error_msg: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class DiscoveredHostOut(BaseModel):
    id: str
    job_id: str
    ip_address: str
    hostname: Optional[str]
    is_alive: bool
    open_ports: list[int]
    vendor_hint: Optional[str]
    os_type_hint: Optional[str]
    imported: bool
    device_id: Optional[str]
    discovered_at: datetime

    model_config = {"from_attributes": True}


class DiscoveryJobDetail(DiscoveryJobOut):
    hosts: list[DiscoveredHostOut] = []


class ImportRequest(BaseModel):
    host_ids: list[str]
    credential_id: Optional[str] = None


class ImportedDeviceOut(BaseModel):
    host_id: str
    device_id: str
    ip_address: str


class BulkJobRequest(BaseModel):
    job_ids: list[str]

    @field_validator("job_ids")
    @classmethod
    def non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("job_ids must not be empty")
        return v


class BulkJobResultItem(BaseModel):
    job_id: str
    status: str  # "ok" | "skipped" | "not_found"
    detail: Optional[str] = None


class BulkJobResponse(BaseModel):
    requested: int
    succeeded: int
    skipped: int
    not_found: int
    results: list[BulkJobResultItem]
