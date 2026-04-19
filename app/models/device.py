import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Integer, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id", ondelete="CASCADE"))
    credential_id: Mapped[str] = mapped_column(String, ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True)

    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22)
    vendor: Mapped[str] = mapped_column(String(100), nullable=True)   # cisco, juniper, mikrotik
    model: Mapped[str] = mapped_column(String(100), nullable=True)
    os_type: Mapped[str] = mapped_column(String(100), nullable=True)  # cisco_ios, junos, routeros

    # ── Inventory facts (populated from `show version` / equivalent) ──────────
    # These are best-effort and may be NULL until the device has been polled.
    serial_number: Mapped[str] = mapped_column(String(100), nullable=True)
    os_name: Mapped[str] = mapped_column(String(100), nullable=True)        # e.g. "IOS", "IOS-XE", "NX-OS", "JUNOS", "RouterOS"
    os_version: Mapped[str] = mapped_column(String(100), nullable=True)     # e.g. "15.2(4)M7", "17.09.04a"
    os_image: Mapped[str] = mapped_column(String(255), nullable=True)       # e.g. "c2900-universalk9-mz.SPA.151-4.M4.bin"
    hardware: Mapped[str] = mapped_column(String(255), nullable=True)       # e.g. "CISCO2911/K9", chassis description
    uptime: Mapped[str] = mapped_column(String(255), nullable=True)         # human-readable, as reported by the device
    facts_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    backup_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    organization: Mapped["Organization"] = relationship("Organization", back_populates="devices")
    credential: Mapped["Credential"] = relationship("Credential", back_populates="devices")
    snapshots: Mapped[list] = relationship("ConfigSnapshot", back_populates="device", cascade="all, delete-orphan")
    change_events: Mapped[list] = relationship("ChangeEvent", back_populates="device", cascade="all, delete-orphan")
