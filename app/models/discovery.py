import uuid
from datetime import datetime
from sqlalchemy import String, Integer, Boolean, Float, DateTime, ForeignKey, JSON, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id", ondelete="CASCADE"))
    created_by: Mapped[str] = mapped_column(
        String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    ip_range: Mapped[str] = mapped_column(String(100), nullable=False)
    ports: Mapped[list] = mapped_column(JSON, nullable=False)
    timeout: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    # pending | running | completed | failed | cancelled
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    total_hosts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scanned_hosts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    found_hosts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error_msg: Mapped[str] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    hosts: Mapped[list] = relationship(
        "DiscoveredHost", back_populates="job", cascade="all, delete-orphan"
    )


class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id: Mapped[str] = mapped_column(
        String, ForeignKey("discovery_jobs.id", ondelete="CASCADE")
    )
    org_id: Mapped[str] = mapped_column(
        String, ForeignKey("organizations.id", ondelete="CASCADE")
    )

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    is_alive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    open_ports: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    vendor_hint: Mapped[str] = mapped_column(String(100), nullable=True)
    os_type_hint: Mapped[str] = mapped_column(String(100), nullable=True)

    # set to True once imported into the devices table
    imported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    device_id: Mapped[str] = mapped_column(
        String, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    job: Mapped["DiscoveryJob"] = relationship("DiscoveryJob", back_populates="hosts")
