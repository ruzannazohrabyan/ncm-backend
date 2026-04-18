import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(50), default="standard")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users: Mapped[list] = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    devices: Mapped[list] = relationship("Device", back_populates="organization", cascade="all, delete-orphan")
    credentials: Mapped[list] = relationship("Credential", back_populates="organization", cascade="all, delete-orphan")
    alert_rules: Mapped[list] = relationship("AlertRule", back_populates="organization", cascade="all, delete-orphan")
