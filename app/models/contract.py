"""Modele Contract."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    CHAR,
    BigInteger,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import ContractStatus
from app.models.user import User


class Contract(Base):
    __tablename__ = "contracts"
    __table_args__ = (
        CheckConstraint("owner_id <> client_id", name="owner_ne_client"),
        CheckConstraint("end_date > start_date", name="end_after_start"),
        CheckConstraint("deposit_cents BETWEEN 1 AND 50000000", name="deposit_bounds"),
        CheckConstraint("currency IN ('EUR','CHF','GBP','USD')", name="currency_whitelist"),
        CheckConstraint("length(btrim(vehicle_label)) > 0", name="vehicle_label_not_blank"),
        CheckConstraint("length(btrim(vehicle_plate)) > 0", name="vehicle_plate_not_blank"),
        CheckConstraint("version >= 1", name="version_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    vehicle_label: Mapped[str] = mapped_column(String(120), nullable=False)
    vehicle_plate: Mapped[str] = mapped_column(String(16), nullable=False)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date] = mapped_column(Date, nullable=False)
    deposit_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(CHAR(3), nullable=False)
    status: Mapped[ContractStatus] = mapped_column(
        Enum(ContractStatus, name="contract_status"),
        nullable=False,
        server_default=text("'DRAFT'"),
    )
    owner_signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    client_signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_cancel_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    client_cancel_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default=text("1"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    owner: Mapped[User] = relationship(foreign_keys=[owner_id], lazy="joined")
    client: Mapped[User] = relationship(foreign_keys=[client_id], lazy="joined")
