"""Modele Deposit : caution bloquee pour un contrat (un seul depot par contrat)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CHAR,
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import DepositStatus


class Deposit(Base):
    __tablename__ = "deposits"
    __table_args__ = (
        CheckConstraint("amount_cents BETWEEN 1 AND 50000000", name="amount_bounds"),
        CheckConstraint("currency IN ('EUR','CHF','GBP','USD')", name="currency_whitelist"),
        CheckConstraint("held_cents >= 0", name="held_non_negative"),
        CheckConstraint("refunded_cents >= 0", name="refunded_non_negative"),
        CheckConstraint("released_cents >= 0", name="released_non_negative"),
        CheckConstraint("retained_cents >= 0", name="retained_non_negative"),
        CheckConstraint(
            "held_cents + refunded_cents + released_cents + retained_cents = amount_cents",
            name="ledger_balanced",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    contract_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("contracts.id"), nullable=False, unique=True
    )
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(CHAR(3), nullable=False)
    status: Mapped[DepositStatus] = mapped_column(
        Enum(DepositStatus, name="deposit_status"),
        nullable=False,
        server_default=text("'HELD'"),
    )
    held_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    refunded_cents: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    released_cents: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    retained_cents: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_ref: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
