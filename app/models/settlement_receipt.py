"""Modele SettlementReceipt : quittance de liberation signee par le serveur (ajout seul, trigger)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CHAR, CheckConstraint, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import BYTEA, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SettlementReceipt(Base):
    __tablename__ = "settlement_receipts"
    __table_args__ = (CheckConstraint("length(server_signature) = 64", name="signature_length"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    contract_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("contracts.id"), nullable=False, unique=True
    )
    deposit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("deposits.id"), nullable=False, unique=True
    )
    return_report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("inspection_reports.id"), nullable=False
    )
    canonical_json: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    receipt_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False, unique=True)
    server_signature: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    server_key_fingerprint: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
