"""Modele EscrowEvent : journal en ajout seul (trigger PostgreSQL anti UPDATE/DELETE)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import ContractStatus


class EscrowEvent(Base):
    __tablename__ = "escrow_events"
    __table_args__ = (
        Index("ix_escrow_events_contract_id_created_at", "contract_id", "created_at"),
        CheckConstraint("seq >= 1", name="seq_positive"),
        UniqueConstraint("contract_id", "seq", name="uq_escrow_events_contract_id_seq"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    contract_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("contracts.id"), nullable=False
    )
    event: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    # NULL uniquement pour l'evenement `create` (pas d'etat source).
    from_status: Mapped[ContractStatus | None] = mapped_column(
        Enum(ContractStatus, name="contract_status", create_type=False), nullable=True
    )
    to_status: Mapped[ContractStatus] = mapped_column(
        Enum(ContractStatus, name="contract_status", create_type=False), nullable=False
    )
    payload_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Donnees de l'evenement en clair (ex. {"reason": "..."}) ; NULL si aucune. Remplie a l'INSERT.
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Chaine de hachage par contrat (voir app/domain/event_chain.py) ; verifiee par trigger PostgreSQL.
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    prev_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
