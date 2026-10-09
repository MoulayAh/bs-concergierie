"""Modeles d'etat des lieux : InspectionReport, ReportFile, ReportSignature."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import BYTEA, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import ReportKind, ReportParty, ReportStatus


class InspectionReport(Base):
    __tablename__ = "inspection_reports"
    __table_args__ = (
        UniqueConstraint(
            "contract_id", "kind", "revision", name="uq_inspection_reports_contract_id_kind_revision"
        ),
        CheckConstraint("revision >= 1", name="revision_positive"),
        CheckConstraint("(revision = 1) = (supersedes_id IS NULL)", name="supersedes_iff_revised"),
        CheckConstraint("odometer_km BETWEEN 0 AND 2000000", name="odometer_bounds"),
        CheckConstraint("fuel_eighths BETWEEN 0 AND 8", name="fuel_bounds"),
        CheckConstraint("claimed_retention_cents >= 0", name="retention_non_negative"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint("(status = 'DRAFT') = (report_hash IS NULL)", name="hash_iff_not_draft"),
        CheckConstraint(
            "status = 'DRAFT' OR (canonical_json IS NOT NULL AND frozen_at IS NOT NULL"
            " AND odometer_km IS NOT NULL AND fuel_eighths IS NOT NULL)",
            name="frozen_content_complete",
        ),
        Index(
            "uq_inspection_reports_active_contract_id_kind",
            "contract_id",
            "kind",
            unique=True,
            postgresql_where=text("status <> 'SUPERSEDED'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    contract_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("contracts.id"), nullable=False
    )
    kind: Mapped[ReportKind] = mapped_column(
        Enum(ReportKind, name="report_kind", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default=text("1"))
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"),
        nullable=False,
        default=ReportStatus.DRAFT,
        server_default=text("'DRAFT'"),
    )
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("inspection_reports.id"), nullable=True
    )
    odometer_km: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fuel_eighths: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    damages: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    claimed_retention_cents: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    notes: Mapped[str] = mapped_column(String(2000), nullable=False, default="", server_default=text("''"))
    canonical_json: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)
    report_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    frozen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default=text("1"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class ReportFile(Base):
    __tablename__ = "report_files"
    __table_args__ = (
        UniqueConstraint("report_id", "sha256", name="uq_report_files_report_id_sha256"),
        CheckConstraint("mime IN ('image/jpeg','image/png','application/pdf')", name="mime_whitelist"),
        CheckConstraint("size_bytes BETWEEN 1 AND 10485760", name="size_bounds"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("inspection_reports.id"), nullable=False
    )
    uploaded_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    mime: Mapped[str] = mapped_column(String(32), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_name: Mapped[str] = mapped_column(String(64), nullable=False)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ReportSignature(Base):
    __tablename__ = "report_signatures"
    __table_args__ = (
        UniqueConstraint("report_id", "party", name="uq_report_signatures_report_id_party"),
        CheckConstraint("length(signature) = 64", name="signature_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("inspection_reports.id"), nullable=False
    )
    party: Mapped[ReportParty] = mapped_column(
        Enum(ReportParty, name="report_party", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    key_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("user_keys.id"), nullable=False)
    report_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    signature: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
