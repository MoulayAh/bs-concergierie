"""Enums du domaine, miroir des ENUM PostgreSQL."""

from __future__ import annotations

import enum


class ContractStatus(enum.StrEnum):
    """Tous les etats de la machine d'etats (skill escrow-domain)."""

    DRAFT = "DRAFT"
    AWAITING_DEPOSIT = "AWAITING_DEPOSIT"
    FUNDED = "FUNDED"
    ACTIVE = "ACTIVE"
    INSPECTION_PENDING = "INSPECTION_PENDING"
    DISPUTED = "DISPUTED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"
    RELEASED = "RELEASED"
    SETTLED = "SETTLED"


class DepositStatus(enum.StrEnum):
    """Etat des fonds d'une caution (ENUM PostgreSQL `deposit_status`)."""

    HELD = "HELD"
    REFUNDED = "REFUNDED"
    RELEASED = "RELEASED"
    SETTLED = "SETTLED"


class ReportKind(enum.StrEnum):
    """Type d'etat des lieux (ENUM PostgreSQL `report_kind`)."""

    CHECKOUT = "checkout"
    RETURN = "return"


class ReportStatus(enum.StrEnum):
    """Cycle de vie d'un rapport (ENUM PostgreSQL `report_status`)."""

    DRAFT = "DRAFT"
    FROZEN = "FROZEN"
    SIGNED = "SIGNED"
    SUPERSEDED = "SUPERSEDED"


class ReportParty(enum.StrEnum):
    """Partie signataire (ENUM PostgreSQL `report_party`)."""

    OWNER = "owner"
    CLIENT = "client"


class UserRole(enum.StrEnum):
    CLIENT = "client"
    OWNER = "owner"
    ADMIN = "admin"
