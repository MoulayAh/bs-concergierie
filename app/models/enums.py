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


class UserRole(enum.StrEnum):
    CLIENT = "client"
    OWNER = "owner"
    ADMIN = "admin"
