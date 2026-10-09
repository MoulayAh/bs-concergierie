"""Modeles SQLAlchemy. `db` = Flask-SQLAlchemy ; l'importer d'ici dans create_app."""

from app.models.base import Base, db
from app.models.contract import Contract
from app.models.deposit import Deposit
from app.models.enums import (
    ContractStatus,
    DepositStatus,
    ReportKind,
    ReportParty,
    ReportStatus,
    UserRole,
)
from app.models.escrow_event import EscrowEvent
from app.models.idempotency_key import IdempotencyKey
from app.models.report import InspectionReport, ReportFile, ReportSignature
from app.models.settlement_receipt import SettlementReceipt
from app.models.user import User
from app.models.user_key import UserKey

__all__ = [
    "Base",
    "Contract",
    "ContractStatus",
    "Deposit",
    "DepositStatus",
    "EscrowEvent",
    "IdempotencyKey",
    "InspectionReport",
    "ReportFile",
    "ReportKind",
    "ReportParty",
    "ReportSignature",
    "ReportStatus",
    "SettlementReceipt",
    "User",
    "UserKey",
    "UserRole",
    "db",
]
