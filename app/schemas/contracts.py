"""Schemas Pydantic (mode strict, champs inconnus interdits) des entrees et sorties /api/contracts."""

import re
from datetime import UTC, date, datetime
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from app.domain.money import ALLOWED_CURRENCIES, MAX_DEPOSIT_CENTS
from app.models import Contract
from app.schemas.parsing import has_forbidden_chars, has_visible_char

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

Label = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Plate = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=16)]
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, min_length=3, max_length=254)]
Reason = Annotated[str, StringConstraints(max_length=500)]
DepositCents = Annotated[int, Field(gt=0, le=MAX_DEPOSIT_CENTS)]


class CreateContractIn(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    client_email: Email
    vehicle_label: Label
    vehicle_plate: Plate
    start_date: date
    end_date: date
    deposit_cents: DepositCents
    currency: str

    @field_validator("start_date", "end_date", mode="before")
    @classmethod
    def _parse_iso_date(cls, value: object) -> date:
        if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
            raise ValueError("date attendue au format AAAA-MM-JJ")
        return date.fromisoformat(value)

    @field_validator("vehicle_label", "vehicle_plate", "client_email")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if has_forbidden_chars(value):
            raise ValueError("caracteres de controle ou invisibles interdits")
        return value

    @field_validator("vehicle_label", "vehicle_plate")
    @classmethod
    def _visible_text(cls, value: str) -> str:
        if not has_visible_char(value):
            raise ValueError("le texte doit contenir au moins un caractere visible")
        return value

    @field_validator("client_email")
    @classmethod
    def _email_shape(cls, value: str) -> str:
        if not _EMAIL_RE.fullmatch(value):
            raise ValueError("adresse e-mail invalide")
        return value

    @field_validator("currency")
    @classmethod
    def _currency_whitelist(cls, value: str) -> str:
        if value not in ALLOWED_CURRENCIES:
            raise ValueError("devise non supportee")
        return value

    @model_validator(mode="after")
    def _period_is_ordered(self) -> Self:
        if self.end_date <= self.start_date:
            raise ValueError("end_date doit etre posterieure a start_date")
        return self


class CancelIn(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    reason: Reason = ""

    @field_validator("reason")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if has_forbidden_chars(value, allow_newlines=True):
            raise ValueError("caracteres de controle interdits")
        return value


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def contract_to_dict(contract: Contract) -> dict[str, Any]:
    """Representation publique d'un contrat (montants en centimes entiers)."""
    return {
        "id": str(contract.id),
        "status": contract.status.value,
        "owner": {"id": str(contract.owner.id), "display_name": contract.owner.display_name},
        "client": {"id": str(contract.client.id), "display_name": contract.client.display_name},
        "vehicle": {"label": contract.vehicle_label, "plate": contract.vehicle_plate},
        "period": {"start": contract.start_date.isoformat(), "end": contract.end_date.isoformat()},
        "deposit": {"amount_cents": contract.deposit_cents, "currency": contract.currency},
        "signatures": {"owner": _iso(contract.owner_signed_at), "client": _iso(contract.client_signed_at)},
        "version": contract.version,
    }
