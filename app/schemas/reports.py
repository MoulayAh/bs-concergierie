"""Schemas Pydantic (champs inconnus interdits) et representations JSON des cles et des rapports."""

import base64
from datetime import UTC, datetime
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator

from app.models import InspectionReport, ReportFile, ReportSignature, UserKey
from app.schemas.parsing import has_forbidden_chars

MAX_ODOMETER_KM: Final = 2_000_000
MAX_DAMAGES: Final = 30
MAX_FILES: Final = 20

Zone = Literal[
    "front_bumper",
    "rear_bumper",
    "hood",
    "roof",
    "left_side",
    "right_side",
    "windshield",
    "wheels",
    "interior",
    "other",
]
Severity = Literal["minor", "moderate", "major"]
Kind = Literal["checkout", "return"]

_STRICT: Final = ConfigDict(extra="forbid", frozen=True)


class KeyIn(BaseModel):
    model_config = _STRICT

    public_key: StrictStr = Field(max_length=128)


class SignatureIn(BaseModel):
    model_config = _STRICT

    signature: StrictStr = Field(max_length=512)


class DamageIn(BaseModel):
    model_config = _STRICT

    zone: Zone
    severity: Severity
    description: StrictStr = Field(max_length=500)
    file_ids: list[StrictStr] = Field(max_length=MAX_FILES)

    @field_validator("description")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if has_forbidden_chars(value, allow_newlines=True):
            raise ValueError("caracteres de controle interdits")
        return value

    @field_validator("file_ids")
    @classmethod
    def _bounded_ids(cls, value: list[str]) -> list[str]:
        if any(len(item) > 64 for item in value):
            raise ValueError("identifiant de fichier invalide")
        return value


class ReportFieldsIn(BaseModel):
    model_config = _STRICT

    odometer_km: Annotated[StrictInt, Field(ge=0, le=MAX_ODOMETER_KM)]
    fuel_eighths: Annotated[StrictInt, Field(ge=0, le=8)]
    damages: list[DamageIn] = Field(default_factory=list, max_length=MAX_DAMAGES)
    claimed_retention_cents: StrictInt = 0
    notes: StrictStr = Field(default="", max_length=2000)

    @field_validator("notes")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if has_forbidden_chars(value, allow_newlines=True):
            raise ValueError("caracteres de controle interdits")
        return value


class CreateReportIn(ReportFieldsIn):
    kind: Kind


def iso_z(moment: datetime | None) -> str | None:
    """Horodatage ISO 8601 UTC a la seconde (forme reprise telle quelle dans le JSON canonique)."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if moment is not None else None


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def _decode(raw: bytes | None) -> str | None:
    return raw.decode("utf-8") if raw is not None else None


def key_to_dict(key: UserKey) -> dict[str, Any]:
    return {
        "id": str(key.id),
        "public_key": base64.b64encode(key.public_key).decode("ascii"),
        "fingerprint": key.fingerprint.strip(),
        "created_at": _iso(key.created_at),
        "revoked_at": _iso(key.revoked_at),
    }


def file_to_dict(item: ReportFile) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "sha256": item.sha256.strip(),
        "mime": item.mime,
        "size_bytes": item.size_bytes,
        "original_name": item.original_name,
        "uploaded_by": str(item.uploaded_by),
        "width": item.width,
        "height": item.height,
    }


def report_to_dict(
    report: InspectionReport, files: list[ReportFile], signatures: list[ReportSignature]
) -> dict[str, Any]:
    return {
        "id": str(report.id),
        "contract_id": str(report.contract_id),
        "kind": report.kind.value,
        "revision": report.revision,
        "status": report.status.value,
        "supersedes_id": str(report.supersedes_id) if report.supersedes_id is not None else None,
        "odometer_km": report.odometer_km,
        "fuel_eighths": report.fuel_eighths,
        "damages": report.damages,
        "claimed_retention_cents": report.claimed_retention_cents,
        "notes": report.notes,
        "files": [file_to_dict(item) for item in files],
        "report_hash": report.report_hash.strip() if report.report_hash is not None else None,
        "canonical_json": _decode(report.canonical_json),
        "frozen_at": iso_z(report.frozen_at),
        "signatures": [
            {"party": sig.party.value, "user_id": str(sig.user_id), "signed_at": _iso(sig.signed_at)}
            for sig in signatures
        ],
        "version": report.version,
    }
