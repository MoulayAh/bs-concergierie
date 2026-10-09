"""Orchestration des etats des lieux : transaction, verrous, domaine, fichiers, signatures, idempotence.

Ordre de verrouillage constant : contrat puis rapport (l'upload et la suppression de fichier ne verrouillent
que le rapport). Aucune route ne modifie ``status`` : le rapport passe par ``app.domain.report`` et le
contrat par ``state_machine.transition``.
"""

import base64
import hashlib
import hmac
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import current_app
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.domain import report as rules
from app.domain.errors import (
    ForbiddenActor,
    InvalidAmount,
    InvalidTransition,
    KeyNotRegistered,
    ResourceNotFound,
    ValidationFailed,
)
from app.domain.money import validate_retained_cents
from app.domain.state_machine import ContractStatus, Event, Party, transition
from app.extensions import db
from app.models import (
    Contract,
    InspectionReport,
    ReportFile,
    ReportKind,
    ReportParty,
    ReportSignature,
    User,
    UserKey,
)
from app.models import ContractStatus as StoredStatus
from app.models import ReportStatus as StoredReportStatus
from app.schemas.reports import (
    MAX_FILES,
    CreateReportIn,
    ReportFieldsIn,
    SignatureIn,
    file_to_dict,
    iso_z,
    report_to_dict,
)
from app.security import uploads
from app.security.signatures import verify_signature
from app.services import idempotency, settlement_journal
from app.services.contracts import load_for_party, parse_id, write_event
from app.services.idempotency import Outcome, fingerprint

_log = logging.getLogger(__name__)
_NOT_FOUND = "Etat des lieux introuvable"


# ------------------------------------------------------------------ utilitaires


def parse_kind(raw: str) -> ReportKind:
    try:
        return ReportKind(raw)
    except ValueError as exc:
        raise ResourceNotFound("Type d'etat des lieux inconnu") from exc


def _domain_status(report: InspectionReport) -> rules.ReportStatus:
    return rules.ReportStatus(report.status.value)


def _upload_dir() -> Path:
    return Path(str(current_app.config["UPLOAD_DIR"]))


def _active_report(contract_id: uuid.UUID, kind: ReportKind, *, lock: bool) -> InspectionReport | None:
    stmt = (
        select(InspectionReport)
        .where(
            InspectionReport.contract_id == contract_id,
            InspectionReport.kind == kind,
            InspectionReport.status != StoredReportStatus.SUPERSEDED,
        )
        .execution_options(populate_existing=True)
    )
    if lock:
        stmt = stmt.with_for_update()
    return db.session.scalar(stmt)


def _guard_settlement(contract_id: uuid.UUID, kind: ReportKind) -> None:
    if kind is ReportKind.RETURN:
        settlement_journal.forbid_if_in_progress(contract_id)


def _require_report(contract_id: uuid.UUID, kind: ReportKind, *, lock: bool) -> InspectionReport:
    report = _active_report(contract_id, kind, lock=lock)
    if report is None:
        raise ResourceNotFound(_NOT_FOUND)
    return report


def _files(report_id: uuid.UUID) -> list[ReportFile]:
    return list(
        db.session.scalars(
            select(ReportFile)
            .where(ReportFile.report_id == report_id)
            .order_by(ReportFile.created_at, ReportFile.id)
            .execution_options(populate_existing=True)
        )
    )


def _signatures(report_id: uuid.UUID) -> list[ReportSignature]:
    return list(
        db.session.scalars(
            select(ReportSignature)
            .where(ReportSignature.report_id == report_id)
            .order_by(ReportSignature.signed_at, ReportSignature.id)
            .execution_options(populate_existing=True)
        )
    )


def _view(report: InspectionReport) -> dict[str, Any]:
    return report_to_dict(report, _files(report.id), _signatures(report.id))


def _require_contract_state(contract: Contract, kind: ReportKind, *, revision: bool = False) -> None:
    """Etat attendu du contrat ; une revision du retour vit en INSPECTION_PENDING (avant la 2e signature)."""
    if kind is ReportKind.CHECKOUT:
        allowed = {StoredStatus.FUNDED}
    elif revision:
        allowed = {StoredStatus.INSPECTION_PENDING}
    else:
        allowed = {StoredStatus.ACTIVE}
    if contract.status not in allowed:
        raise InvalidTransition(
            f"L'etat des lieux de {'depart' if kind is ReportKind.CHECKOUT else 'retour'} "
            f"est impossible dans l'etat {contract.status.value} du contrat",
            details={"reason": "CONTRACT_STATE", "contract_status": contract.status.value},
        )


@dataclass
class _Ctx:
    contract: Contract
    party: Party
    kind: ReportKind
    user_id: uuid.UUID
    key: str | None
    request_hash: str
    replay: Outcome | None


def _enter(user: User, raw_id: str, kind: ReportKind, op: str, body: object, key: str | None) -> _Ctx:
    """Contrat verrouille, appelant identifie (404 si tiers) et rejeu d'idempotence eventuel."""
    contract_id = parse_id(raw_id)
    user_id = user.id
    request_hash = fingerprint({"op": op, "contract": str(contract_id), "kind": kind.value, "body": body})
    if key is not None:
        idempotency.lock_key(key, user_id)
    contract, party = load_for_party(user_id, contract_id, lock=True)
    replay = idempotency.find_replay(key, user_id, request_hash) if key is not None else None
    return _Ctx(contract, party, kind, user_id, key, request_hash, replay)


def _require_owner(ctx: _Ctx) -> None:
    if ctx.party is not Party.OWNER:
        raise ForbiddenActor("Seul le loueur peut effectuer cette action sur l'etat des lieux")


def _finish(ctx: _Ctx, status: int, body: dict[str, Any]) -> Outcome:
    outcome = Outcome(status, body)
    if ctx.key is not None:
        idempotency.record(ctx.key, ctx.user_id, ctx.request_hash, outcome)
    db.session.commit()
    return outcome


def _signed_checkout_odometer(contract_id: uuid.UUID) -> int | None:
    return db.session.scalar(
        select(InspectionReport.odometer_km).where(
            InspectionReport.contract_id == contract_id,
            InspectionReport.kind == ReportKind.CHECKOUT,
            InspectionReport.status != StoredReportStatus.SUPERSEDED,
        )
    )


def _validate_values(
    contract: Contract,
    kind: ReportKind,
    *,
    odometer_km: int,
    retention_cents: int,
    damages: list[dict[str, Any]],
    file_ids: set[str],
) -> None:
    if kind is ReportKind.CHECKOUT:
        if retention_cents != 0:
            raise InvalidAmount("La retenue demandee doit valoir 0 sur l'etat des lieux de depart")
    else:
        validate_retained_cents(retention_cents, contract.deposit_cents)
        start = _signed_checkout_odometer(contract.id)
        if start is not None and odometer_km < start:
            raise ValidationFailed(
                "Le kilometrage de retour ne peut pas etre inferieur a celui du depart",
                details={"errors": [{"field": "odometer_km"}]},
            )
    for index, damage in enumerate(damages):
        if not set(damage["file_ids"]) <= file_ids:
            raise ValidationFailed(
                "Un dommage reference un fichier qui n'appartient pas a ce rapport",
                details={"errors": [{"field": f"damages.{index}.file_ids"}]},
            )


def _damages_payload(data: ReportFieldsIn) -> list[dict[str, Any]]:
    return [damage.model_dump() for damage in data.damages]


# ------------------------------------------------------------------ creation, edition, lecture


def create_report(user: User, raw_id: str, data: CreateReportIn, *, body: object) -> Outcome:
    kind = ReportKind(data.kind)
    ctx = _enter(user, raw_id, kind, "create_report", body, None)
    _require_owner(ctx)
    _require_contract_state(ctx.contract, kind)
    if _active_report(ctx.contract.id, kind, lock=True) is not None:
        raise InvalidTransition(
            "Un etat des lieux de ce type existe deja pour ce contrat", details={"reason": "REPORT_EXISTS"}
        )
    damages = _damages_payload(data)
    _validate_values(
        ctx.contract,
        kind,
        odometer_km=data.odometer_km,
        retention_cents=data.claimed_retention_cents,
        damages=damages,
        file_ids=set(),
    )
    report = InspectionReport(
        contract_id=ctx.contract.id,
        kind=kind,
        revision=1,
        status=StoredReportStatus.DRAFT,
        odometer_km=data.odometer_km,
        fuel_eighths=data.fuel_eighths,
        damages=damages,
        claimed_retention_cents=data.claimed_retention_cents,
        notes=data.notes,
        version=1,
    )
    db.session.add(report)
    try:
        db.session.flush()
    except IntegrityError as exc:
        raise InvalidTransition("Un etat des lieux de ce type existe deja pour ce contrat") from exc
    return _finish(ctx, 201, _view(report))


def update_report(user: User, raw_id: str, raw_kind: str, data: ReportFieldsIn, *, body: object) -> Outcome:
    kind = parse_kind(raw_kind)
    ctx = _enter(user, raw_id, kind, "update_report", body, None)
    _require_owner(ctx)
    report = _require_report(ctx.contract.id, kind, lock=True)
    _guard_settlement(ctx.contract.id, kind)
    rules.next_status(_domain_status(report), rules.ReportAction.EDIT)
    _require_contract_state(ctx.contract, kind, revision=report.supersedes_id is not None)
    damages = _damages_payload(data)
    _validate_values(
        ctx.contract,
        kind,
        odometer_km=data.odometer_km,
        retention_cents=data.claimed_retention_cents,
        damages=damages,
        file_ids={str(item.id) for item in _files(report.id)},
    )
    report.odometer_km = data.odometer_km
    report.fuel_eighths = data.fuel_eighths
    report.damages = damages
    report.claimed_retention_cents = data.claimed_retention_cents
    report.notes = data.notes
    report.version += 1
    db.session.flush()
    return _finish(ctx, 200, _view(report))


def get_report(user: User, raw_id: str, raw_kind: str) -> dict[str, Any]:
    kind = parse_kind(raw_kind)
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    return _view(_require_report(contract.id, kind, lock=False))


def get_history(user: User, raw_id: str, raw_kind: str) -> list[dict[str, Any]]:
    kind = parse_kind(raw_kind)
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    rows = db.session.scalars(
        select(InspectionReport)
        .where(InspectionReport.contract_id == contract.id, InspectionReport.kind == kind)
        .order_by(InspectionReport.revision)
        .execution_options(populate_existing=True)
    ).all()
    return [_view(row) for row in rows]


# ------------------------------------------------------------------ fichiers


def add_file(user: User, raw_id: str, raw_kind: str, data: bytes, filename: str) -> Outcome:
    kind = parse_kind(raw_kind)
    contract_id = parse_id(raw_id)
    user_id = user.id
    contract, _ = load_for_party(user_id, contract_id, lock=False)
    _require_report(contract_id, kind, lock=False)
    inspected = uploads.inspect_upload(data, filename)  # 413 / 415 avant toute ecriture
    report = _require_report(contract_id, kind, lock=True)  # le gel attend la fin de cet upload
    _guard_settlement(contract_id, kind)
    rules.next_status(_domain_status(report), rules.ReportAction.ADD_FILE)
    _require_contract_state(contract, kind, revision=report.supersedes_id is not None)
    existing = _files(report.id)
    if len(existing) >= MAX_FILES:
        raise ValidationFailed(f"Un etat des lieux contient {MAX_FILES} fichiers au plus")
    if any(item.sha256.strip() == inspected.sha256 for item in existing):
        raise ValidationFailed("Ce fichier a deja ete ajoute a l'etat des lieux")
    stored_name = uploads.store_file(inspected, _upload_dir())
    try:
        item = ReportFile(
            report_id=report.id,
            uploaded_by=user_id,
            sha256=inspected.sha256,
            mime=inspected.mime,
            size_bytes=inspected.size_bytes,
            storage_name=stored_name,
            original_name=inspected.original_name,
            width=inspected.width,
            height=inspected.height,
        )
        db.session.add(item)
        report.version += 1
        db.session.flush()
        body = file_to_dict(item)
        db.session.commit()
    except Exception:
        db.session.rollback()
        uploads.delete_stored(_upload_dir(), stored_name)
        raise
    return Outcome(201, body)


def delete_file(user: User, raw_id: str, raw_kind: str, raw_file_id: str) -> None:
    kind = parse_kind(raw_kind)
    contract_id = parse_id(raw_id)
    user_id = user.id
    contract, _ = load_for_party(user_id, contract_id, lock=False)
    report = _require_report(contract_id, kind, lock=True)
    _guard_settlement(contract_id, kind)
    rules.next_status(_domain_status(report), rules.ReportAction.REMOVE_FILE)
    _require_contract_state(contract, kind, revision=report.supersedes_id is not None)
    item = _find_file(report.id, raw_file_id)
    if item.uploaded_by != user_id:
        raise ForbiddenActor("Vous ne pouvez supprimer que vos propres fichiers")
    stored_name = item.storage_name
    db.session.delete(item)
    report.version += 1
    db.session.flush()
    others = db.session.scalar(
        select(func.count()).select_from(ReportFile).where(ReportFile.storage_name == stored_name)
    )
    db.session.commit()
    if not others:  # une revision conservee dans l'historique continue de referencer le fichier
        uploads.delete_stored(_upload_dir(), stored_name)


def _find_file(report_id: uuid.UUID, raw_file_id: str) -> ReportFile:
    try:
        file_id = uuid.UUID(raw_file_id)
    except ValueError as exc:
        raise ResourceNotFound("Fichier introuvable") from exc
    item = db.session.scalar(
        select(ReportFile).where(ReportFile.id == file_id, ReportFile.report_id == report_id)
    )
    if item is None:
        raise ResourceNotFound("Fichier introuvable")
    return item


def get_file(user: User, raw_id: str, raw_kind: str, raw_file_id: str) -> tuple[ReportFile, Path]:
    """Fichier d'un rapport (toute revision) de CE contrat, sinon 404 (pas d'IDOR)."""
    kind = parse_kind(raw_kind)
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    try:
        file_id = uuid.UUID(raw_file_id)
    except ValueError as exc:
        raise ResourceNotFound("Fichier introuvable") from exc
    item = db.session.scalar(
        select(ReportFile)
        .join(InspectionReport, InspectionReport.id == ReportFile.report_id)
        .where(
            ReportFile.id == file_id,
            InspectionReport.contract_id == contract.id,
            InspectionReport.kind == kind,
        )
    )
    if item is None:
        raise ResourceNotFound("Fichier introuvable")
    try:
        path = uploads.stored_path(_upload_dir(), item.storage_name)
    except ValueError as exc:
        _log.error("Nom de fichier stocke invalide pour %s", item.id)
        raise ResourceNotFound("Fichier introuvable") from exc
    if not path.is_file():
        _log.error("Fichier %s absent du disque", item.storage_name)
        raise ResourceNotFound("Fichier indisponible")
    return item, path


# ------------------------------------------------------------------ gel, signature, remplacement


def finalize_report(user: User, raw_id: str, raw_kind: str, *, key: str) -> Outcome:
    kind = parse_kind(raw_kind)
    ctx = _enter(user, raw_id, kind, "finalize_report", None, key)
    if ctx.replay is not None:
        return ctx.replay
    _require_owner(ctx)
    contract = ctx.contract
    report = _require_report(contract.id, kind, lock=True)
    _guard_settlement(contract.id, kind)
    new_status = rules.next_status(_domain_status(report), rules.ReportAction.FINALIZE)
    is_revision = report.supersedes_id is not None
    _require_contract_state(contract, kind, revision=is_revision)
    files = _files(report.id)
    if not files:
        raise ValidationFailed("Au moins une photo est requise pour figer l'etat des lieux")
    if report.odometer_km is None or report.fuel_eighths is None:
        raise ValidationFailed("Kilometrage et carburant sont requis pour figer l'etat des lieux")
    _validate_values(
        contract,
        kind,
        odometer_km=report.odometer_km,
        retention_cents=report.claimed_retention_cents,
        damages=report.damages,
        file_ids={str(item.id) for item in files},
    )
    if kind is ReportKind.RETURN:
        rules.require_retention_justified(report.claimed_retention_cents, report.damages)

    frozen_at = datetime.now(UTC).replace(microsecond=0)
    content: dict[str, Any] = {
        "schema": rules.SCHEMA,
        "contract_id": str(contract.id),
        "kind": kind.value,
        "revision": report.revision,
        "supersedes_id": str(report.supersedes_id) if report.supersedes_id is not None else None,
        "vehicle_plate": contract.vehicle_plate,
        "deposit": {"amount_cents": contract.deposit_cents, "currency": contract.currency.strip()},
        "odometer_km": report.odometer_km,
        "fuel_eighths": report.fuel_eighths,
        "damages": report.damages,
        "claimed_retention_cents": report.claimed_retention_cents,
        "files": [
            {
                "id": str(item.id),
                "sha256": item.sha256.strip(),
                "mime": item.mime,
                "size_bytes": item.size_bytes,
            }
            for item in files
        ],
        "notes": report.notes,
        "frozen_at": iso_z(frozen_at),
    }
    canonical = rules.canonical_bytes(content)

    if kind is ReportKind.RETURN:
        previous = contract.status
        return_event = Event.REVISE_RETURN_REPORT if is_revision else Event.SUBMIT_RETURN_REPORT
        result = transition(ContractStatus(contract.status.value), return_event, actor=ctx.party)
        contract.status = StoredStatus(result.status.value)
        contract.version += 1

    # Un seul UPDATE : statut, empreinte, forme canonique et date de gel (contraintes + trigger).
    report.status = StoredReportStatus(new_status.value)
    report.canonical_json = canonical
    report.report_hash = hashlib.sha256(canonical).hexdigest()
    report.frozen_at = frozen_at
    report.version += 1
    db.session.flush()

    if kind is ReportKind.RETURN:
        write_event(
            contract.id,
            return_event.value,
            ctx.user_id,
            previous,
            contract.status,
            {"report_id": str(report.id), "report_hash": report.report_hash},
        )
    return _finish(ctx, 200, _view(report))


def sign_checkout(user: User, raw_id: str, data: SignatureIn, *, key: str, body: object) -> Outcome:
    kind = ReportKind.CHECKOUT
    ctx = _enter(user, raw_id, kind, "sign_report", body, key)
    if ctx.replay is not None:
        return ctx.replay
    contract = ctx.contract
    report = _require_report(contract.id, kind, lock=True)
    party = ReportParty(ctx.party.value)
    existing = _signatures(report.id)
    if any(sig.party is party for sig in existing):
        raise InvalidTransition("Cette partie a deja signe l'etat des lieux")
    new_status = rules.next_status(
        _domain_status(report), rules.ReportAction.SIGN, signatures=len(existing) + 1
    )
    _require_contract_state(contract, kind)

    user_key = db.session.scalar(
        select(UserKey).where(UserKey.user_id == ctx.user_id, UserKey.revoked_at.is_(None))
    )
    if user_key is None:
        raise KeyNotRegistered("Aucune cle publique active : enregistrez-en une avant de signer")

    # L'empreinte signee est RECALCULEE par le serveur depuis le contenu fige, jamais lue chez le client.
    canonical = report.canonical_json
    stored_hash = report.report_hash
    if canonical is None or stored_hash is None:
        raise InvalidTransition("Etat des lieux non fige")
    report_hash = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(report_hash, stored_hash.strip()):
        _log.error("Empreinte incoherente pour le rapport %s", report.id)
        raise InvalidTransition(
            "Integrite de l'etat des lieux compromise", details={"reason": "HASH_MISMATCH"}
        )
    verify_signature(
        user_key.public_key,
        rules.signing_message(str(contract.id), rules.ReportKind(kind.value), report_hash),
        data.signature,
    )

    db.session.add(
        ReportSignature(
            report_id=report.id,
            party=party,
            user_id=ctx.user_id,
            key_id=user_key.id,
            report_hash=report_hash,
            signature=base64.b64decode(data.signature, validate=True),
        )
    )
    report.status = StoredReportStatus(new_status.value)
    report.version += 1
    try:
        db.session.flush()
    except IntegrityError as exc:
        raise InvalidTransition("Cette partie a deja signe l'etat des lieux") from exc
    return _finish(ctx, 200, _view(report))


def supersede_report(user: User, raw_id: str, raw_kind: str, *, key: str | None) -> Outcome:
    kind = parse_kind(raw_kind)
    ctx = _enter(user, raw_id, kind, "supersede_report", None, key)
    if ctx.replay is not None:
        return ctx.replay
    _require_owner(ctx)
    contract = ctx.contract
    old = _require_report(contract.id, kind, lock=True)
    _guard_settlement(contract.id, kind)
    signed = len(_signatures(old.id))
    new_status = rules.next_status(_domain_status(old), rules.ReportAction.SUPERSEDE, signatures=signed)
    _require_contract_state(contract, kind, revision=True)
    old_files = _files(old.id)
    file_map = {str(item.id): uuid.uuid4() for item in old_files}

    # L'ancienne revision sort de l'index "un seul rapport actif" AVANT l'insertion de la nouvelle.
    old.status = StoredReportStatus(new_status.value)
    old.version += 1
    db.session.flush()

    new = InspectionReport(
        id=uuid.uuid4(),
        contract_id=contract.id,
        kind=kind,
        revision=old.revision + 1,
        status=StoredReportStatus.DRAFT,
        supersedes_id=old.id,
        odometer_km=old.odometer_km,
        fuel_eighths=old.fuel_eighths,
        damages=[
            {**damage, "file_ids": [str(file_map.get(fid, fid)) for fid in damage["file_ids"]]}
            for damage in old.damages
        ],
        claimed_retention_cents=old.claimed_retention_cents,
        notes=old.notes,
        version=1,
    )
    db.session.add(new)
    db.session.flush()
    for item in old_files:
        db.session.add(
            ReportFile(
                id=file_map[str(item.id)],
                report_id=new.id,
                uploaded_by=item.uploaded_by,
                sha256=item.sha256,
                mime=item.mime,
                size_bytes=item.size_bytes,
                storage_name=item.storage_name,
                original_name=item.original_name,
                width=item.width,
                height=item.height,
                created_at=item.created_at,
            )
        )
    db.session.flush()
    return _finish(ctx, 201, _view(new))
