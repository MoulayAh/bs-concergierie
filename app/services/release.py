"""Signature du rapport de retour et liberation de la caution (une seule transaction atomique).

Ordre de verrouillage constant : contrat, puis rapport, puis depot. Le prestataire est appele sous ces
verrous avec une cle ne dependant que du depot : un reessai ne paie jamais deux fois. Aucune route ne
modifie ``status`` : le contrat passe par ``state_machine.transition``, le rapport par ``app.domain.report``.

Avant tout appel au prestataire, la tentative (montants, rapport, signature en attente) est journalisee et
committee (``settlement_journal``). Si la reponse du prestataire est perdue, la ventilation est figee et la
liberation en attente est finalisee au prochain reessai ou a la prochaine tentative de modifier le retour.
"""

import base64
import hashlib
import hmac
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import current_app
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.domain import receipt as receipt_rules
from app.domain import report as rules
from app.domain.errors import (
    InvalidTransition,
    KeyNotRegistered,
    PaymentUnavailable,
    ResourceNotFound,
    SettlementConflict,
)
from app.domain.money import split_deposit
from app.domain.state_machine import ContractStatus, Event, Party, TransitionResult, transition
from app.extensions import db
from app.models import (
    Contract,
    Deposit,
    DepositStatus,
    InspectionReport,
    ReportKind,
    ReportParty,
    ReportSignature,
    SettlementReceipt,
    User,
    UserKey,
)
from app.models import ContractStatus as StoredStatus
from app.models import ReportStatus as StoredReportStatus
from app.schemas.contracts import contract_to_dict, funds_to_dict
from app.schemas.reports import SignatureIn, iso_z
from app.security import server_key
from app.security.signatures import verify_signature
from app.services import settlement_journal
from app.services.contracts import _locked_deposit, load_for_party, parse_id, write_event
from app.services.idempotency import Outcome
from app.services.payments import get_provider
from app.services.reports import (
    _active_report,
    _domain_status,
    _enter,
    _finish,
    _require_report,
    _signatures,
    _view,
)
from app.services.settlement_journal import Attempt

_log = logging.getLogger(__name__)
_PARTY_ORDER = {ReportParty.OWNER: 0, ReportParty.CLIENT: 1}


def _signing_key() -> Ed25519PrivateKey:
    return cast(Ed25519PrivateKey, current_app.extensions["server_signing_key"])


def _frozen_hash(report: InspectionReport) -> str:
    """Empreinte RECALCULEE depuis le contenu fige (jamais lue chez le client)."""
    canonical, stored_hash = report.canonical_json, report.report_hash
    if canonical is None or stored_hash is None:
        raise InvalidTransition("Etat des lieux non fige")
    report_hash = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(report_hash, stored_hash.strip()):
        _log.error("Empreinte incoherente pour le rapport %s", report.id)
        raise InvalidTransition(
            "Integrite de l'etat des lieux compromise", details={"reason": "HASH_MISMATCH"}
        )
    return report_hash


def _settle(deposit: Deposit, release_cents: int, capture_cents: int) -> str:
    try:
        return get_provider().settle(
            deposit.provider_ref,
            release_cents=release_cents,
            capture_cents=capture_cents,
            key=settlement_journal.journal_key(deposit.id),
        )
    except SettlementConflict:
        _log.critical(
            "INCIDENT : reglement du depot %s refuse par le prestataire (cle reutilisee, autres montants)",
            deposit.id,
        )
        raise
    except PaymentUnavailable:
        raise
    except Exception as exc:  # toute panne du prestataire = 503, rien n'est ecrit
        _log.exception("Echec du reglement pour le depot %s", deposit.id)
        raise PaymentUnavailable("Prestataire de paiement indisponible") from exc


def _receipt_content(
    contract: Contract,
    deposit: Deposit,
    outcome: ContractStatus,
    report: InspectionReport,
    signatures: list[ReportSignature],
    head: tuple[int, str],
) -> dict[str, Any]:
    checkout = _active_report(contract.id, ReportKind.CHECKOUT, lock=False)
    if checkout is None or checkout.report_hash is None:
        raise InvalidTransition("Etat des lieux de depart introuvable")
    keys = {
        key.id: key
        for key in db.session.scalars(select(UserKey).where(UserKey.id.in_([s.key_id for s in signatures])))
    }
    entries = [
        {
            "party": sig.party.value,
            "key_fingerprint": keys[sig.key_id].fingerprint.strip(),
            "public_key": base64.b64encode(keys[sig.key_id].public_key).decode("ascii"),
            "signature": base64.b64encode(sig.signature).decode("ascii"),
            "signed_at": iso_z(sig.signed_at),
        }
        for sig in sorted(signatures, key=lambda s: _PARTY_ORDER[s.party])
    ]
    return {
        "schema": receipt_rules.SCHEMA,
        "contract_id": str(contract.id),
        "outcome": outcome.value,
        "currency": deposit.currency.strip(),
        "deposit_cents": deposit.amount_cents,
        "released_to_client_cents": deposit.released_cents,
        "retained_by_owner_cents": deposit.retained_cents,
        "return_report": {
            "id": str(report.id),
            "revision": report.revision,
            "hash": cast(str, report.report_hash).strip(),
        },
        "checkout_report": {"id": str(checkout.id), "hash": checkout.report_hash.strip()},
        "signatures": entries,
        "settlement_ref": deposit.settlement_ref,
        "settled_at": iso_z(deposit.settled_at),
        "event_chain": {"length": head[0], "head": head[1]},
    }


def _receipt_view(row: SettlementReceipt) -> dict[str, Any]:
    return {
        "canonical_json": row.canonical_json.decode("utf-8"),
        "receipt_hash": row.receipt_hash.strip(),
        "server_signature": base64.b64encode(row.server_signature).decode("ascii"),
    }


def _add_signature(
    report: InspectionReport,
    user_id: uuid.UUID,
    party: ReportParty,
    key_id: uuid.UUID,
    report_hash: str,
    signature_b64: str,
    new_status: rules.ReportStatus,
) -> None:
    db.session.add(
        ReportSignature(
            report_id=report.id,
            party=party,
            user_id=user_id,
            key_id=key_id,
            report_hash=report_hash,
            signature=base64.b64decode(signature_b64, validate=True),
        )
    )
    report.status = StoredReportStatus(new_status.value)
    report.version += 1


def _flush_signature() -> None:
    try:
        db.session.flush()
    except IntegrityError as exc:
        raise InvalidTransition("Cette partie a deja signe l'etat des lieux") from exc


def _apply_release(
    contract: Contract,
    report: InspectionReport,
    deposit: Deposit,
    result: TransitionResult,
    *,
    user_id: uuid.UUID,
    party: ReportParty,
    key_id: uuid.UUID,
    signature_b64: str,
    report_hash: str,
    new_status: rules.ReportStatus,
    release_cents: int,
    capture_cents: int,
    settlement_ref: str,
) -> dict[str, Any]:
    """Ecritures de la liberation (apres un reglement reussi) ; renvoie l'objet ``receipt``."""
    previous = contract.status
    # Un seul UPDATE du depot : montants, statut, reference et date de reglement.
    deposit.held_cents = 0
    deposit.released_cents = release_cents
    deposit.retained_cents = capture_cents
    deposit.status = DepositStatus(result.status.value)
    deposit.settled_at = datetime.now(UTC)
    deposit.settlement_ref = settlement_ref
    _add_signature(report, user_id, party, key_id, report_hash, signature_b64, new_status)
    contract.status = StoredStatus(result.status.value)
    contract.version += 1
    _flush_signature()

    written = write_event(
        contract.id,
        Event.SIGN_REPORT.value,
        user_id,
        previous,
        contract.status,
        {"report_id": str(report.id), "report_hash": report_hash},
    )
    head = (written.seq, written.event_hash)
    content = _receipt_content(contract, deposit, result.status, report, _signatures(report.id), head)
    canonical = receipt_rules.canonical_receipt(content)
    digest = receipt_rules.receipt_hash(canonical)
    private = _signing_key()
    sealed = SettlementReceipt(
        contract_id=contract.id,
        deposit_id=deposit.id,
        return_report_id=report.id,
        canonical_json=canonical,
        receipt_hash=digest,
        server_signature=private.sign(receipt_rules.receipt_signing_message(digest)),
        server_key_fingerprint=server_key.key_fingerprint(server_key.public_key_bytes(private)),
    )
    db.session.add(sealed)
    try:
        db.session.flush()
    except IntegrityError as exc:
        raise InvalidTransition("Caution deja liberee") from exc
    return _receipt_view(sealed)


def sign_return(user: User, raw_id: str, data: SignatureIn, *, key: str, body: object) -> Outcome:
    kind = ReportKind.RETURN
    ctx = _enter(user, raw_id, kind, "sign_report", body, key)
    if ctx.replay is not None:
        return ctx.replay
    contract = ctx.contract
    current = ContractStatus(contract.status.value)
    # Etat du contrat d'abord : tout autre etat que INSPECTION_PENDING => INVALID_TRANSITION.
    transition(current, Event.SIGN_REPORT, actor=ctx.party, deposit_cents=contract.deposit_cents)

    report = _require_report(contract.id, kind, lock=True)
    party = ReportParty(ctx.party.value)
    existing = _signatures(report.id)
    if any(sig.party is party for sig in existing):
        raise InvalidTransition("Cette partie a deja signe l'etat des lieux")
    new_status = rules.next_status(
        _domain_status(report), rules.ReportAction.SIGN, signatures=len(existing) + 1
    )

    user_key = db.session.scalar(
        select(UserKey).where(UserKey.user_id == ctx.user_id, UserKey.revoked_at.is_(None))
    )
    if user_key is None:
        raise KeyNotRegistered("Aucune cle publique active : enregistrez-en une avant de signer")
    report_hash = _frozen_hash(report)
    verify_signature(
        user_key.public_key,
        rules.signing_message(str(contract.id), rules.ReportKind.RETURN, report_hash),
        data.signature,
    )

    # Les approbations viennent des signatures du rapport de retour ACTIF, jamais de celles du contrat.
    result = transition(
        current,
        Event.SIGN_REPORT,
        actor=ctx.party,
        signed_by=frozenset(Party(sig.party.value) for sig in existing),
        deposit_cents=contract.deposit_cents,
        retained_cents=report.claimed_retention_cents,
    )
    if result.status is current:  # premiere signature : les fonds restent bloques
        previous = contract.status
        _add_signature(report, ctx.user_id, party, user_key.id, report_hash, data.signature, new_status)
        contract.version += 1
        _flush_signature()
        write_event(
            contract.id,
            Event.SIGN_REPORT.value,
            ctx.user_id,
            previous,
            contract.status,
            {"report_id": str(report.id), "report_hash": report_hash},
        )
        return _finish(ctx, 200, _view(report))

    deposit = _locked_deposit(contract.id)
    if deposit is None or deposit.status is not DepositStatus.HELD:
        raise InvalidTransition("Aucune caution bloquee a liberer")
    released, retained = split_deposit(deposit.amount_cents, report.claimed_retention_cents)
    attempt = settlement_journal.find_attempt(deposit.id)
    if attempt is None:
        # Journal committe AVANT l'appel au prestataire, puis reprise de la requete avec de nouveaux verrous.
        settlement_journal.record_attempt(
            Attempt(
                deposit.id,
                ctx.user_id,
                released,
                retained,
                str(report.id),
                report_hash,
                party.value,
                str(user_key.id),
                data.signature,
            )
        )
        return sign_return(user, raw_id, data, key=key, body=body)
    if (attempt.report_id, attempt.report_hash) != (str(report.id), report_hash):
        raise InvalidTransition(
            "Un reglement est en cours sur un autre etat des lieux de retour",
            details={"reason": "SETTLEMENT_IN_PROGRESS"},
        )
    # Reessai : exactement les montants journalises.
    settlement_ref = _settle(deposit, attempt.release_cents, attempt.capture_cents)
    receipt = _apply_release(
        contract,
        report,
        deposit,
        result,
        user_id=ctx.user_id,
        party=party,
        key_id=user_key.id,
        signature_b64=data.signature,
        report_hash=report_hash,
        new_status=new_status,
        release_cents=attempt.release_cents,
        capture_cents=attempt.capture_cents,
        settlement_ref=settlement_ref,
    )
    response = {
        "contract": contract_to_dict(contract, deposit),
        "funds": funds_to_dict(deposit),
        "receipt": receipt,
    }
    return _finish(ctx, 200, response)


def reconcile_pending(user: User, raw_id: str, raw_kind: str) -> None:
    """Avant toute modification du retour : finalise un reglement dont la reponse a ete perdue.

    Sans effet s'il n'y a pas de tentative en attente. Si le reglement aboutit, la liberation est ecrite
    (avec la signature deja verifiee et journalisee) puis la modification demandee est refusee (409).
    """
    if raw_kind != ReportKind.RETURN.value:
        return
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    contract_id = contract.id
    deposit = _read_pending(contract_id)
    if deposit is None:
        return
    contract, _ = load_for_party(user.id, contract_id, lock=True)
    locked = _locked_deposit(contract_id)
    attempt = settlement_journal.find_attempt(locked.id) if locked is not None else None
    in_progress = InvalidTransition(
        "Un reglement est en cours : l'etat des lieux de retour ne peut plus etre modifie",
        details={"reason": "SETTLEMENT_IN_PROGRESS"},
    )
    if (
        locked is None
        or attempt is None
        or locked.status is not DepositStatus.HELD
        or contract.status is not StoredStatus.INSPECTION_PENDING
    ):
        db.session.rollback()
        return
    report = _active_report(contract_id, ReportKind.RETURN, lock=True)
    if (
        report is None
        or str(report.id) != attempt.report_id
        or (report.report_hash or "").strip() != attempt.report_hash
    ):
        raise in_progress
    party = ReportParty(attempt.party)
    existing = _signatures(report.id)
    user_key = db.session.get(UserKey, uuid.UUID(attempt.key_id))
    if user_key is None or any(sig.party is party for sig in existing):
        raise in_progress
    try:
        settlement_ref = _settle(locked, attempt.release_cents, attempt.capture_cents)
    except PaymentUnavailable as exc:
        raise in_progress from exc
    result = transition(
        ContractStatus.INSPECTION_PENDING,
        Event.SIGN_REPORT,
        actor=Party(party.value),
        signed_by=frozenset(Party(sig.party.value) for sig in existing),
        deposit_cents=contract.deposit_cents,
        retained_cents=report.claimed_retention_cents,
    )
    new_status = rules.next_status(
        _domain_status(report), rules.ReportAction.SIGN, signatures=len(existing) + 1
    )
    _apply_release(
        contract,
        report,
        locked,
        result,
        user_id=attempt.user_id,
        party=party,
        key_id=user_key.id,
        signature_b64=attempt.signature,
        report_hash=attempt.report_hash,
        new_status=new_status,
        release_cents=attempt.release_cents,
        capture_cents=attempt.capture_cents,
        settlement_ref=settlement_ref,
    )
    db.session.commit()
    raise InvalidTransition(
        "La liberation en attente vient d'etre finalisee : le retour ne peut plus etre modifie",
        details={"reason": "SETTLEMENT_COMPLETED"},
    )


def _read_pending(contract_id: uuid.UUID) -> Deposit | None:
    deposit = db.session.scalar(
        select(Deposit).where(Deposit.contract_id == contract_id).execution_options(populate_existing=True)
    )
    if deposit is None or deposit.status is not DepositStatus.HELD:
        return None
    return deposit if settlement_journal.find_attempt(deposit.id) is not None else None


def get_receipt(user: User, raw_id: str) -> dict[str, Any]:
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    row = db.session.scalar(
        select(SettlementReceipt)
        .where(SettlementReceipt.contract_id == contract.id)
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise ResourceNotFound("Quittance introuvable")
    return _receipt_view(row)
