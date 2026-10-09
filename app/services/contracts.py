"""Orchestration des contrats : transaction, verrou de ligne, machine d'etats, evenement, idempotence.

Aucune route ne modifie ``status`` : tout passe par ``state_machine.transition``.
"""

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, insert, select
from sqlalchemy.exc import IntegrityError

from app.domain.errors import (
    ForbiddenActor,
    InvalidAmount,
    InvalidTransition,
    PaymentDeclined,
    PaymentUnavailable,
    ResourceNotFound,
    ValidationFailed,
)
from app.domain.money import validate_deposit_cents
from app.domain.state_machine import ContractStatus, Event, Party, transition
from app.extensions import db
from app.models import (
    Contract,
    Deposit,
    DepositStatus,
    EscrowEvent,
    InspectionReport,
    ReportKind,
    ReportStatus,
    User,
    UserRole,
)
from app.models import ContractStatus as StoredStatus
from app.schemas.contracts import CreateContractIn, DepositIn, contract_to_dict, funds_to_dict
from app.services import idempotency
from app.services.idempotency import Outcome, fingerprint
from app.services.payments import PROVIDER_NAME, get_provider

_NOT_FOUND_MESSAGE = "Contrat introuvable"
_log = logging.getLogger(__name__)


def require_owner(user: User) -> None:
    if user.role is not UserRole.OWNER:
        raise ForbiddenActor("Seul un loueur peut creer un contrat")


def parse_id(raw_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw_id)
    except ValueError as exc:
        raise ResourceNotFound(_NOT_FOUND_MESSAGE) from exc


def _party_of(contract: Contract, user_id: uuid.UUID) -> Party | None:
    if user_id == contract.owner_id:
        return Party.OWNER
    if user_id == contract.client_id:
        return Party.CLIENT
    return None


def load_for_party(user_id: uuid.UUID, contract_id: uuid.UUID, *, lock: bool) -> tuple[Contract, Party]:
    """Charge le contrat (verrou de ligne optionnel). Inexistant ou tiers => meme 404 (pas d'IDOR)."""
    stmt = select(Contract).where(Contract.id == contract_id).execution_options(populate_existing=True)
    if lock:
        stmt = stmt.with_for_update(of=Contract)
    contract = db.session.scalar(stmt)
    party = _party_of(contract, user_id) if contract is not None else None
    if contract is None or party is None:
        raise ResourceNotFound(_NOT_FOUND_MESSAGE)
    return contract, party


def write_event(
    contract_id: uuid.UUID,
    event: str,
    actor_id: uuid.UUID,
    from_status: StoredStatus | None,
    to_status: StoredStatus,
    payload: object,
    data: dict[str, Any] | None = None,
) -> None:
    # clock_timestamp() (et non now()) : l'ordre des evenements suit l'ordre reel d'ecriture,
    # donc l'ordre d'acquisition du verrou, pas celui de debut de transaction.
    db.session.execute(
        insert(EscrowEvent).values(
            contract_id=contract_id,
            event=event,
            actor_id=actor_id,
            from_status=from_status,
            to_status=to_status,
            payload_hash=fingerprint(payload),
            payload=data,
            created_at=func.clock_timestamp(),
        )
    )


def create_contract(
    owner: User, data: CreateContractIn, *, idempotency_key: str, request_hash: str
) -> Outcome:
    require_owner(owner)
    owner_id = owner.id
    idempotency.lock_key(idempotency_key, owner_id)
    replay = idempotency.find_replay(idempotency_key, owner_id, request_hash)
    if replay is not None:
        return replay

    client = db.session.scalar(select(User).where(func.lower(User.email) == data.client_email))
    if client is None or client.role is not UserRole.CLIENT or client.id == owner_id:
        raise ValidationFailed(
            "client_email ne designe pas un client valide", details={"errors": [{"field": "client_email"}]}
        )

    contract = Contract(
        owner=owner,
        client=client,
        vehicle_label=data.vehicle_label,
        vehicle_plate=data.vehicle_plate,
        start_date=data.start_date,
        end_date=data.end_date,
        deposit_cents=validate_deposit_cents(data.deposit_cents),
        currency=data.currency,
        status=StoredStatus.DRAFT,
        version=1,
    )
    db.session.add(contract)
    db.session.flush()
    write_event(
        contract.id,
        "create",
        owner_id,
        None,
        StoredStatus.DRAFT,
        {"op": "create", "request": request_hash},
    )
    outcome = Outcome(201, contract_to_dict(contract))
    idempotency.record(idempotency_key, owner_id, request_hash, outcome)
    db.session.commit()
    return outcome


def _event_data(event: Event, body: object) -> dict[str, Any] | None:
    if event is Event.CANCEL and isinstance(body, dict):
        reason = body.get("reason")
        if isinstance(reason, str) and reason:
            return {"reason": reason}
    return None


def _apply_event(
    user: User,
    raw_id: str,
    event: Event,
    *,
    body: object,
    idempotency_key: str | None,
) -> Outcome:
    contract_id = parse_id(raw_id)
    user_id = user.id
    request_hash = fingerprint({"op": event.value, "contract": str(contract_id), "body": body})
    if idempotency_key is not None:
        idempotency.lock_key(idempotency_key, user_id)
    contract, party = load_for_party(user_id, contract_id, lock=True)
    if idempotency_key is not None:
        replay = idempotency.find_replay(idempotency_key, user_id, request_hash)
        if replay is not None:
            return replay

    current = ContractStatus(contract.status.value)
    result = transition(current, event, actor=party, signed_by=_approvals(contract, event))
    if event is Event.START_RENTAL and (
        contract.owner_cancel_approved_at is not None or contract.client_cancel_approved_at is not None
    ):
        raise InvalidTransition(
            "Une demande d'annulation est en attente : le vehicule ne peut pas etre remis",
            details={"reason": "CANCELLATION_PENDING"},
        )
    if event is Event.START_RENTAL:
        _require_signed_checkout(contract_id)

    previous = contract.status
    now = datetime.now(UTC)
    if event is Event.SIGN_CONTRACT:
        _stamp(contract, party, "signed", now)
    elif event is Event.CANCEL and current is ContractStatus.FUNDED:
        _stamp(contract, party, "cancel_approved", now)
    elif event is Event.START_RENTAL:
        contract.started_at = now
    deposit = _locked_deposit(contract_id) if current is ContractStatus.FUNDED else None
    if event is Event.CANCEL and result.status is ContractStatus.REFUNDED:
        _refund(deposit)
    contract.status = StoredStatus(result.status.value)
    contract.version += 1
    db.session.flush()

    write_event(
        contract_id,
        event.value,
        user_id,
        previous,
        contract.status,
        {"op": event.value, "actor": str(user_id), "body": body, "version": contract.version},
        _event_data(event, body),
    )
    outcome = Outcome(200, contract_to_dict(contract, deposit))
    if idempotency_key is not None:
        idempotency.record(idempotency_key, user_id, request_hash, outcome)
    db.session.commit()
    return outcome


def _require_signed_checkout(contract_id: uuid.UUID) -> None:
    """La remise du vehicule exige un etat des lieux de depart actif signe par les deux parties."""
    status = db.session.scalar(
        select(InspectionReport.status).where(
            InspectionReport.contract_id == contract_id,
            InspectionReport.kind == ReportKind.CHECKOUT,
            InspectionReport.status != ReportStatus.SUPERSEDED,
        )
    )
    if status is not ReportStatus.SIGNED:
        raise InvalidTransition(
            "L'etat des lieux de depart doit etre signe par les deux parties avant la remise du vehicule",
            details={"reason": "CHECKOUT_REPORT_NOT_SIGNED"},
        )


def _approvals(contract: Contract, event: Event) -> frozenset[Party]:
    """Approbations deja posees POUR CET EVENEMENT (et non celles d'un autre evenement)."""
    if event is Event.CANCEL:
        stamps = {
            Party.OWNER: contract.owner_cancel_approved_at,
            Party.CLIENT: contract.client_cancel_approved_at,
        }
    else:
        stamps = {Party.OWNER: contract.owner_signed_at, Party.CLIENT: contract.client_signed_at}
    return frozenset(p for p, at in stamps.items() if at is not None)


def _stamp(contract: Contract, party: Party, kind: str, now: datetime) -> None:
    if kind == "signed":
        if party is Party.OWNER:
            contract.owner_signed_at = now
        else:
            contract.client_signed_at = now
    elif party is Party.OWNER:
        contract.owner_cancel_approved_at = now
    else:
        contract.client_cancel_approved_at = now


def _locked_deposit(contract_id: uuid.UUID) -> Deposit | None:
    return db.session.scalar(
        select(Deposit)
        .where(Deposit.contract_id == contract_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def _refund(deposit: Deposit | None) -> None:
    """Rembourse la totalite : appel prestataire (sous verrou, donc une seule fois) puis une seule UPDATE."""
    if deposit is None or deposit.status is not DepositStatus.HELD:
        raise InvalidTransition("Aucune caution bloquee a rembourser")
    get_provider().refund(deposit.provider_ref)
    deposit.refunded_cents = deposit.refunded_cents + deposit.held_cents
    deposit.held_cents = 0
    deposit.status = DepositStatus.REFUNDED


def deposit_funds(user: User, raw_id: str, data: DepositIn, *, idempotency_key: str, body: object) -> Outcome:
    contract_id = parse_id(raw_id)
    user_id = user.id
    request_hash = fingerprint({"op": Event.DEPOSIT.value, "contract": str(contract_id), "body": body})
    idempotency.lock_key(idempotency_key, user_id)
    contract, party = load_for_party(user_id, contract_id, lock=True)
    replay = idempotency.find_replay(idempotency_key, user_id, request_hash)
    if replay is not None:
        return replay

    result = transition(ContractStatus(contract.status.value), Event.DEPOSIT, actor=party)
    if data.amount_cents != contract.deposit_cents:
        raise InvalidAmount("Le montant doit etre egal a la caution du contrat")
    if data.currency != contract.currency.strip():
        raise ValidationFailed(
            "La devise doit etre celle du contrat", details={"errors": [{"field": "currency"}]}
        )

    amount, currency, previous = contract.deposit_cents, contract.currency.strip(), contract.status
    provider_key = hashlib.sha256(f"{user_id}:{contract_id}:{idempotency_key}".encode()).hexdigest()
    try:
        ref = get_provider().hold(amount, currency, data.payment_method, provider_key)
    except (PaymentDeclined, PaymentUnavailable) as exc:
        db.session.rollback()  # libere le verrou ; le journal est ecrit dans une transaction separee
        try:
            write_event(
                contract_id,
                "deposit_failed",
                user_id,
                previous,
                previous,
                {"op": "deposit_failed", "actor": str(user_id), "code": exc.code},
            )
            db.session.commit()
        except Exception:  # noqa: BLE001 - ne jamais masquer l'erreur 402/503 d'origine
            db.session.rollback()
            _log.exception("Echec d'ecriture de deposit_failed (contrat %s)", contract_id)
        raise

    try:
        db.session.add(
            Deposit(
                contract_id=contract_id,
                amount_cents=amount,
                currency=currency,
                status=DepositStatus.HELD,
                held_cents=amount,
                provider=PROVIDER_NAME,
                provider_ref=ref,
            )
        )
        contract.status = StoredStatus(result.status.value)
        contract.version += 1
        db.session.flush()
        write_event(
            contract_id,
            Event.DEPOSIT.value,
            user_id,
            previous,
            contract.status,
            {"op": "deposit", "actor": str(user_id), "body": body, "version": contract.version},
        )
        deposit = _locked_deposit(contract_id)
        outcome = Outcome(200, contract_to_dict(contract, deposit))
        idempotency.record(idempotency_key, user_id, request_hash, outcome)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        try:
            get_provider().refund(ref)
        except Exception:  # noqa: BLE001 - l'erreur d'origine prime ; l'echec est journalise
            _log.exception("Compensation impossible : blocage %s orphelin (contrat %s)", ref, contract_id)
        if isinstance(exc, IntegrityError):
            raise InvalidTransition("Depot deja enregistre ou conflit concurrent") from exc
        raise
    return outcome


def get_deposit(user: User, raw_id: str) -> dict[str, Any]:
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    deposit = _read_deposit(contract.id)
    if deposit is None:
        raise ResourceNotFound("Aucun depot pour ce contrat")
    return funds_to_dict(deposit)


def _read_deposit(contract_id: uuid.UUID) -> Deposit | None:
    return db.session.scalar(
        select(Deposit).where(Deposit.contract_id == contract_id).execution_options(populate_existing=True)
    )


def start_rental(user: User, raw_id: str, *, idempotency_key: str | None) -> Outcome:
    return _apply_event(user, raw_id, Event.START_RENTAL, body=None, idempotency_key=idempotency_key)


def sign_contract(user: User, raw_id: str, *, idempotency_key: str | None) -> Outcome:
    return _apply_event(user, raw_id, Event.SIGN_CONTRACT, body=None, idempotency_key=idempotency_key)


def cancel_contract(user: User, raw_id: str, *, body: object, idempotency_key: str | None) -> Outcome:
    return _apply_event(user, raw_id, Event.CANCEL, body=body, idempotency_key=idempotency_key)


def get_contract(user: User, raw_id: str) -> dict[str, Any]:
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    return contract_to_dict(contract, _read_deposit(contract.id))


def list_events(user: User, raw_id: str) -> list[dict[str, Any]]:
    contract, _ = load_for_party(user.id, parse_id(raw_id), lock=False)
    rows = db.session.scalars(
        select(EscrowEvent)
        .where(EscrowEvent.contract_id == contract.id)
        .order_by(EscrowEvent.created_at, EscrowEvent.id)
    ).all()
    return [
        {
            "event": row.event,
            "actor_id": str(row.actor_id),
            "from_status": row.from_status.value if row.from_status is not None else None,
            "to_status": row.to_status.value,
            "payload_hash": row.payload_hash,
            "payload": row.payload,
            "created_at": row.created_at.astimezone(UTC).isoformat(),
        }
        for row in rows
    ]
