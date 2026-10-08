"""Orchestration des contrats : transaction, verrou de ligne, machine d'etats, evenement, idempotence.

Aucune route ne modifie ``status`` : tout passe par ``state_machine.transition``.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, insert, select

from app.domain.errors import ForbiddenActor, ResourceNotFound, ValidationFailed
from app.domain.money import validate_deposit_cents
from app.domain.state_machine import ContractStatus, Event, Party, transition
from app.extensions import db
from app.models import Contract, EscrowEvent, User, UserRole
from app.models import ContractStatus as StoredStatus
from app.schemas.contracts import CreateContractIn, contract_to_dict
from app.services import idempotency
from app.services.idempotency import Outcome, fingerprint

_NOT_FOUND_MESSAGE = "Contrat introuvable"


def require_owner(user: User) -> None:
    if user.role is not UserRole.OWNER:
        raise ForbiddenActor("Seul un loueur peut creer un contrat")


def _parse_id(raw_id: str) -> uuid.UUID:
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


def _load_for_party(user_id: uuid.UUID, contract_id: uuid.UUID, *, lock: bool) -> tuple[Contract, Party]:
    """Charge le contrat (verrou de ligne optionnel). Inexistant ou tiers => meme 404 (pas d'IDOR)."""
    stmt = select(Contract).where(Contract.id == contract_id).execution_options(populate_existing=True)
    if lock:
        stmt = stmt.with_for_update(of=Contract)
    contract = db.session.scalar(stmt)
    party = _party_of(contract, user_id) if contract is not None else None
    if contract is None or party is None:
        raise ResourceNotFound(_NOT_FOUND_MESSAGE)
    return contract, party


def _write_event(
    contract_id: uuid.UUID,
    event: str,
    actor_id: uuid.UUID,
    from_status: StoredStatus | None,
    to_status: StoredStatus,
    payload: object,
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
    _write_event(
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


def _apply_event(
    user: User,
    raw_id: str,
    event: Event,
    *,
    body: object,
    idempotency_key: str | None,
) -> Outcome:
    contract_id = _parse_id(raw_id)
    user_id = user.id
    request_hash = fingerprint({"op": event.value, "contract": str(contract_id), "body": body})
    if idempotency_key is not None:
        idempotency.lock_key(idempotency_key, user_id)
    contract, party = _load_for_party(user_id, contract_id, lock=True)
    if idempotency_key is not None:
        replay = idempotency.find_replay(idempotency_key, user_id, request_hash)
        if replay is not None:
            return replay

    current = ContractStatus(contract.status.value)
    signatures = {Party.OWNER: contract.owner_signed_at, Party.CLIENT: contract.client_signed_at}
    signed_by = frozenset(p for p, signed_at in signatures.items() if signed_at is not None)
    result = transition(current, event, actor=party, signed_by=signed_by)

    previous = contract.status
    if event is Event.SIGN_CONTRACT:
        now = datetime.now(UTC)
        if party is Party.OWNER:
            contract.owner_signed_at = now
        else:
            contract.client_signed_at = now
    contract.status = StoredStatus(result.status.value)
    contract.version += 1
    db.session.flush()

    _write_event(
        contract_id,
        event.value,
        user_id,
        previous,
        contract.status,
        {"op": event.value, "actor": str(user_id), "body": body, "version": contract.version},
    )
    outcome = Outcome(200, contract_to_dict(contract))
    if idempotency_key is not None:
        idempotency.record(idempotency_key, user_id, request_hash, outcome)
    db.session.commit()
    return outcome


def sign_contract(user: User, raw_id: str, *, idempotency_key: str | None) -> Outcome:
    return _apply_event(user, raw_id, Event.SIGN_CONTRACT, body=None, idempotency_key=idempotency_key)


def cancel_contract(user: User, raw_id: str, *, body: object, idempotency_key: str | None) -> Outcome:
    return _apply_event(user, raw_id, Event.CANCEL, body=body, idempotency_key=idempotency_key)


def get_contract(user: User, raw_id: str) -> dict[str, Any]:
    contract, _ = _load_for_party(user.id, _parse_id(raw_id), lock=False)
    return contract_to_dict(contract)


def list_events(user: User, raw_id: str) -> list[dict[str, Any]]:
    contract, _ = _load_for_party(user.id, _parse_id(raw_id), lock=False)
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
            "created_at": row.created_at.astimezone(UTC).isoformat(),
        }
        for row in rows
    ]
