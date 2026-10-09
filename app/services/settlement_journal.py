"""Journal des tentatives de reglement (hors chaine d'evenements, committe AVANT l'appel au prestataire).

Un reglement peut avoir ete execute chez le prestataire alors que la reponse est perdue (503). Tant qu'une
tentative est journalisee pour un depot encore HELD, la ventilation est figee : le rapport de retour ne peut
plus etre remplace ni modifie, et tout reessai reutilise exactement les montants journalises.

Stockage : une ligne ``idempotency_keys`` reservee (cle ``settle:<deposit_id>``, hors de portee des clients
car ce prefixe est refuse en entree). Elle est invisible dans ``/events`` : un echec net du prestataire
laisse donc l'etat observable inchange.
"""

import uuid
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select

from app.domain.errors import InvalidTransition
from app.extensions import db
from app.models import Deposit, DepositStatus, IdempotencyKey
from app.services.idempotency import fingerprint

RESERVED_PREFIX: Final = "settle:"
_KIND: Final = "settle_attempt"


@dataclass(frozen=True)
class Attempt:
    deposit_id: uuid.UUID
    user_id: uuid.UUID
    release_cents: int
    capture_cents: int
    report_id: str
    report_hash: str
    party: str
    key_id: str
    signature: str


def journal_key(deposit_id: uuid.UUID) -> str:
    return f"{RESERVED_PREFIX}{deposit_id}"


def find_attempt(deposit_id: uuid.UUID) -> Attempt | None:
    rows = db.session.scalars(select(IdempotencyKey).where(IdempotencyKey.key == journal_key(deposit_id)))
    for row in rows:
        body = row.response_body
        if body.get("kind") == _KIND:
            return Attempt(
                deposit_id,
                row.user_id,
                int(body["release_cents"]),
                int(body["capture_cents"]),
                str(body["report_id"]),
                str(body["report_hash"]),
                str(body["party"]),
                str(body["key_id"]),
                str(body["signature"]),
            )
    return None


def record_attempt(attempt: Attempt) -> None:
    """Ajoute la ligne de journal et COMMIT (libere les verrous ; l'appelant doit reprendre sa requete)."""
    body: dict[str, Any] = {
        "kind": _KIND,
        "release_cents": attempt.release_cents,
        "capture_cents": attempt.capture_cents,
        "report_id": attempt.report_id,
        "report_hash": attempt.report_hash,
        "party": attempt.party,
        "key_id": attempt.key_id,
        "signature": attempt.signature,
    }
    db.session.add(
        IdempotencyKey(
            key=journal_key(attempt.deposit_id),
            user_id=attempt.user_id,
            request_hash=fingerprint(body),
            response_status=202,
            response_body=body,
        )
    )
    db.session.commit()


def forbid_if_in_progress(contract_id: uuid.UUID) -> None:
    """409 SETTLEMENT_IN_PROGRESS si un reglement a ete tente et que le depot est encore bloque."""
    deposit = db.session.scalar(
        select(Deposit).where(Deposit.contract_id == contract_id).execution_options(populate_existing=True)
    )
    if deposit is None or deposit.status is not DepositStatus.HELD:
        return
    if find_attempt(deposit.id) is not None:
        raise InvalidTransition(
            "Un reglement est en cours : l'etat des lieux de retour ne peut plus etre modifie",
            details={"reason": "SETTLEMENT_IN_PROGRESS"},
        )
