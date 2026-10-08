"""Idempotence des requetes POST : portee (cle, utilisateur), empreinte comparee en temps constant."""

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text

from app.domain.errors import IdempotencyConflict
from app.extensions import db
from app.models import IdempotencyKey


@dataclass(frozen=True)
class Outcome:
    """Reponse HTTP memorisee (statut + corps JSON)."""

    status: int
    body: dict[str, Any]


def fingerprint(payload: object) -> str:
    """SHA-256 d'un JSON canonique (independant de l'ordre des cles)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def lock_key(key: str, user_id: uuid.UUID) -> None:
    """Serialise les requetes concurrentes portant la meme cle (verrou libere au commit/rollback)."""
    db.session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {"scope": f"idem:{user_id}:{key}"},
    )


def find_replay(key: str, user_id: uuid.UUID, request_hash: str) -> Outcome | None:
    row = db.session.scalar(
        select(IdempotencyKey).where(IdempotencyKey.key == key, IdempotencyKey.user_id == user_id)
    )
    if row is None:
        return None
    if not hmac.compare_digest(row.request_hash, request_hash):
        raise IdempotencyConflict("Cette Idempotency-Key a deja ete utilisee avec une autre requete")
    return Outcome(row.response_status, row.response_body)


def record(key: str, user_id: uuid.UUID, request_hash: str, outcome: Outcome) -> None:
    db.session.add(
        IdempotencyKey(
            key=key,
            user_id=user_id,
            request_hash=request_hash,
            response_status=outcome.status,
            response_body=outcome.body,
        )
    )
