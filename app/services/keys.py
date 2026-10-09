"""Cles publiques Ed25519 des utilisateurs : une seule cle active, revocation, jamais de cle privee."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.domain.errors import KeyAlreadyActive, ResourceNotFound, ValidationFailed
from app.extensions import db
from app.models import User, UserKey
from app.schemas.reports import KeyIn, key_to_dict
from app.security.signatures import decode_public_key, key_fingerprint


def _active_key(user_id: uuid.UUID) -> UserKey | None:
    return db.session.scalar(
        select(UserKey)
        .where(UserKey.user_id == user_id, UserKey.revoked_at.is_(None))
        .execution_options(populate_existing=True)
    )


def register_key(user: User, data: KeyIn) -> dict[str, Any]:
    user_id = user.id
    raw = decode_public_key(data.public_key)
    # Verrou sur la ligne utilisateur : deux enregistrements concurrents sont serialises.
    db.session.execute(select(User.id).where(User.id == user_id).with_for_update())
    if _active_key(user_id) is not None:
        raise KeyAlreadyActive("Une cle active existe deja : revoquez-la avant d'en enregistrer une autre")
    fingerprint = key_fingerprint(raw)
    if db.session.scalar(select(UserKey.id).where(UserKey.fingerprint == fingerprint)) is not None:
        raise ValidationFailed("Cette cle publique est deja enregistree")
    key = UserKey(user_id=user_id, public_key=raw, fingerprint=fingerprint)
    db.session.add(key)
    try:
        db.session.flush()
    except IntegrityError as exc:
        db.session.rollback()
        raise ValidationFailed("Cette cle publique est deja enregistree") from exc
    db.session.refresh(key)
    body = key_to_dict(key)
    db.session.commit()
    return body


def list_keys(user: User) -> list[dict[str, Any]]:
    rows = db.session.scalars(
        select(UserKey)
        .where(UserKey.user_id == user.id)
        .order_by(UserKey.created_at, UserKey.id)
        .execution_options(populate_existing=True)
    ).all()
    return [key_to_dict(row) for row in rows]


def revoke_key(user: User, raw_key_id: str) -> None:
    user_id = user.id
    try:
        key_id = uuid.UUID(raw_key_id)
    except ValueError as exc:
        raise ResourceNotFound("Cle introuvable") from exc
    key = db.session.scalar(
        select(UserKey).where(UserKey.id == key_id, UserKey.user_id == user_id).with_for_update()
    )
    if key is None:
        raise ResourceNotFound("Cle introuvable")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
    db.session.commit()
