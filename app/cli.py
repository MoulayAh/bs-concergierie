"""Commandes CLI : `flask seed-demo` (comptes et cles de demonstration, idempotente)."""

import base64
import secrets
from datetime import UTC, datetime
from typing import Final

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask
from sqlalchemy import select

from app.extensions import db
from app.models import User, UserKey, UserRole
from app.security.auth import hash_token
from app.security.signatures import key_fingerprint

_DEMO_USERS: Final[tuple[tuple[str, str, UserRole], ...]] = (
    ("owner@demo.test", "Loueur Demo", UserRole.OWNER),
    ("client@demo.test", "Client Demo", UserRole.CLIENT),
    ("admin@demo.test", "Admin Demo", UserRole.ADMIN),
)


def _new_demo_key(user: User, *, rotate: bool) -> str | None:
    """Enregistre une paire Ed25519 si le compte n'a pas de cle active ; renvoie la cle privee (une fois)."""
    active = db.session.scalar(
        select(UserKey).where(UserKey.user_id == user.id, UserKey.revoked_at.is_(None))
    )
    if active is not None:
        if not rotate:
            return None
        active.revoked_at = datetime.now(UTC)
        db.session.flush()  # libere l'index "une seule cle active" avant l'insertion
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    db.session.add(UserKey(user_id=user.id, public_key=public_raw, fingerprint=key_fingerprint(public_raw)))
    seed = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    return base64.b64encode(seed).decode("ascii")


def register_cli(app: Flask) -> None:
    @app.cli.command("seed-demo")
    @click.option("--rotate", is_flag=True, help="Regenere jeton et cle des comptes deja existants.")
    def seed_demo(*, rotate: bool) -> None:
        """Cree les comptes de demo ; jeton et cle privee ne sont affiches qu'a la creation.

        Seuls le hash du jeton et la cle PUBLIQUE sont stockes : la cle privee (graine Ed25519 de 32 octets,
        base64) sert uniquement au script de demonstration en ligne de commande.
        """
        for email, display_name, role in _DEMO_USERS:
            user = db.session.scalar(select(User).where(User.email == email))
            token: str | None = None
            if user is None:
                token = secrets.token_urlsafe(32)
                user = User(
                    email=email, display_name=display_name, role=role, api_token_hash=hash_token(token)
                )
                db.session.add(user)
                db.session.flush()
            elif rotate:
                token = secrets.token_urlsafe(32)
                user.api_token_hash = hash_token(token)
            private_key = _new_demo_key(user, rotate=rotate)
            db.session.commit()
            if token is None:
                click.echo(f"{email}: deja present (jeton inchange)")
            else:
                click.echo(f"{email} ({role.value}): jeton {token}")
            if private_key is not None:
                click.echo(f"{email}: cle privee Ed25519 {private_key} (affichee une seule fois)")
