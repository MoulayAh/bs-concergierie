"""Commandes CLI : `flask seed-demo` (comptes de demonstration, idempotente)."""

import secrets
from typing import Final

import click
from flask import Flask
from sqlalchemy import select

from app.extensions import db
from app.models import User, UserRole
from app.security.auth import hash_token

_DEMO_USERS: Final[tuple[tuple[str, str, UserRole], ...]] = (
    ("owner@demo.test", "Loueur Demo", UserRole.OWNER),
    ("client@demo.test", "Client Demo", UserRole.CLIENT),
    ("admin@demo.test", "Admin Demo", UserRole.ADMIN),
)


def register_cli(app: Flask) -> None:
    @app.cli.command("seed-demo")
    @click.option("--rotate", is_flag=True, help="Regenere le jeton des comptes deja existants.")
    def seed_demo(*, rotate: bool) -> None:
        """Cree les comptes de demo ; le jeton n'est affiche qu'a la creation (seul son hash est stocke)."""
        for email, display_name, role in _DEMO_USERS:
            user = db.session.scalar(select(User).where(User.email == email))
            if user is not None and not rotate:
                click.echo(f"{email}: deja present (jeton inchange)")
                continue
            token = secrets.token_urlsafe(32)
            if user is None:
                db.session.add(
                    User(email=email, display_name=display_name, role=role, api_token_hash=hash_token(token))
                )
            else:
                user.api_token_hash = hash_token(token)
            db.session.commit()
            click.echo(f"{email} ({role.value}): jeton {token}")
