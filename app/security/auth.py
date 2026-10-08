"""Authentification Bearer : le jeton n'est jamais stocke en clair (SHA-256 hexadecimal)."""

import hashlib
from typing import cast

from flask import g, request
from sqlalchemy import select

from app.domain.errors import Unauthenticated
from app.extensions import db
from app.models import User

MAX_TOKEN_LENGTH = 256
_SCHEME = "bearer"


def hash_token(token: str) -> str:
    """Les jetons sont aleatoires a haute entropie : un SHA-256 simple suffit (pas de mot de passe)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _extract_token() -> str:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != _SCHEME or not token:
        raise Unauthenticated("Authentification requise")
    if len(token) > MAX_TOKEN_LENGTH or not token.isascii() or not token.isprintable() or " " in token:
        raise Unauthenticated("Jeton invalide")
    return token


def authenticate_request() -> User:
    """Identifie l'appelant ou leve ``Unauthenticated`` ; place l'utilisateur dans ``g``."""
    token = _extract_token()
    user = db.session.scalar(select(User).where(User.api_token_hash == hash_token(token)))
    if user is None:
        raise Unauthenticated("Jeton invalide")
    g.current_user = user
    return user


def current_user() -> User:
    return cast(User, g.current_user)
