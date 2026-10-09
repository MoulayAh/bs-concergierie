"""Fixtures partagees. Specification executable (TDD) : les interfaces ci-dessous sont SUPPOSEES.

Interfaces supposees (backend-dev / db-migrator doivent s'y aligner) :

Application
  - ``app.create_app(config: dict | None = None) -> flask.Flask``. Cles de config utilisees par les tests :
    ``TESTING``, ``SECRET_KEY``, ``DATABASE_URL`` (URL SQLAlchemy PostgreSQL de test),
    ``UPLOAD_DIR``, ``MAX_DEPOSIT_CENTS``, ``SERVER_SIGNING_KEY`` (F4 : base64 de la graine privee Ed25519
    de 32 octets du serveur ; cle de test generee une fois par session dans tests/fixtures/release.py ;
    ``create_app`` refuse de demarrer sans elle).
  - ``app.extensions.db`` : instance Flask-SQLAlchemy (``create_all`` / ``drop_all`` / ``session``).
  - Commande CLI ``flask seed-demo`` (idempotente) : cree au moins un utilisateur ``owner`` et un ``client``.
  - ``app.security.auth.hash_token(token: str) -> str`` : hachage du jeton Bearer stocke dans
    ``users.api_token_hash`` (le jeton en clair n'est jamais stocke).

Modeles (``app.models``) : ``User``, ``Contract``, ``EscrowEvent``, ``IdempotencyKey``, colonnes du plan
  (users: id, email, display_name, role, api_token_hash ; contracts: id, status, version, ... ;
   escrow_events: id, contract_id, event, actor_id, from_status, to_status, payload_hash, created_at).

Domaine pur (sans Flask ni DB) :
  - ``app.domain.state_machine`` : ``ContractStatus``, ``Event``, ``Party`` (enums str), ``transition(...)``,
    ``TransitionResult``, ``TERMINAL_STATUSES``.
  - ``app.domain.money`` : ``MAX_DEPOSIT_CENTS``, ``ALLOWED_CURRENCIES``, ``validate_deposit_cents``,
    ``validate_retained_cents``, ``split_deposit``.
  - ``app.domain.errors`` : ``DomainError`` (attributs ``code``, ``http_status``), ``InvalidTransition``,
    ``ForbiddenActor``, ``InvalidAmount``.

Fixtures de ce fichier
  - ``app`` : application avec base PostgreSQL de test (env ``TEST_DATABASE_URL``),
    schema PostgreSQL unique par session pytest (search_path), tables recreees
    (drop_all + create_all) avant CHAQUE test dans ce schema.
  - ``api`` : ``tests.fixtures.helpers.Api`` (client de test Flask : JSON + Bearer + Idempotency-Key).
  - ``make_user(role, email=None, display_name=None)`` : fabrique un utilisateur et renvoie un ``TestUser``
    (``id``, ``email``, ``token`` en clair, ``headers``).
  - ``owner_user``, ``client_user``, ``stranger_user`` (client tiers), ``admin_user``.

Les tests d'integration necessitent PostgreSQL : pas de skip, ils echouent si la base est injoignable.
"""

import os
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from app import create_app
from app.extensions import db
from app.models import User
from app.security.auth import hash_token
from tests.fixtures.helpers import Api, TestUser, new_token
from tests.fixtures.release import SERVER_KEY_B64

DEFAULT_TEST_DB = "postgresql+psycopg://escrow:escrow_test@localhost:5433/escrow_test"


def _test_database_url() -> str:
    return os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_DB)


def pytest_configure(config: pytest.Config) -> None:
    """Garde-fou : refuse de tourner si la base ne se termine pas par ``_test`` (protege la base de dev)."""
    database = make_url(_test_database_url()).database or ""
    if not database.endswith("_test"):
        raise pytest.UsageError(
            f"TEST_DATABASE_URL pointe sur la base {database!r} : le nom doit se terminer par '_test' "
            "(protection de la base de dev contre les suppressions)."
        )


@pytest.fixture(scope="session")
def pg_schema() -> Iterator[str]:
    """Schema PostgreSQL unique a cette execution pytest ; retire en fin de session (meme en echec)."""
    schema = f"test_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    admin = create_engine(_test_database_url(), poolclass=NullPool, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        yield schema
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            left = conn.execute(
                text("SELECT count(*) FROM information_schema.schemata WHERE schema_name = :n"), {"n": schema}
            ).scalar_one()
        admin.dispose()
        assert left == 0, f"schema de test {schema} non supprime"


@pytest.fixture
def app(tmp_path: Path, pg_schema: str) -> Iterator[Flask]:
    # Toutes les connexions (threads et nouvelles connexions compris) passent par ce search_path :
    # tables ET types enum sont crees dans le schema dedie, jamais dans ``public``.
    engine_options: dict[str, Any] = {
        "poolclass": NullPool,
        "connect_args": {"options": f"-csearch_path={pg_schema}"},
    }
    flask_app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key-not-for-production-0123456789",
            "DATABASE_URL": _test_database_url(),
            "SQLALCHEMY_ENGINE_OPTIONS": engine_options,
            "UPLOAD_DIR": str(tmp_path / "uploads"),
            "MAX_DEPOSIT_CENTS": 50_000_000,
            "SERVER_SIGNING_KEY": SERVER_KEY_B64,
        }
    )
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
    yield flask_app
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def migrated_app(tmp_path: Path) -> Iterator[Flask]:
    """Application dont le schema jetable dedie est VIDE : le test applique lui-meme les migrations."""
    schema = f"mig_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    admin = create_engine(_test_database_url(), poolclass=NullPool, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        flask_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-not-for-production-0123456789",
                "DATABASE_URL": _test_database_url(),
                "SQLALCHEMY_ENGINE_OPTIONS": {
                    "poolclass": NullPool,
                    "connect_args": {"options": f"-csearch_path={schema}"},
                },
                "UPLOAD_DIR": str(tmp_path / "uploads"),
                "SERVER_SIGNING_KEY": SERVER_KEY_B64,
            }
        )
        yield flask_app
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def api(app: Flask) -> Api:
    return Api(app)


@pytest.fixture
def make_user(app: Flask) -> Callable[..., TestUser]:
    counter = {"n": 0}

    def _make(role: str, email: str | None = None, display_name: str | None = None) -> TestUser:
        counter["n"] += 1
        n = counter["n"]
        token = new_token()
        user_email = email or f"{role}{n}@demo.test"
        with app.app_context():
            user = User(
                email=user_email,
                display_name=display_name or f"{role.title()} {n}",
                role=role,
                api_token_hash=hash_token(token),
            )
            db.session.add(user)
            db.session.commit()
            user_id = str(user.id)
        return TestUser(id=user_id, email=user_email, role=role, token=token)

    return _make


@pytest.fixture
def owner_user(make_user) -> TestUser:
    return make_user("owner", email="owner@demo.test")


@pytest.fixture
def client_user(make_user) -> TestUser:
    return make_user("client", email="client@demo.test")


@pytest.fixture
def stranger_user(make_user) -> TestUser:
    return make_user("client", email="stranger@demo.test")


@pytest.fixture
def admin_user(make_user) -> TestUser:
    return make_user("admin", email="admin@demo.test")
