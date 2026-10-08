"""Reserve 2 : migration reelle sur un schema jetable (le reste de la suite utilise create_all).

Verifie : application jusqu'a head, journal escrow_events en ajout seul (trigger), et absence de derive
entre le schema migre et les modeles SQLAlchemy.
"""

import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask import Flask
from flask_migrate import downgrade, upgrade
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.extensions import db

MIGRATIONS_DIR = str(Path(__file__).resolve().parents[2] / "migrations")
RESTRICT_VIOLATION = "23001"


@pytest.fixture
def migrated(migrated_app: Flask) -> Flask:
    with migrated_app.app_context():
        upgrade(directory=MIGRATIONS_DIR)
    return migrated_app


def _seed_event(app: Flask) -> str:
    """Insere un utilisateur, un contrat et un evenement par SQL brut ; renvoie l'id de l'evenement."""
    owner, client, contract, event = (str(uuid.uuid4()) for _ in range(4))
    with app.app_context(), db.engine.begin() as conn:
        for uid, role in ((owner, "owner"), (client, "client")):
            conn.execute(
                text(
                    "INSERT INTO users (id, email, display_name, role, api_token_hash) "
                    "VALUES (CAST(:id AS uuid), :email, 'Nom', CAST(:role AS user_role), :hash)"
                ),
                {"id": uid, "email": f"{uid}@demo.test", "role": role, "hash": uid},
            )
        conn.execute(
            text(
                "INSERT INTO contracts (id, owner_id, client_id, vehicle_label, vehicle_plate, start_date, "
                "end_date, deposit_cents, currency) VALUES (CAST(:id AS uuid), CAST(:o AS uuid), "
                "CAST(:c AS uuid), 'Audi', 'AB-123-CD', '2026-11-01', '2026-11-05', 100, 'EUR')"
            ),
            {"id": contract, "o": owner, "c": client},
        )
        conn.execute(
            text(
                "INSERT INTO escrow_events (id, contract_id, event, actor_id, from_status, to_status) "
                "VALUES (CAST(:id AS uuid), CAST(:cid AS uuid), 'create', CAST(:a AS uuid), NULL, "
                "CAST('DRAFT' AS contract_status))"
            ),
            {"id": event, "cid": contract, "a": owner},
        )
    return event


def _count_events(app: Flask) -> int:
    with app.app_context(), db.engine.connect() as conn:
        return int(conn.execute(text("SELECT count(*) FROM escrow_events")).scalar_one())


def test_migrations_apply_up_to_head_and_create_all_tables(migrated):
    with migrated.app_context(), db.engine.connect() as conn:
        tables = set(
            conn.execute(
                text("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")
            ).scalars()
        )

    assert {"users", "contracts", "escrow_events", "idempotency_keys", "alembic_version"} <= tables


def test_migrations_create_enum_types_in_the_dedicated_schema(migrated):
    with migrated.app_context(), db.engine.connect() as conn:
        names = set(
            conn.execute(
                text(
                    "SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
                    "WHERE n.nspname = current_schema() AND t.typtype = 'e'"
                )
            ).scalars()
        )

    expected = {
        column.type.name
        for table in db.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, sa.Enum) and column.type.name
    }
    assert expected >= {"contract_status", "user_role"}
    assert names == expected


def test_migrations_add_nullable_jsonb_payload_column(migrated):
    with migrated.app_context(), db.engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = 'escrow_events' "
                "AND column_name = 'payload'"
            )
        ).one()

    assert tuple(row) == ("jsonb", "YES")


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE escrow_events SET event = 'tampered'",
        "UPDATE escrow_events SET payload_hash = 'x'",
        "DELETE FROM escrow_events",
        "TRUNCATE escrow_events",
    ],
)
def test_escrow_events_rejects_update_delete_truncate_with_restrict_violation(migrated, statement):
    _seed_event(migrated)

    with migrated.app_context(), pytest.raises(DBAPIError) as caught, db.engine.begin() as conn:
        conn.execute(text(statement))

    assert getattr(caught.value.orig, "sqlstate", None) == RESTRICT_VIOLATION


def test_escrow_events_row_is_untouched_after_rejected_modifications(migrated):
    _seed_event(migrated)
    for statement in ("UPDATE escrow_events SET event = 'x'", "DELETE FROM escrow_events"):
        with migrated.app_context(), pytest.raises(DBAPIError), db.engine.begin() as conn:
            conn.execute(text(statement))

    assert _count_events(migrated) == 1


def test_escrow_events_accepts_inserts(migrated):
    first = _seed_event(migrated)

    assert first
    assert _count_events(migrated) == 1


def test_migrated_schema_matches_sqlalchemy_metadata(migrated):
    with migrated.app_context(), db.engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        differences = compare_metadata(context, db.metadata)

    assert differences == []


def test_migrations_downgrade_to_base_then_upgrade_again(migrated):
    with migrated.app_context():
        downgrade(directory=MIGRATIONS_DIR, revision="base")
        upgrade(directory=MIGRATIONS_DIR)

    assert _count_events(migrated) == 0
