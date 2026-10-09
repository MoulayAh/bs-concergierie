"""F3 : gel d'un rapport garanti par PostgreSQL (trigger + contraintes), sur un schema reellement migre.

Le trigger n'existe pas avec ``create_all`` : on utilise ``migrated_app`` comme test_migrations.py.
Tables supposees (plan F3) : users, contracts, inspection_reports (enums ``report_kind`` / ``report_status``).
"""

import uuid
from pathlib import Path

import pytest
from flask import Flask
from flask_migrate import upgrade
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.extensions import db

MIGRATIONS_DIR = str(Path(__file__).resolve().parents[2] / "migrations")
HASH = "a" * 64


@pytest.fixture
def migrated(migrated_app: Flask) -> Flask:
    with migrated_app.app_context():
        upgrade(directory=MIGRATIONS_DIR)
    return migrated_app


def _seed_contract(conn) -> str:
    owner, client, contract = (str(uuid.uuid4()) for _ in range(3))
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
    return contract


def _insert_report(
    conn,
    contract: str,
    status: str,
    kind: str = "checkout",
    revision: int = 1,
    report_hash: str | None = None,
    supersedes: str | None = None,
    no_hash: bool = False,
) -> str:
    frozen = status != "DRAFT"
    report_id = str(uuid.uuid4())
    digest = None if no_hash else (report_hash if report_hash is not None else (HASH if frozen else None))
    conn.execute(
        text(
            "INSERT INTO inspection_reports (id, contract_id, kind, revision, status, supersedes_id, "
            "odometer_km, fuel_eighths, damages, claimed_retention_cents, notes, canonical_json, "
            "report_hash, frozen_at, version) VALUES (CAST(:id AS uuid), CAST(:c AS uuid), "
            "CAST(:kind AS report_kind), :rev, CAST(:status AS report_status), CAST(:sup AS uuid), "
            "100, 8, CAST('[]' AS jsonb), 0, '', :canon, :hash, CASE WHEN :frozen THEN now() END, 1)"
        ),
        {
            "id": report_id,
            "c": contract,
            "kind": kind,
            "rev": revision,
            "status": status,
            "sup": supersedes,
            "canon": b"{}" if frozen else None,
            "hash": digest,
            "frozen": frozen,
        },
    )
    return report_id


def _setup(app: Flask, status: str) -> tuple[str, str]:
    with app.app_context(), db.engine.begin() as conn:
        contract = _seed_contract(conn)
        return contract, _insert_report(conn, contract, status)


def _run(app: Flask, statement: str, report_id: str, **params: str) -> None:
    with app.app_context(), db.engine.begin() as conn:
        conn.execute(text(statement), {"id": report_id, **params})


SET_STATUS = (
    "UPDATE inspection_reports SET status = CAST(:target AS report_status) WHERE id = CAST(:id AS uuid)"
)


def _row(app: Flask, report_id: str) -> tuple:
    with app.app_context(), db.engine.connect() as conn:
        return tuple(
            conn.execute(
                text(
                    "SELECT status::text, odometer_km, fuel_eighths, damages::text, claimed_retention_cents, "
                    "notes, canonical_json, report_hash, revision, kind::text FROM inspection_reports "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": report_id},
            ).one()
        )


FROZEN_CONTENT_UPDATES = [
    "UPDATE inspection_reports SET odometer_km = 999 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET fuel_eighths = 1 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET damages = CAST('[1]' AS jsonb) WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET claimed_retention_cents = 5 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET notes = 'edited' WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET canonical_json = convert_to('[]', 'UTF8') WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET report_hash = repeat('b', 64) WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET revision = 2 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET kind = CAST('return' AS report_kind) WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET report_hash = NULL WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET status = CAST('DRAFT' AS report_status) WHERE id = CAST(:id AS uuid)",
]


@pytest.mark.parametrize("statement", FROZEN_CONTENT_UPDATES)
@pytest.mark.parametrize("status", ["FROZEN", "SIGNED", "SUPERSEDED"])
def test_frozen_report_rejected_by_database_trigger(migrated, status, statement):
    _, report_id = _setup(migrated, status)
    before = _row(migrated, report_id)

    with pytest.raises(DBAPIError):
        _run(migrated, statement, report_id)

    assert _row(migrated, report_id) == before


def test_draft_report_content_remains_editable(migrated):
    _, report_id = _setup(migrated, "DRAFT")

    _run(
        migrated,
        "UPDATE inspection_reports SET odometer_km = 321, notes = 'ok' WHERE id = CAST(:id AS uuid)",
        report_id,
    )

    assert _row(migrated, report_id)[1] == 321


def test_frozen_report_can_move_to_signed(migrated):
    _, report_id = _setup(migrated, "FROZEN")
    before = _row(migrated, report_id)

    _run(migrated, SET_STATUS, report_id, target="SIGNED")

    after = _row(migrated, report_id)
    assert after[0] == "SIGNED"
    assert after[1:] == before[1:]


def test_frozen_report_can_move_to_superseded(migrated):
    _, report_id = _setup(migrated, "FROZEN")

    _run(migrated, SET_STATUS, report_id, target="SUPERSEDED")

    assert _row(migrated, report_id)[0] == "SUPERSEDED"


def test_signed_report_can_never_be_superseded(migrated):
    _, report_id = _setup(migrated, "SIGNED")

    with pytest.raises(DBAPIError):
        _run(migrated, SET_STATUS, report_id, target="SUPERSEDED")

    assert _row(migrated, report_id)[0] == "SIGNED"


def test_superseded_report_cannot_be_reopened(migrated):
    _, report_id = _setup(migrated, "SUPERSEDED")

    for target in ("FROZEN", "SIGNED"):
        with pytest.raises(DBAPIError):
            _run(migrated, SET_STATUS, report_id, target=target)

    assert _row(migrated, report_id)[0] == "SUPERSEDED"


def test_draft_with_hash_or_frozen_without_hash_violates_check_constraint(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        contract = _seed_contract(conn)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_report(conn, contract, "DRAFT", report_hash=HASH)
    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_report(conn, contract, "FROZEN", no_hash=True)


def test_only_one_active_report_per_contract_and_kind(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        contract = _seed_contract(conn)
        first = _insert_report(conn, contract, "FROZEN")

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_report(conn, contract, "DRAFT", revision=2, supersedes=first)

    with migrated.app_context(), db.engine.begin() as conn:
        _insert_report(conn, contract, "DRAFT", kind="return")  # autre type : autorise
        conn.execute(text("UPDATE inspection_reports SET status = 'SUPERSEDED' WHERE kind = 'checkout'"))
        # ancien SUPERSEDED : la revision suivante est autorisee
        _insert_report(conn, contract, "DRAFT", revision=2, supersedes=first)


OUT_OF_RANGE_UPDATES = [
    "UPDATE inspection_reports SET odometer_km = -1 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET odometer_km = 2000001 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET fuel_eighths = 9 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET fuel_eighths = -1 WHERE id = CAST(:id AS uuid)",
    "UPDATE inspection_reports SET claimed_retention_cents = -1 WHERE id = CAST(:id AS uuid)",
]


@pytest.mark.parametrize("statement", OUT_OF_RANGE_UPDATES)
def test_draft_report_check_constraints_reject_out_of_range_values(migrated, statement):
    _, report_id = _setup(migrated, "DRAFT")
    before = _row(migrated, report_id)

    with pytest.raises(DBAPIError):
        _run(migrated, statement, report_id)

    assert _row(migrated, report_id) == before
