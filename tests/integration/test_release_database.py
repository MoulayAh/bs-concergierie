"""F4 : garanties PostgreSQL (migration 0005) sur un schema reellement migre.

Le trigger de chainage, l'immuabilite des depots liberes et l'ajout seul de ``settlement_receipts`` n'existent
pas avec ``create_all`` : on utilise ``migrated_app``. Interfaces supposees : tests/fixtures/release.py
(colonnes ``escrow_events.seq/prev_hash/event_hash``, ``deposits.settled_at/settlement_ref``, table
``settlement_receipts`` du plan). Les contraintes sont testees avec des lignes qui respectent TOUTES les
autres contraintes, pour que l'echec prouve la regle visee.
"""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from flask import Flask
from flask_migrate import upgrade
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.extensions import db
from tests.fixtures.release import EVENT_FIELDS, EVENT_TS_FORMAT, GENESIS, chain_hash

MIGRATIONS_DIR = str(Path(__file__).resolve().parents[2] / "migrations")
REVISION_F3 = "0004_inspection_reports_f3"
HASH = "a" * 64
AMOUNT = 1_000


@pytest.fixture
def migrated(migrated_app: Flask) -> Flask:
    with migrated_app.app_context():
        upgrade(directory=MIGRATIONS_DIR)
    return migrated_app


# ------------------------------------------------------------------ amorces SQL


def _seed_contract(conn) -> tuple[str, str]:
    """Utilisateurs + contrat ; renvoie (contrat, loueur)."""
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
            "CAST(:c AS uuid), 'Audi', 'AB-123-CD', '2026-11-01', '2026-11-05', 1000, 'EUR')"
        ),
        {"id": contract, "o": owner, "c": client},
    )
    return contract, owner


def _insert_event(conn, contract: str, actor: str, seq: int, prev: str, digest: str | None = None) -> str:
    digest = digest or hashlib.sha256(f"{contract}:{seq}:{prev}".encode()).hexdigest()
    conn.execute(
        text(
            "INSERT INTO escrow_events (id, contract_id, event, actor_id, from_status, to_status, "
            "seq, prev_hash, event_hash) VALUES (CAST(:id AS uuid), CAST(:c AS uuid), 'noop', "
            "CAST(:a AS uuid), CAST('DRAFT' AS contract_status), CAST('DRAFT' AS contract_status), "
            ":seq, :prev, :hash)"
        ),
        {"id": str(uuid.uuid4()), "c": contract, "a": actor, "seq": seq, "prev": prev, "hash": digest},
    )
    return digest


def _insert_deposit(
    conn,
    contract: str,
    status: str,
    held: int,
    refunded: int,
    released: int,
    retained: int,
    ref: str | None = None,
) -> str:
    deposit = str(uuid.uuid4())
    terminal = status != "HELD"
    conn.execute(
        text(
            "INSERT INTO deposits (id, contract_id, amount_cents, currency, status, held_cents, "
            "refunded_cents, released_cents, retained_cents, provider, provider_ref, settled_at, "
            "settlement_ref) VALUES (CAST(:id AS uuid), CAST(:c AS uuid), :amount, 'EUR', "
            "CAST(:status AS deposit_status), :held, :refunded, :released, :retained, 'sim', :pref, "
            "CASE WHEN :terminal THEN now() END, CASE WHEN :terminal THEN :sref END)"
        ),
        {
            "id": deposit,
            "c": contract,
            "amount": AMOUNT,
            "status": status,
            "held": held,
            "refunded": refunded,
            "released": released,
            "retained": retained,
            "pref": ref or f"sim_{uuid.uuid4().hex[:20]}",
            "terminal": terminal,
            "sref": f"sim_set_{uuid.uuid4().hex[:20]}",
        },
    )
    return deposit


def _insert_return_report(conn, contract: str) -> str:
    report = str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO inspection_reports (id, contract_id, kind, revision, status, odometer_km, "
            "fuel_eighths, damages, claimed_retention_cents, notes, canonical_json, report_hash, frozen_at, "
            "version) VALUES (CAST(:id AS uuid), CAST(:c AS uuid), CAST('return' AS report_kind), 1, "
            "CAST('SIGNED' AS report_status), 100, 8, CAST('[]' AS jsonb), 0, '', :canon, :hash, now(), 1)"
        ),
        {"id": report, "c": contract, "canon": b"{}", "hash": HASH},
    )
    return report


def _insert_receipt(conn, contract: str, deposit: str, report: str, **over) -> str:
    receipt = str(uuid.uuid4())
    params = {
        "id": receipt,
        "c": contract,
        "d": deposit,
        "r": report,
        "canon": b"{}",
        "hash": hashlib.sha256(receipt.encode()).hexdigest(),
        "sig": b"\x01" * 64,
        "fp": "b" * 64,
        **over,
    }
    conn.execute(
        text(
            "INSERT INTO settlement_receipts (id, contract_id, deposit_id, return_report_id, canonical_json, "
            "receipt_hash, server_signature, server_key_fingerprint, created_at) VALUES "
            "(CAST(:id AS uuid), CAST(:c AS uuid), CAST(:d AS uuid), CAST(:r AS uuid), :canon, :hash, "
            ":sig, :fp, now())"
        ),
        params,
    )
    return receipt


def _scalar(app: Flask, sql: str, **params):
    with app.app_context(), db.engine.connect() as conn:
        return conn.execute(text(sql), params).scalar_one()


def _row(app: Flask, sql: str, **params) -> tuple:
    with app.app_context(), db.engine.connect() as conn:
        return tuple(conn.execute(text(sql), params).one())


def _run(app: Flask, sql: str, **params) -> None:
    with app.app_context(), db.engine.begin() as conn:
        conn.execute(text(sql), params)


# ------------------------------------------------------------------ chaine d'evenements


def test_chain_accepts_a_linked_sequence_per_contract(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        c1, a1 = _seed_contract(conn)
        c2, a2 = _seed_contract(conn)
        first = _insert_event(conn, c1, a1, 1, GENESIS)
        _insert_event(conn, c1, a1, 2, first)
        _insert_event(conn, c2, a2, 1, GENESIS)  # autre contrat : chaine independante

    assert _scalar(migrated, "SELECT count(*) FROM escrow_events") == 3


def _chain_case(app: Flask) -> tuple[str, str, str]:
    with app.app_context(), db.engine.begin() as conn:
        contract, actor = _seed_contract(conn)
        first = _insert_event(conn, contract, actor, 1, GENESIS)
    return contract, actor, first


@pytest.mark.parametrize(
    "case",
    ["seq_gap", "wrong_prev", "duplicate_seq", "seq_backwards", "zero_seq", "negative_seq", "prev_genesis"],
)
def test_chain_broken_insert_rejected_by_database(migrated, case):
    contract, actor, first = _chain_case(migrated)
    with migrated.app_context(), db.engine.begin() as conn:
        second = _insert_event(conn, contract, actor, 2, first)
    attempts = {
        "seq_gap": (4, second),
        "wrong_prev": (3, "c" * 64),
        "duplicate_seq": (2, first),
        "seq_backwards": (1, GENESIS),
        "zero_seq": (0, GENESIS),
        "negative_seq": (-1, GENESIS),
        "prev_genesis": (3, GENESIS),
    }
    seq, prev = attempts[case]

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_event(conn, contract, actor, seq, prev)

    assert _scalar(migrated, "SELECT count(*) FROM escrow_events") == 2
    with migrated.app_context(), db.engine.begin() as conn:
        _insert_event(conn, contract, actor, 3, second)  # la chaine reste utilisable
    assert _scalar(migrated, "SELECT count(*) FROM escrow_events") == 3


def test_chain_first_event_must_have_seq_one_and_genesis_prev(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        contract, actor = _seed_contract(conn)

    for seq, prev in ((2, GENESIS), (1, "d" * 64), (2, "d" * 64)):
        with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
            _insert_event(conn, contract, actor, seq, prev)

    assert _scalar(migrated, "SELECT count(*) FROM escrow_events") == 0


def test_chain_rejects_duplicate_event_hash_across_contracts(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        c1, a1 = _seed_contract(conn)
        c2, a2 = _seed_contract(conn)
        _insert_event(conn, c1, a1, 1, GENESIS, digest="e" * 64)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_event(conn, c2, a2, 1, GENESIS, digest="e" * 64)


def test_chain_rejects_malformed_hash_columns(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        contract, actor = _seed_contract(conn)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_event(conn, contract, actor, 1, "trop-court")


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE escrow_events SET prev_hash = repeat('9', 64)",
        "UPDATE escrow_events SET event_hash = repeat('9', 64)",
        "UPDATE escrow_events SET seq = 99",
        "DELETE FROM escrow_events",
    ],
)
def test_chain_columns_are_append_only(migrated, statement):
    _chain_case(migrated)
    before = _row(migrated, "SELECT seq, prev_hash, event_hash FROM escrow_events")

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        conn.execute(text(statement))

    assert _row(migrated, "SELECT seq, prev_hash, event_hash FROM escrow_events") == before


def test_migration_backfills_existing_chain(migrated_app):
    contracts = []
    base = datetime(2026, 10, 1, 8, 0, 0, tzinfo=UTC)
    with migrated_app.app_context():
        upgrade(directory=MIGRATIONS_DIR, revision=REVISION_F3)
    with migrated_app.app_context(), db.engine.begin() as conn:
        for index, count in enumerate((4, 2, 1)):
            contract, actor = _seed_contract(conn)
            contracts.append(contract)
            for n in range(count):
                # ex aequo sur created_at pour les 2e et 3e evenements du 1er contrat : l'ordre suit l'id
                moment = base + timedelta(minutes=index * 10 + (1 if n == 2 else n))
                conn.execute(
                    text(
                        "INSERT INTO escrow_events (id, contract_id, event, actor_id, from_status, "
                        "to_status, payload_hash, created_at) VALUES (CAST(:id AS uuid), "
                        "CAST(:c AS uuid), :event, CAST(:a AS uuid), CAST('DRAFT' AS contract_status), "
                        "CAST('DRAFT' AS contract_status), :ph, :at)"
                    ),
                    {
                        "id": f"00000000-0000-4000-8000-{index:04d}0000{n:04d}",
                        "c": contract,
                        "event": f"step_{n}",
                        "a": actor,
                        "ph": None if n == 0 else hashlib.sha256(str(n).encode()).hexdigest(),
                        "at": moment,
                    },
                )

    with migrated_app.app_context():
        upgrade(directory=MIGRATIONS_DIR)

    with migrated_app.app_context(), db.engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT contract_id::text AS contract_id, seq, event, actor_id::text AS actor_id, "
                    "from_status::text AS from_status, to_status::text AS to_status, "
                    "payload_hash, created_at, "
                    "prev_hash, event_hash FROM escrow_events ORDER BY contract_id, seq"
                )
            )
            .mappings()
            .all()
        )
    assert len(rows) == 7
    for contract, expected in zip(contracts, (4, 2, 1), strict=True):
        chain = [dict(r) for r in rows if r["contract_id"] == contract]
        assert [r["seq"] for r in chain] == list(range(1, expected + 1))
        assert [r["event"] for r in chain] == [f"step_{n}" for n in range(expected)]  # ordre (created_at, id)
        previous = GENESIS
        for event in chain:
            assert event["prev_hash"] == previous
            exported = {**event, "created_at": event["created_at"].astimezone(UTC).strftime(EVENT_TS_FORMAT)}
            assert event["event_hash"] == chain_hash(previous, {k: exported[k] for k in EVENT_FIELDS})
            previous = event["event_hash"]
        from app.domain.event_chain import verify_chain

        exports = [
            {**e, "created_at": e["created_at"].astimezone(UTC).strftime(EVENT_TS_FORMAT)} for e in chain
        ]
        assert verify_chain(exports) is None

    # le trigger est actif apres la migration, et la chaine continue depuis la tete recalculee
    contract = contracts[0]
    head = next(r for r in reversed(rows) if r["contract_id"] == contract)
    actor = head["actor_id"]
    with pytest.raises(DBAPIError), migrated_app.app_context(), db.engine.begin() as conn:
        _insert_event(conn, contract, actor, 6, head["event_hash"])
    with migrated_app.app_context(), db.engine.begin() as conn:
        _insert_event(conn, contract, actor, 5, head["event_hash"])
    with pytest.raises(DBAPIError), migrated_app.app_context(), db.engine.begin() as conn:
        conn.execute(text("DELETE FROM escrow_events"))


def test_migration_backfill_of_an_empty_journal_is_a_noop(migrated_app):
    with migrated_app.app_context():
        upgrade(directory=MIGRATIONS_DIR, revision=REVISION_F3)
        upgrade(directory=MIGRATIONS_DIR)

    assert _scalar(migrated_app, "SELECT count(*) FROM escrow_events") == 0


# ------------------------------------------------------------------ depot libere immuable


def _terminal_deposit(app: Flask, status: str) -> str:
    amounts = {
        "RELEASED": (0, 0, AMOUNT, 0),
        "SETTLED": (0, 0, AMOUNT - 100, 100),
        "REFUNDED": (0, AMOUNT, 0, 0),
    }[status]
    with app.app_context(), db.engine.begin() as conn:
        contract, _ = _seed_contract(conn)
        return _insert_deposit(conn, contract, status, *amounts)


DEPOSIT_COLUMNS = (
    "SELECT status::text, held_cents, refunded_cents, released_cents, retained_cents, provider, "
    "provider_ref, settlement_ref, settled_at, updated_at FROM deposits WHERE id = CAST(:id AS uuid)"
)

IMMUTABLE_UPDATES = [
    "UPDATE deposits SET provider = 'autre' WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET provider_ref = 'sim_modifie' WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET settlement_ref = 'sim_set_modifie' WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET settled_at = now() - interval '1 day' WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET updated_at = now() + interval '1 day' WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET currency = 'USD' WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET status = 'SETTLED', released_cents = 900, retained_cents = 100 "
    "WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET status = 'RELEASED', released_cents = 1000, retained_cents = 0 "
    "WHERE id = CAST(:id AS uuid)",
    "UPDATE deposits SET status = 'REFUNDED', refunded_cents = 1000, released_cents = 0, retained_cents = 0 "
    "WHERE id = CAST(:id AS uuid)",
    "DELETE FROM deposits WHERE id = CAST(:id AS uuid)",
]


@pytest.mark.parametrize("statement", IMMUTABLE_UPDATES)
@pytest.mark.parametrize("status", ["RELEASED", "SETTLED", "REFUNDED"])
def test_released_deposit_immutable_in_database(migrated, status, statement):
    deposit = _terminal_deposit(migrated, status)
    before = _row(migrated, DEPOSIT_COLUMNS, id=deposit)

    with pytest.raises(DBAPIError):
        _run(migrated, statement, id=deposit)

    assert _row(migrated, DEPOSIT_COLUMNS, id=deposit) == before


@pytest.mark.parametrize("status", ["RELEASED", "SETTLED", "REFUNDED"])
def test_terminal_deposit_rejects_a_no_op_update_too(migrated, status):
    deposit = _terminal_deposit(migrated, status)

    with pytest.raises(DBAPIError):
        _run(migrated, "UPDATE deposits SET provider = provider WHERE id = CAST(:id AS uuid)", id=deposit)


def test_held_deposit_can_still_be_settled_once(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        contract, _ = _seed_contract(conn)
        deposit = _insert_deposit(conn, contract, "HELD", AMOUNT, 0, 0, 0)

    _run(migrated, "UPDATE deposits SET updated_at = now() WHERE id = CAST(:id AS uuid)", id=deposit)
    _run(
        migrated,
        "UPDATE deposits SET status = CAST('SETTLED' AS deposit_status), held_cents = 0, "
        "released_cents = 900, retained_cents = 100, settled_at = now(), settlement_ref = 'sim_set_ok' "
        "WHERE id = CAST(:id AS uuid)",
        id=deposit,
    )

    assert _row(migrated, DEPOSIT_COLUMNS, id=deposit)[:5] == ("SETTLED", 0, 0, 900, 100)
    with pytest.raises(DBAPIError):
        _run(
            migrated,
            "UPDATE deposits SET retained_cents = 200, released_cents = 800 WHERE id = CAST(:id AS uuid)",
            id=deposit,
        )


@pytest.mark.parametrize(
    ("status", "amounts"),
    [
        ("HELD", (AMOUNT - 10, 0, 10, 0)),  # HELD avec du libere
        ("HELD", (AMOUNT - 10, 0, 0, 10)),  # HELD avec du retenu
        ("RELEASED", (10, 0, AMOUNT - 10, 0)),  # RELEASED avec du bloque
        ("SETTLED", (10, 0, AMOUNT - 20, 10)),  # SETTLED avec du bloque
        ("RELEASED", (0, 0, AMOUNT - 10, 10)),  # RELEASED avec retenue
        ("SETTLED", (0, 0, AMOUNT, 0)),  # SETTLED sans retenue
    ],
    ids=["held-released", "held-retained", "released-held", "settled-held", "released-kept", "settled-zero"],
)
def test_deposit_status_amount_check_constraints(migrated, status, amounts):
    with migrated.app_context(), db.engine.begin() as conn:
        contract, _ = _seed_contract(conn)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_deposit(conn, contract, status, *amounts)

    assert _scalar(migrated, "SELECT count(*) FROM deposits") == 0


def test_settlement_ref_is_unique_across_deposits(migrated):
    with migrated.app_context(), db.engine.begin() as conn:
        c1, _ = _seed_contract(conn)
        c2, _ = _seed_contract(conn)
        _insert_deposit(conn, c1, "RELEASED", 0, 0, AMOUNT, 0)
        second = _insert_deposit(conn, c2, "HELD", AMOUNT, 0, 0, 0)
    ref = _scalar(migrated, "SELECT settlement_ref FROM deposits WHERE settlement_ref IS NOT NULL")

    with pytest.raises(DBAPIError):
        _run(
            migrated,
            "UPDATE deposits SET status = CAST('RELEASED' AS deposit_status), held_cents = 0, "
            "released_cents = 1000, settled_at = now(), settlement_ref = :ref WHERE id = CAST(:id AS uuid)",
            id=second,
            ref=ref,
        )


# ------------------------------------------------------------------ quittances en ajout seul


def _receipt_case(app: Flask) -> tuple[str, str, str, str]:
    with app.app_context(), db.engine.begin() as conn:
        contract, _ = _seed_contract(conn)
        deposit = _insert_deposit(conn, contract, "RELEASED", 0, 0, AMOUNT, 0)
        report = _insert_return_report(conn, contract)
        receipt = _insert_receipt(conn, contract, deposit, report)
    return contract, deposit, report, receipt


RECEIPT_COLUMNS = (
    "SELECT canonical_json, receipt_hash, server_signature, server_key_fingerprint FROM settlement_receipts "
    "WHERE id = CAST(:id AS uuid)"
)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE settlement_receipts SET canonical_json = convert_to('forged', 'UTF8')",
        "UPDATE settlement_receipts SET receipt_hash = repeat('f', 64)",
        "UPDATE settlement_receipts SET server_signature = decode(repeat('02', 64), 'hex')",
        "UPDATE settlement_receipts SET server_key_fingerprint = repeat('f', 64)",
        "UPDATE settlement_receipts SET created_at = now() + interval '1 day'",
        "DELETE FROM settlement_receipts",
        "TRUNCATE settlement_receipts",
    ],
)
def test_settlement_receipt_is_append_only_in_database(migrated, statement):
    _, _, _, receipt = _receipt_case(migrated)
    before = _row(migrated, RECEIPT_COLUMNS, id=receipt)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        conn.execute(text(statement))

    assert _row(migrated, RECEIPT_COLUMNS, id=receipt) == before


def test_only_one_receipt_per_contract_and_per_deposit(migrated):
    contract, deposit, report, _ = _receipt_case(migrated)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_receipt(conn, contract, deposit, report)

    assert _scalar(migrated, "SELECT count(*) FROM settlement_receipts") == 1


def test_receipt_hash_is_unique(migrated):
    _, _, _, receipt = _receipt_case(migrated)
    existing = _scalar(migrated, "SELECT receipt_hash FROM settlement_receipts")
    with migrated.app_context(), db.engine.begin() as conn:
        contract, _ = _seed_contract(conn)
        deposit = _insert_deposit(conn, contract, "RELEASED", 0, 0, AMOUNT, 0)
        report = _insert_return_report(conn, contract)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_receipt(conn, contract, deposit, report, hash=existing)

    assert receipt


@pytest.mark.parametrize("length", [0, 1, 63, 65, 128])
def test_receipt_server_signature_must_be_64_bytes(migrated, length):
    with migrated.app_context(), db.engine.begin() as conn:
        contract, _ = _seed_contract(conn)
        deposit = _insert_deposit(conn, contract, "RELEASED", 0, 0, AMOUNT, 0)
        report = _insert_return_report(conn, contract)

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_receipt(conn, contract, deposit, report, sig=b"\x01" * length)

    assert _scalar(migrated, "SELECT count(*) FROM settlement_receipts") == 0


@pytest.mark.parametrize("missing", ["contract", "deposit", "report"])
def test_receipt_requires_existing_contract_deposit_and_report(migrated, missing):
    with migrated.app_context(), db.engine.begin() as conn:
        contract, _ = _seed_contract(conn)
        deposit = _insert_deposit(conn, contract, "RELEASED", 0, 0, AMOUNT, 0)
        report = _insert_return_report(conn, contract)
    ids = {"contract": contract, "deposit": deposit, "report": report, missing: str(uuid.uuid4())}

    with pytest.raises(DBAPIError), migrated.app_context(), db.engine.begin() as conn:
        _insert_receipt(conn, ids["contract"], ids["deposit"], ids["report"])

    assert _scalar(migrated, "SELECT count(*) FROM settlement_receipts") == 0
