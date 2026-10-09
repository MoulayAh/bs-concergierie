"""F4 : liberation de la caution, chaine de hachage des evenements, quittances

- deposits : settled_at, settlement_ref (unique), 4 CHECK de coherence, trigger d'immuabilite
  (un depot dont l'ancien statut est RELEASED, SETTLED ou REFUNDED ne se modifie ni ne se supprime).
- escrow_events : seq, prev_hash, event_hash + trigger BEFORE INSERT de chainage ; les evenements
  existants (F1-F3) sont recalcules contrat par contrat, ordre (created_at, id).
- settlement_receipts : table en ajout seul.

FORMAT CANONIQUE DE LA CHAINE (identique a app/domain/event_chain.py) :

    body = {
        "contract_id": str(UUID) minuscule avec tirets,
        "seq": int (>= 1),
        "event": str,
        "actor_id": str(UUID) minuscule avec tirets,
        "from_status": str (valeur de l'enum, ex. "FUNDED") ou null,
        "to_status": str (valeur de l'enum),
        "payload_hash": str ou null,
        "created_at": instant converti en UTC, au format "%Y-%m-%dT%H:%M:%S.%fZ"
                      (toujours 6 chiffres de microsecondes, suffixe Z),
    }
    canonique   = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    event_hash  = sha256((prev_hash + ":" + canonique).encode("utf-8")).hexdigest()   # 64 hex minuscules
    prev_hash   = event_hash de l'evenement precedent du contrat, ou "0" * 64 si seq = 1

Revision ID: 0005_release_f4
Revises: 0004_inspection_reports_f3
Create Date: 2026-10-09

"""
import hashlib
import json
from collections.abc import Mapping
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_release_f4"
down_revision = "0004_inspection_reports_f3"
branch_labels = None
depends_on = None

GENESIS_HASH = "0" * 64

_EVENT_FIELDS = """
    escrow_events.id::text AS id,
    escrow_events.contract_id::text AS contract_id,
    escrow_events.event AS event,
    escrow_events.actor_id::text AS actor_id,
    escrow_events.from_status::text AS from_status,
    escrow_events.to_status::text AS to_status,
    escrow_events.payload_hash AS payload_hash,
    to_char(escrow_events.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
"""


def _event_hash(prev_hash: str, seq: int, row: Mapping[str, Any]) -> str:
    body = {
        "contract_id": row["contract_id"],
        "seq": seq,
        "event": row["event"],
        "actor_id": row["actor_id"],
        "from_status": row["from_status"],
        "to_status": row["to_status"],
        "payload_hash": row["payload_hash"],
        "created_at": row["created_at"],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + ":" + canonical).encode("utf-8")).hexdigest()


def _backfill_chain(bind: sa.engine.Connection) -> None:
    rows = bind.execute(
        sa.text(
            f"SELECT {_EVENT_FIELDS} FROM escrow_events "  # noqa: S608 - constante locale
            "ORDER BY escrow_events.contract_id, escrow_events.created_at, escrow_events.id"
        )
    ).mappings()
    updates: list[dict[str, Any]] = []
    current_contract: str | None = None
    seq = 0
    prev_hash = GENESIS_HASH
    for row in rows:
        if row["contract_id"] != current_contract:
            current_contract = row["contract_id"]
            seq = 0
            prev_hash = GENESIS_HASH
        seq += 1
        event_hash = _event_hash(prev_hash, seq, row)
        updates.append({"id": row["id"], "seq": seq, "prev_hash": prev_hash, "event_hash": event_hash})
        prev_hash = event_hash
    if updates:
        bind.execute(
            sa.text(
                "UPDATE escrow_events SET seq = :seq, prev_hash = :prev_hash, event_hash = :event_hash "
                "WHERE id = CAST(:id AS uuid)"
            ),
            updates,
        )


def _verify_chain(bind: sa.engine.Connection) -> None:
    rows = bind.execute(
        sa.text(
            f"SELECT {_EVENT_FIELDS}, escrow_events.seq AS seq, "  # noqa: S608 - constante locale
            "escrow_events.prev_hash AS prev_hash, escrow_events.event_hash AS event_hash "
            "FROM escrow_events ORDER BY escrow_events.contract_id, escrow_events.seq"
        )
    ).mappings()
    current_contract: str | None = None
    expected_seq = 0
    expected_prev = GENESIS_HASH
    for row in rows:
        if row["contract_id"] != current_contract:
            current_contract = row["contract_id"]
            expected_seq = 0
            expected_prev = GENESIS_HASH
        expected_seq += 1
        if (
            row["seq"] != expected_seq
            or row["prev_hash"] != expected_prev
            or row["event_hash"] != _event_hash(expected_prev, expected_seq, row)
        ):
            raise RuntimeError(f"chaine d'evenements invalide apres backfill (evenement {row['id']})")
        expected_prev = row["event_hash"]


def upgrade() -> None:
    bind = op.get_bind()

    # --- deposits ---------------------------------------------------------------------------
    op.add_column("deposits", sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("deposits", sa.Column("settlement_ref", sa.String(64), nullable=True))
    op.create_unique_constraint(op.f("uq_deposits_settlement_ref"), "deposits", ["settlement_ref"])
    op.create_check_constraint(
        op.f("ck_deposits_held_has_no_settlement"),
        "deposits",
        "status <> 'HELD' OR (released_cents = 0 AND retained_cents = 0)",
    )
    op.create_check_constraint(
        op.f("ck_deposits_final_has_nothing_held"),
        "deposits",
        "status NOT IN ('RELEASED','SETTLED') OR held_cents = 0",
    )
    op.create_check_constraint(
        op.f("ck_deposits_released_has_no_retention"),
        "deposits",
        "status <> 'RELEASED' OR retained_cents = 0",
    )
    op.create_check_constraint(
        op.f("ck_deposits_settled_has_retention"),
        "deposits",
        "status <> 'SETTLED' OR retained_cents > 0",
    )
    op.execute(
        """
        CREATE FUNCTION deposits_final_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.status IN ('RELEASED', 'SETTLED', 'REFUNDED') THEN
                RAISE EXCEPTION 'deposits: depot % definitif, % interdit', OLD.status, TG_OP
                    USING ERRCODE = 'restrict_violation';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_deposits_final_guard
        BEFORE UPDATE OR DELETE ON deposits
        FOR EACH ROW EXECUTE FUNCTION deposits_final_guard()
        """
    )

    # --- escrow_events : chaine ---------------------------------------------------------------
    op.add_column("escrow_events", sa.Column("seq", sa.Integer(), nullable=True))
    op.add_column("escrow_events", sa.Column("prev_hash", sa.CHAR(64), nullable=True))
    op.add_column("escrow_events", sa.Column("event_hash", sa.CHAR(64), nullable=True))

    op.execute("ALTER TABLE escrow_events DISABLE TRIGGER trg_escrow_events_no_update_delete")
    _backfill_chain(bind)
    op.execute("ALTER TABLE escrow_events ENABLE TRIGGER trg_escrow_events_no_update_delete")

    op.alter_column("escrow_events", "seq", nullable=False)
    op.alter_column("escrow_events", "prev_hash", nullable=False)
    op.alter_column("escrow_events", "event_hash", nullable=False)
    op.create_check_constraint(op.f("ck_escrow_events_seq_positive"), "escrow_events", "seq >= 1")
    op.create_unique_constraint(
        op.f("uq_escrow_events_contract_id_seq"), "escrow_events", ["contract_id", "seq"]
    )
    op.create_unique_constraint(op.f("uq_escrow_events_event_hash"), "escrow_events", ["event_hash"])
    _verify_chain(bind)

    op.execute(
        """
        CREATE FUNCTION escrow_events_chain_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
            last_seq integer;
            last_hash text;
        BEGIN
            SELECT seq, event_hash INTO last_seq, last_hash
            FROM escrow_events
            WHERE contract_id = NEW.contract_id
            ORDER BY seq DESC
            LIMIT 1;

            IF NOT FOUND THEN
                IF NEW.seq IS DISTINCT FROM 1 OR NEW.prev_hash IS DISTINCT FROM repeat('0', 64) THEN
                    RAISE EXCEPTION 'escrow_events: premier evenement du contrat attendu avec seq=1 et prev_hash nul'
                        USING ERRCODE = 'restrict_violation';
                END IF;
            ELSIF NEW.seq IS DISTINCT FROM last_seq + 1 OR NEW.prev_hash IS DISTINCT FROM last_hash THEN
                RAISE EXCEPTION 'escrow_events: chaine rompue (seq attendu %)', last_seq + 1
                    USING ERRCODE = 'restrict_violation';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_escrow_events_chain_guard
        BEFORE INSERT ON escrow_events
        FOR EACH ROW EXECUTE FUNCTION escrow_events_chain_guard()
        """
    )

    # --- settlement_receipts --------------------------------------------------------------------
    op.create_table(
        "settlement_receipts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("contract_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("deposit_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("return_report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_json", postgresql.BYTEA(), nullable=False),
        sa.Column("receipt_hash", sa.CHAR(64), nullable=False),
        sa.Column("server_signature", postgresql.BYTEA(), nullable=False),
        sa.Column("server_key_fingerprint", sa.CHAR(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(
            "length(server_signature) = 64", name=op.f("ck_settlement_receipts_signature_length")
        ),
        sa.ForeignKeyConstraint(
            ["contract_id"], ["contracts.id"], name=op.f("fk_settlement_receipts_contract_id_contracts")
        ),
        sa.ForeignKeyConstraint(
            ["deposit_id"], ["deposits.id"], name=op.f("fk_settlement_receipts_deposit_id_deposits")
        ),
        sa.ForeignKeyConstraint(
            ["return_report_id"],
            ["inspection_reports.id"],
            name=op.f("fk_settlement_receipts_return_report_id_inspection_reports"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_settlement_receipts")),
        sa.UniqueConstraint("contract_id", name=op.f("uq_settlement_receipts_contract_id")),
        sa.UniqueConstraint("deposit_id", name=op.f("uq_settlement_receipts_deposit_id")),
        sa.UniqueConstraint("receipt_hash", name=op.f("uq_settlement_receipts_receipt_hash")),
    )
    op.execute(
        """
        CREATE FUNCTION settlement_receipts_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'settlement_receipts est en ajout seul (% interdit)', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_settlement_receipts_no_update_delete
        BEFORE UPDATE OR DELETE ON settlement_receipts
        FOR EACH ROW EXECUTE FUNCTION settlement_receipts_append_only()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_settlement_receipts_no_truncate
        BEFORE TRUNCATE ON settlement_receipts
        FOR EACH STATEMENT EXECUTE FUNCTION settlement_receipts_append_only()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_settlement_receipts_no_truncate ON settlement_receipts")
    op.execute("DROP TRIGGER trg_settlement_receipts_no_update_delete ON settlement_receipts")
    op.drop_table("settlement_receipts")
    op.execute("DROP FUNCTION settlement_receipts_append_only()")

    op.execute("DROP TRIGGER trg_escrow_events_chain_guard ON escrow_events")
    op.execute("DROP FUNCTION escrow_events_chain_guard()")
    op.drop_constraint(op.f("uq_escrow_events_event_hash"), "escrow_events", type_="unique")
    op.drop_constraint(op.f("uq_escrow_events_contract_id_seq"), "escrow_events", type_="unique")
    op.drop_constraint(op.f("ck_escrow_events_seq_positive"), "escrow_events", type_="check")
    op.drop_column("escrow_events", "event_hash")
    op.drop_column("escrow_events", "prev_hash")
    op.drop_column("escrow_events", "seq")

    op.execute("DROP TRIGGER trg_deposits_final_guard ON deposits")
    op.execute("DROP FUNCTION deposits_final_guard()")
    op.drop_constraint(op.f("ck_deposits_settled_has_retention"), "deposits", type_="check")
    op.drop_constraint(op.f("ck_deposits_released_has_no_retention"), "deposits", type_="check")
    op.drop_constraint(op.f("ck_deposits_final_has_nothing_held"), "deposits", type_="check")
    op.drop_constraint(op.f("ck_deposits_held_has_no_settlement"), "deposits", type_="check")
    op.drop_constraint(op.f("uq_deposits_settlement_ref"), "deposits", type_="unique")
    op.drop_column("deposits", "settlement_ref")
    op.drop_column("deposits", "settled_at")
