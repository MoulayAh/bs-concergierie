"""F2 : deposits, enum deposit_status, colonnes d'annulation et started_at sur contracts

Revision ID: 0003_deposits_f2
Revises: 0002_escrow_event_payload
Create Date: 2026-10-08

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_deposits_f2"
down_revision = "0002_escrow_event_payload"
branch_labels = None
depends_on = None

DEPOSIT_STATUSES = ("HELD", "REFUNDED", "RELEASED", "SETTLED")


def upgrade() -> None:
    op.add_column(
        "contracts", sa.Column("owner_cancel_approved_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "contracts", sa.Column("client_cancel_approved_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("contracts", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))

    postgresql.ENUM(*DEPOSIT_STATUSES, name="deposit_status").create(op.get_bind(), checkfirst=False)

    op.create_table(
        "deposits",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("contract_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("amount_cents", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.CHAR(3), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(*DEPOSIT_STATUSES, name="deposit_status", create_type=False),
            server_default=sa.text("'HELD'"),
            nullable=False,
        ),
        sa.Column("held_cents", sa.BigInteger(), nullable=False),
        sa.Column("refunded_cents", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("released_cents", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("retained_cents", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("provider_ref", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint("amount_cents BETWEEN 1 AND 50000000", name=op.f("ck_deposits_amount_bounds")),
        sa.CheckConstraint(
            "currency IN ('EUR','CHF','GBP','USD')", name=op.f("ck_deposits_currency_whitelist")
        ),
        sa.CheckConstraint("held_cents >= 0", name=op.f("ck_deposits_held_non_negative")),
        sa.CheckConstraint("refunded_cents >= 0", name=op.f("ck_deposits_refunded_non_negative")),
        sa.CheckConstraint("released_cents >= 0", name=op.f("ck_deposits_released_non_negative")),
        sa.CheckConstraint("retained_cents >= 0", name=op.f("ck_deposits_retained_non_negative")),
        sa.CheckConstraint(
            "held_cents + refunded_cents + released_cents + retained_cents = amount_cents",
            name=op.f("ck_deposits_ledger_balanced"),
        ),
        sa.ForeignKeyConstraint(
            ["contract_id"], ["contracts.id"], name=op.f("fk_deposits_contract_id_contracts")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_deposits")),
        sa.UniqueConstraint("contract_id", name=op.f("uq_deposits_contract_id")),
        sa.UniqueConstraint("provider_ref", name=op.f("uq_deposits_provider_ref")),
    )


def downgrade() -> None:
    op.drop_table("deposits")
    op.execute("DROP TYPE deposit_status")
    op.drop_column("contracts", "started_at")
    op.drop_column("contracts", "client_cancel_approved_at")
    op.drop_column("contracts", "owner_cancel_approved_at")
