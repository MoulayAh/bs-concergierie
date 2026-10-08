"""F1 : schema initial (users, contracts, escrow_events, idempotency_keys)

Revision ID: 0001_initial_f1
Revises:
Create Date: 2026-10-08

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial_f1"
down_revision = None
branch_labels = None
depends_on = None

CONTRACT_STATUSES = (
    "DRAFT",
    "AWAITING_DEPOSIT",
    "FUNDED",
    "ACTIVE",
    "INSPECTION_PENDING",
    "DISPUTED",
    "CANCELLED",
    "REFUNDED",
    "RELEASED",
    "SETTLED",
)
USER_ROLES = ("client", "owner", "admin")


def _contract_status() -> postgresql.ENUM:
    return postgresql.ENUM(*CONTRACT_STATUSES, name="contract_status", create_type=False)


def upgrade() -> None:
    contract_status = postgresql.ENUM(*CONTRACT_STATUSES, name="contract_status")
    user_role = postgresql.ENUM(*USER_ROLES, name="user_role")
    contract_status.create(op.get_bind(), checkfirst=False)
    user_role.create(op.get_bind(), checkfirst=False)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column(
            "role", postgresql.ENUM(*USER_ROLES, name="user_role", create_type=False), nullable=False
        ),
        sa.Column("api_token_hash", sa.String(128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.UniqueConstraint("api_token_hash", name=op.f("uq_users_api_token_hash")),
    )

    op.create_table(
        "contracts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vehicle_label", sa.String(120), nullable=False),
        sa.Column("vehicle_plate", sa.String(16), nullable=False),
        sa.Column("start_date", sa.Date(), nullable=False),
        sa.Column("end_date", sa.Date(), nullable=False),
        sa.Column("deposit_cents", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.CHAR(3), nullable=False),
        sa.Column(
            "status", _contract_status(), server_default=sa.text("'DRAFT'"), nullable=False
        ),
        sa.Column("owner_signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("client_signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint("owner_id <> client_id", name=op.f("ck_contracts_owner_ne_client")),
        sa.CheckConstraint("end_date > start_date", name=op.f("ck_contracts_end_after_start")),
        sa.CheckConstraint(
            "deposit_cents BETWEEN 1 AND 50000000", name=op.f("ck_contracts_deposit_bounds")
        ),
        sa.CheckConstraint(
            "currency IN ('EUR','CHF','GBP','USD')", name=op.f("ck_contracts_currency_whitelist")
        ),
        sa.CheckConstraint(
            "length(btrim(vehicle_label)) > 0", name=op.f("ck_contracts_vehicle_label_not_blank")
        ),
        sa.CheckConstraint(
            "length(btrim(vehicle_plate)) > 0", name=op.f("ck_contracts_vehicle_plate_not_blank")
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_contracts_version_positive")),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], name=op.f("fk_contracts_owner_id_users")),
        sa.ForeignKeyConstraint(
            ["client_id"], ["users.id"], name=op.f("fk_contracts_client_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_contracts")),
    )
    op.create_index(op.f("ix_contracts_owner_id"), "contracts", ["owner_id"])
    op.create_index(op.f("ix_contracts_client_id"), "contracts", ["client_id"])

    op.create_table(
        "escrow_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("contract_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event", sa.String(40), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("from_status", _contract_status(), nullable=True),
        sa.Column("to_status", _contract_status(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["contract_id"], ["contracts.id"], name=op.f("fk_escrow_events_contract_id_contracts")
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name=op.f("fk_escrow_events_actor_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_escrow_events")),
    )
    op.create_index(
        "ix_escrow_events_contract_id_created_at", "escrow_events", ["contract_id", "created_at"]
    )

    # Journal en ajout seul : aucun UPDATE / DELETE / TRUNCATE, meme pour le proprietaire.
    op.execute(
        """
        CREATE FUNCTION escrow_events_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'escrow_events est en ajout seul (% interdit)', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_escrow_events_no_update_delete
        BEFORE UPDATE OR DELETE ON escrow_events
        FOR EACH ROW EXECUTE FUNCTION escrow_events_append_only()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_escrow_events_no_truncate
        BEFORE TRUNCATE ON escrow_events
        FOR EACH STATEMENT EXECUTE FUNCTION escrow_events_append_only()
        """
    )

    op.create_table(
        "idempotency_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(255), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column("response_body", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_idempotency_keys_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_idempotency_keys")),
        sa.UniqueConstraint("key", "user_id", name="uq_idempotency_keys_key_user_id"),
    )


def downgrade() -> None:
    op.drop_table("idempotency_keys")
    op.execute("DROP TRIGGER trg_escrow_events_no_truncate ON escrow_events")
    op.execute("DROP TRIGGER trg_escrow_events_no_update_delete ON escrow_events")
    op.drop_index("ix_escrow_events_contract_id_created_at", table_name="escrow_events")
    op.drop_table("escrow_events")
    op.execute("DROP FUNCTION escrow_events_append_only()")
    op.drop_index(op.f("ix_contracts_client_id"), table_name="contracts")
    op.drop_index(op.f("ix_contracts_owner_id"), table_name="contracts")
    op.drop_table("contracts")
    op.drop_table("users")
    op.execute("DROP TYPE user_role")
    op.execute("DROP TYPE contract_status")
