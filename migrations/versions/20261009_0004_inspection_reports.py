"""F3 : user_keys, inspection_reports, report_files, report_signatures + trigger de gel

Revision ID: 0004_inspection_reports_f3
Revises: 0003_deposits_f2
Create Date: 2026-10-09

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_inspection_reports_f3"
down_revision = "0003_deposits_f2"
branch_labels = None
depends_on = None

REPORT_KINDS = ("checkout", "return")
REPORT_STATUSES = ("DRAFT", "FROZEN", "SIGNED", "SUPERSEDED")
REPORT_PARTIES = ("owner", "client")


def _ts_now() -> sa.Column:
    raise NotImplementedError  # pragma: no cover


def upgrade() -> None:
    bind = op.get_bind()
    postgresql.ENUM(*REPORT_KINDS, name="report_kind").create(bind, checkfirst=False)
    postgresql.ENUM(*REPORT_STATUSES, name="report_status").create(bind, checkfirst=False)
    postgresql.ENUM(*REPORT_PARTIES, name="report_party").create(bind, checkfirst=False)

    op.create_table(
        "user_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("public_key", postgresql.BYTEA(), nullable=False),
        sa.Column("fingerprint", sa.CHAR(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("length(public_key) = 32", name=op.f("ck_user_keys_public_key_length")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_user_keys_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_keys")),
        sa.UniqueConstraint("public_key", name=op.f("uq_user_keys_public_key")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_user_keys_fingerprint")),
    )
    op.create_index(
        "uq_user_keys_active_user_id",
        "user_keys",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    op.create_table(
        "inspection_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("contract_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "kind",
            postgresql.ENUM(*REPORT_KINDS, name="report_kind", create_type=False),
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(*REPORT_STATUSES, name="report_status", create_type=False),
            server_default=sa.text("'DRAFT'"),
            nullable=False,
        ),
        sa.Column("supersedes_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("odometer_km", sa.Integer(), nullable=True),
        sa.Column("fuel_eighths", sa.SmallInteger(), nullable=True),
        sa.Column(
            "damages", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False
        ),
        sa.Column("claimed_retention_cents", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("notes", sa.String(2000), server_default=sa.text("''"), nullable=False),
        sa.Column("canonical_json", postgresql.BYTEA(), nullable=True),
        sa.Column("report_hash", sa.CHAR(64), nullable=True),
        sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint("revision >= 1", name=op.f("ck_inspection_reports_revision_positive")),
        sa.CheckConstraint(
            "(revision = 1) = (supersedes_id IS NULL)",
            name=op.f("ck_inspection_reports_supersedes_iff_revised"),
        ),
        sa.CheckConstraint(
            "odometer_km BETWEEN 0 AND 2000000", name=op.f("ck_inspection_reports_odometer_bounds")
        ),
        sa.CheckConstraint(
            "fuel_eighths BETWEEN 0 AND 8", name=op.f("ck_inspection_reports_fuel_bounds")
        ),
        sa.CheckConstraint(
            "claimed_retention_cents >= 0", name=op.f("ck_inspection_reports_retention_non_negative")
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_inspection_reports_version_positive")),
        sa.CheckConstraint(
            "(status = 'DRAFT') = (report_hash IS NULL)",
            name=op.f("ck_inspection_reports_hash_iff_not_draft"),
        ),
        sa.CheckConstraint(
            "status = 'DRAFT' OR (canonical_json IS NOT NULL AND frozen_at IS NOT NULL"
            " AND odometer_km IS NOT NULL AND fuel_eighths IS NOT NULL)",
            name=op.f("ck_inspection_reports_frozen_content_complete"),
        ),
        sa.ForeignKeyConstraint(
            ["contract_id"], ["contracts.id"], name=op.f("fk_inspection_reports_contract_id_contracts")
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_id"],
            ["inspection_reports.id"],
            name=op.f("fk_inspection_reports_supersedes_id_inspection_reports"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inspection_reports")),
        sa.UniqueConstraint(
            "contract_id",
            "kind",
            "revision",
            name="uq_inspection_reports_contract_id_kind_revision",
        ),
    )
    op.create_index(
        "uq_inspection_reports_active_contract_id_kind",
        "inspection_reports",
        ["contract_id", "kind"],
        unique=True,
        postgresql_where=sa.text("status <> 'SUPERSEDED'"),
    )

    op.create_table(
        "report_files",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sha256", sa.CHAR(64), nullable=False),
        sa.Column("mime", sa.String(32), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("storage_name", sa.String(64), nullable=False),
        sa.Column("original_name", sa.String(255), nullable=False),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(
            "mime IN ('image/jpeg','image/png','application/pdf')",
            name=op.f("ck_report_files_mime_whitelist"),
        ),
        sa.CheckConstraint("size_bytes BETWEEN 1 AND 10485760", name=op.f("ck_report_files_size_bounds")),
        sa.ForeignKeyConstraint(
            ["report_id"], ["inspection_reports.id"], name=op.f("fk_report_files_report_id_inspection_reports")
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by"], ["users.id"], name=op.f("fk_report_files_uploaded_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_files")),
        sa.UniqueConstraint("report_id", "sha256", name="uq_report_files_report_id_sha256"),
    )

    op.create_table(
        "report_signatures",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "party",
            postgresql.ENUM(*REPORT_PARTIES, name="report_party", create_type=False),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_hash", sa.CHAR(64), nullable=False),
        sa.Column("signature", postgresql.BYTEA(), nullable=False),
        sa.Column(
            "signed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint("length(signature) = 64", name=op.f("ck_report_signatures_signature_length")),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["inspection_reports.id"],
            name=op.f("fk_report_signatures_report_id_inspection_reports"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_report_signatures_user_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["key_id"], ["user_keys.id"], name=op.f("fk_report_signatures_key_id_user_keys")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_signatures")),
        sa.UniqueConstraint("report_id", "party", name="uq_report_signatures_report_id_party"),
    )

    # Gel : un rapport non DRAFT est immuable ; seules FROZEN->SIGNED et FROZEN->SUPERSEDED passent.
    op.execute(
        """
        CREATE FUNCTION inspection_reports_freeze_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                IF OLD.status <> 'DRAFT' THEN
                    RAISE EXCEPTION 'inspection_reports: suppression interdite (statut %)', OLD.status
                        USING ERRCODE = 'restrict_violation';
                END IF;
                RETURN OLD;
            END IF;

            IF OLD.status = 'DRAFT' THEN
                IF NEW.status NOT IN ('DRAFT', 'FROZEN') THEN
                    RAISE EXCEPTION 'inspection_reports: transition % -> % interdite', OLD.status, NEW.status
                        USING ERRCODE = 'restrict_violation';
                END IF;
                RETURN NEW;
            END IF;

            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.contract_id IS DISTINCT FROM OLD.contract_id
               OR NEW.kind IS DISTINCT FROM OLD.kind
               OR NEW.revision IS DISTINCT FROM OLD.revision
               OR NEW.supersedes_id IS DISTINCT FROM OLD.supersedes_id
               OR NEW.odometer_km IS DISTINCT FROM OLD.odometer_km
               OR NEW.fuel_eighths IS DISTINCT FROM OLD.fuel_eighths
               OR NEW.damages IS DISTINCT FROM OLD.damages
               OR NEW.claimed_retention_cents IS DISTINCT FROM OLD.claimed_retention_cents
               OR NEW.notes IS DISTINCT FROM OLD.notes
               OR NEW.canonical_json IS DISTINCT FROM OLD.canonical_json
               OR NEW.report_hash IS DISTINCT FROM OLD.report_hash
               OR NEW.frozen_at IS DISTINCT FROM OLD.frozen_at
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'inspection_reports: contenu ffige (statut %)', OLD.status
                    USING ERRCODE = 'restrict_violation';
            END IF;

            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (OLD.status = 'FROZEN' AND NEW.status IN ('SIGNED', 'SUPERSEDED')) THEN
                RAISE EXCEPTION 'inspection_reports: transition % -> % interdite', OLD.status, NEW.status
                    USING ERRCODE = 'restrict_violation';
            END IF;

            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_inspection_reports_freeze_guard
        BEFORE UPDATE OR DELETE ON inspection_reports
        FOR EACH ROW EXECUTE FUNCTION inspection_reports_freeze_guard()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_inspection_reports_freeze_guard ON inspection_reports")
    op.execute("DROP FUNCTION inspection_reports_freeze_guard()")
    op.drop_table("report_signatures")
    op.drop_table("report_files")
    op.drop_index("uq_inspection_reports_active_contract_id_kind", table_name="inspection_reports")
    op.drop_table("inspection_reports")
    op.drop_index("uq_user_keys_active_user_id", table_name="user_keys")
    op.drop_table("user_keys")
    op.execute("DROP TYPE report_party")
    op.execute("DROP TYPE report_status")
    op.execute("DROP TYPE report_kind")
