"""escrow_events.payload : donnees de l'evenement en clair (ex. motif d'annulation)

Revision ID: 0002_escrow_event_payload
Revises: 0001_initial_f1
Create Date: 2026-10-08

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_escrow_event_payload"
down_revision = "0001_initial_f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("escrow_events", sa.Column("payload", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("escrow_events", "payload")
