"""Isolation de la base de test : toutes les connexions de l'app passent par le schema dedie."""

import threading

from sqlalchemy import text

from app.extensions import db


def _current_schema(app) -> str:
    with app.app_context(), db.engine.connect() as conn:
        return conn.execute(text("SELECT current_schema()")).scalar_one()


def test_app_connections_use_the_dedicated_session_schema(app, pg_schema):
    assert _current_schema(app) == pg_schema
    assert pg_schema.startswith("test_")


def test_connections_opened_in_other_threads_use_the_dedicated_schema(app, pg_schema):
    seen: list[str] = []

    def work() -> None:
        seen.append(_current_schema(app))

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert seen == [pg_schema] * 4


def test_tables_and_enums_live_in_dedicated_schema_not_in_public(app, pg_schema, owner_user):
    with app.app_context(), db.engine.connect() as conn:
        public_tables = conn.execute(
            text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        ).scalars()
        enum_schemas = conn.execute(
            text(
                "SELECT DISTINCT n.nspname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
                "WHERE t.typname IN ('contract_status', 'user_role') AND n.nspname = ANY(:s)"
            ),
            {"s": [pg_schema, "public"]},
        ).scalars()
        own_tables = set(
            conn.execute(
                text("SELECT table_name FROM information_schema.tables WHERE table_schema = :s"),
                {"s": pg_schema},
            ).scalars()
        )
        names_in_public = set(public_tables)
        enum_where = set(enum_schemas)

    assert {"users", "contracts", "escrow_events", "idempotency_keys"} <= own_tables
    assert not names_in_public & {"users", "contracts", "escrow_events", "idempotency_keys"}
    assert enum_where == {pg_schema}
