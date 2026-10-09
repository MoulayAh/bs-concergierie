"""Luxe Escrow - application Flask (app factory)."""

import os
from typing import Any

from flask import Flask, Response
from sqlalchemy.pool import NullPool

from app.api.contracts import bp as contracts_bp
from app.api.public import bp as public_bp
from app.api.reports import bp as reports_bp
from app.cli import register_cli
from app.domain.money import MAX_DEPOSIT_CENTS
from app.errors import register_error_handlers
from app.extensions import db, migrate
from app.http import MemoryUploadRequest
from app.security.server_key import ServerKeyError, load_private_key
from app.services.payments import SimulatedProvider

DEFAULT_MAX_CONTENT_LENGTH = 10 * 1024 * 1024
_DEV_DATABASE_URL = "postgresql+psycopg://escrow:escrow_dev@localhost:5432/escrow"


def create_app(config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.request_class = MemoryUploadRequest
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE_URL=os.environ.get("DATABASE_URL", _DEV_DATABASE_URL),
        UPLOAD_DIR=os.environ.get("UPLOAD_DIR", "./var/uploads"),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", DEFAULT_MAX_CONTENT_LENGTH)),
        MAX_DEPOSIT_CENTS=MAX_DEPOSIT_CENTS,
        SERVER_SIGNING_KEY=os.environ.get("SERVER_SIGNING_KEY"),
    )
    if config:
        app.config.update(config)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY est obligatoire (variable d'environnement ou configuration)")
    if app.config["MAX_DEPOSIT_CENTS"] > MAX_DEPOSIT_CENTS:
        raise RuntimeError("MAX_DEPOSIT_CENTS ne peut pas depasser le plafond du domaine")

    try:
        signing_key = load_private_key(app.config.pop("SERVER_SIGNING_KEY", None))
    except ServerKeyError as exc:
        raise RuntimeError(
            "SERVER_SIGNING_KEY est obligatoire : base64 d'une graine Ed25519 de 32 octets "
            "(generer avec `python -m app.security.server_key`)"
        ) from exc

    app.config.setdefault("SQLALCHEMY_DATABASE_URI", app.config["DATABASE_URL"])
    if app.config.get("TESTING"):
        # Une application (donc un moteur) par test : sans pool, aucune connexion ne survit au test.
        app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {"poolclass": NullPool})
    else:
        app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {"pool_pre_ping": True})

    db.init_app(app)
    migrate.init_app(app, db)
    app.extensions["payment_provider"] = SimulatedProvider()
    app.extensions["server_signing_key"] = signing_key
    register_error_handlers(app)
    app.register_blueprint(contracts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(public_bp)

    @app.get("/reports")
    def reports_page() -> Response:
        """Ecran de demo des etats des lieux (page statique ; les appels API portent le jeton Bearer)."""
        return app.send_static_file("reports.html")

    register_cli(app)
    return app
