"""Handler global : toute erreur sort en JSON {"error": {"code", "message", "details"?}}, jamais de trace."""

import logging
from typing import Any

from flask import Flask, Response, jsonify, request
from sqlalchemy.exc import DBAPIError, OperationalError
from werkzeug.exceptions import HTTPException, MethodNotAllowed

from app.domain.errors import DomainError
from app.extensions import db

logger = logging.getLogger(__name__)

_RESTRICT_VIOLATION = "23001"  # SQLSTATE leve par le trigger de gel des rapports

_HTTP_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    408: "REQUEST_TIMEOUT",
    413: "FILE_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "VALIDATION_ERROR",
}
_HTTP_MESSAGES: dict[int, str] = {
    404: "Ressource introuvable",
    405: "Methode non autorisee",
    413: "Requete trop volumineuse",
    415: "Type de contenu non supporte",
}


def error_response(
    status: int, code: str, message: str, details: dict[str, Any] | None = None
) -> tuple[Response, int]:
    payload: dict[str, Any] = {"code": code, "message": message}
    if details:
        payload["details"] = details
    return jsonify({"error": payload}), status


def _rollback() -> None:
    db.session.rollback()


def _discard_request_body() -> None:
    """Refus 413 : le corps (jamais lu en entier) est ferme pour ne laisser aucun descripteur ouvert."""
    stream = request.environ.get("wsgi.input")
    close = getattr(stream, "close", None)
    if callable(close):
        close()


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(DomainError)
    def _domain_error(exc: DomainError) -> tuple[Response, int]:
        _rollback()
        return error_response(exc.http_status, exc.code, exc.message, exc.details)

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException) -> tuple[Response, int]:
        _rollback()
        status = exc.code or 500
        if status == 413:
            _discard_request_body()
        code = _HTTP_CODES.get(status, "HTTP_ERROR")
        message = _HTTP_MESSAGES.get(status, "Requete invalide")
        body, _ = error_response(status, code, message)
        if isinstance(exc, MethodNotAllowed) and exc.valid_methods:
            body.headers["Allow"] = ", ".join(sorted(exc.valid_methods))
        return body, status

    @app.errorhandler(OperationalError)
    def _db_unavailable(exc: OperationalError) -> tuple[Response, int]:
        logger.error("Base de donnees indisponible", exc_info=exc)
        _rollback()
        return error_response(503, "SERVICE_UNAVAILABLE", "Service temporairement indisponible")

    @app.errorhandler(DBAPIError)
    def _database_error(exc: DBAPIError) -> tuple[Response, int]:
        _rollback()
        if getattr(exc.orig, "sqlstate", None) == _RESTRICT_VIOLATION:
            # Trigger de gel d'un rapport : la base refuse, l'API repond 409 comme la couche metier.
            return error_response(
                409,
                "INVALID_TRANSITION",
                "Le rapport est fige et ne peut plus etre modifie",
                {"reason": "REPORT_FROZEN"},
            )
        logger.error("Erreur base de donnees non geree", exc_info=exc)
        return error_response(500, "INTERNAL_ERROR", "Erreur interne du serveur")

    @app.errorhandler(Exception)
    def _unexpected_error(exc: Exception) -> tuple[Response, int]:
        logger.error("Erreur interne non geree", exc_info=exc)
        _rollback()
        return error_response(500, "INTERNAL_ERROR", "Erreur interne du serveur")

    @app.after_request
    def _security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response
