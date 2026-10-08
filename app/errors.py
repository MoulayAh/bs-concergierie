"""Handler global : toute erreur sort en JSON {"error": {"code", "message", "details"?}}, jamais de trace."""

import logging
from typing import Any

from flask import Flask, Response, jsonify
from werkzeug.exceptions import HTTPException, MethodNotAllowed

from app.domain.errors import DomainError
from app.extensions import db

logger = logging.getLogger(__name__)

_HTTP_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    408: "REQUEST_TIMEOUT",
    413: "PAYLOAD_TOO_LARGE",
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


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(DomainError)
    def _domain_error(exc: DomainError) -> tuple[Response, int]:
        _rollback()
        return error_response(exc.http_status, exc.code, exc.message, exc.details)

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException) -> tuple[Response, int]:
        _rollback()
        status = exc.code or 500
        code = _HTTP_CODES.get(status, "HTTP_ERROR")
        message = _HTTP_MESSAGES.get(status, "Requete invalide")
        body, _ = error_response(status, code, message)
        if isinstance(exc, MethodNotAllowed) and exc.valid_methods:
            body.headers["Allow"] = ", ".join(sorted(exc.valid_methods))
        return body, status

    @app.errorhandler(Exception)
    def _unexpected_error(exc: Exception) -> tuple[Response, int]:
        logger.error("Erreur interne non geree", exc_info=exc)
        _rollback()
        return error_response(500, "INTERNAL_ERROR", "Erreur interne du serveur")

    @app.after_request
    def _security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response
