# Les noms sans suffixe "Error" sont imposes par les tests (InvalidTransition, ForbiddenActor, ...).
# ruff: noqa: N818
"""Exceptions metier typees. Le handler global les convertit en JSON {"error": {...}}."""

from typing import Any


class DomainError(Exception):
    """Erreur metier : porte un code stable et un statut HTTP."""

    code: str = "DOMAIN_ERROR"
    http_status: int = 400

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class ValidationFailed(DomainError):
    code = "VALIDATION_ERROR"
    http_status = 422


class InvalidAmount(DomainError):
    code = "INVALID_AMOUNT"
    http_status = 422


class InvalidTransition(DomainError):
    code = "INVALID_TRANSITION"
    http_status = 409


class ForbiddenActor(DomainError):
    code = "FORBIDDEN_ACTOR"
    http_status = 403


class ResourceNotFound(DomainError):
    code = "NOT_FOUND"
    http_status = 404


class Unauthenticated(DomainError):
    code = "UNAUTHENTICATED"
    http_status = 401


class IdempotencyConflict(DomainError):
    code = "IDEMPOTENCY_CONFLICT"
    http_status = 409


class UnsupportedFile(DomainError):
    code = "UNSUPPORTED_FILE"
    http_status = 415


class FileTooLarge(DomainError):
    code = "FILE_TOO_LARGE"
    http_status = 413


class PaymentDeclined(DomainError):
    code = "PAYMENT_DECLINED"
    http_status = 402


class PaymentUnavailable(DomainError):
    code = "PAYMENT_UNAVAILABLE"
    http_status = 503


class SignatureInvalid(DomainError):
    code = "SIGNATURE_INVALID"
    http_status = 422
