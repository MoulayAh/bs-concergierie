"""Blueprint /api/contracts : parse -> service -> reponse (aucune logique metier ici)."""

from flask import Blueprint, Response, jsonify, request

from app.schemas.contracts import CancelIn, CreateContractIn
from app.schemas.parsing import (
    parse_idempotency_key,
    parse_json_body,
    require_idempotency_key,
    validate_model,
)
from app.security.auth import authenticate_request, current_user
from app.services import contracts as service
from app.services.idempotency import Outcome, fingerprint

bp = Blueprint("contracts", __name__, url_prefix="/api/contracts")


@bp.before_request
def _authenticate() -> None:
    authenticate_request()


def _idempotency_key(*, required: bool) -> str | None:
    return parse_idempotency_key(request.headers.get("Idempotency-Key"), required=required)


def _required_idempotency_key() -> str:
    return require_idempotency_key(request.headers.get("Idempotency-Key"))


def _respond(outcome: Outcome) -> tuple[Response, int]:
    return jsonify(outcome.body), outcome.status


@bp.post("")
def create_contract() -> tuple[Response, int]:
    user = current_user()
    service.require_owner(user)
    key = _required_idempotency_key()
    raw = parse_json_body(request.get_data(), request.mimetype)
    data = validate_model(CreateContractIn, raw)
    outcome = service.create_contract(
        user,
        data,
        idempotency_key=key,
        request_hash=fingerprint({"op": "create", "body": raw}),
    )
    return _respond(outcome)


@bp.get("/<contract_id>")
def get_contract(contract_id: str) -> tuple[Response, int]:
    return jsonify(service.get_contract(current_user(), contract_id)), 200


@bp.get("/<contract_id>/events")
def get_events(contract_id: str) -> tuple[Response, int]:
    return jsonify({"events": service.list_events(current_user(), contract_id)}), 200


@bp.post("/<contract_id>/sign")
def sign_contract(contract_id: str) -> tuple[Response, int]:
    key = _idempotency_key(required=False)
    return _respond(service.sign_contract(current_user(), contract_id, idempotency_key=key))


@bp.post("/<contract_id>/cancel")
def cancel_contract(contract_id: str) -> tuple[Response, int]:
    key = _idempotency_key(required=False)
    payload = request.get_data()
    raw: object | None = None
    if payload.strip():  # corps optionnel ; un corps present doit etre valide (y compris `null`)
        raw = parse_json_body(payload, request.mimetype)
        validate_model(CancelIn, raw)
    return _respond(service.cancel_contract(current_user(), contract_id, body=raw, idempotency_key=key))
