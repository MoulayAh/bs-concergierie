"""Blueprint cles publiques et etats des lieux : parse -> service -> reponse (aucune logique metier ici)."""

import io

from flask import Blueprint, Response, jsonify, request, send_file

from app.domain.errors import ValidationFailed
from app.schemas.parsing import (
    parse_idempotency_key,
    parse_json_body,
    require_idempotency_key,
    validate_model,
)
from app.schemas.reports import CreateReportIn, KeyIn, ReportFieldsIn, SignatureIn
from app.security.auth import authenticate_request, current_user
from app.security.uploads import MAX_UPLOAD_BYTES
from app.services import keys as keys_service
from app.services import reports as service
from app.services.idempotency import Outcome

bp = Blueprint("reports", __name__, url_prefix="/api")

_REPORTS = "/contracts/<contract_id>/reports"


@bp.before_request
def _authenticate() -> None:
    authenticate_request()


def _respond(outcome: Outcome) -> tuple[Response, int]:
    return jsonify(outcome.body), outcome.status


def _required_key() -> str:
    return require_idempotency_key(request.headers.get("Idempotency-Key"))


@bp.get("/me")
def whoami() -> tuple[Response, int]:
    user = current_user()
    return jsonify(
        {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role.value,
        }
    ), 200


# ------------------------------------------------------------------ cles publiques


@bp.post("/me/keys")
def register_key() -> tuple[Response, int]:
    data = validate_model(KeyIn, parse_json_body(request.get_data(), request.mimetype))
    return jsonify(keys_service.register_key(current_user(), data)), 201


@bp.get("/me/keys")
def list_keys() -> tuple[Response, int]:
    return jsonify({"keys": keys_service.list_keys(current_user())}), 200


@bp.delete("/me/keys/<key_id>")
def revoke_key(key_id: str) -> tuple[str, int]:
    keys_service.revoke_key(current_user(), key_id)
    return "", 204


# ------------------------------------------------------------------ etats des lieux


@bp.post(_REPORTS)
def create_report(contract_id: str) -> tuple[Response, int]:
    raw = parse_json_body(request.get_data(), request.mimetype)
    data = validate_model(CreateReportIn, raw)
    return _respond(service.create_report(current_user(), contract_id, data, body=raw))


@bp.get(_REPORTS + "/<kind>")
def get_report(contract_id: str, kind: str) -> tuple[Response, int]:
    return jsonify(service.get_report(current_user(), contract_id, kind)), 200


@bp.get(_REPORTS + "/<kind>/history")
def get_history(contract_id: str, kind: str) -> tuple[Response, int]:
    return jsonify({"reports": service.get_history(current_user(), contract_id, kind)}), 200


@bp.put(_REPORTS + "/<kind>")
def update_report(contract_id: str, kind: str) -> tuple[Response, int]:
    raw = parse_json_body(request.get_data(), request.mimetype)
    data = validate_model(ReportFieldsIn, raw)
    return _respond(service.update_report(current_user(), contract_id, kind, data, body=raw))


@bp.post(_REPORTS + "/<kind>/files")
def upload_file(contract_id: str, kind: str) -> tuple[Response, int]:
    uploads = request.files.getlist("file")
    if len(uploads) != 1:
        raise ValidationFailed("Exactement un fichier est attendu dans le champ multipart 'file'")
    upload = uploads[0]
    data = upload.stream.read(MAX_UPLOAD_BYTES + 1)
    return _respond(service.add_file(current_user(), contract_id, kind, data, upload.filename or ""))


@bp.get(_REPORTS + "/<kind>/files/<file_id>")
def download_file(contract_id: str, kind: str, file_id: str) -> Response:
    item, path = service.get_file(current_user(), contract_id, kind, file_id)
    # Octets lus en memoire (10 Mo au plus) : aucun descripteur de fichier ne reste ouvert apres la reponse.
    response = send_file(
        io.BytesIO(path.read_bytes()),
        mimetype=item.mime,
        as_attachment=True,
        download_name=item.original_name,
        conditional=False,
        etag=False,
        max_age=0,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response


@bp.delete(_REPORTS + "/<kind>/files/<file_id>")
def delete_file(contract_id: str, kind: str, file_id: str) -> tuple[str, int]:
    service.delete_file(current_user(), contract_id, kind, file_id)
    return "", 204


@bp.post(_REPORTS + "/<kind>/finalize")
def finalize_report(contract_id: str, kind: str) -> tuple[Response, int]:
    key = _required_key()
    return _respond(service.finalize_report(current_user(), contract_id, kind, key=key))


@bp.post(_REPORTS + "/<kind>/supersede")
def supersede_report(contract_id: str, kind: str) -> tuple[Response, int]:
    key = parse_idempotency_key(request.headers.get("Idempotency-Key"), required=False)
    return _respond(service.supersede_report(current_user(), contract_id, kind, key=key))


@bp.post(_REPORTS + "/checkout/signatures")
def sign_checkout(contract_id: str) -> tuple[Response, int]:
    key = _required_key()
    raw = parse_json_body(request.get_data(), request.mimetype)
    data = validate_model(SignatureIn, raw)
    return _respond(service.sign_checkout(current_user(), contract_id, data, key=key, body=raw))
