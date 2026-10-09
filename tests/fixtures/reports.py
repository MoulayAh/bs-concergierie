"""Aides F3 : cles Ed25519 de test, rapports, uploads, checkout double-signe (reutilisables en F4).

INTERFACES SUPPOSEES F3 (backend-dev / db-migrator doivent s'y aligner) -- source : plan F3.

Domaine pur
  - ``app.domain.report`` : ``ReportKind`` (StrEnum checkout/return), ``ReportStatus`` (StrEnum DRAFT, FROZEN,
    SIGNED, SUPERSEDED), ``ReportAction`` (StrEnum EDIT, ADD_FILE, REMOVE_FILE, FINALIZE, SIGN, SUPERSEDE),
    ``next_status(status, action, *, signatures=0) -> ReportStatus`` (``signatures`` = nombre de signatures
    APRES l'action pour SIGN, nombre actuel pour SUPERSEDE ; leve ``InvalidTransition``, avec
    ``details["reason"] == "REPORT_FROZEN"`` pour EDIT/ADD_FILE/REMOVE_FILE hors DRAFT),
    ``canonical_bytes(content: Mapping) -> bytes``, ``compute_report_hash(content: Mapping) -> str``
    (``content["files"]`` trie par ``sha256``), ``signing_message(contract_id, kind, report_hash) -> bytes``.
  - ``app.domain.errors`` : ``KeyNotRegistered`` (422, KEY_NOT_REGISTERED), ``KeyAlreadyActive`` (409,
    KEY_ALREADY_ACTIVE) ; ``UnsupportedFile`` / ``FileTooLarge`` / ``SignatureInvalid`` existent deja.
Securite
  - ``app.security.signatures`` : ``decode_public_key(b64) -> bytes`` (32 octets sinon ``ValidationFailed``),
    ``key_fingerprint(raw) -> str`` (sha256 hex), ``verify_signature(public_key: bytes, message: bytes,
    signature_b64: str) -> None`` (leve ``SignatureInvalid`` pour TOUT echec : base64, longueur, signature).
  - ``app.security.uploads`` : ``MAX_UPLOAD_BYTES``, ``inspect_upload(data, filename) -> InspectedFile``
    (attributs ``data`` (octets a stocker, images re-encodees), ``mime``, ``ext``, ``sha256``, ``size_bytes``,
    ``width``, ``height``, ``original_name``), ``store_file(inspected, upload_dir) -> str`` (nom
    ``<uuid4>.<ext>``, ecriture atomique), ``sanitize_filename(name) -> str``.
Modeles (``app.models``) : ``UserKey``, ``InspectionReport``, ``ReportFile``, ``ReportSignature``,
  ``ReportKind``, ``ReportStatus`` (tables du plan). Les tests passent par HTTP ; seul le test du trigger
  (``migrated_app``) touche aux tables, en SQL brut.
API (JSON ; erreurs au format ``{"error": ...}``)
  - ``POST /api/me/keys`` ``{"public_key"}`` -> 201
    ``{id, public_key, fingerprint, created_at, revoked_at}`` ;
    ``GET /api/me/keys`` -> ``{"keys": [...]}`` (cles revoquees incluses, ``revoked_at`` renseigne) ;
    ``DELETE /api/me/keys/<id>`` -> 204.
  - ``POST /api/contracts/<id>/reports`` ``{"kind", "odometer_km", "fuel_eighths", "damages"?,
    "claimed_retention_cents"?, "notes"?}`` -> 201 ; ``PUT .../reports/<kind>`` memes champs sans ``kind``.
  - Representation d'un rapport : ``{id, contract_id, kind, revision, status, supersedes_id, odometer_km,
    fuel_eighths, damages, claimed_retention_cents, notes, files: [{id, sha256, mime, size_bytes,
    original_name, uploaded_by}], report_hash|null, canonical_json|null (chaine exacte), frozen_at|null,
    signatures: [{party, user_id, signed_at}]}``. ``GET .../history`` -> ``{"reports": [...]}`` par revision.
  - ``POST .../files`` (multipart, champ ``file``) -> 201 representation du fichier ;
    ``GET .../files/<id>`` -> octets stockes ; ``DELETE`` -> 204 ; ``POST .../finalize`` et
    ``POST .../checkout/signatures`` (``{"signature"}``) exigent ``Idempotency-Key`` (manquante -> 422
    VALIDATION_ERROR) et renvoient le rapport.
  - Verifications metier : kilometrage de retour >= depart (422 VALIDATION_ERROR) et retenue hors bornes
    (422 INVALID_AMOUNT) a la creation/modification ; gel d'un rapport sans photo -> 422 VALIDATION_ERROR.
"""

import base64
import hashlib
import io
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.fixtures.files import distinct_jpeg
from tests.fixtures.helpers import Api, TestUser, new_key

UUID_FILE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.(jpg|png|pdf)$"
)

DEFAULT_FIELDS: dict[str, Any] = {
    "odometer_km": 12_450,
    "fuel_eighths": 8,
    "damages": [],
    "claimed_retention_cents": 0,
    "notes": "",
}


def report_message(contract_id: str, kind: str, report_hash: str) -> bytes:
    """Message signe exact du plan (reecrit ici pour ne pas dependre du code teste)."""
    prefix = b"luxe-escrow:report:v1:"
    return prefix + contract_id.encode() + b":" + kind.encode() + b":" + report_hash.encode()


class KeyPair:
    """Paire Ed25519 de test ; la cle privee ne quitte jamais le test."""

    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_raw = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_b64 = base64.b64encode(self.public_raw).decode()
        self.fingerprint = hashlib.sha256(self.public_raw).hexdigest()
        self.key_id: str | None = None

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private.sign(message)).decode()

    def sign_report(self, contract_id: str, kind: str, report_hash: str) -> str:
        return self.sign(report_message(contract_id, kind, report_hash))


class KeyRing:
    """Cles de test par utilisateur, enregistrees paresseusement via l'API."""

    def __init__(self, api: Api) -> None:
        self.api = api
        self.pairs: dict[str, KeyPair] = {}

    def get(self, user: TestUser) -> KeyPair:
        if user.id not in self.pairs:
            pair = KeyPair()
            resp = register_key(self.api, user, pair.public_b64)
            assert resp.status_code == 201, resp.get_data(as_text=True)
            pair.key_id = resp.get_json()["id"]
            self.pairs[user.id] = pair
        return self.pairs[user.id]


def register_key(api: Api, user: TestUser | None, public_b64: Any):
    return api.request("POST", "/api/me/keys", user, body={"public_key": public_b64})


def report_url(contract_id: str, kind: str = "checkout") -> str:
    return f"/api/contracts/{contract_id}/reports/{kind}"


def create_report(api: Api, contract_id: str, user: TestUser | None, kind: str = "checkout", **over: Any):
    body = {"kind": kind, **DEFAULT_FIELDS, **over}
    return api.request("POST", f"/api/contracts/{contract_id}/reports", user, body=body)


def update_report(api: Api, contract_id: str, user: TestUser | None, kind: str = "checkout", **over: Any):
    return api.request("PUT", report_url(contract_id, kind), user, body={**DEFAULT_FIELDS, **over})


def get_report(api: Api, contract_id: str, user: TestUser | None, kind: str = "checkout"):
    return api.request("GET", report_url(contract_id, kind), user)


def get_history(api: Api, contract_id: str, user: TestUser | None, kind: str = "checkout"):
    return api.request("GET", report_url(contract_id, kind) + "/history", user)


def upload_file(
    api: Api,
    contract_id: str,
    user: TestUser | None,
    data: bytes,
    filename: str = "photo.jpg",
    content_type: str = "image/jpeg",
    kind: str = "checkout",
    field: str = "file",
):
    headers = dict(user.headers) if user else {}
    return api.http.post(
        report_url(contract_id, kind) + "/files",
        data={field: (io.BytesIO(data), filename, content_type)},
        headers=headers,
        content_type="multipart/form-data",
    )


def upload_ok(api: Api, contract_id: str, user: TestUser, data: bytes, **kw: Any) -> dict[str, Any]:
    resp = upload_file(api, contract_id, user, data, **kw)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()


def delete_file(api: Api, contract_id: str, user: TestUser | None, file_id: str, kind: str = "checkout"):
    return api.request("DELETE", report_url(contract_id, kind) + f"/files/{file_id}", user)


def download_file(api: Api, contract_id: str, user: TestUser | None, file_id: str, kind: str = "checkout"):
    return api.request("GET", report_url(contract_id, kind) + f"/files/{file_id}", user)


def finalize_report(
    api: Api,
    contract_id: str,
    user: TestUser | None,
    kind: str = "checkout",
    idem: str | None = None,
    no_key: bool = False,
):
    key = None if no_key else (idem if idem is not None else new_key())
    return api.request("POST", report_url(contract_id, kind) + "/finalize", user, idem=key)


def supersede_report(api: Api, contract_id: str, user: TestUser | None, kind: str = "checkout"):
    return api.request("POST", report_url(contract_id, kind) + "/supersede", user, idem=new_key())


def post_signature(
    api: Api,
    contract_id: str,
    user: TestUser | None,
    signature: Any,
    idem: str | None = None,
    no_key: bool = False,
):
    key = None if no_key else (idem if idem is not None else new_key())
    return api.request(
        "POST",
        f"/api/contracts/{contract_id}/reports/checkout/signatures",
        user,
        body={"signature": signature},
        idem=key,
    )


def draft_with_photo(
    api: Api, contract_id: str, owner: TestUser, kind: str = "checkout", **over: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    resp = create_report(api, contract_id, owner, kind, **over)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    file = upload_ok(api, contract_id, owner, distinct_jpeg(1), kind=kind)
    report = get_report(api, contract_id, owner, kind).get_json()
    return report, file


def frozen_report(api: Api, contract_id: str, owner: TestUser, kind: str = "checkout", **over: Any):
    draft_with_photo(api, contract_id, owner, kind, **over)
    resp = finalize_report(api, contract_id, owner, kind)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()


def sign_as(api: Api, keyring: KeyRing, contract_id: str, user: TestUser, report: dict[str, Any]):
    signature = keyring.get(user).sign_report(contract_id, report["kind"], report["report_hash"])
    return post_signature(api, contract_id, user, signature)


def signed_checkout(
    api: Api, keyring: KeyRing, contract_id: str, owner: TestUser, client: TestUser
) -> dict[str, Any]:
    """Rapport de depart cree, fige et signe par les deux parties (contrat FUNDED)."""
    report = frozen_report(api, contract_id, owner)
    for user in (client, owner):
        resp = sign_as(api, keyring, contract_id, user, report)
        assert resp.status_code == 200, resp.get_data(as_text=True)
    final = get_report(api, contract_id, owner).get_json()
    assert final["status"] == "SIGNED"
    return final


def start_signed(api: Api, keyring: KeyRing, contract_id: str, owner: TestUser, client: TestUser):
    """Remise du vehicule : checkout double-signe puis ``start``. Renvoie la reponse de ``start``."""
    signed_checkout(api, keyring, contract_id, owner, client)
    return api.start(contract_id, owner)


def active_contract(api: Api, keyring: KeyRing, owner: TestUser, client: TestUser) -> str:
    """Contrat ACTIVE (F4 s'en servira) : FUNDED + checkout double-signe + start."""
    from tests.fixtures.deposits import funded_contract

    cid = funded_contract(api, owner, client)
    resp = start_signed(api, keyring, cid, owner, client)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["status"] == "ACTIVE"
    return cid


def upload_dir_files(app: Any) -> list[Path]:
    root = Path(app.config["UPLOAD_DIR"])
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
