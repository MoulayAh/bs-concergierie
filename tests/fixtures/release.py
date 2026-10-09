"""Aides F4 : cle serveur de test, chaine d'evenements, quittances, contrat amene a INSPECTION_PENDING.

INTERFACES SUPPOSEES F4 (backend-dev / db-migrator doivent s'y aligner) -- source : plan F4.

Configuration
  - ``SERVER_SIGNING_KEY`` (config Flask ou variable d'environnement) = base64 STANDARD de la graine privee
    Ed25519 de 32 octets. ``create_app`` leve ``RuntimeError`` (message contenant ``SERVER_SIGNING_KEY``) si
    elle est absente, vide ou mal formee. Les tests en recoivent une cle generee une fois par session
    (``SERVER_KEY_B64`` ci-dessous ; ``tests/conftest.py`` la passe a ``app`` et ``migrated_app``).
Domaine pur
  - ``app.domain.event_chain`` : ``GENESIS = "0" * 64`` ; ``compute_event_hash(prev_hash: str,
    fields: Mapping) -> str`` = sha256 hex de ``prev_hash + ":" + canonique(fields)`` (canonique = json trie,
    separateurs compacts, ``ensure_ascii=False``) ; ``fields`` contient exactement ``contract_id, seq, event,
    actor_id, from_status, to_status, payload_hash, created_at`` (``created_at`` = chaine telle qu'exportee) ;
    ``verify_chain(events: Sequence[Mapping]) -> None`` leve ``EventChainError`` (meme module) si ``seq`` ne
    va pas de 1 a n sans trou, si le premier ``prev_hash`` n'est pas GENESIS, si un ``prev_hash`` differe de
    l'``event_hash`` precedent ou si un ``event_hash`` ne se recalcule pas. Liste vide = chaine valide.
  - ``app.domain.receipt`` : ``RECEIPT_PREFIX = b"luxe-escrow:receipt:v1:"``, ``canonical_receipt(content:
    Mapping) -> bytes`` (meme canonisation que F3), ``receipt_hash(canonical: bytes) -> str`` (sha256 hex),
    ``receipt_signing_message(receipt_hash: str) -> bytes`` = ``RECEIPT_PREFIX + receipt_hash.encode()``.
Securite
  - ``app.security.server_key`` : ``ServerKeyError`` ; ``load_private_key(seed_b64: str) ->
    Ed25519PrivateKey`` (leve ``ServerKeyError`` si base64 invalide ou graine != 32 octets) ;
    ``public_key_bytes(private) -> bytes`` (32 octets bruts).
Script
  - ``scripts.verify_receipt.verify_receipt(receipt: dict, server_public_key: bytes, events: list | None
    = None) -> None`` ; ``receipt`` = objet renvoye par l'API ``{canonical_json: str, receipt_hash,
    server_signature (base64)}`` ; leve ``ReceiptInvalid`` (meme module) pour TOUT echec (hash, signature
    serveur, signature d'une partie, somme != caution, chaine). ASSUMPTION a valider : chaque entree de
    ``signatures`` du contenu de la quittance porte AUSSI ``public_key`` (base64 de 32 octets) en plus de
    ``key_fingerprint`` -- sans cle publique la verification hors ligne des signatures des parties est
    impossible ; le script verifie ``sha256(public_key) == key_fingerprint``.
    Avec ``events`` : ``verify_chain`` puis ``len(events) == event_chain.length`` et
    ``events[-1].event_hash == event_chain.head``. CLI : ``verify_receipt.py <receipt.json>
    [--events events.json] [--server-key <base64 cle publique>]`` (code de sortie 0 = verifiee).
API
  - ``POST /api/contracts/<id>/reports/return/signatures`` ``{"signature"}`` (Idempotency-Key obligatoire).
    1re signature : 200 + rapport. 2de signature : 200 ``{"contract": {...status RELEASED|SETTLED...},
    "funds": {format F2}, "receipt": {canonical_json, receipt_hash, server_signature}}``.
    ``GET /api/contracts/<id>/receipt`` -> 200 meme objet ``receipt`` ; 404 NOT_FOUND avant liberation/IDOR.
    ``GET /api/server-key`` (public) -> 200 ``{"public_key": <base64>, "fingerprint": <sha256 hex>}``.
  - ``GET /api/contracts/<id>/events`` expose en plus ``contract_id``, ``seq``, ``prev_hash``, ``event_hash``.
  - ``PaymentProvider.settle(ref, *, release_cents, capture_cents, key) -> str`` ; cle
    ``"settle:<deposit_id>"``.
  - Retenue d'un rapport de retour > 0 : au moins un dommage et chaque dommage au moins une photo, sinon
    422 VALIDATION_ERROR au gel.
Base (migration 0005)
  - ``deposits.settled_at``, ``deposits.settlement_ref`` ; trigger : un depot RELEASED/SETTLED/REFUNDED est
    immuable (UPDATE et DELETE rejetes). ``escrow_events.seq/prev_hash/event_hash`` + trigger de chainage.
    ``settlement_receipts`` (colonnes du plan) en ajout seul. Erreurs SQL : ``DBAPIError``.
"""

import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from tests.fixtures.files import distinct_jpeg
from tests.fixtures.helpers import Api, TestUser, new_key
from tests.fixtures.reports import (
    KeyPair,
    KeyRing,
    active_contract,
    create_report,
    finalize_report,
    report_message,
    update_report,
    upload_ok,
)

GENESIS = "0" * 64
# Format de ``created_at`` dans le hash ET dans l'export ``/events`` (aligne sur la migration 0005) :
# UTC, microsecondes, suffixe Z. L'export actuel (isoformat avec +00:00) doit donc changer.
EVENT_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
RECEIPT_PREFIX = b"luxe-escrow:receipt:v1:"
DEPOSIT_CENTS = 2_500_000
RETURN_ODOMETER_KM = 12_600

# Cle serveur de test : generee une fois par session (import du module), jamais ecrite sur disque.
SERVER_SEED = os.urandom(32)
SERVER_KEY_B64 = base64.b64encode(SERVER_SEED).decode()
SERVER_PRIVATE = Ed25519PrivateKey.from_private_bytes(SERVER_SEED)
SERVER_PUBLIC_RAW = SERVER_PRIVATE.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)

EVENT_FIELDS = (
    "contract_id",
    "seq",
    "event",
    "actor_id",
    "from_status",
    "to_status",
    "payload_hash",
    "created_at",
)


def canonical(obj: Any) -> bytes:
    """Canonisation du plan (reecrite ici pour ne pas dependre du code teste)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def chain_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    body = canonical({k: fields[k] for k in EVENT_FIELDS})
    return hashlib.sha256(prev_hash.encode() + b":" + body).hexdigest()


def build_chain(contract_id: str, specs: list[tuple[str, str | None, str]]) -> list[dict[str, Any]]:
    """Chaine valide ; ``specs`` = [(event, from_status, to_status)]. Format = export de ``/events``."""
    events: list[dict[str, Any]] = []
    prev = GENESIS
    moment = datetime(2026, 11, 1, 9, 0, 0, tzinfo=UTC)
    for seq, (event, from_status, to_status) in enumerate(specs, start=1):
        fields: dict[str, Any] = {
            "contract_id": contract_id,
            "seq": seq,
            "event": event,
            "actor_id": str(uuid.uuid4()),
            "from_status": from_status,
            "to_status": to_status,
            "payload_hash": hashlib.sha256(f"{event}{seq}".encode()).hexdigest(),
            "created_at": (moment + timedelta(minutes=seq)).strftime(EVENT_TS_FORMAT),
        }
        digest = chain_hash(prev, fields)
        events.append({**fields, "prev_hash": prev, "event_hash": digest})
        prev = digest
    return events


LIFECYCLE_SPECS: list[tuple[str, str | None, str]] = [
    ("create", None, "DRAFT"),
    ("sign_contract", "DRAFT", "DRAFT"),
    ("sign_contract", "DRAFT", "AWAITING_DEPOSIT"),
    ("deposit", "AWAITING_DEPOSIT", "FUNDED"),
    ("start_rental", "FUNDED", "ACTIVE"),
    ("submit_return_report", "ACTIVE", "INSPECTION_PENDING"),
    ("sign_report", "INSPECTION_PENDING", "INSPECTION_PENDING"),
    ("sign_report", "INSPECTION_PENDING", "SETTLED"),
]


def seal_receipt(content: dict[str, Any], private: Ed25519PrivateKey = SERVER_PRIVATE) -> dict[str, str]:
    """Objet ``receipt`` de l'API : canonical_json, receipt_hash, server_signature."""
    raw = canonical(content)
    digest = hashlib.sha256(raw).hexdigest()
    signature = private.sign(RECEIPT_PREFIX + digest.encode())
    return {
        "canonical_json": raw.decode("utf-8"),
        "receipt_hash": digest,
        "server_signature": base64.b64encode(signature).decode(),
    }


@dataclass
class BuiltReceipt:
    content: dict[str, Any]
    receipt: dict[str, str]
    events: list[dict[str, Any]]
    server_public: bytes
    owner_key: KeyPair
    client_key: KeyPair


def build_receipt(deposit_cents: int = DEPOSIT_CENTS, retained_cents: int = 120_000) -> BuiltReceipt:
    """Quittance hors ligne COHERENTE (signee par le serveur de test et par deux cles de parties)."""
    contract_id = str(uuid.uuid4())
    outcome = "SETTLED" if retained_cents > 0 else "RELEASED"
    specs = list(LIFECYCLE_SPECS)
    specs[-1] = ("sign_report", "INSPECTION_PENDING", outcome)
    events = build_chain(contract_id, specs)
    return_hash = hashlib.sha256(b"return-report").hexdigest()
    owner_key, client_key = KeyPair(), KeyPair()
    moment = "2026-11-05T18:02:11Z"
    signatures = []
    for party, pair in (("owner", owner_key), ("client", client_key)):
        signatures.append(
            {
                "party": party,
                "key_fingerprint": pair.fingerprint,
                "public_key": pair.public_b64,
                "signature": pair.sign(report_message(contract_id, "return", return_hash)),
                "signed_at": moment,
            }
        )
    content: dict[str, Any] = {
        "schema": "luxe-escrow/receipt/v1",
        "contract_id": contract_id,
        "outcome": outcome,
        "currency": "EUR",
        "deposit_cents": deposit_cents,
        "released_to_client_cents": deposit_cents - retained_cents,
        "retained_by_owner_cents": retained_cents,
        "return_report": {"id": str(uuid.uuid4()), "revision": 1, "hash": return_hash},
        "checkout_report": {"id": str(uuid.uuid4()), "hash": hashlib.sha256(b"checkout").hexdigest()},
        "signatures": signatures,
        "settlement_ref": "sim_set_" + "0" * 24,
        "settled_at": moment,
        "event_chain": {"length": len(events), "head": events[-1]["event_hash"]},
    }
    return BuiltReceipt(content, seal_receipt(content), events, SERVER_PUBLIC_RAW, owner_key, client_key)


# ---------------------------------------------------------------- API : contrat INSPECTION_PENDING


@dataclass(frozen=True)
class Pending:
    """Contrat INSPECTION_PENDING : rapport de retour fige, pret a etre signe par les deux parties."""

    contract_id: str
    report: dict[str, Any]
    deposit_cents: int
    retention_cents: int


def pending_contract(
    api: Api,
    keyring: KeyRing,
    owner: TestUser,
    client: TestUser,
    *,
    retention_cents: int = 0,
    damage: bool | None = None,
) -> Pending:
    """ACTIVE -> rapport de retour (avec photo, dommage photographie si ``damage``) -> gel.

    ``damage`` vaut par defaut ``retention_cents > 0`` (une retenue exige un dommage avec photo).
    """
    with_damage = retention_cents > 0 if damage is None else damage
    cid = active_contract(api, keyring, owner, client)
    resp = create_report(api, cid, owner, "return", odometer_km=RETURN_ODOMETER_KM)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    photo = upload_ok(api, cid, owner, distinct_jpeg(2), kind="return")
    damages = (
        [{"zone": "hood", "severity": "minor", "description": "Rayure", "file_ids": [photo["id"]]}]
        if with_damage
        else []
    )
    resp = update_report(
        api,
        cid,
        owner,
        "return",
        odometer_km=RETURN_ODOMETER_KM,
        damages=damages,
        claimed_retention_cents=retention_cents,
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    resp = finalize_report(api, cid, owner, "return")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    report = resp.get_json()
    assert api.get(cid, owner).get_json()["status"] == "INSPECTION_PENDING"
    return Pending(cid, report, DEPOSIT_CENTS, retention_cents)


def return_signatures_url(contract_id: str) -> str:
    return f"/api/contracts/{contract_id}/reports/return/signatures"


def post_return_signature(
    api: Api,
    contract_id: str,
    user: TestUser | None,
    signature: Any,
    idem: str | None = None,
    no_key: bool = False,
    body: dict[str, Any] | None = None,
):
    key = None if no_key else (idem if idem is not None else new_key())
    payload = body if body is not None else {"signature": signature}
    return api.request("POST", return_signatures_url(contract_id), user, body=payload, idem=key)


def sign_return(
    api: Api,
    keyring: KeyRing,
    contract_id: str,
    user: TestUser,
    report: dict[str, Any],
    idem: str | None = None,
):
    signature = keyring.get(user).sign_report(contract_id, "return", report["report_hash"])
    return post_return_signature(api, contract_id, user, signature, idem=idem)


def release(
    api: Api, keyring: KeyRing, pending: Pending, owner: TestUser, client: TestUser
) -> tuple[Any, Any]:
    """Les deux signatures (client puis loueur) ; renvoie (reponse 1re signature, reponse liberation)."""
    first = sign_return(api, keyring, pending.contract_id, client, pending.report)
    assert first.status_code == 200, first.get_data(as_text=True)
    second = sign_return(api, keyring, pending.contract_id, owner, pending.report)
    assert second.status_code == 200, second.get_data(as_text=True)
    return first, second


def get_receipt(api: Api, contract_id: str, user: TestUser | None):
    return api.request("GET", f"/api/contracts/{contract_id}/receipt", user)


def deposit_id(app: Any, contract_id: str) -> str:
    from app.extensions import db
    from app.models import Deposit

    with app.app_context():
        return str(db.session.scalars(select(Deposit.id).where(Deposit.contract_id == contract_id)).one())


def release_state(app: Any, api: Api, contract_id: str, user: TestUser) -> dict[str, Any]:
    """Tout ce qui doit rester identique apres une erreur (contrat, evenements, depot, rapport, quittance)."""
    from tests.fixtures.deposits import full_state
    from tests.fixtures.reports import get_report

    return {
        "state": full_state(app, api, contract_id, user),
        "return_report": get_report(api, contract_id, user, "return").get_json(),
        "receipt_status": get_receipt(api, contract_id, user).status_code,
    }
