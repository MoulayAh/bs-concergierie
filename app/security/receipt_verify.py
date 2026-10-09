"""Verification hors ligne d'une quittance de liberation, sans faire confiance au serveur.

Utilise par ``scripts/verify_receipt.py`` (enveloppe mince) :

    python scripts/verify_receipt.py <receipt.json> [--events events.json] --server-key <base64>

Le fichier de quittance est soit l'objet ``receipt`` de l'API (``canonical_json``, ``receipt_hash``,
``server_signature``), soit le fichier telecharge par l'UI (meme objet plus ``receipt`` deja decode).
Les verifications portent sur les OCTETS de ``canonical_json`` : empreinte, signature du serveur, signatures
des deux parties sur l'empreinte du rapport de retour, somme des montants et, avec ``--events``, toute la
chaine d'evenements (longueur et tete incluses). Code de sortie : 0 verifiee, 1 invalide, 2 usage/fichier.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.domain.event_chain import EventChainError, payload_fingerprint, verify_chain
from app.domain.receipt import SCHEMA, canonical_receipt, receipt_hash, receipt_signing_message
from app.domain.report import ReportKind, signing_message

_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_PARTIES = frozenset({"owner", "client"})


class ReceiptInvalid(Exception):  # noqa: N818 - nom impose par les tests et le plan
    """La quittance (ou la chaine d'evenements fournie) ne se verifie pas."""


def _b64(value: object, expected: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise ReceiptInvalid(f"{label} : base64 attendu")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReceiptInvalid(f"{label} : base64 invalide") from exc
    if len(raw) != expected:
        raise ReceiptInvalid(f"{label} : {expected} octets attendus")
    return raw


def _check_ed25519(public: bytes, signature: bytes, message: bytes, label: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise ReceiptInvalid(f"{label} : signature invalide") from exc


def _same(left: object, right: str) -> bool:
    return isinstance(left, str) and hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _amount(content: Mapping[str, Any], name: str) -> int:
    value = content.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReceiptInvalid(f"{name} : entier en centimes attendu")
    return value


def _canonical_bytes(receipt: Mapping[str, Any]) -> bytes:
    raw = receipt.get("canonical_json")
    if isinstance(raw, str):
        return raw.encode("utf-8")
    decoded = receipt.get("receipt")
    if raw is None and isinstance(decoded, dict):
        return canonical_receipt(decoded)
    raise ReceiptInvalid("canonical_json absent ou illisible")


def _check_server(receipt: Mapping[str, Any], canonical: bytes, server_public_key: bytes) -> None:
    if not isinstance(server_public_key, bytes) or len(server_public_key) != _KEY_BYTES:
        raise ReceiptInvalid("cle publique du serveur : 32 octets attendus")
    digest = receipt_hash(canonical)
    if not _same(receipt.get("receipt_hash"), digest):
        raise ReceiptInvalid("empreinte de la quittance differente du contenu")
    signature = _b64(receipt.get("server_signature"), _SIGNATURE_BYTES, "signature du serveur")
    _check_ed25519(server_public_key, signature, receipt_signing_message(digest), "signature du serveur")


def _check_amounts(content: Mapping[str, Any]) -> None:
    deposit = _amount(content, "deposit_cents")
    released = _amount(content, "released_to_client_cents")
    retained = _amount(content, "retained_by_owner_cents")
    if deposit <= 0 or released < 0 or retained < 0 or released + retained != deposit:
        raise ReceiptInvalid("montants incoherents : rendu + retenue doit valoir la caution")
    if content.get("outcome") != ("SETTLED" if retained > 0 else "RELEASED"):
        raise ReceiptInvalid("issue incoherente avec la retenue")


def _check_parties(content: Mapping[str, Any], expected: Mapping[str, str] | None = None) -> None:
    contract_id, report = content.get("contract_id"), content.get("return_report")
    entries = content.get("signatures")
    if not isinstance(contract_id, str) or not isinstance(report, dict):
        raise ReceiptInvalid("contrat ou rapport de retour manquant")
    report_hash = report.get("hash")
    if not isinstance(report_hash, str):
        raise ReceiptInvalid("empreinte du rapport de retour manquante")
    if not isinstance(entries, list) or len(entries) != len(_PARTIES):
        raise ReceiptInvalid("deux signatures de parties sont requises")
    message = signing_message(contract_id, ReportKind.RETURN, report_hash)
    seen: set[object] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReceiptInvalid("signature de partie illisible")
        party = entry.get("party")
        if party not in _PARTIES or party in seen:
            raise ReceiptInvalid("chaque partie doit signer une fois")
        seen.add(party)
        public = _b64(entry.get("public_key"), _KEY_BYTES, f"cle publique ({party})")
        actual = hashlib.sha256(public).hexdigest()
        if not _same(entry.get("key_fingerprint"), actual):
            raise ReceiptInvalid(f"cle publique ({party}) differente de l'empreinte annoncee")
        if expected is not None and party in expected and not _same(expected[party], actual):
            raise ReceiptInvalid(f"empreinte de la cle ({party}) differente de celle attendue hors bande")
        signature = _b64(entry.get("signature"), _SIGNATURE_BYTES, f"signature ({party})")
        _check_ed25519(public, signature, message, f"signature ({party})")


def _check_events(content: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> None:
    try:
        verify_chain(events)
    except EventChainError as exc:
        raise ReceiptInvalid(f"chaine d'evenements invalide : {exc}") from exc
    chain = content.get("event_chain")
    if not isinstance(chain, dict) or not events:
        raise ReceiptInvalid("chaine d'evenements absente de la quittance ou de l'export")
    if any(event.get("contract_id") != content.get("contract_id") for event in events):
        raise ReceiptInvalid("evenements d'un autre contrat")
    length = chain.get("length")
    if isinstance(length, bool) or length != len(events):
        raise ReceiptInvalid("longueur de la chaine differente de la quittance")
    last = events[-1]
    if not _same(chain.get("head"), str(last.get("event_hash"))):
        raise ReceiptInvalid("tete de la chaine differente de la quittance")
    if last.get("event") != "sign_report" or last.get("to_status") != content.get("outcome"):
        raise ReceiptInvalid("le dernier evenement n'est pas la liberation")
    for index, event in enumerate(events, start=1):
        # Le payload expose doit etre celui que l'empreinte de l'evenement engage.
        if "payload" in event and not _same(event.get("payload_hash"), payload_fingerprint(event["payload"])):
            raise ReceiptInvalid(f"payload de l'evenement {index} different de son empreinte")
    if "payload" in last:
        payload = last["payload"]
        report = content.get("return_report")
        expected = report.get("hash") if isinstance(report, dict) else None
        if not isinstance(payload, dict) or not _same(payload.get("report_hash"), str(expected)):
            raise ReceiptInvalid("le dernier evenement ne porte pas l'empreinte du rapport de retour")


def _content(receipt: object, server_public_key: bytes) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ReceiptInvalid("quittance illisible")
    canonical = _canonical_bytes(receipt)
    _check_server(receipt, canonical, server_public_key)
    try:
        content = json.loads(canonical.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise ReceiptInvalid("contenu de la quittance illisible") from exc
    if not isinstance(content, dict) or content.get("schema") != SCHEMA:
        raise ReceiptInvalid("schema de quittance inconnu")
    return content


def verify_receipt(
    receipt: dict[str, Any],
    server_public_key: bytes,
    events: Sequence[Mapping[str, Any]] | None = None,
    party_fingerprints: Mapping[str, str] | None = None,
) -> None:
    """Leve ``ReceiptInvalid`` pour TOUT echec ; renvoie ``None`` si la quittance est verifiee.

    ``party_fingerprints`` (``{"owner": hex, "client": hex}``, obtenues hors bande) prouve l'identite des
    parties ; sans elle, seule la coherence des signatures avec les cles de la quittance est prouvee.
    """
    try:
        content = _content(receipt, server_public_key)
        _check_amounts(content)
        _check_parties(content, party_fingerprints)
        if events is not None:
            _check_events(content, events)
    except ReceiptInvalid:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise ReceiptInvalid("quittance ou export mal forme") from exc


def _read_json(path: str) -> object:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"fichier illisible : {path}") from exc


def _parse_fingerprints(raw: str | None) -> dict[str, str] | None:
    if raw is None:
        return None
    parsed: dict[str, str] = {}
    for item in raw.split(","):
        party, _, digest = item.partition("=")
        if party.strip() not in _PARTIES or not digest.strip():
            raise ValueError("--party-fingerprint attend owner=<hex>,client=<hex>")
        parsed[party.strip()] = digest.strip().lower()
    return parsed


def _read_events(path: str | None) -> list[Mapping[str, Any]] | None:
    if path is None:
        return None
    raw = _read_json(path)
    events = raw.get("events") if isinstance(raw, dict) else raw
    if not isinstance(events, list):
        raise TypeError("l'export d'evenements doit etre une liste ou {\"events\": [...]}")
    return events


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verifie hors ligne une quittance de liberation.")
    parser.add_argument("receipt", help="fichier JSON de la quittance")
    parser.add_argument("--events", help="export JSON de GET /api/contracts/<id>/events")
    parser.add_argument("--server-key", required=True, help="cle publique du serveur (base64, 32 octets)")
    parser.add_argument(
        "--party-fingerprint",
        help="empreintes attendues des cles des parties, obtenues hors bande : owner=<hex>,client=<hex>",
    )
    args = parser.parse_args(argv)
    try:
        receipt = _read_json(args.receipt)
        events = _read_events(args.events)
        server_key = _b64(args.server_key, _KEY_BYTES, "--server-key")
        expected = _parse_fingerprints(args.party_fingerprint)
        verify_receipt(cast(dict[str, Any], receipt), server_key, events, expected)
    except ReceiptInvalid as exc:
        sys.stderr.write(f"QUITTANCE INVALIDE : {exc}\n")
        return 1
    except (ValueError, TypeError) as exc:
        sys.stderr.write(f"Erreur : {exc}\n")
        return 2
    sys.stdout.write("Quittance verifiee : signatures, montants et chaine d'evenements concordent.\n")
    if expected is None:
        sys.stdout.write(
            "ATTENTION : l'identite des parties n'est PAS prouvee hors bande "
            "(utilisez --party-fingerprint owner=<hex>,client=<hex>).\n"
        )
    return 0
