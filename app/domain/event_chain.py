"""Chaine de hachage des evenements d'un contrat (domaine pur, sans Flask ni DB).

Format canonique (identique a la migration 0005 et a ``scripts/verify_receipt.py``) :
``event_hash = sha256(prev_hash + ":" + canonique(champs))`` ou ``champs`` contient exactement
``contract_id, seq, event, actor_id, from_status, to_status, payload_hash, created_at``.
"""

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

GENESIS: Final = "0" * 64
EVENT_TS_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.%fZ"
EVENT_FIELDS: Final = (
    "contract_id",
    "seq",
    "event",
    "actor_id",
    "from_status",
    "to_status",
    "payload_hash",
    "created_at",
)


class EventChainError(Exception):
    """La chaine d'evenements est rompue, incomplete ou falsifiee."""


def format_timestamp(moment: datetime) -> str:
    """Instant UTC, 6 chiffres de microsecondes, suffixe Z (``moment`` doit etre conscient du fuseau)."""
    if moment.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    return moment.astimezone(UTC).strftime(EVENT_TS_FORMAT)


def payload_fingerprint(payload: object) -> str:
    """SHA-256 du JSON canonique du payload EXACT stocke (``None`` si l'evenement n'en porte pas)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def compute_event_hash(prev_hash: str, fields: Mapping[str, Any]) -> str:
    try:
        body = {name: fields[name] for name in EVENT_FIELDS}
    except KeyError as exc:
        raise EventChainError(f"champ d'evenement manquant : {exc.args[0]}") from exc
    try:
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256((prev_hash + ":" + canonical).encode("utf-8")).hexdigest()
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EventChainError("evenement non serialisable") from exc


def _same(left: object, right: str) -> bool:
    return isinstance(left, str) and hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def verify_chain(events: Sequence[Mapping[str, Any]]) -> None:
    """Verifie la chaine ; liste vide = valide. Leve ``EventChainError`` au premier defaut."""
    previous = GENESIS
    contract_id: object = None
    for index, event in enumerate(events, start=1):
        if not isinstance(event, Mapping):
            raise EventChainError(f"evenement {index} illisible")
        seq = event.get("seq")
        if isinstance(seq, bool) or seq != index:
            raise EventChainError(f"numero de sequence inattendu a la position {index}")
        if index == 1:
            contract_id = event.get("contract_id")
        elif event.get("contract_id") != contract_id:
            raise EventChainError(f"evenement {index} d'un autre contrat")
        if not _same(event.get("prev_hash"), previous):
            raise EventChainError(f"chainage rompu a l'evenement {index}")
        expected = compute_event_hash(previous, event)
        if not _same(event.get("event_hash"), expected):
            raise EventChainError(f"empreinte invalide a l'evenement {index}")
        previous = expected
