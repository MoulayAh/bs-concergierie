"""Quittance de liberation : canonisation, empreinte, message signe par le serveur (domaine pur)."""

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final

SCHEMA: Final = "luxe-escrow/receipt/v1"
RECEIPT_PREFIX: Final = b"luxe-escrow:receipt:v1:"


def canonical_receipt(content: Mapping[str, Any]) -> bytes:
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def receipt_hash(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()


def receipt_signing_message(digest: str) -> bytes:
    """Message signe par le serveur, avec separation de domaine (prefixe versionne)."""
    return RECEIPT_PREFIX + digest.encode("ascii")
