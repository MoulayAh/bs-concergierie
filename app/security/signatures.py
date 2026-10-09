"""Cles publiques et signatures Ed25519 (le serveur ne detient jamais de cle privee)."""

import base64
import binascii
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.domain.errors import SignatureInvalid, ValidationFailed

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64


_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
# Ordonnees y des points d'ordre faible (liste libsodium) ; le bit de signe est ignore, donc les
# variantes avec bit de signe sont couvertes. y = 0 (ordre 4), 1 (neutre), p-1 (ordre 2) + deux d'ordre 8.
_SMALL_ORDER_Y = frozenset(
    {
        0,
        1,
        _P - 1,
        int.from_bytes(
            bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"
        ),
        int.from_bytes(
            bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little"
        ),
    }
)


def _is_weak_point(encoded: bytes) -> bool:
    """Vrai si l'encodage est non canonique (y >= p) ou designe un point d'ordre faible."""
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    return y >= _P or y in _SMALL_ORDER_Y


def decode_public_key(public_key_b64: str) -> bytes:
    """Decode une cle publique brute de 32 octets en base64 strict ; sinon ``ValidationFailed``."""
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationFailed("public_key doit etre une cle Ed25519 de 32 octets en base64") from exc
    if len(raw) != PUBLIC_KEY_BYTES:
        raise ValidationFailed("public_key doit faire exactement 32 octets")
    if _is_weak_point(raw):
        raise ValidationFailed("public_key refusee : point d'ordre faible ou encodage non canonique")
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ValidationFailed("public_key n'est pas une cle Ed25519 valide") from exc
    return raw


def key_fingerprint(raw_public_key: bytes) -> str:
    return hashlib.sha256(raw_public_key).hexdigest()


def verify_signature(public_key: bytes, message: bytes, signature_b64: str) -> None:
    """Leve ``SignatureInvalid`` pour TOUT echec (base64, longueur, cle, signature)."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureInvalid("Signature illisible (base64 attendu)") from exc
    if len(signature) != SIGNATURE_BYTES:
        raise SignatureInvalid("Une signature Ed25519 fait 64 octets")
    if _is_weak_point(signature[:32]) or int.from_bytes(signature[32:], "little") >= _L:
        raise SignatureInvalid("Signature non canonique ou d'ordre faible")
    if _is_weak_point(public_key):
        raise SignatureInvalid("Cle publique d'ordre faible")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise SignatureInvalid("La signature ne correspond pas a l'empreinte du rapport") from exc
