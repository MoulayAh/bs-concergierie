"""Cle de signature du serveur (Ed25519) : chargement, cle publique, empreinte (jamais dans un message)."""

import base64
import binascii
import hashlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SEED_BYTES = 32


class ServerKeyError(Exception):
    """Cle serveur absente ou mal formee (le message ne contient jamais la valeur fournie)."""


def load_private_key(seed_b64: object) -> Ed25519PrivateKey:
    if not isinstance(seed_b64, str):
        raise ServerKeyError("cle serveur absente")
    try:
        seed = base64.b64decode(seed_b64.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ServerKeyError("cle serveur : base64 invalide") from exc
    if len(seed) != SEED_BYTES:
        raise ServerKeyError(f"cle serveur : une graine de {SEED_BYTES} octets est attendue")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_fingerprint(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()


def generate_seed_b64() -> str:
    seed = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    return base64.b64encode(seed).decode("ascii")


if __name__ == "__main__":
    # `python -m app.security.server_key` : affiche une cle neuve, n'ecrit rien, ne cree pas l'application.
    sys.stdout.write(f"SERVER_SIGNING_KEY={generate_seed_b64()}\n")
