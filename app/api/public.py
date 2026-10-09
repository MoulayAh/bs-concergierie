"""Routes publiques (sans authentification) : cle publique de signature du serveur."""

import base64
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Blueprint, Response, current_app, jsonify

from app.security import server_key

bp = Blueprint("public", __name__, url_prefix="/api")


@bp.get("/server-key")
def get_server_key() -> tuple[Response, int]:
    private = cast(Ed25519PrivateKey, current_app.extensions["server_signing_key"])
    public = server_key.public_key_bytes(private)
    body = {
        "public_key": base64.b64encode(public).decode("ascii"),
        "fingerprint": server_key.key_fingerprint(public),
    }
    return jsonify(body), 200
