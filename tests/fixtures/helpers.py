"""Aides de test : client HTTP JSON, utilisateurs, assertions sur le format d'erreur et l'invariant d'etat."""

import json
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.extensions import db
from app.models import Contract, EscrowEvent, IdempotencyKey, User

MODELS: dict[str, Any] = {
    "Contract": Contract,
    "EscrowEvent": EscrowEvent,
    "IdempotencyKey": IdempotencyKey,
    "User": User,
}

VALID_BODY: dict[str, Any] = {
    "client_email": "client@demo.test",
    "vehicle_label": "Audi RS6 Avant",
    "vehicle_plate": "AB-123-CD",
    "start_date": "2026-11-01",
    "end_date": "2026-11-05",
    "deposit_cents": 2_500_000,
    "currency": "EUR",
}


DEPOSIT_BODY: dict[str, Any] = {
    "amount_cents": 2_500_000,
    "currency": "EUR",
    "payment_method": "demo_card_ok",
}


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_key() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class TestUser:
    __test__ = False  # pas une classe de test pour pytest

    id: str
    email: str
    role: str
    token: str
    headers: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", {"Authorization": f"Bearer {self.token}"})


class Api:
    """Enveloppe du client de test Flask. Chaque instance a son propre client (utile pour les threads)."""

    def __init__(self, app: Flask) -> None:
        self.app = app
        self.http: FlaskClient = app.test_client()

    def request(
        self,
        method: str,
        path: str,
        user: TestUser | None = None,
        body: Any = None,
        raw: str | bytes | None = None,
        content_type: str | None = None,
        idem: str | None = None,
        headers: dict[str, str] | None = None,
    ):
        hdrs: dict[str, str] = dict(user.headers) if user else {}
        if idem is not None:
            hdrs["Idempotency-Key"] = idem
        if headers:
            hdrs.update(headers)
        kwargs: dict[str, Any] = {"headers": hdrs}
        if raw is not None:
            kwargs["data"] = raw
            kwargs["content_type"] = content_type or "application/json"
        elif body is not None:
            kwargs["data"] = json.dumps(body)
            kwargs["content_type"] = content_type or "application/json"
        return self.http.open(path, method=method, **kwargs)

    def create(
        self, user: TestUser | None, body: dict[str, Any] | None = None, idem: str | None = None, **kw: Any
    ):
        payload = dict(VALID_BODY) if body is None else body
        key = idem if idem is not None else new_key()
        return self.request("POST", "/api/contracts", user, body=payload, idem=key, **kw)

    def create_ok(self, user: TestUser, body: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self.create(user, body)
        assert resp.status_code == 201, resp.get_data(as_text=True)
        return resp.get_json()

    def get(self, contract_id: str, user: TestUser | None):
        return self.request("GET", f"/api/contracts/{contract_id}", user)

    def events(self, contract_id: str, user: TestUser | None):
        return self.request("GET", f"/api/contracts/{contract_id}/events", user)

    def sign(self, contract_id: str, user: TestUser | None, idem: str | None = None):
        key = idem if idem is not None else new_key()
        return self.request("POST", f"/api/contracts/{contract_id}/sign", user, idem=key)

    def cancel(self, contract_id: str, user: TestUser | None, body: Any = None, idem: str | None = None):
        path = f"/api/contracts/{contract_id}/cancel"
        return self.request("POST", path, user, body=body, idem=idem if idem is not None else new_key())

    def deposit(
        self,
        contract_id: str,
        user: TestUser | None,
        body: Any = None,
        idem: str | None = None,
        no_key: bool = False,
    ):
        """POST /deposit. Corps par defaut : DEPOSIT_BODY ; ``no_key=True`` omet l'Idempotency-Key."""
        payload = dict(DEPOSIT_BODY) if body is None else body
        key = None if no_key else (idem if idem is not None else new_key())
        return self.request("POST", f"/api/contracts/{contract_id}/deposit", user, body=payload, idem=key)

    def get_deposit(self, contract_id: str, user: TestUser | None):
        return self.request("GET", f"/api/contracts/{contract_id}/deposit", user)

    def start(self, contract_id: str, user: TestUser | None, idem: str | None = None):
        key = idem if idem is not None else new_key()
        return self.request("POST", f"/api/contracts/{contract_id}/start", user, idem=key)


def assert_error(
    resp: Any, status: int, code: str | None = None, codes: set[str] | None = None
) -> dict[str, Any]:
    """Verifie le code HTTP ET le format {"error": {"code", "message"}} sans trace."""
    text = resp.get_data(as_text=True)
    assert resp.status_code == status, f"attendu {status}, recu {resp.status_code}: {text}"
    assert resp.is_json, f"reponse non JSON: {text[:200]}"
    payload = resp.get_json()
    assert set(payload.keys()) == {"error"}, payload
    err = payload["error"]
    assert isinstance(err, dict)
    assert isinstance(err.get("code"), str)
    assert err["code"]
    assert isinstance(err.get("message"), str)
    assert err["message"]
    assert set(err.keys()) <= {"code", "message", "details"}, err
    for marker in ("Traceback", 'File "', "sqlalchemy", "psycopg"):
        assert marker not in text, f"fuite technique ({marker}) dans {text[:200]}"
    if code is not None:
        assert err["code"] == code, err
    if codes is not None:
        assert err["code"] in codes, err
    return err


def snapshot(api: Api, contract_id: str, user: TestUser) -> tuple[str, int, int]:
    """(statut, version, nombre d'evenements) vus par une partie."""
    contract = api.get(contract_id, user)
    assert contract.status_code == 200, contract.get_data(as_text=True)
    events = api.events(contract_id, user)
    assert events.status_code == 200, events.get_data(as_text=True)
    data = contract.get_json()
    return data["status"], data["version"], len(events.get_json()["events"])


def count_rows(app: Flask, model_name: str) -> int:
    model = MODELS[model_name]
    with app.app_context():
        return int(db.session.scalar(select(func.count()).select_from(model)) or 0)
