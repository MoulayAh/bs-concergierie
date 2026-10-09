"""F3 : enregistrement et revocation des cles publiques Ed25519 (``/api/me/keys``).

Interfaces supposees : voir l'en-tete de tests/fixtures/reports.py.
"""

import base64

import pytest

from tests.fixtures.helpers import assert_error
from tests.fixtures.reports import KeyPair, register_key

pytestmark = pytest.mark.integration


def _keys(api, user):
    resp = api.request("GET", "/api/me/keys", user)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["keys"]


def test_register_key_returns_201_with_fingerprint(api, owner_user):
    pair = KeyPair()

    resp = register_key(api, owner_user, pair.public_b64)

    assert resp.status_code == 201, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["public_key"] == pair.public_b64
    assert data["fingerprint"] == pair.fingerprint
    assert data["revoked_at"] is None
    assert data["id"]
    assert "private" not in " ".join(data.keys())


def test_list_keys_returns_only_own_keys(api, owner_user, client_user):
    mine = KeyPair()
    register_key(api, owner_user, mine.public_b64)
    register_key(api, client_user, KeyPair().public_b64)

    keys = _keys(api, owner_user)

    assert [k["public_key"] for k in keys] == [mine.public_b64]


def test_second_active_key_is_key_already_active(api, owner_user):
    register_key(api, owner_user, KeyPair().public_b64)

    assert_error(register_key(api, owner_user, KeyPair().public_b64), 409, "KEY_ALREADY_ACTIVE")

    assert len(_keys(api, owner_user)) == 1


def test_revoking_a_key_allows_registering_a_new_one(api, owner_user):
    first = register_key(api, owner_user, KeyPair().public_b64).get_json()

    revoked = api.request("DELETE", f"/api/me/keys/{first['id']}", owner_user)
    second = register_key(api, owner_user, KeyPair().public_b64)

    assert revoked.status_code == 204
    assert revoked.get_data() == b""
    assert second.status_code == 201
    keys = {k["id"]: k for k in _keys(api, owner_user)}
    assert keys[first["id"]]["revoked_at"] is not None
    assert keys[second.get_json()["id"]]["revoked_at"] is None


def test_revoking_someone_elses_key_is_not_found(api, owner_user, client_user):
    key = register_key(api, owner_user, KeyPair().public_b64).get_json()

    assert_error(api.request("DELETE", f"/api/me/keys/{key['id']}", client_user), 404, "NOT_FOUND")

    assert _keys(api, owner_user)[0]["revoked_at"] is None


def test_revoking_unknown_key_is_not_found(api, owner_user):
    resp = api.request("DELETE", "/api/me/keys/00000000-0000-4000-8000-000000000000", owner_user)

    assert_error(resp, 404, "NOT_FOUND")


@pytest.mark.parametrize("length", [0, 1, 31, 33, 64])
def test_key_of_wrong_length_is_validation_error(api, owner_user, length):
    value = base64.b64encode(b"\x05" * length).decode()

    assert_error(register_key(api, owner_user, value), 422, "VALIDATION_ERROR")

    assert _keys(api, owner_user) == []


@pytest.mark.parametrize("value", ["", "!!!", "%%%%", None, 42, 1.5, True, ["a"], {"k": 1}])
def test_malformed_key_value_is_validation_error(api, owner_user, value):
    assert_error(register_key(api, owner_user, value), 422, "VALIDATION_ERROR")

    assert _keys(api, owner_user) == []


@pytest.mark.parametrize("body", [{}, {"public_key": KeyPair().public_b64, "extra": 1}, []])
def test_key_body_with_missing_or_extra_fields_is_validation_error(api, owner_user, body):
    resp = api.request("POST", "/api/me/keys", owner_user, body=body)

    assert_error(resp, 422, "VALIDATION_ERROR")


def test_key_already_used_by_another_account_is_validation_error(api, owner_user, client_user):
    pair = KeyPair()
    assert register_key(api, owner_user, pair.public_b64).status_code == 201

    assert_error(register_key(api, client_user, pair.public_b64), 422, "VALIDATION_ERROR")

    assert _keys(api, client_user) == []


def test_keys_routes_require_authentication(api):
    assert_error(register_key(api, None, KeyPair().public_b64), 401, "UNAUTHENTICATED")
    assert_error(api.request("GET", "/api/me/keys", None), 401, "UNAUTHENTICATED")
    assert_error(
        api.request("DELETE", "/api/me/keys/00000000-0000-4000-8000-000000000000", None),
        401,
        "UNAUTHENTICATED",
    )
