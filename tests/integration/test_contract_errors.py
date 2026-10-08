"""F1 : table "Cas d'erreur a couvrir" - code HTTP, format {"error": {"code", "message"}}, invariants.

Hypotheses : jeton absent/invalide -> 401 UNAUTHENTICATED ; Idempotency-Key absente a la creation ->
422 VALIDATION_ERROR ; 405 et 404 de routage renvoient aussi le JSON d'erreur standard.
"""

import uuid

import pytest
from flask import Blueprint

from tests.fixtures.helpers import VALID_BODY, Api, assert_error, count_rows, snapshot

pytestmark = pytest.mark.integration

AMOUNT_CODES = {"INVALID_AMOUNT", "VALIDATION_ERROR"}


def _assert_nothing_created(app, expected=0):
    assert count_rows(app, "Contract") == expected
    assert count_rows(app, "EscrowEvent") == expected


# --- montants ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("amount", [-1, 0, -50_000_000, 50_000_001, 2**31, 2**63, 10**30])
def test_create_refuses_out_of_range_amount_with_invalid_amount(app, api, owner_user, client_user, amount):
    resp = api.create(owner_user, {**VALID_BODY, "deposit_cents": amount})

    assert_error(resp, 422, "INVALID_AMOUNT")
    _assert_nothing_created(app)


@pytest.mark.parametrize("amount", ["100", "", 0.5, 100.0, True, False, None, [], {}, [1]], ids=repr)
def test_create_refuses_wrongly_typed_amount(app, api, owner_user, client_user, amount):
    resp = api.create(owner_user, {**VALID_BODY, "deposit_cents": amount})

    assert_error(resp, 422, codes=AMOUNT_CODES)
    _assert_nothing_created(app)


def test_create_refuses_missing_amount(app, api, owner_user, client_user):
    body = {k: v for k, v in VALID_BODY.items() if k != "deposit_cents"}

    resp = api.create(owner_user, body)

    assert_error(resp, 422, codes=AMOUNT_CODES)
    _assert_nothing_created(app)


@pytest.mark.parametrize("literal", ["1e309", "Infinity", "-Infinity", "NaN", "1e3", "2500000.0"])
def test_create_refuses_float_literals_in_raw_json(app, api, owner_user, client_user, literal):
    template = (
        '{"client_email":"client@demo.test","vehicle_label":"X","vehicle_plate":"AB-123-CD",'
        '"start_date":"2026-11-01","end_date":"2026-11-05","deposit_cents":AMOUNT,"currency":"EUR"}'
    )
    raw = template.replace("AMOUNT", literal)

    resp = api.create(owner_user, raw=raw, idem=uuid.uuid4().hex)

    assert_error(resp, 422, codes=AMOUNT_CODES)
    _assert_nothing_created(app)


# --- schema -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("currency", ["JPY", "eur", "EURO", "", "XXX", None, 978, True])
def test_create_refuses_currency_outside_whitelist(app, api, owner_user, client_user, currency):
    resp = api.create(owner_user, {**VALID_BODY, "currency": currency})

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ("2026-11-05", "2026-11-05"),
        ("2026-11-05", "2026-11-01"),
        ("2026-13-01", "2026-13-05"),
        ("2026-02-30", "2026-03-05"),
        ("01/11/2026", "05/11/2026"),
        ("not-a-date", "2026-11-05"),
        ("", ""),
        (20261101, 20261105),
        (None, None),
    ],
)
def test_create_refuses_invalid_period(app, api, owner_user, client_user, start, end):
    resp = api.create(owner_user, {**VALID_BODY, "start_date": start, "end_date": end})

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


@pytest.mark.parametrize("missing", [k for k in VALID_BODY if k != "deposit_cents"])
def test_create_refuses_missing_field(app, api, owner_user, client_user, missing):
    body = {k: v for k, v in VALID_BODY.items() if k != missing}

    resp = api.create(owner_user, body)

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


def test_create_refuses_unknown_field(app, api, owner_user, client_user):
    resp = api.create(owner_user, {**VALID_BODY, "status": "FUNDED"})

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


@pytest.mark.parametrize("field", ["vehicle_label", "vehicle_plate"])
@pytest.mark.parametrize(
    "value",
    ["", "   ", "x" * 1_000_000, 123, None, ["a"]],
    ids=["empty", "blank", "1MB", "int", "null", "list"],
)
def test_create_refuses_invalid_vehicle_text(app, api, owner_user, client_user, field, value):
    resp = api.create(owner_user, {**VALID_BODY, field: value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


def test_create_stores_sql_injection_in_label_as_plain_text(app, api, owner_user, client_user):
    label = "x'); DROP TABLE contracts; --"

    resp = api.create(owner_user, {**VALID_BODY, "vehicle_label": label})

    assert resp.status_code == 201
    assert resp.get_json()["vehicle"]["label"] == label
    assert count_rows(app, "Contract") == 1


@pytest.mark.parametrize(
    "raw",
    ['{"client_email": ', "{not json}", "", "[]", "null", '"text"', "42", "\x00\x01"],
    ids=["truncated", "garbage", "empty", "array", "null", "string", "number", "binary"],
)
def test_create_refuses_malformed_or_non_object_json(app, api, owner_user, client_user, raw):
    resp = api.create(owner_user, raw=raw)

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


def test_create_refuses_non_json_content_type(app, api, owner_user, client_user):
    resp = api.create(owner_user, raw="client_email=a", content_type="application/x-www-form-urlencoded")

    assert_error(resp, 422, codes={"VALIDATION_ERROR", "UNSUPPORTED_MEDIA_TYPE"})
    assert resp.status_code in {415, 422}
    _assert_nothing_created(app)


def test_create_refuses_one_megabyte_string_in_unknown_field(app, api, owner_user, client_user):
    resp = api.create(owner_user, {**VALID_BODY, "note": "A" * 1_048_576})

    assert resp.status_code in {413, 422}
    assert_error(resp, resp.status_code)
    _assert_nothing_created(app)


def test_create_refuses_body_above_max_content_length_with_413(app, api, owner_user, client_user):
    resp = api.create(owner_user, raw=b"{" + b" " * (11 * 1024 * 1024) + b"}")

    assert_error(resp, 413)
    _assert_nothing_created(app)


# --- parties ----------------------------------------------------------------------------------------------


def test_create_refuses_unknown_client_email(app, api, owner_user, client_user):
    resp = api.create(owner_user, {**VALID_BODY, "client_email": "ghost@demo.test"})

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


def test_create_refuses_owner_as_own_client(app, api, owner_user, client_user):
    resp = api.create(owner_user, {**VALID_BODY, "client_email": owner_user.email})

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


def test_create_refuses_malformed_client_email(app, api, owner_user, client_user):
    resp = api.create(owner_user, {**VALID_BODY, "client_email": "not-an-email"})

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


def test_client_cannot_create_contract_with_403(app, api, owner_user, client_user, stranger_user):
    resp = api.create(client_user, {**VALID_BODY, "client_email": stranger_user.email})

    assert_error(resp, 403, "FORBIDDEN_ACTOR")
    _assert_nothing_created(app)


def test_admin_cannot_create_contract_with_403(app, api, owner_user, client_user, admin_user):
    resp = api.create(admin_user)

    assert_error(resp, 403, "FORBIDDEN_ACTOR")
    _assert_nothing_created(app)


def test_create_requires_idempotency_key(app, api, owner_user, client_user):
    resp = api.request("POST", "/api/contracts", owner_user, body=VALID_BODY)

    assert_error(resp, 422, "VALIDATION_ERROR")
    _assert_nothing_created(app)


# --- authentification -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer not-a-real-token"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "bearer"},
        {"Authorization": "Bearer a b c"},
        {"Authorization": "Bearer " + "A" * 10_000},
    ],
    ids=["missing", "empty", "unknown", "basic", "no_token", "spaces", "huge"],
)
def test_every_route_refuses_missing_or_invalid_token_with_401(app, api, owner_user, client_user, headers):
    cid = api.create_ok(owner_user)["id"]
    before = snapshot(api, cid, owner_user)
    routes = [
        ("POST", "/api/contracts"),
        ("GET", f"/api/contracts/{cid}"),
        ("GET", f"/api/contracts/{cid}/events"),
        ("POST", f"/api/contracts/{cid}/sign"),
        ("POST", f"/api/contracts/{cid}/cancel"),
    ]

    for method, path in routes:
        body = VALID_BODY if path == "/api/contracts" else None
        resp = api.request(method, path, body=body, headers=headers)
        assert_error(resp, 401, "UNAUTHENTICATED")

    assert snapshot(api, cid, owner_user) == before
    assert count_rows(app, "Contract") == 1


def test_token_of_deleted_identity_is_refused(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    forged = owner_user.token[:-1] + ("A" if owner_user.token[-1] != "A" else "B")

    resp = api.request("GET", f"/api/contracts/{cid}", headers={"Authorization": f"Bearer {forged}"})

    assert_error(resp, 401, "UNAUTHENTICATED")


# --- 404 / IDOR -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("suffix", ["", "/events"])
def test_get_unknown_contract_returns_404(api, owner_user, suffix):
    resp = api.request("GET", f"/api/contracts/{uuid.uuid4()}{suffix}", owner_user)

    assert_error(resp, 404, "NOT_FOUND")


@pytest.mark.parametrize("action", ["sign", "cancel"])
def test_post_on_unknown_contract_returns_404(api, owner_user, action):
    resp = api.request("POST", f"/api/contracts/{uuid.uuid4()}/{action}", owner_user, idem=uuid.uuid4().hex)

    assert_error(resp, 404, "NOT_FOUND")


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "1", "../../etc/passwd", "%27%20OR%201%3D1", "0" * 300])
def test_malformed_contract_id_returns_404_not_500(api, owner_user, bad_id):
    resp = api.request("GET", f"/api/contracts/{bad_id}", owner_user)

    assert_error(resp, 404, "NOT_FOUND")


@pytest.mark.parametrize("who", ["stranger", "admin"])
def test_non_party_gets_404_everywhere_and_contract_is_untouched(
    api, owner_user, client_user, stranger_user, admin_user, who
):
    cid = api.create_ok(owner_user)["id"]
    before = snapshot(api, cid, owner_user)
    outsider = {"stranger": stranger_user, "admin": admin_user}[who]

    for resp in (
        api.get(cid, outsider),
        api.events(cid, outsider),
        api.sign(cid, outsider),
        api.cancel(cid, outsider),
    ):
        assert_error(resp, 404, "NOT_FOUND")

    assert snapshot(api, cid, owner_user) == before


def test_idor_response_is_indistinguishable_from_unknown_contract(
    api, owner_user, client_user, stranger_user
):
    cid = api.create_ok(owner_user)["id"]

    foreign = api.get(cid, stranger_user)
    unknown = api.get(str(uuid.uuid4()), stranger_user)

    assert foreign.status_code == unknown.status_code == 404
    assert foreign.get_json() == unknown.get_json()


def test_other_owner_cannot_see_contract_of_first_owner(api, make_user, owner_user, client_user):
    other_owner = make_user("owner")
    cid = api.create_ok(owner_user)["id"]

    assert_error(api.get(cid, other_owner), 404, "NOT_FOUND")
    assert_error(api.cancel(cid, other_owner), 404, "NOT_FOUND")


# --- cancel : corps ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [{"reason": "x" * 501}, {"reason": 123}, {"reason": None}, {"reason": ["a"]}, {"unknown": 1}, [], "text"],
    ids=["too_long", "int", "null", "list", "extra_field", "array", "string"],
)
def test_cancel_refuses_invalid_body_and_keeps_state(api, owner_user, client_user, body):
    cid = api.create_ok(owner_user)["id"]
    before = snapshot(api, cid, owner_user)

    resp = api.cancel(cid, owner_user, body)

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snapshot(api, cid, owner_user) == before


def test_cancel_refuses_malformed_json_and_keeps_state(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    before = snapshot(api, cid, owner_user)

    resp = api.request("POST", f"/api/contracts/{cid}/cancel", owner_user, raw="{oops", idem=uuid.uuid4().hex)

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snapshot(api, cid, owner_user) == before


# --- methodes interdites ----------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["PATCH", "PUT", "DELETE"])
def test_modifying_a_contract_is_405_json_and_contract_unchanged(api, owner_user, client_user, method):
    cid = api.create_ok(owner_user)["id"]
    before = snapshot(api, cid, owner_user)
    contract_before = api.get(cid, owner_user).get_json()

    resp = api.request(method, f"/api/contracts/{cid}", owner_user, body={"deposit_cents": 1})

    assert_error(resp, 405)
    assert api.get(cid, owner_user).get_json() == contract_before
    assert snapshot(api, cid, owner_user) == before


@pytest.mark.parametrize("method", ["PATCH", "PUT", "DELETE"])
def test_modifying_without_token_is_still_json_error_not_html(api, owner_user, client_user, method):
    cid = api.create_ok(owner_user)["id"]

    resp = api.request(method, f"/api/contracts/{cid}", None, body={"deposit_cents": 1})

    assert resp.is_json
    assert resp.status_code in {401, 405}
    assert_error(resp, resp.status_code)


def test_get_on_post_only_route_is_405_json(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]

    resp = api.request("GET", f"/api/contracts/{cid}/sign", owner_user)

    assert_error(resp, 405)


def test_unknown_route_returns_json_404(api, owner_user):
    resp = api.request("GET", "/api/does-not-exist", owner_user)

    assert_error(resp, 404)


# --- format d'erreur global -------------------------------------------------------------------------------


def test_error_payload_format(api, owner_user, client_user, stranger_user):
    """Toutes les familles d'erreur partagent le meme enveloppe, sans trace ni detail interne."""
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, owner_user)
    responses = [
        (api.request("GET", f"/api/contracts/{cid}"), 401),
        (api.create(client_user, {**VALID_BODY, "client_email": stranger_user.email}), 403),
        (api.get(str(uuid.uuid4()), owner_user), 404),
        (api.request("PATCH", f"/api/contracts/{cid}", owner_user, body={}), 405),
        (api.sign(cid, owner_user), 409),
        (api.create(owner_user, {**VALID_BODY, "deposit_cents": -1}), 422),
        (api.create(owner_user, raw="{"), 422),
    ]

    for resp, status in responses:
        err = assert_error(resp, status)
        assert resp.mimetype == "application/json"
        assert isinstance(err["message"], str)


def test_error_codes_match_contract_table(api, owner_user, client_user, stranger_user):
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, owner_user)

    assert_error(api.request("GET", f"/api/contracts/{cid}"), 401, "UNAUTHENTICATED")
    assert_error(api.create(client_user), 403, "FORBIDDEN_ACTOR")
    assert_error(api.get(cid, stranger_user), 404, "NOT_FOUND")
    assert_error(api.sign(cid, owner_user), 409, "INVALID_TRANSITION")
    assert_error(api.create(owner_user, {**VALID_BODY, "deposit_cents": 0}), 422, "INVALID_AMOUNT")
    assert_error(api.create(owner_user, {**VALID_BODY, "currency": "JPY"}), 422, "VALIDATION_ERROR")


def test_internal_failure_is_json_500_without_stacktrace(app, owner_user):
    """Filet de securite du handler global : une exception inattendue ne fuit jamais de trace."""
    boom = Blueprint("boom", __name__)

    @boom.route("/__boom")
    def _boom():
        raise RuntimeError("secret internal detail")

    app.register_blueprint(boom)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.testing = False
    client = Api(app)

    resp = client.request("GET", "/__boom", owner_user)

    err = assert_error(resp, 500)
    assert "secret internal detail" not in resp.get_data(as_text=True)
    assert err["code"]
