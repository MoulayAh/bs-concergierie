"""F1 : creation, consultation, signature, annulation, journal d'evenements.

Formats supposes :
- GET /api/contracts/<id>/events -> {"events": [{"event", "actor_id", "from_status", "to_status",
  "payload_hash", "created_at"}, ...]} dans l'ordre chronologique.
- Evenements F1 : "create" (from None -> DRAFT), "sign_contract", "cancel".
- Chaque transition incremente ``version`` de 1 (creation => version 1).
"""

import re
import uuid

import pytest

from app.extensions import db
from app.models import User
from tests.fixtures.helpers import VALID_BODY, assert_error, count_rows, snapshot

pytestmark = pytest.mark.integration


def test_create_contract_returns_201_and_draft(api, owner_user, client_user):
    resp = api.create(owner_user)

    assert resp.status_code == 201
    assert resp.is_json
    data = resp.get_json()
    assert uuid.UUID(data["id"])
    assert data["status"] == "DRAFT"
    assert data["version"] == 1
    assert data["owner"]["id"] == owner_user.id
    assert data["client"]["id"] == client_user.id
    assert set(data["owner"]) == {"id", "display_name"}
    assert set(data["client"]) == {"id", "display_name"}
    assert data["vehicle"] == {"label": "Audi RS6 Avant", "plate": "AB-123-CD"}
    assert data["period"] == {"start": "2026-11-01", "end": "2026-11-05"}
    assert data["deposit"] == {"amount_cents": 2_500_000, "currency": "EUR"}
    assert data["signatures"] == {"owner": None, "client": None}


def test_create_contract_exposes_amount_as_integer_cents(api, owner_user, client_user):
    data = api.create_ok(owner_user)

    assert type(data["deposit"]["amount_cents"]) is int


@pytest.mark.parametrize("amount", [1, 50_000_000])
def test_create_contract_accepts_deposit_bounds(api, owner_user, client_user, amount):
    resp = api.create(owner_user, {**VALID_BODY, "deposit_cents": amount})

    assert resp.status_code == 201
    assert resp.get_json()["deposit"]["amount_cents"] == amount


@pytest.mark.parametrize("currency", ["EUR", "CHF", "GBP", "USD"])
def test_create_contract_accepts_whitelisted_currencies(api, owner_user, client_user, currency):
    resp = api.create(owner_user, {**VALID_BODY, "currency": currency})

    assert resp.status_code == 201
    assert resp.get_json()["deposit"]["currency"] == currency


def test_create_contract_writes_a_single_create_event(api, owner_user, client_user):
    contract = api.create_ok(owner_user)

    events = api.events(contract["id"], owner_user).get_json()["events"]

    assert len(events) == 1
    assert events[0]["event"] == "create"
    assert events[0]["from_status"] is None
    assert events[0]["to_status"] == "DRAFT"
    assert events[0]["actor_id"] == owner_user.id


def test_get_contract_is_visible_to_both_parties(api, owner_user, client_user):
    contract = api.create_ok(owner_user)

    for user in (owner_user, client_user):
        resp = api.get(contract["id"], user)
        assert resp.status_code == 200
        assert resp.get_json() == contract


def test_sign_by_both_parties_moves_to_awaiting_deposit(api, owner_user, client_user):
    contract = api.create_ok(owner_user)
    cid = contract["id"]

    first = api.sign(cid, client_user)
    assert first.status_code == 200
    assert first.get_json()["status"] == "DRAFT"
    assert first.get_json()["signatures"]["client"] is not None
    assert first.get_json()["signatures"]["owner"] is None
    assert first.get_json()["version"] == 2

    second = api.sign(cid, owner_user)
    assert second.status_code == 200
    body = second.get_json()
    assert body["status"] == "AWAITING_DEPOSIT"
    assert body["signatures"]["client"] is not None
    assert body["signatures"]["owner"] is not None
    assert body["version"] == 3
    assert api.get(cid, client_user).get_json()["status"] == "AWAITING_DEPOSIT"


def test_sign_order_owner_first_also_reaches_awaiting_deposit(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]

    assert api.sign(cid, owner_user).get_json()["status"] == "DRAFT"
    assert api.sign(cid, client_user).get_json()["status"] == "AWAITING_DEPOSIT"


def test_sign_timestamp_is_iso_8601(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]

    stamp = api.sign(cid, owner_user).get_json()["signatures"]["owner"]

    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", stamp)


@pytest.mark.parametrize("signers", [[], ["client"]], ids=["no_signature", "one_signature"])
def test_cancel_in_draft(api, owner_user, client_user, signers):
    cid = api.create_ok(owner_user)["id"]
    users = {"owner": owner_user, "client": client_user}
    for name in signers:
        assert api.sign(cid, users[name]).status_code == 200

    resp = api.cancel(cid, client_user, {"reason": "changement de plan"})

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "CANCELLED"


@pytest.mark.parametrize("canceller", ["owner", "client"])
def test_cancel_in_awaiting_deposit(api, owner_user, client_user, canceller):
    cid = api.create_ok(owner_user)["id"]
    api.sign(cid, owner_user)
    api.sign(cid, client_user)
    user = {"owner": owner_user, "client": client_user}[canceller]

    resp = api.cancel(cid, user)

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "CANCELLED"


def test_cancel_without_body_is_accepted(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]

    assert api.cancel(cid, owner_user).status_code == 200


def test_cancel_accepts_reason_of_500_characters(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]

    assert api.cancel(cid, owner_user, {"reason": "x" * 500}).status_code == 200


def test_events_written_for_each_transition(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.sign(cid, client_user)
    api.sign(cid, owner_user)
    api.cancel(cid, owner_user)

    events = api.events(cid, owner_user).get_json()["events"]

    assert [(e["event"], e["from_status"], e["to_status"]) for e in events] == [
        ("create", None, "DRAFT"),
        ("sign_contract", "DRAFT", "DRAFT"),
        ("sign_contract", "DRAFT", "AWAITING_DEPOSIT"),
        ("cancel", "AWAITING_DEPOSIT", "CANCELLED"),
    ]
    assert [e["actor_id"] for e in events] == [owner_user.id, client_user.id, owner_user.id, owner_user.id]
    assert all(e["created_at"] for e in events)
    assert api.get(cid, owner_user).get_json()["version"] == len(events)


def test_events_are_visible_to_both_parties_and_identical(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.sign(cid, client_user)

    as_owner = api.events(cid, owner_user).get_json()
    as_client = api.events(cid, client_user).get_json()

    assert as_owner == as_client


def test_each_transition_appends_events(api, app, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    before = count_rows(app, "EscrowEvent")
    api.sign(cid, client_user)
    api.cancel(cid, client_user)

    assert count_rows(app, "EscrowEvent") == before + 2


@pytest.mark.parametrize("action", ["sign", "cancel"])
@pytest.mark.parametrize("actor", ["owner", "client"])
def test_any_event_on_cancelled_contract_is_invalid_transition(api, owner_user, client_user, action, actor):
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, owner_user)
    user = {"owner": owner_user, "client": client_user}[actor]
    before = snapshot(api, cid, owner_user)

    resp = getattr(api, action)(cid, user)

    assert_error(resp, 409, "INVALID_TRANSITION")
    assert snapshot(api, cid, owner_user) == before


@pytest.mark.parametrize("actor", ["owner", "client"])
def test_same_party_signing_twice_is_invalid_transition(api, owner_user, client_user, actor):
    cid = api.create_ok(owner_user)["id"]
    user = {"owner": owner_user, "client": client_user}[actor]
    assert api.sign(cid, user).status_code == 200
    before = snapshot(api, cid, owner_user)

    resp = api.sign(cid, user)

    assert_error(resp, 409, "INVALID_TRANSITION")
    assert snapshot(api, cid, owner_user) == before


def test_sign_in_awaiting_deposit_is_invalid_transition(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.sign(cid, owner_user)
    api.sign(cid, client_user)
    before = snapshot(api, cid, owner_user)

    resp = api.sign(cid, owner_user)

    assert_error(resp, 409, "INVALID_TRANSITION")
    assert snapshot(api, cid, owner_user) == before
    assert before[0] == "AWAITING_DEPOSIT"


def test_seed_demo_command_creates_owner_and_client_idempotently(app):
    runner = app.test_cli_runner()

    first = runner.invoke(args=["seed-demo"])
    second = runner.invoke(args=["seed-demo"])

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert count_rows(app, "User") >= 2
    count_after_first_run = count_rows(app, "User")
    third = runner.invoke(args=["seed-demo"])
    assert third.exit_code == 0
    assert count_rows(app, "User") == count_after_first_run


def test_api_token_is_stored_hashed_never_in_clear(app, owner_user):
    with app.app_context():
        user = db.session.get(User, uuid.UUID(owner_user.id))
        assert user is not None
        stored = user.api_token_hash

    assert stored
    assert stored != owner_user.token
    assert owner_user.token not in stored
