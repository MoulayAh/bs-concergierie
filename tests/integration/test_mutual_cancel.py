"""F2 : annulation mutuelle (FUNDED -> REFUNDED), remise du vehicule (FUNDED -> ACTIVE), annulation tardive.

Interfaces supposees : voir ``tests/fixtures/deposits.py`` (evenements ``cancel`` / ``start_rental``,
sortie ``funds`` / ``cancellation``, remboursement via ``PaymentProvider.refund(ref)``).
"""

import pytest

from tests.fixtures.deposits import (
    awaiting_deposit_contract,
    deposit_rows,
    full_state,
    funded_contract,
    run_concurrently,
)
from tests.fixtures.helpers import assert_error
from tests.fixtures.reports import signed_checkout, start_signed

pytestmark = pytest.mark.integration

AMOUNT = 2_500_000
HELD = {
    "deposit_status": "HELD",
    "amount_cents": AMOUNT,
    "held_cents": AMOUNT,
    "refunded_cents": 0,
    "released_cents": 0,
    "retained_cents": 0,
    "currency": "EUR",
}


@pytest.fixture
def funded(api, owner_user, client_user, provider) -> str:
    return funded_contract(api, owner_user, client_user)


def _assert_unchanged(app, api, cid, user, before):
    assert full_state(app, api, cid, user) == before


# ---------------------------------------------------------------- annulation mutuelle


@pytest.mark.parametrize("order", ["client_first", "owner_first"])
def test_mutual_cancel_after_contract_signed(api, owner_user, client_user, funded, order):
    """Non-regression dette F1 : les approbations sont par evenement, pas deduites des signatures."""
    first, second = (client_user, owner_user) if order == "client_first" else (owner_user, client_user)
    version = api.get(funded, owner_user).get_json()["version"]

    one = api.cancel(funded, first)

    assert one.status_code == 200, one.get_data(as_text=True)
    data = one.get_json()
    assert data["status"] == "FUNDED"
    assert data["version"] == version + 1
    expected = {"owner_approved": first is owner_user, "client_approved": first is client_user}
    assert data["cancellation"] == expected
    assert data["funds"] == HELD

    two = api.cancel(funded, second)

    assert two.status_code == 200, two.get_data(as_text=True)
    done = two.get_json()
    assert done["status"] == "REFUNDED"
    assert done["version"] == version + 2
    assert done["funds"]["refunded_cents"] == done["funds"]["amount_cents"] == AMOUNT
    assert done["funds"]["held_cents"] == 0


def test_mutual_cancel_refunds_in_full(app, api, owner_user, client_user, funded, provider):
    ref = deposit_rows(app, funded)[0]["provider_ref"]
    api.cancel(funded, client_user)

    resp = api.cancel(funded, owner_user)

    assert resp.status_code == 200
    funds = resp.get_json()["funds"]
    assert funds == {**HELD, "deposit_status": "REFUNDED", "held_cents": 0, "refunded_cents": AMOUNT}
    row = deposit_rows(app, funded)[0]
    assert row["status"] == "REFUNDED"
    assert (row["held_cents"], row["refunded_cents"], row["released_cents"], row["retained_cents"]) == (
        0,
        AMOUNT,
        0,
        0,
    )
    assert provider.refund_calls == [ref]
    events = api.events(funded, owner_user).get_json()["events"]
    assert [(e["event"], e["from_status"], e["to_status"]) for e in events[-2:]] == [
        ("cancel", "FUNDED", "FUNDED"),
        ("cancel", "FUNDED", "REFUNDED"),
    ]
    assert api.get_deposit(funded, client_user).get_json() == funds


def test_unilateral_cancel_in_funded_keeps_funds_held(app, api, owner_user, client_user, funded, provider):
    resp = api.cancel(funded, client_user)

    assert resp.status_code == 200
    assert resp.get_json()["funds"] == HELD
    assert deposit_rows(app, funded)[0]["held_cents"] == AMOUNT
    assert provider.refund_calls == []
    assert api.get_deposit(funded, owner_user).get_json() == HELD
    assert api.get(funded, owner_user).get_json()["cancellation"] == {
        "owner_approved": False,
        "client_approved": True,
    }


@pytest.mark.parametrize("who", ["owner", "client"])
def test_same_party_approving_cancel_twice_is_invalid_transition(
    app, api, owner_user, client_user, funded, provider, who
):
    user = owner_user if who == "owner" else client_user
    assert api.cancel(funded, user).status_code == 200
    before = full_state(app, api, funded, owner_user)

    assert_error(api.cancel(funded, user), 409, "INVALID_TRANSITION")

    _assert_unchanged(app, api, funded, owner_user, before)
    assert provider.refund_calls == []


def test_cancel_on_refunded_is_invalid_transition(app, api, owner_user, client_user, funded, provider):
    api.cancel(funded, client_user)
    api.cancel(funded, owner_user)
    before = full_state(app, api, funded, owner_user)

    for user in (owner_user, client_user):
        assert_error(api.cancel(funded, user), 409, "INVALID_TRANSITION")

    _assert_unchanged(app, api, funded, owner_user, before)
    assert len(provider.refund_calls) == 1


def test_cancel_by_third_party_is_not_found_and_changes_nothing(app, api, owner_user, stranger_user, funded):
    before = full_state(app, api, funded, owner_user)

    assert_error(api.cancel(funded, stranger_user), 404, "NOT_FOUND")

    _assert_unchanged(app, api, funded, owner_user, before)


@pytest.mark.parametrize("who", ["owner", "client"])
def test_cancel_in_awaiting_deposit_has_no_fund(app, api, owner_user, client_user, provider, who):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    user = owner_user if who == "owner" else client_user

    resp = api.cancel(cid, user)

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "CANCELLED"
    assert deposit_rows(app, cid) == []
    assert provider.refund_calls == []
    assert provider.hold_calls == []


# ---------------------------------------------------------------- remise du vehicule


def test_start_rental_by_owner_moves_to_active_and_keeps_funds(
    app, api, keyring, owner_user, client_user, funded
):
    signed_checkout(api, keyring, funded, owner_user, client_user)  # F3 : depart double-signe requis
    version = api.get(funded, owner_user).get_json()["version"]

    resp = api.start(funded, owner_user)

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["status"] == "ACTIVE"
    assert data["version"] == version + 1
    assert data["funds"] == HELD
    assert deposit_rows(app, funded)[0]["held_cents"] == AMOUNT
    last = api.events(funded, client_user).get_json()["events"][-1]
    assert (last["event"], last["from_status"], last["to_status"]) == ("start_rental", "FUNDED", "ACTIVE")
    assert last["actor_id"] == owner_user.id


def test_start_rental_by_client_is_forbidden_actor(app, api, owner_user, client_user, funded):
    before = full_state(app, api, funded, owner_user)

    assert_error(api.start(funded, client_user), 403, "FORBIDDEN_ACTOR")

    _assert_unchanged(app, api, funded, owner_user, before)


def test_start_rental_by_third_party_is_not_found(app, api, owner_user, stranger_user, funded):
    before = full_state(app, api, funded, owner_user)

    assert_error(api.start(funded, stranger_user), 404, "NOT_FOUND")

    _assert_unchanged(app, api, funded, owner_user, before)


def test_start_rental_without_credentials_is_unauthenticated(api, funded):
    assert_error(api.start(funded, None), 401, "UNAUTHENTICATED")


def test_start_rental_on_unknown_contract_is_not_found(api, owner_user):
    assert_error(api.start("00000000-0000-4000-8000-000000000000", owner_user), 404, "NOT_FOUND")


def test_start_rental_in_awaiting_deposit_is_invalid_transition(app, api, owner_user, client_user):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, owner_user)

    assert_error(api.start(cid, owner_user), 409, "INVALID_TRANSITION")

    _assert_unchanged(app, api, cid, owner_user, before)


def test_start_rental_in_draft_is_invalid_transition(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    before = full_state(app, api, cid, owner_user)

    assert_error(api.start(cid, owner_user), 409, "INVALID_TRANSITION")

    _assert_unchanged(app, api, cid, owner_user, before)


def test_start_rental_twice_is_invalid_transition(app, api, keyring, owner_user, client_user, funded):
    assert start_signed(api, keyring, funded, owner_user, client_user).status_code == 200
    before = full_state(app, api, funded, owner_user)

    assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")

    _assert_unchanged(app, api, funded, owner_user, before)


def test_start_rental_after_refund_is_invalid_transition(app, api, owner_user, client_user, funded):
    api.cancel(funded, client_user)
    api.cancel(funded, owner_user)
    before = full_state(app, api, funded, owner_user)

    assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")

    _assert_unchanged(app, api, funded, owner_user, before)


@pytest.mark.parametrize("requester", ["client", "owner"])
def test_start_rental_blocked_by_pending_cancellation(
    app, api, keyring, owner_user, client_user, funded, requester
):
    signed_checkout(api, keyring, funded, owner_user, client_user)  # seule l'annulation bloque
    user = client_user if requester == "client" else owner_user
    assert api.cancel(funded, user).status_code == 200
    before = full_state(app, api, funded, owner_user)

    err = assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")

    assert err["details"]["reason"] == "CANCELLATION_PENDING"
    _assert_unchanged(app, api, funded, owner_user, before)
    assert deposit_rows(app, funded)[0]["held_cents"] == AMOUNT


def test_pending_cancellation_cannot_be_withdrawn_by_a_body_flag(
    app, api, keyring, owner_user, client_user, funded
):
    signed_checkout(api, keyring, funded, owner_user, client_user)
    api.cancel(funded, client_user)

    resp = api.cancel(funded, client_user, {"withdraw": True})

    assert resp.status_code in {409, 422}
    assert api.get(funded, owner_user).get_json()["cancellation"]["client_approved"] is True
    assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")


# ---------------------------------------------------------------- annulation tardive


@pytest.mark.parametrize("who", ["owner", "client"])
def test_cancel_after_start_is_invalid_transition(
    app, api, keyring, owner_user, client_user, funded, provider, who
):
    assert start_signed(api, keyring, funded, owner_user, client_user).status_code == 200
    before = full_state(app, api, funded, owner_user)
    user = owner_user if who == "owner" else client_user

    assert_error(api.cancel(funded, user), 409, "INVALID_TRANSITION")

    _assert_unchanged(app, api, funded, owner_user, before)
    assert deposit_rows(app, funded)[0]["held_cents"] == AMOUNT
    assert provider.refund_calls == []


# ---------------------------------------------------------------- concurrence


def test_simultaneous_cancel_by_both_parties_refunds_exactly_once(
    app, api, owner_user, client_user, funded, provider
):
    jobs = [lambda a: a.cancel(funded, client_user), lambda a: a.cancel(funded, owner_user)]

    responses = run_concurrently(app, jobs)

    assert [r.status_code for r in responses] == [200, 200]
    data = api.get(funded, owner_user).get_json()
    assert data["status"] == "REFUNDED"
    assert data["version"] == 6  # creation 1, 2 signatures, depot, 2 approbations
    row = deposit_rows(app, funded)[0]
    assert (row["held_cents"], row["refunded_cents"]) == (0, AMOUNT)
    assert len(provider.refund_calls) == 1


def test_simultaneous_cancel_and_start_stay_coherent(
    app, api, keyring, owner_user, client_user, funded, provider
):
    signed_checkout(api, keyring, funded, owner_user, client_user)
    base_version = api.get(funded, owner_user).get_json()["version"]
    jobs = [lambda a: a.cancel(funded, client_user), lambda a: a.start(funded, owner_user)]

    cancel_resp, start_resp = run_concurrently(app, jobs)

    data = api.get(funded, owner_user).get_json()
    row = deposit_rows(app, funded)[0]
    assert row["held_cents"] == AMOUNT  # une seule approbation : jamais de remboursement
    assert provider.refund_calls == []
    if start_resp.status_code == 200:
        assert data["status"] == "ACTIVE"
        assert_error(cancel_resp, 409, "INVALID_TRANSITION")
        assert data["cancellation"]["client_approved"] is False
    else:
        assert cancel_resp.status_code == 200
        err = assert_error(start_resp, 409, "INVALID_TRANSITION")
        assert err["details"]["reason"] == "CANCELLATION_PENDING"
        assert data["status"] == "FUNDED"
        assert data["cancellation"]["client_approved"] is True
    events = api.events(funded, owner_user).get_json()["events"]
    assert len([e for e in events if e["event"] in {"cancel", "start_rental"}]) == 1
    assert data["version"] == base_version + 1
