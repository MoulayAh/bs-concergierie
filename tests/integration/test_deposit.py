"""F2 : depot et blocage de la caution (POST/GET /api/contracts/<id>/deposit).

Interfaces supposees : voir l'en-tete de ``tests/fixtures/deposits.py`` (modele Deposit, prestataire
injectable via ``app.extensions["payment_provider"]``, evenements ``deposit`` / ``deposit_failed``,
sortie ``funds`` / ``cancellation``). Le prestataire par defaut (``SimulatedProvider``) est utilise
sauf quand la fixture ``provider`` / ``flaky_provider`` est demandee.

Regle commune : apres une erreur, statut, version, ligne ``deposits``, montants et evenements de
transition sont inchanges. Seul le journal ``deposit_failed`` peut s'ajouter (refus / panne).
"""

import hashlib

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.fixtures.deposits import (
    awaiting_deposit_contract,
    deposit_rows,
    failed_events,
    full_state,
    funded_contract,
    run_concurrently,
    transition_events,
)
from tests.fixtures.helpers import DEPOSIT_BODY, VALID_BODY, assert_error, new_key

pytestmark = pytest.mark.integration

AMOUNT = 2_500_000
FUNDS_KEYS = {
    "deposit_status",
    "amount_cents",
    "held_cents",
    "refunded_cents",
    "released_cents",
    "retained_cents",
    "currency",
}
NO_JSON_AMOUNT = object()


@pytest.fixture
def awaiting(api, owner_user, client_user) -> str:
    return awaiting_deposit_contract(api, owner_user, client_user)


def _assert_unchanged(app, api, cid, user, before, *, extra_events=0):
    after = full_state(app, api, cid, user)
    assert after["contract"] == before["contract"]
    assert after["deposits"] == before["deposits"]
    assert after["events"][: len(before["events"])] == before["events"]
    assert len(after["events"]) == len(before["events"]) + extra_events


# ---------------------------------------------------------------- succes


def test_deposit_moves_to_funded_and_holds_funds(app, api, owner_user, client_user, awaiting):
    before = api.get(awaiting, client_user).get_json()

    resp = api.deposit(awaiting, client_user)

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "FUNDED"
    assert data["version"] == before["version"] + 1
    assert data["funds"] == {
        "deposit_status": "HELD",
        "amount_cents": AMOUNT,
        "held_cents": AMOUNT,
        "refunded_cents": 0,
        "released_cents": 0,
        "retained_cents": 0,
        "currency": "EUR",
    }
    assert data["cancellation"] == {"owner_approved": False, "client_approved": False}
    rows = deposit_rows(app, awaiting)
    assert len(rows) == 1
    assert rows[0]["held_cents"] == AMOUNT
    assert rows[0]["amount_cents"] == AMOUNT
    assert rows[0]["provider"] == "simulated"
    assert rows[0]["provider_ref"]
    last = api.events(awaiting, owner_user).get_json()["events"][-1]
    assert last["event"] == "deposit"
    assert (last["from_status"], last["to_status"]) == ("AWAITING_DEPOSIT", "FUNDED")
    assert last["actor_id"] == client_user.id


def _provider_key(user, contract_id: str, http_key: str) -> str:
    """Cle derivee envoyee au prestataire (anti-collision entre clients/contrats, F2-ADV-1)."""
    return hashlib.sha256(f"{user.id}:{contract_id}:{http_key}".encode()).hexdigest()


def test_deposit_calls_provider_once_with_contract_amount_currency_method_and_key(
    api, client_user, awaiting, provider
):
    key = new_key()

    assert api.deposit(awaiting, client_user, idem=key).status_code == 200

    expected = _provider_key(client_user, awaiting, key)
    assert provider.hold_calls == [(AMOUNT, "EUR", "demo_card_ok", expected)]
    assert expected != key


def test_contract_output_exposes_funds(api, owner_user, client_user, awaiting):
    assert api.get(awaiting, owner_user).get_json()["funds"] is None
    assert api.get(awaiting, owner_user).get_json()["cancellation"] == {
        "owner_approved": False,
        "client_approved": False,
    }

    api.deposit(awaiting, client_user)

    for user in (owner_user, client_user):
        data = api.get(awaiting, user).get_json()
        assert set(data["funds"]) == FUNDS_KEYS
        assert data["funds"]["deposit_status"] == "HELD"
        assert all(type(data["funds"][k]) is int for k in FUNDS_KEYS - {"deposit_status", "currency"})
        assert data["cancellation"] == {"owner_approved": False, "client_approved": False}


def test_get_deposit_is_visible_to_both_parties_and_matches_funds(api, owner_user, client_user, awaiting):
    funds = api.deposit(awaiting, client_user).get_json()["funds"]

    for user in (owner_user, client_user):
        resp = api.get_deposit(awaiting, user)
        assert resp.status_code == 200
        assert resp.get_json() == funds


def test_get_deposit_hides_the_contract_from_a_third_party(api, client_user, stranger_user, awaiting):
    api.deposit(awaiting, client_user)

    assert_error(api.get_deposit(awaiting, stranger_user), 404, "NOT_FOUND")


def test_get_deposit_of_unknown_contract_is_not_found(api, client_user):
    assert_error(api.get_deposit("00000000-0000-4000-8000-000000000000", client_user), 404, "NOT_FOUND")


def test_get_deposit_before_any_deposit_is_not_found(api, owner_user, awaiting):
    assert_error(api.get_deposit(awaiting, owner_user), 404, "NOT_FOUND")


def test_get_deposit_without_credentials_is_unauthenticated(api, awaiting):
    assert_error(api.get_deposit(awaiting, None), 401, "UNAUTHENTICATED")


def test_deposit_without_credentials_is_unauthenticated(api, awaiting):
    assert_error(api.deposit(awaiting, None), 401, "UNAUTHENTICATED")


@pytest.mark.parametrize("currency", ["CHF", "GBP", "USD"])
def test_deposit_in_other_whitelisted_currency_holds_that_currency(
    app, api, owner_user, client_user, currency
):
    cid = awaiting_deposit_contract(api, owner_user, client_user, {**VALID_BODY, "currency": currency})

    resp = api.deposit(cid, client_user, {**DEPOSIT_BODY, "currency": currency})

    assert resp.status_code == 200
    assert resp.get_json()["funds"]["currency"] == currency
    assert deposit_rows(app, cid)[0]["currency"] == currency


# ---------------------------------------------------------------- montant


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(amount=st.integers().filter(lambda n: n != AMOUNT))
def test_deposit_amount_must_match_contract(app, api, client_user, awaiting, amount):
    before = full_state(app, api, awaiting, client_user)

    resp = api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "amount_cents": amount})

    assert_error(resp, 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})
    _assert_unchanged(app, api, awaiting, client_user, before)


@pytest.mark.parametrize("amount", [AMOUNT - 1, AMOUNT + 1, 1, 50_000_000])
def test_deposit_amount_off_by_any_amount_in_bounds_is_invalid_amount(
    app, api, client_user, awaiting, amount
):
    before = full_state(app, api, awaiting, client_user)

    err = assert_error(api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "amount_cents": amount}), 422)

    assert err["code"] == "INVALID_AMOUNT"
    _assert_unchanged(app, api, awaiting, client_user, before)


@pytest.mark.parametrize(
    "amount",
    [
        0,
        -1,
        -AMOUNT,
        2**63,
        2**64,
        50_000_001,
        "2500000",
        "25e5",
        2500000.0,
        2500000.5,
        True,
        False,
        None,
        [],
        {},
    ],
    ids=repr,
)
def test_deposit_rejects_trapped_amount_values(app, api, client_user, awaiting, amount):
    before = full_state(app, api, awaiting, client_user)

    resp = api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "amount_cents": amount})

    assert_error(resp, 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})
    _assert_unchanged(app, api, awaiting, client_user, before)


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    amount=st.one_of(
        st.text(max_size=30),
        st.floats(allow_nan=False, allow_infinity=False),
        st.booleans(),
        st.none(),
        st.lists(st.integers(), max_size=3),
    )
)
def test_deposit_rejects_any_non_integer_amount(app, api, client_user, awaiting, amount):
    before = full_state(app, api, awaiting, client_user)

    resp = api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "amount_cents": amount})

    assert_error(resp, 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})
    _assert_unchanged(app, api, awaiting, client_user, before)


def test_deposit_without_amount_is_rejected(app, api, client_user, awaiting):
    before = full_state(app, api, awaiting, client_user)
    body = {k: v for k, v in DEPOSIT_BODY.items() if k != "amount_cents"}

    assert_error(api.deposit(awaiting, client_user, body), 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})
    _assert_unchanged(app, api, awaiting, client_user, before)


# ---------------------------------------------------------------- schema strict


@pytest.mark.parametrize(
    "body",
    [
        {**DEPOSIT_BODY, "currency": "USD"},
        {**DEPOSIT_BODY, "currency": "eur"},
        {**DEPOSIT_BODY, "currency": None},
        {**DEPOSIT_BODY, "payment_method": "visa"},
        {**DEPOSIT_BODY, "payment_method": "DEMO_CARD_OK"},
        {**DEPOSIT_BODY, "payment_method": None},
        {**DEPOSIT_BODY, "payment_method": 1},
        {**DEPOSIT_BODY, "card_number": "4242424242424242"},
        {**DEPOSIT_BODY, "held_cents": 0},
        {**DEPOSIT_BODY, "status": "REFUNDED"},
        {k: v for k, v in DEPOSIT_BODY.items() if k != "currency"},
        {k: v for k, v in DEPOSIT_BODY.items() if k != "payment_method"},
        {},
        [],
        "payment",
    ],
    ids=lambda b: repr(b)[:60],
)
def test_deposit_rejects_invalid_body_with_validation_error(app, api, client_user, awaiting, body):
    before = full_state(app, api, awaiting, client_user)

    err = assert_error(api.deposit(awaiting, client_user, body), 422)

    assert err["code"] in {"VALIDATION_ERROR", "INVALID_AMOUNT"}
    _assert_unchanged(app, api, awaiting, client_user, before)


@pytest.mark.parametrize(
    "body",
    [{**DEPOSIT_BODY, "currency": "USD"}, {**DEPOSIT_BODY, "card_number": "4242"}],
    ids=["currency_mismatch", "card_number"],
)
def test_deposit_currency_mismatch_and_extra_fields_are_validation_error(api, client_user, awaiting, body):
    assert_error(api.deposit(awaiting, client_user, body), 422, "VALIDATION_ERROR")


def test_deposit_never_stores_or_echoes_card_data(app, api, client_user, awaiting):
    resp = api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "card_number": "4242424242424242"})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert "4242424242424242" not in resp.get_data(as_text=True)
    assert deposit_rows(app, awaiting) == []


def test_deposit_without_idempotency_key_is_validation_error(app, api, client_user, awaiting):
    before = full_state(app, api, awaiting, client_user)

    assert_error(api.deposit(awaiting, client_user, no_key=True), 422, "VALIDATION_ERROR")
    _assert_unchanged(app, api, awaiting, client_user, before)


def test_deposit_with_blank_idempotency_key_is_validation_error(app, api, client_user, awaiting):
    before = full_state(app, api, awaiting, client_user)

    assert_error(api.deposit(awaiting, client_user, idem=""), 422, "VALIDATION_ERROR")
    _assert_unchanged(app, api, awaiting, client_user, before)


# ---------------------------------------------------------------- acteur et etat


def test_owner_cannot_deposit(app, api, owner_user, client_user, awaiting):
    before = full_state(app, api, awaiting, owner_user)

    assert_error(api.deposit(awaiting, owner_user), 403, "FORBIDDEN_ACTOR")
    _assert_unchanged(app, api, awaiting, owner_user, before)


def test_stranger_deposit_is_not_found(app, api, owner_user, stranger_user, awaiting):
    before = full_state(app, api, awaiting, owner_user)

    assert_error(api.deposit(awaiting, stranger_user), 404, "NOT_FOUND")
    _assert_unchanged(app, api, awaiting, owner_user, before)


def test_deposit_on_unknown_contract_is_not_found(api, client_user):
    assert_error(api.deposit("00000000-0000-4000-8000-000000000000", client_user), 404, "NOT_FOUND")


def test_deposit_on_draft_contract_is_invalid_transition(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    before = full_state(app, api, cid, owner_user)

    assert_error(api.deposit(cid, client_user), 409, "INVALID_TRANSITION")
    _assert_unchanged(app, api, cid, owner_user, before)
    assert deposit_rows(app, cid) == []


def test_deposit_on_cancelled_contract_is_invalid_transition(app, api, owner_user, client_user, awaiting):
    assert api.cancel(awaiting, owner_user).status_code == 200
    before = full_state(app, api, awaiting, owner_user)

    assert_error(api.deposit(awaiting, client_user), 409, "INVALID_TRANSITION")
    _assert_unchanged(app, api, awaiting, owner_user, before)
    assert deposit_rows(app, awaiting) == []


def test_second_deposit_with_other_key_on_funded_contract_is_invalid_transition(
    app, api, owner_user, client_user, provider
):
    cid = funded_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, owner_user)

    assert_error(api.deposit(cid, client_user), 409, "INVALID_TRANSITION")
    _assert_unchanged(app, api, cid, owner_user, before)
    assert len(deposit_rows(app, cid)) == 1
    assert len(provider.hold_calls) == 1


def test_deposit_on_active_contract_is_invalid_transition(app, api, owner_user, client_user):
    cid = funded_contract(api, owner_user, client_user)
    assert api.start(cid, owner_user).status_code == 200
    before = full_state(app, api, cid, owner_user)

    assert_error(api.deposit(cid, client_user), 409, "INVALID_TRANSITION")
    _assert_unchanged(app, api, cid, owner_user, before)


# ---------------------------------------------------------------- idempotence


def test_same_key_same_body_replays_the_response_and_holds_once(
    app, api, owner_user, client_user, awaiting, provider
):
    key = new_key()
    first = api.deposit(awaiting, client_user, idem=key)

    second = api.deposit(awaiting, client_user, idem=key)

    assert first.status_code == second.status_code == 200
    assert second.get_json() == first.get_json()
    assert len(deposit_rows(app, awaiting)) == 1
    assert len(provider.hold_calls) == 1
    assert len(transition_events(api, awaiting, owner_user)) == 4  # create, 2 signatures, deposit


def test_same_key_other_body_is_idempotency_conflict(app, api, owner_user, client_user, awaiting, provider):
    key = new_key()
    assert api.deposit(awaiting, client_user, idem=key).status_code == 200
    before = full_state(app, api, awaiting, owner_user)
    other = {**DEPOSIT_BODY, "payment_method": "demo_card_declined"}

    resp = api.deposit(awaiting, client_user, other, idem=key)

    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    _assert_unchanged(app, api, awaiting, owner_user, before)
    assert len(provider.hold_calls) == 1


# ---------------------------------------------------------------- prestataire


@pytest.mark.parametrize("method", ["demo_card_declined", "demo_insufficient_funds"])
def test_declined_payment_leaves_contract_unchanged(app, api, owner_user, client_user, awaiting, method):
    before = full_state(app, api, awaiting, owner_user)

    resp = api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "payment_method": method})

    assert_error(resp, 402, "PAYMENT_DECLINED")
    after = full_state(app, api, awaiting, owner_user)
    assert after["contract"] == before["contract"]  # statut, version, funds, cancellation
    assert after["contract"]["status"] == "AWAITING_DEPOSIT"
    assert after["deposits"] == [] == before["deposits"]
    assert len(transition_events(api, awaiting, owner_user)) == len(before["events"])


def test_declined_payment_journals_one_deposit_failed_event(api, owner_user, client_user, awaiting):
    api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "payment_method": "demo_card_declined"})

    failed = failed_events(api, awaiting, owner_user)

    assert len(failed) == 1
    assert failed[0]["actor_id"] == client_user.id
    assert failed[0]["from_status"] == failed[0]["to_status"] == "AWAITING_DEPOSIT"


def test_declined_payment_can_be_followed_by_a_successful_deposit(app, api, client_user, awaiting):
    api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "payment_method": "demo_card_declined"})

    resp = api.deposit(awaiting, client_user)

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "FUNDED"
    assert len(deposit_rows(app, awaiting)) == 1


def test_provider_down_leaves_contract_unchanged(app, api, owner_user, client_user, awaiting):
    before = full_state(app, api, awaiting, owner_user)

    resp = api.deposit(awaiting, client_user, {**DEPOSIT_BODY, "payment_method": "demo_provider_down"})

    assert_error(resp, 503, "PAYMENT_UNAVAILABLE")
    after = full_state(app, api, awaiting, owner_user)
    assert after["contract"] == before["contract"]
    assert after["deposits"] == []
    assert len(transition_events(api, awaiting, owner_user)) == len(before["events"])
    assert len(failed_events(api, awaiting, owner_user)) == 1
    assert api.deposit(awaiting, client_user).status_code == 200


def test_provider_down_then_retry_same_key_holds_once(
    app, api, owner_user, client_user, awaiting, flaky_provider
):
    key = new_key()
    before = full_state(app, api, awaiting, owner_user)

    first = api.deposit(awaiting, client_user, idem=key)

    assert_error(first, 503, "PAYMENT_UNAVAILABLE")
    assert deposit_rows(app, awaiting) == []
    assert api.get(awaiting, owner_user).get_json() == before["contract"]

    second = api.deposit(awaiting, client_user, idem=key)

    assert second.status_code == 200
    assert second.get_json()["status"] == "FUNDED"
    rows = deposit_rows(app, awaiting)
    assert len(rows) == 1
    assert rows[0]["provider_ref"]
    assert rows[0]["held_cents"] == AMOUNT
    expected = _provider_key(client_user, awaiting, key)
    assert expected != key
    # meme cle derivee aux deux appels (503 puis 200) : le prestataire dedoublonne
    assert [c[3] for c in flaky_provider.hold_calls] == [expected, expected]
    events = api.events(awaiting, owner_user).get_json()["events"]
    assert [e["event"] for e in events].count("deposit") == 1
    assert [e["event"] for e in events].count("deposit_failed") == 1


def test_provider_down_then_replay_after_success_does_not_hold_again(
    app, api, client_user, awaiting, flaky_provider
):
    key = new_key()
    api.deposit(awaiting, client_user, idem=key)
    ok = api.deposit(awaiting, client_user, idem=key)
    holds_before = len(flaky_provider.hold_calls)

    replay = api.deposit(awaiting, client_user, idem=key)

    assert replay.status_code == 200
    assert replay.get_json() == ok.get_json()
    assert len(flaky_provider.hold_calls) == holds_before
    assert len(deposit_rows(app, awaiting)) == 1


# ---------------------------------------------------------------- concurrence


def test_two_simultaneous_deposits_with_different_keys_fund_once(
    app, api, owner_user, client_user, awaiting, provider
):
    jobs = [lambda a: a.deposit(awaiting, client_user), lambda a: a.deposit(awaiting, client_user)]

    responses = run_concurrently(app, jobs)

    assert sorted(r.status_code for r in responses) == [200, 409]
    loser = next(r for r in responses if r.status_code == 409)
    assert_error(loser, 409, "INVALID_TRANSITION")
    rows = deposit_rows(app, awaiting)
    assert len(rows) == 1
    assert rows[0]["held_cents"] == AMOUNT
    assert len(provider.hold_calls) == 1  # un seul blocage de fonds aupres du prestataire
    data = api.get(awaiting, owner_user).get_json()
    assert data["status"] == "FUNDED"
    assert data["version"] == 4
    events = api.events(awaiting, owner_user).get_json()["events"]
    assert [e["event"] for e in events].count("deposit") == 1


def test_two_simultaneous_deposits_with_same_key_fund_once(app, api, client_user, awaiting, provider):
    key = new_key()
    jobs = [lambda a: a.deposit(awaiting, client_user, idem=key)] * 2

    responses = run_concurrently(app, jobs)

    assert [r.status_code for r in responses] == [200, 200]
    assert responses[0].get_json() == responses[1].get_json()
    assert len(deposit_rows(app, awaiting)) == 1
    assert len(provider.hold_calls) == 1
