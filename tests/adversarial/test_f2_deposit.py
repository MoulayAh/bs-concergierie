"""Red team F2 : depot et blocage de la caution, annulation mutuelle, remise du vehicule.

Priorite a l'ARGENT : jamais deux blocages, jamais deux remboursements, invariant comptable toujours vrai,
et apres chaque erreur : statut, version, evenements, ligne ``deposits`` et montants inchanges.
Un test rouge ici = une faille trouvee (voir docs/audits/adversarial-2026-10-08.md). Pas de skip/xfail.
"""

import json
import uuid
from typing import Any

import pytest
from flask import Flask

from app.domain.errors import PaymentUnavailable
from tests.fixtures.deposits import (
    RecordingProvider,
    awaiting_deposit_contract,
    deposit_rows,
    full_state,
    funded_contract,
    run_concurrently,
)
from tests.fixtures.helpers import DEPOSIT_BODY, VALID_BODY, Api, TestUser, assert_error, new_key
from tests.fixtures.reports import KeyRing, signed_checkout, start_signed

pytestmark = pytest.mark.adversarial

AMOUNT = DEPOSIT_BODY["amount_cents"]
AMOUNT_CODES = {"VALIDATION_ERROR", "INVALID_AMOUNT"}


@pytest.fixture
def provider(app: Flask) -> RecordingProvider:
    recording = RecordingProvider()
    app.extensions["payment_provider"] = recording
    return recording


class RefundDownProvider(RecordingProvider):
    """Le remboursement echoue une fois (panne prestataire) puis reussit."""

    def __init__(self) -> None:
        super().__init__()
        self.refund_failures = 1

    def refund(self, ref: str) -> None:
        if self.refund_failures > 0:
            self.refund_failures -= 1
            raise PaymentUnavailable("Prestataire de paiement indisponible")
        super().refund(ref)


def body(**over: Any) -> dict[str, Any]:
    data = dict(DEPOSIT_BODY)
    data.update(over)
    return {k: v for k, v in data.items() if v is not _ABSENT}


_ABSENT = object()


def assert_ledger(app: Flask, cid: str) -> None:
    for row in deposit_rows(app, cid):
        total = row["held_cents"] + row["refunded_cents"] + row["released_cents"] + row["retained_cents"]
        assert total == row["amount_cents"], row
        assert min(row["held_cents"], row["refunded_cents"]) >= 0, row


def status_of(api: Api, cid: str, user: TestUser) -> dict[str, Any]:
    resp = api.get(cid, user)
    assert resp.status_code == 200
    data: dict[str, Any] = resp.get_json()
    return data


# --------------------------------------------------------------------------- montants et corps


@pytest.mark.parametrize(
    "amount",
    [
        1,
        0,
        -AMOUNT,
        2**63,
        -(2**63),
        str(AMOUNT),
        float(AMOUNT),
        True,
        None,
        _ABSENT,
        AMOUNT - 1,
        AMOUNT + 1,
        [AMOUNT],
        {"value": AMOUNT},
    ],
    ids=lambda a: repr(a)[:20],
)
def test_trapped_amounts_rejected(app, api, owner_user, client_user, provider, amount):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    resp = api.deposit(cid, client_user, body=body(amount_cents=amount))
    assert_error(resp, 422, codes=AMOUNT_CODES)
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


@pytest.mark.parametrize(
    "raw",
    [
        '{"amount_cents": 1e309, "currency": "EUR", "payment_method": "demo_card_ok"}',
        '{"amount_cents": NaN, "currency": "EUR", "payment_method": "demo_card_ok"}',
        '{"amount_cents": Infinity, "currency": "EUR", "payment_method": "demo_card_ok"}',
        '{"amount_cents": 2500000e0, "currency": "EUR", "payment_method": "demo_card_ok"}',
        '{"amount_cents": 2.5e6, "currency": "EUR", "payment_method": "demo_card_ok"}',
        '{"amount_cents": 0x2625A0, "currency": "EUR", "payment_method": "demo_card_ok"}',
        '{"amount_cents": ' + "9" * 5000 + ', "currency": "EUR", "payment_method": "demo_card_ok"}',
        '{"amount_cents": 2500000, "currency": "EUR"',
        "[]",
        "null",
        "",
    ],
    ids=["1e309", "NaN", "Infinity", "exp", "2.5e6", "hex", "huge-int", "truncated", "list", "null", "empty"],
)
def test_raw_json_amount_tricks_rejected(app, api, owner_user, client_user, provider, raw):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    resp = api.request("POST", f"/api/contracts/{cid}/deposit", client_user, raw=raw, idem=new_key())
    assert 400 <= resp.status_code < 500, resp.get_data(as_text=True)
    assert_error(resp, resp.status_code)
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


@pytest.mark.parametrize("currency", ["CHF", "USD", "eur", "EUR ", "XXX", "", None, 978])
def test_wrong_currency_rejected(app, api, owner_user, client_user, provider, currency):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    assert_error(api.deposit(cid, client_user, body=body(currency=currency)), 422, "VALIDATION_ERROR")
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


def test_deposit_in_eur_on_chf_contract_rejected(app, api, owner_user, client_user, provider):
    cid = awaiting_deposit_contract(api, owner_user, client_user, dict(VALID_BODY, currency="CHF"))
    before = full_state(app, api, cid, client_user)
    assert_error(api.deposit(cid, client_user), 422, "VALIDATION_ERROR")
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


@pytest.mark.parametrize(
    "extra",
    [
        {"card_number": "4111111111111111"},
        {"cvv": "123"},
        {"held_cents": 0},
        {"refunded_cents": AMOUNT},
        {"released_cents": AMOUNT},
        {"status": "FUNDED"},
        {"deposit_status": "REFUNDED"},
        {"provider_ref": "sim_attacker"},
        {"contract_id": str(uuid.uuid4())},
        {"version": 99},
    ],
    ids=lambda e: next(iter(e)),
)
def test_server_fields_in_body_rejected(app, api, owner_user, client_user, provider, extra):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    assert_error(api.deposit(cid, client_user, body=body(**extra)), 422, "VALIDATION_ERROR")
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


@pytest.mark.parametrize(
    "method",
    ["demo_card_ok ", "DEMO_CARD_OK", "card", "", None, 1, "x" * 1_000_000],
    ids=lambda m: repr(m)[:16],
)
def test_unknown_payment_method_rejected(app, api, owner_user, client_user, provider, method):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    assert_error(api.deposit(cid, client_user, body=body(payment_method=method)), 422, "VALIDATION_ERROR")
    assert full_state(app, api, cid, client_user) == before


def test_deposit_without_idempotency_key_rejected(app, api, owner_user, client_user, provider):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    assert_error(api.deposit(cid, client_user, no_key=True), 422, "VALIDATION_ERROR")
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"])
def test_wrong_content_type_rejected(app, api, owner_user, client_user, provider, ctype):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    resp = api.request(
        "POST",
        f"/api/contracts/{cid}/deposit",
        client_user,
        raw=json.dumps(DEPOSIT_BODY),
        content_type=ctype,
        idem=new_key(),
    )
    assert 400 <= resp.status_code < 500
    assert_error(resp, resp.status_code)
    assert full_state(app, api, cid, client_user) == before


# --------------------------------------------------------------------------- acces


def test_owner_cannot_deposit(app, api, owner_user, client_user, provider):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    assert_error(api.deposit(cid, owner_user), 403, "FORBIDDEN_ACTOR")
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


def test_stranger_deposit_is_indistinguishable_from_missing(
    app, api, owner_user, client_user, stranger_user, provider
):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    idor = assert_error(api.deposit(cid, stranger_user), 404, "NOT_FOUND")
    missing = assert_error(api.deposit(str(uuid.uuid4()), stranger_user), 404, "NOT_FOUND")
    garbage = assert_error(api.deposit("1' OR '1'='1", stranger_user), 404, "NOT_FOUND")
    assert idor == missing == garbage
    assert_error(api.deposit("../../etc/passwd", stranger_user), 404, "NOT_FOUND")  # 404 de route
    assert full_state(app, api, cid, client_user) == before
    assert provider.hold_calls == []


def test_stranger_cannot_read_deposit(app, api, owner_user, client_user, stranger_user, provider):
    cid = funded_contract(api, owner_user, client_user)
    idor = assert_error(api.get_deposit(cid, stranger_user), 404, "NOT_FOUND")
    missing = assert_error(api.get_deposit(str(uuid.uuid4()), stranger_user), 404, "NOT_FOUND")
    assert idor == missing
    assert "sim_" not in api.get(cid, client_user).get_data(as_text=True)  # provider_ref jamais expose


@pytest.mark.parametrize("action", ["deposit", "cancel", "start", "get_deposit"])
def test_unauthenticated_money_routes(app, api, owner_user, client_user, provider, action):
    cid = (
        funded_contract(api, owner_user, client_user)
        if action != "deposit"
        else (awaiting_deposit_contract(api, owner_user, client_user))
    )
    before = full_state(app, api, cid, client_user)
    resp = getattr(api, action)(cid, None)
    assert_error(resp, 401, "UNAUTHENTICATED")
    assert full_state(app, api, cid, client_user) == before


def test_stranger_cannot_cancel_or_start_funded(app, api, owner_user, client_user, stranger_user, provider):
    cid = funded_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    assert_error(api.cancel(cid, stranger_user), 404, "NOT_FOUND")
    assert_error(api.start(cid, stranger_user), 404, "NOT_FOUND")
    assert full_state(app, api, cid, client_user) == before
    assert provider.refund_calls == []


# --------------------------------------------------------------------------- double depot, rejeu, cles


def test_deposit_on_wrong_states_rejected(app, api, owner_user, client_user, provider):
    draft = api.create_ok(owner_user)["id"]
    assert_error(api.deposit(draft, client_user), 409, "INVALID_TRANSITION")
    funded = funded_contract(api, owner_user, client_user)
    before = full_state(app, api, funded, client_user)
    assert_error(api.deposit(funded, client_user), 409, "INVALID_TRANSITION")
    assert full_state(app, api, funded, client_user) == before
    cancelled = awaiting_deposit_contract(api, owner_user, client_user)
    assert api.cancel(cancelled, client_user).status_code == 200
    assert_error(api.deposit(cancelled, client_user), 409, "INVALID_TRANSITION")
    assert len(provider.hold_calls) == 1
    assert (deposit_rows(app, draft), deposit_rows(app, cancelled)) == ([], [])


def test_replay_same_key_holds_once(app, api, owner_user, client_user, provider):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    key = new_key()
    first = api.deposit(cid, client_user, idem=key)
    second = api.deposit(cid, client_user, idem=key)
    assert first.status_code == second.status_code == 200
    assert first.get_json() == second.get_json()
    assert len(provider.hold_calls) == 1
    assert len(deposit_rows(app, cid)) == 1
    assert_ledger(app, cid)


def test_same_key_different_body_conflicts(app, api, owner_user, client_user, provider):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    key = new_key()
    assert api.deposit(cid, client_user, idem=key).status_code == 200
    before = full_state(app, api, cid, client_user)
    resp = api.deposit(cid, client_user, body=body(payment_method="demo_card_declined"), idem=key)
    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    assert full_state(app, api, cid, client_user) == before
    assert len(provider.hold_calls) == 1


def test_same_key_reused_on_other_contract_conflicts(app, api, owner_user, client_user, provider):
    a = awaiting_deposit_contract(api, owner_user, client_user)
    b = awaiting_deposit_contract(api, owner_user, client_user)
    key = new_key()
    assert api.deposit(a, client_user, idem=key).status_code == 200
    before = full_state(app, api, b, client_user)
    assert_error(api.deposit(b, client_user, idem=key), 409, "IDEMPOTENCY_CONFLICT")
    assert full_state(app, api, b, client_user) == before
    assert len(provider.hold_calls) == 1


def test_two_clients_same_key_never_share_a_hold(app, api, make_user, owner_user, client_user):
    """Le prestataire PAR DEFAUT (SimulatedProvider) est idempotent sur la cle BRUTE, non scopee
    a l'utilisateur.

    Deux clients qui envoient la meme Idempotency-Key (cle previsible, rejouee ou choisie par un attaquant)
    ne doivent jamais partager un blocage de fonds, ni provoquer de 500.
    """
    other_client = make_user("client", email="other@demo.test")
    a = awaiting_deposit_contract(api, owner_user, client_user)
    other_body = dict(VALID_BODY, client_email="other@demo.test")
    b = awaiting_deposit_contract(api, owner_user, other_client, other_body)
    key = "shared-key-0001"
    assert api.deposit(a, client_user, idem=key).status_code == 200
    before = full_state(app, api, b, other_client)
    resp = api.deposit(b, other_client, idem=key)
    assert resp.status_code != 500, resp.get_data(as_text=True)
    if resp.status_code == 200:
        ref_a = deposit_rows(app, a)[0]["provider_ref"]
        ref_b = deposit_rows(app, b)[0]["provider_ref"]
        assert ref_a != ref_b, "le contrat B est FUNDED avec le blocage de fonds du client A"
    else:
        assert_error(resp, resp.status_code)
        assert full_state(app, api, b, other_client) == before


def test_provider_down_then_retry_holds_once(app, api, owner_user, client_user):
    flaky = RecordingProvider(fail_next_holds=1)
    app.extensions["payment_provider"] = flaky
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    snap = status_of(api, cid, client_user)
    key = new_key()
    assert_error(api.deposit(cid, client_user, idem=key), 503, "PAYMENT_UNAVAILABLE")
    after = status_of(api, cid, client_user)
    assert (after["status"], after["version"], after["funds"]) == (snap["status"], snap["version"], None)
    assert deposit_rows(app, cid) == []
    assert api.deposit(cid, client_user, idem=key).status_code == 200
    assert api.deposit(cid, client_user, idem=key).status_code == 200
    assert flaky.distinct_refs_held == 1
    assert len(deposit_rows(app, cid)) == 1
    assert_ledger(app, cid)


def test_declined_then_ok_with_other_key(app, api, owner_user, client_user, provider):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    before = full_state(app, api, cid, client_user)
    resp = api.deposit(cid, client_user, body=body(payment_method="demo_card_declined"))
    assert_error(resp, 402, "PAYMENT_DECLINED")
    after = full_state(app, api, cid, client_user)
    assert (after["contract"], after["deposits"]) == (before["contract"], [])
    assert api.deposit(cid, client_user).status_code == 200
    assert len(deposit_rows(app, cid)) == 1


@pytest.mark.parametrize("same_key", [False, True], ids=["distinct-keys", "same-key"])
def test_concurrent_deposits_hold_once(app, api, owner_user, client_user, provider, same_key):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    shared = new_key()
    jobs = [
        (lambda k: lambda a: a.deposit(cid, client_user, idem=k))(shared if same_key else new_key())
        for _ in range(5)
    ]
    results = run_concurrently(app, jobs)
    codes = sorted(r.status_code for r in results)
    assert 500 not in codes
    if same_key:
        assert codes == [200] * 5
        assert len({json.dumps(r.get_json(), sort_keys=True) for r in results}) == 1
    else:
        assert codes == [200] + [409] * 4
        for r in results:
            if r.status_code == 409:
                assert_error(r, 409, "INVALID_TRANSITION")
    assert provider.distinct_refs_held == 1
    assert len(deposit_rows(app, cid)) == 1
    assert status_of(api, cid, client_user)["version"] == 4  # create, sign, sign, deposit
    assert_ledger(app, cid)


# --------------------------------------------------------------------------- annulation et fonds


@pytest.mark.parametrize("first", ["client", "owner"])
def test_unilateral_cancel_cannot_recover_funds(app, api, owner_user, client_user, provider, first):
    cid = funded_contract(api, owner_user, client_user)
    actor = client_user if first == "client" else owner_user
    resp = api.cancel(cid, actor, body={"reason": "je veux mon argent"})
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "FUNDED"
    before = full_state(app, api, cid, client_user)
    assert before["deposits"][0]["status"] == "HELD"

    assert_error(api.cancel(cid, actor), 409, "INVALID_TRANSITION")
    assert_error(api.cancel(cid, actor, body={"reason": "encore"}), 409, "INVALID_TRANSITION")
    assert_error(api.cancel(cid, actor, body={"withdraw": True}), 422, "VALIDATION_ERROR")
    assert_error(api.cancel(cid, actor, body={"approved": True, "party": "owner"}), 422, "VALIDATION_ERROR")
    assert_error(api.request("DELETE", f"/api/contracts/{cid}/cancel", actor, idem=new_key()), 405)
    assert_error(api.deposit(cid, client_user), 409, "INVALID_TRANSITION")
    assert_error(api.start(cid, owner_user), 409, "INVALID_TRANSITION")
    assert_error(api.start(cid, client_user), 403, "FORBIDDEN_ACTOR")
    assert_error(api.sign(cid, actor), 409, "INVALID_TRANSITION")

    assert full_state(app, api, cid, client_user) == before
    assert provider.refund_calls == []
    assert_ledger(app, cid)


def test_unilateral_cancel_replayed_with_same_key_has_no_effect(app, api, owner_user, client_user, provider):
    cid = funded_contract(api, owner_user, client_user)
    key = new_key()
    assert api.cancel(cid, client_user, idem=key).status_code == 200
    before = full_state(app, api, cid, client_user)
    for _ in range(3):
        assert api.cancel(cid, client_user, idem=key).status_code == 200
    assert full_state(app, api, cid, client_user) == before
    assert provider.refund_calls == []


def test_mutual_cancel_refunds_exactly_once(app, api, owner_user, client_user, provider):
    cid = funded_contract(api, owner_user, client_user)
    assert api.cancel(cid, client_user).status_code == 200
    key = new_key()
    resp = api.cancel(cid, owner_user, idem=key)
    assert (resp.status_code, resp.get_json()["status"]) == (200, "REFUNDED")
    assert api.cancel(cid, owner_user, idem=key).get_json() == resp.get_json()  # rejeu
    before = full_state(app, api, cid, client_user)
    for who in (client_user, owner_user):
        assert_error(api.cancel(cid, who), 409, "INVALID_TRANSITION")
    assert_error(api.deposit(cid, client_user), 409, "INVALID_TRANSITION")
    assert_error(api.start(cid, owner_user), 409, "INVALID_TRANSITION")
    assert full_state(app, api, cid, client_user) == before
    row = before["deposits"][0]
    assert (row["status"], row["held_cents"], row["refunded_cents"]) == ("REFUNDED", 0, AMOUNT)
    assert len(provider.refund_calls) == 1
    assert_ledger(app, cid)


def test_refund_provider_down_leaves_state_consistent(app, api, owner_user, client_user):
    down = RefundDownProvider()
    app.extensions["payment_provider"] = down
    cid = funded_contract(api, owner_user, client_user)
    assert api.cancel(cid, client_user).status_code == 200
    before = full_state(app, api, cid, client_user)
    assert_error(api.cancel(cid, owner_user), 503, "PAYMENT_UNAVAILABLE")
    assert full_state(app, api, cid, client_user) == before
    resp = api.cancel(cid, owner_user)
    assert (resp.status_code, resp.get_json()["status"]) == (200, "REFUNDED")
    assert len(down.refund_calls) == 1
    assert_ledger(app, cid)


def test_cancel_after_start_rejected(app, api, owner_user, client_user, provider):
    cid = funded_contract(api, owner_user, client_user)
    assert start_signed(api, KeyRing(api), cid, owner_user, client_user).status_code == 200
    before = full_state(app, api, cid, client_user)
    for who in (client_user, owner_user):
        assert_error(api.cancel(cid, who), 409, "INVALID_TRANSITION")
    assert_error(api.start(cid, owner_user), 409, "INVALID_TRANSITION")
    assert_error(api.deposit(cid, client_user), 409, "INVALID_TRANSITION")
    assert full_state(app, api, cid, client_user) == before
    assert before["deposits"][0]["status"] == "HELD"
    assert provider.refund_calls == []


def test_start_after_cancel_rejected(app, api, owner_user, client_user, provider):
    pending = funded_contract(api, owner_user, client_user)
    assert api.cancel(pending, owner_user).status_code == 200
    before = full_state(app, api, pending, client_user)
    assert_error(api.start(pending, owner_user), 409, "INVALID_TRANSITION")
    assert full_state(app, api, pending, client_user) == before

    cancelled = awaiting_deposit_contract(api, owner_user, client_user)
    assert api.cancel(cancelled, owner_user).status_code == 200
    assert_error(api.start(cancelled, owner_user), 409, "INVALID_TRANSITION")
    assert provider.refund_calls == []


# --------------------------------------------------------------------------- courses


def _final_consistency(app: Flask, api: Api, cid: str, client: TestUser, provider: RecordingProvider) -> str:
    data = status_of(api, cid, client)
    row = deposit_rows(app, cid)[0]
    assert_ledger(app, cid)
    expected = {"FUNDED": ("HELD", 0), "ACTIVE": ("HELD", 0), "REFUNDED": ("REFUNDED", 1)}
    assert data["status"] in expected, data
    assert (row["status"], len(provider.refund_calls)) == expected[data["status"]]
    if data["status"] == "ACTIVE":
        assert data["cancellation"] == {"owner_approved": False, "client_approved": False}
    return str(data["status"])


@pytest.mark.parametrize("round_", range(3))
def test_race_cancel_vs_start(app, api, owner_user, client_user, provider, round_):
    cid = funded_contract(api, owner_user, client_user)
    signed_checkout(api, KeyRing(api), cid, owner_user, client_user)  # F3 : start exige un checkout signe x2
    results = run_concurrently(
        app, [lambda a: a.cancel(cid, client_user), lambda a: a.start(cid, owner_user)]
    )
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 409], [r.get_data(as_text=True) for r in results]
    for r in results:
        if r.status_code == 409:
            assert_error(r, 409, "INVALID_TRANSITION")
    final = _final_consistency(app, api, cid, client_user, provider)
    assert final in {"FUNDED", "ACTIVE"}


@pytest.mark.parametrize("round_", range(3))
def test_race_cancel_vs_cancel_refunds_once(app, api, owner_user, client_user, provider, round_):
    cid = funded_contract(api, owner_user, client_user)
    results = run_concurrently(
        app,
        [
            lambda a: a.cancel(cid, client_user),
            lambda a: a.cancel(cid, owner_user),
            lambda a: a.cancel(cid, client_user),
            lambda a: a.cancel(cid, owner_user),
        ],
    )
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 200, 409, 409], [r.get_data(as_text=True) for r in results]
    assert _final_consistency(app, api, cid, client_user, provider) == "REFUNDED"
    assert len(provider.refund_calls) == 1


@pytest.mark.parametrize("round_", range(3))
def test_race_cancel_cancel_start(app, api, owner_user, client_user, provider, round_):
    cid = funded_contract(api, owner_user, client_user)
    signed_checkout(api, KeyRing(api), cid, owner_user, client_user)  # F3 : start exige un checkout signe x2
    results = run_concurrently(
        app,
        [
            lambda a: a.cancel(cid, client_user),
            lambda a: a.cancel(cid, owner_user),
            lambda a: a.start(cid, owner_user),
        ],
    )
    assert all(r.status_code in (200, 409) for r in results), [r.get_data(as_text=True) for r in results]
    _final_consistency(app, api, cid, client_user, provider)


@pytest.mark.parametrize("round_", range(2))
def test_race_deposit_vs_cancel(app, api, owner_user, client_user, provider, round_):
    cid = awaiting_deposit_contract(api, owner_user, client_user)
    jobs = [lambda a: a.deposit(cid, client_user), lambda a: a.cancel(cid, owner_user)]
    results = run_concurrently(app, jobs)
    assert all(r.status_code in (200, 409) for r in results), [r.get_data(as_text=True) for r in results]
    data = status_of(api, cid, client_user)
    rows = deposit_rows(app, cid)
    if data["status"] == "CANCELLED":
        assert rows == []  # annule avant le depot : aucun fonds bloque orphelin
        assert provider.hold_calls == []
    else:
        assert (data["status"], [r["status"] for r in rows]) == ("FUNDED", ["HELD"])
        assert data["cancellation"]["owner_approved"] is True
    assert provider.refund_calls == []
