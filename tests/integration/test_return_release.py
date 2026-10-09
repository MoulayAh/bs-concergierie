"""F4 : signature du rapport de retour et liberation de la caution (HTTP + PostgreSQL).

Interfaces supposees : voir l'en-tete de tests/fixtures/release.py. Apres chaque erreur : rien n'a change
(contrat, rapport, depot, montants, signatures, quittance absente, aucun paiement au prestataire).
"""

import base64
import hashlib
import json
from itertools import pairwise

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.fixtures.deposits import deposit_rows, run_concurrently
from tests.fixtures.helpers import assert_error, new_key
from tests.fixtures.release import (
    DEPOSIT_CENTS,
    EVENT_FIELDS,
    SERVER_PUBLIC_RAW,
    chain_hash,
    deposit_id,
    get_receipt,
    pending_contract,
    post_return_signature,
    release,
    release_state,
    sign_return,
)
from tests.fixtures.reports import (
    create_report,
    finalize_report,
    get_report,
    post_signature,
    supersede_report,
    update_report,
)

pytestmark = pytest.mark.integration

SLOW = settings(max_examples=6, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])


def _events(api, cid, user):
    return api.events(cid, user).get_json()["events"]


def _sig(keyring, user, pending, kind: str = "return") -> str:
    return keyring.get(user).sign_report(pending.contract_id, kind, pending.report["report_hash"])


def _flip(signature_b64: str) -> str:
    raw = base64.b64decode(signature_b64)
    return base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode()


# ------------------------------------------------------------------ liberation nominale


def test_double_signed_return_without_retention_releases_full_deposit(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory()

    _, final = release(api, keyring, pending, owner_user, client_user)

    body = final.get_json()
    assert body["contract"]["status"] == "RELEASED"
    assert (body["funds"]["released_cents"], body["funds"]["retained_cents"]) == (DEPOSIT_CENTS, 0)
    assert (body["funds"]["held_cents"], body["funds"]["deposit_status"]) == (0, "RELEASED")
    row = deposit_rows(app, pending.contract_id)[0]
    assert (row["status"], row["held_cents"], row["released_cents"], row["retained_cents"]) == (
        "RELEASED",
        0,
        DEPOSIT_CENTS,
        0,
    )
    assert api.get(pending.contract_id, client_user).get_json()["status"] == "RELEASED"
    assert get_report(api, pending.contract_id, owner_user, "return").get_json()["status"] == "SIGNED"
    assert provider.settle_calls == [
        (row["provider_ref"], DEPOSIT_CENTS, 0, f"settle:{deposit_id(app, pending.contract_id)}")
    ]
    assert provider.paid_out_cents == DEPOSIT_CENTS


@pytest.mark.parametrize("retained", [1, 120_000, DEPOSIT_CENTS - 1, DEPOSIT_CENTS])
def test_double_signed_return_with_retention_settles_split(
    app, api, keyring, owner_user, client_user, provider, pending_factory, retained
):
    pending = pending_factory(retention_cents=retained)

    _, final = release(api, keyring, pending, owner_user, client_user)

    body = final.get_json()
    assert body["contract"]["status"] == "SETTLED"
    assert body["funds"]["deposit_status"] == "SETTLED"
    assert (body["funds"]["released_cents"], body["funds"]["retained_cents"]) == (
        DEPOSIT_CENTS - retained,
        retained,
    )
    assert body["funds"]["held_cents"] == 0
    row = deposit_rows(app, pending.contract_id)[0]
    assert row["released_cents"] + row["retained_cents"] == DEPOSIT_CENTS
    assert [c[1:3] for c in provider.settle_calls] == [(DEPOSIT_CENTS - retained, retained)]


@SLOW
@given(retained=st.integers(min_value=1, max_value=DEPOSIT_CENTS))
def test_any_valid_retention_conserves_the_deposit(
    app, api, keyring, owner_user, client_user, provider, retained
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=retained)

    _, final = release(api, keyring, pending, owner_user, client_user)

    funds = final.get_json()["funds"]
    assert funds["released_cents"] + funds["retained_cents"] == DEPOSIT_CENTS
    assert funds["retained_cents"] == retained
    row = deposit_rows(app, pending.contract_id)[0]
    assert row["released_cents"] + row["retained_cents"] + row["refunded_cents"] == DEPOSIT_CENTS
    assert provider.settled[f"settle:{deposit_id(app, pending.contract_id)}"][1:3] == (
        DEPOSIT_CENTS - retained,
        retained,
    )


@pytest.mark.parametrize("first_signer", ["client", "owner"])
def test_first_return_signature_keeps_funds_held(
    app, api, keyring, owner_user, client_user, provider, pending_factory, first_signer
):
    pending = pending_factory(retention_cents=50_000)
    first = client_user if first_signer == "client" else owner_user

    resp = sign_return(api, keyring, pending.contract_id, first, pending.report)

    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert api.get(pending.contract_id, owner_user).get_json()["status"] == "INSPECTION_PENDING"
    report = get_report(api, pending.contract_id, owner_user, "return").get_json()
    assert report["status"] == "FROZEN"
    assert [s["party"] for s in report["signatures"]] == [first_signer]
    row = deposit_rows(app, pending.contract_id)[0]
    assert (row["status"], row["held_cents"], row["released_cents"], row["retained_cents"]) == (
        "HELD",
        DEPOSIT_CENTS,
        0,
        0,
    )
    assert provider.settle_calls == []
    assert_error(get_receipt(api, pending.contract_id, owner_user), 404, "NOT_FOUND")


def test_release_works_whoever_signs_first(api, keyring, owner_user, client_user, provider, pending_factory):
    pending = pending_factory()

    assert sign_return(api, keyring, pending.contract_id, owner_user, pending.report).status_code == 200
    final = sign_return(api, keyring, pending.contract_id, client_user, pending.report)

    assert final.status_code == 200
    assert final.get_json()["contract"]["status"] == "RELEASED"


def test_release_response_is_replayed_for_the_same_idempotency_key(
    api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=10_000)
    sign_return(api, keyring, pending.contract_id, client_user, pending.report)
    first = sign_return(api, keyring, pending.contract_id, owner_user, pending.report, idem="same-key")

    replay = sign_return(api, keyring, pending.contract_id, owner_user, pending.report, idem="same-key")

    assert (first.status_code, replay.status_code) == (200, 200)
    assert replay.get_json() == first.get_json()
    assert len(provider.settle_calls) == 1
    assert len([e for e in _events(api, pending.contract_id, owner_user) if e["event"] == "sign_report"]) == 2


# ------------------------------------------------------------------ justification de la retenue


def test_retention_requires_damage_with_photo(api, keyring, owner_user, client_user, provider):
    from tests.fixtures.files import distinct_jpeg
    from tests.fixtures.reports import active_contract, upload_ok

    cid = active_contract(api, keyring, owner_user, client_user)
    assert create_report(api, cid, owner_user, "return", odometer_km=12_600).status_code == 201
    photo = upload_ok(api, cid, owner_user, distinct_jpeg(3), kind="return")
    bad_damage = {"zone": "hood", "severity": "minor", "description": "Rayure", "file_ids": []}
    good_damage = {**bad_damage, "file_ids": [photo["id"]]}

    for damages in ([], [bad_damage]):
        update = update_report(
            api, cid, owner_user, "return", odometer_km=12_600, damages=damages, claimed_retention_cents=5_000
        )
        resp = update if update.status_code != 200 else finalize_report(api, cid, owner_user, "return")
        assert_error(resp, 422, "VALIDATION_ERROR")
        assert api.get(cid, owner_user).get_json()["status"] == "ACTIVE"
        assert get_report(api, cid, owner_user, "return").get_json()["status"] == "DRAFT"

    update = update_report(
        api, cid, owner_user, "return", odometer_km=12_600, damages=[good_damage],
        claimed_retention_cents=5_000,
    )  # fmt: skip
    assert update.status_code == 200, update.get_data(as_text=True)
    assert finalize_report(api, cid, owner_user, "return").status_code == 200
    assert api.get(cid, owner_user).get_json()["status"] == "INSPECTION_PENDING"


def test_return_without_damage_and_without_retention_is_accepted(api, keyring, owner_user, client_user):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=0, damage=False)

    assert pending.report["claimed_retention_cents"] == 0
    assert pending.report["damages"] == []


def test_return_with_damage_but_no_retention_releases_everything(
    api, keyring, owner_user, client_user, provider
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=0, damage=True)

    _, final = release(api, keyring, pending, owner_user, client_user)

    assert final.get_json()["contract"]["status"] == "RELEASED"


# ------------------------------------------------------------------ panne du prestataire


def test_provider_failure_leaves_everything_unchanged(
    app, api, keyring, owner_user, client_user, flaky_settle_provider, pending_factory
):
    provider = flaky_settle_provider
    pending = pending_factory(retention_cents=120_000)
    sign_return(api, keyring, pending.contract_id, client_user, pending.report)
    before = release_state(app, api, pending.contract_id, owner_user)

    resp = sign_return(api, keyring, pending.contract_id, owner_user, pending.report)

    assert_error(resp, 503, "PAYMENT_UNAVAILABLE")
    assert release_state(app, api, pending.contract_id, owner_user) == before
    assert before["receipt_status"] == 404
    assert provider.settled == {}
    assert provider.paid_out_cents == 0
    assert api.get(pending.contract_id, owner_user).get_json()["status"] == "INSPECTION_PENDING"
    assert len(get_report(api, pending.contract_id, owner_user, "return").get_json()["signatures"]) == 1


def test_settle_is_idempotent_on_retry_after_provider_failure(
    app, api, keyring, owner_user, client_user, flaky_settle_provider, pending_factory
):
    provider = flaky_settle_provider
    pending = pending_factory(retention_cents=120_000)
    sign_return(api, keyring, pending.contract_id, client_user, pending.report)
    assert_error(
        sign_return(api, keyring, pending.contract_id, owner_user, pending.report, idem="retry-1"),
        503,
        "PAYMENT_UNAVAILABLE",
    )

    retry = sign_return(api, keyring, pending.contract_id, owner_user, pending.report, idem="retry-1")

    assert retry.status_code == 200, retry.get_data(as_text=True)
    assert retry.get_json()["contract"]["status"] == "SETTLED"
    keys = {call[3] for call in provider.settle_calls}
    assert keys == {f"settle:{deposit_id(app, pending.contract_id)}"}
    assert len(provider.settled) == 1
    assert provider.paid_out_cents == DEPOSIT_CENTS
    assert len([e for e in _events(api, pending.contract_id, owner_user) if e["event"] == "sign_report"]) == 2


def test_retry_after_provider_failure_with_a_new_idempotency_key_also_releases_once(
    app, api, keyring, owner_user, client_user, flaky_settle_provider, pending_factory
):
    pending = pending_factory()
    sign_return(api, keyring, pending.contract_id, client_user, pending.report)
    assert sign_return(api, keyring, pending.contract_id, owner_user, pending.report).status_code == 503

    retry = sign_return(api, keyring, pending.contract_id, owner_user, pending.report)

    assert retry.status_code == 200
    assert len(flaky_settle_provider.settled) == 1
    assert flaky_settle_provider.paid_out_cents == DEPOSIT_CENTS


def test_repeated_signature_attempts_during_outage_never_pay(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    provider.fail_next_settles = 3
    pending = pending_factory()
    sign_return(api, keyring, pending.contract_id, client_user, pending.report)

    cid = pending.contract_id
    codes = [sign_return(api, keyring, cid, owner_user, pending.report).status_code for _ in range(3)]

    assert codes == [503, 503, 503]
    assert provider.settled == {}
    assert sign_return(api, keyring, pending.contract_id, owner_user, pending.report).status_code == 200
    assert provider.paid_out_cents == DEPOSIT_CENTS


# ------------------------------------------------------------------ concurrence


def test_concurrent_second_signatures_release_exactly_once(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=30_000)
    sign_return(api, keyring, pending.contract_id, client_user, pending.report)
    signature = _sig(keyring, owner_user, pending)

    def job(local):
        return post_return_signature(local, pending.contract_id, owner_user, signature)

    responses = run_concurrently(app, [job, job, job])

    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 409, 409], [r.get_data(as_text=True) for r in responses]
    for loser in (r for r in responses if r.status_code == 409):
        assert_error(loser, 409, "INVALID_TRANSITION")
    assert len(provider.settled) == 1
    assert provider.paid_out_cents == DEPOSIT_CENTS
    events = _events(api, pending.contract_id, owner_user)
    assert len([e for e in events if e["event"] == "sign_report"]) == 2
    assert get_receipt(api, pending.contract_id, client_user).status_code == 200


def test_concurrent_replays_with_the_same_key_return_the_same_single_release(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory()
    sign_return(api, keyring, pending.contract_id, client_user, pending.report)
    signature = _sig(keyring, owner_user, pending)

    def job(local):
        return post_return_signature(local, pending.contract_id, owner_user, signature, idem="shared-key")

    responses = run_concurrently(app, [job, job])

    assert [r.status_code for r in responses] == [200, 200]
    assert responses[0].get_json() == responses[1].get_json()
    assert len(provider.settled) == 1


# ------------------------------------------------------------------ quittance (API)


def test_receipt_endpoint_returns_the_receipt_given_at_release(
    api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=120_000)
    _, final = release(api, keyring, pending, owner_user, client_user)

    for user in (owner_user, client_user):
        resp = get_receipt(api, pending.contract_id, user)
        assert resp.status_code == 200
        assert resp.get_json() == final.get_json()["receipt"]


def test_receipt_content_matches_the_release(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=120_000)
    _, final = release(api, keyring, pending, owner_user, client_user)
    receipt = final.get_json()["receipt"]

    content = json.loads(receipt["canonical_json"])

    assert hashlib.sha256(receipt["canonical_json"].encode()).hexdigest() == receipt["receipt_hash"]
    assert content["schema"] == "luxe-escrow/receipt/v1"
    assert content["contract_id"] == pending.contract_id
    assert content["outcome"] == "SETTLED"
    assert (content["currency"], content["deposit_cents"]) == ("EUR", DEPOSIT_CENTS)
    assert (content["released_to_client_cents"], content["retained_by_owner_cents"]) == (
        DEPOSIT_CENTS - 120_000,
        120_000,
    )
    assert content["return_report"]["hash"] == pending.report["report_hash"]
    assert content["return_report"]["id"] == pending.report["id"]
    assert {s["party"] for s in content["signatures"]} == {"owner", "client"}
    events = _events(api, pending.contract_id, owner_user)
    assert content["event_chain"] == {"length": len(events), "head": events[-1]["event_hash"]}
    assert events[-1]["event"] == "sign_report"


def test_server_key_route_is_public_and_exposes_only_the_public_key(api):
    resp = api.request("GET", "/api/server-key")

    assert resp.status_code == 200
    body = resp.get_json()
    assert base64.b64decode(body["public_key"]) == SERVER_PUBLIC_RAW
    assert body["fingerprint"] == hashlib.sha256(SERVER_PUBLIC_RAW).hexdigest()
    assert set(body) == {"public_key", "fingerprint"}


def test_receipt_verifies_offline(api, keyring, owner_user, client_user, provider, pending_factory):
    from scripts.verify_receipt import verify_receipt

    pending = pending_factory(retention_cents=120_000)
    release(api, keyring, pending, owner_user, client_user)
    receipt = get_receipt(api, pending.contract_id, client_user).get_json()
    server_key = base64.b64decode(api.request("GET", "/api/server-key").get_json()["public_key"])
    events = _events(api, pending.contract_id, client_user)

    assert verify_receipt(receipt, server_key, None) is None
    assert verify_receipt(receipt, server_key, events) is None


def test_receipt_without_retention_verifies_offline(
    api, keyring, owner_user, client_user, provider, pending_factory
):
    from scripts.verify_receipt import verify_receipt

    pending = pending_factory()
    _, final = release(api, keyring, pending, owner_user, client_user)
    receipt = final.get_json()["receipt"]
    events = _events(api, pending.contract_id, owner_user)

    assert json.loads(receipt["canonical_json"])["outcome"] == "RELEASED"
    assert verify_receipt(receipt, SERVER_PUBLIC_RAW, events) is None


def test_receipt_tampering_detected(api, keyring, owner_user, client_user, provider, pending_factory):
    from scripts.verify_receipt import ReceiptInvalid, verify_receipt

    pending = pending_factory(retention_cents=120_000)
    _, final = release(api, keyring, pending, owner_user, client_user)
    receipt = final.get_json()["receipt"]
    forged = {**receipt, "canonical_json": receipt["canonical_json"].replace("120000", "119999")}

    assert forged["canonical_json"] != receipt["canonical_json"]
    with pytest.raises(ReceiptInvalid):
        verify_receipt(forged, SERVER_PUBLIC_RAW, None)
    with pytest.raises(ReceiptInvalid):
        verify_receipt(forged, SERVER_PUBLIC_RAW, _events(api, pending.contract_id, owner_user))


def test_event_chain_links_every_event(api, keyring, owner_user, client_user, provider, pending_factory):
    from app.domain.event_chain import GENESIS, compute_event_hash, verify_chain

    pending = pending_factory(retention_cents=1_000)
    release(api, keyring, pending, owner_user, client_user)

    events = _events(api, pending.contract_id, owner_user)

    assert len(events) == 8
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    assert events[0]["prev_hash"] == GENESIS
    previous = GENESIS
    for event in events:
        assert event["prev_hash"] == previous
        assert event["contract_id"] == pending.contract_id
        fields = {k: event[k] for k in EVENT_FIELDS}
        assert compute_event_hash(previous, fields) == event["event_hash"] == chain_hash(previous, fields)
        previous = event["event_hash"]
    assert len({e["event_hash"] for e in events}) == len(events)
    assert verify_chain(events) is None


def test_event_chain_is_linked_before_release_too(api, owner_user, client_user, pending_factory, provider):
    pending = pending_factory()

    events = _events(api, pending.contract_id, owner_user)

    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    assert all(a["event_hash"] == b["prev_hash"] for a, b in pairwise(events))


# ------------------------------------------------------------------ acces a la quittance


def test_receipt_before_release_is_not_found(api, owner_user, client_user, provider, pending_factory):
    pending = pending_factory()

    for user in (owner_user, client_user):
        assert_error(get_receipt(api, pending.contract_id, user), 404, "NOT_FOUND")


def test_receipt_of_another_contract_is_not_found_for_a_stranger(
    api, keyring, owner_user, client_user, stranger_user, provider, pending_factory
):
    pending = pending_factory()
    release(api, keyring, pending, owner_user, client_user)

    assert_error(get_receipt(api, pending.contract_id, stranger_user), 404, "NOT_FOUND")
    assert_error(get_receipt(api, "00000000-0000-4000-8000-000000000000", owner_user), 404, "NOT_FOUND")
    assert_error(get_receipt(api, "pas-un-uuid", owner_user), 404, "NOT_FOUND")


def test_receipt_requires_authentication(api, keyring, owner_user, client_user, provider, pending_factory):
    pending = pending_factory()
    release(api, keyring, pending, owner_user, client_user)

    assert_error(get_receipt(api, pending.contract_id, None), 401, "UNAUTHENTICATED")


# ------------------------------------------------------------------ cas d'erreur de signature


def test_signing_a_draft_return_report_is_invalid_transition(
    app, api, keyring, owner_user, client_user, provider
):
    from tests.fixtures.reports import active_contract

    cid = active_contract(api, keyring, owner_user, client_user)
    create_report(api, cid, owner_user, "return", odometer_km=12_600)
    before = release_state(app, api, cid, owner_user)

    resp = post_return_signature(api, cid, client_user, keyring.get(client_user).sign(b"x"))

    assert_error(resp, 409, "INVALID_TRANSITION")
    assert release_state(app, api, cid, owner_user) == before


@pytest.mark.parametrize("stage", ["funded", "active"])
def test_signing_return_when_contract_is_not_inspection_pending_is_invalid_transition(
    app, api, keyring, owner_user, client_user, provider, stage
):
    from tests.fixtures.deposits import funded_contract
    from tests.fixtures.reports import active_contract

    cid = (
        funded_contract(api, owner_user, client_user)
        if stage == "funded"
        else active_contract(api, keyring, owner_user, client_user)
    )
    keyring.get(client_user)
    before = release_state(app, api, cid, owner_user)

    resp = post_return_signature(api, cid, client_user, base64.b64encode(b"\x01" * 64).decode())

    assert_error(resp, 409, "INVALID_TRANSITION")
    assert release_state(app, api, cid, owner_user) == before
    assert provider.settle_calls == []


def test_checkout_signature_replayed_on_return_is_signature_invalid(
    app, api, keyring, owner_user, client_user, provider
):
    from tests.fixtures.reports import active_contract

    cid = active_contract(api, keyring, owner_user, client_user)
    checkout = get_report(api, cid, owner_user, "checkout").get_json()
    from tests.fixtures.files import distinct_jpeg
    from tests.fixtures.reports import upload_ok

    create_report(api, cid, owner_user, "return", odometer_km=12_600)
    upload_ok(api, cid, owner_user, distinct_jpeg(4), kind="return")
    return_report = finalize_report(api, cid, owner_user, "return").get_json()
    assert return_report["report_hash"] != checkout["report_hash"]
    replay = keyring.get(client_user).sign_report(cid, "checkout", checkout["report_hash"])
    before = release_state(app, api, cid, owner_user)

    resp = post_return_signature(api, cid, client_user, replay)

    assert_error(resp, 422, "SIGNATURE_INVALID")
    assert release_state(app, api, cid, owner_user) == before
    assert provider.settle_calls == []


def test_signature_of_the_return_hash_made_for_the_checkout_kind_is_rejected(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory()
    wrong_kind = _sig(keyring, client_user, pending, "checkout")
    before = release_state(app, api, pending.contract_id, owner_user)

    resp = post_return_signature(api, pending.contract_id, client_user, wrong_kind)

    assert_error(resp, 422, "SIGNATURE_INVALID")
    assert release_state(app, api, pending.contract_id, owner_user) == before


def test_signature_from_another_contract_is_rejected(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    first = pending_factory()
    second = pending_factory()
    foreign = keyring.get(client_user).sign_report(first.contract_id, "return", first.report["report_hash"])
    before = release_state(app, api, second.contract_id, owner_user)

    resp = post_return_signature(api, second.contract_id, client_user, foreign)

    assert_error(resp, 422, "SIGNATURE_INVALID")
    assert release_state(app, api, second.contract_id, owner_user) == before


@pytest.mark.parametrize("signer", ["owner_signs_as_client", "garbage", "flipped"])
def test_invalid_return_signatures_are_rejected_without_side_effect(
    app, api, keyring, owner_user, client_user, provider, pending_factory, signer
):
    pending = pending_factory()
    cid, report_hash = pending.contract_id, pending.report["report_hash"]
    signature = {
        "owner_signs_as_client": lambda: keyring.get(owner_user).sign_report(cid, "return", report_hash),
        "garbage": lambda: base64.b64encode(b"\x00" * 64).decode(),
        "flipped": lambda: _flip(keyring.get(client_user).sign_report(cid, "return", report_hash)),
    }[signer]()
    before = release_state(app, api, cid, owner_user)

    resp = post_return_signature(api, cid, client_user, signature)

    assert_error(resp, 422, "SIGNATURE_INVALID")
    assert release_state(app, api, cid, owner_user) == before
    assert provider.settle_calls == []


def test_same_party_signing_twice_is_invalid_transition(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory()
    assert sign_return(api, keyring, pending.contract_id, client_user, pending.report).status_code == 200
    before = release_state(app, api, pending.contract_id, owner_user)

    again = sign_return(api, keyring, pending.contract_id, client_user, pending.report)

    assert_error(again, 409, "INVALID_TRANSITION")
    assert release_state(app, api, pending.contract_id, owner_user) == before
    assert provider.settle_calls == []


def test_stranger_cannot_sign_a_return_report(
    app, api, keyring, owner_user, stranger_user, provider, pending_factory
):
    pending = pending_factory()
    before = release_state(app, api, pending.contract_id, owner_user)

    resp = sign_return(api, keyring, pending.contract_id, stranger_user, pending.report)

    assert_error(resp, 404, "NOT_FOUND")
    assert release_state(app, api, pending.contract_id, owner_user) == before


def test_unauthenticated_return_signature_is_rejected(api, provider, pending_factory):
    pending = pending_factory()

    resp = post_return_signature(api, pending.contract_id, None, base64.b64encode(b"\x01" * 64).decode())

    assert_error(resp, 401, "UNAUTHENTICATED")


def test_return_signature_without_idempotency_key_is_validation_error(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory()
    signature = _sig(keyring, client_user, pending)
    before = release_state(app, api, pending.contract_id, owner_user)

    resp = post_return_signature(api, pending.contract_id, client_user, signature, no_key=True)

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert release_state(app, api, pending.contract_id, owner_user) == before


@pytest.mark.parametrize(
    "extra",
    [
        {"retained_cents": 0},
        {"retained_cents": 999_999},
        {"release_cents": 2_500_000},
        {"claimed_retention_cents": 1},
        {"amount_cents": 1},
        {"outcome": "RELEASED"},
        {"party": "owner"},
    ],
)
def test_injecting_amounts_in_the_signature_body_is_validation_error(
    app, api, keyring, owner_user, client_user, provider, pending_factory, extra
):
    pending = pending_factory(retention_cents=120_000)
    body = {"signature": _sig(keyring, client_user, pending), **extra}
    before = release_state(app, api, pending.contract_id, owner_user)

    resp = post_return_signature(api, pending.contract_id, client_user, None, body=body)

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert release_state(app, api, pending.contract_id, owner_user) == before
    assert provider.settle_calls == []


@pytest.mark.parametrize(
    "body", [{}, {"signature": None}, {"signature": 12}, {"signature": ["a"]}, {"signature": ""}, []]
)
def test_malformed_return_signature_body_is_a_422_not_a_500(
    app, api, keyring, owner_user, client_user, provider, pending_factory, body
):
    pending = pending_factory()
    before = release_state(app, api, pending.contract_id, owner_user)

    resp = post_return_signature(api, pending.contract_id, client_user, None, body=body)

    assert resp.status_code in {422}
    assert_error(resp, 422, codes={"VALIDATION_ERROR", "SIGNATURE_INVALID"})
    assert release_state(app, api, pending.contract_id, owner_user) == before


# ------------------------------------------------------------------ remplacement du rapport de retour


def _replace_return_report(api, keyring, owner_user, cid, retention_cents):
    resp = supersede_report(api, cid, owner_user, "return")
    assert resp.status_code in {200, 201}, resp.get_data(as_text=True)
    draft = get_report(api, cid, owner_user, "return").get_json()
    assert draft["status"] == "DRAFT"
    photo_ids = [f["id"] for f in draft["files"]]
    assert photo_ids, draft
    damages = [{"zone": "hood", "severity": "major", "description": "Choc", "file_ids": photo_ids[:1]}]
    update = update_report(
        api, cid, owner_user, "return", odometer_km=12_600, damages=damages,
        claimed_retention_cents=retention_cents,
    )  # fmt: skip
    assert update.status_code == 200, update.get_data(as_text=True)
    frozen = finalize_report(api, cid, owner_user, "return")
    assert frozen.status_code == 200, frozen.get_data(as_text=True)
    return frozen.get_json()


def test_replaced_return_report_requires_new_signatures_and_uses_the_new_retention(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=10_000)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    revised = _replace_return_report(api, keyring, owner_user, cid, 900_000)
    assert revised["report_hash"] != pending.report["report_hash"]
    assert revised["revision"] == 2

    stale = sign_return(api, keyring, cid, owner_user, pending.report)
    assert stale.status_code in {409, 422}, stale.get_data(as_text=True)
    assert_error(stale, stale.status_code, codes={"INVALID_TRANSITION", "SIGNATURE_INVALID"})
    assert provider.settle_calls == []
    assert api.get(cid, owner_user).get_json()["status"] == "INSPECTION_PENDING"

    assert sign_return(api, keyring, cid, owner_user, revised).status_code == 200
    assert provider.settle_calls == []
    final = sign_return(api, keyring, cid, client_user, revised)

    assert final.status_code == 200, final.get_data(as_text=True)
    assert final.get_json()["funds"]["retained_cents"] == 900_000
    assert [c[1:3] for c in provider.settle_calls] == [(DEPOSIT_CENTS - 900_000, 900_000)]


def test_finalizing_a_revised_return_report_records_revise_return_report_event(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=10_000)
    cid = pending.contract_id
    before = api.get(cid, owner_user).get_json()
    events_before = _events(api, cid, owner_user)

    _replace_return_report(api, keyring, owner_user, cid, 900_000)

    after = api.get(cid, owner_user).get_json()
    events = _events(api, cid, owner_user)
    last = events[-1]
    assert (last["event"], last["from_status"], last["to_status"]) == (
        "revise_return_report",
        "INSPECTION_PENDING",
        "INSPECTION_PENDING",
    )
    assert len(events) == len(events_before) + 1
    assert after["version"] == before["version"] + 1
    assert after["status"] == "INSPECTION_PENDING"


def test_client_signature_on_old_revision_does_not_release_the_new_retention(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=10_000)
    cid = pending.contract_id
    sign_return(api, keyring, cid, client_user, pending.report)
    revised = _replace_return_report(api, keyring, owner_user, cid, 2_000_000)

    owner_signs = sign_return(api, keyring, cid, owner_user, revised)

    assert owner_signs.status_code == 200
    assert owner_signs.get_json().get("receipt") is None
    assert api.get(cid, owner_user).get_json()["status"] == "INSPECTION_PENDING"
    assert provider.settle_calls == []
    assert_error(get_receipt(api, cid, owner_user), 404, "NOT_FOUND")


# ------------------------------------------------------------------ matrice terminale (HTTP)


def _terminal_actions(api, keyring, owner, client, pending):
    cid = pending.contract_id
    checkout_hash = get_report(api, cid, owner, "checkout").get_json()["report_hash"]
    checkout_sig = keyring.get(client).sign_report(cid, "checkout", checkout_hash)
    return {
        "cancel_owner": lambda: api.cancel(cid, owner),
        "cancel_client": lambda: api.cancel(cid, client),
        "sign_contract": lambda: api.sign(cid, client),
        "deposit": lambda: api.deposit(cid, client),
        "start": lambda: api.start(cid, owner),
        "checkout_signature": lambda: post_signature(api, cid, client, checkout_sig),
        "return_signature_client": lambda: sign_return(api, keyring, cid, client, pending.report),
        "return_signature_owner": lambda: sign_return(api, keyring, cid, owner, pending.report),
        "create_return_report": lambda: create_report(api, cid, owner, "return", odometer_km=12_700),
        "update_return_report": lambda: update_report(api, cid, owner, "return", odometer_km=12_700),
        "finalize_return_report": lambda: finalize_report(api, cid, owner, "return"),
        "supersede_return_report": lambda: supersede_report(api, cid, owner, "return"),
        "supersede_checkout_report": lambda: supersede_report(api, cid, owner, "checkout"),
    }


@pytest.mark.parametrize("retention", [0, 120_000], ids=["RELEASED", "SETTLED"])
def test_terminal_contract_rejects_every_event(
    app, api, keyring, owner_user, client_user, provider, pending_factory, retention
):
    pending = pending_factory(retention_cents=retention)
    release(api, keyring, pending, owner_user, client_user)
    before = release_state(app, api, pending.contract_id, owner_user)
    calls_before = list(provider.settle_calls)

    for name, action in _terminal_actions(api, keyring, owner_user, client_user, pending).items():
        resp = action()
        assert resp.status_code == 409, (name, resp.status_code, resp.get_data(as_text=True))
        assert_error(resp, 409, "INVALID_TRANSITION")
        assert release_state(app, api, pending.contract_id, owner_user) == before, name

    assert provider.settle_calls == calls_before
    assert provider.refund_calls == []
    assert provider.paid_out_cents == DEPOSIT_CENTS


def test_terminal_contract_rejects_every_event_with_a_fresh_idempotency_key_and_replay(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory()
    release(api, keyring, pending, owner_user, client_user)
    key = new_key()

    first = api.cancel(pending.contract_id, owner_user, idem=key)
    replay = api.cancel(pending.contract_id, owner_user, idem=key)

    assert_error(first, 409, "INVALID_TRANSITION")
    assert (replay.status_code, replay.get_json()) == (first.status_code, first.get_json())


def test_new_deposit_after_release_does_not_create_a_second_deposit(
    app, api, keyring, owner_user, client_user, provider, pending_factory
):
    pending = pending_factory(retention_cents=5_000)
    release(api, keyring, pending, owner_user, client_user)

    assert_error(api.deposit(pending.contract_id, client_user), 409, "INVALID_TRANSITION")

    assert len(deposit_rows(app, pending.contract_id)) == 1
