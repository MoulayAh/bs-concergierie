"""F1 : idempotence (en-tete Idempotency-Key) et concurrence.

Regles supposees : portee = (cle, utilisateur) ; meme cle + meme corps => reponse initiale rejouee
(meme statut et meme corps), sans nouvel effet ; meme cle + corps different => 409 IDEMPOTENCY_CONFLICT.
"""

import itertools
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.fixtures.helpers import VALID_BODY, Api, assert_error, count_rows, snapshot

pytestmark = pytest.mark.integration


def test_idempotent_creation_replays_response(app, api, owner_user, client_user):
    key = uuid.uuid4().hex

    first = api.create(owner_user, idem=key)
    second = api.create(owner_user, idem=key)

    assert first.status_code == 201
    assert second.status_code == 201
    assert second.get_json() == first.get_json()
    assert count_rows(app, "Contract") == 1
    assert count_rows(app, "EscrowEvent") == 1


def test_creation_replay_is_independent_of_json_key_order(app, api, owner_user, client_user):
    key = uuid.uuid4().hex
    reordered = dict(reversed(list(VALID_BODY.items())))

    first = api.create(owner_user, idem=key)
    second = api.create(owner_user, reordered, idem=key)

    assert second.status_code == 201
    assert second.get_json()["id"] == first.get_json()["id"]
    assert count_rows(app, "Contract") == 1


def test_same_key_with_different_body_is_idempotency_conflict(app, api, owner_user, client_user):
    key = uuid.uuid4().hex
    api.create(owner_user, idem=key)

    resp = api.create(owner_user, {**VALID_BODY, "deposit_cents": 2_500_001}, idem=key)

    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    assert count_rows(app, "Contract") == 1
    assert count_rows(app, "EscrowEvent") == 1


def test_distinct_keys_create_distinct_contracts(app, api, owner_user, client_user):
    first = api.create_ok(owner_user)
    second = api.create_ok(owner_user)

    assert first["id"] != second["id"]
    assert count_rows(app, "Contract") == 2


def test_same_key_from_two_users_does_not_collide(app, api, owner_user, make_user, client_user):
    other_owner = make_user("owner")
    key = uuid.uuid4().hex

    first = api.create(owner_user, idem=key)
    second = api.create(other_owner, idem=key)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.get_json()["id"] != second.get_json()["id"]
    assert second.get_json()["owner"]["id"] == other_owner.id


def test_failed_creation_does_not_burn_the_idempotency_key(app, api, owner_user, client_user):
    key = uuid.uuid4().hex
    bad = api.create(owner_user, {**VALID_BODY, "deposit_cents": -5}, idem=key)
    assert_error(bad, 422, "INVALID_AMOUNT")

    good = api.create(owner_user, idem=key)

    assert good.status_code == 201
    assert count_rows(app, "Contract") == 1


def test_sign_replay_with_same_key_applies_signature_once(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    key = uuid.uuid4().hex

    first = api.sign(cid, client_user, idem=key)
    second = api.sign(cid, client_user, idem=key)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.get_json() == first.get_json()
    assert snapshot(api, cid, owner_user) == ("DRAFT", 2, 2)


def test_cancel_replay_with_same_key_cancels_once(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    key = uuid.uuid4().hex

    first = api.cancel(cid, owner_user, idem=key)
    second = api.cancel(cid, owner_user, idem=key)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.get_json() == first.get_json()
    assert snapshot(api, cid, owner_user) == ("CANCELLED", 2, 2)


def test_same_key_reused_on_another_action_is_idempotency_conflict(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    key = uuid.uuid4().hex
    assert api.sign(cid, owner_user, idem=key).status_code == 200
    before = snapshot(api, cid, owner_user)

    resp = api.cancel(cid, owner_user, idem=key)

    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    assert snapshot(api, cid, owner_user) == before


def test_idempotency_key_rows_are_persisted(app, api, owner_user, client_user):
    api.create_ok(owner_user)

    assert count_rows(app, "IdempotencyKey") == 1


@pytest.mark.parametrize("key", ["", " ", "k" * 1000])
def test_invalid_idempotency_key_is_rejected_without_side_effect(app, api, owner_user, client_user, key):
    headers = {"Idempotency-Key": key}
    resp = api.request("POST", "/api/contracts", owner_user, body=VALID_BODY, headers=headers)

    assert resp.status_code in {400, 422}
    assert_error(resp, resp.status_code)
    assert count_rows(app, "Contract") == 0


# --- concurrence ------------------------------------------------------------------------------------------


def test_concurrent_signatures_of_both_parties_reach_awaiting_deposit_once(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    barrier = threading.Barrier(2)

    def worker(user):
        local = Api(app)
        barrier.wait(timeout=10)
        return local.sign(cid, user)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, owner_user), pool.submit(worker, client_user)]
        responses = [f.result(timeout=30) for f in futures]

    assert [r.status_code for r in responses] == [200, 200]
    status, version, n_events = snapshot(api, cid, owner_user)
    assert status == "AWAITING_DEPOSIT"
    assert version == 3
    events = api.events(cid, owner_user).get_json()["events"]
    assert n_events == 3
    assert [e["event"] for e in events] == ["create", "sign_contract", "sign_contract"]
    assert [e["to_status"] for e in events].count("AWAITING_DEPOSIT") == 1
    assert {e["actor_id"] for e in events[1:]} == {owner_user.id, client_user.id}


def test_concurrent_double_signature_by_same_party_applies_once(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    barrier = threading.Barrier(4)

    def worker():
        local = Api(app)
        barrier.wait(timeout=10)
        return local.sign(cid, client_user)

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = [f.result(timeout=30) for f in [pool.submit(worker) for _ in range(4)]]

    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 409, 409, 409]
    assert snapshot(api, cid, owner_user) == ("DRAFT", 2, 2)


def test_concurrent_cancel_and_sign_leave_a_coherent_state(app, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.sign(cid, owner_user)
    barrier = threading.Barrier(2)

    def worker(action, user):
        local = Api(app)
        barrier.wait(timeout=10)
        return getattr(local, action)(cid, user)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, "sign", client_user), pool.submit(worker, "cancel", owner_user)]
        responses = [f.result(timeout=30) for f in futures]

    assert all(r.status_code in {200, 409} for r in responses)
    assert all(r.status_code != 500 for r in responses)
    status, version, n_events = snapshot(api, cid, owner_user)
    assert status in {"CANCELLED", "AWAITING_DEPOSIT"}
    assert version == n_events
    events = api.events(cid, owner_user).get_json()["events"]
    last = events[-1]["to_status"]
    assert last == status
    for previous, current in itertools.pairwise(events):
        assert current["from_status"] == previous["to_status"]


def test_concurrent_idempotent_creations_with_same_key_create_one_contract(app, api, owner_user, client_user):
    key = uuid.uuid4().hex
    barrier = threading.Barrier(4)

    def worker():
        local = Api(app)
        barrier.wait(timeout=10)
        return local.create(owner_user, idem=key)

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = [f.result(timeout=30) for f in [pool.submit(worker) for _ in range(4)]]

    assert all(r.status_code in {201, 409} for r in responses)
    assert any(r.status_code == 201 for r in responses)
    assert count_rows(app, "Contract") == 1
    assert count_rows(app, "EscrowEvent") == 1
