"""Red team F4 : liberation de la caution (argent et preuve).

Invariants : jamais de 500, format d'erreur ``{"error": ...}``, et apres chaque erreur : statuts, montants,
signatures, quittance (absente) et prestataire (aucun paiement) inchanges. Un test rouge = une faille
(voir docs/audits/adversarial-2026-10-08.md, section F4). Pas de skip/xfail.
"""

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import func, select

from app.extensions import db
from tests.fixtures.deposits import (
    RecordingProvider,
    awaiting_deposit_contract,
    deposit_rows,
    run_concurrently,
)
from tests.fixtures.files import distinct_jpeg
from tests.fixtures.helpers import DEPOSIT_BODY, Api, TestUser, assert_error, new_key
from tests.fixtures.release import (
    DEPOSIT_CENTS,
    SERVER_KEY_B64,
    SERVER_PUBLIC_RAW,
    SERVER_SEED,
    Pending,
    get_receipt,
    pending_contract,
    post_return_signature,
    release,
    release_state,
    return_signatures_url,
    sign_return,
)
from tests.fixtures.reports import (
    KeyPair,
    KeyRing,
    create_report,
    finalize_report,
    get_report,
    post_signature,
    report_message,
    supersede_report,
    update_report,
    upload_file,
)

pytestmark = pytest.mark.adversarial

GHOST_ID = "00000000-0000-4000-8000-000000000000"
RETENTION = 120_000
FAKE_JPEG = distinct_jpeg(9)


@pytest.fixture
def provider(app: Flask) -> RecordingProvider:
    recording = RecordingProvider()
    app.extensions["payment_provider"] = recording
    return recording


@pytest.fixture
def keyring(api: Api) -> KeyRing:
    return KeyRing(api)


# --------------------------------------------------------------------------- aides locales


def receipts_count(app: Flask, contract_id: str) -> int:
    from app.models import SettlementReceipt

    with app.app_context():
        stmt = select(func.count()).select_from(SettlementReceipt)
        return int(db.session.scalar(stmt.where(SettlementReceipt.contract_id == contract_id)) or 0)


def sig_for(
    keyring: KeyRing, user: TestUser, contract_id: str, report_hash: str, kind: str = "return"
) -> str:
    return keyring.get(user).sign_report(contract_id, kind, report_hash)


def assert_no_payout(provider: RecordingProvider) -> None:
    assert provider.settled == {}, provider.settled
    assert provider.paid_out_cents == 0


def assert_single_settlement(app: Flask, provider: RecordingProvider, pending: Pending) -> None:
    """Un seul reglement reussi, une seule quittance, invariant comptable en base ET chez le prestataire."""
    assert len(provider.settled) == 1, provider.settled
    assert provider.paid_out_cents == pending.deposit_cents
    rows = deposit_rows(app, pending.contract_id)
    assert len(rows) == 1
    row = rows[0]
    assert row["held_cents"] == 0
    assert row["released_cents"] + row["retained_cents"] == row["amount_cents"] == pending.deposit_cents
    assert row["retained_cents"] == pending.retention_cents
    _, released, captured, _ = next(iter(provider.settled.values()))
    assert (released, captured) == (row["released_cents"], row["retained_cents"])
    assert receipts_count(app, pending.contract_id) == 1


def outcome(resp: Any) -> tuple[int, Any]:
    return resp.status_code, resp.get_json(silent=True)


def assert_clean(status: int, body: Any) -> None:
    assert status < 500 or status == 503, (status, body)
    if status >= 400:
        assert isinstance(body, dict), body
        assert set(body) == {"error"}, body


def released_contract(
    app: Flask, api: Api, keyring: KeyRing, owner: TestUser, client: TestUser, retention: int = RETENTION
) -> tuple[Pending, dict[str, Any], list[dict[str, Any]]]:
    pending = pending_contract(api, keyring, owner, client, retention_cents=retention)
    _, final = release(api, keyring, pending, owner, client)
    receipt = final.get_json()["receipt"]
    events = api.events(pending.contract_id, owner).get_json()["events"]
    return pending, receipt, events


def reseal_without_key(receipt: dict[str, str], content: dict[str, Any]) -> dict[str, str]:
    """Contenu modifie, empreinte recalculee, signature du serveur d'origine (l'attaquant n'a pas la cle)."""
    raw = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "canonical_json": raw.decode("utf-8"),
        "receipt_hash": hashlib.sha256(raw).hexdigest(),
        "server_signature": receipt["server_signature"],
    }


# =========================================================================== rejeu de signatures


def test_checkout_signature_replayed_on_return_rejected(app, api, keyring, owner_user, client_user, provider):
    pending = pending_contract(api, keyring, owner_user, client_user)
    cid = pending.contract_id
    checkout_hash = get_report(api, cid, owner_user, "checkout").get_json()["report_hash"]
    before = release_state(app, api, cid, owner_user)

    attempts = [
        sig_for(keyring, client_user, cid, checkout_hash, "checkout"),  # signature d'origine du depart
        sig_for(keyring, client_user, cid, pending.report["report_hash"], "checkout"),  # bon hash, kind
        sig_for(keyring, client_user, cid, checkout_hash, "return"),  # bon kind, hash du depart
    ]
    for signature in attempts:
        assert_error(post_return_signature(api, cid, client_user, signature), 422, "SIGNATURE_INVALID")

    assert release_state(app, api, cid, owner_user) == before
    assert_no_payout(provider)


def test_signature_from_other_contract_rejected(app, api, keyring, owner_user, client_user, provider):
    target = pending_contract(api, keyring, owner_user, client_user)
    other = pending_contract(api, keyring, owner_user, client_user)
    before = release_state(app, api, target.contract_id, owner_user)

    foreign = sig_for(keyring, client_user, other.contract_id, other.report["report_hash"])
    # meme rapport d'un autre contrat mais message lie au contrat cible : hash etranger.
    crossed = sig_for(keyring, client_user, target.contract_id, other.report["report_hash"])
    for signature in (foreign, crossed):
        resp = post_return_signature(api, target.contract_id, client_user, signature)
        assert_error(resp, 422, "SIGNATURE_INVALID")

    assert release_state(app, api, target.contract_id, owner_user) == before
    assert_no_payout(provider)
    # La signature reste valable sur SON contrat : la preuve est bien liee au contrat.
    resp = post_return_signature(api, other.contract_id, client_user, foreign)
    assert resp.status_code == 200, resp.get_data(as_text=True)


def test_superseded_revision_signature_replay_rejected(app, api, keyring, owner_user, client_user, provider):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    old_sig = sig_for(keyring, client_user, cid, pending.report["report_hash"])
    assert post_return_signature(api, cid, client_user, old_sig).status_code == 200

    assert supersede_report(api, cid, owner_user, "return").status_code == 201
    resp = finalize_report(api, cid, owner_user, "return")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    new_report = resp.get_json()
    assert new_report["report_hash"] != pending.report["report_hash"]
    assert sign_return(api, keyring, cid, owner_user, new_report).status_code == 200
    before = release_state(app, api, cid, owner_user)

    assert_error(post_return_signature(api, cid, client_user, old_sig), 422, "SIGNATURE_INVALID")

    assert release_state(app, api, cid, owner_user) == before
    assert before["state"]["contract"]["status"] == "INSPECTION_PENDING"
    assert_no_payout(provider)


# =========================================================================== retenue manipulee


def test_owner_raises_retention_after_client_signature_requires_new_client_signature(
    app, api, keyring, owner_user, client_user, provider
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=0, damage=True)
    cid = pending.contract_id
    client_sig = sig_for(keyring, client_user, cid, pending.report["report_hash"])
    assert post_return_signature(api, cid, client_user, client_sig).status_code == 200

    resp = supersede_report(api, cid, owner_user, "return")
    assert resp.status_code == 201, resp.get_data(as_text=True)
    draft = resp.get_json()
    resp = update_report(
        api,
        cid,
        owner_user,
        "return",
        odometer_km=draft["odometer_km"],
        damages=draft["damages"],
        claimed_retention_cents=DEPOSIT_CENTS,  # retenue totale
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    resp = finalize_report(api, cid, owner_user, "return")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    greedy = resp.get_json()

    resp = sign_return(api, keyring, cid, owner_user, greedy)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert "receipt" not in resp.get_json()
    before = release_state(app, api, cid, owner_user)
    assert before["state"]["contract"]["status"] == "INSPECTION_PENDING"
    assert [s["party"] for s in before["return_report"]["signatures"]] == ["owner"]

    assert_error(post_return_signature(api, cid, client_user, client_sig), 422, "SIGNATURE_INVALID")
    assert release_state(app, api, cid, owner_user) == before
    assert deposit_rows(app, cid)[0]["status"] == "HELD"
    assert_no_payout(provider)
    assert receipts_count(app, cid) == 0


@pytest.mark.parametrize(
    "injected",
    [
        {"retained_cents": 0},
        {"release_cents": DEPOSIT_CENTS},
        {"claimed_retention_cents": 0},
        {"report_hash": "0" * 64},
        {"deposit_cents": 1},
        {"party": "client"},
    ],
)
def test_amount_injection_in_signature_body_rejected(
    app, api, keyring, owner_user, client_user, provider, injected
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    before = release_state(app, api, cid, owner_user)
    signature = sig_for(keyring, owner_user, cid, pending.report["report_hash"])

    resp = post_return_signature(api, cid, owner_user, None, body={"signature": signature, **injected})
    assert_error(resp, 422, "VALIDATION_ERROR")
    assert release_state(app, api, cid, owner_user) == before
    assert_no_payout(provider)

    # La signature legitime libere exactement la retenue FIGEE, pas celle injectee.
    resp = post_return_signature(api, cid, owner_user, signature)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert_single_settlement(app, provider, pending)


@pytest.mark.parametrize(
    "body",
    [
        {"signature": None},
        {"signature": 12345},
        {"signature": ["a"]},
        {"signature": "A" * 1_000_000},
        {"signature": base64.b64encode(b"\x00" * 63).decode()},
        {"signature": "not base64 !!"},
        {},
        [],
        "signature",
    ],
)
def test_garbage_signature_body_rejected(app, api, keyring, owner_user, client_user, provider, body):
    pending = pending_contract(api, keyring, owner_user, client_user)
    keyring.get(client_user)
    before = release_state(app, api, pending.contract_id, owner_user)
    resp = post_return_signature(api, pending.contract_id, client_user, None, body=body)
    assert resp.status_code in {413, 422}, resp.get_data(as_text=True)[:300]
    assert_error(resp, resp.status_code)
    assert release_state(app, api, pending.contract_id, owner_user) == before
    assert_no_payout(provider)


def test_malformed_json_and_missing_key_rejected(app, api, keyring, owner_user, client_user, provider):
    pending = pending_contract(api, keyring, owner_user, client_user)
    cid = pending.contract_id
    before = release_state(app, api, cid, owner_user)
    resp = api.request("POST", return_signatures_url(cid), client_user, raw='{"signature": ', idem=new_key())
    assert resp.status_code in {400, 422}
    assert_error(resp, resp.status_code)
    signature = sig_for(keyring, client_user, cid, pending.report["report_hash"])
    resp = post_return_signature(api, cid, client_user, signature, no_key=True)
    assert resp.status_code in {400, 422}
    assert_error(resp, resp.status_code)
    assert release_state(app, api, cid, owner_user) == before


# =========================================================================== concurrence


def _post_job(cid: str, user: TestUser, signature: str, idem: str):
    def job(local: Api) -> tuple[int, Any]:
        return outcome(post_return_signature(local, cid, user, signature, idem=idem))

    return job


def test_concurrent_second_signature_same_key_settles_once(
    app, api, keyring, owner_user, client_user, provider
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    signature = sig_for(keyring, owner_user, cid, pending.report["report_hash"])
    key = new_key()

    results = run_concurrently(app, [_post_job(cid, owner_user, signature, key) for _ in range(4)])

    for status, body in results:
        assert_clean(status, body)
    oks = [body for status, body in results if status == 200]
    assert oks, results
    assert all(body == oks[0] for body in oks), "rejeu idempotent avec un corps different"
    assert len(provider.settle_calls) == 1, provider.settle_calls
    assert_single_settlement(app, provider, pending)


def test_concurrent_second_signature_different_keys_settles_once(
    app, api, keyring, owner_user, client_user, provider
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    signature = sig_for(keyring, owner_user, cid, pending.report["report_hash"])

    results = run_concurrently(app, [_post_job(cid, owner_user, signature, new_key()) for _ in range(5)])

    statuses = sorted(status for status, _ in results)
    assert statuses == [200, 409, 409, 409, 409], results
    for status, body in results:
        assert_clean(status, body)
        if status == 409:
            assert body["error"]["code"] == "INVALID_TRANSITION"
    assert_single_settlement(app, provider, pending)


def test_both_parties_sign_simultaneously_settles_once(app, api, keyring, owner_user, client_user, provider):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    jobs = []
    for user in (client_user, owner_user):
        signature = sig_for(keyring, user, cid, pending.report["report_hash"])
        jobs += [_post_job(cid, user, signature, new_key()) for _ in range(2)]

    results = run_concurrently(app, jobs)

    for status, body in results:
        assert_clean(status, body)
    assert sorted(status for status, _ in results) == [200, 200, 409, 409], results
    assert sum(1 for _, body in results if isinstance(body, dict) and "receipt" in body) == 1
    assert api.get(cid, owner_user).get_json()["status"] == "SETTLED"
    assert_single_settlement(app, provider, pending)


def test_provider_outage_then_rapid_concurrent_retries_pay_once(
    app, api, keyring, owner_user, client_user, provider
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    signature = sig_for(keyring, owner_user, cid, pending.report["report_hash"])
    provider.fail_next_settles = 2

    results = run_concurrently(app, [_post_job(cid, owner_user, signature, new_key()) for _ in range(6)])

    for status, body in results:
        assert_clean(status, body)
        if status == 503:
            assert body["error"]["code"] == "PAYMENT_UNAVAILABLE"
    assert [s for s, _ in results].count(200) == 1, results
    assert_single_settlement(app, provider, pending)


def test_provider_outage_sequential_retries_same_key_pay_once(
    app, api, keyring, owner_user, client_user, provider
):
    pending = pending_contract(api, keyring, owner_user, client_user)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    before = release_state(app, api, cid, owner_user)
    signature = sig_for(keyring, owner_user, cid, pending.report["report_hash"])
    key = new_key()
    provider.fail_next_settles = 3

    for _ in range(3):
        resp = post_return_signature(api, cid, owner_user, signature, idem=key)
        assert_error(resp, 503, "PAYMENT_UNAVAILABLE")
        assert release_state(app, api, cid, owner_user) == before
        assert_no_payout(provider)

    first = post_return_signature(api, cid, owner_user, signature, idem=key)
    again = post_return_signature(api, cid, owner_user, signature, idem=key)
    assert first.status_code == again.status_code == 200
    assert first.get_json() == again.get_json()
    assert_single_settlement(app, provider, pending)


class SettlesThenTimesOut(RecordingProvider):
    """Panne ambigue : le prestataire execute le reglement mais la reponse se perd (timeout)."""

    def __init__(self) -> None:
        super().__init__()
        self.timeouts = 1

    def settle(self, ref: str, *, release_cents: int, capture_cents: int, key: str) -> str:
        from app.domain.errors import PaymentUnavailable

        settlement = super().settle(ref, release_cents=release_cents, capture_cents=capture_cents, key=key)
        if self.timeouts > 0:
            self.timeouts -= 1
            raise PaymentUnavailable("delai depasse")
        return settlement


def test_ambiguous_settle_then_revision_never_diverges_from_provider(
    app, api, keyring, owner_user, client_user
):
    """Apres un reglement execute mais non confirme, le loueur ne doit pas pouvoir changer la ventilation.

    Sinon : prestataire deja paye avec l'ancienne ventilation, base toujours HELD, et tout nouveau
    reglement (meme cle, autres montants) est refuse : caution bloquee et etat incoherent.
    """
    provider = SettlesThenTimesOut()
    app.extensions["payment_provider"] = provider
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    assert_error(sign_return(api, keyring, cid, owner_user, pending.report), 503, "PAYMENT_UNAVAILABLE")
    assert provider.paid_out_cents == DEPOSIT_CENTS  # l'argent est parti

    resp = supersede_report(api, cid, owner_user, "return")
    steps = [("supersede", resp.status_code)]
    if resp.status_code == 201:
        resp = update_report(api, cid, owner_user, "return", odometer_km=12_600, claimed_retention_cents=0)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        resp = finalize_report(api, cid, owner_user, "return")
        assert resp.status_code == 200, resp.get_data(as_text=True)
        revised = resp.get_json()
        for user in (client_user, owner_user):
            resp = sign_return(api, keyring, cid, user, revised)
            assert resp.status_code != 500, resp.get_data(as_text=True)
            steps.append((f"sign {user.role}", resp.status_code))
    else:
        assert_error(resp, 409)

    row = deposit_rows(app, cid)[0]
    _, released, captured, _ = next(iter(provider.settled.values()))
    assert row["status"] != "HELD", f"prestataire paye mais caution toujours HELD en base : {steps}"
    assert (row["released_cents"], row["retained_cents"]) == (released, captured)


# =========================================================================== etats terminaux


@pytest.mark.parametrize("retention", [0, RETENTION], ids=["RELEASED", "SETTLED"])
def test_terminal_contract_rejects_everything(
    app, api, keyring, owner_user, client_user, provider, retention
):
    pending, receipt, _ = released_contract(app, api, keyring, owner_user, client_user, retention)
    cid = pending.contract_id
    before = release_state(app, api, cid, owner_user)
    calls = list(provider.settle_calls)
    report = pending.report

    attacks = {
        "cancel client": lambda: api.cancel(cid, client_user),
        "cancel owner": lambda: api.cancel(cid, owner_user),
        "deposit": lambda: api.deposit(cid, client_user, dict(DEPOSIT_BODY)),
        "start": lambda: api.start(cid, owner_user),
        "sign contract": lambda: api.sign(cid, client_user),
        "supersede return": lambda: supersede_report(api, cid, owner_user, "return"),
        "supersede checkout": lambda: supersede_report(api, cid, owner_user, "checkout"),
        "finalize return": lambda: finalize_report(api, cid, owner_user, "return"),
        "update return": lambda: update_report(api, cid, owner_user, "return", claimed_retention_cents=0),
        "create return": lambda: create_report(api, cid, owner_user, "return"),
        "resign client": lambda: sign_return(api, keyring, cid, client_user, report),
        "resign owner": lambda: sign_return(api, keyring, cid, owner_user, report),
        "sign checkout": lambda: post_signature(api, cid, client_user, "A" * 88),
        "upload return": lambda: upload_file(api, cid, owner_user, FAKE_JPEG, kind="return"),
    }
    failures = {}
    for name, attack in attacks.items():
        resp = attack()
        if resp.status_code != 409 or not resp.is_json or set(resp.get_json()) != {"error"}:
            failures[name] = (resp.status_code, resp.get_data(as_text=True)[:200])
    assert not failures, failures

    assert release_state(app, api, cid, owner_user) == before
    assert provider.settle_calls == calls
    assert get_receipt(api, cid, owner_user).get_json() == receipt
    assert receipts_count(app, cid) == 1


def test_replayed_release_request_returns_same_receipt_without_new_payment(
    app, api, keyring, owner_user, client_user, provider
):
    pending = pending_contract(api, keyring, owner_user, client_user, retention_cents=RETENTION)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    key = new_key()
    first = sign_return(api, keyring, cid, owner_user, pending.report, idem=key)
    assert first.status_code == 200
    calls = len(provider.settle_calls)
    for _ in range(3):
        again = sign_return(api, keyring, cid, owner_user, pending.report, idem=key)
        assert again.status_code == 200
        assert again.get_json() == first.get_json()
    assert len(provider.settle_calls) == calls
    assert_single_settlement(app, provider, pending)


# =========================================================================== acces


def test_receipt_idor_and_unauthenticated(
    app, api, keyring, owner_user, client_user, stranger_user, provider
):
    pending, receipt, _ = released_contract(app, api, keyring, owner_user, client_user)
    cid = pending.contract_id
    assert_error(get_receipt(api, cid, stranger_user), 404, "NOT_FOUND")
    assert_error(get_receipt(api, cid, None), 401, "UNAUTHENTICATED")
    assert_error(get_receipt(api, GHOST_ID, owner_user), 404, "NOT_FOUND")
    for bad in ("not-a-uuid", "..%2F..%2Fetc%2Fpasswd", "' OR 1=1 --"):
        resp = api.request("GET", f"/api/contracts/{bad}/receipt", owner_user)
        assert resp.status_code == 404, resp.get_data(as_text=True)[:200]
    assert get_receipt(api, cid, client_user).get_json() == receipt
    # Avant liberation : pas de quittance, meme pour les parties.
    other = pending_contract(api, keyring, owner_user, client_user)
    assert_error(get_receipt(api, other.contract_id, client_user), 404, "NOT_FOUND")


def test_stranger_cannot_sign_return(app, api, keyring, owner_user, client_user, stranger_user, provider):
    pending = pending_contract(api, keyring, owner_user, client_user)
    cid = pending.contract_id
    assert sign_return(api, keyring, cid, client_user, pending.report).status_code == 200
    before = release_state(app, api, cid, owner_user)
    signature = sig_for(keyring, stranger_user, cid, pending.report["report_hash"])
    assert_error(post_return_signature(api, cid, stranger_user, signature), 404, "NOT_FOUND")
    assert_error(post_return_signature(api, cid, None, signature), 401, "UNAUTHENTICATED")
    # Le client tente de signer "pour" le loueur (deuxieme signature avec sa propre cle).
    client_again = sig_for(keyring, client_user, cid, pending.report["report_hash"])
    assert_error(post_return_signature(api, cid, client_user, client_again), 409, "INVALID_TRANSITION")
    # Le client signe avec la cle du loueur qu'il n'a pas : signature forgee par sa propre cle.
    assert release_state(app, api, cid, owner_user) == before
    assert_no_payout(provider)


def test_server_key_endpoint_never_leaks_private_key(app, api):
    resp = api.request("GET", "/api/server-key")
    assert resp.status_code == 200
    body = resp.get_json()
    assert set(body) == {"public_key", "fingerprint"}
    assert base64.b64decode(body["public_key"]) == SERVER_PUBLIC_RAW
    assert body["fingerprint"] == hashlib.sha256(SERVER_PUBLIC_RAW).hexdigest()
    text = resp.get_data(as_text=True)
    for secret in (SERVER_KEY_B64, SERVER_SEED.hex(), base64.urlsafe_b64encode(SERVER_SEED).decode()):
        assert secret not in text
    for method in ("POST", "PUT", "DELETE"):
        other = api.request(method, "/api/server-key", body={})
        assert other.status_code == 405, other.get_data(as_text=True)[:200]
        assert_error(other, 405)


def test_server_signing_key_absent_from_config(app):
    assert "SERVER_SIGNING_KEY" not in app.config
    leaked = [k for k, v in app.config.items() if isinstance(v, str | bytes) and _contains_seed(v)]
    assert not leaked, leaked


def _contains_seed(value: str | bytes) -> bool:
    raw = value if isinstance(value, bytes) else value.encode("utf-8", "ignore")
    return SERVER_KEY_B64.encode() in raw or SERVER_SEED in raw


# =========================================================================== quittance falsifiee


Events = list[dict[str, Any]] | None


def _verify(receipt: dict[str, Any], events: Events = None, key: bytes = SERVER_PUBLIC_RAW) -> None:
    from scripts.verify_receipt import verify_receipt

    verify_receipt(receipt, key, events)


def _rejects(receipt: dict[str, Any], events: Events = None, key: bytes = SERVER_PUBLIC_RAW) -> None:
    from scripts.verify_receipt import ReceiptInvalid

    with pytest.raises(ReceiptInvalid):
        _verify(receipt, events, key)


def _content(receipt: dict[str, str]) -> dict[str, Any]:
    return json.loads(receipt["canonical_json"])


def test_forged_receipts_rejected_offline(app, api, keyring, owner_user, client_user, provider):
    _, receipt, events = released_contract(app, api, keyring, owner_user, client_user)
    _, receipt_b, _ = released_contract(app, api, keyring, owner_user, client_user)
    _verify(receipt, events)  # temoin : la vraie quittance se verifie

    forged: dict[str, dict[str, Any]] = {}
    content = _content(receipt)

    one_cent = copy.deepcopy(content)
    one_cent["released_to_client_cents"] += 1
    one_cent["retained_by_owner_cents"] -= 1
    forged["un centime, hash recalcule"] = reseal_without_key(receipt, one_cent)
    forged["un centime, hash d'origine"] = {
        **reseal_without_key(receipt, one_cent),
        "receipt_hash": receipt["receipt_hash"],
    }
    forged["empreinte modifiee"] = {**receipt, "receipt_hash": "f" * 64}
    swapped = copy.deepcopy(content)
    swapped["signatures"].reverse()
    forged["ordre des signatures"] = reseal_without_key(receipt, swapped)
    attacker = KeyPair()
    stolen = copy.deepcopy(content)
    message = report_message(stolen["contract_id"], "return", stolen["return_report"]["hash"])
    for entry in stolen["signatures"]:
        if entry["party"] == "client":
            entry.update(
                public_key=attacker.public_b64,
                key_fingerprint=attacker.fingerprint,
                signature=attacker.sign(message),
            )
    forged["cle du client remplacee"] = reseal_without_key(receipt, stolen)
    sig_a, sig_b = receipt["server_signature"], receipt_b["server_signature"]
    forged["signature serveur d'une autre quittance"] = {**receipt, "server_signature": sig_b}
    forged["contenu d'une autre quittance"] = {**receipt_b, "server_signature": sig_a}
    forged["canonical non canonique"] = {**receipt, "canonical_json": receipt["canonical_json"] + " "}
    forged["signature tronquee"] = {**receipt, "server_signature": receipt["server_signature"][:-4]}

    accepted = []
    for name, fake in forged.items():
        from scripts.verify_receipt import ReceiptInvalid

        try:
            _verify(fake, events)
        except ReceiptInvalid:
            continue
        accepted.append(name)
    assert not accepted, accepted
    _rejects(receipt, events, key=KeyPair().public_raw)


def _tampered_exports(events: list[dict[str, Any]], foreign: list[dict[str, Any]]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    out["evenement supprime"] = events[:3] + events[4:]
    out["dernier evenement supprime"] = events[:-1]
    reordered = list(events)
    reordered[2], reordered[3] = reordered[3], reordered[2]
    out["reordonne"] = reordered
    modified = copy.deepcopy(events)
    modified[4]["actor_id"] = GHOST_ID
    out["acteur modifie"] = modified
    status = copy.deepcopy(events)
    status[-1]["to_status"] = "RELEASED" if status[-1]["to_status"] == "SETTLED" else "SETTLED"
    out["statut final modifie"] = status
    out["rejoue d'un autre contrat"] = foreign
    out["export vide"] = []
    payload = copy.deepcopy(events)
    payload[-1]["payload"] = {"report_id": GHOST_ID, "report_hash": "0" * 64}
    out["payload expose modifie"] = payload
    return out


def test_forged_event_exports_rejected_offline(app, api, keyring, owner_user, client_user, provider):
    _, receipt, events = released_contract(app, api, keyring, owner_user, client_user)
    _, _, foreign = released_contract(app, api, keyring, owner_user, client_user)
    _verify(receipt, events)

    from scripts.verify_receipt import ReceiptInvalid

    accepted = []
    for name, export in _tampered_exports(events, foreign).items():
        try:
            _verify(receipt, export)
        except ReceiptInvalid:
            continue
        accepted.append(name)
    assert not accepted, f"exports falsifies acceptes : {accepted}"


def test_verify_receipt_cli_rejects_forged_export(
    app, api, keyring, owner_user, client_user, provider, tmp_path: Path
):
    from scripts.verify_receipt import main

    _, receipt, events = released_contract(app, api, keyring, owner_user, client_user)
    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
    key = base64.b64encode(SERVER_PUBLIC_RAW).decode()

    good = tmp_path / "events.json"
    good.write_text(json.dumps({"events": events}), encoding="utf-8")
    assert main([str(receipt_file), "--events", str(good), "--server-key", key]) == 0

    for name, export in _tampered_exports(events, []).items():
        if name == "payload expose modifie":
            continue  # couvert par le test hors CLI
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"events": export}), encoding="utf-8")
        assert main([str(receipt_file), "--events", str(path), "--server-key", key]) == 1, name

    garbage = tmp_path / "garbage.json"
    garbage.write_text('{"events": [1, "x", null]}', encoding="utf-8")
    assert main([str(receipt_file), "--events", str(garbage), "--server-key", key]) in {1, 2}
    garbage.write_text("not json", encoding="utf-8")
    assert main([str(garbage), "--server-key", key]) == 2


# =========================================================================== chaine d'evenements


def test_concurrent_event_writes_keep_linear_chain(app, api, owner_user, client_user, provider):
    from app.domain.event_chain import verify_chain

    cid = awaiting_deposit_contract(api, owner_user, client_user)
    down = {**DEPOSIT_BODY, "payment_method": "demo_provider_down"}

    def job(body: dict[str, Any]):
        def run(local: Api) -> tuple[int, Any]:
            return outcome(local.deposit(cid, client_user, dict(body)))

        return run

    jobs = [job(down) for _ in range(6)] + [job(dict(DEPOSIT_BODY)) for _ in range(2)]
    results = run_concurrently(app, jobs)

    for status, body in results:
        assert_clean(status, body)
        assert status in {200, 409, 503}, (status, body)
    assert [s for s, _ in results].count(200) == 1, results
    events = api.events(cid, owner_user).get_json()["events"]
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    verify_chain(events)
    assert len({e["prev_hash"] for e in events}) == len(events), "deux maillons sur le meme parent"
    assert api.get(cid, owner_user).get_json()["status"] == "FUNDED"
