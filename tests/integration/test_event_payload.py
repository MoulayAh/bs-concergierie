"""Reserve 6 : le motif d'annulation est persiste dans escrow_events.payload et expose par GET /events."""

import pytest
from sqlalchemy import select

from app.extensions import db
from app.models import EscrowEvent


@pytest.fixture(autouse=True)
def _client_exists(client_user):
    """VALID_BODY designe client@demo.test : ce compte doit exister pour creer un contrat."""
    return client_user


def _rows(app, cid):
    with app.app_context():
        found = db.session.scalars(
            select(EscrowEvent).where(EscrowEvent.contract_id == cid).order_by(EscrowEvent.created_at)
        ).all()
        return [(e.event, e.payload, e.payload_hash) for e in found]


def _by_event(rows, name):
    matching = [r for r in rows if r[0] == name]
    assert len(matching) == 1, rows
    return matching[0]


def test_cancel_with_reason_persists_payload_in_database(api, app, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]

    assert api.cancel(cid, client_user, {"reason": "X"}).status_code == 200

    assert _by_event(_rows(app, cid), "cancel")[1] == {"reason": "X"}


def test_cancel_with_reason_keeps_payload_hash_filled(api, app, owner_user):
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, owner_user, {"reason": "X"})

    payload_hash = _by_event(_rows(app, cid), "cancel")[2]

    assert isinstance(payload_hash, str)
    assert len(payload_hash) == 64


def test_cancel_payload_hash_differs_for_different_reasons(api, app, owner_user):
    first = api.create_ok(owner_user)["id"]
    second = api.create_ok(owner_user)["id"]
    api.cancel(first, owner_user, {"reason": "A"})
    api.cancel(second, owner_user, {"reason": "B"})

    assert _by_event(_rows(app, first), "cancel")[2] != _by_event(_rows(app, second), "cancel")[2]


def test_cancel_without_body_stores_null_payload(api, app, owner_user):
    cid = api.create_ok(owner_user)["id"]

    assert api.cancel(cid, owner_user).status_code == 200

    event = _by_event(_rows(app, cid), "cancel")
    assert event[1] is None
    assert event[2]


@pytest.mark.parametrize("body", [{}, {"reason": ""}])
def test_cancel_without_reason_stores_null_payload(api, app, owner_user, body):
    cid = api.create_ok(owner_user)["id"]

    assert api.cancel(cid, owner_user, body).status_code == 200

    assert _by_event(_rows(app, cid), "cancel")[1] is None


def test_cancel_reason_with_unicode_round_trips(api, app, owner_user):
    reason = "caution rendue — véhicule non livré \U0001f697"
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, owner_user, {"reason": reason})

    assert _by_event(_rows(app, cid), "cancel")[1] == {"reason": reason}


def test_create_and_sign_events_have_null_payload(api, app, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.sign(cid, owner_user)
    api.sign(cid, client_user)

    rows = _rows(app, cid)

    assert [r[0] for r in rows] == ["create", "sign_contract", "sign_contract"]
    assert all(r[1] is None for r in rows)
    assert all(r[2] is not None or r[0] == "create" for r in rows)


def test_create_event_keeps_payload_hash_behaviour(api, app, owner_user):
    cid = api.create_ok(owner_user)["id"]

    assert _by_event(_rows(app, cid), "create")[2] is not None


def test_events_endpoint_exposes_payload_for_each_event(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.sign(cid, client_user)
    api.cancel(cid, owner_user, {"reason": "X"})

    events = api.events(cid, client_user).get_json()["events"]

    assert all("payload" in e for e in events)
    assert [(e["event"], e["payload"]) for e in events] == [
        ("create", None),
        ("sign_contract", None),
        ("cancel", {"reason": "X"}),
    ]


def test_events_endpoint_payload_is_null_for_cancel_without_reason(api, owner_user):
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, owner_user)

    events = api.events(cid, owner_user).get_json()["events"]

    assert events[-1]["event"] == "cancel"
    assert events[-1]["payload"] is None


def test_events_endpoint_payload_identical_for_both_parties(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, client_user, {"reason": "X"})

    assert api.events(cid, owner_user).get_json() == api.events(cid, client_user).get_json()


def test_events_endpoint_hides_payload_from_third_party_with_404(api, owner_user, client_user, stranger_user):
    cid = api.create_ok(owner_user)["id"]
    api.cancel(cid, client_user, {"reason": "secret-reason"})

    resp = api.events(cid, stranger_user)

    assert resp.status_code == 404
    assert "secret-reason" not in resp.get_data(as_text=True)
