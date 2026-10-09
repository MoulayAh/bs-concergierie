"""F3 : creation, gel, signature et remplacement des rapports ; condition de ``start_rental``.

Interfaces supposees : voir l'en-tete de tests/fixtures/reports.py. Apres chaque erreur : rien n'a change
(rapport, empreinte, signatures, fichiers sur disque, statut du contrat).
"""

import base64
import hashlib
import json

import pytest

from tests.fixtures.deposits import awaiting_deposit_contract, full_state, funded_contract
from tests.fixtures.files import distinct_jpeg
from tests.fixtures.helpers import assert_error
from tests.fixtures.reports import (
    DEFAULT_FIELDS,
    active_contract,
    create_report,
    delete_file,
    draft_with_photo,
    finalize_report,
    frozen_report,
    get_history,
    get_report,
    post_signature,
    register_key,
    report_message,
    sign_as,
    signed_checkout,
    start_signed,
    supersede_report,
    update_report,
    upload_dir_files,
    upload_ok,
)

pytestmark = pytest.mark.integration

DEPOSIT = 2_500_000


@pytest.fixture
def funded(api, owner_user, client_user, provider) -> str:
    return funded_contract(api, owner_user, client_user)


def _flip_first_byte(signature_b64: str) -> str:
    raw = base64.b64decode(signature_b64)
    return base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode()


def _snapshot(app, api, cid, owner, kind="checkout"):
    resp = get_report(api, cid, owner, kind)
    report = resp.get_json() if resp.status_code == 200 else None
    return {
        "report": report,
        "history": get_history(api, cid, owner, kind).get_json(),
        "contract": full_state(app, api, cid, owner),
        "disk": [p.name for p in upload_dir_files(app)],
    }


# ------------------------------------------------------------------ creation


def test_create_checkout_report_on_funded_contract_returns_draft(api, owner_user, funded):
    resp = create_report(api, funded, owner_user)

    assert resp.status_code == 201, resp.get_data(as_text=True)
    data = resp.get_json()
    assert (data["kind"], data["status"], data["revision"]) == ("checkout", "DRAFT", 1)
    assert data["contract_id"] == funded
    assert data["supersedes_id"] is None
    assert (data["odometer_km"], data["fuel_eighths"]) == (12_450, 8)
    assert data["report_hash"] is None
    assert data["canonical_json"] is None
    assert data["files"] == []
    assert data["signatures"] == []


def test_create_report_by_client_is_forbidden_actor(app, api, owner_user, client_user, funded):
    before = full_state(app, api, funded, owner_user)

    assert_error(create_report(api, funded, client_user), 403, "FORBIDDEN_ACTOR")

    assert full_state(app, api, funded, owner_user) == before
    assert get_report(api, funded, owner_user).status_code == 404


def test_create_report_by_stranger_is_not_found(api, stranger_user, funded):
    assert_error(create_report(api, funded, stranger_user), 404, "NOT_FOUND")


def test_create_report_without_credentials_is_unauthenticated(api, funded):
    assert_error(create_report(api, funded, None), 401, "UNAUTHENTICATED")


def test_create_report_on_unknown_contract_is_not_found(api, owner_user):
    resp = create_report(api, "00000000-0000-4000-8000-000000000000", owner_user)

    assert_error(resp, 404, "NOT_FOUND")


def test_checkout_report_on_awaiting_deposit_contract_is_invalid_transition(api, owner_user, client_user):
    cid = awaiting_deposit_contract(api, owner_user, client_user)

    assert_error(create_report(api, cid, owner_user), 409, "INVALID_TRANSITION")


def test_checkout_report_on_draft_contract_is_invalid_transition(api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]

    assert_error(create_report(api, cid, owner_user), 409, "INVALID_TRANSITION")


def test_return_report_on_funded_contract_is_invalid_transition(app, api, owner_user, funded):
    before = full_state(app, api, funded, owner_user)

    assert_error(create_report(api, funded, owner_user, "return"), 409, "INVALID_TRANSITION")

    assert full_state(app, api, funded, owner_user) == before


def test_checkout_report_after_start_is_invalid_transition(api, keyring, owner_user, client_user, funded):
    assert start_signed(api, keyring, funded, owner_user, client_user).status_code == 200

    # le rapport de depart existe deja (SIGNED) : en creer un autre est refuse
    assert_error(create_report(api, funded, owner_user, "checkout"), 409, "INVALID_TRANSITION")


def test_return_report_on_active_contract_is_created(api, keyring, owner_user, client_user, provider):
    cid = active_contract(api, keyring, owner_user, client_user)

    resp = create_report(api, cid, owner_user, "return", odometer_km=12_500)

    assert resp.status_code == 201, resp.get_data(as_text=True)
    assert resp.get_json()["kind"] == "return"


def test_second_report_of_same_kind_is_invalid_transition(app, api, owner_user, funded):
    assert create_report(api, funded, owner_user).status_code == 201
    before = _snapshot(app, api, funded, owner_user)

    assert_error(create_report(api, funded, owner_user), 409, "INVALID_TRANSITION")

    assert _snapshot(app, api, funded, owner_user) == before


@pytest.mark.parametrize(
    "over",
    [
        {"fuel_eighths": 9},
        {"fuel_eighths": -1},
        {"fuel_eighths": "8"},
        {"fuel_eighths": 7.5},
        {"fuel_eighths": True},
        {"fuel_eighths": None},
        {"odometer_km": -1},
        {"odometer_km": 2_000_001},
        {"odometer_km": "12000"},
        {"odometer_km": 12.5},
        {"odometer_km": True},
        {"odometer_km": 10**30},
        {"notes": "x" * 2001},
        {"notes": 5},
        {"damages": "none"},
        {"damages": [{"zone": "hood", "severity": "minor", "description": "d", "file_ids": []}] * 31},
        {"damages": [{"zone": "trunk", "severity": "minor", "description": "d", "file_ids": []}]},
        {"damages": [{"zone": "hood", "severity": "catastrophic", "description": "d", "file_ids": []}]},
        {"damages": [{"zone": "hood", "severity": "minor", "description": "d" * 501, "file_ids": []}]},
        {"damages": [{"zone": "hood", "severity": "minor", "description": "d", "file_ids": [], "x": 1}]},
        {"damages": [{"zone": "hood", "severity": "minor", "description": "d"}]},
        {"unknown_field": 1},
        {"kind": "overnight"},
    ],
    ids=lambda o: json.dumps(o, default=str)[:60],
)
def test_create_report_with_invalid_field_is_validation_error(app, api, owner_user, funded, over):
    before = full_state(app, api, funded, owner_user)

    assert_error(create_report(api, funded, owner_user, **over), 422, "VALIDATION_ERROR")

    assert full_state(app, api, funded, owner_user) == before
    assert get_report(api, funded, owner_user).status_code == 404


def test_create_report_without_required_fields_is_validation_error(api, owner_user, funded):
    resp = api.request("POST", f"/api/contracts/{funded}/reports", owner_user, body={"kind": "checkout"})

    assert_error(resp, 422, "VALIDATION_ERROR")


@pytest.mark.parametrize("value", [-1, 1, DEPOSIT + 1, 10**30, -(10**30)])
def test_checkout_retention_must_be_zero_or_invalid_amount(api, owner_user, funded, value):
    resp = create_report(api, funded, owner_user, claimed_retention_cents=value)

    assert_error(resp, 422, "INVALID_AMOUNT")
    assert get_report(api, funded, owner_user).status_code == 404


@pytest.mark.parametrize("value", [-1, DEPOSIT + 1, 10**30, -(10**30)])
def test_return_retention_outside_bounds_is_invalid_amount(
    api, keyring, owner_user, client_user, provider, value
):
    cid = active_contract(api, keyring, owner_user, client_user)

    resp = create_report(api, cid, owner_user, "return", claimed_retention_cents=value)

    assert_error(resp, 422, "INVALID_AMOUNT")


@pytest.mark.parametrize("value", ["100", 100.0, True, None, [1], {"a": 1}])
def test_return_retention_of_wrong_type_is_rejected_422(
    api, keyring, owner_user, client_user, provider, value
):
    cid = active_contract(api, keyring, owner_user, client_user)

    resp = create_report(api, cid, owner_user, "return", claimed_retention_cents=value)

    assert_error(resp, 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})


@pytest.mark.parametrize("value", [0, 1, DEPOSIT])
def test_return_retention_within_bounds_is_accepted_and_has_no_effect_on_funds(
    api, keyring, owner_user, client_user, provider, value
):
    cid = active_contract(api, keyring, owner_user, client_user)

    resp = create_report(api, cid, owner_user, "return", claimed_retention_cents=value)

    assert resp.status_code == 201, resp.get_data(as_text=True)
    assert resp.get_json()["claimed_retention_cents"] == value
    funds = api.get(cid, owner_user).get_json()["funds"]
    assert (funds["held_cents"], funds["retained_cents"]) == (DEPOSIT, 0)


def test_return_odometer_below_checkout_is_validation_error(api, keyring, owner_user, client_user, provider):
    cid = active_contract(api, keyring, owner_user, client_user)  # depart : 12 450 km

    assert_error(create_report(api, cid, owner_user, "return", odometer_km=12_449), 422, "VALIDATION_ERROR")

    assert create_report(api, cid, owner_user, "return", odometer_km=12_450).status_code == 201


def test_get_report_with_unknown_kind_is_not_found(api, owner_user, funded):
    assert_error(get_report(api, funded, owner_user, "overnight"), 404, "NOT_FOUND")


def test_get_report_by_both_parties_but_not_by_stranger(api, owner_user, client_user, stranger_user, funded):
    create_report(api, funded, owner_user)

    assert get_report(api, funded, owner_user).status_code == 200
    assert get_report(api, funded, client_user).status_code == 200
    assert_error(get_report(api, funded, stranger_user), 404, "NOT_FOUND")
    assert_error(get_report(api, funded, None), 401, "UNAUTHENTICATED")


# ------------------------------------------------------------------ modification (DRAFT)


def test_owner_updates_draft_fields(api, owner_user, funded):
    create_report(api, funded, owner_user)

    resp = update_report(api, funded, owner_user, odometer_km=12_999, fuel_eighths=3, notes="Griffe")

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert (data["odometer_km"], data["fuel_eighths"], data["notes"]) == (12_999, 3, "Griffe")
    assert data["status"] == "DRAFT"


def test_client_cannot_update_report_fields(app, api, owner_user, client_user, funded):
    create_report(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(update_report(api, funded, client_user, odometer_km=1), 403, "FORBIDDEN_ACTOR")

    assert _snapshot(app, api, funded, owner_user) == before


def test_update_with_invalid_values_is_rejected_without_change(app, api, owner_user, funded):
    create_report(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(update_report(api, funded, owner_user, fuel_eighths=9), 422, "VALIDATION_ERROR")
    assert_error(update_report(api, funded, owner_user, claimed_retention_cents=5), 422, "INVALID_AMOUNT")

    assert _snapshot(app, api, funded, owner_user) == before


def test_update_without_existing_report_is_not_found(api, owner_user, funded):
    assert_error(update_report(api, funded, owner_user), 404, "NOT_FOUND")


def test_damage_pointing_to_file_of_another_report_is_validation_error(
    app, api, owner_user, client_user, provider
):
    other = funded_contract(api, owner_user, client_user, body=None)
    other_file = upload_ok_for_new_report(api, owner_user, other)
    cid = funded_contract(api, owner_user, client_user)
    create_report(api, cid, owner_user)
    damage = {"zone": "hood", "severity": "minor", "description": "d", "file_ids": [other_file["id"]]}
    before = _snapshot(app, api, cid, owner_user)

    assert_error(update_report(api, cid, owner_user, damages=[damage]), 422, "VALIDATION_ERROR")

    assert _snapshot(app, api, cid, owner_user) == before


def upload_ok_for_new_report(api, owner, cid):
    assert create_report(api, cid, owner).status_code == 201
    return upload_ok(api, cid, owner, distinct_jpeg(7))


def test_damage_pointing_to_own_file_is_accepted_and_frozen_in_the_report(api, owner_user, funded):
    create_report(api, funded, owner_user)
    photo = upload_ok(api, funded, owner_user, distinct_jpeg(2))
    damage = {"zone": "front_bumper", "severity": "minor", "description": "Rayure", "file_ids": [photo["id"]]}

    assert update_report(api, funded, owner_user, damages=[damage]).status_code == 200
    frozen = finalize_report(api, funded, owner_user).get_json()

    assert json.loads(frozen["canonical_json"])["damages"] == [damage]


# ------------------------------------------------------------------ gel (finalize)


def test_finalize_freezes_report_with_recomputable_hash(api, owner_user, funded):
    report, photo = draft_with_photo(api, funded, owner_user)

    resp = finalize_report(api, funded, owner_user)

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["status"] == "FROZEN"
    assert data["frozen_at"]
    canonical = data["canonical_json"].encode("utf-8")
    assert data["report_hash"] == hashlib.sha256(canonical).hexdigest()
    assert canonical == json.dumps(
        json.loads(canonical), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    content = json.loads(canonical)
    assert content["schema"] == "luxe-escrow/report/v1"
    assert (content["contract_id"], content["kind"], content["revision"]) == (funded, "checkout", 1)
    assert content["supersedes_id"] is None
    assert content["vehicle_plate"] == "AB-123-CD"
    assert content["deposit"] == {"amount_cents": DEPOSIT, "currency": "EUR"}
    assert content["odometer_km"] == report["odometer_km"]
    assert content["claimed_retention_cents"] == 0
    assert [f["sha256"] for f in content["files"]] == [photo["sha256"]]
    assert content["frozen_at"] == data["frozen_at"]


def test_finalized_files_are_sorted_by_sha256(api, owner_user, funded):
    create_report(api, funded, owner_user)
    for index in range(1, 5):
        upload_ok(api, funded, owner_user, distinct_jpeg(index))

    content = json.loads(finalize_report(api, funded, owner_user).get_json()["canonical_json"])

    hashes = [f["sha256"] for f in content["files"]]
    assert len(hashes) == 4
    assert hashes == sorted(hashes)


def test_finalize_checkout_keeps_contract_funded(api, owner_user, funded):
    draft_with_photo(api, funded, owner_user)
    version = api.get(funded, owner_user).get_json()["status"]

    assert finalize_report(api, funded, owner_user).status_code == 200

    assert api.get(funded, owner_user).get_json()["status"] == version == "FUNDED"


def test_finalize_without_photo_is_validation_error(app, api, owner_user, funded):
    create_report(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(finalize_report(api, funded, owner_user), 422, "VALIDATION_ERROR")

    assert _snapshot(app, api, funded, owner_user) == before


def test_finalize_by_client_is_forbidden_actor(app, api, owner_user, client_user, funded):
    draft_with_photo(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(finalize_report(api, funded, client_user), 403, "FORBIDDEN_ACTOR")

    assert _snapshot(app, api, funded, owner_user) == before


def test_finalize_requires_idempotency_key(app, api, owner_user, funded):
    draft_with_photo(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(finalize_report(api, funded, owner_user, no_key=True), 422, "VALIDATION_ERROR")

    assert _snapshot(app, api, funded, owner_user) == before


def test_finalize_replay_with_same_key_returns_same_response(api, owner_user, funded):
    draft_with_photo(api, funded, owner_user)

    first = finalize_report(api, funded, owner_user, idem="fin-key-1")
    second = finalize_report(api, funded, owner_user, idem="fin-key-1")

    assert first.status_code == second.status_code == 200
    assert first.get_json() == second.get_json()


def test_finalize_twice_with_other_key_is_invalid_transition(app, api, owner_user, funded):
    frozen_report(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(finalize_report(api, funded, owner_user), 409, "INVALID_TRANSITION")

    assert _snapshot(app, api, funded, owner_user) == before


def test_finalize_without_report_is_not_found(api, owner_user, funded):
    assert_error(finalize_report(api, funded, owner_user), 404, "NOT_FOUND")


def test_finalize_return_moves_contract_to_inspection_pending(
    api, keyring, owner_user, client_user, provider
):
    cid = active_contract(api, keyring, owner_user, client_user)
    version = api.get(cid, owner_user).get_json()["version"]
    draft_with_photo(api, cid, owner_user, "return", odometer_km=12_600, claimed_retention_cents=10_000)

    resp = finalize_report(api, cid, owner_user, "return")

    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["status"] == "FROZEN"
    contract = api.get(cid, client_user).get_json()
    assert contract["status"] == "INSPECTION_PENDING"
    assert contract["version"] == version + 1
    last = api.events(cid, owner_user).get_json()["events"][-1]
    assert (last["event"], last["from_status"], last["to_status"]) == (
        "submit_return_report",
        "ACTIVE",
        "INSPECTION_PENDING",
    )
    funds = contract["funds"]
    assert (funds["held_cents"], funds["retained_cents"], funds["released_cents"]) == (DEPOSIT, 0, 0)


def test_finalize_return_without_photo_keeps_contract_active(
    app, api, keyring, owner_user, client_user, provider
):
    cid = active_contract(api, keyring, owner_user, client_user)
    create_report(api, cid, owner_user, "return", odometer_km=12_600)
    before = full_state(app, api, cid, owner_user)

    assert_error(finalize_report(api, cid, owner_user, "return"), 422, "VALIDATION_ERROR")

    assert full_state(app, api, cid, owner_user) == before
    assert api.get(cid, owner_user).get_json()["status"] == "ACTIVE"


def test_finalize_return_by_client_keeps_contract_active(
    app, api, keyring, owner_user, client_user, provider
):
    cid = active_contract(api, keyring, owner_user, client_user)
    draft_with_photo(api, cid, owner_user, "return", odometer_km=12_600)
    before = full_state(app, api, cid, owner_user)

    assert_error(finalize_report(api, cid, client_user, "return"), 403, "FORBIDDEN_ACTOR")

    assert full_state(app, api, cid, owner_user) == before


# ------------------------------------------------------------------ rapport fige : plus de modification


def test_frozen_report_rejects_update_upload_and_delete(app, api, owner_user, client_user, funded):
    report = frozen_report(api, funded, owner_user)
    file_id = report["files"][0]["id"]
    before = _snapshot(app, api, funded, owner_user)

    attempts = [
        update_report(api, funded, owner_user, odometer_km=1),
        upload_file_resp(api, funded, owner_user),
        upload_file_resp(api, funded, client_user),
        api.request("DELETE", f"/api/contracts/{funded}/reports/checkout/files/{file_id}", owner_user),
    ]

    for resp in attempts:
        err = assert_error(resp, 409, "INVALID_TRANSITION")
        assert err["details"]["reason"] == "REPORT_FROZEN"
    assert _snapshot(app, api, funded, owner_user) == before


def upload_file_resp(api, cid, user):
    from tests.fixtures.reports import upload_file

    return upload_file(api, cid, user, distinct_jpeg(9))


def test_signed_report_rejects_update(app, api, keyring, owner_user, client_user, funded):
    signed_checkout(api, keyring, funded, owner_user, client_user)
    before = _snapshot(app, api, funded, owner_user)

    err = assert_error(update_report(api, funded, owner_user, odometer_km=1), 409, "INVALID_TRANSITION")

    assert err["details"]["reason"] == "REPORT_FROZEN"
    assert _snapshot(app, api, funded, owner_user) == before


# ------------------------------------------------------------------ signatures


def test_signature_roundtrip_with_registered_key_through_api(api, keyring, owner_user, client_user, funded):
    report = frozen_report(api, funded, owner_user)

    first = sign_as(api, keyring, funded, client_user, report)
    mid = get_report(api, funded, owner_user).get_json()
    second = sign_as(api, keyring, funded, owner_user, report)

    assert first.status_code == 200, first.get_data(as_text=True)
    assert [s["party"] for s in first.get_json()["signatures"]] == ["client"]
    assert mid["status"] == "FROZEN"
    assert second.status_code == 200
    final = second.get_json()
    assert final["status"] == "SIGNED"
    assert {s["party"] for s in final["signatures"]} == {"owner", "client"}
    assert final["report_hash"] == report["report_hash"]
    assert api.get(funded, owner_user).get_json()["status"] == "FUNDED"


def test_signature_before_freeze_is_invalid_transition(app, api, keyring, owner_user, client_user, funded):
    draft_with_photo(api, funded, owner_user)
    keyring.get(client_user)
    before = _snapshot(app, api, funded, owner_user)

    resp = post_signature(api, funded, client_user, base64.b64encode(b"\x00" * 64).decode())

    assert_error(resp, 409, "INVALID_TRANSITION")
    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_without_report_is_not_found(api, keyring, client_user, owner_user, funded):
    keyring.get(client_user)

    resp = post_signature(api, funded, client_user, base64.b64encode(b"\x00" * 64).decode())

    assert_error(resp, 404, "NOT_FOUND")


def test_same_party_signing_twice_is_invalid_transition(app, api, keyring, owner_user, client_user, funded):
    report = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, client_user, report).status_code == 200
    before = _snapshot(app, api, funded, owner_user)

    assert_error(sign_as(api, keyring, funded, client_user, report), 409, "INVALID_TRANSITION")

    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_without_registered_key_is_key_not_registered(app, api, owner_user, client_user, funded):
    frozen_report(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    resp = post_signature(api, funded, client_user, base64.b64encode(b"\x01" * 64).decode())

    assert_error(resp, 422, "KEY_NOT_REGISTERED")
    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_with_revoked_key_is_key_not_registered(app, api, keyring, owner_user, client_user, funded):
    report = frozen_report(api, funded, owner_user)
    pair = keyring.get(client_user)
    assert api.request("DELETE", f"/api/me/keys/{pair.key_id}", client_user).status_code == 204
    before = _snapshot(app, api, funded, owner_user)

    good = pair.sign_report(funded, "checkout", report["report_hash"])

    resp = post_signature(api, funded, client_user, good)

    assert_error(resp, 422, "KEY_NOT_REGISTERED")
    assert _snapshot(app, api, funded, owner_user) == before


@pytest.mark.parametrize(
    "mutate",
    [
        lambda sig: sig[:-8],
        lambda sig: base64.b64encode(base64.b64decode(sig)[:63]).decode(),
        lambda sig: base64.b64encode(base64.b64decode(sig) + b"\x00").decode(),
        lambda sig: "!!!not-base64!!!",
        lambda sig: "",
        lambda sig: base64.b64encode(b"\x00" * 64).decode(),
        lambda sig: _flip_first_byte(sig),
    ],
    ids=["cut_text", "63_bytes", "65_bytes", "not_base64", "empty", "zeros", "bit_flip"],
)
def test_invalid_signature_is_signature_invalid_and_changes_nothing(
    app, api, keyring, owner_user, client_user, funded, mutate
):
    report = frozen_report(api, funded, owner_user)
    good = keyring.get(client_user).sign_report(funded, "checkout", report["report_hash"])
    before = _snapshot(app, api, funded, owner_user)

    assert_error(post_signature(api, funded, client_user, mutate(good)), 422, "SIGNATURE_INVALID")

    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_made_for_another_contract_is_rejected(
    app, api, keyring, owner_user, client_user, provider
):
    first = funded_contract(api, owner_user, client_user)
    second = funded_contract(api, owner_user, client_user)
    report_1 = frozen_report(api, first, owner_user)
    report_2 = frozen_report(api, second, owner_user)
    stolen = keyring.get(client_user).sign_report(first, "checkout", report_1["report_hash"])
    before = _snapshot(app, api, second, owner_user)

    assert report_1["report_hash"] != report_2["report_hash"]
    assert_error(post_signature(api, second, client_user, stolen), 422, "SIGNATURE_INVALID")
    assert _snapshot(app, api, second, owner_user) == before
    assert post_signature(api, first, client_user, stolen).status_code == 200


def test_signature_made_for_the_return_kind_is_rejected_on_checkout(
    app, api, keyring, owner_user, client_user, funded
):
    report = frozen_report(api, funded, owner_user)
    replay = keyring.get(client_user).sign_report(funded, "return", report["report_hash"])
    before = _snapshot(app, api, funded, owner_user)

    assert_error(post_signature(api, funded, client_user, replay), 422, "SIGNATURE_INVALID")

    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_with_the_other_partys_key_is_rejected(app, api, keyring, owner_user, client_user, funded):
    report = frozen_report(api, funded, owner_user)
    keyring.get(client_user)
    owners_signature = keyring.get(owner_user).sign_report(funded, "checkout", report["report_hash"])
    before = _snapshot(app, api, funded, owner_user)

    assert_error(post_signature(api, funded, client_user, owners_signature), 422, "SIGNATURE_INVALID")

    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_over_a_client_supplied_hash_is_rejected(
    app, api, keyring, owner_user, client_user, funded
):
    report = frozen_report(api, funded, owner_user)
    pair = keyring.get(client_user)
    forged = pair.sign(report_message(funded, "checkout", "f" * 64))
    good = pair.sign_report(funded, "checkout", report["report_hash"])
    before = _snapshot(app, api, funded, owner_user)

    assert_error(post_signature(api, funded, client_user, forged), 422, "SIGNATURE_INVALID")
    resp = api.request(
        "POST",
        f"/api/contracts/{funded}/reports/checkout/signatures",
        client_user,
        body={"signature": good, "report_hash": "f" * 64},
        idem="sig-extra-field",
    )
    assert_error(resp, 422, "VALIDATION_ERROR")
    assert _snapshot(app, api, funded, owner_user) == before


BAD_SIGNATURE_BODIES = [{}, {"signature": 5}, {"signature": None}, {"signature": ["a"]}, {"sig": "x"}]


@pytest.mark.parametrize("body", BAD_SIGNATURE_BODIES)
def test_signature_body_with_wrong_shape_is_validation_error(
    app, api, keyring, owner_user, client_user, funded, body
):
    frozen_report(api, funded, owner_user)
    keyring.get(client_user)
    before = _snapshot(app, api, funded, owner_user)

    resp = api.request(
        "POST", f"/api/contracts/{funded}/reports/checkout/signatures", client_user, body=body, idem="k-shape"
    )

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_requires_idempotency_key(app, api, keyring, owner_user, client_user, funded):
    report = frozen_report(api, funded, owner_user)
    good = keyring.get(client_user).sign_report(funded, "checkout", report["report_hash"])
    before = _snapshot(app, api, funded, owner_user)

    assert_error(post_signature(api, funded, client_user, good, no_key=True), 422, "VALIDATION_ERROR")

    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_by_stranger_is_not_found(app, api, keyring, owner_user, stranger_user, funded):
    report = frozen_report(api, funded, owner_user)
    stolen = keyring.get(stranger_user).sign_report(funded, "checkout", report["report_hash"])
    before = _snapshot(app, api, funded, owner_user)

    assert_error(post_signature(api, funded, stranger_user, stolen), 404, "NOT_FOUND")

    assert _snapshot(app, api, funded, owner_user) == before


def test_signature_without_credentials_is_unauthenticated(api, owner_user, funded):
    frozen_report(api, funded, owner_user)

    assert_error(post_signature(api, funded, None, "AAAA"), 401, "UNAUTHENTICATED")


def test_revoked_key_keeps_past_signatures_valid(api, keyring, owner_user, client_user, funded):
    report = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, client_user, report).status_code == 200
    client_key = keyring.get(client_user)

    assert api.request("DELETE", f"/api/me/keys/{client_key.key_id}", client_user).status_code == 204
    after_revocation = get_report(api, funded, owner_user).get_json()
    assert sign_as(api, keyring, funded, owner_user, report).status_code == 200

    assert [s["party"] for s in after_revocation["signatures"]] == ["client"]
    final = get_report(api, funded, owner_user).get_json()
    assert final["status"] == "SIGNED"
    assert start_ok(api, funded, owner_user)


def start_ok(api, cid, owner) -> bool:
    return api.start(cid, owner).status_code == 200


# ------------------------------------------------------------------ start_rental


def test_start_rental_requires_double_signed_checkout(app, api, keyring, owner_user, client_user, funded):
    """Matrice : aucun rapport, brouillon, fige, une signature -> 409 ; deux signatures -> ACTIVE."""
    stages = []

    def attempt(label):
        before = full_state(app, api, funded, owner_user)
        assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")
        assert full_state(app, api, funded, owner_user) == before, label
        stages.append(label)

    attempt("no_report")
    draft_with_photo(api, funded, owner_user)
    attempt("draft")
    report = finalize_report(api, funded, owner_user).get_json()
    attempt("frozen")
    assert sign_as(api, keyring, funded, client_user, report).status_code == 200
    attempt("one_signature_client")
    assert sign_as(api, keyring, funded, owner_user, report).status_code == 200

    resp = api.start(funded, owner_user)

    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["status"] == "ACTIVE"
    assert stages == ["no_report", "draft", "frozen", "one_signature_client"]


def test_start_rental_with_only_owner_signature_is_invalid_transition(
    app, api, keyring, owner_user, client_user, funded
):
    report = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, owner_user, report).status_code == 200
    before = full_state(app, api, funded, owner_user)

    assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")

    assert full_state(app, api, funded, owner_user) == before


def test_start_rental_after_supersede_requires_new_signatures(
    app, api, keyring, owner_user, client_user, funded
):
    report = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, client_user, report).status_code == 200
    assert supersede_report(api, funded, owner_user).status_code == 201
    finalize_report(api, funded, owner_user)
    before = full_state(app, api, funded, owner_user)

    assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")

    assert full_state(app, api, funded, owner_user) == before


# ------------------------------------------------------------------ remplacement (supersede) et historique


def test_supersede_creates_new_revision_and_voids_signatures(api, keyring, owner_user, client_user, funded):
    old = frozen_report(api, funded, owner_user)
    old_signature = keyring.get(client_user).sign_report(funded, "checkout", old["report_hash"])
    assert post_signature(api, funded, client_user, old_signature).status_code == 200

    resp = supersede_report(api, funded, owner_user)

    assert resp.status_code == 201, resp.get_data(as_text=True)
    new = resp.get_json()
    assert (new["status"], new["revision"], new["supersedes_id"]) == ("DRAFT", 2, old["id"])
    assert new["id"] != old["id"]
    assert new["report_hash"] is None
    assert new["signatures"] == []
    assert (new["odometer_km"], new["fuel_eighths"]) == (old["odometer_km"], old["fuel_eighths"])
    assert [f["sha256"] for f in new["files"]] == [f["sha256"] for f in old["files"]]
    assert get_report(api, funded, owner_user).get_json()["id"] == new["id"]

    # l'ancienne signature ne vaut pas pour la nouvelle revision, meme apres un nouveau gel
    refrozen = finalize_report(api, funded, owner_user).get_json()
    assert refrozen["report_hash"] != old["report_hash"]
    assert json.loads(refrozen["canonical_json"])["revision"] == 2
    assert json.loads(refrozen["canonical_json"])["supersedes_id"] == old["id"]
    assert_error(post_signature(api, funded, client_user, old_signature), 422, "SIGNATURE_INVALID")
    fresh = keyring.get(client_user).sign_report(funded, "checkout", refrozen["report_hash"])
    assert post_signature(api, funded, client_user, fresh).status_code == 200


def test_signature_posted_right_after_supersede_is_invalid_transition(
    app, api, keyring, owner_user, client_user, funded
):
    old = frozen_report(api, funded, owner_user)
    old_signature = keyring.get(client_user).sign_report(funded, "checkout", old["report_hash"])
    assert supersede_report(api, funded, owner_user).status_code == 201
    before = _snapshot(app, api, funded, owner_user)

    assert_error(post_signature(api, funded, client_user, old_signature), 409, "INVALID_TRANSITION")

    assert _snapshot(app, api, funded, owner_user) == before


def test_supersede_of_draft_report_is_invalid_transition(app, api, owner_user, funded):
    draft_with_photo(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(supersede_report(api, funded, owner_user), 409, "INVALID_TRANSITION")

    assert _snapshot(app, api, funded, owner_user) == before


def test_signed_report_cannot_be_superseded(app, api, keyring, owner_user, client_user, funded):
    signed_checkout(api, keyring, funded, owner_user, client_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(supersede_report(api, funded, owner_user), 409, "INVALID_TRANSITION")

    after = _snapshot(app, api, funded, owner_user)
    assert after == before
    assert after["report"]["status"] == "SIGNED"
    assert len(after["history"]["reports"]) == 1


def test_supersede_by_client_is_forbidden_actor(app, api, owner_user, client_user, funded):
    frozen_report(api, funded, owner_user)
    before = _snapshot(app, api, funded, owner_user)

    assert_error(supersede_report(api, funded, client_user), 403, "FORBIDDEN_ACTOR")

    assert _snapshot(app, api, funded, owner_user) == before


def test_supersede_by_stranger_is_not_found(api, owner_user, stranger_user, funded):
    frozen_report(api, funded, owner_user)

    assert_error(supersede_report(api, funded, stranger_user), 404, "NOT_FOUND")


def test_history_lists_all_revisions_with_hashes(
    api, keyring, owner_user, client_user, stranger_user, funded
):
    first = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, client_user, first).status_code == 200
    assert supersede_report(api, funded, owner_user).status_code == 201
    second = finalize_report(api, funded, owner_user).get_json()
    assert supersede_report(api, funded, owner_user).status_code == 201

    resp = get_history(api, funded, client_user)

    assert resp.status_code == 200
    reports = resp.get_json()["reports"]
    assert [r["revision"] for r in reports] == [1, 2, 3]
    assert [r["status"] for r in reports] == ["SUPERSEDED", "SUPERSEDED", "DRAFT"]
    assert reports[0]["report_hash"] == first["report_hash"]
    assert reports[1]["report_hash"] == second["report_hash"]
    assert reports[2]["report_hash"] is None
    # la signature reste attachee a l'ancienne revision
    assert [s["party"] for s in reports[0]["signatures"]] == ["client"]
    assert reports[1]["signatures"] == []
    assert_error(get_history(api, funded, stranger_user), 404, "NOT_FOUND")
    assert_error(get_history(api, funded, None), 401, "UNAUTHENTICATED")


def test_superseded_revision_keeps_its_photo_visible_in_history(api, owner_user, funded):
    old = frozen_report(api, funded, owner_user)
    photo = old["files"][0]
    new = supersede_report(api, funded, owner_user).get_json()

    # la copie porte ses propres identifiants : on retire la photo de la nouvelle revision
    copy_id = new["files"][0]["id"]
    deleted = delete_file(api, funded, owner_user, copy_id)

    assert deleted.status_code == 204
    assert get_report(api, funded, owner_user).get_json()["files"] == []
    history = get_history(api, funded, owner_user).get_json()["reports"]
    assert [f["sha256"] for f in history[0]["files"]] == [photo["sha256"]]
    assert history[0]["status"] == "SUPERSEDED"


def test_supersede_without_report_is_not_found(api, owner_user, funded):
    assert_error(supersede_report(api, funded, owner_user), 404, "NOT_FOUND")


def test_kind_return_signature_route_does_not_exist_yet(api, keyring, owner_user, client_user, provider):
    cid = active_contract(api, keyring, owner_user, client_user)

    resp = api.request("POST", f"/api/contracts/{cid}/reports/return/signatures", client_user, idem="k-ret")

    assert resp.status_code in {404, 405}


def test_register_key_helper_is_idempotent_per_user(api, keyring, owner_user):
    first = keyring.get(owner_user)

    assert keyring.get(owner_user) is first
    assert register_key(api, owner_user, first.public_b64).status_code == 409


def test_default_fields_are_valid_for_a_return_report_equal_to_checkout(
    api, keyring, owner_user, client_user, provider
):
    cid = active_contract(api, keyring, owner_user, client_user)

    resp = create_report(api, cid, owner_user, "return", **DEFAULT_FIELDS)

    assert resp.status_code == 201
