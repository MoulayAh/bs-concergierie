"""F3 domaine pur : canonisation, empreinte, message signe, cycle de vie des rapports.

Interfaces supposees : voir l'en-tete de ``tests/fixtures/reports.py`` (``app.domain.report``).
"""

import copy
import hashlib
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.domain.errors import InvalidTransition
from app.domain.report import (
    ReportAction,
    ReportKind,
    ReportStatus,
    canonical_bytes,
    compute_report_hash,
    next_status,
    signing_message,
)

CONTRACT = "11111111-1111-4111-8111-111111111111"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def base_content() -> dict[str, Any]:
    return {
        "schema": "luxe-escrow/report/v1",
        "contract_id": CONTRACT,
        "kind": "checkout",
        "revision": 1,
        "supersedes_id": None,
        "vehicle_plate": "AB-123-CD",
        "deposit": {"amount_cents": 2_500_000, "currency": "EUR"},
        "odometer_km": 12_450,
        "fuel_eighths": 8,
        "damages": [{"zone": "hood", "severity": "minor", "description": "Rayure", "file_ids": ["f1"]}],
        "claimed_retention_cents": 0,
        "files": [
            {"id": "f1", "sha256": SHA_B, "mime": "image/jpeg", "size_bytes": 10},
            {"id": "f2", "sha256": SHA_A, "mime": "image/png", "size_bytes": 20},
        ],
        "notes": "RAS",
        "frozen_at": "2026-11-01T09:12:44Z",
    }


def expected_canonical(content: dict[str, Any]) -> bytes:
    obj = copy.deepcopy(content)
    obj["files"] = sorted(obj["files"], key=lambda f: f["sha256"])
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------ canonisation / empreinte


def test_canonical_bytes_match_the_documented_form_with_files_sorted_by_sha256():
    content = base_content()

    assert canonical_bytes(content) == expected_canonical(content)


def test_canonical_bytes_keep_non_ascii_characters_unescaped():
    content = base_content() | {"notes": "Pare-chocs abime éè €"}

    data = canonical_bytes(content)

    assert "éè €".encode() in data
    assert b"\\u" not in data


def test_canonical_bytes_do_not_mutate_the_input():
    content = base_content()
    before = copy.deepcopy(content)

    canonical_bytes(content)

    assert content == before


def test_report_hash_is_sha256_hex_of_canonical_bytes():
    content = base_content()

    digest = compute_report_hash(content)

    assert digest == hashlib.sha256(expected_canonical(content)).hexdigest()
    assert len(digest) == 64
    assert digest == digest.lower()


file_strategy = st.fixed_dictionaries(
    {
        "id": st.uuids().map(str),
        "sha256": st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
        "mime": st.sampled_from(["image/jpeg", "image/png", "application/pdf"]),
        "size_bytes": st.integers(min_value=1, max_value=10_485_760),
    }
)
damage_strategy = st.fixed_dictionaries(
    {
        "zone": st.sampled_from(["hood", "roof", "wheels", "other"]),
        "severity": st.sampled_from(["minor", "moderate", "major"]),
        "description": st.text(max_size=50),
        "file_ids": st.lists(st.uuids().map(str), max_size=3),
    }
)
content_strategy = st.builds(
    lambda odo, fuel, files, damages, notes, retention: (
        base_content()
        | {
            "odometer_km": odo,
            "fuel_eighths": fuel,
            "files": files,
            "damages": damages,
            "notes": notes,
            "claimed_retention_cents": retention,
        }
    ),
    st.integers(0, 2_000_000),
    st.integers(0, 8),
    st.lists(file_strategy, min_size=1, max_size=6, unique_by=lambda f: f["sha256"]),
    st.lists(damage_strategy, max_size=5),
    st.text(max_size=80),
    st.integers(0, 2_500_000),
)


@given(content=content_strategy, data=st.data())
def test_canonical_json_is_deterministic(content, data):
    """L'ordre des cles et des fichiers n'influe pas sur l'empreinte."""
    keys = data.draw(st.permutations(list(content.keys())))
    files = data.draw(st.permutations(content["files"]))
    shuffled = {k: content[k] for k in keys}
    shuffled["files"] = [dict(reversed(list(f.items()))) for f in files]

    assert canonical_bytes(shuffled) == canonical_bytes(content)
    assert compute_report_hash(shuffled) == compute_report_hash(content)


def _with(path: str, value: Any) -> dict[str, Any]:
    content = base_content()
    if path == "deposit.amount_cents":
        content["deposit"]["amount_cents"] = value
    elif path == "files.0.sha256":
        content["files"][0]["sha256"] = value
    elif path == "damages.0.description":
        content["damages"][0]["description"] = value
    else:
        content[path] = value
    return content


MUTATIONS = [
    ("contract_id", "22222222-2222-4222-8222-222222222222"),
    ("kind", "return"),
    ("revision", 2),
    ("supersedes_id", "33333333-3333-4333-8333-333333333333"),
    ("vehicle_plate", "ZZ-999-ZZ"),
    ("deposit.amount_cents", 2_500_001),
    ("odometer_km", 12_451),
    ("fuel_eighths", 7),
    ("damages", []),
    ("damages.0.description", "Rayure 4 cm"),
    ("claimed_retention_cents", 1),
    ("files.0.sha256", SHA_C),
    ("notes", "RAS."),
    ("frozen_at", "2026-11-01T09:12:45Z"),
    ("files", [base_content()["files"][0]]),
]


@pytest.mark.parametrize(("path", "value"), MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_any_content_change_changes_hash(path, value):
    assert compute_report_hash(_with(path, value)) != compute_report_hash(base_content())


@given(a=st.integers(0, 2_000_000), b=st.integers(0, 2_000_000))
def test_distinct_odometer_values_give_distinct_hashes(a, b):
    first = base_content() | {"odometer_km": a}
    second = base_content() | {"odometer_km": b}

    assert (compute_report_hash(first) == compute_report_hash(second)) == (a == b)


def test_signing_message_is_domain_separated_and_exact():
    message = signing_message(CONTRACT, ReportKind.CHECKOUT, SHA_A)

    assert message == b"luxe-escrow:report:v1:" + CONTRACT.encode() + b":checkout:" + SHA_A.encode()
    assert signing_message(CONTRACT, ReportKind.RETURN, SHA_A) != message
    assert signing_message("22222222-2222-4222-8222-222222222222", ReportKind.CHECKOUT, SHA_A) != message
    assert signing_message(CONTRACT, ReportKind.CHECKOUT, SHA_B) != message


# ------------------------------------------------------------------ cycle de vie

EDITS = (ReportAction.EDIT, ReportAction.ADD_FILE, ReportAction.REMOVE_FILE)


@pytest.mark.parametrize("action", EDITS)
def test_draft_report_accepts_edits_and_stays_draft(action):
    assert next_status(ReportStatus.DRAFT, action) == ReportStatus.DRAFT


def test_finalize_moves_draft_to_frozen():
    assert next_status(ReportStatus.DRAFT, ReportAction.FINALIZE) == ReportStatus.FROZEN


@pytest.mark.parametrize("status", [ReportStatus.FROZEN, ReportStatus.SIGNED])
@pytest.mark.parametrize("action", EDITS)
def test_edit_of_non_draft_report_is_rejected_with_report_frozen_reason(status, action):
    with pytest.raises(InvalidTransition) as caught:
        next_status(status, action)

    assert caught.value.http_status == 409
    assert caught.value.code == "INVALID_TRANSITION"
    assert caught.value.details is not None
    assert caught.value.details["reason"] == "REPORT_FROZEN"


@pytest.mark.parametrize("action", EDITS)
def test_edit_of_superseded_report_is_rejected(action):
    with pytest.raises(InvalidTransition):
        next_status(ReportStatus.SUPERSEDED, action)


def test_first_signature_keeps_report_frozen():
    assert next_status(ReportStatus.FROZEN, ReportAction.SIGN, signatures=1) == ReportStatus.FROZEN


def test_second_signature_moves_report_to_signed():
    assert next_status(ReportStatus.FROZEN, ReportAction.SIGN, signatures=2) == ReportStatus.SIGNED


@pytest.mark.parametrize("signatures", [0, 3, -1])
def test_sign_with_impossible_signature_count_is_rejected(signatures):
    with pytest.raises(InvalidTransition):
        next_status(ReportStatus.FROZEN, ReportAction.SIGN, signatures=signatures)


@pytest.mark.parametrize("signatures", [0, 1])
def test_supersede_of_frozen_report_without_both_signatures_is_allowed(signatures):
    assert (
        next_status(ReportStatus.FROZEN, ReportAction.SUPERSEDE, signatures=signatures)
        == ReportStatus.SUPERSEDED
    )


def test_supersede_of_frozen_report_with_both_signatures_is_rejected():
    with pytest.raises(InvalidTransition):
        next_status(ReportStatus.FROZEN, ReportAction.SUPERSEDE, signatures=2)


def test_report_lifecycle_draft_frozen_signed():
    status = ReportStatus.DRAFT
    status = next_status(status, ReportAction.EDIT)
    status = next_status(status, ReportAction.FINALIZE)
    assert status == ReportStatus.FROZEN
    status = next_status(status, ReportAction.SIGN, signatures=1)
    status = next_status(status, ReportAction.SIGN, signatures=2)
    assert status == ReportStatus.SIGNED


VALID = {
    (ReportStatus.DRAFT, ReportAction.EDIT),
    (ReportStatus.DRAFT, ReportAction.ADD_FILE),
    (ReportStatus.DRAFT, ReportAction.REMOVE_FILE),
    (ReportStatus.DRAFT, ReportAction.FINALIZE),
    (ReportStatus.FROZEN, ReportAction.SIGN),
    (ReportStatus.FROZEN, ReportAction.SUPERSEDE),
}


INVALID = [(s, a) for s in ReportStatus for a in ReportAction if (s, a) not in VALID]


@pytest.mark.parametrize(("status", "action"), INVALID)
def test_every_combination_outside_the_table_is_invalid_transition(status, action):
    with pytest.raises(InvalidTransition):
        next_status(status, action, signatures=1)


@pytest.mark.parametrize("action", list(ReportAction))
def test_signed_and_superseded_reports_accept_no_action(action):
    for status in (ReportStatus.SIGNED, ReportStatus.SUPERSEDED):
        with pytest.raises(InvalidTransition):
            next_status(status, action, signatures=2)
