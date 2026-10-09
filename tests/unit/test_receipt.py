"""F4 : quittance (domaine), cle serveur, demarrage de l'app et verification hors ligne.

Interfaces supposees : voir l'en-tete de tests/fixtures/release.py.
"""

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.fixtures.release import (
    RECEIPT_PREFIX,
    SERVER_KEY_B64,
    SERVER_PRIVATE,
    SERVER_PUBLIC_RAW,
    BuiltReceipt,
    build_receipt,
    canonical,
    chain_hash,
    seal_receipt,
)

ROOT = Path(__file__).resolve().parents[2]


def _verify(built: BuiltReceipt, receipt=None, events="built", server_public=None):
    from scripts.verify_receipt import verify_receipt

    return verify_receipt(
        receipt if receipt is not None else built.receipt,
        server_public if server_public is not None else built.server_public,
        built.events if events == "built" else events,
    )


def _invalid():
    from scripts.verify_receipt import ReceiptInvalid

    return ReceiptInvalid


def _reseal(built: BuiltReceipt, mutate) -> dict:
    content = copy.deepcopy(built.content)
    mutate(content)
    return seal_receipt(content)


# ------------------------------------------------------------------ domaine receipt


def test_canonical_receipt_uses_sorted_compact_utf8_json():
    from app.domain.receipt import canonical_receipt

    accent = chr(233)
    content = {"b": 1, "a": {"z": accent, "y": [3, 2]}}

    assert canonical_receipt(content) == canonical(content)
    assert canonical_receipt(content) == ('{"a":{"y":[3,2],"z":"' + accent + '"},"b":1}').encode("utf-8")


def test_receipt_hash_is_sha256_hex_of_canonical_bytes():
    from app.domain.receipt import receipt_hash

    assert receipt_hash(b"abc") == hashlib.sha256(b"abc").hexdigest()


def test_receipt_signing_message_has_the_versioned_prefix():
    from app.domain.receipt import RECEIPT_PREFIX as PREFIX
    from app.domain.receipt import receipt_signing_message

    assert PREFIX == RECEIPT_PREFIX == b"luxe-escrow:receipt:v1:"
    assert receipt_signing_message("ab" * 32) == RECEIPT_PREFIX + b"ab" * 32


def test_receipt_signing_message_differs_from_report_message():
    from app.domain.receipt import receipt_signing_message
    from tests.fixtures.reports import report_message

    digest = "cd" * 32

    assert receipt_signing_message(digest) != report_message("cid", "return", digest)
    assert not receipt_signing_message(digest).startswith(b"luxe-escrow:report:")


# ------------------------------------------------------------------ cle serveur


def test_load_private_key_derives_the_expected_public_key():
    from app.security.server_key import load_private_key, public_key_bytes

    assert public_key_bytes(load_private_key(SERVER_KEY_B64)) == SERVER_PUBLIC_RAW


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "pas du base64 !!!",
        base64.b64encode(b"\x01" * 31).decode(),
        base64.b64encode(b"\x01" * 33).decode(),
        base64.b64encode(b"").decode(),
    ],
)
def test_load_private_key_rejects_malformed_seed(bad):
    from app.security.server_key import ServerKeyError, load_private_key

    with pytest.raises(ServerKeyError):
        load_private_key(bad)


# ------------------------------------------------------------------ demarrage de l'application


def _config(**over):
    base = {"TESTING": True, "SECRET_KEY": "test-secret-key-not-for-production-0123456789"}
    return {**base, **over}


def test_app_refuses_to_start_without_server_key(monkeypatch):
    from app import create_app

    monkeypatch.delenv("SERVER_SIGNING_KEY", raising=False)

    with pytest.raises(RuntimeError, match="SERVER_SIGNING_KEY"):
        create_app(_config())


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        None,
        "pas du base64 !!!",
        base64.b64encode(b"\x01" * 31).decode(),
        base64.b64encode(b"\x01" * 64).decode(),
    ],
)
def test_app_refuses_to_start_with_empty_or_malformed_server_key(monkeypatch, bad):
    from app import create_app

    monkeypatch.delenv("SERVER_SIGNING_KEY", raising=False)

    with pytest.raises(RuntimeError, match="SERVER_SIGNING_KEY"):
        create_app(_config(SERVER_SIGNING_KEY=bad))


def test_app_starts_with_server_key_from_config(monkeypatch):
    from app import create_app

    monkeypatch.delenv("SERVER_SIGNING_KEY", raising=False)

    assert create_app(_config(SERVER_SIGNING_KEY=SERVER_KEY_B64)) is not None


def test_app_starts_with_server_key_from_environment(monkeypatch):
    from app import create_app

    monkeypatch.setenv("SERVER_SIGNING_KEY", SERVER_KEY_B64)

    assert create_app(_config()) is not None


def test_server_key_never_appears_in_the_startup_error(monkeypatch):
    from app import create_app

    monkeypatch.delenv("SERVER_SIGNING_KEY", raising=False)
    leaked = base64.b64encode(b"\x07" * 31).decode()

    with pytest.raises(RuntimeError) as caught:
        create_app(_config(SERVER_SIGNING_KEY=leaked))

    assert leaked not in str(caught.value)


# ------------------------------------------------------------------ verify_receipt : cas valides


def test_receipt_verifies_offline():
    built = build_receipt()

    assert _verify(built) is None


def test_receipt_verifies_offline_without_events():
    built = build_receipt()

    assert _verify(built, events=None) is None


def test_receipt_without_retention_verifies_as_released():
    built = build_receipt(retained_cents=0)

    assert built.content["outcome"] == "RELEASED"
    assert _verify(built) is None


@settings(max_examples=25, deadline=None)
@given(deposit=st.integers(min_value=1, max_value=50_000_000), data=st.data())
def test_receipt_verifies_for_any_valid_split(deposit, data):
    retained = data.draw(st.integers(min_value=0, max_value=deposit))
    built = build_receipt(deposit_cents=deposit, retained_cents=retained)

    assert _verify(built) is None


# ------------------------------------------------------------------ verify_receipt : falsifications


def test_receipt_tampering_detected():
    built = build_receipt()
    forged = dict(built.receipt)
    forged["canonical_json"] = built.receipt["canonical_json"].replace(
        '"retained_by_owner_cents":120000', '"retained_by_owner_cents":119999'
    )
    assert forged["canonical_json"] != built.receipt["canonical_json"]

    with pytest.raises(_invalid()):
        _verify(built, receipt=forged)


def test_receipt_tampering_with_recomputed_hash_breaks_server_signature():
    built = build_receipt()
    forged = dict(built.receipt)
    forged["canonical_json"] = built.receipt["canonical_json"].replace("120000", "119999")
    forged["receipt_hash"] = hashlib.sha256(forged["canonical_json"].encode()).hexdigest()

    with pytest.raises(_invalid()):
        _verify(built, receipt=forged)


@settings(max_examples=40, deadline=None)
@given(position=st.integers(min_value=0, max_value=10_000), replacement=st.sampled_from("0123456789abcdef"))
def test_any_character_change_in_the_canonical_json_is_detected(position, replacement):
    built = build_receipt()
    text = built.receipt["canonical_json"]
    index = position % len(text)
    if text[index] == replacement:
        return
    forged = {**built.receipt, "canonical_json": text[:index] + replacement + text[index + 1 :]}

    with pytest.raises(_invalid()):
        _verify(built, receipt=forged)


def test_receipt_signed_by_another_server_key_is_rejected():
    built = build_receipt()
    forged = seal_receipt(built.content, Ed25519PrivateKey.generate())

    with pytest.raises(_invalid()):
        _verify(built, receipt=forged)


def test_receipt_checked_against_another_server_public_key_is_rejected():
    built = build_receipt()
    other = Ed25519PrivateKey.generate().public_key()
    from cryptography.hazmat.primitives import serialization

    raw = other.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    with pytest.raises(_invalid()):
        _verify(built, server_public=raw)


def test_receipt_signature_cannot_be_replayed_on_another_prefix():
    built = build_receipt()
    forged = dict(built.receipt)
    forged["server_signature"] = base64.b64encode(
        SERVER_PRIVATE.sign(b"luxe-escrow:report:v1:" + built.receipt["receipt_hash"].encode())
    ).decode()

    with pytest.raises(_invalid()):
        _verify(built, receipt=forged)


def test_receipt_with_unbalanced_amounts_is_rejected_even_when_server_signed():
    built = build_receipt()
    forged = _reseal(built, lambda c: c.update(released_to_client_cents=c["released_to_client_cents"] + 1))

    with pytest.raises(_invalid()):
        _verify(built, receipt=forged)


def test_receipt_with_negative_amount_is_rejected_even_when_balanced_and_signed():
    built = build_receipt()

    def mutate(c):
        c["released_to_client_cents"] = c["deposit_cents"] + 100
        c["retained_by_owner_cents"] = -100

    with pytest.raises(_invalid()):
        _verify(built, receipt=_reseal(built, mutate))


def test_receipt_with_swapped_party_signatures_is_rejected():
    built = build_receipt()

    def mutate(c):
        a, b = c["signatures"]
        a["signature"], b["signature"] = b["signature"], a["signature"]

    with pytest.raises(_invalid()):
        _verify(built, receipt=_reseal(built, mutate))


def test_receipt_with_party_signature_on_another_report_hash_is_rejected():
    built = build_receipt()
    other = hashlib.sha256(b"autre rapport").hexdigest()

    with pytest.raises(_invalid()):
        _verify(built, receipt=_reseal(built, lambda c: c["return_report"].update(hash=other)))


def test_receipt_with_party_signature_on_checkout_kind_is_rejected():
    built = build_receipt()
    from tests.fixtures.reports import report_message

    def mutate(c):
        for sig, pair in zip(c["signatures"], (built.owner_key, built.client_key), strict=True):
            message = report_message(c["contract_id"], "checkout", c["return_report"]["hash"])
            sig["signature"] = pair.sign(message)

    with pytest.raises(_invalid()):
        _verify(built, receipt=_reseal(built, mutate))


def test_receipt_with_public_key_not_matching_fingerprint_is_rejected():
    built = build_receipt()
    from tests.fixtures.reports import KeyPair

    stranger = KeyPair()

    def mutate(c):
        c["signatures"][0]["public_key"] = stranger.public_b64

    with pytest.raises(_invalid()):
        _verify(built, receipt=_reseal(built, mutate))


def test_receipt_with_a_single_signature_is_rejected():
    built = build_receipt()

    with pytest.raises(_invalid()):
        _verify(built, receipt=_reseal(built, lambda c: c["signatures"].pop()))


def test_receipt_with_same_party_twice_is_rejected():
    built = build_receipt()

    def mutate(c):
        c["signatures"][1] = copy.deepcopy(c["signatures"][0])

    with pytest.raises(_invalid()):
        _verify(built, receipt=_reseal(built, mutate))


@pytest.mark.parametrize("bad", [None, [], "texte", 12, {}, {"canonical_json": "{}"}])
def test_malformed_receipt_object_raises_receipt_invalid_not_a_crash(bad):
    built = build_receipt()

    with pytest.raises(_invalid()):
        _verify(built, receipt=bad if bad is not None else {"canonical_json": None})


@pytest.mark.parametrize("canonical_json", ["", "pas du json", "[]", "null", '{"schema":1}'])
def test_receipt_with_non_object_or_incomplete_content_is_rejected(canonical_json):
    built = build_receipt()
    forged = {
        "canonical_json": canonical_json,
        "receipt_hash": hashlib.sha256(canonical_json.encode()).hexdigest(),
        "server_signature": base64.b64encode(
            SERVER_PRIVATE.sign(RECEIPT_PREFIX + hashlib.sha256(canonical_json.encode()).hexdigest().encode())
        ).decode(),
    }

    with pytest.raises(_invalid()):
        _verify(built, receipt=forged)


@pytest.mark.parametrize("server_public", [b"", b"\x00" * 31, b"\x00" * 33])
def test_server_public_key_of_wrong_length_is_rejected(server_public):
    built = build_receipt()

    with pytest.raises(_invalid()):
        _verify(built, server_public=server_public)


# ------------------------------------------------------------------ verify_receipt : chaine d'evenements


def test_verify_receipt_detects_removed_or_altered_event():
    built = build_receipt()

    removed_middle = copy.deepcopy(built.events)
    del removed_middle[2]
    removed_last = built.events[:-1]
    removed_first = built.events[1:]
    altered = copy.deepcopy(built.events)
    altered[1]["actor_id"] = "00000000-0000-4000-8000-000000000000"
    reordered = copy.deepcopy(built.events)
    reordered[2], reordered[3] = reordered[3], reordered[2]
    extra = [*copy.deepcopy(built.events), copy.deepcopy(built.events[-1])]

    for forged in (removed_middle, removed_last, removed_first, altered, reordered, extra):
        with pytest.raises(_invalid()):
            _verify(built, events=forged)


def test_verify_receipt_detects_altered_event_even_if_its_own_hash_is_recomputed():
    built = build_receipt()
    forged = copy.deepcopy(built.events)
    forged[2]["to_status"] = "CANCELLED"
    forged[2]["event_hash"] = chain_hash(forged[2]["prev_hash"], forged[2])

    with pytest.raises(_invalid()):
        _verify(built, events=forged)


def test_verify_receipt_detects_head_mismatch_with_a_valid_longer_chain():
    built = build_receipt()
    from tests.fixtures.release import LIFECYCLE_SPECS, build_chain

    other = build_chain(built.content["contract_id"], [*LIFECYCLE_SPECS, ("noop", "SETTLED", "SETTLED")])

    with pytest.raises(_invalid()):
        _verify(built, events=other)


def test_verify_receipt_detects_events_of_another_contract():
    built = build_receipt()
    other = build_receipt()

    with pytest.raises(_invalid()):
        _verify(built, events=other.events)


def test_verify_receipt_accepts_exports_with_extra_unhashed_keys():
    built = build_receipt()
    exported = [{**e, "note": "libre", "id": "ignored"} for e in built.events]

    assert _verify(built, events=exported) is None


def _with_payloads(payload: dict) -> tuple[BuiltReceipt, list[dict]]:
    """Meme cycle de vie, payload_hash = empreinte du payload exporte ; chaine et quittance rescellees."""
    from app.domain.event_chain import payload_fingerprint

    built = build_receipt()
    events: list[dict] = []
    prev = "0" * 64
    return_hash = built.content["return_report"]["hash"]
    for source in built.events:
        fields = {**{k: source[k] for k in source if k not in ("prev_hash", "event_hash")}}
        # La liberation (dernier evenement) doit porter l'empreinte du rapport de retour.
        body = {**payload, "report_hash": return_hash} if source is built.events[-1] else payload
        fields["payload_hash"] = payload_fingerprint(body)
        digest = chain_hash(prev, fields)
        events.append({**fields, "payload": body, "prev_hash": prev, "event_hash": digest})
        prev = digest
    content = {**built.content, "event_chain": {"length": len(events), "head": prev}}
    rebuilt = BuiltReceipt(
        content, seal_receipt(content), events, built.server_public, built.owner_key, built.client_key
    )
    return rebuilt, events


def test_verify_receipt_accepts_payload_consistent_with_payload_hash():
    rebuilt, events = _with_payloads({"x": 1})

    assert _verify(rebuilt, events=events) is None


def test_verify_receipt_rejects_payload_inconsistent_with_payload_hash():
    rebuilt, events = _with_payloads({"x": 1})
    tampered = [{**e, "payload": {"x": 2}} if e["seq"] == 3 else e for e in events]

    with pytest.raises(_invalid()):
        _verify(rebuilt, events=tampered)


# ------------------------------------------------------------------ CLI


def _run_cli(tmp_path: Path, receipt: dict, events=None, key: bytes = SERVER_PUBLIC_RAW):
    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
    command = [sys.executable, str(ROOT / "scripts" / "verify_receipt.py"), str(receipt_file)]
    if events is not None:
        events_file = tmp_path / "events.json"
        events_file.write_text(json.dumps({"events": events}), encoding="utf-8")
        command += ["--events", str(events_file)]
    command += ["--server-key", base64.b64encode(key).decode()]
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    return subprocess.run(  # noqa: S603
        command, capture_output=True, text=True, cwd=ROOT, env=env, timeout=60, check=False
    )


def test_cli_exits_zero_on_valid_receipt_with_events(tmp_path):
    built = build_receipt()

    result = _run_cli(tmp_path, built.receipt, built.events)

    assert result.returncode == 0, result.stderr


def test_cli_exits_non_zero_when_one_cent_is_changed(tmp_path):
    built = build_receipt()
    forged = {**built.receipt, "canonical_json": built.receipt["canonical_json"].replace("120000", "120001")}

    result = _run_cli(tmp_path, forged, built.events)

    assert result.returncode != 0
    assert "Traceback" not in result.stderr


def test_cli_exits_non_zero_when_an_event_is_removed(tmp_path):
    built = build_receipt()

    result = _run_cli(tmp_path, built.receipt, built.events[:3] + built.events[4:])

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
