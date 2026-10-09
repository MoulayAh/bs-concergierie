"""F3 : verification Ed25519 (``app.security.signatures``).

Interfaces supposees : voir l'en-tete de tests/fixtures/reports.py.
"""

import base64
import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.domain.errors import SignatureInvalid, ValidationFailed
from app.security.signatures import decode_public_key, key_fingerprint, verify_signature
from tests.fixtures.reports import KeyPair, report_message

HASH = "d" * 64
CONTRACT = "11111111-1111-4111-8111-111111111111"


def test_signature_roundtrip_with_registered_key():
    pair = KeyPair()
    message = report_message(CONTRACT, "checkout", HASH)

    verify_signature(pair.public_raw, message, pair.sign(message))


@given(message=st.binary(max_size=300))
def test_signature_roundtrip_for_any_message(message):
    pair = KeyPair()

    verify_signature(pair.public_raw, message, pair.sign(message))


def test_signature_bound_to_contract_and_kind():
    pair = KeyPair()
    signature = pair.sign(report_message(CONTRACT, "checkout", HASH))
    other_contract = report_message("22222222-2222-4222-8222-222222222222", "checkout", HASH)
    other_kind = report_message(CONTRACT, "return", HASH)
    other_hash = report_message(CONTRACT, "checkout", "e" * 64)

    for forged in (other_contract, other_kind, other_hash):
        with pytest.raises(SignatureInvalid):
            verify_signature(pair.public_raw, forged, signature)


def test_signature_by_another_key_is_rejected():
    message = report_message(CONTRACT, "checkout", HASH)

    with pytest.raises(SignatureInvalid):
        verify_signature(KeyPair().public_raw, message, KeyPair().sign(message))


def test_bit_flipped_signature_is_rejected():
    pair = KeyPair()
    message = report_message(CONTRACT, "checkout", HASH)
    raw = bytearray(base64.b64decode(pair.sign(message)))
    raw[10] ^= 0x01

    with pytest.raises(SignatureInvalid):
        verify_signature(pair.public_raw, message, base64.b64encode(bytes(raw)).decode())


@pytest.mark.parametrize("length", [0, 1, 63, 65, 128])
def test_signature_of_wrong_length_is_rejected(length):
    pair = KeyPair()

    with pytest.raises(SignatureInvalid):
        verify_signature(pair.public_raw, b"msg", base64.b64encode(b"\x01" * length).decode())


@pytest.mark.parametrize("garbage", ["", "!!!", "not base64 at all", "éé", "AAAA====", "=" * 5])
def test_malformed_base64_signature_is_signature_invalid(garbage):
    with pytest.raises(SignatureInvalid):
        verify_signature(KeyPair().public_raw, b"msg", garbage)


@given(garbage=st.binary(min_size=64, max_size=64))
def test_random_64_byte_signature_never_verifies(garbage):
    with pytest.raises(SignatureInvalid):
        verify_signature(KeyPair().public_raw, b"msg", base64.b64encode(garbage).decode())


@given(text=st.text(max_size=200))
def test_arbitrary_text_signature_only_ever_raises_signature_invalid(text):
    with pytest.raises(SignatureInvalid):
        verify_signature(KeyPair().public_raw, b"msg", text)


def test_decode_public_key_accepts_32_raw_bytes():
    pair = KeyPair()

    assert decode_public_key(pair.public_b64) == pair.public_raw


@pytest.mark.parametrize("length", [0, 1, 31, 33, 64])
def test_decode_public_key_rejects_wrong_length(length):
    with pytest.raises(ValidationFailed) as caught:
        decode_public_key(base64.b64encode(b"\x07" * length).decode())

    assert caught.value.http_status == 422


@pytest.mark.parametrize("garbage", ["", "!!!", "%%%%", "é"])
def test_decode_public_key_rejects_malformed_base64(garbage):
    with pytest.raises(ValidationFailed):
        decode_public_key(garbage)


def test_key_fingerprint_is_sha256_hex_of_raw_key():
    pair = KeyPair()

    assert key_fingerprint(pair.public_raw) == hashlib.sha256(pair.public_raw).hexdigest()
