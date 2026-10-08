"""Prestataire de paiement simule (sans Flask ni DB).

Interfaces supposees : ``app.services.payments.SimulatedProvider()`` (sans argument) avec
``hold(amount, currency, method, key) -> str`` (reference <= 64 caracteres, deterministe pour une cle
d'idempotence donnee) et ``refund(ref) -> None`` ; ``app.domain.errors.PaymentDeclined`` (402,
PAYMENT_DECLINED) et ``PaymentUnavailable`` (503, PAYMENT_UNAVAILABLE), sous-classes de ``DomainError``.

Les imports sont paresseux : le module se charge (et les tests sont rouges) tant que ces interfaces
n'existent pas.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st


def _provider():
    from app.services.payments import SimulatedProvider

    return SimulatedProvider()


def test_payment_declined_carries_code_and_http_status():
    from app.domain.errors import DomainError, PaymentDeclined

    err = PaymentDeclined("refuse")

    assert isinstance(err, DomainError)
    assert (err.code, err.http_status) == ("PAYMENT_DECLINED", 402)


def test_payment_unavailable_carries_code_and_http_status():
    from app.domain.errors import DomainError, PaymentUnavailable

    err = PaymentUnavailable("panne")

    assert isinstance(err, DomainError)
    assert (err.code, err.http_status) == ("PAYMENT_UNAVAILABLE", 503)


def test_hold_with_ok_card_returns_a_bounded_reference():
    ref = _provider().hold(2_500_000, "EUR", "demo_card_ok", "key-1")

    assert isinstance(ref, str)
    assert 0 < len(ref) <= 64


@given(key=st.text(min_size=1, max_size=64))
def test_hold_is_idempotent_on_the_key(key):
    provider = _provider()

    first = provider.hold(100, "EUR", "demo_card_ok", key)
    second = provider.hold(100, "EUR", "demo_card_ok", key)

    assert first == second
    assert len(first) <= 64


def test_hold_with_different_keys_gives_different_references():
    provider = _provider()

    assert provider.hold(100, "EUR", "demo_card_ok", "a") != provider.hold(100, "EUR", "demo_card_ok", "b")


@pytest.mark.parametrize("method", ["demo_card_declined", "demo_insufficient_funds"])
def test_hold_with_refusing_method_raises_payment_declined(method):
    from app.domain.errors import PaymentDeclined

    with pytest.raises(PaymentDeclined):
        _provider().hold(2_500_000, "EUR", method, "key-1")


def test_hold_with_provider_down_raises_payment_unavailable():
    from app.domain.errors import PaymentUnavailable

    with pytest.raises(PaymentUnavailable):
        _provider().hold(2_500_000, "EUR", "demo_provider_down", "key-1")


def test_refund_returns_nothing_and_can_be_repeated():
    provider = _provider()
    ref = provider.hold(100, "EUR", "demo_card_ok", "key-1")

    assert provider.refund(ref) is None
    assert provider.refund(ref) is None
