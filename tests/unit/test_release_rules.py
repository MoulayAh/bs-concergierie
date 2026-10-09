"""F4 : matrice terminale, cible RELEASED/SETTLED, `settle` du prestataire simule (domaine pur, sans DB).

Interfaces supposees : ``SimulatedProvider.settle(ref, *, release_cents, capture_cents, key) -> str``
(reference <= 64 caracteres) ; refus (sous-classe de ``DomainError``) si somme != montant bloque, montant
negatif, ou meme cle avec des montants differents ; ``hold`` doit avoir eu lieu avant pour obtenir ``ref``.
"""

import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.domain.errors import DomainError, ForbiddenActor, InvalidAmount, InvalidTransition
from app.domain.money import MAX_DEPOSIT_CENTS, split_deposit
from app.domain.state_machine import ContractStatus, Event, Party, transition

S = ContractStatus
TERMINAL_RELEASE = [S.RELEASED, S.SETTLED]
OWNER, CLIENT = Party.OWNER, Party.CLIENT

deposits = st.integers(min_value=1, max_value=MAX_DEPOSIT_CENTS)


def _sign(actor, **kwargs):
    return transition(S.INSPECTION_PENDING, Event.SIGN_REPORT, actor=actor, **kwargs)


# ------------------------------------------------------------------ matrice terminale


@pytest.mark.parametrize(
    ("status", "event", "actor"),
    list(itertools.product(TERMINAL_RELEASE, Event, Party)),
    ids=lambda v: v.name,
)
def test_terminal_contract_rejects_every_event(status, event, actor):
    with pytest.raises(InvalidTransition) as caught:
        transition(status, event, actor=actor, deposit_cents=1_000, retained_cents=0)

    assert (caught.value.code, caught.value.http_status) == ("INVALID_TRANSITION", 409)
    assert not isinstance(caught.value, ForbiddenActor)


@pytest.mark.parametrize("status", TERMINAL_RELEASE)
@pytest.mark.parametrize("already", [frozenset(), frozenset({OWNER}), frozenset({OWNER, CLIENT})])
def test_terminal_contract_rejects_sign_report_whatever_the_signature_history(status, already):
    with pytest.raises(InvalidTransition):
        transition(status, Event.SIGN_REPORT, actor=CLIENT, signed_by=already, deposit_cents=10)


# ------------------------------------------------------------------ cible de la seconde signature


def test_first_return_signature_keeps_inspection_pending():
    first = _sign(CLIENT, deposit_cents=100, retained_cents=40)

    assert first.status is S.INSPECTION_PENDING
    assert first.signed_by == frozenset({CLIENT})


@given(deposit=deposits, first=st.sampled_from([OWNER, CLIENT]))
def test_second_signature_without_retention_releases(deposit, first):
    second = CLIENT if first is OWNER else OWNER
    step = _sign(first, deposit_cents=deposit)

    done = _sign(second, signed_by=step.signed_by, deposit_cents=deposit)

    assert done.status is S.RELEASED


@given(data=st.data(), deposit=deposits, first=st.sampled_from([OWNER, CLIENT]))
def test_second_signature_with_retention_settles(data, deposit, first):
    retained = data.draw(st.integers(min_value=1, max_value=deposit))
    second = CLIENT if first is OWNER else OWNER
    step = _sign(first, deposit_cents=deposit, retained_cents=retained)

    done = _sign(second, signed_by=step.signed_by, deposit_cents=deposit, retained_cents=retained)

    assert done.status is S.SETTLED


@given(deposit=deposits, excess=st.integers(min_value=1, max_value=10**12))
def test_retention_above_deposit_is_invalid_amount(deposit, excess):
    with pytest.raises(InvalidAmount):
        _sign(OWNER, deposit_cents=deposit, retained_cents=deposit + excess)


@given(deposit=deposits, negative=st.integers(max_value=-1))
def test_negative_retention_is_invalid_amount(deposit, negative):
    with pytest.raises(InvalidAmount):
        _sign(CLIENT, deposit_cents=deposit, retained_cents=negative)


@pytest.mark.parametrize("value", [1.5, "100", True, None, 10.0])
def test_non_integer_retention_is_invalid_amount(value):
    with pytest.raises(InvalidAmount):
        _sign(OWNER, deposit_cents=1_000, retained_cents=value)


def test_admin_cannot_sign_the_return_report():
    with pytest.raises(ForbiddenActor):
        _sign(Party.ADMIN, deposit_cents=1_000)


@given(data=st.data(), deposit=deposits)
def test_split_deposit_always_balances(data, deposit):
    retained = data.draw(st.integers(min_value=0, max_value=deposit))

    released, kept = split_deposit(deposit, retained)

    assert released + kept == deposit
    assert released >= 0
    assert kept == retained


# ------------------------------------------------------------------ SimulatedProvider.settle


def _held(amount: int = 1_000):
    from app.services.payments import SimulatedProvider

    provider = SimulatedProvider()
    return provider, provider.hold(amount, "EUR", "demo_card_ok", "hold-key")


def test_settle_returns_a_bounded_reference():
    provider, ref = _held(1_000)

    settlement = provider.settle(ref, release_cents=900, capture_cents=100, key="settle:d1")

    assert isinstance(settlement, str)
    assert 0 < len(settlement) <= 64


@settings(max_examples=40)
@given(data=st.data(), amount=st.integers(min_value=1, max_value=MAX_DEPOSIT_CENTS))
def test_settle_is_idempotent_for_the_same_key_and_amounts(data, amount):
    retained = data.draw(st.integers(min_value=0, max_value=amount))
    provider, ref = _held(amount)

    first = provider.settle(ref, release_cents=amount - retained, capture_cents=retained, key="settle:d1")
    again = provider.settle(ref, release_cents=amount - retained, capture_cents=retained, key="settle:d1")

    assert first == again


def test_settle_with_other_keys_gives_other_references():
    provider, ref = _held(1_000)
    provider2, ref2 = _held(1_000)

    assert provider.settle(ref, release_cents=1_000, capture_cents=0, key="settle:a") != provider2.settle(
        ref2, release_cents=1_000, capture_cents=0, key="settle:b"
    )


def test_settle_same_key_with_different_amounts_is_an_error():
    provider, ref = _held(1_000)
    provider.settle(ref, release_cents=1_000, capture_cents=0, key="settle:d1")

    with pytest.raises(DomainError):
        provider.settle(ref, release_cents=0, capture_cents=1_000, key="settle:d1")


@pytest.mark.parametrize(
    ("release_cents", "capture_cents"),
    [(1_000, 1), (999, 0), (0, 0), (500, 499), (-1, 1_001), (1_001, -1), (2_000, 0)],
)
def test_settle_refuses_amounts_that_do_not_add_up_to_the_held_amount(release_cents, capture_cents):
    provider, ref = _held(1_000)

    with pytest.raises(DomainError):
        provider.settle(ref, release_cents=release_cents, capture_cents=capture_cents, key="settle:d1")


def test_settle_failure_does_not_poison_the_key():
    provider, ref = _held(1_000)
    with pytest.raises(DomainError):
        provider.settle(ref, release_cents=1, capture_cents=1, key="settle:d1")

    assert provider.settle(ref, release_cents=1_000, capture_cents=0, key="settle:d1")
