"""Montants (domaine pur) : centimes entiers, bornes, types stricts. Aucun float pour l'argent.

Interface supposee de ``app.domain.money`` :
    MAX_DEPOSIT_CENTS == 50_000_000 ; ALLOWED_CURRENCIES == {"EUR","CHF","GBP","USD"}
    validate_deposit_cents(value: object) -> int      (leve InvalidAmount : INVALID_AMOUNT / 422)
    validate_retained_cents(retained: object, deposit_cents: int) -> int
    split_deposit(deposit_cents: int, retained_cents: int) -> tuple[int, int]   (released_to_client, retained)
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.domain.errors import DomainError, InvalidAmount
from app.domain.money import (
    ALLOWED_CURRENCIES,
    MAX_DEPOSIT_CENTS,
    split_deposit,
    validate_deposit_cents,
    validate_retained_cents,
)

MAX = 50_000_000


def test_max_deposit_is_500_000_euros_in_cents():
    assert MAX_DEPOSIT_CENTS == MAX
    assert isinstance(MAX_DEPOSIT_CENTS, int)


def test_allowed_currencies_is_the_iso_whitelist():
    assert frozenset(ALLOWED_CURRENCIES) == frozenset({"EUR", "CHF", "GBP", "USD"})


@pytest.mark.parametrize("value", [1, 2, 100, 2_500_000, MAX - 1, MAX])
def test_deposit_accepts_values_inside_bounds(value):
    assert validate_deposit_cents(value) == value


@pytest.mark.parametrize("value", [0, -1, -MAX, MAX + 1, 2**31, 2**63, 2**64, -(2**63), 10**30])
def test_deposit_rejects_out_of_range_integers(value):
    with pytest.raises(InvalidAmount) as exc:
        validate_deposit_cents(value)
    assert exc.value.code == "INVALID_AMOUNT"
    assert exc.value.http_status == 422


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        None,
        "100",
        "",
        "abc",
        " 100",
        100.0,
        0.5,
        1e309,
        float("inf"),
        float("-inf"),
        float("nan"),
        [],
        {},
        (1,),
        b"100",
        1 + 0j,
    ],
    ids=repr,
)
def test_deposit_rejects_non_integer_types(value):
    with pytest.raises(InvalidAmount):
        validate_deposit_cents(value)


@given(st.integers(min_value=1, max_value=MAX))
def test_deposit_amount_bounds_accepts_every_integer_in_range(value):
    assert validate_deposit_cents(value) == value


@given(st.one_of(st.integers(max_value=0), st.integers(min_value=MAX + 1)))
def test_deposit_amount_bounds_rejects_every_integer_outside_range(value):
    with pytest.raises(InvalidAmount):
        validate_deposit_cents(value)


@given(
    st.one_of(
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(),
        st.booleans(),
        st.none(),
        st.binary(),
        st.lists(st.integers()),
    )
)
def test_deposit_amount_bounds_rejects_every_non_integer_value(value):
    with pytest.raises(InvalidAmount):
        validate_deposit_cents(value)


@given(st.integers(min_value=1, max_value=MAX).flatmap(lambda d: st.tuples(st.just(d), st.integers(0, d))))
def test_retained_within_deposit_is_accepted(pair):
    deposit, retained = pair
    assert validate_retained_cents(retained, deposit) == retained


@given(st.integers(min_value=1, max_value=MAX), st.integers(min_value=1, max_value=10**12))
def test_retained_above_deposit_is_rejected(deposit, excess):
    with pytest.raises(InvalidAmount):
        validate_retained_cents(deposit + excess, deposit)


@given(st.integers(min_value=1, max_value=MAX), st.integers(max_value=-1))
def test_negative_retained_is_rejected(deposit, retained):
    with pytest.raises(InvalidAmount):
        validate_retained_cents(retained, deposit)


@pytest.mark.parametrize("retained", [True, None, "10", 1.5, float("nan")], ids=repr)
def test_retained_rejects_non_integer_types(retained):
    with pytest.raises(InvalidAmount):
        validate_retained_cents(retained, 1000)


@given(st.integers(min_value=1, max_value=MAX).flatmap(lambda d: st.tuples(st.just(d), st.integers(0, d))))
def test_split_deposit_preserves_accounting_invariant(pair):
    deposit, retained = pair
    released, kept = split_deposit(deposit, retained)
    assert released + kept == deposit
    assert kept == retained
    assert released >= 0
    assert isinstance(released, int)
    assert isinstance(kept, int)


def test_split_deposit_with_no_retention_returns_everything_to_client():
    assert split_deposit(1_000, 0) == (1_000, 0)


def test_split_deposit_with_full_retention_returns_nothing_to_client():
    assert split_deposit(1_000, 1_000) == (0, 1_000)


@given(st.integers(min_value=1, max_value=MAX), st.integers(min_value=1, max_value=10**9))
def test_split_deposit_rejects_retention_above_deposit(deposit, excess):
    with pytest.raises(DomainError) as exc:
        split_deposit(deposit, deposit + excess)
    assert exc.value.code == "INVALID_AMOUNT"
