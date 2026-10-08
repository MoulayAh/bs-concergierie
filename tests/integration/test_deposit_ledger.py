"""F2 : l'invariant comptable est garanti par PostgreSQL, pas seulement par Python.

Interface supposee : ``app.models.Deposit`` portant les CHECK du plan (dans le modele, car les tests
creent le schema par ``create_all``) :
``held + refunded + released + retained = amount``, colonnes >= 0, ``amount BETWEEN 1 AND 50000000``,
``contract_id`` et ``provider_ref`` UNIQUE.
"""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from tests.fixtures.deposits import awaiting_deposit_contract, deposit_rows, funded_contract

pytestmark = pytest.mark.integration

AMOUNT = 2_500_000


@pytest.fixture
def funded(api, owner_user, client_user) -> str:
    return funded_contract(api, owner_user, client_user)


def _update(app, cid: str, assignment: str) -> None:
    with app.app_context():
        try:
            db.session.execute(
                text(f"UPDATE deposits SET {assignment} WHERE contract_id = :c"),  # noqa: S608
                {"c": cid},
            )
            db.session.commit()
        finally:
            db.session.rollback()


@pytest.mark.parametrize(
    "assignment",
    [
        "held_cents = held_cents + 1",
        "held_cents = held_cents - 1",
        "held_cents = 0",
        "refunded_cents = 1",
        "released_cents = 1",
        "retained_cents = 1",
        "held_cents = 0, refunded_cents = amount_cents + 1",
        "amount_cents = amount_cents + 1",
        "amount_cents = amount_cents - 1",
    ],
)
def test_ledger_invariant_enforced_by_database(app, funded, assignment):
    with pytest.raises(IntegrityError) as exc:
        _update(app, funded, assignment)

    assert type(exc.value.orig).__name__ == "CheckViolation"
    row = deposit_rows(app, funded)[0]
    assert (row["amount_cents"], row["held_cents"]) == (AMOUNT, AMOUNT)
    assert (row["refunded_cents"], row["released_cents"], row["retained_cents"]) == (0, 0, 0)


@pytest.mark.parametrize(
    "assignment",
    [
        "held_cents = -100, refunded_cents = amount_cents + 100",
        "held_cents = amount_cents + 100, retained_cents = -100",
        "held_cents = 0, released_cents = amount_cents + 5, retained_cents = -5",
    ],
)
def test_ledger_rejects_negative_columns_even_when_sum_balances(app, funded, assignment):
    with pytest.raises(IntegrityError) as exc:
        _update(app, funded, assignment)

    assert type(exc.value.orig).__name__ == "CheckViolation"
    assert deposit_rows(app, funded)[0]["held_cents"] == AMOUNT


@pytest.mark.parametrize(
    "assignment",
    [
        "held_cents = 0, refunded_cents = amount_cents",
        "held_cents = 0, released_cents = amount_cents",
        "held_cents = 0, released_cents = 1000, retained_cents = amount_cents - 1000",
    ],
)
def test_ledger_accepts_balanced_updates(app, funded, assignment):
    _update(app, funded, assignment)

    row = deposit_rows(app, funded)[0]
    assert row["held_cents"] != AMOUNT
    total = row["held_cents"] + row["refunded_cents"] + row["released_cents"] + row["retained_cents"]
    assert total == row["amount_cents"] == AMOUNT


def _insert(app, contract_id: str, **overrides) -> None:
    from app.models import Deposit

    values = {
        "contract_id": uuid.UUID(contract_id),
        "amount_cents": AMOUNT,
        "currency": "EUR",
        "held_cents": AMOUNT,
        "refunded_cents": 0,
        "released_cents": 0,
        "retained_cents": 0,
        "provider": "simulated",
        "provider_ref": f"sim_{uuid.uuid4().hex}",
    }
    values.update(overrides)
    with app.app_context():
        try:
            db.session.add(Deposit(**values))
            db.session.commit()
        finally:
            db.session.rollback()


@pytest.mark.parametrize(
    "overrides",
    [
        {"held_cents": AMOUNT - 1},
        {"held_cents": AMOUNT + 1},
        {"amount_cents": 0, "held_cents": 0},
        {"amount_cents": -5, "held_cents": -5},
        {"amount_cents": 50_000_001, "held_cents": 50_000_001},
        {"currency": "JPY"},
    ],
    ids=repr,
)
def test_insert_of_unbalanced_or_invalid_deposit_is_rejected(app, api, owner_user, client_user, overrides):
    cid = awaiting_deposit_contract(api, owner_user, client_user)

    with pytest.raises(IntegrityError):
        _insert(app, cid, **overrides)

    assert deposit_rows(app, cid) == []


def test_insert_of_balanced_deposit_is_accepted(app, api, owner_user, client_user):
    cid = awaiting_deposit_contract(api, owner_user, client_user)

    _insert(app, cid)

    assert len(deposit_rows(app, cid)) == 1


def test_second_deposit_row_for_same_contract_is_rejected(app, funded):
    with pytest.raises(IntegrityError) as exc:
        _insert(app, funded)

    assert type(exc.value.orig).__name__ == "UniqueViolation"
    assert len(deposit_rows(app, funded)) == 1


def test_provider_ref_is_unique_across_contracts(app, api, owner_user, client_user, funded):
    other = awaiting_deposit_contract(api, owner_user, client_user)
    ref = deposit_rows(app, funded)[0]["provider_ref"]

    with pytest.raises(IntegrityError) as exc:
        _insert(app, other, provider_ref=ref)

    assert type(exc.value.orig).__name__ == "UniqueViolation"
    assert deposit_rows(app, other) == []
