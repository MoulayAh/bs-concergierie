"""Matrice complete etat x evenement de la machine d'etats (domaine pur, sans Flask ni DB).

Interface supposee de ``app.domain.state_machine`` :

    transition(current, event, *, actor, signed_by=frozenset(), deposit_cents=None, retained_cents=0)
        -> TransitionResult(status, signed_by)

- ``actor`` est une ``Party`` (OWNER / CLIENT / ADMIN) ; ``signed_by`` = parties ayant deja approuve
  l'evenement en cours (evenements a deux parties).
- Evenement a deux parties : au premier appel ``status`` reste ``current`` et ``signed_by`` contient
  l'acteur ; au second appel (par l'autre partie) ``status`` devient la cible.
- Combinaison (etat, evenement) interdite => ``InvalidTransition`` (code INVALID_TRANSITION, http 409).
- Combinaison permise mais mauvais acteur => ``ForbiddenActor`` (FORBIDDEN_ACTOR, 403).
- La verification de la transition precede celle de l'acteur.
"""

import itertools

import pytest

from app.domain.errors import DomainError, ForbiddenActor, InvalidTransition
from app.domain.state_machine import (
    TERMINAL_STATUSES,
    ContractStatus,
    Event,
    Party,
    transition,
)

S = ContractStatus
E = Event
OWNER, CLIENT, ADMIN = Party.OWNER, Party.CLIENT, Party.ADMIN
BOTH = frozenset({OWNER, CLIENT})

# (etat, evenement) -> (acteurs autorises, deux parties requises ?, etat cible)
VALID: dict[tuple[S, E], tuple[frozenset[Party], bool, S]] = {
    (S.DRAFT, E.SIGN_CONTRACT): (BOTH, True, S.AWAITING_DEPOSIT),
    (S.DRAFT, E.CANCEL): (BOTH, False, S.CANCELLED),
    (S.AWAITING_DEPOSIT, E.DEPOSIT): (frozenset({CLIENT}), False, S.FUNDED),
    (S.AWAITING_DEPOSIT, E.CANCEL): (BOTH, False, S.CANCELLED),
    (S.FUNDED, E.START_RENTAL): (frozenset({OWNER}), False, S.ACTIVE),
    (S.FUNDED, E.CANCEL): (BOTH, True, S.REFUNDED),
    (S.ACTIVE, E.SUBMIT_RETURN_REPORT): (frozenset({OWNER}), False, S.INSPECTION_PENDING),
    (S.INSPECTION_PENDING, E.SIGN_REPORT): (BOTH, True, S.RELEASED),
    (S.INSPECTION_PENDING, E.CONTEST): (BOTH, False, S.DISPUTED),
    (S.DISPUTED, E.RESOLVE): (frozenset({ADMIN}), False, S.SETTLED),
}

ALL_PAIRS = list(itertools.product(S, E))
INVALID_PAIRS = [pair for pair in ALL_PAIRS if pair not in VALID]
VALID_PAIRS = list(VALID)


def _ctx(status: S) -> dict[str, int]:
    """Contexte monetaire neutre (sans retenue) pour les evenements qui en ont besoin."""
    return {"deposit_cents": 1_000_000, "retained_cents": 0} if status is S.INSPECTION_PENDING else {}


def test_matrix_covers_every_state_and_event():
    assert len(ALL_PAIRS) == len(S) * len(E)
    assert len(VALID_PAIRS) + len(INVALID_PAIRS) == len(ALL_PAIRS)
    assert len(S) == 10
    assert len(E) == 8


@pytest.mark.parametrize(("status", "event"), VALID_PAIRS, ids=lambda v: v.name)
def test_valid_transition_reaches_target_when_authorized_actors_complete(status, event):
    actors, two_party, target = VALID[(status, event)]
    if two_party:
        first, second = OWNER, CLIENT
        step1 = transition(status, event, actor=first, **_ctx(status))
        assert step1.status is status
        assert step1.signed_by == frozenset({first})
        step2 = transition(status, event, actor=second, signed_by=step1.signed_by, **_ctx(status))
        assert step2.status is target
    else:
        for actor in actors:
            result = transition(status, event, actor=actor, **_ctx(status))
            assert result.status is target


@pytest.mark.parametrize(("status", "event"), VALID_PAIRS, ids=lambda v: v.name)
def test_valid_pair_refuses_unauthorized_actor_with_forbidden_actor(status, event):
    actors = VALID[(status, event)][0]
    for actor in set(Party) - actors:
        with pytest.raises(ForbiddenActor) as exc:
            transition(status, event, actor=actor, **_ctx(status))
        assert exc.value.code == "FORBIDDEN_ACTOR"
        assert exc.value.http_status == 403


@pytest.mark.parametrize(("status", "event"), INVALID_PAIRS, ids=lambda v: v.name)
def test_invalid_pair_raises_invalid_transition_for_every_actor(status, event):
    for actor in Party:
        with pytest.raises(InvalidTransition) as exc:
            transition(status, event, actor=actor, **_ctx(status))
        assert exc.value.code == "INVALID_TRANSITION"
        assert exc.value.http_status == 409


def test_invalid_transition_is_a_domain_error_with_readable_message():
    with pytest.raises(DomainError) as exc:
        transition(S.CANCELLED, E.SIGN_CONTRACT, actor=OWNER)
    assert isinstance(exc.value, InvalidTransition)
    assert str(exc.value)


@pytest.mark.parametrize("status", sorted(TERMINAL_STATUSES, key=lambda s: s.name), ids=lambda s: s.name)
def test_terminal_status_accepts_no_event(status):
    for event, actor in itertools.product(E, Party):
        with pytest.raises(InvalidTransition):
            transition(status, event, actor=actor)


def test_terminal_statuses_are_exactly_cancelled_refunded_released_settled():
    assert frozenset({S.CANCELLED, S.REFUNDED, S.RELEASED, S.SETTLED}) == frozenset(TERMINAL_STATUSES)


def test_cancel_is_refused_when_active():
    for actor in Party:
        with pytest.raises(InvalidTransition):
            transition(S.ACTIVE, E.CANCEL, actor=actor)


@pytest.mark.parametrize("actor", [OWNER, CLIENT], ids=lambda a: a.name)
def test_same_party_signing_twice_in_draft_is_invalid_transition(actor):
    first = transition(S.DRAFT, E.SIGN_CONTRACT, actor=actor)
    assert first.status is S.DRAFT
    with pytest.raises(InvalidTransition):
        transition(S.DRAFT, E.SIGN_CONTRACT, actor=actor, signed_by=first.signed_by)


@pytest.mark.parametrize(
    ("first", "second"), [(OWNER, CLIENT), (CLIENT, OWNER)], ids=["owner_first", "client_first"]
)
def test_draft_moves_to_awaiting_deposit_whatever_the_signing_order(first, second):
    step1 = transition(S.DRAFT, E.SIGN_CONTRACT, actor=first)
    assert step1.status is S.DRAFT
    step2 = transition(S.DRAFT, E.SIGN_CONTRACT, actor=second, signed_by=step1.signed_by)
    assert step2.status is S.AWAITING_DEPOSIT


def test_admin_cannot_sign_contract():
    with pytest.raises(ForbiddenActor):
        transition(S.DRAFT, E.SIGN_CONTRACT, actor=ADMIN)


def test_funded_cancel_needs_both_parties_to_refund():
    step1 = transition(S.FUNDED, E.CANCEL, actor=CLIENT)
    assert step1.status is S.FUNDED
    step2 = transition(S.FUNDED, E.CANCEL, actor=OWNER, signed_by=step1.signed_by)
    assert step2.status is S.REFUNDED


def test_sign_report_without_retention_releases():
    money = {"deposit_cents": 500_000, "retained_cents": 0}
    first = transition(S.INSPECTION_PENDING, E.SIGN_REPORT, actor=OWNER, **money)
    result = transition(S.INSPECTION_PENDING, E.SIGN_REPORT, actor=CLIENT, signed_by=first.signed_by, **money)
    assert result.status is S.RELEASED


@pytest.mark.parametrize("retained", [1, 250_000, 500_000])
def test_sign_report_with_retention_up_to_deposit_settles(retained):
    first = transition(
        S.INSPECTION_PENDING, E.SIGN_REPORT, actor=OWNER, deposit_cents=500_000, retained_cents=retained
    )
    result = transition(
        S.INSPECTION_PENDING,
        E.SIGN_REPORT,
        actor=CLIENT,
        signed_by=first.signed_by,
        deposit_cents=500_000,
        retained_cents=retained,
    )
    assert result.status is S.SETTLED


@pytest.mark.parametrize("retained", [-1, 500_001, 2**63])
def test_sign_report_with_retention_out_of_bounds_is_rejected(retained):
    with pytest.raises(DomainError) as exc:
        transition(
            S.INSPECTION_PENDING, E.SIGN_REPORT, actor=OWNER, deposit_cents=500_000, retained_cents=retained
        )
    assert exc.value.code == "INVALID_AMOUNT"
    assert exc.value.http_status == 422


def test_transition_does_not_mutate_its_inputs():
    signed = frozenset({OWNER})
    transition(S.DRAFT, E.SIGN_CONTRACT, actor=CLIENT, signed_by=signed)
    assert signed == frozenset({OWNER})
