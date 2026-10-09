"""Machine d'etats du sequestre (source de verite, domaine pur : ni Flask ni DB).

Les etats sont dupliques dans ``app.models.enums`` (miroir de l'ENUM PostgreSQL) ; le service
les convertit par valeur, ce qui echoue bruyamment en cas de divergence.
"""

import enum
from dataclasses import dataclass
from typing import Final

from app.domain.errors import ForbiddenActor, InvalidAmount, InvalidTransition
from app.domain.money import validate_retained_cents


class ContractStatus(enum.StrEnum):
    DRAFT = "DRAFT"
    AWAITING_DEPOSIT = "AWAITING_DEPOSIT"
    FUNDED = "FUNDED"
    ACTIVE = "ACTIVE"
    INSPECTION_PENDING = "INSPECTION_PENDING"
    DISPUTED = "DISPUTED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"
    RELEASED = "RELEASED"
    SETTLED = "SETTLED"


class Event(enum.StrEnum):
    SIGN_CONTRACT = "sign_contract"
    CANCEL = "cancel"
    DEPOSIT = "deposit"
    START_RENTAL = "start_rental"
    SUBMIT_RETURN_REPORT = "submit_return_report"
    SIGN_REPORT = "sign_report"
    REVISE_RETURN_REPORT = "revise_return_report"
    CONTEST = "contest"
    RESOLVE = "resolve"


class Party(enum.StrEnum):
    OWNER = "owner"
    CLIENT = "client"
    ADMIN = "admin"


TERMINAL_STATUSES: Final[frozenset[ContractStatus]] = frozenset(
    {
        ContractStatus.CANCELLED,
        ContractStatus.REFUNDED,
        ContractStatus.RELEASED,
        ContractStatus.SETTLED,
    }
)


@dataclass(frozen=True)
class TransitionResult:
    status: ContractStatus
    signed_by: frozenset[Party]


@dataclass(frozen=True)
class _Rule:
    actors: frozenset[Party]
    two_party: bool
    target: ContractStatus


_BOTH: Final = frozenset({Party.OWNER, Party.CLIENT})
_S = ContractStatus
_E = Event

_RULES: Final[dict[tuple[ContractStatus, Event], _Rule]] = {
    (_S.DRAFT, _E.SIGN_CONTRACT): _Rule(_BOTH, True, _S.AWAITING_DEPOSIT),
    (_S.DRAFT, _E.CANCEL): _Rule(_BOTH, False, _S.CANCELLED),
    (_S.AWAITING_DEPOSIT, _E.DEPOSIT): _Rule(frozenset({Party.CLIENT}), False, _S.FUNDED),
    (_S.AWAITING_DEPOSIT, _E.CANCEL): _Rule(_BOTH, False, _S.CANCELLED),
    (_S.FUNDED, _E.START_RENTAL): _Rule(frozenset({Party.OWNER}), False, _S.ACTIVE),
    (_S.FUNDED, _E.CANCEL): _Rule(_BOTH, True, _S.REFUNDED),
    (_S.ACTIVE, _E.SUBMIT_RETURN_REPORT): _Rule(frozenset({Party.OWNER}), False, _S.INSPECTION_PENDING),
    (_S.INSPECTION_PENDING, _E.SIGN_REPORT): _Rule(_BOTH, True, _S.RELEASED),
    (_S.INSPECTION_PENDING, _E.REVISE_RETURN_REPORT): _Rule(
        frozenset({Party.OWNER}), False, _S.INSPECTION_PENDING
    ),
    (_S.INSPECTION_PENDING, _E.CONTEST): _Rule(_BOTH, False, _S.DISPUTED),
    (_S.DISPUTED, _E.RESOLVE): _Rule(frozenset({Party.ADMIN}), False, _S.SETTLED),
}


def transition(
    current: ContractStatus,
    event: Event,
    *,
    actor: Party,
    signed_by: frozenset[Party] = frozenset(),
    deposit_cents: int | None = None,
    retained_cents: int = 0,
) -> TransitionResult:
    """Calcule l'etat suivant ; ne mute rien.

    Pour un evenement a deux parties, le premier appel renvoie le meme etat avec l'acteur dans
    ``signed_by`` ; l'appel de l'autre partie renvoie l'etat cible.
    """
    rule = _RULES.get((current, event))
    if rule is None:
        raise InvalidTransition(f"L'evenement '{event.value}' est interdit dans l'etat {current.value}")
    if actor not in rule.actors:
        raise ForbiddenActor(f"Cette partie ne peut pas executer '{event.value}'")

    target = rule.target
    if event is Event.SIGN_REPORT:
        if deposit_cents is None:
            raise InvalidAmount("Le montant de la caution est requis pour signer le rapport")
        if validate_retained_cents(retained_cents, deposit_cents) > 0:
            target = ContractStatus.SETTLED

    if not rule.two_party:
        return TransitionResult(target, frozenset())

    if actor in signed_by:
        raise InvalidTransition(f"Cette partie a deja approuve '{event.value}'")
    approvals = frozenset({*signed_by, actor})
    if rule.actors <= approvals:
        return TransitionResult(target, approvals)
    return TransitionResult(current, approvals)
