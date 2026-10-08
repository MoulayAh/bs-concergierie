"""Montants : entiers en centimes, bornes strictes."""

from typing import Final

from app.domain.errors import InvalidAmount

MAX_DEPOSIT_CENTS: Final[int] = 50_000_000
ALLOWED_CURRENCIES: Final[frozenset[str]] = frozenset({"EUR", "CHF", "GBP", "USD"})


def _as_strict_int(value: object, label: str) -> int:
    # bool est une sous-classe de int : il doit etre refuse explicitement.
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidAmount(f"{label} doit etre un entier en centimes")
    return value


def validate_deposit_cents(value: object) -> int:
    amount = _as_strict_int(value, "La caution")
    if not 1 <= amount <= MAX_DEPOSIT_CENTS:
        raise InvalidAmount(f"La caution doit etre comprise entre 1 et {MAX_DEPOSIT_CENTS} centimes")
    return amount


def validate_retained_cents(retained: object, deposit_cents: int) -> int:
    amount = _as_strict_int(retained, "La retenue")
    if not 0 <= amount <= deposit_cents:
        raise InvalidAmount("La retenue doit etre comprise entre 0 et le montant de la caution")
    return amount


def split_deposit(deposit_cents: int, retained_cents: int) -> tuple[int, int]:
    """Renvoie (rendu au client, retenu par le loueur) ; la somme vaut toujours la caution."""
    retained = validate_retained_cents(retained_cents, deposit_cents)
    return deposit_cents - retained, retained
