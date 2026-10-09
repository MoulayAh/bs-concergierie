"""Prestataire de paiement : interface et implementation simulee (aucune donnee de carte, jamais)."""

import hashlib
import threading
import uuid
from typing import Final, Protocol, cast

from flask import current_app

from app.domain.errors import InvalidAmount, PaymentDeclined, PaymentUnavailable, SettlementConflict

PROVIDER_NAME: Final = "simulated"
PAYMENT_METHODS: Final = (
    "demo_card_ok",
    "demo_card_declined",
    "demo_insufficient_funds",
    "demo_provider_down",
)
_DECLINED: Final = frozenset({"demo_card_declined", "demo_insufficient_funds"})


class PaymentProvider(Protocol):
    def hold(self, amount: int, currency: str, method: str, key: str) -> str:
        """Bloque les fonds ; idempotent sur ``key`` (meme cle => meme reference)."""
        ...

    def refund(self, ref: str) -> None:
        """Rembourse integralement ; peut etre rappele sans effet supplementaire."""
        ...

    def settle(self, ref: str, *, release_cents: int, capture_cents: int, key: str) -> str:
        """Rend ``release_cents`` au client et verse ``capture_cents`` au loueur, en un seul appel.

        Idempotent sur ``key`` : memes montants => meme reference ; montants differents => erreur.
        """
        ...


class SimulatedProvider:
    def __init__(self) -> None:
        self._refs: dict[str, str] = {}
        self._held: dict[str, int] = {}
        self._settled: dict[str, tuple[str, int, int, str]] = {}
        self._lock = threading.Lock()

    def hold(self, amount: int, currency: str, method: str, key: str) -> str:
        if method in _DECLINED:
            raise PaymentDeclined("Paiement refuse par le prestataire")
        if method == "demo_provider_down":
            raise PaymentUnavailable("Prestataire de paiement indisponible")
        if method != "demo_card_ok":
            raise PaymentDeclined("Moyen de paiement inconnu")
        with self._lock:
            ref = self._refs.setdefault(key, "sim_" + uuid.uuid4().hex)
            self._held[ref] = amount
            return ref

    def refund(self, ref: str) -> None:
        return None

    def settle(self, ref: str, *, release_cents: int, capture_cents: int, key: str) -> str:
        with self._lock:
            previous = self._settled.get(key)
            if previous is not None:
                if previous[:3] != (ref, release_cents, capture_cents):
                    raise SettlementConflict("Cle de reglement deja utilisee avec des montants differents")
                return previous[3]
            if release_cents < 0 or capture_cents < 0:
                raise InvalidAmount("Un montant de reglement ne peut pas etre negatif")
            held = self._held.get(ref)
            if held is not None and release_cents + capture_cents != held:
                raise InvalidAmount("La somme du reglement doit egaler le montant bloque")
            settlement_ref = "sim_set_" + hashlib.sha256(key.encode()).hexdigest()[:24]
            self._settled[key] = (ref, release_cents, capture_cents, settlement_ref)
            return settlement_ref


def get_provider() -> PaymentProvider:
    return cast(PaymentProvider, current_app.extensions["payment_provider"])
