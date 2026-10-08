"""Prestataire de paiement : interface et implementation simulee (aucune donnee de carte, jamais)."""

import threading
import uuid
from typing import Final, Protocol, cast

from flask import current_app

from app.domain.errors import PaymentDeclined, PaymentUnavailable

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


class SimulatedProvider:
    def __init__(self) -> None:
        self._refs: dict[str, str] = {}
        self._lock = threading.Lock()

    def hold(self, amount: int, currency: str, method: str, key: str) -> str:
        if method in _DECLINED:
            raise PaymentDeclined("Paiement refuse par le prestataire")
        if method == "demo_provider_down":
            raise PaymentUnavailable("Prestataire de paiement indisponible")
        if method != "demo_card_ok":
            raise PaymentDeclined("Moyen de paiement inconnu")
        with self._lock:
            return self._refs.setdefault(key, "sim_" + uuid.uuid4().hex)

    def refund(self, ref: str) -> None:
        return None


def get_provider() -> PaymentProvider:
    return cast(PaymentProvider, current_app.extensions["payment_provider"])
