"""Aides F2 : contrats pre-positionnes, lecture de la table ``deposits``, prestataire de test.

Interfaces SUPPOSEES (a fournir par db-migrator / backend-dev) :

- ``app.models.Deposit`` (colonnes du plan : id, contract_id, amount_cents, currency, status, held_cents,
  refunded_cents, released_cents, retained_cents, provider, provider_ref, created_at, updated_at) et
  ``app.models.DepositStatus`` (HELD / REFUNDED / RELEASED / SETTLED). Contrainte CHECK de l'invariant
  comptable DANS le modele (les tests creent le schema par ``create_all``).
- ``Contract.owner_cancel_approved_at``, ``Contract.client_cancel_approved_at``, ``Contract.started_at``.
- ``app.services.payments`` : ``PaymentProvider`` (``hold(amount, currency, method, key) -> str`` renvoie la
  reference ; ``refund(ref) -> None``) et ``SimulatedProvider``.
- ``app.domain.errors`` : ``PaymentDeclined`` (402, PAYMENT_DECLINED), ``PaymentUnavailable`` (503,
  PAYMENT_UNAVAILABLE), constructibles avec un message.
- INJECTION DU PRESTATAIRE : le service lit le prestataire a CHAQUE requete dans
  ``current_app.extensions["payment_provider"]`` (par defaut un ``SimulatedProvider`` installe par
  ``create_app``). Les tests le remplacent par ``RecordingProvider`` (fixture ``provider``).
- Sortie contrat : ``funds`` (objet du plan, ``null`` tant qu'aucun depot) et ``cancellation``
  (``{"owner_approved", "client_approved"}``, toujours present).
- Evenements : ``deposit`` (AWAITING_DEPOSIT -> FUNDED), ``deposit_failed`` (refus/panne, from == to ==
  AWAITING_DEPOSIT, ne change ni statut ni version), ``cancel`` (1re approbation FUNDED -> FUNDED, 2e
  FUNDED -> REFUNDED), ``start_rental`` (FUNDED -> ACTIVE). Chaque transition incremente ``version``.
- GET /deposit : 200 = objet ``funds`` ; 404 NOT_FOUND si tiers OU si aucun depot n'existe encore.

Les imports de ces interfaces sont paresseux : le module se charge meme si elles n'existent pas encore.
"""

import hashlib
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sqlalchemy import select

from app.extensions import db
from tests.fixtures.helpers import Api, TestUser

TRANSITION_EXCLUDED = frozenset({"deposit_failed"})


def awaiting_deposit_contract(
    api: Api, owner: TestUser, client: TestUser, body: dict[str, Any] | None = None
) -> str:
    cid = api.create_ok(owner, body)["id"]
    assert api.sign(cid, client).status_code == 200
    assert api.sign(cid, owner).status_code == 200
    assert api.get(cid, owner).get_json()["status"] == "AWAITING_DEPOSIT"
    return cid


def funded_contract(api: Api, owner: TestUser, client: TestUser, body: dict[str, Any] | None = None) -> str:
    cid = awaiting_deposit_contract(api, owner, client, body)
    resp = api.deposit(cid, client)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["status"] == "FUNDED"
    return cid


def deposit_rows(app: Any, contract_id: str) -> list[dict[str, Any]]:
    from app.models import Deposit  # import paresseux : interface supposee

    with app.app_context():
        rows = db.session.scalars(select(Deposit).where(Deposit.contract_id == contract_id)).all()
        return [
            {
                "amount_cents": r.amount_cents,
                "currency": r.currency.strip(),
                "status": getattr(r.status, "value", r.status),
                "held_cents": r.held_cents,
                "refunded_cents": r.refunded_cents,
                "released_cents": r.released_cents,
                "retained_cents": r.retained_cents,
                "provider": r.provider,
                "provider_ref": r.provider_ref,
            }
            for r in rows
        ]


def full_state(app: Any, api: Api, contract_id: str, user: TestUser) -> dict[str, Any]:
    """Tout ce qui doit rester identique apres une erreur : statut, version, evenements, depot, sortie."""
    contract = api.get(contract_id, user)
    assert contract.status_code == 200, contract.get_data(as_text=True)
    events = api.events(contract_id, user).get_json()["events"]
    return {
        "contract": contract.get_json(),
        "events": [(e["event"], e["from_status"], e["to_status"], e["payload_hash"]) for e in events],
        "deposits": deposit_rows(app, contract_id),
    }


def transition_events(api: Api, contract_id: str, user: TestUser) -> list[dict[str, Any]]:
    """Evenements de transition (hors journal ``deposit_failed``)."""
    events = api.events(contract_id, user).get_json()["events"]
    return [e for e in events if e["event"] not in TRANSITION_EXCLUDED]


def failed_events(api: Api, contract_id: str, user: TestUser) -> list[dict[str, Any]]:
    """Journal ``deposit_failed`` (refus / panne du prestataire)."""
    events = api.events(contract_id, user).get_json()["events"]
    return [e for e in events if e["event"] == "deposit_failed"]


def run_concurrently(app: Any, jobs: list[Callable[[Api], Any]]) -> list[Any]:
    barrier = threading.Barrier(len(jobs))

    def worker(job: Callable[[Api], Any]) -> Any:
        local = Api(app)
        barrier.wait(timeout=15)
        return job(local)

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(worker, job) for job in jobs]
        return [f.result(timeout=60) for f in futures]


class RecordingProvider:
    """Prestataire de test : memorise les appels, reference deterministe par cle d'idempotence.

    ``fail_next_holds`` : nombre de ``hold`` qui levent d'abord ``PaymentUnavailable`` (panne transitoire).
    ``hold`` est idempotent sur la cle : meme cle => meme reference.
    """

    def __init__(self, fail_next_holds: int = 0) -> None:
        self.fail_next_holds = fail_next_holds
        self.hold_calls: list[tuple[int, str, str, str]] = []
        self.refund_calls: list[str] = []
        self._lock = threading.Lock()

    def hold(self, amount: int, currency: str, method: str, key: str) -> str:
        from app.domain.errors import PaymentDeclined, PaymentUnavailable

        with self._lock:
            self.hold_calls.append((amount, currency, method, key))
            if self.fail_next_holds > 0:
                self.fail_next_holds -= 1
                raise PaymentUnavailable("Prestataire de paiement indisponible")
        if method in {"demo_card_declined", "demo_insufficient_funds"}:
            raise PaymentDeclined("Paiement refuse")
        if method == "demo_provider_down":
            raise PaymentUnavailable("Prestataire de paiement indisponible")
        return "sim_" + hashlib.sha256(key.encode()).hexdigest()[:24]

    def refund(self, ref: str) -> None:
        with self._lock:
            self.refund_calls.append(ref)

    @property
    def distinct_refs_held(self) -> int:
        return len({hashlib.sha256(c[3].encode()).hexdigest() for c in self.hold_calls})
