"""Fixtures F2 : prestataire de paiement injectable (voir tests/fixtures/deposits.py pour l'interface).

Fixtures F3 : ``keyring`` (cles Ed25519 de test par utilisateur, voir tests/fixtures/reports.py).

Fixtures F4 (tests/fixtures/release.py) : ``flaky_settle_provider`` (le premier ``settle`` echoue) et
``pending_factory`` (amene un contrat jusqu'a INSPECTION_PENDING ; a combiner avec ``provider``).
"""

from collections.abc import Callable

import pytest
from flask import Flask

from tests.fixtures.deposits import RecordingProvider
from tests.fixtures.helpers import Api, TestUser
from tests.fixtures.release import Pending, pending_contract
from tests.fixtures.reports import KeyRing


@pytest.fixture
def provider(app: Flask) -> RecordingProvider:
    """Remplace ``app.extensions["payment_provider"]`` par un prestataire qui memorise ses appels."""
    recording = RecordingProvider()
    app.extensions["payment_provider"] = recording
    return recording


@pytest.fixture
def flaky_provider(app: Flask) -> RecordingProvider:
    """Prestataire dont le premier ``hold`` echoue (panne transitoire) puis reussit."""
    recording = RecordingProvider(fail_next_holds=1)
    app.extensions["payment_provider"] = recording
    return recording


@pytest.fixture
def flaky_settle_provider(app: Flask) -> RecordingProvider:
    """Prestataire dont le premier ``settle`` echoue (panne a la liberation) puis reussit."""
    recording = RecordingProvider(fail_next_settles=1)
    app.extensions["payment_provider"] = recording
    return recording


@pytest.fixture
def keyring(api: Api) -> KeyRing:
    return KeyRing(api)


@pytest.fixture
def pending_factory(
    api: Api, keyring: KeyRing, owner_user: TestUser, client_user: TestUser
) -> Callable[..., Pending]:
    """``pending_factory(retention_cents=0, damage=None)`` -> ``Pending`` (INSPECTION_PENDING)."""

    def _make(retention_cents: int = 0, damage: bool | None = None) -> Pending:
        return pending_contract(
            api, keyring, owner_user, client_user, retention_cents=retention_cents, damage=damage
        )

    return _make
