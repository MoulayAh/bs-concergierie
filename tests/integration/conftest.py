"""Fixtures F2 : prestataire de paiement injectable (voir tests/fixtures/deposits.py pour l'interface)."""

import pytest
from flask import Flask

from tests.fixtures.deposits import RecordingProvider


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
