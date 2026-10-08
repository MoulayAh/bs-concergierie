"""Garde-fou de tests/conftest.py : refuse toute base dont le nom ne finit pas par ``_test``."""

import pytest

from tests.conftest import pytest_configure

BASE = "postgresql+psycopg://escrow:pw@localhost:5432/"


@pytest.mark.parametrize("database", ["escrow", "escrow_dev", "escrow_testing", "test_escrow", "postgres"])
def test_guard_refuses_database_not_ending_with_test(monkeypatch, pytestconfig, database):
    monkeypatch.setenv("TEST_DATABASE_URL", BASE + database)

    with pytest.raises(pytest.UsageError) as caught:
        pytest_configure(pytestconfig)

    assert database in str(caught.value)
    assert "_test" in str(caught.value)


@pytest.mark.parametrize("database", ["escrow_test", "other_test"])
def test_guard_accepts_database_ending_with_test(monkeypatch, pytestconfig, database):
    monkeypatch.setenv("TEST_DATABASE_URL", BASE + database)

    pytest_configure(pytestconfig)
