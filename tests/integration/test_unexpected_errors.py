"""Reserve 5 : exceptions inattendues -> JSON {"error": ...} sans fuite, session saine ensuite."""

import pytest
from sqlalchemy.exc import OperationalError

from tests.fixtures.helpers import assert_error

SECRET = "super-secret-internal-detail"


@pytest.fixture
def boom_routes(app):
    def _runtime():
        raise RuntimeError(SECRET)

    def _operational():
        raise OperationalError("SELECT secret_column FROM secret_table", {}, Exception(f"host=db {SECRET}"))

    app.add_url_rule("/_test/runtime", "test_runtime", _runtime)
    app.add_url_rule("/_test/operational", "test_operational", _operational)
    return app


def test_unexpected_exception_returns_500_internal_error_json(boom_routes, api):
    resp = api.request("GET", "/_test/runtime")

    err = assert_error(resp, 500, "INTERNAL_ERROR")
    assert err["message"]


def test_unexpected_exception_does_not_leak_exception_details(boom_routes, api):
    text = api.request("GET", "/_test/runtime").get_data(as_text=True)

    for leaked in (SECRET, "RuntimeError", "Traceback", "boom_routes", ".py"):
        assert leaked not in text


def test_request_after_unexpected_exception_works_with_clean_session(
    boom_routes, api, owner_user, client_user
):
    cid = api.create_ok(owner_user)["id"]
    api.request("GET", "/_test/runtime")

    resp = api.get(cid, client_user)

    assert resp.status_code == 200
    assert resp.get_json()["id"] == cid


def test_database_operational_error_returns_503_service_unavailable(boom_routes, api):
    resp = api.request("GET", "/_test/operational")

    err = assert_error(resp, 503, "SERVICE_UNAVAILABLE")
    assert err["message"]


def test_database_operational_error_does_not_leak_sql_or_driver_details(boom_routes, api):
    text = api.request("GET", "/_test/operational").get_data(as_text=True)

    for leaked in (SECRET, "secret_column", "secret_table", "OperationalError", "host=db"):
        assert leaked not in text


def test_request_after_database_operational_error_works(boom_routes, api, owner_user, client_user):
    cid = api.create_ok(owner_user)["id"]
    api.request("GET", "/_test/operational")

    assert api.get(cid, client_user).status_code == 200
