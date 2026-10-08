"""Red team F1 : creation, consultation, signature et annulation d'un contrat.

Chaque test est une attaque et affirme le comportement SUR attendu : erreur 4xx propre au format
{"error": {"code", "message"}}, jamais de 500, et (statut, version, nombre d'evenements) inchanges.
Un test rouge ici = une faille trouvee (voir docs/audits/adversarial-2026-10-08.md). Pas de skip/xfail.

Les caracteres non ASCII sont ecrits en echappement (\\N{...}, \\x.., \\U........ ou chr()) : aucun
caractere invisible ou ambigu n'apparait en clair dans ce fichier.
"""

import hashlib
import itertools
import json
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.fixtures.helpers import VALID_BODY, Api, TestUser, assert_error, count_rows, new_key, snapshot

pytestmark = pytest.mark.adversarial

TABLES = ("Contract", "EscrowEvent", "IdempotencyKey")
EMPTY_COUNTS = {"Contract": 0, "EscrowEvent": 0, "IdempotencyKey": 0}
ARABIC_DIGITS = str.maketrans("0123456789", "".join(chr(0x660 + i) for i in range(10)))
FULLWIDTH_DIGITS = str.maketrans("0123456789", "".join(chr(0xFF10 + i) for i in range(10)))
FULLWIDTH_ALNUM = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "".join(chr(0xFF21 + i) for i in range(26)) + "".join(chr(0xFF10 + i) for i in range(10)),
)


# --- outils ---------------------------------------------------------------------------------------


def u(*codepoints: int) -> str:
    """Construit une chaine a partir de points de code (evite tout caractere non ASCII en clair)."""
    return "".join(chr(cp) for cp in codepoints)


def counts(app) -> dict[str, int]:
    return {name: count_rows(app, name) for name in TABLES}


def raw_body(**overrides: str) -> str:
    """VALID_BODY serialise, avec certains champs remplaces par un litteral JSON brut."""
    body: dict[str, Any] = dict(VALID_BODY)
    for name in overrides:
        body[name] = f"__RAW_{name}__"
    text = json.dumps(body)
    for name, literal in overrides.items():
        text = text.replace(f'"__RAW_{name}__"', literal)
    return text


def create_raw(api: Api, user: TestUser, raw: str | bytes, content_type: str = "application/json"):
    path = "/api/contracts"
    return api.request("POST", path, user, raw=raw, content_type=content_type, idem=new_key())


def post_with_content_type(api: Api, path: str, user: TestUser, data: str | bytes, content_type: str):
    """POST brut avec un Content-Type exact (vide = aucun en-tete), sans le defaut JSON du helper."""
    headers = {**user.headers, "Idempotency-Key": new_key()}
    ctype = content_type or None
    return api.http.open(path, method="POST", data=data, headers=headers, content_type=ctype)


def assert_never_500(resp) -> None:
    assert resp.status_code < 500, f"{resp.status_code}: {resp.get_data(as_text=True)[:300]}"


def assert_chain_coherent(api: Api, cid: str, user: TestUser) -> list[dict[str, Any]]:
    """Version == nombre d'evenements ; chaque evenement part de l'etat d'arrivee du precedent."""
    status, version, n_events = snapshot(api, cid, user)
    events = api.events(cid, user).get_json()["events"]
    assert version == n_events == len(events)
    assert events[0]["event"] == "create"
    assert events[0]["from_status"] is None
    for previous, current in itertools.pairwise(events):
        assert current["from_status"] == previous["to_status"], events
    assert events[-1]["to_status"] == status
    return events


def run_concurrently(app, jobs: list[Callable[[Api], Any]]) -> list[Any]:
    barrier = threading.Barrier(len(jobs))

    def worker(job: Callable[[Api], Any]) -> Any:
        local = Api(app)
        barrier.wait(timeout=15)
        return job(local)

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(worker, job) for job in jobs]
        return [f.result(timeout=60) for f in futures]


@pytest.fixture
def contract(api, owner_user, client_user) -> str:
    return api.create_ok(owner_user)["id"]


@pytest.fixture
def other_owner(make_user) -> TestUser:
    return make_user("owner", email="other-owner@demo.test")


# ==================================================================================================
# 1. Montants pieges
# ==================================================================================================

AMOUNT_LITERALS = {
    "negatif": "-1",
    "zero": "0",
    "moins_zero": "-0",
    "demi": "0.5",
    "entier_decimal": "2500000.0",
    "un_point_zero": "1.0",
    "exposant": "1e2",
    "chaine": '"100"',
    "chaine_vide": '""',
    "chaine_nan": '"NaN"',
    "1e309": "1e309",
    "moins_1e309": "-1e309",
    "2_puissance_63": str(2**63),
    "moins_2_puissance_63": str(-(2**63)),
    "2_puissance_64": str(2**64),
    "5000_chiffres": "9" * 5000,
    "true": "true",
    "false": "false",
    "null": "null",
    "plafond_plus_un": "50000001",
    "NaN": "NaN",
    "Infinity": "Infinity",
    "moins_Infinity": "-Infinity",
    "liste": "[2500000]",
    "objet": '{"amount": 2500000}',
    "hexa": "0x10",
    "zero_initial": "02500000",
    "plus": "+2500000",
}


@pytest.mark.parametrize("literal", AMOUNT_LITERALS.values(), ids=AMOUNT_LITERALS.keys())
def test_trapped_amount_is_refused_with_422(app, api, owner_user, client_user, literal):
    before = counts(app)

    resp = create_raw(api, owner_user, raw_body(deposit_cents=literal))

    assert_error(resp, 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})
    assert counts(app) == before


def test_typed_but_wrong_amount_reports_invalid_amount_code(app, api, owner_user, client_user):
    for literal in ("-1", "0", "0.5", '"100"', "true", "null", "50000001", str(2**63)):
        resp = create_raw(api, owner_user, raw_body(deposit_cents=literal))
        assert_error(resp, 422, "INVALID_AMOUNT")
    assert count_rows(app, "Contract") == 0


def test_missing_amount_is_refused(app, api, owner_user, client_user):
    body = {k: v for k, v in VALID_BODY.items() if k != "deposit_cents"}

    resp = api.create(owner_user, body)

    assert_error(resp, 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})
    assert counts(app) == EMPTY_COUNTS


def test_ceiling_amount_is_accepted_and_returned_as_exact_integer(api, owner_user, client_user):
    data = api.create_ok(owner_user, {**VALID_BODY, "deposit_cents": 50_000_000})

    assert data["deposit"]["amount_cents"] == 50_000_000
    assert type(data["deposit"]["amount_cents"]) is int


@pytest.mark.parametrize(
    "currency",
    [
        '"XXX"',
        '"eur"',
        '"EUR "',
        '" EUR"',
        '"EURO"',
        '"\\u20ac"',
        '""',
        "null",
        "978",
        '["EUR"]',
        '"BTC"',
        '"E\\u0000R"',
    ],
)
def test_unknown_currency_is_refused(app, api, owner_user, client_user, currency):
    resp = create_raw(api, owner_user, raw_body(currency=currency))

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


# ==================================================================================================
# 2. Acces : usurpation de role, IDOR (y compris /events), sans authentification
# ==================================================================================================


def test_client_cannot_create_a_contract_posing_as_owner(app, api, owner_user, client_user):
    body = {**VALID_BODY, "client_email": "client@demo.test", "owner_id": owner_user.id}
    for payload in (VALID_BODY, body, {**VALID_BODY, "client_email": owner_user.email}):
        resp = api.create(client_user, payload)
        assert_error(resp, 403, "FORBIDDEN_ACTOR")
    assert count_rows(app, "Contract") == 0


def test_client_cannot_provide_the_owner_signature(api, contract, owner_user, client_user):
    assert api.sign(contract, client_user).status_code == 200
    before = snapshot(api, contract, owner_user)

    # deuxieme signature du client, avec des en-tetes et un corps qui pretendent agir pour le loueur
    resp = api.request(
        "POST",
        f"/api/contracts/{contract}/sign",
        client_user,
        body={"party": "owner", "actor_id": owner_user.id, "as": "owner"},
        idem=new_key(),
        headers={
            "X-User-Id": owner_user.id,
            "X-Act-As": "owner",
            "X-Forwarded-User": owner_user.email,
        },
    )

    assert_error(resp, 409, "INVALID_TRANSITION")
    assert snapshot(api, contract, owner_user) == before
    data = api.get(contract, owner_user).get_json()
    assert data["status"] == "DRAFT"
    assert data["signatures"]["owner"] is None


ROUTES = [("GET", ""), ("GET", "/events"), ("POST", "/sign"), ("POST", "/cancel")]


@pytest.mark.parametrize("intruder", ["stranger_user", "other_owner", "admin_user"])
@pytest.mark.parametrize(("method", "suffix"), ROUTES)
def test_idor_on_another_contract_is_404_and_indistinguishable(
    request, app, api, contract, owner_user, intruder, method, suffix
):
    attacker: TestUser = request.getfixturevalue(intruder)
    before = snapshot(api, contract, owner_user)
    before_counts = counts(app)

    resp = api.request(method, f"/api/contracts/{contract}{suffix}", attacker, idem=new_key())
    ghost = api.request(method, f"/api/contracts/{uuid.uuid4()}{suffix}", attacker, idem=new_key())

    assert_error(resp, 404, "NOT_FOUND")
    assert resp.get_data() == ghost.get_data()
    assert dict(resp.headers) == dict(ghost.headers)
    assert snapshot(api, contract, owner_user) == before
    assert counts(app) == before_counts


def test_idor_with_cancel_body_and_reused_key_of_victim(app, api, contract, owner_user, stranger_user):
    key = new_key()
    assert api.sign(contract, owner_user, idem=key).status_code == 200
    before = snapshot(api, contract, owner_user)

    # l'attaquant rejoue la cle d'idempotence du loueur : ne doit ni rejouer sa reponse ni agir
    for action in ("sign", "cancel"):
        resp = api.request("POST", f"/api/contracts/{contract}/{action}", stranger_user, idem=key)
        assert_error(resp, 404, "NOT_FOUND")
        assert contract not in resp.get_data(as_text=True)

    assert snapshot(api, contract, owner_user) == before


def test_other_owner_reusing_victim_creation_key_gets_own_contract_not_victim_replay(
    app, api, owner_user, client_user, other_owner
):
    key = new_key()
    victim = api.create(owner_user, idem=key)
    assert victim.status_code == 201

    resp = api.create(other_owner, idem=key)

    assert resp.status_code == 201, resp.get_data(as_text=True)
    assert resp.get_json()["id"] != victim.get_json()["id"]
    assert resp.get_json()["owner"]["id"] == other_owner.id
    assert_error(api.get(victim.get_json()["id"], other_owner), 404, "NOT_FOUND")


def _alias_ids(cid: str) -> dict[str, str]:
    return {
        "majuscules": cid.upper(),
        "accolades": "{" + cid + "}",
        "urn": "urn:uuid:" + cid,
        "sans_tirets": cid.replace("-", ""),
        "chiffres_arabes": cid.translate(ARABIC_DIGITS),
    }


def test_stranger_using_alias_forms_of_the_uuid_still_gets_404(api, contract, owner_user, stranger_user):
    before = snapshot(api, contract, owner_user)

    for alias in _alias_ids(contract).values():
        for method, suffix in ROUTES:
            resp = api.request(method, f"/api/contracts/{alias}{suffix}", stranger_user, idem=new_key())
            assert_error(resp, 404, "NOT_FOUND")

    assert snapshot(api, contract, owner_user) == before


def test_alias_forms_of_the_uuid_never_break_the_party(api, contract, owner_user):
    for alias in _alias_ids(contract).values():
        resp = api.get(alias, owner_user)
        assert_never_500(resp)
        if resp.status_code == 200:
            assert resp.get_json()["id"] == contract
        else:
            assert_error(resp, 404, "NOT_FOUND")


WEIRD_IDS = [
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "null",
    "undefined",
    "0",
    "-1",
    "%20",
    "%00",
    "%2e%2e",
    "..%2F..%2Fetc%2Fpasswd",
    "%27%20OR%20%271%27%3D%271",
    "1;DROP%20TABLE%20contracts",
    "a" * 5000,
    "\N{ARABIC-INDIC DIGIT ONE}" * 32,
    "1_" + "0" * 30,
    "+" + "0" * 31,
    "{}",
    "urn:uuid:",
    "%F0%9F%9A%97",
    "%ff%fe",
]


@pytest.mark.parametrize("bad_id", WEIRD_IDS, ids=range(len(WEIRD_IDS)))
@pytest.mark.parametrize(("method", "suffix"), ROUTES)
def test_weird_ids_in_url_are_clean_404(app, api, contract, owner_user, bad_id, method, suffix):
    before = snapshot(api, contract, owner_user)

    resp = api.request(method, f"/api/contracts/{bad_id}{suffix}", owner_user, idem=new_key())

    assert_error(resp, 404)
    assert snapshot(api, contract, owner_user) == before


# --- en-tetes Authorization tordus ----------------------------------------------------------------

AUTH_VARIANTS: dict[str, Callable[[str], str]] = {
    "vide": lambda t: "",
    "schema_seul": lambda t: "Bearer",
    "schema_espace": lambda t: "Bearer ",
    "jeton_sans_schema": lambda t: t,
    "double_schema": lambda t: f"Bearer Bearer {t}",
    "basic": lambda t: f"Basic {t}",
    "token": lambda t: f"Token {t}",
    "virgule": lambda t: f"Bearer {t},",
    "deux_jetons": lambda t: f"Bearer {t} {t}",
    "hash_vole": lambda t: f"Bearer {hashlib.sha256(t.encode()).hexdigest()}",
    "prefixe": lambda t: f"Bearer {t[:-1]}",
    "suffixe": lambda t: f"Bearer {t}x",
    "casse": lambda t: f"Bearer {t.swapcase()}",
    "null": lambda t: "Bearer null",
    "undefined": lambda t: "Bearer undefined",
    "sql": lambda t: "Bearer '||'1'='1",
    "sql_like": lambda t: "Bearer %",
    "latin1": lambda t: f"Bearer {t}\xe9",
    "del": lambda t: f"Bearer {t}\x7f",
    "enorme": lambda t: "Bearer " + "A" * 20_000,
    "257_caracteres": lambda t: "Bearer " + (t * 10)[:257],
}


@pytest.mark.parametrize("variant", AUTH_VARIANTS.values(), ids=AUTH_VARIANTS.keys())
def test_twisted_authorization_headers_are_401(app, api, contract, owner_user, client_user, variant):
    header = variant(owner_user.token)
    before = snapshot(api, contract, owner_user)
    before_counts = counts(app)

    for method, path, body in (
        ("POST", "/api/contracts", VALID_BODY),
        ("GET", f"/api/contracts/{contract}", None),
        ("GET", f"/api/contracts/{contract}/events", None),
        ("POST", f"/api/contracts/{contract}/sign", None),
        ("POST", f"/api/contracts/{contract}/cancel", None),
    ):
        resp = api.request(method, path, body=body, idem=new_key(), headers={"Authorization": header})
        err = assert_error(resp, 401, "UNAUTHENTICATED")
        assert owner_user.token not in json.dumps(err)

    assert snapshot(api, contract, owner_user) == before
    assert counts(app) == before_counts


def test_lowercase_scheme_is_accepted_and_does_not_change_identity(api, contract, owner_user):
    headers = {"Authorization": f"bearer {owner_user.token}"}

    resp = api.request("GET", f"/api/contracts/{contract}", headers=headers)

    assert resp.status_code == 200
    assert resp.get_json()["owner"]["id"] == owner_user.id


# ==================================================================================================
# 3. Flux : double signature, apres annulation, rejeu
# ==================================================================================================


@pytest.mark.parametrize("actor", ["owner_user", "client_user"])
def test_double_signature_same_party_is_409_and_state_unchanged(request, api, contract, owner_user, actor):
    user = request.getfixturevalue(actor)
    assert api.sign(contract, user).status_code == 200
    before = snapshot(api, contract, owner_user)

    for _ in range(3):
        assert_error(api.sign(contract, user), 409, "INVALID_TRANSITION")

    assert snapshot(api, contract, owner_user) == before == ("DRAFT", 2, 2)


def test_single_signature_never_reaches_awaiting_deposit(api, contract, owner_user, client_user):
    assert api.sign(contract, owner_user).status_code == 200

    data = api.get(contract, client_user).get_json()

    assert data["status"] == "DRAFT"
    assert data["signatures"]["client"] is None


@pytest.mark.parametrize("signers", [[], ["owner_user"], ["owner_user", "client_user"]])
@pytest.mark.parametrize("canceller", ["owner_user", "client_user"])
def test_sign_and_cancel_after_cancellation_are_409(request, api, contract, owner_user, signers, canceller):
    for name in signers:
        assert api.sign(contract, request.getfixturevalue(name)).status_code == 200
    assert api.cancel(contract, request.getfixturevalue(canceller)).status_code == 200
    before = snapshot(api, contract, owner_user)
    assert before[0] == "CANCELLED"

    for name in ("owner_user", "client_user"):
        user = request.getfixturevalue(name)
        assert_error(api.sign(contract, user), 409, "INVALID_TRANSITION")
        assert_error(api.cancel(contract, user), 409, "INVALID_TRANSITION")
        assert_error(api.cancel(contract, user, body={"reason": "encore"}), 409, "INVALID_TRANSITION")

    assert snapshot(api, contract, owner_user) == before
    assert_chain_coherent(api, contract, owner_user)


def test_sign_after_awaiting_deposit_is_409(api, contract, owner_user, client_user):
    api.sign(contract, owner_user)
    api.sign(contract, client_user)
    before = snapshot(api, contract, owner_user)

    for user in (owner_user, client_user):
        assert_error(api.sign(contract, user), 409, "INVALID_TRANSITION")

    assert snapshot(api, contract, owner_user) == before == ("AWAITING_DEPOSIT", 3, 3)


def test_replay_without_idempotency_key_never_applies_twice(api, contract, owner_user):
    first = api.request("POST", f"/api/contracts/{contract}/sign", owner_user)
    second = api.request("POST", f"/api/contracts/{contract}/sign", owner_user)

    assert first.status_code == 200
    assert_error(second, 409, "INVALID_TRANSITION")
    assert snapshot(api, contract, owner_user) == ("DRAFT", 2, 2)


def test_replaying_an_old_sign_key_after_cancellation_changes_nothing(api, contract, owner_user, client_user):
    key = new_key()
    first = api.sign(contract, owner_user, idem=key)
    assert api.cancel(contract, client_user).status_code == 200
    before = snapshot(api, contract, owner_user)

    replay = api.sign(contract, owner_user, idem=key)

    assert replay.status_code == 200
    assert replay.get_json() == first.get_json()
    assert snapshot(api, contract, owner_user) == before
    assert before[0] == "CANCELLED"


def test_replaying_creation_key_after_cancellation_does_not_resurrect(app, api, owner_user, client_user):
    key = new_key()
    created = api.create(owner_user, idem=key).get_json()
    api.cancel(created["id"], owner_user)

    replay = api.create(owner_user, idem=key)

    assert replay.status_code == 201
    assert count_rows(app, "Contract") == 1
    assert api.get(created["id"], owner_user).get_json()["status"] == "CANCELLED"


# --- modification interdite (PATCH / PUT / DELETE) ------------------------------------------------

MUTATION = {"status": "AWAITING_DEPOSIT", "deposit_cents": 1, "version": 99, "client_email": "x@demo.test"}


@pytest.mark.parametrize("method", ["PATCH", "PUT", "DELETE"])
@pytest.mark.parametrize("suffix", ["", "/sign", "/cancel", "/events"])
@pytest.mark.parametrize("as_who", ["owner_user", "client_user", None])
def test_modification_methods_are_405_json_and_contract_unchanged(
    request, api, contract, owner_user, method, suffix, as_who
):
    user = request.getfixturevalue(as_who) if as_who else None
    api.sign(contract, owner_user)
    before = api.get(contract, owner_user).get_json()

    resp = api.request(method, f"/api/contracts/{contract}{suffix}", user, body=MUTATION, idem=new_key())

    if user is None:
        assert_error(resp, resp.status_code, codes={"METHOD_NOT_ALLOWED", "UNAUTHENTICATED"})
        assert resp.status_code in {401, 405}
    else:
        assert_error(resp, 405, "METHOD_NOT_ALLOWED")
        allow = resp.headers.get("Allow", "")
        assert "POST" in allow or "GET" in allow
    assert api.get(contract, owner_user).get_json() == before


@pytest.mark.parametrize("method", ["PATCH", "PUT", "DELETE", "GET"])
def test_collection_mutation_is_405(app, api, owner_user, client_user, method):
    resp = api.request(method, "/api/contracts", owner_user, body=VALID_BODY, idem=new_key())

    assert_error(resp, 405, "METHOD_NOT_ALLOWED")
    assert count_rows(app, "Contract") == 0


@pytest.mark.parametrize("override", ["PATCH", "PUT", "DELETE"])
def test_method_override_headers_are_ignored(app, api, contract, owner_user, override):
    before = api.get(contract, owner_user).get_json()

    resp = api.request(
        "POST",
        f"/api/contracts/{contract}/sign",
        owner_user,
        body=MUTATION,
        idem=new_key(),
        headers={"X-HTTP-Method-Override": override, "X-Method-Override": override},
    )

    assert resp.status_code == 200
    after = resp.get_json()
    assert after["deposit"] == before["deposit"]
    assert after["status"] == "DRAFT"
    assert after["version"] == 2


# ==================================================================================================
# 4. Mass assignment
# ==================================================================================================

MASS_FIELDS = {
    "status": "RELEASED",
    "version": 99,
    "owner_id": str(uuid.uuid4()),
    "client_id": str(uuid.uuid4()),
    "id": str(uuid.uuid4()),
    "owner_signed_at": "2026-01-01T00:00:00Z",
    "client_signed_at": "2026-01-01T00:00:00Z",
    "signatures": {"owner": "2026-01-01T00:00:00Z", "client": "2026-01-01T00:00:00Z"},
    "created_at": "2000-01-01T00:00:00Z",
    "role": "admin",
    "__class__": "Contract",
    "deposit": {"amount_cents": 1, "currency": "EUR"},
}


@pytest.mark.parametrize(("field", "value"), MASS_FIELDS.items(), ids=MASS_FIELDS.keys())
def test_mass_assignment_on_create_is_refused(app, api, owner_user, client_user, field, value):
    resp = api.create(owner_user, {**VALID_BODY, field: value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert counts(app) == EMPTY_COUNTS


def test_mass_assignment_via_query_string_is_ignored(app, api, owner_user, client_user, other_owner):
    query = f"status=RELEASED&version=99&owner_id={other_owner.id}&deposit_cents=1"

    resp = api.request("POST", f"/api/contracts?{query}", owner_user, body=VALID_BODY, idem=new_key())

    assert resp.status_code == 201
    data = resp.get_json()
    assert (data["status"], data["version"]) == ("DRAFT", 1)
    assert data["owner"]["id"] == owner_user.id
    assert data["deposit"]["amount_cents"] == VALID_BODY["deposit_cents"]


def test_mass_assignment_on_sign_body_is_not_applied(api, contract, owner_user, client_user):
    body = {**MASS_FIELDS, "status": "AWAITING_DEPOSIT"}

    resp = api.request("POST", f"/api/contracts/{contract}/sign", client_user, body=body, idem=new_key())

    assert resp.status_code in {200, 422}
    data = api.get(contract, owner_user).get_json()
    assert data["status"] == "DRAFT"
    assert data["signatures"]["owner"] is None
    assert data["deposit"]["amount_cents"] == VALID_BODY["deposit_cents"]


@pytest.mark.parametrize("field", ["status", "version", "owner_id", "refund", "actor"])
def test_mass_assignment_on_cancel_body_is_refused(api, contract, owner_user, field):
    before = snapshot(api, contract, owner_user)

    resp = api.cancel(contract, owner_user, body={"reason": "ok", field: "DRAFT"})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snapshot(api, contract, owner_user) == before


# ==================================================================================================
# 5. Entrees : JSON malforme, Content-Type mensonger, corps geant, champs en trop, injection SQL
# ==================================================================================================

MALFORMED = {
    "vide": b"",
    "espaces": b"   \n\t ",
    "tronque": b'{"client_email": "client@demo.test", ',
    "garbage_apres": json.dumps(VALID_BODY).encode() + b" garbage",
    "deux_objets": json.dumps(VALID_BODY).encode() * 2,
    "commentaire": b'{/* x */"a": 1}',
    "quotes_simples": b"{'a': 1}",
    "virgule_finale": b'{"a": 1,}',
    "null": b"null",
    "tableau": b"[]",
    "chaine": b'"x"',
    "nombre": b"42",
    "utf8_invalide": b'{"vehicle_label": "\xff\xfe\xc3\x28"}',
    "imbrication_profonde": b'{"vehicle_label": ' + b"[" * 200_000 + b"]" * 200_000 + b"}",
    "imbrication_moyenne": b'{"x": ' + b'{"a":' * 900 + b"1" + b"}" * 900 + b"}",
    "xml": b"<?xml version='1.0'?><contract/>",
    "formulaire": b"client_email=client%40demo.test&deposit_cents=1",
    "nul": b"\x00" * 64,
}


@pytest.mark.parametrize("raw", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_json_on_create_is_422(app, api, owner_user, client_user, raw):
    resp = create_raw(api, owner_user, raw)

    # un objet JSON valide sans deposit_cents remonte INVALID_AMOUNT (montant absent) : tolere par le plan
    assert_error(resp, 422, codes={"VALIDATION_ERROR", "INVALID_AMOUNT"})
    assert count_rows(app, "Contract") == 0


@pytest.mark.parametrize("raw", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_json_on_cancel_never_cancels(api, contract, owner_user, raw):
    before = snapshot(api, contract, owner_user)

    resp = api.request("POST", f"/api/contracts/{contract}/cancel", owner_user, raw=raw, idem=new_key())

    assert_never_500(resp)
    if raw.strip():
        assert_error(resp, 422, "VALIDATION_ERROR")
        assert snapshot(api, contract, owner_user) == before
    else:
        assert resp.status_code == 200  # corps vide = pas de motif, annulation legitime


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "text/html",
        "application/xml",
        "application/javascript",
        "",
        "application/jsonp",
        "json",
        "application/json-patch",
    ],
)
def test_lying_content_type_with_valid_json_is_refused(app, api, owner_user, client_user, content_type):
    resp = post_with_content_type(api, "/api/contracts", owner_user, json.dumps(VALID_BODY), content_type)

    assert_error(resp, resp.status_code, codes={"VALIDATION_ERROR", "UNSUPPORTED_MEDIA_TYPE"})
    assert resp.status_code in {415, 422}
    assert count_rows(app, "Contract") == 0


LATIN1_BODY = json.dumps({**VALID_BODY, "vehicle_label": "Citro\xebn"}, ensure_ascii=False).encode("latin-1")


@pytest.mark.parametrize(
    ("content_type", "raw"),
    [
        ("application/json; charset=utf-16", json.dumps(VALID_BODY).encode()),
        ("application/json", json.dumps(VALID_BODY).encode("utf-16")),
        ("application/json", b"\xef\xbb\xbf" + json.dumps(VALID_BODY).encode()),
        ("APPLICATION/JSON", json.dumps(VALID_BODY).encode()),
        ("application/vnd.evil+json", json.dumps(VALID_BODY).encode()),
        ("application/json; charset=latin-1", LATIN1_BODY),
    ],
    ids=["charset_menteur", "utf16_bom", "utf8_bom", "majuscules", "suffixe_json", "latin1"],
)
def test_odd_but_plausible_encodings_never_500(app, api, owner_user, client_user, content_type, raw):
    resp = post_with_content_type(api, "/api/contracts", owner_user, raw, content_type)

    assert_never_500(resp)
    if resp.status_code == 201:
        assert resp.get_json()["status"] == "DRAFT"
    else:
        assert_error(resp, 422, "VALIDATION_ERROR")
        assert count_rows(app, "Contract") == 0


def test_body_above_10_mb_is_413_json_on_create_and_cancel(app, api, contract, owner_user, client_user):
    before = snapshot(api, contract, owner_user)
    huge = json.dumps({**VALID_BODY, "vehicle_label": "A" * (11 * 1024 * 1024)})

    assert_error(create_raw(api, owner_user, huge), 413)
    resp = api.request("POST", f"/api/contracts/{contract}/cancel", owner_user, raw=huge, idem=new_key())
    assert_error(resp, 413)

    assert snapshot(api, contract, owner_user) == before
    assert count_rows(app, "Contract") == 1


def test_huge_body_on_sign_never_500(api, contract, owner_user):
    huge = b"x" * (11 * 1024 * 1024)

    resp = api.request("POST", f"/api/contracts/{contract}/sign", owner_user, raw=huge, idem=new_key())

    assert_never_500(resp)
    assert resp.status_code in {200, 413}
    expected_version = 2 if resp.status_code == 200 else 1
    assert snapshot(api, contract, owner_user)[1] == expected_version


@pytest.mark.parametrize("field", ["vehicle_label", "vehicle_plate", "client_email", "currency"])
def test_one_megabyte_string_is_422_and_not_echoed(app, api, owner_user, client_user, field):
    marker = "Z" * 64
    big = marker + "Q" * (1024 * 1024)

    resp = api.create(owner_user, {**VALID_BODY, field: big})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert marker not in resp.get_data(as_text=True)
    assert count_rows(app, "Contract") == 0


def test_one_megabyte_cancel_reason_is_422(api, contract, owner_user):
    before = snapshot(api, contract, owner_user)

    resp = api.cancel(contract, owner_user, body={"reason": "r" * (1024 * 1024)})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snapshot(api, contract, owner_user) == before


def test_many_extra_fields_do_not_produce_unbounded_error_payload(app, api, owner_user, client_user):
    """Amplification : N champs en trop => N erreurs renvoyees. Le corps d'erreur doit etre borne."""
    body = dict(VALID_BODY)
    body.update({f"k{i}": 0 for i in range(20_000)})
    request_size = len(json.dumps(body))

    resp = api.create(owner_user, body)

    err = assert_error(resp, 422, "VALIDATION_ERROR")
    response_size = len(resp.get_data())
    assert len(err.get("details", {}).get("errors", [])) <= 50, "liste d'erreurs non bornee"
    assert response_size < 64 * 1024, f"reponse de {response_size} o pour {request_size} o envoyes"
    assert count_rows(app, "Contract") == 0


def test_giant_unknown_key_name_is_not_reflected_in_error(app, api, owner_user, client_user):
    giant_key = "<script>alert(1)</script>" + "K" * (1024 * 1024)

    resp = api.create(owner_user, {**VALID_BODY, giant_key: 1})

    assert_error(resp, 422, "VALIDATION_ERROR")
    size = len(resp.get_data())
    assert size < 64 * 1024, f"cle reflechie : reponse de {size} octets"
    assert "<script>" not in resp.get_data(as_text=True)
    assert count_rows(app, "Contract") == 0


SQLI = [
    "'; DROP TABLE contracts; --",
    "' OR '1'='1",
    "Robert'); DELETE FROM escrow_events;--",
    "1; UPDATE contracts SET status='RELEASED'",
    "\\'; SELECT pg_sleep(5); --",
    "$$; DROP TABLE users; $$",
]


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_in_texts_is_stored_verbatim(app, api, owner_user, client_user, payload):
    label = payload[:120]
    data = api.create_ok(owner_user, {**VALID_BODY, "vehicle_label": label})

    assert data["vehicle"]["label"] == label
    assert api.get(data["id"], client_user).get_json()["vehicle"]["label"] == label
    assert counts(app) == {"Contract": 1, "EscrowEvent": 1, "IdempotencyKey": 1}

    plate = api.create(owner_user, {**VALID_BODY, "vehicle_plate": payload[:16]})
    assert_never_500(plate)
    reason = api.cancel(data["id"], owner_user, body={"reason": payload})
    assert reason.status_code == 200
    assert_chain_coherent(api, data["id"], owner_user)


@pytest.mark.parametrize(
    "email",
    [
        "x'--@demo.test",
        "client@demo.test'--",
        "'or'1'='1@a.b",
        "%@demo.test",
        "_lient@demo.test",
        "client@demo.test%00",
        "*@*.*",
    ],
)
def test_sql_or_like_injection_in_client_email_resolves_nobody(app, api, owner_user, client_user, email):
    resp = api.create(owner_user, {**VALID_BODY, "client_email": email})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


def test_client_email_errors_do_not_enumerate_accounts(
    app, api, owner_user, client_user, admin_user, other_owner
):
    bodies = []
    for email in ("nobody@demo.test", admin_user.email, other_owner.email, owner_user.email):
        resp = api.create(owner_user, {**VALID_BODY, "client_email": email})
        assert_error(resp, 422, "VALIDATION_ERROR")
        bodies.append(resp.get_data())

    assert len(set(bodies)) == 1, "le message differe selon que le compte existe ou non"


# --- unicode, caracteres de controle, NUL ---------------------------------------------------------

CONTROL_VALUES = {
    "nul": "Audi\x00RS6",
    "nul_seul": "\x00",
    "bell": "Audi\x07",
    "escape_ansi": "\x1b[31mAudi",
    "retour_chariot": "Audi\r\nX-Injected: 1",
    "nel_interne": "Au\x85di",  # en fin de chaine, NEL est un espace Unicode et serait simplement retire
    "surrogate_seul": "Audi" + chr(0xD800),
    "surrogate_bas": chr(0xDFFF),
    "espaces_unicode_seuls": "\N{IDEOGRAPHIC SPACE}\xa0\N{EM SPACE}",
    "tabulations": "\t\t",
}


@pytest.mark.parametrize("field", ["vehicle_label", "vehicle_plate"])
@pytest.mark.parametrize("value", CONTROL_VALUES.values(), ids=CONTROL_VALUES.keys())
def test_control_chars_and_blank_texts_are_refused(app, api, owner_user, client_user, field, value):
    resp = api.create(owner_user, {**VALID_BODY, field: value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert counts(app) == EMPTY_COUNTS


@pytest.mark.parametrize("value", ["a\x00", chr(0xD800), "\x1b[2J", "a\rb"])
def test_control_chars_in_cancel_reason_are_refused(api, contract, owner_user, value):
    before = snapshot(api, contract, owner_user)

    resp = api.cancel(contract, owner_user, body={"reason": value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snapshot(api, contract, owner_user) == before


LEGIT_LABELS = {
    "emoji": "Lamborghini \U0001f697\U0001f525",
    "arabe": u(0x645, 0x631, 0x633, 0x64A, 0x62F, 0x633),
    "chinois": u(0x4FDD, 0x65F6, 0x6377) + " 911",
    "120_emoji": "\U0001f697" * 120,
    "combinants": "Za\N{COMBINING DIAERESIS}\N{COMBINING ACUTE ACCENT}hlung",
    "replacement": "\N{REPLACEMENT CHARACTER}" * 2,
}


@pytest.mark.parametrize("label", LEGIT_LABELS.values(), ids=LEGIT_LABELS.keys())
def test_legit_unicode_labels_roundtrip_exactly(api, owner_user, client_user, label):
    data = api.create_ok(owner_user, {**VALID_BODY, "vehicle_label": label})

    assert data["vehicle"]["label"] == label
    assert api.get(data["id"], client_user).get_json()["vehicle"]["label"] == label


def test_121_astral_chars_label_is_refused(app, api, owner_user, client_user):
    resp = api.create(owner_user, {**VALID_BODY, "vehicle_label": "\U0001f697" * 121})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


INVISIBLE = {
    "zero_width_seul": ("vehicle_label", "\N{ZERO WIDTH SPACE}" * 2),
    "joiner_bom_seuls": ("vehicle_label", "\N{WORD JOINER}\N{ZERO WIDTH NO-BREAK SPACE}"),
    "plaque_bidi_rlo": ("vehicle_plate", "\N{RIGHT-TO-LEFT OVERRIDE}DC-321-BA"),
    "label_bidi_isolate": (
        "vehicle_label",
        "Audi RS6 \N{LEFT-TO-RIGHT ISOLATE}\N{RIGHT-TO-LEFT OVERRIDE}0003 x\N{POP DIRECTIONAL ISOLATE}",
    ),
}


@pytest.mark.parametrize(("field", "value"), INVISIBLE.values(), ids=INVISIBLE.keys())
def test_invisible_or_bidi_only_texts_are_refused(app, api, owner_user, client_user, field, value):
    """Les champs signes par les deux parties ne doivent pas etre vides en apparence ni reordonnables
    a l'affichage (Trojan Source : la plaque affichee differe de la plaque stockee)."""
    resp = api.create(owner_user, {**VALID_BODY, field: value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


# --- dates extremes -------------------------------------------------------------------------------

BAD_DATES = {
    "an_0": ("0000-01-01", "0000-01-02"),
    "an_10000": ("9999-12-31", "10000-01-01"),
    "29_fevrier_non_bissextile": ("2027-02-28", "2027-02-29"),
    "30_fevrier": ("2028-02-01", "2028-02-30"),
    "mois_13": ("2026-11-01", "2026-13-01"),
    "jour_0": ("2026-11-00", "2026-11-05"),
    "datetime": ("2026-11-01T00:00:00", "2026-11-05T00:00:00"),
    "fuseau": ("2026-11-01+02:00", "2026-11-05"),
    "semaine_iso": ("2026-W45-1", "2026-W46-1"),
    "compact": ("20261101", "20261105"),
    "sans_zero": ("2026-1-1", "2026-1-5"),
    "chiffres_arabes": ("2026-11-01".translate(ARABIC_DIGITS), "2026-11-05".translate(ARABIC_DIGITS)),
    "chiffres_pleine_chasse": ("2026".translate(FULLWIDTH_DIGITS) + "-11-01", "2026-11-05"),
    "espaces": (" 2026-11-01", "2026-11-05 "),
    "nul": ("2026-11-01\x00", "2026-11-05"),
    "negatif": ("-2026-11-01", "2026-11-05"),
    "egales": ("2026-11-01", "2026-11-01"),
    "inversees": ("2026-11-05", "2026-11-01"),
}


@pytest.mark.parametrize(("start", "end"), BAD_DATES.values(), ids=BAD_DATES.keys())
def test_extreme_or_malformed_dates_are_422(app, api, owner_user, client_user, start, end):
    resp = api.create(owner_user, {**VALID_BODY, "start_date": start, "end_date": end})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


@pytest.mark.parametrize("literal", ["20261101", "null", "true", "[2026, 11, 1]", '{"y": 2026}'])
def test_non_string_dates_are_422(app, api, owner_user, client_user, literal):
    resp = create_raw(api, owner_user, raw_body(start_date=literal))

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ("0001-01-01", "0001-01-02"),
        ("9999-12-30", "9999-12-31"),
        ("2028-02-28", "2028-02-29"),
        ("2028-02-29", "2028-03-01"),
        ("0001-01-01", "9999-12-31"),
    ],
    ids=["an_1", "an_9999", "vers_29_fevrier", "depuis_29_fevrier", "10000_ans"],
)
def test_extreme_but_valid_dates_never_500_and_roundtrip(api, owner_user, client_user, start, end):
    resp = api.create(owner_user, {**VALID_BODY, "start_date": start, "end_date": end})

    assert_never_500(resp)
    if resp.status_code == 201:
        cid = resp.get_json()["id"]
        assert api.get(cid, client_user).get_json()["period"] == {"start": start, "end": end}
        assert_chain_coherent(api, cid, owner_user)
    else:
        assert_error(resp, 422, "VALIDATION_ERROR")


# ==================================================================================================
# 6. Idempotency-Key extremes et reutilisation
# ==================================================================================================

BAD_KEYS = {
    "vide": "",
    "espace": " ",
    "espaces_autour": " abc ",
    "256": "k" * 256,
    "10_ko": "k" * 10_240,
    "latin1": "cl\xe9",
    "euro": "\N{EURO SIGN}",
    "tab": "a\tb",
    "del": "a\x7f",
}


@pytest.mark.parametrize("key", BAD_KEYS.values(), ids=BAD_KEYS.keys())
def test_extreme_idempotency_keys_on_create_are_422(app, api, owner_user, client_user, key):
    resp = api.create(owner_user, idem=None, headers={"Idempotency-Key": key})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert counts(app) == EMPTY_COUNTS


@pytest.mark.parametrize("key", BAD_KEYS.values(), ids=BAD_KEYS.keys())
@pytest.mark.parametrize("action", ["sign", "cancel"])
def test_extreme_idempotency_keys_on_actions_are_422(api, contract, owner_user, key, action):
    before = snapshot(api, contract, owner_user)
    path = f"/api/contracts/{contract}/{action}"

    resp = api.request("POST", path, owner_user, headers={"Idempotency-Key": key})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snapshot(api, contract, owner_user) == before


@pytest.mark.parametrize("key", ["k" * 255, "';DROP/**/TABLE/**/contracts;--", "%_%", "\\x00", "~!@#$%^&*()"])
def test_edge_but_valid_idempotency_keys_work_and_replay(app, api, owner_user, client_user, key):
    first = api.create(owner_user, idem=key)
    second = api.create(owner_user, idem=key)

    assert first.status_code == 201, first.get_data(as_text=True)
    assert second.status_code == 201
    assert second.get_json() == first.get_json()
    assert counts(app) == {"Contract": 1, "EscrowEvent": 1, "IdempotencyKey": 1}


def test_creation_key_reused_on_sign_is_conflict(api, owner_user, client_user):
    key = new_key()
    cid = api.create(owner_user, idem=key).get_json()["id"]

    resp = api.sign(cid, owner_user, idem=key)

    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    assert snapshot(api, cid, owner_user) == ("DRAFT", 1, 1)


def test_sign_key_reused_on_cancel_is_conflict(api, contract, owner_user):
    key = new_key()
    api.sign(contract, owner_user, idem=key)

    resp = api.cancel(contract, owner_user, idem=key)

    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    assert snapshot(api, contract, owner_user) == ("DRAFT", 2, 2)


def test_sign_key_reused_on_another_contract_is_conflict(api, owner_user, client_user):
    first = api.create_ok(owner_user)["id"]
    second = api.create_ok(owner_user)["id"]
    key = new_key()
    api.sign(first, owner_user, idem=key)

    resp = api.sign(second, owner_user, idem=key)

    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    assert snapshot(api, second, owner_user) == ("DRAFT", 1, 1)


def test_cancel_key_reused_with_different_reason_is_conflict(api, contract, owner_user):
    key = new_key()
    api.cancel(contract, owner_user, body={"reason": "a"}, idem=key)

    resp = api.cancel(contract, owner_user, body={"reason": "b"}, idem=key)

    assert_error(resp, 409, "IDEMPOTENCY_CONFLICT")
    assert snapshot(api, contract, owner_user) == ("CANCELLED", 2, 2)


def test_same_key_used_by_both_parties_signs_twice_legitimately(api, contract, owner_user, client_user):
    key = new_key()

    assert api.sign(contract, owner_user, idem=key).status_code == 200
    resp = api.sign(contract, client_user, idem=key)

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "AWAITING_DEPOSIT"
    assert_chain_coherent(api, contract, owner_user)


def test_replayed_key_does_not_bypass_authorization(api, contract, owner_user, client_user, stranger_user):
    """La cle du client rejouee par un tiers (meme valeur) ne doit pas renvoyer la reponse du client."""
    key = new_key()
    original = api.sign(contract, client_user, idem=key)
    assert original.status_code == 200

    resp = api.sign(contract, stranger_user, idem=key)

    assert_error(resp, 404, "NOT_FOUND")
    assert snapshot(api, contract, owner_user) == ("DRAFT", 2, 2)


# ==================================================================================================
# 7. Concurrence
# ==================================================================================================


def test_concurrent_replay_of_same_sign_key_applies_once(app, api, contract, owner_user):
    key = new_key()

    responses = run_concurrently(app, [lambda a: a.sign(contract, owner_user, idem=key)] * 6)

    assert [r.status_code for r in responses] == [200] * 6
    assert len({json.dumps(r.get_json(), sort_keys=True) for r in responses}) == 1
    assert snapshot(api, contract, owner_user) == ("DRAFT", 2, 2)
    assert count_rows(app, "IdempotencyKey") == 2  # creation + signature


def test_concurrent_replay_of_same_creation_key_replays_not_conflicts(app, api, owner_user, client_user):
    key = new_key()

    responses = run_concurrently(app, [lambda a: a.create(owner_user, idem=key)] * 6)

    assert [r.status_code for r in responses] == [201] * 6, [r.get_data(as_text=True) for r in responses]
    assert len({r.get_json()["id"] for r in responses}) == 1
    assert counts(app) == {"Contract": 1, "EscrowEvent": 1, "IdempotencyKey": 1}


def test_concurrent_same_creation_key_with_different_bodies(app, api, owner_user, client_user):
    key = new_key()

    def job_for(amount: int) -> Callable[[Api], Any]:
        return lambda a: a.create(owner_user, {**VALID_BODY, "deposit_cents": amount}, idem=key)

    responses = run_concurrently(app, [job_for(n) for n in range(1000, 1006)])

    codes = sorted(r.status_code for r in responses)
    assert codes == [201, 409, 409, 409, 409, 409]
    for r in responses:
        if r.status_code == 409:
            assert_error(r, 409, "IDEMPOTENCY_CONFLICT")
    assert counts(app) == {"Contract": 1, "EscrowEvent": 1, "IdempotencyKey": 1}


def test_concurrent_same_key_on_two_contracts(app, api, owner_user, client_user):
    first = api.create_ok(owner_user)["id"]
    second = api.create_ok(owner_user)["id"]
    key = new_key()
    jobs = [
        lambda a: a.sign(first, owner_user, idem=key),
        lambda a: a.sign(second, owner_user, idem=key),
    ]

    responses = run_concurrently(app, jobs)

    assert sorted(r.status_code for r in responses) == [200, 409]
    versions = sorted(snapshot(api, cid, owner_user)[1] for cid in (first, second))
    assert versions == [1, 2]


def test_concurrent_cancels_by_both_parties_cancel_once(app, api, contract, owner_user, client_user):
    jobs = [lambda a: a.cancel(contract, owner_user), lambda a: a.cancel(contract, client_user)] * 2

    responses = run_concurrently(app, jobs)

    assert sorted(r.status_code for r in responses) == [200, 409, 409, 409]
    events = assert_chain_coherent(api, contract, owner_user)
    assert [e["event"] for e in events] == ["create", "cancel"]


@pytest.mark.parametrize("pre_signed", [False, True])
def test_concurrent_storm_of_signs_and_cancels_stays_coherent(
    app, api, contract, owner_user, client_user, pre_signed
):
    if pre_signed:
        api.sign(contract, owner_user)
    jobs = (
        [lambda a: a.sign(contract, owner_user)] * 3
        + [lambda a: a.sign(contract, client_user)] * 3
        + [lambda a: a.cancel(contract, owner_user)] * 2
        + [lambda a: a.cancel(contract, client_user)] * 2
    )

    responses = run_concurrently(app, jobs)

    assert all(r.status_code in {200, 409} for r in responses), [r.status_code for r in responses]
    for r in responses:
        if r.status_code == 409:
            assert_error(r, 409, "INVALID_TRANSITION")
    events = assert_chain_coherent(api, contract, owner_user)
    kinds = [e["event"] for e in events]
    assert kinds.count("cancel") == 1
    assert kinds[-1] == "cancel"
    signers = [e["actor_id"] for e in events if e["event"] == "sign_contract"]
    assert len(signers) == len(set(signers)) <= 2
    successes = sum(r.status_code == 200 for r in responses)
    assert successes == len(events) - 1 - (1 if pre_signed else 0)
    assert events[-1]["to_status"] == "CANCELLED"


def test_concurrent_signs_with_cancel_and_idempotency_keys(app, api, contract, owner_user, client_user):
    k_owner, k_client, k_cancel = new_key(), new_key(), new_key()
    jobs = [
        lambda a: a.sign(contract, owner_user, idem=k_owner),
        lambda a: a.sign(contract, owner_user, idem=k_owner),
        lambda a: a.sign(contract, client_user, idem=k_client),
        lambda a: a.sign(contract, client_user, idem=k_client),
        lambda a: a.cancel(contract, client_user, idem=k_cancel),
        lambda a: a.cancel(contract, client_user, idem=k_cancel),
    ]

    responses = run_concurrently(app, jobs)

    assert all(r.status_code in {200, 409} for r in responses)
    # deux requetes portant la meme cle doivent recevoir la meme reponse
    for i in (0, 2, 4):
        left, right = responses[i], responses[i + 1]
        assert left.status_code == right.status_code
        if left.status_code == 200:
            assert left.get_json() == right.get_json()
    events = assert_chain_coherent(api, contract, owner_user)
    assert [e["event"] for e in events].count("cancel") == 1


# ==================================================================================================
# 8. Fuite d'information et forme des erreurs
# ==================================================================================================


def test_responses_never_leak_token_hash_or_emails(app, api, owner_user, client_user):
    created = api.create(owner_user)
    cid = created.get_json()["id"]
    texts = [
        created.get_data(as_text=True),
        api.get(cid, client_user).get_data(as_text=True),
        api.events(cid, client_user).get_data(as_text=True),
    ]

    for text in texts:
        assert "api_token_hash" not in text
        for user in (owner_user, client_user):
            assert hashlib.sha256(user.token.encode()).hexdigest() not in text
            assert user.token not in text
        assert owner_user.email not in text


def test_error_responses_carry_security_headers(api, contract, owner_user, stranger_user):
    for resp in (
        api.get(contract, stranger_user),
        api.sign(contract, None),
        api.request("PATCH", f"/api/contracts/{contract}", owner_user, body={}),
        create_raw(api, owner_user, b"{"),
    ):
        assert resp.status_code >= 400
        assert resp.mimetype == "application/json"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_validation_errors_do_not_echo_submitted_values(app, api, owner_user, client_user):
    secret = "SECRET-VALUE-1234567890"
    fields = ("vehicle_label", "vehicle_plate", "client_email", "currency", "start_date", "deposit_cents")
    for field in fields:
        value = secret * 20 if field != "deposit_cents" else secret
        resp = api.create(owner_user, {**VALID_BODY, field: value})
        assert_error(resp, 422)
        assert secret not in resp.get_data(as_text=True), field


# ==================================================================================================
# 9. Fuzz (hypothesis) : aucune entree ne doit produire de 500 ni un contrat hors invariants
# ==================================================================================================

json_scalars = (
    st.none() | st.booleans() | st.integers(min_value=-(2**70), max_value=2**70) | st.text(max_size=40)
)


def _json_containers(children: st.SearchStrategy[Any]) -> st.SearchStrategy[Any]:
    return st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=8), children, max_size=3)


json_values = st.recursive(json_scalars, _json_containers, max_leaves=8)
FIELDS = [*VALID_BODY.keys(), "status", "version", "extra"]
FUZZ = settings(
    max_examples=120,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)


@FUZZ
@given(field=st.sampled_from(FIELDS), value=json_values, drop=st.booleans())
def test_fuzz_create_one_field_never_500(api, owner_user, client_user, field, value, drop):
    body = dict(VALID_BODY)
    if drop:
        body.pop(field, None)
    else:
        body[field] = value

    resp = api.create(owner_user, body)

    assert_never_500(resp)
    if resp.status_code == 201:
        data = resp.get_json()
        assert data["status"] == "DRAFT"
        assert data["version"] == 1
        assert 1 <= data["deposit"]["amount_cents"] <= 50_000_000
        assert data["deposit"]["currency"] in {"EUR", "CHF", "GBP", "USD"}
        assert data["vehicle"]["label"].strip()
        assert data["period"]["start"] < data["period"]["end"]
    else:
        assert_error(resp, 422)


@FUZZ
@given(body=json_values)
def test_fuzz_create_whole_body_never_500(api, owner_user, client_user, body):
    resp = api.create(owner_user, body if body is not None else {})

    assert_never_500(resp)
    assert_error(resp, 422)


@FUZZ
@given(body=json_values)
def test_fuzz_cancel_body_never_500_and_coherent(api, owner_user, client_user, body):
    cid = api.create_ok(owner_user)["id"]
    path = f"/api/contracts/{cid}/cancel"

    resp = api.request("POST", path, owner_user, raw=json.dumps(body), idem=new_key())

    assert_never_500(resp)
    status = snapshot(api, cid, owner_user)[0]
    if resp.status_code == 200:
        assert status == "CANCELLED"
    else:
        assert_error(resp, 422, "VALIDATION_ERROR")
        assert status == "DRAFT"


header_text = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0xFF, exclude_characters="\x7f"),
    max_size=300,
)


@FUZZ
@given(auth=header_text, key=header_text)
def test_fuzz_headers_never_500(app, api, owner_user, client_user, auth, key):
    headers = {"Authorization": auth, "Idempotency-Key": key}
    resp = api.request("POST", "/api/contracts", body=VALID_BODY, headers=headers)
    assert_error(resp, 401, "UNAUTHENTICATED")

    key_only = {"Idempotency-Key": key}
    resp = api.request("POST", "/api/contracts", owner_user, body=VALID_BODY, headers=key_only)
    assert_never_500(resp)
    assert resp.status_code in {201, 409, 422}
    if resp.status_code != 201:
        assert_error(resp, resp.status_code)


# ==================================================================================================
# 10. Boucle 2 : contournement des correctifs F1-ADV-1 (Cf + has_visible_char) et F1-ADV-2
# ==================================================================================================

# Caracteres qui s'affichent vides mais ne sont PAS de categorie Cf (Lo, So, Mn) : ils echappent a
# has_forbidden_chars, et les Lo/So satisfont meme has_visible_char.
BLANK_LOOKING = {
    "hangul_filler_3164": "\N{HANGUL FILLER}" * 2,
    "hangul_choseong_jungseong_filler": "\N{HANGUL CHOSEONG FILLER}\N{HANGUL JUNGSEONG FILLER}",
    "halfwidth_hangul_filler": "\N{HALFWIDTH HANGUL FILLER}",
    "braille_blank": "\N{BRAILLE PATTERN BLANK}" * 2,
    "filler_plus_selecteur": "\N{HANGUL FILLER}\N{VARIATION SELECTOR-16}",
}
# Temoins : doivent deja etre refuses par le correctif (Zs strippes, Mn seuls, tags Cf).
BLANK_ALREADY_BLOCKED = {
    "espaces_unicode_zs": "\xa0\N{EN QUAD}\N{FOUR-PER-EM SPACE}\N{HAIR SPACE}\N{IDEOGRAPHIC SPACE}",
    "marques_combinantes_seules": "\N{COMBINING ACUTE ACCENT}" * 2,
    "selecteurs_variation_seuls": "\N{VARIATION SELECTOR-1}\N{VARIATION SELECTOR-16}\U000e0100",
    "tags_unicode": "\U000e0041\U000e0042",
    "soft_hyphen": "\xad",
    "mongol_vowel_sep": "\N{MONGOLIAN VOWEL SEPARATOR}",
}


@pytest.mark.parametrize("field", ["vehicle_label", "vehicle_plate"])
@pytest.mark.parametrize("value", BLANK_ALREADY_BLOCKED.values(), ids=BLANK_ALREADY_BLOCKED.keys())
def test_round2_blank_texts_already_blocked(app, api, owner_user, client_user, field, value):
    resp = api.create(owner_user, {**VALID_BODY, field: value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert counts(app) == EMPTY_COUNTS


@pytest.mark.parametrize("field", ["vehicle_label", "vehicle_plate"])
@pytest.mark.parametrize("value", BLANK_LOOKING.values(), ids=BLANK_LOOKING.keys())
def test_round2_blank_looking_letters_or_symbols_are_refused(app, api, owner_user, client_user, field, value):
    """Contournement de has_visible_char : U+3164 (Lo) ou U+2800 (So) comptent comme 'visibles'."""
    resp = api.create(owner_user, {**VALID_BODY, field: value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


HIDDEN_IN_PLATE = {
    "selecteur_variation_fe00": "AB\N{VARIATION SELECTOR-1}-123-CD",
    "selecteur_variation_supplement": "AB-123-CD\U000e0100",
    "combining_grapheme_joiner": "AB\N{COMBINING GRAPHEME JOINER}-123-CD",
    "khmer_inherent_vowel": "AB" + chr(0x17B4) + "-123-CD",
    "hangul_filler_final": "AB-123-CD\N{HANGUL FILLER}",
    "braille_blank_interne": "AB\N{BRAILLE PATTERN BLANK}-123-CD",
}


@pytest.mark.parametrize("value", HIDDEN_IN_PLATE.values(), ids=HIDDEN_IN_PLATE.keys())
def test_round2_invisible_chars_hidden_inside_plate_are_refused(app, api, owner_user, client_user, value):
    """Plaque qui s'affiche 'AB-123-CD' mais dont la valeur signee est differente."""
    resp = api.create(owner_user, {**VALID_BODY, "vehicle_plate": value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


CF_IN_PLATE = [
    "AB\xad-123-CD",
    "AB-123-CD\U000e0041",
    "AB\N{INVISIBLE SEPARATOR}-123-CD",
    "AB\N{ARABIC LETTER MARK}-123-CD",
]


@pytest.mark.parametrize("value", CF_IN_PLATE, ids=["soft_hyphen", "tag", "invisible_sep", "alm"])
def test_round2_cf_hidden_inside_plate_still_refused(app, api, owner_user, client_user, value):
    resp = api.create(owner_user, {**VALID_BODY, "vehicle_plate": value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0


OBSERVED_PLATES = {
    "cyrillique": u(0x410, 0x412) + "-123-" + chr(0x421) + "D",  # homoglyphes de "AB-123-CD"
    "pleine_chasse": "AB-123-CD".translate(FULLWIDTH_ALNUM),
    "nfd_vs_nfc": "E\N{COMBINING ACUTE ACCENT}-123-CD",
    "rtl_hebreu": "\N{HEBREW LETTER ALEF}\N{HEBREW LETTER BET}-123-CD",
    "ponctuation_seule": "-",
    "point_seul": ".",
}


@pytest.mark.parametrize("value", OBSERVED_PLATES.values(), ids=OBSERVED_PLATES.keys())
def test_round2_homoglyph_and_normalisation_plates_never_500_and_roundtrip(
    api, owner_user, client_user, value
):
    """Observation (pas forcement une faille) : la valeur doit au minimum etre restituee verbatim."""
    resp = api.create(owner_user, {**VALID_BODY, "vehicle_plate": value})

    assert_never_500(resp)
    if resp.status_code == 201:
        cid = resp.get_json()["id"]
        assert api.get(cid, client_user).get_json()["vehicle"]["plate"] == value
    else:
        assert_error(resp, 422, "VALIDATION_ERROR")


ODD_LABELS = {
    "point": ".",
    "tiret": "-",
    "points": "...",
    "tiret_cadratin": "\N{EM DASH}",
    "separateur_ligne": "Audi\N{LINE SEPARATOR}RS6",
    "usage_prive": "Audi\U0000e000",
    "non_assigne": "Audi\U00000378",
}


@pytest.mark.parametrize("value", ODD_LABELS.values(), ids=ODD_LABELS.keys())
def test_round2_punctuation_or_odd_labels_never_500(api, owner_user, client_user, value):
    resp = api.create(owner_user, {**VALID_BODY, "vehicle_label": value})

    assert_never_500(resp)
    if resp.status_code == 201:
        assert api.get(resp.get_json()["id"], client_user).get_json()["vehicle"]["label"] == value
    else:
        assert_error(resp, 422, "VALIDATION_ERROR")


# --- erreurs bornees ------------------------------------------------------------------------------


def test_round2_invalid_amount_wins_even_with_many_other_errors(app, api, owner_user, client_user):
    body: dict[str, Any] = {
        "client_email": 1,
        "vehicle_label": 2,
        "vehicle_plate": 3,
        "start_date": 4,
        "end_date": 5,
        "deposit_cents": "100",
        "currency": 6,
    }
    body.update({f"deposit_cents_{i}": i for i in range(40)})
    body["<img src=x onerror=alert(1)>" + "K" * 5000] = 1

    resp = api.create(owner_user, body)

    err = assert_error(resp, 422, "INVALID_AMOUNT")
    errors = err["details"]["errors"]
    assert len(errors) <= 20
    assert err["details"].get("truncated") is True
    assert any(e["field"] == "deposit_cents" for e in errors)
    text = resp.get_data(as_text=True)
    assert "onerror" not in text
    assert "deposit_cents_3" not in text
    assert len(resp.get_data()) < 8 * 1024
    assert count_rows(app, "Contract") == 0


def test_round2_extra_keys_named_like_amount_do_not_fake_invalid_amount(app, api, owner_user, client_user):
    resp = api.create(owner_user, {**VALID_BODY, **{f"deposit_cents{i}": 0 for i in range(30)}})

    err = assert_error(resp, 422, "VALIDATION_ERROR")
    assert len(err["details"]["errors"]) <= 20
    assert err["details"].get("truncated") is True
    assert all(e["field"] == "(champ inconnu)" for e in err["details"]["errors"])


@pytest.mark.parametrize(
    "value",
    [{"a": {"b": {"c": [1, 2, {"d": "x" * 10_000}]}}}, [[[[["deep"]]]]] * 200, {"k" * 10_000: "v"}],
    ids=["dict_imbrique", "liste_imbriquee", "cle_geante_imbriquee"],
)
@pytest.mark.parametrize("field", ["deposit_cents", "vehicle_label", "start_date"])
def test_round2_nested_errors_stay_bounded_and_silent(app, api, owner_user, client_user, field, value):
    resp = api.create(owner_user, {**VALID_BODY, field: value})

    err = assert_error(resp, 422, codes={"INVALID_AMOUNT", "VALIDATION_ERROR"})
    assert len(err["details"]["errors"]) <= 20
    assert all(len(e["field"]) <= 64 for e in err["details"]["errors"])
    assert len(resp.get_data()) < 8 * 1024
    assert count_rows(app, "Contract") == 0


@pytest.mark.parametrize(
    "value",
    [{"x": [1] * 50_000}, [None] * 50_000, {"r" * 100_000: 1}],
    ids=["dict_liste", "liste", "cle_geante"],
)
def test_round2_nested_cancel_reason_is_bounded(api, contract, owner_user, value):
    before = snapshot(api, contract, owner_user)

    resp = api.cancel(contract, owner_user, body={"reason": value, **{f"x{i}": 1 for i in range(100)}})

    err = assert_error(resp, 422, "VALIDATION_ERROR")
    assert len(err["details"]["errors"]) <= 20
    assert len(resp.get_data()) < 8 * 1024
    assert snapshot(api, contract, owner_user) == before


# --- reason : 500 points de code pile -------------------------------------------------------------

E_ACUTE_NFD = "e\N{COMBINING ACUTE ACCENT}"
ZWJ = "\N{ZERO WIDTH JOINER}"
REASON_LIMIT = {
    "combinants_500": (E_ACUTE_NFD * 250, 200),
    "combinants_501": (E_ACUTE_NFD * 250 + "e", 422),
    "emoji_astral_500": ("\U0001f697" * 500, 200),
    "emoji_astral_501": ("\U0001f697" * 501, 422),
    "cjk_500": (chr(0x4FDD) * 500, 200),
    "newlines_tabs_500": ("\n\t" * 250, 200),
    "zwj_famille": ("\U0001f468" + ZWJ + "\U0001f469" + ZWJ + "\U0001f467", 422),
}


@pytest.mark.parametrize(("reason", "expected"), REASON_LIMIT.values(), ids=REASON_LIMIT.keys())
def test_round2_reason_length_counts_code_points(api, contract, owner_user, reason, expected):
    before = snapshot(api, contract, owner_user)

    resp = api.cancel(contract, owner_user, body={"reason": reason})

    assert resp.status_code == expected, resp.get_data(as_text=True)[:300]
    if expected == 200:
        assert snapshot(api, contract, owner_user)[0] == "CANCELLED"
    else:
        assert_error(resp, 422, "VALIDATION_ERROR")
        assert snapshot(api, contract, owner_user) == before


@pytest.mark.parametrize(
    ("raw_reason", "expected"),
    [
        ('"' + "\\ud83d\\ude97" * 500 + '"', 200),  # paires de surrogates echappees = 500 points de code
        ('"' + "\\ud83d\\ude97" * 499 + '\\ud83d"', 422),  # surrogate haut orphelin final
        ('"' + "a" * 499 + '\\udc00"', 422),  # surrogate bas orphelin
        ('"' + "\\ude97\\ud83d" + '"', 422),  # paire inversee
    ],
    ids=["paires_500", "haut_orphelin", "bas_orphelin", "paire_inversee"],
)
def test_round2_reason_with_escaped_surrogates(api, contract, owner_user, raw_reason, expected):
    before = snapshot(api, contract, owner_user)
    raw = '{"reason": ' + raw_reason + "}"

    resp = api.request("POST", f"/api/contracts/{contract}/cancel", owner_user, raw=raw, idem=new_key())

    assert_never_500(resp)
    assert resp.status_code == expected, resp.get_data(as_text=True)[:300]
    if expected == 422:
        assert_error(resp, 422, "VALIDATION_ERROR")
        assert snapshot(api, contract, owner_user) == before


INVISIBLE_EMAILS = [
    "client@demo.test\N{ZERO WIDTH SPACE}",
    "cl\xadient@demo.test",
    "\N{HANGUL FILLER}@demo.test",
]


@pytest.mark.parametrize("value", INVISIBLE_EMAILS, ids=["zwsp", "soft_hyphen", "hangul_filler"])
def test_round2_invisible_chars_in_client_email(app, api, owner_user, client_user, value):
    resp = api.create(owner_user, {**VALID_BODY, "client_email": value})

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert count_rows(app, "Contract") == 0
