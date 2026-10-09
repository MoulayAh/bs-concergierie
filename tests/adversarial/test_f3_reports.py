"""Red team F3 : etats des lieux (fichiers pieges, signatures, acteurs, metier, courses).

Invariants : jamais de 500, format d'erreur ``{"error": ...}``, et apres chaque erreur : statut et empreinte
du rapport, signatures, fichiers sur disque et statut du contrat inchanges. Un test rouge = une faille
(voir docs/audits/adversarial-2026-10-08.md). Pas de skip/xfail.
"""

import base64
import io
import uuid
import zipfile
import zlib
from typing import Any

import pytest
from flask import Flask

from tests.fixtures.deposits import RecordingProvider, full_state, funded_contract, run_concurrently
from tests.fixtures.files import (
    EXIF_ARTIST,
    EXIF_MARKER,
    PNG_TEXT_MARKER,
    bomb_png,
    distinct_jpeg,
    empty_bytes,
    exe_bytes,
    gif_bytes,
    heic_bytes,
    jpeg_bytes,
    one_byte,
    oversized_jpeg,
    pdf_bytes,
    pdf_with_forbidden,
    png_bytes,
    svg_bytes,
    truncated_jpeg,
    wide_png,
    zip_bytes,
)
from tests.fixtures.helpers import Api, TestUser, assert_error, new_key
from tests.fixtures.reports import (
    UUID_FILE,
    KeyPair,
    KeyRing,
    active_contract,
    create_report,
    delete_file,
    download_file,
    draft_with_photo,
    finalize_report,
    frozen_report,
    get_history,
    get_report,
    post_signature,
    register_key,
    report_message,
    sign_as,
    supersede_report,
    update_report,
    upload_dir_files,
    upload_file,
    upload_ok,
)

pytestmark = pytest.mark.adversarial

DEPOSIT = 2_500_000
GHOST_ID = "00000000-0000-4000-8000-000000000000"


@pytest.fixture
def provider(app: Flask) -> RecordingProvider:
    recording = RecordingProvider()
    app.extensions["payment_provider"] = recording
    return recording


@pytest.fixture
def keyring(api: Api) -> KeyRing:
    return KeyRing(api)


@pytest.fixture
def funded(api: Api, owner_user: TestUser, client_user: TestUser, provider: RecordingProvider) -> str:
    return funded_contract(api, owner_user, client_user)


def snap(app: Flask, api: Api, cid: str, owner: TestUser, kind: str = "checkout") -> dict[str, Any]:
    resp = get_report(api, cid, owner, kind)
    return {
        "report": resp.get_json() if resp.status_code == 200 else None,
        "history": get_history(api, cid, owner, kind).get_json(),
        "contract": full_state(app, api, cid, owner),
        "disk": sorted(p.name for p in upload_dir_files(app)),
    }


def disk(app: Flask) -> list[str]:
    return sorted(p.name for p in upload_dir_files(app))


# --------------------------------------------------------------------------- generateurs locaux


def pdf_objstm_js() -> bytes:
    """Catalogue + action JavaScript caches dans un flux d'objets compresse (PDF 1.5, /ObjStm).

    Aucun mot-cle interdit n'apparait en clair : seul un controle sur le contenu DECOMPRESSE le voit.
    """
    catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>"
    action = b"<< /S /JavaScript /JS (app.alert(1)) >>"
    header = b"1 0 5 " + str(len(catalog) + 1).encode() + b" "
    payload = header + catalog + b" " + action
    stream = zlib.compress(payload)
    objects = [
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"),
        (
            4,
            b"<< /Type /ObjStm /N 2 /First "
            + str(len(header)).encode()
            + b" /Filter /FlateDecode /Length "
            + str(len(stream)).encode()
            + b" >>\nstream\n"
            + stream
            + b"\nendstream",
        ),
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.5\n")
    for number, body in objects:
        out.write(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref_at = out.tell()
    out.write(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode())
    return out.getvalue()


def pdf_zip_polyglot() -> bytes:
    base = pdf_bytes()
    cut = base.rindex(b"xref")
    return base[:cut] + zip_bytes() + b"\n" + base[cut:]


def jpeg_zip_polyglot() -> bytes:
    return jpeg_bytes(exif=False) + zip_bytes()


def encrypted_pdf() -> bytes:
    data = pdf_bytes()
    return data.replace(b"/Root 1 0 R", b"/Root 1 0 R /Encrypt << /Filter /Standard /V 1 /R 2 >>")


# --------------------------------------------------------------------------- fichiers pieges


TRAPPED: dict[str, tuple[bytes, str, str, int]] = {
    "exe_as_jpg": (exe_bytes(), "photo.jpg", "image/jpeg", 415),
    "svg_script": (svg_bytes(), "photo.svg", "image/svg+xml", 415),
    "svg_as_png": (svg_bytes(), "photo.png", "image/png", 415),
    "gif": (gif_bytes(), "photo.gif", "image/gif", 415),
    "heic": (heic_bytes(), "photo.heic", "image/heic", 415),
    "zip_as_jpg": (zip_bytes(), "photo.jpg", "image/jpeg", 415),
    "empty": (empty_bytes(), "photo.jpg", "image/jpeg", 415),
    "one_byte": (one_byte(), "photo.jpg", "image/jpeg", 415),
    "truncated_jpeg": (truncated_jpeg(), "photo.jpg", "image/jpeg", 415),
    "png_as_pdf": (png_bytes(), "photo.pdf", "application/pdf", 415),
    "png_as_jpg": (png_bytes(), "photo.jpg", "image/jpeg", 415),
    "jpeg_as_png": (jpeg_bytes(), "photo.png", "image/png", 415),
    "pdf_as_jpg": (pdf_bytes(), "photo.jpg", "image/jpeg", 415),
    "jpeg_double_ext": (jpeg_bytes(), "photo.jpg.exe", "image/jpeg", 415),
    "jpeg_no_ext": (jpeg_bytes(), "photo", "image/jpeg", 415),
    "jpeg_dot_dot": (jpeg_bytes(), "..", "image/jpeg", 415),
    "pdf_javascript": (pdf_with_forbidden("javascript"), "doc.pdf", "application/pdf", 415),
    "pdf_js": (pdf_with_forbidden("js"), "doc.pdf", "application/pdf", 415),
    "pdf_openaction": (pdf_with_forbidden("openaction"), "doc.pdf", "application/pdf", 415),
    "pdf_launch": (pdf_with_forbidden("launch"), "doc.pdf", "application/pdf", 415),
    "pdf_embedded": (pdf_with_forbidden("embedded"), "doc.pdf", "application/pdf", 415),
    "pdf_hex_escape_js": (
        pdf_bytes(catalog_extra=b"/Foo << /S /Java#53cript >>"),
        "doc.pdf",
        "application/pdf",
        415,
    ),
    "pdf_encrypted": (encrypted_pdf(), "doc.pdf", "application/pdf", 415),
    "pdf_too_many_pages": (pdf_bytes(pages=25), "doc.pdf", "application/pdf", 415),
    "pdf_objstm_javascript": (pdf_objstm_js(), "doc.pdf", "application/pdf", 415),
    "pdf_zip_polyglot": (pdf_zip_polyglot(), "doc.pdf", "application/pdf", 415),
    "bomb_png": (bomb_png(), "photo.png", "image/png", 415),
    "wide_png": (wide_png(), "photo.png", "image/png", 415),
    "oversized": (oversized_jpeg(), "photo.jpg", "image/jpeg", 413),
}


@pytest.mark.parametrize("name", sorted(TRAPPED))
def test_trapped_file_refused_without_side_effect(app, api, funded, owner_user, name):
    data, filename, ctype, status = TRAPPED[name]
    draft_with_photo(api, funded, owner_user)
    before = snap(app, api, funded, owner_user)
    resp = upload_file(api, funded, owner_user, data, filename=filename, content_type=ctype)
    expected = {415: "UNSUPPORTED_FILE", 413: "FILE_TOO_LARGE"}[status]
    assert_error(resp, status, expected)
    assert snap(app, api, funded, owner_user) == before


def test_polyglots_are_real(app):
    assert zipfile.is_zipfile(io.BytesIO(pdf_zip_polyglot()))
    assert zipfile.is_zipfile(io.BytesIO(jpeg_zip_polyglot()))
    assert b"JavaScript" not in pdf_objstm_js()
    assert b"/JavaScript" in zlib.decompress(pdf_objstm_js().split(b"stream\n")[1].split(b"\nendstream")[0])


def test_fifty_megabytes_rejected_413(app, api, funded, owner_user):
    draft_with_photo(api, funded, owner_user)
    before = snap(app, api, funded, owner_user)
    resp = upload_file(api, funded, owner_user, b"\xff\xd8\xff\xe0" + b"\x00" * (50 * 1024 * 1024))
    assert_error(resp, 413)
    assert snap(app, api, funded, owner_user) == before


def test_jpeg_zip_polyglot_neutralised(app, api, funded, owner_user):
    draft_with_photo(api, funded, owner_user)
    resp = upload_file(api, funded, owner_user, jpeg_zip_polyglot())
    if resp.status_code != 201:
        assert_error(resp, 415, "UNSUPPORTED_FILE")
        return
    got = download_file(api, funded, owner_user, resp.get_json()["id"])
    assert got.status_code == 200
    assert not zipfile.is_zipfile(io.BytesIO(got.data))
    assert b"PK\x03\x04" not in got.data


def test_exif_and_png_text_stripped(app, api, funded, owner_user):
    draft_with_photo(api, funded, owner_user)
    jpg = upload_ok(api, funded, owner_user, jpeg_bytes(size=(70, 50), exif=True))
    png = upload_ok(
        api, funded, owner_user, png_bytes(text_chunk=True), filename="p.png", content_type="image/png"
    )
    raw_jpg = download_file(api, funded, owner_user, jpg["id"]).data
    raw_png = download_file(api, funded, owner_user, png["id"]).data
    assert EXIF_MARKER not in raw_jpg
    assert EXIF_ARTIST.encode() not in raw_jpg
    assert PNG_TEXT_MARKER.encode() not in raw_png
    assert b"<script>" not in raw_png


@pytest.mark.parametrize(
    "filename",
    [
        "../../etc/passwd.jpg",
        "..\\..\\..\\windows\\evil.jpg",
        "/abs/path/evil.jpg",
        "x" * 10_000 + ".jpg",
        "‮gpj.exe.jpg",
        'a"; filename=evil.html; x=".jpg',
        "photo.jpg\x00.exe",
    ],
)
def test_hostile_filename_never_escapes_upload_dir(app, api, funded, owner_user, tmp_path, filename):
    draft_with_photo(api, funded, owner_user)
    before = disk(app)
    resp = upload_file(api, funded, owner_user, distinct_jpeg(7), filename=filename)
    assert resp.status_code < 500, resp.get_data(as_text=True)
    if resp.status_code != 201:
        assert_error(resp, resp.status_code)
        assert disk(app) == before
    else:
        body = resp.get_json()
        assert len(body["original_name"]) <= 255
        for bad in ("/", "\\", "\x00"):
            assert bad not in body["original_name"]
        got = download_file(api, funded, owner_user, body["id"])
        assert got.status_code == 200
        assert got.headers["X-Content-Type-Options"] == "nosniff"
        disposition = got.headers["Content-Disposition"]
        assert disposition.startswith("attachment")
        assert "\r" not in disposition
        assert "\n" not in disposition
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.parent.name == "uploads":
            assert UUID_FILE.match(path.name), path
        assert "passwd" not in path.name, path
        assert "evil" not in path.name, path


def test_content_type_lie_ignored_real_type_wins(app, api, funded, owner_user):
    draft_with_photo(api, funded, owner_user)
    body = upload_ok(api, funded, owner_user, distinct_jpeg(9), content_type="application/x-msdownload")
    assert body["mime"] == "image/jpeg"
    got = download_file(api, funded, owner_user, body["id"])
    assert got.mimetype == "image/jpeg"


@pytest.mark.parametrize(
    "build",
    [
        lambda: {"other": (io.BytesIO(jpeg_bytes()), "a.jpg", "image/jpeg")},
        lambda: {"file": [(io.BytesIO(distinct_jpeg(3)), "a.jpg"), (io.BytesIO(distinct_jpeg(4)), "b.jpg")]},
        lambda: {},
    ],
)
def test_bad_multipart_shape(app, api, funded, owner_user, build):
    draft_with_photo(api, funded, owner_user)
    before = snap(app, api, funded, owner_user)
    resp = api.http.post(
        f"/api/contracts/{funded}/reports/checkout/files",
        data=build(),
        headers=owner_user.headers,
        content_type="multipart/form-data",
    )
    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snap(app, api, funded, owner_user) == before


def test_json_body_instead_of_multipart(app, api, funded, owner_user):
    draft_with_photo(api, funded, owner_user)
    resp = api.request("POST", f"/api/contracts/{funded}/reports/checkout/files", owner_user, body={"x": 1})
    assert_error(resp, 422)


def test_upload_on_frozen_or_superseded_leaves_no_orphan(app, api, funded, owner_user, keyring, client_user):
    frozen_report(api, funded, owner_user)
    before = snap(app, api, funded, owner_user)
    assert_error(upload_file(api, funded, owner_user, distinct_jpeg(5)), 409, "INVALID_TRANSITION")
    assert_error(upload_file(api, funded, client_user, distinct_jpeg(6)), 409, "INVALID_TRANSITION")
    assert snap(app, api, funded, owner_user) == before


def test_duplicate_upload_leaves_no_orphan(app, api, funded, owner_user):
    draft_with_photo(api, funded, owner_user)
    before = snap(app, api, funded, owner_user)
    assert_error(upload_file(api, funded, owner_user, distinct_jpeg(1)), 422)
    assert snap(app, api, funded, owner_user) == before


# --------------------------------------------------------------------------- cles et signatures


def _flip(signature_b64: str) -> str:
    raw = base64.b64decode(signature_b64)
    return base64.b64encode(raw[:-1] + bytes([raw[-1] ^ 1])).decode()


def test_signature_with_other_party_key(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    keyring.get(client_user)
    before = snap(app, api, funded, owner_user)
    forged = keyring.get(owner_user).sign_report(funded, "checkout", report["report_hash"])
    before = snap(app, api, funded, owner_user)
    assert_error(post_signature(api, funded, client_user, forged), 422, "SIGNATURE_INVALID")
    assert snap(app, api, funded, owner_user) == before


def test_client_supplied_hash_ignored(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    pair = keyring.get(client_user)
    fake_hash = "0" * 64
    before = snap(app, api, funded, owner_user)
    sig = pair.sign_report(funded, "checkout", fake_hash)
    assert_error(post_signature(api, funded, client_user, sig), 422, "SIGNATURE_INVALID")
    good = pair.sign_report(funded, "checkout", report["report_hash"])
    resp = api.request(
        "POST",
        f"/api/contracts/{funded}/reports/checkout/signatures",
        client_user,
        body={"signature": good, "report_hash": fake_hash},
        idem=new_key(),
    )
    assert_error(resp, 422, "VALIDATION_ERROR")
    assert snap(app, api, funded, owner_user) == before


def test_signature_replayed_on_other_contract(app, api, owner_user, client_user, keyring, provider):
    cid_a = funded_contract(api, owner_user, client_user)
    cid_b = funded_contract(api, owner_user, client_user)
    rep_a = frozen_report(api, cid_a, owner_user)
    frozen_report(api, cid_b, owner_user)
    sig_a = keyring.get(client_user).sign_report(cid_a, "checkout", rep_a["report_hash"])
    before = snap(app, api, cid_b, owner_user)
    assert_error(post_signature(api, cid_b, client_user, sig_a), 422, "SIGNATURE_INVALID")
    assert snap(app, api, cid_b, owner_user) == before


def test_signature_with_other_kind_domain(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    sig = keyring.get(client_user).sign(report_message(funded, "return", report["report_hash"]))
    before = snap(app, api, funded, owner_user)
    assert_error(post_signature(api, funded, client_user, sig), 422, "SIGNATURE_INVALID")
    assert snap(app, api, funded, owner_user) == before


def test_signature_of_superseded_revision_replayed(app, api, funded, owner_user, client_user, keyring):
    rev1 = frozen_report(api, funded, owner_user)
    old_sig = keyring.get(client_user).sign_report(funded, "checkout", rev1["report_hash"])
    assert post_signature(api, funded, client_user, old_sig).status_code == 200
    assert supersede_report(api, funded, owner_user).status_code == 201
    assert_error(post_signature(api, funded, client_user, old_sig), 409, "INVALID_TRANSITION")
    assert finalize_report(api, funded, owner_user).status_code == 200
    before = snap(app, api, funded, owner_user)
    assert before["report"]["report_hash"] != rev1["report_hash"]
    assert_error(post_signature(api, funded, client_user, old_sig), 422, "SIGNATURE_INVALID")
    assert snap(app, api, funded, owner_user) == before


def test_revoked_key_cannot_sign(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    pair = keyring.get(client_user)
    assert api.request("DELETE", f"/api/me/keys/{pair.key_id}", client_user).status_code == 204
    before = snap(app, api, funded, owner_user)
    sig = pair.sign_report(funded, "checkout", report["report_hash"])
    assert_error(post_signature(api, funded, client_user, sig), 422, "KEY_NOT_REGISTERED")
    assert snap(app, api, funded, owner_user) == before


def test_cannot_revoke_someone_else_key(app, api, owner_user, client_user, keyring):
    pair = keyring.get(client_user)
    assert_error(api.request("DELETE", f"/api/me/keys/{pair.key_id}", owner_user), 404, "NOT_FOUND")
    keys = api.request("GET", "/api/me/keys", client_user).get_json()["keys"]
    assert keys[0]["revoked_at"] is None


def test_cannot_register_other_party_public_key(app, api, owner_user, client_user, keyring):
    pair = keyring.get(client_user)
    assert_error(register_key(api, owner_user, pair.public_b64), 422)


def test_double_signature_refused(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, client_user, report).status_code == 200
    before = snap(app, api, funded, owner_user)
    assert_error(sign_as(api, keyring, funded, client_user, report), 409, "INVALID_TRANSITION")
    assert snap(app, api, funded, owner_user) == before


def test_concurrent_double_signature_same_party(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    sig = keyring.get(client_user).sign_report(funded, "checkout", report["report_hash"])
    results = run_concurrently(app, [lambda a: post_signature(a, funded, client_user, sig)] * 2)
    assert sorted(r.status_code for r in results) == [200, 409]
    final = get_report(api, funded, owner_user).get_json()
    assert [s["party"] for s in final["signatures"]] == ["client"]
    assert final["status"] == "FROZEN"


def test_signature_on_draft_refused(app, api, funded, owner_user, client_user, keyring):
    draft_with_photo(api, funded, owner_user)
    keyring.get(client_user)
    before = snap(app, api, funded, owner_user)
    sig = keyring.get(client_user).sign_report(funded, "checkout", "0" * 64)
    resp = post_signature(api, funded, client_user, sig)
    assert_error(resp, 409, "INVALID_TRANSITION")
    assert snap(app, api, funded, owner_user) == before


@pytest.mark.parametrize(
    "signature",
    [
        "",
        "!!!!",
        "AAAA",
        "A" * 511,
        "A" * 600,
        base64.b64encode(b"\x00" * 64).decode() + "\n",
        base64.b64encode(b"\x00" * 64).decode().rstrip("="),
        base64.urlsafe_b64encode(b"\xff" * 64).decode(),
        base64.b64encode(b"\x00" * 65).decode(),
        123,
        None,
        ["x"],
        {"sig": "x"},
    ],
)
def test_malformed_signature(app, api, funded, owner_user, client_user, keyring, signature):
    frozen_report(api, funded, owner_user)
    keyring.get(client_user)
    before = snap(app, api, funded, owner_user)
    err = assert_error(post_signature(api, funded, client_user, signature), 422)
    assert err["code"] in {"VALIDATION_ERROR", "SIGNATURE_INVALID"}
    assert snap(app, api, funded, owner_user) == before


def test_flipped_signature_refused(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    good = keyring.get(client_user).sign_report(funded, "checkout", report["report_hash"])
    before = snap(app, api, funded, owner_user)
    assert_error(post_signature(api, funded, client_user, _flip(good)), 422, "SIGNATURE_INVALID")
    assert snap(app, api, funded, owner_user) == before


IDENTITY_POINT = b"\x01" + b"\x00" * 31


def test_weak_public_key_refused(app, api, client_user):
    """Point neutre (ordre 1) : toute signature (R=identite, S=0) verifie pour TOUT message."""
    resp = register_key(api, client_user, base64.b64encode(IDENTITY_POINT).decode())
    assert_error(resp, 422, "VALIDATION_ERROR")


def test_universal_signature_never_accepted(app, api, funded, owner_user, client_user):
    frozen_report(api, funded, owner_user)
    register_key(api, client_user, base64.b64encode(IDENTITY_POINT).decode())
    before = snap(app, api, funded, owner_user)
    universal = base64.b64encode(IDENTITY_POINT + b"\x00" * 32).decode()
    assert_error(post_signature(api, funded, client_user, universal), 422)
    assert snap(app, api, funded, owner_user) == before


# --------------------------------------------------------------------------- acteurs


def test_client_cannot_create_edit_freeze_supersede(app, api, funded, owner_user, client_user, keyring):
    assert_error(create_report(api, funded, client_user), 403, "FORBIDDEN_ACTOR")
    draft_with_photo(api, funded, owner_user)
    before = snap(app, api, funded, owner_user)
    assert_error(update_report(api, funded, client_user, odometer_km=1), 403, "FORBIDDEN_ACTOR")
    assert_error(finalize_report(api, funded, client_user), 403, "FORBIDDEN_ACTOR")
    assert snap(app, api, funded, owner_user) == before
    assert finalize_report(api, funded, owner_user).status_code == 200
    before = snap(app, api, funded, owner_user)
    assert_error(supersede_report(api, funded, client_user), 403, "FORBIDDEN_ACTOR")
    assert snap(app, api, funded, owner_user) == before


def test_owner_cannot_delete_client_photo(app, api, funded, owner_user, client_user):
    draft_with_photo(api, funded, owner_user)
    photo = upload_ok(api, funded, client_user, distinct_jpeg(2))
    before = snap(app, api, funded, owner_user)
    assert_error(delete_file(api, funded, owner_user, photo["id"]), 403, "FORBIDDEN_ACTOR")
    assert snap(app, api, funded, owner_user) == before


def test_stranger_download_is_indistinguishable_404(app, api, funded, owner_user, stranger_user):
    _, photo = draft_with_photo(api, funded, owner_user)
    real = download_file(api, funded, stranger_user, photo["id"])
    fake = download_file(api, funded, stranger_user, str(uuid.uuid4()))
    ghost = download_file(api, str(uuid.uuid4()), stranger_user, photo["id"])
    for resp in (real, fake, ghost):
        assert_error(resp, 404, "NOT_FOUND")
    assert real.get_json() == fake.get_json() == ghost.get_json()
    assert_error(upload_file(api, funded, stranger_user, distinct_jpeg(4)), 404, "NOT_FOUND")
    assert_error(delete_file(api, funded, stranger_user, photo["id"]), 404, "NOT_FOUND")
    assert_error(get_history(api, funded, stranger_user), 404, "NOT_FOUND")


def test_idor_file_through_own_contract(app, api, funded, owner_user, make_user, provider):
    _, photo = draft_with_photo(api, funded, owner_user)
    owner2 = make_user("owner", email="owner2@demo.test")
    client2 = make_user("client", email="client2@demo.test")
    body = {
        "client_email": client2.email,
        "vehicle_label": "X",
        "vehicle_plate": "ZZ-999-ZZ",
        "start_date": "2026-11-01",
        "end_date": "2026-11-05",
        "deposit_cents": DEPOSIT,
        "currency": "EUR",
    }
    cid2 = funded_contract(api, owner2, client2, body)
    draft_with_photo(api, cid2, owner2)
    assert_error(download_file(api, cid2, owner2, photo["id"]), 404, "NOT_FOUND")
    assert_error(delete_file(api, cid2, owner2, photo["id"]), 404, "NOT_FOUND")
    assert_error(download_file(api, funded, owner_user, photo["id"], kind="return"), 404, "NOT_FOUND")


@pytest.mark.parametrize("kind", ["CHECKOUT", "checkout' OR 1=1--", "..%2F..", "x" * 5000])
def test_hostile_kind_in_path(app, api, funded, owner_user, kind):
    draft_with_photo(api, funded, owner_user)
    resp = api.request("GET", f"/api/contracts/{funded}/reports/{kind}", owner_user)
    assert_error(resp, 404)


def test_unauthenticated_everything_401(app, api, funded, owner_user):
    _, photo = draft_with_photo(api, funded, owner_user)
    assert_error(download_file(api, funded, None, photo["id"]), 401, "UNAUTHENTICATED")
    assert_error(upload_file(api, funded, None, distinct_jpeg(3)), 401, "UNAUTHENTICATED")
    assert_error(register_key(api, None, KeyPair().public_b64), 401, "UNAUTHENTICATED")


# --------------------------------------------------------------------------- metier


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"claimed_retention_cents": 1}, "INVALID_AMOUNT"),
        ({"claimed_retention_cents": -1}, "INVALID_AMOUNT"),
        ({"claimed_retention_cents": 2**63}, "INVALID_AMOUNT"),
        ({"claimed_retention_cents": "0"}, "VALIDATION_ERROR"),
        ({"odometer_km": -1}, "VALIDATION_ERROR"),
        ({"odometer_km": 2**63}, "VALIDATION_ERROR"),
        ({"odometer_km": 1.5}, "VALIDATION_ERROR"),
        ({"fuel_eighths": 9}, "VALIDATION_ERROR"),
        ({"notes": "x" * 1_000_000}, None),
        ({"notes": "a\x00b"}, "VALIDATION_ERROR"),
        (
            {"damages": [{"zone": "roof", "severity": "minor", "description": "x", "file_ids": [GHOST_ID]}]},
            "VALIDATION_ERROR",
        ),
        ({"admin": True}, "VALIDATION_ERROR"),
    ],
)
def test_checkout_bad_values(app, api, funded, owner_user, over, code):
    resp = create_report(api, funded, owner_user, **over)
    err = assert_error(resp, resp.status_code)
    assert resp.status_code in {413, 422}
    if code is not None:
        assert err["code"] == code
    assert get_report(api, funded, owner_user).status_code == 404


def test_return_odometer_backwards_and_retention_over_deposit(
    app, api, owner_user, client_user, keyring, provider
):
    cid = active_contract(api, keyring, owner_user, client_user)
    before = full_state(app, api, cid, owner_user)
    assert_error(create_report(api, cid, owner_user, "return", odometer_km=12_449), 422, "VALIDATION_ERROR")
    too_much = create_report(
        api, cid, owner_user, "return", odometer_km=13_000, claimed_retention_cents=DEPOSIT + 1
    )
    assert_error(too_much, 422, "INVALID_AMOUNT")
    assert get_report(api, cid, owner_user, "return").status_code == 404
    assert create_report(api, cid, owner_user, "return", odometer_km=13_000).status_code == 201
    assert_error(update_report(api, cid, owner_user, "return", odometer_km=0), 422, "VALIDATION_ERROR")
    assert_error(
        update_report(api, cid, owner_user, "return", odometer_km=13_000, claimed_retention_cents=-5),
        422,
        "INVALID_AMOUNT",
    )
    assert get_report(api, cid, owner_user, "return").get_json()["odometer_km"] == 13_000
    assert full_state(app, api, cid, owner_user) == before


def test_start_before_client_signature(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, owner_user, report).status_code == 200
    before = snap(app, api, funded, owner_user)
    assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")
    assert snap(app, api, funded, owner_user) == before


def test_signed_report_is_final(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    for user in (client_user, owner_user):
        assert sign_as(api, keyring, funded, user, report).status_code == 200
    before = snap(app, api, funded, owner_user)
    assert_error(supersede_report(api, funded, owner_user), 409, "INVALID_TRANSITION")
    assert_error(update_report(api, funded, owner_user, odometer_km=1), 409, "INVALID_TRANSITION")
    assert_error(upload_file(api, funded, owner_user, distinct_jpeg(8)), 409, "INVALID_TRANSITION")
    assert_error(delete_file(api, funded, owner_user, report["files"][0]["id"]), 409, "INVALID_TRANSITION")
    assert snap(app, api, funded, owner_user) == before


# --------------------------------------------------------------------------- remplacement et courses


def test_supersede_after_client_signature_keeps_evidence(app, api, funded, owner_user, client_user, keyring):
    rev1 = frozen_report(api, funded, owner_user)
    photo = rev1["files"][0]
    assert sign_as(api, keyring, funded, client_user, rev1).status_code == 200
    assert supersede_report(api, funded, owner_user).status_code == 201
    rev2 = get_report(api, funded, owner_user).get_json()
    assert rev2["status"] == "DRAFT"
    assert rev2["signatures"] == []
    new_id = rev2["files"][0]["id"]
    assert delete_file(api, funded, owner_user, new_id).status_code == 204
    history = get_history(api, funded, client_user).get_json()["reports"]
    old = history[0]
    assert old["status"] == "SUPERSEDED"
    assert old["report_hash"] == rev1["report_hash"]
    assert [s["party"] for s in old["signatures"]] == ["client"]
    got = download_file(api, funded, client_user, photo["id"])
    assert got.status_code == 200
    assert photo["sha256"] in {f["sha256"] for f in old["files"]}
    assert len(disk(app)) == 1
    upload_ok(api, funded, owner_user, distinct_jpeg(12))
    assert finalize_report(api, funded, owner_user).status_code == 200
    assert_error(api.start(funded, owner_user), 409, "INVALID_TRANSITION")
    assert get_report(api, funded, owner_user).get_json()["signatures"] == []


def test_race_upload_vs_freeze(app, api, funded, owner_user, client_user):
    draft_with_photo(api, funded, owner_user)
    jobs = [lambda a: finalize_report(a, funded, owner_user)]
    for i in range(4):
        user = owner_user if i % 2 else client_user
        jobs.append(lambda a, i=i, user=user: upload_file(a, funded, user, distinct_jpeg(20 + i)))
    results = run_concurrently(app, jobs)
    for resp in results:
        assert resp.status_code in {200, 201, 409}, resp.get_data(as_text=True)
    report = get_report(api, funded, owner_user).get_json()
    assert report["status"] == "FROZEN"
    import json as _json

    canonical = _json.loads(report["canonical_json"])
    assert sorted(f["sha256"] for f in canonical["files"]) == sorted(f["sha256"] for f in report["files"])
    assert len(disk(app)) == len(report["files"])
    accepted = sum(1 for r in results[1:] if r.status_code == 201)
    assert len(report["files"]) == 1 + accepted


def test_race_second_signature_vs_supersede(app, api, funded, owner_user, client_user, keyring):
    report = frozen_report(api, funded, owner_user)
    assert sign_as(api, keyring, funded, client_user, report).status_code == 200
    owner_sig = keyring.get(owner_user).sign_report(funded, "checkout", report["report_hash"])
    results = run_concurrently(
        app,
        [
            lambda a: post_signature(a, funded, owner_user, owner_sig),
            lambda a: supersede_report(a, funded, owner_user),
        ],
    )
    codes = [r.status_code for r in results]
    assert codes in ([200, 409], [409, 201]), [r.get_data(as_text=True) for r in results]
    history = get_history(api, funded, owner_user).get_json()["reports"]
    for rev in history:
        if rev["status"] == "SUPERSEDED":
            assert len(rev["signatures"]) < 2, rev
    active = get_report(api, funded, owner_user).get_json()
    assert active["status"] in {"SIGNED", "DRAFT"}
    assert full_state(app, api, funded, owner_user)["contract"]["status"] == "FUNDED"
