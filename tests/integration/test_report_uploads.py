"""F3 : upload securise, telechargement authentifie, suppression par l'auteur (routes de fichiers).

Interfaces supposees : voir l'en-tete de tests/fixtures/reports.py. Apres un refus : rien sur disque, aucun
fichier ajoute au rapport.
"""

import io
from pathlib import Path

import pytest
from PIL import Image

from tests.fixtures import files as gen
from tests.fixtures.deposits import funded_contract
from tests.fixtures.helpers import assert_error
from tests.fixtures.reports import (
    UUID_FILE,
    create_report,
    delete_file,
    distinct_jpeg,
    download_file,
    get_report,
    sha256_hex,
    update_report,
    upload_dir_files,
    upload_file,
    upload_ok,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def funded(api, owner_user, client_user, provider) -> str:
    cid = funded_contract(api, owner_user, client_user)
    assert create_report(api, cid, owner_user).status_code == 201
    return cid


def _files(api, cid, user):
    return get_report(api, cid, user).get_json()["files"]


# ------------------------------------------------------------------ fichiers acceptes


def test_upload_accepts_jpeg_png_pdf_and_strips_exif(app, api, owner_user, funded):
    jpeg = upload_ok(api, funded, owner_user, gen.jpeg_bytes(), filename="a.jpg")
    png = upload_ok(api, funded, owner_user, gen.png_bytes(), filename="b.png", content_type="image/png")
    pdf = upload_ok(
        api, funded, owner_user, gen.pdf_bytes(), filename="c.pdf", content_type="application/pdf"
    )

    assert [f["mime"] for f in (jpeg, png, pdf)] == ["image/jpeg", "image/png", "application/pdf"]
    stored = {p.suffix: p.read_bytes() for p in upload_dir_files(app)}
    assert set(stored) == {".jpg", ".png", ".pdf"}
    assert gen.EXIF_MARKER not in stored[".jpg"]
    assert len(Image.open(io.BytesIO(stored[".jpg"])).getexif()) == 0
    assert b"png-text-marker" not in stored[".png"]
    assert len(_files(api, funded, owner_user)) == 3


def test_stored_sha256_matches_bytes_on_disk(app, api, owner_user, funded):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes())

    (path,) = upload_dir_files(app)

    assert UUID_FILE.match(path.name)
    assert uploaded["sha256"] == sha256_hex(path.read_bytes())
    assert uploaded["size_bytes"] == path.stat().st_size
    assert uploaded["mime"] == "image/jpeg"
    assert set(uploaded) >= {"id", "sha256", "mime", "size_bytes", "original_name", "uploaded_by"}
    assert uploaded["uploaded_by"] == owner_user.id


def test_client_can_add_a_photo_to_a_draft_report(api, owner_user, client_user, funded):
    uploaded = upload_ok(api, funded, client_user, distinct_jpeg(3))

    assert uploaded["uploaded_by"] == client_user.id
    assert [f["id"] for f in _files(api, funded, owner_user)] == [uploaded["id"]]


HOSTILE_NAMES = [
    "../../etc/passwd.jpg",
    "a" * 10_000 + ".jpg",
    "evil\x00name.jpg",
    "..\\..\\boot.jpg",
    "/etc/shadow.jpg",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_hostile_filename_is_stored_under_uuid_and_nothing_leaves_upload_dir(
    app, api, owner_user, funded, name
):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes(), filename=name)

    root = Path(app.config["UPLOAD_DIR"])
    on_disk = [p for p in root.parent.rglob("*") if p.is_file()]
    assert len(on_disk) == 1
    assert on_disk[0].parent == root
    assert UUID_FILE.match(on_disk[0].name)
    cleaned = uploaded["original_name"]
    assert len(cleaned) <= 255
    assert not any(c in cleaned for c in ("/", "\\", "\x00"))


# ------------------------------------------------------------------ fichiers refuses

REJECTED = {
    "exe_renamed_jpg": (gen.exe_bytes, "photo.jpg", "image/jpeg"),
    "exe_with_pdf_type": (gen.exe_bytes, "doc.pdf", "application/pdf"),
    "png_named_pdf": (gen.png_bytes, "doc.pdf", "application/pdf"),
    "png_declared_jpeg": (gen.png_bytes, "photo.jpg", "image/jpeg"),
    "svg_script": (gen.svg_bytes, "logo.svg", "image/svg+xml"),
    "svg_lying_type": (gen.svg_bytes, "logo.png", "image/png"),
    "gif": (gen.gif_bytes, "anim.gif", "image/gif"),
    "heic": (gen.heic_bytes, "photo.heic", "image/heic"),
    "zip": (gen.zip_bytes, "archive.zip", "application/zip"),
    "zip_as_jpeg": (gen.zip_bytes, "photo.jpg", "image/jpeg"),
    "empty": (gen.empty_bytes, "photo.jpg", "image/jpeg"),
    "one_byte": (gen.one_byte, "photo.jpg", "image/jpeg"),
    "truncated_jpeg": (gen.truncated_jpeg, "photo.jpg", "image/jpeg"),
    "pdf_javascript": (lambda: gen.pdf_with_forbidden("javascript"), "doc.pdf", "application/pdf"),
    "pdf_openaction": (lambda: gen.pdf_with_forbidden("openaction"), "doc.pdf", "application/pdf"),
    "pdf_launch": (lambda: gen.pdf_with_forbidden("launch"), "doc.pdf", "application/pdf"),
    "pdf_embedded": (lambda: gen.pdf_with_forbidden("embedded"), "doc.pdf", "application/pdf"),
    "bomb_20000x20000": (gen.bomb_png, "photo.png", "image/png"),
}


@pytest.mark.parametrize("case", list(REJECTED))
def test_invalid_upload_is_unsupported_file_and_leaves_no_trace(app, api, owner_user, funded, case):
    maker, name, ctype = REJECTED[case]

    resp = upload_file(api, funded, owner_user, maker(), filename=name, content_type=ctype)

    assert_error(resp, 415, "UNSUPPORTED_FILE")
    assert upload_dir_files(app) == []
    assert _files(api, funded, owner_user) == []


def test_upload_over_ten_megabytes_is_file_too_large_in_json(app, api, owner_user, funded):
    resp = upload_file(api, funded, owner_user, gen.oversized_jpeg())

    assert_error(resp, 413, "FILE_TOO_LARGE")
    assert upload_dir_files(app) == []
    assert _files(api, funded, owner_user) == []


def test_upload_without_file_field_is_validation_error(app, api, owner_user, funded):
    resp = upload_file(api, funded, owner_user, gen.jpeg_bytes(), field="image")

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert upload_dir_files(app) == []


def test_upload_with_no_multipart_body_is_validation_error(api, owner_user, funded):
    resp = api.request("POST", f"/api/contracts/{funded}/reports/checkout/files", owner_user, body={"a": 1})

    assert_error(resp, 422, codes={"VALIDATION_ERROR"})


def test_upload_with_two_files_is_validation_error(app, api, owner_user, funded):
    resp = api.http.post(
        f"/api/contracts/{funded}/reports/checkout/files",
        data={
            "file": [
                (io.BytesIO(gen.jpeg_bytes()), "a.jpg", "image/jpeg"),
                (io.BytesIO(gen.png_bytes()), "b.png", "image/png"),
            ]
        },
        headers=owner_user.headers,
        content_type="multipart/form-data",
    )

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert upload_dir_files(app) == []
    assert _files(api, funded, owner_user) == []


def test_twenty_first_file_is_validation_error(app, api, owner_user, funded):
    for index in range(20):
        upload_ok(api, funded, owner_user, distinct_jpeg(index))
    on_disk = len(upload_dir_files(app))

    resp = upload_file(api, funded, owner_user, distinct_jpeg(40))

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert len(upload_dir_files(app)) == on_disk == 20
    assert len(_files(api, funded, owner_user)) == 20


def test_same_file_twice_is_validation_error(app, api, owner_user, funded):
    upload_ok(api, funded, owner_user, gen.jpeg_bytes())

    resp = upload_file(api, funded, owner_user, gen.jpeg_bytes())

    assert_error(resp, 422, "VALIDATION_ERROR")
    assert len(upload_dir_files(app)) == 1
    assert len(_files(api, funded, owner_user)) == 1


def test_upload_by_stranger_is_not_found(app, api, stranger_user, funded):
    assert_error(upload_file(api, funded, stranger_user, gen.jpeg_bytes()), 404, "NOT_FOUND")
    assert upload_dir_files(app) == []


def test_upload_without_credentials_is_unauthenticated(app, api, funded):
    assert_error(upload_file(api, funded, None, gen.jpeg_bytes()), 401, "UNAUTHENTICATED")
    assert upload_dir_files(app) == []


def test_upload_without_existing_report_is_not_found(app, api, owner_user, client_user, provider):
    cid = funded_contract(api, owner_user, client_user)

    assert_error(upload_file(api, cid, owner_user, gen.jpeg_bytes()), 404, "NOT_FOUND")
    assert upload_dir_files(app) == []


# ------------------------------------------------------------------ telechargement


def test_download_headers_attachment_nosniff(app, api, owner_user, client_user, funded):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes())

    for user in (owner_user, client_user):
        resp = download_file(api, funded, user, uploaded["id"])

        assert resp.status_code == 200
        assert resp.headers["Content-Disposition"].startswith("attachment")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["Content-Type"].startswith("image/jpeg")
        assert sha256_hex(resp.get_data()) == uploaded["sha256"]


def test_download_by_stranger_is_not_found(api, owner_user, stranger_user, funded):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes())

    assert_error(download_file(api, funded, stranger_user, uploaded["id"]), 404, "NOT_FOUND")


def test_download_without_credentials_is_unauthenticated(api, owner_user, funded):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes())

    assert_error(download_file(api, funded, None, uploaded["id"]), 401, "UNAUTHENTICATED")


def test_download_of_a_file_from_another_contract_is_not_found(
    api, owner_user, client_user, funded, provider
):
    mine = upload_ok(api, funded, owner_user, gen.jpeg_bytes())
    other = funded_contract(api, owner_user, client_user)
    create_report(api, other, owner_user)
    foreign = upload_ok(api, other, owner_user, distinct_jpeg(5))

    # fichier du contrat B demande via le contrat A (IDOR) ; meme partie impliquee dans les deux
    assert_error(download_file(api, funded, owner_user, foreign["id"]), 404, "NOT_FOUND")
    assert download_file(api, funded, owner_user, mine["id"]).status_code == 200


def test_download_of_unknown_file_is_not_found(api, owner_user, funded):
    resp = download_file(api, funded, owner_user, "00000000-0000-4000-8000-000000000000")

    assert_error(resp, 404, "NOT_FOUND")


def test_download_with_path_traversal_id_is_not_found(api, owner_user, funded):
    assert_error(download_file(api, funded, owner_user, "..%2F..%2Fetc%2Fpasswd"), 404, "NOT_FOUND")


# ------------------------------------------------------------------ suppression


def test_each_party_deletes_only_own_files(app, api, owner_user, client_user, funded):
    owners = upload_ok(api, funded, owner_user, distinct_jpeg(1))
    clients = upload_ok(api, funded, client_user, distinct_jpeg(2))

    assert_error(delete_file(api, funded, owner_user, clients["id"]), 403, "FORBIDDEN_ACTOR")
    assert_error(delete_file(api, funded, client_user, owners["id"]), 403, "FORBIDDEN_ACTOR")
    assert len(_files(api, funded, owner_user)) == 2
    assert len(upload_dir_files(app)) == 2

    assert delete_file(api, funded, client_user, clients["id"]).status_code == 204
    assert delete_file(api, funded, owner_user, owners["id"]).status_code == 204

    assert _files(api, funded, owner_user) == []
    assert upload_dir_files(app) == []


def test_delete_by_stranger_is_not_found(api, owner_user, stranger_user, funded):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes())

    assert_error(delete_file(api, funded, stranger_user, uploaded["id"]), 404, "NOT_FOUND")
    assert len(_files(api, funded, owner_user)) == 1


def test_delete_unknown_file_is_not_found(api, owner_user, funded):
    resp = delete_file(api, funded, owner_user, "00000000-0000-4000-8000-000000000000")

    assert_error(resp, 404, "NOT_FOUND")


def test_delete_without_credentials_is_unauthenticated(api, owner_user, funded):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes())

    assert_error(delete_file(api, funded, None, uploaded["id"]), 401, "UNAUTHENTICATED")


def test_damage_cannot_reference_a_deleted_file(api, owner_user, funded):
    uploaded = upload_ok(api, funded, owner_user, gen.jpeg_bytes())
    assert delete_file(api, funded, owner_user, uploaded["id"]).status_code == 204
    damage = {"zone": "hood", "severity": "minor", "description": "d", "file_ids": [uploaded["id"]]}

    assert_error(update_report(api, funded, owner_user, damages=[damage]), 422, "VALIDATION_ERROR")
