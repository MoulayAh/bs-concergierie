"""F3 : pipeline d'upload (``app.security.uploads``), logique pure + ecriture dans un repertoire temporaire.

Interfaces supposees : voir l'en-tete de tests/fixtures/reports.py.
"""

import hashlib
import io
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from PIL import Image

from app.domain.errors import FileTooLarge, UnsupportedFile
from app.security.uploads import inspect_upload, sanitize_filename, store_file
from tests.fixtures import files as gen
from tests.fixtures.reports import UUID_FILE

# ------------------------------------------------------------------ fichiers acceptes


def test_upload_accepts_jpeg_and_strips_exif():
    source = gen.jpeg_bytes()
    assert gen.EXIF_MARKER in source

    result = inspect_upload(source, "photo.jpg")

    assert (result.mime, result.ext) == ("image/jpeg", "jpg")
    assert gen.EXIF_MARKER not in result.data
    assert gen.EXIF_ARTIST.encode() not in result.data
    assert len(Image.open(io.BytesIO(result.data)).getexif()) == 0
    assert (result.width, result.height) == (64, 48)


def test_upload_accepts_png_and_strips_text_chunks():
    source = gen.png_bytes()
    assert gen.PNG_TEXT_MARKER.encode() in source

    result = inspect_upload(source, "photo.png")

    assert (result.mime, result.ext) == ("image/png", "png")
    assert b"png-text-marker" not in result.data
    assert Image.open(io.BytesIO(result.data)).info.get("Comment") is None


def test_upload_accepts_valid_pdf():
    source = gen.pdf_bytes()

    result = inspect_upload(source, "etat.pdf")

    assert (result.mime, result.ext) == ("application/pdf", "pdf")
    assert result.data.startswith(b"%PDF-")
    assert (result.width, result.height) == (None, None)


def test_upload_accepts_pdf_with_twenty_pages():
    assert inspect_upload(gen.pdf_pages(20), "etat.pdf").mime == "application/pdf"


@pytest.mark.parametrize(("name", "maker"), [("PHOTO.JPG", gen.jpeg_bytes), ("photo.jpeg", gen.jpeg_bytes)])
def test_upload_accepts_equivalent_jpeg_extensions(name, maker):
    assert inspect_upload(maker(), name).ext == "jpg"


@pytest.mark.parametrize("maker", [gen.jpeg_bytes, gen.png_bytes, gen.pdf_bytes])
def test_stored_sha256_matches_the_bytes_returned_for_storage(maker):
    name = {"jpeg_bytes": "a.jpg", "png_bytes": "a.png", "pdf_bytes": "a.pdf"}[maker.__name__]

    result = inspect_upload(maker(), name)

    assert result.sha256 == hashlib.sha256(result.data).hexdigest()
    assert result.size_bytes == len(result.data)


def test_reencoding_is_deterministic_for_identical_input():
    first = inspect_upload(gen.jpeg_bytes(), "a.jpg")
    second = inspect_upload(gen.jpeg_bytes(), "b.jpg")

    assert first.sha256 == second.sha256


# ------------------------------------------------------------------ fichiers refuses (415)

REJECTED = {
    "exe_renamed_jpg": (gen.exe_bytes, "photo.jpg"),
    "exe_renamed_pdf": (gen.exe_bytes, "doc.pdf"),
    "png_named_pdf": (gen.png_bytes, "doc.pdf"),
    "jpeg_named_png": (gen.jpeg_bytes, "photo.png"),
    "pdf_named_jpg": (gen.pdf_bytes, "photo.jpg"),
    "svg_with_script": (gen.svg_bytes, "logo.svg"),
    "svg_named_jpg": (gen.svg_bytes, "photo.jpg"),
    "gif": (gen.gif_bytes, "anim.gif"),
    "gif_named_jpg": (gen.gif_bytes, "photo.jpg"),
    "heic": (gen.heic_bytes, "photo.heic"),
    "heic_named_jpg": (gen.heic_bytes, "photo.jpg"),
    "zip": (gen.zip_bytes, "archive.zip"),
    "zip_named_png": (gen.zip_bytes, "photo.png"),
    "empty": (gen.empty_bytes, "photo.jpg"),
    "one_byte": (gen.one_byte, "photo.jpg"),
    "truncated_jpeg": (gen.truncated_jpeg, "photo.jpg"),
    "pdf_javascript": (lambda: gen.pdf_with_forbidden("javascript"), "doc.pdf"),
    "pdf_js": (lambda: gen.pdf_with_forbidden("js"), "doc.pdf"),
    "pdf_openaction": (lambda: gen.pdf_with_forbidden("openaction"), "doc.pdf"),
    "pdf_launch": (lambda: gen.pdf_with_forbidden("launch"), "doc.pdf"),
    "pdf_embedded": (lambda: gen.pdf_with_forbidden("embedded"), "doc.pdf"),
    "pdf_aa": (lambda: gen.pdf_with_forbidden("aa"), "doc.pdf"),
    "pdf_too_many_pages": (lambda: gen.pdf_pages(21), "doc.pdf"),
    "image_wider_than_8000": (gen.wide_png, "photo.png"),
}


@pytest.mark.parametrize("case", list(REJECTED))
def test_upload_rejects_invalid_file_with_unsupported_file(case):
    maker, name = REJECTED[case]

    with pytest.raises(UnsupportedFile) as caught:
        inspect_upload(maker(), name)

    assert caught.value.code == "UNSUPPORTED_FILE"
    assert caught.value.http_status == 415


def test_upload_rejects_decompression_bomb_quickly_without_warning():
    """20000x20000 : refuse en 415 (filterwarnings=error : aucun warning ne doit fuiter)."""
    bomb = gen.bomb_png()
    assert len(bomb) < gen.MAX_UPLOAD_BYTES

    started = time.monotonic()
    with pytest.raises(UnsupportedFile):
        inspect_upload(bomb, "photo.png")

    assert time.monotonic() - started < 10


def test_upload_over_ten_megabytes_is_file_too_large():
    with pytest.raises(FileTooLarge) as caught:
        inspect_upload(gen.oversized_jpeg(), "photo.jpg")

    assert (caught.value.code, caught.value.http_status) == ("FILE_TOO_LARGE", 413)


@given(blob=st.binary(max_size=2000), name=st.sampled_from(["a.jpg", "a.png", "a.pdf", "a.bin"]))
@settings(max_examples=60, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_random_bytes_are_never_accepted_nor_crash(blob, name):
    with pytest.raises(UnsupportedFile):
        inspect_upload(blob, name)


@given(tail=st.binary(max_size=500), magic=st.sampled_from([b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"%PDF-"]))
@settings(max_examples=60)
def test_magic_bytes_followed_by_garbage_only_ever_raise_unsupported_file(tail, magic):
    for name in ("a.jpg", "a.png", "a.pdf"):
        try:
            inspect_upload(magic + tail, name)
        except UnsupportedFile:
            continue


# ------------------------------------------------------------------ noms et stockage


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd.jpg",
        "..\\..\\windows\\system32\\x.jpg",
        "a" * 10_000 + ".jpg",
        "evil\x00name.jpg",
        "/abs/p.jpg",
    ],
)
def test_hostile_filename_is_accepted_and_only_kept_as_sanitized_metadata(name):
    result = inspect_upload(gen.jpeg_bytes(), name)

    assert result.ext == "jpg"
    cleaned = result.original_name
    assert len(cleaned) <= 255
    assert not any(c in cleaned for c in ("/", "\\", "\x00"))
    assert ".." + "/" not in cleaned


@given(name=st.text(max_size=400))
def test_sanitize_filename_never_returns_path_separators_nul_or_overlong_names(name):
    cleaned = sanitize_filename(name)

    assert len(cleaned) <= 255
    assert not any(c in cleaned for c in ("/", "\\", "\x00"))


def test_store_file_writes_uuid_name_inside_upload_dir_only(tmp_path):
    upload_dir = tmp_path / "uploads"
    result = inspect_upload(gen.jpeg_bytes(), "../../etc/passwd.jpg")

    stored = store_file(result, upload_dir)

    assert UUID_FILE.match(stored)
    assert stored.endswith(".jpg")
    assert (upload_dir / stored).read_bytes() == result.data
    assert hashlib.sha256((upload_dir / stored).read_bytes()).hexdigest() == result.sha256
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == [upload_dir / stored]


def test_store_file_leaves_no_temporary_file_and_names_are_unique(tmp_path):
    upload_dir = tmp_path / "uploads"
    result = inspect_upload(gen.pdf_bytes(), "a.pdf")

    first = store_file(result, upload_dir)
    second = store_file(result, upload_dir)

    assert first != second
    assert sorted(p.name for p in Path(upload_dir).iterdir()) == sorted([first, second])
