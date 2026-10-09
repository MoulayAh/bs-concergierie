"""Controle des generateurs de fichiers de test (tests/fixtures/files)."""

import io

from PIL import Image

from tests.fixtures import files as gen


def test_jpeg_generator_has_magic_bytes_and_exif_marker():
    data = gen.jpeg_bytes()

    assert data.startswith(b"\xff\xd8\xff")
    assert gen.EXIF_MARKER in data
    assert gen.EXIF_MARKER not in gen.jpeg_bytes(exif=False)
    assert Image.open(io.BytesIO(data)).size == (64, 48)


def test_png_generator_has_magic_bytes_and_text_chunk():
    data = gen.png_bytes()

    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    assert b"png-text-marker" in data
    assert b"png-text-marker" not in gen.png_bytes(text_chunk=False)


def test_pdf_generator_builds_requested_page_count_and_forbidden_markers():
    assert gen.pdf_bytes().startswith(b"%PDF-")
    assert gen.pdf_bytes(pages=3).count(b"/Type /Page ") == 3
    markers = {
        "javascript": b"/JavaScript",
        "js": b"/JS",
        "openaction": b"/OpenAction",
        "launch": b"/Launch",
        "embedded": b"/EmbeddedFile",
        "aa": b"/AA",
    }
    for name, marker in markers.items():
        assert marker in gen.pdf_with_forbidden(name)
    assert b"/JavaScript" not in gen.pdf_bytes()


def test_trap_generators_have_the_expected_signatures():
    assert gen.exe_bytes().startswith(b"MZ")
    assert b"<script>" in gen.svg_bytes()
    assert gen.gif_bytes().startswith(b"GIF8")
    assert gen.zip_bytes().startswith(b"PK")
    assert b"ftypheic" in gen.heic_bytes()
    assert gen.empty_bytes() == b""
    assert len(gen.one_byte()) == 1
    assert len(gen.oversized_jpeg()) == gen.MAX_UPLOAD_BYTES + 1
    assert gen.truncated_jpeg().startswith(b"\xff\xd8\xff")


def test_bomb_generator_declares_400_million_pixels_in_a_small_file():
    data = gen.bomb_png()

    assert len(data) < 1_000_000
    assert data[16:24] == (20_000).to_bytes(4, "big") * 2
    assert gen.wide_png().startswith(b"\x89PNG")
