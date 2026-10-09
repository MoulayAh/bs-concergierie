"""Generateurs de fichiers de test (octets produits a la volee, jamais commites). Aucun vrai malware.

Chaque fonction renvoie des ``bytes``. Les charges "piegees" sont inertes : de simples marqueurs textuels
(``/JavaScript``, ``<script>``, en-tete ``MZ``...) que le pipeline d'upload doit refuser.
"""

import io
import struct
import zipfile
import zlib

from PIL import Image, PngImagePlugin

EXIF_MARKER = b"LeakyCam-9000"
EXIF_ARTIST = "secret-artist-marker"
PNG_TEXT_MARKER = "<script>alert('png-text-marker')</script>"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def jpeg_bytes(
    size: tuple[int, int] = (64, 48), color: tuple[int, int, int] = (200, 30, 30), exif: bool = True
) -> bytes:
    """JPEG valide ; avec ``exif=True`` il porte des marqueurs EXIF (modele + artiste) a faire disparaitre."""
    image = Image.new("RGB", size, color)
    buffer = io.BytesIO()
    if exif:
        tags = Image.Exif()
        tags[0x0110] = EXIF_MARKER.decode()  # Model
        tags[0x013B] = EXIF_ARTIST  # Artist
        image.save(buffer, "JPEG", exif=tags.tobytes())
    else:
        image.save(buffer, "JPEG")
    return buffer.getvalue()


def png_bytes(
    size: tuple[int, int] = (64, 48), color: tuple[int, int, int] = (30, 30, 200), text_chunk: bool = True
) -> bytes:
    """PNG valide ; avec ``text_chunk=True`` un bloc tEXt contient du HTML a supprimer."""
    image = Image.new("RGB", size, color)
    buffer = io.BytesIO()
    if text_chunk:
        info = PngImagePlugin.PngInfo()
        info.add_text("Comment", PNG_TEXT_MARKER)
        image.save(buffer, "PNG", pnginfo=info)
    else:
        image.save(buffer, "PNG")
    return buffer.getvalue()


def distinct_jpeg(index: int) -> bytes:
    """JPEG different pour chaque ``index`` (contenus et empreintes distincts)."""
    return jpeg_bytes(color=(index * 11 % 256, index * 53 % 256, index * 97 % 256), size=(32 + index, 32))


def pdf_bytes(pages: int = 1, catalog_extra: bytes = b"", page_extra: bytes = b"") -> bytes:
    """PDF minimal sain (xref correct). ``catalog_extra`` / ``page_extra`` injectent des cles inertes."""
    objects: list[bytes] = []
    kids = b" ".join(f"{3 + i} 0 R".encode() for i in range(pages))
    objects.append(b"<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b" >>")
    objects.append(b"<< /Type /Pages /Count " + str(pages).encode() + b" /Kids [" + kids + b"] >>")
    for _ in range(pages):
        objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] " + page_extra + b" >>")
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref_at = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n")
    for offset in offsets:
        out.write(f"{offset:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode())
    return out.getvalue()


PDF_FORBIDDEN_CATALOG_EXTRAS: dict[str, bytes] = {
    "javascript": b"/Names << /JavaScript << /Names [(a) << /S /JavaScript /JS (inert) >>] >> >>",
    "js": b"/Foo << /S /Bar /JS (inert) >>",
    "openaction": b"/OpenAction << /S /GoTo /D [3 0 R /Fit] >>",
    "launch": b"/Foo << /S /Launch /F (inert.txt) >>",
    "embedded": b"/Names << /EmbeddedFiles << /Names [] >> >> /Foo /EmbeddedFile",
    "aa": b"/AA << /O << /S /GoTo >> >>",
}


def pdf_with_forbidden(name: str) -> bytes:
    return pdf_bytes(catalog_extra=PDF_FORBIDDEN_CATALOG_EXTRAS[name])


def exe_bytes() -> bytes:
    """En-tete DOS ``MZ`` inerte (pas un executable reel)."""
    return b"MZ" + b"\x90\x00" * 30 + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 200


def svg_bytes() -> bytes:
    return b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def gif_bytes() -> bytes:
    buffer = io.BytesIO()
    Image.new("P", (8, 8), 1).save(buffer, "GIF")
    return buffer.getvalue()


def zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "inerte")
    return buffer.getvalue()


def heic_bytes() -> bytes:
    """Boite ``ftyp heic`` seule : suffisante pour la detection par magic bytes."""
    return b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heicmif1" + b"\x00" * 64


def empty_bytes() -> bytes:
    return b""


def one_byte() -> bytes:
    return b"\xff"


def truncated_jpeg() -> bytes:
    data = jpeg_bytes(size=(200, 200), exif=False)
    return data[: len(data) // 2]


def oversized_jpeg() -> bytes:
    """Un octet de plus que la limite de 10 Mo, en-tete JPEG valide puis remplissage."""
    return b"\xff\xd8\xff\xe0" + b"\x00" * (MAX_UPLOAD_BYTES + 1 - 4)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def bomb_png(width: int = 20_000, height: int = 20_000) -> bytes:
    """PNG 1 bit en niveaux de gris de ``width`` x ``height`` : quelques dizaines de Ko compresses.

    Construit a la main (jamais materialise en memoire cote test) ; 400 millions de pixels une fois decode.
    """
    header = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 1, 0, 0, 0, 0))
    row = b"\x00" * (1 + (width + 7) // 8)
    compressor = zlib.compressobj(9)
    parts = []
    for _ in range(height):
        parts.append(compressor.compress(row))
    parts.append(compressor.flush())
    return b"\x89PNG\r\n\x1a\n" + header + _png_chunk(b"IDAT", b"".join(parts)) + _png_chunk(b"IEND", b"")


def wide_png(width: int = 8001, height: int = 10) -> bytes:
    """PNG leger dont une dimension depasse la limite de 8000 px."""
    buffer = io.BytesIO()
    Image.new("L", (width, height), 7).save(buffer, "PNG")
    return buffer.getvalue()


def pdf_pages(count: int) -> bytes:
    return pdf_bytes(pages=count)
