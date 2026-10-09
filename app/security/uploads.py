"""Pipeline d'upload securise : type reel par magic bytes, re-encodage des images, controle des PDF.

Le nom client n'est jamais utilise pour le stockage (``<uuid4>.<ext>`` dans ``UPLOAD_DIR``) ; il n'est
garde que nettoye, comme metadonnee. Le SHA-256 est calcule sur les octets effectivement stockes.
"""

import hashlib
import io
import logging
import os
import re
import unicodedata
import uuid
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from PIL import Image

from app.domain.errors import FileTooLarge, UnsupportedFile

MAX_UPLOAD_BYTES: Final = 10 * 1024 * 1024
MAX_IMAGE_SIDE: Final = 8000
MAX_PDF_PAGES: Final = 20
MAX_NAME_LENGTH: Final = 255
STORED_NAME_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.(jpg|png|pdf)$"
)

# Anti decompression bomb : au-dela de 2x cette valeur Pillow leve DecompressionBombError a l'ouverture.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_SIDE * MAX_IMAGE_SIDE

_log = logging.getLogger(__name__)

_JPEG_MAGIC: Final = b"\xff\xd8\xff"
_PNG_MAGIC: Final = b"\x89PNG\r\n\x1a\n"
_PDF_MAGIC: Final = b"%PDF-"
_ALLOWED_EXTENSIONS: Final = {
    "image/jpeg": frozenset({"jpg", "jpeg"}),
    "image/png": frozenset({"png"}),
    "application/pdf": frozenset({"pdf"}),
}
_STORED_EXTENSION: Final = {"image/jpeg": "jpg", "image/png": "png", "application/pdf": "pdf"}
_PIL_FORMAT: Final = {"image/jpeg": "JPEG", "image/png": "PNG"}

_PDF_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_PDF_FORBIDDEN = re.compile(
    rb"/(?:ObjStm|XRefStm|Encrypt|URI|GoToR|GoToE|SubmitForm|ImportData|XFA|RichMedia|Launch"
    rb"|JavaScript|OpenAction|EmbeddedFile)"
    rb"|/(?:JS|AA)(?![A-Za-z0-9])"
)
_PDF_PAGE = re.compile(rb"/Type\s*/Page(?![A-Za-z])")
_PDF_COUNT = re.compile(rb"/Count\s+(\d{1,9})")


@dataclass(frozen=True)
class InspectedFile:
    data: bytes
    mime: str
    ext: str
    sha256: str
    size_bytes: int
    width: int | None
    height: int | None
    original_name: str


def sanitize_filename(name: str) -> str:
    """Nom d'origine nettoye (metadonnee seulement) : sans chemin, sans controle, 255 caracteres au plus."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join(c for c in base if unicodedata.category(c) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}).strip()
    if base in {"", ".", ".."}:
        return "fichier"
    if len(base) > MAX_NAME_LENGTH:
        stem, dot, ext = base.rpartition(".")
        if dot and 0 < len(ext) <= 16:
            base = stem[: MAX_NAME_LENGTH - 1 - len(ext)] + "." + ext
        else:
            base = base[:MAX_NAME_LENGTH]
    return base


def _detect_mime(data: bytes) -> str:
    if data.startswith(_JPEG_MAGIC):
        return "image/jpeg"
    if data.startswith(_PNG_MAGIC):
        return "image/png"
    if data.startswith(_PDF_MAGIC):
        return "application/pdf"
    raise UnsupportedFile("Type de fichier refuse : JPEG, PNG ou PDF uniquement")


def _declared_extension(clean_name: str) -> str:
    stem, dot, ext = clean_name.rpartition(".")
    return ext.lower() if dot and stem else ""


def _check_image_header(pil_format: str | None, mime: str, width: int, height: int) -> None:
    if pil_format != _PIL_FORMAT[mime]:
        raise UnsupportedFile("Le contenu de l'image ne correspond pas a son type")
    if not (0 < width <= MAX_IMAGE_SIDE and 0 < height <= MAX_IMAGE_SIDE):
        raise UnsupportedFile(f"Dimensions limitees a {MAX_IMAGE_SIDE}x{MAX_IMAGE_SIDE} pixels")


def _reencode_image(data: bytes, mime: str) -> tuple[bytes, int, int]:
    """Ouvre, verifie puis re-encode l'image : EXIF, blocs texte et octets parasites disparaissent."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                width, height = probe.size
                _check_image_header(probe.format, mime, width, height)
                probe.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.load()  # decode tout : un fichier tronque ou corrompu leve ici
                clean = image.copy()
                clean.info = {}
                out = io.BytesIO()
                if mime == "image/jpeg":
                    clean.save(out, "JPEG", quality=95)
                else:
                    clean.save(out, "PNG")
    except UnsupportedFile:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise UnsupportedFile("Image trop volumineuse une fois decodee") from exc
    except Exception as exc:  # Pillow leve des types varies sur un fichier hostile : tout est 415
        _log.info("Image refusee : %s", type(exc).__name__)
        raise UnsupportedFile("Image illisible ou corrompue") from exc
    return out.getvalue(), width, height


def _check_pdf(data: bytes) -> None:
    if b"%%EOF" not in data[-2048:]:
        raise UnsupportedFile("PDF incomplet ou corrompu")
    if any(marker in data for marker in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x01\x02")):
        raise UnsupportedFile("PDF refuse : archive ZIP embarquee (polyglotte)")
    # Un nom PDF peut s'ecrire avec des escapes hexadecimaux (/Java#53cript) : on normalise avant de chercher.
    flat = _PDF_HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data)
    if _PDF_FORBIDDEN.search(flat):
        raise UnsupportedFile("PDF refuse : contenu actif ou fichier embarque")
    pages = len(_PDF_PAGE.findall(flat))
    declared = max((int(m) for m in _PDF_COUNT.findall(flat)), default=0)
    if max(pages, declared) > MAX_PDF_PAGES:
        raise UnsupportedFile(f"PDF refuse : plus de {MAX_PDF_PAGES} pages")


def inspect_upload(data: bytes, filename: str) -> InspectedFile:
    """Valide un fichier televerse ; leve ``FileTooLarge`` (413) ou ``UnsupportedFile`` (415)."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise FileTooLarge("Fichier trop volumineux (10 Mo maximum)")
    if len(data) < len(_PDF_MAGIC):
        raise UnsupportedFile("Fichier vide ou trop court")
    mime = _detect_mime(data)
    clean_name = sanitize_filename(filename)
    if _declared_extension(clean_name) not in _ALLOWED_EXTENSIONS[mime]:
        raise UnsupportedFile("L'extension ne correspond pas au type reel du fichier")

    width: int | None = None
    height: int | None = None
    stored = data
    if mime == "application/pdf":
        _check_pdf(data)
    else:
        stored, width, height = _reencode_image(data, mime)
        if len(stored) > MAX_UPLOAD_BYTES:
            raise FileTooLarge("Fichier trop volumineux apres re-encodage (10 Mo maximum)")
    return InspectedFile(
        data=stored,
        mime=mime,
        ext=_STORED_EXTENSION[mime],
        sha256=hashlib.sha256(stored).hexdigest(),
        size_bytes=len(stored),
        width=width,
        height=height,
        original_name=clean_name,
    )


def store_file(inspected: InspectedFile, upload_dir: str | Path) -> str:
    """Ecrit sous ``<uuid4>.<ext>`` : fichier temporaire dans le meme dossier puis deplacement atomique."""
    root = Path(upload_dir)
    root.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4()}.{inspected.ext}"
    temp_path = root / f".tmp-{uuid.uuid4().hex}"
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(inspected.data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, root / stored_name)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
    return stored_name


def stored_path(upload_dir: str | Path, stored_name: str) -> Path:
    """Chemin d'un fichier stocke ; refuse tout nom qui ne soit pas ``<uuid4>.<ext>``."""
    if STORED_NAME_RE.fullmatch(stored_name) is None:
        raise ValueError("nom de fichier stocke invalide")
    return Path(upload_dir) / stored_name


def delete_stored(upload_dir: str | Path, stored_name: str) -> None:
    stored_path(upload_dir, stored_name).unlink(missing_ok=True)
