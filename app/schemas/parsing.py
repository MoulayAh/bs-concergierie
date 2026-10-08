"""Lecture du corps JSON et validation Pydantic -> exceptions metier typees."""

import json
import re
import unicodedata
from typing import Any

from pydantic import BaseModel, ValidationError

from app.domain.errors import InvalidAmount, ValidationFailed

_AMOUNT_FIELDS = frozenset({"deposit_cents", "amount_cents"})
_MAX_LISTED_ERRORS = 20
_MAX_FIELD_NAME = 64
_IDEMPOTENCY_KEY_RE = re.compile(r"^[\x21-\x7e]{1,255}$")


def _reject_constant(name: str) -> object:
    raise ValueError(f"constante JSON interdite : {name}")


def parse_json_body(raw: bytes, mimetype: str) -> object:
    """Decode un corps JSON obligatoire (le JSON `null` est un resultat valide pour ce decodeur)."""
    if not raw.strip():
        raise ValidationFailed("Corps JSON requis")
    if mimetype != "application/json" and not mimetype.endswith("+json"):
        raise ValidationFailed("Content-Type application/json requis")
    try:
        parsed: object = json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ValidationFailed("Corps JSON malforme") from exc
    return parsed


def validate_model[M: BaseModel](model: type[M], data: object) -> M:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        errors = exc.errors(include_url=False, include_context=False, include_input=False)
        listed: list[dict[str, Any]] = [
            {
                # Le nom d'une cle inconnue vient du client : jamais recopie.
                "field": "(champ inconnu)"
                if err["type"] == "extra_forbidden"
                else ".".join(str(part) for part in err["loc"])[:_MAX_FIELD_NAME],
                "message": err["msg"],
            }
            for err in errors[:_MAX_LISTED_ERRORS]
        ]
        details: dict[str, Any] = {"errors": listed}
        if len(errors) > _MAX_LISTED_ERRORS:
            details["truncated"] = True
        if any(err["loc"] and err["loc"][0] in _AMOUNT_FIELDS for err in errors):
            raise InvalidAmount(
                "La caution doit etre un entier en centimes compris entre 1 et 50000000",
                details=details,
            ) from exc
        raise ValidationFailed("Donnees invalides", details=details) from exc


def require_idempotency_key(value: str | None) -> str:
    if value is None:
        raise ValidationFailed("En-tete Idempotency-Key requis")
    if not _IDEMPOTENCY_KEY_RE.fullmatch(value):
        raise ValidationFailed("Idempotency-Key invalide (1 a 255 caracteres ASCII imprimables)")
    return value


def parse_idempotency_key(value: str | None, *, required: bool) -> str | None:
    if value is None and not required:
        return None
    return require_idempotency_key(value)


# Default_Ignorable_Code_Point (Python n'expose pas la propriete) + braille vide : s'affichent vides.
_INVISIBLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x2800, 0x2800),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def _is_invisible(char: str) -> bool:
    code = ord(char)
    return any(low <= code <= high for low, high in _INVISIBLE_RANGES)


def has_forbidden_chars(value: str, *, allow_newlines: bool = False) -> bool:
    """Controle (Cc), surrogates isoles (Cs) et formatage invisible/bidi (Cf, ex. U+202E, U+200B)."""
    for char in value:
        if allow_newlines and char in "\n\t":
            continue
        if unicodedata.category(char) in {"Cc", "Cs", "Cf"} or _is_invisible(char):
            return True
    return False


def has_visible_char(value: str) -> bool:
    """Au moins une lettre, un chiffre, un symbole ou une ponctuation (pas seulement espaces/marques)."""
    return any(
        unicodedata.category(char)[0] in {"L", "N", "S", "P"} and not _is_invisible(char) for char in value
    )
