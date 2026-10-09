"""Etat des lieux : canonisation, empreinte, message signe et cycle de vie (domaine pur, sans Flask ni DB).

Les enums sont dupliques dans ``app.models.enums`` (miroir des ENUM PostgreSQL) ;
le service les convertit par valeur.
"""

import enum
import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final

from app.domain.errors import InvalidTransition

SCHEMA: Final = "luxe-escrow/report/v1"
SIGNING_PREFIX: Final = b"luxe-escrow:report:v1:"


class ReportKind(enum.StrEnum):
    CHECKOUT = "checkout"
    RETURN = "return"


class ReportStatus(enum.StrEnum):
    DRAFT = "DRAFT"
    FROZEN = "FROZEN"
    SIGNED = "SIGNED"
    SUPERSEDED = "SUPERSEDED"


class ReportAction(enum.StrEnum):
    EDIT = "edit"
    ADD_FILE = "add_file"
    REMOVE_FILE = "remove_file"
    FINALIZE = "finalize"
    SIGN = "sign"
    SUPERSEDE = "supersede"


_EDITS: Final = frozenset({ReportAction.EDIT, ReportAction.ADD_FILE, ReportAction.REMOVE_FILE})


def canonical_bytes(content: Mapping[str, Any]) -> bytes:
    """Forme canonique : cles triees, sans espace, UTF-8 non echappe, fichiers tries par ``sha256``."""
    obj: dict[str, Any] = dict(content)
    if "files" in obj:
        obj["files"] = sorted(obj["files"], key=lambda item: item["sha256"])
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_report_hash(content: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(content)).hexdigest()


def signing_message(contract_id: str, kind: ReportKind | str, report_hash: str) -> bytes:
    """Message signe, avec separation de domaine (contrat + type de rapport + empreinte)."""
    kind_value = kind.value if isinstance(kind, ReportKind) else kind
    return SIGNING_PREFIX + contract_id.encode() + b":" + kind_value.encode() + b":" + report_hash.encode()


def next_status(status: ReportStatus, action: ReportAction, *, signatures: int = 0) -> ReportStatus:
    """Etat suivant d'un rapport ; ne mute rien. Toute combinaison hors table => ``InvalidTransition``.

    ``signatures`` : nombre de signatures APRES l'action pour SIGN, nombre actuel pour SUPERSEDE.
    """
    if action in _EDITS and status is not ReportStatus.DRAFT:
        reason = "REPORT_SUPERSEDED" if status is ReportStatus.SUPERSEDED else "REPORT_FROZEN"
        raise InvalidTransition(
            "Le rapport n'est plus modifiable", details={"reason": reason, "status": status.value}
        )
    if status is ReportStatus.DRAFT:
        if action in _EDITS:
            return ReportStatus.DRAFT
        if action is ReportAction.FINALIZE:
            return ReportStatus.FROZEN
    elif status is ReportStatus.FROZEN:
        if action is ReportAction.SIGN and signatures in (1, 2):
            return ReportStatus.SIGNED if signatures == 2 else ReportStatus.FROZEN
        if action is ReportAction.SUPERSEDE and 0 <= signatures < 2:
            return ReportStatus.SUPERSEDED
    raise InvalidTransition(
        f"L'action '{action.value}' est interdite pour un rapport {status.value}",
        details={"status": status.value},
    )
