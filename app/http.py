"""Classe de requete : les fichiers multipart restent en memoire (bornes par MAX_CONTENT_LENGTH).

Evite les fichiers temporaires de Werkzeug, qui fuient (descripteurs ouverts) quand le parsing est interrompu
par un 413.
"""

import io
from typing import IO

from flask import Request


class MemoryUploadRequest(Request):
    def _get_file_stream(
        self,
        total_content_length: int | None,
        content_type: str | None,
        filename: str | None = None,
        content_length: int | None = None,
    ) -> IO[bytes]:
        return io.BytesIO()
