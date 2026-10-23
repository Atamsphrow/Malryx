"""Interface commune des moteurs de detection.

Chaque moteur recoit un `FileContext` et rend une liste de menaces (vide si
propre). Le contexte calcule le SHA256 et lit l'en-tete du fichier une seule
fois, quel que soit le nombre de moteurs actifs.
"""

from __future__ import annotations

import hashlib
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path

from core.models import DetectionSource, EngineStatus, Threat

log = logging.getLogger(__name__)

HEADER_BYTES = 4096
HASH_CHUNK = 1024 * 1024


class FileContext:
    """Vue paresseuse sur un fichier a analyser, partagee par tous les moteurs."""

    __slots__ = ("path", "_size", "_sha256", "_header", "_read_error", "inside_archive")

    def __init__(self, path: str | Path, size: int | None = None, inside_archive: bool = False):
        self.path = str(path)
        self._size = size
        self._sha256: str | None = None
        self._header: bytes | None = None
        self._read_error: str | None = None
        # Vrai quand le fichier a ete extrait d'une archive vers un dossier
        # temporaire : `path` n'est alors pas le chemin vu par l'utilisateur.
        self.inside_archive = inside_archive

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def suffix(self) -> str:
        return os.path.splitext(self.path)[1].lower()

    @property
    def size(self) -> int:
        if self._size is None:
            try:
                self._size = os.path.getsize(self.path)
            except OSError as exc:
                self._read_error = str(exc)
                self._size = 0
        return self._size

    @property
    def read_error(self) -> str | None:
        return self._read_error

    @property
    def sha256(self) -> str | None:
        if self._sha256 is None:
            digest = hashlib.sha256()
            try:
                with open(self.path, "rb") as handle:
                    while chunk := handle.read(HASH_CHUNK):
                        digest.update(chunk)
            except OSError as exc:
                self._read_error = str(exc)
                return None
            self._sha256 = digest.hexdigest()
        return self._sha256

    @property
    def header(self) -> bytes:
        if self._header is None:
            try:
                with open(self.path, "rb") as handle:
                    self._header = handle.read(HEADER_BYTES)
            except OSError as exc:
                self._read_error = str(exc)
                self._header = b""
        return self._header


class Engine(ABC):
    """Un moteur de detection."""

    name: str = "engine"
    source: DetectionSource = DetectionSource.HEURISTIC

    @abstractmethod
    def is_available(self) -> bool:
        """Le moteur peut-il reellement travailler sur cette machine ?"""

    @abstractmethod
    def status(self) -> EngineStatus:
        """Etat detaille, expose par /api/health."""

    @abstractmethod
    def scan(self, ctx: FileContext) -> list[Threat]:
        """Analyse un fichier. Ne doit jamais lever : capturer et journaliser."""

    def close(self) -> None:
        """Libere les ressources (sockets, handles) si necessaire."""
