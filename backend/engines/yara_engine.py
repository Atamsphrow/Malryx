"""Moteur YARA (regles de detection par motifs).

`yara-python` est optionnel : s'il n'est pas installe, le moteur se declare
indisponible et le reste de l'application continue de fonctionner.

Les regles sont chargees depuis deux endroits :
  - backend/rules/  : regles livrees avec l'application (dans le .deb)
  - <data>/yara/    : regles ajoutees ou mises a jour par l'utilisateur,
                      sans reconstruire le paquet (section 7)
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from core.models import DetectionSource, EngineStatus, Severity, Threat

from .base import Engine, FileContext

log = logging.getLogger(__name__)

try:  # yara-python est optionnel
    import yara  # type: ignore

    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover
    yara = None  # type: ignore
    YARA_AVAILABLE = False

# Correspondance meta.severity -> Severity. Une regle sans meta prend HIGH.
_SEVERITY_MAP = {
    "clean": Severity.CLEAN,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

MAX_SCAN_SIZE = 64 * 1024 * 1024
SCAN_TIMEOUT_S = 30


class YaraEngine(Engine):
    name = "yara"
    source = DetectionSource.YARA

    def __init__(
        self,
        rule_dirs: list[Path] | None = None,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled and YARA_AVAILABLE
        self.rule_dirs = rule_dirs or []
        self._rules = None
        self._rule_count = 0
        self._error: str | None = None
        self._lock = threading.Lock()
        if self.enabled:
            self.reload()

    # -- chargement des regles ---------------------------------------------- #

    def reload(self) -> None:
        """(Re)compile toutes les regles. Sans effet si yara-python est absent."""
        if not YARA_AVAILABLE:
            self._error = "yara-python non installe"
            return
        sources: dict[str, str] = {}
        for directory in self.rule_dirs:
            if not directory.is_dir():
                continue
            for path in sorted(directory.rglob("*")):
                if path.suffix.lower() not in {".yar", ".yara"}:
                    continue
                try:
                    sources[path.stem] = path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    log.warning("regle YARA illisible %s : %s", path, exc)
        if not sources:
            self._rules = None
            self._rule_count = 0
            self._error = "aucune regle trouvee"
            return
        try:
            with self._lock:
                self._rules = yara.compile(sources=sources)  # type: ignore[union-attr]
            self._rule_count = len(sources)
            self._error = None
            log.info("YARA : %d fichier(s) de regles compile(s)", self._rule_count)
        except Exception as exc:  # yara.SyntaxError et derives
            # Une regle invalide ne doit pas empecher l'application de demarrer.
            self._rules = None
            self._error = f"compilation echouee : {exc}"
            log.error("compilation YARA echouee : %s", exc)

    def is_available(self) -> bool:
        return bool(self.enabled and self._rules is not None)

    def status(self) -> EngineStatus:
        if not YARA_AVAILABLE:
            return EngineStatus(
                name=self.name,
                available=False,
                detail="yara-python non installe (pip install yara-python)",
            )
        if not self.enabled:
            return EngineStatus(name=self.name, available=False, detail="desactive")
        return EngineStatus(
            name=self.name,
            available=self._rules is not None,
            version=getattr(yara, "__version__", None),
            signatures=self._rule_count,
            detail=self._error,
        )

    # -- analyse ------------------------------------------------------------ #

    def scan(self, ctx: FileContext) -> list[Threat]:
        if self._rules is None or ctx.size > MAX_SCAN_SIZE:
            return []
        try:
            with self._lock:
                matches = self._rules.match(ctx.path, timeout=SCAN_TIMEOUT_S)
        except Exception as exc:  # yara.Error, TimeoutError, OSError
            log.debug("YARA a echoue sur %s : %s", ctx.path, exc)
            return []

        threats: list[Threat] = []
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            severity = _SEVERITY_MAP.get(
                str(meta.get("severity", "")).lower(), Severity.HIGH
            )
            threats.append(
                Threat(
                    path=ctx.path,
                    name=meta.get("name") or match.rule,
                    severity=severity,
                    source=self.source,
                    sha256=ctx.sha256,
                    size=ctx.size,
                    details={
                        "rule": match.rule,
                        "tags": list(getattr(match, "tags", []) or []),
                        "description": meta.get("description"),
                        "author": meta.get("author"),
                        "strings": self._describe_strings(match),
                    },
                )
            )
        return threats

    @staticmethod
    def _describe_strings(match: object) -> list[str]:
        """Identifiants des chaines declenchees, sans le contenu brut.

        On ne remonte jamais les octets correspondants a l'UI : ils peuvent
        contenir des donnees sensibles issues d'un faux positif.
        """
        found: list[str] = []
        for item in getattr(match, "strings", []) or []:
            identifier = getattr(item, "identifier", None)
            if identifier is None and isinstance(item, tuple) and len(item) >= 2:
                identifier = item[1]  # API yara-python < 4.3
            if identifier:
                found.append(str(identifier))
        return sorted(set(found))[:20]
