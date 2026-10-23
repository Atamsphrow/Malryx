"""Detection par empreinte : base de hash locale et VirusTotal (section 4.6).

Deux moteurs distincts dans ce fichier :

- `HashDBEngine`  : consultation hors-ligne de la table `known_hashes`. Toujours
  actif, cout negligeable, aucune donnee ne quitte la machine.
- `VirusTotalEngine` : consultation du cloud, strictement opt-in. Envoyer un
  SHA256 a un tiers revele qu'un fichier existe sur la machine, donc rien n'est
  transmis sans que l'option soit explicitement activee et une cle fournie.
  Les verdicts sont mis en cache en base pour respecter le quota de l'API
  publique (4 requetes/minute) et eviter de re-interroger sans cesse.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import TYPE_CHECKING

from core.models import DetectionSource, EngineStatus, Severity, Threat

from .base import Engine, FileContext

if TYPE_CHECKING:
    from db.local_db import LocalDB

log = logging.getLogger(__name__)

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover
    requests = None  # type: ignore
    REQUESTS_AVAILABLE = False


# --------------------------------------------------------------------------- #
# Base locale
# --------------------------------------------------------------------------- #


class HashDBEngine(Engine):
    name = "hash_local"
    source = DetectionSource.HASH_LOCAL

    def __init__(self, db: LocalDB, enabled: bool = True) -> None:
        self.db = db
        self.enabled = enabled

    def is_available(self) -> bool:
        return self.enabled

    def status(self) -> EngineStatus:
        count = self.db.count_known_hashes()
        return EngineStatus(
            name=self.name,
            available=self.enabled,
            signatures=count,
            detail=(
                "base locale vide, importez des signatures via "
                "POST /api/signatures/import"
                if count == 0
                else None
            ),
        )

    def scan(self, ctx: FileContext) -> list[Threat]:
        if not self.enabled:
            return []
        sha = ctx.sha256
        if not sha:
            return []
        hit = self.db.lookup_hash(sha)
        if not hit:
            return []
        try:
            severity = Severity(hit["severity"])
        except ValueError:
            severity = Severity.HIGH
        return [
            Threat(
                path=ctx.path,
                name=hit["name"],
                severity=severity,
                source=self.source,
                sha256=sha,
                size=ctx.size,
                details={"matched": "base de signatures locale"},
            )
        ]


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #

VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
CACHE_TTL_S = 7 * 24 * 3600
# Quota de l'API publique : 4 requetes/minute. On garde une marge.
RATE_LIMIT_CALLS = 4
RATE_LIMIT_WINDOW_S = 60.0
# Nombre de moteurs antivirus qui doivent flaguer le fichier avant qu'on parle
# de menace. En dessous, c'est presque toujours un faux positif.
MIN_MALICIOUS = 3


class RateLimiter:
    """Fenetre glissante simple, partagee entre les threads de scan."""

    def __init__(self, calls: int, window_s: float) -> None:
        self.calls = calls
        self.window_s = window_s
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self, block: bool = True) -> bool:
        """Rend True si l'appel est autorise. En mode non bloquant, False si le
        quota est epuise (le fichier est alors simplement ignore par VT)."""
        while True:
            with self._lock:
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] > self.window_s:
                    self._timestamps.popleft()
                if len(self._timestamps) < self.calls:
                    self._timestamps.append(now)
                    return True
                wait = self.window_s - (now - self._timestamps[0])
            if not block:
                return False
            time.sleep(min(max(wait, 0.05), self.window_s))


class VirusTotalEngine(Engine):
    name = "virustotal"
    source = DetectionSource.VIRUSTOTAL

    def __init__(
        self,
        db: LocalDB,
        api_key: str = "",
        enabled: bool = False,
        block_on_rate_limit: bool = False,
    ) -> None:
        self.db = db
        self.api_key = api_key.strip()
        self.enabled = enabled and bool(self.api_key) and REQUESTS_AVAILABLE
        self.block_on_rate_limit = block_on_rate_limit
        self._limiter = RateLimiter(RATE_LIMIT_CALLS, RATE_LIMIT_WINDOW_S)
        self._session = requests.Session() if REQUESTS_AVAILABLE else None
        self.queries = 0
        self.cache_hits = 0
        self.skipped_rate_limit = 0
        self._last_error: str | None = None

    def is_available(self) -> bool:
        return self.enabled

    def status(self) -> EngineStatus:
        if not REQUESTS_AVAILABLE:
            return EngineStatus(
                name=self.name, available=False, detail="module requests absent"
            )
        if not self.api_key:
            return EngineStatus(
                name=self.name, available=False, detail="aucune cle API configuree"
            )
        if not self.enabled:
            return EngineStatus(
                name=self.name, available=False, detail="desactive (opt-in)"
            )
        detail = f"{self.queries} requete(s), {self.cache_hits} depuis le cache"
        if self.skipped_rate_limit:
            detail += f", {self.skipped_rate_limit} ignoree(s) (quota)"
        if self._last_error:
            detail += f" - derniere erreur : {self._last_error}"
        return EngineStatus(name=self.name, available=True, detail=detail)

    def close(self) -> None:
        if self._session is not None:
            self._session.close()

    def scan(self, ctx: FileContext) -> list[Threat]:
        if not self.enabled:
            return []
        sha = ctx.sha256
        if not sha:
            return []

        verdict = self.db.get_cached_verdict(sha, CACHE_TTL_S)
        if verdict is not None:
            self.cache_hits += 1
        else:
            verdict = self._query(sha)
            if verdict is None:
                return []

        malicious = int(verdict.get("malicious", 0))
        if malicious < MIN_MALICIOUS:
            return []
        total = int(verdict.get("total", 0))
        label = verdict.get("label") or "VirusTotal-Detection"
        return [
            Threat(
                path=ctx.path,
                name=label,
                severity=self._severity_for(malicious, total),
                source=self.source,
                sha256=sha,
                size=ctx.size,
                details={
                    "malicious": malicious,
                    "total_engines": total,
                    "ratio": f"{malicious}/{total}" if total else None,
                    "permalink": f"https://www.virustotal.com/gui/file/{sha}",
                },
            )
        ]

    def _query(self, sha256: str) -> dict[str, object] | None:
        if not self._limiter.acquire(block=self.block_on_rate_limit):
            self.skipped_rate_limit += 1
            return None
        try:
            response = self._session.get(  # type: ignore[union-attr]
                VT_URL.format(sha256=sha256),
                headers={"x-apikey": self.api_key, "accept": "application/json"},
                timeout=20,
            )
        except Exception as exc:  # requests.RequestException et derives
            self._last_error = f"reseau : {exc}"
            log.debug("VirusTotal injoignable : %s", exc)
            return None

        self.queries += 1
        if response.status_code == 404:
            # Inconnu de VirusTotal : ce n'est pas un verdict propre, mais on le
            # met en cache pour ne pas redemander a chaque scan.
            self.db.cache_verdict(sha256, 0, 0, None)
            return {"malicious": 0, "total": 0, "label": None}
        if response.status_code == 401:
            self._last_error = "cle API refusee (401)"
            self.enabled = False  # inutile de continuer a marteler l'API
            log.warning("VirusTotal : cle API refusee, moteur desactive")
            return None
        if response.status_code == 429:
            self._last_error = "quota depasse (429)"
            self.skipped_rate_limit += 1
            return None
        if response.status_code != 200:
            self._last_error = f"HTTP {response.status_code}"
            return None

        try:
            attributes = response.json()["data"]["attributes"]
        except (KeyError, ValueError, TypeError) as exc:
            self._last_error = f"reponse illisible : {exc}"
            return None

        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
        label = (
            (attributes.get("popular_threat_classification") or {}).get(
                "suggested_threat_label"
            )
            or attributes.get("meaningful_name")
            or None
        )
        self.db.cache_verdict(sha256, malicious, total, label, {"stats": stats})
        self._last_error = None
        return {"malicious": malicious, "total": total, "label": label}

    @staticmethod
    def _severity_for(malicious: int, total: int) -> Severity:
        if total <= 0:
            return Severity.MEDIUM
        ratio = malicious / total
        if ratio >= 0.5:
            return Severity.CRITICAL
        if ratio >= 0.2:
            return Severity.HIGH
        return Severity.MEDIUM
