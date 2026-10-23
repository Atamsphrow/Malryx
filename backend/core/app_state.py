"""Etat applicatif partage : base, reglages, quarantaine, gestionnaire de scans.

Un seul point d'assemblage, injecte dans les routes via `get_state()`. Cela
permet aussi a la CLI de construire exactement le meme etat que le serveur, sans
FastAPI.
"""

from __future__ import annotations

import logging
from pathlib import Path

from core.config import PATHS, Paths, Settings, load_settings, save_settings
from core.events import bus
from core.quarantine import QuarantineManager
from core.realtime import RealtimeWatcher
from core.scan_engine import ScanManager
from core.scheduler import ScanScheduler
from db.local_db import LocalDB

log = logging.getLogger(__name__)


class AppState:
    def __init__(self, paths: Paths | None = None) -> None:
        self.paths = paths or PATHS
        self.paths.ensure()
        self.settings: Settings = load_settings(self.paths)
        self.db = LocalDB(self.paths.db_path)
        self.quarantine = QuarantineManager(self.db, self.paths)
        self.bus = bus
        self.scans = ScanManager(
            db=self.db,
            settings=self.settings,
            quarantine=self.quarantine,
            bus=self.bus,
        )
        self.realtime = RealtimeWatcher(self)
        self.scheduler = ScanScheduler(self)
        self._import_bundled_signatures()

    def _import_bundled_signatures(self) -> None:
        """Charge les signatures livrees avec l'application au premier demarrage.

        Format attendu, une entree par ligne :
            <sha256>:<nom>:<severite>
        Les lignes vides et celles commencant par # sont ignorees.
        """
        if self.db.count_known_hashes() > 0:
            return
        candidates = [
            Path(__file__).resolve().parent.parent / "signatures" / "bundled.hashes",
            self.paths.signatures_dir / "bundled.hashes",
        ]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            imported = self.import_signature_file(candidate)
            log.info("%d signature(s) importee(s) depuis %s", imported, candidate)
            return

    def import_signature_file(self, path: Path) -> int:
        entries: list[tuple[str, str, str]] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            log.warning("fichier de signatures illisible %s : %s", path, exc)
            return 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            sha, name = parts[0].strip(), parts[1].strip()
            severity = parts[2].strip() if len(parts) > 2 else "high"
            entries.append((sha, name, severity))
        return self.db.add_known_hashes(entries)

    def update_settings(self, updates: dict) -> Settings:
        self.settings.apply(updates)
        save_settings(self.settings, self.paths)
        self.scans.reload_engines()
        if self.settings.realtime_protection:
            self.realtime.start()
        else:
            self.realtime.stop()
        if self.settings.scheduled_scan_cron:
            self.scheduler.start()
        else:
            self.scheduler.stop()
        return self.settings

    def shutdown(self) -> None:
        self.scheduler.stop()
        self.realtime.stop()
        self.scans.shutdown()
        self.db.close()


_state: AppState | None = None


def init_state(paths: Paths | None = None) -> AppState:
    global _state
    if _state is None:
        _state = AppState(paths)
    return _state


def get_state() -> AppState:
    """Dependance FastAPI. Leve si l'application n'est pas encore demarree."""
    if _state is None:
        raise RuntimeError("etat applicatif non initialise")
    return _state


def reset_state() -> None:
    """Utilise par les tests pour repartir d'un etat propre."""
    global _state
    if _state is not None:
        _state.shutdown()
    _state = None
