"""Configuration et emplacements sur disque.

Cible Debian : on suit la specification XDG. Sur les autres plateformes
(developpement sous Windows/macOS) on retombe sur un dossier equivalent afin que
le backend reste lancable et testable hors Linux.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

APP_NAME = "malryx"
APP_VERSION = "0.1.0"

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

# Port de la boucle locale. Le backend n'ecoute JAMAIS sur 0.0.0.0 : il est
# strictement local, lance en sous-processus par l'application Flutter.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def _xdg(var: str, fallback: str) -> Path:
    raw = os.environ.get(var)
    if raw:
        return Path(raw)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base)
    return Path.home() / fallback


@dataclass
class Paths:
    data_dir: Path
    config_dir: Path
    cache_dir: Path

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "malryx.db"

    @property
    def signatures_dir(self) -> Path:
        """Bases de hash locales, mises a jour sans reconstruire le .deb (section 7)."""
        return self.data_dir / "signatures"

    @property
    def yara_rules_dir(self) -> Path:
        return self.data_dir / "yara"

    @property
    def settings_path(self) -> Path:
        return self.config_dir / "settings.json"

    @property
    def log_path(self) -> Path:
        return self.data_dir / "malryx.log"

    def ensure(self) -> None:
        for directory in (
            self.data_dir,
            self.config_dir,
            self.cache_dir,
            self.quarantine_dir,
            self.signatures_dir,
            self.yara_rules_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        # La quarantaine contient des fichiers malveillants intacts : personne
        # d'autre que le proprietaire ne doit pouvoir y entrer.
        if not IS_WINDOWS:
            os.chmod(self.quarantine_dir, 0o700)


def default_paths() -> Paths:
    if IS_WINDOWS:
        base = _xdg("LOCALAPPDATA", "") / APP_NAME
        return Paths(base / "data", base / "config", base / "cache")
    return Paths(
        data_dir=_xdg("XDG_DATA_HOME", ".local/share") / APP_NAME,
        config_dir=_xdg("XDG_CONFIG_HOME", ".config") / APP_NAME,
        cache_dir=_xdg("XDG_CACHE_HOME", ".cache") / APP_NAME,
    )


PATHS = default_paths()


# --------------------------------------------------------------------------- #
# Reglages persistants (exposes via GET/PUT /api/settings)
# --------------------------------------------------------------------------- #

# Chemins jamais parcourus : pseudo-systemes de fichiers ou parcours infini,
# et le dossier de quarantaine lui-meme (sinon on se re-detecte en boucle).
DEFAULT_EXCLUDES: list[str] = [
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/.snapshots",
]


@dataclass
class Settings:
    realtime_protection: bool = False
    autoscan_removable: bool = True
    virustotal_enabled: bool = False
    virustotal_api_key: str = ""
    clamav_enabled: bool = True
    yara_enabled: bool = True
    heuristics_enabled: bool = True
    scan_archives: bool = True
    auto_quarantine: bool = False
    max_file_size_mb: int = 256
    excluded_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    scheduled_scan_cron: str = ""
    accent_color: str = "#FF00D9FF"

    def to_dict(self) -> dict[str, Any]:
        data = self.__dict__.copy()
        # On n'expose jamais la cle API en clair a l'UI, seulement sa presence.
        data["virustotal_api_key"] = ""
        data["virustotal_key_set"] = bool(self.virustotal_api_key)
        return data

    def apply(self, updates: dict[str, Any]) -> None:
        for key, value in updates.items():
            if key == "virustotal_key_set":
                continue
            # Une chaine vide envoyee par l'UI ne doit pas effacer la cle stockee.
            if key == "virustotal_api_key" and value == "":
                continue
            if hasattr(self, key):
                setattr(self, key, value)


def load_settings(paths: Paths | None = None) -> Settings:
    paths = paths or PATHS
    settings = Settings()
    try:
        raw = json.loads(paths.settings_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return settings
    settings.apply(raw)
    if isinstance(raw.get("virustotal_api_key"), str) and raw["virustotal_api_key"]:
        settings.virustotal_api_key = raw["virustotal_api_key"]
    return settings


def save_settings(settings: Settings, paths: Paths | None = None) -> None:
    paths = paths or PATHS
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    payload = settings.__dict__.copy()
    tmp = paths.settings_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if not IS_WINDOWS:
        os.chmod(tmp, 0o600)  # contient la cle VirusTotal
    tmp.replace(paths.settings_path)


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
