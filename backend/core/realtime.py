"""Protection en temps reel pour Malryx (section 4.1 de la specification).

Surveille les dossiers critiques et d'entree de donnees (Downloads, Temp, Autostart, Bureau) :
- Sous Linux : inotify natif via ctypes (libc) pour une reaction instantanee a la
  creation / ecriture de fichiers (IN_CLOSE_WRITE, IN_MOVED_TO, IN_CREATE) sans dependance externe.
- Repli / Windows : surveillance asynchrone par scrutation rapide des dossiers cles.

Lorsqu'un nouveau fichier suspect ou modifie est detecte :
- Il traverse le pipeline de moteurs (HashDB, ClamAV, YARA, Heuristiques, VirusTotal).
- Si une menace est detectee, une alerte est publiee sur le bus WebSocket et
  la mise en quarantaine automatique est appliquee si le reglage est actif.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import logging
import os
import struct
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from core import events
from core.config import IS_LINUX, IS_WINDOWS
from core.models import DetectionSource, ScanOptions, Threat
from engines.base import FileContext

if TYPE_CHECKING:
    from core.app_state import AppState

log = logging.getLogger(__name__)

# Masques inotify Linux
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_ISDIR = 0x40000000

WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE


def get_monitored_directories() -> list[str]:
    """Retourne la liste des dossiers a surveiller en temps reel."""
    home = Path.home()
    dirs: list[Path] = [
        home / "Downloads",
        home / "Téléchargements",
        home / "Desktop",
        home / "Bureau",
        home / ".config" / "autostart",
        Path("/tmp"),
        Path("/var/tmp"),
        Path("/dev/shm"),
    ]
    if IS_WINDOWS:
        temp = os.environ.get("TEMP")
        if temp:
            dirs.append(Path(temp))
    return [str(d.resolve()) for d in dirs if d.exists() and d.is_dir()]


class RealtimeWatcher:
    def __init__(self, state: AppState) -> None:
        self.state = state
        self._running = False
        self._task: asyncio.Task | None = None
        self._scanned_files_cache: dict[str, float] = {}  # path -> mtime
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        log.info("Protection en temps reel demarree")

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        log.info("Protection en temps reel arretee")

    async def _run_loop(self) -> None:
        """Boucle principale de surveillance."""
        try:
            if IS_LINUX and self._can_use_inotify():
                await self._run_inotify_loop()
            else:
                await self._run_polling_loop()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.warning("Erreur dans la surveillance temps reel : %s", exc)

    def _can_use_inotify(self) -> bool:
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
            return hasattr(libc, "inotify_init1") and hasattr(libc, "inotify_add_watch")
        except Exception:
            return False

    async def _run_inotify_loop(self) -> None:
        """Surveillance via inotify ctypes sous Linux."""
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]

        # IN_NONBLOCK = 0o0004000 (0x800)
        fd = libc.inotify_init1(0x800)
        if fd < 0:
            log.warning("Impossible d'initialiser inotify, bascule vers polling")
            await self._run_polling_loop()
            return

        watch_dirs = get_monitored_directories()
        wd_to_path: dict[int, str] = {}
        for d in watch_dirs:
            wd = libc.inotify_add_watch(fd, d.encode("utf-8"), WATCH_MASK)
            if wd >= 0:
                wd_to_path[wd] = d

        log.info("inotify actif sur %d repertoires", len(wd_to_path))

        loop = asyncio.get_running_loop()
        try:
            while self._running:
                # Lecture non-bloquante avec asyncio
                try:
                    raw_data = await loop.run_in_executor(None, self._read_inotify_fd, fd)
                    if raw_data:
                        self._process_inotify_events(raw_data, wd_to_path)
                except Exception as exc:
                    log.debug("Erreur lecture inotify : %s", exc)
                await asyncio.sleep(1.0)
        finally:
            os.close(fd)

    def _read_inotify_fd(self, fd: int) -> bytes:
        try:
            # 4096 octets pour le buffer d'evenements
            return os.read(fd, 4096)
        except (BlockingIOError, OSError):
            return b""

    def _process_inotify_events(self, raw_data: bytes, wd_to_path: dict[int, str]) -> None:
        offset = 0
        while offset + 16 <= len(raw_data):
            wd, mask, cookie, length = struct.unpack_from("iIII", raw_data, offset)
            name_bytes = raw_data[offset + 16 : offset + 16 + length]
            name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            offset += 16 + length

            if not (mask & IN_ISDIR) and name:
                base_dir = wd_to_path.get(wd)
                if base_dir:
                    filepath = os.path.join(base_dir, name)
                    self._check_file_threat(filepath)

    async def _run_polling_loop(self) -> None:
        """Surveillance par scrutation (polling) sur dossiers cibles."""
        log.info("Protection temps reel en mode polling")
        # Initialiser le cache mtime
        monitored = get_monitored_directories()
        for d in monitored:
            try:
                for entry in os.scandir(d):
                    if entry.is_file():
                        self._scanned_files_cache[entry.path] = entry.stat().st_mtime
            except OSError:
                pass

        while self._running:
            monitored = get_monitored_directories()
            for d in monitored:
                try:
                    for entry in os.scandir(d):
                        if not entry.is_file():
                            continue
                        path = entry.path
                        try:
                            mtime = entry.stat().st_mtime
                            prev = self._scanned_files_cache.get(path)
                            if prev is None or mtime > prev:
                                self._scanned_files_cache[path] = mtime
                                self._check_file_threat(path)
                        except OSError:
                            pass
                except OSError:
                    pass
            await asyncio.sleep(3.0)

    def _check_file_threat(self, path: str) -> None:
        """Scanne un fichier detecte en temps reel et alerte/isole si menace."""
        if not os.path.exists(path) or not os.path.isfile(path):
            return

        # Ne jamais scanner le dossier de quarantaine ou les fichiers de log Malryx
        if str(self.state.paths.quarantine_dir) in path or str(self.state.paths.data_dir) in path:
            return

        try:
            size = os.path.getsize(path)
            if size == 0 or size > self.state.settings.max_file_size_mb * 1024 * 1024:
                return

            options = ScanOptions(
                use_clamav=self.state.settings.clamav_enabled,
                use_yara=self.state.settings.yara_enabled,
                use_heuristics=self.state.settings.heuristics_enabled,
                use_hash_db=True,
                use_virustotal=self.state.settings.virustotal_enabled,
            )
            engines = self.state.scans.build_engines(options)

            ctx = FileContext(path, size=size)
            threats: list[Threat] = []
            for engine in engines:
                if engine.source == DetectionSource.VIRUSTOTAL and threats:
                    continue
                try:
                    found = engine.scan(ctx)
                    if found:
                        threats.extend(found)
                except Exception as exc:
                    log.debug("erreur scan temps reel moteur %s : %s", engine.name, exc)

            for threat in threats:
                log.warning("MENACE DETECTEE EN TEMPS REEL : %s (%s)", threat.name, threat.path)
                threat.details["realtime"] = True

                if self.state.settings.auto_quarantine:
                    try:
                        entry = self.state.quarantine.quarantine_file(
                            threat.path,
                            threat_name=threat.name,
                            severity=threat.severity,
                            source=threat.source,
                        )
                        threat.quarantined = True
                        threat.details["quarantine_id"] = entry.id
                        log.info("Fichier mis en quarantaine automatique : %s", threat.path)
                    except OSError as exc:
                        log.error("Echec de la mise en quarantaine auto de %s : %s", threat.path, exc)

                # Publier l'alerte sur le bus pour notification immediate dans l'UI
                self.state.bus.publish_threadsafe(
                    events.EVT_SCAN_THREAT,
                    {"scan_id": "realtime", "threat": threat.model_dump(mode="json")},
                )
        except Exception as exc:
            log.debug("Erreur analyse temps reel sur %s : %s", path, exc)
