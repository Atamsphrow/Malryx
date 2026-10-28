"""Protection en temps reel pour Malryx (section 4.1 de la specification).

Surveille les dossiers critiques et d'entree de donnees (Downloads, Temp, Autostart, Bureau) :
- Sous Linux : inotify natif via ctypes (libc) pour une reaction instantanee a la
  creation / ecriture de fichiers (IN_CLOSE_WRITE, IN_MOVED_TO, IN_CREATE) sans dependance externe.
- Repli / Windows : surveillance asynchrone par scrutation rapide des dossiers cles.

Durcissement lot 4 (2026-10-28, valide avec code local + man inotify(7) +
DeepSeek via TokenHarbor + GPT via Groq, tous d'accord) :
- Watches recursifs : un watch par sous-dossier, ajoute dynamiquement a
  IN_CREATE/IN_MOVED_TO avec IN_ISDIR, avec re-balayage du dossier nouveau
  (un fichier peut deja exister avant que le watch soit pose). Plafond
  lu dans /proc/sys/fs/inotify/max_user_watches (defaut 8192) : au-dela,
  un avertissement est journalise et les dossiers restants ne sont pas
  surveilles plutot que d'echouer silencieusement.
- Debounce + stabilite : un evenement ne declenche pas un scan immediat.
  Le fichier n'est scanne que si taille+mtime sont stables depuis 1 s, ou
  apres 10 s maximum d'attente (telechargement lent). Un fichier deja
  scanne dans sa version (mtime, taille) n'est pas re-scanne.
- Scan hors boucle : la boucle d'evenements ne fait que noter les
  fichiers ; le scan (bloquant : hash, ClamAV, YARA) tourne dans un
  executor, un fichier a la fois, pour ne pas perdre d'evenements.
- IN_Q_OVERFLOW : journalise, puis re-balayage des dossiers surveilles
  (seuls les fichiers absents du cache sont notes) pour resynchroniser.

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
import time
from dataclasses import dataclass, field
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
IN_IGNORED = 0x00008000
IN_Q_OVERFLOW = 0x00004000

WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE

# Debounce : stabilite requise avant scan, et attente maximale.
STABLE_DELAY_S = 1.0
MAX_WAIT_S = 10.0


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


def _max_watches() -> int:
    try:
        return int(Path("/proc/sys/fs/inotify/max_user_watches").read_text().strip())
    except (OSError, ValueError):
        return 8192


@dataclass
class _PendingFile:
    mtime: float
    size: int
    first_seen: float
    last_change: float


@dataclass
class DebounceQueue:
    """File d'attente debounce, testable sans asyncio ni AppState.

    note() met a jour taille/mtime : si ils n'ont pas change, les horloges
    ne bougent pas (le fichier est stable depuis last_change) ; sinon
    last_change avance mais first_seen reste (plafond MAX_WAIT_S).
    due() renvoie et retire les fichiers stables depuis STABLE_DELAY_S ou
    en attente depuis MAX_WAIT_S.
    """

    pending: dict[str, _PendingFile] = field(default_factory=dict)

    def note(self, path: str, mtime: float, size: int, now: float) -> None:
        entry = self.pending.get(path)
        if entry is not None and entry.mtime == mtime and entry.size == size:
            return
        if entry is not None:
            entry.mtime, entry.size, entry.last_change = mtime, size, now
            return
        self.pending[path] = _PendingFile(mtime, size, now, now)

    def due(self, now: float) -> list[str]:
        ready = [
            path
            for path, entry in self.pending.items()
            if now - entry.last_change >= STABLE_DELAY_S
            or now - entry.first_seen >= MAX_WAIT_S
        ]
        for path in ready:
            del self.pending[path]
        return ready

    def discard(self, path: str) -> None:
        self.pending.pop(path, None)


class RealtimeWatcher:
    def __init__(self, state: AppState) -> None:
        self.state = state
        self._running = False
        self._task: asyncio.Task | None = None
        self._debounce_task: asyncio.Task | None = None
        self._pending = DebounceQueue()
        self._scanned_cache: dict[str, tuple[float, int]] = {}  # path -> (mtime, size)
        self._overflow_rescan = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        log.info("Protection en temps reel demarree")

    def stop(self) -> None:
        self._running = False
        if self._debounce_task:
            self._debounce_task.cancel()
            self._debounce_task = None
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

    def _add_watch_recursive(self, libc, fd: int, root: str, wd_to_path: dict[int, str]) -> None:
        """Ajoute un watch pour root et chaque sous-dossier (sans suivre les liens)."""
        cap = _max_watches()
        for dirpath, dirnames, _filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                d for d in dirnames
                if not os.path.islink(os.path.join(dirpath, d))
            ]
            if len(wd_to_path) >= cap:
                log.warning(
                    "limite inotify atteinte (%d watches) : %s et ses sous-dossiers "
                    "ne sont plus surveilles en temps reel", cap, dirpath
                )
                return
            wd = libc.inotify_add_watch(fd, dirpath.encode("utf-8"), WATCH_MASK)
            if wd >= 0:
                wd_to_path[wd] = dirpath
            else:
                log.debug("watch inotify refuse pour %s", dirpath)

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

        wd_to_path: dict[int, str] = {}
        for d in get_monitored_directories():
            self._add_watch_recursive(libc, fd, d, wd_to_path)

        log.info("inotify actif sur %d repertoires", len(wd_to_path))

        loop = asyncio.get_running_loop()
        self._debounce_task = asyncio.create_task(self._run_debounce_loop(loop))
        try:
            while self._running:
                try:
                    raw_data = await loop.run_in_executor(None, self._read_inotify_fd, fd)
                    if raw_data:
                        self._process_inotify_events(raw_data, wd_to_path, libc, fd)
                except Exception as exc:
                    log.debug("Erreur lecture inotify : %s", exc)
                await asyncio.sleep(0.2)
        finally:
            if self._debounce_task:
                self._debounce_task.cancel()
                self._debounce_task = None
            os.close(fd)

    async def _run_debounce_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Scanne, un fichier a la fois dans un executor, les fichiers dus."""
        try:
            while self._running:
                if self._overflow_rescan:
                    self._overflow_rescan = False
                    self._sweep_monitored_directories()
                await self._process_pending(loop)
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

    async def _process_pending(self, loop: asyncio.AbstractEventLoop) -> None:
        for path in self._pending.due(time.monotonic()):
            try:
                await loop.run_in_executor(None, self._check_file_threat, path)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug("Erreur scan temps reel sur %s : %s", path, exc)

    def _read_inotify_fd(self, fd: int) -> bytes:
        try:
            # 4096 octets pour le buffer d'evenements
            return os.read(fd, 4096)
        except (BlockingIOError, OSError):
            return b""

    def _process_inotify_events(
        self, raw_data: bytes, wd_to_path: dict[int, str], libc, fd: int
    ) -> None:
        offset = 0
        while offset + 16 <= len(raw_data):
            wd, mask, cookie, length = struct.unpack_from("iIII", raw_data, offset)
            name_bytes = raw_data[offset + 16 : offset + 16 + length]
            name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            offset += 16 + length

            if mask & IN_Q_OVERFLOW:
                log.warning(
                    "file d'attente inotify debordee : des evenements ont ete "
                    "perdus, re-balayage des dossiers surveilles"
                )
                self._overflow_rescan = True
                continue
            if mask & IN_IGNORED:
                wd_to_path.pop(wd, None)
                continue
            if not name:
                continue
            base_dir = wd_to_path.get(wd)
            if not base_dir:
                continue
            filepath = os.path.join(base_dir, name)
            if mask & IN_ISDIR:
                if mask & (IN_CREATE | IN_MOVED_TO):
                    # Nouveau dossier : watch recursif + balayage de son
                    # contenu deja present (course watch/creation).
                    self._add_watch_recursive(libc, fd, filepath, wd_to_path)
                    self._sweep_directory(filepath)
                continue
            if mask & (IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO):
                self._note_file(filepath)

    def _note_file(self, path: str) -> None:
        """Note un fichier pour scan debounce, sauf deja scanne a l'identique."""
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                return
            stat = os.stat(path)
        except OSError:
            return
        if self._scanned_cache.get(path) == (stat.st_mtime, stat.st_size):
            return
        self._pending.note(path, stat.st_mtime, stat.st_size, time.monotonic())

    def _sweep_directory(self, root: str) -> None:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                d for d in dirnames
                if not os.path.islink(os.path.join(dirpath, d))
            ]
            for name in filenames:
                self._note_file(os.path.join(dirpath, name))

    def _sweep_monitored_directories(self) -> None:
        for d in get_monitored_directories():
            self._sweep_directory(d)

    async def _run_polling_loop(self) -> None:
        """Surveillance par scrutation (polling) sur dossiers cibles."""
        log.info("Protection temps reel en mode polling")
        # Amorcer le cache : seuls les changements ulterieurs declenchent.
        for d in get_monitored_directories():
            for dirpath, dirnames, filenames in os.walk(d, followlinks=False):
                dirnames[:] = [
                    dn for dn in dirnames
                    if not os.path.islink(os.path.join(dirpath, dn))
                ]
                for name in filenames:
                    path = os.path.join(dirpath, name)
                    try:
                        if os.path.islink(path):
                            continue
                        stat = os.stat(path)
                        self._scanned_cache[path] = (stat.st_mtime, stat.st_size)
                    except OSError:
                        pass

        loop = asyncio.get_running_loop()
        while self._running:
            for d in get_monitored_directories():
                for dirpath, dirnames, filenames in os.walk(d, followlinks=False):
                    dirnames[:] = [
                        dn for dn in dirnames
                        if not os.path.islink(os.path.join(dirpath, dn))
                    ]
                    for name in filenames:
                        self._note_file(os.path.join(dirpath, name))
            await self._process_pending(loop)
            await asyncio.sleep(3.0)

    def _check_file_threat(self, path: str) -> None:
        """Scanne un fichier detecte en temps reel et alerte/isole si menace."""
        if not os.path.exists(path) or not os.path.isfile(path) or os.path.islink(path):
            return

        # Ne jamais scanner le dossier de quarantaine ou les fichiers de log Malryx
        if str(self.state.paths.quarantine_dir) in path or str(self.state.paths.data_dir) in path:
            return

        try:
            size = os.path.getsize(path)
            if size == 0 or size > self.state.settings.max_file_size_mb * 1024 * 1024:
                return
            stat = os.stat(path)
            if self._scanned_cache.get(path) == (stat.st_mtime, stat.st_size):
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

            # Version scannee, menace ou non : ne pas re-scanner a l'identique.
            self._scanned_cache[path] = (stat.st_mtime, stat.st_size)

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
