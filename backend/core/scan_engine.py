"""Orchestrateur de scan : enumeration, pipeline de moteurs, progression, annulation.

Un scan vit dans un thread de travail (les I/O disque et les appels ClamAV sont
bloquants) et communique avec la boucle asyncio uniquement via le bus
d'evenements. L'API ne fait qu'enregistrer une intention et lire l'etat.

Deroulement d'un scan de fichiers :
  1. phase "enumeration" : on compte les fichiers eligibles sans les lire, pour
     pouvoir afficher un pourcentage. On ne stocke pas la liste (un scan complet
     de systeme peut depasser le million de fichiers).
  2. phase "analyse" : second parcours, chaque fichier traverse le pipeline de
     moteurs jusqu'a epuisement.
  3. phase "archives" : les archives rencontrees sont extraites dans un dossier
     temporaire et leur contenu repasse dans le pipeline.
"""

from __future__ import annotations

import logging
import os
import shutil
import tarfile
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core import events
from core.config import Settings
from core.events import EventBus
from core.models import (
    DetectionSource,
    ScanOptions,
    ScanProgress,
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanType,
    Threat,
)
from core.package_scanner import list_installed_packages, verify_package_integrity
from core.cve_checker import check_packages_cve
from core.platform_compat import IS_WINDOWS, have_command, run
from core.process_scanner import list_running_processes
from core.quarantine import QuarantineManager
from db.local_db import LocalDB
from engines.base import Engine, FileContext
from engines.clamav_engine import ClamAVEngine
from engines.hash_checker import HashDBEngine, VirusTotalEngine
from engines.heuristics import HeuristicEngine
from engines.yara_engine import YaraEngine

log = logging.getLogger(__name__)

# Cadence de publication de la progression. Plus court sature le WebSocket sans
# que l'oeil humain y gagne quoi que ce soit.
PROGRESS_INTERVAL_S = 0.2

# Duree pendant laquelle un scan termine reste consultable en memoire, le temps
# que l'UI recupere son resultat final. La purge est paresseuse : declencher un
# thread minuteur par scan empecherait le processus de se terminer.
JOB_RETENTION_S = 120.0

ARCHIVE_SUFFIXES = {
    ".zip", ".jar", ".apk", ".tar", ".gz", ".tgz", ".bz2", ".tbz2",
    ".xz", ".txz", ".rar", ".7z",
}
# Garde-fous anti-bombe de decompression.
ARCHIVE_MAX_TOTAL_BYTES = 1024 * 1024 * 1024   # 1 Gio extraits au maximum
ARCHIVE_MAX_MEMBERS = 10_000
ARCHIVE_MAX_RATIO = 200                        # taille extraite / taille compressee

# Cibles du scan des points de demarrage (section 4.1).
STARTUP_TARGETS = [
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
    "/etc/cron.monthly", "/etc/crontab", "/var/spool/cron",
    "/etc/systemd/system", "/usr/local/lib/systemd/system", "/lib/systemd/system",
    "/etc/init.d", "/etc/rc.local", "/etc/xdg/autostart",
    "/etc/profile.d", "/etc/ld.so.preload",
]


def _user_startup_targets() -> list[str]:
    home = Path.home()
    return [
        str(home / ".config/autostart"),
        str(home / ".config/systemd/user"),
        str(home / ".bashrc"),
        str(home / ".bash_profile"),
        str(home / ".profile"),
        str(home / ".zshrc"),
    ]


class ScanCancelled(Exception):
    """Levee dans le thread de scan quand l'utilisateur annule."""


class ScanJob:
    """Etat vivant d'un scan en cours."""

    def __init__(self, result: ScanResult, options: ScanOptions) -> None:
        self.result = result
        self.options = options
        self.cancel_event = threading.Event()
        self.progress = ScanProgress(scan_id=result.id, status=ScanStatus.PENDING)
        self.started_monotonic = time.monotonic()
        self.finished_monotonic: float | None = None

    @property
    def id(self) -> str:
        return self.result.id

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise ScanCancelled()


class ScanManager:
    def __init__(
        self,
        db: LocalDB,
        settings: Settings,
        quarantine: QuarantineManager,
        bus: EventBus,
        max_concurrent: int = 3,
    ) -> None:
        self.db = db
        self.settings = settings
        self.quarantine = quarantine
        self.bus = bus
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(
            max_workers=max_concurrent, thread_name_prefix="scan"
        )
        # Moteur ClamAV reutilise entre les scans : la detection du daemon et le
        # chargement des regles YARA ont un cout qu'on ne veut pas repayer.
        self._clamav = ClamAVEngine(enabled=settings.clamav_enabled)
        self._yara = YaraEngine(
            rule_dirs=self._yara_dirs(), enabled=settings.yara_enabled
        )

    @staticmethod
    def _yara_dirs() -> list[Path]:
        from core.config import PATHS

        bundled = Path(__file__).resolve().parent.parent / "rules"
        return [bundled, PATHS.yara_rules_dir]

    def shutdown(self) -> None:
        with self._lock:
            for job in self._jobs.values():
                job.cancel_event.set()
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._clamav.close()
        self._yara.close()

    # -- construction du pipeline ------------------------------------------- #

    def build_engines(
        self, options: ScanOptions, removable: bool = False
    ) -> list[Engine]:
        """Ordonne les moteurs du moins cher au plus cher.

        La base de hash locale est quasi gratuite, VirusTotal coute une requete
        reseau et une part du quota : il passe en dernier et est saute si le
        fichier est deja identifie comme menace.
        """
        engines: list[Engine] = []
        if options.use_hash_db:
            engines.append(HashDBEngine(self.db))
        if options.use_clamav and self._clamav.is_available():
            engines.append(self._clamav)
        if options.use_yara and self._yara.is_available():
            engines.append(self._yara)
        if options.use_heuristics:
            engines.append(HeuristicEngine(removable_context=removable))
        if options.use_virustotal and self.settings.virustotal_api_key:
            engines.append(
                VirusTotalEngine(
                    self.db,
                    api_key=self.settings.virustotal_api_key,
                    enabled=True,
                )
            )
        return engines

    def engine_status(self) -> list:
        from engines.hash_checker import HashDBEngine as _HashDB
        from engines.hash_checker import VirusTotalEngine as _VT

        return [
            _HashDB(self.db).status(),
            self._clamav.status(),
            self._yara.status(),
            HeuristicEngine().status(),
            _VT(
                self.db,
                api_key=self.settings.virustotal_api_key,
                enabled=self.settings.virustotal_enabled,
            ).status(),
        ]

    def reload_engines(self) -> None:
        """Appele apres une modification des reglages ou des regles YARA."""
        self._clamav.enabled = self.settings.clamav_enabled
        self._yara.enabled = self.settings.yara_enabled
        self._yara.reload()

    # -- cycle de vie d'un scan --------------------------------------------- #

    def start(self, request: ScanRequest) -> ScanResult:
        targets = self._resolve_targets(request)
        options = self._merge_options(request.options)
        result = ScanResult(
            type=request.type,
            targets=targets,
            device_id=request.device_id,
            status=ScanStatus.PENDING,
        )
        job = ScanJob(result, options)
        self._prune()
        with self._lock:
            self._jobs[job.id] = job
        self.db.save_scan(result)
        self._pool.submit(self._run_job, job)
        return result

    def _merge_options(self, options: ScanOptions) -> ScanOptions:
        """Les reglages globaux servent de valeurs par defaut au scan."""
        merged = options.model_copy()
        if not self.settings.clamav_enabled:
            merged.use_clamav = False
        if not self.settings.yara_enabled:
            merged.use_yara = False
        if not self.settings.heuristics_enabled:
            merged.use_heuristics = False
        if not self.settings.virustotal_enabled:
            merged.use_virustotal = False
        if not self.settings.scan_archives:
            merged.scan_archives = False
        if self.settings.auto_quarantine:
            merged.auto_quarantine = True
        merged.max_file_size = min(
            merged.max_file_size, self.settings.max_file_size_mb * 1024 * 1024
        )
        merged.excluded_paths = sorted(
            set(merged.excluded_paths) | set(self.settings.excluded_paths)
        )
        return merged

    def _resolve_targets(self, request: ScanRequest) -> list[str]:
        if request.type == ScanType.FULL_SYSTEM:
            return ["/"] if not IS_WINDOWS else [os.path.abspath(os.sep)]
        if request.type == ScanType.STARTUP:
            candidates = STARTUP_TARGETS + _user_startup_targets()
            return [p for p in candidates if os.path.exists(p)]
        if request.type == ScanType.MEMORY:
            return ["processus_memoire"]
        if request.type == ScanType.PACKAGES:
            return ["paquets_systeme"]
        resolved: list[str] = []
        for target in request.targets:
            path = os.path.abspath(os.path.expanduser(target))
            if not os.path.exists(path):
                raise FileNotFoundError(f"cible introuvable : {target}")
            resolved.append(path)
        if not resolved:
            raise ValueError("aucune cible a scanner")
        return resolved

    def get(self, scan_id: str) -> ScanResult | None:
        self._prune()
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is not None:
            return job.result
        return self.db.get_scan(scan_id)

    def get_progress(self, scan_id: str) -> ScanProgress | None:
        self._prune()
        with self._lock:
            job = self._jobs.get(scan_id)
        return job.progress if job else None

    def cancel(self, scan_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is None:
            return False
        job.cancel_event.set()
        return True

    def active_scans(self) -> list[ScanResult]:
        self._prune()
        with self._lock:
            return [
                job.result
                for job in self._jobs.values()
                if job.result.status in (ScanStatus.PENDING, ScanStatus.RUNNING)
            ]

    # -- execution ----------------------------------------------------------- #

    def _run_job(self, job: ScanJob) -> None:
        result = job.result
        removable = result.type == ScanType.USB
        engines = self.build_engines(job.options, removable=removable)
        result.engines_used = [e.source for e in engines]
        result.status = ScanStatus.RUNNING
        job.progress.status = ScanStatus.RUNNING
        self.bus.publish_threadsafe(
            events.EVT_SCAN_STARTED,
            {
                "scan_id": result.id,
                "type": result.type.value,
                "targets": result.targets,
                "engines": [e.name for e in engines],
            },
        )
        try:
            if result.type in (
                ScanType.PATH,
                ScanType.FULL_SYSTEM,
                ScanType.USB,
                ScanType.STARTUP,
            ):
                self._run_file_scan(job, engines)
            elif result.type == ScanType.MEMORY:
                self._run_memory_scan(job, engines)
            elif result.type == ScanType.PACKAGES:
                self._run_packages_scan(job, engines)
            else:
                raise NotImplementedError(
                    f"le type de scan '{result.type.value}' n'est pas encore "
                    "implemente dans cette version"
                )
            result.status = ScanStatus.COMPLETED
        except ScanCancelled:
            result.status = ScanStatus.CANCELLED
            log.info("scan %s annule par l'utilisateur", result.id)
        except NotImplementedError as exc:
            result.status = ScanStatus.FAILED
            result.errors.append(str(exc))
        except Exception as exc:  # ne jamais laisser un thread mourir en silence
            result.status = ScanStatus.FAILED
            result.errors.append(f"erreur interne : {exc}")
            log.exception("scan %s a echoue", result.id)
        finally:
            result.finished_at = time.time()
            job.finished_monotonic = time.monotonic()
            job.progress.status = result.status
            job.progress.elapsed_s = round(job.finished_monotonic - job.started_monotonic, 2)
            self.db.save_scan(result)
            self.bus.publish_threadsafe(
                events.EVT_SCAN_FINISHED,
                {
                    "scan_id": result.id,
                    "status": result.status.value,
                    "summary": result.summary(),
                    "errors": result.errors[:10],
                },
            )

    def _prune(self) -> None:
        """Oublie les scans termines depuis assez longtemps.

        Appelee a chaque acces plutot que par un minuteur : un thread
        `threading.Timer` par scan empecherait le processus de se terminer
        pendant toute la duree de retention, ce qui bloque la CLI a la sortie.
        """
        now = time.monotonic()
        with self._lock:
            expired = [
                scan_id
                for scan_id, job in self._jobs.items()
                if job.finished_monotonic is not None
                and now - job.finished_monotonic > JOB_RETENTION_S
            ]
            for scan_id in expired:
                del self._jobs[scan_id]

    def _run_file_scan(self, job: ScanJob, engines: list[Engine]) -> None:
        options = job.options
        excludes = self._build_excludes(options)

        # Phase 1 : comptage, pour un pourcentage honnete.
        job.progress.phase = "enumeration"
        self._publish_progress(job, force=True)
        total = 0
        for _ in self._walk(job, excludes, options):
            total += 1
            if total % 2000 == 0:
                job.progress.files_total = total
                self._publish_progress(job)
        job.progress.files_total = total

        # Phase 2 : analyse.
        job.progress.phase = "analyse"
        archives: list[str] = []
        for path in self._walk(job, excludes, options):
            job.check_cancelled()
            self._scan_one(job, engines, path)
            if options.scan_archives and self._is_archive(path):
                archives.append(path)
            self._publish_progress(job)

        # Phase 3 : contenu des archives.
        if archives:
            job.progress.phase = "archives"
            self._publish_progress(job, force=True)
            for archive in archives:
                job.check_cancelled()
                self._scan_archive(job, engines, archive, depth=1)
        self._publish_progress(job, force=True)

    def _build_excludes(self, options: ScanOptions) -> list[str]:
        excludes = [os.path.abspath(p) for p in options.excluded_paths]
        # Ne jamais scanner la quarantaine : les fichiers y sont volontairement
        # conserves infectes, on se re-detecterait en boucle.
        excludes.append(str(self.quarantine.directory))
        return excludes

    @staticmethod
    def _is_excluded(path: str, excludes: list[str]) -> bool:
        for exclude in excludes:
            if path == exclude or path.startswith(exclude + os.sep):
                return True
        return False

    def _walk(self, job: ScanJob, excludes: list[str], options: ScanOptions):
        """Genere les chemins de fichiers eligibles. Ne leve jamais sur I/O."""
        for target in job.result.targets:
            job.check_cancelled()
            if os.path.isfile(target):
                if not self._is_excluded(target, excludes):
                    yield target
                continue
            for root, dirs, files in os.walk(
                target, topdown=True, followlinks=options.follow_symlinks
            ):
                job.check_cancelled()
                if self._is_excluded(root, excludes):
                    dirs[:] = []
                    continue
                # Elagage : on modifie dirs en place pour eviter de descendre.
                dirs[:] = [
                    d
                    for d in dirs
                    if not self._is_excluded(os.path.join(root, d), excludes)
                ]
                for name in files:
                    path = os.path.join(root, name)
                    if not options.follow_symlinks and os.path.islink(path):
                        continue
                    yield path

    def _scan_one(self, job: ScanJob, engines: list[Engine], path: str) -> None:
        result = job.result
        job.progress.current_file = path
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            result.files_skipped += 1
            job.progress.errors += 1
            self._record_error(result, f"{path} : {exc}")
            return
        if size > job.options.max_file_size:
            result.files_skipped += 1
            return
        if size == 0:
            result.files_scanned += 1
            job.progress.files_scanned = result.files_scanned
            return

        ctx = FileContext(path, size=size)
        found: list[Threat] = []
        for engine in engines:
            # VirusTotal ne sert a rien si un moteur local a deja tranche : on
            # economise le quota.
            if engine.source == DetectionSource.VIRUSTOTAL and found:
                continue
            try:
                found.extend(engine.scan(ctx))
            except Exception as exc:
                job.progress.errors += 1
                self._record_error(result, f"{engine.name} sur {path} : {exc}")
                log.debug("moteur %s a echoue sur %s : %s", engine.name, path, exc)

        result.files_scanned += 1
        result.bytes_scanned += size
        job.progress.files_scanned = result.files_scanned
        job.progress.bytes_scanned = result.bytes_scanned

        if ctx.read_error:
            job.progress.errors += 1
            self._record_error(result, f"{path} : {ctx.read_error}")

        for threat in found:
            self._register_threat(job, threat)

    def _register_threat(self, job: ScanJob, threat: Threat) -> None:
        result = job.result
        if job.options.auto_quarantine and not threat.details.get("archive_member"):
            try:
                entry = self.quarantine.quarantine_file(
                    threat.path,
                    threat_name=threat.name,
                    severity=threat.severity,
                    source=threat.source,
                )
                threat.quarantined = True
                threat.details["quarantine_id"] = entry.id
            except OSError as exc:
                self._record_error(result, f"mise en quarantaine de {threat.path} : {exc}")
        result.threats.append(threat)
        job.progress.threats_found = len(result.threats)
        self.db.add_threat(result.id, threat)
        self.bus.publish_threadsafe(
            events.EVT_SCAN_THREAT,
            {"scan_id": result.id, "threat": threat.model_dump(mode="json")},
        )

    @staticmethod
    def _record_error(result: ScanResult, message: str) -> None:
        # On borne la liste : un scan sur un disque defaillant produirait des
        # centaines de milliers de lignes.
        if len(result.errors) < 200:
            result.errors.append(message)

    def _publish_progress(self, job: ScanJob, force: bool = False) -> None:
        now = time.monotonic()
        last = getattr(job, "_last_publish", 0.0)
        if not force and now - last < PROGRESS_INTERVAL_S:
            return
        job._last_publish = now  # type: ignore[attr-defined]
        job.progress.elapsed_s = round(now - job.started_monotonic, 2)
        self.bus.publish_threadsafe(events.EVT_SCAN_PROGRESS, job.progress.to_event())

    # -- archives ------------------------------------------------------------ #

    @staticmethod
    def _is_archive(path: str) -> bool:
        return os.path.splitext(path)[1].lower() in ARCHIVE_SUFFIXES

    def _scan_archive(
        self, job: ScanJob, engines: list[Engine], archive: str, depth: int
    ) -> None:
        if depth > job.options.max_archive_depth:
            return
        job.progress.current_file = f"{archive} (extraction)"
        self._publish_progress(job)
        tmpdir: str | None = None
        try:
            tmpdir = tempfile.mkdtemp(prefix="malryx-arc-")
            extracted = self._extract(archive, tmpdir)
            if extracted is None:
                # Format reconnu mais non extractible ici (.rar/.7z) : ne
                # JAMAIS laisser croire que l'archive a ete analysee.
                # L'erreur est enregistree, le scan continue sur les autres
                # fichiers, aucune menace n'est inventee.
                self._record_error(
                    job.result,
                    f"archive {archive} : format non pris en charge, "
                    "contenu non analyse (outil 7z absent : installez "
                    "p7zip-full, et p7zip-rar pour .rar)",
                )
                return
            for member_path, member_name in extracted:
                job.check_cancelled()
                ctx = FileContext(member_path, inside_archive=True)
                for engine in engines:
                    if engine.source == DetectionSource.VIRUSTOTAL:
                        continue  # pas de quota gaspille sur du contenu extrait
                    try:
                        for threat in engine.scan(ctx):
                            # On remonte le chemin de l'archive, pas celui du
                            # dossier temporaire qui n'existera plus.
                            threat.path = archive
                            threat.details["archive_member"] = member_name
                            threat.details["archive"] = archive
                            self._register_threat(job, threat)
                    except Exception as exc:
                        log.debug("moteur %s sur %s : %s", engine.name, member_name, exc)
                if self._is_archive(member_path):
                    self._scan_archive(job, engines, member_path, depth + 1)
        except Exception as exc:
            self._record_error(job.result, f"archive {archive} : {exc}")
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

    def _extract(self, archive: str, dest: str) -> list[tuple[str, str]] | None:
        """Extrait une archive avec garde-fous anti-bombe.

        Rend une liste de (chemin_extrait, nom_dans_l_archive), ou None si le
        format n'est pas gere.
        """
        suffix = os.path.splitext(archive)[1].lower()
        # Les exceptions remontent volontairement a `_scan_archive`, qui les
        # enregistre dans les erreurs du scan.
        if suffix in {".zip", ".jar", ".apk"} and zipfile.is_zipfile(archive):
            return self._extract_zip(archive, dest)
        if tarfile.is_tarfile(archive):
            return self._extract_tar(archive, dest)
        if suffix in {".rar", ".7z"}:
            # Extraction externe optionnelle (lot 3) : 7z absent -> None, et
            # l'appelant enregistre une erreur explicite au lieu de passer
            # l'archive sous silence. Un echec de 7z leve RuntimeError, que
            # _scan_archive enregistre de la meme facon.
            if not have_command("7z"):
                return None
            return self._extract_7z(archive, dest)
        return None

    def _extract_7z(self, archive: str, dest: str) -> list[tuple[str, str]]:
        """Extrait .rar/.7z via l'outil externe 7z (p7zip-full, + p7zip-rar
        pour .rar), sans shell et sans invite interactive.

        Securite : stdin vide (aucune invite de mot de passe ne peut
        bloquer), arguments en liste, timeout 300 s. Apres extraction,
        seuls les fichiers reguliers strictement dans dest sont retenus :
        les liens symboliques (restaures par 7z sur Linux) sont ignores
        pour ne jamais scanner hors du dossier temporaire, et les
        garde-fous anti-bombe (1 Gio, 10 000 membres, ratio 200) sont
        re-appliques : depasses, tout le contenu est rejete avec erreur.
        """
        res = run(
            ["7z", "x", "-y", "-bd", f"-o{dest}", "--", archive],
            timeout=300,
            stdin_data="",
        )
        if not res.ok:
            detail = (res.stderr or res.stdout or "").strip().splitlines()
            detail = detail[0][:200] if detail else f"code {res.code}"
            if "password" in (res.stderr or "").lower() or "wrong password" in (res.stderr or "").lower():
                raise RuntimeError(f"archive chiffree, mot de passe non pris en charge ({detail})")
            raise RuntimeError(f"extraction 7z echouee ({detail})")
        out: list[tuple[str, str]] = []
        total = 0
        compressed = max(os.path.getsize(archive), 1)
        dest_abs = os.path.abspath(dest)
        for root, dirs, files in os.walk(dest_abs):
            # Ne jamais descendre dans un repertoire lie symboliquement.
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(os.path.join(root, d))
            ]
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path):
                    continue
                rel = os.path.relpath(path, dest_abs)
                if rel.startswith(".." + os.sep) or rel == "..":
                    continue
                if not os.path.isfile(path):
                    continue
                total += os.path.getsize(path)
                if (
                    total > ARCHIVE_MAX_TOTAL_BYTES
                    or total / compressed > ARCHIVE_MAX_RATIO
                    or len(out) >= ARCHIVE_MAX_MEMBERS
                ):
                    log.warning("archive %s ignoree : bombe de decompression probable", archive)
                    raise RuntimeError("limite anti-bombe depassee (taille, membres ou ratio)")
                out.append((path, rel))
        return out

    def _extract_zip(self, archive: str, dest: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        total = 0
        compressed = max(os.path.getsize(archive), 1)
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist()[:ARCHIVE_MAX_MEMBERS]:
                if info.is_dir():
                    continue
                total += info.file_size
                if total > ARCHIVE_MAX_TOTAL_BYTES or total / compressed > ARCHIVE_MAX_RATIO:
                    log.warning("archive %s ignoree : bombe de decompression probable", archive)
                    break
                target = self._safe_join(dest, info.filename)
                if target is None:
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=256 * 1024)
                out.append((target, info.filename))
        return out

    def _extract_tar(self, archive: str, dest: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        total = 0
        compressed = max(os.path.getsize(archive), 1)
        with tarfile.open(archive) as tf:
            for member in tf:
                if len(out) >= ARCHIVE_MAX_MEMBERS:
                    break
                if not member.isfile():
                    continue  # on ignore liens et peripheriques
                total += member.size
                if total > ARCHIVE_MAX_TOTAL_BYTES or total / compressed > ARCHIVE_MAX_RATIO:
                    log.warning("archive %s ignoree : bombe de decompression probable", archive)
                    break
                target = self._safe_join(dest, member.name)
                if target is None:
                    continue
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with extracted as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=256 * 1024)
                out.append((target, member.name))
        return out

    @staticmethod
    def _safe_join(dest: str, member_name: str) -> str | None:
        """Empeche la traversee de repertoire (`../../etc/passwd`) a l'extraction."""
        dest_abs = os.path.abspath(dest)
        target = os.path.abspath(os.path.join(dest_abs, member_name))
        if not target.startswith(dest_abs + os.sep):
            log.warning("membre d'archive hors perimetre ignore : %s", member_name)
            return None
        return target

    # -- scan memoire / processus -------------------------------------------- #

    def _run_memory_scan(self, job: ScanJob, engines: list[Engine]) -> None:
        job.progress.phase = "enumeration_processus"
        self._publish_progress(job, force=True)

        processes = list(list_running_processes())
        job.progress.files_total = len(processes)

        job.progress.phase = "analyse_processus"
        for proc in processes:
            job.check_cancelled()
            job.progress.current_file = f"PID {proc.pid}: {proc.name}"

            # 1. Alerte si binaire supprime pendant l'execution (stealth malware)
            if proc.deleted_exe:
                threat = Threat(
                    path=proc.exe_path or f"/proc/{proc.pid}/exe",
                    name="Heuristique: Binaire execute puis supprime du disque",
                    severity=Severity.HIGH,
                    source=DetectionSource.HEURISTIC,
                    details={
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "cmdline": proc.cmdline,
                        "reason": "Le fichier binaire a ete supprime pendant son execution pour masquer sa presence.",
                    },
                )
                self._register_threat(job, threat)

            # 2. Analyse de l'executable associe sur disque
            if proc.exe_path and os.path.exists(proc.exe_path):
                self._scan_one(job, engines, proc.exe_path)

            # 3. Analyse des bibliotheques chargees (.so / DLLs)
            for mapped in proc.mapped_files:
                job.check_cancelled()
                if os.path.exists(mapped):
                    self._scan_one(job, engines, mapped)

            job.result.files_scanned += 1
            job.progress.files_scanned = job.result.files_scanned
            self._publish_progress(job)

        self._publish_progress(job, force=True)

    # -- scan des paquets installes ------------------------------------------ #

    def _run_packages_scan(self, job: ScanJob, engines: list[Engine]) -> None:
        job.progress.phase = "enumeration_paquets"
        self._publish_progress(job, force=True)

        packages = list_installed_packages()
        job.progress.files_total = max(len(packages), 1)

        job.progress.phase = "verification_integrite"
        self._publish_progress(job, force=True)

        # Verification globale de l'integrite (fichiers systemes modifies par rapport au depot)
        modified_map = verify_package_integrity()

        for pkg in packages:
            job.check_cancelled()
            job.progress.current_file = f"Paquet: {pkg.name} ({pkg.version})"

            # Si des fichiers de ce paquet ont ete modifies sur le systeme
            if pkg.name in modified_map:
                mod_files = modified_map[pkg.name]
                threat = Threat(
                    path=f"dpkg:{pkg.name}",
                    name=f"Integrite: Fichiers de paquets modifies ({pkg.name})",
                    severity=Severity.MEDIUM,
                    source=DetectionSource.HEURISTIC,
                    details={
                        "package": pkg.name,
                        "version": pkg.version,
                        "modified_files": mod_files,
                        "reason": f"{len(mod_files)} binaire(s) ou bibliotheque(s) du paquet ont ete modifies.",
                    },
                )
                self._register_threat(job, threat)

                # Passer chaque fichier modifie dans les moteurs de scan
                for mod_file in mod_files:
                    if os.path.exists(mod_file):
                        self._scan_one(job, engines, mod_file)

            job.result.files_scanned += 1
            job.progress.files_scanned = job.result.files_scanned
            self._publish_progress(job)

        # Recoupement CVE (opt-in, OSV.dev) : apres l'integrite, jamais a la
        # place. Un echec reseau n'efface pas les menaces deja trouvees.
        if getattr(self.settings, "cve_enabled", False):
            job.check_cancelled()
            job.progress.phase = "verification_cve"
            job.progress.current_file = "Verification CVE (OSV.dev)"
            self._publish_progress(job, force=True)
            cve_result = check_packages_cve(packages)
            for threat in cve_result.threats:
                job.check_cancelled()
                self._register_threat(job, threat)
            for error in cve_result.errors:
                self._record_error(job.result, error)

        self._publish_progress(job, force=True)

