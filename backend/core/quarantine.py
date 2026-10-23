"""Quarantaine locale : isoler un fichier suspect sans le detruire (section 4.1).

Trois garanties :

1. **Neutralisation.** Le fichier stocke est passe au XOR avec une cle fixe. Ce
   n'est pas du chiffrement et ce n'est pas presente comme tel : le but est
   qu'un fichier en quarantaine ne soit plus executable par accident et ne soit
   plus re-detecte en boucle par ce scanner ou un autre. Le SHA256 d'origine est
   verifie a la restauration.
2. **Reversibilite.** Chemin, permissions et empreinte d'origine sont conserves,
   la restauration remet le fichier exactement ou il etait.
3. **Refus des chemins critiques.** Un faux positif sur /bin/bash ne doit pas
   rendre la machine inutilisable : les emplacements systeme vitaux sont refuses
   sauf demande explicite.
"""

from __future__ import annotations

import hashlib
import logging
import os
import posixpath
import re
from pathlib import Path

from core.config import IS_WINDOWS, Paths
from core.models import (
    DetectionSource,
    QuarantineEntry,
    QuarantineStatus,
    Severity,
)
from db.local_db import LocalDB

log = logging.getLogger(__name__)

# Cle de neutralisation. Volontairement publique : elle empeche l'execution
# accidentelle, elle ne protege aucun secret.
XOR_KEY = b"Malryx-Quarantine-v1"
CHUNK = 1024 * 1024

# Prefixe de lecteur Windows, retire avant l'evaluation POSIX des chemins.
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")

# Deplacer un fichier de ces arborescences peut empecher le systeme de demarrer.
PROTECTED_PREFIXES = (
    "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/lib64",
    "/boot", "/etc/passwd", "/etc/shadow", "/etc/fstab", "/etc/sudoers",
    "/proc", "/sys", "/dev", "/run",
)


class QuarantineError(RuntimeError):
    pass


class ProtectedPathError(QuarantineError):
    """Le fichier vise appartient a une arborescence systeme critique."""


class QuarantineManager:
    def __init__(self, db: LocalDB, paths: Paths) -> None:
        self.db = db
        self.paths = paths
        self.directory = paths.quarantine_dir
        self.directory.mkdir(parents=True, exist_ok=True)
        if not IS_WINDOWS:
            os.chmod(self.directory, 0o700)

    # -- garde-fous ---------------------------------------------------------- #

    @staticmethod
    def is_protected(path: str) -> bool:
        """La cible appartient-elle a une arborescence systeme vitale ?

        La normalisation est volontairement POSIX et non dependante de la
        plateforme hote : la garde raisonne sur des chemins Linux, et doit
        rester verifiable quand le backend tourne sous Windows en
        developpement. `normpath` neutralise au passage les detours du type
        /bin/../etc/passwd. Le prefixe de lecteur eventuel est retire pour que
        D:/bin/bash soit juge comme /bin/bash.
        """
        candidate = _DRIVE_PREFIX.sub("", path.replace("\\", "/"))
        resolved = posixpath.normpath(candidate)
        return any(
            resolved == prefix or resolved.startswith(prefix + "/")
            for prefix in PROTECTED_PREFIXES
        )

    # -- mise en quarantaine -------------------------------------------------- #

    def quarantine_file(
        self,
        path: str,
        threat_name: str | None = None,
        severity: Severity = Severity.MEDIUM,
        source: DetectionSource | None = None,
        force: bool = False,
    ) -> QuarantineEntry:
        src = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(src):
            raise QuarantineError(f"fichier introuvable : {path}")
        if os.path.islink(src):
            raise QuarantineError(
                "cible symbolique : mettez en quarantaine le fichier reel, "
                "pas le lien"
            )
        if self.is_protected(src) and not force:
            raise ProtectedPathError(
                f"{src} appartient a une arborescence systeme critique. "
                "Mise en quarantaine refusee : un faux positif ici peut rendre "
                "le systeme inutilisable. Utilisez force=true en connaissance "
                "de cause."
            )

        stat_result = os.stat(src)
        entry = QuarantineEntry(
            original_path=src,
            stored_path="",
            sha256="",
            size=stat_result.st_size,
            threat_name=threat_name,
            severity=severity,
            source=source,
            original_mode=stat_result.st_mode & 0o7777,
        )
        stored = self.directory / f"{entry.id}.quarantine"
        digest = self._transform(Path(src), stored, src_is_plaintext=True)
        entry.sha256 = digest
        entry.stored_path = str(stored)

        if not IS_WINDOWS:
            os.chmod(stored, 0o400)  # lecture seule, proprietaire uniquement
        try:
            os.remove(src)
        except OSError as exc:
            # On ne laisse pas une copie orpheline en quarantaine.
            stored.unlink(missing_ok=True)
            raise QuarantineError(
                f"impossible de retirer {src} : {exc}. Droits insuffisants ?"
            ) from exc

        self.db.save_quarantine(entry)
        log.info("quarantaine : %s -> %s", src, stored.name)
        return entry

    # -- restauration --------------------------------------------------------- #

    def restore(self, entry_id: str, destination: str | None = None) -> str:
        entry = self.db.get_quarantine(entry_id)
        if entry is None:
            raise QuarantineError(f"entree de quarantaine inconnue : {entry_id}")
        if entry.status != QuarantineStatus.QUARANTINED:
            raise QuarantineError(
                f"cette entree est deja '{entry.status.value}'"
            )
        stored = Path(entry.stored_path)
        if not stored.is_file():
            raise QuarantineError(
                f"fichier de quarantaine manquant sur le disque : {stored}"
            )
        target = Path(destination or entry.original_path)
        if target.exists():
            raise QuarantineError(
                f"{target} existe deja, restauration annulee pour ne rien ecraser"
            )
        target.parent.mkdir(parents=True, exist_ok=True)

        digest = self._transform(stored, target, src_is_plaintext=False)
        if digest != entry.sha256:
            # Le fichier restaure ne correspond pas a l'original : on ne laisse
            # pas un fichier douteux en place.
            target.unlink(missing_ok=True)
            raise QuarantineError(
                "empreinte differente apres restauration, le fichier de "
                "quarantaine est corrompu"
            )
        if entry.original_mode is not None and not IS_WINDOWS:
            os.chmod(target, entry.original_mode)
        stored.unlink(missing_ok=True)
        self.db.set_quarantine_status(entry_id, QuarantineStatus.RESTORED)
        log.info("restaure : %s", target)
        return str(target)

    # -- suppression definitive ------------------------------------------------ #

    def delete(self, entry_id: str) -> None:
        entry = self.db.get_quarantine(entry_id)
        if entry is None:
            raise QuarantineError(f"entree de quarantaine inconnue : {entry_id}")
        Path(entry.stored_path).unlink(missing_ok=True)
        self.db.set_quarantine_status(entry_id, QuarantineStatus.DELETED)
        log.info("supprime definitivement : %s", entry.original_path)

    def list_entries(self, include_inactive: bool = False) -> list[QuarantineEntry]:
        return self.db.list_quarantine(include_inactive=include_inactive)

    # -- interne --------------------------------------------------------------- #

    @staticmethod
    def _xor(data: bytes, offset: int) -> bytes:
        """XOR par cle repetee, en une seule operation sur grands entiers.

        `offset` est la position absolue de `data` dans le flux, ce qui permet de
        traiter le fichier par blocs sans desynchroniser la cle.
        """
        if not data:
            return data
        start = offset % len(XOR_KEY)
        repeats = (len(data) + start) // len(XOR_KEY) + 1
        keystream = (XOR_KEY * repeats)[start : start + len(data)]
        merged = int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")
        return merged.to_bytes(len(data), "big")

    @classmethod
    def _transform(cls, src: Path, dst: Path, src_is_plaintext: bool) -> str:
        """Copie src vers dst en appliquant le XOR, et rend le SHA256 du clair.

        La transformation est symetrique, seul le sens de lecture change :
        `src_is_plaintext=True` pour la mise en quarantaine, False pour la
        restauration. L'empreinte porte toujours sur la version en clair, afin
        de pouvoir comparer la restauration a l'original.
        """
        digest = hashlib.sha256()
        offset = 0
        tmp = dst.with_name(dst.name + ".part")
        try:
            with open(src, "rb") as fin, open(tmp, "wb") as fout:
                while chunk := fin.read(CHUNK):
                    transformed = cls._xor(chunk, offset)
                    digest.update(chunk if src_is_plaintext else transformed)
                    fout.write(transformed)
                    offset += len(chunk)
            tmp.replace(dst)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        return digest.hexdigest()

    def orphan_files(self) -> list[str]:
        """Fichiers presents dans le dossier mais absents de la base."""
        known = {Path(e.stored_path).name for e in self.db.list_quarantine(True)}
        return [
            str(p)
            for p in self.directory.glob("*.quarantine")
            if p.name not in known
        ]
