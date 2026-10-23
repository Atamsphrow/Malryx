"""Contrat de donnees partage entre le backend et le frontend Flutter.

Toute modification ici doit etre repercutee dans frontend/lib/models/.
Les valeurs des enums sont serialisees telles quelles en JSON (str).
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def new_id() -> str:
    return uuid.uuid4().hex[:16]


def now() -> float:
    return time.time()


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class ScanType(str, Enum):
    """Cible d'un scan. Voir section 4 de la spec."""

    PATH = "path"                  # 4.1 dossier/fichier a la demande
    FULL_SYSTEM = "full_system"    # 4.1 scan complet
    MEMORY = "memory"              # 4.1 memoire / processus
    STARTUP = "startup"            # 4.1 cron, systemd, autostart
    PACKAGES = "packages"          # 4.1 dpkg vs CVE
    USB = "usb"                    # 4.5 media amovible
    ANDROID = "android"            # 4.2 via ADB / MTP
    WINDOWS_REMOTE = "windows"     # 4.3 SMB / agent
    LINUX_REMOTE = "linux_remote"  # 4.4 SSH / agent


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class Severity(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: list[str] = [
    Severity.CLEAN.value,
    Severity.LOW.value,
    Severity.MEDIUM.value,
    Severity.HIGH.value,
    Severity.CRITICAL.value,
]


def worst_severity(values: list[Severity]) -> Severity:
    worst = Severity.CLEAN
    for value in values:
        if SEVERITY_ORDER.index(value.value) > SEVERITY_ORDER.index(worst.value):
            worst = value
    return worst


class DetectionSource(str, Enum):
    """Moteur ayant produit le verdict (section 4.6)."""

    CLAMAV = "clamav"
    YARA = "yara"
    HASH_LOCAL = "hash_local"
    VIRUSTOTAL = "virustotal"
    HEURISTIC = "heuristic"
    CVE = "cve"


class DeviceKind(str, Enum):
    LOCAL_HOST = "local_host"
    REMOVABLE = "removable"      # cle USB / disque externe
    ANDROID = "android"
    WINDOWS_HOST = "windows_host"
    LINUX_HOST = "linux_host"


class DeviceAccess(str, Enum):
    """Niveau d'acces obtenu sur l'appareil, conditionne les scans possibles."""

    FULL = "full"                # systeme de fichiers monte en lecture
    ADB_DEBUG = "adb_debug"      # Android, debogage USB autorise
    ADB_UNAUTHORIZED = "adb_unauthorized"
    MTP_LIMITED = "mtp_limited"  # Android sans debug, fichiers media seulement
    SMB = "smb"
    SSH = "ssh"
    NONE = "none"


class QuarantineStatus(str, Enum):
    QUARANTINED = "quarantined"
    RESTORED = "restored"
    DELETED = "deleted"


# --------------------------------------------------------------------------- #
# Menaces et resultats
# --------------------------------------------------------------------------- #


class Threat(BaseModel):
    id: str = Field(default_factory=new_id)
    path: str
    name: str                                   # ex. "Eicar-Test-Signature"
    severity: Severity = Severity.MEDIUM
    source: DetectionSource
    sha256: str | None = None
    size: int | None = None
    detected_at: float = Field(default_factory=now)
    quarantined: bool = False
    # Detail libre selon le moteur : permissions APK, regle YARA, ratio VT...
    details: dict[str, Any] = Field(default_factory=dict)


class ScanProgress(BaseModel):
    """Instantane de progression, corps des evenements WebSocket scan.progress."""

    scan_id: str
    status: ScanStatus
    phase: str = ""                 # enumeration, analyse, archives...
    current_file: str | None = None
    files_scanned: int = 0
    files_total: int | None = None  # None tant que l'enumeration n'est pas finie
    bytes_scanned: int = 0
    threats_found: int = 0
    errors: int = 0
    elapsed_s: float = 0.0

    @property
    def percent(self) -> float | None:
        if not self.files_total:
            return None
        return min(100.0, round(self.files_scanned / self.files_total * 100, 2))

    def to_event(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["percent"] = self.percent
        return data


class ScanResult(BaseModel):
    id: str = Field(default_factory=new_id)
    type: ScanType
    targets: list[str] = Field(default_factory=list)
    status: ScanStatus = ScanStatus.PENDING
    device_id: str | None = None
    started_at: float = Field(default_factory=now)
    finished_at: float | None = None
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: list[str] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    engines_used: list[DetectionSource] = Field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return (self.finished_at or now()) - self.started_at

    def max_severity(self) -> Severity:
        return worst_severity([t.severity for t in self.threats])

    def summary(self) -> dict[str, Any]:
        """Version allegee pour les listes d'historique (sans les menaces)."""
        return {
            "id": self.id,
            "type": self.type.value,
            "targets": self.targets,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 2),
            "files_scanned": self.files_scanned,
            "threats_count": len(self.threats),
            "max_severity": self.max_severity().value,
        }


# --------------------------------------------------------------------------- #
# Appareils
# --------------------------------------------------------------------------- #


class DeviceInfo(BaseModel):
    id: str                                  # stable : serial ADB, UUID partition...
    kind: DeviceKind
    label: str                               # nom lisible affiche dans l'UI
    access: DeviceAccess = DeviceAccess.NONE
    mount_point: str | None = None
    filesystem: str | None = None            # vfat, exfat, ntfs, ext4...
    total_bytes: int | None = None
    used_bytes: int | None = None
    model: str | None = None
    connected_at: float = Field(default_factory=now)
    scannable: bool = True
    # Raison pour laquelle un scan n'est pas (encore) possible, affichee telle quelle.
    blocked_reason: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AndroidApp(BaseModel):
    package: str
    label: str | None = None
    version_name: str | None = None
    system_app: bool = False
    apk_path: str | None = None
    sha256: str | None = None
    permissions: list[str] = Field(default_factory=list)
    dangerous_permissions: list[str] = Field(default_factory=list)
    risk_score: int = 0                      # 0-100, heuristique section 4.2
    severity: Severity = Severity.CLEAN
    signature_issuer: str | None = None
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Quarantaine
# --------------------------------------------------------------------------- #


class QuarantineEntry(BaseModel):
    id: str = Field(default_factory=new_id)
    original_path: str
    stored_path: str
    sha256: str
    size: int
    threat_name: str | None = None
    severity: Severity = Severity.MEDIUM
    source: DetectionSource | None = None
    quarantined_at: float = Field(default_factory=now)
    status: QuarantineStatus = QuarantineStatus.QUARANTINED
    original_mode: int | None = None          # permissions a restaurer


# --------------------------------------------------------------------------- #
# Requetes API
# --------------------------------------------------------------------------- #


class ScanOptions(BaseModel):
    use_clamav: bool = True
    use_yara: bool = True
    use_hash_db: bool = True
    use_virustotal: bool = False              # opt-in : envoie des hash au cloud
    use_heuristics: bool = True
    scan_archives: bool = True
    max_archive_depth: int = 3
    follow_symlinks: bool = False
    max_file_size: int = 256 * 1024 * 1024    # 256 MiB
    auto_quarantine: bool = False
    excluded_paths: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    type: ScanType = ScanType.PATH
    targets: list[str] = Field(default_factory=list)
    device_id: str | None = None
    options: ScanOptions = Field(default_factory=ScanOptions)


class QuarantineRequest(BaseModel):
    path: str
    threat_name: str | None = None
    severity: Severity = Severity.MEDIUM


class EngineStatus(BaseModel):
    name: str
    available: bool
    version: str | None = None
    signatures: int | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    platform: str
    is_linux: bool
    root: bool
    engines: list[EngineStatus] = Field(default_factory=list)
