"""Detection d'installations et de partages Windows (section 4.3).

Ce qui est operationnel dans cette version :

- **Partition Windows montee localement.** Une partition NTFS contenant
  Windows/System32 est reconnue comme telle et devient scannable par le moteur
  de fichiers normal : c'est le cas d'usage le plus courant (double amorcage,
  disque externe, recuperation d'une machine en panne).
- **Enumeration des partages SMB** d'un hote distant, quand `smbclient` est
  installe. Sert a savoir quoi monter ; le montage lui-meme reste une action
  utilisateur (il demande des identifiants et les droits CAP_SYS_ADMIN).

Ce qui ne l'est pas encore : l'agent leger cote Windows (evoque en 4.3 comme
optionnel) et le montage automatique des partages.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from core.config import IS_LINUX
from core.models import DeviceAccess, DeviceInfo, DeviceKind
from core.platform_compat import have_command, run

from .usb_scanner import FS_LABELS, PSEUDO_FS, _usage

log = logging.getLogger(__name__)

WINDOWS_FS = {"ntfs", "ntfs3", "fuseblk", "vfat", "exfat"}
# Marqueurs d'une racine Windows. La casse varie selon le pilote de montage.
WINDOWS_MARKERS = (
    ("Windows", "System32"),
    ("WINDOWS", "system32"),
    ("Windows", "system32"),
)


def _looks_like_windows(mount_point: str) -> str | None:
    """Rend le chemin de System32 si le montage contient une installation Windows."""
    for parts in WINDOWS_MARKERS:
        candidate = os.path.join(mount_point, *parts)
        if os.path.isdir(candidate):
            return candidate
    return None


def list_windows_volumes() -> list[DeviceInfo]:
    """Partitions Windows montees sur cette machine Linux."""
    if not IS_LINUX:
        return []
    devices: list[DeviceInfo] = []
    try:
        lines = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        log.warning("/proc/mounts illisible : %s", exc)
        return devices

    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        source, mount, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
        if fstype in PSEUDO_FS or fstype not in WINDOWS_FS:
            continue
        system32 = _looks_like_windows(mount)
        if system32 is None:
            continue
        total, used = _usage(mount)
        devices.append(
            DeviceInfo(
                id=f"windows:{source}",
                kind=DeviceKind.WINDOWS_HOST,
                label=f"Windows sur {os.path.basename(mount) or mount} "
                f"({FS_LABELS.get(fstype, fstype)})",
                access=DeviceAccess.FULL,
                mount_point=mount,
                filesystem=fstype,
                total_bytes=total,
                used_bytes=used,
                details={
                    "device": source,
                    "system32": system32,
                    "hint": (
                        "Scan cible recommande : Users, ProgramData, "
                        "Windows/Temp plutot que la partition entiere."
                    ),
                },
            )
        )
    return devices


def priority_targets(mount_point: str) -> list[str]:
    """Sous-dossiers Windows a scanner en priorite (rapport signal/bruit eleve)."""
    candidates = [
        "Users",
        "ProgramData",
        os.path.join("Windows", "Temp"),
        os.path.join("Windows", "System32", "Tasks"),
        "Temp",
    ]
    found = []
    for candidate in candidates:
        full = os.path.join(mount_point, candidate)
        if os.path.isdir(full):
            found.append(full)
    return found or [mount_point]


def list_smb_shares(host: str, user: str | None = None) -> list[dict[str, str]]:
    """Enumere les partages d'un hote SMB. Lecture seule, sans montage.

    Sans utilisateur, la session invite est tentee : beaucoup d'hotes la
    refusent, ce qui est signale tel quel plutot qu'interprete.
    """
    if not have_command("smbclient"):
        raise RuntimeError(
            "smbclient absent. Sur Debian : sudo apt install smbclient"
        )
    if not host or any(c in host for c in " ;|&$`\n"):
        raise ValueError(f"nom d'hote invalide : {host!r}")
    args = ["smbclient", "-L", host, "-g"]
    args += ["-U", user] if user else ["-N"]
    result = run(args, timeout=45)
    if not result.ok and not result.stdout.strip():
        raise RuntimeError(
            f"enumeration SMB impossible : {result.stderr.strip() or 'hote injoignable'}"
        )
    shares: list[dict[str, str]] = []
    for line in result.lines():
        # Format -g : Disk|nom|commentaire
        fields = line.split("|")
        if len(fields) >= 2 and fields[0].strip().lower() in {"disk", "printer", "ipc"}:
            shares.append(
                {
                    "type": fields[0].strip().lower(),
                    "name": fields[1].strip(),
                    "comment": fields[2].strip() if len(fields) > 2 else "",
                }
            )
    return shares


def mount_hint(host: str, share: str) -> str:
    """Commande de montage a proposer a l'utilisateur (jamais executee ici).

    Monter un partage exige des privileges et des identifiants : c'est une
    decision de l'utilisateur, pas quelque chose que l'antivirus fait dans son
    dos.
    """
    target = f"/mnt/{share}"
    return (
        f"sudo mkdir -p {target} && "
        f"sudo mount -t cifs //{host}/{share} {target} "
        f"-o ro,username=VOTRE_UTILISATEUR,vers=3.0"
    )


def agent_available() -> bool:
    """L'agent leger Windows de la section 4.3 n'existe pas encore."""
    return False
