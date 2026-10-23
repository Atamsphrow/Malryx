"""Detection des medias amovibles montes (section 4.5).

Sur Debian on interroge `lsblk` en JSON, ce qui donne d'un coup le systeme de
fichiers, la taille, le modele et le caractere amovible du peripherique. Si
`lsblk` manque, on retombe sur /proc/mounts croise avec
/sys/block/<dev>/removable.

Une implementation Windows minimale est fournie pour permettre le developpement
de l'UI hors Linux ; elle n'est pas la cible du produit.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import string
from pathlib import Path

from core.config import IS_LINUX, IS_WINDOWS
from core.models import DeviceAccess, DeviceInfo, DeviceKind
from core.platform_compat import have_command, run

log = logging.getLogger(__name__)

# Systemes de fichiers a ignorer : pseudo-fs, montages reseau, images.
PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
    "securityfs", "pstore", "bpf", "debugfs", "tracefs", "fusectl",
    "configfs", "mqueue", "hugetlbfs", "autofs", "binfmt_misc", "efivarfs",
    "squashfs", "overlay", "ramfs", "nsfs",
}

# Points de montage typiques des medias amovibles sous Debian.
REMOVABLE_HINTS = ("/media/", "/mnt/", "/run/media/")

FS_LABELS = {
    "vfat": "FAT32",
    "exfat": "exFAT",
    "ntfs": "NTFS",
    "ntfs3": "NTFS",
    "fuseblk": "NTFS/exFAT (FUSE)",
    "ext2": "ext2",
    "ext3": "ext3",
    "ext4": "ext4",
    "btrfs": "Btrfs",
    "xfs": "XFS",
    "hfsplus": "HFS+",
}


def _usage(mount_point: str) -> tuple[int | None, int | None]:
    try:
        usage = shutil.disk_usage(mount_point)
        return usage.total, usage.used
    except OSError:
        return None, None


def list_removable_devices() -> list[DeviceInfo]:
    if IS_LINUX:
        if have_command("lsblk"):
            devices = _from_lsblk()
            if devices:
                return devices
        return _from_proc_mounts()
    if IS_WINDOWS:
        return _from_windows()
    return []


# --------------------------------------------------------------------------- #
# Linux
# --------------------------------------------------------------------------- #


def _from_lsblk() -> list[DeviceInfo]:
    result = run(
        [
            "lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,PATH,MOUNTPOINT,FSTYPE,SIZE,FSUSED,RM,HOTPLUG,MODEL,LABEL,UUID,TYPE,RO",
        ],
        timeout=15,
    )
    if not result.ok:
        log.debug("lsblk a echoue : %s", result.stderr.strip())
        return []
    try:
        tree = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        log.debug("sortie lsblk illisible : %s", exc)
        return []

    devices: list[DeviceInfo] = []

    def visit(node: dict, parent: dict | None = None) -> None:
        children = node.get("children") or []
        removable = bool(node.get("rm") or node.get("hotplug"))
        if parent:
            removable = removable or bool(parent.get("rm") or parent.get("hotplug"))
        mount = node.get("mountpoint")
        fstype = node.get("fstype")
        if mount and fstype and fstype not in PSEUDO_FS and removable:
            model = (node.get("model") or (parent or {}).get("model") or "").strip()
            label = node.get("label") or os.path.basename(mount) or mount
            total = node.get("size")
            used = node.get("fsused")
            if total is None or used is None:
                total, used = _usage(mount)
            devices.append(
                DeviceInfo(
                    id=node.get("uuid") or node.get("path") or mount,
                    kind=DeviceKind.REMOVABLE,
                    label=f"{label} ({FS_LABELS.get(fstype, fstype)})",
                    access=DeviceAccess.FULL,
                    mount_point=mount,
                    filesystem=fstype,
                    total_bytes=int(total) if total is not None else None,
                    used_bytes=int(used) if used is not None else None,
                    model=model or None,
                    details={
                        "device": node.get("path"),
                        "read_only": bool(node.get("ro")),
                    },
                )
            )
        for child in children:
            visit(child, node)

    for node in tree.get("blockdevices", []):
        visit(node)
    return devices


def _from_proc_mounts() -> list[DeviceInfo]:
    """Repli sans lsblk : /proc/mounts + /sys/block/<dev>/removable."""
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
        if fstype in PSEUDO_FS or not source.startswith("/dev/"):
            continue
        if not (
            mount.startswith(REMOVABLE_HINTS) or _sysfs_removable(source)
        ):
            continue
        total, used = _usage(mount)
        devices.append(
            DeviceInfo(
                id=source,
                kind=DeviceKind.REMOVABLE,
                label=f"{os.path.basename(mount) or mount} "
                f"({FS_LABELS.get(fstype, fstype)})",
                access=DeviceAccess.FULL,
                mount_point=mount,
                filesystem=fstype,
                total_bytes=total,
                used_bytes=used,
                details={"device": source},
            )
        )
    return devices


def _sysfs_removable(device_path: str) -> bool:
    """Vrai si le disque parent de la partition est marque amovible."""
    name = os.path.basename(device_path)
    # sda1 -> sda ; nvme0n1p1 -> nvme0n1 ; mmcblk0p1 -> mmcblk0
    base = name.rstrip("0123456789")
    if base.endswith("p") and base[:-1]:
        base = base[:-1]
    flag = Path(f"/sys/block/{base}/removable")
    try:
        return flag.read_text().strip() == "1"
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Windows (developpement uniquement)
# --------------------------------------------------------------------------- #

DRIVE_REMOVABLE = 2


def _from_windows() -> list[DeviceInfo]:
    import ctypes

    devices: list[DeviceInfo] = []
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) != DRIVE_REMOVABLE:
            continue
        if not os.path.exists(root):
            continue
        total, used = _usage(root)
        fs_buffer = ctypes.create_unicode_buffer(64)
        name_buffer = ctypes.create_unicode_buffer(261)
        kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root),
            name_buffer,
            ctypes.sizeof(name_buffer),
            None,
            None,
            None,
            fs_buffer,
            ctypes.sizeof(fs_buffer),
        )
        fstype = fs_buffer.value or "unknown"
        devices.append(
            DeviceInfo(
                id=root,
                kind=DeviceKind.REMOVABLE,
                label=f"{name_buffer.value or letter} ({fstype})",
                access=DeviceAccess.FULL,
                mount_point=root,
                filesystem=fstype.lower(),
                total_bytes=total,
                used_bytes=used,
                details={"note": "detection Windows, mode developpement"},
            )
        )
    return devices


# --------------------------------------------------------------------------- #
# Indices d'infection propres aux medias amovibles
# --------------------------------------------------------------------------- #

AUTORUN_NAMES = {"autorun.inf", "autorun.exe", "desktop.ini"}


def autorun_findings(mount_point: str) -> list[dict[str, str]]:
    """Cherche les fichiers d'execution automatique a la racine du media.

    Renvoye par /api/devices pour signaler le risque avant meme un scan complet.
    """
    findings: list[dict[str, str]] = []
    try:
        entries = list(os.scandir(mount_point))
    except OSError as exc:
        return [{"path": mount_point, "issue": f"racine illisible : {exc}"}]
    for entry in entries:
        lowered = entry.name.lower()
        if lowered in AUTORUN_NAMES:
            findings.append(
                {
                    "path": entry.path,
                    "issue": "fichier d'execution automatique a la racine",
                }
            )
        elif lowered.endswith(".lnk"):
            findings.append(
                {"path": entry.path, "issue": "raccourci Windows a la racine"}
            )
        elif entry.is_dir() and lowered in {"recycler", "$recycle.bin"} :
            findings.append(
                {"path": entry.path, "issue": "dossier corbeille suspect"}
            )
    return findings
