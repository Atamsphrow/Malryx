"""Routes REST des appareils : local, USB, Android, Windows, Linux distant.

Les identifiants d'appareils contiennent des slashs (`/dev/sda1`,
`/run/media/...`), ils passent donc par des parametres de requete et non par le
chemin de l'URL.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from core.app_state import AppState, get_state
from core.config import IS_LINUX
from core.models import AndroidApp, DeviceAccess, DeviceInfo, DeviceKind
from core.platform_compat import have_command
from devices import android_scanner, linux_remote_scanner, usb_scanner, windows_scanner

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/devices", tags=["devices"])


def _local_host() -> DeviceInfo:
    total, used = None, None
    try:
        usage = shutil.disk_usage("/" if IS_LINUX else os.path.abspath(os.sep))
        total, used = usage.total, usage.used
    except OSError:
        pass
    return DeviceInfo(
        id="local",
        kind=DeviceKind.LOCAL_HOST,
        label=f"Cette machine ({socket.gethostname()})",
        access=DeviceAccess.FULL,
        mount_point="/" if IS_LINUX else os.path.abspath(os.sep),
        total_bytes=total,
        used_bytes=used,
        details={"platform": "linux" if IS_LINUX else os.name},
    )


@router.get("", response_model=list[DeviceInfo])
def list_devices(
    include_local: bool = Query(True),
    state: AppState = Depends(get_state),
) -> list[DeviceInfo]:
    """Inventaire de tout ce qui est scannable maintenant.

    Aucune erreur n'interrompt l'inventaire : si la detection Android echoue, on
    rend quand meme les cles USB.
    """
    devices: list[DeviceInfo] = []
    if include_local:
        devices.append(_local_host())
    for label, collector in (
        ("amovibles", usb_scanner.list_removable_devices),
        ("android", android_scanner.list_android_devices),
        ("windows", windows_scanner.list_windows_volumes),
    ):
        try:
            devices.extend(collector())
        except Exception as exc:
            log.warning("detection %s echouee : %s", label, exc)
    return devices


@router.get("/capabilities")
def capabilities() -> dict:
    """Ce qui est reellement possible sur cette machine, pour que l'UI grise le
    reste au lieu de proposer des actions qui echoueront."""
    return {
        "platform": "linux" if IS_LINUX else os.name,
        "adb": android_scanner.adb_available(),
        "lsblk": have_command("lsblk"),
        "smbclient": have_command("smbclient"),
        "ssh": have_command("ssh"),
        "windows_agent": windows_scanner.agent_available(),
    }


@router.get("/autorun")
def autorun(mount_point: str = Query(..., description="Point de montage a inspecter")) -> dict:
    """Fichiers d'execution automatique a la racine d'un media (section 4.5)."""
    if not os.path.isdir(mount_point):
        raise HTTPException(
            status_code=404, detail=f"point de montage introuvable : {mount_point}"
        )
    return {
        "mount_point": mount_point,
        "findings": usb_scanner.autorun_findings(mount_point),
    }


# --------------------------------------------------------------------------- #
# Android (section 4.2)
# --------------------------------------------------------------------------- #

android_router = APIRouter(prefix="/api/devices/android", tags=["android"])


@android_router.get("/{serial}/apps", response_model=list[AndroidApp])
def list_android_apps(
    serial: str,
    include_system: bool = Query(False),
    analyze: bool = Query(
        True, description="Analyse les permissions de chaque app (plus lent)"
    ),
    limit: int = Query(200, ge=1, le=1000),
) -> list[AndroidApp]:
    if not android_scanner.adb_available():
        raise HTTPException(
            status_code=503,
            detail="adb introuvable. Sur Debian : sudo apt install android-tools-adb",
        )
    try:
        apps = android_scanner.list_apps(serial, include_system=include_system)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    apps = apps[:limit]
    if not analyze:
        return apps
    analyzed: list[AndroidApp] = []
    for app in apps:
        try:
            analyzed.append(android_scanner.analyze_app(serial, app))
        except Exception as exc:
            log.warning("analyse de %s echouee : %s", app.package, exc)
            app.notes.append(f"analyse partielle : {exc}")
            analyzed.append(app)
    return sorted(analyzed, key=lambda a: a.risk_score, reverse=True)


@android_router.post("/{serial}/apps/{package}/uninstall")
def uninstall_app(serial: str, package: str) -> dict:
    """Desinstalle une application du telephone. Action destructive et distante."""
    try:
        output = android_scanner.uninstall(serial, package)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"ok": True, "package": package, "output": output}


@android_router.post("/{serial}/apps/{package}/revoke")
def revoke_app_permission(
    serial: str, package: str, permission: str = Body(..., embed=True)
) -> dict:
    try:
        android_scanner.revoke_permission(serial, package, permission)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"ok": True, "package": package, "permission": permission}


# --------------------------------------------------------------------------- #
# Windows (section 4.3) et Linux distant (section 4.4)
# --------------------------------------------------------------------------- #

remote_router = APIRouter(prefix="/api/devices/remote", tags=["remote"])


@remote_router.get("/windows/targets")
def windows_targets(mount_point: str = Query(...)) -> dict:
    """Sous-dossiers a scanner en priorite sur une partition Windows montee."""
    if not os.path.isdir(mount_point):
        raise HTTPException(status_code=404, detail=f"introuvable : {mount_point}")
    return {"targets": windows_scanner.priority_targets(mount_point)}


@remote_router.post("/smb/shares")
def smb_shares(
    host: str = Body(...), user: str | None = Body(None)
) -> dict:
    try:
        shares = windows_scanner.list_smb_shares(host, user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "host": host,
        "shares": shares,
        "mount_hints": {
            share["name"]: windows_scanner.mount_hint(host, share["name"])
            for share in shares
            if share["type"] == "disk"
        },
    }


@remote_router.post("/ssh/probe", response_model=DeviceInfo)
def ssh_probe(
    host: str = Body(...),
    user: str | None = Body(None),
    port: int = Body(22),
) -> DeviceInfo:
    """Teste l'acces SSH en lecture seule a une autre machine Linux."""
    try:
        return linux_remote_scanner.probe(host, user, port)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except linux_remote_scanner.RemoteError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@remote_router.post("/ssh/scan")
def ssh_hash_scan(
    host: str = Body(...),
    paths: list[str] = Body(...),
    user: str | None = Body(None),
    port: int = Body(22),
    state: AppState = Depends(get_state),
) -> dict:
    """Scan distant sans agent : la machine calcule ses empreintes, on compare.

    Seules des empreintes traversent le reseau, jamais le contenu des fichiers.
    """
    try:
        pairs = linux_remote_scanner.remote_hashes(host, paths, user, port)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except linux_remote_scanner.RemoteError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    matches = []
    for digest, remote_path in pairs:
        hit = state.db.lookup_hash(digest)
        if hit:
            matches.append({**hit, "path": remote_path})
    return {
        "host": host,
        "files_hashed": len(pairs),
        "matches": matches,
        "note": (
            "Comparaison contre la base de hash locale uniquement. "
            "ClamAV et YARA ne sont pas applicables a distance sans agent."
        ),
    }


@remote_router.post("/ssh/packages")
def ssh_packages(
    host: str = Body(...), user: str | None = Body(None), port: int = Body(22)
) -> dict:
    """Inventaire dpkg distant, base du recoupement CVE (sections 4.1 et 4.4)."""
    try:
        packages = linux_remote_scanner.remote_packages(host, user, port)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except linux_remote_scanner.RemoteError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"host": host, "count": len(packages), "packages": packages}
