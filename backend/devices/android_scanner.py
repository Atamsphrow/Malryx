"""Scan Android via ADB, et detection degradee sans debogage USB (section 4.2).

Trois niveaux d'acces, dans l'ordre decroissant :

- `ADB_DEBUG`        : debogage USB autorise. On liste les paquets, on lit les
                       permissions, on peut extraire un APK et le hacher.
- `ADB_UNAUTHORIZED` : le telephone est branche mais l'empreinte RSA n'a pas ete
                       acceptee. On le signale a l'utilisateur avec la marche a
                       suivre plutot que d'echouer silencieusement.
- `MTP_LIMITED`      : pas d'ADB du tout. Le telephone apparait comme un dossier
                       via MTP/GVFS ; on ne voit que les fichiers exposes, aucune
                       app. C'est deja utile pour scanner les APK telecharges.

Aucune commande n'est construite par concatenation de chaines : `adb` est appele
avec une liste d'arguments, et le nom de paquet est valide avant usage.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from pathlib import Path

from core.models import AndroidApp, DeviceAccess, DeviceInfo, DeviceKind, Severity
from core.platform_compat import CommandResult, have_command, run

log = logging.getLogger(__name__)

ADB = "adb"
# Un nom de paquet Android : segments alphanumeriques separes par des points.
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")

# Permissions a fort potentiel d'abus. Le poids sert au score de risque.
DANGEROUS_PERMISSIONS: dict[str, tuple[int, str]] = {
    "android.permission.READ_SMS": (15, "lecture des SMS"),
    "android.permission.RECEIVE_SMS": (15, "reception des SMS"),
    "android.permission.SEND_SMS": (18, "envoi de SMS (surfacturation possible)"),
    "android.permission.READ_CONTACTS": (10, "lecture des contacts"),
    "android.permission.READ_CALL_LOG": (14, "lecture du journal d'appels"),
    "android.permission.PROCESS_OUTGOING_CALLS": (14, "interception des appels"),
    "android.permission.RECORD_AUDIO": (16, "enregistrement du micro"),
    "android.permission.CAMERA": (12, "acces a la camera"),
    "android.permission.ACCESS_FINE_LOCATION": (12, "localisation precise"),
    "android.permission.READ_EXTERNAL_STORAGE": (6, "lecture du stockage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": (8, "ecriture sur le stockage"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        20,
        "installation d'autres applications",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        18,
        "affichage par-dessus les autres apps (superposition de phishing)",
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        25,
        "service d'accessibilite : peut lire l'ecran et cliquer a votre place",
    ),
    "android.permission.BIND_DEVICE_ADMIN": (
        22,
        "administrateur de l'appareil : difficile a desinstaller",
    ),
    "android.permission.READ_PHONE_STATE": (6, "identifiants de l'appareil"),
    "android.permission.QUERY_ALL_PACKAGES": (8, "inventaire des apps installees"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (6, "demarrage automatique"),
    "android.permission.DISABLE_KEYGUARD": (10, "desactivation du verrouillage"),
}

# Combinaisons qui, ensemble, dessinent un comportement de stalkerware.
COMBO_RULES: list[tuple[set[str], int, str]] = [
    (
        {
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        },
        20,
        "accessibilite + superposition : schema typique des chevaux de Troie bancaires",
    ),
    (
        {
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_SMS",
        },
        20,
        "micro + localisation + SMS : profil de logiciel espion",
    ),
    (
        {
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.QUERY_ALL_PACKAGES",
        },
        12,
        "peut inventorier et installer des applications (dropper)",
    ),
]


def adb_available() -> bool:
    return have_command(ADB)


def _adb(args: list[str], serial: str | None = None, timeout: float = 30) -> CommandResult:
    command = [ADB]
    if serial:
        command += ["-s", serial]
    return run(command + args, timeout=timeout)


def _valid_package(package: str) -> bool:
    return bool(PACKAGE_RE.match(package)) and len(package) <= 255


# --------------------------------------------------------------------------- #
# Detection des appareils
# --------------------------------------------------------------------------- #


def list_android_devices() -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    if adb_available():
        devices += _from_adb()
    devices += _from_mtp(known_serials={d.id for d in devices})
    return devices


def _from_adb() -> list[DeviceInfo]:
    result = _adb(["devices", "-l"], timeout=20)
    if not result.ok:
        log.debug("adb devices a echoue : %s", result.stderr.strip())
        return []
    devices: list[DeviceInfo] = []
    for line in result.lines():
        if line.startswith("List of devices") or "\t" not in line and " " not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if state == "device":
            devices.append(_describe_authorized(serial, parts[2:]))
        elif state == "unauthorized":
            devices.append(
                DeviceInfo(
                    id=serial,
                    kind=DeviceKind.ANDROID,
                    label=f"Android {serial} (non autorise)",
                    access=DeviceAccess.ADB_UNAUTHORIZED,
                    scannable=False,
                    blocked_reason=(
                        "Le debogage USB est actif mais cet ordinateur n'est pas "
                        "autorise. Deverrouillez le telephone et acceptez "
                        "l'empreinte RSA affichee, puis relancez la detection."
                    ),
                )
            )
        elif state in {"offline", "bootloader", "recovery"}:
            devices.append(
                DeviceInfo(
                    id=serial,
                    kind=DeviceKind.ANDROID,
                    label=f"Android {serial} ({state})",
                    access=DeviceAccess.NONE,
                    scannable=False,
                    blocked_reason=(
                        f"Appareil en etat '{state}'. Rebranchez le cable ou "
                        "redemarrez le telephone."
                    ),
                )
            )
    return devices


def _describe_authorized(serial: str, extras: list[str]) -> DeviceInfo:
    props = {}
    for key, prop in (
        ("model", "ro.product.model"),
        ("brand", "ro.product.brand"),
        ("android", "ro.build.version.release"),
        ("sdk", "ro.build.version.sdk"),
        ("patch", "ro.build.version.security_patch"),
    ):
        value = _adb(["shell", "getprop", prop], serial, timeout=15)
        props[key] = value.stdout.strip() if value.ok else ""

    label_parts = [p for p in (props.get("brand"), props.get("model")) if p]
    label = " ".join(label_parts) or f"Android {serial}"
    if props.get("android"):
        label += f" - Android {props['android']}"

    details: dict[str, object] = {k: v for k, v in props.items() if v}
    details["usb_debug"] = True
    for extra in extras:
        if ":" in extra:
            key, _, value = extra.partition(":")
            details[key] = value
    # Un telephone roote n'est pas une infection, mais change la surface d'attaque.
    su_check = _adb(["shell", "which", "su"], serial, timeout=10)
    details["rooted_hint"] = bool(su_check.ok and su_check.stdout.strip())
    return DeviceInfo(
        id=serial,
        kind=DeviceKind.ANDROID,
        label=label,
        access=DeviceAccess.ADB_DEBUG,
        model=props.get("model") or None,
        details=details,
    )


def _from_mtp(known_serials: set[str]) -> list[DeviceInfo]:
    """Telephones visibles via MTP/GVFS, sans debogage USB (4.2, mode limite)."""
    devices: list[DeviceInfo] = []
    roots = [
        Path(f"/run/user/{os.getuid()}/gvfs") if hasattr(os, "getuid") else None,
        Path("/media"),
    ]
    for root in roots:
        if root is None or not root.is_dir():
            continue
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name.lower()
            if "mtp" not in name and "gphoto" not in name:
                continue
            devices.append(
                DeviceInfo(
                    id=str(entry),
                    kind=DeviceKind.ANDROID,
                    label=f"{entry.name} (MTP, sans debogage USB)",
                    access=DeviceAccess.MTP_LIMITED,
                    mount_point=str(entry),
                    blocked_reason=(
                        "Sans debogage USB, seuls les fichiers exposes par MTP "
                        "sont analysables : les applications installees restent "
                        "invisibles."
                    ),
                    details={"usb_debug": False},
                )
            )
    return [d for d in devices if d.id not in known_serials]


# --------------------------------------------------------------------------- #
# Applications installees
# --------------------------------------------------------------------------- #


def list_apps(serial: str, include_system: bool = False) -> list[AndroidApp]:
    """Liste les paquets avec le chemin de leur APK."""
    args = ["shell", "pm", "list", "packages", "-f"]
    if not include_system:
        args.append("-3")  # applications tierces uniquement
    result = _adb(args, serial, timeout=60)
    if not result.ok:
        raise RuntimeError(
            f"impossible de lister les paquets : {result.stderr.strip() or result.stdout.strip()}"
        )
    apps: list[AndroidApp] = []
    for line in result.lines():
        if not line.startswith("package:"):
            continue
        # Format : package:/data/app/~~xyz/base.apk=com.exemple.app
        body = line[len("package:") :]
        apk_path, _, package = body.rpartition("=")
        if not package or not _valid_package(package):
            continue
        apps.append(
            AndroidApp(
                package=package,
                apk_path=apk_path or None,
                system_app=bool(apk_path.startswith(("/system", "/product", "/vendor"))),
            )
        )
    return sorted(apps, key=lambda a: a.package)


def analyze_app(serial: str, app: AndroidApp) -> AndroidApp:
    """Complete une app avec ses permissions, sa version et son score de risque."""
    if not _valid_package(app.package):
        raise ValueError(f"nom de paquet invalide : {app.package}")
    dump = _adb(
        ["shell", "dumpsys", "package", app.package], serial, timeout=45
    )
    if dump.ok:
        app.permissions = _parse_permissions(dump.stdout)
        app.version_name = _parse_first(
            dump.stdout, re.compile(r"versionName=([^\s]+)")
        )
        installer = _parse_first(
            dump.stdout, re.compile(r"installerPackageName=([^\s]+)")
        )
        if installer:
            app.notes.append(f"installe par : {installer}")
            if installer not in {"com.android.vending", "com.google.android.packageinstaller"}:
                app.notes.append(
                    "source d'installation hors Play Store (sideloading)"
                )
    score, reasons, dangerous = score_permissions(app.permissions)
    # Une app installee hors magasin officiel merite un point d'attention.
    if any("sideloading" in n for n in app.notes):
        score += 10
        reasons.append("installee hors magasin officiel")
    app.dangerous_permissions = dangerous
    app.risk_score = min(score, 100)
    app.severity = _severity_for_score(app.risk_score)
    app.notes.extend(reasons)
    return app


def _parse_permissions(dump: str) -> list[str]:
    permissions: set[str] = set()
    for match in re.finditer(r"(android\.permission\.[A-Z_]+)", dump):
        permissions.add(match.group(1))
    for match in re.finditer(r"^\s*([a-z][\w.]*\.permission\.[A-Z_]+)", dump, re.M):
        permissions.add(match.group(1))
    return sorted(permissions)


def _parse_first(text: str, pattern: re.Pattern[str]) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match else None


def score_permissions(permissions: list[str]) -> tuple[int, list[str], list[str]]:
    """Rend (score, explications, permissions dangereuses retenues)."""
    granted = set(permissions)
    score = 0
    reasons: list[str] = []
    dangerous: list[str] = []
    for permission in sorted(granted):
        weight_reason = DANGEROUS_PERMISSIONS.get(permission)
        if weight_reason is None:
            continue
        weight, description = weight_reason
        score += weight
        dangerous.append(permission)
        reasons.append(description)
    for combo, bonus, description in COMBO_RULES:
        if combo.issubset(granted):
            score += bonus
            reasons.append(description)
    return score, reasons, dangerous


def _severity_for_score(score: int) -> Severity:
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.CLEAN


# --------------------------------------------------------------------------- #
# Extraction d'APK et actions a distance
# --------------------------------------------------------------------------- #


def pull_apk(serial: str, app: AndroidApp, destination: Path | None = None) -> Path:
    """Extrait l'APK vers un fichier local, pour hachage et analyse."""
    if not app.apk_path:
        raise ValueError(f"chemin d'APK inconnu pour {app.package}")
    if not _valid_package(app.package):
        raise ValueError(f"nom de paquet invalide : {app.package}")
    target_dir = destination or Path(tempfile.mkdtemp(prefix="malryx-apk-"))
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{app.package}.apk"
    result = _adb(["pull", app.apk_path, str(target)], serial, timeout=300)
    if not result.ok or not target.is_file():
        raise RuntimeError(
            f"extraction de {app.package} echouee : "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return target


def uninstall(serial: str, package: str) -> str:
    """Desinstalle une application (4.2). Action destructive cote telephone."""
    if not _valid_package(package):
        raise ValueError(f"nom de paquet invalide : {package}")
    result = _adb(["uninstall", package], serial, timeout=120)
    output = (result.stdout + result.stderr).strip()
    if "Success" not in output:
        raise RuntimeError(f"desinstallation refusee : {output or 'sortie vide'}")
    return output


def revoke_permission(serial: str, package: str, permission: str) -> None:
    """Revoque une permission a distance (4.2)."""
    if not _valid_package(package):
        raise ValueError(f"nom de paquet invalide : {package}")
    if not re.match(r"^[\w.]+\.permission\.[A-Z_]+$", permission):
        raise ValueError(f"permission invalide : {permission}")
    result = _adb(["shell", "pm", "revoke", package, permission], serial, timeout=30)
    if not result.ok:
        raise RuntimeError(
            f"revocation refusee : {result.stderr.strip() or result.stdout.strip()}"
        )
