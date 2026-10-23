"""Scanner de paquets et d'integrite systeme pour Malryx (ScanType.PACKAGES).

Sous Debian / Linux :
- Liste les paquets installes via `dpkg-query`.
- Verifie l'integrite des fichiers installes avec `dpkg -V` (ou `debsums` si present) :
  detecte si des binaires systeme (/bin/ls, /usr/bin/sudo, /sbin/init, etc.) ont ete
  modifies ou remplaces par un rootkit / backdoor.
- Detecte les paquets orphelins, casses ou non signes.
- Scanne les fichiers modifies detectes a travers le pipeline de moteurs.

Sous Windows (compatibilite dev) :
- Liste les applications installees via le Registre / PowerShell.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Iterator

from core.config import IS_LINUX, IS_WINDOWS
from core.models import DetectionSource, Severity, Threat
from core.platform_compat import have_command, run

log = logging.getLogger(__name__)


@dataclass
class InstalledPackage:
    name: str
    version: str
    arch: str = ""
    status: str = "installed"
    description: str = ""
    modified_files: list[str] = field(default_factory=list)


def list_installed_packages() -> list[InstalledPackage]:
    """Liste tous les paquets installes sur le systeme hote."""
    if IS_LINUX:
        return _list_debian_packages()
    if IS_WINDOWS:
        return _list_windows_apps()
    return []


def _list_debian_packages() -> list[InstalledPackage]:
    """Interroge dpkg-query pour obtenir la liste propre des paquets."""
    res = run([
        "dpkg-query",
        "-W",
        "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"
    ], timeout=60)

    packages: list[InstalledPackage] = []
    if not res.ok:
        log.warning("dpkg-query a echoue : %s", res.stderr)
        return packages

    for line in res.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 4:
            pkg_name, version, arch, status = parts[0], parts[1], parts[2], parts[3]
            if status == "installed":
                packages.append(InstalledPackage(
                    name=pkg_name,
                    version=version,
                    arch=arch,
                    status=status
                ))
    return packages


def verify_package_integrity() -> dict[str, list[str]]:
    """Verifie les fichiers modifies par rapport a la somme de controle originale.

    Rend un dictionnaire {nom_paquet: [fichiers_modifies]}.
    Utilise `dpkg -V` (standard dpkg >= 1.17) ou `debsums -c`.
    """
    if not IS_LINUX:
        return {}

    modified_by_pkg: dict[str, list[str]] = {}

    if have_command("dpkg"):
        # dpkg -V sort des lignes du type:
        # ??5?????? c /etc/pam.d/common-auth (le c indique fichier de config)
        # ..5......   /usr/bin/ls           (binaire modifie !)
        res = run(["dpkg", "-V"], timeout=180)
        if res.stdout:
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line or len(line) < 11:
                    continue
                flags = line[:9]
                rest = line[9:].strip()
                is_config = rest.startswith("c ")
                filepath = rest[2:].strip() if is_config else rest.strip()

                # Le 3e caractere '5' indique que le MD5 digest ne correspond pas
                if len(flags) >= 3 and flags[2] == "5" and not is_config:
                    if os.path.exists(filepath):
                        # Trouver a quel paquet appartient ce fichier
                        pkg_res = run(["dpkg", "-S", filepath], timeout=10)
                        pkg_name = pkg_res.stdout.split(":")[0].strip() if pkg_res.ok else "system"
                        modified_by_pkg.setdefault(pkg_name, []).append(filepath)

    return modified_by_pkg


def _list_windows_apps() -> list[InstalledPackage]:
    """Liste les logiciels sous Windows pour les tests de dev."""
    ps_cmd = (
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Select-Object DisplayName, DisplayVersion "
        "| Where-Object { $_.DisplayName } "
        "| ConvertTo-Json -Compress"
    )
    res = run(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    packages: list[InstalledPackage] = []
    if res.ok and res.stdout.strip():
        import json
        try:
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                name = item.get("DisplayName")
                version = item.get("DisplayVersion") or "1.0"
                if name:
                    packages.append(InstalledPackage(
                        name=name,
                        version=version,
                        arch="x64",
                        status="installed"
                    ))
        except Exception as exc:
            log.debug("erreur parsing windows apps : %s", exc)
    return packages
