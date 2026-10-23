"""Scan d'une autre machine Linux via SSH, en lecture seule et sans agent (4.4).

Principe : on n'installe rien sur la machine distante. On lui demande de
calculer les empreintes de ses fichiers (`find` + `sha256sum`, deja presents sur
toute Debian) et on compare ces empreintes a la base locale. Seules des chaines
hexadecimales traversent le reseau, jamais le contenu des fichiers.

Contraintes assumees :

- **Authentification par cle uniquement.** `BatchMode=yes` empeche toute
  demande de mot de passe interactive, qui bloquerait le backend indefiniment.
  Un hote non configure est signale avec la marche a suivre.
- **Verification de l'hote conservee.** On ne desactive pas
  StrictHostKeyChecking : accepter aveuglement une cle inconnue dans un outil de
  securite serait contradictoire.
"""

from __future__ import annotations

import logging
import re
import shlex

from core.models import DeviceAccess, DeviceInfo, DeviceKind
from core.platform_compat import CommandResult, have_command, run

log = logging.getLogger(__name__)

HOST_RE = re.compile(r"^[A-Za-z0-9._\-:\[\]]+$")
USER_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

SSH_BASE = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=accept-new",
]


class RemoteError(RuntimeError):
    pass


def _validate(host: str, user: str | None, port: int) -> None:
    if not HOST_RE.match(host):
        raise ValueError(f"nom d'hote invalide : {host!r}")
    if user is not None and not USER_RE.match(user):
        raise ValueError(f"nom d'utilisateur invalide : {user!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"port invalide : {port}")


def _ssh(
    host: str,
    remote_command: list[str],
    user: str | None = None,
    port: int = 22,
    timeout: float = 60,
) -> CommandResult:
    """Execute une commande distante. `remote_command` est echappe par shlex."""
    if not have_command("ssh"):
        raise RemoteError("client ssh absent. Sur Debian : sudo apt install openssh-client")
    _validate(host, user, port)
    target = f"{user}@{host}" if user else host
    payload = " ".join(shlex.quote(part) for part in remote_command)
    return run(["ssh", *SSH_BASE, "-p", str(port), target, payload], timeout=timeout)


def probe(host: str, user: str | None = None, port: int = 22) -> DeviceInfo:
    """Teste la connexion et rend un descripteur d'appareil."""
    _validate(host, user, port)
    device_id = f"ssh:{user + '@' if user else ''}{host}:{port}"
    result = _ssh(host, ["uname", "-sr"], user, port, timeout=20)
    if not result.ok:
        error = result.stderr.strip() or "hote injoignable"
        reason = (
            "Authentification par cle requise. Depuis cette machine : "
            f"ssh-copy-id {(user + '@') if user else ''}{host}"
            if "Permission denied" in error or "publickey" in error
            else error
        )
        return DeviceInfo(
            id=device_id,
            kind=DeviceKind.LINUX_HOST,
            label=f"{host} (inaccessible)",
            access=DeviceAccess.NONE,
            scannable=False,
            blocked_reason=reason,
        )
    kernel = result.stdout.strip()
    distro = _ssh(
        host,
        ["sh", "-c", ". /etc/os-release 2>/dev/null; echo ${PRETTY_NAME:-inconnu}"],
        user,
        port,
        timeout=20,
    )
    return DeviceInfo(
        id=device_id,
        kind=DeviceKind.LINUX_HOST,
        label=f"{host} - {distro.stdout.strip() or kernel}",
        access=DeviceAccess.SSH,
        details={
            "kernel": kernel,
            "distribution": distro.stdout.strip(),
            "user": user or "(defaut ssh)",
            "port": port,
        },
    )


def remote_hashes(
    host: str,
    paths: list[str],
    user: str | None = None,
    port: int = 22,
    max_size_mb: int = 128,
    timeout: float = 900,
) -> list[tuple[str, str]]:
    """Calcule a distance les SHA256 des fichiers sous `paths`.

    Rend une liste de (sha256, chemin distant). Les erreurs par fichier sont
    ignorees a distance (2>/dev/null) pour qu'un dossier illisible n'interrompe
    pas tout le parcours.
    """
    if not paths:
        raise ValueError("aucun chemin distant fourni")
    for path in paths:
        if not path.startswith("/"):
            raise ValueError(f"chemin distant non absolu : {path!r}")
    quoted = " ".join(shlex.quote(p) for p in paths)
    script = (
        f"find {quoted} -xdev -type f -size -{max_size_mb}M "
        f"-print0 2>/dev/null | xargs -0 -r sha256sum 2>/dev/null"
    )
    result = _ssh(host, ["sh", "-c", script], user, port, timeout=timeout)
    if not result.ok and not result.stdout.strip():
        raise RemoteError(
            f"parcours distant echoue : {result.stderr.strip() or 'sortie vide'}"
        )
    pairs: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        # Format sha256sum : "<hash>  <chemin>"
        if len(line) < 66:
            continue
        digest, _, remote_path = line.partition("  ")
        if len(digest) == 64 and remote_path:
            pairs.append((digest.lower(), remote_path))
    return pairs


def remote_packages(
    host: str, user: str | None = None, port: int = 22
) -> list[dict[str, str]]:
    """Inventaire dpkg de la machine distante, base du recoupement CVE (4.4)."""
    result = _ssh(
        host,
        ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\n"],
        user,
        port,
        timeout=120,
    )
    if not result.ok:
        raise RemoteError(
            f"inventaire dpkg impossible : {result.stderr.strip() or 'commande absente'}"
        )
    packages: list[dict[str, str]] = []
    for line in result.lines():
        fields = line.split("\t")
        if len(fields) >= 2:
            packages.append(
                {
                    "name": fields[0],
                    "version": fields[1],
                    "architecture": fields[2] if len(fields) > 2 else "",
                }
            )
    return packages
