"""Moteur ClamAV (section 4.6 : moteur de base open-source).

Deux modes, dans cet ordre de preference :

1. `clamd` via socket UNIX, commande INSTREAM. C'est le mode rapide : la base de
   signatures est deja chargee en memoire par le daemon. On envoie le contenu du
   fichier plutot que son chemin, ce qui evite le probleme classique du daemon
   tournant sous l'utilisateur `clamav` qui n'a pas le droit de lire les
   fichiers de l'utilisateur.
2. Binaire `clamscan` en repli. Fonctionnel mais lent : chaque appel recharge la
   base complete, on ne l'utilise donc que si aucun daemon n'ecoute.

Aucune dependance Python obligatoire : on parle le protocole clamd directement.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
from pathlib import Path

from core.models import DetectionSource, EngineStatus, Severity, Threat
from core.platform_compat import command_path, run

from .base import Engine, FileContext

log = logging.getLogger(__name__)

# Emplacements du socket clamd selon les distributions (Debian en premier).
SOCKET_CANDIDATES = [
    "/var/run/clamav/clamd.ctl",
    "/run/clamav/clamd.ctl",
    "/tmp/clamd.socket",
    "/var/run/clamd.scan/clamd.sock",
]

# clamd refuse par defaut les flux au-dela de StreamMaxLength (25 Mio).
STREAM_MAX = 25 * 1024 * 1024
CHUNK = 64 * 1024
SOCKET_TIMEOUT = 120.0


class ClamAVEngine(Engine):
    name = "clamav"
    source = DetectionSource.CLAMAV

    def __init__(self, socket_path: str | None = None, enabled: bool = True) -> None:
        self.enabled = enabled
        self._socket_path = socket_path or self._find_socket()
        self._clamscan = command_path("clamscan")
        self._version: str | None = None
        self._signatures: int | None = None
        self._daemon_ok: bool | None = None
        self._lock = threading.Lock()
        # Journalise une seule fois la bascule vers clamscan, pas a chaque fichier.
        self._warned_fallback = False

    # -- detection ---------------------------------------------------------- #

    @staticmethod
    def _find_socket() -> str | None:
        env = os.environ.get("MALRYX_CLAMD_SOCKET")
        if env and Path(env).exists():
            return env
        for candidate in SOCKET_CANDIDATES:
            if Path(candidate).exists():
                return candidate
        return None

    def _connect(self) -> socket.socket | None:
        if not self._socket_path or not hasattr(socket, "AF_UNIX"):
            return None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect(self._socket_path)
            return sock
        except OSError as exc:
            log.debug("connexion clamd impossible (%s) : %s", self._socket_path, exc)
            return None

    def _command(self, command: str) -> str | None:
        """Envoie une commande simple (PING, VERSION) et rend la reponse."""
        sock = self._connect()
        if sock is None:
            return None
        try:
            sock.sendall(f"z{command}\0".encode())
            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode(errors="replace").strip("\0\n ")
        except OSError as exc:
            log.debug("commande clamd %s echouee : %s", command, exc)
            return None
        finally:
            sock.close()

    def daemon_available(self) -> bool:
        if self._daemon_ok is None:
            self._daemon_ok = self._command("PING") == "PONG"
        return self._daemon_ok

    def is_available(self) -> bool:
        if not self.enabled:
            return False
        return self.daemon_available() or self._clamscan is not None

    def status(self) -> EngineStatus:
        if not self.enabled:
            return EngineStatus(name=self.name, available=False, detail="desactive")
        if self.daemon_available():
            raw = self._command("VERSION") or ""
            # Format : ClamAV 1.0.3/27200/Mon Aug 18 09:12:33 2025
            parts = raw.split("/")
            signatures = None
            if len(parts) >= 2 and parts[1].isdigit():
                signatures = int(parts[1])
            return EngineStatus(
                name=self.name,
                available=True,
                version=parts[0].strip() or None,
                signatures=signatures,
                detail=f"daemon clamd ({self._socket_path})",
            )
        if self._clamscan:
            result = run([self._clamscan, "--version"], timeout=20)
            version = result.stdout.strip().split("/")[0] if result.ok else None
            return EngineStatus(
                name=self.name,
                available=True,
                version=version,
                detail="binaire clamscan (lent : aucun daemon clamd detecte)",
            )
        detail = (
            "ClamAV absent. Sur Debian : sudo apt install clamav-daemon clamav puis "
            "sudo freshclam"
            if os.name != "nt"
            else "ClamAV indisponible sur cette plateforme (developpement)"
        )
        return EngineStatus(name=self.name, available=False, detail=detail)

    # -- analyse ------------------------------------------------------------ #

    def scan(self, ctx: FileContext) -> list[Threat]:
        if not self.enabled:
            return []
        verdict: str | None = None
        if self.daemon_available():
            verdict = self._scan_instream(ctx)
        if verdict is None and self._clamscan:
            if not self._warned_fallback and not self.daemon_available():
                log.info(
                    "clamd introuvable, repli sur clamscan : les scans seront "
                    "nettement plus lents"
                )
                self._warned_fallback = True
            verdict = self._scan_binary(ctx)
        if not verdict:
            return []
        return [
            Threat(
                path=ctx.path,
                name=verdict,
                severity=self._severity_for(verdict),
                source=self.source,
                sha256=ctx.sha256,
                size=ctx.size,
                details={"engine": "clamav"},
            )
        ]

    def _scan_instream(self, ctx: FileContext) -> str | None:
        """Rend le nom de la signature, ou None si propre / non concluant."""
        if ctx.size > STREAM_MAX:
            # Trop gros pour un flux : on laisse clamscan s'en charger.
            return None
        with self._lock:
            sock = self._connect()
            if sock is None:
                self._daemon_ok = False
                return None
            try:
                sock.sendall(b"zINSTREAM\0")
                with open(ctx.path, "rb") as handle:
                    while chunk := handle.read(CHUNK):
                        sock.sendall(struct.pack("!L", len(chunk)) + chunk)
                sock.sendall(struct.pack("!L", 0))
                response = sock.recv(8192).decode(errors="replace").strip("\0\n ")
            except (OSError, struct.error) as exc:
                log.debug("INSTREAM echoue sur %s : %s", ctx.path, exc)
                return None
            finally:
                sock.close()
        return self._parse_verdict(response)

    def _scan_binary(self, ctx: FileContext) -> str | None:
        result = run(
            [
                str(self._clamscan),
                "--no-summary",
                "--stdout",
                "--infected",
                ctx.path,
            ],
            timeout=180,
        )
        # clamscan : 0 = propre, 1 = infecte, 2 = erreur.
        if result.code == 1:
            return self._parse_verdict(result.stdout)
        if result.code == 2:
            log.debug("clamscan erreur sur %s : %s", ctx.path, result.stderr.strip())
        return None

    @staticmethod
    def _parse_verdict(response: str) -> str | None:
        """Extrait la signature d'une ligne `... : NOM FOUND`."""
        for line in response.splitlines():
            line = line.strip()
            if line.endswith("FOUND"):
                body = line[: -len("FOUND")].rstrip()
                if ":" in body:
                    body = body.rsplit(":", 1)[1]
                return body.strip() or "ClamAV-Detection"
            if line.endswith("ERROR"):
                log.debug("clamav ERROR : %s", line)
        return None

    @staticmethod
    def _severity_for(signature: str) -> Severity:
        lowered = signature.lower()
        if "eicar" in lowered or "test" in lowered:
            # Fichier de test standard : reel, mais inoffensif.
            return Severity.LOW
        if any(k in lowered for k in ("pua", "adware", "unwanted")):
            return Severity.MEDIUM
        if any(k in lowered for k in ("ransom", "rootkit", "backdoor", "trojan")):
            return Severity.CRITICAL
        return Severity.HIGH
