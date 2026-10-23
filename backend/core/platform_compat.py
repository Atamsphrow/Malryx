"""Garde-fous plateforme et execution de commandes externes.

Le produit cible Debian, mais le code doit rester importable et partiellement
testable ailleurs (developpement sous Windows). Toute fonctionnalite Linux-only
passe par `require_linux()` ou `LinuxOnly`, jamais par un import conditionnel
qui casserait le demarrage du backend.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from dataclasses import dataclass

from .config import IS_LINUX, IS_WINDOWS


class UnsupportedPlatform(RuntimeError):
    """Levee quand une fonctionnalite Linux-only est appelee hors Linux."""


def is_root() -> bool:
    if IS_WINDOWS:
        return False
    return os.geteuid() == 0


def require_linux(feature: str) -> None:
    if not IS_LINUX:
        raise UnsupportedPlatform(
            f"{feature} necessite Linux (plateforme actuelle : "
            f"{'Windows' if IS_WINDOWS else os.name})"
        )


def have_command(name: str) -> bool:
    return shutil.which(name) is not None


def command_path(name: str) -> str | None:
    return shutil.which(name)


@dataclass
class CommandResult:
    code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out

    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]


def run(
    args: list[str],
    timeout: float = 30.0,
    stdin_data: str | None = None,
) -> CommandResult:
    """Execute une commande externe sans passer par un shell.

    Aucune interpolation de chaine : les chemins fournis par l'utilisateur
    arrivent comme arguments distincts, jamais concatenes dans une ligne de
    commande interpretee.
    """
    if not args:
        raise ValueError("args vide")
    if shutil.which(args[0]) is None and not os.path.isabs(args[0]):
        return CommandResult(127, "", f"commande introuvable : {args[0]}")
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            input=stdin_data,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(-1, "", f"delai depasse ({timeout}s)", timed_out=True)
    except OSError as exc:
        return CommandResult(127, "", str(exc))
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


async def run_async(
    args: list[str],
    timeout: float = 30.0,
    stdin_data: str | None = None,
) -> CommandResult:
    """Version non bloquante de `run`, pour ne pas figer la boucle asyncio."""
    return await asyncio.to_thread(run, args, timeout, stdin_data)


def human_bytes(size: float | None) -> str:
    if size is None:
        return "-"
    units = ["o", "Kio", "Mio", "Gio", "Tio"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "o" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} Tio"
