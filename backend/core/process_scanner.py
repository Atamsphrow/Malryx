"""Scanner de memoire et de processus pour Malryx (ScanType.MEMORY).

Sous Linux (cible principale) :
- Scanne l'arborescence /proc pour lister les processus actifs.
- Verifie les executables sur disque relies aux processus via /proc/<pid>/exe.
- Detecte les executables marques comme 'deleted' (technique classique de malware
  qui supprime son binaire apres execution pour masquer sa presence sur disque).
- Analyse les bibliotheques partagees chargees (/proc/<pid>/maps).
- Passe tous les binaires et modules charges dans le pipeline des moteurs Malryx.

Sous Windows (compatibilite dev) :
- Utilise tasklist / PowerShell pour identifier les processus et leurs chemins.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from core.config import IS_LINUX, IS_WINDOWS
from core.models import DetectionSource, Severity, Threat
from core.platform_compat import run
from engines.base import Engine, FileContext

log = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe_path: str | None = None
    cmdline: list[str] = field(default_factory=list)
    user: str | None = None
    deleted_exe: bool = False
    mapped_files: set[str] = field(default_factory=set)


def list_running_processes() -> Iterator[ProcessInfo]:
    """Liste les processus actifs de maniere portable."""
    if IS_LINUX:
        yield from _list_linux_processes()
    elif IS_WINDOWS:
        yield from _list_windows_processes()
    else:
        log.warning("list_running_processes non supporte sur cette plateforme")


def _list_linux_processes() -> Iterator[ProcessInfo]:
    """Parcourt /proc/[0-9]+ sans dependances externes."""
    proc_dir = Path("/proc")
    if not proc_dir.exists():
        return

    for entry in proc_dir.iterdir():
        if not entry.is_dir() or not entry.name.isdigit():
            continue

        pid = int(entry.name)
        exe_path: str | None = None
        deleted_exe = False
        name = entry.name

        # Nom depuis /proc/<pid>/comm ou status
        comm_path = entry / "comm"
        if comm_path.exists():
            try:
                name = comm_path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                pass

        # Executable associe
        exe_link = entry / "exe"
        try:
            target = os.readlink(exe_link)
            if " (deleted)" in target:
                deleted_exe = True
                target = target.replace(" (deleted)", "")
            exe_path = target
        except OSError:
            # Droits insuffisants ou processus noyau (kworker, etc.)
            pass

        # Ligne de commande
        cmdline: list[str] = []
        cmd_path = entry / "cmdline"
        try:
            raw_cmd = cmd_path.read_bytes()
            if raw_cmd:
                cmdline = [p for p in raw_cmd.decode(errors="replace").split("\0") if p]
        except OSError:
            pass

        # Fichiers mappes en memoire (librairies / .so)
        mapped_files: set[str] = set()
        maps_path = entry / "maps"
        try:
            for line in maps_path.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 6:
                    filepath = parts[5]
                    if filepath.startswith("/") and not filepath.startswith(("/dev", "/anon_inode")):
                        mapped_files.add(filepath.replace(" (deleted)", ""))
        except OSError:
            pass

        yield ProcessInfo(
            pid=pid,
            name=name,
            exe_path=exe_path,
            cmdline=cmdline,
            deleted_exe=deleted_exe,
            mapped_files=mapped_files,
        )


def _list_windows_processes() -> Iterator[ProcessInfo]:
    """Recupere les processus sous Windows via PowerShell / tasklist."""
    res = run([
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine | ConvertTo-Json -Compress"
    ], timeout=15)

    if res.ok and res.stdout.strip():
        import json
        try:
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            for p in data:
                pid = p.get("ProcessId")
                name = p.get("Name") or f"PID_{pid}"
                exe = p.get("ExecutablePath")
                cmd = p.get("CommandLine") or ""
                cmdline = [cmd] if cmd else []
                if pid is not None:
                    yield ProcessInfo(
                        pid=pid,
                        name=name,
                        exe_path=exe,
                        cmdline=cmdline,
                    )
            return
        except Exception as exc:
            log.debug("erreur parsing Get-CimInstance : %s", exc)

    # Repli sur tasklist
    res_tasklist = run(["tasklist", "/FO", "CSV", "/NH"], timeout=10)
    if res_tasklist.ok:
        import csv
        import io
        reader = csv.reader(io.StringIO(res_tasklist.stdout))
        for row in reader:
            if len(row) >= 2:
                name = row[0]
                try:
                    pid = int(row[1])
                    yield ProcessInfo(pid=pid, name=name)
                except ValueError:
                    continue
