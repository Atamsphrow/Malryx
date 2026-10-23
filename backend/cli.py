"""Interface en ligne de commande de Malryx.

Le moteur est testable sans l'UI Flutter et sans serveur HTTP, ce qui rend le
diagnostic possible en SSH sur une machine sans session graphique.

    python backend/cli.py health
    python backend/cli.py scan ~/Telechargements --archives
    python backend/cli.py devices
    python backend/cli.py quarantine list
    python backend/cli.py signatures import ma-base.hashes
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.app_state import AppState, init_state  # noqa: E402
from core.config import APP_VERSION  # noqa: E402
from core.models import (  # noqa: E402
    ScanOptions,
    ScanRequest,
    ScanStatus,
    ScanType,
    Severity,
)
from core.platform_compat import human_bytes, is_root  # noqa: E402
from devices import android_scanner, usb_scanner, windows_scanner  # noqa: E402

# Couleurs ANSI, desactivees si la sortie n'est pas un terminal.
_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


SEVERITY_COLORS = {
    Severity.CLEAN: "32",
    Severity.LOW: "36",
    Severity.MEDIUM: "33",
    Severity.HIGH: "31",
    Severity.CRITICAL: "1;31",
}


def _severity(value: Severity) -> str:
    return _c(SEVERITY_COLORS.get(value, "0"), value.value.upper())


# --------------------------------------------------------------------------- #
# Commandes
# --------------------------------------------------------------------------- #


def cmd_health(state: AppState, args: argparse.Namespace) -> int:
    print(f"Malryx {APP_VERSION}")
    print(f"  plateforme     : {sys.platform}")
    print(f"  root           : {'oui' if is_root() else 'non'}")
    print(f"  donnees        : {state.paths.data_dir}")
    print(f"  base           : {state.paths.db_path}")
    print(f"  quarantaine    : {state.paths.quarantine_dir}")
    print("\nMoteurs de detection :")
    for engine in state.scans.engine_status():
        mark = _c("32", "disponible") if engine.available else _c("31", "indisponible")
        line = f"  {engine.name:<12} {mark}"
        if engine.version:
            line += f"  v{engine.version}"
        if engine.signatures is not None:
            line += f"  {engine.signatures} signature(s)"
        print(line)
        if engine.detail:
            print(f"               {engine.detail}")
    stats = state.db.stats()
    print("\nHistorique :")
    print(f"  scans termines : {stats['scans_completed']}")
    print(f"  fichiers vus   : {stats['files_scanned_total']}")
    print(f"  en quarantaine : {stats['quarantine_active']}")
    return 0


def cmd_scan(state: AppState, args: argparse.Namespace) -> int:
    options = ScanOptions(
        use_clamav=not args.no_clamav,
        use_yara=not args.no_yara,
        use_heuristics=not args.no_heuristics,
        use_virustotal=args.virustotal,
        scan_archives=args.archives,
        auto_quarantine=args.quarantine,
        follow_symlinks=args.follow_symlinks,
    )
    scan_type = ScanType(args.type)
    try:
        scan = state.scans.start(
            ScanRequest(type=scan_type, targets=args.targets, options=options)
        )
    except (FileNotFoundError, ValueError) as exc:
        print(_c("31", f"erreur : {exc}"), file=sys.stderr)
        return 2

    print(f"scan {scan.id} ({scan_type.value}) : {', '.join(scan.targets) or '-'}")
    seen_threats = 0
    try:
        while True:
            progress = state.scans.get_progress(scan.id)
            current = state.scans.get(scan.id)
            if progress is not None and _TTY:
                percent = progress.percent
                bar = f"{percent:5.1f}%" if percent is not None else "  ...."
                current_file = (progress.current_file or "")[-60:]
                sys.stdout.write(
                    f"\r  {bar} {progress.phase:<12} "
                    f"{progress.files_scanned}/{progress.files_total or '?'} "
                    f"{current_file:<60}"
                )
                sys.stdout.flush()
            if current is not None and len(current.threats) > seen_threats:
                if _TTY:
                    sys.stdout.write("\r" + " " * 100 + "\r")
                for threat in current.threats[seen_threats:]:
                    print(
                        f"  [{_severity(threat.severity)}] {threat.name}\n"
                        f"      {threat.path}  ({threat.source.value})"
                    )
                seen_threats = len(current.threats)
            if current is not None and current.status not in (
                ScanStatus.PENDING,
                ScanStatus.RUNNING,
            ):
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        state.scans.cancel(scan.id)
        print("\nannulation demandee...")
        time.sleep(1.0)

    if _TTY:
        sys.stdout.write("\r" + " " * 100 + "\r")
    final = state.scans.get(scan.id)
    if final is None:
        print("resultat introuvable", file=sys.stderr)
        return 1
    print(
        f"\n{final.status.value} en {final.duration_s:.1f}s : "
        f"{final.files_scanned} fichier(s) analyse(s), "
        f"{human_bytes(final.bytes_scanned)}, "
        f"{final.files_skipped} ignore(s)"
    )
    if final.threats:
        print(_c("31", f"{len(final.threats)} menace(s), severite max : "
                       f"{final.max_severity().value}"))
    else:
        print(_c("32", "aucune menace detectee"))
    if final.errors:
        print(f"{len(final.errors)} erreur(s), les 5 premieres :")
        for error in final.errors[:5]:
            print(f"  - {error}")
    return 1 if final.threats else 0


def cmd_devices(state: AppState, args: argparse.Namespace) -> int:
    groups = [
        ("Medias amovibles", usb_scanner.list_removable_devices),
        ("Android", android_scanner.list_android_devices),
        ("Volumes Windows", windows_scanner.list_windows_volumes),
    ]
    for title, collector in groups:
        print(f"\n{title} :")
        try:
            devices = collector()
        except Exception as exc:
            print(f"  detection impossible : {exc}")
            continue
        if not devices:
            print("  (aucun)")
            continue
        for device in devices:
            print(f"  {device.label}")
            print(f"    id     : {device.id}")
            print(f"    acces  : {device.access.value}")
            if device.mount_point:
                print(f"    monte  : {device.mount_point}")
            if device.total_bytes:
                print(
                    f"    taille : {human_bytes(device.used_bytes)} / "
                    f"{human_bytes(device.total_bytes)}"
                )
            if device.blocked_reason:
                print(f"    {_c('33', device.blocked_reason)}")
    return 0


def cmd_quarantine(state: AppState, args: argparse.Namespace) -> int:
    from core.quarantine import QuarantineError

    if args.action == "list":
        entries = state.quarantine.list_entries(include_inactive=args.all)
        if not entries:
            print("quarantaine vide")
            return 0
        for entry in entries:
            print(f"{entry.id}  [{_severity(entry.severity)}]  {entry.status.value}")
            print(f"  origine : {entry.original_path}")
            print(f"  menace  : {entry.threat_name or '-'}")
            print(f"  taille  : {human_bytes(entry.size)}  sha256 : {entry.sha256[:16]}...")
        return 0
    try:
        if args.action == "add":
            entry = state.quarantine.quarantine_file(args.target, force=args.force)
            print(f"mis en quarantaine : {entry.id}")
        elif args.action == "restore":
            path = state.quarantine.restore(args.target)
            print(f"restaure : {path}")
        elif args.action == "delete":
            state.quarantine.delete(args.target)
            print("supprime definitivement")
    except QuarantineError as exc:
        print(_c("31", f"erreur : {exc}"), file=sys.stderr)
        return 2
    return 0


def cmd_signatures(state: AppState, args: argparse.Namespace) -> int:
    if args.action == "count":
        print(f"{state.db.count_known_hashes()} signature(s) en base locale")
        return 0
    source = Path(args.file).expanduser()
    if not source.is_file():
        print(_c("31", f"fichier introuvable : {source}"), file=sys.stderr)
        return 2
    imported = state.import_signature_file(source)
    print(f"{imported} signature(s) importee(s), total : {state.db.count_known_hashes()}")
    return 0


# --------------------------------------------------------------------------- #
# Analyse des arguments
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malryx", description="Antivirus Malryx (CLI)")
    parser.add_argument("--version", action="version", version=f"Malryx {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="etat des moteurs et de la base")

    scan = sub.add_parser("scan", help="lance un scan")
    scan.add_argument("targets", nargs="*", help="fichiers ou dossiers a scanner")
    scan.add_argument(
        "--type",
        default=ScanType.PATH.value,
        choices=[t.value for t in ScanType],
        help="type de scan (path par defaut)",
    )
    scan.add_argument("--archives", action="store_true", help="fouiller les archives")
    scan.add_argument("--no-clamav", action="store_true")
    scan.add_argument("--no-yara", action="store_true")
    scan.add_argument("--no-heuristics", action="store_true")
    scan.add_argument("--virustotal", action="store_true", help="interroger VirusTotal")
    scan.add_argument(
        "--quarantine", action="store_true", help="isoler automatiquement les menaces"
    )
    scan.add_argument("--follow-symlinks", action="store_true")

    sub.add_parser("devices", help="liste les appareils detectes")

    quarantine = sub.add_parser("quarantine", help="gere la quarantaine")
    quarantine.add_argument(
        "action", choices=["list", "add", "restore", "delete"]
    )
    quarantine.add_argument(
        "target", nargs="?", help="chemin (add) ou identifiant d'entree"
    )
    quarantine.add_argument("--all", action="store_true", help="inclure l'historique")
    quarantine.add_argument(
        "--force", action="store_true", help="autoriser un chemin systeme critique"
    )

    signatures = sub.add_parser("signatures", help="base de hash locale")
    signatures.add_argument("action", choices=["import", "count"])
    signatures.add_argument("file", nargs="?", help="fichier <sha256>:<nom>:<severite>")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    import logging

    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s"
    )

    if args.command == "scan" and not args.targets and args.type == ScanType.PATH.value:
        parser.error("indiquez au moins une cible, ou utilisez --type full_system")
    if args.command == "quarantine" and args.action != "list" and not args.target:
        parser.error(f"l'action '{args.action}' demande une cible")
    if args.command == "signatures" and args.action == "import" and not args.file:
        parser.error("indiquez le fichier de signatures a importer")

    state = init_state()
    handlers = {
        "health": cmd_health,
        "scan": cmd_scan,
        "devices": cmd_devices,
        "quarantine": cmd_quarantine,
        "signatures": cmd_signatures,
    }
    try:
        return handlers[args.command](state, args)
    finally:
        state.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
