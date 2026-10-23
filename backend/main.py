"""Point d'entree du backend Malryx : API REST + WebSocket temps reel.

Le serveur n'ecoute que sur la boucle locale. Il est lance en sous-processus par
l'application Flutter et n'est jamais expose au reseau.

Lancement en developpement :
    python backend/main.py --reload
Lancement par l'application empaquetee :
    malryx-backend --port 8765
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys
from pathlib import Path

# Permet `python backend/main.py` comme `python -m main` depuis backend/.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from api import device_routes, quarantine_routes, scan_routes  # noqa: E402
from core import events  # noqa: E402
from core.app_state import AppState, get_state, init_state  # noqa: E402
from core.config import (  # noqa: E402
    APP_VERSION,
    DEFAULT_HOST,
    DEFAULT_PORT,
    IS_LINUX,
    PATHS,
    save_settings,
)
from core.models import (  # noqa: E402
    HealthResponse,
    ScanOptions,
    ScanRequest,
    ScanType,
)
from core.platform_compat import is_root  # noqa: E402
from devices import usb_scanner  # noqa: E402

log = logging.getLogger("malryx")

# Intervalle de surveillance des medias amovibles (section 4.5).
DEVICE_POLL_S = 5.0


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    try:
        PATHS.data_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(PATHS.log_path, encoding="utf-8"))
    except OSError:
        pass  # journal fichier optionnel, on ne bloque pas le demarrage
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


# --------------------------------------------------------------------------- #
# Surveillance des medias amovibles
# --------------------------------------------------------------------------- #


async def _watch_removable_devices(state: AppState) -> None:
    """Detecte les branchements/debranchements et declenche l'auto-scan.

    Un scan automatique a l'insertion est un comportement attendu d'un
    antivirus, mais il lit des donnees personnelles sans qu'on le demande : il
    reste donc conditionne au reglage `autoscan_removable`.
    """
    known: dict[str, str] = {}
    first_pass = True
    while True:
        try:
            current = {
                device.id: device.mount_point or ""
                for device in usb_scanner.list_removable_devices()
            }
            for device_id, mount in current.items():
                if device_id in known:
                    continue
                if not first_pass:
                    log.info("media amovible detecte : %s", mount or device_id)
                    state.bus.publish(
                        events.EVT_DEVICE_CONNECTED,
                        {"device_id": device_id, "mount_point": mount},
                    )
                    if state.settings.autoscan_removable and mount:
                        _autoscan(state, mount)
            for device_id in set(known) - set(current):
                state.bus.publish(
                    events.EVT_DEVICE_DISCONNECTED, {"device_id": device_id}
                )
            known = current
            first_pass = False
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("surveillance des medias amovibles : %s", exc)
        await asyncio.sleep(DEVICE_POLL_S)


def _autoscan(state: AppState, mount_point: str) -> None:
    try:
        scan = state.scans.start(
            ScanRequest(
                type=ScanType.USB,
                targets=[mount_point],
                options=ScanOptions(),
            )
        )
        log.info("auto-scan du media %s lance (scan %s)", mount_point, scan.id)
    except Exception as exc:
        log.warning("auto-scan de %s impossible : %s", mount_point, exc)


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    state = init_state()
    # Le bus doit connaitre la boucle qui sert les WebSockets pour que les
    # threads de scan puissent y reinjecter leurs evenements.
    state.bus.bind_loop(asyncio.get_running_loop())
    log.info(
        "Malryx %s pret sur %s (root=%s, linux=%s)",
        APP_VERSION,
        PATHS.data_dir,
        is_root(),
        IS_LINUX,
    )
    # Démarrer la protection en temps réel et le planificateur si activés
    if state.settings.realtime_protection:
        state.realtime.start()
    if state.settings.scheduled_scan_cron:
        state.scheduler.start()

    watcher = asyncio.create_task(_watch_removable_devices(state))
    try:
        yield
    finally:
        state.scheduler.stop()
        state.realtime.stop()
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher
        state.shutdown()
        log.info("Malryx arrete")


app = FastAPI(
    title="Malryx",
    description=(
        "Antivirus local pour Debian : scan du systeme hote et des appareils "
        "connectes (Android, Windows, Linux distant, medias amovibles)."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
)

# L'UI Flutter desktop appelle en direct, sans origine navigateur. On autorise
# tout de meme localhost pour permettre le debogage depuis Flutter web.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_routes.router)
app.include_router(quarantine_routes.router)
app.include_router(quarantine_routes.signatures_router)
app.include_router(device_routes.router)
app.include_router(device_routes.android_router)
app.include_router(device_routes.remote_router)


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health(state: AppState = Depends(get_state)) -> HealthResponse:
    """Etat du backend et des moteurs. Premier appel fait par l'UI au demarrage."""
    return HealthResponse(
        version=APP_VERSION,
        platform=sys.platform,
        is_linux=IS_LINUX,
        root=is_root(),
        engines=state.scans.engine_status(),
    )


@app.get("/api/stats", tags=["system"])
def stats(state: AppState = Depends(get_state)) -> dict:
    """Chiffres du tableau de bord."""
    data = state.db.stats()
    data["active_scans"] = len(state.scans.active_scans())
    data["realtime_protection"] = state.settings.realtime_protection
    return data


@app.get("/api/settings", tags=["system"])
def get_settings(state: AppState = Depends(get_state)) -> dict:
    return state.settings.to_dict()


@app.put("/api/settings", tags=["system"])
def update_settings(updates: dict, state: AppState = Depends(get_state)) -> dict:
    """Met a jour les reglages et recharge les moteurs concernes."""
    return state.update_settings(updates).to_dict()


@app.websocket("/ws")
async def websocket_events(websocket: WebSocket, scan_id: str | None = None) -> None:
    """Flux d'evenements temps reel.

    Sans parametre, le client recoit tout : progression, menaces, branchements
    d'appareils. Avec `?scan_id=...`, il ne recoit que ce qui concerne ce scan.
    """
    await websocket.accept()
    state = get_state()
    subscriber = state.bus.subscribe(scan_id)
    log.debug(
        "WebSocket connecte (scan_id=%s, %d abonne(s))",
        scan_id,
        state.bus.subscriber_count,
    )
    try:
        await websocket.send_json(
            {
                "type": "hello",
                "data": {
                    "version": APP_VERSION,
                    "scan_id": scan_id,
                    "active_scans": [s.summary() for s in state.scans.active_scans()],
                },
            }
        )
        while True:
            event = await subscriber.queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        log.debug("WebSocket deconnecte")
    except Exception as exc:
        log.warning("WebSocket interrompu : %s", exc)
    finally:
        state.bus.unsubscribe(subscriber)


def main() -> int:
    # L'executable empaquete sert aussi de CLI : `malryx-backend --cli scan ...`
    # delegue a cli.py. Cela evite un second binaire PyInstaller de 40 Mio pour
    # le meme code.
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        from cli import main as cli_main

        return cli_main(sys.argv[2:])

    parser = argparse.ArgumentParser(prog="malryx-backend", description="Backend Malryx")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--reload", action="store_true", help="rechargement a chaud")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    configure_logging(args.verbose)
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        log.error(
            "refus de demarrer sur %s : le backend Malryx est strictement local "
            "et ne doit pas etre expose au reseau",
            args.host,
        )
        return 2

    import uvicorn

    uvicorn.run(
        "main:app" if args.reload else app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_config=None,
        access_log=args.verbose,
    )
    return 0


if __name__ == "__main__":
    # Certains reglages doivent exister sur disque avant le premier lancement de
    # l'UI (elle lit accent_color au demarrage).
    PATHS.ensure()
    if not PATHS.settings_path.exists():
        from core.config import Settings

        save_settings(Settings())
    raise SystemExit(main())
