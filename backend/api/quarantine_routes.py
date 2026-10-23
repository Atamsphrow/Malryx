"""Routes REST de la quarantaine (section 4.1) et import de signatures (7)."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from core.app_state import AppState, get_state
from core.events import EVT_QUARANTINE_CHANGED
from core.models import QuarantineEntry, QuarantineRequest
from core.quarantine import ProtectedPathError, QuarantineError

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/quarantine", tags=["quarantine"])


@router.get("", response_model=list[QuarantineEntry])
def list_entries(
    include_inactive: bool = Query(False),
    state: AppState = Depends(get_state),
) -> list[QuarantineEntry]:
    return state.quarantine.list_entries(include_inactive=include_inactive)


@router.post("", response_model=QuarantineEntry, status_code=201)
def quarantine_file(
    request: QuarantineRequest,
    force: bool = Query(
        False,
        description=(
            "Force la mise en quarantaine d'un fichier systeme critique. "
            "A n'utiliser qu'en connaissance de cause."
        ),
    ),
    state: AppState = Depends(get_state),
) -> QuarantineEntry:
    try:
        entry = state.quarantine.quarantine_file(
            request.path,
            threat_name=request.threat_name,
            severity=request.severity,
            force=force,
        )
    except ProtectedPathError as exc:
        # 409 plutot que 403 : la demande est comprise, c'est l'etat de la cible
        # qui la rend refusable, et elle reste forcable.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except QuarantineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"erreur disque : {exc}") from exc
    state.bus.publish(EVT_QUARANTINE_CHANGED, {"action": "added", "id": entry.id})
    return entry


@router.post("/{entry_id}/restore")
def restore(
    entry_id: str,
    destination: str | None = Body(
        None,
        embed=True,
        description="Chemin de restauration. Par defaut, l'emplacement d'origine.",
    ),
    state: AppState = Depends(get_state),
) -> dict:
    try:
        restored = state.quarantine.restore(entry_id, destination)
    except QuarantineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"erreur disque : {exc}") from exc
    state.bus.publish(EVT_QUARANTINE_CHANGED, {"action": "restored", "id": entry_id})
    return {"ok": True, "path": restored}


@router.delete("/{entry_id}")
def delete(entry_id: str, state: AppState = Depends(get_state)) -> dict:
    """Suppression definitive du fichier en quarantaine. Irreversible."""
    try:
        state.quarantine.delete(entry_id)
    except QuarantineError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    state.bus.publish(EVT_QUARANTINE_CHANGED, {"action": "deleted", "id": entry_id})
    return {"ok": True}


@router.get("/orphans")
def orphans(state: AppState = Depends(get_state)) -> dict:
    """Fichiers presents dans le dossier de quarantaine mais absents de la base."""
    return {"orphans": state.quarantine.orphan_files()}


# --------------------------------------------------------------------------- #
# Signatures locales
# --------------------------------------------------------------------------- #

signatures_router = APIRouter(prefix="/api/signatures", tags=["signatures"])


@signatures_router.post("/import")
def import_signatures(
    path: str = Body(..., embed=True), state: AppState = Depends(get_state)
) -> dict:
    """Importe un fichier `<sha256>:<nom>:<severite>` dans la base locale.

    Permet d'enrichir la detection sans reconstruire le paquet .deb (section 7).
    """
    source = Path(path).expanduser()
    if not source.is_file():
        raise HTTPException(status_code=404, detail=f"fichier introuvable : {path}")
    imported = state.import_signature_file(source)
    return {"imported": imported, "total": state.db.count_known_hashes()}


@signatures_router.get("/count")
def count_signatures(state: AppState = Depends(get_state)) -> dict:
    return {"total": state.db.count_known_hashes()}
