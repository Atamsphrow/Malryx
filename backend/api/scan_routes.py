"""Routes REST du scan : lancement, suivi, annulation, historique."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from core.app_state import AppState, get_state
from core.models import ScanRequest, ScanResult, ScanStatus

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scan"])


@router.post("", response_model=ScanResult, status_code=202)
def start_scan(
    request: ScanRequest, state: AppState = Depends(get_state)
) -> ScanResult:
    """Lance un scan et rend immediatement son descripteur.

    La progression n'est pas dans la reponse : elle arrive par le WebSocket
    /ws, filtre sur le `scan_id` retourne ici.
    """
    try:
        return state.scans.start(request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("")
def list_scans(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    state: AppState = Depends(get_state),
) -> dict:
    """Historique des scans, du plus recent au plus ancien."""
    return {
        "active": [scan.summary() for scan in state.scans.active_scans()],
        "history": state.db.list_scans(limit=limit, offset=offset),
    }


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str, state: AppState = Depends(get_state)) -> ScanResult:
    scan = state.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"scan inconnu : {scan_id}")
    return scan


@router.get("/{scan_id}/progress")
def get_progress(scan_id: str, state: AppState = Depends(get_state)) -> dict:
    """Progression instantanee.

    Utile au demarrage de l'UI pour se raccrocher a un scan deja en cours, ou
    si le WebSocket s'est coupe.
    """
    progress = state.scans.get_progress(scan_id)
    if progress is not None:
        return progress.to_event()
    scan = state.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"scan inconnu : {scan_id}")
    # Scan termine et deja sorti de la memoire : on reconstitue depuis la base.
    return {
        "scan_id": scan.id,
        "status": scan.status.value,
        "phase": "termine",
        "files_scanned": scan.files_scanned,
        "files_total": scan.files_scanned,
        "bytes_scanned": scan.bytes_scanned,
        "threats_found": len(scan.threats),
        "errors": len(scan.errors),
        "elapsed_s": round(scan.duration_s, 2),
        "percent": 100.0,
        "current_file": None,
    }


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: str, state: AppState = Depends(get_state)) -> dict:
    if not state.scans.cancel(scan_id):
        scan = state.scans.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail=f"scan inconnu : {scan_id}")
        raise HTTPException(
            status_code=409,
            detail=f"scan deja termine (statut : {scan.status.value})",
        )
    return {"ok": True, "scan_id": scan_id, "status": ScanStatus.CANCELLED.value}


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, state: AppState = Depends(get_state)) -> dict:
    if not state.db.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail=f"scan inconnu : {scan_id}")
    return {"ok": True}
