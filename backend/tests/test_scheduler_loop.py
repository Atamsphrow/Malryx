"""Tests de la boucle du planificateur (correctif lot 5, 2026-10-28).

Bug trouve par la validation lot 5 : au demarrage, la boucle lancait un
scan complet immediatement meme si la prochaine echeance etait dans
plusieurs jours (condition `_next_run is None` => lancement). Le correctif
calcule d'abord la prochaine echeance et ne lance que si elle est due.
"""
import asyncio
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Settings
from core.models import ScanOptions, ScanRequest, ScanType
from core.scheduler import ScanScheduler


class _FakeBus:
    def publish_threadsafe(self, *args, **kwargs):
        pass


class _FakeScans:
    def __init__(self):
        self.started = []

    def start(self, request):
        self.started.append(request)
        return type("Scan", (), {"id": "fake"})()


class _FakeState:
    def __init__(self, cron):
        self.settings = Settings(scheduled_scan_cron=cron)
        self.scans = _FakeScans()
        self.bus = _FakeBus()


async def _run_for(sched, seconds=1.5):
    sched.start()
    await asyncio.sleep(seconds)
    sched.stop()
    await asyncio.sleep(0.2)
    return sched


def test_scheduler_does_not_launch_before_due():
    state = _FakeState("0 3 * * 0")  # dimanche 03:00, pas maintenant
    asyncio.run(_run_for(ScanScheduler(state)))
    assert state.scans.started == []


def test_scheduler_launches_when_due():
    state = _FakeState("0 3 * * 0")
    sched = ScanScheduler(state)
    sched._next_run = datetime.now() - timedelta(minutes=1)
    sched._last_cron_expr = "0 3 * * 0"  # sinon _current_spec() remet _next_run a None
    asyncio.run(_run_for(sched))
    assert len(state.scans.started) == 1
    assert state.scans.started[0].type == ScanType.FULL_SYSTEM
