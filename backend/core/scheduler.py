"""Planificateur de scans (ScanType.FULL_SYSTEM / PATH selon config) via cron.

Analyse la chaine `scheduled_scan_cron` des reglages (ex: "0 3 * * *",
"daily", "weekly", "monthly", "@daily", "@weekly").
Ne necessite aucune dependance externe : parseur minimal + boucle asyncio.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from typing import TYPE_CHECKING

from core.models import ScanOptions, ScanRequest, ScanType

if TYPE_CHECKING:
    from core.app_state import AppState

log = logging.getLogger(__name__)

# Expressions cron predefinies
CRON_PRESETS = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
    "daily": "0 3 * * *",
    "weekly": "0 3 * * 0",   # dimanche 3h
    "monthly": "0 3 1 * *",  # 1er du mois 3h
}

CRON_FIELD_PATTERN = re.compile(r"^\s*(\*|(\d{1,2}(-\d{1,2})?(/\d{1,2})?(,\d{1,2})*))\s*$")


@dataclass
class CronSpec:
    minute: set[int] = None
    hour: set[int] = None
    day: set[int] = None
    month: set[int] = None
    dow: set[int] = None   # 0-6, cron : 0 (et 7) = dimanche
    # True si le champ d'origine etait "*" : indispensable pour la regle
    # crontab(5) jour-du-mois / jour-de-semaine (voir matches()).
    day_is_star: bool = True
    dow_is_star: bool = True

    def __post_init__(self):
        if self.minute is None:
            self.minute = set(range(60))
        if self.hour is None:
            self.hour = set(range(24))
        if self.day is None:
            self.day = set(range(1, 32))
        if self.month is None:
            self.month = set(range(1, 13))
        if self.dow is None:
            self.dow = set(range(7))
        # Normalise un eventuel 7 (dimanche en cron) vers 0.
        self.dow = {0 if v == 7 else v for v in self.dow}

    def matches(self, dt: datetime) -> bool:
        # Python : lundi=0 .. dimanche=6 ; cron : dimanche=0 .. samedi=6.
        # Comparer dt.weekday() directement a dow decalait d'un jour
        # (weekly "0 3 * * 0" declenchait lundi au lieu de dimanche).
        cron_dow = (dt.weekday() + 1) % 7
        day_match = dt.day in self.day
        dow_match = cron_dow in self.dow
        # crontab(5) : minute, heure et mois doivent correspondre, et pour
        # les deux champs jour, au moins l'un des deux doit correspondre.
        # Si l'un est "*", seul l'autre decide ; si les deux sont restreints,
        # c'est un OU, pas un ET.
        if self.day_is_star and self.dow_is_star:
            day_ok = True
        elif self.day_is_star:
            day_ok = dow_match
        elif self.dow_is_star:
            day_ok = day_match
        else:
            day_ok = day_match or dow_match
        return (
            dt.minute in self.minute
            and dt.hour in self.hour
            and dt.month in self.month
            and day_ok
        )

    def next_fire_after(self, after: datetime) -> datetime:
        """Calcule le prochain instant d'execution apres `after`."""
        # On avance minute par minute (simpliste mais suffisant pour des
        # intervalles de quelques minutes/jours). Pour les longues durees,
        # on peut sauter les jours, mais garde simple et fiable.
        cand = after.replace(second=0, microsecond=0)
        for _ in range(366 * 24 * 60):  # max 1 an de recherche
            cand += timedelta(minutes=1)
            if self.matches(cand):
                return cand
        return after + timedelta(days=1)  # fallback


def parse_cron_expression(expr: str) -> CronSpec | None:
    """Parse une expression cron standard 5 champs ou un preset."""
    expr = expr.strip().lower()
    if expr in CRON_PRESETS:
        expr = CRON_PRESETS[expr]

    parts = expr.split()
    if len(parts) != 5:
        log.warning("Expression cron invalide (attendu 5 champs) : %s", expr)
        return None

    def parse_field(field: str, min_val: int, max_val: int) -> set[int]:
        field = field.strip()
        if field == "*":
            return set(range(min_val, max_val + 1))
        result: set[int] = set()
        for part in field.split(","):
            part = part.strip()
            if not part:
                continue
            if "/" in part:
                base, step = part.split("/", 1)
                step = int(step)
                if base == "*":
                    rng = range(min_val, max_val + 1)
                elif "-" in base:
                    a, b = map(int, base.split("-", 1))
                    rng = range(a, b + 1)
                else:
                    rng = range(int(base), max_val + 1)
                result.update(v for v in rng if (v - min_val) % step == 0)
            elif "-" in part:
                a, b = map(int, part.split("-", 1))
                result.update(range(a, b + 1))
            else:
                result.add(int(part))
        return {v for v in result if min_val <= v <= max_val}

    try:
        minute = parse_field(parts[0], 0, 59)
        hour = parse_field(parts[1], 0, 23)
        day = parse_field(parts[2], 1, 31)
        month = parse_field(parts[3], 1, 12)
        dow = parse_field(parts[4], 0, 7)  # 0 ou 7 = dimanche (normalise en 0)
        return CronSpec(
            minute=minute, hour=hour, day=day, month=month, dow=dow,
            day_is_star=(parts[2] == "*"), dow_is_star=(parts[4] == "*"),
        )
    except Exception as exc:
        log.warning("Echec parsing cron '%s' : %s", expr, exc)
        return None


class ScanScheduler:
    def __init__(self, state: AppState) -> None:
        self.state = state
        self._running = False
        self._task: asyncio.Task | None = None
        self._next_run: datetime | None = None
        self._last_cron_expr: str = ""

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        log.info("Planificateur de scans demarre")

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        log.info("Planificateur de scans arrete")

    def _current_spec(self) -> CronSpec | None:
        expr = self.state.settings.scheduled_scan_cron.strip()
        if not expr:
            return None
        if expr != self._last_cron_expr:
            self._last_cron_expr = expr
            self._next_run = None  # forcer recalcul
        return parse_cron_expression(expr)

    def get_next_run(self) -> str | None:
        if self._next_run:
            return self._next_run.isoformat()
        spec = self._current_spec()
        if spec:
            self._next_run = spec.next_fire_after(datetime.now())
            return self._next_run.isoformat()
        return None

    async def _loop(self) -> None:
        try:
            while self._running:
                spec = self._current_spec()
                if spec is None:
                    self._next_run = None
                    await asyncio.sleep(60)
                    continue

                now = datetime.now()
                if self._next_run is None or now >= self._next_run:
                    # Heure du scan atteinte
                    self._next_run = spec.next_fire_after(now)
                    log.info("Lancement du scan planifie (prochain : %s)", self._next_run)
                    await self._launch_scheduled_scan()
                else:
                    # Attendre jusqu'a la prochaine minute
                    wait = (self._next_run - now).total_seconds()
                    await asyncio.sleep(min(max(wait, 1), 60))
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.warning("Erreur dans le planificateur : %s", exc)

    async def _launch_scheduled_scan(self) -> None:
        try:
            # Type de scan : FULL_SYSTEM par defaut pour les scans planifies
            scan = self.state.scans.start(
                ScanRequest(
                    type=ScanType.FULL_SYSTEM,
                    targets=["/"],
                    options=ScanOptions(
                        use_clamav=self.state.settings.clamav_enabled,
                        use_yara=self.state.settings.yara_enabled,
                        use_heuristics=self.state.settings.heuristics_enabled,
                        use_hash_db=True,
                        use_virustotal=self.state.settings.virustotal_enabled,
                    ),
                )
            )
            log.info("Scan planifie lance : %s", scan.id)
            self.state.bus.publish_threadsafe(
                "scan.started",
                {
                    "scan_id": scan.id,
                    "type": "full_system",
                    "targets": ["/"],
                    "engines": ["scheduled"],
                    "scheduled": True,
                },
            )
        except Exception as exc:
            log.error("Echec lancement scan planifie : %s", exc)