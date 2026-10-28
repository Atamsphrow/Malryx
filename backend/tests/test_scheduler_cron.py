"""Tests du planificateur cron (lot 1, 2026-10-28).

Regression : CronSpec.matches() comparait dt.weekday() (lundi=0) directement
a dow cron (dimanche=0), donc "weekly" declenchait lundi au lieu de dimanche.
Reference : crontab(5) - 0 ou 7 = dimanche, et jour-du-mois / jour-de-semaine
restreints ensemble = OU.
"""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scheduler import parse_cron_expression


def test_weekly_fires_sunday_not_monday():
    spec = parse_cron_expression("weekly")
    assert spec is not None
    # 2026-11-01 = dimanche, 2026-11-02 = lundi, 2026-10-31 = samedi
    assert spec.matches(datetime(2026, 11, 1, 3, 0))
    assert not spec.matches(datetime(2026, 11, 2, 3, 0))
    assert not spec.matches(datetime(2026, 10, 31, 3, 0))


def test_weekly_next_fire_after_saturday_is_sunday():
    spec = parse_cron_expression("weekly")
    assert spec.next_fire_after(datetime(2026, 10, 31, 12, 0)) == datetime(2026, 11, 1, 3, 0)


def test_dow_7_is_sunday_too():
    spec = parse_cron_expression("0 3 * * 7")
    assert spec is not None
    assert spec.matches(datetime(2026, 11, 1, 3, 0))
    assert not spec.matches(datetime(2026, 11, 2, 3, 0))


def test_monthly_first_of_month_regardless_of_weekday():
    spec = parse_cron_expression("monthly")
    assert spec.matches(datetime(2026, 11, 1, 3, 0))  # 1er nov., dimanche
    assert spec.matches(datetime(2026, 12, 1, 3, 0))  # 1er dec., mardi
    assert not spec.matches(datetime(2026, 11, 2, 3, 0))


def test_dom_and_dow_both_restricted_is_or_not_and():
    # 15 du mois OU lundi, a 3h.
    spec = parse_cron_expression("0 3 15 * 1")
    assert spec.matches(datetime(2026, 11, 15, 3, 0))  # dom seul (dimanche)
    assert spec.matches(datetime(2026, 11, 16, 3, 0))  # dow seul (lundi)
    assert not spec.matches(datetime(2026, 11, 17, 3, 0))  # ni l'un ni l'autre
    assert spec.matches(datetime(2026, 12, 21, 3, 0))  # lundi, pas le 15


def test_daily_unchanged():
    spec = parse_cron_expression("daily")
    assert spec.matches(datetime(2026, 11, 1, 3, 0))
    assert spec.matches(datetime(2026, 11, 2, 3, 0))
    assert not spec.matches(datetime(2026, 11, 2, 4, 0))
