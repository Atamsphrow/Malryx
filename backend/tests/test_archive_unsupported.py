"""Archive .rar/.7z : le contenu non extractible doit etre signale, jamais
passe sous silence (lot 1, 2026-10-28).

_scan_archive() est appele sur un ScanManager construit sans __init__ (on
evite ClamAV/YARA/DB) : seul le chemin "extraction impossible" est exerce,
il n'a besoin d'aucun moteur.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import ScanOptions, ScanResult, ScanType
from core.scan_engine import ScanJob, ScanManager


class _DummyBus:
    def publish_threadsafe(self, *args, **kwargs):
        pass


def test_rar_records_explicit_error_and_no_threat(tmp_path):
    fake_rar = tmp_path / "test.rar"
    fake_rar.write_bytes(b"ceci n'est pas une vraie archive rar")
    manager = ScanManager.__new__(ScanManager)
    manager.bus = _DummyBus()
    result = ScanResult(type=ScanType.PATH, targets=[str(fake_rar)])
    job = ScanJob(result, ScanOptions())
    manager._scan_archive(job, [], str(fake_rar), depth=1)
    assert result.threats == []
    assert len(result.errors) == 1
    assert "format non pris en charge" in result.errors[0]
    assert "non analyse" in result.errors[0]
    assert str(fake_rar) in result.errors[0]
