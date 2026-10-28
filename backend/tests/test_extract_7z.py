"""Tests de l'extraction .rar/.7z via 7z (lot 3, 2026-10-28).

7z n'est pas installe sur la VM de test : run()/have_command() sont
simules (monkeypatch du module scan_engine). Les cas reels couverts :
fichier regulier retenu, lien symbolique ignore, echec 7z -> erreur,
limite anti-bombe -> erreur, 7z absent -> None (erreur explicite en amont).
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.scan_engine as scan_engine
from core.platform_compat import CommandResult
from core.scan_engine import ScanManager


def _manager():
    return ScanManager.__new__(ScanManager)


def _fake_run_factory(files):
    """files : dict nom -> contenu ; cree aussi un lien symbolique piege."""
    def fake_run(args, timeout=30, stdin_data=None):
        assert args[0] == "7z"
        assert args[1] == "x"
        assert "-y" in args
        assert stdin_data == ""  # aucune invite ne doit bloquer
        dest = next(a[2:] for a in args if a.startswith("-o"))
        os.makedirs(dest, exist_ok=True)
        for name, content in files.items():
            path = os.path.join(dest, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(content)
        # Piege : lien symbolique vers /etc/passwd, a ne jamais scanner.
        os.symlink("/etc/passwd", os.path.join(dest, "evil-link"))
        return CommandResult(0, "Everything is Ok", "")

    return fake_run


def test_extract_7z_keeps_regular_files_skips_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_engine, "have_command", lambda name: True)
    monkeypatch.setattr(
        scan_engine, "run", _fake_run_factory({"hello.txt": b"hello", "sub/inner.txt": b"inner"})
    )
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"fake-7z")
    dest = tmp_path / "out"
    dest.mkdir()
    out = _manager()._extract_7z(str(archive), str(dest))
    names = sorted(rel for _, rel in out)
    assert names == ["hello.txt", "sub/inner.txt"]
    assert "evil-link" not in names


def test_extract_7z_failure_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_engine, "have_command", lambda name: True)

    def failing_run(args, timeout=30, stdin_data=None):
        return CommandResult(2, "", "Can not open file as archive")

    monkeypatch.setattr(scan_engine, "run", failing_run)
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"fake")
    with pytest.raises(RuntimeError, match="extraction 7z echouee"):
        _manager()._extract_7z(str(archive), str(tmp_path / "out"))


def test_extract_7z_bomb_ratio_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_engine, "have_command", lambda name: True)
    monkeypatch.setattr(
        scan_engine, "run", _fake_run_factory({"big.bin": b"\x00" * (1024 * 1024)})
    )
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"tiny")  # ratio >> 200
    with pytest.raises(RuntimeError, match="anti-bombe"):
        _manager()._extract_7z(str(archive), str(tmp_path / "out"))


def test_extract_returns_none_without_7z(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_engine, "have_command", lambda name: False)
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"fake")
    assert _manager()._extract(str(archive), str(tmp_path / "out")) is None
