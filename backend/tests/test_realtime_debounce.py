"""Tests du temps reel durci (lot 4, 2026-10-28).

Couvre la file debounce (pure), la notation de fichiers (liens ignores,
dedupe par (mtime, taille)) et le traitement des evenements inotify
(recursivite dossier, overflow) sans kernel ni AppState reelle.
"""
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.realtime import (
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_ISDIR,
    IN_MOVED_TO,
    IN_Q_OVERFLOW,
    DebounceQueue,
    RealtimeWatcher,
)


def _watcher():
    w = RealtimeWatcher.__new__(RealtimeWatcher)
    w._pending = DebounceQueue()
    w._scanned_cache = {}
    w._overflow_rescan = False
    return w


def test_debounce_stable_then_due():
    q = DebounceQueue()
    q.note("/tmp/a", 100.0, 10, now=0.0)
    assert q.due(0.9) == []
    assert q.due(1.0) == ["/tmp/a"]
    assert q.due(2.0) == []  # deja retire


def test_debounce_change_resets_stability_but_not_cap():
    q = DebounceQueue()
    q.note("/tmp/a", 100.0, 10, now=0.0)
    q.note("/tmp/a", 101.0, 20, now=0.9)  # changement : stabilite repart
    assert q.due(1.5) == []
    assert q.due(2.0) == ["/tmp/a"]
    # Plafond 10 s : changement tardif ne repousse pas au-dela.
    q.note("/tmp/b", 100.0, 10, now=0.0)
    q.note("/tmp/b", 101.0, 20, now=9.0)
    assert q.due(10.0) == ["/tmp/b"]


def test_note_file_skips_symlink_and_scanned_version(tmp_path):
    w = _watcher()
    target = tmp_path / "real.txt"
    target.write_bytes(b"hello")
    link = tmp_path / "link.txt"
    os.symlink(str(target), str(link))
    w._note_file(str(link))
    assert w._pending.pending == {}
    w._note_file(str(target))
    assert str(target) in w._pending.pending
    # Marque comme scanne a l'identique : plus note.
    stat = target.stat()
    w._scanned_cache[str(target)] = (stat.st_mtime, stat.st_size)
    w._pending.pending.clear()
    w._note_file(str(target))
    assert w._pending.pending == {}


def _event(wd, mask, name):
    name_field = name.encode() + b"\x00"
    return struct.pack("iIII", wd, mask, 0, len(name_field)) + name_field


class _FakeLibc:
    def __init__(self):
        self.watched = []

    def inotify_add_watch(self, fd, path, mask):
        self.watched.append(path.decode())
        return 100 + len(self.watched)


def test_process_events_file_create_notes_and_dir_create_watches(tmp_path):
    w = _watcher()
    parent = tmp_path / "parent"
    newdir = parent / "newdir"
    newdir.mkdir(parents=True)
    (newdir / "inside.txt").write_bytes(b"data")
    target = parent / "file.txt"
    target.write_bytes(b"data")
    wd_to_path = {7: str(parent)}
    libc = _FakeLibc()
    raw = _event(7, IN_CREATE, "file.txt") + _event(7, IN_CREATE | IN_ISDIR, "newdir")
    w._process_inotify_events(raw, wd_to_path, libc, fd=99)
    assert str(target) in w._pending.pending
    assert str(newdir / "inside.txt") in w._pending.pending  # balayage post-watch
    assert str(newdir) in libc.watched


def test_process_events_overflow_sets_rescan(tmp_path):
    w = _watcher()
    raw = struct.pack("iIII", -1, IN_Q_OVERFLOW, 0, 0)
    w._process_inotify_events(raw, {}, _FakeLibc(), fd=99)
    assert w._overflow_rescan is True
