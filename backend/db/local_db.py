"""Persistance SQLite : historique des scans, menaces, quarantaine, hash connus.

Une seule connexion partagee, protegee par un verrou : les scans ecrivent depuis
des threads de travail pendant que l'API lit depuis la boucle asyncio.
WAL active pour que les lectures ne bloquent pas les ecritures.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from core.models import (
    DetectionSource,
    QuarantineEntry,
    QuarantineStatus,
    ScanResult,
    ScanStatus,
    ScanType,
    Severity,
    Threat,
)

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    type          TEXT NOT NULL,
    targets       TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL,
    device_id     TEXT,
    started_at    REAL NOT NULL,
    finished_at   REAL,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_skipped INTEGER NOT NULL DEFAULT 0,
    bytes_scanned INTEGER NOT NULL DEFAULT 0,
    threats_count INTEGER NOT NULL DEFAULT 0,
    max_severity  TEXT NOT NULL DEFAULT 'clean',
    engines_used  TEXT NOT NULL DEFAULT '[]',
    errors        TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

CREATE TABLE IF NOT EXISTS threats (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    path        TEXT NOT NULL,
    name        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    source      TEXT NOT NULL,
    sha256      TEXT,
    size        INTEGER,
    detected_at REAL NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0,
    details     TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_threats_scan ON threats(scan_id);
CREATE INDEX IF NOT EXISTS idx_threats_sha  ON threats(sha256);

CREATE TABLE IF NOT EXISTS quarantine (
    id             TEXT PRIMARY KEY,
    original_path  TEXT NOT NULL,
    stored_path    TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    size           INTEGER NOT NULL,
    threat_name    TEXT,
    severity       TEXT NOT NULL,
    source         TEXT,
    quarantined_at REAL NOT NULL,
    status         TEXT NOT NULL,
    original_mode  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);

-- Base de signatures locale (section 4.6), alimentable sans rebuild du .deb.
CREATE TABLE IF NOT EXISTS known_hashes (
    sha256   TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    source   TEXT NOT NULL DEFAULT 'hash_local',
    added_at REAL NOT NULL
);

-- Cache des verdicts VirusTotal, pour ne pas re-interroger le cloud sans cesse.
CREATE TABLE IF NOT EXISTS hash_cache (
    sha256     TEXT PRIMARY KEY,
    malicious  INTEGER NOT NULL DEFAULT 0,
    total      INTEGER NOT NULL DEFAULT 0,
    label      TEXT,
    payload    TEXT NOT NULL DEFAULT '{}',
    checked_at REAL NOT NULL
);
"""


def _json_load(raw: Any, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return fallback


class LocalDB:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- scans -------------------------------------------------------------- #

    def save_scan(self, result: ScanResult) -> None:
        """Insere ou met a jour un scan, menaces comprises (idempotent)."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scans (id, type, targets, status, device_id, started_at,
                                   finished_at, files_scanned, files_skipped,
                                   bytes_scanned, threats_count, max_severity,
                                   engines_used, errors)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    finished_at=excluded.finished_at,
                    files_scanned=excluded.files_scanned,
                    files_skipped=excluded.files_skipped,
                    bytes_scanned=excluded.bytes_scanned,
                    threats_count=excluded.threats_count,
                    max_severity=excluded.max_severity,
                    engines_used=excluded.engines_used,
                    errors=excluded.errors
                """,
                (
                    result.id,
                    result.type.value,
                    json.dumps(result.targets),
                    result.status.value,
                    result.device_id,
                    result.started_at,
                    result.finished_at,
                    result.files_scanned,
                    result.files_skipped,
                    result.bytes_scanned,
                    len(result.threats),
                    result.max_severity().value,
                    json.dumps([e.value for e in result.engines_used]),
                    json.dumps(result.errors[:50]),
                ),
            )
            for threat in result.threats:
                self._insert_threat(result.id, threat)
            self._conn.commit()

    def _insert_threat(self, scan_id: str, threat: Threat) -> None:
        self._conn.execute(
            """
            INSERT INTO threats (id, scan_id, path, name, severity, source, sha256,
                                 size, detected_at, quarantined, details)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET quarantined=excluded.quarantined
            """,
            (
                threat.id,
                scan_id,
                threat.path,
                threat.name,
                threat.severity.value,
                threat.source.value,
                threat.sha256,
                threat.size,
                threat.detected_at,
                int(threat.quarantined),
                json.dumps(threat.details),
            ),
        )

    def add_threat(self, scan_id: str, threat: Threat) -> None:
        with self._lock:
            self._insert_threat(scan_id, threat)
            self._conn.commit()

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "type": r["type"],
                "targets": _json_load(r["targets"], []),
                "status": r["status"],
                "started_at": r["started_at"],
                "finished_at": r["finished_at"],
                "duration_s": round((r["finished_at"] or r["started_at"]) - r["started_at"], 2),
                "files_scanned": r["files_scanned"],
                "threats_count": r["threats_count"],
                "max_severity": r["max_severity"],
            }
            for r in rows
        ]

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return None
            threat_rows = self._conn.execute(
                "SELECT * FROM threats WHERE scan_id = ? ORDER BY detected_at",
                (scan_id,),
            ).fetchall()
        return ScanResult(
            id=row["id"],
            type=ScanType(row["type"]),
            targets=_json_load(row["targets"], []),
            status=ScanStatus(row["status"]),
            device_id=row["device_id"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            files_scanned=row["files_scanned"],
            files_skipped=row["files_skipped"],
            bytes_scanned=row["bytes_scanned"],
            errors=_json_load(row["errors"], []),
            engines_used=[
                DetectionSource(e) for e in _json_load(row["engines_used"], [])
            ],
            threats=[
                Threat(
                    id=t["id"],
                    path=t["path"],
                    name=t["name"],
                    severity=Severity(t["severity"]),
                    source=DetectionSource(t["source"]),
                    sha256=t["sha256"],
                    size=t["size"],
                    detected_at=t["detected_at"],
                    quarantined=bool(t["quarantined"]),
                    details=_json_load(t["details"], {}),
                )
                for t in threat_rows
            ],
        )

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS scans,
                       COALESCE(SUM(files_scanned), 0) AS files,
                       MAX(finished_at) AS last_scan
                FROM scans WHERE status = 'completed'
                """
            ).fetchone()
            active = self._conn.execute(
                "SELECT COUNT(*) AS n FROM quarantine WHERE status = 'quarantined'"
            ).fetchone()
            threats = self._conn.execute(
                "SELECT COUNT(*) AS n FROM threats"
            ).fetchone()
            signatures = self._conn.execute(
                "SELECT COUNT(*) AS n FROM known_hashes"
            ).fetchone()
        return {
            "scans_completed": row["scans"],
            "files_scanned_total": row["files"],
            "last_scan_at": row["last_scan"],
            "threats_total": threats["n"],
            "quarantine_active": active["n"],
            "local_signatures": signatures["n"],
        }

    # -- quarantaine -------------------------------------------------------- #

    def save_quarantine(self, entry: QuarantineEntry) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO quarantine (id, original_path, stored_path, sha256, size,
                                        threat_name, severity, source, quarantined_at,
                                        status, original_mode)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET status=excluded.status
                """,
                (
                    entry.id,
                    entry.original_path,
                    entry.stored_path,
                    entry.sha256,
                    entry.size,
                    entry.threat_name,
                    entry.severity.value,
                    entry.source.value if entry.source else None,
                    entry.quarantined_at,
                    entry.status.value,
                    entry.original_mode,
                ),
            )
            self._conn.commit()

    def _row_to_quarantine(self, row: sqlite3.Row) -> QuarantineEntry:
        return QuarantineEntry(
            id=row["id"],
            original_path=row["original_path"],
            stored_path=row["stored_path"],
            sha256=row["sha256"],
            size=row["size"],
            threat_name=row["threat_name"],
            severity=Severity(row["severity"]),
            source=DetectionSource(row["source"]) if row["source"] else None,
            quarantined_at=row["quarantined_at"],
            status=QuarantineStatus(row["status"]),
            original_mode=row["original_mode"],
        )

    def list_quarantine(self, include_inactive: bool = False) -> list[QuarantineEntry]:
        query = "SELECT * FROM quarantine"
        params: tuple[Any, ...] = ()
        if not include_inactive:
            query += " WHERE status = ?"
            params = (QuarantineStatus.QUARANTINED.value,)
        query += " ORDER BY quarantined_at DESC"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_quarantine(r) for r in rows]

    def get_quarantine(self, entry_id: str) -> QuarantineEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM quarantine WHERE id = ?", (entry_id,)
            ).fetchone()
        return self._row_to_quarantine(row) if row else None

    def set_quarantine_status(self, entry_id: str, status: QuarantineStatus) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE quarantine SET status = ? WHERE id = ?",
                (status.value, entry_id),
            )
            self._conn.commit()

    # -- base de hash locale ------------------------------------------------ #

    def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM known_hashes WHERE sha256 = ?", (sha256.lower(),)
            ).fetchone()
        if row is None:
            return None
        return {
            "sha256": row["sha256"],
            "name": row["name"],
            "severity": row["severity"],
            "source": row["source"],
        }

    def add_known_hashes(
        self, entries: Iterable[tuple[str, str, str]], source: str = "hash_local"
    ) -> int:
        """Ajoute des (sha256, nom, severite). Retourne le nombre de lignes ecrites."""
        rows = [
            (sha.lower().strip(), name.strip(), severity, source, time.time())
            for sha, name, severity in entries
            if len(sha.strip()) == 64
        ]
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO known_hashes (sha256, name, severity, source, added_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                    name=excluded.name, severity=excluded.severity
                """,
                rows,
            )
            self._conn.commit()
        return len(rows)

    def count_known_hashes(self) -> int:
        with self._lock:
            return int(
                self._conn.execute("SELECT COUNT(*) FROM known_hashes").fetchone()[0]
            )

    # -- cache VirusTotal --------------------------------------------------- #

    def get_cached_verdict(self, sha256: str, max_age_s: float) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hash_cache WHERE sha256 = ?", (sha256.lower(),)
            ).fetchone()
        if row is None or time.time() - row["checked_at"] > max_age_s:
            return None
        return {
            "malicious": row["malicious"],
            "total": row["total"],
            "label": row["label"],
            "payload": _json_load(row["payload"], {}),
            "checked_at": row["checked_at"],
        }

    def cache_verdict(
        self,
        sha256: str,
        malicious: int,
        total: int,
        label: str | None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO hash_cache (sha256, malicious, total, label, payload, checked_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                    malicious=excluded.malicious, total=excluded.total,
                    label=excluded.label, payload=excluded.payload,
                    checked_at=excluded.checked_at
                """,
                (
                    sha256.lower(),
                    malicious,
                    total,
                    label,
                    json.dumps(payload or {}),
                    time.time(),
                ),
            )
            self._conn.commit()
