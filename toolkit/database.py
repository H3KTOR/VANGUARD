"""database.py -- read/write access to the shared VANGUARD SQLite database.

The Go core (core/internal/database, migrated via GORM's AutoMigrate) owns
the canonical schema. This module does NOT run migrations and does NOT
create tables -- it assumes `vanguard serve` has already run at least once
against the target DB file. It only ever issues plain SQL against the four
tables GORM creates: users, system_metrics, incidents, firewall_rules.

Concurrency / WAL-safety notes (important -- read before changing this
file):
  - The Go daemon opens SQLite in WAL mode (see core/internal/database/
    database.go) specifically so a long-running writer (the detection
    engine, metrics collector, Autopilot) can coexist with concurrent
    readers without "database is locked" errors. This module's read
    functions open **read-only** connections (`mode=ro` in the URI) so a
    toolkit run can NEVER block or corrupt the live daemon's WAL file,
    even if `vanguard serve` is running at the same time.
  - `sync_malicious_ips` (used by threat_sync.py) is the ONE function in
    this toolkit that writes to the database (inserting into
    firewall_rules). It opens a normal read-write connection with a busy
    timeout so it waits briefly instead of failing outright if the Go
    daemon happens to be mid-write, and commits in a single short
    transaction per batch to minimize the window it holds a write lock.
  - This toolkit never shells out and never touches the filesystem beyond
    the single SQLite file and (in pdf_reporter.py) its own output PDF --
    per the project's Python-toolkit safety constraint ("must never execute
    shell commands, only touches SQLite directly").
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Optional

from dateutil import parser as dateparser

DEFAULT_DB_PATH = os.environ.get("VANGUARD_DB_PATH", "vanguard.db")


class DatabaseNotFoundError(RuntimeError):
    """Raised when the configured SQLite file does not exist yet.

    This almost always means `vanguard serve` has never been run against
    this path -- the toolkit deliberately refuses to silently create an
    empty schema-less file, since that would just produce confusing "no
    such table" errors on the very next query instead of a clear message.
    """


def _resolve_path(db_path: Optional[str]) -> str:
    path = db_path or DEFAULT_DB_PATH
    if not os.path.isfile(path):
        raise DatabaseNotFoundError(
            f"VANGUARD database not found at '{path}'. Run `vanguard serve` "
            "at least once (or pass --db-path) before using the toolkit."
        )
    return path


@contextmanager
def connect_readonly(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    """Open a strictly read-only connection to the VANGUARD SQLite file.

    Using SQLite's `mode=ro` URI parameter guarantees this process can
    never write a single byte to the database or its WAL/SHM sidecar
    files, no matter what bug might exist in calling code -- it's a
    hard guarantee enforced by SQLite itself, not just a convention.
    """
    path = _resolve_path(db_path)
    uri = f"file:{path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def connect_readwrite(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    """Open a read-write connection for the few operations that need to
    insert rows (currently only threat_sync.py's firewall_rules inserts).

    A generous busy_timeout means concurrent writes from the live Go
    daemon cause this connection to wait briefly and retry rather than
    immediately raising `sqlite3.OperationalError: database is locked`.
    """
    path = _resolve_path(db_path)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    try:
        yield conn
    finally:
        conn.close()


def _parse_ts(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    try:
        return dateparser.isoparse(str(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Data classes mirroring core/internal/database/models.go
# ---------------------------------------------------------------------------


@dataclass
class Incident:
    id: int
    type: str
    source_ip: str
    severity: str
    risk_score: int
    status: str
    attempt_count: int
    ai_analysis: Optional[str]
    metadata: dict = field(default_factory=dict)
    detected_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Incident":
        raw_meta = row["metadata"] or ""
        try:
            metadata = json.loads(raw_meta) if raw_meta else {}
        except json.JSONDecodeError:
            metadata = {}
        return cls(
            id=row["id"],
            type=row["type"],
            source_ip=row["source_ip"],
            severity=row["severity"],
            risk_score=row["risk_score"],
            status=row["status"],
            attempt_count=row["attempt_count"],
            ai_analysis=row["ai_analysis"] or None,
            metadata=metadata,
            detected_at=_parse_ts(row["detected_at"]),
            resolved_at=_parse_ts(row["resolved_at"]),
            created_at=_parse_ts(row["created_at"]),
        )


@dataclass
class FirewallRule:
    id: int
    ip_address: str
    reason: str
    source: str
    is_whitelisted: bool
    is_active: bool
    incident_id: Optional[int]
    banned_at: Optional[datetime]
    unban_at: Optional[datetime]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "FirewallRule":
        return cls(
            id=row["id"],
            ip_address=row["ip_address"],
            reason=row["reason"] or "",
            source=row["source"],
            is_whitelisted=bool(row["is_whitelisted"]),
            is_active=bool(row["is_active"]),
            incident_id=row["incident_id"],
            banned_at=_parse_ts(row["banned_at"]),
            unban_at=_parse_ts(row["unban_at"]),
        )


@dataclass
class SystemMetric:
    id: int
    cpu_percent: float
    memory_percent: float
    memory_used_mb: int
    disk_percent: float
    active_connections: int
    timestamp: Optional[datetime]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SystemMetric":
        return cls(
            id=row["id"],
            cpu_percent=row["cpu_percent"],
            memory_percent=row["memory_percent"],
            memory_used_mb=row["memory_used_mb"],
            disk_percent=row["disk_percent"],
            active_connections=row["active_connections"],
            timestamp=_parse_ts(row["timestamp"]),
        )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def get_recent_incidents(
    db_path: Optional[str] = None,
    *,
    limit: int = 25,
    since_hours: Optional[int] = None,
    status: Optional[str] = None,
) -> list[Incident]:
    """Fetch the most recent incidents, newest first.

    Mirrors the filtering shape of the Go API's GET /api/incidents so the
    toolkit's view of "recent incidents" always matches what an operator
    sees on the dashboard.
    """
    clauses = []
    params: list[Any] = []
    if since_hours is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
        clauses.append("detected_at >= ?")
        params.append(cutoff)
    if status:
        clauses.append("status = ?")
        params.append(status)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT id, type, source_ip, severity, risk_score, status, attempt_count,
               ai_analysis, metadata, detected_at, resolved_at, created_at
        FROM incidents
        {where}
        ORDER BY detected_at DESC
        LIMIT ?
    """
    params.append(limit)

    with connect_readonly(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [Incident.from_row(r) for r in rows]


def get_incident_by_id(db_path: Optional[str], incident_id: int) -> Optional[Incident]:
    with connect_readonly(db_path) as conn:
        row = conn.execute(
            """SELECT id, type, source_ip, severity, risk_score, status, attempt_count,
                      ai_analysis, metadata, detected_at, resolved_at, created_at
               FROM incidents WHERE id = ?""",
            (incident_id,),
        ).fetchone()
    return Incident.from_row(row) if row else None


def set_incident_ai_analysis(db_path: Optional[str], incident_id: int, analysis_json: str) -> None:
    """Writes the AI analyst's JSON verdict back onto incidents.ai_analysis.

    This is the toolkit's second (and last) write path besides
    firewall_rules inserts, and is likewise a small, single-statement,
    immediately-committed transaction to minimize lock contention with the
    live Go daemon.
    """
    with connect_readwrite(db_path) as conn:
        conn.execute(
            "UPDATE incidents SET ai_analysis = ?, updated_at = ? WHERE id = ?",
            (analysis_json, datetime.now(timezone.utc).isoformat(), incident_id),
        )
        conn.commit()


def get_active_firewall_rules(db_path: Optional[str] = None) -> list[FirewallRule]:
    with connect_readonly(db_path) as conn:
        rows = conn.execute(
            """SELECT id, ip_address, reason, source, is_whitelisted, is_active,
                      incident_id, banned_at, unban_at
               FROM firewall_rules WHERE is_active = 1
               ORDER BY banned_at DESC"""
        ).fetchall()
    return [FirewallRule.from_row(r) for r in rows]


def ip_already_blocked_or_whitelisted(conn: sqlite3.Connection, ip: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM firewall_rules WHERE ip_address = ? AND is_active = 1 LIMIT 1",
        (ip,),
    ).fetchone()
    return row is not None


def insert_firewall_rule(
    conn: sqlite3.Connection,
    *,
    ip_address: str,
    reason: str,
    source: str = "manual",
    unban_at: Optional[datetime] = None,
) -> int:
    """Insert one firewall_rules row on an already-open read-write
    connection (caller controls the transaction/commit -- see
    threat_sync.sync_malicious_ips for the batching pattern).

    NOTE: this only writes the *database record*. It intentionally does
    NOT invoke ufw/iptables itself -- the toolkit never shells out. The
    live `vanguard serve` daemon's Autopilot.ReconcileOnStartup (or, in a
    future iteration, a lightweight poll) is what would apply these rows
    at the OS firewall level. Until then, rows inserted here are best
    understood as "pre-staged" bans a human/AI operator has approved.
    """
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO firewall_rules
               (ip_address, reason, source, is_whitelisted, is_active,
                incident_id, banned_at, unban_at, created_at, updated_at)
           VALUES (?, ?, ?, 0, 1, NULL, ?, ?, ?, ?)""",
        (
            ip_address,
            reason,
            source,
            now,
            unban_at.isoformat() if unban_at else None,
            now,
            now,
        ),
    )
    return cur.lastrowid


def get_metrics_since(db_path: Optional[str], since_hours: int = 24) -> list[SystemMetric]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    with connect_readonly(db_path) as conn:
        rows = conn.execute(
            """SELECT id, cpu_percent, memory_percent, memory_used_mb, disk_percent,
                      active_connections, timestamp
               FROM system_metrics WHERE timestamp >= ?
               ORDER BY timestamp ASC""",
            (cutoff,),
        ).fetchall()
    return [SystemMetric.from_row(r) for r in rows]


def get_summary_counts(db_path: Optional[str] = None, since_hours: int = 24) -> dict[str, Any]:
    """A lightweight aggregate used by pdf_reporter.py -- counts incidents
    by severity/status over the window, plus active-ban and whitelist
    totals, without pulling every row into Python.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    with connect_readonly(db_path) as conn:
        by_severity = dict(
            conn.execute(
                """SELECT severity, COUNT(*) FROM incidents
                   WHERE detected_at >= ? GROUP BY severity""",
                (cutoff,),
            ).fetchall()
        )
        by_status = dict(
            conn.execute(
                """SELECT status, COUNT(*) FROM incidents
                   WHERE detected_at >= ? GROUP BY status""",
                (cutoff,),
            ).fetchall()
        )
        total_incidents = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE detected_at >= ?", (cutoff,)
        ).fetchone()[0]
        active_bans = conn.execute(
            "SELECT COUNT(*) FROM firewall_rules WHERE is_active = 1 AND is_whitelisted = 0"
        ).fetchone()[0]
        whitelisted = conn.execute(
            "SELECT COUNT(*) FROM firewall_rules WHERE is_whitelisted = 1"
        ).fetchone()[0]
        top_source_ips = conn.execute(
            """SELECT source_ip, COUNT(*) as cnt FROM incidents
               WHERE detected_at >= ? GROUP BY source_ip
               ORDER BY cnt DESC LIMIT 10""",
            (cutoff,),
        ).fetchall()

    return {
        "window_hours": since_hours,
        "total_incidents": total_incidents,
        "by_severity": by_severity,
        "by_status": by_status,
        "active_bans": active_bans,
        "whitelisted": whitelisted,
        "top_source_ips": [(r["source_ip"], r["cnt"]) for r in top_source_ips],
    }
