"""SQLite storage layer shared by the scanner and the dashboard.

Design rules
------------
* A subdomain that was ever confirmed alive by httpx is never deleted.
  Its lifecycle is tracked through ``status`` (active/offline),
  ``first_seen``/``last_seen``/``last_checked`` and the ``events`` table.
* Every httpx JSON line is stored verbatim in ``httpx_results.raw`` (one row per
  probed URL per scan), every DNS answer in ``dns_results.raw``.
* WAL mode lets the dashboard read while a scan is writing.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

DEFAULT_DATA_DIR = "/data"


def data_dir() -> str:
    return os.environ.get("TRACKER_DATA", DEFAULT_DATA_DIR)


def db_path() -> str:
    return os.environ.get("TRACKER_DB") or os.path.join(data_dir(), "tracker.db")


def utcnow() -> str:
    """ISO-8601 UTC timestamp with second precision, e.g. 2026-01-31T12:00:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def jdump(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def jload(value, default=None):
    if value is None or value == "":
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Schema / migrations. Append new entries; never edit an applied migration.   #
# --------------------------------------------------------------------------- #
MIGRATIONS: list[str] = [
    # ---- v1 -------------------------------------------------------------- #
    """
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE roots (
        id            INTEGER PRIMARY KEY,
        domain        TEXT NOT NULL UNIQUE,
        created_at    TEXT NOT NULL,
        last_scan_id  INTEGER,
        last_scan_at  TEXT,
        wildcard      INTEGER NOT NULL DEFAULT 0,
        notes         TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE scans (
        id             INTEGER PRIMARY KEY,
        started_at     TEXT NOT NULL,
        finished_at    TEXT,
        status         TEXT NOT NULL,          -- running|success|partial|failed
        trigger        TEXT NOT NULL DEFAULT 'cli',
        params         TEXT NOT NULL DEFAULT '{}',
        tool_versions  TEXT NOT NULL DEFAULT '{}',
        output_dir     TEXT,
        error          TEXT
    );

    CREATE TABLE scan_roots (
        scan_id      INTEGER NOT NULL REFERENCES scans(id),
        root_id      INTEGER NOT NULL REFERENCES roots(id),
        status       TEXT NOT NULL,            -- running|success|partial|failed|skipped
        started_at   TEXT NOT NULL,
        finished_at  TEXT,
        stats        TEXT NOT NULL DEFAULT '{}',
        warnings     TEXT NOT NULL DEFAULT '[]',
        error        TEXT,
        PRIMARY KEY (scan_id, root_id)
    );

    CREATE TABLE subdomains (
        id                   INTEGER PRIMARY KEY,
        root_id              INTEGER NOT NULL REFERENCES roots(id),
        host                 TEXT NOT NULL UNIQUE,
        status               TEXT NOT NULL,     -- active|offline
        first_seen           TEXT NOT NULL,     -- first time httpx confirmed it
        last_seen            TEXT NOT NULL,     -- last time httpx confirmed it
        last_checked         TEXT NOT NULL,     -- last time it was probed at all
        status_changed_at    TEXT NOT NULL,
        first_scan_id        INTEGER,
        last_seen_scan_id    INTEGER,
        last_checked_scan_id INTEGER,
        seen_count           INTEGER NOT NULL DEFAULT 1,
        sources              TEXT NOT NULL DEFAULT '[]',
        dns_resolves         INTEGER,           -- result of the last DNS lookup (1/0/NULL)
        offline_reason       TEXT,              -- dns|http when offline
        -- snapshot of the most recent successful probe (denormalised for search)
        url                  TEXT,
        scheme               TEXT,
        port                 INTEGER,
        status_code          INTEGER,
        title                TEXT,
        webserver            TEXT,
        content_type         TEXT,
        content_length       INTEGER,
        location             TEXT,
        tech                 TEXT NOT NULL DEFAULT '[]',
        ips                  TEXT NOT NULL DEFAULT '[]',
        cname                TEXT NOT NULL DEFAULT '[]',
        cdn_name             TEXT,
        body_hash            TEXT,
        favicon              TEXT,
        tls_subject_cn       TEXT,
        tls_issuer           TEXT,
        tls_not_after        TEXT,
        urls                 TEXT NOT NULL DEFAULT '[]',
        last_result_id       INTEGER,
        notes                TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_sub_root        ON subdomains(root_id);
    CREATE INDEX idx_sub_status      ON subdomains(status);
    CREATE INDEX idx_sub_first_seen  ON subdomains(first_seen);
    CREATE INDEX idx_sub_last_seen   ON subdomains(last_seen);
    CREATE INDEX idx_sub_code        ON subdomains(status_code);

    CREATE TABLE httpx_results (
        id              INTEGER PRIMARY KEY,
        scan_id         INTEGER NOT NULL REFERENCES scans(id),
        subdomain_id    INTEGER NOT NULL REFERENCES subdomains(id),
        observed_at     TEXT NOT NULL,
        phase           TEXT NOT NULL DEFAULT 'main',   -- main|san|recheck
        url             TEXT,
        status_code     INTEGER,
        title           TEXT,
        webserver       TEXT,
        content_length  INTEGER,
        body_hash       TEXT,
        raw             TEXT NOT NULL                    -- full httpx JSON line
    );
    CREATE INDEX idx_httpx_sub  ON httpx_results(subdomain_id, scan_id);
    CREATE INDEX idx_httpx_scan ON httpx_results(scan_id);

    CREATE TABLE dns_results (
        id            INTEGER PRIMARY KEY,
        scan_id       INTEGER NOT NULL REFERENCES scans(id),
        subdomain_id  INTEGER NOT NULL REFERENCES subdomains(id),
        observed_at   TEXT NOT NULL,
        resolves      INTEGER NOT NULL,
        a             TEXT NOT NULL DEFAULT '[]',
        aaaa          TEXT NOT NULL DEFAULT '[]',
        cname         TEXT NOT NULL DEFAULT '[]',
        raw           TEXT
    );
    CREATE INDEX idx_dns_sub ON dns_results(subdomain_id, scan_id);

    CREATE TABLE events (
        id            INTEGER PRIMARY KEY,
        scan_id       INTEGER REFERENCES scans(id),
        root_id       INTEGER NOT NULL REFERENCES roots(id),
        subdomain_id  INTEGER NOT NULL REFERENCES subdomains(id),
        type          TEXT NOT NULL,          -- new|offline|back_online|changed
        created_at    TEXT NOT NULL,
        details       TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_events_created ON events(created_at);
    CREATE INDEX idx_events_sub     ON events(subdomain_id);
    CREATE INDEX idx_events_type    ON events(type, created_at);

    CREATE TABLE tags (
        id          INTEGER PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
        color       TEXT NOT NULL DEFAULT '#6b7280',
        created_at  TEXT NOT NULL
    );

    CREATE TABLE subdomain_tags (
        subdomain_id  INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
        tag_id        INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
        created_at    TEXT NOT NULL,
        PRIMARY KEY (subdomain_id, tag_id)
    );
    CREATE INDEX idx_subtags_tag ON subdomain_tags(tag_id);

    CREATE TABLE scan_requests (
        id            INTEGER PRIMARY KEY,
        domains       TEXT NOT NULL,           -- comma separated, or "all"
        params        TEXT NOT NULL DEFAULT '{}',
        source        TEXT NOT NULL DEFAULT 'dashboard',
        status        TEXT NOT NULL DEFAULT 'queued',   -- queued|running|done|failed
        requested_at  TEXT NOT NULL,
        started_at    TEXT,
        finished_at   TEXT,
        scan_id       INTEGER,
        error         TEXT
    );
    CREATE INDEX idx_req_status ON scan_requests(status, id);
    """,
]

SCHEMA_VERSION = len(MIGRATIONS)


def connect(path: str | None = None, *, readonly: bool = False, timeout: float = 60.0) -> sqlite3.Connection:
    """Open the database, creating/migrating it if required."""
    path = path or db_path()
    if not readonly:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
    # isolation_level=None -> autocommit; we manage transactions explicitly.
    conn = sqlite3.connect(path, timeout=timeout, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)}")
    conn.execute("PRAGMA foreign_keys = ON")
    if not readonly:
        _set_wal(conn)
        conn.execute("PRAGMA synchronous = NORMAL")
        migrate(conn)
    return conn


def _set_wal(conn: sqlite3.Connection) -> None:
    # Switching journal mode needs a short exclusive lock; retry if a writer is busy.
    for attempt in range(10):
        try:
            mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if mode.lower() == "wal":
                return
        except sqlite3.OperationalError:
            pass
        time.sleep(0.5 * (attempt + 1))


def migrate(conn: sqlite3.Connection) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current >= SCHEMA_VERSION:
        return
    with transaction(conn, immediate=True):
        # Re-check inside the write lock: a concurrent process may have migrated.
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        for version in range(current, SCHEMA_VERSION):
            for statement in _split_sql(MIGRATIONS[version]):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {version + 1}")
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )


def _split_sql(script: str) -> list[str]:
    statements, buf = [], []
    for line in script.splitlines():
        stripped = line.split("--", 1)[0].rstrip()
        if not stripped.strip():
            continue
        buf.append(stripped)
        if stripped.endswith(";"):
            statements.append("\n".join(buf))
            buf = []
    if buf:
        statements.append("\n".join(buf))
    return statements


@contextmanager
def transaction(conn: sqlite3.Connection, *, immediate: bool = True):
    """BEGIN IMMEDIATE ... COMMIT, retrying the BEGIN while another writer holds the lock."""
    for attempt in range(60):
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) and "busy" not in str(exc):
                raise
            time.sleep(min(5.0, 0.2 * (attempt + 1)))
    else:
        raise sqlite3.OperationalError("database is locked (gave up waiting)")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def get_meta(conn: sqlite3.Connection, key: str, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, None if value is None else str(value)),
    )


def ensure_root(conn: sqlite3.Connection, domain: str) -> int:
    row = conn.execute("SELECT id FROM roots WHERE domain = ?", (domain,)).fetchone()
    if row:
        return row[0]
    cur = conn.execute("INSERT OR IGNORE INTO roots(domain, created_at) VALUES(?, ?)", (domain, utcnow()))
    if cur.rowcount:
        return cur.lastrowid
    return conn.execute("SELECT id FROM roots WHERE domain = ?", (domain,)).fetchone()[0]


def hosts_in_scope(conn: sqlite3.Connection, root: str):
    """Every tracked subdomain at or below ``root`` – regardless of which root found it first
    (roots may overlap, e.g. example.com and dev.example.com)."""
    pattern = "%." + root.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return conn.execute("SELECT * FROM subdomains WHERE host = ? OR host LIKE ? ESCAPE '\\'", (root, pattern))


def ensure_tag(conn: sqlite3.Connection, name: str, color: str | None = None) -> int:
    name = name.strip()
    row = conn.execute("SELECT id FROM tags WHERE name = ?", (name,)).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO tags(name, color, created_at) VALUES(?, ?, ?)",
        (name, color or default_tag_color(name), utcnow()),
    )
    return cur.lastrowid


_TAG_COLORS = ["#2563eb", "#0d9488", "#7c3aed", "#db2777", "#ea580c", "#65a30d", "#0891b2", "#c026d3", "#dc2626", "#4f46e5"]


def default_tag_color(name: str) -> str:
    return _TAG_COLORS[sum(name.lower().encode()) % len(_TAG_COLORS)]


def backup(conn: sqlite3.Connection, dest: str) -> str:
    """Consistent online backup (safe while the dashboard / a scan is running)."""
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    target = sqlite3.connect(dest)
    try:
        conn.backup(target)
    finally:
        target.close()
    return dest
