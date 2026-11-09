"""SQLite access layer: connections, migrations and small helpers.

SQLite runs in WAL mode so the API and the worker process can share one
database file safely. Migrations are plain ordered ``.sql`` files in
``backend/migrations``; applied versions are tracked in ``schema_migrations``.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import get_settings

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def jloads(s: str | None, default: Any = None) -> Any:
    if s is None or s == "":
        return [] if default is None else default
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return [] if default is None else default


def jdumps(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = path or get_settings().db_path
    p.parent.mkdir(parents=True, exist_ok=True)
    new = not p.exists()
    conn = sqlite3.connect(p, timeout=30, isolation_level=None, check_same_thread=False)
    if new:
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-8000")  # ~8 MB page cache
    return conn


@contextmanager
def tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Explicit IMMEDIATE transaction (autocommit mode otherwise)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def migrate(conn: sqlite3.Connection) -> list[str]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    done: list[str] = []
    for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = f.stem
        if version in applied:
            continue
        log.info("applying migration %s", version)
        sql = f.read_text()
        # executescript commits implicitly; wrap in our own transaction statements.
        conn.executescript("BEGIN;\n" + sql + f"\nINSERT INTO schema_migrations VALUES ('{version}', '{now_iso()}');\nCOMMIT;")
        done.append(version)
    return done


def get_setting(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return jloads(row[0], default) if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, jdumps(value)),
    )


def row_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None
