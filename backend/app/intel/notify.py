"""In-app notifications (stage 1) with optional Web Push delivery (stage 2).

Duplicate suppression: every notification has a ``dedupe_key`` (e.g.
``watch:<id>:cluster:<cluster_id>``), so several articles reporting the same
story never notify twice.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, time
from zoneinfo import ZoneInfo

from ..config import get_settings
from ..db import now_iso

log = logging.getLogger(__name__)


def notify(conn: sqlite3.Connection, *, kind: str, title: str, body: str = "", link: str | None = None,
           watch_id: int | None = None, article_id: int | None = None, dedupe_key: str, digest: bool = False) -> bool:
    cur = conn.execute(
        """INSERT INTO notifications(created_at, kind, title, body, link, watch_id, article_id, dedupe_key, digest_pending)
           VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(dedupe_key) DO NOTHING""",
        (now_iso(), kind, title[:200], body[:1000], link, watch_id, article_id, dedupe_key, 1 if digest else 0),
    )
    created = bool(cur.rowcount)
    if created and not digest:
        if in_quiet_hours():
            conn.execute("UPDATE notifications SET push_held=1 WHERE dedupe_key=?", (dedupe_key,))
        else:
            try:
                send_push(conn, title, body, link)
            except Exception as e:  # push is best effort
                log.warning("web push failed: %s", type(e).__name__)
    return created


def in_quiet_hours(now: datetime | None = None) -> bool:
    """True inside the configured quiet window (local time; the window may cross midnight)."""
    s = get_settings()
    spec = (s.quiet_hours or "").strip()
    if not spec:
        return False
    try:
        a, b = (time.fromisoformat(x.strip()) for x in spec.split("-", 1))
    except ValueError:
        log.warning("ignoring malformed TW_QUIET_HOURS %r", spec)
        return False
    t = (now or datetime.now(ZoneInfo(s.timezone))).astimezone(ZoneInfo(s.timezone)).time()
    return a <= t < b if a < b else (t >= a or t < b)


def release_held(conn: sqlite3.Connection, now: datetime | None = None) -> int:
    """After quiet hours, send one push summarising the alerts that were held. Returns how many were held."""
    if in_quiet_hours(now):
        return 0
    rows = conn.execute("SELECT id, title FROM notifications WHERE push_held=1 ORDER BY created_at").fetchall()
    if not rows:
        return 0
    conn.execute(f"UPDATE notifications SET push_held=0 WHERE id IN ({','.join(str(r['id']) for r in rows)})")
    n = len(rows)
    body = "; ".join(r["title"] for r in rows[:3]) + (f"; and {n - 3} more" if n > 3 else "")
    try:
        send_push(conn, f"{n} alert{'s' if n != 1 else ''} while notifications were quiet", body, "/notifications")
    except Exception as e:
        log.warning("web push failed: %s", type(e).__name__)
    return n


def compile_digest(conn: sqlite3.Connection, day_label: str) -> bool:
    rows = conn.execute(
        "SELECT n.*, w.title AS watch_title FROM notifications n LEFT JOIN watches w ON w.id=n.watch_id WHERE digest_pending=1 ORDER BY created_at"
    ).fetchall()
    if not rows:
        return False
    lines = [f"• {r['watch_title'] or 'Watch'}: {r['body'][:160]}" for r in rows[:30]]
    created = notify(conn, kind="digest", title=f"Daily digest: {len(rows)} update{'s' if len(rows) != 1 else ''} on what you follow", body="\n".join(lines),
                     link="/watch", dedupe_key=f"digest:{day_label}")
    conn.execute(f"UPDATE notifications SET digest_pending=2 WHERE id IN ({','.join(str(r['id']) for r in rows)})")
    return created


def send_push(conn: sqlite3.Connection, title: str, body: str, link: str | None) -> int:
    s = get_settings()
    if not (s.vapid_public_key and s.vapid_private_key):
        return 0
    try:
        from pywebpush import WebPushException, webpush
    except ImportError:
        return 0
    payload = json.dumps({"title": title[:120], "body": body[:240], "url": link or "/"})
    sent = 0
    for sub in conn.execute("SELECT * FROM push_subscriptions").fetchall():
        try:
            webpush(
                subscription_info={"endpoint": sub["endpoint"], "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}},
                data=payload,
                vapid_private_key=s.vapid_private_key.get_secret_value(),
                vapid_claims={"sub": s.vapid_subject},
                timeout=10,
            )
            sent += 1
        except WebPushException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (404, 410):
                conn.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (sub["endpoint"],))
    return sent
