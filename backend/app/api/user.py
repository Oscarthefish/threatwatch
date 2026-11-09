"""Personal data endpoints: bookmarks, reading history, notifications, push subscriptions."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..auth import get_db, require_user
from ..config import get_settings
from ..db import jdumps, jloads, now_iso
from .serial import ARTICLE_LIST_COLS, article_brief

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


class BookmarkIn(BaseModel):
    note: str = Field("", max_length=10000)
    tags: list[str] = Field(default_factory=list, max_length=30)


@router.get("/bookmarks")
def bookmarks(tag: str | None = None, conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        f"""SELECT {ARTICLE_LIST_COLS}, b.note AS bm_note, b.tags AS bm_tags, b.created_at AS bm_created
            FROM bookmarks b JOIN articles a ON a.id=b.article_id JOIN sources s ON s.id=a.source_id
            ORDER BY b.created_at DESC LIMIT 500""").fetchall()
    out = []
    for r in rows:
        tags = jloads(r["bm_tags"])
        if tag and tag not in tags:
            continue
        d = article_brief(r)
        d["bookmark"] = {"note": r["bm_note"], "tags": tags, "created_at": r["bm_created"]}
        out.append(d)
    return out


@router.put("/bookmarks/{article_id}")
def put_bookmark(article_id: int, body: BookmarkIn, conn: sqlite3.Connection = Depends(get_db)):
    if not conn.execute("SELECT 1 FROM articles WHERE id=?", (article_id,)).fetchone():
        raise HTTPException(404, "article not found")
    tags = sorted({t.strip()[:40] for t in body.tags if t.strip()})
    conn.execute(
        """INSERT INTO bookmarks(article_id, created_at, note, tags) VALUES(?,?,?,?)
           ON CONFLICT(article_id) DO UPDATE SET note=excluded.note, tags=excluded.tags""",
        (article_id, now_iso(), body.note, jdumps(tags)))
    return {"ok": True}


@router.delete("/bookmarks/{article_id}")
def delete_bookmark(article_id: int, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM bookmarks WHERE article_id=?", (article_id,))
    return {"ok": True}


@router.get("/history")
def history(limit: int = Query(100, ge=1, le=500), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        f"""SELECT {ARTICLE_LIST_COLS}, h.last_read_at FROM reading_history h JOIN articles a ON a.id=h.article_id
            JOIN sources s ON s.id=a.source_id ORDER BY h.last_read_at DESC LIMIT ?""", (limit,)).fetchall()
    return [article_brief(r) | {"last_read_at": r["last_read_at"]} for r in rows]


@router.delete("/history")
def clear_history(conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM reading_history")
    return {"ok": True}


@router.get("/tags")
def tags(conn: sqlite3.Connection = Depends(get_db)):
    found: dict[str, int] = {}
    for (t,) in conn.execute("SELECT tags FROM bookmarks UNION ALL SELECT tags FROM watches"):
        for x in jloads(t):
            found[x] = found.get(x, 0) + 1
    return sorted(({"tag": k, "count": v} for k, v in found.items()), key=lambda x: -x["count"])


@router.get("/notifications")
def notifications(unread_only: bool = False, limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        f"""SELECT * FROM notifications WHERE digest_pending=0 {'AND read_at IS NULL' if unread_only else ''}
            ORDER BY created_at DESC LIMIT ?""", (limit,)).fetchall()
    unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE digest_pending=0 AND read_at IS NULL").fetchone()[0]
    return {"items": [dict(r) for r in rows], "unread": unread}


class ReadIn(BaseModel):
    ids: list[int] | None = None
    all: bool = False


@router.post("/notifications/read")
def read_notifications(body: ReadIn, conn: sqlite3.Connection = Depends(get_db)):
    if body.all:
        conn.execute("UPDATE notifications SET read_at=? WHERE read_at IS NULL", (now_iso(),))
    elif body.ids:
        conn.execute(f"UPDATE notifications SET read_at=? WHERE id IN ({','.join('?' * len(body.ids))})", (now_iso(), *body.ids))
    return {"ok": True}


@router.get("/push/key")
def push_key():
    s = get_settings()
    return {"public_key": s.vapid_public_key, "enabled": bool(s.vapid_public_key and s.vapid_private_key)}


class PushSub(BaseModel):
    endpoint: str = Field(..., max_length=1000)
    keys: dict[str, str]


@router.post("/push/subscribe")
def push_subscribe(sub: PushSub, request: Request, conn: sqlite3.Connection = Depends(get_db)):
    if not sub.endpoint.startswith("https://"):
        raise HTTPException(400, "invalid endpoint")
    conn.execute(
        """INSERT INTO push_subscriptions(endpoint, p256dh, auth, created_at, user_agent) VALUES(?,?,?,?,?)
           ON CONFLICT(endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth""",
        (sub.endpoint, sub.keys.get("p256dh", ""), sub.keys.get("auth", ""), now_iso(), (request.headers.get("user-agent") or "")[:200]))
    return {"ok": True}


@router.post("/push/unsubscribe")
def push_unsubscribe(sub: PushSub, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (sub.endpoint,))
    return {"ok": True}
