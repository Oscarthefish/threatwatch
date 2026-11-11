"""Threat Watch (follow) endpoints."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import get_db, require_user
from ..db import jdumps, jloads, now_iso
from ..intel import watch as engine
from .content import _list_articles

router = APIRouter(prefix="/api/watches", dependencies=[Depends(require_user)])


class WatchIn(BaseModel):
    kind: str
    title: str = Field(..., min_length=2, max_length=200)
    description: str = Field("", max_length=2000)
    identifiers: list[str] = Field(default_factory=list, max_length=50)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    context_terms: list[str] = Field(default_factory=list, max_length=50)
    exclude_terms: list[str] = Field(default_factory=list, max_length=50)
    notify_pref: str = "important"
    tags: list[str] = Field(default_factory=list, max_length=30)
    notes: str = Field("", max_length=10000)
    origin_article_id: int | None = None


class WatchPatch(BaseModel):
    title: str | None = Field(None, min_length=2, max_length=200)
    description: str | None = Field(None, max_length=2000)
    identifiers: list[str] | None = None
    aliases: list[str] | None = None
    context_terms: list[str] | None = None
    exclude_terms: list[str] | None = None
    notify_pref: str | None = None
    status: str | None = None
    tags: list[str] | None = None
    notes: str | None = Field(None, max_length=10000)


def _watch_out(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("identifiers", "aliases", "context_terms", "exclude_terms", "tags"):
        d[k] = jloads(d[k])
    return d


@router.get("")
def list_watches(status: str = "active", conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT w.*,
             (SELECT COUNT(*) FROM watch_evidence we WHERE we.watch_id=w.id AND we.status='linked') AS evidence_count,
             (SELECT COUNT(*) FROM watch_evidence we WHERE we.watch_id=w.id AND we.status='candidate') AS candidate_count,
             (SELECT COUNT(*) FROM watch_evidence we WHERE we.watch_id=w.id AND we.status='linked'
                AND (w.last_viewed_at IS NULL OR we.linked_at > w.last_viewed_at) AND we.linked_by='auto') AS unseen_count,
             (SELECT MAX(a.published_at) FROM watch_evidence we JOIN articles a ON a.id=we.article_id
                WHERE we.watch_id=w.id AND we.status='linked') AS latest_evidence_at
           FROM watches w WHERE w.status=? ORDER BY COALESCE(w.last_updated_at, w.created_at) DESC""", (status,)).fetchall()
    out = []
    for r in rows:
        d = _watch_out(r)
        s = conn.execute("SELECT summary, version, method FROM watch_summaries WHERE watch_id=? ORDER BY version DESC LIMIT 1",
                         (r["id"],)).fetchone()
        d["summary_excerpt"] = (s["summary"][:280] if s else "")
        d["summary_version"] = s["version"] if s else 0
        out.append(d)
    return out


@router.post("", status_code=201)
def create(body: WatchIn, conn: sqlite3.Connection = Depends(get_db)):
    try:
        wid, created = engine.create_watch(conn, **body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"id": wid, "created": created}


@router.get("/{watch_id}")
def detail(watch_id: int, mark_viewed: bool = True, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM watches WHERE id=?", (watch_id,)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    w = _watch_out(r)
    w["record"] = engine.latest_summary(conn, watch_id)
    w["versions"] = [dict(x) for x in conn.execute(
        "SELECT version, created_at, method, model, changes FROM watch_summaries WHERE watch_id=? ORDER BY version DESC", (watch_id,))]
    for v in w["versions"]:
        v["changes"] = jloads(v["changes"])
    ev = conn.execute(
        """SELECT we.article_id, we.status, we.match_score, we.match_reasons, we.significance, we.assessment, we.linked_by, we.linked_at
           FROM watch_evidence we WHERE we.watch_id=? AND we.status IN ('linked','candidate')""", (watch_id,)).fetchall()
    meta = {e["article_id"]: dict(e) | {"match_reasons": jloads(e["match_reasons"])} for e in ev}
    # The sentence(s) that mention the followed subject: shows exactly why each report matched
    from ..intel import text as textutil
    terms = engine.watch_terms(r)
    if meta and terms:
        for row in conn.execute(f"SELECT id, title, summary_text, content_text FROM articles WHERE id IN ({','.join('?' * len(meta))})", list(meta)):
            meta[row["id"]]["passages"] = textutil.passages(f"{row['title']}\n{row['summary_text'] or ''}\n{row['content_text'] or ''}", terms, limit=2)
            meta[row["id"]]["terms"] = terms
    arts = _list_articles(conn, ids=list(meta), collapse=False, order="new", limit=500)
    w["evidence"] = [a | {"link": meta[a["id"]]} for a in arts if meta[a["id"]]["status"] == "linked"]
    w["candidates"] = [a | {"link": meta[a["id"]]} for a in arts if meta[a["id"]]["status"] == "candidate"]
    w["timeline"] = [dict(x) for x in conn.execute(
        "SELECT * FROM watch_timeline WHERE watch_id=? ORDER BY occurred_at DESC, id DESC LIMIT 300", (watch_id,))]
    w["previous_viewed_at"] = r["last_viewed_at"]
    if mark_viewed:
        conn.execute("UPDATE watches SET last_viewed_at=? WHERE id=?", (now_iso(), watch_id))
    return w


@router.get("/{watch_id}/versions/{version}")
def version(watch_id: int, version: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM watch_summaries WHERE watch_id=? AND version=?", (watch_id, version)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    d = dict(r)
    for k in ("confirmed", "uncertain", "changes", "iocs", "techniques", "detection", "evidence_ids"):
        d[k] = jloads(d[k])
    return d


@router.patch("/{watch_id}")
def patch(watch_id: int, body: WatchPatch, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM watches WHERE id=?", (watch_id,)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    data = body.model_dump(exclude_none=True)
    if "notify_pref" in data and data["notify_pref"] not in engine.NOTIFY_PREFS:
        raise HTTPException(400, "invalid notify_pref")
    if "status" in data and data["status"] not in ("active", "archived"):
        raise HTTPException(400, "invalid status")
    sets, params, changed_terms = [], [], False
    for k, v in data.items():
        if k in ("identifiers", "aliases", "context_terms", "exclude_terms", "tags"):
            v = jdumps(engine._clean_list(v))
            changed_terms |= k != "tags"
        sets.append(f"{k}=?")
        params.append(v)
    if sets:
        conn.execute(f"UPDATE watches SET {', '.join(sets)} WHERE id=?", (*params, watch_id))
    if "notes" in data:
        engine.timeline(conn, watch_id, "note", "Notes updated", data["notes"][:300])
    if "status" in data and data["status"] != r["status"]:
        engine.timeline(conn, watch_id, "status", f"Watch {data['status']}")
    if changed_terms:
        engine.timeline(conn, watch_id, "note", "Matching terms updated")
        engine.backfill(conn, watch_id)
        engine.update_record(conn, watch_id)
    return {"ok": True}


@router.delete("/{watch_id}")
def delete(watch_id: int, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM watches WHERE id=?", (watch_id,))
    return {"ok": True}


class EvidenceAction(BaseModel):
    action: str  # link | reject


@router.post("/{watch_id}/evidence/{article_id}")
def evidence_action(watch_id: int, article_id: int, body: EvidenceAction, conn: sqlite3.Connection = Depends(get_db)):
    if not conn.execute("SELECT 1 FROM watches WHERE id=?", (watch_id,)).fetchone():
        raise HTTPException(404, "watch not found")
    a = conn.execute("SELECT title FROM articles WHERE id=?", (article_id,)).fetchone()
    if not a:
        raise HTTPException(404, "article not found")
    if body.action == "link":
        cur = conn.execute("UPDATE watch_evidence SET status='linked', linked_by='user', linked_at=? WHERE watch_id=? AND article_id=?",
                           (now_iso(), watch_id, article_id))
        if not cur.rowcount:
            engine.link_evidence(conn, watch_id, article_id, 1.0, ["Linked manually"], linked_by="user")
        else:
            engine.timeline(conn, watch_id, "user_link", f"Confirmed as relevant: {a['title']}", article_id=article_id)
        engine.update_record(conn, watch_id)
    elif body.action == "reject":
        conn.execute(
            """INSERT INTO watch_evidence(watch_id, article_id, status, match_score, linked_by, linked_at) VALUES(?,?,'rejected',0,'user',?)
               ON CONFLICT(watch_id, article_id) DO UPDATE SET status='rejected', linked_by='user'""",
            (watch_id, article_id, now_iso()))
        engine.timeline(conn, watch_id, "user_reject", f"Marked not relevant: {a['title']}", article_id=article_id)
    else:
        raise HTTPException(400, "action must be link or reject")
    return {"ok": True}


@router.post("/{watch_id}/refresh")
def refresh(watch_id: int, conn: sqlite3.Connection = Depends(get_db)):
    if not conn.execute("SELECT 1 FROM watches WHERE id=?", (watch_id,)).fetchone():
        raise HTTPException(404, "not found")
    n = engine.backfill(conn, watch_id, days=60)
    engine.update_record(conn, watch_id)
    return {"linked": n}
