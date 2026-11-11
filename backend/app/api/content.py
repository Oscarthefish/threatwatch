"""Read-mostly intelligence endpoints: today, articles, breaking, vulnerabilities, search, sources, status."""
from __future__ import annotations

import re
import sqlite3
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import get_db, require_user
from ..config import get_settings
from ..db import get_setting, iso, jloads, now_iso, parse_iso, set_setting, utcnow
from ..ingest import pipeline
from ..intel import ai, entities
from ..intel.watch import suggest_from_article
from .serial import ARTICLE_LIST_COLS, article_brief, vuln_dict

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])

SECTIONS = {"breaking", "threat-intel", "vulnerabilities", "soc-dfir", "nz-apac"}


def _fts_query(q: str) -> str:
    """Convert user input to a safe FTS5 query (quoted terms, prefix on last term)."""
    terms = re.findall(r'[\w\-\.$]+', q)[:12]
    if not terms:
        return ""
    parts = ['"' + t.replace('"', "") + '"' for t in terms]
    parts[-1] = parts[-1] + "*"
    return " AND ".join(parts)


def _list_articles(conn, *, section=None, q=None, severity_min=None, source=None, tag=None, region=None, days=None,
                   limit=30, offset=0, collapse=True, ids=None, order="rank") -> list[dict]:
    where, params = [], []
    join = ""
    if q:
        fq = _fts_query(q)
        if not fq:
            return []
        join = "JOIN articles_fts f ON f.rowid = a.id"
        where.append("articles_fts MATCH ?")
        params.append(fq)
    if section:
        where.append("EXISTS (SELECT 1 FROM json_each(a.sections) WHERE value = ?)")
        params.append(section)
    if tag:
        where.append("EXISTS (SELECT 1 FROM json_each(a.tags) WHERE value = ?)")
        params.append(tag)
    if severity_min is not None:
        where.append("a.severity >= ?")
        params.append(severity_min)
    if source:
        where.append("s.key = ?")
        params.append(source)
    if region:
        where.append("a.region = ?")
        params.append(region)
    if days:
        where.append("a.published_at >= ?")
        params.append(iso(utcnow() - timedelta(days=days)))
    if ids is not None:
        if not ids:
            return []
        where.append(f"a.id IN ({','.join('?' * len(ids))})")
        params += list(ids)
    if collapse and not q and ids is None:
        where.append("(a.cluster_id = a.id OR a.cluster_id IS NULL)")
    order_sql = {"rank": "a.score DESC, a.published_at DESC", "new": "a.published_at DESC",
                 "relevance": "bm25(articles_fts) ASC, a.published_at DESC" if q else "a.published_at DESC"}[order]
    sql = f"""SELECT {ARTICLE_LIST_COLS} FROM articles a JOIN sources s ON s.id=a.source_id {join}
              {('WHERE ' + ' AND '.join(where)) if where else ''} ORDER BY {order_sql} LIMIT ? OFFSET ?"""
    rows = conn.execute(sql, [*params, limit, offset]).fetchall()
    return [article_brief(r) for r in rows]


@router.get("/today")
def today(since: str | None = Query(None, max_length=40), conn: sqlite3.Connection = Depends(get_db)):
    """Dashboard data. ``since`` lets the client pin its "since last visit" baseline for the whole session."""
    last_visit = get_setting(conn, "last_visit_at")
    b = conn.execute("SELECT * FROM briefings ORDER BY generated_at DESC LIMIT 1").fetchone()
    briefing, briefing_ids = None, set()
    if b:
        content = jloads(b["content_json"], {})
        ids = jloads(b["article_ids"])
        briefing_ids = set(ids)
        arts = {a["id"]: a for a in _list_articles(conn, ids=ids, limit=500, collapse=False)}
        for it in content.get("items", []):
            it["sources"] = [arts[i] for i in it.get("article_ids", []) if i in arts]
        briefing = {"id": b["id"], "date": b["briefing_date"], "generated_at": b["generated_at"], "method": b["method"],
                    "model": b["model"], **content}
    baseline = since if since and parse_iso(since) else (last_visit or iso(utcnow() - timedelta(hours=24)))
    rep = "(a.cluster_id = a.id OR a.cluster_id IS NULL)"
    new_count = conn.execute(f"SELECT COUNT(*) FROM articles a WHERE a.retrieved_at > ? AND {rep}", (baseline,)).fetchone()[0]
    new_rows = conn.execute(
        f"""SELECT {ARTICLE_LIST_COLS} FROM articles a JOIN sources s ON s.id=a.source_id
            WHERE a.retrieved_at > ? AND {rep} ORDER BY a.severity DESC, a.score DESC LIMIT 40""", (baseline,)).fetchall()
    new_articles = [article_brief(r) for r in new_rows]

    day = iso(utcnow() - timedelta(hours=24))
    sev = {r[0]: r[1] for r in conn.execute(
        f"SELECT a.severity, COUNT(*) FROM articles a WHERE a.published_at >= ? AND {rep} GROUP BY a.severity", (day,))}
    kev_cut = (utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    kev_new = [vuln_dict(r) for r in conn.execute(
        "SELECT * FROM vulnerabilities WHERE kev=1 AND kev_date_added >= ? ORDER BY kev_date_added DESC, cve_id DESC LIMIT 8", (kev_cut,))]
    kev_count = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE kev=1 AND kev_date_added >= ?", (kev_cut,)).fetchone()[0]
    top = [a for a in _list_articles(conn, severity_min=3, days=3, limit=20) if a["id"] not in briefing_ids][:6]
    regional = _list_articles(conn, section="nz-apac", days=14, limit=5, order="new")
    watch_updates = [dict(r) for r in conn.execute(
        """SELECT w.id, w.title, w.kind, w.last_updated_at,
                  SUM(CASE WHEN we.significance='important' THEN 1 ELSE 0 END) AS important,
                  COUNT(we.id) AS new_evidence
           FROM watches w JOIN watch_evidence we ON we.watch_id=w.id AND we.status='linked' AND we.linked_at > ?
           WHERE w.status='active' GROUP BY w.id ORDER BY important DESC, w.last_updated_at DESC LIMIT 8""", (baseline,))]
    watching = conn.execute("SELECT COUNT(*) FROM watches WHERE status='active'").fetchone()[0]
    review = conn.execute(
        "SELECT COUNT(*) FROM watch_evidence we JOIN watches w ON w.id=we.watch_id WHERE we.status='candidate' AND w.status='active'").fetchone()[0]
    srcs = conn.execute("SELECT name, enabled, last_status, consecutive_failures FROM sources WHERE enabled=1").fetchall()
    failing = [r["name"] for r in srcs if r["last_status"] == "error"]
    return {
        "briefing": briefing,
        "last_visit_at": last_visit,
        "baseline": baseline,
        "since_last_visit": {"count": new_count, "articles": new_articles},
        "stats": {
            "new_since_visit": new_count,
            "critical_24h": sev.get(4, 0),
            "high_24h": sev.get(3, 0),
            "total_24h": sum(sev.values()),
            "kev_7d": kev_count,
            "watching": watching,
            "watch_updates": len(watch_updates),
            "review_queue": review,
            "sources_ok": len(srcs) - len(failing),
            "sources_total": len(srcs),
            "sources_failing": failing,
        },
        "kev_new": kev_new,
        "regional": regional,
        "top_threats": top,
        "watch_updates": watch_updates,
        "last_ingest_at": get_setting(conn, "last_ingest_at"),
        "ai_enabled": get_settings().ai_enabled,
    }


@router.post("/visit")
def mark_visit(conn: sqlite3.Connection = Depends(get_db)):
    set_setting(conn, "last_visit_at", now_iso())
    return {"ok": True}


@router.get("/articles")
def list_articles(
    section: str | None = None,
    q: str | None = Query(None, max_length=200),
    severity_min: int | None = Query(None, ge=0, le=4),
    source: str | None = None,
    tag: str | None = None,
    region: str | None = None,
    days: int | None = Query(None, ge=1, le=365),
    order: str = Query("rank", pattern="^(rank|new|relevance)$"),
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    conn: sqlite3.Connection = Depends(get_db),
):
    if section and section not in SECTIONS:
        raise HTTPException(400, "unknown section")
    if section == "breaking" and not days:
        days = 3
    items = _list_articles(conn, section=section, q=q, severity_min=severity_min, source=source, tag=tag, region=region,
                           days=days, limit=limit, offset=offset, order=order)
    return {"items": items, "offset": offset, "limit": limit, "has_more": len(items) == limit}


@router.get("/articles/{article_id}")
def article_detail(article_id: int, conn: sqlite3.Connection = Depends(get_db)):
    rows = _list_articles(conn, ids=[article_id], collapse=False)
    if not rows:
        raise HTTPException(404, "not found")
    art = rows[0]
    full = conn.execute("SELECT a.*, s.homepage, s.authority FROM articles a JOIN sources s ON s.id=a.source_id WHERE a.id=?",
                        (article_id,)).fetchone()
    art["summary_text"] = full["summary_text"]
    art["content_text"] = full["content_text"]
    art["author"] = full["author"]
    art["source"]["homepage"] = full["homepage"]
    art["source"]["authority"] = full["authority"]
    ents = conn.execute(
        "SELECT e.type, e.value, ae.method, ae.in_title FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=? ORDER BY e.type, e.value",
        (article_id,)).fetchall()
    grouped: dict[str, list[dict]] = {}
    for e in ents:
        item = {"value": e["value"], "method": e["method"]}
        if e["type"].startswith("attack_technique"):
            item["name"] = entities.technique_name(e["value"])
        grouped.setdefault(e["type"], []).append(item)
    art["entities"] = grouped
    cves = [e["value"].upper() for e in ents if e["type"] == "cve"]
    art["vulnerabilities"] = [vuln_dict(r) for r in conn.execute(
        f"SELECT * FROM vulnerabilities WHERE cve_id IN ({','.join('?' * len(cves))})", cves)] if cves else []
    art["related"] = _list_articles(conn, ids=[r[0] for r in conn.execute(
        "SELECT id FROM articles WHERE cluster_id=? AND id<>? ORDER BY published_at", (full["cluster_id"], article_id))], collapse=False)
    aio = conn.execute(
        "SELECT output_json, model, created_at FROM ai_outputs WHERE kind='article_summary' AND subject_type='article' AND subject_id=? ORDER BY id DESC LIMIT 1",
        (article_id,)).fetchone()
    art["ai"] = ({**jloads(aio["output_json"], {}), "model": aio["model"], "generated_at": aio["created_at"]} if aio else None)
    bm = conn.execute("SELECT note, tags, created_at FROM bookmarks WHERE article_id=?", (article_id,)).fetchone()
    art["bookmark"] = {"note": bm["note"], "tags": jloads(bm["tags"]), "created_at": bm["created_at"]} if bm else None
    art["watches"] = [dict(r) for r in conn.execute(
        """SELECT w.id, w.title, w.kind, we.status, we.significance FROM watch_evidence we JOIN watches w ON w.id=we.watch_id
           WHERE we.article_id=? AND we.status<>'rejected'""", (article_id,))]
    art["watch_suggestions"] = suggest_from_article(conn, article_id)
    art["ai_available"] = get_settings().ai_enabled
    return art


@router.post("/articles/{article_id}/summarise")
def summarise(article_id: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT a.*, s.name AS source_name FROM articles a JOIN sources s ON s.id=a.source_id WHERE a.id=?",
                     (article_id,)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    ai.reset_run_counter()
    try:
        out = ai.summarise_article(conn, dict(r))
    except ai.AIUnavailable as e:
        raise HTTPException(503, f"AI summary unavailable: {e}")
    pipeline.apply_ai_entities(conn, dict(r), out)
    return out


@router.post("/articles/{article_id}/read")
def mark_read(article_id: int, conn: sqlite3.Connection = Depends(get_db)):
    now = now_iso()
    conn.execute(
        """INSERT INTO reading_history(article_id, first_read_at, last_read_at) VALUES(?,?,?)
           ON CONFLICT(article_id) DO UPDATE SET last_read_at=excluded.last_read_at, read_count=read_count+1""",
        (article_id, now, now))
    return {"ok": True}


@router.get("/breaking")
def breaking(conn: sqlite3.Connection = Depends(get_db)):
    arts = _list_articles(conn, section="breaking", days=3, limit=40, order="rank")
    kev = [vuln_dict(r) for r in conn.execute(
        "SELECT * FROM vulnerabilities WHERE kev=1 AND kev_date_added >= ? ORDER BY kev_date_added DESC, cve_id LIMIT 30",
        ((utcnow() - timedelta(days=7)).strftime("%Y-%m-%d"),))]
    watch_alerts = [dict(r) for r in conn.execute(
        """SELECT w.id AS watch_id, w.title AS watch_title, a.id AS article_id, a.title, we.assessment, we.linked_at
           FROM watch_evidence we JOIN watches w ON w.id=we.watch_id JOIN articles a ON a.id=we.article_id
           WHERE we.significance='important' AND we.linked_at >= ? ORDER BY we.linked_at DESC LIMIT 15""",
        (iso(utcnow() - timedelta(days=3)),))]
    return {"articles": arts, "kev_new": kev, "watch_alerts": watch_alerts}


@router.get("/vulnerabilities")
def vulnerabilities(
    q: str | None = Query(None, max_length=100),
    kev: bool | None = None,
    sort: str = Query("recent", pattern="^(recent|epss|cvss|mentioned)$"),
    days: int | None = Query(None, ge=1, le=3650),
    min_epss: float | None = Query(None, ge=0, le=1),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    conn: sqlite3.Connection = Depends(get_db),
):
    where, params = [], []
    if kev is not None:
        where.append("v.kev = ?")
        params.append(int(kev))
    if q:
        where.append("(v.cve_id LIKE ? OR v.vendor LIKE ? OR v.product LIKE ? OR v.name LIKE ? OR v.description LIKE ?)")
        params += [f"%{q}%"] * 5
    if min_epss is not None:
        where.append("v.epss >= ?")
        params.append(min_epss)
    if days:
        where.append("COALESCE(v.kev_date_added, substr(v.first_seen_at,1,10)) >= ?")
        params.append((utcnow() - timedelta(days=days)).strftime("%Y-%m-%d"))
    mentions = "(SELECT COUNT(*) FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE e.type='cve' AND e.normalized=lower(v.cve_id))"
    order = {"recent": "(v.kev = 0 AND v.description IS NULL AND v.vendor IS NULL), COALESCE(v.kev_date_added, substr(v.first_seen_at,1,10)) DESC, v.cve_id DESC",
             "epss": "v.epss IS NULL, v.epss DESC", "cvss": "v.cvss_score IS NULL, v.cvss_score DESC",
             "mentioned": f"{mentions} DESC, v.first_seen_at DESC"}[sort]
    rows = conn.execute(
        f"SELECT v.*, {mentions} AS mentions FROM vulnerabilities v {('WHERE ' + ' AND '.join(where)) if where else ''} ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, limit, offset]).fetchall()
    stats = conn.execute("SELECT COUNT(*) AS total, SUM(kev) AS kev, SUM(epss IS NOT NULL) AS with_epss FROM vulnerabilities").fetchone()
    return {"items": [vuln_dict(r) for r in rows], "stats": dict(stats), "has_more": len(rows) == limit}


@router.get("/vulnerabilities/{cve_id}")
def vulnerability(cve_id: str, conn: sqlite3.Connection = Depends(get_db)):
    if not entities.CVE_RE.fullmatch(cve_id.upper()):
        raise HTTPException(400, "invalid CVE id")
    r = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id=?", (cve_id.upper(),)).fetchone()
    if not r:
        raise HTTPException(404, "not tracked")
    ids = [x[0] for x in conn.execute(
        "SELECT ae.article_id FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE e.type='cve' AND e.normalized=?",
        (cve_id.lower(),))]
    w = conn.execute("SELECT id FROM watches WHERE canonical_key=?", (f"vulnerability:{cve_id.lower()}",)).fetchone()
    return {**vuln_dict(r), "articles": _list_articles(conn, ids=ids, collapse=False, order="new", limit=50),
            "watch_id": w[0] if w else None}


@router.get("/search")
def search(q: str = Query(..., min_length=2, max_length=200), conn: sqlite3.Connection = Depends(get_db)):
    arts = _list_articles(conn, q=q, limit=40, order="relevance")
    like = f"%{q.strip()}%"
    vulns = [vuln_dict(r) for r in conn.execute(
        "SELECT * FROM vulnerabilities WHERE cve_id LIKE ? OR vendor LIKE ? OR product LIKE ? OR name LIKE ? ORDER BY kev DESC, epss DESC LIMIT 10",
        (like, like, like, like))]
    watches = [dict(r) for r in conn.execute(
        "SELECT id, title, kind, status FROM watches WHERE title LIKE ? OR identifiers LIKE ? OR aliases LIKE ? LIMIT 10", (like, like, like))]
    return {"articles": arts, "vulnerabilities": vulns, "watches": watches}


@router.get("/sources")
def sources(conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT s.*, (SELECT COUNT(*) FROM articles a WHERE a.source_id=s.id) AS article_count,
                  (SELECT MAX(published_at) FROM articles a WHERE a.source_id=s.id) AS latest_article
           FROM sources s ORDER BY s.name""").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d.pop("etag", None)
        d.pop("last_modified", None)
        d["default_sections"] = jloads(d["default_sections"])
        d["enabled"] = bool(d["enabled"])
        out.append(d)
    return out


@router.patch("/sources/{source_id}")
def update_source(source_id: int, body: dict, conn: sqlite3.Connection = Depends(get_db)):
    if "enabled" in body:
        conn.execute("UPDATE sources SET enabled=? WHERE id=?", (int(bool(body["enabled"])), source_id))
    if "interval_minutes" in body:
        iv = int(body["interval_minutes"])
        if not 15 <= iv <= 1440:
            raise HTTPException(400, "interval must be 15..1440 minutes")
        conn.execute("UPDATE sources SET interval_minutes=? WHERE id=?", (iv, source_id))
    return {"ok": True}


@router.post("/ingest")
def request_ingest(conn: sqlite3.Connection = Depends(get_db)):
    set_setting(conn, "ingest_requested", now_iso())
    return {"queued": True, "detail": "The worker will refresh all sources within ~30 seconds."}


@router.post("/briefing")
def request_briefing(conn: sqlite3.Connection = Depends(get_db)):
    set_setting(conn, "briefing_requested", now_iso())
    return {"queued": True}


@router.get("/briefings")
def briefings(limit: int = Query(14, ge=1, le=60), conn: sqlite3.Connection = Depends(get_db)):
    return [dict(r) | {"headline": jloads(r["content_json"], {}).get("headline")} for r in conn.execute(
        "SELECT id, briefing_date, generated_at, method, model, content_json FROM briefings ORDER BY generated_at DESC LIMIT ?", (limit,))]


@router.get("/status")
def app_status(conn: sqlite3.Connection = Depends(get_db)):
    s = get_settings()
    counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("articles", "vulnerabilities", "watches", "bookmarks", "notifications", "briefings")}
    jobs = [dict(r) for r in conn.execute("SELECT job, started_at, finished_at, status, detail FROM job_runs ORDER BY id DESC LIMIT 5")]
    db_size = s.db_path.stat().st_size if s.db_path.exists() else 0
    return {
        "counts": counts,
        "db_bytes": db_size,
        "last_ingest_at": get_setting(conn, "last_ingest_at"),
        "worker_heartbeat": get_setting(conn, "worker_heartbeat"),
        "ai": ai.budget_status(conn),
        "ingest_interval_minutes": s.ingest_interval_minutes,
        "briefing_time": f"{s.briefing_hour:02d}:{s.briefing_minute:02d} {s.timezone}",
        "recent_jobs": jobs,
        "push_configured": bool(s.vapid_public_key and s.vapid_private_key),
        "sources": {
            "total": conn.execute("SELECT COUNT(*) FROM sources WHERE enabled=1").fetchone()[0],
            "failing": [r[0] for r in conn.execute("SELECT name FROM sources WHERE enabled=1 AND last_status='error'")],
        },
    }
