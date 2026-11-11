"""Daily intelligence briefing (AI synthesis with a deterministic fallback)."""
from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from ..config import get_settings
from ..db import iso, jdumps, jloads, now_iso, utcnow
from . import ai
from .classify import SEVERITY_LABELS
from .notify import notify

log = logging.getLogger(__name__)


def local_today() -> str:
    return datetime.now(ZoneInfo(get_settings().timezone)).strftime("%Y-%m-%d")


def _candidates(conn, since: str, limit: int = 40) -> list[dict]:
    rows = conn.execute(
        """SELECT a.*, s.name AS source_name, s.authority,
                  (SELECT COUNT(DISTINCT b.source_id) FROM articles b WHERE b.cluster_id=a.cluster_id) AS n_sources
           FROM articles a JOIN sources s ON s.id=a.source_id
           WHERE a.published_at >= ? AND (a.cluster_id = a.id OR a.cluster_id IS NULL)
           ORDER BY a.score DESC LIMIT ?""",
        (since, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _cluster_ids(conn, article_id: int) -> list[int]:
    return [r[0] for r in conn.execute(
        "SELECT id FROM articles WHERE cluster_id=(SELECT cluster_id FROM articles WHERE id=?) ORDER BY published_at", (article_id,))] or [article_id]


def _cached_summary(conn, article_id: int) -> dict | None:
    r = conn.execute(
        "SELECT output_json FROM ai_outputs WHERE kind='article_summary' AND subject_type='article' AND subject_id=? ORDER BY id DESC LIMIT 1",
        (article_id,)).fetchone()
    return jloads(r[0], {}) if r else None


_TRAIL = re.compile(r"\s*(\[(…|\.\.\.)\]|…|The post .*? appeared first on .*)$", re.S)


def _excerpt(text: str, limit: int = 260) -> str:
    """Lead sentence(s) of a feed excerpt: drop '[…]' / 'The post … appeared first on …' boilerplate and any
    sentence fragment the publisher's own truncation left behind ("… OpenSSH is t…")."""
    t = " ".join(text.split())
    truncated = bool(re.search(r"(\[(…|\.\.\.)\]|…|\.\.\.)$", t)) or len(t) > limit
    t = _TRAIL.sub("", t).rstrip(" .…")
    if not truncated:
        return t + ("" if t.endswith((".", "!", "?")) else ".")
    cut = t[:limit]
    dot = max(cut.rfind(". "), cut.rfind("? "), cut.rfind("! "))
    return cut[: dot + 1] if dot > 25 else cut.rsplit(" ", 1)[0] + " …"


def _kev_summary(conn, a: dict) -> str | None:
    """CISA 'Adds N KEVs' posts say nothing in the title — name the CVEs from structured KEV data."""
    if not a["title"].lower().startswith("cisa adds"):
        return None
    rows = conn.execute(
        """SELECT v.cve_id, v.vendor, v.product, v.kev_ransomware FROM article_entities ae JOIN entities e ON e.id=ae.entity_id
           JOIN vulnerabilities v ON v.cve_id=upper(e.normalized) WHERE ae.article_id=? AND e.type='cve' AND v.kev=1""",
        (a["id"],)).fetchall()
    if not rows:
        return None
    return "Added to KEV: " + "; ".join(
        f"{r['cve_id']} ({r['vendor']} {r['product']}{', known ransomware use' if r['kev_ransomware'] == 'Known' else ''})"
        for r in rows[:5]) + "."


def generate(conn: sqlite3.Connection, hours: int = 24, notify_user: bool = True) -> int:
    since = iso(utcnow() - timedelta(hours=hours))
    cands = _candidates(conn, since)
    if len(cands) < 5:  # quiet day / fresh install: widen the window
        since = iso(utcnow() - timedelta(hours=hours * 3))
        cands = _candidates(conn, since)
    kev_new = [dict(r) for r in conn.execute(
        "SELECT cve_id, vendor, product, name, kev_date_added, kev_ransomware, epss FROM vulnerabilities WHERE kev=1 AND kev_date_added >= ? ORDER BY kev_date_added DESC LIMIT 15",
        ((utcnow() - timedelta(days=2)).strftime("%Y-%m-%d"),))]
    watch_updates = [dict(r) for r in conn.execute(
        """SELECT w.id, w.title, COUNT(we.id) AS n FROM watches w JOIN watch_evidence we ON we.watch_id=w.id
           WHERE we.status='linked' AND we.linked_at >= ? AND we.significance IN ('important','meaningful') GROUP BY w.id""",
        (since,))]

    items: list[dict] = []
    method, model, headline = "heuristic", None, ""
    allowed = {a["id"] for a in cands}
    if get_settings().ai_enabled and cands:
        ctx = [f"- {k['cve_id']} ({k['vendor']} {k['product']}: {k['name']}) added to CISA KEV {k['kev_date_added']}; known ransomware use: {k['kev_ransomware']}"
               for k in kev_new] or ["- No new CISA KEV additions in the last 48 hours."]
        ctx += [f"- Followed item '{w['title']}' received {w['n']} new linked report(s)." for w in watch_updates]
        try:
            out = ai.synthesise_briefing(conn, cands[:30], ctx)
            for it in out.get("items", [])[:10]:
                ids = ai.valid_ids(it.get("evidence_ids", []), allowed)
                if not ids:
                    continue  # uncited items are dropped
                all_ids: list[int] = []
                for i in ids:
                    all_ids += [x for x in _cluster_ids(conn, i) if x not in all_ids]
                items.append({"title": it["title"], "summary": it["summary"], "why_it_matters": it["why_it_matters"],
                              "priority": it["priority"], "article_ids": all_ids, "method": "ai"})
            if len(items) >= 3:
                method, model, headline = "ai", get_settings().ai_model, out.get("headline", "")
            else:
                items = []
        except ai.AIUnavailable as e:
            log.info("briefing AI unavailable: %s", e)

    if not items:
        for a in cands[:8]:
            s = _cached_summary(conn, a["id"])
            items.append({
                "title": a["title"],
                "summary": (s or {}).get("summary") or _kev_summary(conn, a) or _excerpt(a["summary_text"] or ""),
                "why_it_matters": (s or {}).get("why_it_matters") or "; ".join(jloads(a["severity_reasons"])),
                "priority": SEVERITY_LABELS[a["severity"]] if a["severity"] >= 1 else "low",
                "article_ids": _cluster_ids(conn, a["id"]),
                "method": "ai-article" if s else "source",
            })
        crit = sum(1 for it in items if it["priority"] == "critical")
        high = sum(1 for it in items if it["priority"] == "high")
        parts = []
        if crit or high:
            parts.append(" and ".join(p for p in (f"{crit} critical" if crit else "", f"{high} high-priority" if high else "") if p)
                         + f" development{'s' if crit + high != 1 else ''}")
        else:
            parts.append("No critical or high-priority developments")
        if kev_new:
            parts.append(f"{len(kev_new)} CISA KEV addition{'s' if len(kev_new) != 1 else ''} in 48h")
        if watch_updates:
            parts.append(f"updates on {len(watch_updates)} followed item{'s' if len(watch_updates) != 1 else ''}")
        headline = "; ".join(parts) + f" across {len(cands)} reports."

    ids = sorted({i for it in items for i in it["article_ids"]})
    content = {"headline": headline, "items": items, "kev_new": kev_new,
               "watch_updates": watch_updates, "window_start": since}
    bid = conn.execute(
        "INSERT INTO briefings(briefing_date, generated_at, method, model, content_json, article_ids) VALUES(?,?,?,?,?,?)",
        (local_today(), now_iso(), method, model, jdumps(content), jdumps(ids)),
    ).lastrowid
    if notify_user and items:
        notify(conn, kind="briefing", title=f"Daily briefing for {local_today()} is ready", body=headline[:300], link="/",
               dedupe_key=f"briefing:{local_today()}")
    return bid
