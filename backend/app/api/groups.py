"""Threat group profiles: reporting over time for one actor, ransomware group or malware family.

Counting follows the Trends page: stories (clustered articles count once) by publisher date,
roundups excluded from the counts but listed separately, and periods before collection began
flagged as incomplete.
"""
from __future__ import annotations

import sqlite3
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import get_db, require_user
from ..db import jloads, parse_iso, utcnow
from ..intel import entities
from .content import _list_articles

router = APIRouter(prefix="/api/groups", dependencies=[Depends(require_user)])

KINDS = {"actor": ("actor", entities.ACTORS), "ransomware": ("ransomware", entities.RANSOMWARE), "malware": ("malware", entities.MALWARE)}
STORY = "COALESCE(a.cluster_id, a.id)"
ROUNDUP = "EXISTS (SELECT 1 FROM json_each(a.tags) WHERE value = 'roundup')"


def _canonical(kind: str, name: str) -> tuple[str, list[str]]:
    table = KINDS[kind][1]
    for canon, aliases in table.items():
        if name.lower() == canon.lower() or name.lower() in (a.lower() for a in aliases):
            return canon, list(aliases)
    return name, []


@router.get("/{kind}/{name}")
def group(kind: str, name: str, days: int = Query(90, ge=28, le=365), conn: sqlite3.Connection = Depends(get_db)):
    if kind not in KINDS:
        raise HTTPException(404, "unknown kind")
    canon, aliases = _canonical(kind, name.strip())
    ent_ids = [r[0] for r in conn.execute("SELECT id FROM entities WHERE type=? AND lower(value)=lower(?)", (kind, canon))]
    if not ent_ids and not aliases and canon not in KINDS[kind][1]:
        raise HTTPException(404, "not found")
    ph = ",".join("?" * len(ent_ids)) or "NULL"

    today = utcnow().date()
    cur_start = today - timedelta(days=days - 1)
    prev_start = cur_start - timedelta(days=days)
    first = conn.execute("SELECT MIN(retrieved_at) FROM articles").fetchone()[0]
    coverage = parse_iso(first).date() if first else today
    weeks, d = [], cur_start
    while d <= today:
        weeks.append((d, min(d + timedelta(days=6), today)))
        d += timedelta(days=7)

    stories = conn.execute(
        f"""SELECT {STORY} AS story, MIN(substr(a.published_at,1,10)) AS d, MAX(a.severity) AS sev, MAX({ROUNDUP}) AS roundup
            FROM article_entities ae JOIN articles a ON a.id=ae.article_id WHERE ae.entity_id IN ({ph}) GROUP BY story""", ent_ids).fetchall()
    counted = [s for s in stories if not s["roundup"]]
    series = [{"start": a.isoformat(), "end": b.isoformat(), "critical": 0, "high": 0, "other": 0, "partial": a < coverage} for a, b in weeks]
    cur = prev = 0
    for s in counted:
        day = date.fromisoformat(s["d"])
        if day >= cur_start:
            cur += 1
            for i, (a, b) in enumerate(weeks):
                if a <= day <= b:
                    series[i]["critical" if s["sev"] >= 4 else "high" if s["sev"] == 3 else "other"] += 1
                    break
        elif day >= prev_start:
            prev += 1
    totals = {r[0]: r[1] for r in conn.execute(
        f"""SELECT CASE WHEN d >= ? THEN 'cur' ELSE 'prev' END, COUNT(*) FROM
              (SELECT {STORY} AS story, MIN(substr(a.published_at,1,10)) AS d FROM articles a WHERE a.published_at >= ? GROUP BY story)
            GROUP BY 1""", (cur_start.isoformat(), prev_start.isoformat()))}
    dates = sorted(s["d"] for s in counted)

    # Subjects most often reported in the same (non-roundup) articles
    co = conn.execute(
        f"""SELECT e.type, e.value, COUNT(DISTINCT {STORY}) AS n
            FROM article_entities x JOIN articles a ON a.id=x.article_id
            JOIN article_entities ae ON ae.article_id=a.id JOIN entities e ON e.id=ae.entity_id
            WHERE x.entity_id IN ({ph}) AND NOT {ROUNDUP} AND e.id NOT IN ({ph})
              AND e.type IN ('cve','actor','ransomware','malware','vendor','attack_technique')
            GROUP BY e.type, lower(e.value) ORDER BY n DESC, e.value LIMIT 60""", [*ent_ids, *ent_ids]).fetchall()
    related: dict[str, list[dict]] = {}
    for r in co:
        key = "groups" if r["type"] in ("actor", "ransomware") else r["type"]
        if len(related.setdefault(key, [])) < 6:
            related[key].append({"type": r["type"], "value": r["value"].upper() if r["type"] == "cve" else r["value"], "stories": r["n"],
                                 "name": entities.technique_name(r["value"].upper()) if r["type"] == "attack_technique" else None})

    art_ids = [r[0] for r in conn.execute(f"SELECT DISTINCT article_id FROM article_entities WHERE entity_id IN ({ph})", ent_ids)]
    arts = _list_articles(conn, ids=art_ids, collapse=False, order="new", limit=40)
    watch = None
    for w in conn.execute("SELECT id, title, identifiers, aliases FROM watches WHERE status='active'"):
        names = {x.lower() for x in [*jloads(w["identifiers"]), *jloads(w["aliases"])]}
        if canon.lower() in names or any(a.lower() in names for a in aliases):
            watch = {"id": w["id"], "title": w["title"]}
            break

    from ..ingest.attack import lookup
    from ..intel.reading import attack_summary
    attack = attack_summary(lookup(conn, [canon, *aliases], "group" if kind == "actor" else "software"))
    attack_synced = conn.execute("SELECT MAX(synced_at) FROM attack_objects").fetchone()[0]
    for r in related.get("attack_technique", []):
        from ..intel.reading import technique_url
        r["url"] = technique_url(r["value"])
    return {
        "attack": attack, "attack_synced_at": attack_synced,
        "kind": kind, "name": canon, "aliases": aliases, "known": bool(ent_ids), "days": days,
        "period_start": cur_start.isoformat(), "coverage_start": coverage.isoformat(), "current_partial": cur_start < coverage,
        "comparison_indicative": prev_start < coverage,
        "stories": cur, "previous": prev, "all_time": len(counted), "roundups": len(stories) - len(counted),
        "share": round(100 * cur / totals["cur"], 1) if totals.get("cur") else 0.0,
        "previous_share": round(100 * prev / totals["prev"], 1) if totals.get("prev") else None,
        "first_seen": dates[0] if dates else None, "last_seen": dates[-1] if dates else None,
        "sources": sorted({a["source"]["name"] for a in arts if "roundup" not in a["tags"]}),
        "weekly": series, "related": related, "articles": arts, "watch": watch,
    }
