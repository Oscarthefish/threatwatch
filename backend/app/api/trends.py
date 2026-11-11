"""Trends: what the collected reporting says is rising, falling and most active.

What is measured
  * Reporting counts are *stories* (a cluster of articles about the same event counts once),
    by the publisher's date. They measure coverage, not attacks.
  * Threat-group, malware, vendor and topic counts skip roundups and podcasts, which name
    many unrelated subjects at once.
  * Feeds only expose their newest items, so anything published before collection began
    came from feed backlogs and is incomplete. Those periods are flagged ``partial`` and any
    comparison that relies on them is flagged ``indicative``.
  * CISA KEV comes from the full catalogue, so KEV trends are complete from day one.
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict
from datetime import date, timedelta

from fastapi import APIRouter, Depends, Query

from ..auth import get_db, require_user
from ..db import parse_iso, utcnow

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])

STORY = "COALESCE(a.cluster_id, a.id)"
NOT_ROUNDUP = "NOT EXISTS (SELECT 1 FROM json_each(a.tags) WHERE value = 'roundup')"
ENTITY_TYPES = {"actor": "Threat actor", "ransomware": "Ransomware", "malware": "Malware", "vendor": "Vendor"}
TOPICS = {"ransomware": "Ransomware", "phishing": "Phishing", "exploited": "Exploitation", "zero-day": "Zero-days",
          "incident": "Incidents", "vulnerability": "Vulnerabilities",
          "malware": "Malware", "threat-actor": "Threat actors", "ttp": "Tradecraft (TTPs)", "detection": "Detection content"}


def _buckets(start: date, end: date, size: int) -> list[tuple[date, date]]:
    out, d = [], start
    while d <= end:
        out.append((d, min(d + timedelta(days=size - 1), end)))
        d += timedelta(days=size)
    return out


def _idx(buckets, day: date) -> int | None:
    for i, (a, b) in enumerate(buckets):
        if a <= day <= b:
            return i
    return None


@router.get("/trends")
def trends(days: int = Query(30, ge=14, le=180), conn: sqlite3.Connection = Depends(get_db)):
    today = utcnow().date()
    cur_start = today - timedelta(days=days - 1)
    prev_start = cur_start - timedelta(days=days)
    first = conn.execute("SELECT MIN(retrieved_at) FROM articles").fetchone()[0]
    coverage = parse_iso(first).date() if first else today
    size = 1 if days <= 31 else 7
    buckets = _buckets(cur_start, today, size)
    weeks = _buckets(cur_start, today, 7)
    prev_partial = prev_start < coverage
    cur_partial = cur_start < coverage

    # ---- reporting volume by severity (stories, first article's date)
    rows = conn.execute(
        f"""SELECT {STORY} AS story, MIN(substr(a.published_at,1,10)) AS d, MAX(a.severity) AS sev,
                   MAX(EXISTS(SELECT 1 FROM json_each(a.tags) WHERE value IN ('exploited','zero-day'))) AS exploited
            FROM articles a WHERE a.published_at >= ? GROUP BY story""", (prev_start.isoformat(),)).fetchall()
    vol = [{"start": a.isoformat(), "end": b.isoformat(), "critical": 0, "high": 0, "other": 0, "partial": a < coverage} for a, b in buckets]
    tot = {"cur": defaultdict(int), "prev": defaultdict(int)}
    for r in rows:
        d = date.fromisoformat(r["d"])
        period = "cur" if d >= cur_start else "prev"
        tot[period]["reports"] += 1
        tot[period]["critical_high"] += r["sev"] >= 3
        tot[period]["exploited"] += r["exploited"]
        if period == "cur" and (i := _idx(buckets, d)) is not None:
            vol[i]["critical" if r["sev"] >= 4 else "high" if r["sev"] == 3 else "other"] += 1

    # ---- entities: per-period story counts and a weekly series for the current period
    ent_rows = conn.execute(
        f"""SELECT e.type, e.value, {STORY} AS story, MIN(substr(a.published_at,1,10)) AS d
            FROM article_entities ae JOIN entities e ON e.id=ae.entity_id JOIN articles a ON a.id=ae.article_id
            WHERE e.type IN ({','.join('?' * len(ENTITY_TYPES))}) AND a.published_at >= ? AND {NOT_ROUNDUP}
            GROUP BY e.type, lower(e.value), story""", (*ENTITY_TYPES, prev_start.isoformat())).fetchall()
    tag_rows = conn.execute(
        f"""SELECT 'topic' AS type, j.value AS value, {STORY} AS story, MIN(substr(a.published_at,1,10)) AS d
            FROM articles a, json_each(a.tags) j WHERE a.published_at >= ? AND j.value IN ({','.join('?' * len(TOPICS))})
            GROUP BY j.value, story""", (prev_start.isoformat(), *TOPICS)).fetchall()
    ents: dict[tuple[str, str], dict] = {}
    for r in [*ent_rows, *tag_rows]:
        key = (r["type"], r["value"].lower())
        e = ents.setdefault(key, {"type": r["type"], "name": TOPICS.get(r["value"], r["value"]) if r["type"] == "topic" else r["value"],
                                  "query": r["value"] if r["type"] != "topic" else None, "tag": r["value"] if r["type"] == "topic" else None,
                                  "cur": 0, "prev": 0, "weekly": [0] * len(weeks)})
        d = date.fromisoformat(r["d"])
        if d >= cur_start:
            e["cur"] += 1
            if (i := _idx(weeks, d)) is not None:
                e["weekly"][i] += 1
        else:
            e["prev"] += 1

    def ranked(types, n):
        for e in ents.values():
            e["share"] = round(100 * e["cur"] / max(tot["cur"]["reports"], 1), 1)
        xs = [e for e in ents.values() if e["type"] in types and e["cur"] > 0]
        return sorted(xs, key=lambda e: (-e["cur"], -e["prev"], e["name"].lower()))[:n]

    # Movement is a change in *share of all stories*, not in raw counts: collection volume differs between
    # periods (especially while early periods come from feed backlogs), and raw counts would make
    # everything look like it is rising.
    n_cur, n_prev = max(tot["cur"]["reports"], 1), max(tot["prev"]["reports"], 1)
    movers = []
    for e in ents.values():
        if e["cur"] + e["prev"] < 4 or not tot["prev"]["reports"]:
            continue
        cs, ps = 100 * e["cur"] / n_cur, 100 * e["prev"] / n_prev
        if abs(cs - ps) >= 1.0:
            movers.append(e | {"share": round(cs, 1), "prev_share": round(ps, 1), "change": round(cs - ps, 1)})
    rising = sorted([m for m in movers if m["change"] > 0], key=lambda m: -m["change"])[:8]
    falling = sorted([m for m in movers if m["change"] < 0], key=lambda m: m["change"])[:8]

    # ---- CISA KEV (complete catalogue)
    kev_rows = conn.execute("SELECT kev_date_added AS d, vendor, kev_ransomware FROM vulnerabilities WHERE kev=1 AND kev_date_added >= ?",
                            (prev_start.isoformat(),)).fetchall()
    kev_weeks = [{"start": a.isoformat(), "end": b.isoformat(), "count": 0} for a, b in weeks]
    kev_tot = {"cur": 0, "prev": 0, "ransomware": 0}
    vendors: dict[str, dict] = {}
    for r in kev_rows:
        d = date.fromisoformat(r["d"][:10])
        cur = d >= cur_start
        kev_tot["cur" if cur else "prev"] += 1
        v = vendors.setdefault((r["vendor"] or "Unknown").strip(), {"name": (r["vendor"] or "Unknown").strip(), "cur": 0, "prev": 0})
        v["cur" if cur else "prev"] += 1
        if cur:
            kev_tot["ransomware"] += r["kev_ransomware"] == "Known"
            if (i := _idx(weeks, d)) is not None:
                kev_weeks[i]["count"] += 1

    return {
        "days": days, "bucket_days": size, "today": today.isoformat(), "period_start": cur_start.isoformat(),
        "previous_start": prev_start.isoformat(), "coverage_start": coverage.isoformat(),
        "current_partial": cur_partial, "comparison_indicative": prev_partial,
        "totals": {"current": dict(tot["cur"]), "previous": dict(tot["prev"])},
        "volume": vol,
        "weeks": [{"start": a.isoformat(), "end": b.isoformat()} for a, b in weeks],
        "groups": ranked({"actor", "ransomware"}, 10),
        "malware": ranked({"malware"}, 8),
        "vendors": ranked({"vendor"}, 8),
        "topics": ranked({"topic"}, 10),
        "rising": rising, "falling": falling,
        "kev": {"weekly": kev_weeks, "current": kev_tot["cur"], "previous": kev_tot["prev"], "ransomware": kev_tot["ransomware"],
                "vendors": sorted([v for v in vendors.values() if v["cur"]], key=lambda v: (-v["cur"], v["name"]))[:8]},
    }
