"""Ransomware: which groups are posting the most leak-site claims, against which sectors and countries.

What is measured
  * Claims posted on ransomware groups' leak sites, as aggregated by ransomware.live, by the date the tracker
    first saw each post. A claim is the group's own statement: groups exaggerate, re-post old victims and
    sometimes list organisations they never breached. Counts measure claims, not confirmed attacks.
  * Rising and falling compare each group's share of all claims, as on the Trends page.
  * Periods before the backfill start are flagged ``partial``; comparisons relying on them ``indicative``.
  * A claim links to Threat Watch reporting only when a collected story names the victim.
"""
from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from datetime import date, timedelta

from fastapi import APIRouter, Depends, Query

from ..auth import get_db, require_user
from ..db import get_setting, parse_iso, utcnow
from ..ingest.ransom import group_page

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])

REGION = ("NZ", "AU")
_GENERIC = {"inc", "group", "the", "company", "limited", "ltd", "llc", "corp", "school", "hospital", "bank", "city", "county"}


def coverage_start(conn: sqlite3.Connection) -> date | None:
    since = get_setting(conn, "ransom_claims_since")
    if since:
        return date.fromisoformat(since)
    first = conn.execute("SELECT MIN(discovered_at) FROM ransomware_claims").fetchone()[0]
    return parse_iso(first).date() if first else None


def _fts_phrase(name: str) -> str | None:
    words = [w for w in name.replace('"', " ").split() if w]
    if not words or len(name) < 4 or (len(words) == 1 and words[0].lower() in _GENERIC):
        return None
    return '"' + " ".join(words) + '"'


def news_for(conn: sqlite3.Connection, claim: dict, limit: int = 2) -> list[dict]:
    """Collected stories that name the claimed victim (title or summary), from 30 days before the claim onwards."""
    phrase = _fts_phrase(claim["victim"])
    if not phrase:
        return []
    since = (parse_iso(claim["discovered_at"]) - timedelta(days=30)).isoformat()
    try:
        rows = conn.execute(
            """SELECT a.id, a.title, s.name AS source FROM articles_fts f JOIN articles a ON a.id=f.rowid JOIN sources s ON s.id=a.source_id
               WHERE articles_fts MATCH ? AND a.published_at >= ? ORDER BY a.published_at DESC LIMIT ?""",
            (f"{{title summary_text}}: {phrase}", since, limit)).fetchall()
    except sqlite3.OperationalError:  # unusual characters the FTS parser rejects: no link rather than a guess
        return []
    return [{"id": r["id"], "title": r["title"], "source": r["source"]} for r in rows]


def claim_out(conn: sqlite3.Connection, r: sqlite3.Row, with_news: bool = True) -> dict:
    c = {k: r[k] for k in ("id", "group_name", "group_raw", "victim", "domain", "country", "sector", "attack_date", "discovered_at")}
    c["record_url"] = r["record_url"]
    c["news"] = news_for(conn, c) if with_news else []
    return c


def _buckets(start: date, end: date, size: int) -> list[tuple[date, date]]:
    out, d = [], start
    while d <= end:
        out.append((d, min(d + timedelta(days=size - 1), end)))
        d += timedelta(days=size)
    return out


def _idx(buckets, d: date) -> int | None:
    for i, (a, b) in enumerate(buckets):
        if a <= d <= b:
            return i
    return None


@router.get("/ransomware")
def ransomware(days: int = Query(30, ge=14, le=90), conn: sqlite3.Connection = Depends(get_db)):
    today = utcnow().date()
    cur_start = today - timedelta(days=days - 1)
    prev_start = cur_start - timedelta(days=days)
    cov = coverage_start(conn)
    src = conn.execute("SELECT enabled, last_success_at, last_status, last_error FROM sources WHERE key='ransomware-live'").fetchone()
    size = 1 if days <= 31 else 7
    buckets, weeks = _buckets(cur_start, today, size), _buckets(cur_start, today, 7)
    rows = conn.execute(
        "SELECT group_name, group_raw, country, sector, substr(discovered_at,1,10) AS d FROM ransomware_claims WHERE discovered_at >= ?",
        (prev_start.isoformat(),)).fetchall()

    tot = {"cur": 0, "prev": 0}
    volume = [{"start": a.isoformat(), "end": b.isoformat(), "count": 0, "partial": bool(cov is None or a < cov)} for a, b in buckets]
    groups: dict[str, dict] = {}
    sectors: dict[str, dict] = defaultdict(lambda: {"cur": 0, "prev": 0})
    countries: dict[str, dict] = defaultdict(lambda: {"cur": 0, "prev": 0})
    unknown = {"sector": 0, "country": 0}
    for r in rows:
        d = date.fromisoformat(r["d"])
        p = "cur" if d >= cur_start else "prev"
        tot[p] += 1
        g = groups.setdefault(r["group_name"].lower(), {"name": r["group_name"], "raw": Counter(), "cur": 0, "prev": 0,
                                                         "weekly": [0] * len(weeks), "sectors": Counter(), "countries": Counter()})
        g[p] += 1
        sectors[r["sector"] or ""][p] += 1
        countries[r["country"] or ""][p] += 1
        if p == "cur":
            g["raw"][r["group_raw"]] += 1
            if r["sector"]:
                g["sectors"][r["sector"]] += 1
            else:
                unknown["sector"] += 1
            if r["country"]:
                g["countries"][r["country"]] += 1
            else:
                unknown["country"] += 1
            if (i := _idx(buckets, d)) is not None:
                volume[i]["count"] += 1
            if (i := _idx(weeks, d)) is not None:
                g["weekly"][i] += 1

    n_cur, n_prev = max(tot["cur"], 1), max(tot["prev"], 1)

    def group_out(g: dict) -> dict:
        raw = g["raw"].most_common(1)[0][0] if g["raw"] else g["name"]
        return {"name": g["name"], "cur": g["cur"], "prev": g["prev"], "share": round(100 * g["cur"] / n_cur, 1),
                "weekly": g["weekly"], "tracker_url": group_page(raw),
                "sectors": [{"name": k, "n": v} for k, v in g["sectors"].most_common(3)],
                "countries": [{"code": k, "n": v} for k, v in g["countries"].most_common(3)]}

    active = sorted((g for g in groups.values() if g["cur"]), key=lambda g: (-g["cur"], -g["prev"], g["name"].lower()))
    movers = []
    if tot["prev"]:
        for g in groups.values():
            if g["cur"] + g["prev"] < 8:
                continue
            cs, ps = 100 * g["cur"] / n_cur, 100 * g["prev"] / n_prev
            if abs(cs - ps) >= 1.0:
                movers.append(group_out(g) | {"prev_share": round(ps, 1), "change": round(cs - ps, 1)})

    def ranked(d: dict, key: str, n: int) -> list[dict]:
        xs = [{key: k, "cur": v["cur"], "prev": v["prev"]} for k, v in d.items() if k and v["cur"]]
        return sorted(xs, key=lambda x: (-x["cur"], x[key]))[:n]

    recent = [claim_out(conn, r) for r in conn.execute("SELECT * FROM ransomware_claims ORDER BY discovered_at DESC, id DESC LIMIT 30")]
    region_since = (today - timedelta(days=90)).isoformat()
    regional = [claim_out(conn, r) for r in conn.execute(
        f"SELECT * FROM ransomware_claims WHERE country IN ({','.join('?' * len(REGION))}) AND discovered_at >= ? ORDER BY discovered_at DESC LIMIT 40",
        (*REGION, region_since))]
    return {
        "days": days, "bucket_days": size, "today": today.isoformat(), "period_start": cur_start.isoformat(),
        "previous_start": prev_start.isoformat(), "coverage_start": cov.isoformat() if cov else None,
        "current_partial": cov is None or cur_start < cov, "comparison_indicative": cov is None or prev_start < cov,
        "source": {"enabled": bool(src["enabled"]) if src else False, "last_success_at": src["last_success_at"] if src else None,
                   "status": src["last_status"] if src else None},
        "totals": {"current": tot["cur"], "previous": tot["prev"], "groups": sum(1 for g in groups.values() if g["cur"]),
                   "unknown_sector": unknown["sector"], "unknown_country": unknown["country"]},
        "volume": volume, "weeks": [{"start": a.isoformat(), "end": b.isoformat()} for a, b in weeks],
        "groups": [group_out(g) for g in active[:12]],
        "rising": sorted([m for m in movers if m["change"] > 0], key=lambda m: -m["change"])[:6],
        "falling": sorted([m for m in movers if m["change"] < 0], key=lambda m: m["change"])[:6],
        "sectors": ranked(sectors, "name", 10), "countries": ranked(countries, "code", 10),
        "regional": regional, "regional_days": 90, "recent": recent,
    }


def group_claims(conn: sqlite3.Connection, name: str, aliases: list[str], cur_start: date, prev_start: date,
                 weeks: list[tuple[date, date]]) -> dict | None:
    """Leak-site claims for one group's profile page (None when the group has never posted a claim)."""
    names = [n.lower() for n in [name, *aliases]]
    ph = ",".join("?" * len(names))
    rows = conn.execute(
        f"SELECT * FROM ransomware_claims WHERE lower(group_name) IN ({ph}) ORDER BY discovered_at DESC", names).fetchall()
    if not rows:
        return None
    cov = coverage_start(conn)
    weekly = [{"start": a.isoformat(), "end": b.isoformat(), "count": 0, "partial": bool(cov is None or a < cov)} for a, b in weeks]
    cur = prev = 0
    sectors, countries, raw = Counter(), Counter(), Counter()
    for r in rows:
        d = date.fromisoformat(r["discovered_at"][:10])
        if d >= cur_start:
            cur += 1
            raw[r["group_raw"]] += 1
            if r["sector"]:
                sectors[r["sector"]] += 1
            if r["country"]:
                countries[r["country"]] += 1
            if (i := _idx(weeks, d)) is not None:
                weekly[i]["count"] += 1
        elif d >= prev_start:
            prev += 1
    top_raw = (raw or Counter({rows[0]["group_raw"]: 1})).most_common(1)[0][0]
    return {
        "current": cur, "previous": prev, "weekly": weekly, "tracker_url": group_page(top_raw),
        "first_seen": rows[-1]["discovered_at"], "last_seen": rows[0]["discovered_at"],
        "coverage_start": cov.isoformat() if cov else None, "comparison_indicative": cov is None or prev_start < cov,
        "sectors": [{"name": k, "n": v} for k, v in sectors.most_common(6)],
        "countries": [{"code": k, "n": v} for k, v in countries.most_common(6)],
        "recent": [claim_out(conn, r) for r in rows[:12]],
    }
