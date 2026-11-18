"""Ransomware leak-site claims from ransomware.live (free API v2, personal use, 1 request/minute per endpoint).

* Each run reads ``/v2/recentvictims`` (the newest 100 claims, about two days).
* The first run also backfills the last three calendar months from ``/v2/victims/{year}/{month}`` so trends are
  complete from day one; requests are spaced more than a minute apart to respect the rate limit.
* Only identifying fields are stored. Leak descriptions, screenshots and leak-site addresses are dropped: the app
  links to the tracker's record, never to a leak site.
* These are the groups' own claims. Nothing here marks a claim as a confirmed compromise.
"""
from __future__ import annotations

import html
import json
import logging
import re
import sqlite3
import time
from datetime import date, datetime, timedelta, timezone

from ..db import get_setting, iso, now_iso, set_setting, tx, utcnow
from ..intel import entities
from .fetcher import fetch

log = logging.getLogger(__name__)

API = "https://api.ransomware.live/v2"
RECORD_PREFIX = "https://www.ransomware.live/id/"
GROUP_PAGE = "https://www.ransomware.live/group/"
BACKFILL_MONTHS = 3
RETENTION_DAYS = 200  # 90-day view plus the 90 days before it, with margin
_UNKNOWN_SECTOR = {"", "not found", "other", "unknown", "n/a"}
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


_CANON: dict[str, str] = {}
for _canon, _aliases in entities.RANSOMWARE.items():
    for _n in (_canon, *_aliases):
        _CANON.setdefault(_norm(_n), _canon)


def canonical_group(raw: str) -> str:
    """Map the tracker's group name ("thegentlemen", "lockbit5") to Threat Watch's name ("The Gentlemen", "LockBit")."""
    raw = html.unescape(raw or "").strip()
    n = _norm(raw)
    if n in _CANON:
        return _CANON[n]
    stripped = re.sub(r"\d+$", "", n)  # version suffixes: lockbit5 -> lockbit
    if stripped and stripped != n and stripped in _CANON:
        return _CANON[stripped]
    return raw[:1].upper() + raw[1:] if raw.islower() else raw


def group_page(raw: str) -> str:
    return GROUP_PAGE + re.sub(r"[^A-Za-z0-9._~-]", lambda m: "%%%02X" % ord(m.group(0)), raw)


def _iso(v) -> str | None:
    if not v or not isinstance(v, str):
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return iso(d)


def parse(content: bytes) -> list[dict]:
    """Validated claim rows from an API response; malformed entries are skipped, never guessed at."""
    data = json.loads(content)
    if not isinstance(data, list):
        raise ValueError("unexpected response shape")
    out = []
    for x in data:
        if not isinstance(x, dict):
            continue
        url, grp, victim, disc = x.get("url"), x.get("group"), x.get("victim"), _iso(x.get("discovered"))
        if not (isinstance(url, str) and url.startswith(RECORD_PREFIX) and len(url) < 400 and isinstance(grp, str)
                and grp.strip() and isinstance(victim, str) and victim.strip() and disc):
            continue
        domain = (x.get("domain") or "").strip().lower() if isinstance(x.get("domain"), str) else ""
        country = (x.get("country") or "").strip().upper() if isinstance(x.get("country"), str) else ""
        sector = html.unescape((x.get("activity") or "").strip()) if isinstance(x.get("activity"), str) else ""
        out.append({
            "record_url": url, "group_raw": html.unescape(grp.strip())[:100], "group_name": canonical_group(grp)[:100],
            "victim": re.sub(r"\s+", " ", html.unescape(victim)).strip()[:200],
            "domain": domain if _DOMAIN.match(domain) else None,
            "country": country if _COUNTRY.match(country) else None,
            "sector": None if sector.lower() in _UNKNOWN_SECTOR else sector[:80],
            "attack_date": _iso(x.get("attackdate")), "discovered_at": disc,
        })
    return out


def store(conn: sqlite3.Connection, rows: list[dict]) -> int:
    now, n = now_iso(), 0
    with tx(conn):
        for r in rows:
            n += conn.execute(
                """INSERT OR IGNORE INTO ransomware_claims(record_url, group_raw, group_name, victim, domain, country, sector,
                   attack_date, discovered_at, retrieved_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (r["record_url"], r["group_raw"], r["group_name"], r["victim"], r["domain"], r["country"], r["sector"],
                 r["attack_date"], r["discovered_at"], now)).rowcount
    return n


def _months(today: date, n: int) -> list[tuple[int, int]]:
    out, y, m = [], today.year, today.month
    for _ in range(n):
        out.append((y, m))
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return out


def ingest_claims(conn: sqlite3.Connection, src: dict, sleep=time.sleep) -> tuple[int, str]:
    """Returns (new claims, detail). Raises on a failed fetch of the recent list so the source shows the error."""
    base = src["url"].rsplit("/", 1)[0] if src["url"].endswith("/recentvictims") else API
    new = store(conn, parse(fetch(src["url"], accept="application/json").content))
    detail = f"{new} new claims"
    if not get_setting(conn, "ransom_claims_backfilled"):
        months = _months(utcnow().date(), BACKFILL_MONTHS)
        got = 0
        for y, m in months:
            sleep(61)  # free API: one request per minute per endpoint
            try:
                got += store(conn, parse(fetch(f"{base}/victims/{y}/{m:02d}", accept="application/json", max_bytes=20_000_000).content))
            except Exception as e:  # a failed month is retried on the next run
                log.warning("ransomware.live backfill %s-%02d failed: %s", y, m, e)
                return new + got, f"{detail}; backfill incomplete, retrying next run"
        oldest = months[-1]
        set_setting(conn, "ransom_claims_backfilled", now_iso())
        set_setting(conn, "ransom_claims_since", f"{oldest[0]}-{oldest[1]:02d}-01")
        new += got
        detail = f"{new} new claims (including {got} from the {BACKFILL_MONTHS}-month backfill)"
    conn.execute("DELETE FROM ransomware_claims WHERE discovered_at < ?", (iso(utcnow() - timedelta(days=RETENTION_DAYS)),))
    return new, detail
