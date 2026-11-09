"""Ingestion pipeline: fetch sources, store evidence, extract, classify, cluster."""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import timedelta
from urllib.parse import quote

from ..config import get_settings
from ..db import iso, jdumps, jloads, now_iso, parse_iso, tx, utcnow
from ..intel import ai, classify, dedupe, entities
from .fetcher import FetchError, fetch
from .sources import ADAPTERS, DEFAULT_SOURCES, SEVERITY_CAPS, NcscNzAdapter, RawItem, parse_kev

log = logging.getLogger(__name__)

STRONG_TYPES = ("cve", "actor", "ransomware", "malware")


# ------------------------------------------------------------------ sources
def sync_sources(conn: sqlite3.Connection) -> None:
    """Insert default sources that are missing; refresh URLs/metadata, preserving user enable flags."""
    for s in DEFAULT_SOURCES:
        conn.execute(
            """INSERT INTO sources(key, name, kind, url, homepage, enabled, interval_minutes, authority, region, default_sections)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET name=excluded.name, kind=excluded.kind, url=excluded.url,
                 homepage=excluded.homepage, authority=excluded.authority, region=excluded.region,
                 default_sections=excluded.default_sections""",
            (s.key, s.name, s.kind, s.url, s.homepage, int(s.enabled), s.interval_minutes, s.authority, s.region, jdumps(s.sections)),
        )


def _source_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["default_sections"] = jloads(d.get("default_sections"))
    return d


def _due(src: dict, force: bool) -> bool:
    if force or not src.get("last_fetched_at"):
        return True
    last = parse_iso(src["last_fetched_at"])
    interval = max(src["interval_minutes"], get_settings().ingest_interval_minutes)
    if src["consecutive_failures"] >= 3:  # back off failing sources (max 6h)
        interval = min(interval * (2 ** min(src["consecutive_failures"] - 2, 4)), 360)
    return last is None or utcnow() - last >= timedelta(minutes=interval) - timedelta(minutes=2)


def _mark(conn, src_id: int, ok: bool, status: str, error: str | None = None, items: int = 0, etag=None, last_modified=None):
    now = now_iso()
    if ok:
        conn.execute(
            """UPDATE sources SET last_fetched_at=?, last_success_at=?, last_status=?, last_error=NULL, items_last_run=?,
               consecutive_failures=0, etag=COALESCE(?, etag), last_modified=COALESCE(?, last_modified) WHERE id=?""",
            (now, now, status, items, etag, last_modified, src_id),
        )
    else:
        conn.execute(
            "UPDATE sources SET last_fetched_at=?, last_status=?, last_error=?, items_last_run=0, consecutive_failures=consecutive_failures+1 WHERE id=?",
            (now, status, (error or "")[:500], src_id),
        )


# ----------------------------------------------------------------- articles
def store_item(conn: sqlite3.Connection, src: dict, item: RawItem) -> int | None:
    canon = dedupe.canonical_url(item.url)
    if conn.execute("SELECT 1 FROM articles WHERE canonical_url=?", (canon,)).fetchone():
        return None
    if item.guid and conn.execute("SELECT 1 FROM articles WHERE source_id=? AND guid=?", (src["id"], item.guid)).fetchone():
        return None
    now = utcnow()
    pub = item.published_at
    if pub and pub > now + timedelta(hours=1):  # clamp bogus future dates
        pub = now
    cur = conn.execute(
        """INSERT INTO articles(source_id, url, canonical_url, guid, title, author, summary_text, content_text,
               published_at, retrieved_at, title_tokens)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (src["id"], item.url, canon, item.guid, item.title, item.author, item.summary_text, item.content_text,
         iso(pub) if pub else iso(now), iso(now), " ".join(sorted(dedupe.title_tokens(item.title)))),
    )
    return cur.lastrowid


def _upsert_entity(conn, e: entities.Entity) -> int:
    row = conn.execute("SELECT id FROM entities WHERE type=? AND normalized=?", (e.type, e.normalized)).fetchone()
    if row:
        return row[0]
    return conn.execute("INSERT INTO entities(type, value, normalized) VALUES(?,?,?)", (e.type, e.value, e.normalized)).lastrowid


def ensure_vuln_stub(conn, cve_id: str) -> None:
    now = now_iso()
    conn.execute(
        "INSERT INTO vulnerabilities(cve_id, first_seen_at, updated_at) VALUES(?,?,?) ON CONFLICT(cve_id) DO NOTHING",
        (cve_id.upper(), now, now),
    )


def article_entities(conn, article_id: int) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r in conn.execute(
        "SELECT e.type, e.normalized FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=?",
        (article_id,),
    ):
        out.setdefault(r[0], set()).add(r[1])
    return out


def process_article(conn: sqlite3.Connection, article_id: int) -> None:
    a = conn.execute(
        "SELECT a.*, s.name AS source_name, s.key AS source_key, s.kind AS source_kind, s.authority, s.region AS source_region, s.default_sections "
        "FROM articles a JOIN sources s ON s.id=a.source_id WHERE a.id=?",
        (article_id,),
    ).fetchone()
    if not a:
        return
    body = f"{a['summary_text']}\n{a['content_text']}"
    ents = entities.extract(a["title"], body)
    conn.execute("DELETE FROM article_entities WHERE article_id=? AND method='rule'", (article_id,))
    for e in ents:
        eid = _upsert_entity(conn, e)
        conn.execute(
            "INSERT OR IGNORE INTO article_entities(article_id, entity_id, in_title, method) VALUES(?,?,?, 'rule')",
            (article_id, eid, int(e.in_title)),
        )
        if e.type == "cve":
            ensure_vuln_stub(conn, e.value)
    etypes = article_entities(conn, article_id)
    cves = sorted(v.upper() for v in etypes.get("cve", set()))
    vfacts = [dict(r) for r in conn.execute(
        f"SELECT * FROM vulnerabilities WHERE cve_id IN ({','.join('?' * len(cves))})", cves)] if cves else []
    src = {"name": a["source_name"], "kind": a["source_kind"], "authority": a["authority"], "region": a["source_region"],
           "default_sections": jloads(a["default_sections"])}
    c = classify.classify(a["title"], body, src, etypes, vfacts)
    cap = SEVERITY_CAPS.get(a["source_key"])
    if cap is not None and c.severity > cap:
        c.severity = cap
        c.reasons.append("Severity capped for this source type (release notes / podcast)")
        c.sections = [x for x in c.sections if x != "breaking"]
    conn.execute(
        "UPDATE articles SET sections=?, tags=?, severity=?, severity_reasons=?, region=?, extracted_at=? WHERE id=?",
        (jdumps(c.sections), jdumps(c.tags), c.severity, jdumps(c.reasons), c.region, now_iso(), article_id),
    )
    assign_cluster(conn, article_id)


def assign_cluster(conn: sqlite3.Connection, article_id: int) -> None:
    a = conn.execute("SELECT id, source_id, title_tokens, published_at, cluster_id FROM articles WHERE id=?", (article_id,)).fetchone()
    toks = set(a["title_tokens"].split())
    pub = parse_iso(a["published_at"]) or utcnow()
    lo, hi = iso(pub - timedelta(hours=72)), iso(pub + timedelta(hours=72))
    mine = {(t, v) for t, vs in article_entities(conn, article_id).items() if t in STRONG_TYPES for v in vs}
    best, best_j = None, 0.0
    for r in conn.execute(
        "SELECT id, cluster_id, title_tokens FROM articles WHERE id<>? AND source_id<>? AND published_at BETWEEN ? AND ? ORDER BY id DESC LIMIT 600",
        (article_id, a["source_id"], lo, hi),
    ):
        other = set(r["title_tokens"].split())
        j = dedupe.jaccard(toks, other)
        if j < 0.5:
            continue
        theirs = {(t, v) for t, vs in article_entities(conn, r["id"]).items() if t in STRONG_TYPES for v in vs}
        my_cves = {x for x in mine if x[0] == "cve"}
        their_cves = {x for x in theirs if x[0] == "cve"}
        if (my_cves and their_cves and not my_cves & their_cves) or (mine and theirs and not mine & theirs):
            continue  # same template headline, different subject (e.g. "CISA Adds One KEV ...")
        if dedupe.is_near_duplicate(toks, other, len(mine & theirs)) and j > best_j:
            best, best_j = r, j
    cluster = (best["cluster_id"] or best["id"]) if best else article_id
    conn.execute("UPDATE articles SET cluster_id=? WHERE id=?", (cluster, article_id))
    refresh_cluster(conn, cluster)


def refresh_cluster(conn: sqlite3.Connection, cluster_id: int) -> None:
    rows = conn.execute(
        "SELECT a.id, a.severity, a.published_at, a.region, a.source_id, s.authority FROM articles a JOIN sources s ON s.id=a.source_id WHERE a.cluster_id=?",
        (cluster_id,),
    ).fetchall()
    distinct = len({r["source_id"] for r in rows})
    max_auth = max((r["authority"] for r in rows), default=2)
    for r in rows:
        conf = classify.confidence(max_auth if max_auth >= 3 else r["authority"], distinct)
        score = classify.rank_score(r["severity"], parse_iso(r["published_at"]), distinct, r["region"])
        conn.execute("UPDATE articles SET confidence=?, score=? WHERE id=?", (conf, score, r["id"]))


# -------------------------------------------------------- vulnerability data
_URL_RE = re.compile(r"https?://[^\s;,]+")


def ingest_kev(conn: sqlite3.Connection, src: dict) -> tuple[int, list[str]]:
    r = fetch(src["url"], etag=src.get("etag"), last_modified=src.get("last_modified"), accept="application/json")
    if r.not_modified:
        return 0, []
    _version, vulns = parse_kev(r.content)
    first_run = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE kev=1").fetchone()[0] == 0
    new: list[str] = []
    now = now_iso()
    with tx(conn):
        for v in vulns:
            cve = (v.get("cveID") or "").upper()
            if not entities.CVE_RE.fullmatch(cve):
                continue
            existing = conn.execute("SELECT kev FROM vulnerabilities WHERE cve_id=?", (cve,)).fetchone()
            refs = _URL_RE.findall(v.get("notes") or "")
            conn.execute(
                """INSERT INTO vulnerabilities(cve_id, vendor, product, name, description, kev, kev_date_added, kev_due_date,
                       kev_ransomware, kev_required_action, kev_notes, kev_cwes, references_json, first_seen_at, updated_at)
                   VALUES(?,?,?,?,?,1,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET vendor=COALESCE(excluded.vendor, vendor), product=COALESCE(excluded.product, product),
                     name=excluded.name, description=COALESCE(description, excluded.description), kev=1,
                     kev_date_added=excluded.kev_date_added, kev_due_date=excluded.kev_due_date, kev_ransomware=excluded.kev_ransomware,
                     kev_required_action=excluded.kev_required_action, kev_notes=excluded.kev_notes, kev_cwes=excluded.kev_cwes,
                     references_json=CASE WHEN references_json='[]' THEN excluded.references_json ELSE references_json END,
                     updated_at=excluded.updated_at""",
                (cve, v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"), v.get("shortDescription"),
                 v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"), v.get("requiredAction"),
                 v.get("notes"), jdumps(v.get("cwes") or []), jdumps(refs), now, now),
            )
            if not first_run and (existing is None or not existing["kev"]):
                new.append(cve)
    src["etag"], src["last_modified"] = r.headers.get("etag"), r.headers.get("last-modified")
    if new:
        _rescore_articles_mentioning(conn, new)
    return len(vulns), new


def _rescore_articles_mentioning(conn, cves: list[str]) -> None:
    ids = [r[0] for r in conn.execute(
        f"""SELECT DISTINCT ae.article_id FROM article_entities ae JOIN entities e ON e.id=ae.entity_id
            WHERE e.type='cve' AND e.normalized IN ({','.join('?' * len(cves))})""", [c.lower() for c in cves])]
    for aid in ids:
        process_article(conn, aid)


def ingest_epss(conn: sqlite3.Connection, src: dict) -> int:
    cutoff = iso(utcnow() - timedelta(days=60))
    cves = [r[0] for r in conn.execute(
        "SELECT cve_id FROM vulnerabilities WHERE kev=1 OR first_seen_at>=? OR cve_id IN (SELECT upper(e.normalized) FROM entities e WHERE e.type='cve')",
        (cutoff,),
    )]
    updated = 0
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        url = f"{src['url']}?cve={quote(','.join(batch), safe=',')}"
        r = fetch(url, accept="application/json")
        data = json.loads(r.content).get("data", [])
        with tx(conn):
            for d in data:
                try:
                    conn.execute(
                        "UPDATE vulnerabilities SET epss=?, epss_percentile=?, epss_date=?, updated_at=? WHERE cve_id=?",
                        (float(d["epss"]), float(d["percentile"]), d.get("date"), now_iso(), d["cve"].upper()),
                    )
                    updated += 1
                except (KeyError, ValueError):
                    continue
    return updated


def _parse_cve_record(rec: dict) -> dict:
    cont = rec.get("containers", {})
    cna = cont.get("cna", {})
    desc = next((d.get("value") for d in cna.get("descriptions", []) if (d.get("lang") or "").startswith("en")), None)
    affected = cna.get("affected", [])
    vendor = affected[0].get("vendor") if affected else None
    product = ", ".join(sorted({a.get("product") for a in affected if a.get("product")}))[:300] or None
    best = None
    for container in [cna, *cont.get("adp", [])]:
        for m in container.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if key in m and m[key].get("baseScore") is not None:
                    cand = (m[key]["baseScore"], m[key].get("baseSeverity"), m[key].get("vectorString"),
                            f"{container.get('providerMetadata', {}).get('shortName', 'CNA')} {key}")
                    if best is None or key == "cvssV3_1" and "cvssV3_1" not in best[3]:
                        best = cand
    refs = [r.get("url") for r in cna.get("references", []) if r.get("url")][:25]
    return {"description": desc, "vendor": vendor, "product": product, "cvss": best, "refs": refs}


def ingest_cve_enrichment(conn: sqlite3.Connection, src: dict, limit: int = 40) -> int:
    recent = iso(utcnow() - timedelta(days=30))
    rows = conn.execute(
        """SELECT v.cve_id FROM vulnerabilities v
           WHERE v.enriched_at IS NULL OR (v.cvss_score IS NULL AND v.enriched_at < ?)
           ORDER BY (v.cve_id IN (SELECT upper(e.normalized) FROM entities e WHERE e.type='cve')) DESC,
                    v.kev_date_added DESC, v.first_seen_at DESC LIMIT ?""",
        (iso(utcnow() - timedelta(days=3)), limit),
    ).fetchall()
    _ = recent
    done = 0
    for (cve,) in rows:
        try:
            r = fetch(src["url"] + quote(cve), accept="application/json", retries=1)
            info = _parse_cve_record(json.loads(r.content))
        except FetchError as e:
            if "HTTP 404" in str(e):
                conn.execute("UPDATE vulnerabilities SET enriched_at=? WHERE cve_id=?", (now_iso(), cve))
            else:
                log.warning("CVE enrichment failed for %s: %s", cve, e)
            continue
        except ValueError:
            continue
        cv = info["cvss"]
        conn.execute(
            """UPDATE vulnerabilities SET description=COALESCE(?, description), vendor=COALESCE(vendor, ?), product=COALESCE(product, ?),
                 cvss_score=COALESCE(?, cvss_score), cvss_severity=COALESCE(?, cvss_severity), cvss_vector=COALESCE(?, cvss_vector),
                 cvss_source=COALESCE(?, cvss_source),
                 references_json=CASE WHEN ? <> '[]' THEN ? ELSE references_json END, enriched_at=?, updated_at=? WHERE cve_id=?""",
            (info["description"], info["vendor"], info["product"], cv[0] if cv else None, cv[1] if cv else None,
             cv[2] if cv else None, cv[3] if cv else None, jdumps(info["refs"]), jdumps(info["refs"]), now_iso(), now_iso(), cve),
        )
        done += 1
        if cv and cv[0] >= 9.0:
            _rescore_articles_mentioning(conn, [cve])
    return done


# --------------------------------------------------------------------- run
def run_ingest(conn: sqlite3.Connection, force: bool = False, only: list[str] | None = None) -> dict:
    sync_sources(conn)
    ai.reset_run_counter()
    job = conn.execute("INSERT INTO job_runs(job, started_at) VALUES('ingest', ?)", (now_iso(),)).lastrowid
    report: dict = {"sources": {}, "new_articles": [], "new_kev": []}
    srcs = [_source_dict(r) for r in conn.execute("SELECT * FROM sources WHERE enabled=1 ORDER BY id")]
    for src in srcs:
        if only and src["key"] not in only:
            continue
        if not _due(src, force):
            continue
        try:
            if src["kind"] == "kev":
                n, new = ingest_kev(conn, src)
                report["new_kev"] = new
                _mark(conn, src["id"], True, "ok", items=len(new), etag=src.get("etag"), last_modified=src.get("last_modified"))
                report["sources"][src["key"]] = f"{n} KEV entries, {len(new)} new"
            elif src["kind"] == "epss":
                n = ingest_epss(conn, src)
                _mark(conn, src["id"], True, "ok", items=n)
                report["sources"][src["key"]] = f"{n} EPSS scores"
            elif src["kind"] == "cve_enrich":
                n = ingest_cve_enrichment(conn, src)
                _mark(conn, src["id"], True, "ok", items=n)
                report["sources"][src["key"]] = f"{n} CVE records enriched"
            else:
                adapter_cls = ADAPTERS[src["kind"]]
                if adapter_cls is NcscNzAdapter:
                    known = [r[0] for r in conn.execute("SELECT url FROM articles WHERE source_id=?", (src["id"],))]
                    adapter = NcscNzAdapter(known)
                else:
                    adapter = adapter_cls()
                res = adapter.run(src)
                new_ids = []
                if not res.not_modified:
                    max_age = utcnow() - timedelta(days=get_settings().ingest_max_age_days)
                    fresh = [i for i in res.items if not i.published_at or i.published_at >= max_age]
                    fresh.sort(key=lambda i: i.published_at or utcnow(), reverse=True)
                    with tx(conn):
                        for item in fresh[:get_settings().ingest_max_items_per_fetch]:
                            aid = store_item(conn, src, item)
                            if aid:
                                new_ids.append(aid)
                _mark(conn, src["id"], True, "not-modified" if res.not_modified else "ok", items=len(new_ids),
                      etag=res.etag, last_modified=res.last_modified)
                report["new_articles"] += new_ids
                report["sources"][src["key"]] = f"{len(new_ids)} new"
        except Exception as e:  # one failing source must not stop the run
            log.warning("source %s failed: %s", src["key"], e)
            _mark(conn, src["id"], False, "error", error=f"{type(e).__name__}: {e}")
            report["sources"][src["key"]] = f"error: {type(e).__name__}"

    for aid in report["new_articles"]:
        try:
            with tx(conn):
                process_article(conn, aid)
        except Exception:
            log.exception("processing article %s failed", aid)

    conn.execute(
        "UPDATE job_runs SET finished_at=?, status='ok', detail=? WHERE id=?",
        (now_iso(), jdumps({k: v for k, v in report.items() if k != "new_articles"} | {"new_articles": len(report["new_articles"])}), job),
    )
    return report


def summarise_new(conn: sqlite3.Connection, article_ids: list[int], limit: int = 25) -> int:
    """AI summaries for the highest-ranked new articles (no-op without AI)."""
    if not get_settings().ai_enabled or not article_ids:
        return 0
    rows = conn.execute(
        f"""SELECT a.*, s.name AS source_name FROM articles a JOIN sources s ON s.id=a.source_id
            WHERE a.id IN ({','.join('?' * len(article_ids))}) AND a.cluster_id=a.id AND a.severity>=2
            ORDER BY a.score DESC LIMIT ?""",
        [*article_ids, limit],
    ).fetchall()
    n = 0
    for r in rows:
        try:
            out = ai.summarise_article(conn, dict(r))
        except ai.AIUnavailable as e:
            log.info("AI summaries stopped: %s", e)
            break
        apply_ai_entities(conn, dict(r), out)
        n += 1
    return n


def apply_ai_entities(conn, article: dict, out: dict) -> None:
    text = f"{article['title']}\n{article['summary_text']}\n{article['content_text']}"
    added = False
    for e in out.get("entities", []):
        t, v = e.get("type"), (e.get("value") or "").strip()
        if not t or not v or not entities.grounded(v, text):
            continue  # reject anything not literally present in the evidence
        t = {"victim_org": "victim", "country": "country"}.get(t, t)
        norm = v.lower() if t != "cve" else v.lower()
        if t == "cve" and not entities.CVE_RE.fullmatch(v.upper()):
            continue
        eid = _upsert_entity(conn, entities.Entity(t, v, re.sub(r"\s+", " ", norm)))
        conn.execute("INSERT OR IGNORE INTO article_entities(article_id, entity_id, in_title, method) VALUES(?,?,?, 'ai')",
                     (article["id"], eid, int(v.lower() in article["title"].lower())))
        added = True
    if added:
        conn.execute("UPDATE articles SET extracted_at=? WHERE id=?", (now_iso(), article["id"]))


def prune(conn: sqlite3.Connection) -> int:
    days = get_settings().retention_days
    cutoff = iso(utcnow() - timedelta(days=days))
    cur = conn.execute(
        """DELETE FROM articles WHERE retrieved_at < ? AND id NOT IN (SELECT article_id FROM bookmarks)
           AND id NOT IN (SELECT article_id FROM watch_evidence) AND id NOT IN (SELECT origin_article_id FROM watches WHERE origin_article_id IS NOT NULL)""",
        (cutoff,),
    )
    conn.execute("DELETE FROM login_attempts WHERE at < ?", (iso(utcnow() - timedelta(days=2)),))
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_iso(),))
    conn.execute("DELETE FROM job_runs WHERE started_at < ?", (iso(utcnow() - timedelta(days=30)),))
    return cur.rowcount
