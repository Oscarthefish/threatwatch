"""Threat Watch engine: followed threats, evidence matching and cumulative records.

Matching model (deterministic first, AI optional):
  * identifiers  — strong identity terms (CVE IDs, victim organisation, incident name)
  * aliases      — alternative names for the subject (actor / malware aliases)
  * context      — supporting terms (actor, malware, sector) that boost a score but
                   are never sufficient on their own for an *incident* watch, so
                   unrelated incidents involving the same group are not merged
  * similarity   — token cosine between the article and the watch profile
Scores >= LINK_THRESHOLD with the kind's identity requirement satisfied are linked;
scores in the candidate band go to AI adjudication (if configured) or the user's
review queue. Exclusion terms veto a match.
"""
from __future__ import annotations

import logging
import math
import re
import sqlite3
from collections import Counter
from datetime import timedelta

from ..config import get_settings
from ..db import iso, jdumps, jloads, now_iso, tx, utcnow
from . import ai, entities
from . import text as textutil
from .classify import EXPLOITED, SEVERITY_LABELS
from .notify import notify

log = logging.getLogger(__name__)

KINDS = ["incident", "vulnerability", "actor", "malware", "campaign", "product", "topic"]
NOTIFY_PREFS = ["important", "all", "digest", "silent"]
LINK_THRESHOLD = 0.6
CANDIDATE_THRESHOLD = 0.35
_TOKEN = re.compile(r"[a-z0-9][a-z0-9$\-\.]+")
_STOP = set("the a an and or of to in for on with by from at is are was were be as that this its it new after over".split())


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:80]


def _term_re(term: str) -> re.Pattern:
    return re.compile(rf"(?<![\w-]){re.escape(term.strip())}(?![\w-])", re.I)


def _tokens(text: str) -> Counter:
    return Counter(t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 2)


def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(v * b.get(k, 0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def _dict_aliases(kind: str, name: str) -> tuple[str, list[str]]:
    """Expand a known actor/malware/ransomware name to its canonical form + aliases."""
    tables = []
    if kind in ("actor", "campaign"):
        tables.append(entities.ACTORS)
    if kind in ("malware", "campaign", "actor"):
        tables += [entities.RANSOMWARE, entities.MALWARE]
    for t in tables:
        for canon, aliases in t.items():
            names = [canon, *aliases]
            if name.lower() in (n.lower() for n in names):
                return canon, [n for n in names if n.lower() != canon.lower()]
    return name, []


def _clean_list(v) -> list[str]:
    seen, out = set(), []
    for x in v or []:
        x = str(x).strip()
        if x and x.lower() not in seen and len(x) <= 200:
            seen.add(x.lower())
            out.append(x)
    return out[:50]


# ------------------------------------------------------------------ CRUD
def create_watch(
    conn: sqlite3.Connection,
    *,
    kind: str,
    title: str,
    identifiers: list[str] | None = None,
    aliases: list[str] | None = None,
    context_terms: list[str] | None = None,
    exclude_terms: list[str] | None = None,
    description: str = "",
    notify_pref: str = "important",
    tags: list[str] | None = None,
    notes: str = "",
    origin_article_id: int | None = None,
    backfill_days: int = 30,
) -> tuple[int, bool]:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    if notify_pref not in NOTIFY_PREFS:
        raise ValueError(f"notify_pref must be one of {NOTIFY_PREFS}")
    title = title.strip()[:200]
    identifiers = _clean_list(identifiers)
    aliases = _clean_list(aliases)
    if kind == "vulnerability":
        found = {m.group(0).upper() for m in entities.CVE_RE.finditer(" ".join([title, *identifiers]))}
        identifiers = _clean_list([*sorted(found), *identifiers])
    if kind in ("actor", "malware", "campaign"):
        canon, extra = _dict_aliases(kind, identifiers[0] if identifiers else title)
        if extra:
            if canon not in identifiers:
                identifiers.insert(0, canon)
            aliases = _clean_list([*aliases, *extra])
    if not identifiers and not aliases:
        if kind == "incident":
            raise ValueError("an incident watch needs at least one identifying term (e.g. victim organisation or incident name)")
        identifiers = [title]
    key_basis = identifiers[0] if kind in ("vulnerability", "actor", "malware", "product") else title
    canonical_key = f"{kind}:{_slug(key_basis)}"
    existing = conn.execute("SELECT id FROM watches WHERE canonical_key=?", (canonical_key,)).fetchone()
    if existing:
        return existing[0], False
    now = now_iso()
    wid = conn.execute(
        """INSERT INTO watches(kind, title, canonical_key, description, identifiers, aliases, context_terms, exclude_terms,
               notify_pref, tags, notes, origin_article_id, created_at, last_checked_at, last_updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (kind, title, canonical_key, description[:2000], jdumps(identifiers), jdumps(aliases), jdumps(_clean_list(context_terms)),
         jdumps(_clean_list(exclude_terms)), notify_pref, jdumps(_clean_list(tags)), notes[:10000], origin_article_id, now, now, now),
    ).lastrowid
    timeline(conn, wid, "created", f"Started following: {title}", f"Matching {', '.join([*identifiers, *aliases][:6]) or title}")
    if origin_article_id:
        link_evidence(conn, wid, origin_article_id, 1.0, ["Article you followed from"], linked_by="origin")
    backfill(conn, wid, days=backfill_days)
    update_record(conn, wid, initial=True)
    return wid, True


def timeline(conn, watch_id: int, event_type: str, title: str, detail: str = "", article_id: int | None = None,
             summary_version: int | None = None, at: str | None = None) -> None:
    conn.execute(
        "INSERT INTO watch_timeline(watch_id, occurred_at, event_type, title, detail, article_id, summary_version) VALUES(?,?,?,?,?,?,?)",
        (watch_id, at or now_iso(), event_type, title[:300], detail[:2000], article_id, summary_version),
    )


def link_evidence(conn, watch_id: int, article_id: int, score: float, reasons: list[str], status: str = "linked",
                  linked_by: str = "auto") -> bool:
    cur = conn.execute(
        """INSERT INTO watch_evidence(watch_id, article_id, status, match_score, match_reasons, linked_by, linked_at)
           VALUES(?,?,?,?,?,?,?) ON CONFLICT(watch_id, article_id) DO NOTHING""",
        (watch_id, article_id, status, round(score, 3), jdumps(reasons), linked_by, now_iso()),
    )
    if cur.rowcount and status == "linked":
        a = conn.execute("SELECT a.title, a.published_at, s.name FROM articles a JOIN sources s ON s.id=a.source_id WHERE a.id=?",
                         (article_id,)).fetchone()
        if a:
            timeline(conn, watch_id, "evidence", a["title"], f"{a['name']} · match: {'; '.join(reasons)[:400]}",
                     article_id=article_id, at=a["published_at"])
    return bool(cur.rowcount)


# --------------------------------------------------------------- matching
def _article_row(conn, article_id: int) -> dict | None:
    r = conn.execute(
        "SELECT a.*, s.name AS source_name, s.authority FROM articles a JOIN sources s ON s.id=a.source_id WHERE a.id=?",
        (article_id,),
    ).fetchone()
    return dict(r) if r else None


def score_match(watch: dict, article: dict, article_entities: dict[str, set[str]], profile: Counter | None = None) -> tuple[float, list[str], bool]:
    """Return (score, reasons, identity_requirement_met)."""
    title = article["title"]
    body = f"{article.get('summary_text','')}\n{article.get('content_text','')}"
    reasons: list[str] = []
    for t in jloads(watch["exclude_terms"]):
        if _term_re(t).search(title) or _term_re(t).search(body):
            return 0.0, [f"excluded by term '{t}'"], False

    score = 0.0
    id_hits = 0
    cves = article_entities.get("cve", set())
    for ident in jloads(watch["identifiers"]):
        if entities.CVE_RE.fullmatch(ident.upper()):
            if ident.lower() in cves:
                in_title = ident.lower() in title.lower()
                score += 0.8 if in_title else 0.65  # a CVE ID is a unique identifier: any explicit mention links
                id_hits += 1
                reasons.append(f"{ident.upper()} {'in headline' if in_title else 'mentioned'}")
            continue
        p = _term_re(ident)
        if p.search(title):
            score += 0.6
            id_hits += 1
            reasons.append(f"'{ident}' in headline")
        elif p.search(body):
            score += 0.4
            id_hits += 1
            reasons.append(f"'{ident}' in text")
    alias_hit = False
    for al in jloads(watch["aliases"]):
        p = _term_re(al)
        if p.search(title):
            score += 0.5
            alias_hit = True
            reasons.append(f"alias '{al}' in headline")
            break
        if p.search(body):
            score += 0.3
            alias_hit = True
            reasons.append(f"alias '{al}' in text")
            break
    ctx = 0.0
    for c in jloads(watch["context_terms"]):
        if _term_re(c).search(title) or _term_re(c).search(body):
            ctx += 0.1
            reasons.append(f"context '{c}'")
    score += min(ctx, 0.3)
    if profile is not None:
        sim = _cosine(profile, _tokens(f"{title} {title} {body[:3000]}"))
        if sim > 0.1:
            score += min(0.3, sim * 0.5)
            reasons.append(f"contextual similarity {sim:.2f}")

    kind = watch["kind"]
    if kind == "incident":
        met = id_hits > 0 or alias_hit  # actor/malware context alone never suffices
    elif kind == "vulnerability":
        met = id_hits > 0
    else:
        met = id_hits > 0 or alias_hit
    if id_hits >= 2:
        score += 0.1
    return round(min(score, 2.0), 3), reasons, met


def _profile(conn, watch: dict) -> Counter:
    titles = [r[0] for r in conn.execute(
        "SELECT a.title FROM watch_evidence we JOIN articles a ON a.id=we.article_id WHERE we.watch_id=? AND we.status='linked' ORDER BY we.id DESC LIMIT 15",
        (watch["id"],))]
    return _tokens(" ".join([watch["title"], watch.get("description") or "", *jloads(watch["identifiers"]), *jloads(watch["aliases"]), *titles]))


def _entities_for(conn, article_id: int) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r in conn.execute(
        "SELECT e.type, e.normalized FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=?", (article_id,)
    ):
        out.setdefault(r[0], set()).add(r[1])
    return out


def evaluate(conn, watch: dict, article: dict, use_ai: bool = True) -> str | None:
    """Score one article against one watch and persist the decision. Returns status or None."""
    prior = conn.execute("SELECT status FROM watch_evidence WHERE watch_id=? AND article_id=?", (watch["id"], article["id"])).fetchone()
    if prior and prior["status"] != "candidate":
        return None  # already linked, or rejected by the user (never re-linked automatically)
    ents = _entities_for(conn, article["id"])
    score, reasons, met = score_match(watch, article, ents, _profile(conn, watch))
    if not met or score < CANDIDATE_THRESHOLD:
        return None
    status = "linked" if score >= LINK_THRESHOLD else "candidate"
    needs_ai = status == "candidate" or (watch["kind"] == "incident" and not any("headline" in r for r in reasons))
    if needs_ai and use_ai and get_settings().ai_enabled:
        titles = [r[0] for r in conn.execute(
            "SELECT a.title FROM watch_evidence we JOIN articles a ON a.id=we.article_id WHERE we.watch_id=? AND we.status='linked' ORDER BY we.id DESC LIMIT 8",
            (watch["id"],))]
        try:
            v = ai.adjudicate_match(conn, watch, article, titles)
            if v.get("same_subject") and v.get("confidence") in ("high", "medium"):
                status = "linked"
                reasons.append(f"AI check: same subject ({v['confidence']} confidence). {v.get('reason','')[:200]}")
            elif not v.get("same_subject") and v.get("confidence") == "high":
                status = "rejected"
                reasons.append(f"AI check: different subject. {v.get('reason','')[:200]}")
            else:
                status = "candidate"
                reasons.append(f"AI check inconclusive. {v.get('reason','')[:200]}")
        except ai.AIUnavailable:
            if status == "linked" and watch["kind"] == "incident":
                status = "candidate"  # body-only incident mention: ask the user rather than auto-merge
    elif needs_ai and status == "linked" and watch["kind"] == "incident":
        status = "candidate"
    if prior:  # re-evaluation of a review-queue item (e.g. after rule or term changes)
        if status != "linked":
            return None
        conn.execute("UPDATE watch_evidence SET status='linked', match_score=?, match_reasons=?, linked_at=? WHERE watch_id=? AND article_id=?",
                     (round(score, 3), jdumps(reasons), now_iso(), watch["id"], article["id"]))
        timeline(conn, watch["id"], "evidence", article["title"], f"{article.get('source_name', '')} · now matches: {'; '.join(reasons)[:300]}",
                 article_id=article["id"], at=article["published_at"])
        return "linked"
    link_evidence(conn, watch["id"], article["id"], score, reasons, status=status)
    return status


def backfill(conn, watch_id: int, days: int = 30, limit: int = 300) -> int:
    w = dict(conn.execute("SELECT * FROM watches WHERE id=?", (watch_id,)).fetchone())
    terms = [*jloads(w["identifiers"]), *jloads(w["aliases"])]
    if not terms:
        return 0
    q = " OR ".join('"' + t.replace('"', "") + '"' for t in terms if t.strip())
    cutoff = iso(utcnow() - timedelta(days=days))
    try:
        ids = [r[0] for r in conn.execute(
            "SELECT a.id FROM articles_fts f JOIN articles a ON a.id=f.rowid WHERE articles_fts MATCH ? AND a.published_at>=? ORDER BY a.published_at LIMIT ?",
            (q, cutoff, limit))]
    except sqlite3.OperationalError:
        ids = []
    n = 0
    for aid in ids:
        art = _article_row(conn, aid)
        if art and evaluate(conn, w, art, use_ai=False) == "linked":
            n += 1
    conn.execute("UPDATE watches SET last_checked_at=? WHERE id=?", (now_iso(), watch_id))
    return n


def match_new_articles(conn: sqlite3.Connection, article_ids: list[int]) -> dict[int, int]:
    """Check newly ingested articles against all active watches. Returns {watch_id: new_linked_count}."""
    watches = [dict(r) for r in conn.execute("SELECT * FROM watches WHERE status='active'")]
    result: dict[int, int] = {}
    if not watches:
        return result
    for aid in article_ids:
        art = _article_row(conn, aid)
        if not art:
            continue
        for w in watches:
            st = evaluate(conn, w, art)
            if st == "linked":
                result[w["id"]] = result.get(w["id"], 0) + 1
        conn.execute("UPDATE articles SET matched_at=? WHERE id=?", (now_iso(), aid))
    now = now_iso()
    for w in watches:
        conn.execute("UPDATE watches SET last_checked_at=? WHERE id=?", (now, w["id"]))
    for wid in result:
        try:
            update_record(conn, wid)
        except Exception:
            log.exception("updating watch %s failed", wid)
    return result


# ------------------------------------------------------- cumulative record
def latest_summary(conn, watch_id: int) -> dict | None:
    r = conn.execute("SELECT * FROM watch_summaries WHERE watch_id=? ORDER BY version DESC LIMIT 1", (watch_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    for k in ("confirmed", "uncertain", "changes", "iocs", "techniques", "detection", "evidence_ids"):
        d[k] = jloads(d[k])
    return d


def _evidence_rows(conn, watch_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        """SELECT we.*, a.title, a.url, a.published_at, a.summary_text, a.content_text, a.severity, a.tags, a.cluster_id,
                  a.confidence, s.name AS source_name, s.authority, a.id AS id
           FROM watch_evidence we JOIN articles a ON a.id=we.article_id JOIN sources s ON s.id=a.source_id
           WHERE we.watch_id=? AND we.status='linked' ORDER BY a.published_at""",
        (watch_id,),
    )]


def _collect_structured(conn, evidence: list[dict]) -> tuple[list[dict], list[dict], dict[int, set[tuple[str, str]]]]:
    """IOCs and ATT&CK techniques come from deterministic extraction only (never generated)."""
    iocs: dict[tuple[str, str], list[int]] = {}
    techs: dict[str, dict] = {}
    per_article: dict[int, set[tuple[str, str]]] = {}
    for e in evidence:
        ents = conn.execute(
            "SELECT e.type, e.value, ae.method FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=?",
            (e["article_id"],)).fetchall()
        per_article[e["article_id"]] = {(r["type"], r["value"].lower()) for r in ents}
        for r in ents:
            if r["type"] in entities.IOC_TYPES:
                iocs.setdefault((r["type"], r["value"]), []).append(e["article_id"])
            elif r["type"] in ("attack_technique", "attack_technique_inferred"):
                tid = r["value"].upper()
                t = techs.setdefault(tid, {"id": tid, "name": entities.technique_name(tid), "article_ids": [], "inferred": True})
                t["article_ids"].append(e["article_id"])
                if r["type"] == "attack_technique":
                    t["inferred"] = False
    ioc_list = [{"type": t, "value": v, "article_ids": sorted(set(ids))} for (t, v), ids in sorted(iocs.items())][:200]
    return ioc_list, sorted(techs.values(), key=lambda x: (x["inferred"], x["id"])), per_article


def _fmt_entities(new_ents: set[tuple[str, str]]) -> str:
    vals = sorted({(v.upper() if t == "cve" else v) for t, v in new_ents})
    shown = ", ".join(vals[:3])
    return f"{shown} and {len(vals) - 3} more" if len(vals) > 3 else shown


_KEV_BULLETIN = re.compile(r"\badds?\b.{0,40}\bknown exploited vulnerabilit", re.I)
# The same test in SQL, for paged feeds: CISA catalogue announcements ("CISA Adds Six Known Exploited Vulnerabilities to Catalog")
KEV_BULLETIN_SQL = "lower(a.title) LIKE '%add%known exploited vulnerabilit%'"
_CHANGE_TYPES = ("cve", "actor", "ransomware", "malware", "victim", *entities.IOC_TYPES)


def watch_terms(w: dict) -> list[str]:
    """The names that identify a followed subject: its identifiers and aliases."""
    return [t for t in [*jloads(w["identifiers"]), *jloads(w["aliases"])] if t and t.strip()]


def _is_broad(e: dict, ents: set[tuple[str, str]]) -> bool:
    """Bulletins, catalogue updates and roundups cover many unrelated subjects at once."""
    if "roundup" in set(jloads(e["tags"])) or _KEV_BULLETIN.search(e["title"] or ""):
        return True
    cves = sum(1 for t, _ in ents if t == "cve")
    named = sum(1 for t, _ in ents if t in ("actor", "ransomware", "malware"))
    return cves >= 4 or named >= 4


def _heuristic_assess(e: dict, terms: list[str], known_clusters: set[int], known_ents: set[tuple[str, str]],
                      ents: set[tuple[str, str]], known_sources: set[str]) -> tuple[str, str]:
    """Decide what a newly linked report adds to a followed subject.

    Only facts stated alongside the subject count. In a broad bulletin, names that
    appear elsewhere in the report (other CVEs, other actors) are not changes to
    this subject, and the assessment says so.
    """
    tags = set(jloads(e["tags"]))
    body = f"{e['title']}\n{e.get('summary_text') or ''}\n{e.get('content_text') or ''}"
    about = textutil.near_text(body, terms) if terms else ""
    broad = _is_broad(e, ents)
    if "roundup" in tags:
        return "minor", "Mentioned in a news roundup or podcast; read it for context."
    own = {t.lower() for t in terms}
    candidates = {x for x in ents - known_ents if x[0] in _CHANGE_TYPES and x[1].lower() not in own}
    scope = (about or ("" if broad else body)).lower()
    relevant = {x for x in candidates if x[1].lower() in scope}
    unrelated = len(candidates) - len(relevant)
    if e["cluster_id"] in known_clusters and not relevant:
        return "duplicate", "Same story as a report already on record."

    reasons: list[str] = []
    important = False
    kev_listed = bool(_KEV_BULLETIN.search(e["title"] or "") and about)
    if kev_listed:
        reasons.append("Added to the CISA KEV catalogue, so exploitation is confirmed")
        important = e["source_name"] not in known_sources
    elif (EXPLOITED.search(about) if (broad or about) else tags & {"exploited", "zero-day"}):
        reasons.append("Reports exploitation")
        important = True
    if relevant:
        reasons.append(f"Names {_fmt_entities(relevant)} in connection with it")
    if e["authority"] >= 3 and e["source_name"] not in known_sources and not kev_listed:
        reasons.append(f"First official source ({e['source_name']})")
        important = True
    if not reasons and e["source_name"] not in known_sources:
        reasons.append(f"Additional independent reporting from {e['source_name']}")
    note = ""
    if broad and unrelated:
        note = f" The report also covers {unrelated} other item{'s' if unrelated != 1 else ''}, not counted as changes to this one."
    joined = ". ".join(reasons) + "." if reasons else ""
    if important or (e["severity"] >= 3 and reasons and not broad and relevant):
        return "important", joined + note
    if reasons and (relevant or e["source_name"] not in known_sources):
        return "meaningful", joined + note
    return "minor", (joined + " " if joined else "") + ("Only a passing mention in a broad report." if broad else "No new names, indicators or sources.") + note


def update_record(conn: sqlite3.Connection, watch_id: int, initial: bool = False, force_ai: bool = False) -> dict | None:
    w = dict(conn.execute("SELECT * FROM watches WHERE id=?", (watch_id,)).fetchone())
    evidence = _evidence_rows(conn, watch_id)
    new = [e for e in evidence if not e["processed_at"]]
    prev = latest_summary(conn, watch_id)
    if not new and prev and not force_ai:
        return prev
    old = [e for e in evidence if e["processed_at"]]
    allowed = {e["article_id"] for e in evidence}
    iocs, techniques, per_article = _collect_structured(conn, evidence)

    # Heuristic significance (always computed; AI may refine it)
    known_clusters = {e["cluster_id"] for e in old}
    known_ents: set[tuple[str, str]] = set().union(*(per_article.get(e["article_id"], set()) for e in old)) if old else set()
    known_sources = {e["source_name"] for e in old}
    assess: dict[int, tuple[str, str]] = {}
    for e in new:
        sig, why = _heuristic_assess(e, watch_terms(w), known_clusters, known_ents, per_article.get(e["article_id"], set()), known_sources)
        if initial and not old:
            sig, why = ("meaningful", "Initial evidence when the watch was created.")
        assess[e["article_id"]] = (sig, why)
        known_clusters.add(e["cluster_id"])
        known_ents |= per_article.get(e["article_id"], set())
        known_sources.add(e["source_name"])

    method, model = "heuristic", None
    summary_text = ""
    confirmed: list[dict] = []
    uncertain: list[dict] = []
    changes: list[dict] = []
    detection: list[dict] = []
    if get_settings().ai_enabled and evidence:
        try:
            out = ai.update_watch_summary(conn, w, prev, old if prev else [], new if prev else evidence)
            confirmed = ai.filter_claims(out.get("confirmed"), allowed)
            uncertain = ai.filter_claims(out.get("uncertain"), allowed)
            changes = ai.filter_claims(out.get("changes"), allowed)
            detection = ai.filter_claims(out.get("detection"), allowed)
            summary_text = _strip_invalid_cites(out.get("summary", ""), allowed)
            for t in out.get("techniques") or []:
                tid = (t.get("id") or "").upper()
                ids = ai.valid_ids(t.get("evidence_ids", []), allowed)
                if entities.TECH_RE.fullmatch(tid) and ids and not any(x["id"] == tid for x in techniques):
                    techniques.append({"id": tid, "name": entities.technique_name(tid), "article_ids": ids, "inferred": True, "ai": True})
            for a in out.get("new_evidence_assessment") or []:
                ids = ai.valid_ids([a.get("evidence_id", "")], {e["article_id"] for e in new})
                if ids and a.get("significance") in ("important", "meaningful", "minor", "duplicate"):
                    assess[ids[0]] = (a["significance"], (a.get("reason") or "")[:500] + " (AI assessment)")
            method, model = "ai", get_settings().ai_model
        except ai.AIUnavailable as exc:
            log.info("watch %s: AI unavailable (%s); using heuristic record", watch_id, exc)

    if method == "heuristic":
        summary_text, confirmed, uncertain, detection = _heuristic_record(w, evidence)
        for e in new:
            sig, why = assess[e["article_id"]]
            if sig in ("important", "meaningful"):
                changes.append({"claim": f"{e['title']} ({e['source_name']}). {why}", "article_ids": [e["article_id"]]})

    version = (prev["version"] + 1) if prev else 1
    now = now_iso()
    with _maybe_tx(conn):
        conn.execute(
            """INSERT INTO watch_summaries(watch_id, version, created_at, method, model, summary, confirmed, uncertain, changes,
                   iocs, techniques, detection, evidence_ids) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (watch_id, version, now, method, model, summary_text, jdumps(confirmed), jdumps(uncertain),
             jdumps([{"change": c["claim"], "article_ids": c["article_ids"]} for c in changes]),
             jdumps(iocs), jdumps(techniques), jdumps(detection), jdumps(sorted(allowed))),
        )
        for e in new:
            sig, why = assess[e["article_id"]]
            conn.execute("UPDATE watch_evidence SET significance=?, assessment=?, processed_at=? WHERE id=?", (sig, why, now, e["id"]))
        if changes or version == 1:
            timeline(conn, watch_id, "summary", f"Intelligence record updated (v{version}, {method})",
                     "; ".join(c["claim"] for c in changes)[:1500] if changes else "Initial record", summary_version=version)
        conn.execute("UPDATE watches SET last_updated_at=? WHERE id=?", (now, watch_id))

    if not initial:
        _notify_for(conn, w, new, assess, version)
    return latest_summary(conn, watch_id)


class _NullCtx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _maybe_tx(conn):
    return _NullCtx() if conn.in_transaction else tx(conn)


_CITE = re.compile(r"\[E(\d+)\]")


def _strip_invalid_cites(text: str, allowed: set[int]) -> str:
    return _CITE.sub(lambda m: m.group(0) if int(m.group(1)) in allowed else "", text or "").strip()


def _heuristic_record(w: dict, evidence: list[dict]) -> tuple[str, list[dict], list[dict], list[dict]]:
    if not evidence:
        return (f"No reporting has been linked to “{w['title']}” yet. Threat Watch will keep checking new intelligence.", [], [], [])
    pubs = sorted({e["source_name"] for e in evidence})
    first, last = evidence[0]["published_at"][:10], evidence[-1]["published_at"][:10]
    latest = evidence[-3:][::-1]
    lines = [f"{len(evidence)} linked report(s) from {len(pubs)} publisher(s) ({', '.join(pubs[:6])}) between {first} and {last}.",
             "Most recent: " + " | ".join(f"{e['title']} [E{e['article_id']}]" for e in latest)]
    lines.append("AI synthesis is not configured; claims below are the publishers' own headlines grouped by source confidence.")
    confirmed, uncertain, detection = [], [], []
    for e in evidence:
        claim = {"claim": e["title"], "article_ids": [e["article_id"]]}
        if e["authority"] >= 3 or e["confidence"] in ("corroborated", "multi-source", "official"):
            confirmed.append(claim)
        else:
            uncertain.append(claim | {"note": "single-source reporting"})
        if "detection" in jloads(e["tags"]):
            detection.append({"claim": f"See detection/hunting content: {e['title']}", "article_ids": [e["article_id"]]})
    return "\n".join(lines), confirmed[-25:], uncertain[-25:], detection[-10:]


def _matched_on(e: dict) -> str:
    """Short plain statement of why the report was linked, for notification text."""
    rs = [r for r in jloads(e.get("match_reasons") or "[]") if not r.startswith(("contextual similarity", "AI check"))]
    if not rs:
        return ""
    r = rs[0].replace("'", "")
    return f" Matched because {r}."


def _notify_for(conn, w: dict, new: list[dict], assess: dict[int, tuple[str, str]], version: int) -> None:
    pref = w["notify_pref"]
    if pref == "silent":
        return
    for e in new:
        sig, why = assess.get(e["article_id"], ("minor", ""))
        if sig == "duplicate" or sig == "minor":
            continue
        if pref == "important" and sig != "important":
            continue
        key = f"watch:{w['id']}:cluster:{e['cluster_id']}"
        notify(
            conn,
            kind="watch_important" if sig == "important" else "watch_update",
            title=f"{w['title']}: {'important update' if sig == 'important' else 'new development'}",
            body=f"{e['title']} ({e['source_name']}). {why}{_matched_on(e)}"[:500],
            link=f"/watch/{w['id']}",
            watch_id=w["id"],
            article_id=e["article_id"],
            dedupe_key=key,
            digest=pref == "digest",
        )


# -------------------------------------------------------------- suggestions
def suggest_from_article(conn, article_id: int) -> list[dict]:
    art = _article_row(conn, article_id)
    if not art:
        return []
    ents = conn.execute(
        "SELECT e.type, e.value FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=? ORDER BY ae.in_title DESC",
        (article_id,)).fetchall()
    out: list[dict] = []
    victims = [r["value"] for r in ents if r["type"] == "victim"]
    actors = [r["value"] for r in ents if r["type"] == "actor"]
    fams = [r["value"] for r in ents if r["type"] in ("ransomware", "malware")]
    out.append({
        "kind": "incident",
        "title": art["title"][:160],
        "identifiers": victims[:3],
        "aliases": [],
        "context_terms": [*actors[:2], *fams[:2]],
        "hint": "Add the victim organisation or incident name as identifiers. Actor/malware are context only, "
                "so unrelated incidents by the same group are not merged.",
    })
    for r in ents:
        if r["type"] == "cve":
            out.append({"kind": "vulnerability", "title": r["value"], "identifiers": [r["value"]], "aliases": [], "context_terms": []})
    for a in actors[:3]:
        canon, al = _dict_aliases("actor", a)
        out.append({"kind": "actor", "title": canon, "identifiers": [canon], "aliases": al, "context_terms": []})
    for f in fams[:3]:
        canon, al = _dict_aliases("malware", f)
        out.append({"kind": "malware", "title": canon, "identifiers": [canon], "aliases": al, "context_terms": []})
    for o in out:
        k = f"{o['kind']}:{_slug(o['identifiers'][0] if o['kind'] in ('vulnerability', 'actor', 'malware') and o['identifiers'] else o['title'])}"
        row = conn.execute("SELECT id FROM watches WHERE canonical_key=?", (k,)).fetchone()
        o["existing_watch_id"] = row[0] if row else None
    return out


MATCH_RULES_VERSION = 2


def reevaluate_all(conn: sqlite3.Connection) -> int:
    """Re-check active watches once after matching rules change (review-queue items can be upgraded; rejections stay)."""
    from ..db import get_setting, set_setting

    if get_setting(conn, "match_rules_version", 1) >= MATCH_RULES_VERSION:
        return 0
    ids = [r[0] for r in conn.execute("SELECT id FROM watches WHERE status='active'")]
    for wid in ids:
        try:
            backfill(conn, wid, days=60)
            update_record(conn, wid)
        except Exception:
            log.exception("re-evaluating watch %s failed", wid)
    set_setting(conn, "match_rules_version", MATCH_RULES_VERSION)
    return len(ids)


ASSESS_RULES_VERSION = 2


def reassess_all(conn: sqlite3.Connection) -> int:
    """Recompute heuristic assessments for stored evidence after the relevance rules change.

    Evidence is replayed in publication order so "new" still means new at the time.
    AI assessments are left alone. Notification text and the latest heuristic
    record's change list are corrected to match, and the timeline records that
    this happened.
    """
    from ..db import get_setting, set_setting

    if get_setting(conn, "assess_rules_version", 1) >= ASSESS_RULES_VERSION:
        return 0
    changed_total = 0
    for wrow in conn.execute("SELECT * FROM watches").fetchall():
        w = dict(wrow)
        evidence = [e for e in _evidence_rows(conn, w["id"]) if e["processed_at"]]
        if not evidence:
            continue
        _, _, per_article = _collect_structured(conn, evidence)
        known_clusters: set[int] = set()
        known_ents: set[tuple[str, str]] = set()
        known_sources: set[str] = set()
        changed: dict[int, tuple[str, str]] = {}
        for i, e in enumerate(evidence):
            ents = per_article.get(e["article_id"], set())
            if i == 0 and e["linked_by"] == "origin":
                sig, why = e["significance"], e["assessment"]
            elif (e["assessment"] or "").endswith("(AI assessment)"):
                sig, why = e["significance"], e["assessment"]
            else:
                sig, why = _heuristic_assess(e, watch_terms(w), known_clusters, known_ents, ents, known_sources)
                if i == 0 and e["assessment"] == "Initial evidence when the watch was created.":
                    sig, why = e["significance"], e["assessment"]
            if (sig, why) != (e["significance"], e["assessment"]):
                conn.execute("UPDATE watch_evidence SET significance=?, assessment=? WHERE id=?", (sig, why, e["id"]))
                changed[e["article_id"]] = (sig, why)
                conn.execute("UPDATE notifications SET body=? WHERE watch_id=? AND article_id=?",
                             (f"{e['title']} ({e['source_name']}). {why}{_matched_on(e)}"[:1000], w["id"], e["article_id"]))
            known_clusters.add(e["cluster_id"])
            known_ents |= ents
            known_sources.add(e["source_name"])
        if not changed:
            continue
        changed_total += len(changed)
        last = conn.execute("SELECT id, method, changes FROM watch_summaries WHERE watch_id=? ORDER BY version DESC LIMIT 1", (w["id"],)).fetchone()
        if last and last["method"] == "heuristic":
            titles = {e["article_id"]: e for e in evidence}
            fixed = []
            for c in jloads(last["changes"]):
                ids = c.get("article_ids") or []
                if ids and ids[0] in changed:
                    sig, why = changed[ids[0]]
                    if sig not in ("important", "meaningful"):
                        continue
                    e = titles[ids[0]]
                    c = {"change": f"{e['title']} ({e['source_name']}). {why}", "article_ids": ids}
                fixed.append(c)
            conn.execute("UPDATE watch_summaries SET changes=? WHERE id=?", (jdumps(fixed), last["id"]))
        timeline(conn, w["id"], "summary", "Assessments recalculated",
                 f"{len(changed)} linked report(s) re-assessed with stricter relevance rules: only facts stated alongside this subject count as changes.")
    set_setting(conn, "assess_rules_version", ASSESS_RULES_VERSION)
    return changed_total
