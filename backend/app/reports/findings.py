"""Report findings: individual, attributable observations, statistics and recommendations from a report.

Every finding carries a verbatim quote that must appear on the page it cites; nothing is stored otherwise. ATT&CK IDs
are validated against the local ATT&CK data (revoked IDs resolved, unknown IDs dropped) and marked as the publisher's
mapping only when the ID is printed on that page. CVE IDs are kept only when the page states them. The same rules apply
whether a person or the AI proposed the finding.
"""
from __future__ import annotations

import re
import sqlite3
import unicodedata

from ..db import jdumps, jloads, now_iso, tx

CATEGORIES: dict[str, str] = {
    "attacker_behaviour": "Attacker behaviour",
    "threat_actor_activity": "Threat actor activity",
    "initial_access": "Initial access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege escalation",
    "defence_impairment": "Defence impairment",
    "credential_access": "Credential access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral movement",
    "collection": "Collection",
    "command_and_control": "Command and control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "vulnerability_exploitation": "Vulnerability exploitation",
    "identity_compromise": "Identity compromise",
    "supply_chain_compromise": "Supply chain compromise",
    "infrastructure_compromise": "Infrastructure compromise",
    "data_extortion": "Data extortion",
    "control_weakness": "Security control weakness",
    "detection_opportunity": "Detection opportunity",
    "hunting_opportunity": "Threat-hunting opportunity",
    "hardening_recommendation": "Hardening recommendation",
    "ir_recommendation": "Incident response recommendation",
    "readiness_recommendation": "Incident readiness recommendation",
    "statistical_trend": "Statistical trend",
    "research_limitation": "Research limitation",
}

# What kind of evidence the report offers for the finding. Kept separate from review status: an accepted finding is
# analyst-validated, whatever its evidence type.
EVIDENCE: dict[str, str] = {
    "incident_observation": "Documented incident observation",
    "aggregate_statistic": "Aggregated statistic",
    "vendor_conclusion": "Publisher's research conclusion",
    "actor_claim": "Threat actor's unverified claim",
    "vendor_recommendation": "Publisher's recommended defence",
    "user_observation": "Your own observation",
}
ORIGINS = {"analyst", "summary", "ai"}
REVIEW = {"unreviewed", "accepted", "rejected"}
CONFIDENCE = {"high", "medium", "low"}
REGIONS = {"GLOBAL", "NZ", "AU", "APAC", "US", "UK", "EU", "OTHER"}

TID = re.compile(r"^T1\d{3}(?:\.\d{3})?$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", "‑": "-", " ": " "})
MAX_QUOTE = 600


class FindingError(ValueError):
    pass


def norm(s: str) -> str:
    """Comparison form: NFKC, unified quotes and dashes, hyphenated line breaks closed, whitespace collapsed, lower case."""
    s = unicodedata.normalize("NFKC", s or "").translate(QUOTES)
    s = re.sub(r"(\w)-\s+(\w)", r"\1-\2", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def page_texts(conn: sqlite3.Connection, report_id: int, page_no: int) -> list[str]:
    """Normalised forms of a page to verify quotes against: the reading blocks and the raw extracted text."""
    row = conn.execute("SELECT text, blocks FROM report_pages WHERE report_id=? AND page_no=?", (report_id, page_no)).fetchone()
    if not row:
        return []
    out = [norm(row["text"])]
    blocks = jloads(row["blocks"], None)
    if blocks:
        out.append(norm(" ".join(b["text"] for b in blocks)))
    return out


def quote_on_page(conn: sqlite3.Connection, report_id: int, page_no: int, quote: str) -> bool:
    q = norm(quote)
    return len(q) >= 12 and any(q in t for t in page_texts(conn, report_id, page_no))


def techniques(conn: sqlite3.Connection, ids: list[str], page_raw: str) -> list[dict]:
    known = {r[0]: r[1] for r in conn.execute("SELECT attack_id, name FROM attack_techniques")}
    revoked = dict(conn.execute("SELECT old_id, new_id FROM attack_revoked").fetchall())
    out, seen = [], set()
    for raw in ids or []:
        tid = str(raw).strip().upper()
        if not TID.match(tid):
            continue
        cited = tid in page_raw
        tid = revoked.get(tid, tid)
        if tid in known and tid not in seen:
            seen.add(tid)
            out.append({"id": tid, "name": known[tid], "basis": "publisher" if cited else "suggested"})
    return out


def _clean_list(v, cap: int = 12, size: int = 80) -> list[str]:
    out = []
    for x in v or []:
        x = re.sub(r"\s+", " ", str(x)).strip()[:size]
        if x and x.lower() not in {o.lower() for o in out}:
            out.append(x)
    return out[:cap]


def _statistic(v) -> dict | None:
    if not isinstance(v, dict):
        return None
    st = {k: re.sub(r"\s+", " ", str(v.get(k) or "")).strip()[:300] for k in ("value", "population", "period", "definition")}
    return st if st["value"] else None


def build(conn: sqlite3.Connection, report_id: int, data: dict) -> dict:
    """Validate a proposed finding (from a person or the AI). Raises FindingError with a plain reason."""
    try:
        page = int(data.get("page") or data.get("page_no") or 0)
    except (TypeError, ValueError):
        raise FindingError("The page number is not valid") from None
    raw = conn.execute("SELECT text FROM report_pages WHERE report_id=? AND page_no=?", (report_id, page)).fetchone()
    if not raw:
        raise FindingError("That page does not exist in this report")
    quote = re.sub(r"\s+", " ", str(data.get("quote") or "")).strip()
    if len(quote) < 12:
        raise FindingError("The quote is too short to identify a passage")
    if len(quote) > MAX_QUOTE:
        raise FindingError(f"Keep the quote under {MAX_QUOTE} characters; quote the key passage only")
    if not quote_on_page(conn, report_id, page, quote):
        raise FindingError(f"That quote does not appear on page {page}")
    title = re.sub(r"\s+", " ", str(data.get("title") or "")).strip()[:200]
    if len(title) < 3:
        raise FindingError("A short title is required")
    category = data.get("category")
    if category not in CATEGORIES:
        raise FindingError("Choose a category")
    evidence = data.get("evidence_type")
    if evidence not in EVIDENCE:
        raise FindingError("Choose an evidence type")
    page_raw = raw["text"].upper()
    cves = [c.upper() for c in _clean_list(data.get("cves"), 20, 20) if CVE.match(c) and c.upper() in page_raw]
    regions = [r.upper() for r in _clean_list(data.get("regions"), 8, 10) if r.upper() in REGIONS]
    conf = data.get("confidence") if data.get("confidence") in CONFIDENCE else None
    return {
        "page_no": page, "quote": quote, "quote_key": norm(quote), "title": title,
        "summary": re.sub(r"\s+", " ", str(data.get("summary") or "")).strip()[:1200] or None,
        "category": category, "evidence_type": evidence,
        "techniques": techniques(conn, data.get("techniques") or [], page_raw),
        "cves": cves, "actors": _clean_list(data.get("actors")), "technologies": _clean_list(data.get("technologies"), 20),
        "sectors": _clean_list(data.get("sectors"), 10, 60), "regions": regions, "statistic": _statistic(data.get("statistic")),
        "confidence": conf, "notes": (str(data.get("notes") or "").strip()[:4000] or None),
    }


def insert(conn: sqlite3.Connection, report_id: int, f: dict, origin: str, run_id: int | None = None,
           model: str | None = None, prompt_version: int | None = None) -> tuple[int, bool]:
    """Store a built finding. Returns (id, created). An existing finding for the same quote is never overwritten."""
    assert origin in ORIGINS
    dup = conn.execute("SELECT id FROM report_findings WHERE report_id=? AND page_no=? AND quote_key=?",
                       (report_id, f["page_no"], f["quote_key"])).fetchone()
    if dup:
        return dup[0], False
    now = now_iso()
    fid = conn.execute(
        "INSERT INTO report_findings(report_id, page_no, quote, quote_key, title, summary, category, evidence_type, techniques, cves,"
        " actors, technologies, sectors, regions, statistic, confidence, origin, review_status, run_id, model, prompt_version, notes,"
        " created_at, updated_at, reviewed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (report_id, f["page_no"], f["quote"], f["quote_key"], f["title"], f["summary"], f["category"], f["evidence_type"],
         jdumps(f["techniques"]), jdumps(f["cves"]), jdumps(f["actors"]), jdumps(f["technologies"]), jdumps(f["sectors"]),
         jdumps(f["regions"]), jdumps(f["statistic"]) if f["statistic"] else None, f["confidence"], origin,
         # a person adding a finding is reviewing it as they write it
         "accepted" if origin in ("analyst", "summary") else "unreviewed",
         run_id, model, prompt_version, f["notes"], now, now, now if origin != "ai" else None)).lastrowid
    return fid, True


def row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("techniques", "cves", "actors", "technologies", "sectors", "regions"):
        d[k] = jloads(d[k], []) or []
    d["statistic"] = jloads(d["statistic"], {}) if d["statistic"] else None
    d["edited"] = bool(d["edited"])
    d.pop("quote_key", None)
    return d


def suggest(conn: sqlite3.Connection, report_id: int, page: int, quote: str) -> dict:
    """Prefill for a person adding a finding: what the rules can see in the passage. Nothing is invented."""
    from ..intel import entities
    from .reading import STAT, NOT_STAT

    raw = conn.execute("SELECT text FROM report_pages WHERE report_id=? AND page_no=?", (report_id, page)).fetchone()
    text = quote or ""
    ents = entities.extract("", text)
    ids = sorted({m for m in re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", text)})
    is_stat = bool(STAT.search(NOT_STAT.sub(" ", text)))
    return {
        "on_page": bool(raw) and quote_on_page(conn, report_id, page, quote),
        "techniques": techniques(conn, ids, (raw["text"] if raw else "").upper()),
        "cves": sorted({e.value.upper() for e in ents if e.type == "cve"}),
        "actors": sorted({e.value for e in ents if e.type == "actor"}),
        "technologies": sorted({e.value for e in ents if e.type in ("product", "vendor", "malware", "ransomware")}),
        "statistic": is_stat,
    }


def update(conn: sqlite3.Connection, report_id: int, fid: int, data: dict) -> None:
    cur = conn.execute("SELECT * FROM report_findings WHERE id=? AND report_id=?", (fid, report_id)).fetchone()
    if not cur:
        raise LookupError
    now = now_iso()
    if set(data) - {"review_status"}:
        merged = {**row(cur), "page": cur["page_no"], **{k: v for k, v in data.items() if k != "review_status"}}
        if "techniques" in data:
            merged["techniques"] = data["techniques"]
        else:
            merged["techniques"] = [t["id"] for t in row(cur)["techniques"]]
        f = build(conn, report_id, merged)
        clash = conn.execute("SELECT id FROM report_findings WHERE report_id=? AND page_no=? AND quote_key=? AND id<>?",
                             (report_id, f["page_no"], f["quote_key"], fid)).fetchone()
        if clash:
            raise FindingError("Another finding already quotes that passage")
        with tx(conn):
            conn.execute(
                "UPDATE report_findings SET page_no=?, quote=?, quote_key=?, title=?, summary=?, category=?, evidence_type=?, techniques=?,"
                " cves=?, actors=?, technologies=?, sectors=?, regions=?, statistic=?, confidence=?, notes=?, edited=1, updated_at=?,"
                " review_status='accepted', reviewed_at=? WHERE id=?",
                (f["page_no"], f["quote"], f["quote_key"], f["title"], f["summary"], f["category"], f["evidence_type"],
                 jdumps(f["techniques"]), jdumps(f["cves"]), jdumps(f["actors"]), jdumps(f["technologies"]), jdumps(f["sectors"]),
                 jdumps(f["regions"]), jdumps(f["statistic"]) if f["statistic"] else None, f["confidence"], f["notes"], now, now, fid))
    if "review_status" in data:
        if data["review_status"] not in REVIEW:
            raise FindingError("Unknown review status")
        conn.execute("UPDATE report_findings SET review_status=?, reviewed_at=?, updated_at=? WHERE id=?",
                     (data["review_status"], now if data["review_status"] != "unreviewed" else None, now, fid))
