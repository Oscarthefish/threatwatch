"""Threat landscape assessment: deterministic, explainable, built only from data Threat Watch already holds.

Inputs
  * the profile (sector, countries, technologies, telemetry, controls) with each fact's provenance
  * collected reporting in the lookback window (roundups excluded, same-story articles counted once)
  * CISA KEV entries matched to technologies the analyst listed
  * ransomware leak-site claims (unverified by definition) for the sector and countries
  * MITRE ATT&CK relationships for groups named in the evidence

Rules that keep the output honest
  * A finding is "observed" only with dated evidence tied to the sector, country, organisation or a listed technology.
  * Without such evidence a threat is a "plausible scenario": it never claims an active campaign and is capped at P3.
  * CVSS is never treated as evidence of exploitation; EPSS is shown as FIRST's estimate, not a compromise probability.
  * A technology is applicable only when the analyst listed it; versions and exposure stay "unknown" unless recorded.
  * Unknown controls are reported as unknown, never as missing.
  * Every priority lists the factors and points that produced it.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from ..db import get_setting, jdumps, jloads, now_iso, parse_iso, utcnow
from . import kb

METHOD_VERSION = 1
DEFAULT_OPTIONS = {"lookback_days": 90, "use_claims": True, "excluded_sources": [], "platforms": ["splunk", "sentinel", "xdr"]}
PRIORITY = [(6, "P1", "Act now"), (4, "P2", "High"), (2, "P3", "Monitor"), (-99, "P4", "Low")]
RECENT_DAYS = 30
STALE_DAYS = 45
ROUNDUP = "roundup"
TAG_CATEGORY = {"ransomware": "ransomware", "phishing": "phishing"}
GENERIC = {"server", "servers", "software", "products", "product", "multiple", "and", "the", "for", "edition", "enterprise",
           "community", "platform", "suite", "cloud", "management", "manager", "client", "web", "service", "services", "system"}
PRODUCT_ALIASES = {  # analyst wording -> words CISA KEV uses for the same product line
    "fortigate": ["fortios", "fortiproxy"], "netscaler": ["netscaler", "adc", "gateway"], "citrix adc": ["netscaler"],
    "globalprotect": ["pan-os"], "palo alto firewall": ["pan-os"], "asa": ["adaptive", "firepower"],
    "exchange": ["exchange"], "sharepoint": ["sharepoint"], "ivanti vpn": ["connect", "secure"], "pulse secure": ["connect", "secure"],
}


# ------------------------------------------------------------------ helpers
def _norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9.+-]+", " ", (s or "").lower()).strip()


def _tokens(s: str) -> set[str]:
    return set(_norm(s).split())


def _name_patterns(names: list[str]) -> list[re.Pattern]:
    out = []
    for n in names:
        n = (n or "").strip()
        if len(n) < 4:
            continue
        variants = {n, n.replace(" & ", " and "), n.replace(" and ", " & ")}
        for v in variants:
            esc = re.escape(v).replace(r"\ ", r"\s+")
            out.append(re.compile(rf"(?<![\w-]){esc}(?![\w-])", re.I))
    return out


def _days_ago(iso: str | None, now: datetime) -> int:
    """Whole days since ``iso``; 9999 when unknown (so unknown dates never count as recent)."""
    d = parse_iso(iso)
    return 9999 if d is None else max(0, (now - d).days)


def priority_of(points: int, cap: str | None = None) -> dict:
    for floor, code, label in PRIORITY:
        if points >= floor:
            if cap and int(code[1]) < int(cap[1]):
                code, label = cap, next(lbl for _, c, lbl in PRIORITY if c == cap)
            return {"code": code, "label": label, "points": points}
    return {"code": "P4", "label": "Low", "points": points}


class Attack:
    """Current ATT&CK names, tactics and relationships, with revoked IDs resolved."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.tech = {r["attack_id"]: {"name": r["name"], "tactics": jloads(r["tactics"])}
                     for r in conn.execute("SELECT attack_id, name, tactics FROM attack_techniques")}
        self.revoked = dict(conn.execute("SELECT old_id, new_id FROM attack_revoked").fetchall())
        self.version = get_setting(conn, "attack_version")

    @property
    def loaded(self) -> bool:
        return bool(self.tech)

    def resolve(self, tid: str) -> tuple[str, str | None]:
        """Returns (current id, note)."""
        tid = tid.upper()
        if tid in self.tech:
            return tid, None
        if tid in self.revoked:
            return self.revoked[tid], f"{tid} was replaced by {self.revoked[tid]} in ATT&CK"
        parent = tid.split(".")[0]
        if "." in tid and parent in self.tech:
            return parent, f"{tid} is not in ATT&CK {self.version or ''}; shown as {parent}".replace("  ", " ")
        return tid, "not found in the loaded ATT&CK release"

    def group_techniques(self, names: list[str]) -> dict[str, dict]:
        from ..ingest.attack import lookup
        out: dict[str, dict] = {}
        for n in names:
            g = lookup(self.conn, [n], "group")
            if not g:
                continue
            for (dst,) in self.conn.execute("SELECT dst FROM attack_links WHERE src=? AND rel='uses'", (g["attack_id"],)):
                out.setdefault(dst, {"groups": []})["groups"].append({"name": g["name"], "attack_id": g["attack_id"], "url": g["url"]})
        return out


# ------------------------------------------------------------------ profile
def load_profile(conn: sqlite3.Connection, pid: int) -> dict | None:
    row = conn.execute("SELECT * FROM profiles WHERE id=?", (pid,)).fetchone()
    if not row:
        return None
    p = dict(row)
    p["countries"] = jloads(p["countries"])
    p["match_terms"] = jloads(p["match_terms"])
    p["options"] = {**DEFAULT_OPTIONS, **jloads(p["options"], {})}
    p["facts"] = [dict(r) for r in conn.execute("SELECT * FROM profile_facts WHERE profile_id=? ORDER BY category, id", (pid,))]
    return p


def _facts(p: dict, category: str) -> list[dict]:
    return [f for f in p["facts"] if f["category"] == category]


# ------------------------------------------------------------------ evidence gathering
def _articles(conn: sqlite3.Connection, cutoff: str, excluded: list[str]) -> list[dict]:
    rows = conn.execute(
        """SELECT a.id, a.title, a.summary_text, substr(a.content_text, 1, 4000) AS body, a.url, a.published_at, a.retrieved_at,
                  a.severity, a.tags, COALESCE(a.cluster_id, a.id) AS story, a.region, s.name AS source, s.key AS source_key,
                  s.authority, s.region AS source_region
           FROM articles a JOIN sources s ON s.id = a.source_id
           WHERE a.published_at >= ? ORDER BY a.published_at DESC""", (cutoff,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tags"] = jloads(d["tags"])
        if ROUNDUP in d["tags"] or d["source_key"] in excluded:
            continue
        d["head"] = f"{d['title']}\n{d['summary_text']}"
        d["text"] = f"{d['head']}\n{d['body'] or ''}"
        out.append(d)
    return out


def _entities(conn: sqlite3.Connection, ids: list[int]) -> dict[int, list[tuple[str, str]]]:
    out: dict[int, list[tuple[str, str]]] = defaultdict(list)
    if not ids:
        return out
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for r in conn.execute(
                f"""SELECT ae.article_id, e.type, e.value FROM article_entities ae JOIN entities e ON e.id = ae.entity_id
                    WHERE ae.article_id IN ({','.join('?' * len(chunk))})""", chunk):
            out[r[0]].append((r[1], r[2]))
    return out


ADVISORY_SOURCES = {"cisa-advisories"}
_NEGATED = re.compile(r"\b(?:no|not|without|never)\b[^.;:]*", re.I)


def _affirmative(text: str) -> str:
    """Drop negated clauses ("no evidence of ransomware", "no impact to the supply chain") before matching a fact."""
    return _NEGATED.sub(" ", text)


def _threat_evidence(a: dict) -> bool:
    """Vulnerability advisories describe weaknesses, not threat activity: they count only when exploitation is reported.
    Court and policing follow-ups (arrests, extraditions, sentencing) describe past cases, not current targeting."""
    from ..intel.classify import LEGAL
    if LEGAL.search(a["title"]):
        return False
    return a["source_key"] not in ADVISORY_SOURCES or "exploited" in a["tags"]


def _ev(a: dict, why: list[str]) -> dict:
    return {"article_id": a["id"], "title": a["title"], "url": a["url"], "source": a["source"], "authority": a["authority"],
            "published_at": a["published_at"], "retrieved_at": a["retrieved_at"], "severity": a["severity"], "matched": why}


def _dedupe_stories(items: list[tuple[dict, list[str]]], limit: int = 8) -> list[dict]:
    seen, out = set(), []
    for a, why in items:
        if a["story"] in seen:
            continue
        seen.add(a["story"])
        out.append(_ev(a, why))
    return out[:limit]


def _confidence(evidence: list[dict], claims: int = 0, facts: int = 0) -> dict:
    sources = {e["source"] for e in evidence}
    if facts and not evidence:
        return {"level": "medium", "why": "public sources recorded on the profile"}
    gov = any(e["authority"] >= 3 for e in evidence)
    if len(sources) >= 2 or gov:
        level, why = "high", f"{len(sources)} independent source{'s' if len(sources) != 1 else ''}" + (" including a government source" if gov else "")
    elif evidence:
        level, why = "medium", "single source"
    elif claims:
        level, why = "medium", "leak-site claims only (the groups' own statements, unverified)"
    else:
        level, why = "none", "no direct evidence; scenario based on the profile"
    return {"level": level, "why": why}


def _claims(conn, sector_label: str | None, countries: list[str], cutoff: datetime, now: datetime) -> dict | None:
    if not sector_label:
        return None
    days = (now - cutoff).days
    prev_cut = cutoff - timedelta(days=days)
    rows = conn.execute("SELECT group_name, country, discovered_at, victim FROM ransomware_claims WHERE sector=? AND discovered_at >= ?",
                        (sector_label, prev_cut.strftime("%Y-%m-%dT%H:%M:%S"))).fetchall()
    cur = [r for r in rows if r["discovered_at"] >= cutoff.strftime("%Y-%m-%dT%H:%M:%S")]
    prev = len(rows) - len(cur)
    recent = [r for r in cur if (now - parse_iso(r["discovered_at"])).days <= RECENT_DAYS]
    local = [r for r in cur if r["country"] in countries]
    first = conn.execute("SELECT MIN(discovered_at) FROM ransomware_claims").fetchone()[0]
    return {"sector": sector_label, "count": len(cur), "previous": prev, "recent_30d": len(recent),
            "previous_complete": bool(first and first <= prev_cut.strftime("%Y-%m-%dT%H:%M:%S")),
            "top_groups": Counter(r["group_name"] for r in cur).most_common(5),
            "in_countries": len(local), "countries": countries,
            "local_groups": Counter(r["group_name"] for r in local).most_common(3),
            "latest": max((r["discovered_at"] for r in cur), default=None)}


def _tech_match(value: str, vendor: str | None, product: str | None) -> str | None:
    v_tokens = _tokens(value)
    vend = _norm(vendor)
    if not vend or not all(t in v_tokens for t in vend.split()):
        return None
    prod = _norm(product)
    if prod in ("", "multiple products"):
        return "vendor"
    wanted = {t for t in prod.split() if len(t) >= 3 and t not in GENERIC and t not in vend.split()}
    lv = _norm(value)
    for alias, words in PRODUCT_ALIASES.items():
        if alias in lv:
            if any(w in prod for w in words):
                return "product"
    if wanted & v_tokens:
        return "product"
    return None


# ------------------------------------------------------------------ assessment
def assess(conn: sqlite3.Connection, pid: int, now: datetime | None = None) -> dict:
    p = load_profile(conn, pid)
    if not p:
        raise LookupError("profile not found")
    now = now or utcnow()
    opts = p["options"]
    days = int(opts.get("lookback_days") or 90)
    cutoff = now - timedelta(days=days)
    att = Attack(conn)
    sector = kb.SECTORS.get(p["sector"] or "")
    sector_re = re.compile(rf"\b(?:{sector['terms']})\b", re.I) if sector else None
    country_res = {c: re.compile(kb.COUNTRY_TERMS[c], re.I) for c in p["countries"] if c in kb.COUNTRY_TERMS}
    org_res = _name_patterns([p["name"], *p["match_terms"]]) if p["kind"] == "organisation" else []
    techs = [f for f in _facts(p, "tech") if f["provenance"] != "unknown"]  # an open question is not listed technology
    tech_types = {f["subtype"] for f in techs}
    telemetry = {f["subtype"]: f for f in _facts(p, "telemetry")}
    controls = {f["subtype"]: f for f in _facts(p, "control") if f["subtype"] in kb.HARDENING}

    arts = _articles(conn, cutoff.strftime("%Y-%m-%dT%H:%M:%S"), opts.get("excluded_sources") or [])
    ents = _entities(conn, [a["id"] for a in arts])
    findings: list[dict] = []
    sources_used = sorted({a["source"] for a in arts})

    # -- 1. reporting that names the organisation
    org_hits = []
    for a in arts:
        hit = next((m.group(0) for r in org_res if (m := r.search(a["text"]))), None)
        if hit:
            org_hits.append((a, [f"names “{hit}”"]))
    if org_hits:
        ev = _dedupe_stories(org_hits)
        newest = min(_days_ago(e["published_at"], now) for e in ev)
        factors = [{"factor": "Organisation named in reporting", "detail": f"{len(ev)} stor{'ies' if len(ev) != 1 else 'y'} in the last {days} days", "points": 3, "basis": "Collected reporting"}]
        if newest <= RECENT_DAYS:
            factors.append({"factor": "Recent", "detail": f"latest {newest} days ago", "points": 2, "basis": "Publication date"})
        if any(e["severity"] >= 3 for e in ev):
            factors.append({"factor": "Severity", "detail": "at least one story rated high or critical by Threat Watch", "points": 1, "basis": "Threat Watch severity"})
        findings.append(_finding(
            "org-reporting", f"Reporting that names {p['name']}", "Reported incident or activity", "observed",
            "Collected reporting mentions the organisation by name. Read the sources: a name match does not confirm a compromise, "
            "its cause or its scope, and coverage may be about something else.",
            factors, ev, _confidence(ev), [], ["What happened, how access was gained and what was affected, unless the sources state it"], att, ents))

    if p["kind"] == "organisation" and opts.get("use_claims", True):
        names = [n.lower() for n in [p["name"], *p["match_terms"]] if len(n or "") >= 4]
        dom = (p["domain"] or "").lower().removeprefix("www.")
        rows = conn.execute("SELECT group_name, victim, domain, country, discovered_at, record_url FROM ransomware_claims WHERE discovered_at >= ?",
                            ((now - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S"),)).fetchall()
        hits = [dict(r) for r in rows if (dom and (r["domain"] or "").lower().removeprefix("www.") == dom)
                or any(n == r["victim"].lower() or (len(n) >= 8 and n in r["victim"].lower()) for n in names)]
        if hits:
            findings.append(_finding(
                "org-claims", f"Leak-site claim naming {p['name']}", "Ransomware and data extortion", "observed",
                "A ransomware group listed a victim matching this organisation on its leak site (as recorded by ransomware.live). "
                "These are the group's own claims and are not verified; the match is by name or domain.",
                [{"factor": "Leak-site claim", "detail": f"{len(hits)} claim{'s' if len(hits) != 1 else ''} in the last 12 months", "points": 4, "basis": "ransomware.live"}],
                [], {"level": "low", "why": "unverified claim by the group"}, [],
                ["Whether the claim is genuine, and what data (if any) was taken"], att, ents,
                extra={"claims": [{"group": h["group_name"], "victim": h["victim"], "country": h["country"], "discovered_at": h["discovered_at"],
                                   "record_url": h["record_url"]} for h in hits[:10]]}))

    # -- 2. exploited vulnerabilities in listed technology
    kev_rows = [dict(r) for r in conn.execute(
        "SELECT cve_id, vendor, product, name, kev_date_added, kev_due_date, kev_ransomware, kev_required_action, cvss_score, epss, epss_percentile "
        "FROM vulnerabilities WHERE kev=1 AND kev_date_added >= ? ORDER BY kev_date_added DESC", (cutoff.strftime("%Y-%m-%d"),))]
    cve_articles: dict[str, list[dict]] = defaultdict(list)
    for a in arts:
        for t, v in ents.get(a["id"], []):
            if t == "cve":
                cve_articles[v.upper()].append(a)
    for f in techs:
        matched = [(k, m) for k in kev_rows if (m := _tech_match(f["value"], k["vendor"], k["product"]))]
        if not matched:
            continue
        strong = [k for k, m in matched if m == "product"]
        vulns = [{"cve_id": k["cve_id"], "vendor": k["vendor"], "product": k["product"], "name": k["name"], "date_added": k["kev_date_added"],
                  "due": k["kev_due_date"], "ransomware": k["kev_ransomware"] == "Known", "cvss": k["cvss_score"], "epss": k["epss"],
                  "epss_percentile": k["epss_percentile"], "match": "vendor and product" if m == "product" else "vendor only (KEV lists multiple products)",
                  "action": k["kev_required_action"]} for k, m in matched][:12]
        ev = _dedupe_stories([(a, [f"discusses {v['cve_id']}"]) for v in vulns for a in cve_articles.get(v["cve_id"], [])])
        newest = min(_days_ago(v["date_added"] + "T00:00:00Z", now) for v in vulns)
        factors = [{"factor": "Active exploitation", "detail": f"{len(vulns)} CISA KEV entr{'ies' if len(vulns) != 1 else 'y'} added in the last {days} days",
                    "points": 3, "basis": "CISA KEV"},
                   {"factor": "Technology listed for this profile", "detail": f"“{f['value']}” ({_prov(f)})",
                    "points": 2 if strong else 1, "basis": "Profile"}]
        if f["subtype"] in ("internet_facing", "network"):
            factors.append({"factor": "Internet-facing", "detail": "listed as internet-facing or network/remote access", "points": 1, "basis": "Profile"})
        if any(v["ransomware"] for v in vulns):
            factors.append({"factor": "Known ransomware use", "detail": "CISA marks at least one as used in ransomware campaigns", "points": 1, "basis": "CISA KEV"})
        if newest <= RECENT_DAYS:
            factors.append({"factor": "Recent", "detail": f"newest KEV entry {newest} days ago", "points": 1, "basis": "CISA KEV date added"})
        unknowns = ["Versions in use and whether they are affected", "Whether a fix or mitigation is already applied"]
        if f["subtype"] not in ("internet_facing", "network"):
            unknowns.append("Whether the system is reachable from the internet")
        if not strong:
            unknowns.insert(0, "Whether the listed product is one of the products in the KEV entry (KEV names only the vendor)")
        findings.append(_finding(
            "kev:" + _norm(f["value"]), f"Exploited vulnerabilities affecting {f['value']}", "Vulnerability exploitation", "observed",
            "CISA has evidence that these vulnerabilities are exploited in the wild. They are relevant because the profile lists this technology; "
            "Threat Watch does not know the versions in use.",
            factors, ev, {"level": "high", "why": "CISA KEV listing"}, ["T1190"], unknowns, att, ents, threat="edge",
            extra={"vulnerabilities": vulns}))

    # -- 3. threat categories
    claims = _claims(conn, sector["claims"] if sector else None, p["countries"], cutoff, now) if opts.get("use_claims", True) else None
    for key, t in kb.THREATS.items():
        sector_ev, country_ev, all_ev = [], [], []
        recent_all = prev_all = 0
        for a in arts:
            if not _threat_evidence(a):
                continue
            hit = bool(t["signal"].search(a["head"])) or any(TAG_CATEGORY.get(tag) == key for tag in a["tags"])
            if not hit:
                continue
            all_ev.append(a)
            age = _days_ago(a["published_at"], now)
            recent_all += age <= RECENT_DAYS
            prev_all += RECENT_DAYS < age <= 2 * RECENT_DAYS
            why, strength = [], 0
            if sector_re:
                if m := sector_re.search(a["title"]):
                    why.append(f"sector term “{m.group(0)}” in headline")
                    strength = 2
                elif m := sector_re.search(a["summary_text"]):
                    why.append(f"sector term “{m.group(0)}” in summary")
                    strength = 1
            c_hit = next((c for c, r in country_res.items() if r.search(a["title"])), None) or \
                next((c for c in p["countries"] if c == a["source_region"]), None)
            if c_hit:  # headline names the country, or a national agency of that country published it (body mentions are too loose)
                why.append(f"country {c_hit}")
            if strength:
                sector_ev.append((a, why, strength))
            elif c_hit:
                country_ev.append((a, why))
        # Sourced public facts recorded about the organisation (a disclosure, a reported claim) are evidence too.
        org_facts = [f for f in p["facts"] if f["provenance"] == "public" and f["source_url"] and f["category"] in ("context", "asset")
                     and t["signal"].search(_affirmative(f["value"]))] if p["kind"] == "organisation" else []
        stories_all = len({a["story"] for a in all_ev})
        sector_ev.sort(key=lambda x: -x[2])
        sec = _dedupe_stories([(a, w) for a, w, _ in sector_ev])
        sec_strong = any(st == 2 for _, _, st in sector_ev)
        cty = _dedupe_stories(country_ev, 5)
        ev = sec + [e for e in cty if e["article_id"] not in {x["article_id"] for x in sec}]
        cl = claims if key == "ransomware" else None
        applicable_tech = [f for f in techs if key in kb.TECH_THREATS.get(f["subtype"], [])]
        relevant_sector = key != "ot" or (sector and sector["ot"]) or "ot" in tech_types
        if not (ev or org_facts or (cl and cl["count"]) or ((t["baseline"] or applicable_tech) and relevant_sector)):
            continue
        if key == "ot" and not relevant_sector:
            continue

        factors = []
        if org_facts:
            factors.append({"factor": "Reported for this organisation", "detail": "; ".join(f["value"][:160] for f in org_facts[:2]),
                            "points": 3, "basis": "Public source recorded on the profile"})
        newest = min((_days_ago(e["published_at"], now) for e in ev), default=None)
        if sec:
            s_new = min(_days_ago(e["published_at"], now) for e in sec)
            factors.append({"factor": "Sector-specific reporting",
                            "detail": f"{len(sec)} stor{'ies' if len(sec) != 1 else 'y'} tie this threat to {sector['label'].lower()}"
                                      + ("" if sec_strong else " (sector named in the summary only)"),
                            "points": (2 if s_new <= RECENT_DAYS else 1) if sec_strong else 1, "basis": "Collected reporting"})
        if cty:
            factors.append({"factor": "Geographic reporting", "detail": f"{len(cty)} stor{'ies' if len(cty) != 1 else 'y'} tie it to {', '.join(p['countries'])}",
                            "points": 1, "basis": "Collected reporting"})
        if cl and cl["count"]:
            factors.append({"factor": "Leak-site claims against the sector", "detail": f"{cl['count']} claims against {cl['sector']} organisations in {days} days "
                            f"({cl['recent_30d']} in the last 30)", "points": 2 if cl["count"] >= 10 else 1, "basis": "ransomware.live (unverified claims)"})
            if cl["in_countries"]:
                factors.append({"factor": "Claims in the profile's countries", "detail": f"{cl['in_countries']} in {', '.join(p['countries'])}",
                                "points": 1, "basis": "ransomware.live (unverified claims)"})
        if stories_all >= 5:
            factors.append({"factor": "Widespread in current reporting", "detail": f"{stories_all} stories across all sectors in {days} days",
                            "points": 1, "basis": "Collected reporting"})
        if recent_all >= 4 and recent_all >= 2 * max(prev_all, 1):
            factors.append({"factor": "Increasing", "detail": f"{recent_all} stories in the last 30 days against {prev_all} in the 30 before",
                            "points": 1, "basis": "Collected reporting"})
        if applicable_tech:
            factors.append({"factor": "Relevant technology listed", "detail": ", ".join(f["value"] for f in applicable_tech[:3]),
                            "points": 1, "basis": "Profile"})
        if key == "ot" and sector and sector["ot"]:
            factors.append({"factor": "Sector relies on operational technology", "detail": sector["label"], "points": 1, "basis": "Threat Watch guidance"})
        if key == "espionage" and any(re.search(r"intellectual property|research|design|patent|trade secret", f["value"], re.I) for f in _facts(p, "asset")):
            factors.append({"factor": "Valuable intellectual property", "detail": "listed as a critical asset", "points": 1, "basis": "Profile"})
        if key == "bec" and any(re.search(r"payment|finance|invoice|accounts payable", f["value"], re.I) for f in p["facts"] if f["category"] in ("service", "asset")):
            factors.append({"factor": "Payment processes", "detail": "listed as a critical service or asset", "points": 1, "basis": "Profile"})
        tested = [kb.HARDENING[h]["title"] for h in t["hardening"] if controls.get(h, {}).get("status") == "implemented_tested"]
        if tested:
            factors.append({"factor": "Controls reported as implemented and tested", "detail": "; ".join(tested[:3]),
                            "points": -min(2, len(tested)), "basis": "Profile (analyst)"})

        if ev and newest is not None and newest > STALE_DAYS and not (cl and cl["recent_30d"]) and not org_facts:
            cls = "historical"
        elif sec or cty or org_facts or (cl and cl["recent_30d"]):
            cls = "observed"
        elif recent_all >= 4 and recent_all >= 2 * max(prev_all, 1):
            cls = "emerging"
        else:
            cls = "plausible"
        unknowns = []
        if not applicable_tech and key in ("edge", "cloud", "identity", "bec", "ot"):
            unknowns.append("Which relevant technologies the organisation uses (none listed)")
        missing_tel = [kb.TELEMETRY[k]["label"] for k in _telemetry_for(t) if telemetry.get(k, {}).get("status", "unknown") == "unknown"]
        if missing_tel:
            unknowns.append("Telemetry status not recorded: " + ", ".join(missing_tel[:4]) + ("…" if len(missing_tel) > 4 else ""))
        if not any(h in controls for h in t["hardening"]):
            unknowns.append("Status of the relevant preventive controls")
        evidence_summary = {
            "observed": "Sourced facts about the organisation, or dated reporting or claims about its sector or countries, tie this threat to the profile.",
            "historical": "Reporting tied to the sector or countries exists, but nothing recent.",
            "emerging": "Reporting about this threat is increasing, but none is tied to the sector or countries.",
            "plausible": "No reporting ties this threat to the sector or countries in the window. It is listed because it applies to most "
                         "organisations with this profile; it is not evidence of an active campaign."}[cls]
        group_names = [g for g, _ in (cl["top_groups"][:3] if cl else [])]
        group_names += [v for e in sec for ty, v in ents.get(e["article_id"], []) if ty in ("actor", "ransomware")][:3]
        findings.append(_finding(
            f"threat:{key}", t["title"], t["title"], cls, f"{t['summary']} {evidence_summary}", factors, ev,
            _confidence(ev, cl["count"] if cl else 0, len(org_facts)), t["techniques"], unknowns, att, ents, threat=key,
            cap="P3" if cls in ("plausible", "historical") else None,
            extra={"profile_evidence": [{"value": f["value"], "source_url": f["source_url"], "source_title": f["source_title"],
                                         "verified_at": f["verified_at"], "note": f["note"]} for f in org_facts[:5]],
                   "claims": _claims_out(cl) if cl else None, "reporting_volume": {"stories": stories_all, "last_30": recent_all, "previous_30": prev_all},
                   "groups": list(dict.fromkeys(group_names))[:5]}))

    findings.sort(key=lambda f: (f["priority"]["code"], -f["priority"]["points"], {"observed": 0, "emerging": 1, "historical": 2, "plausible": 3}[f["classification"]]))
    inputs = {
        "profile": {k: p[k] for k in ("kind", "name", "sector", "countries", "size", "domain", "match_terms")},
        "facts": [{"category": f["category"], "subtype": f["subtype"], "value": f["value"], "status": f["status"], "provenance": f["provenance"]} for f in p["facts"]],
        "options": opts, "window": {"from": cutoff.isoformat(), "to": now.isoformat(), "days": days},
        "data": {"articles_considered": len(arts), "sources": sources_used, "kev_in_window": len(kev_rows),
                 "claims_used": bool(opts.get("use_claims", True)), "attack_version": att.version,
                 "latest_article": max((a["retrieved_at"] for a in arts), default=None),
                 "collection_started": conn.execute("SELECT MIN(retrieved_at) FROM articles").fetchone()[0]},
        "method_version": METHOD_VERSION,
    }
    return {"inputs": inputs, "findings": findings, "attack_version": att.version}


def _prov(f: dict) -> str:
    return {"user": "entered by analyst", "public": "public source", "inferred": "inferred", "unknown": "unknown"}.get(f["provenance"], f["provenance"])


def _telemetry_for(t: dict) -> list[str]:
    out: list[str] = []
    for m in t["monitoring"]:
        for k in kb.MONITORING[m]["telemetry"]:
            if k not in out:
                out.append(k)
    return out


def _claims_out(cl: dict) -> dict:
    return {**cl, "top_groups": [{"group": g, "claims": n} for g, n in cl["top_groups"]],
            "local_groups": [{"group": g, "claims": n} for g, n in cl["local_groups"]]}


def _finding(key, title, category, classification, summary, factors, evidence, confidence, kb_techniques, unknowns, att: Attack, ents,
             threat: str | None = None, cap: str | None = None, extra: dict | None = None) -> dict:
    points = sum(f["points"] for f in factors)
    techniques: dict[str, dict] = {}

    def add(tid, kind, note=None, **kw):
        cur, rnote = att.resolve(tid)
        entry = techniques.setdefault(cur, {"id": cur, "name": att.tech.get(cur, {}).get("name"), "basis": [], "notes": []})
        if kind not in entry["basis"]:
            entry["basis"].append(kind)
        for n in (note, rnote):
            if n and n not in entry["notes"]:
                entry["notes"].append(n)
        for k, v in kw.items():
            entry.setdefault(k, [])
            entry[k] += [x for x in v if x not in entry[k]]

    for e in evidence:
        for ty, v in ents.get(e["article_id"], []):
            if ty == "attack_technique":
                add(v, "reported", articles=[e["article_id"]])
            elif ty == "attack_technique_inferred":
                add(v, "keyword", articles=[e["article_id"]])
    groups = (extra or {}).get("groups") or []
    if groups and att.loaded:
        for tid, g in att.group_techniques(groups).items():
            add(tid, "group", groups=[x["name"] for x in g["groups"]])
    for tid in kb_techniques:
        add(tid, "guidance")
    out = {"key": key, "title": title, "category": category, "threat": threat or (key.split(":", 1)[1] if key.startswith("threat:") else None),
           "classification": classification, "summary": summary, "priority": priority_of(points, cap), "factors": factors,
           "evidence": evidence, "confidence": confidence, "unknowns": unknowns,
           "techniques": sorted(techniques.values(), key=lambda x: (_basis_rank(x["basis"]), x["id"]))}
    out.update(extra or {})
    return out


def _basis_rank(basis: list[str]) -> int:
    return min({"reported": 0, "group": 1, "keyword": 2, "guidance": 3}[b] for b in basis)


# ------------------------------------------------------------------ saving and change tracking
def _fingerprint(result: dict) -> str:
    stable = {"inputs": {k: v for k, v in result["inputs"].items() if k not in ("window",)}, "findings": [
        {"key": f["key"], "priority": f["priority"], "classification": f["classification"],
         "evidence": [e["article_id"] for e in f["evidence"]], "techniques": [t["id"] for t in f["techniques"]],
         "claims": (f.get("claims") or {}).get("count") if isinstance(f.get("claims"), dict) else len(f.get("claims") or []),
         "vulns": [v["cve_id"] for v in f.get("vulnerabilities") or []]} for f in result["findings"]]}
    stable["inputs"]["data"] = {k: v for k, v in stable["inputs"]["data"].items() if k not in ("latest_article", "articles_considered")}
    return hashlib.sha256(jdumps(stable).encode()).hexdigest()


def diff(prev: list[dict] | None, cur: list[dict]) -> dict:
    if prev is None:
        return {"first": True, "summary": ["First assessment of this profile."]}
    before = {f["key"]: f for f in prev}
    after = {f["key"]: f for f in cur}
    new = [k for k in after if k not in before]
    gone = [k for k in before if k not in after]
    up, down, reclassified, new_evidence, new_tech, dropped = [], [], [], {}, {}, 0
    for k in after.keys() & before.keys():
        a, b = after[k], before[k]
        if a["priority"]["code"] < b["priority"]["code"]:
            up.append({"key": k, "title": a["title"], "from": b["priority"]["code"], "to": a["priority"]["code"]})
        elif a["priority"]["code"] > b["priority"]["code"]:
            down.append({"key": k, "title": a["title"], "from": b["priority"]["code"], "to": a["priority"]["code"]})
        if a["classification"] != b["classification"]:
            reclassified.append({"key": k, "title": a["title"], "from": b["classification"], "to": a["classification"]})
        ids = {e["article_id"] for e in b["evidence"]}
        fresh = [e for e in a["evidence"] if e["article_id"] not in ids]
        dropped += len(ids - {e["article_id"] for e in a["evidence"]})
        if fresh:
            new_evidence[k] = [e["article_id"] for e in fresh]
        bt = {t["id"] for t in b["techniques"] if set(t["basis"]) & {"reported", "group"}}
        nt = [t["id"] for t in a["techniques"] if set(t["basis"]) & {"reported", "group"} and t["id"] not in bt]
        if nt:
            new_tech[k] = nt
        bv = {v["cve_id"] for v in b.get("vulnerabilities") or []}
        nv = [v["cve_id"] for v in a.get("vulnerabilities") or [] if v["cve_id"] not in bv]
        if nv:
            new_evidence.setdefault(k, [])
            after[k].setdefault("_new_cves", nv)
    summary = []

    def plural(n, one, many):
        return f"{n} {one if n == 1 else many}"
    if new:
        summary.append(f"{plural(len(new), 'new finding', 'new findings')}: " + "; ".join(after[k]["title"] for k in new[:4]))
    for u in up:
        summary.append(f"Priority raised: {u['title']} ({u['from']} to {u['to']})")
    for d in down:
        summary.append(f"Priority lowered: {d['title']} ({d['from']} to {d['to']})")
    for r in reclassified:
        summary.append(f"{r['title']}: {r['from']} to {r['to']}")
    if new_evidence:
        n = sum(len(v) for v in new_evidence.values())
        if n:
            summary.append(f"{plural(n, 'new supporting report', 'new supporting reports')} across {plural(len([v for v in new_evidence.values() if v]), 'finding', 'findings')}")
    cves = [c for f in after.values() for c in f.pop("_new_cves", [])]
    if cves:
        summary.append(f"{plural(len(cves), 'newly exploited vulnerability', 'newly exploited vulnerabilities')} in listed technology: {', '.join(cves[:5])}")
    if new_tech:
        n = len({t for v in new_tech.values() for t in v})
        summary.append(f"{plural(n, 'ATT&CK technique', 'ATT&CK techniques')} newly evidenced in reporting or documented for named groups")
    if dropped:
        summary.append(f"{plural(dropped, 'supporting report', 'supporting reports')} no longer counted (outside the window or excluded by a rule change)")
    if gone:
        summary.append(f"{plural(len(gone), 'finding no longer supported', 'findings no longer supported')}: " + "; ".join(before[k]["title"] for k in gone[:4]))
    if not summary:
        summary.append("No change in findings, priorities or evidence.")
    return {"first": False, "new": new, "removed": gone, "removed_titles": {k: before[k]["title"] for k in gone}, "priority_up": up,
            "priority_down": down, "reclassified": reclassified, "new_evidence": new_evidence, "new_techniques": new_tech, "dropped_evidence": dropped, "summary": summary}


def run(conn: sqlite3.Connection, pid: int, now: datetime | None = None) -> dict:
    """Assess and save a snapshot unless nothing changed since the latest one."""
    result = assess(conn, pid, now)
    fp = _fingerprint(result)
    last = conn.execute("SELECT * FROM assessments WHERE profile_id=? ORDER BY id DESC LIMIT 1", (pid,)).fetchone()
    if last and last["fingerprint"] == fp and last["method_version"] == METHOD_VERSION:
        return {"id": last["id"], "unchanged": True, "created_at": last["created_at"]}
    changes = diff(jloads(last["findings"]) if last else None, result["findings"])
    cur = conn.execute(
        "INSERT INTO assessments(profile_id, created_at, method_version, attack_version, inputs, findings, changes, fingerprint) VALUES(?,?,?,?,?,?,?,?)",
        (pid, now_iso(), METHOD_VERSION, result["attack_version"], jdumps(result["inputs"]), jdumps(result["findings"]), jdumps(changes), fp))
    return {"id": cur.lastrowid, "unchanged": False, "changes": changes}


def as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
