"""Further reading: links to primary sources, taken only from stored data.

* CVE references come from the CVE record / CISA KEV notes (vendor advisories, patches).
* Group and software pages come from the synced MITRE ATT&CK data.
* ATT&CK technique pages are derived from the technique ID (T1566.001 -> /techniques/T1566/001/).
Only http(s) URLs are returned; nothing is guessed from a name.
"""
from __future__ import annotations

import re
import sqlite3
from urllib.parse import urlsplit

from ..ingest.attack import lookup
from . import entities

_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
GROUP_TYPES = {"actor": "group", "ransomware": "software", "malware": "software"}


def safe_url(url: str | None) -> str | None:
    if not url:
        return None
    p = urlsplit(url.strip())
    return url.strip() if p.scheme in ("http", "https") and p.netloc else None


def technique_url(tid: str) -> str | None:
    tid = tid.upper()
    if not _TECH.match(tid):
        return None
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _label(url: str) -> str:
    p = urlsplit(url)
    path = p.path.strip("/")
    return p.netloc.removeprefix("www.") + (f" · {path[:60]}{'…' if len(path) > 60 else ''}" if path else "")


def attack_summary(row: dict | None, refs: int = 12) -> dict | None:
    if not row:
        return None
    return {"attack_id": row["attack_id"], "name": row["name"], "kind": row["kind"], "url": row["url"], "aliases": row["aliases"],
            "description": row["description"], "modified": row["modified"], "synced_at": row["synced_at"],
            "refs": [r for r in row["refs"] if safe_url(r.get("url"))][:refs], "ref_count": len(row["refs"])}


def for_article(conn: sqlite3.Connection, ents: list, vulns: list[dict], own_url: str) -> list[dict]:
    """Grouped links: [{section, items: [{title, url, note}]}]."""
    seen = {own_url}
    sections: list[dict] = []
    # Only CVEs with primary references or a KEV entry earn a section (a Patch Tuesday story can name 150 CVEs);
    # exploited ones first. The rest stay reachable from the article's Vulnerabilities panel.
    useful = [v for v in vulns if v.get("kev") or any(safe_url(u) for u in v.get("references") or [])]
    useful.sort(key=lambda v: (not v.get("kev"), -(v.get("epss") or 0), v["cve_id"]))
    for v in useful[:6]:
        items = []
        for u in v.get("references") or []:
            url = safe_url(u)
            if url and url not in seen:
                seen.add(url)
                items.append({"title": _label(url), "url": url, "note": None})
            if len(items) >= 5:
                break
        items.append({"title": f"CVE record for {v['cve_id']}", "url": v["cve_url"], "note": "CVE.org"})
        if v.get("kev_url"):
            items.append({"title": "CISA Known Exploited Vulnerabilities entry", "url": v["kev_url"], "note": "CISA"})
        sections.append({"section": f"{v['cve_id']}" + (f" ({v['vendor']} {v['product']})" if v.get("vendor") and v.get("product") else ""), "items": items})
    if len(useful) > 6 or len(vulns) > len(useful):
        sections.append({"section": "More CVEs", "items": [], "note": f"{len(vulns) - min(len(useful), 6)} more CVE(s) in this story; "
                         "each has its CVE.org, NVD and vendor links on its own page (see Vulnerabilities)."})
    attack_items, done = [], set()
    for e in ents:
        t, val = e["type"], e["value"]
        if t in GROUP_TYPES and val.lower() not in done:
            canon_aliases = {**entities.ACTORS, **entities.RANSOMWARE, **entities.MALWARE}.get(val, [])
            row = lookup(conn, [val, *canon_aliases], GROUP_TYPES[t])
            if row:
                done.add(val.lower())
                attack_items.append({"title": f"{row['name']} ({row['attack_id']})", "url": row["url"], "note": "MITRE ATT&CK " + ("group" if row["kind"] == "group" else "software")})
        elif t in ("attack_technique", "attack_technique_inferred") and (url := technique_url(val)) and url not in seen:
            seen.add(url)
            name = entities.technique_name(val)
            attack_items.append({"title": f"{val.upper()}{f' {name}' if name else ''}", "url": url,
                                 "note": "MITRE ATT&CK technique" + (" (keyword-inferred)" if t.endswith("inferred") else "")})
    if attack_items:
        sections.append({"section": "MITRE ATT&CK", "items": attack_items[:12]})
    return sections
