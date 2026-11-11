"""Serialisation helpers shared by API routes."""
from __future__ import annotations

import sqlite3

from ..db import jloads
from ..intel.classify import SEVERITY_LABELS

ARTICLE_LIST_COLS = """a.id, a.url, a.title, a.summary_text, a.published_at, a.retrieved_at, a.sections, a.tags, a.severity,
    a.severity_reasons, a.actions, a.confidence, a.score, a.region, a.cluster_id, s.name AS source_name, s.key AS source_key,
    (SELECT COUNT(*) FROM articles c WHERE c.cluster_id = a.cluster_id AND c.id <> a.id) AS related_count,
    EXISTS(SELECT 1 FROM bookmarks b WHERE b.article_id=a.id) AS bookmarked,
    EXISTS(SELECT 1 FROM reading_history h WHERE h.article_id=a.id) AS is_read,
    (SELECT o.output_json FROM ai_outputs o WHERE o.kind='article_summary' AND o.subject_type='article' AND o.subject_id=a.id ORDER BY o.id DESC LIMIT 1) AS ai_json"""


def article_brief(r: sqlite3.Row | dict) -> dict:
    d = dict(r)
    ai = jloads(d.pop("ai_json", None), {}) if d.get("ai_json") else None
    return {
        "id": d["id"],
        "url": d["url"],
        "title": d["title"],
        "excerpt": (d.get("summary_text") or "")[:320],
        "ai_summary": ai.get("summary") if ai else None,
        "published_at": d["published_at"],
        "retrieved_at": d["retrieved_at"],
        "source": {"name": d["source_name"], "key": d["source_key"]},
        "sections": jloads(d["sections"]),
        "tags": jloads(d["tags"]),
        "severity": d["severity"],
        "severity_label": SEVERITY_LABELS[d["severity"]],
        "severity_reasons": jloads(d["severity_reasons"]),
        "actions": jloads(d.get("actions")),
        "confidence": d["confidence"],
        "region": d["region"],
        "related_count": d.get("related_count", 0),
        "bookmarked": bool(d.get("bookmarked")),
        "read": bool(d.get("is_read")),
    }


def vuln_dict(r: sqlite3.Row | dict) -> dict:
    d = dict(r)
    d["kev"] = bool(d["kev"])
    d["references"] = jloads(d.pop("references_json", "[]"))
    d["kev_cwes"] = jloads(d.get("kev_cwes"))
    d["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{d['cve_id']}"
    d["cve_url"] = f"https://www.cve.org/CVERecord?id={d['cve_id']}"
    d["kev_url"] = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={d['cve_id']}" if d["kev"] else None
    return d
