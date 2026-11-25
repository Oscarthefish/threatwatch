"""Read models built from a saved assessment: ATT&CK matrix, technique detail, Navigator layer, and defensive guidance."""
from __future__ import annotations

import sqlite3

from ..db import jloads
from . import kb
from .engine import Attack

BASIS_LABEL = {"reported": "Named in reporting", "group": "Documented by MITRE for a group in the evidence",
               "keyword": "Inferred from keywords in reporting", "guidance": "Threat Watch guidance (analyst review needed)"}
DETECTION_STATES = ["unknown", "none", "partial", "implemented", "validated"]
TELEMETRY_STATES = ["unknown", "available", "partial", "not_available"]


def coverage_map(conn: sqlite3.Connection, pid: int) -> dict[str, dict]:
    return {r["technique"]: dict(r) for r in conn.execute("SELECT * FROM coverage WHERE profile_id=?", (pid,))}


def technique_index(findings: list[dict], include_dismissed: set[str] | None = None) -> dict[str, dict]:
    """technique id -> {basis set, findings [{key,title,priority}], groups, articles}"""
    out: dict[str, dict] = {}
    for f in findings:
        if include_dismissed is not None and f["key"] in include_dismissed:
            continue
        for t in f["techniques"]:
            e = out.setdefault(t["id"], {"id": t["id"], "name": t.get("name"), "basis": set(), "findings": [], "groups": set(), "articles": set(), "notes": set()})
            e["basis"].update(t["basis"])
            e["findings"].append({"key": f["key"], "title": f["title"], "priority": f["priority"]["code"]})
            e["groups"].update(t.get("groups") or [])
            e["articles"].update(t.get("articles") or [])
            e["notes"].update(t.get("notes") or [])
    return out


def strongest(basis: set[str]) -> str:
    for b in ("reported", "group", "keyword", "guidance"):
        if b in basis:
            return b
    return "guidance"


def matrix(conn: sqlite3.Connection, pid: int, findings: list[dict], dismissed: set[str]) -> dict:
    att = Attack(conn)
    idx = technique_index(findings, dismissed)
    cov = coverage_map(conn, pid)
    tactics = [dict(r) for r in conn.execute("SELECT attack_id, shortname, name, url FROM attack_tactics ORDER BY ord")]
    cols = {t["shortname"]: [] for t in tactics}
    for tid, e in idx.items():
        info = att.tech.get(tid)
        if not info:
            continue
        c = cov.get(tid, {})
        cell = {"id": tid, "name": info["name"], "basis": strongest(e["basis"]), "all_basis": sorted(e["basis"]),
                "findings": e["findings"], "groups": sorted(e["groups"])[:8], "articles": sorted(e["articles"]),
                "detection": c.get("detection", "unknown"), "telemetry": c.get("telemetry", "unknown")}
        for tac in info["tactics"]:
            if tac in cols:
                cols[tac].append(cell)
    order = {"reported": 0, "group": 1, "keyword": 2, "guidance": 3}
    for v in cols.values():
        v.sort(key=lambda x: (order[x["basis"]], -len(x["findings"]), x["id"]))
    unknown = [tid for tid in idx if tid not in att.tech]
    return {"attack_version": att.version, "loaded": att.loaded,
            "tactics": [{**t, "techniques": cols[t["shortname"]]} for t in tactics], "unresolved": unknown,
            "basis_labels": BASIS_LABEL}


def technique_detail(conn: sqlite3.Connection, tid: str, pid: int | None, findings: list[dict] | None) -> dict | None:
    att = Attack(conn)
    cur, note = att.resolve(tid)
    row = conn.execute("SELECT * FROM attack_techniques WHERE attack_id=?", (cur,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["tactics"] = [r["name"] for r in conn.execute(
        f"SELECT name FROM attack_tactics WHERE shortname IN ({','.join('?' * len(jloads(d['tactics']))) or 'NULL'}) ORDER BY ord", jloads(d["tactics"]))]
    d["platforms"] = jloads(d["platforms"])
    d["resolved_from"] = tid.upper() if cur != tid.upper() else None
    d["note"] = note
    d["parent"] = dict(conn.execute("SELECT attack_id, name FROM attack_techniques WHERE attack_id=?", (d["parent_id"],)).fetchone() or {}) if d["parent_id"] else None
    d["mitigations"] = [dict(r) for r in conn.execute(
        "SELECT m.attack_id, m.name, m.description, m.url FROM attack_links l JOIN attack_mitigations m ON m.attack_id=l.src "
        "WHERE l.dst=? AND l.rel='mitigates' ORDER BY m.attack_id", (cur,))]
    dets = []
    for r in conn.execute("SELECT d.* FROM attack_links l JOIN attack_detections d ON d.attack_id=l.src WHERE l.dst=? AND l.rel='detects'", (cur,)):
        dets.append({"attack_id": r["attack_id"], "name": r["name"], "url": r["url"], "analytics": jloads(r["analytics"])[:6]})
    d["detections"] = dets
    groups = conn.execute(
        "SELECT o.attack_id, o.name, o.kind, o.url FROM attack_links l JOIN attack_objects o ON o.attack_id=l.src "
        "WHERE l.dst=? AND l.rel='uses' ORDER BY o.kind, o.name", (cur,)).fetchall()
    d["used_by"] = {"groups": [dict(g) for g in groups if g["kind"] == "group"][:40], "software": [dict(g) for g in groups if g["kind"] == "software"][:40],
                    "group_count": sum(1 for g in groups if g["kind"] == "group"), "software_count": sum(1 for g in groups if g["kind"] == "software")}
    d["guidance"] = [{"key": k, "title": m["title"]} for k, m in kb.MONITORING.items() if cur in m["techniques"]]
    if pid is not None and findings is not None:
        idx = technique_index(findings).get(cur)
        d["profile"] = {"findings": idx["findings"] if idx else [], "basis": sorted(idx["basis"]) if idx else [],
                        "groups": sorted(idx["groups"]) if idx else [], "notes": sorted(idx["notes"]) if idx else []}
        arts = sorted(idx["articles"]) if idx else []
        d["profile"]["articles"] = [dict(r) for r in conn.execute(
            f"SELECT a.id, a.title, a.url, a.published_at, s.name AS source FROM articles a JOIN sources s ON s.id=a.source_id "
            f"WHERE a.id IN ({','.join('?' * len(arts)) or 'NULL'}) ORDER BY a.published_at DESC", arts)]
        c = coverage_map(conn, pid).get(cur)
        d["coverage"] = c or {"telemetry": "unknown", "detection": "unknown", "note": ""}
    return d


def navigator_layer(conn: sqlite3.Connection, profile: dict, findings: list[dict], dismissed: set[str], assessment: dict) -> dict:
    """ATT&CK Navigator layer (format 4.5). Score: 3 reported, 2 documented for a group, 1 keyword/guidance."""
    att = Attack(conn)
    idx = technique_index(findings, dismissed)
    cov = coverage_map(conn, profile["id"])
    score = {"reported": 3, "group": 2, "keyword": 1, "guidance": 1}
    techs = []
    for tid, e in sorted(idx.items()):
        info = att.tech.get(tid)
        if not info:
            continue
        b = strongest(e["basis"])
        c = cov.get(tid, {})
        comment = f"{BASIS_LABEL[b]}. Findings: " + "; ".join(f"{x['priority']} {x['title']}" for x in e["findings"][:4])
        if c:
            comment += f". Detection: {c.get('detection', 'unknown')}; telemetry: {c.get('telemetry', 'unknown')}"
        for tac in info["tactics"]:
            techs.append({"techniqueID": tid, "tactic": tac, "score": score[b], "comment": comment[:900], "enabled": True,
                          "metadata": [{"name": "basis", "value": b}, {"name": "detection", "value": c.get("detection", "unknown")}],
                          "showSubtechniques": False})
    major = (att.version or "").split(".")[0] or None
    return {
        "name": f"Threat Watch: {profile['name']}"[:100],
        "versions": {"attack": major, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Threat landscape assessment {assessment['id']} ({assessment['created_at'][:10]}). Relevance to the profile, "
                       "not evidence of activity against the organisation. Score 3: named in reporting; 2: documented for a group in the evidence; "
                       "1: inferred or guidance.",
        "sorting": 3, "hideDisabled": False,
        "gradient": {"colors": ["#e8eef7", "#9db7dd", "#2f5f9e"], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "Named in reporting", "color": "#2f5f9e"}, {"label": "Documented for a group", "color": "#9db7dd"},
                        {"label": "Inferred or guidance", "color": "#e8eef7"}],
        "techniques": techs,
    }


def defend(conn: sqlite3.Connection, profile: dict, findings: list[dict], dismissed: set[str]) -> dict:
    """Monitoring, hunting and hardening guidance ordered by the findings it supports."""
    telemetry = {f["subtype"]: f for f in profile["facts"] if f["category"] == "telemetry"}
    controls = {f["subtype"]: f for f in profile["facts"] if f["category"] == "control"}
    att = Attack(conn)
    active = [f for f in findings if f["key"] not in dismissed]
    mon, hunts, hard = {}, {}, {}

    def addto(bucket, key, f):
        e = bucket.setdefault(key, {"key": key, "findings": []})
        if f["key"] not in [x["key"] for x in e["findings"]]:
            e["findings"].append({"key": f["key"], "title": f["title"], "priority": f["priority"]["code"]})

    for f in active:
        t = kb.THREATS.get(f.get("threat") or "")
        if not t:
            continue
        for m in t["monitoring"]:
            addto(mon, m, f)
        for h in t["hunts"]:
            addto(hunts, h, f)
        for x in t["hardening"]:
            addto(hard, x, f)

    def rank(e):
        return (min(x["priority"] for x in e["findings"]), -len(e["findings"]))

    def techs(ids):
        out = []
        for tid in ids:
            cur, note = att.resolve(tid)
            out.append({"id": cur, "name": att.tech.get(cur, {}).get("name"), "note": note})
        return out

    def tel(keys):
        return [{"key": k, "label": kb.TELEMETRY[k]["label"], "detail": kb.TELEMETRY[k]["detail"],
                 "status": telemetry.get(k, {}).get("status") or "unknown"} for k in keys]

    platforms = set(profile["options"].get("platforms") or [])
    monitoring = []
    for e in sorted(mon.values(), key=rank):
        m = kb.MONITORING[e["key"]]
        monitoring.append({**e, **{k: v for k, v in m.items() if k not in ("techniques", "telemetry", "queries")},
                           "techniques": techs(m["techniques"]), "telemetry": tel(m["telemetry"]),
                           "queries": [{"platform": k, "query": q, "status": "conceptual"} for k, q in m["queries"].items() if k in platforms]})
    hunting = []
    for e in sorted(hunts.values(), key=rank):
        h = kb.HUNTS[e["key"]]
        hunting.append({**e, **{k: v for k, v in h.items() if k not in ("techniques", "telemetry")},
                        "techniques": techs(h["techniques"]), "telemetry": tel(h["telemetry"]),
                        "blocked_by": [kb.TELEMETRY[k]["label"] for k in h["telemetry"] if telemetry.get(k, {}).get("status") == "not_available"]})
    mit_names = dict(conn.execute("SELECT attack_id, name FROM attack_mitigations").fetchall())
    hardening = []
    for e in sorted(hard.values(), key=lambda e: ({"high": 0, "medium": 1, "low": 2}[kb.HARDENING[e["key"]]["priority"]], *rank(e))):
        x = kb.HARDENING[e["key"]]
        c = controls.get(e["key"])
        hardening.append({**e, **{k: v for k, v in x.items() if k not in ("cis", "csf", "mitigations")},
                          "cis": [{"id": i, "name": kb.CIS_NAMES[i]} for i in x["cis"]],
                          "csf": [{"id": i, "name": kb.CSF_NAMES[i]} for i in x["csf"]],
                          "mitigations": [{"id": i, "name": mit_names.get(i), "url": f"https://attack.mitre.org/mitigations/{i}/"} for i in x["mitigations"]],
                          "status": c["status"] if c else "unknown", "status_note": c["note"] if c else ""})
    gaps = []
    for k, label in ((k, kb.TELEMETRY[k]["label"]) for m in monitoring for k in [t["key"] for t in m["telemetry"]]):
        if k not in [g["key"] for g in gaps]:
            gaps.append({"key": k, "label": label, "status": telemetry.get(k, {}).get("status") or "unknown",
                         "needed_by": [m["title"] for m in monitoring if k in [t["key"] for t in m["telemetry"]]]})
    return {"monitoring": monitoring, "hunts": hunting, "hardening": hardening, "telemetry": gaps,
            "query_note": "Example queries are conceptual: written for orientation, not syntax-checked or tested in your environment. "
                          "Field names depend on your data sources and parsing."}
