"""Threat Landscapes API: profiles, assessments, ATT&CK views and the defensive work that follows.

Every route is scoped by profile id in the path, and every child record is looked up together with its
profile id, so one profile's data can never be read or changed through another's URL.
Nothing here calls an AI provider or fetches external URLs.
"""
from __future__ import annotations

import re
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator

from ..auth import get_db, require_user
from ..db import get_setting, jdumps, jloads, now_iso
from ..landscape import engine, kb, response, views
from ..landscape import kb_response as R

router = APIRouter(prefix="/api/landscapes", dependencies=[Depends(require_user)])

FACT_CATEGORIES = {"service", "asset", "supplier", "regulation", "tech", "telemetry", "control", "context"}
PROVENANCE = {"user", "public", "inferred", "unknown"}
TELEMETRY_STATUS = {"available", "partial", "not_available", "unknown"}
CONTROL_STATUS = {"implemented_tested", "implemented", "partial", "not_implemented", "unknown"}
COUNTRY = re.compile(r"^[A-Z]{2}$")
PRE_COMPROMISE = {"reconnaissance", "resource-development"}


def _url_ok(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    if not re.match(r"^https?://[^\s/$.?#][^\s]*$", v, re.I) or len(v) > 1000:
        raise ValueError("must be an http(s) URL")
    return v


class ProfileIn(BaseModel):
    kind: Literal["organisation", "industry"]
    name: str = Field(..., min_length=2, max_length=120)
    sector: str | None = None
    countries: list[str] = Field(default_factory=list, max_length=20)
    size: Literal["small", "medium", "large", "enterprise", ""] | None = None
    description: str = Field("", max_length=4000)
    domain: str | None = Field(None, max_length=200)
    match_terms: list[str] = Field(default_factory=list, max_length=20)
    notes: str = Field("", max_length=10000)
    options: dict | None = None

    @field_validator("sector")
    @classmethod
    def _sector(cls, v):
        if v and v not in kb.SECTORS:
            raise ValueError("unknown sector")
        return v or None

    @field_validator("countries")
    @classmethod
    def _countries(cls, v):
        v = [c.strip().upper() for c in v if c.strip()]
        if any(not COUNTRY.match(c) for c in v):
            raise ValueError("use two-letter country codes")
        return list(dict.fromkeys(v))

    @field_validator("match_terms")
    @classmethod
    def _terms(cls, v):
        return [t.strip()[:120] for t in v if t.strip()]

    @field_validator("domain")
    @classmethod
    def _domain(cls, v):
        if not v:
            return None
        v = v.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
        if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v):
            raise ValueError("not a domain name")
        return v


class ProfilePatch(ProfileIn):
    kind: Literal["organisation", "industry"] | None = None  # type: ignore[assignment]
    name: str | None = Field(None, min_length=2, max_length=120)  # type: ignore[assignment]


def _options(raw: dict | None, base: dict | None = None) -> dict:
    o = {**engine.DEFAULT_OPTIONS, **(base or {})}
    raw = raw or {}
    if "lookback_days" in raw:
        d = int(raw["lookback_days"])
        if d not in (30, 60, 90, 180, 365):
            raise HTTPException(422, "lookback_days must be 30, 60, 90, 180 or 365")
        o["lookback_days"] = d
    if "use_claims" in raw:
        o["use_claims"] = bool(raw["use_claims"])
    if "excluded_sources" in raw:
        o["excluded_sources"] = [str(x)[:60] for x in raw["excluded_sources"]][:40]
    if "platforms" in raw:
        o["platforms"] = [p for p in raw["platforms"] if p in ("splunk", "sentinel", "xdr")]
    return o


class FactIn(BaseModel):
    category: str
    subtype: str = Field("", max_length=60)
    value: str = Field(..., min_length=1, max_length=500)
    status: str = ""
    provenance: str = "user"
    source_url: str | None = None
    source_title: str | None = Field(None, max_length=300)
    verified_at: str | None = Field(None, max_length=30)
    note: str = Field("", max_length=2000)

    @field_validator("source_url")
    @classmethod
    def _source(cls, v):
        return _url_ok(v)


def _check_fact(f: dict) -> None:
    if f["category"] not in FACT_CATEGORIES:
        raise HTTPException(422, "unknown category")
    if f["provenance"] not in PROVENANCE:
        raise HTTPException(422, "unknown provenance")
    if f["provenance"] == "public" and not f.get("source_url"):
        raise HTTPException(422, "a public fact needs a source URL")
    if f["category"] == "tech" and f["subtype"] not in kb.TECH_TYPES:
        raise HTTPException(422, "unknown technology type")
    if f["category"] == "telemetry":
        if f["subtype"] not in kb.TELEMETRY:
            raise HTTPException(422, "unknown telemetry source")
        if (f["status"] or "unknown") not in TELEMETRY_STATUS:
            raise HTTPException(422, "unknown telemetry status")
    if f["category"] == "control" and (f["status"] or "unknown") not in CONTROL_STATUS:
        raise HTTPException(422, "unknown control status")


def _profile_or_404(conn, pid: int) -> dict:
    p = engine.load_profile(conn, pid)
    if not p:
        raise HTTPException(404, "not found")
    return p


def _touch(conn, pid: int) -> None:
    conn.execute("UPDATE profiles SET updated_at=? WHERE id=?", (now_iso(), pid))


def _latest(conn, pid: int) -> dict | None:
    r = conn.execute("SELECT * FROM assessments WHERE profile_id=? ORDER BY id DESC LIMIT 1", (pid,)).fetchone()
    return _assessment(r) if r else None


def _assessment(r) -> dict:
    d = dict(r)
    for k in ("inputs", "findings", "changes"):
        d[k] = jloads(d[k], {} if k != "findings" else [])
    d.pop("fingerprint", None)
    return d


def _reviews(conn, pid: int) -> dict[str, dict]:
    return {r["finding_key"]: dict(r) for r in conn.execute("SELECT * FROM finding_reviews WHERE profile_id=?", (pid,))}


def _dismissed(conn, pid: int) -> set[str]:
    return {k for k, r in _reviews(conn, pid).items() if r["decision"] == "dismissed"}


# ------------------------------------------------------------------ reference data
@router.get("/meta")
def meta(conn: sqlite3.Connection = Depends(get_db)):
    return {
        "sectors": [{"key": k, "label": v["label"]} for k, v in kb.SECTORS.items()],
        "tech_types": kb.TECH_TYPES, "telemetry": {k: v["label"] for k, v in kb.TELEMETRY.items()},
        "hardening": {k: v["title"] for k, v in kb.HARDENING.items()},
        "fact_categories": sorted(FACT_CATEGORIES), "provenance": {"user": "Entered by me", "public": "Public, with source", "inferred": "Inferred (assumption)", "unknown": "Unknown (open question)"},
        "telemetry_status": sorted(TELEMETRY_STATUS), "control_status": sorted(CONTROL_STATUS),
        "sources": [{"key": r["key"], "name": r["name"]} for r in conn.execute("SELECT key, name FROM sources WHERE kind IN ('rss','html') ORDER BY name")],
        "scenarios": {k: v["title"] for k, v in R.SCENARIOS.items()},
        "attack_version": get_setting(conn, "attack_version"),
    }


# ------------------------------------------------------------------ profiles
@router.get("")
def list_profiles(conn: sqlite3.Connection = Depends(get_db)):
    out = []
    for p in conn.execute("SELECT * FROM profiles WHERE archived=0 ORDER BY updated_at DESC"):
        a = conn.execute("SELECT id, created_at, findings FROM assessments WHERE profile_id=? ORDER BY id DESC LIMIT 1", (p["id"],)).fetchone()
        top = None
        counts = {}
        if a:
            fs = jloads(a["findings"])
            dismissed = _dismissed(conn, p["id"])
            fs = [f for f in fs if f["key"] not in dismissed]
            counts = {c: sum(1 for f in fs if f["priority"]["code"] == c) for c in ("P1", "P2", "P3", "P4")}
            top = [{"title": f["title"], "priority": f["priority"]["code"], "classification": f["classification"]} for f in fs[:3]]
        out.append({"id": p["id"], "kind": p["kind"], "name": p["name"], "sector": p["sector"],
                    "sector_label": kb.SECTORS.get(p["sector"] or "", {}).get("label"), "countries": jloads(p["countries"]),
                    "updated_at": p["updated_at"], "assessed_at": a["created_at"] if a else None, "counts": counts, "top": top})
    return {"profiles": out}


@router.post("")
def create_profile(body: ProfileIn, conn: sqlite3.Connection = Depends(get_db)):
    n = now_iso()
    cur = conn.execute(
        """INSERT INTO profiles(kind, name, sector, countries, size, description, domain, match_terms, options, notes, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (body.kind, body.name.strip(), body.sector, jdumps(body.countries), body.size or None, body.description, body.domain,
         jdumps(body.match_terms), jdumps(_options(body.options)), body.notes, n, n))
    return {"id": cur.lastrowid}


@router.get("/{pid}")
def get_profile(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    p = _profile_or_404(conn, pid)
    a = _latest(conn, pid)
    reviews = _reviews(conn, pid)
    p["sector_label"] = kb.SECTORS.get(p["sector"] or "", {}).get("label")
    count = conn.execute("SELECT COUNT(*) FROM assessments WHERE profile_id=?", (pid,)).fetchone()[0]
    stale = None
    if a:
        newer = conn.execute("SELECT COUNT(*) FROM articles WHERE retrieved_at > ?", (a["created_at"],)).fetchone()[0]
        stale = {"profile_changed": p["updated_at"] > a["created_at"], "new_articles": newer,
                 "method_changed": a["method_version"] != engine.METHOD_VERSION}
    return {"profile": p, "assessment": a, "reviews": reviews, "assessments": count, "stale": stale,
            "freshness": {"latest_article": conn.execute("SELECT MAX(retrieved_at) FROM articles").fetchone()[0],
                          "latest_claim": conn.execute("SELECT MAX(retrieved_at) FROM ransomware_claims").fetchone()[0],
                          "kev_checked": conn.execute("SELECT last_success_at FROM sources WHERE key='cisa-kev'").fetchone()[0]
                          if conn.execute("SELECT 1 FROM sources WHERE key='cisa-kev'").fetchone() else None}}


@router.patch("/{pid}")
def patch_profile(pid: int, body: ProfilePatch, conn: sqlite3.Connection = Depends(get_db)):
    p = _profile_or_404(conn, pid)
    data = body.model_dump(exclude_unset=True)
    sets, vals = [], []
    for k, v in data.items():
        if k == "options":
            v = jdumps(_options(v, p["options"]))
        elif k in ("countries", "match_terms"):
            v = jdumps(v)
        elif k == "name":
            v = v.strip()
        sets.append(f"{k}=?")
        vals.append(v)
    if sets:
        conn.execute(f"UPDATE profiles SET {', '.join(sets)}, updated_at=? WHERE id=?", (*vals, now_iso(), pid))
    return {"ok": True}


@router.delete("/{pid}")
def delete_profile(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    conn.execute("DELETE FROM profiles WHERE id=?", (pid,))
    return {"ok": True}


@router.post("/{pid}/facts")
def add_fact(pid: int, body: FactIn, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    f = body.model_dump()
    _check_fact(f)
    n = now_iso()
    cur = conn.execute(
        """INSERT INTO profile_facts(profile_id, category, subtype, value, status, provenance, source_url, source_title, verified_at, note, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, f["category"], f["subtype"], f["value"].strip(), f["status"], f["provenance"], f["source_url"], f["source_title"], f["verified_at"], f["note"], n, n))
    _touch(conn, pid)
    return {"id": cur.lastrowid}


@router.put("/{pid}/facts/{fid}")
def update_fact(pid: int, fid: int, body: FactIn, conn: sqlite3.Connection = Depends(get_db)):
    if not conn.execute("SELECT 1 FROM profile_facts WHERE id=? AND profile_id=?", (fid, pid)).fetchone():
        raise HTTPException(404, "not found")
    f = body.model_dump()
    _check_fact(f)
    conn.execute("""UPDATE profile_facts SET category=?, subtype=?, value=?, status=?, provenance=?, source_url=?, source_title=?, verified_at=?, note=?, updated_at=?
                    WHERE id=? AND profile_id=?""",
                 (f["category"], f["subtype"], f["value"].strip(), f["status"], f["provenance"], f["source_url"], f["source_title"], f["verified_at"], f["note"],
                  now_iso(), fid, pid))
    _touch(conn, pid)
    return {"ok": True}


@router.delete("/{pid}/facts/{fid}")
def delete_fact(pid: int, fid: int, conn: sqlite3.Connection = Depends(get_db)):
    if conn.execute("DELETE FROM profile_facts WHERE id=? AND profile_id=?", (fid, pid)).rowcount == 0:
        raise HTTPException(404, "not found")
    _touch(conn, pid)
    return {"ok": True}


# ------------------------------------------------------------------ assessments
@router.post("/{pid}/assess")
def assess(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    return engine.run(conn, pid)


@router.get("/{pid}/assessments")
def history(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    rows = conn.execute("SELECT id, created_at, method_version, attack_version, changes, findings FROM assessments WHERE profile_id=? ORDER BY id DESC LIMIT 100",
                        (pid,)).fetchall()
    out = []
    for r in rows:
        fs = jloads(r["findings"])
        out.append({"id": r["id"], "created_at": r["created_at"], "method_version": r["method_version"], "attack_version": r["attack_version"],
                    "changes": jloads(r["changes"], {}), "counts": {c: sum(1 for f in fs if f["priority"]["code"] == c) for c in ("P1", "P2", "P3", "P4")},
                    "findings": len(fs)})
    return {"assessments": out}


@router.get("/{pid}/assessments/{aid}")
def get_assessment(pid: int, aid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM assessments WHERE id=? AND profile_id=?", (aid, pid)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    return _assessment(r)


class ReviewIn(BaseModel):
    decision: Literal["dismissed", "accepted"]
    reason: str = Field("", max_length=1000)


@router.put("/{pid}/reviews/{key:path}")
def review(pid: int, key: str, body: ReviewIn, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    if body.decision == "dismissed" and not body.reason.strip():
        raise HTTPException(422, "give a reason for dismissing")
    conn.execute("""INSERT INTO finding_reviews(profile_id, finding_key, decision, reason, updated_at) VALUES(?,?,?,?,?)
                    ON CONFLICT(profile_id, finding_key) DO UPDATE SET decision=excluded.decision, reason=excluded.reason, updated_at=excluded.updated_at""",
                 (pid, key[:200], body.decision, body.reason.strip(), now_iso()))
    return {"ok": True}


@router.delete("/{pid}/reviews/{key:path}")
def unreview(pid: int, key: str, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM finding_reviews WHERE profile_id=? AND finding_key=?", (pid, key))
    return {"ok": True}


def _need_assessment(conn, pid) -> tuple[dict, dict]:
    p = _profile_or_404(conn, pid)
    a = _latest(conn, pid)
    if not a:
        raise HTTPException(409, "run an assessment first")
    return p, a


# ------------------------------------------------------------------ ATT&CK
@router.get("/{pid}/attack")
def attack_matrix(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    _, a = _need_assessment(conn, pid)
    return views.matrix(conn, pid, a["findings"], _dismissed(conn, pid))


@router.get("/{pid}/attack/{tid}")
def attack_technique(pid: int, tid: str, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    if not re.match(r"^T\d{4}(\.\d{3})?$", tid.upper()):
        raise HTTPException(404, "not a technique ID")
    a = _latest(conn, pid)
    d = views.technique_detail(conn, tid, pid, a["findings"] if a else [])
    if not d:
        raise HTTPException(404, "technique not in the loaded ATT&CK release")
    return d


@router.get("/{pid}/navigator")
def navigator(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    p, a = _need_assessment(conn, pid)
    layer = views.navigator_layer(conn, p, a["findings"], _dismissed(conn, pid), a)
    name = re.sub(r"[^a-z0-9]+", "-", p["name"].lower()).strip("-")[:40] or "profile"
    return Response(jdumps(layer), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="threatwatch-{name}-layer.json"'})


class CoverageIn(BaseModel):
    telemetry: Literal["available", "partial", "not_available", "unknown"] = "unknown"
    detection: Literal["none", "partial", "implemented", "validated", "unknown"] = "unknown"
    note: str = Field("", max_length=2000)


@router.put("/{pid}/coverage/{tid}")
def set_coverage(pid: int, tid: str, body: CoverageIn, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    tid = tid.upper()
    if not conn.execute("SELECT 1 FROM attack_techniques WHERE attack_id=?", (tid,)).fetchone():
        raise HTTPException(404, "technique not in the loaded ATT&CK release")
    conn.execute("""INSERT INTO coverage(profile_id, technique, telemetry, detection, note, updated_at) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(profile_id, technique) DO UPDATE SET telemetry=excluded.telemetry, detection=excluded.detection, note=excluded.note,
                    updated_at=excluded.updated_at""", (pid, tid, body.telemetry, body.detection, body.note, now_iso()))
    return {"ok": True}


@router.get("/{pid}/coverage")
def coverage(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    """Visibility and detection backlog for the techniques in the latest assessment."""
    _, a = _need_assessment(conn, pid)
    idx = views.technique_index(a["findings"], _dismissed(conn, pid))
    cov = views.coverage_map(conn, pid)
    att = engine.Attack(conn)
    rank_basis = {"reported": 0, "group": 1, "keyword": 2, "guidance": 3}
    rows = []
    for tid, e in idx.items():
        if tid not in att.tech:
            continue
        if set(att.tech[tid]["tactics"]) <= PRE_COMPROMISE:
            continue  # happens on the adversary's side; MITRE notes these are largely outside an enterprise's visibility
        c = cov.get(tid, {})
        b = views.strongest(e["basis"])
        best = min(f["priority"] for f in e["findings"])
        rows.append({"id": tid, "name": att.tech[tid]["name"], "basis": b, "priority": best, "findings": len(e["findings"]),
                     "telemetry": c.get("telemetry", "unknown"), "detection": c.get("detection", "unknown"), "note": c.get("note", "")})
    det_rank = {"none": 0, "unknown": 1, "partial": 2, "implemented": 3, "validated": 4}
    rows.sort(key=lambda r: (r["priority"], rank_basis[r["basis"]], det_rank[r["detection"]], r["id"]))
    backlog = []
    for r in rows:
        if r["basis"] == "guidance" and r["priority"] > "P2":
            continue
        if r["detection"] in ("none", "unknown", "partial") or r["detection"] == "implemented":
            step = {"none": "Build a detection", "unknown": "Record whether a detection exists", "partial": "Extend the detection",
                    "implemented": "Test the detection"}[r["detection"]]
            if r["telemetry"] == "not_available":
                step = "Collect the telemetry first, then build a detection"
            elif r["telemetry"] == "unknown" and r["detection"] in ("none", "unknown"):
                step += " (telemetry availability also unrecorded)"
            backlog.append({**r, "step": step})
    totals = {k: sum(1 for r in rows if r["detection"] == k) for k in det_rank}
    return {"techniques": rows, "backlog": backlog[:60], "totals": totals,
            "note": "Reconnaissance and Resource Development are left out: they happen on the adversary's side and are rarely visible to a SOC. Telemetry, detection existence and testing are recorded separately: collecting a log does not mean anything detects the technique."}


# ------------------------------------------------------------------ defensive guidance
@router.get("/{pid}/defend")
def defend(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    p, a = _need_assessment(conn, pid)
    d = views.defend(conn, p, a["findings"], _dismissed(conn, pid))
    d["saved_hunts"] = [dict(r) for r in conn.execute("SELECT id, template, title, status, updated_at FROM hunts WHERE profile_id=? ORDER BY updated_at DESC", (pid,))]
    d["actions"] = [dict(r) for r in conn.execute("SELECT * FROM landscape_actions WHERE profile_id=? ORDER BY status='done', updated_at DESC", (pid,))]
    return d


HUNT_STATUS = Literal["proposed", "ready", "in_progress", "completed", "findings", "blocked"]


class HuntIn(BaseModel):
    template: str
    finding_key: str | None = Field(None, max_length=200)


@router.post("/{pid}/hunts")
def create_hunt(pid: int, body: HuntIn, conn: sqlite3.Connection = Depends(get_db)):
    p = _profile_or_404(conn, pid)
    h = kb.HUNTS.get(body.template)
    if not h:
        raise HTTPException(404, "unknown hunt")
    a = _latest(conn, pid)
    finding = next((f for f in (a["findings"] if a else []) if f["key"] == body.finding_key), None)
    tel = {f["subtype"]: f["status"] for f in p["facts"] if f["category"] == "telemetry"}
    plan = {**h, "telemetry": [{"key": k, "label": kb.TELEMETRY[k]["label"], "status": tel.get(k) or "unknown"} for k in h["telemetry"]],
            "intelligence": [{"title": e["title"], "url": e["url"], "source": e["source"], "published_at": e["published_at"]} for e in (finding or {}).get("evidence", [])[:5]],
            "finding": {"key": finding["key"], "title": finding["title"], "priority": finding["priority"]["code"]} if finding else None,
            "groups": (finding or {}).get("groups") or []}
    n = now_iso()
    cur = conn.execute("INSERT INTO hunts(profile_id, template, finding_key, title, plan, created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
                       (pid, body.template, body.finding_key, h["title"], jdumps(plan), n, n))
    return {"id": cur.lastrowid}


@router.get("/{pid}/hunts/{hid}")
def get_hunt(pid: int, hid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM hunts WHERE id=? AND profile_id=?", (hid, pid)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    d = dict(r)
    d["plan"] = jloads(d["plan"], {})
    return d


class HuntPatch(BaseModel):
    status: HUNT_STATUS | None = None
    notes: str | None = Field(None, max_length=50000)
    conclusion: str | None = Field(None, max_length=20000)
    limitations: str | None = Field(None, max_length=20000)
    title: str | None = Field(None, min_length=2, max_length=200)


@router.patch("/{pid}/hunts/{hid}")
def patch_hunt(pid: int, hid: int, body: HuntPatch, conn: sqlite3.Connection = Depends(get_db)):
    data = body.model_dump(exclude_unset=True)
    if data.get("status") in ("completed", "findings") and not (data.get("conclusion") or (conn.execute(
            "SELECT conclusion FROM hunts WHERE id=? AND profile_id=?", (hid, pid)).fetchone() or [""])[0]).strip():
        raise HTTPException(422, "record a conclusion before closing the hunt, including what was checked")
    if not data:
        return {"ok": True}
    sets = ", ".join(f"{k}=?" for k in data)
    if conn.execute(f"UPDATE hunts SET {sets}, updated_at=? WHERE id=? AND profile_id=?", (*data.values(), now_iso(), hid, pid)).rowcount == 0:
        raise HTTPException(404, "not found")
    return {"ok": True}


@router.delete("/{pid}/hunts/{hid}")
def delete_hunt(pid: int, hid: int, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM hunts WHERE id=? AND profile_id=?", (hid, pid))
    return {"ok": True}


class ActionIn(BaseModel):
    kind: Literal["detection", "hardening", "readiness", "playbook", "hunt"]
    ref: str = Field("", max_length=200)
    title: str = Field(..., min_length=2, max_length=300)
    detail: str = Field("", max_length=5000)
    priority: Literal["high", "medium", "low"] = "medium"
    owner: str = Field("", max_length=200)


class ActionPatch(BaseModel):
    status: Literal["open", "in_progress", "done", "wont_do"] | None = None
    owner: str | None = Field(None, max_length=200)
    note: str | None = Field(None, max_length=5000)
    priority: Literal["high", "medium", "low"] | None = None


@router.post("/{pid}/actions")
def add_action(pid: int, body: ActionIn, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    if body.ref and conn.execute("SELECT 1 FROM landscape_actions WHERE profile_id=? AND ref=? AND kind=? AND status IN ('open','in_progress')",
                                 (pid, body.ref, body.kind)).fetchone():
        raise HTTPException(409, "already on the action list")
    n = now_iso()
    cur = conn.execute("INSERT INTO landscape_actions(profile_id, kind, ref, title, detail, priority, owner, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (pid, body.kind, body.ref, body.title, body.detail, body.priority, body.owner, n, n))
    return {"id": cur.lastrowid}


@router.patch("/{pid}/actions/{aid}")
def patch_action(pid: int, aid: int, body: ActionPatch, conn: sqlite3.Connection = Depends(get_db)):
    data = body.model_dump(exclude_unset=True)
    if data:
        sets = ", ".join(f"{k}=?" for k in data)
        if conn.execute(f"UPDATE landscape_actions SET {sets}, updated_at=? WHERE id=? AND profile_id=?", (*data.values(), now_iso(), aid, pid)).rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True}


@router.delete("/{pid}/actions/{aid}")
def delete_action(pid: int, aid: int, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM landscape_actions WHERE id=? AND profile_id=?", (aid, pid))
    return {"ok": True}


# ------------------------------------------------------------------ readiness
@router.get("/{pid}/readiness")
def get_readiness(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    a = _latest(conn, pid)
    scen = response.relevant_scenarios(a["findings"] if a else [], _dismissed(conn, pid))
    return response.readiness(conn, pid, scen)


class AnswerIn(BaseModel):
    answer: Literal["tested", "implemented", "partial", "not_implemented", "unknown", "na"]
    evidence: str = Field("", max_length=4000)


@router.put("/{pid}/readiness/{qkey}")
def answer(pid: int, qkey: str, body: AnswerIn, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    if qkey not in R.QUESTIONS:
        raise HTTPException(404, "unknown question")
    conn.execute("""INSERT INTO readiness_answers(profile_id, question, answer, evidence, updated_at) VALUES(?,?,?,?,?)
                    ON CONFLICT(profile_id, question) DO UPDATE SET answer=excluded.answer, evidence=excluded.evidence, updated_at=excluded.updated_at""",
                 (pid, qkey, body.answer, body.evidence, now_iso()))
    return {"ok": True}


# ------------------------------------------------------------------ playbooks
@router.get("/{pid}/playbooks")
def list_playbooks(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    a = _latest(conn, pid)
    saved = [dict(r) for r in conn.execute("SELECT id, scenario, title, version, reviewed_at, updated_at FROM playbooks WHERE profile_id=? ORDER BY updated_at DESC", (pid,))]
    since = a["created_at"] if a else None
    for s in saved:
        s["review_due"] = bool(since and (s["reviewed_at"] or s["updated_at"]) < since and a["changes"].get("new"))
    return {"saved": saved, "scenarios": response.relevant_scenarios(a["findings"] if a else [], _dismissed(conn, pid)),
            "templates": sorted(R.PLAYBOOKS)}


class PlaybookIn(BaseModel):
    scenario: str


@router.post("/{pid}/playbooks")
def create_playbook(pid: int, body: PlaybookIn, conn: sqlite3.Connection = Depends(get_db)):
    p = _profile_or_404(conn, pid)
    if body.scenario not in R.SCENARIOS:
        raise HTTPException(404, "unknown scenario")
    a = _latest(conn, pid)
    title, md = response.draft_playbook(conn, p, body.scenario, a["findings"] if a else [])
    n = now_iso()
    cur = conn.execute("INSERT INTO playbooks(profile_id, scenario, title, body, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                       (pid, body.scenario, title, md, n, n))
    conn.execute("INSERT INTO playbook_versions(playbook_id, version, body, saved_at) VALUES(?,?,?,?)", (cur.lastrowid, 1, md, n))
    return {"id": cur.lastrowid}


@router.get("/{pid}/playbooks/{bid}")
def get_playbook(pid: int, bid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM playbooks WHERE id=? AND profile_id=?", (bid, pid)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    d = dict(r)
    d["versions"] = [dict(v) for v in conn.execute("SELECT version, saved_at FROM playbook_versions WHERE playbook_id=? ORDER BY version DESC", (bid,))]
    return d


class PlaybookPatch(BaseModel):
    body: str | None = Field(None, max_length=200000)
    title: str | None = Field(None, min_length=2, max_length=200)
    reviewed: bool = False


@router.patch("/{pid}/playbooks/{bid}")
def patch_playbook(pid: int, bid: int, body: PlaybookPatch, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM playbooks WHERE id=? AND profile_id=?", (bid, pid)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    n = now_iso()
    version = r["version"]
    if body.body is not None and body.body != r["body"]:
        version += 1
        conn.execute("INSERT INTO playbook_versions(playbook_id, version, body, saved_at) VALUES(?,?,?,?)", (bid, version, body.body, n))
    conn.execute("UPDATE playbooks SET body=?, title=?, version=?, updated_at=?, reviewed_at=COALESCE(?, reviewed_at) WHERE id=?",
                 (body.body if body.body is not None else r["body"], body.title or r["title"], version, n, n if body.reviewed else None, bid))
    return {"ok": True, "version": version}


@router.get("/{pid}/playbooks/{bid}/versions/{ver}")
def playbook_version(pid: int, bid: int, ver: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT v.* FROM playbook_versions v JOIN playbooks p ON p.id=v.playbook_id WHERE p.id=? AND p.profile_id=? AND v.version=?",
                     (bid, pid, ver)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    return dict(r)


@router.delete("/{pid}/playbooks/{bid}")
def delete_playbook(pid: int, bid: int, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM playbooks WHERE id=? AND profile_id=?", (bid, pid))
    return {"ok": True}


# ------------------------------------------------------------------ exercises
@router.get("/{pid}/exercises")
def list_exercises(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    return {"available": [{"scenario": k, "title": v["title"], "stages": len(v["stages"])} for k, v in R.EXERCISES.items()],
            "runs": [dict(r) for r in conn.execute("SELECT id, scenario, format, difficulty, stage, created_at, completed_at FROM exercises WHERE profile_id=? ORDER BY id DESC", (pid,))]}


class ExerciseIn(BaseModel):
    scenario: str
    format: Literal["individual", "team", "guided", "open", "interview"] = "individual"
    difficulty: Literal["foundation", "standard", "advanced"] = "standard"


@router.post("/{pid}/exercises")
def start_exercise(pid: int, body: ExerciseIn, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    if body.scenario not in R.EXERCISES:
        raise HTTPException(404, "unknown exercise")
    n = now_iso()
    cur = conn.execute("INSERT INTO exercises(profile_id, scenario, format, difficulty, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                       (pid, body.scenario, body.format, body.difficulty, n, n))
    return {"id": cur.lastrowid}


@router.get("/{pid}/exercises/{eid}")
def get_exercise(pid: int, eid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM exercises WHERE id=? AND profile_id=?", (eid, pid)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    d = dict(r)
    d["responses"] = jloads(d["responses"], {})
    spec = R.EXERCISES[d["scenario"]]
    # Later stages stay hidden until the analyst moves on, so the exercise unfolds as it would in an incident.
    shown = spec["stages"][: d["stage"] + 1]
    d["spec"] = {"title": spec["title"], "setting": spec["setting"], "total": len(spec["stages"]),
                 "stages": [{**s, "questions": [{k: v for k, v in q.items() if k != "points" or (i < d["stage"] or d["completed_at"])} for q in s["questions"]]}
                            for i, s in enumerate(shown)]}
    return d


class ExercisePatch(BaseModel):
    responses: dict[str, dict] | None = None
    advance: bool = False


@router.patch("/{pid}/exercises/{eid}")
def patch_exercise(pid: int, eid: int, body: ExercisePatch, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM exercises WHERE id=? AND profile_id=?", (eid, pid)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    resp = jloads(r["responses"], {})
    for k, v in (body.responses or {}).items():
        if len(k) > 40:
            continue
        resp[k] = {"answer": str(v.get("answer", ""))[:10000], "covered": [str(x)[:300] for x in (v.get("covered") or [])][:20]}
    stage, done = r["stage"], r["completed_at"]
    total = len(R.EXERCISES[r["scenario"]]["stages"])
    if body.advance:
        if stage + 1 >= total:
            done = done or now_iso()
        else:
            stage += 1
    conn.execute("UPDATE exercises SET responses=?, stage=?, completed_at=?, updated_at=? WHERE id=?", (jdumps(resp), stage, done, now_iso(), eid))
    return {"ok": True, "stage": stage, "completed": bool(done)}


# ------------------------------------------------------------------ interview preparation
class PrepIn(BaseModel):
    role: str = Field(..., min_length=2, max_length=200)
    job_description: str = Field("", max_length=20000)


@router.get("/{pid}/interview")
def interview(pid: int, conn: sqlite3.Connection = Depends(get_db)):
    p = _profile_or_404(conn, pid)
    preps = []
    for r in conn.execute("SELECT * FROM interview_preps WHERE profile_id=? ORDER BY id DESC", (pid,)):
        answers = {a["question"]: {**dict(a), "covered": jloads(a["covered"])} for a in conn.execute("SELECT * FROM interview_answers WHERE prep_id=?", (r["id"],))}
        qs = []
        for k in R.interview_questions(r["role"], r["job_description"]):
            q = R.INTERVIEW[k]
            a = answers.get(k, {})
            covered = [c for c in a.get("covered", []) if c in q["points"]]
            qs.append({"key": k, **q, "category_label": R.INTERVIEW_CATEGORIES[q["category"]], "answer": a.get("answer", ""),
                       "covered": covered, "confidence": a.get("confidence", ""),
                       "revise": bool(a) and (a.get("confidence") == "revise" or len(covered) < len(q["points"]) / 2)})
        preps.append({**dict(r), "level": R.role_level(r["role"]), "questions": qs})
    a = _latest(conn, pid)
    scen = response.relevant_scenarios(a["findings"] if a else [], _dismissed(conn, pid))
    return {"profile_kind": p["kind"], "preps": preps, "scenarios": scen[:5], "has_assessment": bool(a)}


@router.post("/{pid}/interview")
def create_prep(pid: int, body: PrepIn, conn: sqlite3.Connection = Depends(get_db)):
    _profile_or_404(conn, pid)
    n = now_iso()
    cur = conn.execute("INSERT INTO interview_preps(profile_id, role, job_description, created_at, updated_at) VALUES(?,?,?,?,?)",
                       (pid, body.role.strip(), body.job_description, n, n))
    return {"id": cur.lastrowid}


class InterviewAnswerIn(BaseModel):
    answer: str = Field("", max_length=20000)
    covered: list[str] = Field(default_factory=list, max_length=20)
    confidence: Literal["", "revise", "ok", "strong"] = ""


@router.put("/{pid}/interview/{prep}/answers/{qkey}")
def interview_answer(pid: int, prep: int, qkey: str, body: InterviewAnswerIn, conn: sqlite3.Connection = Depends(get_db)):
    if not conn.execute("SELECT 1 FROM interview_preps WHERE id=? AND profile_id=?", (prep, pid)).fetchone():
        raise HTTPException(404, "not found")
    if qkey not in R.INTERVIEW:
        raise HTTPException(404, "unknown question")
    covered = [c for c in body.covered if c in R.INTERVIEW[qkey]["points"]]
    conn.execute("""INSERT INTO interview_answers(prep_id, question, answer, covered, confidence, updated_at) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(prep_id, question) DO UPDATE SET answer=excluded.answer, covered=excluded.covered, confidence=excluded.confidence,
                    updated_at=excluded.updated_at""", (prep, qkey, body.answer, jdumps(covered), body.confidence, now_iso()))
    return {"ok": True}


@router.delete("/{pid}/interview/{prep}")
def delete_prep(pid: int, prep: int, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM interview_preps WHERE id=? AND profile_id=?", (prep, pid))
    return {"ok": True}


@router.get("/{pid}/export.md")
def export_markdown(pid: int, prep: int | None = None, conn: sqlite3.Connection = Depends(get_db)):
    p = _profile_or_404(conn, pid)
    a = _latest(conn, pid)
    dismissed = _dismissed(conn, pid)
    findings = [f for f in (a["findings"] if a else []) if f["key"] not in dismissed]
    prep_row = conn.execute("SELECT * FROM interview_preps WHERE id=? AND profile_id=?", (prep, pid)).fetchone() if prep else None
    answers = {r["question"]: {**dict(r), "covered": jloads(r["covered"])} for r in conn.execute("SELECT * FROM interview_answers WHERE prep_id=?", (prep,))} if prep_row else {}
    md = response.briefing_markdown(p, a, findings, dict(prep_row) if prep_row else None, answers)
    name = re.sub(r"[^a-z0-9]+", "-", p["name"].lower()).strip("-")[:40] or "profile"
    return Response(md, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}-briefing.md"'})


@router.get("/{pid}/playbooks/{bid}/export.md")
def export_playbook(pid: int, bid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT title, body FROM playbooks WHERE id=? AND profile_id=?", (bid, pid)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    name = re.sub(r"[^a-z0-9]+", "-", r["title"].lower()).strip("-")[:50]
    return Response(r["body"], media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
