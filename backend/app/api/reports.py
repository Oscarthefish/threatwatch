"""Intelligence Reports Library API: report series registry, reports, document upload, page text and search.

Uploads arrive as the raw request body (Content-Type application/pdf), streamed to disk with a size cap, so no
multipart parser is needed. The uploaded file name is kept as a label only. Extraction happens in the worker.
Nothing here fetches external URLs or calls an AI provider.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import uuid
from typing import Literal
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from ..auth import get_db, require_user
from ..config import get_settings
from ..db import get_setting, jdumps, jloads, now_iso, set_setting, tx
from ..reports import ai_extract, process, registry
from ..reports import findings as F
from .content import _fts_query

router = APIRouter(prefix="/api/reports", dependencies=[Depends(require_user)])

STATUS_GROUPS = {
    "awaiting": ("discovered",),
    "processing": ("queued", "processing"),
    "processed": ("processed",),
    "review": ("needs_review",),
    "failed": ("failed",),
}
DATE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
EDITABLE = ("title", "publisher", "series", "edition", "published_on", "period_start", "period_end", "publication_url",
            "document_url", "frequency", "category", "regions", "industries", "methodology", "sample_size", "access_notes",
            "notes", "source_id")


def _url(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    if not re.match(r"^https?://[^\s/$.?#][^\s]*$", v, re.I) or len(v) > 1000:
        raise ValueError("must be an http(s) URL")
    return v


def _date(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    if not DATE.match(v):
        raise ValueError("use YYYY, YYYY-MM or YYYY-MM-DD")
    return v


class ReportIn(BaseModel):
    title: str | None = Field(None, min_length=2, max_length=200)
    publisher: str | None = Field(None, max_length=120)
    series: str | None = Field(None, max_length=160)
    edition: str | None = Field(None, max_length=40)
    published_on: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    publication_url: str | None = None
    document_url: str | None = None
    frequency: str | None = None
    category: str | None = None
    regions: list[str] | None = Field(None, max_length=10)
    industries: list[str] | None = Field(None, max_length=20)
    methodology: str | None = Field(None, max_length=4000)
    sample_size: str | None = Field(None, max_length=300)
    access_notes: str | None = Field(None, max_length=1000)
    notes: str | None = Field(None, max_length=10000)
    source_id: int | None = None

    @field_validator("publication_url", "document_url")
    @classmethod
    def _u(cls, v):
        return _url(v)

    @field_validator("published_on", "period_start", "period_end")
    @classmethod
    def _d(cls, v):
        return _date(v)

    @field_validator("frequency")
    @classmethod
    def _freq(cls, v):
        if v and v not in registry.FREQUENCIES:
            raise ValueError("unknown frequency")
        return v or None

    @field_validator("category")
    @classmethod
    def _cat(cls, v):
        if v and v not in registry.CATEGORIES:
            raise ValueError("unknown category")
        return v or None

    @field_validator("regions")
    @classmethod
    def _regions(cls, v):
        if v is None:
            return v
        v = [r.strip().upper() for r in v if r.strip()]
        if any(r not in registry.REGIONS for r in v):
            raise ValueError("unknown region")
        return list(dict.fromkeys(v))

    @field_validator("industries")
    @classmethod
    def _industries(cls, v):
        return None if v is None else list(dict.fromkeys(x.strip()[:60] for x in v if x.strip()))


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("regions", "industries"):
        d[k] = jloads(d.get(k), []) or []
    for k in ("meta_source", "pdf_meta"):
        if k in d:
            d[k] = jloads(d.get(k), {}) or {}
    d["bookmarked"] = bool(d.get("bookmarked"))
    d.pop("file_name", None)
    d["has_document"] = bool(r["sha256"]) if "sha256" in r.keys() else False
    return d


def _get(conn, rid: int) -> sqlite3.Row:
    r = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    if not r:
        raise HTTPException(404, "Report not found")
    return r


def _check_source(conn, sid: int | None) -> None:
    if sid is not None and not conn.execute("SELECT 1 FROM report_sources WHERE id=?", (sid,)).fetchone():
        raise HTTPException(422, "Unknown report series")


# ------------------------------------------------------------------ library
@router.get("/meta")
def meta():
    s = get_settings()
    return {"frequencies": registry.FREQUENCIES, "categories": registry.CATEGORIES, "regions": registry.REGIONS,
            "max_mb": s.reports_max_mb, "max_pages": s.reports_max_pages}


@router.get("")
def list_reports(q: str | None = None, status: str | None = None, publisher: str | None = None, category: str | None = None,
                 region: str | None = None, bookmarked: bool = False, sort: Literal["published", "added", "title"] = "published",
                 conn: sqlite3.Connection = Depends(get_db)):
    where, params = [], []
    if status:
        if status not in STATUS_GROUPS:
            raise HTTPException(422, "Unknown status")
        where.append(f"r.status IN ({','.join('?' * len(STATUS_GROUPS[status]))})")
        params += STATUS_GROUPS[status]
    if publisher:
        where.append("r.publisher = ?")
        params.append(publisher)
    if category:
        where.append("r.category = ?")
        params.append(category)
    if region:
        where.append("EXISTS (SELECT 1 FROM json_each(r.regions) WHERE value = ?)")
        params.append(region.upper())
    if bookmarked:
        where.append("r.bookmarked = 1")
    matches: dict[int, dict] = {}
    if q and q.strip():
        fq = _fts_query(q)
        like = f"%{q.strip()}%"
        if fq:
            for m in conn.execute(
                    "SELECT p.report_id, COUNT(*) AS n, MIN(p.page_no) AS first FROM report_pages_fts f JOIN report_pages p ON p.id=f.rowid"
                    " WHERE report_pages_fts MATCH ? GROUP BY p.report_id", (fq,)):
                matches[m["report_id"]] = {"pages": m["n"], "first_page": m["first"]}
        ids = list(matches)
        cond = "(r.title LIKE ? OR r.publisher LIKE ? OR r.series LIKE ?"
        params_q = [like, like, like]
        if ids:
            cond += f" OR r.id IN ({','.join('?' * len(ids))})"
            params_q += ids
        where.append(cond + ")")
        params += params_q
    order = {"published": "COALESCE(r.published_on, substr(r.created_at,1,10)) DESC, r.id DESC",
             "added": "r.created_at DESC, r.id DESC", "title": "r.title COLLATE NOCASE"}[sort]
    sql = ("SELECT r.id, r.title, r.publisher, r.series, r.edition, r.published_on, r.category, r.regions, r.industries, r.status,"
           " r.status_detail, r.page_count, r.extraction_confidence, r.review_status, r.bookmarked, r.created_at, r.sha256,"
           " r.publication_url FROM reports r" + (" WHERE " + " AND ".join(where) if where else "") + f" ORDER BY {order} LIMIT 500")
    rows = []
    for r in conn.execute(sql, params):
        d = _row(r)
        d.pop("sha256", None)
        d["match"] = matches.get(r["id"])
        rows.append(d)
    counts = {k: 0 for k in STATUS_GROUPS}
    for r in conn.execute("SELECT status, COUNT(*) AS n FROM reports GROUP BY status"):
        for k, sts in STATUS_GROUPS.items():
            if r["status"] in sts:
                counts[k] += r["n"]
    publishers = [r[0] for r in conn.execute("SELECT DISTINCT publisher FROM reports WHERE publisher IS NOT NULL ORDER BY publisher")]
    return {"reports": rows, "counts": counts, "total": sum(counts.values()), "publishers": publishers}


@router.post("")
def create_report(body: ReportIn, conn: sqlite3.Connection = Depends(get_db)):
    """A report known by its link but not yet uploaded (status 'discovered')."""
    if not body.title:
        raise HTTPException(422, "A title is required")
    _check_source(conn, body.source_id)
    now = now_iso()
    vals = body.model_dump()
    src = {k: "user" for k, v in vals.items() if v not in (None, [], "")}
    with tx(conn):
        rid = conn.execute(
            "INSERT INTO reports(title, publisher, series, edition, published_on, period_start, period_end, publication_url, document_url,"
            " frequency, category, regions, industries, methodology, sample_size, access_notes, notes, source_id, meta_source, status,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'discovered',?,?)",
            (vals["title"], vals["publisher"], vals["series"], vals["edition"], vals["published_on"], vals["period_start"],
             vals["period_end"], vals["publication_url"], vals["document_url"], vals["frequency"], vals["category"],
             jdumps(vals["regions"] or []), jdumps(vals["industries"] or []), vals["methodology"], vals["sample_size"],
             vals["access_notes"], vals["notes"], vals["source_id"], jdumps(src), now, now)).lastrowid
    return {"id": rid}


async def _receive(request: Request) -> tuple:
    s = get_settings()
    limit = s.reports_max_mb * 1024 * 1024
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(415, "Upload a PDF file")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"The file is larger than {s.reports_max_mb} MB")
    tmp = process.reports_dir() / ".incoming" / f"{uuid.uuid4().hex}.part"
    h, size, head = hashlib.sha256(), 0, b""
    try:
        with open(tmp, "xb") as f:
            os.chmod(tmp, 0o600)
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"The file is larger than {s.reports_max_mb} MB")
                if len(head) < 1024:
                    head += chunk[:1024 - len(head)]
                h.update(chunk)
                f.write(chunk)
        if size == 0:
            raise HTTPException(422, "The file is empty")
        if b"%PDF-" not in head:
            raise HTTPException(415, "The file is not a PDF")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp, h.hexdigest(), size


@router.post("/upload")
async def upload(request: Request, report_id: int | None = None, conn: sqlite3.Connection = Depends(get_db)):
    if report_id is not None:
        r = _get(conn, report_id)
        if r["sha256"]:
            raise HTTPException(409, "This report already has a document")
    tmp, sha, size = await _receive(request)
    name = request.headers.get("x-filename")
    try:
        rid = process.register(conn, tmp, sha, size, unquote(name) if name else None, report_id)
    except process.DuplicateDocument as d:
        raise HTTPException(409, f"This document is already in the library (report {d.report_id})") from None
    return {"id": rid, "status": "queued"}


@router.get("/sources")
def list_sources(conn: sqlite3.Connection = Depends(get_db)):
    rows = []
    for r in conn.execute(
            "SELECT s.*, (SELECT COUNT(*) FROM reports WHERE source_id=s.id) AS reports,"
            " (SELECT MAX(COALESCE(published_on, substr(created_at,1,10))) FROM reports WHERE source_id=s.id) AS latest"
            " FROM report_sources s ORDER BY s.priority, s.publisher, s.series"):
        d = dict(r)
        d["enabled"] = bool(d["enabled"])
        d["seeded"] = bool(d["seeded"])
        rows.append(d)
    return {"sources": rows}


class SourceIn(BaseModel):
    publisher: str = Field(..., min_length=2, max_length=120)
    series: str = Field(..., min_length=2, max_length=160)
    page_url: str | None = None
    frequency: str = "unknown"
    category: str | None = None
    region: str = "GLOBAL"
    priority: int = Field(2, ge=1, le=4)
    access_notes: str | None = Field(None, max_length=1000)
    notes: str | None = Field(None, max_length=4000)
    verified: bool = False

    @field_validator("page_url")
    @classmethod
    def _u(cls, v):
        return _url(v)

    @field_validator("frequency")
    @classmethod
    def _f(cls, v):
        if v not in registry.FREQUENCIES:
            raise ValueError("unknown frequency")
        return v

    @field_validator("category")
    @classmethod
    def _c(cls, v):
        if v and v not in registry.CATEGORIES:
            raise ValueError("unknown category")
        return v or None

    @field_validator("region")
    @classmethod
    def _r(cls, v):
        v = v.upper()
        if v not in registry.REGIONS:
            raise ValueError("unknown region")
        return v


def _slug(publisher: str, series: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", f"{publisher} {series}".lower()).strip("-")[:80]


@router.post("/sources")
def create_source(body: SourceIn, conn: sqlite3.Connection = Depends(get_db)):
    key = _slug(body.publisher, body.series)
    if conn.execute("SELECT 1 FROM report_sources WHERE key=?", (key,)).fetchone():
        raise HTTPException(409, "That series is already in the registry")
    now = now_iso()
    with tx(conn):
        sid = conn.execute(
            "INSERT INTO report_sources(key, publisher, series, page_url, frequency, category, region, priority, access_notes, notes,"
            " verified_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, body.publisher, body.series, body.page_url, body.frequency, body.category, body.region, body.priority,
             body.access_notes, body.notes, now if body.verified else None, now, now)).lastrowid
    return {"id": sid}


@router.patch("/sources/{sid}")
def update_source(sid: int, body: SourceIn, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT * FROM report_sources WHERE id=?", (sid,)).fetchone()
    if not r:
        raise HTTPException(404, "Series not found")
    verified_at = (r["verified_at"] or now_iso()) if body.verified else None
    with tx(conn):
        conn.execute(
            "UPDATE report_sources SET publisher=?, series=?, page_url=?, frequency=?, category=?, region=?, priority=?, access_notes=?,"
            " notes=?, verified_at=?, updated_at=? WHERE id=?",
            (body.publisher, body.series, body.page_url, body.frequency, body.category, body.region, body.priority, body.access_notes,
             body.notes, verified_at, now_iso(), sid))
    return {"ok": True}


@router.delete("/sources/{sid}")
def delete_source(sid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT key, seeded FROM report_sources WHERE id=?", (sid,)).fetchone()
    if not r:
        raise HTTPException(404, "Series not found")
    with tx(conn):
        conn.execute("DELETE FROM report_sources WHERE id=?", (sid,))  # reports keep their own metadata (source_id -> NULL)
        if r["seeded"]:
            removed = set(get_setting(conn, "report_sources_removed", []) or [])
            removed.add(r["key"])
            set_setting(conn, "report_sources_removed", sorted(removed))
    return {"ok": True}


# ------------------------------------------------------------------ one report
def _suggest_sources(conn, r: sqlite3.Row) -> list[dict]:
    """Series whose publisher name appears in the title, file name or PDF author. A suggestion only."""
    if r["source_id"]:
        return []
    meta = jloads(r["pdf_meta"], {}) or {}
    running = (jloads(r["analysis"], {}) or {}).get("running_title")
    hay = " ".join(filter(None, [r["title"], r["original_filename"], meta.get("author"), meta.get("title"), meta.get("subject"), running])).lower()
    out = []
    for s in conn.execute("SELECT id, publisher, series, frequency FROM report_sources"):
        names = [n.strip().lower() for n in re.split(r"[/(),]", s["publisher"]) if len(n.strip()) >= 4]
        if any(re.search(r"\b" + re.escape(n) + r"\b", hay) for n in names):
            score = 2 if any(w in hay for w in s["series"].lower().split() if len(w) > 4) else 1
            out.append((score, dict(s)))
    out.sort(key=lambda x: -x[0])
    return [s for _, s in out[:4]]


@router.get("/{rid}")
def get_report(rid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = _get(conn, rid)
    d = _row(r)
    d.pop("sha256", None)
    d.pop("analysis", None)
    d["sha256_prefix"] = r["sha256"][:12] if r["sha256"] else None
    analysis = jloads(r["analysis"], {}) if r["analysis"] else None
    src = conn.execute("SELECT * FROM report_sources WHERE id=?", (r["source_id"],)).fetchone() if r["source_id"] else None
    sections = [dict(s) for s in conn.execute(
        "SELECT ord, level, title, page_start, page_end, origin FROM report_sections WHERE report_id=? ORDER BY ord", (rid,))]
    pages = [dict(p) for p in conn.execute("SELECT page_no, label, chars FROM report_pages WHERE report_id=? ORDER BY page_no", (rid,))]
    jobs = [dict(j) for j in conn.execute("SELECT * FROM report_jobs WHERE report_id=? ORDER BY id DESC LIMIT 20", (rid,))]
    editions = []
    if r["source_id"]:
        editions = [dict(e) for e in conn.execute(
            "SELECT id, title, edition, published_on, status FROM reports WHERE source_id=? AND id<>? ORDER BY published_on DESC", (r["source_id"], rid))]
    return {"report": d, "analysis": analysis, "source": dict(src) if src else None, "sections": sections, "pages": pages, "jobs": jobs,
            "editions": editions, "suggested_sources": _suggest_sources(conn, r)}


@router.patch("/{rid}")
def update_report(rid: int, body: ReportIn, conn: sqlite3.Connection = Depends(get_db)):
    r = _get(conn, rid)
    _check_source(conn, body.source_id)
    sent = body.model_dump(exclude_unset=True)
    if "title" in sent and not sent["title"]:
        raise HTTPException(422, "A title is required")
    sets, params = [], []
    src = jloads(r["meta_source"], {}) or {}
    for k in EDITABLE:
        if k not in sent:
            continue
        v = sent[k]
        if k in ("regions", "industries"):
            v = jdumps(v or [])
        if v != r[k]:
            sets.append(f"{k}=?")
            params.append(v)
            src[k] = "user"
    if "source_id" in sent and sent["source_id"]:
        s = conn.execute("SELECT publisher, series, frequency, category, region FROM report_sources WHERE id=?", (sent["source_id"],)).fetchone()
        for k, v in (("publisher", s["publisher"]), ("series", s["series"]), ("frequency", s["frequency"]), ("category", s["category"])):
            if k not in sent and not r[k] and v:
                sets.append(f"{k}=?")
                params.append(v)
                src[k] = "series"
    if not sets:
        return {"ok": True}
    sets += ["meta_source=?", "updated_at=?"]
    params += [jdumps(src), now_iso(), rid]
    with tx(conn):
        conn.execute(f"UPDATE reports SET {', '.join(sets)} WHERE id=?", params)
    return {"ok": True}


@router.post("/{rid}/reprocess")
def reprocess(rid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = _get(conn, rid)
    if not r["file_name"]:
        raise HTTPException(409, "This report has no document to process")
    if r["status"] in ("queued", "processing"):
        return {"ok": True, "status": r["status"]}
    with tx(conn):
        process.queue(conn, rid)
    return {"ok": True, "status": "queued"}


class FlagIn(BaseModel):
    on: bool


@router.post("/{rid}/bookmark")
def bookmark(rid: int, body: FlagIn, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    conn.execute("UPDATE reports SET bookmarked=? WHERE id=?", (int(body.on), rid))
    return {"ok": True}


class ReviewIn(BaseModel):
    review_status: Literal["unreviewed", "reviewed"]


@router.post("/{rid}/review")
def review(rid: int, body: ReviewIn, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    conn.execute("UPDATE reports SET review_status=?, updated_at=? WHERE id=?", (body.review_status, now_iso(), rid))
    return {"ok": True}


@router.delete("/{rid}")
def delete_report(rid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = _get(conn, rid)
    if r["status"] == "processing":
        raise HTTPException(409, "Wait for processing to finish before deleting")
    with tx(conn):
        conn.execute("DELETE FROM reports WHERE id=?", (rid,))
    process.delete_document(r["file_name"])
    return {"ok": True}


@router.get("/{rid}/pages")
def pages(rid: int, start: int = 1, count: int = 5, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    count = max(1, min(count, 20))
    rows = conn.execute("SELECT page_no, label, text FROM report_pages WHERE report_id=? AND page_no>=? ORDER BY page_no LIMIT ?",
                        (rid, max(1, start), count))
    return {"pages": [dict(p) for p in rows]}


@router.get("/{rid}/read")
def read(rid: int, start: int = 1, count: int = 4, raw: bool = False, conn: sqlite3.Connection = Depends(get_db)):
    """Pages as reading blocks (headings, paragraphs, lists, figure text), with the raw text as a fallback."""
    _get(conn, rid)
    count = max(1, min(count, 16))
    out = []
    for p in conn.execute("SELECT page_no, label, text, blocks FROM report_pages WHERE report_id=? AND page_no>=? ORDER BY page_no LIMIT ?",
                          (rid, max(1, start), count)):
        out.append({"page_no": p["page_no"], "label": p["label"], "blocks": jloads(p["blocks"], []) if p["blocks"] else None,
                    "text": p["text"] if raw or p["blocks"] is None else None})
    return {"pages": out}


@router.get("/{rid}/search")
def search(rid: int, q: str, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    fq = _fts_query(q)
    if not fq:
        return {"results": []}
    rows = conn.execute(
        "SELECT p.page_no, p.label, snippet(report_pages_fts, 0, char(2), char(3), '…', 24) AS snip FROM report_pages_fts f"
        " JOIN report_pages p ON p.id=f.rowid WHERE report_pages_fts MATCH ? AND p.report_id=? ORDER BY p.page_no LIMIT 100", (fq, rid))
    return {"results": [dict(r) for r in rows]}


@router.get("/{rid}/file")
def download(rid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = _get(conn, rid)
    if not r["file_name"]:
        raise HTTPException(404, "No document stored")
    path = process.document_path(r["file_name"])
    if not path.exists():
        raise HTTPException(404, "The stored document is missing")
    name = re.sub(r"[^\w.\- ]+", "_", r["original_filename"] or f"report-{rid}.pdf")
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    # Always a download, never rendered inside the app's origin.
    return FileResponse(path, media_type="application/pdf", filename=name, content_disposition_type="attachment",
                        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"})


# ------------------------------------------------------------------ findings
class FindingIn(BaseModel):
    page: int | None = Field(None, ge=1, le=5000)
    quote: str | None = Field(None, max_length=2000)
    title: str | None = Field(None, max_length=200)
    summary: str | None = Field(None, max_length=1200)
    category: str | None = None
    evidence_type: str | None = None
    techniques: list[str] | None = Field(None, max_length=20)
    cves: list[str] | None = Field(None, max_length=20)
    actors: list[str] | None = Field(None, max_length=12)
    technologies: list[str] | None = Field(None, max_length=20)
    sectors: list[str] | None = Field(None, max_length=10)
    regions: list[str] | None = Field(None, max_length=8)
    statistic: dict | None = None
    confidence: Literal["high", "medium", "low"] | None = None
    notes: str | None = Field(None, max_length=4000)
    origin: Literal["analyst", "summary"] = "analyst"
    review_status: Literal["unreviewed", "accepted", "rejected"] | None = None


@router.get("/{rid}/findings")
def list_findings(rid: int, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    rows = [F.row(r) for r in conn.execute(
        "SELECT * FROM report_findings WHERE report_id=? ORDER BY page_no, id", (rid,))]
    counts = {k: sum(1 for f in rows if f["review_status"] == k) for k in F.REVIEW}
    runs = [dict(r) for r in conn.execute("SELECT * FROM report_ai_runs WHERE report_id=? ORDER BY id DESC LIMIT 10", (rid,))]
    return {"findings": rows, "counts": counts, "runs": runs, "ai": ai_extract.estimate(conn, rid),
            "categories": F.CATEGORIES, "evidence": F.EVIDENCE}


@router.post("/{rid}/findings")
def add_finding(rid: int, body: FindingIn, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    try:
        f = F.build(conn, rid, body.model_dump())
    except F.FindingError as e:
        raise HTTPException(422, str(e)) from None
    with tx(conn):
        fid, created = F.insert(conn, rid, f, body.origin)
    if not created:
        raise HTTPException(409, "A finding already quotes that passage")
    return {"id": fid}


class SuggestIn(BaseModel):
    page: int = Field(..., ge=1, le=5000)
    quote: str = Field(..., max_length=2000)


@router.post("/{rid}/findings/suggest")
def suggest_finding(rid: int, body: SuggestIn, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    return F.suggest(conn, rid, body.page, body.quote)


@router.patch("/{rid}/findings/{fid}")
def update_finding(rid: int, fid: int, body: FindingIn, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    data = body.model_dump(exclude_unset=True)
    data.pop("origin", None)
    try:
        F.update(conn, rid, fid, data)
    except LookupError:
        raise HTTPException(404, "Finding not found") from None
    except F.FindingError as e:
        raise HTTPException(422, str(e)) from None
    return {"ok": True}


@router.delete("/{rid}/findings/{fid}")
def delete_finding(rid: int, fid: int, conn: sqlite3.Connection = Depends(get_db)):
    r = conn.execute("SELECT origin FROM report_findings WHERE id=? AND report_id=?", (fid, rid)).fetchone()
    if not r:
        raise HTTPException(404, "Finding not found")
    if r["origin"] == "ai":  # kept as rejected so a re-run does not bring it back
        raise HTTPException(409, "Reject AI findings instead of deleting them")
    conn.execute("DELETE FROM report_findings WHERE id=?", (fid,))
    return {"ok": True}


class RunIn(BaseModel):
    confirm_usd: float = Field(..., ge=0)  # the estimate the person agreed to


@router.post("/{rid}/ai/run")
def start_ai(rid: int, body: RunIn, conn: sqlite3.Connection = Depends(get_db)):
    r = _get(conn, rid)
    if r["status"] not in ("processed", "needs_review"):
        raise HTTPException(409, "Extract the text first")
    est = ai_extract.estimate(conn, rid)
    if est["estimate_usd"] > body.confirm_usd + 0.05:
        raise HTTPException(409, f"The estimate changed to about US${est['estimate_usd']:.2f}; check it and start again")
    try:
        run_id = ai_extract.start(conn, rid)
    except ai_extract.RunError as e:
        raise HTTPException(409, str(e)) from None
    return {"run_id": run_id}


@router.post("/{rid}/ai/cancel")
def cancel_ai(rid: int, conn: sqlite3.Connection = Depends(get_db)):
    _get(conn, rid)
    n = conn.execute("UPDATE report_ai_runs SET status='cancelled', detail='Cancelled', finished_at=? WHERE report_id=? AND status='queued'",
                     (now_iso(), rid)).rowcount
    n += conn.execute("UPDATE report_ai_runs SET status='cancelled' WHERE report_id=? AND status='running'", (rid,)).rowcount
    return {"ok": True, "cancelled": n}
