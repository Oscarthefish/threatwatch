"""Report documents: storage, registration and text extraction.

Flow: the API streams an upload to ``<data_dir>/reports/.incoming`` with a size cap, checks the PDF signature
and hashes it; ``register`` moves it to ``<data_dir>/reports/<sha256>.pdf`` and queues the report. The worker
calls ``process_queued``, which runs ``pdfchild.py`` in a resource-limited child process and stores page text
with page numbers, PDF bookmarks as sections, and a processing-history row. Re-processing replaces only the
extracted text and sections in one transaction; metadata people entered is never touched.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

from ..config import get_settings
from ..db import jdumps, jloads, now_iso, tx

log = logging.getLogger("threatwatch.reports")

EXTRACTOR = "pypdf text layer"
EXTRACTOR_VERSION = 1
CHILD = Path(__file__).with_name("pdfchild.py")
MAX_CHARS_PER_PAGE = 40_000
TEXT_PAGE_MIN_CHARS = 80
SHA = re.compile(r"^[0-9a-f]{64}$")

MESSAGES = {
    "encrypted": "The PDF is password-protected. Remove the password and upload it again.",
    "unreadable": "The file could not be read as a PDF. It may be damaged or not a real PDF.",
    "limits": "Processing stopped because the document went over the time or memory limit.",
    "crashed": "The text extractor stopped unexpectedly.",
    "missing": "The stored document is missing. Upload it again.",
}


class DuplicateDocument(Exception):
    def __init__(self, report_id: int):
        super().__init__(report_id)
        self.report_id = report_id


def reports_dir() -> Path:
    d = get_settings().data_dir / "reports"
    (d / ".incoming").mkdir(parents=True, exist_ok=True)
    return d


def document_path(file_name: str) -> Path:
    """Only ever a sha256-derived name inside the reports directory; anything else is refused."""
    stem = file_name.removesuffix(".pdf")
    if not SHA.match(stem) or file_name != f"{stem}.pdf":
        raise ValueError("invalid stored file name")
    return reports_dir() / file_name


def display_filename(name: str | None) -> str | None:
    """The uploaded file's name is kept as a label only (never used as a path)."""
    if not name:
        return None
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()[:200]
    return name or None


def title_from_filename(name: str | None) -> str:
    base = re.sub(r"\.pdf$", "", name or "", flags=re.I)
    base = re.sub(r"[_]+", " ", base)
    base = re.sub(r"(?<=[a-z])-(?=[a-z])", " ", base, flags=re.I)
    base = re.sub(r"\s+", " ", base).strip()
    return base[:200] or "Untitled report"


def register(conn: sqlite3.Connection, tmp: Path, sha256: str, size: int, filename: str | None,
             report_id: int | None = None) -> int:
    """Attach an uploaded document to a new report, or to an existing one that has no document yet.
    Raises DuplicateDocument if the same bytes are already stored (the temp file is removed)."""
    dup = conn.execute("SELECT id FROM reports WHERE sha256=?", (sha256,)).fetchone()
    if dup:
        tmp.unlink(missing_ok=True)
        raise DuplicateDocument(dup[0])
    dest = document_path(f"{sha256}.pdf")
    os.replace(tmp, dest)
    os.chmod(dest, 0o600)
    now = now_iso()
    label = display_filename(filename)
    with tx(conn):
        if report_id is None:
            cur = conn.execute(
                "INSERT INTO reports(title, meta_source, sha256, file_name, original_filename, file_size, retrieved_at, retrieval,"
                " status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,'queued',?,?)",
                (title_from_filename(label), jdumps({"title": "filename"}), sha256, dest.name, label, size, now, "upload", now, now))
            report_id = cur.lastrowid
        else:
            conn.execute(
                "UPDATE reports SET sha256=?, file_name=?, original_filename=?, file_size=?, retrieved_at=?, retrieval='upload',"
                " status='queued', status_detail=NULL, updated_at=? WHERE id=?",
                (sha256, dest.name, label, size, now, now, report_id))
    return report_id


def queue(conn: sqlite3.Connection, report_id: int) -> None:
    conn.execute("UPDATE reports SET status='queued', status_detail=NULL, updated_at=? WHERE id=? AND file_name IS NOT NULL",
                 (now_iso(), report_id))


def recover_stale(conn: sqlite3.Connection) -> int:
    """A worker restart mid-extraction leaves rows in 'processing'; put them back in the queue."""
    with tx(conn):
        conn.execute("UPDATE report_jobs SET status='failed', detail='Interrupted by a restart', finished_at=? "
                     "WHERE status='running'", (now_iso(),))
        return conn.execute("UPDATE reports SET status='queued' WHERE status='processing'").rowcount


def _run_child(path: Path) -> dict:
    s = get_settings()
    args = [sys.executable, "-I", str(CHILD), str(path), str(s.reports_max_pages), str(MAX_CHARS_PER_PAGE), str(s.reports_child_mem_mb)]
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}  # deliberately no secrets
    try:
        p = subprocess.run(args, capture_output=True, timeout=s.reports_timeout_seconds, env=env, stdin=subprocess.DEVNULL,
                           cwd=str(CHILD.parent), check=False)
    except subprocess.TimeoutExpired:
        return {"error": "limits"}
    if p.returncode != 0 and not p.stdout:
        # SIGKILL / SIGXCPU from the resource limits, or a crash
        return {"error": "limits" if p.returncode in (-9, -24, 137, 152) else "crashed",
                "detail": (p.stderr or b"").decode("utf-8", "replace")[-300:]}
    try:
        return json.loads(p.stdout.decode("utf-8", "replace"))
    except ValueError:
        return {"error": "crashed", "detail": "invalid extractor output"}


def _plausible_title(t: str | None) -> bool:
    if not t or len(t) < 6 or len(t) > 200:
        return False
    low = t.lower()
    return not (low.startswith(("untitled", "microsoft word", "powerpoint", "document")) or re.search(r"\.(docx?|pptx?|indd|ai)$", low))


def _sections(outline: list[dict], pages: int) -> list[dict]:
    items = [o for o in outline if isinstance(o, dict) and o.get("title") and isinstance(o.get("page"), int) and 1 <= o["page"] <= pages]
    out = []
    for i, o in enumerate(items):
        end = pages
        for nxt in items[i + 1:]:
            if nxt["level"] <= o["level"]:
                end = max(o["page"], nxt["page"] - 1) if nxt["page"] > o["page"] else o["page"]
                break
        out.append({"title": o["title"][:200], "level": int(o.get("level") or 1), "start": o["page"], "end": end})
    return out


def assess(result: dict) -> tuple[str, str | None, str]:
    """(status, detail, confidence) from an extraction result."""
    pages = result["pages"]
    n = len(pages)
    text_pages = sum(1 for p in pages if len(p["text"]) >= TEXT_PAGE_MIN_CHARS)
    ratio = text_pages / n if n else 0
    notes = []
    if n == 0:
        return "needs_review", "The PDF has no pages.", "low"
    conf = "high" if ratio >= 0.9 else "medium" if ratio >= 0.6 else "low"
    if result.get("page_errors"):
        notes.append(f"Text could not be read from {result['page_errors']} page(s).")
        conf = "medium" if conf == "high" else conf
    if result.get("truncated"):
        notes.append(f"Only the first {n} of {result['total_pages']} pages were processed.")
    if conf == "low":
        notes.insert(0, f"Only {text_pages} of {n} pages have a usable text layer, so the document is probably image-based. "
                        "OCR is not enabled.")
    status = "needs_review" if conf == "low" or result.get("truncated") else "processed"
    return status, " ".join(notes) or None, conf


def process(conn: sqlite3.Connection, report_id: int) -> str:
    row = conn.execute("SELECT id, file_name, title, meta_source FROM reports WHERE id=?", (report_id,)).fetchone()
    if not row or not row["file_name"]:
        return "skipped"
    started = now_iso()
    with tx(conn):
        conn.execute("UPDATE reports SET status='processing', updated_at=? WHERE id=?", (started, report_id))
        job = conn.execute("INSERT INTO report_jobs(report_id, kind, status, extractor, extractor_version, started_at)"
                           " VALUES (?,?,?,?,?,?)", (report_id, "extract", "running", EXTRACTOR, EXTRACTOR_VERSION, started)).lastrowid
    try:
        path = document_path(row["file_name"])
        result = _run_child(path) if path.exists() else {"error": "missing"}
    except Exception:  # never leave a row stuck in 'processing'
        log.exception("report %s: extraction failed", report_id)
        result = {"error": "crashed"}
    now = now_iso()
    if "error" in result:
        msg = MESSAGES.get(result["error"], MESSAGES["crashed"])
        log.info("report %s: extraction %s", report_id, result["error"])
        with tx(conn):
            conn.execute("UPDATE reports SET status='failed', status_detail=?, updated_at=? WHERE id=?", (msg, now, report_id))
            conn.execute("UPDATE report_jobs SET status='failed', detail=?, finished_at=? WHERE id=?", (msg, now, job))
        return "failed"

    pages = result["pages"]
    status, detail, conf = assess(result)
    sections = _sections(result.get("outline") or [], len(pages))
    text_pages = sum(1 for p in pages if len(p["text"]) >= TEXT_PAGE_MIN_CHARS)
    meta = result.get("meta") or {}
    meta_source = jloads(row["meta_source"], {}) or {}
    title = row["title"]
    if meta_source.get("title") == "filename" and _plausible_title(meta.get("title")):
        title, meta_source["title"] = meta["title"], "pdf"
    with tx(conn):
        conn.execute("DELETE FROM report_pages WHERE report_id=?", (report_id,))
        conn.execute("DELETE FROM report_sections WHERE report_id=?", (report_id,))
        conn.executemany("INSERT INTO report_pages(report_id, page_no, label, text, chars) VALUES (?,?,?,?,?)",
                         [(report_id, p["n"], p.get("label"), p["text"], len(p["text"])) for p in pages])
        conn.executemany("INSERT INTO report_sections(report_id, ord, level, title, page_start, page_end, origin) VALUES (?,?,?,?,?,?,'outline')",
                         [(report_id, i, s["level"], s["title"], s["start"], s["end"]) for i, s in enumerate(sections)])
        conn.execute(
            "UPDATE reports SET title=?, meta_source=?, page_count=?, pdf_meta=?, status=?, status_detail=?, extraction_method=?,"
            " extraction_version=?, extraction_confidence=?, text_pages=?, processed_at=?, updated_at=? WHERE id=?",
            (title, jdumps(meta_source), result.get("total_pages", len(pages)), jdumps(meta), status, detail, EXTRACTOR,
             EXTRACTOR_VERSION, conf, text_pages, now, now, report_id))
        conn.execute("UPDATE report_jobs SET status=?, pages=?, text_pages=?, chars=?, sections=?, detail=?, finished_at=? WHERE id=?",
                     ("ok" if status == "processed" else status, len(pages), text_pages, sum(len(p["text"]) for p in pages),
                      len(sections), detail, now, job))
    log.info("report %s: %s, %d pages, %d with text, %d sections", report_id, status, len(pages), text_pages, len(sections))
    analyse(conn, report_id)
    return status


MACHINE_NAME = re.compile(r"^(?:[0-9a-f]{8}[- ]?[0-9a-f]{4}[- ]?[0-9a-f]{4}[- ]?[0-9a-f]{4}[- ]?[0-9a-f]{12}|[0-9a-f -]{16,}|[\d _-]+"
                          r"|(?:scan|document|download|file|report|untitled)[\d _-]*)$", re.I)


def analyse(conn: sqlite3.Connection, report_id: int) -> bool:
    """Reading blocks and highlights from the stored page text. Safe to re-run; never touches fields a person set."""
    from . import reading

    r = conn.execute("SELECT id, title, publisher, meta_source, original_filename FROM reports WHERE id=?", (report_id,)).fetchone()
    if not r:
        return False
    rows = conn.execute("SELECT id, text FROM report_pages WHERE report_id=? ORDER BY page_no", (report_id,)).fetchall()
    if not rows:
        return False
    try:
        a = reading.analyse(conn, [p["text"] for p in rows], r["publisher"])
    except Exception:  # a heuristic failure must never break the report
        log.exception("report %s: analysis failed", report_id)
        return False
    meta_source = jloads(r["meta_source"], {}) or {}
    title = r["title"]
    stem = re.sub(r"\.pdf$", "", r["original_filename"] or "", flags=re.I)
    if meta_source.get("title") == "filename" and (not stem or MACHINE_NAME.match(stem)):
        first = [ln.strip() for ln in rows[0]["text"].split("\n") if ln.strip()][:4]
        guess = a["running_title"] or (" ".join(first) if first and sum(map(len, first)) <= 120 else None)
        if guess and len(guess) >= 6:
            title, meta_source["title"] = re.sub(r"\s+", " ", guess)[:200], "layout"
    summary = {k: v for k, v in a.items() if k != "pages"}
    with tx(conn):
        conn.executemany("UPDATE report_pages SET blocks=?, labels=? WHERE id=?",
                         [(jdumps(pg["blocks"]), jdumps(pg["labels"]), row["id"]) for pg, row in zip(a["pages"], rows)])
        conn.execute("UPDATE reports SET analysis=?, analysis_version=?, title=?, meta_source=? WHERE id=?",
                     (jdumps(summary), a["version"], title, jdumps(meta_source), report_id))
    return True


def reanalyse_stale(conn: sqlite3.Connection) -> int:
    """Re-run the reading analysis for reports processed with an older version (no PDF re-read needed)."""
    from .reading import ANALYSIS_VERSION

    ids = [r[0] for r in conn.execute(
        "SELECT id FROM reports WHERE status IN ('processed','needs_review') AND COALESCE(analysis_version,0) < ?", (ANALYSIS_VERSION,))]
    return sum(1 for rid in ids if analyse(conn, rid))


def process_queued(conn: sqlite3.Connection, limit: int = 3) -> int:
    ids = [r[0] for r in conn.execute("SELECT id FROM reports WHERE status='queued' ORDER BY updated_at LIMIT ?", (limit,))]
    for rid in ids:
        process(conn, rid)
    return len(ids)


def delete_document(file_name: str | None) -> None:
    if file_name:
        try:
            document_path(file_name).unlink(missing_ok=True)
        except ValueError:
            pass


def clean_incoming(max_age_seconds: int = 3600) -> int:
    """Remove partial uploads left behind by a dropped connection."""
    import time

    n = 0
    for f in (reports_dir() / ".incoming").iterdir():
        try:
            if time.time() - f.stat().st_mtime > max_age_seconds:
                f.unlink()
                n += 1
        except OSError:
            pass
    return n
