"""Optional AI extraction of report findings, started by a person for one report at a time.

What is sent: the report's own extracted text, one chapter (or a few pages) per request, with page markers. Passages
labelled as the publisher's product guidance and figure labels are left out. Nothing else is sent: no profiles, notes,
other reports or settings. The text is wrapped as untrusted data, and the model has no tools.

What is kept: only findings whose quote appears on the cited page, with known categories and evidence types; ATT&CK IDs
validated against ATT&CK v20.1; CVE IDs only if the page states them. Findings arrive unreviewed. Re-running never
overwrites or revives a finding that already exists for the same passage, including ones a person rejected.

Cost: estimated before the run, capped per run, and counted against a monthly budget of its own, separate from the
daily news budget.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

from ..config import get_settings
from ..db import jloads, now_iso, tx
from ..intel import ai
from . import findings as F
from . import reading

log = logging.getLogger("threatwatch.reports.ai")

PROMPT_VERSION = 1
MAX_CHUNK_PAGES = 8
MAX_CHUNK_CHARS = 22_000
MAX_OUTPUT_TOKENS = 6000
EXPECTED_OUTPUT_TOKENS = 2500  # typical per chunk, for the estimate
SYSTEM_TOKENS = 1400

SYSTEM = """You extract individual, attributable intelligence findings from one section of a published cyber threat report,
for a SOC analyst building an evidence base. You are not summarising the report.

A finding is one specific observation, statistic, conclusion, claim, recommendation or stated limitation that someone
could cite on its own. Prefer specific, defensible findings: documented incidents and techniques, statistics with their
stated population, concrete defensive recommendations, and the report's own caveats. Skip marketing, generic scene-setting,
repetition, and anything about the publisher's own products. At most 15 findings for the section; fewer is fine.

For each finding:
- page: the number from the [Page N] marker above the passage.
- quote: copy one contiguous passage EXACTLY as it appears on that page, 40 to 400 characters, no ellipses, no edits.
  It is checked character for character against the page; a quote that does not match is discarded.
- title: a short neutral label (under 12 words). summary: one or two sentences in plain words, adding nothing the passage
  does not say.
- evidence_type: incident_observation (a specific incident or case the publisher documented), aggregate_statistic (a
  figure across many cases or customers), vendor_conclusion (the publisher's interpretation or trend claim),
  actor_claim (something a threat actor asserted, unverified), vendor_recommendation (defensive advice).
- category: the best fit from the list.
- techniques: MITRE ATT&CK Enterprise technique IDs only when the passage clearly describes that behaviour. Use an ID only
  if you are sure it exists; leave empty when unsure. Never map just to add coverage.
- cves: only CVE IDs written in the text. actors, technologies, sectors: names written in the text. regions: from the list,
  only when the text names the geography.
- statistic: for figures, the value and, exactly as stated, the population or denominator, the period and what is being
  measured; empty strings when the report does not state them. Never combine or recalculate numbers.
- confidence: how clearly the passage supports the finding (high, medium, low).
Do not infer facts about any organisation that is not described in the text."""

SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["findings"],
    "properties": {"findings": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["page", "quote", "title", "summary", "evidence_type", "category", "techniques", "cves", "actors",
                     "technologies", "sectors", "regions", "statistic", "confidence"],
        "properties": {
            "page": {"type": "integer"},
            "quote": {"type": "string"},
            "title": {"type": "string"},
            "summary": {"type": "string"},
            "evidence_type": {"type": "string", "enum": [k for k in F.EVIDENCE if k != "user_observation"]},
            "category": {"type": "string", "enum": list(F.CATEGORIES)},
            "techniques": {"type": "array", "items": {"type": "string"}},
            "cves": {"type": "array", "items": {"type": "string"}},
            "actors": {"type": "array", "items": {"type": "string"}},
            "technologies": {"type": "array", "items": {"type": "string"}},
            "sectors": {"type": "array", "items": {"type": "string"}},
            "regions": {"type": "array", "items": {"type": "string", "enum": sorted(F.REGIONS)}},
            "statistic": {"type": "object", "additionalProperties": False, "required": ["value", "population", "period", "definition"],
                          "properties": {k: {"type": "string"} for k in ("value", "population", "period", "definition")}},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        }}}},
}


def _page_text(blocks: list[dict] | None, raw: str, vpat=None) -> str:
    if not blocks:
        return raw.strip()
    out = []
    for b in blocks:
        if b.get("vendor") or b["type"] == "figure":
            continue
        text = b["text"] if b["type"] == "h" else reading.strip_vendor(b["text"], vpat)
        if text:
            out.append(("## " if b["type"] == "h" else "- " if b["type"] == "li" else "") + text)
    return "\n".join(out)


def chunks(conn: sqlite3.Connection, report_id: int) -> list[dict]:
    """Sections to send: chapters when known, otherwise runs of pages, each capped in pages and characters."""
    r = conn.execute("SELECT analysis, publisher FROM reports WHERE id=?", (report_id,)).fetchone()
    analysis = (jloads(r["analysis"], {}) or {}) if r else {}
    chapters = analysis.get("chapters", [])
    publisher = (r["publisher"] if r else None) or ((analysis.get("running_title") or "").split(" ")[0] or None)
    vpat = reading.vendor_pattern(reading._vendor_terms(publisher))
    pages = [(p["page_no"], _page_text(jloads(p["blocks"], None), p["text"], vpat))
             for p in conn.execute("SELECT page_no, text, blocks FROM report_pages WHERE report_id=? ORDER BY page_no", (report_id,))]
    pages = [(n, t) for n, t in pages if len(t) >= 80]

    def label(n: int) -> str | None:
        c = next((c for c in chapters if c["start"] <= n <= c["end"]), None)
        return f"{c['number']} {c['title']}" + (f": {c['subtitle']}" if c.get("subtitle") else "") if c else None

    out: list[dict] = []
    for n, t in pages:
        lab = label(n)
        cur = out[-1] if out else None
        if cur and cur["label"] == lab and len(cur["pages"]) < MAX_CHUNK_PAGES and cur["chars"] + len(t) <= MAX_CHUNK_CHARS:
            cur["pages"].append(n)
            cur["text"] += f"\n\n[Page {n}]\n{t}"
            cur["chars"] += len(t)
        else:
            out.append({"label": lab, "pages": [n], "text": f"[Page {n}]\n{t}", "chars": len(t)})
    return out


def _model() -> str:
    return ai.model_for(get_settings().reports_ai_tier)


def month_spend(conn: sqlite3.Connection) -> float:
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    v = conn.execute("SELECT COALESCE(SUM(cost_usd),0) FROM report_ai_runs WHERE substr(created_at,1,7)=?", (month,)).fetchone()[0]
    return float(v or 0)


def estimate(conn: sqlite3.Connection, report_id: int) -> dict:
    s = get_settings()
    cs = chunks(conn, report_id)
    tin = sum(int(c["chars"] / 3.6) + SYSTEM_TOKENS + 300 for c in cs)
    model = _model()
    return {
        "enabled": s.ai_enabled, "model": model, "chunks": len(cs), "pages": sum(len(c["pages"]) for c in cs),
        "input_tokens": tin, "estimate_usd": round(ai.cost_usd(model, tin, EXPECTED_OUTPUT_TOKENS * len(cs)), 2),
        "worst_usd": round(ai.cost_usd(model, tin, MAX_OUTPUT_TOKENS * len(cs)), 2),
        "cap_usd": s.reports_ai_max_run_usd, "month_spent_usd": round(month_spend(conn), 2),
        "month_budget_usd": s.reports_ai_monthly_budget_usd,
    }


class RunError(Exception):
    pass


def start(conn: sqlite3.Connection, report_id: int) -> int:
    s = get_settings()
    if not s.ai_enabled:
        raise RunError("AI is not configured on this server")
    if conn.execute("SELECT 1 FROM report_ai_runs WHERE report_id=? AND status IN ('queued','running')", (report_id,)).fetchone():
        raise RunError("An extraction is already running for this report")
    est = estimate(conn, report_id)
    if not est["chunks"]:
        raise RunError("This report has no extracted text to send")
    left = s.reports_ai_monthly_budget_usd - est["month_spent_usd"]
    if left < min(est["estimate_usd"], s.reports_ai_max_run_usd):
        raise RunError(f"Not enough left in this month's report AI budget (US${max(left, 0):.2f} of US${s.reports_ai_monthly_budget_usd:.2f})")
    with tx(conn):
        return conn.execute(
            "INSERT INTO report_ai_runs(report_id, status, model, prompt_version, chunks, estimate_usd, cap_usd, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (report_id, "queued", est["model"], PROMPT_VERSION, est["chunks"], est["estimate_usd"],
             min(s.reports_ai_max_run_usd, left), now_iso())).lastrowid


def _user(report: sqlite3.Row, chunk: dict) -> str:
    text = chunk["text"].replace("</untrusted_source", "</untrusted-source")
    head = f"Report: {report['title']}" + (f" (publisher: {report['publisher']})" if report["publisher"] else "")
    if chunk["label"]:
        head += f"\nSection: {chunk['label']}"
    return f"{head}\nPages in this section: {', '.join(map(str, chunk['pages']))}\n\n<untrusted_source>\n{text}\n</untrusted_source>"


def run(conn: sqlite3.Connection, run_id: int) -> str:
    s = get_settings()
    rr = conn.execute("SELECT * FROM report_ai_runs WHERE id=?", (run_id,)).fetchone()
    if not rr or rr["status"] != "queued":
        return "skipped"
    report = conn.execute("SELECT id, title, publisher FROM reports WHERE id=?", (rr["report_id"],)).fetchone()
    conn.execute("UPDATE report_ai_runs SET status='running', started_at=? WHERE id=?", (now_iso(), run_id))
    cs = chunks(conn, rr["report_id"])
    model = _model()
    spent = tin_total = tout_total = proposed = kept = rejected = done = 0
    status, detail = "done", None
    for c in cs:
        if conn.execute("SELECT status FROM report_ai_runs WHERE id=?", (run_id,)).fetchone()[0] == "cancelled":
            status, detail = "cancelled", "Cancelled"
            break
        worst = ai.cost_usd(model, int(c["chars"] / 3.6) + SYSTEM_TOKENS + 300, MAX_OUTPUT_TOKENS)
        if spent + worst > rr["cap_usd"]:
            status, detail = "stopped", f"Stopped before section {done + 1} of {len(cs)} to stay under the US${rr['cap_usd']:.2f} cap"
            break
        usage: dict = {}
        try:
            out = ai.structured(conn, kind="report_findings", system=SYSTEM, user=_user(report, c), schema=SCHEMA,
                                subject_type="report", subject_id=rr["report_id"], max_tokens=MAX_OUTPUT_TOKENS,
                                tier=s.reports_ai_tier, effort=s.reports_ai_effort, timeout=300, own_budget=True, usage_out=usage)
        except ai.AIUnavailable as e:
            spent += usage.get("cost_usd", 0.0)
            tin_total += usage.get("input_tokens", 0)
            tout_total += usage.get("output_tokens", 0)
            log.warning("report %s run %s: section %d failed: %s", rr["report_id"], run_id, done + 1, e)
            status, detail = "failed", f"Section {done + 1} of {len(cs)} failed: {e}"
            break
        spent += usage.get("cost_usd", 0.0)
        tin_total += usage.get("input_tokens", 0)
        tout_total += usage.get("output_tokens", 0)
        allowed = set(c["pages"])
        with tx(conn):
            for item in (out.get("findings") or [])[:20]:
                proposed += 1
                if item.get("page") not in allowed:
                    rejected += 1
                    continue
                try:
                    f = F.build(conn, rr["report_id"], item)
                except F.FindingError:
                    rejected += 1
                    continue
                _, created = F.insert(conn, rr["report_id"], f, "ai", run_id=run_id, model=usage.get("model") or model,
                                      prompt_version=PROMPT_VERSION)
                kept += int(created)
            done += 1
            conn.execute("UPDATE report_ai_runs SET chunks_done=?, input_tokens=?, output_tokens=?, cost_usd=?, proposed=?, kept=?, rejected=?"
                         " WHERE id=?", (done, tin_total, tout_total, round(spent, 4), proposed, kept, rejected, run_id))
    conn.execute("UPDATE report_ai_runs SET status=?, detail=?, chunks_done=?, input_tokens=?, output_tokens=?, cost_usd=?, proposed=?,"
                 " kept=?, rejected=?, finished_at=? WHERE id=?",
                 (status, detail, done, tin_total, tout_total, round(spent, 4), proposed, kept, rejected, now_iso(), run_id))
    log.info("report %s AI run %s: %s, %d/%d sections, %d kept, %d rejected, US$%.3f", rr["report_id"], run_id, status, done,
             len(cs), kept, rejected, spent)
    return status


def run_queued(conn: sqlite3.Connection) -> int:
    ids = [r[0] for r in conn.execute("SELECT id FROM report_ai_runs WHERE status='queued' ORDER BY id LIMIT 1")]
    for rid in ids:
        run(conn, rid)
    return len(ids)


def recover_stale(conn: sqlite3.Connection) -> int:
    return conn.execute("UPDATE report_ai_runs SET status='failed', detail='Interrupted by a restart', finished_at=? WHERE status='running'",
                        (now_iso(),)).rowcount
