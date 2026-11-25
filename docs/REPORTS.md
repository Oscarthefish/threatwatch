# Intelligence Reports Library

Turns published threat reports (annual, quarterly and specialist research from vendors, incident responders and
government agencies) into a private, page-referenced knowledge base. Later phases extract attributable findings,
consolidate attacker behaviours across reports and connect them to Threat Landscapes and defensive planning.

Status: **Phases 1 and 2 built**: library, registry, upload, page-referenced text, reading view, rule-based summary, and findings (by hand or optional AI) with verified quotes. Phases 2 to 7 are planned below.

## 1. Architecture assessment (2026-11-25)

Threat Watch is a FastAPI + SQLite (WAL, FTS5) API, an APScheduler worker in a second container, and a React/TypeScript
PWA, deployed with Docker Compose on a 1 GB droplet (web 192 MB, worker 256 MB, read-only root, `/data` volume).

**Reused as is**
- Migrations, FTS5 search (and its safe query builder), the `tx` helper, settings store.
- Authentication on every route, the `X-TW-Request` CSRF header, the strict CSP, plain-text rendering (no `innerHTML`).
- The worker's job scheduler (a new 20-second job) and its start-up recovery pattern.
- UI: page header, tabs, sheets with the sticky action bar, filters, chips, empty and error states, the confirm dialog.
- MITRE ATT&CK v20.1 tables (`attack_techniques`, `attack_revoked`, `attack_links`) for Phase 2 validation of technique IDs.
- Threat Landscapes: profiles with provenance-tagged facts, the deterministic engine, telemetry and control states, readiness,
  playbooks, exercises and interview prep. Phases 5 and 7 extend these rather than rebuild them.
- Vulnerability records (CVE.org, CISA KEV, EPSS) for Phase 2 CVE linking.
- AI module (`app/intel/ai.py`): structured output, a daily budget and usage logging, if Phase 2 uses it (see the decision below).

**Genuinely new**
- Document storage and a safe PDF text pipeline (no PDF handling existed).
- A report series registry, separate from news feed sources: reports are editions, not feed items, and are kept forever.
- Page-level text with search; sections from PDF bookmarks; processing history.
- Later: findings, canonical behaviours, cross-source correlation, telemetry catalogue (the existing `TELEMETRY` list in
  `landscape/kb.py` is the starting point).

**Not added:** no new stack, no multipart parser (uploads are a raw body), no OCR engine, no background queue
service. The only new dependency is `pypdf` (pure Python, no system libraries).

## 2. Phase 1: what is built

### Data model (migration `008_reports.sql`)
| Table | Purpose |
|---|---|
| `report_sources` | Report series registry: publisher, series, official page (once verified), expected frequency, category, region, priority, discovery method (manual only for now), verification date, access notes, health fields for Phase 4. |
| `reports` | One row per edition: bibliographic metadata, a `meta_source` map recording where each field came from (you, PDF metadata, file name, series), document facts (SHA-256, size, stored name, retrieval), processing status and confidence, review status, bookmark. |
| `report_pages` + `report_pages_fts` | Extracted text per physical page with its printed label when the PDF defines one; full-text index kept in step by triggers. |
| `report_sections` | Sections from the PDF's bookmarks, with page ranges. |
| `report_jobs` | Processing history: extractor and version, pages, pages with text, characters, sections, result. |

Statuses: `discovered` (known by link, no document) → `queued` → `processing` → `processed`, `needs_review` or `failed`.

### Flow
1. **Upload** (`POST /api/reports/upload`, raw PDF body). Streamed to `data/reports/.incoming` with the size cap enforced
   while reading; must contain the `%PDF-` signature; SHA-256 computed. A duplicate hash is refused with a link to the
   existing report. The file is stored as `data/reports/<sha256>.pdf` (mode 600). The original file name is a label only.
2. **Extraction** (worker job every 20 s, or `python -m app.cli process-reports`). `pdfchild.py` runs in a child process
   with no environment variables (so no API keys), may not create files, has a CPU limit of 150 s and an address-space cap
   (`TW_REPORTS_CHILD_MEM_MB`, 224 MB), and a 180 s wall-clock timeout. It reads the text layer page by page, the PDF's
   bookmarks, page labels and document metadata. JavaScript, forms, attachments and links inside the PDF are ignored.
3. **Assessment**. Pages with at least 80 characters count as having text. Confidence is high (90% or more), medium
   (60% or more) or low. Low confidence or a page-cap truncation sets `needs_review`; password-protected, damaged and
   over-limit files set `failed` with a plain explanation.
4. **Metadata**. A plausible PDF title replaces a title derived from the file name. The PDF creation date and author are
   shown as hints and never fill the publication date or publisher. Linking a report to a registry series fills only
   empty fields, marked "From the series". Your edits are marked "Entered by you" and are never overwritten by re-processing.
5. **Re-processing** replaces pages and sections in one transaction and adds a history row. A worker restart mid-run
   re-queues the report.

### Registry
40 seeded series (from the brief's four priority tiers), all disabled, with no page URL and marked unverified. The
expected frequency is shown as "(unverified)" until you tick "I have checked the publication page, report name and
frequency". Deleting a seeded series is remembered, so it is not re-added. Series that overlap existing news sources
(Red Canary, Unit 42, Microsoft, Google/Mandiant, Hudson Rock, CISA, ASD) say so in their notes.

### UI
- **Reports library** (Intelligence menu): search across titles and full text (results jump to the first matching page),
  status filters with counts, publisher, category and coverage filters, sort, bookmarks; upload; add a report by link.
- **Report**: Overview (processing state and actions, suggested series, details with provenance, document facts,
  processing history, other editions), Contents (bookmarks with page ranges), Page text (page viewer with printed page
  labels, in-report search with highlighted snippets).
- **Report series**: the registry grouped by priority, with add, edit, verify and remove.

### Tests
`backend/tests/test_reports.py` (18 tests, synthetic PDFs built in `tests/pdfgen.py`): upload and extraction with page
and section references; search; duplicate refused; non-PDF, wrong content type, empty and oversized rejected with no
leftover temp files; malformed PDF fails cleanly; password-protected PDF reported; image-only PDF needs review; page cap
flagged; re-processing keeps your edits and keeps search in step; invalid dates, URLs, regions, frequencies and series
ids refused; discovered-then-uploaded; hostile file names stay labels; path traversal refused; series suggestion;
registry idempotent and respects deletion; delete removes the file; stale jobs re-queued; the child gets no secrets;
instruction-like text in a PDF is stored as inert text. Full suite: 133 passed.

Manual checks: the FBI IC3 2024 report (47 pages, 3 MB) processed in about 1 s with a 41 MB peak on Linux, 45 of 47
pages with text. A 30 MB cap produced the clean "limits" failure. UI: 0 axe violations and no horizontal overflow on the
library, search, report overview, contents, page text, edit and upload sheets and the registry, at 390 and 1366 px in
light and dark.

### Reading view and summary (migration `009_report_reading.sql`, `app/reports/reading.py`)
Built from the stored page text by layout rules, with no AI and no PDF re-read, so it can be improved and re-run
(`analysis_version`; the worker rebuilds older analyses at start-up).
- **Reading blocks per page:** running headers, footers and page numbers are found as short lines repeated at the top or
  bottom of many pages and set aside. Wrapped lines are rejoined into paragraphs; headings, bullet lists and wrapped
  two-line headings are recognised. Runs of short fragments are folded into "Text from a figure or diagram". Letter-spacing
  artefacts such as "T able" are repaired. The original text is always one click away.
- **Chapters:** numbered running labels ("03 INFRASTRUCTURE") give chapter ranges, titled from the chapter's opening page.
- **Summary:** key-takeaway lists; the publisher's recommendations (headed paragraphs on playbook or recommendation
  pages); sentences that quote figures (CVE IDs, model numbers and years are not counted as figures); threat actors,
  malware, CVEs (with CVSS and CISA KEV status when Threat Watch has the record) and products named in the text, using
  the existing entity lists; ATT&CK techniques, either cited by ID (validated, revoked IDs resolved) or named in the text
  (labelled as a Threat Watch match, never as the publisher's mapping; generic names such as "Multi-Factor
  Authentication" are skipped).
- **Vendor product guidance:** passages that name the publisher's own products (a short list per major vendor, or the
  publisher's name used possessively or with "customers" or "platform") are labelled and kept out of the recommendations.
- **Title:** a machine-generated file name (for example a UUID) is replaced by the running header or the first page's text.

Tuned on the SentinelOne Annual Threat Report 2026 (70 pages): 8 chapters matching its contents page, 24 key takeaways,
36 recommendations, 32 vendor passages kept apart, 7 quoted figures, 4 CVEs, 11 named techniques. Text from that report
is not stored in the repository; the tests use synthetic text with the same layout patterns.

### Limitations
- The summary is extraction, not understanding: it finds passages by layout, so a report with an unusual design yields less.
- Text layer only. Image-based PDFs are flagged for review; OCR is not built (it would need Tesseract, about 30 MB in
  the image and heavy CPU on a 1 GB server).
- Sections come from PDF bookmarks or numbered running labels; reports with neither have no chapter list.
- Multi-column and designed layouts can interleave text; tables come through as plain text.
- No automatic discovery yet; the registry is a list to verify.
- The extractor's address-space cap does not work under x86 emulation on Apple silicon (`deploy/local.sh` with an
  amd64 image); there it fails with "stopped unexpectedly". The live server is native x86-64.

## 3. Phase 2: findings (built)

A finding is one citable passage: an observation, a figure, a conclusion, a claim, a recommendation or a stated
limitation, stored with its exact quote and page (`report_findings`, migration 010).

**Rules applied to every finding, whoever proposes it** (`app/reports/findings.py`)
- The quote (12 to 600 characters) must appear on the cited page. Matching ignores whitespace, line wraps, curly
  quotes and dash styles, and accepts either the raw text or the reading view.
- Category from the brief's list of 27; evidence type from: documented incident observation, aggregated statistic,
  publisher's research conclusion, threat actor's unverified claim, publisher's recommended defence, your own observation.
  "Analyst-validated" is the review status (accepted), not an evidence type.
- ATT&CK IDs are checked against v20.1 (revoked IDs resolved, unknown IDs dropped). An ID printed on the page is the
  publisher's mapping; any other is marked as a suggestion (yours or the AI's). CVE IDs are kept only if the page states them.
- Statistics carry value, population, period and definition as stated, with empty fields where the report is silent.
  Nothing adds or compares figures across reports.
- One finding per passage: re-running never duplicates, overwrites or revives a finding, including rejected ones.

**Adding findings by hand.** "Save as finding" on Summary items (takeaways, recommendations, figures) and "Add as finding"
for text selected in Read both open a form with the page and quote filled in. The rules pre-fill ATT&CK IDs, CVEs, actors
and technologies they can see in the passage. Findings a person writes start as accepted.

**AI extraction** (`app/reports/ai_extract.py`, off until started per report)
- Sends only the report's text, one chapter (or up to eight pages) per request, with page markers. Product guidance,
  figure labels and sentences naming the publisher's products are left out. No profiles, notes, other reports or
  settings are sent. The text is wrapped as untrusted data, the model has no tools, and output is schema-constrained.
- Every proposed finding goes through the rules above and must cite a page inside the section it was sent. Failures are
  counted and discarded. Kept findings arrive unreviewed and are labelled "AI" until you accept, edit or reject them.
- Cost: shown before the run (about US$0.38 for the 70-page SentinelOne report on Sonnet 5.5), confirmed in a dialog,
  capped per run (`TW_REPORTS_AI_MAX_RUN_USD`, 1.50; the run stops before a section that could pass the cap) and per month
  (`TW_REPORTS_AI_MONTHLY_BUDGET_USD`, 5.00). It does not touch the daily news budget or its request cap. Model and
  effort: `TW_REPORTS_AI_TIER` (deep = Sonnet, fast = Haiku), `TW_REPORTS_AI_EFFORT` (medium). Identical requests are
  served from the existing AI output cache at no cost.
- Each run records model, prompt version, sections done, tokens, cost, proposed, kept and discarded counts. A restart
  mid-run marks it failed; a run can be stopped from the page.

**Tests.** Quote verification (invented, wrong page, wrapped and curly-quoted text), enums, technique and CVE validation,
edit and review, delete rules, and the AI run with a stubbed model: product guidance not sent, only verified findings
kept, re-runs not duplicating or reviving rejected findings, daily news budget untouched, failures, the per-run cap,
the monthly budget and the consent check. The real model has not been called in tests; the first real run is the
first end-to-end check of the prompt.

## 4. Earlier decision: extraction method

**Structured extraction method.** Reliable extraction of individual, attributable findings from report prose is not
realistic with rules alone. Options:

| Option | Quality | Cost | Notes |
|---|---|---|---|
| A. Analyst-entered findings, with deterministic helpers (ATT&CK IDs, CVEs, percentages and sample phrases detected per page; one click to cite the page) | High where you enter them; slow | Free | Works offline; nothing leaves the server. |
| B. Claude per section, opt-in per report, strict JSON schema, every finding must quote text present on its cited page (verified server-side), output marked "Extracted by AI, unreviewed" | Good first pass; needs review | Roughly US$0.20 to 0.50 per 60-page report with Sonnet 5.5, a few cents with Haiku 5.5 (the 47-page IC3 report is about 18k tokens of text; most cost is structured output) | Report text is published vendor content, not your profile data. Needs its own budget, separate from the US$0.50/day news cap. |
| C. Local model via Ollama | Lower than B on long technical prose | Free to run | Cannot run on the 1 GB droplet; would need the Mac or a larger server. |

Chosen 2026-11-26: A plus B, with B off by default and the estimated cost shown before each run. Profile data is never
sent. C can be added behind the same interface later if a machine is available.

## 5. Remaining phases

2. ~~Structured extraction~~: built (section 3).
3. **Behaviour knowledge base**: canonical behaviours linked to findings, merge and split with audit history; telemetry
   catalogue built on `landscape/kb.TELEMETRY`; monitoring, hunting, detection (draft queries labelled as such),
   hardening and readiness content per behaviour.
4. **Discovery**: per-series RSS or page checks through the existing SSRF-guarded fetcher, weekly by default, health and
   backoff, never past registration walls; discovered editions arrive as `discovered` with an upload option.
5. **Organisation integration**: findings and behaviours feed Threat Landscape relevance with the existing provenance
   rules (organisation, sector, region, known technology, generic, unknown); coverage states extended to the brief's
   ten-state scale.
6. **Correlation and history**: independence-aware corroboration (same incident, republication and independent
   observation kept apart), edition comparisons only where metrics are comparable, change summaries.
7. **Readiness and development**: intelligence-derived readiness questions and exercises; interview questions citing
   findings; Markdown exports with scope, sources, dates, confidence, assumptions and unknowns.

## 6. Security notes
- Uploaded documents and extracted text are untrusted data. They are rendered only as plain text; nothing in a report is
  executed, followed or treated as an instruction. A test stores an instruction-like line and a `<script>` tag as inert text.
- The parser runs in a separate, limited process so a malicious or pathological PDF cannot exhaust the worker or read secrets.
- Documents are stored by hash inside the data volume, never in the repository, and downloads are always attachments
  (`nosniff`, `no-store`), never rendered inside the app's origin.
- Upload size is capped while streaming (`TW_REPORTS_MAX_MB`, 50); partial uploads are removed, and stale ones are
  cleaned at worker start.
- Nothing in Phase 1 fetches URLs. Publication links are stored and shown only as validated `http(s)` links.
- Copyright: reports are stored privately for personal analysis. Exports (Phase 7) quote short, attributed findings
  with page references rather than redistributing report text.
