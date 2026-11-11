# Architecture

```
                 Tailscale (WireGuard, HTTPS via Tailscale Serve)
 Phone / Desktop ───────────────────────────────────────────────► VPS 127.0.0.1:8080
   PWA (React)                                                     │
                                                  ┌────────────────┴────────────────┐
                                                  │ web  (uvicorn/FastAPI, 1 proc)  │  serves SPA + /api, auth, CSP
                                                  │ worker (APScheduler, 1 proc)    │  ingestion, briefing, digest, pruning
                                                  └────────────────┬────────────────┘
                                                        shared volume: /data/threatwatch.db (SQLite WAL)
                                                                   │ outbound HTTPS only
                     RSS/Atom feeds · NCSC NZ alerts page · CISA KEV JSON · FIRST EPSS API · CVE.org API · Anthropic API (optional)
```

## Why this stack

| Choice | Reason |
|---|---|
| FastAPI + sync sqlite3 | Small, explicit, low memory (~45 MB). No ORM needed for ~15 tables. |
| SQLite WAL + FTS5 | Single file, trivial backups, full-text search built in; WAL lets API and worker share it safely. Data volume is tiny (≈4 MB/200 articles). |
| Separate worker process | Long fetches/AI calls never block the API; worker crash doesn't take down the UI. Both containers together use ~105 MB idle, ~180 MB peak. |
| APScheduler (in-process) | Cron + interval jobs with Pacific/Auckland timezone; no Redis/Celery. |
| React + TanStack Query + Workbox | Responsive SPA, client caching, offline support via service worker. No CSS framework (13 kB CSS). |
| No Redis/Elasticsearch/K8s | Not needed at single-user scale (per brief). |

Plain SQL migrations (`backend/migrations/NNN_*.sql`, tracked in `schema_migrations`) were chosen over Alembic: no ORM models to autogenerate from, and the files are reviewable SQL.

## Backend layout

```
backend/app/
  config.py          env-driven settings (TW_*); secrets are SecretStr, never logged
  db.py              connections (WAL, FK, busy timeout), migrations, helpers
  auth.py            Argon2id, server-side sessions, CSRF header, login rate limiting
  main.py            app factory, security headers, SPA serving, auth routes
  api/               content (today/articles/breaking/vulns/search/sources/status), user (bookmarks/history/notifications/push), watches
  ingest/fetcher.py  SSRF-guarded HTTP fetch (public IPs only, ports 80/443, per-hop redirect validation, size caps, politeness)
  ingest/sanitize.py untrusted HTML → bounded plain text (nh3)
  ingest/sources.py  source catalogue + adapters (RSS/Atom, NCSC NZ HTML, KEV parser)
  ingest/pipeline.py store → extract → classify → cluster; KEV/EPSS/CVE enrichment; retention
  intel/entities.py  rule-based extraction: CVE, ATT&CK, actors/aliases, malware, ransomware, vendors/products, regions, defanged IOCs
  intel/classify.py  sections, tags, severity (with reasons), confidence, ranking
  intel/dedupe.py    URL canonicalisation, near-duplicate titles
  intel/ai.py        Anthropic client wrapper: schema-constrained JSON, caching, budget, injection guard, citation validation
  intel/briefing.py  daily briefing (AI synthesis or deterministic ranking)
  intel/watch.py     Threat Watch engine
  intel/notify.py    in-app notifications, digest, web push
  worker.py          scheduler entrypoint
  cli.py             set-password, ingest, briefing, reprocess, sources, vapid, backup
```

## Data model (key tables)

- **Evidence:** `sources`, `articles` (+ `articles_fts`), `entities`, `article_entities` (method `rule`/`ai`), `vulnerabilities`
- **Generated:** `ai_outputs` (cached by input hash), `briefings`, `watch_summaries` (versioned)
- **Threat Watch:** `watches`, `watch_evidence` (linked/candidate/rejected + score, reasons, significance, assessment), `watch_timeline`
- **Personal:** `bookmarks` (note, tags), `reading_history`, `notifications`, `push_subscriptions`, `settings` (last visit etc.)
- **Ops:** `users`, `sessions` (token hashes), `login_attempts`, `job_runs`, `ai_usage`

## Ingestion

Every 30 minutes (per-source intervals respected, failing sources back off exponentially up to 6 h):

1. Fetch with ETag/Last-Modified; cap 60 newest items/fetch, ignore items older than 60 days.
2. Exact dedupe by canonical URL (tracking params stripped) and source GUID. Original URL kept.
3. Extract entities, ensure CVE stubs exist, classify (sections, tags, severity + reasons).
4. Near-duplicate clustering across *different* sources (title Jaccard + shared strong entities; template titles with disjoint entities are never merged). Cluster size drives confidence (`official` / `multi-source` / `corroborated` / `single-source`).
5. KEV (hourly), EPSS (twice daily, batched 100 CVEs/request), CVE.org enrichment (≤60 CVEs/run, 1 req/s/host).
6. Optional AI summaries for the top-ranked new cluster representatives.
7. Match new articles against active watches.

## SecOps next steps

`intel/actions.py` derives up to six “What to do” steps per article when it is processed (stored in `articles.actions`,
recomputed when KEV status changes, and backfilled when the rules version changes). Each step states its basis:

| Step | Trigger | Basis |
|---|---|---|
| Patch now | CVE listed in CISA KEV | CISA KEV required action + federal deadline + ransomware use |
| Prioritise patching | CVSS ≥ 9, EPSS ≥ 10 %, or reported exploitation | CVE record / EPSS |
| Apply vendor update | exploitation reported but no CVE in the text | Source (reported exploitation) |
| Check exposure | vulnerability / exploitation story naming products | Playbook |
| Hunt for indicators | IOCs extracted from the source | Source indicators |
| Check detections / Review detection content | ATT&CK IDs named, or detection material in the source | Source ATT&CK / Source |
| Ransomware readiness, Identity and users, Check dependencies, Track actor | threat type | Playbook |

Roundups and podcasts get no steps (they mix unrelated stories). “Playbook” steps are labelled in the UI as
general practice, not claims about the incident. With an AI key, the article summary may add grounded
steps (`soc_actions`, each with the source rationale), labelled “AI, from source”. Following pages aggregate
the steps from all linked evidence.

## Threat Watch matching

Each watch has **identifiers** (strong identity: CVE, victim org, incident name), **aliases**, **context terms**, **exclude terms**, and a token profile built from its title, description and linked evidence.

```
score = identifier hits (headline 0.6 / body 0.4; CVE entity 0.7 / 0.55)
      + best alias hit (headline 0.5 / body 0.3)
      + context terms (0.1 each, max 0.3)
      + contextual similarity (cosine vs profile, max 0.3)
```

- Identity requirement: incident/vulnerability watches need an identifier (or incident alias) hit. **Actor/malware context alone never links an incident**, which prevents merging unrelated incidents by the same group (tested).
- `score ≥ 0.6` → linked; `0.35–0.6` → candidate. Incident matches found only in body text are also routed to review.
- Candidates go to AI adjudication when configured (“same specific event?”), otherwise to the user’s **review queue** (Link / Not relevant).
- Exclusion terms veto. User rejections are remembered.

When new evidence links: significance is assessed (AI if available; otherwise heuristics — new CVEs/IOCs/actors, first official advisory, exploitation, new independent source, or duplicate of a known cluster), a new **summary version** is written (old versions retained), the timeline records evidence and summary events, and notifications follow the watch’s preference (`important` / `all` / `digest` / `silent`) with dedupe key `watch:<id>:cluster:<cluster>` so duplicate coverage never re-notifies.

## AI safeguards

- Optional. Without `ANTHROPIC_API_KEY` everything except AI summaries works (briefing and watch records fall back to deterministic versions that quote publishers’ headlines with citations).
- Untrusted text wrapped in `<untrusted_source id="E123">` tags (closing tag neutralised), system prompt treats it strictly as data, no tools are given to the model, output constrained to a JSON schema.
- Citations validated against supplied IDs; uncited claims removed; AI-proposed entities kept only if literally present in source text; IOCs never generated.
- Responses cached by SHA-256 of (model, task, prompt, schema); daily USD budget and per-run request cap; refusals/truncation/invalid JSON handled as “unavailable”. Server-side refusal fallback enabled by default (`TW_AI_SERVER_FALLBACK`).
- Personal notes are never sent to the provider.

## Frontend

Routes: `/`, `/breaking`, `/intel`, `/vulns`, `/vuln/:cve`, `/soc`, `/apac`, `/article/:id`, `/watch`, `/watch/:id`, `/saved`, `/search`, `/notifications`, `/settings`.
Mobile: bottom navigation + “More” sheet; desktop: sidebar. Light/dark/system themes. Generated text is rendered as React text nodes only (no `innerHTML`), citations `[E123]` become links to the evidence.

Service worker: precached app shell; `NetworkFirst` (3 s timeout) cache for authenticated GET API responses → previously viewed and saved content is available offline; cache wiped on sign-out.


## Follow-alert relevance (assessment rules v2)
A linked report's *significance* is judged only on what it says about the followed subject:
- The sentences naming the subject's identifiers or aliases are found (`intel/text.py`).
- New names (CVEs, actors, malware, victims, indicators) count as changes only if they appear in those sentences.
- Broad reports (roundups, CISA KEV catalogue updates, or four or more CVEs or named threats) never contribute other
  subjects' names; the assessment says how many other items the report covers.
- A KEV catalogue update that names the followed CVE is recorded as "Added to the CISA KEV catalogue".
- Exploitation counts only when stated alongside the subject in broad reports.

Stored assessments were recalculated once on upgrade (`reassess_all`, gated by `assess_rules_version`); AI
assessments and the origin report were left as they were, and each affected watch's timeline records the change.
Display text is decoded and trimmed at read time (`excerpt`, `date_notes`); publisher titles are never rewritten.
