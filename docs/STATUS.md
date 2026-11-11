# Implementation status

Legend: ✅ implemented and verified · 🟡 implemented, not yet verified in its real environment · ⛔ not done

_Last updated 2026-11-09._

## Phase 1 — Foundation
- ✅ Git repository, structure, pinned dependencies
- ✅ SQLite schema with migrations, WAL, FTS5
- ✅ Docker image (multi-stage, non-root, read-only) and Compose stack (web + worker), health checks, resource limits, restart policy
- ✅ FastAPI backend with authentication on all private endpoints
- ✅ Real ingestion: 19 sources verified live (BleepingComputer, SANS ISC, The DFIR Report, Google Threat Intelligence/Mandiant, The Record, NCSC NZ, CISA KEV, FIRST EPSS, CVE.org, Risky Bulletin, Risky Business, CISA advisories, ASD’s ACSC, Microsoft Security, Unit 42, Red Canary, Huntress, SigmaHQ releases, Splunk Security Content releases)
- ✅ Responsive React/TypeScript frontend; article browsing (verified at 390 px and 1366 px, light/dark, no horizontal overflow)

## Phase 2 — Intelligence
- ✅ Exact dedupe (canonical URL + GUID) and cross-source near-duplicate clustering
- ✅ Severity (with stated reasons), confidence (source authority + corroboration), ranking
- ✅ Daily briefing at 07:00 Pacific/Auckland, with source citations (deterministic mode verified live)
- 🟡 AI summaries / AI briefing / AI watch updates / AI match adjudication — implemented and tested with a mocked Anthropic client (caching, budget, refusal, citation filtering, grounding). **Not exercised against the live API**, because no API key was provided.
- ✅ Article detail: summary/why it matters/technical (AI when configured), source text, publication + retrieval times, entities, IOCs, CVE facts, related coverage, bookmark & follow
- ✅ Full-text search and filters (section, topic tag, region, severity, time, sort)
- ✅ Vulnerabilities: KEV, EPSS, CVSS, affected products, references, linked reporting

- ✅ SecOps next steps (“What to do”) on articles, briefing items and followed threats, each with its evidence basis

## Phase 3 — Threat Watch
- ✅ Follow incidents, vulnerabilities, actors, malware, campaigns, products, topics (from an article, a CVE page, or manually)
- ✅ Matching via identifiers, aliases (auto-expanded for known actors/malware), context terms, exclusions, contextual similarity; incidents never merged on shared actor/malware alone (tested)
- ✅ Review queue for uncertain matches (link / not relevant), manual linking
- ✅ Cumulative record with confirmed vs uncertain claims, IOCs, ATT&CK techniques, detection pointers, every claim cited
- ✅ Versioned summaries (history view), timeline, “what changed”, significance assessment per new evidence
- ✅ Notification preferences (important / all / daily digest / silent) with duplicate suppression
- ✅ Bookmarks with notes and tags, reading history, watch notes and tags

## Phase 4 — Deployment
- ✅ Production Compose verified locally: both services healthy, data persists across restarts, auth enforced, backup command works
- ✅ Deploy / rollback / backup / restore scripts, systemd backup timer, read-only server inspection script
- ✅ In-app notifications
- 🟡 PWA: manifest, icons, service worker, offline cache of viewed/saved content — built, but install/offline behaviour needs HTTPS and a real Android device to verify
- 🟡 Web push: server + client implemented (VAPID, `pywebpush`), untested end-to-end (needs HTTPS deployment and VAPID keys)
- ✅ **Local deployment** on the development Mac (`deploy/local.sh`, http://localhost:8787) — running continuously while Docker Desktop is up
- ⛔ **Deployment to the VPS** — deferred by decision (2026-11-11); migration path documented in DEPLOYMENT.md
- ⛔ Server hardening (deploy user, Docker install, Tailscale, firewall) — documented in DEPLOYMENT.md, requires your approval
- ⛔ watch.thefish.nz / Cloudflare — evaluated only (SECURITY.md); no DNS or Cloudflare changes made

## Known limitations
- Sources are defined in code (`backend/app/ingest/sources.py`); the UI can enable/disable them but not add new ones.
- Rule-based entity dictionaries (actors, malware, vendors) are curated lists; unknown names are only picked up by AI extraction (when enabled) or by watch terms you type.
- Feeds often provide only a summary, so extraction/IOCs are limited to what the feed text contains; the full article page is not scraped (licensing/robots respect).
- NCSC NZ has no feed; its HTML adapter depends on the current page markup and will need updating if the site changes (failures surface on the Settings page).
- Without AI, “confirmed vs uncertain” is approximated by source authority/corroboration of headlines, and briefing summaries are publishers’ excerpts.
- Frontend has type-checking and lint but no automated UI tests; UI was verified manually via headless Chrome screenshots.
- Single user only; no multi-user roles.
- The SSRF guard does not pin resolved IPs (DNS-rebinding window); acceptable because only the owner configures sources.
