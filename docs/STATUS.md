# Implementation status

Legend: ✅ implemented and verified · 🟡 implemented, not yet verified in its real environment · ⛔ not done

_Last updated 2026-11-18._

## Phase 1 — Foundation
- ✅ Git repository, structure, pinned dependencies
- ✅ SQLite schema with migrations, WAL, FTS5
- ✅ Docker image (multi-stage, non-root, read-only) and Compose stack (web + worker), health checks, resource limits, restart policy
- ✅ FastAPI backend with authentication on all private endpoints
- ✅ Real ingestion: 19 sources verified live (BleepingComputer, SANS ISC, The DFIR Report, Google Threat Intelligence/Mandiant, The Record, NCSC NZ, CISA KEV, FIRST EPSS, CVE.org, Risky Bulletin, Risky Business, CISA advisories, ASD’s ACSC, Microsoft Security, Unit 42, Red Canary, Huntress, SigmaHQ releases, Splunk Security Content releases); Hudson Rock research and Threat Feeds weekly report added 2026-11-17 (21 feeds plus MITRE ATT&CK)
- ✅ Responsive React/TypeScript frontend; article browsing (verified at 390 px and 1366 px, light/dark, no horizontal overflow)

## Phase 2 — Intelligence
- ✅ Exact dedupe (canonical URL + GUID) and cross-source near-duplicate clustering
- ✅ Severity (with stated reasons), confidence (source authority + corroboration), ranking
- ✅ Daily briefing at 07:00 Pacific/Auckland, with source citations (deterministic mode verified live)
- ✅ AI (live since 2026-11-13): Claude Haiku 5.5 for story summaries and extraction (about US$0.0008 a story), Claude Sonnet 5.5 for the briefing, followed-item records and match decisions; per-model pricing, US$0.50/day hard cap, cache by input hash, citation filtering and grounding. Both tiers verified against the live API on the server.
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
- ✅ PWA: manifest, icons, service worker, offline cache of viewed/saved content; installed and signed in on a real Android phone (Pixel 7 Pro) over Tailscale HTTPS
- ✅ Web push: VAPID keys generated on the server (never displayed); test notifications delivered to the Android phone; expired subscriptions are pruned automatically
- ✅ Local deployment on the development Mac (`deploy/local.sh`); stopped since the move to the server, data kept
- ✅ **Server deployment (2026-11-13):** DigitalOcean droplet (Sydney, 1 GB), host key verified out of band, data restored from the Mac and integrity-checked, health and security headers checked over HTTPS, app unreachable from the public internet
- ✅ Server hardening: non-root deploy user (key only), Docker from the official repository with log limits, swap, Tailscale Serve, ufw (SSH and Tailscale only), SSH without passwords
- ✅ Backups: nightly on the server (14 kept) and a daily copy to the Mac (30 kept, integrity-checked)
- ⛔ Public watch.thefish.nz: not wanted for now (access is private via Tailscale); no DNS changes made

## Phase 5: Clarity, trends and reference
- ✅ Desktop and mobile redesign (8 batches), keyboard shortcuts, guided tour, glossary; WCAG 2.2 AA with 0 axe violations across 126 page views
- ✅ Breaking reorganised; follow alerts count only facts stated alongside the subject; search passages highlighted; date checks
- ✅ Trends page and Today panel; threat group profiles with weekly charts
- ✅ MITRE ATT&CK groups and software synced weekly; technique links; further reading from CVE records and KEV
- ✅ Ransomware page (leak-site claims from ransomware.live: active groups, rising and falling, sectors, countries, NZ and Australia, recent claims linked to news) and claims panels on ransomware group profiles; alerts for new claims against New Zealand organisations (Settings → Alerts)
- ✅ "Keep me signed in on this device" (180 days, renewed on use), signed-in devices list with remote sign-out; a server that cannot be reached no longer shows the sign-in form
- ✅ Hudson Rock (InfoStealers) research feed and Threat Feeds weekly report; the weekly report is context only (see DECISIONS.md)

## Known limitations
- Sources are defined in code (`backend/app/ingest/sources.py`); the UI can enable/disable them but not add new ones.
- Rule-based entity dictionaries (actors, malware, vendors) are curated lists; unknown names are only picked up by AI extraction (when enabled) or by watch terms you type.
- Feeds often provide only a summary, so extraction/IOCs are limited to what the feed text contains; the full article page is not scraped (licensing/robots respect).
- NCSC NZ has no feed; its HTML adapter depends on the current page markup and will need updating if the site changes (failures surface on the Settings page).
- Ransomware claims use ransomware.live's free API (personal use only; slightly delayed versus its PRO API). Work use would need a free PRO key (`url` change plus a key header, not built). Claims are unverified and news links depend on a collected story naming the victim exactly.
- Vendor research is single-source until another publisher covers it; vendor sensor statistics (Hudson Rock weekly report) are never treated as confirmed activity.
- Without AI, “confirmed vs uncertain” is approximated by source authority/corroboration of headlines, and briefing summaries are publishers’ excerpts.
- Frontend has type-checking and lint but no automated UI tests; UI was verified manually via headless Chrome screenshots.
- Single user only; no multi-user roles.
- The SSRF guard does not pin resolved IPs (DNS-rebinding window); acceptable because only the owner configures sources.
