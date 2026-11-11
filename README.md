# Threat Watch

A private, single-user cybersecurity intelligence platform: collects real reporting from
trusted security sources, ranks it, produces a daily briefing, and — its core feature —
lets you **follow** evolving threats so new reporting is automatically linked to a
persistent, versioned, source-cited intelligence record.

Works in a desktop browser and as an installable PWA on Android.

| | |
|---|---|
| Backend | Python 3.13 · FastAPI · SQLite (WAL + FTS5) · APScheduler worker |
| Frontend | React 19 · TypeScript · Vite · PWA (Workbox service worker) |
| AI (optional) | Anthropic API (default `claude-opus-5-5`), cached, budgeted, citation-validated |
| Deployment | Docker Compose (2 small containers), private access via Tailscale Serve |

## Sections

- **Today** — daily briefing (07:00 Pacific/Auckland), what’s new since your last visit, top threats, followed-item updates
- **Breaking** — exploited vulnerabilities, new CISA KEV entries, significant incidents (source-backed severity + confidence)
- **Threat Intelligence** — ransomware, malware, actors, phishing, ATT&CK
- **Vulnerabilities** — CVE, CISA KEV, FIRST EPSS, CVSS (CVE.org), affected products, references
- **Trends and threat group profiles** — reporting charts; each group links to its MITRE ATT&CK entry (synced weekly from the public mitre/cti STIX data)
- **Further reading** — on each article, primary sources from the CVE record, CISA KEV and MITRE ATT&CK
- **SOC & DFIR** — DFIR Report, SANS ISC, detection/hunting, Sigma & Splunk content releases
- **NZ & APAC** — NCSC NZ alerts, ASD’s ACSC, regional reporting
- **Threat Watch** — followed incidents/CVEs/actors/malware/topics with timelines, change history and review queue
- **Saved** — bookmarks with notes & tags, followed items, reading history

**Bookmark** = read later. **Follow** = keep tracking an evolving subject.

## Quick start (local development)

```bash
python3.13 -m venv .venv && .venv/bin/pip install -r backend/requirements-dev.txt
cd backend
export TW_DATA_DIR=../.localdata TW_COOKIE_SECURE=false
../.venv/bin/python -m app.cli set-password analyst     # interactive; min 12 chars
../.venv/bin/python -m app.cli ingest --force           # first collection (~1–2 min)
../.venv/bin/uvicorn app.main:create_app --factory --port 8000 &
../.venv/bin/python -m app.worker &                     # scheduler (optional locally)
cd ../frontend && npm ci && npm run dev                 # http://localhost:5173 (proxies /api)
```

Tests: `cd backend && ../.venv/bin/python -m pytest -q` · Frontend type-check/build: `cd frontend && npm run build`

## Running it (current: local)

`deploy/local.sh up` → http://localhost:8787, then `deploy/local.sh password` once.

## Production (planned)

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). In short: build locally, `deploy/deploy.sh <ssh-host>`,
access privately over Tailscale (HTTPS via Tailscale Serve). Secrets live in
`/etc/threatwatch/threatwatch.env` on the server (never in git).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — components, data model, matching algorithm, AI safeguards
- [Deployment](docs/DEPLOYMENT.md) — server prerequisites, deploy, updates, backup & restore
- [Security](docs/SECURITY.md) — threat model, controls, Tailscale vs Cloudflare Tunnel/Access evaluation
- [Implementation status](docs/STATUS.md) — what is done, what is not
- [Configuration example](deploy/threatwatch.example.env)

## Data integrity rules

- Articles are never fabricated: every item comes from a source adapter and keeps its original URL, publication and retrieval timestamps.
- Evidence (articles, KEV/EPSS/CVE data) is stored separately from model output (`ai_outputs`, briefings, watch summaries).
- Generated claims must cite supplied evidence IDs; uncited claims are dropped. IOCs are only ever extracted deterministically from source text.
- Test fixtures (`backend/tests/fixtures`) are synthetic, use `example.*` hosts and `CVE-2099-*` IDs, and never enter a production database.
