# Decisions

Consequential product and architecture decisions, newest first. Each records what was decided, why, and what it
rules out.

## 2026-11-22: Group one story across outlets; keep newsletters and passing mentions off Breaking

**Context.** A review of the live data (450 articles) found three problems.
- No two articles from different sources had been grouped in 14 days. Grouping needed near-identical headlines, and
  outlets word the same story differently, so the Optimizely supply-chain attack showed as five cards from four sources.
- 5 of 25 Breaking items in ten days were not breaking: three Risky Bulletin newsletters, a SANS guest diary on
  honeypot workflow and a court ruling. Any KEV-listed CVE anywhere in the text added two severity levels, and a
  roundup only lost one.
- The 07:00 briefing and the 07:05 summary of held alerts ran at 07:00 and 07:05 UTC (20:00 and 20:05 in New
  Zealand). A `CronTrigger` without its own timezone uses the host zone, not the scheduler's.

**Decided.**
- *Grouping.* Besides near-identical headlines, two reports are one story when, within 48 hours, their headlines
  share a distinctive name: a word capitalised mid-headline that appears in no more than six headlines in a week
  either side. Agencies, countries, months, days and big vendors never count. A loose match is only made against a
  story's first report, so stories cannot chain into each other. A shared CVE, group or malware name plus some
  headline overlap also groups. Re-scoring an article no longer regroups it.
- *Severity.* A KEV-listed CVE raises severity by two only when it is the article's subject: named in the headline or
  the feed's summary, or its product is named in the headline. A passing mention adds one and does not qualify for
  Breaking. CVSS and EPSS count only for subject CVEs. Roundups (newsletters, podcasts, weekly reports) are capped
  at medium and never reach Breaking. Court, policing and regulatory headlines are not counted as live incidents.
- *Following.* A report in a story already on record is a duplicate only if its source is too; new outlets can add
  new facts. Notifications are limited to one routine and one important ping per story.
- Stored articles are re-scored and regrouped once when these rule versions change.

**Checked against live data before release.** Grouping: 37 articles into 16 stories, no wrong merges found (the
rejected drafts merged on words like "provider", "CISA" and "Russian"). Severity: 14 fewer Breaking items in 30 days,
all newsletters, passing mentions or follow-ups; real exploitation stories (vCenter zero-day, SCKit and
ScreenConnect, KEV additions) unchanged.

**Ruled out.** Topic-level grouping (for example, every ScreenConnect story in a week): related but separate
developments would be hidden behind one card.

## 2026-11-18: Ransomware leak-site claims from ransomware.live

**Decision.** Add a Ransomware page and claims panels on ransomware group profiles, fed by ransomware.live's free
API v2 (`/v2/recentvictims` each collection; a one-time three-month backfill from `/v2/victims/{year}/{month}`).

**Why.** Collected news named only about five ransomware stories and three groups in 30 days, and article victim
extraction is unreliable, so trends from news alone would be thin and misleading. The tracker adds about 50 claims a
day with group, sector (92%) and country (86%).

**Terms.** The free API is for personal use only, rate limited to one request a minute per endpoint, and slightly
delayed. The owner confirmed Threat Watch is personal use. If it is ever used for work, switch to the free PRO API
(key required) and read its terms first. robots.txt allows the API; the site asks not to be used for AI training,
which this does not do.

**Handling.** Claims are criminals' statements: always labelled unverified, never notified, never linked to a leak
site, and stored with identifying fields only (no descriptions or screenshots). A claim links to Threat Watch
reporting only when a collected story names the victim. Rising and falling use share of claims, as on Trends.

**Ruled out.** RansomLook as the source (less structured: no sector or country fields), notifications for claims
in general, and showing the groups' leak descriptions.

**Update, same day: New Zealand claim alerts.** At the owner's request, a new claim against a New Zealand
organisation creates one notification (push, held during quiet hours) worded as an unverified claim and linking to
the Ransomware page. Only claims first seen in the last 7 days alert, the backfill never alerts, the record URL is
the dedupe key, and Settings → Alerts turns it off. Other countries do not alert.

## 2026-11-18: Trusted devices instead of re-entering the password

**Problem.** The phone app kept showing the sign-in form although its 30-day session was valid. The cause was the
start-up check: any failure to reach the server (Tailscale off, server restarting) was treated as "signed out".

**Decision.**
- Only a 401 from the server shows the sign-in form. A connection failure or proxy error shows "Cannot reach Threat
  Watch", keeps the session, and retries every 20 seconds and whenever the app comes back to the foreground.
- "Keep me signed in on this device" (off by default) creates a *trusted* session lasting 180 days from last use: the
  server-side expiry and the cookie are renewed at most once a day by `/api/auth/me`. Other sign-ins keep a fixed
  30 days.
- Settings lists signed-in devices (browser and system from the user agent, last use, trusted or not) and can sign
  any other device out, which deletes its session server-side.

**Why it is acceptable.** The app is reachable only from devices on the owner's tailnet, so a trusted session still
requires an authorised Tailscale device plus the HttpOnly, SameSite=Strict cookie. A lost device can be signed out
from Settings and removed from the tailnet; a password change still revokes every session.

**Ruled out.** Passkeys/WebAuthn (more moving parts for one user), long-lived tokens in localStorage (readable by
script), and an "always" session with no expiry.

## 2026-11-17: Hudson Rock as a research source; weekly statistics as context only

**Decision.** Add two RSS sources from Hudson Rock's infostealers.com:
- `hudson-rock`: the research feed (`/learn-info-stealers/feed/`), Threat intel by default, normal severity rules,
  checked every 6 h.
- `hudson-rock-weekly`: the Threat Feeds weekly report (`/feed/?post_type=threat-report`), capped at *low*, tagged as
  a roundup, checked daily.

The site-wide `/feed/` is not used because it also carries a weekly compromised-domain count report with no analysis.

**Why.** On 2026-11-17 none of the 305 stored articles mentioned Hudson Rock or infostealers.com, so its first-party
investigations (new stealer families such as Remus, ClickFix panels such as Corium, stealer-log case studies) were not
reaching Threat Watch through other publishers. Infostealer and ClickFix reporting was otherwise thin (9 and 13
articles in 30 days).

**How the weekly report is treated.** It lists sensor sightings (C2 hosts, phishing-kit hosts, ClickFix pages) by
family and country. These are one vendor's observations of infrastructure, not confirmed infections or attacks, and
week-to-week changes partly reflect the sensors. So:
- severity is capped at low, it never reaches Breaking, and it gets no AI summary (summaries start at medium);
- it is a roundup: a followed item named in it links as silent "minor" context, a passing mention is not queued for
  review, and it is excluded from Trends counts;
- its numbers are not parsed, stored as statistics, charted or compared week to week.

**Related rule changes (apply to all sources).**
- Titles containing "weekly report" are classified as roundups, like "weekly recap" and "week in review".
- A roundup that only partly matches a followed item is no longer put in the review queue; such a report could only
  ever be minor context.
- "Remus Stealer" was added to the malware dictionary (bare "Remus" needs a qualifier such as "stealer" nearby).

**Ruled out.** Ingesting Hudson Rock IOC feeds or the Cavalier API, scraping article pages, new tables, dashboards or
time series for the weekly numbers, and a Hudson Rock-specific UI.

**Revisit if** the research feed turns mostly promotional (partnership announcements and vendor rankings already
appear at low severity), or the weekly report's endpoint, which is a standard WordPress query rather than an advertised
feed, stops working (the source will show errors on Settings).
