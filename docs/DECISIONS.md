# Decisions

Consequential product and architecture decisions, newest first. Each records what was decided, why, and what it
rules out.

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
