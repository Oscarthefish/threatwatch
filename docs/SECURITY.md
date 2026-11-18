# Security

## Threat model (single-user private app)

| Threat | Controls |
|---|---|
| Unauthenticated access to intelligence, notes, follows | Private network (Tailscale) **and** app authentication on every `/api/*` route except `/api/health` and `/api/auth/login` (tested). Static assets contain no data. |
| Credential guessing | Argon2id hashes; login limited to 8 failures/15 min per client and 32 globally; generic error; constant-work dummy verify for unknown users. |
| Session theft / CSRF | 256-bit random token in `HttpOnly; Secure; SameSite=Strict` cookie; only SHA-256 stored server-side; 30-day fixed expiry, or 180 days renewed on use when "Keep me signed in on this device" is ticked; every session can be signed out from Settings (deleted server-side); password change revokes all sessions; unsafe methods require `X-TW-Request: 1` header. |
| XSS from hostile feed content | Feed HTML stripped to text with nh3; React renders text nodes only (no `innerHTML` anywhere); strict CSP `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'`. |
| Prompt injection via articles | Untrusted-source wrapper with neutralised closing tag; system prompt treats content as data; no tools available to the model; JSON-schema output; citation validation; ungrounded entities dropped; IOCs never AI-generated; AI output labelled as such and kept separate from evidence. A test fixture contains an injection attempt. |
| SSRF / unsafe fetching | Only http(s) on ports 80/443; DNS resolved and all addresses must be public (blocks loopback, RFC1918, link-local/metadata `169.254.169.254`, CGNAT, multicast, reserved, IPv4-mapped IPv6); redirects followed manually with per-hop validation (max 5); 15 MB body cap with streaming; 20 s timeout; per-host politeness. Residual: DNS rebinding between check and connect (sources are owner-controlled). |
| Secrets exposure | Secrets only in `/etc/threatwatch/threatwatch.env` (root:deploy 640), never in git (`.gitignore`), images or logs (`SecretStr`, `safe_dict()`); API key never echoed; no tracebacks returned to clients. |
| Data file exposure | DB created mode 600 inside a 700 directory owned by the container user; backups mode 600 in a root-only 700 directory. |
| Container escape / lateral movement | Non-root UID 10001, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, pids limit, memory/CPU limits, tmpfs `/tmp`, dedicated bridge network, no Docker socket mounted. |
| Network exposure | Only `127.0.0.1:8080` published; no DB or Docker API ports; reached via Tailscale Serve (WireGuard + HTTPS). Host header allow-list via `TW_TRUSTED_HOSTS`. |
| Supply chain | Pinned Python requirements and `package-lock.json`; slim official base images; frontend has 3 runtime deps. Rebuild regularly for security patches. |
| Information leakage to sources | `Referrer-Policy: no-referrer`; outbound links use `rel="noopener noreferrer"`; the app never loads third-party resources in the browser. |

Docker group note: the `deploy` user’s docker group membership is root-equivalent on the host. Restrict SSH for that account to keys (and later to the tailnet).

## External reference data and links
- MITRE ATT&CK is fetched weekly from `raw.githubusercontent.com` (mitre/cti) through the same SSRF-guarded fetcher as
  every feed (public IPs only, per-hop redirect checks), with a 150 MB cap, conditional requests by ETag, and the body
  streamed to a temporary file in the data volume that is deleted after parsing. A download yielding fewer than 50
  groups/software is rejected so a truncated file cannot wipe good data.
- Links shown to the user ("Further reading", ATT&CK references, technique pages) come only from stored data (CVE
  records, CISA KEV, MITRE) or are derived from a validated technique ID. Only `http(s)` URLs are rendered, always
  with `target="_blank" rel="noopener noreferrer"`, so the destination gets no referrer and no window handle.

- Hudson Rock (infostealers.com) is read only through its public RSS feeds (`robots.txt` allows all agents, checked
  2026-11-17), with conditional requests and at most every 6 h (research) and 24 h (weekly report). Like every feed,
  only the feed's own text is stored, with the original link and attribution; pages are not scraped, and no IOC
  feeds or paid/restricted APIs (Cavalier) are used. Content is copyright of the publisher and shown only to the
  single owner of this private instance.

- ransomware.live (leak-site claims) is read through its free API v2, which is for personal use only and limited to
  one request per minute per endpoint; Threat Watch makes one request per collection (every 2 h) plus a one-time
  three-month backfill spaced 61 s apart. Only the group, victim name, domain, sector, country, dates and the tracker's
  record URL are stored: no leak descriptions, screenshots or leak-site addresses, and the UI never links to a leak site.
  Victim names are criminal claims and are always shown as unverified.

## Logging

Application logs contain source keys, counts, HTTP status classes and exception types — not
cookies, passwords, API keys, or full request bodies. Uvicorn access logs include paths and status codes only.

## Public hostname evaluation

Goal: eventually serve at `https://watch.thefish.nz`. **Nothing has been configured and no DNS has been changed.**

| Option | Pros | Cons |
|---|---|---|
| **Tailscale Serve (current recommendation)** | No public exposure at all; valid HTTPS (`*.ts.net`); works on Android with the Tailscale app; zero cost; nothing to configure on thefish.nz | Requires the Tailscale client on every device; URL is `*.ts.net`, not `watch.thefish.nz` |
| **Cloudflare Tunnel + Cloudflare Access** | Custom hostname; no inbound ports (outbound-only `cloudflared`); Access enforces SSO/OTP + device posture **before** traffic reaches the VPS; DDoS/WAF in front | Requires `thefish.nz` DNS on Cloudflare (or a CNAME setup) — a DNS change; Cloudflare terminates TLS (can see traffic); one more container (`cloudflared`, ~30 MB); Access policy mistakes would expose the app (app login still protects it) |
| Caddy/nginx + Let’s Encrypt on a public port | Custom hostname, no third party | Internet-exposed login page; needs firewall changes; highest risk — not recommended |

**Recommendation:** keep Tailscale for now. If a custom hostname is wanted, use Cloudflare Tunnel
with an Access application (allow only your identity, short session duration, optional WARP device posture),
keep `TW_TRUSTED_HOSTS=watch.thefish.nz`, keep app authentication enabled (defence in depth), and add
the `cloudflared` service bound to the internal compose network. This needs your approval for:
creating the Cloudflare tunnel/Access app, and the DNS record for `watch.thefish.nz`. Your existing
website (`thefish.nz`) would not be touched beyond adding that one record.

## Reporting / rotating

- Rotate the app password: `docker compose exec web python -m app.cli set-password analyst` (revokes all sessions).
- Rotate the AI key: edit the env file, `docker compose up -d`.
- Revoke a lost phone: sign it out under Settings → Signed-in devices and remove it from the tailnet (Tailscale admin console). If the password may be known, also change it, which signs out every device.
