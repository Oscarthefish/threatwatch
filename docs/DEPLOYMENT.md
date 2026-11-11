# Deployment

## Current mode: local (this Mac)

Threat Watch currently runs on the development Mac with Docker Desktop:

```bash
deploy/local.sh up          # build + start → http://localhost:8787
deploy/local.sh password    # set the login password (interactive, run once)
deploy/local.sh status      # health, memory, source status
deploy/local.sh backup      # → ~/Backups/threatwatch/tw-<UTC>.db.gz (14 kept)
deploy/local.sh down        # stop; data stays in the `threatwatch_tw-data` volume
```

- Config/secrets: `~/.config/threatwatch/threatwatch.env` (mode 600, outside git). Add `ANTHROPIC_API_KEY=` there to enable AI, then `deploy/local.sh up`.
- Bound to `127.0.0.1:8787` only — not reachable from the network or your phone.
- Containers restart automatically whenever Docker Desktop is running. For always-on collection enable
  Docker Desktop → Settings → General → *Start Docker Desktop when you sign in*. Collection pauses while the Mac sleeps
  and catches up on wake (misfired jobs run once, within an hour’s grace).
- Over plain `http://localhost`, the app runs as a normal web page; Android install / web push need the HTTPS deployment below.

### Migrating to the VPS later
1. `deploy/local.sh backup`
2. Complete steps 1–4 below on the server (deploy creates the empty stack).
3. `scp ~/Backups/threatwatch/tw-<STAMP>.db.gz tw-vps:/tmp/` then on the server `sudo /opt/threatwatch/restore.sh /tmp/tw-<STAMP>.db.gz`.
   Bookmarks, follows, notes, history and the password all move with the database.

---

## VPS deployment (planned)

Target: Ubuntu 24.04 VPS, Docker Compose, private access over Tailscale. Images are **built
locally** and shipped over SSH — nothing is built (and no Claude Code is installed) on the server.

> Steps marked **[approval]** change server access, packages or networking. They are written
> out here so they can be reviewed; they have **not** been run.

## 0. Resource assessment

Measured on the production image (Docker, ingesting all 19 sources):

| | Idle | Peak (ingest of KEV JSON + feeds) | Limit |
|---|---|---|---|
| web | ~46 MB | ~50 MB | 192 MB |
| worker | ~60 MB | ~132 MB | 256 MB |
| SQLite DB | ~4 MB per ~200 articles; est. 50–150 MB/year | | |

Ubuntu 24.04 + dockerd + containerd + tailscaled typically use 250–350 MB, so a **512 MB VPS is
marginal**: it can run but risks OOM kills during upgrades or `apt`. Recommendation:

- **Upgrade to ≥ 1 GB (the planned 2 GB is comfortable)** before go-live; or
- if staying at 512 MB temporarily: add a 1 GB swap file and set `TW_WEB_MEM=128m` in `/opt/threatwatch/.env`.

1 vCPU is sufficient (ingest is I/O bound; CPU limits 0.75 per container).

## 1. Inspect the server (read-only)

```bash
deploy/inspect-server.sh <ssh-host>
```
Prints OS, SSH host key fingerprints (compare with your provider console before trusting the host),
RAM/disk/swap, listening ports, running services, Docker/Tailscale presence, firewall and sshd settings.
Changes nothing.

## 2. Prepare the server **[approval]**

Run as your existing admin user. Review each block first.

```bash
# 2a. Dedicated non-root deployment user (SSH key only)
sudo adduser --disabled-password --gecos "" deploy
sudo install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
sudo cp ~/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys   # or add only your laptop key
sudo chown deploy:deploy /home/deploy/.ssh/authorized_keys && sudo chmod 600 /home/deploy/.ssh/authorized_keys

# 2b. Docker Engine + compose plugin from Docker's apt repository
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin sqlite3
sudo systemctl enable --now docker
# NOTE: docker group membership is root-equivalent on this host. It is limited to the deploy user.
sudo usermod -aG docker deploy
# Daemon hardening: log rotation, no inter-container ICC on the default bridge, live-restore
echo '{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"icc":false,"live-restore":true,"no-new-privileges":true}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker

# 2c. App directories and secrets file (outside git, not world-readable)
sudo install -d -m 750 -o deploy -g deploy /opt/threatwatch
sudo install -d -m 750 -o root -g deploy /etc/threatwatch
sudo install -m 640 -o root -g deploy /dev/null /etc/threatwatch/threatwatch.env
sudoedit /etc/threatwatch/threatwatch.env       # paste from deploy/threatwatch.example.env and edit
sudo install -d -m 700 -o root -g root /var/backups/threatwatch

# 2d. (optional, 512 MB VPS only) swap
sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

The API key (if any) is entered by you directly into `/etc/threatwatch/threatwatch.env` with
`sudoedit` — it never passes through chat, git, or command-line arguments.

## 3. Private access with Tailscale **[approval]**

```bash
curl -fsSL https://tailscale.com/install.sh | sh     # or the apt repo from tailscale.com/kb/1476
sudo tailscale up --ssh=false                        # authenticate in the browser link it prints
sudo tailscale serve --bg --https=443 http://127.0.0.1:8080
tailscale serve status                               # → https://<host>.<tailnet>.ts.net
```
Then set in the env file: `TW_COOKIE_SECURE=true` and `TW_TRUSTED_HOSTS=<host>.<tailnet>.ts.net`.
Tailscale Serve provides a valid HTTPS certificate, which Android requires for PWA install, the service worker and web push.
Install the Tailscale app on your Android phone and sign in to the same tailnet.

**Firewall:** the app is bound to `127.0.0.1:8080` only and publishes no other ports, so Docker’s
iptables behaviour (which bypasses UFW for *published* ports) cannot expose it. Optional
hardening **[approval]**: `ufw default deny incoming; ufw allow OpenSSH; ufw allow in on tailscale0; ufw enable`
— confirm you have console access first, and later consider restricting SSH to the tailnet.

## 4. Deploy

From your laptop (repo root, clean git tree):

```bash
# ~/.ssh/config
# Host tw-vps
#   HostName <SERVER_IP>
#   User deploy
#   IdentityFile ~/.ssh/id_ed25519
ssh tw-vps true                       # verify the host key fingerprint against step 1 on first connect
scp deploy/backup.sh deploy/restore.sh tw-vps:/opt/threatwatch/
deploy/deploy.sh tw-vps               # build for the server arch, ship, compose up, health check
ssh -t tw-vps 'cd /opt/threatwatch && docker compose exec web python -m app.cli set-password analyst'
```
The first ingestion starts automatically; the first briefing is generated right after it.

### Backups **[approval for systemd install]**
```bash
sudo cp threatwatch-backup.service threatwatch-backup.timer /etc/systemd/system/   # copy from deploy/ first
sudo systemctl daemon-reload && sudo systemctl enable --now threatwatch-backup.timer
sudo /opt/threatwatch/backup.sh       # test once → /var/backups/threatwatch/tw-<UTC>.db.gz (mode 600, 14 kept)
```
Backups use SQLite’s online backup API (consistent while running). Copy them off-host periodically
(e.g. `scp tw-vps:/var/backups/threatwatch/*.gz ~/Backups/`); a VPS-local backup does not survive loss of the VPS.

### Restore (destructive)
```bash
sudo /opt/threatwatch/restore.sh /var/backups/threatwatch/tw-<STAMP>.db.gz   # asks for confirmation
```
It integrity-checks the file, stops the stack, replaces the database inside the volume and restarts.

## 5. Updates and rollback

```bash
# commit changes → backend tests pass →
deploy/deploy.sh tw-vps
deploy/rollback.sh tw-vps             # previous image tag (kept on the server)
```
Migrations run automatically at startup and are forward-only; take a backup before deploying schema changes.
OS updates: keep `unattended-upgrades` enabled; run `docker image prune` occasionally.

## 6. Verification checklist

```bash
ssh tw-vps 'cd /opt/threatwatch && docker compose ps'                              # web + worker (healthy)
ssh tw-vps 'curl -s 127.0.0.1:8080/api/health'                                      # {"status":"ok",...}
ssh tw-vps 'curl -s -o /dev/null -w "%{http_code}\n" 127.0.0.1:8080/api/today'      # 401 (auth enforced)
ssh tw-vps 'docker stats --no-stream'
ssh tw-vps 'sudo reboot'    # then re-run `docker compose ps` — containers return automatically
```
`ss -tlnp` on the server must show nothing new listening on public interfaces.

## 7. Later: watch.thefish.nz

Not configured, and no DNS has been changed. See [SECURITY.md](SECURITY.md#public-hostname-evaluation)
for the Cloudflare Tunnel + Access evaluation. It requires your approval (DNS change, Cloudflare resources).
