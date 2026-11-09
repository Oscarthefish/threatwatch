#!/usr/bin/env bash
# READ-ONLY server inspection. Changes nothing. Usage: deploy/inspect-server.sh <ssh-host>
set -uo pipefail
HOST="${1:?usage: inspect-server.sh <ssh-host>}"
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$HOST" 'bash -s' <<'REMOTE'
echo "== identity";      hostname; hostname -I 2>/dev/null; cat /etc/os-release | grep -E "^(PRETTY_NAME|VERSION_ID)="; uname -rm
echo "== host keys";     for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done
echo "== resources";     nproc; free -m; df -h / | tail -1; swapon --show 2>/dev/null
echo "== uptime/load";   uptime
echo "== user";          id
echo "== listening";     (ss -tlnpH 2>/dev/null || ss -tlnH) | awk '{print $4, $6}'
echo "== services";      systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}'
echo "== docker";        (docker version --format '{{.Server.Version}}' 2>/dev/null || echo "docker not installed / no access"); docker ps --format '{{.Names}} {{.Image}} {{.Ports}}' 2>/dev/null
echo "== compose";       docker compose version 2>/dev/null || echo "compose not available"
echo "== firewall";      (sudo -n ufw status 2>/dev/null || echo "ufw status needs sudo"); (sudo -n nft list ruleset 2>/dev/null | head -20 || true)
echo "== tailscale";     (tailscale status 2>/dev/null | head -5 || echo "tailscale not installed")
echo "== sshd";          (sudo -n sshd -T 2>/dev/null | grep -E "^(passwordauthentication|permitrootlogin|pubkeyauthentication) " || echo "sshd -T needs sudo")
echo "== unattended";    (systemctl is-enabled unattended-upgrades 2>/dev/null || echo "unknown")
REMOTE
