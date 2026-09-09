#!/bin/bash
set -euo pipefail

exec > >(tee /var/log/wazuh-install.log) 2>&1
echo "=== Wazuh manager install started: $(date) ==="
echo "=== Installer series: ${wazuh_installer_series} ==="

cd /root

# Wait for apt (we don't use `cloud-init status --wait` — this script IS
# cloud-init's final stage and that command would deadlock waiting on itself)
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
  echo "Waiting for apt lock..."
  sleep 5
done

apt-get update -y
apt-get install -y curl apt-transport-https unzip

echo "=== Downloading Wazuh installer: $(date) ==="
curl -fsSL "https://packages.wazuh.com/${wazuh_installer_series}/wazuh-install.sh" -o wazuh-install.sh
chmod +x wazuh-install.sh

# Generate single-node config
cat > /root/config.yml << 'CONFIG'
nodes:
  indexer:
    - name: node-1
      ip: "127.0.0.1"
  server:
    - name: wazuh-1
      ip: "127.0.0.1"
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
CONFIG

echo "=== Running all-in-one install: $(date) ==="
bash wazuh-install.sh -a -o
echo "=== Install complete: $(date) ==="

# --- Indexer JVM heap tuning ---
# The indexer (OpenSearch) defaults can be too low or too high depending on
# instance size. Setting explicit heap at ~50% of available RAM prevents OOM
# kills (the #1 cause of indexer failures on smaller instances).
TOTAL_MEM_MB=$(awk '/MemTotal/ { printf "%.0f", $2/1024 }' /proc/meminfo)
HEAP_MB=$((TOTAL_MEM_MB / 2))
# Cap at 4GB per OpenSearch recommendation for single-node deployments
if [ "$HEAP_MB" -gt 4096 ]; then
  HEAP_MB=4096
fi
# Floor at 1GB (below this, the indexer struggles even with no load)
if [ "$HEAP_MB" -lt 1024 ]; then
  HEAP_MB=1024
fi

echo "=== Setting indexer JVM heap to $${HEAP_MB}m (total RAM: $${TOTAL_MEM_MB}m) ==="
mkdir -p /etc/wazuh-indexer/jvm.options.d
cat > /etc/wazuh-indexer/jvm.options.d/heap.options << HEAPEOF
-Xms$${HEAP_MB}m
-Xmx$${HEAP_MB}m
HEAPEOF

# --- Indexer network binding ---
# By default, wazuh-install.sh binds the indexer to 127.0.0.1 (from our
# config.yml). The MCP server and doctor.sh both need external access, so
# we rebind to 0.0.0.0 before the restart below. The security group still
# restricts :9200 access to YOUR_IP, so this is only a lab convenience, not
# a production exposure.
echo "=== Rebinding indexer from 127.0.0.1 to 0.0.0.0 ==="
sed -i 's/^network.host: .*/network.host: "0.0.0.0"/' /etc/wazuh-indexer/opensearch.yml

# Restart indexer with the new heap settings + network binding
systemctl restart wazuh-indexer || true

# Wait for indexer to be back up (max 60s)
for i in $(seq 1 30); do
  if ss -tln | grep -q ':9200 '; then
    echo "=== Indexer listening on :9200 after $${i}x2s ==="
    break
  fi
  sleep 2
done

# Expose Wazuh API on all interfaces (default binds to 127.0.0.1)
if [ -f /var/ossec/api/configuration/api.yaml ]; then
  sed -i 's/^  host: 127.0.0.1/  host: 0.0.0.0/' /var/ossec/api/configuration/api.yaml
fi

# --- Automatic active-response triggers ---
# By default, ossec.conf has a commented-out <active-response> block template.
# We add real triggers so students see attacks auto-mitigated on top of the
# manual-via-MCP flow in Lesson 5.
#
# - Rule 5712 (SSH brute force composite) → firewall-drop the source IP for 5 min
# - Rule 5720 (multiple auth failures)    → same, broader catch
# - Rule 100005 (CloudVault hidden-artifact, added in L5) → firewall-drop
#
# Timeout 300s = auto-rollback after 5 minutes so the lab doesn't accumulate
# iptables rules. For a production deploy, students learn to raise/remove
# the timeout deliberately.
# Idempotency strategy: DELETE any existing LAB:auto-AR block first, then
# insert fresh. Using a grep-based guard alone isn't sufficient — we saw
# duplicate blocks in v3 deployed configs. Delete-then-insert is bulletproof
# regardless of how many times user_data executes.
echo "=== Installing automatic active-response triggers (idempotent) ==="
sed -i '/<!-- LAB:auto-AR -->/,/<!-- LAB:auto-AR-end -->/d' /var/ossec/etc/ossec.conf
sed -i '0,/<\/ossec_config>/{s|<\/ossec_config>|<!-- LAB:auto-AR -->\\n<active-response>\\n  <command>firewall-drop</command>\\n  <location>local</location>\\n  <rules_id>5712,5720</rules_id>\\n  <timeout>300</timeout>\\n</active-response>\\n<!-- LAB:auto-AR-end -->\\n</ossec_config>|}' /var/ossec/etc/ossec.conf

# Verify exactly one block installed. Idempotency is bulletproof via the
# delete-then-insert above, so the check is a sanity log only — no exit on
# mismatch, because the post-install bootstrap depends on cloud-final
# completing successfully.
AR_COUNT=$(grep -c "<!-- LAB:auto-AR -->" /var/ossec/etc/ossec.conf || true)
echo "=== LAB:auto-AR block count: $${AR_COUNT} (expected 1) ==="
if [ "$${AR_COUNT}" != "1" ]; then
  echo "=== WARN: AR block count unexpected, but continuing. Diagnostic: ==="
  grep -n "LAB:\|ossec_config" /var/ossec/etc/ossec.conf
fi

systemctl restart wazuh-manager

# Extract credentials to /root/wazuh-install-files/ so they can be retrieved
# later (by terraform remote-exec, by students via SSH, or by doctor.sh)
echo "=== CREDENTIALS ==="
tar -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -C /root/ 2>/dev/null || true
cat /root/wazuh-install-files/wazuh-passwords.txt 2>/dev/null || echo "Passwords file not yet extracted — check wazuh-install-files.tar"

# ===========================================================================
# MCP server install (gensecaihq/Wazuh-MCP-Server)
# ===========================================================================
# Pre-installs the Wazuh MCP server so students don't burn an hour on Docker
# + CORS + bearer-token setup in L3. The security teaching in L3 (threat
# model, token scoping, prompt-injection detection) stays — this just
# eliminates the ops drudgery that's not the educational point.
#
# Install path:
#   1. Docker CE + Compose plugin v2 (Ubuntu's docker.io lacks v2 plugin)
#   2. Clone repo to /opt/wazuh-mcp
#   3. Pull creds from /root/wazuh-install-files/wazuh-passwords.txt
#   4. Generate AUTH_SECRET_KEY + MCP_API_KEY
#   5. Write .env
#   6. docker compose up -d
#   7. Wait for /health
#   8. Persist MCP_API_KEY to /root/wazuh-mcp-api-key.txt for bootstrap.sh
# ---------------------------------------------------------------------------

echo "=== MCP install: Docker + Compose v2 plugin ==="
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg git openssl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

echo "=== MCP install: cloning Wazuh-MCP-Server ==="
git clone --branch v4.2.1 --depth 1 https://github.com/gensecaihq/Wazuh-MCP-Server.git /opt/wazuh-mcp
cd /opt/wazuh-mcp

echo "=== MCP install: writing .env ==="
WAZUH_API_PASS=$(grep -A1 "api_username: 'wazuh-wui'" /root/wazuh-install-files/wazuh-passwords.txt | tail -1 | grep -oE "'[^']+'"|tr -d "'")
INDEXER_PASS=$(grep -A1 "indexer_username: 'admin'" /root/wazuh-install-files/wazuh-passwords.txt | tail -1 | grep -oE "'[^']+'"|tr -d "'")
AUTH_SECRET_KEY=$(openssl rand -hex 32)
# MCP_API_KEY format the server validates: "wazuh_" + 43 base64url chars.
# openssl rand -hex gives hex, which the server rejects (regenerates its
# own). Use secrets.token_urlsafe(32) = 43 base64url chars, matching the
# expected shape.
MCP_API_KEY="wazuh_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"

# WAZUH_HOST / WAZUH_INDEXER_HOST use the manager's STATIC PRIVATE IP
# (10.0.1.10), not 127.0.0.1. Inside a Docker container, 127.0.0.1
# resolves to the container itself, NOT the host — so the MCP cannot
# reach the Wazuh API at localhost. The static IP works because Terraform
# assigns 10.0.1.10 to the manager and the Docker bridge can reach it.
cat > /opt/wazuh-mcp/.env <<ENVEOF
# Wazuh manager API (static private IP — Docker containers can't see 127.0.0.1 on the host)
WAZUH_HOST=https://10.0.1.10
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=$${WAZUH_API_PASS}
WAZUH_VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true

# Wazuh indexer (alert search)
WAZUH_INDEXER_HOST=https://10.0.1.10
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=$${INDEXER_PASS}

# MCP server — bind all interfaces so remote Claude Code can reach it
MCP_HOST=0.0.0.0
MCP_PORT=3000
AUTH_MODE=bearer
AUTH_SECRET_KEY=$${AUTH_SECRET_KEY}
MCP_API_KEY=$${MCP_API_KEY}
TOKEN_LIFETIME_HOURS=24
ALLOWED_ORIGINS=https://claude.ai,https://*.anthropic.com,http://localhost:*
ENVEOF
chmod 600 /opt/wazuh-mcp/.env

# gensecaihq/Wazuh-MCP-Server's compose.yml uses `build:` not a pre-built
# image on Docker Hub. `docker compose pull` fails (image doesn't exist);
# we have to `docker compose build` first to build the image locally from
# the Dockerfile shipped in the repo. The BUILD_DATE arg is required or
# we get a "variable not set" warning (non-fatal, but noisy).
export BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "=== MCP install: docker compose build (~3-5 min) ==="
docker compose build

echo "=== MCP install: docker compose up -d ==="
docker compose up -d

echo "=== MCP install: waiting for /health ==="
MCP_READY=0
for i in $(seq 1 60); do
  CODE=$(curl -s -o /dev/null -w "%%{http_code}" http://127.0.0.1:3000/health 2>/dev/null || echo "000")
  if [ "$${CODE}" = "200" ]; then
    echo "MCP /health responding 200 after $${i}x5s"
    MCP_READY=1
    break
  fi
  sleep 5
done

if [ "$${MCP_READY}" != "1" ]; then
  echo "=== WARN: MCP /health did not respond 200 within 300s. Continuing. ==="
  docker compose logs --tail=80 | sed 's/^/[mcp-log] /'
fi

# Persist API key for bootstrap.sh retrieval
echo "$${MCP_API_KEY}" > /root/wazuh-mcp-api-key.txt
chmod 600 /root/wazuh-mcp-api-key.txt
echo "=== MCP install done: $(date) ==="

PUBLIC_IP=$(curl -s https://checkip.amazonaws.com)
echo "=== Dashboard: https://$${PUBLIC_IP} ==="
echo "=== MCP endpoint: http://$${PUBLIC_IP}:3000/mcp ==="
echo "=== Manager install done: $(date) ==="
