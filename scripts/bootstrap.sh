#!/bin/bash
# CloudVault Wazuh Lab - One-command deploy + verify
#
# Deploys the lab, waits for Wazuh to finish installing, fetches passwords,
# and prints everything you need to start the course.
#
# Usage: ./scripts/bootstrap.sh

set -euo pipefail

# --- Colors ---
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

info()    { echo -e "${BLUE}[i]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[✗]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TF_DIR="$REPO_ROOT/terraform"

echo -e "${BOLD}"
cat << 'BANNER'
============================================
  CloudVault Wazuh Lab - Bootstrap
============================================
BANNER
echo -e "${NC}"

# --- Pre-flight checks ---
info "Pre-flight checks..."

if ! command -v terraform >/dev/null 2>&1; then
  fail "Terraform not installed. Install from https://terraform.io"
  exit 1
fi
success "Terraform installed ($(terraform version | head -1))"

if ! command -v aws >/dev/null 2>&1; then
  fail "AWS CLI not installed. Install with: brew install awscli (or equivalent)"
  exit 1
fi
success "AWS CLI installed"

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  fail "AWS credentials not configured. Run: aws configure"
  exit 1
fi
success "AWS credentials configured (account: $(aws sts get-caller-identity --query Account --output text))"

if [ ! -f "$TF_DIR/terraform.tfvars" ]; then
  fail "terraform.tfvars not found at $TF_DIR/terraform.tfvars"
  info "Copy the example and edit it:"
  info "  cp $TF_DIR/terraform.tfvars.example $TF_DIR/terraform.tfvars"
  exit 1
fi
success "terraform.tfvars configured"

# --- Terraform state backend (S3 + DynamoDB lock) ---
# Codespaces are ephemeral; local terraform.tfstate would disappear on rebuild.
# bootstrap-tfstate.sh creates the bucket + table and writes terraform/backend.hcl.
# Idempotent — skips resources that already exist.
if [ ! -f "$TF_DIR/backend.hcl" ]; then
  echo ""
  info "First run — bootstrapping S3 state backend..."
  "$SCRIPT_DIR/bootstrap-tfstate.sh"
  success "State backend ready"
fi

# --- Terraform apply ---
echo ""
info "Running terraform init..."
cd "$TF_DIR"
terraform init -upgrade -backend-config=backend.hcl >/dev/null
success "Terraform initialized"

info "Running terraform apply (this takes ~1-2 minutes)..."
terraform apply -auto-approve
success "Infrastructure deployed"

# --- Gather outputs ---
echo ""
info "Gathering deployment details..."
MANAGER_IP=$(terraform output -raw manager_public_ip)
KEY_NAME=$(terraform output -json | python3 -c 'import sys, json; d=json.load(sys.stdin); print(d["ssh_manager_command"]["value"].split(" ")[2].split("/")[-1].replace(".pem",""))' 2>/dev/null || echo "your-key")
success "Manager IP: $MANAGER_IP"

# --- Wait for Wazuh install to complete ---
echo ""
info "Waiting for Wazuh to finish installing on the manager..."
info "This takes 10-15 minutes. Grab coffee or re-read the CloudVault profile."
echo ""

ATTEMPT=0
MAX_ATTEMPTS=60  # 60 * 30s = 30 minutes max
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

# Definitive "install done" signal: the Wazuh installer writes
# /root/wazuh-install-files/wazuh-passwords.txt only AFTER every service is up.
# The API starts responding 4-5 minutes before that, so polling the API has a
# race. Poll the passwords file directly instead.
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
  ATTEMPT=$((ATTEMPT + 1))
  if ssh -i ~/.ssh/$KEY_NAME.pem $SSH_OPTS ubuntu@$MANAGER_IP \
    'sudo test -f /root/wazuh-install-files/wazuh-passwords.txt' 2>/dev/null; then
    success "Wazuh install complete (attempt $ATTEMPT — passwords file present)"
    break
  fi
  printf "  [%02d/%02d] Waiting for Wazuh install to finish... \r" "$ATTEMPT" "$MAX_ATTEMPTS"
  sleep 30
done

echo ""
if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
  warn "Wazuh install did not complete after 30 minutes."
  warn "Check the install log:"
  warn "  ssh -i ~/.ssh/$KEY_NAME.pem ubuntu@$MANAGER_IP 'sudo tail -50 /var/log/wazuh-install.log'"
  exit 1
fi

# --- Verify API reachable ---
info "Verifying Wazuh API is reachable on :55000..."
for i in $(seq 1 10); do
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$MANAGER_IP:55000/" || echo "000")
  if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ]; then
    success "API responding on :55000"
    break
  fi
  [ $i -eq 10 ] && warn "API not responding. Check security group :55000 rule."
  sleep 5
done

# --- Verify indexer reachable ---
info "Verifying Wazuh Indexer is up..."
for i in $(seq 1 20); do
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$MANAGER_IP:9200/" || echo "000")
  if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ]; then
    success "Indexer responding on :9200"
    break
  fi
  if [ $i -eq 20 ]; then
    warn "Indexer not responding on :9200 after 100s."
    warn "If this persists, run ./scripts/doctor.sh to diagnose (often a network.host binding issue)."
  fi
  sleep 5
done

# --- Fetch credentials ---
echo ""
info "Retrieving Wazuh credentials..."
PASSWORDS=$(ssh -i ~/.ssh/$KEY_NAME.pem $SSH_OPTS \
  ubuntu@$MANAGER_IP 'sudo cat /root/wazuh-install-files/wazuh-passwords.txt 2>/dev/null' 2>/dev/null || echo "")

if [ -z "$PASSWORDS" ]; then
  warn "Could not fetch passwords — unexpected since install is complete. Try manually:"
  warn "  ssh -i ~/.ssh/$KEY_NAME.pem ubuntu@$MANAGER_IP 'sudo cat /root/wazuh-install-files/wazuh-passwords.txt'"
else
  # Save to local file for convenience
  echo "$PASSWORDS" > "$REPO_ROOT/.lab-credentials.txt"
  chmod 600 "$REPO_ROOT/.lab-credentials.txt"
  success "Credentials saved to $REPO_ROOT/.lab-credentials.txt (chmod 600)"
fi

# --- Wait for agents ---
echo ""
info "Waiting for all 3 agents to register with the manager..."
info "(Agents need ~5-10 more minutes after the manager is up.)"
info "This step is optional — you can Ctrl+C and check agent status later with doctor.sh."

# Parse passwords file. Actual format (Wazuh 4.9.x):
#   # Admin user for the web user interface and Wazuh indexer...
#     indexer_username: 'admin'
#     indexer_password: 'SECRET'
#
# We grep for the user line, read the line below, and extract the quoted value.
ADMIN_PASS=$(echo "$PASSWORDS" | grep -A1 "indexer_username: 'admin'"   | tail -1 | grep -oE "'[^']+'" | tr -d "'")
WUI_PASS=$(echo "$PASSWORDS"   | grep -A1 "api_username: 'wazuh-wui'"   | tail -1 | grep -oE "'[^']+'" | tr -d "'")

if [ -n "$ADMIN_PASS" ] && [ -n "$WUI_PASS" ]; then
  for i in $(seq 1 20); do
    # Wazuh 4.9 requires a JWT for /agents — get one via Basic auth against
    # /security/user/authenticate, then use the bearer token for the actual query.
    API_TOKEN=$(curl -sk --max-time 5 -u "wazuh-wui:$WUI_PASS" \
      -X POST "https://$MANAGER_IP:55000/security/user/authenticate" 2>/dev/null | \
      python3 -c 'import sys, json; print(json.load(sys.stdin).get("data",{}).get("token",""))' 2>/dev/null || echo "")

    if [ -n "$API_TOKEN" ]; then
      ACTIVE_AGENTS=$(curl -sk --max-time 5 -H "Authorization: Bearer $API_TOKEN" \
        "https://$MANAGER_IP:55000/agents?status=active&limit=10" 2>/dev/null | \
        python3 -c 'import sys, json; d=json.load(sys.stdin); print(d.get("data",{}).get("total_affected_items",0))' 2>/dev/null || echo "0")
    else
      ACTIVE_AGENTS=0
    fi

    if [ "$ACTIVE_AGENTS" -ge 4 ]; then
      success "All agents registered ($ACTIVE_AGENTS active including manager node 000)"
      break
    fi
    printf "  [%02d/20] Active agents so far: %s (expecting 4: manager + web + app + dev)\r" "$i" "$ACTIVE_AGENTS"
    sleep 30
  done
  echo ""
fi

# --- Wait for MCP server + wire up .mcp.json ---
#
# The manager's user_data pre-installs the Wazuh MCP server (Docker on :3000,
# bearer auth). We wait for /health, pull the API key via SSH, exchange it
# for a JWT, and write .mcp.json in the repo root so Claude Code auto-mounts
# the MCP the next time the student launches `claude` in this directory.
#
# Why pre-install + auto-wire: L3 is about learning to threat-model MCP,
# not about fighting Docker/CORS/auth flows. Install drudgery is a 45-min
# distraction from the pedagogy. All the security considerations still
# show up as L3 teaching content.
echo ""
info "Waiting for MCP server on the manager..."

MCP_READY=0
for i in $(seq 1 40); do
  MCP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://$MANAGER_IP:3000/health" 2>/dev/null || echo "000")
  if [ "$MCP_CODE" = "200" ]; then
    success "MCP server responding on :3000"
    MCP_READY=1
    break
  fi
  printf "  [%02d/40] MCP /health response: %s\r" "$i" "$MCP_CODE"
  sleep 15
done
echo ""

if [ "$MCP_READY" = "1" ]; then
  info "Fetching MCP API key from manager..."
  MCP_API_KEY=$(ssh -i ~/.ssh/$KEY_NAME.pem $SSH_OPTS \
    ubuntu@$MANAGER_IP 'sudo cat /root/wazuh-mcp-api-key.txt 2>/dev/null' 2>/dev/null || echo "")

  if [ -n "$MCP_API_KEY" ]; then
    info "Exchanging API key for bearer JWT..."
    JWT=$(curl -s --max-time 10 -X POST "http://$MANAGER_IP:3000/auth/token" \
      -H "Content-Type: application/json" \
      -d "{\"api_key\":\"$MCP_API_KEY\"}" \
      | python3 -c 'import sys, json
try:
    d=json.load(sys.stdin)
    print(d.get("access_token") or d.get("token") or "")
except Exception:
    print("")' 2>/dev/null || echo "")

    if [ -n "$JWT" ]; then
      cat > "$REPO_ROOT/.mcp.json" <<MCPEOF
{
  "mcpServers": {
    "wazuh": {
      "type": "http",
      "url": "http://$MANAGER_IP:3000/mcp",
      "headers": {
        "Authorization": "Bearer $JWT"
      }
    }
  }
}
MCPEOF
      chmod 600 "$REPO_ROOT/.mcp.json"
      success "MCP wired. .mcp.json written to $REPO_ROOT/.mcp.json"
      info "Claude Code will auto-mount the 'wazuh' MCP the next time you launch it here."
    else
      warn "Could not exchange API key for JWT. MCP is up but .mcp.json not written."
      warn "Manual workaround in docs/mcp-server-setup.md — L3 walks through it."
    fi
  else
    warn "Could not fetch MCP API key via SSH. Manager may still be finalizing."
    warn "Re-run bootstrap.sh after a few minutes, or see docs/mcp-server-setup.md."
  fi
else
  warn "MCP server /health did not respond within 10 minutes. Check manager logs:"
  warn "  ssh -i ~/.ssh/$KEY_NAME.pem ubuntu@$MANAGER_IP 'sudo grep -i mcp /var/log/wazuh-install.log | tail -30'"
fi

# --- Print summary panel ---
# Extract admin password from credentials file if available
ADMIN_PW=""
if [ -f "$REPO_ROOT/.lab-credentials.txt" ]; then
  # The admin password appears as the `indexer_password:` line immediately after
  # the `indexer_username: 'admin'` line. File has multiple indexer_password entries
  # (for different users), so we have to anchor on the admin username block.
  ADMIN_PW=$(grep -A1 "indexer_username: 'admin'" "$REPO_ROOT/.lab-credentials.txt" 2>/dev/null | tail -1 | grep -oE "'[^']+'" | tr -d "'" || echo "")
fi

# MCP connection status
MCP_STATUS="✗ not wired"
if [ -f "$REPO_ROOT/.mcp.json" ]; then
  MCP_STATUS="✓ auto-wired (.mcp.json written)"
fi

echo ""
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║                         LAB IS LIVE                               ║${NC}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}     https://$MANAGER_IP"
echo -e "  ${BOLD}Username:${NC}      admin"
if [ -n "$ADMIN_PW" ]; then
  echo -e "  ${BOLD}Password:${NC}      $ADMIN_PW"
else
  echo -e "  ${BOLD}Password:${NC}      (see .lab-credentials.txt — admin_password)"
fi
echo ""
echo -e "  ${BOLD}MCP server:${NC}    http://$MANAGER_IP:3000  $MCP_STATUS"
echo -e "  ${BOLD}SSH (manager):${NC} ssh -i ~/.ssh/$KEY_NAME.pem ubuntu@$MANAGER_IP"
echo ""
echo -e "  ${BOLD}${BLUE}→ NEXT STEP${NC}"
echo -e "    1. Accept the self-signed cert warning when you hit the dashboard"
echo -e "    2. Launch Claude Code in this directory:   ${BOLD}claude${NC}"
echo -e "    3. Tell Mateo:  ${BOLD}start the Wazuh lab${NC}"
echo ""
echo -e "  ${YELLOW}${BOLD}⚠ WHEN YOU'RE DONE${NC}"
echo -e "    Destroy the lab to stop AWS charges (~\$0.14/hr while running):"
echo -e "      ${BOLD}cd terraform && terraform destroy${NC}"
echo ""
echo -e "  Full creds + connection details:  ${BOLD}.lab-credentials.txt${NC}"
echo -e "  Troubleshooting:                  ${BOLD}./scripts/doctor.sh${NC}"
echo ""
