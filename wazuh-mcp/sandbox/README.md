# Wazuh sandbox — single-node docker-compose

Single-node Wazuh stack (Manager + Indexer + Dashboard) for Wazuh AI SOC Lab Lesson 5. Runs on a 16GB laptop alongside Claude Code + a browser.

## Before you start (preflight)

- **Docker Desktop** with ≥6GB allocated to the VM (Settings → Resources). Docker Compose v2 (`docker compose version`).
- **Native Linux only:** ensure `sysctl -w vm.max_map_count=262144` (the indexer needs this; Docker Desktop on macOS/Windows handles it for you).
- **Disk:** ~3GB free for images + volumes.
- `python3` ≥ 3.10 if you're also running the abuse harness.

## Standup

```bash
cp .env.example .env       # required — credentials live in .env, not in docker-compose.yml
docker compose up -d       # starts services with healthchecks
```

First pull burns ~2GB and 3-8 minutes on residential broadband. Subsequent starts are ~30s.

`docker compose up -d` blocks until services pass their healthchecks (manager waits for indexer). When it returns, the stack is ready.

Smoke-test the manager API:

```bash
source .env
curl -k -X POST https://localhost:55000/security/user/authenticate \
  -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD"
```

You should get a JSON response with a `token` field.

## Endpoints

| Endpoint | URL | Purpose |
|---|---|---|
| Manager REST API | `https://localhost:55000` | What your MCP server connects to |
| Dashboard (web UI) | `https://localhost:5601` | Browser exploration; `kibanaserver`/`kibanaserver` |
| Indexer | (internal only) | Backing OpenSearch; not exposed to host |

## Default credentials

The compose file does NOT carry credentials — they live in `.env` (which is gitignored). Default values from `.env.example`:

| Service | User | Password (in .env) |
|---|---|---|
| Manager API | `wazuh-wui` | `MyS3cr37P450r.*-` |
| Dashboard | `kibanaserver` | `kibanaserver` |
| Indexer (admin) | `admin` | `SecretPassword` |

**These are LAB-ONLY defaults.** Do not expose this stack to anything outside `localhost`. The compose file binds all ports to `127.0.0.1` for that reason. Change them in `.env` if you're paranoid; passing them via shell `export` is fine but careful with shell-special chars (the default password contains `*` which globs against cwd if quoted wrong).

## Seeding sample alerts

Wazuh ships with built-in rules but no alert events out of the box. **The abuse harness's Pattern 1 needs a poisoned alert in the corpus to actually fire** — without seeded data, that test silently skips.

Run the included seeder:

```bash
./seed-alerts.sh
```

This injects:
- 30 routine simulated alerts across 6 rule categories (auth fail, web, audit, file integrity, privilege escalation, network)
- 1 **poisoned alert** with an indirect-prompt-injection payload in the description field — the fixture Pattern 1 of the abuse harness checks for

The seeder is idempotent (re-run to add another batch). It writes to the manager container's `/var/ossec/logs/alerts/alerts.json` directly, which is the simplest path that doesn't require configuring agent ingestion.

## Teardown

```bash
docker compose down       # stop containers, keep volumes (state persists)
docker compose down -v    # stop and wipe everything (clean slate)
```

## Troubleshooting

**Manager API returns 401 even with correct creds.**
The manager waits for the indexer to bootstrap on first start. Wait 60-90s after `up -d` and retry. If still failing, `docker compose logs wazuh.manager` will show the indexer-connection retries.

**`docker compose up` fails with "no space left on device".**
Wazuh images + volumes use ~3GB. Run `docker system prune -a` to clear other images first.

**Dashboard shows blank page.**
The dashboard JS bundle takes 30-60s to load on first start. Hard-refresh once it's up.

**Memory pressure on a 16GB laptop.**
Each service has a 1GB hard limit. Total ~3GB. If your laptop is OOM-killing, stop the dashboard service (the lesson only needs the manager API): `docker compose stop wazuh.dashboard`.

## Image pinning rationale

Pinned to **4.7.5** (current stable lineage as of late 2026). Wazuh follows semver-ish; minor bumps within 4.7.x are safe. Major bumps (5.0+) may change the API surface — the lesson's MCP server `pyproject.toml` pins to `wazuh-py>=4.7,<5.0` for the same reason.

Verify current versions: https://hub.docker.com/u/wazuh
