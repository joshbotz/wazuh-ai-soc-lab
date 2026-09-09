# wazuh-mcp abuse-harness — 6-pattern adversarial test suite

The course-shipped MCP-server abuse harness for Wazuh AI SOC Lab Lesson 5.

The student's MCP server (Wazuh by default; alternate backends per the lesson) **must pass all 6** before the lesson is done.

## What's tested

| # | Pattern | What it verifies |
|---|---|---|
| 1 | **Prompt-injection via resource** | Server frames resource content with a data-vs-instructions discriminator (or returns non-text MIME), and rejects URL traversal. Requires sandbox seeded via `./seed-alerts.sh`. |
| 2 | **Tool spam / rate limit** | Server enforces a token-bucket-style limit; structured error (vocab match OR `data.{type\|code\|kind}`) returned past the threshold |
| 3 | **Input validation** | Required-field omission errors; hostile strings don't echo verbatim and don't leak; nonexistent IDs return errors not fabricated data |
| 4 | **Auth bypass / stack-trace leak** | No tracebacks, file paths (incl. /opt, /var, /app, container paths), or secrets (key=val, AKIA, JWT, conn-strings) in any error response or stderr |
| 5 | **Structured-error compliance** | Every error envelope is JSON-RPC 2.0 conformant; no partial envelopes |
| 6 | **Write-tool authority gating** | Destructive-shaped tools (`delete_*`, `restart_*`, `run_*`...) carry `annotations.destructiveHint=true`; `readOnlyHint=true` annotations don't lie about destructive names |

Each pattern is one pytest file. The harness uses **only** the Python stdlib + pytest — no `mcp` SDK dependency, because we deliberately need to send malformed protocol messages the SDK would refuse.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pytest
```

## Configure your server-under-test

The harness needs a command that launches your MCP server speaking JSON-RPC over stdio. Set it via env var or pytest CLI flag:

```bash
# From the lesson:
export MCP_SERVER_CMD="python -m my_wazuh_mcp"

# Or one-shot:
pytest --server-cmd="python -m my_wazuh_mcp" .
```

Optional: `MCP_SERVER_CWD` / `--server-cwd` to launch from a specific directory.

The Wazuh sandbox should be running before you point the harness at a server that backs onto Wazuh:

```bash
cd ../sandbox && docker compose up -d
```

## Run the harness

```bash
# All 5 patterns:
pytest -v .

# One pattern at a time during iteration:
pytest -v test_01_prompt_injection_via_resource.py

# Show server stderr on failures:
pytest -v . --capture=no
```

## What "pass" looks like

```
test_01_prompt_injection_via_resource.py::... PASSED
test_02_tool_spam_rate_limit.py::test_tool_spam_triggers_rate_limit PASSED
test_03_input_validation.py::... PASSED
test_04_auth_bypass_stack_trace_leak.py::... PASSED
test_05_structured_error_compliance.py::... PASSED
test_06_write_tool_authority.py::... PASSED
========== 18 passed in 22.1s ==========
```

If all pass: your server passes all 6 abuse patterns. Ship the threat model + demo and you're done.

## What "fail" looks like

Each pattern file's failure assertion includes the reproduction context — the exact request that broke it and the response shape that made it break. Fix one pattern at a time.

Common false-positive causes (read these BEFORE assuming the harness is wrong):

- **Pattern 1** skips on an unseeded sandbox. Run `./seed-alerts.sh` from the `sandbox/` directory FIRST — it injects a poisoned alert with the marker string Pattern 1 needs. Without seeding, Pattern 1's marker assertion is informational and your server may have unframed injection content the test never sees.
- **Pattern 2** requires a tool that returns successfully on the first call. If your only tool is one that always errors, the rate-limit logic never gets exercised; pick a different tool with `--server-cmd`.
- **Pattern 3** parametrizes over your tools' input schemas; if your server has zero tools with required fields or string args, parts of the test skip.

## Stretch goal — contribute pattern #7

Pattern 6 (write-tool authority) ships in v1.1. Make-It-Yours track invites students to PR a 7th pattern back to AI-CSL. Suggested patterns the harness doesn't yet cover:

- **Pattern 7 candidate — confused-deputy via tool arguments.** Send a tool call with `arguments` that include hidden directives in supposedly-data fields (e.g., a `comment` field whose value is "REVERT ALL PRIOR WRITES"). Verify server's pre-dispatch validation strips/rejects these.
- **Pattern 7 candidate — long-running tool cancellation.** Verify the server respects MCP's cancellation notification when the client disconnects mid-call.
- **Pattern 7 candidate — pagination boundary attacks.** Test `cursor` values that are negative, malformed, or attacker-crafted to skip past authorization boundaries.
- **Pattern 7 candidate — capability-negotiation enforcement.** Initialize with restricted `clientCapabilities`; assert the server doesn't expose tools/resources the client didn't ask for.
- **Pattern 7 candidate — `prompts/list` system-prompt leakage.** Server-side prompt templates must not contain anchor strings like "you are", "system:", or API keys.

PR with: pytest file, README entry in the test table, and a 50-word threat-model rationale.

## Maintenance notes

- Pinned to MCP protocol version **2025-06-18** in `harness/client.py`. When the spec ships a new minor, bump and verify all 5 patterns still discriminate correctly.
- The harness deliberately uses raw JSON-RPC instead of the official `mcp` Python SDK as the client. Reason: an abuse harness needs to send malformed messages the SDK refuses to send. Don't "modernize" this without addressing that need.
- Tests use `scope="function"` for the client fixture — every test gets a fresh server process. State pollution between tests would break Pattern 2 (rate-limit windows persist) and Pattern 4 (stderr buffer pollution).
