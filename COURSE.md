# Running this lab in a group or class

> Context for any AI assistant helping with this repo. The primary teaching surface is `.claude/skills/course-3-instructor/SKILL.md` (the Mateo persona) which auto-loads in Claude Code. This file is a cold-start map for assistants that don't load that skill.

---

## How to run it

**The lab is the repo.** Each person clones it, launches Claude Code, and tells it "start the Wazuh lab." The instructor skill activates Mateo (a senior-SOC-analyst persona), who guides them through all six phases end-to-end. It works solo, in a workshop, or as a class assignment — everyone deploys their own copy in their own AWS account.

**If someone asks something the skill file doesn't cover:** read `.claude/skills/course-3-instructor/SKILL.md` — that's the source of truth.

---

## Lab structure

The lab has **6 core phases** that run as one ~2-hour continuous session.

### Narrative frame (critical — do not break)

Course 3 is a continuation of the CloudVault Financial arc from Courses 1-2. The student is CloudVault's security lead (from C1-C2). **Mateo is a senior SOC analyst brought in by Dana (CISO) after the contractor breach in C2.** He is a peer, not an instructor — never references "Course 3," "Lesson N," "the exercise," or "the simulation" to the student.

**The investigation spine:** the contractor IR from Course 2 flagged three suspected persistence mechanisms (account, network listener, scheduler) that were never confirmed eliminated. Wazuh is being stood up now both to answer "are they still in?" and to provide SOC 2 evidence before the audit. Every phase serves that spine.

### Core arc (in SKILL.md §7–§12)

| # | Phase | What happens |
|---|-------|--------------|
| 1 | 🛡️ Stand up the SIEM | Student clones the repo, edits `tfvars`, runs `./scripts/bootstrap.sh`. Mateo briefs the case, walks Terraform / Wazuh architecture / MCP preview / dashboard during the ~20-min install wait. Login, dashboard tour, first reverse-prompt cycle, SCA + vuln exploration. |
| 2 | 🎯 Baseline the environment | SSH to dev-server-01, run `sudo bash /home/ubuntu/generate-events.sh` (4 MITRE-mapped TTPs matching the IR report's pattern classes). Investigate manually. Confirm SIEM coverage before hunting. First update to Dana. |
| 3 | 🔗 Threat-model the MCP + plug it in | MCP is pre-installed by user_data + auto-wired into `.mcp.json` by bootstrap.sh. Student inspects what's running, threat-models it (stolen JWT / prompt injection / supply chain), re-runs the baseline investigation via natural language. Verification-as-reflex practice. |
| 4 | 🎯 The backdoor hunt | Four structured hunts against the three persistence categories from the IR report (account, listener, scheduler) plus an AI-verification drill. Hypothesis / query / disposition framing → hunt log → SOC 2 evidence. |
| 5 | ⚡ Tripwires and response | Rule-syntax primer against a real Wazuh default. Student writes rule 100001 (CloudVault client-data tripwire Dana asked for), validates with `wazuh-logtest`, deploys, triggers, verifies firing via MCP. Duration-based active response (anti-`wazuh_firewall_allow` quirk). |
| 6 | 🧹 Close the case | Compressed IR on a fresh alert (brute-force on web-server-01). Evidence package for Dana + SOC 2 (CC7.1 / CC7.2). Personal artifact for interviews. `terraform destroy` with verification. |

---

## Fictional company: CloudVault Financial (canon across C1-C3)

Mid-size wealth-management firm, **200 employees, $2.1B AUM, Austin**. **Dana Chen is CISO**, not IT director — she hired the student (the security lead) before Course 1. Marcus Webb = junior analyst. Priya Sharma = DevOps lead. Mateo joined as a short-engagement senior peer after the Course 2 contractor breach.

**What happened in Courses 1-2 that Course 3 continues from:** a compromised contractor account escalated via `sts:AssumeRole`, exfiltrated client documents, and attempted CloudTrail cover-up (C2's 28-event attack chain). The IR report flagged three suspected persistence mechanisms the attacker may have left — account, network listener, scheduler — none definitively eliminated. SOC 2 Type II audit ~6 weeks out; evidence collection drives the urgency.

- **Three servers deployed:** `web-server-01` (nginx+TLS portal), `app-server-01` (Python API `/health` + `/api/accounts`), `dev-server-01` (dev workstation + attack launch point)
- **Wazuh manager + 3 agents**, all monitored by FIM, SCA, rootcheck, vulnerability detection
- **CloudVault paths on agents** (monitored by FIM in realtime): `/opt/cloudvault/client-data/`, `/opt/cloudvault/financial-records/`, `/opt/cloudvault/config/`

---

## Architecture facts any assistant should know

- **Static private IPs** — manager `10.0.1.10`, web `10.0.1.20`, app `10.0.1.30`, dev `10.0.1.40`. Mappings live in `/etc/hosts` on each agent.
- **MCP server** — pre-installed on the manager by `terraform/user_data/wazuh_manager.sh`. Docker container listens on port 3000 with bearer auth. `bootstrap.sh` fetches the JWT and writes `.mcp.json` in the repo root.
- **Attack generator** — `scripts/agent-events-generator.sh` is the source. It's deployed to `/home/ubuntu/generate-events.sh` on each agent via user_data base64 encode. The agent copy is what actually runs.
- **Credentials** — `.lab-credentials.txt` (gitignored, written by bootstrap.sh from the install tarball). `.mcp.json` (gitignored, written by bootstrap.sh from MCP /auth/token exchange).
- **Idempotency** — `bootstrap.sh` is re-runnable; re-running fetches fresh credentials and re-writes `.mcp.json`. `terraform apply` is idempotent.

---

## Quick reference for AI assistants in this repo

1. **"Has the student run the generator yet?"** — Check the indexer for recent alerts from dev-server-01 via the MCP (`get_alerts` with `agent.name:"dev-server-01"`, last 15 min). If empty, they haven't run it. Path on the agent: `/home/ubuntu/generate-events.sh`.
2. **"MCP isn't connected" in Claude Code** — Restart Claude Code (it only reads `.mcp.json` at launch). If still broken: JWT may have expired (24h default) — re-run `bootstrap.sh` or its MCP-wiring section.
3. **"Filter syntax in the dashboard"** — Wazuh 4.9 defaults to DQL (`rule.level >= 5 and agent.name : "dev-server-01"`), NOT the old Lucene syntax (`rule.level:>=5`). If the student sees "Expected value" syntax errors, it's DQL vs Lucene.
4. **"Dashboard menu paths"** — Wazuh 4.9 renamed things vs older docs. See SKILL.md §5 Block 6 for the authoritative map (`☰ → Threat intelligence → Threat Hunting` is home base for alerts, not the old "Modules → Security Events").
5. **"Expected false positives"** — Rule 510 on `/bin/diff` is a known Wazuh rootcheck FP. Document and ignore.

---

## Contributing / feedback

- **Infrastructure bugs** (Terraform, user_data, bootstrap, MCP install): GitHub Issue + PR
- **Course content** (Mateo voice, lesson pedagogy): GitHub Issue + PR against SKILL.md
- **Upstream Wazuh / MCP issues**: upstream to gensecaihq/Wazuh-MCP-Server or wazuh/wazuh

MIT licensed — use in training, workshops, demos. Attribution appreciated.
