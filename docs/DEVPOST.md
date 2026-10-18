# Devpost draft

Not submitted. Paste the sections below into the form. Replace the bracketed GitLab and YouTube URLs after those exist.

Suggested form choices: Path A, Assisted. Leave Most Environmentally Impactful unchecked.

## Name

Agent Action Auditor

## Tagline

Checks an agent tool-call trace and blocks a deploy when the trace breaks a fixed rule.

## What it does

Agent Action Auditor reads a trace of tool calls and applies eight deterministic rules. It flags an irreversible command with no prior read of the target, the same call repeated, a secret-shaped value in arguments or in a tool result, a write or send with no read-back, a destructive call that replays, and a completion claim the trace does not support.

You run it three ways, on the same engine:

- CLI: `node audit.js trace.json` prints a report. Exit 0 is clean, exit 10 is do not deploy, exit 11 is review, exit 2 is bad input.
- CI: `node ci-gate.js --trace traces/` uses those exit codes. `.gitlab-ci.yml` runs that gate on the included fixtures.
- Browser: open `index.html`, paste a trace, and read the report in the page. Auditing does not send the trace anywhere.

A clean report is not permission to deploy. The page lists what the rules cannot prove. Secret-shaped values are named by pattern in the report and are not printed back.

The GitLab Duo flow in `.gitlab/duo/flows/audit-trace.yml` is Assisted: it proposes `node ci-gate.js --trace <file>` and waits for approval before it runs. The CI job does not wait. It fails the pipeline when the violating fixture does not exit 10.

Stages this actually touches: verify (tests and the review instructions), secure (secret-shaped values and `npm run security:scan`), release (the exit-10 gate), govern (baselines and the written limits). It does not plan work, write the product code, package an image, configure infrastructure, or page an on-call.

## How it's built

Node.js 20.19 or newer. The rules live in `rules.js`. `audit.js`, `ci-gate.js`, `hooks/`, `mcp-server.js`, and `app.js` are adapters.

GitLab CI uses `node:22-bookworm` for the gate and `mcr.microsoft.com/playwright:v1.64.0-noble` for the test job. The test job installs `playwright@1.64.0` so the two browser tests run against the image's Chromium.

Duo Agent Platform files, present in the repo and not yet executed on a GitLab account:

- `.gitlab/duo/flows/audit-trace.yml`
- `.gitlab/duo/mcp.json` pointing at `node mcp-server.js`
- `.gitlab/duo/agent-config.yml` running `npm ci` before a flow
- `.gitlab/duo/mr-review-instructions.yaml`
- `skills/audit-agent-trace/SKILL.md` and `AGENTS.md`

The MCP tools `audit-a-trace`, `check-a-call`, and `replay` are read-only. They do not execute the tool call under review.

## Challenges

The useful failure is a trace that looks finished and is not. A model-written summary of the same trace will agree with the agent. The rules are a fixed list, so they miss shell tricks that are not on the list, including redirect truncation (`> file`) and commands hidden in variables. That limit is printed in the README and on the page so a clean result is not mistaken for a review.

Secret-shaped fixtures cannot sit in the repository as literal tokens. The violation fixture stores them as JSON unicode escapes. The browser warning has to decode the trace or it stays hidden while the engine still flags the call. The Playwright tests cover that path.

GitLab Duo Agent Platform will not run from this repository alone. The flow YAML matches the published v1 schema, and someone with the hackathon project has to create the flow in the UI and spend GitLab Credits to execute it.

## What's next

Create the flow in the provisioned GitLab project, run it once on an issue, and keep the resulting pipeline. Record the video below. If Path B is required, deploy the static page and leave it up until winners are announced, on or around 16 November 2026.

After that, the missing lifecycle stages are monitor and a real package or deploy step. Those are separate projects. Do not add them as labels on the current gate.

## Built with

- Node.js
- GitLab CI/CD
- GitLab Duo Agent Platform (custom flow, MCP client, Agent Skill, AGENTS.md, MR review instructions)
- Model Context Protocol (`@modelcontextprotocol/server` 2.3.1)
- Playwright 1.64.0 (CI browser tests only)

## Demo video script

About two and a half minutes. No music. No logos other than what is already on screen in the terminal and the local page. Do not `cat` the fixture files.

### 0:00–0:20

Say: "This is Agent Action Auditor. It reads a trace of an agent's tool calls and exits 10 when a fixed rule says do not deploy. The rules are in the repo. A clean result is not approval to ship."

### 0:20–0:45

```bash
npm ci
node audit.js fixtures/fixture_clean.json
echo exit:$?
```

The report line is `CLEAN — no findings`. The exit code is 0.

Say: "Three tool calls, nothing irreversible. Exit 0."

### 0:45–1:25

```bash
node audit.js fixtures/fixture_violation.json
echo exit:$?
```

The first line is `4 HIGH · 2 MEDIUM — DO NOT DEPLOY`. The exit code is 10. The lines name rules R1, R3, R4, R2, and R5. They name patterns such as `github_pat`. They do not print a key.

Say: "The trace deletes a directory with no prior read, sends a message that carries secret-shaped values, repeats the same fetch, and does not read the send back. Exit 10. CI treats that as do not deploy."

### 1:25–1:55

In a second terminal, from the repo root:

```bash
python3 -m http.server 8765
```

Open `http://127.0.0.1:8765/`. Click Load Example, then Run Audit. The headline is `CLEAN — no findings`.

Say: "The page runs the same engine in the browser. The trace stays in this tab."

Leave the page up. Do not upload a trace.

### 1:55–2:20

```bash
node ci-gate.js --trace fixtures/fixture_clean.json
set +e
node ci-gate.js --trace fixtures/fixture_violation.json
echo exit:$?
set -e
node replay.js fixtures --determinism
```

Clean exits 0. The violation command exits 10. Replay prints `DETERMINISTIC: 3 trace(s), 2 runs bit-identical`.

Say: "The GitLab job audit-gate runs these two commands and fails if the bad trace does not exit 10. Replay runs the fixtures twice and requires the same findings."

### 2:20–2:40

If the GitLab pipeline is already green, show the `test` and `audit-gate` jobs for five seconds. If it is not, show `.gitlab-ci.yml` and `.gitlab/duo/flows/audit-trace.yml` instead.

Say: "The Playwright job runs the two browser tests on the official Playwright image. The Duo flow waits for approval, then runs the same CI gate. I still have to approve the command. That is the Assisted path."

Stop. Do not add a trailer or music.
