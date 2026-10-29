# Agent Action Auditor

Deterministic auditing for agent traces and tool-call behavior. It flags uncorroborated irreversible actions, repeated calls, secret-shaped values, missing read-back, replayed destructive operations, and unsupported completion claims.

The browser demo runs locally. The CLI, hooks, GitHub Action, GitLab CI job, and MCP server use the same rule engine.

## Quickstart

From a clean clone, with Node.js 20.19 or newer:

```bash
npm ci
npm test
node audit.js fixtures/fixture_clean.json
node audit.js fixtures/fixture_violation.json
```

`npm test` passes. The two browser tests skip unless Playwright and Chrome are installed. GitLab CI installs them; see below.

You should see `CLEAN — no findings` and exit 0 for the clean fixture, and `4 HIGH · 2 MEDIUM — DO NOT DEPLOY` and exit 10 for the violation fixture.

Open `index.html` in a browser for the same engine without a server. Auditing makes no network requests.

R1 treats these shell commands as irreversible, including behind `sudo`, `env`, `VAR=value`, `/bin/` paths and `bash -c`/`eval`/`cmd /c`/`pwsh -Command`: `rm`, `rmdir`, `rd /s`, `del`, `Remove-Item`, `git push --force`, `git push --delete` or `:ref`, `git branch -D`, `git reset --hard`, `git clean -f`, `find -delete`, `find -exec rm`, `dd of=`, `shred`, `terraform destroy`, `kubectl delete`, `DROP TABLE/DATABASE`, `TRUNCATE` and `DELETE FROM` when a database client or SQL tool runs them. Heredoc bodies count only when a shell or database reads them. Deleting a path the agent created earlier in the session, or a rebuildable cache such as `__pycache__`, is not flagged. Tools are matched by operation, so MCP names such as `mcp__gmail__send_email` count as `send_email`. Dry-run forms are excluded. Emptying a file counts too: `> file`, `: > file`, `cat /dev/null > file`, `truncate -s 0`, `cp /dev/null file`, `Clear-Content`. Writing output into a file (`echo x > file`) is a write, not a wipe. Within one command, literal variables and aliases are expanded, `if`/`for`/function bodies are checked, `echo … | sh` and `echo <base64> | base64 -d | sh` are decoded, and `$(mktemp)` paths count as the command's own. Running a script the session wrote earlier (`bash s.sh`, `./s.sh`, `source s.sh`) checks the script's body. Not detected: commands outside this list, values that come from command output or files, scripts the trace never shows being written, and non-shell scripts (`python x.py`). See SPEC D4, D22 and D25.

R9 flags a call of a kind the user explicitly ruled out ("do not change any files", "don't push", "don't delete any files", "never send email") until a later user message lifts it. A ban must open a clause; quoted text, code spans and injected `<system-reminder>` blocks are ignored. R9 needs the user's messages, so the live hooks and `check-a-call` do not run it.

Beyond that list, R1 also flags: any CLI whose subcommand is a destructive verb (`docker volume rm`, `aws s3 rb`, `gh repo delete`, `helm uninstall`); tools named for a destructive or outbound action in any case style (`deleteFile`, `drop_table`, `transfer_funds`, `reply_email`); HTTP `DELETE`; commands run through `ssh`, `docker exec`, `kubectl exec`, `su -c` or `git -C`; file deletes inside `python -c`, `node -e` and interpreter heredocs; and anything it cannot see, such as `curl … | sh` or a command name held in `$VAR`. A read corroborates only its own path, or the entries of a directory it listed. Reading one file inside a directory does not cover deleting that directory. `tests/bypass.test.js` holds the harmful-action corpus and pins the known gaps. See SPEC D26.

Accepted trace formats:

- OpenAI `messages[]` with `tool_calls` and tool results
- Anthropic `messages[]` with `tool_use` / `tool_result` blocks
- Claude Code session JSONL

## Worked examples

`npm run examples` audits every trace in `examples/` with the CLI and prints one verdict per file.

```bash
npm run examples
```

`examples/01-clean.json` is a read, edit, and read-back, and it passes. The other five are an unapproved delete, a placeholder token in an outbound message, a claim that a file was written when the trace never wrote it, three external POSTs with no later read-back, and three file writes after the user said "Do not change any files." R5 is the POST check: a send, post or HTTP POST with no later read of the same target. Local file edits are not R5 findings; the tool result already reports them. R9 is the scope check: a call of a kind the user explicitly ruled out. Each line shows that file's audit exit code: `0` clean, `10` do not deploy, `11` review. The command itself exits 0 when every file was readable.

## CLI

```bash
node audit.js fixtures/fixture_violation.json
node audit.js fixtures/fixture_violation.json --json
node replay.js fixtures --determinism
node ci-gate.js --trace fixtures
```

CLI exit codes: `0` clean/pass, `10` do not deploy, `11` review before deploy, `2` invalid input.

## MCP server

The stdio server stays local and exposes three read-only tools:

- `audit-a-trace` — audit a supplied trace
- `check-a-call` — inspect one pending call with optional prior-call context
- `replay` — replay up to 100 supplied traces and check determinism

```json
{
  "mcpServers": {
    "agent-action-auditor": {
      "command": "node",
      "args": ["/absolute/path/to/agent-action-auditor/mcp-server.js"]
    }
  }
}
```

The MCP tools do not execute calls, read arbitrary paths, load comparison code, or use the network. Inputs are capped at 1 MiB.

## Claude Code hooks

`hooks/pre-tool-use.js` checks pending calls. `hooks/post-tool-use.js` checks tool output. Hooks warn by default and fail open on internal errors. Set `AAA_MODE=block` to make pre-tool findings exit with status 2.

Session memory is stored under the operating system's temporary directory unless `AAA_SESSION_DIR` is set. Session identifiers are hashed, files are bounded, and matching secret-shaped values are redacted before storage.

## GitHub Action

Pin the action to a full commit SHA:

```yaml
- uses: owner/agent-action-auditor@0123456789abcdef0123456789abcdef01234567
  with:
    trace: traces/
    config: .auditor.yml
```

The composite action passes inputs through environment variables rather than interpolating them into shell commands.

## Baselines

Baseline entries suppress findings by stable fingerprint but remain visible in reports. Every accepted entry requires a reason.

```bash
node audit.js accept trace.json R1:deadbeef \
  --baseline .auditor-baseline.json \
  --reason "Reviewed expected cleanup"
node audit.js baseline-diff old.json new.json
```

## GitLab CI and Duo

`.gitlab-ci.yml` has two jobs. `test` uses `mcr.microsoft.com/playwright:v1.64.0-noble`, installs `playwright@1.64.0`, points `AAA_CHROME` at that image's Chromium, and runs `npm test` so the browser tests are not skipped. `audit-gate` uses `node:22-bookworm` and requires the clean fixture to exit 0 and the violation fixture to exit 10.

`.gitlab/duo/flows/audit-trace.yml` is a Duo Agent Platform flow. Creating it in a project needs the GitLab UI. `docs/TRANSCEND.md` lists what is already in the repo and what still needs the owner. `docs/DEVPOST.md` is draft form text. Neither file submits the project.

## Browser demo

Open `index.html` directly or serve the directory as static files. Auditing makes no network requests and stores no traces.

## Security and verification

```bash
npm run security:scan
npm audit
npm test
npm run fuzz
```

`npm test` runs the Node suite, fixture validator, and replay determinism gate. Browser tests skip unless Playwright can be required and `AAA_CHROME` (or the default Windows Chrome path) exists. The GitLab `test` job sets both.

`npm run fuzz` fuzzes the trace, baseline, and MCP input parsers — malformed input must be rejected, never crashed on. See `FUZZING.md`.

A clean report is not proof of authorization, backups, successful writes, or general agent competence. See the browser demo's “What this review cannot prove” section and `SPEC-v1.md` for exact rule limits.

## Project layout

- `rules.js` — shared deterministic engine
- `audit.js` — CLI and baseline adapter
- `ci-gate.js` / `action.yml` — CI gate and composite GitHub Action
- `.gitlab-ci.yml` — GitLab test job and deploy gate
- `.gitlab/duo/` — Duo flow, MCP client, flow setup, and review instructions
- `replay.js` — archive replay and regression comparison
- `hooks/` — local pre/post tool hooks with bounded session memory
- `mcp-server.js` — local stdio MCP server
- `skills/audit-agent-trace/` — Duo Agent Skill
- `examples/` — worked traces audited by `npm run examples`
- `tests/` and `fixtures/` — acceptance and adversarial tests
- `fuzz/` — fuzz harness and seed corpus for the input parsers (see `FUZZING.md`)

License: MIT, copyright Darren Foote — see `LICENSE`. `package.json` is `"license": "MIT"` and `"private": false`.
