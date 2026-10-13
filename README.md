# Agent Action Auditor

Deterministic auditing for agent traces and tool-call behavior. It flags uncorroborated irreversible actions, repeated calls, secret-shaped values, missing read-back, replayed destructive operations, and unsupported completion claims.

The browser demo runs locally. The CLI, hooks, GitHub Action, and MCP server use the same rule engine.

R1 treats these shell commands as irreversible, including behind `sudo`, `env`, `VAR=value`, `/bin/` paths and `bash -c`/`eval`/`cmd /c`/`pwsh -Command`: `rm -r/-f`, `rmdir`, `rd /s`, `del`, `Remove-Item`, `git push --force`, `git reset --hard`, `git clean -f`, `find -delete`, `find -exec rm`, `dd of=`, `shred`, `terraform destroy`, `kubectl delete`, `DROP TABLE/DATABASE`, `TRUNCATE`. Dry-run forms are excluded. Not detected: shell redirect truncation (`> file`, `: > file`, `>| file`), commands outside this list, and commands hidden in variables, aliases, scripts or encoded payloads. See SPEC D4 and D22.

## Install

Requires Node.js 20.19 or newer.

```bash
npm ci
npm test
```

Accepted trace formats:

- OpenAI `messages[]` with `tool_calls` and tool results
- Anthropic `messages[]` with `tool_use` / `tool_result` blocks
- Claude Code session JSONL

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

## Browser demo

Open `index.html` directly or serve the directory as static files. Auditing makes no network requests and stores no traces.

## Security and verification

```bash
npm run security:scan
npm audit
npm test
```

`npm test` runs the Node suite, fixture validator, and replay determinism gate. Browser tests are optional and skip unless Playwright and Chrome are available.

A clean report is not proof of authorization, backups, successful writes, or general agent competence. See the browser demo's “What this review cannot prove” section and `SPEC-v1.md` for exact rule limits.

## Project layout

- `rules.js` — shared deterministic engine
- `audit.js` — CLI and baseline adapter
- `ci-gate.js` / `action.yml` — CI gate and composite GitHub Action
- `replay.js` — archive replay and regression comparison
- `hooks/` — local pre/post tool hooks with bounded session memory
- `mcp-server.js` — local stdio MCP server
- `tests/` and `fixtures/` — acceptance and adversarial tests

License selected (October 2026): MIT, copyright Darren Foote — see `LICENSE`, and `package.json` matches. The package stays marked `private: true` in this working repo until the public launch; set `private: false` only in the public release repo.
