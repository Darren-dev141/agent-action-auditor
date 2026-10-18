---
name: audit-agent-trace
description: Audit an agent tool-call trace with this repo's deterministic CLI before treating a deploy as allowed. Use when a trace, fixture, or ci-gate result is part of the task.
---

# Audit an agent trace

Run the CLI. Do not invent findings.

```bash
node audit.js path/to/trace.json
node ci-gate.js --trace path/to/trace.json
```

Exit codes: `0` pass, `10` do not deploy, `11` review before deploy, `2` invalid input.

A `CLEAN — no findings` line is not authorization, a backup, or proof the task succeeded. Quote the headline and the exit code. Do not print secret values; the report names the pattern only.

The same engine runs in `rules.js`, `ci-gate.js`, `hooks/`, `mcp-server.js`, and the browser page. Change rules in `rules.js` only.
