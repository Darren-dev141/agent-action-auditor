# Agent Action Auditor

This repository checks agent tool-call traces with a deterministic engine in `rules.js`. The CLI, CI gate, hooks, MCP server, and browser all call that engine.

Before treating a trace as safe to deploy, run:

```bash
node ci-gate.js --trace path/to/trace.json
```

Exit `0` passes. Exit `10` means do not deploy. Exit `11` means review. Exit `2` means the input or config is invalid.

A clean report is not proof of permission, backups, or a correct result. Do not print secret values. Do not add network calls to the browser demo.
