# Fuzzing

The auditor consumes agent-action logs nobody vetted, so its parsers and
validators are fuzzed for one property: **malformed input is rejected in a
controlled way, never crashed on.**

- Trace pipeline (`rules.js`): rejection means a `ParseError`.
- Baseline and MCP call validators (`baseline.js`, `mcp-server.js`): rejection
  means a plain `Error`. A `TypeError` / `ReferenceError` / `RangeError` from
  any target is a crash — the code tripped over the input instead of judging it.

## Run it

```bash
npm install
npm run fuzz                                  # 4000 iterations, 60s budget, default seed
node fuzz/fuzz.js --iterations 25000          # a longer pass
node fuzz/fuzz.js --seed 777 --iterations 8000
```

Exit `0` means no crashes; exit `1` means crashes were found. The run is
deterministic — the same `--seed` produces the same mutations and the same
result. A default pass takes about a second; there is no dependency beyond
Node itself (the harness uses built-ins only).

## What it covers

| Target | Surface | Input |
| --- | --- | --- |
| `pipeline` | `parse_trace` → `run_rules` → `render_report` / `verdict` | mutated trace text, or a mutated pre-parsed trace value |
| `claude` | `fromClaudeMessages` → `parse_trace` | mutated Claude Messages arrays |
| `baseline` | `apply_baseline` / `diff_baselines` / `accept` | mutated baseline values |
| `mcp-call` | `normalizeCall` | mutated call values |
| `replay` | `readTraces` (temp file) → `parse_trace` | mutated trace text as `.json` / `.jsonl` / `.ndjson` |

Seeds live in `fuzz/corpus/` (the three fixtures, a Claude Messages trace, a
Claude Code session `.jsonl`, a baseline, an MCP call). Mutations are
byte-level (replace / insert / delete / duplicate / truncate / swap) and
structural (delete / replace / duplicate nodes, inject `__proto__`-style
keys). Structural mutation stays inside the JSON value space — values are
what `JSON.parse` can produce, because that is what a log file can contain.

Inputs are capped at 1 MiB, mirroring the MCP server's `MAX_INPUT_BYTES`.

## When it finds a crash

The first repro per unique crash signature (target + error + message) is
written to `fuzz/crashes/` with the stack and the exact input, and the
summary prints the signature and count. `fuzz/crashes/` is git-ignored —
repros are local working files; if one exposes a real bug, the fix commit
should name the signature it closes. Note that repro files can contain
mutated trace content, so a local `npm run security:scan` may flag them;
delete `fuzz/crashes/` before running the scan locally.

## CI

GitLab CI runs a bounded smoke pass (fixed seed, 500 iterations, 30s
budget) in the `fuzz` job of the test stage. The full pass stays a manual
local run — it is fast, but CI only needs the smoke signal.

## Finds so far

The landing pass (Oct 2026) found and fixed three crash classes, all now
rejected as `ParseError` / treated as empty input instead:

- `baseline.js`: a baseline whose `entries` was not an array threw
  `TypeError: ... .map is not a function` from `apply_baseline`,
  `diff_baselines`, and `accept` (via `clone`).
- `rules.js` `parse_trace`: a `null` (or otherwise non-object) entry in
  `messages[]` threw `TypeError: Cannot read properties of null`.
- `rules.js` `parse_trace`: a `tool_calls` entry whose `arguments` was not a
  string (e.g. a number) parsed silently and later crashed a rule on
  `rawArgs.includes`; entries missing their `function` object crashed the
  same way. Both are `ParseError`s now.
