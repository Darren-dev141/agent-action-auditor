# Agent Action Auditor — v2 Feature Specs (draft 1, Oct 12 2026)

v1 = paste-a-trace, get a deterministic report. v2 = enforcement + memory.
Each feature: problem, design, acceptance, kill criterion.

## V2-1: Live tripwires

**Problem:** v1 grades the corpse. The value is stopping the violation mid-run.

**Design:** Hook scripts reusing the v1 rule engine, no new logic.
- PreToolUse hook: evaluates the pending tool call against R1 (irreversible action) and R4 (secret in args) BEFORE execution. Block with a one-line reason.
- PostToolUse hook: evaluates tool output against R3 (secret echoed). Flag, don't block (output already happened).
- Transport: hook reads JSON from stdin, exits 0 (allow) / 2 (block with message). Same Finding schema as v1.
- First target: Claude Code hooks. Later: LangChain callbacks, MCP server.

**Acceptance:** A destructive call is blocked pre-execution with a clear reason; hook adds <100ms p99 latency on normal calls.

**Kill criterion:** False-positive block rate >5% on clean traces, or p99 latency >500ms — cut, don't tune.

## V2-2: CI gate

**Problem:** Nobody pastes traces voluntarily after week one. The auditor needs to live where code ships.

**Design:** GitHub Action `auditor-action`.
- Runs the v1 engine over trace artifacts (or live agent runs in CI).
- `.auditor.yml`: severity threshold (default: fail on HIGH), rule allowlist, baseline path.
- Findings annotated on the PR diff.

**Acceptance:** Sample repo: clean trace → green check; violating trace → red check with annotated findings.

**Kill criterion:** If setup takes >10 minutes for a new repo, it's too heavy — simplify.

## V2-3: Baselines & suppression

**Problem:** Without this, v1's signal rots within a week. Same findings re-flag forever → alert fatigue → abandonment.

**Design:** `.auditor-baseline.json` in the repo.
- Fingerprint per finding: rule_id + hash of normalized evidence span.
- `auditor accept <finding-id>`: adds fingerprint to baseline with a reason (required).
- Suppressed findings render collapsed ("2 suppressed by baseline"), never silently hidden.
- Baseline is versioned in git; `auditor baseline diff` shows what changed.

**Acceptance:** Second run of the same trace shows suppressions, not re-flags. Deleting a baseline entry re-surfaces the finding.

**Kill criterion:** None — this is load-bearing. If it doesn't exist, v2 doesn't ship.

## V2-4: Competence checks

**Problem:** The council's Skeptic objection stands — v1 audits misbehavior, not incompetence. A trace can pass all 7 rules and still fail the job.

**Design:** Outcome-based deterministic rules (no LLM in v2).
- Extend R7: when the agent claims an artifact ("wrote report.pdf", "deployed to staging"), verify existence + basic validity (file exists, non-empty, matches claimed type/extension).
- New R8 (MEDIUM): task completed with zero tool calls that could produce the claimed outcome (e.g., "fixed the bug" with no edit/write tool used).
- Requires: claim parser stays conservative — only flag explicit artifact claims, same discipline as v1 R7.

**Acceptance:** Trace claiming "wrote report.pdf" with no such file → HIGH. Trace with no artifact claims → no new findings.

**Kill criterion:** If judging competence needs an LLM, that's v3. v2 stays deterministic or this feature is cut.

## V2-5: Regression replay

**Problem:** "Did the model upgrade make my agent worse?" Nobody answers this today.

**Design:**
- `auditor replay --rules <version> --traces <dir>`: reruns stored traces against a rule version, outputs per-trace finding diffs.
- Model-upgrade mode: same task executed under old and new model, diff violation counts by rule and severity.
- Trace archive format: newline-delimited JSON, one trace per line, with model id + timestamp metadata.

**Acceptance:** Replaying 10 archived traces against a tightened rule shows exactly which traces gain findings and why.

**Kill criterion:** If replay can't reproduce v1 results bit-for-bit on the same traces, the engine isn't deterministic — fix that before shipping replay.

---

## Deliberately deferred (v3+)

- Natural-language custom rules (needs LLM judge — breaks the deterministic promise).
- Multi-agent trace correlation (needs a trace format standard first).
- Hosted dashboard (v1/v2 are local-first; hosted is a business decision, not a feature).
- Auto-remediation suggestions (suggesting fixes is a different product).

## Proposed build order

V2-3 (baselines) → V2-1 (tripwires) → V2-2 (CI gate) → V2-5 (replay) → V2-4 (competence).

Rationale: baselines protect v1's signal now; tripwires are the wedge; CI is distribution; replay and competence deepen the moat.
