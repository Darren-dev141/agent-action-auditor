---
name: verify-r1-gate
description: Use when a change touches how rules.js decides an agent action is irreversible or corroborated (shell parsing, the R1 lexicon, CLI verbs, heredocs, wrappers, pipes to a shell, the read index, checkCall/gate/sweep). Runs a bounded exhaustive check that destructive commands cannot slip past the R1 gate by rewording, benign ones are not flagged, the live gate agrees with the batch audit, and R1 is cleared only by real evidence.
---

# Verify the R1 gate

`rules.js` promises one thing above all: **an irreversible action with no evidence behind it gets a HIGH R1 finding, however the command is written.** If that breaks, `ci-gate.js` exits 0 on a trace that deletes data, and the deploy goes ahead.

Hand-written tests missed this repeatedly. When this check was first built, 340 passing tests sat beside 2,101 bypasses and 864 false alarms that it found at depth 3. So use this check, not just `npm test`, when you change the gate.

## When to run it

Run it when your diff touches any of these in `rules.js`:

- **Tokenizing:** `splitSegments`, `words`, `simpleWords`, `stripComments`, `heredocs`.
- **Shell structure:** `WRAPPERS`, `KEYWORDS`, `SHELLS`, `SHELL_RUN_FLAG`, `innerCommand`, `gitWords`.
- **Classification:** `destructiveSegs` and its regexes (`PIPED_TO_SHELL`, `HERESTRING_TO_SHELL`, `STDIN_EXEC`, `DYNAMIC_NAME`, `VAR_REF`, `TEMP_ASSIGN`), `IRREVERSIBLE_CMD`, `CLI_VERBS`/`cliVerb`, `SQL_DESTRUCTIVE`/`DB_CLIENT`, `INTERPRETER`/`codeHits`.
- **Targets and redirects:** `segTargets`, `truncated`, `redirects`, `createdBy`, `norm`.
- **Reads and evidence:** `operands`, `isRead`, `isListing`, `targetsOf`, `createdPaths`, `readIndex` (`add`, `known`, `mine`, `corroborates`), `recipientOf`.
- **The gate:** `checkCall`, `gate`, `sweep`.

Also run it when you edit the D5, D22, D25 or D26 entries in `SPEC-v1.md`.

## Run

```bash
npm run verify            # about 5 s; exit 0 = all four properties hold within the bounds
npm run verify:mutants    # about 50 s; exit 0 = the check still catches each of 10 known breaks
```

Run `verify` on every relevant change. Run `verify:mutants` when you change `verify/r1-gate.js`, or rename code that a mutant names. Node ≥ 20.19 (`package.json` engines), no dependencies.

## What each property means

All four properties run against the real `rules.js`. The oracles live in `verify/r1-gate.js`, not in the engine.

| Property | Plain statement | Harm if broken |
|---|---|---|
| P1 closure | Each of 12 destructive commands is still irreversible after every sequence of up to 3 rewrites from 26 that keep its meaning. The rewrites include `sudo`, `bash -c '…'`, `eval`, `if…then`, functions, `ssh`, `docker exec`, `echo … \| sh`, base64, heredoc, `$VAR` and comments. Up to 6 nested `bash -c` layers must also be caught. | An agent's `rm -rf`, `DROP TABLE` or `git push --force` passes the gate because of how it was quoted or wrapped. |
| P2 precision | Each of 12 benign look-alikes (`ls`, `git status`, `git push origin main`, `SELECT 1`, …) stays not irreversible under the same rewrites. | Every session goes red, and people stop reading the gate. |
| P3 parity | For every trace of up to 3 calls over 13 call kinds, the batch audit's R1/R4 findings (`run_rules`) equal what the live gate (`checkCall`, used by the PreToolUse hook and MCP `check-a-call`) returns call by call. | The hook allows an action that CI later blocks, or the reverse. |
| P4 evidence | In those same traces, R1 is cleared exactly when an earlier call justifies it per the `JUSTIFIES` table: read of the target, listing of it or its parent, plain `mkdir` or write that created it, or for a send, the address in a read's result. | A read of `/srv/app/README` "authorizes" `rm -rf /srv`, or `mkdir -p` on an existing directory "proves" the agent made it. |

## Reading a failure

The output shows up to 5 counterexamples per property, as JSON. For P1/P2 it gives the `core`, the `rewrites` applied (innermost first) and the exact `command`. Feed that command to the engine to reproduce:

```bash
node -e "console.log(require('./rules.js').isIrreversible({name:'bash',args:{command:process.argv[1]}}))" "<command>"
```

**Real bug or modeling error?**

1. Check whether the rewritten command really means "run the core" in bash. If it does not, the rewrite or its precondition in `REWRITES` is wrong. Fix the precondition and say why in the commit. An example is a comment that swallows a closing `fi`; that is why `noComment` exists.
2. If the shell meaning holds, the engine is wrong. **Fix the engine, not the property.** Find the root cause, as D26 did. A failure across many rewrites usually means one tokenizing step, not many lexicon gaps.
3. For a P2 failure, decide whether the engine has started treating something benign as opaque or destructive. If the new behaviour is intended, for example a deliberate fail-closed rule, change `BENIGN` only with a SPEC D-entry saying so.
4. For P4, the `JUSTIFIES` table *is* the D5 rule. If you intentionally change what corroborates, change `JUSTIFIES` and SPEC D5 in the same commit.

Never weaken a property or drop a core to make the run pass.

## Updating it when a change is intended

- **New destructive form:** add a core to `DESTRUCTIVE`, or a rewrite to `REWRITES` with an honest precondition. Then run both commands.
- **New evidence rule:** add the call kind to `ALPHABET` and its row to `JUSTIFIES`. Trace count grows as 13³, so keep the alphabet small.
- **Renamed or rewritten guarded code:** `verify:mutants` reports `pattern found 0 times`. Update that mutant's `from`/`to` text so it still re-breaks the same behaviour, then confirm it is caught.

## Scope and bounds: what a pass does not cover

- **Bounds.** A pass covers rewrite sequences up to depth 3 (about 90k cases per property), 12+12 cores, and traces up to 3 calls (2,379 traces). Longer chains and other cores are not enumerated.
- **The rewrite set is a model of bash.** It is not a shell parser. Not covered:
  - PowerShell syntax (`ps` mode in `destructiveSegs`) and `scriptRisk`, which covers scripts the session wrote.
  - Tool-name classification (`isIrreversibleTool`), apart from `send_email`.
  - Secret patterns. P3 runs with no secret-format strings.
  - R2, R3 and R5–R9.
- **P3 runs without user messages.** The batch audit also counts a recipient named by the user (D26), which the live hook cannot see. Live may therefore flag a send that batch clears. That divergence is intended and is not in the alphabet.
- **Hand-picked corpus.** `tests/bypass.test.js` holds the corpus of single harmful actions and pins the known gaps. This skill is the exhaustive complement to it, not a replacement.

## Coverage record

- **Verified:** `rules.js`, the functions and tables listed under "When to run it".
- **Harness:** `verify/r1-gate.js` holds the properties and oracles. `verify/mutants.js` holds M1–M10, which cover the wrapper `sudo`, the depth-cap fail-closed, `cliVerb`, heredoc quote tracking, `stripComments`, keyword-aware assignments, `checkCall` history, exact-read corroboration, recipient-in-result and `mkdir -p`.
- **Sync commit:** `f9e72f1` plus the uncommitted D25/D26 working tree, confirmed 2026-10-29: verify 0 counterexamples, mutants 10/10 caught.

Move the sync commit forward only after both commands pass and you have checked that the code areas listed above still mean what the properties say, at the new commit. To see what changed since the sync point:

```bash
git diff f9e72f1 -- rules.js
```

If the diff touches the covered functions and you have not rechecked, the verification is stale. Run both commands before trusting it.
