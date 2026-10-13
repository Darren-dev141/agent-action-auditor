#!/usr/bin/env node
// V2-1 live tripwire — PreToolUse (SPEC D19). Reads Claude Code hook JSON on stdin:
//   { "session_id": "...", "tool_name": "Bash", "tool_input": { ... } }
// Default (D21): WARN — exit 0 with '[auditor] would block: …' on stderr. Opt in to blocking with AAA_MODE=block
// (exit 2). Reason line names patterns only, never the secret.
// Blocks: R4 secret in args; R1 irreversible action whose target was not read earlier this session.
// Fails open: any internal error → exit 0 with a note, so the auditor never breaks the agent.
'use strict';
const { readStdin } = require('./read-input.js');
readStdin((readError, input) => {
  if (readError) {
    process.stderr.write('[auditor] hook input rejected, allowing\n');
    process.exit(0);
  }
  try {
    const AAA = require('../rules.js');
    const S = require('./session.js');
    let payload;
    try { payload = JSON.parse(input || '{}'); } catch { process.exit(0); }
    const sid = payload.session_id;
    const prior = S.load(sid);
    const call = S.toCall(payload, prior.length);
    const calls = prior.concat([call]);
    const reasons = [];
    const secrets = AAA.secretsIn(call.rawArgs);
    if (secrets.length) reasons.push(`R4 secret detected in args (${secrets.join(', ')})`);
    if (AAA.isIrreversible(call) && !AAA.corroborated(call, calls))
      reasons.push(`R1 irreversible ${call.name} with no prior read of its target this session`);
    if (reasons.length) {
      const block = String(process.env.AAA_MODE || '').toLowerCase() === 'block';
      process.stderr.write(`[auditor] ${block ? 'blocked' : 'would block'}: ` + reasons.join('; ') + '\n');
      if (block) process.exit(2);
      // warn mode: the call runs, so record it (secrets redacted) to keep session memory truthful
    }
    S.append(sid, call);
    process.exit(0);
  } catch {
    process.stderr.write('[auditor] hook error, allowing\n');
    process.exit(0);
  }
});
