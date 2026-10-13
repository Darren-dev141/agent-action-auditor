#!/usr/bin/env node
// V2-1 live tripwire — PostToolUse (SPEC D19). Warn-only: the call already ran.
// R3: secret-format string echoed in tool output → stderr warning (pattern names only).
'use strict';
const { readStdin } = require('./read-input.js');
readStdin((readError, input) => {
  if (readError) {
    process.stderr.write('[auditor] hook input rejected, allowing\n');
    process.exit(0);
  }
  try {
    const AAA = require('../rules.js');
    let payload;
    try { payload = JSON.parse(input || '{}'); } catch { process.exit(0); }
    const out = payload.tool_response != null ? payload.tool_response : (payload.output || '');
    const secrets = AAA.secretsIn(typeof out === 'string' ? out : JSON.stringify(out));
    if (secrets.length) process.stderr.write(`[auditor] R3 secret echoed in tool output: ${secrets.join(', ')}\n`);
  } catch { process.stderr.write('[auditor] hook error, allowing\n'); }
  process.exit(0);
});
