#!/usr/bin/env node
// Static check (D4): every tests/<file>.js path cited in the Markdown docs
// must name a file that exists. Catches spec citations that outlive the
// file they point at (the D13 -> tests/audit.test.js rot). Docs live at
// the repo root; historical mentions of removed files are written without
// the tests/ path prefix so they don't read as live citations.
// Usage: node tests/check-spec-refs.js   (exit 0 = no dangling references)
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const REF = /tests\/[\w.-]+\.js/g;
let bad = 0;
for (const f of fs.readdirSync(root).filter(f => f.endsWith('.md'))) {
  const text = fs.readFileSync(path.join(root, f), 'utf8');
  for (const m of text.matchAll(REF)) {
    if (!fs.existsSync(path.join(root, m[0]))) {
      console.log(`FAIL ${f}: cites missing ${m[0]}`);
      bad++;
    }
  }
}
if (bad) { console.log(`\n${bad} dangling test-file reference(s)`); process.exit(1); }
console.log('ok   all tests/*.js references in *.md exist');
