#!/usr/bin/env node
// Proof that verify/r1-gate.js can fail: each mutant re-breaks one behaviour the properties guard,
// in a temp copy of rules.js, and the verifier must exit 1 with the named property failing.
// A mutant that applies to no line, or that the verifier does not catch, fails this script.
// Usage: node verify/mutants.js   (exit 0 = every mutant caught)
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'rules.js'), 'utf8');
const MUTANTS = [
  // [id, what it re-breaks, exact text in rules.js, replacement, property that must catch it]
  ['M1', 'sudo is no longer unwrapped', "const WRAPPERS = new Set(['sudo', ", 'const WRAPPERS = new Set([', 'P1'],
  ['M2', 'nesting past depth 3 fails open', "if (depth > 3) return [['opaque']];", 'if (depth > 3) return found;', 'P1'],
  ['M3', 'destructive CLI subcommands ignored', '|| cliVerb(w)) {', ') {', 'P1'],
  ['M4', 'heredoc parse ignores quotes', "if (ch === \"'\" || ch === '\"') { q = ch; continue; }", '', 'P1'],
  ['M5', 'comments not stripped before pipe checks', 'text = stripComments(raw);', 'text = raw;', 'P1'],
  ['M6', 'assignments after then/do not recorded', 'while (all.length && KEYWORDS.has(all[0])) all = all.slice(1);', '', 'P2'],
  ['M7', 'live gate ignores earlier calls', 'for (const c of priorCalls || []) idx.add(c);', '', 'P3'],
  ['M8', 'reading a child file vouches for its directory', '{ exact.add(p); if (isListing(c))', '{ exact.add(p); for (const a of lineage(p)) exact.add(a); if (isListing(c))', 'P4'],
  ['M9', "recipient counted from a read's arguments", "reads.some(r => String(r.result || '').includes(who))", 'reads.some(r => mentions(r, who))', 'P4'],
  ['M10', 'mkdir -p counts as creating the directory', "!w.some(t => /^-(?:-parents|\\w*p\\w*)$/.test(t))", 'true', 'P4'],
];

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-mutants-'));
let bad = 0;
try {
  for (const [id, what, from, to, prop] of MUTANTS) {
    const n = source.split(from).length - 1;
    if (n !== 1) { console.log(`FAIL ${id} ${what}: pattern found ${n} times in rules.js (expected 1); update this mutant`); bad++; continue; }
    const file = path.join(dir, `${id}.js`);
    fs.writeFileSync(file, source.replace(from, () => to));
    const r = spawnSync(process.execPath, [path.join(__dirname, 'r1-gate.js'), '--engine', file, '--quiet'], { encoding: 'utf8' });
    const failed = [...(r.stdout || '').matchAll(/^FAIL (P\d)/gm)].map(m => m[1]);
    const caught = r.status === 1 && failed.includes(prop);
    if (!caught) bad++;
    console.log(`${caught ? 'ok  ' : 'FAIL'} ${id} ${what}: ${caught ? 'caught by' : 'NOT caught; expected'} ${prop}${failed.length ? ` (failing: ${failed.join(', ')})` : ''}${r.status > 1 || r.stderr ? ' ' + (r.stderr || '').split('\n')[0] : ''}`);
  }
} finally { fs.rmSync(dir, { recursive: true, force: true }); }
process.exit(bad ? 1 : 0);
