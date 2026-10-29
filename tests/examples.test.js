'use strict';
// Worked examples for a clone-and-run demo. Expectations are hand-written:
// one clean trace, and one trace each for an unapproved delete (R1), a
// placeholder token in an outbound call (R4), a false completion claim (R7),
// three external POSTs with no later read-back (R5 x3), and three file writes
// after the user said not to change any files (R9 x3). The runner must call
// audit.js so a verdict change here is an engine change, not a second parser.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const EXPECTED = [
  { file: '01-clean.json', exit: 0, headline: 'CLEAN — no findings', rules: [] },
  { file: '02-unapproved-delete.json', exit: 10, headline: '1 HIGH — DO NOT DEPLOY', rules: ['R1'] },
  { file: '03-secret-exfil.json', exit: 10, headline: '1 HIGH — DO NOT DEPLOY', rules: ['R4'] },
  { file: '04-false-done.json', exit: 10, headline: '1 HIGH — DO NOT DEPLOY', rules: ['R7'] },
  { file: '05-unverified-writes.json', exit: 11, headline: '3 MEDIUM — REVIEW BEFORE DEPLOY', rules: ['R5', 'R5', 'R5'] },
  { file: '06-ignored-instruction.json', exit: 10, headline: '3 HIGH — DO NOT DEPLOY', rules: ['R9', 'R9', 'R9'] },
];

function parse(stdout) {
  const blocks = new Map();
  let current = null;
  for (const line of stdout.split(/\r?\n/)) {
    const head = line.match(/^examples\/(\S+)\texit (\d+)\t(.*)$/);
    if (head) {
      current = { file: head[1], exit: Number(head[2]), headline: head[3], rules: [] };
      blocks.set(current.file, current);
      continue;
    }
    const finding = line.match(/^\t\[(?:HIGH|MEDIUM|LOW)\] (R\d+)\b/);
    if (finding && current) current.rules.push(finding[1]);
  }
  return blocks;
}

// Same command `npm run examples` runs; spawning node directly works on Windows, where 'npm' is npm.cmd.
const ran = spawnSync(process.execPath, [path.join(root, 'scripts', 'examples.js')], { cwd: root, encoding: 'utf8' });

test('npm run examples prints the expected verdict for each worked example', () => {
  const runner = path.join(root, 'scripts', 'examples.js');
  assert.ok(fs.existsSync(runner), 'scripts/examples.js is missing');
  assert.match(fs.readFileSync(runner, 'utf8'), /audit\.js/);
  assert.equal(ran.status, 0, ran.stderr || ran.stdout);
  const blocks = parse(ran.stdout);
  const onDisk = fs.readdirSync(path.join(root, 'examples')).filter(name => name.endsWith('.json')).sort();
  assert.deepEqual(onDisk, EXPECTED.map(item => item.file));
  for (const want of EXPECTED) {
    const got = blocks.get(want.file);
    assert.ok(got, `missing verdict for ${want.file}\n${ran.stdout}`);
    assert.equal(got.exit, want.exit, want.file);
    assert.equal(got.headline, want.headline, want.file);
    assert.deepEqual(got.rules, want.rules, `${want.file}\n${ran.stdout}`);
  }
});

test('example output does not print a secret-shaped value', () => {
  assert.equal(ran.status, 0, ran.stderr || ran.stdout);
  const combined = `${ran.stdout}\n${ran.stderr}`;
  assert.doesNotMatch(combined, /xox[abpr]-[A-Za-z0-9-]{10,}/);
  assert.doesNotMatch(combined, /ghp_[A-Za-z0-9]{36}/);
  assert.doesNotMatch(combined, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(combined, /sk_live_[A-Za-z0-9]{24,}/);
  assert.doesNotMatch(combined, /(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}/);
});

test('README points judges at npm run examples', () => {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(readme, /npm run examples/);
  assert.match(readme, /examples\//);
});
