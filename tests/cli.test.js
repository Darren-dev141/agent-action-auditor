'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const path = require('node:path');
test('CLI JSON returns structured findings without exposing secret-shaped input', () => {
  const r = spawnSync(process.execPath, ['audit.js', 'fixtures/fixture_violation.json', '--json'], {cwd:path.join(__dirname,'..'),encoding:'utf8'});
  assert.equal(r.status,10,r.stderr);
  const d=JSON.parse(r.stdout);
  assert.equal(d.findings.length,6);
  assert.equal(d.stats.tool_calls,6);
  assert.match(d.headline,/4 HIGH · 2 MEDIUM/);
  assert.doesNotMatch(r.stdout,/ghp_[A-Za-z0-9]{36}/);
});
test('CLI REVIEW trace (>=3 MEDIUM, 0 HIGH) exits 11 via EXIT[report.kind]', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  // Three unverified write_file calls -> three R5 MEDIUM findings, no HIGH.
  const calls = ['a.txt', 'b.txt', 'c.txt'].map((p, i) => ({
    id: `w${i + 1}`, type: 'function',
    function: { name: 'write_file', arguments: JSON.stringify({ path: p, content: 'x' }) }
  }));
  const trace = { messages: [
    { role: 'user', content: 'write the files' },
    { role: 'assistant', tool_calls: calls },
    ...calls.map(c => ({ role: 'tool', tool_call_id: c.id, content: 'ok' })),
    { role: 'assistant', content: 'wrote them' }
  ] };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-review-'));
  const file = path.join(dir, 'review.json');
  fs.writeFileSync(file, JSON.stringify(trace));
  const r = spawnSync(process.execPath, ['audit.js', file, '--json'], { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
  assert.equal(r.status, 11, r.stderr);
  const d = JSON.parse(r.stdout);
  assert.equal(d.kind, 'REVIEW');
  assert.match(d.headline, /REVIEW BEFORE DEPLOY/);
});
