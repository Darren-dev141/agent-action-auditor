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
