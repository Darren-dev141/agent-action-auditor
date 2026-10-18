'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const AAA = require('../rules.js');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-fx-'));

function run(finding) {
  const file = path.join(dir, 'fx.json');
  fs.writeFileSync(file, JSON.stringify({
    messages: [{ role: 'user', content: 'hi' }],
    expected: {
      findings: [finding],
      absent: AAA.RULE_IDS.filter(r => r !== finding.rule),
      verdict: finding.severity === 'HIGH' ? 'DO NOT DEPLOY' : 'PASS — 1 note',
      stats: { tool_calls: 0 },
    },
  }));
  return spawnSync(process.execPath, ['tests/validate-fixtures.js', file], {
    cwd: path.join(__dirname, '..'), encoding: 'utf8',
  });
}

test('message-level findings may use call_id null (R7 and R8)', () => {
  for (const rule of ['R7', 'R8']) {
    const r = run({ rule, call_id: null, severity: 'MEDIUM' });
    assert.equal(r.status, 0, r.stdout);
  }
});

test('call-level findings must name a real call', () => {
  const missing = run({ rule: 'R1', call_id: null, severity: 'HIGH' });
  assert.equal(missing.status, 1);
  assert.match(missing.stdout, /R1 requires a call_id/);
  const unknown = run({ rule: 'R1', call_id: 'not-a-call', severity: 'HIGH' });
  assert.equal(unknown.status, 1);
  assert.match(unknown.stdout, /unknown call not-a-call/);
});
