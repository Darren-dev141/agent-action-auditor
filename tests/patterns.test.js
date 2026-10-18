'use strict';
// D3 pattern parity: the secret table exists in two forms — the engine's
// search form (rules.js SECRET_PATTERNS) and the fixture validator's
// anchored full-match form (tests/validate-fixtures.js). This test pins
// both behaviorally so the pair can never silently drift: every pattern
// fires on a full sample and stays silent on near-misses, in the engine
// directly and (for ghp_, end to end) through the validator CLI.
// Samples are built from fragments — no literal secret-shaped string
// lives in this source (same discipline as tests/seams.test.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const AAA = require('../rules.js');

const rep = (s, n) => s.repeat(n);
const SAMPLES = [
  // [pattern name, full sample (fires), near-misses (silent)]
  ['github_pat', 'ghp_' + rep('Ab1', 12), ['ghp_' + rep('Ab1', 11) + 'Ab', 'ghp_' + rep('Ab1', 12) + 'Z']],
  ['aws_key_id', 'AKIA' + rep('A1', 8), ['AKIA' + rep('A1', 7) + 'A', 'AKIA' + rep('a', 16)]],
  ['stripe_live', 'sk_live_' + rep('a', 24), ['sk_live_' + rep('a', 23)]],
  ['openai_key', 'sk-' + rep('a', 20), ['sk-' + rep('a', 19), 'please ask-me-anything today']],
  ['openai_key', 'sk-proj-' + rep('a', 20), []],
  ['slack_token', 'xoxb-' + rep('a', 10), ['xoxb-' + rep('a', 9), 'xoxz-' + rep('a', 10)]],
];

test('D3 parity: engine fires on full samples, silent on near-misses', () => {
  for (const [name, full, misses] of SAMPLES) {
    assert.ok(AAA.secretsIn(`x ${full} y`).includes(name), `${name} fires on a full sample`);
    for (const miss of misses)
      assert.ok(!AAA.secretsIn(`x ${miss} y`).includes(name), `${name} silent on near-miss "${miss.slice(0, 10)}…"`);
  }
});

test('D3 parity: fixture validator accepts a full ghp_ token, rejects a 35-char near-miss', () => {
  const fixture = token => JSON.stringify({
    messages: [{ role: 'user', content: `token ${token}` }],
    expected: { findings: [], absent: [...AAA.RULE_IDS], verdict: 'CLEAN — no findings', stats: { tool_calls: 0 } }
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-patterns-'));
  const run = token => {
    const file = path.join(dir, 'fx.json');
    fs.writeFileSync(file, fixture(token));
    return spawnSync(process.execPath, ['tests/validate-fixtures.js', file], { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
  };
  assert.equal(run('ghp_' + rep('Ab1', 12)).status, 0);
  const bad = run('ghp_' + rep('Ab1', 11) + 'Ab');
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /near-miss secret/);
});
