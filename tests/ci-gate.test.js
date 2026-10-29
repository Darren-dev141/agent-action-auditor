'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
const scratch = process.env.TMPDIR || os.tmpdir();
const temp = () => fs.mkdtempSync(path.join(scratch, 'aaa-ci-'));
const gate = (args, env = {}) => spawnSync(process.execPath, [path.join(root, 'ci-gate.js'), ...args], {
  cwd: root, encoding: 'utf8', env: { ...process.env, ...env }
});
test('CI acceptance: clean trace passes and violating trace blocks with trace-line annotation', () => {
  const clean = gate(['--trace', 'fixtures/fixture_clean.json']);
  assert.equal(clean.status, 0, clean.stderr);
  assert.match(clean.stdout, /CLEAN/);
  const bad = gate(['--trace', 'fixtures/fixture_violation.json']);
  assert.equal(bad.status, 10, bad.stderr);
  assert.match(bad.stdout, /::error file=fixtures\/fixture_violation.json,line=\d+,title=R1/);
  assert.match(bad.stdout, /4 HIGH/);
  assert.doesNotMatch(bad.stdout, /ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}/);
});
test('baseline suppression is visible; removing acceptance restores the block; invalid baseline fails', () => {
  const dir = temp();
  try {
    const AAA = require('../rules.js');
    const findings = AAA.run_rules(AAA.parse_trace(fs.readFileSync(path.join(root, 'fixtures/fixture_violation.json'), 'utf8')));
    const baseline = { version: 1, entries: findings.map(f => ({ fingerprint: f.fingerprint, rule: f.rule, reason: 'Test fixture only', added: '2026-10-12T00:00:00Z' })) };
    const config = path.join(dir, '.auditor.yml');
    const file = path.join(dir, 'accepted.json');
    fs.writeFileSync(config, 'baseline: accepted.json\n');
    fs.writeFileSync(file, JSON.stringify(baseline));
    const accepted = gate(['--trace', 'fixtures/fixture_violation.json', '--config', config]);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.match(accepted.stdout, /6 suppressed by baseline/);
    assert.doesNotMatch(accepted.stdout, /title=R/);
    baseline.entries = baseline.entries.filter(f => f.rule !== 'R1');
    fs.writeFileSync(file, JSON.stringify(baseline));
    assert.equal(gate(['--trace', 'fixtures/fixture_violation.json', '--config', config]).status, 10);
    fs.writeFileSync(file, '{"version":1,"entries":[{"fingerprint":"R1:de98eac8"}]}');
    assert.equal(gate(['--trace', 'fixtures/fixture_violation.json', '--config', config]).status, 2);
    fs.unlinkSync(file);
    assert.equal(gate(['--trace', 'fixtures/fixture_clean.json', '--config', config]).status, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('trace directories process every JSON artifact and fail on malformed or empty input', () => {
  const dir = temp();
  try {
    fs.copyFileSync(path.join(root, 'fixtures/fixture_clean.json'), path.join(dir, 'clean.json'));
    assert.equal(gate(['--trace', dir]).status, 0);
    fs.copyFileSync(path.join(root, 'fixtures/fixture_violation.json'), path.join(dir, 'violation.json'));
    const mixed = gate(['--trace', dir]);
    assert.equal(mixed.status, 10);
    assert.match(mixed.stdout, /clean.json/);
    assert.match(mixed.stdout, /violation.json/);
    fs.writeFileSync(path.join(dir, 'malformed.json'), 'not a trace');
    assert.equal(gate(['--trace', dir]).status, 2);
    for (const file of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, file));
    assert.equal(gate(['--trace', dir]).status, 2);
    assert.equal(gate(['--trace', path.join(dir, 'absent.json')]).status, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('configuration selects severity threshold and rule allowlist', () => {
  const dir = temp();
  try {
    const config = path.join(dir, '.auditor.yml');
    fs.writeFileSync(config, 'severity: MEDIUM\nrules: [R2]\n');
    const blocked = gate(['--trace', 'fixtures/fixture_violation.json', '--config', config]);
    assert.equal(blocked.status, 10, blocked.stderr);
    assert.match(blocked.stdout, /title=R2/);
    assert.doesNotMatch(blocked.stdout, /title=R1/);
    fs.writeFileSync(config, 'severity: HIGH\nrules:\n  - R2\n');
    assert.equal(gate(['--trace', 'fixtures/fixture_violation.json', '--config', config]).status, 0);
    fs.writeFileSync(config, 'severity: typo\n');
    assert.equal(gate(['--trace', 'fixtures/fixture_clean.json', '--config', config]).status, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('Gate 1 fix 2: R8 is selectable in config and baselinable without invalidating the file', () => {
  const dir = temp();
  try {
    const trace = path.join(dir, 'r8.json');
    fs.writeFileSync(trace, JSON.stringify({ messages: [
      { role: 'assistant', content: null, tool_calls: [{ id: 'a', type: 'function', function: { name: 'read_file', arguments: '{"path":"src/a.js"}' } }] },
      { role: 'tool', tool_call_id: 'a', content: 'x' },
      { role: 'assistant', content: 'I fixed the bug.' }] }));
    const AAA = require('../rules.js');
    const f = AAA.run_rules(AAA.parse_trace(fs.readFileSync(trace, 'utf8'))).filter(x => x.rule === 'R8');
    assert.equal(f.length, 1, 'fixture trace emits R8');
    const config = path.join(dir, '.auditor.yml');
    fs.writeFileSync(config, 'severity: MEDIUM\nrules: [R8]\n');
    const flagged = gate(['--trace', trace, '--config', config]);
    assert.equal(flagged.status, 10, flagged.stderr);
    assert.match(flagged.stdout, /title=R8/);
    fs.writeFileSync(path.join(dir, 'base.json'), JSON.stringify({ version: 1, entries: [
      { fingerprint: f[0].fingerprint, rule: 'R8', reason: 'Reviewed: test fixture', added: '2026-10-13T00:00:00Z' }] }));
    fs.writeFileSync(config, 'severity: MEDIUM\nrules: [R8]\nbaseline: base.json\n');
    const accepted = gate(['--trace', trace, '--config', config]);
    assert.equal(accepted.status, 0, accepted.stderr);
    fs.writeFileSync(config, 'rules: [R99]\n');
    assert.equal(gate(['--trace', trace, '--config', config]).status, 2, 'unknown rule ids still rejected');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
