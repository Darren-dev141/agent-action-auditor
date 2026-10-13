const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const R = require(path.join(ROOT, 'replay.js'));
const AAA = require(path.join(ROOT, 'rules.js'));
const fx = n => fs.readFileSync(path.join(ROOT, 'fixtures', n), 'utf8');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-replay-'));

test('replay runs over a directory of json traces', () => {
  const dir = tmp();
  try {
    fs.writeFileSync(path.join(dir, 'v.json'), fx('fixture_violation.json'));
    fs.writeFileSync(path.join(dir, 'c.json'), fx('fixture_clean.json'));
    const out = execFileSync('node', [path.join(ROOT, 'replay.js'), dir], { encoding: 'utf8' });
    assert.match(out, /v\.json/);
    assert.match(out, /Replayed 2 trace/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('replay reads ndjson archives with model/timestamp metadata', () => {
  const dir = tmp();
  try {
    const t = JSON.parse(fx('fixture_clean.json'));
    fs.writeFileSync(path.join(dir, 'a.ndjson'),
      JSON.stringify({ model: 'm-old', timestamp: '2026-10-01T00:00:00Z', trace: t }) + '\n' + JSON.stringify(t) + '\n');
    const tr = R.readTraces(path.join(dir, 'a.ndjson'));
    assert.equal(tr.length, 2);
    assert.equal(tr[0].model, 'm-old');
    assert.equal(tr[1].model, undefined);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('kill criterion: two runs over the same traces are bit-identical', () => {
  const traces = ['fixture_clean.json', 'fixture_violation.json', 'fixture_borderline.json'].map(n => ({ label: n, raw: fx(n) }));
  assert.equal(R.snapshot(AAA, traces), R.snapshot(AAA, traces));
  const r = spawnSync('node', [path.join(ROOT, 'replay.js'), path.join(ROOT, 'fixtures'), '--determinism'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /DETERMINISTIC: 3 trace/);
});

test('acceptance: 10 archived traces vs a tightened rule shows exactly which gain findings', () => {
  // tightened engine: every R1 finding escalates to HIGH; plus a new rule flags any call to tool "read_file"
  const tight = Object.assign({}, AAA, {
    RULES_VERSION: 'v2-tight',
    run_rules: calls => {
      const base = AAA.run_rules(calls);
      const out = base.map(f => f.rule === 'R1' ? Object.assign({}, f, { severity: 'HIGH' }) : f);
      out.stats = base.stats;
      return out;
    },
  });
  const names = ['fixture_clean.json', 'fixture_violation.json', 'fixture_borderline.json'];
  const traces = Array.from({ length: 10 }, (_, i) => ({ label: `t${i}`, raw: fx(names[i % 3]) }));
  const d = R.diffEngines(AAA, tight, traces);
  assert.equal(d.length, 10);
  const base = traces.map(t => AAA.run_rules(AAA.parse_trace(t.raw)));
  d.forEach((r, i) => {
    const expect = base[i].filter(f => f.rule === 'R1' && f.severity !== 'HIGH').length;
    assert.equal(r.gained.length, expect, `${r.label} gained`);
    assert.equal(r.lost.length, 0);
    r.gained.forEach(f => { assert.equal(f.rule, 'R1'); assert.equal(f.severity, 'HIGH'); });
  });
  // identical engines → no diff at all
  assert.ok(R.diffEngines(AAA, AAA, traces).every(r => !r.gained.length && !r.lost.length));
});

test('model-upgrade mode diffs violation counts by rule and severity', () => {
  const traces = [
    { label: 'a', raw: fx('fixture_clean.json'), model: 'old' },
    { label: 'b', raw: fx('fixture_violation.json'), model: 'new' },
  ];
  const d = R.diffModels(AAA, traces, 'old', 'new');
  assert.equal(d.old.traces, 1);
  assert.equal(d.new.traces, 1);
  const viol = AAA.run_rules(AAA.parse_trace(fx('fixture_violation.json')));
  const total = d.rows.reduce((s, r) => s + r.delta, 0);
  assert.equal(total, viol.length);
});

test('--compare CLI reports changed traces and --fail-on-diff exits 1', () => {
  const dir = tmp();
  try {
    const p = path.join(dir, 'tight.js');
    fs.writeFileSync(p, `const A=require(${JSON.stringify(path.join(ROOT, 'rules.js'))});
module.exports=Object.assign({},A,{RULES_VERSION:'v2-tight',run_rules:c=>{const b=A.run_rules(c);const o=b.map(f=>f.rule==='R1'?Object.assign({},f,{severity:'HIGH'}):f);o.stats=b.stats;return o;}});`);
    const r = spawnSync('node', [path.join(ROOT, 'replay.js'), path.join(ROOT, 'fixtures'), '--compare', p, '--fail-on-diff'], { encoding: 'utf8' });
    assert.match(r.stdout, /trace\(s\) changed between/);
    const same = spawnSync('node', [path.join(ROOT, 'replay.js'), path.join(ROOT, 'fixtures'), '--compare', path.join(ROOT, 'rules.js'), '--fail-on-diff'], { encoding: 'utf8' });
    assert.equal(same.status, 0);
    assert.match(same.stdout, /^0 of 3 trace/m);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
