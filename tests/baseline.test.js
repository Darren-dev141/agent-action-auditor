'use strict';
// V2-3 Baselines & suppression — seam tests (red-first).
//   finding.fingerprint  : rule + tool + hash(canonical args); stable across call ids and positions
//   apply_baseline(findings, baseline) -> active[]  (.suppressed[], .stats carried)
//   accept(baseline, finding, reason)  -> new baseline (reason required)
//   diff_baselines(a, b)               -> {added, removed}
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const AAA = require('../rules.js');
const BL = require('../baseline.js');

const tc = (id, name, args) => ({ role: 'assistant', tool_calls: [{ id, type: 'function', function: { name, arguments: JSON.stringify(args) } }] });
const tr = (id, content) => ({ role: 'tool', tool_call_id: id, content });
const run = messages => AAA.run_rules(AAA.parse_trace(JSON.stringify({ messages })));
const violation = () => AAA.run_rules(AAA.parse_trace(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'fixture_violation.json'), 'utf8')));
const empty = () => ({ version: 1, entries: [] });

test('every finding carries a fingerprint', () => {
  for (const f of violation()) assert.match(f.fingerprint, /^R\d:[0-9a-f]{8}$/);
});
test('fingerprint is stable across call ids, positions and arg key order', () => {
  const a = run([tc('x1', 'terminal', { command: 'rm -rf /tmp/a' }), tr('x1', 'ok')]);
  const b = run([{ role: 'user', content: 'hi' }, tc('read0', 'read_file', { path: '/etc/other' }), tr('read0', 'x'),
                 tc('zz9', 'terminal', { command: 'rm -rf /tmp/a' }), tr('zz9', 'ok')]);
  assert.equal(a.find(f => f.rule === 'R1').fingerprint, b.find(f => f.rule === 'R1').fingerprint);
  const c = run([tc('k1', 'send_message', { to: 'a@x.com', body: 'hi' }), tr('k1', 'ok')]);
  const d = run([tc('k2', 'send_message', { body: 'hi', to: 'a@x.com' }), tr('k2', 'ok')]);
  assert.equal(c.find(f => f.rule === 'R1').fingerprint, d.find(f => f.rule === 'R1').fingerprint);
});
test('fingerprint differs when the args differ', () => {
  const a = run([tc('x1', 'terminal', { command: 'rm -rf /tmp/a' }), tr('x1', 'ok')]);
  const b = run([tc('x1', 'terminal', { command: 'rm -rf /tmp/b' }), tr('x1', 'ok')]);
  assert.notEqual(a[0].fingerprint, b[0].fingerprint);
});

test('accept requires a non-empty reason', () => {
  const f = violation()[0];
  assert.throws(() => BL.accept(empty(), f), /reason/);
  assert.throws(() => BL.accept(empty(), f, '   '), /reason/);
});
test('accept is idempotent and does not mutate its input', () => {
  const f = violation()[0], b0 = empty();
  const b1 = BL.accept(b0, f, 'known: cache dir is ephemeral');
  const b2 = BL.accept(b1, f, 'again');
  assert.equal(b0.entries.length, 0);
  assert.equal(b1.entries.length, 1);
  assert.equal(b2.entries.length, 1);
  assert.equal(b1.entries[0].fingerprint, f.fingerprint);
  assert.equal(b1.entries[0].rule, f.rule);
});

test('ACCEPTANCE: second run of the same trace shows suppressions, not re-flags', () => {
  const first = violation();
  const r1 = first.find(f => f.rule === 'R1');
  const base = BL.accept(empty(), r1, 'cache dir is throwaway');
  const active = BL.apply_baseline(violation(), base);
  assert.equal(active.length, first.length - 1);
  assert.equal(active.suppressed.length, 1);
  assert.equal(active.suppressed[0].fingerprint, r1.fingerprint);
  assert.deepEqual(active.stats, first.stats, 'stats ride along unchanged');
});
test('ACCEPTANCE: deleting a baseline entry re-surfaces the finding', () => {
  const first = violation();
  const base = BL.accept(empty(), first[0], 'temp');
  const removed = { version: 1, entries: base.entries.filter(e => e.fingerprint !== first[0].fingerprint) };
  const active = BL.apply_baseline(violation(), removed);
  assert.equal(active.length, first.length);
  assert.equal(active.suppressed.length, 0);
});
test('suppressed findings render collapsed, never silently hidden; headline counts active only', () => {
  const all = violation();
  let base = empty();
  for (const f of all.filter(f => f.severity === 'HIGH')) base = BL.accept(base, f, 'accepted for test');
  const active = BL.apply_baseline(violation(), base);
  const report = AAA.render_report(active);
  assert.ok(!report.headline.includes('HIGH'), 'suppressed HIGHs do not count toward the verdict');
  assert.ok(report.lines.some(l => /\d+ suppressed by baseline/.test(l)), 'suppression count is visible');
});
test('a null/absent baseline suppresses nothing', () => {
  const active = BL.apply_baseline(violation(), null);
  assert.equal(active.length, violation().length);
  assert.equal(active.suppressed.length, 0);
});
test('diff_baselines shows what changed', () => {
  const [f1, f2] = violation();
  const a = BL.accept(empty(), f1, 'one');
  const b = BL.accept(BL.accept(empty(), f1, 'one'), f2, 'two');
  const d = BL.diff_baselines(a, b);
  assert.deepEqual(d.added.map(e => e.fingerprint), [f2.fingerprint]);
  assert.deepEqual(d.removed, []);
  assert.deepEqual(BL.diff_baselines(b, a).removed.map(e => e.fingerprint), [f2.fingerprint]);
});
