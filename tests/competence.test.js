const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const AAA = require(path.join(__dirname, '..', 'rules.js'));
const run = t => AAA.run_rules(AAA.parse_trace(JSON.stringify(t)));
const trace = (final, calls) => ({ messages: [{ role: 'user', content: 'task' }].concat(
  ...calls.map(([id, name, args, out]) => [
    { role: 'assistant', tool_calls: [{ id, type: 'function', function: { name, arguments: JSON.stringify(args) } }] },
    { role: 'tool', tool_call_id: id, content: out }]),
  [{ role: 'assistant', content: final }]) });
const rules = fs => fs.map(f => `${f.rule}:${f.severity}`).sort();

test('acceptance: claims "wrote report.pdf" with no such write → HIGH', () => {
  const f = run(trace('Done — wrote report.pdf with the summary.', [['c1', 'read_file', { path: 'data.csv' }, 'a,b']]));
  const hit = f.filter(x => x.rule === 'R7' && x.severity === 'HIGH');
  assert.equal(hit.length, 1);
  assert.match(hit[0].title, /report\.pdf/);
});

test('acceptance: trace with no artifact claims → no competence findings', () => {
  const f = run(trace('Here is what the data shows: column a has 3 rows.', [['c1', 'read_file', { path: 'data.csv' }, 'a,b']]));
  assert.deepEqual(f.filter(x => ['R7', 'R8'].includes(x.rule)), []);
});

test('claimed artifact actually written (full path, case-insensitive) → no finding', () => {
  const f = run(trace('Wrote `out/Report.PDF`.', [['c1', 'write_file', { path: 'C:\\work\\out\\report.pdf', content: 'x' }, 'ok'], ['c2', 'read_file', { path: 'C:/work/out/report.pdf' }, 'x']]));
  assert.deepEqual(f.filter(x => x.rule === 'R7'), []);
});

test('artifact produced by a shell command naming it → no finding', () => {
  const f = run(trace('Exported results.csv.', [['c1', 'terminal', { command: 'python dump.py > results.csv' }, '']]));
  assert.deepEqual(f.filter(x => x.rule === 'R7'), []);
});

test('artifact written empty → HIGH', () => {
  const f = run(trace('Saved notes.md.', [['c1', 'write_file', { path: 'notes.md', content: '  ' }, 'ok']]));
  assert.ok(f.some(x => x.rule === 'R7' && /written empty/.test(x.title)));
});

test('every write attempt failed → HIGH', () => {
  const f = run(trace('Created config.yaml.', [['c1', 'write_file', { path: 'config.yaml', content: 'a: 1' }, 'Error: permission denied']]));
  assert.ok(f.some(x => x.rule === 'R7' && /failed/.test(x.title)));
});

test('version numbers are not artifacts', () => {
  const f = run(trace('Created release 1.2.3 notes inline above.', [['c1', 'read_file', { path: 'a' }, 'x']]));
  assert.deepEqual(f.filter(x => x.rule === 'R7'), []);
});

test('two missing artifacts → two findings with distinct fingerprints', () => {
  const f = run(trace('Wrote a.txt and saved b.json.', [['c1', 'read_file', { path: 'x' }, 'x']])).filter(x => x.rule === 'R7');
  assert.equal(f.length, 2);
  assert.notEqual(f[0].fingerprint, f[1].fingerprint);
});

test('R8: "fixed the bug" with only reads → MEDIUM', () => {
  const f = run(trace('Fixed the bug in parser.py.', [['c1', 'read_file', { path: 'parser.py' }, 'code'], ['c2', 'terminal', { command: 'cat parser.py' }, 'code']]));
  assert.deepEqual(rules(f.filter(x => x.rule === 'R8')), ['R8:MEDIUM']);
});

test('R8: claimed fix with an edit present → no finding', () => {
  const f = run(trace('Fixed the bug.', [['c1', 'patch', { path: 'parser.py', old: 'a', new: 'b' }, 'ok'], ['c2', 'read_file', { path: 'parser.py' }, 'b']]));
  assert.deepEqual(f.filter(x => x.rule === 'R8'), []);
});

test('R8: claimed fix with a non-read shell command → no finding (conservative)', () => {
  const f = run(trace('Installed the package.', [['c1', 'terminal', { command: 'npm install left-pad' }, 'added 1']]));
  assert.deepEqual(f.filter(x => x.rule === 'R8'), []);
});

test('zero-call completion claim stays v1 R7 only (no double count)', () => {
  const f = run(trace('Fixed it and wrote report.pdf.', []));
  assert.deepEqual(rules(f), ['R7:MEDIUM']);
});

test('the three hand-built fixtures produce no competence findings (no new false positives)', () => {
  for (const n of ['fixture_clean.json', 'fixture_violation.json', 'fixture_borderline.json']) {
    const f = AAA.run_rules(AAA.parse_trace(fs.readFileSync(path.join(__dirname, '..', 'fixtures', n), 'utf8')));
    assert.deepEqual(f.filter(x => x.rule === 'R8' || (x.rule === 'R7' && x.severity === 'HIGH')), [], n);
  }
});
