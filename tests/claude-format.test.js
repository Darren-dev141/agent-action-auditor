const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'); const os = require('os'); const path = require('path');
const { spawnSync } = require('node:child_process');
const ROOT = path.resolve(__dirname, '..');
const AAA = require(path.join(ROOT, 'rules.js'));
const R = require(path.join(ROOT, 'replay.js'));
const use = (id, name, input) => ({ type: 'tool_use', id, name, input });
const res = (id, content, is_error = false) => ({ type: 'tool_result', tool_use_id: id, content, is_error });
// Claude Code session JSONL shape (synthetic): bookkeeping lines + user/assistant lines with block content
const line = (type, role, content, extra = {}) => JSON.stringify(Object.assign({ type, sessionId: 's', uuid: 'u', message: { role, content } }, extra));
const jsonl = (...ls) => [JSON.stringify({ type: 'queue-operation', operation: 'x' })].concat(ls, [JSON.stringify({ type: 'cost-state' })]).join('\n');

test('Claude Code JSONL: tool_use/tool_result pair up, names and args are mapped', () => {
  const t = jsonl(
    line('user', 'user', 'clean the build dir'),
    line('assistant', 'assistant', [{ type: 'thinking', thinking: 'x' }, use('t1', 'Bash', { command: 'rm -rf build' })]),
    line('user', 'user', [res('t1', '')]),
    line('assistant', 'assistant', [{ type: 'text', text: 'Done.' }]));
  const calls = AAA.parse_trace(t);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, 'bash');
  assert.equal(calls[0].args.command, 'rm -rf build');
  assert.equal(calls.finalMessage, 'Done.');
  assert.ok(AAA.run_rules(calls).some(f => f.rule === 'R1'));
});

test('Read with file_path corroborates a later delete of the same path (R1 quiet)', () => {
  const t = jsonl(
    line('assistant', 'assistant', [use('a', 'Read', { file_path: 'build' })]),
    line('user', 'user', [res('a', [{ type: 'text', text: 'listing' }])]),
    line('assistant', 'assistant', [use('b', 'PowerShell', { command: 'Remove-Item build' })]),
    line('user', 'user', [res('b', 'ok')]));
  const calls = AAA.parse_trace(t);
  assert.equal(calls[0].name, 'read_file');
  assert.equal(calls[0].args.path, 'build');
  assert.equal(calls[1].name, 'powershell');
  assert.deepEqual(AAA.run_rules(calls).filter(f => f.rule === 'R1'), []);
});

test('parallel tool_uses with out-of-order results pair by id, not position', () => {
  const t = jsonl(
    line('assistant', 'assistant', [use('x', 'Read', { file_path: 'a' }), use('y', 'Read', { file_path: 'b' })]),
    line('user', 'user', [res('y', 'B'), res('x', 'A')]));
  const calls = AAA.parse_trace(t);
  assert.equal(calls.find(c => c.id === 'x').result, 'A');
  assert.equal(calls.find(c => c.id === 'y').result, 'B');
});

test('is_error results carry through as failures (R7 failed-write check sees them)', () => {
  const t = jsonl(
    line('assistant', 'assistant', [use('w', 'Write', { file_path: 'out/report.md', content: 'x' })]),
    line('user', 'user', [res('w', 'permission denied', true)]),
    line('assistant', 'assistant', [{ type: 'text', text: 'Wrote report.md.' }]));
  const calls = AAA.parse_trace(t);
  assert.match(calls[0].result, /^Error:/);
  assert.ok(AAA.run_rules(calls).some(f => f.rule === 'R7' && /failed/.test(f.title)));
});

test('orphan tool_result (no matching tool_use, e.g. after compaction) is dropped, not a parse error', () => {
  const t = jsonl(line('user', 'user', [res('gone', 'x')]), line('assistant', 'assistant', [use('k', 'Read', { file_path: 'a' })]), line('user', 'user', [res('k', 'A')]));
  assert.equal(AAA.parse_trace(t).length, 1);
});

test('Anthropic API messages[] JSON (block content) is converted too', () => {
  const t = JSON.stringify({ messages: [
    { role: 'user', content: 'go' },
    { role: 'assistant', content: [use('q', 'Bash', { command: `echo ghp_${'A'.repeat(36)}` })] },
    { role: 'user', content: [res('q', 'ok')] }] });
  const f = AAA.run_rules(AAA.parse_trace(t));
  assert.ok(f.some(x => x.rule === 'R4'));
});

test('OpenAI fixtures parse exactly as before (converter not triggered)', () => {
  for (const n of ['fixture_clean.json', 'fixture_violation.json', 'fixture_borderline.json']) {
    const raw = fs.readFileSync(path.join(ROOT, 'fixtures', n), 'utf8');
    assert.equal(AAA.parse_trace(raw).length, AAA.parse_trace(JSON.parse(raw)).length, n);
  }
});

test('garbage that is neither JSON nor Claude JSONL still raises ParseError', () => {
  assert.throws(() => AAA.parse_trace('not json\nat all'), AAA.ParseError);
  assert.throws(() => AAA.parse_trace('{"a":1}\n{"b":2}'), AAA.ParseError);
});

test('replay and CLI accept a .jsonl session file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-cc-'));
  try {
    const f = path.join(dir, 'session.jsonl');
    fs.writeFileSync(f, jsonl(line('assistant', 'assistant', [use('t', 'Bash', { command: 'rm -rf dist' })]), line('user', 'user', [res('t', '')])));
    assert.equal(R.readTraces(dir).length, 1);
    const r = spawnSync('node', [path.join(ROOT, 'audit.js'), f], { encoding: 'utf8' });
    assert.equal(r.status, 10);
    assert.match(r.stdout, /DO NOT DEPLOY/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
