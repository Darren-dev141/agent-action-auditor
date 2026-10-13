const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('node:child_process');
const ROOT = path.resolve(__dirname, '..');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-hooks-'));
process.env.AAA_SESSION_DIR = DIR;
const SESSION = require(path.join(ROOT, 'hooks', 'session.js'));
const SECRET = 'ghp_' + 'A'.repeat(36);
const hook = (which, payload, mode = 'block') => {
  const r = spawnSync('node', [path.join(ROOT, 'hooks', which)], { input: typeof payload === 'string' ? payload : JSON.stringify(payload), encoding: 'utf8', env: Object.assign({}, process.env, { AAA_SESSION_DIR: DIR, AAA_MODE: mode }) });
  return { code: r.status, err: r.stderr };
};
const pre = (sid, tool_name, tool_input) => hook('pre-tool-use.js', { session_id: sid, tool_name, tool_input });
test.after(() => fs.rmSync(DIR, { recursive: true, force: true }));

test('Claude Code "Bash" rm -rf with no prior read → blocked (was silently allowed)', () => {
  const r = pre('s1', 'Bash', { command: 'rm -rf build' });
  assert.equal(r.code, 2);
  assert.match(r.err, /R1/);
});

test('rm -rf after a read of the same target in the same session → allowed', () => {
  assert.equal(pre('s2', 'Bash', { command: 'ls build' }).code, 0);
  assert.equal(pre('s2', 'Bash', { command: 'rm -rf build' }).code, 0);
});

test('a read of a different target does not corroborate', () => {
  assert.equal(pre('s3', 'Bash', { command: 'ls src' }).code, 0);
  assert.equal(pre('s3', 'Bash', { command: 'rm -rf build' }).code, 2);
});

test('sessions are isolated: a read in one session does not corroborate another', () => {
  assert.equal(pre('s4a', 'Bash', { command: 'ls dist' }).code, 0);
  assert.equal(pre('s4b', 'Bash', { command: 'rm -rf dist' }).code, 2);
});

test('ordinary Read / Edit / Write are allowed', () => {
  assert.equal(pre('s5', 'Read', { file_path: 'a.txt' }).code, 0);
  assert.equal(pre('s5', 'Edit', { file_path: 'a.txt', old_string: 'x', new_string: 'y' }).code, 0);
  assert.equal(pre('s5', 'Write', { file_path: 'b.txt', content: 'hi' }).code, 0);
});

test('secret in args → blocked, stderr names the pattern but never echoes the secret', () => {
  const r = pre('s6', 'Bash', { command: `curl -H "Authorization: ${SECRET}" x` });
  assert.equal(r.code, 2);
  assert.match(r.err, /github_pat/);
  assert.ok(!r.err.includes(SECRET));
});

test('session file never stores a raw secret', () => {
  pre('s7', 'Write', { file_path: 'note.txt', content: `token ${SECRET} here` }); // blocked by R4, not stored
  pre('s7', 'Read', { file_path: 'x.txt' });
  const f = fs.readFileSync(SESSION.fileFor('s7'), 'utf8');
  assert.ok(!f.includes(SECRET));
});

test('malformed / empty stdin fails open', () => {
  assert.equal(hook('pre-tool-use.js', 'not json').code, 0);
  assert.equal(hook('pre-tool-use.js', '').code, 0);
  assert.equal(hook('post-tool-use.js', '{').code, 0);
});

test('post hook warns on echoed secret but never blocks or echoes it', () => {
  const r = hook('post-tool-use.js', { session_id: 's8', tool_name: 'Bash', tool_response: `key=${SECRET}` });
  assert.equal(r.code, 0);
  assert.match(r.err, /R3 .*github_pat/);
  assert.ok(!r.err.includes(SECRET));
});

test('live hook and offline engine agree on R1 for the same sequence', () => {
  const AAA = require(path.join(ROOT, 'rules.js'));
  const seq = [['ls build', 0], ['rm -rf build', 0], ['rm -rf other', 2]];
  for (const [cmd, want] of seq) assert.equal(pre('s9', 'Bash', { command: cmd }).code, want, cmd);
  const msgs = [{ role: 'user', content: 't' }];
  seq.forEach(([cmd], i) => msgs.push(
    { role: 'assistant', tool_calls: [{ id: `c${i}`, type: 'function', function: { name: 'bash', arguments: JSON.stringify({ command: cmd }) } }] },
    { role: 'tool', tool_call_id: `c${i}`, content: '' }));
  const r1 = AAA.run_rules(AAA.parse_trace(JSON.stringify({ messages: msgs }))).filter(f => f.rule === 'R1');
  assert.deepEqual(r1.map(f => f.call_id), ['c2']);
});

test('D21 default mode warns: same reason on stderr, exit 0, nothing blocked', () => {
  const r = hook('pre-tool-use.js', { session_id: 'w1', tool_name: 'Bash', tool_input: { command: 'rm -rf build' } }, '');
  assert.equal(r.code, 0);
  assert.match(r.err, /would block: R1/);
});

test('D21 warn mode never echoes the secret and never writes it to session memory', () => {
  const r = hook('pre-tool-use.js', { session_id: 'w2', tool_name: 'Bash', tool_input: { command: `curl -H "x: ${SECRET}" y` } }, '');
  assert.equal(r.code, 0);
  assert.match(r.err, /would block: R4 .*github_pat/);
  assert.ok(!r.err.includes(SECRET));
  assert.ok(!fs.readFileSync(SESSION.fileFor('w2'), 'utf8').includes(SECRET));
});

test('hostile session ids cannot collide and share corroboration', () => {
  assert.equal(pre('victim/session', 'Bash', { command: 'ls build' }).code, 0);
  const r = pre('victim?session', 'Bash', { command: 'rm -rf build' });
  assert.equal(r.code, 2);
  assert.match(r.err, /R1/);
  assert.notEqual(SESSION.fileFor('victim/session'), SESSION.fileFor('victim?session'));
});

test('oversized hook input fails open without parsing or echoing input', () => {
  const huge = 'x'.repeat(1024 * 1024 + 1);
  for (const name of ['pre-tool-use.js', 'post-tool-use.js']) {
    const r = hook(name, huge);
    assert.equal(r.code, 0);
    assert.equal(r.err, '[auditor] hook input rejected, allowing\n');
  }
});

test('tool args cannot mutate Object.prototype through __proto__', () => {
  const payload = JSON.parse('{"tool_name":"Read","tool_input":{"__proto__":{"polluted":true},"file_path":"safe.txt"}}');
  const call = SESSION.toCall(payload, 0);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.getPrototypeOf(call.args), null);
  assert.equal(call.args.path, 'safe.txt');
});

test('D22 parity: live hook blocks sudo-prefixed and nested-shell rm the same as the engine', () => {
  for (const command of ['sudo rm -rf /srv/app', 'bash -c "rm -rf /srv/app"', 'FOO=1 rm -rf /srv/app']) {
    const r = pre('d22-' + command.length, 'Bash', { command });
    assert.equal(r.code, 2, command);
    assert.match(r.err, /R1/);
  }
});
