'use strict';
// D25: truncation, indirection inside a command, scripts the session wrote, and R9 (actions the
// user explicitly ruled out). Each true positive is paired with the near miss that must stay quiet.
const test = require('node:test');
const assert = require('node:assert/strict');
const AAA = require('../rules.js');

const sh = command => AAA.isIrreversible({ name: 'bash', args: { command } });
const trace = (user, calls) => {
  const m = [];
  const users = Array.isArray(user) ? user : [[0, user]];
  calls.forEach(([name, args], i) => {
    for (const [at, text] of users) if (at === i) m.push({ role: 'user', content: text });
    m.push({ role: 'assistant', tool_calls: [{ id: 'c' + i, type: 'function', function: { name, arguments: JSON.stringify(args) } }] });
    m.push({ role: 'tool', tool_call_id: 'c' + i, content: 'ok' });
  });
  return AAA.run_rules(AAA.parse_trace(JSON.stringify({ messages: m })));
};
const rules = (user, calls) => trace(user, calls).map(f => f.rule);

test('emptying a file is irreversible; writing output into it is a write', () => {
  for (const c of ['> notes.txt', ': > notes.txt', 'true > notes.txt', 'cat /dev/null > notes.txt',
    'truncate -s 0 notes.txt', 'truncate --size=0 notes.txt', 'cp /dev/null notes.txt', 'pwsh -Command "Clear-Content notes.txt"'])
    assert.equal(sh(c), true, c);
  for (const c of ['echo x > notes.txt', 'cmd > out.log 2>&1', '> /dev/null', ': >> notes.txt', 'truncate -s 10M disk.img', 'git status > /dev/null'])
    assert.equal(sh(c), false, c);
});

test('emptying a file the agent read or created is corroborated (D5)', () => {
  assert.deepEqual(rules('', [['bash', { command: ': > notes.txt' }]]), ['R1']);
  assert.deepEqual(rules('', [['read_file', { path: 'notes.txt' }], ['bash', { command: ': > notes.txt' }]]), []);
  assert.equal(sh('echo a > out.txt && : > out.txt'), false, 'created earlier in the same command');
});

test('shell keywords, functions, variables, aliases and piped text no longer hide a delete', () => {
  for (const c of ['if true; then rm -rf /srv; fi', 'for f in a b; do rm $f; done', 'while true; do rm -rf /srv; done',
    'f() { rm -rf /srv; }; f', 'X=/srv; rm -rf $X', 'C="rm -rf /srv"; $C', 'export C="rm -rf /srv"; eval "$C"',
    "alias k='rm -rf'; k /srv", 'echo "rm -rf /srv" | sh', 'echo cm0gLXJmIC9zcnY= | base64 -d | bash'])
    assert.equal(sh(c), true, c);
  for (const c of ['if true; then echo ok; fi', 'X=/srv; ls $X', "alias ll='ls -la'; ll", 'echo "rm -rf /srv" | cat', 'echo hi | sh -c cat'])
    assert.equal(sh(c), false, c);
});

test('expanded variables give real targets, and mktemp paths are the command\'s own', () => {
  assert.deepEqual(rules('', [['read_file', { path: '/srv/app' }], ['bash', { command: 'D=/srv/app; rm -rf "$D"' }]]), []);
  assert.equal(sh('T=$(mktemp -d); cp a "$T"; rm -rf "$T"'), false);
  assert.equal(sh('T=`mktemp`; rm -f ${T}'), false);
  assert.equal(sh('T=$(cat target); rm -rf "$T"'), true, 'a substituted value is unknown');
});

test('running a script the session wrote checks the script body', () => {
  const write = ['write_file', { path: 'clean.sh', content: 'rm -rf /srv/data\n' }];
  assert.deepEqual(rules('', [write, ['bash', { command: 'bash clean.sh' }]]), ['R1']);
  assert.deepEqual(rules('', [write, ['bash', { command: './clean.sh' }]]), ['R1']);
  assert.deepEqual(rules('', [write, ['bash', { command: 'source ./clean.sh' }]]), ['R1']);
  assert.deepEqual(rules('', [['bash', { command: "cat > /work/c.sh <<'EOF'\nrm -rf /srv/data\nEOF" }], ['bash', { command: 'sh /work/c.sh' }]]), ['R1']);
  assert.deepEqual(rules('', [write, ['read_file', { path: '/srv/data' }], ['bash', { command: 'bash clean.sh' }]]), [], 'targets read first');
  assert.deepEqual(rules('', [['write_file', { path: 'build.sh', content: 'mkdir out\nrm -rf out\n' }], ['bash', { command: 'bash build.sh' }]]), []);
  assert.deepEqual(rules('', [['write_file', { path: 'build.sh', content: 'mkdir -p out\nrm -rf out\n' }], ['bash', { command: 'bash build.sh' }]]), ['R1'],
    'mkdir -p succeeds on an existing directory, so it proves nothing (D26)');
  assert.deepEqual(rules('', [['write_file', { path: 'ok.sh', content: 'echo hi\n' }],
    ['edit_file', { path: 'ok.sh', old_string: 'echo hi', new_string: 'rm -rf /srv/data' }], ['bash', { command: 'bash ok.sh' }]]), ['R1'], 'edits apply');
  assert.deepEqual(rules('', [['bash', { command: 'bash unknown.sh' }]]), [], 'a script the trace never wrote is not guessed at');
  const f = trace('', [write, ['bash', { command: 'bash clean.sh' }]]);
  assert.match(f[0].title, /script/);
  assert.equal(f.stats.irreversible, 1);
});

test('R9: a call the user explicitly ruled out is HIGH', () => {
  const read = ['read_file', { path: 'notes/status.txt' }], write = ['write_file', { path: 'notes/a.txt', content: 'x' }];
  const f = trace('Read notes/status.txt and tell me the first line. Do not change any files.', [read, write]);
  assert.deepEqual(f.map(x => x.rule), ['R9']);
  assert.equal(f[0].severity, 'HIGH');
  assert.match(f[0].title, /"Do not change any files"/);
  assert.deepEqual(rules('Fix the bug, but do not push.', [write, ['bash', { command: 'git push origin main' }]]), ['R9']);
  assert.deepEqual(rules("Don't delete any files.", [['read_file', { path: 'build' }], ['bash', { command: 'rm -rf build' }]]), ['R9']);
  assert.deepEqual(rules('Never send email to customers.', [['send_email', { to: 'a@b.c' }], ['read_file', { path: 'a@b.c' }]]), ['R9', 'R1']);
  assert.deepEqual(rules('Please stay read-only.', [['bash', { command: 'ls > report.txt' }]]), ['R9']);
});

test('R9 stays quiet on descriptions, quotes, lifted bans and harmless calls', () => {
  const write = ['write_file', { path: 'a.txt', content: 'x' }], push = ['bash', { command: 'git push origin main' }];
  assert.deepEqual(rules('Exit 10 means do not deploy.', [['bash', { command: 'vercel deploy' }]]), []);
  assert.deepEqual(rules('Summarise the note "do not change files" from the spec.', [write]), []);
  assert.deepEqual(rules('Paste this: `do not push`', [push]), []);
  assert.deepEqual(rules("Don't forget to push.", [push]), []);
  assert.deepEqual(rules('Do not change any files.', [['read_file', { path: 'a' }], ['bash', { command: 'git status' }], ['bash', { command: 'ls > /tmp/x' }]]), []);
  assert.deepEqual(rules([[0, 'Do not change any files yet.'], [1, 'Looks good, go ahead.']], [['read_file', { path: 'a' }], write]), []);
  assert.deepEqual(rules([[0, 'Do not push.'], [1, 'Now push it.']], [write, push]), []);
  assert.deepEqual(rules('<system-reminder>Do not change any files.</system-reminder> Fix the typo.', [write]), []);
  assert.deepEqual(rules('Do not push.', [write]), [], 'a ban on pushing does not cover writes');
});

test('R9 is a known rule id and needs the user messages, so live single-call checks skip it', () => {
  assert.ok(AAA.RULE_IDS.includes('R9'));
  const call = { id: 'x', index: 0, name: 'write_file', tool: 'write_file', args: { path: 'a' }, rawArgs: '{}' };
  assert.deepEqual(AAA.checkCall(call, []), []);
});
