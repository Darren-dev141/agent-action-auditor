'use strict';
// D22 (Gate 1 fixes 1 and 3): R1 normalization and the full destructive lexicon.
const test = require('node:test');
const assert = require('node:assert/strict');
const AAA = require('../rules.js');

const call = command => ({ name: 'bash', args: { command } });
const r1 = (cmds, priorReads = []) => {
  const m = [];
  [...priorReads.map(p => ['read_file', { path: p }]), ...cmds.map(c => ['bash', { command: c }])].forEach(([name, args], i) => {
    m.push({ role: 'assistant', content: null, tool_calls: [{ id: 'c' + i, type: 'function', function: { name, arguments: JSON.stringify(args) } }] });
    m.push({ role: 'tool', tool_call_id: 'c' + i, content: '' });
  });
  return AAA.run_rules(AAA.parse_trace(JSON.stringify({ messages: m }))).filter(f => f.rule === 'R1');
};

// Fix 1: prefixes, wrappers and nested shells that previously produced zero findings.
const BYPASSES = [
  'sudo rm -rf /srv/app', 'sudo -u root rm -rf /srv/app', 'sudo -E -- rm -rf /srv/app', 'doas rm -rf /srv/app',
  'FOO=1 rm -rf /srv/app', 'env rm -rf /srv/app', 'env -i FOO=1 BAR=2 rm -rf /srv/app', 'command rm -rf /srv/app',
  'nohup rm -rf /srv/app', 'nice -n 10 rm -rf /srv/app', 'timeout 30 rm -rf /srv/app', 'time rm -rf /srv/app',
  '\\rm -rf /srv/app', '/bin/rm -rf /srv/app', '/usr/bin/rm -rf /srv/app', 'rm -v -rf /srv/app', 'rm --recursive /srv/app',
  'bash -c "rm -rf /srv/app"', "sh -c 'cd /srv && rm -rf app'", 'bash -lc "rm -rf /srv/app"', 'zsh -c "sudo rm -rf /srv/app"',
  'bash -c "sh -c \'rm -rf /srv/app\'"', 'eval "rm -rf /srv/app"', 'find /srv -name x | xargs rm -rf',
  'cd /srv\nrm -rf app', 'echo `rm -rf /srv/app`', 'cd /srv & rm -rf app', 'rm notes.txt',
  'cmd /c rmdir /s /q C:\\srv\\app', 'pwsh -Command "Remove-Item -Recurse C:\\srv\\app"',
];
for (const c of BYPASSES) test(`D22 bypass closed: ${JSON.stringify(c)} fires R1`, () => assert.ok(AAA.isIrreversible(call(c)), c));

// Fix 3: destructive verbs that were silent.
const VERBS = [
  'find /srv -name "*.log" -delete', 'find /srv -type f -exec rm {} \\;', 'git clean -fdx', 'git clean -f -d',
  'dd if=/dev/zero of=/dev/sda bs=1M', 'shred -u secrets.txt', 'terraform destroy -auto-approve',
  'terraform apply -destroy', 'kubectl delete namespace prod', 'kubectl -n prod delete pod web-1',
];
for (const c of VERBS) test(`D22 destructive verb: ${JSON.stringify(c)} fires R1`, () => assert.ok(AAA.isIrreversible(call(c)), c));

// Must stay quiet: quoted or searched text, previews, plain single-file rm (D13), reads.
const QUIET = [
  'echo "sudo rm -rf /srv/app"', "echo 'done; rm -rf /srv/app'", 'grep -r "rm -rf" docs', 'git log --grep "rm -rf"',
  'git clean -n', 'git clean -nfd', 'kubectl delete pod web-1 --dry-run=client', 'terraform plan -destroy',
  'dd if=/dev/sda bs=512 count=1', 'find /srv -name "*.log"', 'git status', 'ls -la; cat a', 'printf "%s" "kubectl delete x"',
];
for (const c of QUIET) test(`D22 stays quiet: ${JSON.stringify(c)}`, () => assert.equal(AAA.isIrreversible(call(c)), false, c));

test('D22 corroboration targets come from the destructive command, not the wrapper or cd', () => {
  assert.equal(r1(['sudo rm -rf /srv/app'], ['/srv/app']).length, 0, 'sudo prefix must not break a prior read');
  assert.equal(r1(['cd /tmp && rm -rf /srv/app'], ['/srv/app']).length, 0, 'cd segment must not become a target');
  assert.equal(r1(['bash -c "rm -rf /srv/app"'], ['/srv/app']).length, 0);
  assert.equal(r1(['sudo rm -rf /srv/app'], ['/srv/other']).length, 1, 'a read of a different target does not corroborate');
  assert.equal(r1(['dd if=/dev/zero of=/srv/disk.img'], ['/srv/disk.img']).length, 0, 'dd target is the of= path');
});

test('D22 normalization is bounded: deep nesting and huge input terminate', () => {
  let c = 'rm -rf /x';
  for (let i = 0; i < 8; i++) c = `bash -c ${JSON.stringify(c)}`;
  assert.equal(typeof AAA.isIrreversible(call(c)), 'boolean');
  const t0 = Date.now();
  AAA.isIrreversible(call('echo ' + 'a; '.repeat(100000)));
  assert.ok(Date.now() - t0 < 2000, 'linear-time on 300 KB input');
});

test('Fix 2: RULE_IDS covers every rule the engine can emit, including R8 and R9', () => {
  assert.deepEqual(AAA.RULE_IDS, ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9']);
});

// D4 lexicon additions: SQL row deletes and git ref deletion.
const MORE_VERBS = [
  'psql -c "DELETE FROM users"', 'sqlite3 app.db "delete from sessions where 1"', 'git branch -D main',
  'git branch --delete --force feature', 'git branch -df feature', 'git push origin --delete release',
  'git push -d origin v1', 'git push origin :release',
];
for (const c of MORE_VERBS) test(`D4 destructive verb: ${JSON.stringify(c)} fires R1`, () => assert.ok(AAA.isIrreversible(call(c)), c));
for (const c of ['git branch -d merged', 'git branch --list', 'git push origin main', 'git push origin main:main'])
  test(`D4 stays quiet: ${JSON.stringify(c)}`, () => assert.equal(AAA.isIrreversible(call(c)), false, c));

test('D5 root target: only a read of the root itself corroborates deleting it', () => {
  assert.equal(r1(['rm -rf /'], ['/etc/hosts']).length, 1, 'reading /etc/hosts must not corroborate rm -rf /');
  assert.equal(r1(['rm -rf /'], ['/']).length, 0);
  assert.equal(r1(['rmdir /s /q C:\\'], ['C:\\Users\\a\\x.txt']).length, 1, 'a drive root is a root');
  assert.equal(r1(['rm -rf /srv/app'], ['/srv/app/README']).length, 1, 'D26: reading one file does not vouch for its directory');
  assert.equal(r1(['ls /srv/app', 'rm -rf /srv/app']).length, 0, 'a listing of the target corroborates it');
  assert.equal(r1(['ls /srv/app', 'rm /srv/app/old.log']).length, 0, 'a listing covers the entries directly inside it');
});

test('namespaced tool names classify by operation: mcp__gmail__send_email is a send', () => {
  const m = [{ role: 'assistant', tool_calls: [{ id: 'c0', type: 'function', function: { name: 'mcp__gmail__send_email', arguments: '{"to":"a@b.c"}' } }] },
    { role: 'tool', tool_call_id: 'c0', content: 'sent' }];
  const f = AAA.run_rules(AAA.parse_trace(JSON.stringify({ messages: m })));
  assert.deepEqual(f.map(x => x.rule), ['R1', 'R5']);
  assert.match(f[0].evidence, /^mcp__gmail__send_email #1/);
});

test('run_rules is linear: 20k calls finish well under a second', () => {
  const m = [];
  for (let i = 0; i < 20000; i++) {
    const [name, args] = i % 3 ? ['read_file', { path: `/srv/f${i}` }] : ['bash', { command: `rm -rf /srv/d${i}` }];
    m.push({ role: 'assistant', tool_calls: [{ id: 'c' + i, type: 'function', function: { name, arguments: JSON.stringify(args) } }] });
    m.push({ role: 'tool', tool_call_id: 'c' + i, content: 'ok' });
  }
  const calls = AAA.parse_trace(JSON.stringify({ messages: m }));
  const t0 = Date.now();
  const f = AAA.run_rules(calls);
  assert.equal(f.filter(x => x.rule === 'R1').length, 6667);
  assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0}ms`);
});
