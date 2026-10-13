#!/usr/bin/env node
// Agent Action Auditor — CLI adapter (SPEC §13 D1/D14/D15). Thin: parse → run_rules → [baseline] → render.
// Usage:
//   node audit.js <trace.json> [--baseline <file>] [--json]
//   node audit.js accept <trace.json> <fingerprint> --baseline <file> --reason "<why>"
//   node audit.js baseline-diff <old.json> <new.json>
// Exit: 0 CLEAN/PASS · 10 DO NOT DEPLOY · 11 REVIEW BEFORE DEPLOY · 2 parse/usage error
'use strict';
const fs = require('fs');
const AAA = require('./rules.js');
const BL = require('./baseline.js');

const argv = process.argv.slice(2);
const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
const positional = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && ['--baseline', '--reason'].includes(argv[i - 1])));
const die = msg => { console.error(`ERROR: ${msg}`); process.exit(2); };
const readJson = (file, what) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { die(`could not read ${what} ${file}: ${e.message}`); }
};
const loadBaseline = file => (file && fs.existsSync(file)) ? readJson(file, 'baseline') : BL.empty();
const audit = file => {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { die(`could not read trace: ${e.message}`); }
  try { return AAA.run_rules(AAA.parse_trace(raw)); }
  catch (e) { die(`${e instanceof AAA.ParseError ? 'invalid trace' : 'could not audit trace'}: ${e.message}`); }
};

if (positional[0] === 'accept') {
  const [, trace, fp] = positional;
  const file = opt('--baseline'), reason = opt('--reason');
  if (!trace || !fp || !file) die('usage: node audit.js accept <trace.json> <fingerprint> --baseline <file> --reason "<why>"');
  const finding = audit(trace).find(f => f.fingerprint === fp);
  if (!finding) die(`no finding with fingerprint ${fp} in ${trace}`);
  let next;
  try { next = BL.accept(loadBaseline(file), finding, reason); } catch (e) { die(e.message); }
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + '\n');
  console.log(`accepted ${fp} (${finding.rule}) into ${file}`);
  process.exit(0);
}

if (positional[0] === 'baseline-diff') {
  const [, a, b] = positional;
  if (!a || !b) die('usage: node audit.js baseline-diff <old.json> <new.json>');
  const d = BL.diff_baselines(readJson(a, 'baseline'), readJson(b, 'baseline'));
  for (const e of d.added) console.log(`+ ${e.fingerprint} ${e.rule} — ${e.reason}`);
  for (const e of d.removed) console.log(`- ${e.fingerprint} ${e.rule} — ${e.reason}`);
  if (!d.added.length && !d.removed.length) console.log('no changes');
  process.exit(0);
}

const file = positional[0];
if (!file) die('usage: node audit.js <trace.json> [--baseline <file>] [--json]');
const findings = BL.apply_baseline(audit(file), loadBaseline(opt('--baseline')));
const report = AAA.render_report(findings);

if (argv.includes('--json')) {
  console.log(JSON.stringify({ headline: report.headline, counts: report.counts, stats: findings.stats,
    findings, suppressed: findings.suppressed }, null, 2));
} else {
  console.log(report.headline);
  for (const line of report.lines) console.log(line);
}
process.exit(report.headline.includes('DO NOT DEPLOY') ? 10 : report.headline.includes('REVIEW BEFORE DEPLOY') ? 11 : 0);
