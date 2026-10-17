'use strict';
// D2 agreement test: the engine's verdict derivation (classify + labelText)
// must agree with the hand-written fixture oracle. The oracle below restates
// tests/validate-fixtures.js expectedVerdict() independently (that script
// executes on load, so it cannot be required) — if the thresholds ever
// drift apart, this test is the tripwire.
const test = require('node:test');
const assert = require('node:assert/strict');
const AAA = require('../rules.js');

function expectedVerdict(findings) {
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const med = findings.filter(f => f.severity === 'MEDIUM').length;
  if (findings.length === 0) return 'CLEAN — no findings';
  if (high > 0) return 'DO NOT DEPLOY';
  if (med >= 3) return 'REVIEW BEFORE DEPLOY';
  return `PASS — ${findings.length} note${findings.length === 1 ? '' : 's'}`;
}

const mk = sevs => sevs.map((severity, i) => ({ rule: 'R1', severity, title: 't', evidence: `x #${i + 1} (c${i + 1})` }));
const corpus = [
  [],                                     // CLEAN
  ['LOW'],                                // PASS — 1 note
  ['MEDIUM'],                             // PASS — 1 note
  ['MEDIUM', 'MEDIUM'],                   // PASS — 2 notes
  ['MEDIUM', 'LOW'],                      // PASS — 2 notes
  ['MEDIUM', 'MEDIUM', 'MEDIUM'],         // REVIEW
  ['MEDIUM', 'MEDIUM', 'MEDIUM', 'LOW'],  // REVIEW
  ['HIGH'],                               // DO NOT DEPLOY
  ['HIGH', 'MEDIUM', 'MEDIUM', 'MEDIUM'], // HIGH beats the MEDIUM threshold
];

test('D2: labelText(classify(f)) agrees with the fixture oracle across the corpus', () => {
  for (const sevs of corpus) {
    const findings = mk(sevs);
    const { kind } = AAA.classify(findings);
    assert.equal(AAA.labelText(kind, findings.length), expectedVerdict(findings), `severities: ${sevs}`);
  }
});

test('D2: classify kinds follow the D9 thresholds', () => {
  assert.equal(AAA.classify([]).kind, 'CLEAN');
  assert.equal(AAA.classify(mk(['LOW'])).kind, 'PASS');
  assert.equal(AAA.classify(mk(['MEDIUM', 'MEDIUM'])).kind, 'PASS');
  assert.equal(AAA.classify(mk(['MEDIUM', 'MEDIUM', 'MEDIUM'])).kind, 'REVIEW');
  assert.equal(AAA.classify(mk(['HIGH'])).kind, 'DO_NOT_DEPLOY');
  assert.deepEqual(AAA.classify(mk(['HIGH', 'MEDIUM', 'LOW'])).counts, { HIGH: 1, MEDIUM: 1, LOW: 1 });
});

test('D2: verdict() and render_report() derive one label from classify()', () => {
  for (const sevs of corpus) {
    const findings = mk(sevs);
    const want = expectedVerdict(findings);
    assert.equal(AAA.verdict(findings, []).label, want, `verdict: ${sevs}`);
    const report = AAA.render_report(findings);
    assert.equal(report.kind, AAA.classify(findings).kind, `kind: ${sevs}`);
    assert.ok(report.headline.endsWith(want), `headline "${report.headline}" ends with "${want}"`);
  }
});
